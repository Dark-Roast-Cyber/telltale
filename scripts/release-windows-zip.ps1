[CmdletBinding()]
param(
    [Parameter()][string]$BundleDirectory,
    [Parameter()][string]$OutputArchive,
    [Parameter()][switch]$ValidateOnly,
    [Parameter()][string]$ArchivePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$ZipEndOfCentralDirectorySize = 22
$ZipCentralDirectoryHeaderSize = 46
$ZipLocalFileHeaderSize = 30
$ZipMaxCommentLength = 65535
$ZipMaxCentralDirectoryBytes = [long]67108864
$ZipUtf8Flag = [uint32]0x0800
$ZipDataDescriptorFlag = [uint32]0x0008
$ZipEncryptionFlags = [uint32]0x2041
$script:Crc32Table = [uint32[]]::new(256)
for ($tableIndex = 0; $tableIndex -lt $script:Crc32Table.Length; $tableIndex++) {
    $tableValue = [uint32]$tableIndex
    for ($bit = 0; $bit -lt 8; $bit++) {
        if (($tableValue -band [uint32]1) -ne 0) {
            $tableValue = [uint32](($tableValue -shr 1) -bxor [uint32]0xEDB88320)
        } else {
            $tableValue = [uint32]($tableValue -shr 1)
        }
    }
    $script:Crc32Table[$tableIndex] = $tableValue
}

$CanonicalMembers = [ordered]@{
    'telltale.exe' = 'telltale.exe'
    'LICENSE' = 'LICENSE'
    'README.md' = 'README.md'
    'config/examples/telltale-outputs.yaml' = 'config/examples/telltale-outputs.yaml'
    'config/examples/telltale-scan.service' = 'config/examples/telltale-scan.service'
    'config/examples/telltale-scan.timer' = 'config/examples/telltale-scan.timer'
    'config/examples/telltale-scan-task.xml' = 'config/examples/telltale-scan-task.xml'
    'config/examples/elastic-telltale-index-template.json' = 'config/examples/elastic-telltale-index-template.json'
    'config/examples/elastic-telltale-role.json' = 'config/examples/elastic-telltale-role.json'
}

function Fail([string]$Message) {
    throw "Windows release ZIP validation failed: $Message"
}

function Get-RegularFile([string]$Path, [string]$Description) {
    if (-not [System.IO.File]::Exists($Path)) {
        Fail "$Description is missing or is not a regular file: $Path"
    }

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) {
        Fail "$Description is a directory: $Path"
    }

    $attributes = [System.IO.File]::GetAttributes($Path)
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "$Description is a reparse point: $Path"
    }

    return $item
}

function Assert-ArchivePath([string]$Path) {
    Get-RegularFile $Path 'output archive' | Out-Null
}

function Read-ExactBytes(
    [System.IO.Stream]$Stream,
    [int]$Count,
    [string]$Description
) {
    if ($Count -lt 0) {
        Fail "invalid byte count for $Description"
    }

    $buffer = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -le 0) {
            Fail "ZIP ended while reading $Description"
        }
        $offset += $read
    }
    return ,$buffer
}

function Assert-BufferRange(
    [byte[]]$Buffer,
    [int]$Offset,
    [int]$Length,
    [string]$Description
) {
    if ($Offset -lt 0 -or $Length -lt 0 -or $Offset -gt ($Buffer.Length - $Length)) {
        Fail "ZIP metadata extends beyond $Description"
    }
}

function Read-ZipUInt16([byte[]]$Buffer, [int]$Offset, [string]$Description) {
    Assert-BufferRange $Buffer $Offset 2 $Description
    return [uint32][System.BitConverter]::ToUInt16($Buffer, $Offset)
}

function Read-ZipUInt32([byte[]]$Buffer, [int]$Offset, [string]$Description) {
    Assert-BufferRange $Buffer $Offset 4 $Description
    return [uint32][System.BitConverter]::ToUInt32($Buffer, $Offset)
}

function Convert-ZipName([byte[]]$NameBytes, [string]$Description) {
    try {
        return [System.Text.UTF8Encoding]::new($false, $true).GetString($NameBytes)
    } catch {
        Fail "$Description is not valid UTF-8"
    }
}

function Assert-ZipExtraFields([byte[]]$ExtraBytes, [string]$Description) {
    $offset = 0
    while ($offset -lt $ExtraBytes.Length) {
        if ($offset -gt ($ExtraBytes.Length - 4)) {
            Fail "$Description has a truncated extra field header"
        }
        $fieldId = Read-ZipUInt16 $ExtraBytes $offset $Description
        $fieldLength = [int](Read-ZipUInt16 $ExtraBytes ($offset + 2) $Description)
        if ($fieldLength -gt ($ExtraBytes.Length - $offset - 4)) {
            Fail "$Description has an extra field that extends beyond its record"
        }
        if ($fieldId -eq [uint32]0x0001) {
            Fail "$Description uses unsupported ZIP64 metadata"
        }
        $offset += 4 + $fieldLength
    }
}

function Assert-GeneralPurposeFlags([uint32]$Flags, [string]$Name, [string]$Location) {
    if (($Flags -band $ZipEncryptionFlags) -ne 0) {
        Fail "archive member has an encryption flag in the $Location general-purpose bit flag: $Name"
    }
    if (($Flags -band $ZipDataDescriptorFlag) -ne 0) {
        Fail "archive member uses the unsupported data-descriptor flag in the $Location general-purpose bit flag: $Name"
    }
    if ($Flags -ne [uint32]0 -and $Flags -ne $ZipUtf8Flag) {
        Fail "archive member has unsupported general-purpose flags in the $Location header: $Name"
    }
}

function Read-ZipCentralDirectoryMetadata([string]$Path) {
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        $fileLength = [long]$stream.Length
        if ($fileLength -lt $ZipEndOfCentralDirectorySize) {
            Fail 'archive is too short to contain an end-of-central-directory record'
        }

        $tailLength = [int][Math]::Min(
            [long]($ZipEndOfCentralDirectorySize + $ZipMaxCommentLength),
            $fileLength
        )
        $stream.Seek([long](-$tailLength), [System.IO.SeekOrigin]::End) | Out-Null
        $tail = Read-ExactBytes $stream $tailLength 'the end-of-central-directory record'
        $endRecordOffset = -1
        for ($offset = $tail.Length - $ZipEndOfCentralDirectorySize; $offset -ge 0; $offset--) {
            if ((Read-ZipUInt32 $tail $offset 'the end-of-central-directory search') -ne [uint32]0x06054B50) {
                continue
            }
            $commentLength = [int](Read-ZipUInt16 $tail ($offset + 20) 'the end-of-central-directory record')
            if ($offset + $ZipEndOfCentralDirectorySize + $commentLength -ne $tail.Length) {
                continue
            }
            if ($endRecordOffset -ge 0) {
                Fail 'archive has ambiguous end-of-central-directory records'
            }
            $endRecordOffset = $offset
        }
        if ($endRecordOffset -lt 0) {
            Fail 'archive has no valid end-of-central-directory record'
        }

        $endRecordAbsoluteOffset = $fileLength - $tailLength + $endRecordOffset
        $diskNumber = Read-ZipUInt16 $tail ($endRecordOffset + 4) 'the end-of-central-directory record'
        $centralDirectoryDisk = Read-ZipUInt16 $tail ($endRecordOffset + 6) 'the end-of-central-directory record'
        $entriesOnDisk = Read-ZipUInt16 $tail ($endRecordOffset + 8) 'the end-of-central-directory record'
        $entriesTotal = Read-ZipUInt16 $tail ($endRecordOffset + 10) 'the end-of-central-directory record'
        $centralDirectorySize32 = Read-ZipUInt32 $tail ($endRecordOffset + 12) 'the end-of-central-directory record'
        $centralDirectoryOffset32 = Read-ZipUInt32 $tail ($endRecordOffset + 16) 'the end-of-central-directory record'

        if ($diskNumber -ne 0 -or $centralDirectoryDisk -ne 0 -or $entriesOnDisk -ne $entriesTotal) {
            Fail 'archive uses unsupported multi-disk ZIP metadata'
        }
        if ($entriesTotal -eq [uint32]0xFFFF -or
            $centralDirectorySize32 -eq [uint32]0xFFFFFFFF -or
            $centralDirectoryOffset32 -eq [uint32]0xFFFFFFFF) {
            Fail 'archive uses unsupported ZIP64 metadata'
        }

        $centralDirectorySize = [long]$centralDirectorySize32
        $centralDirectoryOffset = [long]$centralDirectoryOffset32
        if ($centralDirectorySize -gt $ZipMaxCentralDirectoryBytes) {
            Fail 'archive central-directory metadata exceeds the supported bound'
        }
        if ($centralDirectoryOffset -gt $fileLength -or
            $centralDirectorySize -gt ($fileLength - $centralDirectoryOffset)) {
            Fail 'archive central-directory metadata is outside the file'
        }
        if ($centralDirectoryOffset + $centralDirectorySize -ne $endRecordAbsoluteOffset) {
            Fail 'archive has unsupported data between the central directory and end record'
        }

        $centralDirectory = [byte[]]::new([int]$centralDirectorySize)
        if ($centralDirectorySize -gt 0) {
            $stream.Seek($centralDirectoryOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
            $centralDirectory = Read-ExactBytes $stream ([int]$centralDirectorySize) 'the central directory'
        }

        $metadata = [System.Collections.Generic.List[object]]::new()
        $offset = 0
        $entryCount = [int]$entriesTotal
        for ($entryIndex = 0; $entryIndex -lt $entryCount; $entryIndex++) {
            Assert-BufferRange $centralDirectory $offset $ZipCentralDirectoryHeaderSize 'the central directory'
            if ((Read-ZipUInt32 $centralDirectory $offset 'the central directory') -ne [uint32]0x02014B50) {
                Fail "central directory entry $entryIndex has an invalid signature"
            }

            $flags = Read-ZipUInt16 $centralDirectory ($offset + 8) 'the central directory'
            $compressionMethod = Read-ZipUInt16 $centralDirectory ($offset + 10) 'the central directory'
            $crc32 = Read-ZipUInt32 $centralDirectory ($offset + 16) 'the central directory'
            $compressedSize32 = Read-ZipUInt32 $centralDirectory ($offset + 20) 'the central directory'
            $uncompressedSize32 = Read-ZipUInt32 $centralDirectory ($offset + 24) 'the central directory'
            $nameLength = [int](Read-ZipUInt16 $centralDirectory ($offset + 28) 'the central directory')
            $extraLength = [int](Read-ZipUInt16 $centralDirectory ($offset + 30) 'the central directory')
            $commentLength = [int](Read-ZipUInt16 $centralDirectory ($offset + 32) 'the central directory')
            $diskStart = Read-ZipUInt16 $centralDirectory ($offset + 34) 'the central directory'
            $externalAttributes = Read-ZipUInt32 $centralDirectory ($offset + 38) 'the central directory'
            $localHeaderOffset32 = Read-ZipUInt32 $centralDirectory ($offset + 42) 'the central directory'

            Assert-GeneralPurposeFlags $flags "central directory entry $entryIndex" 'central-directory'
            if ($compressionMethod -ne 0 -and $compressionMethod -ne 8) {
                Fail "archive member in central directory entry $entryIndex uses unsupported compression method: $compressionMethod"
            }
            if ($diskStart -ne 0) {
                Fail "archive central directory entry $entryIndex starts on an unsupported disk"
            }
            if ($compressedSize32 -eq [uint32]0xFFFFFFFF -or
                $uncompressedSize32 -eq [uint32]0xFFFFFFFF -or
                $localHeaderOffset32 -eq [uint32]0xFFFFFFFF) {
                Fail 'archive uses unsupported ZIP64 member metadata'
            }

            $recordLength = [long]$ZipCentralDirectoryHeaderSize + $nameLength + $extraLength + $commentLength
            if ($recordLength -gt ($centralDirectory.Length - $offset)) {
                Fail "central directory entry $entryIndex extends beyond the central directory"
            }
            $nameBytes = [byte[]]::new($nameLength)
            if ($nameLength -gt 0) {
                [System.Array]::Copy($centralDirectory, $offset + $ZipCentralDirectoryHeaderSize, $nameBytes, 0, $nameLength)
            }
            $extraBytes = [byte[]]::new($extraLength)
            if ($extraLength -gt 0) {
                [System.Array]::Copy(
                    $centralDirectory,
                    $offset + $ZipCentralDirectoryHeaderSize + $nameLength,
                    $extraBytes,
                    0,
                    $extraLength
                )
            }
            $name = Convert-ZipName $nameBytes "central directory entry $entryIndex name"
            Assert-ZipExtraFields $extraBytes "central directory entry $entryIndex"

            $metadata.Add([pscustomobject]@{
                Index = $entryIndex
                Name = $name
                NameBytes = $nameBytes
                GeneralPurposeFlags = $flags
                CompressionMethod = $compressionMethod
                Crc32 = $crc32
                CompressedSize = [uint64]$compressedSize32
                UncompressedSize = [uint64]$uncompressedSize32
                ExternalAttributes = $externalAttributes
                LocalHeaderOffset = [long]$localHeaderOffset32
            }) | Out-Null
            $offset += [int]$recordLength
        }
        if ($offset -ne $centralDirectory.Length) {
            Fail 'central directory contains trailing or unrecognized metadata'
        }

        $seenLocalOffsets = [System.Collections.Generic.HashSet[long]]::new()
        foreach ($entryMetadata in $metadata) {
            if (-not $seenLocalOffsets.Add($entryMetadata.LocalHeaderOffset)) {
                Fail "archive has duplicate local-header offsets: $($entryMetadata.Name)"
            }
            $localHeaderOffset = $entryMetadata.LocalHeaderOffset
            if ($localHeaderOffset -gt ($centralDirectoryOffset - $ZipLocalFileHeaderSize)) {
                Fail "archive member local header is outside the local-file area: $($entryMetadata.Name)"
            }
            $stream.Seek($localHeaderOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
            $localHeader = Read-ExactBytes $stream $ZipLocalFileHeaderSize "the local header for $($entryMetadata.Name)"
            if ((Read-ZipUInt32 $localHeader 0 'the local file header') -ne [uint32]0x04034B50) {
                Fail "archive member has an invalid local-header signature: $($entryMetadata.Name)"
            }
            $localFlags = Read-ZipUInt16 $localHeader 6 'the local file header'
            $localCompressionMethod = Read-ZipUInt16 $localHeader 8 'the local file header'
            $localCrc32 = Read-ZipUInt32 $localHeader 14 'the local file header'
            $localCompressedSize32 = Read-ZipUInt32 $localHeader 18 'the local file header'
            $localUncompressedSize32 = Read-ZipUInt32 $localHeader 22 'the local file header'
            $localNameLength = [int](Read-ZipUInt16 $localHeader 26 'the local file header')
            $localExtraLength = [int](Read-ZipUInt16 $localHeader 28 'the local file header')

            Assert-GeneralPurposeFlags $localFlags $entryMetadata.Name 'local-file'
            if ($localFlags -ne $entryMetadata.GeneralPurposeFlags) {
                Fail "archive member local and central general-purpose flags differ: $($entryMetadata.Name)"
            }
            if ($localCompressionMethod -ne $entryMetadata.CompressionMethod) {
                Fail "archive member local and central compression methods differ: $($entryMetadata.Name)"
            }
            if ($localCompressedSize32 -eq [uint32]0xFFFFFFFF -or
                $localUncompressedSize32 -eq [uint32]0xFFFFFFFF) {
                Fail "archive member uses unsupported ZIP64 local-header metadata: $($entryMetadata.Name)"
            }

            $localNameBytes = Read-ExactBytes $stream $localNameLength "the local name for $($entryMetadata.Name)"
            $localExtraBytes = Read-ExactBytes $stream $localExtraLength "the local extra fields for $($entryMetadata.Name)"
            Assert-ZipExtraFields $localExtraBytes "local header for $($entryMetadata.Name)"
            if ($localNameLength -ne $entryMetadata.NameBytes.Length) {
                Fail "archive member local and central names differ: $($entryMetadata.Name)"
            }
            for ($nameIndex = 0; $nameIndex -lt $localNameLength; $nameIndex++) {
                if ($localNameBytes[$nameIndex] -ne $entryMetadata.NameBytes[$nameIndex]) {
                    Fail "archive member local and central names differ: $($entryMetadata.Name)"
                }
            }

            if ($localCrc32 -ne $entryMetadata.Crc32 -or
                $localCompressedSize32 -ne [uint32]$entryMetadata.CompressedSize -or
                $localUncompressedSize32 -ne [uint32]$entryMetadata.UncompressedSize) {
                Fail "archive member local and central sizes or CRC differ: $($entryMetadata.Name)"
            }

            $dataOffset = $localHeaderOffset + $ZipLocalFileHeaderSize + $localNameLength + $localExtraLength
            if ($dataOffset -gt $centralDirectoryOffset -or
                [long]$entryMetadata.CompressedSize -gt ($centralDirectoryOffset - $dataOffset)) {
                Fail "archive member payload is outside the local-file area: $($entryMetadata.Name)"
            }
        }

        return $metadata.ToArray()
    } finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Assert-EntryName([string]$Name, [System.Collections.Generic.HashSet[string]]$Seen) {
    if ([string]::IsNullOrEmpty($Name)) {
        Fail 'archive contains an empty member name'
    }
    if ($Name.Contains('\')) {
        Fail "archive member uses a backslash: $Name"
    }
    if ($Name.StartsWith('/') -or $Name -match '^[A-Za-z]:($|/)') {
        Fail "archive member is absolute: $Name"
    }

    foreach ($part in ($Name -split '/')) {
        if ($part -eq '.' -or $part -eq '..' -or [string]::IsNullOrEmpty($part)) {
            Fail "archive member contains a noncanonical or traversal path: $Name"
        }
    }
    if ($Name -eq 'adr' -or $Name -eq 'adr.exe') {
        Fail "archive contains retired ADR member: $Name"
    }
    if (-not $Seen.Add($Name)) {
        Fail "archive contains duplicate member: $Name"
    }
}

function Assert-RegularEntry([System.IO.Compression.ZipArchiveEntry]$Entry) {
    $name = $Entry.FullName
    if ($name.EndsWith('/')) {
        Fail "archive contains a directory member: $name"
    }

    $externalAttributes = [uint32]$Entry.ExternalAttributes
    $dosAttributes = $externalAttributes -band [uint32]0xFFFF
    $unixMode = ($externalAttributes -shr 16) -band [uint32]0xFFFF
    $unixType = $unixMode -band [uint32]0xF000

    if (($dosAttributes -band [uint32]0x10) -ne 0) {
        Fail "archive member has the DOS directory attribute: $name"
    }
    if (($dosAttributes -band [uint32]0x08) -ne 0) {
        Fail "archive member has the DOS volume-label attribute: $name"
    }
    if (($dosAttributes -band [uint32]0xFFC0) -ne 0) {
        Fail "archive member has unsupported DOS attributes: $name"
    }
    if ($unixType -eq [uint32]0x4000) {
        Fail "archive member has the Unix directory type: $name"
    }
    if ($unixType -eq [uint32]0xA000) {
        Fail "archive member has the Unix link type: $name"
    }
    if ($unixType -ne 0 -and $unixType -ne [uint32]0x8000) {
        Fail "archive member has an unsupported Unix type: $name"
    }
}

function Read-EntryToEnd(
    [System.IO.Compression.ZipArchiveEntry]$Entry,
    [psobject]$Metadata
) {
    if ([uint64]$Entry.Length -ne [uint64]$Metadata.UncompressedSize) {
        Fail "archive member length differs from central-directory metadata: $($Entry.FullName)"
    }

    $stream = $null
    $crc32 = [uint32]0xFFFFFFFF
    $length = [uint64]0
    $readException = $null
    try {
        $stream = $Entry.Open()
        $buffer = New-Object byte[] 81920
        while ($true) {
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -eq 0) {
                break
            }
            for ($index = 0; $index -lt $read; $index++) {
                $mixed = [uint32]($crc32 -bxor [uint32]$buffer[$index])
                $tableIndex = [int]($mixed -band [uint32]0xFF)
                $crc32 = [uint32](($crc32 -shr 8) -bxor $script:Crc32Table[$tableIndex])
            }
            $length = [uint64]($length + [uint64]$read)
        }
    } catch {
        $readException = $_.Exception
    } finally {
        if ($null -ne $stream) {
            try {
                $stream.Dispose()
            } catch {
                if ($null -eq $readException) {
                    $readException = $_.Exception
                }
            }
        }
    }

    $crc32 = [uint32]($crc32 -bxor [uint32]0xFFFFFFFF)
    if ($length -ne [uint64]$Metadata.UncompressedSize) {
        Fail "archive member length mismatch: $($Entry.FullName)"
    }
    if ($crc32 -ne [uint32]$Metadata.Crc32) {
        $actual = $crc32.ToString('X8')
        $expected = ([uint32]$Metadata.Crc32).ToString('X8')
        Fail "archive member CRC32 mismatch for $($Entry.FullName): expected $expected, got $actual"
    }
    if ($null -ne $readException) {
        Fail "could not read archive member $($Entry.FullName): $($readException.Message)"
    }
}

function Validate-FinalizedArchive([string]$Path) {
    Assert-ArchivePath $Path

    $archive = $null
    try {
        $archive = [System.IO.Compression.ZipFile]::Open(
            $Path,
            [System.IO.Compression.ZipArchiveMode]::Read
        )
        $entries = @($archive.Entries)
        $metadata = @(Read-ZipCentralDirectoryMetadata $Path)
        if ($metadata.Count -ne $entries.Count) {
            Fail 'central-directory entry count differs from the readable archive entry count'
        }
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $expected = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($member in $CanonicalMembers.Keys) {
            $expected.Add($member) | Out-Null
        }

        for ($index = 0; $index -lt $entries.Count; $index++) {
            $entry = $entries[$index]
            $entryMetadata = $metadata[$index]
            if (-not [string]::Equals($entry.FullName, $entryMetadata.Name, [System.StringComparison]::Ordinal)) {
                Fail "central-directory name differs from the readable archive entry: $($entry.FullName)"
            }
            if ([uint32]$entry.ExternalAttributes -ne [uint32]$entryMetadata.ExternalAttributes) {
                Fail "central-directory attributes differ from the readable archive entry: $($entry.FullName)"
            }
            Assert-EntryName $entry.FullName $seen
            Assert-RegularEntry $entry
        }

        if ($entries.Count -ne $expected.Count -or -not $seen.SetEquals($expected)) {
            $actual = @($seen | Sort-Object)
            Fail "archive does not contain the exact canonical member set: $($actual -join ', ')"
        }

        for ($index = 0; $index -lt $entries.Count; $index++) {
            Read-EntryToEnd $entries[$index] $metadata[$index]
        }
    } finally {
        if ($null -ne $archive) {
            $archive.Dispose()
        }
    }
}

function Remove-ExistingArchive([string]$Path) {
    $existing = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        return
    }
    if ($existing.PSIsContainer) {
        Fail "output archive path is a directory: $Path"
    }
    $attributes = [System.IO.File]::GetAttributes($Path)
    if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "output archive path is a reparse point: $Path"
    }
    Remove-Item -LiteralPath $Path -Force
}

if ($ValidateOnly) {
    if (-not [string]::IsNullOrWhiteSpace($ArchivePath) -and -not [string]::IsNullOrWhiteSpace($OutputArchive)) {
        Fail '-ValidateOnly accepts only one archive path'
    }
    $validationPath = if (-not [string]::IsNullOrWhiteSpace($ArchivePath)) {
        $ArchivePath
    } else {
        $OutputArchive
    }
    if ([string]::IsNullOrWhiteSpace($validationPath)) {
        Fail '-ValidateOnly requires -ArchivePath or -OutputArchive'
    }
    if (-not [string]::IsNullOrWhiteSpace($BundleDirectory)) {
        Fail '-ValidateOnly cannot be combined with production package arguments'
    }
    Validate-FinalizedArchive ([System.IO.Path]::GetFullPath($validationPath))
    exit 0
}

if ([string]::IsNullOrWhiteSpace($BundleDirectory) -or [string]::IsNullOrWhiteSpace($OutputArchive)) {
    Fail 'production package mode requires -BundleDirectory and -OutputArchive'
}
if (-not [string]::IsNullOrWhiteSpace($ArchivePath)) {
    Fail '-ArchivePath is only valid with -ValidateOnly'
}

$bundle = [System.IO.Path]::GetFullPath($BundleDirectory)
$archivePath = [System.IO.Path]::GetFullPath($OutputArchive)
$bundleItem = Get-Item -LiteralPath $bundle -Force
if (-not $bundleItem.PSIsContainer) {
    Fail "staged bundle path is not a directory: $bundle"
}
$bundleAttributes = [System.IO.File]::GetAttributes($bundle)
if (($bundleAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "staged bundle path is a reparse point: $bundle"
}

$sources = [ordered]@{}
foreach ($member in $CanonicalMembers.GetEnumerator()) {
    $source = Join-Path $bundle $member.Value
    Get-RegularFile $source "canonical source $($member.Key)" | Out-Null
    $sources[$member.Key] = $source
}

Remove-ExistingArchive $archivePath
$writer = $null
try {
    $writer = [System.IO.Compression.ZipFile]::Open(
        $archivePath,
        [System.IO.Compression.ZipArchiveMode]::Create
    )
    foreach ($member in $CanonicalMembers.GetEnumerator()) {
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $writer,
            $sources[$member.Key],
            $member.Key,
            [System.IO.Compression.CompressionLevel]::Optimal
        ) | Out-Null
    }
} finally {
    if ($null -ne $writer) {
        $writer.Dispose()
    }
}

Validate-FinalizedArchive $archivePath
