[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$helper = (Resolve-Path (Join-Path $PSScriptRoot '..\scripts\release-windows-zip.ps1')).Path
$temp = Join-Path ([System.IO.Path]::GetTempPath()) "telltale-windows-zip-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $temp -Force | Out-Null

$canonicalNames = @(
    'telltale.exe',
    'LICENSE',
    'README.md',
    'config/examples/telltale-outputs.yaml',
    'config/examples/telltale-scan.service',
    'config/examples/telltale-scan.timer',
    'config/examples/telltale-scan-task.xml',
    'config/examples/elastic-telltale-index-template.json',
    'config/examples/elastic-telltale-role.json'
)

function New-StagedBundle([string]$Path) {
    New-Item -ItemType Directory -Path (Join-Path $Path 'config/examples') -Force | Out-Null
    foreach ($name in $canonicalNames) {
        $file = Join-Path $Path ($name -replace '/', '\')
        $parent = Split-Path -Parent $file
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        [System.IO.File]::WriteAllBytes(
            $file,
            [System.Text.Encoding]::UTF8.GetBytes("synthetic $name`n")
        )
    }
}

function New-CanonicalArchive(
    [string]$Path,
    [string[]]$Omit = @(),
    [string[]]$Extra = @(),
    [hashtable]$Attributes = @{}
) {
    if ($null -eq $Attributes) {
        $Attributes = @{}
    }
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $canonicalNames) {
        if ($Omit -notcontains $name) {
            $names.Add($name)
        }
    }
    foreach ($name in $Extra) {
        $names.Add($name)
    }

    $archive = $null
    try {
        $archive = [System.IO.Compression.ZipFile]::Open(
            $Path,
            [System.IO.Compression.ZipArchiveMode]::Create
        )
        foreach ($name in $names) {
            $entry = $archive.CreateEntry($name, [System.IO.Compression.CompressionLevel]::NoCompression)
            if ($Attributes.ContainsKey($name)) {
                $entry.ExternalAttributes = [int]$Attributes[$name]
            }
            if ($name.EndsWith('/')) {
                continue
            }
            $stream = $null
            try {
                $stream = $entry.Open()
                $bytes = [System.Text.Encoding]::UTF8.GetBytes("synthetic payload for $name`n")
                $stream.Write($bytes, 0, $bytes.Length)
            } finally {
                if ($null -ne $stream) {
                    $stream.Dispose()
                }
            }
        }
    } finally {
        if ($null -ne $archive) {
            $archive.Dispose()
        }
    }
}

function Invoke-Helper([string[]]$Arguments) {
    $output = & pwsh -NoLogo -NoProfile -NonInteractive -File $helper @Arguments 2>&1
    [pscustomobject]@{
        Success = ($LASTEXITCODE -eq 0)
        Output = ($output -join [Environment]::NewLine)
    }
}

function Assert-HelperSuccess([string]$Archive) {
    $result = Invoke-Helper @('-ValidateOnly', '-ArchivePath', $Archive)
    if (-not $result.Success) {
        throw "expected helper success for $Archive`n$($result.Output)"
    }
}

function Assert-HelperFailure([string]$Archive) {
    $result = Invoke-Helper @('-ValidateOnly', '-ArchivePath', $Archive)
    if ($result.Success) {
        throw "expected helper failure for $Archive"
    }
}

function Assert-HelperFailureWithMessage([string]$Archive, [string]$ExpectedMessage) {
    $result = Invoke-Helper @('-ValidateOnly', '-ArchivePath', $Archive)
    if ($result.Success) {
        throw "expected helper failure for $Archive"
    }
    if ([string]::IsNullOrEmpty($result.Output) -or
        $result.Output.IndexOf($ExpectedMessage, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "expected helper failure for $Archive to mention '$ExpectedMessage'`n$($result.Output)"
    }
}

function Corrupt-Payload([string]$Path, [string]$MemberName) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    for ($index = 0; $index -le $bytes.Length - 30; $index++) {
        if ($bytes[$index] -ne 0x50 -or $bytes[$index + 1] -ne 0x4b -or
            $bytes[$index + 2] -ne 0x03 -or $bytes[$index + 3] -ne 0x04) {
            continue
        }
        $nameLength = [int][System.BitConverter]::ToUInt16($bytes, $index + 26)
        $extraLength = [int][System.BitConverter]::ToUInt16($bytes, $index + 28)
        $recordEnd = [long]$index + 30 + $nameLength + $extraLength
        if ($recordEnd -gt $bytes.Length) {
            continue
        }
        $name = [System.Text.Encoding]::UTF8.GetString($bytes, $index + 30, $nameLength)
        if ($name -ne $MemberName) {
            continue
        }
        $method = [System.BitConverter]::ToUInt16($bytes, $index + 8)
        if ($method -ne 0) {
            throw "test member is not stored: $MemberName"
        }
        $payloadLength = [uint32][System.BitConverter]::ToUInt32($bytes, $index + 18)
        if ($payloadLength -eq 0) {
            throw "test member has no payload: $MemberName"
        }
        $payloadOffset = [int]$recordEnd
        if ([long]$payloadOffset + [long]$payloadLength -gt $bytes.Length) {
            throw "test member payload is truncated: $MemberName"
        }
        $bytes[$payloadOffset] = [byte]($bytes[$payloadOffset] -bxor 0xff)
        [System.IO.File]::WriteAllBytes($Path, $bytes)
        return
    }
    throw "could not locate local payload for $MemberName"
}

function Set-EntryFlags([string]$Path, [string]$MemberName, [uint16]$FlagMask) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $localFound = $false
    $centralFound = $false

    for ($index = 0; $index -le $bytes.Length - 30; $index++) {
        if ($bytes[$index] -ne 0x50 -or $bytes[$index + 1] -ne 0x4b -or
            $bytes[$index + 2] -ne 0x03 -or $bytes[$index + 3] -ne 0x04) {
            continue
        }
        $nameLength = [int][System.BitConverter]::ToUInt16($bytes, $index + 26)
        $extraLength = [int][System.BitConverter]::ToUInt16($bytes, $index + 28)
        $recordEnd = [long]$index + 30 + $nameLength + $extraLength
        if ($recordEnd -gt $bytes.Length) {
            continue
        }
        $name = [System.Text.Encoding]::UTF8.GetString($bytes, $index + 30, $nameLength)
        if ($name -eq $MemberName) {
            $flags = [uint16][System.BitConverter]::ToUInt16($bytes, $index + 6)
            $updatedFlags = [uint16](([uint32]$flags) -bor ([uint32]$FlagMask))
            [System.Array]::Copy(
                [System.BitConverter]::GetBytes($updatedFlags),
                0,
                $bytes,
                $index + 6,
                2
            )
            $localFound = $true
            break
        }
    }

    for ($index = 0; $index -le $bytes.Length - 46; $index++) {
        if ($bytes[$index] -ne 0x50 -or $bytes[$index + 1] -ne 0x4b -or
            $bytes[$index + 2] -ne 0x01 -or $bytes[$index + 3] -ne 0x02) {
            continue
        }
        $nameLength = [int][System.BitConverter]::ToUInt16($bytes, $index + 28)
        $extraLength = [int][System.BitConverter]::ToUInt16($bytes, $index + 30)
        $commentLength = [int][System.BitConverter]::ToUInt16($bytes, $index + 32)
        $recordEnd = [long]$index + 46 + $nameLength + $extraLength + $commentLength
        if ($recordEnd -gt $bytes.Length) {
            continue
        }
        $name = [System.Text.Encoding]::UTF8.GetString($bytes, $index + 46, $nameLength)
        if ($name -eq $MemberName) {
            $flags = [uint16][System.BitConverter]::ToUInt16($bytes, $index + 8)
            $updatedFlags = [uint16](([uint32]$flags) -bor ([uint32]$FlagMask))
            [System.Array]::Copy(
                [System.BitConverter]::GetBytes($updatedFlags),
                0,
                $bytes,
                $index + 8,
                2
            )
            $centralFound = $true
            break
        }
    }

    if (-not $localFound -or -not $centralFound) {
        throw "could not update flags for $MemberName"
    }
    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

function Increase-EntryUncompressedSize([string]$Path, [string]$MemberName) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $localFound = $false
    $centralFound = $false

    for ($index = 0; $index -le $bytes.Length - 30; $index++) {
        if ($bytes[$index] -ne 0x50 -or $bytes[$index + 1] -ne 0x4b -or
            $bytes[$index + 2] -ne 0x03 -or $bytes[$index + 3] -ne 0x04) {
            continue
        }
        $nameLength = [int][System.BitConverter]::ToUInt16($bytes, $index + 26)
        $extraLength = [int][System.BitConverter]::ToUInt16($bytes, $index + 28)
        $recordEnd = [long]$index + 30 + $nameLength + $extraLength
        if ($recordEnd -gt $bytes.Length) {
            continue
        }
        $name = [System.Text.Encoding]::UTF8.GetString($bytes, $index + 30, $nameLength)
        if ($name -eq $MemberName) {
            $size = [uint32][System.BitConverter]::ToUInt32($bytes, $index + 22)
            if ($size -eq [uint32]0xFFFFFFFF) {
                throw "test member uses ZIP64 metadata: $MemberName"
            }
            $updatedSize = [uint32]($size + [uint32]1)
            [System.Array]::Copy(
                [System.BitConverter]::GetBytes($updatedSize),
                0,
                $bytes,
                $index + 22,
                4
            )
            $localFound = $true
            break
        }
    }

    for ($index = 0; $index -le $bytes.Length - 46; $index++) {
        if ($bytes[$index] -ne 0x50 -or $bytes[$index + 1] -ne 0x4b -or
            $bytes[$index + 2] -ne 0x01 -or $bytes[$index + 3] -ne 0x02) {
            continue
        }
        $nameLength = [int][System.BitConverter]::ToUInt16($bytes, $index + 28)
        $extraLength = [int][System.BitConverter]::ToUInt16($bytes, $index + 30)
        $commentLength = [int][System.BitConverter]::ToUInt16($bytes, $index + 32)
        $recordEnd = [long]$index + 46 + $nameLength + $extraLength + $commentLength
        if ($recordEnd -gt $bytes.Length) {
            continue
        }
        $name = [System.Text.Encoding]::UTF8.GetString($bytes, $index + 46, $nameLength)
        if ($name -eq $MemberName) {
            $size = [uint32][System.BitConverter]::ToUInt32($bytes, $index + 24)
            if ($size -eq [uint32]0xFFFFFFFF) {
                throw "test member uses ZIP64 metadata: $MemberName"
            }
            $updatedSize = [uint32]($size + [uint32]1)
            [System.Array]::Copy(
                [System.BitConverter]::GetBytes($updatedSize),
                0,
                $bytes,
                $index + 24,
                4
            )
            $centralFound = $true
            break
        }
    }

    if (-not $localFound -or -not $centralFound) {
        throw "could not update uncompressed size for $MemberName"
    }
    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

try {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $bundle = Join-Path $temp 'bundle'
    New-StagedBundle $bundle
    $productionArchive = Join-Path $temp 'production.zip'
    $production = Invoke-Helper @('-BundleDirectory', $bundle, '-OutputArchive', $productionArchive)
    if (-not $production.Success) {
        throw "production package mode failed`n$($production.Output)"
    }
    if (-not [System.IO.File]::Exists($productionArchive)) {
        throw 'production package mode did not create the archive'
    }
    Assert-HelperSuccess $productionArchive

    $cases = @(
        @{ Name = 'empty'; Omit = $canonicalNames },
        @{ Name = 'missing'; Omit = @('README.md') },
        @{ Name = 'unexpected'; Extra = @('unexpected.txt') },
        @{ Name = 'duplicate'; Extra = @('README.md') },
        @{ Name = 'directory'; Extra = @('config/examples/') },
        @{ Name = 'traversal'; Extra = @('../escape.txt') },
        @{ Name = 'backslash'; Extra = @('bad\name.txt') },
        @{ Name = 'retired-adr'; Extra = @('adr.exe') },
        @{ Name = 'dos-directory'; Attributes = @{ 'README.md' = 0x10 } },
        @{ Name = 'dos-volume-label'; Attributes = @{ 'README.md' = 0x08 }; Expected = 'DOS volume-label' },
        @{ Name = 'unsupported-flags'; Flags = 0x10; Expected = 'unsupported general-purpose flags' },
        @{ Name = 'data-descriptor'; Flags = 0x08; Expected = 'data-descriptor flag' },
        @{ Name = 'central-encryption'; Flags = 0x2000; Expected = 'encryption flag' },
        @{ Name = 'unix-link'; Attributes = @{ 'README.md' = -1610612736 } },
        @{ Name = 'unsupported-attributes'; Attributes = @{ 'README.md' = 0x80 } }
    )
    foreach ($case in $cases) {
        $archive = Join-Path $temp "$($case.Name).zip"
        $omit = if ($case.ContainsKey('Omit')) { $case.Omit } else { @() }
        $extra = if ($case.ContainsKey('Extra')) { $case.Extra } else { @() }
        $attributes = if ($case.ContainsKey('Attributes')) { $case.Attributes } else { @{} }
        New-CanonicalArchive $archive $omit $extra $attributes
        if ($case.ContainsKey('Flags')) {
            Set-EntryFlags $archive 'README.md' $case.Flags
        }
        if ($case.ContainsKey('Expected')) {
            Assert-HelperFailureWithMessage $archive $case.Expected
        } else {
            Assert-HelperFailure $archive
        }
    }

    $corrupt = Join-Path $temp 'corrupt-payload.zip'
    New-CanonicalArchive $corrupt
    Corrupt-Payload $corrupt 'README.md'
    Assert-HelperFailureWithMessage $corrupt 'CRC32 mismatch'

    $encrypted = Join-Path $temp 'encrypted.zip'
    New-CanonicalArchive $encrypted
    Set-EntryFlags $encrypted 'README.md' 0x0001
    Assert-HelperFailureWithMessage $encrypted 'encryption flag'

    $lengthMismatch = Join-Path $temp 'length-mismatch.zip'
    New-CanonicalArchive $lengthMismatch
    Increase-EntryUncompressedSize $lengthMismatch 'README.md'
    Assert-HelperFailureWithMessage $lengthMismatch 'length mismatch'

    $malformed = Join-Path $temp 'malformed.zip'
    [System.IO.File]::WriteAllBytes($malformed, [byte[]](0x6e, 0x6f, 0x74, 0x2d, 0x2a, 0x2a, 0x2a))
    Assert-HelperFailure $malformed

    $truncated = Join-Path $temp 'truncated.zip'
    New-CanonicalArchive $truncated
    $truncatedBytes = [System.IO.File]::ReadAllBytes($truncated)
    [System.IO.File]::WriteAllBytes($truncated, $truncatedBytes[0..($truncatedBytes.Length - 12)])
    Assert-HelperFailure $truncated

    $blockedArchive = Join-Path $temp 'blocked.zip'
    New-CanonicalArchive $blockedArchive -Extra @('unexpected.txt')
    $downstreamMarkers = @(
        (Join-Path $temp 'smoke-ran'),
        (Join-Path $temp 'attestation-ran'),
        (Join-Path $temp 'upload-ran')
    )
    $gate = Invoke-Helper @('-ValidateOnly', '-ArchivePath', $blockedArchive)
    if ($gate.Success) {
        foreach ($marker in $downstreamMarkers) {
            [System.IO.File]::WriteAllText($marker, 'must not run')
        }
    }
    if ($gate.Success -or ($downstreamMarkers | Where-Object { Test-Path -LiteralPath $_ })) {
        throw 'a failed ZIP validation did not block downstream continuation'
    }

    Write-Output 'Windows release ZIP helper tests passed.'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
