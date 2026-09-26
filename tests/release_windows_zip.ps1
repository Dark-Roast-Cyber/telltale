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
            if ($size -eq [uint32]::MaxValue) {
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
            if ($size -eq [uint32]::MaxValue) {
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

    # Exercise the Windows workflow's Python staging command on a synthetic checkout.
    $checkout = Join-Path $temp 'checkout'
    New-Item -ItemType Directory -Path (Join-Path $checkout 'scripts'), (Join-Path $checkout 'release'), (Join-Path $checkout 'target/release') | Out-Null
    Copy-Item (Join-Path $PSScriptRoot '../scripts/release-artifact-manifest') (Join-Path $checkout 'scripts/release-artifact-manifest')
    Copy-Item (Join-Path $PSScriptRoot '../release/bundle.tsv') (Join-Path $checkout 'release/bundle.tsv')
    foreach ($name in $canonicalNames) {
        $source = switch -CaseSensitive ($name) {
            'telltale.exe' { 'target/release/telltale.exe' }
            'README.md' { 'release/README.md' }
            default { $name }
        }
        $destination = Join-Path $checkout $source
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item (Join-Path $bundle $name) $destination
    }
    [System.IO.File]::WriteAllText((Join-Path $checkout 'README.md'), 'wrong repository README')
    $bundle = Join-Path $temp 'python-bundle'
    & python (Join-Path $checkout 'scripts/release-artifact-manifest') --platform windows --stage (Join-Path $checkout 'target/release/telltale.exe') $bundle
    if ($LASTEXITCODE -ne 0) { throw 'Windows Python staging command failed' }
    if ([System.IO.File]::ReadAllText((Join-Path $bundle 'README.md')) -cne "synthetic README.md`n") {
        throw 'Windows Python staging did not map release/README.md to README.md'
    }
    if ($IsWindows) {
        foreach ($parent in @('release', 'config', 'target')) {
            $redirected = Join-Path $checkout $parent
            $outside = Join-Path $temp "outside-$parent"
            $rejectedBundle = Join-Path $temp "rejected-$parent"
            Move-Item -LiteralPath $redirected -Destination $outside
            New-Item -ItemType Junction -Path $redirected -Target $outside | Out-Null
            try {
                $result = & python (Join-Path $checkout 'scripts/release-artifact-manifest') --platform windows --stage (Join-Path $checkout 'target/release/telltale.exe') $rejectedBundle 2>&1
                if ($LASTEXITCODE -eq 0 -or ($result -join "`n") -notmatch 'outside the checkout' -or (Test-Path -LiteralPath $rejectedBundle)) {
                    throw "Windows staging did not reject the $parent junction escape before staging"
                }
            } finally {
                [System.IO.Directory]::Delete($redirected)
                Move-Item -LiteralPath $outside -Destination $redirected
            }
        }
    }
    $productionArchive = Join-Path $temp 'production.zip'
    $production = Invoke-Helper @('-BundleDirectory', $bundle, '-OutputArchive', $productionArchive)
    if (-not $production.Success) {
        throw "production package mode failed`n$($production.Output)"
    }
    if (-not [System.IO.File]::Exists($productionArchive)) {
        throw 'production package mode did not create the archive'
    }
    Assert-HelperSuccess $productionArchive

    $produced = [System.IO.Compression.ZipFile]::OpenRead($productionArchive)
    try {
        foreach ($entry in $produced.Entries) {
            $expectedMode = if ($entry.FullName -ceq 'telltale.exe') { 0x1ED } else { 0x1A4 }
            if ((($entry.ExternalAttributes -shr 16) -band 0xFFFF) -ne (0x8000 -bor $expectedMode)) {
                throw "production ZIP has incorrect type/mode for $($entry.FullName)"
            }
        }
    } finally {
        $produced.Dispose()
    }

    # Exercise the repo-side loader without mutating the checkout inventory.
    $originalHelper = $helper
    $inventoryText = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot '../release/bundle.tsv'))
    $isolated = Join-Path $temp 'isolated'
    New-Item -ItemType Directory -Path (Join-Path $isolated 'scripts'), (Join-Path $isolated 'release') | Out-Null
    $helper = Join-Path $isolated 'scripts/release-windows-zip.ps1'
    Copy-Item -LiteralPath $originalHelper -Destination $helper
    $badInventories = @(
        $inventoryText.Replace("LICENSE`tLICENSE", "README.md`tLICENSE"),
        $inventoryText.Replace("LICENSE`tLICENSE", "../LICENSE`tLICENSE"),
        $inventoryText.Replace("LICENSE`tLICENSE", "LICENSE`t/absolute"),
        $inventoryText.Replace("LICENSE`tLICENSE", "LICENSE`tconfig/../LICENSE"),
        $inventoryText.Replace("LICENSE`tLICENSE", "--option`tLICENSE"),
        $inventoryText.Replace('0644', '0777'),
        $inventoryText.Replace('{binary}', '{unknown}'),
        ($inventoryText + "LICENSE`tLICENSE`t0644`n"),
        $inventoryText.Replace("`t", ' ')
    )
    foreach ($badInventory in $badInventories) {
        [System.IO.File]::WriteAllText((Join-Path $isolated 'release/bundle.tsv'), $badInventory)
        Assert-HelperFailureWithMessage $productionArchive 'inventory'
    }
    [System.IO.File]::WriteAllText((Join-Path $isolated 'release/bundle.tsv'), $inventoryText)
    Assert-HelperSuccess $productionArchive
    $helper = $originalHelper

    $cases = @(
        @{ Name = 'empty'; Omit = $canonicalNames },
        @{ Name = 'missing'; Omit = @('README.md') },
        @{ Name = 'unexpected'; Extra = @('unexpected.txt') },
        @{ Name = 'duplicate'; Extra = @('README.md') },
        @{ Name = 'directory'; Extra = @('config/examples/') },
        @{ Name = 'traversal'; Extra = @('../escape.txt') },
        @{ Name = 'backslash'; Extra = @('bad\name.txt') },
        @{ Name = 'unexpected-executable'; Extra = @('unexpected.exe') },
        @{ Name = 'dos-directory'; Attributes = @{ 'README.md' = 0x10 } },
        @{ Name = 'dos-volume-label'; Attributes = @{ 'README.md' = 0x08 }; Expected = 'DOS volume-label' },
        @{ Name = 'unsupported-flags'; Flags = 0x10; Expected = 'unsupported general-purpose flags' },
        @{ Name = 'data-descriptor'; Flags = 0x08; Expected = 'data-descriptor flag' },
        @{ Name = 'central-encryption'; Flags = 0x2000; Expected = 'encryption flag' },
        @{ Name = 'unix-link'; Attributes = @{ 'README.md' = -1610612736 } },
        @{ Name = 'wrong-support-mode'; Attributes = @{ 'README.md' = (0x180 -shl 16) }; Expected = 'unexpected mode' },
        @{ Name = 'wrong-binary-mode'; Attributes = @{ 'telltale.exe' = (0x1A4 -shl 16) }; Expected = 'unexpected mode' },
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

# Expected negative helper invocations leave LASTEXITCODE nonzero. Reaching this
# point means every assertion passed, so report the suite result explicitly.
exit 0
