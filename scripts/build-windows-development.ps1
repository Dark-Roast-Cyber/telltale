[CmdletBinding()]
param(
    [ValidateSet('x86_64-pc-windows-msvc', 'x86_64-pc-windows-gnu')]
    [string]$Target = 'x86_64-pc-windows-msvc'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Cargo reads exactly one rustflags source, in this order, so the static-CRT
# flag is added to the first one that is set rather than to one Cargo ignores.
function Get-TTStaticCrtFlags([hashtable]$Saved) {
    foreach ($name in @('CARGO_ENCODED_RUSTFLAGS', 'RUSTFLAGS', 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS')) {
        if ($Saved[$name] -match '(?:target-feature(?:=|\s+)[^\s\x1f]*-crt-static)') {
            throw "Conflicting CRT flags in $name; remove the conflict before building."
        }
    }
    if ($null -ne $Saved['CARGO_ENCODED_RUSTFLAGS']) {
        $prefix = $Saved['CARGO_ENCODED_RUSTFLAGS']
        if ($prefix.Length -gt 0) { $prefix += [char]31 }
        return @{ Name = 'CARGO_ENCODED_RUSTFLAGS'; Value = $prefix + '-C' + [char]31 + 'target-feature=+crt-static' }
    }
    if ($null -ne $Saved['RUSTFLAGS']) {
        return @{ Name = 'RUSTFLAGS'; Value = ($Saved['RUSTFLAGS'] + ' -C target-feature=+crt-static').Trim() }
    }
    return @{
        Name = 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS'
        Value = ($Saved['CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS'] + ' -C target-feature=+crt-static').Trim()
    }
}

# Dot-sourcing loads the functions for tests without building.
if ($MyInvocation.InvocationName -eq '.') { return }

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$git = (Get-Command git.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$cargo = (Get-Command cargo.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$variables = @('PATH', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS')
$saved = @{}
foreach ($name in $variables) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

Push-Location -LiteralPath $repo
try {
    $env:PATH = [IO.Path]::GetDirectoryName($git) + [IO.Path]::PathSeparator + $saved['PATH']
    $revision = @(& $git -C $repo rev-parse HEAD)
    if ($LASTEXITCODE -ne 0 -or $revision.Count -ne 1 -or $revision[0] -cnotmatch '^[0-9a-f]{40}$') {
        throw 'Could not resolve the checked-out revision.'
    }
    $expected = $revision[0].Substring(0, 12)
    if ($Target -eq 'x86_64-pc-windows-msvc') {
        $flags = Get-TTStaticCrtFlags $saved
        [Environment]::SetEnvironmentVariable($flags.Name, $flags.Value, 'Process')
    }
    & $cargo build --locked --release --bin telltale --target $Target
    if ($LASTEXITCODE -ne 0) { throw "Development build failed for $Target; no fallback target was attempted." }
    $metadataText = @(& $cargo metadata --locked --no-deps --format-version 1)
    if ($LASTEXITCODE -ne 0) { throw 'Could not locate the Cargo target directory.' }
    $metadata = ($metadataText -join [Environment]::NewLine) | ConvertFrom-Json
    $binary = Join-Path $metadata.target_directory "$Target\release\telltale.exe"
    $version = @(& $binary --version)
    if ($LASTEXITCODE -ne 0 -or $version.Count -ne 1 -or $version[0] -cnotmatch ('^telltale \S+ \(' + [regex]::Escape($expected) + '\)$')) {
        throw 'Built binary provenance does not match the checked-out revision.'
    }
    [pscustomobject][ordered]@{
        binary_path = $binary
        target = $Target
        version = $version[0]
        source_revision = $revision[0]
        sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        development_only = $true
    }
} finally {
    foreach ($name in $variables) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    Pop-Location
}
