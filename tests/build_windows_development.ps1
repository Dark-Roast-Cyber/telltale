Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$helper = Join-Path $PSScriptRoot '..\scripts\build-windows-development.ps1'
$names = @('PATH', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS')
$original = @{}
foreach ($name in $names) { $original[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    foreach ($conflicting in $names[1..3]) {
        foreach ($name in $names[1..3]) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
        $flags = '-C target-feature=-crt-static'
        if ($conflicting -eq 'CARGO_ENCODED_RUSTFLAGS') { $flags = '-C' + [char]31 + 'target-feature=-crt-static' }
        [Environment]::SetEnvironmentVariable($conflicting, $flags, 'Process')
        $expected = @{}
        foreach ($name in $names) { $expected[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
        $rejected = $false
        try { & $helper -Target x86_64-pc-windows-msvc | Out-Null } catch {
            $rejected = $_.Exception.Message -like "Conflicting CRT flags in $conflicting*"
        }
        if (-not $rejected) { throw "Expected bounded conflict from $conflicting." }
        foreach ($name in $names) {
            if ([Environment]::GetEnvironmentVariable($name, 'Process') -cne $expected[$name]) {
                throw "Build helper did not restore $name after failure."
            }
        }
    }
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $original[$name], 'Process') }
}

# Each supported form must carry +crt-static in the source Cargo actually reads.
. $helper
$static = '-C target-feature=+crt-static'
$unit = [string][char]31
$cases = @(
    @{ Saved = @{}; Name = 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS'; Value = $static },
    @{ Saved = @{ CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = '-C opt-level=2' }
        Name = 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS'; Value = "-C opt-level=2 $static" },
    @{ Saved = @{ RUSTFLAGS = '-C opt-level=2'; CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = '-C debuginfo=0' }
        Name = 'RUSTFLAGS'; Value = "-C opt-level=2 $static" },
    @{ Saved = @{ RUSTFLAGS = '' }; Name = 'RUSTFLAGS'; Value = $static },
    @{ Saved = @{ CARGO_ENCODED_RUSTFLAGS = '-C' + $unit + 'opt-level=2'; RUSTFLAGS = '-C debuginfo=0' }
        Name = 'CARGO_ENCODED_RUSTFLAGS'; Value = '-C' + $unit + 'opt-level=2' + $unit + '-C' + $unit + 'target-feature=+crt-static' },
    @{ Saved = @{ CARGO_ENCODED_RUSTFLAGS = '' }
        Name = 'CARGO_ENCODED_RUSTFLAGS'; Value = '-C' + $unit + 'target-feature=+crt-static' }
)
foreach ($case in $cases) {
    $flags = Get-TTStaticCrtFlags $case.Saved
    if ($flags.Name -cne $case.Name -or $flags.Value -cne $case.Value) {
        throw "Static CRT flag was not added to $($case.Name)."
    }
}
Write-Output 'Windows development build flag/environment tests passed.'
