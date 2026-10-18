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
Write-Output 'Windows development build flag/environment tests passed.'
