param(
    [ValidateSet('suite', 'unset-status', 'inherited-failure', 'after-rejection', 'inspection-failure')]
    [string]$ProcessScenario = 'suite',
    [switch]$NoProcessChildren
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$verifier = Join-Path $root 'scripts\verify-windows-runtime.ps1'
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("telltale windows runtime-{0}" -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $temp | Out-Null

try {
    $binary = Join-Path $temp 'telltale.exe'
    [System.IO.File]::WriteAllBytes($binary, [byte[]](0x4d, 0x5a, 0x00, 0x00))
    $env:FAKE_DUMPBIN_CALLS = Join-Path $temp 'inspector-calls.txt'
    if ($IsWindows) {
        $fakeDumpbin = Join-Path $temp 'dumpbin.cmd'
        @'
@echo off
if not "%~1"=="/DEPENDENTS" exit /b 91
if not exist "%~2" exit /b 92
echo inspected>>"%FAKE_DUMPBIN_CALLS%"
if "%FAKE_DUMPBIN_MODE%"=="failure" exit /b 17
echo Microsoft (R) COFF/PE Dumper Version synthetic
echo.
if not "%FAKE_DUMPBIN_MODE%"=="no-table" echo Image has the following dependencies:
echo.
if "%FAKE_DUMPBIN_MODE%"=="vcruntime" echo     vCrUnTiMe140_1.dll
if "%FAKE_DUMPBIN_MODE%"=="msvcp" echo     MSVCP140.dll
if "%FAKE_DUMPBIN_MODE%"=="msvcr" echo     mSvCr120.dll
if "%FAKE_DUMPBIN_MODE%"=="concrt" echo     CONCRT140.dll
if "%FAKE_DUMPBIN_MODE%"=="system" echo     KERNEL32.dll
if "%FAKE_DUMPBIN_MODE%"=="system" echo     USER32.dll
if "%FAKE_DUMPBIN_MODE%"=="system" echo     ADVAPI32.dll
if "%FAKE_DUMPBIN_MODE%"=="no-table" echo     KERNEL32.dll
if "%FAKE_DUMPBIN_MODE%"=="failure-with-table" echo     KERNEL32.dll
echo.
echo Summary
if "%FAKE_DUMPBIN_MODE%"=="failure-with-table" exit /b 17
exit /b 0
'@ | Set-Content -LiteralPath $fakeDumpbin -Encoding ascii
    }
    else {
        $fakeDumpbin = Join-Path $temp 'dumpbin.sh'
        @'
#!/bin/sh
set -eu
test "$1" = /DEPENDENTS || exit 91
test -f "$2" || exit 92
printf 'inspected\n' >> "$FAKE_DUMPBIN_CALLS"
test "$FAKE_DUMPBIN_MODE" != failure || exit 17
printf 'Microsoft COFF/PE Dumper synthetic\n\n'
test "$FAKE_DUMPBIN_MODE" = no-table || printf 'Image has the following dependencies:\n'
case "$FAKE_DUMPBIN_MODE" in
  vcruntime) printf '    vCrUnTiMe140_1.dll\n';;
  msvcp) printf '    MSVCP140.dll\n';;
  msvcr) printf '    mSvCr120.dll\n';;
  concrt) printf '    CONCRT140.dll\n';;
  system) printf '    KERNEL32.dll\n    USER32.dll\n    ADVAPI32.dll\n';;
  no-table|failure-with-table) printf '    KERNEL32.dll\n';;
esac
printf '\nSummary\n'
test "$FAKE_DUMPBIN_MODE" != failure-with-table || exit 17
exit 0
'@ | Set-Content -LiteralPath $fakeDumpbin -Encoding ascii
        [System.IO.File]::SetUnixFileMode($fakeDumpbin, [System.IO.UnixFileMode]'UserRead, UserWrite, UserExecute')
    }

    function Get-InspectionCount {
        if (Test-Path -LiteralPath $env:FAKE_DUMPBIN_CALLS) {
            return @(Get-Content -LiteralPath $env:FAKE_DUMPBIN_CALLS).Count
        }
        return 0
    }

    function Invoke-Case {
        param(
            [string]$Name,
            [string]$Mode,
            [string]$Path,
            [bool]$ShouldPass,
            [string]$Expected = 'Windows runtime linkage verified:',
            [string]$Inspector = $fakeDumpbin,
            [bool]$ShouldInspect = $true
        )

        $env:FAKE_DUMPBIN_MODE = $Mode
        $before = Get-InspectionCount
        try {
            $output = & $verifier -BinaryPath $Path -DumpbinPath $Inspector 2>&1
            $passed = $true
        }
        catch {
            $output = $_
            $passed = $false
        }
        if ($passed -ne $ShouldPass) {
            throw "Verifier case '$Name' had unexpected result. Output: $($output -join ' ')"
        }
        if ($ShouldPass -and $LASTEXITCODE -ne 0) {
            throw "Verifier case '$Name' left native failure status $LASTEXITCODE after success."
        }
        if (-not (($output -join ' ').Contains($Expected))) {
            throw "Verifier case '$Name' had the wrong diagnostic. Output: $($output -join ' ')"
        }
        $expectedCount = $before + [int]$ShouldInspect
        if ((Get-InspectionCount) -ne $expectedCount) {
            throw "Verifier case '$Name' did not honor the inspection boundary."
        }
        Write-Output "Case passed: $Name"
    }

    switch ($ProcessScenario) {
        'unset-status' {
            Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
            if (Get-Variable -Name LASTEXITCODE -ErrorAction SilentlyContinue) { throw 'Expected unset native status.' }
            Invoke-Case -Name 'unset status under StrictMode' -Mode 'system' -Path $binary -ShouldPass $true
        }
        'inherited-failure' {
            $env:FAKE_DUMPBIN_MODE = 'failure'
            & $fakeDumpbin /DEPENDENTS $binary | Out-Null
            if ($LASTEXITCODE -ne 17) { throw 'Expected inherited native failure.' }
            Invoke-Case -Name 'success after inherited native failure' -Mode 'system' -Path $binary -ShouldPass $true
        }
        'after-rejection' {
            Invoke-Case -Name 'expected inspection rejection' -Mode 'failure' -Path $binary -ShouldPass $false -Expected 'inspection failed with exit code 17'
            Invoke-Case -Name 'successful inspection after rejection' -Mode 'system' -Path $binary -ShouldPass $true
        }
        'inspection-failure' {
            $env:FAKE_DUMPBIN_MODE = 'failure'
            & $verifier -BinaryPath $binary -DumpbinPath $fakeDumpbin
            throw 'Expected an unhandled verifier failure.'
        }
        'suite' {
            foreach ($family in @('vcruntime', 'msvcp', 'msvcr', 'concrt')) {
                Invoke-Case -Name "$family import" -Mode $family -Path $binary -ShouldPass $false -Expected 'forbidden redistributable MSVC runtime DLLs'
            }
            Invoke-Case -Name 'system imports only' -Mode 'system' -Path $binary -ShouldPass $true
            Invoke-Case -Name 'missing dependency table' -Mode 'no-table' -Path $binary -ShouldPass $false -Expected 'did not contain a PE dependency table'
            Invoke-Case -Name 'empty imports' -Mode 'empty' -Path $binary -ShouldPass $false -Expected 'returned no PE imports'
            Invoke-Case -Name 'failed inspection with plausible table' -Mode 'failure-with-table' -Path $binary -ShouldPass $false -Expected 'inspection failed with exit code 17'
            Invoke-Case -Name 'missing binary' -Mode 'system' -Path (Join-Path $temp 'missing.exe') -ShouldPass $false -Expected 'Windows release binary is missing' -ShouldInspect $false
            Invoke-Case -Name 'non-regular binary' -Mode 'system' -Path $temp -ShouldPass $false -Expected 'Windows release binary is missing' -ShouldInspect $false
            Invoke-Case -Name 'missing inspector' -Mode 'system' -Path $binary -ShouldPass $false -Inspector (Join-Path $temp 'missing-inspector') -Expected 'dumpbin inspection tool is missing' -ShouldInspect $false
            Invoke-Case -Name 'non-regular inspector' -Mode 'system' -Path $binary -ShouldPass $false -Inspector $temp -Expected 'dumpbin inspection tool is missing' -ShouldInspect $false

            # Symlink creation is a required test capability, never a silent skip.
            $binaryLink = Join-Path $temp 'binary-link.exe'
            $inspectorLink = Join-Path $temp 'inspector-link'
            New-Item -ItemType SymbolicLink -Path $binaryLink -Target $binary | Out-Null
            New-Item -ItemType SymbolicLink -Path $inspectorLink -Target $fakeDumpbin | Out-Null
            Invoke-Case -Name 'reparse binary' -Mode 'system' -Path $binaryLink -ShouldPass $false -Expected 'Windows release binary must not be a reparse point' -ShouldInspect $false
            Invoke-Case -Name 'reparse inspector' -Mode 'system' -Path $binary -Inspector $inspectorLink -ShouldPass $false -Expected 'dumpbin inspection tool must not be a reparse point' -ShouldInspect $false

            if (-not $NoProcessChildren) {
                $powerShell = (Get-Process -Id $PID).Path
                $env:FAKE_RUNTIME_TEST_PATH = $PSCommandPath
                foreach ($scenario in @('unset-status', 'inherited-failure', 'after-rejection', 'inspection-failure', 'suite')) {
                    $env:FAKE_RUNTIME_SCENARIO = $scenario
                    # Match the CI runner's native-status epilogue, not merely
                    # pwsh -File (which can hide a leaked nonzero native status).
                    $output = & $powerShell -NoLogo -NoProfile -NonInteractive -Command '$ErrorActionPreference = "Stop"; & $env:FAKE_RUNTIME_TEST_PATH -ProcessScenario $env:FAKE_RUNTIME_SCENARIO -NoProcessChildren; if (Test-Path -LiteralPath variable:\LASTEXITCODE) { exit $LASTEXITCODE }' 2>&1
                    $expectedExit = if ($scenario -eq 'inspection-failure') { 1 } else { 0 }
                    if ($LASTEXITCODE -ne $expectedExit) { throw "Process case '$scenario' exited $LASTEXITCODE. Output: $($output -join ' ')" }
                    $expectedText = if ($scenario -eq 'inspection-failure') { 'inspection failed with exit code 17' } else { "Windows runtime verifier tests passed ($scenario)." }
                    if (-not (($output -join ' ').Contains($expectedText))) { throw "Process case '$scenario' did not reach its expected assertion. Output: $($output -join ' ')" }
                    Write-Output "Process case passed: $scenario (exit $LASTEXITCODE)"
                }
            }
            # The child suite must finish successfully even after this native failure.
            Invoke-Case -Name 'terminal expected inspection rejection' -Mode 'failure' -Path $binary -ShouldPass $false -Expected 'inspection failed with exit code 17'
        }
    }

    Write-Output "Windows runtime verifier tests passed ($ProcessScenario)."
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}

exit 0
