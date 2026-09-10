$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$verifier = Join-Path $root 'scripts\verify-windows-runtime.ps1'
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("telltale-windows-runtime-{0}" -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $temp | Out-Null

try {
    $binary = Join-Path $temp 'telltale.exe'
    [System.IO.File]::WriteAllBytes($binary, [byte[]](0x4d, 0x5a, 0x00, 0x00))
    $fakeDumpbin = Join-Path $temp 'dumpbin.cmd'
    @'
@echo off
if "%FAKE_DUMPBIN_MODE%"=="failure" exit /b 17
echo Microsoft (R) COFF/PE Dumper Version synthetic
echo.
echo Image has the following dependencies:
echo.
if "%FAKE_DUMPBIN_MODE%"=="vcruntime" echo     vCrUnTiMe140_1.dll
if "%FAKE_DUMPBIN_MODE%"=="msvcp" echo     MSVCP140.dll
if "%FAKE_DUMPBIN_MODE%"=="concrt" echo     CONCRT140.dll
if "%FAKE_DUMPBIN_MODE%"=="system" echo     KERNEL32.dll
if "%FAKE_DUMPBIN_MODE%"=="system" echo     USER32.dll
if "%FAKE_DUMPBIN_MODE%"=="system" echo     ADVAPI32.dll
echo.
echo Summary
exit /b 0
'@ | Set-Content -LiteralPath $fakeDumpbin -Encoding ascii

    function Invoke-Case {
        param(
            [string]$Name,
            [string]$Mode,
            [string]$Path,
            [bool]$ShouldPass
        )

        $env:FAKE_DUMPBIN_MODE = $Mode
        try {
            $output = & $verifier -BinaryPath $Path -DumpbinPath $fakeDumpbin 2>&1
            $passed = $true
        }
        catch {
            $output = $_
            $passed = $false
        }
        if ($passed -ne $ShouldPass) {
            throw "Verifier case '$Name' had unexpected result. Output: $($output -join ' ')"
        }
    }

    Invoke-Case -Name 'VCRUNTIME import' -Mode 'vcruntime' -Path $binary -ShouldPass $false
    Invoke-Case -Name 'MSVCP import' -Mode 'msvcp' -Path $binary -ShouldPass $false
    Invoke-Case -Name 'CONCRT import' -Mode 'concrt' -Path $binary -ShouldPass $false
    Invoke-Case -Name 'system imports only' -Mode 'system' -Path $binary -ShouldPass $true
    Invoke-Case -Name 'inspection failure' -Mode 'failure' -Path $binary -ShouldPass $false
    Invoke-Case -Name 'missing binary' -Mode 'system' -Path (Join-Path $temp 'missing.exe') -ShouldPass $false
    Invoke-Case -Name 'non-regular binary' -Mode 'system' -Path $temp -ShouldPass $false

    Write-Output 'Windows runtime verifier tests passed.'
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}

exit 0
