param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,

    [string]$DumpbinPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-RegularFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description is missing or is not a regular file: $Path"
    }

    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not be a reparse point: $Path"
    }
    return $item.FullName
}

function Find-Dumpbin {
    if ($DumpbinPath) {
        return Resolve-RegularFile -Path $DumpbinPath -Description 'dumpbin inspection tool'
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vswhere = Resolve-RegularFile -Path $vswhere -Description 'Visual Studio locator'
    $installationPath = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($installationPath)) {
        throw 'Could not locate a Visual Studio installation with the x64 C++ toolchain.'
    }

    $candidates = @(Get-ChildItem -LiteralPath (Join-Path $installationPath 'VC\Tools\MSVC') -Directory |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName 'bin\Hostx64\x64\dumpbin.exe' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($candidates.Count -eq 0) {
        throw 'Could not locate dumpbin.exe in the selected Visual Studio C++ toolchain.'
    }
    return Resolve-RegularFile -Path $candidates[0] -Description 'dumpbin inspection tool'
}

$binary = Resolve-RegularFile -Path $BinaryPath -Description 'Windows release binary'
$dumpbin = Find-Dumpbin

$dependencyOutput = @(& $dumpbin /DEPENDENTS $binary 2>&1 | ForEach-Object { $_.ToString() })
if ($LASTEXITCODE -ne 0) {
    throw "dumpbin dependency inspection failed with exit code $LASTEXITCODE."
}

$dependencyText = $dependencyOutput -join "`n"
if ($dependencyText -notmatch '(?im)^\s*Image has the following dependencies:\s*$') {
    throw 'dumpbin output did not contain a PE dependency table.'
}

$dependencies = @([regex]::Matches($dependencyText, '(?im)^\s*([A-Z0-9._-]+\.dll)\s*$') |
    ForEach-Object { $_.Groups[1].Value })
if ($dependencies.Count -eq 0) {
    throw 'dumpbin dependency inspection returned no PE imports.'
}
$forbidden = @($dependencies | Where-Object {
    $_ -match '^(VCRUNTIME|MSVCP|MSVCR|CONCRT).*\.dll$'
} | Sort-Object -Unique)

if ($forbidden.Count -ne 0) {
    throw "Windows release binary imports forbidden redistributable MSVC runtime DLLs: $($forbidden -join ', ')"
}

Write-Output "Windows runtime linkage verified: $binary"
Write-Output "PE dependencies inspected with: $dumpbin"
