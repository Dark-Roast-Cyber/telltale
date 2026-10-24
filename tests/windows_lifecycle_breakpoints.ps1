# Portable engine-level proof of the real breakpoint actions. Windows File.Replace
# sharing and native resource attribution remain owned by the lifecycle control.
#Requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows_lifecycle_pre_rollback.ps1')
$temp = Join-Path ([IO.Path]::GetTempPath()) ('telltale-breakpoint-test-' + [guid]::NewGuid())
[IO.Directory]::CreateDirectory($temp) | Out-Null
$target = Join-Path $temp 'synthetic-installer.ps1'
$stage = Join-Path $temp 'staged.exe'
$rollbackMarker = Join-Path $temp 'rollback-marker'
[IO.File]::WriteAllText($stage, 'synthetic breakpoint payload')
[IO.File]::WriteAllText($target, @'
param([string]$Stage, [string]$Install, [string]$Data)
$script:testPreRollbackControlArmed = $false
try {
    [IO.File]::ReadAllText($stage) | Out-Null
    throw [IO.IOException]::new('synthetic target failure')
} catch {
    $failure = $_
    [IO.File]::WriteAllText($data, 'rollback')
    throw
}
'@)
# These stand-ins validate only action argument/scope dispatch. They perform no
# Windows ownership, reparse-point or resource-user query; never claim that proof.
function Get-TestExceptionChain($Exception) {
    $chain = @()
    for ($depth = 0; $null -ne $Exception -and $depth -lt 8; $depth++) {
        $chain += @{ type = $Exception.GetType().FullName; hresult = $Exception.HResult }
        $Exception = $Exception.InnerException
    }
    return $chain
}
function Assert-TestDiagnosticTarget([string]$Path, $Context) {
    if ($Path -cne $Context.Stage) { throw 'Unexpected synthetic control target.' }
    return $Path
}
function Get-TTHash([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
function Write-TestPreRollbackRefusal($Context, $Failure, [string]$Install, [string]$Data) {
    $Context.Report = [object]::ReferenceEquals($Context, $Context.Identity) -and
        $Failure.InvocationInfo.ScriptName -ceq $Context.Installer -and
        $Failure.InvocationInfo.ScriptLineNumber -eq 5 -and $Install -ceq $Context.Stage -and
        $Data -ceq $Context.Marker -and (Test-Path -LiteralPath $Context.Stage) -and
        -not (Test-Path -LiteralPath $Context.Marker)
}
$context = @{
    Installer = $target; Stage = $stage; Marker = $rollbackMarker; Identity = $null
    Scenario = 'pre-rollback-control'; ControlArmed = $true; ControlStream = $null
    ControlHash = $null; ControlHits = 0; ControlErrors = @(); ObserverHits = 0; ObserverErrors = @(); Report = $false
}
$context.Identity = $context
$control = $null; $observer = $null
try {
    $control = New-TestPreRollbackBreakpoint $context 4 -Control
    $observer = New-TestPreRollbackBreakpoint $context 8
    $failed = $false
    try { & $target -Stage $stage -Install $stage -Data $rollbackMarker }
    catch { $failed = $_.InvocationInfo.ScriptName -ceq $target -and $_.InvocationInfo.ScriptLineNumber -eq 5 }
    if (-not $failed -or $control.HitCount -ne 1 -or $context.ControlHits -ne 1 -or
        $observer.HitCount -ne 1 -or $context.ObserverHits -ne 1 -or
        $context.ControlErrors.Count -ne 0 -or $context.ObserverErrors.Count -ne 0 -or
        $context.ControlArmed -or $null -eq $context.ControlStream -or -not $context.ControlStream.CanRead -or
        -not $context.Report -or -not (Test-Path -LiteralPath $rollbackMarker) -or
        (Get-TTHash $stage) -cne $context.ControlHash) {
        throw 'Breakpoint actions failed scope, dispatch, order, error propagation or byte-preservation proof.'
    }
    # Deliberately corrupt only the portable fixture target: swallowed action
    # errors must be visible in explicit context, not mistaken for a valid lock.
    $context.Stage = Join-Path $temp 'different-target'
    $context.ControlArmed = $true
    try { & $target -Stage $stage -Install $stage -Data $rollbackMarker } catch { }
    if ($context.ControlErrors.Count -eq 0) { throw 'Action exception was not retained in the bounded context.' }
    Write-Output 'PowerShell breakpoint scope/order/error tests passed (not native Windows sharing validation).'
} finally {
    if ($null -ne $control) { Remove-PSBreakpoint -Breakpoint $control }
    if ($null -ne $observer) { Remove-PSBreakpoint -Breakpoint $observer }
    if ($null -ne $context.ControlStream) { $context.ControlStream.Dispose() }
    foreach ($path in @($target, $stage, $rollbackMarker)) {
        if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
    }
    [IO.Directory]::Delete($temp)
}
