# Temporary synthetic CI investigation. Remove after the sharing-refusal diagnosis.
# Breakpoint actions execute in the target script's scope. Their breakpoint object
# carries the test context explicitly; never resolve test state through $script:.
$script:testPreRollbackContext = $null

function Assert-TestPreRollbackQuery([string]$Path, $Refusal, $Context) {
    if ($env:GITHUB_ACTIONS -cne 'true' -or $null -eq $Context -or $Context.Scheduler -cne 'substituted' -or
        $null -eq $Context.Report -or $Path -cne $Context.QueryPath -or
        -not [object]::ReferenceEquals($Refusal, $Context.Probe) -or $null -eq $Refusal -or
        [IO.Path]::GetFileName($Path) -cnotin @('telltale.exe', 'staged.exe', 'previous.exe') -or
        @(Get-TestExceptionChain $Refusal.Exception | Where-Object { $_.hresult -eq -2147024864 }).Count -eq 0) {
        throw 'Pre-rollback query requires the current exact synthetic leaf and its sharing refusal.'
    }
}

function Write-TestPreRollbackRefusal($Context, $Failure, [string]$Install, [string]$Data) {
    # One first replacement refusal across the matrix, plus the explicit control.
    if ($env:GITHUB_ACTIONS -cne 'true' -or $Context.Scheduler -cne 'substituted' -or
        $null -ne $Context.Report -or $null -eq $Failure -or
        -not [string]::Equals($Failure.InvocationInfo.ScriptName, $Context.Installer, [StringComparison]::OrdinalIgnoreCase) -or
        $Failure.InvocationInfo.ScriptLineNumber -ne $Context.ReplacementLine -or
        @(Get-TestExceptionChain $Failure.Exception | Where-Object { $_.hresult -eq -2147024864 }).Count -eq 0 -or
        $null -eq $Context.Layout -or $Context.Layout.Count -ne 2 -or
        $Install -cne $Context.Layout.InstallDirectory -or $Data -cne $Context.Layout.DataDirectory) { return }
    $Context.Report = [ordered]@{
        phase = 'before-installer-rollback'; observed_utc = [DateTime]::UtcNow.ToString('o')
        scenario_sha256 = Get-TTTextHash $Context.Scenario; original_error = Get-TestErrorSummary $Failure
        limitation = 'pre-rollback probes and resource users are later than the failed native call, not proof of lock ownership'
        files = @()
    }
    foreach ($name in @('telltale.exe', 'staged.exe', 'previous.exe')) {
        $entry = [ordered]@{ name = $name; state = 'unknown' }
        try {
            $path = [IO.Path]::Combine($Install, $name)
            $path = Assert-TestDiagnosticTarget $path -FixedLeaf -AllowMissing -Context $Context
            if (Test-Path -LiteralPath $path) {
                $entry.state = 'present'
                try { Assert-TTUnlocked $path; $entry.exclusive_probe = 'available' }
                catch {
                    $probeFailure = $_
                    $entry.exclusive_probe = 'refused'
                    $entry.probe_error = @(Get-TestExceptionChain $probeFailure.Exception)
                    if (@($entry.probe_error | Where-Object { $_.hresult -eq -2147024864 }).Count -gt 0) {
                        $Context.QueryPath = $path
                        $Context.Probe = $probeFailure
                        try { $entry.lock_users = Get-TestLockUsers $path $probeFailure -BeforeRollback -Context $Context }
                        finally { $Context.QueryPath = $null; $Context.Probe = $null }
                    }
                }
            } else { $entry.state = 'missing' }
        } catch { $entry.error = @(Get-TestExceptionChain $_.Exception) }
        $Context.Report.files += $entry
    }
    Write-Host ('Windows lifecycle pre-rollback refusal: ' + ($Context.Report | ConvertTo-Json -Depth 12 -Compress))
}

function New-TestPreRollbackBreakpoint($Context, [int]$Line, [switch]$Control) {
    $action = if ($Control) {
        {
            $context = $_.TelltaleContext
            $context.ControlHits++
            try {
                if ($context.ControlArmed -and $context.Scenario -ceq 'pre-rollback-control') {
                    $context.ControlArmed = $false
                    $path = Assert-TestDiagnosticTarget $stage -Context $context
                    $context.ControlHash = Get-TTHash $path
                    $context.ControlStream = [IO.File]::Open($path, 'Open', 'Read', 'Read')
                }
            } catch { $context.ControlErrors = @(Get-TestExceptionChain $_.Exception) }
        }
    } else {
        {
            $context = $_.TelltaleContext
            $context.ObserverHits++
            try { Write-TestPreRollbackRefusal $context $failure $install $data }
            catch {
                $context.ObserverErrors = @(Get-TestExceptionChain $_.Exception)
                try { Write-Host 'Windows lifecycle pre-rollback refusal: unknown; capture failed.' } catch { }
            }
        }
    }
    $breakpoint = Set-PSBreakpoint -Script $Context.Installer -Line $Line -Action $action
    $breakpoint | Add-Member -NotePropertyName TelltaleContext -NotePropertyValue $Context
    return $breakpoint
}

function Start-TestPreRollbackCapture {
    if ($env:GITHUB_ACTIONS -cne 'true') { return }
    $lines = [IO.File]::ReadAllLines($installer)
    $replacement = @(); $rollback = @()
    for ($index = 0; $index -lt $lines.Length; $index++) {
        if ($lines[$index].Trim() -ceq 'if (Test-Path -LiteralPath $binary) { [IO.File]::Replace($stage, $binary, (Join-Path $install ''previous.exe'')) }') { $replacement += $index + 1 }
        if ($lines[$index].Trim() -ceq 'try { Restore-TTTransaction $install $data | Out-Null }') { $rollback += $index + 1 }
    }
    if ($replacement.Count -ne 1 -or $rollback.Count -ne 1 -or $rollback[0] -le $replacement[0] -or
        $lines[$rollback[0] - 2].Trim() -cne '$failure = $_') { throw 'Installer catch/replacement anchors changed; do not guess a capture location.' }
    $script:testPreRollbackContext = @{
        Installer = $installer; Parent = $script:testParent; Root = $script:temp; Layout = $null; Scenario = $null
        Scheduler = $script:testScheduler; ReplacementLine = $replacement[0]; Breakpoint = $null
        Report = $null; QueryPath = $null; Probe = $null; ObserverHits = 0; ObserverErrors = @()
        ControlArmed = $false; ControlStream = $null; ControlHash = $null; ControlHits = 0; ControlErrors = @()
    }
    $script:testPreRollbackContext.Breakpoint = New-TestPreRollbackBreakpoint $script:testPreRollbackContext $rollback[0]
}

function Stop-TestPreRollbackCapture {
    if ($null -ne $script:testPreRollbackContext) {
        try { Remove-PSBreakpoint -Breakpoint $script:testPreRollbackContext.Breakpoint }
        catch {
            if (-not $script:firstFailureReported) { throw }
            try { Write-Host 'Windows lifecycle breakpoint cleanup: unknown; original failure retained.' } catch { }
        } finally { $script:testPreRollbackContext = $null }
    }
}

function Invoke-TestPreRollbackControl([string]$Binary) {
    if ($env:GITHUB_ACTIONS -cne 'true') { return }
    $context = $script:testPreRollbackContext
    $layout = New-TestLayout 'pre-rollback-control'
    Assert-Fails { Get-TestLockUsers (Join-Path $layout.InstallDirectory 'staged.exe') -BeforeRollback } 'pre-rollback query rejects calls outside an active refusal'
    & $installer @layout -DevelopmentBinary $Binary
    $previous = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
    $receiptPath = Join-Path $layout.InstallDirectory 'install-receipt.json'
    $receiptHash = Get-TTHash $receiptPath
    $controlBreakpoint = New-TestPreRollbackBreakpoint $context $context.ReplacementLine -Control
    $context.ControlArmed = $true
    $errors = @(); $failed = $false
    try {
        try { & $installer @layout -DevelopmentBinary $Binary -ErrorVariable errors | Out-Null }
        catch { $failed = $true }
        Write-Host ('Windows lifecycle breakpoint control status: ' + (@{ control_hits = $controlBreakpoint.HitCount; control_errors = $context.ControlErrors; observer_hits = $context.Breakpoint.HitCount; observer_errors = $context.ObserverErrors } | ConvertTo-Json -Depth 5 -Compress))
        Assert-True ($context.ControlHits -eq 1 -and $controlBreakpoint.HitCount -eq 1 -and $context.ControlErrors.Count -eq 0) 'control breakpoint hit without a swallowed action error'
        Assert-True $failed 'controlled installer failure still propagates'
        Assert-True ($null -ne (Get-TestSharingError $errors)) 'controlled installer retains its original sharing error'
        Assert-True ($null -ne $context.ControlStream -and $context.ControlStream.CanRead) 'capture does not release the controlled handle'
        Assert-True ($context.ObserverHits -eq 1 -and $context.ObserverErrors.Count -eq 0 -and $null -ne $context.Report -and $context.Report.phase -ceq 'before-installer-rollback' -and $context.Report.original_error.line -eq $context.ReplacementLine) 'controlled replacement refusal captured before rollback'
        $stage = Join-Path $layout.InstallDirectory 'staged.exe'
        $stagedReport = @($context.Report.files | Where-Object { $_.name -ceq 'staged.exe' })
        Assert-True ($stagedReport.Count -eq 1 -and $stagedReport[0].state -ceq 'present' -and $stagedReport[0].exclusive_probe -ceq 'refused' -and (Get-TTHash $stage) -ceq $context.ControlHash) 'controlled stage remains locked and byte-identical'
        Assert-True ($stagedReport[0].lock_users.scope -ceq 'exact synthetic staged.exe') 'pre-rollback resource query retains its exact guarded scope'
        Assert-True ((Get-TTHash (Join-Path $layout.InstallDirectory 'telltale.exe')) -ceq $previous.binary_sha256 -and (Get-TTHash $receiptPath) -ceq $receiptHash) 'pre-rollback capture preserves installed binary and receipt'
        Assert-True (Test-Path -LiteralPath (Join-Path $layout.InstallDirectory 'transaction.json')) 'controlled recovery failure retains its journal'
    } finally {
        $context.ControlArmed = $false
        Remove-PSBreakpoint -Breakpoint $controlBreakpoint
        if ($null -ne $context.ControlStream) { $context.ControlStream.Dispose(); $context.ControlStream = $null }
    }
    # Release only this control's handle, outside the observer; perform real
    # recovery once, then observe the first refusal in the unchanged matrix.
    $context.Report = $null
    & $installer @layout -DevelopmentBinary $Binary
    & $uninstaller @layout -Confirm:$false
    Write-Host 'Windows lifecycle pre-rollback control passed; first-refusal capture armed for the matrix.'
}
