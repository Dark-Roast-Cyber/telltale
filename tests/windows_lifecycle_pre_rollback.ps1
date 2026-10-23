# Temporary synthetic CI investigation. Remove after the sharing-refusal diagnosis.
# Logs/backtraces lose staged files during rollback; inspect the catch-local error
# immediately before recovery without changing the production installer source.
$script:testPreRollbackBreakpoint = $null
$script:testPreRollbackReport = $null
$script:testPreRollbackQueryPath = $null
$script:testPreRollbackProbe = $null
$script:testReplacementLine = 0
$script:testPreRollbackControlArmed = $false
$script:testPreRollbackControlStream = $null
$script:testPreRollbackControlHash = $null

function Assert-TestPreRollbackQuery([string]$Path, $Refusal) {
    if ($env:GITHUB_ACTIONS -cne 'true' -or $script:testScheduler -cne 'substituted' -or
        $null -eq $script:testPreRollbackReport -or $Path -cne $script:testPreRollbackQueryPath -or
        -not [object]::ReferenceEquals($Refusal, $script:testPreRollbackProbe) -or $null -eq $Refusal -or
        [IO.Path]::GetFileName($Path) -cnotin @('telltale.exe', 'staged.exe', 'previous.exe') -or
        @(Get-TestExceptionChain $Refusal.Exception | Where-Object { $_.hresult -eq -2147024864 }).Count -eq 0) {
        throw 'Pre-rollback query requires the current exact synthetic leaf and its sharing refusal.'
    }
}

function Write-TestPreRollbackRefusal($Failure, [string]$Install, [string]$Data) {
    # One first replacement refusal across the matrix, plus the explicit control.
    if ($env:GITHUB_ACTIONS -cne 'true' -or $script:testScheduler -cne 'substituted' -or
        $null -ne $script:testPreRollbackReport -or $null -eq $Failure -or
        -not [string]::Equals($Failure.InvocationInfo.ScriptName, $installer, [StringComparison]::OrdinalIgnoreCase) -or
        $Failure.InvocationInfo.ScriptLineNumber -ne $script:testReplacementLine -or
        @(Get-TestExceptionChain $Failure.Exception | Where-Object { $_.hresult -eq -2147024864 }).Count -eq 0 -or
        $null -eq $script:testLayout -or $script:testLayout.Count -ne 2 -or
        $Install -cne $script:testLayout.InstallDirectory -or $Data -cne $script:testLayout.DataDirectory) { return }
    $script:testPreRollbackReport = [ordered]@{
        phase = 'before-installer-rollback'; observed_utc = [DateTime]::UtcNow.ToString('o')
        scenario_sha256 = Get-TTTextHash $script:testScenario; original_error = Get-TestErrorSummary $Failure
        limitation = 'pre-rollback probes and resource users are later than the failed native call, not proof of lock ownership'
        files = @()
    }
    foreach ($name in @('telltale.exe', 'staged.exe', 'previous.exe')) {
        $entry = [ordered]@{ name = $name; state = 'unknown' }
        try {
            $path = [IO.Path]::Combine($Install, $name)
            $path = Assert-TestDiagnosticTarget $path -FixedLeaf -AllowMissing
            if (Test-Path -LiteralPath $path) {
                $entry.state = 'present'
                try { Assert-TTUnlocked $path; $entry.exclusive_probe = 'available' }
                catch {
                    $probeFailure = $_
                    $entry.exclusive_probe = 'refused'
                    $entry.probe_error = @(Get-TestExceptionChain $probeFailure.Exception)
                    if (@($entry.probe_error | Where-Object { $_.hresult -eq -2147024864 }).Count -gt 0) {
                        $script:testPreRollbackQueryPath = $path
                        $script:testPreRollbackProbe = $probeFailure
                        try { $entry.lock_users = Get-TestLockUsers $path $probeFailure -BeforeRollback }
                        finally { $script:testPreRollbackQueryPath = $null; $script:testPreRollbackProbe = $null }
                    }
                }
            } else { $entry.state = 'missing' }
        } catch { $entry.error = @(Get-TestExceptionChain $_.Exception) }
        $script:testPreRollbackReport.files += $entry
    }
    Write-Host ('Windows lifecycle pre-rollback refusal: ' + ($script:testPreRollbackReport | ConvertTo-Json -Depth 12 -Compress))
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
    $script:testReplacementLine = $replacement[0]
    $rollbackLine = $rollback[0]
    $script:testPreRollbackBreakpoint = Set-PSBreakpoint -Script $installer -Line $rollbackLine -Action {
        try { Write-TestPreRollbackRefusal $failure $install $data }
        catch {
            # Diagnostics must not replace the installer error or enter a debugger.
            try { Write-Host 'Windows lifecycle pre-rollback refusal: unknown; capture failed.' } catch { }
        }
    }
}

function Stop-TestPreRollbackCapture {
    if ($null -ne $script:testPreRollbackBreakpoint) {
        try { Remove-PSBreakpoint -Breakpoint $script:testPreRollbackBreakpoint }
        catch {
            if (-not $script:firstFailureReported) { throw }
            try { Write-Host 'Windows lifecycle breakpoint cleanup: unknown; original failure retained.' } catch { }
        } finally { $script:testPreRollbackBreakpoint = $null }
    }
}

function Invoke-TestPreRollbackControl([string]$Binary) {
    if ($env:GITHUB_ACTIONS -cne 'true') { return }
    $layout = New-TestLayout 'pre-rollback-control'
    Assert-Fails { Get-TestLockUsers (Join-Path $layout.InstallDirectory 'staged.exe') -BeforeRollback } 'pre-rollback query rejects calls outside an active refusal'
    & $installer @layout -DevelopmentBinary $Binary
    $previous = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
    $receiptPath = Join-Path $layout.InstallDirectory 'install-receipt.json'
    $receiptHash = Get-TTHash $receiptPath
    $controlBreakpoint = Set-PSBreakpoint -Script $installer -Line $script:testReplacementLine -Action {
        if ($script:testPreRollbackControlArmed -and $script:testScenario -ceq 'pre-rollback-control') {
            $script:testPreRollbackControlArmed = $false
            $path = Assert-TestDiagnosticTarget $stage
            $script:testPreRollbackControlHash = Get-TTHash $path
            $script:testPreRollbackControlStream = [IO.File]::Open($path, 'Open', 'Read', 'Read')
        }
    }
    $script:testPreRollbackControlArmed = $true
    $errors = @(); $failed = $false
    try {
        try { & $installer @layout -DevelopmentBinary $Binary -ErrorVariable errors | Out-Null }
        catch { $failed = $true }
        Assert-True $failed 'controlled installer failure still propagates'
        Assert-True ($null -ne (Get-TestSharingError $errors)) 'controlled installer retains its original sharing error'
        Assert-True ($null -ne $script:testPreRollbackControlStream -and $script:testPreRollbackControlStream.CanRead) 'capture does not release the controlled handle'
        Assert-True ($null -ne $script:testPreRollbackReport -and $script:testPreRollbackReport.phase -ceq 'before-installer-rollback' -and $script:testPreRollbackReport.original_error.line -eq $script:testReplacementLine) 'controlled replacement refusal captured before rollback'
        $stage = Join-Path $layout.InstallDirectory 'staged.exe'
        $stagedReport = @($script:testPreRollbackReport.files | Where-Object { $_.name -ceq 'staged.exe' })
        Assert-True ($stagedReport.Count -eq 1 -and $stagedReport[0].state -ceq 'present' -and $stagedReport[0].exclusive_probe -ceq 'refused' -and (Get-TTHash $stage) -ceq $script:testPreRollbackControlHash) 'controlled stage remains locked and byte-identical'
        Assert-True ($stagedReport[0].lock_users.scope -ceq 'exact synthetic staged.exe') 'pre-rollback resource query retains its exact guarded scope'
        Assert-True ((Get-TTHash (Join-Path $layout.InstallDirectory 'telltale.exe')) -ceq $previous.binary_sha256 -and (Get-TTHash $receiptPath) -ceq $receiptHash) 'pre-rollback capture preserves installed binary and receipt'
        Assert-True (Test-Path -LiteralPath (Join-Path $layout.InstallDirectory 'transaction.json')) 'controlled recovery failure retains its journal'
    } finally {
        $script:testPreRollbackControlArmed = $false
        Remove-PSBreakpoint -Breakpoint $controlBreakpoint
        if ($null -ne $script:testPreRollbackControlStream) { $script:testPreRollbackControlStream.Dispose(); $script:testPreRollbackControlStream = $null }
    }
    # Only this control's known handle was released, outside the observer. Resume
    # real recovery once, then observe the first refusal in the unchanged matrix.
    $script:testPreRollbackReport = $null
    & $installer @layout -DevelopmentBinary $Binary
    & $uninstaller @layout -Confirm:$false
    Write-Host 'Windows lifecycle pre-rollback control passed; first-refusal capture armed for the matrix.'
}
