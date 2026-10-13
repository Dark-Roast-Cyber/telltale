#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$InstallDirectory = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs\Telltale'),
    [string]$DataDirectory = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Telltale'),
    [switch]$PurgeData,
    [switch]$PurgeConfiguration
)
. (Join-Path $PSScriptRoot 'windows-lifecycle.ps1')
$install = Get-TTPath $InstallDirectory
$data = Get-TTPath $DataDirectory
Assert-TTDirectories $install $data
if ($PurgeConfiguration -and -not $PurgeData) { throw 'PurgeConfiguration requires PurgeData and separate explicit selection.' }
$inspectionMutex = Open-TTLifecycleMutex
try {
if (Test-Path -LiteralPath (Join-Path $install 'transaction.json')) {
    throw 'An installation transaction requires recovery; rerun the installer first.'
}
$receipt = Get-TTReceipt $install $data
$task = if ($null -ne $receipt) { Assert-TTTask $receipt } else { $null }
$binary = Join-Path $install 'telltale.exe'
if ($null -eq $receipt -and (Test-Path -LiteralPath $binary)) { throw 'Unowned executable at the installation path; retained.' }
$orphanLock = Join-Path $install '.lifecycle.lock'
$ownedOrphanLock = $null -eq $receipt -and (Test-Path -LiteralPath $orphanLock)
if ($ownedOrphanLock) {
    Assert-TTFile $orphanLock -Owned
    if ([IO.File]::ReadAllText($orphanLock) -cne "$script:TTInstaller $script:TTSid") { throw 'Unrecognized orphan lifecycle lock; retained.' }
}
$snapshot = [ordered]@{}
foreach ($path in @((Join-Path $install 'install-receipt.json'), $orphanLock, (Join-Path $data 'data-receipt.json'))) {
    $snapshot[$path] = if (Test-Path -LiteralPath $path) { Get-TTHash $path } else { $null }
}
$legacy = Join-Path $data 'telltale.exe'
if (Test-Path -LiteralPath $legacy) { Write-Output "Legacy manual installation detected and retained: $legacy. Its presence does not prove installer ownership." }
$ownedData = Get-TTDataReceipt $data
$performPurge = $PurgeData -and $null -ne $ownedData
$purgeFiles = if ($performPurge) { @(Get-TTPurgeFiles $data) } else { @() }
if ($PurgeData -and -not $performPurge) { Write-Output 'No managed data receipt remains; unowned data is retained.' }
$configFiles = @()
if ($PurgeConfiguration) {
    $configFiles = @(Get-TTConfigurationFiles)
}
$plan = @()
if ($null -ne $receipt) {
    $plan += $binary, (Join-Path $install 'install-receipt.json')
    if ($null -ne $task) { $plan += 'Scheduled Task \TelltaleScan (exact managed declaration)' }
    if ($receipt.path_added) {
        $plan += "User PATH entry: $install"
        $removedAlready = $receipt.PSObject.Properties['path_removal_after'] -and (Get-TTUserPath) -ceq $receipt.path_removal_after
        if (-not $removedAlready) { Get-TTPathWithoutEntry (Get-TTUserPath) $install | Out-Null }
    }
}
$plan += $purgeFiles
$plan += $configFiles
if ($ownedOrphanLock) { $plan += $orphanLock }
Write-Output 'Cleanup plan:'
foreach ($item in $plan) { Write-Output "  $item" }
if (-not $PurgeData) { Write-Output "Retained logs, state, history and configuration. Data directory: $data" }
if ($null -eq $receipt -and -not $performPurge -and $configFiles.Count -eq 0 -and -not $ownedOrphanLock) { Write-Output 'No managed installation remains. No resources changed.'; return }
} finally { Close-TTLifecycleMutex $inspectionMutex }
$operation = if ($PurgeData) { 'Uninstall and permanently purge the listed Telltale data' } else { 'Uninstall managed application; retain data' }
if (-not $PSCmdlet.ShouldProcess(($plan -join '; '), $operation)) { return }
$lock = $null
$mutex = $null
try {
    $mutex = Open-TTLifecycleMutex
    Assert-TTDirectories (Get-TTPath $install) (Get-TTPath $data)
    if (Test-Path -LiteralPath (Join-Path $install 'transaction.json')) { throw 'An installation transaction appeared; recover it before cleanup.' }
    foreach ($path in $snapshot.Keys) {
        $current = if (Test-Path -LiteralPath $path) { Get-TTHash $path } else { $null }
        if ($current -cne $snapshot[$path]) { throw 'Lifecycle ownership changed while reviewing the plan; inspect and rerun cleanup.' }
    }
    if ($performPurge -and ((@(Get-TTPurgeFiles $data) -join "`n") -cne ($purgeFiles -join "`n"))) { throw 'Purge inventory changed while reviewing the plan; inspect and rerun cleanup.' }
    if ($PurgeConfiguration -and ((@(Get-TTConfigurationFiles) -join "`n") -cne ($configFiles -join "`n"))) { throw 'Configuration inventory changed while reviewing the plan; inspect and rerun cleanup.' }
    if ($null -ne $receipt) {
        $lock = Open-TTLock $install
        # Recheck identities after acquiring the exclusive lifecycle lock.
        $receipt = Get-TTReceipt $install $data
        $task = Assert-TTTask $receipt
        if ($null -ne $task -and $task.State -eq 4) {
            $task.Stop(0)
            for ($attempt = 0; $attempt -lt 50 -and $task.State -eq 4; $attempt++) { Start-Sleep -Milliseconds 100 }
            if ($task.State -eq 4) { throw 'Managed Scheduled Task did not stop.' }
        }
        Assert-TTUnlocked $binary
        $receipt | Add-Member -NotePropertyName uninstalling -NotePropertyValue $true -Force
        Write-TTJson (Join-Path $install 'install-receipt.json') $receipt
        if ($null -ne $task) {
            Remove-TTTask $task
            $receipt.task_xml = $null
            Write-TTJson (Join-Path $install 'install-receipt.json') $receipt
        }
        if ($receipt.path_added) {
            $userPath = Get-TTUserPath
            $removedAlready = $receipt.PSObject.Properties['path_removal_after'] -and $userPath -ceq $receipt.path_removal_after
            if (-not $removedAlready) {
                $after = Get-TTPathWithoutEntry $userPath $install
                $receipt | Add-Member -NotePropertyName path_removal_before -NotePropertyValue $userPath -Force
                $receipt | Add-Member -NotePropertyName path_removal_after -NotePropertyValue $after -Force
                Write-TTJson (Join-Path $install 'install-receipt.json') $receipt
                Set-TTUserPath $after -Expected $userPath
            }
            $receipt.path_added = $false
            Write-TTJson (Join-Path $install 'install-receipt.json') $receipt
        }
        if (Test-Path -LiteralPath $binary) { Remove-Item -LiteralPath $binary -Force }
        Remove-Item -LiteralPath (Join-Path $install 'install-receipt.json') -Force
        $lock.Dispose(); $lock = $null
        Assert-TTFile (Join-Path $install '.lifecycle.lock') -Owned
        Remove-Item -LiteralPath (Join-Path $install '.lifecycle.lock') -Force
        # Never recurse: unrelated files leave the directory in place.
        if ($receipt.PSObject.Properties['directory_created'] -and $receipt.directory_created -and @(Get-ChildItem -LiteralPath $install -Force).Count -eq 0) { [IO.Directory]::Delete($install) }
    } elseif ($ownedOrphanLock) {
        $lock = Open-TTLock $install
        $lock.Dispose(); $lock = $null
        Remove-Item -LiteralPath $orphanLock -Force
    }
    if ($performPurge) {
        $dataReceipt = Get-TTDataReceipt $data
        # Rebuild the plan immediately before deleting; all leaves must be recognized.
        foreach ($file in @(Get-TTPurgeFiles $data)) { Remove-Item -LiteralPath $file -Force }
        foreach ($name in @($dataReceipt.directories)) {
            $directory = Get-TTPath (Join-Path $data $name)
            if (Test-Path -LiteralPath $directory) { [IO.Directory]::Delete($directory) }
        }
        Remove-Item -LiteralPath (Join-Path $data 'data-receipt.json') -Force
        if ($dataReceipt.PSObject.Properties['directory_created'] -and $dataReceipt.directory_created -and @(Get-ChildItem -LiteralPath $data -Force).Count -eq 0) { [IO.Directory]::Delete($data) }
        Write-Output 'Explicit purge completed. Agent session stores were outside the cleanup scope.'
    }
    foreach ($file in $configFiles) { Assert-TTFile $file -Owned; Remove-Item -LiteralPath $file -Force }
    Write-Output "Uninstall completed. Retained files, if any, remain under $data; user configuration retained unless explicitly selected."
} catch { throw "Uninstall incomplete; retained ownership metadata permits retry where possible. $_" }
finally {
    if ($null -ne $lock) { $lock.Dispose() }
    if ($null -ne $mutex) { Close-TTLifecycleMutex $mutex }
}
