#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ReleaseTag,
    [string]$DevelopmentBinary,
    [string]$InstallDirectory = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs\Telltale'),
    [string]$DataDirectory = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Telltale'),
    [switch]$WithScheduledTask,
    [switch]$AddToPath
)
. (Join-Path $PSScriptRoot 'windows-lifecycle.ps1')
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$install = Get-TTPath $InstallDirectory
$data = Get-TTPath $DataDirectory
Assert-TTDirectories $install $data
if ($ReleaseTag -and $ReleaseTag -cnotmatch '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.(0|[1-9][0-9]*))?$') { throw 'Invalid explicit release tag.' }
if ($ReleaseTag -and $DevelopmentBinary) { throw 'DevelopmentBinary cannot be combined with ReleaseTag.' }
if ($WhatIfPreference) {
    Write-Output "Would verify selected source, then install to $install; task opt-in=$WithScheduledTask; PATH opt-in=$AddToPath."
    return
}

# Verify in a disposable directory before acquiring the install lock or touching destinations.
$temp = Join-Path $script:TTLocal ("telltale-install-{0}" -f [guid]::NewGuid())
$temp = Get-TTPath $temp
New-TTDirectory $temp
$lock = $null
$mutex = $null
try {
    $candidate = Join-Path $temp 'telltale.exe'
    if ($DevelopmentBinary) {
        $inputBinary = Get-TTPath ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DevelopmentBinary))
        Assert-TTFile $inputBinary -DevelopmentSource
        Copy-Item -LiteralPath $inputBinary -Destination $candidate
        Set-TTCreatedOwner $candidate
        $version = Assert-TTVersion $candidate '' ''
        $source = [ordered]@{ kind = 'development-local'; qualification = 'unpublished local build' }
    } else {
        $release = Get-TTRelease $ReleaseTag
        $tag = $release.tag_name
        $sha = Get-TTReleaseSource $tag
        $archiveName = "telltale-$tag-x86_64-pc-windows-msvc.zip"
        Invoke-TTNative 'gh' @('release', 'download', $tag, '--repo', $script:TTRepo, '--pattern', $archiveName, '--pattern', 'SHA256SUMS', '--dir', $temp) | Out-Null
        $archive = Join-Path $temp $archiveName
        $sums = Join-Path $temp 'SHA256SUMS'
        Set-TTCreatedOwner $archive
        Set-TTCreatedOwner $sums
        $archiveHash = Get-TTHash $archive
        Assert-TTReleaseAssets $release $archiveName $archiveHash (Get-TTHash $sums)
        Assert-TTChecksum $sums $archiveName $archiveHash
        # Bind cryptographic verification to the exact tag, commit, digest and release workflow.
        $verified = Invoke-TTNative 'gh' @('attestation', 'verify', $archive, '--repo', $script:TTRepo, '--source-ref', "refs/tags/$tag", '--source-digest', $sha, '--signer-workflow', "$script:TTRepo/.github/workflows/release.yml", '--deny-self-hosted-runners', '--format', 'json')
        $receipts = @($verified | ConvertFrom-Json)
        if ($receipts.Count -eq 0) { throw 'Attestation verification returned no verified receipts.' }
        # Reuse the authoritative nine-member ZIP validator in a child PowerShell (it calls exit).
        $engine = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $shell = Join-Path $PSHOME $engine
        Invoke-TTNative $shell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'release-windows-zip.ps1'), '-ValidateOnly', '-ArchivePath', $archive) | Out-Null
        $zip = [IO.Compression.ZipFile]::OpenRead($archive)
        try { [IO.Compression.ZipFileExtensions]::ExtractToFile($zip.GetEntry('telltale.exe'), $candidate, $false) }
        finally { $zip.Dispose() }
        Set-TTCreatedOwner $candidate
        $version = Assert-TTVersion $candidate $tag.Substring(1) $sha
        # Reject tag/Release changes while downloading and verifying.
        $latestMetadata = Get-TTRelease $tag
        if ($latestMetadata.id -ne $release.id -or (Get-TTReleaseSource $tag) -cne $sha) { throw 'Release identity changed during verification.' }
        Assert-TTReleaseAssets $latestMetadata $archiveName $archiveHash (Get-TTHash $sums)
        $source = [ordered]@{ kind = 'published-release'; tag = $tag; release_id = $release.id; source_sha = $sha; archive = $archiveName; archive_sha256 = $archiveHash; attestation_sha256 = Get-TTTextHash $verified }
    }
    $hash = Get-TTHash $candidate
    if (-not $PSCmdlet.ShouldProcess($install, "Install $version ($($source.kind))")) { return }
    $mutex = Open-TTLifecycleMutex
    Assert-TTDirectories (Get-TTPath $install) (Get-TTPath $data)
    $createdDirectory = -not (Test-Path -LiteralPath $install)
    if (Test-Path -LiteralPath $install) {
        $allowed = @('telltale.exe', 'install-receipt.json', '.lifecycle.lock')
        if (Test-Path -LiteralPath (Join-Path $install 'transaction.json')) { $allowed += 'transaction.json', 'staged.exe', 'previous.exe' }
        foreach ($item in @(Get-ChildItem -LiteralPath $install -Force)) {
            if ($item.Name -cnotin $allowed) { throw 'Installation directory contains unrelated files; refusing ownership.' }
        }
        if (-not (Test-Path -LiteralPath (Join-Path $install 'install-receipt.json')) -and
            -not (Test-Path -LiteralPath (Join-Path $install 'transaction.json')) -and
            @(Get-ChildItem -LiteralPath $install -Force | Where-Object { $_.Name -cne '.lifecycle.lock' }).Count) {
            throw 'Existing installation has no ownership receipt.'
        }
    } else { New-TTDirectory $install }
    $lock = Open-TTLock $install
    $recovery = Restore-TTTransaction $install $data
    $previous = Get-TTReceipt $install $data
    if ($null -ne $previous -and $previous.PSObject.Properties['uninstalling'] -and $previous.uninstalling) { throw 'Complete the interrupted uninstall before installing.' }
    $task = Assert-TTTask $previous
    $taskWasEnabled = $null -ne $task -and $task.Enabled
    if ($null -eq $task -and $null -ne $previous) { $previous.task_xml = $null }
    $binary = Join-Path $install 'telltale.exe'
    Assert-TTUnlocked $binary
    $id = if ($null -ne $previous) { $previous.id } else { [guid]::NewGuid().ToString() }
    $directoryOwned = if ($null -ne $previous) { $previous.PSObject.Properties['directory_created'] -and $previous.directory_created }
        else { $createdDirectory -or ($null -ne $recovery -and $recovery.DirectoryCreated) }
    $pathBefore = if ($AddToPath) { Get-TTUserPath } else { $null }
    $pathAfter = $pathBefore
    $pathOwned = $null -ne $previous -and $previous.path_added
    if ($AddToPath -and -not @($pathBefore -split ';' | Where-Object { $_.TrimEnd('\') -ieq $install }).Count) {
        $pathAfter = if ($pathBefore) { "$pathBefore;$install" } else { $install }
        $pathOwned = $true
    }
    $next = [ordered]@{ installer = $script:TTInstaller; sid = $script:TTSid; id = $id; install = $install; data = $data; directory_created = [bool]$directoryOwned; binary_sha256 = $hash; version = $version; source = $source; path_added = $pathOwned; task_xml = if ($null -ne $previous) { $previous.task_xml } else { $null } }
    Initialize-TTData $data
    $journal = [ordered]@{ previous = $previous; next = $next; task_transition_xml = $null; committed = $false; path_applied = $false; path_changed = $pathBefore -cne $pathAfter; path_before = $pathBefore; path_after = $pathAfter }
    $journalPath = Join-Path $install 'transaction.json'
    Write-TTJson $journalPath $journal
    try {
        $stage = Join-Path $install 'staged.exe'
        # Candidate copying and verification completed outside the installation.
        # A same-volume atomic rename cannot expose a partially copied staged.exe.
        [IO.File]::Move($candidate, $stage)
        if ((Get-TTHash $stage) -cne $hash) { throw 'Staged executable digest mismatch.' }
        if ($null -ne $task) {
            $journal.task_transition_xml = Get-TTTaskEnabledXml $task.Xml $false
            Write-TTJson $journalPath $journal
            $task.Enabled = $false
            $next.task_xml = $task.Xml
            Write-TTJson $journalPath $journal
        }
        if ($WithScheduledTask -and $null -eq $task) {
            # Persist the expected declaration before registration. A crash in the tiny
            # registration/receipt gap fails closed on an unknown task rather than adopting it.
            $next.task_xml = New-TTTaskXml $install $data $id
            Write-TTJson $journalPath $journal
            $next.task_xml = Set-TTTask $next.task_xml -CreateOnly
            Write-TTJson $journalPath $journal
        }
        if (Test-Path -LiteralPath $binary) { [IO.File]::Replace($stage, $binary, (Join-Path $install 'previous.exe')) }
        else { [IO.File]::Move($stage, $binary) }
        if ((Get-TTHash $binary) -cne $hash) { throw 'Installed executable digest mismatch.' }
        Write-TTJson (Join-Path $install 'install-receipt.json') $next
        if ($pathBefore -cne $pathAfter) {
            Set-TTUserPath $pathAfter -Expected $pathBefore
            $journal.path_applied = $true
            Write-TTJson $journalPath $journal
        }
        if ($WithScheduledTask -or $taskWasEnabled) {
            $task = Assert-TTTask $next
            $journal.task_transition_xml = Get-TTTaskEnabledXml $task.Xml $true
            Write-TTJson $journalPath $journal
            $task.Enabled = $true
            $next.task_xml = $task.Xml
            Write-TTJson $journalPath $journal
            Write-TTJson (Join-Path $install 'install-receipt.json') $next
        }
        # A durable commit marker distinguishes final cleanup from rollback after a crash.
        $journal.committed = $true
        Write-TTJson $journalPath $journal
        $backup = Join-Path $install 'previous.exe'
        if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
        Remove-Item -LiteralPath $journalPath -Force
    } catch {
        $failure = $_
        try { Restore-TTTransaction $install $data | Out-Null }
        catch { throw "Installation failed; recovery requires attention. Original: $failure Recovery: $_" }
        throw $failure
    }
    Write-Output "Installed $version to $binary. Provenance: $($source.kind)."
    Write-Output "Runtime data: $data. Scheduled execution enabled only by opt-in (existing managed schedule preserved)."
} finally {
    if ($null -ne $lock) { $lock.Dispose() }
    if ($null -ne $mutex) { Close-TTLifecycleMutex $mutex }
    # The temporary root is fresh, generated here, and contains only known downloaded/staged files.
    Get-TTPath $temp | Out-Null
    foreach ($file in @(Get-ChildItem -LiteralPath $temp -Force)) { Assert-TTFile $file.FullName -Owned; Remove-Item -LiteralPath $file.FullName -Force }
    [IO.Directory]::Delete($temp)
}
