# Shared current-user lifecycle primitives. This file has no entrypoint.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:TTInstaller = 'telltale-windows-v1'
$script:TTSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:TTLocal = [Environment]::GetFolderPath('LocalApplicationData')
$script:TTRepo = 'Dark-Roast-Cyber/telltale'

function Get-TTPath([string]$Path) {
    if ($Path -notmatch '^[a-zA-Z]:[\\/]' -or $Path -match '[\x00-\x1f"<>|?*;%]' -or $Path.Substring(2).Contains(':')) {
        throw 'Use an absolute local Windows path without special characters.'
    }
    foreach ($part in ($Path.Substring(3) -split '[\\/]')) {
        if ($part -eq '..' -or $part -eq '.' -or $part.Contains('~') -or $part -match '[. ]$' -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
            throw 'Unsafe Windows path component.'
        }
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $cursor = $full
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Reparse points are forbidden: $cursor"
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    return $full
}

function Assert-TTOwner([string]$Path) {
    $owner = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne $script:TTSid) { throw "Resource is not owned by the current user: $Path" }
}

function Set-TTCreatedOwner([string]$Path) {
    # An elevated CI token can default newly created objects to Administrators.
    # Assign only objects just created by this invocation to the recorded user SID.
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($script:TTSid))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function New-TTDirectory([string]$Path) {
    Get-TTPath $Path | Out-Null
    if (-not (Test-Path -LiteralPath $Path)) {
        [IO.Directory]::CreateDirectory($Path) | Out-Null
        Set-TTCreatedOwner $Path
    }
    Assert-TTOwner $Path
}

# File handles also reject hard links, which do not have the reparse attribute.
if (-not ('TelltaleLifecycle.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace TelltaleLifecycle {
    public static class Native {
        [StructLayout(LayoutKind.Sequential)]
        struct Info {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
        [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern IntPtr SendMessageTimeout(IntPtr window, uint message, UIntPtr parameter,
            string text, uint flags, uint timeout, out UIntPtr result);
        public static void SingleLink(FileStream stream) {
            Info info;
            if (!GetFileInformationByHandle(stream.SafeFileHandle, out info) || info.Links != 1)
                throw new IOException("File must have exactly one link.");
        }
        public static void EnvironmentChanged() {
            UIntPtr result;
            SendMessageTimeout(new IntPtr(0xffff), 0x001a, UIntPtr.Zero, "Environment", 2, 1000, out result);
        }
    }
}
'@
}

function Assert-TTFile([string]$Path, [switch]$Owned, [switch]$DevelopmentSource) {
    $pathChecked = Get-TTPath $Path
    $item = Get-Item -LiteralPath $pathChecked -Force
    if ($item.PSIsContainer) { throw "Expected a regular file: $Path" }
    if ($Owned) { Assert-TTOwner $pathChecked }
    $stream = [IO.File]::Open($pathChecked, 'Open', 'Read', 'Read')
    try {
        # Cargo hard-links its output to target/*/deps. A development input is
        # copied into a new single-link file; installed files never get this exception.
        if (-not $DevelopmentSource) { [TelltaleLifecycle.Native]::SingleLink($stream) }
    } finally { $stream.Dispose() }
}

function Get-TTHash([string]$Path) {
    Assert-TTFile $Path -Owned
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-TTDirectories([string]$Install, [string]$Data) {
    foreach ($path in @($Install, $Data)) {
        if (-not $path.StartsWith($script:TTLocal.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Lifecycle destinations must be inside the current user LocalApplicationData folder.'
        }
        if (Test-Path -LiteralPath $path) {
            if (-not (Get-Item -LiteralPath $path -Force).PSIsContainer) { throw 'Destination must be a directory.' }
            Assert-TTOwner $path
        }
    }
    if ($Install -eq $Data -or $Install.StartsWith($Data + '\', [StringComparison]::OrdinalIgnoreCase) -or $Data.StartsWith($Install + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Binary and data directories must be separate.'
    }
}

function Read-TTJson([string]$Path) {
    Assert-TTFile $Path -Owned
    if ((Get-Item -LiteralPath $Path).Length -gt 1048576) { throw 'Oversized lifecycle metadata.' }
    return [IO.File]::ReadAllText($Path) | ConvertFrom-Json
}

function Write-TTJson([string]$Path, $Value) {
    # Atomic rename requires the same volume. All managed destinations are under
    # LocalApplicationData, with reparse points forbidden. A killed writer can
    # leave a scratch file here, but never an incomplete installation member.
    $stage = Join-Path $script:TTLocal ("telltale-metadata-{0}.tmp" -f [guid]::NewGuid())
    $stream = [IO.File]::Open($stage, 'CreateNew', 'Write', 'None')
    try {
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 12))
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        Set-TTCreatedOwner $stage
        if (Test-Path -LiteralPath $Path) {
            Assert-TTFile $Path -Owned
            [IO.File]::Replace($stage, $Path, [NullString]::Value)
        } else { [IO.File]::Move($stage, $Path) }
    } catch {
        # Only this invocation's exclusively created scratch file is removed.
        if (Test-Path -LiteralPath $stage) { Assert-TTFile $stage -Owned; Remove-Item -LiteralPath $stage -Force }
        throw
    }
}

function Assert-TTReceipt($Receipt, [string]$Install, [string]$Data) {
    if ($Receipt.installer -cne $script:TTInstaller -or $Receipt.sid -cne $script:TTSid -or
        $Receipt.install -cne $Install -or $Receipt.data -cne $Data -or
        $Receipt.id -notmatch '^[0-9a-f-]{36}$' -or $Receipt.binary_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Installation receipt identity is invalid.'
    }
    if ($Receipt.source.kind -notin @('published-release', 'development-local')) { throw 'Unknown installation provenance.' }
}

function Get-TTReceipt([string]$Install, [string]$Data) {
    $path = Join-Path $Install 'install-receipt.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $receipt = Read-TTJson $path
    Assert-TTReceipt $receipt $Install $Data
    $binary = Join-Path $Install 'telltale.exe'
    $uninstalling = $receipt.PSObject.Properties['uninstalling'] -and $receipt.uninstalling
    if (-not ($uninstalling -and -not (Test-Path -LiteralPath $binary)) -and (Get-TTHash $binary) -cne $receipt.binary_sha256) {
        throw 'Installed executable changed; refusing to replace or delete it.'
    }
    return $receipt
}

function Assert-TTUnlocked([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Assert-TTFile $Path -Owned
    # Windows prevents exclusive write access to loaded or locked executables.
    $stream = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
    $stream.Dispose()
}

function Get-TTTask {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $service.GetFolder('\')
    try { return $folder.GetTask('TelltaleScan') }
    catch {
        $failure = $_.Exception
        while ($null -ne $failure.InnerException) { $failure = $failure.InnerException }
        if ($failure.HResult -eq -2147024894) { return $null }
        throw
    }
}

function Get-TTTextHash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Open-TTLifecycleMutex {
    # One current-user lifecycle lock spans binary, data, PATH and the single task
    # identity, including data-only purge and separate Windows logon sessions.
    $mutex = [Threading.Mutex]::new($false, ('Global\TelltaleLifecycle-' + (Get-TTTextHash $script:TTSid)))
    try {
        try { if (-not $mutex.WaitOne(0)) { throw 'Another current-user lifecycle operation is in progress; retry later.' } }
        catch [Threading.AbandonedMutexException] { } # Acquired; journal recovery still proves files.
        return $mutex
    } catch { $mutex.Dispose(); throw }
}

function Close-TTLifecycleMutex([Threading.Mutex]$Mutex) {
    try { $Mutex.ReleaseMutex() } finally { $Mutex.Dispose() }
}

function Assert-TTTask($Receipt) {
    $task = Get-TTTask
    if ($null -ne $task) {
        if ($null -eq $Receipt -or -not $Receipt.task_xml -or (Get-TTTextHash $task.Xml) -cne (Get-TTTextHash $Receipt.task_xml)) {
            throw 'TelltaleScan exists but is not the exact installer-managed task.'
        }
    }
    return $task
}

function Set-TTTask([string]$Xml, [switch]$CreateOnly) {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    # TASK_CREATE_OR_UPDATE=6, TASK_LOGON_INTERACTIVE_TOKEN=3. No password or elevation.
    $flags = if ($CreateOnly) { 2 } else { 6 }
    $task = $service.GetFolder('\').RegisterTask('TelltaleScan', $Xml, $flags, $script:TTSid, $null, 3, $null)
    return $task.Xml
}

function Remove-TTTask($Task) {
    if ($Task.State -eq 4) {
        $Task.Stop(0)
        for ($attempt = 0; $attempt -lt 50 -and $Task.State -eq 4; $attempt++) { Start-Sleep -Milliseconds 100 }
        if ($Task.State -eq 4) { throw 'Managed Scheduled Task did not stop.' }
    }
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $service.GetFolder('\').DeleteTask('TelltaleScan', 0)
}

function New-TTTaskXml([string]$Install, [string]$Data, [string]$Id) {
    [xml]$xml = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '../config/examples/telltale-scan-task.xml'))
    # RegisterTask accepts a UTF-16 COM BSTR. The UTF-8 file declaration must
    # describe that transport or the native scheduler rejects the document.
    $xml.FirstChild.Encoding = 'UTF-16'
    $xml.Task.RegistrationInfo.Description = "Telltale installer $Id"
    $xml.Task.Triggers.LogonTrigger.UserId = $script:TTSid
    $xml.Task.Principals.Principal.UserId = $script:TTSid
    $xml.Task.Actions.Exec.Command = [string](Join-Path $Install 'telltale.exe')
    $scanRoot = [Environment]::GetFolderPath('UserProfile')
    # Windows path validation forbids embedded quotes/control characters.
    Get-TTPath $scanRoot | Out-Null
    $xml.Task.Actions.Exec.Arguments = 'scan --once --emit-activity --root "{0}" --state-path "{1}" --log-path "{2}"' -f $scanRoot, (Join-Path $Data 'State\telltale-state.json'), (Join-Path $Data 'Logs\telltale-events.jsonl')
    $xml.Task.Actions.Exec.WorkingDirectory = [string]$Install
    # Registration is disabled; enabling follows committed binary + receipt.
    $xml.Task.Settings.Enabled = 'false'
    return $xml.OuterXml
}

function Get-TTTaskEnabledXml([string]$Xml, [bool]$Enabled) {
    # Retain the exact scheduler export, including whitespace and declaration.
    $pattern = [regex]::new('(?s)(<Settings>.*?<Enabled>)(true|false)(</Enabled>)')
    if ($pattern.Matches($Xml).Count -ne 1) { throw 'Unknown Scheduled Task settings declaration.' }
    $value = if ($Enabled) { 'true' } else { 'false' }
    return $pattern.Replace($Xml, ('${1}' + $value + '${3}'), 1)
}

function Get-TTUserPath {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment')
    if ($null -eq $key) { return $null }
    try {
        $value = $key.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -ne $value -and $value -isnot [string]) { throw 'User PATH must be a string registry value.' }
        return $value
    } finally { $key.Dispose() }
}

function Set-TTUserPath($Value, $Expected) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        if ($PSBoundParameters.ContainsKey('Expected')) {
            $current = $key.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($current -cne $Expected) { throw 'User PATH changed before the write; no PATH value was overwritten.' }
        }
        if ($null -eq $Value) { $key.DeleteValue('Path', $false) }
        else {
            $kind = if ($key.GetValueNames() -contains 'Path') { $key.GetValueKind('Path') }
                else { [Microsoft.Win32.RegistryValueKind]::ExpandString }
            if ($kind -notin @([Microsoft.Win32.RegistryValueKind]::String, [Microsoft.Win32.RegistryValueKind]::ExpandString)) { throw 'User PATH registry kind changed.' }
            $key.SetValue('Path', [string]$Value, $kind)
        }
    } finally { $key.Dispose() }
    [TelltaleLifecycle.Native]::EnvironmentChanged()
}

function Get-TTPathWithoutEntry($Value, [string]$Entry) {
    if ($null -eq $Value) { return $null }
    $parts = @($Value -split ';')
    $matches = @($parts | Where-Object { $_.TrimEnd('\') -ieq $Entry })
    if ($matches.Count -eq 0) { return $Value }
    if ($matches.Count -ne 1) { throw 'Managed PATH entry duplicated; resolve it before cleanup.' }
    $retained = @($parts | Where-Object { $_.TrimEnd('\') -ine $Entry })
    if ($retained.Count -eq 0) { return $null }
    return ($retained -join ';')
}

function Get-TTConfigurationFiles {
    # Match src/config.rs user_config_root; Windows USERPROFILE is not a fallback.
    $base = [Environment]::GetEnvironmentVariable('XDG_CONFIG_HOME')
    if ($base) { $root = Join-Path $base 'telltale' }
    else {
        $base = [Environment]::GetEnvironmentVariable('HOME')
        if (-not $base) { return }
        $root = Join-Path $base '.config\telltale'
    }
    $root = Get-TTPath $root
    if (-not (Test-Path -LiteralPath $root)) { return }
    Assert-TTOwner $root
    $tiers = @('organization-rules.d', 'rules.d', 'ui-rules.d', 'overrides.d', 'policies.d', 'allowlists.d', 'outputs.d')
    foreach ($directory in @(Get-ChildItem -LiteralPath $root -Force)) {
        Get-TTPath $directory.FullName | Out-Null
        if (-not $directory.PSIsContainer -or $directory.Name -cnotin $tiers) { throw 'Unrecognized user configuration; purge refused.' }
        Assert-TTOwner $directory.FullName
        foreach ($file in @(Get-ChildItem -LiteralPath $directory.FullName -Force)) {
            if ($file.Extension -cnotin @('.yaml', '.yml')) { throw 'Unrecognized configuration file; purge refused.' }
            Assert-TTFile $file.FullName -Owned
            Assert-TTUnlocked $file.FullName
            $file.FullName
        }
    }
}

function Get-TTDataReceipt([string]$Data) {
    $path = Join-Path $Data 'data-receipt.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $receipt = Read-TTJson $path
    if ($receipt.installer -cne $script:TTInstaller -or $receipt.sid -cne $script:TTSid -or $receipt.data -cne $Data) {
        throw 'Data ownership receipt is invalid.'
    }
    $names = @($receipt.directories)
    if ($names.Count -gt 2 -or @($names | Select-Object -Unique).Count -ne $names.Count) { throw 'Invalid owned directory inventory.' }
    foreach ($name in $names) { if ($name -cnotin @('Logs', 'State')) { throw 'Unknown owned directory.' } }
    return $receipt
}

function Initialize-TTData([string]$Data) {
    foreach ($name in @('Logs', 'State')) {
        $path = Get-TTPath (Join-Path $Data $name)
        if (Test-Path -LiteralPath $path) {
            if (-not (Get-Item -LiteralPath $path -Force).PSIsContainer) { throw 'Runtime Logs/State destinations must be directories.' }
            Assert-TTOwner $path
        }
    }
    $receipt = Get-TTDataReceipt $Data
    if ($null -ne $receipt) { return }
    $createdRoot = -not (Test-Path -LiteralPath $Data)
    New-TTDirectory $Data
    $owned = @()
    foreach ($name in @('Logs', 'State')) {
        $path = Join-Path $Data $name
        Get-TTPath $path | Out-Null
        if (-not (Test-Path -LiteralPath $path)) {
            New-TTDirectory $path
            $owned += $name
        }
    }
    Write-TTJson (Join-Path $Data 'data-receipt.json') ([ordered]@{ installer = $script:TTInstaller; sid = $script:TTSid; data = $Data; directories = $owned; directory_created = $createdRoot })
}

function Get-TTPurgeFiles([string]$Data) {
    $receipt = Get-TTDataReceipt $Data
    if ($null -eq $receipt) { throw 'No installer data ownership receipt; data must be retained.' }
    foreach ($name in @($receipt.directories)) {
        if ($name -cnotin @('Logs', 'State')) { throw 'Unknown owned data directory.' }
        $directory = Get-TTPath (Join-Path $Data $name)
        if (-not (Test-Path -LiteralPath $directory)) { continue }
        Assert-TTOwner $directory
        foreach ($file in @(Get-ChildItem -LiteralPath $directory -Force)) {
            $recognized = if ($name -eq 'Logs') { $file.Name -cmatch '^telltale-events(?:-[0-9]{4}-[0-9]{2}-[0-9]{2}(?:\.[1-9][0-9]*)?)?\.jsonl(?:\.lock)?$' }
                else { $file.Name -cin @('telltale-state.json', 'telltale-state.json.lock', 'telltale-state.json.baseline.json', 'telltale-state.json.baseline.json.lock') }
            if (-not $recognized) { throw "Unrecognized data remains; purge refused: $($file.FullName)" }
            Assert-TTFile $file.FullName -Owned
            Assert-TTUnlocked $file.FullName
            $file.FullName
        }
    }
}

function Invoke-TTNative([string]$Command, [string[]]$Arguments) {
    $output = @(& $Command @Arguments)
    if ($LASTEXITCODE -ne 0) { throw "Native command failed: $Command (exit $LASTEXITCODE)" }
    return $output -join "`n"
}

function Get-TTRelease([string]$Tag) {
    $endpoint = if ($Tag) { "repos/$script:TTRepo/releases/tags/$Tag" } else { "repos/$script:TTRepo/releases/latest" }
    $release = (Invoke-TTNative 'gh' @('api', $endpoint)) | ConvertFrom-Json
    if ($release.draft -ne $false -or ($Tag -and $release.tag_name -cne $Tag) -or (-not $Tag -and $release.prerelease -ne $false)) {
        throw 'GitHub Release identity does not match the selection.'
    }
    if ($release.tag_name -cnotmatch '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.(0|[1-9][0-9]*))?$') { throw 'Unsupported release tag.' }
    if ([bool]$release.prerelease -ne $release.tag_name.Contains('-rc.')) { throw 'Release prerelease identity mismatch.' }
    return $release
}

function Get-TTReleaseSource([string]$Tag) {
    $object = ((Invoke-TTNative 'gh' @('api', "repos/$script:TTRepo/git/ref/tags/$Tag")) | ConvertFrom-Json).object
    for ($depth = 0; $object.type -eq 'tag' -and $depth -lt 8; $depth++) {
        $object = ((Invoke-TTNative 'gh' @('api', "repos/$script:TTRepo/git/tags/$($object.sha)")) | ConvertFrom-Json).object
    }
    if ($object.type -cne 'commit' -or $object.sha -cnotmatch '^[0-9a-f]{40}$') { throw 'Tag does not resolve to an immutable commit.' }
    return $object.sha
}

function Assert-TTReleaseAssets($Release, [string]$ArchiveName, [string]$ArchiveHash, [string]$SumsHash) {
    foreach ($pair in @(@($ArchiveName, $ArchiveHash), @('SHA256SUMS', $SumsHash))) {
        $assets = @($Release.assets | Where-Object { $_.name -ceq $pair[0] })
        if ($assets.Count -ne 1 -or $assets[0].digest -cne "sha256:$($pair[1])" -or
            $assets[0].browser_download_url -cne "https://github.com/$script:TTRepo/releases/download/$($Release.tag_name)/$($pair[0])") {
            throw 'Release asset identity or GitHub digest mismatch.'
        }
    }
}

function Assert-TTChecksum([string]$Sums, [string]$Name, [string]$Digest) {
    $matchedDigests = @()
    foreach ($line in [IO.File]::ReadAllLines($Sums)) {
        if (-not $line.Trim()) { continue }
        if ($line -cnotmatch '^([0-9a-f]{64}) [ *]([^\s]+)$') { throw 'Malformed SHA256SUMS.' }
        if ($Matches[2] -ceq $Name) { $matchedDigests += $Matches[1] }
    }
    if ($matchedDigests.Count -ne 1 -or $matchedDigests[0] -cne $Digest) { throw 'Missing, duplicated or mismatched SHA256SUMS archive entry.' }
}

function Assert-TTVersion([string]$Binary, [string]$Version, [string]$Source) {
    $actual = Invoke-TTNative $Binary @('--version')
    if ($Version) {
        if ($actual -cne "telltale $Version ($($Source.Substring(0, 12)))") { throw 'Binary version/source identity does not match the release.' }
    } elseif ($actual -cnotmatch '^telltale [0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)? \((?:[0-9a-f]{12}|unknown)\)$') {
        throw 'Development binary does not report a recognized Telltale version.'
    }
    Invoke-TTNative $Binary @('rules', 'validate', '--no-local-config') | Out-Null
    return $actual
}

function Open-TTLock([string]$Install) {
    $path = Join-Path $Install '.lifecycle.lock'
    $identity = "$script:TTInstaller $script:TTSid"
    if (Test-Path -LiteralPath $path) {
        Assert-TTFile $path -Owned
        if ([IO.File]::ReadAllText($path) -cne $identity) { throw 'Unrecognized lifecycle lock.' }
    } else {
        $created = [IO.File]::Open($path, 'CreateNew', 'Write', 'None')
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($identity)
            $created.Write($bytes, 0, $bytes.Length)
            $created.Flush($true)
        } finally { $created.Dispose() }
        Set-TTCreatedOwner $path
    }
    return [IO.File]::Open($path, 'Open', 'ReadWrite', 'None')
}

function Restore-TTTransaction([string]$Install, [string]$Data) {
    $journalPath = Join-Path $Install 'transaction.json'
    if (-not (Test-Path -LiteralPath $journalPath)) { return }
    $journal = Read-TTJson $journalPath
    Assert-TTReceipt $journal.next $Install $Data
    if ($null -ne $journal.previous) { Assert-TTReceipt $journal.previous $Install $Data }
    $binary = Join-Path $Install 'telltale.exe'
    $stage = Join-Path $Install 'staged.exe'
    $backup = Join-Path $Install 'previous.exe'
    $allowed = @($journal.next.binary_sha256)
    if ($null -ne $journal.previous) { $allowed += $journal.previous.binary_sha256 }
    foreach ($path in @($binary, $stage, $backup)) {
        if (Test-Path -LiteralPath $path) {
            if ((Get-TTHash $path) -cnotin $allowed) { throw 'Transaction file changed; automatic recovery refused.' }
            Assert-TTUnlocked $path
        }
    }
    $receiptPath = Join-Path $Install 'install-receipt.json'
    if (Test-Path -LiteralPath $receiptPath) {
        $receipt = Read-TTJson $receiptPath
        Assert-TTReceipt $receipt $Install $Data
        if ($receipt.binary_sha256 -cnotin $allowed -or $receipt.id -cne $journal.next.id) { throw 'Transaction receipt changed.' }
    }
    if ($journal.committed) {
        if ((Get-TTHash $binary) -cne $journal.next.binary_sha256 -or
            -not (Test-Path -LiteralPath $receiptPath) -or $receipt.binary_sha256 -cne $journal.next.binary_sha256) { throw 'Committed transaction identity changed.' }
        if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Force }
        Remove-Item -LiteralPath $journalPath -Force
        return [pscustomobject]@{ DirectoryCreated = [bool]$journal.next.directory_created }
    }
    $task = Get-TTTask
    if ($null -ne $task) {
        $taskHashes = @()
        if ($null -ne $journal.previous -and $journal.previous.task_xml) { $taskHashes += Get-TTTextHash $journal.previous.task_xml }
        if ($journal.next.task_xml) { $taskHashes += Get-TTTextHash $journal.next.task_xml }
        if ($journal.PSObject.Properties['task_transition_xml'] -and $journal.task_transition_xml) { $taskHashes += Get-TTTextHash $journal.task_transition_xml }
        if ((Get-TTTextHash $task.Xml) -cnotin $taskHashes) { throw 'Task changed during transaction; recovery refused.' }
    }
    # Recover PATH only when it is exactly one of the two journaled values.
    $userPath = if ($journal.path_changed) { Get-TTUserPath } else { $null }
    $pathWasApplied = $journal.PSObject.Properties['path_applied'] -and $journal.path_applied
    $undoPath = $journal.path_changed -and ($pathWasApplied -or $userPath -ceq $journal.path_after)
    $restoredPath = $null
    if ($undoPath) { $restoredPath = Get-TTPathWithoutEntry $userPath $Install }
    if ($null -ne $journal.previous) {
        if (Test-Path -LiteralPath $backup) {
            if ((Get-TTHash $backup) -cne $journal.previous.binary_sha256) { throw 'Rollback backup does not match previous installation.' }
            if (Test-Path -LiteralPath $binary) { [IO.File]::Replace($backup, $binary, [NullString]::Value) }
            else { [IO.File]::Move($backup, $binary) }
        } elseif (-not (Test-Path -LiteralPath $binary) -or (Get-TTHash $binary) -cne $journal.previous.binary_sha256) {
            throw 'Previous executable is unavailable; recovery refused.'
        }
        if ($journal.previous.task_xml -and $null -ne $task) {
            $restoredXml = Set-TTTask $journal.previous.task_xml
            $journal.previous.task_xml = $restoredXml
        } elseif ($null -ne $task) { Remove-TTTask $task }
        else { $journal.previous.task_xml = $null }
        Write-TTJson $receiptPath $journal.previous
    } else {
        if ($null -ne $task) { Remove-TTTask $task }
        if (Test-Path -LiteralPath $binary) { Remove-Item -LiteralPath $binary -Force }
        if (Test-Path -LiteralPath $receiptPath) { Remove-Item -LiteralPath $receiptPath -Force }
    }
    if ($undoPath -and $userPath -cne $restoredPath) { Set-TTUserPath $restoredPath -Expected $userPath }
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Force }
    Remove-Item -LiteralPath $journalPath -Force
    Write-Verbose 'Recovered the interrupted installation; previous installation restored.'
    return [pscustomobject]@{ DirectoryCreated = [bool]$journal.next.directory_created }
}
