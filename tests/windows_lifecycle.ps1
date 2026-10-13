#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$BinaryPath,
    [string]$Python = 'python',
    [switch]$TestScheduledTask
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
if (-not $BinaryPath) { $BinaryPath = Join-Path $root 'target/debug/telltale.exe' }
$helper = Join-Path $root 'scripts/windows-lifecycle.ps1'
. $helper
$installer = Join-Path $root 'scripts/install-telltale.ps1'
$uninstaller = Join-Path $root 'scripts/uninstall-telltale.ps1'
$binary = (Get-Item -LiteralPath $BinaryPath).FullName
$testParent = Get-TTPath (Join-Path $script:TTLocal 'TelltaleLifecycleTests')
New-TTDirectory $testParent
$temp = Get-TTPath (Join-Path $testParent ("telltale-lifecycle-tests-{0}" -f [guid]::NewGuid()))
New-TTDirectory $temp
$script:assertions = 0
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Assertion failed: $Message" }
    $script:assertions++
}
function Assert-Fails([scriptblock]$Operation, [string]$Message) {
    $failed = $false
    try { & $Operation | Out-Null } catch { $failed = $true }
    Assert-True $failed $Message
}
function New-TestLayout([string]$Name) {
    $directory = Join-Path $temp $Name
    return @{ InstallDirectory = (Join-Path $directory 'Application With Spaces'); DataDirectory = (Join-Path $directory 'Runtime Data') }
}
function Get-TreeDigest([string]$Directory) {
    return (@(Get-ChildItem -LiteralPath $Directory -Recurse -Force | Sort-Object FullName | ForEach-Object {
        if ($_.PSIsContainer) { $_.FullName } else { "$($_.FullName):$((Get-FileHash -LiteralPath $_.FullName).Hash)" }
    }) -join "`n")
}

# The regression matrix exercises real scripts, files and binaries. Only Task
# Scheduler is substituted, so it cannot change a developer's real task.
$testAssemblyRefs = if ($PSVersionTable.PSEdition -eq 'Desktop') { @{ ReferencedAssemblies = @('System.Xml.dll') } } else { @{} }
Add-Type @testAssemblyRefs -TypeDefinition @'
using System;
using System.IO;
using System.Xml;
namespace TelltaleLifecycleTests {
    public class Task {
        XmlDocument document = new XmlDocument();
        public Task(string xml) { document.LoadXml(xml); State = 3; }
        public string Xml { get { return document.OuterXml; } }
        public int State { get; set; }
        public bool Enabled {
            get { return document.GetElementsByTagName("Settings")[0]["Enabled"].InnerText == "true"; }
            set { document.GetElementsByTagName("Settings")[0]["Enabled"].InnerText = value ? "true" : "false"; }
        }
        public void Stop(int flags) { State = 3; }
    }
    public class Folder {
        public static Task Current;
        public Task GetTask(string name) { if (Current == null) throw new FileNotFoundException(); return Current; }
        public Task RegisterTask(string name, string xml, int flags, string sid, object password, int logon, object security) {
            Current = new Task(xml); return Current;
        }
        public void DeleteTask(string name, int flags) { Current = null; }
    }
    public class Service {
        public void Connect() {}
        public Folder GetFolder(string path) { return new Folder(); }
    }
}
'@
function New-Object {
    param([string]$ComObject)
    if ($ComObject -cne 'Schedule.Service') { throw 'Unexpected COM object in test.' }
    return [TelltaleLifecycleTests.Service]::new()
}
try {
    $layout = New-TestLayout 'fresh'
    $before = Get-TreeDigest $temp
    & $installer @layout -DevelopmentBinary $binary -WhatIf
    Assert-True ((Get-TreeDigest $temp) -ceq $before) 'install WhatIf makes no filesystem changes'
    & $installer @layout -DevelopmentBinary $BinaryPath
    Assert-True (Test-Path -LiteralPath (Join-Path $layout.InstallDirectory 'telltale.exe')) 'fresh development installation'
    Assert-True ($null -eq (Get-TTTask)) 'task absent by default'
    $receipt = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
    Assert-True ($receipt.source.kind -ceq 'development-local') 'development provenance stays distinct'
    & $installer @layout -DevelopmentBinary $binary
    Assert-True ((Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory).id -ceq $receipt.id) 'same-version repeat preserves installation identity'
    $variant = Join-Path $temp 'development-variant.exe'
    Copy-Item -LiteralPath $binary -Destination $variant
    Set-TTCreatedOwner $variant
    # A valid executable overlay gives a distinct development digest without
    # pretending this fixture is a separately compiled or published version.
    $stream = [IO.File]::Open($variant, 'Append', 'Write', 'None')
    try { $stream.WriteByte(42) } finally { $stream.Dispose() }
    & $installer @layout -DevelopmentBinary $variant
    Assert-True ((Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory).binary_sha256 -ceq (Get-TTHash $variant)) 'replacement with a different development digest'
    $installed = Join-Path $layout.InstallDirectory 'telltale.exe'
    Assert-True ((Invoke-TTNative $installed @('--version')) -ceq $receipt.version) 'installed binary version'
    $relativeSourceDirectory = Join-Path $temp 'Relative Source With Spaces'
    New-TTDirectory $relativeSourceDirectory
    Copy-Item -LiteralPath $binary -Destination (Join-Path $relativeSourceDirectory 'telltale.exe')
    $relativeLayout = New-TestLayout 'relative-source-location'
    Push-Location $relativeSourceDirectory
    try { & $installer @relativeLayout -DevelopmentBinary '.\telltale.exe' }
    finally { Pop-Location }
    Assert-True (Test-Path -LiteralPath (Join-Path $relativeLayout.InstallDirectory 'telltale.exe')) 'development source follows PowerShell location'
    & $uninstaller @relativeLayout -Confirm:$false
    Invoke-TTNative $installed @('rules', 'validate', '--no-local-config') | Out-Null

    $fixtureRoot = Join-Path $temp 'synthetic-session-store'
    $fixtureDirectory = Join-Path $fixtureRoot 'codex/sessions/2026/04'
    [IO.Directory]::CreateDirectory($fixtureDirectory) | Out-Null
    Copy-Item -LiteralPath (Join-Path $root 'tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl') -Destination $fixtureDirectory
    $state = Join-Path $layout.DataDirectory 'State/telltale-state.json'
    $log = Join-Path $layout.DataDirectory 'Logs/telltale-events.jsonl'
    $oldProjectConfig = $env:TELLTALE_PROJECT_CONFIG
    $env:TELLTALE_PROJECT_CONFIG = $null
    try {
        Invoke-TTNative $installed @('scan', '--once', '--allow-fixtures', '--install-inventory-disabled', '--no-local-config', '--root', $fixtureRoot, '--state-path', $state, '--log-path', $log) | Out-Null
    } finally { $env:TELLTALE_PROJECT_CONFIG = $oldProjectConfig }
    # This fixture invocation created these leaves. Elevated CI shells can
    # default their owner to Administrators; model the supported user-owned data.
    foreach ($name in @('Logs', 'State')) {
        foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $layout.DataDirectory $name) -Force)) { Set-TTCreatedOwner $file.FullName }
    }
    $events = @([IO.File]::ReadAllLines($log) | ForEach-Object { $_ | ConvertFrom-Json })
    $detections = @($events | Where-Object { $_.event_type -ceq 'detection' })
    Assert-True ($detections.Count -eq 1 -and $detections[0].session_id -ceq 'uc001-positive' -and $detections[0].rule_ids -contains 'mcp.tool_metadata.prompt_injection') 'expected synthetic detection'
    Assert-True (@($events | Where-Object { $_.schema_version -cne '3.0' }).Count -eq 0) 'Event 3.0 identity'
    Invoke-TTNative $Python @((Join-Path $root 'scripts/validate-event-jsonl'), '--schema', (Join-Path $root 'schemas/event.schema.json'), '--events', $log) | Out-Null
    $provenance = (Invoke-TTNative $installed @('config', 'validate', '--no-local-config')) | ConvertFrom-Json
    Assert-True ($provenance.outputs.delivery.remote_sink_count -eq 0) 'no remote sinks'
    $before = Get-TreeDigest $temp
    & $uninstaller @layout -WhatIf
    Assert-True ((Get-TreeDigest $temp) -ceq $before) 'uninstall WhatIf is read-only'
    $unrelated = Join-Path $layout.InstallDirectory 'user-note.txt'
    [IO.File]::WriteAllText($unrelated, 'retain')
    & $uninstaller @layout -Confirm:$false
    Assert-True (-not (Test-Path -LiteralPath $installed)) 'managed binary removed'
    Assert-True ((Test-Path -LiteralPath $state) -and (Test-Path -LiteralPath $log) -and (Test-Path -LiteralPath $unrelated)) 'data and unrelated files retained'
    & $uninstaller @layout -Confirm:$false
    $other = Join-Path $layout.DataDirectory 'keep.txt'
    [IO.File]::WriteAllText($other, 'retain')
    # A distinct process proves the mutex also protects data-only purge after
    # default uninstall. A same-thread mutex check would merely be recursive.
    $worker = Join-Path $temp 'mutex-worker.ps1'
    [IO.File]::WriteAllText($worker, @'
param($Helper, $Ready, $Release)
. $Helper
$mutex = Open-TTLifecycleMutex
try {
    [IO.File]::WriteAllText($Ready, 'ready')
    for ($attempt = 0; $attempt -lt 600 -and -not (Test-Path -LiteralPath $Release); $attempt++) { Start-Sleep -Milliseconds 100 }
} finally { Close-TTLifecycleMutex $mutex }
'@)
    $ready = Join-Path $temp 'mutex-ready'
    $release = Join-Path $temp 'mutex-release'
    $engineName = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
    $engine = Join-Path $PSHOME $engineName
    $workerArguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Helper "{1}" -Ready "{2}" -Release "{3}"' -f $worker, $helper, $ready, $release
    $workerProcess = Start-Process -FilePath $engine -ArgumentList $workerArguments -WindowStyle Hidden -PassThru
    try {
        for ($attempt = 0; $attempt -lt 100 -and -not (Test-Path -LiteralPath $ready); $attempt++) { Start-Sleep -Milliseconds 100 }
        Assert-True (Test-Path -LiteralPath $ready) 'separate process acquired lifecycle mutex'
        Assert-Fails { & $installer @layout -DevelopmentBinary $binary } 'lifecycle mutex blocks concurrent installation'
        Assert-Fails { & $uninstaller @layout -PurgeData -Confirm:$false } 'lifecycle mutex blocks concurrent data-only purge'
        Assert-True ((Test-Path -LiteralPath $state) -and (Test-Path -LiteralPath $log)) 'blocked purge leaves data intact'
    } finally {
        [IO.File]::WriteAllText($release, 'release')
        if (-not $workerProcess.WaitForExit(15000)) { $workerProcess.Kill(); $workerProcess.WaitForExit() }
    }
    & $uninstaller @layout -PurgeData -WhatIf
    Assert-True (Test-Path -LiteralPath $state) 'purge preview retains files'
    $foreign = Join-Path $layout.DataDirectory 'Logs/foreign.txt'
    [IO.File]::WriteAllText($foreign, 'retain')
    Assert-Fails { & $uninstaller @layout -PurgeData -Confirm:$false } 'unknown data member blocks purge before mutation'
    Remove-Item -LiteralPath $foreign
    & $uninstaller @layout -PurgeData -Confirm:$false
    Assert-True (-not (Test-Path -LiteralPath $state) -and -not (Test-Path -LiteralPath $log) -and (Test-Path -LiteralPath $other)) 'purge is bounded to generated data'
    & $uninstaller @layout -PurgeData -Confirm:$false

    $layout = New-TestLayout 'task'
    & $installer @layout -DevelopmentBinary $binary -WithScheduledTask
    Assert-True ((Get-TTTask).Enabled) 'task opt-in enables after install'
    [xml]$taskXml = (Get-TTTask).Xml
    Assert-True ($taskXml.Task.Principals.Principal.UserId -ceq $script:TTSid -and $taskXml.Task.Principals.Principal.RunLevel -ceq 'LeastPrivilege') 'current-user least-privilege task'
    Assert-True ($taskXml.Task.Triggers.LogonTrigger.Repetition.Interval -ceq 'PT30M' -and $taskXml.Task.Actions.Exec.Arguments.Contains('"')) 'template cadence and quoting'
    & $installer @layout -DevelopmentBinary $binary
    Assert-True ((Get-TTTask).Enabled) 'repeat preserves managed schedule'
    [TelltaleLifecycleTests.Folder]::Current = $null
    & $installer @layout -DevelopmentBinary $binary
    Assert-True ($null -eq (Get-TTTask)) 'plain reinstall preserves a deliberately removed task'
    & $installer @layout -DevelopmentBinary $binary -WithScheduledTask
    $saved = (Get-TTTask).Xml
    [TelltaleLifecycleTests.Folder]::Current = [TelltaleLifecycleTests.Task]::new($saved.Replace('PT30M', 'PT1M'))
    Assert-Fails { & $uninstaller @layout -Confirm:$false } 'modified task is not removed'
    [TelltaleLifecycleTests.Folder]::Current = [TelltaleLifecycleTests.Task]::new($saved)
    & $uninstaller @layout -Confirm:$false
    Assert-True ($null -eq (Get-TTTask)) 'managed task removed'
    [TelltaleLifecycleTests.Folder]::Current = [TelltaleLifecycleTests.Task]::new($saved)
    $collision = New-TestLayout 'task-collision'
    Assert-Fails { & $installer @collision -DevelopmentBinary $binary -WithScheduledTask } 'task name collision'
    Assert-True ((Get-TTTask).Xml -ceq $saved) 'collision leaves existing task untouched'
    [TelltaleLifecycleTests.Folder]::Current = $null

    $missing = New-TestLayout 'missing-release'
    $global:TTReleaseProbeCalls = @()
    function gh {
        $global:TTReleaseProbeCalls += ($args -join ' ')
        $global:LASTEXITCODE = 1
        'Synthetic missing Release response'
    }
    try {
        Assert-Fails { & $installer @missing -ReleaseTag v999.0.0 } 'missing explicit release fails before installation'
        Assert-True ($global:TTReleaseProbeCalls.Count -eq 1 -and $global:TTReleaseProbeCalls[0].Contains('releases/tags/v999.0.0') -and -not (Test-Path -LiteralPath $missing.InstallDirectory)) 'missing release never falls back or mutates destination'
    } finally { Remove-Item Function:gh; Remove-Variable TTReleaseProbeCalls -Scope Global }

    $layout = New-TestLayout 'locked'
    & $installer @layout -DevelopmentBinary $binary
    $installed = Join-Path $layout.InstallDirectory 'telltale.exe'
    $stream = [IO.File]::Open($installed, 'Open', 'Read', 'Read')
    try {
        Assert-Fails { & $installer @layout -DevelopmentBinary $variant } 'locked executable blocks replacement'
        Assert-Fails { & $uninstaller @layout -Confirm:$false } 'locked executable blocks cleanup'
    } finally { $stream.Dispose() }
    $originalHash = Get-TTHash $installed
    [IO.File]::WriteAllText($installed, 'modified')
    Assert-Fails { & $installer @layout -DevelopmentBinary $binary } 'modified installed binary blocks reinstall'
    Assert-Fails { & $uninstaller @layout -Confirm:$false } 'modified installed binary is retained'
    Copy-Item -LiteralPath $binary -Destination $installed -Force
    Assert-True ((Get-TTHash $installed) -ceq $originalHash) 'restored only the synthetic test binary'
    & $uninstaller @layout -Confirm:$false

    $layout = New-TestLayout 'partial-rollback'
    & $installer @layout -DevelopmentBinary $binary
    $installed = Join-Path $layout.InstallDirectory 'telltale.exe'
    $beforeHash = Get-TTHash $installed
    $metadata = Join-Path $layout.InstallDirectory 'install-receipt.json'
    $stream = [IO.File]::Open($metadata, 'Open', 'Read', 'Read')
    try {
        Assert-Fails { & $installer @layout -DevelopmentBinary $variant } 'metadata failure reports failed install and rollback'
        Assert-Fails { & $uninstaller @layout -Confirm:$false } 'pending recovery blocks cleanup'
    } finally { $stream.Dispose() }
    Assert-True ((Get-TTHash $installed) -ceq $beforeHash) 'previous binary restored despite blocked metadata rollback'
    & $installer @layout -DevelopmentBinary $binary
    $stream = [IO.File]::Open($metadata, 'Open', 'Read', 'Read')
    try { Assert-Fails { & $uninstaller @layout -Confirm:$false } 'cleanup metadata failure does not report success' }
    finally { $stream.Dispose() }
    Assert-True (Test-Path -LiteralPath $installed) 'failed cleanup retained executable'
    & $uninstaller @layout -Confirm:$false

    $layout = New-TestLayout 'running'
    & $installer @layout -DevelopmentBinary $binary
    $installed = Join-Path $layout.InstallDirectory 'telltale.exe'
    $watchArguments = 'watch --allow-fixtures --install-inventory-disabled --no-local-config --root "{0}" --state-path "{1}" --log-path "{2}"' -f $fixtureRoot, (Join-Path $layout.DataDirectory 'State/telltale-state.json'), (Join-Path $layout.DataDirectory 'Logs/telltale-events.jsonl')
    $oldProjectConfig = $env:TELLTALE_PROJECT_CONFIG
    $env:TELLTALE_PROJECT_CONFIG = $null
    $process = $null
    try {
        $process = Start-Process -FilePath $installed -ArgumentList $watchArguments -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 500
        Assert-True (-not $process.HasExited) 'synthetic watch process running'
        Assert-Fails { & $installer @layout -DevelopmentBinary $variant } 'running binary blocks replacement'
        Assert-Fails { & $uninstaller @layout -Confirm:$false } 'running binary blocks removal'
    } finally {
        $env:TELLTALE_PROJECT_CONFIG = $oldProjectConfig
        if ($null -ne $process -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
    }
    & $uninstaller @layout -Confirm:$false

    $legacyLayout = New-TestLayout 'legacy'
    New-TTDirectory $legacyLayout.DataDirectory
    $legacy = Join-Path $legacyLayout.DataDirectory 'telltale.exe'
    Copy-Item -LiteralPath $binary -Destination $legacy
    $report = & $uninstaller @legacyLayout -Confirm:$false
    Assert-True ((Test-Path -LiteralPath $legacy) -and ($report -join ' ').Contains('Legacy manual')) 'legacy detection does not adopt or delete it'
    Assert-Fails { & $installer -DevelopmentBinary $binary -InstallDirectory $legacyLayout.DataDirectory -DataDirectory $legacyLayout.InstallDirectory } 'unowned binary directory rejected'
    foreach ($path in @("$temp\..\escape", "$temp\file:stream", "$temp\trailing.", "$temp\NUL", "$temp\ALIAS~1", "$temp\semi;path", "$temp\percent%path", '\\server\share\telltale')) {
        Assert-Fails { Get-TTPath $path } 'unsafe path rejected'
    }
    $link = Join-Path $temp 'junction'
    New-Item -ItemType Junction -Path $link -Target $legacyLayout.DataDirectory | Out-Null
    Assert-Fails { Get-TTPath (Join-Path $link 'telltale.exe') } 'junction ancestor rejected'
    [IO.Directory]::Delete($link)
    $hardLink = Join-Path $temp 'hardlink.exe'
    New-Item -ItemType HardLink -Path $hardLink -Target $variant | Out-Null
    Assert-Fails { Assert-TTFile $hardLink -Owned } 'hard links rejected'
    Remove-Item -LiteralPath $hardLink
    Assert-Fails { & $installer @legacyLayout -ReleaseTag 'main' } 'invalid explicit release tag rejected'
    Assert-Fails { & $installer @legacyLayout -DevelopmentBinary $binary -SkipChecksum } 'production checksum bypass is not a supported parameter'
    Assert-Fails { & $installer @legacyLayout -ReleaseTag v0.7.0-rc.2 -DevelopmentBinary $binary } 'development and release modes cannot mix'
    foreach ($name in @('Logs', 'State')) {
        $wrongType = New-TestLayout "runtime-file-$name"
        New-TTDirectory $wrongType.DataDirectory
        [IO.File]::WriteAllText((Join-Path $wrongType.DataDirectory $name), 'unrelated')
        Assert-Fails { & $installer @wrongType -DevelopmentBinary $BinaryPath } 'regular runtime file blocks installation'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $wrongType.InstallDirectory 'telltale.exe'))) 'runtime type failure precedes replacement'
    }
    $sums = Join-Path $temp 'SHA256SUMS'
    $digest = 'a' * 64
    [IO.File]::WriteAllText($sums, "$digest  test.zip`n")
    Assert-TTChecksum $sums 'test.zip' $digest
    Assert-Fails { Assert-TTChecksum $sums 'missing.zip' $digest } 'missing checksum entry'
    Assert-Fails { Assert-TTChecksum $sums 'test.zip' ('b' * 64) } 'wrong checksum'
    [IO.File]::AppendAllText($sums, "$digest  test.zip`n")
    Assert-Fails { Assert-TTChecksum $sums 'test.zip' $digest } 'duplicate checksum'
    Assert-True ((Get-TTPathWithoutEntry "one;$temp;two" $temp) -ceq 'one;two') 'PATH cleanup preserves unrelated entries'
    Assert-True ((Get-TTPathWithoutEntry 'one;two' $temp) -ceq 'one;two') 'already removed PATH entry is harmless'
    Assert-True ($null -eq (Get-TTPathWithoutEntry $temp $temp)) 'sole owned PATH entry restores absent value'
    Assert-True ((Get-TTPathWithoutEntry ("one;" + $temp.ToUpperInvariant() + '\;two') $temp) -ceq 'one;two') 'unique normalized PATH entry can be removed'
    Assert-True ((Get-TTPathWithoutEntry ";$temp" $temp) -ceq '') 'preexisting empty PATH component retained'
    Assert-Fails { Get-TTPathWithoutEntry "$temp;$temp" $temp } 'duplicated PATH ownership rejected'

    # Runtime configuration resolver, isolated from real user configuration.
    $oldXdg = $env:XDG_CONFIG_HOME
    $oldHome = $env:HOME
    try {
        $env:XDG_CONFIG_HOME = Join-Path $temp 'synthetic-xdg'
        $env:HOME = Join-Path $temp 'synthetic-home'
        $configFile = Join-Path $env:XDG_CONFIG_HOME 'telltale/outputs.d/synthetic.yaml'
        New-TTDirectory (Join-Path $env:XDG_CONFIG_HOME 'telltale')
        New-TTDirectory (Split-Path -Parent $configFile)
        [IO.File]::WriteAllText($configFile, 'version: 1')
        Set-TTCreatedOwner $configFile
        Assert-True ((@(Get-TTConfigurationFiles) -join '') -ceq $configFile.Replace('/', '\')) 'XDG configuration root and outputs tier match runtime'
        $env:XDG_CONFIG_HOME = $null
        Assert-True (@(Get-TTConfigurationFiles).Count -eq 0) 'HOME fallback ignores other XDG configuration'
        $homeFile = Join-Path $env:HOME '.config/telltale/rules.d/synthetic.yml'
        New-TTDirectory (Join-Path $env:HOME '.config/telltale')
        New-TTDirectory (Split-Path -Parent $homeFile)
        [IO.File]::WriteAllText($homeFile, 'version: 1')
        Set-TTCreatedOwner $homeFile
        Assert-True (@(Get-TTConfigurationFiles).Count -eq 1) 'HOME configuration fallback'
        $env:HOME = $null
        Assert-True (@(Get-TTConfigurationFiles).Count -eq 0) 'absent runtime variables select no USERPROFILE configuration'
        $env:XDG_CONFIG_HOME = '..\agent-store'
        Assert-Fails { Get-TTConfigurationFiles } 'relative configuration root rejected'
    } finally { $env:XDG_CONFIG_HOME = $oldXdg; $env:HOME = $oldHome }

    # Interrupted writes are confined to invocation scratch outside the install;
    # only an atomic move exposes a complete stage or metadata member.
    $layout = New-TestLayout 'first-install-recovery'
    New-TTDirectory $layout.InstallDirectory
    $next = ($receipt | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
    $next.install = $layout.InstallDirectory
    $next.data = $layout.DataDirectory
    $next.directory_created = $true
    $next.binary_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    $next.task_xml = $null
    $next.path_added = $false
    Write-TTJson (Join-Path $layout.InstallDirectory 'transaction.json') @{ previous = $null; next = $next; committed = $false; path_changed = $false; path_before = $null; path_after = $null }
    $scratch = Join-Path $temp 'interrupted-scratch'
    New-TTDirectory $scratch
    [IO.File]::WriteAllText((Join-Path $scratch 'candidate.exe'), 'partial copy')
    [IO.File]::WriteAllText((Join-Path $scratch 'metadata.tmp'), '{partial json')
    & $installer @layout -DevelopmentBinary $binary
    Assert-True ((Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory).directory_created) 'recovery preserves fresh directory ownership'
    Assert-True (@(Get-ChildItem -LiteralPath $layout.InstallDirectory -Force | Where-Object { $_.Extension -cin @('.new', '.tmp') }).Count -eq 0) 'metadata staging remains outside installation'
    & $uninstaller @layout -Confirm:$false
    Assert-True (-not (Test-Path -LiteralPath $layout.InstallDirectory)) 'recovered fresh installation removes owned empty root'

    # Emulate process interruption after staging, then after executable replacement.
    foreach ($replace in @($false, $true)) {
        $layout = New-TestLayout "recovery-$replace"
        & $installer @layout -DevelopmentBinary $binary
        $previous = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
        $next = ($previous | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
        $next.binary_sha256 = Get-TTHash $variant
        Write-TTJson (Join-Path $layout.InstallDirectory 'transaction.json') @{ previous = $previous; next = $next; committed = $false; path_changed = $false; path_before = Get-TTUserPath; path_after = Get-TTUserPath }
        $stage = Join-Path $layout.InstallDirectory 'staged.exe'
        Copy-Item -LiteralPath $variant -Destination $stage
        Set-TTCreatedOwner $stage
        if ($replace) { [IO.File]::Replace($stage, (Join-Path $layout.InstallDirectory 'telltale.exe'), (Join-Path $layout.InstallDirectory 'previous.exe')) }
        & $installer @layout -DevelopmentBinary $binary
        Assert-True ((Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory).binary_sha256 -ceq $previous.binary_sha256) 'interrupted transaction recovered'
        & $uninstaller @layout -Confirm:$false
    }
    foreach ($freshActivation in @($false, $true)) {
        $layout = New-TestLayout "task-transition-$freshActivation"
        & $installer @layout -DevelopmentBinary $binary -WithScheduledTask
        $previous = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
        $enabledXml = (Get-TTTask).Xml
        $disabledXml = Get-TTTaskEnabledXml $enabledXml $false
        $next = ($previous | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
        if ($freshActivation) {
            $next.task_xml = $disabledXml
            $journal = @{ previous = $null; next = $next; task_transition_xml = $enabledXml; committed = $false; path_changed = $false; path_before = $null; path_after = $null }
        } else {
            (Get-TTTask).Enabled = $false
            $journal = @{ previous = $previous; next = $next; task_transition_xml = $disabledXml; committed = $false; path_changed = $false; path_before = $null; path_after = $null }
        }
        Write-TTJson (Join-Path $layout.InstallDirectory 'transaction.json') $journal
        & $installer @layout -DevelopmentBinary $binary
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $layout.InstallDirectory 'transaction.json'))) 'task transition interruption recovered'
        if ($freshActivation) { Assert-True ($null -eq (Get-TTTask)) 'interrupted fresh activation rolled back before plain reinstall' }
        else { Assert-True ((Get-TTTask).Enabled) 'interrupted disable restores original managed schedule' }
        & $uninstaller @layout -Confirm:$false
    }
    Write-Output "Windows lifecycle regression matrix passed: $script:assertions assertions. Synthetic root: $temp"
} finally {
    [TelltaleLifecycleTests.Folder]::Current = $null
    Remove-Item Function:New-Object
    # A fresh GUID root, checked again after junction tests; never delete canonical directories.
    $checkedTemp = Get-TTPath $temp
    if (-not $checkedTemp.StartsWith($testParent + '\telltale-lifecycle-tests-', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected test cleanup root.' }
    Remove-Item -LiteralPath $checkedTemp -Recurse -Force
}
if ($TestScheduledTask) {
    if ($env:GITHUB_ACTIONS -cne 'true') { throw 'Live Task Scheduler testing is restricted to the disposable CI runner.' }
    # The disposable CI account has no personal agent stores. Never run the
    # production home-root action: replace it temporarily with explicit synthetic paths.
    if ($null -ne (Get-TTTask)) { throw 'CI task collision; refusing to change an existing task.' }
    $liveTemp = Get-TTPath (Join-Path $testParent ("telltale-lifecycle-live-{0}" -f [guid]::NewGuid()))
    $layout = @{ InstallDirectory = (Join-Path $liveTemp 'Application With Spaces'); DataDirectory = (Join-Path $liveTemp 'Runtime Data') }
    $savedXml = $null
    $savedXdg = $env:XDG_CONFIG_HOME
    $env:XDG_CONFIG_HOME = Join-Path $liveTemp 'synthetic-xdg'
    $configRoot = Get-TTPath (Join-Path $env:XDG_CONFIG_HOME 'telltale')
    if (Test-Path -LiteralPath $configRoot) { throw 'Disposable runner configuration collision; no existing configuration will be modified.' }
    $configDirectory = Join-Path $configRoot 'rules.d'
    $configFile = Join-Path $configDirectory 'synthetic-user-rule.yaml'
    try {
        New-TTDirectory $configRoot
        New-TTDirectory $configDirectory
        [IO.File]::WriteAllText($configFile, 'version: 1')
        Set-TTCreatedOwner $configFile
        & $installer @layout -DevelopmentBinary $binary -WithScheduledTask -AddToPath
        $receipt = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
        Assert-True $receipt.path_added 'CI PATH opt-in owned'
        $savedXml = $receipt.task_xml
        $fixtureRoot = Join-Path $liveTemp 'synthetic-session-store'
        $fixtureDirectory = Join-Path $fixtureRoot 'codex/sessions/2026/04'
        [IO.Directory]::CreateDirectory($fixtureDirectory) | Out-Null
        Copy-Item -LiteralPath (Join-Path $root 'tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl') -Destination $fixtureDirectory
        [xml]$syntheticXml = $savedXml
        $state = Join-Path $layout.DataDirectory 'State/telltale-state.json'
        $log = Join-Path $layout.DataDirectory 'Logs/telltale-events.jsonl'
        $syntheticXml.Task.Actions.Exec.Arguments = 'scan --once --allow-fixtures --install-inventory-disabled --no-local-config --root "{0}" --state-path "{1}" --log-path "{2}"' -f $fixtureRoot, $state, $log
        Set-TTTask $syntheticXml.OuterXml | Out-Null
        $task = Get-TTTask
        $instance = $task.Run($null)
        for ($attempt = 0; $attempt -lt 120 -and -not (Test-Path -LiteralPath $log); $attempt++) { Start-Sleep -Milliseconds 500 }
        for ($attempt = 0; $attempt -lt 120 -and $task.State -eq 4; $attempt++) { Start-Sleep -Milliseconds 500 }
        Assert-True ($task.State -ne 4 -and $task.LastTaskResult -eq 0 -and (Test-Path -LiteralPath $log)) 'real scheduled synthetic execution'
        $events = @([IO.File]::ReadAllLines($log) | ForEach-Object { $_ | ConvertFrom-Json })
        Assert-True (@($events | Where-Object { $_.event_type -ceq 'detection' -and $_.session_id -ceq 'uc001-positive' -and $_.schema_version -ceq '3.0' }).Count -eq 1) 'scheduled expected Event 3.0 detection'
        Invoke-TTNative $Python @((Join-Path $root 'scripts/validate-event-jsonl'), '--schema', (Join-Path $root 'schemas/event.schema.json'), '--events', $log) | Out-Null
        $restored = Set-TTTask $savedXml
        Assert-True ((Get-TTTextHash $restored) -ceq (Get-TTTextHash $savedXml)) 'original managed task declaration restored'
        & $uninstaller @layout -PurgeData -Confirm:$false
        Assert-True (Test-Path -LiteralPath $configFile) 'data purge retains authored configuration'
        $configHash = Get-TTHash $configFile
        & $uninstaller @layout -PurgeData -PurgeConfiguration -WhatIf
        Assert-True ((Get-TTHash $configFile) -ceq $configHash) 'configuration purge WhatIf retains bytes'
        & $uninstaller @layout -PurgeData -PurgeConfiguration -Confirm:$false
        Assert-True (-not (Test-Path -LiteralPath $configFile)) 'separate configuration purge consent'
        Assert-True ($null -eq (Get-TTTask) -and -not @((Get-TTUserPath) -split ';' | Where-Object { $_ -ceq $layout.InstallDirectory }).Count) 'live task and owned PATH removed'
        $canonical = @{ InstallDirectory = (Join-Path $script:TTLocal 'Programs\Telltale'); DataDirectory = (Join-Path $script:TTLocal 'Telltale') }
        if ((Test-Path -LiteralPath $canonical.InstallDirectory) -or (Test-Path -LiteralPath $canonical.DataDirectory)) { throw 'Canonical CI installation collision; no existing installation will be touched.' }
        try {
            & $installer -DevelopmentBinary $binary
            Assert-True ($null -eq (Get-TTTask)) 'canonical default install leaves real task absent'
            $canonicalBinary = Join-Path $canonical.InstallDirectory 'telltale.exe'
            Invoke-TTNative $canonicalBinary @('scan', '--once', '--allow-fixtures', '--install-inventory-disabled', '--no-local-config', '--root', $fixtureRoot) | Out-Null
            $canonicalLog = Join-Path $canonical.DataDirectory 'Logs\telltale-events.jsonl'
            $canonicalState = Join-Path $canonical.DataDirectory 'State\telltale-state.json'
            Assert-True ((Test-Path -LiteralPath $canonicalLog) -and (Test-Path -LiteralPath $canonicalState)) 'canonical runtime defaults stay separate from executable'
            Invoke-TTNative $Python @((Join-Path $root 'scripts/validate-event-jsonl'), '--schema', (Join-Path $root 'schemas/event.schema.json'), '--events', $canonicalLog) | Out-Null
            foreach ($name in @('Logs', 'State')) {
                foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $canonical.DataDirectory $name) -Force)) { Set-TTCreatedOwner $file.FullName }
            }
            & $uninstaller -Confirm:$false
            Assert-True ((Test-Path -LiteralPath $canonicalLog) -and (Test-Path -LiteralPath $canonicalState)) 'canonical default uninstall retains data'
            & $uninstaller -PurgeData -Confirm:$false
            Assert-True (-not (Test-Path -LiteralPath $canonical.InstallDirectory) -and -not (Test-Path -LiteralPath $canonical.DataDirectory)) 'canonical owned installation fully purged'
        } finally {
            if (Test-Path -LiteralPath (Join-Path $canonical.InstallDirectory 'install-receipt.json')) { & $uninstaller -Confirm:$false }
        }
        Write-Output 'Disposable-runner live Scheduled Task and PATH lifecycle passed.'
    } finally {
        $env:XDG_CONFIG_HOME = $savedXdg
        if ($savedXml -and $null -ne (Get-TTTask)) {
            # Only this test owns the exact saved receipt and its synthetic variant.
            Set-TTTask $savedXml | Out-Null
            & $uninstaller @layout -Confirm:$false
        }
        $checkedLive = Get-TTPath $liveTemp
        if (-not $checkedLive.StartsWith($testParent + '\telltale-lifecycle-live-', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected live test cleanup root.' }
        if (Test-Path -LiteralPath $checkedLive) { Remove-Item -LiteralPath $checkedLive -Recurse -Force }
    }
}
