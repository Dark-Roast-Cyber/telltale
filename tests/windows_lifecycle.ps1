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
$script:firstFailureReported = $false
$script:testScenario = 'setup'
$script:testLayout = $null
$script:lockWorker = $null
$script:testScheduler = 'substituted'
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Assertion failed: $Message" }
    $script:assertions++
}
function Assert-Fails([scriptblock]$Operation, [string]$Message, [string]$ExpectedExceptionType) {
    $failed = $false
    try { & $Operation | Out-Null } catch {
        $failed = $true
        if ($ExpectedExceptionType) {
            Assert-True (@(Get-TestExceptionChain $_.Exception | Where-Object { $_.type -ceq $ExpectedExceptionType }).Count -eq 1) 'expected injected exception type, not an unrelated failure'
        }
    }
    Assert-True $failed $Message
}
function New-TestLayout([string]$Name) {
    $directory = Join-Path $temp $Name
    $script:testScenario = $Name
    $script:testLayout = @{ InstallDirectory = (Join-Path $directory 'Application With Spaces'); DataDirectory = (Join-Path $directory 'Runtime Data') }
    if ($null -ne $script:testPreRollbackContext) {
        $script:testPreRollbackContext.Layout = $script:testLayout
        $script:testPreRollbackContext.Scenario = $Name
    }
    return $script:testLayout
}
function Get-TreeDigest([string]$Directory) {
    return (@(Get-ChildItem -LiteralPath $Directory -Recurse -Force | Sort-Object FullName | ForEach-Object {
        if ($_.PSIsContainer) { $_.FullName } else { "$($_.FullName):$((Get-FileHash -LiteralPath $_.FullName).Hash)" }
    }) -join "`n")
}

function Get-TestExceptionChain($Exception) {
    $chain = @()
    for ($depth = 0; $null -ne $Exception -and $depth -lt 8; $depth++) {
        $chain += @{ type = $Exception.GetType().FullName; hresult = $Exception.HResult }
        $Exception = $Exception.InnerException
    }
    return $chain
}

function Get-TestSharingError([object[]]$Records) {
    # ErrorVariable is command-local and includes nested errors. Never inspect
    # the session-wide error history or assume the final string throw is original.
    if ($null -eq $Records) { return $null }
    for ($index = 0; $index -lt [Math]::Min(32, $Records.Count); $index++) {
        $record = $Records[$index]
        if ($record -isnot [System.Management.Automation.ErrorRecord]) { continue }
        if (-not [string]::Equals($record.InvocationInfo.ScriptName, $helper, [StringComparison]::OrdinalIgnoreCase) -and
            -not [string]::Equals($record.InvocationInfo.ScriptName, $installer, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if (@(Get-TestExceptionChain $record.Exception | Where-Object { $_.hresult -eq -2147024864 }).Count -gt 0) { return $record }
    }
    return $null
}

function Get-TestErrorSummary($Failure) {
    if ($null -eq $Failure) { return @{ status = 'unknown'; reason = 'original command error unavailable within 32 records' } }
    $scriptName = [IO.Path]::GetFileName($Failure.InvocationInfo.ScriptName)
    if ($scriptName -cnotin @('windows-lifecycle.ps1', 'uninstall-telltale.ps1', 'install-telltale.ps1')) { return @{ status = 'unknown'; reason = 'unexpected error origin' } }
    return @{
        status = 'captured'; script = $scriptName; line = $Failure.InvocationInfo.ScriptLineNumber
        stack = ([string]$Failure.ScriptStackTrace).Substring(0, [Math]::Min(4096, ([string]$Failure.ScriptStackTrace).Length))
        exceptions = @(Get-TestExceptionChain $Failure.Exception)
    }
}

function Assert-TestDiagnosticTarget([string]$Path, [switch]$FixedLeaf, [switch]$AllowMissing, $Context = $null) {
    # Lexical scope checks precede ALL filesystem/native probes. A similar
    # prefix, another test root, canonical installation or normalized escape fails.
    $parent = [IO.Path]::Combine($script:TTLocal, 'TelltaleLifecycleTests')
    $diagnosticParent = if ($null -eq $Context) { $script:testParent } else { $Context.Parent }
    $diagnosticRoot = if ($null -eq $Context) { $script:temp } else { $Context.Root }
    $diagnosticLayout = if ($null -eq $Context) { $script:testLayout } else { $Context.Layout }
    if (-not [string]::Equals($diagnosticParent, $parent, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([IO.Path]::GetDirectoryName($diagnosticRoot), $parent, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($diagnosticRoot) -cnotmatch '^telltale-lifecycle-tests-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
        $null -eq $diagnosticLayout) { throw 'Diagnostic root is not the current GUID-scoped synthetic root.' }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [string]::Equals($full, $Path, [StringComparison]::OrdinalIgnoreCase) -or
        -not $full.StartsWith($diagnosticRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Diagnostic target is outside the exact synthetic root or is not normalized.' }
    $relative = $full.Substring($diagnosticRoot.Length + 1)
    $leaf = [IO.Path]::GetFileName($full)
    $allowed = if ($FixedLeaf) { @('telltale.exe', 'staged.exe', 'previous.exe', 'install-receipt.json', 'transaction.json') } else { @('telltale.exe', 'staged.exe') }
    if ($relative -cnotmatch '^[A-Za-z0-9-]{1,64}\\Application With Spaces\\[^\\]+$' -or $leaf -cnotin $allowed -or
        -not [string]::Equals($full, [IO.Path]::Combine($diagnosticLayout.InstallDirectory, $leaf), [StringComparison]::OrdinalIgnoreCase)) { throw 'Diagnostic target is not an exact selected synthetic leaf.' }
    Get-TTPath $full | Out-Null
    foreach ($directory in @($diagnosticParent, $diagnosticRoot, $diagnosticLayout.InstallDirectory)) {
        if (Test-Path -LiteralPath $directory) {
            if (-not (Test-Path -LiteralPath $directory -PathType Container)) { throw 'Diagnostic ancestor is not a directory.' }
            Assert-TTOwner $directory
        }
    }
    if ($AllowMissing -and -not (Test-Path -LiteralPath $full)) { return $full }
    Assert-TTFile $full -Owned
    return $full
}

function Get-TestLockUsers([string]$Path, $Refusal = $null, [switch]$BeforeRollback, $Context = $null) {
    $leaf = [IO.Path]::GetFileName($Path)
    if ($BeforeRollback) {
        Assert-TestPreRollbackQuery $Path $Refusal $Context
        $checked = Assert-TestDiagnosticTarget $Path -FixedLeaf -Context $Context
    } else {
        if ($leaf -ceq 'staged.exe' -and ($script:testScenario -cnotin @('fresh', 'partial-rollback', 'controlled-stage-lock', 'recovery-False') -or
            $null -eq $Refusal -or @(Get-TestExceptionChain $Refusal.Exception | Where-Object { $_.hresult -eq -2147024864 }).Count -eq 0)) {
            throw 'Staged attribution requires a selected scenario and an observed sharing refusal.'
        }
        $checked = Assert-TestDiagnosticTarget $Path
    }
    $report = @{ status = 'unknown'; scope = "exact synthetic $leaf"; processes = @(); limitation = 'post-failure resource users are not proof of lock ownership; kernel users may be absent' }
    if ($env:GITHUB_ACTIONS -cne 'true') { $report.reason = 'native attribution restricted to disposable CI'; return $report }
    try {
        $result = [TelltaleLifecycleTests.LockUsers]::Query($checked)
        $report.status = $result.Status
        $report.reason = $result.Stage
        $report.code = $result.Code
        $report.end_code = $result.EndCode
        $report.truncated = $result.Truncated
        foreach ($user in $result.Processes) { $report.processes += @{ pid = $user.Pid; start_filetime = $user.StartFileTime; image = $user.Image } }
    } catch { $report.reason = 'native attribution unavailable'; $report.exceptions = @(Get-TestExceptionChain $_.Exception) }
    return $report
}

function Get-TestFileDiagnostic([string]$Name) {
    $entry = [ordered]@{ name = $Name; state = 'unknown' }
    try {
        $path = Assert-TestDiagnosticTarget ([IO.Path]::Combine($script:testLayout.InstallDirectory, $Name)) -FixedLeaf -AllowMissing
        if (Test-Path -LiteralPath $path) {
            $entry.state = 'present'
            try { $entry.sha256 = Get-TTHash $path }
            catch { $entry.read_error = @(Get-TestExceptionChain $_.Exception) }
            try { Assert-TTUnlocked $path; $entry.exclusive_probe = 'available' }
            catch {
                $probeFailure = $_
                $entry.exclusive_probe = 'refused'; $entry.probe_error = @(Get-TestExceptionChain $probeFailure.Exception)
                if ($Name -ceq 'staged.exe' -and $script:testScenario -cin @('fresh', 'partial-rollback', 'controlled-stage-lock', 'recovery-False')) {
                    try { $entry.lock_users = Get-TestLockUsers $path $probeFailure }
                    catch { $entry.lock_users = @{ status = 'unknown'; reason = 'synthetic stage validation or attribution failed'; processes = @(); exceptions = @(Get-TestExceptionChain $_.Exception) } }
                }
            }
            if ($Name -cin @('telltale.exe', 'staged.exe', 'previous.exe')) {
                # Distinguishes a sharing reader from a running image or a user that blocks replacement.
                try { [TelltaleLifecycle.Native]::AssertReplaceable($path); $entry.replace_probe = 'available' }
                catch { $entry.replace_probe = 'refused'; $entry.replace_probe_error = @(Get-TestExceptionChain $_.Exception) }
            }
            if ($Name -cin @('install-receipt.json', 'transaction.json')) {
                try {
                    $metadata = Read-TTJson $path
                    $entry.metadata = 'readable'
                    foreach ($flag in @('uninstalling', 'committed')) {
                        if ($metadata.PSObject.Properties[$flag] -and $metadata.$flag -is [bool]) { $entry[$flag] = $metadata.$flag }
                    }
                } catch { $entry.metadata = 'unknown'; $entry.metadata_error = @(Get-TestExceptionChain $_.Exception) }
            }
        } else { $entry.state = 'missing' }
    } catch { $entry.error = @(Get-TestExceptionChain $_.Exception) }
    return $entry
}

function Invoke-TestDiagnosticInstall([hashtable]$Layout, [string]$DevelopmentBinary) {
    if ($script:testScenario -cnotin @('fresh', 'partial-rollback', 'recovery-False') -or $Layout.Count -ne 2 -or
        $Layout.InstallDirectory -cne $script:testLayout.InstallDirectory -or $Layout.DataDirectory -cne $script:testLayout.DataDirectory) { throw 'Installer diagnostics require the exact selected scenario.' }
    $installErrors = @()
    try { & $installer @Layout -DevelopmentBinary $DevelopmentBinary -ErrorVariable installErrors }
    catch {
        $failure = $_
        Write-TestFailure $failure (Get-TestSharingError $installErrors)
        throw
    }
}

function Write-TestFailure($Failure, $OriginalError = $null) {
    if ($script:firstFailureReported) { return }
    $script:firstFailureReported = $true
    try {
        $self = [Diagnostics.Process]::GetCurrentProcess()
        try { $identity = @{ pid = $self.Id; start_utc = $self.StartTime.ToUniversalTime().ToString('o') } }
        finally { $self.Dispose() }
        # String throws can use the entire message as their error ID; do not
        # serialize arbitrary messages or source lines in addition to the rethrow.
        $errorId = [string]$Failure.FullyQualifiedErrorId
        if ($errorId -cnotmatch '^[A-Za-z0-9_.:,-]{1,256}$') { $errorId = 'omitted-non-identifier' }
        $report = [ordered]@{
            scenario = $script:testScenario; observed_utc = [DateTime]::UtcNow.ToString('o'); assertions = $script:assertions; process = $identity
            error_id = $errorId
            category = [string]$Failure.CategoryInfo.Category
            script = [IO.Path]::GetFileName($Failure.InvocationInfo.ScriptName)
            line = $Failure.InvocationInfo.ScriptLineNumber
            stack = ([string]$Failure.ScriptStackTrace).Substring(0, [Math]::Min(4096, ([string]$Failure.ScriptStackTrace).Length))
            exceptions = @(Get-TestExceptionChain $Failure.Exception)
            exception_limit = 'Installer string rethrows may have discarded the original inner stack and HResult.'
            original_error = Get-TestErrorSummary $OriginalError
            lock_owner = 'unknown: resource users and file probes below are post-failure observations, not proof of ownership'
            lock_users = @{ status = 'unknown'; reason = 'outside selected synthetic sharing-failure scenarios'; processes = @() }
            known_lock_worker = $script:lockWorker; files = @(); task = 'not inspected'; scheduler = $script:testScheduler
            target = if ($null -ne $script:testLayout) { $script:testLayout.InstallDirectory } else { 'not selected' }
        }
        if ($null -ne $script:testLayout -and $script:testScenario -cin @('task-transition-True', 'distinct-process-locked-recovery', 'first-install-recovery')) {
            try { $report.lock_users = Get-TestLockUsers ([IO.Path]::Combine($script:testLayout.InstallDirectory, 'telltale.exe')) }
            catch { $report.lock_users.reason = 'synthetic target validation or attribution failed'; $report.lock_users.exceptions = @(Get-TestExceptionChain $_.Exception) }
        }
        if ($null -ne $script:testLayout) {
            # Fixed synthetic leaves only: never enumerate directories or dump metadata contents.
            foreach ($name in @('telltale.exe', 'staged.exe', 'previous.exe', 'install-receipt.json', 'transaction.json')) {
                $report.files += Get-TestFileDiagnostic $name
            }
        }
        if ($script:testScheduler -ne 'not inspected') {
            try {
                $task = Get-TTTask
                $report.task = if ($null -eq $task) { @{ present = $false } }
                    else { @{ present = $true; state = $task.State; enabled = $task.Enabled; xml_sha256 = Get-TTTextHash $task.Xml } }
            } catch { $report.task = @{ state = 'unknown'; exceptions = @(Get-TestExceptionChain $_.Exception) } }
        }
        Write-Host ('Windows lifecycle first failure: ' + ($report | ConvertTo-Json -Depth 12 -Compress))
    } catch {
        # Even a failed diagnostic output channel must not replace the test error.
        try { Write-Host ('Windows lifecycle diagnostics: unknown; capture failed: ' + ($_.Exception.GetType().FullName)) }
        catch { }
    }
}

# The regression matrix exercises real scripts, files and binaries. Only Task
# Scheduler is substituted, so it cannot change a developer's real task.
$testAssemblyRefs = if ($PSVersionTable.PSEdition -eq 'Desktop') { @{ ReferencedAssemblies = @('System.Xml.dll') } } else { @{} }
Add-Type @testAssemblyRefs -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;
namespace TelltaleLifecycleTests {
    // https://learn.microsoft.com/windows/win32/api/restartmanager/nf-restartmanager-rmgetlist
    // Register ONE file, one fixed-buffer query, no retries/shutdown/restart.
    public static class LockUsers {
        [StructLayout(LayoutKind.Sequential)]
        struct UniqueProcess { public uint Pid; public System.Runtime.InteropServices.ComTypes.FILETIME Started; }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        struct ProcessInfo {
            public UniqueProcess Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string AppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst=64)] public string ServiceName;
            public uint ApplicationType, Status, SessionId;
            [MarshalAs(UnmanagedType.Bool)] public bool Restartable;
        }
        [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)]
        static extern uint RmStartSession(out uint session, uint flags, StringBuilder key);
        [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)]
        static extern uint RmRegisterResources(uint session, uint fileCount,
            [MarshalAs(UnmanagedType.LPArray, ArraySubType=UnmanagedType.LPWStr)] string[] files,
            uint appCount, UniqueProcess[] apps, uint serviceCount, string[] services);
        [DllImport("rstrtmgr.dll")]
        static extern uint RmGetList(uint session, out uint needed, ref uint count,
            [In, Out] ProcessInfo[] processes, out uint rebootReasons);
        [DllImport("rstrtmgr.dll")]
        static extern uint RmEndSession(uint session);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool GetProcessTimes(IntPtr process, out long created, out long exited, out long kernel, out long user);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref uint size);
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr handle);
        // Only a reported PID whose live creation time matches yields an image
        // basename; exited, reused or inaccessible identities stay explicit unknowns.
        static string ImageName(uint pid, long started) {
            IntPtr process = OpenProcess(0x1000, false, pid);
            if (process == IntPtr.Zero) return "unknown: not accessible";
            try {
                long created, exited, kernel, user;
                if (!GetProcessTimes(process, out created, out exited, out kernel, out user)) return "unknown: start time unavailable";
                if (created != started) return "unknown: identity changed";
                var name = new StringBuilder(1024);
                uint size = 1024;
                if (!QueryFullProcessImageName(process, 0, name, ref size)) return "unknown: image unavailable";
                return Path.GetFileName(name.ToString());
            } finally { CloseHandle(process); }
        }
        public class Identity { public uint Pid; public long StartFileTime; public string Image; }
        public class Result {
            public string Status = "unknown", Stage = "start_session";
            public uint Code, EndCode;
            public bool Truncated;
            public Identity[] Processes = new Identity[0];
        }
        public static Result Query(string path) {
            var result = new Result();
            uint session;
            result.Code = RmStartSession(out session, 0, new StringBuilder(33));
            if (result.Code != 0) return result;
            try {
                result.Stage = "register_resource";
                result.Code = RmRegisterResources(session, 1, new[] { path }, 0, null, 0, null);
                if (result.Code != 0) return result;
                var buffer = new ProcessInfo[16];
                uint count = 16, needed, rebootReasons;
                result.Stage = "get_list";
                result.Code = RmGetList(session, out needed, ref count, buffer, out rebootReasons);
                result.Truncated = result.Code == 234 || count > 8;
                if (result.Code != 0 || count > 16) return result;
                int retained = (int)Math.Min(count, 8u);
                result.Processes = new Identity[retained];
                for (int index = 0; index < retained; index++) {
                    var process = buffer[index].Process;
                    long started = ((long)(uint)process.Started.dwHighDateTime << 32) | (uint)process.Started.dwLowDateTime;
                    result.Processes[index] = new Identity { Pid = process.Pid, StartFileTime = started, Image = ImageName(process.Pid, started) };
                }
                result.Stage = count == 0 ? "no_resource_users_reported" : "resource_users_reported";
                if (count != 0) result.Status = "reported";
            } finally {
                result.EndCode = RmEndSession(session);
                if (result.EndCode != 0) { result.Status = "unknown"; result.Stage = "end_session"; }
            }
            return result;
        }
    }
    public class Task {
        XmlDocument document = new XmlDocument();
        bool enabled;
        public Task(string xml) { document.LoadXml(xml); State = 3; enabled = document.GetElementsByTagName("Settings")[0]["Enabled"].InnerText == "true"; }
        public string Xml { get { return document.OuterXml; } }
        public int State { get; set; }
        public bool Enabled {
            // Model the native cached XML getter: changing Enabled alone does
            // not replace this object's captured definition.
            get { return enabled; }
            set { enabled = value; }
        }
        public void Stop(int flags) { State = 3; }
    }
    public class InjectedRegistrationInterruption : IOException {
        public InjectedRegistrationInterruption() : base("Injected interruption before task registration.") {}
    }
    public class Folder {
        public static Task Current;
        public static bool FailRegistrationOnce;
        public Task GetTask(string name) { if (Current == null) throw new FileNotFoundException(); return Current; }
        public Task RegisterTask(string name, string xml, int flags, string sid, object password, int logon, object security) {
            if (FailRegistrationOnce) { FailRegistrationOnce = false; throw new InjectedRegistrationInterruption(); }
            if (flags == 4 && Current == null) throw new FileNotFoundException();
            if (flags == 2 && Current != null) throw new IOException("Task already exists.");
            if (xml.IndexOf("encoding=\"UTF-8\"", StringComparison.OrdinalIgnoreCase) >= 0)
                throw new ArgumentException("Task XML must match UTF-16 COM transport.");
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
. (Join-Path $PSScriptRoot 'windows_lifecycle_pre_rollback.ps1')
try {
    & (Join-Path $PSScriptRoot 'windows_lifecycle_breakpoints.ps1')
    Start-TestPreRollbackCapture
    Invoke-TestPreRollbackControl $binary
    Assert-Fails {
        Assert-Fails { throw [IO.IOException]::new('unrelated synthetic error') } 'synthetic failure' -ExpectedExceptionType 'TelltaleLifecycleTests.InjectedRegistrationInterruption'
    } 'unrelated failure cannot satisfy the registration interruption assertion'
    $layout = New-TestLayout 'fresh'
    $before = Get-TreeDigest $temp
    & $installer @layout -DevelopmentBinary $binary -WhatIf
    Assert-True ((Get-TreeDigest $temp) -ceq $before) 'install WhatIf makes no filesystem changes'
    Invoke-TestDiagnosticInstall $layout $BinaryPath
    Assert-True (Test-Path -LiteralPath (Join-Path $layout.InstallDirectory 'telltale.exe')) 'fresh development installation'
    Assert-True ($null -eq (Get-TTTask)) 'task absent by default'
    $receipt = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
    Assert-True ($receipt.source.kind -ceq 'development-local') 'development provenance stays distinct'
    Invoke-TestDiagnosticInstall $layout $binary
    Assert-True ((Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory).id -ceq $receipt.id) 'same-version repeat preserves installation identity'
    $variant = Join-Path $temp 'development-variant.exe'
    Copy-Item -LiteralPath $binary -Destination $variant
    Set-TTCreatedOwner $variant
    # A valid executable overlay gives a distinct development digest without
    # pretending this fixture is a separately compiled or published version.
    $stream = [IO.File]::Open($variant, 'Append', 'Write', 'None')
    try { $stream.WriteByte(42) } finally { $stream.Dispose() }
    Invoke-TestDiagnosticInstall $layout $variant
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
    $script:testScenario = 'fresh-synthetic-scan'
    $script:testLayout = $layout
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
    Assert-True ($taskXml.FirstChild.Encoding -ceq 'UTF-16') 'task declaration matches native COM string transport'
    Assert-True ($taskXml.Task.Settings.Enabled -ceq 'true') 'enabled task export can be registered again without disabling execution'
    Assert-True ($taskXml.Task.Principals.Principal.UserId -ceq $script:TTSid -and $taskXml.Task.Principals.Principal.RunLevel -ceq 'LeastPrivilege') 'current-user least-privilege task'
    Assert-True ($taskXml.Task.Triggers.LogonTrigger.Repetition.Interval -ceq 'PT30M' -and $taskXml.Task.Actions.Exec.Arguments.Contains('"')) 'template cadence and quoting'
    & $installer @layout -DevelopmentBinary $binary
    Assert-True ((Get-TTTask).Enabled) 'repeat preserves managed schedule'
    (Get-TTTask).Enabled = $false
    $taskMetadata = Join-Path $layout.InstallDirectory 'install-receipt.json'
    $taskMetadataLock = [IO.File]::Open($taskMetadata, 'Open', 'Read', 'Read')
    try { Assert-Fails { & $installer @layout -DevelopmentBinary $variant } 'failed reinstall of disabled task reports failure' }
    finally { $taskMetadataLock.Dispose() }
    & $installer @layout -DevelopmentBinary $binary
    Assert-True (-not (Get-TTTask).Enabled) 'rollback and retry preserve a manually disabled managed task'
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

    $layout = New-TestLayout 'distinct-process-locked-recovery'
    & $installer @layout -DevelopmentBinary $binary
    $installed = Join-Path $layout.InstallDirectory 'telltale.exe'
    $previous = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
    $before = Get-TreeDigest $layout.InstallDirectory
    $lockWorkerScript = Join-Path $temp 'read-lock-worker.ps1'
    [IO.File]::WriteAllText($lockWorkerScript, @'
param($Target, $ReadyEvent, $ReleaseEvent)
$ErrorActionPreference = 'Stop'
$ready = [Threading.EventWaitHandle]::OpenExisting($ReadyEvent)
$release = [Threading.EventWaitHandle]::OpenExisting($ReleaseEvent)
$stream = $null
try {
    $stream = [IO.File]::Open($Target, 'Open', 'Read', 'Read')
    $ready.Set() | Out-Null
    if (-not $release.WaitOne(120000)) { throw 'Synthetic read-lock release timed out.' }
} finally {
    if ($null -ne $stream) { $stream.Dispose() }
    $ready.Dispose()
    $release.Dispose()
}
'@)
    $eventPrefix = 'Local\TelltaleLifecycleTests-' + [guid]::NewGuid().ToString()
    $lockReady = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, ($eventPrefix + '-ready'))
    $lockRelease = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset, ($eventPrefix + '-release'))
    $lockProcess = $null
    $workerId = $null
    $workerStart = $null
    try {
        $workerArguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Target "{1}" -ReadyEvent "{2}" -ReleaseEvent "{3}"' -f $lockWorkerScript, $installed, ($eventPrefix + '-ready'), ($eventPrefix + '-release')
        $lockProcess = Start-Process -FilePath $engine -ArgumentList $workerArguments -WindowStyle Hidden -PassThru
        $workerId = $lockProcess.Id
        $workerStart = $lockProcess.StartTime.ToUniversalTime()
        $script:lockWorker = @{ pid = $workerId; start_utc = $workerStart.ToString('o'); target = $installed; ready = $false; release_requested = $false; exit_observed = $false }
        $script:lockWorker.ready = $lockReady.WaitOne(15000)
        Assert-True $script:lockWorker.ready 'distinct worker signaled after opening exact installed binary'
        Assert-True (-not $lockProcess.HasExited -and $lockProcess.Id -eq $workerId -and $lockProcess.StartTime.ToUniversalTime() -eq $workerStart) 'ready worker PID and start time match owned process'
        $probeFailure = $null
        try { Assert-TTUnlocked $installed } catch { $probeFailure = $_ }
        Assert-True ($null -ne $probeFailure) 'known child read lock rejects exclusive binary access'
        $script:lockWorker.exclusive_probe_exceptions = @(Get-TestExceptionChain $probeFailure.Exception)
        Assert-True (@($script:lockWorker.exclusive_probe_exceptions | Where-Object { $_.hresult -eq -2147024864 }).Count -gt 0) 'known child lock produces native ERROR_SHARING_VIOLATION'
        Write-Host ('Windows lifecycle synthetic read lock: ' + ($script:lockWorker | ConvertTo-Json -Depth 6 -Compress))
        Assert-Fails { & $installer @layout -DevelopmentBinary $variant } 'distinct-process lock blocks replacement'
        Assert-True ((Get-TreeDigest $layout.InstallDirectory) -ceq $before) 'blocked replacement preserves binary, receipt and absent journal'
        $uninstallErrors = @()
        $uninstallFailure = $null
        try { & $uninstaller @layout -Confirm:$false -ErrorVariable uninstallErrors | Out-Null }
        catch { $uninstallFailure = $_ }
        Assert-True ($null -ne $uninstallFailure) 'distinct-process lock blocks uninstall'
        $originalError = Get-TestSharingError $uninstallErrors
        Assert-True ($null -ne $originalError) 'command-scoped errors retain original sharing violation through production string rethrow'
        $originalSummary = Get-TestErrorSummary $originalError
        Assert-True ($originalSummary.script -ceq 'windows-lifecycle.ps1' -and $originalSummary.line -gt 0) 'original diagnostic points to helper rather than uninstall wrapper'
        Assert-True (@($originalSummary.exceptions | Where-Object { $_.hresult -eq -2147024864 }).Count -gt 0) 'original diagnostic retains native sharing HRESULT'
        Assert-True (-not ($originalSummary | ConvertTo-Json -Depth 12 -Compress).Contains($installed)) 'original diagnostic omits raw exception target and message'
        Assert-True ([IO.Path]::GetFileName($uninstallFailure.InvocationInfo.ScriptName) -ceq 'uninstall-telltale.ps1') 'controlled failure still travels through unchanged production catch'
        $users = Get-TestLockUsers $installed
        Assert-True ($users.status -cin @('reported', 'unknown') -and @($users.processes).Count -le 8) 'exact-file attribution has bounded explicit reported or unknown result'
        foreach ($user in @($users.processes)) {
            Assert-True (@($user.Keys | Where-Object { $_ -cnotin @('pid', 'start_filetime', 'image') }).Count -eq 0 -and $user.image -cmatch '^(?:unknown: [a-z ]+|[^\\/:]{1,255})$') 'attribution exposes only process identity and an image basename or explicit unknown'
            if ($user.pid -eq $workerId) {
                Assert-True ($user.start_filetime -eq $workerStart.ToFileTimeUtc() -and $user.image -ceq $engineName) 'reported controlled worker has the recorded start identity and engine image'
            }
        }
        foreach ($invalidTarget in @($binary, (Join-Path $temp 'telltale.exe'), (Join-Path $layout.InstallDirectory 'install-receipt.json'), (Join-Path $layout.InstallDirectory '..\Application With Spaces\telltale.exe'))) {
            Assert-Fails { Assert-TestDiagnosticTarget $invalidTarget } 'diagnostics reject nonexact or nonnormalized synthetic target before native query'
        }
        Write-Host ('Windows lifecycle controlled diagnostic: ' + (@{ original_error = $originalSummary; lock_users = $users; known_worker_match = @($users.processes | Where-Object { $_.pid -eq $workerId -and $_.start_filetime -eq $workerStart.ToFileTimeUtc() }).Count -eq 1 } | ConvertTo-Json -Depth 12 -Compress))
        Assert-True ((Get-TreeDigest $layout.InstallDirectory) -ceq $before) 'blocked uninstall preserves binary, receipt and absent journal'

        # A separate interrupted transaction must remain byte-for-byte recoverable
        # while the same known worker still holds the installed executable.
        $next = ($previous | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
        $next.binary_sha256 = Get-TTHash $variant
        $journalPath = Join-Path $layout.InstallDirectory 'transaction.json'
        Write-TTJson $journalPath @{ previous = $previous; next = $next; committed = $false; path_changed = $false; path_before = $null; path_after = $null }
        $stage = Join-Path $layout.InstallDirectory 'staged.exe'
        Copy-Item -LiteralPath $variant -Destination $stage
        Set-TTCreatedOwner $stage
        $beforeRecovery = Get-TreeDigest $layout.InstallDirectory
        Assert-Fails { & $installer @layout -DevelopmentBinary $binary } 'known child lock blocks pending transaction recovery'
        Assert-True ((Get-TreeDigest $layout.InstallDirectory) -ceq $beforeRecovery) 'blocked recovery preserves binary, receipt, journal and stage bytes'
        Assert-Fails { & $uninstaller @layout -Confirm:$false } 'pending locked transaction blocks cleanup'
        Assert-True ((Get-TreeDigest $layout.InstallDirectory) -ceq $beforeRecovery) 'blocked pending cleanup preserves transaction evidence'
        Assert-True (-not $lockProcess.HasExited -and $lockProcess.Id -eq $workerId -and $lockProcess.StartTime.ToUniversalTime() -eq $workerStart) 'same owned worker remains until explicit release'
        $lockRelease.Set() | Out-Null
        $script:lockWorker.release_requested = $true
        $script:lockWorker.exit_observed = $lockProcess.WaitForExit(15000)
        Assert-True $script:lockWorker.exit_observed 'released worker exited within bound'
        Assert-True ($lockProcess.ExitCode -eq 0) 'released worker closed lock successfully'
        Write-Host ('Windows lifecycle synthetic read lock: ' + ($script:lockWorker | ConvertTo-Json -Depth 6 -Compress))
        Assert-TTUnlocked $installed
        & $installer @layout -DevelopmentBinary $binary
        $recovered = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
        Assert-True ($recovered.id -ceq $previous.id -and $recovered.binary_sha256 -ceq $previous.binary_sha256 -and -not (Test-Path -LiteralPath $journalPath) -and -not (Test-Path -LiteralPath $stage)) 'explicit post-release recovery preserves identity and clears transaction'
        & $uninstaller @layout -Confirm:$false
        Assert-True (-not (Test-Path -LiteralPath $installed)) 'post-release cleanup removes owned executable'
    } catch {
        Write-TestFailure $_
        throw
    } finally {
        try {
            $lockRelease.Set() | Out-Null
            if ($null -ne $lockProcess) {
                if (-not $lockProcess.WaitForExit(15000)) {
                    if ($null -eq $workerStart -or $lockProcess.Id -ne $workerId -or $lockProcess.StartTime.ToUniversalTime() -ne $workerStart) { throw 'Owned worker identity unknown or changed; no process terminated.' }
                    $lockProcess.Kill()
                    if (-not $lockProcess.WaitForExit(15000)) { throw 'Owned read-lock worker did not exit after termination.' }
                }
                $lockProcess.Dispose()
            }
        } catch {
            if (-not $script:firstFailureReported) { Write-TestFailure $_; throw }
            try { Write-Host 'Windows lifecycle read-lock worker cleanup: unknown; original failure retained.' } catch { }
        } finally { $lockReady.Dispose(); $lockRelease.Dispose() }
        $script:lockWorker = $null
    }

    $layout = New-TestLayout 'controlled-stage-lock'
    & $installer @layout -DevelopmentBinary $binary
    $installed = Join-Path $layout.InstallDirectory 'telltale.exe'
    $previous = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
    $next = ($previous | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
    $next.binary_sha256 = Get-TTHash $variant
    $journalPath = Join-Path $layout.InstallDirectory 'transaction.json'
    Write-TTJson $journalPath @{ previous = $previous; next = $next; committed = $false; path_changed = $false; path_before = $null; path_after = $null }
    $stage = Join-Path $layout.InstallDirectory 'staged.exe'
    Copy-Item -LiteralPath $variant -Destination $stage
    Set-TTCreatedOwner $stage
    $stageAlias = Join-Path $temp 'stage-hardlink.exe'
    New-Item -ItemType HardLink -Path $stageAlias -Target $stage | Out-Null
    try { Assert-Fails { Assert-TestDiagnosticTarget $stage } 'stage diagnostics reject a hard-linked exact target' }
    finally { Remove-Item -LiteralPath $stageAlias }
    foreach ($invalidTarget in @((Join-Path $temp 'staged.exe'), (Join-Path $layout.DataDirectory 'staged.exe'), (Join-Path $layout.InstallDirectory 'previous.exe'), (Join-Path $layout.InstallDirectory '..\Application With Spaces\staged.exe'))) {
        Assert-Fails { Assert-TestDiagnosticTarget $invalidTarget } 'stage diagnostics reject nonselected filename layout or normalized escape'
    }
    $beforeStageDiagnostic = Get-TreeDigest $layout.InstallDirectory
    $stageStream = [IO.File]::Open($stage, 'Open', 'Read', 'Read')
    try {
        Assert-TTUnlocked $installed
        $installErrors = @()
        $installFailure = $null
        try { & $installer @layout -DevelopmentBinary $binary -ErrorVariable installErrors | Out-Null }
        catch { $installFailure = $_ }
        Assert-True ($null -ne $installFailure) 'controlled stage lock blocks installer recovery'
        $originalSummary = Get-TestErrorSummary (Get-TestSharingError $installErrors)
        Assert-True ($originalSummary.status -ceq 'captured' -and $originalSummary.script -ceq 'windows-lifecycle.ps1') 'installer command retains original recovery sharing error'
        Assert-True (@($originalSummary.exceptions | Where-Object { $_.hresult -eq -2147024864 }).Count -gt 0) 'controlled stage recovery retains native sharing HRESULT'
        Assert-Fails { Get-TestLockUsers $stage } 'staged-file query requires an observed sharing refusal'
        $stageDiagnostic = Get-TestFileDiagnostic 'staged.exe'
        Assert-True ($stageDiagnostic.exclusive_probe -ceq 'refused' -and $stageDiagnostic.lock_users.status -cin @('reported', 'unknown')) 'refused exact stage has bounded attribution or explicit unknown'
        Assert-True (@($stageDiagnostic.lock_users.processes).Count -le 8) 'staged-file attribution is bounded'
        foreach ($user in @($stageDiagnostic.lock_users.processes)) {
            Assert-True (@($user.Keys | Where-Object { $_ -cnotin @('pid', 'start_filetime', 'image') }).Count -eq 0 -and $user.image -cmatch '^(?:unknown: [a-z ]+|[^\\/:]{1,255})$') 'stage attribution exposes only process identity and an image basename or explicit unknown'
        }
        Assert-True ($stageStream.CanRead -and (Get-TreeDigest $layout.InstallDirectory) -ceq $beforeStageDiagnostic) 'stage diagnostics preserve open lock and all protected bytes'
        Assert-Fails { Assert-TTUnlocked $stage } 'stage diagnostics do not release or remediate the lock'
        Assert-Fails { & $uninstaller @layout -Confirm:$false } 'locked staged transaction still blocks cleanup'
        Assert-True ((Get-TreeDigest $layout.InstallDirectory) -ceq $beforeStageDiagnostic) 'stage diagnostics and refused cleanup preserve transaction evidence'
        Write-Host ('Windows lifecycle controlled stage diagnostic: ' + (@{ original_error = $originalSummary; file = $stageDiagnostic; lock_owner = 'known test stream; resource users are not ownership proof'; bytes_preserved = $true } | ConvertTo-Json -Depth 12 -Compress))
    } finally { $stageStream.Dispose() }
    Assert-TTUnlocked $stage
    & $installer @layout -DevelopmentBinary $binary
    Assert-True ((Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory).binary_sha256 -ceq $previous.binary_sha256 -and -not (Test-Path -LiteralPath $journalPath) -and -not (Test-Path -LiteralPath $stage)) 'controlled stage recovers only after explicit test release'
    & $uninstaller @layout -Confirm:$false

    # File.Replace opens its replacement with no sharing: even an outside reader
    # that shares read, write and delete produces the CI HRESULT 0x80070020.
    $layout = New-TestLayout 'shared-stage-reader'
    & $installer @layout -DevelopmentBinary $binary
    $installed = Join-Path $layout.InstallDirectory 'telltale.exe'
    $stage = Join-Path $layout.InstallDirectory 'staged.exe'
    $journalPath = Join-Path $layout.InstallDirectory 'transaction.json'
    $backup = Join-Path $layout.InstallDirectory 'previous.exe'
    $receiptPath = Join-Path $layout.InstallDirectory 'install-receipt.json'
    $previous = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
    $replacement = Join-Path $temp 'shared-reader-replacement.exe'
    $replaced = Join-Path $temp 'shared-reader-replaced.exe'
    Copy-Item -LiteralPath $variant -Destination $replacement
    Copy-Item -LiteralPath $binary -Destination $replaced
    $sharedReader = [IO.File]::Open($replacement, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        $refusal = $null
        try { [IO.File]::Replace($replacement, $replaced, [NullString]::Value) } catch { $refusal = $_ }
        Assert-True ($null -ne $refusal -and @(Get-TestExceptionChain $refusal.Exception | Where-Object { $_.hresult -eq -2147024864 }).Count -gt 0) 'File.Replace refuses a replacement with a fully sharing reader'
        Assert-True ((Get-FileHash -LiteralPath $replaced).Hash -ceq (Get-FileHash -LiteralPath $binary).Hash) 'refused File.Replace leaves the replaced file unchanged'
    } finally { $sharedReader.Dispose() }
    $staleBackup = Join-Path $temp 'shared-reader-backup.exe'
    [IO.File]::WriteAllText($staleBackup, 'stale backup')
    $refusal = $null
    try { [TelltaleLifecycle.Native]::ReplaceExecutable($replacement, $replaced, $staleBackup) } catch { $refusal = $_ }
    Assert-True ($null -ne $refusal -and @(Get-TestExceptionChain $refusal.Exception | Where-Object { $_.hresult -eq -2147024713 }).Count -gt 0) 'executable swap refuses a stale backup with ERROR_ALREADY_EXISTS'
    Assert-True ((Get-FileHash -LiteralPath $replacement).Hash -ceq (Get-FileHash -LiteralPath $variant).Hash -and (Get-FileHash -LiteralPath $replaced).Hash -ceq (Get-FileHash -LiteralPath $binary).Hash -and [IO.File]::ReadAllText($staleBackup) -ceq 'stale backup') 'stale backup refusal renames and overwrites nothing'
    Remove-Item -LiteralPath $staleBackup
    # A backup name differing only by case turns the first rename into a case
    # change, so the second rename deterministically collides and must be undone.
    $caseBackup = Join-Path $temp 'SHARED-READER-REPLACED.EXE'
    $refusal = $null
    try { [TelltaleLifecycle.Native]::ReplaceExecutable($replacement, $replaced, $caseBackup) } catch { $refusal = $_ }
    $names = @(Get-ChildItem -LiteralPath $temp -Force | Where-Object { $_.Name -like 'shared-reader-*' } | ForEach-Object { $_.Name })
    Assert-True ($null -ne $refusal -and @(Get-TestExceptionChain $refusal.Exception | Where-Object { $_.hresult -eq -2147024713 }).Count -gt 0) 'failed second rename propagates its original error'
    Assert-True ($names -ccontains 'shared-reader-replaced.exe' -and $names -cnotcontains 'SHARED-READER-REPLACED.EXE' -and (Get-FileHash -LiteralPath $replaced).Hash -ceq (Get-FileHash -LiteralPath $binary).Hash -and (Get-FileHash -LiteralPath $replacement).Hash -ceq (Get-FileHash -LiteralPath $variant).Hash) 'failed second rename undoes the first rename'
    Remove-Item -LiteralPath $replacement, $replaced
    $installerLines = [IO.File]::ReadAllLines($installer)
    $swapLines = @()
    for ($index = 0; $index -lt $installerLines.Length; $index++) {
        if ($installerLines[$index].Contains('[TelltaleLifecycle.Native]::ReplaceExecutable($stage, $binary,')) { $swapLines += $index + 1 }
    }
    Assert-True ($swapLines.Count -eq 1) 'installer has exactly one executable swap'
    # Inject the reader at the real installer swap. Breakpoint actions run in the
    # installer's scope, so the context travels on the breakpoint, not $script:.
    foreach ($share in @('ReadWrite, Delete', 'Read')) {
        $reader = @{ Target = $stage; Share = $share; Stream = $null; Hits = 0; Errors = @() }
        $breakpoint = Set-PSBreakpoint -Script $installer -Line $swapLines[0] -Action {
            $reader = $_.TelltaleReader
            $reader.Hits++
            try {
                if ($stage -cne $reader.Target) { throw 'Unexpected shared-reader target.' }
                if ($null -eq $reader.Stream) { $reader.Stream = [IO.File]::Open($stage, 'Open', 'Read', $reader.Share) }
            } catch { $reader.Errors = @(Get-TestExceptionChain $_.Exception) }
        }
        $breakpoint | Add-Member -NotePropertyName TelltaleReader -NotePropertyValue $reader
        $installedBefore = Get-TTHash $installed
        $receiptBefore = Get-TTHash $receiptPath
        $userPathBefore = Get-TTUserPath
        $candidate = if ($share -ceq 'Read') { $binary } else { $variant }
        # Cargo output can be hard-linked, so digest the input without the installed-file guard.
        $candidateHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
        $installErrors = @()
        $installFailure = $null
        try {
            try { & $installer @layout -DevelopmentBinary $candidate -ErrorVariable installErrors | Out-Null }
            catch { $installFailure = $_ }
            finally { Remove-PSBreakpoint -Breakpoint $breakpoint }
            Assert-True ($reader.Hits -eq 1 -and $reader.Errors.Count -eq 0 -and $null -ne $reader.Stream -and $reader.Stream.CanRead) "outside reader sharing [$share] held the exact stage at the swap"
            Assert-True ((Get-TTUserPath) -ceq $userPathBefore -and $null -eq (Get-TTTask)) "swap with outside reader sharing [$share] leaves PATH and task untouched"
            if ($share -ceq 'Read') {
                Assert-True ($null -ne $installFailure) 'outside stage reader that forbids renaming still blocks the swap'
                $swapRefusals = @($installErrors | Where-Object {
                    $_ -is [System.Management.Automation.ErrorRecord] -and $_.InvocationInfo.ScriptLineNumber -eq $swapLines[0] -and
                    [string]::Equals($_.InvocationInfo.ScriptName, $installer, [StringComparison]::OrdinalIgnoreCase) -and
                    @(Get-TestExceptionChain $_.Exception | Where-Object { $_.hresult -eq -2147024864 }).Count -gt 0
                })
                Assert-True ($swapRefusals.Count -ge 1) 'refused swap retains its original native sharing error at the installer swap'
                Assert-True ((Get-TTHash $installed) -ceq $installedBefore -and (Get-TTHash $receiptPath) -ceq $receiptBefore -and -not (Test-Path -LiteralPath $backup) -and (Test-Path -LiteralPath $journalPath) -and (Get-TTHash $stage) -ceq $candidateHash) 'refused swap renames nothing and keeps receipt and transaction evidence'
                if ($null -ne $script:testPreRollbackContext) {
                    # This deliberate refusal occupies the single first-refusal capture;
                    # verify it, then re-arm the capture for unexpected refusals.
                    $captured = $script:testPreRollbackContext.Report
                    Assert-True ($null -ne $captured -and $captured.original_error.line -eq $swapLines[0]) 'deliberate swap refusal reaches the pre-rollback capture'
                    $script:testPreRollbackContext.Report = $null
                }
            } else {
                Assert-True ($null -eq $installFailure) 'swap tolerates an outside stage reader that permits renaming'
                $swapped = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
                Assert-True ($swapped.id -ceq $previous.id -and $swapped.binary_sha256 -ceq $candidateHash -and (Get-TTHash $installed) -ceq $swapped.binary_sha256) 'shared-reader swap installs the verified digest'
                Assert-True (-not (Test-Path -LiteralPath $journalPath) -and -not (Test-Path -LiteralPath $stage) -and -not (Test-Path -LiteralPath $backup)) 'shared-reader swap commits and clears the transaction'
            }
        } finally { if ($null -ne $reader.Stream) { $reader.Stream.Dispose() } }
    }
    Assert-TTUnlocked $stage
    & $installer @layout -DevelopmentBinary $binary
    Assert-True ((Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory).binary_sha256 -ceq (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -and -not (Test-Path -LiteralPath $journalPath) -and -not (Test-Path -LiteralPath $stage)) 'refused swap recovers only after explicit reader release'
    & $uninstaller @layout -Confirm:$false

    # Managed executables require replaceability, not exclusivity: a transient reader
    # that shares everything cannot block reinstall, rollback or removal, while a
    # running image or a user that forbids deletion still can.
    $layout = New-TestLayout 'shared-executable-reader'
    & $installer @layout -DevelopmentBinary $binary
    $installed = Join-Path $layout.InstallDirectory 'telltale.exe'
    $stage = Join-Path $layout.InstallDirectory 'staged.exe'
    $backup = Join-Path $layout.InstallDirectory 'previous.exe'
    $journalPath = Join-Path $layout.InstallDirectory 'transaction.json'
    $previous = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
    $variantHash = Get-TTHash $variant
    $readers = @()
    try {
        $readers += [IO.File]::Open($installed, 'Open', 'Read', 'ReadWrite, Delete')
        Assert-Fails { Assert-TTUnlocked $installed } 'sharing reader still fails the exclusive probe kept for data and configuration'
        & $installer @layout -DevelopmentBinary $variant
        $current = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
        Assert-True ($current.id -ceq $previous.id -and $current.binary_sha256 -ceq $variantHash -and (Get-TTHash $installed) -ceq $variantHash -and -not (Test-Path -LiteralPath $journalPath) -and -not (Test-Path -LiteralPath $backup)) 'reinstall tolerates a sharing reader of the installed executable'
    } finally { foreach ($reader in $readers) { $reader.Dispose() } }
    # Emulate interruption after the swap and receipt write, before commit. Observe
    # recovery itself: a later install of the same variant could conceal bad rollback.
    $receiptPath = Join-Path $layout.InstallDirectory 'install-receipt.json'
    $receiptBeforeRecovery = Get-TTHash $receiptPath
    $next = ($current | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
    $next.binary_sha256 = $previous.binary_sha256
    Write-TTJson $journalPath @{ previous = $current; next = $next; committed = $false; path_changed = $false; path_before = $null; path_after = $null }
    Copy-Item -LiteralPath $binary -Destination $stage
    Set-TTCreatedOwner $stage
    [TelltaleLifecycle.Native]::ReplaceExecutable($stage, $installed, $backup)
    Write-TTJson $receiptPath $next
    Assert-True ((Get-TTHash $installed) -ceq $next.binary_sha256 -and (Get-TTHash $backup) -ceq $current.binary_sha256 -and $next.binary_sha256 -cne $current.binary_sha256 -and (Get-TTHash $receiptPath) -cne $receiptBeforeRecovery) 'interrupted transaction has distinct next executable and receipt, plus the previous backup'
    $readers = @()
    try {
        $readers += [IO.File]::Open($installed, 'Open', 'Read', 'ReadWrite, Delete')
        $readers += [IO.File]::Open($backup, 'Open', 'Read', 'ReadWrite, Delete')
        $mutex = Open-TTLifecycleMutex
        $lock = $null
        try {
            $lock = Open-TTLock $layout.InstallDirectory
            Restore-TTTransaction $layout.InstallDirectory $layout.DataDirectory | Out-Null
            $recovered = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
            Assert-True ((Get-TTHash $installed) -ceq $current.binary_sha256) 'recovery alone restores the exact previous executable under sharing readers'
            Assert-True ($recovered.id -ceq $current.id -and $recovered.binary_sha256 -ceq $current.binary_sha256 -and (Get-TTHash $receiptPath) -ceq $receiptBeforeRecovery) 'recovery alone restores the exact previous receipt and installation identity'
            Assert-True (-not (Test-Path -LiteralPath $journalPath) -and -not (Test-Path -LiteralPath $stage) -and -not (Test-Path -LiteralPath $backup)) 'recovery alone clears the transaction under sharing readers'
            Assert-True (@($readers | Where-Object { -not $_.CanRead }).Count -eq 0) 'recovery alone leaves outside readers open'
        } finally {
            if ($null -ne $lock) { $lock.Dispose() }
            Close-TTLifecycleMutex $mutex
        }
        & $installer @layout -DevelopmentBinary $binary
        $reinstalled = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
        Assert-True ($reinstalled.id -ceq $current.id -and $reinstalled.binary_sha256 -ceq $next.binary_sha256 -and (Get-TTHash $installed) -ceq $next.binary_sha256) 'separate reinstall succeeds after the recovery assertions'
    } finally { foreach ($reader in $readers) { $reader.Dispose() } }
    $reader = [IO.File]::Open($installed, 'Open', 'Read', 'ReadWrite')
    try {
        $beforeBlocked = Get-TreeDigest $layout.InstallDirectory
        Assert-Fails { & $uninstaller @layout -Confirm:$false } 'reader that forbids deletion still blocks uninstall'
        Assert-True ((Get-TreeDigest $layout.InstallDirectory) -ceq $beforeBlocked) 'blocked uninstall preserves executable and receipt'
    } finally { $reader.Dispose() }
    $reader = [IO.File]::Open($installed, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        & $uninstaller @layout -Confirm:$false
        Assert-True (-not (Test-Path -LiteralPath $installed) -and -not (Test-Path -LiteralPath $layout.InstallDirectory) -and $reader.CanRead) 'uninstall removes the executable and owned root despite a sharing reader'
    } finally { $reader.Dispose() }

    $layout = New-TestLayout 'partial-rollback'
    Invoke-TestDiagnosticInstall $layout $binary
    $installed = Join-Path $layout.InstallDirectory 'telltale.exe'
    $beforeHash = Get-TTHash $installed
    $metadata = Join-Path $layout.InstallDirectory 'install-receipt.json'
    $stream = [IO.File]::Open($metadata, 'Open', 'Read', 'Read')
    try {
        Assert-Fails { & $installer @layout -DevelopmentBinary $variant } 'metadata failure reports failed install and rollback'
        Assert-Fails { & $uninstaller @layout -Confirm:$false } 'pending recovery blocks cleanup'
    } finally { $stream.Dispose() }
    Assert-True ((Get-TTHash $installed) -ceq $beforeHash) 'previous binary restored despite blocked metadata rollback'
    Invoke-TestDiagnosticInstall $layout $binary
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
    $script:testScenario = 'synthetic-configuration-roots'
    $script:testLayout = $null
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
    # CI once refused an Open of this freshly installed executable here; the
    # uninstaller's string rethrow discarded which operation and HRESULT.
    $uninstallErrors = @()
    try { & $uninstaller @layout -Confirm:$false -ErrorVariable uninstallErrors }
    catch {
        $failure = $_
        Write-TestFailure $failure (Get-TestSharingError $uninstallErrors)
        throw
    }
    Assert-True (-not (Test-Path -LiteralPath $layout.InstallDirectory)) 'recovered fresh installation removes owned empty root'

    # The swap is two renames. Interruption between them, or a failed undo of the
    # first, leaves the backup present and the installed executable absent.
    $layout = New-TestLayout 'swap-interruption'
    & $installer @layout -DevelopmentBinary $binary
    $installed = Join-Path $layout.InstallDirectory 'telltale.exe'
    $stage = Join-Path $layout.InstallDirectory 'staged.exe'
    $backup = Join-Path $layout.InstallDirectory 'previous.exe'
    $journalPath = Join-Path $layout.InstallDirectory 'transaction.json'
    $receiptPath = Join-Path $layout.InstallDirectory 'install-receipt.json'
    $previous = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
    $next = ($previous | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
    $next.binary_sha256 = Get-TTHash $variant
    Write-TTJson $journalPath @{ previous = $previous; next = $next; committed = $false; path_changed = $false; path_before = $null; path_after = $null }
    Copy-Item -LiteralPath $variant -Destination $stage
    Set-TTCreatedOwner $stage
    [IO.File]::Move($installed, $backup)
    $beforeRecovery = Get-TreeDigest $layout.InstallDirectory
    Assert-Fails { & $uninstaller @layout -Confirm:$false } 'interrupted swap blocks cleanup'
    Assert-True ((Get-TreeDigest $layout.InstallDirectory) -ceq $beforeRecovery -and -not (Test-Path -LiteralPath $installed) -and (Get-TTHash $backup) -ceq $previous.binary_sha256) 'blocked cleanup preserves backup, stage, receipt and journal'
    & $installer @layout -DevelopmentBinary $binary
    $recovered = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
    Assert-True ($recovered.id -ceq $previous.id -and $recovered.binary_sha256 -ceq $previous.binary_sha256 -and (Get-TTHash $installed) -ceq $previous.binary_sha256) 'interrupted swap recovers the previous executable and identity'
    Assert-True (-not (Test-Path -LiteralPath $journalPath) -and -not (Test-Path -LiteralPath $stage) -and -not (Test-Path -LiteralPath $backup)) 'interrupted swap recovery clears the transaction'
    & $uninstaller @layout -Confirm:$false

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
        if ($replace) { [TelltaleLifecycle.Native]::ReplaceExecutable($stage, (Join-Path $layout.InstallDirectory 'telltale.exe'), (Join-Path $layout.InstallDirectory 'previous.exe')) }
        if (-not $replace) { Invoke-TestDiagnosticInstall $layout $binary }
        else { & $installer @layout -DevelopmentBinary $binary }
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
        if ($freshActivation) {
            $uninstallErrors = @()
            try { & $uninstaller @layout -Confirm:$false -ErrorVariable uninstallErrors }
            catch {
                $failure = $_
                $originalError = Get-TestSharingError $uninstallErrors
                Write-TestFailure $failure $originalError
                throw
            }
        } else { & $uninstaller @layout -Confirm:$false }
    }
    $layout = New-TestLayout 'rollback-registration-interruption'
    & $installer @layout -DevelopmentBinary $binary -WithScheduledTask
    $previous = Get-TTReceipt $layout.InstallDirectory $layout.DataDirectory
    $next = ($previous | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
    $disabledXml = Get-TTTaskEnabledXml $previous.task_xml $false
    [TelltaleLifecycleTests.Folder]::Current = [TelltaleLifecycleTests.Task]::new($disabledXml)
    Write-TTJson (Join-Path $layout.InstallDirectory 'transaction.json') @{ previous = $previous; next = $next; previous_task_enabled = $true; task_transition_xml = $disabledXml; committed = $false; path_changed = $false; path_before = $null; path_after = $null }
    [TelltaleLifecycleTests.Folder]::FailRegistrationOnce = $true
    Assert-Fails { & $installer @layout -DevelopmentBinary $binary } 'interruption immediately before rollback task registration reported' -ExpectedExceptionType 'TelltaleLifecycleTests.InjectedRegistrationInterruption'
    Assert-True (-not [TelltaleLifecycleTests.Folder]::FailRegistrationOnce) 'registration interruption was consumed'
    & $installer @layout -DevelopmentBinary $binary
    Assert-True ((Get-TTTask).Enabled) 'original transition proof survives interrupted rollback registration'
    & $uninstaller @layout -Confirm:$false
    Write-Output "Windows lifecycle regression matrix passed: $script:assertions assertions. Synthetic root: $temp"
} catch {
    Write-TestFailure $_
    throw
} finally {
    Stop-TestPreRollbackCapture
    [TelltaleLifecycleTests.Folder]::Current = $null
    [TelltaleLifecycleTests.Folder]::FailRegistrationOnce = $false
    Remove-Item Function:New-Object
    $script:testScheduler = 'not inspected'
    # A fresh GUID root, checked again after junction tests; never delete canonical directories.
    try {
        $checkedTemp = Get-TTPath $temp
        if (-not $checkedTemp.StartsWith($testParent + '\telltale-lifecycle-tests-', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected test cleanup root.' }
        Remove-Item -LiteralPath $checkedTemp -Recurse -Force
    } catch {
        if (-not $script:firstFailureReported) { Write-TestFailure $_; throw }
        try { Write-Host 'Windows lifecycle synthetic-root cleanup: unknown; original failure retained.' } catch { }
    }
}
if ($TestScheduledTask) {
    if ($env:GITHUB_ACTIONS -cne 'true') { throw 'Live Task Scheduler testing is restricted to the disposable CI runner.' }
    $script:testScheduler = 'native-disposable-runner'
    function Set-SyntheticRuntimeOwner($Layout) {
        # Only fresh outputs of this runner's synthetic scan may be normalized.
        # First prove that group ownership still blocks purge without mutation.
        $files = @()
        $groupOwned = $false
        foreach ($name in @('Logs/telltale-events.jsonl', 'Logs/telltale-events.jsonl.lock',
                'State/telltale-state.json', 'State/telltale-state.json.lock',
                'State/telltale-state.json.baseline.json', 'State/telltale-state.json.baseline.json.lock')) {
            $file = Join-Path $Layout.DataDirectory $name
            if (-not (Test-Path -LiteralPath $file)) { continue }
            Assert-TTFile $file
            $owner = (Get-Acl -LiteralPath $file).GetOwner([Security.Principal.SecurityIdentifier]).Value
            if ($owner -ne $script:TTSid -and $owner -ne 'S-1-5-32-544') { throw 'Unexpected synthetic runtime file owner.' }
            $groupOwned = $groupOwned -or $owner -eq 'S-1-5-32-544'
            $files += $file
        }
        if ($groupOwned) {
            $before = (Get-TreeDigest $Layout.InstallDirectory) + (Get-TreeDigest $Layout.DataDirectory)
            $beforePath = Get-TTUserPath
            $task = Get-TTTask
            $beforeTask = if ($task) { '{0}:{1}' -f (Get-TTTextHash $task.Xml), $task.Enabled } else { '' }
            Assert-Fails { & $uninstaller @Layout -PurgeData -Confirm:$false } 'group-owned synthetic output blocks purge'
            $task = Get-TTTask
            $afterTask = if ($task) { '{0}:{1}' -f (Get-TTTextHash $task.Xml), $task.Enabled } else { '' }
            Assert-True (($before -ceq ((Get-TreeDigest $Layout.InstallDirectory) + (Get-TreeDigest $Layout.DataDirectory))) -and
                $beforePath -ceq (Get-TTUserPath) -and $beforeTask -ceq $afterTask) 'refused group-owned purge leaves files, task and PATH unchanged'
        }
        foreach ($file in $files) { Set-TTCreatedOwner $file }
    }
    # The disposable CI account has no personal agent stores. Never run the
    # production home-root action: replace it temporarily with explicit synthetic paths.
    if ($null -ne (Get-TTTask)) { throw 'CI task collision; refusing to change an existing task.' }
    $liveTemp = Get-TTPath (Join-Path $testParent ("telltale-lifecycle-live-{0}" -f [guid]::NewGuid()))
    $layout = @{ InstallDirectory = (Join-Path $liveTemp 'Application With Spaces'); DataDirectory = (Join-Path $liveTemp 'Runtime Data') }
    $script:testScenario = 'live-scheduler-and-path'
    $script:testLayout = $layout
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
        Assert-TTFile $state
        Set-SyntheticRuntimeOwner $layout
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
        $script:testScenario = 'canonical-disposable-runner-lifecycle'
        $script:testLayout = $null # Failure probes are confined to GUID synthetic roots, never canonical paths.
        try {
            & $installer -DevelopmentBinary $binary
            Assert-True ($null -eq (Get-TTTask)) 'canonical default install leaves real task absent'
            $canonicalBinary = Join-Path $canonical.InstallDirectory 'telltale.exe'
            Invoke-TTNative $canonicalBinary @('scan', '--once', '--allow-fixtures', '--install-inventory-disabled', '--no-local-config', '--root', $fixtureRoot) | Out-Null
            $canonicalLog = Join-Path $canonical.DataDirectory 'Logs\telltale-events.jsonl'
            $canonicalState = Join-Path $canonical.DataDirectory 'State\telltale-state.json'
            Assert-True ((Test-Path -LiteralPath $canonicalLog) -and (Test-Path -LiteralPath $canonicalState)) 'canonical runtime defaults stay separate from executable'
            Invoke-TTNative $Python @((Join-Path $root 'scripts/validate-event-jsonl'), '--schema', (Join-Path $root 'schemas/event.schema.json'), '--events', $canonicalLog) | Out-Null
            Set-SyntheticRuntimeOwner $canonical
            & $uninstaller -Confirm:$false
            Assert-True ((Test-Path -LiteralPath $canonicalLog) -and (Test-Path -LiteralPath $canonicalState)) 'canonical default uninstall retains data'
            & $uninstaller -PurgeData -Confirm:$false
            Assert-True (-not (Test-Path -LiteralPath $canonical.InstallDirectory) -and -not (Test-Path -LiteralPath $canonical.DataDirectory)) 'canonical owned installation fully purged'
        } catch {
            Write-TestFailure $_
            throw
        } finally {
            try {
                if (Test-Path -LiteralPath (Join-Path $canonical.InstallDirectory 'install-receipt.json')) { & $uninstaller -Confirm:$false }
            } catch {
                if (-not $script:firstFailureReported) { Write-TestFailure $_; throw }
                try { Write-Host 'Windows lifecycle canonical cleanup: unknown; original failure retained.' } catch { }
            }
        }
        Write-Output 'Disposable-runner live Scheduled Task and PATH lifecycle passed.'
    } catch {
        Write-TestFailure $_
        throw
    } finally {
        $env:XDG_CONFIG_HOME = $savedXdg
        $script:testScenario = 'live-cleanup'
        $script:testLayout = $layout
        $cleanupFailure = $null
        $liveTaskCleanupFailed = $false
        try {
            if ($savedXml -and $null -ne (Get-TTTask)) {
                # Only this test owns the exact saved receipt and its synthetic variant.
                Set-TTTask $savedXml | Out-Null
                & $uninstaller @layout -Confirm:$false
            }
        } catch {
            $liveTaskCleanupFailed = $true
            if (-not $script:firstFailureReported) { $cleanupFailure = $_; Write-TestFailure $_ }
            else { try { Write-Host 'Windows lifecycle live task cleanup: unknown; original failure retained.' } catch { } }
        }
        try {
            if ($liveTaskCleanupFailed) {
                try { Write-Host 'Windows lifecycle live synthetic root retained: task cleanup failed; recovery evidence preserved.' } catch { }
            } else {
                $checkedLive = Get-TTPath $liveTemp
                if (-not $checkedLive.StartsWith($testParent + '\telltale-lifecycle-live-', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected live test cleanup root.' }
                if (Test-Path -LiteralPath $checkedLive) { Remove-Item -LiteralPath $checkedLive -Recurse -Force }
            }
        } catch {
            if (-not $script:firstFailureReported) { $cleanupFailure = $_; Write-TestFailure $_ }
            else { try { Write-Host 'Windows lifecycle live synthetic-root cleanup: unknown; original failure retained.' } catch { } }
        }
        if ($null -ne $cleanupFailure) { throw $cleanupFailure }
    }
}
