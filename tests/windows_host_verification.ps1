param([string]$BinaryPath)
$script:TestBinary = $BinaryPath
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
. (Join-Path $repo 'scripts\verify-live-host.ps1') -BinaryPath 'unused' -Root $repo

function Assert-TTHost([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function New-TTSummary {
    return [pscustomobject]@{
        source_discovery = [pscustomobject]@{ checked_status = 'succeeded'; best_effort_fallback_used = $false; first_error_category = $null }
        source_processing = [pscustomobject]@{
            selected_source_count = 1; parse_success_source_count = 1; parse_error_source_count = 0
            accounting_complete_source_count = 1; accounting_partial_source_count = 0
            quarantined_unit_count = 0; parsed_record_count = 2; selected_source_coverage = 'complete'
            record_kind_counts = [pscustomobject]@{ user_message = 1; assistant_message = 0; tool_call = 0; tool_result = 0; session_meta = 1; other = 0 }
            quarantined_units = @()
        }
        detection_flow = [pscustomobject]@{ emitted_detection_count = 0 }
        session_id = 'SENTINEL-PRIVATE-SESSION'
        log_path = 'SENTINEL-PRIVATE-PATH'
    }
}
$summary = New-TTSummary
Assert-TTHost ((Get-TTHostClassification $summary 0 $true $false).classification -eq 'passed') 'Complete supported activity must pass even with zero detections.'
$summary.source_processing.parse_success_source_count = 0
$summary.source_processing.parse_error_source_count = 1
$summary.source_processing.accounting_complete_source_count = 0
Assert-TTHost ((Get-TTHostClassification $summary 0 $true $false).classification -eq 'failed') 'Exit-zero complete parse loss must fail.'
$summary = New-TTSummary
$summary.source_processing.accounting_complete_source_count = 0
$summary.source_processing.accounting_partial_source_count = 1
$summary.source_processing.selected_source_coverage = 'partial'
Assert-TTHost ((Get-TTHostClassification $summary 0 $false $false).classification -eq 'passed_with_limits') 'Suffix/OpenCode partial coverage must keep its limit.'
$summary = New-TTSummary
$summary.source_processing.record_kind_counts.user_message = 0
$summary.source_processing.record_kind_counts.session_meta = 2
Assert-TTHost ((Get-TTHostClassification $summary 0 $false $false).classification -eq 'passed_with_limits') 'Metadata-only accounting does not prove semantic activity.'
$summary = New-TTSummary
$summary.source_processing.quarantined_unit_count = 1
$summary.source_processing.quarantined_units = @([pscustomobject]@{code = 'unsupported_completed_item'; native_id = 'SENTINEL-PRIVATE-NATIVE'; session_id = 'SENTINEL-PRIVATE-SESSION'})
$check = Get-TTHostClassification $summary 0 $false $false
Assert-TTHost ($check.classification -eq 'passed_with_limits') 'Quarantine must remain visible.'
Assert-TTHost (($check | ConvertTo-Json -Depth 8) -notmatch 'SENTINEL-PRIVATE') 'Summary must discard private fields.'
$summary.source_processing.selected_source_coverage = 'SENTINEL-PRIVATE-COVERAGE'
$check = Get-TTHostClassification $summary 0 $false $false
Assert-TTHost ($check.classification -eq 'failed' -and ($check | ConvertTo-Json -Depth 8) -notmatch 'SENTINEL-PRIVATE') 'Invalid summary must fail without copying strings.'
$summary = New-TTSummary
$summary.source_discovery.best_effort_fallback_used = $true
Assert-TTHost ((Get-TTHostClassification $summary 0 $false $false).classification -eq 'failed') 'Discovery fallback must fail.'
Assert-TTHost ((Get-TTHostClassification (New-TTSummary) 1 $false $false).classification -eq 'failed') 'Nonzero scanner exit must fail.'
Assert-TTHost ((Get-TTHostClassification (New-TTSummary) 0 $false $true).classification -eq 'failed') 'Unexpected dry-run output must fail.'
Assert-TTHost ((Get-TTHostClassification $null 0 $false $false).classification -eq 'failed') 'Invalid JSON must fail.'
$summary = New-TTSummary
$summary.source_processing.record_kind_counts.other = 1
Assert-TTHost ((Get-TTHostClassification $summary 0 $false $false).classification -eq 'failed') 'Record kinds that disagree with parsed_record_count must fail.'
$summary = New-TTSummary
$summary.source_processing.record_kind_counts.session_meta = 0
Assert-TTHost ((Get-TTHostClassification $summary 0 $false $false).classification -eq 'failed') 'Uncounted parsed records must fail.'
$check = Get-TTHostClassification (New-TTSummary) 0 $false $false $true
Assert-TTHost ($check.classification -eq 'failed' -and $check.error_codes -contains 'scanner_timeout') 'A timed-out scan must fail.'
$shell = (Get-Process -Id $PID).Path
$clock = [Diagnostics.Stopwatch]::StartNew()
$blocked = Invoke-TTHostProcess $shell @('-NoProfile', '-Command', 'Start-Sleep -Seconds 60') 1
Assert-TTHost ($blocked.TimedOut -and $clock.Elapsed.TotalSeconds -lt 30) 'A blocked process must be stopped at the deadline.'
$finished = Invoke-TTHostProcess $shell @('-NoProfile', '-Command', 'exit 3') 60
Assert-TTHost (-not $finished.TimedOut -and $finished.ExitCode -eq 3) 'A process that exits in time keeps its exit code.'
$summary = New-TTSummary
$summary.source_processing.selected_source_count = 0
$summary.source_processing.parse_success_source_count = 0
$summary.source_processing.accounting_complete_source_count = 0
$summary.source_processing.selected_source_coverage = 'no_sources'
Assert-TTHost ((Get-TTHostClassification $summary 0 $false $false).classification -eq 'not_available') 'Missing optional client must remain unavailable.'
Assert-TTHost ((Get-TTHostClassification $summary 0 $true $false).classification -eq 'failed') 'Missing required client must fail.'

# Dot-sourcing supplies its own parameters, so retain the caller's binary separately.
if ($script:TestBinary) { $BinaryPath = $script:TestBinary }
if ($script:TestBinary) {
    $testRoot = Join-Path ([IO.Path]::GetTempPath()) ('telltale verifier tests ' + [guid]::NewGuid().ToString('N'))
    $store = Join-Path $testRoot 'codex\sessions'
    [IO.Directory]::CreateDirectory($store) | Out-Null
    $source = Join-Path $store 'synthetic.jsonl'
    $verifier = Join-Path $repo 'scripts\verify-live-host.ps1'
    $shell = (Get-Process -Id $PID).Path
    try {
        $meta = '{"type":"session_meta","payload":{"id":"SENTINEL-PRIVATE-SESSION"}}'
        $message = '{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"SENTINEL-PRIVATE-MESSAGE"}]}}'
        $encoding = New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($source, $meta + "`n" + $message + "`n", $encoding)
        $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $verifier,
            '-BinaryPath', $BinaryPath, '-Root', $testRoot, '-Client', 'codex')
        $run = Invoke-TTHostProcess $shell $arguments
        $report = $run.Stdout | ConvertFrom-Json
        Assert-TTHost ($run.ExitCode -eq 0 -and $report.checks[0].classification -eq 'passed') 'Real supported source must pass.'
        Assert-TTHost ($run.Stdout -notmatch 'SENTINEL-PRIVATE|synthetic.jsonl|codex\\sessions') 'Real report must omit paths and transcript content.'
        $expectedRevision = [regex]::Match($report.binary_version, '\(([0-9a-f]{12}|unknown)\)').Groups[1].Value
        $scan = Invoke-TTHostProcess $BinaryPath @('scan', '--once', '--dry-run', '--no-local-config', '--root', $testRoot, '--client', 'codex')
        $runtime = ($scan.Stdout | ConvertFrom-Json).runtime
        Assert-TTHost ($runtime.build_git_hash -eq $expectedRevision) 'Actual CLI version and runtime metadata must agree.'
        [IO.File]::WriteAllText($source, $meta + "`n", $encoding)
        $run = Invoke-TTHostProcess $shell $arguments
        Assert-TTHost ($run.ExitCode -eq 0 -and ($run.Stdout | ConvertFrom-Json).checks[0].classification -eq 'passed_with_limits') 'Real metadata-only source must keep its limit.'
        [IO.File]::WriteAllText($source, "{malformed`n", $encoding)
        $run = Invoke-TTHostProcess $shell $arguments
        Assert-TTHost ($run.ExitCode -eq 1 -and ($run.Stdout | ConvertFrom-Json).checks[0].classification -eq 'failed') 'Exit-zero scanner parse failures must make verifier fail.'
        Remove-Item -LiteralPath $source
        $run = Invoke-TTHostProcess $shell $arguments
        Assert-TTHost ($run.ExitCode -eq 0 -and ($run.Stdout | ConvertFrom-Json).checks[0].classification -eq 'not_available') 'Real absent optional client must be unavailable.'
        $run = Invoke-TTHostProcess $shell ($arguments + @('-RequiredClient', 'codex'))
        Assert-TTHost ($run.ExitCode -eq 1 -and ($run.Stdout | ConvertFrom-Json).checks[0].classification -eq 'failed') 'Real absent required client must fail.'
    } finally {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        if ([IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -ne [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') -or
            [IO.Path]::GetFileName($resolved) -notmatch '^telltale verifier tests [0-9a-f]{32}$') { throw 'Unexpected test temporary directory.' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
Write-Output 'Windows host verifier classification/privacy tests passed.'
