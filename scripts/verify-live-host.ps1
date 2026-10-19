[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BinaryPath,
    [Parameter(Mandatory = $true)][string]$Root,
    [ValidateSet('codex', 'claude', 'opencode', 'copilot', 'openclaw', 'qwen')]
    [string[]]$Client = @('codex', 'claude', 'opencode', 'copilot'),
    [ValidateRange(1, 25)][int]$MaxSources = 5,
    [ValidateRange(1, 3600)][int]$TimeoutSeconds = 600,
    [ValidateSet('codex', 'claude', 'opencode', 'copilot', 'openclaw', 'qwen')]
    [string[]]$RequiredClient = @(),
    [string]$ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-TTHostProperty($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-TTHostCount($Object, [string]$Name) {
    $value = Get-TTHostProperty $Object $Name
    if ($null -eq $value -or $value -is [bool] -or
        $value -is [string] -or $value -lt 0 -or
        [decimal]$value -ne [decimal]::Truncate([decimal]$value)) {
        throw 'invalid_summary'
    }
    return [decimal]$value
}

function Get-TTHostClassification($Summary, [int]$ExitCode, [bool]$Required, [bool]$RuntimeOutputs, [bool]$TimedOut = $false) {
    $codes = New-Object 'System.Collections.Generic.List[string]'
    $counts = [ordered]@{}
    $quarantineReasons = [ordered]@{}
    $coverage = $null
    try {
        if ($TimedOut) { $codes.Add('scanner_timeout') }
        if ($ExitCode -ne 0) { $codes.Add('scanner_exit') }
        if ($RuntimeOutputs) { $codes.Add('dry_run_wrote_outputs') }
        $discovery = Get-TTHostProperty $Summary 'source_discovery'
        $processing = Get-TTHostProperty $Summary 'source_processing'
        if ((Get-TTHostProperty $discovery 'checked_status') -ne 'succeeded' -or
            (Get-TTHostProperty $discovery 'best_effort_fallback_used') -ne $false -or
            $null -ne (Get-TTHostProperty $discovery 'first_error_category')) {
            $codes.Add('discovery_failed')
        }
        foreach ($name in @('selected_source_count', 'parse_success_source_count', 'parse_error_source_count',
                'accounting_complete_source_count', 'accounting_partial_source_count',
                'quarantined_unit_count', 'parsed_record_count')) {
            $counts[$name] = Get-TTHostCount $processing $name
        }
        $coverage = Get-TTHostProperty $processing 'selected_source_coverage'
        if ($coverage -notin @('no_sources', 'complete', 'partial')) { $coverage = $null; throw 'invalid_summary' }
        if ($counts.parse_error_source_count -gt 0) { $codes.Add('source_parse_failed') }
        if ($counts.parse_success_source_count + $counts.parse_error_source_count -ne $counts.selected_source_count -or
            $counts.accounting_complete_source_count + $counts.accounting_partial_source_count -ne $counts.parse_success_source_count) {
            throw 'invalid_summary'
        }
        $kinds = Get-TTHostProperty $processing 'record_kind_counts'
        $semanticCount = [decimal]0
        $kindTotal = [decimal]0
        foreach ($name in @('user_message', 'assistant_message', 'tool_call', 'tool_result', 'session_meta', 'other')) {
            $count = Get-TTHostCount $kinds $name
            $counts[$name + '_count'] = $count
            $kindTotal += $count
            if ($name -notin @('session_meta', 'other')) { $semanticCount += $count }
        }
        # The scanner counts every parsed record under exactly one kind.
        if ($kindTotal -ne $counts.parsed_record_count) { throw 'invalid_summary' }
        $flow = Get-TTHostProperty $Summary 'detection_flow'
        $counts['emitted_detection_count'] = Get-TTHostCount $flow 'emitted_detection_count'
        # Only aggregate closed scanner codes. Never retain native/session IDs,
        # coordinates, raw failure messages or arbitrary producer strings.
        $knownReasons = @('unknown_discriminator', 'unsupported_completed_item', 'unknown_content_block',
            'unbounded_value', 'invalid_native_contribution', 'unsupported_record', 'unsupported_content')
        foreach ($unit in @(Get-TTHostProperty $processing 'quarantined_units')) {
            $code = Get-TTHostProperty $unit 'code'
            if ($code -in $knownReasons) {
                if (-not $quarantineReasons.Contains($code)) { $quarantineReasons[$code] = 0 }
                $quarantineReasons[$code]++
            }
        }
        if ($counts.selected_source_count -eq 0) {
            if ($Required) { $codes.Add('required_client_missing') }
            $classification = 'not_available'
        } elseif ($counts.accounting_partial_source_count -gt 0 -or
            $counts.quarantined_unit_count -gt 0 -or $coverage -ne 'complete' -or $semanticCount -eq 0) {
            $classification = 'passed_with_limits'
        } else {
            $classification = 'passed'
        }
    } catch {
        $codes.Add('invalid_summary')
        $classification = 'failed'
    }
    if ($codes.Count -gt 0) { $classification = 'failed' }
    return [pscustomobject][ordered]@{
        classification = $classification
        error_codes = @($codes | Select-Object -Unique)
        counters = [pscustomobject]$counts
        coverage = $coverage
        reported_quarantine_reason_counts = [pscustomobject]$quarantineReasons
        quarantine_reason_counts_complete = ($counts.Contains('quarantined_unit_count') -and
            $counts.quarantined_unit_count -eq [decimal](@($quarantineReasons.Values | Measure-Object -Sum)[0].Sum))
    }
}

function ConvertTo-TTHostArgument([string]$Value) {
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-TTHostProcess([string]$File, [string[]]$Arguments, [int]$TimeoutSeconds = 0) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $File
    $start.Arguments = (@($Arguments | ForEach-Object { ConvertTo-TTHostArgument $_ }) -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'scanner_start_failed' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = $false
        if ($TimeoutSeconds -gt 0 -and -not $process.WaitForExit($TimeoutSeconds * 1000)) {
            # A blocked scan must not hang the verifier; stop it and report.
            $timedOut = $true
            try { $process.Kill() } catch { }
        }
        # The parameterless wait also drains the redirected output streams.
        $process.WaitForExit()
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout.Result; Stderr = $stderr.Result; TimedOut = $timedOut }
    } finally { $process.Dispose() }
}

function Invoke-TTHostVerification {
    $binary = (Get-Item -LiteralPath $BinaryPath -ErrorAction Stop).FullName
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'BinaryPath must be a file.' }
    $scanRoot = (Get-Item -LiteralPath $Root -ErrorAction Stop).FullName
    if (-not (Test-Path -LiteralPath $scanRoot -PathType Container)) { throw 'Root must be a directory.' }
    $clients = @($Client + $RequiredClient | Select-Object -Unique)
    $versionResult = Invoke-TTHostProcess $binary @('--version') $TimeoutSeconds
    $version = $versionResult.Stdout.Trim()
    if ($versionResult.TimedOut -or $versionResult.ExitCode -ne 0 -or $version -cnotmatch '^telltale [0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)? \((?:[0-9a-f]{12}|unknown)\)$') {
        throw 'invalid_binary_version'
    }
    $started = [DateTime]::UtcNow.ToString('o')
    $checks = @()
    foreach ($selectedClient in $clients) {
        $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        $temp = Join-Path $tempRoot ('telltale-host-verification-' + [guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($temp) | Out-Null
        try {
            $arguments = @('scan', '--once', '--dry-run', '--no-local-config', '--emit-activity',
                '--root', $scanRoot, '--client', $selectedClient, '--max-sources', [string]$MaxSources,
                '--log-path', (Join-Path $temp 'events.jsonl'), '--state-path', (Join-Path $temp 'state.json'))
            $scan = Invoke-TTHostProcess $binary $arguments $TimeoutSeconds
            $summary = $null
            if (-not $scan.TimedOut) {
                try { $summary = $scan.Stdout | ConvertFrom-Json -ErrorAction Stop } catch { }
            }
            $outputs = @(Get-ChildItem -LiteralPath $temp -Force).Count -gt 0
            $check = Get-TTHostClassification $summary $scan.ExitCode ($selectedClient -in $RequiredClient) $outputs $scan.TimedOut
            $checks += [pscustomobject][ordered]@{
                client = $selectedClient
                classification = $check.classification
                error_codes = $check.error_codes
                counters = $check.counters
                coverage = $check.coverage
                reported_quarantine_reason_counts = $check.reported_quarantine_reason_counts
                quarantine_reason_counts_complete = $check.quarantine_reason_counts_complete
                checked_at_utc = [DateTime]::UtcNow.ToString('o')
            }
        } finally {
            # Delete only the exact, newly generated temporary directory.
            $resolved = [IO.Path]::GetFullPath($temp)
            if ([IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -ne $tempRoot.TrimEnd('\') -or
                [IO.Path]::GetFileName($resolved) -notmatch '^telltale-host-verification-[0-9a-f]{32}$') {
                throw 'Unexpected verifier temporary directory.'
            }
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    }
    $report = [pscustomobject][ordered]@{
        report_version = 1
        started_at_utc = $started
        completed_at_utc = [DateTime]::UtcNow.ToString('o')
        binary_version = $version
        binary_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        max_sources_per_client = $MaxSources
        timeout_seconds = $TimeoutSeconds
        checks = $checks
    }
    $json = $report | ConvertTo-Json -Depth 8
    if ($ReportPath) {
        $destination = [IO.Path]::GetFullPath($ReportPath)
        [IO.File]::WriteAllText($destination, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
    }
    Write-Output $json
    if (@($checks | Where-Object { $_.classification -eq 'failed' }).Count -gt 0) { return 1 }
    return 0
}

if ($MyInvocation.InvocationName -ne '.') {
    # Preserve a single JSON report on stdout; exit status remains independent.
    $result = @(Invoke-TTHostVerification)
    $result[0..($result.Count - 2)] | Write-Output
    exit [int]$result[-1]
}
