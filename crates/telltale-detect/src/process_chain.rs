//! Process-chain detection: observations in, `process_chain` events out.
//!
//! Telltale's other detection path scores a whole session against regex rules.
//! This path is per-observation: each parent/child process relationship is
//! evaluated on its own and produces its own event, so a timeline keeps the
//! individual steps of an intrusion rather than one aggregate verdict.
//!
//! Three things happen here that the rule crate deliberately does not do:
//!
//! 1. **Extraction.** Agent sessions do not ship process trees. What they ship
//!    is a shell tool call. [`observations_from_records`] recovers the chains a
//!    command line actually describes — `cmd /c whoami` is a real cmd→whoami
//!    relationship — and marks anything it had to infer.
//! 2. **Emission.** Every surviving detection becomes an event, including
//!    zero-score ones. A zero-score event has `risk_score: 0`,
//!    `severity: informational`, `informational: true`, and no risk
//!    contribution, so it adds nothing to entity risk while remaining fully
//!    available for hunting and correlation.
//! 3. **Correlation.** [`correlate_process_chain_events`] walks emitted events
//!    for ordered sequences within a time window and entity boundary, with
//!    per-rule throttling and a per-entity risk cap so informational noise
//!    cannot be summed indefinitely.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use time::{Duration, OffsetDateTime};

use telltale_rules::process_chain::{
    CompiledCorrelationRule, CompiledProcessChainRules, ProcessChainContext, ProcessChainDetection,
    ProcessObservation, ProcessRef, normalize_process_name,
};
use telltale_schema::event::{
    Event, Evidence, ProcessChainEventInput, ProcessContext, evidence_hash, parse_event_timestamp,
    path_hash, process_chain_event, redact_sensitive_text,
};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::scoring::{RiskAccountingError, RiskContribution, RiskContributionType};
use telltale_schema::source::Source;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessChainConfig {
    /// Environment-specific false-positive controls.
    pub context: ProcessChainContext,
    /// Repeats of the same rule for the same entity inside this window are
    /// collapsed into the first event, which records `repeat_count`.
    pub suppression_window: Duration,
    /// Maximum correlation events emitted per rule per entity per scan.
    pub max_correlations_per_rule_entity: usize,
    /// Ceiling on total correlation risk attributed to one entity per scan.
    /// Correlations past the cap still emit, but as informational events.
    pub max_correlation_risk_per_entity: u64,
}

impl Default for ProcessChainConfig {
    fn default() -> Self {
        Self {
            context: ProcessChainContext::default(),
            suppression_window: Duration::hours(1),
            max_correlations_per_rule_entity: 1,
            max_correlation_risk_per_entity: 150,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Evaluates every process observation recoverable from a session's records and
/// returns the resulting `process_chain` events, followed by any correlation
/// events those detections satisfy.
pub fn detect_process_chains(
    source: &Source,
    rules: &CompiledProcessChainRules,
    records: &[NormalizedRecord],
    config: &ProcessChainConfig,
) -> Result<Vec<Event>, RiskAccountingError> {
    let observations = observations_from_records(records);
    let mut events = Vec::new();
    for (observation, record_index) in &observations {
        let record = records.get(*record_index);
        for detection in rules.evaluate_with_context(observation, &config.context) {
            events.push(process_chain_detection_event(
                source,
                record,
                records,
                observation,
                &detection,
            )?);
        }
    }

    let (mut events, _suppressed) = suppress_repeats(events, config.suppression_window);
    let correlations = correlate_process_chain_events(source, &events, rules, config)?;
    events.extend(correlations);
    Ok(events)
}

// ---------------------------------------------------------------------------
// Observation extraction
// ---------------------------------------------------------------------------

/// Interpreters whose command line embeds another command line, with the flags
/// that introduce the nested payload.
const NESTED_INTERPRETERS: &[(&str, &[&str])] = &[
    ("cmd", &["/c", "/k", "/r"]),
    (
        "powershell",
        &["-c", "-command", "-comman", "-comm", "-com"],
    ),
    ("pwsh", &["-c", "-command"]),
    ("bash", &["-c"]),
    ("sh", &["-c"]),
    ("zsh", &["-c"]),
    ("wsl", &["-e", "--exec", "--"]),
];

/// Wrappers that prefix a real command without being the meaningful parent.
const TRANSPARENT_WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "nohup", "time", "timeout", "start", "call", "exec", "nice", "stdbuf",
];

/// Binaries that only exist on Windows. Seeing one lets the extractor infer a
/// Windows shell as the parent when the source did not report a process tree.
const WINDOWS_ONLY_BINARIES: &[&str] = &[
    "arp",
    "atbroker",
    "bcdedit",
    "bitsadmin",
    "certutil",
    "cipher",
    "cmd",
    "cmstp",
    "copy",
    "cscript",
    "csc",
    "csvde",
    "diskshadow",
    "displayswitch",
    "dsget",
    "dsquery",
    "esentutl",
    "fltmc",
    "forfiles",
    "fsutil",
    "gpupdate",
    "hostname",
    "icacls",
    "installutil",
    "ipconfig",
    "klist",
    "ldifde",
    "magnify",
    "makecab",
    "mmc",
    "mpcmdrun",
    "msbuild",
    "msdt",
    "mshta",
    "msiexec",
    "narrator",
    "nbtstat",
    "net",
    "net1",
    "netsh",
    "netstat",
    "nltest",
    "ntdsutil",
    "osk",
    "pathping",
    "pcalua",
    "powershell",
    "procdump",
    "psexec",
    "qprocess",
    "reg",
    "regsvr32",
    "route",
    "rundll32",
    "sc",
    "schtasks",
    "sethc",
    "systeminfo",
    "tasklist",
    "taskkill",
    "tracert",
    "utilman",
    "vssadmin",
    "wbadmin",
    "wevtutil",
    "whoami",
    "wmic",
    "wscript",
    "xcopy",
    "xwizard",
];

/// Recovers process observations from a session's records.
///
/// The returned index points at the record each observation came from, so the
/// emitted event can carry that record's timestamp and tool name.
pub fn observations_from_records(records: &[NormalizedRecord]) -> Vec<(ProcessObservation, usize)> {
    let mut observations = Vec::new();
    for (index, record) in records.iter().enumerate() {
        if record.kind != RecordKind::ToolCall {
            continue;
        }
        let mut seen = BTreeSet::new();
        for text in [
            record.content.as_str(),
            record.arguments.as_deref().unwrap_or_default(),
        ] {
            if text.trim().is_empty() {
                continue;
            }
            for mut observation in observations_from_command_line(text) {
                let key = (
                    observation.parent.normalized_name(),
                    observation.child.normalized_name(),
                    observation.child.command_line_text().to_string(),
                );
                if !seen.insert(key) {
                    continue;
                }
                observation.timestamp = record.timestamp.clone();
                observations.push((observation, index));
            }
        }
    }
    observations
}

/// Recovers the parent/child relationships a single command line describes.
///
/// Explicit relationships (`cmd /c whoami`) are reported with
/// `parent_inferred: false`. A statement with no visible interpreter gets an
/// inferred Windows shell only when the invoked binary is Windows-only or the
/// statement is unambiguously Windows-shaped; otherwise the parent is left
/// empty and only standalone indicators can match.
pub fn observations_from_command_line(command_line: &str) -> Vec<ProcessObservation> {
    let mut observations = Vec::new();
    collect_observations(command_line, None, 0, &mut observations);
    observations
}

fn collect_observations(
    command_line: &str,
    explicit_parent: Option<&str>,
    depth: usize,
    out: &mut Vec<ProcessObservation>,
) {
    if depth > 3 {
        return;
    }
    for statement in split_statements(command_line) {
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        let tokens = tokenize(statement);
        let Some(binary_token) = first_meaningful_token(&tokens) else {
            continue;
        };
        let child = normalize_process_name(binary_token);
        if child.is_empty() {
            continue;
        }

        let (parent_name, inferred) = match explicit_parent {
            Some(parent) => (parent.to_string(), false),
            None => match infer_parent_shell(&child, statement) {
                Some(shell) => (shell.to_string(), true),
                None => (String::new(), true),
            },
        };

        let nested = nested_payload(&child, &tokens);

        // An interpreter that carries a payload is only a wrapper: the payload's
        // own statements describe the real children, and they repeat the same
        // text, so emitting the wrapper too would duplicate every command-line
        // indicator. An interpreter with no recoverable payload (an encoded
        // PowerShell command, for instance) still has to be reported.
        if nested.is_none() {
            out.push(ProcessObservation {
                parent: ProcessRef::named(parent_name),
                child: ProcessRef {
                    name: binary_token.to_string(),
                    path: binary_token
                        .contains(['\\', '/'])
                        .then(|| binary_token.to_string()),
                    pid: None,
                    command_line: Some(statement.to_string()),
                },
                parent_inferred: inferred,
                ..ProcessObservation::default()
            });
        }

        if let Some(nested) = nested {
            collect_observations(&nested, Some(&child), depth + 1, out);
        }
    }
}

fn first_meaningful_token(tokens: &[String]) -> Option<&str> {
    let mut index = 0;
    while index < tokens.len() {
        let candidate = tokens[index].as_str();
        // Skip `VAR=value` prefixes and transparent wrappers such as `sudo`.
        let normalized = normalize_process_name(candidate);
        if candidate.contains('=') && !candidate.contains(['\\', '/']) {
            index += 1;
            continue;
        }
        if TRANSPARENT_WRAPPERS.contains(&normalized.as_str()) {
            index += 1;
            continue;
        }
        // A leading `-flag` or a short `/c`-style switch is never the binary.
        if candidate.starts_with('-') || (candidate.starts_with('/') && candidate.len() <= 3) {
            index += 1;
            continue;
        }
        return Some(candidate);
    }
    None
}

fn nested_payload(binary: &str, tokens: &[String]) -> Option<String> {
    let flags = NESTED_INTERPRETERS
        .iter()
        .find(|(name, _)| *name == binary)
        .map(|(_, flags)| *flags)?;
    let position = tokens.iter().position(|token| {
        let lowered = token.to_ascii_lowercase();
        flags.contains(&lowered.as_str())
    })?;
    let payload = tokens
        .get(position + 1..)
        .map(|rest| rest.join(" "))
        .unwrap_or_default();
    (!payload.trim().is_empty()).then_some(payload)
}

fn infer_parent_shell(child: &str, statement: &str) -> Option<&'static str> {
    // A shell invoking itself is an artefact of inference, not an observation.
    if matches!(
        child,
        "cmd" | "powershell" | "pwsh" | "bash" | "sh" | "zsh" | "wsl"
    ) {
        return None;
    }
    if WINDOWS_ONLY_BINARIES.contains(&child) {
        return Some("cmd");
    }
    if statement_is_windows_shaped(statement) {
        return Some("cmd");
    }
    None
}

fn statement_is_windows_shaped(statement: &str) -> bool {
    let lowered = statement.to_ascii_lowercase();
    let has_env_var_reference = lowered.matches('%').count() >= 2 && !lowered.contains("http");
    lowered.contains(".exe") || lowered.contains(r":\") || has_env_var_reference
}

/// Splits a command line on statement and pipeline separators, ignoring
/// separators inside quotes.
fn split_statements(command_line: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = command_line.chars().peekable();

    while let Some(character) = chars.next() {
        match quote {
            Some(open) => {
                if character == open {
                    quote = None;
                } else {
                    current.push(character);
                    continue;
                }
                current.push(character);
            }
            None => match character {
                '"' | '\'' => {
                    quote = Some(character);
                    current.push(character);
                }
                '\n' | '\r' | ';' | '|' => {
                    // `&&`, `||`, and single `|` all end a statement.
                    if character == '|' && chars.peek() == Some(&'|') {
                        chars.next();
                    }
                    statements.push(std::mem::take(&mut current));
                }
                '&' => {
                    if chars.peek() == Some(&'&') {
                        chars.next();
                    }
                    statements.push(std::mem::take(&mut current));
                }
                _ => current.push(character),
            },
        }
    }
    statements.push(current);
    statements
        .into_iter()
        .filter(|statement| !statement.trim().is_empty())
        .collect()
}

/// Quote-aware whitespace tokenizer. Quotes are stripped from the token so that
/// `"C:\Program Files\7z.exe"` normalizes to `7z`.
fn tokenize(statement: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for character in statement.chars() {
        match quote {
            Some(open) if character == open => quote = None,
            Some(_) => current.push(character),
            None => match character {
                '"' | '\'' => quote = Some(character),
                character if character.is_whitespace() => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(character),
            },
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

// ---------------------------------------------------------------------------
// Event construction
// ---------------------------------------------------------------------------

fn process_chain_detection_event(
    source: &Source,
    record: Option<&NormalizedRecord>,
    records: &[NormalizedRecord],
    observation: &ProcessObservation,
    detection: &ProcessChainDetection,
) -> Result<Event, RiskAccountingError> {
    let mut risk_contributions = Vec::new();
    if detection.score > 0 {
        risk_contributions.push(RiskContribution::new(
            &detection.rule_id,
            RiskContributionType::DeterministicRule,
            detection.score,
            detection.detection_reason.clone(),
        )?);
    }

    let mut tags = vec!["process_chain".to_string(), detection.rule_category.clone()];
    if detection.informational {
        tags.push("informational".to_string());
    }
    if observation.parent_inferred {
        tags.push("inferred_parent".to_string());
    }
    if !detection.secondary_rule_ids.is_empty() {
        tags.push("deduplicated".to_string());
    }
    tags.sort();
    tags.dedup();

    let chain_text = format!(
        "{} -> {}",
        observation.parent.normalized_name(),
        observation.child.normalized_name()
    );
    let evidence = vec![Evidence {
        field: "process_chain".to_string(),
        redacted_value: redact_sensitive_text(&chain_text),
        hash: Some(evidence_hash(&chain_text)),
        rule_id: Some(detection.rule_id.clone()),
    }];

    let session_id = records
        .first()
        .map(|record| record.session_id.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let (entity_type, entity_value) = match detection.risk_entity_value.clone() {
        Some(value) => (detection.risk_entity_type.as_str(), Some(value)),
        None => ("session", Some(session_id.clone())),
    };

    let process = ProcessContext {
        host: observation.host.clone(),
        user: observation.user.clone(),
        source_process_name: observation.parent.normalized_name(),
        source_process_path: observation.parent.path.clone(),
        source_process_id: observation.parent.pid,
        source_process_command_line: observation.parent.command_line.clone(),
        target_process_name: observation.child.normalized_name(),
        target_process_path: observation.child.path.clone(),
        target_process_id: observation.child.pid,
        target_process_command_line: observation.child.command_line.clone(),
        parent_process_name: observation
            .grandparent
            .as_ref()
            .map(|process| process.normalized_name()),
        parent_process_path: observation
            .grandparent
            .as_ref()
            .and_then(|process| process.path.clone()),
        source_event_id: observation.source_event_id.clone(),
        source_process_inferred: observation.parent_inferred,
        rule_name: detection.rule_name.clone(),
        secondary_rule_ids: detection.secondary_rule_ids.clone(),
        investigation_fields: detection.investigation_fields.clone(),
        falsepositives: detection.falsepositives.clone(),
        dedup_key: detection.dedup_key.clone(),
        suppression_window_seconds: detection.suppression_window_seconds,
        rule_severity: detection.severity.clone(),
        risk_adjustment: detection.risk_adjustment.clone(),
    };

    process_chain_event(ProcessChainEventInput {
        client: source.client,
        agent: record
            .and_then(|record| record.agent.clone())
            .or_else(|| Some(source.client.as_str().to_string())),
        model: record.and_then(|record| record.model.clone()),
        provider: record.and_then(|record| record.provider.clone()),
        session_id,
        source_path_hash: path_hash(&source.path),
        tool_name: record.and_then(|record| record.tool_name.clone()),
        rule_ids: std::iter::once(detection.rule_id.clone())
            .chain(detection.secondary_rule_ids.iter().cloned())
            .collect(),
        categories: vec![detection.rule_category.clone()],
        detection_classes: vec![detection.detection_class.clone()],
        signal_types: vec![detection.signal_type.clone()],
        analytic_intents: vec![detection.analytic_intent.clone()],
        tags,
        evidence,
        risk_contributions,
        event_time: observation.timestamp.clone(),
        confidence: detection.confidence.clone(),
        detection_reason: detection.detection_reason.clone(),
        mitre_attack_techniques: detection.mitre_attack_techniques.clone(),
        // Agent transcripts rarely name an OS host or user. Rather than label a
        // session ID as a host, the entity type degrades to `session` when the
        // rule's preferred entity is unavailable.
        risk_entity_type: entity_type.to_string(),
        risk_entity_value: entity_value,
        process,
    })
}

// ---------------------------------------------------------------------------
// Duplicate suppression
// ---------------------------------------------------------------------------

/// Collapses repeats of the same rule against the same entity and process chain
/// inside the suppression window. The first event survives and records a
/// `repeat_count`; the rest are dropped and counted.
pub fn suppress_repeats(events: Vec<Event>, window: Duration) -> (Vec<Event>, usize) {
    let mut anchors: HashMap<String, (usize, OffsetDateTime, u64)> = HashMap::new();
    let mut kept: Vec<Option<Event>> = Vec::with_capacity(events.len());
    let mut suppressed = 0;

    for event in events {
        let Some(process) = event.process.as_ref() else {
            kept.push(Some(event));
            continue;
        };
        let key = format!(
            "{}|{}|{}",
            event.rule_ids.first().cloned().unwrap_or_default(),
            event.risk_entity_value.clone().unwrap_or_default(),
            process.dedup_key
        );
        let timestamp = parse_event_timestamp(&event.timestamp);
        match (anchors.get_mut(&key), timestamp) {
            (Some((index, anchor_time, count)), Some(timestamp))
                if timestamp - *anchor_time <= window =>
            {
                *count += 1;
                let repeats = *count;
                let index = *index;
                if let Some(Some(anchor)) = kept.get_mut(index) {
                    record_repeat_count(anchor, repeats);
                }
                suppressed += 1;
                kept.push(None);
            }
            _ => {
                if let Some(timestamp) = timestamp {
                    anchors.insert(key, (kept.len(), timestamp, 1));
                }
                kept.push(Some(event));
            }
        }
    }

    (kept.into_iter().flatten().collect(), suppressed)
}

fn record_repeat_count(event: &mut Event, repeats: u64) {
    let value = repeats.to_string();
    if let Some(existing) = event
        .evidence
        .iter_mut()
        .find(|evidence| evidence.field == "repeat_count")
    {
        existing.redacted_value = value;
        return;
    }
    event.evidence.push(Evidence {
        field: "repeat_count".to_string(),
        redacted_value: value,
        hash: None,
        rule_id: event.rule_ids.first().cloned(),
    });
}

// ---------------------------------------------------------------------------
// Correlation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CorrelationCandidate<'a> {
    event: &'a Event,
    timestamp: OffsetDateTime,
    category: String,
    rule_id: String,
    child: String,
}

/// Finds ordered sequences of process-chain detections and emits one event per
/// satisfied sequence.
///
/// Boundaries applied, in order: entity (never across hosts), time window,
/// per-rule/per-entity throttle, and a per-entity risk cap. Past the cap a
/// correlation still emits, but as an informational event, so evidence is never
/// lost to a budget.
pub fn correlate_process_chain_events(
    source: &Source,
    events: &[Event],
    rules: &CompiledProcessChainRules,
    config: &ProcessChainConfig,
) -> Result<Vec<Event>, RiskAccountingError> {
    let mut by_entity: BTreeMap<String, Vec<CorrelationCandidate<'_>>> = BTreeMap::new();
    for event in events {
        if event.event_type != "process_chain" {
            continue;
        }
        let Some(process) = event.process.as_ref() else {
            continue;
        };
        let Some(timestamp) = parse_event_timestamp(&event.timestamp) else {
            continue;
        };
        let entity = event
            .risk_entity_value
            .clone()
            .unwrap_or_else(|| event.session_id.clone());
        by_entity
            .entry(entity)
            .or_default()
            .push(CorrelationCandidate {
                event,
                timestamp,
                category: event.categories.first().cloned().unwrap_or_default(),
                rule_id: event.rule_ids.first().cloned().unwrap_or_default(),
                child: process.target_process_name.clone(),
            });
    }

    let mut correlation_events = Vec::new();
    for (entity, mut candidates) in by_entity {
        candidates.sort_by_key(|candidate| candidate.timestamp);
        let mut entity_risk = 0_u64;
        for rule in rules.correlations() {
            let matches =
                find_sequences(rule, &candidates, config.max_correlations_per_rule_entity);
            for matched in matches {
                let over_cap =
                    entity_risk.saturating_add(rule.score) > config.max_correlation_risk_per_entity;
                let score = if over_cap { 0 } else { rule.score };
                entity_risk = entity_risk.saturating_add(score);
                correlation_events.push(correlation_event(
                    source, &entity, rule, &matched, score, over_cap,
                )?);
            }
        }
    }

    Ok(correlation_events)
}

fn find_sequences<'a>(
    rule: &CompiledCorrelationRule,
    candidates: &[CorrelationCandidate<'a>],
    limit: usize,
) -> Vec<Vec<&'a Event>> {
    let mut sequences = Vec::new();
    let window = Duration::seconds(rule.window_seconds as i64);

    for start in 0..candidates.len() {
        if sequences.len() >= limit {
            break;
        }
        let mut step = 0;
        let mut matched: Vec<&Event> = Vec::new();
        let anchor = candidates[start].timestamp;
        for candidate in &candidates[start..] {
            if candidate.timestamp - anchor > window {
                break;
            }
            let Some(current) = rule.steps.get(step) else {
                break;
            };
            if current.matches(&candidate.category, &candidate.rule_id, &candidate.child) {
                matched.push(candidate.event);
                step += 1;
                if step == rule.steps.len() {
                    break;
                }
            }
        }
        if step == rule.steps.len() {
            sequences.push(matched);
        }
    }

    sequences
}

fn correlation_event(
    source: &Source,
    entity: &str,
    rule: &CompiledCorrelationRule,
    matched: &[&Event],
    score: u64,
    over_cap: bool,
) -> Result<Event, RiskAccountingError> {
    let anchor = matched.first().copied();
    let last = matched.last().copied();

    let mut risk_contributions = Vec::new();
    if score > 0 {
        risk_contributions.push(RiskContribution::new(
            &rule.id,
            RiskContributionType::DeterministicRule,
            score,
            rule.reason.clone(),
        )?);
    }

    let supporting: Vec<String> = matched
        .iter()
        .filter_map(|event| event.rule_ids.first().cloned())
        .collect();
    let supporting_text = supporting.join(" -> ");
    let mut evidence = vec![Evidence {
        field: "correlation_sequence".to_string(),
        redacted_value: redact_sensitive_text(&supporting_text),
        hash: Some(evidence_hash(&supporting_text)),
        rule_id: Some(rule.id.clone()),
    }];
    let event_ids = matched
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>()
        .join(",");
    evidence.push(Evidence {
        field: "correlated_event_ids".to_string(),
        redacted_value: event_ids.clone(),
        hash: Some(evidence_hash(&event_ids)),
        rule_id: Some(rule.id.clone()),
    });

    let mut tags = vec![
        "process_chain".to_string(),
        "correlation".to_string(),
        rule.category.clone(),
    ];
    if over_cap {
        tags.push("risk_capped".to_string());
    }
    tags.sort();
    tags.dedup();

    let process = ProcessContext {
        host: anchor
            .and_then(|event| event.process.as_ref())
            .and_then(|process| process.host.clone()),
        user: anchor
            .and_then(|event| event.process.as_ref())
            .and_then(|process| process.user.clone()),
        source_process_name: anchor
            .and_then(|event| event.process.as_ref())
            .map(|process| process.source_process_name.clone())
            .unwrap_or_default(),
        source_process_path: None,
        source_process_id: None,
        source_process_command_line: None,
        target_process_name: last
            .and_then(|event| event.process.as_ref())
            .map(|process| process.target_process_name.clone())
            .unwrap_or_default(),
        target_process_path: None,
        target_process_id: None,
        target_process_command_line: None,
        parent_process_name: None,
        parent_process_path: None,
        source_event_id: None,
        source_process_inferred: false,
        rule_name: rule.title.clone(),
        secondary_rule_ids: supporting,
        investigation_fields: Vec::new(),
        falsepositives: rule.falsepositives.clone(),
        dedup_key: format!("correlation:{}:{entity}", rule.id),
        suppression_window_seconds: rule.window_seconds,
        rule_severity: rule.severity.clone(),
        risk_adjustment: over_cap.then(|| "per-entity correlation risk cap reached".to_string()),
    };

    process_chain_event(ProcessChainEventInput {
        client: source.client,
        agent: anchor.and_then(|event| event.agent.clone()),
        model: anchor.and_then(|event| event.model.clone()),
        provider: anchor.and_then(|event| event.provider.clone()),
        session_id: anchor
            .map(|event| event.session_id.clone())
            .unwrap_or_else(|| entity.to_string()),
        source_path_hash: path_hash(&source.path),
        tool_name: None,
        rule_ids: vec![rule.id.clone()],
        categories: vec![rule.category.clone()],
        detection_classes: vec![rule.detection_class.clone()],
        signal_types: vec!["correlation".to_string()],
        analytic_intents: vec![rule.analytic_intent.clone()],
        tags,
        evidence,
        risk_contributions,
        event_time: last.and_then(|event| event.event_time.clone()),
        confidence: rule.confidence.clone(),
        detection_reason: rule.reason.clone(),
        mitre_attack_techniques: rule.mitre_attack_techniques.clone(),
        // Correlations inherit the entity type their evidence actually carried,
        // so a session-scoped sequence is never mislabelled as host-scoped.
        risk_entity_type: anchor
            .and_then(|event| event.risk_entity_type.clone())
            .unwrap_or_else(|| rule.entity.clone()),
        risk_entity_value: Some(entity.to_string()),
        process,
    })
}
