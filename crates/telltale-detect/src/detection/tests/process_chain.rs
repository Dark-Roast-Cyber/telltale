//! End-to-end coverage for the process-chain path: records in, events out.

use std::path::PathBuf;

use telltale_rules::process_chain::load_default_process_chain_rules;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::source::Source;

use crate::process_chain::{
    ProcessChainConfig, detect_process_chains, observations_from_command_line,
};

fn test_source() -> Source {
    Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: PathBuf::from("/fixtures/process-chain.jsonl"),
    }
}

fn tool_call(command: &str, timestamp: &str) -> NormalizedRecord {
    NormalizedRecord {
        session_id: "process-chain".to_string(),
        client: "codex".to_string(),
        agent: Some("codex".to_string()),
        model: Some("test-model".to_string()),
        provider: Some("test".to_string()),
        timestamp: Some(timestamp.to_string()),
        kind: RecordKind::ToolCall,
        tool_name: Some("shell".to_string()),
        arguments: None,
        content: command.to_string(),
    }
}

fn events_for(commands: &[(&str, &str)]) -> Vec<telltale_schema::event::Event> {
    let records = commands
        .iter()
        .map(|(command, timestamp)| tool_call(command, timestamp))
        .collect::<Vec<_>>();
    let rules = load_default_process_chain_rules().expect("pack compiles");
    detect_process_chains(
        &test_source(),
        &rules,
        &records,
        &ProcessChainConfig::default(),
    )
    .expect("risk accounting holds")
}

fn event_with_rule<'a>(
    events: &'a [telltale_schema::event::Event],
    rule_id: &str,
) -> Option<&'a telltale_schema::event::Event> {
    events
        .iter()
        .find(|event| event.rule_ids.first().is_some_and(|id| id == rule_id))
}

#[test]
fn zero_risk_chain_emits_an_informational_event_with_no_risk() {
    let events = events_for(&[("cmd.exe /c hostname", "2026-05-10T10:00:00Z")]);
    let event = event_with_rule(&events, "procchain.discovery.cmd_hostname")
        .expect("informational event emitted");

    assert_eq!(event.event_type, "process_chain");
    assert_eq!(event.risk_score, 0);
    assert_eq!(event.severity, "informational");
    assert_eq!(event.informational, Some(true));
    // A zero-risk event names its entity but contributes nothing to it. Agent
    // transcripts carry no OS host, so the entity degrades to the session.
    assert!(event.risk_contributions.is_empty());
    assert_eq!(event.risk_entity_type.as_deref(), Some("session"));
    assert_eq!(event.risk_entity_value.as_deref(), Some("process-chain"));
}

#[test]
fn low_risk_rule_emits_its_declared_low_score() {
    let events = events_for(&[("cmd.exe /c whoami", "2026-05-10T10:00:00Z")]);
    let event =
        event_with_rule(&events, "procchain.discovery.cmd_whoami").expect("low-risk event emitted");
    assert_eq!(event.risk_score, 20);
    assert_eq!(event.severity, "low");
    assert_eq!(event.informational, Some(false));
}

#[test]
fn office_to_powershell_scores_far_higher_than_shell_discovery() {
    let office = events_for(&[("winword.exe", "2026-05-10T10:00:00Z")]);
    // Word is not observable as a parent from a command line alone, so drive
    // this case through the rule layer with an explicit observation instead.
    assert!(office.iter().all(|event| event.risk_score < 60));

    let rules = load_default_process_chain_rules().expect("pack compiles");
    let observation = telltale_rules::process_chain::ProcessObservation {
        parent: telltale_rules::process_chain::ProcessRef::named("winword.exe"),
        child: telltale_rules::process_chain::ProcessRef::named("powershell.exe")
            .with_command_line("powershell -w hidden -nop"),
        host: Some("desk-1".to_string()),
        ..Default::default()
    };
    let office_score = rules
        .evaluate(&observation)
        .into_iter()
        .find(|detection| detection.rule_id == "procchain.execution.winword_powershell")
        .map(|detection| detection.score)
        .expect("office chain matched");

    let discovery = events_for(&[("cmd.exe /c whoami", "2026-05-10T10:00:00Z")]);
    let discovery_score = event_with_rule(&discovery, "procchain.discovery.cmd_whoami")
        .map(|event| event.risk_score)
        .expect("discovery matched");

    assert!(
        office_score >= discovery_score * 3,
        "office chain {office_score} should be at least 3x shell discovery {discovery_score}"
    );
}

#[test]
fn web_server_to_shell_is_critical() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let observation = telltale_rules::process_chain::ProcessObservation {
        parent: telltale_rules::process_chain::ProcessRef::named(
            r"C:\Windows\System32\inetsrv\w3wp.exe",
        ),
        child: telltale_rules::process_chain::ProcessRef::named("cmd.exe")
            .with_command_line("cmd /c whoami"),
        host: Some("web-1".to_string()),
        ..Default::default()
    };
    let detection = rules
        .evaluate(&observation)
        .into_iter()
        .find(|detection| detection.rule_id == "procchain.execution.w3wp_cmd")
        .expect("web shell chain matched");
    assert_eq!(detection.severity, "critical");
    assert!(detection.score >= 80);
}

#[test]
fn credential_dumping_scores_critical_end_to_end() {
    let events = events_for(&[(
        r"cmd.exe /c procdump.exe -ma lsass.exe C:\temp\out.dmp",
        "2026-05-10T10:00:00Z",
    )]);
    let event = event_with_rule(&events, "procchain.credaccess.credential_dump_command")
        .expect("credential dumping detected");
    assert!(event.risk_score >= 80);
    assert_eq!(event.severity, "high");
    assert!(
        event
            .mitre_attack_techniques
            .contains(&"T1003.001".to_string())
    );
}

#[test]
fn duplicate_interpretations_collapse_to_one_event_with_the_strongest_score() {
    let events = events_for(&[(
        "cmd.exe /c vssadmin delete shadows /all /quiet",
        "2026-05-10T10:00:00Z",
    )]);
    let chain_events = events
        .iter()
        .filter(|event| {
            event
                .process
                .as_ref()
                .is_some_and(|process| process.dedup_key == "chain:cmd>vssadmin")
        })
        .collect::<Vec<_>>();

    assert_eq!(chain_events.len(), 1, "one finding per chain");
    let event = chain_events[0];
    assert_eq!(
        event.rule_ids.first().map(String::as_str),
        Some("procchain.impact.vssadmin_shadow_delete")
    );
    assert!(event.risk_score >= 80);
}

#[test]
fn matching_is_case_insensitive_and_paths_are_normalized() {
    let events = events_for(&[(
        r#""C:\Windows\System32\CMD.EXE" /C "C:\Windows\System32\WHOAMI.EXE" /all"#,
        "2026-05-10T10:00:00Z",
    )]);
    let event = event_with_rule(&events, "procchain.discovery.cmd_whoami")
        .expect("normalized chain matched");
    let process = event.process.as_ref().expect("process context present");
    assert_eq!(process.source_process_name, "cmd");
    assert_eq!(process.target_process_name, "whoami");
    // The observed spelling is preserved alongside the normalized key.
    assert!(
        process
            .target_process_command_line
            .as_deref()
            .is_some_and(|command| command.contains("WHOAMI.EXE"))
    );
    assert!(!process.source_process_inferred);
}

#[test]
fn missing_optional_fields_do_not_prevent_matching() {
    // No path, no PID, no host, no user - only the two process names.
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let observation = telltale_rules::process_chain::ProcessObservation {
        parent: telltale_rules::process_chain::ProcessRef::named("mshta"),
        child: telltale_rules::process_chain::ProcessRef::named("powershell"),
        ..Default::default()
    };
    assert!(
        rules
            .evaluate(&observation)
            .iter()
            .any(|detection| detection.rule_id == "procchain.evasion.mshta_powershell")
    );
}

#[test]
fn informational_events_participate_in_a_correlated_detection() {
    let events = events_for(&[
        ("cmd.exe /c hostname", "2026-05-10T10:00:00Z"),
        ("cmd.exe /c ipconfig /all", "2026-05-10T10:01:00Z"),
        ("cmd.exe /c net user /domain", "2026-05-10T10:02:00Z"),
    ]);

    let correlation = event_with_rule(&events, "procchain.correlation.host_then_account_discovery")
        .expect("correlation emitted");
    assert_eq!(correlation.signal_types, vec!["correlation".to_string()]);
    assert_eq!(correlation.risk_score, 45);

    // The zero-risk hostname event still exists and still carries no risk.
    let informational = event_with_rule(&events, "procchain.discovery.cmd_hostname")
        .expect("informational event retained");
    assert_eq!(informational.risk_score, 0);
    assert!(
        correlation
            .evidence
            .iter()
            .any(|evidence| evidence.field == "correlated_event_ids")
    );
}

#[test]
fn correlation_respects_the_time_window() {
    let events = events_for(&[
        ("cmd.exe /c hostname", "2026-05-10T10:00:00Z"),
        // 30 minutes later, well outside the 900-second window.
        ("cmd.exe /c net user /domain", "2026-05-10T10:30:00Z"),
    ]);
    assert!(
        event_with_rule(&events, "procchain.correlation.host_then_account_discovery").is_none(),
        "sequence outside the window must not correlate"
    );
}

#[test]
fn repeated_identical_chains_are_suppressed_into_one_event() {
    let events = events_for(&[
        ("cmd.exe /c whoami", "2026-05-10T10:00:00Z"),
        ("cmd.exe /c whoami", "2026-05-10T10:01:00Z"),
        ("cmd.exe /c whoami", "2026-05-10T10:02:00Z"),
    ]);
    let whoami = events
        .iter()
        .filter(|event| {
            event
                .rule_ids
                .first()
                .is_some_and(|id| id == "procchain.discovery.cmd_whoami")
        })
        .collect::<Vec<_>>();
    assert_eq!(whoami.len(), 1, "repeats collapse into the first event");
    assert!(
        whoami[0]
            .evidence
            .iter()
            .any(|evidence| evidence.field == "repeat_count" && evidence.redacted_value == "3")
    );
}

#[test]
fn approved_admin_context_reduces_risk_without_deleting_the_event() {
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let mut config = ProcessChainConfig::default();
    config
        .context
        .approved_admin_users
        .insert("svc_deploy".to_string());

    let mut record = tool_call("cmd.exe /c whoami", "2026-05-10T10:00:00Z");
    record.session_id = "approved".to_string();

    // Feed the user through the observation layer directly; agent transcripts do
    // not carry an OS user, so this is the structured-telemetry path.
    let observation = telltale_rules::process_chain::ProcessObservation {
        parent: telltale_rules::process_chain::ProcessRef::named("cmd.exe"),
        child: telltale_rules::process_chain::ProcessRef::named("whoami.exe")
            .with_command_line("whoami"),
        user: Some("svc_deploy".to_string()),
        host: Some("build-1".to_string()),
        ..Default::default()
    };
    let detection = rules
        .evaluate_with_context(&observation, &config.context)
        .into_iter()
        .find(|detection| detection.rule_id == "procchain.discovery.cmd_whoami")
        .expect("detection retained");

    assert_eq!(detection.score, 0);
    assert!(detection.informational);
    assert!(detection.risk_adjustment.is_some());
}

#[test]
fn command_line_extraction_recovers_explicit_and_inferred_parents() {
    let observations = observations_from_command_line("cmd.exe /c \"whoami && hostname\"");
    let explicit = observations
        .iter()
        .filter(|observation| !observation.parent_inferred)
        .map(|observation| {
            (
                observation.parent.normalized_name(),
                observation.child.normalized_name(),
            )
        })
        .collect::<Vec<_>>();
    assert!(explicit.contains(&("cmd".to_string(), "whoami".to_string())));
    assert!(explicit.contains(&("cmd".to_string(), "hostname".to_string())));

    // The wrapping `cmd /c` is not reported as its own child: its payload
    // already describes the real children and repeats the same text.
    assert!(
        observations
            .iter()
            .all(|observation| observation.child.normalized_name() != "cmd")
    );

    // An interpreter with no recoverable payload is still reported.
    let encoded = observations_from_command_line("powershell.exe -enc SQBFAFgAKAA=");
    assert_eq!(encoded.len(), 1);
    assert_eq!(encoded[0].child.normalized_name(), "powershell");
}

#[test]
fn posix_only_commands_get_no_fabricated_windows_parent() {
    let observations = observations_from_command_line("git status && ls -la");
    assert!(
        observations
            .iter()
            .all(|observation| observation.parent.normalized_name().is_empty()),
        "no Windows shell is invented for POSIX-shaped commands"
    );
}
