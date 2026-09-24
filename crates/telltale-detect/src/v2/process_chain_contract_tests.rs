//! Permanent process-chain contracts through canonical source evaluation.

use telltale_rules::process_chain::load_default_process_chain_rules;
use telltale_schema::clients::ClientId;
use telltale_schema::observation::*;

use super::{
    compile_rule_v1,
    event3::{Event3CompatibilityContext, project_event3},
    session::{CanonicalSourceInput, evaluate_source},
};
use crate::process_chain::ProcessChainConfig;

fn events_for(commands: &[(&str, &str)]) -> Vec<telltale_schema::event::Event> {
    let observations = commands
        .iter()
        .enumerate()
        .map(|(index, (command, timestamp))| {
            CanonicalObservationV2::builder(
                ObservationBody::Tool(
                    ToolObservation::new()
                        .with_name("shell")
                        .unwrap()
                        .with_arguments(JsonValue::string(*command)),
                ),
                ObservationStage::ToolRequested,
                ObservedAt::new("2026-05-10T11:00:00Z").unwrap(),
                SourceProvenance::new(
                    IngestionMode::SessionStore,
                    "codex",
                    "codex.sessions",
                    Fidelity::FullNative,
                )
                .unwrap()
                .with_native_id(format!("command-{index}"))
                .unwrap(),
            )
            .session_id(CorrelationId::source_reported("process-chain").unwrap())
            .sequence(index as u64)
            .fact_metadata(
                "tool.name",
                FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
            )
            .occurred_at(SourceTimestamp::new(*timestamp).unwrap())
            .fact_metadata(
                "tool.arguments",
                FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
            )
            .build()
            .unwrap()
        })
        .collect::<Vec<_>>();
    let rules = load_default_process_chain_rules().expect("pack compiles");
    let plan = compile_rule_v1(
        &telltale_rules::load_default_rule_set()
            .unwrap()
            .compatibility_export(),
    )
    .unwrap();
    let instance = CorrelationId::source_reported("synthetic-process-source").unwrap();
    let evaluation = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Codex,
            source_id: "codex.sessions",
            source_instance: Some(&instance),
            observations: &observations,
        },
        &plan,
        Some((&rules, &ProcessChainConfig::default())),
    )
    .unwrap();
    project_event3(
        &evaluation,
        &Event3CompatibilityContext {
            source_path_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            sessions: &[],
        },
    )
    .unwrap()
    .events
    .into_iter()
    .filter(|event| event.event_type == "process_chain")
    .collect()
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
    // Canonical projection redacts path-bearing command text before retention.
    assert_eq!(
        process.target_process_command_line.as_deref(),
        Some("[sensitive-path] [sensitive-path]")
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
fn one_tool_observation_correlation_preserves_parser_statement_order() {
    let reversed = events_for(&[(
        "cmd.exe /c whoami && cmd.exe /c hostname",
        "2026-05-10T10:00:00Z",
    )]);
    assert!(
        event_with_rule(
            &reversed,
            "procchain.correlation.host_then_account_discovery"
        )
        .is_none()
    );

    let forward = events_for(&[(
        "cmd.exe /c hostname && cmd.exe /c whoami",
        "2026-05-10T10:00:00Z",
    )]);
    assert!(
        event_with_rule(
            &forward,
            "procchain.correlation.host_then_account_discovery"
        )
        .is_some()
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
