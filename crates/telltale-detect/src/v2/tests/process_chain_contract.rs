//! Permanent process-chain contracts through canonical source evaluation.

use telltale_rules::process_chain::load_default_process_chain_rules;
use telltale_schema::clients::ClientId;
use telltale_schema::observation::*;

use super::super::{
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
    let plan = crate::v2::bundled_plan();
    let instance = CorrelationId::source_reported("synthetic-process-source").unwrap();
    let evaluation = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Codex,
            source_id: "codex.sessions",
            source_instance: Some(&instance),
            observations: &observations,
        },
        plan,
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
fn schtasks_query_is_not_scored_as_task_creation() {
    let scored = |command| {
        let events = events_for(&[(command, "2026-05-10T10:00:00Z")]);
        ["cmd", "powershell"].into_iter().find(|parent| {
            event_with_rule(&events, &format!("procchain.persistence.{parent}_schtasks")).is_some()
        })
    };
    assert_eq!(
        scored("schtasks.exe /Query /TN SyntheticUpdater /FO LIST"),
        None
    );
    assert_eq!(scored(r"C:\Windows\System32\schtasks.exe -query"), None);
    assert_eq!(
        scored(r#"powershell -c "schtasks /query /tn SyntheticUpdater""#),
        None
    );
    assert_eq!(
        scored("schtasks.exe /Create /TN SyntheticUpdater /TR synthetic-updater.exe /SC DAILY"),
        Some("cmd")
    );
    assert_eq!(
        scored(
            r#"powershell -c "schtasks /create /tn SyntheticUpdater /tr synthetic-updater.exe""#
        ),
        Some("powershell")
    );
    // A query inside the created task's action does not excuse the creation.
    assert_eq!(
        scored(
            r#"schtasks.exe /Create /TN SyntheticUpdater /TR "cmd /c schtasks /query & synthetic-updater.exe" /SC DAILY"#
        ),
        Some("cmd")
    );
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
    // Canonical projection redacts path-bearing command text before retention;
    // a bare command flag is not a path.
    assert_eq!(
        process.target_process_command_line.as_deref(),
        Some("[sensitive-path] /all")
    );
    assert!(!process.source_process_inferred);
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
