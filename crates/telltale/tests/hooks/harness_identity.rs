//! Hooks records carry the identity of the harness the call belongs to: the
//! adapter's client and hook-journal source (ADR 0002 addendum). Every
//! registered adapter is held to the same table, so a new harness cannot be
//! added without its captured pre-execution payload.

use crate::common;

use serde_json::{Value, json};
use telltale_core::hooks::harness::{Harness, Parsed};
use telltale_core::hooks::runtime::{Context, Event, ToolCall};
use telltale_core::{
    AcquisitionError, ClientId, DetailedEvaluationOptions, Pipeline, Source, SourceKind,
};

const HARVEST: &str = "cat ~/.aws/credentials";

/// Each harness's captured pre-execution payload: fixture directory, file and
/// the event name its capture lines carry.
const CAPTURES: &[(Harness, &str, &str, &str)] = &[
    (
        Harness::ClaudeCode,
        "claude-code/2.1.318",
        "tool-lifecycle-subagent.jsonl",
        "PreToolUse",
    ),
    (
        Harness::CodexCli,
        "codex-cli/0.166.0",
        "deny-hso.jsonl",
        "PreToolUse",
    ),
    (
        Harness::CopilotCli,
        "copilot-cli/1.0.105",
        "deny-camel-hso.jsonl",
        "preToolUse",
    ),
];

/// The captured pre-execution payload of `harness`, its command replaced by one
/// that earns findings, as bytes for the adapter.
fn pre_tool_use(harness: Harness) -> Vec<u8> {
    let (_, dir, file, event) = CAPTURES
        .iter()
        .find(|(known, ..)| *known == harness)
        .unwrap_or_else(|| panic!("no captured payload for {}", harness.name()));
    let text = std::fs::read_to_string(common::fixtures(dir).join(file)).unwrap();
    // Capture lines wrap the payload; Claude Code's are the payloads themselves.
    let mut payload = text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .map(|line| {
            (
                line["event"].clone(),
                line.get("payload").cloned().unwrap_or(line),
            )
        })
        .find(|(name, payload)| {
            (*name == *event || payload["hook_event_name"] == *event)
                && payload.get("agent_id").is_none()
        })
        .map(|(_, payload)| payload)
        .unwrap_or_else(|| panic!("no {event} capture in {file}"));
    let args = ["tool_input", "toolArgs"]
        .into_iter()
        .find(|key| payload.get(key).is_some())
        .expect("a tool input");
    payload[args]["command"] = HARVEST.into();
    serde_json::to_vec(&payload).unwrap()
}

/// Run `bytes` through `entry`'s parser and the runtime. Returns the parsed
/// context's harness name and the decision's Telltale records.
fn decide(entry: Harness, bytes: &[u8]) -> (&'static str, Vec<Value>) {
    let Parsed::Event(ctx, event) = entry.parse(bytes) else {
        panic!("{} could not read its own capture", entry.name());
    };
    let mut h = common::Harness::new();
    h.runtime.handle(&ctx, event);
    let decisions = h.records("decision");
    assert_eq!(decisions.len(), 1, "{}", entry.name());
    let records = decisions[0]["telltale"].as_array().unwrap().clone();
    (ctx.harness, records)
}

fn assert_identity(records: &[Value], harness: Harness) {
    let adapter = harness.adapter();
    assert!(!records.is_empty(), "{}: no Telltale records", adapter.name);
    for record in records {
        let record = &record["record"];
        assert_eq!(
            record["client"],
            adapter.client.as_str(),
            "{}",
            adapter.name
        );
        assert_eq!(record["source_id"], adapter.hook_source, "{}", adapter.name);
    }
}

#[test]
fn records_carry_the_identity_of_every_registered_harness() {
    for &harness in Harness::ALL {
        let (name, records) = decide(harness, &pre_tool_use(harness));
        assert_eq!(name, harness.name());
        assert_identity(&records, harness);
    }
}

/// A Copilot CLI payload that arrives at the Claude Code entry point is
/// recorded as Copilot CLI, not as the entry point's harness.
#[test]
fn a_copilot_payload_at_the_claude_code_entry_point_is_recorded_as_copilot() {
    let (name, records) = decide(Harness::ClaudeCode, &pre_tool_use(Harness::CopilotCli));
    assert_eq!(name, Harness::CopilotCli.name());
    assert_identity(&records, Harness::CopilotCli);
}

#[test]
fn every_adapter_identity_is_accepted_by_acquisition_for_its_own_client_only() {
    let dir = tempfile::tempdir().unwrap();
    let window = dir.path().join("window.jsonl");
    std::fs::write(
        &window,
        format!(
            "{}\n",
            json!({"type":"user","sessionId":"s","uuid":"u","timestamp":"2026-11-04T00:00:00.001Z",
                   "message":{"role":"user","content":"synthetic"}})
        ),
    )
    .unwrap();
    let options = || {
        telltale_sources::acquisition::AcquisitionOptions::new(
            telltale_schema::observation::ObservedAt::new("2026-11-04T00:00:01Z").unwrap(),
        )
    };
    let source = |client: ClientId, source_id: &str| Source {
        client,
        kind: SourceKind::Jsonl,
        source_id: source_id.to_owned(),
        path: window.clone(),
    };
    for &harness in Harness::ALL {
        let adapter = harness.adapter();
        let batch = telltale_sources::acquisition::acquire_source(
            &source(adapter.client, adapter.hook_source),
            options(),
        )
        .unwrap_or_else(|error| panic!("{}: {error}", adapter.name));
        assert!(!batch.observations.is_empty());
        for other in Harness::ALL.iter().filter(|other| **other != harness) {
            let cross = telltale_sources::acquisition::acquire_source(
                &source(adapter.client, other.adapter().hook_source),
                options(),
            );
            assert_eq!(
                cross.err(),
                Some(AcquisitionError::UnsupportedSourceIdentity)
            );
        }
    }
}

/// A harness name with no adapter is never given an identity: nothing is
/// evaluated and the call takes the error path (`on_error`).
#[test]
fn an_unregistered_harness_name_is_not_evaluated() {
    let mut h = common::Harness::with(|config| {
        config.on_error = telltale_core::hooks::config::OnError::Deny;
    });
    let ctx = Context {
        harness: "unregistered-harness",
        hook_event: "PreToolUse".into(),
        session_id: h.session_id.clone(),
        agent_id: None,
        agent_type: None,
        prompt_id: None,
        permission_mode: None,
        cwd: None,
        can_ask: true,
    };
    let call = ToolCall {
        tool_use_id: Some("c1".into()),
        tool_name: "Bash".into(),
        input: json!({"command": HARVEST}),
    };
    h.runtime.handle(&ctx, Event::ToolRequested(call));
    let record = h.decision_for("c1");
    assert_eq!(record["decision"]["verdict"], "deny");
    assert_eq!(record["decision"]["basis"], "evaluation_gap");
    assert!(record["telltale"].as_array().unwrap().is_empty());
    let errors = h.records("error");
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["error_code"], "harness_unregistered");
}

/// The same window scanned as the Claude Code session source and under each
/// hook-journal identity gives the same Telltale records and detection results:
/// only fields derived from the identity differ.
#[test]
fn a_window_scans_alike_under_every_identity() {
    let dir = tempfile::tempdir().unwrap();
    let window = dir.path().join("window.jsonl");
    let lines = [
        json!({"type":"user","sessionId":"s","uuid":"u0","timestamp":"2026-11-04T00:00:00.001Z",
               "message":{"role":"user","content":"synthetic prompt"}}),
        tool_use(
            "a1",
            "2026-11-04T00:00:00.002Z",
            "Bash",
            json!({"command": "ls -la"}),
        ),
        tool_use(
            "a2",
            "2026-11-04T00:00:00.003Z",
            "Bash",
            json!({"command": HARVEST}),
        ),
        tool_use(
            "a3",
            "2026-11-04T00:00:00.004Z",
            "Read",
            json!({"file_path": "/home/synthetic/.ssh/id_ed25519"}),
        ),
        tool_use(
            "a4",
            "2026-11-04T00:00:00.005Z",
            "Write",
            json!({"file_path": "/home/synthetic/.claude/settings.json", "content": "{}"}),
        ),
    ];
    std::fs::write(
        &window,
        lines
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>(),
    )
    .unwrap();
    let pipeline = Pipeline::builder().build().unwrap();
    let options = DetailedEvaluationOptions::default();
    let scan = |client: ClientId, source_id: &str| {
        let scan = pipeline
            .scan_sources_detailed(
                &[Source {
                    client,
                    kind: SourceKind::Jsonl,
                    source_id: source_id.to_owned(),
                    path: window.clone(),
                }],
                &options,
            )
            .unwrap()
            .remove(0);
        assert!(scan.failure().is_none(), "{source_id}");
        scan
    };
    let masked = |scan: &telltale_core::SourceScan| {
        let records: Vec<Value> = scan
            .action_records()
            .into_iter()
            .map(|record| {
                let mut value = serde_json::to_value(record).unwrap();
                let fields = value.as_object_mut().unwrap();
                for derived in [
                    "client",
                    "source_id",
                    "coordinate",
                    "replay_identity",
                    "session_event_id",
                    "supporting_observation_ids",
                ] {
                    fields.remove(derived);
                }
                // The IDs inside findings are hashes over the identity as well.
                for finding in fields["canonical_findings"].as_array_mut().unwrap() {
                    for derived in ["finding_id", "observation_ids", "signal_ids"] {
                        finding.as_object_mut().unwrap().remove(derived);
                    }
                }
                value
            })
            .collect();
        let events: Vec<Value> = scan
            .events
            .iter()
            .map(|event| {
                json!([
                    event.event_type,
                    event.severity,
                    event.risk_score,
                    event.rule_ids,
                    event.categories,
                    event.tool_name,
                    event.session_id,
                ])
            })
            .collect();
        (
            records,
            events,
            scan.completion,
            scan.coverage(),
            scan.quarantined().len(),
            scan.visibility_limits().len(),
        )
    };
    let reference = scan(ClientId::Claude, "claude.projects");
    let expected = masked(&reference);
    assert!(
        expected.0.len() >= 2,
        "the window must earn findings: {}",
        expected.0.len()
    );
    for &harness in Harness::ALL {
        let adapter = harness.adapter();
        let hooked = scan(adapter.client, adapter.hook_source);
        assert_eq!(masked(&hooked), expected, "{}", adapter.name);
        for record in hooked.action_records() {
            assert_eq!(record.client, adapter.client.as_str());
            assert_eq!(record.source_id, adapter.hook_source);
        }
        for event in &hooked.events {
            assert_eq!(event.client, adapter.client.as_str(), "{}", adapter.name);
        }
    }
}

fn tool_use(id: &str, at: &str, tool: &str, input: Value) -> Value {
    json!({"type":"assistant","sessionId":"s","uuid":id,"timestamp":at,
           "message":{"role":"assistant","content":[{"type":"tool_use","id":id,"name":tool,"input":input}]}})
}
