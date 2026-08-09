use std::collections::HashMap;
use std::fs;
use std::process::Command;

use jsonschema::validator_for;
use serde_json::Value;
use telltale_schema::event::path_hash;
use telltale_sources::discovery::discover_sources_best_effort;
use tempfile::tempdir;

#[test]
fn parser_maturity_fixture_events_preserve_source_tuple_and_order() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("events.jsonl");
    let state_path = temp.path().join("state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_telltale"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--emit-activity",
            "--no-local-config",
            "--root",
            "tests/fixtures/parser_maturity",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run telltale");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = fs::read_to_string(log_path)
        .expect("event log")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let schema: Value =
        serde_json::from_str(include_str!("../../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    assert!(events.iter().all(|event| validator.is_valid(event)));

    let sources =
        discover_sources_best_effort(std::path::Path::new("tests/fixtures/parser_maturity"));
    let source_by_hash = sources
        .iter()
        .map(|source| {
            (
                path_hash(&source.path),
                (source.source_id.as_str(), source.client.as_str()),
            )
        })
        .collect::<HashMap<_, _>>();

    let actual = events
        .iter()
        .map(|event| {
            let source = event
                .get("source_path_hash")
                .and_then(Value::as_str)
                .and_then(|hash| source_by_hash.get(hash).copied());
            (
                source,
                event["event_type"].as_str(),
                event["client"].as_str(),
                event["session_id"].as_str(),
                event["schema_version"].as_str(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        vec![
            (
                None,
                Some("health"),
                Some("codex,opencode"),
                Some("scanner"),
                Some("3.0"),
            ),
            (
                None,
                Some("activity"),
                Some("install_inventory"),
                Some("scanner"),
                Some("3.0"),
            ),
            (
                Some(("codex.project_sessions", "codex")),
                Some("activity"),
                Some("codex"),
                Some("project-session"),
                Some("3.0"),
            ),
            (
                Some(("opencode.project_json", "opencode")),
                Some("activity"),
                Some("opencode"),
                Some("opencode-project-session"),
                Some("3.0"),
            ),
        ]
    );
}
