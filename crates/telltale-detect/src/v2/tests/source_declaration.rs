//! Calls mapped by each source that reads files without SQLite give the action
//! view their written path, read paths and command from the source's own tool
//! table. The OpenCode store is covered by the source crate's conformance test.

use std::fs;

use super::super::actions::view_reading;
use serde_json::{Value, json};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{ObservationBody, ObservationStage, ObservedAt};
use telltale_schema::source::Source;
use telltale_sources::acquisition::{AcquisitionOptions, acquire_source};
use tempfile::tempdir;

const WRITTEN: &str = "/synthetic/written.txt";
const READ: &str = "/synthetic/read.txt";
const COMMAND: &str = "echo synthetic-command";

fn jsonl(lines: &[Value]) -> String {
    lines
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

fn tool_calls(calls: [(&str, Value); 3]) -> String {
    jsonl(
        &calls
            .iter()
            .enumerate()
            .map(|(index, (name, arguments))| {
                json!({"type":"tool_call","sessionId":"declared","call_id":format!("call-{index}"),
                    "name":name,"arguments":arguments})
            })
            .collect::<Vec<_>>(),
    )
}

fn claude() -> String {
    let content = [
        ("Write", json!({"file_path":WRITTEN,"content":"synthetic"})),
        ("Read", json!({"file_path":READ})),
        ("Bash", json!({"command":COMMAND})),
    ]
    .iter()
    .enumerate()
    .map(|(index, (name, input))| {
        json!({"type":"tool_use","id":format!("call-{index}"),"name":name,"input":input})
    })
    .collect::<Vec<_>>();
    jsonl(&[json!({"type":"assistant","sessionId":"declared",
        "message":{"role":"assistant","content":content}})])
}

fn codex() -> String {
    let patch = format!("*** Begin Patch\n*** Add File: {WRITTEN}\n+synthetic\n*** End Patch");
    jsonl(&[
        json!({"type":"session_meta","payload":{"id":"declared"}}),
        json!({"type":"response_item","payload":{"type":"custom_tool_call",
            "call_id":"call-0","name":"apply_patch","input":patch,"status":"completed"}}),
        json!({"type":"response_item","payload":{"type":"function_call","name":"exec_command",
            "call_id":"call-1","arguments":json!({"cmd":format!("cat {READ}")}).to_string()}}),
        json!({"type":"response_item","payload":{"type":"function_call","name":"exec_command",
            "call_id":"call-2","arguments":json!({"cmd":COMMAND}).to_string()}}),
    ])
}

fn copilot() -> String {
    let call = |name: &str, id: &str, arguments: Value| {
        json!({"type":"function_call","name":name,"call_id":id,
            "arguments":arguments.to_string(),"status":"completed"})
    };
    let items = json!([
        call(
            "create",
            "call-0",
            json!({"path":WRITTEN,"file_text":"synthetic"})
        ),
        call("view", "call-1", json!({"path":READ})),
        call("bash", "call-2", json!({"command":COMMAND})),
    ]);
    format!(
        "2026-09-02T12:00:00Z [INFO] Workspace initialized: declared (checkpoints: 0)\n2026-09-02T12:00:01Z [INFO] Accumulated output items (3): {items}\n"
    )
}

/// The action-view facts of each tool request in one source's fixture.
fn requests(
    client: ClientId,
    source_id: &str,
    kind: SourceKind,
    contents: &str,
) -> Vec<(std::collections::BTreeMap<&'static str, String>, bool)> {
    let directory = tempdir().unwrap();
    let path = directory.path().join("declared.jsonl");
    fs::write(&path, contents).unwrap();
    let batch = acquire_source(
        &Source {
            client,
            kind,
            source_id: source_id.to_owned(),
            path,
        },
        AcquisitionOptions::new(ObservedAt::new("2026-09-20T00:00:00Z").unwrap()),
    )
    .unwrap_or_else(|error| panic!("{source_id}: {}", error.code()));
    batch
        .observations
        .iter()
        .filter(|observation| {
            observation.stage() == ObservationStage::ToolRequested
                && matches!(observation.body(), ObservationBody::Tool(_))
        })
        .map(view_reading)
        .collect()
}

fn has(
    readings: &[(std::collections::BTreeMap<&'static str, String>, bool)],
    field: &str,
    text: &str,
) -> bool {
    readings.iter().any(|(fields, _)| {
        fields
            .get(field)
            .is_some_and(|value| value.lines().any(|line| line.contains(text)))
    })
}

#[test]
fn each_file_source_gives_detection_its_write_read_and_shell_facts() {
    let cases: [(ClientId, &str, SourceKind, String, bool); 6] = [
        (
            ClientId::Claude,
            "claude.projects",
            SourceKind::Jsonl,
            claude(),
            true,
        ),
        (
            ClientId::OpenClaw,
            "openclaw.agents",
            SourceKind::Jsonl,
            tool_calls([
                ("write", json!({"path":WRITTEN,"content":"synthetic"})),
                ("read", json!({"path":READ})),
                ("bash", json!({"command":COMMAND})),
            ]),
            true,
        ),
        (
            ClientId::Qwen,
            "qwen.projects",
            SourceKind::Jsonl,
            tool_calls([
                (
                    "write_file",
                    json!({"file_path":WRITTEN,"content":"synthetic"}),
                ),
                ("read_file", json!({"absolute_path":READ})),
                ("run_shell_command", json!({"command":COMMAND})),
            ]),
            true,
        ),
        (
            ClientId::Codex,
            "codex.sessions",
            SourceKind::Jsonl,
            codex(),
            false,
        ),
        (
            ClientId::Codex,
            "codex.archived_sessions",
            SourceKind::ArchivedJsonl,
            codex(),
            false,
        ),
        (
            ClientId::Codex,
            "codex.headless_sessions",
            SourceKind::HeadlessJsonl,
            codex(),
            false,
        ),
    ];
    for (client, source_id, kind, contents, read_tool) in cases {
        let readings = requests(client, source_id, kind, &contents);
        assert!(
            has(&readings, "written_path", WRITTEN),
            "{source_id}: written path"
        );
        assert!(has(&readings, "file_path", READ), "{source_id}: read path");
        assert!(has(&readings, "command", COMMAND), "{source_id}: command");
        // A read tool reads every path it is given. Codex reads through the
        // shell, which the command's own reading covers.
        assert!(
            readings.iter().any(|(_, reads)| *reads),
            "{source_id}: reads paths (read tool: {read_tool})"
        );
    }

    let directory = tempdir().unwrap();
    let path = directory.path().join("copilot.log");
    fs::write(&path, copilot()).unwrap();
    let batch = acquire_source(
        &Source {
            client: ClientId::Copilot,
            kind: SourceKind::CopilotProcessLog,
            source_id: "copilot.process_log".to_owned(),
            path,
        },
        AcquisitionOptions::new(ObservedAt::new("2026-09-20T00:00:00Z").unwrap()),
    )
    .unwrap();
    let readings: Vec<_> = batch
        .observations
        .iter()
        .filter(|observation| observation.stage() == ObservationStage::ToolRequested)
        .map(view_reading)
        .collect();
    assert!(
        has(&readings, "written_path", WRITTEN),
        "copilot: written path"
    );
    assert!(has(&readings, "file_path", READ), "copilot: read path");
    assert!(has(&readings, "command", COMMAND), "copilot: command");
    assert!(
        readings.iter().any(|(_, reads)| *reads),
        "copilot: reads paths"
    );
}

/// Every tool a source's table names is declared as detection's fallback reads
/// its name, so a declaration never narrows what the name alone gave.
#[test]
fn every_table_row_agrees_with_the_name_fallback() {
    use super::super::tool_arguments::{is_file_read_tool, is_file_write_tool};
    use telltale_schema::observation::ToolKind;
    let rows = telltale_sources::declared_tools();
    assert!(!rows.is_empty());
    for telltale_sources::DeclaredTool {
        client, name, kind, ..
    } in rows
    {
        if is_file_write_tool(name) {
            assert_eq!(kind, ToolKind::FileWrite, "{client:?} {name}");
        }
        if is_file_read_tool(name) {
            assert_eq!(kind, ToolKind::FileRead, "{client:?} {name}");
        }
    }
}

const URL: &str = "https://example.invalid/synthetic";

/// Rows restored from the harnesses' own tool definitions give detection the
/// facts their operands name, and a call that carries no such operand gives
/// none: a declaration only adds facts.
#[test]
fn restored_rows_add_facts_only_when_the_call_carries_the_operand() {
    let patch = format!("*** Begin Patch\n*** Add File: {WRITTEN}\n+synthetic\n*** End Patch");
    let with_operands = [
        (
            ClientId::OpenClaw,
            "openclaw.agents",
            tool_calls([
                ("exec", json!({"command":COMMAND})),
                ("apply_patch", json!({"input":patch})),
                ("web_fetch", json!({"url":URL})),
            ]),
        ),
        (
            ClientId::Qwen,
            "qwen.projects",
            tool_calls([
                ("monitor", json!({"command":COMMAND})),
                ("list_directory", json!({"path":READ})),
                ("web_fetch", json!({"url":URL})),
            ]),
        ),
    ];
    for (client, source_id, contents) in with_operands {
        let readings = requests(client, source_id, SourceKind::Jsonl, &contents);
        assert!(has(&readings, "command", COMMAND), "{source_id}: command");
        assert!(has(&readings, "url", URL), "{source_id}: url");
        let wrote = has(&readings, "written_path", WRITTEN);
        let read = has(&readings, "file_path", READ);
        assert!(wrote || read, "{source_id}: file operand");
    }
    let without_operands = [
        (
            ClientId::OpenClaw,
            "openclaw.agents",
            tool_calls([
                ("exec", json!({"title":"synthetic"})),
                ("apply_patch", json!({"input":"no patch here"})),
                ("web_fetch", json!({"extractMode":"text"})),
            ]),
        ),
        (
            ClientId::Qwen,
            "qwen.projects",
            tool_calls([
                ("monitor", json!({"description":"synthetic"})),
                ("list_directory", json!({"ignore":["x"]})),
                ("web_fetch", json!({"prompt":"synthetic"})),
            ]),
        ),
    ];
    for (client, source_id, contents) in without_operands {
        let readings = requests(client, source_id, SourceKind::Jsonl, &contents);
        for field in ["command", "url", "written_path", "file_path"] {
            assert!(
                !has(&readings, field, "synthetic") && !has(&readings, field, "example.invalid"),
                "{source_id}: {field}"
            );
        }
        assert!(
            readings
                .iter()
                .all(|(fields, _)| !fields.contains_key("written_path")
                    && !fields.contains_key("url")),
            "{source_id}: no operand, no fact"
        );
    }
}

/// A Copilot CLI request with an argument value over its bound keeps its other
/// arguments, and its raw request text is not kept beside them: the argument
/// text selectors have no visibility into the call, while the command from a
/// kept member is read.
#[test]
fn a_copilot_request_with_a_replaced_argument_has_no_argument_text_visibility() {
    use super::super::{
        MatchState, MatcherSpec, NonEvaluationReason, SelectorId, SelectorPresence,
    };
    let items = json!([{"type":"function_call","name":"bash","call_id":"call-0",
        "arguments":json!({"command":COMMAND,"description":"x".repeat(4_097)}).to_string(),
        "status":"completed"}]);
    let directory = tempdir().unwrap();
    let path = directory.path().join("copilot.log");
    fs::write(
        &path,
        format!(
            "2026-09-02T12:00:00Z [INFO] Workspace initialized: declared (checkpoints: 0)\n2026-09-02T12:00:01Z [INFO] Accumulated output items (1): {items}\n"
        ),
    )
    .unwrap();
    let batch = acquire_source(
        &Source {
            client: ClientId::Copilot,
            kind: SourceKind::CopilotProcessLog,
            source_id: "copilot.process_log".to_owned(),
            path,
        },
        AcquisitionOptions::new(ObservedAt::new("2026-09-20T00:00:00Z").unwrap()),
    )
    .unwrap();
    let [request] = batch.observations.as_slice() else {
        panic!("one request")
    };
    let resolve = |name| {
        super::super::SelectorRegistry::new()
            .resolve(SelectorId::parse(name).unwrap(), request)
            .unwrap()
    };
    assert_eq!(
        resolve("compat.v1.arguments").presence(),
        SelectorPresence::UnavailableVisibility
    );
    assert_eq!(
        resolve("tool.searchable_arguments").presence(),
        SelectorPresence::UnavailableVisibility
    );
    assert_eq!(
        resolve("compat.v1.command").value(),
        Some(&telltale_schema::observation::JsonValue::string(COMMAND))
    );
    let state = MatcherSpec::not_exists("compat.v1.arguments")
        .compile()
        .unwrap()
        .evaluate(request)
        .unwrap();
    assert_eq!(
        state.state(),
        &MatchState::NotEvaluated(NonEvaluationReason::InsufficientVisibility)
    );
}
