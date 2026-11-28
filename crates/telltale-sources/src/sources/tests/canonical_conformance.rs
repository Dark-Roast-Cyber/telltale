//! Cross-source conformance tests: equivalent native input from different
//! adapters must produce the same canonical meaning and truthful capabilities.

use std::fs;

#[cfg(feature = "opencode-sqlite")]
use rusqlite::Connection;
use telltale_schema::clients::{ClientId, SourceKind};
#[cfg(feature = "opencode-sqlite")]
use telltale_schema::observation::ToolStatus;
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityId, ContentPartKind, JsonValue,
    MessageRole, ObservationBody, ObservationFamily, ObservationStage, ObservedAt,
};
use telltale_schema::source::Source;
use tempfile::{TempDir, tempdir};

const OBSERVED_AT: &str = "2026-09-02T12:00:00Z";

fn source(client: ClientId, source_id: &str, kind: SourceKind, path: std::path::PathBuf) -> Source {
    Source {
        client,
        kind,
        source_id: source_id.to_owned(),
        path,
    }
}

fn project_claude(contents: &str) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("claude-vector.jsonl");
    fs::write(&path, contents).expect("Claude vector");
    let result = crate::acquisition::acquire_source(
        &source(ClientId::Claude, "claude.projects", SourceKind::Jsonl, path),
        crate::acquisition::AcquisitionOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .map(|batch| batch.observations)
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

fn project_codex(contents: &str) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("codex-vector.jsonl");
    fs::write(&path, contents).expect("Codex vector");
    let result = crate::acquisition::acquire_source(
        &source(ClientId::Codex, "codex.sessions", SourceKind::Jsonl, path),
        crate::acquisition::AcquisitionOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .map(|batch| batch.observations)
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

fn project_openclaw(contents: &str) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("openclaw-vector.jsonl");
    fs::write(&path, contents).expect("OpenClaw vector");
    let result = crate::acquisition::acquire_source(
        &source(
            ClientId::OpenClaw,
            "openclaw.agents",
            SourceKind::Jsonl,
            path,
        ),
        crate::acquisition::AcquisitionOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .map(|batch| batch.observations)
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

fn project_qwen(contents: &str) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("qwen-vector.jsonl");
    fs::write(&path, contents).expect("Qwen vector");
    let result = crate::acquisition::acquire_source(
        &source(ClientId::Qwen, "qwen.projects", SourceKind::Jsonl, path),
        crate::acquisition::AcquisitionOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .map(|batch| batch.observations)
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

fn project_copilot(contents: &str) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("copilot-vector.log");
    fs::write(&path, contents).expect("Copilot vector");
    let result = crate::acquisition::acquire_source(
        &source(
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
            path,
        ),
        crate::acquisition::AcquisitionOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .map(|batch| batch.observations)
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

#[cfg(feature = "opencode-sqlite")]
fn opencode_fixture(
    messages: &[(&str, &str, serde_json::Value)],
    parts: &[(&str, &str, i64, serde_json::Value)],
) -> (TempDir, Source) {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("opencode-vector.db");
    let connection = Connection::open(&path).expect("OpenCode vector database");
    connection
        .execute_batch(
            "create table message (id text, session_id text, time_created integer, time_updated integer, data text);
             create table part (id text, message_id text, session_id text, time_created integer, time_updated integer, data text);",
        )
        .expect("OpenCode vector schema");
    for (id, session_id, data) in messages {
        connection
            .execute(
                "insert into message values (?1, ?2, ?3, ?4, ?5)",
                (*id, *session_id, 1_000_i64, 1_000_i64, data.to_string()),
            )
            .expect("OpenCode message vector");
    }
    for (id, message_id, updated, data) in parts {
        connection
            .execute(
                "insert into part values (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    *id,
                    *message_id,
                    "opencode-conformance",
                    *updated,
                    *updated,
                    data.to_string(),
                ),
            )
            .expect("OpenCode part vector");
    }
    drop(connection);
    (
        directory,
        source(
            ClientId::OpenCode,
            "opencode.sqlite",
            SourceKind::Sqlite,
            path,
        ),
    )
}

#[cfg(feature = "opencode-sqlite")]
fn project_opencode(
    messages: &[(&str, &str, serde_json::Value)],
    parts: &[(&str, &str, i64, serde_json::Value)],
) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let (directory, source) = opencode_fixture(messages, parts);
    let result = crate::acquisition::acquire_source(
        &source,
        crate::acquisition::AcquisitionOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .map(|batch| batch.observations)
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

#[cfg(feature = "opencode-sqlite")]
fn project_opencode_native(
    messages: &[(&str, &str, serde_json::Value)],
    parts: &[(&str, &str, i64, serde_json::Value)],
) -> (TempDir, Result<Vec<CanonicalObservationV2>, String>) {
    let (directory, source) = opencode_fixture(messages, parts);
    let native = super::super::opencode::native::extract_sqlite_native_source(
        &source,
        super::super::opencode::native::OpenCodeSqliteReadOptions::default(),
    )
    .expect("OpenCode native vector");
    let result = super::super::opencode::canonical::project_opencode_native_records(
        &native.records,
        &ObservedAt::new(OBSERVED_AT).expect("observed time"),
    )
    .map_err(|error| error.code().to_owned());
    (directory, result)
}

fn assert_semantically_equal(left: &CanonicalObservationV2, right: &CanonicalObservationV2) {
    assert_eq!(left.kind(), right.kind());
    assert_eq!(left.stage(), right.stage());
    // A declared operation comes from the source's own tool table, so it is
    // the one part of a tool body that differs between sources by design.
    match (left.body(), right.body()) {
        (ObservationBody::Tool(left), ObservationBody::Tool(right)) => {
            assert_eq!(left.name(), right.name());
            assert_eq!(left.arguments(), right.arguments());
            assert_eq!(left.searchable_arguments(), right.searchable_arguments());
            assert_eq!(left.result(), right.result());
            assert_eq!(left.searchable_result(), right.searchable_result());
            assert_eq!(left.reported_status(), right.reported_status());
            assert_eq!(left.is_error(), right.is_error());
            assert_eq!(left.exit_code(), right.exit_code());
        }
        (left, right) => assert_eq!(left, right),
    }
    assert_eq!(left.facets(), right.facets());
    assert_eq!(left.fact_metadata(), right.fact_metadata());
    assert_eq!(
        left.correlation().call_id().map(|id| id.value()),
        right.correlation().call_id().map(|id| id.value())
    );
}

fn assert_partial_session_capabilities(observations: &[CanonicalObservationV2]) {
    for observation in observations {
        let capabilities = observation.capability_context().expect("capabilities");
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolCall),
            CapabilityAvailability::Supported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::UserContext),
            CapabilityAvailability::Supported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Unknown
        );
    }
}

// Declared tool operations: every registered source identity declares what a
// file write, a file read and a shell call do, from its own tool table.

const WRITTEN: &str = "/synthetic/written.txt";
const READ: &str = "/synthetic/read.txt";
const COMMAND: &str = "echo synthetic-command";

fn jsonl(lines: &[serde_json::Value]) -> String {
    lines
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

fn assistant_tools(calls: &[(&str, serde_json::Value)]) -> String {
    let content = calls
        .iter()
        .enumerate()
        .map(|(index, (name, input))| {
            serde_json::json!({"type":"tool_use","id":format!("call-{index}"),"name":name,"input":input})
        })
        .collect::<Vec<_>>();
    jsonl(&[
        serde_json::json!({"type":"assistant","sessionId":"declared-operations",
        "message":{"role":"assistant","content":content}}),
    ])
}

fn tool_calls(calls: &[(&str, serde_json::Value)]) -> String {
    jsonl(
        &calls
            .iter()
            .enumerate()
            .map(|(index, (name, arguments))| {
                serde_json::json!({"type":"tool_call","sessionId":"declared-operations",
                    "call_id":format!("call-{index}"),"name":name,"arguments":arguments})
            })
            .collect::<Vec<_>>(),
    )
}

fn patch(path: &str) -> String {
    format!("*** Begin Patch\n*** Add File: {path}\n+synthetic\n*** End Patch")
}

fn codex_rollout() -> String {
    jsonl(&[
        serde_json::json!({"type":"session_meta","payload":{"id":"declared-operations"}}),
        serde_json::json!({"type":"response_item","payload":{"type":"custom_tool_call",
            "call_id":"call-0","name":"apply_patch","input":patch(WRITTEN),"status":"completed"}}),
        serde_json::json!({"type":"response_item","payload":{"type":"function_call",
            "name":"exec_command","call_id":"call-1",
            "arguments":serde_json::json!({"cmd":format!("cat {READ}")}).to_string()}}),
        serde_json::json!({"type":"response_item","payload":{"type":"function_call",
            "name":"exec_command","call_id":"call-2",
            "arguments":serde_json::json!({"cmd":COMMAND}).to_string()}}),
    ])
}

fn copilot_log() -> String {
    let call = |name: &str, call_id: &str, arguments: serde_json::Value| {
        serde_json::json!({"type":"function_call","name":name,"call_id":call_id,
            "arguments":arguments.to_string(),"status":"completed"})
    };
    let items = serde_json::json!([
        call(
            "create",
            "call-0",
            serde_json::json!({"path":WRITTEN,"file_text":"synthetic"})
        ),
        call("view", "call-1", serde_json::json!({"path":READ})),
        call("bash", "call-2", serde_json::json!({"command":COMMAND})),
    ]);
    format!(
        "2026-09-02T12:00:00Z [INFO] Workspace initialized: declared-operations (checkpoints: 0)\n2026-09-02T12:00:01Z [INFO] Accumulated output items (3): {items}\n"
    )
}

/// The observations of one registered identity's write, read and shell
/// fixture, and whether the identity has a read tool in its table.
fn declared_fixture(
    client: ClientId,
    source_id: &str,
    kind: SourceKind,
) -> (Vec<CanonicalObservationV2>, bool, Option<TempDir>) {
    let text_fixture = |contents: String| {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("declared-operations.jsonl");
        fs::write(&path, contents).expect("fixture");
        (directory, path)
    };
    let (contents, read_tool) = match source_id {
        "claude.projects" => (
            assistant_tools(&[
                (
                    "Write",
                    serde_json::json!({"file_path":WRITTEN,"content":"synthetic"}),
                ),
                ("Read", serde_json::json!({"file_path":READ})),
                ("Bash", serde_json::json!({"command":COMMAND})),
            ]),
            true,
        ),
        "openclaw.agents" => (
            tool_calls(&[
                (
                    "write",
                    serde_json::json!({"path":WRITTEN,"content":"synthetic"}),
                ),
                ("read", serde_json::json!({"path":READ})),
                ("bash", serde_json::json!({"command":COMMAND})),
            ]),
            true,
        ),
        "qwen.projects" => (
            tool_calls(&[
                (
                    "write_file",
                    serde_json::json!({"file_path":WRITTEN,"content":"synthetic"}),
                ),
                ("read_file", serde_json::json!({"absolute_path":READ})),
                ("run_shell_command", serde_json::json!({"command":COMMAND})),
            ]),
            true,
        ),
        "pi.sessions" => (
            jsonl(&[
                serde_json::json!({"type":"message","id":"declared-operations",
                "timestamp":"2026-09-02T12:00:00Z","message":{"role":"assistant","content":[
                    {"type":"toolCall","id":"call-0","name":"write",
                        "arguments":{"path":WRITTEN,"content":"synthetic"}},
                    {"type":"toolCall","id":"call-1","name":"read","arguments":{"path":READ}},
                    {"type":"toolCall","id":"call-2","name":"bash","arguments":{"command":COMMAND}}]}}),
            ]),
            true,
        ),
        "codex.sessions" | "codex.archived_sessions" | "codex.headless_sessions" => {
            (codex_rollout(), false)
        }
        "copilot.process_log" => {
            let directory = tempdir().expect("tempdir");
            let path = directory.path().join("copilot-declared.log");
            fs::write(&path, copilot_log()).expect("fixture");
            let batch = crate::acquisition::acquire_source(
                &source(client, source_id, kind, path),
                crate::acquisition::AcquisitionOptions::new(
                    ObservedAt::new(OBSERVED_AT).expect("observed time"),
                ),
            )
            .expect("Copilot declared fixture");
            return (batch.observations, true, Some(directory));
        }
        #[cfg(feature = "opencode-sqlite")]
        "opencode.sqlite" => {
            let part = |id: &str, order: i64, tool: &str, input: serde_json::Value| {
                (
                    id.to_owned(),
                    order,
                    serde_json::json!({"type":"tool","tool":tool,"callID":id,
                        "state":{"status":"pending","input":input}}),
                )
            };
            let parts = [
                part(
                    "call-0",
                    1,
                    "write",
                    serde_json::json!({"filePath":WRITTEN,"content":"synthetic"}),
                ),
                part("call-1", 2, "read", serde_json::json!({"filePath":READ})),
                part("call-2", 3, "bash", serde_json::json!({"command":COMMAND})),
            ];
            let parts = parts
                .iter()
                .map(|(id, order, data)| (id.as_str(), "tool-context", *order, data.clone()))
                .collect::<Vec<_>>();
            let (directory, source) = opencode_fixture(
                &[(
                    "tool-context",
                    "opencode-conformance",
                    serde_json::json!({"role":"assistant"}),
                )],
                &parts,
            );
            let batch = crate::acquisition::acquire_source(
                &source,
                crate::acquisition::AcquisitionOptions::new(
                    ObservedAt::new(OBSERVED_AT).expect("observed time"),
                ),
            )
            .expect("OpenCode declared fixture");
            return (batch.observations, true, Some(directory));
        }
        other => panic!("{other} has no declared-operation fixture"),
    };
    let (directory, path) = text_fixture(contents);
    let batch = crate::acquisition::acquire_source(
        &source(client, source_id, kind, path),
        crate::acquisition::AcquisitionOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .unwrap_or_else(|error| panic!("{source_id}: {}", error.code()));
    (batch.observations, read_tool, Some(directory))
}

mod capability_gaps;
mod cross_source_equivalence;
mod declared_operations;
#[cfg(feature = "opencode-sqlite")]
mod opencode_sqlite;
