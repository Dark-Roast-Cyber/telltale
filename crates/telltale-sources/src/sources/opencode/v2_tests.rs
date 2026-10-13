//! OpenCode v2 (`session_v2`/`session_message`) acquisition through the public
//! acquisition seam. Every store is synthetic and owned by these tests; the DDL
//! mirrors OpenCode v2.0.27 (`packages/core/src/database/schema.gen.ts` at
//! 1f4d07a4a519185955ae8ab2ea3607805509e386) for the tables this adapter reads.

use std::collections::BTreeMap;

use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::native::{SqliteAdmission, on_next_incremental_page};
use super::session_message::extract_incremental_messages;
use crate::acquisition::{
    AccountingCoverage, AcquisitionBatch, AcquisitionError, AcquisitionOptions,
    AcquisitionProgress, AttestedValue, BoundedReadError, OpenCodeSqliteReadOptions,
    acquire_opencode_sqlite,
};
use crate::source_read::SourceReadError;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{
    CanonicalObservationV2, CapabilityAvailability, CapabilityId, FactProvenance, JsonValue,
    MessageRole, ObservationBody, ObservationFamily, ObservationStage, ObservedAt,
    SemanticReplayVerdict, ToolObservation, ToolStatus,
};
use telltale_schema::source::Source;

pub(super) const V2_SCHEMA: &str = "
CREATE TABLE `session_v2` (
  `id` text PRIMARY KEY, `project_id` text NOT NULL, `workspace_id` text, `parent_id` text,
  `fork_session_id` text, `fork_boundary` text, `slug` text NOT NULL, `directory` text NOT NULL,
  `path` text, `title` text, `version` text NOT NULL, `share_url` text, `summary_additions` integer,
  `summary_deletions` integer, `summary_files` integer, `summary_diffs` text, `metadata` text,
  `cost` real DEFAULT 0 NOT NULL, `tokens_input` integer DEFAULT 0 NOT NULL,
  `tokens_output` integer DEFAULT 0 NOT NULL, `tokens_reasoning` integer DEFAULT 0 NOT NULL,
  `tokens_cache_read` integer DEFAULT 0 NOT NULL, `tokens_cache_write` integer DEFAULT 0 NOT NULL,
  `revert` text, `permission` text, `agent` text, `model` text, `time_created` integer NOT NULL,
  `time_updated` integer NOT NULL, `time_idle` integer, `time_viewed` integer, `idle_outcome` text,
  `time_compacting` integer, `time_archived` integer, `time_suspended` integer,
  `resume_attempts` integer DEFAULT 0 NOT NULL
);
CREATE TABLE `session_message` (
  `id` text PRIMARY KEY, `session_id` text NOT NULL, `type` text NOT NULL, `seq` integer NOT NULL,
  `time_created` integer NOT NULL, `time_updated` integer NOT NULL, `data` text NOT NULL,
  CONSTRAINT `fk_session_message_session_id_session_v2_id_fk` FOREIGN KEY (`session_id`) REFERENCES `session_v2`(`id`) ON DELETE CASCADE
);
CREATE UNIQUE INDEX `session_message_session_seq_idx` ON `session_message` (`session_id`,`seq`);
CREATE TABLE `credential` (`id` text PRIMARY KEY, `integration_id` text, `label` text NOT NULL,
  `value` text NOT NULL, `connector_id` text, `method_id` text, `active` integer,
  `time_created` integer NOT NULL, `time_updated` integer NOT NULL);
";

const LEGACY_SCHEMA: &str = "
create table message (id text, session_id text, time_created integer, time_updated integer, data text);
create table part (id text, message_id text, session_id text, time_created integer, time_updated integer, data text);
";

/// 2026-03-31T23:33:20Z in Unix milliseconds.
pub(super) const T0: i64 = 1_775_000_000_000;
const HOUR: i64 = 3_600_000;
const OBSERVED_AT: &str = "2026-10-13T12:00:00Z";

pub(super) struct Store {
    directory: TempDir,
    pub(super) connection: Connection,
    pub(super) source: Source,
}

impl Store {
    pub(super) fn new(schema: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("opencode.db");
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(schema).unwrap();
        Self {
            directory,
            connection,
            source: source(path),
        }
    }

    pub(super) fn v2() -> Self {
        let store = Self::new(V2_SCHEMA);
        store.session("ses_synthetic");
        store
    }

    pub(super) fn session(&self, id: &str) {
        self.connection
            .execute(
                "insert into session_v2 (id, project_id, slug, directory, version, agent, model, time_created, time_updated, metadata, permission)
                 values (?1, 'prj_synthetic', 'synthetic-slug', '/synthetic/private-directory-marker', '2.0.27', 'build',
                         '{\"id\":\"synthetic-model\",\"providerID\":\"synthetic-provider\"}', ?2, ?2,
                         '{\"private\":\"session-metadata-marker\"}', '[]')",
                rusqlite::params![id, T0],
            )
            .unwrap();
    }

    pub(super) fn message(&self, id: &str, seq: i64, updated: i64, data: Value) {
        self.message_in("ses_synthetic", id, seq, updated, data);
    }

    pub(super) fn message_in(
        &self,
        session: &str,
        id: &str,
        seq: i64,
        updated: i64,
        mut data: Value,
    ) {
        let kind = data
            .as_object_mut()
            .unwrap()
            .remove("type")
            .and_then(|kind| kind.as_str().map(ToOwned::to_owned))
            .unwrap();
        let created = data["time"]["created"].as_i64().unwrap_or(updated);
        self.connection
            .execute(
                "insert into session_message (id, session_id, type, seq, time_created, time_updated, data) values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![id, session, kind, seq, created, updated, data.to_string()],
            )
            .unwrap();
    }

    /// An in-place lifecycle update: OpenCode rewrites `data` and refreshes
    /// `time_updated`, but never changes `seq`.
    pub(super) fn update(&self, id: &str, updated: i64, mut data: Value) {
        data.as_object_mut().unwrap().remove("type");
        self.connection
            .execute(
                "update session_message set time_updated = ?2, data = ?3 where id = ?1",
                rusqlite::params![id, updated, data.to_string()],
            )
            .unwrap();
    }

    pub(super) fn acquire(
        &self,
        read: OpenCodeSqliteReadOptions,
    ) -> Result<AcquisitionBatch, AcquisitionError> {
        acquire_opencode_sqlite(
            &self.source,
            AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
            read,
        )
    }

    fn acquire_default(&self) -> AcquisitionBatch {
        self.acquire(OpenCodeSqliteReadOptions::default()).unwrap()
    }
}

fn source(path: std::path::PathBuf) -> Source {
    Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".to_owned(),
        path,
    }
}

pub(super) fn user(text: &str, created: i64) -> Value {
    json!({"type": "user", "text": text, "time": {"created": created}})
}

pub(super) fn assistant(content: Value, created: i64) -> Value {
    json!({
        "type": "assistant",
        "agent": "build",
        "model": {"id": "synthetic-model", "providerID": "synthetic-provider"},
        "content": content,
        "time": {"created": created}
    })
}

pub(super) fn completed_tool(
    id: &str,
    name: &str,
    input: Value,
    output: &str,
    created: i64,
) -> Value {
    json!({
        "type": "tool", "id": id, "name": name, "executed": false,
        "state": {"status": "completed", "input": input, "content": [{"type": "text", "text": output}]},
        "time": {"created": created, "ran": created + 1_000, "completed": created + 2_000}
    })
}

fn tool_entry(id: &str, executed: Option<bool>, state: Value, time: Value) -> Value {
    let mut entry = json!({"type": "tool", "id": id, "name": "bash", "state": state, "time": time});
    if let Some(executed) = executed {
        entry["executed"] = json!(executed);
    }
    entry
}

/// `(native id, child ordinal, stage)` in returned order.
fn shape(batch: &AcquisitionBatch) -> Vec<(String, u32, ObservationStage)> {
    batch
        .observations
        .iter()
        .map(|item| {
            (
                item.source().native_id().unwrap().to_owned(),
                item.identity_basis().child_ordinal(),
                item.stage(),
            )
        })
        .collect()
}

fn find<'a>(
    batch: &'a AcquisitionBatch,
    id: &str,
    child: u32,
    stage: ObservationStage,
) -> &'a CanonicalObservationV2 {
    batch
        .observations
        .iter()
        .find(|item| {
            item.source().native_id() == Some(id)
                && item.identity_basis().child_ordinal() == child
                && item.stage() == stage
        })
        .unwrap_or_else(|| panic!("missing {id}/{child}/{stage:?}"))
}

fn tool(observation: &CanonicalObservationV2) -> &ToolObservation {
    match observation.body() {
        ObservationBody::Tool(tool) => tool,
        _ => panic!("expected a tool observation"),
    }
}

fn message_text(observation: &CanonicalObservationV2) -> (MessageRole, String) {
    match observation.body() {
        ObservationBody::Message(message) => (
            message.role().unwrap(),
            match message.content() {
                Some(JsonValue::String(text)) => text.clone(),
                other => panic!("unexpected content {other:?}"),
            },
        ),
        _ => panic!("expected a message observation"),
    }
}

fn identities(batch: &AcquisitionBatch) -> BTreeMap<(String, u32, &'static str), String> {
    shape(batch)
        .into_iter()
        .zip(&batch.observations)
        .map(|((id, child, stage), item)| {
            (
                (id, child, stage.as_str()),
                item.observation_id().to_owned(),
            )
        })
        .collect()
}

fn mapping_code(error: AcquisitionError) -> &'static str {
    match error {
        AcquisitionError::CanonicalMapping { code } => code,
        other => panic!("expected canonical mapping failure, got {other:?}"),
    }
}

#[test]
fn fresh_v2_store_maps_messages_tools_and_accounting() {
    let store = Store::v2();
    store.message(
        "msg_001",
        1,
        T0 + 1,
        user("Synthetic request to list files", T0),
    );
    store.message(
        "msg_002",
        2,
        T0 + 30_000,
        assistant(
            json!([
                {"type": "text", "text": "Listing the synthetic workspace."},
                {"type": "reasoning", "text": "synthetic-reasoning-marker"},
                completed_tool("call_ls", "bash", json!({"command": "ls -la"}), "synthetic listing", T0 + 5_000),
            ]),
            T0 + 2_000,
        ),
    );

    let batch = store.acquire_default();
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0 + 30_000)
        }
    );
    use ObservationStage::*;
    assert_eq!(
        shape(&batch),
        vec![
            ("msg_001".to_owned(), 0, MessageObserved),
            ("msg_002".to_owned(), 0, MessageObserved),
            ("msg_002".to_owned(), 2, ToolRequested),
            ("msg_002".to_owned(), 2, ToolResultReturned),
        ],
        "reasoning is skipped and keeps its content index out of other identities"
    );
    let prompt = find(&batch, "msg_001", 0, MessageObserved);
    assert_eq!(
        message_text(prompt),
        (MessageRole::User, "Synthetic request to list files".into())
    );
    assert_eq!(
        prompt.occurred_at().unwrap().as_str(),
        "2026-03-31T23:33:20Z"
    );
    assert_eq!(
        message_text(find(&batch, "msg_002", 0, MessageObserved)),
        (
            MessageRole::Assistant,
            "Listing the synthetic workspace.".into()
        )
    );

    let request = find(&batch, "msg_002", 2, ToolRequested);
    assert_eq!(tool(request).name(), Some("bash"));
    assert_eq!(
        tool(request).arguments(),
        Some(&JsonValue::object([(String::from("command"), JsonValue::string("ls -la"))]).unwrap())
    );
    assert_eq!(tool(request).result(), None);
    assert_eq!(
        request.occurred_at().unwrap().as_str(),
        "2026-03-31T23:33:25Z"
    );
    let outcome = find(&batch, "msg_002", 2, ToolResultReturned);
    assert_eq!(
        tool(outcome).result(),
        Some(&JsonValue::string("synthetic listing"))
    );
    assert_eq!(tool(outcome).reported_status(), None);
    assert_eq!(tool(outcome).exit_code(), None);
    assert_eq!(
        outcome.occurred_at().unwrap().as_str(),
        "2026-03-31T23:33:27Z"
    );
    for item in [request, outcome] {
        assert_eq!(item.correlation().call_id().unwrap().value(), "call_ls");
        assert_eq!(
            item.facets()["command.text"].value(),
            &JsonValue::string("ls -la")
        );
        assert_eq!(
            item.facets()["tool.executed"].value(),
            &JsonValue::Bool(false)
        );
        assert_eq!(
            item.fact_metadata()["tool.executed"].provenance(),
            FactProvenance::Reported
        );
    }
    assert_ne!(request.observation_id(), outcome.observation_id());

    for item in &batch.observations {
        assert_eq!(item.session_id().unwrap().value(), "ses_synthetic");
        assert_eq!(item.source().adapter_type(), "opencode");
        assert_eq!(item.source().adapter_id(), "opencode.sqlite");
        assert_eq!(item.source().source_path_hash(), None);
        assert_eq!(item.observed_at().as_str(), OBSERVED_AT);
        let capabilities = item.capability_context().unwrap();
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolCall),
            CapabilityAvailability::Supported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Unknown
        );
        if let ObservationBody::Message(message) = item.body() {
            assert_ne!(
                message.content(),
                Some(&JsonValue::string("synthetic-reasoning-marker"))
            );
        }
    }

    assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
    assert_eq!(batch.accounting.sessions.len(), 1);
    let session = &batch.accounting.sessions[0];
    assert_eq!(session.session_id.value(), "ses_synthetic");
    assert_eq!(session.counts.native_units, 2);
    let counts = session.counts.record_counts;
    assert_eq!(
        (
            counts.user_message,
            counts.assistant_message,
            counts.tool_call,
            counts.tool_result
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(session.counts.tool_usage["bash"].count, 1);
    assert_eq!(session.metadata.agent.known(), Some("build"));
    assert_eq!(session.metadata.model.known(), Some("synthetic-model"));
    assert_eq!(
        session.metadata.provider.known(),
        Some("synthetic-provider")
    );
}

#[test]
fn tool_lifecycle_separates_requests_outcomes_and_reported_execution() {
    let store = Store::v2();
    let created = json!({"created": T0});
    let called = json!({"created": T0, "ran": T0 + 1_000});
    let finished = json!({"created": T0, "ran": T0 + 1_000, "completed": T0 + 2_000});
    store.message(
        "msg_tools",
        1,
        T0 + 3_000,
        assistant(
            json!([
                tool_entry("call_stream", None, json!({"status": "streaming", "input": "{\"command\":\"ec"}), created.clone()),
                tool_entry("call_local", Some(false), json!({"status": "running", "input": {"command": "sleep 1"}, "metadata": {}}), called.clone()),
                tool_entry("call_provider", Some(true), json!({"status": "running", "input": {"command": "provider run"}, "metadata": {}}), called),
                tool_entry("call_done", Some(true), json!({"status": "completed", "input": {"command": "provider done"}, "content": [{"type": "text", "text": "a"}, {"type": "file", "uri": "file:///synthetic", "mime": "text/plain"}]}), finished.clone()),
                tool_entry("call_denied", Some(false), json!({"status": "error", "input": {"command": "rm -rf synthetic"}, "error": {"type": "aborted", "message": "The user declined this tool call"}}), finished),
                tool_entry("call_bad_json", Some(false), json!({"status": "error", "input": {}, "error": {"type": "tool.input-json", "message": "Tool call arguments were malformed JSON and were not executed."}}), json!({"created": T0, "completed": T0 + 2_000})),
            ]),
            T0,
        ),
    );
    let batch = store.acquire_default();
    use ObservationStage::*;
    let id = "msg_tools".to_owned();
    assert_eq!(
        shape(&batch),
        vec![
            (id.clone(), 0, ToolRequested),
            (id.clone(), 1, ToolRequested),
            (id.clone(), 2, ToolRequested),
            (id.clone(), 2, ToolExecutionStarted),
            (id.clone(), 3, ToolRequested),
            (id.clone(), 3, ToolExecutionCompleted),
            (id.clone(), 3, ToolResultReturned),
            (id.clone(), 4, ToolRequested),
            (id.clone(), 4, ToolResultReturned),
            (id.clone(), 5, ToolRequested),
            (id, 5, ToolResultReturned),
        ],
        "only executed=true claims execution; running/streaming have no outcome"
    );
    assert_eq!(
        tool(find(&batch, "msg_tools", 0, ToolRequested)).arguments(),
        Some(&JsonValue::string("{\"command\":\"ec"))
    );
    assert!(
        !find(&batch, "msg_tools", 0, ToolRequested)
            .facets()
            .contains_key("tool.executed")
    );
    assert_eq!(
        find(&batch, "msg_tools", 2, ToolExecutionStarted)
            .occurred_at()
            .unwrap()
            .as_str(),
        "2026-03-31T23:33:21Z"
    );
    let structured = tool(find(&batch, "msg_tools", 3, ToolResultReturned))
        .result()
        .unwrap();
    assert!(
        matches!(structured, JsonValue::Array(items) if items.len() == 2),
        "multi-part content stays structured"
    );
    for (child, executed) in [(1, false), (2, true), (3, true), (4, false), (5, false)] {
        assert_eq!(
            find(&batch, "msg_tools", child, ToolRequested).facets()["tool.executed"].value(),
            &JsonValue::Bool(executed)
        );
    }
    for child in [4, 5] {
        let failed = tool(find(&batch, "msg_tools", child, ToolResultReturned));
        assert_eq!(failed.reported_status(), Some(ToolStatus::Failed));
        assert!(matches!(failed.result(), Some(JsonValue::Object(_))));
        assert_eq!(
            tool(find(&batch, "msg_tools", child, ToolRequested)).reported_status(),
            None
        );
    }
    for item in &batch.observations {
        assert_eq!(item.kind(), ObservationFamily::Tool);
        assert_ne!(tool(item).reported_status(), Some(ToolStatus::Succeeded));
        assert_eq!(tool(item).exit_code(), None);
        assert_eq!(tool(item).is_error(), None);
    }
    let counts = batch.accounting.sessions[0].counts.record_counts;
    assert_eq!((counts.tool_call, counts.tool_result), (6, 3));
}

/// OpenCode's `shell` tool writes `{status, truncated, exit?, signal?,
/// timeout?, shellID?}` into its completed state only after the command has
/// been authorized, run and settled (`packages/core/src/tool/plugin/shell.ts`
/// and `packages/core/src/shell/result.ts` at the pinned revision).
#[test]
fn shell_tool_result_metadata_reports_completion_without_inferring_success() {
    let shell_tool = |id: &str, executed: bool, state: Value, time: Value| {
        let mut entry = tool_entry(id, Some(executed), state, time);
        entry["name"] = json!("shell");
        entry
    };
    let completed = |metadata: Value| {
        json!({"status": "completed", "input": {"command": "make test"},
               "content": [{"type": "text", "text": "synthetic output"}], "metadata": metadata})
    };
    let called = json!({"created": T0, "ran": T0 + 1_000});
    let finished = json!({"created": T0, "ran": T0 + 1_000, "completed": T0 + 2_000});
    let entries = json!([
        shell_tool(
            "call_exit0",
            false,
            completed(json!({"status": "completed", "truncated": false, "exit": 0})),
            finished.clone()
        ),
        shell_tool(
            "call_exit2",
            false,
            completed(json!({"status": "completed", "truncated": false, "exit": 2})),
            finished.clone()
        ),
        shell_tool(
            "call_timeout",
            false,
            completed(json!({"status": "completed", "truncated": false, "timeout": true})),
            finished.clone()
        ),
        shell_tool(
            "call_signal",
            false,
            completed(json!({"status": "completed", "truncated": true, "signal": "SIGKILL"})),
            finished.clone()
        ),
        // Background command: returned before the process settled.
        shell_tool(
            "call_background",
            false,
            completed(json!({"status": "running", "truncated": false, "shellID": "shl_bg"})),
            finished.clone()
        ),
        // Missing and malformed metadata make no execution claim.
        shell_tool(
            "call_no_metadata",
            false,
            json!({"status": "completed", "input": {"command": "make"}, "content": [{"type": "text", "text": "x"}]}),
            finished.clone()
        ),
        shell_tool(
            "call_string_exit",
            false,
            completed(json!({"status": "completed", "truncated": false, "exit": "0"})),
            finished.clone()
        ),
        shell_tool(
            "call_fraction_exit",
            false,
            completed(json!({"status": "completed", "truncated": false, "exit": 1.5})),
            finished.clone()
        ),
        shell_tool(
            "call_bad_signal",
            false,
            completed(json!({"status": "completed", "truncated": false, "signal": 9})),
            finished.clone()
        ),
        shell_tool(
            "call_no_status",
            false,
            completed(json!({"truncated": false, "exit": 0})),
            finished.clone()
        ),
        shell_tool(
            "call_not_object",
            false,
            completed(json!("exit 0")),
            finished.clone()
        ),
        // Error and running entries never claim execution, whatever metadata says.
        shell_tool(
            "call_error",
            false,
            json!({"status": "error", "input": {"command": "make"},
            "error": {"type": "aborted", "message": "synthetic"},
            "metadata": {"status": "completed", "truncated": false, "exit": 1, "shellID": "shl_err"}}),
            finished.clone()
        ),
        shell_tool(
            "call_running",
            false,
            json!({"status": "running", "input": {"command": "make"},
            "metadata": {"shellID": "shl_run", "status": "completed", "exit": 0}}),
            called
        ),
        // Only the `shell` tool's metadata is interpreted.
        tool_entry(
            "call_other_tool",
            Some(false),
            completed(json!({"status": "completed", "truncated": false, "exit": 0})),
            finished.clone()
        ),
        // A provider-executed entry with metadata is completed once.
        shell_tool(
            "call_provider",
            true,
            completed(json!({"status": "completed", "truncated": false, "exit": 0})),
            finished
        ),
    ]);
    let store = Store::v2();
    store.message(
        "msg_shell_tools",
        1,
        T0 + 3_000,
        assistant(entries.clone(), T0),
    );
    let batch = store.acquire_default();
    use ObservationStage::*;
    let stages = |child: u32| {
        shape(&batch)
            .into_iter()
            .filter(|(_, ordinal, _)| *ordinal == child)
            .map(|(_, _, stage)| stage)
            .collect::<Vec<_>>()
    };
    let claimed = vec![ToolRequested, ToolExecutionCompleted, ToolResultReturned];
    let unclaimed = vec![ToolRequested, ToolResultReturned];
    for child in [0, 1, 2, 3, 14] {
        assert_eq!(stages(child), claimed, "child {child} reports completion");
    }
    for child in [4, 5, 6, 7, 8, 9, 10, 11, 13] {
        assert_eq!(stages(child), unclaimed, "child {child} makes no claim");
    }
    assert_eq!(stages(12), vec![ToolRequested], "running has no outcome");

    for stage in [ToolExecutionCompleted, ToolResultReturned] {
        let exit0 = find(&batch, "msg_shell_tools", 0, stage);
        assert_eq!(tool(exit0).exit_code(), Some(0));
        assert_eq!(
            tool(exit0).reported_status(),
            None,
            "exit 0 is not Succeeded"
        );
        assert_eq!(
            exit0.fact_metadata()["tool.exit_code"].provenance(),
            FactProvenance::Reported
        );
        let exit2 = tool(find(&batch, "msg_shell_tools", 1, stage));
        assert_eq!(exit2.exit_code(), Some(2));
        assert_eq!(exit2.reported_status(), None, "an exit code is not Failed");
        let timeout = find(&batch, "msg_shell_tools", 2, stage);
        assert_eq!(tool(timeout).exit_code(), None);
        assert_eq!(tool(timeout).reported_status(), Some(ToolStatus::Failed));
        assert_eq!(
            timeout.fact_metadata()["tool.reported_status"].provenance(),
            FactProvenance::Reported
        );
        let signal = find(&batch, "msg_shell_tools", 3, stage);
        assert_eq!(tool(signal).exit_code(), None);
        assert_eq!(tool(signal).reported_status(), None);
        assert_eq!(
            signal.facets()["tool.signal"].value(),
            &JsonValue::string("SIGKILL")
        );
        assert_eq!(
            signal.fact_metadata()["tool.signal"].provenance(),
            FactProvenance::Reported
        );
    }
    assert_eq!(
        find(&batch, "msg_shell_tools", 0, ToolExecutionCompleted)
            .occurred_at()
            .unwrap()
            .as_str(),
        "2026-03-31T23:33:22Z"
    );
    for item in &batch.observations {
        let body = tool(item);
        assert_ne!(body.reported_status(), Some(ToolStatus::Succeeded));
        assert_eq!(
            item.capability_context()
                .unwrap()
                .resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Unknown
        );
        if item.stage() == ToolRequested {
            assert_eq!(body.exit_code(), None);
            assert!(!item.facets().contains_key("tool.signal"));
        }
        let child = item.identity_basis().child_ordinal();
        if ![0, 1, 2, 3, 14].contains(&child) {
            assert_eq!(body.exit_code(), None, "child {child}");
            assert!(!item.facets().contains_key("tool.signal"), "child {child}");
        }
    }

    // The new stage adds an observation; it never moves an existing identity.
    let mut stripped = entries;
    for entry in stripped.as_array_mut().unwrap() {
        entry["state"].as_object_mut().unwrap().remove("metadata");
    }
    let plain = Store::v2();
    plain.message("msg_shell_tools", 1, T0 + 3_000, assistant(stripped, T0));
    let plain_ids = identities(&plain.acquire_default());
    let ids = identities(&batch);
    for (key, id) in &plain_ids {
        assert_eq!(ids.get(key), Some(id), "{key:?}");
    }
    assert_eq!(ids.len(), plain_ids.len() + 4);
}

#[test]
fn shell_metadata_does_not_override_provider_execution_evidence() {
    let store = Store::v2();
    let mut running = tool_entry(
        "call_provider_running",
        Some(true),
        json!({"status": "running", "input": {}, "metadata": "unrecognized"}),
        json!({"created": T0, "ran": T0 + 1_000}),
    );
    running["name"] = json!("shell");
    let mut error = tool_entry(
        "call_provider_error",
        Some(true),
        json!({"status": "error", "input": {},
            "error": {"type": "tool.execution", "message": "synthetic"},
            "metadata": {"status": "completed", "exit": 3}}),
        json!({"created": T0, "ran": T0 + 1_000, "completed": T0 + 2_000}),
    );
    error["name"] = json!("shell");
    store.message(
        "msg_provider",
        1,
        T0 + 3_000,
        assistant(json!([running, error]), T0),
    );
    let batch = store.acquire_default();
    use ObservationStage::*;
    let stages = shape(&batch)
        .into_iter()
        .map(|(_, child, stage)| (child, stage))
        .collect::<Vec<_>>();
    assert_eq!(
        stages,
        vec![
            (0, ToolRequested),
            (0, ToolExecutionStarted),
            (1, ToolRequested),
            (1, ToolExecutionCompleted),
            (1, ToolResultReturned)
        ]
    );
    for observation in &batch.observations {
        assert_eq!(tool(observation).exit_code(), None);
        assert!(!observation.facets().contains_key("tool.signal"));
    }
}

#[test]
fn content_children_keep_identity_across_updates_relocation_and_rowids() {
    let store = Store::v2();
    let draft = assistant(
        json!([
            {"type": "text", "text": "draft"},
            tool_entry("call_a", None, json!({"status": "streaming", "input": ""}), json!({"created": T0})),
            tool_entry("call_b", Some(false), json!({"status": "running", "input": {"command": "make"}, "metadata": {}}), json!({"created": T0, "ran": T0 + 1})),
        ]),
        T0,
    );
    let settled = assistant(
        json!([
            {"type": "text", "text": "final answer"},
            tool_entry("call_a", Some(false), json!({"status": "completed", "input": {"command": "true"}, "content": [{"type": "text", "text": "ok"}]}), json!({"created": T0, "ran": T0 + 1, "completed": T0 + 2})),
            tool_entry("call_b", Some(false), json!({"status": "error", "input": {"command": "make"}, "error": {"type": "aborted", "message": "Tool execution interrupted"}}), json!({"created": T0, "ran": T0 + 1, "completed": T0 + 3})),
        ]),
        T0,
    );
    store.message("msg_live", 7, T0 + 10, draft);
    let first = store.acquire_default();
    let first_ids = identities(&first);
    assert_eq!(first_ids.len(), 3);

    store.update("msg_live", T0 + 20, settled.clone());
    let second = store.acquire_default();
    let second_ids = identities(&second);
    for (key, id) in &first_ids {
        assert_eq!(
            second_ids.get(key),
            Some(id),
            "lifecycle update kept {key:?}"
        );
    }
    assert_eq!(second_ids.len(), 5);
    let text = |batch| find(batch, "msg_live", 0, ObservationStage::MessageObserved);
    assert_eq!(
        text(&first)
            .semantic_comparison()
            .compare(text(&second).semantic_comparison()),
        SemanticReplayVerdict::Mutated
    );

    // Relocation: an exact copy at another path.
    let copy = store.directory.path().join("relocated.db");
    store
        .connection
        .execute("vacuum into ?1", [copy.to_str().unwrap()])
        .unwrap();
    let relocated = acquire_opencode_sqlite(
        &source(copy),
        AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        OpenCodeSqliteReadOptions::default(),
    )
    .unwrap();
    assert_eq!(identities(&relocated), second_ids);

    // Different rowids and an unrelated earlier message.
    let shifted = Store::v2();
    shifted.message("msg_other", 1, T0, user("unrelated", T0));
    shifted.message("msg_live", 7, T0 + 99, settled);
    shifted
        .connection
        .execute("delete from session_message where id = 'msg_other'", [])
        .unwrap();
    let shifted = shifted.acquire_default();
    assert_eq!(identities(&shifted), second_ids);
}

#[test]
fn user_shell_messages_map_reported_execution_without_os_observations() {
    let store = Store::v2();
    for (id, seq, data) in [
        (
            "msg_sh_run",
            1,
            json!({"type": "shell", "shellID": "sh_run", "command": "curl https://example.invalid/synthetic", "status": "running", "time": {"created": T0}}),
        ),
        (
            "msg_sh_exit",
            2,
            json!({"type": "shell", "shellID": "sh_exit", "command": "echo ok", "status": "exited", "exit": 0,
            "output": {"output": "ok\n", "cursor": 3, "size": 3, "truncated": false}, "time": {"created": T0, "completed": T0 + 1_000}}),
        ),
        (
            "msg_sh_kill",
            3,
            json!({"type": "shell", "shellID": "sh_kill", "command": "sleep 99", "status": "killed", "time": {"created": T0, "completed": T0 + 1_000}}),
        ),
        (
            "msg_sh_slow",
            4,
            json!({"type": "shell", "shellID": "sh_slow", "command": "sleep 999", "status": "timeout", "exit": 124, "time": {"created": T0, "completed": T0 + 1_000}}),
        ),
    ] {
        store.message(id, seq, T0 + seq, data);
    }
    let batch = store.acquire_default();
    use ObservationStage::*;
    let expected: Vec<(String, u32, ObservationStage)> = [
        ("msg_sh_run", ToolExecutionStarted),
        ("msg_sh_exit", ToolExecutionStarted),
        ("msg_sh_exit", ToolExecutionCompleted),
        ("msg_sh_exit", ToolResultReturned),
        ("msg_sh_kill", ToolExecutionStarted),
        ("msg_sh_kill", ToolExecutionCompleted),
        ("msg_sh_slow", ToolExecutionStarted),
        ("msg_sh_slow", ToolExecutionCompleted),
    ]
    .into_iter()
    .map(|(id, stage)| (id.to_owned(), 0, stage))
    .collect();
    assert_eq!(shape(&batch), expected);
    let exited = tool(find(&batch, "msg_sh_exit", 0, ToolExecutionCompleted));
    assert_eq!(exited.exit_code(), Some(0));
    assert_eq!(
        exited.reported_status(),
        None,
        "exit 0 is not inferred success"
    );
    assert_eq!(exited.result(), Some(&JsonValue::string("ok\n")));
    assert_eq!(
        tool(find(&batch, "msg_sh_kill", 0, ToolExecutionCompleted)).reported_status(),
        Some(ToolStatus::Cancelled)
    );
    assert_eq!(
        tool(find(&batch, "msg_sh_kill", 0, ToolExecutionCompleted)).exit_code(),
        None
    );
    assert_eq!(
        tool(find(&batch, "msg_sh_slow", 0, ToolExecutionCompleted)).reported_status(),
        Some(ToolStatus::Failed)
    );
    let started = find(&batch, "msg_sh_run", 0, ToolExecutionStarted);
    assert_eq!(tool(started).name(), Some("shell"));
    assert_eq!(
        started.fact_metadata()["tool.name"].provenance(),
        FactProvenance::Parsed
    );
    assert_eq!(
        tool(started).arguments(),
        Some(&JsonValue::string("curl https://example.invalid/synthetic"))
    );
    assert_eq!(
        started.facets()["command.text"].value(),
        &JsonValue::string("curl https://example.invalid/synthetic")
    );
    assert_eq!(tool(started).exit_code(), None);
    assert_eq!(started.correlation().call_id().unwrap().value(), "sh_run");
    for item in &batch.observations {
        assert_eq!(item.kind(), ObservationFamily::Tool);
        assert_eq!(
            item.capability_context()
                .unwrap()
                .resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Supported
        );
    }
    let counts = batch.accounting.sessions[0].counts.record_counts;
    assert_eq!((counts.tool_call, counts.tool_result), (4, 3));
    assert_eq!(
        batch.accounting.sessions[0].counts.tool_usage["shell"].count,
        4
    );
}

#[test]
fn recognized_auxiliary_messages_are_accounted_without_observations() {
    let store = Store::v2();
    let time = json!({"created": T0});
    for (seq, data) in [
        json!({"type": "agent-switched", "agent": "plan", "previous": "build", "time": time}),
        json!({"type": "model-switched", "model": {"id": "other-model", "providerID": "synthetic-provider"}, "time": time}),
        json!({"type": "location-switched", "location": {"type": "local"}, "time": time}),
        json!({"type": "synthetic", "text": "synthetic-injected-marker", "time": time}),
        json!({"type": "system", "text": "synthetic-system-marker", "time": time}),
        json!({"type": "skill", "skill": "sk_1", "name": "synthetic", "text": "synthetic-skill-marker", "time": time}),
        json!({"type": "compaction", "status": "completed", "reason": "auto", "summary": "s", "recent": "r", "time": time}),
        json!({"type": "idle", "outcome": "succeeded", "time": time}),
        json!({"type": "assistant", "agent": "build", "model": {"id": "synthetic-model", "providerID": "synthetic-provider"},
            "content": [{"type": "reasoning", "text": "synthetic-reasoning-marker"}], "error": {"type": "provider", "message": "synthetic"}, "time": time}),
    ]
    .into_iter()
    .enumerate()
    {
        store.message(&format!("msg_aux_{seq}"), seq as i64, T0 + seq as i64, data);
    }
    let batch = store.acquire_default();
    assert!(batch.observations.is_empty());
    let session = &batch.accounting.sessions[0];
    assert_eq!(session.counts.native_units, 9);
    let counts = session.counts.record_counts;
    assert_eq!(
        (counts.session_meta, counts.other, counts.assistant_message),
        (3, 5, 1)
    );
    assert_eq!(session.metadata.agent, AttestedValue::Ambiguous);
    assert_eq!(session.metadata.model, AttestedValue::Ambiguous);
    assert_eq!(
        session.metadata.provider.known(),
        Some("synthetic-provider")
    );
}

#[test]
fn malformed_unsupported_and_identity_less_rows_fail_without_leaking_payloads() {
    let secret = "synthetic-secret-marker";
    let unsupported: Vec<(&str, Value, &str)> = vec![
        (
            "future",
            json!({"type": "future-variant", "text": secret, "time": {"created": T0}}),
            "unknown_message_variant",
        ),
        (
            "content",
            assistant(json!([{"type": "future-content", "text": secret}]), T0),
            "unknown_content_variant",
        ),
        (
            "status",
            assistant(
                json!([tool_entry(
                    "call",
                    None,
                    json!({"status": "queued", "input": {"command": secret}}),
                    json!({"created": T0})
                )]),
                T0,
            ),
            "unknown_tool_status",
        ),
        (
            "state",
            assistant(
                json!([tool_entry(
                    "call",
                    None,
                    json!(secret),
                    json!({"created": T0})
                )]),
                T0,
            ),
            "invalid_tool_state",
        ),
        (
            "executed",
            assistant(
                json!([{"type": "tool", "id": "call", "name": "bash", "executed": "yes",
            "state": {"status": "running", "input": {"command": secret}, "metadata": {}}, "time": {"created": T0}}]),
                T0,
            ),
            "invalid_tool_state",
        ),
        (
            "empty_result",
            assistant(
                json!([tool_entry(
                    "call",
                    None,
                    json!({"status": "completed", "input": {}, "content": []}),
                    json!({"created": T0})
                )]),
                T0,
            ),
            "invalid_tool_state",
        ),
        (
            "no_tool_id",
            assistant(
                json!([{"type": "tool", "name": "bash", "state": {"status": "streaming", "input": secret}, "time": {"created": T0}}]),
                T0,
            ),
            "missing_tool_id",
        ),
        (
            "no_tool_name",
            assistant(
                json!([{"type": "tool", "id": "call", "state": {"status": "streaming", "input": secret}, "time": {"created": T0}}]),
                T0,
            ),
            "missing_tool_name",
        ),
        (
            "content_type",
            json!({"type": "assistant", "content": secret, "time": {"created": T0}}),
            "invalid_assistant_content",
        ),
        (
            "user_text",
            json!({"type": "user", "text": {"secret": secret}, "time": {"created": T0}}),
            "invalid_message_text",
        ),
        (
            "shell_status",
            json!({"type": "shell", "shellID": "sh", "command": secret, "status": "paused", "time": {"created": T0}}),
            "unknown_shell_status",
        ),
        (
            "shell_command",
            json!({"type": "shell", "shellID": "sh", "status": "running", "time": {"created": T0}}),
            "invalid_shell_state",
        ),
    ];
    for (name, data, code) in unsupported {
        let store = Store::v2();
        store.message("msg_bad", 1, T0, data);
        let error = store.acquire_default_error();
        assert_eq!(mapping_code(error), code, "{name}");
        assert!(!format!("{error} {error:?}").contains(secret), "{name}");
    }

    let store = Store::v2();
    store.message("", 1, T0, user(secret, T0));
    assert_eq!(
        mapping_code(store.acquire_default_error()),
        "replay_unverifiable"
    );

    for (name, statement) in [
        (
            "not json",
            "insert into session_message values ('m','ses_synthetic','user',1,1,1,'not json synthetic-secret-marker')",
        ),
        (
            "array data",
            "insert into session_message values ('m','ses_synthetic','user',1,1,1,'[\"synthetic-secret-marker\"]')",
        ),
        (
            "id in data",
            "insert into session_message values ('m','ses_synthetic','user',1,1,1,'{\"id\":\"other\",\"text\":\"synthetic-secret-marker\"}')",
        ),
        (
            "type in data",
            "insert into session_message values ('m','ses_synthetic','user',1,1,1,'{\"type\":\"user\",\"text\":\"synthetic-secret-marker\"}')",
        ),
        (
            "text seq",
            "insert into session_message values ('m','ses_synthetic','user','one',1,1,'{\"text\":\"synthetic-secret-marker\"}')",
        ),
        (
            "negative seq",
            "insert into session_message values ('m','ses_synthetic','user',-1,1,1,'{\"text\":\"synthetic-secret-marker\"}')",
        ),
        (
            "text time",
            "insert into session_message values ('m','ses_synthetic','user',1,1,'late','{\"text\":\"synthetic-secret-marker\"}')",
        ),
        (
            "null type",
            "insert into session_message values ('m','ses_synthetic',null,1,1,1,'{\"text\":\"synthetic-secret-marker\"}')",
        ),
    ] {
        let store = Store::new(&V2_SCHEMA.replace("NOT NULL", ""));
        store.session("ses_synthetic");
        store.connection.execute(statement, []).unwrap();
        let error = store.acquire_default_error();
        assert_eq!(error, AcquisitionError::SourceRead, "{name}");
        assert!(!format!("{error} {error:?}").contains(secret), "{name}");
    }

    let store = Store::new(&V2_SCHEMA.replace("NOT NULL", ""));
    store.session("ses_synthetic");
    store
        .connection
        .execute(
            "insert into session_message values ('m',null,'user',1,1,1,'{\"text\":\"t\"}')",
            [],
        )
        .unwrap();
    assert_eq!(
        mapping_code(store.acquire_default_error()),
        "missing_session_id"
    );

    let store = Store::new(&V2_SCHEMA.replace(
        "`id` text PRIMARY KEY, `session_id`",
        "`id` text, `session_id`",
    ));
    store.session("ses_synthetic");
    store.message("msg_dup", 1, T0, user("first", T0));
    store.message("msg_dup", 2, T0, user("second", T0));
    assert_eq!(
        mapping_code(store.acquire_default_error()),
        "ambiguous_source_identity"
    );
}

impl Store {
    fn acquire_default_error(&self) -> AcquisitionError {
        match self.acquire(OpenCodeSqliteReadOptions::default()) {
            Ok(_) => panic!("acquisition unexpectedly succeeded"),
            Err(error) => error,
        }
    }
}

#[test]
fn schema_selection_is_deterministic_and_never_falls_back_to_legacy() {
    let legacy_rows = |store: &Store| {
        store
            .connection
            .execute_batch(
                "insert into message values ('legacy-message','ses_legacy',1,1,'{\"role\":\"user\"}');
                 insert into part values ('legacy-part','legacy-message','ses_legacy',1,9999999999999,'{\"type\":\"text\",\"text\":\"stale legacy text\"}');",
            )
            .unwrap();
    };

    // Mixed store: v2 wins even when legacy rows look newer.
    let mixed = Store::new(&format!("{V2_SCHEMA}{LEGACY_SCHEMA}"));
    mixed.session("ses_synthetic");
    legacy_rows(&mixed);
    mixed.message("msg_v2", 1, T0, user("current v2 text", T0));
    let batch = mixed.acquire_default();
    assert_eq!(
        shape(&batch),
        vec![("msg_v2".to_owned(), 0, ObservationStage::MessageObserved)]
    );
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0)
        }
    );
    assert_eq!(batch.accounting.sessions.len(), 1);

    // An empty v2 schema beside legacy rows is still the v2 schema.
    let migrated = Store::new(&format!("{V2_SCHEMA}{LEGACY_SCHEMA}"));
    legacy_rows(&migrated);
    let batch = migrated.acquire_default();
    assert!(batch.observations.is_empty());
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: None
        }
    );

    // Legacy-only stores keep the legacy path and progress coordinate.
    let legacy = Store::new(LEGACY_SCHEMA);
    legacy_rows(&legacy);
    let batch = legacy.acquire_default();
    assert_eq!(batch.observations.len(), 1);
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSqlite {
            part_max_time_updated: Some(9_999_999_999_999)
        }
    );

    // Partial or column-incomplete v2 schemas fail, with or without legacy tables.
    for schema in [
        "create table session_message (id text, session_id text, type text, seq integer, time_updated integer, data text);".to_owned(),
        "create table session_v2 (id text, agent text, model text);".to_owned(),
        format!("create table session_message (id text, session_id text, type text, seq integer, time_updated integer, data text);{LEGACY_SCHEMA}"),
        "create table session_message (id text, session_id text, type text, time_updated integer, data text);
         create table session_v2 (id text, agent text, model text);".to_owned(),
        "create table session_message (id text, session_id text, type text, seq integer, time_updated integer, data text);
         create table session_v2 (id text, agent text);".to_owned(),
    ] {
        let store = Store::new(&schema);
        if schema.contains("create table part") {
            legacy_rows(&store);
        }
        let error = store.acquire_default_error();
        assert_eq!(error, AcquisitionError::UnsupportedSourceSchema, "{schema}");
        assert_eq!(error.code(), "unsupported_source_schema");
    }
}

#[test]
fn bootstrap_sampling_incremental_limits_and_regression() {
    let store = Store::v2();
    for seq in 1..=3 {
        store.message(&format!("msg_{seq}"), seq, T0 + seq, user("text", T0));
    }
    let sampled = store
        .acquire(OpenCodeSqliteReadOptions {
            message_limit: 2,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        shape(&sampled)
            .into_iter()
            .map(|(id, ..)| id)
            .collect::<Vec<_>>(),
        ["msg_2", "msg_3"]
    );
    assert_eq!(
        sampled.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0 + 3)
        }
    );
    let incremental = |limit| {
        store.acquire(OpenCodeSqliteReadOptions {
            message_min_time_updated: Some(T0 + 2),
            message_limit: limit,
            ..Default::default()
        })
    };
    assert_eq!(
        incremental(1).err(),
        Some(AcquisitionError::BoundedSourceRead(
            BoundedReadError::LimitExceeded
        ))
    );
    assert_eq!(incremental(2).unwrap().observations.len(), 2);

    let regressed = OpenCodeSqliteReadOptions::default().resume_session_messages_after(T0 + 4);
    assert_eq!(
        store.acquire(regressed).err(),
        Some(AcquisitionError::ResumeRegressed)
    );
    let at_high_water = OpenCodeSqliteReadOptions::default().resume_session_messages_after(T0 + 3);
    assert_eq!(store.acquire(at_high_water).unwrap().observations.len(), 3);

    // A legacy part watermark far beyond every v2 row neither regresses nor
    // skips v2 history: the v2 store reads its own bootstrap selection.
    let legacy_cursor = OpenCodeSqliteReadOptions::resume_after(T0 + 100 * HOUR);
    let batch = store.acquire(legacy_cursor).unwrap();
    assert_eq!(batch.observations.len(), 3);
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0 + 3)
        }
    );
    // And a v2 cursor does not apply to a legacy store.
    let legacy = Store::new(LEGACY_SCHEMA);
    assert!(
        legacy
            .acquire(OpenCodeSqliteReadOptions::default().resume_session_messages_after(T0))
            .unwrap()
            .observations
            .is_empty()
    );
}

#[test]
fn in_place_updates_are_reselected_by_update_coordinate_not_seq() {
    let store = Store::v2();
    store.message("msg_1", 1, T0, user("first", T0));
    store.message("msg_2", 2, T0 + HOUR, user("second", T0));
    store.message(
        "msg_3",
        3,
        T0 + 2 * HOUR,
        assistant(
            json!([tool_entry(
                "call",
                Some(false),
                json!({"status": "running", "input": {"command": "make"}, "metadata": {}}),
                json!({"created": T0})
            )]),
            T0,
        ),
    );
    let high_water = T0 + 2 * HOUR;
    let resume = OpenCodeSqliteReadOptions::default().resume_session_messages_after(high_water);
    let ids = |batch: AcquisitionBatch| {
        let mut ids = shape(&batch)
            .into_iter()
            .map(|(id, ..)| id)
            .collect::<Vec<_>>();
        ids.dedup();
        ids
    };
    assert_eq!(ids(store.acquire(resume).unwrap()), ["msg_3"]);

    // msg_1 keeps seq 1, below every seq already read, but its in-place update
    // moves its update coordinate past the cursor.
    store.update("msg_1", T0 + 3 * HOUR, user("first, edited", T0));
    // msg_3 completes inside the overlap window with the same timestamp tie.
    store.update(
        "msg_3",
        high_water,
        assistant(
            json!([tool_entry("call", Some(false), json!({"status": "completed", "input": {"command": "make"}, "content": [{"type": "text", "text": "built"}]}), json!({"created": T0, "ran": T0, "completed": T0}))]),
            T0,
        ),
    );
    let batch = store.acquire(resume).unwrap();
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0 + 3 * HOUR)
        }
    );
    assert!(
        batch
            .observations
            .iter()
            .any(|item| item.stage() == ObservationStage::ToolResultReturned)
    );
    assert_eq!(
        ids(batch),
        ["msg_1", "msg_3"],
        "source order is session seq order"
    );
}

#[test]
fn equal_timestamps_cross_pages_and_late_failures_reject_the_source() {
    let store = Store::v2();
    for seq in 1..=5 {
        store.message(&format!("msg_{seq}"), seq, T0, user("tie", T0));
    }
    let read = |limit, page| {
        extract_incremental_messages(
            &store.connection,
            T0,
            limit,
            page,
            &mut SqliteAdmission::default(),
        )
    };
    for page in [1, 2, 5, 6] {
        let (records, high_water) = read(5, page).unwrap();
        assert_eq!(high_water, Some(T0));
        assert_eq!(
            records.iter().map(|record| record.seq).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5],
            "page {page}"
        );
        assert!(matches!(
            read(4, page),
            Err(SourceReadError::Bounded(BoundedReadError::LimitExceeded))
        ));
    }

    store
        .connection
        .execute(
            "insert into session_message values ('msg_late','ses_synthetic','user',6,1,?1,'not json')",
            [T0 + 1],
        )
        .unwrap();
    assert!(read(10, 2).is_err());
    store
        .connection
        .execute("update session_message set data = '{\"text\":\"t\"}', time_updated = 'late' where id = 'msg_late'", [])
        .unwrap();
    assert!(read(10, 2).is_err());
    assert!(store.acquire(OpenCodeSqliteReadOptions::default()).is_err());
}

#[test]
fn read_snapshot_pins_every_page_including_committed_wal_contents() {
    let store = Store::v2();
    store
        .connection
        .execute_batch("pragma journal_mode=WAL; pragma wal_autocheckpoint=0;")
        .unwrap();
    for seq in 1..=3 {
        store.message(&format!("msg_{seq}"), seq, T0, user("committed in wal", T0));
    }
    assert!(store.source.path.with_extension("db-wal").is_file());

    let mut reader =
        Connection::open_with_flags(&store.source.path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let snapshot = reader.transaction().unwrap();
    let writer = Connection::open(&store.source.path).unwrap();
    let _guard = on_next_incremental_page(move || {
        writer
            .execute(
                "insert into session_message values ('msg_4','ses_synthetic','user',4,1,?1,'not json')",
                [T0],
            )
            .unwrap();
        writer
            .execute(
                "update session_message set data = 'not json' where id = 'msg_3'",
                [],
            )
            .unwrap();
    });
    let (records, _) =
        extract_incremental_messages(&snapshot, T0, 10, 1, &mut SqliteAdmission::default())
            .unwrap();
    assert_eq!(records.len(), 3, "later pages read the pinned snapshot");
    snapshot.commit().unwrap();
    assert_eq!(
        store.acquire(OpenCodeSqliteReadOptions::default()).err(),
        Some(AcquisitionError::SourceRead),
        "the next extraction sees the committed writer change"
    );
}

#[test]
fn admission_caps_and_canonical_budgets_reject_atomically() {
    // Unselected session columns and other tables are never admitted.
    let store = Store::v2();
    store
        .connection
        .execute_batch(
            "update session_v2 set metadata = cast(zeroblob(8388609) as text), directory = cast(zeroblob(8388609) as text);
             insert into credential values ('cred','i','label',cast(zeroblob(8388609) as text),null,null,1,1,1);",
        )
        .unwrap();
    store.message("msg_ok", 1, T0, user("fits", T0));
    assert_eq!(store.acquire_default().observations.len(), 1);

    // Joined session context is charged on every selected occurrence.
    store
        .connection
        .execute(
            "update session_v2 set agent = cast(zeroblob(8388609) as text)",
            [],
        )
        .unwrap();
    assert_eq!(store.acquire_default_error(), AcquisitionError::SourceRead);

    let store = Store::v2();
    for seq in 1..=3 {
        store.message(&format!("msg_{seq}"), seq, T0, user("row", T0));
    }
    let mut rows = SqliteAdmission::with_limits(usize::MAX, 2);
    assert!(extract_incremental_messages(&store.connection, T0, 10, 2, &mut rows).is_err());
    let mut exact = SqliteAdmission::with_limits(usize::MAX, 3);
    assert!(extract_incremental_messages(&store.connection, T0, 10, 2, &mut exact).is_ok());

    // A sole text result uses the direct-text budget; structured multi-part
    // results keep ordinary nested string bounds.
    let long = "x".repeat(60_000);
    let store = Store::v2();
    store.message(
        "msg_long",
        1,
        T0,
        assistant(
            json!([completed_tool(
                "call",
                "bash",
                json!({"command": "cat"}),
                &long,
                T0
            )]),
            T0,
        ),
    );
    assert_eq!(store.acquire_default().observations.len(), 2);
    let store = Store::v2();
    store.message(
        "msg_parts",
        1,
        T0,
        assistant(
            json!([tool_entry(
                "call",
                Some(false),
                json!({"status": "completed", "input": {}, "content": [
                {"type": "text", "text": "y".repeat(5_000)}, {"type": "text", "text": "z"}]}),
                json!({"created": T0})
            )]),
            T0,
        ),
    );
    assert!(matches!(
        store.acquire_default_error(),
        AcquisitionError::CanonicalBoundValidation { .. }
    ));
    let store = Store::v2();
    store.message(
        "msg_huge",
        1,
        T0,
        assistant(
            json!([completed_tool(
                "call",
                "bash",
                json!({"command": "cat"}),
                &"x".repeat(65_537),
                T0
            )]),
            T0,
        ),
    );
    assert!(matches!(
        store.acquire_default_error(),
        AcquisitionError::CanonicalBoundValidation { .. }
    ));
}

#[test]
fn repeated_acquisition_is_deterministic_in_session_seq_order() {
    let store = Store::v2();
    store.session("ses_other");
    store.message("msg_b", 2, T0 + 10, user("second by seq", T0));
    store.message("msg_a", 1, T0 + 50, user("first by seq", T0));
    store.message_in("ses_other", "msg_c", 1, T0 + 5, user("other session", T0));
    let first = store.acquire_default();
    let second = store.acquire_default();
    assert_eq!(
        first
            .observations
            .iter()
            .map(|item| item.source().native_id().unwrap())
            .collect::<Vec<_>>(),
        ["msg_c", "msg_a", "msg_b"]
    );
    assert_eq!(identities(&first), identities(&second));
    assert_eq!(
        first
            .observations
            .iter()
            .map(|item| item.sequence())
            .collect::<Vec<_>>(),
        [Some(1), Some(1), Some(2)]
    );
}

/// Activity contributions come from what the agent requested (tool input and
/// the user shell command). Tool results, errors
/// and shell output are returned data: a long encoded token there (within the
/// 65,536-byte direct-text budget) must not reject the source, and paths or
/// hosts there are not the agent's activity.
#[test]
fn contributions_count_requests_not_returned_payloads() {
    use telltale_schema::activity_facts::PathClass;

    // Base64 contains '/' and has no whitespace: one long token.
    let encoded = format!("iVBORw0KGgo/{}", "QUJD/".repeat(1_000));
    let store = Store::v2();
    store.message(
        "msg_tools",
        1,
        T0 + 3_000,
        assistant(
            json!([
                completed_tool("call_fetch", "bash",
                    json!({"command": "curl https://requested.example.test/x ~/.ssh/config"}),
                    &format!("see https://returned.example.test/ {encoded}"), T0),
                {"type": "tool", "id": "call_read", "name": "read", "executed": false,
                 "state": {"status": "completed", "input": {"filePath": "./synthetic.png"},
                           "content": [{"type": "file", "uri": "https://file.example.test/a.png",
                                        "mime": "image/png"}]},
                 "time": {"created": T0, "ran": T0 + 1, "completed": T0 + 2}},
                {"type": "tool", "id": "call_fail", "name": "bash", "executed": false,
                 "state": {"status": "error", "input": {"command": "false"},
                           "error": {"type": "tool.execution", "message": "https://error.example.test/"}},
                 "time": {"created": T0, "ran": T0 + 1, "completed": T0 + 2}},
            ]),
            T0,
        ),
    );
    store.message(
        "msg_shell",
        2,
        T0 + 4_000,
        json!({"type": "shell", "shellID": "sh_1", "command": "cat synthetic.b64",
               "status": "exited", "exit": 0,
               "output": {"output": encoded, "cursor": 1, "size": 1, "truncated": false},
               "time": {"created": T0, "completed": T0 + 1}}),
    );
    let batch = store.acquire_default();
    let contributions = &batch.accounting.sessions[0].counts.contributions;
    assert_eq!(
        contributions.network_hosts.keys().collect::<Vec<_>>(),
        vec!["requested.example.test"]
    );
    assert_eq!(
        contributions.path_classes.get(&PathClass::SecretStore),
        Some(&1)
    );
    assert_eq!(contributions.tool_calls.get("bash"), Some(&2));
    assert_eq!(contributions.tool_calls.get("read"), Some(&1));
    assert_eq!(contributions.tool_calls.get("shell"), Some(&1));

    // The fail-closed bound still applies to request input.
    let rejected = Store::v2();
    rejected.message(
        "msg_tools",
        1,
        T0 + 3_000,
        assistant(
            json!([completed_tool(
                "call_write",
                "write",
                json!({"filePath": "./out.b64", "content": encoded}),
                "ok",
                T0
            )]),
            T0,
        ),
    );
    assert_eq!(
        rejected.acquire_default_error(),
        AcquisitionError::InvalidContribution
    );
}
