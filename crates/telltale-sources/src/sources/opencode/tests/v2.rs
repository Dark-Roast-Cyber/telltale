//! OpenCode v2 (`session_v2`/`session_message`) acquisition through the public
//! acquisition seam. Every store is synthetic and owned by these tests; the DDL
//! mirrors OpenCode v2.0.27 (`packages/core/src/database/schema.gen.ts` at
//! 1f4d07a4a519185955ae8ab2ea3607805509e386) for the tables this adapter reads.

use std::collections::BTreeMap;

use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::super::native::{SqliteAdmission, on_next_incremental_page};
use super::super::session_message::extract_incremental_messages;
use crate::acquisition::{
    AccountingCoverage, AcquisitionBatch, AcquisitionError, AcquisitionOptions,
    AcquisitionProgress, AttestedValue, BoundedReadError, OpenCodeSqliteReadOptions,
    acquire_opencode_sqlite,
};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{
    BoundDimension, CanonicalObservationV2, CapabilityAvailability, CapabilityId, FactProvenance,
    JsonValue, MessageRole, ObservationBody, ObservationFamily, ObservationStage, ObservedAt,
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

impl Store {
    fn acquire_default_error(&self) -> AcquisitionError {
        match self.acquire(OpenCodeSqliteReadOptions::default()) {
            Ok(_) => panic!("acquisition unexpectedly succeeded"),
            Err(error) => error,
        }
    }
}

mod adaptive_windows;
mod incremental_reads;
mod message_mapping;
mod quarantine;
mod shell_execution;
mod source_rejection;
mod text_budgets;
