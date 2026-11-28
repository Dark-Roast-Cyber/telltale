use crate::acquisition::{
    AcquisitionBatch, AcquisitionOptions, AcquisitionProgress, acquire_source,
};
use serde_json::{Value, json};
use telltale_schema::observation::{
    BoundDimension, BoundedTarget, JsonValue, MessageRole, ObservationBody, ObservationStage,
    ObservedAt, ToolStatus,
};
use telltale_schema::{
    clients::{ClientId, SourceKind},
    source::Source,
};

fn meta() -> Value {
    json!({"type":"session_meta","payload":{"id":"child","session_id":"root","history_mode":"paginated"}})
}

fn completed(kind: &str, id: &str) -> Value {
    let content = if kind == "UserMessage" {
        json!([{"type":"text","text":"synthetic"}])
    } else {
        json!([{"type":"Text","text":"synthetic"}])
    };
    json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"child","turn_id":"turn-a","item":{"type":kind,"id":id,"content":content}}})
}

fn each(mut check: impl FnMut(&Source)) {
    let dir = tempfile::tempdir().unwrap();
    for (source_id, kind) in [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ] {
        check(&Source {
            client: ClientId::Codex,
            kind,
            source_id: source_id.into(),
            path: dir.path().join("synthetic.jsonl"),
        });
    }
}

/// The reported bounded units by coordinates, target and bound.
fn bounded_units(batch: &AcquisitionBatch) -> Vec<(&str, u64, BoundedTarget, BoundDimension)> {
    batch
        .bounded
        .iter()
        .map(|unit| {
            (
                unit.native_id.as_str(),
                unit.source_sequence,
                unit.target,
                unit.dimension,
            )
        })
        .collect()
}

fn acquire(
    source: &Source,
    values: &[Value],
) -> Result<crate::acquisition::AcquisitionBatch, crate::acquisition::AcquisitionError> {
    std::fs::write(
        &source.path,
        values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    acquire_source(
        source,
        AcquisitionOptions::new(ObservedAt::new("2026-10-03T12:00:00Z").unwrap()),
    )
}

fn file_change(changes: Value) -> Value {
    let mut value = completed("FileChange", "patch-a");
    value["payload"]["item"] =
        json!({"type":"FileChange","id":"patch-a","changes":changes,"status":"completed"});
    value
}

fn ordinal_records() -> Vec<Value> {
    let raw = json!({"type":"response_item","payload":{"type":"message","role":"assistant","id":"same","internal_chat_message_metadata_passthrough":{"turn_id":"turn-a"},"content":[{"type":"output_text","text":"synthetic"}]}});
    let mut command = completed("CommandExecution", "call-a");
    command["payload"]["item"]["command"] = json!(["printf", "synthetic"]);
    command["payload"]["item"]["status"] = json!("completed");
    let mut values = vec![
        meta(),
        json!({"type":"event_msg","payload":{"type":"token_count"}}),
        raw,
        completed("AgentMessage", "same"),
        completed("UserMessage", "u"),
        command,
    ];
    for (ordinal, value) in values.iter_mut().enumerate() {
        value["ordinal"] = json!(ordinal);
    }
    values
}

fn world_state(full: bool, state: Value) -> Value {
    json!({"type":"world_state","payload":{"full":full,"state":state}})
}

mod coordinates;
mod file_changes;
mod mirror_ownership;
mod tool_calls;
mod world_state;
