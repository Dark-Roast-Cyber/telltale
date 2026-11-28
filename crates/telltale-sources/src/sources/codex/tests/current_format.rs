//! Record shapes that current Codex releases write on Windows, which failed
//! whole sources before. Every payload is synthetic.

use crate::acquisition::{
    AccountingCoverage, AcquisitionBatch, AcquisitionError, AcquisitionOptions, acquire_source,
};
use serde_json::{Value, json};
use telltale_schema::observation::{BoundDimension, JsonValue, ObservationBody, ObservedAt};
use telltale_schema::{
    clients::{ClientId, SourceKind},
    source::Source,
};

fn meta(extra: Value) -> Value {
    let mut meta = json!({"type":"session_meta","payload":{"id":"thread-a","session_id":"thread-a","history_mode":"paginated"}});
    meta["payload"]
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    meta
}

fn user(text: &str) -> Value {
    json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":text}]}})
}

fn completed(thread: &str, item: Value) -> Value {
    json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":thread,"turn_id":"turn-a","item":item}})
}

/// Number the records from `first`, as a paginated rollout does.
fn numbered(first: u64, mut values: Vec<Value>) -> Vec<Value> {
    for (offset, value) in values.iter_mut().enumerate() {
        value["ordinal"] = json!(first + offset as u64);
    }
    values
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

fn acquire(source: &Source, values: &[Value]) -> Result<AcquisitionBatch, AcquisitionError> {
    let lines = values.iter().map(Value::to_string).collect::<Vec<_>>();
    std::fs::write(&source.path, lines.join("\n")).unwrap();
    acquire_source(
        source,
        AcquisitionOptions::new(ObservedAt::new("2026-10-14T12:00:00Z").unwrap()),
    )
}

fn private(batch: &AcquisitionBatch) -> bool {
    format!("{:?} {:?}", batch.observations, batch.quarantined).contains("PRIVATE")
}

/// A paginated subagent rollout whose ordinals 1..start copy the parent's
/// model context, as the pinned harness writes a copied fork: its own
/// metadata first, then the inherited prefix, then its own history.
fn subagent_rollout(start: Value, inherited: Vec<Value>, own: Vec<Value>) -> Vec<Value> {
    let child_meta = json!({"type":"session_meta","payload":{
        "id":"thread-child","session_id":"thread-root","parent_thread_id":"thread-root",
        "history_mode":"paginated","source":{"subagent":{"other":"synthetic-role"}},
        "multi_agent_version":"disabled","subagent_history_start_ordinal":start}});
    let mut values = vec![child_meta];
    values.extend(inherited);
    values.extend(own);
    numbered(0, values)
}

fn parent_context() -> Vec<Value> {
    vec![
        // The parent's own metadata, messages, calls and completed items are
        // copied verbatim; none of them belongs to the child.
        json!({"type":"session_meta","payload":{"id":"thread-root","session_id":"thread-root","history_mode":"paginated","model_provider":"PRIVATE-provider"}}),
        user("PRIVATE parent prompt"),
        json!({"type":"response_item","payload":{"type":"function_call","call_id":"call-parent","name":"shell","arguments":"{\"command\":[\"PRIVATE-parent-command\"]}"}}),
        json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"call-parent","output":"PRIVATE parent output"}}),
        completed(
            "thread-root",
            json!({"type":"CommandExecution","id":"cmd-parent","command":["PRIVATE"],"status":"completed","aggregated_output":"PRIVATE"}),
        ),
        json!({"type":"response_item","payload":{"type":"compaction","id":"cmp-parent","encrypted_content":"PRIVATE-opaque"}}),
        json!({"type":"future_record","payload":{"thread_id":"PRIVATE-other","anything":"PRIVATE"}}),
    ]
}

fn child_history() -> Vec<Value> {
    vec![
        json!({"type":"event_msg","payload":{"type":"task_started","turn_id":"turn-child"}}),
        user("synthetic child prompt"),
        json!({"type":"response_item","payload":{"type":"function_call","call_id":"call-child","name":"shell","arguments":"{\"command\":[\"synthetic-child-command\"]}"}}),
        json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"call-child","output":"synthetic child output"}}),
        completed(
            "thread-child",
            json!({"type":"CommandExecution","id":"cmd-child","command":["synthetic-child-argv"],"status":"completed","exit_code":0,"aggregated_output":"synthetic"}),
        ),
    ]
}

fn assistant(texts: &[&str]) -> Value {
    json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":texts.iter().map(|text| json!({"type":"output_text","text":text})).collect::<Vec<_>>()}})
}

fn agent_message(text: &str) -> Value {
    json!({"type":"event_msg","payload":{"type":"agent_message","message":text,"phase":null,"memory_citation":null}})
}

mod legacy_mirrors;
mod record_gaps;
mod subagent_history;
mod web_search;
