use super::super::*;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::source::Source;
use tempfile::tempdir;

fn options() -> AcquisitionOptions {
    AcquisitionOptions::new(ObservedAt::new("2026-09-18T12:00:00Z").unwrap())
}

fn codex_auxiliary_records() -> Vec<serde_json::Value> {
    use serde_json::json;
    let mut records = vec![
        json!({"type":"turn_context","payload":{"model":"synthetic-model","model_provider":"synthetic-provider"}}),
        json!({"type":"response_item","payload":{"type":"reasoning","summary":[{"type":"summary_text","text":"PRIVATE reasoning"}],"content":[{"type":"reasoning_text","text":"PRIVATE reasoning"}]}}),
    ];
    // Bookkeeping that current Codex releases write between conversation items.
    records.extend([
        json!({"type":"token_usage_record","payload":{"turn_id":"turn-a","response_id":"response-a","usage":{"input_tokens":1,"output_tokens":2}}}),
        json!({"type":"compacted","payload":{"message":"PRIVATE summary","replacement_history":[{"type":"message","role":"user","content":[{"type":"input_text","text":"PRIVATE history"}]}]}}),
    ]);
    for kind in [
        "task_started",
        "task_complete",
        "turn_aborted",
        "thread_settings_applied",
        "token_count",
        "agent_reasoning",
        "agent_reasoning_raw_content",
        "agent_reasoning_section_break",
        "reasoning_content_delta",
        "reasoning_raw_content_delta",
    ] {
        records.push(json!({"type":"event_msg","payload":{"type":kind,"turn_id":"turn-a","thread_id":"thread-a","item_id":"item-a","text":"PRIVATE reasoning","delta":"PRIVATE delta","last_agent_message":"PRIVATE fallback","error":{"message":"PRIVATE error"}}}));
    }
    records
}

mod auxiliary_records;
mod contributions;
mod coverage;
mod instruction_records;
mod metadata_ownership;
mod metadata_selection;
