use crate::acquisition::{
    AccountingCoverage, AcquisitionError, AcquisitionOptions, AcquisitionProgress,
    DirectReadLimits, acquire_source, acquire_source_bounded,
};
use crate::source_read::SourceReadError;
use serde_json::{Value, json};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{FactProvenance, JsonValue, ObservationBody, ObservedAt};
use telltale_schema::source::Source;

fn options() -> AcquisitionOptions {
    AcquisitionOptions::new(ObservedAt::new("2026-10-16T00:00:00Z").unwrap())
}

fn conversation_forms(content: &Value) -> [Value; 7] {
    [
        json!({"type":"user","sessionId":"synthetic","message":{"role":"user","content":content}}),
        json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":content}}),
        json!({"type":"user","sessionId":"synthetic","content":content}),
        json!({"role":"assistant","sessionId":"synthetic","content":content}),
        json!({"sessionId":"synthetic","message":{"role":"user","content":content}}),
        json!({"type":"assistant_message","sessionId":"synthetic","content":content}),
        json!({"type":"assistant","sessionId":"synthetic","content":[null],"message":{"role":"assistant","content":content}}),
    ]
}

const SPILL_SESSION: &str = "synthetic-spill-session";
const SPILL_MARKER: &str = "synthetic full output beyond the preview";

fn spill_notice(path: &str) -> String {
    format!(
        "<persisted-output>\nOutput too large (3KB). Full output saved to: {path}\n\nPreview (first 2KB):\nsynthetic preview\n...\n</persisted-output>"
    )
}

/// A call/result pair whose result is `result`, in a transcript at `transcript`.
fn spill_source(transcript: std::path::PathBuf, result: Value) -> Source {
    let call = json!({"type":"assistant","sessionId":SPILL_SESSION,"message":{"role":"assistant",
        "content":[{"type":"tool_use","id":"synthetic-call","name":"Bash",
            "input":{"command":"printf synthetic"}}]}});
    let returned = json!({"type":"user","sessionId":SPILL_SESSION,"message":{"role":"user",
        "content":[{"type":"tool_result","tool_use_id":"synthetic-call","content":result}]}});
    std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    std::fs::write(&transcript, format!("{call}\n{returned}\n")).unwrap();
    Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: transcript,
    }
}

fn write_spill(project: &std::path::Path, name: &str, bytes: &[u8]) {
    let directory = project.join(SPILL_SESSION).join("tool-results");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join(name), bytes).unwrap();
}

fn observed_result(
    observations: &[telltale_schema::observation::CanonicalObservationV2],
) -> Option<JsonValue> {
    observations
        .iter()
        .find_map(|observation| match observation.body() {
            ObservationBody::Tool(tool) => tool.result().cloned(),
            _ => None,
        })
}

fn spilled_result(source: &Source) -> Value {
    super::native::extract_claude_native_records(source)
        .unwrap()
        .into_iter()
        .flat_map(|record| record.blocks.unwrap_or_default())
        .find_map(|block| match block {
            super::native::ClaudeContentBlock::ToolResult { content, .. } => content,
            _ => None,
        })
        .unwrap()
}

mod bookkeeping_records;
mod content_blocks;
mod record_envelopes;
mod spilled_results;
