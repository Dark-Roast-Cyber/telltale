use super::super::*;
use serde_json::{Value, json};
use telltale_schema::observation::{
    BoundDimension, BoundedTarget, CanonicalFieldCategory, JsonValue, ObservationBody,
};

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

fn options() -> AcquisitionOptions {
    AcquisitionOptions::new(ObservedAt::new("2026-09-18T12:00:00Z").unwrap())
}

/// One synthetic tool call and its result for each adapter whose generic
/// record shape the router accepts.
fn tool_call_corpus(
    name: &str,
    arguments: &Value,
    result: &Value,
) -> Vec<(ClientId, &'static str, SourceKind, String)> {
    let claude = format!(
        "{}\n{}\n",
        json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_synthetic","name":name,"input":arguments}]}}),
        json!({"type":"user","sessionId":"synthetic","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_synthetic","content":result}]}}),
    );
    let codex = format!(
        "{}\n{}\n",
        json!({"type":"tool_call","session_id":"synthetic","name":name,"arguments":arguments}),
        json!({"type":"tool_result","session_id":"synthetic","name":name,"output":result}),
    );
    let qwen = format!(
        "{}\n{}\n",
        json!({"type":"tool_call","sessionId":"synthetic","tool_name":name,"arguments":arguments}),
        json!({"type":"tool_result","sessionId":"synthetic","content":result}),
    );
    let copilot = format!(
        "Workspace initialized: synthetic (checkpoints: 0)\nAccumulated output items (1): {}\n",
        json!([{"type":"function_call","name":name,"call_id":"call_synthetic","arguments":arguments.to_string()}])
    );
    vec![
        (
            ClientId::Claude,
            "claude.projects",
            SourceKind::Jsonl,
            claude,
        ),
        (ClientId::Codex, "codex.sessions", SourceKind::Jsonl, codex),
        (
            ClientId::Qwen,
            "qwen.projects",
            SourceKind::Jsonl,
            qwen.clone(),
        ),
        (
            ClientId::OpenClaw,
            "openclaw.agents",
            SourceKind::Jsonl,
            qwen,
        ),
        (
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
            copilot,
        ),
    ]
}

fn acquire_input(
    client: ClientId,
    source_id: &str,
    kind: SourceKind,
    input: &str,
) -> AcquisitionBatch {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client,
        source_id: source_id.into(),
        kind,
        path: directory.path().join("synthetic-input.log"),
    };
    std::fs::write(&source.path, input).unwrap();
    acquire_source(&source, options()).unwrap_or_else(|error| panic!("{client:?}: {error}"))
}

/// The contribution labels are checked for every call, with or without
/// replaced values: a call whose name or time is not a valid label keeps
/// exactly the outcome it has with in-bound values.
fn copilot_call(arguments: &str) -> AcquisitionBatch {
    let log = format!(
        "Workspace initialized: synthetic (checkpoints: 0)\nAccumulated output items (1): {}\n",
        json!([{"type":"function_call","name":"exec","call_id":"call_synthetic","arguments":arguments}])
    );
    acquire_input(
        ClientId::Copilot,
        "copilot.process_log",
        SourceKind::CopilotProcessLog,
        &log,
    )
}

/// Sweep `sizes` and check the band where a call's values, each admitted on
/// its own, overflow the observation together with its other fields: below
/// it nothing is replaced, within it the call named `name` is held with one
/// value replaced and the unit reported as `expected`. Nothing is derived
/// from a replaced argument, and no diagnostic carries its content.
fn assert_fitted_band(
    sizes: impl IntoIterator<Item = usize>,
    name: &str,
    expected: (&str, Option<u64>, BoundedTarget),
    acquire: impl Fn(usize) -> AcquisitionBatch,
) {
    let (mut kept, mut replaced) = (0, 0);
    for size in sizes {
        let batch = acquire(size);
        assert!(
            batch.quarantined.is_empty(),
            "{size}: {:?}",
            batch.quarantined
        );
        let named = batch
            .observations
            .iter()
            .filter_map(|observation| match observation.body() {
                ObservationBody::Tool(tool) if tool.name() == Some(name) => {
                    Some((observation, tool))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(!named.is_empty(), "{size}: the call is projected");
        let units = bounded_units(&batch);
        if units.is_empty() {
            assert_eq!(replaced, 0, "{size}: replacement stops inside the band");
            kept += 1;
            continue;
        }
        replaced += 1;
        let [(native_id, sequence, target, dimension)] = units.as_slice() else {
            panic!("{size}: one unit: {units:?}")
        };
        assert_eq!(
            (*native_id, *target, *dimension),
            (expected.0, expected.2, BoundDimension::EncodedBytes),
            "{size}"
        );
        if let Some(expected) = expected.1 {
            assert_eq!(*sequence, expected, "{size}");
        }
        // Each observation of the call carries the one replacement.
        let carrying = named
            .iter()
            .filter(|(_, tool)| !tool.bounded_values().is_empty())
            .collect::<Vec<_>>();
        assert!(!carrying.is_empty(), "{size}");
        for (observation, tool) in carrying {
            assert_eq!(tool.bounded_values().len(), 1, "{size}");
            assert_eq!(tool.bounded_values()[0].target(), expected.2, "{size}");
            if expected.2 == BoundedTarget::Arguments {
                assert!(!observation.facets().contains_key("command.text"), "{size}");
            }
        }
        let debug = format!("{:?}{:?}", batch.bounded, batch.observations);
        assert!(!debug.contains("xxxx") && !debug.contains("yyyy"), "{size}");
    }
    assert!(kept > 0 && replaced > 0, "the sweep crosses the band");
}

fn claude_bash_call(size: usize) -> String {
    format!(
        "{}\n",
        json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_synthetic","name":"Bash","input":{"command":"x".repeat(size)}}]}})
    )
}

mod aggregate_bounds;
mod bound_diagnostics;
mod message_retention;
mod replaced_values;
mod tool_results;
