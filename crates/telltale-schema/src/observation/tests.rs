use super::*;

const OBSERVED_AT: &str = "2026-09-02T12:00:00Z";
const PRODUCER_KEY: &[u8] = b"synthetic-only-producer-key-epoch-1";
const ASSIGNMENT_KEY: &[u8] = b"synthetic-only-assignment-comparison-key-1";

/// Synthetic declarations standing in for a source's tool table: the schema
/// holds the mechanism, a source adapter declares which fields are text.
fn declared(name: &str) -> ArgumentText {
    let (keys, whole, strict): (&[&str], bool, bool) = match name {
        "apply_patch" => (&["patchText"], true, true),
        "patch" => (&["patchText"], false, false),
        "shell" => (&["command"], true, false),
        "bash" => (&["command"], false, false),
        "write" => (&["content"], false, false),
        "edit" => (&["oldString", "newString"], false, false),
        "execute" => (&["code"], false, false),
        "subagent" | "task" => (&["prompt"], false, false),
        "exec" => (&[], true, false),
        _ => (&[], false, false),
    };
    let mut text = keys
        .iter()
        .fold(ArgumentText::new(), |text, key| text.with_key(*key));
    if whole {
        text = text.with_whole();
    }
    if strict {
        text = text.with_strict();
    }
    text
}

fn message_text_builder(message: MessageObservation) -> ObservationBuilder {
    let has_content = message.content().is_some();
    let has_parts = !message.content_parts().is_empty();
    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Message(message),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("message.role", FactMetadata::reported().unwrap());
    if has_content {
        builder = builder.fact_metadata("message.content", FactMetadata::reported().unwrap());
    }
    if has_parts {
        builder = builder.fact_metadata("message.content_parts", FactMetadata::reported().unwrap());
    }
    builder
}

fn source() -> SourceProvenance {
    SourceProvenance::new(
        IngestionMode::Harness,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id("native-record-1")
    .unwrap()
}

fn scoped_source(namespace: &str) -> SourceProvenance {
    SourceProvenance::new(
        IngestionMode::SessionStore,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_identity_source_sequence(namespace, 0)
    .unwrap()
}

fn scoped_message(
    source: SourceProvenance,
    content: &str,
) -> Result<CanonicalObservationV2, ObservationError> {
    CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string(content)),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source,
    )
    .fact_metadata("message.role", FactMetadata::reported().unwrap())
    .fact_metadata("message.content", FactMetadata::reported().unwrap())
    .build()
}

fn metadata(provenance: FactProvenance) -> FactMetadata {
    FactMetadata::new(provenance, Sensitivity::Normal).unwrap()
}

fn build(body: ObservationBody, stage: ObservationStage, paths: &[&str]) -> CanonicalObservationV2 {
    let mut builder = CanonicalObservationV2::builder(
        body,
        stage,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    );
    for path in paths {
        builder = builder.fact_metadata(*path, metadata(FactProvenance::Reported));
    }
    builder.build().unwrap()
}

fn build_with_provenance(
    body: ObservationBody,
    stage: ObservationStage,
    paths: &[(&str, FactProvenance)],
) -> Result<CanonicalObservationV2, ObservationError> {
    let mut builder = CanonicalObservationV2::builder(
        body,
        stage,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    );
    for (path, provenance) in paths {
        builder = builder.fact_metadata(*path, metadata(*provenance));
    }
    builder.build()
}

fn declared_tool(
    arguments: Option<serde_json::Value>,
    operation: Option<ToolOperation>,
) -> CanonicalObservationV2 {
    let mut tool = ToolObservation::new().with_name("write").unwrap();
    let mut paths = vec!["tool.name"];
    if let Some(arguments) = arguments {
        tool = tool.with_arguments(JsonValue::try_from_source_value(&arguments).unwrap());
        paths.push("tool.arguments");
    }
    if let Some(operation) = operation {
        tool = tool.with_operation(operation);
    }
    build(
        ObservationBody::Tool(tool),
        ObservationStage::ToolRequested,
        &paths,
    )
}

fn operation_of(observation: &CanonicalObservationV2) -> &ToolOperation {
    let ObservationBody::Tool(tool) = observation.body() else {
        panic!("a tool observation")
    };
    tool.operation().expect("declared")
}

fn bounded(value: &serde_json::Value) -> (JsonValue, Vec<BoundedValue>) {
    JsonValue::try_from_source_value_bounded(BoundedTarget::Arguments, value).unwrap()
}

fn replacements(values: &[BoundedValue]) -> Vec<(&str, BoundDimension)> {
    values
        .iter()
        .map(|value| (value.pointer(), value.dimension()))
        .collect()
}

fn entries(tool: &ToolObservation) -> Vec<(BoundedTarget, String, BoundDimension)> {
    tool.bounded_values()
        .iter()
        .map(|value| {
            (
                value.target(),
                value.pointer().to_owned(),
                value.dimension(),
            )
        })
        .collect()
}

const TOOL_PATHS: [(&str, FactProvenance); 3] = [
    ("tool.name", FactProvenance::Reported),
    ("tool.arguments", FactProvenance::Reported),
    ("tool.result", FactProvenance::Reported),
];

fn tool_with(arguments: JsonValue, result: JsonValue) -> ToolObservation {
    ToolObservation::new()
        .with_name("synthetic")
        .unwrap()
        .with_arguments(arguments)
        .with_result(result)
}

mod activity_facets;
mod assignment_replay;
mod bounded_conversion;
mod canonical_bounds;
mod family_construction;
mod identity;
mod message_text;
mod searchable_text;
mod sensitive_values;
mod tool_arguments;
