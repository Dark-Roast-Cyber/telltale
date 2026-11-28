use std::collections::BTreeMap;

use telltale_schema::observation::{
    BrowserObservation, CanonicalObservationV2, CapabilityAvailability, CapabilityContext,
    CapabilityId, CorrelationId, FactMetadata, FactProvenance, Fidelity, InferenceObservation,
    IngestionMode, JsonValue, LocalReference, McpObservation, MessageObservation, MessageRole,
    NetworkObservation, ObservationBody, ObservationFamily, ObservationId, ObservationStage,
    ObservedAt, ProcessObservation, RuntimeObservation, SemanticFacet, SourceProvenance,
    ToolObservation,
};

use super::rule_v1::{RuleV1SessionError, evaluate_rule_v1_session_with_budget};
use super::session::RetentionBudget;
use super::types::signal_identity_tuple;
use super::*;

const OBSERVED_AT: &str = "2026-09-03T12:00:00Z";

fn capabilities(tool_call: CapabilityAvailability) -> CapabilityContext {
    CapabilityContext::new()
        .with_override(CapabilityId::ToolCall, tool_call)
        .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported)
        .with_override(
            CapabilityId::ToolExecution,
            CapabilityAvailability::Unsupported,
        )
}

fn source(native_id: &str) -> SourceProvenance {
    SourceProvenance::new(
        IngestionMode::Harness,
        "synthetic",
        "detection-tests",
        Fidelity::FullNative,
    )
    .expect("source")
    .with_native_id(native_id)
    .expect("native id")
}

fn message(role: MessageRole, text: &str, native_id: &str) -> CanonicalObservationV2 {
    CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(role).with_content(JsonValue::string(text)),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).expect("observed at"),
        source(native_id),
    )
    .capability_context(capabilities(CapabilityAvailability::Supported))
    .fact_metadata("message.role", FactMetadata::reported().expect("metadata"))
    .fact_metadata(
        "message.content",
        FactMetadata::reported().expect("metadata"),
    )
    .build()
    .expect("message")
}

fn message_with_session(text: &str, native_id: &str) -> CanonicalObservationV2 {
    CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::Assistant).with_content(JsonValue::string(text)),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).expect("observed at"),
        source(native_id),
    )
    .session_id(CorrelationId::source_reported("session:synthetic").expect("session id"))
    .capability_context(capabilities(CapabilityAvailability::Supported))
    .fact_metadata("message.role", FactMetadata::reported().expect("metadata"))
    .fact_metadata(
        "message.content",
        FactMetadata::reported().expect("metadata"),
    )
    .build()
    .expect("message with session")
}

fn tool(text: &str, native_id: &str) -> CanonicalObservationV2 {
    tool_with_stage(ObservationStage::ToolRequested, text, native_id)
}

fn tool_with_object_arguments(native_id: &str) -> CanonicalObservationV2 {
    let arguments = JsonValue::Object(BTreeMap::from([
        ("alpha".to_owned(), JsonValue::string("one")),
        ("beta".to_owned(), JsonValue::Unsigned(2)),
    ]));
    CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .expect("tool name")
                .with_arguments(arguments),
        ),
        ObservationStage::ToolRequested,
        ObservedAt::new(OBSERVED_AT).expect("observed at"),
        source(native_id),
    )
    .capability_context(capabilities(CapabilityAvailability::Supported))
    .fact_metadata("tool.name", FactMetadata::reported().expect("metadata"))
    .fact_metadata(
        "tool.arguments",
        FactMetadata::reported().expect("metadata"),
    )
    .build()
    .expect("object tool")
}

fn tool_with_stage(stage: ObservationStage, text: &str, native_id: &str) -> CanonicalObservationV2 {
    CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .expect("tool name")
                .with_arguments(JsonValue::string(text)),
        ),
        stage,
        ObservedAt::new(OBSERVED_AT).expect("observed at"),
        source(native_id),
    )
    .capability_context(capabilities(CapabilityAvailability::Supported))
    .fact_metadata("tool.name", FactMetadata::reported().expect("metadata"))
    .fact_metadata(
        "tool.arguments",
        FactMetadata::reported().expect("metadata"),
    )
    .build()
    .expect("tool")
}

fn tool_with_result(stage: ObservationStage, native_id: &str) -> CanonicalObservationV2 {
    tool_with_result_exit(stage, native_id, 3)
}

fn tool_with_result_exit(
    stage: ObservationStage,
    native_id: &str,
    exit_code: i64,
) -> CanonicalObservationV2 {
    let body = ToolObservation::new()
        .with_name("shell")
        .expect("tool name")
        .with_arguments(JsonValue::string("synthetic arguments"))
        .with_result(JsonValue::string("synthetic result"))
        .with_is_error(true)
        .with_exit_code(exit_code);
    CanonicalObservationV2::builder(
        ObservationBody::Tool(body),
        stage,
        ObservedAt::new(OBSERVED_AT).expect("observed at"),
        source(native_id),
    )
    .capability_context(capabilities(CapabilityAvailability::Supported))
    .fact_metadata("tool.name", FactMetadata::reported().expect("metadata"))
    .fact_metadata(
        "tool.arguments",
        FactMetadata::reported().expect("metadata"),
    )
    .fact_metadata("tool.result", FactMetadata::reported().expect("metadata"))
    .fact_metadata("tool.is_error", FactMetadata::reported().expect("metadata"))
    .fact_metadata(
        "tool.exit_code",
        FactMetadata::reported().expect("metadata"),
    )
    .build()
    .expect("tool result")
}

fn matcher_state(matcher: MatcherSpec, observation: &CanonicalObservationV2) -> MatchState {
    matcher
        .compile()
        .expect("matcher")
        .evaluate(observation)
        .expect("matcher evaluation")
        .state()
        .clone()
}

fn metadata(kind: FindingKind, category: &str) -> FindingMetadata {
    FindingMetadata::new(kind, category, Severity::Medium).expect("finding metadata")
}

fn body_observation(
    body: ObservationBody,
    stage: ObservationStage,
    native_id: &str,
    metadata: &[(&str, FactProvenance)],
) -> CanonicalObservationV2 {
    let mut builder = CanonicalObservationV2::builder(
        body,
        stage,
        ObservedAt::new(OBSERVED_AT).expect("observed at"),
        source(native_id),
    )
    .capability_context(capabilities(CapabilityAvailability::Supported));
    for (path, provenance) in metadata {
        builder = builder.fact_metadata(
            *path,
            FactMetadata::new(
                *provenance,
                telltale_schema::observation::Sensitivity::Normal,
            )
            .expect("metadata"),
        );
    }
    builder.build().expect("body observation")
}

fn assert_selector_value(
    registry: &SelectorRegistry,
    selector: SelectorId,
    observation: &CanonicalObservationV2,
    expected: JsonValue,
    provenance: FactProvenance,
) {
    let resolution = registry.resolve(selector, observation).unwrap();
    assert_eq!(resolution.presence(), SelectorPresence::Present);
    assert_eq!(resolution.value(), Some(&expected));
    assert_eq!(
        resolution.metadata().expect("metadata").provenance(),
        provenance
    );
}

fn detector(matcher: MatcherSpec) -> CompiledObservationMatchDetector {
    let identity =
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.detector").expect("identity");
    ObservationMatchSpec::new(
        identity,
        ObservationFamily::Message,
        vec![ObservationStage::MessageObserved],
        matcher,
        metadata(FindingKind::SecurityDetection, "synthetic"),
    )
    .compile()
    .expect("detector")
}

fn rule_v1_session_plan() -> RuleV1CompatibilityPlan {
    let document = r#"
title: alpha rationale
id: 7a02cd2b-4f01-4a02-8ba6-5de7618c40b2
name: synthetic.alpha
taxonomy: telltale
logsource:
    product: ai_agent
    category: message
detection:
    selection:
        - message.assistant_text|re: 'alpha'
    condition: selection
level: low
tags:
    - atlas.aml.t0001
telltale:
    category: alpha
    score: 7
    explanation: 'alpha rationale'
    analytic_intent: alert
    detection_class: security_detection
    signal_type: atomic
    tags: [tag:alpha]
---
title: beta rationale
id: 07accc6a-2c10-4c59-82a0-1ae67c726ef6
name: synthetic.beta
taxonomy: telltale
logsource:
    product: ai_agent
    category: message
detection:
    selection:
        - message.assistant_text|re: 'beta'
    condition: selection
level: medium
tags:
    - atlas.aml.t0002
telltale:
    category: beta
    score: 0
    explanation: 'beta rationale'
    analytic_intent: hunt
    detection_class: threat_hunting
    signal_type: atomic
    tags: [tag:beta]
---
title: category rationale
id: 5991de8b-bb59-4184-807d-d3a9e17a11e0
name: chain.categories
taxonomy: telltale
correlation:
    type: telltale_chain
    categories: [alpha, beta]
tags:
    - atlas.aml.t0003
telltale:
    score: 9
    explanation: 'category rationale'
    analytic_intent: audit
    detection_class: policy_violation
    signal_type: chain
---
title: rule rationale
id: 8b5542bf-0676-443c-8a31-62b597541bd2
name: chain.rules
taxonomy: telltale
correlation:
    type: telltale_chain
    rules: [synthetic.alpha, synthetic.beta]
tags:
    - atlas.aml.t0004
telltale:
    score: 0
    explanation: 'rule rationale'
    analytic_intent: audit
    detection_class: compliance_observation
    signal_type: chain
---
title: combined rationale
id: de963e6a-4ce3-4bdc-8e37-387d614e2284
name: chain.combined
taxonomy: telltale
correlation:
    type: telltale_chain
    rules: [synthetic.alpha, synthetic.beta]
tags:
    - atlas.aml.t0005
telltale:
    score: 11
    explanation: 'combined rationale'
    analytic_intent: audit
    detection_class: security_detection
    signal_type: chain
"#;
    let export = telltale_rules::load_rule_set_from_documents(&[document], None)
        .expect("session rules")
        .compatibility_export();
    compile_rule_v1(&export).expect("session plan")
}

fn observation_without_capability(observation: &CanonicalObservationV2) -> CanonicalObservationV2 {
    // Rebuild the small synthetic tool through the public builder so the test
    // does not depend on internal observation storage or serialization.
    let body = observation.body().clone();
    let mut builder = CanonicalObservationV2::builder(
        body,
        observation.stage(),
        observation.observed_at().clone(),
        observation.source().clone(),
    );
    for (path, metadata) in observation.fact_metadata() {
        builder = builder.fact_metadata(path, metadata.clone());
    }
    builder.build().expect("observation without capability")
}

fn observation_with_capability(
    observation: &CanonicalObservationV2,
    capability_context: CapabilityContext,
) -> CanonicalObservationV2 {
    let body = observation.body().clone();
    let mut builder = CanonicalObservationV2::builder(
        body,
        observation.stage(),
        observation.observed_at().clone(),
        observation.source().clone(),
    )
    .capability_context(capability_context);
    for (path, metadata) in observation.fact_metadata() {
        builder = builder.fact_metadata(path, metadata.clone());
    }
    builder.build().expect("observation with capability")
}

fn add_facet(
    observation: CanonicalObservationV2,
    path: &str,
    value: &str,
    provenance: FactProvenance,
) -> CanonicalObservationV2 {
    add_json_facet(observation, path, JsonValue::string(value), provenance)
}

fn add_json_facet(
    observation: CanonicalObservationV2,
    path: &str,
    value: JsonValue,
    provenance: FactProvenance,
) -> CanonicalObservationV2 {
    let mut builder = CanonicalObservationV2::builder(
        observation.body().clone(),
        observation.stage(),
        observation.observed_at().clone(),
        observation.source().clone(),
    )
    .capability_context(
        observation
            .capability_context()
            .cloned()
            .expect("capabilities"),
    )
    .facet(path, SemanticFacet::new(value))
    .expect("facet")
    .fact_metadata(
        path,
        FactMetadata::new(
            provenance,
            telltale_schema::observation::Sensitivity::Normal,
        )
        .expect("metadata"),
    );
    for (existing_path, metadata) in observation.fact_metadata() {
        if existing_path != path {
            builder = builder.fact_metadata(existing_path, metadata.clone());
        }
    }
    builder.build().expect("facet observation")
}

fn replace_metadata(
    observation: &CanonicalObservationV2,
    path: &str,
    provenance: FactProvenance,
) -> CanonicalObservationV2 {
    let mut builder = CanonicalObservationV2::builder(
        observation.body().clone(),
        observation.stage(),
        observation.observed_at().clone(),
        observation.source().clone(),
    )
    .capability_context(
        observation
            .capability_context()
            .cloned()
            .expect("capabilities"),
    );
    for (existing_path, metadata) in observation.fact_metadata() {
        builder = if existing_path == path {
            builder.fact_metadata(
                existing_path,
                FactMetadata::new(
                    provenance,
                    telltale_schema::observation::Sensitivity::Normal,
                )
                .expect("metadata"),
            )
        } else {
            builder.fact_metadata(existing_path, metadata.clone())
        };
    }
    builder.build().expect("replacement observation")
}

pub(super) mod action;

#[cfg(test)]
mod chain_link;

#[cfg(test)]
mod cloud_credential;

#[cfg(test)]
mod declared_operation;

#[cfg(test)]
mod declared_role;

pub(super) mod declared_role_selector;

mod download_link;

#[cfg(test)]
mod process_chain_contract;

#[cfg(test)]
mod shell_reading;

#[cfg(all(test, feature = "source-io"))]
mod source_declaration;

mod tool_kind;

pub(super) mod written_path;

mod capability_and_provenance;
mod materialization;
mod operators;
mod rule_v1_compatibility;
mod selector_registry;
mod selector_views;
mod signal_identity;
