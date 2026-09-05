use std::collections::BTreeMap;
use std::path::Path;

use telltale_schema::observation::{
    BrowserObservation, CanonicalObservationV2, CapabilityAvailability, CapabilityContext,
    CapabilityId, CorrelationId, FactMetadata, FactProvenance, Fidelity, InferenceObservation,
    IngestionMode, JsonValue, LocalReference, McpObservation, MessageObservation, MessageRole,
    NetworkObservation, ObservationBody, ObservationFamily, ObservationId, ObservationStage,
    ObservedAt, ProcessObservation, RuntimeObservation, SemanticFacet, SourceProvenance,
    ToolObservation,
};

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
    let resolution = registry.resolve(selector, observation);
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

#[test]
fn all_compatibility_names_are_registered() {
    for target in [
        "arguments",
        "assistant_context",
        "command",
        "file_path",
        "tool_name",
        "tool_result",
        "url",
        "user_context",
    ] {
        let selector = SelectorId::parse(&format!("compat.v1.{target}"));
        assert!(selector.is_ok(), "compat target {target} must compile");
    }
}

#[test]
fn selector_registry_has_only_contract_backed_names() {
    assert_eq!(SelectorId::all().len(), 56);
    let counts = SelectorId::all()
        .iter()
        .map(|name| name.split('.').next().expect("selector group"))
        .fold(BTreeMap::<&str, usize>::new(), |mut counts, group| {
            *counts.entry(group).or_default() += 1;
            counts
        });
    assert_eq!(
        counts,
        BTreeMap::from([
            ("browser", 3),
            ("command", 1),
            ("compat", 8),
            ("inference", 5),
            ("mcp", 4),
            ("message", 3),
            ("network", 5),
            ("process", 4),
            ("resource", 3),
            ("runtime", 4),
            ("session", 1),
            ("tool", 15),
        ])
    );

    let backing_counts = SelectorId::all()
        .iter()
        .map(|name| {
            SelectorId::parse(name)
                .expect("registered selector")
                .backing()
        })
        .fold(
            BTreeMap::<SelectorBacking, usize>::new(),
            |mut counts, backing| {
                *counts.entry(backing).or_default() += 1;
                counts
            },
        );
    assert_eq!(
        backing_counts,
        BTreeMap::from([
            (SelectorBacking::Compatibility, 8),
            (SelectorBacking::Derived, 7),
            (SelectorBacking::Direct, 2),
            (SelectorBacking::GovernedFacet, 2),
            (SelectorBacking::Typed, 37),
        ])
    );

    for removed in [
        "session.client",
        "session.kind",
        "session.execution_mode",
        "session.workspace.class",
        "session.runtime_ref",
        "session.capability_ref",
        "session.ruleset_ref",
        "session.policy_ref",
        "session.toolset_ref",
        "session.mcp_ref",
        "message.content_hash",
        "message.length",
        "message.classification",
        "tool.arguments.hash",
        "tool.result.hash",
        "command.interpreter",
        "command.encoded",
        "command.shell",
        "resource.type",
        "resource.class",
        "resource.workspace_relation",
        "resource.sensitive",
        "network.url",
        "network.new_destination",
        "process.parent.name",
        "process.parent.pid",
        "process.command_line",
        "inference.input_tokens",
        "inference.output_tokens",
        "inference.reasoning_tokens",
        "inference.duration_ms",
        "inference.time_to_first_token_ms",
        "mcp.tool.description_hash",
        "mcp.tool.schema_hash",
        "mcp.tool.capabilities",
        "mcp.tool.changed",
        "mcp.instructions_hash",
        "runtime.sandbox.state",
        "runtime.sandbox.type",
        "runtime.isolation.type",
        "runtime.containerized",
        "browser.page_id",
        "browser.managed",
    ] {
        assert_eq!(
            MatcherSpec::exists(removed).compile().unwrap_err(),
            DetectionError::InvalidSelector,
            "removed selector {removed} must not compile"
        );
    }
}

#[test]
fn generic_namespace_facets_do_not_extend_typed_selector_backing() {
    let observation = add_facet(
        tool("synthetic", "facet-governance"),
        "network.domain",
        "example.invalid",
        FactProvenance::Parsed,
    );
    let resolution = SelectorRegistry::new().resolve(
        SelectorId::parse("network.domain").expect("typed selector"),
        &observation,
    );
    assert_eq!(resolution.presence(), SelectorPresence::Absent);
}

#[test]
fn tool_stage_is_absent_outside_tool_family() {
    let registry = SelectorRegistry::new();
    let selector = SelectorId::parse("tool.stage").expect("selector");
    let tool_observation = tool("synthetic", "tool-stage");
    let tool_resolution = registry.resolve(selector, &tool_observation);
    assert_eq!(tool_resolution.presence(), SelectorPresence::Present);
    assert_eq!(
        tool_resolution.value(),
        Some(&JsonValue::string("requested"))
    );
    assert_eq!(
        tool_resolution
            .metadata()
            .expect("derived stage metadata")
            .provenance(),
        FactProvenance::Derived
    );

    let message_observation = message(MessageRole::User, "synthetic", "message-stage");
    let runtime_observation = body_observation(
        ObservationBody::Runtime(
            RuntimeObservation::new()
                .with_state_marker("observed")
                .expect("runtime state"),
        ),
        ObservationStage::RuntimeObserved,
        "runtime-stage",
        &[("runtime.state_marker", FactProvenance::Reported)],
    );
    for observation in [message_observation, runtime_observation] {
        let resolution = registry.resolve(selector, &observation);
        assert_eq!(resolution.presence(), SelectorPresence::Absent);
        assert!(resolution.value().is_none());
        assert_eq!(
            matcher_state(MatcherSpec::exists("tool.stage"), &observation),
            MatchState::NoMatch
        );
    }
}

#[test]
fn present_not_exists_is_no_match_after_capability_and_provenance_preflight() {
    let supported = tool("synthetic", "present-not-exists");
    let matcher = MatcherSpec::predicate_with_requirements(
        "tool.name",
        MatcherOperator::NotExists,
        None,
        None,
        Some(CapabilityId::ToolCall),
    );
    assert_eq!(matcher_state(matcher, &supported), MatchState::NoMatch);

    let detector = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.present-not-exists")
            .expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolRequested],
        MatcherSpec::predicate_with_requirements(
            "tool.name",
            MatcherOperator::NotExists,
            None,
            None,
            Some(CapabilityId::ToolCall),
        ),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .compile()
    .expect("detector");
    let unsupported = observation_with_capability(
        &supported,
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Unsupported),
    );
    let result = detector.evaluate(&unsupported);
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::RequiredCapabilityUnsupported)
    );

    let provenance_mismatch = replace_metadata(&supported, "tool.name", FactProvenance::Parsed);
    let matcher = MatcherSpec::predicate_with_requirements(
        "tool.name",
        MatcherOperator::NotExists,
        None,
        Some(FactProvenance::Observed),
        None,
    );
    assert_eq!(
        matcher_state(matcher, &provenance_mismatch),
        MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput)
    );
}

#[test]
fn capability_preflight_is_explicit_and_result_visibility_is_not_execution_visibility() {
    let matcher = MatcherSpec::equals("compat.v1.tool_name", JsonValue::string("shell"));
    let detector = detector(matcher);
    // The test above uses a supported ToolCall context.  A missing context is
    // the published unknown state; an explicit unsupported override is checked
    // through the direct selector matcher below.
    let no_context = tool("synthetic command", "cap-unknown");
    let (result, signal) = detector.evaluate_to_signal(&no_context);
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotApplicable);
    assert!(signal.is_none());
    let result = detector.evaluate(&no_context);
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotApplicable);

    let result = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.tool").expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolRequested],
        MatcherSpec::equals("compat.v1.tool_name", JsonValue::string("shell")),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .compile()
    .expect("tool detector")
    .evaluate(&no_context);
    assert_eq!(result.evaluation_status(), EvaluationStatus::EvaluatedMatch);

    let result = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.result").expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolRequested],
        MatcherSpec::equals("compat.v1.tool_result", JsonValue::string("synthetic")),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .compile()
    .expect("result detector")
    .evaluate(&no_context);
    assert_eq!(
        result.evaluation_status(),
        EvaluationStatus::EvaluatedNoMatch
    );
}

#[test]
fn missing_context_is_unknown_and_unsupported_is_not_a_no_match() {
    let observation = tool("synthetic", "missing-context");
    let detector = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.capability").expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolRequested],
        MatcherSpec::equals("compat.v1.tool_name", JsonValue::string("shell")),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .compile()
    .expect("detector");
    let result = detector.evaluate(&observation_without_capability(&observation));
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::RequiredCapabilityUnknown)
    );

    let unsupported = observation_with_capability(
        &observation,
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Unsupported),
    );
    let result = detector.evaluate(&unsupported);
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::RequiredCapabilityUnsupported)
    );
}

#[test]
fn parsed_facts_do_not_satisfy_observed_provenance() {
    let mut observation = tool("synthetic command", "parsed-provenance");
    observation = add_facet(
        observation,
        "command.text",
        "synthetic command",
        FactProvenance::Parsed,
    );
    let matcher = MatcherSpec::predicate_with_requirements(
        "command.text",
        MatcherOperator::Exists,
        None,
        Some(FactProvenance::Observed),
        None,
    );
    let result = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.provenance").expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolRequested],
        matcher,
        metadata(FindingKind::Informational, "synthetic"),
    )
    .compile()
    .expect("detector")
    .evaluate(&observation);
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::IneligibleInput)
    );
}

#[test]
fn boolean_algebra_is_three_state_and_reason_precedence_is_stable() {
    let provenance_mismatch = MatcherSpec::predicate_with_requirements(
        "message.content",
        MatcherOperator::Equals,
        Some(JsonValue::string("different")),
        Some(FactProvenance::Observed),
        None,
    );
    let different = MatcherSpec::equals("message.content", JsonValue::string("different"));
    let all = detector(MatcherSpec::all(vec![
        MatcherSpec::equals("message.content", JsonValue::string("synthetic")),
        different,
    ]));
    let result = all.evaluate(&message(MessageRole::User, "synthetic", "boolean-all"));
    assert_eq!(
        result.evaluation_status(),
        EvaluationStatus::EvaluatedNoMatch
    );

    let any = detector(MatcherSpec::any(vec![provenance_mismatch.clone()]));
    let result = any.evaluate(&replace_metadata(
        &message(MessageRole::User, "synthetic", "boolean-any"),
        "message.content",
        FactProvenance::Parsed,
    ));
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::IneligibleInput)
    );

    let not = detector(MatcherSpec::not(provenance_mismatch));
    let result = not.evaluate(&message(MessageRole::User, "synthetic", "boolean-not"));
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::IneligibleInput)
    );
}

#[test]
fn provenance_mismatch_is_ineligible_for_every_operator() {
    let observation = replace_metadata(
        &message(MessageRole::User, "synthetic", "all-operators"),
        "message.content",
        FactProvenance::Parsed,
    );
    let operators = [
        (
            MatcherOperator::Equals,
            Some(JsonValue::string("synthetic")),
        ),
        (
            MatcherOperator::NotEquals,
            Some(JsonValue::string("different")),
        ),
        (MatcherOperator::Contains, Some(JsonValue::string("synt"))),
        (MatcherOperator::Regex, Some(JsonValue::string("synthetic"))),
        (MatcherOperator::Glob, Some(JsonValue::string("synthetic*"))),
        (MatcherOperator::Exists, None),
        (MatcherOperator::NotExists, None),
        (
            MatcherOperator::In,
            Some(JsonValue::Array(vec![JsonValue::string("synthetic")])),
        ),
        (
            MatcherOperator::NotIn,
            Some(JsonValue::Array(vec![JsonValue::string("different")])),
        ),
        (MatcherOperator::StartsWith, Some(JsonValue::string("synt"))),
        (MatcherOperator::EndsWith, Some(JsonValue::string("etic"))),
        (MatcherOperator::Gt, Some(JsonValue::Integer(1))),
        (MatcherOperator::Gte, Some(JsonValue::Integer(1))),
        (MatcherOperator::Lt, Some(JsonValue::Integer(1))),
        (MatcherOperator::Lte, Some(JsonValue::Integer(1))),
    ];

    for (operator, expected) in operators {
        let matcher = MatcherSpec::predicate_with_requirements(
            "message.content",
            operator,
            expected,
            Some(FactProvenance::Observed),
            None,
        );
        assert_eq!(
            matcher_state(matcher, &observation),
            MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput),
            "{}",
            operator.as_str()
        );
    }
}

#[test]
fn identity_and_materialization_never_include_matched_values() {
    let detector = detector(MatcherSpec::contains(
        "message.content",
        JsonValue::string("marker"),
    ));
    let left = detector.evaluate(&message(MessageRole::User, "marker-one", "identity"));
    let right = detector.evaluate(&message(MessageRole::User, "marker-two", "identity"));
    let left_signal = left.signal().expect("signal").expect("match");
    let right_signal = right.signal().expect("signal").expect("match");
    assert_eq!(left_signal.signal_id(), right_signal.signal_id());
    assert!(left_signal.signal_id().starts_with(SIGNAL_ID_PREFIX));
    assert!(!format!("{:?}", left_signal).contains("message.content"));
    let finding = left_signal.finding().expect("finding");
    assert!(finding.finding_id().starts_with(FINDING_ID_PREFIX));
    assert_eq!(finding.signal_ids(), &[left_signal.signal_id().to_owned()]);

    let no_match = detector.evaluate(&message(MessageRole::User, "other", "no-match"));
    assert_eq!(
        no_match.evaluation_status(),
        EvaluationStatus::EvaluatedNoMatch
    );
    assert!(no_match.signal().expect("materialization").is_none());
    assert!(no_match.finding().expect("materialization").is_none());

    let resolution = SelectorRegistry::new().resolve(
        SelectorId::MessageContent,
        &message(MessageRole::User, "synthetic-private-marker", "debug"),
    );
    assert!(!format!("{resolution:?}").contains("synthetic-private-marker"));
    let compiled = MatcherSpec::contains(
        "message.content",
        JsonValue::string("synthetic-private-marker"),
    )
    .compile()
    .expect("matcher");
    assert!(!format!("{compiled:?}").contains("synthetic-private-marker"));
}

#[test]
fn signal_identity_includes_every_detector_identity_field() {
    let observation = message(MessageRole::User, "synthetic", "identity-fields");
    let observation_id = ObservationId::new(observation.observation_id()).expect("observation id");
    let make_signal_id = |identity: DetectorIdentity| {
        DetectorResult::evaluated_match(
            identity,
            std::slice::from_ref(&observation_id),
            metadata(FindingKind::Informational, "synthetic"),
        )
        .expect("evaluated match")
        .with_match_surface("structured")
        .expect("match surface")
        .with_matched_selector_paths(vec!["message.content".to_owned()])
        .expect("selector paths")
        .signal()
        .expect("signal")
        .expect("match")
        .signal_id()
        .to_owned()
    };

    let base = make_signal_id(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity.base")
            .expect("identity"),
    );
    let variants = [
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity.other")
            .expect("identity"),
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity.base")
            .expect("identity")
            .with_version("2")
            .expect("version"),
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity.base")
            .expect("identity")
            .with_engine("synthetic-engine")
            .expect("engine"),
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity.base")
            .expect("identity")
            .with_content_ref("synthetic-content")
            .expect("content ref"),
        DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity.base")
            .expect("identity")
            .with_rule_version(1)
            .expect("rule version"),
    ];
    for identity in variants {
        assert_ne!(base, make_signal_id(identity));
    }
}

#[test]
fn signal_identity_tuple_includes_kind_and_explicit_optional_nulls() {
    let result = DetectorResult::not_evaluated(
        DetectorIdentity::new(DetectorKind::Sequence, "synthetic.sequence").expect("identity"),
        NonEvaluationReason::IneligibleInput,
        metadata(FindingKind::Informational, "synthetic"),
    )
    .expect("not evaluated");
    let tuple = signal_identity_tuple(&result).expect("identity tuple");
    let JsonValue::Array(fields) = tuple else {
        panic!("signal identity must be an array");
    };
    assert_eq!(fields.len(), 13);
    assert_eq!(fields[0], JsonValue::string("telltale:detection-v2-signal"));
    assert_eq!(fields[1], JsonValue::Unsigned(2));
    assert_eq!(fields[2], JsonValue::string("sequence"));
    assert_eq!(fields[4], JsonValue::Null);
    assert_eq!(fields[5], JsonValue::Null);
    assert_eq!(fields[6], JsonValue::Null);
    assert_eq!(fields[7], JsonValue::Null);
    assert_eq!(fields[8], JsonValue::Null);
    assert_eq!(fields[9], JsonValue::Array(Vec::new()));
    assert_eq!(fields[10], JsonValue::Null);
    assert_eq!(fields[11], JsonValue::string("not_evaluated"));
}

#[test]
fn signal_identity_normalizes_observations_and_selectors_and_finding_identity() {
    let observation_one = message(MessageRole::User, "synthetic", "identity-one");
    let observation_two = message(MessageRole::User, "synthetic", "identity-two");
    let observation_id_one =
        ObservationId::new(observation_one.observation_id()).expect("observation id");
    let observation_id_two =
        ObservationId::new(observation_two.observation_id()).expect("observation id");
    assert_ne!(observation_id_one, observation_id_two);

    let make_result = |observation_ids: &[ObservationId], paths: Vec<&str>| {
        DetectorResult::evaluated_match(
            DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.normalized")
                .expect("identity"),
            observation_ids,
            metadata(FindingKind::Informational, "synthetic"),
        )
        .expect("evaluated match")
        .with_match_surface("text")
        .expect("match surface")
        .with_matched_selector_paths(paths.into_iter().map(str::to_owned).collect())
        .expect("selector paths")
    };

    let normalized_ids = [observation_id_two.clone(), observation_id_one.clone()];
    let duplicate_ids = [
        observation_id_one.clone(),
        observation_id_two.clone(),
        observation_id_one.clone(),
    ];
    let base = make_result(&normalized_ids, vec!["message.role", "message.content"]);
    let base_signal = base.signal().expect("signal").expect("match");
    let base_finding = base_signal.finding().expect("finding");

    let reordered = make_result(
        &duplicate_ids,
        vec!["message.content", "message.role", "message.content"],
    );
    let reordered_signal = reordered.signal().expect("signal").expect("match");
    assert_eq!(base_signal.signal_id(), reordered_signal.signal_id());
    assert_eq!(
        base_finding.finding_id(),
        reordered_signal.finding().expect("finding").finding_id()
    );

    let different_observation = make_result(
        std::slice::from_ref(&observation_id_two),
        vec!["message.role", "message.content"],
    );
    assert_ne!(
        base_signal.signal_id(),
        different_observation
            .signal()
            .expect("signal")
            .expect("match")
            .signal_id()
    );

    let different_selector_set = make_result(
        std::slice::from_ref(&observation_id_one),
        vec!["message.content"],
    );
    assert_ne!(
        base_signal.signal_id(),
        different_selector_set
            .signal()
            .expect("signal")
            .expect("match")
            .signal_id()
    );
}

#[test]
fn invalid_matcher_content_is_rejected_before_evaluation() {
    for (name, expected) in [
        ("equals", MatcherOperator::Equals),
        ("not_equals", MatcherOperator::NotEquals),
        ("contains", MatcherOperator::Contains),
        ("regex", MatcherOperator::Regex),
        ("glob", MatcherOperator::Glob),
        ("exists", MatcherOperator::Exists),
        ("not_exists", MatcherOperator::NotExists),
        ("in", MatcherOperator::In),
        ("not_in", MatcherOperator::NotIn),
        ("starts_with", MatcherOperator::StartsWith),
        ("ends_with", MatcherOperator::EndsWith),
        ("gt", MatcherOperator::Gt),
        ("gte", MatcherOperator::Gte),
        ("lt", MatcherOperator::Lt),
        ("lte", MatcherOperator::Lte),
    ] {
        assert_eq!(MatcherOperator::parse(name).expect("operator"), expected);
    }
    assert_eq!(
        MatcherOperator::parse("greater_than").unwrap_err(),
        DetectionError::InvalidOperator
    );
    assert_eq!(
        SelectorId::parse("actor.id").unwrap_err(),
        DetectionError::InvalidSelector
    );
    assert_eq!(
        SelectorId::parse("native.source_field").unwrap_err(),
        DetectionError::InvalidSelector
    );
    assert_eq!(
        MatcherSpec::all(Vec::new()).compile().unwrap_err(),
        DetectionError::EmptyBooleanGroup
    );
    assert!(matches!(
        MatcherSpec::predicate(
            "message.content",
            MatcherOperator::Regex,
            Some(JsonValue::string("[")),
        )
        .compile(),
        Err(DetectionError::InvalidPattern)
    ));
    assert!(matches!(
        MatcherSpec::predicate(
            "message.content",
            MatcherOperator::Glob,
            Some(JsonValue::string("[unterminated")),
        )
        .compile(),
        Err(DetectionError::InvalidPattern)
    ));
    assert!(matches!(
        MatcherSpec::predicate(
            "message.content",
            MatcherOperator::Regex,
            Some(JsonValue::string("x".repeat(MAX_PATTERN_BYTES + 1))),
        )
        .compile(),
        Err(DetectionError::PatternTooLong)
    ));
}

#[test]
fn statuses_and_diagnostics_are_closed_and_materialization_is_gated() {
    assert_eq!(
        [
            EvaluationStatus::EvaluatedMatch,
            EvaluationStatus::EvaluatedNoMatch,
            EvaluationStatus::NotApplicable,
            EvaluationStatus::NotEvaluated,
            EvaluationStatus::DetectorError,
        ]
        .iter()
        .map(|status| status.as_str())
        .collect::<Vec<_>>(),
        vec![
            "evaluated_match",
            "evaluated_no_match",
            "not_applicable",
            "not_evaluated",
            "detector_error",
        ]
    );
    assert_eq!(
        [
            NonEvaluationReason::InsufficientVisibility,
            NonEvaluationReason::RequiredCapabilityUnsupported,
            NonEvaluationReason::RequiredCapabilityUnknown,
            NonEvaluationReason::MissingOrderingField,
            NonEvaluationReason::MissingCorrelationKey,
            NonEvaluationReason::TypeMismatch,
            NonEvaluationReason::IneligibleInput,
        ]
        .iter()
        .map(|reason| reason.as_str())
        .collect::<Vec<_>>(),
        vec![
            "insufficient_visibility",
            "required_capability_unsupported",
            "required_capability_unknown",
            "missing_ordering_field",
            "missing_correlation_key",
            "type_mismatch",
            "ineligible_input",
        ]
    );

    let identity =
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.status").expect("identity");
    let finding_metadata = metadata(FindingKind::Informational, "synthetic");
    assert_eq!(
        DetectorResult::new(
            identity.clone(),
            EvaluationStatus::NotEvaluated,
            finding_metadata.clone()
        )
        .unwrap_err(),
        DetectionError::InvalidStatus
    );
    assert_eq!(
        DetectorResult::new(
            identity.clone(),
            EvaluationStatus::DetectorError,
            finding_metadata.clone()
        )
        .unwrap_err(),
        DetectionError::InvalidStatus
    );
    let result = DetectorResult::detector_error(
        identity,
        finding_metadata,
        Diagnostic::new(DiagnosticKind::RuntimeDetectorError, "synthetic_failure")
            .expect("diagnostic"),
    )
    .expect("detector error");
    assert!(result.signal().expect("materialization").is_none());
    assert!(result.finding().expect("materialization").is_none());
    assert_eq!(
        result.diagnostics().expect("diagnostic").code(),
        "synthetic_failure"
    );

    let unsupported = DetectorResult::unsupported(
        DetectorIdentity::new(DetectorKind::Sequence, "test.reserved").expect("identity"),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .expect("unsupported result");
    assert_eq!(
        unsupported.evaluation_status(),
        EvaluationStatus::DetectorError
    );
    assert_eq!(
        unsupported.diagnostics().expect("diagnostic").code(),
        "unsupported_detector_kind"
    );
}

#[test]
fn evidence_references_are_typed_safe_handles_and_debug_is_redacted() {
    let secret_marker = "synthetic-secret-marker";
    for representation in [
        EvidenceRepresentation::RedactedExcerpt,
        EvidenceRepresentation::Hash,
        EvidenceRepresentation::Classification,
        EvidenceRepresentation::LocalStructuredValue,
        EvidenceRepresentation::Correlation,
        EvidenceRepresentation::Timeline,
    ] {
        assert!(
            EvidenceRef::new(representation, secret_marker).is_err(),
            "raw marker accepted for {:?}",
            representation
        );
    }
    assert!(EvidenceRef::new(EvidenceRepresentation::Hash, "a".repeat(64)).is_ok());
    assert!(
        EvidenceRef::new(
            EvidenceRepresentation::RedactedExcerpt,
            format!("redacted:{}", "b".repeat(64)),
        )
        .is_ok()
    );
    assert!(EvidenceRef::classification("classification:secret").is_ok());
    assert!(EvidenceRef::timeline("timeline:signal.synthetic").is_ok());
    assert!(EvidenceReference::hash(secret_marker).is_err());
    let classification =
        EvidenceReference::classification(format!("classification:{secret_marker}"))
            .expect("safe classification");
    assert!(!format!("{classification:?}").contains(secret_marker));
    let safe_hash = EvidenceReference::hash("d".repeat(64)).expect("typed hash");
    assert!(EvidenceRef::from_reference(safe_hash).is_ok());

    let local = LocalReference::new("synthetic-local-handle", "identity_key").expect("local ref");
    let local_ref = EvidenceRef::local_structured(&local).expect("local evidence ref");
    assert_eq!(
        local_ref.representation(),
        EvidenceRepresentation::LocalStructuredValue
    );
    let correlation = CorrelationId::source_reported("session:synthetic").expect("correlation");
    let correlation_ref = EvidenceRef::correlation(&correlation).expect("correlation ref");
    assert_eq!(correlation_ref.reference(), "correlation:session:synthetic");

    let observation = message(MessageRole::User, secret_marker, "evidence");
    let observation_id = ObservationId::new(observation.observation_id()).expect("observation id");
    let evidence = EvidenceRef::hash("c".repeat(64))
        .expect("hash ref")
        .with_observation_id(&observation_id)
        .expect("observation ref")
        .with_field("message.content")
        .expect("field ref");
    assert!(!format!("{evidence:?}").contains(secret_marker));

    let finding_metadata =
        FindingMetadata::new(FindingKind::Informational, secret_marker, Severity::Low)
            .expect("metadata")
            .with_semantic_identity(secret_marker)
            .expect("semantic identity")
            .with_evidence_refs(vec![evidence])
            .expect("evidence metadata");
    let result = DetectorResult::evaluated_match(
        DetectorIdentity::new(DetectorKind::ObservationMatch, secret_marker).expect("identity"),
        &[observation_id],
        finding_metadata,
    )
    .expect("evaluated match");
    let signal = result.signal().expect("signal").expect("match");
    let finding = signal.finding().expect("finding");
    for debug in [
        format!("{result:?}"),
        format!("{signal:?}"),
        format!("{finding:?}"),
    ] {
        assert!(
            !debug.contains(secret_marker),
            "debug leaked evidence: {debug}"
        );
    }
}

#[test]
fn evaluated_matches_require_observation_identity_before_materialization() {
    let detector = DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.invariant")
        .expect("identity");
    let finding_metadata = metadata(FindingKind::Informational, "synthetic");
    assert_eq!(
        DetectorResult::new(
            detector.clone(),
            EvaluationStatus::EvaluatedMatch,
            finding_metadata.clone(),
        )
        .unwrap_err(),
        DetectionError::MissingObservationId
    );

    let observation = message(MessageRole::User, "synthetic", "invariant");
    let observation_id = ObservationId::new(observation.observation_id()).expect("observation id");
    let result = DetectorResult::evaluated_match(
        detector.clone(),
        std::slice::from_ref(&observation_id),
        finding_metadata.clone(),
    )
    .expect("evaluated match");
    assert!(result.signal().expect("signal").is_some());
    assert!(result.finding().expect("finding").is_some());
    assert_eq!(
        result.with_observation_ids(&[]).unwrap_err(),
        DetectionError::MissingObservationId
    );

    let no_match = DetectorResult::new(
        detector,
        EvaluationStatus::EvaluatedNoMatch,
        finding_metadata,
    )
    .expect("no match");
    assert!(no_match.signal().expect("signal").is_none());
    assert!(no_match.finding().expect("finding").is_none());
}

#[test]
fn rule_v1_export_is_effective_and_modifiers_are_not_detectors() {
    let rules = telltale_rules::load_default_rule_set().expect("bundled rules");
    let export = rules.compatibility_export();
    assert_eq!(export.rules().len(), 18);
    assert_eq!(export.modifiers().len(), 8);
    let matcher_count = export
        .rules()
        .iter()
        .map(|rule| rule.matchers.len())
        .sum::<usize>();
    assert_eq!(matcher_count, 56);
    let targets = export
        .rules()
        .iter()
        .flat_map(|rule| rule.matchers.iter().map(|matcher| matcher.target.as_str()))
        .fold(BTreeMap::<&str, usize>::new(), |mut counts, target| {
            *counts.entry(target).or_default() += 1;
            counts
        });
    assert_eq!(
        targets,
        BTreeMap::from([
            ("arguments", 18),
            ("assistant_context", 7),
            ("command", 16),
            ("file_path", 4),
            ("tool_name", 1),
            ("tool_result", 7),
            ("url", 3),
        ])
    );
    let severities =
        export
            .rules()
            .iter()
            .fold(BTreeMap::<&str, usize>::new(), |mut counts, rule| {
                *counts.entry(rule.severity.as_str()).or_default() += 1;
                counts
            });
    assert_eq!(
        severities,
        BTreeMap::from([("high", 12), ("low", 3), ("medium", 3)])
    );
    let classes = export
        .rules()
        .iter()
        .fold(BTreeMap::<&str, usize>::new(), |mut counts, rule| {
            *counts.entry(rule.detection_class.as_str()).or_default() += 1;
            counts
        });
    assert_eq!(
        classes,
        BTreeMap::from([
            ("policy_violation", 1),
            ("security_detection", 16),
            ("threat_hunting", 1),
        ])
    );
    assert_eq!(export.rules().iter().map(|rule| rule.score).min(), Some(15));
    assert_eq!(export.rules().iter().map(|rule| rule.score).max(), Some(60));
    assert!(export.rules().iter().all(|rule| {
        !rule.matchers.is_empty()
            && rule
                .matchers
                .iter()
                .all(|matcher| !matcher.target.is_empty())
    }));
    let plan = compile_rule_v1(&export).expect("v1 compatibility plan");
    assert_eq!(plan.detectors().len(), export.rules().len());
    assert_eq!(plan.modifiers().len(), export.modifiers().len());
    assert!(plan.detectors().iter().all(|detector| {
        detector.detector().kind() == DetectorKind::ObservationMatch
            && detector.detector().rule_version() == Some(1)
    }));
}

#[test]
fn compatibility_views_preserve_roles_and_truthful_absence() {
    let registry = SelectorRegistry::new();
    assert_eq!(
        SelectorId::CompatUrl.required_capability(),
        Some(CapabilityId::ToolCall)
    );
    assert_ne!(
        SelectorId::CompatUrl.required_capability(),
        Some(CapabilityId::ToolExecution)
    );
    let assistant = message(
        MessageRole::Assistant,
        "synthetic assistant context",
        "assistant",
    );
    let user = message(MessageRole::User, "synthetic user context", "user");
    let command = add_facet(
        tool("synthetic arguments", "command"),
        "command.text",
        "synthetic command",
        FactProvenance::Parsed,
    );
    let path = add_facet(
        tool("synthetic arguments", "path"),
        "resource.path",
        "synthetic-resource",
        FactProvenance::Parsed,
    );
    let url = add_facet(
        tool("synthetic arguments", "url"),
        "network.url",
        "https://example.invalid/synthetic",
        FactProvenance::Parsed,
    );
    let result = tool_with_result(ObservationStage::ToolResultReturned, "result");

    for (selector, observation, expected) in [
        (
            SelectorId::CompatArguments,
            tool("synthetic arguments", "arguments"),
            true,
        ),
        (SelectorId::CompatAssistantContext, assistant.clone(), true),
        (SelectorId::CompatCommand, command, true),
        (SelectorId::CompatFilePath, path, true),
        (
            SelectorId::CompatToolName,
            tool("synthetic arguments", "name"),
            true,
        ),
        (SelectorId::CompatToolResult, result, true),
        (SelectorId::CompatUrl, url, false),
        (SelectorId::CompatUserContext, user, true),
    ] {
        let resolution = registry.resolve(selector, &observation);
        assert_eq!(resolution.is_present(), expected, "{}", selector.as_str());
        assert_eq!(resolution.selector(), selector);
    }

    let url_matcher = MatcherSpec::equals("compat.v1.url", JsonValue::string("https://example"));
    let url_matcher = url_matcher.compile().expect("URL compatibility matcher");
    assert_eq!(
        url_matcher.required_capabilities().collect::<Vec<_>>(),
        vec![CapabilityId::ToolCall]
    );
    assert_eq!(
        url_matcher
            .evaluate(&tool("synthetic arguments", "url-capability"))
            .state(),
        &MatchState::NoMatch
    );
}

#[test]
fn canonical_fields_cover_tool_lifecycle_and_governed_facets() {
    for (stage, native_id) in [
        (ObservationStage::ToolProposed, "proposed"),
        (ObservationStage::ToolRequested, "requested"),
        (ObservationStage::ToolExecutionStarted, "started"),
        (ObservationStage::ToolExecutionCompleted, "completed"),
        (ObservationStage::ToolResultReturned, "returned"),
    ] {
        let identity = DetectorIdentity::new(
            DetectorKind::ObservationMatch,
            format!("test.stage.{native_id}"),
        )
        .expect("identity");
        let detector = ObservationMatchSpec::new(
            identity,
            ObservationFamily::Tool,
            vec![stage],
            MatcherSpec::exists("tool.name"),
            metadata(FindingKind::Informational, "synthetic"),
        )
        .compile()
        .expect("lifecycle detector");
        let observation = if matches!(
            stage,
            ObservationStage::ToolExecutionCompleted | ObservationStage::ToolResultReturned
        ) {
            tool_with_result(stage, native_id)
        } else {
            tool_with_stage(stage, "synthetic arguments", native_id)
        };
        assert_eq!(
            detector.evaluate(&observation).evaluation_status(),
            EvaluationStatus::EvaluatedMatch,
            "{}",
            stage.as_str()
        );
    }

    for selector in [
        "message.text",
        "tool.arguments.text",
        "tool.arguments.keys",
        "tool.result.text",
        "tool.result.is_error",
        "tool.result.exit_code",
        "process.name",
        "inference.provider",
        "runtime.execution_mode",
        "browser.navigation_id",
    ] {
        assert!(
            SelectorId::parse(selector).is_ok(),
            "registered selector {selector}"
        );
    }
}

#[test]
fn typed_body_selectors_preserve_body_metadata() {
    let registry = SelectorRegistry::new();
    let inference = body_observation(
        ObservationBody::Inference(
            InferenceObservation::new()
                .with_provider("synthetic-provider")
                .expect("provider")
                .with_streaming(true),
        ),
        ObservationStage::InferenceCompleted,
        "body-inference",
        &[
            ("inference.provider", FactProvenance::Reported),
            ("inference.streaming", FactProvenance::Reported),
        ],
    );
    assert_selector_value(
        &registry,
        SelectorId::parse("inference.provider").expect("selector"),
        &inference,
        JsonValue::string("synthetic-provider"),
        FactProvenance::Reported,
    );

    let network = body_observation(
        ObservationBody::Network(
            NetworkObservation::new()
                .with_operation("connect")
                .expect("operation")
                .with_domain("example.invalid")
                .expect("domain")
                .with_protocol("https")
                .expect("protocol")
                .with_port(443),
        ),
        ObservationStage::NetworkObserved,
        "body-network",
        &[
            ("network.operation", FactProvenance::Observed),
            ("network.domain", FactProvenance::Reported),
            ("network.protocol", FactProvenance::Reported),
            ("network.port", FactProvenance::Reported),
        ],
    );
    assert_selector_value(
        &registry,
        SelectorId::parse("network.domain").expect("selector"),
        &network,
        JsonValue::string("example.invalid"),
        FactProvenance::Reported,
    );
    assert_selector_value(
        &registry,
        SelectorId::parse("network.port").expect("selector"),
        &network,
        JsonValue::Unsigned(443),
        FactProvenance::Reported,
    );

    let process = body_observation(
        ObservationBody::Process(
            ProcessObservation::new()
                .with_operation("start")
                .expect("operation")
                .with_name("synthetic-process")
                .expect("name")
                .with_pid(42),
        ),
        ObservationStage::ProcessObserved,
        "body-process",
        &[
            ("process.operation", FactProvenance::Observed),
            ("process.name", FactProvenance::Reported),
            ("process.pid", FactProvenance::Reported),
        ],
    );
    assert_selector_value(
        &registry,
        SelectorId::parse("process.pid").expect("selector"),
        &process,
        JsonValue::Unsigned(42),
        FactProvenance::Reported,
    );

    let runtime = body_observation(
        ObservationBody::Runtime(
            RuntimeObservation::new()
                .with_state_marker("observed")
                .expect("state")
                .with_execution_mode("sandbox")
                .expect("execution mode")
                .with_isolation_state("isolated")
                .expect("isolation state"),
        ),
        ObservationStage::RuntimeObserved,
        "body-runtime",
        &[
            ("runtime.state_marker", FactProvenance::Reported),
            ("runtime.execution_mode", FactProvenance::Reported),
            ("runtime.isolation_state", FactProvenance::Reported),
        ],
    );
    assert_selector_value(
        &registry,
        SelectorId::parse("runtime.isolation.state").expect("selector"),
        &runtime,
        JsonValue::string("isolated"),
        FactProvenance::Reported,
    );

    let browser = body_observation(
        ObservationBody::Browser(
            BrowserObservation::new()
                .with_state_marker("observed")
                .expect("state")
                .with_surface("synthetic-browser")
                .expect("surface")
                .with_origin_class("synthetic-origin")
                .expect("origin"),
        ),
        ObservationStage::BrowserObserved,
        "body-browser",
        &[
            ("browser.state_marker", FactProvenance::Reported),
            ("browser.surface", FactProvenance::Reported),
            ("browser.origin_class", FactProvenance::Reported),
        ],
    );
    assert_selector_value(
        &registry,
        SelectorId::parse("browser.surface").expect("selector"),
        &browser,
        JsonValue::string("synthetic-browser"),
        FactProvenance::Reported,
    );

    let mcp = body_observation(
        ObservationBody::Mcp(
            McpObservation::new("changed")
                .expect("change")
                .with_server_id("synthetic-server")
                .expect("server")
                .with_tool_name("synthetic-tool")
                .expect("tool")
                .with_transport("stdio")
                .expect("transport"),
        ),
        ObservationStage::McpInventoryChanged,
        "body-mcp",
        &[
            ("mcp.change", FactProvenance::Reported),
            ("mcp.server_id", FactProvenance::Reported),
            ("mcp.tool_name", FactProvenance::Reported),
            ("mcp.transport", FactProvenance::Reported),
        ],
    );
    assert_selector_value(
        &registry,
        SelectorId::parse("mcp.server.id").expect("selector"),
        &mcp,
        JsonValue::string("synthetic-server"),
        FactProvenance::Reported,
    );
}

#[test]
fn derived_argument_keys_have_derived_provenance() {
    let observation = tool_with_object_arguments("derived-argument-keys");
    let resolution = SelectorRegistry::new().resolve(
        SelectorId::parse("tool.arguments.keys").expect("selector"),
        &observation,
    );
    assert_eq!(resolution.presence(), SelectorPresence::Present);
    assert_eq!(
        resolution.value(),
        Some(&JsonValue::Array(vec![
            JsonValue::string("alpha"),
            JsonValue::string("beta"),
        ]))
    );
    assert_eq!(
        resolution
            .metadata()
            .expect("derived metadata")
            .provenance(),
        FactProvenance::Derived
    );
}

#[test]
fn scalar_selector_views_preserve_backing_fact_provenance() {
    let registry = SelectorRegistry::new();
    let message_observation = replace_metadata(
        &message(MessageRole::User, "synthetic message", "message-text"),
        "message.content",
        FactProvenance::Parsed,
    );
    assert_selector_value(
        &registry,
        SelectorId::parse("message.text").expect("message text selector"),
        &message_observation,
        JsonValue::string("synthetic message"),
        FactProvenance::Parsed,
    );
    let direct_arguments = replace_metadata(
        &tool("synthetic direct arguments", "arguments-direct"),
        "tool.arguments",
        FactProvenance::Observed,
    );
    assert_selector_value(
        &registry,
        SelectorId::parse("tool.arguments.text").expect("arguments text selector"),
        &direct_arguments,
        JsonValue::string("synthetic direct arguments"),
        FactProvenance::Observed,
    );

    let arguments_observation = body_observation(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .expect("tool name")
                .with_arguments(JsonValue::string("synthetic raw arguments"))
                .with_searchable_arguments("synthetic searchable arguments")
                .expect("searchable arguments"),
        ),
        ObservationStage::ToolRequested,
        "arguments-text",
        &[
            ("tool.name", FactProvenance::Reported),
            ("tool.arguments", FactProvenance::Parsed),
            ("tool.searchable_arguments", FactProvenance::Inferred),
        ],
    );
    assert_selector_value(
        &registry,
        SelectorId::parse("tool.arguments.text").expect("arguments text selector"),
        &arguments_observation,
        JsonValue::string("synthetic searchable arguments"),
        FactProvenance::Inferred,
    );

    let result_observation = body_observation(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .expect("tool name")
                .with_result(JsonValue::string("synthetic raw result"))
                .with_searchable_result("synthetic searchable result")
                .expect("searchable result"),
        ),
        ObservationStage::ToolResultReturned,
        "result-text",
        &[
            ("tool.name", FactProvenance::Reported),
            ("tool.result", FactProvenance::Parsed),
            ("tool.searchable_result", FactProvenance::Observed),
        ],
    );
    assert_selector_value(
        &registry,
        SelectorId::parse("tool.result.text").expect("result text selector"),
        &result_observation,
        JsonValue::string("synthetic searchable result"),
        FactProvenance::Observed,
    );
    let direct_result = replace_metadata(
        &tool_with_result(ObservationStage::ToolResultReturned, "result-direct"),
        "tool.result",
        FactProvenance::Parsed,
    );
    assert_selector_value(
        &registry,
        SelectorId::parse("tool.result.text").expect("result text selector"),
        &direct_result,
        JsonValue::string("synthetic result"),
        FactProvenance::Parsed,
    );
}

#[test]
fn session_scope_is_copied_to_result_and_signal_when_known() {
    let detector = detector(MatcherSpec::exists("message.content"));
    let result = detector.evaluate(&message_with_session("synthetic", "session-result"));
    assert_eq!(result.session_id(), Some("session:synthetic"));
    let signal = result.signal().expect("signal").expect("match");
    assert_eq!(signal.session_id(), Some("session:synthetic"));
}

#[test]
fn result_visibility_does_not_claim_tool_execution() {
    let result_observation =
        tool_with_result(ObservationStage::ToolResultReturned, "result-capability");
    let result_detector = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.result.visible")
            .expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolResultReturned],
        MatcherSpec::equals("tool.result.text", JsonValue::string("synthetic result")),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .compile()
    .expect("result detector");
    assert_eq!(
        result_detector
            .evaluate(&result_observation)
            .evaluation_status(),
        EvaluationStatus::EvaluatedMatch
    );

    let execution_detector = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.execution.required")
            .expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolResultReturned],
        MatcherSpec::exists("tool.result.text"),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .with_required_capabilities(vec![CapabilityId::ToolExecution])
    .compile()
    .expect("execution detector");
    let result = execution_detector.evaluate(&result_observation);
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::RequiredCapabilityUnsupported)
    );
}

#[test]
fn unknown_tool_execution_is_not_a_clean_no_match() {
    let observation = tool_with_result(ObservationStage::ToolResultReturned, "unknown-execution");
    let observation = observation_with_capability(
        &observation,
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported)
            .with_override(CapabilityId::ToolExecution, CapabilityAvailability::Unknown)
            .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported),
    );
    let detector = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.execution.unknown")
            .expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolResultReturned],
        MatcherSpec::exists("tool.result.text"),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .with_required_capabilities(vec![CapabilityId::ToolExecution])
    .compile()
    .expect("execution detector");

    let result = detector.evaluate(&observation);
    assert_eq!(result.evaluation_status(), EvaluationStatus::NotEvaluated);
    assert_eq!(
        result.non_evaluation_reason(),
        Some(NonEvaluationReason::RequiredCapabilityUnknown)
    );
    assert_ne!(
        result.evaluation_status(),
        EvaluationStatus::EvaluatedNoMatch
    );
}

#[test]
fn matcher_implements_all_typed_operators() {
    let observation = tool_with_result(ObservationStage::ToolResultReturned, "operators");
    let string_cases = [
        (MatcherOperator::Equals, JsonValue::string("shell")),
        (MatcherOperator::NotEquals, JsonValue::string("read")),
        (MatcherOperator::Contains, JsonValue::string("hel")),
        (MatcherOperator::Regex, JsonValue::string("^sh")),
        (MatcherOperator::Glob, JsonValue::string("s*ll")),
        (MatcherOperator::StartsWith, JsonValue::string("sh")),
        (MatcherOperator::EndsWith, JsonValue::string("ll")),
    ];
    for (operator, value) in string_cases {
        let matcher = MatcherSpec::predicate("tool.name", operator, Some(value));
        assert_eq!(
            matcher_state(matcher, &observation),
            MatchState::Match,
            "{}",
            operator.as_str()
        );
    }

    assert_eq!(
        matcher_state(MatcherSpec::exists("tool.name"), &observation),
        MatchState::Match
    );
    assert_eq!(
        matcher_state(MatcherSpec::not_exists("resource.path"), &observation),
        MatchState::Match
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "tool.name",
                MatcherOperator::In,
                Some(JsonValue::Array(vec![
                    JsonValue::string("read"),
                    JsonValue::string("shell")
                ])),
            ),
            &observation,
        ),
        MatchState::Match
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "tool.name",
                MatcherOperator::NotIn,
                Some(JsonValue::Array(vec![JsonValue::string("read")])),
            ),
            &observation,
        ),
        MatchState::Match
    );

    for (operator, expected) in [
        (MatcherOperator::Gt, false),
        (MatcherOperator::Gte, true),
        (MatcherOperator::Lt, false),
        (MatcherOperator::Lte, true),
    ] {
        assert_eq!(
            matcher_state(
                MatcherSpec::predicate(
                    "tool.result.exit_code",
                    operator,
                    Some(JsonValue::Unsigned(3)),
                ),
                &observation,
            ),
            if expected {
                MatchState::Match
            } else {
                MatchState::NoMatch
            },
            "{}",
            operator.as_str()
        );
    }
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("tool.result.exit_code", JsonValue::Unsigned(3)),
            &observation,
        ),
        MatchState::Match
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("tool.result.is_error", JsonValue::Bool(true)),
            &observation,
        ),
        MatchState::Match
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "tool.name",
                MatcherOperator::Contains,
                Some(JsonValue::Bool(true)),
            ),
            &observation,
        ),
        MatchState::NotEvaluated(NonEvaluationReason::TypeMismatch)
    );
}

#[test]
fn numeric_matching_is_exact_at_integer_and_float_boundaries() {
    const TWO_TO_53: u64 = 9_007_199_254_740_992;

    let exact = tool_with_result_exit(
        ObservationStage::ToolResultReturned,
        "numeric-exact",
        TWO_TO_53 as i64,
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("tool.exit_code", JsonValue::Number(TWO_TO_53 as f64),),
            &exact,
        ),
        MatchState::Match
    );

    let unsafe_mixed = tool_with_result_exit(
        ObservationStage::ToolResultReturned,
        "numeric-unsafe-mixed",
        (TWO_TO_53 + 1) as i64,
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("tool.exit_code", JsonValue::Number((TWO_TO_53 + 1) as f64),),
            &unsafe_mixed,
        ),
        MatchState::NotEvaluated(NonEvaluationReason::TypeMismatch)
    );

    let signed_min = tool_with_result_exit(
        ObservationStage::ToolResultReturned,
        "numeric-signed-min",
        i64::MIN,
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("tool.exit_code", JsonValue::Number(i64::MIN as f64),),
            &signed_min,
        ),
        MatchState::Match
    );
    let signed_max = tool_with_result_exit(
        ObservationStage::ToolResultReturned,
        "numeric-signed-max",
        i64::MAX,
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("tool.exit_code", JsonValue::Number(i64::MAX as f64),),
            &signed_max,
        ),
        MatchState::NotEvaluated(NonEvaluationReason::TypeMismatch)
    );

    let unsigned_edge = body_observation(
        ObservationBody::Process(
            ProcessObservation::new()
                .with_operation("observe")
                .expect("operation")
                .with_pid(u64::MAX),
        ),
        ObservationStage::ProcessObserved,
        "numeric-unsigned-edge",
        &[
            ("process.operation", FactProvenance::Observed),
            ("process.pid", FactProvenance::Reported),
        ],
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "process.pid",
                MatcherOperator::Gt,
                Some(JsonValue::Integer(i64::MAX)),
            ),
            &unsigned_edge,
        ),
        MatchState::Match
    );

    let signed_negative = tool_with_result_exit(
        ObservationStage::ToolResultReturned,
        "numeric-signed-negative",
        -1,
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "tool.exit_code",
                MatcherOperator::Lt,
                Some(JsonValue::Unsigned(0)),
            ),
            &signed_negative,
        ),
        MatchState::Match
    );

    for non_finite in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            matcher_state(
                MatcherSpec::equals("tool.exit_code", JsonValue::Number(non_finite),),
                &exact,
            ),
            MatchState::NotEvaluated(NonEvaluationReason::TypeMismatch)
        );
    }
}

#[test]
fn missing_and_provenance_mismatch_follow_negative_operator_rules() {
    let observation = tool("synthetic arguments", "missing-fields");
    assert_eq!(
        matcher_state(
            MatcherSpec::equals("resource.path", JsonValue::string("missing")),
            &observation,
        ),
        MatchState::NoMatch
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "resource.path",
                MatcherOperator::NotEquals,
                Some(JsonValue::string("missing")),
            ),
            &observation,
        ),
        MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput)
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate(
                "command.text",
                MatcherOperator::NotIn,
                Some(JsonValue::Array(vec![JsonValue::string("missing")])),
            ),
            &observation,
        ),
        MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput)
    );
    assert_eq!(
        matcher_state(
            MatcherSpec::predicate_with_requirements(
                "resource.path",
                MatcherOperator::NotExists,
                None,
                Some(FactProvenance::Observed),
                None,
            ),
            &observation,
        ),
        MatchState::Match
    );

    let parsed = add_facet(
        observation,
        "command.text",
        "synthetic parsed command",
        FactProvenance::Parsed,
    );
    let observed_only_exists = MatcherSpec::predicate_with_requirements(
        "command.text",
        MatcherOperator::Exists,
        None,
        Some(FactProvenance::Observed),
        None,
    );
    assert_eq!(
        matcher_state(observed_only_exists, &parsed),
        MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput)
    );
    let observed_only_not_exists = MatcherSpec::predicate_with_requirements(
        "command.text",
        MatcherOperator::NotExists,
        None,
        Some(FactProvenance::Observed),
        None,
    );
    assert_eq!(
        matcher_state(observed_only_not_exists, &parsed),
        MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput)
    );
    let observed_only_not_equals = MatcherSpec::predicate_with_requirements(
        "command.text",
        MatcherOperator::NotEquals,
        Some(JsonValue::string("other")),
        Some(FactProvenance::Observed),
        None,
    );
    assert_eq!(
        matcher_state(observed_only_not_equals, &parsed),
        MatchState::NotEvaluated(NonEvaluationReason::IneligibleInput)
    );
}

#[test]
fn capability_precedence_is_independent_of_boolean_branch_order() {
    let matcher = MatcherSpec::any(vec![
        MatcherSpec::predicate_with_requirements(
            "message.content",
            MatcherOperator::Exists,
            None,
            None,
            Some(CapabilityId::UserContext),
        ),
        MatcherSpec::predicate_with_requirements(
            "tool.name",
            MatcherOperator::Exists,
            None,
            None,
            Some(CapabilityId::ToolCall),
        ),
    ]);
    let compiled = matcher.compile().expect("matcher");
    let observation = observation_with_capability(
        &tool("synthetic", "capability-precedence"),
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Unsupported),
    );
    assert_eq!(
        compiled.evaluate(&observation).state(),
        &MatchState::NotEvaluated(NonEvaluationReason::RequiredCapabilityUnsupported)
    );

    let observation = observation_with_capability(
        &tool("synthetic", "capability-precedence-unknown"),
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported),
    );
    assert_eq!(
        compiled.evaluate(&observation).state(),
        &MatchState::NotEvaluated(NonEvaluationReason::RequiredCapabilityUnknown)
    );
}

#[test]
fn recursive_bounds_and_result_metadata_are_enforced() {
    let too_many = MatcherSpec::all(
        (0..=MAX_MATCHER_BRANCHES)
            .map(|_| MatcherSpec::exists("tool.name"))
            .collect(),
    );
    assert_eq!(
        too_many.compile().unwrap_err(),
        DetectionError::BooleanBranchLimit
    );

    let too_many_capabilities = ObservationMatchSpec::new(
        DetectorIdentity::new(DetectorKind::ObservationMatch, "test.capability.bounds")
            .expect("identity"),
        ObservationFamily::Tool,
        vec![ObservationStage::ToolRequested],
        MatcherSpec::exists("tool.name"),
        metadata(FindingKind::Informational, "synthetic"),
    )
    .with_required_capabilities(vec![CapabilityId::ToolCall; MAX_REQUIRED_CAPABILITIES + 1]);
    assert_eq!(
        too_many_capabilities.compile().unwrap_err(),
        DetectionError::InvalidBounds
    );

    assert_eq!(
        Score::new(1.1).unwrap_err(),
        DetectionError::ScoreOutOfRange
    );
    assert_eq!(
        metadata(FindingKind::Informational, "synthetic")
            .with_risk_points(101)
            .unwrap_err(),
        DetectionError::ScoreOutOfRange
    );
    assert!(
        metadata(FindingKind::Informational, "synthetic")
            .with_techniques(["atlas:AML.T0051"])
            .is_ok()
    );
    assert!(
        metadata(FindingKind::Informational, "synthetic")
            .with_techniques(["raw-technique"])
            .is_err()
    );
}

#[test]
fn fixed_identity_vector_matches_architecture_tuple() {
    let observation_one = telltale_schema::observation::ObservationId::new(
        "obs:v2:sha256:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("observation id");
    let observation_two = telltale_schema::observation::ObservationId::new(
        "obs:v2:sha256:2222222222222222222222222222222222222222222222222222222222222222",
    )
    .expect("observation id");
    let identity = DetectorIdentity::new(DetectorKind::ObservationMatch, "synthetic.identity")
        .expect("identity")
        .with_version("2")
        .expect("version");
    let metadata = metadata(FindingKind::SecurityDetection, "synthetic")
        .with_semantic_identity("session:synthetic")
        .expect("semantic identity");
    let result =
        DetectorResult::evaluated_match(identity, &[observation_two, observation_one], metadata)
            .expect("result")
            .with_match_surface("structured")
            .expect("surface")
            .with_matched_selector_paths(vec!["resource.path".to_owned(), "tool.name".to_owned()])
            .expect("paths");
    let signal = result.signal().expect("signal").expect("match");
    assert_eq!(
        signal.signal_id(),
        "sig:v2:sha256:7ec2c26030843a0a829c482344bae3f678f4fe4dcfcc4cbdeba62be0fb119e77",
        "selector digest {}",
        signal.selector_digest()
    );
    assert_eq!(
        signal.finding().expect("finding").finding_id(),
        "fnd:v2:sha256:6323443e36bc349b4ba13471d5c849dcdc8e9ac320364d3fc45d0dc03f08b4d2"
    );
}

#[test]
fn effective_rule_export_preserves_defaults_and_fails_closed_on_unmappable_class() {
    let document = r#"
version: 1
description: synthetic
defaults:
  case_insensitive: true
  enabled: true
rules:
  - id: synthetic.case
    category: synthetic
    detection_class: security_detection
    severity: high
    score: 25
    targets: [tool_name]
    regex: SHELL
    tags: [synthetic]
    atlas_tags: [atlas:AML.T0051]
    explanation: synthetic explanation
modifiers: []
"#;
    let export = telltale_rules::load_rule_set_from_documents(&[document], None)
        .expect("custom rules")
        .compatibility_export();
    assert_eq!(export.rules().len(), 1);
    assert_eq!(export.rules()[0].matchers[0].regex, "(?i:SHELL)");
    assert_eq!(export.rules()[0].score, 25);
    let plan = compile_rule_v1(&export).expect("compatible rule");
    let result = plan.detectors()[0].evaluate(&tool("synthetic", "rule-match"));
    assert_eq!(result.evaluation_status(), EvaluationStatus::EvaluatedMatch);
    assert_eq!(result.finding_kind(), FindingKind::SecurityDetection);
    assert_eq!(result.risk_points(), Some(25));
    assert_eq!(result.techniques(), &["atlas:AML.T0051".to_owned()]);

    let policy = r#"
version: 1
name: synthetic-policy
disabled_rules: [synthetic.case]
"#;
    let export = telltale_rules::load_rule_set_from_documents(&[document], Some(policy))
        .expect("policy rules")
        .compatibility_export();
    assert_eq!(export.policy_name(), Some("synthetic-policy"));
    assert!(export.rules().is_empty());

    let override_yaml = r#"
version: 1
overrides:
  - rule_id: synthetic.case
    reason: synthetic review
    score: 31
"#;
    let override_doc: telltale_rules::RuleOverrideDocument =
        serde_yaml::from_str(override_yaml).expect("override document");
    // Apply the override to a synthetic equivalent so the effective export
    // proves that the compatibility seam sees post-override values.
    let mut rule_set = serde_yaml::from_str(document).expect("synthetic document");
    telltale_rules::apply_rule_override_document(
        &mut rule_set,
        &override_doc,
        Path::new("synthetic-overrides.yaml"),
    )
    .expect("apply override");
    assert_eq!(
        rule_set
            .compile(None)
            .expect("overridden rules")
            .compatibility_export()
            .rules()[0]
            .score,
        31
    );

    let unmappable = document.replace(
        "detection_class: security_detection",
        "detection_class: operational_health",
    );
    let export = telltale_rules::load_rule_set_from_documents(&[&unmappable], None)
        .expect("unmappable rules still load")
        .compatibility_export();
    assert_eq!(
        compile_rule_v1(&export).unwrap_err(),
        RuleV1CompileError::UnmappableDetectionClass
    );
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
