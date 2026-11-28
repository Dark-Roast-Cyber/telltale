use super::*;

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
        let resolution = registry.resolve(selector, &observation).unwrap();
        assert_eq!(resolution.is_present(), expected, "{}", selector.as_str());
        assert_eq!(resolution.selector(), selector);
    }
    assert!(
        !registry
            .resolve(
                SelectorId::CompatCommand,
                &tool_with_object_arguments("name-only")
            )
            .unwrap()
            .is_present(),
        "tool name and unrelated arguments must not become command evidence"
    );

    let url_matcher = MatcherSpec::equals("compat.v1.url", JsonValue::string("https://example"));
    let url_matcher = url_matcher.compile().expect("URL compatibility matcher");
    assert_eq!(
        url_matcher.required_capabilities().collect::<Vec<_>>(),
        vec![CapabilityId::ToolCall]
    );
    // No URL-keyed argument is an evaluated absence, not a visibility gap; a
    // network facet alone is not a tool-argument URL.
    assert_eq!(
        url_matcher
            .evaluate(&tool("synthetic arguments", "url-capability"))
            .unwrap()
            .state(),
        &MatchState::NoMatch
    );
    assert_eq!(
        url_matcher
            .evaluate(&tool(r#"{"url":"https://example"}"#, "url-argument"))
            .unwrap()
            .state(),
        &MatchState::Match
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
    let resolution = SelectorRegistry::new()
        .resolve(
            SelectorId::parse("tool.arguments.keys").expect("selector"),
            &observation,
        )
        .unwrap();
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
