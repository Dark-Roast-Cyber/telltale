use super::*;

#[test]
fn work_budget_control_rules_do_not_scan_unrelated_authored_arguments() {
    let observations = (0..128)
        .map(|index| {
            CanonicalObservationV2::builder(
                ObservationBody::Tool(
                    ToolObservation::new()
                        .with_name("Bash")
                        .unwrap()
                        .with_argument_text(ArgumentText::new().with_key("command"))
                        .with_arguments(
                            JsonValue::object([(
                                "command".into(),
                                JsonValue::string("x".repeat(60_000)),
                            )])
                            .unwrap(),
                        ),
                ),
                ObservationStage::ToolRequested,
                ObservedAt::new("2026-10-06T12:00:00Z").unwrap(),
                SourceProvenance::new(
                    IngestionMode::SessionStore,
                    "claude_code",
                    "claude.projects",
                    Fidelity::FullNative,
                )
                .unwrap()
                .with_native_id(format!("synthetic-{index}"))
                .unwrap(),
            )
            .session_id(CorrelationId::source_reported("synthetic-session").unwrap())
            .capability_context(
                CapabilityContext::new()
                    .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported),
            )
            .fact_metadata("tool.name", metadata())
            .fact_metadata("tool.arguments", metadata())
            .build()
            .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(
        observations
            .iter()
            .map(|o| o.retained_byte_len())
            .sum::<usize>()
            < telltale_schema::observation::MAX_CANONICAL_RETAINED_BYTES
    );
    let instance = CorrelationId::source_reported("synthetic-instance").unwrap();
    for (target, field) in [("arguments", "tool.arguments"), ("tool_name", "tool.name")] {
        let document = (0..40)
            .map(|index| synthetic_never_match_rule(index, field))
            .collect::<Vec<_>>()
            .join("---\n");
        let rules = telltale_rules::load_rule_set_from_documents(&[&document], None).unwrap();
        let plan = compile_rule_v1(&rules.compatibility_export()).unwrap();
        let work = EvaluationWorkBudget::default();
        let result = evaluate_source_with_work_budget(
            CanonicalSourceInput {
                client: ClientId::Claude,
                source_id: "claude.projects",
                source_instance: Some(&instance),
                observations: &observations,
            },
            &plan,
            None,
            &work,
        );
        if target == "arguments" {
            assert!(matches!(result, Err(ProcessingError::Bounds)));
            assert!(work.is_exhausted(), "actual full-input scans remain fatal");
        } else {
            let evaluation = result.expect("name lookups must not reserve unrelated arguments");
            assert!(!work.is_exhausted());
            for detector in evaluation.sessions()[0].detectors() {
                assert_eq!(detector.evaluated_no_match_count(), 128);
            }
        }
    }
}

#[test]
fn work_budget_scalar_controls_preserve_resolution_and_structured_fallback() {
    use super::super::super::{SelectorId, SelectorRegistry};

    for structured in [false, true] {
        let facet_value = if structured {
            JsonValue::array(vec![JsonValue::string("synthetic")])
        } else {
            JsonValue::string("synthetic")
        };
        let observation = CanonicalObservationV2::builder(
            ObservationBody::Tool(
                ToolObservation::new()
                    .with_name("Bash")
                    .unwrap()
                    .with_argument_text(ArgumentText::new().with_key("command"))
                    .with_arguments(
                        JsonValue::object([(
                            "command".into(),
                            JsonValue::string("x".repeat(60_000)),
                        )])
                        .unwrap(),
                    ),
            ),
            ObservationStage::ToolRequested,
            ObservedAt::new("2026-10-06T12:00:00Z").unwrap(),
            SourceProvenance::new(
                IngestionMode::SessionStore,
                "claude_code",
                "claude.projects",
                Fidelity::FullNative,
            )
            .unwrap()
            .with_native_id("synthetic-control")
            .unwrap(),
        )
        .fact_metadata("tool.name", metadata())
        .fact_metadata("tool.arguments", metadata())
        .facet("command.text", SemanticFacet::new(facet_value.clone()))
        .unwrap()
        .fact_metadata(
            "command.text",
            FactMetadata::parsed()
                .unwrap()
                .with_fidelity_override(Fidelity::PartialStructured),
        )
        .facet("resource.path", SemanticFacet::new(facet_value))
        .unwrap()
        .fact_metadata("resource.path", metadata())
        .build()
        .unwrap();
        let registry = SelectorRegistry::new();
        for selector in [
            SelectorId::ToolName,
            SelectorId::CompatToolName,
            SelectorId::CommandText,
            SelectorId::CompatCommand,
            SelectorId::ResourcePath,
            SelectorId::CompatFilePath,
        ] {
            let ordinary = registry.resolve(selector, &observation).unwrap();
            let mut budget = RetentionBudget::new();
            budget.charge(MAX_EVALUATION_BYTE_VISITS - 1024).unwrap();
            let constrained = registry.try_resolve(selector, &observation, &mut budget);
            if structured && !matches!(selector, SelectorId::ToolName | SelectorId::CompatToolName)
            {
                assert!(
                    matches!(constrained, Err(ProcessingError::Bounds)),
                    "structured facets keep their conservative reservation"
                );
                continue;
            }
            let constrained = constrained.expect("scalar control must not visit arguments");
            assert_eq!(constrained.selector(), ordinary.selector());
            assert_eq!(constrained.presence(), ordinary.presence());
            assert_eq!(constrained.value(), ordinary.value());
            assert_eq!(constrained.metadata(), ordinary.metadata());
            assert_eq!(
                constrained.required_capability(),
                ordinary.required_capability()
            );
        }
    }
    let observation = message(
        "synthetic-absent",
        None,
        &"x".repeat(60_000),
        CapabilityAvailability::Supported,
    );
    for selector in [
        SelectorId::ToolName,
        SelectorId::CompatToolName,
        SelectorId::CommandText,
        SelectorId::CompatCommand,
        SelectorId::ResourcePath,
        SelectorId::CompatFilePath,
    ] {
        let mut budget = RetentionBudget::new();
        budget.charge(MAX_EVALUATION_BYTE_VISITS - 1024).unwrap();
        let resolution = SelectorRegistry::new()
            .try_resolve(selector, &observation, &mut budget)
            .unwrap();
        assert_eq!(
            resolution.presence(),
            super::super::super::SelectorPresence::Absent
        );
        assert!(resolution.value().is_none());
        assert!(resolution.metadata().is_none());
    }
}

#[test]
fn work_budget_literal_percent_messages_do_not_reserve_encoded_url_scans() {
    for suffix in ['~', '%'] {
        let text = format!("needle {}{suffix}", "ordinary ".repeat(368));
        assert_eq!(text.len(), 3_320);
        let observations = (0..8)
            .map(|index| {
                message(
                    &format!("synthetic-{index}"),
                    Some("synthetic-session"),
                    &text,
                    CapabilityAvailability::Supported,
                )
            })
            .collect::<Vec<_>>();
        let instance = CorrelationId::source_reported("synthetic-instance").unwrap();
        let work = EvaluationWorkBudget::default();
        let evaluation = evaluate_source_with_work_budget(
            CanonicalSourceInput {
                client: ClientId::Claude,
                source_id: "claude.projects",
                source_instance: Some(&instance),
                observations: &observations,
            },
            &target_plan("user_context", "needle"),
            None,
            &work,
        )
        .expect("literal percent without an escape cannot hide an encoded URL");
        assert!(!work.is_exhausted());
        assert_eq!(
            evaluation.sessions()[0].detectors()[0].evaluated_match_count(),
            8
        );
    }
}

#[test]
fn tool_control_lookup_does_not_visit_unrelated_large_result() {
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("bash")
                .unwrap()
                .with_result(JsonValue::string("x".repeat(58_000))),
        ),
        ObservationStage::ToolResultReturned,
        ObservedAt::new("2026-10-06T12:00:00Z").unwrap(),
        SourceProvenance::new(
            IngestionMode::SessionStore,
            "opencode",
            "opencode.sqlite",
            Fidelity::PartialStructured,
        )
        .unwrap()
        .with_native_id("synthetic-result")
        .unwrap(),
    )
    .fact_metadata("tool.name", FactMetadata::reported().unwrap())
    .fact_metadata("tool.result", FactMetadata::reported().unwrap())
    .build()
    .unwrap();
    let registry = super::super::super::SelectorRegistry::new();
    let mut borrow_budget = RetentionBudget::new();
    borrow_budget
        .charge(MAX_EVALUATION_BYTE_VISITS - 1024)
        .unwrap();
    let (borrowed, presence) =
        super::super::super::selector::borrow_tool_result_text(&observation, &mut borrow_budget)
            .unwrap()
            .unwrap();
    assert_eq!(
        presence,
        super::super::super::selector::SelectorPresence::Present
    );
    let ObservationBody::Tool(tool) = observation.body() else {
        unreachable!()
    };
    let Some(JsonValue::String(original)) = tool.result() else {
        unreachable!()
    };
    assert_eq!(
        borrowed.as_ptr(),
        original.as_ptr(),
        "lookup must borrow, not copy, output"
    );
    assert!(
        borrow_budget.charge(borrowed.len()).is_err(),
        "the subsequent full-content scan must still exhaust insufficient work"
    );
    let mut control_budget = RetentionBudget::new();
    control_budget
        .charge(MAX_EVALUATION_BYTE_VISITS - 1024)
        .unwrap();
    assert_eq!(
        registry
            .try_resolve(
                super::super::super::SelectorId::CompatToolName,
                &observation,
                &mut control_budget
            )
            .unwrap()
            .value(),
        Some(&JsonValue::string("bash"))
    );
    let mut result_budget = RetentionBudget::new();
    result_budget
        .charge(MAX_EVALUATION_BYTE_VISITS - 1024)
        .unwrap();
    assert!(
        registry
            .try_resolve(
                super::super::super::SelectorId::CompatToolResult,
                &observation,
                &mut result_budget
            )
            .is_err()
    );
}

#[test]
fn default_rules_evaluate_a_store_of_realistic_large_tool_results() {
    let plan = crate::v2::bundled_plan();
    let mut observations = Vec::new();
    for i in 0..64 {
        let output = format!(
            "{}\nsynthetic-tail",
            "compiler output\n".repeat(if i == 0 { 3600 } else { 1000 })
        );
        for stage in [
            ObservationStage::ToolExecutionCompleted,
            ObservationStage::ToolResultReturned,
        ] {
            observations.push(
                CanonicalObservationV2::builder(
                    ObservationBody::Tool(
                        ToolObservation::new()
                            .with_name("bash")
                            .unwrap()
                            .with_arguments(
                                JsonValue::try_from_source_value(
                                    &serde_json::json!({"command":"cargo check"}),
                                )
                                .unwrap(),
                            )
                            .with_result(JsonValue::string(&output)),
                    ),
                    stage,
                    ObservedAt::new("2026-10-06T12:00:00Z").unwrap(),
                    SourceProvenance::new(
                        IngestionMode::SessionStore,
                        "opencode",
                        "opencode.sqlite",
                        Fidelity::PartialStructured,
                    )
                    .unwrap()
                    .with_native_id(format!("synthetic-{i}"))
                    .unwrap(),
                )
                .session_id(CorrelationId::source_reported("synthetic-build").unwrap())
                .capability_context(
                    CapabilityContext::new()
                        .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported)
                        .with_override(
                            CapabilityId::UserContext,
                            CapabilityAvailability::Supported,
                        ),
                )
                .fact_metadata("tool.name", FactMetadata::reported().unwrap())
                .fact_metadata("tool.arguments", FactMetadata::reported().unwrap())
                .fact_metadata("tool.result", FactMetadata::reported().unwrap())
                .build()
                .unwrap(),
            );
        }
    }
    let instance = CorrelationId::source_reported("synthetic-instance").unwrap();
    assert!(
        evaluate_source(
            CanonicalSourceInput {
                client: ClientId::OpenCode,
                source_id: "opencode.sqlite",
                source_instance: Some(&instance),
                observations: &observations
            },
            plan,
            None
        )
        .is_ok()
    );
}

#[test]
fn repeated_punctuation_urls_exhaust_source_work_without_private_output() {
    let text = format!(
        "https://example.invalid/{}?token=SYNTHETIC-PUNCT-SECRET&needle=1",
        ":".repeat(4_000)
    );
    let observations = (0..1_024)
        .map(|index| {
            message(
                &format!("url{index}"),
                Some("session"),
                &text,
                CapabilityAvailability::Supported,
            )
        })
        .collect::<Vec<_>>();
    let evaluation = evaluate(&observations[..1], &plan(0)).unwrap();
    let projected = super::super::super::event3::project_event3(&evaluation, &context()).unwrap();
    let event = serde_json::to_string(&projected.events).unwrap();
    assert!(!event.contains("SYNTHETIC-PUNCT-SECRET"));
    assert!(event.contains(&telltale_schema::event::evidence_hash(&text)));
    let work = EvaluationWorkBudget::default();
    let instance = CorrelationId::source_reported("synthetic-instance").unwrap();
    assert!(matches!(
        evaluate_source_with_work_budget(
            CanonicalSourceInput {
                client: ClientId::Claude,
                source_id: "claude.projects",
                source_instance: Some(&instance),
                observations: &observations
            },
            &plan(0),
            None,
            &work
        ),
        Err(ProcessingError::Bounds)
    ));
    assert!(work.is_exhausted(), "not a compatibility retention failure");
}

#[test]
fn evaluation_work_is_charged_for_no_matches_and_never_reset_between_detectors() {
    let observations = (0..128)
        .map(|index| {
            message(
                &format!("n{index}"),
                Some(if index % 2 == 0 { "one" } else { "two" }),
                &"x".repeat(60_000),
                CapabilityAvailability::Supported,
            )
        })
        .collect::<Vec<_>>();
    let documents = (0..40)
        .map(|index| synthetic_never_match_rule(index, "message.user_text"))
        .collect::<Vec<_>>();
    let document = documents.join("---\n");
    let rules = compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[&document], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap();
    assert!(matches!(
        evaluate(&observations, &rules),
        Err(ProcessingError::Bounds)
    ));
    let half_document = documents[..10].join("---\n");
    let half_rules = compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[&half_document], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap();
    let instance =
        CorrelationId::new("synthetic-host", CorrelationOrigin::TelltaleOriginated).unwrap();
    let input = || CanonicalSourceInput {
        client: ClientId::Claude,
        source_id: "claude.projects",
        source_instance: Some(&instance),
        observations: &observations,
    };
    let work = EvaluationWorkBudget::default();
    evaluate_source_with_work_budget(input(), &half_rules, None, &work).unwrap();
    assert!(matches!(
        evaluate_source_with_work_budget(input(), &half_rules, None, &work),
        Err(ProcessingError::Bounds)
    ));
    let mut budget = RetentionBudget::new();
    budget.charge(MAX_EVALUATION_BYTE_VISITS).unwrap();
    assert_eq!(budget.charge(0), Err(ProcessingError::Bounds));
    assert_eq!(budget.charge(0), Err(ProcessingError::Bounds));
}
