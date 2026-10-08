use super::compile_rule_v1;
use super::session::*;
use telltale_rules::load_default_rule_set;
use telltale_schema::clients::ClientId;
use telltale_schema::observation::*;

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
    let registry = super::SelectorRegistry::new();
    let mut borrow_budget = RetentionBudget::new();
    borrow_budget
        .charge(MAX_EVALUATION_BYTE_VISITS - 1024)
        .unwrap();
    let (borrowed, presence) =
        super::selector::borrow_tool_result_text(&observation, &mut borrow_budget)
            .unwrap()
            .unwrap();
    assert_eq!(presence, super::selector::SelectorPresence::Present);
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
                super::SelectorId::CompatToolName,
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
                super::SelectorId::CompatToolResult,
                &observation,
                &mut result_budget
            )
            .is_err()
    );
}

#[test]
fn default_rules_evaluate_a_store_of_realistic_large_tool_results() {
    let plan = compile_rule_v1(&load_default_rule_set().unwrap().compatibility_export()).unwrap();
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
            &plan,
            None
        )
        .is_ok()
    );
}

fn observation(
    id: &str,
    session: Option<&str>,
    time: Option<&str>,
    sequence: u64,
) -> CanonicalObservationV2 {
    let source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "claude_code",
        "claude.projects",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id(id)
    .unwrap();
    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User)
                .with_content(JsonValue::string("ordinary synthetic text")),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
        source,
    )
    .sequence(sequence)
    .fact_metadata(
        "message.role",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    )
    .fact_metadata(
        "message.content",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    );
    if let Some(session) = session {
        builder = builder.session_id(CorrelationId::source_reported(session).unwrap());
    }
    if let Some(time) = time {
        builder = builder.occurred_at(SourceTimestamp::new(time).unwrap());
    }
    builder.build().unwrap()
}

#[test]
fn canonical_order_is_replay_stable_and_untimed_last() {
    let observations = vec![
        observation("three", Some("session"), None, 3),
        observation("two", Some("session"), Some("2026-09-18T00:00:00Z"), 2),
        observation("one", Some("session"), Some("2026-09-18T00:00:00Z"), 1),
    ];
    let groups = group_sessions(&observations, true);
    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0]
            .iter()
            .map(|o| o.sequence().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let reversed = observations.into_iter().rev().collect::<Vec<_>>();
    assert_eq!(
        group_sessions(&reversed, true)[0]
            .iter()
            .map(|o| o.sequence().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

#[test]
fn unknown_identity_never_groups_unrelated_occurrences() {
    let observations = vec![
        observation("one", Some("same"), None, 1),
        observation("two", Some("same"), None, 2),
    ];
    assert_eq!(group_sessions(&observations, false).len(), 2);
    let unscoped = vec![
        observation("one", None, None, 1),
        observation("two", None, None, 2),
    ];
    assert_eq!(group_sessions(&unscoped, true).len(), 2);
}

#[test]
fn unrelated_source_instances_with_identical_sessions_are_isolated() {
    let rules = load_default_rule_set().unwrap();
    let plan = compile_rule_v1(&rules.compatibility_export()).unwrap();
    let observations = vec![observation("one", Some("same"), None, 1)];
    let first = CorrelationId::source_reported("instance-one").unwrap();
    let second = CorrelationId::source_reported("instance-two").unwrap();
    for instance in [&first, &second] {
        let output = evaluate_source(
            CanonicalSourceInput {
                client: ClientId::Claude,
                source_id: "claude.projects",
                source_instance: Some(instance),
                observations: &observations,
            },
            &plan,
            None,
        )
        .unwrap();
        assert_eq!(output.sessions().len(), 1);
        assert_eq!(output.source_instance(), Some(instance));
    }
}

#[test]
fn errors_are_bounded_and_do_not_contain_source_data() {
    for error in [
        ProcessingError::InvalidSource,
        ProcessingError::Evaluation,
        ProcessingError::Projection,
        ProcessingError::Bounds,
    ] {
        assert!(error.to_string().len() < 64);
        assert!(format!("{error:?}").len() < 64);
    }
}

fn metadata() -> FactMetadata {
    FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap()
}

fn message(
    id: &str,
    session: Option<&str>,
    text: &str,
    capability: CapabilityAvailability,
) -> CanonicalObservationV2 {
    message_with_correlation(
        id,
        session.map(|value| CorrelationId::source_reported(value).unwrap()),
        text,
        capability,
    )
}

fn message_with_correlation(
    id: &str,
    session: Option<CorrelationId>,
    text: &str,
    capability: CapabilityAvailability,
) -> CanonicalObservationV2 {
    let source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "claude_code",
        "claude.projects",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id(id)
    .unwrap();
    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string(text)),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
        source,
    )
    .fact_metadata("message.role", metadata())
    .fact_metadata("message.content", metadata())
    .capability_context(
        CapabilityContext::new().with_override(CapabilityId::UserContext, capability),
    )
    .occurred_at(SourceTimestamp::new("2026-09-17T00:00:00Z").unwrap());
    if let Some(session) = session {
        builder = builder.session_id(session);
    }
    builder.build().unwrap()
}

fn plan(modifier_score: u64) -> super::RuleV1CompatibilityPlan {
    let document = format!(
        "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.atomic\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 1\n    targets: [user_context]\n    regex: needle\n    tags: [synthetic]\n    explanation: synthetic\nmodifiers:\n  - id: chain.synthetic\n    score: {modifier_score}\n    detection_class: security_detection\n    signal_type: chain\n    analytic_intent: audit\n    atlas_tags: []\n    when_all_rule_ids: [synthetic.atomic]\n    explanation: synthetic\n"
    );
    compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[&document], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap()
}

fn target_plan(targets: &str, regex: &str) -> super::RuleV1CompatibilityPlan {
    let document = format!(
        "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.target\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 1\n    targets: [{targets}]\n    regex: {regex}\n    tags: [synthetic]\n    explanation: synthetic\nmodifiers: []\n"
    );
    compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[&document], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap()
}

fn evaluate(
    observations: &[CanonicalObservationV2],
    plan: &super::RuleV1CompatibilityPlan,
) -> Result<CanonicalSourceEvaluation, ProcessingError> {
    let instance = CorrelationId::source_reported("synthetic-source-instance").unwrap();
    evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations,
        },
        plan,
        None,
    )
}

fn context() -> super::event3::Event3CompatibilityContext<'static> {
    super::event3::Event3CompatibilityContext {
        source_path_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        sessions: &[],
    }
}

#[test]
fn long_message_suffix_matches_with_full_hash_and_safe_bounded_evidence() {
    let text = format!(
        "{}needle api_key=SYNTHETIC-LONG-SECRET",
        "ordinary ".repeat(1_000)
    );
    let observations = [message(
        "suffix",
        Some("session"),
        &text,
        CapabilityAvailability::Supported,
    )];
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    assert_eq!(
        evaluation.sessions()[0].detectors()[0].evaluated_match_count(),
        1
    );
    let projected = super::event3::project_event3(&evaluation, &context()).unwrap();
    let json = serde_json::to_string(&projected.events).unwrap();
    assert!(!json.contains("SYNTHETIC-LONG-SECRET"));
    let evidence = projected.events[0]
        .evidence
        .iter()
        .find(|e| e.field == "user_context")
        .unwrap();
    assert_eq!(
        evidence.hash.as_deref(),
        Some(telltale_schema::event::evidence_hash(&text).as_str())
    );
    assert!(evidence.redacted_value.len() <= 512);
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
    let projected = super::event3::project_event3(&evaluation, &context()).unwrap();
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
fn canonical_ingress_retention_cap_is_source_wide_and_exact() {
    let text = "x".repeat(65_528);
    let mut observations = (0..128)
        .map(|index| {
            message(
                &format!("n{index}"),
                Some("session"),
                &text,
                CapabilityAvailability::Supported,
            )
        })
        .collect::<Vec<_>>();
    assert!(evaluate(&observations, &plan(0)).is_ok());
    observations.push(message(
        "excess",
        Some("other-session"),
        "x",
        CapabilityAvailability::Supported,
    ));
    assert!(matches!(
        evaluate(&observations, &plan(0)),
        Err(ProcessingError::Bounds)
    ));
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
    let base = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n";
    let rules = (0..40).map(|index| format!("  - id: synthetic.no{index}\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 1\n    targets: [user_context]\n    regex: NEVER-MATCH\n    tags: []\n    explanation: synthetic\n")).collect::<String>();
    let document = format!("{base}{rules}modifiers: []\n");
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
    let half_document = document
        .split("  - id: synthetic.no10\n")
        .next()
        .unwrap()
        .to_owned()
        + "modifiers: []\n";
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

#[test]
fn event3_uses_checked_contributions_and_actual_canonical_anchors() {
    use super::event3::project_event3;
    let observations = [
        message(
            "match",
            Some("synthetic-session"),
            "needle api_key=tt_SYNTHETIC_SECRET_123456789",
            CapabilityAvailability::Supported,
        ),
        message(
            "no-match",
            Some("synthetic-session"),
            "ordinary text",
            CapabilityAvailability::Supported,
        ),
    ];
    let evaluation = evaluate(&observations, &plan(7)).unwrap();
    assert_eq!(evaluation.completion(), EvaluationCompletion::Complete);
    let projected = project_event3(&evaluation, &context()).unwrap();
    assert_eq!(projected.events.len(), 1);
    let event = &projected.events[0];
    assert_eq!(event.rule_ids, ["chain.synthetic", "synthetic.atomic"]);
    assert_eq!(event.risk_score, 8);
    assert_eq!(event.risk_contributions.len(), 2);
    assert!(event.tags.contains(&"chain".to_owned()));
    assert_eq!(event.categories, ["synthetic"]);
    assert_eq!(
        event.event_time.as_deref(),
        Some("2026-09-17T00:00:00.000Z")
    );
    assert_eq!(event.agent, None);
    assert_eq!(event.model, None);
    assert_eq!(event.provider, None);
    assert_eq!(event.timeline_anchors.len(), 1);
    assert!(
        event
            .evidence
            .iter()
            .any(|e| e.field == "canonical_observation_id"
                && e.hash.as_deref()
                    == Some(
                        telltale_schema::event::evidence_hash(observations[0].observation_id())
                            .as_str()
                    ))
    );
    let serialized = serde_json::to_string(event).unwrap();
    assert!(!serialized.contains("tt_SYNTHETIC_SECRET_123456789"));
    assert!(serialized.contains("3.0"));
    assert_eq!(
        evaluation.sessions()[0].activity().observation_counts["message.observed"],
        2
    );
}

#[test]
fn capability_limited_completion_is_not_no_match_or_operational_failure() {
    for (availability, reason) in [
        (
            CapabilityAvailability::Unsupported,
            "required_capability_unsupported",
        ),
        (
            CapabilityAvailability::Unknown,
            "required_capability_unknown",
        ),
    ] {
        let observations = [message("limited", Some("session"), "needle", availability)];
        let evaluation = evaluate(&observations, &plan(0)).unwrap();
        assert_eq!(
            evaluation.completion(),
            EvaluationCompletion::VisibilityLimited
        );
        let detector = &evaluation.sessions()[0].detectors()[0];
        assert_eq!(
            detector.outcome(),
            super::RuleV1DetectorOutcome::Indeterminate
        );
        assert_eq!(detector.non_evaluation_reason_counts()[reason], 1);
        let projected = super::event3::project_event3(&evaluation, &context()).unwrap();
        assert!(projected.events.is_empty());
        assert_eq!(
            projected.completion,
            EvaluationCompletion::VisibilityLimited
        );
    }
    let observations = [message(
        "ordinary",
        Some("session"),
        "ordinary",
        CapabilityAvailability::Supported,
    )];
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    assert_eq!(evaluation.completion(), EvaluationCompletion::Complete);
    assert_eq!(
        evaluation.sessions()[0].detectors()[0].outcome(),
        super::RuleV1DetectorOutcome::NoMatch
    );
}

#[test]
fn url_target_reads_tool_argument_urls_and_keeps_completion_complete() {
    // A tool call with no URL-keyed argument has no URL: an evaluated no-match,
    // not a visibility gap.
    let plain = [command(
        "url-absent",
        "ordinary synthetic text",
        Some("2026-09-17T00:00:00Z"),
        0,
    )];
    let evaluation = evaluate(&plain, &target_plan("url", "example")).unwrap();
    assert_eq!(evaluation.completion(), EvaluationCompletion::Complete);
    assert!(evaluation.visibility_limits().is_empty());
    assert_eq!(
        evaluation.sessions()[0].detectors()[0].outcome(),
        super::RuleV1DetectorOutcome::NoMatch
    );

    // URL-keyed top-level string arguments (also JSON-encoded) are the URL fact;
    // other argument text is not.
    let encoded = [command(
        "url-present",
        r#"{"url":"https://fetch.example.invalid/page","prompt":"see other.example.org"}"#,
        Some("2026-09-17T00:00:00Z"),
        0,
    )];
    let evaluation = evaluate(&encoded, &target_plan("url", "fetch\\.example")).unwrap();
    assert_eq!(evaluation.completion(), EvaluationCompletion::Complete);
    assert_eq!(
        evaluation.sessions()[0].detectors()[0].outcome(),
        super::RuleV1DetectorOutcome::Match
    );
    let prompt_only = evaluate(&encoded, &target_plan("url", "other\\.example")).unwrap();
    assert_eq!(
        prompt_only.sessions()[0].detectors()[0].outcome(),
        super::RuleV1DetectorOutcome::NoMatch
    );

    // Mixed-target rules evaluate the URL alternative too, still complete.
    let mixed = evaluate(&encoded, &target_plan("command, url", "fetch\\.example")).unwrap();
    assert_eq!(mixed.completion(), EvaluationCompletion::Complete);
    assert_eq!(
        mixed.sessions()[0].detectors()[0].outcome(),
        super::RuleV1DetectorOutcome::Match
    );
}

#[test]
fn event3_aggregates_one_deterministic_anchor_per_occurrence() {
    let document = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.alpha\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 1\n    targets: [arguments, tool_name]\n    regex: shell\n    tags: [synthetic]\n    explanation: synthetic\n  - id: synthetic.beta\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 2\n    targets: [arguments]\n    regex: needle\n    tags: [synthetic]\n    explanation: synthetic\nmodifiers:\n  - id: chain.synthetic_both\n    score: 3\n    detection_class: security_detection\n    signal_type: chain\n    analytic_intent: audit\n    atlas_tags: []\n    when_all_rule_ids: [synthetic.alpha, synthetic.beta]\n    explanation: synthetic\n";
    let anchor_plan = compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[document], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap();
    let observations = [command(
        "anchor",
        "shell needle",
        Some("2026-09-17T00:00:00Z"),
        0,
    )];
    let evaluation = evaluate(&observations, &anchor_plan).unwrap();
    let projected = super::event3::project_event3(&evaluation, &context()).unwrap();
    let first = &projected.events;
    let first_anchor = &first[0].timeline_anchors[0];
    assert_eq!(first[0].timeline_anchors.len(), 1);
    assert_eq!(first_anchor.entry_index, 0);
    assert_eq!(
        first_anchor.rule_ids,
        ["chain.synthetic_both", "synthetic.alpha", "synthetic.beta"]
    );
    assert_eq!(first_anchor.evidence_fields, ["arguments", "tool_name"]);
    assert_eq!(projected.occurrences.len(), 1);
    let occurrence = &projected.occurrences[0];
    assert_eq!(occurrence.finding_index, 0);
    assert_eq!(occurrence.timeline_index, Some(first_anchor.entry_index));
    assert_eq!(occurrence.rule_ids, first_anchor.rule_ids);
    assert_eq!(occurrence.categories, first_anchor.categories);
    assert_eq!(occurrence.evidence_fields, first_anchor.evidence_fields);
    assert_eq!(occurrence.session_id, first[0].session_id);
    for retained in evaluation.sessions()[0].rules.projection() {
        assert_eq!(occurrence.observation_id, retained.observation_id);
        assert_eq!(occurrence.occurred_at, retained.occurred_at);
    }
    assert_eq!(occurrence.observation_id, observations[0].observation_id());
    assert_eq!(
        occurrence.occurred_at.as_deref(),
        Some("2026-09-17T00:00:00Z")
    );
}

#[test]
fn overflow_and_projection_failure_never_return_partial_success() {
    let observations = [message(
        "one",
        Some("session"),
        "needle",
        CapabilityAvailability::Supported,
    )];
    assert!(matches!(
        evaluate(&observations, &plan(u64::MAX)),
        Err(ProcessingError::Evaluation)
    ));
    let observations = [
        message(
            "one",
            Some("session"),
            "needle",
            CapabilityAvailability::Supported,
        ),
        message(
            "unscoped",
            None,
            "needle",
            CapabilityAvailability::Supported,
        ),
    ];
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    assert!(matches!(
        super::event3::project_event3(&evaluation, &context()),
        Err(ProcessingError::Projection)
    ));
    let evaluation = evaluate(&observations[..1], &plan(0)).unwrap();
    let invalid = super::event3::Event3CompatibilityContext {
        source_path_hash: "",
        ..context()
    };
    assert!(matches!(
        super::event3::project_event3(&evaluation, &invalid),
        Err(ProcessingError::Projection)
    ));
}

fn command(id: &str, text: &str, time: Option<&str>, sequence: u64) -> CanonicalObservationV2 {
    let source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "claude_code",
        "claude.projects",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id(id)
    .unwrap();
    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .unwrap()
                .with_arguments(JsonValue::string(text)),
        ),
        ObservationStage::ToolRequested,
        ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
        source,
    )
    .session_id(CorrelationId::source_reported("process-session").unwrap())
    .sequence(sequence)
    .fact_metadata("tool.name", metadata())
    .fact_metadata("tool.arguments", metadata())
    .capability_context(
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported),
    );
    if let Some(time) = time {
        builder = builder.occurred_at(SourceTimestamp::new(time).unwrap());
    }
    builder.build().unwrap()
}

#[test]
fn projected_occurrences_preserve_process_repeats_correlations_and_derived_context() {
    let observations = [
        command(
            "hostname",
            "cmd.exe /c hostname",
            Some("2026-09-17T00:00:00Z"),
            0,
        ),
        command(
            "repeat",
            "cmd.exe /c hostname",
            Some("2026-09-17T00:00:01Z"),
            1,
        ),
        command(
            "whoami",
            "cmd.exe /c whoami",
            Some("2026-09-17T00:01:00Z"),
            2,
        ),
    ];
    assert!(observations[0].observation_id() > observations[2].observation_id());
    let instance = CorrelationId::source_reported("instance").unwrap();
    let process_rules = telltale_rules::process_chain::load_default_process_chain_rules().unwrap();
    let config = crate::process_chain::ProcessChainConfig::default();
    let evaluation = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &observations,
        },
        &plan(0),
        Some((&process_rules, &config)),
    )
    .unwrap();
    let projected = super::event3::project_event3(&evaluation, &context()).unwrap();
    let events = &projected.events;
    for (finding_index, event) in events.iter().enumerate() {
        let occurrences = projected
            .occurrences
            .iter()
            .filter(|occurrence| occurrence.finding_index == finding_index)
            .collect::<Vec<_>>();
        let result = evaluation.sessions()[0]
            .processes
            .as_ref()
            .unwrap()
            .results()
            .iter()
            .find(|result| result.detector().id() == event.rule_ids[0])
            .unwrap();
        assert_eq!(
            occurrences.len(),
            result
                .observation_ids()
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
        for occurrence in occurrences {
            let index = observations
                .iter()
                .position(|observation| observation.observation_id() == occurrence.observation_id)
                .unwrap();
            assert_eq!(occurrence.timeline_index, Some(index));
            assert_eq!(occurrence.rule_ids, event.rule_ids);
            assert_eq!(occurrence.categories, event.categories);
            assert_eq!(occurrence.session_id, event.session_id);
            assert!(occurrence.evidence_fields.is_empty());
            if result.observation_ids().len() == 1 {
                let observation = observations
                    .iter()
                    .find(|observation| observation.observation_id() == occurrence.observation_id)
                    .unwrap();
                assert_eq!(
                    occurrence.occurred_at.as_deref(),
                    observation.occurred_at().map(|time| time.as_str())
                );
            } else {
                assert_eq!(occurrence.occurred_at, None);
            }
        }
    }
    assert!(
        observations
            .iter()
            .all(|o| o.kind() == ObservationFamily::Tool)
    );
    assert!(events.iter().any(|e| {
        e.evidence
            .iter()
            .any(|item| item.field == "repeat_count" && item.redacted_value == "2")
    }));
    let correlation = events
        .iter()
        .find(|e| e.rule_ids[0] == "procchain.correlation.host_then_account_discovery")
        .unwrap();
    let hostname_index = events
        .iter()
        .position(|event| event.rule_ids[0] == "procchain.discovery.cmd_hostname")
        .unwrap();
    let whoami_index = events
        .iter()
        .position(|event| event.rule_ids[0] == "procchain.discovery.cmd_whoami")
        .unwrap();
    let correlation_index = events
        .iter()
        .position(|event| event.rule_ids[0] == "procchain.correlation.host_then_account_discovery")
        .unwrap();
    assert!(hostname_index < whoami_index && whoami_index < correlation_index);
    assert_eq!(correlation.risk_score, 45);
    assert_eq!(
        correlation.process.as_ref().unwrap().dedup_key,
        "correlation:sha256:41b8eb6755cfda95d8059e32619a191386e1177f0939f6e3af208bfe64caa72c"
    );
    assert_eq!(correlation.risk_entity_type.as_deref(), Some("session"));
    assert!(correlation.timeline_anchors.is_empty());
    assert!(
        correlation
            .evidence
            .iter()
            .any(|e| e.field == "canonical_occurrences" && e.redacted_value == "0,2")
    );
    let supporting = correlation
        .evidence
        .iter()
        .find(|e| e.field == "correlated_event_ids")
        .unwrap();
    for id in supporting.redacted_value.split(',') {
        assert!(events.iter().any(|e| e.event_id == id));
    }
    let atomic = events
        .iter()
        .find(|e| e.rule_ids[0] == "procchain.discovery.cmd_whoami")
        .unwrap();
    let process = atomic.process.as_ref().unwrap();
    assert_eq!(process.source_process_name, "cmd");
    assert_eq!(process.target_process_name, "whoami");
    assert!(process.source_process_id.is_none());
    assert_eq!(
        process.source_event_id.as_deref(),
        Some(observations[2].observation_id())
    );
    assert!(!process.rule_name.is_empty());
    for event in events {
        serde_json::to_string(event).unwrap();
    }
}

#[test]
fn equal_time_and_untimed_ties_preserve_caller_occurrence_order() {
    let observations = [
        observation("z-first", Some("session"), None, 1),
        observation("a-second", Some("session"), None, 1),
    ];
    let grouped = group_sessions(&observations, true);
    assert_eq!(
        grouped[0][0].observation_id(),
        observations[0].observation_id()
    );
    let reversed = [observations[1].clone(), observations[0].clone()];
    assert_eq!(
        group_sessions(&reversed, true)[0][0].observation_id(),
        observations[1].observation_id()
    );
}

#[test]
fn session_metadata_is_explicit_scoped_and_not_invented() {
    use super::event3::{Event3CompatibilityContext, Event3SessionMetadata, project_event3};
    let observations = [
        message(
            "one",
            Some("session-a"),
            "needle",
            CapabilityAvailability::Supported,
        ),
        message(
            "two",
            Some("session-b"),
            "needle",
            CapabilityAvailability::Supported,
        ),
    ];
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    let session_id = observations[0].session_id().unwrap();
    let metadata = [Event3SessionMetadata {
        session_id,
        agent: Some("synthetic-agent"),
        model: Some("synthetic-model"),
        provider: Some("synthetic-provider"),
    }];
    let events = project_event3(
        &evaluation,
        &Event3CompatibilityContext {
            sessions: &metadata,
            ..context()
        },
    )
    .unwrap()
    .events;
    assert_eq!(events[0].model.as_deref(), Some("synthetic-model"));
    assert_eq!(events[1].model, None);
    let unknown = CorrelationId::source_reported("not-in-evaluation").unwrap();
    let invalid = [Event3SessionMetadata {
        session_id: &unknown,
        agent: None,
        model: None,
        provider: None,
    }];
    assert!(matches!(
        project_event3(
            &evaluation,
            &Event3CompatibilityContext {
                sessions: &invalid,
                ..context()
            }
        ),
        Err(ProcessingError::Projection)
    ));
}

#[test]
fn metadata_index_rejects_duplicate_and_event3_ambiguous_session_keys() {
    use super::event3::{Event3CompatibilityContext, Event3SessionMetadata, project_event3};
    let source_id =
        CorrelationId::new("same-visible-session", CorrelationOrigin::SourceReported).unwrap();
    let derived_id = CorrelationId::new(
        "same-visible-session",
        CorrelationOrigin::TelltaleOriginated,
    )
    .unwrap();
    let observations = [
        message_with_correlation(
            "source-origin",
            Some(source_id.clone()),
            "needle",
            CapabilityAvailability::Supported,
        ),
        message_with_correlation(
            "derived-origin",
            Some(derived_id.clone()),
            "needle",
            CapabilityAvailability::Supported,
        ),
    ];
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    let duplicate = [
        Event3SessionMetadata {
            session_id: &source_id,
            agent: None,
            model: None,
            provider: None,
        },
        Event3SessionMetadata {
            session_id: &source_id,
            agent: None,
            model: None,
            provider: None,
        },
    ];
    assert!(matches!(
        project_event3(
            &evaluation,
            &Event3CompatibilityContext {
                sessions: &duplicate,
                ..context()
            }
        ),
        Err(ProcessingError::Projection)
    ));
    let ambiguous = [
        Event3SessionMetadata {
            session_id: &source_id,
            agent: None,
            model: None,
            provider: None,
        },
        Event3SessionMetadata {
            session_id: &derived_id,
            agent: None,
            model: None,
            provider: None,
        },
    ];
    assert!(matches!(
        project_event3(
            &evaluation,
            &Event3CompatibilityContext {
                sessions: &ambiguous,
                ..context()
            }
        ),
        Err(ProcessingError::Projection)
    ));
    let one_origin = [Event3SessionMetadata {
        session_id: &source_id,
        agent: Some("synthetic-agent"),
        model: None,
        provider: None,
    }];
    assert!(matches!(
        project_event3(
            &evaluation,
            &Event3CompatibilityContext {
                sessions: &one_origin,
                ..context()
            }
        ),
        Err(ProcessingError::Projection)
    ));
}

#[test]
fn canonical_source_hash_is_required_without_normalization() {
    let observations = [message(
        "hash",
        Some("session"),
        "needle",
        CapabilityAvailability::Supported,
    )];
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    let canonical = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let projected = super::event3::project_event3(
        &evaluation,
        &super::event3::Event3CompatibilityContext {
            source_path_hash: canonical,
            sessions: &[],
        },
    )
    .unwrap();
    assert_eq!(
        projected.events[0].source_path_hash.as_deref(),
        Some(canonical)
    );
    for invalid in [
        "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD",
        "abcdef",
        "gbcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    ] {
        assert!(matches!(
            super::event3::project_event3(
                &evaluation,
                &super::event3::Event3CompatibilityContext {
                    source_path_hash: invalid,
                    sessions: &[],
                }
            ),
            Err(ProcessingError::Projection)
        ));
    }
}

#[test]
fn source_instance_none_keeps_deterministic_singletons_and_limited_visibility() {
    let observations = [
        observation("one", Some("same"), Some("2026-09-17T00:00:00Z"), 1),
        observation("two", Some("same"), Some("2026-09-17T00:00:01Z"), 2),
    ];
    let rules = load_default_rule_set().unwrap();
    let compatibility = compile_rule_v1(&rules.compatibility_export()).unwrap();
    let unverified = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: None,
            observations: &observations,
        },
        &compatibility,
        None,
    )
    .unwrap();
    assert_eq!(unverified.sessions().len(), 2);
    assert_eq!(
        unverified.completion(),
        EvaluationCompletion::VisibilityLimited
    );
    assert!(unverified.source_instance().is_none());
    let session_ids = unverified
        .sessions()
        .iter()
        .map(|session| session.session_id().unwrap().value())
        .collect::<Vec<_>>();
    assert_eq!(session_ids, ["same", "same"]);

    let instance = CorrelationId::source_reported("verified").unwrap();
    let verified = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &observations,
        },
        &compatibility,
        None,
    )
    .unwrap();
    assert_eq!(verified.sessions().len(), 1);
}

#[test]
fn reordered_inputs_have_identical_replay_stable_event3_semantics() {
    fn semantics(events: &[telltale_schema::event::Event]) -> Vec<String> {
        events
            .iter()
            .map(|event| {
                serde_json::to_string(&(
                    &event.session_id,
                    &event.rule_ids,
                    event.risk_score,
                    event
                        .evidence
                        .iter()
                        .map(|item| (&item.field, &item.hash, &item.rule_id))
                        .collect::<Vec<_>>(),
                    &event.timeline_anchors,
                    &event.event_time,
                ))
                .unwrap()
            })
            .collect()
    }
    let forward = [
        observation("later", Some("session"), Some("2026-09-17T00:01:00Z"), 2),
        message(
            "match",
            Some("session"),
            "needle",
            CapabilityAvailability::Supported,
        ),
    ];
    let reversed = [forward[1].clone(), forward[0].clone()];
    let first =
        super::event3::project_event3(&evaluate(&forward, &plan(0)).unwrap(), &context()).unwrap();
    let second =
        super::event3::project_event3(&evaluate(&reversed, &plan(0)).unwrap(), &context()).unwrap();
    assert_eq!(semantics(&first.events), semantics(&second.events));
}

#[test]
fn caller_controlled_identity_and_metadata_bounds_fail_without_content_leaks() {
    let marker = "S".repeat(MAX_COMPATIBILITY_STRING_BYTES + 1);
    let instance = CorrelationId::source_reported(&marker).unwrap();
    let observations = [observation("bounded", Some("session"), None, 1)];
    let error = match evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &observations,
        },
        &plan(0),
        None,
    ) {
        Err(error) => error,
        Ok(_) => panic!("oversized source identity accepted"),
    };
    assert_eq!(error, ProcessingError::Bounds);
    assert!(!error.to_string().contains(&marker));
    assert!(!format!("{error:?}").contains(&marker));

    let evaluation = evaluate(
        &[message(
            "metadata-bound",
            Some("session"),
            "needle",
            CapabilityAvailability::Supported,
        )],
        &plan(0),
    )
    .unwrap();
    let session_id = CorrelationId::source_reported("session").unwrap();
    let metadata = [super::event3::Event3SessionMetadata {
        session_id: &session_id,
        agent: Some(&marker),
        model: None,
        provider: None,
    }];
    let error = match super::event3::project_event3(
        &evaluation,
        &super::event3::Event3CompatibilityContext {
            sessions: &metadata,
            ..context()
        },
    ) {
        Err(error) => error,
        Ok(_) => panic!("oversized metadata accepted"),
    };
    assert_eq!(error, ProcessingError::Bounds);
    assert!(!error.to_string().contains(&marker));
    assert!(!format!("{error:?}").contains(&marker));
}

#[test]
fn retention_budget_accepts_exact_limits_and_rejects_incremental_overage() {
    let mut exact = RetentionBudget::new();
    exact
        .consume(MAX_PROJECTION_ITEMS, MAX_COMPATIBILITY_RETAINED_BYTES)
        .unwrap();
    assert_eq!(exact.consume(1, 0), Err(ProcessingError::Bounds));
    assert_eq!(exact.consume(0, 1), Err(ProcessingError::Bounds));

    let mut incremental = RetentionBudget::new();
    incremental
        .consume(
            MAX_PROJECTION_ITEMS - 1,
            MAX_COMPATIBILITY_RETAINED_BYTES - 1,
        )
        .unwrap();
    incremental.consume(1, 1).unwrap();
}

#[test]
fn event3_projection_budget_failure_is_atomic() {
    // Evaluation remains within its retained-context budget; projection's
    // independent item budget must reject before constructing a partial batch.
    let text = format!("needle {}", "ordinary synthetic text ".repeat(30));
    let observations = (0..2000)
        .map(|index| {
            message(
                &format!("synthetic-{index}"),
                Some("session"),
                &text,
                CapabilityAvailability::Supported,
            )
        })
        .collect::<Vec<_>>();
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    assert!(matches!(
        super::event3::project_event3(&evaluation, &context()),
        Err(ProcessingError::Bounds)
    ));
}

#[test]
fn event3_occurrence_modifier_copies_are_preflight_charged() {
    let mut document = "version: 1\ndescription: synthetic\ndefaults: { case_insensitive: false, enabled: true }\nrules:\n  - id: synthetic.atomic\n    category: synthetic\n    severity: low\n    score: 1\n    targets: [user_context]\n    regex: needle\n    tags: []\n    explanation: synthetic\nmodifiers:\n".to_owned();
    for index in 0..30 {
        document.push_str(&format!("  - id: chain.synthetic_{index}\n    score: 0\n    when_all_rule_ids: [synthetic.atomic]\n    explanation: synthetic\n"));
    }
    let plan = compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[&document], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap();
    let observations = (0..100)
        .map(|index| {
            message(
                &format!("synthetic-{index}"),
                Some("session"),
                "needle",
                CapabilityAvailability::Supported,
            )
        })
        .collect::<Vec<_>>();
    let evaluation = evaluate(&observations, &plan).unwrap();
    assert!(matches!(
        super::event3::project_event3(&evaluation, &context()),
        Err(ProcessingError::Bounds)
    ));
}

#[test]
fn duplicate_observations_and_mismatched_sources_fail_before_evaluation() {
    let first = observation("one", Some("session"), None, 1);
    assert!(matches!(
        evaluate(&[first.clone(), first.clone()], &plan(0)),
        Err(ProcessingError::DuplicateObservation)
    ));
    let observations = [first];
    assert!(matches!(
        evaluate_source(
            CanonicalSourceInput {
                client: ClientId::Codex,
                source_id: "codex.sessions",
                source_instance: None,
                observations: &observations
            },
            &plan(0),
            None
        ),
        Err(ProcessingError::InvalidSource)
    ));
}

#[test]
fn collapsed_process_variants_keep_truthful_correlation_step_evidence() {
    let rules = telltale_rules::process_chain::load_process_chain_rules(r#"
version: 1
description: synthetic variant projection
defaults: { enabled: true, risk_entity: host, suppression_window_seconds: 3600 }
categories:
  discovery: { detection_class: security_detection, analytic_intent: alert, investigation_fields: [], falsepositives: [] }
rules: []
standalone:
  - { id: procchain.synthetic.command, title: command, category: discovery, severity: informational, score: 0, confidence: low, match: command_line, patterns: ["\\b(hostname|whoami)\\b"], mitre: [T1082], reason: command }
correlations:
  - id: procchain.correlation.synthetic_children
    title: child sequence
    category: discovery
    severity: medium
    score: 45
    confidence: medium
    mitre: [T1082]
    reason: child sequence
    window_seconds: 60
    entity: host
    sequence:
      - { any_rule_id: [procchain.synthetic.command], any_child: [hostname] }
      - { any_rule_id: [procchain.synthetic.command], any_child: [whoami] }
"#).unwrap();
    let observations = [command(
        "variants",
        "cmd.exe /c hostname && cmd.exe /c whoami",
        Some("2026-09-17T00:00:00Z"),
        0,
    )];
    let instance = CorrelationId::source_reported("instance").unwrap();
    let config = crate::process_chain::ProcessChainConfig::default();
    let output = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &observations,
        },
        &plan(0),
        Some((&rules, &config)),
    )
    .unwrap();
    let events = super::event3::project_event3(&output, &context())
        .unwrap()
        .events;
    let atomic = events
        .iter()
        .find(|e| e.rule_ids[0] == "procchain.synthetic.command")
        .unwrap();
    assert!(
        atomic
            .evidence
            .iter()
            .any(|e| e.field == "process_context_variant")
    );
    let correlation = events
        .iter()
        .find(|e| e.rule_ids[0] == "procchain.correlation.synthetic_children")
        .unwrap();
    let steps = correlation
        .evidence
        .iter()
        .filter(|e| e.field == "correlation_process_step")
        .collect::<Vec<_>>();
    assert_eq!(steps.len(), 2);
    assert!(steps[0].redacted_value.contains("hostname"));
    assert!(steps[1].redacted_value.contains("whoami"));
}

#[test]
fn retained_process_context_markers_do_not_survive_terminal_event3() {
    let markers = [
        "api_key=tt_SYNTHETIC_COMMAND_SECRET_123456789",
        "api_key=tt_SYNTHETIC_TITLE_SECRET_123456789",
        "api_key=tt_SYNTHETIC_REASON_SECRET_123456789",
        "api_key=tt_SYNTHETIC_INVESTIGATION_SECRET_123456789",
        "api_key=tt_SYNTHETIC_FALSEPOSITIVE_SECRET_123456789",
    ];
    let document = format!(
        r#"
version: 1
description: synthetic privacy
defaults: {{ enabled: true, risk_entity: host, suppression_window_seconds: 3600 }}
categories:
  discovery:
    detection_class: security_detection
    analytic_intent: alert
    investigation_fields: ["{}"]
    falsepositives: ["{}"]
rules:
  - id: procchain.synthetic.privacy
    title: "{}"
    category: discovery
    severity: low
    score: 20
    confidence: low
    parent: cmd
    child: whoami
    mitre: [T1087]
    reason: "{}"
standalone: []
correlations: []
"#,
        markers[3], markers[4], markers[1], markers[2]
    );
    let rules = telltale_rules::process_chain::load_process_chain_rules(&document).unwrap();
    let command_text = format!(r#"cmd.exe /c whoami C:\private\token.txt {}"#, markers[0]);
    let observations = [command(
        "privacy-context",
        &command_text,
        Some("2026-09-17T00:00:00Z"),
        0,
    )];
    let instance = CorrelationId::source_reported("privacy-instance").unwrap();
    let evaluation = evaluate_source(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &observations,
        },
        &plan(0),
        Some((&rules, &crate::process_chain::ProcessChainConfig::default())),
    )
    .unwrap();
    let serialized = serde_json::to_string(
        &super::event3::project_event3(&evaluation, &context())
            .unwrap()
            .events,
    )
    .unwrap();
    for marker in markers {
        assert!(!serialized.contains(marker));
    }
    assert!(!serialized.contains(r#"C:\private\token.txt"#));
}
