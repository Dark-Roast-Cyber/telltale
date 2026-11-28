use super::*;

#[test]
fn action_evidence_sanitizer_reservation_uses_shared_budget() {
    let export = sanitizer_budget_rules();
    let compiled = super::super::super::actions::compile(&export).unwrap();
    let observation = tool(
        "encoded-evidence",
        &format!("echo MATCH {}", "%25".repeat(1333)),
        None,
    );
    let mut budget = super::super::super::session::RetentionBudget::new();
    budget
        .charge(super::super::super::session::MAX_EVALUATION_BYTE_VISITS - 1024 * 1024)
        .unwrap();
    assert!(matches!(
        super::super::super::actions::evaluate(
            &export,
            &compiled,
            &[&observation],
            &DetailedEvaluationOptions::default(),
            &mut budget
        ),
        Err(ProcessingError::Bounds)
    ));
}

#[test]
fn action_context_sanitizer_reservation_fails_source_atomically() {
    let export = sanitizer_budget_rules();
    let plan = compile_rule_v1(&export).unwrap();
    let observations = [
        tool("encoded-context", &"%25".repeat(1333), None),
        tool("match", "echo MATCH", None),
    ];
    let mut options = DetailedEvaluationOptions::default();
    options.context.before = 1;
    options.context.tool_arguments = true;
    let instance = CorrelationId::source_reported("synthetic-source").unwrap();
    let input = || CanonicalSourceInput {
        client: ClientId::Claude,
        source_id: "claude.projects",
        source_instance: Some(&instance),
        observations: &observations,
    };
    let used = super::super::super::session::MAX_EVALUATION_BYTE_VISITS - 1024 * 1024;
    let ordinary = EvaluationWorkBudget::with_used_bytes(used);
    super::super::super::session::evaluate_source_with_work_budget(input(), &plan, None, &ordinary)
        .unwrap();
    assert!(!ordinary.is_exhausted());
    let work = EvaluationWorkBudget::with_used_bytes(used);
    assert!(matches!(
        super::super::super::session::evaluate_source_with_options_and_work_budget(
            input(),
            &plan,
            None,
            &options,
            &work
        ),
        Err(ProcessingError::Bounds)
    ));
    assert!(work.is_exhausted());
}

#[test]
fn action_nonmatches_exhaust_the_shared_work_budget() {
    let export = telltale_rules::load_default_rule_set()
        .unwrap()
        .compatibility_export();
    let compiled = super::super::super::actions::compile(&export).unwrap();
    let observation = tool("nonmatch", &"x".repeat(4096), None);
    let mut budget = super::super::super::session::RetentionBudget::new();
    budget
        .charge(super::super::super::session::MAX_EVALUATION_BYTE_VISITS - 1024)
        .unwrap();
    assert!(matches!(
        super::super::super::actions::evaluate(
            &export,
            &compiled,
            &[&observation],
            &DetailedEvaluationOptions::default(),
            &mut budget
        ),
        Err(ProcessingError::Bounds)
    ));
}

#[test]
fn each_reached_nonmatching_action_matcher_charges_work() {
    let document = |count| {
        let yaml = (0..count)
            .map(|index| format!("title: Synthetic {index}\nid: 00000000-0000-4000-8000-{index:012}\nname: synthetic.nonmatch{index}\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: tool_activity\ndetection:\n    selection:\n        - tool.command|re: NEVER-MATCH\n    condition: selection\nlevel: low\ntelltale:\n    category: synthetic\n    score: 1\n    explanation: synthetic\n"))
            .collect::<Vec<_>>()
            .join("---\n");
        telltale_rules::load_rule_set_from_documents(&[&yaml], None)
            .unwrap()
            .compatibility_export()
    };
    let observation = tool("nonmatch", &"x".repeat(4096), None);
    let one = document(1);
    let mut measured = super::super::super::session::RetentionBudget::new();
    assert!(
        super::super::super::actions::evaluate(
            &one,
            &super::super::super::actions::compile(&one).unwrap(),
            &[&observation],
            &DetailedEvaluationOptions::default(),
            &mut measured
        )
        .unwrap()
        .0
        .is_empty()
    );
    let used = measured
        .work_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    let two = document(2);
    let mut budget = super::super::super::session::RetentionBudget::new();
    budget
        .charge(super::super::super::session::MAX_EVALUATION_BYTE_VISITS - used)
        .unwrap();
    assert!(matches!(
        super::super::super::actions::evaluate(
            &two,
            &super::super::super::actions::compile(&two).unwrap(),
            &[&observation],
            &DetailedEvaluationOptions::default(),
            &mut budget
        ),
        Err(ProcessingError::Bounds)
    ));
}

#[test]
fn detailed_source_work_failure_returns_no_partial_evaluation() {
    let plan = crate::v2::bundled_plan();
    let observations = [
        tool("match", "cat .env", None),
        tool("nonmatch", &"x".repeat(4096), None),
    ];
    let instance = CorrelationId::source_reported("synthetic-source").unwrap();
    let measured = EvaluationWorkBudget::default();
    let input = || CanonicalSourceInput {
        client: ClientId::Claude,
        source_id: "claude.projects",
        source_instance: Some(&instance),
        observations: &observations,
    };
    let complete = super::super::super::session::evaluate_source_with_options_and_work_budget(
        input(),
        plan,
        None,
        &DetailedEvaluationOptions::default(),
        &measured,
    )
    .unwrap();
    assert!(!complete.sessions()[0].action_findings().is_empty());
    let work = EvaluationWorkBudget::with_used_bytes(
        super::super::super::session::MAX_EVALUATION_BYTE_VISITS - measured.used_bytes() + 1,
    );
    assert!(matches!(
        super::super::super::session::evaluate_source_with_options_and_work_budget(
            input(),
            plan,
            None,
            &DetailedEvaluationOptions::default(),
            &work
        ),
        Err(ProcessingError::Bounds)
    ));
    assert!(work.is_exhausted());
}

#[test]
fn second_review_large_harmless_timed_batch_has_no_sequence_state() {
    let observations = (0..4000)
        .map(|index| {
            tool(
                &format!("harmless-{index}"),
                "echo ordinary",
                Some("2026-09-17T00:00:00Z"),
            )
        })
        .collect::<Vec<_>>();
    assert!(
        actions(&observations).sessions()[0]
            .action_findings()
            .is_empty()
    );
}

#[test]
fn large_shell_credit_batches_preserve_late_detection_and_match_counts() {
    assert_large_shell_credit_batch(ClientId::Claude, "claude.projects", "Bash", false);
}

#[test]
fn large_codex_shell_credit_batch() {
    assert_large_shell_credit_batch(ClientId::Codex, "codex.sessions", "exec_command", false);
}

#[test]
fn large_opencode_shell_credit_batch() {
    assert_large_shell_credit_batch(ClientId::OpenCode, "opencode.sqlite", "shell", false);
}

#[test]
fn large_legacy_codex_shell_credit_batch() {
    assert_large_shell_credit_batch(ClientId::Codex, "codex.sessions", "shell", true);
}

fn assert_large_shell_credit_batch(client: ClientId, source_id: &str, name: &str, wrapper: bool) {
    let observation = |index, command: &str| {
        let arguments = if name == "exec_command" {
            serde_json::json!({"cmd":command})
        } else {
            serde_json::json!({"command":command})
        };
        CanonicalObservationV2::builder(
            ObservationBody::Tool(
                ToolObservation::new()
                    .with_name(name)
                    .unwrap()
                    .with_arguments(JsonValue::try_from_source_value(&arguments).unwrap()),
            ),
            ObservationStage::ToolRequested,
            ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
            SourceProvenance::new(
                IngestionMode::SessionStore,
                if client == ClientId::Claude {
                    "claude_code"
                } else {
                    client.as_str()
                },
                source_id,
                Fidelity::FullNative,
            )
            .unwrap()
            .with_native_id(format!("harmless-{index}"))
            .unwrap(),
        )
        .session_id(CorrelationId::source_reported("synthetic-session").unwrap())
        .sequence(index)
        .occurred_at(SourceTimestamp::new("2026-09-17T00:00:00Z").unwrap())
        .facet(
            "command.text",
            SemanticFacet::new(JsonValue::string(command)),
        )
        .unwrap()
        .fact_metadata("command.text", FactMetadata::parsed().unwrap())
        .fact_metadata("tool.name", FactMetadata::reported().unwrap())
        .fact_metadata("tool.arguments", FactMetadata::reported().unwrap())
        .capability_context(
            CapabilityContext::new()
                .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported),
        )
        .build()
        .unwrap()
    };
    let command = if wrapper {
        "bash -lc 'echo ordinary'"
    } else {
        "echo ordinary"
    };
    let mut observations = (0..4000)
        .map(|index| observation(index, command))
        .collect::<Vec<_>>();
    let plan = crate::v2::bundled_plan();
    let instance = CorrelationId::source_reported("synthetic-source").unwrap();
    let evaluate = |observations: &[CanonicalObservationV2]| {
        let input = CanonicalSourceInput {
            client,
            source_id,
            source_instance: Some(&instance),
            observations,
        };
        if wrapper {
            evaluate_source(input, plan, None)
        } else {
            evaluate_source_with_options(input, plan, None, &DetailedEvaluationOptions::default())
        }
        .unwrap()
    };
    let output = evaluate(&observations);
    let session = &output.sessions()[0];
    assert_eq!(session.rule_score(), 15, "{source_id}");
    assert_eq!(session.rule_ids(), ["execution.shell"]);
    assert!(session.action_findings().is_empty());
    let shell = session
        .detectors()
        .iter()
        .find(|d| d.detector_id() == "execution.shell")
        .unwrap();
    assert_eq!(shell.evaluated_match_count(), 4000);
    assert!(
        session.rules.projection().count() <= 3,
        "only representative shell-credit evidence is retained"
    );
    observations.push(observation(
        4000,
        "systemctl --user enable synthetic-preview.service",
    ));
    let output = evaluate(&observations);
    assert_eq!(
        output.sessions()[0].rule_score(),
        60,
        "late persistence must still be detected: {source_id}"
    );
    assert_eq!(
        output.sessions()[0].rule_ids(),
        ["execution.shell", "persistence.shell_profile"]
    );
}

#[test]
fn second_review_predecessor_search_exhausts_explicit_work_budget() {
    let timestamp = time::OffsetDateTime::UNIX_EPOCH;
    let mut remaining = 1;
    assert!(
        crate::process_chain_session::ordered_predecessors(
            100,
            time::Duration::minutes(15),
            2,
            |_| timestamp,
            |step, index| step == 1 && index == 100,
            &mut remaining
        )
        .is_err()
    );
    assert_eq!(remaining, 0);
}
