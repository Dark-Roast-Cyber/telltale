use super::*;

#[test]
fn only_command_bearing_tool_evidence_is_eligible() {
    let rules = load_default_process_chain_rules().unwrap();
    let message = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User)
                .with_content(JsonValue::string("cmd.exe /c whoami")),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source("message"),
    )
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .fact_metadata("message.content", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    let name_only = tool(
        ObservationStage::ToolRequested,
        None,
        None,
        None,
        "cmd.exe /c whoami",
        "name-only",
    );
    let result_stage = tool(
        ObservationStage::ToolResultReturned,
        Some("cmd.exe /c whoami"),
        Some("cmd.exe /c whoami"),
        Some(JsonValue::string("cmd.exe /c whoami")),
        "shell",
        "result-stage",
    );
    let object_arguments = tool(
        ObservationStage::ToolRequested,
        None,
        None,
        Some(JsonValue::Object(BTreeMap::from([(
            "command".to_owned(),
            JsonValue::string("cmd.exe /c whoami"),
        )]))),
        "shell",
        "object",
    );
    let parsed_searchable = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .unwrap()
                .with_searchable_arguments("cmd.exe /c whoami")
                .unwrap(),
        ),
        ObservationStage::ToolRequested,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source("parsed-searchable"),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata(
        "tool.searchable_arguments",
        metadata(FactProvenance::Parsed),
    )
    .build()
    .unwrap();

    for observation in [
        &message,
        &name_only,
        &result_stage,
        &object_arguments,
        &parsed_searchable,
    ] {
        assert!(
            evaluate_tool_process_chains(&rules, observation, &ProcessChainContext::default(),)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn identical_command_surfaces_are_parsed_once() {
    let observation = tool(
        ObservationStage::ToolRequested,
        Some("cmd.exe /c whoami"),
        Some("cmd.exe /c whoami"),
        Some(JsonValue::string("cmd.exe /c whoami")),
        "shell",
        "candidate-dedupe",
    );
    assert_eq!(command_candidates(&observation), ["cmd.exe /c whoami"]);
    assert_eq!(
        command_derived_process_matcher_inputs(&observation).len(),
        1
    );
}

#[test]
fn distinct_command_surfaces_are_evaluated_without_duplicate_result_identity() {
    let observation = tool(
        ObservationStage::ToolRequested,
        Some("cmd.exe /c whoami"),
        Some("cmd.exe /c hostname"),
        Some(JsonValue::string("cmd /c whoami /all")),
        "shell",
        "distinct-candidates",
    );
    let results = evaluate_tool_process_chains(
        &load_default_process_chain_rules().unwrap(),
        &observation,
        &ProcessChainContext::default(),
    )
    .unwrap();
    let ids = results
        .iter()
        .map(|result| result.detector().id())
        .collect::<BTreeSet<_>>();
    assert!(ids.contains("procchain.discovery.cmd_whoami"));
    assert!(ids.contains("procchain.discovery.cmd_hostname"));
    assert_eq!(
        results
            .iter()
            .filter(|result| result.detector().id() == "procchain.discovery.cmd_whoami")
            .count(),
        1,
        "one Tool observation must not emit duplicate Signal identity"
    );
    let signal_ids = results
        .iter()
        .map(|result| result.signal().unwrap().unwrap().signal_id().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(signal_ids.len(), results.len());
    assert!(
        results
            .windows(2)
            .all(|pair| { pair[0].detector().id() <= pair[1].detector().id() })
    );
}

#[test]
fn lifecycle_stage_policy_is_source_neutral_and_excludes_results() {
    let rules = load_default_process_chain_rules().unwrap();
    for (stage, id) in [
        (ObservationStage::ToolProposed, "proposed"),
        (ObservationStage::ToolRequested, "requested"),
        (ObservationStage::ToolExecutionStarted, "started"),
        (ObservationStage::ToolExecutionCompleted, "completed"),
    ] {
        let observation = tool(stage, Some("cmd.exe /c whoami"), None, None, "shell", id);
        assert!(
            evaluate_tool_process_chains(&rules, &observation, &ProcessChainContext::default(),)
                .unwrap()
                .iter()
                .any(|result| result.detector().id() == "procchain.discovery.cmd_whoami")
        );
    }
    let returned = tool(
        ObservationStage::ToolResultReturned,
        Some("cmd.exe /c whoami"),
        None,
        None,
        "shell",
        "returned",
    );
    assert!(
        evaluate_tool_process_chains(&rules, &returned, &ProcessChainContext::default())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn process_chain_materialization_debug_does_not_expose_command_evidence() {
    let marker = "synthetic-secret-marker-C:\\private\\token.txt";
    let command = format!("cmd.exe /c whoami {marker}");
    let results = default_results(&command, "privacy");
    let matched = result(&results, "procchain.discovery.cmd_whoami");
    let signal = matched.signal().unwrap().expect("signal");
    let finding = signal.finding().expect("finding");
    for debug in [
        format!("{matched:?}"),
        format!("{signal:?}"),
        format!("{finding:?}"),
    ] {
        assert!(!debug.contains(marker), "debug leaked command evidence");
        assert!(!debug.contains("private"), "debug leaked a path");
    }
}

#[test]
fn canonical_process_observations_are_not_consumed() {
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Process(CanonicalProcess::new().with_operation("exec").unwrap()),
        ObservationStage::ProcessObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source("direct-process"),
    )
    .fact_metadata("process.operation", metadata(FactProvenance::Observed))
    .build()
    .unwrap();
    assert!(
        evaluate_tool_process_chains(
            &load_default_process_chain_rules().unwrap(),
            &observation,
            &ProcessChainContext::default(),
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn only_process_chain_is_newly_runtime_supported() {
    let metadata = FindingMetadata::new(
        FindingKind::Informational,
        "synthetic",
        Severity::Informational,
    )
    .unwrap();
    let process_chain = DetectorResult::new(
        DetectorIdentity::new(DetectorKind::ProcessChain, "procchain.synthetic").unwrap(),
        EvaluationStatus::EvaluatedNoMatch,
        metadata.clone(),
    );
    assert!(process_chain.is_ok());

    for kind in [
        DetectorKind::Sequence,
        DetectorKind::Correlation,
        DetectorKind::Imported,
        DetectorKind::Baseline,
        DetectorKind::GuardModel,
    ] {
        assert_eq!(
            DetectorResult::new(
                DetectorIdentity::new(kind, "synthetic.unsupported").unwrap(),
                EvaluationStatus::EvaluatedNoMatch,
                metadata.clone(),
            )
            .unwrap_err(),
            DetectionError::UnsupportedDetectorKind
        );
        assert!(
            DetectorResult::not_evaluated(
                DetectorIdentity::new(kind, "synthetic.unsupported").unwrap(),
                NonEvaluationReason::IneligibleInput,
                metadata.clone(),
            )
            .is_ok()
        );
    }
}
