use super::*;

#[test]
fn openclaw_and_qwen_tool_facts_keep_unknown_execution_and_parsed_facets() {
    let (_openclaw_dir, openclaw) = project_openclaw(
        r#"{"type":"tool_call","sessionId":"openclaw-facets","call_id":"call-facets","name":"shell","arguments":{"command":"printf synthetic","file_path":"synthetic.txt"}}"#,
    );
    let (_qwen_dir, qwen) = project_qwen(
        r#"{"type":"tool_call","sessionId":"qwen-facets","call_id":"call-facets","name":"shell","arguments":{"command":"printf synthetic","file_path":"synthetic.txt"}}"#,
    );
    let openclaw = openclaw.expect("OpenClaw facet vector");
    let qwen = qwen.expect("Qwen facet vector");
    assert_semantically_equal(&openclaw[0], &qwen[0]);

    for observations in [&openclaw, &qwen] {
        assert_partial_session_capabilities(observations);
        let tool = observations
            .iter()
            .find(|item| item.kind() == ObservationFamily::Tool)
            .expect("tool observation");
        assert_eq!(
            tool.facets()["command.text"].value(),
            &JsonValue::string("printf synthetic")
        );
        assert_eq!(
            tool.facets()["resource.path"].value(),
            &JsonValue::string("synthetic.txt")
        );
        assert_eq!(
            tool.fact_metadata()["command.text"].provenance(),
            telltale_schema::observation::FactProvenance::Parsed
        );
        assert_eq!(
            tool.fact_metadata()["resource.path"].provenance(),
            telltale_schema::observation::FactProvenance::Parsed
        );
        assert!(observations.iter().all(|observation| {
            !matches!(
                observation.kind(),
                ObservationFamily::File | ObservationFamily::Process | ObservationFamily::Network
            ) && !matches!(
                observation.stage(),
                ObservationStage::ToolProposed
                    | ObservationStage::ToolExecutionStarted
                    | ObservationStage::ToolExecutionCompleted
            )
        }));
    }
}

#[test]
fn copilot_vectors_preserve_assistant_tools_arguments_and_capability_gaps() {
    let (_directory, result) = project_copilot(
        "2026-09-02T12:00:00Z [INFO] Workspace initialized: copilot-conformance (checkpoints: 0)\n2026-09-02T12:00:01Z [INFO] Accumulated output items (2): [{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Synthetic assistant output.\"}]},{\"type\":\"function_call\",\"name\":\"shell\",\"call_id\":\"copilot-call\",\"arguments\":\"{\\\"command\\\":\\\"printf synthetic\\\",\\\"path\\\":\\\"synthetic.txt\\\"}\",\"status\":\"completed\",\"message\":\"Synthetic result.\"}]\n",
    );
    let observations = result.expect("Copilot conformance vector");
    assert_eq!(observations.len(), 3);
    assert_eq!(observations[0].kind(), ObservationFamily::Message);
    assert_eq!(observations[0].stage(), ObservationStage::MessageObserved);
    assert_eq!(observations[1].stage(), ObservationStage::ToolRequested);
    assert_eq!(
        observations[2].stage(),
        ObservationStage::ToolResultReturned
    );

    for observation in &observations {
        let capabilities = observation
            .capability_context()
            .expect("Copilot capabilities");
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolCall),
            CapabilityAvailability::Supported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::UserContext),
            CapabilityAvailability::Unsupported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Unknown
        );
        assert_eq!(observation.source().adapter_type(), "copilot");
        assert_eq!(observation.source().adapter_id(), "copilot.process_log");
    }

    let ObservationBody::Message(message) = observations[0].body() else {
        panic!("expected Copilot assistant message")
    };
    assert_eq!(message.role(), Some(MessageRole::Assistant));
    assert_eq!(message.content_parts().len(), 1);
    assert_eq!(message.content_parts()[0].kind(), ContentPartKind::Text);
    let ObservationBody::Tool(tool) = observations[1].body() else {
        panic!("expected Copilot tool request")
    };
    assert_eq!(tool.name(), Some("shell"));
    assert_eq!(
        observations[1].correlation().call_id().unwrap().value(),
        "copilot-call"
    );
    assert_eq!(
        tool.arguments(),
        Some(
            &JsonValue::object([
                ("command".to_owned(), JsonValue::string("printf synthetic")),
                ("path".to_owned(), JsonValue::string("synthetic.txt")),
            ])
            .unwrap(),
        )
    );
    assert_eq!(
        observations[1].fact_metadata()["tool.arguments"].provenance(),
        telltale_schema::observation::FactProvenance::Parsed
    );
    assert_eq!(
        observations[1].fact_metadata()["tool.searchable_arguments"].provenance(),
        telltale_schema::observation::FactProvenance::Reported
    );
    assert_eq!(
        observations[1].facets()["command.text"].value(),
        &JsonValue::string("printf synthetic")
    );
    assert_eq!(
        observations[1].facets()["resource.path"].value(),
        &JsonValue::string("synthetic.txt")
    );
    let ObservationBody::Tool(result) = observations[2].body() else {
        panic!("expected Copilot result")
    };
    assert_eq!(
        result.result(),
        Some(&JsonValue::string("Synthetic result."))
    );
}

#[test]
fn openclaw_and_qwen_generic_tool_states_do_not_claim_execution_lifecycle() {
    let vector = |session: &str| {
        format!(
            r#"{{"type":"tool","sessionId":"{session}","tool":"shell","callID":"call-running","state":{{"status":"running","input":{{"command":"printf synthetic"}}}}}}
{{"type":"tool","sessionId":"{session}","tool":"shell","callID":"call-completed","state":{{"status":"completed","output":{{"status":"ok"}}}}}}
{{"type":"tool","sessionId":"{session}","tool":"shell","callID":"call-error","state":{{"status":"error","error":{{"message":"synthetic failure"}}}}}}"#
        )
    };
    let (_openclaw_dir, openclaw) = project_openclaw(&vector("openclaw-generic"));
    let (_qwen_dir, qwen) = project_qwen(&vector("qwen-generic"));

    for observations in [
        openclaw.expect("OpenClaw generic tool vector"),
        qwen.expect("Qwen generic tool vector"),
    ] {
        assert_partial_session_capabilities(&observations);
        assert!(
            observations
                .iter()
                .any(|observation| { observation.stage() == ObservationStage::ToolResultReturned })
        );
        assert!(observations.iter().all(|observation| {
            observation.kind() == ObservationFamily::Tool
                && !matches!(
                    observation.stage(),
                    ObservationStage::ToolProposed
                        | ObservationStage::ToolExecutionStarted
                        | ObservationStage::ToolExecutionCompleted
                )
        }));
    }
}

#[test]
fn parsed_facets_and_capability_gaps_do_not_claim_activity_or_execution() {
    let (_claude_dir, claude) = project_claude(
        r#"{"type":"assistant","sessionId":"claude-facets","message":{"role":"assistant","content":[{"type":"tool_use","id":"call-facets","name":"Read","input":{"file_path":"synthetic.txt"}}]}}"#,
    );
    let (_codex_dir, codex) = project_codex(
        r#"{"type":"tool_call","session_id":"codex-facets","call_id":"call-facets","name":"Read","arguments":{"command":"printf synthetic","file_path":"synthetic.txt"}}"#,
    );
    let claude = claude.expect("Claude facet vector");
    let codex = codex.expect("Codex facet vector");
    let claude_tool = claude
        .iter()
        .find(|item| item.kind() == ObservationFamily::Tool)
        .expect("Claude tool");
    let codex_tool = codex
        .iter()
        .find(|item| item.kind() == ObservationFamily::Tool)
        .expect("Codex tool");
    assert_eq!(
        claude_tool
            .facets()
            .get("resource.path")
            .map(|facet| facet.value()),
        codex_tool
            .facets()
            .get("resource.path")
            .map(|facet| facet.value())
    );
    assert_eq!(
        codex_tool.facets()["command.text"].value(),
        &telltale_schema::observation::JsonValue::string("printf synthetic")
    );
    assert_eq!(
        claude_tool.fact_metadata()["resource.path"].provenance(),
        telltale_schema::observation::FactProvenance::Parsed
    );
    assert_eq!(
        codex_tool.fact_metadata()["command.text"].provenance(),
        telltale_schema::observation::FactProvenance::Parsed
    );
    for observation in claude
        .iter()
        .chain(&codex)
        .filter(|item| item.kind() == ObservationFamily::Tool)
    {
        assert_eq!(
            observation
                .capability_context()
                .expect("capabilities")
                .resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Unsupported
        );
        assert!(!matches!(
            observation.stage(),
            ObservationStage::ToolProposed
                | ObservationStage::ToolExecutionStarted
                | ObservationStage::ToolExecutionCompleted
        ));
        assert!(!matches!(
            observation.kind(),
            ObservationFamily::File | ObservationFamily::Process | ObservationFamily::Network
        ));
    }
}
