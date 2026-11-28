use super::*;

#[test]
#[cfg(feature = "opencode-sqlite")]
fn opencode_sqlite_messages_join_shared_message_semantics() {
    let (_directory, opencode) = project_opencode(
        &[
            (
                "message-user",
                "opencode-conformance",
                serde_json::json!({
                    "type": "user",
                    "role": "user",
                    "content": "Synthetic user message."
                }),
            ),
            (
                "message-assistant",
                "opencode-conformance",
                serde_json::json!({
                    "type": "assistant",
                    "role": "assistant",
                    "content": "Synthetic assistant message."
                }),
            ),
        ],
        &[],
    );
    let opencode = opencode.expect("OpenCode message vector");
    assert_eq!(opencode.len(), 2);
    assert_eq!(opencode[0].kind(), ObservationFamily::Message);
    assert_eq!(opencode[0].stage(), ObservationStage::MessageObserved);
    assert_eq!(opencode[1].kind(), ObservationFamily::Message);
    assert_eq!(opencode[1].stage(), ObservationStage::MessageObserved);
    let ObservationBody::Message(user) = opencode[0].body() else {
        panic!("expected OpenCode user message")
    };
    assert_eq!(
        user.role(),
        Some(telltale_schema::observation::MessageRole::User)
    );
    let ObservationBody::Message(assistant) = opencode[1].body() else {
        panic!("expected OpenCode assistant message")
    };
    assert_eq!(
        assistant.role(),
        Some(telltale_schema::observation::MessageRole::Assistant)
    );
    assert_eq!(opencode[0].source().native_id(), Some("message-user"));
    assert_eq!(opencode[1].source().native_id(), Some("message-assistant"));
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn opencode_sqlite_tool_overlap_preserves_call_linkage_values_and_facets() {
    let (_directory, opencode) = project_opencode_native(
        &[(
            "tool-context",
            "opencode-tool-conformance",
            serde_json::json!({"role":"assistant"}),
        )],
        &[
            (
                "part-request",
                "tool-context",
                1,
                serde_json::json!({
                    "type":"tool","tool":"Read","callID":"call-conformance",
                    "state":{"status":"pending","input":{"file_path":"synthetic.txt"}}
                }),
            ),
            (
                "part-result",
                "tool-context",
                2,
                serde_json::json!({
                    "type":"tool","tool":"Read","callID":"call-conformance",
                    "state":{"status":"completed","input":{"file_path":"synthetic.txt"},"output":{"status":"ok"}}
                }),
            ),
        ],
    );
    let opencode = opencode.expect("OpenCode tool vector");
    let request = opencode
        .iter()
        .find(|item| item.stage() == ObservationStage::ToolRequested)
        .expect("OpenCode request");
    let result = opencode
        .iter()
        .find(|item| item.stage() == ObservationStage::ToolResultReturned)
        .expect("OpenCode result");
    assert_eq!(request.kind(), ObservationFamily::Tool);
    assert_eq!(result.kind(), ObservationFamily::Tool);
    assert_eq!(
        request.correlation().call_id().unwrap().value(),
        "call-conformance"
    );
    assert_eq!(
        result.correlation().call_id().unwrap().value(),
        "call-conformance"
    );
    let ObservationBody::Tool(request_body) = request.body() else {
        panic!("expected request body")
    };
    assert_eq!(
        request_body.arguments(),
        Some(
            &JsonValue::object([("file_path".to_owned(), JsonValue::string("synthetic.txt"))])
                .unwrap()
        )
    );
    let ObservationBody::Tool(result_body) = result.body() else {
        panic!("expected result body")
    };
    assert_eq!(
        result_body.result(),
        Some(&JsonValue::object([("status".to_owned(), JsonValue::string("ok"))]).unwrap())
    );
    assert_eq!(
        request.facets()["resource.path"].value(),
        &JsonValue::string("synthetic.txt")
    );
    assert!(opencode.iter().all(|item| !matches!(
        item.kind(),
        ObservationFamily::File | ObservationFamily::Process | ObservationFamily::Network
    )));
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn opencode_sqlite_missing_call_id_is_absent_and_not_derived() {
    let (_directory, opencode) = project_opencode_native(
        &[(
            "tool-context",
            "opencode-missing-call",
            serde_json::json!({"role":"assistant"}),
        )],
        &[(
            "part-no-call",
            "tool-context",
            1,
            serde_json::json!({
                "type":"tool","tool":"shell",
                "state":{"status":"pending","input":{"command":"printf synthetic"}}
            }),
        )],
    );
    let opencode = opencode.expect("OpenCode missing-call vector");
    let tool = opencode
        .iter()
        .find(|item| item.kind() == ObservationFamily::Tool)
        .expect("OpenCode tool");
    assert_eq!(tool.correlation().call_id(), None);
    assert_eq!(tool.source().native_id(), Some("part-no-call"));
}

#[test]
#[cfg(feature = "opencode-sqlite")]
fn opencode_sqlite_direct_lifecycle_is_supported_without_inferred_success() {
    let (_directory, opencode) = project_opencode_native(
        &[(
            "tool-context",
            "opencode-lifecycle",
            serde_json::json!({"role":"assistant"}),
        )],
        &[
            (
                "part-running",
                "tool-context",
                1,
                serde_json::json!({
                    "type":"tool","tool":"shell","callID":"call-running",
                    "state":{"status":"running","input":{"command":"printf synthetic"}}
                }),
            ),
            (
                "part-completed",
                "tool-context",
                2,
                serde_json::json!({
                    "type":"tool","tool":"shell","callID":"call-completed",
                    "state":{"status":"completed","output":"Synthetic output"}
                }),
            ),
        ],
    );
    let opencode = opencode.expect("OpenCode lifecycle vector");
    let running = opencode
        .iter()
        .find(|item| item.source().native_id() == Some("part-running"))
        .expect("running observation");
    assert_eq!(running.stage(), ObservationStage::ToolExecutionStarted);
    let completed = opencode
        .iter()
        .find(|item| {
            item.source().native_id() == Some("part-completed")
                && item.stage() == ObservationStage::ToolExecutionCompleted
        })
        .expect("completed observation");
    assert_eq!(completed.stage(), ObservationStage::ToolExecutionCompleted);
    let ObservationBody::Tool(body) = completed.body() else {
        panic!("expected completed tool")
    };
    assert_eq!(body.reported_status(), None);
    assert_eq!(body.is_error(), None);
    assert!(opencode.iter().all(|item| {
        item.capability_context()
            .expect("capabilities")
            .resolve(CapabilityId::ToolExecution)
            == CapabilityAvailability::Supported
    }));
    assert!(
        opencode
            .iter()
            .all(|item| item.stage() != ObservationStage::ToolRequested)
    );
    assert!(
        opencode
            .iter()
            .all(|item| item.stage() != ObservationStage::ToolProposed)
    );
    assert!(
        opencode
            .iter()
            .all(|item| item.body().kind() == ObservationFamily::Tool)
    );
    assert_eq!(body.reported_status(), None::<ToolStatus>);
}
