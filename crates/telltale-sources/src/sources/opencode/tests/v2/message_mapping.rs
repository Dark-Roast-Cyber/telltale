use super::*;

#[test]
fn fresh_v2_store_maps_messages_tools_and_accounting() {
    let store = Store::v2();
    store.message(
        "msg_001",
        1,
        T0 + 1,
        user("Synthetic request to list files", T0),
    );
    store.message(
        "msg_002",
        2,
        T0 + 30_000,
        assistant(
            json!([
                {"type": "text", "text": "Listing the synthetic workspace."},
                {"type": "reasoning", "text": "synthetic-reasoning-marker"},
                completed_tool("call_ls", "bash", json!({"command": "ls -la"}), "synthetic listing", T0 + 5_000),
            ]),
            T0 + 2_000,
        ),
    );

    let batch = store.acquire_default();
    assert_eq!(
        batch.progress,
        AcquisitionProgress::OpenCodeSessionMessages {
            message_max_time_updated: Some(T0 + 30_000),
            window_complete: true,
        }
    );
    use ObservationStage::*;
    assert_eq!(
        shape(&batch),
        vec![
            ("msg_001".to_owned(), 0, MessageObserved),
            ("msg_002".to_owned(), 0, MessageObserved),
            ("msg_002".to_owned(), 2, ToolRequested),
            ("msg_002".to_owned(), 2, ToolResultReturned),
        ],
        "reasoning is skipped and keeps its content index out of other identities"
    );
    let prompt = find(&batch, "msg_001", 0, MessageObserved);
    assert_eq!(
        message_text(prompt),
        (MessageRole::User, "Synthetic request to list files".into())
    );
    assert_eq!(
        prompt.occurred_at().unwrap().as_str(),
        "2026-03-31T23:33:20Z"
    );
    assert_eq!(
        message_text(find(&batch, "msg_002", 0, MessageObserved)),
        (
            MessageRole::Assistant,
            "Listing the synthetic workspace.".into()
        )
    );

    let request = find(&batch, "msg_002", 2, ToolRequested);
    assert_eq!(tool(request).name(), Some("bash"));
    assert_eq!(
        tool(request).arguments(),
        Some(&JsonValue::object([(String::from("command"), JsonValue::string("ls -la"))]).unwrap())
    );
    assert_eq!(tool(request).result(), None);
    assert_eq!(
        request.occurred_at().unwrap().as_str(),
        "2026-03-31T23:33:25Z"
    );
    let outcome = find(&batch, "msg_002", 2, ToolResultReturned);
    assert_eq!(
        tool(outcome).result(),
        Some(&JsonValue::string("synthetic listing"))
    );
    assert_eq!(tool(outcome).reported_status(), None);
    assert_eq!(tool(outcome).exit_code(), None);
    assert_eq!(
        outcome.occurred_at().unwrap().as_str(),
        "2026-03-31T23:33:27Z"
    );
    for item in [request, outcome] {
        assert_eq!(item.correlation().call_id().unwrap().value(), "call_ls");
        assert_eq!(
            item.facets()["command.text"].value(),
            &JsonValue::string("ls -la")
        );
        assert_eq!(
            item.facets()["tool.executed"].value(),
            &JsonValue::Bool(false)
        );
        assert_eq!(
            item.fact_metadata()["tool.executed"].provenance(),
            FactProvenance::Reported
        );
    }
    assert_ne!(request.observation_id(), outcome.observation_id());

    for item in &batch.observations {
        assert_eq!(item.session_id().unwrap().value(), "ses_synthetic");
        assert_eq!(item.source().adapter_type(), "opencode");
        assert_eq!(item.source().adapter_id(), "opencode.sqlite");
        assert_eq!(item.source().source_path_hash(), None);
        assert_eq!(item.observed_at().as_str(), OBSERVED_AT);
        let capabilities = item.capability_context().unwrap();
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolCall),
            CapabilityAvailability::Supported
        );
        assert_eq!(
            capabilities.resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Unknown
        );
        if let ObservationBody::Message(message) = item.body() {
            assert_ne!(
                message.content(),
                Some(&JsonValue::string("synthetic-reasoning-marker"))
            );
        }
    }

    assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
    assert_eq!(batch.accounting.sessions.len(), 1);
    let session = &batch.accounting.sessions[0];
    assert_eq!(session.session_id.value(), "ses_synthetic");
    assert_eq!(session.counts.native_units, 2);
    let counts = session.counts.record_counts;
    assert_eq!(
        (
            counts.user_message,
            counts.assistant_message,
            counts.tool_call,
            counts.tool_result
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(session.counts.tool_usage["bash"].count, 1);
    assert_eq!(session.metadata.agent.known(), Some("build"));
    assert_eq!(session.metadata.model.known(), Some("synthetic-model"));
    assert_eq!(
        session.metadata.provider.known(),
        Some("synthetic-provider")
    );
}

#[test]
fn tool_lifecycle_separates_requests_outcomes_and_reported_execution() {
    let store = Store::v2();
    let created = json!({"created": T0});
    let called = json!({"created": T0, "ran": T0 + 1_000});
    let finished = json!({"created": T0, "ran": T0 + 1_000, "completed": T0 + 2_000});
    store.message(
        "msg_tools",
        1,
        T0 + 3_000,
        assistant(
            json!([
                tool_entry("call_stream", None, json!({"status": "streaming", "input": "{\"command\":\"ec"}), created.clone()),
                tool_entry("call_local", Some(false), json!({"status": "running", "input": {"command": "sleep 1"}, "metadata": {}}), called.clone()),
                tool_entry("call_provider", Some(true), json!({"status": "running", "input": {"command": "provider run"}, "metadata": {}}), called),
                tool_entry("call_done", Some(true), json!({"status": "completed", "input": {"command": "provider done"}, "content": [{"type": "text", "text": "a"}, {"type": "file", "uri": "file:///synthetic", "mime": "text/plain"}]}), finished.clone()),
                tool_entry("call_denied", Some(false), json!({"status": "error", "input": {"command": "rm -rf synthetic"}, "error": {"type": "aborted", "message": "The user declined this tool call"}}), finished),
                tool_entry("call_bad_json", Some(false), json!({"status": "error", "input": {}, "error": {"type": "tool.input-json", "message": "Tool call arguments were malformed JSON and were not executed."}}), json!({"created": T0, "completed": T0 + 2_000})),
            ]),
            T0,
        ),
    );
    let batch = store.acquire_default();
    use ObservationStage::*;
    let id = "msg_tools".to_owned();
    assert_eq!(
        shape(&batch),
        vec![
            (id.clone(), 0, ToolRequested),
            (id.clone(), 1, ToolRequested),
            (id.clone(), 2, ToolRequested),
            (id.clone(), 2, ToolExecutionStarted),
            (id.clone(), 3, ToolRequested),
            (id.clone(), 3, ToolExecutionCompleted),
            (id.clone(), 3, ToolResultReturned),
            (id.clone(), 4, ToolRequested),
            (id.clone(), 4, ToolResultReturned),
            (id.clone(), 5, ToolRequested),
            (id, 5, ToolResultReturned),
        ],
        "only executed=true claims execution; running/streaming have no outcome"
    );
    assert_eq!(
        tool(find(&batch, "msg_tools", 0, ToolRequested)).arguments(),
        Some(&JsonValue::string("{\"command\":\"ec"))
    );
    assert!(
        !find(&batch, "msg_tools", 0, ToolRequested)
            .facets()
            .contains_key("tool.executed")
    );
    assert_eq!(
        find(&batch, "msg_tools", 2, ToolExecutionStarted)
            .occurred_at()
            .unwrap()
            .as_str(),
        "2026-03-31T23:33:21Z"
    );
    let structured = tool(find(&batch, "msg_tools", 3, ToolResultReturned))
        .result()
        .unwrap();
    assert!(
        matches!(structured, JsonValue::Array(items) if items.len() == 2),
        "multi-part content stays structured"
    );
    for (child, executed) in [(1, false), (2, true), (3, true), (4, false), (5, false)] {
        assert_eq!(
            find(&batch, "msg_tools", child, ToolRequested).facets()["tool.executed"].value(),
            &JsonValue::Bool(executed)
        );
    }
    for (child, error_type) in [(4, "aborted"), (5, "tool.input-json")] {
        let returned = find(&batch, "msg_tools", child, ToolResultReturned);
        assert_eq!(
            returned.facets()["tool.error_type"].value(),
            &JsonValue::string(error_type)
        );
        let failed = tool(returned);
        assert_eq!(failed.reported_status(), Some(ToolStatus::Failed));
        assert!(matches!(failed.result(), Some(JsonValue::String(_))));
        assert_eq!(
            tool(find(&batch, "msg_tools", child, ToolRequested)).reported_status(),
            None
        );
    }
    for item in &batch.observations {
        assert_eq!(item.kind(), ObservationFamily::Tool);
        assert_ne!(tool(item).reported_status(), Some(ToolStatus::Succeeded));
        assert_eq!(tool(item).exit_code(), None);
        assert_eq!(tool(item).is_error(), None);
    }
    let counts = batch.accounting.sessions[0].counts.record_counts;
    assert_eq!((counts.tool_call, counts.tool_result), (6, 3));
}

#[test]
fn content_children_keep_identity_across_updates_relocation_and_rowids() {
    let store = Store::v2();
    let draft = assistant(
        json!([
            {"type": "text", "text": "draft"},
            tool_entry("call_a", None, json!({"status": "streaming", "input": ""}), json!({"created": T0})),
            tool_entry("call_b", Some(false), json!({"status": "running", "input": {"command": "make"}, "metadata": {}}), json!({"created": T0, "ran": T0 + 1})),
        ]),
        T0,
    );
    let settled = assistant(
        json!([
            {"type": "text", "text": "final answer"},
            tool_entry("call_a", Some(false), json!({"status": "completed", "input": {"command": "true"}, "content": [{"type": "text", "text": "ok"}]}), json!({"created": T0, "ran": T0 + 1, "completed": T0 + 2})),
            tool_entry("call_b", Some(false), json!({"status": "error", "input": {"command": "make"}, "error": {"type": "aborted", "message": "Tool execution interrupted"}}), json!({"created": T0, "ran": T0 + 1, "completed": T0 + 3})),
        ]),
        T0,
    );
    store.message("msg_live", 7, T0 + 10, draft);
    let first = store.acquire_default();
    let first_ids = identities(&first);
    assert_eq!(first_ids.len(), 3);

    store.update("msg_live", T0 + 20, settled.clone());
    let second = store.acquire_default();
    let second_ids = identities(&second);
    for (key, id) in &first_ids {
        assert_eq!(
            second_ids.get(key),
            Some(id),
            "lifecycle update kept {key:?}"
        );
    }
    assert_eq!(second_ids.len(), 5);
    let text = |batch| find(batch, "msg_live", 0, ObservationStage::MessageObserved);
    assert_eq!(
        text(&first)
            .semantic_comparison()
            .compare(text(&second).semantic_comparison()),
        SemanticReplayVerdict::Mutated
    );

    // Relocation: an exact copy at another path.
    let copy = store.directory.path().join("relocated.db");
    store
        .connection
        .execute("vacuum into ?1", [copy.to_str().unwrap()])
        .unwrap();
    let relocated = acquire_opencode_sqlite(
        &source(copy),
        AcquisitionOptions::new(ObservedAt::new(OBSERVED_AT).unwrap()),
        OpenCodeSqliteReadOptions::default(),
    )
    .unwrap();
    assert_eq!(identities(&relocated), second_ids);

    // Different rowids and an unrelated earlier message.
    let shifted = Store::v2();
    shifted.message("msg_other", 1, T0, user("unrelated", T0));
    shifted.message("msg_live", 7, T0 + 99, settled);
    shifted
        .connection
        .execute("delete from session_message where id = 'msg_other'", [])
        .unwrap();
    let shifted = shifted.acquire_default();
    assert_eq!(identities(&shifted), second_ids);
}

#[test]
fn recognized_auxiliary_messages_are_accounted_without_observations() {
    let store = Store::v2();
    let time = json!({"created": T0});
    for (seq, data) in [
        json!({"type": "agent-switched", "agent": "plan", "previous": "build", "time": time}),
        json!({"type": "model-switched", "model": {"id": "other-model", "providerID": "synthetic-provider"}, "time": time}),
        json!({"type": "location-switched", "location": {"type": "local"}, "time": time}),
        json!({"type": "synthetic", "text": "synthetic-injected-marker", "time": time}),
        json!({"type": "system", "text": "synthetic-system-marker", "time": time}),
        json!({"type": "skill", "skill": "sk_1", "name": "synthetic", "text": "synthetic-skill-marker", "time": time}),
        json!({"type": "compaction", "status": "completed", "reason": "auto", "summary": "s", "recent": "r", "time": time}),
        json!({"type": "idle", "outcome": "succeeded", "time": time}),
        json!({"type": "assistant", "agent": "build", "model": {"id": "synthetic-model", "providerID": "synthetic-provider"},
            "content": [{"type": "reasoning", "text": "synthetic-reasoning-marker"}], "error": {"type": "provider", "message": "synthetic"}, "time": time}),
    ]
    .into_iter()
    .enumerate()
    {
        store.message(&format!("msg_aux_{seq}"), seq as i64, T0 + seq as i64, data);
    }
    let batch = store.acquire_default();
    assert!(batch.observations.is_empty());
    let session = &batch.accounting.sessions[0];
    assert_eq!(session.counts.native_units, 9);
    let counts = session.counts.record_counts;
    assert_eq!(
        (counts.session_meta, counts.other, counts.assistant_message),
        (3, 5, 1)
    );
    assert_eq!(session.metadata.agent, AttestedValue::Ambiguous);
    assert_eq!(session.metadata.model, AttestedValue::Ambiguous);
    assert_eq!(
        session.metadata.provider.known(),
        Some("synthetic-provider")
    );
}

/// Activity contributions come from what the agent requested (tool input and
/// the user shell command). Tool results, errors
/// and shell output are returned data: a long encoded token there (within the
/// 65,536-byte direct-text budget) must not reject the source, and paths or
/// hosts there are not the agent's activity.
#[test]
fn contributions_count_requests_not_returned_payloads() {
    use telltale_schema::activity_facts::PathClass;

    // Base64 contains '/' and has no whitespace: one long token.
    let encoded = format!("iVBORw0KGgo/{}", "QUJD/".repeat(1_000));
    let store = Store::v2();
    store.message(
        "msg_tools",
        1,
        T0 + 3_000,
        assistant(
            json!([
                completed_tool("call_fetch", "bash",
                    json!({"command": "curl https://requested.example.test/x ~/.ssh/config"}),
                    &format!("see https://returned.example.test/ {encoded}"), T0),
                {"type": "tool", "id": "call_read", "name": "read", "executed": false,
                 "state": {"status": "completed", "input": {"filePath": "./synthetic.png"},
                           "content": [{"type": "file", "uri": "https://file.example.test/a.png",
                                        "mime": "image/png"}]},
                 "time": {"created": T0, "ran": T0 + 1, "completed": T0 + 2}},
                {"type": "tool", "id": "call_fail", "name": "bash", "executed": false,
                 "state": {"status": "error", "input": {"command": "false"},
                           "error": {"type": "tool.execution", "message": "https://error.example.test/"}},
                 "time": {"created": T0, "ran": T0 + 1, "completed": T0 + 2}},
            ]),
            T0,
        ),
    );
    store.message(
        "msg_shell",
        2,
        T0 + 4_000,
        json!({"type": "shell", "shellID": "sh_1", "command": "cat synthetic.b64",
               "status": "exited", "exit": 0,
               "output": {"output": encoded, "cursor": 1, "size": 1, "truncated": false},
               "time": {"created": T0, "completed": T0 + 1}}),
    );
    let batch = store.acquire_default();
    let contributions = &batch.accounting.sessions[0].counts.contributions;
    assert_eq!(
        contributions.network_hosts.keys().collect::<Vec<_>>(),
        vec!["requested.example.test"]
    );
    assert_eq!(
        contributions.path_classes.get(&PathClass::SecretStore),
        Some(&1)
    );
    assert_eq!(contributions.tool_calls.get("bash"), Some(&2));
    assert_eq!(contributions.tool_calls.get("read"), Some(&1));
    assert_eq!(contributions.tool_calls.get("shell"), Some(&1));

    // The contribution bound still applies to request input: the row is
    // quarantined with the bound's code instead of being counted.
    let rejected = Store::v2();
    rejected.message(
        "msg_tools",
        1,
        T0 + 3_000,
        assistant(
            json!([completed_tool(
                "call_write",
                "write",
                json!({"path": "./out.b64", "content": encoded}),
                "ok",
                T0
            )]),
            T0,
        ),
    );
    let batch = rejected.acquire_default();
    assert!(batch.observations.is_empty());
    assert_eq!(batch.quarantined.len(), 1);
    assert_eq!(batch.quarantined[0].code, "invalid_native_contribution");
    assert!(
        batch.accounting.sessions[0]
            .counts
            .contributions
            .tool_calls
            .is_empty()
    );
}

/// Both v2 mapping sites declare operations from the shared OpenCode table:
/// the tool content parts (file tools name their file `path`) and the user
/// shell message, whose command is the bare command text.
#[test]
fn v2_tool_parts_and_shell_messages_declare_their_operations() {
    use telltale_schema::observation::ToolKind;
    let store = Store::v2();
    store.message(
        "msg_tools",
        1,
        T0 + 1,
        assistant(
            json!([
                completed_tool("call_write", "write", json!({"path": "/synthetic/w.txt", "content": "x"}), "ok", T0),
                completed_tool("call_read", "read", json!({"path": "/synthetic/r.txt"}), "ok", T0 + 10),
                completed_tool("call_patch", "patch", json!({"patchText": "*** Begin Patch\n*** Add File: /synthetic/p.txt\n+x\n*** End Patch"}), "ok", T0 + 20),
                completed_tool("call_bash", "bash", json!({"command": "echo declared"}), "ok", T0 + 30),
            ]),
            T0,
        ),
    );
    store.message(
        "msg_shell",
        2,
        T0 + 2,
        json!({"type": "shell", "shellID": "sh_declared", "command": "echo bare", "status": "running", "time": {"created": T0}}),
    );
    let batch = store.acquire_default();
    let operations: Vec<_> = batch
        .observations
        .iter()
        .filter_map(|observation| match observation.body() {
            ObservationBody::Tool(tool) => tool.operation(),
            _ => None,
        })
        .collect();
    let has = |kind: ToolKind,
               pick: fn(&telltale_schema::observation::ToolOperation) -> &[String],
               value: &str| {
        operations
            .iter()
            .any(|operation| operation.kind() == kind && pick(operation) == [value])
    };
    assert!(has(
        ToolKind::FileWrite,
        |o| o.written_paths(),
        "/synthetic/w.txt"
    ));
    assert!(has(
        ToolKind::FileRead,
        |o| o.read_paths(),
        "/synthetic/r.txt"
    ));
    assert!(has(
        ToolKind::FileWrite,
        |o| o.written_paths(),
        "/synthetic/p.txt"
    ));
    assert!(has(ToolKind::Shell, |o| o.commands(), "echo declared"));
    assert!(has(ToolKind::Shell, |o| o.commands(), "echo bare"));
}
