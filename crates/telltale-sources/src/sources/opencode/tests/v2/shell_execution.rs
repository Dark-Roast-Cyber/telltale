use super::*;

/// OpenCode's `shell` tool writes `{status, truncated, exit?, signal?,
/// timeout?, shellID?}` into its completed state only after the command has
/// been authorized, run and settled (`packages/core/src/tool/plugin/shell.ts`
/// and `packages/core/src/shell/result.ts` at the pinned revision).
#[test]
fn shell_tool_result_metadata_reports_completion_without_inferring_success() {
    let shell_tool = |id: &str, executed: bool, state: Value, time: Value| {
        let mut entry = tool_entry(id, Some(executed), state, time);
        entry["name"] = json!("shell");
        entry
    };
    let completed = |metadata: Value| {
        json!({"status": "completed", "input": {"command": "make test"},
               "content": [{"type": "text", "text": "synthetic output"}], "metadata": metadata})
    };
    let called = json!({"created": T0, "ran": T0 + 1_000});
    let finished = json!({"created": T0, "ran": T0 + 1_000, "completed": T0 + 2_000});
    let entries = json!([
        shell_tool(
            "call_exit0",
            false,
            completed(json!({"status": "completed", "truncated": false, "exit": 0})),
            finished.clone()
        ),
        shell_tool(
            "call_exit2",
            false,
            completed(json!({"status": "completed", "truncated": false, "exit": 2})),
            finished.clone()
        ),
        shell_tool(
            "call_timeout",
            false,
            completed(json!({"status": "completed", "truncated": false, "timeout": true})),
            finished.clone()
        ),
        shell_tool(
            "call_signal",
            false,
            completed(json!({"status": "completed", "truncated": true, "signal": "SIGKILL"})),
            finished.clone()
        ),
        // Background command: returned before the process settled.
        shell_tool(
            "call_background",
            false,
            completed(json!({"status": "running", "truncated": false, "shellID": "shl_bg"})),
            finished.clone()
        ),
        // Missing and malformed metadata make no execution claim.
        shell_tool(
            "call_no_metadata",
            false,
            json!({"status": "completed", "input": {"command": "make"}, "content": [{"type": "text", "text": "x"}]}),
            finished.clone()
        ),
        shell_tool(
            "call_string_exit",
            false,
            completed(json!({"status": "completed", "truncated": false, "exit": "0"})),
            finished.clone()
        ),
        shell_tool(
            "call_fraction_exit",
            false,
            completed(json!({"status": "completed", "truncated": false, "exit": 1.5})),
            finished.clone()
        ),
        shell_tool(
            "call_bad_signal",
            false,
            completed(json!({"status": "completed", "truncated": false, "signal": 9})),
            finished.clone()
        ),
        shell_tool(
            "call_no_status",
            false,
            completed(json!({"truncated": false, "exit": 0})),
            finished.clone()
        ),
        shell_tool(
            "call_not_object",
            false,
            completed(json!("exit 0")),
            finished.clone()
        ),
        // Error and running entries never claim execution, whatever metadata says.
        shell_tool(
            "call_error",
            false,
            json!({"status": "error", "input": {"command": "make"},
            "error": {"type": "aborted", "message": "synthetic"},
            "metadata": {"status": "completed", "truncated": false, "exit": 1, "shellID": "shl_err"}}),
            finished.clone()
        ),
        shell_tool(
            "call_running",
            false,
            json!({"status": "running", "input": {"command": "make"},
            "metadata": {"shellID": "shl_run", "status": "completed", "exit": 0}}),
            called
        ),
        // Only the `shell` tool's metadata is interpreted.
        tool_entry(
            "call_other_tool",
            Some(false),
            completed(json!({"status": "completed", "truncated": false, "exit": 0})),
            finished.clone()
        ),
        // A provider-executed entry with metadata is completed once.
        shell_tool(
            "call_provider",
            true,
            completed(json!({"status": "completed", "truncated": false, "exit": 0})),
            finished
        ),
    ]);
    let store = Store::v2();
    store.message(
        "msg_shell_tools",
        1,
        T0 + 3_000,
        assistant(entries.clone(), T0),
    );
    let batch = store.acquire_default();
    use ObservationStage::*;
    let stages = |child: u32| {
        shape(&batch)
            .into_iter()
            .filter(|(_, ordinal, _)| *ordinal == child)
            .map(|(_, _, stage)| stage)
            .collect::<Vec<_>>()
    };
    let claimed = vec![ToolRequested, ToolExecutionCompleted, ToolResultReturned];
    let unclaimed = vec![ToolRequested, ToolResultReturned];
    for child in [0, 1, 2, 3, 14] {
        assert_eq!(stages(child), claimed, "child {child} reports completion");
    }
    for child in [4, 5, 6, 7, 8, 9, 10, 11, 13] {
        assert_eq!(stages(child), unclaimed, "child {child} makes no claim");
    }
    assert_eq!(stages(12), vec![ToolRequested], "running has no outcome");

    for stage in [ToolExecutionCompleted, ToolResultReturned] {
        let exit0 = find(&batch, "msg_shell_tools", 0, stage);
        assert_eq!(tool(exit0).exit_code(), Some(0));
        assert_eq!(
            tool(exit0).reported_status(),
            None,
            "exit 0 is not Succeeded"
        );
        assert_eq!(
            exit0.fact_metadata()["tool.exit_code"].provenance(),
            FactProvenance::Reported
        );
        let exit2 = tool(find(&batch, "msg_shell_tools", 1, stage));
        assert_eq!(exit2.exit_code(), Some(2));
        assert_eq!(exit2.reported_status(), None, "an exit code is not Failed");
        let timeout = find(&batch, "msg_shell_tools", 2, stage);
        assert_eq!(tool(timeout).exit_code(), None);
        assert_eq!(tool(timeout).reported_status(), Some(ToolStatus::Failed));
        assert_eq!(
            timeout.fact_metadata()["tool.reported_status"].provenance(),
            FactProvenance::Reported
        );
        let signal = find(&batch, "msg_shell_tools", 3, stage);
        assert_eq!(tool(signal).exit_code(), None);
        assert_eq!(tool(signal).reported_status(), None);
        assert_eq!(
            signal.facets()["tool.signal"].value(),
            &JsonValue::string("SIGKILL")
        );
        assert_eq!(
            signal.fact_metadata()["tool.signal"].provenance(),
            FactProvenance::Reported
        );
    }
    assert_eq!(
        find(&batch, "msg_shell_tools", 0, ToolExecutionCompleted)
            .occurred_at()
            .unwrap()
            .as_str(),
        "2026-03-31T23:33:22Z"
    );
    for item in &batch.observations {
        let body = tool(item);
        assert_ne!(body.reported_status(), Some(ToolStatus::Succeeded));
        assert_eq!(
            item.capability_context()
                .unwrap()
                .resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Unknown
        );
        if item.stage() == ToolRequested {
            assert_eq!(body.exit_code(), None);
            assert!(!item.facets().contains_key("tool.signal"));
        }
        let child = item.identity_basis().child_ordinal();
        if ![0, 1, 2, 3, 14].contains(&child) {
            assert_eq!(body.exit_code(), None, "child {child}");
            assert!(!item.facets().contains_key("tool.signal"), "child {child}");
        }
    }

    // The new stage adds an observation; it never moves an existing identity.
    let mut stripped = entries;
    for entry in stripped.as_array_mut().unwrap() {
        entry["state"].as_object_mut().unwrap().remove("metadata");
    }
    let plain = Store::v2();
    plain.message("msg_shell_tools", 1, T0 + 3_000, assistant(stripped, T0));
    let plain_ids = identities(&plain.acquire_default());
    let ids = identities(&batch);
    for (key, id) in &plain_ids {
        assert_eq!(ids.get(key), Some(id), "{key:?}");
    }
    assert_eq!(ids.len(), plain_ids.len() + 4);
}

#[test]
fn shell_metadata_does_not_override_provider_execution_evidence() {
    let store = Store::v2();
    let mut running = tool_entry(
        "call_provider_running",
        Some(true),
        json!({"status": "running", "input": {}, "metadata": "unrecognized"}),
        json!({"created": T0, "ran": T0 + 1_000}),
    );
    running["name"] = json!("shell");
    let mut error = tool_entry(
        "call_provider_error",
        Some(true),
        json!({"status": "error", "input": {},
            "error": {"type": "tool.execution", "message": "synthetic"},
            "metadata": {"status": "completed", "exit": 3}}),
        json!({"created": T0, "ran": T0 + 1_000, "completed": T0 + 2_000}),
    );
    error["name"] = json!("shell");
    store.message(
        "msg_provider",
        1,
        T0 + 3_000,
        assistant(json!([running, error]), T0),
    );
    let batch = store.acquire_default();
    use ObservationStage::*;
    let stages = shape(&batch)
        .into_iter()
        .map(|(_, child, stage)| (child, stage))
        .collect::<Vec<_>>();
    assert_eq!(
        stages,
        vec![
            (0, ToolRequested),
            (0, ToolExecutionStarted),
            (1, ToolRequested),
            (1, ToolExecutionCompleted),
            (1, ToolResultReturned)
        ]
    );
    for observation in &batch.observations {
        assert_eq!(tool(observation).exit_code(), None);
        assert!(!observation.facets().contains_key("tool.signal"));
    }
}

#[test]
fn user_shell_messages_map_reported_execution_without_os_observations() {
    let store = Store::v2();
    for (id, seq, data) in [
        (
            "msg_sh_run",
            1,
            json!({"type": "shell", "shellID": "sh_run", "command": "curl https://example.invalid/synthetic", "status": "running", "time": {"created": T0}}),
        ),
        (
            "msg_sh_exit",
            2,
            json!({"type": "shell", "shellID": "sh_exit", "command": "echo ok", "status": "exited", "exit": 0,
            "output": {"output": "ok\n", "cursor": 3, "size": 3, "truncated": false}, "time": {"created": T0, "completed": T0 + 1_000}}),
        ),
        (
            "msg_sh_kill",
            3,
            json!({"type": "shell", "shellID": "sh_kill", "command": "sleep 99", "status": "killed", "time": {"created": T0, "completed": T0 + 1_000}}),
        ),
        (
            "msg_sh_slow",
            4,
            json!({"type": "shell", "shellID": "sh_slow", "command": "sleep 999", "status": "timeout", "exit": 124, "time": {"created": T0, "completed": T0 + 1_000}}),
        ),
    ] {
        store.message(id, seq, T0 + seq, data);
    }
    let batch = store.acquire_default();
    use ObservationStage::*;
    let expected: Vec<(String, u32, ObservationStage)> = [
        ("msg_sh_run", ToolExecutionStarted),
        ("msg_sh_exit", ToolExecutionStarted),
        ("msg_sh_exit", ToolExecutionCompleted),
        ("msg_sh_exit", ToolResultReturned),
        ("msg_sh_kill", ToolExecutionStarted),
        ("msg_sh_kill", ToolExecutionCompleted),
        ("msg_sh_slow", ToolExecutionStarted),
        ("msg_sh_slow", ToolExecutionCompleted),
    ]
    .into_iter()
    .map(|(id, stage)| (id.to_owned(), 0, stage))
    .collect();
    assert_eq!(shape(&batch), expected);
    let exited = tool(find(&batch, "msg_sh_exit", 0, ToolExecutionCompleted));
    assert_eq!(exited.exit_code(), Some(0));
    assert_eq!(
        exited.reported_status(),
        None,
        "exit 0 is not inferred success"
    );
    assert_eq!(exited.result(), Some(&JsonValue::string("ok\n")));
    assert_eq!(
        tool(find(&batch, "msg_sh_kill", 0, ToolExecutionCompleted)).reported_status(),
        Some(ToolStatus::Cancelled)
    );
    assert_eq!(
        tool(find(&batch, "msg_sh_kill", 0, ToolExecutionCompleted)).exit_code(),
        None
    );
    assert_eq!(
        tool(find(&batch, "msg_sh_slow", 0, ToolExecutionCompleted)).reported_status(),
        Some(ToolStatus::Failed)
    );
    let started = find(&batch, "msg_sh_run", 0, ToolExecutionStarted);
    assert_eq!(tool(started).name(), Some("shell"));
    assert_eq!(
        started.fact_metadata()["tool.name"].provenance(),
        FactProvenance::Parsed
    );
    assert_eq!(
        tool(started).arguments(),
        Some(&JsonValue::string("curl https://example.invalid/synthetic"))
    );
    assert_eq!(
        started.facets()["command.text"].value(),
        &JsonValue::string("curl https://example.invalid/synthetic")
    );
    assert_eq!(tool(started).exit_code(), None);
    assert_eq!(started.correlation().call_id().unwrap().value(), "sh_run");
    for item in &batch.observations {
        assert_eq!(item.kind(), ObservationFamily::Tool);
        assert_eq!(
            item.capability_context()
                .unwrap()
                .resolve(CapabilityId::ToolExecution),
            CapabilityAvailability::Supported
        );
    }
    let counts = batch.accounting.sessions[0].counts.record_counts;
    assert_eq!((counts.tool_call, counts.tool_result), (4, 3));
    assert_eq!(
        batch.accounting.sessions[0].counts.tool_usage["shell"].count,
        4
    );
}
