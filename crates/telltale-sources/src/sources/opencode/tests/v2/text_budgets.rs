use super::*;

/// Live OpenCode v2.0.28 stores routinely exceed the ordinary 4,096-byte string
/// bound in authored-text inputs and in multi-part or error results. Exact
/// `(tool, field)` pairs get the 65,536-byte direct-text budget instead.
#[test]
fn authored_text_and_returned_payloads_use_direct_text_budgets() {
    let long = |marker: &str| format!("{} {marker}", "word ".repeat(2_000));
    let entry = |id: &str, name: &str, state: Value| {
        json!({"type": "tool", "id": id, "name": name, "executed": false, "state": state,
               "time": {"created": T0, "ran": T0 + 1, "completed": T0 + 2}})
    };
    let done = |input: Value| json!({"status": "completed", "input": input, "content": [{"type": "text", "text": "ok"}]});
    let image = format!("data:image/png;base64,{}", "QUJD".repeat(30_000));
    let store = Store::v2();
    store.message(
        "msg_long",
        1,
        T0 + 10,
        assistant(
            json!([
                entry("c_shell", "shell", done(json!({"command": long("shell-end-marker"), "workdir": "."}))),
                entry("c_bash", "bash", done(json!({"command": long("bash-end-marker")}))),
                entry("c_patch", "patch", done(json!({"patchText": long("patch-end-marker")}))),
                entry("c_write", "write", done(json!({"path": "./notes.md", "content": long("write-end")}))),
                entry("c_edit", "edit", done(json!({"path": "~/.ssh/config", "oldString": long("old"), "newString": long("new")}))),
                entry("c_exec", "execute", done(json!({"code": long("exec-end")}))),
                entry("c_agent", "subagent", done(json!({"prompt": long("agent-end")}))),
                entry("c_read", "read", json!({"status": "completed", "input": {"path": "./shot.png"},
                    "content": [{"type": "text", "text": "Image read"},
                                {"type": "file", "uri": image, "mime": "image/png", "name": "shot.png"}]})),
                entry("c_fetch", "webfetch", json!({"status": "completed", "input": {"url": "https://example.test/"},
                    "content": [{"type": "text", "text": long("page")}, {"type": "text", "text": "notice"}]})),
                entry("c_fail", "glob", json!({"status": "error", "input": {"pattern": "**/*", "path": "/"},
                    "error": {"type": "tool.execution", "message": long("error-end")}})),
            ]),
            T0,
        ),
    );
    let batch = store.acquire_default();
    use ObservationStage::*;
    let request = |child| find(&batch, "msg_long", child, ToolRequested);
    let returned = |child| find(&batch, "msg_long", child, ToolResultReturned);
    let argument = |child, key: &str| match tool(request(child)).arguments() {
        Some(JsonValue::Object(members)) => members[key].clone(),
        other => panic!("child {child}: {other:?}"),
    };

    for (child, key, marker) in [
        (0, "command", "shell-end-marker"),
        (1, "command", "bash-end-marker"),
        (2, "patchText", "patch-end-marker"),
        (3, "content", "write-end"),
        (4, "newString", "new"),
        (5, "code", "exec-end"),
        (6, "prompt", "agent-end"),
    ] {
        assert_eq!(
            argument(child, key),
            JsonValue::string(long(marker)),
            "child {child}"
        );
    }
    assert_eq!(
        request(0).facets()["command.text"].value(),
        &JsonValue::string(long("shell-end-marker"))
    );
    // v2 file tools name their path `path`.
    for (child, path) in [(3, "./notes.md"), (4, "~/.ssh/config"), (7, "./shot.png")] {
        assert_eq!(
            request(child).facets()["resource.path"].value(),
            &JsonValue::string(path),
            "child {child}"
        );
    }
    assert!(
        !request(9).facets().contains_key("resource.path"),
        "glob path is a search root"
    );

    // A data: URI keeps its media type; the payload is not retained.
    let read = returned(7);
    let Some(JsonValue::Array(parts)) = tool(read).result() else {
        panic!("file content stays structured")
    };
    let JsonValue::Object(file) = &parts[1] else {
        panic!()
    };
    assert_eq!(file["uri"], JsonValue::string("data:image/png"));
    assert_eq!(file["mime"], JsonValue::string("image/png"));
    assert_eq!(
        read.facets()["tool.result.omitted_bytes"].value(),
        &JsonValue::Integer(i64::try_from(image.len() - "data:image/png".len()).unwrap())
    );
    // All-text parts join like upstream's own result messages.
    assert_eq!(
        tool(returned(8)).result(),
        Some(&JsonValue::string(format!("{}\n\nnotice", long("page"))))
    );
    // An error is its message text, with its reported type kept as a fact.
    let failed = returned(9);
    assert_eq!(
        tool(failed).result(),
        Some(&JsonValue::string(long("error-end")))
    );
    assert_eq!(tool(failed).reported_status(), Some(ToolStatus::Failed));
    assert_eq!(
        failed.facets()["tool.error_type"].value(),
        &JsonValue::string("tool.execution")
    );
    assert_eq!(
        failed.fact_metadata()["tool.error_type"].provenance(),
        FactProvenance::Reported
    );
}

/// One oversized row must not blind the source: it is quarantined with its
/// coordinates (never its content) and every other row is still evaluated.
/// Malformed, unknown and identity failures still fail the source.
/// A command near the direct-text budget maps whole, for the agent shell
/// tool and for a user `!` command, so detection sees its end. Its
/// `command.text` facet repeats the argument and is counted once.
#[test]
fn long_shell_commands_map_whole_instead_of_quarantining() {
    let command = format!("{} synthetic-long-command-end", "x ".repeat(30_000));
    let store = Store::v2();
    store.message(
        "msg_agent",
        1,
        T0 + 1,
        assistant(
            json!([completed_tool(
                "call_long",
                "shell",
                json!({"command": command}),
                "ok",
                T0
            )]),
            T0,
        ),
    );
    store.message(
        "msg_user",
        2,
        T0 + 2,
        json!({"type": "shell", "shellID": "sh_long", "command": command, "status": "exited", "exit": 0,
               "output": {"output": "ok\n", "cursor": 3, "size": 3, "truncated": false},
               "time": {"created": T0, "completed": T0 + 1_000}}),
    );
    let batch = store.acquire_default();
    assert!(batch.quarantined.is_empty(), "{:?}", batch.quarantined);
    use ObservationStage::*;
    for observation in [
        find(&batch, "msg_agent", 0, ToolRequested),
        find(&batch, "msg_agent", 0, ToolResultReturned),
        find(&batch, "msg_user", 0, ToolExecutionStarted),
        find(&batch, "msg_user", 0, ToolResultReturned),
    ] {
        assert_eq!(
            observation.facets()["command.text"].value(),
            &JsonValue::string(&command)
        );
    }
}

/// A user shell command over the authored-text bound is replaced in the arguments,
/// and the command facet, built from the same text, is left out: the row is
/// admitted with the command replaced.
#[test]
fn user_shell_command_over_bound_is_replaced_and_admitted() {
    let store = Store::v2();
    let secret = "private-suffix";
    let command = format!("{}{secret}", "z".repeat(70_000));
    store.message(
        "msg_sh_long",
        1,
        T0 + 1,
        json!({"type": "shell", "shellID": "sh_long", "command": command, "status": "running", "time": {"created": T0}}),
    );
    let batch = store.acquire_default();
    assert!(batch.quarantined.is_empty(), "{:?}", batch.quarantined);
    assert_eq!(batch.bounded.len(), 1);
    let observation = find(
        &batch,
        "msg_sh_long",
        0,
        ObservationStage::ToolExecutionStarted,
    );
    let tool = tool(observation);
    assert_eq!(
        tool.bounded_values()
            .iter()
            .map(|value| (value.target(), value.dimension()))
            .collect::<Vec<_>>(),
        [(
            telltale_schema::observation::BoundedTarget::Arguments,
            BoundDimension::StringBytes
        )]
    );
    assert!(!observation.facets().contains_key("command.text"));
    assert!(!format!("{:?}", batch.observations).contains(secret));
}

/// An error type is reported beside a replaced error message, which it is
/// not part of, but not once the error object that carries it as a member is
/// replaced.
#[test]
fn an_error_type_inside_a_replaced_error_object_is_not_reported() {
    use ObservationStage::*;
    let store = Store::v2();
    let finished = json!({"created": T0, "completed": T0 + 2_000});
    let mut error = serde_json::Map::new();
    error.insert("type".into(), json!("aborted"));
    for index in 0..32 {
        error.insert(format!("k{index}"), json!("xxxx"));
    }
    store.message(
        "msg_error",
        1,
        T0,
        assistant(
            json!([
                tool_entry("call_object", Some(false), json!({"status": "error", "input": {}, "error": error}), finished.clone()),
                tool_entry("call_message", Some(false), json!({"status": "error", "input": {}, "error": {"type": "aborted", "message": "y".repeat(70_000)}}), finished),
            ]),
            T0,
        ),
    );
    let batch = store.acquire_default();
    let object = find(&batch, "msg_error", 0, ToolResultReturned);
    assert_eq!(tool(object).result(), Some(&JsonValue::Null));
    assert!(!tool(object).bounded_values().is_empty());
    assert!(!object.facets().contains_key("tool.error_type"));
    let message = find(&batch, "msg_error", 1, ToolResultReturned);
    assert_eq!(tool(message).result(), Some(&JsonValue::Null));
    assert_eq!(
        message.facets()["tool.error_type"].value(),
        &JsonValue::string("aborted")
    );
    assert!(!format!("{:?}{:?}", batch.bounded, batch.observations).contains("yyyy"));
}
