use super::*;
fn tool(name: &str, arguments: serde_json::Value) -> ToolObservation {
    ToolObservation::new()
        .with_name(name)
        .unwrap()
        .with_arguments(JsonValue::try_from_source_value(&arguments).unwrap())
}

fn declared(table: &[ToolSpec], body: ToolObservation) -> ToolOperation {
    declare(table, body).operation().cloned().expect("declared")
}

/// The attempts [`build_fitted`] makes: the first only, unless it fails on
/// a bound under [`ValueBounds::Replace`]; then the omitted text, the
/// fitted values and the whole replacement, stopping at the first that
/// builds. Strict conversion never retries.
#[test]
fn build_fitted_omits_searchable_text_before_fitting_values() {
    let attempts = |bounds, builds: Option<ValueBounds>, error: &'static str| {
        let mut seen = Vec::new();
        let outcome = build_fitted(
            bounds,
            |error: &&str| *error == "bound",
            |attempt| {
                seen.push(attempt);
                if Some(attempt) == builds {
                    Ok(attempt)
                } else {
                    Err(error)
                }
            },
        );
        (seen, outcome)
    };
    use ValueBounds::{Fit, OmitText, Replace, Strict, Whole};
    assert_eq!(
        attempts(Replace, Some(Replace), "bound"),
        (vec![Replace], Ok(Replace))
    );
    assert_eq!(
        attempts(Replace, Some(OmitText), "bound"),
        (vec![Replace, OmitText], Ok(OmitText))
    );
    assert_eq!(
        attempts(Replace, Some(Fit), "bound"),
        (vec![Replace, OmitText, Fit], Ok(Fit))
    );
    assert_eq!(
        attempts(Replace, Some(Whole), "bound"),
        (vec![Replace, OmitText, Fit, Whole], Ok(Whole))
    );
    assert_eq!(
        attempts(Replace, None, "bound"),
        (vec![Replace, OmitText, Fit, Whole], Err("bound"))
    );
    assert_eq!(
        attempts(Replace, None, "other"),
        (vec![Replace], Err("other"))
    );
    assert_eq!(
        attempts(Strict, None, "bound"),
        (vec![Strict], Err("bound"))
    );
}

/// Only the retries omit a searchable text over its bound; the first
/// attempt and strict conversion set it as given, so it fails the call.
#[test]
fn searchable_text_is_omitted_only_on_a_retry() {
    let text = "x".repeat(4_097);
    for target in [
        BoundedTarget::SearchableArguments,
        BoundedTarget::SearchableResult,
    ] {
        for bounds in [ValueBounds::Replace, ValueBounds::Strict] {
            let body = with_searchable_text(ToolObservation::new(), target, &text, bounds).unwrap();
            assert!(body.bounded_values().is_empty(), "{bounds:?}");
            assert!(
                body.searchable_arguments()
                    .or(body.searchable_result())
                    .is_some(),
                "{bounds:?}"
            );
        }
        for bounds in [ValueBounds::OmitText, ValueBounds::Fit, ValueBounds::Whole] {
            let body = with_searchable_text(ToolObservation::new(), target, &text, bounds).unwrap();
            assert_eq!(
                body.searchable_arguments().or(body.searchable_result()),
                None
            );
            assert_eq!(
                body.bounded_values()
                    .iter()
                    .map(|value| (value.target(), value.dimension()))
                    .collect::<Vec<_>>(),
                [(target, BoundDimension::StringBytes)],
                "{bounds:?}"
            );
            // Within its bound the text is kept on every attempt.
            let kept =
                with_searchable_text(ToolObservation::new(), target, "short", bounds).unwrap();
            assert!(kept.bounded_values().is_empty());
        }
    }
}

type TextRow = (&'static str, &'static [&'static str], bool, bool);

/// Every row of `table` that declares authored text, as `(name, keys,
/// whole, strict)`.
fn text_rows(table: &[ToolSpec]) -> Vec<TextRow> {
    table
        .iter()
        .filter_map(|spec| {
            let (keys, whole, strict) = spec.text_declaration();
            (!keys.is_empty() || whole || strict).then_some((spec.name(), keys, whole, strict))
        })
        .collect()
}

#[test]
fn claude_declares_its_authored_text_arguments() {
    let expected: &[TextRow] = &[
        ("Bash", &["command"], false, false),
        ("PowerShell", &["command"], false, false),
        ("Write", &["content"], false, false),
        ("Edit", &["old_string", "new_string"], false, false),
        ("NotebookEdit", &["new_source"], false, false),
        ("Task", &["prompt"], false, false),
        ("Agent", &["prompt"], false, false),
        ("SendMessage", &["message"], false, false),
        ("SubagentHandback", &["message"], false, false),
    ];
    assert_eq!(text_rows(claude::tools::TOOLS), expected);
}

#[test]
fn opencode_declares_its_authored_text_arguments() {
    let expected: &[TextRow] = &[
        ("bash", &["command"], false, false),
        ("shell", &["command"], true, false),
        ("write", &["content"], false, false),
        ("edit", &["oldString", "newString"], false, false),
        ("patch", &["patchText"], false, false),
        ("apply_patch", &["patchText"], false, true),
        ("task", &["prompt"], false, false),
        ("subagent", &["prompt"], false, false),
        ("execute", &["code"], false, false),
    ];
    assert_eq!(text_rows(opencode::tools::TOOLS), expected);
}

#[test]
fn pi_declares_its_authored_text_arguments() {
    let expected: &[TextRow] = &[
        ("bash", &["command"], false, false),
        ("powershell", &["command"], false, false),
        ("write", &["content"], false, false),
        ("edit", &["oldText", "newText"], false, false),
    ];
    assert_eq!(text_rows(pi::tools::TOOLS), expected);
}

#[test]
fn codex_declares_its_authored_text_arguments() {
    let expected: &[TextRow] = &[
        ("apply_patch", &[], true, false),
        ("exec", &[], true, false),
    ];
    assert_eq!(text_rows(codex::tools::TOOLS), expected);
}

/// Copilot, Qwen and OpenClaw convert their own records with the structured
/// bounds and declare no text; their hook journals read shared spellings.
#[test]
fn copilot_qwen_and_openclaw_declare_no_authored_text() {
    for table in [
        copilot::tools::TOOLS,
        qwen::tools::TOOLS,
        openclaw::tools::TOOLS,
    ] {
        assert!(text_rows(table).is_empty());
    }
}

/// The move from one shared list into the adapters keeps every name's
/// declaration wherever the name is read, including a hook journal read
/// with a table that has no row for it. The message tools are new.
#[test]
fn every_formerly_shared_declaration_holds_for_every_table() {
    let expected: &[TextRow] = &[
        ("apply_patch", &["patchText"], true, true),
        ("patch", &["patchText"], false, false),
        ("shell", &["command"], true, false),
        ("bash", &["command"], false, false),
        ("powershell", &["command"], false, false),
        ("write", &["content"], false, false),
        (
            "edit",
            &["oldString", "newString", "oldText", "newText"],
            false,
            false,
        ),
        ("execute", &["code"], false, false),
        ("subagent", &["prompt"], false, false),
        ("task", &["prompt"], false, false),
        ("exec", &[], true, false),
        ("Bash", &["command"], false, false),
        ("PowerShell", &["command"], false, false),
        ("Write", &["content"], false, false),
        ("Edit", &["old_string", "new_string"], false, false),
        ("NotebookEdit", &["new_source"], false, false),
        ("Task", &["prompt"], false, false),
        ("Agent", &["prompt"], false, false),
        ("SendMessage", &["message"], false, false),
        ("SubagentHandback", &["message"], false, false),
    ];
    for client in ClientId::ALL {
        let own = table(*client).expect("every client has a table");
        for (name, keys, whole, strict) in expected {
            let declared = argument_text(own, Some(name));
            let mut actual: Vec<&str> = declared.keys().iter().map(String::as_str).collect();
            let mut keys = keys.to_vec();
            actual.sort_unstable();
            keys.sort_unstable();
            assert_eq!(
                (actual, declared.whole(), declared.strict()),
                (keys, *whole, *strict),
                "{client:?} {name}"
            );
        }
        for name in [None, Some("NoSuchTool"), Some("mcp__server__write")] {
            assert_eq!(argument_text(own, name), ArgumentText::new());
        }
    }
}

#[test]
fn a_tool_with_no_row_stays_undeclared() {
    let body = declare(
        claude::tools::TOOLS,
        tool("NoSuchTool", serde_json::json!({"file_path": "/p/a"})),
    );
    assert!(body.operation().is_none());
    let body = declare(claude::tools::TOOLS, ToolObservation::new());
    assert!(body.operation().is_none());
}

#[test]
fn operands_come_from_objects_encoded_objects_argv_and_plain_text() {
    let table = &[
        ToolSpec::new("run", ToolKind::Shell).commands(&["cmd", "command"]),
        ToolSpec::new("save", ToolKind::FileWrite).written(&["path"]),
        ToolSpec::new("look", ToolKind::FileRead).read(&["paths"]),
        ToolSpec::new("fetch", ToolKind::Web).urls(&["url"]),
    ];
    let operation = declared(table, tool("run", serde_json::json!({"cmd": "ls /p"})));
    assert_eq!(operation.kind(), ToolKind::Shell);
    assert_eq!(operation.commands(), ["ls /p"]);
    let operation = declared(
        table,
        tool("run", serde_json::json!({"command": ["cat", "/p/a"]})),
    );
    assert_eq!(operation.commands(), ["cat /p/a"]);
    let encoded = serde_json::json!({"command": "ls"}).to_string();
    let operation = declared(table, tool("run", serde_json::Value::String(encoded)));
    assert_eq!(operation.commands(), ["ls"]);
    let operation = declared(table, tool("run", serde_json::json!("ls /bare")));
    assert_eq!(operation.commands(), ["ls /bare"]);
    let operation = declared(table, tool("save", serde_json::json!({"path": "/p/a"})));
    assert_eq!(operation.written_paths(), ["/p/a"]);
    let operation = declared(
        table,
        tool("look", serde_json::json!({"paths": ["/p/a", "/p/b"]})),
    );
    assert_eq!(operation.read_paths(), ["/p/a", "/p/b"]);
    let operation = declared(
        table,
        tool(
            "fetch",
            serde_json::json!({"url": "https://example.test/x"}),
        ),
    );
    assert_eq!(operation.urls(), ["https://example.test/x"]);
    // The kind is declared even when the call holds no operand.
    let operation = declared(table, tool("save", serde_json::json!({"other": 1})));
    assert_eq!(operation.kind(), ToolKind::FileWrite);
    assert!(operation.written_paths().is_empty());
}

#[test]
fn patch_tools_name_their_files_from_headers_only() {
    let table = &[ToolSpec::new("patch", ToolKind::FileWrite).patch(&["patchText"])];
    let text = "*** Begin Patch\n*** Add File: /p/new\n+*** Update File: /p/not-a-header\n*** Update File: /p/old\n*** Move to: /p/moved\n*** Delete File: /p/gone\n*** End Patch";
    let expected = ["/p/new", "/p/old", "/p/moved", "/p/gone"];
    for arguments in [
        serde_json::json!({"patchText": text}),
        serde_json::json!(text),
        serde_json::Value::String(serde_json::json!({"patchText": text}).to_string()),
    ] {
        let operation = declared(table, tool("patch", arguments));
        assert_eq!(operation.written_paths(), expected);
    }
    let operation = declared(
        table,
        tool(
            "patch",
            serde_json::json!({"patchText": "*** Add File: /p/x"}),
        ),
    );
    assert!(operation.written_paths().is_empty());
}

#[test]
fn an_over_deep_member_hides_no_other_member_and_adds_no_command() {
    let table = &[ToolSpec::new("run", ToolKind::Shell).commands(&["command"])];
    let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
    let encoded = format!(r#"{{"command":"ls /p","prose":"not a command","deep":{deep}}}"#);
    let operation = declared(table, tool("run", serde_json::Value::String(encoded)));
    assert_eq!(operation.commands(), ["ls /p"]);
    // An over-deep member under a key the table reads has no operand.
    let encoded = format!(r#"{{"command":{deep},"prose":"not a command"}}"#);
    let operation = declared(table, tool("run", serde_json::Value::String(encoded)));
    assert!(operation.commands().is_empty());
    // Only text that is no JSON object at all is a bare command.
    let operation = declared(table, tool("run", serde_json::json!("{not json")));
    assert_eq!(operation.commands(), ["{not json"]);
}

#[test]
fn restored_rows_declare_their_operands_only_when_the_call_carries_them() {
    use ToolKind::{FileRead, FileWrite, Shell, Web};
    let patch = "*** Begin Patch\n*** Add File: /p/new\n+x\n*** End Patch";
    let cases: [(&[ToolSpec], &str, serde_json::Value, ToolKind); 7] = [
        (
            qwen::tools::TOOLS,
            "monitor",
            serde_json::json!({"command": "ls /p"}),
            Shell,
        ),
        (
            qwen::tools::TOOLS,
            "list_directory",
            serde_json::json!({"path": "/p"}),
            FileRead,
        ),
        (
            qwen::tools::TOOLS,
            "web_fetch",
            serde_json::json!({"url": "https://example.test/x"}),
            Web,
        ),
        (
            openclaw::tools::TOOLS,
            "exec",
            serde_json::json!({"command": "ls /p"}),
            Shell,
        ),
        (
            openclaw::tools::TOOLS,
            "apply_patch",
            serde_json::json!({"input": patch}),
            FileWrite,
        ),
        (
            openclaw::tools::TOOLS,
            "web_fetch",
            serde_json::json!({"url": "https://example.test/x"}),
            Web,
        ),
        (
            codex::tools::TOOLS,
            "view_image",
            serde_json::json!({"path": "/p/image"}),
            FileRead,
        ),
    ];
    for (table, name, arguments, kind) in cases {
        let operation = declared(table, tool(name, arguments));
        assert_eq!(operation.kind(), kind, "{name}");
        let operands = operation.commands().len()
            + operation.written_paths().len()
            + operation.read_paths().len()
            + operation.urls().len();
        assert_eq!(operands, 1, "{name}");
        // The same call without its operand declares the kind and no fact.
        let operation = declared(table, tool(name, serde_json::json!({"other": "x"})));
        assert_eq!(operation.kind(), kind, "{name}");
        assert!(
            operation.commands().is_empty()
                && operation.written_paths().is_empty()
                && operation.read_paths().is_empty()
                && operation.urls().is_empty(),
            "{name}"
        );
    }
}

const PATCH: &str = "*** Begin Patch\n*** Update File: /p/old\n+x\n*** End Patch\n";

#[test]
fn argument_roles_come_only_from_the_keys_a_row_names() {
    let table = copilot::tools::TOOLS;
    let operation = declared(
        table,
        tool(
            "edit",
            serde_json::json!({"path": "/p/a", "new_str": "n", "old_str": "o", "note": "x"}),
        ),
    );
    assert_eq!(operation.authored_keys(), ["new_str"]);
    assert_eq!(operation.replaced_keys(), ["old_str"]);
    // A key no row names has no role, whatever it looks like, and neither
    // has a row that names none.
    let operation = declared(
        table,
        tool(
            "edit",
            serde_json::json!({"path": "/p/a", "newString": "n"}),
        ),
    );
    assert!(!operation.has_roles());
    let operation = declared(
        claude::tools::TOOLS,
        tool(
            "Edit",
            serde_json::json!({"file_path": "/p/a", "new_str": "n", "old_str": "o"}),
        ),
    );
    assert!(!operation.has_roles());
}

#[test]
fn a_patch_key_is_authored_content_only_when_its_text_is_a_patch() {
    let table = codex::tools::TOOLS;
    let operation = declared(
        table,
        tool("apply_patch", serde_json::json!({"command": PATCH})),
    );
    assert_eq!(operation.authored_keys(), ["command"]);
    assert_eq!(operation.written_paths(), ["/p/old"]);
    let heredoc = format!("<<'EOF'\n{PATCH}EOF\n");
    let operation = declared(
        table,
        tool("apply_patch", serde_json::json!({"command": heredoc})),
    );
    assert_eq!(operation.authored_keys(), ["command"]);
    // A command, or text around a patch, keeps its structural reading.
    for text in [
        "ls /p".to_owned(),
        format!("ls /p\n{PATCH}"),
        format!("{PATCH}ls /p\n"),
        "*** Begin Patch\n+x\n".to_owned(),
    ] {
        let operation = declared(
            table,
            tool("apply_patch", serde_json::json!({"command": text})),
        );
        assert!(!operation.has_roles(), "{text:?}");
    }
    // The same holds for the whole argument text of a call with no object.
    let operation = declared(
        copilot::tools::TOOLS,
        tool("apply_patch", serde_json::json!(PATCH)),
    );
    assert!(operation.authored_text());
    assert_eq!(operation.written_paths(), ["/p/old"]);
    for text in ["rm -rf /p", &format!("rm -rf /p\n{PATCH}")] {
        let operation = declared(
            copilot::tools::TOOLS,
            tool("apply_patch", serde_json::json!(text)),
        );
        assert!(!operation.authored_text(), "{text:?}");
    }
}

#[test]
fn a_namespaced_call_gets_a_kind_and_operands_and_no_role() {
    let patch = "*** Begin Patch\n*** Add File: /p/a.rs\n+x\n*** End Patch\n";
    let call = || tool("apply_patch", serde_json::json!({"input": patch}));
    let table = codex::tools::TOOLS;
    let bare = declare_in(table, call(), None);
    assert!(bare.operation().unwrap().has_roles());
    // An MCP server's namespace: the row is not this tool's.
    assert!(
        declare_in(table, call(), Some("mcp__srv__files"))
            .operation()
            .is_none()
    );
    // Any other namespace: the kind and the written paths, and no role.
    let other = declare_in(table, call(), Some("extension"));
    let operation = other.operation().unwrap();
    assert_eq!(operation.kind(), bare.operation().unwrap().kind());
    assert_eq!(operation.written_paths(), ["/p/a.rs".to_owned()]);
    assert!(!operation.has_roles());
    // A built-in tool that carries a namespace keeps its kind.
    let delegate = declare_in(
        table,
        tool("spawn_agent", serde_json::json!({"message": "m"})),
        Some("collaboration"),
    );
    assert_eq!(delegate.operation().unwrap().kind(), ToolKind::Delegate);
}

#[test]
fn a_name_an_mcp_server_gives_its_tools_is_never_declared() {
    let table = &[
        ToolSpec::new("mcp__srv__edit", ToolKind::FileWrite)
            .written(&["path"])
            .authored(&["new_str"]),
        ToolSpec::new("edit", ToolKind::FileWrite)
            .written(&["path"])
            .authored(&["new_str"]),
    ];
    let arguments = serde_json::json!({"path": "/p/a", "new_str": "n"});
    assert!(
        declare(table, tool("mcp__srv__edit", arguments.clone()))
            .operation()
            .is_none()
    );
    assert!(
        declare(table, tool("MCP-srv.edit", arguments.clone()))
            .operation()
            .is_none()
    );
    assert!(declared(table, tool("edit", arguments.clone())).has_roles());
    // A tool a harness names after a server and its tool is not the built-in.
    for name in ["mcp__srv__apply_patch", "mcp__srv__edit"] {
        for harness in [
            copilot::tools::TOOLS,
            codex::tools::TOOLS,
            opencode::tools::TOOLS,
        ] {
            assert!(
                declare(harness, tool(name, arguments.clone()))
                    .operation()
                    .is_none()
            );
        }
    }
}

#[test]
fn no_table_lists_a_tool_twice() {
    let tables: &[(&str, &[ToolSpec])] = &[
        ("claude", claude::tools::TOOLS),
        ("codex", codex::tools::TOOLS),
        ("copilot", copilot::tools::TOOLS),
        ("openclaw", openclaw::tools::TOOLS),
        ("opencode", opencode::tools::TOOLS),
        ("qwen", qwen::tools::TOOLS),
    ];
    for &(source, table) in tables {
        let mut names = std::collections::BTreeSet::new();
        for spec in table {
            assert!(
                names.insert(spec.name()),
                "{source} lists {} twice",
                spec.name()
            );
        }
    }
}
