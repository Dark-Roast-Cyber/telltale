use super::*;

#[test]
fn codex_generic_tool_accounting_distinguishes_requests_from_results() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Codex,
        source_id: "codex.sessions".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    for (label, value, expected, tool_name, request_host) in [
        (
            "arguments only",
            serde_json::json!({"type":"tool","session_id":"s","arguments":{"url":"https://request.example.test/"}}),
            RecordCounts {
                tool_call: 1,
                ..Default::default()
            },
            "unknown",
            true,
        ),
        (
            "named request",
            serde_json::json!({"type":"tool","session_id":"s","name":"shell","arguments":{"command":"true"}}),
            RecordCounts {
                tool_call: 1,
                ..Default::default()
            },
            "shell",
            false,
        ),
        (
            "reported error",
            serde_json::json!({"type":"tool","session_id":"s","name":"shell","state":{"status":"error","error":"https://error.example.test/"}}),
            RecordCounts {
                tool_result: 1,
                ..Default::default()
            },
            "shell",
            false,
        ),
        (
            "completed output",
            serde_json::json!({"type":"tool","session_id":"s","name":"shell","state":{"status":"completed","output":"https://output.example.test/"}}),
            RecordCounts {
                tool_result: 1,
                ..Default::default()
            },
            "shell",
            false,
        ),
    ] {
        std::fs::write(&source.path, value.to_string()).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        let counts = &batch.accounting.sessions[0].counts;
        assert_eq!(counts.record_counts, expected, "{label}");
        assert_eq!(counts.native_units, 1, "{label}");
        let is_call = expected.tool_call == 1;
        assert_eq!(
            counts.contributions.tool_calls.get(tool_name),
            is_call.then_some(&1),
            "{label}"
        );
        assert_eq!(
            counts.tool_usage.get("shell").map(|usage| usage.count),
            (is_call && tool_name == "shell").then_some(1),
            "{label}"
        );
        assert_eq!(
            counts
                .contributions
                .network_hosts
                .get("request.example.test"),
            request_host.then_some(&1),
            "{label}"
        );
        if !is_call {
            assert!(counts.contributions.network_hosts.is_empty(), "{label}");
            assert!(counts.contributions.tool_calls.is_empty(), "{label}");
            assert!(counts.tool_usage.is_empty(), "{label}");
        }
    }
}

#[test]
fn discarded_native_sibling_retains_semantic_contributions() {
    use telltale_schema::activity_facts::PathClass;
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    let mut value = serde_json::json!({"type":"assistant","session_id":"s","content":[{"type":"tool_use","id":"call-a","name":"shell","input":{"command":"true"}}]});
    std::fs::write(&source.path, value.to_string()).unwrap();
    let before = acquire_source(&source, options()).unwrap();
    value["sibling_context"] = serde_json::json!("https://internal.example.test/x /home/u/.env");
    std::fs::write(&source.path, value.to_string()).unwrap();
    let after = acquire_source(&source, options()).unwrap();
    assert_eq!(before.observations.len(), after.observations.len());
    for (left, right) in before.observations.iter().zip(&after.observations) {
        assert_eq!(left.body(), right.body());
        assert_eq!(left.facets(), right.facets());
        assert_eq!(left.fact_metadata(), right.fact_metadata());
        assert_eq!(left.stage(), right.stage());
        assert_eq!(left.session_id(), right.session_id());
    }
    let before = &before.accounting.sessions[0];
    let after = &after.accounting.sessions[0];
    assert_eq!(before.metadata, after.metadata);
    assert_eq!(before.counts.native_units, after.counts.native_units);
    assert_eq!(before.counts.record_counts, after.counts.record_counts);
    assert_eq!(after.counts.contributions.tool_calls.get("shell"), Some(&1));
    assert_eq!(
        after
            .counts
            .contributions
            .path_classes
            .get(&PathClass::SecretStore),
        Some(&1)
    );
    assert_eq!(
        after
            .counts
            .contributions
            .network_hosts
            .get("internal.example.test"),
        Some(&1)
    );
    assert_ne!(before.counts.contributions, after.counts.contributions);
    assert!(!format!("{:?}", after.counts.contributions).contains("internal.example"));
}

#[test]
fn unscoped_native_contributions_and_private_failures() {
    let directory = tempdir().unwrap();
    #[cfg(feature = "opencode-sqlite")]
    {
        let source = Source {
            client: ClientId::OpenCode,
            source_id: "opencode.sqlite".into(),
            kind: SourceKind::Sqlite,
            path: directory.path().join("synthetic.db"),
        };
        let conn = rusqlite::Connection::open(&source.path).unwrap();
        conn.execute_batch(r#"CREATE TABLE part (id TEXT, message_id TEXT, session_id TEXT, time_updated INTEGER, data TEXT);
        INSERT INTO part VALUES ('p',NULL,NULL,10,'{"type":"tool","tool":"shell","callID":"call-a","state":{"status":"running","input":{"command":"https://unscoped.example.test/"}}}');"#).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert!(batch.accounting.sessions.is_empty());
        assert_eq!(
            batch
                .accounting
                .unscoped
                .contributions
                .tool_calls
                .get("shell"),
            Some(&1)
        );
        assert!(
            batch
                .accounting
                .unscoped
                .contributions
                .network_hosts
                .contains_key("unscoped.example.test")
        );
    }

    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("PRIVATE-path"),
    };
    let text = format!("https://PRIVATE{}", "x".repeat(4096));
    let value = serde_json::json!({"type":"assistant","session_id":"s","content":[{"type":"tool_use","id":"call-a","name":"shell","input":{}}],"sibling_context":text});
    std::fs::write(&source.path, value.to_string()).unwrap();
    // Claude quarantines the record by itself, as OpenCode v2 does a row; the
    // source is still evaluated and nothing private is reported.
    let batch = acquire_source(&source, options()).unwrap();
    assert!(batch.observations.is_empty());
    assert_eq!(batch.quarantined.len(), 1);
    assert_eq!(batch.quarantined[0].code, "invalid_native_contribution");
    let counts = &batch.accounting.sessions[0].counts;
    assert_eq!(counts.native_units, 1);
    assert!(counts.contributions.tool_calls.is_empty());
    assert!(counts.tool_usage.is_empty());
    assert!(!format!("{:?}", batch.quarantined).contains("PRIVATE"));
}

#[test]
fn multi_record_contribution_budget_is_acquisition_wide() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    let unit = |session: &str, start: usize, end: usize| {
        let hosts = (start..end)
            .map(|i| format!("https://synthetic-{i}.example/x"))
            .collect::<Vec<_>>()
            .join(" ");
        serde_json::json!({"type":"assistant","session_id":session,
            "content":[{"type":"tool_use","id":"call-a","name":"shell","input":{}}],
            "sibling_context":hosts})
        .to_string()
    };
    // Two tool keys plus 4,092 host keys across two sessions. Repeated facts
    // increment counts without reserving more keys.
    let first = unit("a", 0, 2046);
    let second = unit("b", 2046, 4092);
    let below = format!("{first}\n{second}\n{first}\n");
    std::fs::write(&source.path, &below).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(batch.accounting.sessions.len(), 2);
    assert_eq!(
        batch.accounting.sessions[0].counts.contributions.tool_calls["shell"],
        2
    );
    assert_eq!(
        batch.accounting.sessions[0]
            .counts
            .contributions
            .network_hosts["synthetic-0.example"],
        2
    );
    assert_eq!(
        batch.accounting.sessions[1]
            .counts
            .contributions
            .network_hosts
            .len(),
        2046
    );

    // Every individual unit is below the bound; only the shared budget fails.
    let over = format!("{below}{}\n", unit("c", 4092, 4095));
    std::fs::write(&source.path, &over).unwrap();
    assert_eq!(
        acquire_source(&source, options()).err().unwrap(),
        AcquisitionError::ContributionCapacity
    );
}

#[test]
fn codex_contribution_preflight_checks_only_tool_calls() {
    // Only tool calls contribute activity facts, so a tool result whose name
    // would be rejected as a contribution label must not be quarantined.
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Codex,
        source_id: "codex.sessions".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    let message = serde_json::json!({"type":"tool","name":"shell\u{7}","state":{"status":"completed","output":"synthetic"}});
    std::fs::write(
        &source.path,
        format!("{{\"type\":\"session_meta\",\"payload\":{{\"session_id\":\"s\"}}}}\n{message}\n"),
    )
    .unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(batch.quarantined.len(), 0);
    assert_eq!(batch.observations.len(), 1);
}

/// A tool request whose name no table row lists, and a declared request whose
/// row names an operand the call lacks, are counted. Counting reads the
/// observations only, so the same read without the counts differs in nothing
/// else, and the counts hold numbers, never a name.
#[test]
fn tool_table_counts_unclassified_and_operand_drift_without_changing_the_read() {
    let directory = tempdir().unwrap();
    let source = Source {
        client: ClientId::Qwen,
        source_id: "qwen.projects".into(),
        kind: SourceKind::Jsonl,
        path: directory.path().join("synthetic.jsonl"),
    };
    let calls = [
        (
            "read_file",
            serde_json::json!({"file_path": "/synthetic/a"}),
        ),
        // Declared, but the call names no file.
        ("read_file", serde_json::json!({"offset": 1})),
        ("list_directory", serde_json::json!({"ignore": ["x"]})),
        // A search root is optional.
        ("glob", serde_json::json!({"pattern": "*.txt"})),
        ("web_search", serde_json::json!({"query": "synthetic"})),
        // No row, and not MCP-shaped.
        ("synthetic_unlisted_tool", serde_json::json!({})),
        // MCP-shaped names belong to MCP servers, not to the table.
        ("mcp__synthetic__tool", serde_json::json!({})),
    ];
    let lines: Vec<String> = calls
        .iter()
        .enumerate()
        .map(|(index, (name, arguments))| {
            serde_json::json!({"type":"tool_call","sessionId":"counted",
                "call_id":format!("call-{index}"),"name":name,"arguments":arguments})
            .to_string()
        })
        .collect();
    std::fs::write(&source.path, lines.join("\n")).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(
        batch.accounting.tool_table,
        ToolTableCounts {
            unclassified_tool_calls: 1,
            tool_operand_drift: 2,
        }
    );
    let rendered = format!("{:?}", batch.accounting.tool_table);
    assert!(!rendered.contains("synthetic") && !rendered.contains("read_file"));
    // Every call is still read, declared or not.
    assert_eq!(
        batch.accounting.sessions[0].counts.record_counts.tool_call,
        7
    );
    assert!(batch.quarantined.is_empty());
}
