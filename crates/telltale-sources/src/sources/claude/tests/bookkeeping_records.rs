use super::*;

#[test]
fn skipped_or_unknown_record_payloads_remain_opaque() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-opaque-record.jsonl"),
    };
    let prefix = json!({"type":"user","sessionId":"synthetic","content":"valid prefix"});
    for (kind, coverage) in [
        ("queue-operation", AccountingCoverage::CompleteSource),
        ("Future", AccountingCoverage::PartialSource),
    ] {
        let record = json!({"type":kind,"sessionId":"synthetic","content":[null,{"type":false}]});
        std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert_eq!(batch.accounting.coverage, coverage);
        assert_eq!(batch.progress, AcquisitionProgress::None);
        assert_eq!(batch.observations.len(), 1);
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 2);
        if kind == "Future" {
            assert_eq!(batch.quarantined.len(), 1);
            assert_eq!(batch.quarantined[0].code, "unknown_discriminator");
        } else {
            assert!(batch.quarantined.is_empty());
        }
    }
}

#[test]
fn session_tag_bookkeeping_requires_its_native_envelope() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-tag.jsonl"),
    };
    let records = r#"{"type":"user","sessionId":"synthetic","content":"valid turn"}
{"type":"tag","sessionId":"synthetic","tag":""}
{"role":"tag","sessionId":"synthetic","tag":"label"}
{"type":"tag","sessionId":"synthetic","tag":false}
{"type":"tag","sessionId":"synthetic","tag":"label","content":"unknown shape"}
{"type":"tag","sessionId":"","tag":"label"}
{"type":"tag","tag":"label"}
"#;
    let label_at_limit = "é".repeat(2048); // 4,096 UTF-8 bytes
    let at_limit = json!({"type":"tag","sessionId":"synthetic","tag":&label_at_limit});
    let oversized =
        json!({"type":"tag","sessionId":"synthetic","tag":format!("{label_at_limit}x")});
    std::fs::write(&source.path, format!("{records}{at_limit}\n{oversized}\n")).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(
        batch
            .quarantined
            .iter()
            .map(|unit| (unit.source_sequence, unit.code))
            .collect::<Vec<_>>(),
        [
            (2, "unknown_discriminator"),
            (3, "unknown_discriminator"),
            (4, "unknown_discriminator"),
            (5, "unknown_discriminator"),
            (6, "unknown_discriminator"),
            (8, "unknown_discriminator"),
        ],
    );
    assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
    assert_eq!(batch.observations.len(), 1);
}

#[test]
fn session_tag_bookkeeping_counts_cleared_tag_as_other() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-cleared-tag.jsonl"),
    };
    std::fs::write(
        &source.path,
        r#"{"type":"user","sessionId":"synthetic","content":"valid turn"}
{"type":"tag","sessionId":"synthetic","tag":""}
"#,
    )
    .unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(
        batch.accounting.coverage,
        AccountingCoverage::CompleteSource
    );
    assert!(batch.quarantined.is_empty());
    assert_eq!(batch.observations.len(), 1);
    let counts = &batch.accounting.sessions[0].counts;
    assert_eq!(counts.native_units, 2);
    assert_eq!(counts.record_counts.other, 1);
}

#[test]
fn current_bookkeeping_records_count_as_other() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-bookkeeping.jsonl"),
    };
    std::fs::write(
        &source.path,
        r#"{"type":"user","sessionId":"synthetic","content":"valid turn"}
{"type":"bridge-session","sessionId":"synthetic","bridgeSessionId":"bridge-synthetic","lastSequenceNum":7,"ownerAccountUuid":"account-synthetic","ownerOrganizationUuid":"org-synthetic"}
{"type":"tools-used","sessionId":"synthetic","tools":["Bash","Read"]}
{"type":"tools-used","sessionId":"synthetic","tools":[]}
{"type":"session-owner","sessionId":"synthetic","accountUuid":"account-synthetic","organizationUuid":"org-synthetic"}
{"type":"agent-setting","sessionId":"synthetic","agentSetting":"agent-synthetic"}
"#,
    )
    .unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert!(batch.quarantined.is_empty());
    assert_eq!(
        batch.accounting.coverage,
        AccountingCoverage::CompleteSource
    );
    assert_eq!(batch.observations.len(), 1);
    let counts = &batch.accounting.sessions[0].counts;
    assert_eq!(counts.native_units, 6);
    assert_eq!(counts.record_counts.other, 5);
}

#[test]
fn current_bookkeeping_records_require_their_native_envelopes() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-bookkeeping-shapes.jsonl"),
    };
    let bridge = json!({"type":"bridge-session","sessionId":"synthetic",
        "bridgeSessionId":"bridge","lastSequenceNum":1,
        "ownerAccountUuid":"account","ownerOrganizationUuid":"org"});
    let with = |key: &str, value: Value| {
        let mut record = bridge.clone();
        record[key] = value;
        record
    };
    let mut extra_bridge = bridge.clone();
    extra_bridge["message"] = json!({"role":"assistant","content":[{"type":"tool_use",
        "id":"synthetic-call","name":"Bash","input":{"command":"printf synthetic"}}]});
    let mut missing_bridge = bridge.clone();
    missing_bridge
        .as_object_mut()
        .unwrap()
        .remove("ownerAccountUuid");
    let tools = |value: Value| json!({"type":"tools-used","sessionId":"synthetic","tools":value});
    let at_limit = "a".repeat(4096);
    let owner = |account: Value, organization: Value| {
        json!({"type":"session-owner","sessionId":"synthetic",
            "accountUuid":account,"organizationUuid":organization})
    };
    let agent = |setting: Value| json!({"type":"agent-setting","sessionId":"synthetic","agentSetting":setting});
    let lines = [
        json!({"type":"user","sessionId":"synthetic","content":"valid turn"}),
        extra_bridge,                       // 1: unknown key carrying a tool call
        missing_bridge,                     // 2
        with("lastSequenceNum", json!(-1)), // 3
        with("bridgeSessionId", json!(7)),  // 4
        with("sessionId", json!("")),       // 5
        with("ownerOrganizationUuid", json!(format!("{at_limit}x"))), // 6
        with("bridgeSessionId", json!(at_limit)), // 7: at the bound, accepted
        tools(json!("Bash")),               // 8
        tools(json!(["Bash", 1])),          // 9
        tools(json!(vec!["Bash"; 65])),     // 10
        tools(json!(vec!["Bash"; 64])),     // 11: at the bound, accepted
        json!({"type":"tools-used","sessionId":"synthetic","tools":[],"extra":true}), // 12
        owner(json!(""), json!("org")),     // 13
        owner(json!("account"), Value::Null), // 14
        owner(json!("account"), json!(format!("{at_limit}x"))), // 15
        owner(json!("account"), json!(at_limit)), // 16: at the bound, accepted
        json!({"type":"session-owner","sessionId":"synthetic","accountUuid":"account"}), // 17
        agent(json!("")),                   // 18
        agent(json!(7)),                    // 19
        json!({"type":"agent-setting","sessionId":"synthetic","agentSetting":"a","extra":1}), // 20
        json!({"type":"agent-setting","agentSetting":"agent"}), // 21
    ];
    let text = lines
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    std::fs::write(&source.path, text).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(
        batch
            .quarantined
            .iter()
            .map(|unit| (unit.source_sequence, unit.code))
            .collect::<Vec<_>>(),
        [
            (1, "unknown_discriminator"),
            (2, "unknown_discriminator"),
            (3, "unknown_discriminator"),
            (4, "unknown_discriminator"),
            (5, "unknown_discriminator"),
            (6, "unknown_discriminator"),
            (8, "unknown_discriminator"),
            (9, "unknown_discriminator"),
            (10, "unknown_discriminator"),
            (12, "unknown_discriminator"),
            (13, "unknown_discriminator"),
            (14, "unknown_discriminator"),
            (15, "unknown_discriminator"),
            (17, "unknown_discriminator"),
            (18, "unknown_discriminator"),
            (19, "unknown_discriminator"),
            (20, "unknown_discriminator"),
            (21, "unknown_discriminator"),
        ],
    );
    assert_eq!(batch.observations.len(), 1);
}

#[test]
fn bookkeeping_replays_are_opaque_to_observations_and_activity() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-bookkeeping.jsonl"),
    };
    let prefix = json!({"type":"user","sessionId":"synthetic","content":"valid turn"});
    for kind in [
        "attachment",
        "api-request",
        "api-request-blob",
        "api-request-shape",
        "mode",
        "permission-mode",
        "relocated",
        "worktree-state",
        "cost-state",
        "pr-link",
        "artifact-autoreact-ledger",
        "artifact-comment-monitor",
        "continued-in",
    ] {
        let record = json!({"type":kind,"sessionId":"synthetic","message":{
            "role":"assistant","content":[{"type":"tool_use","id":"synthetic-call",
                "name":"Bash","input":{"command":"curl https://fixture.invalid/example"}}]}});
        std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert!(batch.quarantined.is_empty(), "{kind}");
        assert_eq!(batch.observations.len(), 1, "{kind}");
        assert_eq!(
            batch.accounting.coverage,
            AccountingCoverage::CompleteSource,
            "{kind}"
        );
        let counts = &batch.accounting.sessions[0].counts;
        assert_eq!(counts.native_units, 2, "{kind}");
        assert_eq!(counts.record_counts.other, 1, "{kind}");
        assert_eq!(counts.record_counts.tool_call, 0, "{kind}");
        assert_eq!(counts.contributions, Default::default(), "{kind}");
        assert!(counts.tool_usage.is_empty(), "{kind}");
        let mut conflict = record;
        conflict["message"]["sessionId"] = json!("synthetic-other");
        std::fs::write(&source.path, format!("{prefix}\n{conflict}\n")).unwrap();
        assert!(
            matches!(
                acquire_source(&source, options()),
                Err(AcquisitionError::ConflictingSessionOwnership)
            ),
            "{kind}"
        );
    }
}
