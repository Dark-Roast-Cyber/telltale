use crate::acquisition::{
    AccountingCoverage, AcquisitionError, AcquisitionOptions, AcquisitionProgress,
    DirectReadLimits, acquire_source, acquire_source_bounded,
};
use crate::source_read::SourceReadError;
use serde_json::{Value, json};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::observation::{FactProvenance, JsonValue, ObservationBody, ObservedAt};
use telltale_schema::source::Source;

fn options() -> AcquisitionOptions {
    AcquisitionOptions::new(ObservedAt::new("2026-10-16T00:00:00Z").unwrap())
}

fn conversation_forms(content: &Value) -> [Value; 7] {
    [
        json!({"type":"user","sessionId":"synthetic","message":{"role":"user","content":content}}),
        json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":content}}),
        json!({"type":"user","sessionId":"synthetic","content":content}),
        json!({"role":"assistant","sessionId":"synthetic","content":content}),
        json!({"sessionId":"synthetic","message":{"role":"user","content":content}}),
        json!({"type":"assistant_message","sessionId":"synthetic","content":content}),
        json!({"type":"assistant","sessionId":"synthetic","content":[null],"message":{"role":"assistant","content":content}}),
    ]
}

#[test]
fn malformed_content_block_envelopes_fail_acquisition_atomically() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("PRIVATE-malformed-block.jsonl"),
    };
    let prefix = json!({"type":"user","sessionId":"synthetic","content":"valid prefix"});
    let bad_blocks = [
        json!(null),
        json!(false),
        json!(9),
        json!("PRIVATE-block"),
        json!([]),
        json!({"text":"PRIVATE-block"}),
        json!({"type":null,"text":"PRIVATE-block"}),
        json!({"type":9,"text":"PRIVATE-block"}),
        json!({"type":false,"text":"PRIVATE-block"}),
        json!({"type":{"PRIVATE-key":true},"text":"PRIVATE-block"}),
        json!({"type":["PRIVATE-type"],"text":"PRIVATE-block"}),
    ];
    for (case, bad) in bad_blocks.iter().enumerate() {
        let content = json!([{"type":"text","text":"valid part before malformed tail"},bad]);
        for (form, record) in conversation_forms(&content).iter().enumerate() {
            std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
            let error = match acquire_source(&source, options()) {
                Err(error) => error,
                Ok(_) => panic!(
                    "case {case}, form {form}: malformed envelope preserved a successful prefix"
                ),
            };
            assert_eq!(error, AcquisitionError::SourceRead);
            assert!(!format!("{error} {error:?}").contains("PRIVATE"));
            let bounded = match acquire_source_bounded(
                source.path.parent().unwrap(),
                &source,
                options(),
                DirectReadLimits::default(),
            ) {
                Err(error) => error,
                Ok(_) => panic!(
                    "case {case}, form {form}: bounded acquisition accepted malformed envelope"
                ),
            };
            assert_eq!(
                bounded,
                AcquisitionError::BoundedSourceRead(
                    crate::source_read::BoundedReadError::MalformedSource
                )
            );
            let native = match super::native::extract_claude_native_records(&source) {
                Err(error) => error,
                Ok(_) => {
                    panic!("case {case}, form {form}: extraction must reject malformed envelopes")
                }
            };
            assert!(matches!(native, SourceReadError::SchemaDrift { .. }));
            assert!(!format!("{native} {native:?}").contains("PRIVATE"));
        }
    }
}

#[test]
fn well_formed_unknown_content_types_quarantine_only_their_record() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-unknown-block.jsonl"),
    };
    let prefix = json!({"type":"user","sessionId":"synthetic","content":"valid prefix"});
    let content = json!([{"type":"text","text":"excluded valid part"},{"type":"Future","data":"PRIVATE-unknown"}]);
    for record in conversation_forms(&content) {
        std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
        assert_eq!(batch.accounting.sessions.len(), 1);
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 2);
        assert_eq!(batch.progress, AcquisitionProgress::None);
        assert_eq!(batch.quarantined.len(), 1);
        assert_eq!(batch.quarantined[0].code, "unknown_content_block");
        assert_eq!(batch.quarantined[0].source_sequence, 1);
        assert_eq!(batch.observations.len(), 1);
        let ObservationBody::Message(message) = batch.observations[0].body() else {
            panic!("valid prefix must remain a message")
        };
        assert!(message.content() == Some(&JsonValue::string("valid prefix")));
        assert!(!format!("{:?}", batch.quarantined).contains("PRIVATE"));
    }
}

#[test]
fn malformed_known_part_fields_remain_atomic_mapping_failures() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("PRIVATE-known-part.jsonl"),
    };
    let prefix = json!({"type":"user","sessionId":"synthetic","content":"valid prefix"});
    for (block, code) in [
        (json!({"type":"text","text":null}), "invalid_content_block"),
        (
            json!({"type":"text","text":{"PRIVATE-key":true}}),
            "invalid_content_block",
        ),
        (
            json!({"type":"tool_use","id":null,"name":"Read","input":{}}),
            "missing_tool_id",
        ),
        (
            json!({"type":"tool_use","id":"call","name":false,"input":{}}),
            "missing_tool_name",
        ),
        (
            json!({"type":"tool_result","tool_use_id":null,"content":"PRIVATE-result"}),
            "missing_tool_id",
        ),
        (
            json!({"type":"tool_result","tool_use_id":"call","is_error":null}),
            "invalid_content_block",
        ),
    ] {
        for record in conversation_forms(&json!([block])) {
            std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
            let error = match acquire_source(&source, options()) {
                Err(error) => error,
                Ok(_) => panic!("malformed known part preserved a successful prefix"),
            };
            assert_eq!(error, AcquisitionError::CanonicalMapping { code });
            assert!(!format!("{error} {error:?}").contains("PRIVATE"));
        }
    }
}

#[test]
fn direct_message_structures_are_not_content_block_envelopes() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-direct-content.jsonl"),
    };
    let content = json!({"type":false,"content":[null]});
    let expected = JsonValue::object([
        ("type".into(), JsonValue::Bool(false)),
        ("content".into(), JsonValue::array(vec![JsonValue::Null])),
    ])
    .unwrap();
    for record in conversation_forms(&content) {
        std::fs::write(&source.path, format!("{record}\n")).unwrap();
        let batch = acquire_source(&source, options()).unwrap();
        assert!(batch.quarantined.is_empty());
        assert_eq!(
            batch.accounting.coverage,
            AccountingCoverage::CompleteSource
        );
        assert_eq!(batch.observations.len(), 1);
        let ObservationBody::Message(message) = batch.observations[0].body() else {
            panic!("expected direct message")
        };
        assert!(message.content() == Some(&expected));
        assert_eq!(
            batch.observations[0].fact_metadata()["message.content"].provenance(),
            FactProvenance::Reported
        );
    }
}

#[test]
fn tool_values_and_ignored_payloads_are_not_content_block_envelopes() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-opaque-content.jsonl"),
    };
    let opaque = json!([null,{"type":false,"content":[null]}]);
    let expected = JsonValue::array(vec![
        JsonValue::Null,
        JsonValue::object([
            ("type".into(), JsonValue::Bool(false)),
            ("content".into(), JsonValue::array(vec![JsonValue::Null])),
        ])
        .unwrap(),
    ]);
    let request = json!({"type":"assistant","sessionId":"synthetic","content":[{"type":"tool_use","id":"call","name":"Read","input":opaque}]});
    let result = json!({"type":"user","sessionId":"synthetic","content":[{"type":"tool_result","tool_use_id":"call","content":opaque}]});
    let ignored = json!({"type":"assistant","sessionId":"synthetic","content":[
        {"type":"thinking","thinking":{"content":[null,{"type":false}],"text":"PRIVATE-reasoning"}},
        {"type":"image","source":{"content":[false],"type":null}},
        {"type":"text","text":"kept"}
    ]});
    std::fs::write(&source.path, format!("{request}\n{result}\n{ignored}\n")).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert!(batch.quarantined.is_empty());
    assert_eq!(
        batch.accounting.coverage,
        AccountingCoverage::CompleteSource
    );
    assert_eq!(batch.observations.len(), 4);
    let tools = batch
        .observations
        .iter()
        .filter_map(|observation| match observation.body() {
            ObservationBody::Tool(tool) => Some((observation, tool)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(tools.len(), 2);
    assert!(tools[0].1.arguments() == Some(&expected));
    assert!(tools[1].1.result() == Some(&expected));
    assert_eq!(
        tools[1].0.fact_metadata()["tool.result"].provenance(),
        FactProvenance::Reported
    );
    assert!(!format!("{:?}", batch.observations).contains("PRIVATE"));
}

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

#[test]
fn transcript_session_id_owns_records_that_also_name_another_session() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory.path().join("synthetic-continued.jsonl"),
    };
    let first = json!({"type":"user","sessionId":"synthetic-transcript",
        "session_id":"synthetic-transcript","uuid":"synthetic-1",
        "message":{"role":"user","content":"first turn"}});
    let continued = json!({"type":"assistant","sessionId":"synthetic-transcript",
        "session_id":"synthetic-continuation","uuid":"synthetic-2",
        "message":{"role":"assistant","content":[{"type":"text","text":"second turn"}]}});
    std::fs::write(&source.path, format!("{first}\n{continued}\n")).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(batch.observations.len(), 2);
    assert!(batch.observations.iter().all(|observation| {
        observation.session_id().unwrap().value() == "synthetic-transcript"
    }));
    assert_eq!(batch.accounting.sessions.len(), 1);
    assert_eq!(
        batch.accounting.sessions[0].session_id.value(),
        "synthetic-transcript"
    );

    let fallback = json!({"type":"user","session_id":"synthetic-fallback",
        "message":{"role":"user","content":"turn"}});
    std::fs::write(&source.path, format!("{fallback}\n")).unwrap();
    let batch = acquire_source(&source, options()).unwrap();
    assert_eq!(
        batch.accounting.sessions[0].session_id.value(),
        "synthetic-fallback"
    );

    let conflict = json!({"type":"user","session_id":"synthetic-fallback",
        "sessionID":"synthetic-other","message":{"role":"user","content":"turn"}});
    std::fs::write(&source.path, format!("{conflict}\n")).unwrap();
    assert!(matches!(
        acquire_source(&source, options()),
        Err(AcquisitionError::ConflictingSessionOwnership)
    ));
}

#[test]
fn explicit_outer_record_types_cannot_be_shadowed_by_payload_types() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: directory
            .path()
            .join("synthetic-discriminator-shadow.jsonl"),
    };
    let prefix = json!({"type":"user","sessionId":"synthetic","content":"valid turn"});
    for kind in [
        "api-request",
        "api-request-blob",
        "api-request-shape",
        "attachment",
        "pr-link",
        "artifact-autoreact-ledger",
        "artifact-comment-monitor",
        "continued-in",
        "Future",
    ] {
        for payload in [
            json!({"type":"assistant"}),
            json!({"payload":{"type":"assistant"}}),
        ] {
            let record = json!({"type":kind,"sessionId":"synthetic","payload":payload,
                "message":{"role":"assistant","content":[{"type":"tool_use","id":"synthetic-call",
                    "name":"Bash","input":{"command":"printf synthetic"}}]}});
            std::fs::write(&source.path, format!("{prefix}\n{record}\n")).unwrap();
            let batch = acquire_source(&source, options()).unwrap();
            assert_eq!(batch.observations.len(), 1, "{kind}");
            assert_eq!(
                batch.quarantined.len(),
                usize::from(kind == "Future"),
                "{kind}"
            );
            assert_eq!(
                batch.accounting.sessions[0].counts.record_counts.tool_call, 0,
                "{kind}"
            );
        }
    }
}

#[test]
fn malformed_jsonl_is_a_json_read_error() {
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_string(),
        path: crate::test_fixture_path("rule_samples/malformed-source.jsonl"),
    };
    let error = super::native::extract_claude_native_records(&source).expect_err("malformed");
    let message = error.to_string();
    assert!(matches!(error, SourceReadError::Json(_)));
    assert!(message.contains("json parse error"));
    assert!(!message.contains("malformed-source"));
}

#[test]
fn missing_jsonl_is_an_io_read_error() {
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_string(),
        path: "missing-session.jsonl".into(),
    };
    let error = super::native::extract_claude_native_records(&source).expect_err("missing");
    assert!(matches!(error, SourceReadError::Io(_)));
    assert!(error.to_string().contains("io error"));
}

#[test]
fn non_object_envelope_is_schema_drift() {
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".to_string(),
        path: crate::test_fixture_path("parser_maturity/non_discovered/schema-drift.jsonl"),
    };
    let error = super::native::extract_claude_native_records(&source).expect_err("drift");
    let message = error.to_string();
    assert!(matches!(error, SourceReadError::SchemaDrift { .. }));
    assert!(message.contains("schema drift"));
    assert!(!message.contains("Synthetic schema envelope drift"));
}

const SPILL_SESSION: &str = "synthetic-spill-session";
const SPILL_MARKER: &str = "synthetic full output beyond the preview";

fn spill_notice(path: &str) -> String {
    format!(
        "<persisted-output>\nOutput too large (3KB). Full output saved to: {path}\n\nPreview (first 2KB):\nsynthetic preview\n...\n</persisted-output>"
    )
}

/// A call/result pair whose result is `result`, in a transcript at `transcript`.
fn spill_source(transcript: std::path::PathBuf, result: Value) -> Source {
    let call = json!({"type":"assistant","sessionId":SPILL_SESSION,"message":{"role":"assistant",
        "content":[{"type":"tool_use","id":"synthetic-call","name":"Bash",
            "input":{"command":"printf synthetic"}}]}});
    let returned = json!({"type":"user","sessionId":SPILL_SESSION,"message":{"role":"user",
        "content":[{"type":"tool_result","tool_use_id":"synthetic-call","content":result}]}});
    std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
    std::fs::write(&transcript, format!("{call}\n{returned}\n")).unwrap();
    Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: transcript,
    }
}

fn write_spill(project: &std::path::Path, name: &str, bytes: &[u8]) {
    let directory = project.join(SPILL_SESSION).join("tool-results");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join(name), bytes).unwrap();
}

fn observed_result(
    observations: &[telltale_schema::observation::CanonicalObservationV2],
) -> Option<JsonValue> {
    observations
        .iter()
        .find_map(|observation| match observation.body() {
            ObservationBody::Tool(tool) => tool.result().cloned(),
            _ => None,
        })
}

fn spilled_result(source: &Source) -> Value {
    super::native::extract_claude_native_records(source)
        .unwrap()
        .into_iter()
        .flat_map(|record| record.blocks.unwrap_or_default())
        .find_map(|block| match block {
            super::native::ClaudeContentBlock::ToolResult { content, .. } => content,
            _ => None,
        })
        .unwrap()
}

#[test]
fn spilled_tool_results_resolve_from_the_session_directory() {
    let project = tempfile::tempdir().unwrap();
    let full = format!("{SPILL_MARKER}\n{}", "x".repeat(3000));
    write_spill(project.path(), "b9synthetic.txt", full.as_bytes());
    // The notice names the writer's absolute path; only the file name is used,
    // so a store copied elsewhere (here, a different directory) still resolves.
    let notice = spill_notice(r"C:\Elsewhere\project\other-session\tool-results\b9synthetic.txt");
    let source = spill_source(
        project.path().join(format!("{SPILL_SESSION}.jsonl")),
        json!(notice),
    );
    assert_eq!(spilled_result(&source), json!(full));

    // Every production read mode resolves it, and the observation carries it.
    let batch = acquire_source(&source, options()).unwrap();
    assert!(batch.quarantined.is_empty());
    assert_eq!(
        observed_result(&batch.observations),
        Some(JsonValue::string(&full))
    );
    let bounded = acquire_source_bounded(
        project.path(),
        &source,
        options(),
        DirectReadLimits::default(),
    )
    .unwrap();
    assert_eq!(
        observed_result(&bounded.observations),
        Some(JsonValue::string(&full))
    );

    // A single-text-block array notice resolves the same way.
    let source = spill_source(
        project.path().join(format!("{SPILL_SESSION}.jsonl")),
        json!([{"type":"text","text":notice}]),
    );
    assert_eq!(spilled_result(&source), json!(full));
}

#[test]
fn spilled_subagent_results_resolve_from_the_parent_session_directory() {
    let project = tempfile::tempdir().unwrap();
    write_spill(
        project.path(),
        "toolu_synthetic.txt",
        SPILL_MARKER.as_bytes(),
    );
    let source = spill_source(
        project
            .path()
            .join(SPILL_SESSION)
            .join("subagents")
            .join("agent-synthetic.jsonl"),
        json!(spill_notice("/home/u/p/s/tool-results/toolu_synthetic.txt")),
    );
    assert_eq!(spilled_result(&source), json!(SPILL_MARKER));
}

#[test]
fn unresolvable_spills_keep_the_notice() {
    let project = tempfile::tempdir().unwrap();
    write_spill(project.path(), "present.txt", SPILL_MARKER.as_bytes());
    write_spill(project.path(), "invalid.txt", &[0xff, 0xfe, 0x00]);
    write_spill(
        project.path(),
        "oversized.txt",
        &vec![b'x'; telltale_schema::observation::TOOL_RESULT_MAX_TEXT_BYTES + 1],
    );
    write_spill(
        project.path(),
        "atlimit.txt",
        &vec![b'y'; telltale_schema::observation::TOOL_RESULT_MAX_TEXT_BYTES],
    );
    let present = spill_notice("/p/s/tool-results/present.txt");
    let cases = [
        // Not exactly one notice: quoted inside other output, or unterminated.
        json!(format!("transcript excerpt: {present}")),
        json!(present.trim_end_matches("</persisted-output>")),
        json!([{"type":"text","text":present},{"type":"text","text":"more"}]),
        // The named file is not a plain name in a tool-results directory.
        json!(spill_notice("/p/s/other/present.txt")),
        json!(spill_notice("/p/s/tool-results/../present.txt")),
        json!(spill_notice("/p/s/tool-results/pre sent.txt")),
        json!(spill_notice("/p/s/tool-results/present.exe")),
        // Missing, not UTF-8, or over the direct tool-result budget.
        json!(spill_notice("/p/s/tool-results/missing.txt")),
        json!(spill_notice("/p/s/tool-results/invalid.txt")),
        json!(spill_notice("/p/s/tool-results/oversized.txt")),
    ];
    let transcript = project.path().join(format!("{SPILL_SESSION}.jsonl"));
    for case in cases {
        let source = spill_source(transcript.clone(), case.clone());
        assert_eq!(spilled_result(&source), case);
    }
    let source = spill_source(
        transcript,
        json!(spill_notice("/p/s/tool-results/atlimit.txt")),
    );
    assert_eq!(
        spilled_result(&source).as_str().map(str::len),
        Some(telltale_schema::observation::TOOL_RESULT_MAX_TEXT_BYTES)
    );
}

#[test]
fn spills_outside_a_plain_session_directory_are_not_read() {
    let project = tempfile::tempdir().unwrap();
    write_spill(project.path(), "present.txt", SPILL_MARKER.as_bytes());
    let notice = json!(spill_notice("/p/s/tool-results/present.txt"));
    // A subagent directory under a different session, and a session id that
    // is not a single plain path component, resolve nothing.
    let source = spill_source(
        project
            .path()
            .join("other-session")
            .join("subagents")
            .join("agent-synthetic.jsonl"),
        notice.clone(),
    );
    assert_eq!(spilled_result(&source), notice);
    let transcript = project.path().join("traversal.jsonl");
    let call = json!({"type":"user","sessionId":"../synthetic-spill-session","message":{"role":"user",
        "content":[{"type":"tool_result","tool_use_id":"synthetic-call","content":notice}]}});
    std::fs::write(&transcript, format!("{call}\n")).unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path: transcript,
    };
    assert_eq!(spilled_result(&source), notice);
}
