//! Record shapes that current Codex releases write on Windows, which failed
//! whole sources before. Every payload is synthetic.

use crate::acquisition::{
    AccountingCoverage, AcquisitionBatch, AcquisitionError, AcquisitionOptions, acquire_source,
};
use serde_json::{Value, json};
use telltale_schema::observation::{
    BoundDimension, CanonicalBoundContext, CanonicalFieldCategory, JsonValue, ObservationBody,
    ObservedAt,
};
use telltale_schema::{
    clients::{ClientId, SourceKind},
    source::Source,
};

fn meta(extra: Value) -> Value {
    let mut meta = json!({"type":"session_meta","payload":{"id":"thread-a","session_id":"thread-a","history_mode":"paginated"}});
    meta["payload"]
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    meta
}

fn user(text: &str) -> Value {
    json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":text}]}})
}

fn completed(thread: &str, item: Value) -> Value {
    json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":thread,"turn_id":"turn-a","item":item}})
}

/// Number the records from `first`, as a paginated rollout does.
fn numbered(first: u64, mut values: Vec<Value>) -> Vec<Value> {
    for (offset, value) in values.iter_mut().enumerate() {
        value["ordinal"] = json!(first + offset as u64);
    }
    values
}

fn each(mut check: impl FnMut(&Source)) {
    let dir = tempfile::tempdir().unwrap();
    for (source_id, kind) in [
        ("codex.sessions", SourceKind::Jsonl),
        ("codex.archived_sessions", SourceKind::ArchivedJsonl),
        ("codex.headless_sessions", SourceKind::HeadlessJsonl),
    ] {
        check(&Source {
            client: ClientId::Codex,
            kind,
            source_id: source_id.into(),
            path: dir.path().join("synthetic.jsonl"),
        });
    }
}

fn acquire(source: &Source, values: &[Value]) -> Result<AcquisitionBatch, AcquisitionError> {
    let lines = values.iter().map(Value::to_string).collect::<Vec<_>>();
    std::fs::write(&source.path, lines.join("\n")).unwrap();
    acquire_source(
        source,
        AcquisitionOptions::new(ObservedAt::new("2026-10-14T12:00:00Z").unwrap()),
    )
}

fn private(batch: &AcquisitionBatch) -> bool {
    format!("{:?} {:?}", batch.observations, batch.quarantined).contains("PRIVATE")
}

#[test]
fn forked_thread_ordinals_continue_from_the_parent_history_base() {
    each(|source| {
        let base = json!({"history_base":{"thread_id":"thread-parent","end_ordinal_exclusive":40,"end_byte_offset":9000}});
        let fork = numbered(40, vec![meta(base.clone()), user("synthetic fork")]);
        let batch = acquire(source, &fork).unwrap();
        assert_eq!(batch.observations.len(), 1);
        assert_eq!(batch.observations[0].sequence(), Some(41));
        assert_eq!(
            batch.accounting.coverage,
            AccountingCoverage::CompleteSource
        );

        let mut invalid = Vec::new();
        // Ordinals must start exactly at the base.
        invalid.push(numbered(0, vec![meta(base.clone()), user("x")]));
        invalid.push(numbered(41, vec![meta(base.clone()), user("x")]));
        // The base is exactly a parent thread and two offsets.
        for history_base in [
            json!(0),
            json!({"end_ordinal_exclusive":40}),
            json!({"thread_id":"","end_ordinal_exclusive":40,"end_byte_offset":9000}),
            json!({"thread_id":"thread-parent","end_ordinal_exclusive":-1,"end_byte_offset":9000}),
            json!({"thread_id":"thread-parent","end_ordinal_exclusive":40,"end_byte_offset":"9000"}),
            json!({"thread_id":"thread-parent","end_ordinal_exclusive":40,"end_byte_offset":9000,"extra":1}),
        ] {
            invalid.push(numbered(
                40,
                vec![meta(json!({ "history_base": history_base })), user("x")],
            ));
        }
        // A base needs native ordinals, and only the first record may carry it.
        let mut unnumbered = vec![meta(base.clone()), user("x")];
        invalid.push(unnumbered.clone());
        unnumbered.insert(0, meta(json!({})));
        invalid.push(numbered(0, unnumbered));
        // Inherited subagent history is still unsupported.
        invalid.push(numbered(
            40,
            vec![
                meta(json!({"history_base": base["history_base"], "subagent_history_start_ordinal": 3})),
                user("x"),
            ],
        ));
        for values in invalid {
            assert!(acquire(source, &values).is_err(), "{values:?}");
        }
    });
}

#[test]
fn current_bookkeeping_records_are_recognized_and_not_projected() {
    each(|source| {
        let bookkeeping = vec![
            json!({"type":"token_usage_record","payload":{"session_id":"thread-root","thread_id":"thread-a","turn_id":"turn-a","response_id":"response-a","usage":{"input_tokens":1}}}),
            json!({"type":"compacted","payload":{"message":"PRIVATE summary","replacement_history":[user("PRIVATE history")]}}),
            json!({"type":"event_msg","payload":{"type":"thread_settings_applied","thread_id":"thread-a","thread_settings":{"model":"synthetic","cwd":"PRIVATE"}}}),
            json!({"type":"event_msg","payload":{"type":"turn_aborted","turn_id":"turn-a","reason":"interrupted"}}),
            completed(
                "thread-a",
                json!({"type":"ContextCompaction","id":"compaction-a"}),
            ),
            completed(
                "thread-a",
                json!({"type":"EnteredReviewMode","id":"review-a","target":"PRIVATE","user_facing_hint":"PRIVATE"}),
            ),
            completed(
                "thread-a",
                json!({"type":"ExitedReviewMode","id":"review-b","review_output":"PRIVATE"}),
            ),
        ];
        let count = bookkeeping.len() as u64;
        let mut values = vec![meta(json!({})), user("synthetic before")];
        values.extend(bookkeeping);
        values.push(user("synthetic after"));
        for values in [values.clone(), numbered(0, values)] {
            let batch = acquire(source, &values).unwrap();
            assert_eq!(batch.observations.len(), 2);
            assert!(batch.quarantined.is_empty());
            assert_eq!(
                batch.accounting.coverage,
                AccountingCoverage::CompleteSource
            );
            let counts = &batch.accounting.sessions[0].counts.record_counts;
            assert_eq!(counts.other, count);
            assert_eq!(counts.user_message, 2);
            assert!(!private(&batch));
        }
    });
}

#[test]
fn exec_scripts_and_text_array_outputs_keep_the_direct_text_budget() {
    each(|source| {
        let script = format!(
            "const r = await tools.shell({{}});\n{}",
            "// line\n".repeat(2_000)
        );
        let output = format!("token=PRIVATE-SECRET\n{}", "out ".repeat(5_000));
        let values = vec![
            meta(json!({})),
            json!({"type":"response_item","payload":{"type":"custom_tool_call","call_id":"call-a","name":"exec","input":script,"status":"completed"}}),
            json!({"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"call-a","output":[{"type":"input_text","text":"Script completed"},{"type":"input_text","text":output}]}}),
        ];
        let batch = acquire(source, &values).unwrap();
        assert!(batch.quarantined.is_empty());
        let ObservationBody::Tool(call) = batch.observations[0].body() else {
            panic!("tool call")
        };
        assert_eq!(call.name(), Some("exec"));
        assert_eq!(call.arguments(), Some(&JsonValue::string(&script)));
        let ObservationBody::Tool(result) = batch.observations[1].body() else {
            panic!("tool result")
        };
        assert_eq!(
            result.result(),
            Some(&JsonValue::string(format!("Script completed\n{output}")))
        );

        // Past the direct-text budget each record is quarantined by itself.
        let over = "x".repeat(65_537);
        let values = vec![
            meta(json!({})),
            json!({"type":"response_item","payload":{"type":"custom_tool_call","call_id":"call-b","name":"exec","input":over,"status":"completed"}}),
            json!({"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"call-b","output":[{"type":"input_text","text":over}]}}),
            user("synthetic after"),
        ];
        let batch = acquire(source, &values).unwrap();
        assert_eq!(batch.observations.len(), 1);
        let bounds = batch
            .quarantined
            .iter()
            .map(|unit| (unit.code, unit.native_id.as_str(), unit.bound))
            .collect::<Vec<_>>();
        let bound = |category| {
            Some(CanonicalBoundContext {
                category,
                dimension: BoundDimension::StringBytes,
            })
        };
        assert_eq!(
            bounds,
            [
                (
                    "unbounded_value",
                    "call-b",
                    bound(CanonicalFieldCategory::ToolArguments)
                ),
                (
                    "unbounded_value",
                    "call-b",
                    bound(CanonicalFieldCategory::ToolResult)
                ),
            ]
        );
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
    });
}

#[test]
fn a_parents_copies_of_subagent_items_are_quarantined_not_attributed() {
    each(|source| {
        let values = numbered(
            0,
            vec![
                meta(json!({})),
                user("synthetic parent"),
                completed(
                    "thread-subagent",
                    json!({"type":"CommandExecution","id":"call-sub","command":["PRIVATE"],"status":"completed","aggregated_output":"PRIVATE"}),
                ),
                completed(
                    "thread-subagent",
                    json!({"type":"Reasoning","id":"reason-sub","summary_text":["PRIVATE"]}),
                ),
            ],
        );
        let batch = acquire(source, &values).unwrap();
        assert_eq!(batch.observations.len(), 1);
        assert_eq!(
            batch.accounting.sessions.len(),
            1,
            "no subagent session here"
        );
        assert_eq!(
            batch
                .quarantined
                .iter()
                .map(|unit| (
                    unit.code,
                    unit.session_id.as_deref(),
                    unit.native_id.as_str(),
                    unit.source_sequence
                ))
                .collect::<Vec<_>>(),
            [
                ("foreign_thread_item", Some("thread-a"), "call-sub", 2),
                ("foreign_thread_item", Some("thread-a"), "reason-sub", 3),
            ]
        );
        assert!(!private(&batch));
    });
}
