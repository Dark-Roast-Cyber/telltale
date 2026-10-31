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

/// A paginated subagent rollout whose ordinals 1..start copy the parent's
/// model context, as the pinned harness writes a copied fork: its own
/// metadata first, then the inherited prefix, then its own history.
fn subagent_rollout(start: Value, inherited: Vec<Value>, own: Vec<Value>) -> Vec<Value> {
    let child_meta = json!({"type":"session_meta","payload":{
        "id":"thread-child","session_id":"thread-root","parent_thread_id":"thread-root",
        "history_mode":"paginated","source":{"subagent":{"other":"synthetic-role"}},
        "multi_agent_version":"disabled","subagent_history_start_ordinal":start}});
    let mut values = vec![child_meta];
    values.extend(inherited);
    values.extend(own);
    numbered(0, values)
}

fn parent_context() -> Vec<Value> {
    vec![
        // The parent's own metadata, messages, calls and completed items are
        // copied verbatim; none of them belongs to the child.
        json!({"type":"session_meta","payload":{"id":"thread-root","session_id":"thread-root","history_mode":"paginated","model_provider":"PRIVATE-provider"}}),
        user("PRIVATE parent prompt"),
        json!({"type":"response_item","payload":{"type":"function_call","call_id":"call-parent","name":"shell","arguments":"{\"command\":[\"PRIVATE-parent-command\"]}"}}),
        json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"call-parent","output":"PRIVATE parent output"}}),
        completed(
            "thread-root",
            json!({"type":"CommandExecution","id":"cmd-parent","command":["PRIVATE"],"status":"completed","aggregated_output":"PRIVATE"}),
        ),
        json!({"type":"response_item","payload":{"type":"compaction","id":"cmp-parent","encrypted_content":"PRIVATE-opaque"}}),
        json!({"type":"future_record","payload":{"thread_id":"PRIVATE-other","anything":"PRIVATE"}}),
    ]
}

fn child_history() -> Vec<Value> {
    vec![
        json!({"type":"event_msg","payload":{"type":"task_started","turn_id":"turn-child"}}),
        user("synthetic child prompt"),
        json!({"type":"response_item","payload":{"type":"function_call","call_id":"call-child","name":"shell","arguments":"{\"command\":[\"synthetic-child-command\"]}"}}),
        json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"call-child","output":"synthetic child output"}}),
        completed(
            "thread-child",
            json!({"type":"CommandExecution","id":"cmd-child","command":["synthetic-child-argv"],"status":"completed","exit_code":0,"aggregated_output":"synthetic"}),
        ),
    ]
}

#[test]
fn subagent_inherited_parent_context_is_quarantined_and_only_child_history_is_attributed() {
    each(|source| {
        let inherited = parent_context();
        let start = 1 + inherited.len() as u64;
        let values = subagent_rollout(json!(start), inherited.clone(), child_history());
        let batch = acquire(source, &values).expect("copied subagent rollout must parse");

        // Every observation is the child's own and keeps its native ordinal.
        assert!(!batch.observations.is_empty());
        for o in &batch.observations {
            assert_eq!(o.session_id().unwrap().value(), "thread-child");
            assert!(o.sequence().unwrap() >= start, "{:?}", o.sequence());
        }
        let only_child = acquire(
            source,
            &subagent_rollout(json!(1), Vec::new(), child_history()),
        )
        .unwrap();
        assert_eq!(batch.observations.len(), only_child.observations.len());

        // Each inherited unit stays visible by itself, content-free, under the
        // file's owner at its native ordinal; nothing is silently dropped.
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
            (1..start)
                .map(|sequence| ("foreign_thread_item", Some("thread-child"), "", sequence))
                .collect::<Vec<_>>()
        );
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);

        // The copied parent metadata never opens a second session, and the
        // parent's calls are never counted as the child's activity.
        assert_eq!(batch.accounting.sessions.len(), 1);
        let session = &batch.accounting.sessions[0];
        assert_eq!(session.session_id.value(), "thread-child");
        assert_eq!(session.counts.native_units, values.len() as u64);
        assert_eq!(session.counts.record_counts.session_meta, 1);
        assert_eq!(
            session.counts.contributions,
            only_child.accounting.sessions[0].counts.contributions
        );
        assert!(!private(&batch));
        assert!(!format!("{:?}", batch.accounting).contains("PRIVATE"));

        // Child identities derive from child coordinates only: replay and
        // different inherited content with the same boundary keep them.
        let replay = acquire(source, &values).unwrap();
        let mut other = parent_context();
        other[1] = user("different parent prompt");
        other[6] = json!({"type":"another_future","payload":{}});
        let changed = acquire(
            source,
            &subagent_rollout(json!(start), other, child_history()),
        )
        .unwrap();
        for run in [&replay, &changed] {
            assert_eq!(
                batch
                    .observations
                    .iter()
                    .map(|o| (o.observation_id(), o.sequence()))
                    .collect::<Vec<_>>(),
                run.observations
                    .iter()
                    .map(|o| (o.observation_id(), o.sequence()))
                    .collect::<Vec<_>>()
            );
        }

        // An empty inherited prefix is complete and quarantines nothing.
        assert!(only_child.quarantined.is_empty());
        assert_eq!(
            only_child.accounting.coverage,
            AccountingCoverage::CompleteSource
        );

        // A child-owned item under another thread is still foreign, and an
        // inherited parent message never stands in for a child mirror.
        let mut own = child_history();
        own.push(completed(
            "thread-root",
            json!({"type":"Reasoning","id":"reason-root","summary_text":["PRIVATE"]}),
        ));
        let batch = acquire(
            source,
            &subagent_rollout(json!(start), parent_context(), own),
        )
        .unwrap();
        let last = batch.quarantined.last().unwrap();
        assert_eq!(
            (last.code, last.native_id.as_str()),
            ("foreign_thread_item", "reason-root")
        );
    });
}

#[test]
fn subagent_history_boundary_is_end_exclusive_at_the_files_last_ordinal() {
    each(|source| {
        // Metadata only, boundary 1: an empty prefix and no child history yet.
        let batch = acquire(source, &subagent_rollout(json!(1), Vec::new(), Vec::new())).unwrap();
        assert!(batch.observations.is_empty() && batch.quarantined.is_empty());
        assert_eq!(batch.accounting.sessions.len(), 1);
        assert_eq!(
            batch.accounting.coverage,
            AccountingCoverage::CompleteSource
        );

        // The file ends exactly at its last copied record: the boundary is one
        // past the final ordinal and the child has no own records yet.
        let inherited = parent_context();
        let start = 1 + inherited.len() as u64;
        let values = subagent_rollout(json!(start), inherited.clone(), Vec::new());
        assert_eq!(values.last().unwrap()["ordinal"], json!(start - 1));
        let batch = acquire(source, &values).unwrap();
        assert!(batch.observations.is_empty());
        assert_eq!(
            batch
                .quarantined
                .iter()
                .map(|unit| (unit.code, unit.source_sequence))
                .collect::<Vec<_>>(),
            (1..start)
                .map(|sequence| ("foreign_thread_item", sequence))
                .collect::<Vec<_>>()
        );
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);

        // One further past the final ordinal is an incomplete copied prefix.
        for values in [
            subagent_rollout(json!(start + 1), inherited, Vec::new()),
            subagent_rollout(json!(2), Vec::new(), Vec::new()),
        ] {
            assert!(acquire(source, &values).is_err());
        }
    });
}

#[test]
fn malformed_or_unsupported_subagent_history_boundaries_fail_the_source() {
    each(|source| {
        let inherited = parent_context();
        let start = 1 + inherited.len() as u64;
        let mut invalid = Vec::new();
        // The boundary is a u64 past the child's own metadata.
        for bad in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!("3"),
            json!({"end_ordinal_exclusive":3}),
        ] {
            invalid.push(subagent_rollout(bad, inherited.clone(), child_history()));
        }
        // An incomplete copied prefix: the boundary lies past the last record.
        invalid.push(subagent_rollout(
            json!(start + 10),
            inherited.clone(),
            Vec::new(),
        ));
        invalid.push(subagent_rollout(
            json!(start),
            inherited[..2].to_vec(),
            Vec::new(),
        ));
        // A copied prefix and a referenced history base are never combined.
        let mut both = subagent_rollout(json!(start), inherited.clone(), child_history());
        both[0]["payload"]["history_base"] =
            json!({"thread_id":"thread-root","end_ordinal_exclusive":0,"end_byte_offset":0});
        invalid.push(both);
        // Unpaginated rollouts have no ordinal boundary to honor.
        let mut legacy = subagent_rollout(json!(start), inherited.clone(), child_history());
        for value in &mut legacy {
            value.as_object_mut().unwrap().remove("ordinal");
        }
        invalid.push(legacy.clone());
        legacy[0]["payload"]["history_mode"] = json!("legacy");
        invalid.push(legacy);
        // Only the child's first metadata may carry the boundary.
        let mut own = child_history();
        own.push(json!({"type":"session_meta","payload":{"id":"thread-child","subagent_history_start_ordinal":1}}));
        invalid.push(subagent_rollout(json!(start), inherited.clone(), own));
        // An inherited unit is still a typed rollout record.
        for bad in [json!({}), json!({"type":7})] {
            let mut prefix = inherited.clone();
            prefix[2] = bad;
            invalid.push(subagent_rollout(json!(start), prefix, child_history()));
        }
        // Child-owned coordinates keep their checks after the boundary.
        let mut own = child_history();
        own[1]["payload"]["thread_id"] = json!("thread-root");
        invalid.push(subagent_rollout(json!(start), inherited.clone(), own));
        let mut gap = subagent_rollout(json!(start), inherited, child_history());
        gap.last_mut().unwrap()["ordinal"] = json!(99);
        invalid.push(gap);
        for values in invalid {
            let error = acquire(source, &values)
                .err()
                .unwrap_or_else(|| panic!("must fail: {}", values[0]["payload"]));
            assert!(!format!("{error:?} {error}").contains("PRIVATE"));
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

fn assistant(texts: &[&str]) -> Value {
    json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":texts.iter().map(|text| json!({"type":"output_text","text":text})).collect::<Vec<_>>()}})
}

fn agent_message(text: &str) -> Value {
    json!({"type":"event_msg","payload":{"type":"agent_message","message":text,"phase":null,"memory_citation":null}})
}

#[test]
fn web_search_calls_preserve_closed_actions_without_inventing_execution() {
    use telltale_schema::observation::{
        CapabilityAvailability, CapabilityId, FactProvenance, ObservationStage,
    };
    each(|source| {
        for action in [
            json!({"type":"search","query":"synthetic.invalid","queries":["one","two"]}),
            json!({"type":"open_page","url":"https://synthetic.invalid/page"}),
            json!({"type":"find_in_page","url":"https://synthetic.invalid/page","pattern":"needle"}),
            json!({"type":"search","query":null,"queries":[]}),
        ] {
            for status in [
                None,
                Some("completed"),
                Some("in_progress"),
                Some("failed"),
                Some("error"),
            ] {
                let mut search = json!({"type":"response_item","payload":{"type":"web_search_call","id":"ws-synthetic","action":action,"private":"PRIVATE-IGNORED"}});
                if let Some(status) = status {
                    search["payload"]["status"] = json!(status);
                }
                let values = vec![
                    meta(json!({})),
                    user("before"),
                    search,
                    assistant(&["after"]),
                ];
                let batch = acquire(source, &values).unwrap();
                assert!(batch.quarantined.is_empty(), "{action}");
                assert_eq!(batch.observations.len(), 3);
                assert_eq!(
                    batch.accounting.coverage,
                    AccountingCoverage::CompleteSource
                );
                let counts = &batch.accounting.sessions[0].counts;
                assert_eq!(counts.native_units, 4);
                assert_eq!(counts.record_counts.tool_call, 1);
                assert_eq!(counts.record_counts.tool_result, 0);
                assert_eq!(counts.contributions.tool_calls["web_search"], 1);
                let o = &batch.observations[1];
                assert_eq!(o.stage(), ObservationStage::ToolRequested);
                assert_eq!(o.source().adapter_id(), source.source_id);
                assert_eq!(o.sequence(), Some(2));
                assert!(
                    o.correlation().call_id().is_none(),
                    "response ID is not a call ID"
                );
                assert_eq!(
                    o.correlation(),
                    &telltale_schema::observation::CorrelationIds::new().with_response_id(
                        telltale_schema::observation::CorrelationId::source_reported(
                            "ws-synthetic"
                        )
                        .unwrap()
                    )
                );
                let ObservationBody::Tool(tool) = o.body() else {
                    panic!("tool")
                };
                assert_eq!(tool.name(), Some("web_search"));
                assert_eq!(
                    tool.arguments(),
                    Some(&JsonValue::try_from_source_value(&action).unwrap())
                );
                assert!(tool.result().is_none() && tool.reported_status().is_none());
                assert_eq!(
                    o.fact_metadata()["tool.name"].provenance(),
                    FactProvenance::Parsed
                );
                assert_eq!(
                    o.fact_metadata()["tool.arguments"].provenance(),
                    FactProvenance::Reported
                );
                if tool.searchable_arguments().is_some() {
                    assert_eq!(
                        o.fact_metadata()["tool.searchable_arguments"].provenance(),
                        FactProvenance::Parsed
                    );
                } else {
                    assert!(!o.fact_metadata().contains_key("tool.searchable_arguments"));
                }
                if let Some(status) = status {
                    assert_eq!(
                        o.facets()["tool.source_status"].value(),
                        &JsonValue::string(status)
                    );
                } else {
                    assert!(!o.facets().contains_key("tool.source_status"));
                }
                assert_eq!(
                    o.capability_context()
                        .unwrap()
                        .resolve(CapabilityId::ToolExecution),
                    CapabilityAvailability::Unsupported
                );
                assert!(!private(&batch));
                let replay = acquire(source, &numbered(0, values)).unwrap();
                assert_eq!(o.observation_id(), replay.observations[1].observation_id());
            }
        }
        let action = json!({"type":"search","query":"synthetic needle"});
        let poisoned = json!({"type":"response_item","payload":{"type":"web_search_call","action":action,"role":"assistant","content":[{"type":"output_text","text":"PRIVATE"}],"message":{"role":"user","session_id":"poison","model":"PRIVATE","content":"PRIVATE"}}});
        let batch = acquire(source, &[meta(json!({})), poisoned]).unwrap();
        assert!(batch.quarantined.is_empty());
        assert_eq!(batch.observations.len(), 1);
        assert!(!private(&batch));
        let ObservationBody::Tool(tool) = batch.observations[0].body() else {
            panic!("search must not become a message")
        };
        assert_eq!(
            tool.arguments(),
            Some(&JsonValue::try_from_source_value(&action).unwrap())
        );
        assert!(
            tool.searchable_arguments()
                .unwrap()
                .contains("synthetic needle")
        );
        // Partial provider items have no action yet; absence is not a result.
        for action in [None, Some(Value::Null)] {
            let mut search = json!({"type":"response_item","payload":{"type":"web_search_call"}});
            if let Some(action) = action {
                search["payload"]["action"] = action;
            }
            let batch = acquire(source, &[meta(json!({})), search]).unwrap();
            assert!(batch.quarantined.is_empty());
            assert_eq!(batch.observations.len(), 1);
            let ObservationBody::Tool(tool) = batch.observations[0].body() else {
                panic!("tool")
            };
            assert!(tool.arguments().is_none());
        }
    });
}

#[test]
fn completed_plan_retains_assistant_text_typed_identity_and_accounting() {
    use telltale_schema::observation::{MessageRole, ObservationStage};
    each(|source| {
        let text = format!("1. Read synthetic notes.\n{}", "p".repeat(5000));
        let plan = completed(
            "thread-a",
            json!({"type":"Plan","id":"plan-a","text":text,"private":"PRIVATE-IGNORED"}),
        );
        for history in ["legacy", "paginated"] {
            let values = vec![
                meta(json!({"history_mode":history})),
                user("before"),
                plan.clone(),
                assistant(&["after"]),
            ];
            let batch = acquire(source, &values).unwrap();
            assert!(batch.quarantined.is_empty());
            assert_eq!(batch.observations.len(), 3);
            assert_eq!(
                batch.accounting.coverage,
                AccountingCoverage::CompleteSource
            );
            let counts = &batch.accounting.sessions[0].counts;
            assert_eq!(counts.native_units, 4);
            assert_eq!(counts.record_counts.assistant_message, 2);
            assert_eq!(counts.contributions, Default::default());
            let o = &batch.observations[1];
            assert_eq!(o.stage(), ObservationStage::MessageObserved);
            assert_eq!(
                o.source().native_id(),
                Some(r#"["thread-a","turn-a","plan-a"]"#)
            );
            assert_eq!(
                o.correlation(),
                &telltale_schema::observation::CorrelationIds::new()
                    .with_turn_id(
                        telltale_schema::observation::CorrelationId::source_reported("turn-a")
                            .unwrap()
                    )
                    .with_response_id(
                        telltale_schema::observation::CorrelationId::source_reported("plan-a")
                            .unwrap()
                    )
            );
            let ObservationBody::Message(message) = o.body() else {
                panic!("plan message")
            };
            assert_eq!(message.role(), Some(MessageRole::Assistant));
            assert_eq!(
                message.content_parts()[0].value(),
                &JsonValue::string(&text)
            );
            assert!(!private(&batch));
            let shifted = acquire(source, &[meta(json!({})), plan.clone()]).unwrap();
            assert_eq!(o.observation_id(), shifted.observations[0].observation_id());
        }
    });
}

#[test]
fn legacy_agent_message_mirrors_are_local_one_to_one_and_keep_unique_text() {
    each(|source| {
        let legacy = meta(json!({"history_mode":"legacy"}));
        let raw = assistant(&["first", "second"]);
        let events = vec![agent_message("first"), agent_message("second")];
        for reversed in [false, true] {
            let mut values = vec![legacy.clone(), user("before")];
            if reversed {
                values.extend(events.clone());
                values.push(raw.clone());
            } else {
                values.push(raw.clone());
                values.extend(events.clone());
            }
            values.push(assistant(&["after"]));
            let batch = acquire(source, &values).unwrap();
            assert!(batch.quarantined.is_empty());
            assert_eq!(batch.observations.len(), 3);
            assert_eq!(
                batch.accounting.coverage,
                AccountingCoverage::CompleteSource
            );
            let counts = &batch.accounting.sessions[0].counts;
            assert_eq!(counts.native_units, 6);
            assert_eq!(
                counts.record_counts.assistant_message, 4,
                "physical units still count"
            );
            assert_eq!(counts.contributions, Default::default());
            let ObservationBody::Message(message) = batch.observations[1].body() else {
                panic!("raw message")
            };
            assert_eq!(message.content_parts().len(), 2);
            let replay = acquire(source, &values).unwrap();
            for (first, replay) in batch.observations.iter().zip(&replay.observations) {
                assert_eq!(first.observation_id(), replay.observation_id());
                assert_eq!(first.semantic_comparison(), replay.semantic_comparison());
                assert_eq!(first.sequence(), replay.sequence());
            }
        }
        // Never search the whole session for identical text, or erase an unmatched event.
        for (values, expected) in [
            (vec![agent_message("unique")], 1),
            (vec![assistant(&["different"]), agent_message("unique")], 2),
            (
                vec![
                    assistant(&["same"]),
                    user("boundary"),
                    agent_message("same"),
                ],
                3,
            ),
            (
                vec![
                    assistant(&["same"]),
                    agent_message("same"),
                    agent_message("same"),
                ],
                2,
            ),
            (
                vec![
                    assistant(&["same"]),
                    agent_message("same"),
                    assistant(&["same"]),
                    agent_message("same"),
                ],
                2,
            ),
        ] {
            let mut input = vec![legacy.clone()];
            input.extend(values);
            let batch = acquire(source, &input).unwrap();
            assert!(batch.quarantined.is_empty());
            assert_eq!(batch.observations.len(), expected);
        }
        let paginated = acquire(
            source,
            &[meta(json!({})), assistant(&["same"]), agent_message("same")],
        )
        .unwrap();
        assert_eq!(
            paginated.observations.len(),
            2,
            "legacy pairing never applies in paginated mode"
        );
    });
}

#[test]
fn inter_agent_response_items_stay_unit_quarantined_not_legacy_events() {
    each(|source| {
        // The pinned harness persists inter-agent messages as their own
        // response item type; it is not a misplaced legacy assistant event.
        let inter_agent = json!({"type":"response_item","payload":{"type":"agent_message","id":"amsg-synthetic","author":"/root","recipient":"/root/worker","content":[{"type":"input_text","text":"PRIVATE"}],"internal_chat_message_metadata_passthrough":{"turn_id":"turn-a"}},"metadata":{"user_input_order":1}});
        // Unmapped content, even tool-shaped, is neither a tool fact nor evidence.
        let mut tool_shaped = Vec::new();
        for part in [
            json!({"type":"tool_use","id":"call-x","name":"shell","input":{"command":"curl https://private.invalid/PRIVATE /tmp/x"}}),
            json!({"type":"tool_result","tool_use_id":"call-x","content":"PRIVATE"}),
        ] {
            let mut record = inter_agent.clone();
            record["payload"]["content"] = json!([part]);
            tool_shaped.push(record);
        }
        for record in std::iter::once(&inter_agent).chain(&tool_shaped) {
            for history in ["legacy", "paginated"] {
                let batch = acquire(
                    source,
                    &[
                        meta(json!({"history_mode":history})),
                        user("before"),
                        record.clone(),
                        assistant(&["after"]),
                    ],
                )
                .expect("one unmapped unit must not fail the source");
                assert_eq!(batch.observations.len(), 2);
                assert_eq!(
                    batch
                        .quarantined
                        .iter()
                        .map(|unit| (unit.source_sequence, unit.code))
                        .collect::<Vec<_>>(),
                    [(2, "unknown_discriminator")]
                );
                assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
                let counts = &batch.accounting.sessions[0].counts;
                let kinds = &counts.record_counts;
                assert_eq!(
                    (
                        kinds.assistant_message,
                        kinds.tool_call,
                        kinds.tool_result,
                        kinds.other
                    ),
                    (1, 0, 0, 1)
                );
                assert_eq!(counts.contributions, Default::default());
                assert!(!private(&batch));
                let native = super::native::extract_codex_native_records(source).unwrap();
                assert!(native[2].blocks.is_none() && native[2].message_content.is_none());
                assert!(native[2].contribution_strings.is_empty());
            }
        }
        // An exact wrapper is required: a nested payload is still integrity drift.
        let nested = json!({"type":"response_item","payload":{"type":"agent_message","payload":{"type":"agent_message","message":"PRIVATE"}}});
        let error = acquire(
            source,
            &[meta(json!({})), user("supported neighbor"), nested],
        )
        .err()
        .expect("nested wrapper must fail the source");
        assert!(!format!("{error:?} {error}").contains("PRIVATE"));
    });
}

#[test]
fn record_gaps_keep_malformed_bounds_and_unknown_failures_visible() {
    each(|source| {
        let search = json!({"type":"response_item","payload":{"type":"web_search_call","action":{"type":"search","query":"synthetic"}}});
        let plan = completed(
            "thread-a",
            json!({"type":"Plan","id":"plan-a","text":"synthetic"}),
        );
        let event = agent_message("synthetic");
        let mut malformed = Vec::new();
        for value in [&search, &event] {
            malformed.push(value["payload"].clone());
            let mut wrong = value.clone();
            wrong["type"] = json!("unknown");
            malformed.push(wrong);
            let mut nested = value.clone();
            nested["payload"] = json!({"payload":value["payload"]});
            malformed.push(nested);
            if value["payload"]["type"] == "web_search_call" {
                let mut hidden = value.clone();
                hidden["payload"] =
                    json!({"type":"future","name":"bypass","payload":value["payload"]});
                malformed.push(hidden);
            }
            for shadow in ["session_meta", "tool_call"] {
                let mut shadowed = value.clone();
                shadowed["payload"]["payload"] = json!({"type":shadow});
                shadowed["payload"]["status"] = json!("error");
                malformed.push(shadowed);
            }
        }
        for (original, key) in [(&plan, "text"), (&event, "message")] {
            for bad in [
                None,
                Some(Value::Null),
                Some(json!({"private":"PRIVATE"})),
                Some(json!(42)),
            ] {
                let mut value = original.clone();
                let fields = if key == "text" {
                    &mut value["payload"]["item"]
                } else {
                    &mut value["payload"]
                };
                fields.as_object_mut().unwrap().remove(key);
                if let Some(bad) = bad {
                    fields[key] = bad;
                }
                malformed.push(value);
            }
        }
        for action in [
            json!([]),
            json!({}),
            json!({"type":"search","query":42}),
            json!({"type":"search","queries":["ok",42]}),
            json!({"type":"find_in_page","pattern":{}}),
        ] {
            let mut bad = search.clone();
            bad["payload"]["action"] = action;
            malformed.push(bad);
        }
        for (key, bad) in [("id", json!(42)), ("id", json!("")), ("status", json!({}))] {
            let mut value = search.clone();
            value["payload"][key] = bad;
            malformed.push(value);
        }
        for value in [&search, &event] {
            let mut wrong_owner = value.clone();
            wrong_owner["payload"]["thread_id"] = json!("other-owner");
            malformed.push(wrong_owner);
        }
        for bad in malformed {
            let error = acquire(source, &[meta(json!({})), user("supported neighbor"), bad])
                .err()
                .expect("malformed source must fail");
            assert!(!format!("{error:?} {error}").contains("PRIVATE"));
        }
        let mut future = search.clone();
        future["payload"]["action"] = json!({"type":"future","query":"PRIVATE"});
        let mut large_search = search;
        large_search["payload"]["action"]["query"] = json!("x".repeat(4097));
        let mut large_plan = plan;
        large_plan["payload"]["item"]["text"] = json!("x".repeat(65_537));
        let batch = acquire(
            source,
            &[
                meta(json!({})),
                user("neighbor"),
                future,
                large_search,
                large_plan,
                agent_message(&"x".repeat(65_537)),
            ],
        )
        .unwrap();
        assert_eq!(batch.observations.len(), 1);
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
        assert_eq!(
            batch
                .quarantined
                .iter()
                .map(|unit| (unit.source_sequence, unit.code))
                .collect::<Vec<_>>(),
            [
                (2, "unknown_discriminator"),
                (3, "unbounded_value"),
                (4, "unbounded_value"),
                (5, "unbounded_value")
            ]
        );
        assert!(!private(&batch));
        assert!(
            batch.accounting.sessions[0]
                .counts
                .contributions
                .tool_calls
                .is_empty()
        );
    });
}

#[test]
fn legacy_pairing_preserves_phase_ownership_tool_parts_and_quarantined_raw_text() {
    each(|source| {
        let legacy = meta(json!({"history_mode":"legacy"}));
        let mut phased = assistant(&["same"]);
        phased["payload"]["phase"] = json!("commentary");
        let mut phased_event = agent_message("same");
        phased_event["payload"]["phase"] = json!("final_answer");
        let mut other_owner = agent_message("same");
        other_owner["payload"]["session_id"] = json!("thread-b");
        let mut tool_message = assistant(&["same"]);
        tool_message["payload"]["content"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"tool_use","id":"call-a","name":"synthetic","input":{}}));
        for (raw, event, expected) in [
            (phased.clone(), phased_event, 2),
            (assistant(&["same"]), other_owner, 2),
            (tool_message, agent_message("same"), 3),
        ] {
            let batch = acquire(source, &[legacy.clone(), raw, event]).unwrap();
            assert!(batch.quarantined.is_empty());
            assert_eq!(batch.observations.len(), expected);
        }
        let mut same_phase = agent_message("same");
        same_phase["payload"]["phase"] = json!("commentary");
        assert_eq!(
            acquire(source, &[legacy.clone(), phased, same_phase])
                .unwrap()
                .observations
                .len(),
            1
        );
        // Each event fits individually, but the raw response's aggregate text does not.
        let text = "x".repeat(40_000);
        for reversed in [false, true] {
            let raw = assistant(&[&text, &text]);
            let events = [agent_message(&text), agent_message(&text)];
            let mut values = vec![legacy.clone()];
            if reversed {
                values.extend(events);
                values.push(raw);
            } else {
                values.push(raw);
                values.extend(events);
            }
            let batch = acquire(source, &values).unwrap();
            assert_eq!(
                batch.observations.len(),
                2,
                "usable events survive rejected raw content"
            );
            assert_eq!(batch.quarantined.len(), 1);
            assert_eq!(batch.quarantined[0].code, "unbounded_value");
            assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
        }
        // A Plan must never become authority for the existing raw/typed AgentMessage policy.
        let mut raw = assistant(&["same"]);
        raw["payload"]["id"] = json!("plan-a");
        raw["payload"]["internal_chat_message_metadata_passthrough"] = json!({"turn_id":"turn-a"});
        let plan = completed(
            "thread-a",
            json!({"type":"Plan","id":"plan-a","text":"same"}),
        );
        assert_eq!(
            acquire(source, &[legacy, raw, plan])
                .unwrap()
                .observations
                .len(),
            2
        );
    });
}

#[test]
fn hosted_search_text_folds_newlines_and_enforces_assembled_bounds() {
    each(|source| {
        let search = |action: Value| json!({"type":"response_item","payload":{"type":"web_search_call","action":action}});
        let action = json!({"type":"find_in_page","url":"https://synthetic.invalid","pattern":"line one\r\nline two"});
        let batch = acquire(source, &[meta(json!({})), search(action.clone())]).unwrap();
        assert!(batch.quarantined.is_empty());
        let ObservationBody::Tool(tool) = batch.observations[0].body() else {
            panic!("tool")
        };
        assert_eq!(
            tool.arguments(),
            Some(&JsonValue::try_from_source_value(&action).unwrap())
        );
        assert_eq!(
            tool.searchable_arguments(),
            Some("url https://synthetic.invalid pattern line one  line two ")
        );
        // query label + two separators consume seven bytes of the 4,096-byte view.
        for (bytes, kept) in [(4089, true), (4090, false)] {
            let batch = acquire(
                source,
                &[
                    meta(json!({})),
                    user("neighbor"),
                    search(json!({"type":"search","query":"x".repeat(bytes)})),
                ],
            )
            .unwrap();
            assert_eq!(batch.observations.len(), if kept { 2 } else { 1 });
            assert_eq!(batch.quarantined.len(), usize::from(!kept));
            if !kept {
                assert_eq!(batch.quarantined[0].code, "unbounded_value");
            }
        }
        let batch = acquire(
            source,
            &[
                meta(json!({})),
                user("neighbor"),
                search(
                    json!({"type":"search","query":"x".repeat(2050),"queries":["y".repeat(2050)]}),
                ),
            ],
        )
        .unwrap();
        assert_eq!(batch.observations.len(), 1);
        assert_eq!(batch.quarantined[0].code, "unbounded_value");
        assert!(
            batch.accounting.sessions[0]
                .counts
                .contributions
                .tool_calls
                .is_empty()
        );
    });
}
