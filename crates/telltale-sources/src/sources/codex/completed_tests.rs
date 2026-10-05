use crate::acquisition::{AcquisitionOptions, AcquisitionProgress, acquire_source};
use serde_json::{Value, json};
use telltale_schema::observation::{
    JsonValue, MessageRole, ObservationBody, ObservationStage, ObservedAt, ToolStatus,
};
use telltale_schema::{
    clients::{ClientId, SourceKind},
    source::Source,
};

fn meta() -> Value {
    json!({"type":"session_meta","payload":{"id":"child","session_id":"root","history_mode":"paginated"}})
}

fn completed(kind: &str, id: &str) -> Value {
    let content = if kind == "UserMessage" {
        json!([{"type":"text","text":"synthetic"}])
    } else {
        json!([{"type":"Text","text":"synthetic"}])
    };
    json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"child","turn_id":"turn-a","item":{"type":kind,"id":id,"content":content}}})
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

fn acquire(
    source: &Source,
    values: &[Value],
) -> Result<crate::acquisition::AcquisitionBatch, crate::acquisition::AcquisitionError> {
    std::fs::write(
        &source.path,
        values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    acquire_source(
        source,
        AcquisitionOptions::new(ObservedAt::new("2026-10-03T12:00:00Z").unwrap()),
    )
}

#[test]
fn completed_messages_reasoning_coordinates_and_replay() {
    each(|source| {
        let mut agent = completed("AgentMessage", "assistant-id");
        agent["payload"]["item"]["content"] =
            json!([{"type":"Text","text":"a".repeat(5000)},{"type":"Text","text":"last"}]);
        let reasoning = json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"child","turn_id":"turn-a","item":{"type":"Reasoning","id":"reason-id","raw_content":["PRIVATE"],"summary_text":["PRIVATE"]}}});
        let values = [
            meta(),
            completed("UserMessage", "user-id"),
            agent,
            reasoning,
        ];
        let batch = acquire(source, &values).unwrap();
        let replay = acquire(source, &values).unwrap();
        assert_eq!(batch.observations.len(), 2);
        assert_eq!(batch.progress, AcquisitionProgress::None);
        assert_eq!(batch.accounting.sessions[0].session_id.value(), "child");
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 4);
        assert_eq!(batch.accounting.sessions[0].counts.record_counts.other, 1);
        for (index, role) in [MessageRole::User, MessageRole::Assistant]
            .into_iter()
            .enumerate()
        {
            let o = &batch.observations[index];
            assert_eq!(
                o.observation_id(),
                replay.observations[index].observation_id()
            );
            assert_eq!(o.session_id().unwrap().value(), "child");
            let ObservationBody::Message(m) = o.body() else {
                panic!("message")
            };
            assert_eq!(m.role(), Some(role));
        }
        assert!(!format!("{:?}", batch.observations).contains("PRIVATE"));
    });
}

#[test]
fn completed_rejects_late_wrong_shapes_and_ownership_atomically() {
    each(|source| {
        let good = completed("AgentMessage", "a");
        let mut invalid = Vec::new();
        for kind in ["agent_message", "Plan", "Future"] {
            invalid.push(completed(kind, "bad"));
        }
        for wrapper in ["response_item", "unknown"] {
            let mut v = good.clone();
            v["type"] = json!(wrapper);
            invalid.push(v);
        }
        invalid.push(good["payload"].clone());
        for path in [
            vec!["payload", "thread_id"],
            vec!["payload", "turn_id"],
            vec!["payload", "item", "id"],
        ] {
            for val in [json!(""), Value::Null, json!(42)] {
                let mut v = good.clone();
                let mut at = &mut v;
                for key in &path[..path.len() - 1] {
                    at = &mut at[*key];
                }
                at[path[path.len() - 1]] = val;
                invalid.push(v);
            }
        }
        for level in [0, 1, 2] {
            for key in ["session_id", "thread_id", "turn_id"] {
                if level == 1 && key == "turn_id" {
                    continue;
                }
                let mut v = good.clone();
                let at = match level {
                    0 => &mut v,
                    1 => &mut v["payload"],
                    _ => &mut v["payload"]["item"],
                };
                at[key] = json!("poison");
                invalid.push(v);
            }
        }
        for key in ["thread_id", "turn_id"] {
            let mut v = good.clone();
            v["payload"].as_object_mut().unwrap().remove(key);
            invalid.push(v);
        }
        let mut missing_item_id = good.clone();
        missing_item_id["payload"]["item"]
            .as_object_mut()
            .unwrap()
            .remove("id");
        invalid.push(missing_item_id);
        let mut mismatch = good.clone();
        mismatch["payload"]["thread_id"] = json!("other");
        invalid.push(mismatch);
        let mut user = completed("UserMessage", "u");
        user["payload"]["item"]["content"] =
            json!([{"type":"text","text":"ok"},{"type":"image","image_url":"PRIVATE"}]);
        invalid.push(user);
        for kind in ["audio", "local_image", "skill", "Future", "Text"] {
            let mut user = completed("UserMessage", "u");
            user["payload"]["item"]["content"] = json!([{"type":kind,"text":"PRIVATE"}]);
            invalid.push(user);
        }
        let mut wrong = good.clone();
        wrong["payload"]["item"]["content"] = json!([{"type":"text","text":"PRIVATE"}]);
        invalid.push(wrong);
        let mut ordinal = good.clone();
        ordinal["ordinal"] = json!(100);
        invalid.push(ordinal);
        let mut inherited = meta();
        inherited["payload"]["subagent_history_start_ordinal"] = json!(10);
        invalid.push(inherited);
        for bad in invalid {
            let error = acquire(source, &[meta(), good.clone(), bad])
                .err()
                .expect("late whole-source rejection");
            assert!(!format!("{error:?} {error}").contains("PRIVATE"));
        }
    });
}

#[test]
fn completed_command_terminal_structured_and_not_invocation() {
    each(|source| {
        for (status, mapped) in [
            ("completed", ToolStatus::Succeeded),
            ("failed", ToolStatus::Failed),
            ("declined", ToolStatus::Denied),
        ] {
            for output in [
                None,
                Some(""),
                Some("... command output truncated for persistence ..."),
                Some("synthetic diagnostic"),
            ] {
                let mut v = completed("CommandExecution", "call-a");
                let item = &mut v["payload"]["item"];
                item["command"] = json!(["/bin/sh", "-c", "printf 'a b'", ""]);
                item["cwd"] = json!("/synthetic");
                item["status"] = json!(status);
                item["exit_code"] = json!(-1);
                if let Some(output) = output {
                    item["aggregated_output"] = json!(output);
                }
                let batch = acquire(source, &[meta(), v]).unwrap();
                assert_eq!(
                    batch.accounting.sessions[0].counts.record_counts.tool_call,
                    0
                );
                assert_eq!(
                    batch.accounting.sessions[0]
                        .counts
                        .record_counts
                        .tool_result,
                    1
                );
                assert_eq!(
                    batch.accounting.sessions[0].counts.contributions,
                    Default::default()
                );
                let o = &batch.observations[0];
                assert_eq!(o.stage(), ObservationStage::ToolResultReturned);
                assert_eq!(o.correlation().call_id().unwrap().value(), "call-a");
                let ObservationBody::Tool(t) = o.body() else {
                    panic!("tool")
                };
                assert_eq!(t.name(), None);
                assert_eq!(t.reported_status(), Some(mapped));
                assert_eq!(
                    o.fact_metadata()["tool.reported_status"].provenance(),
                    telltale_schema::observation::FactProvenance::Reported
                );
                assert_eq!(
                    o.capability_context()
                        .unwrap()
                        .resolve(telltale_schema::observation::CapabilityId::ToolExecution),
                    telltale_schema::observation::CapabilityAvailability::Unsupported
                );
                assert_eq!(
                    t.arguments(),
                    Some(&JsonValue::array(
                        ["/bin/sh", "-c", "printf 'a b'", ""]
                            .into_iter()
                            .map(JsonValue::string)
                            .collect()
                    ))
                );
                let expected_fidelity = match output {
                    None => "not_captured",
                    Some("... command output truncated for persistence ...") => "truncated",
                    Some(_) if status != "completed" => "diagnostic_or_capture",
                    Some(_) => "capture_completeness_unknown",
                };
                assert_eq!(
                    o.facets()["tool.output_fidelity"].value(),
                    &JsonValue::string(expected_fidelity)
                );
                assert_eq!(
                    o.facets()["resource.path"].value(),
                    &JsonValue::string("/synthetic")
                );
                assert!(t.result().is_some());
            }
        }
        let mut bad = completed("CommandExecution", "call-a");
        bad["payload"]["item"]["command"] = json!(["echo"]);
        bad["payload"]["item"]["status"] = json!("in_progress");
        assert!(acquire(source, &[meta(), bad]).is_err());
    });
}

#[test]
fn completed_mirror_authority_is_coordinate_not_content_based() {
    each(|source| {
        let raw = |role: &str, id: &str, turn: Option<&str>| {
            let mut v = json!({"type":"response_item","payload":{"type":"message","role":role,"id":id,"content":[{"type":"output_text","text":"synthetic"}]}});
            if let Some(turn) = turn {
                v["payload"]["internal_chat_message_metadata_passthrough"] =
                    json!({"turn_id":turn});
            }
            v
        };
        let batch = acquire(
            source,
            &[
                meta(),
                raw("assistant", "same", Some("turn-a")),
                completed("AgentMessage", "same"),
                raw("assistant", "distinct", Some("turn-a")),
                raw("assistant", "same", None),
                raw("user", "raw-user", Some("turn-a")),
                completed("UserMessage", "typed-user"),
                raw("user", "other-turn", Some("turn-b")),
                raw("user", "ambiguous", None),
            ],
        )
        .unwrap();
        assert_eq!(batch.observations.len(), 6);
        let mut legacy = meta();
        legacy["payload"]["history_mode"] = json!("legacy");
        assert_eq!(
            acquire(
                source,
                &[
                    legacy,
                    raw("user", "raw-user", Some("turn-a")),
                    completed("UserMessage", "typed-user")
                ]
            )
            .unwrap()
            .observations
            .len(),
            2
        );
        assert_eq!(
            acquire(source, &[completed("AgentMessage", "alone")])
                .unwrap()
                .observations
                .len(),
            1
        );
    });
}

#[test]
fn completed_native_identity_is_owner_turn_item_scoped_not_file_position() {
    each(|source| {
        let first = completed("AgentMessage", "stable");
        let original = acquire(source, std::slice::from_ref(&first))
            .unwrap()
            .observations
            .remove(0);
        let mut changed = first.clone();
        changed["payload"]["item"]["content"][0]["text"] = json!("mutated");
        let replay = acquire(source, &[meta(), changed])
            .unwrap()
            .observations
            .remove(0);
        assert_eq!(original.observation_id(), replay.observation_id());
        assert_eq!(
            original
                .semantic_comparison()
                .compare(replay.semantic_comparison()),
            telltale_schema::observation::SemanticReplayVerdict::Mutated
        );
        for (key, value) in [("thread_id", "other-child"), ("turn_id", "other-turn")] {
            let mut other = first.clone();
            other["payload"][key] = json!(value);
            assert_ne!(
                original.observation_id(),
                acquire(source, &[other]).unwrap().observations[0].observation_id()
            );
        }
        let native = super::native::extract_codex_native_records(source).unwrap();
        assert_eq!(native[0].completed.as_ref().unwrap().turn_id, "other-turn");
        let mut stray = first.clone();
        stray["session_meta"] = json!({"id":"poison"});
        assert_eq!(
            acquire(source, &[stray, completed("UserMessage", "u")])
                .unwrap()
                .accounting
                .sessions[0]
                .session_id
                .value(),
            "child"
        );
        let mut poison = meta();
        poison["session_id"] = json!("poison");
        assert!(acquire(source, &[poison, first]).is_err());
    });
}

#[test]
fn completed_tool_bounds_missing_values_and_separate_stages() {
    each(|source| {
        let command = |argv: Value| {
            let mut v = completed("CommandExecution", "call-a");
            v["payload"]["item"]["command"] = argv;
            v["payload"]["item"]["status"] = json!("completed");
            v
        };
        let empty = acquire(source, &[meta(), command(json!(["echo"]))]).unwrap();
        let ObservationBody::Tool(t) = empty.observations[0].body() else {
            panic!("tool")
        };
        assert_eq!(t.result(), None);
        assert_eq!(
            empty.observations[0].facets()["tool.output_fidelity"].value(),
            &JsonValue::string("not_captured")
        );
        for exit in [0, 1, -1] {
            let mut v = command(json!(["echo"]));
            v["payload"]["item"]["exit_code"] = json!(exit);
            let batch = acquire(source, &[meta(), v]).unwrap();
            let ObservationBody::Tool(t) = batch.observations[0].body() else {
                panic!("tool")
            };
            assert_eq!(
                t.result(),
                Some(&JsonValue::object([("exit_code".into(), JsonValue::Integer(exit))]).unwrap())
            );
        }
        let mut null = command(json!(["echo"]));
        null["payload"]["item"]["exit_code"] = Value::Null;
        null["payload"]["item"]["aggregated_output"] = Value::Null;
        assert!(acquire(source, &[meta(), null]).unwrap().observations.len() == 1);
        for argv in [
            json!(["x".repeat(4097)]),
            json!(vec!["x".repeat(4096); 5]),
            json!("echo joined"),
            json!([42]),
        ] {
            assert!(
                acquire(
                    source,
                    &[meta(), completed("AgentMessage", "valid"), command(argv)]
                )
                .is_err()
            );
        }
        for key in ["exit_code", "aggregated_output"] {
            let mut bad = command(json!(["echo"]));
            bad["payload"]["item"][key] = json!({"bad":"PRIVATE"});
            assert!(acquire(source, &[meta(), bad]).is_err());
        }
        let request = json!({"type":"response_item","payload":{"type":"function_call","id":"response-not-call","call_id":"call-a","name":"exec","arguments":{"command":"printf synthetic"}}});
        let returned = json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"call-a","output":"synthetic"}});
        let batch = acquire(
            source,
            &[
                meta(),
                request,
                returned,
                command(json!(["printf", "synthetic"])),
            ],
        )
        .unwrap();
        assert_eq!(batch.observations.len(), 3);
        assert_eq!(
            batch.observations[0].stage(),
            ObservationStage::ToolRequested
        );
        assert!(
            batch.observations[1..]
                .iter()
                .all(|o| o.stage() == ObservationStage::ToolResultReturned)
        );
        assert!(
            batch
                .observations
                .iter()
                .all(|o| o.correlation().call_id().unwrap().value() == "call-a")
        );
    });
}

#[test]
fn completed_ambiguous_mirrors_preserve_and_conflicting_proven_mirror_rejects() {
    each(|source| {
        let raw = |id: Value, turn: Value| json!({"type":"response_item","payload":{"type":"message","id":id,"role":"assistant","internal_chat_message_metadata_passthrough":{"turn_id":turn},"content":[{"type":"output_text","text":"synthetic"}]}});
        for (id, turn) in [
            (Value::Null, json!("turn-a")),
            (json!("same"), Value::Null),
            (json!("distinct"), json!("turn-a")),
            (json!("same"), json!("turn-b")),
        ] {
            assert_eq!(
                acquire(
                    source,
                    &[meta(), raw(id, turn), completed("AgentMessage", "same")]
                )
                .unwrap()
                .observations
                .len(),
                2
            );
        }
        let mut mutated = raw(json!("same"), json!("turn-a"));
        mutated["payload"]["content"][0]["text"] = json!("mutated");
        assert!(
            acquire(
                source,
                &[meta(), mutated, completed("AgentMessage", "same")]
            )
            .is_err()
        );
        let user = json!({"type":"response_item","payload":{"type":"message","role":"user","internal_chat_message_metadata_passthrough":{"turn_id":"turn-a"},"content":[{"type":"input_text","text":"raw synthetic"}]}});
        assert_eq!(
            acquire(
                source,
                &[meta(), user, completed("UserMessage", "different-id")]
            )
            .unwrap()
            .observations
            .len(),
            1
        );
    });
}

#[test]
fn completed_stray_metadata_cannot_establish_owner() {
    each(|source| {
        let stray = json!({"session_id":"child","session_meta":{"id":"child"}});
        assert!(
            acquire(
                source,
                &[
                    stray,
                    json!({"type":"user","content":"synthetic"}),
                    completed("AgentMessage", "a")
                ]
            )
            .is_err()
        );
    });
}

#[test]
fn completed_raw_mirror_cannot_ignore_explicit_thread_owner() {
    each(|source| {
        for level in [0, 1] {
            let mut raw = json!({"type":"response_item","payload":{"type":"message","id":"same","role":"assistant","internal_chat_message_metadata_passthrough":{"turn_id":"turn-a"},"content":[{"type":"output_text","text":"synthetic"}]}});
            let at = if level == 0 {
                &mut raw
            } else {
                &mut raw["payload"]
            };
            at["thread_id"] = json!("other-child");
            let result = acquire(source, &[meta(), raw, completed("AgentMessage", "same")]);
            assert!(result.is_err() || result.unwrap().observations.len() == 2);
        }
    });
}

#[test]
fn completed_unrelated_metadata_never_proves_raw_mirror_turn() {
    each(|source| {
        for (role, kind) in [("assistant", "AgentMessage"), ("user", "UserMessage")] {
            for level in [0, 1] {
                for key in ["metadata", "internal_chat_message_metadata_passthrough"] {
                    if level == 1 && key == "internal_chat_message_metadata_passthrough" {
                        continue;
                    }
                    let mut raw = json!({"type":"response_item","payload":{"type":"message","id":"same","role":role,"content":[{"type":"output_text","text":"synthetic"}]}});
                    let at = if level == 0 {
                        &mut raw
                    } else {
                        &mut raw["payload"]
                    };
                    at[key] = json!({"turn_id":"turn-a"});
                    assert_eq!(
                        acquire(source, &[meta(), raw, completed(kind, "same")])
                            .unwrap()
                            .observations
                            .len(),
                        2,
                        "stray metadata must not authorize suppression"
                    );
                }
            }
            let mut raw = json!({"type":"response_item","metadata":{"turn_id":"harness-turn"},"payload":{"type":"message","id":"same","role":role,"internal_chat_message_metadata_passthrough":{"turn_id":"turn-a"},"metadata":{"turn_id":"unrelated-turn"},"content":[{"type":"output_text","text":"synthetic"}]}});
            assert_eq!(
                acquire(source, &[meta(), raw.clone(), completed(kind, "same")])
                    .unwrap()
                    .observations
                    .len(),
                1,
                "only the public payload passthrough field supplies the turn"
            );
            raw["payload"]["internal_chat_message_metadata_passthrough"] = Value::Null;
            assert_eq!(
                acquire(source, &[meta(), raw, completed(kind, "same")])
                    .unwrap()
                    .observations
                    .len(),
                2
            );
            let direct_only = json!({"type":"response_item","turn_id":"turn-a","payload":{"type":"message","id":"same","role":role,"turn_id":"turn-a","content":[{"type":"output_text","text":"synthetic"}]}});
            assert_eq!(
                acquire(source, &[meta(), direct_only, completed(kind, "same")])
                    .unwrap()
                    .observations
                    .len(),
                2
            );
        }
    });
}

#[test]
fn completed_public_raw_turn_metadata_validation_is_source_atomic() {
    each(|source| {
        let raw = json!({"type":"response_item","payload":{"type":"message","id":"same","role":"assistant","internal_chat_message_metadata_passthrough":{"turn_id":"turn-a"},"content":[{"type":"output_text","text":"synthetic"}]}});
        let mut invalid = Vec::new();
        for metadata in [json!("PRIVATE"), json!([]), json!(42), json!(false)] {
            let mut v = raw.clone();
            v["payload"]["internal_chat_message_metadata_passthrough"] = metadata;
            invalid.push(v);
        }
        for turn in [
            json!(""),
            json!("  "),
            json!(42),
            json!({}),
            json!("x".repeat(4097)),
            json!("PRIVATE\nturn"),
        ] {
            let mut v = raw.clone();
            v["payload"]["internal_chat_message_metadata_passthrough"]["turn_id"] = turn;
            invalid.push(v);
        }
        for level in [0, 1] {
            for turn in [json!("other-turn"), json!(""), Value::Null, json!(42)] {
                let mut v = raw.clone();
                let at = if level == 0 {
                    &mut v
                } else {
                    &mut v["payload"]
                };
                at["turn_id"] = turn;
                invalid.push(v);
            }
        }
        for bad in invalid {
            let error = acquire(source, &[meta(), completed("AgentMessage", "same"), bad])
                .err()
                .expect("late raw coordinate validation must reject atomically");
            assert!(!format!("{error:?} {error}").contains("PRIVATE"));
        }
        for metadata in [Value::Null, json!({}), json!({"turn_id":null})] {
            let mut v = raw.clone();
            v["payload"]["internal_chat_message_metadata_passthrough"] = metadata;
            assert_eq!(
                acquire(source, &[meta(), completed("AgentMessage", "same"), v])
                    .unwrap()
                    .observations
                    .len(),
                2,
                "optional metadata absence cannot prove a mirror"
            );
        }
        let mut exact_bound = raw.clone();
        exact_bound["payload"]["internal_chat_message_metadata_passthrough"]["turn_id"] =
            json!("x".repeat(4096));
        assert_eq!(
            acquire(
                source,
                &[meta(), completed("AgentMessage", "same"), exact_bound]
            )
            .unwrap()
            .observations
            .len(),
            2
        );
        let mut contradictory = raw.clone();
        contradictory["payload"]["internal_chat_message_metadata_passthrough"] = Value::Null;
        contradictory["turn_id"] = json!("turn-a");
        contradictory["payload"]["turn_id"] = json!("turn-b");
        assert!(acquire(source, &[meta(), contradictory]).is_err());
        let mut v = raw;
        v["turn_id"] = json!("turn-a");
        v["payload"]["turn_id"] = json!("turn-a");
        assert_eq!(
            acquire(source, &[meta(), completed("AgentMessage", "same"), v])
                .unwrap()
                .observations
                .len(),
            1
        );
    });
}

fn ordinal_records() -> Vec<Value> {
    let raw = json!({"type":"response_item","payload":{"type":"message","role":"assistant","id":"same","internal_chat_message_metadata_passthrough":{"turn_id":"turn-a"},"content":[{"type":"output_text","text":"synthetic"}]}});
    let mut command = completed("CommandExecution", "call-a");
    command["payload"]["item"]["command"] = json!(["printf", "synthetic"]);
    command["payload"]["item"]["status"] = json!("completed");
    let mut values = vec![
        meta(),
        json!({"type":"event_msg","payload":{"type":"token_count"}}),
        raw,
        completed("AgentMessage", "same"),
        completed("UserMessage", "u"),
        command,
    ];
    for (ordinal, value) in values.iter_mut().enumerate() {
        value["ordinal"] = json!(ordinal);
    }
    values
}

#[test]
fn completed_self_contained_ordinals_preserve_accounting_coordinates_and_legacy() {
    each(|source| {
        let values = ordinal_records();
        let batch = acquire(source, &values).unwrap();
        let replay = acquire(source, &values).unwrap();
        assert_eq!(batch.observations.len(), 3);
        assert_eq!(batch.accounting, replay.accounting);
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 6);
        assert_eq!(batch.accounting.sessions[0].counts.record_counts.other, 1);
        assert_eq!(batch.progress, AcquisitionProgress::None);
        for (o, ordinal) in batch.observations.iter().zip([3, 4, 5]) {
            assert_eq!(o.source().source_sequence(), Some(ordinal));
            assert_eq!(o.sequence(), Some(ordinal));
            assert_eq!(o.identity_basis().child_ordinal(), 0);
        }
        let legacy = values
            .iter()
            .cloned()
            .map(|mut v| {
                v.as_object_mut().unwrap().remove("ordinal");
                v
            })
            .collect::<Vec<_>>();
        let legacy_batch = acquire(source, &legacy).unwrap();
        for (native, legacy) in batch.observations.iter().zip(&legacy_batch.observations) {
            assert_eq!(native.observation_id(), legacy.observation_id());
        }
        let contents = values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n \t\n");
        std::fs::write(&source.path, format!("\n\n{contents}\n \n")).unwrap();
        let native = super::native::extract_codex_native_records(source).unwrap();
        assert_eq!(
            native.iter().map(|r| r.source_sequence).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4, 5]
        );
        let blank_batch = acquire_source(
            source,
            AcquisitionOptions::new(ObservedAt::new("2026-10-03T12:00:00Z").unwrap()),
        )
        .unwrap();
        assert_eq!(batch.accounting, blank_batch.accounting);
        for (original, blank) in batch.observations.iter().zip(&blank_batch.observations) {
            assert_eq!(original.observation_id(), blank.observation_id());
        }
        let legacy_values = vec![
            json!({"type":"session_meta","payload":{"session_id":"legacy"}}),
            json!({"type":"user","content":"synthetic legacy"}),
        ];
        let before = acquire(source, &legacy_values)
            .unwrap()
            .observations
            .remove(0);
        assert_eq!(before.source().source_sequence(), Some(1));
        use telltale_schema::observation::{
            CanonicalObservationV2, FactMetadata, Fidelity, IngestionMode, MessageObservation,
            SourceProvenance,
        };
        let legacy_identity = CanonicalObservationV2::builder(
            ObservationBody::Message(MessageObservation::new(MessageRole::User)),
            ObservationStage::MessageObserved,
            ObservedAt::new("2026-10-03T12:00:00Z").unwrap(),
            SourceProvenance::new(
                IngestionMode::SessionStore,
                "codex",
                &source.source_id,
                Fidelity::PartialStructured,
            )
            .unwrap()
            .with_source_sequence(1)
            .with_identity_source_sequence("legacy", 1)
            .unwrap(),
        )
        .fact_metadata("message.role", FactMetadata::reported().unwrap())
        .build()
        .unwrap();
        assert_eq!(before.observation_id(), legacy_identity.observation_id());
    });
}

#[test]
fn completed_native_ordinals_reject_incomplete_or_inconsistent_sources_atomically() {
    each(|source| {
        let values = ordinal_records();
        let mut invalid = Vec::new();
        for index in [0, 1, 2, 5] {
            for ordinal in [
                Value::Null,
                json!("0"),
                json!(-1),
                json!(1.5),
                json!(u64::MAX),
                json!(6),
                json!(0),
                serde_json::from_str::<Value>("18446744073709551616").unwrap(),
            ] {
                if index == 0 && ordinal == json!(0) {
                    continue;
                }
                let mut v = values.clone();
                v[index]["ordinal"] = ordinal;
                invalid.push(v);
            }
            let mut v = values.clone();
            v[index].as_object_mut().unwrap().remove("ordinal");
            invalid.push(v);
        }
        for ordinal in [3, 4] {
            let mut v = values.clone();
            v[5]["ordinal"] = json!(ordinal);
            invalid.push(v);
        }
        for mode in [Value::Null, json!("legacy"), json!("Paginated"), json!(42)] {
            let mut v = values.clone();
            v[0]["payload"]["history_mode"] = mode;
            invalid.push(v);
        }
        let mut absent_mode = values.clone();
        absent_mode[0]["payload"]
            .as_object_mut()
            .unwrap()
            .remove("history_mode");
        invalid.push(absent_mode);
        for owner in [
            Value::Null,
            json!(""),
            json!("  "),
            json!(42),
            json!("x".repeat(4097)),
        ] {
            let mut v = values.clone();
            v[0]["payload"]["id"] = owner;
            invalid.push(v);
        }
        let mut absent_owner = values.clone();
        absent_owner[0]["payload"]
            .as_object_mut()
            .unwrap()
            .remove("id");
        invalid.push(absent_owner);
        for first in [
            json!({"type":"event_msg","ordinal":0,"payload":{"type":"token_count"}}),
            json!({"type":"session_meta","ordinal":0,"payload":null}),
            json!({"type":"unknown","ordinal":0,"payload":{"id":"child","history_mode":"paginated"}}),
        ] {
            let mut v = values.clone();
            v[0] = first;
            invalid.push(v);
        }
        for key in ["history_base", "subagent_history_start_ordinal"] {
            for prefix in [json!(0), json!({"end_ordinal_exclusive":0})] {
                let mut v = values.clone();
                v[0]["payload"][key] = prefix;
                invalid.push(v);
            }
        }
        for bad in invalid {
            assert!(
                acquire(source, &bad).is_err(),
                "invalid ordinal source must reject atomically"
            );
        }
    });
}

fn world_state(full: bool, state: Value) -> Value {
    json!({"type":"world_state","payload":{"full":full,"state":state}})
}

#[test]
fn completed_world_state_is_opaque_auxiliary_with_truthful_ordinals() {
    each(|source| {
        for full in [false, true] {
            for state in [
                json!({}),
                json!({"type":"item_completed","thread_id":"poison","turn_id":"poison","session_id":"poison","model":"PRIVATE-WORLD","provider":"PRIVATE-WORLD","item":{"type":"CommandExecution","id":"poison","command":["PRIVATE-WORLD"]},"message":{"role":"user","content":"PRIVATE-WORLD"},"tool_name":"PRIVATE-WORLD","arguments":{"command":"PRIVATE-WORLD"}}),
            ] {
                let mut values = vec![
                    meta(),
                    world_state(full, state),
                    completed("UserMessage", "u"),
                ];
                for (ordinal, value) in values.iter_mut().enumerate() {
                    value["ordinal"] = json!(ordinal);
                }
                let batch = acquire(source, &values).unwrap();
                let replay = acquire(source, &values).unwrap();
                assert_eq!(batch.observations.len(), 1);
                assert_eq!(batch.accounting, replay.accounting);
                assert_eq!(batch.accounting.sessions.len(), 1);
                assert_eq!(batch.accounting.sessions[0].session_id.value(), "child");
                assert_eq!(batch.accounting.sessions[0].counts.native_units, 3);
                assert_eq!(batch.accounting.sessions[0].counts.record_counts.other, 1);
                assert_eq!(
                    batch.accounting.sessions[0].counts.contributions,
                    Default::default()
                );
                assert_eq!(batch.observations[0].source().source_sequence(), Some(2));
                assert_eq!(
                    batch.observations[0].observation_id(),
                    replay.observations[0].observation_id()
                );
                let records = super::native::extract_codex_native_records(source).unwrap();
                let world = &records[1];
                assert!(world.auxiliary);
                assert!(!world.session_metadata);
                assert_eq!(
                    world.accounting_kind(),
                    telltale_schema::record::RecordKind::Other
                );
                assert!(
                    world.message_content.is_none()
                        && world.blocks.is_none()
                        && world.completed.is_none()
                );
                assert!(
                    world.tool.name.is_none()
                        && world.tool.arguments.is_none()
                        && world.tool.result.is_none()
                );
                assert!(world.contribution_strings.is_empty());
                assert!(
                    !format!(
                        "{records:?} {:?} {:?}",
                        batch.observations, batch.accounting
                    )
                    .contains("PRIVATE-WORLD")
                );
            }
        }
    });
}

#[test]
fn completed_world_state_rejects_wrong_shapes_and_late_failures_atomically() {
    each(|source| {
        let good = world_state(
            true,
            json!({"type":"item_completed","text":"PRIVATE-WORLD"}),
        );
        let mut invalid = vec![json!({"type":"world_state"})];
        for payload in [Value::Null, json!([]), json!("PRIVATE-WORLD")] {
            invalid.push(json!({"type":"world_state","payload":payload}));
        }
        for key in ["full", "state"] {
            let mut missing = good.clone();
            missing["payload"].as_object_mut().unwrap().remove(key);
            invalid.push(missing);
            let wrong = if key == "full" {
                vec![Value::Null, json!(0), json!("true"), json!({}), json!([])]
            } else {
                vec![
                    Value::Null,
                    json!(false),
                    json!(0),
                    json!("PRIVATE-WORLD"),
                    json!([]),
                ]
            };
            for value in wrong {
                let mut bad = good.clone();
                bad["payload"][key] = value;
                invalid.push(bad);
            }
        }
        for key in ["type", "payload"] {
            for value in [
                Value::Null,
                json!("item_completed"),
                json!({"type":"item_completed"}),
            ] {
                let mut bad = good.clone();
                bad["payload"][key] = value;
                invalid.push(bad);
            }
        }
        invalid.push(good["payload"].clone());
        for wrapper in ["event_msg", "response_item", "unknown"] {
            let mut bad = good.clone();
            bad["type"] = json!(wrapper);
            invalid.push(bad);
            invalid.push(json!({"type":wrapper,"payload":good}));
        }
        invalid.push(json!({"type":"world_state","payload":{"payload":{"full":true,"state":{}}}}));
        for bad in invalid {
            let error = acquire(
                source,
                &[meta(), good.clone(), completed("UserMessage", "u"), bad],
            )
            .err()
            .expect("late unsupported world state must reject source");
            assert!(!format!("{error:?} {error}").contains("PRIVATE-WORLD"));
        }
        let mut ordinal = vec![meta(), good.clone(), completed("UserMessage", "u")];
        for (index, value) in ordinal.iter_mut().enumerate() {
            value["ordinal"] = json!(index);
        }
        for coordinate in [0, 3] {
            let mut bad = ordinal.clone();
            bad[1]["ordinal"] = json!(coordinate);
            assert!(acquire(source, &bad).is_err());
        }
        for key in ["history_base", "subagent_history_start_ordinal"] {
            let mut bad = ordinal.clone();
            bad[0]["payload"][key] = json!(0);
            assert!(acquire(source, &bad).is_err());
        }
        let mut unknown =
            json!({"type":"event_msg","payload":{"type":"future_variant"},"ordinal":3});
        ordinal.push(unknown.clone());
        assert!(acquire(source, &ordinal).is_err());
        unknown.as_object_mut().unwrap().remove("ordinal");
        assert!(acquire(source, &[meta(), good, unknown]).is_err());
    });
}

#[test]
fn completed_world_state_owner_is_direct_envelope_only_and_never_inherited() {
    each(|source| {
        let good = world_state(
            false,
            json!({"session_id":"state-owner","model":"PRIVATE-WORLD","message":{"session_id":"state-owner"}}),
        );
        let unscoped = acquire(source, std::slice::from_ref(&good)).unwrap();
        assert!(unscoped.observations.is_empty() && unscoped.accounting.sessions.is_empty());
        assert!(
            acquire(
                source,
                &[good.clone(), json!({"type":"user","content":"synthetic"})]
            )
            .is_err()
        );
        for level in [0, 1] {
            for id in [
                json!(42),
                json!("x".repeat(4097)),
                json!("PRIVATE-WORLD\nowner"),
            ] {
                let mut bad = good.clone();
                let at = if level == 0 {
                    &mut bad
                } else {
                    &mut bad["payload"]
                };
                at["session_id"] = id;
                assert!(acquire(source, &[meta(), bad, completed("UserMessage", "u")]).is_err());
            }
            let mut auxiliary = good.clone();
            auxiliary["session_meta"] = json!({"session_id":"b"});
            let at = if level == 0 {
                &mut auxiliary
            } else {
                &mut auxiliary["payload"]
            };
            at["session_id"] = json!("b");
            let batch = acquire(
                source,
                &[meta(), auxiliary.clone(), completed("UserMessage", "u")],
            )
            .unwrap();
            assert_eq!(batch.observations[0].session_id().unwrap().value(), "child");
            assert_eq!(batch.accounting.sessions.len(), 2);
            assert!(
                acquire(
                    source,
                    &[auxiliary, json!({"type":"user","content":"synthetic"})]
                )
                .is_err()
            );
        }
        let mut conflict = good.clone();
        conflict["session_id"] = json!("a");
        conflict["payload"]["session_id"] = json!("b");
        assert!(acquire(source, &[meta(), conflict]).is_err());
        let mut poison = good;
        poison["session_meta"] = json!({"session_id":"poison","model":"PRIVATE-WORLD"});
        poison["message"] = json!({"session_id":"poison","model":"PRIVATE-WORLD"});
        let batch = acquire(source, &[meta(), poison, completed("UserMessage", "u")]).unwrap();
        assert_eq!(batch.accounting.sessions.len(), 1);
        assert_eq!(batch.observations[0].session_id().unwrap().value(), "child");
    });
}
