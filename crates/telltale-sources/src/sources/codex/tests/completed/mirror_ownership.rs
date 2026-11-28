use super::*;

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
        let native = super::super::super::native::extract_codex_native_records(source).unwrap();
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
