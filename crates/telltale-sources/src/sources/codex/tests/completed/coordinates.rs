use super::*;

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
        // Well-owned items this adapter cannot map are quarantined by
        // themselves; coordinates and wrappers stay whole-source integrity.
        let mut quarantined = Vec::new();
        for kind in ["agent_message", "Future"] {
            quarantined.push((completed(kind, "bad"), "unknown_discriminator"));
        }
        for kind in ["McpToolCall", "Extension"] {
            let mut v = completed(kind, "bad");
            v["payload"]["item"]["arguments"] = json!({"query":"PRIVATE"});
            quarantined.push((v, "unsupported_completed_item"));
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
                if level == 1 && key == "thread_id" {
                    // A consistent item of another thread, as a parent's
                    // rollout repeats its subagent's items.
                    quarantined.push((v, "foreign_thread_item"));
                } else {
                    invalid.push(v);
                }
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
        quarantined.push((mismatch, "foreign_thread_item"));
        let mut user = completed("UserMessage", "u");
        user["payload"]["item"]["content"] =
            json!([{"type":"text","text":"ok"},{"type":"image","image_url":"PRIVATE"}]);
        quarantined.push((user, "unknown_content_block"));
        for kind in ["audio", "local_image", "skill", "Future", "Text"] {
            let mut user = completed("UserMessage", "u");
            user["payload"]["item"]["content"] = json!([{"type":kind,"text":"PRIVATE"}]);
            quarantined.push((user, "unknown_content_block"));
        }
        let mut wrong = good.clone();
        wrong["payload"]["item"]["content"] = json!([{"type":"text","text":"PRIVATE"}]);
        quarantined.push((wrong, "unknown_content_block"));
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
        for (bad, code) in quarantined {
            let batch = acquire(source, &[meta(), good.clone(), bad]).unwrap();
            assert_eq!(batch.observations.len(), 1, "{code}");
            assert_eq!(batch.quarantined.len(), 1, "{code}");
            assert_eq!(batch.quarantined[0].code, code);
            assert_eq!(batch.quarantined[0].source_sequence, 2);
            assert_eq!(batch.quarantined[0].session_id.as_deref(), Some("child"));
            assert!(["bad", "u", "a"].contains(&batch.quarantined[0].native_id.as_str()));
            assert!(!format!("{:?}", batch.quarantined).contains("PRIVATE"));
        }
    });
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
        let native = super::super::super::native::extract_codex_native_records(source).unwrap();
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
