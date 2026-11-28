use super::*;

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
                let records =
                    super::super::super::native::extract_codex_native_records(source).unwrap();
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
        // Records whose discriminator is unknown, rather than a wrong
        // world-state shape.
        let mut unknown = Vec::new();
        for wrapper in ["event_msg", "response_item", "unknown"] {
            let mut bad = good.clone();
            bad["type"] = json!(wrapper);
            if wrapper == "response_item" {
                invalid.push(bad);
            } else {
                unknown.push(bad);
            }
            unknown.push(json!({"type":wrapper,"payload":good}));
        }
        invalid.push(json!({"type":"world_state","payload":{"payload":{"full":true,"state":{}}}}));
        let cases = invalid
            .into_iter()
            .map(|bad| (bad, false))
            .chain(unknown.into_iter().map(|bad| (bad, true)));
        for (bad, quarantines) in cases {
            // A wrong world-state shape fails the source; a record whose
            // discriminator is unknown is quarantined by itself. Neither is
            // ever projected.
            let label = bad.to_string();
            match acquire(
                source,
                &[meta(), good.clone(), completed("UserMessage", "u"), bad],
            ) {
                Err(error) => {
                    assert!(!quarantines, "{label}: {}", error.code());
                    assert!(!format!("{error:?} {error}").contains("PRIVATE-WORLD"));
                }
                Ok(batch) => {
                    assert!(quarantines, "{label}");
                    assert_eq!(batch.observations.len(), 1);
                    assert_eq!(batch.quarantined.len(), 1);
                    assert_eq!(batch.quarantined[0].code, "unknown_discriminator");
                    assert!(
                        !format!("{:?} {:?}", batch.observations, batch.quarantined)
                            .contains("PRIVATE-WORLD")
                    );
                }
            }
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
        // A late unknown event is quarantined by itself, in ordinal mode at
        // its native ordinal.
        let mut unknown =
            json!({"type":"event_msg","payload":{"type":"future_variant"},"ordinal":3});
        ordinal.push(unknown.clone());
        let batch = acquire(source, &ordinal).unwrap();
        assert_eq!(batch.quarantined.len(), 1);
        assert_eq!(batch.quarantined[0].code, "unknown_discriminator");
        assert_eq!(batch.quarantined[0].source_sequence, 3);
        unknown.as_object_mut().unwrap().remove("ordinal");
        let batch = acquire(source, &[meta(), good, unknown]).unwrap();
        assert_eq!(batch.quarantined[0].code, "unknown_discriminator");
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
