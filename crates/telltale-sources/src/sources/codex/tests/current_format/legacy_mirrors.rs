use super::*;

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
