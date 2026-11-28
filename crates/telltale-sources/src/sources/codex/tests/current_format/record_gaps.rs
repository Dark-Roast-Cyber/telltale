use super::*;

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

        // Past the direct-text budget each value is replaced and recorded;
        // both records are admitted and the source reads as partly evaluated.
        let over = "x".repeat(65_537);
        let values = vec![
            meta(json!({})),
            json!({"type":"response_item","payload":{"type":"custom_tool_call","call_id":"call-b","name":"exec","input":over,"status":"completed"}}),
            json!({"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"call-b","output":[{"type":"input_text","text":over}]}}),
            user("synthetic after"),
        ];
        let batch = acquire(source, &values).unwrap();
        assert!(batch.quarantined.is_empty());
        assert_eq!(batch.observations.len(), 3);
        let ObservationBody::Tool(call) = batch.observations[0].body() else {
            panic!("tool call")
        };
        assert_eq!(call.name(), Some("exec"));
        assert_eq!(
            batch
                .bounded
                .iter()
                .map(|unit| (unit.native_id.as_str(), unit.target, unit.dimension))
                .collect::<Vec<_>>(),
            [
                (
                    "call-b",
                    telltale_schema::observation::BoundedTarget::Arguments,
                    BoundDimension::StringBytes
                ),
                (
                    "call-b",
                    telltale_schema::observation::BoundedTarget::Result,
                    BoundDimension::StringBytes
                ),
            ]
        );
        assert!(!format!("{:?}", batch.bounded).contains("xxxx"));
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
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
        // The search call's over-bound query is replaced and the call is
        // projected; the unknown action, the plan text and the message text
        // stay quarantined.
        assert_eq!(batch.observations.len(), 2);
        let ObservationBody::Tool(search) = batch.observations[1].body() else {
            panic!("search call")
        };
        assert_eq!(
            search
                .bounded_values()
                .iter()
                .map(|value| (value.target(), value.dimension()))
                .collect::<Vec<_>>(),
            [(
                telltale_schema::observation::BoundedTarget::Arguments,
                BoundDimension::StringBytes
            )]
        );
        assert_eq!(search.searchable_arguments(), None);
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
        assert_eq!(
            batch
                .quarantined
                .iter()
                .map(|unit| (unit.source_sequence, unit.code))
                .collect::<Vec<_>>(),
            [
                (2, "unknown_discriminator"),
                (4, "unbounded_value"),
                (5, "unbounded_value")
            ]
        );
        assert!(!private(&batch));
        // Neither the quarantined units nor the call with a replaced value
        // contribute.
        assert!(
            batch.accounting.sessions[0]
                .counts
                .contributions
                .tool_calls
                .is_empty()
        );
    });
}
