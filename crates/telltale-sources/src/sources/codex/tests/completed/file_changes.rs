use super::*;

#[test]
fn completed_file_change_preserves_native_patch_status_identity_and_accounting() {
    use telltale_schema::observation::{CapabilityAvailability, CapabilityId, FactProvenance};
    each(|source| {
        let changes = json!({
            "/synthetic/z.txt":{"type":"delete","content":"removed-only"},
            "/synthetic/a.txt":{"type":"add","content":"added-only"},
            "/synthetic/m.txt":{"type":"update","unified_diff":"@@\n-old-only\n+new-only\n","move_path":"/synthetic/moved.txt"}
        });
        for (status, mapped) in [
            (Some(json!("completed")), Some(ToolStatus::Succeeded)),
            (Some(json!("failed")), Some(ToolStatus::Failed)),
            (Some(json!("declined")), Some(ToolStatus::Denied)),
            (Some(Value::Null), None),
            (None, None),
        ] {
            let mut value = file_change(changes.clone());
            let item = value["payload"]["item"].as_object_mut().unwrap();
            item.remove("status");
            if let Some(status) = &status {
                item.insert("status".into(), status.clone());
            }
            item.insert("stdout".into(), json!(""));
            item.insert("stderr".into(), Value::Null);
            item.insert("auto_approved".into(), json!(false));
            item.insert("arbitrary".into(), json!({"content":"EXCLUDED-PRIVATE"}));
            value["timestamp"] = json!("2026-10-02T00:00:00Z");
            let batch = acquire(source, &[meta(), value.clone()]).unwrap();
            assert!(batch.quarantined.is_empty());
            assert_eq!(batch.observations.len(), 1);
            assert_eq!(
                batch.accounting.coverage,
                crate::acquisition::AccountingCoverage::CompleteSource
            );
            let counts = &batch.accounting.sessions[0].counts;
            assert_eq!(counts.native_units, 2);
            assert_eq!(counts.record_counts.tool_result, 1);
            assert_eq!(counts.record_counts.tool_call, 0);
            assert_eq!(counts.contributions, Default::default());
            let o = &batch.observations[0];
            assert_eq!(o.stage(), ObservationStage::ToolResultReturned);
            assert_eq!(o.source().adapter_id(), source.source_id);
            assert_eq!(o.session_id().unwrap().value(), "child");
            assert_eq!(
                o.correlation(),
                &telltale_schema::observation::CorrelationIds::new()
                    .with_turn_id(
                        telltale_schema::observation::CorrelationId::source_reported("turn-a")
                            .unwrap()
                    )
                    .with_response_id(
                        telltale_schema::observation::CorrelationId::source_reported("patch-a")
                            .unwrap()
                    )
            );
            assert!(o.correlation().call_id().is_none());
            assert_eq!(
                o.source().native_id(),
                Some(r#"["child","turn-a","patch-a"]"#)
            );
            assert_eq!(o.source().source_sequence(), Some(1));
            assert_eq!(o.identity_basis().child_ordinal(), 0);
            assert_eq!(o.occurred_at().unwrap().as_str(), "2026-10-02T00:00:00Z");
            assert_eq!(o.observed_at().as_str(), "2026-10-03T12:00:00Z");
            assert_eq!(
                o.facets()["session.root_id"].value(),
                &JsonValue::string("root")
            );
            assert_eq!(
                o.capability_context()
                    .unwrap()
                    .resolve(CapabilityId::ToolExecution),
                CapabilityAvailability::Unsupported
            );
            let ObservationBody::Tool(tool) = o.body() else {
                panic!("reported result")
            };
            assert!(tool.name().is_none() && tool.arguments().is_none());
            assert_eq!(tool.reported_status(), mapped);
            let mut expected =
                json!({"changes":changes,"stdout":"","stderr":null,"auto_approved":false});
            if let Some(status) = &status {
                expected["status"] = status.clone();
            }
            assert_eq!(
                tool.result(),
                Some(&JsonValue::try_from_source_value(&expected).unwrap())
            );
            let text = tool.searchable_result().expect("selector text");
            assert!(text.contains("add.content added-only"));
            assert!(text.contains("delete.content removed-only"));
            assert!(text.contains("update.unified_diff @@ -old-only +new-only"));
            assert!(text.contains("update.move_path /synthetic/moved.txt"));
            assert!(
                text.find("/synthetic/a.txt").unwrap() < text.find("/synthetic/z.txt").unwrap()
            );
            assert_eq!(
                o.fact_metadata()["tool.result"].provenance(),
                FactProvenance::Reported
            );
            assert_eq!(
                o.fact_metadata()["tool.searchable_result"].provenance(),
                FactProvenance::Parsed
            );
            if let Some(mapped) = mapped {
                assert_eq!(
                    o.fact_metadata()["tool.reported_status"].provenance(),
                    FactProvenance::Reported
                );
                assert_eq!(
                    o.facets()["tool.source_status"].value(),
                    &JsonValue::string(status.as_ref().unwrap().as_str().unwrap())
                );
                assert_eq!(tool.reported_status(), Some(mapped));
            } else {
                assert!(!o.facets().contains_key("tool.source_status"));
            }
            assert!(!format!("{:?}", batch.observations).contains("EXCLUDED-PRIVATE"));
            // Typed identity is independent of artifact name, position and ordinal mode.
            let mut moved_source = source.clone();
            moved_source.path.set_file_name("renamed.jsonl");
            let mut values = vec![
                meta(),
                json!({"type":"event_msg","payload":{"type":"token_count"}}),
                value,
            ];
            for (ordinal, value) in values.iter_mut().enumerate() {
                value["ordinal"] = json!(ordinal);
            }
            let replay = acquire(&moved_source, &values).unwrap();
            assert_eq!(o.observation_id(), replay.observations[0].observation_id());
            assert_eq!(replay.observations[0].source().source_sequence(), Some(2));
        }
        let empty = acquire(source, &[meta(), file_change(json!({}))]).unwrap();
        assert_eq!(empty.observations.len(), 1);
        for move_path in [None, Some(Value::Null), Some(json!(""))] {
            let mut change = json!({"type":"update","unified_diff":""});
            if let Some(path) = move_path {
                change["move_path"] = path;
            }
            let expected = json!({"changes":{"/synthetic/a":change},"status":"completed"});
            let batch =
                acquire(source, &[meta(), file_change(expected["changes"].clone())]).unwrap();
            let ObservationBody::Tool(tool) = batch.observations[0].body() else {
                panic!("tool")
            };
            assert_eq!(
                tool.result(),
                Some(&JsonValue::try_from_source_value(&expected).unwrap())
            );
        }
        let request = json!({"type":"response_item","payload":{"type":"function_call","name":"apply_patch","call_id":"patch-a","arguments":"synthetic request"}});
        let output = json!({"type":"response_item","payload":{"type":"function_call_output","call_id":"patch-a","output":"synthetic output"}});
        let original = acquire(source, &[meta(), request.clone(), output.clone()]).unwrap();
        let combined = acquire(source, &[meta(), request, output, file_change(changes)]).unwrap();
        assert_eq!(combined.observations.len(), 3);
        assert_eq!(combined.accounting.sessions[0].counts.native_units, 4);
        assert_eq!(
            combined.accounting.sessions[0]
                .counts
                .record_counts
                .tool_call,
            1
        );
        assert_eq!(
            combined.accounting.sessions[0]
                .counts
                .record_counts
                .tool_result,
            2
        );
        assert_eq!(
            original.accounting.sessions[0].counts.contributions,
            combined.accounting.sessions[0].counts.contributions
        );
        assert!(combined.observations[2].correlation().call_id().is_none());
    });
}

#[test]
fn completed_file_change_rejects_malformed_and_preserves_neighbor_quarantine() {
    each(|source| {
        let good = file_change(json!({"/synthetic/a":{"type":"add","content":"ok"}}));
        let mut invalid = Vec::new();
        for status in [json!("in_progress"), json!("unknown"), json!(42), json!({})] {
            let mut bad = good.clone();
            bad["payload"]["item"]["status"] = status;
            invalid.push(bad);
        }
        for changes in [
            Value::Null,
            json!([]),
            json!({"/synthetic/a":null}),
            json!({"/synthetic/a":{"type":"add"}}),
            json!({"/synthetic/a":{"type":"delete","content":42}}),
            json!({"/synthetic/a":{"type":"update","unified_diff":{},"move_path":null}}),
            json!({"/synthetic/a":{"type":"update","unified_diff":"diff","move_path":42}}),
        ] {
            invalid.push(file_change(changes));
        }
        let mut missing = good.clone();
        missing["payload"]["item"]
            .as_object_mut()
            .unwrap()
            .remove("changes");
        invalid.push(missing);
        for (key, bad_value) in [
            ("stdout", json!(42)),
            ("stderr", json!([])),
            ("auto_approved", json!("true")),
        ] {
            let mut bad = good.clone();
            bad["payload"]["item"][key] = bad_value;
            invalid.push(bad);
        }
        for wrapper in ["response_item", "unknown"] {
            let mut bad = good.clone();
            bad["type"] = json!(wrapper);
            invalid.push(bad);
        }
        let mut conflict = good.clone();
        conflict["payload"]["item"]["thread_id"] = json!("conflict");
        invalid.push(conflict);
        for bad in invalid {
            let error = acquire(source, &[meta(), good.clone(), bad])
                .err()
                .expect("atomic malformed rejection");
            assert!(!format!("{error:?} {error}").contains("/synthetic"));
        }
        let mut foreign = good.clone();
        foreign["payload"]["thread_id"] = json!("foreign");
        let future =
            file_change(json!({"/synthetic/future":{"type":"future","content":"PRIVATE-FUTURE"}}));
        let mut reasoning = completed("Reasoning", "reasoning");
        reasoning["payload"]["item"]["content"] = json!("PRIVATE-REASONING");
        let batch = acquire(
            source,
            &[
                meta(),
                good,
                foreign,
                future,
                completed("McpToolCall", "mcp"),
                completed("Extension", "extension"),
                completed("Future", "future"),
                reasoning,
            ],
        )
        .unwrap();
        assert_eq!(batch.observations.len(), 1);
        assert_eq!(
            batch.quarantined.iter().map(|q| q.code).collect::<Vec<_>>(),
            [
                "foreign_thread_item",
                "unsupported_completed_item",
                "unsupported_completed_item",
                "unsupported_completed_item",
                "unknown_discriminator"
            ]
        );
        assert_eq!(
            batch.accounting.coverage,
            crate::acquisition::AccountingCoverage::PartialSource
        );
        assert_eq!(batch.accounting.sessions[0].counts.native_units, 8);
        assert!(!format!("{:?} {:?}", batch.observations, batch.quarantined).contains("PRIVATE-"));
    });
}

#[test]
fn completed_file_change_bounds_are_per_unit_content_free_and_not_truncated() {
    use telltale_schema::observation::{BoundDimension, CanonicalFieldCategory};
    each(|source| {
        let changes = |n| json!({"/synthetic/a":{"type":"add","content":"x".repeat(n)}});
        let good = completed("AgentMessage", "neighbor");
        for (value, category, dimension) in [
            (
                file_change(changes(4097)),
                CanonicalFieldCategory::ToolResult,
                BoundDimension::StringBytes,
            ),
            (
                file_change(json!({"x".repeat(65):{"type":"add","content":"ok"}})),
                CanonicalFieldCategory::ToolResult,
                BoundDimension::KeyBytes,
            ),
            (
                file_change(Value::Object(
                    (0..33)
                        .map(|i| {
                            (
                                format!("/synthetic/{i}"),
                                json!({"type":"delete","content":""}),
                            )
                        })
                        .collect(),
                )),
                CanonicalFieldCategory::ToolResult,
                BoundDimension::ObjectMembers,
            ),
            (
                file_change(Value::Object(
                    (0..5)
                        .map(|i| {
                            (
                                format!("/synthetic/{i}"),
                                json!({"type":"add","content":"x".repeat(3500)}),
                            )
                        })
                        .collect(),
                )),
                CanonicalFieldCategory::ToolResult,
                BoundDimension::EncodedBytes,
            ),
        ] {
            // The over-bound part of the change is replaced and recorded;
            // the unit is projected next to its neighbor, not quarantined.
            assert_eq!(category, CanonicalFieldCategory::ToolResult);
            let batch = acquire(source, &[meta(), good.clone(), value]).unwrap();
            assert!(batch.quarantined.is_empty());
            assert_eq!(batch.observations.len(), 2);
            let tool = batch
                .observations
                .iter()
                .find_map(|observation| match observation.body() {
                    ObservationBody::Tool(tool) => Some(tool),
                    _ => None,
                })
                .expect("the change is projected");
            let replaced = tool
                .bounded_values()
                .iter()
                .map(|value| (value.target(), value.dimension()))
                .collect::<Vec<_>>();
            assert_eq!(
                replaced,
                [(
                    telltale_schema::observation::BoundedTarget::Result,
                    dimension
                )]
            );
            let result = format!("{:?}", tool.result());
            assert!(!result.contains(&"x".repeat(3500)) && !result.contains(&"x".repeat(65)));
            assert!(!format!("{:?}", tool.bounded_values()).contains("/synthetic"));
            assert_eq!(
                bounded_units(&batch),
                [("patch-a", 2, BoundedTarget::Result, dimension)]
            );
            let reported = format!("{:?}", batch.bounded);
            assert!(!reported.contains("/synthetic") && !reported.contains(&"x".repeat(16)));
            assert_eq!(batch.accounting.sessions[0].counts.native_units, 3);
        }
        // The assembled searchable projection is also bounded, never silently clipped.
        let small = acquire(source, &[meta(), file_change(changes(4000))]).unwrap();
        assert!(small.quarantined.is_empty());
        let ObservationBody::Tool(tool) = small.observations[0].body() else {
            panic!("tool")
        };
        let max_content = 4000 + 4096 - tool.searchable_result().unwrap().len();
        let exact = acquire(source, &[meta(), file_change(changes(max_content))]).unwrap();
        assert!(exact.quarantined.is_empty());
        let large = acquire(
            source,
            &[meta(), good, file_change(changes(max_content + 1))],
        )
        .unwrap();
        // Over that bound the change keeps its result; only the searchable
        // text is omitted, and the unit is reported.
        assert_eq!(large.observations.len(), 2);
        assert!(large.quarantined.is_empty());
        assert_eq!(
            bounded_units(&large),
            [(
                "patch-a",
                2,
                BoundedTarget::SearchableResult,
                BoundDimension::StringBytes
            )]
        );
        let ObservationBody::Tool(tool) = large.observations[1].body() else {
            panic!("tool")
        };
        assert_eq!(tool.searchable_result(), None);
        assert!(
            tool.bounded_values()
                .iter()
                .all(|value| value.pointer().is_empty())
        );
        assert!(format!("{:?}", tool.result()).contains(&"x".repeat(max_content + 1)));
        assert!(
            !large.observations[1]
                .fact_metadata()
                .contains_key("tool.searchable_result")
        );
        let reported = format!("{:?}", large.bounded);
        assert!(!reported.contains("/synthetic") && !reported.contains(&"x".repeat(16)));
        for changes in [
            json!({"x".repeat(64):{"type":"add","content":""}}),
            Value::Object(
                (0..32)
                    .map(|i| {
                        (
                            format!("/synthetic/{i}"),
                            json!({"type":"delete","content":""}),
                        )
                    })
                    .collect(),
            ),
        ] {
            let batch = acquire(source, &[meta(), file_change(changes.clone())]).unwrap();
            assert!(batch.quarantined.is_empty());
            let ObservationBody::Tool(tool) = batch.observations[0].body() else {
                panic!("tool")
            };
            assert_eq!(
                tool.result(),
                Some(
                    &JsonValue::try_from_source_value(
                        &json!({"changes":changes,"status":"completed"})
                    )
                    .unwrap()
                )
            );
        }
        // Distinct native paths that collide under canonical NFC must reject,
        // never silently discard one change during map conversion.
        assert!(acquire(source, &[meta(), file_change(json!({"/synthetic/\u{e9}":{"type":"add","content":"one"},"/synthetic/e\u{301}":{"type":"delete","content":"two"}}))]).is_err());
    });
}
