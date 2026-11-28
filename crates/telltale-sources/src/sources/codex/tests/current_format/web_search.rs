use super::*;

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
            // Over the view's bound the search keeps its arguments, only the
            // view is omitted, and the unit is reported.
            assert_eq!(batch.observations.len(), 2);
            assert!(batch.quarantined.is_empty());
            let bounded = batch
                .bounded
                .iter()
                .map(|unit| (unit.source_sequence, unit.target, unit.dimension))
                .collect::<Vec<_>>();
            let ObservationBody::Tool(tool) = batch.observations[1].body() else {
                panic!("tool")
            };
            assert_eq!(
                tool.arguments(),
                Some(
                    &JsonValue::try_from_source_value(
                        &json!({"type":"search","query":"x".repeat(bytes)})
                    )
                    .unwrap()
                )
            );
            if kept {
                assert!(bounded.is_empty());
                assert!(tool.searchable_arguments().is_some());
            } else {
                assert_eq!(
                    bounded,
                    [(
                        2,
                        telltale_schema::observation::BoundedTarget::SearchableArguments,
                        BoundDimension::StringBytes
                    )]
                );
                assert_eq!(tool.searchable_arguments(), None);
                assert!(!format!("{:?}", batch.bounded).contains("xxxx"));
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
        // Each value within its bound and the view over it: the arguments
        // are kept and only the view is omitted and reported.
        assert_eq!(batch.observations.len(), 2);
        assert!(batch.quarantined.is_empty());
        assert_eq!(
            batch
                .bounded
                .iter()
                .map(|unit| (unit.source_sequence, unit.target, unit.dimension))
                .collect::<Vec<_>>(),
            [(
                2,
                telltale_schema::observation::BoundedTarget::SearchableArguments,
                BoundDimension::StringBytes
            )]
        );
        let ObservationBody::Tool(tool) = batch.observations[1].body() else {
            panic!("tool")
        };
        assert_eq!(tool.searchable_arguments(), None);
        assert!(format!("{:?}", tool.arguments()).contains(&"y".repeat(2050)));
        assert!(!format!("{:?}", batch.bounded).contains("xxxx"));
        // A unit reported as bounded takes no part in activity accounting.
        assert!(
            batch.accounting.sessions[0]
                .counts
                .contributions
                .tool_calls
                .is_empty()
        );
        // Over its own bound the query is replaced, and no view is built
        // from arguments with a replaced value.
        let batch = acquire(
            source,
            &[
                meta(json!({})),
                user("neighbor"),
                search(
                    json!({"type":"search","query":"x".repeat(4097),"queries":["y".repeat(4000)]}),
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            batch
                .bounded
                .iter()
                .map(|unit| (unit.target, unit.dimension))
                .collect::<Vec<_>>(),
            [(
                telltale_schema::observation::BoundedTarget::Arguments,
                BoundDimension::StringBytes
            )]
        );
        let ObservationBody::Tool(tool) = batch.observations[1].body() else {
            panic!("tool")
        };
        assert_eq!(tool.searchable_arguments(), None);
        assert!(!format!("{:?}{:?}", batch.bounded, batch.observations).contains("xxxx"));
    });
}
