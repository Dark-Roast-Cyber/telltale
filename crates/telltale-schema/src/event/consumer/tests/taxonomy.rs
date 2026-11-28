use super::*;

#[test]
fn schema_asset_matches_frozen_event3_hash() {
    assert_eq!(
        hex::encode(Sha256::digest(EVENT3_SCHEMA.as_bytes())),
        EVENT3_SCHEMA_SHA256
    );
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/event.schema.json");
    if root.is_file() {
        assert_eq!(
            std::fs::read(root).expect("root schema"),
            EVENT3_SCHEMA.as_bytes()
        );
        let historical = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/historical/event-3.0.schema.json");
        assert_eq!(
            std::fs::read(historical).expect("historical schema"),
            EVENT3_SCHEMA.as_bytes()
        );
    }
}

#[test]
fn taxonomy_agrees_across_frozen_schema_producer_import_and_typed_consumer() {
    let schema: Value = serde_json::from_str(EVENT3_SCHEMA).expect("frozen schema");
    let mut event = positive_constructor_corpus().remove(0).1;
    event.detection_classes = crate::event::VALID_DETECTION_CLASSES
        .iter()
        .map(|value| value.to_string())
        .collect();
    event.signal_types = crate::event::VALID_SIGNAL_TYPES
        .iter()
        .map(|value| value.to_string())
        .collect();
    event.analytic_intents = crate::event::VALID_ANALYTIC_INTENTS
        .iter()
        .map(|value| value.to_string())
        .collect();
    let native = serde_json::to_value(&event).expect("all taxonomy values emit");
    for field in ["detection_classes", "signal_types", "analytic_intents"] {
        assert_eq!(
            native[field],
            schema["$defs"]["detection"]["allOf"][1]["properties"][field]["items"]["enum"],
            "{field}"
        );
    }
    let mut imported = native.clone();
    crate::event::sanitize_serialized_event(&mut imported);
    for field in ["detection_classes", "signal_types", "analytic_intents"] {
        assert_eq!(imported[field], native[field], "{field}");
    }
    let record = Event3Record::from_json(&serde_json::to_vec(&imported).expect("JSON"))
        .expect("all taxonomy values consume");
    let Event3Family::Detection(detection) = record.family() else {
        panic!("expected detection");
    };
    assert_eq!(
        detection.detection_classes.len(),
        event.detection_classes.len()
    );
    assert_eq!(detection.signal_types.len(), event.signal_types.len());
    assert_eq!(
        detection.analytic_intents.len(),
        event.analytic_intents.len()
    );
}

#[test]
fn taxonomy_rejects_unknown_empty_and_near_miss_values_at_each_boundary() {
    let event = positive_constructor_corpus().remove(0).1;
    for (field, kind) in [
        ("detection_classes", "detection-class"),
        ("signal_types", "signal-type"),
        ("analytic_intents", "analytic-intent"),
    ] {
        for invalid in ["", "unknown", "ALERT", "atomic ", " alert", "alert\u{a0}"] {
            let mut native = event.clone();
            match field {
                "detection_classes" => native.detection_classes = vec![invalid.to_string()],
                "signal_types" => native.signal_types = vec![invalid.to_string()],
                "analytic_intents" => native.analytic_intents = vec![invalid.to_string()],
                _ => unreachable!(),
            }
            assert!(serde_json::to_vec(&native).is_err(), "{field}");
            let mut imported = serde_json::to_value(&event).expect("detection JSON");
            imported[field] = serde_json::json!([invalid]);
            let error = Event3Record::from_json(&serde_json::to_vec(&imported).expect("JSON"))
                .expect_err("unknown taxonomy");
            assert_eq!(error.category(), Event3ErrorCategory::Semantic, "{field}");
            crate::event::sanitize_serialized_event(&mut imported);
            assert_eq!(
                imported[field],
                serde_json::json!([crate::event::opaque_identifier(kind, invalid)]),
                "{field}"
            );
            assert!(
                Event3Record::from_json(&serde_json::to_vec(&imported).expect("JSON")).is_err()
            );
        }
    }
}

#[test]
fn taxonomy_family_profiles_remain_narrower_than_the_shared_vocabulary() {
    for (name, event) in positive_constructor_corpus()
        .into_iter()
        .filter(|(name, _)| matches!(*name, "operational_alert" | "correlation"))
    {
        for field in ["detection_classes", "signal_types", "analytic_intents"] {
            let mut native = event.clone();
            // Valid global values, but outside each of these family profiles.
            match field {
                "detection_classes" => {
                    native.detection_classes = vec!["threat_hunting".to_string()]
                }
                "signal_types" => native.signal_types = vec!["baseline_deviation".to_string()],
                "analytic_intents" => native.analytic_intents = vec!["hunt".to_string()],
                _ => unreachable!(),
            }
            assert!(serde_json::to_vec(&native).is_err(), "{name}: {field}");
            let mut wire = serde_json::to_value(&event).expect("family JSON");
            wire[field] = match field {
                "detection_classes" => serde_json::json!(native.detection_classes),
                "signal_types" => serde_json::json!(native.signal_types),
                "analytic_intents" => serde_json::json!(native.analytic_intents),
                _ => unreachable!(),
            };
            assert!(
                Event3Record::from_json(&serde_json::to_vec(&wire).expect("JSON")).is_err(),
                "{name}: {field}"
            );
        }
    }
}

#[test]
fn actual_terminal_constructor_corpus_covers_all_nine_families() {
    let corpus = positive_constructor_corpus();
    let registered = crate::event::NATIVE_EVENT_CONSTRUCTOR_FAMILIES
        .iter()
        .map(|family| family.name)
        .collect::<std::collections::BTreeSet<_>>();
    let covered = corpus
        .iter()
        .map(|(name, _)| *name)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(covered, registered);
    for (name, event) in corpus {
        let bytes = serde_json::to_vec(&event).expect("terminal bytes");
        let record = Event3Record::from_json(&bytes)
            .unwrap_or_else(|error| panic!("constructor family {name} did not consume: {error}"));
        assert_eq!(record.event_type(), event.event_type);
        match (name, record.family()) {
            ("detection", Event3Family::Detection(detection)) => {
                assert_eq!(detection.rule_ids.len(), 2);
                assert_eq!(detection.timeline_anchors.len(), 1);
                assert!(detection.response.is_some());
                assert_eq!(
                    record.common().evidence[0].hash.as_ref().map(String::len),
                    Some(64)
                );
            }
            ("activity_standard", Event3Family::Activity(Event3Activity::Standard(activity))) => {
                assert_eq!(activity.source_path_hash.len(), 64);
                assert!(activity.event_time.is_none());
            }
            (
                "install_inventory_activity",
                Event3Family::Activity(Event3Activity::InstallInventory(activity)),
            ) => {
                assert_eq!(activity.component, "scanner");
                assert_eq!(activity.check_name, "install_inventory");
                assert_eq!(activity.status, "ok");
            }
            ("session_risk_summary", Event3Family::SessionRiskSummary(summary)) => {
                assert_eq!(summary.rule_ids.len(), 2);
                assert_eq!(summary.source_path_hash.as_ref().map(String::len), Some(64));
            }
            ("health", Event3Family::Health(health)) => {
                assert_eq!(health.emitted_count, 1);
                assert!(
                    health
                        .active_policy_name
                        .as_deref()
                        .is_some_and(|name| name.starts_with("[policy:"))
                );
            }
            ("scanner_error", Event3Family::ScannerError(error)) => {
                assert_eq!(error.check_name, "source_parse");
                assert_eq!(error.status, "degraded");
            }
            ("operational_alert", Event3Family::OperationalAlert(alert)) => {
                assert_eq!(alert.scan_duration_ms, Some(1));
                assert_eq!(alert.scanner_error_count, None);
            }
            ("process_chain", Event3Family::ProcessChain(process)) => {
                assert!(!process.informational);
                assert_eq!(process.process.target_process_name, "curl");
                assert_eq!(process.response.recommended_action, "monitor");
            }
            ("correlation", Event3Family::Correlation(correlation)) => {
                assert_eq!(correlation.event_time, "2026-05-01T00:01:00.000Z");
            }
            (family, actual) => panic!("family {family} projected as {actual:?}"),
        }
    }
}
