//! Re-exports the canonical event model from `telltale-schema` and adds the
//! filesystem-facing JSONL append helper, which stays out of the I/O-free
//! schema crate.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::file_lock::{SidecarLock, open_append, safe_path_info, sync_parent};
pub use telltale_schema::event::*;

#[allow(dead_code)]
pub fn append_jsonl_events(
    path: &Path,
    events: &[Event],
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = serialize_jsonl_events(events)?;
    if bytes.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _lock = SidecarLock::acquire_lock_only(path)?;
    let created = append_jsonl_bytes(path, &bytes)?;
    if created {
        sync_parent(path)?;
    }
    Ok(())
}

pub(crate) fn serialize_jsonl_events(
    events: &[Event],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    for event in events {
        let mut serializer = serde_json::Serializer::new(&mut bytes);
        serialize_event_for_emission(event, &mut serializer)?;
        bytes.push(b'\n');
    }
    Ok(bytes)
}

pub(crate) fn append_jsonl_bytes(
    path: &Path,
    bytes: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    ensure_jsonl_tail(path)?;
    let (mut file, created, info) = open_append(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    let current = safe_path_info(path)?.ok_or("log target disappeared during append")?;
    if current.identity != info.identity || current.links != info.links {
        return Err("log target changed during append".into());
    }
    Ok(created)
}

pub(crate) fn ensure_jsonl_tail(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let length = file.metadata()?.len();
    if length == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    if last[0] != b'\n' {
        return Err(
            "local JSONL ends with a partial record; repair or replace it before retrying".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use tempfile::tempdir;

    use super::{append_jsonl_events, serialize_jsonl_events};
    use crate::event::{
        ActivityEventInput, ControlledMarker, CorrelationEventInput, CorrelationSessionInput,
        Evidence, HealthEventInput, ProcessChainEventInput, ProcessContext, TELLTALE_VERSION,
        check_serialized_event_markers, correlation_event, evidence_hash,
        health_event_with_metadata, install_inventory_event, process_chain_event,
        serialize_event_for_emission,
    };
    use telltale_schema::clients::ClientId;

    #[test]
    fn canonical_jsonl_persists_only_sanitized_event_bytes() {
        let marker = "TT_PRIVACY_JSONL_25";
        let mut event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "opaque-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "tool_result".to_string(),
                redacted_value: format!(
                    "delivery=https://user:{marker}@example.invalid/?%74%6f%6b%65%6e={marker}"
                ),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");
        event.tags.push(format!("allowlist:{marker}"));
        event.evidence.push(Evidence {
            field: "allowlist".to_string(),
            redacted_value: marker.to_string(),
            hash: None,
            rule_id: None,
        });
        let expected =
            serialize_jsonl_events(std::slice::from_ref(&event)).expect("serialize event");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");

        append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
        let persisted = fs::read(path).expect("read canonical JSONL");

        assert_eq!(persisted, expected);
        assert!(
            check_serialized_event_markers(
                &persisted,
                "canonical-jsonl",
                &[ControlledMarker {
                    id: "jsonl-marker",
                    value: marker,
                }],
            )
            .is_ok()
        );
    }

    #[test]
    fn canonical_jsonl_stores_the_terminal_emission_bytes() {
        let marker = "TT_PRIVACY_JSONL_STORED_BYTES_26";
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "synthetic-jsonl-session".to_string(),
            source_path_hash: "synthetic-jsonl-source".to_string(),
            tool_name: Some("shell".to_string()),
            tags: vec![format!("controlled:{marker}")],
            evidence: vec![Evidence {
                field: "tool_result".to_string(),
                redacted_value: format!("SECRET={marker}"),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");
        let mut canonical = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut canonical);
        serialize_event_for_emission(&event, &mut serializer).expect("terminal Event 3.0");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");

        append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append JSONL");
        let stored = fs::read(&path).expect("read stored JSONL bytes");

        assert_eq!(stored, [canonical.as_slice(), b"\n"].concat());
        assert_eq!(stored.strip_suffix(b"\n"), Some(canonical.as_slice()));
        assert!(
            check_serialized_event_markers(
                &stored,
                "canonical-jsonl-stored-bytes",
                &[ControlledMarker {
                    id: "stored-bytes-marker",
                    value: marker,
                }],
            )
            .is_ok()
        );
    }

    #[test]
    fn canonical_jsonl_sanitizes_source_hash_and_mitre_techniques() {
        let source_hash_marker = "TT_PRIVACY_JSONL_SOURCE_HASH_30";
        let mitre_marker = "TT_PRIVACY_JSONL_MITRE_30";
        let event = process_chain_event(ProcessChainEventInput {
            client: telltale_schema::clients::ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "jsonl-process-session".to_string(),
            source_path_hash: source_hash_marker.to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["rule.synthetic".to_string()],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
            confidence: "low".to_string(),
            detection_reason: "synthetic JSONL privacy fixture".to_string(),
            mitre_attack_techniques: vec![mitre_marker.to_string(), "T1059".to_string()],
            risk_entity_type: "session".to_string(),
            risk_entity_value: Some("jsonl-process-session".to_string()),
            process: ProcessContext {
                host: None,
                user: None,
                source_process_name: "shell".to_string(),
                source_process_path: None,
                source_process_id: None,
                source_process_command_line: None,
                target_process_name: "curl".to_string(),
                target_process_path: None,
                target_process_id: None,
                target_process_command_line: None,
                parent_process_name: None,
                parent_process_path: None,
                source_event_id: None,
                source_process_inferred: false,
                rule_name: "synthetic".to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: Vec::new(),
                falsepositives: Vec::new(),
                dedup_key: "jsonl-process".to_string(),
                suppression_window_seconds: 0,
                rule_severity: "low".to_string(),
                risk_adjustment: None,
            },
        })
        .expect("process-chain event");
        let expected = serialize_jsonl_events(std::slice::from_ref(&event))
            .expect("serialize canonical JSONL");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");

        append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append canonical JSONL");
        let stored = fs::read(&path).expect("read canonical JSONL");
        assert_eq!(stored, expected);
        assert!(
            check_serialized_event_markers(
                &stored,
                "canonical-jsonl-source-and-mitre",
                &[
                    ControlledMarker {
                        id: "source-hash",
                        value: source_hash_marker,
                    },
                    ControlledMarker {
                        id: "mitre-technique",
                        value: mitre_marker,
                    },
                ],
            )
            .is_ok()
        );

        let serialized: serde_json::Value =
            serde_json::from_slice(stored.strip_suffix(b"\n").expect("JSONL newline"))
                .expect("serialized Event JSON");
        assert_eq!(
            serialized["source_path_hash"],
            telltale_schema::event::evidence_hash(source_hash_marker)
        );
        assert_eq!(
            serialized["mitre_attack_techniques"][0],
            format!(
                "mitre:{}",
                telltale_schema::event::evidence_hash(mitre_marker)
            )
        );
        assert_eq!(serialized["mitre_attack_techniques"][1], "T1059");

        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/event.schema.json"))
                .expect("Event 3.0 schema");
        let validator = jsonschema::validator_for(&schema).expect("schema validator");
        assert!(validator.is_valid(&serialized));
    }

    #[test]
    fn canonical_jsonl_preserves_source_count_values_across_key_collisions() {
        let marker = "TT_PRIVACY_JSONL_SOURCE_COUNTS_KEY_30";
        let canonical_fallback = format!("source_count:{}", evidence_hash(marker));
        let canonical_collision = format!("{canonical_fallback}:2");
        let mut source_counts = BTreeMap::new();
        source_counts.insert(marker.to_string(), 3);
        source_counts.insert(canonical_fallback.clone(), 5);
        source_counts.insert(canonical_collision.clone(), 7);
        source_counts.insert("codex.jsonl".to_string(), 11);

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.source_counts = Some(source_counts);
        let expected = serialize_jsonl_events(std::slice::from_ref(&event))
            .expect("serialize canonical JSONL");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("health-events.jsonl");

        append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append health JSONL");
        let stored = fs::read(&path).expect("read health JSONL");
        assert_eq!(stored, expected);
        assert_eq!(
            serialize_jsonl_events(std::slice::from_ref(&event))
                .expect("repeat JSONL serialization"),
            stored
        );
        assert!(
            check_serialized_event_markers(
                &stored,
                "canonical-jsonl-source-count-key",
                &[ControlledMarker {
                    id: "source-count-key",
                    value: marker,
                }],
            )
            .is_ok()
        );

        let serialized: serde_json::Value =
            serde_json::from_slice(stored.strip_suffix(b"\n").expect("JSONL newline"))
                .expect("serialized health Event");
        let counts = serialized["source_counts"]
            .as_object()
            .expect("serialized source counts");
        assert_eq!(counts[&canonical_fallback], 5);
        assert_eq!(counts[&canonical_collision], 7);
        assert_eq!(counts["codex.jsonl"], 11);
        assert_eq!(counts[&format!("{canonical_fallback}:3")], 3);
        assert_eq!(
            counts
                .values()
                .filter_map(serde_json::Value::as_u64)
                .sum::<u64>(),
            26
        );
    }

    #[test]
    fn canonical_jsonl_persists_the_trusted_telltale_version() {
        let credential_version = format!("1.2.3-AKIA{}", "T".repeat(16));
        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.telltale_version = credential_version.clone();
        let expected = serialize_jsonl_events(std::slice::from_ref(&event))
            .expect("serialize canonical JSONL");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("version-events.jsonl");

        append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append canonical JSONL");
        let stored = fs::read(&path).expect("read canonical JSONL");
        assert_eq!(stored, expected);
        assert_eq!(
            serialize_jsonl_events(std::slice::from_ref(&event))
                .expect("repeat JSONL serialization"),
            stored
        );
        assert!(!String::from_utf8_lossy(&stored).contains(&credential_version));
        let emitted: serde_json::Value =
            serde_json::from_slice(stored.strip_suffix(b"\n").expect("JSONL newline"))
                .expect("serialized health Event");
        assert_eq!(emitted["telltale_version"], TELLTALE_VERSION);
    }

    #[test]
    fn canonical_jsonl_rejects_invalid_controlled_fields_before_opening_file() {
        let marker = |field: &str| format!("TT_PRIVACY_JSONL_CONTROLLED_{field}_31");
        let mut cases = Vec::new();

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.time_source = marker("time_source");
        cases.push(("time_source", marker("time_source"), event));

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.time_confidence = marker("time_confidence");
        cases.push(("time_confidence", marker("time_confidence"), event));

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.event_type = marker("event_type");
        cases.push(("event_type", marker("event_type"), event));

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.severity = marker("severity");
        cases.push(("severity", marker("severity"), event));

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.schema_version = marker("schema_version");
        cases.push(("schema_version", marker("schema_version"), event));

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.detection_classes = vec![marker("detection_classes")];
        cases.push(("detection_classes", marker("detection_classes"), event));

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.signal_types = vec![marker("signal_types")];
        cases.push(("signal_types", marker("signal_types"), event));

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.analytic_intents = vec![marker("analytic_intents")];
        cases.push(("analytic_intents", marker("analytic_intents"), event));

        let mut event = correlation_event(CorrelationEventInput {
            client: "codex".to_string(),
            agent: None,
            model: None,
            provider: None,
            shared_rule_ids: vec!["rule.synthetic".to_string()],
            sessions: vec![
                CorrelationSessionInput {
                    session_id: "jsonl-session-a".to_string(),
                    event_id: "jsonl-event-a".to_string(),
                    timestamp: "2026-05-01T00:00:00Z".to_string(),
                    severity: "low".to_string(),
                    risk_score: 1,
                },
                CorrelationSessionInput {
                    session_id: "jsonl-session-b".to_string(),
                    event_id: "jsonl-event-b".to_string(),
                    timestamp: "2026-05-01T00:01:00Z".to_string(),
                    severity: "low".to_string(),
                    risk_score: 2,
                },
            ],
            window_start: "2026-05-01T00:00:00Z".to_string(),
            window_end: "2026-05-01T00:01:00Z".to_string(),
            max_risk_score: 2,
        })
        .expect("controlled correlation event");
        event.categories = vec![marker("correlation_category")];
        cases.push((
            "correlation.categories",
            marker("correlation_category"),
            event,
        ));

        let mut process_event = process_chain_event(ProcessChainEventInput {
            client: telltale_schema::clients::ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "jsonl-controlled-process".to_string(),
            source_path_hash: "jsonl-controlled-source".to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["rule.synthetic".to_string()],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
            confidence: "low".to_string(),
            detection_reason: "synthetic JSONL controlled-field fixture".to_string(),
            mitre_attack_techniques: Vec::new(),
            risk_entity_type: "session".to_string(),
            risk_entity_value: Some("jsonl-controlled-process".to_string()),
            process: ProcessContext {
                host: None,
                user: None,
                source_process_name: "shell".to_string(),
                source_process_path: None,
                source_process_id: None,
                source_process_command_line: None,
                target_process_name: "curl".to_string(),
                target_process_path: None,
                target_process_id: None,
                target_process_command_line: None,
                parent_process_name: None,
                parent_process_path: None,
                source_event_id: None,
                source_process_inferred: false,
                rule_name: "synthetic".to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: Vec::new(),
                falsepositives: Vec::new(),
                dedup_key: "jsonl-controlled-process".to_string(),
                suppression_window_seconds: 0,
                rule_severity: "low".to_string(),
                risk_adjustment: None,
            },
        })
        .expect("controlled process event");
        process_event.confidence = Some(marker("confidence"));
        cases.push(("confidence", marker("confidence"), process_event));

        let mut process_event = process_chain_event(ProcessChainEventInput {
            client: telltale_schema::clients::ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "jsonl-controlled-risk".to_string(),
            source_path_hash: "jsonl-controlled-risk-source".to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["rule.synthetic".to_string()],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
            confidence: "low".to_string(),
            detection_reason: "synthetic JSONL controlled-field fixture".to_string(),
            mitre_attack_techniques: Vec::new(),
            risk_entity_type: "session".to_string(),
            risk_entity_value: Some("jsonl-controlled-risk".to_string()),
            process: ProcessContext {
                host: None,
                user: None,
                source_process_name: "shell".to_string(),
                source_process_path: None,
                source_process_id: None,
                source_process_command_line: None,
                target_process_name: "curl".to_string(),
                target_process_path: None,
                target_process_id: None,
                target_process_command_line: None,
                parent_process_name: None,
                parent_process_path: None,
                source_event_id: None,
                source_process_inferred: false,
                rule_name: "synthetic".to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: Vec::new(),
                falsepositives: Vec::new(),
                dedup_key: "jsonl-controlled-risk".to_string(),
                suppression_window_seconds: 0,
                rule_severity: "low".to_string(),
                risk_adjustment: None,
            },
        })
        .expect("controlled process event");
        process_event.risk_entity_type = Some(marker("risk_entity_type"));
        cases.push((
            "risk_entity_type",
            marker("risk_entity_type"),
            process_event,
        ));

        let mut process_event = process_chain_event(ProcessChainEventInput {
            client: telltale_schema::clients::ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "jsonl-controlled-rule".to_string(),
            source_path_hash: "jsonl-controlled-rule-source".to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["rule.synthetic".to_string()],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
            confidence: "low".to_string(),
            detection_reason: "synthetic JSONL controlled-field fixture".to_string(),
            mitre_attack_techniques: Vec::new(),
            risk_entity_type: "session".to_string(),
            risk_entity_value: Some("jsonl-controlled-rule".to_string()),
            process: ProcessContext {
                host: None,
                user: None,
                source_process_name: "shell".to_string(),
                source_process_path: None,
                source_process_id: None,
                source_process_command_line: None,
                target_process_name: "curl".to_string(),
                target_process_path: None,
                target_process_id: None,
                target_process_command_line: None,
                parent_process_name: None,
                parent_process_path: None,
                source_event_id: None,
                source_process_inferred: false,
                rule_name: "synthetic".to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: Vec::new(),
                falsepositives: Vec::new(),
                dedup_key: "jsonl-controlled-rule".to_string(),
                suppression_window_seconds: 0,
                rule_severity: "low".to_string(),
                risk_adjustment: None,
            },
        })
        .expect("controlled process event");
        process_event
            .process
            .as_mut()
            .expect("process context")
            .rule_severity = marker("rule_severity");
        cases.push((
            "process.rule_severity",
            marker("rule_severity"),
            process_event,
        ));

        let mut process_event = process_chain_event(ProcessChainEventInput {
            client: telltale_schema::clients::ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "jsonl-controlled-response".to_string(),
            source_path_hash: "jsonl-controlled-response-source".to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["rule.synthetic".to_string()],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
            confidence: "low".to_string(),
            detection_reason: "synthetic JSONL controlled-field fixture".to_string(),
            mitre_attack_techniques: Vec::new(),
            risk_entity_type: "session".to_string(),
            risk_entity_value: Some("jsonl-controlled-response".to_string()),
            process: ProcessContext {
                host: None,
                user: None,
                source_process_name: "shell".to_string(),
                source_process_path: None,
                source_process_id: None,
                source_process_command_line: None,
                target_process_name: "curl".to_string(),
                target_process_path: None,
                target_process_id: None,
                target_process_command_line: None,
                parent_process_name: None,
                parent_process_path: None,
                source_event_id: None,
                source_process_inferred: false,
                rule_name: "synthetic".to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: Vec::new(),
                falsepositives: Vec::new(),
                dedup_key: "jsonl-controlled-response".to_string(),
                suppression_window_seconds: 0,
                rule_severity: "low".to_string(),
                risk_adjustment: None,
            },
        })
        .expect("controlled process event");
        process_event
            .response
            .as_mut()
            .expect("process response")
            .recommended_action = marker("recommended_action");
        cases.push((
            "response.recommended_action",
            marker("recommended_action"),
            process_event,
        ));

        let mut process_event = process_chain_event(ProcessChainEventInput {
            client: telltale_schema::clients::ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "jsonl-controlled-escalation".to_string(),
            source_path_hash: "jsonl-controlled-escalation-source".to_string(),
            tool_name: Some("shell".to_string()),
            rule_ids: vec!["rule.synthetic".to_string()],
            categories: vec!["execution".to_string()],
            detection_classes: vec!["security_detection".to_string()],
            signal_types: vec!["chain".to_string()],
            analytic_intents: vec!["alert".to_string()],
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: None,
            confidence: "low".to_string(),
            detection_reason: "synthetic JSONL controlled-field fixture".to_string(),
            mitre_attack_techniques: Vec::new(),
            risk_entity_type: "session".to_string(),
            risk_entity_value: Some("jsonl-controlled-escalation".to_string()),
            process: ProcessContext {
                host: None,
                user: None,
                source_process_name: "shell".to_string(),
                source_process_path: None,
                source_process_id: None,
                source_process_command_line: None,
                target_process_name: "curl".to_string(),
                target_process_path: None,
                target_process_id: None,
                target_process_command_line: None,
                parent_process_name: None,
                parent_process_path: None,
                source_event_id: None,
                source_process_inferred: false,
                rule_name: "synthetic".to_string(),
                secondary_rule_ids: Vec::new(),
                investigation_fields: Vec::new(),
                falsepositives: Vec::new(),
                dedup_key: "jsonl-controlled-escalation".to_string(),
                suppression_window_seconds: 0,
                rule_severity: "low".to_string(),
                risk_adjustment: None,
            },
        })
        .expect("controlled process event");
        process_event
            .response
            .as_mut()
            .expect("process response")
            .escalation = marker("escalation");
        cases.push(("response.escalation", marker("escalation"), process_event));

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.component = Some(marker("component"));
        cases.push(("component", marker("component"), event));

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.check_name = Some(marker("check_name"));
        cases.push(("check_name", marker("check_name"), event));

        let mut event = health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 0,
            rule_count: 0,
            threshold_config: telltale_schema::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        });
        event.status = Some(marker("status"));
        cases.push(("status", marker("status"), event));

        let mut event = install_inventory_event(vec![Evidence {
            field: "inventory".to_string(),
            redacted_value: "synthetic".to_string(),
            hash: None,
            rule_id: None,
        }])
        .expect("controlled install inventory event");
        event.client = marker("client");
        cases.push(("client", marker("client"), event));

        let mut event = install_inventory_event(vec![Evidence {
            field: "inventory".to_string(),
            redacted_value: "synthetic".to_string(),
            hash: None,
            rule_id: None,
        }])
        .expect("controlled install inventory event");
        event.session_id = marker("session_id");
        cases.push(("session_id", marker("session_id"), event));

        let mut event = install_inventory_event(vec![Evidence {
            field: "inventory".to_string(),
            redacted_value: "synthetic".to_string(),
            hash: None,
            rule_id: None,
        }])
        .expect("controlled install inventory event");
        event.tags[0] = marker("install_tag");
        cases.push(("install.tags", marker("install_tag"), event));

        let directory = tempdir().expect("temporary directory");
        for (field, marker, event) in cases {
            let path = directory.path().join(format!("{field}.jsonl"));
            let error = append_jsonl_events(&path, &[event]).expect_err(field);
            let message = error.to_string();
            assert!(
                message.contains("event contains invalid controlled metadata"),
                "{field} did not fail with the generic controlled-field error: {message}"
            );
            assert!(
                !message.contains(&marker),
                "{field} echoed its marker: {message}"
            );
            assert!(!path.exists(), "{field} opened or wrote its JSONL target");
        }
    }

    #[test]
    fn canonical_jsonl_rejects_invalid_event_identity_and_timestamps_before_opening_file() {
        let marker = |field: &str| format!("TT_PRIVACY_JSONL_CANONICAL_{field}_32");
        let mut cases = Vec::new();
        for field in ["event_id", "timestamp", "observed_at", "ingested_at"] {
            let mut event = health_event_with_metadata(HealthEventInput {
                sources: &[],
                source_inventory_change: None,
                scan_duration_ms: 0,
                rule_count: 0,
                threshold_config: telltale_schema::scoring::load_thresholds(),
                active_policy_name: None,
                emitted_count: 0,
                suppressed_count: 0,
                scanner_error_count: 0,
            });
            let value = marker(field);
            match field {
                "event_id" => event.event_id = value.clone(),
                "timestamp" => event.timestamp = value.clone(),
                "observed_at" => event.observed_at = value.clone(),
                "ingested_at" => event.ingested_at = value.clone(),
                _ => unreachable!("canonical field test case is exhaustive"),
            }
            cases.push((field, value, event));
        }

        let directory = tempdir().expect("temporary directory");
        for (field, marker, event) in cases {
            let path = directory.path().join(format!("{field}.jsonl"));
            let valid_event = health_event_with_metadata(HealthEventInput {
                sources: &[],
                source_inventory_change: None,
                scan_duration_ms: 0,
                rule_count: 0,
                threshold_config: telltale_schema::scoring::load_thresholds(),
                active_policy_name: None,
                emitted_count: 0,
                suppressed_count: 0,
                scanner_error_count: 0,
            });
            let error = append_jsonl_events(&path, &[valid_event, event]).expect_err(field);
            let message = error.to_string();
            assert_eq!(message, "event contains invalid controlled metadata");
            assert!(!message.contains(&marker));
            assert!(!path.exists(), "{field} opened or wrote its JSONL target");
        }
    }

    #[test]
    fn canonical_jsonl_batch_rejects_unreviewed_response_playbooks_before_opening_file() {
        let cases = [
            (
                "telltale-playbook-unreviewed-operator-escalation",
                "unreviewed",
            ),
            (
                "telltale-playbook-credential-access-ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12",
                "sensitive",
            ),
        ];
        let directory = tempdir().expect("temporary directory");

        for (playbook, case_name) in cases {
            let mut event = process_chain_event(ProcessChainEventInput {
                client: telltale_schema::clients::ClientId::Codex,
                agent: None,
                model: None,
                provider: None,
                session_id: format!("jsonl-response-{case_name}"),
                source_path_hash: format!("jsonl-response-{case_name}-source"),
                tool_name: Some("shell".to_string()),
                rule_ids: vec!["rule.synthetic".to_string()],
                categories: vec!["execution".to_string()],
                detection_classes: vec!["security_detection".to_string()],
                signal_types: vec!["chain".to_string()],
                analytic_intents: vec!["alert".to_string()],
                tags: Vec::new(),
                evidence: Vec::new(),
                risk_contributions: Vec::new(),
                event_time: None,
                confidence: "low".to_string(),
                detection_reason: "synthetic JSONL controlled-field fixture".to_string(),
                mitre_attack_techniques: Vec::new(),
                risk_entity_type: "session".to_string(),
                risk_entity_value: Some(format!("jsonl-response-{case_name}")),
                process: ProcessContext {
                    host: None,
                    user: None,
                    source_process_name: "shell".to_string(),
                    source_process_path: None,
                    source_process_id: None,
                    source_process_command_line: None,
                    target_process_name: "curl".to_string(),
                    target_process_path: None,
                    target_process_id: None,
                    target_process_command_line: None,
                    parent_process_name: None,
                    parent_process_path: None,
                    source_event_id: None,
                    source_process_inferred: false,
                    rule_name: "synthetic".to_string(),
                    secondary_rule_ids: Vec::new(),
                    investigation_fields: Vec::new(),
                    falsepositives: Vec::new(),
                    dedup_key: format!("jsonl-response-{case_name}"),
                    suppression_window_seconds: 0,
                    rule_severity: "low".to_string(),
                    risk_adjustment: None,
                },
            })
            .expect("controlled process event");
            let valid_event = event.clone();
            event
                .response
                .as_mut()
                .expect("process response")
                .response_playbook = playbook.to_string();
            let path = directory.path().join(format!("response-{case_name}.jsonl"));

            let error = append_jsonl_events(&path, &[valid_event, event]).expect_err(case_name);
            assert_eq!(
                error.to_string(),
                "event contains invalid controlled metadata"
            );
            assert!(!error.to_string().contains(playbook));
            assert!(
                !path.exists(),
                "{case_name} opened or wrote its JSONL target"
            );
        }
    }

    #[test]
    fn canonical_jsonl_terminalizes_invalid_event_time_without_leaking_it() {
        let marker = "TT_PRIVACY_JSONL_EVENT_TIME_32";
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "jsonl-event-time-session".to_string(),
            source_path_hash: "jsonl-event-time-source".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: Vec::new(),
            risk_contributions: Vec::new(),
            event_time: Some(marker.to_string()),
        })
        .expect("activity event");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("event-time.jsonl");

        append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append JSONL");
        let stored = fs::read(&path).expect("read JSONL");
        assert!(!String::from_utf8_lossy(&stored).contains(marker));
        let emitted: serde_json::Value =
            serde_json::from_slice(stored.strip_suffix(b"\n").expect("JSONL newline"))
                .expect("event JSON");
        assert!(
            emitted["event_time"]
                .as_str()
                .is_some_and(|value| value.starts_with("[invalid-event-time:"))
        );
    }

    #[test]
    fn canonical_jsonl_drops_partial_truncated_url_credential_prefix() {
        const INPUT_CAP: usize = 4096;
        let tail = "https://uTT_PRIVACY_JSONL_TAIL_25";
        let start = INPUT_CAP - 10;
        let input = format!(
            "safe-prefix{}{}",
            " ".repeat(start - "safe-prefix".len()),
            tail
        );
        let retained_prefix = &tail[..INPUT_CAP - start];
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: input,
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");

        append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
        let persisted = fs::read_to_string(path).expect("read canonical JSONL");

        assert!(!persisted.contains(retained_prefix));
        assert!(persisted.contains("safe-prefix"));
        assert!(!persisted.contains(tail));
    }

    #[test]
    fn canonical_jsonl_hides_sensitive_filesystem_paths_inside_urls() {
        let marker = "TT_PRIVACY_JSONL_URL_PATH_USER_25";
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: format!(
                    "https://example.invalid/home/{marker}/.ssh/id_rsa?mode=view"
                ),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

        append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
        let persisted = fs::read(path).expect("read canonical JSONL");
        assert!(!String::from_utf8_lossy(&persisted).contains(marker));
        assert!(String::from_utf8_lossy(&persisted).contains("[sensitive-path]"));
    }

    #[test]
    fn canonical_jsonl_replaces_malformed_percent_encoded_url_authorities() {
        let path_marker = "TT_PRIVACY_PATH_25";
        let query_marker = "TT_PRIVACY_QUERY_25";
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: format!(
                    "https://@/home/{path_marker}/.ssh/id_rsa?token={query_marker} https://example.invalid%2Fhome%2F{path_marker}%2F.ssh%2Fid_rsa"
                ),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

        append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
        let persisted = fs::read(path).expect("read canonical JSONL");
        assert!(
            check_serialized_event_markers(
                &persisted,
                "canonical-malformed-url-authority",
                &[
                    ControlledMarker {
                        id: "path",
                        value: path_marker,
                    },
                    ControlledMarker {
                        id: "query",
                        value: query_marker,
                    },
                ],
            )
            .is_ok(),
            "canonical JSONL retained a malformed URL authority marker"
        );
        assert!(String::from_utf8_lossy(&persisted).contains("[redacted-url]"));
    }

    #[test]
    fn canonical_jsonl_replaces_fully_encoded_url_authority_candidates() {
        let marker = "TT_PRIVACY_JSONL_ENCODED_AUTHORITY_25";
        let cases = [
            format!("https%3A%2F%2Fexample.invalid%252F{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%255C{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%253Fnext%253D{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%2523safe%253D{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%2540{marker}%2Fsafe"),
            format!("https%3A%2F%2Fexample.invalid%252f{marker}%2Fsafe"),
            format!("https%253A%252F%252Fexample.invalid%25252F{marker}%252Fsafe"),
        ];
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: cases.join(" "),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

        append_jsonl_events(&path, &[event]).expect("append canonical JSONL");
        let persisted = fs::read(path).expect("read canonical JSONL");
        assert!(
            check_serialized_event_markers(
                &persisted,
                "canonical-fully-encoded-url-authority",
                &[ControlledMarker {
                    id: "authority",
                    value: marker,
                }],
            )
            .is_ok(),
            "canonical JSONL retained a fully encoded URL authority marker"
        );
        let persisted_event: serde_json::Value =
            serde_json::from_slice(&persisted).expect("canonical JSONL event");
        assert_eq!(
            persisted_event["evidence"][0]["redacted_value"],
            "[redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url] [redacted-url]"
        );
    }

    #[test]
    fn canonical_jsonl_redacts_encoded_url_candidate_prefix_forms_atomically() {
        let path_marker = "TT_PRIVACY_JSONL_ENCODED_CANDIDATE_PATH_25";
        let authority_marker = "TT_PRIVACY_JSONL_ENCODED_CANDIDATE_AUTHORITY_25";
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "safe-session".to_string(),
            source_path_hash: "source-hash".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: format!(
                    "https:%2F%2Fexample.invalid%2Fhome%2F{path_marker}%2F.ssh%2Fid_rsa https%3A//example.invalid%252Fhome%252F{authority_marker}%252F.ssh%252Fid_rsa"
                ),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("activity event");

        append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append canonical JSONL");
        let persisted = fs::read(&path).expect("read canonical JSONL");
        assert!(
            check_serialized_event_markers(
                &persisted,
                "canonical-encoded-url-candidate-prefix",
                &[
                    ControlledMarker {
                        id: "path",
                        value: path_marker,
                    },
                    ControlledMarker {
                        id: "authority",
                        value: authority_marker,
                    },
                ],
            )
            .is_ok(),
            "canonical JSONL retained an encoded URL candidate marker"
        );
        let persisted_event: serde_json::Value =
            serde_json::from_slice(&persisted).expect("canonical JSONL event");
        assert_eq!(
            persisted_event["evidence"][0]["redacted_value"],
            "https://example.invalid/[sensitive-path] [redacted-url]"
        );
    }

    #[test]
    fn canonical_jsonl_redacts_nested_encoded_urls_inside_outer_components() {
        let marker = "TT_PRIVACY_JSONL_NESTED_BOUNDARY_25";
        let values = [
            format!("https://outer.invalid/?next=https%3A%2F%2Finner.invalid%252F{marker}"),
            format!("https://outer.invalid/redirect/https%3A%2F%2Finner.invalid%252F{marker}"),
            format!(
                "https://outer.invalid/#next=https%3A%2F%2Finner.invalid%2523token%253D{marker}"
            ),
        ];
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("events.jsonl");
        let event = crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "nested-jsonl-session".to_string(),
            source_path_hash: "nested-jsonl-source".to_string(),
            tool_name: Some("shell".to_string()),
            tags: Vec::new(),
            evidence: vec![Evidence {
                field: "url".to_string(),
                redacted_value: values.join(" "),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("nested URL activity event");

        append_jsonl_events(&path, std::slice::from_ref(&event)).expect("append nested URLs");
        let persisted = fs::read(&path).expect("read nested URL JSONL");
        assert!(
            check_serialized_event_markers(
                &persisted,
                "canonical-jsonl-nested-url-components",
                &[ControlledMarker {
                    id: "nested-url",
                    value: marker,
                }],
            )
            .is_ok(),
            "canonical JSONL retained a nested URL marker"
        );
        let persisted_text = String::from_utf8_lossy(&persisted);
        assert!(
            !persisted_text.contains("https%3A%2F%2Finner.invalid"),
            "canonical JSONL retained a nested encoded URL prefix"
        );
        assert!(persisted_text.contains("[redacted-url]"));
        assert_eq!(
            persisted,
            serialize_jsonl_events(std::slice::from_ref(&event)).expect("repeat nested URLs"),
            "canonical JSONL serialization must be idempotent"
        );
    }
}
