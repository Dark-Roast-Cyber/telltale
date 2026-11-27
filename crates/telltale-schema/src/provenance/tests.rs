use super::*;

fn manifest() -> ProducerProvenanceManifestV1 {
    ProducerProvenanceManifestV1::new(
        "0.5.0",
        ProducerRuleProvenance {
            canonicalization: RULE_V1_CANONICALIZATION.to_string(),
            fingerprint: format!("sha256:{}", "1".repeat(64)),
            rule_count: 2,
            active_policy_name: Some(crate::event::opaque_identifier("policy", "policy-a")),
        },
        ProducerRiskThresholds {
            low: 20,
            medium: 50,
            high: 70,
            critical: 90,
        },
        ProducerOperationalAlertThresholds {
            max_scanner_errors: 3,
            max_scan_duration_ms: 300_000,
        },
        ProducerSuppressionProvenance::none(),
        ProducerFeatureSwitches {
            emit_activity: false,
            emit_session_risk_summary: false,
            baseline_deviation_scoring: false,
            process_chain_detections: true,
            install_inventory: true,
            install_inventory_interval_seconds: Some(86_400),
        },
    )
    .expect("manifest")
}

#[test]
fn canonical_json_is_stable_and_round_trips() {
    let manifest = manifest();
    let first = manifest.to_json_bytes().expect("json");
    let second = manifest.to_json_bytes().expect("json");
    assert_eq!(first, second);
    assert_eq!(
        ProducerProvenanceManifestV1::from_json_bytes(&first),
        Ok(manifest)
    );
}

#[test]
fn historical_v1_rule_canonicalization_remains_valid() {
    let current = manifest();
    let historical = ProducerProvenanceManifestV1::new(
        current.telltale_version,
        ProducerRuleProvenance {
            canonicalization: RULE_V1_CANONICALIZATION_V1.to_string(),
            ..current.rules
        },
        current.risk_thresholds,
        current.operational_alert_thresholds,
        current.suppression,
        current.features,
    )
    .expect("historical manifest");
    let bytes = historical.to_json_bytes().expect("historical JSON");
    assert_eq!(
        ProducerProvenanceManifestV1::from_json_bytes(&bytes),
        Ok(historical)
    );
}

#[test]
fn rejects_identity_event_and_unknown_field_failures_without_payloads() {
    let base_manifest = manifest();
    let mut value: serde_json::Value =
        serde_json::from_slice(&base_manifest.to_json_bytes().unwrap()).unwrap();
    value["unexpected"] = serde_json::json!("synthetic-secret");
    let error = ProducerProvenanceManifestV1::from_json_bytes(&serde_json::to_vec(&value).unwrap())
        .expect_err("unknown field");
    assert_eq!(error, ProducerProvenanceError::InvalidFormat);
    assert!(!error.to_string().contains("synthetic-secret"));

    let mut changed = base_manifest.clone();
    changed.producer_manifest_id = format!("sha256:{}", "2".repeat(64));
    assert_eq!(
        changed.validate(),
        Err(ProducerProvenanceError::IdentityMismatch)
    );

    let mut malformed_version = base_manifest.clone();
    malformed_version.telltale_version = "01.2.3".to_string();
    assert_eq!(
        malformed_version.validate(),
        Err(ProducerProvenanceError::InvalidVersion)
    );

    let mut invalid_serialization = base_manifest;
    invalid_serialization.producer_manifest_id = format!("sha256:{}", "3".repeat(64));
    let error = serde_json::to_vec(&invalid_serialization).expect_err("invalid manifest");
    assert!(
        !error
            .to_string()
            .contains(&invalid_serialization.producer_manifest_id)
    );
}

#[test]
fn rule_fingerprint_must_be_a_lowercase_prefixed_sha256_digest() {
    for fingerprint in [
        "1".repeat(64),
        format!("sha512:{}", "1".repeat(64)),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha256:{}", "g".repeat(64)),
        format!("sha256:{}", "1".repeat(63)),
        format!("sha256:{}", "1".repeat(65)),
    ] {
        let mut invalid = manifest();
        invalid.rules.fingerprint = fingerprint.clone();
        assert_eq!(
            invalid.validate(),
            Err(ProducerProvenanceError::InvalidHash),
            "{fingerprint}"
        );
    }
}

#[test]
fn explicit_suppression_state_requires_digest() {
    let mut configured_without_digest = manifest();
    configured_without_digest.suppression.state = ProducerSuppressionState::Configured;
    assert_eq!(
        configured_without_digest.validate(),
        Err(ProducerProvenanceError::InvalidSuppressionState)
    );

    let mut invalid_canonicalization = manifest();
    invalid_canonicalization.suppression.canonicalization = "suppression-v0".to_string();
    assert_ne!(
        manifest().expected_identity().unwrap(),
        invalid_canonicalization.expected_identity().unwrap()
    );
    assert_eq!(
        invalid_canonicalization.validate(),
        Err(ProducerProvenanceError::InvalidSuppressionState)
    );

    let mut raw_policy_name = manifest();
    raw_policy_name.rules.active_policy_name = Some("user@example.invalid".to_string());
    assert_eq!(
        raw_policy_name.validate(),
        Err(ProducerProvenanceError::InvalidPublicLabel)
    );

    let mut enabled_without_interval = manifest();
    enabled_without_interval
        .features
        .install_inventory_interval_seconds = None;
    assert_eq!(
        enabled_without_interval.validate(),
        Err(ProducerProvenanceError::InvalidFeatureSwitches)
    );

    let mut disabled_with_interval = manifest();
    disabled_with_interval.features.install_inventory = false;
    assert_eq!(
        disabled_with_interval.validate(),
        Err(ProducerProvenanceError::InvalidFeatureSwitches)
    );
}
