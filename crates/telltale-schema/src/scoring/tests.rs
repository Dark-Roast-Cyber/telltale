use super::{
    MAX_RISK_RATIONALE_LENGTH, RiskAccountingError, RiskContribution, RiskContributionType,
    RiskSeverity, RiskThresholds, ThresholdsAlreadyConfigured, assess_risk_with_thresholds,
    canonicalize_contributions, checked_risk_sum, configure_thresholds,
    is_canonical_contribution_id, load_thresholds,
};

#[test]
fn maps_scores_to_expected_severity_bands() {
    let thresholds = RiskThresholds::default();

    for (score, expected) in [
        (19, RiskSeverity::Informational),
        (20, RiskSeverity::Low),
        (49, RiskSeverity::Low),
        (50, RiskSeverity::Medium),
        (69, RiskSeverity::Medium),
        (70, RiskSeverity::High),
        (89, RiskSeverity::High),
        (90, RiskSeverity::Critical),
    ] {
        assert_eq!(
            assess_risk_with_thresholds(score, thresholds).severity,
            expected
        );
    }
}

#[test]
fn maps_scores_to_configured_low_and_medium_thresholds() {
    let thresholds = RiskThresholds {
        low: 10,
        medium: 30,
        high: 70,
        critical: 90,
    };

    assert_eq!(
        assess_risk_with_thresholds(9, thresholds).severity,
        RiskSeverity::Informational
    );
    assert_eq!(
        assess_risk_with_thresholds(10, thresholds).severity,
        RiskSeverity::Low
    );
    assert_eq!(
        assess_risk_with_thresholds(30, thresholds).severity,
        RiskSeverity::Medium
    );
}

#[test]
fn configured_thresholds_are_fixed_once_per_process() {
    // Other tests in this binary build events with the defaults, so only
    // the defaults are ever configured here.
    let defaults = RiskThresholds::default();
    configure_thresholds(defaults).expect("configure defaults");
    configure_thresholds(defaults).expect("repeat the same values");
    assert_eq!(
        configure_thresholds(RiskThresholds {
            high: 1,
            ..defaults
        }),
        Err(ThresholdsAlreadyConfigured)
    );
    assert_eq!(load_thresholds(), defaults);
}

#[test]
fn contribution_serialization_uses_closed_canonical_fields() {
    let contribution = RiskContribution::new(
        "rule.secret",
        RiskContributionType::DeterministicRule,
        4_294_967_296,
        "matched a synthetic secret path",
    )
    .expect("valid contribution");
    assert_eq!(
        serde_json::to_value(contribution).expect("serialize contribution"),
        serde_json::json!({
            "id": "rule.secret",
            "type": "deterministic_rule",
            "points": 4294967296_u64,
            "rationale": "matched a synthetic secret path"
        })
    );
}

#[test]
fn risk_sum_is_checked_and_supports_values_above_u32() {
    let contributions = vec![
        RiskContribution::new(
            "rule.a",
            RiskContributionType::DeterministicRule,
            u64::MAX - 1,
            "a",
        )
        .expect("valid contribution"),
        RiskContribution::new("chain.b", RiskContributionType::ChainModifier, 1, "b")
            .expect("valid contribution"),
    ];
    assert_eq!(checked_risk_sum(&contributions), Ok(u64::MAX));
    let overflow = RiskContribution::new(
        "baseline.c",
        RiskContributionType::BaselineDeviation,
        2,
        "c",
    )
    .expect("valid contribution");
    assert!(matches!(
        checked_risk_sum(&[contributions[0].clone(), overflow]),
        Err(super::RiskAccountingError::Overflow)
    ));
}

#[test]
fn generic_deserialization_rejects_historical_replacement_ids() {
    let replacement = format!("redacted.{}", "a".repeat(64));
    let result = serde_json::from_value::<RiskContribution>(serde_json::json!({
        "id": replacement,
        "type": "deterministic_rule",
        "points": 1,
        "rationale": "synthetic"
    }));
    assert!(result.is_err(), "native decoder admitted a replacement id");
    let historical = super::historical_risk_contribution(&serde_json::json!({
        "id": replacement,
        "type": "deterministic_rule",
        "points": 1,
        "rationale": "synthetic"
    }));
    assert!(
        historical.is_ok(),
        "historical readback rejected exact syntax"
    );
}

#[test]
fn contribution_deserialization_rejects_non_positive_points() {
    let result = serde_json::from_value::<RiskContribution>(serde_json::json!({
        "id": "rule.zero",
        "type": "deterministic_rule",
        "points": 0,
        "rationale": "zero"
    }));
    assert!(result.is_err());
}

#[test]
fn canonicalization_sorts_and_collapses_exact_duplicates() {
    let first = RiskContribution::new("rule.z", RiskContributionType::DeterministicRule, 3, "z")
        .expect("contribution");
    let second = RiskContribution::new("chain.a", RiskContributionType::ChainModifier, 4, "a")
        .expect("contribution");
    let canonical = canonicalize_contributions(vec![first.clone(), second.clone(), first.clone()])
        .expect("canonical contributions");
    assert_eq!(canonical.len(), 2);
    assert_eq!(canonical[0], first);
    assert_eq!(canonical[1], second);
    assert_eq!(checked_risk_sum(&canonical), Ok(7));
}

#[test]
fn canonicalization_rejects_conflicts_and_overflow() {
    let make = |points, rationale| {
        RiskContribution::new(
            "rule.same",
            RiskContributionType::DeterministicRule,
            points,
            rationale,
        )
        .expect("contribution")
    };
    assert!(matches!(
        canonicalize_contributions(vec![make(1, "one"), make(2, "two")]),
        Err(RiskAccountingError::ConflictingContribution(id)) if id == "rule.same"
    ));
    let max = RiskContribution::new(
        "rule.max",
        RiskContributionType::DeterministicRule,
        u64::MAX,
        "max",
    )
    .expect("contribution");
    let one = RiskContribution::new(
        "rule.one",
        RiskContributionType::DeterministicRule,
        1,
        "one",
    )
    .expect("contribution");
    assert!(matches!(
        canonicalize_contributions(vec![one, max]),
        Err(RiskAccountingError::Overflow)
    ));
}

#[test]
fn rationale_normalization_matches_manifest_safe_text() {
    let contribution = RiskContribution::new(
        "rule.safe",
        RiskContributionType::DeterministicRule,
        1,
        "  .secret/path @ value;  ",
    )
    .expect("valid contribution");
    assert_eq!(contribution.rationale(), "secret path value;");
    assert!(contribution.rationale().len() <= MAX_RISK_RATIONALE_LENGTH);
    assert!(contribution.rationale().chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                ' ' | ',' | '_' | ';' | ':' | '\'' | '(' | ')' | '-'
            )
    }));
}

#[test]
fn rationale_normalization_never_exceeds_manifest_limit() {
    let raw = format!("{} /x", "a".repeat(MAX_RISK_RATIONALE_LENGTH - 2));
    let contribution = RiskContribution::new(
        "rule.bounded",
        RiskContributionType::DeterministicRule,
        1,
        raw,
    )
    .expect("bounded contribution");

    assert!(contribution.rationale().len() <= MAX_RISK_RATIONALE_LENGTH);
}

#[test]
fn contribution_deserialization_rejects_noncanonical_rationale() {
    let result = serde_json::from_value::<RiskContribution>(serde_json::json!({
        "id": "rule.invalid",
        "type": "deterministic_rule",
        "points": 1,
        "rationale": "invalid/path"
    }));

    assert!(result.is_err());
}

#[test]
fn contribution_ids_and_deserialized_markers_are_rejected() {
    assert!(is_canonical_contribution_id("rule.valid_id"));
    for id in [
        "rule",
        "Rule.invalid",
        "1rule.invalid",
        "rule..invalid",
        "rule.invalid/extra",
    ] {
        assert!(
            !is_canonical_contribution_id(id),
            "unexpected valid id: {id}"
        );
    }
    assert!(!is_canonical_contribution_id(&format!(
        "rule.{}",
        "x".repeat(96)
    )));

    let constructor = RiskContribution::new(
        "rule.marker",
        RiskContributionType::DeterministicRule,
        1,
        "ghp_12345678901234567890",
    )
    .expect_err("constructor must reject marker before redaction");
    assert!(!constructor.to_string().contains("ghp_"));
    let imported = serde_json::from_value::<RiskContribution>(serde_json::json!({
        "id": "rule.marker",
        "type": "deterministic_rule",
        "points": 1,
        "rationale": "ghp_12345678901234567890"
    }));
    assert!(imported.is_err());
}

#[test]
fn exact_credential_markers_are_rejected_by_constructor_and_deserialization() {
    for (index, marker) in [
        "GhP_12345678",
        "SK-abcdefgh",
        "akia1234567890ab",
        "XoXb-12345678",
        "eYj_12345678.segment_5678.segment_9012",
        "-----begin openssh private key-----",
    ]
    .into_iter()
    .enumerate()
    {
        let raw_rationale = format!("prefix {marker} suffix");
        let constructor = RiskContribution::new(
            format!("rule.marker_{index}"),
            RiskContributionType::DeterministicRule,
            1,
            &raw_rationale,
        );
        let error = constructor.expect_err("constructor accepted embedded marker");
        assert!(!error.to_string().contains(marker));
        let imported = serde_json::from_value::<RiskContribution>(serde_json::json!({
            "id": format!("rule.imported_{index}"),
            "type": "deterministic_rule",
            "points": 1,
            "rationale": raw_rationale,
        }));
        assert!(
            imported.is_err(),
            "deserialization accepted marker: {marker}"
        );
    }
}

#[test]
fn credential_marker_near_misses_remain_valid_safe_text() {
    for (index, rationale) in [
        "ghp_1234567",
        "sk-1234567",
        "AKIA1234567890A",
        "xoxb-1234567",
        "segment_1234.segment_5678.segment_9012",
        "-----BEGIN OPENSSH PUBLIC KEY-----",
    ]
    .into_iter()
    .enumerate()
    {
        let contribution = RiskContribution::new(
            format!("rule.near_miss_{index}"),
            RiskContributionType::DeterministicRule,
            1,
            rationale,
        )
        .expect("near miss should remain valid");
        assert!(!contribution.rationale().is_empty());
    }
}
