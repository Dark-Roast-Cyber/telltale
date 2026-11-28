use super::*;

#[test]
fn override_disables_a_rule() {
    let disabled = base_builder()
        .override_document(overrides(
            "  - rule_id: syn.base\n    reason: Synthetic.\n    enabled: false\n",
        ))
        .build()
        .unwrap();
    assert_eq!(disabled.rule_count(), 1);
    assert_eq!(
        scan_commands(&disabled, &["echo syn-alpha", "echo syn-beta"]),
        [(vec!["syn.other".to_string()], 15)]
    );
}

#[test]
fn override_rescores_a_rule() {
    let tuned = base_builder()
        .override_document(overrides(
            "  - rule_id: syn.base\n    reason: Synthetic.\n    score: 55\n",
        ))
        .build()
        .unwrap();
    assert_eq!(
        scan_commands(&tuned, &["echo syn-alpha"]),
        [(vec!["syn.base".to_string()], 55)]
    );
}

#[test]
fn later_override_documents_win() {
    let tuned = base_builder()
        .override_document(overrides(
            "  - rule_id: syn.base\n    reason: Synthetic.\n    score: 30\n",
        ))
        .override_document(overrides(
            "  - rule_id: syn.base\n    reason: Synthetic.\n    score: 60\n",
        ))
        .build()
        .unwrap();
    assert_eq!(
        scan_commands(&tuned, &["echo syn-alpha"]),
        [(vec!["syn.base".to_string()], 60)]
    );
}

#[test]
fn organization_document_replaces_a_same_id_rule_with_its_own_matcher() {
    let replaced = base_builder()
        .organization_rules_document(rule(BASE, BASE_UUID, "syn-gamma", 35))
        .build()
        .unwrap();
    assert_eq!(replaced.rule_count(), 2);
    assert_eq!(
        scan_commands(&replaced, &["echo syn-alpha", "echo syn-gamma"]),
        [(vec!["syn.base".to_string()], 35)]
    );
}

#[test]
fn organization_document_adds_a_unique_rule() {
    let added = base_builder()
        .organization_rules_document(rule(
            "org.synthetic.added",
            "6a1f0c2e-1b2c-4d3e-8f40-000000000003",
            "syn-delta",
            25,
        ))
        .build()
        .unwrap();
    assert_eq!(added.rule_count(), 3);
    assert_eq!(
        scan_commands(&added, &["echo syn-delta"]),
        [(vec!["org.synthetic.added".to_string()], 25)]
    );
}

#[test]
fn equal_tier_organization_duplicate_fails_naming_the_later_input() {
    let replacement = rule(BASE, BASE_UUID, "syn-gamma", 35);
    let error = rejected(
        base_builder()
            .labeled_organization_rules_document("first", &replacement)
            .labeled_organization_rules_document("second", &replacement),
    );
    assert_eq!(error.code(), RuleContentErrorCode::DuplicateId);
    assert_eq!(error.document(), Some("organization:second"));
    assert_eq!(error.to_string(), "rule_content_duplicate_id");
}

#[test]
fn rules_document_cannot_replace_a_lower_tier_rule() {
    let error = rejected(base_builder().rules_document(rule(BASE, BASE_UUID, "syn-gamma", 35)));
    assert_eq!(error.code(), RuleContentErrorCode::DuplicateId);
    assert_eq!(error.document(), Some("explicit:2"));
}

/// The CLI leaves out an override for a hooks rule that its pipeline does
/// not carry. A pipeline an embedder builds has no such rules to expect: the
/// same entry is an unknown `rule_id` there.
#[test]
fn an_override_for_a_hooks_rule_is_unknown_to_an_embedded_pipeline() {
    let error = rejected(base_builder().override_document(overrides(
        "  - rule_id: tth.tamper.hook_settings_write\n    reason: Synthetic.\n    enabled: false\n",
    )));
    assert_eq!(error.code(), RuleContentErrorCode::UnknownRuleId);
}

#[test]
fn unknown_override_rule_id_fails_without_echoing_it() {
    let error = rejected(base_builder().labeled_override_document(
        "fleet-tuning",
        overrides("  - rule_id: syn.private.marker\n    reason: Synthetic.\n    enabled: false\n"),
    ));
    assert_eq!(error.code(), RuleContentErrorCode::UnknownRuleId);
    assert_eq!(error.document(), Some("override:fleet-tuning"));
    assert_eq!(
        format!("{error} {error:?}"),
        "rule_content_unknown_rule_id RuleContentError { code: UnknownRuleId, document: Some(\"override:fleet-tuning\") }"
    );
}

#[test]
fn opt_in_skip_unknown_override_rules_loads_known_and_reports_skipped() {
    let pipeline = base_builder()
        .skip_unknown_override_rules(true)
        .labeled_override_document(
            "fleet-tuning",
            overrides(
                "  - rule_id: syn.future.rule\n    reason: Newer release.\n    enabled: false\n  \
                 - rule_id: syn.base\n    reason: Raise score.\n    score: 45\n",
            ),
        )
        .override_document(overrides(
            "  - rule_id: tth.tamper.hook_settings_write\n    reason: Hooks only.\n    enabled: false\n",
        ))
        .build()
        .expect("pipeline builds with unknown overrides skipped");

    assert_eq!(pipeline.skipped_overrides().len(), 2);
    assert_eq!(pipeline.skipped_overrides()[0].rule_id(), "syn.future.rule");
    assert_eq!(
        pipeline.skipped_overrides()[0].document(),
        "override:fleet-tuning"
    );
    assert_eq!(
        pipeline.skipped_overrides()[1].rule_id(),
        "tth.tamper.hook_settings_write"
    );
    assert_eq!(pipeline.skipped_overrides()[1].document(), "override:2");

    assert_eq!(
        scan_commands(&pipeline, &["echo syn-alpha"]),
        [(vec![BASE.to_string()], 45)]
    );

    // Frozen EffectiveConfigurationV1 still builds and validates cleanly.
    let effective = pipeline
        .effective_configuration(&DetailedEvaluationOptions::default())
        .expect("effective configuration");
    let json = effective.to_json().expect("serialize effective config");
    EffectiveConfigurationV1::from_json(&json).expect("validate effective config");
}

#[test]
fn opt_in_skip_unknown_override_rules_sanitizes_unsafe_ids_and_keeps_validation() {
    // Default mode (and matching overrides) report no skipped overrides.
    let matched = base_builder()
        .override_document(overrides(
            "  - rule_id: syn.base\n    reason: Known.\n    score: 30\n",
        ))
        .build()
        .expect("known override");
    assert!(matched.skipped_overrides().is_empty());

    // Unsafe rule IDs (BiDi override, path, oversized) are hashed to terminal
    // opaque markers rather than echoed raw.
    let pipeline = base_builder()
        .skip_unknown_override_rules(true)
        .labeled_override_document(
            "unsafe",
            overrides(&format!(
                "  - rule_id: \"syn.bidi\u{202E}rule\"\n    reason: Synthetic.\n    enabled: false\n  \
                 - rule_id: \"/etc/secret/path\"\n    reason: Synthetic.\n    enabled: false\n  \
                 - rule_id: \"{}\"\n    reason: Synthetic.\n    enabled: false\n",
                "a".repeat(200),
            )),
        )
        .build()
        .expect("unsafe unknown ids skipped safely");
    let skipped = pipeline.skipped_overrides();
    assert_eq!(skipped.len(), 3);
    assert!(
        skipped[0].rule_id().starts_with("redacted.")
            && skipped[1].rule_id()
                == "redacted.8486a5960faab415322a88aefd7d080dfb2b1bc006435f85f1ef6f1bb8990c66"
            && skipped[2].rule_id().starts_with("redacted."),
        "unsafe rule IDs were not redacted"
    );
    assert_eq!(
        skipped
            .iter()
            .map(SkippedOverride::document)
            .collect::<Vec<_>>(),
        ["override:unsafe"; 3]
    );

    // Invalid entries, bad versions, and unparsable documents still fail even
    // when unknown overrides are skipped.
    let invalid = rejected(
        base_builder()
            .skip_unknown_override_rules(true)
            .override_document(overrides(
                "  - rule_id: syn.unknown\n    reason: ' '\n    enabled: false\n",
            )),
    );
    assert_eq!(invalid.code(), RuleContentErrorCode::InvalidOverride);

    let version = rejected(
        base_builder()
            .skip_unknown_override_rules(true)
            .override_document("version: 2\noverrides: []\n"),
    );
    assert_eq!(version.code(), RuleContentErrorCode::UnsupportedVersion);

    let unparsable = rejected(
        base_builder()
            .skip_unknown_override_rules(true)
            .override_document("version: 1\noverrides: [broken\n"),
    );
    assert_eq!(unparsable.code(), RuleContentErrorCode::InvalidDocument);
}

#[test]
fn opt_in_skip_unknown_override_rules_preserves_empty_rule_set_and_strict_toggle() {
    // Explicit false restores strict default.
    let error = rejected(
        base_builder()
            .skip_unknown_override_rules(true)
            .skip_unknown_override_rules(false)
            .labeled_override_document(
                "fleet",
                overrides(
                    "  - rule_id: syn.future.rule\n    reason: Synthetic.\n    enabled: false\n",
                ),
            ),
    );
    assert_eq!(error.code(), RuleContentErrorCode::UnknownRuleId);

    // Skipping unknown overrides still fails with EmptyRuleSet when no rule remains enabled.
    let error = base_builder()
        .skip_unknown_override_rules(true)
        .override_document(overrides(
            "  - rule_id: syn.future.rule\n    reason: Synthetic.\n    enabled: false\n  \
             - rule_id: syn.base\n    reason: Disable only rule.\n    enabled: false\n  \
             - rule_id: syn.other\n    reason: Disable other rule.\n    enabled: false\n",
        ))
        .build()
        .err()
        .expect("empty rule set");
    assert!(matches!(error, PipelineError::EmptyRuleSet));
}
