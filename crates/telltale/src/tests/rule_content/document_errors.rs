use super::*;

#[test]
fn override_document_failures_have_closed_codes() {
    let invalid =
        rejected(base_builder().override_document("version: 1\noverrides: [secret-text\n"));
    assert_eq!(
        (invalid.code(), invalid.document()),
        (RuleContentErrorCode::InvalidDocument, Some("override:1"))
    );
    let version = rejected(base_builder().override_document("version: 2\noverrides: []\n"));
    assert_eq!(version.code(), RuleContentErrorCode::UnsupportedVersion);
    let no_reason = rejected(base_builder().override_document(overrides(
        "  - rule_id: syn.base\n    reason: ' '\n    score: 5\n",
    )));
    assert_eq!(no_reason.code(), RuleContentErrorCode::InvalidOverride);
}

#[test]
fn unparsable_organization_document_fails_with_a_closed_code() {
    let error = rejected(
        base_builder().labeled_organization_rules_document("fleet", "title: [secret-text\n"),
    );
    assert_eq!(
        (error.code(), error.document()),
        (
            RuleContentErrorCode::InvalidDocument,
            Some("organization:fleet")
        )
    );
}

#[test]
fn unparsable_rules_document_fails_with_a_closed_code_and_no_document_text() {
    let error = rejected(base_builder().rules_document("title: [secret-text\n"));
    assert_eq!(
        format!("{error} {error:?}"),
        "rule_content_invalid_document RuleContentError { code: InvalidDocument, document: Some(\"explicit:2\") }"
    );
}

#[test]
fn unparsable_rule_package_fails_with_a_closed_code_and_no_document_text() {
    let error =
        rejected(base_builder().rule_package(
            "format: telltale-rule-package/v2\nid: syn.secret\ntitle: [secret-text\n",
        ));
    assert_eq!(
        format!("{error} {error:?}"),
        "rule_content_invalid_document RuleContentError { code: InvalidDocument, document: Some(\"package:2\") }"
    );
}

#[test]
fn unparsable_policy_fails_with_a_closed_code_and_no_document_text() {
    let error =
        rejected(base_builder().policy_document("version: 1\ndisabled_rule: [secret-text]\n"));
    assert_eq!(
        format!("{error} {error:?}"),
        "rule_content_invalid_document RuleContentError { code: InvalidDocument, document: Some(\"policy:1\") }"
    );
}

#[test]
fn labels_outside_the_allowed_form_or_repeated_fail() {
    let document = rule(BASE, BASE_UUID, "syn-gamma", 35);
    let tune = overrides("  - rule_id: syn.base\n    reason: Synthetic.\n    score: 5\n");
    for builder in [
        base_builder().labeled_organization_rules_document("", &document),
        base_builder().labeled_organization_rules_document("/etc/fleet.yaml", &document),
        base_builder().labeled_override_document("a".repeat(65), &tune),
        base_builder()
            .labeled_override_document("fleet", &tune)
            .labeled_override_document("fleet", &tune),
        // An unlabelled input is named by its position.
        base_builder()
            .override_document(&tune)
            .labeled_override_document("1", &tune),
    ] {
        let error = rejected(builder);
        assert_eq!(
            (error.code(), error.document()),
            (RuleContentErrorCode::InvalidLabel, None)
        );
    }
    let accepted = base_builder()
        .labeled_organization_rules_document("Fleet_2026.tuning-v1", &document)
        .labeled_override_document("a".repeat(64), &tune)
        .build();
    assert!(accepted.is_ok());
}

#[test]
fn overrides_that_leave_no_effective_rule_fail_as_empty() {
    let error = base_builder()
        .override_document(overrides(
            "  - rule_id: syn.base\n    reason: Synthetic.\n    enabled: false\n  \
             - rule_id: syn.other\n    reason: Synthetic.\n    enabled: false\n",
        ))
        .build()
        .err()
        .expect("no effective rule");
    assert!(matches!(error, PipelineError::EmptyRuleSet), "{error:?}");
}

#[test]
fn compile_time_rule_validation_keeps_the_untyped_cause() {
    let error = base_builder()
        .organization_rules_document(rule(BASE, BASE_UUID, "syn-gamma", 35).replace(
            "explanation: Synthetic.\n",
            "explanation: Synthetic.\n    detection_class: operational_health\n",
        ))
        .build()
        .err()
        .expect("canonical rejection");
    assert!(matches!(error, PipelineError::Compilation(_)));
    let cause = std::error::Error::source(&error).unwrap();
    assert!(cause.downcast_ref::<RuleContentError>().is_none());
    assert!(cause.downcast_ref::<RuleCompileError>().is_some());
}

#[test]
fn override_reasons_are_bounded_text_without_control_characters() {
    let reason = |reason: &str| {
        base_builder().override_document(overrides(&format!(
            "  - rule_id: syn.base\n    reason: {reason}\n    score: 5\n"
        )))
    };
    assert!(reason(&"a".repeat(256)).build().is_ok());
    for rejected_reason in [
        "a".repeat(257),
        r#""escape \e[2J""#.into(),
        r#""c1 \x9b""#.into(),
    ] {
        assert_eq!(
            rejected(reason(&rejected_reason)).code(),
            RuleContentErrorCode::InvalidOverride,
            "{rejected_reason}"
        );
    }
}

#[test]
fn more_override_entries_on_one_rule_than_the_document_holds_fail() {
    let entry = "  - rule_id: syn.base\n    reason: Synthetic.\n    score: 5\n";
    let error =
        rejected(base_builder().labeled_override_document("bulk", overrides(&entry.repeat(257))));
    assert_eq!(
        (error.code(), error.document()),
        (RuleContentErrorCode::ExceedsBounds, Some("override:bulk"))
    );
    assert_eq!(error.to_string(), "rule_content_exceeds_bounds");
    let at_bound = effective(base_builder().override_document(overrides(&entry.repeat(256))));
    assert_eq!(at_bound.definitions[0].overrides.len(), 256);
}

#[test]
fn more_supplied_documents_than_the_document_holds_fail() {
    let empty = "version: 1\noverrides: []\n";
    let with = |count: usize| {
        (0..count).fold(base_builder(), |builder, _| {
            builder.override_document(empty)
        })
    };
    // With the one `rules_document` of `base_builder`, 1024 inputs fit.
    assert_eq!(effective(with(1023)).documents.len(), 1024);
    let error = rejected(with(1024));
    assert_eq!(
        (error.code(), error.document()),
        (RuleContentErrorCode::ExceedsBounds, Some("override:1024"))
    );
}

#[test]
fn more_definitions_than_the_document_holds_with_process_chain_rules_fail() {
    // `base_builder` has 2 definitions; with the 371 bundled process-chain
    // rules, 3725 definitions fill the 4096 the document holds.
    let mut options = DetailedEvaluationOptions::default();
    options.process_chain = true;
    let at_bound = base_builder()
        .rules_document(bulk_rules(3723))
        .build()
        .unwrap();
    assert_eq!(
        at_bound
            .effective_configuration(&options)
            .unwrap()
            .definitions
            .len(),
        4096
    );
    assert_eq!(at_bound.rule_catalog(&options).unwrap().len(), 4096);
    let error = rejected(base_builder().rules_document(bulk_rules(3724)));
    assert_eq!(
        (error.code(), error.document()),
        (RuleContentErrorCode::ExceedsBounds, Some("explicit:2"))
    );
}

#[test]
fn more_rule_packages_than_the_document_holds_fail() {
    let with = |count: usize| {
        (2..count + 2).fold(base_builder(), |builder, number| {
            builder.rule_package(numbered_package(number))
        })
    };
    // With the one package of `base_builder`, 256 packages fit.
    assert_eq!(effective(with(255)).packages.len(), 256);
    let error = rejected(with(256));
    assert_eq!(
        (error.code(), error.document()),
        (RuleContentErrorCode::ExceedsBounds, Some("package:257"))
    );
}

#[test]
fn input_names_in_errors_use_the_kind_and_label_the_document_reports() {
    let replacement = rule(BASE, BASE_UUID, "syn-gamma", 35);
    let tune = overrides("  - rule_id: syn.base\n    reason: Synthetic.\n    score: 5\n");
    let accepted = effective(
        base_builder()
            .labeled_organization_rules_document("acme", &replacement)
            .rules_document(rule(
                "syn.added",
                "6a1f0c2e-1b2c-4d3e-8f40-000000000008",
                "syn-added",
                5,
            ))
            .labeled_override_document("fleet", &tune),
    );
    let reported = accepted
        .documents
        .iter()
        .map(|document| {
            let kind = serde_json::to_value(document.kind).unwrap();
            format!("{}:{}", kind.as_str().unwrap(), document.label)
        })
        .collect::<Vec<_>>();
    let organization = rejected(
        base_builder()
            .labeled_organization_rules_document("acme", "title: [unparsable\n")
            .labeled_override_document("fleet", &tune),
    );
    let explicit = rejected(base_builder().rules_document(&replacement));
    let override_input = rejected(
        base_builder()
            .labeled_organization_rules_document("acme", &replacement)
            .labeled_override_document("fleet", "version: 1\noverrides: [unparsable\n"),
    );
    assert_eq!(
        reported,
        [
            "organization:acme",
            "explicit:1",
            "explicit:2",
            "override:fleet"
        ]
    );
    assert_eq!(organization.document(), Some(reported[0].as_str()));
    assert_eq!(explicit.document(), Some(reported[2].as_str()));
    assert_eq!(override_input.document(), Some(reported[3].as_str()));
}

#[test]
fn a_pipeline_over_rule_files_reports_no_document_labels() {
    let root = tempfile::tempdir().unwrap();
    let organization = root.path().join("acme.yaml");
    let tuning = root.path().join("fleet-tuning.yaml");
    std::fs::write(&organization, rule(BASE, BASE_UUID, "syn-gamma", 35)).unwrap();
    std::fs::write(
        &tuning,
        overrides("  - rule_id: syn.base\n    reason: Noisy in CI.\n    score: 55\n"),
    )
    .unwrap();
    let paths = crate::rule_resolution::RulePackPaths {
        organization: vec![organization],
        ..Default::default()
    };
    let document = crate::rule_resolution::resolve_rule_set(
        &paths,
        &[],
        Vec::new(),
        None,
        RuleLoadMode::CustomOnly,
        &[tuning],
        &[],
    )
    .unwrap()
    .into_pipeline()
    .unwrap()
    .effective_configuration(&DetailedEvaluationOptions::default())
    .unwrap();
    let [base] = document.definitions.as_slice() else {
        panic!("one definition");
    };
    assert_eq!(
        (base.tier, base.document.as_deref(), base.session_score),
        (RuleTierV1::Organization, None, 55)
    );
    assert_eq!(base.overrides[0].document, None);
    assert_eq!(base.overrides[0].reason, "Noisy in CI.");
    assert!(document.documents.is_empty());
}
