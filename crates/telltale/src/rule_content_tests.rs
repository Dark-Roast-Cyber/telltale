//! The builder's organization and override tiers, through the facade.

use crate::*;

const BASE: &str = "syn.base";
const BASE_UUID: &str = "6a1f0c2e-1b2c-4d3e-8f40-000000000001";

fn rule(name: &str, uuid: &str, marker: &str, score: u64) -> String {
    format!(
        "title: Synthetic {name}\nid: {uuid}\nname: {name}\ntaxonomy: telltale\nstatus: test\n\
         logsource:\n    product: ai_agent\n    category: tool_activity\n\
         detection:\n    selection:\n        tool.command|contains: {marker}\n    condition: selection\n\
         level: medium\ntelltale:\n    category: synthetic\n    score: {score}\n    explanation: Synthetic.\n"
    )
}

/// A package rule `syn.base` matching `syn-alpha` (score 20) and an explicit
/// rule `syn.other` matching `syn-beta`, without bundled content.
fn base_builder() -> PipelineBuilder {
    Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(rule(
            "syn.other",
            "6a1f0c2e-1b2c-4d3e-8f40-000000000002",
            "syn-beta",
            15,
        ))
        .rule_package(format!(
            "format: telltale-rule-package/v2\nid: syn.pack\ntitle: Synthetic pack\n\
             version: \"1.0.0\"\npublisher: Synthetic\nlicense: Apache-2.0\nrule_namespace: syn\n---\n{}",
            rule(BASE, BASE_UUID, "syn-alpha", 20)
        ))
}

fn overrides(entries: &str) -> String {
    format!("version: 1\ndescription: Synthetic.\noverrides:\n{entries}")
}

/// Rule IDs and score of every action finding for one command each.
fn scan_commands(pipeline: &Pipeline, commands: &[&str]) -> Vec<(Vec<String>, u64)> {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(".claude/projects/synthetic");
    std::fs::create_dir_all(&directory).unwrap();
    let rows = commands
        .iter()
        .enumerate()
        .map(|(index, command)| {
            serde_json::json!({"type": "assistant", "sessionId": "rule-content-session",
                "uuid": format!("call-{index}"), "timestamp": format!("2026-11-20T12:00:0{index}Z"),
                "message": {"role": "assistant", "content": [{"type": "tool_use",
                "id": format!("toolu_{index}"), "name": "Bash", "input": {"command": command}}]}})
            .to_string()
                + "\n"
        })
        .collect::<String>();
    std::fs::write(directory.join("session.jsonl"), rows).unwrap();
    pipeline
        .scan_root_detailed(root.path(), &DetailedEvaluationOptions::default())
        .unwrap()
        .into_iter()
        .flat_map(|scan| scan.action_findings)
        .map(|action| (action.rule_ids().to_vec(), action.promotion_score()))
        .collect()
}

fn rejected(builder: PipelineBuilder) -> RuleContentError {
    let error = builder.build().err().expect("rejected content");
    assert_eq!(error.to_string(), "pipeline_compilation_failed");
    std::error::Error::source(&error)
        .and_then(|cause| cause.downcast_ref::<RuleContentError>())
        .cloned()
        .unwrap_or_else(|| panic!("typed rule content error, got {error:?}"))
}

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

fn effective(builder: PipelineBuilder) -> EffectiveConfigurationV1 {
    builder
        .build()
        .unwrap()
        .effective_configuration(&DetailedEvaluationOptions::default())
        .unwrap()
}

#[test]
fn default_effective_configuration_lists_the_rule_catalog_rules() {
    let mut options = DetailedEvaluationOptions::default();
    options.process_chain = true;
    let document = Pipeline::builder()
        .build()
        .unwrap()
        .effective_configuration(&options)
        .unwrap();
    let catalog = rule_catalog_document(&options).unwrap();
    assert_eq!(
        document
            .definitions
            .iter()
            .map(|definition| (definition.id.as_str(), definition.enabled))
            .collect::<Vec<_>>(),
        catalog
            .entries
            .iter()
            .map(|entry| (entry.id.as_str(), entry.enabled))
            .collect::<Vec<_>>()
    );
    assert_eq!(document.semantic_identity, catalog.semantic_identity);
    assert!(document.documents.is_empty());
}

/// Every entry's `enabled` flag and scores are the catalog's, for the bundled
/// content with and without the process-chain pack and for tuned content.
#[test]
fn effective_configuration_agrees_with_the_rule_catalog_entry_by_entry() {
    let tuned = Pipeline::builder().labeled_override_document(
        "fleet-tuning",
        overrides(
            "  - rule_id: exfil.outbound_upload\n    reason: Retired.\n    enabled: false\n  \
                 - rule_id: execution.shell\n    reason: Quieter.\n    score: 5\n",
        ),
    );
    // An organization chain that replaces a bundled one by ID.
    let replaced_chain = Pipeline::builder().organization_rules_document(
        "title: Download followed by execution\n\
             id: fcff0b3e-cbed-4bec-b561-9717dbce4abb\n\
             name: chain.download_then_execute\n\
             taxonomy: telltale\nstatus: stable\n\
             correlation:\n    type: telltale_chain\n    categories: [download, execution]\n    \
             within_calls: 2\n    order: ordered\n\
             falsepositives:\n    - 'Synthetic.'\n\
             telltale:\n    score: 40\n    explanation: 'Synthetic replacement.'\n",
    );
    let policy = Pipeline::builder().policy_document(
        "version: 1\ndisabled_rules: [execution.shell, chain.download_then_execute]\n",
    );
    let builders = [
        ("bundled", Pipeline::builder()),
        ("tuned", tuned),
        ("policy", policy),
        ("replaced chain", replaced_chain),
        ("synthetic", base_builder()),
    ];
    for (name, builder) in builders {
        let pipeline = builder.build().unwrap();
        for process_chain in [false, true] {
            let mut options = DetailedEvaluationOptions::default();
            options.process_chain = process_chain;
            let fields =
                |id: &str, enabled, session, action: Option<u64>, package: Option<&str>| {
                    (
                        id.to_owned(),
                        enabled,
                        session,
                        action,
                        package.map(str::to_owned),
                    )
                };
            let document = pipeline.effective_configuration(&options).unwrap();
            let catalog = pipeline.rule_catalog_document(&options).unwrap();
            assert_eq!(
                document
                    .definitions
                    .iter()
                    .map(|entry| fields(
                        &entry.id,
                        entry.enabled,
                        entry.session_score,
                        entry.action_score,
                        entry.package_id.as_deref(),
                    ))
                    .collect::<Vec<_>>(),
                catalog
                    .entries
                    .iter()
                    .map(|entry| fields(
                        &entry.id,
                        entry.enabled,
                        entry.session_score,
                        entry.action_score,
                        entry.package_id.as_deref(),
                    ))
                    .collect::<Vec<_>>(),
                "{name}, process_chain {process_chain}"
            );
        }
    }
}

#[test]
fn effective_configuration_shows_overrides_with_label_and_reason() {
    let document = effective(base_builder().labeled_override_document(
        "fleet-tuning",
        overrides(
            "  - rule_id: syn.base\n    reason: Noisy in CI.\n    score: 55\n  \
             - rule_id: syn.other\n    reason: Retired.\n    enabled: false\n",
        ),
    ));
    assert_eq!(
        document.definitions,
        [
            EffectiveDefinitionV1 {
                id: "syn.base".into(),
                kind: DefinitionKindV1::Rule,
                enabled: true,
                disabled_by: None,
                session_score: 55,
                action_score: Some(55),
                tier: RuleTierV1::Package,
                replaced_tier: None,
                package_id: Some("syn.pack".into()),
                document: None,
                overrides: vec![AppliedOverrideV1 {
                    document: Some("fleet-tuning".into()),
                    reason: "Noisy in CI.".into(),
                    enabled: None,
                    score: Some(55),
                }],
            },
            EffectiveDefinitionV1 {
                id: "syn.other".into(),
                kind: DefinitionKindV1::Rule,
                enabled: false,
                disabled_by: Some(DisabledByV1::Override),
                session_score: 15,
                action_score: None,
                tier: RuleTierV1::Explicit,
                replaced_tier: None,
                package_id: None,
                document: Some("1".into()),
                overrides: vec![AppliedOverrideV1 {
                    document: Some("fleet-tuning".into()),
                    reason: "Retired.".into(),
                    enabled: Some(false),
                    score: None,
                }],
            },
        ]
    );
}

#[test]
fn effective_configuration_shows_a_replaced_rule_at_the_organization_tier() {
    let document = effective(
        base_builder()
            .labeled_organization_rules_document("acme", rule(BASE, BASE_UUID, "syn-gamma", 35)),
    );
    let base = &document.definitions[0];
    assert_eq!(
        (
            base.id.as_str(),
            base.tier,
            base.replaced_tier,
            base.document.as_deref(),
            base.package_id.as_deref(),
            base.session_score,
        ),
        (
            "syn.base",
            RuleTierV1::Organization,
            Some(RuleTierV1::Package),
            Some("acme"),
            None,
            35
        )
    );
}

#[test]
fn effective_configuration_identifies_packages_and_documents_by_content_sha256() {
    use sha2::{Digest, Sha256};
    let package = format!(
        "format: telltale-rule-package/v2\nid: syn.pack\ntitle: Synthetic pack\n\
         version: \"1.0.0\"\npublisher: Synthetic\nlicense: Apache-2.0\nrule_namespace: syn\n---\n{}",
        rule(BASE, BASE_UUID, "syn-alpha", 20)
    );
    let organization = rule(
        "syn.org",
        "6a1f0c2e-1b2c-4d3e-8f40-000000000004",
        "syn-org",
        10,
    );
    let policy = "version: 1\ndisabled_rules: [syn.org]\n";
    let sha256 = |text: &str| hex::encode(Sha256::digest(text.as_bytes()));
    let document = effective(
        Pipeline::builder()
            .without_bundled_defaults()
            .rule_package(&package)
            .labeled_organization_rules_document("acme", &organization)
            .policy_document(policy),
    );
    assert_eq!(
        document.packages,
        [EffectivePackageV1 {
            id: "syn.pack".into(),
            version: "1.0.0".into(),
            content_sha256: sha256(&package),
            origin: PackageOriginV1::Supplied,
        }]
    );
    assert_eq!(
        document.documents,
        [
            EffectiveDocumentV1 {
                kind: DocumentKindV1::Organization,
                label: "acme".into(),
                content_sha256: sha256(&organization),
            },
            EffectiveDocumentV1 {
                kind: DocumentKindV1::Policy,
                label: "1".into(),
                content_sha256: sha256(policy),
            },
        ]
    );
}

#[test]
fn effective_configuration_names_what_turned_each_rule_off() {
    let document = effective(
        base_builder()
            .rules_document(
                rule(
                    "syn.own",
                    "6a1f0c2e-1b2c-4d3e-8f40-000000000006",
                    "syn-own",
                    10,
                )
                .replace("    score: 10\n", "    score: 10\n    enabled: false\n"),
            )
            .rules_document(rule(
                "syn.kept",
                "6a1f0c2e-1b2c-4d3e-8f40-000000000007",
                "syn-kept",
                10,
            ))
            .override_document(overrides(
                "  - rule_id: syn.base\n    reason: Retired.\n    enabled: false\n",
            ))
            .policy_document("version: 1\ndisabled_rules: [syn.other]\n"),
    );
    assert_eq!(
        document
            .definitions
            .iter()
            .map(|definition| (
                definition.id.as_str(),
                definition.enabled,
                definition.disabled_by
            ))
            .collect::<Vec<_>>(),
        [
            ("syn.base", false, Some(DisabledByV1::Override)),
            ("syn.kept", true, None),
            ("syn.other", false, Some(DisabledByV1::Policy)),
            ("syn.own", false, Some(DisabledByV1::Definition)),
        ]
    );
}

#[test]
fn an_override_that_enables_a_rule_the_policy_drops_leaves_it_off_by_policy() {
    let document = effective(
        base_builder()
            .rules_document(
                rule(
                    "syn.own",
                    "6a1f0c2e-1b2c-4d3e-8f40-000000000006",
                    "syn-own",
                    10,
                )
                .replace("    score: 10\n", "    score: 10\n    enabled: false\n"),
            )
            .override_document(overrides(
                "  - rule_id: syn.own\n    reason: Wanted.\n    enabled: true\n",
            ))
            .policy_document("version: 1\ndisabled_rules: [syn.own]\n"),
    );
    let own = document
        .definitions
        .iter()
        .find(|definition| definition.id == "syn.own")
        .unwrap();
    assert_eq!(
        (own.enabled, own.disabled_by),
        (false, Some(DisabledByV1::Policy))
    );
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

/// `count` rules `syn.bulk.<n>`, as one multi-document rule text.
fn bulk_rules(count: usize) -> String {
    (0..count)
        .map(|index| {
            rule(
                &format!("syn.bulk.{index}"),
                &format!("6a1f0c2e-1b2c-4d3e-8f41-{index:012}"),
                "syn-bulk",
                5,
            )
        })
        .collect::<Vec<_>>()
        .join("---\n")
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

/// A package `syn.pack<n>` with one rule, in its own namespace.
fn numbered_package(number: usize) -> String {
    format!(
        "format: telltale-rule-package/v2\nid: syn.pack{number}\ntitle: Synthetic pack\n\
         version: \"1.0.0\"\npublisher: Synthetic\nlicense: Apache-2.0\nrule_namespace: syn{number}\n---\n{}",
        rule(
            &format!("syn{number}.rule"),
            &format!("6a1f0c2e-1b2c-4d3e-8f42-{number:012}"),
            "syn-pack",
            5
        )
    )
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
