use super::*;

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
