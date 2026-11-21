//! A pipeline's effective configuration through the public API only.

use telltale_core::*;

fn rule(name: &str, uuid: &str, marker: &str, score: u64) -> String {
    format!(
        "title: Synthetic {name}\nid: {uuid}\nname: {name}\ntaxonomy: telltale\nstatus: test\n\
         logsource:\n    product: ai_agent\n    category: tool_activity\n\
         detection:\n    selection:\n        tool.command|contains: {marker}\n    condition: selection\n\
         level: medium\ntelltale:\n    category: synthetic\n    score: {score}\n    explanation: Synthetic.\n"
    )
}

#[test]
fn default_pipeline_reports_the_catalog_rules_and_the_embedded_package() {
    let options = DetailedEvaluationOptions::default();
    let document = Pipeline::builder()
        .build()
        .unwrap()
        .effective_configuration(&options)
        .unwrap();
    let catalog = rule_catalog_document(&options).unwrap();
    assert_eq!(document.schema, EFFECTIVE_CONFIGURATION_V1_ID);
    assert_eq!(
        document
            .definitions
            .iter()
            .map(|definition| definition.id.as_str())
            .collect::<Vec<_>>(),
        catalog
            .entries
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        document
            .packages
            .iter()
            .map(|package| (package.id.as_str(), package.origin))
            .collect::<Vec<_>>(),
        [(COMMUNITY_PACKAGE_ID, PackageOriginV1::Embedded)]
    );
    assert!(document.documents.is_empty());
}

#[test]
fn an_override_reports_its_label_reason_and_values() {
    let document = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(rule(
            "host.base",
            "7b2e1d3c-2c3d-4e4f-9a51-000000000011",
            "host-alpha",
            20,
        ))
        .labeled_override_document(
            "fleet-tuning",
            "version: 1\noverrides:\n  - rule_id: host.base\n    reason: Noisy in CI.\n    score: 45\n",
        )
        .build()
        .unwrap()
        .effective_configuration(&DetailedEvaluationOptions::default())
        .unwrap();
    let base = &document.definitions[0];
    assert_eq!(
        (
            base.id.as_str(),
            base.enabled,
            base.session_score,
            base.tier
        ),
        ("host.base", true, 45, RuleTierV1::Explicit)
    );
    assert_eq!(
        base.overrides,
        [AppliedOverrideV1 {
            document: Some("fleet-tuning".into()),
            reason: "Noisy in CI.".into(),
            enabled: None,
            score: Some(45),
        }]
    );
}

#[test]
fn the_document_round_trips_through_its_strict_wire_form() {
    let document = Pipeline::builder()
        .build()
        .unwrap()
        .effective_configuration(&DetailedEvaluationOptions::default())
        .unwrap();
    let bytes = document.to_json().unwrap();
    assert!(bytes.len() <= EFFECTIVE_CONFIGURATION_MAX_INPUT_BYTES);
    assert_eq!(
        EffectiveConfigurationV1::from_json(&bytes).unwrap(),
        document
    );
}
