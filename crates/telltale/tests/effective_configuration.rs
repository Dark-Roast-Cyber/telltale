//! The effective configuration document of a synthetic pipeline, pinned.
//!
//! Hosts store and compare this document, so its bytes are the contract: a
//! change here is a new document version, not an edit of the golden file.

use telltale_core::{
    DetailedEvaluationOptions, EFFECTIVE_CONFIGURATION_V1_SCHEMA, EffectiveConfigurationV1,
    Pipeline,
};

const GOLDEN: &str = include_str!("fixtures/effective-configuration-v1.json");
const GOLDEN_IDENTITY: &str =
    "semantic:v1:sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn rule(name: &str, uuid: &str, marker: &str, score: u64) -> String {
    format!(
        "title: Synthetic {name}\nid: {uuid}\nname: {name}\ntaxonomy: telltale\nstatus: test\n\
         logsource:\n    product: ai_agent\n    category: tool_activity\n\
         detection:\n    selection:\n        tool.command|contains: {marker}\n    condition: selection\n\
         level: medium\ntelltale:\n    category: synthetic\n    score: {score}\n    explanation: Synthetic.\n"
    )
}

/// A package rule replaced at the organization tier, an additive document, an
/// override and a policy.
fn synthetic_document() -> EffectiveConfigurationV1 {
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rule_package(format!(
            "format: telltale-rule-package/v2\nid: syn.pack\ntitle: Synthetic pack\n\
             version: \"1.0.0\"\npublisher: Synthetic\nlicense: Apache-2.0\nrule_namespace: syn\n---\n{}{}",
            rule("syn.base", "6a1f0c2e-1b2c-4d3e-8f40-000000000001", "syn-alpha", 20),
            format_args!(
                "---\n{}",
                rule("syn.kept", "6a1f0c2e-1b2c-4d3e-8f40-000000000005", "syn-kept", 5)
            ),
        ))
        .rules_document(rule(
            "syn.other",
            "6a1f0c2e-1b2c-4d3e-8f40-000000000002",
            "syn-beta",
            15,
        ))
        .labeled_organization_rules_document(
            "acme",
            rule("syn.base", "6a1f0c2e-1b2c-4d3e-8f40-000000000001", "syn-gamma", 35),
        )
        .labeled_override_document(
            "fleet-tuning",
            "version: 1\noverrides:\n  - rule_id: syn.base\n    reason: Noisy in CI.\n    score: 55\n",
        )
        .policy_document("version: 1\ndisabled_rules: [syn.other]\n")
        .build()
        .unwrap();
    let options = DetailedEvaluationOptions::default();
    let mut document = pipeline.effective_configuration(&options).unwrap();
    // The identity is the pipeline's semantic identity, which the engine's
    // native profile changes and the detailed scan tests pin; the release
    // version changes with every release. Neither is this document's format.
    assert_eq!(
        document.semantic_identity,
        pipeline.semantic_provenance(&options).unwrap().identity()
    );
    document.semantic_identity = GOLDEN_IDENTITY.into();
    document.telltale_version = "0.0.0-golden".into();
    document
}

#[test]
fn effective_configuration_matches_the_golden_document() {
    let document = synthetic_document();
    let pretty = serde_json::to_string_pretty(&document).unwrap() + "\n";
    assert_eq!(pretty, GOLDEN);
    assert_eq!(
        EffectiveConfigurationV1::from_json(GOLDEN.as_bytes()).unwrap(),
        document
    );
}

#[test]
fn schema_accepts_the_golden_document() {
    let schema: serde_json::Value =
        serde_json::from_str(EFFECTIVE_CONFIGURATION_V1_SCHEMA).unwrap();
    let golden: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&golden));
}
