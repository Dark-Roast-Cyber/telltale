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
    assert!(cause.downcast_ref::<RuleV1CompileError>().is_some());
}
