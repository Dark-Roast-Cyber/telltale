//! Organization and override rule tiers through the public builder only.

use serde_json::json;
use telltale_core::*;

const BASE_UUID: &str = "7b2e1d3c-2c3d-4e4f-9a51-000000000001";

fn rule(name: &str, uuid: &str, marker: &str, score: u64) -> String {
    format!(
        "title: Synthetic {name}\nid: {uuid}\nname: {name}\ntaxonomy: telltale\nstatus: test\n\
         logsource:\n    product: ai_agent\n    category: tool_activity\n\
         detection:\n    selection:\n        tool.command|contains: {marker}\n    condition: selection\n\
         level: medium\ntelltale:\n    category: synthetic\n    score: {score}\n    explanation: Synthetic.\n"
    )
}

/// `host.base` matches `host-alpha` (score 20); `host.other` matches
/// `host-beta` (score 15). No bundled content.
fn builder() -> PipelineBuilder {
    Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(rule("host.base", BASE_UUID, "host-alpha", 20))
        .rules_document(rule(
            "host.other",
            "7b2e1d3c-2c3d-4e4f-9a51-000000000002",
            "host-beta",
            15,
        ))
}

fn tune(entries: &str) -> String {
    format!("version: 1\noverrides:\n{entries}")
}

/// Rule IDs and score of each action finding, one command per call.
fn findings(pipeline: &Pipeline, commands: &[&str]) -> Vec<(Vec<String>, u64)> {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("session.jsonl");
    let rows = commands
        .iter()
        .enumerate()
        .map(|(index, command)| {
            let id = format!("call-{index}");
            format!(
                "{}\n",
                json!({"type": "assistant", "sessionId": "host-session", "uuid": id,
                    "timestamp": format!("2026-11-21T00:00:0{index}Z"),
                    "message": {"role": "assistant", "content": [{"type": "tool_use",
                    "id": id, "name": "Bash", "input": {"command": command}}]}})
            )
        })
        .collect::<String>();
    std::fs::write(&path, rows).unwrap();
    let source = Source {
        client: ClientId::Claude,
        source_id: "claude.projects".into(),
        kind: SourceKind::Jsonl,
        path,
    };
    pipeline
        .scan_sources_detailed(&[source], &DetailedEvaluationOptions::default())
        .unwrap()
        .into_iter()
        .flat_map(|scan| scan.action_findings)
        .map(|action| (action.rule_ids().to_vec(), action.promotion_score()))
        .collect()
}

fn content_error(builder: PipelineBuilder) -> RuleContentError {
    let error = builder.build().err().expect("rejected content");
    assert!(matches!(error, PipelineError::Compilation(_)));
    std::error::Error::source(&error)
        .and_then(|cause| cause.downcast_ref::<RuleContentError>())
        .cloned()
        .expect("typed rule content error")
}

#[test]
fn override_document_disables_a_rule() {
    let pipeline = builder()
        .override_document(tune(
            "  - rule_id: host.base\n    reason: Host tuning.\n    enabled: false\n",
        ))
        .build()
        .unwrap();
    assert_eq!(pipeline.rule_count(), 1);
    assert_eq!(
        findings(&pipeline, &["echo host-alpha", "echo host-beta"]),
        [(vec!["host.other".to_string()], 15)]
    );
}

#[test]
fn override_document_rescores_a_rule() {
    let pipeline = builder()
        .labeled_override_document(
            "fleet",
            tune("  - rule_id: host.base\n    reason: Host tuning.\n    score: 55\n"),
        )
        .build()
        .unwrap();
    assert_eq!(
        findings(&pipeline, &["echo host-alpha"]),
        [(vec!["host.base".to_string()], 55)]
    );
}

#[test]
fn organization_document_replaces_a_same_id_rule() {
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rule_package(format!(
            "format: telltale-rule-package/v2\nid: host.pack\ntitle: Host pack\n\
             version: \"1.0.0\"\npublisher: Synthetic\nlicense: Apache-2.0\nrule_namespace: host\n---\n{}",
            rule("host.base", BASE_UUID, "host-alpha", 20)
        ))
        .organization_rules_document(rule("host.base", BASE_UUID, "host-gamma", 35))
        .build()
        .unwrap();
    assert_eq!(pipeline.rule_count(), 1);
    assert_eq!(
        findings(&pipeline, &["echo host-alpha", "echo host-gamma"]),
        [(vec!["host.base".to_string()], 35)]
    );
}

#[test]
fn equal_tier_duplicate_fails_with_duplicate_id() {
    let added = rule(
        "host.added",
        "7b2e1d3c-2c3d-4e4f-9a51-000000000003",
        "host-delta",
        25,
    );
    let error = content_error(
        builder()
            .labeled_organization_rules_document("first", &added)
            .labeled_organization_rules_document("second", &added),
    );
    assert_eq!(error.code(), RuleContentErrorCode::DuplicateId);
    assert_eq!(error.document(), Some("organization:second"));
    assert_eq!(error.to_string(), "rule_content_duplicate_id");
}

#[test]
fn unknown_override_rule_id_fails_with_unknown_rule_id() {
    let error = content_error(builder().labeled_override_document(
        "fleet",
        tune("  - rule_id: host.absent\n    reason: Host tuning.\n    enabled: false\n"),
    ));
    assert_eq!(error.code(), RuleContentErrorCode::UnknownRuleId);
    assert_eq!(error.document(), Some("override:fleet"));
    assert_eq!(error.to_string(), "rule_content_unknown_rule_id");
}

#[test]
fn skip_unknown_override_rules_reports_skipped_and_applies_known() {
    let pipeline = builder()
        .skip_unknown_override_rules(true)
        .labeled_override_document(
            "fleet",
            tune(
                "  - rule_id: host.future\n    reason: Newer release.\n    enabled: false\n  \
                 - rule_id: host.base\n    reason: Host tuning.\n    score: 50\n",
            ),
        )
        .build()
        .expect("pipeline builds with skipped unknown override");
    let skipped = pipeline.skipped_overrides();
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].rule_id(), "host.future");
    assert_eq!(skipped[0].document(), "override:fleet");
    assert_eq!(
        findings(&pipeline, &["echo host-alpha"]),
        [(vec!["host.base".to_string()], 50)]
    );
}

#[test]
fn skip_unknown_override_rules_still_fails_as_empty_when_all_known_disabled() {
    let error = builder()
        .skip_unknown_override_rules(true)
        .override_document(tune(
            "  - rule_id: host.future\n    reason: Newer release.\n    enabled: false\n  \
             - rule_id: host.base\n    reason: Host tuning.\n    enabled: false\n  \
             - rule_id: host.other\n    reason: Host tuning.\n    enabled: false\n",
        ))
        .build()
        .err()
        .expect("no effective rule");
    assert!(matches!(error, PipelineError::EmptyRuleSet));
}

#[test]
fn overrides_that_leave_no_effective_rule_fail_as_empty() {
    let error = builder()
        .override_document(tune(
            "  - rule_id: host.base\n    reason: Host tuning.\n    enabled: false\n  \
             - rule_id: host.other\n    reason: Host tuning.\n    enabled: false\n",
        ))
        .build()
        .err()
        .expect("no effective rule");
    assert!(matches!(error, PipelineError::EmptyRuleSet));
}
