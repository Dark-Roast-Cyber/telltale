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

fn effective(builder: PipelineBuilder) -> EffectiveConfigurationV1 {
    builder
        .build()
        .unwrap()
        .effective_configuration(&DetailedEvaluationOptions::default())
        .unwrap()
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

mod document_errors;
mod effective_configuration;
mod layering;
