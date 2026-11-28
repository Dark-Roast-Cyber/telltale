use super::test_rules::{chain, file, rule};
use super::{LoadedRules, RuleOverrideDocument, RulePolicy, load_rule_set_from_documents};

/// Two case-insensitive selections, on assistant text and tool results,
/// for `hidden instruction`.
const HIDDEN_INSTRUCTION: &str = "selection:\n    - message.assistant_text|re|i: &pattern 'hidden instruction'\n    - tool.result|re|i: *pattern\ncondition: selection";

/// A rule on [`HIDDEN_INSTRUCTION`] with the Telltale tag `mcp`.
fn hidden_instruction_rule(name: &str, category: &str) -> String {
    rule(name, category, HIDDEN_INSTRUCTION, "tags: [mcp]")
}

fn compile(documents: &[String]) -> super::CompiledRuleSet {
    load_rule_set_from_documents(&[file(documents).as_str()], None).expect("compile rules")
}

fn compile_error(documents: &[String]) -> String {
    load_rule_set_from_documents(&[file(documents).as_str()], None)
        .expect_err("rejected")
        .to_string()
}

/// `documents` with rule scores set by an override document, which accepts
/// scores above the Rule v2 maximum.
fn with_scores(documents: &[String], scores: &[(&str, u64)]) -> super::CompiledRuleSet {
    let mut loaded = LoadedRules::parse(&file(documents)).unwrap();
    let entries = scores
        .iter()
        .map(|(id, score)| format!("  - {{rule_id: {id}, reason: synthetic, score: {score}}}\n"))
        .collect::<String>();
    let overrides: RuleOverrideDocument =
        serde_yaml::from_str(&format!("version: 1\noverrides:\n{entries}")).unwrap();
    loaded
        .apply_override_document(&overrides, "synthetic-overrides.yaml", None)
        .unwrap();
    loaded.compile(None).unwrap()
}

/// Two rules and a chain over them, for override tests.
fn chained_documents() -> [String; 3] {
    [
        hidden_instruction_rule("hosted.present", "test"),
        hidden_instruction_rule("hosted.second", "other"),
        chain("hosted.chain", "rules: [hosted.present, hosted.second]", ""),
    ]
}

/// The override document with one entry per line of `entries`, each a
/// flow mapping's fields after `rule_id` and `reason`.
fn override_document(entries: &[(&str, &str)]) -> RuleOverrideDocument {
    let entries = entries
        .iter()
        .map(|(id, fields)| format!("  - {{rule_id: {id}, reason: synthetic, {fields}}}\n"))
        .collect::<String>();
    serde_yaml::from_str(&format!("version: 1\noverrides:\n{entries}")).unwrap()
}

#[test]
fn excluded_candidates_preserve_retained_metadata_and_modifiers() {
    let text = "policy says do not read .env; hidden instruction";
    let fields = [("assistant_context", text), ("tool_result", text)];
    let retained = hidden_instruction_rule("test.retained", "execution").replace(
        "level: high\n",
        "level: high\ntags:\n    - atlas.aml.t0051\n",
    );
    let skipped = rule(
            "test.excluded",
            "execution",
            "selection_assistant_context:\n    message.assistant_text|re|i: 'hidden instruction'\n\
             filter_assistant_context:\n    message.assistant_text|re|i: 'policy'\n\
             selection_tool_result:\n    tool.result|re|i: 'hidden instruction'\n\
             filter_tool_result:\n    tool.result|re|i: 'policy'\n\
             condition: (selection_assistant_context and not filter_assistant_context) or (selection_tool_result and not filter_tool_result)",
            "tags: [mcp, skipped-only]",
        )
        .replace(
            "level: high\n",
            "level: high\ntags:\n    - atlas.aml.t0051\n    - atlas.aml.t0000\n",
        );
    let unmatched = hidden_instruction_rule("test.unmatched", "unmatched")
        .replace("'hidden instruction'", "'absent marker'");
    let disabled = rule(
        "test.disabled",
        "disabled",
        HIDDEN_INSTRUCTION,
        "tags: [mcp]\nenabled: false",
    );
    let modifier = chain(
        "chain.retained",
        "rules: [test.retained]",
        "detection_class: baseline_deviation\nanalytic_intent: baseline",
    )
    .replace("correlation:", "tags:\n    - atlas.aml.t0051\ncorrelation:");

    for skipped_first in [false, true] {
        for with_modifier in [false, true] {
            let mut documents = if skipped_first {
                vec![skipped.clone(), retained.clone()]
            } else {
                vec![retained.clone(), skipped.clone()]
            };
            documents.extend([unmatched.clone(), disabled.clone()]);
            if with_modifier {
                documents.push(modifier.clone());
            }
            let compiled = compile(&documents);
            for _ in 0..2 {
                let result = compiled
                    .evaluate(&fields)
                    .expect("evaluate")
                    .expect("retained");
                assert_eq!(result.categories, ["execution"]);
                assert_eq!(result.tags, ["mcp"]);
                assert_eq!(result.atlas_tags, ["atlas:AML.T0051"]);
                assert_eq!(result.evidence.len(), 1);
                assert_eq!(result.evidence[0].rule_id.as_deref(), Some("test.retained"));
                assert_eq!(result.evidence[0].field, "assistant_context");
                assert_eq!(
                    result.evidence[0].redacted_value,
                    super::redact_sensitive_text(text)
                );
                assert_eq!(result.evidence[0].hash, Some(super::evidence_hash(text)));
                let expected_ids = if with_modifier {
                    vec!["test.retained", "chain.retained"]
                } else {
                    vec!["test.retained"]
                };
                assert_eq!(result.rule_ids, expected_ids);
                assert_eq!(result.score, if with_modifier { 67 } else { 60 });
                assert_eq!(result.contributions.len(), expected_ids.len());
                for contribution in &result.contributions {
                    match contribution.id() {
                        "test.retained" => {
                            assert_eq!(contribution.points(), 60);
                            assert_eq!(
                                contribution.contribution_type(),
                                telltale_schema::scoring::RiskContributionType::DeterministicRule
                            );
                        }
                        "chain.retained" => {
                            assert_eq!(contribution.points(), 7);
                            assert_eq!(
                                contribution.contribution_type(),
                                telltale_schema::scoring::RiskContributionType::ChainModifier
                            );
                        }
                        other => panic!("unexpected contribution {other}"),
                    }
                }
                let mut classes = vec![super::default_detection_class()];
                let mut signals = vec![super::default_signal_type()];
                let mut intents = vec![super::default_analytic_intent()];
                if with_modifier {
                    classes.push("baseline_deviation".to_string());
                    signals.push(super::default_chain_signal_type());
                    intents.push("baseline".to_string());
                }
                classes.sort();
                signals.sort();
                intents.sort();
                assert_eq!(result.detection_classes, classes);
                assert_eq!(result.signal_types, signals);
                assert_eq!(result.analytic_intents, intents);
            }
        }
    }
    assert!(
        compile(&[skipped])
            .evaluate(&fields)
            .expect("evaluate")
            .is_none()
    );
}

#[cfg(test)]
mod modifier_link;

#[cfg(test)]
mod segment_scope;

mod compilation;
mod contributions;
mod matching;
mod metadata;
mod overrides;
mod policy;
