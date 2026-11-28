use crate::{CompiledRuleSet, MatchScope, RuleV1CompatibilityExport, load_rule_set_from_documents};

const UUID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const OTHER_UUID: &str = "9b2d6c8e-1f4a-4c3b-8d2e-5a6f7b8c9d0e";

/// A valid rule whose `detection` block is `detection` (indented by four
/// spaces in the document) and whose logsource category is `category`.
fn rule(detection: &str, category: &str) -> String {
    let detection = detection
        .lines()
        .map(|line| format!("    {line}\n"))
        .collect::<String>();
    format!(
        "title: Synthetic rule\n\
         id: {UUID}\n\
         name: synthetic.rule\n\
         taxonomy: telltale\n\
         status: experimental\n\
         logsource:\n    product: ai_agent\n    category: {category}\n\
         detection:\n{detection}\
         level: low\n\
         telltale:\n    category: synthetic\n    score: 10\n    explanation: Synthetic explanation.\n"
    )
}

fn tool_rule(detection: &str) -> String {
    rule(detection, "tool_activity")
}

fn load(documents: &[&str]) -> CompiledRuleSet {
    load_rule_set_from_documents(documents, None).unwrap()
}

fn export(document: &str) -> RuleV1CompatibilityExport {
    load(&[document]).compatibility_export()
}

fn error(documents: &[&str]) -> String {
    match load_rule_set_from_documents(documents, None) {
        Ok(_) => panic!("expected an error for {documents:?}"),
        Err(error) => error.to_string(),
    }
}

fn assert_error(document: &str, expected: &str) {
    let message = error(&[document]);
    assert!(
        message.contains(expected),
        "error {message:?} does not contain {expected:?}"
    );
}

/// (target, regex, exclusion, scope) for each matcher of the only rule.
fn matchers(document: &str) -> Vec<(String, String, Option<String>, MatchScope)> {
    let export = export(document);
    assert_eq!(export.rules().len(), 1);
    export.rules()[0]
        .matchers
        .iter()
        .map(|matcher| {
            (
                matcher.target.clone(),
                matcher.regex.clone(),
                matcher.exclusion_regex.clone(),
                matcher.scope,
            )
        })
        .collect()
}

fn regex_of(detection_item: &str) -> String {
    let document = tool_rule(&format!(
        "selection:\n    {detection_item}\ncondition: selection"
    ));
    let found = matchers(&document);
    assert_eq!(found.len(), 1);
    found[0].1.clone()
}

/// A rule named `synthetic.<suffix>` whose two matchers share `pattern`
/// through the anchor `&pattern`.
fn anchored_rule(suffix: &str, uuid: &str, pattern: &str) -> String {
    tool_rule(&format!(
        "selection:\n    - tool.command|re|i: &pattern '{pattern}'\n    - tool.arguments|re|i: *pattern\n\
         condition: selection"
    ))
    .replacen(UUID, uuid, 1)
    .replacen("synthetic.rule", &format!("synthetic.{suffix}"), 1)
}

/// (rule id, matcher regexes) for every rule of a file.
fn rule_patterns(file: &str) -> Vec<(String, Vec<String>)> {
    export(file)
        .rules()
        .iter()
        .map(|rule| {
            let regexes = rule.matchers.iter().map(|m| m.regex.clone()).collect();
            (rule.id.clone(), regexes)
        })
        .collect()
}

const CHAIN_UUID: &str = "6a0c3b7e-2d1f-4e8a-9b5c-7d6e5f4a3b2c";

/// A valid chain whose `correlation` block holds `steps` plus `type`.
fn chain(steps: &str) -> String {
    let steps = steps
        .lines()
        .map(|line| format!("    {line}\n"))
        .collect::<String>();
    format!(
        "title: Synthetic chain\n\
         id: {CHAIN_UUID}\n\
         name: chain.synthetic\n\
         taxonomy: telltale\n\
         status: stable\n\
         correlation:\n    type: telltale_chain\n{steps}\
         telltale:\n    score: 15\n    explanation: Synthetic chain explanation.\n"
    )
}

mod chains;
mod conditions;
mod documents;
mod metadata;
mod values;
