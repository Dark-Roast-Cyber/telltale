//! Bundled rules select on what a call does (`tool_kind`) and what it carries,
//! not on a harness's tool names. A bundled rule uses `tool_name` as a target
//! or selection field only when it is about the tool name as text, and is
//! exempt here with its reason. `tool_name` stays available to custom rules.
//!
//! The rule file under `config/rules/` is byte-identical to the one linted
//! here (`tests/package_metadata.rs`).

use super::{RuleSet, bundled_default_rule_set, parse_rule_document};
use crate::package::bundled_community_package;

/// Bundled rules that may use `tool_name`, each with its reason.
const TOOL_NAME_EXEMPT: &[(&str, &str)] = &[(
    "tool.injection.shape",
    "reads the tool name as untrusted text for injected tool-call shapes, not as a harness vocabulary",
)];

/// The IDs of the rules in `rule_set` that use `tool_name` as a target or as a
/// selection or exclusion field and are not exempt.
fn unexempt_tool_name_rules(rule_set: &RuleSet) -> Vec<&str> {
    rule_set
        .rules
        .iter()
        .filter(|rule| {
            let detection = rule
                .detection
                .iter()
                .flat_map(|detection| detection.selection.keys().chain(detection.exclude.keys()));
            rule.targets
                .iter()
                .chain(detection)
                .any(|target| target == "tool_name")
        })
        .map(|rule| rule.id.as_str())
        .filter(|id| !TOOL_NAME_EXEMPT.iter().any(|(exempt, _)| exempt == id))
        .collect()
}

#[test]
fn bundled_rules_select_tool_name_only_when_exempt() {
    let mut sets = vec![bundled_default_rule_set().unwrap()];
    sets.extend(bundled_community_package().unwrap().into_documents());
    for set in &sets {
        assert_eq!(unexempt_tool_name_rules(set), Vec::<&str>::new());
    }
    // An exemption names a rule that still exists and still uses the name.
    let rules = &sets[0].rules;
    for (id, reason) in TOOL_NAME_EXEMPT {
        assert!(!reason.is_empty(), "{id}");
        let rule = rules.iter().find(|rule| rule.id == *id).expect(id);
        assert!(rule.targets.iter().any(|t| t == "tool_name"), "{id}");
    }
}

#[test]
fn the_lint_flags_a_rule_that_selects_tool_name_unless_it_is_exempt() {
    let rule = |id: &str, body: &str| {
        format!(
            "  - id: {id}\n    category: synthetic\n    severity: low\n    score: 1\n{body}\n    tags: []\n    explanation: synthetic\n"
        )
    };
    let document = format!(
        "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: true\n  enabled: true\nrules:\n{}{}{}{}{}modifiers: []\n",
        rule("synthetic.target", "    targets: [tool_name]\n    regex: x"),
        rule(
            "synthetic.selection",
            "    detection:\n      selection:\n        tool_name: x\n      condition: selection"
        ),
        rule(
            "synthetic.exclusion",
            "    detection:\n      selection:\n        command: x\n      exclude:\n        tool_name: x\n      condition: selection"
        ),
        rule("synthetic.kind", "    targets: [tool_kind]\n    regex: x"),
        rule(
            "tool.injection.shape",
            "    targets: [tool_name]\n    regex: x"
        ),
    );
    let set = parse_rule_document(&document).unwrap();
    assert_eq!(
        unexempt_tool_name_rules(&set),
        [
            "synthetic.target",
            "synthetic.selection",
            "synthetic.exclusion"
        ]
    );
}
