//! Bundled rules select on what a call does (`tool_kind`) and what it carries,
//! not on a harness's tool names. A bundled rule uses `tool_name` as a target
//! or selection field only when it is about the tool name as text, and is
//! exempt here with its reason. `tool_name` stays available to custom rules.
//!
//! The rule file under `config/rules/` is byte-identical to the one linted
//! here (`tests/package_metadata.rs`).

use super::test_rules::{file, rule};
use super::{CompiledDefinition, LoadedRules, bundled_default_rules};
use crate::package::bundled_community_package;

/// Bundled rules that may use `tool_name`, each with its reason.
const TOOL_NAME_EXEMPT: &[(&str, &str)] = &[(
    "tool.injection.shape",
    "reads the tool name as untrusted text for injected tool-call shapes, not as a harness vocabulary",
)];

/// Whether the rule compiles to a matcher on `tool_name`. A Rule v2 filter
/// always shares its selection's target.
fn selects_tool_name(rule: &CompiledDefinition) -> bool {
    matches!(rule, CompiledDefinition::Rule(rule)
        if rule.matchers.iter().any(|matcher| matcher.target == "tool_name"))
}

/// The IDs of the rules in `rules` that use `tool_name` as a target or as a
/// selection or exclusion field and are not exempt.
fn unexempt_tool_name_rules(rules: &LoadedRules) -> Vec<&str> {
    rules
        .definitions()
        .iter()
        .filter(|definition| selects_tool_name(&definition.compile()))
        .map(|definition| definition.id())
        .filter(|id| !TOOL_NAME_EXEMPT.iter().any(|(exempt, _)| exempt == id))
        .collect()
}

#[test]
fn bundled_rules_select_tool_name_only_when_exempt() {
    let mut sets = vec![bundled_default_rules().unwrap()];
    sets.extend(bundled_community_package().unwrap().into_documents());
    for set in &sets {
        assert_eq!(unexempt_tool_name_rules(set), Vec::<&str>::new());
    }
    // An exemption names a rule that still exists and still uses the name.
    for (id, reason) in TOOL_NAME_EXEMPT {
        assert!(!reason.is_empty(), "{id}");
        let rule = sets[0].get(id).expect(id);
        assert!(selects_tool_name(&rule.compile()), "{id}");
    }
}

#[test]
fn the_lint_flags_a_rule_that_selects_tool_name_unless_it_is_exempt() {
    let rule = |id: &str, detection: &str| rule(id, "synthetic", detection, "");
    let document = file(&[
        rule(
            "synthetic.target",
            "selection:\n    - tool.name|re|i: x\ncondition: selection",
        ),
        rule(
            "synthetic.selection",
            "selection_tool_name:\n    tool.name|re|i: x\ncondition: selection_tool_name",
        ),
        // A filter needs a selection on its own field.
        rule(
            "synthetic.exclusion",
            "selection_tool_name:\n    tool.name|re|i: x\nfilter_tool_name:\n    tool.name|re|i: y\n\
             condition: selection_tool_name and not filter_tool_name",
        ),
        rule(
            "synthetic.kind",
            "selection:\n    - tool.kind|re|i: x\ncondition: selection",
        ),
        rule(
            "tool.injection.shape",
            "selection:\n    - tool.name|re|i: x\ncondition: selection",
        ),
    ]);
    let set = LoadedRules::parse(&document).unwrap();
    assert_eq!(
        unexempt_tool_name_rules(&set),
        [
            "synthetic.target",
            "synthetic.selection",
            "synthetic.exclusion"
        ]
    );
}
