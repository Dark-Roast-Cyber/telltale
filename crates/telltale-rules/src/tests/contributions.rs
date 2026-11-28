use super::*;

#[test]
fn matched_rules_emit_positive_contribution_metadata() {
    // Rule v2 caps a rule's score at 100; an override is not capped.
    let rule_set = with_scores(
        &[hidden_instruction_rule("rule.large", "hidden instruction")],
        &[("rule.large", 4_294_967_296)],
    );
    let result = rule_set
        .evaluate(&[("assistant_context", "hidden instruction")])
        .expect("evaluate")
        .expect("match");

    assert_eq!(result.score, 4_294_967_296);
    assert_eq!(result.contributions.len(), 1);
    assert_eq!(result.contributions[0].id(), "rule.large");
    assert_eq!(
        result.contributions[0].contribution_type(),
        telltale_schema::scoring::RiskContributionType::DeterministicRule
    );
}

#[test]
fn matched_modifiers_emit_chain_contribution_metadata() {
    let rule_set = compile(&[
        hidden_instruction_rule("rule.base", "execution"),
        chain("chain.test", "categories: [execution]", ""),
    ]);

    let result = rule_set
        .evaluate(&[("assistant_context", "hidden instruction")])
        .expect("evaluate")
        .expect("match");
    assert_eq!(result.score, 67);
    assert_eq!(result.contributions.len(), 2);
    assert_eq!(
        result.contributions[1].contribution_type(),
        telltale_schema::scoring::RiskContributionType::ChainModifier
    );
}

#[test]
fn contributions_are_sorted_by_type_then_resolved_id() {
    let rule_set = compile(&[
        hidden_instruction_rule("rule.z", "hidden instruction"),
        hidden_instruction_rule("rule.a", "hidden instruction"),
    ]);

    let result = rule_set
        .evaluate(&[("assistant_context", "hidden instruction")])
        .expect("evaluate")
        .expect("match");
    assert_eq!(
        result
            .contributions
            .iter()
            .map(|contribution| contribution.id())
            .collect::<Vec<_>>(),
        vec!["rule.a", "rule.z"]
    );
}
