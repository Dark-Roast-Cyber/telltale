use super::*;

#[test]
fn policy_can_disable_categories() {
    let policy = RulePolicy {
        disabled_categories: vec!["mcp_prompt_injection".to_string()],
        ..RulePolicy::default()
    };
    let rule_set = LoadedRules::parse(&hidden_instruction_rule(
        "mcp.tool_metadata.prompt_injection",
        "mcp_prompt_injection",
    ))
    .unwrap()
    .compile(Some(&policy))
    .expect("compile rules");

    assert_eq!(rule_set.rule_count(), 0);
}

#[test]
fn policy_name_normalizes_blank_names_to_none() {
    for name in ["", "   ", "\t\n"] {
        let policy = RulePolicy {
            name: Some(name.to_string()),
            ..RulePolicy::default()
        };
        let compiled = LoadedRules::default()
            .compile(Some(&policy))
            .expect("compile rules");

        assert_eq!(compiled.policy_name(), None);
    }

    let policy = RulePolicy {
        name: Some("  named-policy  ".to_string()),
        ..RulePolicy::default()
    };
    let compiled = LoadedRules::default()
        .compile(Some(&policy))
        .expect("compile rules");
    assert_eq!(compiled.policy_name(), Some("named-policy"));
}
