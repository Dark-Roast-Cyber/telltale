use super::*;

#[test]
fn values_lower_to_rule_v1_patterns() {
    for (item, expected) in [
        ("tool.name: Bash", "(?i:^(?:Bash)$)"),
        ("tool.name|cased: Bash", "^(?:Bash)$"),
        ("tool.command|contains: curl", "(?i:(?:curl))"),
        ("tool.command|startswith: curl", "(?i:^(?:curl))"),
        ("tool.command|endswith: .sh", r"(?i:(?:\.sh)$)"),
        ("tool.command|contains|cased: Curl", "(?:Curl)"),
        ("tool.path: '*.env'", r"(?i:^(?:(?s:.*)\.env)$)"),
        ("tool.path|endswith: '\\*.txt'", r"(?i:(?:\*\.txt)$)"),
        ("tool.command|re: 'a+b'", "a+b"),
        ("tool.command|re|i: 'a+b'", "(?i:a+b)"),
        ("tool.command|re|m: '^a$'", "(?m:^a$)"),
        ("tool.command|re|s: 'a.b'", "(?s:a.b)"),
        ("tool.command|re|s|i: 'a.b'", "(?is:a.b)"),
        ("tool.command|re|s|m|i: 'a.b'", "(?ims:a.b)"),
        ("tool.command|re|i|segment: 'a'", "(?i:a)"),
    ] {
        assert_eq!(regex_of(item), expected, "{item}");
    }
}

#[test]
fn every_field_compiles_to_its_rule_v1_target() {
    for (field, target, category) in [
        ("tool.command", "command", "tool_activity"),
        ("tool.arguments", "arguments", "tool_activity"),
        ("tool.written_path", "written_path", "tool_activity"),
        ("tool.path", "file_path", "tool_activity"),
        ("tool.name", "tool_name", "tool_activity"),
        ("tool.kind", "tool_kind", "tool_activity"),
        ("tool.url", "url", "tool_activity"),
        ("tool.result", "tool_result", "tool_activity"),
        ("message.assistant_text", "assistant_context", "message"),
        ("message.user_text", "user_context", "message"),
    ] {
        assert!(crate::SUPPORTED_RULE_TARGETS.contains(&target));
        let document = rule(
            &format!("selection:\n    {field}|re: x\ncondition: selection"),
            category,
        );
        assert_eq!(matchers(&document)[0].0, target, "{field}");
    }
}

#[test]
fn list_values_wrap_each_item_so_flags_do_not_leak() {
    let document =
        tool_rule("selection:\n    tool.command|re: ['(?s)a.b', 'c.d']\ncondition: selection");
    assert_eq!(matchers(&document)[0].1, "(?:(?:(?s)a.b)|(?:c.d))");
    let rules = load(&[&document]);
    assert!(rules.evaluate(&[("command", "a\nb")]).unwrap().is_some());
    assert!(
        rules.evaluate(&[("command", "c\nd")]).unwrap().is_none(),
        "the first item's (?s) must not reach the second"
    );
    assert!(rules.evaluate(&[("command", "c-d")]).unwrap().is_some());

    assert_eq!(
        regex_of("tool.command|contains: [curl, wget]"),
        "(?i:(?:(?:(?:curl))|(?:(?:wget))))"
    );
    assert_eq!(
        regex_of("tool.command|re|i: [a, b]"),
        "(?i:(?:(?:a)|(?:b)))"
    );
}

#[test]
fn each_list_item_must_compile_alone() {
    // Joined, these two halves would form a valid pattern.
    assert_error(
        &tool_rule("selection:\n    tool.command|re: ['(a', 'b)']\ncondition: selection"),
        "list item 1",
    );
}

#[test]
fn plain_values_match_whole_fields_case_insensitively() {
    let rules = load(&[&tool_rule(
        "selection:\n    tool.name: bash\ncondition: selection",
    )]);
    assert!(rules.evaluate(&[("tool_name", "BASH")]).unwrap().is_some());
    assert!(rules.evaluate(&[("tool_name", "bash2")]).unwrap().is_none());
    let rules = load(&[&tool_rule(
        "selection:\n    tool.name|cased: bash\ncondition: selection",
    )]);
    assert!(rules.evaluate(&[("tool_name", "BASH")]).unwrap().is_none());
}

#[test]
fn filters_veto_their_own_field_with_their_own_case() {
    let document = tool_rule(
        "selection_command:\n    tool.command|re|i: curl\n\
         filter_command:\n    tool.command|re|i: localhost\n\
         selection_url:\n    tool.url|re|i: curl\n\
         condition: (selection_command and not filter_command) or selection_url",
    );
    assert_eq!(
        matchers(&document),
        vec![
            (
                "command".into(),
                "(?i:curl)".into(),
                Some("(?i:localhost)".into()),
                MatchScope::Field
            ),
            ("url".into(), "(?i:curl)".into(), None, MatchScope::Field),
        ]
    );
    let rules = load(&[&document]);
    assert!(rules.notices().is_empty());
    assert!(
        rules
            .evaluate(&[("command", "curl LOCALHOST")])
            .unwrap()
            .is_none()
    );
    assert!(
        rules
            .evaluate(&[("url", "curl localhost")])
            .unwrap()
            .is_some(),
        "the filter does not veto another field"
    );

    let mixed = tool_rule(
        "selection:\n    tool.command|re|i: curl\n\
         filter:\n    tool.command|re: localhost\n\
         condition: selection and not filter",
    );
    let rules = load(&[&mixed]);
    assert_eq!(matchers(&mixed)[0].2.as_deref(), Some("localhost"));
    assert_eq!(rules.notices().len(), 1);
    assert!(rules.notices()[0].to_string().contains("case-sensitive"));
    assert!(
        rules
            .evaluate(&[("command", "curl LOCALHOST")])
            .unwrap()
            .is_some()
    );
}

#[test]
fn filters_take_their_selections_scope() {
    let inherited = tool_rule(
        "selection:\n    tool.command|re|segment: curl\n\
         filter:\n    tool.command|re: localhost\n\
         condition: selection and not filter",
    );
    assert_eq!(matchers(&inherited)[0].3, MatchScope::Segment);
    let same = tool_rule(
        "selection:\n    tool.command|re|exclusion_segment: curl\n\
         filter:\n    tool.command|re|exclusion_segment: localhost\n\
         condition: selection and not filter",
    );
    assert_eq!(matchers(&same)[0].3, MatchScope::ExclusionSegment);
    assert_error(
        &tool_rule(
            "selection:\n    tool.command|re|segment: curl\n\
             filter:\n    tool.command|re|exclusion_segment: localhost\n\
             condition: selection and not filter",
        ),
        "different scope modifiers",
    );
    assert_error(
        &tool_rule(
            "selection:\n    tool.command|re: curl\n\
             filter:\n    tool.command|re|segment: localhost\n\
             condition: selection and not filter",
        ),
        "different scope modifiers",
    );
}

#[test]
fn matchers_follow_document_and_list_order() {
    let document = tool_rule(
        "selection_url:\n    tool.url|re: a\n\
         selection_rest:\n    - tool.result|re: b\n    - tool.arguments|re: c\n\
         selection_command:\n    tool.command|re: d\n\
         condition: 1 of selection_*",
    );
    let targets = matchers(&document)
        .into_iter()
        .map(|(target, ..)| target)
        .collect::<Vec<_>>();
    assert_eq!(targets, ["url", "tool_result", "arguments", "command"]);
}
