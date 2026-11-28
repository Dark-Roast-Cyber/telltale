use super::*;

#[test]
fn shared_regex_matches_a_fresh_compile_and_keeps_no_failure() {
    let pattern = r"(?i:shared-regex-test\s+(\d+))";
    let (first, again) = (
        super::super::shared_regex(pattern).unwrap(),
        super::super::shared_regex(pattern).unwrap(),
    );
    let fresh = regex::Regex::new(pattern).unwrap();
    for text in ["Shared-Regex-Test 42", "shared-regex-test", ""] {
        let expected = fresh.find(text).map(|found| found.range());
        assert_eq!(first.find(text).map(|found| found.range()), expected);
        assert_eq!(again.find(text).map(|found| found.range()), expected);
    }
    // An invalid pattern fails every time, with the compiler's own error.
    let invalid = String::from("(unclosed");
    let expected = regex::Regex::new(&invalid).unwrap_err().to_string();
    for _ in 0..2 {
        assert_eq!(
            super::super::shared_regex(&invalid)
                .unwrap_err()
                .to_string(),
            expected
        );
    }
}

#[test]
fn shared_regex_map_starts_over_at_capacity() {
    let first = "bounded-first-pattern";
    assert!(super::super::shared_regex(first).unwrap().is_match(first));
    // Enough new patterns to pass the capacity whatever else is in the map.
    for index in 0..super::super::SHARED_REGEX_CAPACITY {
        let pattern = format!("bounded-{index}x");
        assert!(
            super::super::shared_regex(&pattern)
                .unwrap()
                .is_match(&pattern)
        );
    }
    {
        let compiled = super::super::SHARED_REGEXES.lock().unwrap();
        assert!(compiled.len() <= super::super::SHARED_REGEX_CAPACITY);
        assert!(!compiled.contains_key(first), "the map did not start over");
    }
    // A dropped pattern compiles again and matches as before.
    assert!(super::super::shared_regex(first).unwrap().is_match(first));
}

#[test]
fn rule_v1_documents_fail_with_a_pointer_to_rule_v2() {
    let v1 = "version: 1\ndescription: synthetic\ndefaults: {case_insensitive: false, enabled: true}\nrules: []\nmodifiers: []\n";
    let expected = format!(
        "rule document 1: {}",
        super::super::rule_v2::RULE_V1_UNSUPPORTED
    );
    assert!(expected.contains("docs/rule-format.md"));
    assert!(expected.contains("docs/migrations/0.8.0.md"));
    for version in [0, 1, 2] {
        let raw = v1.replacen("version: 1", &format!("version: {version}"), 1);
        for raw in [raw.clone(), raw.replace('\n', "\r\n")] {
            assert_eq!(
                load_rule_set_from_documents(&[&raw], None)
                    .unwrap_err()
                    .to_string(),
                expected
            );
            assert_eq!(LoadedRules::parse(&raw).unwrap_err().to_string(), expected);
        }
    }
    // A Rule v1 document after a Rule v2 one is named by its position.
    let v2 = rule(
        "synthetic.v2",
        "execution",
        "selection:\n    - tool.command|re: a\ncondition: selection",
        "",
    );
    assert_eq!(
        compile_error(&[v2, v1.to_owned()]),
        format!(
            "rule document 2: {}",
            super::super::rule_v2::RULE_V1_UNSUPPORTED
        )
    );
}

#[test]
fn rule_yaml_preserves_aliases_and_rejects_ambiguous_documents() {
    let document = rule(
        "synthetic.yaml",
        "execution",
        "selection:\n    - tool.command|re: &pattern '^needle$'\ncondition: selection",
        "",
    )
    .replace(
        "explanation: Synthetic explanation.",
        "explanation: *pattern",
    );
    let compiled = load_rule_set_from_documents(&[&document], None)
        .expect("offline rules support YAML anchors and aliases");
    let export = compiled.compatibility_export();
    assert_eq!(export.rules()[0].explanation, "^needle$");
    let matcher = export.rules()[0].compile_content_matcher().unwrap();
    assert_eq!(
        matcher.matching_fields(&[("command", "needle"), ("command", "not needle")]),
        [("command", "needle")]
    );
    assert!(matcher.matching_fields(&[("command", "NEEDLE")]).is_empty());

    for (case, invalid) in [
        document.replacen("level: high", "level: high\nlevel: low", 1),
        document.replacen("level: high", "level: high\nunknown_field: true", 1),
        format!("{document}---\n{document}"),
        document.replace("explanation: *pattern", "explanation: *missing"),
        document.replace("level: high", "level: [high"),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            load_rule_set_from_documents(&[&invalid], None).is_err(),
            "invalid YAML case {case} was accepted"
        );
    }
}

#[test]
fn supports_sigma_selection_rules() {
    let rule_set = compile(&[rule(
        "custom.agent_behavior",
        "custom",
        "selection_arguments:\n    tool.arguments|re|i: 'evil-action'\ncondition: selection_arguments",
        "",
    )]);

    let result = rule_set
        .evaluate(&[("arguments", "run evil-action now")])
        .expect("evaluate")
        .expect("match");

    assert_eq!(result.rule_ids, vec!["custom.agent_behavior"]);
    assert_eq!(result.categories, vec!["custom"]);
}
