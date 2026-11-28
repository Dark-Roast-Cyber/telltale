use super::*;

#[test]
fn metadata_is_validated() {
    let base = tool_rule("selection:\n    tool.command|re: a\ncondition: selection");
    let replaced = |old: &str, new: &str| {
        assert!(base.contains(old), "{old}");
        base.replacen(old, new, 1)
    };
    for (document, expected) in [
        (replaced(UUID, &UUID.to_uppercase()), "lowercase UUIDv4"),
        (
            replaced(UUID, "3f2504e0-4f89-11d3-9a0c-0305e82c3301"),
            "lowercase UUIDv4",
        ),
        (
            replaced("name: synthetic.rule", "name: Synthetic"),
            "not canonical",
        ),
        (
            replaced("name: synthetic.rule", "name: single"),
            "not canonical",
        ),
        (
            replaced("title: Synthetic rule", "title: ''"),
            "`title` must not be empty",
        ),
        (
            replaced("level: low", "level: severe"),
            "unsupported level 'severe'",
        ),
        (replaced("score: 10", "score: 101"), "between 0 and 100"),
        (
            replaced("status: experimental", "status: draft"),
            "unknown variant `draft`",
        ),
        (
            replaced("product: ai_agent", "product: windows"),
            "logsource.product must be `ai_agent`",
        ),
        (
            replaced("category: tool_activity", "category: message"),
            "this rule needs `tool_activity`",
        ),
        (
            replaced(
                "category: tool_activity",
                "category: tool_activity\n    service: codex",
            ),
            "logsource.service is reserved",
        ),
        (
            replaced(
                "category: tool_activity",
                "category: tool_activity\n    vendor: x",
            ),
            "unknown field `vendor`",
        ),
        (
            replaced("level: low", "level: low\nreference: x"),
            "unknown field `reference`",
        ),
        (
            replaced("score: 10", "score: 10\n    severity: low"),
            "unknown field `severity`",
        ),
        (
            replaced("level: low", "level: low\ndate: 2026-02-30"),
            "`date` must be a date written YYYY-MM-DD",
        ),
        (
            replaced("level: low", "level: low\nmodified: 2026/11/18"),
            "`modified` must be a date",
        ),
        (
            replaced("level: low", "level: low\nreferences: [docs.example]"),
            "must be an http or https URL",
        ),
        (
            replaced(
                "level: low",
                "level: low\ndescription: see https://example.com",
            ),
            "plain text without links",
        ),
        (
            replaced("level: low", "level: low\nauthor: <b>someone</b>"),
            "plain text without links",
        ),
        (
            replaced("level: low", "level: low\ntags: [Attack.T1059]"),
            "is not a Sigma tag",
        ),
        (
            replaced("level: low", "level: low\ntags: [t1059]"),
            "is not a Sigma tag",
        ),
        (
            replaced(
                "level: low",
                "level: low\ntags: [attack.t1059, attack.t1059]",
            ),
            "listed twice",
        ),
        (
            replaced(
                "level: low",
                "level: low\nrelated:\n    - id: nope\n      type: derived",
            ),
            "`related id` must be a lowercase UUID",
        ),
        (
            replaced(
                "level: low",
                &format!("level: low\nrelated:\n    - id: {OTHER_UUID}\n      type: replaces"),
            ),
            "unknown variant `replaces`",
        ),
    ] {
        assert_error(&document, expected);
    }
    assert_error(
        &replaced("score: 10", "score: 10\n    detection_class: invented"),
        "unsupported detection_class 'invented'",
    );
    assert_error(
        &replaced("explanation: Synthetic explanation.", "explanation: ' '"),
        "`telltale.explanation` must not be empty",
    );
    assert_error(
        &replaced("score: 10", "score: 10\n    score: 11"),
        "duplicate entry",
    );
}

#[test]
fn sigma_tags_map_atlas_and_keep_attack_out_of_compiled_tags() {
    let document = tool_rule("selection:\n    tool.command|re: a\ncondition: selection").replacen(
        "level: low",
        "level: low\ntags: [attack.execution, attack.t1059.004, atlas.aml.t0051, cve.2021-44228]",
        1,
    );
    let export = export(&document);
    let rule = &export.rules()[0];
    assert_eq!(rule.atlas_tags, ["atlas:AML.T0051"]);
    assert!(rule.tags.is_empty());
}

#[test]
fn optional_metadata_reaches_only_catalog_fields() {
    let document = tool_rule("selection:\n    tool.command|re: a\ncondition: selection").replacen(
        "level: low",
        &format!(
            "level: low\n\
             description: A synthetic rule.\n\
             license: MIT\n\
             author: Synthetic Author\n\
             references: [https://example.com/a]\n\
             date: 2024-02-29\n\
             modified: 2026-11-18\n\
             related:\n    - id: {OTHER_UUID}\n      type: derived\n\
             fields: [tool.command]\n\
             scope: [workstation]\n\
             falsepositives: [Synthetic false positive.]"
        ),
        1,
    );
    let export = export(&document);
    let rule = &export.rules()[0];
    assert_eq!(rule.id, "synthetic.rule");
    assert_eq!(rule.title.as_deref(), Some("Synthetic rule"));
    assert_eq!(rule.description.as_deref(), Some("A synthetic rule."));
    assert_eq!(rule.falsepositives, ["Synthetic false positive."]);
    assert_eq!(rule.severity, "low");
    assert_eq!(rule.detection_class, "security_detection");
    assert_eq!(rule.signal_type, "atomic");
    assert_eq!(rule.analytic_intent, "alert");
}

#[test]
fn logsource_category_must_fit_the_fields() {
    let mixed = "selection:\n    - tool.command|re: a\n    - message.assistant_text|re: b\n\
                 condition: selection";
    assert_eq!(matchers(&rule(mixed, "agent_activity")).len(), 2);
    for category in ["tool_activity", "message", "tool_call"] {
        assert_error(&rule(mixed, category), "this rule needs `agent_activity`");
    }
    assert_error(
        &rule(
            "selection:\n    tool.command|re: a\ncondition: selection",
            "agent_activity",
        ),
        "this rule needs `tool_activity`",
    );
}

#[test]
fn deprecated_unsupported_and_disabled_rules_load_disabled() {
    let base = tool_rule("selection:\n    tool.command|re: a\ncondition: selection");
    for (old, new) in [
        ("status: experimental", "status: deprecated"),
        ("status: experimental", "status: unsupported"),
        ("score: 10", "score: 10\n    enabled: false"),
    ] {
        let rules = load(&[&base.replacen(old, new, 1)]);
        assert_eq!(rules.rule_count(), 0, "{new}");
    }
    for status in ["stable", "test"] {
        let document = base.replacen("experimental", status, 1);
        assert_eq!(load(&[&document]).rule_count(), 1);
    }
    // A disabled rule still holds its name and id.
    let disabled = base.replacen("status: experimental", "status: deprecated", 1);
    assert!(error(&[&disabled, &base]).contains("duplicate rule id: synthetic.rule"));
}

#[test]
fn policy_filters_rule_v2_rules_and_chains() {
    let document = format!(
        "{}---\n{}",
        tool_rule("selection:\n    tool.command|re: a\ncondition: selection"),
        chain("categories: [synthetic]")
    );
    let all = load(&[&document]).compatibility_export();
    assert_eq!((all.rules().len(), all.modifiers().len()), (1, 1));
    let policy = "disabled_rules: [synthetic.rule, chain.synthetic]\n";
    let filtered = load_rule_set_from_documents(&[&document], Some(policy))
        .unwrap()
        .compatibility_export();
    assert_eq!((filtered.rules().len(), filtered.modifiers().len()), (0, 0));
}

#[test]
fn names_and_ids_are_unique_across_the_set() {
    let first = tool_rule("selection:\n    tool.command|re: a\ncondition: selection");
    let same_name = first.replacen(UUID, OTHER_UUID, 1);
    assert!(error(&[&first, &same_name]).contains("duplicate rule id: synthetic.rule"));
    let same_id = first.replacen("name: synthetic.rule", "name: synthetic.other", 1);
    assert!(
        error(&[&format!("{first}---\n{same_id}")])
            .contains(&format!("duplicate Rule v2 id {UUID}"))
    );

    let chain_named_like_rule = chain("categories: [synthetic]").replacen(
        "name: chain.synthetic",
        "name: synthetic.rule",
        1,
    );
    assert!(error(&[&first, &chain_named_like_rule]).contains("duplicate rule id: synthetic.rule"));
}

/// The lists the published vocabulary reads are the ones the reader accepts.
#[test]
fn published_vocabulary_matches_the_reader() {
    use super::super::{
        DISABLED_STATUSES, FIELD_TARGETS, LOGSOURCE_CATEGORIES, REGEX_FLAGS, REJECTED_MODIFIERS,
        RELATED_TYPES, SCOPE_MODIFIERS, STATUSES, VALUE_MODIFIERS,
    };
    for (field, target) in FIELD_TARGETS {
        let category = if field.starts_with("message.") {
            "message"
        } else {
            "tool_activity"
        };
        let document = rule(
            &format!("selection:\n    {field}|re: x\ncondition: selection"),
            category,
        );
        assert_eq!(matchers(&document)[0].0, *target, "{field}");
    }
    for modifier in VALUE_MODIFIERS {
        regex_of(&format!("tool.command|{modifier}: x"));
    }
    for flag in REGEX_FLAGS {
        regex_of(&format!("tool.command|re|{flag}: x"));
    }
    for modifier in SCOPE_MODIFIERS {
        let document = tool_rule(&format!(
            "selection:\n    tool.command|{modifier}: x\ncondition: selection"
        ));
        assert_eq!(matchers(&document)[0].3.as_str(), *modifier);
    }
    for modifier in REJECTED_MODIFIERS {
        assert_error(
            &tool_rule(&format!(
                "selection:\n    tool.command|{modifier}: x\ncondition: selection"
            )),
            "is not supported at profile level 1",
        );
    }
    let base = tool_rule("selection:\n    tool.command|re: a\ncondition: selection");
    for status in STATUSES {
        let document = base.replacen("status: experimental", &format!("status: {status}"), 1);
        let enabled = !DISABLED_STATUSES.contains(status);
        assert_eq!(
            load(&[&document]).rule_count(),
            usize::from(enabled),
            "{status}"
        );
    }
    for kind in RELATED_TYPES {
        let document = base.replacen(
            "level: low",
            &format!("level: low\nrelated:\n    - id: {OTHER_UUID}\n      type: {kind}"),
            1,
        );
        load(&[&document]);
    }
    let both = "selection:\n    - tool.command|re: a\n    - message.user_text|re: b\n\
                condition: selection";
    let fitting = [
        tool_rule("selection:\n    tool.command|re: a\ncondition: selection"),
        rule(
            "selection:\n    message.user_text|re: a\ncondition: selection",
            "message",
        ),
        rule(both, "agent_activity"),
    ];
    assert_eq!(LOGSOURCE_CATEGORIES.len(), fitting.len());
    for (category, document) in LOGSOURCE_CATEGORIES.iter().zip(fitting) {
        assert!(document.contains(&format!("category: {category}\n")));
        load(&[&document]);
    }
}
