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

#[test]
fn accepted_condition_shapes() {
    let two = "selection_command:\n    tool.command|re: a\nselection_url:\n    tool.url|re: b\n";
    for condition in [
        "1 of selection_*",
        "1 of selection*",
        "1 of them",
        "selection_command or selection_url",
        "(selection_command) or (selection_url)",
        "((selection_command or selection_url))",
    ] {
        let document = tool_rule(&format!("{two}condition: {condition}"));
        assert_eq!(matchers(&document).len(), 2, "{condition}");
    }
    let filtered = "selection_command:\n    tool.command|re: a\nfilter_command:\n    tool.command|re: x\n\
                    selection_url:\n    tool.url|re: b\nfilter_url:\n    tool.url|re: y\n";
    for condition in [
        "(selection_command and not filter_command) or (selection_url and not filter_url)",
        "selection_command and not filter_command or selection_url and not filter_url",
        "((selection_command and not filter_command)) or (selection_url and not filter_url)",
    ] {
        let document = tool_rule(&format!("{filtered}condition: {condition}"));
        let found = matchers(&document);
        assert_eq!(found[0].2.as_deref(), Some("x"), "{condition}");
        assert_eq!(found[1].2.as_deref(), Some("y"), "{condition}");
    }
}

#[test]
fn rejected_condition_shapes_name_the_problem() {
    let two = "selection_command:\n    tool.command|re: a\nselection_url:\n    tool.url|re: b\n";
    let filtered = "selection_command:\n    tool.command|re: a\nfilter_command:\n    tool.command|re: x\n\
                    selection_url:\n    tool.url|re: b\nfilter_url:\n    tool.url|re: y\n";
    for (blocks, condition, expected) in [
        (
            two,
            "selection_command and selection_url",
            "`and` between selections",
        ),
        (
            two,
            "selection_command or not selection_url",
            "negates a selection",
        ),
        (two, "all of selection*", "`all of …`"),
        (two, "any of selection*", "use `1 of …`"),
        (
            two,
            "1 of selection* or selection_url",
            "must be the whole condition",
        ),
        (two, "selection_command", "`selection_url` is not used"),
        (
            two,
            "selection_command or selection_command or selection_url",
            "used more than once",
        ),
        (two, "1 of nothing*", "matches no search identifier"),
        (
            two,
            "selection_command or other",
            "`other` is not a search identifier",
        ),
        (two, "selection_command | count() > 5", "aggregations"),
        (two, "(selection_command or selection_url", "not closed"),
        (two, "selection_command or", "ends early"),
        (
            two,
            "selection_command selection_url",
            "unexpected `selection_url`",
        ),
        (two, "selection_* or selection_url", "only after `1 of`"),
        (two, "", "detection condition must be a string"),
        (
            filtered,
            "1 of selection*",
            "cannot be used in a rule with filters",
        ),
        (
            filtered,
            "1 of them",
            "cannot be used in a rule with filters",
        ),
        (
            filtered,
            "(selection_command and not filter_command) or selection_url",
            "filter `filter_url` is not used",
        ),
        (
            filtered,
            "(selection_command and not filter_command) or (selection_url and not filter_command) or filter_url",
            "must be written as",
        ),
        (
            filtered,
            "(selection_command and not filter_command) or (selection_url and not filter_command)",
            "applies to more than one selection",
        ),
        (
            filtered,
            "(selection_command and not 1 of filter*) or selection_url",
            "more than one selection",
        ),
        (
            filtered,
            "(not filter_command and selection_command) or (selection_url and not filter_url)",
            "write the selection first",
        ),
        (
            filtered,
            "(selection_command and not selection_url) or (selection_url and not filter_url)",
            "negates a selection",
        ),
        (
            filtered,
            "(selection_command and not filter_url) or (selection_url and not filter_command)",
            "a filter vetoes only its own field",
        ),
    ] {
        let document = tool_rule(&format!("{blocks}condition: {condition}"));
        assert_error(&document, expected);
    }
    assert_error(
        &tool_rule(&format!(
            "{two}condition: [selection_command, selection_url]"
        )),
        "a list of conditions",
    );
    assert_error(
        &tool_rule("selection:\n    tool.command|re: a\n"),
        "needs a condition",
    );
}

#[test]
fn rejected_modifiers_and_values_name_the_problem() {
    for modifier in [
        "all",
        "exists",
        "base64",
        "base64offset",
        "utf16le",
        "utf16be",
        "utf16",
        "wide",
        "windash",
        "cidr",
        "fieldref",
        "gt",
        "gte",
        "lt",
        "lte",
        "neq",
        "expand",
        "minute",
        "hour",
        "day",
        "week",
        "month",
        "year",
    ] {
        assert_error(
            &tool_rule(&format!(
                "selection:\n    tool.command|{modifier}: a\ncondition: selection"
            )),
            &format!("modifier `{modifier}` is not supported at profile level 1"),
        );
    }
    for (item, expected) in [
        ("tool.command|nocase: a", "unknown modifier `nocase`"),
        (
            "tool.command|ignorecase: a",
            "unknown modifier `ignorecase`",
        ),
        ("tool.command||re: a", "unknown modifier ``"),
        ("tool.command|i: a", "must follow `re`"),
        (
            "tool.command|contains|re: a",
            "`re` must be the first modifier",
        ),
        ("tool.command|re|contains: a", "cannot be combined"),
        ("tool.command|re|cased: a", "cannot be combined"),
        ("tool.command|re|i|i: a", "repeats modifier `i`"),
        ("tool.command|cased|cased: a", "repeats modifier `cased`"),
        ("tool.command|contains|endswith: a", "only one of contains"),
        (
            "tool.command|re|segment|exclusion_segment: a",
            "only one scope modifier",
        ),
        ("tool.name|re|segment: a", "applies only to tool.command"),
        ("tool.read_path|re: a", "unknown field `tool.read_path`"),
        ("command|re: a", "unknown field `command`"),
        ("'|re': a", "has no field"),
        ("tool.command: ''", "empty values"),
        ("tool.command: []", "empty list"),
        ("tool.command: null", "`null` values"),
        ("tool.command: [[a]]", "nested lists"),
        ("tool.command: 5", "values must be strings"),
        ("tool.command: {a: b}", "values must be strings"),
    ] {
        assert_error(
            &tool_rule(&format!("selection:\n    {item}\ncondition: selection")),
            expected,
        );
    }
}

#[test]
fn rejected_search_identifiers_name_the_problem() {
    for (blocks, expected) in [
        (
            "selection:\n    tool.command|re: a\n    tool.url|re: b\n",
            "needs profile level 2",
        ),
        ("selection: {}\n", "exactly one key"),
        ("selection: [curl, wget]\n", "keyword lists"),
        ("selection: curl\n", "keyword search"),
        ("selection: []\n", "empty list"),
        ("selection: null\n", "must be a map with one key"),
        (
            "selection:\n    - tool.command|re: a\n      tool.url|re: b\n",
            "needs profile level 2",
        ),
        (
            "selection:\n    tool.command|re: a\nselection_b:\n    tool.command|re: b\n",
            "appears in more than one selection item",
        ),
        (
            "selection:\n    - tool.command|re: a\n    - tool.command|re: b\n",
            "appears in more than one selection item",
        ),
    ] {
        assert_error(
            &tool_rule(&format!("{blocks}condition: 1 of them")),
            expected,
        );
    }
    assert_error(
        &tool_rule("_hidden:\n    tool.command|re: a\ncondition: 1 of them"),
        "starts with `_`",
    );
    assert_error(
        &tool_rule(
            "selection:\n    - tool.command|re: a\n    - tool.url|re: b\n\
             filter:\n    tool.command|re: x\n\
             condition: selection and not filter",
        ),
        "is a list",
    );
    assert_error(
        &tool_rule(
            "selection:\n    tool.command|re: a\n\
             filter:\n    - tool.command|re: x\n\
             condition: selection and not filter",
        ),
        "must be a map with exactly one key",
    );
    assert_error(
        &tool_rule(
            "selection:\n    tool.command|re: a\n\
             filter_a:\n    tool.command|re: x\nfilter_b:\n    tool.command|re: y\n\
             condition: selection and not filter_a",
        ),
        "appears in more than one filter",
    );
}

#[test]
fn compiled_patterns_are_capped_after_flags() {
    // `(?i:` and `)` add five bytes.
    let fits = "a".repeat(1_019);
    let document = tool_rule(&format!(
        "selection:\n    tool.command|re|i: '{fits}'\ncondition: selection"
    ));
    assert_eq!(matchers(&document)[0].1.len(), crate::MAX_PATTERN_BYTES);
    let over = "a".repeat(1_020);
    assert_error(
        &tool_rule(&format!(
            "selection:\n    tool.command|re|i: '{over}'\ncondition: selection"
        )),
        "search identifier `selection` compiles to a 1025 byte pattern",
    );
}

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

#[test]
fn files_load_together_in_order() {
    let first = tool_rule("selection:\n    tool.command|re|i: a\ncondition: selection")
        .replacen(UUID, OTHER_UUID, 1)
        .replacen("name: synthetic.rule", "name: synthetic.first", 1);
    let v2 = tool_rule("selection:\n    tool.command|re|i: a\ncondition: selection");
    let export = load(&[&first, &v2]).compatibility_export();
    let ids = export
        .rules()
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["synthetic.first", "synthetic.rule"]);
    assert_eq!(export.rules()[0].matchers, export.rules()[1].matchers);
    let export = load(&[&v2, &first]).compatibility_export();
    assert_eq!(export.rules()[0].id, "synthetic.rule");
}

#[test]
fn documents_are_dispatched_by_their_top_level_keys() {
    let rule_document = tool_rule("selection:\n    tool.command|re: a\ncondition: selection");
    for (document, expected) in [
        (
            "title: Sigma filter\nlogsource:\n    product: ai_agent\nfilter:\n    rules: [x]\n"
                .to_owned(),
            "Sigma filter documents are not supported",
        ),
        (
            rule_document.replacen("taxonomy: telltale", "taxonomy: sigma", 1),
            "must set `taxonomy: telltale`",
        ),
        (
            rule_document.replacen("taxonomy: telltale\n", "", 1),
            "must set `taxonomy: telltale`",
        ),
        (
            "title: Something else\nkey: value\n".to_owned(),
            "not a rule document",
        ),
        (
            "taxonomy: telltale\ntitle: Neither\n".to_owned(),
            "needs `detection` (a rule) or `correlation` (a chain)",
        ),
        (
            format!("{rule_document}correlation:\n    type: telltale_chain\n"),
            "not both",
        ),
        ("- a\n- b\n".to_owned(), "must be a YAML mapping"),
        (
            format!("{rule_document}---\nversion: 1\n"),
            "rule document 2: Rule v1 is no longer supported",
        ),
        (
            rule_document.replacen("title: Synthetic rule", "title: !custom Synthetic", 1),
            "YAML tag",
        ),
        (
            rule_document.replacen("Synthetic rule", "Synthetic\u{200B}rule", 1),
            "forbidden character U+200B",
        ),
    ] {
        assert_error(&document, expected);
    }
    // A Rule v1 document fails whatever else it holds.
    assert_eq!(
        error(&["version: 1\ndescription: x\n"]),
        format!("rule document 1: {}", super::RULE_V1_UNSUPPORTED)
    );
}

#[test]
fn a_file_may_hold_several_documents() {
    let first = tool_rule("selection:\n    tool.command|re: a\ncondition: selection");
    let second =
        first
            .replacen(UUID, OTHER_UUID, 1)
            .replacen("synthetic.rule", "synthetic.second", 1);
    let export = export(&format!(
        "{first}---\n{second}---\n{}",
        chain("categories: [synthetic]")
    ));
    let ids = export
        .rules()
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["synthetic.rule", "synthetic.second"]);
    assert_eq!(export.modifiers()[0].id, "chain.synthetic");
}

#[test]
fn yaml_anchors_share_one_pattern() {
    let document = tool_rule(
        "selection:\n    - tool.command|re|i: &pattern 'curl\\s'\n    - tool.arguments|re|i: *pattern\n\
         condition: selection",
    );
    let found = matchers(&document);
    assert_eq!(found[0].1, found[1].1);
    assert_eq!(found[0].1, r"(?i:curl\s)");
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

#[test]
fn each_document_keeps_its_own_anchors() {
    let uuids = [UUID, OTHER_UUID, "0d0c4f7e-2a1b-4c3d-8e5f-6a7b8c9d0e1f"];
    let file = ["alpha", "beta", "gamma"]
        .iter()
        .zip(uuids)
        .map(|(name, uuid)| anchored_rule(name, uuid, &format!("{name}-marker")))
        .collect::<Vec<_>>()
        .join("---\n");
    let expected = ["alpha", "beta", "gamma"]
        .map(|name| {
            let regex = format!("(?i:{name}-marker)");
            (format!("synthetic.{name}"), vec![regex.clone(), regex])
        })
        .to_vec();
    assert_eq!(rule_patterns(&file), expected);
    assert_eq!(rule_patterns(&file.replace('\n', "\r\n")), expected);
}

#[test]
fn an_anchor_defined_twice_in_one_document_is_rejected() {
    let message = "YAML anchor `&pattern` is defined more than once in this document; anchor \
                   names must be unique within a document";
    let twice = tool_rule(
        "selection:\n    - tool.command|re: &pattern 'first'\n    - tool.arguments|re: *pattern\n\
         \x20   - tool.written_path|re: &pattern 'second'\n    - tool.path|re: *pattern\n\
         condition: selection",
    );
    assert_error(&twice, &format!("rule document 1: {message}"));
    // Flow style, and in the second document of a file.
    let flow = tool_rule(
        "selection:\n    - tool.command|re: [&pattern 'first', &pattern 'second']\n\
         \x20   - tool.arguments|re: *pattern\ncondition: selection",
    )
    .replacen(UUID, OTHER_UUID, 1)
    .replacen("synthetic.rule", "synthetic.flow", 1);
    let first = anchored_rule("first", UUID, "marker");
    assert_error(
        &format!("{first}---\n{flow}"),
        &format!("rule document 2: {message}"),
    );
    assert_error(&twice.replace('\n', "\r\n"), message);
}

#[test]
fn ampersands_and_unaliased_repeats_are_not_rejected() {
    // ` && ` names no anchor; `&marker` inside quotes repeats but is never
    // aliased.
    let document = tool_rule(
        "selection:\n    - tool.command|re: 'make && make install'\n\
         \x20   - tool.arguments|re: 'cd /tmp && ls'\n    - tool.written_path|re: 'a&marker'\n\
         \x20   - tool.path|re: 'b&marker'\ncondition: selection",
    );
    let regexes = matchers(&document)
        .into_iter()
        .map(|(_, regex, _, _)| regex)
        .collect::<Vec<_>>();
    assert_eq!(
        regexes,
        [
            "make && make install",
            "cd /tmp && ls",
            "a&marker",
            "b&marker"
        ]
    );
}

#[test]
fn document_texts_split_where_yaml_starts_and_ends_documents() {
    let raw = "# leading comment\n%YAML 1.2\n---\na: &x 1\n--- &y\nb: 2\n...\n# trailing\n\
               ---x: not a marker\n----\nc: 3\n... \nd: 4\n";
    assert_eq!(
        super::document_texts(raw),
        [
            "---\na: &x 1\n",
            "--- &y\nb: 2\n",
            "# trailing\n---x: not a marker\n----\nc: 3\n",
            "d: 4\n",
        ]
    );
    assert_eq!(super::document_texts("a: 1\n---\n"), ["a: 1\n", "---\n"]);
    assert_eq!(
        super::document_texts("a: 1\r\n---\r\nb: 2\r\n"),
        ["a: 1\r\n", "---\r\nb: 2\r\n"]
    );
}

#[test]
fn crlf_rule_files_load_like_lf() {
    let first = tool_rule(
        "selection:\n    tool.command|re: |\n        first\n        line\ncondition: selection",
    );
    let second = anchored_rule("second", OTHER_UUID, "second-marker");
    let file = format!(
        "{first}---\n{second}---\n{}",
        chain("categories: [synthetic]")
    );
    let lf = export(&file);
    let crlf = export(&file.replace('\n', "\r\n"));
    assert_eq!(format!("{crlf:?}"), format!("{lf:?}"));
    assert_eq!(lf.rules().len(), 2);
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

#[test]
fn chains_compile_to_modifiers() {
    let linked = export(&chain(
        "categories: [secret_access, exfiltration]\nwithin_calls: 3\norder: any",
    ));
    let modifier = &linked.modifiers()[0];
    assert_eq!(modifier.id, "chain.synthetic");
    assert_eq!(
        modifier.when_all_categories,
        ["secret_access", "exfiltration"]
    );
    assert!(modifier.when_all_rule_ids.is_empty());
    assert_eq!(modifier.signal_type, "chain");
    let link = modifier.link.unwrap();
    assert_eq!(
        (link.calls, link.order, link.minutes),
        (3, crate::ModifierLinkOrder::Any, None)
    );

    let by_rule = export(&chain(
        "rules: [execution.shell, execution.encoded_payload]\nwithin_calls: 0",
    ));
    let modifier = &by_rule.modifiers()[0];
    assert_eq!(
        modifier.when_all_rule_ids,
        ["execution.shell", "execution.encoded_payload"]
    );
    assert_eq!(
        modifier.link.unwrap().order,
        crate::ModifierLinkOrder::Declared
    );

    let unlinked = export(&chain("categories: [download, execution]"));
    assert!(unlinked.modifiers()[0].link.is_none());

    let tagged = export(&chain("categories: [a]").replacen(
        "status: stable",
        "status: stable\ntags: [atlas.aml.t0051, attack.t1059]",
        1,
    ));
    assert_eq!(tagged.modifiers()[0].atlas_tags, ["atlas:AML.T0051"]);
}

#[test]
fn rejected_chains_name_the_problem() {
    for (steps, expected) in [
        (
            "categories: [a]\nrules: [b.c]",
            "exactly one of `categories` and `rules`",
        ),
        ("within_calls: 3", "exactly one of `categories` and `rules`"),
        ("categories: []", "must not be empty"),
        (
            "categories: [a]\norder: any",
            "`order` needs `within_calls`",
        ),
        (
            "categories: [a]\nwithin_calls: 11",
            "link calls must be at most 10",
        ),
        (
            "categories: [a]\nwithin_minutes: 5",
            "unknown field `within_minutes`",
        ),
        (
            "categories: [a]\norder: declared",
            "unknown variant `declared`",
        ),
        ("rules: [NotCanonical]", "is not canonical"),
    ] {
        assert_error(&chain(steps), expected);
    }
    assert_error(
        &chain("categories: [a]").replacen("type: telltale_chain", "type: temporal", 1),
        "correlation type `temporal` is not supported",
    );
    assert_error(
        &chain("categories: [a]").replacen("status: stable", "status: stable\nlevel: high", 1),
        "unknown field `level`",
    );
    assert_error(
        &chain("categories: [a]").replacen("score: 15", "score: 15\n    category: x", 1),
        "unknown field `category`",
    );
    assert_error(
        &chain("categories: [a]").replacen("score: 15", "score: 15\n    signal_type: invented", 1),
        "unsupported signal_type 'invented'",
    );
}

/// The lists the published vocabulary reads are the ones the reader accepts.
#[test]
fn published_vocabulary_matches_the_reader() {
    use super::{
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
