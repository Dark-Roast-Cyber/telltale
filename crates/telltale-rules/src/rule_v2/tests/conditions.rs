use super::*;

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
