use super::*;

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
        format!("rule document 1: {}", super::super::RULE_V1_UNSUPPORTED)
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
        super::super::document_texts(raw),
        [
            "---\na: &x 1\n",
            "--- &y\nb: 2\n",
            "# trailing\n---x: not a marker\n----\nc: 3\n",
            "d: 4\n",
        ]
    );
    assert_eq!(
        super::super::document_texts("a: 1\n---\n"),
        ["a: 1\n", "---\n"]
    );
    assert_eq!(
        super::super::document_texts("a: 1\r\n---\r\nb: 2\r\n"),
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
