use super::*;

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
