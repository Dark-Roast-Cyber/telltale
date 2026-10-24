use super::{ModifierLink, ModifierLinkOrder, load_rule_set_from_documents};

fn document(link: &str) -> String {
    format!(
        "version: 1
description: synthetic
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: synthetic.alpha
    category: alpha
    severity: low
    score: 1
    targets: [command]
    regex: alpha
    tags: []
    explanation: alpha
modifiers:
  - id: chain.synthetic
    score: 1
    when_all_categories: [alpha]
{link}    explanation: synthetic
"
    )
}

fn load(link: &str) -> Result<Option<ModifierLink>, String> {
    load_rule_set_from_documents(&[document(link).as_str()], None)
        .map(|rules| rules.compatibility_export().modifiers()[0].link)
        .map_err(|error| error.to_string())
}

#[test]
fn links_default_to_declared_order_without_a_time_cap() {
    assert_eq!(load(""), Ok(None));
    assert_eq!(
        load("    link: {calls: 3}\n"),
        Ok(Some(ModifierLink {
            calls: 3,
            order: ModifierLinkOrder::Declared,
            minutes: None,
        }))
    );
    assert_eq!(
        load("    link: {calls: 0, order: any, minutes: 15}\n"),
        Ok(Some(ModifierLink {
            calls: 0,
            order: ModifierLinkOrder::Any,
            minutes: Some(15),
        }))
    );
}

#[test]
fn links_reject_unknown_fields_and_out_of_range_bounds() {
    for link in [
        "    link: {calls: 3, window: 5}\n",
        "    link: {calls: 3, order: sometimes}\n",
        "    link: {order: any}\n",
    ] {
        assert!(load(link).is_err(), "{link}");
    }
    for (link, message) in [
        ("    link: {calls: 11}\n", "link calls must be at most 10"),
        ("    link: {calls: 1, minutes: 0}\n", "between 1 and 1440"),
        (
            "    link: {calls: 1, minutes: 1441}\n",
            "between 1 and 1440",
        ),
    ] {
        let error = load(link).unwrap_err();
        assert!(error.contains(message), "{link}: {error}");
    }
}
