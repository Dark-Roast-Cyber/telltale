use super::test_rules::{chain, file, rule};
use super::{ModifierLink, ModifierLinkOrder, load_rule_set_from_documents};

/// A rule in category `alpha` and a chain on it whose correlation adds `link`.
fn document(link: &str) -> String {
    file(&[
        rule(
            "synthetic.alpha",
            "alpha",
            "selection:\n    - tool.command|re: alpha\ncondition: selection",
            "",
        ),
        chain(
            "chain.synthetic",
            &format!("categories: [alpha]\n{link}"),
            "",
        ),
    ])
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
        load("within_calls: 3\n"),
        Ok(Some(ModifierLink {
            calls: 3,
            order: ModifierLinkOrder::Declared,
            minutes: None,
        }))
    );
    assert_eq!(
        load("within_calls: 3\norder: ordered\n"),
        load("within_calls: 3\n")
    );
    assert_eq!(
        load("within_calls: 0\norder: any\n"),
        Ok(Some(ModifierLink {
            calls: 0,
            order: ModifierLinkOrder::Any,
            minutes: None,
        }))
    );
}

#[test]
fn links_reject_unknown_fields_and_out_of_range_bounds() {
    for link in [
        "within_calls: 3\nwindow: 5\n",
        "within_calls: 3\norder: sometimes\n",
        "order: any\n",
    ] {
        assert!(load(link).is_err(), "{link}");
    }
    let error = load("within_calls: 11\n").unwrap_err();
    assert!(error.contains("link calls must be at most 10"), "{error}");
}

#[test]
fn a_minutes_cap_is_set_only_on_the_compiled_form() {
    let export = load_rule_set_from_documents(&[document("within_calls: 2\n").as_str()], None)
        .unwrap()
        .compatibility_export();
    let fingerprint = export.fingerprint();
    let timed = export.with_modifier("chain.synthetic", |modifier| {
        if let Some(link) = &mut modifier.link {
            link.minutes = Some(15);
        }
    });
    assert_eq!(timed.modifiers()[0].link.unwrap().minutes, Some(15));
    assert_ne!(timed.fingerprint(), fingerprint);
    // A chain without a link gains none.
    let unlinked = load_rule_set_from_documents(&[document("").as_str()], None)
        .unwrap()
        .compatibility_export()
        .with_modifier("chain.synthetic", |modifier| {
            if let Some(link) = &mut modifier.link {
                link.minutes = Some(15);
            }
        });
    assert_eq!(unlinked.modifiers()[0].link, None);
}
