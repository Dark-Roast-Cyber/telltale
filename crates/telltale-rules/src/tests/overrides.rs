use super::*;

/// `apply_override_document_skipping` leaves out every entry that names
/// nothing loaded, whatever its name, and applies the rest, the chain's
/// included. The strict `apply_override_document` fails on the same
/// unknown entry and accepts the chain's.
#[test]
fn skipping_leaves_out_only_entries_that_name_nothing_loaded() {
    let documents = chained_documents();
    let overrides = override_document(&[
        ("hosted.absent", "enabled: false"),
        ("hosted.present", "enabled: false"),
        ("elsewhere.absent", "enabled: false"),
        ("hosted.chain", "enabled: false"),
    ]);
    let mut loaded = LoadedRules::parse(&file(&documents)).unwrap();
    let skipped = loaded
        .apply_override_document_skipping(&overrides, "synthetic.yaml", None)
        .unwrap();
    assert_eq!(skipped, ["hosted.absent", "elsewhere.absent"]);
    for id in ["hosted.present", "hosted.chain"] {
        assert!(!loaded.get(id).unwrap().enabled(), "{id}");
    }
    assert!(loaded.get("hosted.second").unwrap().enabled());

    let mut strict = LoadedRules::parse(&file(&documents)).unwrap();
    assert_eq!(
        strict
            .apply_override_document(&overrides, "synthetic.yaml", None)
            .map_err(|error| error.to_string()),
        Err("unknown rule_id 'hosted.absent' in rule override file synthetic.yaml".to_owned()),
    );
    let only_chain = override_document(&[("hosted.chain", "enabled: false")]);
    strict
        .apply_override_document(&only_chain, "synthetic.yaml", None)
        .unwrap();
    assert!(!strict.get("hosted.chain").unwrap().enabled());
}

/// An override entry on a chain sets its `enabled` and `score` like a
/// rule's and records the entry. Disabling it leaves it out of the
/// compiled set and keeps its rules; rescoring it changes the compiled
/// modifier. Both change the set's fingerprint, as a rule override does.
#[test]
fn an_override_on_a_chain_sets_it_like_a_rule() {
    let documents = chained_documents();
    let compiled = |entries: &[(&str, &str)]| {
        let mut loaded = LoadedRules::parse(&file(&documents)).unwrap();
        loaded
            .apply_override_document(&override_document(entries), "synthetic.yaml", Some("ops"))
            .unwrap();
        let set = loaded.compile(None).unwrap();
        (loaded, set)
    };
    let (_, baseline) = compiled(&[]);
    let modifier_score = |set: &super::super::CompiledRuleSet| {
        set.compatibility_export()
            .modifiers()
            .iter()
            .find(|modifier| modifier.id == "hosted.chain")
            .map(|modifier| modifier.score)
    };
    let rule_ids = |set: &super::super::CompiledRuleSet| {
        set.compatibility_export()
            .rules()
            .iter()
            .map(|rule| rule.id.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(modifier_score(&baseline), Some(7));
    let fingerprint = baseline.compatibility_export().fingerprint();

    let (loaded, disabled) = compiled(&[("hosted.chain", "enabled: false")]);
    let definition = loaded.get("hosted.chain").unwrap();
    assert!(!definition.enabled());
    assert_eq!(
        definition.overrides(),
        [super::super::AppliedOverride {
            source: "synthetic.yaml".to_owned(),
            label: Some("ops".to_owned()),
            reason: "synthetic".to_owned(),
            enabled: Some(false),
            score: None,
        }]
    );
    assert_eq!(modifier_score(&disabled), None);
    assert_eq!(rule_ids(&disabled), rule_ids(&baseline));
    assert_ne!(disabled.compatibility_export().fingerprint(), fingerprint);

    let (loaded, rescored) = compiled(&[("hosted.chain", "score: 40")]);
    assert_eq!(loaded.get("hosted.chain").unwrap().score(), 40);
    assert_eq!(modifier_score(&rescored), Some(40));
    assert_ne!(rescored.compatibility_export().fingerprint(), fingerprint);

    // The same changes on a rule move the fingerprint the same way.
    let (_, rule_disabled) = compiled(&[("hosted.second", "enabled: false")]);
    let (_, rule_rescored) = compiled(&[("hosted.second", "score: 40")]);
    for set in [&rule_disabled, &rule_rescored] {
        assert_ne!(set.compatibility_export().fingerprint(), fingerprint);
    }
}
