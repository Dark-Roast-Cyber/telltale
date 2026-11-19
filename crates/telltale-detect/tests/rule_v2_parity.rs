//! Rule v2 parity: converted Rule v2 documents compile to the same compiled
//! form as their Rule v1 originals: the shipped core rules and chains and the
//! rule examples, against the pre-conversion Rule v1 files kept under
//! `fixtures/rule_v2/v1_baseline`, and hand-converted fixtures. Matchers are byte-identical and
//! in order, per-rule and per-set fingerprints are equal, and Detection v2
//! compiles both to the same semantic provenance.
//!
//! Temporary, like the Rule v1 reader: this test goes when the native content
//! is converted and Rule v1 is removed.

use telltale_detect::v2::{compile_rule_v1, native_profile_notices};
use telltale_rules::provenance::{rule_v1_modifier_fingerprint, rule_v1_rule_fingerprint};
use telltale_rules::{
    RuleSet, RuleV1CompatibilityExport, bundled_default_rule_yaml, compile_rule_sets,
    load_rule_set_from_documents, parse_rule_document,
};

const CONTAINER_V1: &str = include_str!("fixtures/rule_v2/container_host_access.v1.yaml");
const CONTAINER_V2: &str = include_str!("fixtures/rule_v2/container_host_access.yml");
const CORE_V2: &str = include_str!("fixtures/rule_v2/core_parity.yml");
/// The bundled core rules and chains before their conversion to Rule v2.
const CORE_V1_BASELINE: &str = include_str!("fixtures/rule_v2/v1_baseline/tool-call-regex.yaml");
/// The rule examples under `config/rules`, before and after conversion.
const EXAMPLES: &[(&str, &str)] = &[
    (
        include_str!("fixtures/rule_v2/v1_baseline/examples/example-ad-hoc-alerts.yaml"),
        include_str!("../../../config/rules/ad-hoc/example-ad-hoc-alerts.yaml"),
    ),
    (
        include_str!("fixtures/rule_v2/v1_baseline/examples/example-policy-violations.yaml"),
        include_str!("../../../config/rules/policy-violations/example-policy-violations.yaml"),
    ),
];

/// Bundled core content in `CORE_V2`, in bundled order.
const CORE_IDS: &[&str] = &[
    "secret.env.read",
    "network.download",
    "exfil.outbound_upload",
    "exfil.encoded_http",
    "chain.secret_then_network",
    "chain.download_then_execute",
    "chain.shell_encoded_payload",
];

fn load(documents: &[&str]) -> RuleV1CompatibilityExport {
    load_rule_set_from_documents(documents, None)
        .unwrap()
        .compatibility_export()
}

/// `text` with LF line endings, then with CRLF ones. A Windows checkout may
/// hold either, so every test runs on both.
fn line_endings(text: &str) -> [String; 2] {
    let lf = text.replace("\r\n", "\n");
    let crlf = lf.replace('\n', "\r\n");
    [lf, crlf]
}

/// The documents of a multi-document Rule v2 file, with LF line endings.
fn documents(file: &str) -> Vec<String> {
    file.replace("\r\n", "\n")
        .trim_end_matches('\n')
        .split("\n---\n")
        .map(str::to_owned)
        .collect()
}

/// The pre-conversion bundled core content.
fn core_v1(baseline: &str) -> RuleSet {
    parse_rule_document(baseline).unwrap()
}

/// The id of the one rule or chain `v2` holds.
fn only_id(v2: &RuleV1CompatibilityExport) -> String {
    assert_eq!(v2.rules().len() + v2.modifiers().len(), 1);
    v2.rules()
        .first()
        .map(|rule| rule.id.clone())
        .unwrap_or_else(|| v2.modifiers()[0].id.clone())
}

/// Each Rule v2 document alone compiles like its Rule v1 original alone, and
/// the documents hold every original once, in order.
fn assert_each_document_matches(v1: &RuleSet, v2_file: &str) {
    let ids = documents(v2_file)
        .into_iter()
        .map(|document| {
            let v2 = load(&[&document]);
            let id = only_id(&v2);
            assert_parity(&v1_subset(v1.clone(), &[&id]), &v2);
            id
        })
        .collect::<Vec<_>>();
    let original = v1
        .rules
        .iter()
        .map(|rule| rule.id.clone())
        .chain(v1.modifiers.iter().map(|modifier| modifier.id.clone()))
        .collect::<Vec<_>>();
    assert_eq!(ids, original);
}

/// `rule_set` with only the rules and modifiers named in `ids`, compiled.
fn v1_subset(mut rule_set: RuleSet, ids: &[&str]) -> RuleV1CompatibilityExport {
    rule_set
        .rules
        .retain(|rule| ids.contains(&rule.id.as_str()));
    rule_set
        .modifiers
        .retain(|modifier| ids.contains(&modifier.id.as_str()));
    assert_eq!(rule_set.rules.len() + rule_set.modifiers.len(), ids.len());
    compile_rule_sets(vec![rule_set], None)
        .unwrap()
        .compatibility_export()
}

fn assert_parity(v1: &RuleV1CompatibilityExport, v2: &RuleV1CompatibilityExport) {
    assert_eq!(v1.rules().len(), v2.rules().len());
    for (old, new) in v1.rules().iter().zip(v2.rules()) {
        let mut expected = old.clone();
        if old.title.is_none() {
            // Core rules have no title; Rule v2 requires one. The title is
            // catalog text, not part of any fingerprint.
            assert!(new.title.is_some(), "{}", new.id);
            expected.title = new.title.clone();
        }
        assert_eq!(new, &expected, "{}", old.id);
        assert_eq!(
            rule_v1_rule_fingerprint(new),
            rule_v1_rule_fingerprint(old),
            "{}",
            old.id
        );
    }
    assert_eq!(v2.modifiers(), v1.modifiers());
    for (old, new) in v1.modifiers().iter().zip(v2.modifiers()) {
        assert_eq!(
            rule_v1_modifier_fingerprint(new),
            rule_v1_modifier_fingerprint(old),
            "{}",
            old.id
        );
    }
    assert_eq!(v2.fingerprint(), v1.fingerprint());
    let (old_plan, new_plan) = (compile_rule_v1(v1).unwrap(), compile_rule_v1(v2).unwrap());
    assert_eq!(
        new_plan.semantic_provenance().identity(),
        old_plan.semantic_provenance().identity()
    );
    assert_eq!(native_profile_notices(v2), native_profile_notices(v1));
}

#[test]
fn container_rules_compile_like_rule_v1() {
    for (container_v1, container_v2) in line_endings(CONTAINER_V1)
        .into_iter()
        .zip(line_endings(CONTAINER_V2))
    {
        assert_container_parity(&container_v1, &container_v2);
    }
}

fn assert_container_parity(container_v1: &str, container_v2: &str) {
    let v1 = load(&[container_v1]);
    let v2 = load(&[container_v2]);
    assert_parity(&v1, &v2);

    // The walkthrough's compiled form: `(?i:P)` on command, then arguments.
    for (rule, bytes) in v2.rules().iter().zip([965, 469]) {
        let targets = rule
            .matchers
            .iter()
            .map(|matcher| matcher.target.as_str())
            .collect::<Vec<_>>();
        assert_eq!(targets, ["command", "arguments"]);
        assert_eq!(rule.matchers[0].regex, rule.matchers[1].regex);
        assert!(rule.matchers[0].regex.starts_with("(?i:"));
        assert_eq!(rule.matchers[0].regex.len(), bytes, "{}", rule.id);
    }

    let v1_set = parse_rule_document(container_v1).unwrap();
    for document in documents(container_v2) {
        let v2 = load(&[&document]);
        let id = v2.rules()[0].id.clone();
        assert_parity(&v1_subset(v1_set.clone(), &[&id]), &v2);
    }
}

#[test]
fn core_rules_and_chains_compile_like_bundled_rule_v1() {
    for (baseline, core_v2) in line_endings(CORE_V1_BASELINE)
        .into_iter()
        .zip(line_endings(CORE_V2))
    {
        let bundled = core_v1(&baseline);
        assert_parity(&v1_subset(bundled.clone(), CORE_IDS), &load(&[&core_v2]));

        let documents = documents(&core_v2);
        assert_eq!(documents.len(), CORE_IDS.len());
        for document in documents {
            let v2 = load(&[&document]);
            let id = v2
                .rules()
                .first()
                .map(|rule| rule.id.clone())
                .unwrap_or_else(|| v2.modifiers()[0].id.clone());
            assert_parity(&v1_subset(bundled.clone(), &[&id]), &v2);
        }
    }
}

#[test]
fn converted_core_rules_keep_their_native_action_profiles() {
    for (newline, core_v2) in ["\n", "\r\n"].into_iter().zip(line_endings(CORE_V2)) {
        assert_native_profiles_kept(newline, &core_v2);
    }
}

/// `core_v2` is the converted core content with `newline` line endings; its
/// edited documents load with the same line endings.
fn assert_native_profiles_kept(newline: &str, core_v2: &str) {
    let converted = load(&[core_v2]);
    assert!(native_profile_notices(&converted).is_empty());

    // Selections written in another order compile to matchers in another
    // order. The fingerprint and the native profile compare matchers sorted,
    // so neither changes.
    let download = documents(core_v2)
        .into_iter()
        .find(|document| document.contains("name: network.download"))
        .unwrap();
    let lines = download.lines().collect::<Vec<_>>();
    let block = |name: &str| {
        let start = lines
            .iter()
            .position(|line| *line == format!("    selection_{name}:"))
            .unwrap();
        lines[start..start + 4].join("\n")
    };
    let in_order = [block("arguments"), block("command"), block("url")].join("\n");
    let reordered_blocks = [block("url"), block("command"), block("arguments")].join("\n");
    let reordered = download.replacen(&in_order, &reordered_blocks, 1);
    assert_ne!(reordered, download);
    let reordered = load(&[&reordered.replace('\n', newline)]);
    let bundled = v1_subset(core_v1(CORE_V1_BASELINE), &["network.download"]);
    assert_ne!(reordered.rules()[0].matchers, bundled.rules()[0].matchers);
    assert_eq!(reordered.fingerprint(), bundled.fingerprint());
    assert!(native_profile_notices(&reordered).is_empty());

    // A changed matcher keeps the rule but not the native profile.
    let changed = download.replacen(
        "    filter_url:\n        tool.url|re|i|segment:",
        "    filter_url:\n        tool.url|re|segment:",
        1,
    );
    assert_ne!(changed, download);
    let rules = load_rule_set_from_documents(&[&changed.replace('\n', newline)], None).unwrap();
    assert_eq!(rules.notices().len(), 1, "the filter's case differs");
    let notices = native_profile_notices(&rules.compatibility_export());
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].rule_id, "network.download");
    assert!(
        notices[0]
            .to_string()
            .contains("native action profile not applied")
    );
}

#[test]
fn the_shipped_core_rules_and_chains_compile_like_their_rule_v1_originals() {
    for (baseline, shipped) in line_endings(CORE_V1_BASELINE)
        .into_iter()
        .zip(line_endings(bundled_default_rule_yaml()))
    {
        assert_shipped_core_parity(&baseline, &shipped);
    }
}

fn assert_shipped_core_parity(baseline: &str, shipped: &str) {
    let v1 = load(&[baseline]);
    let v2 = load(&[shipped]);
    assert_eq!((v2.rules().len(), v2.modifiers().len()), (25, 9));
    // Every core rule gains a title; the two that had one keep it.
    for (old, new) in v1.rules().iter().zip(v2.rules()) {
        assert!(new.title.is_some(), "{}", new.id);
        if old.title.is_some() {
            assert_eq!(new.title, old.title, "{}", old.id);
        }
    }
    assert_parity(&v1, &v2);
    assert!(native_profile_notices(&v1).is_empty());
    assert!(native_profile_notices(&v2).is_empty());
    assert!(
        load_rule_set_from_documents(&[shipped], None)
            .unwrap()
            .notices()
            .is_empty()
    );
    assert_each_document_matches(&core_v1(baseline), shipped);
}

#[test]
fn the_converted_rule_examples_compile_like_their_rule_v1_originals() {
    for (v1_file, v2_file) in EXAMPLES {
        for (v1_file, v2_file) in line_endings(v1_file).into_iter().zip(line_endings(v2_file)) {
            let (v1, v2) = (load(&[&v1_file]), load(&[&v2_file]));
            assert_eq!(v2.rules().len(), 1);
            assert_parity(&v1, &v2);
            assert!(native_profile_notices(&v2).is_empty());
            assert_each_document_matches(&parse_rule_document(&v1_file).unwrap(), &v2_file);
        }
    }
}
