//! Rule v2 parity of the host self-protection rules: each bundled rules file,
//! converted to Rule v2, compiles exactly as its pre-conversion Rule v1 file
//! (kept in `tests/fixtures/rule_v2/v1_baseline/hooks`), both expanded the
//! same way. The generated rules have their own parity test beside the
//! generator (`hooks::engine`).
//!
//! Temporary, like the Rule v1 reader: it goes when Rule v1 is removed.

use telltale_core::hooks::engine::{expand_rule_template, host_rule_documents};
use telltale_detect::v2::{compile_rule_v1, native_profile_notices};
use telltale_rules::provenance::rule_v1_rule_fingerprint;
use telltale_rules::{
    RuleV1CompatibilityExport, compile_rule_sets, load_rule_set_from_documents, parse_rule_document,
};

const V1_BASELINE: &[(&str, &str)] = &[
    (
        "telltale-hooks-self-protection.yaml",
        include_str!(
            "../../../../tests/fixtures/rule_v2/v1_baseline/hooks/telltale-hooks-self-protection.yaml"
        ),
    ),
    (
        "codex-cli-self-protection.yaml",
        include_str!(
            "../../../../tests/fixtures/rule_v2/v1_baseline/hooks/codex-cli-self-protection.yaml"
        ),
    ),
    (
        "copilot-cli-self-protection.yaml",
        include_str!(
            "../../../../tests/fixtures/rule_v2/v1_baseline/hooks/copilot-cli-self-protection.yaml"
        ),
    ),
];

fn export(document: &str) -> RuleV1CompatibilityExport {
    load_rule_set_from_documents(&[document], None)
        .unwrap()
        .compatibility_export()
}

fn assert_parity(v1: &RuleV1CompatibilityExport, v2: &RuleV1CompatibilityExport, label: &str) {
    assert!(!v1.rules().is_empty(), "{label}");
    // Host rules had titles in Rule v1, so the whole compiled rule is equal.
    assert_eq!(v2.rules(), v1.rules(), "{label}");
    assert!(
        v2.modifiers().is_empty() && v1.modifiers().is_empty(),
        "{label}"
    );
    for (old, new) in v1.rules().iter().zip(v2.rules()) {
        assert_eq!(
            rule_v1_rule_fingerprint(new),
            rule_v1_rule_fingerprint(old),
            "{}",
            old.id
        );
    }
    assert_eq!(v2.fingerprint(), v1.fingerprint(), "{label}");
    let (old_plan, new_plan) = (compile_rule_v1(v1).unwrap(), compile_rule_v1(v2).unwrap());
    assert_eq!(
        new_plan.semantic_provenance().identity(),
        old_plan.semantic_provenance().identity(),
        "{label}"
    );
    assert!(native_profile_notices(v2).is_empty(), "{label}");
}

#[test]
fn host_rule_files_compile_like_their_rule_v1_originals() {
    let documents = host_rule_documents();
    assert_eq!(documents.len(), V1_BASELINE.len());
    for (name, template) in V1_BASELINE {
        let (_, converted) = documents
            .iter()
            .find(|(document, _)| document == name)
            .unwrap_or_else(|| panic!("{name} is not a host rule document"));
        let original = expand_rule_template(template);
        let loaded = load_rule_set_from_documents(&[converted], None).unwrap();
        assert!(loaded.notices().is_empty(), "{name}");
        assert_parity(&export(&original), &loaded.compatibility_export(), name);

        // Each document alone compiles like its original rule alone, and the
        // documents hold every original once, in order.
        let v1_set = parse_rule_document(&original).unwrap();
        let converted = converted.replace("\r\n", "\n");
        let mut ids = Vec::new();
        for document in converted.trim_end_matches('\n').split("\n---\n") {
            let v2 = export(document);
            assert_eq!(v2.rules().len(), 1, "{name}");
            let id = v2.rules()[0].id.clone();
            let mut v1 = v1_set.clone();
            v1.rules.retain(|rule| rule.id == id);
            let v1 = compile_rule_sets(vec![v1], None)
                .unwrap()
                .compatibility_export();
            assert_parity(&v1, &v2, &id);
            ids.push(id);
        }
        let original_ids = v1_set
            .rules
            .iter()
            .map(|rule| rule.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(ids, original_ids, "{name}");
    }
}
