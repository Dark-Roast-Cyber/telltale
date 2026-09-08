//! Content identity for effective Rule v1 compatibility semantics.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    RuleV1CompatibilityExport, RuleV1CompatibilityMatcher, RuleV1CompatibilityModifier,
    RuleV1CompatibilityRule,
};

pub const RULE_V1_FINGERPRINT_DOMAIN: &[u8] = b"telltale:producer-rule-v1-fingerprint:v1\0";

/// Fingerprint the already compiled compatibility export, never source YAML.
pub fn rule_v1_fingerprint(export: &RuleV1CompatibilityExport) -> String {
    let canonical = canonical_export(export);
    let mut hasher = Sha256::new();
    hasher.update(RULE_V1_FINGERPRINT_DOMAIN);
    hasher.update(canonical);
    format!("sha256:{:x}", hasher.finalize())
}

fn canonical_export(export: &RuleV1CompatibilityExport) -> Vec<u8> {
    let payload = CanonicalRuleExport {
        rules: export.rules.iter().map(canonical_rule).collect(),
        modifiers: export.modifiers.iter().map(canonical_modifier).collect(),
    };
    serde_json::to_vec(&payload).expect("rule provenance payload is serializable")
}

fn canonical_rule(rule: &RuleV1CompatibilityRule) -> CanonicalRule<'_> {
    let mut matchers = rule
        .matchers
        .iter()
        .map(canonical_matcher)
        .collect::<Vec<_>>();
    matchers.sort_by(|left, right| {
        left.target
            .cmp(right.target)
            .then_with(|| left.regex.cmp(right.regex))
    });
    matchers.dedup_by(|left, right| left.target == right.target && left.regex == right.regex);
    CanonicalRule {
        id: &rule.id,
        category: &rule.category,
        detection_class: &rule.detection_class,
        signal_type: &rule.signal_type,
        analytic_intent: &rule.analytic_intent,
        atlas_tags: sorted_unique(&rule.atlas_tags),
        severity: &rule.severity,
        score: rule.score,
        tags: sorted_unique(&rule.tags),
        explanation: &rule.explanation,
        matchers,
    }
}

fn canonical_matcher(matcher: &RuleV1CompatibilityMatcher) -> CanonicalMatcher<'_> {
    CanonicalMatcher {
        target: &matcher.target,
        regex: &matcher.regex,
    }
}

fn canonical_modifier(modifier: &RuleV1CompatibilityModifier) -> CanonicalModifier<'_> {
    CanonicalModifier {
        id: &modifier.id,
        score: modifier.score,
        detection_class: &modifier.detection_class,
        signal_type: &modifier.signal_type,
        analytic_intent: &modifier.analytic_intent,
        atlas_tags: sorted_unique(&modifier.atlas_tags),
        when_all_categories: sorted_unique(&modifier.when_all_categories),
        when_all_rule_ids: sorted_unique(&modifier.when_all_rule_ids),
        explanation: &modifier.explanation,
    }
}

fn sorted_unique(values: &[String]) -> Vec<&str> {
    let mut values = values.iter().map(String::as_str).collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

#[derive(Serialize)]
struct CanonicalRuleExport<'a> {
    rules: Vec<CanonicalRule<'a>>,
    modifiers: Vec<CanonicalModifier<'a>>,
}

#[derive(Serialize)]
struct CanonicalRule<'a> {
    id: &'a str,
    category: &'a str,
    detection_class: &'a str,
    signal_type: &'a str,
    analytic_intent: &'a str,
    atlas_tags: Vec<&'a str>,
    severity: &'a str,
    score: u64,
    tags: Vec<&'a str>,
    explanation: &'a str,
    matchers: Vec<CanonicalMatcher<'a>>,
}

#[derive(Serialize)]
struct CanonicalMatcher<'a> {
    target: &'a str,
    regex: &'a str,
}

#[derive(Serialize)]
struct CanonicalModifier<'a> {
    id: &'a str,
    score: u64,
    detection_class: &'a str,
    signal_type: &'a str,
    analytic_intent: &'a str,
    atlas_tags: Vec<&'a str>,
    when_all_categories: Vec<&'a str>,
    when_all_rule_ids: Vec<&'a str>,
    explanation: &'a str,
}

#[cfg(test)]
mod tests {
    use super::rule_v1_fingerprint;
    use crate::{
        DetectionDefinition, ModifierDefinition, RuleDefaults, RuleDefinition, RulePolicy, RuleSet,
        load_rule_set_from_documents,
    };
    use std::collections::BTreeMap;

    fn rule() -> RuleDefinition {
        RuleDefinition {
            id: "rule.synthetic".to_string(),
            title: Some("Synthetic title".to_string()),
            description: Some("Synthetic description".to_string()),
            status: None,
            author: None,
            references: Vec::new(),
            falsepositives: vec!["z".to_string(), "a".to_string()],
            level: None,
            category: "execution".to_string(),
            detection_class: "security_detection".to_string(),
            signal_type: "atomic".to_string(),
            analytic_intent: "alert".to_string(),
            atlas_tags: vec!["atlas:Z".to_string(), "atlas:A".to_string()],
            severity: "high".to_string(),
            score: 60,
            targets: vec!["tool_result".to_string(), "command".to_string()],
            regex: Some("synthetic".to_string()),
            detection: None,
            tags: vec!["z".to_string(), "a".to_string()],
            explanation: "Synthetic explanation".to_string(),
            enabled: true,
        }
    }

    fn compiled(
        rule: RuleDefinition,
        modifiers: Vec<ModifierDefinition>,
    ) -> crate::CompiledRuleSet {
        RuleSet {
            version: 1,
            description: "synthetic source-only text".to_string(),
            defaults: RuleDefaults {
                case_insensitive: false,
                enabled: true,
            },
            rules: vec![rule],
            modifiers,
        }
        .compile(None)
        .expect("compiled rules")
    }

    #[test]
    fn unordered_rule_metadata_and_matchers_are_canonical() {
        let mut first = rule();
        first.targets = vec!["command".to_string(), "tool_result".to_string()];
        first.atlas_tags.reverse();
        first.tags.reverse();
        let first = rule_v1_fingerprint(&compiled(first, Vec::new()).compatibility_export());

        let second = rule_v1_fingerprint(&compiled(rule(), Vec::new()).compatibility_export());
        assert_eq!(first, second);
    }

    #[test]
    fn source_formatting_and_line_endings_do_not_affect_identity() {
        let first = "version: 1\ndescription: source-a\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: rule.synthetic\n    title: Synthetic title\n    description: Synthetic description\n    category: execution\n    severity: high\n    score: 60\n    targets: [command, tool_result]\n    regex: synthetic\n    tags: [z, a]\n    explanation: Synthetic explanation\nmodifiers: []\n";
        let second = first
            .replace("source-a", "source-b")
            .replace("[command, tool_result]", "[tool_result, command]")
            .replace("[z, a]", "[a, z]")
            .replace('\n', "\r\n");
        let first = load_rule_set_from_documents(&[first], None)
            .expect("first rules")
            .compatibility_export();
        let second = load_rule_set_from_documents(&[second.as_str()], None)
            .expect("second rules")
            .compatibility_export();
        assert_eq!(rule_v1_fingerprint(&first), rule_v1_fingerprint(&second));
    }

    #[test]
    fn descriptive_rule_metadata_does_not_change_compiled_fingerprint() {
        let first = rule_v1_fingerprint(&compiled(rule(), Vec::new()).compatibility_export());
        let mut changed = rule();
        changed.title = Some("different title".to_string());
        changed.description = Some("different description".to_string());
        changed.falsepositives = vec!["different false-positive guidance".to_string()];
        let second = rule_v1_fingerprint(&compiled(changed, Vec::new()).compatibility_export());
        assert_eq!(first, second);

        let base_modifier = ModifierDefinition {
            id: "chain.synthetic".to_string(),
            score: 7,
            detection_class: "security_detection".to_string(),
            signal_type: "chain".to_string(),
            analytic_intent: "alert".to_string(),
            atlas_tags: vec!["atlas:A".to_string()],
            when_all_categories: vec!["execution".to_string()],
            when_all_rule_ids: vec!["rule.synthetic".to_string()],
            falsepositives: vec!["base guidance".to_string()],
            explanation: "modifier explanation".to_string(),
            enabled: true,
        };
        let mut changed_modifier = base_modifier.clone();
        changed_modifier.falsepositives = vec!["different guidance".to_string()];
        let first =
            rule_v1_fingerprint(&compiled(rule(), vec![base_modifier]).compatibility_export());
        let second =
            rule_v1_fingerprint(&compiled(rule(), vec![changed_modifier]).compatibility_export());
        assert_eq!(first, second);
    }

    #[test]
    fn every_fingerprinted_rule_field_changes_identity() {
        let base = compiled(
            rule(),
            vec![ModifierDefinition {
                id: "chain.synthetic".to_string(),
                score: 7,
                detection_class: "security_detection".to_string(),
                signal_type: "chain".to_string(),
                analytic_intent: "alert".to_string(),
                atlas_tags: vec!["atlas:A".to_string()],
                when_all_categories: vec!["execution".to_string()],
                when_all_rule_ids: vec!["rule.synthetic".to_string()],
                falsepositives: vec!["none".to_string()],
                explanation: "modifier explanation".to_string(),
                enabled: true,
            }],
        );
        let base = rule_v1_fingerprint(&base.compatibility_export());
        for mutate in [
            |rule: &mut RuleDefinition| rule.id = "rule.other".to_string(),
            |rule: &mut RuleDefinition| rule.category = "other".to_string(),
            |rule: &mut RuleDefinition| rule.detection_class = "policy_violation".to_string(),
            |rule: &mut RuleDefinition| rule.signal_type = "chain".to_string(),
            |rule: &mut RuleDefinition| rule.analytic_intent = "audit".to_string(),
            |rule: &mut RuleDefinition| rule.atlas_tags.push("atlas:B".to_string()),
            |rule: &mut RuleDefinition| rule.severity = "critical".to_string(),
            |rule: &mut RuleDefinition| rule.score = 80,
            |rule: &mut RuleDefinition| rule.tags.push("other".to_string()),
            |rule: &mut RuleDefinition| rule.explanation = "other".to_string(),
            |rule: &mut RuleDefinition| rule.targets = vec!["url".to_string()],
            |rule: &mut RuleDefinition| rule.regex = Some("other".to_string()),
        ] {
            let mut changed = rule();
            mutate(&mut changed);
            let fingerprint =
                rule_v1_fingerprint(&compiled(changed, Vec::new()).compatibility_export());
            assert_ne!(base, fingerprint);
        }

        let modifier = ModifierDefinition {
            id: "chain.synthetic".to_string(),
            score: 8,
            detection_class: "security_detection".to_string(),
            signal_type: "chain".to_string(),
            analytic_intent: "alert".to_string(),
            atlas_tags: vec!["atlas:A".to_string()],
            when_all_categories: vec!["execution".to_string()],
            when_all_rule_ids: vec!["rule.synthetic".to_string()],
            falsepositives: vec!["none".to_string()],
            explanation: "modifier explanation".to_string(),
            enabled: true,
        };
        let fingerprint =
            rule_v1_fingerprint(&compiled(rule(), vec![modifier]).compatibility_export());
        assert_ne!(base, fingerprint);
    }

    #[test]
    fn duplicate_matchers_and_rule_order_are_canonicalized_as_specified() {
        let mut first_rule = rule();
        first_rule.targets = vec!["command".to_string(), "command".to_string()];
        let mut unique_rule = first_rule.clone();
        unique_rule.targets = vec!["command".to_string()];
        let mut second_rule = rule();
        second_rule.id = "rule.second".to_string();
        second_rule.targets = vec!["tool_result".to_string()];
        let first = RuleSet {
            version: 1,
            description: "source".to_string(),
            defaults: RuleDefaults {
                case_insensitive: false,
                enabled: true,
            },
            rules: vec![first_rule.clone(), second_rule.clone()],
            modifiers: Vec::new(),
        }
        .compile(None)
        .expect("compiled")
        .compatibility_export();

        let mut reordered = second_rule.clone();
        reordered.targets = vec!["tool_result".to_string()];
        let second = RuleSet {
            version: 1,
            description: "source".to_string(),
            defaults: RuleDefaults {
                case_insensitive: false,
                enabled: true,
            },
            rules: vec![reordered, first_rule],
            modifiers: Vec::new(),
        }
        .compile(None)
        .expect("compiled")
        .compatibility_export();

        assert_ne!(rule_v1_fingerprint(&first), rule_v1_fingerprint(&second));
        let unique = RuleSet {
            version: 1,
            description: "source".to_string(),
            defaults: RuleDefaults {
                case_insensitive: false,
                enabled: true,
            },
            rules: vec![unique_rule, second_rule],
            modifiers: Vec::new(),
        }
        .compile(None)
        .expect("compiled")
        .compatibility_export();
        assert_eq!(rule_v1_fingerprint(&first), rule_v1_fingerprint(&unique));
    }

    #[test]
    fn every_fingerprinted_modifier_field_changes_identity() {
        let modifier = || ModifierDefinition {
            id: "chain.synthetic".to_string(),
            score: 7,
            detection_class: "security_detection".to_string(),
            signal_type: "chain".to_string(),
            analytic_intent: "alert".to_string(),
            atlas_tags: vec!["atlas:A".to_string()],
            when_all_categories: vec!["execution".to_string()],
            when_all_rule_ids: vec!["rule.synthetic".to_string()],
            falsepositives: vec!["none".to_string()],
            explanation: "modifier explanation".to_string(),
            enabled: true,
        };
        let fingerprint = |modifier: ModifierDefinition| {
            rule_v1_fingerprint(&compiled(rule(), vec![modifier]).compatibility_export())
        };
        let base = fingerprint(modifier());
        for mutate in [
            |value: &mut ModifierDefinition| value.id = "chain.other".to_string(),
            |value: &mut ModifierDefinition| value.score = 8,
            |value: &mut ModifierDefinition| value.detection_class = "policy_violation".to_string(),
            |value: &mut ModifierDefinition| value.signal_type = "correlation".to_string(),
            |value: &mut ModifierDefinition| value.analytic_intent = "audit".to_string(),
            |value: &mut ModifierDefinition| value.atlas_tags.push("atlas:B".to_string()),
            |value: &mut ModifierDefinition| value.when_all_categories.push("other".to_string()),
            |value: &mut ModifierDefinition| value.when_all_rule_ids.push("rule.other".to_string()),
            |value: &mut ModifierDefinition| value.explanation = "other".to_string(),
        ] {
            let mut changed = modifier();
            mutate(&mut changed);
            assert_ne!(base, fingerprint(changed));
        }
    }

    #[test]
    fn policy_names_are_not_part_of_ruleset_identity() {
        let policy_a = RulePolicy {
            name: Some("policy-a".to_string()),
            ..RulePolicy::default()
        };
        let policy_b = RulePolicy {
            name: Some("policy-b".to_string()),
            ..RulePolicy::default()
        };
        let mut selection = BTreeMap::new();
        selection.insert("command".to_string(), "synthetic".to_string());
        let mut selected_rule = rule();
        selected_rule.targets.clear();
        selected_rule.regex = None;
        selected_rule.detection = Some(DetectionDefinition {
            selection,
            condition: "selection".to_string(),
        });
        let first = RuleSet {
            version: 1,
            description: "test".to_string(),
            defaults: RuleDefaults {
                case_insensitive: false,
                enabled: true,
            },
            rules: vec![selected_rule.clone()],
            modifiers: Vec::new(),
        }
        .compile(Some(&policy_a))
        .expect("compiled policy a");
        let second = RuleSet {
            version: 1,
            description: "test".to_string(),
            defaults: RuleDefaults {
                case_insensitive: false,
                enabled: true,
            },
            rules: vec![selected_rule],
            modifiers: Vec::new(),
        }
        .compile(Some(&policy_b))
        .expect("compiled policy b");
        assert_eq!(first.policy_name(), Some("policy-a"));
        assert_eq!(second.policy_name(), Some("policy-b"));
        assert_eq!(
            rule_v1_fingerprint(&first.compatibility_export()),
            rule_v1_fingerprint(&second.compatibility_export())
        );
    }
}
