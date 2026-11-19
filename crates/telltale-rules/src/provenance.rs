//! Content identity of the compiled rule form ([`RuleV1CompatibilityExport`]).
//!
//! The `rule_v1_*` names and the fingerprint domain name the compiled detector
//! version 1, not an authoring format; they stay so that identities computed
//! for the same compiled content never change.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    DefinitionMetadata, MatchScope, RuleV1CompatibilityExport, RuleV1CompatibilityMatcher,
    RuleV1CompatibilityModifier, RuleV1CompatibilityRule,
};

pub const RULE_V1_FINGERPRINT_DOMAIN: &[u8] = b"telltale:producer-rule-v1-fingerprint:v2\0";

/// Fingerprint the already compiled compatibility export, never source YAML.
pub fn rule_v1_fingerprint(export: &RuleV1CompatibilityExport) -> String {
    hash_canonical(&CanonicalRuleExport {
        rules: export.rules.iter().map(canonical_rule).collect(),
        modifiers: export.modifiers.iter().map(canonical_modifier).collect(),
    })
}

fn hash_canonical(payload: &CanonicalRuleExport<'_>) -> String {
    let canonical = serde_json::to_vec(payload).expect("rule provenance payload is serializable");
    let mut hasher = Sha256::new();
    hasher.update(RULE_V1_FINGERPRINT_DOMAIN);
    hasher.update(canonical);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

impl RuleV1CompatibilityRule {
    /// The rule's matchers in fingerprint order: sorted by target, pattern,
    /// exclusion and scope, duplicates removed. Two rules whose lists are equal
    /// match the same text; their declared order only decides which matcher
    /// reports a field's evidence span.
    pub fn canonical_matchers(&self) -> Vec<&RuleV1CompatibilityMatcher> {
        fn key(
            matcher: &RuleV1CompatibilityMatcher,
        ) -> (&str, &str, Option<&str>, Option<&'static str>) {
            (
                matcher.target.as_str(),
                matcher.regex.as_str(),
                matcher.exclusion_regex.as_deref(),
                canonical_scope(matcher.scope),
            )
        }
        let mut matchers = self.matchers.iter().collect::<Vec<_>>();
        matchers.sort_by(|left, right| key(left).cmp(&key(right)));
        matchers.dedup_by(|left, right| key(left) == key(right));
        matchers
    }
}

/// Fingerprint the one-rule export of `rule`: its behaviour revision, which
/// rule order elsewhere in a set does not change.
pub fn rule_v1_rule_fingerprint(rule: &RuleV1CompatibilityRule) -> String {
    hash_canonical(&CanonicalRuleExport {
        rules: vec![canonical_rule(rule)],
        modifiers: Vec::new(),
    })
}

/// Fingerprint the one-modifier export of `modifier`.
pub fn rule_v1_modifier_fingerprint(modifier: &RuleV1CompatibilityModifier) -> String {
    hash_canonical(&CanonicalRuleExport {
        rules: Vec::new(),
        modifiers: vec![canonical_modifier(modifier)],
    })
}

fn canonical_rule(rule: &RuleV1CompatibilityRule) -> CanonicalRule<'_> {
    let matchers = rule
        .canonical_matchers()
        .into_iter()
        .map(canonical_matcher)
        .collect::<Vec<_>>();
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
        exclusion_regex: matcher.exclusion_regex.as_deref(),
        scope: canonical_scope(matcher.scope),
    }
}

// Absent for the default field scope, so field-scoped rules keep their
// fingerprints; this is also the scope's sort key.
fn canonical_scope(scope: MatchScope) -> Option<&'static str> {
    (scope != MatchScope::Field).then(|| scope.as_str())
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
        link: modifier.link.map(|link| CanonicalLink {
            calls: link.calls,
            order: link.order.as_str(),
            minutes: link.minutes,
        }),
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
    exclusion_regex: Option<&'a str>,
    // Absent for the default field scope, so field-scoped rules keep their
    // fingerprints.
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'static str>,
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
    // Absent for unlinked modifiers, so their fingerprints do not change.
    #[serde(skip_serializing_if = "Option::is_none")]
    link: Option<CanonicalLink>,
    explanation: &'a str,
}

#[derive(Serialize)]
struct CanonicalLink {
    calls: u32,
    order: &'static str,
    minutes: Option<u32>,
}

/// Domain of [`metadata_revision`].
pub const RULE_METADATA_REVISION_DOMAIN: &[u8] = b"telltale:rule-metadata-revision:v1\0";

/// The metadata revision of one definition: SHA-256, domain-separated, over
/// canonical JSON of the descriptive metadata the behaviour fingerprint leaves
/// out. Tags are a set (sorted, duplicates removed) without the `atlas.*`
/// tags, which compile into the fingerprinted ATLAS tags; lists that are read
/// in order (references, related rules, false positives) keep it.
pub fn metadata_revision(metadata: &DefinitionMetadata) -> String {
    let tags = metadata
        .tags
        .iter()
        .filter(|tag| !tag.starts_with("atlas."))
        .cloned()
        .collect::<Vec<_>>();
    let payload = CanonicalMetadata {
        title: metadata.title.as_deref(),
        status: metadata.status.as_deref(),
        description: metadata.description.as_deref(),
        references: metadata.references.iter().map(String::as_str).collect(),
        author: metadata.author.as_deref(),
        license: metadata.license.as_deref(),
        date: metadata.date.as_deref(),
        modified: metadata.modified.as_deref(),
        related: metadata
            .related
            .iter()
            .map(|related| (related.id.as_str(), related.kind.as_str()))
            .collect(),
        logsource: metadata.logsource.as_ref().map(|logsource| {
            (
                logsource.product.as_str(),
                logsource.category.as_str(),
                logsource.service.as_deref(),
            )
        }),
        tags: sorted_unique(&tags),
        falsepositives: metadata.falsepositives.iter().map(String::as_str).collect(),
    };
    let canonical = serde_json::to_vec(&payload).expect("rule metadata payload is serializable");
    let mut hasher = Sha256::new();
    hasher.update(RULE_METADATA_REVISION_DOMAIN);
    hasher.update(canonical);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[derive(Serialize)]
struct CanonicalMetadata<'a> {
    title: Option<&'a str>,
    status: Option<&'a str>,
    description: Option<&'a str>,
    references: Vec<&'a str>,
    author: Option<&'a str>,
    license: Option<&'a str>,
    date: Option<&'a str>,
    modified: Option<&'a str>,
    related: Vec<(&'a str, &'a str)>,
    logsource: Option<(&'a str, &'a str, Option<&'a str>)>,
    tags: Vec<&'a str>,
    falsepositives: Vec<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::rule_v1_fingerprint;
    use crate::test_rules::{file, uuid};
    use crate::{RulePolicy, load_rule_set_from_documents};

    const RULE: &str = "title: Synthetic title
id: UUID
name: rule.synthetic
taxonomy: telltale
description: Synthetic description
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.result|re: &pattern synthetic
        - tool.command|re: *pattern
    condition: selection
falsepositives: [z, a]
level: high
tags: [atlas.z, atlas.a]
telltale:
    category: execution
    score: 60
    explanation: Synthetic explanation
    tags: [z, a]
";

    const CHAIN: &str = "title: Synthetic chain
id: UUID
name: chain.synthetic
taxonomy: telltale
correlation:
    type: telltale_chain
    rules: [rule.synthetic]
    within_calls: 3
falsepositives: [none]
tags: [atlas.a]
telltale:
    score: 7
    explanation: modifier explanation
";

    fn rule() -> String {
        RULE.replace("UUID", &uuid("rule.synthetic"))
    }

    fn modifier() -> String {
        CHAIN.replace("UUID", &uuid("chain.synthetic"))
    }

    fn fingerprint(documents: &[String]) -> String {
        rule_v1_fingerprint(
            &load_rule_set_from_documents(&[file(documents).as_str()], None)
                .expect("compiled rules")
                .compatibility_export(),
        )
    }

    #[test]
    fn unordered_rule_metadata_and_matchers_are_canonical() {
        let reordered = rule()
            .replace(
                "        - tool.result|re: &pattern synthetic\n        - tool.command|re: *pattern",
                "        - tool.command|re: &pattern synthetic\n        - tool.result|re: *pattern",
            )
            .replace("[atlas.z, atlas.a]", "[atlas.a, atlas.z]")
            .replace("tags: [z, a]", "tags: [a, z]");
        assert_ne!(reordered, rule());
        assert_eq!(fingerprint(&[reordered]), fingerprint(&[rule()]));
    }

    #[test]
    fn source_formatting_and_line_endings_do_not_affect_identity() {
        let second = format!("# A comment the first source does not have.\n{}", rule())
            .replace("tags: [z, a]", "tags:\n        - a\n        - z")
            .replace('\n', "\r\n");
        assert_eq!(fingerprint(&[rule()]), fingerprint(&[second]));
    }

    #[test]
    fn descriptive_rule_metadata_does_not_change_compiled_fingerprint() {
        let first = fingerprint(&[rule()]);
        let changed = rule()
            .replace("title: Synthetic title", "title: different title")
            .replace(
                "description: Synthetic description",
                "description: different description\nstatus: test\nauthor: Someone",
            )
            .replace(
                "falsepositives: [z, a]",
                "falsepositives: [different false-positive guidance]",
            )
            .replace(
                "id: ",
                "references:\n    - https://example.invalid/rule\nid: ",
            )
            .replace(
                "tags: [atlas.z, atlas.a]",
                "tags: [atlas.z, atlas.a, attack.t1105]",
            );
        assert_eq!(first, fingerprint(&[changed]));

        let first = fingerprint(&[rule(), modifier()]);
        let changed = modifier()
            .replace(
                "falsepositives: [none]",
                "falsepositives: [different guidance]",
            )
            .replace("title: Synthetic chain", "title: Different chain");
        assert_eq!(first, fingerprint(&[rule(), changed]));
    }

    #[test]
    fn every_fingerprinted_rule_field_changes_identity() {
        let base = fingerprint(&[rule(), modifier()]);
        for (from, to) in [
            ("name: rule.synthetic", "name: rule.other"),
            ("category: execution", "category: other"),
            (
                "    tags: [z, a]",
                "    tags: [z, a]\n    detection_class: policy_violation",
            ),
            (
                "    tags: [z, a]",
                "    tags: [z, a]\n    signal_type: chain",
            ),
            (
                "    tags: [z, a]",
                "    tags: [z, a]\n    analytic_intent: audit",
            ),
            ("[atlas.z, atlas.a]", "[atlas.z, atlas.a, atlas.b]"),
            ("level: high", "level: critical"),
            ("score: 60", "score: 80"),
            ("tags: [z, a]", "tags: [z, a, other]"),
            ("explanation: Synthetic explanation", "explanation: other"),
            ("tool.result|re", "tool.url|re"),
            ("&pattern synthetic", "&pattern other"),
            (
                "    condition: selection",
                "    selection_url:\n        tool.url|re: benign\n    condition: 1 of selection*",
            ),
        ] {
            let changed = rule().replacen(from, to, 1);
            assert_ne!(changed, rule(), "{from}");
            assert_ne!(base, fingerprint(&[changed, modifier()]), "{from} -> {to}");
        }
        let changed = modifier().replace("score: 7", "score: 8");
        assert_ne!(base, fingerprint(&[rule(), changed]));
    }

    #[test]
    fn exclusion_order_and_source_formatting_do_not_affect_v2_identity() {
        let detection = "    selection_command:
        tool.command|re: synthetic
    filter_command:
        tool.command|re: benign-command
    selection_tool_result:
        tool.result|re: synthetic
    filter_tool_result:
        tool.result|re: benign-result
    condition: (selection_command and not filter_command) or (selection_tool_result and not filter_tool_result)
";
        let first = rule().replace(
            "    selection:\n        - tool.result|re: &pattern synthetic\n        - tool.command|re: *pattern\n    condition: selection\n",
            detection,
        );
        let second = first
            .replace(
                "    filter_command:\n        tool.command|re: benign-command\n    selection_tool_result:\n        tool.result|re: synthetic\n    filter_tool_result:\n        tool.result|re: benign-result\n",
                "    filter_tool_result:\n        tool.result|re: benign-result\n    selection_tool_result:\n        tool.result|re: synthetic\n    filter_command:\n        tool.command|re: benign-command\n",
            )
            .replace("tags: [z, a]", "tags: [a, z]")
            .replace('\n', "\r\n");
        assert_ne!(first.replace('\n', "\r\n"), second);
        assert_eq!(fingerprint(&[first]), fingerprint(&[second]));
    }

    #[test]
    fn changing_only_exclusion_regex_changes_v2_identity() {
        let document = |exclusion: &str| {
            rule().replace(
                "    selection:\n        - tool.result|re: &pattern synthetic\n        - tool.command|re: *pattern\n    condition: selection\n",
                &format!(
                    "    selection_command:\n        tool.command|re: synthetic\n    filter_command:\n        tool.command|re: {exclusion}\n    condition: selection_command and not filter_command\n"
                ),
            )
        };
        assert_ne!(
            fingerprint(&[document("benign-a")]),
            fingerprint(&[document("benign-b")])
        );
    }

    #[test]
    fn duplicate_matchers_and_rule_order_are_canonicalized_as_specified() {
        let one_target = |name: &str, field: &str| {
            rule()
                .replace("name: rule.synthetic", &format!("name: {name}"))
                .replace(&uuid("rule.synthetic"), &uuid(name))
                .replace(
                    "        - tool.result|re: &pattern synthetic\n        - tool.command|re: *pattern\n",
                    &format!("        - {field}|re: synthetic\n"),
                )
        };
        let first = fingerprint(&[
            one_target("rule.synthetic", "tool.command"),
            one_target("rule.second", "tool.result"),
        ]);
        let reordered = fingerprint(&[
            one_target("rule.second", "tool.result"),
            one_target("rule.synthetic", "tool.command"),
        ]);
        assert_ne!(first, reordered);
        // Rule v2 never compiles a field twice; the compiled form drops a
        // repeated matcher from its identity all the same.
        let export = load_rule_set_from_documents(
            &[one_target("rule.synthetic", "tool.command").as_str()],
            None,
        )
        .unwrap()
        .compatibility_export();
        let unique = export.rules()[0].clone();
        let mut repeated = unique.clone();
        repeated.matchers.push(repeated.matchers[0].clone());
        assert_eq!(
            super::rule_v1_rule_fingerprint(&unique),
            super::rule_v1_rule_fingerprint(&repeated)
        );
    }

    #[test]
    fn every_fingerprinted_modifier_field_changes_identity() {
        let base = fingerprint(&[rule(), modifier()]);
        for (from, to) in [
            ("name: chain.synthetic", "name: chain.other"),
            ("score: 7", "score: 8"),
            (
                "    explanation: modifier explanation",
                "    explanation: modifier explanation\n    detection_class: policy_violation",
            ),
            (
                "    explanation: modifier explanation",
                "    explanation: modifier explanation\n    signal_type: correlation",
            ),
            (
                "    explanation: modifier explanation",
                "    explanation: modifier explanation\n    analytic_intent: audit",
            ),
            ("tags: [atlas.a]", "tags: [atlas.a, atlas.b]"),
            ("rules: [rule.synthetic]", "categories: [execution]"),
            (
                "rules: [rule.synthetic]",
                "rules: [rule.synthetic, rule.other]",
            ),
            ("explanation: modifier explanation", "explanation: other"),
            ("    within_calls: 3\n", ""),
            ("within_calls: 3", "within_calls: 2"),
            ("within_calls: 3", "within_calls: 3\n    order: any"),
        ] {
            let changed = modifier().replacen(from, to, 1);
            assert_ne!(changed, modifier(), "{from}");
            assert_ne!(base, fingerprint(&[rule(), changed]), "{from} -> {to}");
        }
        // A minutes cap has no Rule v2 spelling; the compiled form keeps it
        // in the fingerprint.
        let export = load_rule_set_from_documents(&[file(&[rule(), modifier()]).as_str()], None)
            .unwrap()
            .compatibility_export();
        assert_eq!(rule_v1_fingerprint(&export), base);
        assert_ne!(
            rule_v1_fingerprint(&export.with_modifier("chain.synthetic", |modifier| {
                if let Some(link) = &mut modifier.link {
                    link.minutes = Some(15);
                }
            })),
            base
        );
    }

    #[test]
    fn policy_names_are_not_part_of_ruleset_identity() {
        let compiled = |name: &str| {
            let policy = RulePolicy {
                name: Some(name.to_string()),
                ..RulePolicy::default()
            };
            crate::LoadedRules::parse(&rule())
                .unwrap()
                .compile(Some(&policy))
                .expect("compiled")
        };
        let (first, second) = (compiled("policy-a"), compiled("policy-b"));
        assert_eq!(first.policy_name(), Some("policy-a"));
        assert_eq!(second.policy_name(), Some("policy-b"));
        assert_eq!(
            rule_v1_fingerprint(&first.compatibility_export()),
            rule_v1_fingerprint(&second.compatibility_export())
        );
    }
}
