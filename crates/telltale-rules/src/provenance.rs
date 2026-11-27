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
mod tests;
