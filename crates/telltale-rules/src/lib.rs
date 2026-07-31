//! Telltale rule language: YAML rule-set parsing, validation, defaults and
//! policy merging, and in-memory regex evaluation.
//!
//! This crate is deliberately I/O-free: it never touches the filesystem, a
//! watcher, or a database. Callers hand it rule documents as strings and
//! normalized fields as in-memory values, which keeps the engine reusable for
//! batch session scanning and future inline inference-proxy evaluation alike.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;
use serde::{Deserialize, Serialize};

use telltale_schema::event::{Evidence, evidence_hash, redact_sensitive_text};
use telltale_schema::scoring::{
    RiskAccountingError, RiskContribution, RiskContributionType, canonicalize_contributions,
    is_canonical_contribution_id,
};

const DEFAULT_RULE_YAML: &str = include_str!("../data/tool-call-regex.yaml");

const SUPPORTED_RULE_TARGETS: &[&str] = &[
    "arguments",
    "assistant_context",
    "command",
    "file_path",
    "tool_name",
    "tool_result",
    "url",
    "user_context",
];

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct RuleSet {
    pub version: u32,
    pub description: String,
    pub defaults: RuleDefaults,
    pub rules: Vec<RuleDefinition>,
    pub modifiers: Vec<ModifierDefinition>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleDefaults {
    pub case_insensitive: bool,
    pub enabled: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct RuleDefinition {
    pub id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub falsepositives: Vec<String>,
    #[serde(default)]
    pub level: Option<String>,
    pub category: String,
    #[serde(default = "default_detection_class")]
    pub detection_class: String,
    #[serde(default = "default_signal_type")]
    pub signal_type: String,
    #[serde(default = "default_analytic_intent")]
    pub analytic_intent: String,
    #[serde(default)]
    pub atlas_tags: Vec<String>,
    pub severity: String,
    pub score: u64,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub detection: Option<DetectionDefinition>,
    pub tags: Vec<String>,
    pub explanation: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct DetectionDefinition {
    pub selection: BTreeMap<String, String>,
    #[serde(default = "default_condition")]
    pub condition: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct ModifierDefinition {
    pub id: String,
    pub score: u64,
    #[serde(default = "default_detection_class")]
    pub detection_class: String,
    #[serde(default = "default_chain_signal_type")]
    pub signal_type: String,
    #[serde(default = "default_analytic_intent")]
    pub analytic_intent: String,
    #[serde(default)]
    pub atlas_tags: Vec<String>,
    #[serde(default)]
    pub when_all_categories: Vec<String>,
    #[serde(default)]
    pub when_all_rule_ids: Vec<String>,
    #[serde(default)]
    pub falsepositives: Vec<String>,
    pub explanation: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledRuleSet {
    rules: Vec<CompiledRule>,
    modifiers: Vec<ModifierDefinition>,
    policy_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MatchResult {
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub detection_classes: Vec<String>,
    pub signal_types: Vec<String>,
    pub analytic_intents: Vec<String>,
    pub atlas_tags: Vec<String>,
    pub tags: Vec<String>,
    pub score: u64,
    pub contributions: Vec<RiskContribution>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    definition: RuleDefinition,
    matchers: Vec<CompiledMatcher>,
}

#[derive(Debug, Clone)]
struct CompiledMatcher {
    target: String,
    regex: Regex,
}

#[derive(Debug, Clone, Copy)]
struct MatchedField<'a> {
    name: &'a str,
    value: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleSummary {
    pub id: String,
    pub category: String,
    pub detection_class: String,
    pub signal_type: String,
    pub analytic_intent: String,
    pub atlas_tags: Vec<String>,
    pub severity: String,
    pub score: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePolicy {
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled_categories: Vec<String>,
    #[serde(default)]
    pub disabled_categories: Vec<String>,
    #[serde(default)]
    pub enabled_rules: Vec<String>,
    #[serde(default)]
    pub disabled_rules: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleOverrideDocument {
    version: u32,
    #[serde(default)]
    description: Option<String>,
    overrides: Vec<RuleOverrideEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleOverrideEntry {
    rule_id: String,
    reason: String,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    score: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleLoadMode {
    IncludeDefault,
    CustomOnly,
}

pub fn bundled_default_rule_yaml() -> &'static str {
    DEFAULT_RULE_YAML
}

pub fn load_default_rule_set() -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    load_rule_set_from_documents(&[bundled_default_rule_yaml()], None)
}

pub fn bundled_default_rule_set() -> Result<RuleSet, Box<dyn std::error::Error>> {
    Ok(serde_yaml::from_str::<RuleSet>(bundled_default_rule_yaml())?)
}

pub fn load_rule_set_from_documents(
    rule_documents: &[&str],
    policy_document: Option<&str>,
) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    let loaded = rule_documents
        .iter()
        .map(|raw| serde_yaml::from_str::<RuleSet>(raw))
        .collect::<Result<Vec<_>, _>>()?;
    let policy = match policy_document {
        Some(raw) => Some(serde_yaml::from_str::<RulePolicy>(raw)?),
        None => None,
    };

    merge_rule_sets(loaded)?.compile(policy.as_ref())
}

pub fn merge_rule_sets(rule_sets: Vec<RuleSet>) -> Result<RuleSet, Box<dyn std::error::Error>> {
    let mut ids = BTreeSet::new();
    let mut descriptions = Vec::new();
    let mut rules = Vec::new();
    let mut modifiers = Vec::new();
    let defaults = RuleDefaults {
        case_insensitive: false,
        enabled: true,
    };

    for rule_set in rule_sets {
        let document_defaults = rule_set.defaults.clone();
        descriptions.push(rule_set.description);
        for mut rule in rule_set.rules {
            if !ids.insert(rule.id.clone()) {
                return Err(format!("duplicate rule id: {}", rule.id).into());
            }
            apply_rule_defaults(&mut rule, &document_defaults);
            rules.push(rule);
        }
        for mut modifier in rule_set.modifiers {
            if !ids.insert(modifier.id.clone()) {
                return Err(format!("duplicate rule id: {}", modifier.id).into());
            }
            apply_modifier_defaults(&mut modifier, &document_defaults);
            modifiers.push(modifier);
        }
    }

    Ok(RuleSet {
        version: 1,
        description: descriptions.join("; "),
        defaults,
        rules,
        modifiers,
    })
}

fn apply_rule_defaults(rule: &mut RuleDefinition, defaults: &RuleDefaults) {
    if !defaults.enabled {
        rule.enabled = false;
    }
    if defaults.case_insensitive {
        if let Some(regex) = rule.regex.as_mut() {
            *regex = case_insensitive_pattern(regex);
        }
        if let Some(detection) = rule.detection.as_mut() {
            for regex in detection.selection.values_mut() {
                *regex = case_insensitive_pattern(regex);
            }
        }
    }
}

fn apply_modifier_defaults(modifier: &mut ModifierDefinition, defaults: &RuleDefaults) {
    if !defaults.enabled {
        modifier.enabled = false;
    }
}

pub fn apply_rule_override_document(
    rule_set: &mut RuleSet,
    document: &RuleOverrideDocument,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if document.version != 1 {
        return Err(format!(
            "unsupported rule override version {} in {}; only version 1 is supported",
            document.version,
            path.display()
        )
        .into());
    }
    let _ = &document.description;

    let rule_indexes = rule_set
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| (rule.id.clone(), index))
        .collect::<BTreeMap<_, _>>();
    for entry in &document.overrides {
        validate_rule_override_entry(entry, path)?;
        let Some(index) = rule_indexes.get(&entry.rule_id).copied() else {
            return Err(format!(
                "unknown rule_id '{}' in rule override file {}",
                entry.rule_id,
                path.display()
            )
            .into());
        };
        let rule = &mut rule_set.rules[index];
        if let Some(enabled) = entry.enabled {
            rule.enabled = enabled;
        }
        if let Some(score) = entry.score {
            rule.score = score;
        }
    }
    Ok(())
}

fn validate_rule_override_entry(
    entry: &RuleOverrideEntry,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if entry.rule_id.trim().is_empty() {
        return Err(format!("rule override in {} has empty rule_id", path.display()).into());
    }
    if entry.reason.trim().is_empty() {
        return Err(format!(
            "rule override for '{}' in {} requires a non-empty reason",
            entry.rule_id,
            path.display()
        )
        .into());
    }
    if entry.enabled.is_none() && entry.score.is_none() {
        return Err(format!(
            "rule override for '{}' in {} must set enabled or score",
            entry.rule_id,
            path.display()
        )
        .into());
    }
    Ok(())
}

fn case_insensitive_pattern(pattern: &str) -> String {
    format!("(?i:{pattern})")
}

impl RuleSet {
    pub fn compile(
        self,
        policy: Option<&RulePolicy>,
    ) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
        validate_rule_ids(&self)?;
        let case_insensitive = self.defaults.case_insensitive;
        let rules = self
            .rules
            .into_iter()
            .filter(|rule| {
                rule.enabled && self.defaults.enabled && policy_allows_rule(rule, policy)
            })
            .map(|definition| {
                let matchers = compile_matchers(&definition, case_insensitive)?;
                Ok(CompiledRule {
                    definition,
                    matchers,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let modifiers = self
            .modifiers
            .into_iter()
            .filter(|modifier| {
                modifier.enabled
                    && self.defaults.enabled
                    && policy_allows_modifier(modifier, policy)
            })
            .map(|modifier| {
                validate_rule_metadata(
                    &modifier.id,
                    &modifier.detection_class,
                    &modifier.signal_type,
                    &modifier.analytic_intent,
                    &modifier.atlas_tags,
                )?;
                Ok(modifier)
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        Ok(CompiledRuleSet {
            rules,
            modifiers,
            policy_name: policy.and_then(|policy| policy.name.clone()),
        })
    }
}

fn validate_rule_ids(rule_set: &RuleSet) -> Result<(), Box<dyn std::error::Error>> {
    for rule in &rule_set.rules {
        validate_canonical_rule_id(&rule.id, "rule")?;
    }
    for modifier in &rule_set.modifiers {
        validate_canonical_rule_id(&modifier.id, "modifier")?;
        for rule_id in &modifier.when_all_rule_ids {
            validate_canonical_rule_id(rule_id, "modifier rule reference")?;
        }
    }
    Ok(())
}

fn validate_canonical_rule_id(id: &str, kind: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !is_canonical_contribution_id(id) {
        return Err(format!("{kind} id '{id}' is not canonical").into());
    }
    Ok(())
}

impl CompiledRuleSet {
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn policy_name(&self) -> Option<&str> {
        self.policy_name.as_deref()
    }

    pub fn summaries(&self) -> Vec<RuleSummary> {
        self.rules
            .iter()
            .map(|rule| RuleSummary {
                id: rule.definition.id.clone(),
                category: rule.definition.category.clone(),
                detection_class: rule.definition.detection_class.clone(),
                signal_type: rule.definition.signal_type.clone(),
                analytic_intent: rule.definition.analytic_intent.clone(),
                atlas_tags: rule.definition.atlas_tags.clone(),
                severity: rule.definition.severity.clone(),
                score: rule.definition.score,
                enabled: rule.definition.enabled,
            })
            .collect()
    }

    pub fn evaluate(
        &self,
        fields: &[(&str, &str)],
    ) -> Result<Option<MatchResult>, RiskAccountingError> {
        let mut rule_ids = Vec::new();
        let mut categories = BTreeSet::new();
        let mut detection_classes = BTreeSet::new();
        let mut signal_types = BTreeSet::new();
        let mut analytic_intents = BTreeSet::new();
        let mut atlas_tags = BTreeSet::new();
        let mut tags = BTreeSet::new();
        let mut contributions = Vec::new();
        let mut evidence = Vec::new();

        for rule in &self.rules {
            if let Some(matched) = matching_field(rule, fields) {
                rule_ids.push(rule.definition.id.clone());
                categories.insert(rule.definition.category.clone());
                detection_classes.insert(rule.definition.detection_class.clone());
                signal_types.insert(rule.definition.signal_type.clone());
                analytic_intents.insert(rule.definition.analytic_intent.clone());
                atlas_tags.extend(rule.definition.atlas_tags.iter().cloned());
                tags.extend(rule.definition.tags.iter().cloned());
                if should_skip_match(&rule.definition.id, matched) {
                    rule_ids.pop();
                    categories.remove(&rule.definition.category);
                    detection_classes.remove(&rule.definition.detection_class);
                    signal_types.remove(&rule.definition.signal_type);
                    analytic_intents.remove(&rule.definition.analytic_intent);
                    for atlas_tag in &rule.definition.atlas_tags {
                        atlas_tags.remove(atlas_tag);
                    }
                    tags.retain(|tag| !rule.definition.tags.contains(tag));
                    continue;
                }
                if rule.definition.score > 0 {
                    contributions.push(RiskContribution::new(
                        &rule.definition.id,
                        RiskContributionType::DeterministicRule,
                        rule.definition.score,
                        redact_sensitive_text(&rule.definition.explanation),
                    )?);
                }
                evidence.push(Evidence {
                    field: matched.name.to_string(),
                    redacted_value: redact_sensitive_text(matched.value),
                    hash: Some(evidence_hash(matched.value)),
                    rule_id: Some(rule.definition.id.clone()),
                });
            }
        }

        let category_set: BTreeSet<_> = categories.iter().cloned().collect();
        let rule_id_set: BTreeSet<_> = rule_ids.iter().cloned().collect();
        for modifier in &self.modifiers {
            let has_category_conditions = !modifier.when_all_categories.is_empty();
            let has_rule_id_conditions = !modifier.when_all_rule_ids.is_empty();
            let categories_match = modifier
                .when_all_categories
                .iter()
                .all(|category| category_set.contains(category));
            let rule_ids_match = modifier
                .when_all_rule_ids
                .iter()
                .all(|rule_id| rule_id_set.contains(rule_id));

            if (has_category_conditions || has_rule_id_conditions)
                && categories_match
                && rule_ids_match
            {
                rule_ids.push(modifier.id.clone());
                detection_classes.insert(modifier.detection_class.clone());
                signal_types.insert(modifier.signal_type.clone());
                analytic_intents.insert(modifier.analytic_intent.clone());
                atlas_tags.extend(modifier.atlas_tags.iter().cloned());
                if modifier.score > 0 {
                    contributions.push(RiskContribution::new(
                        &modifier.id,
                        RiskContributionType::ChainModifier,
                        modifier.score,
                        redact_sensitive_text(&modifier.explanation),
                    )?);
                }
            }
        }

        let contributions = canonicalize_contributions(contributions)?;

        if rule_ids.is_empty() {
            Ok(None)
        } else {
            let score = telltale_schema::scoring::checked_risk_sum(&contributions)?;
            Ok(Some(MatchResult {
                rule_ids,
                categories: categories.into_iter().collect(),
                detection_classes: detection_classes.into_iter().collect(),
                signal_types: signal_types.into_iter().collect(),
                analytic_intents: analytic_intents.into_iter().collect(),
                atlas_tags: atlas_tags.into_iter().collect(),
                tags: tags.into_iter().collect(),
                score,
                contributions,
                evidence,
            }))
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_condition() -> String {
    "selection".to_string()
}

fn default_detection_class() -> String {
    "security_detection".to_string()
}

fn default_signal_type() -> String {
    "atomic".to_string()
}

fn default_chain_signal_type() -> String {
    "chain".to_string()
}

fn default_analytic_intent() -> String {
    "alert".to_string()
}

fn compile_matchers(
    definition: &RuleDefinition,
    case_insensitive: bool,
) -> Result<Vec<CompiledMatcher>, Box<dyn std::error::Error>> {
    validate_rule_metadata(
        &definition.id,
        &definition.detection_class,
        &definition.signal_type,
        &definition.analytic_intent,
        &definition.atlas_tags,
    )?;
    let mut matchers = Vec::new();
    if let Some(regex) = &definition.regex {
        if definition.targets.is_empty() {
            return Err(format!("rule {} has regex but no targets", definition.id).into());
        }
        for target in &definition.targets {
            validate_target(&definition.id, target)?;
            matchers.push(CompiledMatcher {
                target: target.clone(),
                regex: compile_regex(regex, case_insensitive, &definition.id)?,
            });
        }
    }
    if let Some(detection) = &definition.detection {
        if detection.condition != "selection" {
            return Err(format!(
                "rule {} uses unsupported condition {}; only 'selection' is supported",
                definition.id, detection.condition
            )
            .into());
        }
        for (target, regex) in &detection.selection {
            validate_target(&definition.id, target)?;
            matchers.push(CompiledMatcher {
                target: target.clone(),
                regex: compile_regex(regex, case_insensitive, &definition.id)?,
            });
        }
    }
    if matchers.is_empty() {
        return Err(format!("rule {} has no regex or detection.selection", definition.id).into());
    }
    Ok(matchers)
}

fn validate_rule_metadata(
    rule_id: &str,
    detection_class: &str,
    signal_type: &str,
    analytic_intent: &str,
    atlas_tags: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    validate_metadata_value(
        rule_id,
        "detection_class",
        detection_class,
        &[
            "security_detection",
            "policy_violation",
            "threat_hunting",
            "compliance_observation",
            "operational_health",
            "baseline_deviation",
        ],
    )?;
    validate_metadata_value(
        rule_id,
        "signal_type",
        signal_type,
        &[
            "atomic",
            "chain",
            "correlation",
            "baseline_deviation",
            "llm_triage",
        ],
    )?;
    validate_metadata_value(
        rule_id,
        "analytic_intent",
        analytic_intent,
        &["alert", "hunt", "enrich", "baseline", "audit"],
    )?;
    for tag in atlas_tags {
        if !tag.starts_with("atlas:") {
            return Err(format!(
                "rule {rule_id} uses unsupported atlas tag '{tag}'; atlas_tags must use atlas:<id>"
            )
            .into());
        }
    }
    Ok(())
}

fn validate_metadata_value(
    rule_id: &str,
    field: &str,
    value: &str,
    allowed: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!(
            "rule {rule_id} uses unsupported {field} '{value}'; supported values: {}",
            allowed.join(", ")
        )
        .into())
    }
}

fn validate_target(rule_id: &str, target: &str) -> Result<(), Box<dyn std::error::Error>> {
    if SUPPORTED_RULE_TARGETS.contains(&target) {
        Ok(())
    } else {
        Err(format!(
            "rule {rule_id} uses unsupported target '{target}'; supported targets: {}",
            SUPPORTED_RULE_TARGETS.join(", ")
        )
        .into())
    }
}

fn compile_regex(
    pattern: &str,
    case_insensitive: bool,
    rule_id: &str,
) -> Result<Regex, Box<dyn std::error::Error>> {
    let pattern = if case_insensitive {
        format!("(?i:{pattern})")
    } else {
        pattern.to_string()
    };
    Regex::new(&pattern)
        .map_err(|error| format!("invalid regex for rule {rule_id}: {error}").into())
}

fn matching_field<'a>(
    rule: &CompiledRule,
    fields: &'a [(&'a str, &'a str)],
) -> Option<MatchedField<'a>> {
    fields
        .iter()
        .find(|(name, value)| {
            rule.matchers
                .iter()
                .any(|matcher| matcher.target == *name && matcher.regex.is_match(value))
        })
        .map(|(name, value)| MatchedField { name, value })
}

fn policy_allows_rule(rule: &RuleDefinition, policy: Option<&RulePolicy>) -> bool {
    let Some(policy) = policy else {
        return true;
    };
    if !policy.enabled_categories.is_empty()
        && !policy
            .enabled_categories
            .iter()
            .any(|category| category == &rule.category)
    {
        return false;
    }
    if policy
        .disabled_categories
        .iter()
        .any(|category| category == &rule.category)
    {
        return false;
    }
    if !policy.enabled_rules.is_empty()
        && !policy
            .enabled_rules
            .iter()
            .any(|rule_id| rule_id == &rule.id)
    {
        return false;
    }
    !policy
        .disabled_rules
        .iter()
        .any(|rule_id| rule_id == &rule.id)
}

fn policy_allows_modifier(modifier: &ModifierDefinition, policy: Option<&RulePolicy>) -> bool {
    let Some(policy) = policy else {
        return true;
    };
    if !policy.enabled_rules.is_empty()
        && !policy
            .enabled_rules
            .iter()
            .any(|rule_id| rule_id == &modifier.id)
    {
        return false;
    }
    !policy
        .disabled_rules
        .iter()
        .any(|rule_id| rule_id == &modifier.id)
}

fn should_skip_match(rule_id: &str, matched: MatchedField<'_>) -> bool {
    match rule_id {
        "approval.bypass.context" => approval_bypass_match_should_skip(matched),
        "secret.env.read" => secret_env_read_match_should_skip(matched),
        _ => false,
    }
}

fn approval_bypass_match_should_skip(matched: MatchedField<'_>) -> bool {
    let text = matched.value.to_ascii_lowercase();
    let is_quoted_example = text.contains("quoted example")
        || text.contains("appears only as a quoted example")
        || text.contains("should not be treated as an instruction")
        || text.contains("documentation review")
        || text.contains("review notes");
    let is_system_prompt_or_boilerplate = text.contains("cost data")
        || text.contains("messageabortederror")
        || text.contains("apierror")
        || text.contains("unauthorized")
        || text.contains("not authenticated")
        || text.contains("you are opencode")
        || text.contains("refuse to write code")
        || text.contains("important: refuse")
        || text.contains("may be used maliciously");

    is_system_prompt_or_boilerplate || (text.contains("bypass approval") && is_quoted_example)
}

fn secret_env_read_match_should_skip(matched: MatchedField<'_>) -> bool {
    match matched.name {
        "command" | "arguments" | "file_path" => false,
        "assistant_context" | "tool_result" => {
            let text = matched.value.to_ascii_lowercase();
            let has_explicit_read_context = text.contains("read_file")
                || text.contains("readfile")
                || text.contains("view_file")
                || text.contains("file_path")
                || text.contains("path=")
                || text.contains("path:")
                || text.contains("/.env")
                || text.contains("\\.env")
                || text.contains(".bash_secrets")
                || text.contains(".zsh_secrets");
            let is_negated_or_policy_text = text.contains("do not read .env")
                || text.contains("don't read .env")
                || text.contains("should not read .env")
                || text.contains("not read .env")
                || text.contains("refuse to read .env")
                || text.contains("do not read .bash_secrets")
                || text.contains("don't read .bash_secrets")
                || text.contains("should not read .bash_secrets")
                || text.contains("not read .bash_secrets")
                || text.contains("refuse to read .bash_secrets")
                || text.contains("do not read .zsh_secrets")
                || text.contains("don't read .zsh_secrets")
                || text.contains("should not read .zsh_secrets")
                || text.contains("not read .zsh_secrets")
                || text.contains("refuse to read .zsh_secrets")
                || text.contains("policy")
                || text.contains("forbidden behavior")
                || text.contains("disallowed behavior");

            !has_explicit_read_context || is_negated_or_policy_text
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DetectionDefinition, ModifierDefinition, RuleDefaults, RuleDefinition, RulePolicy, RuleSet,
    };
    use std::collections::BTreeMap;

    fn single_rule_set(rule: RuleDefinition) -> super::CompiledRuleSet {
        RuleSet {
            version: 1,
            description: "test rules".to_string(),
            defaults: RuleDefaults {
                case_insensitive: true,
                enabled: true,
            },
            rules: vec![rule],
            modifiers: Vec::new(),
        }
        .compile(None)
        .expect("compile rules")
    }

    fn rule(id: &str, category: &str) -> RuleDefinition {
        RuleDefinition {
            id: id.to_string(),
            title: None,
            description: None,
            status: None,
            author: None,
            references: Vec::new(),
            falsepositives: Vec::new(),
            level: None,
            category: category.to_string(),
            detection_class: super::default_detection_class(),
            signal_type: super::default_signal_type(),
            analytic_intent: super::default_analytic_intent(),
            atlas_tags: Vec::new(),
            severity: "high".to_string(),
            score: 60,
            targets: vec!["assistant_context".to_string(), "tool_result".to_string()],
            regex: Some("hidden instruction".to_string()),
            detection: None,
            tags: vec!["mcp".to_string()],
            explanation: "test".to_string(),
            enabled: true,
        }
    }

    #[test]
    fn evidence_field_uses_actual_matched_target() {
        let rule_set = single_rule_set(rule(
            "mcp.tool_metadata.prompt_injection",
            "mcp_prompt_injection",
        ));

        let result = rule_set
            .evaluate(&[
                (
                    "assistant_context",
                    "MCP hidden instruction in tool metadata",
                ),
                ("tool_result", ""),
            ])
            .expect("evaluate")
            .expect("match");

        assert_eq!(result.evidence.len(), 1);
        assert_eq!(result.evidence[0].field, "assistant_context");
        assert_eq!(
            result.evidence[0].rule_id.as_deref(),
            Some("mcp.tool_metadata.prompt_injection")
        );
    }

    #[test]
    fn matched_rules_emit_positive_contribution_metadata() {
        let mut definition = rule("rule.large", "hidden instruction");
        definition.score = 4_294_967_296;
        definition.explanation = "synthetic execution match".to_string();
        let rule_set = single_rule_set(definition);
        let result = rule_set
            .evaluate(&[("assistant_context", "hidden instruction")])
            .expect("evaluate")
            .expect("match");

        assert_eq!(result.score, 4_294_967_296);
        assert_eq!(result.contributions.len(), 1);
        assert_eq!(result.contributions[0].id(), "rule.large");
        assert_eq!(
            result.contributions[0].contribution_type(),
            telltale_schema::scoring::RiskContributionType::DeterministicRule
        );
    }

    #[test]
    fn matched_modifiers_emit_chain_contribution_metadata() {
        let mut definition = rule("rule.base", "hidden instruction");
        definition.category = "execution".to_string();
        let rule_set = RuleSet {
            version: 1,
            description: "test rules".to_string(),
            defaults: RuleDefaults {
                case_insensitive: true,
                enabled: true,
            },
            rules: vec![definition],
            modifiers: vec![ModifierDefinition {
                id: "chain.test".to_string(),
                score: 7,
                detection_class: super::default_detection_class(),
                signal_type: super::default_chain_signal_type(),
                analytic_intent: super::default_analytic_intent(),
                atlas_tags: Vec::new(),
                when_all_categories: vec!["execution".to_string()],
                when_all_rule_ids: Vec::new(),
                falsepositives: Vec::new(),
                explanation: "synthetic chain modifier".to_string(),
                enabled: true,
            }],
        }
        .compile(None)
        .expect("compile rules");

        let result = rule_set
            .evaluate(&[("assistant_context", "hidden instruction")])
            .expect("evaluate")
            .expect("match");
        assert_eq!(result.score, 67);
        assert_eq!(result.contributions.len(), 2);
        assert_eq!(
            result.contributions[1].contribution_type(),
            telltale_schema::scoring::RiskContributionType::ChainModifier
        );
    }

    #[test]
    fn contributions_are_sorted_by_type_then_resolved_id() {
        let rule_set = RuleSet {
            version: 1,
            description: "test rules".to_string(),
            defaults: RuleDefaults {
                case_insensitive: true,
                enabled: true,
            },
            rules: vec![
                rule("rule.z", "hidden instruction"),
                rule("rule.a", "hidden instruction"),
            ],
            modifiers: Vec::new(),
        }
        .compile(None)
        .expect("compile rules");

        let result = rule_set
            .evaluate(&[("assistant_context", "hidden instruction")])
            .expect("evaluate")
            .expect("match");
        assert_eq!(
            result
                .contributions
                .iter()
                .map(|contribution| contribution.id())
                .collect::<Vec<_>>(),
            vec!["rule.a", "rule.z"]
        );
    }

    #[test]
    fn supports_sigma_inspired_selection_rules() {
        let mut selection = BTreeMap::new();
        selection.insert("arguments".to_string(), "evil-action".to_string());
        let mut definition = rule("custom.agent_behavior", "custom");
        definition.targets = Vec::new();
        definition.regex = None;
        definition.detection = Some(DetectionDefinition {
            selection,
            condition: "selection".to_string(),
        });
        let rule_set = single_rule_set(definition);

        let result = rule_set
            .evaluate(&[("arguments", "run evil-action now")])
            .expect("evaluate")
            .expect("match");

        assert_eq!(result.rule_ids, vec!["custom.agent_behavior"]);
        assert_eq!(result.categories, vec!["custom"]);
    }

    #[test]
    fn evaluates_rule_purpose_metadata_and_atlas_tags() {
        let mut definition = rule("policy.agent_guardrail_modification", "persistence");
        definition.detection_class = "policy_violation".to_string();
        definition.signal_type = "atomic".to_string();
        definition.analytic_intent = "audit".to_string();
        definition.atlas_tags = vec!["atlas:AML.T0051".to_string()];
        let rule_set = single_rule_set(definition);

        let result = rule_set
            .evaluate(&[("assistant_context", "hidden instruction")])
            .expect("evaluate")
            .expect("match");

        assert_eq!(result.detection_classes, vec!["policy_violation"]);
        assert_eq!(result.signal_types, vec!["atomic"]);
        assert_eq!(result.analytic_intents, vec!["audit"]);
        assert_eq!(result.atlas_tags, vec!["atlas:AML.T0051"]);
    }

    #[test]
    fn rejects_invalid_rule_purpose_metadata() {
        let mut definition = rule("custom.invalid_metadata", "custom");
        definition.detection_class = "alert".to_string();
        let result = RuleSet {
            version: 1,
            description: "test rules".to_string(),
            defaults: RuleDefaults {
                case_insensitive: true,
                enabled: true,
            },
            rules: vec![definition],
            modifiers: Vec::new(),
        }
        .compile(None);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_noncanonical_rule_ids_before_matching_for_zero_and_positive_scores() {
        for score in [0, 1] {
            let mut definition = rule("invalid", "custom");
            definition.score = score;
            let result = RuleSet {
                version: 1,
                description: "test rules".to_string(),
                defaults: RuleDefaults {
                    case_insensitive: true,
                    enabled: true,
                },
                rules: vec![definition],
                modifiers: Vec::new(),
            }
            .compile(None);
            assert!(result.is_err(), "score {score} should reject invalid id");
        }
    }

    #[test]
    fn rejects_noncanonical_modifier_ids_and_rule_references_before_matching() {
        for score in [0, 1] {
            for (id, references) in [("invalid", Vec::new()), ("chain.valid", vec!["invalid"])] {
                let result = RuleSet {
                    version: 1,
                    description: "test rules".to_string(),
                    defaults: RuleDefaults {
                        case_insensitive: true,
                        enabled: true,
                    },
                    rules: Vec::new(),
                    modifiers: vec![ModifierDefinition {
                        id: id.to_string(),
                        score,
                        detection_class: super::default_detection_class(),
                        signal_type: super::default_chain_signal_type(),
                        analytic_intent: super::default_analytic_intent(),
                        atlas_tags: Vec::new(),
                        when_all_categories: Vec::new(),
                        when_all_rule_ids: references.into_iter().map(str::to_string).collect(),
                        falsepositives: Vec::new(),
                        explanation: "test modifier".to_string(),
                        enabled: true,
                    }],
                }
                .compile(None);
                assert!(
                    result.is_err(),
                    "invalid modifier metadata should reject at score {score}"
                );
            }
        }
    }

    #[test]
    fn policy_can_disable_categories() {
        let policy = RulePolicy {
            disabled_categories: vec!["mcp_prompt_injection".to_string()],
            ..RulePolicy::default()
        };
        let rule_set = RuleSet {
            version: 1,
            description: "test rules".to_string(),
            defaults: RuleDefaults {
                case_insensitive: true,
                enabled: true,
            },
            rules: vec![rule(
                "mcp.tool_metadata.prompt_injection",
                "mcp_prompt_injection",
            )],
            modifiers: Vec::new(),
        }
        .compile(Some(&policy))
        .expect("compile rules");

        assert_eq!(rule_set.rule_count(), 0);
    }
}
