use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::event::{Evidence, evidence_hash, redact_sensitive_text};

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
    pub score: u32,
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
    pub score: u32,
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
    pub score: u32,
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
    pub score: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RulePolicy {
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

pub fn default_rule_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("config/rules/tool-call-regex.yaml")
}

#[allow(dead_code)]
pub fn load_default_rule_set() -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    load_rule_set_from_paths(&[], None)
}

pub fn load_rule_set_from_paths(
    rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    let paths = if rule_paths.is_empty() {
        vec![default_rule_path()]
    } else {
        rule_paths.to_vec()
    };

    let mut loaded = Vec::new();
    for path in paths {
        let raw = fs::read_to_string(&path)?;
        loaded.push(serde_yaml::from_str::<RuleSet>(&raw)?);
    }

    let policy = match policy_path {
        Some(path) => {
            let raw = fs::read_to_string(path)?;
            Some(serde_yaml::from_str::<RulePolicy>(&raw)?)
        }
        None => None,
    };

    merge_rule_sets(loaded)?.compile(policy.as_ref())
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

fn merge_rule_sets(rule_sets: Vec<RuleSet>) -> Result<RuleSet, Box<dyn std::error::Error>> {
    let mut ids = BTreeSet::new();
    let mut descriptions = Vec::new();
    let mut rules = Vec::new();
    let mut modifiers = Vec::new();
    let mut defaults = RuleDefaults {
        case_insensitive: true,
        enabled: true,
    };

    for rule_set in rule_sets {
        defaults.case_insensitive &= rule_set.defaults.case_insensitive;
        defaults.enabled &= rule_set.defaults.enabled;
        descriptions.push(rule_set.description);
        for rule in rule_set.rules {
            if !ids.insert(rule.id.clone()) {
                return Err(format!("duplicate rule id: {}", rule.id).into());
            }
            rules.push(rule);
        }
        for modifier in rule_set.modifiers {
            if !ids.insert(modifier.id.clone()) {
                return Err(format!("duplicate rule id: {}", modifier.id).into());
            }
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

impl RuleSet {
    fn compile(
        self,
        policy: Option<&RulePolicy>,
    ) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
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

    pub fn evaluate(&self, fields: &[(&str, &str)]) -> Option<MatchResult> {
        let mut rule_ids = Vec::new();
        let mut categories = BTreeSet::new();
        let mut detection_classes = BTreeSet::new();
        let mut signal_types = BTreeSet::new();
        let mut analytic_intents = BTreeSet::new();
        let mut atlas_tags = BTreeSet::new();
        let mut tags = BTreeSet::new();
        let mut score = 0;
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
                score += rule.definition.score;
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
                    score = score.saturating_sub(rule.definition.score);
                    continue;
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
                score += modifier.score;
            }
        }

        if rule_ids.is_empty() {
            None
        } else {
            Some(MatchResult {
                rule_ids,
                categories: categories.into_iter().collect(),
                detection_classes: detection_classes.into_iter().collect(),
                signal_types: signal_types.into_iter().collect(),
                analytic_intents: analytic_intents.into_iter().collect(),
                atlas_tags: atlas_tags.into_iter().collect(),
                tags: tags.into_iter().collect(),
                score,
                evidence,
            })
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

fn matching_field<'a>(rule: &CompiledRule, fields: &'a [(&'a str, &'a str)]) -> Option<MatchedField<'a>> {
    fields
        .iter()
        .find(|(name, value)| {
            rule.matchers
                .iter()
                .any(|matcher| matcher.target == *name && matcher.regex.is_match(value))
        })
        .map(|(name, value)| MatchedField {
            name,
            value,
        })
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
    let is_copied_transcript_boilerplate = text.contains("cost data")
        || text.contains("messageabortederror")
        || text.contains("apierror")
        || text.contains("unauthorized")
        || text.contains("not authenticated")
        || text.contains("you are opencode")
        || text.contains("refuse to write code");

    text.contains("bypass approval") && (is_quoted_example || is_copied_transcript_boilerplate)
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
    use super::{DetectionDefinition, RuleDefaults, RuleDefinition, RulePolicy, RuleSet};
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
            .expect("match");

        assert_eq!(result.evidence.len(), 1);
        assert_eq!(result.evidence[0].field, "assistant_context");
        assert_eq!(
            result.evidence[0].rule_id.as_deref(),
            Some("mcp.tool_metadata.prompt_injection")
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
