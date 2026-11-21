//! Loaded rule content: every rule and chain modifier that Rule v2 files and
//! packages define, as one ordered list, before overrides and policy.
//!
//! A Rule v2 file reads into [`LoadedRules`]. Callers merge them, additively
//! ([`LoadedRules::merge`]) or by tier (the CLI's resolution), apply override
//! documents, and compile with an optional policy. The order of the list is
//! the rule order and the modifier order of the compiled set, which its
//! fingerprint covers. Definitions are compiled when read, so a disabled rule
//! must compile too.
//!
//! Each definition also keeps the descriptive metadata the catalog reports
//! ([`DefinitionMetadata`]) and the package that shipped it, if any.

use crate::{
    CompiledRule, CompiledRuleSet, RuleLoadNotice, RuleOverrideDocument, RulePolicy,
    RuleV1CompatibilityModifier, RuleV1CompatibilityRule, policy_allows_modifier,
    policy_allows_rule, policy_name, provenance, rule_v2, validate_rule_override_entry,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

/// Whether a definition is a rule or a chain modifier (a Rule v2 chain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionKind {
    Rule,
    Modifier,
}

impl DefinitionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Modifier => "modifier",
        }
    }
}

/// Descriptive metadata of one definition: catalog data that never reaches the
/// compiled form or its behaviour fingerprint. Rule v2 documents fill every
/// field they set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DefinitionMetadata {
    /// The Rule v2 `id` (a UUID).
    pub uuid: Option<String>,
    pub title: Option<String>,
    /// The Sigma status of a Rule v2 document.
    pub status: Option<String>,
    pub description: Option<String>,
    pub references: Vec<String>,
    pub author: Option<String>,
    pub license: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub related: Vec<RelatedRule>,
    /// A Rule v2 rule's `logsource`; `None` for chains.
    pub logsource: Option<RuleLogSource>,
    /// Sigma tags as written, such as `attack.t1105` or `atlas.aml.t0051`.
    pub tags: Vec<String>,
    pub falsepositives: Vec<String>,
}

impl DefinitionMetadata {
    /// MITRE ATT&CK technique IDs from `attack.tNNNN[.NNN]` tags, uppercased,
    /// in tag order.
    pub fn attack_techniques(&self) -> Vec<String> {
        self.tags
            .iter()
            .filter_map(|tag| tag.strip_prefix("attack."))
            .filter(|id| is_attack_technique(id))
            .map(str::to_ascii_uppercase)
            .collect()
    }
}

fn is_attack_technique(id: &str) -> bool {
    let digits = |text: &str, count: usize| {
        text.len() == count && text.bytes().all(|byte| byte.is_ascii_digit())
    };
    let Some(rest) = id.strip_prefix('t') else {
        return false;
    };
    match rest.split_once('.') {
        Some((technique, sub)) => digits(technique, 4) && digits(sub, 3),
        None => digits(rest, 4),
    }
}

/// A Sigma `related` entry: another rule's UUID and the relation type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelatedRule {
    pub id: String,
    /// `derived`, `obsolete`, `merged`, `renamed` or `similar`.
    pub kind: String,
}

/// A Rule v2 rule's `logsource`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleLogSource {
    pub product: String,
    pub category: String,
    pub service: Option<String>,
}

/// One rule or chain modifier as loaded and compiled.
#[derive(Debug, Clone)]
pub struct LoadedDefinition {
    body: Body,
    metadata: DefinitionMetadata,
    package_id: Option<String>,
    overrides: Vec<AppliedOverride>,
}

/// Most override entries one definition takes.
pub const MAX_APPLIED_OVERRIDES: usize = 256;

/// One override entry applied to a definition: the document's source name
/// and label, the operator's reason and the values it set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedOverride {
    pub source: String,
    /// The caller's label for the document, if it gave one.
    pub label: Option<String>,
    pub reason: String,
    pub enabled: Option<bool>,
    pub score: Option<u64>,
}

#[derive(Debug, Clone)]
enum Body {
    Rule {
        rule: CompiledRule,
        enabled: bool,
        notices: Vec<RuleLoadNotice>,
    },
    Chain {
        modifier: RuleV1CompatibilityModifier,
        enabled: bool,
    },
}

/// A definition's compiled form, whether or not it is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledDefinition {
    Rule(RuleV1CompatibilityRule),
    Modifier(RuleV1CompatibilityModifier),
}

impl PartialEq for LoadedDefinition {
    fn eq(&self, other: &Self) -> bool {
        let body = match (&self.body, &other.body) {
            (
                Body::Rule {
                    rule: left,
                    enabled: left_enabled,
                    notices: left_notices,
                },
                Body::Rule {
                    rule: right,
                    enabled: right_enabled,
                    notices: right_notices,
                },
            ) => {
                left.export == right.export
                    && left_enabled == right_enabled
                    && left_notices == right_notices
            }
            (
                Body::Chain {
                    modifier: left,
                    enabled: left_enabled,
                },
                Body::Chain {
                    modifier: right,
                    enabled: right_enabled,
                },
            ) => left == right && left_enabled == right_enabled,
            _ => false,
        };
        body && self.metadata == other.metadata
            && self.package_id == other.package_id
            && self.overrides == other.overrides
    }
}

impl LoadedDefinition {
    pub(crate) fn from_v2(definition: rule_v2::Definition) -> Self {
        let body = match definition.body {
            rule_v2::Body::Rule(rule) => Body::Rule {
                rule,
                enabled: definition.enabled,
                notices: definition.notices,
            },
            rule_v2::Body::Chain(modifier) => Body::Chain {
                modifier,
                enabled: definition.enabled,
            },
        };
        Self {
            body,
            metadata: definition.metadata,
            package_id: None,
            overrides: Vec::new(),
        }
    }

    /// The compiled id: the Rule v2 `name`.
    pub fn id(&self) -> &str {
        match &self.body {
            Body::Rule { rule, .. } => &rule.export.id,
            Body::Chain { modifier, .. } => &modifier.id,
        }
    }

    pub fn kind(&self) -> DefinitionKind {
        match &self.body {
            Body::Rule { .. } => DefinitionKind::Rule,
            Body::Chain { .. } => DefinitionKind::Modifier,
        }
    }

    /// The Rule v2 `id` (a UUID).
    pub fn uuid(&self) -> Option<&str> {
        self.metadata.uuid.as_deref()
    }

    /// Whether it takes part before policy: its own `enabled`, a Rule v2
    /// status that loads disabled, and overrides.
    pub fn enabled(&self) -> bool {
        match &self.body {
            Body::Rule { enabled, .. } | Body::Chain { enabled, .. } => *enabled,
        }
    }

    pub fn metadata(&self) -> &DefinitionMetadata {
        &self.metadata
    }

    /// The rule package that ships this definition; `None` for other content.
    pub fn package_id(&self) -> Option<&str> {
        self.package_id.as_deref()
    }

    /// Override entries applied to this definition, in order.
    pub fn overrides(&self) -> &[AppliedOverride] {
        &self.overrides
    }

    /// Findings about this definition that did not stop it from loading.
    pub fn notices(&self) -> &[RuleLoadNotice] {
        match &self.body {
            Body::Rule { notices, .. } => notices,
            _ => &[],
        }
    }

    /// A rule's threat category; `None` for modifiers.
    pub fn category(&self) -> Option<&str> {
        match &self.body {
            Body::Rule { rule, .. } => Some(&rule.export.category),
            _ => None,
        }
    }

    /// A rule's severity (Rule v2 `level`); `None` for modifiers.
    pub fn severity(&self) -> Option<&str> {
        match &self.body {
            Body::Rule { rule, .. } => Some(&rule.export.severity),
            _ => None,
        }
    }

    pub fn score(&self) -> u64 {
        match &self.body {
            Body::Rule { rule, .. } => rule.export.score,
            Body::Chain { modifier, .. } => modifier.score,
        }
    }

    pub fn explanation(&self) -> &str {
        match &self.body {
            Body::Rule { rule, .. } => &rule.export.explanation,
            Body::Chain { modifier, .. } => &modifier.explanation,
        }
    }

    pub fn signal_type(&self) -> &str {
        match &self.body {
            Body::Rule { rule, .. } => &rule.export.signal_type,
            Body::Chain { modifier, .. } => &modifier.signal_type,
        }
    }

    /// Compiled ATLAS tags (`atlas:<ID>`).
    pub fn atlas_tags(&self) -> &[String] {
        match &self.body {
            Body::Rule { rule, .. } => &rule.export.atlas_tags,
            Body::Chain { modifier, .. } => &modifier.atlas_tags,
        }
    }

    /// A rule's free-form Telltale labels (`telltale.tags`); empty for
    /// modifiers.
    pub fn tags(&self) -> &[String] {
        match &self.body {
            Body::Rule { rule, .. } => &rule.export.tags,
            _ => &[],
        }
    }

    pub fn when_all_categories(&self) -> &[String] {
        match &self.body {
            Body::Chain { modifier, .. } => &modifier.when_all_categories,
            _ => &[],
        }
    }

    pub fn when_all_rule_ids(&self) -> &[String] {
        match &self.body {
            Body::Chain { modifier, .. } => &modifier.when_all_rule_ids,
            _ => &[],
        }
    }

    /// The compiled form whether or not the definition is enabled.
    pub fn compile(&self) -> CompiledDefinition {
        match &self.body {
            Body::Rule { rule, .. } => CompiledDefinition::Rule(rule.export.clone()),
            Body::Chain { modifier, .. } => CompiledDefinition::Modifier(modifier.clone()),
        }
    }

    /// The behaviour revision: the fingerprint of the one-definition export.
    pub fn behavior_fingerprint(&self) -> String {
        match &self.body {
            Body::Rule { rule, .. } => provenance::rule_v1_rule_fingerprint(&rule.export),
            Body::Chain { modifier, .. } => provenance::rule_v1_modifier_fingerprint(modifier),
        }
    }

    /// The metadata revision: a hash of the descriptive metadata the behaviour
    /// fingerprint leaves out.
    pub fn metadata_revision(&self) -> String {
        provenance::metadata_revision(&self.metadata)
    }

    fn set_enabled(&mut self, value: bool) {
        match &mut self.body {
            Body::Rule { enabled, .. } | Body::Chain { enabled, .. } => *enabled = value,
        }
    }

    fn set_score(&mut self, score: u64) {
        match &mut self.body {
            Body::Rule { rule, .. } => rule.export.score = score,
            Body::Chain { modifier, .. } => modifier.score = score,
        }
    }
}

/// Why [`LoadedRules::apply_override_document`] rejected a document. Each
/// variant holds the full message, which names the document's source and can
/// name a rule ID; `Display` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleOverrideError {
    /// The document's `version` is not 1.
    UnsupportedVersion(String),
    /// An entry has an empty `rule_id` or `reason`, or sets neither `enabled`
    /// nor `score`.
    InvalidEntry(String),
    /// An entry names no rule in the content.
    UnknownRuleId(String),
    /// An entry would give a rule more than [`MAX_APPLIED_OVERRIDES`]
    /// applied overrides.
    TooManyOverrides(String),
}

impl std::fmt::Display for RuleOverrideError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (Self::UnsupportedVersion(message)
        | Self::InvalidEntry(message)
        | Self::UnknownRuleId(message)
        | Self::TooManyOverrides(message)) = self;
        formatter.write_str(message)
    }
}

impl Error for RuleOverrideError {}

/// An ordered list of loaded definitions, each id and each Rule v2 UUID once.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LoadedRules {
    definitions: Vec<LoadedDefinition>,
}

impl LoadedRules {
    /// Read one rule file: one or more Rule v2 rule and chain documents (see
    /// [`crate::rule_v2`]). A Rule v1 document is an error that points to the
    /// Rule v2 documentation.
    pub fn parse(raw: &str) -> Result<Self, Box<dyn Error>> {
        Self::from_definitions(
            rule_v2::read_file(raw)?
                .into_iter()
                .map(LoadedDefinition::from_v2)
                .collect(),
        )
    }

    /// Definitions in this order; an id or a Rule v2 UUID used twice fails.
    pub fn from_definitions(definitions: Vec<LoadedDefinition>) -> Result<Self, Box<dyn Error>> {
        let mut ids = BTreeSet::new();
        let mut uuids = BTreeMap::new();
        for definition in &definitions {
            if !ids.insert(definition.id()) {
                return Err(format!("duplicate rule id: {}", definition.id()).into());
            }
            if let Some(uuid) = definition.uuid()
                && let Some(first) = uuids.insert(uuid, definition.id())
            {
                return Err(format!(
                    "duplicate Rule v2 id {uuid} (rules '{first}' and '{}')",
                    definition.id()
                )
                .into());
            }
        }
        Ok(Self { definitions })
    }

    /// Concatenate `parts` in order; definitions only add, so an id or UUID
    /// that two parts define fails.
    pub fn merge(parts: impl IntoIterator<Item = LoadedRules>) -> Result<Self, Box<dyn Error>> {
        Self::from_definitions(
            parts
                .into_iter()
                .flat_map(|part| part.definitions)
                .collect(),
        )
    }

    pub fn definitions(&self) -> &[LoadedDefinition] {
        &self.definitions
    }

    pub fn into_definitions(self) -> Vec<LoadedDefinition> {
        self.definitions
    }

    pub fn get(&self, id: &str) -> Option<&LoadedDefinition> {
        self.definitions
            .iter()
            .find(|definition| definition.id() == id)
    }

    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }

    /// Mark every definition as shipped by package `id`.
    pub(crate) fn with_package_id(mut self, id: &str) -> Self {
        for definition in &mut self.definitions {
            definition.package_id = Some(id.to_owned());
        }
        self
    }

    /// Apply one override document: each entry sets a rule's `enabled` or
    /// `score`. Overrides change rules, never chain modifiers, so a modifier
    /// ID is an unknown `rule_id` and fails, as does an entry past
    /// [`MAX_APPLIED_OVERRIDES`] for one rule. `source` names the document in
    /// error messages (the CLI passes its path); `label` is recorded with
    /// each applied entry.
    pub fn apply_override_document(
        &mut self,
        document: &RuleOverrideDocument,
        source: &str,
        label: Option<&str>,
    ) -> Result<(), RuleOverrideError> {
        if document.version != 1 {
            return Err(RuleOverrideError::UnsupportedVersion(format!(
                "unsupported rule override version {} in {source}; only version 1 is supported",
                document.version
            )));
        }
        let _ = &document.description;
        for entry in &document.overrides {
            validate_rule_override_entry(entry, source).map_err(RuleOverrideError::InvalidEntry)?;
            let Some(rule) = self.definitions.iter_mut().find(|definition| {
                definition.kind() == DefinitionKind::Rule && definition.id() == entry.rule_id
            }) else {
                return Err(RuleOverrideError::UnknownRuleId(format!(
                    "unknown rule_id '{}' in rule override file {source}",
                    entry.rule_id
                )));
            };
            if rule.overrides.len() >= MAX_APPLIED_OVERRIDES {
                return Err(RuleOverrideError::TooManyOverrides(format!(
                    "rule '{}' has more than {MAX_APPLIED_OVERRIDES} override entries; \
                     the last is in rule override file {source}",
                    entry.rule_id
                )));
            }
            if let Some(enabled) = entry.enabled {
                rule.set_enabled(enabled);
            }
            if let Some(score) = entry.score {
                rule.set_score(score);
            }
            rule.overrides.push(AppliedOverride {
                source: source.to_owned(),
                label: label.map(str::to_owned),
                reason: entry.reason.clone(),
                enabled: entry.enabled,
                score: entry.score,
            });
        }
        Ok(())
    }

    /// Compile the enabled definitions the policy selects, in order. Notices
    /// of every definition carry over.
    pub fn compile(&self, policy: Option<&RulePolicy>) -> Result<CompiledRuleSet, Box<dyn Error>> {
        let mut rules = Vec::new();
        let mut modifiers = Vec::new();
        for definition in &self.definitions {
            if !definition.enabled() {
                continue;
            }
            match &definition.body {
                Body::Rule { rule, .. } => {
                    if policy_allows_rule(&rule.export.id, &rule.export.category, policy) {
                        rules.push(rule.clone());
                    }
                }
                Body::Chain { .. } => {}
            }
        }
        for definition in &self.definitions {
            if !definition.enabled() || !policy_allows_modifier(definition.id(), policy) {
                continue;
            }
            if let Body::Chain { modifier, .. } = &definition.body {
                modifiers.push(modifier.clone());
            }
        }
        let mut compiled = CompiledRuleSet::new(rules, modifiers, policy_name(policy));
        compiled.notices = self
            .definitions
            .iter()
            .flat_map(|definition| definition.notices().iter().cloned())
            .collect();
        Ok(compiled)
    }
}
