//! Loaded rule content: every rule and chain modifier that Rule v1 and Rule v2
//! files define, as one ordered list, before overrides and policy.
//!
//! A Rule v1 document or a Rule v2 file reads into [`LoadedRules`]. Callers
//! merge them, additively ([`LoadedRules::merge`]) or by tier (the CLI's
//! resolution), apply override documents, and compile with an optional
//! policy. The order of the list is the rule order and the modifier order of
//! the compiled set, which its fingerprint covers. Rule v1 definitions are
//! compiled only then, so a disabled or policy-filtered Rule v1 rule never
//! compiles, as before; Rule v2 definitions are compiled when read.
//!
//! Each definition also keeps the descriptive metadata the catalog reports
//! ([`DefinitionMetadata`]) and the package that shipped it, if any.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::Path;

use crate::{
    CompiledRule, CompiledRuleSet, ModifierDefinition, RuleDefinition, RuleLoadNotice,
    RuleOverrideDocument, RulePolicy, RuleSet, RuleV1CompatibilityModifier,
    RuleV1CompatibilityRule, apply_modifier_defaults, apply_rule_defaults, compile_matchers,
    parse_rule_document, policy_allows_modifier, policy_allows_rule, policy_name, provenance,
    rule_v2, validate_canonical_rule_id, validate_modifier_link, validate_rule_metadata,
    validate_rule_override_entry,
};

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
/// field they set; Rule v1 rules only `title`, `status`, `description`,
/// `author`, `references` and `falsepositives`, and Rule v1 modifiers only
/// `falsepositives`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DefinitionMetadata {
    /// The Rule v2 `id` (a UUID); `None` for Rule v1.
    pub uuid: Option<String>,
    pub title: Option<String>,
    /// The Sigma status of a Rule v2 document; Rule v1 text as written.
    pub status: Option<String>,
    pub description: Option<String>,
    pub references: Vec<String>,
    pub author: Option<String>,
    pub license: Option<String>,
    pub date: Option<String>,
    pub modified: Option<String>,
    pub related: Vec<RelatedRule>,
    /// A Rule v2 rule's `logsource`; `None` for chains and Rule v1.
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

/// One rule or modifier as loaded, with document defaults applied.
#[derive(Debug, Clone)]
pub struct LoadedDefinition {
    body: Body,
    metadata: DefinitionMetadata,
    package_id: Option<String>,
}

#[derive(Debug, Clone)]
enum Body {
    V1Rule(RuleDefinition),
    V1Modifier(ModifierDefinition),
    V2Rule {
        rule: CompiledRule,
        enabled: bool,
        notices: Vec<RuleLoadNotice>,
    },
    V2Chain {
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
            (Body::V1Rule(left), Body::V1Rule(right)) => left == right,
            (Body::V1Modifier(left), Body::V1Modifier(right)) => left == right,
            (
                Body::V2Rule {
                    rule: left,
                    enabled: left_enabled,
                    notices: left_notices,
                },
                Body::V2Rule {
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
                Body::V2Chain {
                    modifier: left,
                    enabled: left_enabled,
                },
                Body::V2Chain {
                    modifier: right,
                    enabled: right_enabled,
                },
            ) => left == right && left_enabled == right_enabled,
            _ => false,
        };
        body && self.metadata == other.metadata && self.package_id == other.package_id
    }
}

impl LoadedDefinition {
    fn from_v1_rule(rule: RuleDefinition) -> Self {
        let metadata = DefinitionMetadata {
            title: rule.title.clone(),
            status: rule.status.clone(),
            description: rule.description.clone(),
            references: rule.references.clone(),
            author: rule.author.clone(),
            falsepositives: rule.falsepositives.clone(),
            ..DefinitionMetadata::default()
        };
        Self {
            body: Body::V1Rule(rule),
            metadata,
            package_id: None,
        }
    }

    fn from_v1_modifier(modifier: ModifierDefinition) -> Self {
        let metadata = DefinitionMetadata {
            falsepositives: modifier.falsepositives.clone(),
            ..DefinitionMetadata::default()
        };
        Self {
            body: Body::V1Modifier(modifier),
            metadata,
            package_id: None,
        }
    }

    pub(crate) fn from_v2(definition: rule_v2::Definition) -> Self {
        let body = match definition.body {
            rule_v2::Body::Rule(rule) => Body::V2Rule {
                rule,
                enabled: definition.enabled,
                notices: definition.notices,
            },
            rule_v2::Body::Chain(modifier) => Body::V2Chain {
                modifier,
                enabled: definition.enabled,
            },
        };
        Self {
            body,
            metadata: definition.metadata,
            package_id: None,
        }
    }

    /// The compiled id: a Rule v1 `id` or a Rule v2 `name`.
    pub fn id(&self) -> &str {
        match &self.body {
            Body::V1Rule(rule) => &rule.id,
            Body::V1Modifier(modifier) => &modifier.id,
            Body::V2Rule { rule, .. } => &rule.export.id,
            Body::V2Chain { modifier, .. } => &modifier.id,
        }
    }

    pub fn kind(&self) -> DefinitionKind {
        match &self.body {
            Body::V1Rule(_) | Body::V2Rule { .. } => DefinitionKind::Rule,
            Body::V1Modifier(_) | Body::V2Chain { .. } => DefinitionKind::Modifier,
        }
    }

    /// Whether a Rule v2 document defines it.
    pub fn is_rule_v2(&self) -> bool {
        matches!(self.body, Body::V2Rule { .. } | Body::V2Chain { .. })
    }

    /// The Rule v2 `id` (a UUID); `None` for Rule v1.
    pub fn uuid(&self) -> Option<&str> {
        self.metadata.uuid.as_deref()
    }

    /// Whether it takes part before policy: its own `enabled`, document
    /// defaults, a Rule v2 status that loads disabled, and overrides.
    pub fn enabled(&self) -> bool {
        match &self.body {
            Body::V1Rule(rule) => rule.enabled,
            Body::V1Modifier(modifier) => modifier.enabled,
            Body::V2Rule { enabled, .. } | Body::V2Chain { enabled, .. } => *enabled,
        }
    }

    pub fn metadata(&self) -> &DefinitionMetadata {
        &self.metadata
    }

    /// The rule package that ships this definition; `None` for other content.
    pub fn package_id(&self) -> Option<&str> {
        self.package_id.as_deref()
    }

    /// Findings about this definition that did not stop it from loading.
    pub fn notices(&self) -> &[RuleLoadNotice] {
        match &self.body {
            Body::V2Rule { notices, .. } => notices,
            _ => &[],
        }
    }

    /// A rule's threat category; `None` for modifiers.
    pub fn category(&self) -> Option<&str> {
        match &self.body {
            Body::V1Rule(rule) => Some(&rule.category),
            Body::V2Rule { rule, .. } => Some(&rule.export.category),
            _ => None,
        }
    }

    /// A rule's severity (Rule v2 `level`); `None` for modifiers.
    pub fn severity(&self) -> Option<&str> {
        match &self.body {
            Body::V1Rule(rule) => Some(&rule.severity),
            Body::V2Rule { rule, .. } => Some(&rule.export.severity),
            _ => None,
        }
    }

    pub fn score(&self) -> u64 {
        match &self.body {
            Body::V1Rule(rule) => rule.score,
            Body::V1Modifier(modifier) => modifier.score,
            Body::V2Rule { rule, .. } => rule.export.score,
            Body::V2Chain { modifier, .. } => modifier.score,
        }
    }

    pub fn explanation(&self) -> &str {
        match &self.body {
            Body::V1Rule(rule) => &rule.explanation,
            Body::V1Modifier(modifier) => &modifier.explanation,
            Body::V2Rule { rule, .. } => &rule.export.explanation,
            Body::V2Chain { modifier, .. } => &modifier.explanation,
        }
    }

    pub fn signal_type(&self) -> &str {
        match &self.body {
            Body::V1Rule(rule) => &rule.signal_type,
            Body::V1Modifier(modifier) => &modifier.signal_type,
            Body::V2Rule { rule, .. } => &rule.export.signal_type,
            Body::V2Chain { modifier, .. } => &modifier.signal_type,
        }
    }

    /// Compiled ATLAS tags (`atlas:<ID>`).
    pub fn atlas_tags(&self) -> &[String] {
        match &self.body {
            Body::V1Rule(rule) => &rule.atlas_tags,
            Body::V1Modifier(modifier) => &modifier.atlas_tags,
            Body::V2Rule { rule, .. } => &rule.export.atlas_tags,
            Body::V2Chain { modifier, .. } => &modifier.atlas_tags,
        }
    }

    /// A rule's free-form Telltale labels (Rule v1 `tags`, Rule v2
    /// `telltale.tags`); empty for modifiers.
    pub fn tags(&self) -> &[String] {
        match &self.body {
            Body::V1Rule(rule) => &rule.tags,
            Body::V2Rule { rule, .. } => &rule.export.tags,
            _ => &[],
        }
    }

    pub fn when_all_categories(&self) -> &[String] {
        match &self.body {
            Body::V1Modifier(modifier) => &modifier.when_all_categories,
            Body::V2Chain { modifier, .. } => &modifier.when_all_categories,
            _ => &[],
        }
    }

    pub fn when_all_rule_ids(&self) -> &[String] {
        match &self.body {
            Body::V1Modifier(modifier) => &modifier.when_all_rule_ids,
            Body::V2Chain { modifier, .. } => &modifier.when_all_rule_ids,
            _ => &[],
        }
    }

    /// The compiled form whether or not the definition is enabled. A Rule v1
    /// definition is compiled here, so this fails where loading it enabled
    /// would.
    pub fn compile(&self) -> Result<CompiledDefinition, Box<dyn Error>> {
        Ok(match &self.body {
            Body::V1Rule(rule) => CompiledDefinition::Rule(compile_v1_rule(rule)?.export),
            Body::V1Modifier(modifier) => {
                CompiledDefinition::Modifier(compile_v1_modifier(modifier)?)
            }
            Body::V2Rule { rule, .. } => CompiledDefinition::Rule(rule.export.clone()),
            Body::V2Chain { modifier, .. } => CompiledDefinition::Modifier(modifier.clone()),
        })
    }

    /// The behaviour revision: the fingerprint of the one-definition export.
    /// `None` when a Rule v1 definition does not compile.
    pub fn behavior_fingerprint(&self) -> Option<String> {
        self.compile().ok().map(|compiled| match compiled {
            CompiledDefinition::Rule(rule) => provenance::rule_v1_rule_fingerprint(&rule),
            CompiledDefinition::Modifier(modifier) => {
                provenance::rule_v1_modifier_fingerprint(&modifier)
            }
        })
    }

    /// The metadata revision: a hash of the descriptive metadata the behaviour
    /// fingerprint leaves out.
    pub fn metadata_revision(&self) -> String {
        provenance::metadata_revision(&self.metadata)
    }

    fn set_enabled(&mut self, value: bool) {
        match &mut self.body {
            Body::V1Rule(rule) => rule.enabled = value,
            Body::V1Modifier(modifier) => modifier.enabled = value,
            Body::V2Rule { enabled, .. } | Body::V2Chain { enabled, .. } => *enabled = value,
        }
    }

    fn set_score(&mut self, score: u64) {
        match &mut self.body {
            Body::V1Rule(rule) => rule.score = score,
            Body::V1Modifier(modifier) => modifier.score = score,
            Body::V2Rule { rule, .. } => rule.export.score = score,
            Body::V2Chain { modifier, .. } => modifier.score = score,
        }
    }
}

/// An ordered list of loaded definitions, each id and each Rule v2 UUID once.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LoadedRules {
    definitions: Vec<LoadedDefinition>,
}

impl LoadedRules {
    /// Read one rule file: exactly one Rule v1 document, or one or more Rule v2
    /// rule and chain documents (see [`crate::rule_v2`]).
    pub fn parse(raw: &str) -> Result<Self, Box<dyn Error>> {
        let v1_error = match parse_rule_document(raw) {
            Ok(rule_set) => return Self::from_rule_set(rule_set),
            Err(error) => error,
        };
        match rule_v2::read_file(raw)? {
            rule_v2::RuleFile::V1 => Err(v1_error),
            rule_v2::RuleFile::V2(definitions) => Self::from_definitions(
                definitions
                    .into_iter()
                    .map(LoadedDefinition::from_v2)
                    .collect(),
            ),
        }
    }

    /// One Rule v1 document, its defaults applied to each definition.
    pub fn from_rule_set(rule_set: RuleSet) -> Result<Self, Box<dyn Error>> {
        rule_set.validate_version()?;
        let defaults = rule_set.defaults;
        let rules = rule_set.rules.into_iter().map(|mut rule| {
            apply_rule_defaults(&mut rule, &defaults);
            LoadedDefinition::from_v1_rule(rule)
        });
        let modifiers = rule_set.modifiers.into_iter().map(|mut modifier| {
            apply_modifier_defaults(&mut modifier, &defaults);
            LoadedDefinition::from_v1_modifier(modifier)
        });
        Self::from_definitions(rules.chain(modifiers).collect())
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

    /// Apply one override document read from `path`: each entry sets a rule's
    /// `enabled` or `score`. An entry naming no rule fails.
    pub fn apply_override_document(
        &mut self,
        document: &RuleOverrideDocument,
        path: &Path,
    ) -> Result<(), Box<dyn Error>> {
        if document.version != 1 {
            return Err(format!(
                "unsupported rule override version {} in {}; only version 1 is supported",
                document.version,
                path.display()
            )
            .into());
        }
        let _ = &document.description;
        for entry in &document.overrides {
            validate_rule_override_entry(entry, path)?;
            let Some(rule) = self.definitions.iter_mut().find(|definition| {
                definition.kind() == DefinitionKind::Rule && definition.id() == entry.rule_id
            }) else {
                return Err(format!(
                    "unknown rule_id '{}' in rule override file {}",
                    entry.rule_id,
                    path.display()
                )
                .into());
            };
            if let Some(enabled) = entry.enabled {
                rule.set_enabled(enabled);
            }
            if let Some(score) = entry.score {
                rule.set_score(score);
            }
        }
        Ok(())
    }

    /// Compile the enabled definitions the policy selects, in order. Every
    /// Rule v1 id is checked first, enabled or not, as a Rule v1 document's
    /// compile does. Notices of every definition carry over.
    pub fn compile(&self, policy: Option<&RulePolicy>) -> Result<CompiledRuleSet, Box<dyn Error>> {
        for definition in &self.definitions {
            match &definition.body {
                Body::V1Rule(rule) => validate_canonical_rule_id(&rule.id, "rule")?,
                Body::V1Modifier(modifier) => {
                    validate_canonical_rule_id(&modifier.id, "modifier")?;
                    for rule_id in &modifier.when_all_rule_ids {
                        validate_canonical_rule_id(rule_id, "modifier rule reference")?;
                    }
                }
                _ => {}
            }
        }
        let mut rules = Vec::new();
        let mut modifiers = Vec::new();
        for definition in &self.definitions {
            if !definition.enabled() {
                continue;
            }
            match &definition.body {
                Body::V1Rule(rule) => {
                    if policy_allows_rule(&rule.id, &rule.category, policy) {
                        rules.push(compile_v1_rule(rule)?);
                    }
                }
                Body::V2Rule { rule, .. } => {
                    if policy_allows_rule(&rule.export.id, &rule.export.category, policy) {
                        rules.push(rule.clone());
                    }
                }
                Body::V1Modifier(_) | Body::V2Chain { .. } => {}
            }
        }
        for definition in &self.definitions {
            if !definition.enabled() || !policy_allows_modifier(definition.id(), policy) {
                continue;
            }
            match &definition.body {
                Body::V1Modifier(modifier) => modifiers.push(compile_v1_modifier(modifier)?),
                Body::V2Chain { modifier, .. } => modifiers.push(modifier.clone()),
                Body::V1Rule(_) | Body::V2Rule { .. } => {}
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

fn compile_v1_rule(rule: &RuleDefinition) -> Result<CompiledRule, Box<dyn Error>> {
    // Defaults are already applied, so the pattern needs no case flag here.
    let matchers = compile_matchers(rule, false)?;
    Ok(CompiledRule::from_v1(rule.clone(), matchers))
}

fn compile_v1_modifier(
    modifier: &ModifierDefinition,
) -> Result<RuleV1CompatibilityModifier, Box<dyn Error>> {
    validate_rule_metadata(
        &modifier.id,
        &modifier.detection_class,
        &modifier.signal_type,
        &modifier.analytic_intent,
        &modifier.atlas_tags,
    )?;
    validate_modifier_link(
        &modifier.id,
        !modifier.when_all_categories.is_empty() || !modifier.when_all_rule_ids.is_empty(),
        modifier.link,
    )?;
    Ok(RuleV1CompatibilityModifier {
        id: modifier.id.clone(),
        score: modifier.score,
        detection_class: modifier.detection_class.clone(),
        signal_type: modifier.signal_type.clone(),
        analytic_intent: modifier.analytic_intent.clone(),
        atlas_tags: modifier.atlas_tags.clone(),
        when_all_categories: modifier.when_all_categories.clone(),
        when_all_rule_ids: modifier.when_all_rule_ids.clone(),
        link: modifier.link,
        falsepositives: modifier.falsepositives.clone(),
        explanation: modifier.explanation.clone(),
    })
}
