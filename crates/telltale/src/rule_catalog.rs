//! Rule catalog: presentation metadata for the rules and chain modifiers of a
//! pipeline's content and, when enabled, the bundled process-chain pack, as
//! Rust values and as the versioned catalog v2 document. The effective
//! configuration document reports the same definitions with where each came
//! from and what changed it.
use std::collections::BTreeSet;

use crate::rule_resolution::{DisabledBy, RuleTier, effective_definitions};
use crate::{DetailedEvaluationOptions, Pipeline, PipelineError};
use telltale_rules::{DefinitionKind, LoadedDefinition};
use telltale_schema::effective_configuration::{
    AppliedOverrideV1, DefinitionKindV1, DisabledByV1, EFFECTIVE_CONFIGURATION_V1_ID,
    EffectiveConfigurationV1, EffectiveDefinitionV1, EffectivePackageV1, PackageOriginV1,
    RuleTierV1,
};
use telltale_schema::event::TELLTALE_VERSION;
use telltale_schema::rule_catalog::{
    RULE_CATALOG_V2_ID, RuleCatalogEntryV2, RuleCatalogLogSourceV2, RuleCatalogRelatedV2,
    RuleCatalogV2,
};

/// Most entries one catalog holds.
pub(crate) const MAX_CATALOG_ENTRIES: usize = 4096;
/// The Sigma statuses the catalog reports; any other status is reported as
/// `None`.
const SIGMA_STATUSES: &[&str] = &[
    "experimental",
    "test",
    "stable",
    "deprecated",
    "unsupported",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleCatalogKind {
    Rule,
    /// A chain modifier (a Rule v2 chain).
    Modifier,
    /// A rule of the bundled process-chain pack, listed when detailed scans
    /// enable it.
    ProcessChain,
}

/// Immutable display metadata, not executable content or a detection AST.
/// Session scores describe frozen compatibility contributions; action scores
/// describe individual native contributions, not host promotion totals.
/// A Rust value; [`Pipeline::rule_catalog_document`] is its versioned wire
/// form.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RuleCatalogEntry {
    id: String,
    kind: RuleCatalogKind,
    title: Option<String>,
    explanation: String,
    falsepositives: Vec<String>,
    category: Option<String>,
    severity: Option<String>,
    session_score: u64,
    action_score: Option<u64>,
    action_ordered: bool,
    action_within_seconds: Option<u64>,
    action_link: Option<String>,
    atlas_tags: Vec<String>,
    attack_techniques: Vec<String>,
    signal_type: String,
    tags: Vec<String>,
    enabled: bool,
    when_all_categories: Vec<String>,
    when_all_rule_ids: Vec<String>,
    package_id: Option<String>,
    uuid: Option<String>,
    status: Option<String>,
    description: Option<String>,
    references: Vec<String>,
    author: Option<String>,
    license: Option<String>,
    date: Option<String>,
    modified: Option<String>,
    related: Vec<RuleCatalogRelatedV2>,
    logsource: Option<RuleCatalogLogSourceV2>,
    behavior_fingerprint: Option<String>,
    metadata_revision: Option<String>,
}
impl RuleCatalogEntry {
    /// The compiled id: a Rule v2 `name` or a process-chain rule `id`.
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn kind(&self) -> RuleCatalogKind {
        self.kind
    }
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }
    pub fn explanation(&self) -> &str {
        &self.explanation
    }
    pub fn falsepositives(&self) -> &[String] {
        &self.falsepositives
    }
    pub fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }
    pub fn severity(&self) -> Option<&str> {
        self.severity.as_deref()
    }
    pub fn session_score(&self) -> u64 {
        self.session_score
    }
    pub fn action_score(&self) -> Option<u64> {
        self.action_score
    }
    pub fn action_ordered(&self) -> bool {
        self.action_ordered
    }
    pub fn action_within_seconds(&self) -> Option<u64> {
        self.action_within_seconds
    }
    pub fn action_link(&self) -> Option<&str> {
        self.action_link.as_deref()
    }
    pub fn atlas_tags(&self) -> &[String] {
        &self.atlas_tags
    }
    /// MITRE ATT&CK technique IDs, such as `T1105`: from a Rule v2 document's
    /// `attack.*` tags, or a process-chain rule's techniques.
    pub fn attack_techniques(&self) -> &[String] {
        &self.attack_techniques
    }
    pub fn signal_type(&self) -> &str {
        &self.signal_type
    }
    pub fn tags(&self) -> &[String] {
        &self.tags
    }
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn when_all_categories(&self) -> &[String] {
        &self.when_all_categories
    }
    pub fn when_all_rule_ids(&self) -> &[String] {
        &self.when_all_rule_ids
    }
    /// The rule package that ships this definition; `None` for core rules.
    pub fn package_id(&self) -> Option<&str> {
        self.package_id.as_deref()
    }
    /// The Rule v2 `id` (a UUID); `None` for process-chain rules.
    pub fn uuid(&self) -> Option<&str> {
        self.uuid.as_deref()
    }
    /// The Sigma status, if the definition has one.
    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
    pub fn references(&self) -> &[String] {
        &self.references
    }
    pub fn author(&self) -> Option<&str> {
        self.author.as_deref()
    }
    pub fn license(&self) -> Option<&str> {
        self.license.as_deref()
    }
    pub fn date(&self) -> Option<&str> {
        self.date.as_deref()
    }
    pub fn modified(&self) -> Option<&str> {
        self.modified.as_deref()
    }
    pub fn related(&self) -> &[RuleCatalogRelatedV2] {
        &self.related
    }
    pub fn logsource(&self) -> Option<&RuleCatalogLogSourceV2> {
        self.logsource.as_ref()
    }
    /// The behaviour revision (`sha256:<hex>`): the fingerprint of the
    /// definition's one-definition compiled export.
    pub fn behavior_fingerprint(&self) -> Option<&str> {
        self.behavior_fingerprint.as_deref()
    }
    /// The metadata revision (`sha256:<hex>`) of the descriptive metadata.
    pub fn metadata_revision(&self) -> Option<&str> {
        self.metadata_revision.as_deref()
    }
}

/// Catalog of the bundled content: core rules and the embedded community
/// package (the default pipeline's content), and the bundled process-chain
/// pack when `options.process_chain` enables it. See
/// [`Pipeline::rule_catalog`].
pub fn bundled_rule_catalog(
    options: &DetailedEvaluationOptions,
) -> Result<Vec<RuleCatalogEntry>, PipelineError> {
    if telltale_rules::bundled_default_rule_yaml().len() > 1024 * 1024 {
        return Err(catalog_bounds());
    }
    Pipeline::builder().build()?.rule_catalog(options)
}

/// [`bundled_rule_catalog`] as a versioned [`RuleCatalogV2`] document. See
/// [`Pipeline::rule_catalog_document`].
pub fn rule_catalog_document(
    options: &DetailedEvaluationOptions,
) -> Result<RuleCatalogV2, PipelineError> {
    Pipeline::builder().build()?.rule_catalog_document(options)
}

fn catalog_bounds() -> PipelineError {
    PipelineError::Compilation(Box::new(std::io::Error::other("catalog_exceeds_bounds")))
}

impl Pipeline {
    /// UI metadata for every rule and chain modifier this pipeline loaded,
    /// enabled or not, and for the bundled process-chain pack when
    /// `options.process_chain` enables it; deterministically ID-ordered and
    /// bounded. `enabled` and action scores describe this pipeline, its
    /// policy and overrides included. No source, environment, or filesystem
    /// access is performed.
    pub fn rule_catalog(
        &self,
        options: &DetailedEvaluationOptions,
    ) -> Result<Vec<RuleCatalogEntry>, PipelineError> {
        options
            .validate()
            .map_err(|_| PipelineError::InvalidOptions)?;
        if self.content.definitions().len() > MAX_CATALOG_ENTRIES {
            return Err(catalog_bounds());
        }
        // Validate exactly the switches accepted by detailed scans, including the
        // optional bundled process pack.
        let (plan, _) = self.compile_semantics(Some(options))?;
        let export = self.rule_set.compatibility_export();
        let effective_rules = export
            .rules()
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<BTreeSet<_>>();
        let mut entries = Vec::new();
        for definition in self.content.definitions() {
            let entry = match definition.kind() {
                DefinitionKind::Rule => {
                    let enabled = effective_rules.contains(definition.id());
                    RuleCatalogEntry {
                        kind: RuleCatalogKind::Rule,
                        action_score: enabled.then_some(definition.score()),
                        action_ordered: false,
                        action_within_seconds: None,
                        action_link: None,
                        enabled,
                        ..definition_entry(definition)
                    }
                }
                DefinitionKind::Modifier => {
                    let action = plan.action_modifier_semantics(definition.id(), options);
                    RuleCatalogEntry {
                        kind: RuleCatalogKind::Modifier,
                        action_score: action.as_ref().map(|semantics| semantics.score),
                        action_ordered: action.as_ref().is_some_and(|semantics| semantics.ordered),
                        action_within_seconds: action
                            .as_ref()
                            .and_then(|semantics| semantics.within_seconds),
                        action_link: action.as_ref().and_then(|semantics| {
                            semantics.link.map(str::to_owned).or_else(|| {
                                semantics
                                    .within_calls
                                    .map(|calls| format!("within_calls:{calls}"))
                            })
                        }),
                        enabled: action.is_some(),
                        ..definition_entry(definition)
                    }
                }
            };
            entries.push(entry);
        }
        if options.process_chain {
            let rules = telltale_rules::process_chain::bundled_process_chain_metadata()
                .map_err(|error| PipelineError::Compilation(Box::new(error)))?;
            if entries.len() + rules.len() > MAX_CATALOG_ENTRIES {
                return Err(catalog_bounds());
            }
            for rule in rules {
                entries.push(RuleCatalogEntry {
                    id: rule.id,
                    kind: RuleCatalogKind::ProcessChain,
                    title: Some(rule.title),
                    explanation: rule.reason,
                    falsepositives: rule.falsepositives,
                    category: Some(rule.category),
                    severity: Some(rule.severity),
                    session_score: rule.score,
                    action_score: rule.enabled.then_some(rule.score),
                    // Correlation steps match in sequence order.
                    action_ordered: rule.signal_type == "correlation",
                    action_within_seconds: rule.window_seconds,
                    action_link: None,
                    atlas_tags: Vec::new(),
                    attack_techniques: rule.attack_techniques,
                    signal_type: rule.signal_type.to_owned(),
                    tags: Vec::new(),
                    enabled: rule.enabled,
                    when_all_categories: Vec::new(),
                    when_all_rule_ids: Vec::new(),
                    package_id: None,
                    uuid: None,
                    status: None,
                    description: None,
                    references: Vec::new(),
                    author: None,
                    license: None,
                    date: None,
                    modified: None,
                    related: Vec::new(),
                    logsource: None,
                    behavior_fingerprint: None,
                    metadata_revision: None,
                });
            }
        }
        entries.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(entries)
    }

    /// [`Self::rule_catalog`] as a versioned [`RuleCatalogV2`] document, with
    /// this pipeline's semantic identity, which its `enabled` flags and action
    /// scores describe.
    pub fn rule_catalog_document(
        &self,
        options: &DetailedEvaluationOptions,
    ) -> Result<RuleCatalogV2, PipelineError> {
        let entries = self.rule_catalog(options)?;
        let semantic_identity = self.semantic_provenance(options)?.identity().to_owned();
        Ok(RuleCatalogV2 {
            schema: RULE_CATALOG_V2_ID.to_owned(),
            telltale_version: TELLTALE_VERSION.to_owned(),
            semantic_identity,
            entries: entries
                .into_iter()
                .map(RuleCatalogEntry::into_wire)
                .collect(),
        })
    }
}

impl Pipeline {
    /// What this pipeline runs, as a versioned [`EffectiveConfigurationV1`]
    /// document: its rule packages and the builder's text inputs by label and
    /// content SHA-256, and for every entry of [`Self::rule_catalog_document`]
    /// its effective `enabled` flag and what turned it off, its scores, the
    /// tier whose definition is in effect and the tier it replaced, and the
    /// overrides applied to it with their reasons. It holds no matchers, paths
    /// or document text. No source, environment, or filesystem access is
    /// performed.
    pub fn effective_configuration(
        &self,
        options: &DetailedEvaluationOptions,
    ) -> Result<EffectiveConfigurationV1, PipelineError> {
        let (plan, _) = self.compile_semantics(Some(options))?;
        let semantic_identity = plan
            .semantic_provenance_with_options(options)
            .identity()
            .to_owned();
        let process_chain = if options.process_chain {
            telltale_rules::process_chain::bundled_process_chain_metadata()
                .map_err(|error| PipelineError::Compilation(Box::new(error)))?
        } else {
            Vec::new()
        };
        if self.content.definitions().len() + process_chain.len() > MAX_CATALOG_ENTRIES {
            return Err(catalog_bounds());
        }
        let mut packages = self
            .rule_packages
            .iter()
            .map(|package| EffectivePackageV1 {
                id: package.id.clone(),
                version: package.version.clone(),
                content_sha256: package.content_sha256.clone(),
                origin: if package.embedded {
                    PackageOriginV1::Embedded
                } else {
                    PackageOriginV1::Supplied
                },
            })
            .collect::<Vec<_>>();
        packages.sort_by(|left, right| left.id.cmp(&right.id));
        let loaded = effective_definitions(&self.content, &self.rule_set, &self.provenance)
            .into_iter()
            .map(|effective| {
                let definition = effective.definition;
                let (kind, action_score) = match definition.kind() {
                    DefinitionKind::Rule => (
                        DefinitionKindV1::Rule,
                        effective.enabled.then_some(definition.score()),
                    ),
                    DefinitionKind::Modifier => (
                        DefinitionKindV1::Modifier,
                        plan.action_modifier_semantics(definition.id(), options)
                            .map(|semantics| semantics.score),
                    ),
                };
                EffectiveDefinitionV1 {
                    id: definition.id().to_owned(),
                    kind,
                    enabled: effective.enabled,
                    disabled_by: effective.disabled_by.map(|cause| match cause {
                        DisabledBy::Definition => DisabledByV1::Definition,
                        DisabledBy::Override => DisabledByV1::Override,
                        DisabledBy::Policy => DisabledByV1::Policy,
                    }),
                    session_score: definition.score(),
                    action_score,
                    tier: tier_v1(effective.tier),
                    replaced_tier: effective.replaced_tier.map(tier_v1),
                    package_id: definition.package_id().map(str::to_owned),
                    document: effective.label.map(str::to_owned),
                    overrides: definition
                        .overrides()
                        .iter()
                        .map(|applied| AppliedOverrideV1 {
                            document: applied.label.clone(),
                            reason: applied.reason.clone(),
                            enabled: applied.enabled,
                            score: applied.score,
                        })
                        .collect(),
                }
            });
        // Process-chain rules are bundled, never overridden or replaced, and
        // off only in their own definition.
        let process_chain = process_chain.into_iter().map(|rule| EffectiveDefinitionV1 {
            id: rule.id,
            kind: DefinitionKindV1::ProcessChain,
            enabled: rule.enabled,
            disabled_by: (!rule.enabled).then_some(DisabledByV1::Definition),
            session_score: rule.score,
            action_score: rule.enabled.then_some(rule.score),
            tier: RuleTierV1::Builtin,
            replaced_tier: None,
            package_id: None,
            document: None,
            overrides: Vec::new(),
        });
        let mut definitions = loaded.chain(process_chain).collect::<Vec<_>>();
        definitions.sort_by(|left, right| left.id.cmp(&right.id));
        let document = EffectiveConfigurationV1 {
            schema: EFFECTIVE_CONFIGURATION_V1_ID.to_owned(),
            telltale_version: TELLTALE_VERSION.to_owned(),
            semantic_identity,
            packages,
            documents: self.documents.clone(),
            definitions,
        };
        document
            .to_json()
            .map_err(|error| PipelineError::Compilation(Box::new(error)))?;
        Ok(document)
    }
}

/// The wire form of a tier.
fn tier_v1(tier: RuleTier) -> RuleTierV1 {
    match tier {
        RuleTier::Builtin => RuleTierV1::Builtin,
        RuleTier::Package => RuleTierV1::Package,
        RuleTier::Organization => RuleTierV1::Organization,
        RuleTier::Deployment => RuleTierV1::Deployment,
        RuleTier::Local => RuleTierV1::Local,
        RuleTier::Explicit => RuleTierV1::Explicit,
    }
}

/// The fields a definition sets whatever its kind; the caller sets the kind,
/// enablement and action fields.
fn definition_entry(definition: &LoadedDefinition) -> RuleCatalogEntry {
    let metadata = definition.metadata();
    RuleCatalogEntry {
        id: definition.id().to_owned(),
        kind: RuleCatalogKind::Rule,
        title: metadata.title.clone(),
        explanation: definition.explanation().to_owned(),
        falsepositives: metadata.falsepositives.clone(),
        category: definition.category().map(str::to_owned),
        severity: definition.severity().map(str::to_owned),
        session_score: definition.score(),
        action_score: None,
        action_ordered: false,
        action_within_seconds: None,
        action_link: None,
        atlas_tags: definition.atlas_tags().to_vec(),
        attack_techniques: metadata.attack_techniques(),
        signal_type: definition.signal_type().to_owned(),
        tags: definition.tags().to_vec(),
        enabled: false,
        when_all_categories: definition.when_all_categories().to_vec(),
        when_all_rule_ids: definition.when_all_rule_ids().to_vec(),
        package_id: definition.package_id().map(str::to_owned),
        uuid: metadata.uuid.clone(),
        status: metadata
            .status
            .clone()
            .filter(|status| SIGMA_STATUSES.contains(&status.as_str())),
        description: metadata.description.clone(),
        references: metadata.references.clone(),
        author: metadata.author.clone(),
        license: metadata.license.clone(),
        date: metadata.date.clone(),
        modified: metadata.modified.clone(),
        related: metadata
            .related
            .iter()
            .map(|related| RuleCatalogRelatedV2 {
                id: related.id.clone(),
                kind: related.kind.clone(),
            })
            .collect(),
        logsource: metadata
            .logsource
            .as_ref()
            .map(|logsource| RuleCatalogLogSourceV2 {
                product: logsource.product.clone(),
                category: logsource.category.clone(),
                service: logsource.service.clone(),
            }),
        behavior_fingerprint: Some(definition.behavior_fingerprint()),
        metadata_revision: Some(definition.metadata_revision()),
    }
}

impl RuleCatalogEntry {
    fn into_wire(self) -> RuleCatalogEntryV2 {
        RuleCatalogEntryV2 {
            kind: match self.kind {
                RuleCatalogKind::Rule => "rule",
                RuleCatalogKind::Modifier => "modifier",
                RuleCatalogKind::ProcessChain => "process_chain",
            }
            .to_owned(),
            id: self.id,
            title: self.title,
            explanation: self.explanation,
            falsepositives: self.falsepositives,
            category: self.category,
            severity: self.severity,
            session_score: self.session_score,
            action_score: self.action_score,
            action_ordered: self.action_ordered,
            action_within_seconds: self.action_within_seconds,
            action_link: self.action_link,
            atlas_tags: self.atlas_tags,
            attack_techniques: self.attack_techniques,
            signal_type: self.signal_type,
            tags: self.tags,
            enabled: self.enabled,
            when_all_categories: self.when_all_categories,
            when_all_rule_ids: self.when_all_rule_ids,
            package_id: self.package_id,
            uuid: self.uuid,
            status: self.status,
            description: self.description,
            references: self.references,
            author: self.author,
            license: self.license,
            date: self.date,
            modified: self.modified,
            related: self.related,
            logsource: self.logsource,
            behavior_fingerprint: self.behavior_fingerprint,
            metadata_revision: self.metadata_revision,
        }
    }
}

#[cfg(test)]
mod tests;
