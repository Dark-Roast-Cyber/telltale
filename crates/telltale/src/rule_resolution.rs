//! Telltale's tiered rule resolution, shared by the CLI (`scan`, `watch`,
//! `rules`) and hooks: bundled rules, rule packages, the organization,
//! deployment and local rule folders, explicit rule files and in-memory
//! documents, merged by tier, then overrides and an optional policy.
//!
//! Callers discover the files (the CLI from its config roots); this module
//! only reads the paths it is given. [`crate::Pipeline::builder`] passes its
//! documents as text through the same resolution, so the CLI and an embedding
//! host resolve the same content the same way.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::rule_catalog::MAX_CATALOG_ENTRIES;
use crate::{Pipeline, PipelineError};
use serde::Serialize;
use telltale_rules::package::{
    CommunityRules, PackageOrigin, RulePackage, RulePackageSummary, resolve_rule_packages,
};
use telltale_rules::process_chain::BUNDLED_PROCESS_CHAIN_RULE_COUNT;
use telltale_rules::{
    CompiledRuleSet, DefinitionKind, LoadedDefinition, LoadedRules, RuleLoadMode,
    RuleOverrideDocument, RuleOverrideError, bundled_default_rules, parse_rule_policy,
};

/// Managed rule content: tiered rule files, installed rule packages, and
/// whether community content participates.
#[derive(Debug, Clone, Default)]
pub struct RulePackPaths {
    pub organization: Vec<PathBuf>,
    pub deployment: Vec<PathBuf>,
    pub local: Vec<PathBuf>,
    pub packages: Vec<PathBuf>,
    pub community: CommunityRules,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleProvenance {
    pub id: String,
    pub kind: String,
    pub winner: String,
    pub replaced_sources: Vec<String>,
    /// The tier of `winner`.
    #[serde(skip)]
    pub(crate) tier: RuleTier,
    /// The caller's label for the input of `winner`, if it gave one.
    #[serde(skip)]
    pub(crate) label: Option<String>,
    /// The tier of the definition `winner` replaced, if any.
    #[serde(skip)]
    pub(crate) replaced_tier: Option<RuleTier>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleResolutionDiagnostics {
    pub sources: Vec<String>,
    pub provenance: Vec<RuleProvenance>,
    pub packages: Vec<RulePackageSummary>,
}

#[derive(Debug, Clone)]
pub struct RuleResolution {
    /// The effective set: enabled definitions the policy selects.
    pub rule_set: CompiledRuleSet,
    /// Every definition after tier merge and overrides, before policy,
    /// disabled ones included.
    pub content: LoadedRules,
    pub diagnostics: RuleResolutionDiagnostics,
}

impl RuleResolution {
    /// A pipeline over the effective set, which keeps [`Self::content`] for
    /// its rule catalog.
    pub fn into_pipeline(self) -> Result<Pipeline, PipelineError> {
        Pipeline::from_compiled(self.content, self.rule_set, self.diagnostics)
    }

    /// Every definition as it takes effect, in content order: the view the
    /// CLI's rule listing and [`Pipeline::effective_configuration`] share.
    pub fn effective_definitions(&self) -> Vec<EffectiveDefinition<'_>> {
        effective_definitions(&self.content, &self.rule_set, &self.diagnostics.provenance)
    }
}

/// One rule or chain modifier as it takes effect. Its session score, kind
/// and applied overrides are on [`Self::definition`], overrides included.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct EffectiveDefinition<'a> {
    pub definition: &'a LoadedDefinition,
    /// Compiled into the effective set: its own `enabled`, overrides and the
    /// policy decide.
    pub enabled: bool,
    /// What left it out of the effective set; `None` exactly when enabled.
    pub disabled_by: Option<DisabledBy>,
    /// The tier whose definition is in effect.
    pub tier: RuleTier,
    /// The tier of the definition it replaced by ID, if any.
    pub replaced_tier: Option<RuleTier>,
    /// The source name of the input that supplied it, which for a rule file
    /// names its path.
    pub source: &'a str,
    /// The builder's label for the document that supplied it; `None` for
    /// bundled, packaged and file content.
    pub label: Option<&'a str>,
}

/// What left a definition out of the effective set, checked in this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DisabledBy {
    /// Its own definition, and no override sets `enabled`.
    Definition,
    /// The last override entry that sets `enabled` sets `false`.
    Override,
    /// It is enabled before policy, and the policy leaves it out.
    Policy,
}

/// [`RuleResolution::effective_definitions`] over a resolution's parts.
pub(crate) fn effective_definitions<'a>(
    content: &'a LoadedRules,
    rule_set: &CompiledRuleSet,
    provenance: &'a [RuleProvenance],
) -> Vec<EffectiveDefinition<'a>> {
    let export = rule_set.compatibility_export();
    let rules = export
        .rules()
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<BTreeSet<_>>();
    let modifiers = export
        .modifiers()
        .iter()
        .map(|modifier| modifier.id.as_str())
        .collect::<BTreeSet<_>>();
    let provenance = provenance
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    content
        .definitions()
        .iter()
        .map(|definition| {
            let id = definition.id();
            let winner = provenance.get(id);
            let enabled = match definition.kind() {
                DefinitionKind::Rule => rules.contains(id),
                DefinitionKind::Modifier => modifiers.contains(id),
            };
            let overridden_off = definition
                .overrides()
                .iter()
                .rev()
                .find_map(|applied| applied.enabled)
                == Some(false);
            EffectiveDefinition {
                definition,
                enabled,
                disabled_by: (!enabled).then_some(if definition.enabled() {
                    DisabledBy::Policy
                } else if overridden_off {
                    DisabledBy::Override
                } else {
                    DisabledBy::Definition
                }),
                tier: winner.map_or(RuleTier::Builtin, |winner| winner.tier),
                replaced_tier: winner.and_then(|winner| winner.replaced_tier),
                source: winner.map_or("", |winner| winner.winner.as_str()),
                label: winner.and_then(|winner| winner.label.as_deref()),
            }
        })
        .collect()
}

/// Closed reasons [`crate::PipelineBuilder::build`] rejects rule content.
/// Match these, not message text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleContentErrorCode {
    /// An input label is empty, longer than 64 characters, has a character
    /// outside `A-Z a-z 0-9 . _ -`, or names two inputs of one kind.
    InvalidLabel,
    /// An organization rule document or an override document does not parse.
    InvalidDocument,
    /// An override document declares a version other than 1.
    UnsupportedVersion,
    /// A definition ID repeats within one tier, across kinds, or where the
    /// tier only adds; or a replacement changes the Rule v2 id it replaces.
    DuplicateId,
    /// An override entry has an empty `rule_id` or `reason`, a `reason` over
    /// 256 characters or with control or invisible formatting characters
    /// other than tab and newline, or sets nothing.
    InvalidOverride,
    /// An override names a `rule_id` that no rule in the content has.
    UnknownRuleId,
    /// More inputs than the effective configuration describes: over 1024
    /// supplied documents, over 256 rule packages, over 3725 rules and chain
    /// modifiers (a 4096-entry catalog less the bundled process-chain rules),
    /// or over 256 override entries applied to one rule.
    ExceedsBounds,
}

impl RuleContentErrorCode {
    /// Stable text for the code, for logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLabel => "rule_content_invalid_label",
            Self::InvalidDocument => "rule_content_invalid_document",
            Self::UnsupportedVersion => "rule_content_unsupported_version",
            Self::DuplicateId => "rule_content_duplicate_id",
            Self::InvalidOverride => "rule_content_invalid_override",
            Self::UnknownRuleId => "rule_content_unknown_rule_id",
            Self::ExceedsBounds => "rule_content_exceeds_bounds",
        }
    }
}

/// Rule content the builder rejected: a closed code and the input it
/// concerns, never document text, rule IDs or paths. `Display` is the code.
/// It is the `Error::source()` of [`crate::PipelineError::Compilation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleContentError {
    code: RuleContentErrorCode,
    document: Option<String>,
}

impl RuleContentError {
    pub(crate) fn new(code: RuleContentErrorCode, document: Option<String>) -> Self {
        Self { code, document }
    }

    pub fn code(&self) -> RuleContentErrorCode {
        self.code
    }

    /// The input the failure concerns, as `<kind>:<label>`: `organization` or
    /// `override` with the caller's label or the input's 1-based position among
    /// its kind, `explicit:<n>` for the n-th `rules_document`, `package:<n>`
    /// for the n-th `rule_package` itself, `builtin:telltale.default`,
    /// or `package:<id>@<version>:<origin>#document:<n>` with the ID and
    /// version the package declares for one of its rule documents. `None` when
    /// no single input is to blame.
    pub fn document(&self) -> Option<&str> {
        self.document.as_deref()
    }
}

impl std::fmt::Display for RuleContentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for RuleContentError {}

/// A content failure with its full message, which can name paths and rule
/// IDs. The CLI shows the message; the builder keeps only the code and source.
#[derive(Debug)]
pub(crate) struct ContentFailure {
    code: RuleContentErrorCode,
    source: Option<String>,
    message: String,
}

impl ContentFailure {
    fn new(code: RuleContentErrorCode, source: Option<&str>, message: String) -> Self {
        Self {
            code,
            source: source.map(str::to_owned),
            message,
        }
    }

    pub(crate) fn without_message(&self) -> RuleContentError {
        RuleContentError::new(self.code, self.source.clone())
    }
}

impl std::fmt::Display for ContentFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ContentFailure {}

/// No tier supplied any rule document.
#[derive(Debug)]
pub(crate) struct NoRuleDocuments;

impl std::fmt::Display for NoRuleDocuments {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "no rule documents loaded; remove --no-default-rules or pass at least one --rules file",
        )
    }
}

impl std::error::Error for NoRuleDocuments {}

/// Rule content as named text, by tier: everything [`resolve_rule_content`]
/// resolves. Names label sources in diagnostics and messages.
pub(crate) struct RuleContent {
    pub(crate) mode: RuleLoadMode,
    pub(crate) community: CommunityRules,
    /// Rule packages: (location, text).
    pub(crate) packages: Vec<(String, String)>,
    /// Rule files at the organization, deployment, local or explicit tier:
    /// (tier, name, text), in load order within each tier.
    pub(crate) files: Vec<(RuleTier, InputName, String)>,
    /// Parsed documents at the explicit tier, after `files`.
    pub(crate) documents: Vec<(InputName, LoadedRules)>,
    /// Override documents: (name, text), applied in order.
    pub(crate) overrides: Vec<(InputName, String)>,
    pub(crate) policy: Option<String>,
}

/// An input's source name, for diagnostics and errors, and the label the
/// builder's caller gave it, carried into provenance and applied overrides.
#[derive(Clone, Debug)]
pub(crate) struct InputName {
    pub(crate) source: String,
    pub(crate) label: Option<String>,
}

impl InputName {
    /// A name without a caller's label, such as a file's.
    fn unlabeled(source: String) -> Self {
        Self {
            source,
            label: None,
        }
    }
}

/// Resolve rule content. `documents` are in-memory rule content, labelled by
/// source, loaded at the explicit tier: additive, so a definition ID that any
/// other tier already has is an error. `replacements` is text to use in place
/// of reading a named file (a rule, package, override or policy file).
///
/// Every file is one or more Rule v2 documents; a Rule v1 document fails.
/// Definitions merge by compiled id (the Rule v2 `name`): a higher tier
/// replaces a lower one in place, and must keep its UUID. An id twice within one tier, or a
/// UUID on two names, is an error. Every named file is read before any is
/// parsed; `resolve_rule_content` does the rest.
pub fn resolve_rule_set(
    pack_paths: &RulePackPaths,
    explicit_rule_paths: &[PathBuf],
    documents: Vec<(String, LoadedRules)>,
    policy_path: Option<&Path>,
    mode: RuleLoadMode,
    override_paths: &[PathBuf],
    replacements: &[(PathBuf, &str)],
) -> Result<RuleResolution, Box<dyn std::error::Error>> {
    // Keyed by the path as given and by its canonical form: a caller that
    // supplies every file it names (hooks) is found by the exact path, with no
    // second resolution that a changed symlink could send elsewhere.
    let replacements = replacements
        .iter()
        .flat_map(|(path, raw)| [(path.clone(), *raw), (canonical_or_original(path), *raw)])
        .collect::<BTreeMap<_, _>>();
    let read = |path: &Path| read_source(path, &replacements);
    let packages = pack_paths
        .packages
        .iter()
        .map(|path| Ok((source_label_path(path), read(path)?)))
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut managed_paths = BTreeSet::new();
    let mut files = Vec::new();
    for (tier, paths) in [
        (RuleTier::Organization, &pack_paths.organization),
        (RuleTier::Deployment, &pack_paths.deployment),
        (RuleTier::Local, &pack_paths.local),
    ] {
        for path in paths {
            managed_paths.insert(canonical_or_original(path));
            files.push((tier, file_source(tier, path), read(path)?));
        }
    }
    for path in explicit_rule_paths {
        if !managed_paths.contains(&canonical_or_original(path)) {
            let tier = RuleTier::Explicit;
            files.push((tier, file_source(tier, path), read(path)?));
        }
    }
    let overrides = override_paths
        .iter()
        .map(|path| {
            Ok((
                InputName::unlabeled(path.display().to_string()),
                read(path)?,
            ))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    resolve_rule_content(RuleContent {
        mode,
        community: pack_paths.community,
        packages,
        files,
        documents: documents
            .into_iter()
            .map(|(source, rules)| (InputName::unlabeled(source), rules))
            .collect(),
        overrides,
        policy: policy_path.map(read).transpose()?,
    })
}

/// Merge the tiers of `content`, apply its overrides in order, and compile
/// with its policy: the one resolution the CLI, hooks and the embedding
/// builder share.
pub(crate) fn resolve_rule_content(
    content: RuleContent,
) -> Result<RuleResolution, Box<dyn std::error::Error>> {
    let RuleContent {
        mode,
        community,
        packages,
        files,
        documents,
        overrides,
        policy,
    } = content;
    let (documents, packages) = load_rule_documents(mode, community, packages, files, documents)?;
    if documents.is_empty() {
        return Err(Box::new(NoRuleDocuments));
    }
    let policy = policy.as_deref().map(parse_rule_policy).transpose()?;
    let (mut content, mut diagnostics) = merge_rule_documents(documents)?;
    // A rule catalog lists every definition, and the bundled process-chain
    // rules when a query enables them, which loading cannot know.
    let limit = MAX_CATALOG_ENTRIES - BUNDLED_PROCESS_CHAIN_RULE_COUNT;
    if let Some(extra) = content.definitions().get(limit) {
        let source = diagnostics
            .provenance
            .iter()
            .find(|entry| entry.id == extra.id())
            .map(|entry| entry.winner.as_str());
        return Err(Box::new(ContentFailure::new(
            RuleContentErrorCode::ExceedsBounds,
            source,
            format!(
                "rule content has more than {limit} rules and chain modifiers; with the \
                 {BUNDLED_PROCESS_CHAIN_RULE_COUNT} bundled process-chain rules a rule \
                 catalog holds at most {MAX_CATALOG_ENTRIES}"
            ),
        )));
    }
    diagnostics.packages = packages;
    for (name, raw) in &overrides {
        apply_rule_override(&mut content, name, raw)?;
    }
    Ok(RuleResolution {
        rule_set: content.compile(policy.as_ref())?,
        content,
        diagnostics,
    })
}

/// Rule content tiers, lowest first; a higher tier replaces a definition in
/// place.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RuleTier {
    Builtin,
    Package,
    Organization,
    Deployment,
    Local,
    Explicit,
}

impl RuleTier {
    fn name(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Package => "package",
            Self::Organization => "organization",
            Self::Deployment => "deployment",
            Self::Local => "local-ui",
            Self::Explicit => "explicit",
        }
    }

    /// Packages and explicit `--rules` files add definitions; they never
    /// replace a definition from any tier.
    fn is_additive_only(self) -> bool {
        matches!(self, Self::Package | Self::Explicit)
    }
}

struct RuleDocument {
    tier: RuleTier,
    source: String,
    label: Option<String>,
    rules: LoadedRules,
}

fn load_rule_documents(
    mode: RuleLoadMode,
    community: CommunityRules,
    packages: Vec<(String, String)>,
    files: Vec<(RuleTier, InputName, String)>,
    extra_documents: Vec<(InputName, LoadedRules)>,
) -> Result<(Vec<RuleDocument>, Vec<RulePackageSummary>), Box<dyn std::error::Error>> {
    let mut documents = Vec::new();
    if matches!(mode, RuleLoadMode::IncludeDefault) {
        documents.push(RuleDocument {
            tier: RuleTier::Builtin,
            source: "builtin:telltale.default".to_string(),
            label: None,
            rules: bundled_default_rules()?,
        });
    }
    let packages = load_package_documents(mode, community, packages, &mut documents)?;
    for (tier, InputName { source, label }, raw) in files {
        let rules = LoadedRules::parse(&raw).map_err(|error| {
            ContentFailure::new(
                RuleContentErrorCode::InvalidDocument,
                Some(&source),
                format!("invalid rule document '{source}': {error}"),
            )
        })?;
        documents.push(RuleDocument {
            tier,
            source,
            label,
            rules,
        });
    }
    for (InputName { source, label }, rules) in extra_documents {
        documents.push(RuleDocument {
            tier: RuleTier::Explicit,
            source,
            label,
            rules,
        });
    }
    Ok((documents, packages))
}

/// Add the effective packages' documents at the package tier. Without bundled
/// defaults, the embedded community snapshot is omitted but an installed
/// community package still loads, like any other managed content.
fn load_package_documents(
    mode: RuleLoadMode,
    community: CommunityRules,
    packages: Vec<(String, String)>,
    documents: &mut Vec<RuleDocument>,
) -> Result<Vec<RulePackageSummary>, Box<dyn std::error::Error>> {
    let community = match (mode, community) {
        (RuleLoadMode::CustomOnly, CommunityRules::Embedded) => CommunityRules::SuppliedOnly,
        (_, community) => community,
    };
    let installed = packages
        .iter()
        .map(|(location, raw)| {
            RulePackage::parse(raw)
                .map_err(|error| format!("invalid rule package '{location}': {error}").into())
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let resolved = resolve_rule_packages(community, installed)?;
    if let Some(extra) = resolved.get(MAX_RULE_PACKAGES) {
        let source = match extra.origin {
            PackageOrigin::Supplied(index) => Some(package_input(index)),
            PackageOrigin::Embedded => None,
        };
        return Err(Box::new(ContentFailure::new(
            RuleContentErrorCode::ExceedsBounds,
            source.as_deref(),
            format!(
                "more than {MAX_RULE_PACKAGES} rule packages; the effective configuration \
                 lists at most {MAX_RULE_PACKAGES}"
            ),
        )));
    }
    let mut summaries = Vec::new();
    for resolved in resolved {
        summaries.push(resolved.summary());
        let location = match resolved.origin {
            PackageOrigin::Embedded => "embedded",
            PackageOrigin::Supplied(index) => packages[index].0.as_str(),
        };
        let package = resolved.package;
        let identity = format!("{}@{}", package.id(), package.version());
        for (index, rules) in package.into_documents().into_iter().enumerate() {
            documents.push(RuleDocument {
                tier: RuleTier::Package,
                source: format!("package:{identity}:{location}#document:{index}"),
                label: None,
                rules,
            });
        }
    }
    Ok(summaries)
}

/// Most rule packages the effective configuration lists.
const MAX_RULE_PACKAGES: usize = 256;

/// A rule package input's name in errors: `package:<n>`, its 1-based position
/// among the packages supplied, since a package that fails declares no
/// identity to name it by.
fn package_input(index: usize) -> String {
    format!("package:{}", index + 1)
}

/// A rule file's name: `<tier>:<path>#document:0`.
fn file_source(tier: RuleTier, path: &Path) -> InputName {
    InputName::unlabeled(format!(
        "{}:{}#document:0",
        tier.name(),
        source_label_path(path)
    ))
}

struct DefinitionLocation {
    kind: DefinitionKind,
    tier: RuleTier,
    index: usize,
    source: String,
    label: Option<String>,
    replaced_sources: Vec<String>,
    replaced_tier: Option<RuleTier>,
}

fn merge_rule_documents(
    documents: Vec<RuleDocument>,
) -> Result<(LoadedRules, RuleResolutionDiagnostics), Box<dyn std::error::Error>> {
    let mut definitions = Vec::<LoadedDefinition>::new();
    let mut locations = BTreeMap::<String, DefinitionLocation>::new();
    let mut sources = Vec::new();

    for tier in [
        RuleTier::Builtin,
        RuleTier::Package,
        RuleTier::Organization,
        RuleTier::Deployment,
        RuleTier::Local,
        RuleTier::Explicit,
    ] {
        let tier_documents = documents
            .iter()
            .filter(|document| document.tier == tier)
            .collect::<Vec<_>>();
        let mut equal_tier_ids = BTreeMap::<&str, (DefinitionKind, &str)>::new();
        for document in &tier_documents {
            for definition in document.rules.definitions() {
                if let Some((previous_kind, previous_source)) = equal_tier_ids.insert(
                    definition.id(),
                    (definition.kind(), document.source.as_str()),
                ) {
                    return Err(duplicate_definition_error(
                        definition.id(),
                        previous_kind,
                        previous_source,
                        definition.kind(),
                        &document.source,
                    ));
                }
            }
        }

        for document in tier_documents {
            sources.push(document.source.clone());
            for definition in document.rules.definitions() {
                upsert_definition(
                    &mut locations,
                    &mut definitions,
                    definition.clone(),
                    document,
                )?;
            }
        }
    }

    let provenance = locations
        .into_iter()
        .map(|(id, location)| RuleProvenance {
            id,
            kind: location.kind.as_str().to_string(),
            winner: location.source,
            replaced_sources: location.replaced_sources,
            tier: location.tier,
            label: location.label,
            replaced_tier: location.replaced_tier,
        })
        .collect();
    // Names are unique by now; a Rule v2 id on two names is what remains.
    let content = LoadedRules::from_definitions(definitions).map_err(|error| {
        ContentFailure::new(RuleContentErrorCode::DuplicateId, None, error.to_string())
    })?;
    Ok((
        content,
        RuleResolutionDiagnostics {
            sources,
            provenance,
            packages: Vec::new(),
        },
    ))
}

fn duplicate_definition_error(
    id: &str,
    first_kind: DefinitionKind,
    first_source: &str,
    second_kind: DefinitionKind,
    second_source: &str,
) -> Box<dyn std::error::Error> {
    Box::new(ContentFailure::new(
        RuleContentErrorCode::DuplicateId,
        Some(second_source),
        format!(
            "duplicate rule id: {id} ({} from {first_source}; {} from {second_source})",
            first_kind.as_str(),
            second_kind.as_str(),
        ),
    ))
}

/// Add `definition`, or let it replace the definition with its id from a
/// lower tier that allows replacement, at that definition's position.
fn upsert_definition(
    locations: &mut BTreeMap<String, DefinitionLocation>,
    definitions: &mut Vec<LoadedDefinition>,
    definition: LoadedDefinition,
    document: &RuleDocument,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tier, source) = (document.tier, document.source.as_str());
    let id = definition.id().to_owned();
    let kind = definition.kind();
    let Some(existing) = locations.get_mut(&id) else {
        locations.insert(
            id,
            DefinitionLocation {
                kind,
                tier,
                index: definitions.len(),
                source: source.to_string(),
                label: document.label.clone(),
                replaced_sources: Vec::new(),
                replaced_tier: None,
            },
        );
        definitions.push(definition);
        return Ok(());
    };
    if existing.kind != kind || tier.is_additive_only() || existing.tier >= tier {
        return Err(duplicate_definition_error(
            &id,
            existing.kind,
            &existing.source,
            kind,
            source,
        ));
    }
    let replaced = &definitions[existing.index];
    if let (Some(old), Some(new)) = (replaced.uuid(), definition.uuid())
        && old != new
    {
        return Err(Box::new(ContentFailure::new(
            RuleContentErrorCode::DuplicateId,
            Some(source),
            format!(
                "rule '{id}' from {source} replaces the rule from {} but its Rule v2 id {new} \
                 differs from {old}; a replacement keeps the id of the rule it replaces",
                existing.source
            ),
        )));
    }
    definitions[existing.index] = definition;
    existing.replaced_sources.push(existing.source.clone());
    existing.replaced_tier = Some(existing.tier);
    existing.source = source.to_string();
    existing.label = document.label.clone();
    existing.tier = tier;
    Ok(())
}

/// The canonical path, or `path` itself when it cannot be canonicalized.
pub fn canonical_or_original(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// `path` canonicalized for a rule source label, without the verbatim prefix
/// (`\\?\`) that canonicalizing a Windows drive path adds: labels show the path
/// as people write it.
fn source_label_path(path: &Path) -> String {
    let label = canonical_or_original(path).display().to_string();
    match label.strip_prefix(r"\\?\") {
        Some(plain) if plain.as_bytes().get(1) == Some(&b':') => plain.to_string(),
        _ => label,
    }
}

/// Parse and apply one override document named `name`.
fn apply_rule_override(
    content: &mut LoadedRules,
    name: &InputName,
    raw: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = name.source.as_str();
    let document = serde_yaml::from_str::<RuleOverrideDocument>(raw).map_err(|error| {
        ContentFailure::new(
            RuleContentErrorCode::InvalidDocument,
            Some(source),
            format!("invalid rule override file '{source}': {error}"),
        )
    })?;
    content
        .apply_override_document(&document, source, name.label.as_deref())
        .map_err(|error| {
            let code = match &error {
                RuleOverrideError::UnsupportedVersion(_) => {
                    RuleContentErrorCode::UnsupportedVersion
                }
                RuleOverrideError::UnknownRuleId(_) => RuleContentErrorCode::UnknownRuleId,
                RuleOverrideError::TooManyOverrides(_) => RuleContentErrorCode::ExceedsBounds,
                // `InvalidEntry`, and any reason added later, is an invalid override.
                _ => RuleContentErrorCode::InvalidOverride,
            };
            ContentFailure::new(code, Some(source), error.to_string()).into()
        })
}

/// The replacement text for `path`, else the file's contents.
fn read_source(path: &Path, replacements: &BTreeMap<PathBuf, &str>) -> std::io::Result<String> {
    if let Some(raw) = replacements.get(path) {
        return Ok((*raw).to_string());
    }
    match replacements.get(&canonical_or_original(path)) {
        Some(raw) => Ok((*raw).to_string()),
        None => fs::read_to_string(path),
    }
}
