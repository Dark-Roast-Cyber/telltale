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

use serde::Serialize;
use telltale_rules::package::{
    CommunityRules, PackageOrigin, RulePackage, RulePackageSummary, resolve_rule_packages,
};
use telltale_rules::{
    CompiledRuleSet, DefinitionKind, LoadedDefinition, LoadedRules, RuleLoadMode,
    RuleOverrideDocument, RuleOverrideError, bundled_default_rules, parse_rule_policy,
};

use crate::{Pipeline, PipelineError};

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
        Pipeline::from_compiled(self.content, self.rule_set, self.diagnostics.packages)
    }
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
    /// An override entry has an empty `rule_id` or `reason`, or sets nothing.
    InvalidOverride,
    /// An override names a `rule_id` that no rule in the content has.
    UnknownRuleId,
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

    /// The input the failure concerns, as `<kind>:<label>`: `organization`,
    /// `override` or `explicit` (a `rules_document`) with the caller's label or
    /// the input's 1-based position among its kind, `builtin:telltale.default`,
    /// or `package:<id>@<version>:<origin>#document:<n>` with the ID and
    /// version the package declares. `None` when no single input is to blame.
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
    /// (tier, source, text), in load order within each tier.
    pub(crate) files: Vec<(RuleTier, String, String)>,
    /// Parsed documents at the explicit tier, after `files`.
    pub(crate) documents: Vec<(String, LoadedRules)>,
    /// Override documents: (source, text), applied in order.
    pub(crate) overrides: Vec<(String, String)>,
    pub(crate) policy: Option<String>,
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
        .map(|path| Ok((path.display().to_string(), read(path)?)))
        .collect::<std::io::Result<Vec<_>>>()?;
    resolve_rule_content(RuleContent {
        mode,
        community: pack_paths.community,
        packages,
        files,
        documents,
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
    diagnostics.packages = packages;
    for (source, raw) in &overrides {
        apply_rule_override(&mut content, source, raw)?;
    }
    Ok(RuleResolution {
        rule_set: content.compile(policy.as_ref())?,
        content,
        diagnostics,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RuleTier {
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
    rules: LoadedRules,
}

fn load_rule_documents(
    mode: RuleLoadMode,
    community: CommunityRules,
    packages: Vec<(String, String)>,
    files: Vec<(RuleTier, String, String)>,
    extra_documents: Vec<(String, LoadedRules)>,
) -> Result<(Vec<RuleDocument>, Vec<RulePackageSummary>), Box<dyn std::error::Error>> {
    let mut documents = Vec::new();
    if matches!(mode, RuleLoadMode::IncludeDefault) {
        documents.push(RuleDocument {
            tier: RuleTier::Builtin,
            source: "builtin:telltale.default".to_string(),
            rules: bundled_default_rules()?,
        });
    }
    let packages = load_package_documents(mode, community, packages, &mut documents)?;
    for (tier, source, raw) in files {
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
            rules,
        });
    }
    for (source, rules) in extra_documents {
        documents.push(RuleDocument {
            tier: RuleTier::Explicit,
            source,
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
    let mut summaries = Vec::new();
    for resolved in resolve_rule_packages(community, installed)? {
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
                rules,
            });
        }
    }
    Ok(summaries)
}

/// A rule file's source: `<tier>:<path>#document:0`.
fn file_source(tier: RuleTier, path: &Path) -> String {
    format!("{}:{}#document:0", tier.name(), source_label_path(path))
}

struct DefinitionLocation {
    kind: DefinitionKind,
    tier: RuleTier,
    index: usize,
    source: String,
    replaced_sources: Vec<String>,
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
                    tier,
                    &document.source,
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
    tier: RuleTier,
    source: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
                replaced_sources: Vec::new(),
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
    existing.source = source.to_string();
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

/// Parse and apply one override document named `source`.
fn apply_rule_override(
    content: &mut LoadedRules,
    source: &str,
    raw: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let document = serde_yaml::from_str::<RuleOverrideDocument>(raw).map_err(|error| {
        ContentFailure::new(
            RuleContentErrorCode::InvalidDocument,
            Some(source),
            format!("invalid rule override file '{source}': {error}"),
        )
    })?;
    content
        .apply_override_document(&document, source)
        .map_err(|error| {
            let code = match &error {
                RuleOverrideError::UnsupportedVersion(_) => {
                    RuleContentErrorCode::UnsupportedVersion
                }
                RuleOverrideError::InvalidEntry(_) => RuleContentErrorCode::InvalidOverride,
                RuleOverrideError::UnknownRuleId(_) => RuleContentErrorCode::UnknownRuleId,
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
