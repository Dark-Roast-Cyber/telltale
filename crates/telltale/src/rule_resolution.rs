//! Telltale's tiered rule resolution, shared by the CLI (`scan`, `watch`,
//! `rules`) and hooks: bundled rules, rule packages, the organization,
//! deployment and local rule folders, explicit rule files and in-memory
//! documents, merged by tier, then overrides and an optional policy.
//!
//! Callers discover the files (the CLI from its config roots); this module
//! only reads the paths it is given. [`crate::Pipeline::builder`] is the
//! simpler additive path for embedders that do not use rule folders.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use telltale_rules::package::{
    CommunityRules, PackageOrigin, RulePackage, RulePackageSummary, resolve_rule_packages,
};
use telltale_rules::{
    CompiledRuleSet, DefinitionKind, LoadedDefinition, LoadedRules, RuleLoadMode,
    RuleOverrideDocument, bundled_default_rules, parse_rule_policy,
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

/// Resolve rule content. `documents` are in-memory rule content, labelled by
/// source, loaded at the explicit tier: additive, so a definition ID that any
/// other tier already has is an error. `replacements` is text to use in place
/// of reading a named file (a rule, package, override or policy file).
///
/// Every file is one or more Rule v2 documents; a Rule v1 document fails.
/// Definitions merge by compiled id (the Rule v2 `name`): a higher tier
/// replaces a lower one in place, and must keep its UUID. An id twice within one tier, or a
/// UUID on two names, is an error.
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
    let (documents, packages) = load_rule_documents(
        pack_paths,
        explicit_rule_paths,
        documents,
        mode,
        &replacements,
    )?;
    if documents.is_empty() {
        return Err(
            "no rule documents loaded; remove --no-default-rules or pass at least one --rules file"
                .into(),
        );
    }

    let policy = match policy_path {
        Some(path) => Some(parse_rule_policy(&read_source(path, &replacements)?)?),
        None => None,
    };

    let (mut content, mut diagnostics) = merge_rule_documents(documents)?;
    diagnostics.packages = packages;
    apply_rule_overrides_from_paths(&mut content, override_paths, &replacements)?;
    Ok(RuleResolution {
        rule_set: content.compile(policy.as_ref())?,
        content,
        diagnostics,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RuleTier {
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
    pack_paths: &RulePackPaths,
    explicit_rule_paths: &[PathBuf],
    extra_documents: Vec<(String, LoadedRules)>,
    mode: RuleLoadMode,
    replacements: &BTreeMap<PathBuf, &str>,
) -> Result<(Vec<RuleDocument>, Vec<RulePackageSummary>), Box<dyn std::error::Error>> {
    let mut documents = Vec::new();
    let mut managed_paths = BTreeSet::new();
    if matches!(mode, RuleLoadMode::IncludeDefault) {
        documents.push(RuleDocument {
            tier: RuleTier::Builtin,
            source: "builtin:telltale.default".to_string(),
            rules: bundled_default_rules()?,
        });
    }
    let packages = load_package_documents(pack_paths, mode, &mut documents, replacements)?;

    for (tier, paths) in [
        (RuleTier::Organization, &pack_paths.organization),
        (RuleTier::Deployment, &pack_paths.deployment),
        (RuleTier::Local, &pack_paths.local),
    ] {
        for path in paths {
            managed_paths.insert(canonical_or_original(path));
            documents.push(load_rule_document(tier, path, replacements)?);
        }
    }

    for path in explicit_rule_paths {
        let canonical = canonical_or_original(path);
        if managed_paths.contains(&canonical) {
            continue;
        }
        documents.push(load_rule_document(RuleTier::Explicit, path, replacements)?);
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
    pack_paths: &RulePackPaths,
    mode: RuleLoadMode,
    documents: &mut Vec<RuleDocument>,
    replacements: &BTreeMap<PathBuf, &str>,
) -> Result<Vec<RulePackageSummary>, Box<dyn std::error::Error>> {
    let community = match (mode, pack_paths.community) {
        (RuleLoadMode::CustomOnly, CommunityRules::Embedded) => CommunityRules::SuppliedOnly,
        (_, community) => community,
    };
    let installed = pack_paths
        .packages
        .iter()
        .map(|path| {
            RulePackage::parse(&read_source(path, replacements)?).map_err(|error| {
                format!(
                    "invalid rule package '{}': {error}",
                    canonical_or_original(path).display()
                )
                .into()
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let mut summaries = Vec::new();
    for resolved in resolve_rule_packages(community, installed)? {
        summaries.push(resolved.summary());
        let location = match resolved.origin {
            PackageOrigin::Embedded => "embedded".to_string(),
            PackageOrigin::Supplied(index) => source_label_path(&pack_paths.packages[index]),
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

fn load_rule_document(
    tier: RuleTier,
    path: &Path,
    replacements: &BTreeMap<PathBuf, &str>,
) -> Result<RuleDocument, Box<dyn std::error::Error>> {
    let source = format!("{}:{}#document:0", tier.name(), source_label_path(path));
    let raw = read_source(path, replacements)?;
    let rules = LoadedRules::parse(&raw)
        .map_err(|error| format!("invalid rule document '{source}': {error}"))?;
    Ok(RuleDocument {
        tier,
        source,
        rules,
    })
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
    Ok((
        LoadedRules::from_definitions(definitions)?,
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
    format!(
        "duplicate rule id: {id} ({} from {first_source}; {} from {second_source})",
        first_kind.as_str(),
        second_kind.as_str(),
    )
    .into()
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
        return Err(format!(
            "rule '{id}' from {source} replaces the rule from {} but its Rule v2 id {new} differs \
             from {old}; a replacement keeps the id of the rule it replaces",
            existing.source
        )
        .into());
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

fn apply_rule_overrides_from_paths(
    content: &mut LoadedRules,
    override_paths: &[PathBuf],
    replacements: &BTreeMap<PathBuf, &str>,
) -> Result<(), Box<dyn std::error::Error>> {
    for path in override_paths {
        let raw = read_source(path, replacements)?;
        let document = serde_yaml::from_str::<RuleOverrideDocument>(&raw)
            .map_err(|error| format!("invalid rule override file '{}': {error}", path.display()))?;
        content.apply_override_document(&document, path)?;
    }
    Ok(())
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
