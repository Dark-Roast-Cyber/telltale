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
    CompiledRuleSet, ModifierDefinition, RuleDefaults, RuleDefinition, RuleLoadMode,
    RuleOverrideDocument, RulePolicy, RuleSet, apply_modifier_defaults, apply_rule_defaults,
    apply_rule_override_document, bundled_default_rule_set,
};

/// Managed rule content: tiered Rule v1 packs, installed rule packages, and
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
    pub rule_set: CompiledRuleSet,
    pub merged_rule_set: RuleSet,
    pub diagnostics: RuleResolutionDiagnostics,
}

/// Resolve rule content. `documents` are in-memory rule documents, labelled
/// by source, loaded at the explicit tier: additive, so a definition ID that
/// any other tier already has is an error. `replacements` is text to use in
/// place of reading a named file (a rule, package, override or policy file).
pub fn resolve_rule_set(
    pack_paths: &RulePackPaths,
    explicit_rule_paths: &[PathBuf],
    documents: Vec<(String, RuleSet)>,
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
        Some(path) => {
            let raw = read_source(path, &replacements)?;
            Some(serde_yaml::from_str::<RulePolicy>(&raw)?)
        }
        None => None,
    };

    let (mut rule_set, mut diagnostics) = merge_rule_documents(documents)?;
    diagnostics.packages = packages;
    apply_rule_overrides_from_paths(&mut rule_set, override_paths, &replacements)?;
    let merged_rule_set = rule_set.clone();
    Ok(RuleResolution {
        rule_set: rule_set.compile(policy.as_ref())?,
        merged_rule_set,
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
    rule_set: RuleSet,
}

fn load_rule_documents(
    pack_paths: &RulePackPaths,
    explicit_rule_paths: &[PathBuf],
    extra_documents: Vec<(String, RuleSet)>,
    mode: RuleLoadMode,
    replacements: &BTreeMap<PathBuf, &str>,
) -> Result<(Vec<RuleDocument>, Vec<RulePackageSummary>), Box<dyn std::error::Error>> {
    let mut documents = Vec::new();
    let mut managed_paths = BTreeSet::new();
    if matches!(mode, RuleLoadMode::IncludeDefault) {
        documents.push(RuleDocument {
            tier: RuleTier::Builtin,
            source: "builtin:telltale.default".to_string(),
            rule_set: bundled_default_rule_set()?,
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
    for (source, rule_set) in extra_documents {
        documents.push(RuleDocument {
            tier: RuleTier::Explicit,
            source,
            rule_set,
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
            PackageOrigin::Supplied(index) => canonical_or_original(&pack_paths.packages[index])
                .display()
                .to_string(),
        };
        let package = resolved.package;
        let identity = format!("{}@{}", package.id(), package.version());
        for (index, rule_set) in package.into_documents().into_iter().enumerate() {
            documents.push(RuleDocument {
                tier: RuleTier::Package,
                source: format!("package:{identity}:{location}#document:{index}"),
                rule_set,
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
    let identity_path = canonical_or_original(path);
    let source = format!("{}:{}#document:0", tier.name(), identity_path.display());
    let raw = read_source(path, replacements)?;
    let rule_set = serde_yaml::from_str::<RuleSet>(&raw)
        .map_err(|error| format!("invalid rule document '{source}': {error}"))?;
    Ok(RuleDocument {
        tier,
        source,
        rule_set,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DefinitionKind {
    Rule,
    Modifier,
}

impl DefinitionKind {
    fn name(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Modifier => "modifier",
        }
    }
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
) -> Result<(RuleSet, RuleResolutionDiagnostics), Box<dyn std::error::Error>> {
    for document in &documents {
        document
            .rule_set
            .validate_version()
            .map_err(|error| format!("invalid rule document '{}': {error}", document.source))?;
    }
    let mut descriptions = Vec::new();
    let mut rules = Vec::new();
    let mut modifiers = Vec::new();
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
        let tier_documents = documents.iter().filter(|document| document.tier == tier);
        let mut equal_tier_ids = BTreeMap::<String, (DefinitionKind, String)>::new();
        for document in tier_documents {
            for id in document
                .rule_set
                .rules
                .iter()
                .map(|rule| (&rule.id, DefinitionKind::Rule))
                .chain(
                    document
                        .rule_set
                        .modifiers
                        .iter()
                        .map(|modifier| (&modifier.id, DefinitionKind::Modifier)),
                )
            {
                if let Some((previous_kind, previous_source)) =
                    equal_tier_ids.insert(id.0.clone(), (id.1, document.source.clone()))
                {
                    return Err(duplicate_definition_error(
                        id.0.to_string(),
                        previous_kind,
                        &previous_source,
                        id.1,
                        &document.source,
                    ));
                }
            }
        }

        for document in documents.iter().filter(|document| document.tier == tier) {
            sources.push(document.source.clone());
            descriptions.push(document.rule_set.description.clone());
            let defaults = document.rule_set.defaults.clone();
            for mut rule in document.rule_set.rules.clone() {
                apply_rule_defaults(&mut rule, &defaults);
                upsert_rule_definition(
                    &mut locations,
                    &mut rules,
                    rule,
                    DefinitionKind::Rule,
                    tier,
                    &document.source,
                )?;
            }
            for mut modifier in document.rule_set.modifiers.clone() {
                apply_modifier_defaults(&mut modifier, &defaults);
                upsert_modifier_definition(
                    &mut locations,
                    &mut modifiers,
                    modifier,
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
            kind: location.kind.name().to_string(),
            winner: location.source,
            replaced_sources: location.replaced_sources,
        })
        .collect();
    Ok((
        RuleSet {
            version: 1,
            description: descriptions.join("; "),
            defaults: RuleDefaults {
                case_insensitive: false,
                enabled: true,
            },
            rules,
            modifiers,
        },
        RuleResolutionDiagnostics {
            sources,
            provenance,
            packages: Vec::new(),
        },
    ))
}

fn duplicate_definition_error(
    id: String,
    first_kind: DefinitionKind,
    first_source: &str,
    second_kind: DefinitionKind,
    second_source: &str,
) -> Box<dyn std::error::Error> {
    format!(
        "duplicate rule id: {id} ({} from {first_source}; {} from {second_source})",
        first_kind.name(),
        second_kind.name(),
    )
    .into()
}

fn upsert_rule_definition(
    locations: &mut BTreeMap<String, DefinitionLocation>,
    rules: &mut Vec<RuleDefinition>,
    rule: RuleDefinition,
    kind: DefinitionKind,
    tier: RuleTier,
    source: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    upsert_definition_location(locations, &rule.id, kind, tier, source, rules.len())?;
    if let Some(location) = locations.get_mut(&rule.id)
        && location.index < rules.len()
    {
        rules[location.index] = rule;
        location.replaced_sources.push(location.source.clone());
        location.source = source.to_string();
        return Ok(());
    }
    let index = rules.len();
    rules.push(rule);
    locations
        .get_mut(source_id_from_rule(&rules[index]))
        .unwrap()
        .index = index;
    Ok(())
}

fn source_id_from_rule(rule: &RuleDefinition) -> &str {
    &rule.id
}

fn upsert_modifier_definition(
    locations: &mut BTreeMap<String, DefinitionLocation>,
    modifiers: &mut Vec<ModifierDefinition>,
    modifier: ModifierDefinition,
    tier: RuleTier,
    source: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let id = modifier.id.clone();
    upsert_definition_location(
        locations,
        &id,
        DefinitionKind::Modifier,
        tier,
        source,
        modifiers.len(),
    )?;
    if let Some(location) = locations.get_mut(&id)
        && location.kind == DefinitionKind::Modifier
        && location.index < modifiers.len()
    {
        modifiers[location.index] = modifier;
        location.replaced_sources.push(location.source.clone());
        location.source = source.to_string();
        return Ok(());
    }
    modifiers.push(modifier);
    Ok(())
}

fn upsert_definition_location(
    locations: &mut BTreeMap<String, DefinitionLocation>,
    id: &str,
    kind: DefinitionKind,
    tier: RuleTier,
    source: &str,
    index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(existing) = locations.get_mut(id) else {
        locations.insert(
            id.to_string(),
            DefinitionLocation {
                kind,
                tier,
                index,
                source: source.to_string(),
                replaced_sources: Vec::new(),
            },
        );
        return Ok(());
    };
    if existing.kind != kind {
        return Err(duplicate_definition_error(
            id.to_string(),
            existing.kind,
            &existing.source,
            kind,
            source,
        ));
    }
    if tier.is_additive_only() || existing.tier >= tier {
        return Err(duplicate_definition_error(
            id.to_string(),
            existing.kind,
            &existing.source,
            kind,
            source,
        ));
    }
    Ok(())
}

/// The canonical path, or `path` itself when it cannot be canonicalized.
pub fn canonical_or_original(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn apply_rule_overrides_from_paths(
    rule_set: &mut RuleSet,
    override_paths: &[PathBuf],
    replacements: &BTreeMap<PathBuf, &str>,
) -> Result<(), Box<dyn std::error::Error>> {
    for path in override_paths {
        let raw = read_source(path, replacements)?;
        let document = serde_yaml::from_str::<RuleOverrideDocument>(&raw)
            .map_err(|error| format!("invalid rule override file '{}': {error}", path.display()))?;
        apply_rule_override_document(rule_set, &document, path)?;
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
