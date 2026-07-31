//! Rule loading for the CLI: filesystem-facing wrappers around the I/O-free
//! rule language in `telltale-rules`, which this module re-exports.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

pub(crate) use telltale_rules::*;

#[derive(Debug, Clone, Default)]
pub struct RulePackPaths {
    pub organization: Vec<PathBuf>,
    pub deployment: Vec<PathBuf>,
    pub local: Vec<PathBuf>,
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
}

#[derive(Debug, Clone)]
pub struct RuleResolution {
    pub rule_set: CompiledRuleSet,
    pub merged_rule_set: RuleSet,
    pub diagnostics: RuleResolutionDiagnostics,
}

pub fn default_rule_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("config/rules/tool-call-regex.yaml")
}

#[cfg(test)]
fn load_rule_set_from_paths_with_mode_and_override_paths(
    rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
    mode: RuleLoadMode,
    override_paths: &[PathBuf],
) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        &RulePackPaths::default(),
        rule_paths,
        policy_path,
        mode,
        override_paths,
        &[],
    )
    .map(|resolution| resolution.rule_set)
}

pub(crate) fn resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
    pack_paths: &RulePackPaths,
    explicit_rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
    mode: RuleLoadMode,
    override_paths: &[PathBuf],
    replacements: &[(PathBuf, &str)],
) -> Result<RuleResolution, Box<dyn std::error::Error>> {
    let replacements = replacements
        .iter()
        .map(|(path, raw)| (canonical_or_original(path), *raw))
        .collect::<BTreeMap<_, _>>();
    let documents = load_rule_documents(pack_paths, explicit_rule_paths, mode, &replacements)?;
    if documents.is_empty() {
        return Err(
            "no rule documents loaded; remove --no-default-rules or pass at least one --rules file"
                .into(),
        );
    }

    let policy = match policy_path {
        Some(path) => {
            let raw = fs::read_to_string(path)?;
            Some(serde_yaml::from_str::<RulePolicy>(&raw)?)
        }
        None => None,
    };

    let (mut rule_set, diagnostics) = merge_rule_documents(documents)?;
    apply_rule_overrides_from_paths(&mut rule_set, override_paths)?;
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
    Organization,
    Deployment,
    Local,
    Explicit,
}

impl RuleTier {
    fn name(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Organization => "organization",
            Self::Deployment => "deployment",
            Self::Local => "local-ui",
            Self::Explicit => "explicit",
        }
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
    mode: RuleLoadMode,
    replacements: &BTreeMap<PathBuf, &str>,
) -> Result<Vec<RuleDocument>, Box<dyn std::error::Error>> {
    let mut documents = Vec::new();
    let mut managed_paths = BTreeSet::new();
    if matches!(mode, RuleLoadMode::IncludeDefault) {
        documents.push(RuleDocument {
            tier: RuleTier::Builtin,
            source: "builtin:telltale.default".to_string(),
            rule_set: bundled_default_rule_set()?,
        });
    }

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
        if !should_load_rule_path(path, mode) {
            continue;
        }
        let canonical = canonical_or_original(path);
        if managed_paths.contains(&canonical) {
            continue;
        }
        documents.push(load_rule_document(RuleTier::Explicit, path, replacements)?);
    }
    Ok(documents)
}

fn load_rule_document(
    tier: RuleTier,
    path: &Path,
    replacements: &BTreeMap<PathBuf, &str>,
) -> Result<RuleDocument, Box<dyn std::error::Error>> {
    let identity_path = canonical_or_original(path);
    let source = format!("{}:{}#document:0", tier.name(), identity_path.display());
    let raw = match replacements.get(&canonical_or_original(path)) {
        Some(raw) => (*raw).to_string(),
        None => fs::read_to_string(path)?,
    };
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
    let mut descriptions = Vec::new();
    let mut rules = Vec::new();
    let mut modifiers = Vec::new();
    let mut locations = BTreeMap::<String, DefinitionLocation>::new();
    let mut sources = Vec::new();

    for tier in [
        RuleTier::Builtin,
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

fn apply_rule_defaults(rule: &mut RuleDefinition, defaults: &RuleDefaults) {
    if !defaults.enabled {
        rule.enabled = false;
    }
    if defaults.case_insensitive {
        if let Some(regex) = rule.regex.as_mut() {
            *regex = format!("(?i:{regex})");
        }
        if let Some(detection) = rule.detection.as_mut() {
            for regex in detection.selection.values_mut() {
                *regex = format!("(?i:{regex})");
            }
        }
    }
}

fn apply_modifier_defaults(modifier: &mut ModifierDefinition, defaults: &RuleDefaults) {
    if !defaults.enabled {
        modifier.enabled = false;
    }
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
    if tier == RuleTier::Explicit || existing.tier >= tier {
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

fn canonical_or_original(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

pub(crate) fn should_load_rule_path(path: &Path, mode: RuleLoadMode) -> bool {
    if matches!(mode, RuleLoadMode::CustomOnly) {
        return true;
    }

    let default_path = default_rule_path();
    match (path.canonicalize(), default_path.canonicalize()) {
        (Ok(path), Ok(default_path)) => path != default_path,
        _ => path != default_path,
    }
}

fn apply_rule_overrides_from_paths(
    rule_set: &mut RuleSet,
    override_paths: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error>> {
    for path in override_paths {
        let raw = fs::read_to_string(path)?;
        let document = serde_yaml::from_str::<RuleOverrideDocument>(&raw)
            .map_err(|error| format!("invalid rule override file '{}': {error}", path.display()))?;
        apply_rule_override_document(rule_set, &document, path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::{
        RuleLoadMode, RulePackPaths, canonical_or_original,
        resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements,
    };

    fn rule_yaml(id: &str, regex: &str, score: u64) -> String {
        format!(
            r#"version: 1
description: Test rules.
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: {id}
    category: test
    severity: low
    score: {score}
    targets: [command]
    regex: '{regex}'
    tags: [test]
    explanation: Synthetic test rule.
modifiers: []
"#
        )
    }

    fn write_rule(path: &std::path::Path, id: &str, regex: &str, score: u64) {
        fs::create_dir_all(path.parent().expect("rule parent")).expect("rule parent");
        fs::write(path, rule_yaml(id, regex, score)).expect("rule file");
    }

    fn fixture_pack_paths(name: &str) -> RulePackPaths {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rule_packs")
            .join(name);
        let discovered = crate::config::discover_local_config_files(
            std::slice::from_ref(&root),
            false,
            crate::config::LocalConfigDiscoveryKind::Rules,
        )
        .expect("fixture pack discovery");
        RulePackPaths {
            organization: discovered.organization_rule_paths,
            deployment: discovered.deployment_rule_paths,
            local: discovered.local_rule_paths,
        }
    }

    #[test]
    fn fixture_packs_are_additive_and_stably_ordered() {
        let resolution =
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &fixture_pack_paths("ordered"),
                &[],
                None,
                RuleLoadMode::CustomOnly,
                &[],
                &[],
            )
            .expect("resolve fixture packs");

        assert_eq!(
            resolution
                .merged_rule_set
                .rules
                .iter()
                .map(|rule| rule.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "pack.organization",
                "secret.env.read",
                "pack.deployment",
                "pack.local"
            ]
        );
    }

    #[test]
    fn fixture_pack_replaces_bundled_rule_and_wins_evaluation() {
        let resolution =
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &fixture_pack_paths("ordered"),
                &[],
                None,
                RuleLoadMode::IncludeDefault,
                &[],
                &[],
            )
            .expect("resolve bundled fixture replacement");
        let replacement = resolution
            .merged_rule_set
            .rules
            .iter()
            .find(|rule| rule.id == "secret.env.read")
            .expect("replaced bundled rule");
        assert_eq!(replacement.score, 77);
        let provenance = resolution
            .diagnostics
            .provenance
            .iter()
            .find(|entry| entry.id == "secret.env.read")
            .expect("replacement provenance");
        assert!(provenance.winner.contains("deployment:"));
        assert_eq!(
            provenance.replaced_sources,
            vec!["builtin:telltale.default"]
        );
        let matched = resolution
            .rule_set
            .evaluate(&[("command", "fixture-secret-marker")])
            .expect("replacement should evaluate")
            .expect("replacement should match");
        assert!(matched.rule_ids.contains(&"secret.env.read".to_string()));
    }

    #[test]
    fn fixture_pack_equal_tier_conflict_reports_sources() {
        let error = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &fixture_pack_paths("conflict"),
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("equal-tier fixture conflict");
        let error = error.to_string();
        assert!(error.starts_with("duplicate rule id: pack.conflict"));
        assert!(error.contains("10-first.yaml"));
        assert!(error.contains("20-second.yaml"));
    }

    #[test]
    fn fixture_modifier_replacement_and_conflict_follow_rule_semantics() {
        let replacement =
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &fixture_pack_paths("modifier-replacement"),
                &[],
                None,
                RuleLoadMode::CustomOnly,
                &[],
                &[],
            )
            .expect("modifier replacement");
        assert_eq!(replacement.merged_rule_set.modifiers[0].score, 9);
        assert_eq!(
            replacement
                .diagnostics
                .provenance
                .iter()
                .find(|entry| entry.id == "pack.modifier")
                .expect("modifier provenance")
                .replaced_sources
                .len(),
            1
        );

        let conflict = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &fixture_pack_paths("modifier-conflict"),
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("modifier conflict");
        assert!(
            conflict
                .to_string()
                .starts_with("duplicate rule id: pack.modifier.conflict")
        );
    }

    #[test]
    fn fixture_cross_kind_collision_is_rejected() {
        let error = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &fixture_pack_paths("cross-kind"),
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("cross-kind collision");
        let error = error.to_string();
        assert!(error.starts_with("duplicate rule id: pack.cross_kind"));
        assert!(error.contains("rule"));
        assert!(error.contains("modifier"));
        assert!(error.contains("10-rule.yaml"));
        assert!(error.contains("20-modifier.yaml"));
    }

    #[test]
    fn canonical_alias_of_managed_file_is_not_loaded_twice() {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rule_packs/ordered");
        let managed = root.join("organization-rules.d/10-organization.yaml");
        let alias = root
            .join("organization-rules.d")
            .join(".")
            .join("10-organization.yaml");
        let resolution =
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &RulePackPaths {
                    organization: vec![managed],
                    ..RulePackPaths::default()
                },
                &[alias],
                None,
                RuleLoadMode::CustomOnly,
                &[],
                &[],
            )
            .expect("canonical alias dedupe");
        assert_eq!(resolution.rule_set.rule_count(), 1);
    }

    #[test]
    fn ordered_packs_add_rules_and_replace_in_place() {
        let temp = tempdir().expect("tempdir");
        let deployment_first = temp.path().join("rules.d/a-deployment.yaml");
        let deployment_second = temp.path().join("rules.d/b-deployment.yaml");
        let local = temp.path().join("ui-rules.d/local.yaml");
        write_rule(&deployment_first, "pack.first", "first", 1);
        write_rule(&deployment_second, "pack.second", "second", 2);
        write_rule(&local, "pack.first", "replacement", 9);
        write_rule(
            &temp.path().join("organization-rules.d/organization.yaml"),
            "organization.only",
            "organization",
            3,
        );

        let resolution =
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &RulePackPaths {
                    organization: vec![temp.path().join("organization-rules.d/organization.yaml")],
                    deployment: vec![deployment_first, deployment_second],
                    local: vec![local],
                },
                &[],
                None,
                RuleLoadMode::CustomOnly,
                &[],
                &[],
            )
            .expect("resolve packs");

        assert_eq!(
            resolution
                .merged_rule_set
                .rules
                .iter()
                .map(|rule| rule.id.as_str())
                .collect::<Vec<_>>(),
            vec!["organization.only", "pack.first", "pack.second"]
        );
        assert_eq!(resolution.merged_rule_set.rules[1].score, 9);
        let first = resolution
            .diagnostics
            .provenance
            .iter()
            .find(|entry| entry.id == "pack.first")
            .expect("replacement provenance");
        assert!(first.winner.contains("local-ui:"));
        assert_eq!(first.replaced_sources.len(), 1);
        assert!(first.replaced_sources[0].contains("deployment:"));
    }

    #[test]
    fn equal_tier_duplicate_reports_both_sources() {
        let temp = tempdir().expect("tempdir");
        let first = temp.path().join("one.yaml");
        let second = temp.path().join("two.yaml");
        write_rule(&first, "same.id", "one", 1);
        write_rule(&second, "same.id", "two", 2);

        let error = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &RulePackPaths {
                organization: vec![first.clone(), second.clone()],
                ..RulePackPaths::default()
            },
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("equal-tier duplicate");
        let error = error.to_string();
        assert!(error.starts_with("duplicate rule id: same.id"));
        assert!(error.contains(&canonical_or_original(&first).display().to_string()));
        assert!(error.contains(&canonical_or_original(&second).display().to_string()));
    }

    #[test]
    fn explicit_rules_are_additive_only_after_managed_packs() {
        let temp = tempdir().expect("tempdir");
        let managed = temp.path().join("rules.d/managed.yaml");
        let explicit = temp.path().join("explicit.yaml");
        write_rule(&managed, "managed.id", "managed", 1);
        write_rule(&explicit, "explicit.id", "explicit", 2);

        let resolution =
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &RulePackPaths {
                    deployment: vec![managed.clone()],
                    ..RulePackPaths::default()
                },
                std::slice::from_ref(&explicit),
                None,
                RuleLoadMode::CustomOnly,
                &[],
                &[],
            )
            .expect("explicit additive rule");
        assert_eq!(resolution.rule_set.rule_count(), 2);

        let collision = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &RulePackPaths {
                deployment: vec![temp.path().join("rules.d/managed.yaml")],
                ..RulePackPaths::default()
            },
            std::slice::from_ref(&managed),
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect("same canonical managed and explicit path is deduplicated");
        assert_eq!(collision.rule_set.rule_count(), 1);

        let explicit_collision = temp.path().join("explicit-collision.yaml");
        write_rule(&explicit_collision, "managed.id", "collision", 3);
        let collision = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &RulePackPaths {
                deployment: vec![managed.clone()],
                ..RulePackPaths::default()
            },
            std::slice::from_ref(&explicit_collision),
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("distinct explicit collision");
        let collision = collision.to_string();
        assert!(collision.contains(&canonical_or_original(&managed).display().to_string()));
        assert!(
            collision.contains(
                &canonical_or_original(&explicit_collision)
                    .display()
                    .to_string()
            )
        );

        let duplicate = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &RulePackPaths::default(),
            &[explicit.clone(), explicit],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("repeated explicit document");
        assert!(
            duplicate
                .to_string()
                .starts_with("duplicate rule id: explicit.id")
        );
    }

    #[test]
    fn invalid_higher_tier_winner_does_not_fall_back() {
        let temp = tempdir().expect("tempdir");
        let deployment = temp.path().join("rules.d/deployment.yaml");
        let local = temp.path().join("ui-rules.d/local.yaml");
        write_rule(&deployment, "same.id", "valid", 1);
        write_rule(&local, "same.id", "[", 9);

        let error = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &RulePackPaths {
                deployment: vec![deployment],
                local: vec![local],
                ..RulePackPaths::default()
            },
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("invalid replacement must fail");
        assert!(error.to_string().contains("same.id"));
    }

    #[test]
    fn rule_overrides_disable_rules_and_change_scores() {
        let temp = tempdir().expect("tempdir");
        let override_path = temp.path().join("override.yaml");
        fs::write(
            &override_path,
            r#"version: 1
overrides:
  - rule_id: network.download
    enabled: false
    reason: Too noisy for this fixture.
  - rule_id: secret.env.read
    score: 7
    reason: Lab tuning.
"#,
        )
        .expect("write override");

        let rule_set = super::load_rule_set_from_paths_with_mode_and_override_paths(
            &[],
            None,
            super::RuleLoadMode::IncludeDefault,
            &[override_path],
        )
        .expect("load overridden rules");

        assert!(
            !rule_set
                .summaries()
                .iter()
                .any(|rule| rule.id == "network.download")
        );
        assert_eq!(
            rule_set
                .summaries()
                .iter()
                .find(|rule| rule.id == "secret.env.read")
                .expect("secret rule")
                .score,
            7
        );
    }

    #[test]
    fn rule_overrides_reject_unknown_rule_ids() {
        let temp = tempdir().expect("tempdir");
        let override_path = temp.path().join("override.yaml");
        fs::write(
            &override_path,
            r#"version: 1
overrides:
  - rule_id: chain.download_then_execute
    enabled: false
    reason: Modifier override is not supported yet.
"#,
        )
        .expect("write override");

        let error = super::load_rule_set_from_paths_with_mode_and_override_paths(
            &[],
            None,
            super::RuleLoadMode::IncludeDefault,
            &[override_path],
        )
        .expect_err("modifier override should fail")
        .to_string();

        assert!(error.contains("unknown rule_id 'chain.download_then_execute'"));
    }

    #[test]
    fn rule_overrides_require_reason_and_effect() {
        let temp = tempdir().expect("tempdir");
        let override_path = temp.path().join("override.yaml");
        fs::write(
            &override_path,
            r#"version: 1
overrides:
  - rule_id: network.download
    reason: "   "
"#,
        )
        .expect("write override");

        let error = super::load_rule_set_from_paths_with_mode_and_override_paths(
            &[],
            None,
            super::RuleLoadMode::IncludeDefault,
            &[override_path],
        )
        .expect_err("invalid override should fail")
        .to_string();

        assert!(error.contains("requires a non-empty reason"));
    }

    #[test]
    fn rule_overrides_apply_later_paths_deterministically() {
        let temp = tempdir().expect("tempdir");
        let first_override = temp.path().join("a.yaml");
        let second_override = temp.path().join("b.yaml");
        fs::write(
            &first_override,
            r#"version: 1
overrides:
  - rule_id: network.download
    score: 5
    reason: First local tuning.
"#,
        )
        .expect("write first override");
        fs::write(
            &second_override,
            r#"version: 1
overrides:
  - rule_id: network.download
    score: 12
    reason: Later local tuning wins.
"#,
        )
        .expect("write second override");

        let rule_set = super::load_rule_set_from_paths_with_mode_and_override_paths(
            &[],
            None,
            super::RuleLoadMode::IncludeDefault,
            &[first_override, second_override],
        )
        .expect("load overridden rules");

        assert_eq!(
            rule_set
                .summaries()
                .iter()
                .find(|rule| rule.id == "network.download")
                .expect("download rule")
                .score,
            12
        );
    }
}
