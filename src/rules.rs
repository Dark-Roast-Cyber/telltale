//! Rule loading for the CLI: filesystem-facing wrappers around the I/O-free
//! rule language in `telltale-rules`, which this module re-exports. Tiered
//! resolution itself lives in `telltale_core::rule_resolution`, which hooks
//! shares.

use std::path::{Path, PathBuf};

pub(crate) use telltale_core::rule_resolution::{
    RulePackPaths, RuleResolution, RuleResolutionDiagnostics,
};
pub(crate) use telltale_rules::package::CommunityRules;
pub(crate) use telltale_rules::*;

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

/// Resolve rule content for a CLI command. The CLI's own default rule file,
/// passed explicitly, is skipped unless the mode loads custom rules only (the
/// bundled defaults already hold it).
pub(crate) fn resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
    pack_paths: &RulePackPaths,
    explicit_rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
    mode: RuleLoadMode,
    override_paths: &[PathBuf],
    replacements: &[(PathBuf, &str)],
) -> Result<RuleResolution, Box<dyn std::error::Error>> {
    let explicit_rule_paths = explicit_rule_paths
        .iter()
        .filter(|path| should_load_rule_path(path, mode))
        .cloned()
        .collect::<Vec<_>>();
    telltale_core::rule_resolution::resolve_rule_set(
        pack_paths,
        &explicit_rule_paths,
        Vec::new(),
        policy_path,
        mode,
        override_paths,
        replacements,
    )
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

#[cfg(test)]
mod tests;
