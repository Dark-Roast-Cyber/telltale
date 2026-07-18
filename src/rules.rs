//! Rule loading for the CLI: filesystem-facing wrappers around the I/O-free
//! rule language in `telltale-rules`, which this module re-exports.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub use telltale_rules::*;

pub fn default_rule_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("config/rules/tool-call-regex.yaml")
}

pub fn load_rule_set_from_paths(
    rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    load_rule_set_from_paths_with_mode(rule_paths, policy_path, RuleLoadMode::IncludeDefault)
}

pub fn load_rule_set_from_paths_with_mode(
    rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
    mode: RuleLoadMode,
) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    load_rule_set_from_paths_with_mode_and_override_paths(rule_paths, policy_path, mode, &[])
}

pub(crate) fn load_rule_set_from_paths_with_mode_and_override_paths(
    rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
    mode: RuleLoadMode,
    override_paths: &[PathBuf],
) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    load_rule_set_from_paths_with_mode_override_paths_and_replacements(
        rule_paths,
        policy_path,
        mode,
        override_paths,
        &[],
    )
}

pub(crate) fn load_rule_set_from_paths_with_mode_override_paths_and_replacements(
    rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
    mode: RuleLoadMode,
    override_paths: &[PathBuf],
    replacements: &[(PathBuf, &str)],
) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    let replacements = replacements
        .iter()
        .map(|(path, raw)| (canonical_or_original(path), *raw))
        .collect::<BTreeMap<_, _>>();
    let mut loaded = Vec::new();
    if matches!(mode, RuleLoadMode::IncludeDefault) {
        loaded.push(bundled_default_rule_set()?);
    }

    for path in rule_paths
        .iter()
        .filter(|path| should_load_rule_path(path, mode))
    {
        let raw = match replacements.get(&canonical_or_original(path)) {
            Some(raw) => raw.to_string(),
            None => fs::read_to_string(path)?,
        };
        loaded.push(serde_yaml::from_str::<RuleSet>(&raw)?);
    }

    if loaded.is_empty() {
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

    let mut rule_set = merge_rule_sets(loaded)?;
    apply_rule_overrides_from_paths(&mut rule_set, override_paths)?;
    rule_set.compile(policy.as_ref())
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

    use tempfile::tempdir;

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
