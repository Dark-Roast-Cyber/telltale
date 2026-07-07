use std::fs;
use std::path::{Path, PathBuf};

const SYSTEM_CONFIG_ROOT: &str = "/etc/telltale";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalConfigFiles {
    pub rule_paths: Vec<PathBuf>,
    pub override_paths: Vec<PathBuf>,
    pub policy_paths: Vec<PathBuf>,
    pub allowlist_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalConfigDiscoveryKind {
    Rules,
    Scan,
}

pub fn discover_local_config_files(
    explicit_roots: &[PathBuf],
    no_local_config: bool,
    kind: LocalConfigDiscoveryKind,
) -> Result<LocalConfigFiles, Box<dyn std::error::Error>> {
    if no_local_config {
        return Ok(LocalConfigFiles::default());
    }

    let roots = active_config_roots(explicit_roots)?;
    let allowlist_paths = if matches!(kind, LocalConfigDiscoveryKind::Scan) {
        discover_yaml_files(&roots, "allowlists.d")?
    } else {
        Vec::new()
    };
    Ok(LocalConfigFiles {
        rule_paths: discover_yaml_files(&roots, "rules.d")?,
        override_paths: discover_yaml_files(&roots, "overrides.d")?,
        policy_paths: discover_yaml_files(&roots, "policies.d")?,
        allowlist_paths,
    })
}

pub fn effective_rule_paths(discovered: &[PathBuf], explicit: &[PathBuf]) -> Vec<PathBuf> {
    discovered.iter().chain(explicit.iter()).cloned().collect()
}

pub fn resolve_policy_path(
    explicit: Option<&Path>,
    discovered: &[PathBuf],
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    resolve_single_discovered_path(explicit, discovered, "policy", "--policy")
}

pub fn resolve_allowlist_path(
    explicit: Option<&Path>,
    discovered: &[PathBuf],
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    resolve_single_discovered_path(explicit, discovered, "allowlist", "--allowlist")
}

fn active_config_roots(
    explicit_roots: &[PathBuf],
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    if explicit_roots.is_empty() {
        return Ok(default_config_roots()
            .into_iter()
            .filter(|root| root.is_dir())
            .collect());
    }

    let mut roots = Vec::new();
    for root in explicit_roots {
        if !root.is_dir() {
            return Err(format!(
                "local config root '{}' does not exist or is not a directory",
                root.display()
            )
            .into());
        }
        roots.push(root.clone());
    }
    Ok(roots)
}

fn default_config_roots() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from(SYSTEM_CONFIG_ROOT)];
    if let Some(user_root) = user_config_root() {
        roots.push(user_root);
    }
    roots
}

fn user_config_root() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(|value| PathBuf::from(value).join("telltale"))
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|value| PathBuf::from(value).join(".config/telltale"))
        })
}

fn discover_yaml_files(
    roots: &[PathBuf],
    subdir: &str,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut discovered = Vec::new();
    for root in roots {
        let dir = root.join(subdir);
        if !dir.is_dir() {
            continue;
        }
        let mut files = fs::read_dir(&dir)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        files.retain(|path| path.is_file() && is_yaml_file(path));
        files.sort();
        discovered.extend(files);
    }
    Ok(discovered)
}

fn is_yaml_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("yaml") | Some("yml")
    )
}

fn resolve_single_discovered_path(
    explicit: Option<&Path>,
    discovered: &[PathBuf],
    kind: &str,
    flag: &str,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    if let Some(path) = explicit {
        return Ok(Some(path.to_path_buf()));
    }
    match discovered {
        [] => Ok(None),
        [path] => Ok(Some(path.clone())),
        paths => Err(format!(
            "multiple local {kind} files discovered: {}; pass {flag} explicitly or remove extra {kind} files",
            paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;

    use super::{
        LocalConfigDiscoveryKind, discover_local_config_files, effective_rule_paths,
        resolve_allowlist_path, resolve_policy_path,
    };

    fn write(path: &Path) {
        fs::create_dir_all(path.parent().expect("parent dir")).expect("create parent");
        fs::write(path, "---\n").expect("write file");
    }

    #[test]
    fn discovers_yaml_files_in_root_order_then_path_order() {
        let temp = tempdir().expect("tempdir");
        let root_a = temp.path().join("a");
        let root_b = temp.path().join("b");
        write(&root_a.join("rules.d/z.yml"));
        write(&root_a.join("rules.d/a.yaml"));
        write(&root_a.join("rules.d/ignored.txt"));
        write(&root_a.join("overrides.d/z.yml"));
        write(&root_a.join("overrides.d/a.yaml"));
        write(&root_b.join("rules.d/b.yaml"));
        write(&root_b.join("overrides.d/b.yaml"));

        let discovered = discover_local_config_files(
            &[root_a.clone(), root_b.clone()],
            false,
            LocalConfigDiscoveryKind::Scan,
        )
        .expect("discover config");

        assert_eq!(
            discovered.rule_paths,
            vec![
                root_a.join("rules.d/a.yaml"),
                root_a.join("rules.d/z.yml"),
                root_b.join("rules.d/b.yaml"),
            ]
        );
        assert_eq!(
            discovered.override_paths,
            vec![
                root_a.join("overrides.d/a.yaml"),
                root_a.join("overrides.d/z.yml"),
                root_b.join("overrides.d/b.yaml"),
            ]
        );
    }

    #[test]
    fn ignores_existing_roots_with_missing_config_subdirs() {
        let temp = tempdir().expect("tempdir");
        let existing = temp.path().join("existing");
        fs::create_dir_all(&existing).expect("create root");

        let discovered =
            discover_local_config_files(&[existing], false, LocalConfigDiscoveryKind::Scan)
                .expect("discover config");

        assert!(discovered.rule_paths.is_empty());
        assert!(discovered.override_paths.is_empty());
        assert!(discovered.policy_paths.is_empty());
        assert!(discovered.allowlist_paths.is_empty());
    }

    #[test]
    fn explicit_missing_config_root_is_an_error() {
        let temp = tempdir().expect("tempdir");
        let missing = temp.path().join("missing");

        let error = discover_local_config_files(
            std::slice::from_ref(&missing),
            false,
            LocalConfigDiscoveryKind::Scan,
        )
        .expect_err("explicit missing config root should fail")
        .to_string();

        assert!(error.contains("local config root"));
        assert!(error.contains(&missing.display().to_string()));
    }

    #[test]
    fn no_local_config_ignores_explicit_roots() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");
        write(&root.join("rules.d/local.yaml"));
        write(&root.join("overrides.d/local.yaml"));

        let discovered = discover_local_config_files(&[root], true, LocalConfigDiscoveryKind::Scan)
            .expect("discover config");

        assert!(discovered.rule_paths.is_empty());
        assert!(discovered.override_paths.is_empty());
    }

    #[test]
    fn rule_discovery_scans_overrides_but_not_allowlists() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");
        write(&root.join("rules.d/local.yaml"));
        write(&root.join("overrides.d/local.yaml"));
        write(&root.join("policies.d/local.yaml"));
        write(&root.join("allowlists.d/one.yaml"));
        write(&root.join("allowlists.d/two.yml"));

        let discovered = discover_local_config_files(
            std::slice::from_ref(&root),
            false,
            LocalConfigDiscoveryKind::Rules,
        )
        .expect("discover config");

        assert_eq!(discovered.rule_paths, vec![root.join("rules.d/local.yaml")]);
        assert_eq!(
            discovered.override_paths,
            vec![root.join("overrides.d/local.yaml")]
        );
        assert_eq!(
            discovered.policy_paths,
            vec![root.join("policies.d/local.yaml")]
        );
        assert!(discovered.allowlist_paths.is_empty());
    }

    #[test]
    fn combines_discovered_rules_before_explicit_rules() {
        let discovered = vec![Path::new("local-a.yaml").to_path_buf()];
        let explicit = vec![Path::new("cli-b.yaml").to_path_buf()];

        assert_eq!(
            effective_rule_paths(&discovered, &explicit),
            vec![
                Path::new("local-a.yaml").to_path_buf(),
                Path::new("cli-b.yaml").to_path_buf(),
            ]
        );
    }

    #[test]
    fn policy_and_allowlist_discovery_require_a_single_file() {
        let paths = vec![
            Path::new("one.yaml").to_path_buf(),
            Path::new("two.yml").to_path_buf(),
        ];

        let policy_error = resolve_policy_path(None, &paths)
            .expect_err("multiple discovered policies should be ambiguous")
            .to_string();
        assert!(policy_error.contains("multiple local policy files discovered"));
        assert!(policy_error.contains("pass --policy explicitly"));

        let allowlist_error = resolve_allowlist_path(None, &paths)
            .expect_err("multiple discovered allowlists should be ambiguous")
            .to_string();
        assert!(allowlist_error.contains("multiple local allowlist files discovered"));
        assert!(allowlist_error.contains("pass --allowlist explicitly"));
    }

    #[test]
    fn explicit_policy_or_allowlist_wins_over_discovered_ambiguity() {
        let discovered = vec![
            Path::new("one.yaml").to_path_buf(),
            Path::new("two.yml").to_path_buf(),
        ];

        assert_eq!(
            resolve_policy_path(Some(Path::new("explicit-policy.yaml")), &discovered)
                .expect("resolve policy"),
            Some(Path::new("explicit-policy.yaml").to_path_buf())
        );
        assert_eq!(
            resolve_allowlist_path(Some(Path::new("explicit-allowlist.yaml")), &discovered)
                .expect("resolve allowlist"),
            Some(Path::new("explicit-allowlist.yaml").to_path_buf())
        );
    }
}
