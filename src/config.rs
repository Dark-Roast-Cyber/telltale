//! Discovery of local configuration files (system, user and explicit roots) and
//! resolution of rule, policy and allowlist paths. Setting values and their
//! precedence live in `settings`.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
const SYSTEM_CONFIG_ROOT: &str = "/etc/telltale";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalConfigFiles {
    pub organization_rule_paths: Vec<PathBuf>,
    pub deployment_rule_paths: Vec<PathBuf>,
    pub local_rule_paths: Vec<PathBuf>,
    pub rule_paths: Vec<PathBuf>,
    pub rule_package_paths: Vec<PathBuf>,
    pub override_paths: Vec<PathBuf>,
    pub policy_paths: Vec<PathBuf>,
    pub allowlist_paths: Vec<PathBuf>,
    pub output_paths: Vec<PathBuf>,
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
    let (allowlist_paths, output_paths) = if matches!(kind, LocalConfigDiscoveryKind::Scan) {
        (
            discover_yaml_files(&roots, "allowlists.d")?,
            discover_yaml_files(&roots, "outputs.d")?,
        )
    } else {
        (Vec::new(), Vec::new())
    };
    let organization_rule_paths = discover_yaml_files(&roots, "organization-rules.d")?;
    let deployment_rule_paths = discover_yaml_files(&roots, "rules.d")?;
    let local_rule_paths = discover_yaml_files(&roots, "ui-rules.d")?;
    let rule_paths = organization_rule_paths
        .iter()
        .chain(deployment_rule_paths.iter())
        .chain(local_rule_paths.iter())
        .cloned()
        .collect();
    Ok(LocalConfigFiles {
        organization_rule_paths,
        deployment_rule_paths,
        local_rule_paths,
        rule_paths,
        rule_package_paths: discover_yaml_files(&roots, "rule-packages.d")?,
        override_paths: discover_yaml_files(&roots, "overrides.d")?,
        policy_paths: discover_yaml_files(&roots, "policies.d")?,
        allowlist_paths,
        output_paths,
    })
}

/// `settings.d/*.yaml` files in root order, sorted within each root.
pub fn discover_settings_files(
    explicit_roots: &[PathBuf],
    no_local_config: bool,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    if no_local_config {
        return Ok(Vec::new());
    }
    discover_yaml_files(&active_config_roots(explicit_roots)?, "settings.d")
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
    let optional = explicit_roots.is_empty();
    let candidates = if optional {
        default_config_roots()
    } else {
        explicit_roots.to_vec()
    };
    #[cfg(windows)]
    if optional {
        refuse_legacy_system_root()?;
    }
    let mut roots = Vec::new();
    for root in candidates {
        // A pinned user root was there when the hook command was generated.
        let pinned = pinned_user_config_root() == Some(root.as_path());
        let metadata = config_metadata(&root, optional && !pinned).map_err(|error| {
            if pinned {
                format!("the pinned user config root (--user-config-dir) is unavailable: {error}; restore it or generate the hook settings again")
                    .into()
            } else {
                Box::<dyn std::error::Error>::from(error)
            }
        })?;
        let Some(metadata) = metadata else {
            continue;
        };
        if !metadata.is_dir() {
            return Err("local config root is not a directory".into());
        }
        trust_system_path(&root, &root)?;
        roots.push(root);
    }
    Ok(roots)
}

/// Before 0.8 the Windows system root was the literal `\etc\telltale` on the
/// current drive, which any user can create. Refuse it rather than silently
/// stop reading an operator's configuration.
#[cfg(windows)]
fn refuse_legacy_system_root() -> Result<(), Box<dyn std::error::Error>> {
    let legacy = Path::new(r"\etc\telltale");
    match fs::symlink_metadata(legacy) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ if system_config_root().is_some_and(|root| same_directory(legacy, &root)) => Ok(()),
        _ => Err(concat!(
            r"\etc\telltale is no longer a config root; move it to %ProgramData%\telltale",
            " (writable only by Administrators, SYSTEM and TrustedInstaller) or remove it"
        )
        .into()),
    }
}

/// The system config root: `/etc/telltale`, or on Windows `telltale` in the
/// `ProgramData` known folder (`None` only if Windows cannot resolve it).
pub(crate) fn system_config_root() -> Option<PathBuf> {
    #[cfg(windows)]
    return windows::program_data().map(|root| root.join("telltale"));
    #[cfg(not(windows))]
    Some(PathBuf::from(SYSTEM_CONFIG_ROOT))
}

#[cfg(all(feature = "hooks", windows))]
pub(crate) fn program_data() -> Option<PathBuf> {
    windows::program_data()
}

#[cfg(all(feature = "hooks", windows))]
pub(crate) fn program_files() -> Option<PathBuf> {
    windows::program_files()
}

#[cfg(windows)]
fn same_directory(a: &Path, b: &Path) -> bool {
    a == b || matches!((fs::canonicalize(a), fs::canonicalize(b)), (Ok(a), Ok(b)) if a == b)
}

/// On Windows, `path` read from the system root (however it is named) must be
/// owned by and writable only by Administrators, SYSTEM or TrustedInstaller,
/// and not be a link; anything else fails the load. `/etc` gives a Unix root
/// that guarantee by default, so Unix is not checked.
fn trust_system_path(root: &Path, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    if system_config_root().is_some_and(|system| same_directory(root, &system)) {
        return match windows::administrator_only(path) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(untrusted)) => Err(format!(
                "system config path {} {untrusted}; only Administrators, SYSTEM and TrustedInstaller may own or change the system config root",
                path.display()
            )
            .into()),
            Err(error) => Err(format!(
                "system config path {} could not be checked: {:?}",
                path.display(),
                error.kind()
            )
            .into()),
        };
    }
    let _ = (root, path);
    Ok(())
}

fn config_metadata(path: &Path, optional: bool) -> io::Result<Option<fs::Metadata>> {
    config_metadata_result(path, optional, fs::metadata(path))
}

fn config_metadata_result(
    path: &Path,
    optional: bool,
    result: io::Result<fs::Metadata>,
) -> io::Result<Option<fs::Metadata>> {
    let result = match result {
        Err(error) if optional && error.kind() == io::ErrorKind::NotFound => {
            // Following a dangling symlink is not the same as absent optional config.
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
                Ok(_) => Err(error),
            }
        }
        result => result.map(Some),
    };
    result.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("local config metadata failed: {:?}", error.kind()),
        )
    })
}

/// The config roots a command reads: the explicit roots when any are given,
/// else the default roots, whether or not they exist yet.
#[cfg(feature = "hooks")]
pub(crate) fn config_roots(explicit_roots: &[PathBuf]) -> Vec<PathBuf> {
    if explicit_roots.is_empty() {
        default_config_roots()
    } else {
        explicit_roots.to_vec()
    }
}

fn default_config_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = system_config_root().into_iter().collect();
    if let Some(user_root) = pinned_user_config_root()
        .map(Path::to_path_buf)
        .or_else(user_config_root)
    {
        roots.push(user_root);
    }
    roots
}

/// The user config root `telltale hooks … --user-config-dir` pinned for this
/// process. It stands in for the one the environment names, in the same place
/// after the system root, and must exist: the hook command that carries it was
/// generated while it did.
static PINNED_USER_CONFIG_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Pin the user config root for the rest of this process (first pin wins).
#[cfg(feature = "hooks")]
pub(crate) fn pin_user_config_root(root: PathBuf) {
    let _ = PINNED_USER_CONFIG_ROOT.set(root);
}

pub(crate) fn pinned_user_config_root() -> Option<&'static Path> {
    PINNED_USER_CONFIG_ROOT.get().map(PathBuf::as_path)
}

/// The user config root the environment names (`XDG_CONFIG_HOME`, else
/// `HOME` or on Windows `USERPROFILE`), ignoring any pin.
pub(crate) fn user_config_root() -> Option<PathBuf> {
    // Windows rarely sets HOME; USERPROFILE is where Git Bash and similar shells point it.
    let profile = if cfg!(windows) {
        std::env::var_os("USERPROFILE")
    } else {
        None
    };
    user_config_root_from(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
        profile,
    )
}

/// [`user_config_root`], with the environment variable that named it.
#[cfg(feature = "hooks")]
pub(crate) fn user_config_root_source() -> Option<(&'static str, PathBuf)> {
    let root = user_config_root()?;
    let set = |name| std::env::var_os(name).is_some_and(|value| !value.is_empty());
    let name = if set("XDG_CONFIG_HOME") {
        "XDG_CONFIG_HOME"
    } else if set("HOME") {
        "HOME"
    } else {
        "USERPROFILE"
    };
    Some((name, root))
}

fn user_config_root_from(
    xdg_config_home: Option<OsString>,
    home: Option<OsString>,
    windows_profile: Option<OsString>,
) -> Option<PathBuf> {
    let set = |value: Option<OsString>| value.filter(|value| !value.is_empty());
    set(xdg_config_home)
        .map(|value| PathBuf::from(value).join("telltale"))
        .or_else(|| {
            set(home)
                .or_else(|| set(windows_profile))
                .map(|value| PathBuf::from(value).join(".config").join("telltale"))
        })
}

fn discover_yaml_files(
    roots: &[PathBuf],
    subdir: &str,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut discovered = Vec::new();
    for root in roots {
        let dir = root.join(subdir);
        let Some(metadata) = config_metadata(&dir, true)? else {
            continue;
        };
        if !metadata.is_dir() {
            return Err("local config subdirectory is not a directory".into());
        }
        let mut files = fs::read_dir(&dir)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        files.retain(|path| is_yaml_file(path));
        files.sort();
        trust_system_path(root, &dir)?;
        for path in &files {
            if !config_metadata(path, false)?.is_some_and(|metadata| metadata.is_file()) {
                return Err("local config YAML entry is not a regular file".into());
            }
            trust_system_path(root, path)?;
        }
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
    use std::io;
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
    fn user_config_root_prefers_xdg_then_home_then_windows_profile() {
        use std::ffi::OsString;
        use std::path::PathBuf;
        let root = |xdg: Option<&str>, home: Option<&str>, profile: Option<&str>| {
            super::user_config_root_from(
                xdg.map(OsString::from),
                home.map(OsString::from),
                profile.map(OsString::from),
            )
        };
        let dot_config = |base: &str| PathBuf::from(base).join(".config").join("telltale");
        assert_eq!(
            root(Some("xdg"), Some("home"), Some("profile")),
            Some(PathBuf::from("xdg").join("telltale"))
        );
        assert_eq!(
            root(Some(""), Some("home"), Some("profile")),
            Some(dot_config("home"))
        );
        assert_eq!(
            root(None, Some(""), Some("profile")),
            Some(dot_config("profile"))
        );
        assert_eq!(
            root(None, None, Some("profile")),
            Some(dot_config("profile"))
        );
        assert_eq!(root(None, None, Some("")), None);
        assert_eq!(root(None, None, None), None);
    }

    #[test]
    fn optional_metadata_skips_only_genuinely_absent_paths() {
        let temp = tempdir().expect("tempdir");
        let missing = temp.path().join("missing");
        assert!(
            super::config_metadata(&missing, true)
                .expect("optional absent path")
                .is_none()
        );
        assert!(super::config_metadata(&missing, false).is_err());
        assert!(
            super::config_metadata(temp.path(), true)
                .expect("present optional root")
                .is_some()
        );
    }

    #[test]
    fn metadata_errors_are_not_optional_and_have_bounded_diagnostics() {
        let temp = tempdir().expect("tempdir");
        for optional in [false, true] {
            for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
                let error = super::config_metadata_result(
                    temp.path(),
                    optional,
                    Err(io::Error::new(kind, "CONTROLLED_METADATA_SECRET")),
                )
                .expect_err("metadata failure is not absence");
                assert_eq!(error.kind(), kind);
                assert_eq!(
                    error.to_string(),
                    format!("local config metadata failed: {kind:?}")
                );
                assert!(!format!("{error:?}").contains("CONTROLLED_METADATA_SECRET"));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn optional_broken_root_symlink_is_not_absent() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("root");
        std::os::unix::fs::symlink("missing-target", &root).expect("broken root link");
        super::config_metadata(&root, true).expect_err("broken optional root must fail");
    }

    #[test]
    fn discovers_yaml_files_in_root_order_then_path_order() {
        let temp = tempdir().expect("tempdir");
        let root_a = temp.path().join("a");
        let root_b = temp.path().join("b");
        write(&root_a.join("rules.d/z.yml"));
        write(&root_a.join("rules.d/a.yaml"));
        write(&root_a.join("organization-rules.d/org.yaml"));
        write(&root_a.join("ui-rules.d/ui.yaml"));
        write(&root_a.join("rules.d/ignored.txt"));
        write(&root_a.join("overrides.d/z.yml"));
        write(&root_a.join("overrides.d/a.yaml"));
        write(&root_b.join("rules.d/b.yaml"));
        write(&root_b.join("organization-rules.d/org-b.yaml"));
        write(&root_b.join("ui-rules.d/ui-b.yaml"));
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
                root_a.join("organization-rules.d/org.yaml"),
                root_b.join("organization-rules.d/org-b.yaml"),
                root_a.join("rules.d/a.yaml"),
                root_a.join("rules.d/z.yml"),
                root_b.join("rules.d/b.yaml"),
                root_a.join("ui-rules.d/ui.yaml"),
                root_b.join("ui-rules.d/ui-b.yaml"),
            ]
        );
        assert_eq!(
            discovered.organization_rule_paths,
            vec![
                root_a.join("organization-rules.d/org.yaml"),
                root_b.join("organization-rules.d/org-b.yaml"),
            ]
        );
        assert_eq!(
            discovered.deployment_rule_paths,
            vec![
                root_a.join("rules.d/a.yaml"),
                root_a.join("rules.d/z.yml"),
                root_b.join("rules.d/b.yaml"),
            ]
        );
        assert_eq!(
            discovered.local_rule_paths,
            vec![
                root_a.join("ui-rules.d/ui.yaml"),
                root_b.join("ui-rules.d/ui-b.yaml")
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
        assert!(discovered.organization_rule_paths.is_empty());
        assert!(discovered.deployment_rule_paths.is_empty());
        assert!(discovered.local_rule_paths.is_empty());
        assert!(discovered.override_paths.is_empty());
        assert!(discovered.policy_paths.is_empty());
        assert!(discovered.allowlist_paths.is_empty());
        assert!(discovered.output_paths.is_empty());
    }

    #[test]
    fn present_config_subdirs_must_be_directories() {
        for subdir in ["rules.d", "policies.d", "outputs.d"] {
            let temp = tempdir().expect("tempdir");
            write(&temp.path().join(subdir));
            let error = discover_local_config_files(
                &[temp.path().to_path_buf()],
                false,
                LocalConfigDiscoveryKind::Scan,
            )
            .expect_err("present config subdir with wrong type must fail");
            assert!(error.to_string().contains("not a directory"));
        }
    }

    #[test]
    fn yaml_entries_must_be_regular_files() {
        for subdir in ["rules.d", "outputs.d"] {
            let temp = tempdir().expect("tempdir");
            fs::create_dir_all(temp.path().join(subdir).join("invalid.yaml"))
                .expect("YAML directory");
            let error = discover_local_config_files(
                &[temp.path().to_path_buf()],
                false,
                LocalConfigDiscoveryKind::Scan,
            )
            .expect_err("YAML entry with wrong type must fail");
            assert!(error.to_string().contains("not a regular file"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn broken_yaml_symlinks_are_errors_not_absent_configuration() {
        for subdir in ["rules.d", "outputs.d"] {
            let temp = tempdir().expect("tempdir");
            let dir = temp.path().join(subdir);
            fs::create_dir_all(&dir).expect("config subdir");
            std::os::unix::fs::symlink("missing-target", dir.join("broken.yaml"))
                .expect("broken YAML symlink");
            discover_local_config_files(
                &[temp.path().to_path_buf()],
                false,
                LocalConfigDiscoveryKind::Scan,
            )
            .expect_err("broken YAML symlink must fail");
        }
    }

    #[cfg(unix)]
    #[test]
    fn broken_config_subdir_symlinks_are_errors() {
        let temp = tempdir().expect("tempdir");
        std::os::unix::fs::symlink("missing-target", temp.path().join("rules.d"))
            .expect("broken subdir symlink");
        discover_local_config_files(
            &[temp.path().to_path_buf()],
            false,
            LocalConfigDiscoveryKind::Scan,
        )
        .expect_err("broken subdir symlink must fail");
    }

    #[cfg(unix)]
    #[test]
    fn valid_config_symlinks_are_followed_and_non_yaml_entries_ignored() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir");
        let target_root = temp.path().join("target");
        let rule = target_root.join("rule.yaml");
        write(&rule);
        let target_dir = temp.path().join("rule-files");
        fs::create_dir_all(&target_dir).expect("target directory");
        symlink(&rule, target_dir.join("linked.yml")).expect("valid YAML symlink");
        symlink("missing-target", target_dir.join("ignored.txt")).expect("non-YAML symlink");
        fs::create_dir(target_dir.join("nested")).expect("ignored directory");
        symlink(&target_dir, target_root.join("rules.d")).expect("valid directory symlink");
        let root = temp.path().join("linked-root");
        symlink(&target_root, &root).expect("valid root symlink");

        let discovered = discover_local_config_files(
            std::slice::from_ref(&root),
            false,
            LocalConfigDiscoveryKind::Scan,
        )
        .expect("discover symlink configuration");
        assert_eq!(discovered.rule_paths, vec![root.join("rules.d/linked.yml")]);
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

        assert!(error.contains("local config metadata failed: NotFound"));
        assert!(!error.contains(&missing.display().to_string()));
    }

    #[test]
    fn explicit_config_root_must_be_a_directory() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("root");
        write(&root);
        let error = discover_local_config_files(&[root], false, LocalConfigDiscoveryKind::Scan)
            .expect_err("wrong-type root must fail");
        assert_eq!(error.to_string(), "local config root is not a directory");
    }

    #[test]
    fn no_local_config_ignores_explicit_roots() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("config");
        write(&root.join("rules.d/local.yaml"));
        write(&root.join("overrides.d/local.yaml"));
        write(&root.join("outputs.d"));

        let discovered = discover_local_config_files(&[root], true, LocalConfigDiscoveryKind::Scan)
            .expect("discover config");

        assert!(discovered.rule_paths.is_empty());
        assert!(discovered.organization_rule_paths.is_empty());
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
        write(&root.join("outputs.d"));

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
        assert!(discovered.output_paths.is_empty());
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

    /// Only paths read from the system root are checked, however that root
    /// is named; a user-created folder there fails the load.
    #[cfg(windows)]
    #[test]
    fn only_the_system_root_must_be_administrator_only() {
        let system = super::system_config_root().expect("ProgramData resolves");
        assert!(system.ends_with(r"ProgramData\telltale"));
        let temp = tempdir().expect("tempdir");
        super::trust_system_path(temp.path(), temp.path()).expect("not the system root");
        let error = super::trust_system_path(&system, temp.path())
            .expect_err("a user-owned folder is not trusted");
        let message = error.to_string();
        assert!(
            message.contains("Administrators, SYSTEM and TrustedInstaller"),
            "{message}"
        );
        let missing = super::trust_system_path(&system, &temp.path().join("missing"))
            .expect_err("an unreadable path is not trusted");
        assert!(missing.to_string().contains("NotFound"), "{missing}");
    }
}
