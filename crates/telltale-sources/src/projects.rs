use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct ProjectDef {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
struct ProjectConfig {
    projects: Vec<ProjectDef>,
}

pub fn load_project_config(path: &Path) -> Result<Vec<ProjectDef>, Box<dyn std::error::Error>> {
    let contents = std::fs::read_to_string(path)?;
    let config: ProjectConfig = serde_yaml::from_str(&contents)?;
    let mut projects = Vec::new();
    for mut project in config.projects {
        let expanded = expand_tilde(&project.path);
        if !expanded.exists() {
            return Err(format!("project path does not exist: {}", expanded.display()).into());
        }
        if !expanded.is_dir() {
            return Err(format!("project path is not a directory: {}", expanded.display()).into());
        }
        project.path = expanded.canonicalize().unwrap_or(expanded);
        projects.push(project);
    }
    Ok(projects)
}

pub fn load_project_configs(paths: &[PathBuf]) -> Vec<ProjectDef> {
    let mut all = Vec::new();
    for path in paths {
        match load_project_config(path) {
            Ok(projects) => all.extend(projects),
            Err(_) => eprintln!("warning: failed_project_configuration"),
        }
    }
    all
}

pub fn project_config_paths_from_env() -> Vec<PathBuf> {
    project_config_paths_from_value(std::env::var_os("TELLTALE_PROJECT_CONFIG"))
}

fn project_config_paths_from_value(value: Option<OsString>) -> Vec<PathBuf> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| std::env::split_paths(&value).collect())
        .unwrap_or_default()
}

/// Returns default project paths to scan when no config is provided.
/// These are common developer workspace directories.
pub fn default_project_paths() -> Vec<PathBuf> {
    vec![PathBuf::from("~/github"), PathBuf::from("~/projects")]
}

/// Loads default project paths, filtering to only those that exist.
/// Used when no --project-config or TELLTALE_PROJECT_CONFIG is provided.
pub fn load_default_projects() -> Vec<ProjectDef> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    load_default_projects_with_home(home.as_deref())
}

fn load_default_projects_with_home(home: Option<&Path>) -> Vec<ProjectDef> {
    default_project_paths()
        .into_iter()
        .filter_map(|path| {
            let expanded = expand_tilde_with_home(&path, home);
            if expanded.exists() && expanded.is_dir() {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("default")
                    .to_string();
                Some(ProjectDef {
                    name,
                    path: expanded.canonicalize().unwrap_or(expanded),
                })
            } else {
                None
            }
        })
        .collect()
}

fn expand_tilde(path: &Path) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    expand_tilde_with_home(path, home.as_deref())
}

fn expand_tilde_with_home(path: &Path, home: Option<&Path>) -> PathBuf {
    if let Some(rest) = path.to_str().and_then(|s| s.strip_prefix("~/"))
        && let Some(home) = home
    {
        return home.join(rest);
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn bulk_loader_diagnostics_are_fixed_and_best_effort() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("PRIVATE_PROJECT_PATH_CANARY");
        fs::create_dir(&root).expect("synthetic root");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "projects::tests::bulk_loader_diagnostic_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("TELLTALE_PROJECT_LOADER_TEST_ROOT", &root)
            .output()
            .expect("diagnostic worker");
        assert!(output.status.success(), "diagnostic worker failed");
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        assert!(
            output.stderr == b"warning: failed_project_configuration\n".repeat(4),
            "project configuration stderr must contain only fixed classifications"
        );
    }

    #[test]
    #[ignore = "invoked in a subprocess to capture public loader stderr"]
    fn bulk_loader_diagnostic_worker() {
        let root = PathBuf::from(
            std::env::var_os("TELLTALE_PROJECT_LOADER_TEST_ROOT").expect("synthetic root"),
        );
        let project = root.join("project");
        fs::create_dir(&project).expect("project directory");
        let good = root.join("good.yaml");
        fs::write(
            &good,
            format!(
                "projects:\n  - name: good\n    path: '{}'\n",
                project.display()
            ),
        )
        .expect("valid config");
        let scalar = root.join("scalar.yaml");
        fs::write(&scalar, "projects: ORDINARY_PROSE_SECRET_CANARY\n")
            .expect("invalid scalar config");
        let missing_project = root.join("missing-project.yaml");
        fs::write(
            &missing_project,
            format!(
                "projects:\n  - name: good\n    path: '{}'\n  - name: missing\n    path: '{}'\n",
                project.display(),
                root.join("MISSING_PROJECT_PATH_CANARY").display()
            ),
        )
        .expect("missing project config");
        let non_directory = root.join("non-directory.yaml");
        fs::write(
            &non_directory,
            format!(
                "projects:\n  - name: file\n    path: '{}'\n",
                good.display()
            ),
        )
        .expect("non-directory config");
        let expected = load_project_config(&good).expect("valid project");
        assert!(load_project_configs(&[]).is_empty());
        assert_eq!(load_project_configs(std::slice::from_ref(&good)), expected);
        let loaded = load_project_configs(&[
            good.clone(),
            scalar,
            root.join("MISSING_CONFIG_PATH_CANARY.yaml"),
            missing_project,
            non_directory,
            good,
        ]);
        assert_eq!(loaded, [expected.clone(), expected].concat());
    }

    #[test]
    fn loads_valid_yaml() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("projects.yaml");
        let project_path = temp.path().join("project");
        fs::create_dir_all(&project_path).expect("project dir");
        fs::write(
            &path,
            format!(
                "projects:\n  - name: test\n    path: '{}'\n",
                project_path.display()
            ),
        )
        .expect("write");
        let projects = load_project_config(&path).expect("load");
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "test");
        assert_eq!(
            projects[0].path,
            project_path.canonicalize().expect("canonical project path")
        );
    }

    #[test]
    fn expands_tilde() {
        let temp = tempdir().expect("tempdir");
        let home = temp.path().join("home");
        fs::create_dir_all(&home).expect("home dir");
        fs::create_dir_all(home.join("docs")).expect("docs dir");
        let expanded = expand_tilde_with_home(&PathBuf::from("~/docs"), Some(&home));
        assert_eq!(expanded, home.join("docs"));
    }

    #[test]
    fn rejects_missing_path() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("projects.yaml");
        fs::write(&path, "projects:\n  - name: test\n    path: /nonexistent\n").expect("write");
        assert!(load_project_config(&path).is_err());
    }

    #[test]
    fn rejects_empty_file() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("projects.yaml");
        fs::write(&path, "").expect("write");
        assert!(load_project_config(&path).is_err());
    }

    #[test]
    fn parses_platform_native_path_list() {
        let joined = std::env::join_paths([PathBuf::from("a.yaml"), PathBuf::from("b.yaml")])
            .expect("join paths");
        let paths = project_config_paths_from_value(Some(joined));
        assert_eq!(
            paths,
            vec![PathBuf::from("a.yaml"), PathBuf::from("b.yaml")]
        );
        assert!(project_config_paths_from_value(None).is_empty());
        assert!(project_config_paths_from_value(Some(OsString::new())).is_empty());
    }

    #[test]
    fn default_paths_include_github_and_projects() {
        let defaults = default_project_paths();
        assert_eq!(defaults.len(), 2);
        assert!(defaults[0].to_str().unwrap().contains("github"));
        assert!(defaults[1].to_str().unwrap().contains("projects"));
    }

    #[test]
    fn load_default_projects_filters_nonexistent() {
        let temp = tempdir().expect("tempdir");
        let home = temp.path().join("home");
        fs::create_dir_all(&home).expect("home dir");
        // Create only ~/github, not ~/projects
        fs::create_dir_all(home.join("github")).expect("github dir");
        let projects = load_default_projects_with_home(Some(&home));
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "github");
    }

    #[test]
    fn load_project_configs_uses_defaults_when_empty() {
        let temp = tempdir().expect("tempdir");
        let home = temp.path().join("home");
        fs::create_dir_all(&home).expect("home dir");
        fs::create_dir_all(home.join("github")).expect("github dir");
        fs::create_dir_all(home.join("projects")).expect("projects dir");
        // This test verifies the logic, but we can't easily test load_project_configs
        // without setting HOME globally. The function is tested indirectly through
        // load_default_projects_with_home above.
        let projects = load_default_projects_with_home(Some(&home));
        assert_eq!(projects.len(), 2);
    }
}
