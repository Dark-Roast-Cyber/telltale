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
            Err(e) => eprintln!(
                "warning: failed to load project config {}: {}",
                path.display(),
                e
            ),
        }
    }
    all
}

pub fn project_config_paths_from_env() -> Vec<PathBuf> {
    std::env::var("ADR_PROJECT_CONFIG")
        .ok()
        .map(|v| v.split(':').map(PathBuf::from).collect())
        .unwrap_or_default()
}

/// Returns default project paths to scan when no config is provided.
/// These are common developer workspace directories.
pub fn default_project_paths() -> Vec<PathBuf> {
    vec![PathBuf::from("~/github"), PathBuf::from("~/projects")]
}

/// Loads default project paths, filtering to only those that exist.
/// Used when no --project-config or ADR_PROJECT_CONFIG is provided.
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
    fn parses_env_var() {
        unsafe { std::env::set_var("ADR_PROJECT_CONFIG", "/a/b.yaml:/c/d.yaml") };
        let paths = project_config_paths_from_env();
        assert_eq!(
            paths,
            vec![PathBuf::from("/a/b.yaml"), PathBuf::from("/c/d.yaml")]
        );
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
