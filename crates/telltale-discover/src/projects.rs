//! Project configuration: the project roots searched for project-local
//! session-store discovery. No session contents are opened.

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
    let home = project_home();
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
    let home = project_home();
    expand_tilde_with_home(path, home.as_deref())
}

fn project_home() -> Option<PathBuf> {
    let home = std::env::var_os("HOME");
    #[cfg(windows)]
    let home = home
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()));
    home.map(PathBuf::from)
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
mod tests;
