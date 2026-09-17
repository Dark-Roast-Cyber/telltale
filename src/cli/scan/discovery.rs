use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::discovery::{
    DiscoveryError, discover_sources_with_projects, discover_sources_with_projects_best_effort,
};
use telltale_schema::clients::ClientId;
use telltale_schema::source::Source;

#[derive(Clone)]
pub(super) struct ProjectConfigurationAccounting {
    pub(super) mode: &'static str,
    pub(super) document_attempt_count: usize,
    pub(super) document_success_count: usize,
    pub(super) document_failure_count: usize,
    pub(super) loaded_project_count: usize,
}

impl ProjectConfigurationAccounting {
    pub(super) fn none() -> Self {
        Self {
            mode: "none",
            document_attempt_count: 0,
            document_success_count: 0,
            document_failure_count: 0,
            loaded_project_count: 0,
        }
    }

    pub(super) fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "mode": self.mode,
            "document_attempt_count": self.document_attempt_count,
            "document_success_count": self.document_success_count,
            "document_failure_count": self.document_failure_count,
            "loaded_project_count": self.loaded_project_count,
        })
    }
}

pub(super) fn load_project_configuration(
    root: &Path,
    paths: &[PathBuf],
) -> (
    Vec<crate::projects::ProjectDef>,
    ProjectConfigurationAccounting,
) {
    if paths.is_empty() && root == Path::new(".") {
        let projects = crate::projects::load_default_projects();
        let loaded_project_count = projects.len();
        return (
            projects,
            ProjectConfigurationAccounting {
                mode: "default_roots",
                document_attempt_count: 0,
                document_success_count: 0,
                document_failure_count: 0,
                loaded_project_count,
            },
        );
    }
    if paths.is_empty() {
        return (Vec::new(), ProjectConfigurationAccounting::none());
    }

    let mut projects = Vec::new();
    let mut document_success_count = 0;
    let mut document_failure_count = 0;
    for path in paths {
        match crate::projects::load_project_config(path) {
            Ok(loaded) => {
                document_success_count += 1;
                projects.extend(loaded);
            }
            Err(_) => document_failure_count += 1,
        }
    }
    let loaded_project_count = projects.len();
    (
        projects,
        ProjectConfigurationAccounting {
            mode: "configured_documents",
            document_attempt_count: paths.len(),
            document_success_count,
            document_failure_count,
            loaded_project_count,
        },
    )
}

#[derive(Clone)]
pub(super) struct SourceDiscoveryAccounting {
    pub(super) checked_status: &'static str,
    pub(super) first_error_category: Option<&'static str>,
    pub(super) best_effort_fallback_used: bool,
    pub(super) returned_source_count: usize,
    pub(super) operational_source_count: usize,
    pub(super) project_configuration: ProjectConfigurationAccounting,
}

impl SourceDiscoveryAccounting {
    pub(super) fn json(
        &self,
        basis: &'static str,
        performed_for_current_scan: bool,
    ) -> serde_json::Value {
        serde_json::json!({
            "basis": basis,
            "performed_for_current_scan": performed_for_current_scan,
            "checked_status": self.checked_status,
            "first_error_category": self.first_error_category,
            "best_effort_fallback_used": self.best_effort_fallback_used,
            "returned_source_count": self.returned_source_count,
            "operational_source_count": self.operational_source_count,
            "project_configuration": self.project_configuration.json(),
        })
    }
}

fn discovery_error_category(error: &DiscoveryError) -> &'static str {
    match error {
        DiscoveryError::InvalidRoot { .. } => "invalid_root",
        DiscoveryError::Traversal { .. } => "traversal",
        _ => "other",
    }
}

struct DiscoveryResolution {
    sources: Vec<Source>,
    checked_status: &'static str,
    first_error_category: Option<&'static str>,
    best_effort_fallback_used: bool,
}

fn resolve_discovery_result(
    checked: Result<Vec<Source>, DiscoveryError>,
    best_effort: impl FnOnce() -> Vec<Source>,
) -> DiscoveryResolution {
    match checked {
        Ok(sources) => DiscoveryResolution {
            sources,
            checked_status: "succeeded",
            first_error_category: None,
            best_effort_fallback_used: false,
        },
        Err(error) => DiscoveryResolution {
            sources: best_effort(),
            checked_status: "first_error",
            first_error_category: Some(discovery_error_category(&error)),
            best_effort_fallback_used: true,
        },
    }
}

pub(super) fn discover_operational_sources(
    root: &Path,
    clients: &[ClientId],
    max_sources: Option<usize>,
    project_configs: &[crate::projects::ProjectDef],
    project_configuration: &ProjectConfigurationAccounting,
) -> (Vec<Source>, SourceDiscoveryAccounting) {
    let resolution = resolve_discovery_result(
        discover_sources_with_projects(root, project_configs),
        || discover_sources_with_projects_best_effort(root, project_configs),
    );
    let DiscoveryResolution {
        mut sources,
        checked_status,
        first_error_category,
        best_effort_fallback_used,
    } = resolution;
    let returned_source_count = sources.len();
    if !clients.is_empty() {
        let allowed_clients = clients.iter().copied().collect::<BTreeSet<_>>();
        sources.retain(|source| allowed_clients.contains(&source.client));
    }
    if let Some(max_sources) = max_sources {
        sources.truncate(max_sources);
    }
    let operational_source_count = sources.len();
    (
        sources,
        SourceDiscoveryAccounting {
            checked_status,
            first_error_category,
            best_effort_fallback_used,
            returned_source_count,
            operational_source_count,
            project_configuration: project_configuration.clone(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_schema::clients::SourceKind;

    #[test]
    fn discovery_error_categories_are_stable_and_do_not_use_error_text() {
        assert_eq!(
            discovery_error_category(&DiscoveryError::InvalidRoot {
                root: PathBuf::from("private-root"),
            }),
            "invalid_root"
        );
        assert_eq!(
            discovery_error_category(&DiscoveryError::Traversal {
                root: PathBuf::from("private-root"),
                source_id: "private-source".to_string(),
            }),
            "traversal"
        );
    }

    #[test]
    fn checked_traversal_uses_fallback_without_serializing_error_details() {
        let fallback_source = Source {
            client: ClientId::Codex,
            kind: SourceKind::Jsonl,
            source_id: "fallback-source-sentinel".to_string(),
            path: PathBuf::from("fallback-path-sentinel.jsonl"),
        };
        let resolution = resolve_discovery_result(
            Err(DiscoveryError::Traversal {
                root: PathBuf::from("private-root-sentinel"),
                source_id: "private-source-sentinel".to_string(),
            }),
            || vec![fallback_source],
        );
        assert_eq!(resolution.checked_status, "first_error");
        assert_eq!(resolution.first_error_category, Some("traversal"));
        assert!(resolution.best_effort_fallback_used);
        assert_eq!(resolution.sources.len(), 1);

        let accounting = SourceDiscoveryAccounting {
            checked_status: resolution.checked_status,
            first_error_category: resolution.first_error_category,
            best_effort_fallback_used: resolution.best_effort_fallback_used,
            returned_source_count: resolution.sources.len(),
            operational_source_count: resolution.sources.len(),
            project_configuration: ProjectConfigurationAccounting::none(),
        };
        let serialized = accounting.json("current_full_scan", true).to_string();
        assert!(!serialized.contains("private-root-sentinel"));
        assert!(!serialized.contains("private-source-sentinel"));
        assert!(!serialized.contains("fallback-source-sentinel"));
        assert!(!serialized.contains("fallback-path-sentinel"));
        let serialized_value: serde_json::Value =
            serde_json::from_str(&serialized).expect("discovery accounting json");
        assert!(serialized_value.get("root").is_none());
        assert!(serialized_value.get("source_id").is_none());
        assert!(serialized_value.get("error").is_none());
    }
}
