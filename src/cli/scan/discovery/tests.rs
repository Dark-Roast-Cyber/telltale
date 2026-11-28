use super::*;
use telltale_schema::clients::SourceKind;

#[test]
fn repeated_project_configs_do_not_consume_distinct_source_cap() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    let workspace = temp.path().join("workspace");
    let project = workspace.join("repo");
    std::fs::create_dir_all(&home).expect("home");
    std::fs::create_dir_all(project.join("logs/copilot")).expect("logs");
    for name in ["process-a.log", "process-b.log", "process-c.log"] {
        std::fs::write(project.join("logs/copilot").join(name), b"synthetic log\n").expect("log");
    }
    let config = temp.path().join("projects.yaml");
    std::fs::write(
        &config,
        format!(
            "projects:\n  - name: workspace\n    path: '{}'\n  - name: repo\n    path: '{}'\n",
            workspace.display(),
            project.display()
        ),
    )
    .expect("config");
    let (projects, configuration) = load_project_configuration(&home, &[config.clone(), config]);
    assert_eq!(configuration.document_success_count, 2);
    assert_eq!(configuration.loaded_project_count, 4);
    let (all, all_accounting) =
        discover_operational_sources(&home, &[ClientId::Copilot], None, &projects, &configuration);
    let (capped, accounting) = discover_operational_sources(
        &home,
        &[ClientId::Copilot],
        Some(2),
        &projects,
        &configuration,
    );
    assert_eq!(all.len(), 3);
    assert_eq!(all_accounting.returned_source_count, 3);
    assert_eq!(all_accounting.operational_source_count, 3);
    assert_eq!(capped, all[..2]);
    assert_ne!(capped[0], capped[1]);
    assert_eq!(accounting.returned_source_count, 3);
    assert_eq!(accounting.operational_source_count, 2);
}

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
