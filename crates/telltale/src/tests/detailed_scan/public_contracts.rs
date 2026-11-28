use super::*;

#[test]
fn core_discovery_exports_preserve_existing_contracts() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join(".claude/projects/synthetic");
    std::fs::create_dir_all(&project).unwrap();
    let source = write_source(
        &project,
        "session.jsonl",
        "session",
        &[call("call", "2026-09-17T00:00:00Z", "echo ordinary")],
    );
    let checked = discover_sources(root.path()).unwrap();
    assert!(checked.iter().any(|found| found.path == source.path));
    assert_eq!(checked, discover_sources_best_effort(root.path()));
    let roots = discover_watch_roots_for_clients(root.path(), &[ClientId::Claude]);
    assert!(roots.iter().any(|watch| source.path.starts_with(watch)));
}

#[test]
fn review_custom_metadata_does_not_survive_detailed_serialization() {
    let root = tempfile::tempdir().unwrap();
    let source = write_source(
        root.path(),
        "metadata.jsonl",
        "session",
        &[call("call", "2026-09-17T00:00:00Z", "needle")],
    );
    let marker = "/home/synthetic/private-category";
    let document = format!(
        "title: synthetic\nid: ed3e2258-5474-404b-8f03-f55c1ba86f44\nname: synthetic.rule\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: tool_activity\ndetection:\n    selection:\n        - tool.command|re: 'needle'\n    condition: selection\nlevel: high\ntelltale:\n    category: {marker}\n    score: 30\n    explanation: 'synthetic'\n"
    );
    let scans = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(document)
        .build()
        .unwrap()
        .scan_sources_detailed(&[source], &DetailedEvaluationOptions::default())
        .unwrap();
    let finding = &scans[0].action_findings[0];
    // Debug renders every retained field; the DTO is not a wire format.
    assert!(!format!("{finding:?}").contains(marker));
    assert_eq!(finding.finding_kind(), ActionFindingKind::Atomic);
    assert_eq!(
        finding.supporting_observation_ids(),
        [finding.observation_id()]
    );
    assert!(!finding.coordinate().as_str().is_empty());
    assert_eq!(finding.severity(), Severity::High);
}

#[test]
fn pipeline_errors_have_typed_sources_and_safe_rendering() {
    let error = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document("synthetic invalid /home/synthetic/private token=controlledsecret")
        .build()
        .err()
        .unwrap();
    assert!(matches!(error, PipelineError::Compilation(_)));
    assert!(std::error::Error::source(&error).is_some());
    assert_eq!(format!("{error:?}"), "pipeline_compilation_failed");
    assert_eq!(error.to_string(), "pipeline_compilation_failed");
    let error = Pipeline::builder()
        .build()
        .unwrap()
        .scan_root(std::path::Path::new("/synthetic/nonexistent/root"))
        .err()
        .unwrap();
    assert!(matches!(error, PipelineError::Discovery(_)));
    assert!(
        std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<DiscoveryError>()
            .is_some()
    );
    assert_eq!(error.to_string(), "pipeline_discovery_failed");
}

#[test]
fn pipeline_remains_shareable_across_host_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Pipeline>();
}

/// Pinned identities for a custom-rule synthetic fixture. Hosts key delivery
/// and dedup on these values, so a change here must come with the matching
/// version bump (`REPLAY_ALGORITHM_VERSION`, `ACTION_SEMANTICS_VERSION`, or the
/// native profile version) and a migration note. Never update values alone.
#[test]
fn action_identities_are_pinned_to_their_algorithm_versions() {
    const RULE: &str = "title: synthetic\nid: 0bb3a1f3-c75a-489d-8d11-77e9c483a86b\nname: synthetic.golden\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: tool_activity\ndetection:\n    selection:\n        - tool.command|re: 'needle'\n    condition: selection\nlevel: high\ntelltale:\n    category: synthetic\n    score: 30\n    explanation: 'synthetic'\n";
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE)
        .build()
        .unwrap();
    let options = DetailedEvaluationOptions::default();
    let startup = pipeline.semantic_provenance(&options).unwrap();
    assert_eq!(
        (
            startup.action_semantics_version(),
            startup.native_profile_version(),
            startup.replay_algorithm_version(),
        ),
        (3, 19, 1)
    );
    // Identities exclude paths: two roots must produce the same values.
    let mut seen = Vec::new();
    for _ in 0..2 {
        let root = tempfile::tempdir().unwrap();
        let source = write_source(
            root.path(),
            "golden.jsonl",
            "golden-session",
            &[call("golden-call", "2026-09-17T00:00:00Z", "echo needle")],
        );
        let scan = pipeline
            .scan_sources_detailed(&[source], &options)
            .unwrap()
            .remove(0);
        let action = &scan.action_findings[0];
        seen.push((
            scan.semantic_provenance.unwrap().identity().to_owned(),
            action.replay_identity().unwrap().as_str().to_owned(),
            action.coordinate().as_str().to_owned(),
            action.observation_id().to_owned(),
        ));
    }
    assert_eq!(seen[0], seen[1]);
    let (semantic, replay, coordinate, observation) = &seen[0];
    assert_eq!(semantic, startup.identity());
    assert_eq!(
        semantic,
        "semantic:v1:sha256:380891ab30c40929b09572edebada1498b45efe9b479ba3b6331a5f0b4c9491d"
    );
    assert_eq!(
        coordinate,
        "obs:v2:sha256:8c6859e14c8aba279a67d1a85ff2e3f6847614864c0c2f341aa60342ade3a7c1"
    );
    assert_eq!(
        replay,
        "replay:v1:sha256:e872d2809d69c73a189c8e7e3be73574e8f80985739401ce7b56e4f15c9739c0"
    );
    assert_eq!(observation, coordinate);
}
