use super::*;
use std::error::Error;
use telltale_schema::clients::{ClientId, SourceKind};

fn synthetic_source() -> Source {
    Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "embedded.synthetic".to_string(),
        path: std::path::PathBuf::from("embedded://synthetic"),
    }
}

#[test]
fn canonical_rejection_fails_build_and_batch_time_precedes_source_io() {
    let invalid_rules = r#"
title: Synthetic batch error precedence
id: 3f2504e0-4f89-41d3-9a0c-0305e82c3302
name: synthetic.invalid
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re: 'needle'
    condition: selection
level: low
telltale:
    category: synthetic
    score: 1
    explanation: synthetic
    detection_class: operational_health
"#;
    // Rule loading accepts the detection class; canonical compilation
    // rejects it at build time, so no pipeline exists that can only fail
    // scans.
    let error = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(invalid_rules)
        .build()
        .err()
        .expect("canonical rejection at build");
    assert!(matches!(error, PipelineError::Compilation(_)));
    assert!(matches!(
        error
            .source()
            .and_then(|cause| cause.downcast_ref::<RuleCompileError>()),
        Some(RuleCompileError::UnmappableDetectionClass)
    ));
    let valid = Pipeline::builder().build().unwrap();
    let sources = [synthetic_source()];
    for batch in [&[][..], &sources[..]] {
        let error = valid
            .scan_sources_with_time(batch, || {
                time::Date::from_calendar_date(2026, time::Month::October, 4)
                    .unwrap()
                    .format(
                        &time::format_description::parse_borrowed::<1>("[offset_hour]").unwrap(),
                    )
            })
            .err()
            .expect("clock failure");
        assert!(matches!(error, PipelineError::Clock(_)));
        let error = valid
            .scan_sources_with_time(batch, || Ok("invalid-observed-at".into()))
            .err()
            .expect("observation failure");
        assert!(matches!(error, PipelineError::Observation(_)));
    }
    let scans = valid
        .scan_sources_with_time(&sources, || Ok("2026-10-04T00:00:00Z".into()))
        .unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].events.len(), 1);
    assert_eq!(scans[0].events[0].event_type, "scanner_error");
    assert!(scans[0].occurrences.is_empty());
}

#[test]
fn custom_only_without_documents_is_an_error() {
    assert!(
        Pipeline::builder()
            .without_bundled_defaults()
            .build()
            .is_err()
    );
}

fn community_package(version: &str, rule_id: &str) -> String {
    format!(
        "format: telltale-rule-package/v2\nid: telltale.community\ntitle: Synthetic community\n\
             version: \"{version}\"\npublisher: Synthetic\nlicense: Apache-2.0\nrule_namespace: tdx\n\
             ---\ntitle: Synthetic community rule\nid: 5d0f6c4e-8a1b-4c2d-9e3f-0a1b2c3d4e5f\n\
             name: {rule_id}\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    \
             category: tool_activity\ndetection:\n    selection:\n        - tool.command|re|i: marker\n    \
             condition: selection\nlevel: low\ntelltale:\n    category: persistence\n    score: 20\n    \
             explanation: Synthetic.\n    tags: [synthetic]\n"
    )
}

#[test]
fn rule_v1_documents_and_packages_fail_as_invalid_documents() {
    // The CLI shows the pointer to Rule v2; the builder reports the code.
    let v1 = concat!(
        "version: 1\ndescription: synthetic\n",
        "defaults: {case_insensitive: true, enabled: true}\nrules: []\nmodifiers: []\n",
    );
    let content_error = |error: PipelineError| {
        let PipelineError::Compilation(cause) = error else {
            panic!("compilation error, got {error:?}");
        };
        cause.downcast_ref::<RuleContentError>().cloned().unwrap()
    };
    let document = content_error(
        Pipeline::builder()
            .rules_document(v1)
            .build()
            .err()
            .expect("Rule v1 document"),
    );
    assert_eq!(
        (document.code(), document.document()),
        (RuleContentErrorCode::InvalidDocument, Some("explicit:1"))
    );
    let package = format!(
        "format: telltale-rule-package/v1\nid: acme.rules\nversion: 1.0.0\npublisher: Acme\n\
             license: Apache-2.0\nrule_namespace: acme\ndocuments:\n  - {}",
        v1.replace('\n', "\n    ")
    );
    let package = content_error(
        Pipeline::builder()
            .rule_package(package)
            .build()
            .err()
            .expect("format v1 package"),
    );
    assert_eq!(
        (package.code(), package.document()),
        (RuleContentErrorCode::InvalidDocument, Some("package:1"))
    );
}

#[test]
fn builder_accepts_rule_v2_documents_beside_bundled_rules() {
    let v2 = "title: Synthetic v2 marker\nid: 3f2504e0-4f89-41d3-9a0c-0305e82c3301\n\
                  name: synthetic.v2.marker\ntaxonomy: telltale\nstatus: test\n\
                  logsource:\n    product: ai_agent\n    category: tool_activity\n\
                  detection:\n    selection:\n        tool.command|contains: synthetic-v2-marker\n    condition: selection\n\
                  level: medium\ntelltale:\n    category: synthetic\n    score: 25\n    explanation: Synthetic v2 rule.\n";
    let pipeline = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(v2)
        .build()
        .unwrap();
    assert_eq!(pipeline.rule_count(), 1);
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("source.jsonl");
    let row = serde_json::json!({"sessionId":"v2-session","type":"assistant","uuid":"v2-call","timestamp":"2026-11-18T00:00:00Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"v2-call","name":"Bash","input":{"command":"echo synthetic-v2-marker"}}]}});
    std::fs::write(&path, format!("{row}\n")).unwrap();
    let source = Source {
        client: ClientId::Claude,
        kind: SourceKind::Jsonl,
        source_id: "claude.projects".into(),
        path,
    };
    let events = pipeline.scan_sources(&[source]).unwrap();
    assert!(
        events
            .iter()
            .any(|(_, event)| event.rule_ids.iter().any(|id| id == "synthetic.v2.marker")),
        "{events:?}"
    );

    // Added beside the bundled content, a rule may not reuse a bundled id.
    assert_eq!(
        Pipeline::builder()
            .rules_document(v2)
            .build()
            .unwrap()
            .rule_count(),
        Pipeline::builder().build().unwrap().rule_count() + 1
    );
    let error = Pipeline::builder()
        .rules_document(v2.replace("synthetic.v2.marker", "network.download"))
        .build()
        .err()
        .unwrap();
    assert_eq!(
        error.source().unwrap().to_string(),
        "rule_content_duplicate_id"
    );
}

#[test]
fn community_rules_are_default_and_opt_out_leaves_core_rules() {
    let embedded = telltale_rules::package::bundled_community_package().unwrap();
    let community_rules = embedded
        .documents()
        .iter()
        .flat_map(|document| document.definitions())
        .filter(|definition| definition.kind() == telltale_rules::DefinitionKind::Rule)
        .count();
    let default = Pipeline::builder().build().unwrap();
    let core = Pipeline::builder()
        .without_community_rules()
        .build()
        .unwrap();
    assert_eq!(default.rule_count(), core.rule_count() + community_rules);
    assert_eq!(
        default.rule_packages(),
        [RulePackageSummary {
            id: COMMUNITY_PACKAGE_ID.to_string(),
            version: embedded.version().to_string(),
            content_sha256: embedded.content_sha256().to_string(),
            embedded: true,
            replaced_embedded_version: None,
        }]
    );
    assert!(core.rule_packages().is_empty());
    assert_eq!(
        core.rule_count(),
        telltale_rules::load_default_rule_set()
            .unwrap()
            .rule_count()
    );
}

#[test]
fn default_pipeline_detects_with_embedded_community_rules() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(".claude/projects/synthetic");
    std::fs::create_dir_all(&directory).unwrap();
    let call = serde_json::json!({"type": "assistant", "sessionId": "community-session",
            "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1",
            "name": "Bash", "input": {"command": "claude mcp add synthetic-server -- npx synthetic-mcp"}}]}});
    std::fs::write(directory.join("session.jsonl"), format!("{call}\n")).unwrap();
    let community_rule_ids = |pipeline: Pipeline| {
        pipeline
            .scan_root(root.path())
            .unwrap()
            .into_iter()
            .filter(|(_, event)| event.event_type == "detection")
            .flat_map(|(_, event)| event.rule_ids)
            .filter(|id| id.starts_with("tdx."))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        community_rule_ids(Pipeline::builder().build().unwrap()),
        ["tdx.persistence.mcp_server_registration"]
    );
    assert!(
        community_rule_ids(
            Pipeline::builder()
                .without_community_rules()
                .build()
                .unwrap()
        )
        .is_empty()
    );
}

#[test]
fn supplied_community_package_replaces_embedded_and_stays_opt_out() {
    let supplied = community_package("99.0.0", "tdx.synthetic.newer");
    let replaced = Pipeline::builder().rule_package(&supplied).build().unwrap();
    let summary = &replaced.rule_packages()[0];
    assert_eq!(
        (summary.version.as_str(), summary.embedded),
        ("99.0.0", false)
    );
    assert!(summary.replaced_embedded_version.is_some());
    let core = Pipeline::builder()
        .without_community_rules()
        .build()
        .unwrap();
    assert_eq!(replaced.rule_count(), core.rule_count() + 1);

    let package_only = Pipeline::builder()
        .without_bundled_defaults()
        .rule_package(&supplied)
        .build()
        .unwrap();
    assert_eq!(package_only.rule_count(), 1);
    assert!(matches!(
        Pipeline::builder()
            .without_bundled_defaults()
            .without_community_rules()
            .rule_package(&supplied)
            .build(),
        Err(PipelineError::InvalidConfiguration)
    ));
    assert!(matches!(
        Pipeline::builder()
            .rule_package("format: unknown\n")
            .build(),
        Err(PipelineError::Compilation(_))
    ));
}

#[test]
fn rule_catalog_attributes_community_entries_to_their_package() {
    let catalog = bundled_rule_catalog(&DetailedEvaluationOptions::default()).unwrap();
    let community = catalog
        .iter()
        .filter(|entry| entry.package_id() == Some(COMMUNITY_PACKAGE_ID))
        .collect::<Vec<_>>();
    assert!(!community.is_empty());
    assert!(
        community
            .iter()
            .all(|entry| entry.id().starts_with("tdx.") && entry.enabled())
    );
    assert!(
        catalog
            .iter()
            .any(|entry| entry.id() == "secret.env.read" && entry.package_id().is_none())
    );
}

#[cfg(test)]
mod canonical_embedding;

#[cfg(test)]
mod detailed_scan;

#[cfg(test)]
mod rule_content;
