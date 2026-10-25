use std::error::Error;
use telltale_core::{
    DiscoveryError, ObservationError, Pipeline, PipelineError, RuleV1CompileError,
};

const RULE: &str = r#"
version: 1
description: synthetic error contract
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: custom.error_contract
    category: custom
    severity: low
    score: 10
    targets: [arguments]
    regex: needle
    tags: [synthetic]
    explanation: synthetic
modifiers: []
"#;

fn synthetic_package(document: &str) -> String {
    format!(
        "format: telltale-rule-package/v1\nid: custom.synthetic\nversion: 1.0.0\npublisher: Synthetic\nlicense: Apache-2.0\nrule_namespace: custom\ndocuments:\n  - {}\n",
        document.trim().replace('\n', "\n    ")
    )
}

#[test]
fn accepted_detection_severities_have_shared_canonical_and_embedding_parity() {
    for severity in telltale_schema::event::VALID_DETECTION_SEVERITIES {
        let document = RULE.replace("severity: low", &format!("severity: {severity}"));
        let compiled = telltale_rules::load_rule_set_from_documents(&[&document], None)
            .expect("supported detection severity");
        let plan = telltale_detect::v2::compile_rule_v1(&compiled.compatibility_export())
            .expect("canonical severity parity");
        assert_eq!(plan.detectors().len(), 1);
        for builder in [
            Pipeline::builder()
                .without_bundled_defaults()
                .rules_document(&document),
            Pipeline::builder()
                .without_bundled_defaults()
                .rule_package(synthetic_package(&document)),
        ] {
            let pipeline = builder.build().expect("embedding severity parity");
            assert_eq!(pipeline.rule_count(), 1);
        }
    }
}

#[test]
fn unsupported_detection_severities_fail_shared_compilation_for_documents_and_packages() {
    for severity in ["warning", "catastrophic"] {
        let document = RULE.replace("severity: low", &format!("severity: {severity}"));
        for builder in [
            Pipeline::builder()
                .without_bundled_defaults()
                .rules_document(&document),
            Pipeline::builder()
                .without_bundled_defaults()
                .rule_package(synthetic_package(&document)),
        ] {
            let error = builder.build().err().expect("unsupported severity");
            assert!(matches!(error, PipelineError::Compilation(_)));
            assert_eq!(
                error.source().unwrap().to_string(),
                format!(
                    "rule custom.error_contract uses unsupported severity '{severity}'; supported values: {}",
                    telltale_schema::event::VALID_DETECTION_SEVERITIES.join(", ")
                )
            );
        }
    }
}

#[test]
fn pipeline_error_characterization_builder_diagnostics() {
    let error = Pipeline::builder()
        .without_bundled_defaults()
        .build()
        .err()
        .expect("missing documents");
    assert!(matches!(error, PipelineError::InvalidConfiguration));
    assert_eq!(error.to_string(), "pipeline_no_rule_documents");
    assert!(error.source().is_none());

    for (document, expected) in [
        (
            RULE.replace("version: 1", "version: 2"),
            "unsupported rule set version 2; only version 1 is supported",
        ),
        (
            RULE.replace("[arguments]", "[unknown]"),
            "rule custom.error_contract uses unsupported target 'unknown'",
        ),
        (
            RULE.replace("regex: needle", "regex: '['"),
            "invalid regex for rule custom.error_contract:",
        ),
        (
            RULE.replace("severity: low", "severity: catastrophic"),
            "rule custom.error_contract uses unsupported severity 'catastrophic'; supported values:",
        ),
    ] {
        let error = Pipeline::builder()
            .without_bundled_defaults()
            .rules_document(document)
            .build()
            .err()
            .expect("invalid rules");
        assert!(matches!(error, PipelineError::Compilation(_)));
        assert_eq!(error.to_string(), "pipeline_compilation_failed");
        assert!(
            error.source().unwrap().to_string().starts_with(expected),
            "{error:?}"
        );
    }
    let duplicate = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE)
        .rules_document(RULE)
        .build()
        .err()
        .expect("duplicate");
    assert_eq!(duplicate.to_string(), "pipeline_compilation_failed");
    assert_eq!(
        duplicate.source().unwrap().to_string(),
        "duplicate rule id: custom.error_contract"
    );
    assert!(matches!(duplicate, PipelineError::Compilation(_)));
    assert!(
        Pipeline::builder()
            .rules_document("rules: [")
            .build()
            .is_err()
    );
    assert!(
        Pipeline::builder()
            .policy_document("categories: [")
            .build()
            .is_err()
    );
}

#[test]
fn pipeline_error_characterization_canonical_rejection_fails_build() {
    let error = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE.replace("score: 10", "score: 101"))
        .build()
        .err()
        .expect("canonical score rejection at build");
    assert_eq!(error.to_string(), "pipeline_compilation_failed");
    assert_eq!(error.source().unwrap().to_string(), "score_out_of_range");
}

#[test]
fn pipeline_error_characterization_checked_discovery() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    let pipeline = Pipeline::builder().build().unwrap();
    let expected = format!(
        "discovery root is not a readable directory: {}",
        missing.display()
    );
    for error in [
        pipeline.scan_root(&missing).expect_err("discovery"),
        pipeline
            .scan_root_with_occurrences(&missing)
            .err()
            .expect("discovery"),
    ] {
        assert_eq!(error.to_string(), "pipeline_discovery_failed");
        assert_eq!(error.source().unwrap().to_string(), expected);
    }
}

#[test]
fn pipeline_error_typed_public_operations() -> Result<(), PipelineError> {
    let missing = Pipeline::builder()
        .without_bundled_defaults()
        .build()
        .err()
        .unwrap();
    assert!(matches!(missing, PipelineError::InvalidConfiguration));
    assert_eq!(missing.to_string(), "pipeline_no_rule_documents");
    assert!(missing.source().is_none());
    for builder in [
        Pipeline::builder().rules_document("rules: ["),
        Pipeline::builder().policy_document("categories: ["),
        Pipeline::builder()
            .without_bundled_defaults()
            .rules_document(RULE.replace("regex: needle", "regex: '['")),
    ] {
        let error = builder.build().err().unwrap();
        assert!(matches!(error, PipelineError::Compilation(_)));
        assert_eq!(error.to_string(), "pipeline_compilation_failed");
        assert!(error.source().is_some());
    }
    let pipeline = Pipeline::builder().build()?;
    let root = tempfile::tempdir().unwrap();
    let absent = root.path().join("absent");
    for error in [
        pipeline.scan_root(&absent).err().unwrap(),
        pipeline.scan_root_with_occurrences(&absent).err().unwrap(),
    ] {
        assert!(matches!(
            error,
            PipelineError::Discovery(DiscoveryError::InvalidRoot { .. })
        ));
    }
    let error = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE.replace("score: 10", "score: 101"))
        .build()
        .err()
        .unwrap();
    assert!(matches!(error, PipelineError::Compilation(_)));
    assert!(matches!(
        error
            .source()
            .and_then(|cause| cause.downcast_ref::<RuleV1CompileError>()),
        Some(RuleV1CompileError::ScoreOutOfRange)
    ));
    assert!(pipeline.scan_sources(&[])?.is_empty());
    assert!(pipeline.scan_sources_with_occurrences(&[])?.is_empty());
    Ok(())
}

#[test]
fn pipeline_error_typed_conversions_preserve_sources_and_display() {
    let discovery = DiscoveryError::InvalidRoot {
        root: "synthetic-missing".into(),
    };
    let observation: ObservationError =
        telltale_schema::observation::ObservedAt::new("not-a-timestamp")
            .err()
            .unwrap();
    let clock = time::Date::from_calendar_date(2026, time::Month::October, 4)
        .unwrap()
        .format(&time::format_description::parse_borrowed::<1>("[offset_hour]").unwrap())
        .unwrap_err();
    let errors: [PipelineError; 5] = [
        discovery.into(),
        RuleV1CompileError::ScoreOutOfRange.into(),
        observation.into(),
        clock.into(),
        PipelineError::Compilation(Box::new(std::io::Error::other(
            "synthetic loader diagnostic",
        ))),
    ];
    for error in &errors {
        let original: &(dyn Error + 'static) = match error {
            PipelineError::Discovery(source) => source,
            PipelineError::Compilation(source) => source.as_ref(),
            PipelineError::Observation(source) => source,
            PipelineError::Clock(source) => source.as_ref(),
            other => panic!("unexpected category: {other}"),
        };
        assert!(std::ptr::addr_eq(error.source().unwrap(), original));
        assert!(!error.to_string().contains("synthetic"));
    }
    assert!(matches!(errors[0], PipelineError::Discovery(_)));
    assert!(matches!(errors[1], PipelineError::Compilation(_)));
    assert!(matches!(errors[2], PipelineError::Observation(_)));
    assert!(matches!(errors[3], PipelineError::Clock(_)));
}
