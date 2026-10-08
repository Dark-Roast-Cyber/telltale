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
    for (document, expected) in [
        (
            RULE.replace("severity: low", "severity: unknown"),
            "invalid_severity",
        ),
        (
            RULE.replace("score: 10", "score: 101"),
            "score_out_of_range",
        ),
    ] {
        // Rule v1 loading accepts these; canonical compilation rejects them at
        // build time, before any scan or source processing can be attempted.
        let error = Pipeline::builder()
            .without_bundled_defaults()
            .rules_document(document)
            .build()
            .err()
            .expect("canonical rejection at build");
        assert_eq!(error.to_string(), "pipeline_compilation_failed");
        assert_eq!(error.source().unwrap().to_string(), expected);
    }
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
        .rules_document(RULE.replace("severity: low", "severity: unknown"))
        .build()
        .err()
        .unwrap();
    assert!(matches!(error, PipelineError::Compilation(_)));
    assert!(matches!(
        error
            .source()
            .and_then(|cause| cause.downcast_ref::<RuleV1CompileError>()),
        Some(RuleV1CompileError::InvalidSeverity)
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
        .format(&time::format_description::parse("[offset_hour]").unwrap())
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
