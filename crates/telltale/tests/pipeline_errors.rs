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
    assert_eq!(
        error.to_string(),
        "no rule documents provided; remove without_bundled_defaults or add rules_document"
    );

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
        assert!(matches!(error, PipelineError::RuleConfiguration(_)));
        assert!(error.to_string().starts_with(expected), "{error}");
    }
    let duplicate = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE)
        .rules_document(RULE)
        .build()
        .err()
        .expect("duplicate");
    assert_eq!(
        duplicate.to_string(),
        "duplicate rule id: custom.error_contract"
    );
    assert!(matches!(duplicate, PipelineError::RuleConfiguration(_)));
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
fn pipeline_error_characterization_compilation_precedes_source_processing() {
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
        let pipeline = Pipeline::builder()
            .without_bundled_defaults()
            .rules_document(document)
            .build()
            .expect("Rule v1 builder accepts document");
        assert_eq!(
            pipeline
                .scan_sources(&[])
                .expect_err("compilation")
                .to_string(),
            expected
        );
        assert_eq!(
            pipeline
                .scan_sources_with_occurrences(&[])
                .err()
                .expect("compilation")
                .to_string(),
            expected
        );
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            pipeline
                .scan_root(root.path())
                .expect_err("compilation")
                .to_string(),
            expected
        );
        assert_eq!(
            pipeline
                .scan_root_with_occurrences(root.path())
                .err()
                .expect("compilation")
                .to_string(),
            expected
        );
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
    assert_eq!(
        pipeline
            .scan_root(&missing)
            .expect_err("discovery")
            .to_string(),
        expected
    );
    assert_eq!(
        pipeline
            .scan_root_with_occurrences(&missing)
            .err()
            .expect("discovery")
            .to_string(),
        expected
    );
}

#[test]
fn pipeline_error_typed_public_operations() -> Result<(), PipelineError> {
    let missing = Pipeline::builder()
        .without_bundled_defaults()
        .build()
        .err()
        .unwrap();
    assert!(matches!(missing, PipelineError::MissingRuleDocuments));
    assert!(missing.source().is_none());
    for builder in [
        Pipeline::builder().rules_document("rules: ["),
        Pipeline::builder().policy_document("categories: ["),
        Pipeline::builder()
            .without_bundled_defaults()
            .rules_document(RULE.replace("regex: needle", "regex: '['")),
    ] {
        let error = builder.build().err().unwrap();
        assert!(matches!(error, PipelineError::RuleConfiguration(_)));
        assert_eq!(error.to_string(), error.source().unwrap().to_string());
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
    let invalid = Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(RULE.replace("severity: low", "severity: unknown"))
        .build()?;
    for error in [
        invalid.scan_sources(&[]).err().unwrap(),
        invalid.scan_sources_with_occurrences(&[]).err().unwrap(),
        invalid.scan_root(root.path()).err().unwrap(),
        invalid
            .scan_root_with_occurrences(root.path())
            .err()
            .unwrap(),
    ] {
        assert!(matches!(
            error,
            PipelineError::RuleCompilation(RuleV1CompileError::InvalidSeverity)
        ));
    }
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
        PipelineError::RuleConfiguration(Box::new(std::io::Error::other(
            "synthetic loader diagnostic",
        ))),
    ];
    for error in &errors {
        let original: &(dyn Error + 'static) = match error {
            PipelineError::Discovery(source) => source,
            PipelineError::RuleCompilation(source) => source,
            PipelineError::Observation(source) => source,
            PipelineError::Clock(source) => source,
            PipelineError::RuleConfiguration(source) => source.as_ref(),
            other => panic!("unexpected category: {other:?}"),
        };
        assert!(std::ptr::addr_eq(error.source().unwrap(), original));
        assert_eq!(error.to_string(), original.to_string());
    }
    assert!(matches!(errors[0], PipelineError::Discovery(_)));
    assert!(matches!(errors[1], PipelineError::RuleCompilation(_)));
    assert!(matches!(errors[2], PipelineError::Observation(_)));
    assert!(matches!(errors[3], PipelineError::Clock(_)));
}
