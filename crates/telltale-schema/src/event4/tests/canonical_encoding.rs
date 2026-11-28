use super::*;

#[test]
fn canonical_open_maps_sort_normalize_and_preserve_array_order() {
    let context = Event4InMemoryContext::new();
    let mut first = summary("evt-map");
    let mut extensions = OpenMap::new();
    extensions.insert(
        "zeta.example",
        OpenMap::from_entries([(
            "b".to_owned(),
            ExtensionValue::Scalar(ExtensionScalar::Bool(true)),
        )]),
    );
    extensions.insert(
        "alpha.example",
        OpenMap::from_entries([(
            "a".to_owned(),
            ExtensionValue::Array(vec![
                ExtensionScalar::Number(1.0),
                ExtensionScalar::Number(2.0),
            ]),
        )]),
    );
    first.extensions = Some(extensions);

    let mut second = summary("evt-map");
    let mut extensions = OpenMap::new();
    extensions.insert(
        "alpha.example",
        OpenMap::from_entries([(
            "a".to_owned(),
            ExtensionValue::Array(vec![
                ExtensionScalar::Number(1.0),
                ExtensionScalar::Number(2.0),
            ]),
        )]),
    );
    extensions.insert(
        "zeta.example",
        OpenMap::from_entries([(
            "b".to_owned(),
            ExtensionValue::Scalar(ExtensionScalar::Bool(true)),
        )]),
    );
    second.extensions = Some(extensions);
    let first = validate_terminal(&first.materialize(MATERIALIZED), &context).unwrap();
    let second = validate_terminal(&second.materialize(MATERIALIZED), &context).unwrap();
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    let repeated =
        summary_with_same_extensions("evt-map", first.canonical_bytes()).materialize(MATERIALIZED);
    assert_eq!(
        first.canonical_bytes(),
        validate_terminal(&repeated, &context)
            .unwrap()
            .canonical_bytes()
    );

    let mut forward = summary("evt-map-array");
    forward.extensions = Some(one_extension(
        "alpha.example",
        "a",
        ExtensionValue::Array(vec![
            ExtensionScalar::Number(1.0),
            ExtensionScalar::Number(2.0),
        ]),
    ));
    let mut reversed = summary("evt-map-array");
    reversed.extensions = Some(one_extension(
        "alpha.example",
        "a",
        ExtensionValue::Array(vec![
            ExtensionScalar::Number(2.0),
            ExtensionScalar::Number(1.0),
        ]),
    ));
    let forward = forward.materialize(MATERIALIZED);
    let forward = validate_terminal(&forward, &context).unwrap();
    let reversed = reversed.materialize(MATERIALIZED);
    assert_ne!(
        forward.canonical_bytes(),
        validate_terminal(&reversed, &context)
            .unwrap()
            .canonical_bytes()
    );
}

#[test]
fn nfc_equivalent_open_map_keys_are_rejected() {
    let context = Event4InMemoryContext::new();
    let mut candidate = observation("evt-nfc");
    if let EventBody::Observation(body) = &mut candidate.body {
        body.fact_provenance = Some(OpenMap::from_entries([
            ("caf\u{e9}".to_owned(), FactProvenance::Parsed),
            ("cafe\u{301}".to_owned(), FactProvenance::Parsed),
        ]));
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::DuplicateNormalizedKey
    );
}

#[test]
fn non_finite_numbers_and_oversized_excerpts_fail() {
    let context = Event4InMemoryContext::new();
    let mut candidate = finding("evt-nan");
    if let EventBody::Finding(body) = &mut candidate.body {
        body.confidence_score = Some(f64::NAN);
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidStructure
    );

    let mut candidate = finding("evt-evidence-nan");
    if let EventBody::Finding(body) = &mut candidate.body {
        body.evidence = Some(vec![Evidence {
            observation_id: Some(OBS_A.to_owned()),
            field: None,
            representation: EvidenceRepresentation::Count,
            value: Some(ExtensionScalar::Number(f64::INFINITY)),
        }]);
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::NonFiniteNumber
    );

    let mut candidate = summary("evt-extension-nan");
    candidate.extensions = Some(one_extension(
        "vendor.example",
        "number",
        ExtensionValue::Scalar(ExtensionScalar::Number(f64::NEG_INFINITY)),
    ));
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::NonFiniteNumber
    );

    let mut candidate = finding("evt-excerpt");
    if let EventBody::Finding(body) = &mut candidate.body {
        body.evidence = Some(vec![Evidence {
            observation_id: Some(OBS_A.to_owned()),
            field: None,
            representation: EvidenceRepresentation::RedactedExcerpt,
            value: Some(ExtensionScalar::String("x".repeat(513))),
        }]);
    }
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::InvalidEvidence
    );

    for (count, accepted) in [(32, true), (33, false)] {
        let mut candidate = finding(if accepted {
            "evt-evidence-32"
        } else {
            "evt-evidence-33"
        });
        if let EventBody::Finding(body) = &mut candidate.body {
            body.evidence = Some(
                (0..count)
                    .map(|_| Evidence {
                        observation_id: Some(OBS_A.to_owned()),
                        field: None,
                        representation: EvidenceRepresentation::Classification,
                        value: Some(ExtensionScalar::String("safe".to_owned())),
                    })
                    .collect(),
            );
        }
        assert_eq!(
            validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_ok(),
            accepted
        );
    }
}

#[test]
fn canonical_property_order_and_escaping_are_stable() {
    let context = Event4InMemoryContext::new();
    let mut candidate = summary("evt-order");
    candidate.extensions = Some(one_extension(
        "vendor.example",
        "escaped",
        ExtensionValue::Scalar(ExtensionScalar::String("quote\"line\n".to_owned())),
    ));
    let accepted =
        validate_terminal(&candidate.clone().materialize(MATERIALIZED), &context).unwrap();
    let text = std::str::from_utf8(accepted.canonical_bytes()).unwrap();
    assert!(text.starts_with("{\"schema_version\":\"4.0\",\"event_id\":\"evt-order\",\"type\":\"summary\",\"event_action\":\"summary.emitted\",\"observed_at\":"));
    assert!(text.contains("\"materialized_at\":\"2026-09-16T12:00:01Z\",\"summary\":"));
    assert!(text.contains("\"escaped\":\"quote\\\"line\\n\""));
    assert_eq!(
        accepted.canonical_bytes(),
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap()
            .canonical_bytes()
    );
}

#[test]
fn error_surfaces_never_echo_candidate_markers() {
    let context = Event4InMemoryContext::new();
    let marker = "SYNTHETIC_SECRET_MARKER";
    let mut candidate = summary("evt-private-error");
    candidate.observed_at = marker.to_owned();
    let error = validate_terminal(&candidate.materialize(MATERIALIZED), &context).unwrap_err();
    assert!(!error.to_string().contains(marker));
    assert!(!format!("{error:?}").contains(marker));
}
