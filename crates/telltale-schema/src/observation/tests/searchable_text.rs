use super::*;

/// A derived searchable text over its bound is omitted and recorded while the
/// tool values stay whole; one within its bound is kept as given.
#[test]
fn searchable_text_over_its_bound_is_omitted_and_recorded() {
    let arguments = JsonValue::try_from_source_value(&serde_json::json!({"path":"/p"})).unwrap();
    let tool = || {
        ToolObservation::new()
            .with_name("synthetic")
            .unwrap()
            .with_arguments(arguments.clone())
    };
    let paths = [
        ("tool.name", FactProvenance::Reported),
        ("tool.arguments", FactProvenance::Reported),
    ];
    for (text, dimension) in [
        ("x".repeat(4_097), BoundDimension::StringBytes),
        // Within the string bound, over the encoded bound of a value.
        ("\u{1}".repeat(2_731), BoundDimension::EncodedBytes),
    ] {
        // As given, the text fails the observation.
        let error = build_with_provenance(
            ObservationBody::Tool(tool().with_searchable_arguments(&text).unwrap()),
            ObservationStage::ToolRequested,
            &[
                paths[0],
                paths[1],
                ("tool.searchable_arguments", FactProvenance::Reported),
            ],
        )
        .unwrap_err();
        assert_eq!(error.bound_dimension(), Some(dimension));
        for target in [
            BoundedTarget::SearchableArguments,
            BoundedTarget::SearchableResult,
        ] {
            let body = if target == BoundedTarget::SearchableArguments {
                tool().with_bounded_searchable_arguments(&text).unwrap()
            } else {
                tool().with_bounded_searchable_result(&text).unwrap()
            };
            assert_eq!(body.searchable_arguments(), None);
            assert_eq!(body.searchable_result(), None);
            assert_eq!(body.arguments(), Some(&arguments));
            assert_eq!(entries(&body), [(target, String::new(), dimension)]);
            assert_eq!(body.bounded_values()[0].bytes(), text.len() as u64);
            let observation = build_with_provenance(
                ObservationBody::Tool(body),
                ObservationStage::ToolRequested,
                &paths,
            )
            .unwrap();
            let field = observation
                .body()
                .semantic_fields()
                .into_iter()
                .find(|(path, _)| path == "tool.bounded_values")
                .unwrap()
                .1;
            assert_eq!(
                field,
                JsonValue::try_from_source_value(&serde_json::json!([{"bytes":text.len(), "dimension":dimension.as_str(), "pointer":"", "target":target.as_str()}])).unwrap()
            );
            assert!(!format!("{:?}", observation.body()).contains("xxxx"));
        }
    }
    let kept = tool()
        .with_bounded_searchable_arguments("x".repeat(4_096))
        .unwrap();
    assert_eq!(
        kept.searchable_arguments(),
        Some("x".repeat(4_096).as_str())
    );
    assert!(kept.bounded_values().is_empty());
}

/// An omitted searchable text's entry is checked as strictly as a replaced
/// value's: its field absent, the empty pointer and a string bound.
#[test]
fn a_searchable_text_entry_must_name_an_omitted_text() {
    let entry = |pointer: &str, dimension| {
        BoundedValue::new(
            BoundedTarget::SearchableArguments,
            pointer,
            dimension,
            5_000,
        )
    };
    let arguments = JsonValue::try_from_source_value(&serde_json::json!({"a":"kept"})).unwrap();
    let validate = |values: &[BoundedValue], searchable| {
        super::super::value::validate_bounded_values(values, Some(&arguments), None, searchable)
    };
    validate(&[entry("", BoundDimension::StringBytes)], [false; 2]).unwrap();
    validate(&[entry("", BoundDimension::EncodedBytes)], [false; 2]).unwrap();
    // The text it names is present.
    validate(&[entry("", BoundDimension::StringBytes)], [true, false]).unwrap_err();
    // A pointer into a value.
    validate(&[entry("/a", BoundDimension::StringBytes)], [false; 2]).unwrap_err();
    // A bound no string has.
    validate(&[entry("", BoundDimension::ArrayItems)], [false; 2]).unwrap_err();
    // Built through the body, a present text is refused too.
    let body = ToolObservation::new()
        .with_name("synthetic")
        .unwrap()
        .with_arguments(arguments.clone())
        .with_searchable_arguments("kept")
        .unwrap()
        .with_bounded_values([entry("", BoundDimension::StringBytes)]);
    let error = build_with_provenance(
        ObservationBody::Tool(body),
        ObservationStage::ToolRequested,
        &[
            ("tool.name", FactProvenance::Reported),
            ("tool.arguments", FactProvenance::Reported),
            ("tool.searchable_arguments", FactProvenance::Reported),
        ],
    )
    .unwrap_err();
    assert_eq!(error.code(), ValidationCode::InvalidBody.as_str());
}

/// Fitting or replacing the tool values keeps an omitted text's entry.
#[test]
fn fitting_values_keeps_an_omitted_searchable_text_entry() {
    let large = |count: usize| {
        // Each value within its bound, together over the room for them.
        JsonValue::Object(
            (0..count)
                .map(|index| (format!("k{index}"), JsonValue::string("v".repeat(4_000))))
                .collect(),
        )
    };
    let omitted = (
        BoundedTarget::SearchableArguments,
        String::new(),
        BoundDimension::StringBytes,
    );
    let body = || {
        ToolObservation::new()
            .with_name("synthetic")
            .unwrap()
            .with_arguments(large(13))
            .with_bounded_searchable_arguments("x".repeat(4_097))
            .unwrap()
    };
    let fitted = body().with_fitted_values().unwrap();
    let fitted_entries = entries(&fitted);
    assert!(fitted_entries.contains(&omitted), "{fitted_entries:?}");
    assert!(
        fitted_entries
            .iter()
            .any(|(target, _, _)| *target == BoundedTarget::Arguments)
    );
    let whole = body().with_replaced_values().unwrap();
    assert_eq!(
        entries(&whole),
        [
            (
                BoundedTarget::Arguments,
                String::new(),
                BoundDimension::EncodedBytes
            ),
            omitted
        ]
    );
}

/// An omitted searchable text's entry counts toward the cap on recorded
/// entries: on top of a full list of replaced values, the field with more
/// entries is replaced whole and the observation stays valid.
#[test]
fn an_omitted_searchable_text_counts_toward_the_entry_cap() {
    let source = serde_json::Value::Object(
        (0..TOOL_MAX_BOUNDED_VALUES)
            .map(|index| (format!("k{index}"), serde_json::json!("x".repeat(4_097))))
            .collect(),
    );
    let (arguments, replaced) = bounded(&source);
    assert_eq!(replaced.len(), TOOL_MAX_BOUNDED_VALUES);
    let tool = ToolObservation::new()
        .with_name("synthetic")
        .unwrap()
        .with_arguments(arguments)
        .with_bounded_values(replaced);
    assert_eq!(tool.bounded_values().len(), TOOL_MAX_BOUNDED_VALUES);
    let tool = tool
        .with_bounded_searchable_arguments("y".repeat(4_097))
        .unwrap();
    assert_eq!(
        entries(&tool),
        [
            (
                BoundedTarget::Arguments,
                String::new(),
                BoundDimension::StringBytes
            ),
            (
                BoundedTarget::SearchableArguments,
                String::new(),
                BoundDimension::StringBytes
            ),
        ]
    );
    assert_eq!(tool.arguments(), Some(&JsonValue::Null));
    build_with_provenance(
        ObservationBody::Tool(tool),
        ObservationStage::ToolRequested,
        &[
            ("tool.name", FactProvenance::Reported),
            ("tool.arguments", FactProvenance::Reported),
        ],
    )
    .unwrap();
}
