use super::*;

#[test]
fn canonical_bound_dimensions_preserve_exact_limits_and_check_order() {
    use serde_json::{Value, json};
    let nested = |count| (0..count).fold(Value::Null, |value, _| json!([value]));
    let object =
        |count| Value::Object((0..count).map(|i| (format!("k{i}"), Value::Null)).collect());
    let cases = [
        (
            json!("é".repeat(2048)),
            json!(format!("{}x", "é".repeat(2048))),
            BoundDimension::StringBytes,
        ),
        (nested(5), nested(6), BoundDimension::Depth),
        (
            json!(vec![Value::Null; 64]),
            json!(vec![Value::Null; 65]),
            BoundDimension::ArrayItems,
        ),
        (object(32), object(33), BoundDimension::ObjectMembers),
        (
            json!({"k".repeat(64): null}),
            json!({"k".repeat(65): null}),
            BoundDimension::KeyBytes,
        ),
        (
            json!(["\u{1}".repeat(2730)]),
            json!(["\u{1}".repeat(2731)]),
            BoundDimension::EncodedBytes,
        ),
    ];
    for (exact, excess, dimension) in cases {
        let accepted = JsonValue::try_from_source_value(&exact).expect("exact bound");
        bounded_semantic_value_bytes(&accepted).unwrap();
        let error = JsonValue::try_from_source_value(&excess).unwrap_err();
        assert_eq!(error.bound_dimension(), Some(dimension));
        assert_eq!(error.bound_context(), None);
        assert_eq!(error.code(), "unbounded_value");
        assert_eq!(
            error.to_string(),
            "canonical observation rejected (unbounded_value)"
        );
        // Builder validation uses the same dimension, not a source reread/conversion.
        let converted: JsonValue = match dimension {
            BoundDimension::StringBytes => JsonValue::String("é".repeat(2049)),
            BoundDimension::Depth => (0..6).fold(JsonValue::Null, |v, _| JsonValue::Array(vec![v])),
            BoundDimension::ArrayItems => JsonValue::Array(vec![JsonValue::Null; 65]),
            BoundDimension::ObjectMembers => JsonValue::Object(
                (0..33)
                    .map(|i| (format!("k{i}"), JsonValue::Null))
                    .collect(),
            ),
            BoundDimension::KeyBytes => {
                JsonValue::Object([("k".repeat(65), JsonValue::Null)].into())
            }
            BoundDimension::EncodedBytes => {
                JsonValue::Array(vec![JsonValue::string("\u{1}".repeat(2731))])
            }
        };
        let body = ObservationBody::Tool(ToolObservation::new().with_arguments(converted));
        let error = build_with_provenance(body, ObservationStage::ToolRequested, &[]).unwrap_err();
        assert_eq!(
            error.bound_context(),
            Some(CanonicalBoundContext {
                category: CanonicalFieldCategory::ToolArguments,
                dimension
            })
        );
    }
    let error = JsonValue::try_from_source_value(&json!(vec!["x".repeat(4097); 65])).unwrap_err();
    assert_eq!(error.bound_dimension(), Some(BoundDimension::ArrayItems));
    let error =
        JsonValue::try_from_source_value(&json!({"k".repeat(65): "x".repeat(4097)})).unwrap_err();
    assert_eq!(error.bound_dimension(), Some(BoundDimension::KeyBytes));
}

#[test]
fn canonical_bound_nfc_and_assembled_fields_are_not_revalidated_differently() {
    let decomposed = "e\u{301}".repeat(1366);
    assert_eq!(
        JsonValue::try_from_source_value(&serde_json::json!(decomposed))
            .unwrap_err()
            .bound_dimension(),
        Some(BoundDimension::StringBytes)
    );
    // Source conversion checks original bytes; builder checks already-normalized text.
    scoped_message(source(), &decomposed).unwrap();
    let parts = (0..65).fold(MessageObservation::new(MessageRole::User), |body, _| {
        body.with_content_part(ContentPart::new(
            ContentPartKind::Text,
            JsonValue::string("ok"),
        ))
    });
    let error = build_with_provenance(
        ObservationBody::Message(parts),
        ObservationStage::MessageObserved,
        &[],
    )
    .unwrap_err();
    assert_eq!(
        error.bound_context(),
        Some(CanonicalBoundContext {
            category: CanonicalFieldCategory::MessageContentParts,
            dimension: BoundDimension::ArrayItems
        })
    );
    for (name, category) in [
        ("command.text", CanonicalFieldCategory::CommandText),
        ("resource.path", CanonicalFieldCategory::ResourcePath),
        ("runtime.synthetic", CanonicalFieldCategory::SemanticFacet),
    ] {
        let error = CanonicalObservationV2::builder(
            ObservationBody::Message(MessageObservation::new(MessageRole::User)),
            ObservationStage::MessageObserved,
            ObservedAt::new(OBSERVED_AT).unwrap(),
            source(),
        )
        .facet(
            name,
            SemanticFacet::new(JsonValue::string("x".repeat(4097))),
        )
        .unwrap()
        .build()
        .unwrap_err();
        assert_eq!(
            error.bound_context(),
            Some(CanonicalBoundContext {
                category,
                dimension: BoundDimension::StringBytes
            })
        );
        assert!(!format!("{error:?}").contains(name), "facet name retained");
    }
    let error = ObservationError::from_validation_code(ValidationCode::UnboundedValue)
        .with_bound_category(CanonicalFieldCategory::ToolResult);
    assert_eq!(error.bound_context(), None);
    assert_eq!(
        ObservationError::new(ValidationCode::NonFiniteNumber)
            .with_bound_category(CanonicalFieldCategory::ToolResult)
            .bound_context(),
        None
    );
}
