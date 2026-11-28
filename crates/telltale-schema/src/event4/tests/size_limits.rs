use super::*;

#[test]
fn extensions_reject_names_nesting_and_reserved_properties() {
    let context = Event4InMemoryContext::new();
    for (namespace, property) in [
        ("notqualified", "custom"),
        ("telltale.vendor", "custom"),
        ("vendor.example", "event_id"),
        ("vendor.example", "materialized_at"),
        ("vendor.example", "finding"),
        ("vendor.example", "risk_score"),
    ] {
        let mut candidate = summary("evt-extension-invalid");
        candidate.extensions = Some(one_extension(
            namespace,
            property,
            ExtensionValue::Scalar(ExtensionScalar::Bool(true)),
        ));
        assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_err());
    }

    let event = summary("evt-extension-nested").materialize(MATERIALIZED);
    let mut value = serde_json::to_value(&event).unwrap();
    value.as_object_mut().unwrap().insert(
        "extensions".to_owned(),
        json!({"vendor.example":{"custom":{"nested":true}}}),
    );
    assert!(validate_event4_structure(&value).is_err());

    let mut value = serde_json::to_value(&event).unwrap();
    value.as_object_mut().unwrap().insert(
        "extensions".to_owned(),
        json!({"vendor.example":{"custom":[[true]]}}),
    );
    assert!(validate_event4_structure(&value).is_err());
}

#[test]
fn extension_scalar_limit_accepts_512_and_rejects_513() {
    let context = Event4InMemoryContext::new();
    let mut candidate = summary("evt-512");
    candidate.extensions = Some(scalar_boundary_extensions(false));
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_ok());

    let mut candidate = summary("evt-513");
    candidate.extensions = Some(scalar_boundary_extensions(true));
    assert_eq!(
        validate_terminal(&candidate.materialize(MATERIALIZED), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::ExtensionScalarLimit
    );
}

#[test]
fn extension_collection_and_string_limits_are_enforced() {
    let context = Event4InMemoryContext::new();

    let mut candidate = summary("evt-array-32");
    candidate.extensions = Some(one_extension(
        "vendor.example",
        "items",
        ExtensionValue::Array(vec![ExtensionScalar::Bool(true); 32]),
    ));
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_ok());

    let mut candidate = summary("evt-array-33");
    candidate.extensions = Some(one_extension(
        "vendor.example",
        "items",
        ExtensionValue::Array(vec![ExtensionScalar::Bool(true); 33]),
    ));
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_err());

    for (length, accepted) in [(1024, true), (1025, false)] {
        let mut candidate = summary(if accepted {
            "evt-string-1024"
        } else {
            "evt-string-1025"
        });
        candidate.extensions = Some(one_extension(
            "vendor.example",
            "text",
            ExtensionValue::Scalar(ExtensionScalar::String("x".repeat(length))),
        ));
        assert_eq!(
            validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_ok(),
            accepted
        );
    }

    let mut namespaces = OpenMap::new();
    for index in 0..17 {
        namespaces.insert(format!("vendor{index}.example"), OpenMap::new());
    }
    let mut candidate = summary("evt-namespace-17");
    candidate.extensions = Some(namespaces);
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_err());

    let mut properties = OpenMap::new();
    for index in 0..17 {
        properties.insert(
            format!("property_{index}"),
            ExtensionValue::Scalar(ExtensionScalar::Null),
        );
    }
    let mut extensions = OpenMap::new();
    extensions.insert("vendor.example", properties);
    let mut candidate = summary("evt-property-17");
    candidate.extensions = Some(extensions);
    assert!(validate_terminal(&candidate.materialize(MATERIALIZED), &context).is_err());
}

#[test]
fn extension_byte_limit_accepts_16384_and_rejects_16385() {
    let context = Event4InMemoryContext::new();
    for (size, accepted) in [
        (EXTENSIONS_MAX_BYTES, true),
        (EXTENSIONS_MAX_BYTES + 1, false),
    ] {
        let extensions = sized_extensions(size);
        assert_eq!(serde_json::to_vec(&extensions).unwrap().len(), size);
        let mut candidate = summary(if accepted {
            "evt-ext-max"
        } else {
            "evt-ext-over"
        });
        candidate.extensions = Some(extensions);
        let result = validate_terminal(&candidate.materialize(MATERIALIZED), &context);
        assert_eq!(result.is_ok(), accepted);
    }
}

#[test]
fn full_event_byte_limit_accepts_65536_and_rejects_65537() {
    let context = Event4InMemoryContext::new();
    assert!(validate_terminal(&sized_event(EVENT4_MAX_BYTES), &context).is_ok());
    assert_eq!(
        validate_terminal(&sized_event(EVENT4_MAX_BYTES + 1), &context)
            .unwrap_err()
            .code(),
        Event4ValidationCode::EventTooLarge
    );
}

#[test]
fn object_array_depth_counts_root_as_one() {
    let depth8 = json!({"a":{"b":[{"c":{"d":[{"e":[]} ]}}]}});
    assert_eq!(super::super::validate::test_container_depth(&depth8), 8);
    let depth9 = json!({"a":{"b":[{"c":{"d":[{"e":[[]]}]}}]}});
    assert_eq!(super::super::validate::test_container_depth(&depth9), 9);
}
