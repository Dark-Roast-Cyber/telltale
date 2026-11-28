use super::*;

#[test]
fn message_text_recursive_failures_precede_partition_encoded_overflow() {
    for prefix in [
        JsonValue::Array(vec![JsonValue::string("\u{1}".repeat(2_731))]),
        JsonValue::string("x".repeat(4_000)),
    ] {
        let mut message = MessageObservation::new(MessageRole::User);
        for _ in 0..5 {
            message =
                message.with_content_part(ContentPart::new(ContentPartKind::Other, prefix.clone()));
        }
        let deep = (0..5).fold(JsonValue::Null, |v, _| JsonValue::Array(vec![v]));
        message = message.with_content_part(ContentPart::new(ContentPartKind::Other, deep));
        assert_eq!(
            message_text_builder(message)
                .build()
                .unwrap_err()
                .bound_dimension(),
            Some(BoundDimension::Depth)
        );
    }
}

#[test]
fn message_text_exact_aggregate_float_spelling_preserves_ordinary_sizing() {
    let value = JsonValue::Number(100.0);
    assert_eq!(value::bounded_json_bytes(&value, 1).unwrap(), 3);
    assert_eq!(
        value.encoded_byte_len().unwrap(),
        canonical_identity_json(&value).unwrap().len()
    );
    for (size, accepted) in [(65_523, true), (65_524, false)] {
        let builder = message_text_builder(
            MessageObservation::new(MessageRole::User)
                .with_content(JsonValue::string("x".repeat(size))),
        )
        .facet("message.number", SemanticFacet::new(value.clone()))
        .unwrap()
        .fact_metadata("message.number", FactMetadata::reported().unwrap());
        assert_eq!(builder.build().is_ok(), accepted);
    }
}

#[test]
fn message_text_long_scalar_and_parts_preserve_full_suffix() {
    let prefix = "é".repeat(10_000);
    let first = message_text_builder(
        MessageObservation::new(MessageRole::User)
            .with_content(JsonValue::string(format!("{prefix}A"))),
    );
    let changed = message_text_builder(
        MessageObservation::new(MessageRole::User)
            .with_content(JsonValue::string(format!("{prefix}B"))),
    );
    assert_ne!(
        first.assignment_commitment(ASSIGNMENT_KEY).unwrap(),
        changed.assignment_commitment(ASSIGNMENT_KEY).unwrap()
    );
    let a = first.build().unwrap();
    let b = changed.build().unwrap();
    assert_eq!(a.observation_id(), b.observation_id());
    assert_eq!(
        a.semantic_comparison().compare(b.semantic_comparison()),
        SemanticReplayVerdict::Mutated
    );
    message_text_builder(
        MessageObservation::new(MessageRole::User).with_content_part(ContentPart::new(
            ContentPartKind::Text,
            JsonValue::string(prefix),
        )),
    )
    .build()
    .unwrap();
}

#[test]
fn message_text_aggregate_parts_and_facets_fail_closed() {
    let parts = (0..2).fold(MessageObservation::new(MessageRole::User), |message, _| {
        message.with_content_part(ContentPart::new(
            ContentPartKind::Text,
            JsonValue::string("x".repeat(33_000)),
        ))
    });
    let builder = message_text_builder(parts);
    assert_eq!(
        builder.clone().build().unwrap_err().bound_dimension(),
        Some(BoundDimension::EncodedBytes)
    );
    assert_eq!(
        builder
            .assignment_commitment(ASSIGNMENT_KEY)
            .unwrap_err()
            .bound_dimension(),
        Some(BoundDimension::EncodedBytes)
    );
    let builder = message_text_builder(
        MessageObservation::new(MessageRole::User)
            .with_content(JsonValue::string("x".repeat(64_000))),
    )
    .facet(
        "message.extra",
        SemanticFacet::new(JsonValue::string("y".repeat(2_000))),
    )
    .unwrap()
    .fact_metadata("message.extra", FactMetadata::reported().unwrap());
    assert_eq!(
        builder.build().unwrap_err().bound_dimension(),
        Some(BoundDimension::EncodedBytes)
    );
}

#[test]
fn message_text_source_raw_utf8_limit_and_nfc_order() {
    let exact = "é".repeat(32_768);
    let converted = JsonValue::try_from_source_message_content(&serde_json::json!(exact)).unwrap();
    assert_eq!(converted, JsonValue::string(&exact));
    let part = ContentPart::try_from_source_value(ContentPartKind::Text, &serde_json::json!(exact))
        .unwrap();
    assert_eq!(part.value(), &converted);
    for text in [format!("{exact}x"), "e\u{301}".repeat(21_846)] {
        assert_eq!(
            JsonValue::try_from_source_message_content(&serde_json::json!(text))
                .unwrap_err()
                .bound_dimension(),
            Some(BoundDimension::StringBytes)
        );
        assert_eq!(
            ContentPart::try_from_source_value(ContentPartKind::Text, &serde_json::json!(text))
                .unwrap_err()
                .bound_dimension(),
            Some(BoundDimension::StringBytes)
        );
    }
    let decomposed = "e\u{301}".repeat(21_846);
    message_text_builder(
        MessageObservation::new(MessageRole::User).with_content(JsonValue::String(decomposed)),
    )
    .build()
    .unwrap();
    // A valid raw allowance does not promise aggregate acceptance.
    assert_eq!(
        message_text_builder(MessageObservation::new(MessageRole::User).with_content(converted))
            .build()
            .unwrap_err()
            .bound_dimension(),
        Some(BoundDimension::EncodedBytes)
    );
    assert_eq!(
        scoped_message(source(), &format!("{exact}x"))
            .unwrap_err()
            .bound_dimension(),
        Some(BoundDimension::StringBytes)
    );
}

#[test]
fn message_text_exact_encoded_aggregate_and_conversion_builder_parity() {
    // Sum of encoded values: role = 6, scalar quotes = 2.
    for (text, accepted) in [
        ("x".repeat(65_528), true),
        ("x".repeat(65_529), false),
        ("\n".repeat(32_764), true),
        ("\n".repeat(32_765), false),
    ] {
        let converted =
            JsonValue::try_from_source_message_content(&serde_json::json!(text)).unwrap();
        let builder = message_text_builder(
            MessageObservation::new(MessageRole::User).with_content(converted),
        );
        let direct = message_text_builder(
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string(&text)),
        );
        assert_eq!(
            builder.assignment_commitment(ASSIGNMENT_KEY),
            direct.assignment_commitment(ASSIGNMENT_KEY)
        );
        assert_eq!(builder.clone().build().is_ok(), accepted);
        assert_eq!(
            builder.assignment_commitment(ASSIGNMENT_KEY).is_ok(),
            accepted
        );
    }
    // role = 6, array = 2, part wrapper + kind + quotes = 26.
    for (size, accepted) in [(65_502, true), (65_503, false)] {
        let part = ContentPart::try_from_source_value(
            ContentPartKind::Text,
            &serde_json::json!("x".repeat(size)),
        )
        .unwrap();
        let wrapped = JsonValue::object([
            ("kind".to_owned(), JsonValue::string(part.kind().as_str())),
            ("value".to_owned(), part.value().clone()),
        ])
        .unwrap();
        assert_eq!(
            part.bounded_json_bytes().unwrap(),
            canonical_identity_json(&wrapped).unwrap().len()
        );
        assert_eq!(
            message_text_builder(
                MessageObservation::new(MessageRole::User).with_content_part(part)
            )
            .build()
            .is_ok(),
            accepted
        );
    }
}

#[test]
fn message_text_allowance_does_not_escape_into_structured_or_local_values() {
    let long = "x".repeat(4_097);
    for value in [serde_json::json!([long]), serde_json::json!({"text": long})] {
        assert_eq!(
            JsonValue::try_from_source_message_content(&value)
                .unwrap_err()
                .bound_dimension(),
            Some(BoundDimension::StringBytes)
        );
        assert_eq!(
            ContentPart::try_from_source_value(ContentPartKind::Text, &value)
                .unwrap_err()
                .bound_dimension(),
            Some(BoundDimension::StringBytes)
        );
    }
    for kind in [
        ContentPartKind::ToolUse,
        ContentPartKind::ToolResult,
        ContentPartKind::ImageReference,
        ContentPartKind::Other,
    ] {
        assert_eq!(
            ContentPart::try_from_source_value(kind, &serde_json::json!(long))
                .unwrap_err()
                .bound_dimension(),
            Some(BoundDimension::StringBytes)
        );
        assert_eq!(
            message_text_builder(
                MessageObservation::new(MessageRole::User)
                    .with_content_part(ContentPart::new(kind, JsonValue::string(&long)))
            )
            .build()
            .unwrap_err()
            .bound_dimension(),
            Some(BoundDimension::StringBytes)
        );
    }
    for value in [
        JsonValue::Array(vec![JsonValue::string(&long)]),
        JsonValue::object([("text".to_owned(), JsonValue::string(&long))]).unwrap(),
    ] {
        assert_eq!(
            message_text_builder(
                MessageObservation::new(MessageRole::User).with_content(value.clone())
            )
            .build()
            .unwrap_err()
            .bound_dimension(),
            Some(BoundDimension::StringBytes)
        );
        assert_eq!(
            message_text_builder(
                MessageObservation::new(MessageRole::User)
                    .with_content_part(ContentPart::new(ContentPartKind::Text, value))
            )
            .build()
            .unwrap_err()
            .bound_dimension(),
            Some(BoundDimension::StringBytes)
        );
    }
    assert!(JsonValue::try_from_source_value(&serde_json::json!(long)).is_err());
    assert!(
        LocalValue::new(
            JsonValue::string(&long),
            None::<&str>,
            FactProvenance::Reported,
            Sensitivity::Normal
        )
        .is_err()
    );
    assert!(
        build_with_provenance(
            ObservationBody::Tool(ToolObservation::new().with_name(&long).unwrap()),
            ObservationStage::ToolRequested,
            &[("tool.name", FactProvenance::Reported)]
        )
        .is_err()
    );
    assert!(
        build_with_provenance(
            ObservationBody::Inference(InferenceObservation::new().with_provider(&long).unwrap()),
            ObservationStage::InferenceRequested,
            &[("inference.provider", FactProvenance::Reported)]
        )
        .is_err()
    );
    let builder = message_text_builder(MessageObservation::new(MessageRole::User))
        .facet(
            "message.content",
            SemanticFacet::new(JsonValue::string(&long)),
        )
        .unwrap()
        .fact_metadata("message.content", FactMetadata::reported().unwrap());
    assert_eq!(
        builder.build().unwrap_err().bound_dimension(),
        Some(BoundDimension::StringBytes)
    );
    let encoded_excess = JsonValue::Array(vec![JsonValue::string("\u{1}".repeat(2_731))]);
    assert_eq!(
        message_text_builder(
            MessageObservation::new(MessageRole::User).with_content(encoded_excess.clone())
        )
        .build()
        .unwrap_err()
        .bound_dimension(),
        Some(BoundDimension::EncodedBytes)
    );
    assert_eq!(
        message_text_builder(
            MessageObservation::new(MessageRole::User)
                .with_content_part(ContentPart::new(ContentPartKind::Text, encoded_excess))
        )
        .build()
        .unwrap_err()
        .bound_dimension(),
        Some(BoundDimension::EncodedBytes)
    );
    assert!(
        LocalValue::new(
            JsonValue::Array(vec![JsonValue::string(&long)]),
            None::<&str>,
            FactProvenance::Reported,
            Sensitivity::Normal
        )
        .is_err()
    );
}

#[test]
fn message_text_mixed_scalar_parts_and_facet_exact_aggregate() {
    for (size, accepted) in [(1_498, true), (1_499, false)] {
        // role(6) + scalar(64002) + parts([{"kind":"text","value":""}])(28)
        // + facet(size + 2) = 65536 at the exact boundary.
        let builder = message_text_builder(
            MessageObservation::new(MessageRole::User)
                .with_content(JsonValue::string("x".repeat(64_000)))
                .with_content_part(ContentPart::new(
                    ContentPartKind::Text,
                    JsonValue::string(""),
                )),
        )
        .facet(
            "message.extra",
            SemanticFacet::new(JsonValue::string("y".repeat(size))),
        )
        .unwrap()
        .fact_metadata("message.extra", FactMetadata::reported().unwrap());
        assert_eq!(builder.clone().build().is_ok(), accepted);
        let commitment = builder.assignment_commitment(ASSIGNMENT_KEY);
        assert_eq!(commitment.is_ok(), accepted);
        if !accepted {
            assert_eq!(
                commitment.unwrap_err().bound_context(),
                Some(CanonicalBoundContext {
                    category: CanonicalFieldCategory::SemanticFacet,
                    dimension: BoundDimension::EncodedBytes,
                })
            );
        }
    }
}

#[test]
fn message_text_non_text_parts_keep_the_ordinary_encoded_field_budget() {
    for kind in [ContentPartKind::ToolUse, ContentPartKind::Text] {
        let message = (0..5).fold(MessageObservation::new(MessageRole::User), |message, _| {
            message.with_content_part(ContentPart::new(
                kind,
                JsonValue::Array(vec![JsonValue::string("x".repeat(4_000))]),
            ))
        });
        assert_eq!(
            message_text_builder(message)
                .build()
                .unwrap_err()
                .bound_context(),
            Some(CanonicalBoundContext {
                category: CanonicalFieldCategory::MessageContentParts,
                dimension: BoundDimension::EncodedBytes,
            })
        );
    }
}

#[test]
fn message_text_assignment_preflight_and_replay_share_complete_validation() {
    let source = SourceProvenance::new(
        IngestionMode::Import,
        "synthetic",
        "assignment",
        Fidelity::FullNative,
    )
    .unwrap();
    let builder = |suffix| {
        let mut builder = message_text_builder(
            MessageObservation::new(MessageRole::User)
                .with_content(JsonValue::string(format!("{}{suffix}", "x".repeat(20_000)))),
        );
        builder.source = source.clone();
        builder
    };
    let original = builder("A");
    let claim = original.prepare_assignment_claim(ASSIGNMENT_KEY).unwrap();
    assert_eq!(
        claim.commitment(),
        original.assignment_commitment(ASSIGNMENT_KEY).unwrap()
    );
    let mut store = InMemoryAssignmentStore::new();
    store
        .insert_key("assignmentkey:v2:synthetic-1", ASSIGNMENT_KEY)
        .unwrap();
    store
        .insert_assignment(
            "assignment-ref-1",
            AssignmentRecord::new(
                "synthetic:assignment",
                "replay-key-1",
                0,
                "obs:v2:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "assignmentkey:v2:synthetic-1",
                claim.commitment(),
            )
            .unwrap(),
        )
        .unwrap();
    let basis = IdentityBasis::persisted(
        "synthetic:assignment",
        "replay-key-1",
        LocalReference::new("assignment-ref-1", "assignment").unwrap(),
        0,
        "none",
    )
    .unwrap();
    original
        .identity_basis(basis.clone())
        .build_with_assignments(&store)
        .unwrap();
    assert_eq!(
        builder("B")
            .identity_basis(basis)
            .build_with_assignments(&store)
            .unwrap_err()
            .code(),
        "replay_collision"
    );
    let mut oversized = message_text_builder(
        MessageObservation::new(MessageRole::User)
            .with_content(JsonValue::string("x".repeat(65_529))),
    );
    oversized.source = source;
    assert_eq!(
        oversized
            .prepare_assignment_claim(ASSIGNMENT_KEY)
            .unwrap_err()
            .bound_dimension(),
        Some(BoundDimension::EncodedBytes)
    );
}
