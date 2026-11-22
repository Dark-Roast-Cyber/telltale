use super::*;

const OBSERVED_AT: &str = "2026-09-02T12:00:00Z";
const PRODUCER_KEY: &[u8] = b"synthetic-only-producer-key-epoch-1";
const ASSIGNMENT_KEY: &[u8] = b"synthetic-only-assignment-comparison-key-1";

#[test]
fn direct_tool_result_text_bounds_are_distinct_from_structured_values() {
    let build = |result: JsonValue| {
        CanonicalObservationV2::builder(
            ObservationBody::Tool(ToolObservation::new().with_result(result)),
            ObservationStage::ToolResultReturned,
            ObservedAt::new(OBSERVED_AT).unwrap(),
            source(),
        )
        .fact_metadata("tool.result", FactMetadata::reported().unwrap())
        .build()
    };
    for text in ["x".repeat(58_346), "é".repeat(32_767), "\n".repeat(32_767)] {
        let value = JsonValue::try_from_source_tool_result(&serde_json::json!(text)).unwrap();
        assert_eq!(
            build(value).unwrap().body(),
            &ObservationBody::Tool(ToolObservation::new().with_result(JsonValue::string(&text)))
        );
    }
    for (text, dimension) in [
        ("x".repeat(65_535), BoundDimension::EncodedBytes),
        ("\n".repeat(32_768), BoundDimension::EncodedBytes),
        ("é".repeat(32_769), BoundDimension::StringBytes),
    ] {
        let error = build(JsonValue::string(text)).unwrap_err();
        assert_eq!(
            error.bound_context(),
            Some(CanonicalBoundContext {
                category: CanonicalFieldCategory::ToolResult,
                dimension,
            })
        );
    }
    assert!(JsonValue::try_from_source_tool_result(&serde_json::json!("x".repeat(65_536))).is_ok());
    assert_eq!(
        JsonValue::try_from_source_tool_result(&serde_json::json!("x".repeat(65_537)))
            .unwrap_err()
            .bound_dimension(),
        Some(BoundDimension::StringBytes)
    );
    // The relaxation is restricted to a direct result, including on embedding
    // construction. It does not extend local evidence, facets or arguments.
    let nested = serde_json::json!({"output": "x".repeat(4_097)});
    assert!(JsonValue::try_from_source_tool_result(&nested).is_err());
    assert!(
        build(
            JsonValue::try_from_source_value(&serde_json::json!({"output":"x".repeat(4_096)}))
                .unwrap()
        )
        .is_ok()
    );
    assert!(
        LocalValue::new(
            JsonValue::string("x".repeat(4_097)),
            None::<&str>,
            FactProvenance::Reported,
            Sensitivity::Normal
        )
        .is_err()
    );
    let arguments = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new().with_arguments(JsonValue::string("x".repeat(4_097))),
        ),
        ObservationStage::ToolRequested,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.arguments", FactMetadata::reported().unwrap())
    .build()
    .unwrap_err();
    assert_eq!(
        arguments.bound_context(),
        Some(CanonicalBoundContext {
            category: CanonicalFieldCategory::ToolArguments,
            dimension: BoundDimension::StringBytes,
        })
    );
}

/// Synthetic declarations standing in for a source's tool table: the schema
/// holds the mechanism, a source adapter declares which fields are text.
fn declared(name: &str) -> ArgumentText {
    let (keys, whole, strict): (&[&str], bool, bool) = match name {
        "apply_patch" => (&["patchText"], true, true),
        "patch" => (&["patchText"], false, false),
        "shell" => (&["command"], true, false),
        "bash" => (&["command"], false, false),
        "write" => (&["content"], false, false),
        "edit" => (&["oldString", "newString"], false, false),
        "execute" => (&["code"], false, false),
        "subagent" | "task" => (&["prompt"], false, false),
        "exec" => (&[], true, false),
        _ => (&[], false, false),
    };
    let mut text = keys
        .iter()
        .fold(ArgumentText::new(), |text, key| text.with_key(*key));
    if whole {
        text = text.with_whole();
    }
    if strict {
        text = text.with_strict();
    }
    text
}

#[test]
fn apply_patch_text_is_a_narrow_bounded_argument_exception() {
    let build = |name: &str, arguments: JsonValue, result: Option<JsonValue>| {
        let mut tool = ToolObservation::new()
            .with_name(name)
            .unwrap()
            .with_arguments(arguments)
            .with_argument_text(declared(name));
        if let Some(result) = &result {
            tool = tool.with_result(result.clone());
        }
        let mut builder = CanonicalObservationV2::builder(
            ObservationBody::Tool(tool),
            if result.is_some() {
                ObservationStage::ToolExecutionCompleted
            } else {
                ObservationStage::ToolRequested
            },
            ObservedAt::new(OBSERVED_AT).unwrap(),
            source(),
        )
        .fact_metadata("tool.name", FactMetadata::reported().unwrap())
        .fact_metadata("tool.arguments", FactMetadata::reported().unwrap());
        if result.is_some() {
            builder = builder.fact_metadata("tool.result", FactMetadata::reported().unwrap());
        }
        builder.build()
    };
    for (bytes, accepted) in [(9_493, true), (65_507, true), (65_508, false)] {
        let input = serde_json::json!({"patchText":"x".repeat(bytes)});
        let arguments =
            JsonValue::try_from_source_tool_arguments(&declared("apply_patch"), &input).unwrap();
        assert_eq!(build("apply_patch", arguments, None).is_ok(), accepted);
    }
    let long = serde_json::json!({"patchText":"x".repeat(9_493)});
    assert!(JsonValue::try_from_source_tool_arguments(&declared("bash"), &long).is_err());
    for input in [
        serde_json::json!({"patchText": ["ok"]}),
        serde_json::json!({"patchText":"x".repeat(65_537)}),
        serde_json::json!({"patchText":"ok", "command":"x".repeat(4_097)}),
        serde_json::json!({"nested":{"patchText":"x".repeat(4_097)}}),
    ] {
        assert!(
            JsonValue::try_from_source_tool_arguments(&declared("apply_patch"), &input).is_err()
        );
    }
    let arguments =
        JsonValue::try_from_source_tool_arguments(&declared("apply_patch"), &long).unwrap();
    let error = build(
        "apply_patch",
        arguments,
        Some(JsonValue::string("y".repeat(56_020))),
    )
    .unwrap_err();
    assert_eq!(error.bound_dimension(), Some(BoundDimension::EncodedBytes));
    // Direct embedding construction cannot bypass the declared fields.
    let arguments =
        JsonValue::object([("patchText".into(), JsonValue::string("x".repeat(9_493)))]).unwrap();
    assert!(build("bash", arguments, None).is_err());
}

#[test]
fn authored_text_arguments_are_exact_tool_field_pairs() {
    let long = "x".repeat(20_000);
    let tool_body = |name: &str, arguments: JsonValue| {
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name(name)
                .unwrap()
                .with_arguments(arguments)
                .with_argument_text(declared(name)),
        )
    };
    let build = |body: ObservationBody, command: Option<&str>| {
        let mut builder = CanonicalObservationV2::builder(
            body,
            ObservationStage::ToolRequested,
            ObservedAt::new(OBSERVED_AT).unwrap(),
            source(),
        )
        .fact_metadata("tool.name", FactMetadata::reported().unwrap())
        .fact_metadata("tool.arguments", FactMetadata::reported().unwrap());
        if let Some(command) = command {
            builder = builder
                .facet(
                    "command.text",
                    SemanticFacet::new(JsonValue::string(command)),
                )
                .unwrap()
                .fact_metadata("command.text", FactMetadata::parsed().unwrap());
        }
        builder.build()
    };
    for (name, field) in [
        ("patch", "patchText"),
        ("shell", "command"),
        ("bash", "command"),
        ("write", "content"),
        ("edit", "oldString"),
        ("edit", "newString"),
        ("execute", "code"),
        ("subagent", "prompt"),
        ("task", "prompt"),
    ] {
        let input = serde_json::json!({field: long, "path": "./a"});
        let arguments = JsonValue::try_from_source_tool_arguments(&declared(name), &input).unwrap();
        assert!(
            build(tool_body(name, arguments), None).is_ok(),
            "{name}.{field}"
        );
        // The same field on another tool, or another field, keeps ordinary bounds.
        assert!(JsonValue::try_from_source_tool_arguments(&declared("exec"), &input).is_err());
        let other = serde_json::json!({field: "ok", "path": long});
        assert!(JsonValue::try_from_source_tool_arguments(&declared(name), &other).is_err());
    }
    // A non-string field keeps ordinary conversion instead of failing the call.
    let array = serde_json::json!({"command": ["sh", "-c", "true"]});
    let arguments = JsonValue::try_from_source_tool_arguments(&declared("shell"), &array).unwrap();
    assert!(build(tool_body("shell", arguments), None).is_ok());

    // Command text keeps the direct-text budget only for an authored command.
    let shell = JsonValue::try_from_source_tool_arguments(
        &declared("shell"),
        &serde_json::json!({"command": long}),
    )
    .unwrap();
    assert!(build(tool_body("shell", shell), Some(&long)).is_ok());

    // A command near the direct-text budget fits once: the command facet that
    // repeats it adds nothing to the observation aggregate, whether the
    // arguments hold it as `command` or are the command string itself (a
    // user `!` command). A facet that differs from the argument still counts.
    let near = "y".repeat(60_000);
    for input in [
        serde_json::json!({"command": near}),
        serde_json::json!(near),
    ] {
        let arguments =
            JsonValue::try_from_source_tool_arguments(&declared("shell"), &input).unwrap();
        let observation = build(tool_body("shell", arguments.clone()), Some(&near)).unwrap();
        // Retained bytes still count both copies.
        assert!(
            observation.retained_byte_len() > 2 * near.len(),
            "{input:.20}"
        );
        let other = format!("{near}!");
        let error = build(tool_body("shell", arguments), Some(&other)).unwrap_err();
        assert_eq!(error.bound_dimension(), Some(BoundDimension::EncodedBytes));
    }
    // A bare command string keeps the direct-text maximum, and only as the
    // v2 `shell` tool's arguments.
    let over = serde_json::json!("z".repeat(MESSAGE_MAX_TEXT_BYTES + 1));
    assert!(JsonValue::try_from_source_tool_arguments(&declared("shell"), &over).is_err());
    let bare = serde_json::json!(long);
    for name in ["read", "bash"] {
        assert!(JsonValue::try_from_source_tool_arguments(&declared(name), &bare).is_err());
    }
    // Codex freeform custom tools take one authored string: an `exec` script
    // or an `apply_patch` patch. It gets the text budget but is not a command.
    for name in ["exec", "apply_patch"] {
        let arguments = JsonValue::try_from_source_tool_arguments(&declared(name), &bare).unwrap();
        assert!(build(tool_body(name, arguments.clone()), None).is_ok());
        assert!(build(tool_body(name, arguments), Some(&long)).is_err());
        assert!(JsonValue::try_from_source_tool_arguments(&declared(name), &over).is_err());
        let direct = JsonValue::String("S".repeat(LOCAL_MAX_STRING_BYTES + 1));
        assert!(build(tool_body("read", direct), None).is_err());
    }

    let error = build(
        tool_body("exec", JsonValue::object([]).unwrap()),
        Some(&long),
    )
    .unwrap_err();
    assert_eq!(
        error.bound_context(),
        Some(CanonicalBoundContext {
            category: CanonicalFieldCategory::CommandText,
            dimension: BoundDimension::StringBytes,
        })
    );
}

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

fn message_text_builder(message: MessageObservation) -> ObservationBuilder {
    let has_content = message.content().is_some();
    let has_parts = !message.content_parts().is_empty();
    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Message(message),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("message.role", FactMetadata::reported().unwrap());
    if has_content {
        builder = builder.fact_metadata("message.content", FactMetadata::reported().unwrap());
    }
    if has_parts {
        builder = builder.fact_metadata("message.content_parts", FactMetadata::reported().unwrap());
    }
    builder
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

fn source() -> SourceProvenance {
    SourceProvenance::new(
        IngestionMode::Harness,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id("native-record-1")
    .unwrap()
}

fn scoped_source(namespace: &str) -> SourceProvenance {
    SourceProvenance::new(
        IngestionMode::SessionStore,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_identity_source_sequence(namespace, 0)
    .unwrap()
}

fn scoped_message(
    source: SourceProvenance,
    content: &str,
) -> Result<CanonicalObservationV2, ObservationError> {
    CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string(content)),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source,
    )
    .fact_metadata("message.role", FactMetadata::reported().unwrap())
    .fact_metadata("message.content", FactMetadata::reported().unwrap())
    .build()
}

fn metadata(provenance: FactProvenance) -> FactMetadata {
    FactMetadata::new(provenance, Sensitivity::Normal).unwrap()
}

fn build(body: ObservationBody, stage: ObservationStage, paths: &[&str]) -> CanonicalObservationV2 {
    let mut builder = CanonicalObservationV2::builder(
        body,
        stage,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    );
    for path in paths {
        builder = builder.fact_metadata(*path, metadata(FactProvenance::Reported));
    }
    builder.build().unwrap()
}

fn build_with_provenance(
    body: ObservationBody,
    stage: ObservationStage,
    paths: &[(&str, FactProvenance)],
) -> Result<CanonicalObservationV2, ObservationError> {
    let mut builder = CanonicalObservationV2::builder(
        body,
        stage,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    );
    for (path, provenance) in paths {
        builder = builder.fact_metadata(*path, metadata(*provenance));
    }
    builder.build()
}

#[test]
fn every_family_has_a_valid_constructed_observation() {
    assert_eq!(ObservationFamily::ALL.len(), 12);
    let cases = [
        (
            ObservationBody::Message(MessageObservation::new(MessageRole::User)),
            ObservationStage::MessageObserved,
            vec!["message.role"],
        ),
        (
            ObservationBody::Inference(
                InferenceObservation::new()
                    .with_provider("synthetic")
                    .unwrap(),
            ),
            ObservationStage::InferenceRequested,
            vec!["inference.provider"],
        ),
        (
            ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
            ObservationStage::ToolProposed,
            vec!["tool.name"],
        ),
        (
            ObservationBody::ToolDefinition(
                ToolDefinitionObservation::new("added")
                    .unwrap()
                    .with_name("shell")
                    .unwrap(),
            ),
            ObservationStage::DefinitionChanged,
            vec!["tool_definition.name", "tool_definition.change"],
        ),
        (
            ObservationBody::Mcp(McpObservation::new("added").unwrap()),
            ObservationStage::McpInventoryChanged,
            vec!["mcp.change"],
        ),
        (
            ObservationBody::Process(ProcessObservation::new().with_operation("exec").unwrap()),
            ObservationStage::ProcessObserved,
            vec!["process.operation"],
        ),
        (
            ObservationBody::File(FileObservation::new().with_operation("read").unwrap()),
            ObservationStage::FileObserved,
            vec!["file.operation"],
        ),
        (
            ObservationBody::Network(NetworkObservation::new().with_state("connected").unwrap()),
            ObservationStage::NetworkObserved,
            vec!["network.state"],
        ),
        (
            ObservationBody::Browser(
                BrowserObservation::new()
                    .with_state_marker("visible")
                    .unwrap(),
            ),
            ObservationStage::BrowserObserved,
            vec!["browser.state_marker"],
        ),
        (
            ObservationBody::Runtime(
                RuntimeObservation::new()
                    .with_state_marker("isolated")
                    .unwrap(),
            ),
            ObservationStage::RuntimeObserved,
            vec!["runtime.state_marker"],
        ),
        (
            ObservationBody::Session(SessionObservation::new(SessionLifecycle::Opened)),
            ObservationStage::SessionOpened,
            vec!["session.lifecycle"],
        ),
        (
            ObservationBody::Other(
                OtherObservation::new("adapter_notice", "capability_gap")
                    .unwrap()
                    .with_summary("fixture")
                    .unwrap(),
            ),
            ObservationStage::OtherObserved,
            vec![
                "other.registered_kind",
                "other.registry_version",
                "other.classification",
                "other.summary",
            ],
        ),
    ];

    for (body, stage, paths) in cases {
        let observation = if matches!(&body, ObservationBody::Session(_)) {
            let session_id =
                CorrelationId::new("session-fixture", CorrelationOrigin::SourceReported).unwrap();
            let mut builder = CanonicalObservationV2::builder(
                body,
                stage,
                ObservedAt::new(OBSERVED_AT).unwrap(),
                source(),
            )
            .session_id(session_id);
            for path in paths {
                builder = builder.fact_metadata(path, metadata(FactProvenance::Reported));
            }
            builder.build().unwrap()
        } else if matches!(
            &body,
            ObservationBody::Process(_) | ObservationBody::File(_) | ObservationBody::Network(_)
        ) {
            let mut builder = CanonicalObservationV2::builder(
                body,
                stage,
                ObservedAt::new(OBSERVED_AT).unwrap(),
                source(),
            );
            for path in paths {
                builder = builder.fact_metadata(path, metadata(FactProvenance::Observed));
            }
            builder.build().unwrap()
        } else {
            build(body, stage, &paths)
        };
        assert_eq!(
            observation.kind().as_str(),
            observation.body().kind().as_str()
        );
    }
}

#[test]
fn tool_lifecycle_stages_are_distinct_and_do_not_infer_failure() {
    let stages = [
        ObservationStage::ToolProposed,
        ObservationStage::ToolRequested,
        ObservationStage::ToolExecutionStarted,
        ObservationStage::ToolExecutionCompleted,
        ObservationStage::ToolResultReturned,
    ];
    let observations = stages.map(|stage| {
        let body = match stage {
            ObservationStage::ToolExecutionCompleted => {
                ToolObservation::new().with_result(JsonValue::string("done"))
            }
            ObservationStage::ToolResultReturned => ToolObservation::new()
                .with_name("shell")
                .unwrap()
                .with_is_error(true),
            _ => ToolObservation::new().with_name("shell").unwrap(),
        };
        build(
            ObservationBody::Tool(body),
            stage,
            if matches!(stage, ObservationStage::ToolExecutionCompleted) {
                &["tool.result"]
            } else if matches!(stage, ObservationStage::ToolResultReturned) {
                &["tool.name", "tool.is_error"]
            } else {
                &["tool.name"]
            },
        )
    });
    assert_eq!(observations.map(|item| item.stage()), stages);
    assert!(
        build(
            ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
            ObservationStage::ToolRequested,
            &["tool.name"]
        )
        .body()
        .kind()
            == ObservationFamily::Tool
    );
}

#[test]
fn invalid_stage_and_other_registry_are_rejected() {
    let error = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .build()
    .unwrap_err();
    assert_eq!(error.code(), "invalid_stage");
    assert!(OtherObservation::new("unknown", "anything").is_err());
    assert!(OtherObservation::new("adapter_notice", "redaction").is_err());
    assert_eq!(OTHER_REGISTRY_VERSION, "other-v1");

    let session = SessionObservation::new(SessionLifecycle::Opened);
    let mismatch = CanonicalObservationV2::builder(
        ObservationBody::Session(session),
        ObservationStage::SessionClosed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .session_id(CorrelationId::new("session-fixture", CorrelationOrigin::SourceReported).unwrap())
    .fact_metadata("session.lifecycle", metadata(FactProvenance::Reported))
    .build();
    assert_eq!(mismatch.unwrap_err().code(), "family_minimum");
}

#[test]
fn observation_id_shape_is_the_lowercase_prefixed_sha256_digest() {
    assert!(ObservationId::new(format!("obs:v2:sha256:{}", "0a".repeat(32))).is_ok());
    for value in [
        "0a".repeat(32),
        format!("obs:v1:sha256:{}", "0a".repeat(32)),
        format!("obs:v2:sha256:{}", "0A".repeat(32)),
        format!("obs:v2:sha256:{}", "0g".repeat(32)),
        format!("obs:v2:sha256:{}", "a".repeat(63)),
        format!("obs:v2:sha256:{}", "a".repeat(65)),
    ] {
        assert!(ObservationId::new(&value).is_err(), "{value}");
    }
}

#[test]
fn identity_is_deterministic_ordered_and_child_specific() {
    let first = build(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        &["message.role"],
    );
    let second = build(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        &["message.role"],
    );
    assert_eq!(first.observation_id(), second.observation_id());
    assert!(valid_observation_id(first.observation_id()));
    assert!(first.observation_id().chars().skip(13).all(
        |character| character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == ':'
    ));

    let changed = CanonicalObservationV2::builder(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source().with_native_id("native-record-2").unwrap(),
    )
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    assert_ne!(first.observation_id(), changed.observation_id());

    let child = CanonicalObservationV2::builder(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .child_ordinal(1)
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    assert_ne!(first.observation_id(), child.observation_id());
    assert_eq!(child.identity_basis().child_ordinal(), 1);

    let semantic_changed = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string("changed")),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .fact_metadata("message.content", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    assert_eq!(first.observation_id(), semantic_changed.observation_id());
    assert_eq!(
        first
            .semantic_comparison()
            .compare(semantic_changed.semantic_comparison()),
        SemanticReplayVerdict::Mutated
    );

    let ordered = SourceProvenance::new(
        IngestionMode::Harness,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_native_id("native-coordinate")
    .unwrap()
    .with_source_sequence(7);
    let ordered_again = ordered.clone().with_source_sequence(8);
    let one = CanonicalObservationV2::builder(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        ordered,
    )
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    let two = CanonicalObservationV2::builder(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        ordered_again,
    )
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    assert_eq!(one.observation_id(), two.observation_id());
}

#[test]
fn stable_identity_is_coordinate_only_and_comparison_detects_mutation() {
    let first = scoped_message(scoped_source("session-a"), "synthetic-first").unwrap();
    let changed = scoped_message(scoped_source("session-a"), "synthetic-second").unwrap();
    assert_eq!(
        first
            .semantic_comparison()
            .compare(first.semantic_comparison()),
        SemanticReplayVerdict::Equivalent
    );
    assert_eq!(first.observation_id(), changed.observation_id());
    assert_eq!(
        first
            .semantic_comparison()
            .compare(changed.semantic_comparison()),
        SemanticReplayVerdict::Mutated
    );

    let versioned_source = scoped_source("session-a")
        .with_adapter_version("fixture-v2")
        .unwrap();
    let versioned = scoped_message(versioned_source, "synthetic-first").unwrap();
    assert_eq!(first.observation_id(), versioned.observation_id());
}

#[test]
fn fingerprint_epoch_changes_are_incomparable_but_not_identity_changes() {
    let secret = JsonValue::string("synthetic-secret-marker");
    let source = scoped_source("session-a")
        .with_producer_identity_key_ref(
            LocalReference::new("producerkey:v2:synthetic-1", "identity_key").unwrap(),
        )
        .unwrap();
    let build_secret = |epoch: &str| {
        let fingerprint = KeyedFingerprint::compute(
            "tool.arguments",
            Sensitivity::Secret,
            &secret,
            epoch,
            PRODUCER_KEY,
        )
        .unwrap();
        CanonicalObservationV2::builder(
            ObservationBody::Tool(
                ToolObservation::new()
                    .with_name("shell")
                    .unwrap()
                    .with_arguments(secret.clone()),
            ),
            ObservationStage::ToolRequested,
            ObservedAt::new(OBSERVED_AT).unwrap(),
            source.clone(),
        )
        .fact_metadata("tool.name", FactMetadata::reported().unwrap())
        .fact_metadata(
            "tool.arguments",
            FactMetadata::new(FactProvenance::Reported, Sensitivity::Secret)
                .unwrap()
                .with_keyed_fingerprint(fingerprint)
                .unwrap(),
        )
        .build()
        .unwrap()
    };
    let first = build_secret("keyepoch:v2:synthetic-1");
    let rotated = build_secret("keyepoch:v2:synthetic-2");
    assert_eq!(first.observation_id(), rotated.observation_id());
    assert_eq!(
        first
            .semantic_comparison()
            .compare(rotated.semantic_comparison()),
        SemanticReplayVerdict::Incomparable
    );
}

#[test]
fn scoped_coordinates_are_required_and_namespaced() {
    let first = scoped_message(scoped_source("session-a"), "synthetic").unwrap();
    let second = scoped_message(scoped_source("session-b"), "synthetic").unwrap();
    assert_ne!(first.observation_id(), second.observation_id());
    let coordinate = first.identity_basis().coordinate().unwrap().1;
    assert!(matches!(
        coordinate,
        IdentityCoordinateValue::SourceSequence {
            namespace,
            ordinal: 0
        } if namespace == "session-a"
    ));
    assert_eq!(
        canonical_identity_json(
            &IdentityCoordinateValue::SourceSequence {
                namespace: "session-a".to_owned(),
                ordinal: 0,
            }
            .as_json()
        )
        .unwrap(),
        br#"["session","session-a",0]"#
    );

    let bare_source = SourceProvenance::new(
        IngestionMode::SessionStore,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_source_sequence(0);
    assert_eq!(
        scoped_message(bare_source, "synthetic").unwrap_err().code(),
        "replay_unverifiable"
    );
    assert_eq!(
        SourceProvenance::new(
            IngestionMode::SessionStore,
            "synthetic",
            "fixture",
            Fidelity::FullNative,
        )
        .unwrap()
        .with_identity_source_sequence("../session", 0)
        .unwrap_err()
        .code(),
        "path_derived_id"
    );
    let bare_offset = SourceProvenance::new(
        IngestionMode::SessionStore,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_offset("row:0")
    .unwrap();
    assert_eq!(
        scoped_message(bare_offset, "synthetic").unwrap_err().code(),
        "replay_unverifiable"
    );
    let scoped_offset = SourceProvenance::new(
        IngestionMode::SessionStore,
        "synthetic",
        "fixture",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_identity_offset("artifact", "row:0")
    .unwrap();
    assert_eq!(
        scoped_message(scoped_offset, "synthetic")
            .unwrap()
            .identity_basis()
            .coordinate()
            .unwrap()
            .0,
        IdentityCoordinateKind::Offset
    );
}

#[test]
fn stable_sensitive_identity_can_be_unavailable_without_a_key() {
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .unwrap()
                .with_arguments(JsonValue::string("synthetic-secret-marker")),
        ),
        ObservationStage::ToolRequested,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        scoped_source("session-a"),
    )
    .fact_metadata("tool.name", FactMetadata::reported().unwrap())
    .fact_metadata(
        "tool.arguments",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Secret).unwrap(),
    )
    .build()
    .unwrap();
    assert!(matches!(
        observation.semantic_comparison(),
        SemanticComparison::Unavailable
    ));
    assert!(
        !observation
            .observation_id()
            .contains("synthetic-secret-marker")
    );
    assert_eq!(
        observation
            .semantic_comparison()
            .compare(observation.semantic_comparison()),
        SemanticReplayVerdict::Incomparable
    );
}

#[test]
fn comparison_debug_is_redacted() {
    let observation =
        scoped_message(scoped_source("session-a"), "synthetic-secret-marker").unwrap();
    let debug = format!("{:?}", observation.semantic_comparison());
    let display = observation.semantic_comparison().to_string();
    assert!(!debug.contains("sha256:"));
    assert!(!debug.contains("synthetic-secret-marker"));
    assert!(!display.contains("sha256:"));
    assert!(!display.contains("synthetic-secret-marker"));
    assert!(!format!("{observation:?}").contains("synthetic-secret-marker"));
}

#[test]
fn canonical_identity_encoding_normalizes_unicode_and_sorts_objects() {
    let first = JsonValue::object([
        ("z".to_owned(), JsonValue::string("é")),
        ("a".to_owned(), JsonValue::Integer(1)),
    ])
    .unwrap();
    let second = JsonValue::object([
        ("a".to_owned(), JsonValue::Integer(1)),
        ("z".to_owned(), JsonValue::string("e\u{301}")),
    ])
    .unwrap();
    assert_eq!(
        canonical_identity_json(&first).unwrap(),
        canonical_identity_json(&second).unwrap()
    );
    assert_eq!(
        canonical_identity_json(&first).unwrap(),
        "{\"a\":1,\"z\":\"é\"}".as_bytes()
    );
    assert!(canonical_identity_json(&JsonValue::Number(f64::NAN)).is_err());

    let fixture_source = SourceProvenance::new(
        IngestionMode::Harness,
        "fixture.adapter",
        "fixture.harness",
        Fidelity::FullNative,
    )
    .unwrap()
    .with_adapter_version("fixture-1")
    .unwrap()
    .with_native_id("native-basic")
    .unwrap()
    .with_source_sequence(4)
    .with_offset("row:4")
    .unwrap();
    let fixture = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("read")
                .unwrap()
                .with_arguments(
                    JsonValue::object([(
                        "path".to_owned(),
                        JsonValue::string("workspace/SYNTHETIC.txt"),
                    )])
                    .unwrap(),
                ),
        ),
        ObservationStage::ToolRequested,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        fixture_source,
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("tool.arguments", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    assert_eq!(
        fixture.observation_id(),
        "obs:v2:sha256:81ad3e8e171654579fde3de76a7a9f56bddefa04322928035445932410c4a21c"
    );
}

#[test]
fn source_value_and_provenance_helpers_preserve_schema_ownership() {
    let value = JsonValue::try_from_source_value(&serde_json::json!({
        "number": 7,
        "nested": [true, null, "é"],
    }))
    .unwrap();
    assert_eq!(
        value,
        JsonValue::object([
            ("number".to_owned(), JsonValue::Integer(7)),
            (
                "nested".to_owned(),
                JsonValue::array(vec![
                    JsonValue::Bool(true),
                    JsonValue::Null,
                    JsonValue::string("é"),
                ]),
            ),
        ])
        .unwrap()
    );
    assert_eq!(
        FactMetadata::reported().unwrap().provenance(),
        FactProvenance::Reported
    );
    assert_eq!(
        FactMetadata::parsed().unwrap().provenance(),
        FactProvenance::Parsed
    );
    assert_eq!(
        CorrelationId::source_reported("synthetic-session")
            .unwrap()
            .origin(),
        CorrelationOrigin::SourceReported
    );
}

#[test]
fn sensitive_semantics_use_keyed_digest_not_raw_value() {
    let secret = JsonValue::string("synthetic-secret-marker");
    let key_ref = LocalReference::new("producerkey:v2:synthetic-1", "identity_key").unwrap();
    let source = source().with_producer_identity_key_ref(key_ref).unwrap();
    let fingerprint = KeyedFingerprint::compute(
        "tool.arguments",
        Sensitivity::Secret,
        &secret,
        "keyepoch:v2:synthetic-1",
        PRODUCER_KEY,
    )
    .unwrap();
    // Independently calculated HMAC-SHA256 over the canonical JSON tuple.
    assert_eq!(
        fingerprint.digest(),
        "hmac-sha256:v1:aa046bae2d93160005553c2dcbc5e5307169b61df38fae2db735709f4a0cc285"
    );
    let facts = FactMetadata::new(FactProvenance::Reported, Sensitivity::Secret)
        .unwrap()
        .with_keyed_fingerprint(fingerprint)
        .unwrap();
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_arguments(secret)
                .with_name("shell")
                .unwrap(),
        ),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source,
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("tool.arguments", facts)
    .build()
    .unwrap();
    assert!(
        !observation
            .observation_id()
            .contains("synthetic-secret-marker")
    );
    assert!(matches!(
        observation.semantic_comparison(),
        SemanticComparison::Comparable { .. }
    ));
}

#[test]
fn empty_hmac_keys_fail_closed_without_disclosing_payloads() {
    let error = KeyedFingerprint::compute(
        "tool.arguments",
        Sensitivity::Secret,
        &JsonValue::string("synthetic-secret-marker"),
        "keyepoch:v2:synthetic-1",
        &[],
    )
    .unwrap_err();
    assert_eq!(error.code(), "invalid_fingerprint");
    assert!(!error.to_string().contains("synthetic-secret-marker"));

    let builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    let error = builder.assignment_commitment(&[]).unwrap_err();
    assert_eq!(error.code(), "replay_unverifiable");

    let mut store = InMemoryAssignmentStore::new();
    let error = store
        .insert_key("assignmentkey:v2:synthetic-empty", &[])
        .unwrap_err();
    assert_eq!(error.code(), "replay_unverifiable");
}

#[test]
fn local_values_store_canonical_unicode() {
    let value = LocalValue::new(
        JsonValue::String("e\u{301}".into()),
        None::<&str>,
        FactProvenance::Reported,
        Sensitivity::Normal,
    )
    .unwrap();
    assert_eq!(value.value(), &JsonValue::string("é"));
}

#[test]
fn semantic_body_and_facet_values_are_bounded_without_payload_errors() {
    let body_error = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("read")
                .unwrap()
                .with_arguments(JsonValue::String("S".repeat(LOCAL_MAX_STRING_BYTES + 1))),
        ),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("tool.arguments", metadata(FactProvenance::Reported))
    .build()
    .unwrap_err();
    assert_eq!(body_error.code(), "unbounded_value");
    assert!(!body_error.to_string().contains('S'));

    let facet_error = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .facet(
        "tool.payload",
        SemanticFacet::new(JsonValue::String("S".repeat(LOCAL_MAX_STRING_BYTES + 1))),
    )
    .unwrap()
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("tool.payload", metadata(FactProvenance::Reported))
    .build()
    .unwrap_err();
    assert_eq!(facet_error.code(), "unbounded_value");
    assert!(!facet_error.to_string().contains('S'));
}

#[test]
fn observation_debug_redacts_body_values() {
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .unwrap()
                .with_arguments(JsonValue::string("synthetic-secret-marker")),
        ),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("tool.arguments", metadata(FactProvenance::Reported))
    .build()
    .unwrap();
    assert!(!format!("{observation:?}").contains("synthetic-secret-marker"));
}

#[test]
fn no_coordinate_has_no_random_fallback_and_assignment_replay_is_protected() {
    let coordinate_less_source = SourceProvenance::new(
        IngestionMode::Import,
        "synthetic",
        "assignment",
        Fidelity::FullNative,
    )
    .unwrap();
    let assignment = LocalReference::new("assignment-ref-1", "assignment").unwrap();
    let basis = IdentityBasis::persisted(
        "synthetic:assignment",
        "replay-key-1",
        assignment.clone(),
        0,
        "none",
    )
    .unwrap();
    let builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        coordinate_less_source.clone(),
    )
    .identity_basis(basis.clone())
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    let error = builder.build().unwrap_err();
    assert_eq!(error.code(), "replay_unverifiable");

    let builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        coordinate_less_source.clone(),
    )
    .identity_basis(basis.clone())
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    let commitment = builder.assignment_commitment(ASSIGNMENT_KEY).unwrap();
    let mut store = InMemoryAssignmentStore::new();
    store
        .insert_key("assignmentkey:v2:synthetic-1", ASSIGNMENT_KEY)
        .unwrap();
    store
        .insert_assignment(
            assignment.handle(),
            AssignmentRecord::new(
                "synthetic:assignment",
                "replay-key-1",
                0,
                "obs:v2:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "assignmentkey:v2:synthetic-1",
                commitment,
            )
            .unwrap(),
        )
        .unwrap();
    let observation = builder.build_with_assignments(&store).unwrap();
    assert_eq!(
        observation.observation_id(),
        "obs:v2:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    let changed = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("different").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        coordinate_less_source,
    )
    .identity_basis(basis)
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    assert_eq!(
        changed.build_with_assignments(&store).unwrap_err().code(),
        "replay_collision"
    );

    let missing_key_builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        SourceProvenance::new(
            IngestionMode::Import,
            "synthetic",
            "assignment",
            Fidelity::FullNative,
        )
        .unwrap(),
    )
    .identity_basis(
        IdentityBasis::persisted(
            "synthetic:assignment",
            "replay-key-1",
            LocalReference::new("assignment-ref-1", "assignment").unwrap(),
            0,
            "none",
        )
        .unwrap(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    let commitment = missing_key_builder
        .assignment_commitment(ASSIGNMENT_KEY)
        .unwrap();
    let mut missing_key_store = InMemoryAssignmentStore::new();
    missing_key_store
        .insert_assignment(
            "assignment-ref-1",
            AssignmentRecord::new(
                "synthetic:assignment",
                "replay-key-1",
                0,
                "obs:v2:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "missing-key",
                commitment,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        missing_key_builder
            .build_with_assignments(&missing_key_store)
            .unwrap_err()
            .code(),
        "replay_unverifiable"
    );
}

#[test]
fn assignment_record_is_bound_to_domain_replay_key_and_child_ordinal() {
    let source = SourceProvenance::new(
        IngestionMode::Import,
        "synthetic",
        "assignment",
        Fidelity::FullNative,
    )
    .unwrap();
    let assignment = LocalReference::new("assignment-ref-bound", "assignment").unwrap();
    let builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source,
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    let commitment = builder.assignment_commitment(ASSIGNMENT_KEY).unwrap();

    for (record_domain, record_replay_key, record_child_ordinal) in [
        ("other:assignment", "replay-key-bound", 0),
        ("synthetic:assignment", "replay-key-other", 0),
        ("synthetic:assignment", "replay-key-bound", 1),
    ] {
        let mut store = InMemoryAssignmentStore::new();
        store
            .insert_key("assignmentkey:v2:synthetic-bound", ASSIGNMENT_KEY)
            .unwrap();
        store
            .insert_assignment(
                assignment.handle(),
                AssignmentRecord::new(
                    record_domain,
                    record_replay_key,
                    record_child_ordinal,
                    "obs:v2:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "assignmentkey:v2:synthetic-bound",
                    &commitment,
                )
                .unwrap(),
            )
            .unwrap();
        let basis = IdentityBasis::persisted(
            "synthetic:assignment",
            "replay-key-bound",
            assignment.clone(),
            0,
            "none",
        )
        .unwrap();
        assert_eq!(
            builder
                .clone()
                .identity_basis(basis)
                .build_with_assignments(&store)
                .unwrap_err()
                .code(),
            "replay_unverifiable"
        );
    }

    let mut store = InMemoryAssignmentStore::new();
    store
        .insert_key("assignmentkey:v2:synthetic-bound", ASSIGNMENT_KEY)
        .unwrap();
    store
        .insert_assignment(
            assignment.handle(),
            AssignmentRecord::new(
                "synthetic:assignment",
                "replay-key-bound",
                0,
                "obs:v2:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "assignmentkey:v2:synthetic-bound",
                commitment,
            )
            .unwrap(),
        )
        .unwrap();
    let wrong_child_basis = IdentityBasis::persisted(
        "synthetic:assignment",
        "replay-key-bound",
        assignment,
        0,
        "none",
    )
    .unwrap();
    assert_eq!(
        builder
            .child_ordinal(1)
            .identity_basis(wrong_child_basis)
            .build_with_assignments(&store)
            .unwrap_err()
            .code(),
        "invalid_identity_basis"
    );
}

#[test]
fn assignment_claim_material_is_io_free_bounded_and_coordinate_less() {
    let coordinate_less_source = SourceProvenance::new(
        IngestionMode::Import,
        "synthetic",
        "assignment",
        Fidelity::FullNative,
    )
    .unwrap();
    let builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        coordinate_less_source,
    )
    .child_ordinal(7)
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));

    let material = builder.prepare_assignment_claim(ASSIGNMENT_KEY).unwrap();
    assert_eq!(material.adapter_type(), "synthetic");
    assert_eq!(material.adapter_id(), "assignment");
    assert_eq!(material.domain(), "synthetic:assignment");
    assert_eq!(material.child_ordinal(), 7);
    assert_eq!(material.fingerprint_key_epoch_ref(), "none");
    assert!(
        material
            .commitment()
            .starts_with(ASSIGNMENT_COMMITMENT_PREFIX)
    );
    let debug = format!("{material:?}");
    assert!(!debug.contains(material.commitment()));
    assert!(!debug.contains("synthetic:assignment"));

    let stable = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported));
    assert_eq!(
        stable
            .prepare_assignment_claim(ASSIGNMENT_KEY)
            .unwrap_err()
            .code(),
        "invalid_identity_basis"
    );
    assert_eq!(
        builder
            .clone()
            .identity_basis(
                IdentityBasis::persisted(
                    "synthetic:assignment",
                    "replay-key-bound",
                    LocalReference::new("assignment-ref-bound", "assignment").unwrap(),
                    7,
                    "none",
                )
                .unwrap(),
            )
            .prepare_assignment_claim(ASSIGNMENT_KEY)
            .unwrap_err()
            .code(),
        "invalid_identity_basis"
    );
}

#[test]
fn persisted_identity_debug_redacts_protected_local_material() {
    let secret = "synthetic-protected-replay-secret";
    let basis = IdentityBasis::persisted(
        "synthetic:assignment",
        secret,
        LocalReference::new("synthetic-assignment-secret", "assignment").unwrap(),
        0,
        "synthetic-key-secret",
    )
    .unwrap();
    let debug = format!("{basis:?}");
    assert!(!debug.contains(secret));
    assert!(!debug.contains("synthetic-assignment-secret"));
    assert!(!debug.contains("synthetic-key-secret"));

    let record = AssignmentRecord::new(
        "synthetic:assignment",
        secret,
        0,
        "obs:v2:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "synthetic-key-secret",
        format!("{ASSIGNMENT_COMMITMENT_PREFIX}{}", "e".repeat(64)),
    )
    .unwrap();
    let debug = format!("{record:?}");
    assert!(!debug.contains(secret));
    assert!(!debug.contains("synthetic-key-secret"));
    assert!(!debug.contains(&"e".repeat(64)));

    let mut store = InMemoryAssignmentStore::new();
    store
        .insert_key("synthetic-comparison-key", b"synthetic-key-marker")
        .unwrap();
    let debug = format!("{store:?}");
    assert!(!debug.contains("synthetic-comparison-key"));
    assert!(!debug.contains("synthetic-key-marker"));
}

#[test]
fn time_correlation_capability_and_provenance_boundaries_are_explicit() {
    assert!(ObservedAt::new("").is_err());
    assert!(ObservedAt::new("2026-09-02T12:00:00").is_err());
    assert!(CorrelationId::new("../session", CorrelationOrigin::SourceReported).is_err());
    assert!(CorrelationId::new("session", CorrelationOrigin::SourceReported).is_ok());

    let context = CapabilityContext::new()
        .with_override(CapabilityId::ToolCall, CapabilityAvailability::Unsupported)
        .with_override(CapabilityId::ToolExecution, CapabilityAvailability::Unknown);
    assert_eq!(
        context.resolve(CapabilityId::ToolCall),
        CapabilityAvailability::Unsupported
    );
    assert_eq!(
        context.resolve(CapabilityId::ToolExecution),
        CapabilityAvailability::Unknown
    );
    assert_eq!(
        context.resolve(CapabilityId::UserContext),
        CapabilityAvailability::Unknown
    );
    assert_eq!(Fidelity::DerivedOnly.as_str(), "derived_only");
    assert_eq!(FactProvenance::Observed.as_str(), "observed");
    assert_eq!(IngestionMode::Gateway.as_str(), "gateway");

    let parsed_tool = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .facet(
        "network.domain",
        SemanticFacet::new(JsonValue::string("example.invalid")),
    )
    .unwrap()
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("network.domain", metadata(FactProvenance::Parsed))
    .build()
    .unwrap();
    assert_eq!(parsed_tool.kind(), ObservationFamily::Tool);
    let direct_network = CanonicalObservationV2::builder(
        ObservationBody::Network(
            NetworkObservation::new()
                .with_operation("connect")
                .unwrap()
                .with_destination_class("public")
                .unwrap()
                .with_domain("example.invalid")
                .unwrap(),
        ),
        ObservationStage::NetworkObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("network.operation", metadata(FactProvenance::Observed))
    .fact_metadata(
        "network.destination_class",
        metadata(FactProvenance::Observed),
    )
    .fact_metadata("network.domain", metadata(FactProvenance::Observed))
    .build()
    .unwrap();
    assert_eq!(direct_network.kind(), ObservationFamily::Network);

    let no_occurrence = build(
        ObservationBody::Message(MessageObservation::new(MessageRole::Assistant)),
        ObservationStage::MessageObserved,
        &["message.role"],
    );
    assert!(no_occurrence.occurred_at().is_none());
    assert_eq!(no_occurrence.observed_at().as_str(), OBSERVED_AT);
}

#[test]
fn local_values_are_structured_bounded_and_not_export_references() {
    let arguments = LocalValue::new(
        JsonValue::object([("command".to_owned(), JsonValue::string("echo synthetic"))]).unwrap(),
        Some("echo synthetic"),
        FactProvenance::Reported,
        Sensitivity::Normal,
    )
    .unwrap();
    let local = LocalEvidence::new()
        .insert("tool.arguments", arguments)
        .unwrap();
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .local(local)
    .build()
    .unwrap();
    assert_eq!(observation.local().unwrap().structured_values().len(), 1);
    assert!(
        LocalEvidence::new()
            .insert(
                "other.payload",
                LocalValue::new(
                    JsonValue::Null,
                    None::<&str>,
                    FactProvenance::Reported,
                    Sensitivity::Normal
                )
                .unwrap()
            )
            .is_err()
    );
    assert!(LocalReference::new("raw-handle", "exportable").is_err());
    let raw_local =
        LocalEvidence::new().with_raw_ref(LocalReference::new("raw-handle", "local_only").unwrap());
    let raw_observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .local(raw_local)
    .build()
    .unwrap();
    assert!(raw_observation.local().unwrap().raw_ref().is_some());
    assert!(
        LocalValue::new(
            JsonValue::Number(f64::INFINITY),
            None::<&str>,
            FactProvenance::Reported,
            Sensitivity::Normal
        )
        .is_err()
    );
    let oversized = LocalValue::new(
        JsonValue::string("S".repeat(LOCAL_MAX_STRING_BYTES + 1)),
        None::<&str>,
        FactProvenance::Reported,
        Sensitivity::Normal,
    )
    .unwrap_err();
    assert!(!oversized.to_string().contains('S'));
    let prohibited = LocalValue::new(
        JsonValue::Null,
        None::<&str>,
        FactProvenance::Reported,
        Sensitivity::Prohibited,
    );
    assert!(prohibited.is_err());
}

#[test]
fn metadata_is_sole_facet_authority_and_observed_activity_is_required() {
    let missing = CanonicalObservationV2::builder(
        ObservationBody::Network(
            NetworkObservation::new()
                .with_destination_class("public")
                .unwrap()
                .with_domain("example.invalid")
                .unwrap(),
        ),
        ObservationStage::NetworkObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata(
        "network.destination_class",
        metadata(FactProvenance::Parsed),
    )
    .fact_metadata("network.domain", metadata(FactProvenance::Parsed))
    .build();
    assert_eq!(missing.unwrap_err().code(), "family_minimum");

    let destination_only = build_with_provenance(
        ObservationBody::Network(
            NetworkObservation::new()
                .with_destination_class("public")
                .unwrap()
                .with_domain("example.invalid")
                .unwrap(),
        ),
        ObservationStage::NetworkObserved,
        &[
            ("network.destination_class", FactProvenance::Observed),
            ("network.domain", FactProvenance::Observed),
        ],
    );
    assert_eq!(destination_only.unwrap_err().code(), "family_minimum");

    let extra = CanonicalObservationV2::builder(
        ObservationBody::Message(MessageObservation::new(MessageRole::User)),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .fact_metadata("message.role", metadata(FactProvenance::Reported))
    .fact_metadata("native.key", metadata(FactProvenance::Reported))
    .build();
    assert_eq!(extra.unwrap_err().code(), "metadata_coverage");
    let arbitrary = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .facet("native.command", SemanticFacet::new(JsonValue::string("x")));
    assert!(arbitrary.is_err());
}

#[test]
fn parsed_activity_cannot_construct_direct_process_file_or_network() {
    let parsed_process_name = build_with_provenance(
        ObservationBody::Process(ProcessObservation::new().with_name("shell").unwrap()),
        ObservationStage::ProcessObserved,
        &[("process.name", FactProvenance::Parsed)],
    );
    assert_eq!(parsed_process_name.unwrap_err().code(), "family_minimum");

    let parsed_process_activity = build_with_provenance(
        ObservationBody::Process(
            ProcessObservation::new()
                .with_operation("exec")
                .unwrap()
                .with_name("shell")
                .unwrap(),
        ),
        ObservationStage::ProcessObserved,
        &[
            ("process.operation", FactProvenance::Parsed),
            ("process.name", FactProvenance::Parsed),
        ],
    );
    assert_eq!(
        parsed_process_activity.unwrap_err().code(),
        "family_minimum"
    );

    let parsed_file_activity = build_with_provenance(
        ObservationBody::File(
            FileObservation::new()
                .with_operation("read")
                .unwrap()
                .with_path_class("workspace")
                .unwrap(),
        ),
        ObservationStage::FileObserved,
        &[
            ("file.operation", FactProvenance::Parsed),
            ("file.path_class", FactProvenance::Parsed),
        ],
    );
    assert_eq!(parsed_file_activity.unwrap_err().code(), "family_minimum");

    let parsed_network_activity = build_with_provenance(
        ObservationBody::Network(
            NetworkObservation::new()
                .with_operation("connect")
                .unwrap()
                .with_domain("example.invalid")
                .unwrap(),
        ),
        ObservationStage::NetworkObserved,
        &[
            ("network.operation", FactProvenance::Parsed),
            ("network.domain", FactProvenance::Observed),
        ],
    );
    assert_eq!(
        parsed_network_activity.unwrap_err().code(),
        "family_minimum"
    );

    let direct_process = build_with_provenance(
        ObservationBody::Process(ProcessObservation::new().with_state("running").unwrap()),
        ObservationStage::ProcessObserved,
        &[("process.state", FactProvenance::Observed)],
    )
    .unwrap();
    assert_eq!(direct_process.kind(), ObservationFamily::Process);

    let direct_file = build_with_provenance(
        ObservationBody::File(FileObservation::new().with_operation("read").unwrap()),
        ObservationStage::FileObserved,
        &[("file.operation", FactProvenance::Observed)],
    )
    .unwrap();
    assert_eq!(direct_file.kind(), ObservationFamily::File);

    let direct_network = build_with_provenance(
        ObservationBody::Network(NetworkObservation::new().with_state("connected").unwrap()),
        ObservationStage::NetworkObserved,
        &[("network.state", FactProvenance::Observed)],
    )
    .unwrap();
    assert_eq!(direct_network.kind(), ObservationFamily::Network);
}

#[test]
fn parsed_command_facets_remain_tool_observation_facets() {
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source(),
    )
    .facet(
        "process.name",
        SemanticFacet::new(JsonValue::string("shell")),
    )
    .unwrap()
    .facet(
        "network.domain",
        SemanticFacet::new(JsonValue::string("example.invalid")),
    )
    .unwrap()
    .facet(
        "resource.path",
        SemanticFacet::new(JsonValue::string("workspace/config")),
    )
    .unwrap()
    .fact_metadata("tool.name", metadata(FactProvenance::Reported))
    .fact_metadata("process.name", metadata(FactProvenance::Parsed))
    .fact_metadata("network.domain", metadata(FactProvenance::Parsed))
    .fact_metadata("resource.path", metadata(FactProvenance::Parsed))
    .build()
    .unwrap();

    assert_eq!(observation.kind(), ObservationFamily::Tool);
}

fn declared_tool(
    arguments: Option<serde_json::Value>,
    operation: Option<ToolOperation>,
) -> CanonicalObservationV2 {
    let mut tool = ToolObservation::new().with_name("write").unwrap();
    let mut paths = vec!["tool.name"];
    if let Some(arguments) = arguments {
        tool = tool.with_arguments(JsonValue::try_from_source_value(&arguments).unwrap());
        paths.push("tool.arguments");
    }
    if let Some(operation) = operation {
        tool = tool.with_operation(operation);
    }
    build(
        ObservationBody::Tool(tool),
        ObservationStage::ToolRequested,
        &paths,
    )
}

fn operation_of(observation: &CanonicalObservationV2) -> &ToolOperation {
    let ObservationBody::Tool(tool) = observation.body() else {
        panic!("a tool observation")
    };
    tool.operation().expect("declared")
}

#[test]
fn a_declared_operation_changes_neither_identity_nor_retained_bytes() {
    let arguments = serde_json::json!({"file_path": "/p/a", "content": "synthetic"});
    let bare = declared_tool(Some(arguments.clone()), None);
    let declared = declared_tool(
        Some(arguments),
        Some(ToolOperation::new(ToolKind::FileWrite).with_written_path("/p/a")),
    );
    assert_eq!(bare.observation_id(), declared.observation_id());
    assert_eq!(bare.retained_byte_len(), declared.retained_byte_len());
    assert_eq!(operation_of(&declared).written_paths(), ["/p/a"]);
}

#[test]
fn argument_roles_change_neither_identity_nor_retained_bytes() {
    let arguments = serde_json::json!({"path": "/p/a", "new_str": "synthetic", "old_str": "x"});
    let bare = declared_tool(Some(arguments.clone()), None);
    let declared = declared_tool(
        Some(arguments),
        Some(
            ToolOperation::new(ToolKind::FileWrite)
                .with_authored_key("new_str")
                .with_replaced_key("old_str")
                .with_authored_text(),
        ),
    );
    assert_eq!(bare.observation_id(), declared.observation_id());
    assert_eq!(bare.retained_byte_len(), declared.retained_byte_len());
    let operation = operation_of(&declared);
    assert_eq!(operation.authored_keys(), ["new_str"]);
    assert_eq!(operation.replaced_keys(), ["old_str"]);
    assert!(operation.authored_text() && operation.has_roles());
}

#[test]
fn operands_take_the_arguments_normal_form_and_never_exceed_them() {
    // An NFD path becomes the NFC path the arguments hold, and repeats merge.
    let nfd = "/p/e\u{301}";
    let nfc = "/p/\u{e9}";
    let declared = declared_tool(
        Some(serde_json::json!({"file_path": nfd})),
        Some(
            ToolOperation::new(ToolKind::FileWrite)
                .with_written_path(nfd)
                .with_written_path(nfc),
        ),
    );
    assert_eq!(operation_of(&declared).written_paths(), [nfc]);

    // Operands that would outweigh the arguments they were read from are
    // dropped; the kind stays.
    for (arguments, operand) in [
        (
            Some(serde_json::json!({"p": "a"})),
            "/a/path/much/longer/than/the/arguments",
        ),
        (None, "/p/a"),
    ] {
        let declared = declared_tool(
            arguments,
            Some(ToolOperation::new(ToolKind::FileWrite).with_written_path(operand)),
        );
        let operation = operation_of(&declared);
        assert_eq!(operation.kind(), ToolKind::FileWrite);
        assert!(operation.written_paths().is_empty());
    }
}

fn bounded(value: &serde_json::Value) -> (JsonValue, Vec<BoundedValue>) {
    JsonValue::try_from_source_value_bounded(BoundedTarget::Arguments, value).unwrap()
}

fn replacements(values: &[BoundedValue]) -> Vec<(&str, BoundDimension)> {
    values
        .iter()
        .map(|value| (value.pointer(), value.dimension()))
        .collect()
}

#[test]
fn bounded_conversion_replaces_only_the_value_over_each_bound() {
    use serde_json::{Value, json};
    let nested = |count| (0..count).fold(Value::Null, |value, _| json!([value]));
    let members = |count| {
        Value::Object(
            (0..count)
                .map(|index| (format!("k{index}"), json!(index)))
                .collect(),
        )
    };
    for (value, pointer, dimension) in [
        (
            json!({"a":"x".repeat(4097), "path":"/p"}),
            "/a",
            BoundDimension::StringBytes,
        ),
        (
            json!({"a":nested(5), "path":"/p"}),
            "/a/0/0/0/0",
            BoundDimension::Depth,
        ),
        (
            json!({"a":vec![json!(1); 65], "path":"/p"}),
            "/a",
            BoundDimension::ArrayItems,
        ),
        (
            json!({"a":members(33), "path":"/p"}),
            "/a",
            BoundDimension::ObjectMembers,
        ),
        (
            json!({"a":{"k".repeat(65):1, "b":2}, "path":"/p"}),
            "/a",
            BoundDimension::KeyBytes,
        ),
    ] {
        let strict = JsonValue::try_from_source_value(&value).unwrap_err();
        assert_eq!(strict.bound_dimension(), Some(dimension));
        let (converted, replaced) = bounded(&value);
        assert_eq!(replacements(&replaced), [(pointer, dimension)]);
        assert!(
            replaced
                .iter()
                .all(|entry| entry.target() == BoundedTarget::Arguments)
        );
        let JsonValue::Object(fields) = &converted else {
            panic!("arguments stay an object")
        };
        assert_eq!(fields["path"], JsonValue::string("/p"));
        super::value::validate_bounded_values(&replaced, Some(&converted), None, [false; 2])
            .unwrap();
    }
    // An over-long key drops only its member; its siblings stay.
    let (converted, _) = bounded(&json!({"a":{"k".repeat(65):1, "b":2}}));
    assert_eq!(
        converted,
        JsonValue::try_from_source_value(&json!({"a":{"b":2}})).unwrap()
    );
    // At each bound the value converts as strictly and records nothing.
    for value in [
        json!({"a":"x".repeat(4096)}),
        json!({"a":nested(4)}),
        json!({"a":vec![json!(1); 64]}),
        json!({"a":members(32)}),
        json!({"k".repeat(64):1}),
        json!(["\u{1}".repeat(2730)]),
    ] {
        let (converted, replaced) = bounded(&value);
        assert!(replaced.is_empty());
        assert_eq!(converted, JsonValue::try_from_source_value(&value).unwrap());
    }
}

#[test]
fn bounded_conversion_replaces_the_largest_members_until_the_value_fits() {
    use serde_json::json;
    let value = json!({"a":["\u{1}".repeat(2000)], "b":["\u{1}".repeat(1000)], "c":"/p"});
    assert_eq!(
        JsonValue::try_from_source_value(&value)
            .unwrap_err()
            .bound_dimension(),
        Some(BoundDimension::EncodedBytes)
    );
    let (converted, replaced) = bounded(&value);
    assert_eq!(
        replacements(&replaced),
        [("/a", BoundDimension::EncodedBytes)]
    );
    let JsonValue::Object(fields) = &converted else {
        panic!("arguments stay an object")
    };
    assert_eq!(fields["a"], JsonValue::Null);
    assert!(matches!(fields["b"], JsonValue::Array(_)));
    assert_eq!(fields["c"], JsonValue::string("/p"));

    // Declared text keeps its budget; when the texts together overflow the
    // aggregate, the largest goes whole and the rest stays whole.
    let declared = ArgumentText::new().with_key("old").with_key("new");
    let value = json!({"old":"x".repeat(40_000), "new":"y".repeat(30_000), "path":"/p"});
    let (converted, replaced) =
        JsonValue::try_from_source_tool_arguments_bounded(&declared, &value).unwrap();
    assert_eq!(
        replacements(&replaced),
        [("/old", BoundDimension::EncodedBytes)]
    );
    let JsonValue::Object(fields) = &converted else {
        panic!("arguments stay an object")
    };
    assert_eq!(fields["new"], JsonValue::string("y".repeat(30_000)));
    // Text over its own budget is replaced, never shortened.
    let value = json!({"old":"x".repeat(65_537), "path":"/p"});
    let (converted, replaced) =
        JsonValue::try_from_source_tool_arguments_bounded(&declared, &value).unwrap();
    assert_eq!(
        replacements(&replaced),
        [("/old", BoundDimension::StringBytes)]
    );
    assert_eq!(replaced[0].bytes(), 65_537);
    let JsonValue::Object(fields) = &converted else {
        panic!("arguments stay an object")
    };
    assert_eq!(fields["old"], JsonValue::Null);
    assert_eq!(fields["path"], JsonValue::string("/p"));
    // A direct result over the text budget is replaced whole.
    let (converted, replaced) =
        JsonValue::try_from_source_tool_result_bounded(&json!("x".repeat(65_537))).unwrap();
    assert_eq!(converted, JsonValue::Null);
    assert_eq!(replacements(&replaced), [("", BoundDimension::StringBytes)]);
    assert_eq!(replaced[0].target(), BoundedTarget::Result);
}

#[test]
fn bounded_conversion_over_the_entry_cap_replaces_the_whole_field() {
    use serde_json::{Value, json};
    let over = |count| {
        Value::Object(
            (0..count)
                .map(|index| (format!("k{index}"), json!("x".repeat(4097))))
                .collect(),
        )
    };
    let (converted, replaced) = bounded(&over(TOOL_MAX_BOUNDED_VALUES));
    assert_eq!(replaced.len(), TOOL_MAX_BOUNDED_VALUES);
    assert!(matches!(converted, JsonValue::Object(_)));
    let value = over(TOOL_MAX_BOUNDED_VALUES + 1);
    let (converted, replaced) = bounded(&value);
    assert_eq!(converted, JsonValue::Null);
    assert_eq!(replacements(&replaced), [("", BoundDimension::StringBytes)]);
    assert_eq!(
        replaced[0].bytes(),
        serde_json::to_string(&value).unwrap().len() as u64
    );
}

#[test]
fn bounded_values_are_a_side_list_source_data_cannot_forge() {
    use serde_json::json;
    let paths = [
        ("tool.name", FactProvenance::Reported),
        ("tool.arguments", FactProvenance::Reported),
    ];
    let tool = |arguments: JsonValue| {
        ToolObservation::new()
            .with_name("synthetic")
            .unwrap()
            .with_arguments(arguments)
    };
    // A model-supplied null, or an object shaped like an entry, is data.
    let forged = json!({"a":null, "tool.bounded_values":[{"target":"arguments","pointer":"/a","dimension":"string_bytes","bytes":9}]});
    let (arguments, replaced) = bounded(&forged);
    assert!(replaced.is_empty());
    let observation = build_with_provenance(
        ObservationBody::Tool(tool(arguments)),
        ObservationStage::ToolRequested,
        &paths,
    )
    .unwrap();
    assert!(
        !observation
            .fact_metadata()
            .contains_key("tool.bounded_values")
    );
    assert!(
        observation
            .body()
            .semantic_fields()
            .iter()
            .all(|(path, _)| path != "tool.bounded_values")
    );

    // A real replacement is emitted with fixed metadata.
    let (arguments, replaced) = bounded(&json!({"private_member":"x".repeat(4097), "path":"/p"}));
    let replaced_tool = tool(arguments).with_bounded_values(replaced.clone());
    assert!(replaced_tool.bounded_member(BoundedTarget::Arguments, "private_member"));
    assert!(!replaced_tool.bounded_member(BoundedTarget::Arguments, "path"));
    assert!(!replaced_tool.bounded_member(BoundedTarget::Result, "private_member"));
    let observation = build_with_provenance(
        ObservationBody::Tool(replaced_tool.clone()),
        ObservationStage::ToolRequested,
        &paths,
    )
    .unwrap();
    assert_eq!(
        observation.fact_metadata()["tool.bounded_values"].provenance(),
        FactProvenance::Derived
    );
    let field = observation
        .body()
        .semantic_fields()
        .into_iter()
        .find(|(path, _)| path == "tool.bounded_values")
        .unwrap()
        .1;
    assert_eq!(
        field,
        JsonValue::try_from_source_value(&json!([{"bytes":4097, "dimension":"string_bytes", "pointer":"/private_member", "target":"arguments"}])).unwrap()
    );
    // Source metadata for the list is refused.
    let error = build_with_provenance(
        ObservationBody::Tool(replaced_tool),
        ObservationStage::ToolRequested,
        &[
            paths[0],
            paths[1],
            ("tool.bounded_values", FactProvenance::Reported),
        ],
    )
    .unwrap_err();
    assert_eq!(error.code(), ValidationCode::InvalidMetadata.as_str());
    // An entry must name a replacement that is there.
    let moved = tool(JsonValue::try_from_source_value(&json!({"private_member":"short"})).unwrap())
        .with_bounded_values(replaced.clone());
    let error = build_with_provenance(
        ObservationBody::Tool(moved),
        ObservationStage::ToolRequested,
        &paths,
    )
    .unwrap_err();
    assert_eq!(error.code(), ValidationCode::InvalidBody.as_str());
    // Diagnostics carry neither the keys nor the replaced content.
    let debug = format!("{replaced:?}");
    assert!(
        !debug.contains("private") && !debug.contains("xxx"),
        "{debug}"
    );
}

fn entries(tool: &ToolObservation) -> Vec<(BoundedTarget, String, BoundDimension)> {
    tool.bounded_values()
        .iter()
        .map(|value| {
            (
                value.target(),
                value.pointer().to_owned(),
                value.dimension(),
            )
        })
        .collect()
}

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
        super::value::validate_bounded_values(values, Some(&arguments), None, searchable)
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

const TOOL_PATHS: [(&str, FactProvenance); 3] = [
    ("tool.name", FactProvenance::Reported),
    ("tool.arguments", FactProvenance::Reported),
    ("tool.result", FactProvenance::Reported),
];

fn tool_with(arguments: JsonValue, result: JsonValue) -> ToolObservation {
    ToolObservation::new()
        .with_name("synthetic")
        .unwrap()
        .with_arguments(arguments)
        .with_result(result)
}

#[test]
fn fitted_values_replace_the_largest_value_of_either_field_first() {
    let text = |bytes: usize| JsonValue::try_from_source_message_text(&"x".repeat(bytes)).unwrap();
    let object = |members: Vec<(&str, JsonValue)>| {
        JsonValue::object(
            members
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value)),
        )
        .unwrap()
    };
    // A tie goes to the arguments; the other field is kept whole.
    let tool = tool_with(object(vec![("a", text(30_000))]), text(30_000))
        .with_fitted_values()
        .unwrap();
    assert_eq!(
        entries(&tool),
        [(
            BoundedTarget::Arguments,
            "/a".to_owned(),
            BoundDimension::EncodedBytes
        )]
    );
    assert_eq!(tool.result(), Some(&text(30_000)));
    // Otherwise the largest value goes first, and no more than needed.
    let tool = tool_with(
        object(vec![("a", text(20_000)), ("b", text(10_000))]),
        text(25_000),
    )
    // Authored text, so the kept arguments keep the direct-text budget.
    .with_argument_text(ArgumentText::new().with_key("a").with_key("b"))
    .with_fitted_values()
    .unwrap();
    assert_eq!(
        entries(&tool),
        [(
            BoundedTarget::Result,
            String::new(),
            BoundDimension::EncodedBytes
        )]
    );
    assert_eq!(tool.result(), Some(&JsonValue::Null));
    let observation = build_with_provenance(
        ObservationBody::Tool(tool),
        ObservationStage::ToolResultReturned,
        &TOOL_PATHS,
    )
    .unwrap();
    assert!(!format!("{observation:?}").contains("xxxx"));
    // Values that already fit are kept as they are.
    let small = tool_with(object(vec![("a", text(100))]), text(100));
    assert_eq!(small.clone().with_fitted_values().unwrap(), small);
}

#[test]
fn replaced_values_cover_earlier_entries_and_skip_null_fields() {
    let (arguments, replaced) =
        bounded(&serde_json::json!({"long": "z".repeat(4097), "short": "kept"}));
    assert_eq!(replaced.len(), 1);
    let tool = tool_with(arguments, JsonValue::Null)
        .with_bounded_values(replaced)
        .with_replaced_values()
        .unwrap();
    // One entry for the replaced arguments covers the earlier one; the
    // `null` result holds nothing to replace.
    assert_eq!(
        entries(&tool),
        [(
            BoundedTarget::Arguments,
            String::new(),
            BoundDimension::EncodedBytes
        )]
    );
    assert_eq!(tool.arguments(), Some(&JsonValue::Null));
    let observation = build_with_provenance(
        ObservationBody::Tool(tool.clone()),
        ObservationStage::ToolResultReturned,
        &TOOL_PATHS,
    )
    .unwrap();
    assert!(!format!("{observation:?}").contains("kept"));
    // Replacing again records nothing new.
    assert_eq!(tool.clone().with_replaced_values().unwrap(), tool);
}

/// Each field keeps the cap on its own; together they may exceed it. The
/// field with more entries (ties: the arguments) is then replaced whole.
#[test]
fn entries_over_the_cap_replace_the_field_with_more_entries() {
    let members = |count: usize| {
        serde_json::Value::Object(
            (0..count)
                .map(|index| (format!("k{index}"), serde_json::json!("z".repeat(4097))))
                .collect(),
        )
    };
    for (arguments, result, expected) in [
        (16, 1, (BoundedTarget::Arguments, 2)),
        (1, 16, (BoundedTarget::Result, 2)),
        (9, 9, (BoundedTarget::Arguments, 10)),
    ] {
        let (arguments_value, arguments_entries) = bounded(&members(arguments));
        let (result_value, result_entries) =
            JsonValue::try_from_source_value_bounded(BoundedTarget::Result, &members(result))
                .unwrap();
        let tool = ToolObservation::new()
            .with_name("synthetic")
            .unwrap()
            .with_arguments(arguments_value)
            .with_bounded_values(arguments_entries)
            .with_result(result_value)
            .with_bounded_values(result_entries);
        let (whole, count) = expected;
        assert_eq!(tool.bounded_values().len(), count);
        assert!(
            entries(&tool)
                .iter()
                .any(|(target, pointer, _)| *target == whole && pointer.is_empty())
        );
        build_with_provenance(
            ObservationBody::Tool(tool),
            ObservationStage::ToolResultReturned,
            &TOOL_PATHS,
        )
        .unwrap();
    }
}

/// The bounded conversion decides on the normalized text: a string or key
/// within its bound at the source whose normalized form is over it is
/// replaced or dropped and recorded, like one over it at the source.
#[test]
fn bounded_conversion_decides_on_the_normalized_size() {
    // Each character normalizes to two, of twice its length.
    let expanding = |count: usize| "\u{958}".repeat(count);
    let source = serde_json::json!({"q": expanding(1_365), expanding(21): 1, "kept": "ok"});
    assert!(JsonValue::try_from_source_value(&source).is_err());
    let (value, replaced) = bounded(&source);
    assert_eq!(
        replacements(&replaced),
        [
            ("", BoundDimension::KeyBytes),
            ("/q", BoundDimension::StringBytes)
        ]
    );
    assert_eq!(replaced[1].bytes(), 4_095);
    let JsonValue::Object(members) = &value else {
        panic!("object")
    };
    assert_eq!(members.len(), 2);
    assert_eq!(members["q"], JsonValue::Null);
    assert_eq!(members["kept"], JsonValue::string("ok"));
    // Within the bound once normalized, the string is kept normalized.
    let (value, replaced) = bounded(&serde_json::json!({"q": expanding(600)}));
    assert!(replaced.is_empty());
    assert_eq!(
        value,
        JsonValue::try_from_source_value(&serde_json::json!({"q": expanding(600)})).unwrap()
    );
}
