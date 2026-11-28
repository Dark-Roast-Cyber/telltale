use super::*;

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
