use super::*;

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
        super::super::value::validate_bounded_values(&replaced, Some(&converted), None, [false; 2])
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
