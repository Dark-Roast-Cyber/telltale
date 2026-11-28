use super::*;

#[test]
fn schema_array_bounds_match_the_rust_constants() {
    let schema: Value = serde_json::from_str(HOOKS_RECORD_V1_SCHEMA).unwrap();
    fn arrays(value: &Value, pointer: String, out: &mut Vec<String>) {
        match value {
            Value::Object(members) => {
                if value["type"] == "array" {
                    out.push(pointer.clone());
                }
                for (name, member) in members {
                    arrays(member, format!("{pointer}/{name}"), out);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    arrays(item, format!("{pointer}/{index}"), out);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    arrays(&schema, String::new(), &mut found);
    let destinations = "/properties/telltale/items/properties/destinations/properties/destinations";
    let mut expected: Vec<_> = BOUNDED_ARRAYS
        .iter()
        .copied()
        .chain([destinations])
        .collect();
    expected.sort_unstable();
    found.sort_unstable();
    assert_eq!(found, expected, "every schema array is listed");
    for pointer in BOUNDED_ARRAYS {
        assert_eq!(
            schema.pointer(pointer).unwrap()["maxItems"],
            json!(HOOKS_RECORD_MAX_ARRAY_ITEMS),
            "{pointer}"
        );
    }
    // Bounded by DestinationFacts, not by this constant.
    assert_eq!(schema.pointer(destinations).unwrap()["maxItems"], json!(16));
}

#[test]
fn every_envelope_array_accepts_its_bound_and_rejects_one_more_item() {
    let max = HOOKS_RECORD_MAX_ARRAY_ITEMS;
    let entry = record()["telltale"][0].clone();
    let names = |prefix: &str, count: usize| -> Vec<Value> {
        // Zero-padded, so the byte order is the numeric order.
        (0..count)
            .map(|i| json!(format!("{prefix}{i:04}")))
            .collect()
    };
    for (pointer, items) in [
        (
            "/evaluation/visibility_limits",
            vec![json!("synthetic_limit"); max + 1],
        ),
        ("/lifecycle/pinned_over", names("SYNTHETIC_", max + 1)),
        ("/lifecycle/rule_ids", names("synthetic.rule_", max + 1)),
        ("/telltale", vec![entry; max + 1]),
    ] {
        let at_bound = with_array(pointer, items[..max].to_vec());
        HooksRecordV1::from_json(&bytes(&at_bound))
            .unwrap_or_else(|error| panic!("{pointer}: {error}"));
        check_rejection(
            &bytes(&with_array(pointer, items)),
            "schema_mismatch",
            Structure,
        );
    }
    // The decision summarizes its actions, so a summary at the bound passes
    // the wire bound and reaches the summary check.
    for pointer in ["/decision/rule_ids", "/decision/categories"] {
        let items = names("synthetic.rule_", max + 1);
        check_rejection(
            &bytes(&with_array(pointer, items[..max].to_vec())),
            "finding_summary_mismatch",
            Semantic,
        );
        check_rejection(
            &bytes(&with_array(pointer, items)),
            "schema_mismatch",
            Structure,
        );
    }
}

#[test]
fn a_line_of_tiny_items_is_rejected_by_the_array_bound_before_item_checks() {
    // Each line is at the 16 MiB bound. Its first item fails the check that
    // would read every item (redaction, the action reader, the summary), so
    // `schema_mismatch` shows the bound rejected it before any item work.
    let unredacted = json!("AKIAPRIVATEMARKER234");
    let invalid_action = json!({"delivery_key": "k", "record": {"schema": "telltale.action.v1"}});
    for (pointer, first, filler) in [
        ("/evaluation/visibility_limits", &unredacted, json!("a")),
        (
            "/decision/rule_ids",
            &json!("synthetic.unmatched"),
            json!("a"),
        ),
        (
            "/decision/categories",
            &json!("synthetic.unmatched"),
            json!("a"),
        ),
        ("/lifecycle/pinned_over", &unredacted, json!("a")),
        ("/lifecycle/rule_ids", &json!("Not A Rule"), json!("a")),
        ("/telltale", &invalid_action, invalid_action.clone()),
    ] {
        let mut small = with_array(pointer, vec![first.clone()]);
        let expected = HooksRecordV1::from_json(&bytes(&small)).unwrap_err();
        assert_ne!(expected.code(), "schema_mismatch", "{pointer}");

        let filler = bytes(&filler);
        small = with_array(pointer, vec![first.clone(), json!("__FILL__")]);
        let wire = bytes(&small);
        let marker = b"\"__FILL__\"";
        let at = wire
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap();
        let room = HOOKS_RECORD_MAX_INPUT_BYTES - 1 - (wire.len() - marker.len());
        let count = room / (filler.len() + 1);
        let mut line = wire[..at].to_vec();
        for index in 0..count {
            if index > 0 {
                line.push(b',');
            }
            line.extend_from_slice(&filler);
        }
        line.extend_from_slice(&wire[at + marker.len()..]);
        line.resize(HOOKS_RECORD_MAX_INPUT_BYTES - 1, b' ');
        line.push(b'\n');
        assert!(count > 100 * HOOKS_RECORD_MAX_ARRAY_ITEMS, "{pointer}");
        check_rejection(&line, "schema_mismatch", Structure);
    }
}
