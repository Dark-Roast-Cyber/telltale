use super::*;

#[test]
fn identity_values_are_kept_or_encoded_idempotently() {
    for ok in ["toolu_01:a%b.c", "5f0e3b1c-0d3a", "caf\u{e9}", "a b"] {
        assert_eq!(safe_id(ok), ok);
    }
    for bad in [
        "", " ", "\u{a0}", "a/b", "a\\b", "a..b", "a\nb", "a\tb", "a\0b",
    ] {
        let id = safe_id(bad).into_owned();
        assert!(id.starts_with("tth-esc-") && id.len() == 8 + 32, "{bad:?}");
        assert_eq!(safe_id(&id), id);
    }
    assert_ne!(safe_id("a/b"), safe_id("a\\b"));
    assert!(safe_id(&"k".repeat(257)).starts_with("tth-esc-"));
    for name in [
        "Bash",
        "mcp__server__tool",
        "server-tool",
        "server_tool",
        "a/b",
    ] {
        assert_eq!(safe_tool_name(name), name);
    }
    for bad in ["", " ", "\u{a0}", "Bash\n", "Bash\r", "Bash\t", "Bash\0"] {
        assert!(safe_tool_name(bad).starts_with("tth-esc-"), "{bad:?}");
    }
}

#[test]
fn colliding_keys_are_renamed_and_nothing_else_changes() {
    // No collision: either spelling alone, ASCII, nested, arrays.
    for clean in [
        json!({"command": "ls", "\u{e9}": 1}),
        json!({"command": "ls", "e\u{301}": 1}),
        json!({"a": [{"b": "\u{e9}"}], "n": 5, "s": "e\u{301}"}),
        json!("e\u{301}"),
    ] {
        assert_eq!(safe_input_keys(&clean), clean);
        assert!(!input_keys_collide(&clean));
    }
    // The spelling already in NFC keeps its name; values all survive.
    let top = json!({"\u{e9}": "composed", "e\u{301}": "decomposed", "command": "ls"});
    let safe = json!({"\u{e9}": "composed", "\u{e9}~1": "decomposed", "command": "ls"});
    assert_eq!(safe_input_keys(&top), safe);
    assert!(input_keys_collide(&top));
    // Idempotent, and nested objects inside arrays are covered.
    assert_eq!(safe_input_keys(&safe), safe);
    let nested = json!({"a": [{"\u{e9}": 1, "e\u{301}": 2}]});
    assert_eq!(
        safe_input_keys(&nested),
        json!({"a": [{"\u{e9}": 1, "\u{e9}~1": 2}]})
    );
    // Non-ASCII spellings of ASCII keys: the ASCII key keeps its name.
    let kelvin = json!({"Key": "plain", "\u{212a}ey": "kelvin"});
    assert_eq!(
        safe_input_keys(&kelvin),
        json!({"Key": "plain", "Key~1": "kelvin"})
    );
    // A chosen suffix never lands on a key that is already there, in
    // either spelling, and no two results share an NFC form.
    let taken = json!({"\u{e9}": 1, "e\u{301}": 2, "\u{e9}~1": 3, "e\u{301}~1": 4});
    let safe = safe_input_keys(&taken);
    let map = safe.as_object().unwrap();
    assert_eq!(map.len(), 4);
    let forms: BTreeSet<String> = map.keys().map(|key| key.nfc().collect()).collect();
    assert_eq!(forms.len(), 4, "{safe}");
    assert_eq!(map["\u{e9}"], 1);
    assert_eq!(map["\u{e9}~1"], 3);
    // No spelling in NFC: one keeps its spelling, Telltale folds it alone.
    let neither = json!({"\u{212b}": 1, "A\u{30a}": 2});
    let safe = safe_input_keys(&neither);
    let forms: BTreeSet<String> = safe
        .as_object()
        .unwrap()
        .keys()
        .map(|key| key.nfc().collect())
        .collect();
    assert_eq!(forms.len(), 2, "{safe}");
}

#[test]
fn tail_is_bounded_by_records_and_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::new(dir.path().join("j.jsonl"));
    for i in 0..10 {
        journal
            .append(&Line::user_prompt(
                "s",
                &format!("u{i}"),
                "2026-01-01T00:00:00.000Z",
                "hi",
            ))
            .unwrap();
    }
    let tail = journal.tail(3, 1 << 20).unwrap();
    assert_eq!(tail.lines.len(), 3);
    assert!(tail.truncated);
    assert_eq!(tail.lines[2].0["uuid"], "u9");

    let one_line = Line::user_prompt("s", "u0", "2026-01-01T00:00:00.000Z", "hi")
        .to_jsonl()
        .len() as u64;
    let tail = journal.tail(100, one_line * 2 + 5).unwrap();
    assert_eq!(tail.lines.len(), 2, "partial first line is dropped");
    assert_eq!(tail.skipped, 0);
}

#[test]
fn missing_journal_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let tail = Journal::new(dir.path().join("none.jsonl"))
        .tail(10, 10)
        .unwrap();
    assert!(tail.lines.is_empty() && !tail.truncated);
}

#[test]
fn bound_history_cuts_on_char_boundaries() {
    let value = json!({"a": "ééé", "b": [ "abcdef" ], "n": 5});
    let bounded = bound_history(&value, 3, 1 << 20);
    assert_eq!(bounded, json!({"a": "é", "b": ["abc"], "n": 5}));
}

/// An input within the budget is only string-cut; any other is cut to the
/// budget exactly as the line encodes it, short top-level values first.
#[test]
fn bound_history_fits_the_budget_and_keeps_short_top_level_values() {
    let ordinary = json!({"command": "ls -la", "description": "x".repeat(5000)});
    assert_eq!(
        bound_history(&ordinary, 4000, 16 * 1024),
        json!({"command": "ls -la", "description": "x".repeat(4000)})
    );
    let members = |n: usize, text: &str| {
        let mut map: Map<String, Value> =
            (0..n).map(|i| (format!("a{i:04}"), json!(text))).collect();
        map.insert("url".to_owned(), json!("https://example.invalid/x"));
        map.insert("command".to_owned(), json!("sh /tmp/x.sh"));
        Value::Object(map)
    };
    let deep = (0..100).fold(json!("q\"\u{1}é".repeat(2000)), |v, _| json!({"d": [v, 1]}));
    let cases = [
        members(1100, &"m".repeat(4000)),
        members(2000, "m"),
        members(3, &"\u{1}\"\\é".repeat(4000)),
        json!({"command": "ls", "nested": deep}),
        json!([deep, "x".repeat(4000), "y".repeat(4000)]),
        json!("z".repeat(100_000)),
    ];
    for budget in [16 * 1024, 300, 40, 2] {
        for (n, value) in cases.iter().enumerate() {
            let bounded = bound_history(value, 4000, budget);
            let written = bounded.to_string().len();
            assert!(written <= budget, "{written} > {budget}");
            // Long padding members do not crowd out the short values.
            if budget >= 300
                && (n == 0 || n == 2)
                && let Some(map) = value.as_object()
            {
                assert_eq!(bounded["command"], map["command"]);
                assert_eq!(bounded["url"], map["url"]);
            }
        }
    }
    // Filled close to the budget, not left far short of it.
    let bounded = bound_history(&cases[0], 4000, 16 * 1024);
    assert!(bounded.to_string().len() > 16 * 1024 - 4100);
}

/// A command member goes into history ahead of members shorter than it.
#[test]
fn bound_history_keeps_the_command_ahead_of_shorter_members() {
    let mut map: Map<String, Value> = (0..3000).map(|i| (format!("a{i:04}"), json!(1))).collect();
    map.insert("command".to_owned(), json!("sh /tmp/x.sh"));
    let bounded = bound_history(&Value::Object(map), 4000, 16 * 1024);
    assert_eq!(bounded["command"], "sh /tmp/x.sh");
}

/// A line longer than the whole budget is skipped, not left to empty the
/// window: the lines before it fill the budget in its place.
#[test]
fn tail_steps_over_a_line_longer_than_the_budget() {
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::new(dir.path().join("j.jsonl"));
    let prompt =
        |uuid: &str, text: &str| Line::user_prompt("s", uuid, "2026-01-01T00:00:00.000Z", text);
    let one_line = prompt("u0", "hi").to_jsonl().len() as u64;
    for i in 0..5 {
        journal.append(&prompt(&format!("u{i}"), "hi")).unwrap();
    }
    let budget = one_line * 3 + 5;
    // Longer than the budget, within the bytes read to step over it.
    let big = "b".repeat(budget as usize * 2);
    journal.append(&prompt("big", &big)).unwrap();
    journal.append(&prompt("u5", "hi")).unwrap();
    let tail = journal.tail(100, budget).unwrap();
    let uuids: Vec<&Value> = tail.lines.iter().map(|line| &line.0["uuid"]).collect();
    assert_eq!(uuids, [&json!("u3"), &json!("u4"), &json!("u5")]);
    assert!(tail.truncated);
    assert_eq!(tail.skipped, 1);

    // The oversized line last, and alone.
    journal.append(&prompt("big2", &big)).unwrap();
    let tail = journal.tail(100, budget).unwrap();
    let uuids: Vec<&Value> = tail.lines.iter().map(|line| &line.0["uuid"]).collect();
    assert_eq!(uuids, [&json!("u3"), &json!("u4"), &json!("u5")]);
    assert_eq!(tail.skipped, 2);

    // Stepping over is bounded: past the bytes it may read, the window
    // ends there.
    journal
        .append(&prompt("huge", &"h".repeat(budget as usize * 10)))
        .unwrap();
    let tail = journal.tail(100, budget).unwrap();
    assert!(tail.lines.is_empty() && tail.truncated);
}
