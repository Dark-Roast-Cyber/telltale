use super::*;

#[test]
fn values_over_the_observation_aggregate_are_replaced_and_reported() {
    // One value with the tool name and its record's other fields.
    assert_fitted_band(
        65_480..=65_536,
        "Bash",
        ("", Some(0), BoundedTarget::Arguments),
        |size| {
            let batch = acquire_input(
                ClientId::Claude,
                "claude.projects",
                SourceKind::Jsonl,
                &claude_bash_call(size),
            );
            // A replaced call contributes no activity.
            let counts = &batch.accounting.sessions[0].counts;
            if !batch.bounded.is_empty() {
                assert!(counts.contributions.tool_calls.is_empty());
                assert!(counts.tool_usage.is_empty());
            }
            batch
        },
    );
    assert_fitted_band(
        65_480..=65_536,
        "mcp__synthetic__probe",
        ("", Some(1), BoundedTarget::Result),
        |size| {
            let input = format!(
                "{}\n{}\n",
                json!({"type":"tool_call","session_id":"synthetic","name":"mcp__synthetic__probe","arguments":{}}),
                json!({"type":"tool_result","session_id":"synthetic","name":"mcp__synthetic__probe","output":"x".repeat(size)}),
            );
            acquire_input(ClientId::Codex, "codex.sessions", SourceKind::Jsonl, &input)
        },
    );
    // Arguments and result together: the larger is replaced first.
    assert_fitted_band(
        (31_000..=34_000).step_by(50),
        "exec",
        ("", Some(0), BoundedTarget::Result),
        |size| {
            let input = format!(
                "{}\n",
                json!({"type":"tool_result","session_id":"synthetic","name":"exec","arguments":"x".repeat(32_000),"output":"y".repeat(size + 1_000)})
            );
            acquire_input(ClientId::Codex, "codex.sessions", SourceKind::Jsonl, &input)
        },
    );
}

/// A hook journal keeps strict values: where a session source replaces a
/// value over the observation aggregate, the journal quarantines the call,
/// and nothing is reported as replaced.
#[cfg(feature = "hook-journal")]
#[test]
fn a_hook_journal_keeps_quarantining_values_over_the_aggregate() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.jsonl");
    let mut quarantined = 0;
    for size in 65_480..=65_536 {
        let input = claude_bash_call(size);
        std::fs::write(&path, &input).unwrap();
        let journal = Source {
            client: ClientId::Claude,
            source_id: ClientId::Claude.hook_journal_source_id().to_owned(),
            kind: SourceKind::Jsonl,
            path: path.clone(),
        };
        let batch = acquire_source(&journal, options()).unwrap();
        assert!(batch.bounded.is_empty(), "{size}");
        let session = acquire_input(
            ClientId::Claude,
            "claude.projects",
            SourceKind::Jsonl,
            &input,
        );
        assert_eq!(batch.quarantined.len(), session.bounded.len(), "{size}");
        quarantined += batch.quarantined.len();
    }
    assert!(quarantined > 0);
}

/// Arguments and result of one OpenCode part together over the aggregate:
/// the larger value is replaced, and no facet is built from a replaced
/// command.
#[cfg(feature = "opencode-sqlite")]
#[test]
fn opencode_values_over_the_observation_aggregate_are_replaced_and_reported() {
    let directory = tempfile::tempdir().unwrap();
    let source = Source {
        client: ClientId::OpenCode,
        source_id: "opencode.sqlite".into(),
        kind: SourceKind::Sqlite,
        path: directory.path().join("opencode.db"),
    };
    let writer = rusqlite::Connection::open(&source.path).unwrap();
    writer
        .execute_batch(
            "create table part (id text primary key, session_id text, time_updated integer, data text);",
        )
        .unwrap();
    assert_fitted_band(
        (29_000..=33_000).step_by(50),
        "bash",
        ("output", None, BoundedTarget::Arguments),
        |size| {
            let data = json!({"type":"tool","tool":"bash","state":{"status":"completed","input":{"command":"x".repeat(34_000)},"output":"y".repeat(size)}});
            writer
                .execute(
                    "insert or replace into part values ('output','synthetic',20,?1)",
                    [data.to_string()],
                )
                .unwrap();
            acquire_source(&source, options()).expect("held, not refused")
        },
    );
}

/// A string within its bound whose normalized form is over it is replaced,
/// in sources that read a record at a time and in those that read a source
/// as one unit.
#[test]
fn values_over_their_bound_once_normalized_are_replaced_and_reported() {
    // Each character normalizes to two, of twice its length.
    let expanding = "\u{958}".repeat(1_300);
    let decomposed = "\u{915}\u{93c}";
    for (arguments, result, sequence, target) in [
        (
            json!({"q": expanding}),
            json!({"structured":"ok"}),
            0,
            BoundedTarget::Arguments,
        ),
        (json!({}), json!({"q": expanding}), 1, BoundedTarget::Result),
    ] {
        for (client, source_id, kind, input) in
            tool_call_corpus("mcp__synthetic__probe", &arguments, &result)
        {
            if client == ClientId::Copilot && target == BoundedTarget::Result {
                continue; // Its request carries no result.
            }
            let batch = acquire_input(client, source_id, kind, &input);
            assert!(batch.quarantined.is_empty(), "{client:?}");
            let units = batch
                .bounded
                .iter()
                .map(|unit| (unit.source_sequence, unit.target, unit.dimension))
                .collect::<Vec<_>>();
            let sequence = if client == ClientId::Copilot {
                0
            } else {
                sequence
            };
            assert_eq!(
                units,
                [(sequence, target, BoundDimension::StringBytes)],
                "{client:?}"
            );
            let debug = format!("{:?}{:?}", batch.bounded, batch.observations);
            assert!(
                !debug.contains(decomposed) && !debug.contains("\u{958}"),
                "{client:?}"
            );
            assert!(batch.observations.iter().any(|observation| matches!(
                observation.body(),
                ObservationBody::Tool(tool) if tool.name() == Some("mcp__synthetic__probe")
            )));
        }
    }
}

/// Copilot request text that is no JSON is one value, and the text of the
/// item's message is the call's result: each is kept whole within its bound
/// and otherwise replaced whole and reported, with nothing derived from it.
#[test]
fn copilot_request_text_and_message_are_replaced_whole_over_their_bound() {
    let acquire = |item: Value| {
        let log = format!(
            "Workspace initialized: synthetic (checkpoints: 0)\nAccumulated output items (1): {}\n",
            json!([item])
        );
        acquire_input(
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
            &log,
        )
    };
    let units = |batch: &AcquisitionBatch| {
        batch
            .bounded
            .iter()
            .map(|unit| (unit.source_sequence, unit.target, unit.dimension))
            .collect::<Vec<_>>()
    };
    let tools = |batch: &AcquisitionBatch| {
        batch
            .observations
            .iter()
            .filter_map(|observation| match observation.body() {
                ObservationBody::Tool(tool) => Some(tool.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    // Within the bound the text is kept as it was.
    let kept = acquire(
        json!({"type":"function_call","name":"exec","call_id":"call_synthetic","arguments":"not json, short","message":"done"}),
    );
    assert!(kept.bounded.is_empty());
    let [request, result] = tools(&kept).try_into().unwrap();
    assert_eq!(
        request.arguments(),
        Some(&JsonValue::string("not json, short"))
    );
    assert_eq!(request.searchable_arguments(), Some("not json, short"));
    assert_eq!(result.result(), Some(&JsonValue::string("done")));

    let batch = acquire(
        json!({"type":"function_call","name":"exec","call_id":"call_synthetic","arguments":format!("not json {}", "x".repeat(5_000))}),
    );
    assert_eq!(
        units(&batch),
        [(0, BoundedTarget::Arguments, BoundDimension::StringBytes)]
    );
    let [request] = tools(&batch).try_into().unwrap();
    assert_eq!(request.name(), Some("exec"));
    assert_eq!(request.arguments(), Some(&JsonValue::Null));
    assert_eq!(
        request
            .bounded_values()
            .iter()
            .map(|value| value.pointer())
            .collect::<Vec<_>>(),
        [""]
    );
    assert_eq!(request.searchable_arguments(), None);
    assert!(batch.observations[0].facets().is_empty());
    assert!(
        batch.accounting.sessions[0]
            .counts
            .contributions
            .tool_calls
            .is_empty()
    );
    assert!(!format!("{:?}{:?}", batch.bounded, batch.observations).contains("xxxx"));

    let batch = acquire(
        json!({"type":"function_call","name":"exec","call_id":"call_synthetic","arguments":"{}","message":"y".repeat(65_537)}),
    );
    assert_eq!(
        units(&batch),
        [(0, BoundedTarget::Result, BoundDimension::StringBytes)]
    );
    let [request, result] = tools(&batch).try_into().unwrap();
    assert!(request.bounded_values().is_empty());
    assert_eq!(result.result(), Some(&JsonValue::Null));
    assert!(!format!("{:?}{:?}", batch.bounded, batch.observations).contains("yyyy"));
}

/// Copilot request text that is no JSON and the item's message text are held
/// as the observation stores them, normalized: text whose normalized form is
/// within its bound is kept, whatever its source length, as before these
/// texts took the shared conversion.
#[test]
fn copilot_texts_within_their_bound_once_normalized_are_kept() {
    // Each decomposed pair normalizes to one shorter character.
    let request = format!("a{}", "e\u{301}".repeat(1_400));
    let message = "e\u{301}".repeat(22_000);
    assert!(request.len() > 4_096 && message.len() > 65_536);
    let log = format!(
        "Workspace initialized: synthetic (checkpoints: 0)\nAccumulated output items (1): {}\n",
        json!([{"type":"function_call","name":"exec","call_id":"call_synthetic","arguments":request,"message":message}])
    );
    let batch = acquire_input(
        ClientId::Copilot,
        "copilot.process_log",
        SourceKind::CopilotProcessLog,
        &log,
    );
    assert!(batch.bounded.is_empty(), "{:?}", batch.bounded);
    assert!(batch.quarantined.is_empty());
    let tools = batch
        .observations
        .iter()
        .filter_map(|observation| match observation.body() {
            ObservationBody::Tool(tool) => Some(tool),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [call, result] = tools.as_slice() else {
        panic!("request and result")
    };
    assert_eq!(call.arguments(), Some(&JsonValue::string(&request)));
    assert!(call.bounded_values().is_empty());
    assert!(call.searchable_arguments().is_some());
    assert_eq!(result.result(), Some(&JsonValue::string(&message)));
    assert!(result.bounded_values().is_empty());
}
