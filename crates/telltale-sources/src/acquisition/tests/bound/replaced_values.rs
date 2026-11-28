use super::*;

/// Exactly-at-bound tool values keep their observation ids and semantic
/// content byte for byte in every adapter with tool calls. The pin is a
/// digest, so the corpus outcome stays reviewable without listing it.
#[test]
fn in_bound_tool_calls_keep_identity_and_semantic_content() {
    use sha2::{Digest, Sha256};
    use telltale_schema::observation::{CanonicalObservationV2, canonical_identity_json};
    let nested = |count| (0..count).fold(Value::Null, |value, _| json!([value]));
    let members = |count| {
        Value::Object(
            (0..count)
                .map(|index| (format!("k{index}"), json!(index)))
                .collect(),
        )
    };
    let mut cases = [
        json!({"note":"s".repeat(4096), "path":"/synthetic/project/file.txt"}),
        json!({"tree":nested(4)}),
        json!({"items":vec![json!(1); 64]}),
        members(32),
        json!({"k".repeat(64): "v"}),
        json!(["\u{1}".repeat(2730)]),
    ]
    .map(|arguments| (arguments, json!({"structured":"ok"})))
    .to_vec();
    cases.push((json!({"command":"x".repeat(64)}), json!("x".repeat(4096))));
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut tools = 0;
    let absorb = |observation: &CanonicalObservationV2| {
        let mut line = observation.observation_id().as_bytes().to_vec();
        line.extend(format!("|{:?}|{:?}|", observation.kind(), observation.stage()).bytes());
        if let ObservationBody::Tool(tool) = observation.body() {
            line.extend(tool.name().unwrap_or("").bytes());
            for value in [tool.arguments(), tool.result()].into_iter().flatten() {
                line.extend(canonical_identity_json(value).unwrap());
                line.push(b'|');
            }
        }
        for (name, facet) in observation.facets() {
            line.extend(name.bytes());
            line.extend(canonical_identity_json(facet.value()).unwrap());
        }
        for (path, metadata) in observation.fact_metadata() {
            line.extend(
                format!(
                    "{path}:{:?}:{:?}",
                    metadata.provenance(),
                    metadata.sensitivity()
                )
                .bytes(),
            );
        }
        line.extend(observation.semantic_comparison().to_string().bytes());
        line
    };
    // The accounting a batch carries for its units: an in-bound call wrongly
    // treated as replaced would drop out of these counts.
    let accounting = |batch: &AcquisitionBatch| {
        let counts = |counts: &NativeCounts| {
            format!(
                "{}|{:?}|{:?}|{:?}|{:?}|{:?}",
                counts.native_units,
                counts.record_counts,
                counts.contributions.tool_calls,
                counts.contributions.path_classes,
                counts.contributions.network_hosts,
                counts
                    .tool_usage
                    .iter()
                    .map(|(name, usage)| (
                        name,
                        usage.count,
                        usage.first_order,
                        &usage.first_timestamp
                    ))
                    .collect::<Vec<_>>()
            )
        };
        let mut text = format!(
            "{:?}|{:?}|{}",
            batch.accounting.coverage,
            batch.accounting.tool_table,
            counts(&batch.accounting.unscoped)
        );
        for session in &batch.accounting.sessions {
            text.push('|');
            text.push_str(&counts(&session.counts));
        }
        text
    };
    let mut absorb_batch = |batch: &AcquisitionBatch, lines: &mut Vec<Vec<u8>>| {
        lines.push(format!("{:?}|{}", batch.bounded, accounting(batch)).into_bytes());
        for observation in &batch.observations {
            tools += usize::from(matches!(observation.body(), ObservationBody::Tool(_)));
            lines.push(absorb(observation));
        }
    };
    for (case, (arguments, result)) in cases.iter().enumerate() {
        for (client, source_id, kind, input) in
            tool_call_corpus("mcp__synthetic__probe", arguments, result)
        {
            let directory = tempfile::tempdir().unwrap();
            let source = Source {
                client,
                source_id: source_id.into(),
                kind,
                path: directory.path().join("synthetic-input.log"),
            };
            std::fs::write(&source.path, input).unwrap();
            // Pin what each adapter does, a refusal included.
            match acquire_source(&source, options()) {
                Ok(batch) => {
                    // In bounds nothing is replaced, so no unit is reported as
                    // bounded. In two Copilot cases the raw request text is
                    // over its own bound: the call keeps its arguments, only
                    // that searchable text is omitted, and the unit is
                    // reported.
                    if client == ClientId::Copilot && matches!(case, 0 | 5) {
                        assert_eq!(
                            bounded_units(&batch),
                            [(
                                "",
                                0,
                                BoundedTarget::SearchableArguments,
                                BoundDimension::StringBytes
                            )],
                            "{case}"
                        );
                        let [call] = batch.observations.as_slice() else {
                            panic!("{case}: one call")
                        };
                        let ObservationBody::Tool(tool) = call.body() else {
                            panic!("{case}: a tool call")
                        };
                        assert_eq!(
                            tool.arguments(),
                            Some(&JsonValue::try_from_source_value(arguments).unwrap()),
                            "{case}"
                        );
                        assert_eq!(tool.searchable_arguments(), None, "{case}");
                    } else {
                        assert!(
                            batch.bounded.is_empty(),
                            "{client:?} {case}: {:?}",
                            batch.bounded
                        );
                    }
                    lines.push(format!("{client:?}:{:?}", batch.quarantined).into_bytes());
                    absorb_batch(&batch, &mut lines);
                }
                Err(error) => lines.push(format!("{client:?}:{error}").into_bytes()),
            }
        }
    }
    // A Claude command over the structured string bound keeps the
    // authored-text budget.
    let input = format!(
        "{}\n",
        json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_authored","name":"Bash","input":{"command":"x".repeat(65_000),"description":"synthetic"}}]}})
    );
    let batch = acquire_input(
        ClientId::Claude,
        "claude.projects",
        SourceKind::Jsonl,
        &input,
    );
    assert!(batch.quarantined.is_empty());
    assert!(batch.bounded.is_empty(), "{:?}", batch.bounded);
    absorb_batch(&batch, &mut lines);
    assert!(tools >= 45, "corpus produced {tools} tool observations");
    let mut digest = Sha256::new();
    for line in &lines {
        digest.update(Sha256::digest(line));
    }
    let digest: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        digest, "7606363534c6b600d99e01aa2d237beaa2bd99450633228a4c573e72e1318f93",
        "in-bound projection changed"
    );
}

/// The router admits a call whose over-bound value was replaced. Nothing is
/// derived from a value the observation does not carry: like a quarantined
/// unit, the call takes no part in contribution accounting, so a long
/// path-like token in the replaced value can no longer quarantine it. A
/// neighbouring call with whole values is still counted.
#[test]
fn replaced_tool_values_admit_the_unit_and_contribute_nothing() {
    let call = |id: &str, value: String| {
        format!(
            "{}\n",
            json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":[{"type":"tool_use","id":id,"name":"mcp__synthetic__run","input":{"query":value,"file_path":"/synthetic/project/notes.txt"}}]}})
        )
    };
    let neighbour = call(
        "toolu_neighbour",
        "ok https://neighbour.example.test/".into(),
    );
    for value in ["z ".repeat(2_500), "synthetic/".repeat(500)] {
        let batch = acquire_input(
            ClientId::Claude,
            "claude.projects",
            SourceKind::Jsonl,
            &format!("{}{neighbour}", call("toolu_synthetic", value)),
        );
        assert!(batch.quarantined.is_empty());
        assert_eq!(batch.accounting.coverage, AccountingCoverage::PartialSource);
        let [unit] = batch.bounded.as_slice() else {
            panic!("expected one bounded unit: {:?}", batch.bounded)
        };
        assert_eq!(
            (unit.source_sequence, unit.target, unit.dimension),
            (0, BoundedTarget::Arguments, BoundDimension::StringBytes)
        );
        let (observation, tool) = batch
            .observations
            .iter()
            .find_map(|observation| match observation.body() {
                ObservationBody::Tool(tool) if !tool.bounded_values().is_empty() => {
                    Some((observation, tool))
                }
                _ => None,
            })
            .expect("the call is projected");
        assert_eq!(tool.name(), Some("mcp__synthetic__run"));
        assert!(observation.facets().contains_key("resource.path"));
        // Only the neighbour contributes: one call, its host, no path of the
        // replaced value.
        let counts = &batch.accounting.sessions[0].counts;
        assert_eq!(
            counts.contributions.tool_calls.values().sum::<u64>(),
            1,
            "{:?}",
            counts.contributions
        );
        assert_eq!(counts.contributions.network_hosts.len(), 1);
        assert_eq!(
            counts
                .tool_usage
                .values()
                .map(|usage| usage.count)
                .sum::<u64>(),
            1
        );
        assert_eq!(counts.native_units, 2);
    }
}

/// Copilot keeps the raw request text as searchable text. Beside arguments
/// with a replaced value it is omitted, or it would carry what was replaced.
#[test]
fn copilot_drops_searchable_text_beside_replaced_arguments() {
    let items = (0..65).map(|_| json!("replaced-item")).collect::<Vec<_>>();
    let arguments = json!({"items": items, "path": "/synthetic/kept"}).to_string();
    assert!(arguments.len() < 4_096);
    let log = format!(
        "Workspace initialized: synthetic (checkpoints: 0)\nAccumulated output items (1): {}\n",
        json!([{"type":"function_call","name":"exec","call_id":"call_synthetic","arguments":arguments}])
    );
    let batch = acquire_input(
        ClientId::Copilot,
        "copilot.process_log",
        SourceKind::CopilotProcessLog,
        &log,
    );
    let ObservationBody::Tool(tool) = batch.observations[0].body() else {
        panic!("expected the call")
    };
    assert_eq!(
        tool.bounded_values()
            .iter()
            .map(|value| (value.target(), value.dimension()))
            .collect::<Vec<_>>(),
        [(BoundedTarget::Arguments, BoundDimension::ArrayItems)]
    );
    assert_eq!(tool.searchable_arguments(), None);
    assert!(!format!("{:?}", batch.observations).contains("replaced-item"));
    assert!(format!("{:?}", tool.arguments()).contains("/synthetic/kept"));
    assert_eq!(batch.bounded.len(), 1);
}

/// A Copilot call whose values are each within their bounds keeps them when
/// its raw request text is over its own bound: only that searchable text is
/// omitted, the command facet is built from the kept argument, and the unit
/// is reported with the searchable target.
#[test]
fn copilot_keeps_in_bound_arguments_beside_an_omitted_request_text() {
    let arguments = |note: usize| json!({"command":"echo synthetic", "path":"/synthetic/kept", "note":"n".repeat(note), "more":"m".repeat(1_200)});
    let long = arguments(3_000).to_string();
    assert!(long.len() > 4_096);
    let batch = copilot_call(&long);
    assert!(batch.quarantined.is_empty());
    assert_eq!(
        bounded_units(&batch),
        [(
            "",
            0,
            BoundedTarget::SearchableArguments,
            BoundDimension::StringBytes
        )]
    );
    let [call] = batch.observations.as_slice() else {
        panic!("one call")
    };
    let ObservationBody::Tool(tool) = call.body() else {
        panic!("a tool call")
    };
    assert_eq!(
        tool.arguments(),
        Some(&JsonValue::try_from_source_value(&arguments(3_000)).unwrap())
    );
    assert_eq!(tool.searchable_arguments(), None);
    assert!(
        !call
            .fact_metadata()
            .contains_key("tool.searchable_arguments")
    );
    assert_eq!(
        tool.bounded_values()
            .iter()
            .map(|value| (value.target().as_str(), value.pointer()))
            .collect::<Vec<_>>(),
        [("searchable_arguments", "")]
    );
    // The facets are those of the same call with a short request text.
    let short = copilot_call(&arguments(10).to_string());
    assert!(short.bounded.is_empty());
    assert_eq!(call.facets(), short.observations[0].facets());
    assert!(call.facets().contains_key("command.text"));
}

/// A Copilot call with a replaced argument value keeps today's outcome even
/// when its raw request text is also over its bound: the value is replaced,
/// no searchable text is kept, and no omission is recorded beside it.
#[test]
fn copilot_replaced_arguments_record_no_omitted_request_text() {
    let items = (0..65).map(|_| json!("replaced-item")).collect::<Vec<_>>();
    let arguments =
        json!({"items": items, "path": "/synthetic/kept", "note":"n".repeat(4_000)}).to_string();
    assert!(arguments.len() > 4_096);
    let batch = copilot_call(&arguments);
    assert_eq!(
        bounded_units(&batch),
        [("", 0, BoundedTarget::Arguments, BoundDimension::ArrayItems)]
    );
    let ObservationBody::Tool(tool) = batch.observations[0].body() else {
        panic!("expected the call")
    };
    assert_eq!(tool.searchable_arguments(), None);
    assert!(
        tool.bounded_values()
            .iter()
            .all(|value| value.target() == BoundedTarget::Arguments)
    );
    assert!(format!("{:?}", tool.arguments()).contains("/synthetic/kept"));
}

#[test]
fn replaced_values_keep_the_contribution_label_checks() {
    let name = "exec\u{1}tool";
    let outcome = |client: ClientId, source_id: &str, input: String| {
        let directory = tempfile::tempdir().unwrap();
        let source = Source {
            client,
            source_id: source_id.into(),
            kind: SourceKind::Jsonl,
            path: directory.path().join("synthetic-label.jsonl"),
        };
        std::fs::write(&source.path, input).unwrap();
        match acquire_source(&source, options()) {
            Ok(batch) => format!(
                "ok observations={} quarantined={:?} bounded={}",
                batch.observations.len(),
                batch
                    .quarantined
                    .iter()
                    .map(|unit| unit.code)
                    .collect::<Vec<_>>(),
                batch.bounded.len()
            ),
            Err(error) => format!("error {}", error.code()),
        }
    };
    for value in ["small".to_owned(), "z".repeat(5_000)] {
        let claude = format!(
            "{}\n",
            json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_synthetic","name":name,"input":{"note":value}}]}})
        );
        let qwen = format!(
            "{}\n",
            json!({"type":"tool_call","sessionId":"synthetic","tool_name":name,"arguments":{"note":value}})
        );
        // A per-record adapter quarantines the call; a whole-source adapter
        // fails the source, with or without a replaced value.
        assert_eq!(
            outcome(ClientId::Claude, "claude.projects", claude),
            "ok observations=0 quarantined=[\"invalid_native_contribution\"] bounded=0",
            "{}",
            value.len()
        );
        assert_eq!(
            outcome(ClientId::Qwen, "qwen.projects", qwen),
            "error invalid_native_contribution",
            "{}",
            value.len()
        );
    }
}

/// A call whose operand was replaced for its size is counted as replaced,
/// not as a call whose table row lost its operand.
#[test]
fn a_replaced_operand_is_not_tool_table_drift() {
    let call = |input: Value| {
        format!(
            "{}\n",
            json!({"type":"assistant","sessionId":"synthetic","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_synthetic","name":"Bash","input":input}]}})
        )
    };
    let drift = |input: Value| {
        let batch = acquire_input(
            ClientId::Claude,
            "claude.projects",
            SourceKind::Jsonl,
            &call(input),
        );
        (
            batch.bounded.len(),
            batch.accounting.tool_table.tool_operand_drift,
        )
    };
    // Without its command the row has drifted; a replaced command has not.
    assert_eq!(drift(json!({"description": "synthetic"})), (0, 1));
    assert_eq!(drift(json!({"command": "z ".repeat(40_000)})), (1, 0));
}

/// The command facet is decided per argument key: a replaced `command` does
/// not hide an in-bound `cmd`, and `command` stays preferred when admitted.
#[test]
fn codex_command_facet_is_decided_per_argument_key() {
    let command_text = |arguments: Value| {
        let input = format!(
            "{}\n",
            json!({"type":"tool_call","session_id":"synthetic","name":"exec_command","arguments":arguments})
        );
        let batch = acquire_input(ClientId::Codex, "codex.sessions", SourceKind::Jsonl, &input);
        let observation = &batch.observations[0];
        (
            batch.bounded.len(),
            observation
                .facets()
                .get("command.text")
                .map(|facet| format!("{:?}", facet.value())),
        )
    };
    let over = "z ".repeat(40_000);
    assert_eq!(
        command_text(json!({"command": over, "cmd": "synthetic fallback"})),
        (
            1,
            Some(format!("{:?}", JsonValue::string("synthetic fallback")))
        )
    );
    assert_eq!(
        command_text(json!({"command": "printf synthetic", "cmd": over})),
        (
            1,
            Some(format!("{:?}", JsonValue::string("printf synthetic")))
        )
    );
    assert_eq!(
        command_text(json!({"command": "printf synthetic", "cmd": "synthetic fallback"})),
        (
            0,
            Some(format!("{:?}", JsonValue::string("printf synthetic")))
        )
    );
    assert_eq!(command_text(json!({"command": over})), (1, None));
}

/// A Copilot call with a replaced value is matched to its native item by the
/// session id the observation carries, so a session id the projection
/// normalizes still keeps that call out of contribution accounting.
#[test]
fn copilot_replaced_call_in_a_normalized_session_contributes_nothing() {
    let items = (0..65).map(|_| json!("item")).collect::<Vec<_>>();
    let calls = |session: &str| {
        let log = format!(
            "Workspace initialized: {session} (checkpoints: 0)\nAccumulated output items (1): {}\n",
            json!([{"type":"function_call","name":"exec","call_id":"call_synthetic","arguments":json!({"items": items}).to_string()}])
        );
        let batch = acquire_input(
            ClientId::Copilot,
            "copilot.process_log",
            SourceKind::CopilotProcessLog,
            &log,
        );
        assert_eq!(batch.bounded.len(), 1, "{session}");
        batch
            .accounting
            .sessions
            .iter()
            .map(|session| session.counts.contributions.tool_calls.get("exec").copied())
            .collect::<Vec<_>>()
    };
    // Composed and decomposed spellings of one session id.
    assert_eq!(calls("synthetic-caf\u{e9}"), [None]);
    assert_eq!(calls("synthetic-cafe\u{301}"), [None]);
}
