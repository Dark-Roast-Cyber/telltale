use serde_json::{Value, json};
use telltale_inference::*;
use telltale_schema::observation::*;

const PROFILES: [Profile; 3] = [
    Profile::AnthropicMessages,
    Profile::OpenAiResponses,
    Profile::OllamaChat,
];
fn at() -> ObservedAt {
    ObservedAt::new("2026-10-01T00:00:00Z").unwrap()
}
fn make(profile: Profile, limits: Limits) -> Normalizer {
    Normalizer::with_profile(
        profile,
        Identity {
            verified_installation: Some("11111111111111111111111111111111"),
            native_coordinate: Some("attempt-1"),
            stable_sequence: None,
            request_id: None,
        },
        CapturePolicy::LocalSensitive,
        limits,
    )
    .unwrap()
}
fn request(profile: Profile, stream: bool) -> Value {
    if profile == Profile::OpenAiResponses {
        json!({"model":"requested","stream":stream,"input":"SECRET_MARKER"})
    } else {
        json!({"model":"requested","stream":stream,"messages":[{"role":"user","content":"SECRET_MARKER"}]})
    }
}

#[test]
fn supported_object_commands_are_parsed_sensitive_facets_not_result_execution() {
    const COMMAND: &str = "synthetic command-facet fixture";
    for profile in PROFILES.into_iter().chain([Profile::OpenAiChat]) {
        for command_present in [true, false] {
            let args = if command_present {
                json!({"command":COMMAND})
            } else {
                json!({"synthetic_note":"synthetic non-command argument"})
            };
            let mut req = json!({"model":"synthetic-model","stream":false});
            match profile {
                Profile::AnthropicMessages => {
                    req["messages"] = json!([
                    {"role":"assistant","content":[{"type":"tool_use","id":"synthetic-call","name":"shell","input":args}]},
                    {"role":"user","content":[{"type":"tool_result","tool_use_id":"synthetic-call","content":COMMAND}]}])
                }
                Profile::OpenAiResponses => {
                    req["input"] = json!([
                    {"type":"function_call","call_id":"synthetic-call","name":"shell","arguments":args.to_string()},
                    {"type":"function_call_output","call_id":"synthetic-call","output":COMMAND}])
                }
                _ => {
                    let call = if profile == Profile::OllamaChat {
                        json!({"id":"synthetic-call","function":{"name":"shell","arguments":args}})
                    } else {
                        json!({"id":"synthetic-call","type":"function","function":{"name":"shell","arguments":args.to_string()}})
                    };
                    req["messages"] = json!([
                        {"role":"assistant","content":"","tool_calls":[call]},
                        {"role":"tool","tool_call_id":"synthetic-call","content":COMMAND}]);
                }
            }
            let facts = make(profile, Limits::default())
                .accept_request(&serde_json::to_vec(&req).unwrap(), at())
                .unwrap();
            let proposal = facts
                .iter()
                .find(|o| o.stage() == ObservationStage::ToolProposed)
                .unwrap();
            if command_present {
                assert!(
                    proposal.facets()["command.text"].value() == &JsonValue::string(COMMAND),
                    "{}: proposal.command.text",
                    profile.version()
                );
                let metadata = &proposal.fact_metadata()["command.text"];
                assert!(
                    metadata.provenance() == FactProvenance::Parsed,
                    "{}: proposal.command.provenance",
                    profile.version()
                );
                assert!(
                    metadata.sensitivity() == Sensitivity::Sensitive,
                    "{}: proposal.command.sensitivity",
                    profile.version()
                );
            } else {
                assert!(
                    !proposal.facets().contains_key("command.text"),
                    "{}: proposal.command.absent",
                    profile.version()
                );
                assert!(
                    !proposal.fact_metadata().contains_key("command.text"),
                    "{}: proposal.command.metadata_absent",
                    profile.version()
                );
            }
            let result = facts
                .iter()
                .find(|o| o.stage() == ObservationStage::ToolResultReturned)
                .unwrap();
            assert!(
                result.facets().is_empty(),
                "{}: result.facets.absent",
                profile.version()
            );
            assert!(
                !result.facets().contains_key("command.text"),
                "{}: result.command.absent",
                profile.version()
            );
            assert!(
                !result.fact_metadata().contains_key("command.text"),
                "{}: result.command.metadata_absent",
                profile.version()
            );
            assert!(
                facts.iter().all(|o| o.kind() != ObservationFamily::Process
                    && !matches!(
                        o.stage(),
                        ObservationStage::ToolExecutionStarted
                            | ObservationStage::ToolExecutionCompleted
                    )),
                "{}: execution.absent",
                profile.version()
            );
        }
    }
}

fn response(profile: Profile) -> Value {
    match profile {
        Profile::AnthropicMessages => {
            json!({"id":"response-1","type":"message","role":"assistant","model":"resolved","content":[{"type":"text","text":"hé SECRET_MARKER"},{"type":"tool_use","id":"call-1","name":"shell","input":{"command":"SECRET_MARKER"}}],"stop_reason":"tool_use","usage":{"input_tokens":7,"output_tokens":9}})
        }
        Profile::OpenAiResponses => {
            json!({"id":"response-1","object":"response","status":"completed","model":"resolved","output":[{"id":"message-1","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"hé SECRET_MARKER","annotations":[]}]},{"id":"item-1","type":"function_call","call_id":"call-1","name":"shell","arguments":"{\"command\":\"SECRET_MARKER\"}","status":"completed"}],"usage":{"input_tokens":7,"output_tokens":9}})
        }
        Profile::OllamaChat => {
            json!({"model":"resolved","message":{"role":"assistant","content":"hé SECRET_MARKER","tool_calls":[{"function":{"name":"shell","arguments":{"command":"SECRET_MARKER"}}}]},"done":true,"done_reason":"stop","prompt_eval_count":7,"eval_count":9,"total_duration":12000000})
        }
        Profile::OpenAiChat => {
            json!({"id":"response-1","model":"resolved","choices":[{"index":0,"message":{"role":"assistant","content":"hé SECRET_MARKER","tool_calls":[{"id":"call-1","type":"function","function":{"name":"shell","arguments":"{\"command\":\"SECRET_MARKER\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":7,"completion_tokens":9}})
        }
    }
}
fn run(
    profile: Profile,
    format: ResponseFormat,
    wire: &[u8],
    split: usize,
) -> Result<Vec<CanonicalObservationV2>, Failure> {
    let mut n = make(profile, Limits::default());
    n.accept_request(
        &serde_json::to_vec(&request(profile, format != ResponseFormat::Json)).unwrap(),
        at(),
    )?;
    n.begin_response(format)?;
    n.push_response(&wire[..split], 1)?;
    n.push_response(&wire[split..], 2)?;
    n.finish(EndReason::Complete, at(), 3)
}
#[test]
fn json_profiles_are_atomic_private_and_equivalent() {
    let mut proposals = Vec::new();
    for profile in PROFILES.into_iter().chain([Profile::OpenAiChat]) {
        let wire = serde_json::to_vec(&response(profile)).unwrap();
        let baseline = run(profile, ResponseFormat::Json, &wire, 0).unwrap();
        for split in 0..=wire.len() {
            let actual = run(profile, ResponseFormat::Json, &wire, split).unwrap();
            assert_eq!(actual.len(), baseline.len());
            for (a, b) in actual.iter().zip(&baseline) {
                assert_eq!(a.observation_id(), b.observation_id());
                assert!(a.body() == b.body());
            }
        }
        for obs in &baseline {
            obs.validate().unwrap();
            assert!(!format!("{obs:?}").contains("SECRET_MARKER"));
            assert!(matches!(
                obs.semantic_comparison(),
                SemanticComparison::Unavailable
            ));
            assert!(obs.session_id().is_none() && obs.workflow_id().is_none());
            assert!(
                obs.fact_metadata()
                    .values()
                    .all(|m| m.sensitivity() == Sensitivity::Sensitive)
            );
        }
        let tool = baseline
            .iter()
            .find(|o| o.stage() == ObservationStage::ToolProposed)
            .unwrap();
        if profile == Profile::OllamaChat {
            assert!(tool.correlation().call_id().is_none());
        } else {
            assert_eq!(tool.correlation().call_id().unwrap().value(), "call-1");
        }
        proposals.push(tool.body().clone());
        let invalid = [wire.as_slice(), b"{}"].concat();
        assert!(run(profile, ResponseFormat::Json, &invalid, wire.len()).is_err());
    }
    assert!(proposals.windows(2).all(|p| p[0] == p[1]));
}

fn stream(profile: Profile) -> (ResponseFormat, &'static str) {
    match profile {
        Profile::AnthropicMessages => (ResponseFormat::Sse, include_str!("fixtures/anthropic.sse")),
        Profile::OpenAiResponses => (ResponseFormat::Sse, include_str!("fixtures/responses.sse")),
        Profile::OllamaChat => (
            ResponseFormat::Ndjson,
            include_str!("fixtures/ollama.ndjson"),
        ),
        _ => unreachable!(),
    }
}
fn equivalent(a: &[CanonicalObservationV2], b: &[CanonicalObservationV2]) {
    assert_eq!(a.len(), b.len());
    for (a, b) in a.iter().zip(b) {
        assert_eq!(a.observation_id(), b.observation_id());
        assert!(a.body() == b.body());
        assert!(a.correlation() == b.correlation());
        assert!(a.local() == b.local());
    }
}
#[test]
fn streams_every_boundary_private_commit_and_json_parity() {
    for profile in PROFILES {
        let (format, wire) = stream(profile);
        let baseline = run(profile, format, wire.as_bytes(), 0).unwrap();
        for split in 0..=wire.len() {
            equivalent(
                &run(profile, format, wire.as_bytes(), split).unwrap(),
                &baseline,
            );
        }
        let mut n = make(profile, Limits::default());
        n.accept_request(&serde_json::to_vec(&request(profile, true)).unwrap(), at())
            .unwrap();
        n.begin_response(format).unwrap();
        for byte in wire.bytes() {
            n.push_response(&[byte], 1).unwrap();
        }
        assert!(!format!("{n:?}").contains("SECRET_MARKER"));
        equivalent(&n.finish(EndReason::Complete, at(), 2).unwrap(), &baseline);
        let mut value = response(profile);
        if profile == Profile::OpenAiResponses {
            value["output"].as_array_mut().unwrap().remove(0);
        }
        let json = run(
            profile,
            ResponseFormat::Json,
            &serde_json::to_vec(&value).unwrap(),
            0,
        )
        .unwrap();
        let a: Vec<_> = baseline
            .iter()
            .filter(|o| o.kind() != ObservationFamily::Inference)
            .collect();
        let b: Vec<_> = json
            .iter()
            .filter(|o| o.kind() != ObservationFamily::Inference)
            .collect();
        assert_eq!(a.len(), b.len());
        for (a, b) in a.iter().zip(b) {
            assert!(a.body() == b.body());
            assert_eq!(a.observation_id(), b.observation_id());
        }
        for obs in baseline {
            obs.validate().unwrap();
            assert!(!format!("{obs:?}").contains("SECRET_MARKER"));
            assert!(matches!(
                obs.semantic_comparison(),
                SemanticComparison::Unavailable
            ));
            if let ObservationBody::Inference(body) = obs.body()
                && obs.stage() == ObservationStage::InferenceCompleted
            {
                let mut expected = InferenceMetrics::default()
                    .with_input_tokens(7)
                    .with_output_tokens(9);
                if profile == Profile::OllamaChat {
                    expected = expected.with_duration_ms(12);
                }
                assert_eq!(body.metrics(), &expected);
            }
        }
    }
}
#[test]
fn all_profiles_isolate_installations_and_keep_results_unjoined() {
    let mut results = Vec::new();
    for profile in PROFILES.into_iter().chain([Profile::OpenAiChat]) {
        let mut req = request(profile, false);
        match profile {
            Profile::AnthropicMessages => {
                req["messages"] = json!([{"role":"user","content":[{"type":"tool_result","content":"SECRET_MARKER"}]}])
            }
            Profile::OpenAiResponses => {
                req["input"] = json!([{"type":"function_call_output","output":"SECRET_MARKER"}])
            }
            Profile::OllamaChat => {
                req["messages"] =
                    json!([{"role":"tool","tool_name":"shell","content":"SECRET_MARKER"}])
            }
            Profile::OpenAiChat => {
                req["messages"] = json!([{"role":"tool","content":"SECRET_MARKER"}])
            }
        }
        let wire = serde_json::to_vec(&req).unwrap();
        let a = make(profile, Limits::default())
            .accept_request(&wire, at())
            .unwrap();
        let result = a
            .iter()
            .find(|o| o.stage() == ObservationStage::ToolResultReturned)
            .unwrap();
        assert!(result.correlation().call_id().is_none());
        results.push(result.body().clone());
        for native in [None, Some("attempt-1")] {
            let capture = |scope| {
                Normalizer::with_profile(
                    profile,
                    Identity {
                        verified_installation: Some(scope),
                        native_coordinate: native,
                        stable_sequence: Some(("capture", 1)),
                        request_id: None,
                    },
                    CapturePolicy::LocalSensitive,
                    Limits::default(),
                )
                .unwrap()
                .accept_request(&wire, at())
                .unwrap()
            };
            let a = capture("11111111111111111111111111111111");
            equivalent(&a, &capture("11111111111111111111111111111111"));
            let b = capture("22222222222222222222222222222222");
            assert!(
                a.iter()
                    .zip(b)
                    .all(|(a, b)| a.observation_id() != b.observation_id())
            );
        }
    }
    assert!(results.windows(2).all(|p| p[0] == p[1]));
}
#[test]
fn invalid_streams_never_release_a_partial_batch() {
    for profile in PROFILES {
        let (format, wire) = stream(profile);
        let mut cases = vec![
            format!("{wire}{wire}"),
            format!("{wire}SECRET_MARKER"),
            wire[..wire.len() / 2].to_owned(),
        ];
        match profile {
            Profile::AnthropicMessages => {
                cases.push(wire.replace("content_block_stop", "unknown_semantic_event"));
                cases.push(wire.replace("\"type\":\"ping\"", "\"type\":\"error\""));
                cases.push(wire.replace("\"index\":1", "\"index\":0"));
                cases.push(wire.replace("\"id\":\"call-1\",", ""));
                cases.push(wire.replace("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n", ""));
                cases.push(wire.replace("\\\"SECRET_MARKER\\\"}", "\\\"SECRET_MARKER\\\""));
            }
            Profile::OpenAiResponses => {
                cases.push(wire.replace("response.completed", "response.failed"));
                cases.push(wire.replace("response.completed", "response.incomplete"));
                cases.push(
                    wire.replace("response.function_call_arguments.delta", "response.unknown"),
                );
                cases.push(wire.replacen("\"item_id\":\"item-1\"", "\"item_id\":\"call-1\"", 1));
                cases.push(wire.replacen("\"output_index\":0", "\"output_index\":1", 1));
                cases.push(wire.replacen("\"sequence_number\":3", "\"sequence_number\":2", 1));
                cases.push(wire.replacen("\"call_id\":\"call-1\"", "\"call_id\":\"wrong\"", 1));
            }
            Profile::OllamaChat => {
                cases.push(wire.replace("\"done\":true", "\"done\":false"));
                cases.push(wire.replace("12000000", "-1"));
                cases.push(wire.replace("12000000", "1.5"));
                cases.push(wire.replace(
                    "\"total_duration\":",
                    "\"duration_unit\":\"seconds\",\"total_duration\":",
                ));
                cases.push(wire.replace(
                    "\"content\":\"SECRET_MARKER\"",
                    "\"thinking\":\"SECRET_MARKER\",\"content\":\"\"",
                ));
            }
            _ => unreachable!(),
        }
        for invalid in cases {
            for split in [0, invalid.len() / 2, invalid.len()] {
                let error = run(profile, format, invalid.as_bytes(), split).unwrap_err();
                assert!(!format!("{error:?} {error}").contains("SECRET_MARKER"));
            }
        }
        for reason in [
            EndReason::Eof,
            EndReason::Cancelled,
            EndReason::Timeout,
            EndReason::TransportFailure,
            EndReason::UpstreamError,
        ] {
            let mut n = make(profile, Limits::default());
            n.accept_request(&serde_json::to_vec(&request(profile, true)).unwrap(), at())
                .unwrap();
            n.begin_response(format).unwrap();
            n.push_response(wire.as_bytes(), 1).unwrap();
            assert!(n.finish(reason, at(), 2).is_err());
        }
    }
}
#[test]
fn profile_specific_identity_error_and_duration_contracts() {
    let mut req = request(Profile::OpenAiResponses, false);
    req["previous_response_id"] = json!("prior-secret");
    assert_eq!(
        make(Profile::OpenAiResponses, Limits::default())
            .accept_request(&serde_json::to_vec(&req).unwrap(), at())
            .unwrap_err(),
        Failure::Unsupported
    );
    let mut req = request(Profile::AnthropicMessages, false);
    req["messages"] = json!([{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-1","content":"failed","is_error":true}]}]);
    let result = make(Profile::AnthropicMessages, Limits::default())
        .accept_request(&serde_json::to_vec(&req).unwrap(), at())
        .unwrap();
    let result = result
        .iter()
        .find(|o| o.stage() == ObservationStage::ToolResultReturned)
        .unwrap();
    assert_eq!(result.correlation().call_id().unwrap().value(), "call-1");
    if let ObservationBody::Tool(body) = result.body() {
        assert_eq!(body.is_error(), Some(true));
    } else {
        panic!("wrong family");
    }
    let r = response(Profile::OpenAiResponses);
    let output = run(
        Profile::OpenAiResponses,
        ResponseFormat::Json,
        &serde_json::to_vec(&r).unwrap(),
        0,
    )
    .unwrap();
    let proposal = output
        .iter()
        .find(|o| o.stage() == ObservationStage::ToolProposed)
        .unwrap();
    assert!(
        proposal.correlation()
            == &CorrelationIds::new()
                .with_response_id(CorrelationId::source_reported("response-1").unwrap())
                .with_call_id(CorrelationId::source_reported("call-1").unwrap())
    );
    assert_eq!(proposal.correlation().call_id().unwrap().value(), "call-1");
    assert!(proposal.local().is_some());
    for status in ["failed", "incomplete", "in_progress"] {
        let mut r = r.clone();
        r["status"] = json!(status);
        assert!(
            run(
                Profile::OpenAiResponses,
                ResponseFormat::Json,
                &serde_json::to_vec(&r).unwrap(),
                0
            )
            .is_err()
        );
    }
    for ns in [0, 999999, 1000000, u64::MAX] {
        let mut r = response(Profile::OllamaChat);
        r["total_duration"] = json!(ns);
        let batch = run(
            Profile::OllamaChat,
            ResponseFormat::Json,
            &serde_json::to_vec(&r).unwrap(),
            0,
        )
        .unwrap();
        if let ObservationBody::Inference(body) = batch.last().unwrap().body() {
            assert_eq!(
                body.metrics(),
                &InferenceMetrics::default()
                    .with_input_tokens(7)
                    .with_output_tokens(9)
                    .with_duration_ms(ns / 1_000_000)
            );
        }
    }
}
#[test]
fn ndjson_limits_include_unterminated_final_line() {
    let req = serde_json::to_vec(&request(Profile::OllamaChat, true)).unwrap();
    for frames in [2, 3] {
        let mut n = make(
            Profile::OllamaChat,
            Limits {
                frames,
                ..Limits::default()
            },
        );
        n.accept_request(&req, at()).unwrap();
        n.begin_response(ResponseFormat::Ndjson).unwrap();
        let wire = stream(Profile::OllamaChat).1.trim_end();
        assert_eq!(n.push_response(wire.as_bytes(), 1).is_ok(), frames == 3);
        if frames == 2 {
            assert_eq!(n.buffered_bytes(), 0);
        } else {
            assert!(n.finish(EndReason::Complete, at(), 2).is_ok());
        }
    }
}

#[test]
fn responses_text_requires_each_native_closure_and_exact_snapshot() {
    let part = json!({"type":"output_text","text":"","annotations":[]});
    let final_part = json!({"type":"output_text","text":"hé SECRET_MARKER","annotations":[]});
    let item = json!({"type":"message","id":"msg-1","role":"assistant","status":"in_progress","content":[]});
    let final_item = json!({"type":"message","id":"msg-1","role":"assistant","status":"completed","content":[final_part]});
    let events = vec![
        json!({"type":"response.created","response":{"id":"resp-1","object":"response","model":"resolved","status":"in_progress","output":[]}}),
        json!({"type":"response.output_item.added","output_index":0,"item":item}),
        json!({"type":"response.content_part.added","output_index":0,"item_id":"msg-1","content_index":0,"part":part}),
        json!({"type":"response.output_text.delta","output_index":0,"item_id":"msg-1","content_index":0,"delta":"hé SECRET_MARKER"}),
        json!({"type":"response.output_text.done","output_index":0,"item_id":"msg-1","content_index":0,"text":"hé SECRET_MARKER"}),
        json!({"type":"response.content_part.done","output_index":0,"item_id":"msg-1","content_index":0,"part":final_part}),
        json!({"type":"response.output_item.done","output_index":0,"item":final_item}),
        json!({"type":"response.completed","response":{"id":"resp-1","object":"response","model":"resolved","status":"completed","output":[final_item]}}),
    ];
    let wire = |events: &[Value]| {
        events
            .iter()
            .map(|v| {
                format!(
                    "event: {}\r\ndata: {v}\r\n\r\n",
                    v["type"].as_str().unwrap()
                )
            })
            .collect::<String>()
    };
    let bytes = wire(&events);
    let baseline = run(
        Profile::OpenAiResponses,
        ResponseFormat::Sse,
        bytes.as_bytes(),
        0,
    )
    .unwrap();
    for split in 0..=bytes.len() {
        equivalent(
            &run(
                Profile::OpenAiResponses,
                ResponseFormat::Sse,
                bytes.as_bytes(),
                split,
            )
            .unwrap(),
            &baseline,
        );
    }
    for remove in 0..events.len() {
        let mut invalid = events.clone();
        invalid.remove(remove);
        assert!(
            run(
                Profile::OpenAiResponses,
                ResponseFormat::Sse,
                wire(&invalid).as_bytes(),
                0
            )
            .is_err()
        );
    }
    let mut invalid = events.clone();
    invalid[7]["response"]["output"][0]["content"][0]["text"] = json!("conflict");
    assert!(
        run(
            Profile::OpenAiResponses,
            ResponseFormat::Sse,
            wire(&invalid).as_bytes(),
            0
        )
        .is_err()
    );
}

#[test]
fn definitions_unsupported_content_and_tight_limits_are_explicit() {
    for profile in PROFILES {
        let mut req = request(profile, false);
        req["tools"] = match profile {
            Profile::AnthropicMessages => {
                json!([{"name":"shell","description":"SECRET_MARKER","input_schema":{"type":"object"}}])
            }
            Profile::OpenAiResponses => {
                json!([{"type":"function","name":"shell","description":"SECRET_MARKER","parameters":{"type":"object"}}])
            }
            _ => {
                json!([{"type":"function","function":{"name":"shell","description":"SECRET_MARKER","parameters":{"type":"object"}}}])
            }
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let batch = make(profile, Limits::default())
            .accept_request(&bytes, at())
            .unwrap();
        let definition = batch
            .iter()
            .find(|o| o.stage() == ObservationStage::DefinitionChanged)
            .unwrap();
        assert!(definition.local().is_some());
        assert!(!format!("{batch:?}").contains("SECRET_MARKER"));
        assert_eq!(
            make(
                profile,
                Limits {
                    items: 1,
                    ..Limits::default()
                }
            )
            .accept_request(&bytes, at())
            .unwrap_err(),
            Failure::Capacity
        );
        let mut value = response(profile);
        match profile {
            Profile::AnthropicMessages => {
                value["content"][0] = json!({"type":"thinking","thinking":"SECRET_MARKER"})
            }
            Profile::OpenAiResponses => {
                value["output"][0] =
                    json!({"type":"web_search_call","id":"search-1","status":"completed"})
            }
            _ => value["message"]["thinking"] = json!("SECRET_MARKER"),
        }
        assert_eq!(
            run(
                profile,
                ResponseFormat::Json,
                &serde_json::to_vec(&value).unwrap(),
                0
            )
            .unwrap_err(),
            Failure::Unsupported
        );
        let (format, wire) = stream(profile);
        let mut n = make(
            profile,
            Limits {
                response_bytes: wire.len() - 1,
                ..Limits::default()
            },
        );
        n.accept_request(&serde_json::to_vec(&request(profile, true)).unwrap(), at())
            .unwrap();
        n.begin_response(format).unwrap();
        assert_eq!(n.push_response(wire.as_bytes(), 1), Err(Failure::Capacity));
        assert_eq!(n.buffered_bytes(), 0);
    }
}
