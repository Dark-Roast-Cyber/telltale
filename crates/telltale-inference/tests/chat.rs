use serde_json::Value;
use telltale_inference::*;
use telltale_schema::observation::*;

const REQUEST: &[u8] = br#"{"model":"requested","stream":true,"messages":[{"role":"user","content":"SECRET_MARKER"}]}"#;
const SSE: &str = "data: {\"id\":\"response-1\",\"model\":\"resolved\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hé SECRET_MARKER\"},\"finish_reason\":null}]}\r\n\r\ndata: {\"id\":\"response-1\",\"model\":\"resolved\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n";
fn at() -> ObservedAt {
    ObservedAt::new("2026-10-01T00:00:00Z").unwrap()
}
fn normalizer(scope: &str, native: Option<&str>, sequence: u64, limits: Limits) -> Normalizer {
    Normalizer::new(
        Identity {
            verified_installation: Some(scope),
            native_coordinate: native,
            stable_sequence: Some(("capture", sequence)),
            request_id: Some("request-1"),
        },
        CapturePolicy::LocalSensitive,
        limits,
    )
    .unwrap()
}
fn ready(limits: Limits) -> Normalizer {
    let mut n = normalizer(
        "11111111111111111111111111111111",
        Some("attempt-1"),
        1,
        limits,
    );
    let batch = n.accept_request(REQUEST, at()).unwrap();
    assert!(!batch.is_empty());
    n.begin_response(ResponseFormat::Sse).unwrap();
    n
}
fn run(bytes: &[u8], split: usize) -> Result<Vec<CanonicalObservationV2>, Failure> {
    let mut n = ready(Limits::default());
    n.push_response(&bytes[..split], 1)?;
    n.push_response(&bytes[split..], 2)?;
    n.finish(EndReason::Complete, at(), 3)
}
fn equivalent(a: &[CanonicalObservationV2], b: &[CanonicalObservationV2]) {
    assert_eq!(a.len(), b.len());
    for (a, b) in a.iter().zip(b) {
        assert_eq!(a.observation_id(), b.observation_id());
        assert!(a.body() == b.body());
        assert!(a.correlation() == b.correlation());
        assert!(a.fact_metadata() == b.fact_metadata());
        assert!(a.local() == b.local());
    }
}
#[test]
fn every_byte_rechunking_and_private_commit() {
    let baseline = run(SSE.as_bytes(), 0).unwrap();
    for split in 0..=SSE.len() {
        let actual = run(SSE.as_bytes(), split).unwrap();
        equivalent(&actual, &baseline);
    }
    let mut n = ready(Limits::default());
    for byte in SSE.as_bytes() {
        n.push_response(&[*byte], 1).unwrap();
    }
    equivalent(&n.finish(EndReason::Complete, at(), 2).unwrap(), &baseline);
    for obs in baseline {
        obs.validate().unwrap();
        assert!(!format!("{obs:?}").contains("SECRET_MARKER"));
        assert!(matches!(
            obs.semantic_comparison(),
            SemanticComparison::Unavailable
        ));
    }
}
#[test]
fn trailing_conflict_is_chunk_independent() {
    for tail in [
        "data: [DONE]\n\n",
        "data: {\"error\":\"SECRET_MARKER\"}\n\n",
        "garbage",
    ] {
        let invalid = format!("{SSE}{tail}");
        for split in 0..=invalid.len() {
            assert!(run(invalid.as_bytes(), split).is_err());
        }
    }
}
#[test]
fn failures_discard_response_and_hide_secrets() {
    for reason in [
        EndReason::Eof,
        EndReason::Cancelled,
        EndReason::UpstreamError,
        EndReason::TransportFailure,
        EndReason::Timeout,
    ] {
        let mut n = ready(Limits::default());
        n.push_response(SSE.as_bytes(), 1).unwrap();
        assert!(!format!("{n:?}").contains("SECRET_MARKER"));
        let err = n.finish(reason, at(), 2).unwrap_err();
        assert!(!format!("{err:?} {err}").contains("SECRET_MARKER"));
    }
    let mut n = ready(Limits::default());
    assert_eq!(n.push_response(&[], 30_001), Err(Failure::Timeout));
    assert_eq!(n.buffered_bytes(), 0);
    assert!(n.finish(EndReason::Complete, at(), 30_002).is_err());
}

const RICH_REQUEST: &[u8] = include_bytes!("fixtures/request.json");
const RICH_JSON: &[u8] = include_bytes!("fixtures/response.json");
const RICH_SSE: &[u8] = include_bytes!("fixtures/response.sse");
fn rich(
    format: ResponseFormat,
    bytes: &[u8],
    split: usize,
) -> Result<Vec<CanonicalObservationV2>, Failure> {
    let mut n = normalizer(
        "11111111111111111111111111111111",
        Some("attempt-1"),
        1,
        Limits::default(),
    );
    let request = String::from_utf8(RICH_REQUEST.to_vec()).unwrap().replace(
        "\"stream\":false",
        if format == ResponseFormat::Sse {
            "\"stream\":true"
        } else {
            "\"stream\":false"
        },
    );
    n.accept_request(request.as_bytes(), at())?;
    n.begin_response(format)?;
    n.push_response(&bytes[..split], 1)?;
    n.push_response(&bytes[split..], 2)?;
    n.finish(EndReason::Complete, at(), 3)
}
#[test]
fn rich_fixtures_every_byte_and_history() {
    let json = rich(ResponseFormat::Json, RICH_JSON, 0).unwrap();
    let sse = rich(ResponseFormat::Sse, RICH_SSE, 0).unwrap();
    for (a, b) in json.iter().zip(&sse) {
        assert_eq!(a.observation_id(), b.observation_id());
        if a.kind() != ObservationFamily::Inference {
            assert!(a.body() == b.body());
        }
    }
    for (format, wire) in [
        (ResponseFormat::Json, RICH_JSON),
        (ResponseFormat::Sse, RICH_SSE),
    ] {
        let baseline = rich(format, wire, 0).unwrap();
        for split in 0..=wire.len() {
            equivalent(&rich(format, wire, split).unwrap(), &baseline);
        }
        let tools: Vec<_> = baseline
            .iter()
            .filter(|o| o.stage() == ObservationStage::ToolProposed)
            .collect();
        assert_eq!(tools.len(), 3);
        assert_eq!(
            tools
                .iter()
                .filter(|o| o.correlation().call_id().is_none())
                .count(),
            1
        );
        for obs in &baseline {
            obs.validate().unwrap();
            assert!(
                obs.session_id().is_none()
                    && obs.workflow_id().is_none()
                    && obs.occurred_at().is_none()
            );
            assert_eq!(
                obs.capability_context()
                    .unwrap()
                    .resolve(CapabilityId::ToolExecution),
                CapabilityAvailability::Unsupported
            );
            assert!(!format!("{obs:?}").contains("SECRET_MARKER"));
            if let ObservationBody::Inference(body) = obs.body() {
                assert_eq!(body.requested_model(), Some("requested"));
                assert_eq!(body.resolved_model(), Some("resolved"));
                assert!(body.provider().is_none());
            }
        }
    }
    let mut n = normalizer(
        "11111111111111111111111111111111",
        Some("attempt-1"),
        1,
        Limits::default(),
    );
    let observations = n.accept_request(RICH_REQUEST, at()).unwrap();
    let results: Vec<_> = observations
        .iter()
        .filter(|o| o.stage() == ObservationStage::ToolResultReturned)
        .collect();
    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0].correlation().call_id().unwrap().value(),
        "history-call"
    );
    assert!(results[1].correlation().call_id().is_none());
    assert!(
        observations
            .iter()
            .any(|o| o.stage() == ObservationStage::DefinitionChanged && o.local().is_some())
    );
    for obs in observations {
        obs.validate().unwrap();
        assert!(matches!(
            obs.semantic_comparison(),
            SemanticComparison::Unavailable
        ));
        assert!(
            obs.fact_metadata()
                .values()
                .all(|m| m.sensitivity() == Sensitivity::Sensitive)
        );
        assert!(!format!("{obs:?}").contains("SECRET_MARKER"));
    }
}
#[test]
fn installation_isolation_replay_retry_and_content_changes() {
    for native in [None, Some("attempt-1")] {
        let capture = |scope, seq, time: &str, request: &[u8]| {
            let mut n = normalizer(scope, native, seq, Limits::default());
            n.accept_request(request, ObservedAt::new(time).unwrap())
                .unwrap()
        };
        let a = capture(
            "11111111111111111111111111111111",
            1,
            "2026-10-01T00:00:00Z",
            REQUEST,
        );
        let replay = capture(
            "11111111111111111111111111111111",
            1,
            "2026-10-02T00:00:00Z",
            REQUEST,
        );
        equivalent(&a, &replay);
        let b = capture(
            "22222222222222222222222222222222",
            1,
            "2026-10-01T00:00:00Z",
            REQUEST,
        );
        assert!(
            a.iter()
                .zip(&b)
                .all(|(a, b)| a.observation_id() != b.observation_id())
        );
        assert_eq!(
            a[0].source().adapter_id(),
            "inference.boundary:installation:11111111111111111111111111111111"
        );
        let changed = capture(
            "11111111111111111111111111111111",
            1,
            "2026-10-01T00:00:00Z",
            &String::from_utf8(REQUEST.to_vec())
                .unwrap()
                .replace("SECRET_MARKER", "changed")
                .into_bytes(),
        );
        assert!(
            a.iter()
                .zip(changed)
                .all(|(a, b)| a.observation_id() == b.observation_id())
        );
        let mut retry = normalizer(
            "11111111111111111111111111111111",
            native.map(|_| "attempt-2"),
            2,
            Limits::default(),
        );
        let retry = retry.accept_request(REQUEST, at()).unwrap();
        assert!(
            a.iter()
                .zip(retry)
                .all(|(a, b)| a.observation_id() != b.observation_id())
        );
    }
    for identity in [
        Identity {
            verified_installation: None,
            native_coordinate: Some("a"),
            stable_sequence: None,
            request_id: None,
        },
        Identity {
            verified_installation: Some("11111111111111111111111111111111"),
            native_coordinate: None,
            stable_sequence: None,
            request_id: None,
        },
        Identity {
            verified_installation: Some("INVALID"),
            native_coordinate: Some("a"),
            stable_sequence: None,
            request_id: None,
        },
        Identity {
            verified_installation: Some("11111111111111111111111111111111"),
            native_coordinate: Some("path/a"),
            stable_sequence: None,
            request_id: None,
        },
    ] {
        assert_eq!(
            Normalizer::new(identity, CapturePolicy::LocalSensitive, Limits::default())
                .unwrap_err(),
            Failure::ReplayUnverifiable
        );
    }
}
#[test]
fn malformed_conflicting_and_unknown_streams_fail_atomically() {
    let wire = std::str::from_utf8(RICH_SSE).unwrap();
    let invalid = [
        wire.replace("[DONE]", "[UNKNOWN]"),
        wire.replace("data: [DONE]\n\n", ""),
        wire.replacen("\"index\":2", "\"index\":0", 1),
        wire.replacen("\"model\":\"resolved\"", "\"model\":\"different\"", 1),
        wire.replacen("\"id\":\"response-2\"", "\"id\":\"different\"", 1),
        wire.replace(
            "\"finish_reason\":\"tool_calls\"",
            "\"finish_reason\":\"mystery\"",
        ),
        wire.replacen("\"arguments\":\"{\"", "\"arguments\":\"[\"", 1),
        wire.replace("\"role\":\"assistant\"", "\"role\":\"tool\""),
        wire.replace("\"delta\":{", "\"delta\":{\"opaque\":\"SECRET_MARKER\","),
    ];
    for bytes in invalid {
        for split in 0..=bytes.len() {
            assert!(rich(ResponseFormat::Sse, bytes.as_bytes(), split).is_err());
        }
    }
    for bytes in [b"{bad SECRET_MARKER".as_slice(),br#"{"model":"a","model":"b","messages":[]}"#,
        br#"{"model":"a","messages":[{"role":"user","content":[{"type":"image_url","image_url":"SECRET_MARKER"}]}]}"#] {
        let mut n = normalizer("11111111111111111111111111111111",Some("a"),1,Limits::default());
        assert!(n.accept_request(bytes,at()).is_err());
        assert!(n.accept_request(REQUEST,at()).is_err());
        assert!(!format!("{n:?}").contains("SECRET_MARKER"));
    }
}

fn request_with(limits: Limits, bytes: &[u8]) -> Result<Vec<CanonicalObservationV2>, Failure> {
    normalizer("11111111111111111111111111111111", Some("a"), 1, limits).accept_request(bytes, at())
}
#[test]
fn exact_and_plus_one_bounds() {
    assert!(
        request_with(
            Limits {
                request_bytes: REQUEST.len(),
                ..Limits::default()
            },
            REQUEST
        )
        .is_ok()
    );
    assert_eq!(
        request_with(
            Limits {
                request_bytes: REQUEST.len() - 1,
                ..Limits::default()
            },
            REQUEST
        )
        .unwrap_err(),
        Failure::Capacity
    );
    assert!(
        request_with(
            Limits {
                items: 1,
                output_observations: 2,
                ..Limits::default()
            },
            REQUEST
        )
        .is_ok()
    );
    assert_eq!(
        request_with(
            Limits {
                output_observations: 1,
                ..Limits::default()
            },
            REQUEST
        )
        .unwrap_err(),
        Failure::Capacity
    );
    let two = br#"{"model":"a","messages":[{"role":"user","content":"a"},{"role":"user","content":"b"}]}"#;
    assert!(
        request_with(
            Limits {
                items: 2,
                ..Limits::default()
            },
            two
        )
        .is_ok()
    );
    assert_eq!(
        request_with(
            Limits {
                items: 1,
                ..Limits::default()
            },
            two
        )
        .unwrap_err(),
        Failure::Capacity
    );
    assert!(
        request_with(
            Limits {
                json_array_items: 2,
                ..Limits::default()
            },
            two
        )
        .is_ok()
    );
    assert_eq!(
        request_with(
            Limits {
                json_array_items: 1,
                ..Limits::default()
            },
            two
        )
        .unwrap_err(),
        Failure::Capacity
    );
    assert!(
        request_with(
            Limits {
                json_members: 3,
                ..Limits::default()
            },
            REQUEST
        )
        .is_ok()
    );
    assert_eq!(
        request_with(
            Limits {
                json_members: 2,
                ..Limits::default()
            },
            REQUEST
        )
        .unwrap_err(),
        Failure::Capacity
    );
    assert!(
        request_with(
            Limits {
                json_depth: 4,
                ..Limits::default()
            },
            REQUEST
        )
        .is_ok()
    );
    assert_eq!(
        request_with(
            Limits {
                json_depth: 3,
                ..Limits::default()
            },
            REQUEST
        )
        .unwrap_err(),
        Failure::Capacity
    );
    for length in [4096, 4097] {
        let value = serde_json::json!({"model":"a","messages":[{"role":"user","content":"x".repeat(length)}]});
        assert_eq!(
            request_with(Limits::default(), value.to_string().as_bytes()).is_ok(),
            length == 4096
        );
    }
    for cap in [SSE.len(), SSE.len() - 1] {
        let mut n = ready(Limits {
            response_bytes: cap,
            ..Limits::default()
        });
        let result = n.push_response(SSE.as_bytes(), 1);
        assert_eq!(result.is_ok(), cap == SSE.len());
        assert!(n.buffered_bytes() <= cap);
        if result.is_err() {
            assert_eq!(n.buffered_bytes(), 0);
        }
    }
    let largest_frame = SSE.find("\r\n\r\n").unwrap() + 4;
    for cap in [largest_frame, largest_frame - 1] {
        let mut n = ready(Limits {
            frame_bytes: cap,
            ..Limits::default()
        });
        assert_eq!(
            n.push_response(SSE.as_bytes(), 1).is_ok(),
            cap == largest_frame
        );
    }
    for cap in [3, 2] {
        let mut n = ready(Limits {
            frames: cap,
            ..Limits::default()
        });
        assert_eq!(n.push_response(SSE.as_bytes(), 1).is_ok(), cap == 3);
    }
    let identity = Identity {
        verified_installation: Some("11111111111111111111111111111111"),
        native_coordinate: Some("a"),
        stable_sequence: None,
        request_id: None,
    };
    assert_eq!(
        Normalizer::new(
            identity,
            CapturePolicy::LocalSensitive,
            Limits {
                response_bytes: usize::MAX,
                ..Limits::default()
            }
        )
        .unwrap_err(),
        Failure::Capacity
    );
}
#[test]
fn deadlines_and_invalid_state_are_terminal() {
    let mut n = ready(Limits::default());
    n.push_response(&[], 30_000).unwrap();
    assert_eq!(n.push_response(&[], 30_001), Err(Failure::Timeout));
    assert_eq!(
        n.push_response(SSE.as_bytes(), 30_001),
        Err(Failure::InvalidState)
    );
    let mut n = ready(Limits {
        total_ms: 10,
        idle_ms: 10,
        ..Limits::default()
    });
    n.push_response(SSE.as_bytes(), 10).unwrap();
    assert_eq!(
        n.finish(EndReason::Complete, at(), 11).unwrap_err(),
        Failure::Timeout
    );
    let mut n = ready(Limits::default());
    n.push_response(&[], 2).unwrap();
    assert_eq!(n.push_response(&[], 1), Err(Failure::InvalidState));
    let identity = Identity {
        verified_installation: Some("11111111111111111111111111111111"),
        native_coordinate: Some("SECRET_MARKER"),
        stable_sequence: None,
        request_id: None,
    };
    assert!(!format!("{identity:?}").contains("SECRET_MARKER"));
    assert_eq!(
        Normalizer::new(identity, CapturePolicy::Disabled, Limits::default()).unwrap_err(),
        Failure::CaptureDisabled
    );
}

#[test]
fn response_schema_limits_usage_and_conflicts() {
    let response = |arguments: Value| {
        serde_json::json!({"model":"resolved","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"type":"function","function":{"name":"f","arguments":arguments.to_string()}}]},"finish_reason":"tool_calls"}]}).to_string()
    };
    for size in [64, 65] {
        let bytes = response(serde_json::json!({"array":vec![0;size]}));
        assert_eq!(
            rich(ResponseFormat::Json, bytes.as_bytes(), 0).is_ok(),
            size == 64
        );
    }
    for size in [32, 33] {
        let mut object = serde_json::Map::new();
        for i in 0..size {
            object.insert(format!("k{i}"), serde_json::json!(0));
        }
        let bytes = response(Value::Object(object));
        assert_eq!(
            rich(ResponseFormat::Json, bytes.as_bytes(), 0).is_ok(),
            size == 32
        );
    }
    for depth in [6, 7] {
        let mut value = serde_json::json!(0);
        for _ in 1..depth {
            value = serde_json::json!({"a":value});
        }
        let bytes = response(value);
        assert_eq!(
            rich(ResponseFormat::Json, bytes.as_bytes(), 0).is_ok(),
            depth == 6
        );
    }
    for cap in [3, 2] {
        let mut n = ready(Limits {
            output_observations: cap,
            ..Limits::default()
        });
        n.push_response(SSE.as_bytes(), 1).unwrap();
        assert_eq!(n.finish(EndReason::Complete, at(), 2).is_ok(), cap == 3);
    }
    for cap in [5, 4] {
        let mut n = ready(Limits {
            items: cap,
            ..Limits::default()
        });
        n.push_response(RICH_SSE, 1).unwrap();
        assert_eq!(n.finish(EndReason::Complete, at(), 2).is_ok(), cap == 5);
    }
    let baseline = run(SSE.as_bytes(), 0).unwrap();
    for obs in baseline {
        if let ObservationBody::Inference(body) = obs.body() {
            assert!(*body.metrics() == InferenceMetrics::default());
        }
    }
    let original = std::str::from_utf8(RICH_JSON).unwrap();
    for invalid in [
        original.replacen(
            "\"finish_reason\":\"tool_calls\"",
            "\"finish_reason\":\"length\"",
            1,
        ),
        original.replace("\"call-0\"", "\"call-2\""),
        original.replace("\"prompt_tokens\":12", "\"prompt_tokens\":-1"),
        original.replace("\"arguments\":\"{}\"", "\"arguments\":\"{\""),
        original.replace("\"function\"", "\"custom\""),
        format!("{original} {{}}"),
    ] {
        assert!(rich(ResponseFormat::Json, invalid.as_bytes(), 0).is_err());
    }
    let bytes = SSE.replace("\"stop\"", "\"length\"");
    assert!(run(bytes.as_bytes(), 0).is_ok());
    let mut n = ready(Limits::default());
    assert_eq!(n.push_response(&[], u64::MAX), Err(Failure::Timeout));
}

#[test]
fn semantic_secrets_never_reach_allowed_diagnostics() {
    let mut n = normalizer(
        "11111111111111111111111111111111",
        Some("a"),
        1,
        Limits::default(),
    );
    let request = br#"{"model":"SECRET_MARKER","stream":false,"messages":[{"role":"assistant","content":"SECRET_MARKER","tool_calls":[{"id":"SECRET_MARKER","type":"function","function":{"name":"SECRET_MARKER","arguments":"{\"value\":\"SECRET_MARKER\"}"}}]}]}"#;
    let request = n.accept_request(request, at()).unwrap();
    assert!(!format!("{n:?} {request:?}").contains("SECRET_MARKER"));
    n.begin_response(ResponseFormat::Json).unwrap();
    let response = std::str::from_utf8(RICH_JSON)
        .unwrap()
        .replace("resolved", "SECRET_MARKER")
        .replace("response-2", "SECRET_MARKER");
    n.push_response(response.as_bytes(), 1).unwrap();
    assert!(!format!("{n:?}").contains("SECRET_MARKER"));
    let observations = n.finish(EndReason::Complete, at(), 2).unwrap();
    assert!(!format!("{observations:?}").contains("SECRET_MARKER"));
    for failure in [
        Failure::ReplayUnverifiable,
        Failure::Capacity,
        Failure::Malformed,
        Failure::Unsupported,
        Failure::Conflict,
        Failure::Incomplete,
        Failure::Cancelled,
        Failure::UpstreamError,
        Failure::TransportFailure,
        Failure::Timeout,
        Failure::InvalidState,
        Failure::CaptureDisabled,
        Failure::Schema,
    ] {
        assert!(!format!("{failure:?} {failure}").contains("SECRET_MARKER"));
    }
}
