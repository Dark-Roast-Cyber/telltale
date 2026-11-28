use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::{SplunkHecConfig, SplunkHecHttpSink, hec_url, splunk_hec_envelopes};
use crate::sink::emit_events;
use crate::sink::test_support::{make_health_event, read_mock_request};

#[test]
fn mock_request_reader_handles_nonblocking_socket_and_fragmented_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    // Reproduce platforms that inherit the listener's nonblocking mode.
    server.set_nonblocking(true).unwrap();
    client
        .write_all(b"POST / HTTP/1.1\r\nContent-Length: 4\r\n")
        .unwrap();
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        client.write_all(b"\r\nab").unwrap();
        thread::sleep(Duration::from_millis(50));
        client.write_all(b"cd").unwrap();
    });
    let request = read_mock_request(&mut server);
    writer.join().unwrap();
    assert_eq!(request, b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd");
}

fn mock_responses(responses: Vec<(u16, String)>) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("synthetic listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for (status, body) in responses {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "missing synthetic request");
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => panic!("synthetic accept failed"),
                }
            };
            requests.push(read_mock_request(&mut stream));
            if status == 0 {
                // Synthetic peer disconnect after receiving the request.
                continue;
            }
            write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("synthetic response");
        }
        requests
    });
    (format!("http://{address}/services/collector"), handle)
}

fn fast_sink(url: String, attempts: u32) -> SplunkHecHttpSink {
    SplunkHecHttpSink::new(url, "synthetic-token".into(), SplunkHecConfig::default())
        .with_transport_warning(
            Duration::from_secs(2),
            crate::sink::http::RetryConfig {
                max_attempts: attempts,
                base_delay_ms: 1,
            },
            &crate::sink::http::TlsOptions::default(),
            super::DEFAULT_HEC_MAX_BATCH_BYTES,
            false,
        )
        .unwrap()
}

fn response_cases() -> Vec<(String, Option<&'static str>)> {
    let mut cases = vec![(r#"{"code":0,"text":"TT_PRIVATE_RESPONSE"}"#.into(), None)];
    for code in 1..=27 {
        let class = match code {
            1..=4 | 21..=22 => "authentication_blocked",
            5..=7 | 10..=16 => "sink_application_rejected",
            _ => "sink_application_retryable",
        };
        cases.push((
            format!(r#"{{"code":{code},"text":"TT_PRIVATE_RESPONSE"}}"#),
            Some(class),
        ));
    }
    for body in [
        r#"{"code":999,"text":"TT_PRIVATE_RESPONSE"}"#,
        r#"{"text":"TT_PRIVATE_RESPONSE"}"#,
        "TT_PRIVATE_RESPONSE",
        "",
        "[]",
        "null",
        r#"{"code":"0"}"#,
        r#"{"code":0.0}"#,
        r#"{"code":false}"#,
    ] {
        cases.push((body.into(), Some("sink_response_blocked")));
    }
    cases
}

#[test]
fn hec_response_contract_for_single_batch_and_canonical() {
    use crate::sink::{DeliveryError, EventSink};
    for (body, expected) in response_cases() {
        for mode in 0..3 {
            let (url, server) = mock_responses(vec![(200, body.clone())]);
            let sink = fast_sink(url, 1);
            let event = make_health_event();
            let result = match mode {
                0 => sink.emit(std::slice::from_ref(&event)),
                1 => sink.emit(&[event.clone(), event.clone()]),
                _ => sink.emit_canonical_once(&serde_json::to_vec(&event.emittable()).unwrap()),
            };
            assert_eq!(server.join().unwrap().len(), 1);
            if let Some(class) = expected {
                let error = result.expect_err("HEC response must not be accepted");
                let delivery = error
                    .downcast_ref::<DeliveryError>()
                    .expect("structured error");
                assert_eq!(delivery.class.as_str(), class);
                assert_eq!(delivery.attempts, 1);
                assert!(!format!("{error:?} {error}").contains("TT_PRIVATE_RESPONSE"));
            } else {
                result.expect("HEC code zero accepted");
            }
        }
    }
}

#[test]
fn hec_preserves_retryable_response_when_later_attempt_disconnects() {
    use crate::sink::{DeliveryError, DeliveryErrorClass, EventSink};
    for (status, body, expected) in [
        (
            503,
            "TT_PRIVATE_RESPONSE",
            DeliveryErrorClass::HttpStatus { status: 503 },
        ),
        (
            200,
            r#"{"code":9,"text":"TT_PRIVATE_RESPONSE"}"#,
            DeliveryErrorClass::SinkApplicationRetryable,
        ),
    ] {
        let (url, server) = mock_responses(vec![(status, body.into()), (0, String::new())]);
        let error = fast_sink(url, 2).emit(&[make_health_event()]).unwrap_err();
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        let delivery = error.downcast_ref::<DeliveryError>().unwrap();
        assert_eq!(delivery.class, expected);
        assert_eq!(delivery.attempts, 2);
        assert!(!format!("{error:?} {error}").contains("TT_PRIVATE_RESPONSE"));
    }
}

#[test]
fn hec_retries_share_one_bounded_attempt_budget() {
    use crate::sink::{DeliveryError, EventSink};
    for responses in [
        vec![(200, r#"{"code":9}"#), (200, r#"{"code":0}"#)],
        vec![
            (429, "TT_PRIVATE_RESPONSE"),
            (200, r#"{"code":9}"#),
            (503, "TT_PRIVATE_RESPONSE"),
        ],
        vec![(200, r#"{"code":9}"#); 3],
        vec![(401, "TT_PRIVATE_RESPONSE")],
    ] {
        let count = responses.len();
        let success = responses.last().unwrap().1 == r#"{"code":0}"#;
        let (url, server) =
            mock_responses(responses.into_iter().map(|(s, b)| (s, b.into())).collect());
        let result = fast_sink(url, 3).emit(&[make_health_event()]);
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), count);
        assert!(requests.windows(2).all(|pair| pair[0] == pair[1]));
        if success {
            result.unwrap();
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                error.downcast_ref::<DeliveryError>().unwrap().attempts,
                count as u32
            );
            assert!(!error.to_string().contains("TT_PRIVATE_RESPONSE"));
        }
    }
}

#[cfg(not(windows))]
#[test]
fn hec_durable_response_states_survive_reopen() {
    use crate::sink::{
        SinkSet,
        outbox::{CapacityLimits, DeliveryState, Outbox},
    };
    for (body, expected) in response_cases() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private/outbox.sqlite");
        let event = make_health_event();
        Outbox::open(&path)
            .unwrap()
            .insert_event(&event, &["remote"])
            .unwrap();
        let (url, server) = mock_responses(vec![(200, body)]);
        let mut sinks = SinkSet::new();
        sinks.add_best_effort_with_retry(
            "splunk_hec",
            Box::new(fast_sink(url, 3).with_name("remote")),
            crate::sink::http::RetryConfig {
                max_attempts: 3,
                base_delay_ms: 1000,
            },
        );
        sinks.enable_persistent_replay_with_capacity(
            path.clone(),
            vec!["remote".into()],
            CapacityLimits::default(),
        );
        let failures = sinks
            .dispatch_durable_with_clock(&crate::sink::outbox::SystemDeliveryClock)
            .unwrap();
        assert_eq!(server.join().unwrap().len(), 1);
        assert!(
            failures
                .iter()
                .all(|failure| !failure.error.contains("TT_PRIVATE_RESPONSE"))
        );
        let outbox = Outbox::open(&path).unwrap();
        let row = outbox
            .get_delivery(&event.event_id, "remote")
            .unwrap()
            .unwrap();
        let state = match expected {
            None => DeliveryState::Acked,
            Some("sink_application_retryable") => DeliveryState::Pending,
            Some("sink_application_rejected") => DeliveryState::Dead,
            _ => DeliveryState::Blocked,
        };
        assert_eq!(row.state, state);
        assert_eq!(row.attempts, 1);
        assert_eq!(row.last_error_class.map(|class| class.as_str()), expected);
        assert_eq!(
            row.next_attempt_at.is_some(),
            state == DeliveryState::Pending
        );
    }
}

#[cfg(not(windows))]
#[test]
fn hec_durable_retry_is_scheduled_and_bounded() {
    use crate::sink::{
        SinkSet,
        outbox::{CapacityLimits, DeliveryClock, DeliveryState, Outbox},
    };
    struct Clock(i64);
    impl DeliveryClock for Clock {
        fn now_millis(&self) -> i64 {
            self.0
        }
    }
    for final_code in [0, 9] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private/outbox.sqlite");
        let event = make_health_event();
        Outbox::open(&path)
            .unwrap()
            .insert_event(&event, &["remote"])
            .unwrap();
        let (url, server) = mock_responses(vec![
            (200, r#"{"code":9,"text":"TT_PRIVATE_RESPONSE"}"#.into()),
            (
                200,
                format!(r#"{{"code":{final_code},"text":"TT_PRIVATE_RESPONSE"}}"#),
            ),
        ]);
        let mut sinks = SinkSet::new();
        sinks.add_best_effort_with_retry(
            "splunk_hec",
            Box::new(fast_sink(url, 5).with_name("remote")),
            crate::sink::http::RetryConfig {
                max_attempts: 2,
                base_delay_ms: 10,
            },
        );
        sinks.enable_persistent_replay_with_capacity(
            path.clone(),
            vec!["remote".into()],
            CapacityLimits::default(),
        );
        let failures = sinks.dispatch_durable_with_clock(&Clock(1000)).unwrap();
        assert_eq!(failures.len(), 1);
        assert!(!failures[0].error.contains("TT_PRIVATE_RESPONSE"));
        let row = Outbox::open(&path)
            .unwrap()
            .get_delivery(&event.event_id, "remote")
            .unwrap()
            .unwrap();
        assert_eq!(row.state, DeliveryState::Pending);
        assert_eq!(row.attempts, 1);
        assert_eq!(row.next_attempt_at, Some(1010));
        assert!(
            sinks
                .dispatch_durable_with_clock(&Clock(1009))
                .unwrap()
                .is_empty()
        );
        sinks.dispatch_durable_with_clock(&Clock(1010)).unwrap();
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        let row = Outbox::open(&path)
            .unwrap()
            .get_delivery(&event.event_id, "remote")
            .unwrap()
            .unwrap();
        assert_eq!(
            row.state,
            if final_code == 0 {
                DeliveryState::Acked
            } else {
                DeliveryState::Dead
            }
        );
        assert_eq!(row.attempts, 2);
        assert_eq!(row.next_attempt_at, None);
        assert!(
            sinks
                .dispatch_durable_with_clock(&Clock(2000))
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn splunk_hec_envelope_wraps_canonical_event_with_transport_metadata() {
    let mut event = make_health_event();
    event.timestamp = "2026-05-18T02:00:00.000Z".to_string();
    let config = SplunkHecConfig {
        index: Some("telltale".to_string()),
        sourcetype: "telltale:json".to_string(),
        source: Some("telltale".to_string()),
        host: Some("developer-workstation".to_string()),
    };

    let events = vec![event];
    let envelopes = splunk_hec_envelopes(&events, &config);
    let envelope = serde_json::to_value(&envelopes[0]).expect("serialize hec envelope");

    assert_eq!(envelope["index"], "telltale");
    assert_eq!(envelope["sourcetype"], "telltale:json");
    assert_eq!(envelope["source"], "telltale");
    assert_eq!(envelope["host"], "developer-workstation");
    assert_eq!(envelope["time"], 1_779_069_600.0);
    assert_eq!(envelope["event"]["event_type"], "health");
    assert_eq!(envelope["event"]["schema_version"], "3.0");
    assert!(envelope["event"].get("index").is_none());
    assert!(envelope["event"].get("sourcetype").is_none());
}

#[test]
fn splunk_hec_http_sink_posts_batched_envelopes_to_collector() {
    let (url, handle) = mock_responses(vec![(200, r#"{"code":0}"#.into())]);

    let marker = "TT_PRIVACY_HEC_25";
    let mut first = make_health_event();
    first.timestamp = "2026-05-18T02:00:00.000Z".to_string();
    first.tags.push(format!("allowlist:{marker}"));
    first.evidence.push(crate::event::Evidence {
        field: "allowlist".to_string(),
        redacted_value: marker.to_string(),
        hash: None,
        rule_id: None,
    });
    first.evidence.push(crate::event::Evidence {
        field: "url".to_string(),
        redacted_value: format!("https://example.invalid/home/{marker}/.ssh/id_rsa?mode=view"),
        hash: None,
        rule_id: None,
    });
    let mut second = make_health_event();
    second.timestamp = "2026-05-18T02:05:00.000Z".to_string();
    let sink = SplunkHecHttpSink::new(url, "test-token".to_string(), SplunkHecConfig::default())
        .with_timeout(Duration::from_secs(2));

    emit_events(&sink, &[first, second]).expect("emit hec events");
    let requests = handle.join().expect("mock hec join");
    assert_eq!(requests.len(), 1);
    let request = String::from_utf8(requests.into_iter().next().unwrap()).expect("request");

    assert!(request.starts_with("POST /services/collector HTTP/1.1"));
    let lowercase = request.to_lowercase();
    assert!(lowercase.contains("authorization: splunk test-token"));
    let request_channel = request
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-splunk-request-channel")
                .then_some(value.trim())
        })
        .unwrap_or_else(|| panic!("request channel header missing; request:\n{request}"));
    assert!(Uuid::parse_str(request_channel.trim()).is_ok());
    assert!(lowercase.contains("content-type: application/json"));
    assert!(!request.contains(marker));
    assert!(request.contains("https://example.invalid/[sensitive-path]?mode=view"));
    // Both envelopes arrive in one newline-batched request body.
    let body = request.split_once("\r\n\r\n").expect("body split").1;
    let envelopes: Vec<serde_json::Value> = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("hec envelope"))
        .collect();
    assert_eq!(envelopes.len(), 2);
    for envelope in &envelopes {
        assert_eq!(envelope["index"], "telltale");
        assert_eq!(envelope["sourcetype"], "telltale:json");
        assert_eq!(envelope["event"]["event_type"], "health");
    }
}

#[test]
fn splunk_hec_non_success_error_excludes_response_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock hec listener");
    let addr = listener.local_addr().expect("mock hec addr");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        read_mock_request(&mut stream);
        stream
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 29\r\nConnection: close\r\n\r\ncredential-marker=do-not-leak",
                )
                .expect("respond");
    });
    let sink = SplunkHecHttpSink::new(
        format!("http://{addr}/services/collector"),
        "test-token".to_string(),
        SplunkHecConfig::default(),
    )
    .with_timeout(Duration::from_secs(2));

    let error = emit_events(&sink, &[make_health_event()]).expect_err("HTTP failure");
    handle.join().expect("mock hec join");
    let delivery = error
        .downcast_ref::<crate::sink::DeliveryError>()
        .expect("structured delivery error");
    assert_eq!(
        delivery.class,
        crate::sink::DeliveryErrorClass::AuthenticationBlocked { status: 403 }
    );
    assert_eq!(delivery.attempts, 1);
    let message = error.to_string();
    assert!(message.contains("HTTP 403"), "message: {message}");
    assert!(!message.contains("credential-marker"), "message: {message}");
}

#[test]
fn hec_url_maps_empty_or_root_path_to_default_collector_path() {
    assert_eq!(
        hec_url("http://127.0.0.1:8088/"),
        "http://127.0.0.1:8088/services/collector"
    );
    assert_eq!(
        hec_url("http://127.0.0.1:8088"),
        "http://127.0.0.1:8088/services/collector"
    );
    assert_eq!(
        hec_url("https://splunk.example.com:8088/services/collector"),
        "https://splunk.example.com:8088/services/collector"
    );
    assert_eq!(
        hec_url("https://splunk.example.com"),
        "https://splunk.example.com/services/collector"
    );
}
