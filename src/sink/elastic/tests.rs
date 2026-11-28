use std::collections::BTreeSet;
use std::io::Write;
use std::net::TcpListener;
use std::thread;

use super::{BulkItemErrorSummary, ElasticBulkSink, bulk_item_errors, elastic_bulk_action_json};
use crate::sink::emit_events;
use crate::sink::test_support::{make_health_event, read_mock_request};

/// Mock Elasticsearch answering one request with the given body.
fn start_mock_elastic(response_body: impl Into<String>) -> (String, thread::JoinHandle<String>) {
    let response_body = response_body.into();
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock listener");
    let addr = listener.local_addr().expect("mock addr");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let request = read_mock_request(&mut stream);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream.write_all(response.as_bytes()).expect("respond");
        String::from_utf8_lossy(&request).to_string()
    });
    (format!("http://{addr}"), handle)
}

#[test]
fn emits_bulk_action_and_source_pairs_with_event_id() {
    let (endpoint, handle) = start_mock_elastic(r#"{"took":1,"errors":false,"items":[]}"#);
    let sink = ElasticBulkSink::new(&endpoint, "telltale-events").with_api_key("test-key");

    let marker = "TT_PRIVACY_ELASTIC_25";
    let mut first = make_health_event();
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
    let events = [first, make_health_event()];
    emit_events(&sink, &events).expect("emit bulk events");

    let request = handle.join().expect("mock join");
    assert!(request.starts_with("POST /_bulk HTTP/1.1"));
    let lowercase = request.to_lowercase();
    assert!(lowercase.contains("authorization: apikey test-key"));
    assert!(lowercase.contains("content-type: application/x-ndjson"));
    assert!(!request.contains(marker));
    assert!(request.contains("https://example.invalid/[sensitive-path]?mode=view"));

    let body = request.split_once("\r\n\r\n").expect("body split").1;
    assert!(body.ends_with('\n'), "bulk body must end with a newline");
    let lines: Vec<&str> = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 4, "two action/source pairs");
    for pair in lines.chunks(2) {
        let action: serde_json::Value = serde_json::from_str(pair[0]).expect("action line");
        let source: serde_json::Value = serde_json::from_str(pair[1]).expect("source line");
        assert_eq!(action["index"]["_index"], "telltale-events");
        assert_eq!(action["index"]["_id"], source["event_id"]);
        assert_eq!(source["event_type"], "health");
        // Transport metadata stays out of the canonical event body.
        assert!(source.get("_index").is_none());
    }
}

#[test]
fn bulk_response_item_errors_fail_the_batch() {
    let (endpoint, handle) = start_mock_elastic(
        r#"{"took":1,"errors":true,"items":[{"index":{"_id":"a","status":403,"error":{"type":"security_exception","reason":"credential-marker=do-not-leak"}}},{"index":{"_id":"b","status":201}}]}"#,
    );
    let sink = ElasticBulkSink::new(&endpoint, "telltale-events");

    let err = emit_events(&sink, &[make_health_event()]).expect_err("item errors");
    handle.join().expect("mock join");
    let delivery = err
        .downcast_ref::<crate::sink::DeliveryError>()
        .expect("structured delivery error");
    assert_eq!(
        delivery.class,
        crate::sink::DeliveryErrorClass::SinkApplicationRejected
    );
    assert_eq!(delivery.attempts, 1);

    let message = err.to_string();
    assert!(message.contains("1 failed item(s)"), "message: {message}");
    assert!(message.contains("status codes: 403"), "message: {message}");
    assert!(!message.contains("credential-marker"), "message: {message}");
}

#[test]
fn malformed_bulk_response_fails_without_body_or_losing_attempt_count() {
    let (endpoint, handle) = start_mock_elastic("credential-marker=malformed-body");
    let sink = ElasticBulkSink::new(&endpoint, "telltale-events");

    let err = emit_events(&sink, &[make_health_event()]).expect_err("malformed response");
    handle.join().expect("mock join");
    let delivery = err
        .downcast_ref::<crate::sink::DeliveryError>()
        .expect("structured delivery error");
    assert_eq!(
        delivery.class,
        crate::sink::DeliveryErrorClass::SinkApplicationRejected
    );

    let message = err.to_string();
    assert!(
        message.contains("response is not valid JSON"),
        "message: {message}"
    );
    assert!(message.contains("after 1 attempts"), "message: {message}");
    assert!(!message.contains("credential-marker"), "message: {message}");
}

#[test]
fn basic_auth_sets_encoded_authorization_header() {
    let (endpoint, handle) = start_mock_elastic(r#"{"errors":false}"#);
    let sink =
        ElasticBulkSink::new(&endpoint, "telltale-events").with_basic_auth("telltale", "s3cret");

    emit_events(&sink, &[make_health_event()]).expect("emit");
    let request = handle.join().expect("mock join").to_lowercase();
    // base64("telltale:s3cret")
    assert!(request.contains("authorization: basic dgvsbhrhbgu6cznjcmv0"));
}

#[test]
fn bulk_item_errors_summarizes_counts_and_statuses_without_reasons() {
    assert_eq!(bulk_item_errors(r#"{"errors":false,"items":[]}"#), Ok(None));
    assert_eq!(
        bulk_item_errors("not json"),
        Err("response is not valid JSON")
    );
    assert_eq!(bulk_item_errors(""), Err("response is not valid JSON"));
    assert_eq!(
        bulk_item_errors(r#"{"items":[]}"#),
        Err("response errors field is missing or not boolean")
    );
    assert_eq!(
        bulk_item_errors(r#"{"errors":"false","items":[]}"#),
        Err("response errors field is missing or not boolean")
    );

    let summary = bulk_item_errors(
        r#"{"errors":true,"items":[
                {"index":{"status":400,"error":{"reason":"credential-marker=one"}}},
                {"index":{"status":400,"error":{"reason":"credential-marker=two"}}},
                {"index":{"status":429,"error":{"reason":"credential-marker=three"}}},
                {"index":{"status":201}}
            ]}"#,
    )
    .expect("valid response")
    .expect("summary");
    assert_eq!(
        summary,
        BulkItemErrorSummary {
            failed_count: 3,
            statuses: BTreeSet::from([400, 429]),
        }
    );
}

#[test]
fn action_json_matches_export_format() {
    let action = elastic_bulk_action_json(
        "telltale-events",
        Some("telltale-00000000-0000-4000-8000-000000000001"),
    );
    assert_eq!(
        serde_json::to_string(&action).expect("serialize"),
        r#"{"index":{"_id":"telltale-00000000-0000-4000-8000-000000000001","_index":"telltale-events"}}"#
    );
    let without_id = elastic_bulk_action_json("telltale-events", None);
    assert_eq!(
        serde_json::to_string(&without_id).expect("serialize"),
        r#"{"index":{"_index":"telltale-events"}}"#
    );
}

#[cfg(not(windows))]
mod durable;
