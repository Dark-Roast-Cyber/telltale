use std::collections::BTreeSet;
use std::time::Duration;

use base64::Engine as _;

use crate::event::Event;
use crate::sink::http::{HttpClient, RetryConfig, TlsOptions, chunk_segments};
use crate::sink::{DeliveryError, DeliveryErrorClass, EventSink};

pub const DEFAULT_ELASTIC_INDEX: &str = "telltale-events";
/// Elasticsearch's default `http.max_content_length` is 100 MB; 5 MiB per
/// request keeps bulk bodies well under typical proxy limits.
pub const DEFAULT_ELASTIC_MAX_BATCH_BYTES: usize = 5 * 1024 * 1024;
const DEFAULT_ELASTIC_TIMEOUT: Duration = Duration::from_secs(10);

/// Live shipper for the Elasticsearch Bulk API. Uses `index` actions with the
/// event's `event_id` as `_id`, so redelivery after a retry overwrites the
/// same document instead of duplicating it.
pub struct ElasticBulkSink {
    name: String,
    bulk_url: String,
    index: String,
    auth_header: Option<String>,
    client: HttpClient,
    max_batch_bytes: usize,
}

impl ElasticBulkSink {
    pub fn new(endpoint: &str, index: impl Into<String>) -> Self {
        let client = HttpClient::new(
            DEFAULT_ELASTIC_TIMEOUT,
            RetryConfig::default(),
            &TlsOptions::default(),
        )
        .expect("default http client");
        Self {
            name: "elastic".to_string(),
            bulk_url: format!("{}/_bulk", endpoint.trim_end_matches('/')),
            index: index.into(),
            auth_header: None,
            client,
            max_batch_bytes: DEFAULT_ELASTIC_MAX_BATCH_BYTES,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Authenticate with an Elasticsearch API key (the pre-encoded
    /// `base64(id:key)` value Kibana provides).
    pub fn with_api_key(mut self, api_key: &str) -> Self {
        self.auth_header = Some(format!("ApiKey {api_key}"));
        self
    }

    pub fn with_basic_auth(mut self, username: &str, password: &str) -> Self {
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        self.auth_header = Some(format!("Basic {credentials}"));
        self
    }

    /// Replace the transport with fully-specified options (config-file path).
    pub(crate) fn with_transport_warning(
        mut self,
        timeout: Duration,
        retry: RetryConfig,
        tls: &TlsOptions,
        max_batch_bytes: usize,
        emit_warning: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        self.client = HttpClient::new_with_warning(timeout, retry, tls, emit_warning)?;
        self.max_batch_bytes = max_batch_bytes;
        Ok(self)
    }
}

impl EventSink for ElasticBulkSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        let mut segments = Vec::with_capacity(events.len());
        for event in events {
            let action = elastic_bulk_action_json(&self.index, Some(&event.event_id));
            let mut segment = serde_json::to_vec(&action)?;
            segment.push(b'\n');
            let mut event_bytes = Vec::new();
            let mut serializer = serde_json::Serializer::new(&mut event_bytes);
            crate::event::serialize_event_for_emission(event, &mut serializer)?;
            segment.extend_from_slice(&event_bytes);
            segments.push(segment);
        }
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(auth) = &self.auth_header {
            headers.push(("Authorization", auth));
        }
        for chunk in chunk_segments(&segments, self.max_batch_bytes) {
            let response = self
                .client
                .post(&self.bulk_url, &headers, "application/x-ndjson", &chunk)
                .map_err(elastic_transport_error)?;
            if !(200..300).contains(&response.status) {
                return Err(elastic_status_error(response.status, response.attempts).into());
            }
            validate_bulk_response(&response.body, response.attempts)?;
        }
        Ok(())
    }

    fn emit_canonical_once(&self, payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let (segment, event_id) = elastic_bulk_segment(payload, &self.index)?;
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(auth) = &self.auth_header {
            headers.push(("Authorization", auth));
        }
        let response = self
            .client
            .post_once(&self.bulk_url, &headers, "application/x-ndjson", &segment)
            .map_err(elastic_transport_error)?;
        if !(200..300).contains(&response.status) {
            return Err(elastic_status_error(response.status, response.attempts).into());
        }
        validate_durable_bulk_response(&response.body, &event_id, response.attempts)
    }
}

fn elastic_transport_error(err: crate::sink::http::HttpPostError) -> DeliveryError {
    let class = match err.kind {
        crate::sink::http::HttpPostErrorKind::NoResponse => DeliveryErrorClass::TransportNoResponse,
        crate::sink::http::HttpPostErrorKind::Timeout => DeliveryErrorClass::Timeout,
    };
    DeliveryError::new(
        class,
        err.attempts,
        format!("Elasticsearch bulk request failed: {}", err.message),
    )
}

fn elastic_status_error(status: u16, attempts: u32) -> DeliveryError {
    let class = match status {
        401 | 403 => DeliveryErrorClass::AuthenticationBlocked { status },
        status => DeliveryErrorClass::HttpStatus { status },
    };
    DeliveryError::new(
        class,
        attempts,
        format!("Elasticsearch bulk request failed with HTTP {status}"),
    )
}

fn validate_bulk_response(body: &str, attempts: u32) -> Result<(), Box<dyn std::error::Error>> {
    // The bulk API returns 200 even when individual items failed, but every
    // successful response must still carry a valid `errors` flag.
    let item_errors = bulk_item_errors(body).map_err(|reason| {
        Box::new(DeliveryError::new(
            DeliveryErrorClass::SinkApplicationRejected,
            attempts,
            format!("Elasticsearch bulk response is invalid: {reason}"),
        )) as Box<dyn std::error::Error>
    })?;
    if let Some(item_errors) = item_errors {
        let statuses = item_errors
            .statuses
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>();
        let detail = if statuses.is_empty() {
            "no parseable item statuses".to_string()
        } else {
            format!("status codes: {}", statuses.join(", "))
        };
        return Err(DeliveryError::new(
            DeliveryErrorClass::SinkApplicationRejected,
            attempts,
            format!(
                "Elasticsearch bulk response reported {} failed item(s); {detail}",
                item_errors.failed_count
            ),
        )
        .into());
    }
    Ok(())
}

fn validate_durable_bulk_response(
    body: &str,
    event_id: &str,
    attempts: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let blocked = || {
        DeliveryError::new(
            DeliveryErrorClass::SinkResponseBlocked,
            attempts,
            "Elasticsearch bulk response does not confirm the event outcome",
        )
    };
    let (parsed, errors) = parse_bulk_response(body).map_err(|_| blocked())?;
    let items = parsed.get("items").and_then(serde_json::Value::as_array);
    let item = items
        .filter(|items| items.len() == 1)
        .and_then(|items| items[0].as_object())
        .filter(|item| item.len() == 1)
        .and_then(|item| item.get("index"))
        .ok_or_else(blocked)?;
    if item.get("_id").and_then(serde_json::Value::as_str) != Some(event_id) {
        return Err(blocked().into());
    }
    let status = item
        .get("status")
        .and_then(serde_json::Value::as_u64)
        .and_then(|status| u16::try_from(status).ok())
        .ok_or_else(blocked)?;
    if !errors {
        let expected_result = match status {
            200 => "updated",
            201 => "created",
            _ => return Err(blocked().into()),
        };
        if item.get("error").is_some()
            || item.get("result").and_then(serde_json::Value::as_str) != Some(expected_result)
        {
            return Err(blocked().into());
        }
        return Ok(());
    }
    if item.get("result").is_some()
        || item
            .get("error")
            .and_then(|error| error.get("type"))
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(blocked().into());
    }
    let class = match status {
        401 | 403 => DeliveryErrorClass::AuthenticationBlocked { status },
        status if (DeliveryErrorClass::HttpStatus { status }).is_retryable() => {
            DeliveryErrorClass::HttpStatus { status }
        }
        400 | 413 | 422 => DeliveryErrorClass::SinkApplicationRejected,
        _ => return Err(blocked().into()),
    };
    Err(DeliveryError::new(
        class,
        attempts,
        format!("Elasticsearch bulk item failed with status {status}"),
    )
    .into())
}

/// Build one Bulk API action/source pair while retaining the stored canonical
/// Event 3.0 bytes verbatim as the source line.
fn elastic_bulk_segment(
    payload: &[u8],
    index: &str,
) -> Result<(Vec<u8>, String), Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_slice(payload).map_err(|error| {
        Box::new(DeliveryError::new(
            DeliveryErrorClass::SinkApplicationRejected,
            1,
            format!("canonical Elasticsearch payload is invalid: {error}"),
        )) as Box<dyn std::error::Error>
    })?;
    let event_id = value
        .get("event_id")
        .and_then(serde_json::Value::as_str)
        .filter(|event_id| !event_id.is_empty())
        .ok_or_else(|| {
            Box::new(DeliveryError::new(
                DeliveryErrorClass::SinkApplicationRejected,
                1,
                "canonical Elasticsearch payload has no event ID",
            )) as Box<dyn std::error::Error>
        })?;
    if !value.is_object() {
        return Err(DeliveryError::new(
            DeliveryErrorClass::SinkApplicationRejected,
            1,
            "canonical Elasticsearch payload is not an Event object",
        )
        .into());
    }
    let action = elastic_bulk_action_json(index, Some(event_id));
    let mut segment = serde_json::to_vec(&action)?;
    segment.push(b'\n');
    segment.extend_from_slice(payload);
    segment.push(b'\n');
    Ok((segment, event_id.to_string()))
}

/// The Bulk API action line for one event. Shared with `telltale export
/// --format elastic-bulk` so the offline and live formats cannot drift.
pub fn elastic_bulk_action_json(index: &str, event_id: Option<&str>) -> serde_json::Value {
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        "_index".to_string(),
        serde_json::Value::String(index.to_string()),
    );
    if let Some(event_id) = event_id {
        metadata.insert(
            "_id".to_string(),
            serde_json::Value::String(event_id.to_string()),
        );
    }
    serde_json::json!({ "index": metadata })
}

#[derive(Debug, Eq, PartialEq)]
struct BulkItemErrorSummary {
    failed_count: usize,
    statuses: BTreeSet<u16>,
}

fn parse_bulk_response(body: &str) -> Result<(serde_json::Value, bool), &'static str> {
    let parsed: serde_json::Value =
        serde_json::from_str(body).map_err(|_| "response is not valid JSON")?;
    let errors = parsed
        .get("errors")
        .and_then(|value| value.as_bool())
        .ok_or("response errors field is missing or not boolean")?;
    Ok((parsed, errors))
}

/// Summarize legacy best-effort failures without endpoint-controlled reasons.
fn bulk_item_errors(body: &str) -> Result<Option<BulkItemErrorSummary>, &'static str> {
    let (parsed, errors) = parse_bulk_response(body)?;
    if !errors {
        return Ok(None);
    }
    let mut failed_count = 0_usize;
    let mut statuses = BTreeSet::new();
    if let Some(items) = parsed.get("items").and_then(|value| value.as_array()) {
        for item in items {
            let Some(action) = item.as_object().and_then(|map| map.values().next()) else {
                continue;
            };
            let Some(_) = action.get("error") else {
                continue;
            };
            failed_count += 1;
            if let Some(status) = action
                .get("status")
                .and_then(|value| value.as_u64())
                .and_then(|status| u16::try_from(status).ok())
            {
                statuses.insert(status);
            }
        }
    }
    Ok(Some(BulkItemErrorSummary {
        failed_count,
        statuses,
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use super::{
        BulkItemErrorSummary, ElasticBulkSink, bulk_item_errors, elastic_bulk_action_json,
    };
    use crate::event::health_event_with_metadata;
    use crate::sink::emit_events;

    fn make_health_event() -> crate::event::Event {
        health_event_with_metadata(crate::event::HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        })
    }

    /// Mock Elasticsearch answering one request with the given body.
    fn start_mock_elastic(
        response_body: impl Into<String>,
    ) -> (String, thread::JoinHandle<String>) {
        let response_body = response_body.into();
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock listener");
        let addr = listener.local_addr().expect("mock addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            let mut request = Vec::new();
            let mut buf = [0_u8; 4096];
            while let Ok(read) = stream.read(&mut buf) {
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..read]);
                let text = String::from_utf8_lossy(&request).to_lowercase();
                if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                    let content_length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if body.len() >= content_length {
                        break;
                    }
                }
            }
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
        let sink = ElasticBulkSink::new(&endpoint, "telltale-events")
            .with_basic_auth("telltale", "s3cret");

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
    mod durable {
        use super::*;
        use crate::sink::http::RetryConfig;
        use crate::sink::outbox::{CapacityLimits, DeliveryClock, DeliveryState, Outbox};
        use crate::sink::{DeliveryErrorClass, LocalJsonlSink, RotationConfig, SinkSet};
        use std::path::Path;

        struct Clock(i64);
        impl DeliveryClock for Clock {
            fn now_millis(&self) -> i64 {
                self.0
            }
        }

        fn sinks(directory: &Path, endpoint: &str) -> SinkSet {
            let log = directory.join("events.jsonl");
            let mut sinks = SinkSet::new();
            sinks.add_canonical_first_write_path_with_rotation(
                "jsonl",
                Box::new(LocalJsonlSink::with_rotation(
                    &log,
                    RotationConfig::disabled(),
                )),
                log,
                None,
            );
            sinks.add_best_effort_with_retry(
                "elastic_bulk",
                Box::new(ElasticBulkSink::new(endpoint, "events")),
                RetryConfig {
                    max_attempts: 2,
                    base_delay_ms: 10,
                },
            );
            sinks.enable_persistent_replay_with_capacity(
                directory.join("private/outbox.sqlite"),
                vec!["elastic".into()],
                CapacityLimits::default(),
            );
            sinks
        }

        fn row(directory: &Path, id: &str) -> crate::sink::outbox::DeliveryRow {
            Outbox::open(directory.join("private/outbox.sqlite"))
                .unwrap()
                .get_delivery(id, "elastic")
                .unwrap()
                .unwrap()
        }

        fn response(id: &str, status: u16) -> String {
            let mut item = serde_json::json!({"_id": id, "status": status});
            if status >= 400 {
                item["error"] = serde_json::json!({"type": "synthetic_exception", "reason": "TT_ENDPOINT_SECRET /home/synthetic/private"});
            } else if status == 200 || status == 201 {
                item["result"] =
                    serde_json::json!(if status == 201 { "created" } else { "updated" });
            }
            serde_json::json!({"errors": status >= 400, "items": [{"index": item}]}).to_string()
        }

        #[test]
        fn durable_elastic_item_retry_replays_exact_journal_bytes_after_restart() {
            for status in [408, 429, 500, 503, 599] {
                let directory = tempfile::tempdir().unwrap();
                let event = make_health_event();
                let (endpoint, request) = start_mock_elastic(response(&event.event_id, status));
                let first = sinks(directory.path(), &endpoint);
                first
                    .persist_for_durable_replay(std::slice::from_ref(&event))
                    .unwrap();
                let journal = std::fs::read(directory.path().join("events.jsonl")).unwrap();
                assert_eq!(row(directory.path(), &event.event_id).attempts, 0);
                let failures = first.dispatch_durable_with_clock(&Clock(1000)).unwrap();
                let sent = request.join().unwrap();
                assert_eq!(failures.len(), 1);
                assert_eq!(failures[0].class, DeliveryErrorClass::HttpStatus { status });
                assert!(!failures[0].error.contains("TT_ENDPOINT_SECRET"));
                let pending = row(directory.path(), &event.event_id);
                assert_eq!(pending.state, DeliveryState::Pending);
                assert_eq!(pending.attempts, 1);
                assert_eq!(pending.next_attempt_at, Some(1010));
                drop(first);

                let (endpoint, request) = start_mock_elastic(response(&event.event_id, 200));
                let restarted = sinks(directory.path(), &endpoint);
                assert!(
                    restarted
                        .dispatch_durable_with_clock(&Clock(1009))
                        .unwrap()
                        .is_empty()
                );
                assert_eq!(row(directory.path(), &event.event_id), pending);
                assert!(
                    restarted
                        .dispatch_durable_with_clock(&Clock(1010))
                        .unwrap()
                        .is_empty()
                );
                let replay = request.join().unwrap();
                let body = sent.split_once("\r\n\r\n").unwrap().1;
                assert_eq!(body, replay.split_once("\r\n\r\n").unwrap().1);
                assert_eq!(body.split_once('\n').unwrap().1.as_bytes(), journal);
                let acked = row(directory.path(), &event.event_id);
                assert_eq!(acked.state, DeliveryState::Acked);
                assert_eq!(acked.attempts, 2);
                assert_eq!(acked.next_attempt_at, None);
            }
        }

        #[test]
        fn durable_elastic_auth_and_ambiguous_responses_block_without_poisoning() {
            let event = make_health_event();
            let mut cases = vec![
                (
                    response(&event.event_id, 401),
                    DeliveryErrorClass::AuthenticationBlocked { status: 401 },
                ),
                (
                    response(&event.event_id, 403),
                    DeliveryErrorClass::AuthenticationBlocked { status: 403 },
                ),
            ];
            let success: serde_json::Value =
                serde_json::from_str(&response(&event.event_id, 201)).unwrap();
            let mut inconsistent = success.clone();
            inconsistent["errors"] = true.into();
            let mut hidden_failure: serde_json::Value =
                serde_json::from_str(&response(&event.event_id, 400)).unwrap();
            hidden_failure["errors"] = false.into();
            let mut extra = success.clone();
            extra["items"]
                .as_array_mut()
                .unwrap()
                .push(success["items"][0].clone());
            let mut wrong_action = success.clone();
            wrong_action["items"][0] = serde_json::json!({"create": success["items"][0]["index"]});
            let mut missing_status = success.clone();
            missing_status["items"][0]["index"]
                .as_object_mut()
                .unwrap()
                .remove("status");
            let mut missing_error: serde_json::Value =
                serde_json::from_str(&response(&event.event_id, 400)).unwrap();
            missing_error["items"][0]["index"]
                .as_object_mut()
                .unwrap()
                .remove("error");
            let mut missing_result = success.clone();
            missing_result["items"][0]["index"]
                .as_object_mut()
                .unwrap()
                .remove("result");
            let mut wrong_result = success.clone();
            wrong_result["items"][0]["index"]["result"] = "updated".into();
            let mut null_error = success.clone();
            null_error["items"][0]["index"]["error"] = serde_json::Value::Null;
            let mut multiple_actions = success.clone();
            multiple_actions["items"][0]["delete"] = success["items"][0]["index"].clone();
            let mut empty_error: serde_json::Value =
                serde_json::from_str(&response(&event.event_id, 400)).unwrap();
            empty_error["items"][0]["index"]["error"] = serde_json::json!({});
            for body in [
                "TT_ENDPOINT_SECRET /home/synthetic/private".to_string(),
                r#"{"errors":false}"#.into(),
                r#"{"errors":false,"items":[]}"#.into(),
                response("TT_ENDPOINT_SECRET /home/synthetic/private", 201),
                response(&event.event_id, 302),
                response(&event.event_id, 404),
                response(&event.event_id, 409),
                inconsistent.to_string(),
                hidden_failure.to_string(),
                extra.to_string(),
                wrong_action.to_string(),
                missing_status.to_string(),
                missing_error.to_string(),
                missing_result.to_string(),
                wrong_result.to_string(),
                null_error.to_string(),
                multiple_actions.to_string(),
                empty_error.to_string(),
            ] {
                cases.push((body, DeliveryErrorClass::SinkResponseBlocked));
            }
            for (body, class) in cases {
                let directory = tempfile::tempdir().unwrap();
                let (endpoint, request) = start_mock_elastic(body);
                let sinks = sinks(directory.path(), &endpoint);
                sinks
                    .persist_for_durable_replay(std::slice::from_ref(&event))
                    .unwrap();
                let failures = sinks.dispatch_durable_with_clock(&Clock(1000)).unwrap();
                request.join().unwrap();
                assert_eq!(failures.len(), 1);
                assert_eq!(failures[0].class, class);
                assert!(failures[0].error.len() < 200);
                assert!(!failures[0].error.contains("TT_ENDPOINT_SECRET"));
                assert!(!failures[0].error.contains("/home/synthetic/private"));
                let blocked = row(directory.path(), &event.event_id);
                assert_eq!(blocked.state, DeliveryState::Blocked);
                assert_eq!(blocked.last_error_class, Some(class));
                assert_eq!(blocked.next_attempt_at, None);
                assert!(
                    sinks
                        .dispatch_durable_with_clock(&Clock(2000))
                        .unwrap()
                        .is_empty()
                );
                assert_eq!(row(directory.path(), &event.event_id), blocked);
            }
        }

        #[test]
        fn durable_elastic_permanent_item_does_not_prevent_next_event() {
            let directory = tempfile::tempdir().unwrap();
            let poison = make_health_event();
            let (endpoint, request) = start_mock_elastic(response(&poison.event_id, 400));
            let first = sinks(directory.path(), &endpoint);
            first
                .persist_for_durable_replay(std::slice::from_ref(&poison))
                .unwrap();
            let failures = first.dispatch_durable_with_clock(&Clock(1000)).unwrap();
            request.join().unwrap();
            assert_eq!(
                failures[0].class,
                DeliveryErrorClass::SinkApplicationRejected
            );
            assert_eq!(
                row(directory.path(), &poison.event_id).state,
                DeliveryState::Dead
            );
            drop(first);
            let valid = make_health_event();
            let (endpoint, request) = start_mock_elastic(response(&valid.event_id, 201));
            let next = sinks(directory.path(), &endpoint);
            next.persist_for_durable_replay(std::slice::from_ref(&valid))
                .unwrap();
            assert!(
                next.dispatch_durable_with_clock(&Clock(2000))
                    .unwrap()
                    .is_empty()
            );
            request.join().unwrap();
            assert_eq!(
                row(directory.path(), &valid.event_id).state,
                DeliveryState::Acked
            );
        }

        #[test]
        fn durable_elastic_item_retries_obey_persisted_attempt_budget() {
            let directory = tempfile::tempdir().unwrap();
            let event = make_health_event();
            for (now, state) in [(1000, DeliveryState::Pending), (1010, DeliveryState::Dead)] {
                let (endpoint, request) = start_mock_elastic(response(&event.event_id, 503));
                let sinks = sinks(directory.path(), &endpoint);
                if now == 1000 {
                    sinks
                        .persist_for_durable_replay(std::slice::from_ref(&event))
                        .unwrap();
                }
                sinks.dispatch_durable_with_clock(&Clock(now)).unwrap();
                request.join().unwrap();
                assert_eq!(row(directory.path(), &event.event_id).state, state);
            }
            assert_eq!(row(directory.path(), &event.event_id).attempts, 2);
        }
    }
}
