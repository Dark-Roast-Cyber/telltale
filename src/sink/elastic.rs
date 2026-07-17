use std::time::Duration;

use base64::Engine as _;

use crate::event::Event;
use crate::sink::http::{HttpClient, RetryConfig, TlsOptions, chunk_segments};
use crate::sink::{EventSink, SinkDeliveryError};

pub const DEFAULT_ELASTIC_INDEX: &str = "adr-events";
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
    pub fn with_transport(
        mut self,
        timeout: Duration,
        retry: RetryConfig,
        tls: &TlsOptions,
        max_batch_bytes: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        self.client = HttpClient::new(timeout, retry, tls)?;
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
            segment.extend_from_slice(&serde_json::to_vec(event)?);
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
                .map_err(|err| SinkDeliveryError {
                    attempts: err.attempts,
                    message: format!("Elasticsearch bulk request failed: {}", err.message),
                })?;
            if !(200..300).contains(&response.status) {
                return Err(SinkDeliveryError {
                    attempts: response.attempts,
                    message: format!(
                        "Elasticsearch bulk request failed with HTTP {}: {}",
                        response.status,
                        truncate_body(&response.body)
                    ),
                }
                .into());
            }
            // The bulk API returns 200 even when individual items failed.
            if let Some(item_errors) = bulk_item_errors(&response.body) {
                return Err(SinkDeliveryError {
                    attempts: response.attempts,
                    message: format!("Elasticsearch bulk response reported item errors: {item_errors}"),
                }
                .into());
            }
        }
        Ok(())
    }
}

/// The Bulk API action line for one event. Shared with `adr export
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

/// Parse a bulk response body; when `errors` is true, summarize up to three
/// distinct item error reasons. Returns None when every item succeeded (or
/// the body is unparseable, which non-2xx handling already covers).
fn bulk_item_errors(body: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    if !parsed.get("errors").and_then(|value| value.as_bool())? {
        return None;
    }
    let mut reasons: Vec<String> = Vec::new();
    let mut failed_count = 0_usize;
    if let Some(items) = parsed.get("items").and_then(|value| value.as_array()) {
        for item in items {
            let Some(action) = item.as_object().and_then(|map| map.values().next()) else {
                continue;
            };
            let Some(error) = action.get("error") else {
                continue;
            };
            failed_count += 1;
            let status = action.get("status").and_then(|value| value.as_u64());
            let reason = error
                .get("reason")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown reason");
            let summary = match status {
                Some(status) => format!("status {status}: {reason}"),
                None => reason.to_string(),
            };
            if reasons.len() < 3 && !reasons.contains(&summary) {
                reasons.push(summary);
            }
        }
    }
    if failed_count == 0 {
        // errors=true with no parseable item errors: still a failure.
        return Some("errors=true with no parseable items".to_string());
    }
    Some(format!(
        "{failed_count} item(s) failed; first distinct errors: {}",
        reasons.join(" | ")
    ))
}

fn truncate_body(body: &str) -> String {
    const MAX: usize = 300;
    if body.chars().count() > MAX {
        let mut truncated: String = body.chars().take(MAX).collect();
        truncated.push('…');
        truncated
    } else {
        body.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use super::{ElasticBulkSink, bulk_item_errors, elastic_bulk_action_json};
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
    fn start_mock_elastic(response_body: &'static str) -> (String, thread::JoinHandle<String>) {
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
        let sink = ElasticBulkSink::new(&endpoint, "adr-events").with_api_key("test-key");

        let events = [make_health_event(), make_health_event()];
        emit_events(&sink, &events).expect("emit bulk events");

        let request = handle.join().expect("mock join");
        assert!(request.starts_with("POST /_bulk HTTP/1.1"));
        let lowercase = request.to_lowercase();
        assert!(lowercase.contains("authorization: apikey test-key"));
        assert!(lowercase.contains("content-type: application/x-ndjson"));

        let body = request.split_once("\r\n\r\n").expect("body split").1;
        assert!(body.ends_with('\n'), "bulk body must end with a newline");
        let lines: Vec<&str> = body.lines().filter(|line| !line.trim().is_empty()).collect();
        assert_eq!(lines.len(), 4, "two action/source pairs");
        for pair in lines.chunks(2) {
            let action: serde_json::Value = serde_json::from_str(pair[0]).expect("action line");
            let source: serde_json::Value = serde_json::from_str(pair[1]).expect("source line");
            assert_eq!(action["index"]["_index"], "adr-events");
            assert_eq!(action["index"]["_id"], source["event_id"]);
            assert_eq!(source["event_type"], "health");
            // Transport metadata stays out of the canonical event body.
            assert!(source.get("_index").is_none());
        }
    }

    #[test]
    fn bulk_response_item_errors_fail_the_batch() {
        let (endpoint, handle) = start_mock_elastic(
            r#"{"took":1,"errors":true,"items":[{"index":{"_id":"a","status":403,"error":{"type":"security_exception","reason":"index write blocked"}}},{"index":{"_id":"b","status":201}}]}"#,
        );
        let sink = ElasticBulkSink::new(&endpoint, "adr-events");

        let err = emit_events(&sink, &[make_health_event()]).expect_err("item errors");
        handle.join().expect("mock join");

        let message = err.to_string();
        assert!(message.contains("1 item(s) failed"), "message: {message}");
        assert!(message.contains("index write blocked"), "message: {message}");
    }

    #[test]
    fn basic_auth_sets_encoded_authorization_header() {
        let (endpoint, handle) = start_mock_elastic(r#"{"errors":false}"#);
        let sink = ElasticBulkSink::new(&endpoint, "adr-events")
            .with_basic_auth("telltale", "s3cret");

        emit_events(&sink, &[make_health_event()]).expect("emit");
        let request = handle.join().expect("mock join").to_lowercase();
        // base64("telltale:s3cret")
        assert!(request.contains("authorization: basic dgvsbhrhbgu6cznjcmv0"));
    }

    #[test]
    fn bulk_item_errors_summarizes_distinct_reasons() {
        assert_eq!(bulk_item_errors(r#"{"errors":false,"items":[]}"#), None);
        assert_eq!(bulk_item_errors("not json"), None);

        let summary = bulk_item_errors(
            r#"{"errors":true,"items":[
                {"index":{"status":400,"error":{"reason":"mapper_parsing_exception"}}},
                {"index":{"status":400,"error":{"reason":"mapper_parsing_exception"}}},
                {"index":{"status":429,"error":{"reason":"too many requests"}}},
                {"index":{"status":201}}
            ]}"#,
        )
        .expect("summary");
        assert!(summary.contains("3 item(s) failed"));
        assert!(summary.contains("mapper_parsing_exception"));
        assert!(summary.contains("too many requests"));
    }

    #[test]
    fn action_json_matches_export_format() {
        let action = elastic_bulk_action_json("adr-events", Some("adr-1234"));
        assert_eq!(
            serde_json::to_string(&action).expect("serialize"),
            r#"{"index":{"_id":"adr-1234","_index":"adr-events"}}"#
        );
        let without_id = elastic_bulk_action_json("adr-events", None);
        assert_eq!(
            serde_json::to_string(&without_id).expect("serialize"),
            r#"{"index":{"_index":"adr-events"}}"#
        );
    }
}
