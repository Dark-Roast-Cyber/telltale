use std::time::Duration;

use serde::Serialize;
use uuid::Uuid;

use crate::event::{Event, parse_event_timestamp};
use crate::sink::http::{HttpClient, RetryConfig, TlsOptions, chunk_segments};
use crate::sink::{EventSink, SinkDeliveryError};

const DEFAULT_HEC_TIMEOUT: Duration = Duration::from_secs(10);
/// Splunk's conservative default `max_content_length` is 1 MiB.
pub const DEFAULT_HEC_MAX_BATCH_BYTES: usize = 1024 * 1024;

pub struct SplunkHecHttpSink {
    name: String,
    url: String,
    token: String,
    // Required by HEC tokens with indexer acknowledgment enabled.
    request_channel: String,
    config: SplunkHecConfig,
    client: HttpClient,
    max_batch_bytes: usize,
}

impl SplunkHecHttpSink {
    pub fn new(endpoint: String, token: String, config: SplunkHecConfig) -> Self {
        let client = HttpClient::new(
            DEFAULT_HEC_TIMEOUT,
            RetryConfig::default(),
            &TlsOptions::default(),
        )
        .expect("default http client");
        Self {
            name: "cli-splunk-hec".to_string(),
            url: hec_url(&endpoint),
            token,
            request_channel: Uuid::new_v4().to_string(),
            config,
            client,
            max_batch_bytes: DEFAULT_HEC_MAX_BATCH_BYTES,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.client = HttpClient::new(timeout, RetryConfig::default(), &TlsOptions::default())
            .expect("default http client");
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Replace the transport with fully-specified options (config-file path).
    pub fn with_transport(
        self,
        timeout: Duration,
        retry: RetryConfig,
        tls: &TlsOptions,
        max_batch_bytes: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        self.with_transport_warning(timeout, retry, tls, max_batch_bytes, true)
    }

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

impl EventSink for SplunkHecHttpSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        let envelopes = splunk_hec_envelopes(events, &self.config);
        let mut segments = Vec::with_capacity(envelopes.len());
        for envelope in &envelopes {
            segments.push(serde_json::to_vec(envelope)?);
        }
        let auth = format!("Splunk {}", self.token);
        let headers = [
            ("Authorization", auth.as_str()),
            ("X-Splunk-Request-Channel", self.request_channel.as_str()),
        ];
        for chunk in chunk_segments(&segments, self.max_batch_bytes) {
            let response = self
                .client
                .post(&self.url, &headers, "application/json", &chunk)
                .map_err(|err| SinkDeliveryError {
                    attempts: err.attempts,
                    message: format!("Splunk HEC request failed: {}", err.message),
                })?;
            if !(200..300).contains(&response.status) {
                return Err(SinkDeliveryError {
                    attempts: response.attempts,
                    message: format!("Splunk HEC request failed with HTTP {}", response.status),
                }
                .into());
            }
        }
        Ok(())
    }
}

/// Normalize a HEC endpoint: an empty or root path gets the default
/// `/services/collector`; an explicit path is kept as-is.
fn hec_url(endpoint: &str) -> String {
    let rest = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"));
    let Some(rest) = rest else {
        // Invalid scheme: hand the URL to the transport unchanged; it will
        // produce the error.
        return endpoint.to_string();
    };
    match rest.split_once('/') {
        None => format!("{endpoint}/services/collector"),
        Some((_, "")) => format!("{}/services/collector", endpoint.trim_end_matches('/')),
        Some(_) => endpoint.to_string(),
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SplunkHecConfig {
    pub index: Option<String>,
    pub sourcetype: String,
    pub source: Option<String>,
    pub host: Option<String>,
}

impl Default for SplunkHecConfig {
    fn default() -> Self {
        Self {
            index: Some("adr".to_string()),
            sourcetype: "adr:json".to_string(),
            source: Some("telltale:adr".to_string()),
            host: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SplunkHecEnvelope<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<&'a str>,
    pub sourcetype: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'a str>,
    pub event: &'a Event,
}

impl<'a> SplunkHecEnvelope<'a> {
    fn new(event: &'a Event, config: &'a SplunkHecConfig) -> Self {
        Self {
            time: splunk_hec_time(&event.timestamp),
            host: config.host.as_deref(),
            index: config.index.as_deref(),
            sourcetype: &config.sourcetype,
            source: config.source.as_deref(),
            event,
        }
    }
}

pub fn splunk_hec_envelopes<'a>(
    events: &'a [Event],
    config: &'a SplunkHecConfig,
) -> Vec<SplunkHecEnvelope<'a>> {
    events
        .iter()
        .map(|event| SplunkHecEnvelope::new(event, config))
        .collect()
}

fn splunk_hec_time(timestamp: &str) -> Option<f64> {
    let parsed = parse_event_timestamp(timestamp)?;
    Some(parsed.unix_timestamp() as f64 + f64::from(parsed.nanosecond()) / 1_000_000_000.0)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use uuid::Uuid;

    use super::{SplunkHecConfig, SplunkHecHttpSink, hec_url, splunk_hec_envelopes};
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

    #[test]
    fn splunk_hec_envelope_wraps_canonical_event_with_transport_metadata() {
        let mut event = make_health_event();
        event.timestamp = "2026-05-18T02:00:00.000Z".to_string();
        let config = SplunkHecConfig {
            index: Some("adr".to_string()),
            sourcetype: "adr:json".to_string(),
            source: Some("telltale:adr-events".to_string()),
            host: Some("developer-workstation".to_string()),
        };

        let events = vec![event];
        let envelopes = splunk_hec_envelopes(&events, &config);
        let envelope = serde_json::to_value(&envelopes[0]).expect("serialize hec envelope");

        assert_eq!(envelope["index"], "adr");
        assert_eq!(envelope["sourcetype"], "adr:json");
        assert_eq!(envelope["source"], "telltale:adr-events");
        assert_eq!(envelope["host"], "developer-workstation");
        assert_eq!(envelope["time"], 1_779_069_600.0);
        assert_eq!(envelope["event"]["event_type"], "health");
        assert_eq!(envelope["event"]["schema_version"], "2.0");
        assert!(envelope["event"].get("index").is_none());
        assert!(envelope["event"].get("sourcetype").is_none());
    }

    #[test]
    fn splunk_hec_http_sink_posts_batched_envelopes_to_collector() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock hec listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let addr = listener.local_addr().expect("listener addr");
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .expect("read timeout");
                        let mut request = Vec::new();
                        let mut buf = [0_u8; 1024];
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
                        tx.send(String::from_utf8_lossy(&request).to_string())
                            .expect("request capture");
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"text\":\"ok\"}\n",
                            )
                            .expect("mock hec response");
                        return;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(err) => panic!("mock hec accept failed: {err}"),
                }
            }
            panic!("mock hec listener timed out");
        });

        let mut first = make_health_event();
        first.timestamp = "2026-05-18T02:00:00.000Z".to_string();
        let mut second = make_health_event();
        second.timestamp = "2026-05-18T02:05:00.000Z".to_string();
        let sink = SplunkHecHttpSink::new(
            format!("http://{addr}/services/collector"),
            "test-token".to_string(),
            SplunkHecConfig::default(),
        )
        .with_timeout(Duration::from_secs(2));

        emit_events(&sink, &[first, second]).expect("emit hec events");
        let request = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        handle.join().expect("mock hec join");

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
        // Both envelopes arrive in one newline-batched request body.
        let body = request.split_once("\r\n\r\n").expect("body split").1;
        let envelopes: Vec<serde_json::Value> = body
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("hec envelope"))
            .collect();
        assert_eq!(envelopes.len(), 2);
        for envelope in &envelopes {
            assert_eq!(envelope["index"], "adr");
            assert_eq!(envelope["sourcetype"], "adr:json");
            assert_eq!(envelope["event"]["event_type"], "health");
        }
    }

    #[test]
    fn splunk_hec_non_success_error_excludes_response_body() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock hec listener");
        let addr = listener.local_addr().expect("mock hec addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
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
}
