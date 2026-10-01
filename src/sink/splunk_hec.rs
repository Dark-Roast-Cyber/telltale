use std::time::Duration;

use serde::Serialize;
use uuid::Uuid;

use crate::event::{EmittableEvent, Event, parse_event_timestamp};
use crate::sink::http::{HttpClient, HttpResponse, RetryConfig, TlsOptions, chunk_segments};
use crate::sink::{DeliveryError, DeliveryErrorClass, EventSink};

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

    #[cfg(test)]
    fn with_timeout(mut self, timeout: Duration) -> Self {
        self.client = HttpClient::new(timeout, RetryConfig::default(), &TlsOptions::default())
            .expect("default http client");
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
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

    fn post_once(&self, headers: &[(&str, &str)], body: &[u8]) -> Result<(), DeliveryError> {
        let response = self
            .client
            .post_once(&self.url, headers, "application/json", body)
            .map_err(splunk_transport_error)?;
        splunk_response_result(&response)
    }

    fn post(&self, headers: &[(&str, &str)], body: &[u8]) -> Result<(), DeliveryError> {
        let retry = self.client.retry_config();
        let mut delay = Duration::from_millis(retry.base_delay_ms);
        let mut last_response_error = None;
        // One budget covers transport, HTTP, and HEC application failures.
        for attempt in 1..=retry.max_attempts.max(1) {
            match self.post_once(headers, body) {
                Ok(()) => return Ok(()),
                Err(mut error) => {
                    let no_response = matches!(
                        error.class,
                        DeliveryErrorClass::TransportNoResponse | DeliveryErrorClass::Timeout
                    );
                    error.attempts = attempt;
                    let retryable = match error.class {
                        DeliveryErrorClass::HttpStatus { status } => {
                            status == 429 || (500..600).contains(&status)
                        }
                        class => class.is_retryable(),
                    };
                    if !retryable || attempt == retry.max_attempts.max(1) {
                        if no_response {
                            // Preserve the last observed rejection when later attempts obtain no response.
                            error = last_response_error.unwrap_or(error);
                            error.attempts = attempt;
                        }
                        return Err(error);
                    }
                    if !no_response {
                        last_response_error = Some(error);
                    }
                    std::thread::sleep(delay);
                    delay = delay.saturating_mul(2);
                }
            }
        }
        unreachable!("at least one attempt")
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
            self.post(&headers, &chunk)?;
        }
        Ok(())
    }

    fn emit_canonical_once(&self, payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let body = splunk_hec_envelope_bytes(payload, &self.config)?;
        let auth = format!("Splunk {}", self.token);
        let headers = [
            ("Authorization", auth.as_str()),
            ("X-Splunk-Request-Channel", self.request_channel.as_str()),
        ];
        self.post_once(&headers, &body)?;
        Ok(())
    }
}

fn splunk_response_result(response: &HttpResponse) -> Result<(), DeliveryError> {
    if !(200..300).contains(&response.status) {
        return Err(splunk_status_error(response.status, response.attempts));
    }
    // Never carry response text or JSON parser errors across the diagnostic boundary.
    let code = serde_json::from_str::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|value| value.as_object()?.get("code")?.as_i64());
    let class = match code {
        Some(0) => return Ok(()),
        Some(1..=4 | 21..=22) => DeliveryErrorClass::AuthenticationBlocked {
            status: response.status,
        },
        Some(5..=7 | 10..=16) => DeliveryErrorClass::SinkApplicationRejected,
        Some(8..=9 | 17..=20 | 23..=27) => DeliveryErrorClass::SinkApplicationRetryable,
        _ => DeliveryErrorClass::SinkResponseBlocked,
    };
    let detail = match code {
        Some(code) => format!("HEC code {code}"),
        None => "invalid HEC response".to_string(),
    };
    Err(DeliveryError::new(
        class,
        response.attempts,
        format!(
            "Splunk HEC request failed with HTTP {}: {detail}",
            response.status
        ),
    ))
}

fn splunk_transport_error(err: crate::sink::http::HttpPostError) -> DeliveryError {
    let class = match err.kind {
        crate::sink::http::HttpPostErrorKind::NoResponse => DeliveryErrorClass::TransportNoResponse,
        crate::sink::http::HttpPostErrorKind::Timeout => DeliveryErrorClass::Timeout,
    };
    DeliveryError::new(
        class,
        err.attempts,
        format!("Splunk HEC request failed: {}", err.message),
    )
}

fn splunk_status_error(status: u16, attempts: u32) -> DeliveryError {
    let class = match status {
        401 | 403 => DeliveryErrorClass::AuthenticationBlocked { status },
        status => DeliveryErrorClass::HttpStatus { status },
    };
    DeliveryError::new(
        class,
        attempts,
        format!("Splunk HEC request failed with HTTP {status}"),
    )
}

fn append_json_field<T: serde::Serialize>(
    output: &mut Vec<u8>,
    first: &mut bool,
    name: &str,
    value: &T,
) -> Result<(), serde_json::Error> {
    if !*first {
        output.push(b',');
    }
    output.extend_from_slice(&serde_json::to_vec(name)?);
    output.push(b':');
    output.extend_from_slice(&serde_json::to_vec(value)?);
    *first = false;
    Ok(())
}

/// Wrap stored canonical Event 3.0 bytes in the HEC envelope without parsing
/// and reserializing the event body. The optional timestamp is read only to
/// preserve the existing HEC metadata behavior.
fn splunk_hec_envelope_bytes(
    payload: &[u8],
    config: &SplunkHecConfig,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_slice(payload).map_err(|error| {
        Box::new(DeliveryError::new(
            DeliveryErrorClass::SinkApplicationRejected,
            1,
            format!("canonical Splunk HEC payload is invalid: {error}"),
        )) as Box<dyn std::error::Error>
    })?;
    if !value.is_object() {
        return Err(DeliveryError::new(
            DeliveryErrorClass::SinkApplicationRejected,
            1,
            "canonical Splunk HEC payload is not an Event object",
        )
        .into());
    }

    let mut output = vec![b'{'];
    let mut first = true;
    if let Some(time) = value
        .get("timestamp")
        .and_then(serde_json::Value::as_str)
        .and_then(splunk_hec_time)
    {
        append_json_field(&mut output, &mut first, "time", &time)?;
    }
    if let Some(host) = config.host.as_deref() {
        append_json_field(&mut output, &mut first, "host", &host)?;
    }
    if let Some(index) = config.index.as_deref() {
        append_json_field(&mut output, &mut first, "index", &index)?;
    }
    append_json_field(&mut output, &mut first, "sourcetype", &config.sourcetype)?;
    if let Some(source) = config.source.as_deref() {
        append_json_field(&mut output, &mut first, "source", &source)?;
    }
    if !first {
        output.push(b',');
    }
    output.extend_from_slice(b"\"event\":");
    output.extend_from_slice(payload);
    output.push(b'}');
    Ok(output)
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
            index: Some("telltale".to_string()),
            sourcetype: "telltale:json".to_string(),
            source: Some("telltale".to_string()),
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
    pub event: EmittableEvent<'a>,
}

impl<'a> SplunkHecEnvelope<'a> {
    fn new(event: &'a Event, config: &'a SplunkHecConfig) -> Self {
        Self {
            time: splunk_hec_time(&event.timestamp),
            host: config.host.as_deref(),
            index: config.index.as_deref(),
            sourcetype: &config.sourcetype,
            source: config.source.as_deref(),
            event: event.emittable(),
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
    use std::net::{TcpListener, TcpStream};
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

    fn read_mock_request(stream: &mut TcpStream) -> Vec<u8> {
        // Accepted sockets may inherit nonblocking mode on macOS and Windows.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let count = stream.read(&mut buffer).expect("read request");
            assert_ne!(count, 0);
            request.extend_from_slice(&buffer[..count]);
            if let Some(split) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..split]).to_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                if request.len() >= split + 4 + length {
                    return request;
                }
            }
        }
    }

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
        let sink =
            SplunkHecHttpSink::new(url, "test-token".to_string(), SplunkHecConfig::default())
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
}
