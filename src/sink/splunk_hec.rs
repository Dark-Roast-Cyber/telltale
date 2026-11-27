//! Splunk HTTP Event Collector sink. Wraps each canonical payload in a HEC
//! envelope whose `time` comes from the event `timestamp`.

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
        300..=399 => DeliveryErrorClass::SinkResponseBlocked,
        401 | 403 => DeliveryErrorClass::AuthenticationBlocked { status },
        status => DeliveryErrorClass::HttpStatus { status },
    };
    DeliveryError::new(
        class,
        attempts,
        format!("Splunk HEC request failed with HTTP {status}"),
    )
}

#[test]
fn redirects_are_releasable_not_poison() {
    for status in [301, 302, 303, 307, 308] {
        assert_eq!(
            splunk_status_error(status, 1).class,
            DeliveryErrorClass::SinkResponseBlocked
        );
    }
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
mod tests;
