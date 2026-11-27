//! Elasticsearch bulk sink. Indexes the canonical payload with `_id` set to
//! `event_id` and validates per-item bulk results.

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
        300..=399 => DeliveryErrorClass::SinkResponseBlocked,
        401 | 403 => DeliveryErrorClass::AuthenticationBlocked { status },
        status => DeliveryErrorClass::HttpStatus { status },
    };
    DeliveryError::new(
        class,
        attempts,
        format!("Elasticsearch bulk request failed with HTTP {status}"),
    )
}

#[test]
fn redirects_are_releasable_not_poison() {
    for status in [301, 302, 303, 307, 308] {
        assert_eq!(
            elastic_status_error(status, 1).class,
            DeliveryErrorClass::SinkResponseBlocked
        );
    }
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
mod tests;
