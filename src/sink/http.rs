//! Minimal HTTP client for network sinks: endpoint validation, bounded retry
//! with structured error classes, TLS options and batch chunking.

use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

/// Retry policy for network sink requests: `max_attempts` total attempts with
/// exponential backoff starting at `base_delay_ms`.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub base_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_ms: 500,
        }
    }
}

/// TLS options for network sinks. `ca_file` replaces the built-in webpki roots
/// with the PEM certificates in the file (corporate CA). `insecure_skip_verify`
/// disables certificate verification entirely and is only for lab use.
#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    pub ca_file: Option<PathBuf>,
    pub insecure_skip_verify: bool,
    /// Explicit lab-only consent to send telemetry and credentials over remote HTTP.
    pub allow_insecure_http: bool,
}

pub(crate) fn validate_endpoint(
    endpoint: &str,
    allow_insecure_http: bool,
) -> Result<ureq::http::Uri, &'static str> {
    let uri: ureq::http::Uri = endpoint.parse().map_err(|_| "invalid HTTP endpoint")?;
    if endpoint.contains('#')
        || uri.authority().is_none()
        || uri.authority().is_some_and(|a| a.as_str().contains('@'))
    {
        return Err("HTTP endpoint must not contain credentials or fragments");
    }
    let host = uri.host().ok_or("HTTP endpoint requires a host")?;
    let loopback = host
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback());
    match uri.scheme_str() {
        Some("https") => Ok(uri),
        Some("http") if loopback || allow_insecure_http => Ok(uri),
        Some("http") => Err(
            "non-loopback HTTP requires explicit lab-only tls.allow_insecure_http consent; use HTTPS",
        ),
        _ => Err("endpoint must use http:// or https://"),
    }
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub attempts: u32,
}

/// A transport-level failure after retries were exhausted.
#[derive(Debug)]
pub struct HttpPostError {
    pub attempts: u32,
    pub kind: HttpPostErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HttpPostErrorKind {
    NoResponse,
    Timeout,
}

impl std::fmt::Display for HttpPostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (after {} attempts)", self.message, self.attempts)
    }
}

impl std::error::Error for HttpPostError {}

/// Synchronous HTTP client shared by the network sinks: ureq with rustls,
/// a global timeout, and retry with exponential backoff on transport errors
/// and retryable statuses (429 and 5xx).
pub struct HttpClient {
    agent: ureq::Agent,
    retry: RetryConfig,
    allow_insecure_http: bool,
}

impl HttpClient {
    pub(crate) fn retry_config(&self) -> &RetryConfig {
        &self.retry
    }

    pub fn new(
        timeout: Duration,
        retry: RetryConfig,
        tls: &TlsOptions,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_warning(timeout, retry, tls, true)
    }

    pub(crate) fn new_with_warning(
        timeout: Duration,
        retry: RetryConfig,
        tls: &TlsOptions,
        emit_warning: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut builder = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .max_redirects(0)
            .http_status_as_error(false);
        if tls.allow_insecure_http && emit_warning {
            eprintln!(
                "warning: remote plaintext HTTP is enabled; credentials and telemetry are exposed outside a lab"
            );
        }
        if tls.ca_file.is_some() || tls.insecure_skip_verify {
            let mut tls_builder = ureq::tls::TlsConfig::builder();
            if let Some(ca_file) = &tls.ca_file {
                let pem = fs::read(ca_file).map_err(|err| {
                    format!("could not read tls ca_file {}: {err}", ca_file.display())
                })?;
                let mut certs = Vec::new();
                for item in ureq::tls::parse_pem(&pem) {
                    let item = item.map_err(|err| {
                        format!("invalid PEM in tls ca_file {}: {err}", ca_file.display())
                    })?;
                    if let ureq::tls::PemItem::Certificate(cert) = item {
                        certs.push(cert);
                    }
                }
                if certs.is_empty() {
                    return Err(format!(
                        "tls ca_file {} contains no certificates",
                        ca_file.display()
                    )
                    .into());
                }
                tls_builder = tls_builder.root_certs(ureq::tls::RootCerts::new_with_certs(&certs));
            }
            if tls.insecure_skip_verify {
                if emit_warning {
                    eprintln!(
                        "warning: TLS certificate verification is disabled (insecure_skip_verify); this is unsafe outside a lab"
                    );
                }
                tls_builder = tls_builder.disable_verification(true);
            }
            builder = builder.tls_config(tls_builder.build());
        }
        Ok(Self {
            agent: builder.build().new_agent(),
            retry,
            allow_insecure_http: tls.allow_insecure_http,
        })
    }

    fn post_once_inner(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<HttpResponse, HttpPostError> {
        let uri =
            validate_endpoint(url, self.allow_insecure_http).map_err(|message| HttpPostError {
                attempts: 0,
                kind: HttpPostErrorKind::NoResponse,
                message: message.into(),
            })?;
        let mut request = self.agent.post(url).content_type(content_type);
        if uri.scheme_str() == Some("http") {
            // Never let an ambient proxy turn loopback's plaintext exemption
            // into remote delivery. HTTPS retains its established proxy support.
            request = request.config().proxy(None).build();
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        match request.send(body) {
            Ok(mut response) => {
                let status = response.status().as_u16();
                let body = response
                    .body_mut()
                    .read_to_string()
                    .unwrap_or_else(|err| format!("<unreadable response body: {err}>"));
                Ok(HttpResponse {
                    status,
                    body,
                    attempts: 1,
                })
            }
            Err(err) => {
                let kind = if matches!(&err, ureq::Error::Timeout(_)) {
                    HttpPostErrorKind::Timeout
                } else {
                    HttpPostErrorKind::NoResponse
                };
                Err(HttpPostError {
                    attempts: 1,
                    kind,
                    message: err.to_string(),
                })
            }
        }
    }

    /// POST a body exactly once. Durable delivery owns retry scheduling, so
    /// this operation never sleeps or retries a response/status.
    pub fn post_once(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<HttpResponse, HttpPostError> {
        self.post_once_inner(url, headers, content_type, body)
    }

    /// POST a body, retrying transport errors, 429, and 5xx with exponential
    /// backoff. Returns the final response (which may still be non-2xx for
    /// non-retryable statuses, or a retryable status once attempts are
    /// exhausted); `Err` means no response was obtained at all.
    pub fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<HttpResponse, HttpPostError> {
        let max_attempts = self.retry.max_attempts.max(1);
        let mut delay = Duration::from_millis(self.retry.base_delay_ms);
        let mut last_error = None;
        let mut last_response = None;
        for attempt in 1..=max_attempts {
            if attempt > 1 {
                thread::sleep(delay);
                delay *= 2;
            }
            match self.post_once_inner(url, headers, content_type, body) {
                Ok(mut response) => {
                    response.attempts = attempt;
                    if is_retryable_status(response.status) && attempt < max_attempts {
                        last_response = Some(response);
                        continue;
                    }
                    return Ok(response);
                }
                Err(err) => {
                    last_error = Some((err.kind, err.message));
                    continue;
                }
            }
        }
        if let Some(response) = last_response {
            return Ok(HttpResponse {
                attempts: max_attempts,
                ..response
            });
        }
        let (kind, message) =
            last_error.unwrap_or((HttpPostErrorKind::NoResponse, "request failed".to_string()));
        Err(HttpPostError {
            attempts: max_attempts,
            kind,
            message,
        })
    }
}

fn is_retryable_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

/// Group per-event payload segments into request bodies of at most
/// `max_bytes`, joining segments with newlines (and a trailing newline, as the
/// Elasticsearch bulk API requires and Splunk HEC tolerates). A single
/// oversized segment is sent alone rather than split.
pub fn chunk_segments(segments: &[Vec<u8>], max_bytes: usize) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for segment in segments {
        if !current.is_empty() && current.len() + segment.len() + 1 > max_bytes {
            chunks.push(std::mem::take(&mut current));
        }
        current.extend_from_slice(segment);
        current.push(b'\n');
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

#[cfg(test)]
mod tests;
