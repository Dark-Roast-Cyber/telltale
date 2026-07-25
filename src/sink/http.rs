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
    pub message: String,
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
}

impl HttpClient {
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
            .http_status_as_error(false);
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
        })
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
            let mut request = self.agent.post(url).content_type(content_type);
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
                    let response = HttpResponse {
                        status,
                        body,
                        attempts: attempt,
                    };
                    if is_retryable_status(status) && attempt < max_attempts {
                        last_response = Some(response);
                        continue;
                    }
                    return Ok(response);
                }
                Err(err) => {
                    last_error = Some(err.to_string());
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
        Err(HttpPostError {
            attempts: max_attempts,
            message: last_error.unwrap_or_else(|| "request failed".to_string()),
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
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use super::{HttpClient, RetryConfig, TlsOptions, chunk_segments, is_retryable_status};

    /// Mock HTTP server answering each connection with the next status in
    /// `statuses`, then exiting.
    fn start_mock_server(statuses: Vec<u16>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock listener");
        let addr = listener.local_addr().expect("mock addr");
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for status in statuses {
                let (mut stream, _) = listener.accept().expect("accept");
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
                requests.push(String::from_utf8_lossy(&request).to_string());
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                );
                stream.write_all(response.as_bytes()).expect("respond");
            }
            requests
        });
        (format!("http://{addr}/ingest"), handle)
    }

    fn fast_retry(max_attempts: u32) -> RetryConfig {
        RetryConfig {
            max_attempts,
            base_delay_ms: 1,
        }
    }

    #[test]
    fn post_retries_5xx_until_success() {
        let (url, handle) = start_mock_server(vec![500, 500, 200]);
        let client = HttpClient::new(
            Duration::from_secs(2),
            fast_retry(3),
            &TlsOptions::default(),
        )
        .expect("client");

        let response = client
            .post(
                &url,
                &[("Authorization", "Bearer x")],
                "application/json",
                b"{}",
            )
            .expect("response");

        assert_eq!(response.status, 200);
        assert_eq!(response.attempts, 3);
        let requests = handle.join().expect("mock join");
        assert_eq!(requests.len(), 3);
        assert!(
            requests[0]
                .to_lowercase()
                .contains("authorization: bearer x")
        );
    }

    #[test]
    fn post_returns_last_retryable_status_after_exhaustion() {
        let (url, handle) = start_mock_server(vec![503, 503]);
        let client = HttpClient::new(
            Duration::from_secs(2),
            fast_retry(2),
            &TlsOptions::default(),
        )
        .expect("client");

        let response = client
            .post(&url, &[], "application/json", b"{}")
            .expect("response");

        assert_eq!(response.status, 503);
        assert_eq!(response.attempts, 2);
        handle.join().expect("mock join");
    }

    #[test]
    fn post_does_not_retry_non_retryable_status() {
        let (url, handle) = start_mock_server(vec![401]);
        let client = HttpClient::new(
            Duration::from_secs(2),
            fast_retry(3),
            &TlsOptions::default(),
        )
        .expect("client");

        let response = client
            .post(&url, &[], "application/json", b"{}")
            .expect("response");

        assert_eq!(response.status, 401);
        assert_eq!(response.attempts, 1);
        let requests = handle.join().expect("mock join");
        assert_eq!(requests.len(), 1);
    }

    #[test]
    fn post_errors_with_attempt_count_when_unreachable() {
        // Bind and drop a listener so the port is closed.
        let addr = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("probe listener");
            listener.local_addr().expect("probe addr")
        };
        let client = HttpClient::new(
            Duration::from_secs(1),
            fast_retry(2),
            &TlsOptions::default(),
        )
        .expect("client");

        let err = client
            .post(&format!("http://{addr}/x"), &[], "application/json", b"{}")
            .expect_err("unreachable");

        assert_eq!(err.attempts, 2);
    }

    #[test]
    fn missing_ca_file_fails_client_construction() {
        let err = HttpClient::new(
            Duration::from_secs(1),
            RetryConfig::default(),
            &TlsOptions {
                ca_file: Some("/nonexistent/ca.pem".into()),
                insecure_skip_verify: false,
            },
        )
        .err()
        .expect("missing ca file must error");
        assert!(err.to_string().contains("ca_file"));
    }

    #[test]
    fn chunk_segments_respects_byte_cap() {
        let segments = vec![vec![b'a'; 10], vec![b'b'; 10], vec![b'c'; 10]];
        // Cap fits one 10-byte segment plus newline per chunk.
        let chunks = chunk_segments(&segments, 15);
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|chunk| chunk.ends_with(b"\n")));

        // A large cap keeps everything in one newline-joined chunk.
        let chunks = chunk_segments(&segments, 1024);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 33);

        // An oversized single segment is sent alone, not split.
        let oversized = vec![vec![b'x'; 100]];
        let chunks = chunk_segments(&oversized, 15);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 101);
    }

    #[test]
    fn retryable_statuses_are_429_and_5xx() {
        assert!(is_retryable_status(429));
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(503));
        assert!(!is_retryable_status(200));
        assert!(!is_retryable_status(400));
        assert!(!is_retryable_status(401));
    }
}
