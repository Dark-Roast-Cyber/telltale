use std::io::Write;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use super::{HttpClient, RetryConfig, TlsOptions, chunk_segments, is_retryable_status};
use crate::sink::test_support::read_mock_request;

/// Mock HTTP server answering each connection with the next status in
/// `statuses`, then exiting.
fn start_mock_server(statuses: Vec<u16>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock listener");
    let addr = listener.local_addr().expect("mock addr");
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for status in statuses {
            let (mut stream, _) = listener.accept().expect("accept");
            let request = read_mock_request(&mut stream);
            requests.push(String::from_utf8_lossy(&request).to_string());
            let response =
                format!("HTTP/1.1 {status} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            stream.write_all(response.as_bytes()).expect("respond");
        }
        requests
    });
    (format!("http://{addr}/ingest"), handle)
}

/// Mock HTTP server accepting each connection and closing it without a response.
fn start_closing_server(connections: usize) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock listener");
    let addr = listener.local_addr().expect("mock addr");
    let handle = thread::spawn(move || {
        for _ in 0..connections {
            let (stream, _) = listener.accept().expect("accept");
            drop(stream);
        }
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
fn endpoint_policy_is_structural_and_plaintext_consent_is_explicit() {
    for endpoint in [
        "http://127.0.0.1:9999/ingest",
        "http://[::1]/ingest",
        "https://collector.example.invalid/ingest",
    ] {
        assert!(super::validate_endpoint(endpoint, false).is_ok());
    }
    for endpoint in [
        "http://collector.example.invalid",
        "http://localhost/",
        "http://127.0.0.1.example.invalid",
        "http://127.1/",
    ] {
        assert!(super::validate_endpoint(endpoint, false).is_err());
        assert!(super::validate_endpoint(endpoint, true).is_ok());
    }
    for endpoint in [
        "https://user:synthetic@collector.example.invalid",
        "https://collector.example.invalid/#fragment",
        "file:///synthetic",
        "https:///missing",
        "not-a-url",
    ] {
        assert!(
            super::validate_endpoint(endpoint, true).is_err(),
            "{endpoint}"
        );
    }
}

#[test]
fn redirects_never_forward_authorization_or_payload() {
    for status in [301, 302, 303, 307, 308] {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/ingest", listener.local_addr().unwrap());
        let location = format!("http://{}/redirected", destination.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_mock_request(&mut stream);
            write!(stream, "HTTP/1.1 {status} Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let client = HttpClient::new(
            Duration::from_secs(2),
            fast_retry(1),
            &TlsOptions::default(),
        )
        .unwrap();
        let response = client.post_once(
            &url,
            &[("Authorization", "Bearer synthetic")],
            "application/json",
            b"{}",
        );
        server.join().unwrap();
        assert_eq!(response.unwrap().status, status);
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
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
fn post_retries_429_until_success() {
    let (url, handle) = start_mock_server(vec![429, 200]);
    let client = HttpClient::new(
        Duration::from_secs(2),
        fast_retry(2),
        &TlsOptions::default(),
    )
    .expect("client");

    let response = client
        .post(&url, &[], "application/json", b"{}")
        .expect("response");

    assert_eq!(response.status, 200);
    assert_eq!(response.attempts, 2);
    assert_eq!(handle.join().expect("mock join").len(), 2);
}

#[test]
fn post_once_does_not_retry_a_retryable_status() {
    let (url, handle) = start_mock_server(vec![503]);
    let client = HttpClient::new(
        Duration::from_secs(2),
        fast_retry(3),
        &TlsOptions::default(),
    )
    .expect("client");

    let response = client
        .post_once(&url, &[], "application/json", b"{}")
        .expect("one response");

    assert_eq!(response.status, 503);
    assert_eq!(response.attempts, 1);
    assert_eq!(handle.join().expect("mock join").len(), 1);
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
fn post_errors_with_attempt_count_when_peer_closes_without_response() {
    let (url, handle) = start_closing_server(2);
    let client = HttpClient::new(
        Duration::from_secs(1),
        fast_retry(2),
        &TlsOptions::default(),
    )
    .expect("client");

    let err = client
        .post(&url, &[], "application/json", b"{}")
        .expect_err("unreachable");
    handle.join().expect("mock join");

    assert_eq!(err.attempts, 2);
    assert_eq!(err.kind, super::HttpPostErrorKind::NoResponse);
}

#[test]
fn missing_ca_file_fails_client_construction() {
    let err = HttpClient::new(
        Duration::from_secs(1),
        RetryConfig::default(),
        &TlsOptions {
            ca_file: Some("/nonexistent/ca.pem".into()),
            insecure_skip_verify: false,
            allow_insecure_http: false,
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
