//! Test support shared by the sink test modules: the standard synthetic
//! health event and the reader for one request sent to a mock HTTP server.

use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use crate::event::{Event, HealthEventInput, health_event_with_metadata};

pub(crate) fn make_health_event() -> Event {
    health_event_with_metadata(HealthEventInput {
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

/// Reads one request from a stream a mock server accepted: the headers and
/// the body their Content-Length announces (no body when it is missing).
/// Panics on a read error, the 2-second read timeout or an early end of stream.
/// `splunk_hec`'s `mock_request_reader_handles_nonblocking_socket_and_fragmented_request`
/// guards it.
pub(crate) fn read_mock_request(stream: &mut TcpStream) -> Vec<u8> {
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
            let length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if request.len() >= split + 4 + length {
                return request;
            }
        }
    }
}
