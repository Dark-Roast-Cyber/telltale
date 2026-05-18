use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::event::{Event, append_jsonl_events, parse_event_timestamp};

pub trait EventSink {
    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>>;
}

pub struct LocalJsonlSink<'a> {
    path: &'a Path,
}

impl<'a> LocalJsonlSink<'a> {
    pub fn new(path: &'a Path) -> Self {
        Self { path }
    }
}

impl EventSink for LocalJsonlSink<'_> {
    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        append_jsonl_events(self.path, events)
    }
}

pub struct SplunkHecHttpSink {
    endpoint: String,
    token: String,
    config: SplunkHecConfig,
    timeout: Duration,
}

impl SplunkHecHttpSink {
    pub fn new(endpoint: String, token: String, config: SplunkHecConfig) -> Self {
        Self {
            endpoint,
            token,
            config,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl EventSink for SplunkHecHttpSink {
    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
        for envelope in splunk_hec_envelopes(events, &self.config) {
            send_splunk_hec_envelope(&self.endpoint, &self.token, &envelope, self.timeout)?;
        }
        Ok(())
    }
}

pub fn emit_events(
    sink: &dyn EventSink,
    events: &[Event],
) -> Result<(), Box<dyn std::error::Error>> {
    sink.emit(events)
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

fn send_splunk_hec_envelope(
    endpoint: &str,
    token: &str,
    envelope: &SplunkHecEnvelope<'_>,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let (host, port, path) = parse_http_endpoint(endpoint)?;
    let address = (host.as_str(), port)
        .to_socket_addrs()?
        .next()
        .ok_or("could not resolve Splunk HEC host")?;
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let payload = serde_json::to_vec(envelope)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nAuthorization: Splunk {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        host,
        port,
        token,
        payload.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(&payload)?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status_line = response
        .lines()
        .next()
        .ok_or("invalid Splunk HEC response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("missing Splunk HEC response status")?
        .parse::<u16>()?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("Splunk HEC request failed with HTTP {status}").into())
    }
}

fn parse_http_endpoint(
    endpoint: &str,
) -> Result<(String, u16, String), Box<dyn std::error::Error>> {
    let endpoint = endpoint
        .strip_prefix("http://")
        .ok_or("only http:// Splunk HEC endpoints are supported")?;
    let (host_port, path) = match endpoint.split_once('/') {
        Some((host_port, rest)) => (host_port, format!("/{}", rest)),
        None => (endpoint, "/services/collector".to_string()),
    };
    let (host, port) = match host_port.split_once(':') {
        Some((host, port)) => (host.to_string(), port.parse()?),
        None => (host_port.to_string(), 8088),
    };
    Ok((host, port, path))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use tempfile::tempdir;

    use crate::event::health_event_with_metadata;
    use crate::sink::{
        LocalJsonlSink, SplunkHecConfig, SplunkHecHttpSink, emit_events, splunk_hec_envelopes,
    };

    #[test]
    fn local_jsonl_sink_appends_canonical_events() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("logs/adr-events.jsonl");
        let sink = LocalJsonlSink::new(&log_path);
        let event = health_event_with_metadata(crate::event::HealthEventInput {
            sources: &[],
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
        });

        emit_events(&sink, &[event]).expect("emit events");

        let output = std::fs::read_to_string(log_path).expect("jsonl output");
        assert_eq!(output.lines().count(), 1);
        assert!(output.contains("\"event_type\":\"health\""));
    }

    #[test]
    fn splunk_hec_envelope_wraps_canonical_event_with_transport_metadata() {
        let mut event = health_event_with_metadata(crate::event::HealthEventInput {
            sources: &[],
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
        });
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
        assert_eq!(envelope["event"]["schema_version"], "1.0");
        assert!(envelope["event"].get("index").is_none());
        assert!(envelope["event"].get("sourcetype").is_none());
    }

    #[test]
    fn splunk_hec_http_sink_posts_envelope_to_collector() {
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
                            let text = String::from_utf8_lossy(&request);
                            if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                                let content_length = headers
                                    .lines()
                                    .find_map(|line| line.strip_prefix("Content-Length: "))
                                    .and_then(|value| value.parse::<usize>().ok())
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

        let mut event = health_event_with_metadata(crate::event::HealthEventInput {
            sources: &[],
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
        });
        event.timestamp = "2026-05-18T02:00:00.000Z".to_string();
        let sink = SplunkHecHttpSink::new(
            format!("http://{addr}/services/collector"),
            "test-token".to_string(),
            SplunkHecConfig::default(),
        )
        .with_timeout(Duration::from_secs(2));

        emit_events(&sink, &[event]).expect("emit hec event");
        let request = rx.recv_timeout(Duration::from_secs(2)).expect("request");
        handle.join().expect("mock hec join");

        assert!(request.starts_with("POST /services/collector HTTP/1.1"));
        assert!(request.contains("Authorization: Splunk test-token"));
        assert!(request.contains("Content-Type: application/json"));
        let body = request.split_once("\r\n\r\n").expect("body split").1;
        let envelope: serde_json::Value = serde_json::from_str(body).expect("hec body");
        assert_eq!(envelope["index"], "adr");
        assert_eq!(envelope["sourcetype"], "adr:json");
        assert_eq!(envelope["event"]["event_type"], "health");
    }
}
