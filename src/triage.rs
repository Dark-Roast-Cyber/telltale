use std::env;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::thread;
use std::time::Duration;

use serde_json::Value;

use crate::event::{Event, redact_sensitive_text};

const DEFAULT_TRIAGE_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_TRIAGE_MAX_RETRIES: u32 = 2;
const DEFAULT_TRIAGE_RETRY_BASE_DELAY_MS: u64 = 100;

#[derive(Clone)]
pub struct TriageConfig {
    pub api_base: String,
    pub api_key: String,
    pub model: String,
    pub guard_model: String,
    pub request_timeout_ms: u64,
    pub max_retries: u32,
}

impl fmt::Debug for TriageConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TriageConfig")
            .field("api_base", &self.api_base)
            .field("api_key", &"<redacted>")
            .field("model", &self.model)
            .field("guard_model", &self.guard_model)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("max_retries", &self.max_retries)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct TriageOutcome {
    pub verdict: String,
    pub confidence: f64,
    pub reason: String,
}

pub fn maybe_triage(event: &Event) -> Result<Option<TriageOutcome>, Box<dyn std::error::Error>> {
    if !matches!(event.event_type.as_str(), "detection") || event.triage.is_none() {
        return Ok(None);
    }
    let config = match load_config() {
        Ok(Some(config)) => config,
        Ok(None) => return Ok(None),
        Err(_) => return Ok(None),
    };
    maybe_triage_with_config(config, event).or(Ok(None))
}

pub fn maybe_triage_with_config(
    config: TriageConfig,
    event: &Event,
) -> Result<Option<TriageOutcome>, Box<dyn std::error::Error>> {
    maybe_triage_with_chat(config, event, chat_completion)
}

fn maybe_triage_with_chat<F>(
    config: TriageConfig,
    event: &Event,
    chat: F,
) -> Result<Option<TriageOutcome>, Box<dyn std::error::Error>>
where
    F: Fn(&TriageConfig, &str, String) -> Result<Value, Box<dyn std::error::Error>>,
{
    let context = build_context(event);
    let guard = chat(&config, &config.guard_model, guard_prompt(&context))?;
    let _triage = chat(&config, &config.model, triage_prompt(&context))?;
    let guard_content = extract_content(&guard);
    let verdict = guard_content
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let confidence = guard_content
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let reason = guard_content
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(Some(TriageOutcome {
        verdict,
        confidence,
        reason,
    }))
}

pub fn load_config() -> Result<Option<TriageConfig>, Box<dyn std::error::Error>> {
    load_config_from(Path::new(".env"))
}

pub fn load_config_from(path: &Path) -> Result<Option<TriageConfig>, Box<dyn std::error::Error>> {
    load_dotenv_if_present(path)?;
    let api_base = match env::var("LITELLM_API_BASE") {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let api_key = env::var("LITELLM_API_KEY")?;
    let model = env::var("MODEL")?;
    let guard_model = env::var("LLAMA_GUARD_MODEL")?;
    let request_timeout_ms =
        read_env_u64("ADR_TRIAGE_TIMEOUT_MS", DEFAULT_TRIAGE_TIMEOUT_MS).max(1);
    let max_retries = read_env_u32("ADR_TRIAGE_MAX_RETRIES", DEFAULT_TRIAGE_MAX_RETRIES);
    Ok(Some(TriageConfig {
        api_base,
        api_key,
        model,
        guard_model,
        request_timeout_ms,
        max_retries,
    }))
}

fn read_env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn read_env_u32(name: &str, default: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(default)
}

fn load_dotenv_if_present(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim().trim_matches('"');
            unsafe { env::set_var(key.trim(), value) };
        }
    }
    Ok(())
}

fn build_context(event: &Event) -> String {
    let mut parts = vec![
        format!("client={}", event.client),
        format!("session_id={}", event.session_id),
        format!("severity={}", event.severity),
        format!("risk_score={}", event.risk_score),
    ];
    if let Some(tool_name) = &event.tool_name {
        parts.push(format!("tool_name={tool_name}"));
    }
    if let Some(provider) = &event.provider {
        parts.push(format!("provider={provider}"));
    }
    if let Some(model) = &event.model {
        parts.push(format!("model={model}"));
    }
    if !event.rule_ids.is_empty() {
        parts.push(format!("matched_rules={}", event.rule_ids.join(",")));
    }
    if !event.categories.is_empty() {
        parts.push(format!("categories={}", event.categories.join(",")));
    }
    if !event.tags.is_empty() {
        parts.push(format!("tags={}", event.tags.join(",")));
    }
    parts.extend(event.evidence.iter().map(|item| {
        format!(
            "{}={}",
            item.field,
            redact_sensitive_text(&item.redacted_value)
        )
    }));
    if let Some(anchors) = event
        .triage
        .as_ref()
        .and_then(|triage| triage.get("timeline_anchors"))
        .and_then(|anchors| anchors.as_array())
    {
        parts.push(format!("timeline_anchor_count={}", anchors.len()));
        parts.extend(anchors.iter().enumerate().map(|(index, anchor)| {
            let entry_index = anchor
                .get("entry_index")
                .and_then(|value| value.as_u64())
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let fields = anchor
                .get("evidence_fields")
                .and_then(|value| value.as_array())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            format!("timeline_anchor[{index}]=entry_index:{entry_index};evidence_fields:{fields}")
        }));
    }
    parts.join("\n")
}

fn extract_content(response: &Value) -> Value {
    response
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(Value::Object(serde_json::Map::new()))
}

fn guard_prompt(context: &str) -> String {
    format!(
        "Return JSON with verdict (malicious, suspicious, benign, or unknown), severity, confidence (0.0-1.0), reason, matched_risks, and recommended_action.\n\
         Use benign when the activity is clearly safe or explained by normal development workflow.\n{}\n",
        context
    )
}

fn triage_prompt(context: &str) -> String {
    format!(
        "Decide if the detected agent activity is malicious, suspicious, or benign. Consider the matched rules, evidence, and timeline context.\n\
         Return JSON with verdict, confidence (0.0-1.0), and reason explaining your decision.\n{}\n",
        context
    )
}

fn chat_completion(
    config: &TriageConfig,
    model: &str,
    prompt: String,
) -> Result<Value, Box<dyn std::error::Error>> {
    chat_completion_with_retry(
        config,
        model,
        &prompt,
        Duration::from_millis(DEFAULT_TRIAGE_RETRY_BASE_DELAY_MS),
        send_chat_completion_request,
    )
}

fn chat_completion_with_retry<F>(
    config: &TriageConfig,
    model: &str,
    prompt: &str,
    retry_base_delay: Duration,
    mut send: F,
) -> Result<Value, Box<dyn std::error::Error>>
where
    F: FnMut(&TriageConfig, &str, &str) -> Result<Value, Box<dyn std::error::Error>>,
{
    let mut attempt = 0;
    let mut retry_delay = retry_base_delay;
    loop {
        match send(config, model, prompt) {
            Ok(value) => return Ok(value),
            Err(_err) if attempt < config.max_retries => {
                attempt += 1;
                if !retry_delay.is_zero() {
                    thread::sleep(retry_delay);
                    retry_delay = retry_delay.checked_mul(2).unwrap_or(Duration::MAX);
                }
                continue;
            }
            Err(err) => return Err(err),
        }
    }
}

fn send_chat_completion_request(
    config: &TriageConfig,
    model: &str,
    prompt: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (host, port, path) = parse_http_base(&config.api_base)?;
    let address = (host.as_str(), port)
        .to_socket_addrs()?
        .next()
        .ok_or("could not resolve triage host")?;
    let timeout = Duration::from_millis(config.request_timeout_ms);
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let body = serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a security triage assistant."},
            {"role": "user", "content": prompt}
        ]
    });
    let payload = serde_json::to_vec(&body)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        host,
        port,
        config.api_key,
        payload.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(&payload)?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let body = response
        .split_once("\r\n\r\n")
        .ok_or("invalid HTTP response")?
        .1;
    Ok(serde_json::from_str(body)?)
}

fn parse_http_base(base: &str) -> Result<(String, u16, String), Box<dyn std::error::Error>> {
    let base = base
        .strip_prefix("http://")
        .ok_or("only http:// bases are supported")?;
    let (host_port, path) = match base.split_once('/') {
        Some((host_port, rest)) => (host_port, format!("/{}", rest)),
        None => (base, "/v1/chat/completions".to_string()),
    };
    let (host, port) = match host_port.split_once(':') {
        Some((host, port)) => (host.to_string(), port.parse()?),
        None => (host_port.to_string(), 80),
    };
    Ok((host, port, path))
}

#[cfg(test)]
mod tests {
    use super::{
        TriageConfig, chat_completion_with_retry, load_config_from, maybe_triage_with_chat,
    };
    use crate::event::{DetectionEventInput, detection_event};
    use std::fs;
    use std::io;
    use std::sync::OnceLock;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use telltale_schema::clients::ClientId;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn loads_dotenv_configuration_and_runs_triage() {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let env_path = temp.path().join(".env");
        fs::write(
            &env_path,
            "LITELLM_API_BASE=http://127.0.0.1:0\nLITELLM_API_KEY=test-key\nMODEL=triage-model\nLLAMA_GUARD_MODEL=guard-model\nADR_TRIAGE_TIMEOUT_MS=2500\nADR_TRIAGE_MAX_RETRIES=4\n",
        )
        .expect("write env");

        let config = load_config_from(&env_path)
            .expect("config")
            .expect("present");
        assert_eq!(config.api_key, "test-key");
        assert_eq!(config.request_timeout_ms, 2500);
        assert_eq!(config.max_retries, 4);

        let debug = format!("{config:?}");
        assert!(!debug.contains("test-key"));
    }

    #[test]
    fn triage_client_posts_guard_and_triage_requests() {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("lock");
        let requests = Arc::new(Mutex::new(Vec::new()));

        let mut event = detection_event(DetectionEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "session".to_string(),
            source_path_hash: "hash".to_string(),
            tool_name: Some("repo_status".to_string()),
            rule_ids: vec!["rule.test".to_string()],
            categories: vec!["category".to_string()],
            detection_classes: Vec::new(),
            signal_types: Vec::new(),
            analytic_intents: Vec::new(),
            atlas_tags: Vec::new(),
            tags: vec!["tag".to_string()],
            evidence: vec![],
            risk_contributions: Vec::new(),
            event_time: Some("2026-05-01T00:00:00.000Z".to_string()),
        })
        .expect("build detection event");
        event.triage = Some(serde_json::json!({
            "required": true,
            "verdict": "pending",
            "timeline_anchors": [{
                "entry_index": 2,
                "rule_ids": ["rule"],
                "categories": ["category"],
                "evidence_fields": ["tool_result"]
            }]
        }));
        event.tags = vec!["tag1".to_string(), "tag2".to_string()];

        let captured = Arc::clone(&requests);
        let outcome = maybe_triage_with_chat(
            TriageConfig {
                api_base: "http://127.0.0.1:1".to_string(),
                api_key: "secret".to_string(),
                model: "triage-model".to_string(),
                guard_model: "guard-model".to_string(),
                request_timeout_ms: 1000,
                max_retries: 0,
            },
            &event,
            |config, model, prompt| {
                captured.lock().expect("lock").push(format!(
                    "model={model}\nauthorization=Bearer {}\n{prompt}",
                    config.api_key
                ));
                Ok(serde_json::json!({
                    "id": "x",
                    "choices": [{
                        "message": {
                            "content": "{\"verdict\":\"malicious\",\"severity\":\"critical\",\"confidence\":0.99,\"reason\":\"test\",\"matched_risks\":[\"mcp\"],\"recommended_action\":\"block\"}"
                        }
                    }]
                }))
            },
        )
        .expect("triage")
        .expect("present");
        assert_eq!(outcome.verdict, "malicious");
        assert!(outcome.confidence > 0.9);
        assert!(!outcome.reason.is_empty());

        let requests = requests.lock().expect("lock");
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("model=guard-model"));
        assert!(requests[1].contains("model=triage-model"));
        assert!(requests[0].contains("authorization=Bearer secret"));
        assert!(requests[0].contains("timeline_anchor_count=1"));
        assert!(requests[1].contains("timeline_anchor[0]=entry_index:2;"));
        assert!(requests[0].contains("matched_rules=rule"));
        assert!(requests[0].contains("categories=category"));
        assert!(requests[0].contains("tags=tag1,tag2"));
        assert!(requests[0].contains("benign"));
    }

    #[test]
    fn chat_completion_retries_transient_failures() {
        let attempts = Arc::new(Mutex::new(0_usize));
        let captured = Arc::clone(&attempts);

        let result = chat_completion_with_retry(
            &TriageConfig {
                api_base: "http://127.0.0.1:1".to_string(),
                api_key: "secret".to_string(),
                model: "triage-model".to_string(),
                guard_model: "guard-model".to_string(),
                request_timeout_ms: 1000,
                max_retries: 2,
            },
            "triage-model",
            "prompt",
            Duration::from_millis(0),
            move |_, _, _| {
                let mut attempts = captured.lock().expect("lock");
                *attempts += 1;
                if *attempts < 3 {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "transient").into())
                } else {
                    Ok(serde_json::json!({"ok": true}))
                }
            },
        )
        .expect("retry should eventually succeed");

        assert_eq!(result["ok"], true);
        assert_eq!(*attempts.lock().expect("lock"), 3);
    }
}
