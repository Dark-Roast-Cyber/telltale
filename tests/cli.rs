use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use jsonschema::validator_for;
use serde_json::Value;
use tempfile::tempdir;

fn source_inventory_change_value(event: &Value) -> &str {
    event["evidence"]
        .as_array()
        .expect("evidence array")
        .iter()
        .find(|item| item["field"] == "source_inventory_change")
        .expect("source inventory change evidence")["redacted_value"]
        .as_str()
        .expect("source inventory change value")
}

#[test]
fn readme_local_markdown_links_resolve() {
    let local_links = repo_local_markdown_links(Path::new("README.md"));

    assert!(!local_links.is_empty(), "expected README local links");

    let missing = local_links
        .iter()
        .filter(|(_, target)| !target.exists())
        .map(|(link, _)| link.clone())
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "README local links must point at tracked files or directories: {missing:?}"
    );
}

#[test]
fn public_docs_local_markdown_links_resolve() {
    let docs = fs::read_dir("docs")
        .expect("docs directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "md"))
        .collect::<Vec<_>>();

    assert!(!docs.is_empty(), "expected public docs");

    let missing = docs
        .iter()
        .flat_map(|path| {
            repo_local_markdown_links(path)
                .into_iter()
                .filter(|(_, target)| !target.exists())
                .map(|(link, target)| {
                    format!("{} -> {} ({})", path.display(), link, target.display())
                })
        })
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "public docs local links must point at existing files or directories: {missing:?}"
    );
}

#[test]
fn public_docs_do_not_reintroduce_split_checkout_guidance() {
    let stale_terms = [
        "runewatch-public",
        "split-checkout",
        "split checkout",
        "second local checkout",
        "separate checkout",
        "export tree",
        "exported tree",
        "export-tree",
        "paired private/public",
    ];

    let docs = public_markdown_docs();
    assert!(!docs.is_empty(), "expected public docs");

    let mut matches = stale_public_guidance_matches(Path::new("README.md"), &stale_terms);
    for doc in docs {
        matches.extend(stale_public_guidance_matches(&doc, &stale_terms));
    }

    assert!(
        matches.is_empty(),
        "public docs must not reintroduce retired split-checkout guidance: {matches:?}"
    );
}

#[test]
fn public_docs_do_not_link_to_host_only_paths() {
    let mut docs = vec![Path::new("README.md").to_path_buf()];
    docs.extend(
        public_markdown_docs()
            .into_iter()
            .filter(|path| !is_host_only_repo_path(path)),
    );

    let host_only_links = docs
        .iter()
        .flat_map(|path| {
            repo_local_markdown_links(path)
                .into_iter()
                .filter(|(_, target)| is_host_only_repo_path(target))
                .map(|(link, target)| {
                    format!("{} -> {} ({})", path.display(), link, target.display())
                })
        })
        .collect::<Vec<_>>();

    assert!(
        host_only_links.is_empty(),
        "public docs must not link to ignored host-only release paths: {host_only_links:?}"
    );
}

#[test]
fn host_only_release_paths_remain_ignored() {
    let required_patterns = [
        "AGENTS.md",
        "PLAN.md",
        "VISION.md",
        "IDEAS.md",
        "docs/internal/",
        "docs/CHANGELOG.md",
        "docs/siem-logging.md",
        "docs/splunk-content.md",
        "skills/",
        "scripts/ralph*",
        "scripts/inspiration/",
        ".opencode/",
        "logs/",
        "state/",
        "runtime/ralph/",
        "config/examples/splunk-*.conf",
        "config/examples/splunk-*.xml",
    ];

    let gitignore = fs::read_to_string(".gitignore").expect(".gitignore");
    let patterns = gitignore
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();

    let missing = required_patterns
        .iter()
        .filter(|pattern| !patterns.contains(pattern))
        .copied()
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "host-only release paths must stay ignored: {missing:?}"
    );
}

fn public_markdown_docs() -> Vec<std::path::PathBuf> {
    fs::read_dir("docs")
        .expect("docs directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "md"))
        .filter(|path| path.file_name().is_none_or(|name| name != "CHANGELOG.md"))
        .collect()
}

fn is_host_only_repo_path(path: &Path) -> bool {
    let path = normalize_repo_path(path);
    let host_only_paths = [
        "AGENTS.md",
        "PLAN.md",
        "VISION.md",
        "IDEAS.md",
        "docs/internal/",
        "docs/CHANGELOG.md",
        "docs/siem-logging.md",
        "docs/splunk-content.md",
        "skills/",
        "scripts/ralph",
        "scripts/inspiration/",
        ".opencode/",
        "logs/",
        "state/",
        "runtime/ralph/",
        "config/examples/splunk-",
    ];

    host_only_paths.iter().any(|host_only_path| {
        if host_only_path.ends_with('/') || host_only_path.ends_with('-') {
            path.starts_with(host_only_path)
        } else {
            path == *host_only_path
        }
    })
}

fn normalize_repo_path(path: &Path) -> String {
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::Normal(value) => {
                components.push(value.to_string_lossy().to_string());
            }
            _ => {}
        }
    }

    components.join("/")
}

fn stale_public_guidance_matches(path: &Path, stale_terms: &[&str]) -> Vec<String> {
    let markdown =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let lowercase = markdown.to_lowercase();

    stale_terms
        .iter()
        .filter(|term| lowercase.contains(**term))
        .map(|term| format!("{} contains {term:?}", path.display()))
        .collect()
}

fn repo_local_markdown_links(markdown_path: &Path) -> Vec<(String, std::path::PathBuf)> {
    let markdown = fs::read_to_string(markdown_path)
        .unwrap_or_else(|error| panic!("{}: {error}", markdown_path.display()));
    let base = markdown_path.parent().unwrap_or_else(|| Path::new(""));

    extract_markdown_links(&markdown)
        .into_iter()
        .filter(|link| is_repo_local_link(link))
        .map(|link| {
            let target = link.split_once('#').map_or(link, |(path, _)| path);
            (link.to_string(), base.join(target))
        })
        .collect()
}

fn extract_markdown_links(markdown: &str) -> Vec<&str> {
    let mut links = Vec::new();
    let mut rest = markdown;

    while let Some(start) = rest.find("](") {
        rest = &rest[start + 2..];
        let Some(end) = rest.find(')') else {
            break;
        };
        links.push(&rest[..end]);
        rest = &rest[end + 1..];
    }

    links
}

fn is_repo_local_link(link: &str) -> bool {
    !link.is_empty()
        && !link.starts_with('#')
        && !link.starts_with("http://")
        && !link.starts_with("https://")
        && !link.starts_with("mailto:")
}

fn start_mock_llm_server() -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    start_mock_llm_server_with_content(
        "{\"verdict\":\"malicious\",\"severity\":\"critical\",\"confidence\":0.97,\"reason\":\"mock triage confirmed MCP injection\"}",
    )
}

fn start_mock_llm_server_with_content(
    content: &'static str,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock llm server");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let addr = listener.local_addr().expect("listener addr");
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let response_body = serde_json::json!({
            "id": "mock",
            "choices": [{
                "message": {
                    "content": content
                }
            }]
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        let mut handled = 0_usize;
        while handled < 2 && Instant::now() < deadline {
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
                    let _ = tx.send(String::from_utf8_lossy(&request).to_string());
                    stream
                        .write_all(response.as_bytes())
                        .expect("write mock response");
                    handled += 1;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{}", addr), rx, handle)
}

fn start_mock_hec_server() -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock hec server");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let addr = listener.local_addr().expect("listener addr");
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
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
                    let _ = tx.send(String::from_utf8_lossy(&request).to_string());
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"text\":\"ok\"}\n",
                        )
                        .expect("write mock hec response");
                    return;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{addr}/services/collector"), rx, handle)
}

#[test]
fn scan_once_writes_schema_shaped_health_jsonl() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["event_type"], "health");
    assert_eq!(summary["detection_count"], 36);
    assert_eq!(summary["source_counts"]["claude.jsonl"], 3);
    assert_eq!(summary["source_counts"]["codex.jsonl"], 40);
    assert_eq!(summary["source_counts"]["codex.archived_jsonl"], 2);
    assert_eq!(summary["source_counts"]["codex.headless_jsonl"], 2);
    assert_eq!(summary["source_counts"]["gemini.json"], 2);
    assert_eq!(summary["source_counts"]["openclaw.jsonl"], 2);
    assert_eq!(summary["source_counts"]["qwen.jsonl"], 2);
    assert_eq!(summary["source_counts"]["roocode.ui_messages_json"], 2);
    assert_eq!(summary["source_counts"]["kilocode.ui_messages_json"], 2);
    assert_eq!(summary["source_counts"]["opencode.sqlite"], 1);
    assert_eq!(summary["source_counts"]["opencode.legacy_json"], 5);
    assert_eq!(summary["source_counts"]["copilot.copilot_process_log"], 5);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 37);
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "session-a" && event["client"] == "claude")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "claude-tool-use" && event["client"] == "claude")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "gemini-session-a" && event["client"] == "gemini")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "qwen-session-a" && event["client"] == "qwen")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "openclaw-session-a"
                && event["client"] == "openclaw")
    );
    assert!(
        !events.iter().any(
            |event| event["session_id"] == "roocode-session-a" && event["client"] == "roocode"
        )
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "kilocode-session-a"
                && event["client"] == "kilocode")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "approval-bypass-quoted-example")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "uc001-negative-normal-mcp")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "controlled-domain-user-text")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "controlled-domain-assistant-text")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "uc001-negative-server-instructions")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "uc001-negative-tools-list")
    );
    assert!(
        !events
            .iter()
            .any(|event| event["session_id"] == "uc001-negative-domain-only")
    );

    let schema: Value =
        serde_json::from_str(include_str!("../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    for event in &events {
        assert!(
            validator.is_valid(event),
            "event failed schema validation: {}",
            event["session_id"]
                .as_str()
                .unwrap_or("<missing session_id>")
        );
        for item in event["evidence"].as_array().expect("evidence array") {
            let redacted = item["redacted_value"].as_str().expect("redacted value");
            assert!(
                item["hash"].is_string(),
                "evidence hash missing for {}",
                event["session_id"]
                    .as_str()
                    .unwrap_or("<missing session_id>")
            );
            assert!(!redacted.contains(".env"));
            assert!(!redacted.contains("darkroastcyber.io"));
            assert!(!redacted.contains("mcp-lab"));
            assert!(!redacted.contains("id_rsa"));
            assert!(!redacted.contains("ghp_1234567890abcdef1234"));
            assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ"));
            assert!(!redacted.contains("fixture_session_token_1234567890abcdef"));
        }
    }

    let event = &events[0];
    assert!(
        validator.is_valid(event),
        "health event failed schema validation"
    );
    assert_eq!(event["schema_version"], "1.0");
    assert_eq!(event["event_type"], "health");
    assert_eq!(event["severity"], "informational");
    assert_eq!(event["risk_score"], 0);
    assert_eq!(event["session_id"], "scanner");
    assert_eq!(event["component"], "scanner");
    assert_eq!(event["check_name"], "source_discovery");
    assert_eq!(event["status"], "ok");
    assert_eq!(event["adr_version"], env!("CARGO_PKG_VERSION"));
    assert!(event["scan_duration_ms"].as_u64().is_some());
    assert_eq!(event["rule_count"], 18);
    assert_eq!(event["threshold_config"]["low"], 20);
    assert_eq!(event["threshold_config"]["medium"], 50);
    assert_eq!(event["threshold_config"]["triage"], 70);
    assert_eq!(event["threshold_config"]["alert"], 90);
    assert_eq!(event["active_policy_name"], Value::Null);
    assert!(
        event["evidence"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    assert_eq!(
        event["evidence"].as_array().expect("health evidence").len(),
        2
    );
    assert_eq!(event["evidence"][0]["field"], "source_inventory");
    assert_eq!(
        event["evidence"][0]["redacted_value"],
        "sources=68; client_source_kinds=12"
    );
    assert!(
        event["evidence"][0]["hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );
    assert_eq!(event["evidence"][1]["field"], "source_inventory_change");
    assert_eq!(
        event["evidence"][1]["redacted_value"],
        "baseline=true; added=68; removed=0; unchanged=0"
    );
    assert!(
        event["evidence"][1]["hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );
    for item in event["evidence"].as_array().expect("evidence array") {
        let redacted = item["redacted_value"].as_str().expect("redacted value");
        assert!(!redacted.contains("tests/fixtures"));
        assert!(!redacted.contains(".jsonl"));
        assert!(!redacted.contains(".sqlite"));
    }

    let detection = events
        .iter()
        .find(|event| event["session_id"] == "uc001-positive")
        .expect("uc001 detection");
    assert!(
        validator.is_valid(detection),
        "detection event failed schema validation"
    );
    assert_eq!(detection["event_type"], "detection");
    assert_eq!(detection["severity"], "critical");
    assert_eq!(detection["session_id"], "uc001-positive");
    assert_eq!(detection["tool_name"], "repo_status");
    assert!(
        detection["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        detection["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("mcp-lab")
            })
    );

    let server_instructions = events
        .iter()
        .find(|event| event["session_id"] == "uc001-positive-server-instructions")
        .expect("server instructions detection");
    assert!(
        validator.is_valid(server_instructions),
        "server instructions event failed schema validation"
    );
    assert_eq!(server_instructions["event_type"], "detection");
    assert_eq!(server_instructions["severity"], "critical");
    assert!(
        server_instructions["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        server_instructions["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "mcp_prompt_injection")
    );
    assert!(
        server_instructions["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("mcp-lab")
            })
    );

    let tool_description = events
        .iter()
        .find(|event| event["session_id"] == "uc001-positive-tool-description")
        .expect("tool description detection");
    assert!(
        validator.is_valid(tool_description),
        "tool description event failed schema validation"
    );
    assert_eq!(tool_description["event_type"], "detection");
    assert_eq!(tool_description["severity"], "critical");
    assert!(
        tool_description["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        tool_description["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("mcp-lab")
            })
    );

    let parameter_description = events
        .iter()
        .find(|event| event["session_id"] == "uc001-positive-parameter-description")
        .expect("parameter description detection");
    assert!(
        validator.is_valid(parameter_description),
        "parameter description event failed schema validation"
    );
    assert_eq!(parameter_description["event_type"], "detection");
    assert_eq!(parameter_description["severity"], "critical");
    assert!(
        parameter_description["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        parameter_description["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("mcp-lab")
            })
    );

    let compliance_tool = events
        .iter()
        .find(|event| event["session_id"] == "uc001-positive-compliance-tool")
        .expect("compliance tool detection");
    assert!(
        validator.is_valid(compliance_tool),
        "compliance tool event failed schema validation"
    );
    assert_eq!(compliance_tool["event_type"], "detection");
    assert_eq!(compliance_tool["severity"], "critical");
    assert_eq!(compliance_tool["tool_name"], "get_compliance_status");
    assert!(
        compliance_tool["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        compliance_tool["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        compliance_tool["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("darkroastcyber.io")
            })
    );

    let reversed_injection = events
        .iter()
        .find(|event| event["session_id"] == "uc001-positive-reversed-injection")
        .expect("reversed injection detection");
    assert!(
        validator.is_valid(reversed_injection),
        "reversed injection event failed schema validation"
    );
    assert_eq!(reversed_injection["event_type"], "detection");
    assert_eq!(reversed_injection["severity"], "critical");
    assert_eq!(reversed_injection["tool_name"], "repo_status");
    assert!(
        reversed_injection["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        reversed_injection["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        reversed_injection["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("darkroastcyber.io")
            })
    );

    let tool_result = events
        .iter()
        .find(|event| event["session_id"] == "tool-result-injection")
        .expect("tool result detection");
    assert!(
        validator.is_valid(tool_result),
        "tool result event failed schema validation"
    );
    assert_eq!(tool_result["event_type"], "detection");
    assert_eq!(tool_result["severity"], "critical");
    assert!(
        tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "approval.bypass.context")
    );
    assert!(
        tool_result["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "approval_bypass")
    );
    assert!(
        !tool_result["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "secret_access")
    );
    assert!(
        tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("mcp-lab")
            })
    );

    let claude_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "claude-uc001-tool-result")
        .expect("claude tool result detection");
    assert!(
        validator.is_valid(claude_tool_result),
        "claude tool result event failed schema validation"
    );
    assert_eq!(claude_tool_result["event_type"], "detection");
    assert_eq!(claude_tool_result["client"], "claude");
    assert_eq!(claude_tool_result["severity"], "critical");
    assert_eq!(claude_tool_result["tool_name"], "repo_status");
    assert!(
        claude_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        claude_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        claude_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let gemini_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "gemini-uc001-tool-result")
        .expect("gemini tool result detection");
    assert!(
        validator.is_valid(gemini_tool_result),
        "gemini tool result event failed schema validation"
    );
    assert_eq!(gemini_tool_result["event_type"], "detection");
    assert_eq!(gemini_tool_result["client"], "gemini");
    assert_eq!(gemini_tool_result["severity"], "critical");
    assert_eq!(gemini_tool_result["tool_name"], "repo_status");
    assert!(
        gemini_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        gemini_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        gemini_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let qwen_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "qwen-uc001-tool-result")
        .expect("qwen tool result detection");
    assert!(
        validator.is_valid(qwen_tool_result),
        "qwen tool result event failed schema validation"
    );
    assert_eq!(qwen_tool_result["event_type"], "detection");
    assert_eq!(qwen_tool_result["client"], "qwen");
    assert_eq!(qwen_tool_result["severity"], "critical");
    assert_eq!(qwen_tool_result["tool_name"], "repo_status");
    assert!(
        qwen_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        qwen_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        qwen_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let openclaw_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "openclaw-uc001-tool-result")
        .expect("openclaw tool result detection");
    assert!(
        validator.is_valid(openclaw_tool_result),
        "openclaw tool result event failed schema validation"
    );
    assert_eq!(openclaw_tool_result["event_type"], "detection");
    assert_eq!(openclaw_tool_result["client"], "openclaw");
    assert_eq!(openclaw_tool_result["severity"], "critical");
    assert_eq!(openclaw_tool_result["tool_name"], "repo_status");
    assert!(
        openclaw_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        openclaw_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        openclaw_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let roocode_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "roocode-uc001-tool-result")
        .expect("roocode tool result detection");
    assert!(
        validator.is_valid(roocode_tool_result),
        "roocode tool result event failed schema validation"
    );
    assert_eq!(roocode_tool_result["event_type"], "detection");
    assert_eq!(roocode_tool_result["client"], "roocode");
    assert_eq!(roocode_tool_result["severity"], "critical");
    assert_eq!(roocode_tool_result["tool_name"], "repo_status");
    assert!(
        roocode_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        roocode_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        roocode_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let kilocode_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "kilocode-uc001-tool-result")
        .expect("kilocode tool result detection");
    assert!(
        validator.is_valid(kilocode_tool_result),
        "kilocode tool result event failed schema validation"
    );
    assert_eq!(kilocode_tool_result["event_type"], "detection");
    assert_eq!(kilocode_tool_result["client"], "kilocode");
    assert_eq!(kilocode_tool_result["severity"], "critical");
    assert_eq!(kilocode_tool_result["tool_name"], "repo_status");
    assert!(
        kilocode_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        kilocode_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        kilocode_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let opencode_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "opencode-uc001-legacy-tool-result")
        .expect("opencode legacy tool result detection");
    assert!(
        validator.is_valid(opencode_tool_result),
        "opencode legacy tool result event failed schema validation"
    );
    assert_eq!(opencode_tool_result["event_type"], "detection");
    assert_eq!(opencode_tool_result["client"], "opencode");
    assert_eq!(opencode_tool_result["severity"], "critical");
    assert_eq!(opencode_tool_result["tool_name"], "repo_status");
    assert!(
        opencode_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        opencode_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        opencode_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let opencode_sqlite_tool_result = events
        .iter()
        .find(|event| event["session_id"] == "opencode-uc001-sqlite-tool-result")
        .expect("opencode sqlite tool result detection");
    assert!(
        validator.is_valid(opencode_sqlite_tool_result),
        "opencode sqlite tool result event failed schema validation"
    );
    assert_eq!(opencode_sqlite_tool_result["event_type"], "detection");
    assert_eq!(opencode_sqlite_tool_result["client"], "opencode");
    assert_eq!(opencode_sqlite_tool_result["severity"], "critical");
    assert_eq!(opencode_sqlite_tool_result["tool_name"], "repo_status");
    assert!(
        opencode_sqlite_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "mcp.tool_metadata.prompt_injection")
    );
    assert!(
        opencode_sqlite_tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        opencode_sqlite_tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && !value.contains("mcp-lab")
            })
    );

    let jwt_bearer_token = events
        .iter()
        .find(|event| event["session_id"] == "jwt-bearer-token-pattern")
        .expect("jwt bearer token detection");
    assert!(
        validator.is_valid(jwt_bearer_token),
        "jwt bearer token event failed schema validation"
    );
    assert_eq!(jwt_bearer_token["event_type"], "detection");
    assert_eq!(jwt_bearer_token["severity"], "low");
    assert!(
        jwt_bearer_token["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "credential.api_key.pattern")
    );
    assert!(
        jwt_bearer_token["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "credential_pattern")
    );
    assert!(
        jwt_bearer_token["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ")
                    && !value.contains("fixture_session_token_1234567890abcdef")
            })
    );

    let tool_injection_session = events
        .iter()
        .find(|event| event["session_id"] == "tool-injection-shape-session")
        .expect("tool injection session detection");
    assert!(
        validator.is_valid(tool_injection_session),
        "tool injection session event failed schema validation"
    );
    assert_eq!(tool_injection_session["event_type"], "detection");
    assert_eq!(tool_injection_session["severity"], "critical");
    assert!(
        tool_injection_session["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "tool.injection.shape")
    );
    assert!(
        tool_injection_session["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("mcp-lab")
            })
    );
    assert!(
        tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "network.controlled_test_domain.darkroast")
    );
    assert!(
        tool_result["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.mcp_injection_then_egress")
    );
    assert!(
        tool_result["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env") && !value.contains("darkroastcyber.io")
            })
    );
    let approval = events
        .iter()
        .find(|event| event["session_id"] == "approval-bypass-context")
        .expect("approval detection");
    assert!(
        validator.is_valid(approval),
        "approval bypass event failed schema validation"
    );
    assert_eq!(approval["event_type"], "detection");
    assert_eq!(approval["session_id"], "approval-bypass-context");
    assert!(
        approval["rule_ids"]
            .as_array()
            .is_some_and(|rules| { rules.iter().any(|rule| rule == "approval.bypass.context") })
    );
    assert!(approval["categories"].as_array().is_some_and(|categories| {
        categories
            .iter()
            .any(|category| category == "approval_bypass")
    }));

    let install_persistence = events
        .iter()
        .find(|event| event["session_id"] == "install-persistence-chain")
        .expect("install persistence detection");
    assert!(
        validator.is_valid(install_persistence),
        "install persistence event failed schema validation"
    );
    assert_eq!(install_persistence["event_type"], "detection");
    assert_eq!(install_persistence["severity"], "critical");
    assert!(
        install_persistence["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "install.package_manager")
    );
    assert!(
        install_persistence["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "persistence.shell_profile")
    );
    assert!(
        install_persistence["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.install_then_persistence")
    );
    assert!(
        install_persistence["categories"]
            .as_array()
            .is_some_and(|categories| {
                categories.iter().any(|category| category == "install")
                    && categories.iter().any(|category| category == "persistence")
            })
    );
    assert!(
        install_persistence["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains("darkroastcyber.io")
                    && !value.contains("pip install")
                    && !value.contains("~/.bashrc")
            })
    );

    let encoded_payload = events
        .iter()
        .find(|event| event["session_id"] == "encoded-payload-chain")
        .expect("encoded payload detection");
    assert!(
        validator.is_valid(encoded_payload),
        "encoded payload event failed schema validation"
    );
    assert_eq!(encoded_payload["event_type"], "detection");
    assert_eq!(encoded_payload["severity"], "high");
    assert!(
        encoded_payload["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "execution.shell")
    );
    assert!(
        encoded_payload["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "execution.encoded_payload")
    );
    assert!(
        encoded_payload["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.shell_encoded_payload")
    );
    assert!(
        encoded_payload["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "execution")
    );
    assert!(
        encoded_payload["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag == "chain")
    );
    assert!(
        encoded_payload["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                item["hash"].is_string() && !value.contains("base64 --decode")
            })
    );

    let download_execute = events
        .iter()
        .find(|event| event["session_id"] == "download-execute-chain")
        .expect("download execute detection");
    assert!(
        validator.is_valid(download_execute),
        "download execute event failed schema validation"
    );
    assert_eq!(download_execute["event_type"], "detection");
    assert_eq!(download_execute["severity"], "high");
    assert!(
        download_execute["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "network.download")
    );
    assert!(
        download_execute["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "execution.shell")
    );
    assert!(
        download_execute["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.download_then_execute")
    );
    assert!(
        download_execute["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                item["hash"].is_string()
                    && !value.is_empty()
                    && !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
            })
    );

    let secret_network = events
        .iter()
        .find(|event| event["session_id"] == "secret-network-chain")
        .expect("secret network detection");
    assert!(
        validator.is_valid(secret_network),
        "secret network event failed schema validation"
    );
    assert_eq!(secret_network["event_type"], "detection");
    assert_eq!(secret_network["severity"], "critical");
    assert!(
        secret_network["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "secret.env.read")
    );
    assert!(
        secret_network["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "network.download")
    );
    assert!(
        secret_network["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "chain.secret_then_network")
    );
    assert!(
        secret_network["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "secret_access")
            && secret_network["categories"]
                .as_array()
                .expect("categories")
                .iter()
                .any(|category| category == "download")
    );
    assert!(
        secret_network["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.is_empty() && !value.contains(".env") && !value.contains("darkroastcyber.io")
            })
    );

    let private_key = events
        .iter()
        .find(|event| event["session_id"] == "private-key-read")
        .expect("private key detection");
    assert!(
        validator.is_valid(private_key),
        "private key event failed schema validation"
    );
    assert_eq!(private_key["event_type"], "detection");
    assert_eq!(private_key["severity"], "high");
    assert!(
        private_key["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "secret.private_key.read")
    );
    assert!(
        private_key["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "secret_access")
    );
    assert!(
        private_key["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains("id_rsa")
            })
    );

    let api_key = events
        .iter()
        .find(|event| event["session_id"] == "api-key-pattern")
        .expect("api key detection");
    assert!(
        validator.is_valid(api_key),
        "api key event failed schema validation"
    );
    assert_eq!(api_key["event_type"], "detection");
    assert_eq!(api_key["severity"], "low");
    assert!(
        api_key["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "credential.api_key.pattern")
    );
    assert!(
        api_key["categories"]
            .as_array()
            .expect("categories")
            .iter()
            .any(|category| category == "credential_pattern")
    );
    assert!(
        api_key["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                item["hash"].is_string()
                    && !value.is_empty()
                    && !value.contains("ghp_1234567890abcdef1234")
            })
    );

    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "uc001-negative-mcp-user-text")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "uc001-negative-normal-mcp")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "uc001-negative-server-instructions")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "uc001-negative-domain-only")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "controlled-domain-user-text")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "controlled-domain-assistant-text")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "uc001-negative-domain-tool-result")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "tool-result-injection"
            && event["severity"] != "critical")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "normal-mcp-tool-result")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "approval-bypass-user-text")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "approval-bypass-tool-result")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "approval-bypass-quoted-example")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "approval-bypass-cost-data")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "secret-access-auth-log")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "opencode-noise-approval-cost-data")
    );
    assert!(
        !events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "opencode-noise-secret-auth-log")
    );
    assert!(
        events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "tool-injection-shape")
    );
    let tool_injection_shape_session = events
        .iter()
        .find(|event| event["session_id"] == "tool-injection-shape-session")
        .expect("tool injection shape session detection");
    assert!(
        validator.is_valid(tool_injection_shape_session),
        "tool injection shape session event failed schema validation"
    );
    assert_eq!(tool_injection_shape_session["event_type"], "detection");
    assert_eq!(tool_injection_shape_session["severity"], "critical");
    assert!(
        tool_injection_shape_session["rule_ids"]
            .as_array()
            .expect("rule ids")
            .iter()
            .any(|rule| rule == "tool.injection.shape")
    );
    assert!(
        tool_injection_shape_session["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .all(|item| {
                let value = item["redacted_value"].as_str().expect("redacted value");
                !value.contains(".env")
                    && !value.contains("darkroastcyber.io")
                    && item["hash"].is_string()
            })
    );
    assert!(events.iter().any(|event| event["event_type"] == "detection"
        && event["session_id"] == "install-persistence-chain"));
    assert!(
        events.iter().any(|event| event["event_type"] == "detection"
            && event["session_id"] == "secret-network-chain")
    );
}

#[test]
fn scan_once_can_emit_to_splunk_hec_without_disabling_jsonl() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let (hec_endpoint, requests, handle) = start_mock_hec_server();

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--root"])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .args(["--splunk-hec-endpoint", &hec_endpoint])
        .args(["--splunk-hec-token", "test-token"])
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = fs::read_to_string(&log_path).expect("jsonl log");
    assert_eq!(lines.lines().count(), 1);
    let request = requests
        .recv_timeout(Duration::from_secs(2))
        .expect("hec request");
    handle.join().expect("mock hec thread");
    assert!(request.starts_with("POST /services/collector HTTP/1.1"));
    assert!(request.contains("Authorization: Splunk test-token"));
    let body = request.split_once("\r\n\r\n").expect("body split").1;
    let envelope: Value = serde_json::from_str(body).expect("hec envelope");
    assert_eq!(envelope["index"], "adr");
    assert_eq!(envelope["sourcetype"], "adr:json");
    assert_eq!(envelope["event"]["event_type"], "health");
    assert_eq!(
        envelope["event"]["source_counts"]
            .as_object()
            .unwrap()
            .len(),
        0
    );
    assert!(envelope["event"].get("index").is_none());
}

#[test]
fn scan_once_requires_splunk_hec_endpoint_and_token_together() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("empty-root");
    fs::create_dir_all(&root).expect("empty root");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--root"])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .args([
            "--splunk-hec-endpoint",
            "http://127.0.0.1:8088/services/collector",
        ])
        .output()
        .expect("run adr");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--splunk-hec-endpoint and --splunk-hec-token must be set together"));
    assert!(!log_path.exists());
    assert!(!state_path.exists());
}

#[test]
fn scan_once_client_filter_limits_discovered_sources() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--emit-activity",
            "--root",
            "tests/fixtures/session_stores",
            "--client",
            "gemini",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    let source_counts = summary["source_counts"]
        .as_object()
        .expect("source counts object");
    assert_eq!(source_counts.len(), 1);
    assert_eq!(source_counts["gemini.json"], 2);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .all(|event| event["client"] == "scanner" || event["client"] == "gemini")
    );
}

#[test]
fn scan_once_accepts_repeated_client_filters() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--dry-run",
            "--root",
            "tests/fixtures/session_stores",
            "--client",
            "codex",
            "--client",
            "gemini",
        ])
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    let source_counts = summary["source_counts"]
        .as_object()
        .expect("source counts object");
    assert_eq!(source_counts.len(), 4);
    assert_eq!(source_counts["codex.jsonl"], 40);
    assert_eq!(source_counts["codex.archived_jsonl"], 2);
    assert_eq!(source_counts["codex.headless_jsonl"], 2);
    assert_eq!(source_counts["gemini.json"], 2);
}

#[test]
fn scan_once_rejects_unknown_client_filter() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--dry-run",
            "--root",
            "tests/fixtures/session_stores",
            "--client",
            "unknown-agent",
        ])
        .output()
        .expect("run adr");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported client 'unknown-agent'"));
    assert!(stderr.contains("codex"));
    assert!(stderr.contains("gemini"));
}

#[test]
fn scan_once_max_sources_limits_discovered_sources() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--emit-activity",
            "--root",
            "tests/fixtures/session_stores",
            "--client",
            "gemini",
            "--max-sources",
            "1",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    let source_counts = summary["source_counts"]
        .as_object()
        .expect("source counts object");
    assert_eq!(source_counts.len(), 1);
    assert_eq!(source_counts["gemini.json"], 1);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let health = events
        .iter()
        .find(|event| event["event_type"] == "health")
        .expect("health event");
    assert_eq!(health["source_counts"]["gemini.json"], 1);
}

#[test]
fn scan_once_health_reports_unchanged_source_inventory() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_adr"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--root",
                "tests/fixtures/session_stores",
                "--client",
                "gemini",
                "--log-path",
            ])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .output()
            .expect("run adr");

        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let lines = fs::read_to_string(log_path).expect("log file");
    let health_events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .filter(|event| event["event_type"] == "health")
        .collect::<Vec<_>>();
    assert_eq!(health_events.len(), 1);

    assert_eq!(
        source_inventory_change_value(&health_events[0]),
        "baseline=true; added=2; removed=0; unchanged=0"
    );
}

#[test]
fn scan_once_max_sources_rejects_zero() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--dry-run",
            "--root",
            "tests/fixtures/session_stores",
            "--max-sources",
            "0",
        ])
        .output()
        .expect("run adr");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--max-sources must be greater than 0"));
}

#[test]
fn scan_once_max_sources_is_deterministic() {
    let run_scan = || {
        Command::new(env!("CARGO_BIN_EXE_adr"))
            .args([
                "scan",
                "--once",
                "--dry-run",
                "--root",
                "tests/fixtures/session_stores",
                "--client",
                "codex",
                "--max-sources",
                "3",
            ])
            .output()
            .expect("run adr")
    };

    let first = run_scan();
    let second = run_scan();
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let first_summary: Value = serde_json::from_slice(&first.stdout).expect("first summary json");
    let second_summary: Value =
        serde_json::from_slice(&second.stdout).expect("second summary json");
    assert_eq!(
        first_summary["source_counts"],
        second_summary["source_counts"]
    );
    assert_eq!(
        first_summary["activity_count"],
        second_summary["activity_count"]
    );
    assert_eq!(
        first_summary["detection_count"],
        second_summary["detection_count"]
    );
}

#[test]
fn repeated_scans_suppress_duplicate_detections() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let first = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr");
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_summary: Value = serde_json::from_slice(&first.stdout).expect("summary json");
    assert_eq!(first_summary["detection_count"], 36);
    assert_eq!(first_summary["emitted_count"], 36);

    let second = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr");
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_summary: Value = serde_json::from_slice(&second.stdout).expect("summary json");
    assert_eq!(second_summary["detection_count"], 36);
    assert_eq!(second_summary["emitted_count"], 0);

    let lines = fs::read_to_string(log_path).expect("log file");
    assert_eq!(lines.lines().count(), 37);
}

#[test]
fn scan_once_persists_incremental_baseline_snapshots() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let run_scan = || {
        let output = Command::new(env!("CARGO_BIN_EXE_adr"))
            .args([
                "scan",
                "--once",
                "--allow-fixtures",
                "--root",
                "tests/fixtures/benign_baselines",
                "--log-path",
            ])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .output()
            .expect("run adr");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };

    run_scan();
    let state_after_first = fs::read_to_string(&state_path).expect("first state json");
    run_scan();
    let state_after_second = fs::read_to_string(&state_path).expect("second state json");
    let first_state: Value = serde_json::from_str(&state_after_first).expect("first state parses");
    let second_state: Value =
        serde_json::from_str(&state_after_second).expect("second state parses");
    assert_eq!(
        second_state["baseline_snapshots"], first_state["baseline_snapshots"],
        "repeat scans should not double-count baseline snapshots"
    );

    let snapshots = second_state["baseline_snapshots"]["snapshots"]
        .as_object()
        .expect("baseline snapshots");
    assert!(!snapshots.is_empty());

    let codex_records: u64 = snapshots
        .values()
        .filter(|snapshot| snapshot["key"]["client"] == "codex")
        .map(|snapshot| {
            snapshot["observations"]["records"]
                .as_u64()
                .unwrap_or_default()
        })
        .sum();
    assert!(codex_records > 0);
}

#[test]
fn scan_once_replaces_changed_source_baseline_contribution() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_store");
    let source_dir = root.join("codex/sessions");
    fs::create_dir_all(&source_dir).expect("source dir");
    let source_path = source_dir.join("append-only.jsonl");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let write_source = |tool_calls: &[(&str, &str)]| {
        let mut lines = vec![
            r#"{"type":"session_meta","timestamp":"2026-05-17T10:00:00Z","payload":{"source":"cli","model_provider":"openai","agent_nickname":"codex-baseline-test","model":"o3"}}"#.to_string(),
            r#"{"type":"event_msg","timestamp":"2026-05-17T10:00:01Z","payload":{"type":"user_message","message":"Inspect the project files."}}"#.to_string(),
        ];
        for (index, (call_id, command)) in tool_calls.iter().enumerate() {
            lines.push(format!(
                r#"{{"type":"event_msg","timestamp":"2026-05-17T10:00:0{}Z","payload":{{"type":"tool_call","name":"shell","call_id":"{}","arguments":{{"command":"{}"}}}}}}"#,
                index + 2,
                call_id,
                command
            ));
        }
        fs::write(&source_path, format!("{}\n", lines.join("\n"))).expect("write source");
    };

    let run_scan = || {
        let output = Command::new(env!("CARGO_BIN_EXE_adr"))
            .args(["scan", "--once", "--allow-fixtures", "--root"])
            .arg(&root)
            .args(["--client", "codex", "--log-path"])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path)
            .output()
            .expect("run adr");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };

    write_source(&[("call-one", "ls src")]);
    run_scan();
    write_source(&[
        ("call-one", "ls src"),
        (
            "call-two",
            "curl https://internal.example.test/docs && cargo test --quiet",
        ),
    ]);
    run_scan();

    let state: Value = serde_json::from_str(&fs::read_to_string(&state_path).expect("state json"))
        .expect("state parses");
    let snapshot = state["baseline_snapshots"]["snapshots"]
        .as_object()
        .expect("snapshots")
        .values()
        .find(|snapshot| snapshot["key"]["client"] == "codex")
        .expect("codex snapshot");

    assert_eq!(snapshot["observations"]["tool_calls"], 2);
    assert_eq!(snapshot["tool_call_counts"]["shell"], 2);
    let state_text = fs::read_to_string(&state_path).expect("state text");
    assert!(
        !state_text.contains("internal.example.test"),
        "persisted baseline state should not contain raw network host labels"
    );
    assert!(
        state_text.contains("sha256:"),
        "persisted baseline state should contain deterministic host hashes"
    );
}

#[test]
fn scan_once_persists_distinct_source_contributions_for_same_bucket() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_store");
    let source_dir = root.join("codex/sessions/2026/05");
    fs::create_dir_all(&source_dir).expect("source dir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    for (name, command) in [
        ("session-a.jsonl", "ls src"),
        ("session-b.jsonl", "git status --short"),
    ] {
        let event = serde_json::json!({
            "type": "event_msg",
            "timestamp": "2026-05-17T10:00:02Z",
            "payload": {
                "type": "tool_call",
                "name": "shell",
                "call_id": format!("call-{name}"),
                "arguments": {"command": command}
            }
        });
        fs::write(
            source_dir.join(name),
            format!(
                "{}\n{}\n{}\n",
                r#"{"type":"session_meta","timestamp":"2026-05-17T10:00:00Z","payload":{"source":"cli","model_provider":"openai","agent_nickname":"codex-baseline-test","model":"o3"}}"#,
                r#"{"type":"event_msg","timestamp":"2026-05-17T10:00:01Z","payload":{"type":"user_message","message":"Inspect the project files."}}"#,
                event
            ),
        )
        .expect("write source");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--allow-fixtures", "--root"])
        .arg(&root)
        .args(["--client", "codex", "--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let state: Value = serde_json::from_str(&fs::read_to_string(&state_path).expect("state json"))
        .expect("state parses");
    let contributions = state["baseline_source_contributions"]
        .as_object()
        .expect("contributions");
    assert_eq!(contributions.len(), 2);
}

#[test]
fn scan_once_rebuild_baselines_reparses_unchanged_sources_without_reemitting_detections() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_store");
    let source_dir = root.join("codex/sessions/2026/05");
    fs::create_dir_all(&source_dir).expect("source dir");
    let source_path = source_dir.join("session-a.jsonl");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    fs::write(
        &source_path,
        concat!(
            r#"{"type":"session_meta","timestamp":"2026-05-17T10:00:00Z","payload":{"source":"cli","model_provider":"openai","agent_nickname":"codex-baseline-test","model":"o3"}}"#,
            "\n",
            r#"{"type":"event_msg","timestamp":"2026-05-17T10:00:01Z","payload":{"type":"user_message","message":"Inspect the project files."}}"#,
            "\n",
            r#"{"type":"event_msg","timestamp":"2026-05-17T10:00:02Z","payload":{"type":"tool_call","name":"shell","call_id":"call-one","arguments":{"command":"ls src"}}}"#,
            "\n"
        ),
    )
    .expect("write source");

    let run_scan = |rebuild_baselines: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_adr"));
        command
            .args(["scan", "--once", "--allow-fixtures", "--root"])
            .arg(&root)
            .args(["--client", "codex", "--emit-activity", "--log-path"])
            .arg(&log_path)
            .args(["--state-path"])
            .arg(&state_path);
        if rebuild_baselines {
            command.arg("--rebuild-baselines");
        }
        command.output().expect("run adr")
    };

    let first = run_scan(false);
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_summary: Value = serde_json::from_slice(&first.stdout).expect("summary json");
    assert_eq!(first_summary["activity_count"], 1);
    assert_eq!(first_summary["emitted_count"], 1);

    let mut state: Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("state json"))
            .expect("state parses");
    state["baseline_snapshots"]["snapshots"] = serde_json::json!({});
    state["baseline_source_contributions"] = serde_json::json!({});
    state["source_observations"] = serde_json::json!({});
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&state).expect("serialize state"),
    )
    .expect("rewrite state");

    let rebuilt = run_scan(true);
    assert!(
        rebuilt.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&rebuilt.stderr)
    );
    let rebuilt_summary: Value = serde_json::from_slice(&rebuilt.stdout).expect("summary json");
    assert_eq!(rebuilt_summary["activity_count"], 1);
    assert_eq!(rebuilt_summary["emitted_count"], 0);

    let rebuilt_state: Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("rebuilt state json"))
            .expect("rebuilt state parses");
    assert!(
        rebuilt_state["baseline_snapshots"]["snapshots"]
            .as_object()
            .is_some_and(|snapshots| !snapshots.is_empty())
    );
    assert!(
        rebuilt_state["baseline_source_contributions"]
            .as_object()
            .is_some_and(|contributions| contributions.len() == 1)
    );
    assert!(
        rebuilt_state["source_observations"]
            .as_object()
            .is_some_and(|observations| observations.len() == 1)
    );

    let lines = fs::read_to_string(log_path).expect("log file");
    assert_eq!(lines.lines().count(), 3);
}

#[test]
fn scan_once_can_emit_activity_events() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--emit-activity",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert!(summary["activity_count"].as_u64().unwrap_or_default() > 0);
    assert_eq!(summary["detection_count"], 36);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    assert!(events.iter().any(|event| {
        event["event_type"] == "activity"
            && event["client"] == "opencode"
            && (event["severity"] == "informational" || event["severity"] == "low")
    }));
}

#[test]
fn scan_once_activity_includes_static_mcp_inventory_events() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("home");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    fs::create_dir_all(&root).expect("root dir");
    fs::write(
        root.join(".mcp.json"),
        r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "synthetic-secret"},
                    "tools": [{"name": "list_issues"}, {"name": "create_issue"}]
                },
                "placeholder": {
                    "args": ["--flag-only"]
                }
            }
        }"#,
    )
    .expect("mcp config");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--emit-activity", "--root"])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["activity_count"], 2);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let inventory = events
        .iter()
        .find(|event| {
            event["event_type"] == "activity"
                && event["session_id"] == "mcp_inventory"
                && event["tool_name"] == "mcp::github"
        })
        .expect("mcp inventory event");
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    assert!(
        validator.is_valid(inventory),
        "mcp inventory activity event should match schema: {inventory}"
    );
    let unsupported_inventory = events
        .iter()
        .find(|event| {
            event["event_type"] == "activity"
                && event["session_id"] == "mcp_inventory"
                && event["tool_name"] == "mcp::placeholder"
        })
        .expect("unsupported mcp inventory event");
    assert!(
        validator.is_valid(unsupported_inventory),
        "unsupported mcp inventory activity event should match schema: {unsupported_inventory}"
    );
    assert!(
        inventory["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag == "mcp_inventory")
    );
    let evidence = inventory["evidence"][0]["redacted_value"]
        .as_str()
        .expect("evidence");
    assert!(evidence.contains("list_issues"));
    assert!(evidence.contains("GITHUB_TOKEN"));
    assert!(!evidence.contains("synthetic-secret"));
    assert!(
        unsupported_inventory["tags"]
            .as_array()
            .expect("unsupported tags")
            .iter()
            .any(|tag| tag == "mcp_inventory_unsupported")
    );
    let unsupported_evidence: Value = serde_json::from_str(
        unsupported_inventory["evidence"][0]["redacted_value"]
            .as_str()
            .expect("unsupported evidence"),
    )
    .expect("unsupported evidence json");
    assert_eq!(unsupported_evidence["supported"], false);
    assert_eq!(
        unsupported_evidence["unsupported_reason"],
        "missing_command_or_url"
    );
}

#[test]
fn scan_once_can_emit_session_risk_summary_events() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--emit-activity",
            "--emit-session-risk-summary",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert!(
        summary["session_risk_summary_count"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let summary_event = events
        .iter()
        .find(|event| event["event_type"] == "session_risk_summary")
        .expect("session risk summary event");
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    assert!(
        validator.is_valid(summary_event),
        "session_risk_summary event should match schema: {summary_event}"
    );
    assert!(summary_event["risk_score"].as_u64().unwrap_or_default() > 0);
    assert!(
        summary_event["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag == "risk_summary")
    );
    assert!(
        summary_event["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .any(|item| item["field"] == "event_counts")
    );
    assert!(
        summary_event["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .any(|item| item["field"] == "risky_action_count")
    );
}

#[test]
fn scan_dry_run_session_risk_summary_does_not_write_log() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--dry-run",
            "--emit-activity",
            "--emit-session-risk-summary",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["log_path"], Value::Null);
    assert!(
        summary["session_risk_summary_count"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert!(!log_path.exists(), "dry-run should not write JSONL output");
}

#[test]
fn shipper_examples_target_default_jsonl_path() {
    let filebeat = include_str!("../config/examples/filebeat-filestream.yml");
    assert!(filebeat.contains("/srv/telltale/logs/adr-events.jsonl"));
    assert!(filebeat.contains("filestream"));
    assert!(filebeat.contains("ndjson"));
}

#[test]
fn scan_defaults_separate_jsonl_telemetry_from_state() {
    let temp = tempdir().expect("tempdir");
    let fixture_root = std::env::current_dir()
        .expect("current dir")
        .join("tests/fixtures/session_stores");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .current_dir(temp.path())
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--root",
            fixture_root.to_str().expect("fixture path"),
            "--max-sources",
            "1",
        ])
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["log_path"], "logs/adr-events.jsonl");
    assert!(temp.path().join("logs/adr-events.jsonl").is_file());
    assert!(temp.path().join("state/adr-state.json").is_file());
    assert!(!temp.path().join("logs/adr-state.json").exists());
}

#[test]
fn systemd_examples_run_periodic_scan_with_env_defaults() {
    let service = include_str!("../config/examples/adr-scan.service");
    assert!(service.contains("WorkingDirectory=%h/github/adr"));
    assert!(service.contains("Environment=ADR_LOG_PATH=%h/github/adr/logs/adr-events.jsonl"));
    assert!(service.contains("Environment=ADR_STATE_PATH=%h/github/adr/state/adr-state.json"));
    assert!(service.contains("Environment=ADR_SCAN_ROOT=%h"));
    assert!(service.contains("EnvironmentFile=-%h/github/adr/.env"));
    assert!(
        service
            .find("Environment=ADR_SCAN_ROOT=%h")
            .expect("scan root default")
            < service
                .find("EnvironmentFile=-%h/github/adr/.env")
                .expect("env file")
    );
    assert!(service.contains("%h/github/adr/target/release/adr scan --once"));
    assert!(service.contains("--emit-activity"));
    assert!(service.contains("--log-path %h/github/adr/logs/adr-events.jsonl"));
    assert!(service.contains("--state-path %h/github/adr/state/adr-state.json"));

    let timer = include_str!("../config/examples/adr-scan.timer");
    assert!(timer.contains("OnUnitActiveSec=5min"));
    assert!(timer.contains("Unit=adr-scan.service"));
    assert!(timer.contains("WantedBy=timers.target"));
}

#[test]
fn scan_once_continues_after_malformed_source() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("malformed-source.jsonl"),
        include_str!("../tests/fixtures/rule_samples/malformed-source.jsonl"),
    )
    .expect("malformed fixture");
    fs::write(
        codex_sessions.join("uc001-positive.jsonl"),
        include_str!(
            "../tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl"
        ),
    )
    .expect("positive fixture");

    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--allow-fixtures", "--root"])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["detection_count"], 2);
    assert_eq!(summary["emitted_count"], 2);
    assert_eq!(summary["source_counts"]["codex.jsonl"], 2);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 3);
    assert!(events.iter().any(|event| event["event_type"] == "detection"
        && event["session_id"] == "uc001-positive"
        && event["severity"] == "critical"));
    assert!(events.iter().any(|event| {
        event["event_type"] == "scanner_error"
            && event["severity"] == "informational"
            && event["session_id"] == "scanner"
            && event["tags"]
                .as_array()
                .unwrap()
                .contains(&Value::String("parse_failure".to_string()))
    }));
}

#[test]
fn scan_once_refuses_fixture_root_without_allow_fixtures() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing to write fixture/demo data"));
    assert!(!log_path.exists());
}

#[test]
fn scan_once_allows_fixture_root_with_dry_run() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--dry-run",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["event_type"], "health");
    assert_eq!(summary["detection_count"], 36);
}

#[test]
fn rules_list_and_validate_default_rules() {
    let list = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "list"])
        .output()
        .expect("run adr rules list");
    assert!(
        list.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("mcp.tool_metadata.prompt_injection"));
    assert!(stdout.contains("secret.env.read"));

    let validate = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "validate"])
        .output()
        .expect("run adr rules validate");
    assert!(
        validate.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let summary: Value = serde_json::from_slice(&validate.stdout).expect("summary json");
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["rule_count"], 18);
}

#[test]
fn rules_serve_exposes_read_only_rule_summary_endpoint() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "serve", "--addr", "127.0.0.1:0", "--once"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adr rules serve");
    let stdout = child.stdout.take().expect("server stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listen summary");
    let listen: Value = serde_json::from_str(line.trim()).expect("listen summary json");
    assert_eq!(listen["status"], "listening");
    let addr = listen["addr"].as_str().expect("listener addr");

    let mut stream = TcpStream::connect(addr).expect("connect rules server");
    stream
        .write_all(b"GET /api/rules HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("Content-Type: application/json"));
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("response body");
    let summary: Value = serde_json::from_str(body).expect("rules json");
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["rule_count"], 18);
    assert!(
        summary["rules"]
            .as_array()
            .expect("rules array")
            .iter()
            .any(|rule| rule["id"] == "mcp.tool_metadata.prompt_injection")
    );

    let output = child.wait_with_output().expect("wait for rules server");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_validates_submitted_rule_yaml_without_writing() {
    let rules_yaml =
        fs::read_to_string("tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml")
            .expect("read custom rules");
    let body = serde_json::json!({ "rules_yaml": rules_yaml }).to_string();
    let (response, output) = post_rules_serve_once("/api/rules/validate", &body);

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("Content-Type: application/json"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["rule_count"], 1);
    assert_eq!(summary["rules"][0]["id"], "custom.agent.malicious_behavior");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_previews_matches_against_fixture_only_path() {
    let rules_yaml =
        fs::read_to_string("tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml")
            .expect("read custom rules");
    let body = serde_json::json!({
        "rules_yaml": rules_yaml,
        "fixture_path": "tests/fixtures/custom_rules/custom-agent-behavior.jsonl",
    })
    .to_string();
    let (response, output) = post_rules_serve_once("/api/rules/preview", &body);

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["match_count"], 1);
    assert_eq!(
        summary["matches"][0]["rule_ids"][0],
        "custom.agent.malicious_behavior"
    );
    assert_eq!(
        summary["fixture_path"],
        "tests/fixtures/custom_rules/custom-agent-behavior.jsonl"
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_rejects_preview_paths_outside_fixtures() {
    let body = serde_json::json!({ "fixture_path": "Cargo.toml" }).to_string();
    let (response, output) = post_rules_serve_once("/api/rules/preview", &body);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "error");
    assert!(
        summary["error"]
            .as_str()
            .expect("error string")
            .contains("preview fixture must be under tests/fixtures")
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn post_rules_serve_once(path: &str, body: &str) -> (String, std::process::Output) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "serve", "--addr", "127.0.0.1:0", "--once"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adr rules serve");
    let stdout = child.stdout.take().expect("server stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listen summary");
    let listen: Value = serde_json::from_str(line.trim()).expect("listen summary json");
    let addr = listen["addr"].as_str().expect("listener addr");

    let mut stream = TcpStream::connect(addr).expect("connect rules server");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    let output = child.wait_with_output().expect("wait for rules server");
    (response, output)
}

fn json_response_body(response: &str) -> Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("response body");
    serde_json::from_str(body).expect("json response")
}

fn post_rules_serve_save(
    body: &str,
    rule_file: &std::path::Path,
) -> (String, std::process::Output) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "serve",
            "--addr",
            "127.0.0.1:0",
            "--once",
            "--rules",
            &rule_file.to_string_lossy(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adr rules serve");
    let stdout = child.stdout.take().expect("server stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listen summary");
    let listen: Value = serde_json::from_str(line.trim()).expect("listen summary json");
    let addr = listen["addr"].as_str().expect("listener addr");

    let mut stream = TcpStream::connect(addr).expect("connect rules server");
    let request = format!(
        "POST /api/rules/save HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    let output = child.wait_with_output().expect("wait for rules server");
    (response, output)
}

fn rules_serve_request(addr: &str, method: &str, path: &str, body: Option<&str>) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect rules server");
    let request = if let Some(body) = body {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    } else {
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
    };
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}

#[test]
fn rules_serve_save_writes_validated_rules_and_creates_backup() {
    let dir = tempdir().expect("temp dir");
    let rule_file = dir.path().join("tool-call-regex.yaml");
    let original =
        fs::read_to_string("config/rules/tool-call-regex.yaml").expect("read default rules");
    fs::write(&rule_file, &original).expect("copy rules to temp");

    let custom_rules =
        fs::read_to_string("tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml")
            .expect("read custom rules");
    let body = serde_json::json!({ "rules_yaml": custom_rules }).to_string();
    let (response, output) = post_rules_serve_save(&body, &rule_file);

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["rule_count"], 1);
    assert!(
        summary["saved"]
            .as_str()
            .expect("saved path")
            .ends_with("tool-call-regex.yaml")
    );

    // Verify the file was actually written.
    let saved = fs::read_to_string(&rule_file).expect("read saved file");
    assert_eq!(saved, custom_rules);

    // Verify backup was created.
    let backup = dir.path().join("tool-call-regex.yaml.bak");
    assert!(backup.exists(), "backup file should exist");
    let backup_content = fs::read_to_string(&backup).expect("read backup");
    assert_eq!(backup_content, original);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_save_reloads_rules_without_restart() {
    let dir = tempdir().expect("temp dir");
    let rule_file = dir.path().join("tool-call-regex.yaml");
    let original =
        fs::read_to_string("config/rules/tool-call-regex.yaml").expect("read default rules");
    fs::write(&rule_file, &original).expect("copy rules to temp");

    let mut child = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "serve",
            "--addr",
            "127.0.0.1:0",
            "--rules",
            &rule_file.to_string_lossy(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adr rules serve");
    let stdout = child.stdout.take().expect("server stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listen summary");
    let listen: Value = serde_json::from_str(line.trim()).expect("listen summary json");
    let addr = listen["addr"].as_str().expect("listener addr");

    let custom_rules =
        fs::read_to_string("tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml")
            .expect("read custom rules");
    let save_body = serde_json::json!({ "rules_yaml": custom_rules }).to_string();
    let save_response = rules_serve_request(addr, "POST", "/api/rules/save", Some(&save_body));
    assert!(save_response.starts_with("HTTP/1.1 200 OK"));

    let rules_response = rules_serve_request(addr, "GET", "/api/rules", None);
    assert!(rules_response.starts_with("HTTP/1.1 200 OK"));
    let rules_summary = json_response_body(&rules_response);
    assert_eq!(rules_summary["status"], "ok");
    assert_eq!(rules_summary["rule_count"], 1);
    assert_eq!(
        rules_summary["rules"][0]["id"],
        "custom.agent.malicious_behavior"
    );

    let preview_body = serde_json::json!({
        "fixture_path": "tests/fixtures/custom_rules/custom-agent-behavior.jsonl",
    })
    .to_string();
    let preview_response =
        rules_serve_request(addr, "POST", "/api/rules/preview", Some(&preview_body));
    assert!(preview_response.starts_with("HTTP/1.1 200 OK"));
    let preview_summary = json_response_body(&preview_response);
    assert_eq!(preview_summary["status"], "ok");
    assert_eq!(preview_summary["match_count"], 1);
    assert_eq!(
        preview_summary["matches"][0]["rule_ids"][0],
        "custom.agent.malicious_behavior"
    );

    child.kill().expect("stop rules server");
    let output = child.wait_with_output().expect("wait for rules server");
    assert!(
        String::from_utf8_lossy(&output.stderr).is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_save_rejects_invalid_yaml() {
    let dir = tempdir().expect("temp dir");
    let rule_file = dir.path().join("tool-call-regex.yaml");
    let original =
        fs::read_to_string("config/rules/tool-call-regex.yaml").expect("read default rules");
    fs::write(&rule_file, &original).expect("copy rules to temp");

    let body = serde_json::json!({ "rules_yaml": "not: valid: yaml: [broken" }).to_string();
    let (response, output) = post_rules_serve_save(&body, &rule_file);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "error");
    assert!(!summary["error"].as_str().expect("error string").is_empty());

    // Original file should be unchanged.
    let current = fs::read_to_string(&rule_file).expect("read file after rejected save");
    assert_eq!(current, original);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn rules_serve_save_rejects_path_not_in_loaded_rules() {
    let dir = tempdir().expect("temp dir");
    let rule_file = dir.path().join("tool-call-regex.yaml");
    let original =
        fs::read_to_string("config/rules/tool-call-regex.yaml").expect("read default rules");
    fs::write(&rule_file, &original).expect("copy rules to temp");

    let custom_rules =
        fs::read_to_string("tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml")
            .expect("read custom rules");
    let body = serde_json::json!({
        "rules_yaml": custom_rules,
        "path": "/etc/passwd",
    })
    .to_string();
    let (response, output) = post_rules_serve_save(&body, &rule_file);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    let summary = json_response_body(&response);
    assert_eq!(summary["status"], "error");
    assert!(
        summary["error"]
            .as_str()
            .expect("error string")
            .contains("not one of the loaded rule files")
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn watch_command_is_available_for_realtime_scans() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["watch", "--help"])
        .output()
        .expect("run adr watch help");

    assert!(
        output.status.success(),
        "watch help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Watch local session stores"));
    assert!(stdout.contains("--debounce-ms"));
    assert!(stdout.contains("--iterations"));
    assert!(stdout.contains("--client"));
}

#[test]
fn watch_rejects_unknown_client_filter() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "watch",
            "--dry-run",
            "--root",
            "tests/fixtures/session_stores",
            "--client",
            "unknown-agent",
        ])
        .output()
        .expect("run adr watch");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported client 'unknown-agent'"));
    assert!(stderr.contains("codex"));
    assert!(stderr.contains("gemini"));
}

#[test]
fn export_help_mentions_client_for_ambiguous_timeline_session_ids() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["export", "--help"])
        .output()
        .expect("run adr export help");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Requires --session-id to select a single session"));
    assert!(stdout.contains("add --client when a session id is ambiguous across clients"));
}

#[test]
fn top_level_version_prints_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("--version")
        .output()
        .expect("run adr --version");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        format!(
            "adr {} ({})",
            env!("CARGO_PKG_VERSION"),
            env!("ADR_GIT_HASH")
        )
    );
}

#[test]
fn status_reports_latest_health_event() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let scan = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "scan",
            "--once",
            "--allow-fixtures",
            "--root",
            "tests/fixtures/session_stores",
            "--log-path",
        ])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr scan");
    assert!(
        scan.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&scan.stderr)
    );

    let status = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("status")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--state-path")
        .arg(&state_path)
        .output()
        .expect("run adr status");
    assert!(
        status.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let summary: Value = serde_json::from_slice(&status.stdout).expect("status json");

    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["log_path"], log_path.display().to_string());
    assert_eq!(summary["state_path"], state_path.display().to_string());
    assert!(summary["last_scan_time"].as_str().is_some());
    assert_eq!(summary["health_component"], "scanner");
    assert_eq!(summary["health_check_name"], "source_discovery");
    assert_eq!(summary["health_check_status"], "ok");
    assert_eq!(summary["active_policy_name"], Value::Null);
    assert_eq!(summary["rule_count"], 18);
    assert!(
        summary["detection_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert_eq!(summary["threshold_config"]["low"], 20);
    assert_eq!(summary["threshold_config"]["medium"], 50);
    assert_eq!(summary["threshold_config"]["triage"], 70);
    assert_eq!(summary["threshold_config"]["alert"], 90);
    assert_eq!(summary["source_counts"]["codex.jsonl"], 40);
    assert_eq!(summary["source_counts"]["opencode.sqlite"], 1);
    assert_eq!(summary["source_counts"]["copilot.copilot_process_log"], 5);
}

#[test]
fn status_rejects_invalid_jsonl() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "health",
                "severity": "informational",
                "client": "scanner",
                "session_id": "scanner",
                "rule_ids": [],
            })
            .to_string(),
            "{not-json".to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let status = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("status")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--state-path")
        .arg(&state_path)
        .output()
        .expect("run adr status");

    assert!(!status.status.success());
    assert!(
        String::from_utf8_lossy(&status.stderr).contains("invalid JSONL"),
        "stderr: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

#[test]
fn export_rejects_invalid_jsonl() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "detection",
                "severity": "critical",
                "client": "codex",
                "session_id": "session-a",
                "rule_ids": ["mcp.test"],
            })
            .to_string(),
            "{not-json".to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .output()
        .expect("run adr export");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid JSONL"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn export_filters_jsonl_by_event_fields() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "detection",
                "severity": "critical",
                "client": "codex",
                "session_id": "session-a",
                "rule_ids": ["mcp.test"],
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-05-01T00:10:00Z",
                "event_type": "detection",
                "severity": "high",
                "client": "opencode",
                "session_id": "session-b",
                "rule_ids": ["secret.test"],
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args([
            "--severity",
            "CRITICAL",
            "--client",
            "codex",
            "--session-id",
            "session-a",
            "--rule-id",
            "mcp.test",
            "--since",
            "2026-05-01T00:00:00Z",
            "--until",
            "2026-05-01T00:00:00Z",
        ])
        .output()
        .expect("run adr export");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("exported json"))
        .collect::<Vec<_>>();

    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["session_id"], "session-a");
    assert_eq!(lines[0]["rule_ids"][0], "mcp.test");
}

#[test]
fn export_time_filters_accept_canonical_millisecond_timestamps() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        serde_json::json!({
            "timestamp": "2026-05-01T00:00:00.000Z",
            "event_type": "detection",
            "severity": "critical",
            "client": "codex",
            "session_id": "session-a",
            "rule_ids": ["mcp.test"],
        })
        .to_string(),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--since", "2026-05-01T00:00:00Z"])
        .args(["--until", "2026-05-01T00:00:00Z"])
        .output()
        .expect("run adr export with canonical timestamp filters");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("exported json"))
        .collect::<Vec<_>>();

    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["timestamp"], "2026-05-01T00:00:00.000Z");
}

#[test]
fn export_time_filters_accept_offset_rfc3339_inputs() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        serde_json::json!({
            "timestamp": "2026-05-01T10:00:00.000Z",
            "event_type": "detection",
            "severity": "critical",
            "client": "codex",
            "session_id": "session-a",
            "rule_ids": ["mcp.test"],
        })
        .to_string(),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--since", "2026-05-01T12:00:00+02:00"])
        .args(["--until", "2026-05-01T12:00:00+02:00"])
        .output()
        .expect("run adr export with offset timestamp filters");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("exported json"))
        .collect::<Vec<_>>();

    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["timestamp"], "2026-05-01T10:00:00.000Z");
}

#[test]
fn export_rejects_invalid_time_filters() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let since_output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--since", "not-a-timestamp"])
        .output()
        .expect("run adr export with invalid since");
    assert!(!since_output.status.success());
    assert!(
        String::from_utf8_lossy(&since_output.stderr)
            .contains("--since requires a valid RFC3339 timestamp")
    );

    let until_output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--until", "still-not-a-timestamp"])
        .output()
        .expect("run adr export with invalid until");
    assert!(!until_output.status.success());
    assert!(
        String::from_utf8_lossy(&until_output.stderr)
            .contains("--until requires a valid RFC3339 timestamp")
    );
}

#[test]
fn export_rejects_inverted_time_filter_window() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--since", "2026-05-01T00:01:00Z"])
        .args(["--until", "2026-05-01T00:00:00Z"])
        .output()
        .expect("run adr export with inverted time window");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--since must be less than or equal to --until")
    );
}

#[test]
fn export_summary_reports_filtered_counts() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "health",
                "severity": "informational",
                "client": "codex,opencode",
                "session_id": "scanner",
                "rule_ids": [],
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-05-01T00:01:00Z",
                "event_type": "detection",
                "severity": "critical",
                "client": "codex",
                "session_id": "session-a",
                "rule_ids": ["mcp.test", "secret.test"],
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--client", "codex", "--format", "summary"])
        .output()
        .expect("run adr export summary");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("events: 1"));
    assert!(stdout.contains("  detection: 1"));
    assert!(stdout.contains("  critical: 1"));
    assert!(stdout.contains("  codex: 1"));
    assert!(stdout.contains("  mcp.test: 1"));
    assert!(stdout.contains("  secret.test: 1"));
}

#[test]
fn export_elastic_bulk_wraps_canonical_events_without_rewriting_fields() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "timestamp": "2026-05-01T00:00:00Z",
                "event_id": "event-a",
                "event_type": "health",
                "severity": "informational",
                "client": "codex",
                "session_id": "scanner",
                "rule_ids": [],
            })
            .to_string(),
            serde_json::json!({
                "timestamp": "2026-05-01T00:01:00Z",
                "event_id": "event-b",
                "event_type": "detection",
                "severity": "critical",
                "client": "codex",
                "session_id": "session-a",
                "rule_ids": ["mcp.test"],
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--severity", "critical", "--format", "elastic-bulk"])
        .output()
        .expect("run adr elastic bulk export");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("elastic bulk json"))
        .collect::<Vec<_>>();

    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["index"]["_index"], "adr-events");
    assert_eq!(lines[0]["index"]["_id"], "event-b");
    assert_eq!(lines[1]["event_type"], "detection");
    assert_eq!(lines[1]["event_id"], "event-b");
    assert_eq!(lines[1]["rule_ids"][0], "mcp.test");
    assert!(lines[1].get("_index").is_none());
    assert!(lines[1].get("index").is_none());
}

#[test]
fn export_correlate_emits_cross_session_event() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-a",
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "detection",
                "severity": "critical",
                "risk_score": 95,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "session-a",
                "rule_ids": ["mcp.test"],
                "categories": ["mcp_prompt_injection"],
                "tags": ["mcp"],
                "evidence": [],
            })
            .to_string(),
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-b",
                "timestamp": "2026-05-01T00:20:00Z",
                "event_type": "detection",
                "severity": "high",
                "risk_score": 80,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "session-b",
                "rule_ids": ["mcp.test", "network.test"],
                "categories": ["mcp_prompt_injection", "exfiltration"],
                "tags": ["mcp"],
                "evidence": [],
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--correlate")
        .output()
        .expect("run adr export correlate");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("exported json"))
        .collect::<Vec<_>>();

    assert_eq!(lines.len(), 1);
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    assert!(
        validator.is_valid(&lines[0]),
        "correlation event failed schema validation"
    );
    assert_eq!(lines[0]["event_type"], "correlation");
    assert_eq!(lines[0]["client"], "codex");
    assert_eq!(lines[0]["session_id"], "correlation");
    assert_eq!(lines[0]["rule_ids"][0], "mcp.test");
    assert_eq!(lines[0]["categories"][0], "cross_session_correlation");
    assert_eq!(lines[0]["risk_score"], 95);
    assert_eq!(
        lines[0]["evidence"]
            .as_array()
            .expect("evidence array")
            .iter()
            .filter(|item| item["field"] == "related_detection")
            .count(),
        2
    );
}

#[test]
fn export_timeline_produces_redacted_session_timeline() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-activity-a",
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "activity",
                "severity": "low",
                "risk_score": 15,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "session-a",
                "rule_ids": [],
                "categories": [],
                "tags": [],
                "evidence": [
                    {
                        "field": "record_counts",
                        "redacted_value": "{\"tool_call\":2,\"tool_result\":1,\"user_message\":1}",
                        "hash": "sha256:activity-counts"
                    }
                ],
            })
            .to_string(),
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-a",
                "timestamp": "2026-05-01T00:01:00Z",
                "event_type": "detection",
                "severity": "critical",
                "risk_score": 95,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "session-a",
                "tool_name": "shell",
                "rule_ids": ["mcp.tool_metadata.prompt_injection"],
                "categories": ["mcp_prompt_injection"],
                "tags": ["mcp"],
                "evidence": [
                    {
                        "field": "tool_result",
                        "redacted_value": "[REDACTED]",
                        "hash": "sha256:abc123",
                        "rule_id": "mcp.tool_metadata.prompt_injection"
                    }
                ],
                "triage": {
                    "verdict": "malicious",
                    "confidence": 0.95,
                    "reason": "MCP prompt injection detected"
                },
                "response": {
                    "recommended_action": "investigate_session",
                    "response_playbook": "mcp_injection",
                    "investigation_summary": "Agent received injected MCP instructions"
                }
            })
            .to_string(),
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-b",
                "timestamp": "2026-05-01T00:00:30Z",
                "event_type": "detection",
                "severity": "high",
                "risk_score": 80,
                "client": "codex",
                "session_id": "session-a",
                "rule_ids": ["network.controlled_test_domain.darkroast"],
                "categories": ["exfiltration"],
                "tags": ["network"],
                "evidence": []
            })
            .to_string(),
            // Different session — should not appear in session-a timeline.
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-c",
                "timestamp": "2026-05-01T00:02:00Z",
                "event_type": "detection",
                "severity": "medium",
                "risk_score": 50,
                "client": "opencode",
                "session_id": "session-b",
                "rule_ids": ["secret.test"],
                "categories": ["credential_access"],
                "tags": [],
                "evidence": []
            })
            .to_string(),
            // Same session_id on a different client — should force client disambiguation.
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-d",
                "timestamp": "2026-05-01T00:00:45Z",
                "event_type": "detection",
                "severity": "medium",
                "risk_score": 40,
                "client": "opencode",
                "agent": "opencode",
                "model": "claude-sonnet",
                "provider": "anthropic",
                "session_id": "session-a",
                "rule_ids": ["secret.test"],
                "categories": ["credential_access"],
                "tags": [],
                "evidence": []
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    // Test 1: --timeline requires --session-id.
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .output()
        .expect("run adr export timeline without session-id");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--timeline requires --session-id"),
        "expected validation error, got: {stderr}"
    );

    // Test 2: ambiguous cross-client session ids require --client disambiguation.
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "session-a"])
        .output()
        .expect("run adr export timeline");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--timeline resolved 2 sessions for session_id 'session-a'; add --client to disambiguate"),
        "expected ambiguity error, got: {stderr}"
    );

    // Test 3: adding --client selects a single timeline.
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "session-a"])
        .args(["--client", "codex"])
        .output()
        .expect("run adr export timeline with client filter");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("timeline json"))
        .collect();

    assert_eq!(lines.len(), 1, "expected one selected timeline");
    let codex_timeline = &lines[0];

    // Timeline metadata.
    assert_eq!(codex_timeline["event_type"], "timeline");
    assert_eq!(codex_timeline["session_id"], "session-a");
    assert_eq!(codex_timeline["client"], "codex");
    assert_eq!(codex_timeline["agent"], "codex");
    assert_eq!(codex_timeline["model"], "gpt-5");
    assert_eq!(codex_timeline["provider"], "openai");
    assert_eq!(codex_timeline["entry_count"], 3);
    assert_eq!(codex_timeline["detection_count"], 2);
    assert_eq!(codex_timeline["max_severity"], "critical");
    assert_eq!(codex_timeline["has_triage"], true);
    assert_eq!(codex_timeline["risk_summary"]["tool_call_count"], 2);
    assert_eq!(codex_timeline["risk_summary"]["risky_action_count"], 2);
    assert_eq!(codex_timeline["risk_summary"]["max_severity"], "critical");
    assert_eq!(codex_timeline["risk_summary"]["triage_ran"], true);
    assert!(
        codex_timeline["risk_summary"]["top_rule_ids"]
            .as_array()
            .expect("top rule ids")
            .contains(&Value::String(
                "mcp.tool_metadata.prompt_injection".to_string()
            ))
    );
    assert!(
        codex_timeline["risk_summary"]["top_rule_ids"]
            .as_array()
            .expect("top rule ids")
            .contains(&Value::String(
                "network.controlled_test_domain.darkroast".to_string()
            ))
    );
    assert!(
        codex_timeline["risk_summary"]["top_categories"]
            .as_array()
            .expect("top categories")
            .contains(&Value::String("mcp_prompt_injection".to_string()))
    );
    assert!(
        codex_timeline["risk_summary"]["top_categories"]
            .as_array()
            .expect("top categories")
            .contains(&Value::String("exfiltration".to_string()))
    );
    // Entries sorted by timestamp.
    let entries = codex_timeline["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["timestamp"], "2026-05-01T00:00:00Z");
    assert_eq!(entries[0]["event_type"], "activity");
    assert_eq!(entries[1]["timestamp"], "2026-05-01T00:00:30Z");
    assert_eq!(entries[1]["event_type"], "detection");
    assert_eq!(entries[1]["severity"], "high");
    assert_eq!(entries[2]["timestamp"], "2026-05-01T00:01:00Z");
    assert_eq!(entries[2]["event_type"], "detection");
    assert_eq!(entries[2]["severity"], "critical");
    assert_eq!(entries[2]["tool_name"], "shell");

    // Evidence is redacted: field + hash only, no redacted_value.
    let evidence = entries[2]["evidence"].as_array().expect("evidence");
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0]["field"], "tool_result");
    assert_eq!(evidence[0]["hash"], "sha256:abc123");
    assert!(
        evidence[0].get("redacted_value").is_none(),
        "redacted_value should not appear in timeline"
    );

    // Triage and response are included.
    assert_eq!(entries[2]["triage"]["verdict"], "malicious");
    assert_eq!(entries[2]["triage"]["confidence"], 0.95);
    assert_eq!(
        entries[2]["response"]["recommended_action"],
        "investigate_session"
    );

    // Rule ids are preserved.
    assert_eq!(
        entries[2]["rule_ids"][0],
        "mcp.tool_metadata.prompt_injection"
    );
}

#[test]
fn export_timeline_requires_session_id() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .output()
        .expect("run adr export timeline");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--timeline requires --session-id"));
}

#[test]
fn export_timeline_text_requires_timeline() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .args(["--format", "timeline-text"])
        .output()
        .expect("run adr export timeline text without timeline");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format timeline-text requires --timeline"));
}

#[test]
fn export_timeline_rejects_multiple_session_ids() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "session-a"])
        .args(["--session-id", "session-b"])
        .output()
        .expect("run adr export timeline with multiple session ids");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--timeline requires exactly one --session-id"));
}

#[test]
fn export_timeline_rejects_summary_format() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        serde_json::json!({
            "schema_version": "1.0",
            "event_type": "activity",
            "session_id": "timeline-summary-session",
            "client": "codex",
            "timestamp": "2026-05-01T00:00:00Z",
            "severity": "low",
            "risk_score": 20,
            "evidence": []
        })
        .to_string(),
    )
    .expect("write log event");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "timeline-summary-session"])
        .args(["--format", "summary"])
        .output()
        .expect("run adr export timeline summary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format summary does not support --timeline"));
}

#[test]
fn export_timeline_rejects_elastic_bulk_format() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "timeline-elastic-session"])
        .args(["--format", "elastic-bulk"])
        .output()
        .expect("run adr export timeline elastic bulk");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format elastic-bulk does not support --timeline"));
}

#[test]
fn export_timeline_rejects_correlate() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        serde_json::json!({
            "schema_version": "1.0",
            "event_type": "detection",
            "event_id": "adr-detection-correlate",
            "session_id": "timeline-correlate-session",
            "client": "codex",
            "timestamp": "2026-05-01T00:00:00Z",
            "severity": "high",
            "risk_score": 80,
            "rule_ids": ["secret.env.read"],
            "categories": ["secret_access"],
            "evidence": []
        })
        .to_string(),
    )
    .expect("write log event");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "timeline-correlate-session"])
        .arg("--correlate")
        .output()
        .expect("run adr export timeline correlate");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--correlate does not support --timeline"));
}

#[test]
fn export_source_root_requires_timeline() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--source-root")
        .arg(temp.path())
        .output()
        .expect("run adr export source-root without timeline");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--source-root requires --timeline"));
}

#[test]
fn export_source_root_rejects_summary_format() {
    let temp = tempdir().expect("tempdir");
    let source_dir = temp.path().join("codex/sessions/2026/05");
    fs::create_dir_all(&source_dir).expect("create fixture source dir");
    fs::write(
        source_dir.join("source-backed-summary.jsonl"),
        serde_json::json!({
            "type": "user",
            "timestamp": "2026-05-01T00:01:00Z",
            "session_id": "source-summary-session",
            "agent": "codex",
            "model": "gpt-5",
            "provider": "openai",
            "content": "Summarize the repository status"
        })
        .to_string(),
    )
    .expect("write source fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-summary-session"])
        .args(["--format", "summary"])
        .output()
        .expect("run adr export source-root timeline summary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format summary does not support --timeline"));
}

#[test]
fn export_source_root_rejects_jsonl_only_filters() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let severity_output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--severity", "critical"])
        .output()
        .expect("run adr export source-root with severity filter");
    assert!(!severity_output.status.success());
    assert!(
        String::from_utf8_lossy(&severity_output.stderr)
            .contains("--source-root does not support --severity filters")
    );

    let rule_output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--rule-id", "secret.env.read"])
        .output()
        .expect("run adr export source-root with rule filter");
    assert!(!rule_output.status.success());
    assert!(
        String::from_utf8_lossy(&rule_output.stderr)
            .contains("--source-root does not support --rule-id filters")
    );

    let time_output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--since", "2026-05-01T00:00:00Z"])
        .output()
        .expect("run adr export source-root with time filter");
    assert!(!time_output.status.success());
    assert!(
        String::from_utf8_lossy(&time_output.stderr)
            .contains("--source-root does not support --since/--until filters")
    );

    let correlate_output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .arg("--correlate")
        .output()
        .expect("run adr export source-root with correlate");
    assert!(!correlate_output.status.success());
    assert!(
        String::from_utf8_lossy(&correlate_output.stderr)
            .contains("--correlate does not support --timeline")
    );
}

#[test]
fn export_source_root_rejects_unknown_client_filter() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(&log_path, "").expect("write empty log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--client", "unknown-agent"])
        .output()
        .expect("run adr export source-root with unknown client");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--source-root does not support unknown client 'unknown-agent'"),
        "{stderr}"
    );
    assert!(stderr.contains("codex"), "{stderr}");
}

#[test]
fn export_timeline_text_produces_human_readable_session_timeline() {
    let temp = tempdir().expect("tempdir");
    let log_path = temp.path().join("adr-events.jsonl");
    fs::write(
        &log_path,
        [
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-activity-text",
                "timestamp": "2026-05-01T00:00:00Z",
                "event_type": "activity",
                "severity": "low",
                "risk_score": 15,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "text-session",
                "rule_ids": [],
                "categories": [],
                "tags": [],
                "evidence": [
                    {
                        "field": "record_counts",
                        "redacted_value": "{\"tool_call\":1,\"tool_result\":1,\"user_message\":1}",
                        "hash": "sha256:activity-counts"
                    }
                ]
            })
            .to_string(),
            serde_json::json!({
                "schema_version": "1.0",
                "event_id": "adr-detection-text",
                "timestamp": "2026-05-01T00:00:30Z",
                "event_type": "detection",
                "severity": "critical",
                "risk_score": 95,
                "client": "codex",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "session_id": "text-session",
                "tool_name": "shell",
                "rule_ids": ["mcp.tool_metadata.prompt_injection"],
                "categories": ["mcp_prompt_injection"],
                "tags": ["mcp"],
                "evidence": [
                    {
                        "field": "tool_result",
                        "redacted_value": "[REDACTED]",
                        "hash": "sha256:abc123",
                        "rule_id": "mcp.tool_metadata.prompt_injection"
                    }
                ],
                "triage": {
                    "verdict": "malicious",
                    "confidence": 0.95,
                    "reason": "MCP prompt injection detected"
                },
                "response": {
                    "recommended_action": "investigate_session",
                    "response_playbook": "mcp_injection",
                    "investigation_summary": "Agent received injected MCP instructions"
                }
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write log");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--timeline")
        .args(["--session-id", "text-session"])
        .args(["--format", "timeline-text"])
        .output()
        .expect("run adr export timeline text");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Timeline text-session (codex)"));
    assert!(stdout.contains("Agent: codex | Model: gpt-5 | Provider: openai"));
    assert!(stdout.contains("Entries: 2 | Detections: 1 | Max severity: critical | Triage: yes"));
    assert!(
        stdout.contains("Risk: tool_calls=1 risky_actions=1 max_severity=critical triage_ran=yes")
    );
    assert!(stdout.contains("[0] 2026-05-01T00:00:00Z low activity"));
    assert!(stdout.contains("[1] 2026-05-01T00:00:30Z critical detection tool=shell"));
    assert!(stdout.contains("Rules: mcp.tool_metadata.prompt_injection"));
    assert!(stdout.contains("Categories: mcp_prompt_injection"));
    assert!(stdout.contains("Evidence: tool_result hash=sha256:abc123"));
    assert!(
        stdout.contains("Triage: malicious confidence=0.95 reason=MCP prompt injection detected")
    );
    assert!(stdout.contains("Recommended action: investigate_session"));
    assert!(stdout.contains("Playbook: mcp_injection"));
    assert!(stdout.contains("Summary: Agent received injected MCP instructions"));
    assert!(!stdout.contains("\"event_type\""));
}

#[test]
fn export_timeline_from_source_root_uses_parsed_session_records() {
    let temp = tempdir().expect("tempdir");
    let source_dir = temp.path().join("codex/sessions/2026/05");
    fs::create_dir_all(&source_dir).expect("create fixture source dir");
    fs::write(
        source_dir.join("source-backed-timeline.jsonl"),
        [
            serde_json::json!({
                "type": "tool_result",
                "timestamp": "2026-05-01T00:03:00Z",
                "session_id": "source-session",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "tool_name": "shell",
                "content": "read /home/alice/project/.env and returned ghp_1234567890abcdefghijklmnop"
            })
            .to_string(),
            serde_json::json!({
                "type": "user",
                "timestamp": "2026-05-01T00:01:00Z",
                "session_id": "source-session",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "content": "Summarize the repository status"
            })
            .to_string(),
            serde_json::json!({
                "type": "tool_call",
                "timestamp": "2026-05-01T00:02:00Z",
                "session_id": "source-session",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "tool_name": "shell",
                "arguments": {"cmd": "cat /home/alice/project/.env"}
            })
            .to_string(),
            serde_json::json!({
                "type": "assistant",
                "timestamp": "2026-05-01T00:04:00Z",
                "session_id": "other-session",
                "agent": "codex",
                "content": "This different session should not export"
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write source fixture");
    let opencode_dir = temp
        .path()
        .join("opencode/storage/message/session-source-session");
    fs::create_dir_all(&opencode_dir).expect("create opencode fixture dir");
    fs::write(
        opencode_dir.join("messages.json"),
        serde_json::json!([
            {
                "type": "assistant",
                "timestamp": "2026-05-01T00:01:30Z",
                "session_id": "source-session",
                "agent": "opencode",
                "model": "claude-sonnet",
                "provider": "anthropic",
                "content": "OpenCode session sharing the same id should require client disambiguation"
            }
        ])
        .to_string(),
    )
    .expect("write opencode source fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .output()
        .expect("run adr source-backed timeline export");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--timeline resolved 2 sessions for session_id 'source-session'; add --client to disambiguate"),
        "expected ambiguity error, got: {stderr}"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-session"])
        .args(["--client", "codex"])
        .output()
        .expect("run adr source-backed timeline export with client filter");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("timeline json"))
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 1);
    let timeline = &lines[0];
    assert_eq!(timeline["event_type"], "timeline");
    assert_eq!(timeline["session_id"], "source-session");
    assert_eq!(timeline["client"], "codex");
    assert_eq!(timeline["agent"], "codex");
    assert_eq!(timeline["model"], "gpt-5");
    assert_eq!(timeline["provider"], "openai");
    assert_eq!(timeline["entry_count"], 3);
    assert_eq!(timeline["detection_count"], 1);
    assert_eq!(timeline["max_severity"], "medium");
    assert_eq!(timeline["has_triage"], false);
    assert_eq!(timeline["risk_summary"]["tool_call_count"], 1);
    assert_eq!(timeline["risk_summary"]["risky_action_count"], 1);
    assert_eq!(timeline["risk_summary"]["max_severity"], "medium");
    assert_eq!(timeline["risk_summary"]["triage_ran"], false);
    assert!(
        timeline["risk_summary"]["top_rule_ids"]
            .as_array()
            .expect("top rule ids")
            .contains(&Value::String("secret.env.read".to_string()))
    );
    assert!(
        timeline["risk_summary"]["top_categories"]
            .as_array()
            .expect("top categories")
            .contains(&Value::String("secret_access".to_string()))
    );
    let entries = timeline["entries"].as_array().expect("entries array");
    assert_eq!(entries[0]["event_type"], "user_message");
    assert_eq!(entries[0]["timestamp"], "2026-05-01T00:01:00Z");
    assert_eq!(entries[1]["event_type"], "tool_call");
    assert_eq!(entries[1]["tool_name"], "shell");
    assert_eq!(entries[2]["event_type"], "tool_result");
    assert_eq!(entries[2]["tool_name"], "shell");

    let arguments = entries[1]["evidence"]
        .as_array()
        .expect("tool call evidence")
        .iter()
        .find(|item| item["field"] == "arguments")
        .expect("arguments evidence");
    assert_eq!(
        arguments["redacted_value"],
        "{\"cmd\":\"cat /home/alice/project/[sensitive-path]\"}"
    );
    assert!(arguments["hash"].as_str().expect("hash").len() >= 64);

    let result = entries[2]["evidence"]
        .as_array()
        .expect("tool result evidence")
        .iter()
        .find(|item| item["field"] == "tool_result")
        .expect("tool result evidence");
    let redacted_result = result["redacted_value"].as_str().expect("redacted value");
    assert!(redacted_result.contains("[sensitive-path]"));
    assert!(redacted_result.contains("[redacted-secret]"));
    assert!(!redacted_result.contains("ghp_1234567890abcdefghijklmnop"));
}

#[test]
fn export_timeline_text_from_source_root_includes_risk_summary() {
    let temp = tempdir().expect("tempdir");
    let source_dir = temp.path().join("codex/sessions/2026/05");
    fs::create_dir_all(&source_dir).expect("create fixture source dir");
    fs::write(
        source_dir.join("source-backed-timeline-text.jsonl"),
        [
            serde_json::json!({
                "type": "user",
                "timestamp": "2026-05-01T00:01:00Z",
                "session_id": "source-text-session",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "content": "Inspect secrets exposure"
            })
            .to_string(),
            serde_json::json!({
                "type": "tool_call",
                "timestamp": "2026-05-01T00:02:00Z",
                "session_id": "source-text-session",
                "agent": "codex",
                "model": "gpt-5",
                "provider": "openai",
                "tool_name": "shell",
                "arguments": {"cmd": "cat /home/alice/project/.env"}
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write source fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .arg("export")
        .arg("--timeline")
        .arg("--source-root")
        .arg(temp.path())
        .args(["--session-id", "source-text-session"])
        .args(["--format", "timeline-text"])
        .output()
        .expect("run source-backed timeline text export");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Timeline source-text-session (codex)"));
    assert!(stdout.contains("Entries: 2 | Detections: 1 | Max severity: low | Triage: no"));
    assert!(stdout.contains(
        "Risk: tool_calls=1 risky_actions=1 max_severity=low triage_ran=no top_rules=secret.env.read top_categories=secret_access"
    ));
}

#[test]
fn rules_validate_reports_invalid_custom_regex() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "validate",
            "--rules",
            "tests/fixtures/custom_rules/invalid-regex.yaml",
        ])
        .output()
        .expect("run adr rules validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("custom.invalid_regex"));
}

#[test]
fn rules_validate_reports_unsupported_targets() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "validate",
            "--rules",
            "tests/fixtures/custom_rules/unsupported-target.yaml",
        ])
        .output()
        .expect("run adr rules validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("custom.unsupported_target"));
    assert!(stderr.contains("unsupported target 'raw_transcript'"));
    assert!(stderr.contains("supported targets"));
}

#[test]
fn rules_test_supports_sigma_inspired_custom_yaml() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "test",
            "tests/fixtures/custom_rules/custom-agent-behavior.jsonl",
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
        ])
        .output()
        .expect("run adr rules test");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["match_count"], 1);
    assert_eq!(
        summary["matches"][0]["rule_ids"][0],
        "custom.agent.malicious_behavior"
    );
    assert_eq!(
        summary["matches"][0]["categories"][0],
        "custom_agent_behavior"
    );
}

#[test]
fn rules_test_classifies_gemini_secret_file_reads_as_secret_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args([
            "rules",
            "test",
            "tests/fixtures/rule_samples/gemini-secret-file-read.jsonl",
            "--rules",
            "config/rules/tool-call-regex.yaml",
        ])
        .output()
        .expect("run adr rules test");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["match_count"], 1);
    assert!(
        summary["matches"][0]["rule_ids"]
            .as_array()
            .expect("rule ids array")
            .iter()
            .any(|rule| rule == "secret.env.read")
    );
    assert!(
        summary["matches"][0]["categories"]
            .as_array()
            .expect("categories array")
            .iter()
            .any(|category| category == "secret_access")
    );
}

#[test]
fn scan_uses_custom_rules_and_policy_category_filters() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("custom-agent-behavior.jsonl"),
        include_str!("../tests/fixtures/custom_rules/custom-agent-behavior.jsonl"),
    )
    .expect("custom behavior fixture");

    let enabled = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--dry-run", "--root"])
        .arg(&root)
        .args([
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
        ])
        .output()
        .expect("run adr scan");
    assert!(
        enabled.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&enabled.stderr)
    );
    let enabled_summary: Value = serde_json::from_slice(&enabled.stdout).expect("summary json");
    assert_eq!(enabled_summary["detection_count"], 1);
    assert_eq!(enabled_summary["rule_count"], 1);

    let disabled = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--dry-run", "--root"])
        .arg(&root)
        .args([
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
            "--policy",
            "tests/fixtures/custom_rules/disable-custom-category.yaml",
        ])
        .output()
        .expect("run adr scan");
    assert!(
        disabled.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    let disabled_summary: Value = serde_json::from_slice(&disabled.stdout).expect("summary json");
    assert_eq!(disabled_summary["detection_count"], 0);
    assert_eq!(disabled_summary["rule_count"], 0);
    assert_eq!(disabled_summary["policy"], "no-custom-agent-behavior");
}

#[test]
fn scan_allowlist_marks_matching_detections_suppressed() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("custom-agent-behavior.jsonl"),
        include_str!("../tests/fixtures/custom_rules/custom-agent-behavior.jsonl"),
    )
    .expect("custom behavior fixture");
    let allowlist_path = temp.path().join("allowlists.yaml");
    fs::write(
        &allowlist_path,
        r#"
version: 1
suppressions:
  - name: fixture-custom-agent
    clients: ["codex"]
    session_ids: ["custom-agent-behavior"]
    rule_ids: ["custom.agent.malicious_behavior"]
"#,
    )
    .expect("allowlist fixture");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--allow-fixtures", "--root"])
        .arg(&root)
        .args([
            "--rules",
            "tests/fixtures/custom_rules/sigma-inspired-agent-behavior.yaml",
            "--allowlist",
        ])
        .arg(&allowlist_path)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("run adr scan");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["detection_count"], 1);
    assert_eq!(summary["suppressed_count"], 1);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let detection = events
        .iter()
        .find(|event| event["event_type"] == "detection")
        .expect("suppressed detection");
    assert_eq!(detection["severity"], "informational");
    assert_eq!(detection["risk_score"], 0);
    assert!(
        detection["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag == "suppressed")
    );
    assert!(
        detection["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag == "allowlist:fixture-custom-agent")
    );
    assert_eq!(detection["triage"]["required"], false);
    assert!(detection["response"].is_null());
}

#[test]
fn scan_once_attaches_mock_llm_triage_to_detection_event() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions/2026/04");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("uc001-positive.jsonl"),
        include_str!(
            "../tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl"
        ),
    )
    .expect("uc001 fixture");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let (api_base, requests, handle) = start_mock_llm_server();
    let rule_path = std::env::current_dir()
        .expect("repo cwd")
        .join("config/rules/tool-call-regex.yaml");
    fs::write(
        temp.path().join(".env"),
        format!(
            "LITELLM_API_BASE={api_base}\nLITELLM_API_KEY=test-key\nMODEL=triage-model\nLLAMA_GUARD_MODEL=guard-model\n"
        ),
    )
    .expect("mock env");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--allow-fixtures", "--root"])
        .arg(&root)
        .args(["--rules"])
        .arg(&rule_path)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .env("ADR_RISK_THRESHOLD_TRIAGE", "1")
        .current_dir(temp.path())
        .output()
        .expect("run adr scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    handle.join().expect("mock server thread");
    let captured_requests = requests.try_iter().collect::<Vec<_>>();
    assert_eq!(captured_requests.len(), 2);
    assert!(captured_requests[0].contains("\"model\":\"guard-model\""));
    assert!(captured_requests[1].contains("\"model\":\"triage-model\""));

    let summary: Value = serde_json::from_slice(&output.stdout).expect("summary json");
    assert_eq!(summary["detection_count"], 1);

    let lines = fs::read_to_string(log_path).expect("log file");
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let detection = events
        .iter()
        .find(|event| event["event_type"] == "detection")
        .expect("detection event");
    assert_eq!(detection["triage"]["required"], true);
    assert_eq!(detection["triage"]["verdict"], "malicious");
    assert_eq!(detection["triage"]["confidence"], 0.97);
    assert_eq!(
        detection["triage"]["reason"],
        "mock triage confirmed MCP injection"
    );
}

#[test]
fn scan_once_preserves_schema_valid_benign_triage_verdict() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions/2026/04");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("uc001-positive.jsonl"),
        include_str!(
            "../tests/fixtures/session_stores/codex/sessions/2026/04/uc001-positive.jsonl"
        ),
    )
    .expect("uc001 fixture");
    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let (api_base, _requests, handle) = start_mock_llm_server_with_content(
        "{\"verdict\":\"benign\",\"severity\":\"low\",\"confidence\":0.88,\"reason\":\"mock triage treated fixture as explained developer workflow\"}",
    );
    let rule_path = std::env::current_dir()
        .expect("repo cwd")
        .join("config/rules/tool-call-regex.yaml");
    fs::write(
        temp.path().join(".env"),
        format!(
            "LITELLM_API_BASE={api_base}\nLITELLM_API_KEY=test-key\nMODEL=triage-model\nLLAMA_GUARD_MODEL=guard-model\n"
        ),
    )
    .expect("mock env");

    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--allow-fixtures", "--root"])
        .arg(&root)
        .args(["--rules"])
        .arg(&rule_path)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .env("ADR_RISK_THRESHOLD_TRIAGE", "1")
        .current_dir(temp.path())
        .output()
        .expect("run adr scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    handle.join().expect("mock server thread");

    let lines = fs::read_to_string(log_path).expect("log file");
    let detection = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .find(|event| event["event_type"] == "detection")
        .expect("detection event");
    assert_eq!(detection["triage"]["required"], true);
    assert_eq!(detection["triage"]["verdict"], "benign");
    assert_eq!(detection["triage"]["confidence"], 0.88);

    let schema: Value =
        serde_json::from_str(include_str!("../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    assert!(
        validator.is_valid(&detection),
        "benign triage event failed schema validation"
    );
}

#[test]
fn operational_alert_emitted_when_scanner_errors_exceed_threshold() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    // Use a malformed source that triggers a scanner_error event.
    fs::write(
        codex_sessions.join("malformed-source.jsonl"),
        include_str!("../tests/fixtures/rule_samples/malformed-source.jsonl"),
    )
    .expect("malformed fixture");

    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--allow-fixtures", "--root"])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .env("ADR_OP_ALERT_MAX_SCANNER_ERRORS", "0")
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = fs::read_to_string(log_path).expect("log file");
    let events: Vec<Value> = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect();

    let alert = events
        .iter()
        .find(|event| event["event_type"] == "operational_alert")
        .expect("operational_alert event should be present");
    assert_eq!(alert["severity"], "warning");
    assert_eq!(alert["client"], "scanner");
    assert_eq!(alert["session_id"], "scanner");
    assert!(
        alert["categories"]
            .as_array()
            .unwrap()
            .contains(&Value::String("operational".to_string()))
    );
    assert!(
        alert["tags"]
            .as_array()
            .unwrap()
            .contains(&Value::String("operational".to_string()))
    );
    assert!(
        alert["tags"]
            .as_array()
            .unwrap()
            .contains(&Value::String("scanner_health".to_string()))
    );
    assert_eq!(alert["risk_score"], 0);
    assert!(alert["adr_version"].is_string());

    // Verify the alert_type evidence field.
    let alert_type_evidence = alert["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["field"] == "alert_type")
        .expect("alert_type evidence");
    assert_eq!(
        alert_type_evidence["redacted_value"],
        "scanner_error_threshold_exceeded"
    );

    // Validate against the event schema.
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/event.schema.json")).expect("schema json");
    let validator = validator_for(&schema).expect("schema validator");
    assert!(
        validator.is_valid(alert),
        "operational_alert event failed schema validation"
    );
}

#[test]
fn operational_alert_not_emitted_when_scanner_errors_below_threshold() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    fs::write(
        codex_sessions.join("malformed-source.jsonl"),
        include_str!("../tests/fixtures/rule_samples/malformed-source.jsonl"),
    )
    .expect("malformed fixture");

    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--allow-fixtures", "--root"])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .env("ADR_OP_ALERT_MAX_SCANNER_ERRORS", "5")
        .output()
        .expect("run adr");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = fs::read_to_string(log_path).expect("log file");
    let events: Vec<Value> = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect();

    assert!(
        !events
            .iter()
            .any(|event| event["event_type"] == "operational_alert"),
        "operational_alert should not be emitted when errors are below threshold"
    );
}

#[test]
fn operational_alert_emitted_when_previously_seen_source_goes_silent() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("session_stores");
    let codex_sessions = root.join("codex/sessions");
    fs::create_dir_all(&codex_sessions).expect("codex sessions dir");
    let source_path = codex_sessions.join("session-a.jsonl");
    fs::write(
        &source_path,
        include_str!("../tests/fixtures/session_stores/codex/sessions/2026/04/session-a.jsonl"),
    )
    .expect("codex fixture");

    let log_path = temp.path().join("adr-events.jsonl");
    let state_path = temp.path().join("adr-state.json");
    let first = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--allow-fixtures", "--root"])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .output()
        .expect("first adr run");
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    fs::remove_file(&source_path).expect("remove source");
    thread::sleep(Duration::from_millis(2));

    let second = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["scan", "--once", "--allow-fixtures", "--root"])
        .arg(&root)
        .args(["--log-path"])
        .arg(&log_path)
        .args(["--state-path"])
        .arg(&state_path)
        .env("ADR_OP_ALERT_MAX_SOURCE_SILENCE_MS", "0")
        .output()
        .expect("second adr run");
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let lines = fs::read_to_string(log_path).expect("log file");
    let events: Vec<Value> = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect();
    let alert = events
        .iter()
        .find(|event| {
            event["event_type"] == "operational_alert"
                && event["evidence"].as_array().unwrap().iter().any(|e| {
                    e["field"] == "alert_type"
                        && e["redacted_value"] == "source_silence_threshold_exceeded"
                })
        })
        .expect("source silence operational_alert");

    assert!(alert["evidence"].as_array().unwrap().iter().any(|e| {
        e["field"] == "actual_value"
            && e["redacted_value"]
                .as_str()
                .is_some_and(|value| value.contains("missing_source=codex/codex.sessions/"))
    }));
}

#[test]
fn rules_coverage_reports_fixture_and_client_coverage() {
    let output = Command::new(env!("CARGO_BIN_EXE_adr"))
        .args(["rules", "coverage"])
        .output()
        .expect("run adr rules coverage");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("RULE COVERAGE REPORT"));
    assert!(stdout.contains("mcp.tool_metadata.prompt_injection"));
    assert!(stdout.contains("secret.env.read"));
    assert!(!stdout.contains("COVERAGE GAPS"));
    // Verify columns are present.
    assert!(stdout.contains("POSITIVE"));
    assert!(stdout.contains("CLIENTS"));
    assert!(stdout.contains("FALSE_POSITIVES"));
    assert!(stdout.contains("chain.secret_then_network"));
    assert!(stdout.contains("secret_access+download"));
    assert!(stdout.contains("Authorized troubleshooting may inspect environment files"));
}
