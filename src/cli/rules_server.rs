use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

use serde::Deserialize;

use crate::rules::{
    CompiledRuleSet, RuleLoadMode, RulePackPaths, RuleResolution,
    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements,
};
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::event::{
    PrivacySanitizer, SanitizationContext, opaque_identifier, terminal_identifier,
    terminal_session_id,
};
use telltale_schema::source::Source;

pub(crate) fn run_rules_server(
    addr: SocketAddr,
    config: RuleServerConfig<'_>,
    once: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !addr.ip().is_loopback() {
        return Err("rules serve only binds to loopback addresses".into());
    }
    let resolution = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        config.rule_pack_paths,
        config.explicit_rule_paths,
        config.policy_path,
        config.rule_load_mode,
        config.override_paths,
        &[],
    )?;
    let mut state = RuleServerState::new(resolution);
    let listener = TcpListener::bind(addr)?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "status": "listening",
            "addr": listener.local_addr()?.to_string(),
            "endpoints": [
                "/",
                "/api/rules",
                "/api/rules/validate",
                "/api/rules/preview",
            ],
        }))?
    );
    std::io::stdout().flush()?;
    if once {
        let (stream, _) = listener.accept()?;
        let _ = handle_rules_request(stream, &mut state, &config);
        return Ok(());
    }
    for stream in listener.incoming() {
        // A client disconnect, malformed request, or timeout is not a server failure.
        let _ = handle_rules_request(stream?, &mut state, &config);
    }
    Ok(())
}

pub(crate) struct RuleServerConfig<'a> {
    pub(crate) rule_pack_paths: &'a RulePackPaths,
    pub(crate) explicit_rule_paths: &'a [PathBuf],
    pub(crate) override_paths: &'a [PathBuf],
    pub(crate) policy_path: Option<&'a Path>,
    pub(crate) rule_load_mode: RuleLoadMode,
}

struct RuleServerState {
    rule_set: CompiledRuleSet,
    rule_summary: serde_json::Value,
}

impl RuleServerState {
    fn new(resolution: RuleResolution) -> Self {
        let rule_summary = rule_summary_json(&resolution.rule_set, &resolution.diagnostics);
        Self {
            rule_set: resolution.rule_set,
            rule_summary,
        }
    }
}

fn rule_summary_json(
    rule_set: &CompiledRuleSet,
    diagnostics: &crate::rules::RuleResolutionDiagnostics,
) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "rule_count": rule_set.rule_count(),
        "policy": rule_set.policy_name().map(|value| opaque_identifier("policy", value)),
        "rules": rule_set.summaries().into_iter().map(|rule| serde_json::json!({
            "id": terminal_identifier("rule", &rule.id),
            "category": terminal_identifier("category", &rule.category),
            "detection_class": rule.detection_class,
            "signal_type": rule.signal_type,
            "analytic_intent": rule.analytic_intent,
            "atlas_tags": rule.atlas_tags.into_iter().map(|value| terminal_identifier("atlas-tag", &value)).collect::<Vec<_>>(),
            "severity": rule.severity,
            "score": rule.score,
            "enabled": rule.enabled,
        })).collect::<Vec<_>>(),
        "sources": diagnostics.sources.iter().map(|source| opaque_identifier("rule-source", source)).collect::<Vec<_>>(),
        "provenance": diagnostics.provenance.iter().map(|entry| serde_json::json!({
            "id": terminal_identifier("rule", &entry.id),
            "kind": terminal_identifier("provenance-kind", &entry.kind),
            "winner": opaque_identifier("rule-source", &entry.winner),
            "replaced_sources": entry.replaced_sources.iter().map(|source| opaque_identifier("rule-source", source)).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

#[derive(Clone, Copy)]
enum RuleServerRoute {
    Editor,
    Summary,
    Validate,
    Preview,
    NotFound,
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn handle_rules_request(
    mut stream: TcpStream,
    state: &mut RuleServerState,
    config: &RuleServerConfig<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer_ip = stream.peer_addr()?.ip();
    if !peer_ip.is_loopback() {
        write_http_response(
            &mut stream,
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            "loopback clients only",
        )?;
        return Ok(());
    }
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err((status, reason)) => {
            return write_http_response(&mut stream, status, reason, "text/plain", reason);
        }
    };
    if write_rules_route_response(
        &mut stream,
        rule_server_route(&request),
        &request.body,
        state,
        config,
    )
    .is_err()
    {
        // Do not expose parser text, paths, request headers, or request bodies.
        write_json_api_response(&mut stream, ApiResponse::bad_request("invalid request"))?;
    }
    Ok(())
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, (u16, &'static str)> {
    let bad = (400, "Bad Request");
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    let mut bytes = Vec::new();
    // Read only the bounded header before admitting a body. The absolute deadline
    // also bounds clients that drip a byte before each socket timeout.
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == MAX_HEADER_BYTES {
            return Err((431, "Request Header Fields Too Large"));
        }
        let mut byte = [0];
        read_before_deadline(stream, &mut byte, deadline)?;
        bytes.push(byte[0]);
    }
    let header = std::str::from_utf8(&bytes).map_err(|_| bad)?;
    let mut lines = header.split("\r\n");
    let parts = lines.next().ok_or(bad)?.split(' ').collect::<Vec<_>>();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" {
        return Err(bad);
    }
    let (method, path) = (parts[0], parts[1]);
    let mut headers = std::collections::BTreeMap::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(bad)?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || headers
                .insert(name.to_ascii_lowercase(), value.trim())
                .is_some()
        {
            return Err(bad);
        }
    }
    let authority = stream.local_addr().map_err(|_| bad)?.to_string();
    if headers.get("host") != Some(&authority.as_str())
        || headers
            .get("origin")
            .is_some_and(|origin| *origin != format!("http://{authority}"))
        || headers
            .get("sec-fetch-site")
            .is_some_and(|site| !matches!(*site, "same-origin" | "none"))
    {
        return Err((403, "Forbidden"));
    }
    if headers.contains_key("transfer-encoding") || headers.contains_key("expect") {
        return Err(bad);
    }
    let content_length = headers
        .get("content-length")
        .map(|value| {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad);
            }
            value.parse::<usize>().map_err(|_| bad)
        })
        .transpose()?
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err((413, "Content Too Large"));
    }
    if method == "POST"
        && !headers.get("content-type").is_some_and(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
    {
        return Err((415, "Unsupported Media Type"));
    }
    let mut body = vec![0; content_length];
    read_before_deadline(stream, &mut body, deadline)?;
    Ok(HttpRequest {
        method: method.into(),
        path: path.into(),
        body,
    })
}

fn read_before_deadline(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), (u16, &'static str)> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or((408, "Request Timeout"))?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| (400, "Bad Request"))?;
        match stream.read(bytes) {
            Ok(0) => return Err((400, "Bad Request")),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err((408, "Request Timeout"));
            }
            Err(_) => return Err((400, "Bad Request")),
        }
    }
    Ok(())
}

fn rule_server_route(request: &HttpRequest) -> RuleServerRoute {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") | ("HEAD", "/") => RuleServerRoute::Editor,
        ("GET", "/api/rules") | ("HEAD", "/api/rules") => RuleServerRoute::Summary,
        ("POST", "/api/rules/validate") => RuleServerRoute::Validate,
        ("POST", "/api/rules/preview") => RuleServerRoute::Preview,
        _ => RuleServerRoute::NotFound,
    }
}

fn write_rules_route_response(
    stream: &mut TcpStream,
    route: RuleServerRoute,
    body: &[u8],
    state: &mut RuleServerState,
    _config: &RuleServerConfig<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    match route {
        RuleServerRoute::Editor => write_http_response(
            stream,
            200,
            "OK",
            "text/html; charset=utf-8",
            RULE_EDITOR_HTML,
        ),
        RuleServerRoute::Summary => write_json_response(stream, 200, "OK", &state.rule_summary),
        RuleServerRoute::Validate => write_json_api_response(stream, validate_rules_request(body)?),
        RuleServerRoute::Preview => {
            write_json_api_response(stream, preview_rules_request(body, &state.rule_set)?)
        }
        RuleServerRoute::NotFound => write_http_response(
            stream,
            404,
            "Not Found",
            "text/plain; charset=utf-8",
            "not found",
        ),
    }
}

#[derive(Debug, Deserialize)]
struct RuleValidationRequest {
    rules_yaml: String,
    #[serde(default)]
    policy_yaml: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RulePreviewRequest {
    fixture_path: PathBuf,
    #[serde(default)]
    rules_yaml: Option<String>,
    #[serde(default)]
    policy_yaml: Option<String>,
}

struct ApiResponse {
    status_code: u16,
    reason: &'static str,
    body: serde_json::Value,
}

impl ApiResponse {
    fn ok(body: serde_json::Value) -> Self {
        Self {
            status_code: 200,
            reason: "OK",
            body,
        }
    }

    fn bad_request(error: impl Into<String>) -> Self {
        let error = PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &error.into());
        Self {
            status_code: 400,
            reason: "Bad Request",
            body: serde_json::json!({
                "status": "error",
                "error": error,
            }),
        }
    }
}

fn validate_rules_request(body: &[u8]) -> Result<ApiResponse, Box<dyn std::error::Error>> {
    let request: RuleValidationRequest = serde_json::from_slice(body)?;
    match compile_rule_yaml(&request.rules_yaml, request.policy_yaml.as_deref()) {
        Ok(rule_set) => Ok(ApiResponse::ok(rule_summary_json(
            &rule_set,
            &crate::rules::RuleResolutionDiagnostics {
                sources: Vec::new(),
                provenance: Vec::new(),
            },
        ))),
        Err(error) => Ok(ApiResponse::bad_request(error.to_string())),
    }
}

fn preview_rules_request(
    body: &[u8],
    default_rule_set: &CompiledRuleSet,
) -> Result<ApiResponse, Box<dyn std::error::Error>> {
    let request: RulePreviewRequest = serde_json::from_slice(body)?;
    let fixture_path = match canonical_fixture_path(&request.fixture_path) {
        Ok(path) => path,
        Err(error) => return Ok(ApiResponse::bad_request(error.to_string())),
    };
    let rule_set = if let Some(rules_yaml) = request.rules_yaml.as_deref() {
        match compile_rule_yaml(rules_yaml, request.policy_yaml.as_deref()) {
            Ok(rule_set) => rule_set,
            Err(error) => return Ok(ApiResponse::bad_request(error.to_string())),
        }
    } else {
        default_rule_set.clone()
    };
    let source = Source {
        client: ClientId::Codex,
        kind: SourceKind::Jsonl,
        source_id: "codex.sessions".to_string(),
        path: fixture_path.clone(),
    };
    let rules = match telltale_detect::v2::compile_rule_v1(&rule_set.compatibility_export()) {
        Ok(rules) => rules,
        Err(error) => return Ok(ApiResponse::bad_request(error.to_string())),
    };
    let observed_at = telltale_schema::observation::ObservedAt::new(
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?,
    )?;
    let result = match telltale_core::canonical_runtime::process_source(
        &source,
        observed_at,
        None,
        telltale_core::canonical_runtime::SourceContext {
            mcp_servers: &[],
            rules: &rules,
            pre_policy_rules: None,
            process: None,
            prior: &crate::baseline::BaselineSnapshotStore::default(),
            baseline_deviation: Default::default(),
        },
    ) {
        Ok(result) => result,
        Err(error) => return Ok(ApiResponse::bad_request(error.to_string())),
    };
    let matches = result.events
        .iter()
        .filter(|event| event.event_type == "detection")
        .map(|event| {
            serde_json::json!({
                "session_id": terminal_session_id(&event.session_id),
                "severity": event.severity,
                "risk_score": event.risk_score,
                "rule_ids": event.rule_ids.iter().map(|value| terminal_identifier("rule", value)).collect::<Vec<_>>(),
                "categories": event.categories.iter().map(|value| terminal_identifier("category", value)).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

    Ok(ApiResponse::ok(serde_json::json!({
        "status": "ok",
        "fixture_path": PrivacySanitizer::sanitize(
            SanitizationContext::Path,
            &display_fixture_path(&fixture_path),
        ),
        "match_count": matches.len(),
        "matches": matches,
    })))
}

fn compile_rule_yaml(
    rules_yaml: &str,
    policy_yaml: Option<&str>,
) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    if rules_yaml.len() + policy_yaml.map_or(0, str::len) > MAX_BODY_BYTES {
        return Err("rule editor document limit exceeded".into());
    }
    for document in std::iter::once(rules_yaml).chain(policy_yaml) {
        reject_yaml_references(document)?;
    }
    let rules: telltale_rules::RuleSet = serde_yaml::from_str(rules_yaml)?;
    let matchers: usize = rules
        .rules
        .iter()
        .map(|rule| {
            (if rule.regex.is_some() {
                rule.targets.len()
            } else {
                0
            }) + rule
                .detection
                .as_ref()
                .map_or(0, |d| d.selection.len() + d.exclude.len())
        })
        .sum();
    if rules.rules.len() > 16 || rules.modifiers.len() > 16 || matchers > 16 {
        return Err("rule editor supports at most 16 rules, modifiers, and matchers per request; use rules validate for larger packs".into());
    }
    let policy = policy_yaml
        .map(serde_yaml::from_str::<telltale_rules::RulePolicy>)
        .transpose()?;
    telltale_rules::merge_rule_sets(vec![rules])?.compile(policy.as_ref())
}

fn reject_yaml_references(document: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Conservative lexical admission, before serde_yaml can expand references.
    // Delimiter-shaped markers in comments/quoted/block text are also refused;
    // the offline CLI remains available for the full YAML language.
    let mut boundary = true;
    for ch in document.chars() {
        if boundary && matches!(ch, '&' | '*') {
            return Err("YAML anchors and aliases are not supported by the HTTP rule editor; use rules validate offline".into());
        }
        boundary =
            ch.is_whitespace() || matches!(ch, '\u{feff}' | '[' | '{' | ',' | ':' | '?' | '-');
    }
    Ok(())
}

fn canonical_fixture_path(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let requested = if path.is_absolute() {
        path.to_path_buf()
    } else {
        manifest_dir.join(path)
    };
    let canonical = requested.canonicalize()?;
    let fixture_root = manifest_dir.join("tests/fixtures").canonicalize()?;
    if !canonical.starts_with(&fixture_root) {
        return Err("preview fixture must be under tests/fixtures".into());
    }
    let metadata = std::fs::metadata(&canonical)?;
    if !metadata.is_file() || metadata.len() > 256 * 1024 {
        return Err("preview requires a regular fixture of at most 256 KiB".into());
    }
    Ok(canonical)
}

fn display_fixture_path(path: &Path) -> String {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let relative = match manifest_dir.canonicalize() {
        Ok(canonical_manifest_dir) => path.strip_prefix(&canonical_manifest_dir).unwrap_or(path),
        Err(_) => path.strip_prefix(manifest_dir).unwrap_or(path),
    };
    relative
        .display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn write_json_api_response(
    stream: &mut TcpStream,
    response: ApiResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    write_json_response(
        stream,
        response.status_code,
        response.reason,
        &response.body,
    )
}

fn write_json_response(
    stream: &mut TcpStream,
    status_code: u16,
    reason: &str,
    body: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    write_http_response(
        stream,
        status_code,
        reason,
        "application/json",
        &serde_json::to_string(body)?,
    )
}

fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    reason: &str,
    content_type: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    write!(
        stream,
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    Ok(())
}

const RULE_EDITOR_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Telltale Rules</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, sans-serif; }
body { margin: 0; padding: 24px; }
main { max-width: 960px; margin: 0 auto; }
section { margin-top: 24px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px; border-bottom: 1px solid #8885; text-align: left; }
label { display: block; margin: 12px 0 4px; font-weight: 600; }
textarea, input { box-sizing: border-box; width: 100%; font: inherit; }
textarea { min-height: 160px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
button { margin-top: 12px; padding: 6px 10px; font: inherit; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
</head>
<body>
<main>
<h1>Telltale Rules</h1>
<p>Read-only validation and preview. Edit rule files locally; saving over HTTP is disabled.</p>
<table>
<thead><tr><th>ID</th><th>Category</th><th>Severity</th><th>Score</th></tr></thead>
<tbody id="rules"></tbody>
</table>
<section>
<h2>Validate</h2>
<label for="rules-yaml">Rule YAML</label>
<textarea id="rules-yaml"></textarea>
<button id="validate-rules">Validate</button>
<pre id="validation-result"></pre>
</section>
<section>
<h2>Fixture Preview</h2>
<label for="fixture-path">Fixture path</label>
<input id="fixture-path" value="tests/fixtures/rule_samples/tool-injection-shape.jsonl">
<button id="preview-rules">Preview</button>
<pre id="preview-result"></pre>
</section>
</main>
<script>
fetch('/api/rules').then(response => response.json()).then(data => {
  const body = document.getElementById('rules');
  body.textContent = '';
  for (const rule of data.rules) {
    const row = document.createElement('tr');
    for (const key of ['id', 'category', 'severity', 'score']) {
      const cell = document.createElement('td');
      cell.textContent = rule[key];
      row.appendChild(cell);
    }
    body.appendChild(row);
  }
});

function postJson(path, payload, target) {
  fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  }).then(async response => {
    const data = await response.json();
    target.textContent = JSON.stringify(data, null, 2);
  }).catch(error => {
    target.textContent = String(error);
  });
}

document.getElementById('validate-rules').addEventListener('click', () => {
  postJson('/api/rules/validate', {
    rules_yaml: document.getElementById('rules-yaml').value
  }, document.getElementById('validation-result'));
});

document.getElementById('preview-rules').addEventListener('click', () => {
  postJson('/api/rules/preview', {
    rules_yaml: document.getElementById('rules-yaml').value || undefined,
    fixture_path: document.getElementById('fixture-path').value
  }, document.getElementById('preview-result'));
});
</script>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    #[test]
    fn yaml_references_are_rejected_before_typed_expansion_in_both_documents() {
        for raw in [
            "&root {}",
            "\u{feff}&root {}",
            "a: &a [x]",
            "a: [*a]",
            "a: {x: &a y}",
            "a:\u{85}&a x",
            "a:\u{2028}*a",
        ] {
            assert!(super::reject_yaml_references(raw).is_err());
        }
        assert!(super::reject_yaml_references("regex: '.*foo[ab]*'\n").is_ok());
        let rules = "version: 1\ndescription: synthetic\ndefaults: {case_insensitive: false, enabled: true}\nrules: []\nmodifiers: []\n";
        assert!(
            super::compile_rule_yaml(
                rules,
                Some("version: 1\nname: &name synthetic\ndisabled_rules: []\n")
            )
            .unwrap_err()
            .to_string()
            .contains("YAML anchors and aliases")
        );
    }
    #[test]
    fn editor_compilation_counts_each_target_matcher() {
        let raw = format!(
            "version: 1\ndescription: synthetic\ndefaults: {{case_insensitive: false, enabled: true}}\nrules:\n  - id: synthetic\n    category: test\n    severity: low\n    score: 1\n    targets: [{}]\n    regex: 'x'\n    tags: []\n    explanation: synthetic\nmodifiers: []\n",
            vec!["command"; 17].join(",")
        );
        assert!(
            super::compile_rule_yaml(&raw, None)
                .unwrap_err()
                .to_string()
                .contains("16")
        );
    }
    use super::{
        compile_rule_yaml, preview_rules_request, rule_summary_json, validate_rules_request,
    };

    #[test]
    fn preview_and_validation_reject_unsupported_rule_versions() {
        let valid = "version: 1\ndescription: synthetic\ndefaults: {case_insensitive: false, enabled: true}\nrules: []\nmodifiers: []\n";
        let default = compile_rule_yaml(valid, None).expect("v1 compiles");
        for version in [0, 2] {
            let raw = valid.replacen("version: 1", &format!("version: {version}"), 1);
            let validate = serde_json::to_vec(&serde_json::json!({ "rules_yaml": raw })).unwrap();
            let response = validate_rules_request(&validate).expect("validation response");
            assert_eq!(response.status_code, 400);
            assert!(
                response.body["error"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("unsupported rule set version {version}"))
            );
            let preview = serde_json::to_vec(&serde_json::json!({
                "rules_yaml": raw,
                "fixture_path": "tests/fixtures/rule_samples/privacy-session-id.jsonl"
            }))
            .unwrap();
            let response = preview_rules_request(&preview, &default).expect("preview response");
            assert_eq!(response.status_code, 400);
            assert!(
                response.body["error"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("unsupported rule set version {version}"))
            );
        }
    }

    #[test]
    fn preview_rejects_unsafe_source_sessions_without_leaking() {
        let sessions = [
            "TOKEN=TT_PRIVACY_RULES_SERVER_SESSION_ASSIGNMENT_25",
            "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12",
            "https://user:TT_PRIVACY_RULES_SERVER_SESSION_URL_25@session.example.invalid",
        ];
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rule_samples/privacy-session-id.jsonl"
        );
        let body = serde_json::to_vec(&serde_json::json!({ "fixture_path": fixture }))
            .expect("preview request JSON");
        let rule_set = compile_rule_yaml(
            r#"version: 1
description: synthetic privacy preview rule
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: fixture.session
    category: test
    severity: low
    score: 20
    targets: [command]
    regex: "cat \\.env"
    tags: []
    explanation: synthetic privacy preview rule
modifiers: []
"#,
            None,
        )
        .expect("synthetic rule set");
        let response = preview_rules_request(&body, &rule_set).expect("preview response");
        let serialized = serde_json::to_string(&response.body).expect("preview JSON");

        for session in sessions {
            assert!(
                !serialized.contains(session),
                "rules preview retained a controlled session marker"
            );
        }
        assert_eq!(response.status_code, 400);
        assert_eq!(response.body["status"], "error");
        assert!(response.body["error"].as_str().is_some_and(|value| {
            value.contains("canonical source processing failed: Acquisition")
        }));
    }

    #[test]
    fn summary_omits_policy_source_and_provenance_text() {
        let marker = "ghp_abcdefghijklmnop";
        let rule_set = compile_rule_yaml(
            &format!(
                r#"version: 1
description: synthetic privacy summary rule
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: {marker}.rule
    category: {marker}
    severity: low
    score: 20
    targets: [command]
    regex: "cat \\.env"
    tags: []
    explanation: synthetic privacy summary rule
modifiers: []
"#
            ),
            Some(&format!(
                "version: 1\nname: {marker}\nenabled_rules: []\ndisabled_rules: []\n"
            )),
        )
        .expect("synthetic rule set");
        let summary = rule_summary_json(
            &rule_set,
            &crate::rules::RuleResolutionDiagnostics {
                sources: vec![format!(
                    "https://{marker}@source.example.invalid/rules.yaml"
                )],
                provenance: vec![crate::rules::RuleProvenance {
                    id: format!("{marker}.rule"),
                    kind: "rule".to_string(),
                    winner: format!("/private/{marker}/winner.yaml"),
                    replaced_sources: vec![format!("/private/{marker}/replaced.yaml")],
                }],
            },
        );

        assert!(
            !serde_json::to_string(&summary)
                .expect("serialize summary")
                .contains(marker),
            "rules-server summary exposed policy, source, or provenance text"
        );
    }
}
