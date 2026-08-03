use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::detection::detect_sources_with_rules;
use crate::rules::{
    CompiledRuleSet, RuleLoadMode, RulePackPaths, RuleResolution, load_rule_set_from_documents,
    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements,
};
use telltale_schema::clients::{ClientId, SourceKind};
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
                "/api/rules/save",
            ],
        }))?
    );
    std::io::stdout().flush()?;
    if once {
        let (stream, _) = listener.accept()?;
        handle_rules_request(stream, &mut state, &config)?;
        return Ok(());
    }
    for stream in listener.incoming() {
        handle_rules_request(stream?, &mut state, &config)?;
    }
    Ok(())
}

pub(crate) struct RuleServerConfig<'a> {
    pub(crate) rule_pack_paths: &'a RulePackPaths,
    pub(crate) explicit_rule_paths: &'a [PathBuf],
    pub(crate) editable_rule_paths: &'a [PathBuf],
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

    fn reload(&mut self, resolution: RuleResolution) {
        *self = Self::new(resolution);
    }
}

fn rule_summary_json(
    rule_set: &CompiledRuleSet,
    diagnostics: &crate::rules::RuleResolutionDiagnostics,
) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "rule_count": rule_set.rule_count(),
        "policy": rule_set.policy_name(),
        "rules": rule_set.summaries(),
        "sources": diagnostics.sources,
        "provenance": diagnostics.provenance,
    })
}

#[derive(Clone, Copy)]
enum RuleServerRoute {
    Editor,
    Summary,
    Validate,
    Preview,
    Save,
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
    let request = read_http_request(&stream)?;
    write_rules_route_response(
        &mut stream,
        rule_server_route(&request),
        &request.body,
        state,
        config,
    )?;
    Ok(())
}

fn read_http_request(stream: &TcpStream) -> Result<HttpRequest, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let mut content_length = 0_usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        let trimmed = header.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("Content-Length: ") {
            content_length = value.parse::<usize>()?;
        }
    }

    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let mut parts = request_line.split_whitespace();
    Ok(HttpRequest {
        method: parts.next().unwrap_or_default().to_string(),
        path: parts.next().unwrap_or_default().to_string(),
        body,
    })
}

fn rule_server_route(request: &HttpRequest) -> RuleServerRoute {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") | ("HEAD", "/") => RuleServerRoute::Editor,
        ("GET", "/api/rules") | ("HEAD", "/api/rules") => RuleServerRoute::Summary,
        ("POST", "/api/rules/validate") => RuleServerRoute::Validate,
        ("POST", "/api/rules/preview") => RuleServerRoute::Preview,
        ("POST", "/api/rules/save") => RuleServerRoute::Save,
        _ => RuleServerRoute::NotFound,
    }
}

fn write_rules_route_response(
    stream: &mut TcpStream,
    route: RuleServerRoute,
    body: &[u8],
    state: &mut RuleServerState,
    config: &RuleServerConfig<'_>,
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
        RuleServerRoute::Save => {
            let response = save_rules_request(
                body,
                config.rule_pack_paths,
                config.explicit_rule_paths,
                config.editable_rule_paths,
                config.override_paths,
                config.policy_path,
                config.rule_load_mode,
            )?;
            if response.status_code == 200 {
                state.reload(
                    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                        config.rule_pack_paths,
                        config.explicit_rule_paths,
                        config.policy_path,
                        config.rule_load_mode,
                        config.override_paths,
                        &[],
                    )?,
                );
            }
            write_json_api_response(stream, response)
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
        Self {
            status_code: 400,
            reason: "Bad Request",
            body: serde_json::json!({
                "status": "error",
                "error": error.into(),
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
    let detections = detect_sources_with_rules(&[source], &rule_set);
    if let Some((_, event)) = detections
        .iter()
        .find(|(_, event)| event.event_type == "scanner_error")
    {
        return Ok(ApiResponse::bad_request(format!(
            "fixture parse failed for {}",
            event.session_id
        )));
    }
    let matches = detections
        .iter()
        .filter(|(_, event)| event.event_type == "detection")
        .map(|(_, event)| {
            serde_json::json!({
                "session_id": event.session_id,
                "severity": event.severity,
                "risk_score": event.risk_score,
                "rule_ids": event.rule_ids,
                "categories": event.categories,
            })
        })
        .collect::<Vec<_>>();

    Ok(ApiResponse::ok(serde_json::json!({
        "status": "ok",
        "fixture_path": display_fixture_path(&fixture_path),
        "match_count": matches.len(),
        "matches": matches,
    })))
}

#[derive(Debug, Deserialize)]
struct RuleSaveRequest {
    rules_yaml: String,
    #[serde(default)]
    policy_yaml: Option<String>,
    /// Target rule file path. Must be one of the explicit editable --rules files.
    /// Defaults to the first editable --rules file if omitted.
    #[serde(default)]
    path: Option<PathBuf>,
}

fn save_rules_request(
    body: &[u8],
    rule_pack_paths: &RulePackPaths,
    explicit_rule_paths: &[PathBuf],
    editable_rule_paths: &[PathBuf],
    override_paths: &[PathBuf],
    policy_path: Option<&Path>,
    rule_load_mode: RuleLoadMode,
) -> Result<ApiResponse, Box<dyn std::error::Error>> {
    let request: RuleSaveRequest = serde_json::from_slice(body)?;

    let target = match resolve_save_target(request.path.as_deref(), editable_rule_paths) {
        Ok(target) => target,
        Err(error) => return Ok(ApiResponse::bad_request(error)),
    };

    // Validate rules compile before writing.
    if let Err(error) = compile_rule_yaml(&request.rules_yaml, request.policy_yaml.as_deref()) {
        return Ok(ApiResponse::bad_request(error.to_string()));
    }

    // Validate the effective rule set that would be active after this save. This
    // catches conflicts with bundled defaults or other configured rule files
    // before any on-disk content is changed.
    if let Err(error) = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        rule_pack_paths,
        explicit_rule_paths,
        policy_path,
        rule_load_mode,
        override_paths,
        &[(target.clone(), request.rules_yaml.as_str())],
    ) {
        return Ok(ApiResponse::bad_request(error.to_string()));
    }

    // Backup existing file.
    let backup = target.with_extension("yaml.bak");
    if target.exists() {
        std::fs::copy(&target, &backup)?;
    }

    // Atomic write: temp file in same directory, then rename.
    let dir = target.parent().ok_or("rule file has no parent directory")?;
    let tmp = dir.join(".adr-rules-save.tmp");
    std::fs::write(&tmp, &request.rules_yaml)?;
    std::fs::rename(&tmp, &target)?;

    Ok(ApiResponse::ok(serde_json::json!({
        "status": "ok",
        "saved": target.display().to_string(),
        "backup": backup.display().to_string(),
        "rule_count": request.rules_yaml.lines().filter(|l| l.contains("id:")).count(),
    })))
}

fn resolve_save_target(
    requested: Option<&Path>,
    rule_paths: &[PathBuf],
) -> Result<PathBuf, String> {
    let editable_paths = rule_paths
        .iter()
        .map(|path| {
            path.canonicalize()
                .map_err(|error| format!("cannot resolve rule path '{}': {error}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if editable_paths.is_empty() {
        return Err(
            "no editable --rules path configured; start rules serve with --rules <path> to enable saving"
                .to_string(),
        );
    }

    let Some(requested) = requested else {
        return Ok(rule_paths[0].clone());
    };

    let canonical_requested = match requested.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            return Err(format!(
                "requested path '{}' is not one of the loaded rule files editable via --rules",
                requested.display()
            ));
        }
    };
    editable_paths
        .iter()
        .position(|path| path == &canonical_requested)
        .map(|index| rule_paths[index].clone())
        .ok_or_else(|| {
            format!(
                "requested path '{}' is not one of the loaded rule files editable via --rules",
                requested.display()
            )
        })
}

fn compile_rule_yaml(
    rules_yaml: &str,
    policy_yaml: Option<&str>,
) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    load_rule_set_from_documents(&[rules_yaml], policy_yaml)
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
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
