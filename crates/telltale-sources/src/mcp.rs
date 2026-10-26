//! Static MCP configuration acquisition, separate from session-source acquisition.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;
use walkdir::WalkDir;

use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::event::{PrivacySanitizer, SanitizationContext, path_hash};
use telltale_schema::source::Source;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ConfigFormat {
    Json,
    Toml,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct McpConfigDef {
    client: ClientId,
    id: &'static str,
    relative_path: &'static str,
    format: ConfigFormat,
}

/// Raw host-local configuration metadata, not a construction-sanitized observation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct McpServerInventory {
    pub client: ClientId,
    pub source_id: String,
    pub path: PathBuf,
    pub server_name: String,
    pub transport: Option<String>,
    pub command: Option<String>,
    pub package: Option<String>,
    pub url_host: Option<String>,
    pub arg_count: usize,
    pub env_keys: Vec<String>,
    pub declared_tools: Vec<String>,
    pub supported: bool,
    pub unsupported_reason: Option<String>,
}

const MCP_CONFIGS: &[McpConfigDef] = &[
    McpConfigDef {
        client: ClientId::Codex,
        id: "codex.mcp_config",
        relative_path: ".codex/config.toml",
        format: ConfigFormat::Toml,
    },
    McpConfigDef {
        client: ClientId::Claude,
        id: "claude.user_mcp_config",
        relative_path: ".claude.json",
        format: ConfigFormat::Json,
    },
    McpConfigDef {
        client: ClientId::Claude,
        id: "claude.project_mcp_config",
        relative_path: ".mcp.json",
        format: ConfigFormat::Json,
    },
    McpConfigDef {
        client: ClientId::OpenCode,
        id: "opencode.mcp_config",
        relative_path: ".config/opencode/opencode.json",
        format: ConfigFormat::Json,
    },
    McpConfigDef {
        client: ClientId::OpenClaw,
        id: "openclaw.mcp_config",
        relative_path: ".openclaw/config.json",
        format: ConfigFormat::Json,
    },
    McpConfigDef {
        client: ClientId::Qwen,
        id: "qwen.mcp_config",
        relative_path: ".qwen/settings.json",
        format: ConfigFormat::Json,
    },
];

/// Local caller configuration; paths are deliberately not serializable telemetry.
#[derive(Debug, Clone)]
pub struct McpConfigInput {
    client: ClientId,
    source_id: String,
    path: PathBuf,
}

impl McpConfigInput {
    pub fn new(client: ClientId, source_id: impl Into<String>, path: PathBuf) -> Self {
        Self {
            client,
            source_id: source_id.into(),
            path,
        }
    }
    pub fn client(&self) -> ClientId {
        self.client
    }
    pub fn source_id(&self) -> &str {
        &self.source_id
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Explicit files or the known fixed paths only. Neither mode walks workspaces.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum McpInventoryInput {
    Configs(Vec<McpConfigInput>),
    FixedRoot(PathBuf),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum McpInventoryState {
    Supported,
    Unsupported,
    Error,
}

/// Immutable, construction-sanitized static inventory; never contains a raw path,
/// argument, environment key/value, declared tool name, or complete URL.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize)]
#[non_exhaustive]
pub struct McpInventoryObservation {
    #[serde(serialize_with = "serialize_inventory_client")]
    client: ClientId,
    source_id: String,
    config_path_hash: String,
    server_name: Option<String>,
    transport: Option<String>,
    command: Option<String>,
    package: Option<String>,
    url_host: Option<String>,
    arg_count: usize,
    env_key_count: usize,
    declared_tool_count: usize,
    state: McpInventoryState,
    reason: Option<&'static str>,
}

impl McpInventoryObservation {
    pub fn client(&self) -> ClientId {
        self.client
    }
    pub fn source_id(&self) -> &str {
        &self.source_id
    }
    pub fn config_path_hash(&self) -> &str {
        &self.config_path_hash
    }
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }
    pub fn transport(&self) -> Option<&str> {
        self.transport.as_deref()
    }
    pub fn command(&self) -> Option<&str> {
        self.command.as_deref()
    }
    pub fn package(&self) -> Option<&str> {
        self.package.as_deref()
    }
    pub fn url_host(&self) -> Option<&str> {
        self.url_host.as_deref()
    }
    pub fn arg_count(&self) -> usize {
        self.arg_count
    }
    pub fn env_key_count(&self) -> usize {
        self.env_key_count
    }
    pub fn declared_tool_count(&self) -> usize {
        self.declared_tool_count
    }
    pub fn state(&self) -> McpInventoryState {
        self.state
    }
    pub fn reason(&self) -> Option<&'static str> {
        self.reason
    }
}

/// Static local configuration reads only; no commands, network, or workspace walk.
/// Explicit invalid identities and file failures remain visible as bounded errors.
/// At most 64 configs and 256 server/error observations are processed, plus one
/// content-free exhaustion observation. Accepted content is at most 1 MiB per
/// file. Each read reserves at most 1 MiB + 1 byte, including the overrun probe,
/// capped by the remaining 4 MiB budget. A failed read restores that reservation
/// because the reader returns no bytes; only accepted bytes stay charged.
pub fn collect_mcp_inventory(input: &McpInventoryInput) -> Vec<McpInventoryObservation> {
    let configs: Vec<McpConfigInput> = match input {
        McpInventoryInput::Configs(configs) => configs.iter().take(65).cloned().collect(),
        McpInventoryInput::FixedRoot(root) => MCP_CONFIGS
            .iter()
            .filter_map(|def| {
                let path = root.join(def.relative_path);
                path.symlink_metadata()
                    .is_ok()
                    .then(|| McpConfigInput::new(def.client, def.id, path))
            })
            .collect(),
    };
    let mut observations = Vec::new();
    let mut remaining_bytes = 4 * 1024 * 1024;
    for (index, input) in configs.into_iter().enumerate() {
        let definition = MCP_CONFIGS
            .iter()
            .find(|def| def.client == input.client && def.id == input.source_id);
        let definition = definition.or_else(|| {
            (input.client == ClientId::Claude && input.source_id == "claude.workspace_mcp_config")
                .then(|| {
                    MCP_CONFIGS
                        .iter()
                        .find(|def| def.id == "claude.project_mcp_config")
                        .unwrap()
                })
        });
        let mut base = McpInventoryObservation {
            client: input.client,
            source_id: definition
                .map(|_| input.source_id.clone())
                .unwrap_or_else(|| "unsupported_mcp_source".into()),
            config_path_hash: path_hash(&input.path),
            server_name: None,
            transport: None,
            command: None,
            package: None,
            url_host: None,
            arg_count: 0,
            env_key_count: 0,
            declared_tool_count: 0,
            state: McpInventoryState::Error,
            reason: None,
        };
        if index == 64 || observations.len() == 256 || remaining_bytes == 0 {
            base.reason = Some("mcp_inventory_limit_exceeded");
            observations.push(base);
            break;
        }
        let Some(definition) = definition else {
            base.reason = Some("unsupported_mcp_source_identity");
            observations.push(base);
            continue;
        };
        let config = DiscoveredMcpConfig {
            client: input.client,
            id: if input.source_id == "claude.workspace_mcp_config" {
                "claude.workspace_mcp_config"
            } else {
                definition.id
            },
            path: input.path,
            format: definition.format,
        };
        let parsed = read_mcp_config(&config, &mut remaining_bytes, 256 - observations.len());
        match parsed {
            Err(reason) => {
                base.reason = Some(reason);
                observations.push(base);
            }
            Ok(servers) => {
                for server in servers {
                    let mut observation = base.clone();
                    observation.server_name = Some(safe_inventory_text(&server.server_name));
                    observation.transport = server.transport.as_deref().map(safe_inventory_text);
                    observation.command = server.command.as_deref().map(|command| {
                        // A command identity, never the configured command line.
                        safe_command_identity(command)
                    });
                    observation.package = server.package.as_deref().map(safe_package_identity);
                    observation.url_host = server.url_host.as_deref().map(safe_inventory_text);
                    observation.arg_count = server.arg_count;
                    observation.env_key_count = server.env_keys.len();
                    observation.declared_tool_count = server.declared_tools.len();
                    observation.state = if server.supported {
                        McpInventoryState::Supported
                    } else {
                        McpInventoryState::Unsupported
                    };
                    observation.reason = match server.unsupported_reason.as_deref() {
                        Some("invalid_json_mcp_config") => Some("invalid_json_mcp_config"),
                        Some("unsupported_toml_mcp_syntax") => Some("unsupported_toml_mcp_syntax"),
                        Some("mcp_server_limit_exceeded") => {
                            observation.state = McpInventoryState::Error;
                            Some("mcp_inventory_limit_exceeded")
                        }
                        Some("server_definition_not_object") => {
                            Some("server_definition_not_object")
                        }
                        Some(_) => Some("missing_command_or_url"),
                        None => None,
                    };
                    observations.push(observation);
                    if server.unsupported_reason.as_deref() == Some("mcp_server_limit_exceeded") {
                        return observations;
                    }
                }
            }
        }
    }
    observations
}

fn is_url_shaped(value: &str) -> bool {
    let trimmed = value.trim().trim_matches(['\'', '"']);
    trimmed.contains("://") || trimmed.starts_with("//")
}

fn safe_command_identity(command: &str) -> String {
    let command = command.trim();
    if is_url_shaped(command) {
        return "[redacted-url]".into();
    }
    let executable = if let Some(quote @ ('\'' | '"')) = command.chars().next() {
        command[1..].split(quote).next().unwrap_or_default()
    } else {
        let first = command.split_whitespace().next().unwrap_or_default();
        if first.contains(['/', '\\']) && first.len() != command.len() {
            // Unquoted paths with spaces cannot be distinguished from command
            // lines without guessing; never expose an intermediate directory.
            return "[unrepresented-command]".into();
        }
        first
    };
    if is_url_shaped(executable) {
        return "[redacted-url]".into();
    }
    safe_inventory_text(executable.rsplit(['/', '\\']).next().unwrap_or_default())
}

fn safe_package_identity(package: &str) -> String {
    let package = package.trim();
    if is_url_shaped(package) {
        return "[redacted-url]".into();
    }
    // Scoped package names are identities; all other separators describe local
    // filesystem structure and must be reduced to a basename.
    if package.starts_with('@')
        && package.matches('/').count() == 1
        && package[1..]
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '-' | '.'))
    {
        safe_inventory_text(package)
    } else {
        safe_command_identity(package)
    }
}

fn safe_inventory_text(value: &str) -> String {
    let sanitized = PrivacySanitizer::sanitize(SanitizationContext::Summary, value);
    if value.contains("://") || sanitized.contains("://") {
        return "[redacted-url]".into();
    }
    sanitized
}

fn serialize_inventory_client<S: serde::Serializer>(
    client: &ClientId,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(client.as_str())
}

/// One configuration outcome in discovery order. Raw inventory stays host-local.
pub struct McpConfigInventory {
    pub source: Source,
    pub servers: Result<Vec<McpServerInventory>, &'static str>,
}

/// Acquire scan inventory once, including bounded workspace discovery.
/// Unlike `collect_mcp_inventory`, this preserves the Event3/usage TOML policy.
pub fn acquire_mcp_inventory(root: &Path) -> Vec<McpConfigInventory> {
    let mut result = Vec::new();
    let (configs, discovery_error) = discover_mcp_configs(root);
    if let Some(reason) = discovery_error {
        result.push(McpConfigInventory {
            source: Source {
                client: ClientId::Claude,
                kind: SourceKind::Json,
                source_id: "claude.workspace_mcp_config".into(),
                path: root.into(),
            },
            servers: Err(reason),
        });
    }
    let mut remaining_bytes = 4 * 1024 * 1024;
    let mut server_count = 0;
    for config in configs {
        let source = Source {
            client: config.client,
            kind: SourceKind::Json,
            source_id: config.id.to_string(),
            path: config.path.clone(),
        };
        let servers = match read_mcp_config(&config, &mut remaining_bytes, 256 - server_count) {
            Ok(mut inventory) => {
                if config.format == ConfigFormat::Toml {
                    // Preserve the established Event3/usage-inference contract.
                    for server in &mut inventory {
                        server.declared_tools.clear();
                    }
                }
                if inventory.iter().any(|server| {
                    server.unsupported_reason.as_deref() == Some("mcp_server_limit_exceeded")
                }) {
                    Err("mcp_inventory_limit_exceeded")
                } else {
                    server_count += inventory.len();
                    Ok(inventory)
                }
            }
            Err(reason) => Err(reason),
        };
        result.push(McpConfigInventory { source, servers });
    }
    result
}

#[derive(Debug)]
struct DiscoveredMcpConfig {
    client: ClientId,
    id: &'static str,
    path: PathBuf,
    format: ConfigFormat,
}

fn discover_mcp_configs(root: &Path) -> (Vec<DiscoveredMcpConfig>, Option<&'static str>) {
    let mut configs = MCP_CONFIGS
        .iter()
        .filter_map(|definition| {
            let path = root.join(definition.relative_path);
            path.symlink_metadata()
                .is_ok()
                .then_some(DiscoveredMcpConfig {
                    client: definition.client,
                    id: definition.id,
                    path,
                    format: definition.format,
                })
        })
        .collect::<Vec<_>>();
    let fixed_count = configs.len();
    let mut discovery_error = None;
    if root.is_dir() {
        // Count every visited entry, including errors and irrelevant files. Do
        // not sort directory entries: WalkDir sorting would allocate before the cap.
        for (index, entry) in WalkDir::new(root).max_depth(4).into_iter().enumerate() {
            if index == 10_000 {
                discovery_error = Some("mcp_traversal_limit_exceeded");
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    discovery_error = Some("mcp_discovery_unreadable");
                    break;
                }
            };
            if entry.file_name() != ".mcp.json" {
                continue;
            }
            if configs.iter().any(|config| config.path == entry.path()) {
                continue;
            }
            if configs.len() == 64 {
                discovery_error = Some("mcp_inventory_limit_exceeded");
                break;
            }
            configs.push(DiscoveredMcpConfig {
                client: ClientId::Claude,
                id: "claude.workspace_mcp_config",
                path: entry.into_path(),
                format: ConfigFormat::Json,
            });
        }
    }
    if discovery_error.is_some() {
        // Keep independently acquired fixed paths. An incomplete filesystem walk
        // must not choose an arbitrary traversal-order subset for usage inference.
        configs.truncate(fixed_count);
    }
    configs.sort_by(|left, right| {
        (
            left.client.as_str(),
            left.path.to_string_lossy().to_string(),
            left.id,
        )
            .cmp(&(
                right.client.as_str(),
                right.path.to_string_lossy().to_string(),
                right.id,
            ))
    });
    configs.dedup_by(|left, right| left.client == right.client && left.path == right.path);
    (configs, discovery_error)
}

fn read_mcp_config(
    config: &DiscoveredMcpConfig,
    remaining_bytes: &mut usize,
    server_limit: usize,
) -> Result<Vec<McpServerInventory>, &'static str> {
    if *remaining_bytes == 0 {
        return Err("mcp_inventory_limit_exceeded");
    }
    let allowance = (*remaining_bytes).min(1024 * 1024 + 1);
    *remaining_bytes -= allowance;
    let bytes = match crate::source_read::bounded_file_bytes(&config.path, allowance - 1) {
        Ok(bytes) => bytes,
        Err(error) => {
            *remaining_bytes += allowance;
            return Err(error.code());
        }
    };
    *remaining_bytes += allowance - bytes.len();
    let raw = std::str::from_utf8(&bytes).map_err(|_| "malformed_source")?;
    Ok(parse_mcp_config_text(config, raw, server_limit))
}

fn parse_mcp_config_text(
    config: &DiscoveredMcpConfig,
    raw: &str,
    server_limit: usize,
) -> Vec<McpServerInventory> {
    let mut inventory = match config.format {
        ConfigFormat::Json => parse_json_mcp_config(config, raw, server_limit),
        ConfigFormat::Toml => parse_toml_mcp_config_limited(config, raw, server_limit),
    };
    inventory.sort_by(|left, right| left.server_name.cmp(&right.server_name));
    inventory
}

fn parse_json_mcp_config(
    config: &DiscoveredMcpConfig,
    raw: &str,
    server_limit: usize,
) -> Vec<McpServerInventory> {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return vec![unsupported_inventory(
            config,
            "unknown",
            "invalid_json_mcp_config",
        )];
    };
    let Some(servers) = find_mcp_servers_object(&value) else {
        return Vec::new();
    };
    if servers.len() > server_limit {
        return vec![unsupported_inventory(
            config,
            "unknown",
            "mcp_server_limit_exceeded",
        )];
    }

    servers
        .iter()
        .filter_map(|(name, definition)| {
            definition
                .as_object()
                .map(|object| inventory_from_json_server(config, name, object))
                .or_else(|| {
                    Some(unsupported_inventory(
                        config,
                        name,
                        "server_definition_not_object",
                    ))
                })
        })
        .collect()
}

fn find_mcp_servers_object(value: &Value) -> Option<&serde_json::Map<String, Value>> {
    let mcp = value.get("mcp");
    let nested = mcp
        .and_then(|mcp| mcp.get("servers"))
        .and_then(Value::as_object)
        // A direct server can itself be named `servers`. Its command/URL is
        // a string, whereas a nested map's entries are server definitions.
        .filter(|servers| {
            !["command", "url"]
                .iter()
                .any(|key| servers.get(*key).is_some_and(Value::is_string))
        });
    match value.get("mcpServers").or_else(|| value.get("mcp_servers")) {
        Some(servers) => servers.as_object().or(nested),
        None => nested.or_else(|| mcp.and_then(Value::as_object)),
    }
}

fn inventory_from_json_server(
    config: &DiscoveredMcpConfig,
    name: &str,
    object: &serde_json::Map<String, Value>,
) -> McpServerInventory {
    let command = string_value(object, "command");
    let url_host = string_value(object, "url").and_then(|url| host_from_url(&url));
    let transport = string_value(object, "transport")
        .or_else(|| string_value(object, "type"))
        .or_else(|| url_host.as_ref().map(|_| "http".to_string()))
        .or_else(|| command.as_ref().map(|_| "stdio".to_string()));
    let args = object
        .get("args")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or_default();
    let env_keys = object
        .get("env")
        .and_then(Value::as_object)
        .map(|env| sorted_keys(env.keys()))
        .unwrap_or_default();
    let declared_tools = declared_tools(object.get("tools"));
    let package = command
        .as_deref()
        .and_then(package_from_command)
        .or_else(|| {
            first_string_array_value(object.get("args")).and_then(|arg| package_from_arg(&arg))
        });
    let supported = command.is_some() || url_host.is_some();

    McpServerInventory {
        client: config.client,
        source_id: config.id.to_string(),
        path: config.path.clone(),
        server_name: name.to_string(),
        transport,
        command,
        package,
        url_host,
        arg_count: args,
        env_keys,
        declared_tools,
        supported,
        unsupported_reason: (!supported).then_some("missing_command_or_url".to_string()),
    }
}

#[cfg(test)]
fn parse_toml_mcp_config(config: &DiscoveredMcpConfig, raw: &str) -> Vec<McpServerInventory> {
    parse_toml_mcp_config_limited(config, raw, usize::MAX)
}

/// Deliberately narrow, single-line TOML subset. Section paths are structural:
/// environment subtables contribute keys only, never values or server commands.
/// Syntax outside this subset produces an explicit unsupported observation.
fn parse_toml_mcp_config_limited(
    config: &DiscoveredMcpConfig,
    raw: &str,
    server_limit: usize,
) -> Vec<McpServerInventory> {
    let mut servers = BTreeMap::<String, (serde_json::Map<String, Value>, bool)>::new();
    let mut current: Option<(String, bool)> = None;
    let mut active_multiline: Option<&'static str> = None;
    for line in raw.lines() {
        if let Some(delimiter) = active_multiline {
            let count = count_triple_quotes(line, delimiter);
            if count > 0 && count % 2 == 1 {
                active_multiline = None;
            }
            continue;
        }

        let line_clean = strip_toml_comment(line).trim();
        if line_clean.is_empty() {
            continue;
        }

        let count_double = count_triple_quotes(line_clean, "\"\"\"");
        let count_single = count_triple_quotes(line_clean, "'''");
        if count_double > 0 || count_single > 0 {
            let (delimiter, count) = if count_double > 0 {
                ("\"\"\"", count_double)
            } else {
                ("'''", count_single)
            };
            if let Some((name, _)) = &current {
                servers.get_mut(name).unwrap().1 = true;
            }
            if count % 2 == 1 {
                active_multiline = Some(delimiter);
            }
            continue;
        }

        let Some(line) = toml_without_comment(line) else {
            if let Some((name, _)) = &current {
                servers.get_mut(name).unwrap().1 = true;
                continue;
            }
            if line.contains("mcp_servers") || line.contains("mcp.servers") {
                return vec![unsupported_inventory(
                    config,
                    "unknown",
                    "unsupported_toml_mcp_syntax",
                )];
            }
            continue;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            current = None;
            let Some(section) = line
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .and_then(toml_key_path)
            else {
                if line.contains("mcp_servers") || line.contains("mcp.servers") {
                    return vec![unsupported_inventory(
                        config,
                        "unknown",
                        "unsupported_toml_mcp_syntax",
                    )];
                }
                continue;
            };
            let tail = if section.first().map(String::as_str) == Some("mcp_servers") {
                &section[1..]
            } else if section.first().map(String::as_str) == Some("mcp")
                && section.get(1).map(String::as_str) == Some("servers")
            {
                &section[2..]
            } else {
                continue;
            };
            let Some(name) = tail.first() else {
                continue;
            };
            let server = servers.entry(name.clone()).or_default();
            let env = tail.len() == 2 && tail[1] == "env";
            if tail.len() == 1 || env {
                current = Some((name.clone(), env));
            } else {
                server.1 = true;
            }
            if servers.len() > server_limit {
                return vec![unsupported_inventory(
                    config,
                    "unknown",
                    "mcp_server_limit_exceeded",
                )];
            }
            continue;
        }
        let Some((name, env)) = &current else {
            continue;
        };
        let (fields, unsupported) = servers.get_mut(name).unwrap();
        // Find the assignment outside a quoted key, not inside its contents.
        let Some((key, value)) = toml_assignment(line) else {
            *unsupported = true;
            continue;
        };
        let Some(keys) = toml_key_path(key) else {
            *unsupported = true;
            continue;
        };
        if keys.len() != 1 {
            *unsupported = true;
            continue;
        }
        let key = &keys[0];
        if *env {
            if toml_string(value).is_none() {
                return vec![unsupported_inventory(
                    config,
                    name,
                    "unsupported_toml_mcp_syntax",
                )];
            }
            fields
                .entry("env")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .unwrap()
                .insert(key.clone(), Value::Null);
            continue;
        }
        let parsed = match key.as_str() {
            "command" | "url" | "transport" | "type" => toml_string(value).map(Value::String),
            "args" | "tools" => toml_string_array(value)
                .map(|v| Value::Array(v.into_iter().map(Value::String).collect())),
            // Inline tables and multiline values are not represented by this subset.
            "env" => None,
            _ => continue,
        };
        if let Some(parsed) = parsed {
            fields.insert(key.clone(), parsed);
        } else {
            *unsupported = true;
        }
    }
    servers
        .into_iter()
        .map(|(name, (fields, unsupported))| {
            if unsupported {
                unsupported_inventory(config, &name, "unsupported_toml_mcp_syntax")
            } else {
                inventory_from_json_server(config, &name, &fields)
            }
        })
        .collect()
}

fn count_triple_quotes(line: &str, delimiter: &str) -> usize {
    let mut count = 0;
    let mut cursor = line;
    let is_basic = delimiter == "\"\"\"";
    while let Some(pos) = cursor.find(delimiter) {
        if is_basic {
            let backslashes = cursor[..pos]
                .chars()
                .rev()
                .take_while(|&c| c == '\\')
                .count();
            if backslashes % 2 == 1 {
                cursor = &cursor[pos + 1..];
                continue;
            }
        }
        count += 1;
        cursor = &cursor[pos + delimiter.len()..];
    }
    count
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;
    for (index, ch) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if in_double && ch == '\\' {
            escape = true;
            continue;
        }
        if in_double {
            if ch == '"' {
                in_double = false;
            }
        } else if in_single {
            if ch == '\'' {
                in_single = false;
            }
        } else {
            if ch == '#' {
                return &line[..index];
            }
            if ch == '"' {
                in_double = true;
            } else if ch == '\'' {
                in_single = true;
            }
        }
    }
    line
}

fn toml_without_comment(line: &str) -> Option<&str> {
    let (mut quote, mut escape) = (None, false);
    for (index, ch) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if quote == Some('"') && ch == '\\' {
            escape = true;
            continue;
        }
        if quote == Some(ch) {
            quote = None;
        } else if quote.is_none() {
            if ch == '#' {
                return Some(&line[..index]);
            }
            if ch == '\'' || ch == '"' {
                quote = Some(ch);
            }
        }
    }
    quote.is_none().then_some(line)
}

fn toml_assignment(line: &str) -> Option<(&str, &str)> {
    let (mut quote, mut escape) = (None, false);
    for (index, ch) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if quote == Some('"') && ch == '\\' {
            escape = true;
            continue;
        }
        if quote == Some(ch) {
            quote = None;
        } else if quote.is_none() {
            if ch == '=' {
                return Some((line[..index].trim(), line[index + 1..].trim()));
            }
            if ch == '\'' || ch == '"' {
                quote = Some(ch);
            }
        }
    }
    None
}

fn toml_quoted(value: &str) -> Option<(String, &str)> {
    let quote = value.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let mut escape = false;
    for (index, ch) in value.char_indices().skip(1) {
        if escape {
            escape = false;
            continue;
        }
        if quote == '"' && ch == '\\' {
            escape = true;
            continue;
        }
        if ch == quote {
            let text = if quote == '"' {
                serde_json::from_str(&value[..index + 1]).ok()?
            } else {
                value[1..index].to_string()
            };
            return Some((text, &value[index + 1..]));
        }
    }
    None
}

fn toml_string(value: &str) -> Option<String> {
    let (text, rest) = toml_quoted(value.trim())?;
    rest.trim().is_empty().then_some(text)
}

fn toml_key_path(mut value: &str) -> Option<Vec<String>> {
    let mut keys = Vec::new();
    loop {
        value = value.trim_start();
        let (key, rest) = if value.starts_with(['\'', '"']) {
            toml_quoted(value)?
        } else {
            let end = value
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                .unwrap_or(value.len());
            if end == 0 {
                return None;
            }
            (value[..end].to_string(), &value[end..])
        };
        keys.push(key);
        let rest = rest.trim_start();
        if rest.is_empty() {
            return Some(keys);
        }
        value = rest.strip_prefix('.')?;
    }
}

fn toml_string_array(value: &str) -> Option<Vec<String>> {
    let mut rest = value.trim().strip_prefix('[')?.strip_suffix(']')?.trim();
    let mut values = Vec::new();
    while !rest.is_empty() {
        let (value, tail) = toml_quoted(rest)?;
        values.push(value);
        rest = tail.trim();
        if rest.is_empty() {
            break;
        }
        rest = rest.strip_prefix(',')?.trim();
    }
    Some(values)
}

fn unsupported_inventory(
    config: &DiscoveredMcpConfig,
    name: &str,
    reason: &str,
) -> McpServerInventory {
    McpServerInventory {
        client: config.client,
        source_id: config.id.to_string(),
        path: config.path.clone(),
        server_name: name.to_string(),
        transport: None,
        command: None,
        package: None,
        url_host: None,
        arg_count: 0,
        env_keys: Vec::new(),
        declared_tools: Vec::new(),
        supported: false,
        unsupported_reason: Some(reason.to_string()),
    }
}

fn string_value(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_string)
}

fn sorted_keys<'a>(keys: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut values = keys.cloned().collect::<Vec<_>>();
    values.sort();
    values
}

fn declared_tools(value: Option<&Value>) -> Vec<String> {
    let mut tools = value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    item.as_str()
                        .map(str::to_string)
                        .or_else(|| item.get("name").and_then(Value::as_str).map(str::to_string))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    tools.sort();
    tools.dedup();
    tools
}

fn first_string_array_value(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_array)?
        .iter()
        .find_map(Value::as_str)
        .map(str::to_string)
}

fn package_from_command(command: &str) -> Option<String> {
    command
        .split_whitespace()
        .find(|part| {
            part.starts_with("@")
                || part.starts_with("mcp-")
                || part.contains("/mcp")
                || part.contains("mcp-server")
        })
        .map(str::to_string)
}

fn package_from_arg(arg: &str) -> Option<String> {
    (arg.starts_with('@') || arg.starts_with("mcp-") || arg.contains("mcp-server"))
        .then_some(arg.to_string())
}

fn host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .map(|authority| {
            authority
                .rsplit_once('@')
                .map_or(authority, |(_, host)| host)
        })
        .filter(|host| !host.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    #[test]
    fn scan_server_limit_rejects_whole_config_without_charging_later_capacity() {
        let root = tempdir().unwrap();
        let servers = (0..255)
            .map(|i| {
                (
                    format!("server-{i}"),
                    serde_json::json!({"command": "node"}),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        fs::write(
            root.path().join(".claude.json"),
            serde_json::json!({"mcpServers": servers}).to_string(),
        )
        .unwrap();
        fs::write(
            root.path().join(".mcp.json"),
            r#"{"mcpServers":{"overflow-a":{"command":"node"},"overflow-b":{"command":"node"}}}"#,
        )
        .unwrap();
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(
            workspace.join(".mcp.json"),
            r#"{"mcpServers":{"kept":{"command":"node"}}}"#,
        )
        .unwrap();

        let configs = super::acquire_mcp_inventory(root.path());
        assert_eq!(configs.len(), 3);
        assert_eq!(configs[0].servers.as_ref().unwrap().len(), 255);
        assert_eq!(configs[1].servers, Err("mcp_inventory_limit_exceeded"));
        let last = configs[2].servers.as_ref().unwrap();
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].server_name, "kept");
        assert_eq!(last[0].source_id, "claude.workspace_mcp_config");
    }

    #[test]
    fn mcp_nested_servers_object_is_parsed() {
        let temp = tempdir().unwrap();
        let path = temp.path().join(".mcp.json");
        fs::write(
            &path,
            r#"{"mcp":{"servers":{"actual":{"command":"node","tools":["lookup"]}}}}"#,
        )
        .unwrap();
        let configs = super::acquire_mcp_inventory(temp.path());
        assert_eq!(configs.len(), 1);
        let servers = configs[0].servers.as_ref().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].server_name, "actual");
        assert!(servers[0].supported);
        assert_eq!(servers[0].command.as_deref(), Some("node"));
        assert_eq!(servers[0].declared_tools, ["lookup"]);
        assert_eq!(servers[0].source_id, "claude.project_mcp_config");
        assert_eq!(servers[0].path, path);

        let observations =
            super::collect_mcp_inventory(&super::McpInventoryInput::FixedRoot(temp.path().into()));
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].server_name(), Some("actual"));
        assert_eq!(observations[0].state(), super::McpInventoryState::Supported);
        assert_eq!(observations[0].declared_tool_count(), 1);
    }

    #[test]
    fn json_mcp_shapes_preserve_explicit_top_level_precedence() {
        let server = serde_json::json!({"actual": {"command": "node"}});
        for value in [
            serde_json::json!({"mcpServers": server}),
            serde_json::json!({"mcp_servers": server}),
            serde_json::json!({"mcp": server}),
            serde_json::json!({"mcp": {"servers": server}}),
            serde_json::json!({"mcpServers": server, "mcp_servers": {}, "mcp": {"servers": {}}}),
            serde_json::json!({"mcp_servers": server, "mcp": {"servers": {}}}),
        ] {
            assert_eq!(super::find_mcp_servers_object(&value), server.as_object());
        }
        // Preserve the existing nested fallback for malformed explicit keys.
        for value in [
            serde_json::json!({"mcpServers": null, "mcp_servers": server, "mcp": {"servers": server}}),
            serde_json::json!({"mcp_servers": null, "mcp": {"servers": server}}),
        ] {
            assert_eq!(super::find_mcp_servers_object(&value), server.as_object());
        }
        let malformed = serde_json::json!({"mcpServers": null, "mcp_servers": server});
        assert!(super::find_mcp_servers_object(&malformed).is_none());
    }

    #[test]
    fn direct_server_named_servers_is_not_a_nested_container() {
        let root = tempdir().unwrap();
        let path = root.path().join(".mcp.json");
        for definition in [
            serde_json::json!({"command": "node", "tools": ["lookup"]}),
            serde_json::json!({"url": "https://example.invalid/mcp", "tools": ["lookup"]}),
        ] {
            fs::write(
                &path,
                serde_json::json!({"mcp": {
                    "servers": definition,
                    "actual": {"command": "node", "tools": ["other"]}
                }})
                .to_string(),
            )
            .unwrap();
            let acquired = super::acquire_mcp_inventory(root.path());
            let servers = acquired[0].servers.as_ref().unwrap();
            assert_eq!(
                servers
                    .iter()
                    .map(|s| s.server_name.as_str())
                    .collect::<Vec<_>>(),
                ["actual", "servers"]
            );
            assert!(servers.iter().all(|s| s.supported));
            assert_eq!(servers[1].declared_tools, ["lookup"]);
            let observations = super::collect_mcp_inventory(&super::McpInventoryInput::FixedRoot(
                root.path().into(),
            ));
            assert_eq!(observations.len(), 2);
            assert!(
                observations
                    .iter()
                    .all(|s| s.state() == super::McpInventoryState::Supported)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn inventory_config_fifo_returns_without_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt;
        let root = tempdir().unwrap();
        let path = root.path().join("fifo");
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // Synthetic FIFO, with no writer: blocking open would hang this regression.
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        let observations = super::collect_mcp_inventory(&super::McpInventoryInput::Configs(vec![
            super::McpConfigInput::new(ClientId::Claude, "claude.project_mcp_config", path),
        ]));
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].reason(), Some("non_regular_source"));
    }

    #[test]
    fn workspace_candidate_limit_preserves_fixed_inventory_and_reports_gap() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".mcp.json"),
            r#"{"mcpServers":{"fixed":{"command":"synthetic"}}}"#,
        )
        .unwrap();
        for index in 0..63 {
            let workspace = dir.path().join(format!("workspace-{index}"));
            std::fs::create_dir(&workspace).unwrap();
            std::fs::write(workspace.join(".mcp.json"), "{}").unwrap();
        }
        let (_, error) = super::discover_mcp_configs(dir.path());
        assert_eq!(error, None);
        let workspace = dir.path().join("workspace-overflow");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join(".mcp.json"), "{}").unwrap();
        let result = super::acquire_mcp_inventory(dir.path());
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].servers, Err("mcp_inventory_limit_exceeded"));
        let servers = result[1].servers.as_ref().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].server_name, "fixed");
    }

    #[test]
    fn failed_workspace_reads_do_not_starve_fixed_mcp_configs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".codex")).unwrap();
        std::fs::write(
            dir.path().join(".codex/config.toml"),
            "[mcp_servers.fixed]\ncommand = 'synthetic'\n",
        )
        .unwrap();
        for index in 0..4 {
            let workspace = dir.path().join(format!("workspace-{index}"));
            std::fs::create_dir(&workspace).unwrap();
            std::fs::create_dir(workspace.join(".mcp.json")).unwrap();
        }
        let result = super::acquire_mcp_inventory(dir.path());
        assert!(
            result
                .iter()
                .filter_map(|config| config.servers.as_ref().ok())
                .flatten()
                .any(|server| {
                    server.server_name == "fixed" && server.client == ClientId::Codex
                })
        );
        let error_reasons: Vec<_> = result
            .iter()
            .filter_map(|config| config.servers.as_ref().err().copied())
            .collect();
        assert_eq!(error_reasons.len(), 4);
        assert!(error_reasons.iter().all(|reason| {
            *reason == "non_regular_source" || *reason == "source_permission_denied"
        }));
        assert!(!error_reasons.contains(&"mcp_inventory_limit_exceeded"));
    }

    #[test]
    fn workspace_entry_limit_keeps_fixed_paths_and_counts_irrelevant_entries() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".mcp.json"), "{}").unwrap();
        for index in 0..10_000 {
            std::fs::File::create(dir.path().join(format!("irrelevant-{index}"))).unwrap();
        }
        let (configs, error) = super::discover_mcp_configs(dir.path());
        assert_eq!(configs.len(), 1);
        assert_eq!(error, Some("mcp_traversal_limit_exceeded"));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_workspace_does_not_discard_fixed_paths() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".mcp.json"), "{}").unwrap();
        let private = dir.path().join("unreadable");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o000)).unwrap();
        let permissions_enforced = std::fs::read_dir(&private).is_err();
        let (configs, error) = super::discover_mcp_configs(dir.path());
        std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(configs.len(), 1);
        if permissions_enforced {
            assert_eq!(error, Some("mcp_discovery_unreadable"));
        }
    }
    #[test]
    fn production_inventory_rejects_oversized_padding() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".mcp.json");
        let raw = r#"{"mcpServers":{"synthetic":{"command":"synthetic"}}}"#;
        std::fs::write(
            &path,
            format!("{raw}{}", " ".repeat(1024 * 1024 - raw.len())),
        )
        .unwrap();
        let result = super::acquire_mcp_inventory(dir.path());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].servers.as_ref().unwrap().len(), 1);
        std::fs::write(
            &path,
            format!("{raw}{}", " ".repeat(1024 * 1024 + 1 - raw.len())),
        )
        .unwrap();
        let result = super::acquire_mcp_inventory(dir.path());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].servers, Err("source_limit_exceeded"));
    }
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::{ConfigFormat, DiscoveredMcpConfig, parse_toml_mcp_config};
    use telltale_schema::clients::ClientId;

    #[test]
    fn toml_env_values_never_become_inventory_fields() {
        let temp = tempdir().unwrap();
        let config = DiscoveredMcpConfig {
            client: ClientId::Codex,
            id: "codex.mcp_config",
            path: temp.path().join("config.toml"),
            format: ConfigFormat::Toml,
        };
        fs::write(&config.path, "[mcp_servers.s]\ncommand = 'node'\nargs = []\n[mcp_servers.s.env]\ncommand = 'TT_ENV_COMMAND_VALUE'\nurl = 'TT_ENV_URL_VALUE'\n").unwrap();
        let servers = super::read_mcp_config(&config, &mut (4 * 1024 * 1024), 256).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].server_name, "s");
        assert_eq!(servers[0].command.as_deref(), Some("node"));
        assert_eq!(servers[0].arg_count, 0);
        assert_eq!(servers[0].env_keys.len(), 2);
        assert!(
            !format!("{servers:?}").contains("TT_ENV_"),
            "environment value escaped parser ownership"
        );
    }

    #[test]
    fn parses_codex_toml_mcp_servers_without_toml_dependency() {
        let temp = tempdir().expect("tempdir");
        let config = DiscoveredMcpConfig {
            client: ClientId::Codex,
            id: "codex.mcp_config",
            path: temp.path().join("config.toml"),
            format: ConfigFormat::Toml,
        };
        let inventory = parse_toml_mcp_config(
            &config,
            r#"
            [mcp_servers.filesystem]
            command = "npx"
            args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/project"]

            [mcp_servers.remote]
            type = "http"
            url = "https://mcp.example.invalid/mcp"
            "#,
        );

        assert_eq!(inventory.len(), 2);
        assert_eq!(inventory[0].server_name, "filesystem");
        assert_eq!(inventory[0].transport.as_deref(), Some("stdio"));
        assert_eq!(
            inventory[1].url_host.as_deref(),
            Some("mcp.example.invalid")
        );
    }

    #[test]
    fn static_inventory_unsupported_identities_do_not_charge_read_budget() {
        let configs = (0..65)
            .map(|_| {
                super::McpConfigInput::new(
                    ClientId::Claude,
                    "unsupported",
                    PathBuf::from("synthetic-missing.json"),
                )
            })
            .collect();
        let observations =
            super::collect_mcp_inventory(&super::McpInventoryInput::Configs(configs));
        assert_eq!(observations.len(), 65);
        assert!(
            observations[..64]
                .iter()
                .all(|item| { item.reason() == Some("unsupported_mcp_source_identity") })
        );
        assert_eq!(
            observations[64].reason(),
            Some("mcp_inventory_limit_exceeded")
        );
    }

    #[test]
    fn static_inventory_failed_reads_do_not_consume_the_byte_budget() {
        let temp = tempdir().unwrap();
        let directory_reason = crate::source_read::bounded_file_bytes(temp.path(), 1024 * 1024)
            .expect_err("a directory must fail at the source read boundary")
            .code();
        assert!(matches!(
            directory_reason,
            "non_regular_source" | "source_permission_denied"
        ));
        if cfg!(windows) {
            // Windows rejects directory opens before regular-file metadata validation.
            assert_eq!(directory_reason, "source_permission_denied");
        }
        let valid = temp.path().join("valid.json");
        fs::write(&valid, r#"{"mcpServers":{"kept":{"command":"node"}}}"#).unwrap();
        for (path, reason) in [
            (temp.path().join("missing.json"), "source_missing"),
            (temp.path().to_path_buf(), directory_reason),
        ] {
            let configs = (0..8)
                .map(|_| {
                    super::McpConfigInput::new(
                        ClientId::Claude,
                        "claude.project_mcp_config",
                        path.clone(),
                    )
                })
                .chain(std::iter::once(super::McpConfigInput::new(
                    ClientId::Claude,
                    "claude.project_mcp_config",
                    valid.clone(),
                )))
                .collect();
            let observations =
                super::collect_mcp_inventory(&super::McpInventoryInput::Configs(configs));
            assert_eq!(observations.len(), 9);
            assert!(observations[..8].iter().all(|item| {
                item.reason() == Some(reason) && item.state() == super::McpInventoryState::Error
            }));
            assert_eq!(observations[8].state(), super::McpInventoryState::Supported);
            assert_eq!(observations[8].server_name(), Some("kept"));
        }
    }

    #[test]
    fn static_inventory_accepts_exactly_one_mib_and_refunds_unused_read_allowance() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("config.json");
        let mut raw = r#"{"mcpServers":{"fixture":{"command":"node"}}}"#.to_owned();
        raw.push_str(&" ".repeat(1024 * 1024 - raw.len()));
        fs::write(&path, &raw).unwrap();
        let tail = temp.path().join("tail.json");
        fs::write(&tail, &raw[..raw.len() - 1]).unwrap();
        let configs = (0..3)
            .map(|_| {
                super::McpConfigInput::new(
                    ClientId::Claude,
                    "claude.project_mcp_config",
                    path.clone(),
                )
            })
            .chain(std::iter::once(super::McpConfigInput::new(
                ClientId::Claude,
                "claude.project_mcp_config",
                tail,
            )))
            .collect();
        let observations =
            super::collect_mcp_inventory(&super::McpInventoryInput::Configs(configs));
        assert_eq!(observations.len(), 4);
        assert!(
            observations
                .iter()
                .all(|item| item.state() == super::McpInventoryState::Supported)
        );
    }

    #[test]
    fn static_inventory_charges_only_accepted_bytes_at_aggregate_boundary() {
        let temp = tempdir().unwrap();
        let exact = temp.path().join("exact.json");
        let mut raw = r#"{"mcpServers":{"fixture":{"command":"node"}}}"#.to_owned();
        raw.push_str(&" ".repeat(1024 * 1024 - raw.len()));
        fs::write(&exact, &raw).unwrap();
        let oversized = temp.path().join("oversized.json");
        fs::write(&oversized, format!("{raw} ")).unwrap();
        let tiny = temp.path().join("tiny.json");
        fs::write(&tiny, r#"{"mcpServers":{"kept":{"command":"node"}}}"#).unwrap();
        // Three exact-MiB reads leave 1 MiB. The oversized file does not fit in
        // that remainder including its probe, fails closed, and restores the
        // reservation so the tiny file is still accepted.
        let configs = [exact.clone(), exact.clone(), exact.clone(), oversized, tiny]
            .into_iter()
            .map(|path| {
                super::McpConfigInput::new(ClientId::Claude, "claude.project_mcp_config", path)
            })
            .collect();
        let observations =
            super::collect_mcp_inventory(&super::McpInventoryInput::Configs(configs));
        assert_eq!(observations.len(), 5);
        assert!(
            observations[..3]
                .iter()
                .all(|item| item.state() == super::McpInventoryState::Supported)
        );
        assert_eq!(observations[3].reason(), Some("source_limit_exceeded"));
        assert_eq!(observations[4].state(), super::McpInventoryState::Supported);
        assert_eq!(observations[4].server_name(), Some("kept"));

        // An exact-MiB file does not fit in a 1 MiB remainder once the probe is
        // reserved. That rejection must not consume the remainder.
        let after = temp.path().join("after.json");
        fs::write(&after, r#"{"mcpServers":{"after":{"command":"node"}}}"#).unwrap();
        let configs = [exact.clone(), exact.clone(), exact.clone(), exact, after]
            .into_iter()
            .map(|path| {
                super::McpConfigInput::new(ClientId::Claude, "claude.project_mcp_config", path)
            })
            .collect();
        let observations =
            super::collect_mcp_inventory(&super::McpInventoryInput::Configs(configs));
        assert_eq!(observations.len(), 5);
        assert!(
            observations[..3]
                .iter()
                .all(|item| item.state() == super::McpInventoryState::Supported)
        );
        assert_eq!(observations[3].reason(), Some("source_limit_exceeded"));
        assert_eq!(observations[4].server_name(), Some("after"));
    }

    #[test]
    fn safe_command_and_package_identities_redact_url_credentials_before_splitting() {
        assert_eq!(
            super::safe_command_identity("https://alice:pass@example.invalid"),
            "[redacted-url]"
        );
        assert_eq!(
            super::safe_command_identity("\"https://alice:pass@example.invalid\""),
            "[redacted-url]"
        );
        assert_eq!(
            super::safe_command_identity("https://alice:pass@example.invalid/bin/server"),
            "[redacted-url]"
        );
        assert_eq!(
            super::safe_package_identity("https://alice:pass@example.invalid"),
            "[redacted-url]"
        );
        assert_eq!(
            super::safe_package_identity("mcp-server-https://alice:pass@example.invalid"),
            "[redacted-url]"
        );
        assert_eq!(
            super::safe_package_identity("@scope/https://alice:pass@example.invalid"),
            "[redacted-url]"
        );
    }

    #[test]
    fn static_inventory_url_commands_are_safe_in_accessors_debug_and_serialization() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("config.json");
        for command in [
            "https://TT_MCP_USER:TT_MCP_PASSWORD@example.invalid",
            "//TT_MCP_USER:TT_MCP_PASSWORD@example.invalid/mcp-server",
            "\"https://TT_MCP_USER:TT_MCP_PASSWORD@example.invalid/bin/server\"",
        ] {
            fs::write(
                &path,
                serde_json::json!({"mcpServers": {"fixture": {"command": command}}}).to_string(),
            )
            .unwrap();
            let observations =
                super::collect_mcp_inventory(&super::McpInventoryInput::Configs(vec![
                    super::McpConfigInput::new(
                        ClientId::Claude,
                        "claude.project_mcp_config",
                        path.clone(),
                    ),
                ]));
            assert_eq!(observations.len(), 1);
            assert_eq!(observations[0].command(), Some("[redacted-url]"));
            for output in [
                observations[0].command().unwrap().to_owned(),
                observations[0].package().unwrap_or_default().to_owned(),
                format!("{observations:?}"),
                serde_json::to_string(&observations).unwrap(),
            ] {
                assert!(
                    !output.contains("TT_MCP_"),
                    "inventory retained URL credential marker"
                );
            }
        }
    }

    #[test]
    fn codex_toml_unrelated_multiline_with_fake_mcp_preserves_declared_tools() {
        let temp = tempdir().expect("tempdir");
        let config = DiscoveredMcpConfig {
            client: ClientId::Codex,
            id: "codex.mcp_config",
            path: temp.path().join("config.toml"),
            format: ConfigFormat::Toml,
        };
        let raw = r#"
instructions = """
[mcp_servers.fake_server]
command = "fake_cmd"
tools = ["fake_tool"]
"""
[mcp_servers.actual]
command = "node"
tools = ["lookup"]
[unrelated]
notes = '''
[mcp_servers.second_fake]
command = "second_fake_cmd"
tools = ["second_tool"]
'''
"#;
        let servers = parse_toml_mcp_config(&config, raw);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].server_name, "actual");
        assert_eq!(servers[0].declared_tools, vec!["lookup".to_string()]);
        assert!(servers[0].supported);
    }
}
