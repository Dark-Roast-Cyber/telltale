use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use walkdir::WalkDir;

use crate::clients::ClientId;
use crate::discovery::Source;
use crate::event::{ActivityEventInput, Event, Evidence, activity_event, evidence_hash, path_hash};
use crate::parser::{RecordKind, parse_source_records};

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
        client: ClientId::Gemini,
        id: "gemini.mcp_config",
        relative_path: ".gemini/settings.json",
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

pub fn discover_mcp_inventory(root: &Path) -> Vec<(Source, Event)> {
    let mut events = Vec::new();
    for config in discover_mcp_configs(root) {
        let source = Source {
            client: config.client,
            kind: crate::clients::SourceKind::Json,
            source_id: config.id.to_string(),
            path: config.path.clone(),
        };
        match parse_mcp_config(&config) {
            Ok(inventory) => {
                events.extend(
                    inventory
                        .into_iter()
                        .map(|server| (source.clone(), mcp_inventory_event(&server))),
                );
            }
            Err(error) => events.push((source, mcp_inventory_error_event(config.client, error))),
        }
    }
    events
}

pub fn discover_mcp_inventory_servers(root: &Path) -> Vec<McpServerInventory> {
    discover_mcp_configs(root)
        .into_iter()
        .flat_map(|config| parse_mcp_config(&config).unwrap_or_default())
        .collect()
}

pub fn discover_mcp_usage(root: &Path, sources: &[Source]) -> Vec<(Source, Event)> {
    let servers = discover_mcp_inventory_servers(root);
    let tool_index = McpToolIndex::from_servers(&servers);
    if tool_index.is_empty() {
        return Vec::new();
    }

    let mut events = Vec::new();
    for source in sources {
        let Ok(records) = parse_source_records(source) else {
            continue;
        };
        let mut sessions: BTreeMap<String, McpSessionUsage> = BTreeMap::new();

        for record in records
            .into_iter()
            .filter(|record| record.kind == RecordKind::ToolCall)
        {
            let session = sessions
                .entry(record.session_id.clone())
                .or_insert_with(|| {
                    McpSessionUsage::new(
                        record.session_id.clone(),
                        record.agent.clone(),
                        record.model.clone(),
                        record.provider.clone(),
                    )
                });
            session.fill_metadata(&record.agent, &record.model, &record.provider);

            let Some(tool_name) = record.tool_name.as_deref() else {
                session.unattributed_tool_calls += 1;
                continue;
            };
            let Some(matching_servers) = tool_index.lookup(source.client, tool_name) else {
                session.unattributed_tool_calls += 1;
                continue;
            };

            for server in matching_servers {
                session.add_tool_call(server, tool_name, record.timestamp.as_deref());
            }
        }

        for usage in sessions.into_values() {
            for server_usage in usage.servers.values() {
                events.push((
                    source.clone(),
                    mcp_usage_event(source, &usage, server_usage),
                ));
            }
        }
    }

    events
}

#[derive(Debug, Default)]
struct McpToolIndex {
    tools: BTreeMap<(ClientId, String), Vec<McpServerInventory>>,
}

impl McpToolIndex {
    fn from_servers(servers: &[McpServerInventory]) -> Self {
        let mut index = Self::default();
        for server in servers.iter().filter(|server| server.supported) {
            for tool_name in &server.declared_tools {
                index
                    .tools
                    .entry((server.client, normalize_tool_name(tool_name)))
                    .or_default()
                    .push(server.clone());
            }
        }
        index
    }

    fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    fn lookup(&self, client: ClientId, tool_name: &str) -> Option<&[McpServerInventory]> {
        self.tools
            .get(&(client, normalize_tool_name(tool_name)))
            .map(Vec::as_slice)
    }
}

#[derive(Debug)]
struct McpSessionUsage {
    session_id: String,
    agent: Option<String>,
    model: Option<String>,
    provider: Option<String>,
    unattributed_tool_calls: u32,
    servers: BTreeMap<String, McpServerUsage>,
}

impl McpSessionUsage {
    fn new(
        session_id: String,
        agent: Option<String>,
        model: Option<String>,
        provider: Option<String>,
    ) -> Self {
        Self {
            session_id,
            agent,
            model,
            provider,
            unattributed_tool_calls: 0,
            servers: BTreeMap::new(),
        }
    }

    fn fill_metadata(
        &mut self,
        agent: &Option<String>,
        model: &Option<String>,
        provider: &Option<String>,
    ) {
        if self.agent.is_none() {
            self.agent = agent.clone();
        }
        if self.model.is_none() {
            self.model = model.clone();
        }
        if self.provider.is_none() {
            self.provider = provider.clone();
        }
    }

    fn add_tool_call(
        &mut self,
        server: &McpServerInventory,
        tool_name: &str,
        timestamp: Option<&str>,
    ) {
        self.servers
            .entry(server.server_name.clone())
            .or_insert_with(|| McpServerUsage::new(server.clone()))
            .add_tool_call(tool_name, timestamp);
    }
}

#[derive(Debug)]
struct McpServerUsage {
    server: McpServerInventory,
    tools_used: BTreeMap<String, u32>,
    tool_call_count: u32,
    event_time: Option<String>,
}

impl McpServerUsage {
    fn new(server: McpServerInventory) -> Self {
        Self {
            server,
            tools_used: BTreeMap::new(),
            tool_call_count: 0,
            event_time: None,
        }
    }

    fn add_tool_call(&mut self, tool_name: &str, timestamp: Option<&str>) {
        *self.tools_used.entry(tool_name.to_string()).or_default() += 1;
        self.tool_call_count += 1;
        if self.event_time.is_none() {
            self.event_time = timestamp.map(str::to_string);
        }
    }
}

#[derive(Debug)]
struct DiscoveredMcpConfig {
    client: ClientId,
    id: &'static str,
    path: PathBuf,
    format: ConfigFormat,
}

fn discover_mcp_configs(root: &Path) -> Vec<DiscoveredMcpConfig> {
    let mut configs = MCP_CONFIGS
        .iter()
        .filter_map(|definition| {
            let path = root.join(definition.relative_path);
            path.is_file().then_some(DiscoveredMcpConfig {
                client: definition.client,
                id: definition.id,
                path,
                format: definition.format,
            })
        })
        .collect::<Vec<_>>();

    configs.extend(discover_workspace_mcp_configs(root));
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
    configs
}

fn discover_workspace_mcp_configs(root: &Path) -> Vec<DiscoveredMcpConfig> {
    if !root.is_dir() {
        return Vec::new();
    }

    WalkDir::new(root)
        .max_depth(4)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some(".mcp.json"))
        .map(|path| DiscoveredMcpConfig {
            client: ClientId::Claude,
            id: "claude.workspace_mcp_config",
            path,
            format: ConfigFormat::Json,
        })
        .collect()
}

fn parse_mcp_config(
    config: &DiscoveredMcpConfig,
) -> Result<Vec<McpServerInventory>, std::io::Error> {
    let raw = fs::read_to_string(&config.path)?;
    let mut inventory = match config.format {
        ConfigFormat::Json => parse_json_mcp_config(config, &raw),
        ConfigFormat::Toml => parse_toml_mcp_config(config, &raw),
    };
    inventory.sort_by(|left, right| left.server_name.cmp(&right.server_name));
    Ok(inventory)
}

fn parse_json_mcp_config(config: &DiscoveredMcpConfig, raw: &str) -> Vec<McpServerInventory> {
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
    value
        .get("mcpServers")
        .or_else(|| value.get("mcp_servers"))
        .or_else(|| value.get("mcp"))
        .and_then(Value::as_object)
        .or_else(|| {
            value
                .get("mcp")
                .and_then(|mcp| mcp.get("servers"))
                .and_then(Value::as_object)
        })
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

fn parse_toml_mcp_config(config: &DiscoveredMcpConfig, raw: &str) -> Vec<McpServerInventory> {
    let mut servers: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current_server: Option<String> = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let section = trimmed.trim_matches(&['[', ']'][..]);
            current_server = section
                .strip_prefix("mcp_servers.")
                .or_else(|| section.strip_prefix("mcp.servers."))
                .map(|name| name.trim_matches('"').to_string());
            continue;
        }
        let Some(server_name) = &current_server else {
            continue;
        };
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        servers.entry(server_name.clone()).or_default().insert(
            key.trim().to_string(),
            value.trim().trim_matches('"').to_string(),
        );
    }

    servers
        .into_iter()
        .map(|(name, fields)| {
            let command = fields.get("command").cloned();
            let url_host = fields.get("url").and_then(|url| host_from_url(url));
            let transport = fields
                .get("transport")
                .or_else(|| fields.get("type"))
                .cloned()
                .or_else(|| url_host.as_ref().map(|_| "http".to_string()))
                .or_else(|| command.as_ref().map(|_| "stdio".to_string()));
            let supported = command.is_some() || url_host.is_some();
            McpServerInventory {
                client: config.client,
                source_id: config.id.to_string(),
                path: config.path.clone(),
                server_name: name,
                transport,
                package: command.as_deref().and_then(package_from_command),
                command,
                url_host,
                arg_count: fields
                    .get("args")
                    .map(|args| args.matches(',').count().saturating_add(1))
                    .unwrap_or_default(),
                env_keys: Vec::new(),
                declared_tools: Vec::new(),
                supported,
                unsupported_reason: (!supported).then_some("missing_command_or_url".to_string()),
            }
        })
        .collect()
}

fn mcp_inventory_event(server: &McpServerInventory) -> Event {
    let mut tags = vec![
        "activity".to_string(),
        "mcp".to_string(),
        "mcp_inventory".to_string(),
        "configured_tooling".to_string(),
    ];
    tags.push(if server.supported {
        "mcp_inventory_supported".to_string()
    } else {
        "mcp_inventory_unsupported".to_string()
    });
    tags.sort();
    tags.dedup();

    activity_event(ActivityEventInput {
        client: server.client,
        agent: Some(server.client.as_str().to_string()),
        model: None,
        provider: None,
        session_id: "mcp_inventory".to_string(),
        source_path_hash: path_hash(&server.path),
        tool_name: Some(format!("mcp::{}", server.server_name)),
        tags,
        evidence: inventory_evidence(server),
        risk_score: 0,
        event_time: None,
    })
}

fn mcp_usage_event(source: &Source, session: &McpSessionUsage, usage: &McpServerUsage) -> Event {
    activity_event(ActivityEventInput {
        client: source.client,
        agent: session.agent.clone(),
        model: session.model.clone(),
        provider: session.provider.clone(),
        session_id: session.session_id.clone(),
        source_path_hash: path_hash(&source.path),
        tool_name: Some(format!("mcp::{}", usage.server.server_name)),
        tags: vec![
            "activity".to_string(),
            "mcp".to_string(),
            "mcp_usage".to_string(),
            "tool_usage".to_string(),
        ],
        evidence: mcp_usage_evidence(session, usage),
        risk_score: 0,
        event_time: usage.event_time.clone(),
    })
}

fn mcp_usage_evidence(session: &McpSessionUsage, usage: &McpServerUsage) -> Vec<Evidence> {
    let tools_used = usage
        .tools_used
        .iter()
        .map(|(tool_name, call_count)| {
            serde_json::json!({
                "tool_name": tool_name,
                "call_count": call_count,
            })
        })
        .collect::<Vec<_>>();
    let server_type = if usage.server.url_host.is_some() {
        Some("remote")
    } else if usage.server.command.is_some() {
        Some("local")
    } else {
        None
    };
    let summary = serde_json::json!({
        "tool_usage_type": "mcp",
        "server_name": usage.server.server_name,
        "server_type": server_type,
        "transport": usage.server.transport,
        "configured_host": usage.server.url_host,
        "server_command": usage.server.command.as_deref().map(redact_command_value),
        "package": usage.server.package,
        "source_id": usage.server.source_id,
        "declared_tools": usage.server.declared_tools,
        "declared_tool_count": usage.server.declared_tools.len(),
        "tools_used": tools_used,
        "tool_call_count": usage.tool_call_count,
        "unattributed_tool_calls": session.unattributed_tool_calls,
        "attribution_method": "declared_tools",
    })
    .to_string();

    vec![
        Evidence {
            field: "tool_usage_summary".to_string(),
            redacted_value: summary.clone(),
            hash: Some(evidence_hash(&summary)),
            rule_id: None,
        },
        Evidence {
            field: "mcp_config_path".to_string(),
            redacted_value: usage.server.source_id.clone(),
            hash: Some(path_hash(&usage.server.path)),
            rule_id: None,
        },
    ]
}

fn mcp_inventory_error_event(client: ClientId, error: std::io::Error) -> Event {
    activity_event(ActivityEventInput {
        client,
        agent: Some(client.as_str().to_string()),
        model: None,
        provider: None,
        session_id: "mcp_inventory".to_string(),
        source_path_hash: evidence_hash(&format!("mcp_inventory_error:{client:?}")),
        tool_name: None,
        tags: vec![
            "activity".to_string(),
            "mcp".to_string(),
            "mcp_inventory".to_string(),
            "mcp_inventory_error".to_string(),
        ],
        evidence: vec![Evidence {
            field: "mcp_inventory_error".to_string(),
            redacted_value: redact_error_message(&error.to_string()),
            hash: Some(evidence_hash(&error.to_string())),
            rule_id: None,
        }],
        risk_score: 0,
        event_time: None,
    })
}

fn inventory_evidence(server: &McpServerInventory) -> Vec<Evidence> {
    let summary = serde_json::json!({
        "source_id": server.source_id,
        "server_name": server.server_name,
        "transport": server.transport,
        "command": server.command.as_deref().map(redact_command_value),
        "package": server.package,
        "url_host": server.url_host,
        "arg_count": server.arg_count,
        "env_keys": server.env_keys,
        "declared_tools": server.declared_tools,
        "declared_tool_count": server.declared_tools.len(),
        "enumeration_method": "static_config",
        "supported": server.supported,
        "unsupported_reason": server.unsupported_reason,
    })
    .to_string();
    vec![
        Evidence {
            field: "mcp_server_inventory".to_string(),
            redacted_value: summary.clone(),
            hash: Some(evidence_hash(&summary)),
            rule_id: None,
        },
        Evidence {
            field: "mcp_config_path".to_string(),
            redacted_value: server.source_id.clone(),
            hash: Some(path_hash(&server.path)),
            rule_id: None,
        },
    ]
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

fn redact_command_value(command: &str) -> String {
    if command.contains('=') || command.to_ascii_lowercase().contains("token") {
        "[redacted-command]".to_string()
    } else {
        command.to_string()
    }
}

fn normalize_tool_name(tool_name: &str) -> String {
    tool_name.trim().to_ascii_lowercase()
}

fn host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    after_scheme
        .split('/')
        .next()
        .filter(|host| !host.is_empty())
        .map(str::to_string)
}

fn redact_error_message(message: &str) -> String {
    if message.len() > 240 {
        format!("{}[truncated]", &message[..240])
    } else {
        message.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{
        ConfigFormat, DiscoveredMcpConfig, McpToolIndex, discover_mcp_inventory,
        discover_mcp_inventory_servers, discover_mcp_usage, parse_toml_mcp_config,
    };
    use crate::clients::{ClientId, SourceKind};
    use crate::discovery::Source;

    #[test]
    fn emits_static_mcp_inventory_for_json_configs() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join(".mcp.json");
        fs::write(
            &config_path,
            r#"{
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_TOKEN": "synthetic-secret"},
                        "tools": [{"name": "list_issues"}, {"name": "create_issue"}]
                    },
                    "remote": {
                        "type": "streamable-http",
                        "url": "https://mcp.example.invalid/mcp"
                    }
                }
            }"#,
        )
        .expect("write config");

        let events = discover_mcp_inventory(temp.path());
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|(_, event)| {
            event.event_type == "activity"
                && event.session_id == "mcp_inventory"
                && event.tool_name.as_deref() == Some("mcp::github")
                && event.tags.iter().any(|tag| tag == "mcp_inventory")
                && event.evidence.iter().any(|evidence| {
                    evidence.field == "mcp_server_inventory"
                        && evidence.redacted_value.contains("list_issues")
                        && evidence.redacted_value.contains("GITHUB_TOKEN")
                        && !evidence.redacted_value.contains("synthetic-secret")
                })
        }));
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
    fn builds_mcp_tool_index_from_declared_tools() {
        let temp = tempdir().expect("tempdir");
        fs::write(
            temp.path().join(".mcp.json"),
            r#"{
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "tools": [{"name": "list_issues"}, {"name": "create_issue"}]
                    },
                    "empty": {"command": "npx"}
                }
            }"#,
        )
        .expect("write config");

        let servers = discover_mcp_inventory_servers(temp.path());
        let index = McpToolIndex::from_servers(&servers);

        let matches = index
            .lookup(ClientId::Claude, "LIST_ISSUES")
            .expect("tool match");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].server_name, "github");
        assert!(index.lookup(ClientId::Claude, "not_declared").is_none());
    }

    #[test]
    fn emits_mcp_usage_event_for_attributed_tool_calls() {
        let temp = tempdir().expect("tempdir");
        fs::write(
            temp.path().join(".mcp.json"),
            r#"{
                "mcpServers": {
                    "github": {
                        "type": "streamable-http",
                        "url": "https://api.githubcopilot.com/mcp/",
                        "tools": [{"name": "list_issues"}, {"name": "create_issue"}]
                    }
                }
            }"#,
        )
        .expect("write config");
        let session_path = temp.path().join("session-a.jsonl");
        fs::write(
            &session_path,
            concat!(
                r#"{"type":"tool_call","session_id":"session-a","timestamp":"2026-04-03T06:00:00Z","tool_name":"list_issues","agent":"claude","model":"fixture-model","provider":"anthropic"}"#,
                "\n",
                r#"{"type":"tool_call","session_id":"session-a","timestamp":"2026-04-03T06:00:01Z","tool_name":"create_issue"}"#,
                "\n",
                r#"{"type":"tool_call","session_id":"session-a","timestamp":"2026-04-03T06:00:02Z","tool_name":"view"}"#,
                "\n",
            ),
        )
        .expect("write session");
        let sources = vec![Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.fixture".to_string(),
            path: session_path,
        }];

        let events = discover_mcp_usage(temp.path(), &sources);
        assert_eq!(events.len(), 1);
        let event = &events[0].1;
        assert_eq!(event.event_type, "activity");
        assert_eq!(event.session_id, "session-a");
        assert_eq!(event.tool_name.as_deref(), Some("mcp::github"));
        assert!(event.tags.iter().any(|tag| tag == "mcp_usage"));
        assert_eq!(event.risk_score, 0);
        let summary = event
            .evidence
            .iter()
            .find(|evidence| evidence.field == "tool_usage_summary")
            .expect("summary evidence");
        assert!(summary.redacted_value.contains("list_issues"));
        assert!(summary.redacted_value.contains("create_issue"));
        assert!(summary.redacted_value.contains("api.githubcopilot.com"));
        assert!(
            summary
                .redacted_value
                .contains(r#""unattributed_tool_calls":1"#)
        );
    }

    #[test]
    fn skips_mcp_usage_when_no_declared_tools_match() {
        let temp = tempdir().expect("tempdir");
        fs::write(
            temp.path().join(".mcp.json"),
            r#"{
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "tools": [{"name": "list_issues"}]
                    }
                }
            }"#,
        )
        .expect("write config");
        let session_path = temp.path().join("session-a.jsonl");
        fs::write(
            &session_path,
            r#"{"type":"tool_call","session_id":"session-a","tool_name":"view"}"#,
        )
        .expect("write session");
        let sources = vec![Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.fixture".to_string(),
            path: session_path,
        }];

        assert!(discover_mcp_usage(temp.path(), &sources).is_empty());
    }
}
