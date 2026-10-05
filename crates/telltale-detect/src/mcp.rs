use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use walkdir::WalkDir;

use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::event::{
    ActivityEventInput, Event, Evidence, PrivacySanitizer, SanitizationContext, activity_event,
    evidence_hash, path_hash,
};
use telltale_schema::scoring::RiskAccountingError;
use telltale_schema::source::Source;
use telltale_sources::acquisition::SourceAccounting;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ConfigFormat {
    Json,
    Toml,
}

#[cfg(test)]
#[path = "mcp_canonical_tests.rs"]
mod mcp_canonical_tests;

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
/// file; the 4 MiB read budget includes each attempt's one-byte overrun probe.
/// Failed reads retain their full reserved allowance since consumption is unknown.
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
        let read_allowance = remaining_bytes.min(1024 * 1024 + 1);
        remaining_bytes -= read_allowance;
        let parsed = match telltale_sources::install_inventory::read_inventory_config_bytes(
            &config.path,
            read_allowance - 1,
        ) {
            Ok(bytes) => {
                remaining_bytes += read_allowance - bytes.len();
                match std::str::from_utf8(&bytes) {
                    Ok(raw) => Ok(parse_mcp_config_text(
                        &config,
                        raw,
                        256 - observations.len(),
                    )),
                    Err(_) => Err("malformed_source"),
                }
            }
            Err(reason) => Err(reason),
        };
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

pub fn discover_mcp_inventory(root: &Path) -> Vec<(Source, Event)> {
    let mut events = Vec::new();
    for config in discover_mcp_configs(root) {
        let source = Source {
            client: config.client,
            kind: SourceKind::Json,
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

/// Configuration-derived inference over one acquisition, not observed server provenance.
/// No source I/O; the caller discards this output if any source stage fails.
pub fn project_mcp_usage(
    source: &Source,
    accounting: &SourceAccounting,
    servers: &[McpServerInventory],
) -> Result<Vec<Event>, RiskAccountingError> {
    let tool_index = McpToolIndex::from_servers(servers);
    if tool_index.is_empty() {
        return Ok(Vec::new());
    }

    let mut events = Vec::new();
    for facts in &accounting.sessions {
        let mut session = McpSessionUsage::new(
            facts.session_id.value().into(),
            facts.metadata.agent.known().map(str::to_owned),
            facts.metadata.model.known().map(str::to_owned),
            facts.metadata.provider.known().map(str::to_owned),
        );
        let mut attributed = 0u64;
        let mut times = BTreeMap::<String, (u64, String)>::new();
        let mut tools = facts.counts.tool_usage.iter().collect::<Vec<_>>();
        tools.sort_by_key(|(name, fact)| (fact.first_order, *name));
        for (tool_name, fact) in tools {
            let Some(matching_servers) = tool_index.lookup(source.client, tool_name) else {
                continue;
            };
            attributed = attributed
                .checked_add(fact.count)
                .ok_or(RiskAccountingError::Overflow)?;
            let count = u32::try_from(fact.count).map_err(|_| RiskAccountingError::Overflow)?;
            for server in matching_servers {
                let usage = session
                    .servers
                    .entry(server.server_name.clone())
                    .or_insert_with(|| McpServerUsage::new(server.clone()));
                let tool_count = usage.tools_used.entry(tool_name.clone()).or_default();
                *tool_count = tool_count
                    .checked_add(count)
                    .ok_or(RiskAccountingError::Overflow)?;
                usage.tool_call_count = usage
                    .tool_call_count
                    .checked_add(count)
                    .ok_or(RiskAccountingError::Overflow)?;
                if let Some(time) = &fact.first_timestamp {
                    let first = times
                        .entry(server.server_name.clone())
                        .or_insert_with(|| time.clone());
                    if time.0 < first.0 {
                        *first = time.clone();
                    }
                }
            }
        }
        session.unattributed_tool_calls = u32::try_from(
            facts
                .counts
                .record_counts
                .tool_call
                .checked_sub(attributed)
                .ok_or(RiskAccountingError::Overflow)?,
        )
        .map_err(|_| RiskAccountingError::Overflow)?;
        for (name, usage) in &mut session.servers {
            usage.event_time = times.remove(name).map(|(_, time)| time);
        }
        for usage in session.servers.values() {
            events.push(mcp_usage_event(source, &session, usage));
        }
    }

    Ok(events)
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

    #[cfg(test)]
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

    #[cfg(test)]
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
    let mut inventory = parse_mcp_config_text(config, &raw, usize::MAX);
    if config.format == ConfigFormat::Toml {
        // Preserve the established Event3/usage-inference contract: Codex TOML
        // tool declarations are counted by the static facade, not attributed
        // to observed calls by the legacy discovery entry point.
        for server in &mut inventory {
            server.declared_tools.clear();
        }
    }
    Ok(inventory)
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
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("MCP inventory activity has no risk contributions")
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
        risk_contributions: Vec::new(),
        event_time: usage.event_time.clone(),
    })
    .expect("MCP usage activity has no risk contributions")
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
            redacted_value: PrivacySanitizer::sanitize(
                SanitizationContext::Diagnostic,
                &error.to_string(),
            ),
            hash: Some(evidence_hash(&error.to_string())),
            rule_id: None,
        }],
        risk_contributions: Vec::new(),
        event_time: None,
    })
    .expect("MCP inventory error activity has no risk contributions")
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

/// This predates terminal event sanitization and deliberately remains before
/// summary hashing so state and correlation retain their established inputs.
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
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::{
        ConfigFormat, DiscoveredMcpConfig, McpServerInventory, McpToolIndex,
        discover_mcp_inventory, discover_mcp_inventory_servers, inventory_evidence,
        mcp_inventory_error_event, mcp_inventory_event, parse_toml_mcp_config, project_mcp_usage,
    };
    use telltale_schema::clients::{ClientId, SourceKind};
    use telltale_schema::event::Event;
    use telltale_schema::event::{ControlledMarker, check_serialized_event_markers, evidence_hash};
    use telltale_schema::observation::ObservedAt;
    use telltale_schema::source::Source;
    use telltale_sources::acquisition::{AcquisitionOptions, acquire_source};

    #[test]
    fn toml_env_values_never_become_inventory_fields_or_events() {
        let temp = tempdir().unwrap();
        let config = DiscoveredMcpConfig {
            client: ClientId::Codex,
            id: "codex.mcp_config",
            path: temp.path().join("config.toml"),
            format: ConfigFormat::Toml,
        };
        fs::write(&config.path, "[mcp_servers.s]\ncommand = 'node'\nargs = []\n[mcp_servers.s.env]\ncommand = 'TT_ENV_COMMAND_VALUE'\nurl = 'TT_ENV_URL_VALUE'\n").unwrap();
        let servers = super::parse_mcp_config(&config).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].server_name, "s");
        assert_eq!(servers[0].command.as_deref(), Some("node"));
        assert_eq!(servers[0].arg_count, 0);
        assert_eq!(servers[0].env_keys.len(), 2);
        for output in [
            format!("{servers:?}"),
            serde_json::to_string(&mcp_inventory_event(&servers[0])).unwrap(),
        ] {
            assert!(
                !output.contains("TT_ENV_"),
                "environment value escaped parser ownership"
            );
        }
    }

    fn canonical_mcp_events(root: &std::path::Path, sources: &[Source]) -> Vec<(Source, Event)> {
        let servers = discover_mcp_inventory_servers(root);
        let observed_at = ObservedAt::new("2026-09-20T00:00:00Z").expect("observed_at");
        sources
            .iter()
            .flat_map(|source| {
                let batch = acquire_source(source, AcquisitionOptions::new(observed_at.clone()))
                    .expect("synthetic source acquisition");
                project_mcp_usage(source, &batch.accounting, &servers)
                    .expect("synthetic MCP usage projection")
                    .into_iter()
                    .map(|event| (source.clone(), event))
            })
            .collect()
    }

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
                r#"{"type":"assistant","sessionId":"session-a","timestamp":"2026-04-03T06:00:00Z","agent":"claude","model":"fixture-model","provider":"anthropic","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu-list","name":"list_issues","input":{}}]}}"#,
                "\n",
                r#"{"type":"assistant","sessionId":"session-a","timestamp":"2026-04-03T06:00:01Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu-create","name":"create_issue","input":{}}]}}"#,
                "\n",
                r#"{"type":"assistant","sessionId":"session-a","timestamp":"2026-04-03T06:00:02Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu-view","name":"view","input":{}}]}}"#,
                "\n",
            ),
        )
        .expect("write session");
        let sources = vec![Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_string(),
            path: session_path,
        }];

        let events = canonical_mcp_events(temp.path(), &sources);
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
    fn usage_time_is_first_present_in_traversal_order_not_chronological_minimum() {
        let temp = tempdir().expect("tempdir");
        fs::write(
            temp.path().join(".mcp.json"),
            r#"{"mcpServers":{"synthetic":{"command":"synthetic","tools":["lookup"]}}}"#,
        )
        .unwrap();
        let server = discover_mcp_inventory_servers(temp.path()).remove(0);
        let mut usage = super::McpServerUsage::new(server);
        usage.add_tool_call("lookup", None);
        usage.add_tool_call("LOOKUP", Some("2026-09-20T02:00:00Z"));
        usage.add_tool_call("lookup", Some("2026-09-20T01:00:00Z"));
        assert_eq!(usage.event_time.as_deref(), Some("2026-09-20T02:00:00Z"));
        assert_eq!(usage.tool_call_count, 3);
        assert_eq!(usage.tools_used["lookup"], 2);
        assert_eq!(usage.tools_used["LOOKUP"], 1);
    }

    #[test]
    fn usage_metadata_is_independent_first_nonmissing_not_consensus() {
        let mut session =
            super::McpSessionUsage::new("synthetic".into(), Some("first".into()), None, None);
        session.fill_metadata(&Some("conflicting".into()), &Some("model".into()), &None);
        session.fill_metadata(&None, &Some("conflicting".into()), &Some("provider".into()));
        assert_eq!(session.agent.as_deref(), Some("first"));
        assert_eq!(session.model.as_deref(), Some("model"));
        assert_eq!(session.provider.as_deref(), Some("provider"));
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
            r#"{"type":"assistant","sessionId":"session-a","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu-view","name":"view","input":{}}]}}"#,
        )
        .expect("write session");
        let sources = vec![Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_string(),
            path: session_path,
        }];

        assert!(canonical_mcp_events(temp.path(), &sources).is_empty());
    }

    #[test]
    fn mcp_inventory_summaries_and_errors_cross_the_privacy_boundary() {
        let marker = "TT_PRIVACY_MCP_25";
        let inventory = McpServerInventory {
            client: ClientId::Codex,
            source_id: "codex.mcp_config".to_string(),
            path: PathBuf::from(format!("/home/{marker}/.codex/config.toml")),
            server_name: "fixture".to_string(),
            transport: Some("stdio".to_string()),
            command: Some(format!("node --api-key={marker}")),
            package: Some("mcp-fixture".to_string()),
            url_host: None,
            arg_count: 1,
            env_keys: vec!["API_KEY".to_string()],
            declared_tools: vec!["fixture_tool".to_string()],
            supported: true,
            unsupported_reason: None,
        };
        let events = [
            mcp_inventory_event(&inventory),
            mcp_inventory_error_event(
                ClientId::Codex,
                std::io::Error::other(format!(
                    "config at /home/{marker}/.codex/config.toml failed for https://user:{marker}@example.invalid/?token={marker}"
                )),
            ),
        ];
        let markers = [ControlledMarker {
            id: "mcp-marker",
            value: marker,
        }];

        for event in events {
            let bytes = serde_json::to_vec(&event.emittable()).expect("serialize MCP event");
            assert!(
                check_serialized_event_markers(&bytes, "mcp", &markers).is_ok(),
                "MCP event retained a controlled marker"
            );
        }
    }

    #[test]
    fn mcp_inventory_errors_use_the_shared_diagnostic_policy_before_emission() {
        let marker = "TT_PRIVACY_MCP_DIAGNOSTIC_25";
        let event = mcp_inventory_error_event(
            ClientId::Codex,
            std::io::Error::other(format!(
                "config at /home/{marker}/.codex/config.toml failed with token={marker}"
            )),
        );
        let error = event
            .evidence
            .iter()
            .find(|evidence| evidence.field == "mcp_inventory_error")
            .expect("MCP error evidence");

        assert!(
            !error.redacted_value.contains(marker),
            "MCP diagnostic retained a controlled marker before emission"
        );
        assert!(error.redacted_value.contains("<path>"));
    }

    #[test]
    fn mcp_inventory_summary_hashes_the_established_safe_command_value() {
        let inventory = McpServerInventory {
            client: ClientId::Codex,
            source_id: "codex.mcp_config".to_string(),
            path: PathBuf::from("/synthetic/config.toml"),
            server_name: "fixture".to_string(),
            transport: Some("stdio".to_string()),
            command: Some("node --api-key=synthetic-value".to_string()),
            package: Some("mcp-fixture".to_string()),
            url_host: None,
            arg_count: 1,
            env_keys: Vec::new(),
            declared_tools: Vec::new(),
            supported: true,
            unsupported_reason: None,
        };

        let evidence = inventory_evidence(&inventory);
        let summary = &evidence[0];
        let expected_hash = evidence_hash(&summary.redacted_value);
        assert!(summary.redacted_value.contains("[redacted-command]"));
        assert_eq!(summary.hash.as_deref(), Some(expected_hash.as_str()));
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
    fn static_inventory_failed_reads_conservatively_exhaust_the_byte_budget() {
        let temp = tempdir().unwrap();
        for (path, reason) in [
            (temp.path().join("missing.json"), "source_missing"),
            (temp.path().to_path_buf(), "non_regular_source"),
        ] {
            let configs = (0..8)
                .map(|_| {
                    super::McpConfigInput::new(
                        ClientId::Claude,
                        "claude.project_mcp_config",
                        path.clone(),
                    )
                })
                .collect();
            let observations =
                super::collect_mcp_inventory(&super::McpInventoryInput::Configs(configs));
            assert_eq!(observations.len(), 5);
            assert!(
                observations[..4]
                    .iter()
                    .all(|item| item.reason() == Some(reason))
            );
            assert_eq!(
                observations[4].reason(),
                Some("mcp_inventory_limit_exceeded")
            );
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
    fn static_inventory_reserves_overrun_probe_at_aggregate_boundary() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("config.json");
        let missing = temp.path().join("missing.json");
        let tiny = temp.path().join("tiny.json");
        fs::write(&tiny, "x").unwrap();
        let mut raw = r#"{"mcpServers":{"fixture":{"command":"node"}}}"#.to_owned();
        raw.push_str(&" ".repeat(1024 * 1024 - 4 - raw.len()));
        fs::write(&path, raw).unwrap();
        // One successful read plus three unknown-consumption failures leaves
        // exactly one byte: only the overrun probe, no accepted content.
        let configs = [
            path,
            missing.clone(),
            missing.clone(),
            missing,
            tiny.clone(),
            tiny,
        ]
        .into_iter()
        .map(|path| super::McpConfigInput::new(ClientId::Claude, "claude.project_mcp_config", path))
        .collect();
        let observations =
            super::collect_mcp_inventory(&super::McpInventoryInput::Configs(configs));
        assert_eq!(observations.len(), 6);
        assert_eq!(observations[0].state(), super::McpInventoryState::Supported);
        assert!(
            observations[1..4]
                .iter()
                .all(|item| item.reason() == Some("source_missing"))
        );
        assert_eq!(observations[4].reason(), Some("source_limit_exceeded"));
        assert_eq!(
            observations[5].reason(),
            Some("mcp_inventory_limit_exceeded")
        );
        assert!(
            observations[4..]
                .iter()
                .all(|item| item.server_name().is_none())
        );
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
    fn codex_toml_unrelated_multiline_with_fake_mcp_preserves_tool_attribution() {
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

        let index = McpToolIndex::from_servers(&servers);
        let matches = index.lookup(ClientId::Codex, "lookup").expect("tool match");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].server_name, "actual");
        assert!(index.lookup(ClientId::Codex, "fake_tool").is_none());
        assert!(index.lookup(ClientId::Codex, "second_tool").is_none());
    }
}
