//! Pure configuration-derived MCP attribution and Event3 projection.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use telltale_schema::clients::ClientId;
use telltale_schema::event::{
    ActivityEventInput, Event, Evidence, PrivacySanitizer, SanitizationContext, activity_event,
    evidence_hash, path_hash,
};
use telltale_schema::scoring::RiskAccountingError;
use telltale_schema::source::Source;
use telltale_sources::acquisition::SourceAccounting;
use telltale_sources::mcp::McpServerInventory;

#[cfg(test)]
#[path = "mcp_canonical_tests.rs"]
mod mcp_canonical_tests;

/// Configuration-derived inference over one acquisition, not observed server provenance.
/// No source I/O; the caller discards this output if any source stage fails.
/// Multiple candidate configurations retain separate, non-additive call counts.
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
        let mut times = BTreeMap::<McpServerIdentity, (u64, String)>::new();
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
                    .entry(McpServerIdentity::from(*server))
                    .or_insert_with(|| McpServerUsage::new((*server).clone()));
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
                        .entry(McpServerIdentity::from(*server))
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
struct McpToolIndex<'a> {
    tools: BTreeMap<(ClientId, String), Vec<&'a McpServerInventory>>,
    /// The same tools under the server that declares each one.
    server_tools: BTreeMap<(ClientId, String, String), Vec<&'a McpServerInventory>>,
}

impl<'a> McpToolIndex<'a> {
    fn from_servers(servers: &'a [McpServerInventory]) -> Self {
        let mut index = Self::default();
        for server in servers.iter().filter(|server| server.supported) {
            let tools = server
                .declared_tools
                .iter()
                .map(|name| normalize_tool_name(name))
                .collect::<BTreeSet<_>>();
            let server_name = normalize_tool_name(&server.server_name);
            for tool_name in tools {
                index
                    .server_tools
                    .entry((server.client, server_name.clone(), tool_name.clone()))
                    .or_default()
                    .push(server);
                index
                    .tools
                    .entry((server.client, tool_name))
                    .or_default()
                    .push(server);
            }
        }
        index
    }

    fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// The servers a tool name belongs to: every server declaring the name as
    /// it stands, or the one server a `mcp__<server>__<tool>` name spells out.
    /// That wrapping is the only one read. A harness that joins the two names
    /// with a single separator gives a name a built-in tool can also have, so
    /// such a name is attributed to no server.
    fn lookup(&self, client: ClientId, tool_name: &str) -> Option<&[&'a McpServerInventory]> {
        let name = normalize_tool_name(tool_name);
        let wrapped = name.strip_prefix("mcp__").map(str::to_owned);
        if let Some(servers) = self.tools.get(&(client, name)) {
            return Some(servers);
        }
        let wrapped = wrapped?;
        // Either name may itself hold the separator.
        wrapped.match_indices("__").find_map(|(at, separator)| {
            let key = (
                client,
                wrapped[..at].to_owned(),
                wrapped[at + separator.len()..].to_owned(),
            );
            self.server_tools.get(&key).map(Vec::as_slice)
        })
    }
}

/// Preserve server-name ordering while keeping each configuration's attribution separate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct McpServerIdentity {
    server_name: String,
    client: ClientId,
    source_id: String,
    path: PathBuf,
}

impl From<&McpServerInventory> for McpServerIdentity {
    fn from(server: &McpServerInventory) -> Self {
        Self {
            server_name: server.server_name.clone(),
            client: server.client,
            source_id: server.source_id.clone(),
            path: server.path.clone(),
        }
    }
}

#[derive(Debug)]
struct McpSessionUsage {
    session_id: String,
    agent: Option<String>,
    model: Option<String>,
    provider: Option<String>,
    unattributed_tool_calls: u32,
    servers: BTreeMap<McpServerIdentity, McpServerUsage>,
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
}

pub fn project_mcp_inventory(server: &McpServerInventory) -> Event {
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

pub fn project_mcp_inventory_error(client: ClientId, reason: &str) -> Event {
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
            redacted_value: PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, reason),
            hash: Some(evidence_hash(reason)),
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

#[cfg(test)]
mod tests;
