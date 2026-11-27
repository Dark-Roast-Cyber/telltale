//! Installed-agent inventory: bounded executable, package, extension and
//! storage signals per agent, reported as hashed evidence. This is presence
//! evidence, not session activity.

use std::env;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use telltale_schema::event::{Event, Evidence, evidence_hash, install_inventory_event};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstallInventorySnapshot {
    pub observed_at_unix_ms: u64,
    pub hash: String,
    pub agents: Vec<AgentInstallObservation>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AgentInstallObservation {
    pub agent: String,
    pub installed: bool,
    pub confidence: InstallConfidence,
    pub signals: Vec<InstallSignal>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallConfidence {
    Confirmed,
    Partial,
    Absent,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct InstallSignal {
    pub kind: String,
    pub name: String,
    pub present: bool,
    pub path_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InstallInventoryContext {
    pub home: PathBuf,
    pub path_dirs: Vec<PathBuf>,
    pub extension_roots: Vec<PathBuf>,
    pub global_storage_roots: Vec<PathBuf>,
    pub node_roots: Vec<PathBuf>,
}

/// Launcher naming convention, selectable for metadata-only cross-platform probes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum InstallPlatform {
    Unix,
    Windows,
}

impl InstallPlatform {
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }
}

impl InstallInventoryContext {
    pub fn current() -> Self {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            path_dirs: env_path_dirs(),
            extension_roots: extension_roots(&home),
            global_storage_roots: global_storage_roots(&home),
            node_roots: node_roots(&home),
            home,
        }
    }
}

/// Metadata-only install evidence definition for one agent. Per-agent values
/// live in `src/sources/<agent>/install.rs` and are collected in registry
/// client order via `crate::sources::registry::builtin_install_defs()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AgentInstallDef {
    pub(crate) agent: &'static str,
    pub(crate) executables: &'static [&'static str],
    pub(crate) node_packages: &'static [&'static str],
    pub(crate) extension_ids: &'static [&'static str],
    pub(crate) global_storage_ids: &'static [&'static str],
}

pub fn collect_install_inventory(observed_at_unix_ms: u64) -> InstallInventorySnapshot {
    collect_install_inventory_with_context(&InstallInventoryContext::current(), observed_at_unix_ms)
}

pub fn collect_install_inventory_with_context(
    context: &InstallInventoryContext,
    observed_at_unix_ms: u64,
) -> InstallInventorySnapshot {
    collect_install_inventory_for_platform(context, observed_at_unix_ms, InstallPlatform::current())
}

pub fn collect_install_inventory_for_platform(
    context: &InstallInventoryContext,
    observed_at_unix_ms: u64,
    platform: InstallPlatform,
) -> InstallInventorySnapshot {
    let agents = crate::sources::registry::builtin_install_defs()
        .iter()
        .map(|def| observe_agent(*def, context, platform))
        .collect::<Vec<_>>();
    let hash = inventory_hash(&agents);
    InstallInventorySnapshot {
        observed_at_unix_ms,
        hash,
        agents,
    }
}

/// Supplement metadata probes with caller-discovered supported session sources.
/// Does not discover sources or read their contents. Session evidence means an
/// agent is or was installed, not that a runnable installation still exists.
pub fn collect_install_inventory_with_sources(
    context: &InstallInventoryContext,
    observed_at_unix_ms: u64,
    sources: &[telltale_schema::source::Source],
) -> InstallInventorySnapshot {
    let mut snapshot = collect_install_inventory_with_context(context, observed_at_unix_ms);
    for agent in &mut snapshot.agents {
        let mut matching = sources
            .iter()
            .filter(|source| {
                source.client.as_str() == agent.agent
                    && crate::clients::supported_clients().iter().any(|client| {
                        client.id == source.client
                            && client
                                .sources
                                .iter()
                                .any(|def| def.id == source.source_id && def.kind == source.kind)
                    })
            })
            .map(|source| (source.source_id.clone(), path_hash(&source.path)))
            .collect::<Vec<_>>();
        matching.sort();
        matching.dedup();
        for (name, hash) in matching {
            agent.signals.push(InstallSignal {
                kind: "session_store".into(),
                name,
                present: true,
                path_hash: Some(hash),
            });
            agent.installed = true;
            if agent.confidence == InstallConfidence::Absent {
                agent.confidence = InstallConfidence::Partial;
            }
        }
    }
    snapshot.hash = inventory_hash(&snapshot.agents);
    snapshot
}

pub fn install_inventory_due(
    previous: Option<&InstallInventorySnapshot>,
    observed_at_unix_ms: u64,
    interval_seconds: u64,
) -> bool {
    if interval_seconds == 0 {
        return true;
    }
    let Some(previous) = previous else {
        return true;
    };
    let interval_ms = interval_seconds.saturating_mul(1_000);
    observed_at_unix_ms.saturating_sub(previous.observed_at_unix_ms) >= interval_ms
}

pub fn snapshot_to_event(
    snapshot: &InstallInventorySnapshot,
) -> Result<Event, telltale_schema::scoring::RiskAccountingError> {
    let installed = snapshot
        .agents
        .iter()
        .filter(|agent| agent.confidence == InstallConfidence::Confirmed)
        .count();
    let partial = snapshot
        .agents
        .iter()
        .filter(|agent| agent.confidence == InstallConfidence::Partial)
        .count();
    let absent = snapshot.agents.len().saturating_sub(installed + partial);
    let mut evidence = vec![Evidence {
        field: "install_inventory_summary".to_string(),
        redacted_value: format!(
            "agents={}; installed={installed}; partial={partial}; absent={absent}",
            snapshot.agents.len()
        ),
        hash: Some(snapshot.hash.clone()),
        rule_id: None,
    }];
    evidence.extend(snapshot.agents.iter().map(agent_evidence));
    install_inventory_event(evidence)
}

fn observe_agent(
    def: AgentInstallDef,
    context: &InstallInventoryContext,
    platform: InstallPlatform,
) -> AgentInstallObservation {
    let mut signals = Vec::new();
    for executable in def.executables {
        signals.push(executable_signal_for_platform(
            executable,
            &context.path_dirs,
            platform,
        ));
    }
    for package in def.node_packages {
        signals.push(node_package_signal(package, &context.node_roots));
    }
    for extension_id in def.extension_ids {
        signals.push(extension_signal(extension_id, &context.extension_roots));
    }
    for storage_id in def.global_storage_ids {
        signals.push(global_storage_signal(
            storage_id,
            &context.global_storage_roots,
        ));
    }
    if def.agent == "codex" {
        signals.extend(crate::sources::codex::desktop_install_signals(
            &context.home,
            platform,
        ));
    }
    if def.agent == "claude" {
        signals.extend(crate::sources::claude::desktop_install_signals(
            &context.home,
            platform,
        ));
    }
    if def.agent == "pi" {
        signals.extend(crate::sources::pi::managed_install_signals(
            &context.home,
            platform,
        ));
    }
    if def.agent == "opencode" {
        signals.extend(crate::sources::opencode::desktop_install_signals(
            &context.home,
            platform,
        ));
    }

    let strong_present = signals.iter().any(|signal| {
        signal.present
            // AWS Copilot uses the same launcher name. Keep that signal visible,
            // but only GitHub-specific package/extension evidence confirms it.
            && !(def.agent == "copilot" && signal.kind == "executable")
            && matches!(
                signal.kind.as_str(),
                "executable" | "node_package" | "vscode_extension"
            )
    });
    let any_present = signals.iter().any(|signal| signal.present);
    let confidence = if strong_present {
        InstallConfidence::Confirmed
    } else if any_present {
        InstallConfidence::Partial
    } else {
        InstallConfidence::Absent
    };
    AgentInstallObservation {
        agent: def.agent.to_string(),
        installed: strong_present,
        confidence,
        signals,
    }
}

fn executable_signal_for_platform(
    executable: &str,
    path_dirs: &[PathBuf],
    platform: InstallPlatform,
) -> InstallSignal {
    let candidates = path_dirs.iter().flat_map(|dir| {
        let mut candidates = vec![dir.join(executable)];
        if platform == InstallPlatform::Windows && Path::new(executable).extension().is_none() {
            candidates.extend(
                ["exe", "com", "cmd", "bat", "ps1"]
                    .map(|ext| dir.join(format!("{executable}.{ext}"))),
            );
        }
        candidates
    });
    executable_path_signal(executable, candidates)
}

pub(crate) fn executable_path_signal(
    name: &str,
    candidates: impl IntoIterator<Item = PathBuf>,
) -> InstallSignal {
    let path = candidates.into_iter().find(|candidate| candidate.is_file());
    signal("executable", name, path)
}

fn node_package_signal(package: &str, node_roots: &[PathBuf]) -> InstallSignal {
    let path = node_roots
        .iter()
        .map(|root| root.join(package).join("package.json"))
        .find(|candidate| candidate.is_file());
    signal("node_package", package, path)
}

fn extension_signal(extension_id: &str, extension_roots: &[PathBuf]) -> InstallSignal {
    let prefix = format!("{}-", extension_id.to_ascii_lowercase());
    let path = extension_roots.iter().find_map(|root| {
        let entries = std::fs::read_dir(root).ok()?;
        entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.is_dir()
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(|name| name.to_ascii_lowercase().starts_with(&prefix))
                        .unwrap_or(false)
            })
    });
    signal("vscode_extension", extension_id, path)
}

fn global_storage_signal(storage_id: &str, global_storage_roots: &[PathBuf]) -> InstallSignal {
    let path = global_storage_roots
        .iter()
        .map(|root| root.join(storage_id))
        .find(|candidate| candidate.is_dir());
    signal("global_storage", storage_id, path)
}

fn signal(kind: &str, name: &str, path: Option<PathBuf>) -> InstallSignal {
    InstallSignal {
        kind: kind.to_string(),
        name: name.to_string(),
        present: path.is_some(),
        path_hash: path.as_ref().map(|path| path_hash(path.as_path())),
    }
}

fn agent_evidence(agent: &AgentInstallObservation) -> Evidence {
    let present_signals = agent
        .signals
        .iter()
        .filter(|signal| signal.present)
        .map(|signal| format!("{}:{}", signal.kind, signal.name))
        .collect::<Vec<_>>();
    Evidence {
        field: "agent_install".to_string(),
        redacted_value: format!(
            "agent={}; installed={}; confidence={:?}; present_signals={}",
            agent.agent,
            agent.installed,
            agent.confidence,
            if present_signals.is_empty() {
                "none".to_string()
            } else {
                present_signals.join(",")
            }
        ),
        hash: Some(evidence_hash(
            &serde_json::to_string(agent).unwrap_or_default(),
        )),
        rule_id: None,
    }
}

fn inventory_hash(agents: &[AgentInstallObservation]) -> String {
    let mut hasher = Sha256::new();
    for agent in agents {
        hasher.update(agent.agent.as_bytes());
        hasher.update(b"\0");
        hasher.update(format!("{:?}", agent.confidence).as_bytes());
        hasher.update(b"\0");
        for signal in &agent.signals {
            hasher.update(signal.kind.as_bytes());
            hasher.update(b":");
            hasher.update(signal.name.as_bytes());
            hasher.update(b":");
            hasher.update(if signal.present { b"1" } else { b"0" });
            hasher.update(b"\n");
        }
    }
    hex::encode(hasher.finalize())
}

fn path_hash(path: &Path) -> String {
    evidence_hash(&path.to_string_lossy())
}

fn env_path_dirs() -> Vec<PathBuf> {
    let Some(path) = env::var_os("PATH") else {
        return Vec::new();
    };
    if cfg!(windows)
        && let Some(text) = path.to_str()
        && let Some(dirs) = split_unbalanced_windows_path(text)
    {
        return dirs;
    }
    env::split_paths(&path).collect()
}

/// Windows `split_paths` treats `"` as a quote toggle, so one stray quote (for
/// example `C:\Program Files\dotnet"`) folds every later entry into a single
/// bogus directory, while shells still resolve them. With an odd number of
/// quotes, split on `;` and drop the quotes instead, as shells do.
fn split_unbalanced_windows_path(text: &str) -> Option<Vec<PathBuf>> {
    if text.matches('"').count().is_multiple_of(2) {
        return None;
    }
    Some(
        text.split(';')
            .map(|entry| entry.replace('"', ""))
            .filter(|entry| !entry.is_empty())
            .map(PathBuf::from)
            .collect(),
    )
}

fn extension_roots(home: &Path) -> Vec<PathBuf> {
    let mut roots = vec![
        home.join(".vscode/extensions"),
        home.join(".vscode-server/extensions"),
        home.join(".vscode-oss/extensions"),
        home.join(".cursor/extensions"),
        home.join(".cursor-server/extensions"),
        home.join(".windsurf/extensions"),
        home.join(".windsurf-server/extensions"),
    ];
    if let Some(custom) = env::var_os("VSCODE_EXTENSIONS") {
        roots.push(PathBuf::from(custom));
    }
    roots
}

fn global_storage_roots(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".config/Code/User/globalStorage"),
        home.join(".config/Code - Insiders/User/globalStorage"),
        home.join(".config/VSCodium/User/globalStorage"),
        home.join(".config/Cursor/User/globalStorage"),
        home.join(".config/Windsurf/User/globalStorage"),
        home.join("Library/Application Support/Code/User/globalStorage"),
        home.join("Library/Application Support/Code - Insiders/User/globalStorage"),
        home.join("Library/Application Support/Cursor/User/globalStorage"),
        home.join("Library/Application Support/Windsurf/User/globalStorage"),
        home.join("AppData/Roaming/Code/User/globalStorage"),
        home.join("AppData/Roaming/Code - Insiders/User/globalStorage"),
        home.join("AppData/Roaming/Cursor/User/globalStorage"),
        home.join("AppData/Roaming/Windsurf/User/globalStorage"),
    ]
}

fn node_roots(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".npm-global/lib/node_modules"),
        home.join(".local/share/pnpm/global/5/node_modules"),
        home.join(".bun/install/global/node_modules"),
        home.join("AppData/Roaming/npm/node_modules"),
    ]
}

#[cfg(test)]
mod tests;
