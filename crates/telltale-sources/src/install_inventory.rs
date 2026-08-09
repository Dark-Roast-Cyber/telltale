use std::collections::BTreeMap;
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
    let agents = crate::sources::registry::builtin_install_defs()
        .iter()
        .map(|def| observe_agent(*def, context))
        .collect::<Vec<_>>();
    let hash = inventory_hash(&agents);
    InstallInventorySnapshot {
        observed_at_unix_ms,
        hash,
        agents,
    }
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
        .filter(|agent| agent.installed)
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
) -> AgentInstallObservation {
    let mut signals = Vec::new();
    for executable in def.executables {
        signals.push(executable_signal(executable, &context.path_dirs));
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

    let strong_present = signals.iter().any(|signal| {
        signal.present
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

fn executable_signal(executable: &str, path_dirs: &[PathBuf]) -> InstallSignal {
    let path = path_dirs
        .iter()
        .map(|dir| dir.join(executable))
        .find(|candidate| candidate.is_file());
    signal("executable", executable, path)
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
    format!("{:x}", hasher.finalize())
}

fn path_hash(path: &Path) -> String {
    evidence_hash(&path.to_string_lossy())
}

fn env_path_dirs() -> Vec<PathBuf> {
    env::var_os("PATH")
        .map(|path| env::split_paths(&path).collect())
        .unwrap_or_default()
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

pub fn installed_agent_counts(
    snapshot: &InstallInventorySnapshot,
) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    counts.insert(
        "confirmed",
        snapshot
            .agents
            .iter()
            .filter(|agent| agent.confidence == InstallConfidence::Confirmed)
            .count(),
    );
    counts.insert(
        "partial",
        snapshot
            .agents
            .iter()
            .filter(|agent| agent.confidence == InstallConfidence::Partial)
            .count(),
    );
    counts.insert(
        "absent",
        snapshot
            .agents
            .iter()
            .filter(|agent| agent.confidence == InstallConfidence::Absent)
            .count(),
    );
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_cli_and_extension_install_evidence_without_contents() {
        let temp = tempdir().expect("tempdir");
        let bin = temp.path().join("bin");
        let npm_root = temp.path().join("node_modules");
        let extensions = temp.path().join("extensions");
        std::fs::create_dir_all(&bin).expect("bin");
        std::fs::create_dir_all(npm_root.join("@openai/codex")).expect("npm package");
        std::fs::create_dir_all(extensions.join("github.copilot-1.2.3")).expect("extension");
        std::fs::write(bin.join("codex"), b"").expect("codex executable");
        std::fs::write(npm_root.join("@openai/codex/package.json"), b"{}").expect("package");

        let snapshot = collect_install_inventory_with_context(
            &InstallInventoryContext {
                home: temp.path().to_path_buf(),
                path_dirs: vec![bin],
                extension_roots: vec![extensions],
                global_storage_roots: Vec::new(),
                node_roots: vec![npm_root],
            },
            1_000,
        );

        let codex = snapshot
            .agents
            .iter()
            .find(|agent| agent.agent == "codex")
            .expect("codex observation");
        assert!(codex.installed);
        assert_eq!(codex.confidence, InstallConfidence::Confirmed);
        let copilot = snapshot
            .agents
            .iter()
            .find(|agent| agent.agent == "copilot")
            .expect("copilot observation");
        assert!(copilot.installed);
        assert_eq!(copilot.confidence, InstallConfidence::Confirmed);
    }

    #[test]
    fn marks_global_storage_only_as_partial() {
        let temp = tempdir().expect("tempdir");
        let storage = temp.path().join("globalStorage");
        std::fs::create_dir_all(storage.join("github.copilot")).expect("storage");

        let snapshot = collect_install_inventory_with_context(
            &InstallInventoryContext {
                home: temp.path().to_path_buf(),
                path_dirs: Vec::new(),
                extension_roots: Vec::new(),
                global_storage_roots: vec![storage],
                node_roots: Vec::new(),
            },
            1_000,
        );

        let copilot = snapshot
            .agents
            .iter()
            .find(|agent| agent.agent == "copilot")
            .expect("copilot observation");
        assert!(!copilot.installed);
        assert_eq!(copilot.confidence, InstallConfidence::Partial);
    }

    #[test]
    fn inventory_due_honors_interval() {
        let snapshot = InstallInventorySnapshot {
            observed_at_unix_ms: 1_000,
            hash: "abc".to_string(),
            agents: Vec::new(),
        };

        assert!(!install_inventory_due(
            Some(&snapshot),
            1_000 + 86_399_000,
            86_400
        ));
        assert!(install_inventory_due(
            Some(&snapshot),
            1_000 + 86_400_000,
            86_400
        ));
        assert!(install_inventory_due(Some(&snapshot), 1_001, 0));
        assert!(install_inventory_due(None, 1_001, 86_400));
    }
}
