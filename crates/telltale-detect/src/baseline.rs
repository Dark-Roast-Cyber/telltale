use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use telltale_sources::parser::{NormalizedRecord, RecordKind};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BaselineDeviationConfig {
    pub enabled: bool,
    pub min_previous_tool_calls: u64,
    pub max_risk_modifier: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BaselineDeviation {
    pub risk_modifier: u32,
    pub new_tool_names: usize,
    pub new_path_classes: usize,
    pub new_network_hosts: usize,
}

impl Default for BaselineDeviationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_previous_tool_calls: 5,
            max_risk_modifier: 15,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct BaselineKey {
    pub client: String,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub key: BaselineKey,
    pub observations: BaselineObservationTotals,
    pub tool_call_counts: BTreeMap<String, u64>,
    pub path_class_counts: BTreeMap<PathClass, u64>,
    pub network_host_counts: BTreeMap<String, u64>,
}

pub const BASELINE_HOST_HASH_PREFIX: &str = "sha256:";

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BaselineObservationTotals {
    pub records: u64,
    pub user_messages: u64,
    pub assistant_messages: u64,
    pub tool_calls: u64,
    pub tool_results: u64,
    pub session_meta: u64,
    pub other: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathClass {
    Source,
    Test,
    Documentation,
    Config,
    BuildManifest,
    SecretStore,
    Home,
    Temp,
    Other,
}

impl Default for BaselineKey {
    fn default() -> Self {
        Self {
            client: "unknown".to_string(),
            agent: None,
            model: None,
            provider: None,
        }
    }
}

pub fn build_baseline_summaries(records: &[NormalizedRecord]) -> Vec<BaselineSummary> {
    let mut summaries: BTreeMap<BaselineKey, BaselineSummary> = BTreeMap::new();

    for record in records {
        let key = BaselineKey::from(record);
        let summary = summaries
            .entry(key.clone())
            .or_insert_with(|| BaselineSummary {
                key,
                ..BaselineSummary::default()
            });
        summary.observe(record);
    }

    summaries.into_values().collect()
}

pub fn assess_baseline_deviation(
    previous: Option<&BaselineSummary>,
    current: &BaselineSummary,
    config: BaselineDeviationConfig,
) -> Option<BaselineDeviation> {
    if !config.enabled || current.key.model.is_none() || current.key.provider.is_none() {
        return None;
    }

    let previous = previous?;
    if previous.observations.tool_calls < config.min_previous_tool_calls {
        return None;
    }

    let previous_network_hosts = baseline_host_identity_counts(previous);
    let new_tool_names = current
        .tool_call_counts
        .keys()
        .filter(|tool| !previous.tool_call_counts.contains_key(*tool))
        .count();
    let new_path_classes = current
        .path_class_counts
        .keys()
        .filter(|path_class| !previous.path_class_counts.contains_key(*path_class))
        .count();
    let new_network_hosts = current
        .network_host_counts
        .keys()
        .map(|host| baseline_host_identity(host))
        .filter(|host| !previous_network_hosts.contains_key(host))
        .count();

    let raw_modifier = (new_tool_names as u32 * 5)
        + (new_path_classes as u32 * 5)
        + (new_network_hosts as u32 * 5);
    let risk_modifier = raw_modifier.min(config.max_risk_modifier);
    if risk_modifier == 0 {
        return None;
    }

    Some(BaselineDeviation {
        risk_modifier,
        new_tool_names,
        new_path_classes,
        new_network_hosts,
    })
}

impl BaselineSummary {
    pub fn merge_from(&mut self, other: BaselineSummary) {
        self.observations.merge_from(other.observations);
        merge_counts(&mut self.tool_call_counts, other.tool_call_counts);
        merge_counts(&mut self.path_class_counts, other.path_class_counts);
        merge_counts(&mut self.network_host_counts, other.network_host_counts);
    }

    fn observe(&mut self, record: &NormalizedRecord) {
        self.observations.observe(record.kind);

        if record.kind != RecordKind::ToolCall {
            return;
        }

        let tool_name = record
            .tool_name
            .as_deref()
            .unwrap_or("unknown")
            .trim()
            .to_ascii_lowercase();
        *self.tool_call_counts.entry(tool_name).or_insert(0) += 1;

        let text_values = text_observation_values(record);
        for value in &text_values {
            for path_class in path_classes(value) {
                *self.path_class_counts.entry(path_class).or_insert(0) += 1;
            }
            for host in network_hosts(value) {
                *self.network_host_counts.entry(host).or_insert(0) += 1;
            }
        }
    }

    pub fn hash_network_hosts_for_state(&mut self) {
        self.network_host_counts = self
            .network_host_counts
            .iter()
            .map(|(host, count)| (baseline_host_identity(host), *count))
            .fold(BTreeMap::new(), |mut counts, (host, count)| {
                *counts.entry(host).or_insert(0) += count;
                counts
            });
    }
}

impl BaselineObservationTotals {
    fn merge_from(&mut self, other: BaselineObservationTotals) {
        self.records += other.records;
        self.user_messages += other.user_messages;
        self.assistant_messages += other.assistant_messages;
        self.tool_calls += other.tool_calls;
        self.tool_results += other.tool_results;
        self.session_meta += other.session_meta;
        self.other += other.other;
    }

    fn observe(&mut self, kind: RecordKind) {
        self.records += 1;
        match kind {
            RecordKind::UserMessage => self.user_messages += 1,
            RecordKind::AssistantMessage => self.assistant_messages += 1,
            RecordKind::ToolCall => self.tool_calls += 1,
            RecordKind::ToolResult => self.tool_results += 1,
            RecordKind::SessionMeta => self.session_meta += 1,
            RecordKind::Other => self.other += 1,
        }
    }
}

fn merge_counts<K: Ord>(target: &mut BTreeMap<K, u64>, source: BTreeMap<K, u64>) {
    for (key, count) in source {
        *target.entry(key).or_insert(0) += count;
    }
}

pub fn baseline_host_identity(host: &str) -> String {
    if host.starts_with(BASELINE_HOST_HASH_PREFIX) {
        return host.to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(host.trim().to_ascii_lowercase().as_bytes());
    format!("{BASELINE_HOST_HASH_PREFIX}{:x}", hasher.finalize())
}

fn baseline_host_identity_counts(summary: &BaselineSummary) -> BTreeMap<String, u64> {
    summary
        .network_host_counts
        .iter()
        .map(|(host, count)| (baseline_host_identity(host), *count))
        .fold(BTreeMap::new(), |mut counts, (host, count)| {
            *counts.entry(host).or_insert(0) += count;
            counts
        })
}

impl From<&NormalizedRecord> for BaselineKey {
    fn from(record: &NormalizedRecord) -> Self {
        Self {
            client: blank_to_none(&record.client).unwrap_or_else(|| "unknown".to_string()),
            agent: record.agent.as_deref().and_then(blank_to_none),
            model: record.model.as_deref().and_then(blank_to_none),
            provider: record.provider.as_deref().and_then(blank_to_none),
        }
    }
}

fn blank_to_none(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn text_observation_values(record: &NormalizedRecord) -> Vec<String> {
    let mut values = Vec::new();

    if let Some(arguments) = &record.arguments {
        if let Ok(value) = serde_json::from_str::<Value>(arguments) {
            collect_json_strings(&value, &mut values);
        } else {
            values.push(arguments.clone());
        }
    }

    if !record.content.trim().is_empty() {
        values.push(record.content.clone());
    }

    values
}

fn collect_json_strings(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(s) => output.push(s.clone()),
        Value::Array(items) => {
            for item in items {
                collect_json_strings(item, output);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                collect_json_strings(value, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn path_classes(input: &str) -> Vec<PathClass> {
    tokenize(input)
        .into_iter()
        .filter_map(|token| classify_path_token(&token))
        .collect()
}

fn classify_path_token(token: &str) -> Option<PathClass> {
    let trimmed = token.trim_matches(|c: char| {
        matches!(
            c,
            '"' | '\'' | '`' | ',' | ';' | ':' | ')' | '(' | '[' | ']' | '{' | '}'
        )
    });
    if trimmed.is_empty() || trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    let looks_like_path = lower.contains('/')
        || lower.starts_with("~/")
        || lower.starts_with("./")
        || lower.starts_with("../")
        || lower.contains('.');

    if !looks_like_path {
        return None;
    }

    if lower.contains(".env")
        || lower.contains("id_rsa")
        || lower.contains("id_ed25519")
        || lower.contains(".aws/credentials")
        || lower.contains(".ssh/")
        || lower.contains("credentials")
        || lower.contains("token")
    {
        return Some(PathClass::SecretStore);
    }
    if lower.starts_with("/tmp/")
        || lower.starts_with("tmp/")
        || lower.starts_with("/var/tmp/")
        || lower.starts_with("/users/") && lower.contains("/appdata/local/temp/")
        || lower.starts_with("c:/users/") && lower.contains("/appdata/local/temp/")
    {
        return Some(PathClass::Temp);
    }
    if lower.starts_with("~/")
        || lower.starts_with("/home/")
        || lower.starts_with("/users/")
        || lower.starts_with("c:/users/")
        || lower.starts_with("$home/")
    {
        return Some(PathClass::Home);
    }
    if lower.contains("/test/")
        || lower.contains("/tests/")
        || lower.starts_with("test/")
        || lower.starts_with("tests/")
        || lower.ends_with("_test.rs")
        || lower.ends_with(".test.js")
        || lower.ends_with(".spec.ts")
    {
        return Some(PathClass::Test);
    }
    if lower.ends_with(".md")
        || lower.starts_with("docs/")
        || lower.contains("/docs/")
        || lower.ends_with(".rst")
    {
        return Some(PathClass::Documentation);
    }
    if lower.ends_with("cargo.toml")
        || lower.ends_with("package.json")
        || lower.ends_with("pyproject.toml")
        || lower.ends_with("go.mod")
        || lower.ends_with("pom.xml")
    {
        return Some(PathClass::BuildManifest);
    }
    if lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.ends_with(".toml")
        || lower.ends_with(".json")
        || lower.ends_with(".ini")
        || lower.ends_with(".conf")
    {
        return Some(PathClass::Config);
    }
    if lower.ends_with(".rs")
        || lower.ends_with(".py")
        || lower.ends_with(".js")
        || lower.ends_with(".ts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".go")
        || lower.ends_with(".java")
        || lower.ends_with(".c")
        || lower.ends_with(".cpp")
        || lower.ends_with(".h")
    {
        return Some(PathClass::Source);
    }

    Some(PathClass::Other)
}

fn network_hosts(input: &str) -> Vec<String> {
    tokenize(input)
        .into_iter()
        .filter_map(|token| host_from_url_token(&token))
        .collect()
}

fn host_from_url_token(token: &str) -> Option<String> {
    let trimmed = token.trim_matches(|c: char| {
        matches!(
            c,
            '"' | '\'' | '`' | ',' | ';' | ')' | '(' | '[' | ']' | '{' | '}' | '<' | '>'
        )
    });
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))?;
    let authority = without_scheme
        .split(['/', '?', '#', ':'])
        .next()
        .unwrap_or_default()
        .trim();
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or(authority)
        .to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

fn tokenize(input: &str) -> Vec<String> {
    input
        .split_whitespace()
        .map(|token| {
            token
                .trim_matches(|c: char| c.is_ascii_control())
                .to_string()
        })
        .filter(|token| !token.is_empty())
        .collect()
}

/// Version stamp for persisted baseline snapshot stores.
pub const BASELINE_STATE_VERSION: u16 = 2;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BaselineSnapshotStore {
    pub schema_version: u16,
    pub snapshots: BTreeMap<String, BaselineSummary>,
}

impl Default for BaselineSnapshotStore {
    fn default() -> Self {
        Self {
            schema_version: BASELINE_STATE_VERSION,
            snapshots: BTreeMap::new(),
        }
    }
}

pub fn baseline_snapshot_id(key: &BaselineKey) -> String {
    [
        key.client.as_str(),
        key.agent.as_deref().unwrap_or(""),
        key.model.as_deref().unwrap_or(""),
        key.provider.as_deref().unwrap_or(""),
    ]
    .join("\u{1f}")
}

#[cfg(test)]
mod tests {
    use telltale_sources::discovery::discover_sources;
    use telltale_sources::parser::parse_source_records;

    use super::*;

    fn record(
        client: &str,
        model: Option<&str>,
        provider: Option<&str>,
        kind: RecordKind,
        tool_name: Option<&str>,
        arguments: Option<&str>,
        content: &str,
    ) -> NormalizedRecord {
        NormalizedRecord {
            session_id: "session-a".to_string(),
            client: client.to_string(),
            agent: Some(format!("{client}-agent")),
            model: model.map(str::to_string),
            provider: provider.map(str::to_string),
            timestamp: None,
            kind,
            tool_name: tool_name.map(str::to_string),
            arguments: arguments.map(str::to_string),
            content: content.to_string(),
        }
    }

    #[test]
    fn builds_deterministic_model_baseline_from_synthetic_records() {
        let records = vec![
            record(
                "codex",
                Some("o3"),
                Some("openai"),
                RecordKind::UserMessage,
                None,
                None,
                "Inspect the project files.",
            ),
            record(
                "codex",
                Some("o3"),
                Some("openai"),
                RecordKind::ToolCall,
                Some("shell"),
                Some(r#"{"command":"cat src/lib.rs && curl https://docs.example.test/api"}"#),
                "",
            ),
            record(
                "codex",
                Some("o3"),
                Some("openai"),
                RecordKind::ToolCall,
                Some("shell"),
                Some(r#"{"command":"cargo test tests/baseline_test.rs"}"#),
                "",
            ),
            record(
                "qwen",
                Some("qwen3-coder-plus"),
                Some("qwen"),
                RecordKind::ToolCall,
                Some("read_file"),
                Some(r#"{"path":"README.md"}"#),
                "",
            ),
        ];

        let summaries = build_baseline_summaries(&records);

        assert_eq!(summaries.len(), 2);
        let codex = summaries
            .iter()
            .find(|summary| summary.key.client == "codex")
            .expect("codex baseline");
        assert_eq!(codex.key.model.as_deref(), Some("o3"));
        assert_eq!(codex.observations.records, 3);
        assert_eq!(codex.observations.user_messages, 1);
        assert_eq!(codex.observations.tool_calls, 2);
        assert_eq!(codex.tool_call_counts.get("shell"), Some(&2));
        assert_eq!(codex.path_class_counts.get(&PathClass::Source), Some(&1));
        assert_eq!(codex.path_class_counts.get(&PathClass::Test), Some(&1));
        assert_eq!(codex.network_host_counts.get("docs.example.test"), Some(&1));

        let qwen = summaries
            .iter()
            .find(|summary| summary.key.client == "qwen")
            .expect("qwen baseline");
        assert_eq!(qwen.tool_call_counts.get("read_file"), Some(&1));
        assert_eq!(
            qwen.path_class_counts.get(&PathClass::Documentation),
            Some(&1)
        );
    }

    #[test]
    fn benign_fixture_records_produce_baseline_without_side_effects() {
        let sources = discover_sources(&crate::test_fixture_path("benign_baselines"));
        let mut records = Vec::new();
        for source in sources {
            records.extend(parse_source_records(&source).expect("parse benign source"));
        }

        let summaries = build_baseline_summaries(&records);

        assert!(
            summaries.len() >= 8,
            "expected supported benign clients, got {}",
            summaries.len()
        );
        assert!(
            summaries
                .iter()
                .any(|summary| summary.observations.tool_calls > 0)
        );
        assert!(
            summaries
                .iter()
                .any(|summary| !summary.tool_call_counts.is_empty()),
            "expected at least one tool-call count"
        );
    }

    #[test]
    fn baseline_deviation_scoring_is_bounded_and_opt_in() {
        let previous_records = (0..6)
            .map(|_| {
                record(
                    "codex",
                    Some("o3"),
                    Some("openai"),
                    RecordKind::ToolCall,
                    Some("read_file"),
                    Some(r#"{"path":"src/lib.rs"}"#),
                    "",
                )
            })
            .collect::<Vec<_>>();
        let current_records = vec![record(
            "codex",
            Some("o3"),
            Some("openai"),
            RecordKind::ToolCall,
            Some("shell"),
            Some(r#"{"command":"curl https://new.example.test/data > /tmp/out"}"#),
            "",
        )];
        let previous = build_baseline_summaries(&previous_records).remove(0);
        let current = build_baseline_summaries(&current_records).remove(0);

        assert_eq!(
            assess_baseline_deviation(
                Some(&previous),
                &current,
                BaselineDeviationConfig::default()
            ),
            None,
            "default config must not alter scores"
        );

        let deviation = assess_baseline_deviation(
            Some(&previous),
            &current,
            BaselineDeviationConfig {
                enabled: true,
                min_previous_tool_calls: 5,
                max_risk_modifier: 10,
            },
        )
        .expect("deviation");

        assert_eq!(deviation.risk_modifier, 10);
        assert_eq!(deviation.new_tool_names, 1);
        assert!(deviation.new_path_classes > 0);
        assert_eq!(deviation.new_network_hosts, 1);
    }

    #[test]
    fn baseline_deviation_compares_hashed_persisted_hosts() {
        let previous_records = (0..6)
            .map(|_| {
                record(
                    "codex",
                    Some("o3"),
                    Some("openai"),
                    RecordKind::ToolCall,
                    Some("shell"),
                    Some(r#"{"command":"curl https://known.example.test/api"}"#),
                    "",
                )
            })
            .collect::<Vec<_>>();
        let current_records = vec![record(
            "codex",
            Some("o3"),
            Some("openai"),
            RecordKind::ToolCall,
            Some("shell"),
            Some(r#"{"command":"curl https://known.example.test/api"}"#),
            "",
        )];
        let mut previous = build_baseline_summaries(&previous_records).remove(0);
        previous.hash_network_hosts_for_state();
        let current = build_baseline_summaries(&current_records).remove(0);

        assert_eq!(
            assess_baseline_deviation(
                Some(&previous),
                &current,
                BaselineDeviationConfig {
                    enabled: true,
                    min_previous_tool_calls: 5,
                    max_risk_modifier: 15,
                },
            ),
            None,
            "raw current hosts should match hashed persisted baseline hosts"
        );
    }

    #[test]
    fn baseline_deviation_treats_missing_model_or_provider_as_unavailable() {
        let previous = build_baseline_summaries(&[record(
            "codex",
            Some("o3"),
            Some("openai"),
            RecordKind::ToolCall,
            Some("read_file"),
            Some(r#"{"path":"src/lib.rs"}"#),
            "",
        )])
        .remove(0);
        let current = build_baseline_summaries(&[record(
            "codex",
            None,
            Some("openai"),
            RecordKind::ToolCall,
            Some("shell"),
            Some(r#"{"command":"curl https://new.example.test"}"#),
            "",
        )])
        .remove(0);

        assert_eq!(
            assess_baseline_deviation(
                Some(&previous),
                &current,
                BaselineDeviationConfig {
                    enabled: true,
                    min_previous_tool_calls: 0,
                    max_risk_modifier: 15,
                },
            ),
            None
        );
    }

    #[test]
    fn baseline_network_hosts_drop_url_userinfo() {
        let current = build_baseline_summaries(&[record(
            "codex",
            Some("o3"),
            Some("openai"),
            RecordKind::ToolCall,
            Some("shell"),
            Some(r#"{"command":"curl https://token@example.test/path"}"#),
            "",
        )])
        .remove(0);

        assert_eq!(current.network_host_counts.get("example.test"), Some(&1));
        assert!(
            !current
                .network_host_counts
                .contains_key("token@example.test")
        );
    }

    #[test]
    fn classifies_macos_and_windows_home_and_temp_paths() {
        assert_eq!(
            classify_path_token("/Users/tester/project/src/main.rs"),
            Some(PathClass::Home)
        );
        assert_eq!(
            classify_path_token("C:/Users/tester/AppData/Local/Temp/build.log"),
            Some(PathClass::Temp)
        );
        assert_eq!(
            classify_path_token("C:/Users/tester/Documents/notes.txt"),
            Some(PathClass::Home)
        );
    }
}
