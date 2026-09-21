use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use telltale_schema::activity_facts::PathClass;
use telltale_schema::activity_facts::{network_hosts, path_classes};
use telltale_schema::record::{NormalizedRecord, RecordKind};
use telltale_schema::scoring::RiskAccountingError;

#[cfg(feature = "source-io")]
pub(crate) mod accounting;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BaselineDeviationConfig {
    pub enabled: bool,
    pub min_previous_tool_calls: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BaselineDeviation {
    pub risk_modifier: u64,
    pub new_tool_names: usize,
    pub new_path_classes: usize,
    pub new_network_hosts: usize,
}

impl Default for BaselineDeviationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_previous_tool_calls: 5,
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
) -> Result<Option<BaselineDeviation>, RiskAccountingError> {
    if !config.enabled || current.key.model.is_none() || current.key.provider.is_none() {
        return Ok(None);
    }

    let Some(previous) = previous else {
        return Ok(None);
    };
    if previous.observations.tool_calls < config.min_previous_tool_calls {
        return Ok(None);
    }

    let previous_network_hosts = previous
        .network_host_counts
        .keys()
        .map(|host| baseline_host_identity(host))
        .collect::<BTreeSet<_>>();
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
        .filter(|host| !previous_network_hosts.contains(host))
        .count();

    let risk_modifier = u64::try_from(new_tool_names)
        .map_err(|_| RiskAccountingError::Overflow)?
        .checked_mul(5)
        .ok_or(RiskAccountingError::Overflow)?
        .checked_add(
            u64::try_from(new_path_classes)
                .map_err(|_| RiskAccountingError::Overflow)?
                .checked_mul(5)
                .ok_or(RiskAccountingError::Overflow)?,
        )
        .ok_or(RiskAccountingError::Overflow)?
        .checked_add(
            u64::try_from(new_network_hosts)
                .map_err(|_| RiskAccountingError::Overflow)?
                .checked_mul(5)
                .ok_or(RiskAccountingError::Overflow)?,
        )
        .ok_or(RiskAccountingError::Overflow)?;
    if risk_modifier == 0 {
        return Ok(None);
    }

    Ok(Some(BaselineDeviation {
        risk_modifier,
        new_tool_names,
        new_path_classes,
        new_network_hosts,
    }))
}

impl BaselineSummary {
    /// Use on a disposable staged value: errors can leave a partial merge, which
    /// must never be installed.
    pub fn checked_merge_from(
        &mut self,
        other: BaselineSummary,
    ) -> Result<(), RiskAccountingError> {
        self.merge_with(other, |left, right| {
            left.checked_add(right).ok_or(RiskAccountingError::Overflow)
        })
    }

    fn merge_with(
        &mut self,
        other: BaselineSummary,
        add: impl Fn(u64, u64) -> Result<u64, RiskAccountingError> + Copy,
    ) -> Result<(), RiskAccountingError> {
        self.observations.merge_from(other.observations, add)?;
        merge_counts(&mut self.tool_call_counts, other.tool_call_counts, add)?;
        merge_counts(&mut self.path_class_counts, other.path_class_counts, add)?;
        merge_counts(
            &mut self.network_host_counts,
            other.network_host_counts,
            add,
        )
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

    pub fn hash_network_hosts_for_state(&mut self) -> Result<(), RiskAccountingError> {
        let mut counts = BTreeMap::<String, u64>::new();
        for (host, count) in &self.network_host_counts {
            let total = counts.entry(baseline_host_identity(host)).or_default();
            *total = total
                .checked_add(*count)
                .ok_or(RiskAccountingError::Overflow)?;
        }
        self.network_host_counts = counts;
        Ok(())
    }
}

impl BaselineObservationTotals {
    fn merge_from(
        &mut self,
        other: BaselineObservationTotals,
        add: impl Fn(u64, u64) -> Result<u64, RiskAccountingError>,
    ) -> Result<(), RiskAccountingError> {
        for (target, count) in [
            (&mut self.records, other.records),
            (&mut self.user_messages, other.user_messages),
            (&mut self.assistant_messages, other.assistant_messages),
            (&mut self.tool_calls, other.tool_calls),
            (&mut self.tool_results, other.tool_results),
            (&mut self.session_meta, other.session_meta),
            (&mut self.other, other.other),
        ] {
            *target = add(*target, count)?;
        }
        Ok(())
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
            _ => self.other += 1,
        }
    }
}

fn merge_counts<K: Ord>(
    target: &mut BTreeMap<K, u64>,
    source: BTreeMap<K, u64>,
    add: impl Fn(u64, u64) -> Result<u64, RiskAccountingError>,
) -> Result<(), RiskAccountingError> {
    for (key, count) in source {
        let value = target.entry(key).or_insert(0);
        *value = add(*value, count)?;
    }
    Ok(())
}

pub fn baseline_host_identity(host: &str) -> String {
    if is_canonical_host_hash(host) {
        return host.to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(host.trim().to_ascii_lowercase().as_bytes());
    format!("{BASELINE_HOST_HASH_PREFIX}{:x}", hasher.finalize())
}

fn is_canonical_host_hash(host: &str) -> bool {
    let Some(hex) = host.strip_prefix(BASELINE_HOST_HASH_PREFIX) else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

/// Version stamp for persisted baseline snapshot stores.
pub const BASELINE_STATE_VERSION: u16 = 3;

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
    use telltale_schema::activity_facts::classify_path_token;
    #[cfg(feature = "source-io")]
    use telltale_sources::discovery::discover_sources_best_effort;
    #[cfg(feature = "source-io")]
    use telltale_sources::parser::parse_source_records;

    use super::*;

    #[test]
    fn only_exact_lowercase_host_hashes_bypass_normalization() {
        let canonical = format!("sha256:{}", "a".repeat(64));
        assert_eq!(baseline_host_identity(&canonical), canonical);
        assert_ne!(
            baseline_host_identity("sha256:ABC"),
            "sha256:ABC".to_string()
        );
        assert_ne!(
            baseline_host_identity(&format!("sha256:{}", "A".repeat(64))),
            format!("sha256:{}", "A".repeat(64))
        );
    }

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
    #[cfg(feature = "source-io")]
    fn benign_fixture_records_produce_baseline_without_side_effects() {
        let sources = discover_sources_best_effort(&crate::test_fixture_path("benign_baselines"));
        let mut records = Vec::new();
        for source in sources {
            records.extend(parse_source_records(&source).expect("parse benign source"));
        }

        let summaries = build_baseline_summaries(&records);

        assert_eq!(
            summaries.len(),
            7,
            "expected retained benign fixture summaries"
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
            )
            .expect("baseline assessment"),
            None,
            "default config must not alter scores"
        );

        let deviation = assess_baseline_deviation(
            Some(&previous),
            &current,
            BaselineDeviationConfig {
                enabled: true,
                min_previous_tool_calls: 5,
            },
        )
        .expect("baseline assessment")
        .expect("deviation");

        assert_eq!(deviation.risk_modifier, 15);
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
        previous.hash_network_hosts_for_state().unwrap();
        let current = build_baseline_summaries(&current_records).remove(0);

        assert_eq!(
            assess_baseline_deviation(
                Some(&previous),
                &current,
                BaselineDeviationConfig {
                    enabled: true,
                    min_previous_tool_calls: 5,
                },
            )
            .expect("baseline assessment"),
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
                },
            )
            .expect("baseline assessment"),
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
