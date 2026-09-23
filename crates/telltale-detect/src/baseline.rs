use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use telltale_schema::activity_facts::PathClass;
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

fn blank_to_none(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
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
    use super::*;
    use telltale_schema::activity_facts::classify_path_token;

    fn summary() -> BaselineSummary {
        BaselineSummary {
            key: BaselineKey {
                client: "codex".into(),
                agent: Some("agent".into()),
                model: Some("model".into()),
                provider: Some("provider".into()),
            },
            ..BaselineSummary::default()
        }
    }

    #[test]
    fn only_exact_lowercase_host_hashes_bypass_normalization() {
        let canonical = format!("sha256:{}", "a".repeat(64));
        assert_eq!(baseline_host_identity(&canonical), canonical);
        assert_ne!(baseline_host_identity("sha256:ABC"), "sha256:ABC");
        assert_ne!(
            baseline_host_identity(&format!("sha256:{}", "A".repeat(64))),
            format!("sha256:{}", "A".repeat(64))
        );
    }

    #[test]
    fn baseline_deviation_scoring_is_bounded_and_opt_in() {
        let mut previous = summary();
        previous.observations.tool_calls = 6;
        previous.tool_call_counts.insert("read_file".into(), 6);
        previous.path_class_counts.insert(PathClass::Source, 6);
        let mut current = summary();
        current.observations.tool_calls = 1;
        current.tool_call_counts.insert("shell".into(), 1);
        current.path_class_counts.insert(PathClass::Temp, 1);
        current
            .network_host_counts
            .insert("new.example.test".into(), 1);

        assert_eq!(
            assess_baseline_deviation(
                Some(&previous),
                &current,
                BaselineDeviationConfig::default()
            )
            .unwrap(),
            None
        );
        let deviation = assess_baseline_deviation(
            Some(&previous),
            &current,
            BaselineDeviationConfig {
                enabled: true,
                min_previous_tool_calls: 5,
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(deviation.risk_modifier, 15);
        assert_eq!(deviation.new_tool_names, 1);
        assert_eq!(deviation.new_path_classes, 1);
        assert_eq!(deviation.new_network_hosts, 1);
    }

    #[test]
    fn baseline_deviation_compares_hashed_persisted_hosts() {
        let host = "known.example.test";
        let mut previous = summary();
        previous.observations.tool_calls = 6;
        previous
            .network_host_counts
            .insert(baseline_host_identity(host), 6);
        let mut current = summary();
        current.network_host_counts.insert(host.into(), 1);
        assert_eq!(
            assess_baseline_deviation(
                Some(&previous),
                &current,
                BaselineDeviationConfig {
                    enabled: true,
                    min_previous_tool_calls: 5
                },
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn baseline_deviation_requires_model_and_provider() {
        let mut previous = summary();
        previous.observations.tool_calls = 6;
        let mut current = summary();
        current.key.model = None;
        current.tool_call_counts.insert("shell".into(), 1);
        assert_eq!(
            assess_baseline_deviation(
                Some(&previous),
                &current,
                BaselineDeviationConfig {
                    enabled: true,
                    min_previous_tool_calls: 0
                },
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn baseline_merge_hashes_and_snapshot_ids_preserve_state_semantics() {
        let mut first = summary();
        first.observations.records = 2;
        first.observations.tool_calls = 2;
        first.network_host_counts.insert("Example.test".into(), 1);
        let mut second = summary();
        second.observations.records = 3;
        second.observations.tool_calls = 3;
        second.network_host_counts.insert("example.test".into(), 2);
        first.checked_merge_from(second).unwrap();
        assert_eq!(first.observations.records, 5);
        assert_eq!(first.observations.tool_calls, 5);
        assert_eq!(first.network_host_counts.get("Example.test"), Some(&1));
        assert_eq!(first.network_host_counts.get("example.test"), Some(&2));
        first.hash_network_hosts_for_state().unwrap();
        assert_eq!(first.network_host_counts.len(), 1);
        assert_eq!(first.network_host_counts.values().copied().sum::<u64>(), 3);
        assert_eq!(
            baseline_snapshot_id(&first.key),
            "codex\u{1f}agent\u{1f}model\u{1f}provider"
        );
        assert_eq!(
            BaselineSnapshotStore::default().schema_version,
            BASELINE_STATE_VERSION
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
