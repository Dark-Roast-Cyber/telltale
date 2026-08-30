use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::sink::http::{RetryConfig, TlsOptions};
use crate::sink::outbox::CapacityLimits;
use crate::sink::splunk_hec::DEFAULT_HEC_MAX_BATCH_BYTES;
use crate::sink::{
    DEFAULT_ELASTIC_INDEX, DeliveryPosture, ElasticBulkSink, LocalJsonlSink, RotationConfig,
    SinkSet, SplunkHecConfig, SplunkHecHttpSink,
};

/// The only outputs document version this build understands.
const SUPPORTED_OUTPUTS_VERSION: u64 = 1;

/// Sink name reserved for the sink built from `--splunk-hec-*` CLI flags. A
/// config sink with this name is replaced when the flags are set.
pub const CLI_SPLUNK_HEC_SINK_NAME: &str = "cli-splunk-hec";

/// One named sink entry from a merged `outputs.d` config.
#[derive(Debug, Clone)]
pub struct SinkSpec {
    pub name: String,
    pub enabled: bool,
    pub kind: SinkKind,
    pub(crate) origin_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum SinkKind {
    Jsonl(JsonlSpec),
    SplunkHec(SplunkHecSpec),
    ElasticBulk(ElasticBulkSpec),
}

impl SinkKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            SinkKind::Jsonl(_) => "jsonl",
            SinkKind::SplunkHec(_) => "splunk_hec",
            SinkKind::ElasticBulk(_) => "elastic_bulk",
        }
    }
}

impl SinkSpec {
    /// True when the sink carries a secret written inline in the YAML.
    /// `telltale config validate` flags these; env/file references are preferred.
    pub fn has_inline_secret(&self) -> bool {
        match &self.kind {
            SinkKind::Jsonl(_) => false,
            SinkKind::SplunkHec(spec) => matches!(spec.token, SecretValue::Inline(_)),
            SinkKind::ElasticBulk(spec) => {
                matches!(spec.api_key, Some(SecretValue::Inline(_)))
                    || matches!(spec.password, Some(SecretValue::Inline(_)))
            }
        }
    }

    /// True when the sink disables TLS certificate verification.
    pub fn has_insecure_tls(&self) -> bool {
        let tls = match &self.kind {
            SinkKind::Jsonl(_) => &None,
            SinkKind::SplunkHec(spec) => &spec.tls,
            SinkKind::ElasticBulk(spec) => &spec.tls,
        };
        tls.as_ref().is_some_and(|tls| tls.insecure_skip_verify)
    }
}

pub(crate) fn effective_delivery_posture(
    specs: &[SinkSpec],
    outputs_config_present: bool,
) -> DeliveryPosture {
    if !outputs_config_present {
        return DeliveryPosture::DurableFirstWrite;
    }
    if !specs.iter().any(|spec| spec.enabled) {
        return DeliveryPosture::NoEnabledSinks;
    }
    if specs
        .iter()
        .any(|spec| spec.enabled && matches!(spec.kind, SinkKind::Jsonl(_)))
    {
        DeliveryPosture::DurableFirstWrite
    } else {
        DeliveryPosture::BestEffortNoReplay
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonlSpec {
    /// Log file path. Defaults to the resolved CLI/env/profile log path.
    pub path: Option<PathBuf>,
    /// Rotation settings. Defaults to the resolved CLI/env rotation.
    pub rotation: Option<RotationSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationSpec {
    pub max_size_bytes: Option<u64>,
    pub keep: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplunkHecSpec {
    pub endpoint: String,
    pub token: SecretValue,
    pub index: Option<String>,
    pub sourcetype: Option<String>,
    pub source: Option<String>,
    pub host: Option<String>,
    pub timeout_ms: Option<u64>,
    pub max_batch_bytes: Option<usize>,
    pub retry: Option<RetrySpec>,
    pub tls: Option<TlsSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElasticBulkSpec {
    pub endpoint: String,
    pub index: Option<String>,
    pub api_key: Option<SecretValue>,
    pub username: Option<String>,
    pub password: Option<SecretValue>,
    pub timeout_ms: Option<u64>,
    pub max_batch_bytes: Option<usize>,
    pub retry: Option<RetrySpec>,
    pub tls: Option<TlsSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrySpec {
    pub max_attempts: Option<u32>,
    pub base_delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSpec {
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

fn retry_config_from_spec(spec: Option<&RetrySpec>) -> RetryConfig {
    let defaults = RetryConfig::default();
    match spec {
        None => defaults,
        Some(spec) => RetryConfig {
            max_attempts: spec.max_attempts.unwrap_or(defaults.max_attempts),
            base_delay_ms: spec.base_delay_ms.unwrap_or(defaults.base_delay_ms),
        },
    }
}

fn tls_options_from_spec(spec: Option<&TlsSpec>) -> TlsOptions {
    match spec {
        None => TlsOptions::default(),
        Some(spec) => TlsOptions {
            ca_file: spec.ca_file.clone(),
            insecure_skip_verify: spec.insecure_skip_verify,
        },
    }
}

fn validate_http_endpoint(
    sink_name: &str,
    endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        Ok(())
    } else {
        Err(format!(
            "sink '{sink_name}': endpoint must start with http:// or https://, got '{endpoint}'"
        )
        .into())
    }
}

/// A secret in sink config: an inline string, `{env: NAME}`, or `{file: PATH}`.
/// Inline is allowed for lab use; env/file references are the documented best
/// practice and what `config validate` recommends.
#[derive(Clone, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum SecretValue {
    Env { env: String },
    File { file: PathBuf },
    Inline(String),
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env { env } => formatter.debug_struct("Env").field("env", env).finish(),
            Self::File { file } => formatter.debug_struct("File").field("file", file).finish(),
            Self::Inline(_) => formatter.write_str("Inline(\"<redacted>\")"),
        }
    }
}

impl SecretValue {
    /// Resolve the secret to its value. Called once at sink-build time so a
    /// missing env var or unreadable file fails the run at startup.
    pub fn resolve(&self, what: &str) -> Result<String, Box<dyn std::error::Error>> {
        match self {
            SecretValue::Inline(value) => Ok(value.clone()),
            SecretValue::Env { env } => match std::env::var(env) {
                Ok(value) if !value.trim().is_empty() => Ok(value),
                _ => Err(format!("{what}: environment variable {env} is not set or empty").into()),
            },
            SecretValue::File { file } => {
                let value = fs::read_to_string(file).map_err(|err| {
                    format!(
                        "{what}: could not read secret file {}: {err}",
                        file.display()
                    )
                })?;
                let value = value.trim_end().to_string();
                if value.is_empty() {
                    return Err(format!("{what}: secret file {} is empty", file.display()).into());
                }
                Ok(value)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputsDocRaw {
    version: u64,
    sinks: Vec<serde_yaml::Value>,
    delivery: Option<DeliverySpecRaw>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliverySpecRaw {
    policy: String,
    outbox_path: Option<PathBuf>,
    max_pending_events: Option<u64>,
    max_pending_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ConfigDeliveryPolicy {
    BestEffort,
    Durable,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DeliveryConfig {
    pub(crate) policy: ConfigDeliveryPolicy,
    pub(crate) outbox_path: Option<PathBuf>,
    pub(crate) capacity_limits: CapacityLimits,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            policy: ConfigDeliveryPolicy::BestEffort,
            outbox_path: None,
            capacity_limits: CapacityLimits::default(),
        }
    }
}

pub(crate) struct LoadedOutputsConfig {
    pub(crate) sinks: Vec<SinkSpec>,
    /// Retained for durable-mode construction; Batch 4+ reads it for dispatch wiring.
    #[allow(dead_code)]
    pub(crate) delivery: DeliveryConfig,
}

fn parse_delivery(value: DeliverySpecRaw) -> Result<DeliveryConfig, Box<dyn std::error::Error>> {
    let policy = match value.policy.as_str() {
        "best_effort" => ConfigDeliveryPolicy::BestEffort,
        "durable" => ConfigDeliveryPolicy::Durable,
        other => return Err(format!("unsupported delivery policy '{other}'").into()),
    };
    if policy == ConfigDeliveryPolicy::Durable && value.outbox_path.is_none() {
        return Err("durable delivery requires outbox_path".into());
    }
    if policy == ConfigDeliveryPolicy::BestEffort && value.outbox_path.is_some() {
        return Err("best-effort delivery cannot configure outbox_path".into());
    }
    if policy == ConfigDeliveryPolicy::BestEffort
        && (value.max_pending_events.is_some() || value.max_pending_bytes.is_some())
    {
        return Err(
            "best-effort delivery cannot configure durable capacity limits (max_pending_events/max_pending_bytes)"
                .into(),
        );
    }
    let defaults = CapacityLimits::default();
    let max_pending_events = validate_capacity_value(
        "max_pending_events",
        value
            .max_pending_events
            .unwrap_or(defaults.max_pending_events),
    )?;
    let max_pending_bytes = validate_capacity_value(
        "max_pending_bytes",
        value
            .max_pending_bytes
            .unwrap_or(defaults.max_pending_bytes),
    )?;
    Ok(DeliveryConfig {
        policy,
        outbox_path: value.outbox_path,
        capacity_limits: CapacityLimits {
            max_pending_events,
            max_pending_bytes,
        },
    })
}

fn validate_capacity_value(name: &str, value: u64) -> Result<u64, Box<dyn std::error::Error>> {
    if value == 0 {
        return Err(format!("{name} must be greater than zero").into());
    }
    usize::try_from(value).map_err(|_| -> Box<dyn std::error::Error> {
        format!("{name} is too large for this platform").into()
    })?;
    Ok(value)
}

pub(crate) fn load_outputs_config_with_delivery(
    paths: &[PathBuf],
) -> Result<LoadedOutputsConfig, Box<dyn std::error::Error>> {
    let mut merged: Vec<SinkSpec> = Vec::new();
    let mut delivery = DeliveryConfig::default();
    for path in paths {
        let text = fs::read_to_string(path)
            .map_err(|err| format!("could not read outputs config {}: {err}", path.display()))?;
        let doc: OutputsDocRaw = serde_yaml::from_str(&text)
            .map_err(|err| format!("invalid outputs config {}: {err}", path.display()))?;
        if doc.version != SUPPORTED_OUTPUTS_VERSION {
            return Err(format!(
                "outputs config {}: version {} is not supported by this Telltale build (expected {})",
                path.display(),
                doc.version,
                SUPPORTED_OUTPUTS_VERSION
            )
            .into());
        }
        if let Some(raw_delivery) = doc.delivery {
            delivery = parse_delivery(raw_delivery)
                .map_err(|err| format!("outputs config {}: {err}", path.display()))?;
        }
        let mut names_in_file = BTreeSet::new();
        for sink_value in doc.sinks {
            let mut spec = parse_sink_spec(sink_value)
                .map_err(|err| format!("outputs config {}: {err}", path.display()))?;
            spec.origin_path = Some(path.clone());
            if !names_in_file.insert(spec.name.clone()) {
                return Err(format!(
                    "outputs config {}: duplicate sink name '{}'",
                    path.display(),
                    spec.name
                )
                .into());
            }
            if let Some(existing) = merged.iter_mut().find(|s| s.name == spec.name) {
                *existing = spec;
            } else {
                merged.push(spec);
            }
        }
    }
    Ok(LoadedOutputsConfig {
        sinks: merged,
        delivery,
    })
}

/// Parse one `sinks:` entry. `name`/`enabled`/`type` are extracted by hand and
/// the remaining keys are deserialized into the type-specific spec struct;
/// serde's `deny_unknown_fields` cannot be combined with `flatten`, and this
/// keeps typo rejection working for every field.
fn parse_sink_spec(value: serde_yaml::Value) -> Result<SinkSpec, String> {
    let serde_yaml::Value::Mapping(mut map) = value else {
        return Err("sink entry must be a mapping".to_string());
    };
    let name = match map.remove(serde_yaml::Value::from("name")) {
        Some(serde_yaml::Value::String(name)) if !name.trim().is_empty() => name,
        Some(_) => return Err("sink 'name' must be a non-empty string".to_string()),
        None => return Err("sink entry is missing required field 'name'".to_string()),
    };
    let enabled = match map.remove(serde_yaml::Value::from("enabled")) {
        None => true,
        Some(serde_yaml::Value::Bool(enabled)) => enabled,
        Some(_) => return Err(format!("sink '{name}': 'enabled' must be a boolean")),
    };
    let sink_type = match map.remove(serde_yaml::Value::from("type")) {
        Some(serde_yaml::Value::String(sink_type)) => sink_type,
        Some(_) => return Err(format!("sink '{name}': 'type' must be a string")),
        None => return Err(format!("sink '{name}' is missing required field 'type'")),
    };
    let rest = serde_yaml::Value::Mapping(map);
    let kind = match sink_type.as_str() {
        "jsonl" => SinkKind::Jsonl(
            serde_yaml::from_value(rest).map_err(|err| format!("sink '{name}': {err}"))?,
        ),
        "splunk_hec" => SinkKind::SplunkHec(
            serde_yaml::from_value(rest).map_err(|err| format!("sink '{name}': {err}"))?,
        ),
        "elastic_bulk" => SinkKind::ElasticBulk(
            serde_yaml::from_value(rest).map_err(|err| format!("sink '{name}': {err}"))?,
        ),
        other => {
            return Err(format!(
                "sink '{name}': unknown sink type '{other}' (expected one of: jsonl, splunk_hec, elastic_bulk)"
            ));
        }
    };
    Ok(SinkSpec {
        name,
        enabled,
        kind,
        origin_path: None,
    })
}

/// Sink-relevant values resolved from CLI flags and env, overlaid on the
/// outputs config.
pub struct CliSinkOverrides<'a> {
    pub log_path: &'a Path,
    pub rotation: RotationConfig,
    pub splunk_hec_endpoint: Option<&'a str>,
    pub splunk_hec_token: Option<&'a str>,
}

/// Build the sink set for a run from merged outputs config plus CLI overlays.
///
/// With no outputs config this reproduces the legacy behavior exactly: a local
/// JSONL sink at the resolved log path, plus a Splunk HEC sink iff both
/// `--splunk-hec-*` flags are set.
#[cfg(test)]
fn build_sink_set(
    specs: &[SinkSpec],
    cli: &CliSinkOverrides<'_>,
) -> Result<SinkSet, Box<dyn std::error::Error>> {
    build_sink_set_with_presence_and_delivery(
        specs,
        !specs.is_empty(),
        cli,
        &DeliveryConfig::default(),
        true,
    )
}

#[cfg(test)]
fn build_sink_set_with_presence_and_delivery(
    specs: &[SinkSpec],
    outputs_config_present: bool,
    cli: &CliSinkOverrides<'_>,
    delivery: &DeliveryConfig,
    emit_warnings: bool,
) -> Result<SinkSet, Box<dyn std::error::Error>> {
    build_sink_set_with_presence_and_delivery_for_activation(
        specs,
        outputs_config_present,
        cli,
        delivery,
        emit_warnings,
        true,
    )
}

/// Build and validate sinks without activating persistent durable storage.
/// This is used by configuration validation and dry-run scans so they can
/// resolve durable settings without opening SQLite or creating its artifacts.
pub(crate) fn build_sink_set_with_presence_and_delivery_for_validation(
    specs: &[SinkSpec],
    outputs_config_present: bool,
    cli: &CliSinkOverrides<'_>,
    delivery: &DeliveryConfig,
    emit_warnings: bool,
) -> Result<SinkSet, Box<dyn std::error::Error>> {
    build_sink_set_with_presence_and_delivery_for_activation(
        specs,
        outputs_config_present,
        cli,
        delivery,
        emit_warnings,
        false,
    )
}

/// Build sinks with an explicit persistent-storage activation decision. The
/// activation flag is deliberately controlled by the caller's command mode.
pub(crate) fn build_sink_set_with_presence_and_delivery_for_activation(
    specs: &[SinkSpec],
    outputs_config_present: bool,
    cli: &CliSinkOverrides<'_>,
    delivery: &DeliveryConfig,
    emit_warnings: bool,
    activate_persistent_replay: bool,
) -> Result<SinkSet, Box<dyn std::error::Error>> {
    build_sink_set_with_presence_and_delivery_with_activation(
        specs,
        outputs_config_present,
        cli,
        delivery,
        emit_warnings,
        activate_persistent_replay,
        crate::sink::outbox::current_platform_is_windows(),
    )
}

#[cfg(test)]
fn build_sink_set_with_presence_and_delivery_for_platform(
    specs: &[SinkSpec],
    outputs_config_present: bool,
    cli: &CliSinkOverrides<'_>,
    delivery: &DeliveryConfig,
    emit_warnings: bool,
    is_windows: bool,
) -> Result<SinkSet, Box<dyn std::error::Error>> {
    build_sink_set_with_presence_and_delivery_with_activation(
        specs,
        outputs_config_present,
        cli,
        delivery,
        emit_warnings,
        true,
        is_windows,
    )
}

fn build_sink_set_with_presence_and_delivery_with_activation(
    specs: &[SinkSpec],
    outputs_config_present: bool,
    cli: &CliSinkOverrides<'_>,
    delivery: &DeliveryConfig,
    emit_warnings: bool,
    activate_persistent_replay: bool,
    is_windows: bool,
) -> Result<SinkSet, Box<dyn std::error::Error>> {
    if delivery.policy == ConfigDeliveryPolicy::Durable {
        crate::sink::outbox::ensure_durable_storage_supported_for_platform(is_windows)?;
    }

    let cli_hec = match (cli.splunk_hec_endpoint, cli.splunk_hec_token) {
        (None, None) => None,
        (Some(endpoint), Some(token)) => Some((endpoint, token)),
        _ => {
            return Err("--splunk-hec-endpoint and --splunk-hec-token must be set together".into());
        }
    };

    let mut sinks = SinkSet::new();
    if !outputs_config_present {
        let sink = LocalJsonlSink::with_rotation(cli.log_path, cli.rotation.clone());
        let rotation_keep = (delivery.policy == ConfigDeliveryPolicy::Durable
            && cli.rotation.is_enabled())
        .then_some(cli.rotation.keep);
        let sink = if delivery.policy == ConfigDeliveryPolicy::Durable {
            sink.with_durable_rotation()
        } else {
            sink
        };
        let rotation_namespace = sink.rotation_namespace()?;
        if let Some(rotation_keep) = rotation_keep {
            sinks.add_canonical_first_write_path_with_rotation_and_keep(
                "jsonl",
                Box::new(sink),
                cli.log_path,
                rotation_namespace,
                Some(rotation_keep),
            );
        } else {
            sinks.add_canonical_first_write_path_with_rotation(
                "jsonl",
                Box::new(sink),
                cli.log_path,
                rotation_namespace,
            );
        }
    } else {
        for spec in specs.iter().filter(|spec| spec.enabled) {
            // The CLI flags own this reserved name: the flag-built sink below
            // replaces a config sink that claims it.
            if cli_hec.is_some() && spec.name == CLI_SPLUNK_HEC_SINK_NAME {
                continue;
            }
            match &spec.kind {
                SinkKind::Jsonl(jsonl) => {
                    let path = jsonl
                        .path
                        .clone()
                        .unwrap_or_else(|| cli.log_path.to_path_buf());
                    let rotation = match &jsonl.rotation {
                        None => cli.rotation.clone(),
                        Some(rotation) => RotationConfig {
                            max_size_bytes: rotation
                                .max_size_bytes
                                .unwrap_or(cli.rotation.max_size_bytes),
                            keep: rotation.keep.unwrap_or(cli.rotation.keep),
                        },
                    };
                    let rotation_keep = rotation.is_enabled().then_some(rotation.keep);
                    let sink =
                        LocalJsonlSink::with_rotation(path.clone(), rotation).with_name(&spec.name);
                    let sink = if delivery.policy == ConfigDeliveryPolicy::Durable {
                        sink.with_durable_rotation()
                    } else {
                        sink
                    };
                    let rotation_namespace = sink.rotation_namespace()?;
                    sinks.add_canonical_first_write_path_with_rotation_and_keep(
                        "jsonl",
                        Box::new(sink),
                        path,
                        rotation_namespace,
                        (delivery.policy == ConfigDeliveryPolicy::Durable)
                            .then_some(rotation_keep)
                            .flatten(),
                    );
                }
                SinkKind::SplunkHec(hec) => {
                    validate_http_endpoint(&spec.name, &hec.endpoint)?;
                    let token = hec.token.resolve(&format!("sink '{}' token", spec.name))?;
                    let retry = retry_config_from_spec(hec.retry.as_ref());
                    let defaults = SplunkHecConfig::default();
                    let config = SplunkHecConfig {
                        index: hec.index.clone().or(defaults.index),
                        sourcetype: hec.sourcetype.clone().unwrap_or(defaults.sourcetype),
                        source: hec.source.clone().or(defaults.source),
                        host: hec.host.clone(),
                    };
                    let sink = SplunkHecHttpSink::new(hec.endpoint.clone(), token, config)
                        .with_name(&spec.name)
                        .with_transport_warning(
                            Duration::from_millis(hec.timeout_ms.unwrap_or(10_000)),
                            retry.clone(),
                            &tls_options_from_spec(hec.tls.as_ref()),
                            hec.max_batch_bytes.unwrap_or(DEFAULT_HEC_MAX_BATCH_BYTES),
                            emit_warnings,
                        )
                        .map_err(|err| format!("sink '{}': {err}", spec.name))?;
                    sinks.add_best_effort_with_retry("splunk_hec", Box::new(sink), retry);
                }
                SinkKind::ElasticBulk(elastic) => {
                    validate_http_endpoint(&spec.name, &elastic.endpoint)?;
                    let retry = retry_config_from_spec(elastic.retry.as_ref());
                    let index = elastic
                        .index
                        .clone()
                        .unwrap_or_else(|| DEFAULT_ELASTIC_INDEX.to_string());
                    let mut sink = ElasticBulkSink::new(&elastic.endpoint, index)
                        .with_name(&spec.name)
                        .with_transport_warning(
                            Duration::from_millis(elastic.timeout_ms.unwrap_or(10_000)),
                            retry.clone(),
                            &tls_options_from_spec(elastic.tls.as_ref()),
                            elastic
                                .max_batch_bytes
                                .unwrap_or(crate::sink::elastic::DEFAULT_ELASTIC_MAX_BATCH_BYTES),
                            emit_warnings,
                        )
                        .map_err(|err| format!("sink '{}': {err}", spec.name))?;
                    match (&elastic.api_key, &elastic.username, &elastic.password) {
                        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                            return Err(format!(
                                "sink '{}': set either api_key or username/password, not both",
                                spec.name
                            )
                            .into());
                        }
                        (Some(api_key), None, None) => {
                            let api_key =
                                api_key.resolve(&format!("sink '{}' api_key", spec.name))?;
                            sink = sink.with_api_key(&api_key);
                        }
                        (None, Some(username), Some(password)) => {
                            let password =
                                password.resolve(&format!("sink '{}' password", spec.name))?;
                            sink = sink.with_basic_auth(username, &password);
                        }
                        (None, Some(_), None) | (None, None, Some(_)) => {
                            return Err(format!(
                                "sink '{}': username and password must be set together",
                                spec.name
                            )
                            .into());
                        }
                        (None, None, None) => {}
                    }
                    sinks.add_best_effort_with_retry("elastic_bulk", Box::new(sink), retry);
                }
            }
        }
    }

    if let Some((endpoint, token)) = cli_hec {
        sinks.add_best_effort(
            "splunk_hec",
            Box::new(SplunkHecHttpSink::new(
                endpoint.to_string(),
                token.to_string(),
                SplunkHecConfig::default(),
            )),
        );
    }

    if delivery.policy == ConfigDeliveryPolicy::Durable {
        let paths = sinks.local_persistence_paths();
        if paths.len() != 1 {
            return Err("durable downstream delivery requires canonical JSONL".into());
        }
        let outbox_path = delivery
            .outbox_path
            .as_ref()
            .ok_or("durable delivery requires outbox_path")?;
        crate::sink::outbox::validate_outbox_jsonl_paths(outbox_path, &paths[0])?;
        crate::sink::outbox::validate_outbox_path_without_activation(outbox_path)?;
        let sink_ids = sinks.delivery_sink_ids();
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            sink_ids,
            delivery.capacity_limits,
        );
        if activate_persistent_replay {
            sinks.activate_persistent_replay()?;
        }
    }

    if emit_warnings && sinks.is_empty() {
        eprintln!("warning: outputs config defines no enabled sinks; events will not be delivered");
    } else if emit_warnings && !sinks.has_canonical_first_write() {
        eprintln!(
            "warning: outputs config defines no enabled jsonl sink; remote delivery is best-effort with no persistent replay, and events may be lost after retry exhaustion, process exit, or restart"
        );
    }

    Ok(sinks)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::tempdir;
    #[cfg(unix)]
    use tempfile::tempdir_in;

    use super::{
        CliSinkOverrides, DeliveryConfig, SecretValue, SinkKind, SinkSpec, build_sink_set,
        build_sink_set_with_presence_and_delivery_for_platform, load_outputs_config_with_delivery,
    };
    #[cfg(not(windows))]
    use super::{
        ConfigDeliveryPolicy, JsonlSpec, build_sink_set_with_presence_and_delivery_for_validation,
    };
    #[cfg(not(windows))]
    use crate::sink::outbox::{
        CapacityLimits, DEFAULT_MAX_PENDING_BYTES, DEFAULT_MAX_PENDING_EVENTS,
    };
    use crate::sink::{DeliveryError, DeliveryErrorClass};

    fn load_outputs_config(paths: &[PathBuf]) -> Result<Vec<SinkSpec>, Box<dyn std::error::Error>> {
        Ok(load_outputs_config_with_delivery(paths)?.sinks)
    }
    use crate::sink::RotationConfig;

    fn write_outputs(dir: &std::path::Path, file_name: &str, contents: &str) -> PathBuf {
        let path = dir.join(file_name);
        std::fs::write(&path, contents).expect("write outputs yaml");
        path
    }

    #[test]
    fn debug_redacts_inline_secrets_directly_and_when_nested() {
        let secret = "sentinel-inline-secret";
        let direct = format!("{:?}", SecretValue::Inline(secret.to_string()));
        assert!(!direct.contains(secret));

        let dir = tempdir().expect("tempdir");
        let path = write_outputs(
            dir.path(),
            "outputs.yaml",
            &format!(
                "version: 1\nsinks:\n  - name: splunk\n    type: splunk_hec\n    endpoint: http://127.0.0.1:8088\n    token: {secret}\n  - name: elastic\n    type: elastic_bulk\n    endpoint: http://127.0.0.1:9200\n    api_key: {secret}\n"
            ),
        );
        let specs = load_outputs_config(&[path]).expect("outputs");
        let nested = format!("{specs:?}");
        assert!(!nested.contains(secret));
    }

    fn cli_defaults<'a>(log_path: &'a std::path::Path) -> CliSinkOverrides<'a> {
        CliSinkOverrides {
            log_path,
            rotation: RotationConfig::default(),
            splunk_hec_endpoint: None,
            splunk_hec_token: None,
        }
    }

    #[test]
    fn parses_full_outputs_document() {
        let temp = tempdir().expect("tempdir");
        let path = write_outputs(
            temp.path(),
            "outputs.yaml",
            r#"
version: 1
sinks:
  - name: local
    type: jsonl
    path: /var/log/telltale/telltale-events.jsonl
    rotation:
      max_size_bytes: 1048576
      keep: 3
  - name: corp-splunk
    type: splunk_hec
    endpoint: http://splunk.example.com:8088/services/collector
    token: { env: SPLUNK_HEC_TOKEN }
    index: telltale
    sourcetype: telltale:json
    timeout_ms: 5000
  - name: disabled-splunk
    type: splunk_hec
    enabled: false
    endpoint: http://other.example.com:8088
    token: inline-lab-token
"#,
        );

        let specs = load_outputs_config(&[path]).expect("load outputs");

        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0].name, "local");
        assert!(specs[0].enabled);
        assert!(matches!(specs[0].kind, SinkKind::Jsonl(_)));
        assert_eq!(specs[1].name, "corp-splunk");
        let SinkKind::SplunkHec(hec) = &specs[1].kind else {
            panic!("expected splunk_hec kind");
        };
        assert!(matches!(&hec.token, SecretValue::Env { env } if env == "SPLUNK_HEC_TOKEN"));
        assert_eq!(hec.timeout_ms, Some(5000));
        assert!(!specs[2].enabled);
        assert!(specs[2].has_inline_secret());
        assert!(!specs[1].has_inline_secret());
    }

    #[test]
    fn merge_is_last_wins_per_sink_name() {
        let temp = tempdir().expect("tempdir");
        let system = write_outputs(
            temp.path(),
            "50-system.yaml",
            r#"
version: 1
sinks:
  - name: corp-splunk
    type: splunk_hec
    endpoint: http://splunk.example.com:8088
    token: system-token
  - name: local
    type: jsonl
"#,
        );
        let user = write_outputs(
            temp.path(),
            "60-user.yaml",
            r#"
version: 1
sinks:
  - name: corp-splunk
    type: splunk_hec
    enabled: false
    endpoint: http://splunk.example.com:8088
    token: user-token
  - name: extra-jsonl
    type: jsonl
    path: /tmp/extra.jsonl
"#,
        );

        let specs = load_outputs_config(&[system, user]).expect("load outputs");

        // First-seen order, later definition replaces the earlier one.
        assert_eq!(
            specs.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            vec!["corp-splunk", "local", "extra-jsonl"]
        );
        assert!(!specs[0].enabled, "user file disabled corp-splunk");
    }

    #[test]
    fn duplicate_sink_name_in_one_file_is_an_error() {
        let temp = tempdir().expect("tempdir");
        let path = write_outputs(
            temp.path(),
            "outputs.yaml",
            r#"
version: 1
sinks:
  - name: local
    type: jsonl
  - name: local
    type: jsonl
"#,
        );

        let err = load_outputs_config(&[path]).expect_err("duplicate names");
        assert!(err.to_string().contains("duplicate sink name 'local'"));
    }

    #[test]
    fn unknown_sink_type_is_an_error() {
        let temp = tempdir().expect("tempdir");
        let path = write_outputs(
            temp.path(),
            "outputs.yaml",
            "version: 1\nsinks:\n  - name: sys\n    type: syslog\n    endpoint: udp://x\n",
        );

        let err = load_outputs_config(&[path]).expect_err("unknown type");
        assert!(err.to_string().contains("unknown sink type 'syslog'"));
    }

    #[test]
    fn elastic_bulk_spec_parses_and_flags_inline_secrets() {
        let temp = tempdir().expect("tempdir");
        let path = write_outputs(
            temp.path(),
            "outputs.yaml",
            r#"
version: 1
sinks:
  - name: corp-elastic
    type: elastic_bulk
    endpoint: https://elastic.example.com:9243
    index: telltale-events
    api_key: inline-key
    max_batch_bytes: 1048576
    retry: { max_attempts: 5, base_delay_ms: 250 }
    tls: { insecure_skip_verify: true }
"#,
        );

        let specs = load_outputs_config(&[path]).expect("load outputs");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].kind.type_name(), "elastic_bulk");
        assert!(specs[0].has_inline_secret());
        assert!(specs[0].has_insecure_tls());
    }

    #[test]
    fn elastic_bulk_rejects_conflicting_auth() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("telltale-events.jsonl");
        let path = write_outputs(
            temp.path(),
            "outputs.yaml",
            r#"
version: 1
sinks:
  - name: corp-elastic
    type: elastic_bulk
    endpoint: http://elastic.example.com:9200
    api_key: key
    username: user
    password: pass
"#,
        );
        let specs = load_outputs_config(&[path]).expect("load");

        let err = match build_sink_set(&specs, &cli_defaults(&log_path)) {
            Ok(_) => panic!("conflicting auth must error"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("either api_key or username/password")
        );
    }

    #[test]
    fn unknown_field_is_an_error() {
        let temp = tempdir().expect("tempdir");
        let path = write_outputs(
            temp.path(),
            "outputs.yaml",
            "version: 1\nsinks:\n  - name: local\n    type: jsonl\n    pth: /tmp/x.jsonl\n",
        );

        let err = load_outputs_config(&[path]).expect_err("unknown field");
        let message = err.to_string();
        assert!(message.contains("sink 'local'"), "message: {message}");
        assert!(message.contains("pth"), "message: {message}");
    }

    #[test]
    fn unsupported_version_is_an_error() {
        let temp = tempdir().expect("tempdir");
        let path = write_outputs(temp.path(), "outputs.yaml", "version: 2\nsinks: []\n");

        let err = load_outputs_config(&[path]).expect_err("bad version");
        assert!(err.to_string().contains("version 2 is not supported"));
    }

    #[test]
    fn secret_resolution_covers_inline_env_and_file() {
        let inline = SecretValue::Inline("inline-token".to_string());
        assert_eq!(inline.resolve("test").expect("inline"), "inline-token");

        // SAFETY: test-only env mutation; key is unique to this test.
        unsafe { std::env::set_var("TELLTALE_TEST_SINK_SECRET", "env-token") };
        let env = SecretValue::Env {
            env: "TELLTALE_TEST_SINK_SECRET".to_string(),
        };
        assert_eq!(env.resolve("test").expect("env"), "env-token");
        unsafe { std::env::remove_var("TELLTALE_TEST_SINK_SECRET") };
        assert!(env.resolve("test").is_err(), "unset env must error");

        let temp = tempdir().expect("tempdir");
        let secret_path = temp.path().join("hec-token");
        std::fs::write(&secret_path, "file-token\n").expect("write secret");
        let file = SecretValue::File {
            file: secret_path.clone(),
        };
        // Trailing newline is trimmed.
        assert_eq!(file.resolve("test").expect("file"), "file-token");

        let missing = SecretValue::File {
            file: temp.path().join("missing"),
        };
        assert!(missing.resolve("test").is_err(), "missing file must error");
    }

    #[test]
    fn empty_specs_reproduce_legacy_default_sinks() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("telltale-events.jsonl");

        let sinks = build_sink_set(&[], &cli_defaults(&log_path)).expect("build");
        assert!(sinks.has_canonical_first_write());

        let mut cli = cli_defaults(&log_path);
        cli.splunk_hec_endpoint = Some("http://127.0.0.1:8088");
        let err = match build_sink_set(&[], &cli) {
            Ok(_) => panic!("endpoint without token must error"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("--splunk-hec-endpoint and --splunk-hec-token must be set together")
        );
    }

    #[test]
    fn build_resolves_env_secret_and_honors_disabled_sinks() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("telltale-events.jsonl");
        let path = write_outputs(
            temp.path(),
            "outputs.yaml",
            r#"
version: 1
sinks:
  - name: local
    type: jsonl
  - name: corp-splunk
    type: splunk_hec
    enabled: false
    endpoint: http://splunk.example.com:8088
    token: { env: TELLTALE_TEST_UNSET_TOKEN_VAR }
"#,
        );
        let specs = load_outputs_config(&[path]).expect("load");

        // The disabled sink's secret must not be resolved: no error.
        let sinks = build_sink_set(&specs, &cli_defaults(&log_path)).expect("build");
        assert!(sinks.has_canonical_first_write());
    }

    #[test]
    fn build_fails_fast_on_missing_env_secret_for_enabled_sink() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("telltale-events.jsonl");
        let path = write_outputs(
            temp.path(),
            "outputs.yaml",
            r#"
version: 1
sinks:
  - name: corp-splunk
    type: splunk_hec
    endpoint: http://splunk.example.com:8088
    token: { env: TELLTALE_TEST_UNSET_TOKEN_VAR }
"#,
        );
        let specs = load_outputs_config(&[path]).expect("load");

        let err = match build_sink_set(&specs, &cli_defaults(&log_path)) {
            Ok(_) => panic!("missing env secret must error"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("TELLTALE_TEST_UNSET_TOKEN_VAR"));
    }

    #[test]
    fn simulated_windows_durable_config_is_rejected_before_outbox_initialization() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");
        let path = write_outputs(
            temp.path(),
            "durable-windows.yaml",
            &format!(
                "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}\nsinks:\n  - name: canonical\n    type: jsonl\n",
                outbox_path.display()
            ),
        );
        let loaded = load_outputs_config_with_delivery(&[path]).expect("load durable config");

        let error = match build_sink_set_with_presence_and_delivery_for_platform(
            &loaded.sinks,
            true,
            &CliSinkOverrides {
                log_path: &log_path,
                rotation: RotationConfig::disabled(),
                splunk_hec_endpoint: None,
                splunk_hec_token: None,
            },
            &loaded.delivery,
            false,
            true,
        ) {
            Ok(_) => panic!("Windows durable config must be rejected"),
            Err(error) => error,
        };
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("platform rejection must be structured");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(
            error
                .to_string()
                .contains(crate::sink::outbox::WINDOWS_DURABLE_STORAGE_UNSUPPORTED)
        );
        assert!(!outbox_path.parent().expect("outbox parent").exists());
        assert!(!outbox_path.exists());
        assert!(!log_path.exists());
    }

    #[test]
    fn simulated_windows_best_effort_configuration_remains_valid() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("best-effort.jsonl");
        let sinks = build_sink_set_with_presence_and_delivery_for_platform(
            &[],
            false,
            &cli_defaults(&log_path),
            &DeliveryConfig::default(),
            false,
            true,
        )
        .expect("Windows best-effort configuration");
        assert!(sinks.has_canonical_first_write());
        assert!(!sinks.has_persistent_replay());
    }

    #[cfg(unix)]
    fn pure_durable_sink_set(
        log_path: &std::path::Path,
        outbox_path: &std::path::Path,
    ) -> Result<crate::sink::SinkSet, Box<dyn std::error::Error>> {
        let specs = [SinkSpec {
            name: "canonical".to_string(),
            enabled: true,
            kind: SinkKind::Jsonl(JsonlSpec {
                path: Some(log_path.to_path_buf()),
                rotation: None,
            }),
            origin_path: None,
        }];
        let delivery = DeliveryConfig {
            policy: ConfigDeliveryPolicy::Durable,
            outbox_path: Some(outbox_path.to_path_buf()),
            capacity_limits: CapacityLimits::default(),
        };
        build_sink_set_with_presence_and_delivery_for_validation(
            &specs,
            true,
            &cli_defaults(log_path),
            &delivery,
            false,
        )
    }

    #[cfg(unix)]
    #[test]
    fn pure_durable_validation_rejects_nonexistent_lexical_alias_without_artifacts() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("journal").join("events.jsonl");
        let outbox_path = temp
            .path()
            .join("missing")
            .join("..")
            .join("journal")
            .join("events.jsonl");

        let error = match pure_durable_sink_set(&log_path, &outbox_path) {
            Err(error) => error,
            Ok(_) => panic!("lexical durable path alias must be rejected"),
        };
        assert!(error.to_string().contains("collides"), "error: {error}");
        assert!(!log_path.exists());
        assert!(!outbox_path.parent().expect("outbox parent").exists());
    }

    #[cfg(unix)]
    #[test]
    fn pure_durable_validation_rejects_relative_absolute_alias_without_artifacts() {
        let working_dir = std::env::current_dir().expect("working directory");
        let temp = tempdir_in(&working_dir).expect("temporary directory");
        let absolute_path = temp.path().join("events.jsonl");
        let relative_root = temp
            .path()
            .strip_prefix(&working_dir)
            .expect("temporary directory under working directory");
        let relative_path = relative_root.join("events.jsonl");

        let error = match pure_durable_sink_set(&absolute_path, &relative_path) {
            Err(error) => error,
            Ok(_) => panic!("relative/absolute durable path alias must be rejected"),
        };
        assert!(error.to_string().contains("collides"), "error: {error}");
        assert!(!absolute_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn pure_durable_validation_rejects_symlink_parent_alias_without_artifacts() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir");
        let real_parent = temp.path().join("real");
        let alias_parent = temp.path().join("alias");
        std::fs::create_dir(&real_parent).expect("real parent");
        symlink(&real_parent, &alias_parent).expect("symlink parent");
        let log_path = real_parent.join("events.jsonl");
        let outbox_path = alias_parent.join("events.jsonl");

        let error = match pure_durable_sink_set(&log_path, &outbox_path) {
            Err(error) => error,
            Ok(_) => panic!("symlink-parent durable path alias must be rejected"),
        };
        assert!(error.to_string().contains("collides"), "error: {error}");
        assert!(!log_path.exists());
        assert!(!outbox_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn pure_durable_validation_rejects_existing_symlink_leaf_alias_without_opening_outbox() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = temp.path().join("outbox.sqlite");
        std::fs::write(&log_path, b"synthetic JSONL fixture\n").expect("log fixture");
        symlink(&log_path, &outbox_path).expect("symlink leaf fixture");

        let error = match pure_durable_sink_set(&log_path, &outbox_path) {
            Err(error) => error,
            Ok(_) => panic!("symlink-leaf durable path alias must be rejected"),
        };
        assert!(error.to_string().contains("collides"), "error: {error}");
        assert_eq!(
            std::fs::read(&log_path).expect("read log fixture"),
            b"synthetic JSONL fixture\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pure_durable_validation_rejects_existing_hard_link_alias_without_opening_outbox() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = temp.path().join("outbox.sqlite");
        std::fs::write(&log_path, b"synthetic durable path fixture\n").expect("log fixture");
        std::fs::hard_link(&log_path, &outbox_path).expect("hard-link fixture");

        let before = std::fs::read(&log_path).expect("read log fixture");
        let error = match pure_durable_sink_set(&log_path, &outbox_path) {
            Err(error) => error,
            Ok(_) => panic!("hard-linked durable paths must be rejected"),
        };
        assert!(error.to_string().contains("collides"), "error: {error}");
        assert_eq!(
            std::fs::read(&outbox_path).expect("read outbox fixture"),
            before
        );
    }

    #[cfg(unix)]
    #[test]
    fn pure_durable_validation_accepts_distinct_paths_without_activation() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");

        let sinks = pure_durable_sink_set(&log_path, &outbox_path).expect("distinct paths");
        assert!(sinks.has_persistent_replay());
        assert!(!outbox_path.exists());
        assert!(!log_path.exists());
        assert!(!outbox_path.parent().expect("outbox parent").exists());
    }

    #[cfg(unix)]
    #[test]
    fn pure_durable_validation_rejects_delete_journal_sidecar_alias() {
        let temp = tempdir().expect("tempdir");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");
        let log_path = temp.path().join("private").join("outbox.sqlite-journal");

        let error = match pure_durable_sink_set(&log_path, &outbox_path) {
            Err(error) => error,
            Ok(_) => panic!("SQLite rollback journal alias must be rejected"),
        };
        assert!(error.to_string().contains("journal"), "error: {error}");
        assert!(!outbox_path.parent().expect("outbox parent").exists());
    }

    #[cfg(unix)]
    #[test]
    fn pure_durable_validation_rejects_jsonl_coordination_sidecar_alias() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = temp.path().join("events.jsonl.lock");

        let error = match pure_durable_sink_set(&log_path, &outbox_path) {
            Err(error) => error,
            Ok(_) => panic!("JSONL coordination sidecar alias must be rejected"),
        };
        assert!(error.to_string().contains("sidecar"), "error: {error}");
        assert!(!outbox_path.exists());
    }

    #[cfg(not(windows))]
    #[test]
    fn durable_mode_requires_canonical_jsonl_and_private_outbox() {
        let temp = tempdir().expect("tempdir");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");
        let path = write_outputs(
            temp.path(),
            "durable.yaml",
            &format!(
                "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}\nsinks:\n  - name: canonical\n    type: jsonl\n  - name: remote-a\n    type: splunk_hec\n    endpoint: https://collector.example.invalid/collector\n    token: {{ env: TELLTALE_TEST_DURABLE_TOKEN }}\n",
                outbox_path.display()
            ),
        );
        let loaded = load_outputs_config_with_delivery(&[path]).expect("load durable config");
        // SAFETY: test-only env mutation; key is unique to this test.
        unsafe { std::env::set_var("TELLTALE_TEST_DURABLE_TOKEN", "synthetic-token") };
        let sinks = super::build_sink_set_with_presence_and_delivery(
            &loaded.sinks,
            true,
            &CliSinkOverrides {
                log_path: &log_path,
                rotation: RotationConfig::disabled(),
                splunk_hec_endpoint: None,
                splunk_hec_token: None,
            },
            &loaded.delivery,
            false,
        )
        .expect("durable config");
        unsafe { std::env::remove_var("TELLTALE_TEST_DURABLE_TOKEN") };

        assert!(sinks.has_persistent_replay());
        assert!(sinks.durable_sink_ids().contains(&"remote-a".to_string()));
        assert!(outbox_path.is_file());
        assert_eq!(
            sinks.delivery_posture(),
            crate::sink::DeliveryPosture::DurableFirstWrite
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn durable_mode_without_jsonl_is_rejected_without_forcing_a_local_sink() {
        let temp = tempdir().expect("tempdir");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");
        let path = write_outputs(
            temp.path(),
            "durable-remote-only.yaml",
            &format!(
                "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}\nsinks:\n  - name: remote-a\n    type: splunk_hec\n    endpoint: https://collector.example.invalid/collector\n    token: synthetic-token\n",
                outbox_path.display()
            ),
        );
        let loaded = load_outputs_config_with_delivery(&[path]).expect("load durable config");
        let result = super::build_sink_set_with_presence_and_delivery(
            &loaded.sinks,
            true,
            &CliSinkOverrides {
                log_path: temp.path().join("events.jsonl").as_path(),
                rotation: RotationConfig::disabled(),
                splunk_hec_endpoint: None,
                splunk_hec_token: None,
            },
            &loaded.delivery,
            false,
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("durable remote-only config must fail"),
        };
        assert!(error.to_string().contains("requires canonical JSONL"));
    }

    #[cfg(not(windows))]
    #[test]
    fn durable_mode_retains_existing_tls_validation() {
        let temp = tempdir().expect("tempdir");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");
        let path = write_outputs(
            temp.path(),
            "durable-invalid-tls.yaml",
            &format!(
                "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}\nsinks:\n  - name: canonical\n    type: jsonl\n  - name: remote-a\n    type: splunk_hec\n    endpoint: https://collector.example.invalid/collector\n    token: synthetic-token\n    tls:\n      ca_file: {}/missing-ca.pem\n",
                outbox_path.display(),
                temp.path().display()
            ),
        );
        let loaded = load_outputs_config_with_delivery(&[path]).expect("load durable config");
        let log_path = temp.path().join("events.jsonl");
        let result = super::build_sink_set_with_presence_and_delivery(
            &loaded.sinks,
            true,
            &CliSinkOverrides {
                log_path: &log_path,
                rotation: RotationConfig::disabled(),
                splunk_hec_endpoint: None,
                splunk_hec_token: None,
            },
            &loaded.delivery,
            false,
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("missing TLS CA must fail in durable mode"),
        };
        assert!(error.to_string().contains("ca_file"));
    }

    #[cfg(not(windows))]
    #[test]
    fn durable_capacity_defaults_and_yaml_overrides_are_loaded() {
        let temp = tempdir().expect("tempdir");
        let default_path = write_outputs(
            temp.path(),
            "default.yaml",
            &format!(
                "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}/outbox.sqlite\nsinks: []\n",
                temp.path().display()
            ),
        );
        let defaults = load_outputs_config_with_delivery(&[default_path])
            .expect("default durable config")
            .delivery;
        assert_eq!(defaults.policy, ConfigDeliveryPolicy::Durable);
        assert_eq!(
            defaults.capacity_limits,
            CapacityLimits {
                max_pending_events: DEFAULT_MAX_PENDING_EVENTS,
                max_pending_bytes: DEFAULT_MAX_PENDING_BYTES,
            }
        );

        let override_path = write_outputs(
            temp.path(),
            "override.yaml",
            &format!(
                "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}/outbox.sqlite\n  max_pending_events: 7\n  max_pending_bytes: 4096\nsinks: []\n",
                temp.path().display()
            ),
        );
        let overrides = load_outputs_config_with_delivery(&[override_path])
            .expect("overridden durable config")
            .delivery;
        assert_eq!(
            overrides.capacity_limits,
            CapacityLimits {
                max_pending_events: 7,
                max_pending_bytes: 4096,
            }
        );
    }

    #[test]
    fn zero_capacity_and_best_effort_capacity_fields_are_rejected() {
        let temp = tempdir().expect("tempdir");
        for field in ["max_pending_events", "max_pending_bytes"] {
            let path = write_outputs(
                temp.path(),
                &format!("zero-{field}.yaml"),
                &format!(
                    "version: 1\ndelivery:\n  policy: durable\n  outbox_path: {}/outbox.sqlite\n  {field}: 0\nsinks: []\n",
                    temp.path().display()
                ),
            );
            let error = match load_outputs_config_with_delivery(&[path]) {
                Ok(_) => panic!("zero durable capacity must be rejected"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("must be greater than zero"));
        }

        let path = write_outputs(
            temp.path(),
            "best-effort-capacity.yaml",
            "version: 1\ndelivery:\n  policy: best_effort\n  max_pending_events: 1\nsinks: []\n",
        );
        let error = match load_outputs_config_with_delivery(&[path]) {
            Ok(_) => panic!("best-effort capacity fields must be rejected"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("best-effort delivery cannot configure durable capacity limits")
        );
    }
}
