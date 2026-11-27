//! Outputs configuration: sink specifications, endpoint and credential
//! validation, retry and TLS options, and durable delivery capacity.

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

    pub fn allows_insecure_http(&self) -> bool {
        let tls = match &self.kind {
            SinkKind::Jsonl(_) => &None,
            SinkKind::SplunkHec(spec) => &spec.tls,
            SinkKind::ElasticBulk(spec) => &spec.tls,
        };
        tls.as_ref().is_some_and(|tls| tls.allow_insecure_http)
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
    #[serde(default)]
    pub allow_insecure_http: bool,
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
            allow_insecure_http: spec.allow_insecure_http,
        },
    }
}

fn validate_http_endpoint(
    sink_name: &str,
    endpoint: &str,
    allow_insecure_http: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    super::http::validate_endpoint(endpoint, allow_insecure_http)
        .map(|_| ())
        .map_err(|reason| format!("sink '{sink_name}': {reason}").into())
}

#[test]
fn endpoints_reject_remote_plaintext_and_embedded_credentials() {
    for endpoint in [
        "http://collector.example.invalid/ingest",
        "https://user:synthetic@collector.example.invalid/ingest",
        "https://collector.example.invalid/ingest#fragment",
    ] {
        assert!(
            validate_http_endpoint("synthetic", endpoint, false).is_err(),
            "{endpoint}"
        );
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
                    validate_http_endpoint(
                        &spec.name,
                        &hec.endpoint,
                        hec.tls.as_ref().is_some_and(|tls| tls.allow_insecure_http),
                    )?;
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
                    validate_http_endpoint(
                        &spec.name,
                        &elastic.endpoint,
                        elastic
                            .tls
                            .as_ref()
                            .is_some_and(|tls| tls.allow_insecure_http),
                    )?;
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
        validate_http_endpoint(CLI_SPLUNK_HEC_SINK_NAME, endpoint, false)?;
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
mod tests;
