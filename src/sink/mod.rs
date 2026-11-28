//! Event delivery. A sink has an identity, a transport, a delivery policy
//! (best effort or durable) and a persistence role. Sinks serialize already
//! privacy-safe canonical Event 3.0 bytes; they never repair or reshape event
//! content. Vendor envelopes wrap the canonical payload.

pub mod config;
mod elastic;
pub mod http;
mod jsonl;
pub(crate) mod outbox;
mod splunk_hec;
#[cfg(test)]
mod test_support;

pub(crate) use elastic::{DEFAULT_ELASTIC_INDEX, ElasticBulkSink, elastic_bulk_action_json};
pub(crate) use jsonl::{LocalJsonlSink, RotationConfig};
pub(crate) use splunk_hec::{SplunkHecConfig, SplunkHecHttpSink};

use crate::event::{Event, PrivacySanitizer, SanitizationContext};
use crate::file_lock::RotationNamespace;
use crate::sink::http::RetryConfig;

/// Delivery reliability is a policy, not a property of the transport or its
/// location. `Durable` uses the persistent downstream dispatcher;
/// `BestEffort` delivers without persistent replay.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum DeliveryPolicy {
    BestEffort,
    Durable,
}

/// The persistence responsibility associated with a sink. A canonical event
/// log is a first-write record; downstream delivery state is a separate role.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum PersistenceRole {
    None,
    CanonicalFirstWrite,
    DeliveryState,
}

/// Stable classification for delivery failures. Callers can make retry or
/// operator-action decisions without interpreting a human diagnostic.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum DeliveryErrorClass {
    TransportNoResponse,
    Timeout,
    HttpStatus { status: u16 },
    SinkApplicationRejected,
    SinkApplicationRetryable,
    SinkResponseBlocked,
    AuthenticationBlocked { status: u16 },
    PayloadCollision,
    DurableStorage,
    UnknownInternal,
}

impl DeliveryErrorClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::TransportNoResponse => "transport_no_response",
            Self::Timeout => "timeout",
            Self::HttpStatus { .. } => "http_status",
            Self::SinkApplicationRejected => "sink_application_rejected",
            Self::SinkApplicationRetryable => "sink_application_retryable",
            Self::SinkResponseBlocked => "sink_response_blocked",
            Self::AuthenticationBlocked { .. } => "authentication_blocked",
            Self::PayloadCollision => "payload_collision",
            Self::DurableStorage => "durable_storage",
            Self::UnknownInternal => "unknown_internal",
        }
    }

    /// Retryability is derived from the structured class/status, never from
    /// the diagnostic text. The current HTTP transport retries 429 and 5xx;
    /// 408 is included for the durable scheduler's one-attempt contract.
    pub(crate) fn is_retryable(self) -> bool {
        match self {
            Self::TransportNoResponse | Self::Timeout | Self::SinkApplicationRetryable => true,
            Self::HttpStatus { status } => {
                status == 408 || status == 429 || (500..600).contains(&status)
            }
            Self::SinkApplicationRejected
            | Self::SinkResponseBlocked
            | Self::AuthenticationBlocked { .. }
            | Self::PayloadCollision
            | Self::DurableStorage
            | Self::UnknownInternal => false,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum DeliveryPosture {
    DurableFirstWrite,
    BestEffortNoReplay,
    NoEnabledSinks,
}

impl DeliveryPosture {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DurableFirstWrite => "durable_first_write",
            Self::BestEffortNoReplay => "best_effort_no_replay",
            Self::NoEnabledSinks => "no_enabled_sinks",
        }
    }

    pub(crate) fn has_durable_first_write(self) -> bool {
        matches!(self, Self::DurableFirstWrite)
    }
}

pub(crate) trait EventSink {
    /// Operator-facing sink name, used in delivery-failure alerts and logs.
    fn name(&self) -> &str;
    fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>>;

    /// Deliver one already-terminal Event 3.0 payload with exactly one
    /// transport attempt. Durable dispatch uses this method so retry timing
    /// and attempt accounting stay in the outbox. Sinks that do not implement
    /// a canonical transport cannot accidentally fall back to in-memory retry.
    fn emit_canonical_once(&self, _payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        Err(DeliveryError::new(
            DeliveryErrorClass::UnknownInternal,
            1,
            "sink does not support canonical durable delivery",
        )
        .into())
    }

    /// Append already-terminal, newline-delimited Event 3.0 bytes to a
    /// canonical first-write sink. Durable replay uses this after its
    /// read-only capacity check so serialization cannot change between the
    /// check and the append.
    fn emit_canonical_jsonl_bytes(&self, _bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        Err(DeliveryError::new(
            DeliveryErrorClass::DurableStorage,
            0,
            "canonical first-write sink does not accept serialized JSONL bytes",
        )
        .into())
    }
}

#[cfg(test)]
fn emit_events(sink: &dyn EventSink, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
    sink.emit(events)
}

/// A delivery failure on a non-durable sink, reported back to the caller so it
/// can emit an operational alert and continue.
#[derive(Debug, Clone)]
pub(crate) struct SinkFailure {
    pub name: String,
    pub kind: String,
    pub class: DeliveryErrorClass,
    pub attempts: u32,
    pub error: String,
    /// Attempts already stored on a durable row before this attempt.
    /// `release_blocked_for_sink` preserves that count. Best-effort failures
    /// have no preserved outbox history.
    pub prior_attempts: u32,
    /// Structured error already stored on a durable row before this attempt.
    pub prior_error_class: Option<DeliveryErrorClass>,
}

/// Structured error type sinks return from `emit`. The message is only a
/// bounded operator diagnostic; behavior must use `class` instead.
#[derive(Debug)]
pub(crate) struct DeliveryError {
    pub class: DeliveryErrorClass,
    pub attempts: u32,
    pub message: String,
}

impl DeliveryError {
    pub(crate) fn new(
        class: DeliveryErrorClass,
        attempts: u32,
        message: impl Into<String>,
    ) -> Self {
        let message = PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &message.into());
        Self {
            class,
            attempts,
            message,
        }
    }
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (after {} attempts)", self.message, self.attempts)
    }
}

impl std::error::Error for DeliveryError {}

fn delivery_error_details(
    error: &(dyn std::error::Error + 'static),
) -> (DeliveryErrorClass, String) {
    if let Some(delivery) = error.downcast_ref::<DeliveryError>() {
        return (
            delivery.class,
            PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &delivery.message),
        );
    }
    (
        DeliveryErrorClass::UnknownInternal,
        PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &error.to_string()),
    )
}

struct SinkEntry {
    sink: Box<dyn EventSink + Send + Sync>,
    transport: &'static str,
    persistence_path: Option<std::path::PathBuf>,
    rotation_namespace: Option<RotationNamespace>,
    rotation_keep: Option<usize>,
    delivery_policy: DeliveryPolicy,
    persistence_role: PersistenceRole,
    retry: RetryConfig,
}

/// The ordered set of sinks a scan delivers events to.
#[derive(Default)]
pub(crate) struct SinkSet {
    entries: Vec<SinkEntry>,
    durable_outbox_path: Option<std::path::PathBuf>,
    durable_sink_ids: Vec<String>,
    durable_capacity_limits: outbox::CapacityLimits,
    durable_replay_active: bool,
    #[cfg(test)]
    durable_capacity_scan_limit: Option<u64>,
}

impl SinkSet {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn enable_persistent_replay_with_capacity(
        &mut self,
        outbox_path: std::path::PathBuf,
        sink_ids: Vec<String>,
        capacity_limits: outbox::CapacityLimits,
    ) {
        for entry in &mut self.entries {
            if sink_ids.iter().any(|sink_id| sink_id == entry.sink.name()) {
                entry.delivery_policy = DeliveryPolicy::Durable;
                entry.persistence_role = PersistenceRole::DeliveryState;
            }
        }
        self.durable_outbox_path = Some(outbox_path);
        self.durable_sink_ids = sink_ids;
        self.durable_capacity_limits = capacity_limits;
        self.durable_replay_active = false;
    }

    /// Activate persistent replay after pure sink/configuration validation.
    /// Scan/watch activate only after command guards; validation and dry-run
    /// construction deliberately do not activate.
    pub(crate) fn activate_persistent_replay(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.durable_outbox_path.is_none() {
            return Ok(());
        }
        self.validate_persistent_replay_paths()?;
        outbox::ensure_durable_storage_supported()?;
        let outbox_path = self
            .durable_outbox_path
            .as_ref()
            .ok_or("durable outbox path is missing")?;
        let _outbox = outbox::Outbox::open(outbox_path)?;
        self.durable_replay_active = true;
        Ok(())
    }

    #[cfg(all(test, not(windows)))]
    pub(crate) fn set_durable_capacity_scan_limit(&mut self, limit: u64) {
        self.durable_capacity_scan_limit = Some(limit);
    }

    pub(crate) fn has_persistent_replay(&self) -> bool {
        self.durable_outbox_path.is_some()
    }

    /// Return metadata-only durable queue health. The unavailable shape keeps
    /// scan summaries useful when the bounded read-only lookup cannot open a
    /// locked, corrupt, or otherwise inaccessible outbox.
    pub(crate) fn durable_health_json(&self) -> serde_json::Value {
        let Some(outbox_path) = self.durable_outbox_path.as_ref() else {
            return serde_json::json!({
                "mode": "not_configured",
                "sinks": {},
            });
        };
        if !self.durable_replay_active {
            return serde_json::json!({
                "mode": "not_activated",
                "sinks": {},
            });
        }
        let sink_ids = self
            .durable_sink_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        durable_health_json_from_path(outbox_path, &sink_ids)
    }

    fn validate_persistent_replay_paths(&self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(outbox_path) = self.durable_outbox_path.as_ref() else {
            return Ok(());
        };
        let paths = self.local_persistence_paths();
        if paths.is_empty() {
            // Some internal dispatch tests construct only the downstream
            // transport. Configuration activation rejects this shape before a
            // real durable writer can use it.
            outbox::validate_outbox_path_without_activation(outbox_path)?;
            return Ok(());
        }
        if paths.len() != 1 {
            return Err(DeliveryError::new(
                DeliveryErrorClass::DurableStorage,
                0,
                "durable downstream delivery requires exactly one canonical JSONL path",
            )
            .into());
        }
        outbox::validate_outbox_jsonl_paths(outbox_path, &paths[0])?;
        outbox::validate_outbox_path_without_activation(outbox_path)
    }

    pub(crate) fn delivery_sink_ids(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.persistence_role != PersistenceRole::CanonicalFirstWrite)
            .map(|entry| entry.sink.name().to_string())
            .collect()
    }

    pub(crate) fn durable_sink_ids(&self) -> &[String] {
        &self.durable_sink_ids
    }

    fn add_with_roles(
        &mut self,
        transport: &'static str,
        sink: Box<dyn EventSink + Send + Sync>,
        delivery_policy: DeliveryPolicy,
        persistence_role: PersistenceRole,
    ) {
        self.add_with_roles_and_retry(
            transport,
            sink,
            delivery_policy,
            persistence_role,
            RetryConfig::default(),
        );
    }

    fn add_with_roles_and_retry(
        &mut self,
        transport: &'static str,
        sink: Box<dyn EventSink + Send + Sync>,
        delivery_policy: DeliveryPolicy,
        persistence_role: PersistenceRole,
        retry: RetryConfig,
    ) {
        self.entries.push(SinkEntry {
            sink,
            transport,
            persistence_path: None,
            rotation_namespace: None,
            rotation_keep: None,
            delivery_policy,
            persistence_role,
            retry,
        });
    }

    #[cfg(test)]
    pub(crate) fn add_canonical_first_write(
        &mut self,
        transport: &'static str,
        sink: Box<dyn EventSink + Send + Sync>,
    ) {
        self.add_with_roles(
            transport,
            sink,
            DeliveryPolicy::BestEffort,
            PersistenceRole::CanonicalFirstWrite,
        );
    }

    pub(crate) fn add_canonical_first_write_path_with_rotation(
        &mut self,
        transport: &'static str,
        sink: Box<dyn EventSink + Send + Sync>,
        path: impl Into<std::path::PathBuf>,
        rotation_namespace: Option<RotationNamespace>,
    ) {
        self.add_canonical_first_write_path_with_rotation_and_keep(
            transport,
            sink,
            path,
            rotation_namespace,
            None,
        );
    }

    pub(crate) fn add_canonical_first_write_path_with_rotation_and_keep(
        &mut self,
        transport: &'static str,
        sink: Box<dyn EventSink + Send + Sync>,
        path: impl Into<std::path::PathBuf>,
        rotation_namespace: Option<RotationNamespace>,
        rotation_keep: Option<usize>,
    ) {
        self.entries.push(SinkEntry {
            sink,
            transport,
            persistence_path: Some(path.into()),
            rotation_namespace,
            rotation_keep,
            delivery_policy: DeliveryPolicy::BestEffort,
            persistence_role: PersistenceRole::CanonicalFirstWrite,
            retry: RetryConfig::default(),
        });
    }

    pub(crate) fn add_best_effort(
        &mut self,
        transport: &'static str,
        sink: Box<dyn EventSink + Send + Sync>,
    ) {
        self.add_with_roles(
            transport,
            sink,
            DeliveryPolicy::BestEffort,
            PersistenceRole::None,
        );
    }

    pub(crate) fn add_best_effort_with_retry(
        &mut self,
        transport: &'static str,
        sink: Box<dyn EventSink + Send + Sync>,
        retry: RetryConfig,
    ) {
        self.add_with_roles_and_retry(
            transport,
            sink,
            DeliveryPolicy::BestEffort,
            PersistenceRole::None,
            retry,
        );
    }

    pub(crate) fn local_persistence_paths(&self) -> Vec<std::path::PathBuf> {
        self.entries
            .iter()
            .filter_map(|entry| entry.persistence_path.clone())
            .collect()
    }

    pub(crate) fn durable_outbox_path(&self) -> Option<&std::path::Path> {
        self.durable_outbox_path.as_deref()
    }

    pub(crate) fn local_rotation_namespaces(&self) -> Vec<RotationNamespace> {
        self.entries
            .iter()
            .filter_map(|entry| entry.rotation_namespace.clone())
            .collect()
    }

    /// Prune durable JSONL generations only after reconciliation and durable
    /// dispatch have completed. Cleanup is fail-safe and never changes the
    /// scan result when storage is uncertain.
    pub(crate) fn prune_durable_rotations(&self) {
        let Some(outbox_path) = self.durable_outbox_path.as_ref() else {
            return;
        };
        if let Err(error) = self.validate_persistent_replay_paths() {
            let rendered = format!("warning: durable JSONL pruning skipped: {error}");
            eprintln!(
                "{}",
                PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &rendered)
            );
            return;
        }
        let mut outbox = match outbox::Outbox::open(outbox_path) {
            Ok(outbox) => outbox,
            Err(error) => {
                let rendered =
                    format!("warning: could not open durable outbox for JSONL pruning: {error}");
                eprintln!(
                    "{}",
                    PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &rendered)
                );
                return;
            }
        };
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.persistence_role == PersistenceRole::CanonicalFirstWrite)
        {
            let (Some(path), Some(keep)) = (&entry.persistence_path, entry.rotation_keep) else {
                continue;
            };
            let report = outbox.prune_eligible_rotations(path, keep);
            for warning in report.warnings {
                eprintln!("warning: durable JSONL pruning: {warning}");
            }
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn has_canonical_first_write(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.persistence_role == PersistenceRole::CanonicalFirstWrite)
    }

    pub(crate) fn delivery_posture(&self) -> DeliveryPosture {
        if self.entries.is_empty() {
            DeliveryPosture::NoEnabledSinks
        } else if self.has_canonical_first_write() {
            DeliveryPosture::DurableFirstWrite
        } else {
            DeliveryPosture::BestEffortNoReplay
        }
    }

    /// Deliver a batch to every sink. Persistent replay commits the canonical
    /// first write before downstream delivery; otherwise this preserves the
    /// existing best-effort ordering. The scan runs these steps itself, with
    /// its state install between them, so this sequence serves the tests,
    /// which do not build on Windows.
    #[cfg(all(test, not(windows)))]
    pub(crate) fn deliver(
        &self,
        events: &[Event],
    ) -> Result<Vec<SinkFailure>, Box<dyn std::error::Error>> {
        if self.has_persistent_replay() {
            let mut failures = self.persist_for_durable_replay_with_failures(events)?;
            failures.extend(self.deliver_durable()?);
            failures.extend(self.deliver_best_effort(events)?);
            return Ok(failures);
        }
        self.deliver_best_effort(events)
    }

    /// Commit canonical JSONL and reconcile it into the durable outbox. Existing
    /// ready work is dispatched before the prospective capacity check so an
    /// endpoint recovery can release queue capacity without a restart. The
    /// returned failures are only from that pre-admission drain; the newly
    /// admitted batch is dispatched by the caller's normal delivery step. An
    /// empty batch performs recovery and ready-work dispatch only, without a
    /// prospective capacity check or canonical append.
    pub(crate) fn persist_for_durable_replay(
        &self,
        events: &[Event],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.persist_for_durable_replay_with_failures(events)
            .map(|_| ())
    }

    pub(crate) fn persist_for_durable_replay_with_failures(
        &self,
        events: &[Event],
    ) -> Result<Vec<SinkFailure>, Box<dyn std::error::Error>> {
        self.persist_for_durable_replay_with_failures_for_platform(
            events,
            outbox::current_platform_is_windows(),
        )
    }

    fn persist_for_durable_replay_with_failures_for_platform(
        &self,
        events: &[Event],
        is_windows: bool,
    ) -> Result<Vec<SinkFailure>, Box<dyn std::error::Error>> {
        if !self.has_persistent_replay() {
            return Ok(Vec::new());
        }
        outbox::ensure_durable_storage_supported_for_platform(is_windows)?;
        let batch = outbox::event3_durable_batch(events)?;
        let paths = self.local_persistence_paths();
        if paths.len() != 1 {
            return Err(DeliveryError::new(
                DeliveryErrorClass::DurableStorage,
                0,
                "durable replay requires exactly one canonical JSONL path",
            )
            .into());
        }
        let log_path = &paths[0];
        let Some(outbox_path) = self.durable_outbox_path.as_ref() else {
            return Ok(Vec::new());
        };
        self.validate_persistent_replay_paths()?;
        // The outbox sidecar is the admission owner for this JSONL/outbox pair.
        // It is held across recovery, capacity inspection, the canonical append,
        // and the follow-up reconciliation so two Telltale writers cannot both
        // admit against the same observed headroom.
        let admission_lock = outbox::acquire_admission_lock(outbox_path).map_err(|error| {
            Box::new(DeliveryError::new(
                DeliveryErrorClass::DurableStorage,
                0,
                format!("durable capacity admission lock unavailable: {error}"),
            )) as Box<dyn std::error::Error>
        })?;
        let mut outbox = outbox::Outbox::open(outbox_path)?;
        #[cfg(test)]
        if let Some(limit) = self.durable_capacity_scan_limit {
            outbox.set_capacity_scan_limit(limit);
        }
        let sink_ids = self
            .durable_sink_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();

        // Already synchronized JSONL is recovery input, not a prospective
        // acceptance. Reconcile it before applying the bounded capacity scan
        // so a crash gap cannot be mistaken for an uninspectable new batch.
        outbox.reconcile_jsonl(log_path, &sink_ids)?;

        // Dispatch bounded ready work while the admission owner is held. A successful
        // acknowledgement can make room for the prospective batch; blocked
        // and retry-delayed rows remain counted and are not hot-looped.
        let clock = outbox::SystemDeliveryClock;
        let failures = if self.durable_sink_ids.iter().all(|sink_id| {
            self.entries
                .iter()
                .any(|entry| entry.sink.name() == sink_id)
        }) {
            self.dispatch_durable_with_outbox(&mut outbox, &clock)?
        } else {
            // Persistence-only callers may reconcile an outbox before the
            // corresponding transport objects are constructed. The normal
            // configured runtime always has every durable identity present;
            // leave such rows pending rather than turning reconciliation into
            // an unrelated dispatch configuration error.
            Vec::new()
        };
        if !events.is_empty() {
            outbox.check_capacity_for_payloads(
                log_path,
                &batch.payloads,
                self.durable_capacity_limits,
            )?;
            for entry in self
                .entries
                .iter()
                .filter(|entry| entry.persistence_role == PersistenceRole::CanonicalFirstWrite)
            {
                entry.sink.emit_canonical_jsonl_bytes(&batch.jsonl_bytes)?;
            }
            outbox.reconcile_jsonl(log_path, &sink_ids)?;
        }
        drop(outbox);
        admission_lock
            .verify_lock()
            .map_err(|error| storage_admission_error("verify", error))?;
        // Reconciliation, rather than downstream acknowledgement, establishes
        // that rotated bytes have a durable outbox representation. Cleanup is
        // warning-only and revalidates the cursor, identities, and keep window.
        self.prune_durable_rotations();
        Ok(failures)
    }

    /// The canonical first write, then every remote sink. Without persistent
    /// replay this is the whole delivery of a batch.
    pub(crate) fn deliver_best_effort(
        &self,
        events: &[Event],
    ) -> Result<Vec<SinkFailure>, Box<dyn std::error::Error>> {
        self.write_canonical_best_effort(events)?;
        self.deliver_remote_best_effort(events)
    }

    /// The canonical JSONL write when no persistent replay owns it. A failure
    /// aborts the batch before any remote sink sees it.
    pub(crate) fn write_canonical_best_effort(
        &self,
        events: &[Event],
    ) -> Result<(), Box<dyn std::error::Error>> {
        for entry in self.entries.iter().filter(|entry| {
            entry.persistence_role == PersistenceRole::CanonicalFirstWrite
                && !self.has_persistent_replay()
        }) {
            entry.sink.emit(events)?;
        }
        Ok(())
    }

    /// Every sink other than the canonical write, except durable sinks that
    /// persistent replay delivers. Failures are collected, not raised.
    pub(crate) fn deliver_remote_best_effort(
        &self,
        events: &[Event],
    ) -> Result<Vec<SinkFailure>, Box<dyn std::error::Error>> {
        let mut failures = Vec::new();
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.persistence_role != PersistenceRole::CanonicalFirstWrite)
            .filter(|entry| {
                !self.has_persistent_replay() || entry.delivery_policy != DeliveryPolicy::Durable
            })
        {
            match entry.sink.emit(events) {
                Ok(()) => {}
                Err(err) => {
                    let delivery = err.downcast_ref::<DeliveryError>();
                    let attempts = delivery.map(|delivery| delivery.attempts).unwrap_or(1);
                    let class = delivery
                        .map(|delivery| delivery.class)
                        .unwrap_or(DeliveryErrorClass::UnknownInternal);
                    failures.push(SinkFailure {
                        name: entry.sink.name().to_string(),
                        kind: entry.transport.to_string(),
                        class,
                        attempts,
                        error: PrivacySanitizer::sanitize(
                            SanitizationContext::Diagnostic,
                            &err.to_string(),
                        ),
                        prior_attempts: 0,
                        prior_error_class: None,
                    });
                }
            }
        }
        Ok(failures)
    }

    /// Dispatch a bounded share of eligible deliveries for each sink. The outbox owns
    /// retry scheduling; this method never sleeps and each selected row gets
    /// at most one transport attempt before its state is committed.
    pub(crate) fn deliver_durable(&self) -> Result<Vec<SinkFailure>, Box<dyn std::error::Error>> {
        if self.has_persistent_replay() {
            outbox::ensure_durable_storage_supported()?;
        }
        let clock = outbox::SystemDeliveryClock;
        self.deliver_durable_with_clock(&clock)
    }

    fn deliver_durable_with_clock(
        &self,
        clock: &dyn outbox::DeliveryClock,
    ) -> Result<Vec<SinkFailure>, Box<dyn std::error::Error>> {
        let failures = self.dispatch_durable_with_clock(clock)?;
        // Dispatch has committed each durable sink result. The outbox now
        // rechecks cursor/generation identity and terminal state under the
        // JSONL lock before attempting any deletion.
        self.prune_durable_rotations();
        Ok(failures)
    }

    fn dispatch_durable_with_clock(
        &self,
        clock: &dyn outbox::DeliveryClock,
    ) -> Result<Vec<SinkFailure>, Box<dyn std::error::Error>> {
        let Some(outbox_path) = self.durable_outbox_path.as_ref() else {
            return Ok(Vec::new());
        };
        self.validate_persistent_replay_paths()?;
        let admission_lock = outbox::acquire_admission_lock(outbox_path)
            .map_err(|error| storage_admission_error("dispatch lock", error))?;
        let mut outbox = outbox::Outbox::open(outbox_path)?;
        let failures = self.dispatch_durable_with_outbox(&mut outbox, clock)?;
        drop(outbox);
        admission_lock
            .verify_lock()
            .map_err(|error| storage_admission_error("verify", error))?;
        Ok(failures)
    }

    /// Caller holds the outbox admission owner across selection, transport, and
    /// result commit. Admission predrain must not recursively acquire that owner.
    fn dispatch_durable_with_outbox(
        &self,
        outbox: &mut outbox::Outbox,
        clock: &dyn outbox::DeliveryClock,
    ) -> Result<Vec<SinkFailure>, Box<dyn std::error::Error>> {
        let mut failures = Vec::new();
        let now = clock.now_millis();

        for sink_id in &self.durable_sink_ids {
            let Some(entry) = self
                .entries
                .iter()
                .find(|entry| entry.sink.name() == sink_id)
            else {
                return Err(format!("durable sink identity '{sink_id}' is not configured").into());
            };
            // Every sink receives its own share, even after a slow predecessor.
            // The time budget stops new attempts; an in-flight attempt retains
            // its configured transport deadline. Unselected rows remain pending.
            let started = clock.monotonic_now();
            for row in 0..16 {
                if row > 0
                    && clock.monotonic_now().duration_since(started)
                        >= std::time::Duration::from_millis(100)
                {
                    break;
                }
                let Some(ready) = outbox.next_ready_delivery(sink_id, now)? else {
                    break;
                };
                let attempt = ready
                    .row
                    .attempts
                    .checked_add(1)
                    .ok_or("durable delivery attempt count overflow")?;
                if outbox::is_delivery_failure_alert_payload(&ready.payload) {
                    // Older outboxes may contain delivery rows for operational
                    // failure alerts created before alert recursion was
                    // suppressed at ingest. Do not send those rows or create a
                    // second alert; terminalize the stale row without a new
                    // failure signal.
                    outbox.record_delivery_at(
                        &ready.row.event_id,
                        sink_id,
                        outbox::DeliveryUpdate {
                            state: outbox::DeliveryState::Dead,
                            attempts: attempt,
                            next_attempt_at: None,
                            last_error_class: None,
                            updated_at: now,
                        },
                    )?;
                    continue;
                }
                let result = entry.sink.emit_canonical_once(&ready.payload);
                match result {
                    Ok(()) => {
                        outbox.record_delivery_at(
                            &ready.row.event_id,
                            sink_id,
                            outbox::DeliveryUpdate {
                                state: outbox::DeliveryState::Acked,
                                attempts: attempt,
                                next_attempt_at: None,
                                last_error_class: None,
                                updated_at: now,
                            },
                        )?;
                    }
                    Err(error) => {
                        let (class, message) = delivery_error_details(error.as_ref());
                        if class == DeliveryErrorClass::DurableStorage {
                            // A storage-class result is not an event poison
                            // verdict. Leave the row pending and fail the run
                            // rather than acknowledging or dead-lettering it.
                            return Err(error);
                        }
                        let class = match class {
                            DeliveryErrorClass::HttpStatus { status }
                                if status == 401 || status == 403 =>
                            {
                                DeliveryErrorClass::AuthenticationBlocked { status }
                            }
                            class => class,
                        };
                        let (state, next_attempt_at) = if matches!(
                            class,
                            DeliveryErrorClass::AuthenticationBlocked { .. }
                                | DeliveryErrorClass::SinkResponseBlocked
                        ) {
                            (outbox::DeliveryState::Blocked, None)
                        } else if class.is_retryable() && attempt < entry.retry.max_attempts.max(1)
                        {
                            (
                                outbox::DeliveryState::Pending,
                                Some(outbox::next_retry_at(
                                    now,
                                    entry.retry.base_delay_ms,
                                    attempt,
                                )),
                            )
                        } else {
                            (outbox::DeliveryState::Dead, None)
                        };
                        outbox.record_delivery_at(
                            &ready.row.event_id,
                            sink_id,
                            outbox::DeliveryUpdate {
                                state,
                                attempts: attempt,
                                next_attempt_at,
                                last_error_class: Some(class),
                                updated_at: now,
                            },
                        )?;
                        failures.push(SinkFailure {
                            name: entry.sink.name().to_string(),
                            kind: entry.transport.to_string(),
                            class,
                            attempts: attempt,
                            error: format!(
                                "durable delivery attempt for sink {}: {}",
                                PrivacySanitizer::sanitize(
                                    SanitizationContext::Diagnostic,
                                    entry.sink.name(),
                                ),
                                message
                            ),
                            prior_attempts: ready.row.attempts,
                            prior_error_class: ready.row.last_error_class,
                        });
                    }
                }
            }
        }
        Ok(failures)
    }

    /// Deliver follow-up delivery-failure alert events, skipping the named
    /// (just-failed) sinks. Remote errors are logged to stderr and never
    /// generate further events, so a failing sink cannot alert about itself
    /// recursively. A successfully admitted alert is delivered once directly
    /// to healthy durable sinks; it is not added to their replay queue.
    /// Returns whether the batch was persisted or delivered anywhere. A
    /// required canonical write failure propagates instead of acknowledging it.
    pub(crate) fn deliver_alerts(
        &self,
        events: &[Event],
        skip: &[&str],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let durable_alert_admitted = self.durable_alerts_admitted(events);
        if !durable_alert_admitted {
            return Ok(false);
        }
        let mut accepted = self.has_persistent_replay();
        for entry in self.entries.iter().filter(|entry| {
            entry.persistence_role == PersistenceRole::CanonicalFirstWrite
                && !self.has_persistent_replay()
        }) {
            if skip.contains(&entry.sink.name()) {
                continue;
            }
            entry.sink.emit(events)?;
            accepted = true;
        }
        for entry in self.entries.iter().filter(|entry| {
            entry.persistence_role != PersistenceRole::CanonicalFirstWrite
                && entry.delivery_policy == DeliveryPolicy::Durable
                && (!self.has_persistent_replay() || durable_alert_admitted)
        }) {
            if skip.contains(&entry.sink.name()) {
                continue;
            }
            if let Err(err) = entry.sink.emit(events) {
                let rendered = format!(
                    "warning: could not deliver sink-failure alert to sink {}: {err}",
                    entry.sink.name()
                );
                eprintln!(
                    "{}",
                    PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &rendered)
                );
            } else {
                accepted = true;
            }
        }
        for entry in self.entries.iter().filter(|entry| {
            entry.persistence_role != PersistenceRole::CanonicalFirstWrite
                && entry.delivery_policy != DeliveryPolicy::Durable
        }) {
            if skip.contains(&entry.sink.name()) {
                continue;
            }
            if let Err(err) = entry.sink.emit(events) {
                let rendered = format!(
                    "warning: could not deliver sink-failure alert to sink {}: {err}",
                    entry.sink.name()
                );
                eprintln!(
                    "{}",
                    PrivacySanitizer::sanitize(SanitizationContext::Diagnostic, &rendered)
                );
            } else {
                accepted = true;
            }
        }
        Ok(accepted)
    }

    fn durable_alerts_admitted(&self, events: &[Event]) -> bool {
        if !self.has_persistent_replay() || events.is_empty() {
            return true;
        }
        let Some(outbox_path) = self.durable_outbox_path.as_ref() else {
            return false;
        };
        let Ok(outbox) = outbox::Outbox::open_read_only(outbox_path) else {
            return false;
        };
        events
            .iter()
            .all(|event| outbox.get_event(&event.event_id).ok().flatten().is_some())
    }
}

fn storage_admission_error(context: &str, error: impl std::fmt::Display) -> DeliveryError {
    DeliveryError::new(
        DeliveryErrorClass::DurableStorage,
        0,
        format!("durable capacity admission {context} failed: {error}"),
    )
}

fn terminal_health_sink_id(value: &str) -> String {
    crate::event::terminal_identifier("sink", value)
}

pub(crate) fn durable_health_json_from_path(
    outbox_path: &std::path::Path,
    sink_ids: &[&str],
) -> serde_json::Value {
    durable_health_json_from_path_for_platform(
        outbox_path,
        sink_ids,
        outbox::current_platform_is_windows(),
    )
}

fn durable_health_json_from_path_for_platform(
    outbox_path: &std::path::Path,
    sink_ids: &[&str],
    is_windows: bool,
) -> serde_json::Value {
    let health = match outbox::ensure_durable_storage_supported_for_platform(is_windows)
        .and_then(|()| outbox::Outbox::open_read_only(outbox_path))
        .and_then(|outbox| outbox.health(sink_ids, outbox::unix_seconds()))
    {
        Ok(health) => health,
        Err(error) => {
            let (_, message) = delivery_error_details(error.as_ref());
            return serde_json::json!({
                "mode": "unavailable",
                "error": {
                    "class": DeliveryErrorClass::DurableStorage.as_str(),
                    "message": message,
                },
                "sinks": {},
            });
        }
    };
    let sinks = health
        .sinks
        .into_iter()
        .map(|sink| {
            let last_error = sink.last_error_at.map(|at| {
                let mut value = serde_json::json!({
                    "at": at,
                    "class": sink.last_error_class.map(DeliveryErrorClass::as_str),
                });
                if let Some(status) = sink.last_error_status {
                    value["status"] = serde_json::json!(status);
                }
                value
            });
            (
                terminal_health_sink_id(&sink.sink_id),
                serde_json::json!({
                    "pending_depth": sink.pending_depth,
                    "pending_bytes": sink.pending_bytes,
                    "oldest_pending_age_seconds": sink.oldest_pending_age_seconds,
                    "dead_count": sink.dead_count,
                    "last_success_at": sink.last_success_at,
                    "last_error": last_error,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    serde_json::json!({
        "mode": "durable",
        "sinks": sinks,
    })
}

#[cfg(test)]
mod tests;
