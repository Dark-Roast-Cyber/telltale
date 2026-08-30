pub mod config;
mod elastic;
pub mod http;
mod jsonl;
pub(crate) mod outbox;
mod splunk_hec;

pub(crate) use elastic::{DEFAULT_ELASTIC_INDEX, ElasticBulkSink, elastic_bulk_action_json};
pub(crate) use jsonl::{LocalJsonlSink, RotationConfig};
pub(crate) use splunk_hec::{SplunkHecConfig, SplunkHecHttpSink};

use crate::event::{Event, PrivacySanitizer, SanitizationContext};
use crate::file_lock::RotationNamespace;
use crate::sink::http::RetryConfig;

/// Delivery reliability is a policy, not a property of the transport or its
/// location. `Durable` is reserved for the persistent downstream dispatcher;
/// the current sinks use `BestEffort` and retain their existing behavior.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum DeliveryPolicy {
    BestEffort,
    Durable,
}

/// The persistence responsibility associated with a sink. A canonical event
/// log is a first-write record; downstream delivery state is a separate role.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum PersistenceRole {
    None,
    CanonicalFirstWrite,
    DeliveryState,
}

/// Stable classification for delivery failures. Callers can make retry or
/// operator-action decisions without interpreting a human diagnostic.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum DeliveryErrorClass {
    TransportNoResponse,
    Timeout,
    HttpStatus { status: u16 },
    SinkApplicationRejected,
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
            Self::AuthenticationBlocked { .. } => "authentication_blocked",
            Self::PayloadCollision => "payload_collision",
            Self::DurableStorage => "durable_storage",
            Self::UnknownInternal => "unknown_internal",
        }
    }

    /// Retryability is derived from the structured class/status, never from
    /// the diagnostic text. The current HTTP transport retries 429 and 5xx;
    /// 408 is included for the durable scheduler's one-attempt contract.
    #[allow(dead_code)]
    pub(crate) fn is_retryable(self) -> bool {
        match self {
            Self::TransportNoResponse | Self::Timeout => true,
            Self::HttpStatus { status } => {
                status == 408 || status == 429 || (500..600).contains(&status)
            }
            Self::SinkApplicationRejected
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
    /// Normal runtime construction calls this eagerly; validation and dry-run
    /// construction deliberately do not.
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

    #[allow(dead_code)]
    pub(crate) fn durable_sink_ids(&self) -> &[String] {
        &self.durable_sink_ids
    }

    #[allow(dead_code)]
    pub(crate) fn durable_capacity_limits(&self) -> outbox::CapacityLimits {
        self.durable_capacity_limits
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
    /// existing best-effort ordering.
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
    /// admitted batch is dispatched by the caller's normal delivery step.
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
        let batch = outbox::canonical_replay_batch(events)?;
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

        // Drain ready work while the admission owner is held. A successful
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

    pub(crate) fn deliver_best_effort(
        &self,
        events: &[Event],
    ) -> Result<Vec<SinkFailure>, Box<dyn std::error::Error>> {
        let mut failures = Vec::new();
        for entry in self.entries.iter().filter(|entry| {
            entry.persistence_role == PersistenceRole::CanonicalFirstWrite
                && !self.has_persistent_replay()
        }) {
            entry.sink.emit(events)?;
        }
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
                    });
                }
            }
        }
        Ok(failures)
    }

    /// Dispatch every currently eligible durable delivery. The outbox owns
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
        let mut outbox = outbox::Outbox::open(outbox_path)?;
        self.dispatch_durable_with_outbox(&mut outbox, clock)
    }

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
            loop {
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
                        let (state, next_attempt_at) =
                            if matches!(class, DeliveryErrorClass::AuthenticationBlocked { .. }) {
                                (outbox::DeliveryState::Blocked, None)
                            } else if class.is_retryable()
                                && attempt < entry.retry.max_attempts.max(1)
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
                        });
                    }
                }
            }
        }
        Ok(failures)
    }

    /// Deliver follow-up delivery-failure alert events, skipping the named
    /// (just-failed) sinks. Errors here are logged to stderr and never
    /// generate further events, so a failing sink cannot alert about itself
    /// recursively. A successfully admitted alert is delivered once directly
    /// to healthy durable sinks; it is not added to their replay queue.
    pub(crate) fn deliver_alerts(&self, events: &[Event], skip: &[&str]) {
        let durable_alert_admitted = self.durable_alerts_admitted(events);
        for entry in self.entries.iter().filter(|entry| {
            entry.persistence_role == PersistenceRole::CanonicalFirstWrite
                && !self.has_persistent_replay()
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
                return;
            }
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
            }
        }
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

#[cfg(all(test, not(windows)))]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::{Arc, Barrier, Mutex};

    use tempfile::tempdir;

    use super::outbox::{CapacityLimits, DeliveryClock, DeliveryState, DeliveryUpdate, Outbox};
    use super::{
        DeliveryError, DeliveryErrorClass, DeliveryPolicy, EventSink, LocalJsonlSink,
        PersistenceRole, RetryConfig, RotationConfig, SinkSet,
    };
    use crate::event::{
        ActivityEventInput, ControlledMarker, Event, Evidence, OperationalAlertInput,
        check_serialized_event_markers, health_event_with_metadata, operational_alert_event,
    };
    use telltale_schema::clients::ClientId;

    fn make_health_event() -> Event {
        health_event_with_metadata(crate::event::HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 7,
            rule_count: 3,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        })
    }

    fn marked_event(marker: &str) -> Event {
        crate::event::activity_event(ActivityEventInput {
            client: ClientId::Codex,
            agent: None,
            model: None,
            provider: None,
            session_id: "synthetic-sink-session".to_string(),
            source_path_hash: "synthetic-sink-source".to_string(),
            tool_name: Some("shell".to_string()),
            tags: vec![format!("synthetic:{marker}")],
            evidence: vec![Evidence {
                field: "tool_result".to_string(),
                redacted_value: format!("token={marker}"),
                hash: None,
                rule_id: None,
            }],
            risk_contributions: Vec::new(),
            event_time: None,
        })
        .expect("synthetic activity event")
    }

    fn capacity_limits(max_pending_events: u64, max_pending_bytes: u64) -> CapacityLimits {
        CapacityLimits {
            max_pending_events,
            max_pending_bytes,
        }
    }

    type RecordedPayloads = Arc<Mutex<Vec<Vec<u8>>>>;
    type AlertCallCount = Arc<Mutex<usize>>;

    struct RecordingSink {
        name: String,
        batches: Arc<Mutex<Vec<usize>>>,
    }

    struct OrderedSink {
        name: String,
        order: Arc<Mutex<Vec<String>>>,
    }

    impl OrderedSink {
        fn new(name: &str, order: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                name: name.to_string(),
                order,
            }
        }
    }

    impl EventSink for OrderedSink {
        fn name(&self) -> &str {
            &self.name
        }

        fn emit(&self, _events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
            self.order.lock().expect("lock").push(self.name.clone());
            Ok(())
        }
    }

    impl RecordingSink {
        fn new(name: &str) -> (Self, Arc<Mutex<Vec<usize>>>) {
            let batches = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    name: name.to_string(),
                    batches: Arc::clone(&batches),
                },
                batches,
            )
        }
    }

    impl EventSink for RecordingSink {
        fn name(&self) -> &str {
            &self.name
        }

        fn emit(&self, events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
            self.batches.lock().expect("lock").push(events.len());
            Ok(())
        }
    }

    struct FailingSink {
        name: String,
        emit_calls: Arc<Mutex<u32>>,
    }

    impl FailingSink {
        fn new(name: &str) -> (Self, Arc<Mutex<u32>>) {
            let emit_calls = Arc::new(Mutex::new(0));
            (
                Self {
                    name: name.to_string(),
                    emit_calls: Arc::clone(&emit_calls),
                },
                emit_calls,
            )
        }
    }

    impl EventSink for FailingSink {
        fn name(&self) -> &str {
            &self.name
        }

        fn emit(&self, _events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
            *self.emit_calls.lock().expect("lock") += 1;
            Err("connection refused".into())
        }
    }

    #[derive(Clone, Copy)]
    enum ScriptedOutcome {
        Success,
        Failure(DeliveryErrorClass),
    }

    struct ScriptedDurableSink {
        name: String,
        outcomes: Mutex<VecDeque<ScriptedOutcome>>,
        calls: Arc<Mutex<Vec<Vec<u8>>>>,
        alert_calls: Option<Arc<Mutex<usize>>>,
    }

    impl ScriptedDurableSink {
        fn new(
            name: &str,
            outcomes: impl IntoIterator<Item = ScriptedOutcome>,
        ) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    name: name.to_string(),
                    outcomes: Mutex::new(outcomes.into_iter().collect()),
                    calls: Arc::clone(&calls),
                    alert_calls: None,
                },
                calls,
            )
        }

        fn new_with_alerts(
            name: &str,
            outcomes: impl IntoIterator<Item = ScriptedOutcome>,
        ) -> (Self, RecordedPayloads, AlertCallCount) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let alert_calls = Arc::new(Mutex::new(0));
            (
                Self {
                    name: name.to_string(),
                    outcomes: Mutex::new(outcomes.into_iter().collect()),
                    calls: Arc::clone(&calls),
                    alert_calls: Some(Arc::clone(&alert_calls)),
                },
                calls,
                alert_calls,
            )
        }
    }

    impl EventSink for ScriptedDurableSink {
        fn name(&self) -> &str {
            &self.name
        }

        fn emit(&self, _events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
            if let Some(alert_calls) = &self.alert_calls {
                *alert_calls.lock().expect("alert calls lock") += 1;
            }
            Ok(())
        }

        fn emit_canonical_once(&self, payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(payload.to_vec());
            let outcome = self
                .outcomes
                .lock()
                .expect("outcomes lock")
                .pop_front()
                .unwrap_or(ScriptedOutcome::Success);
            match outcome {
                ScriptedOutcome::Success => Ok(()),
                ScriptedOutcome::Failure(class) => {
                    Err(DeliveryError::new(class, 1, "synthetic durable delivery failure").into())
                }
            }
        }
    }

    struct FakeClock {
        now: AtomicI64,
    }

    impl FakeClock {
        fn new(now: i64) -> Self {
            Self {
                now: AtomicI64::new(now),
            }
        }

        fn advance(&self, millis: i64) {
            self.now.fetch_add(millis, Ordering::SeqCst);
        }
    }

    impl DeliveryClock for FakeClock {
        fn now_millis(&self) -> i64 {
            self.now.load(Ordering::SeqCst)
        }
    }

    fn retry_config(max_attempts: u32, base_delay_ms: u64) -> RetryConfig {
        RetryConfig {
            max_attempts,
            base_delay_ms,
        }
    }

    fn seed_pending(
        outbox_path: &Path,
        events: &[&Event],
        sink_ids: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut outbox = Outbox::open(outbox_path)?;
        for event in events {
            outbox.insert_event(event, sink_ids)?;
        }
        Ok(())
    }

    fn durable_sink_set(
        outbox_path: &Path,
        sink: ScriptedDurableSink,
        retry: RetryConfig,
    ) -> SinkSet {
        let sink_id = sink.name.clone();
        let mut sinks = SinkSet::new();
        sinks.add_best_effort_with_retry("synthetic", Box::new(sink), retry);
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.to_path_buf(),
            vec![sink_id],
            super::outbox::CapacityLimits::default(),
        );
        sinks
    }

    fn classify_admission(
        result: Result<(), Box<dyn std::error::Error>>,
    ) -> (bool, Option<DeliveryErrorClass>, String) {
        match result {
            Ok(()) => (true, None, String::new()),
            Err(error) => {
                let class = error
                    .downcast_ref::<DeliveryError>()
                    .map(|error| error.class);
                (false, class, error.to_string())
            }
        }
    }

    #[test]
    fn deliver_collects_remote_failures_and_continues_to_other_sinks() {
        let (failing, _) = FailingSink::new("corp-splunk");
        let (recorder, batches) = RecordingSink::new("second-remote");
        let mut sinks = SinkSet::new();
        sinks.add_best_effort("splunk_hec", Box::new(failing));
        sinks.add_best_effort("splunk_hec", Box::new(recorder));

        let failures = sinks
            .deliver(&[make_health_event()])
            .expect("remote failure is not fatal");

        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].name, "corp-splunk");
        assert_eq!(failures[0].kind, "splunk_hec");
        assert!(failures[0].error.contains("connection refused"));
        // The later sink still received the batch.
        assert_eq!(*batches.lock().expect("lock"), vec![1]);
    }

    #[test]
    fn delivery_failures_redact_unsafe_urls_before_alert_serialization() {
        struct UnsafeFailingSink;

        impl EventSink for UnsafeFailingSink {
            fn name(&self) -> &str {
                "remote"
            }

            fn emit(&self, _events: &[Event]) -> Result<(), Box<dyn std::error::Error>> {
                Err("request to https://user:TT_PRIVACY_DELIVERY_25@example.invalid/?token=TT_PRIVACY_DELIVERY_25 failed at /home/TT_PRIVACY_DELIVERY_25/.config/state.db".into())
            }
        }

        let mut sinks = SinkSet::new();
        sinks.add_best_effort("splunk_hec", Box::new(UnsafeFailingSink));
        let failures = sinks
            .deliver(&[make_health_event()])
            .expect("remote failure is collected");
        assert_eq!(failures.len(), 1);
        assert!(!failures[0].error.contains("TT_PRIVACY_DELIVERY_25"));

        let alert = operational_alert_event(OperationalAlertInput {
            alert_type: "sink_delivery_failure".to_string(),
            threshold: "attempts_made=1".to_string(),
            actual_value: format!(
                "sink={} type={} error={}",
                failures[0].name, failures[0].kind, failures[0].error
            ),
            scan_duration_ms: None,
            scanner_error_count: None,
        });
        let bytes = serde_json::to_vec(&alert.emittable()).expect("serialize delivery alert");
        assert!(
            check_serialized_event_markers(
                &bytes,
                "delivery-alert",
                &[ControlledMarker {
                    id: "delivery-marker",
                    value: "TT_PRIVACY_DELIVERY_25",
                }],
            )
            .is_ok()
        );
    }

    #[test]
    fn deliver_fails_fast_when_durable_sink_fails() {
        let (failing, _) = FailingSink::new("local");
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write("jsonl", Box::new(failing));

        let result = sinks.deliver(&[make_health_event()]);

        assert!(result.is_err(), "durable sink failure must be fatal");
    }

    #[test]
    fn durable_failure_prevents_remote_delivery_even_when_remote_was_added_first() {
        let (remote, batches) = RecordingSink::new("remote");
        let (durable, _) = FailingSink::new("local");
        let mut sinks = SinkSet::new();
        sinks.add_best_effort("splunk_hec", Box::new(remote));
        sinks.add_canonical_first_write("jsonl", Box::new(durable));

        assert!(sinks.deliver(&[make_health_event()]).is_err());
        assert!(
            batches.lock().expect("lock").is_empty(),
            "remote delivery must wait for durable sinks"
        );
    }

    #[test]
    fn deliver_alerts_skips_failed_sinks_and_never_recurses() {
        let (failing, emit_calls) = FailingSink::new("corp-splunk");
        let (recorder, batches) = RecordingSink::new("local");

        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write("jsonl", Box::new(recorder));
        sinks.add_best_effort("splunk_hec", Box::new(failing));

        let events = [make_health_event()];
        let failures = sinks.deliver(&events).expect("deliver");
        assert_eq!(failures.len(), 1);

        let failed_names: Vec<&str> = failures.iter().map(|f| f.name.as_str()).collect();
        sinks.deliver_alerts(&events, &failed_names);

        // The failed sink was skipped: exactly one emit call (the original delivery).
        assert_eq!(*emit_calls.lock().expect("lock"), 1);
        // The healthy durable sink received both the batch and the alert.
        assert_eq!(*batches.lock().expect("lock"), vec![1, 1]);
    }

    #[test]
    fn deliver_alerts_swallows_errors_from_remaining_sinks() {
        let (failing, _) = FailingSink::new("corp-splunk");
        let mut sinks = SinkSet::new();
        sinks.add_best_effort("splunk_hec", Box::new(failing));

        // No skip: the failing sink receives the alert, fails, and the error
        // is swallowed (stderr only) instead of propagating or recursing.
        sinks.deliver_alerts(&[make_health_event()], &[]);
    }

    #[test]
    fn deliver_alerts_runs_durable_sinks_before_remotes_in_class_order() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut sinks = SinkSet::new();
        sinks.add_best_effort(
            "splunk_hec",
            Box::new(OrderedSink::new("remote-1", Arc::clone(&order))),
        );
        sinks.add_canonical_first_write(
            "jsonl",
            Box::new(OrderedSink::new("local-1", Arc::clone(&order))),
        );
        sinks.add_best_effort(
            "elastic_bulk",
            Box::new(OrderedSink::new("remote-2", Arc::clone(&order))),
        );
        sinks.add_canonical_first_write(
            "jsonl",
            Box::new(OrderedSink::new("local-2", Arc::clone(&order))),
        );

        sinks.deliver_alerts(&[make_health_event()], &[]);

        assert_eq!(
            *order.lock().expect("lock"),
            vec!["local-1", "local-2", "remote-1", "remote-2"]
        );
    }

    #[test]
    fn durable_alert_failure_stops_before_remote_alert_even_when_remote_was_added_first() {
        let (remote, batches) = RecordingSink::new("remote");
        let (durable, _) = FailingSink::new("local");
        let mut sinks = SinkSet::new();
        sinks.add_best_effort("splunk_hec", Box::new(remote));
        sinks.add_canonical_first_write("jsonl", Box::new(durable));

        sinks.deliver_alerts(&[make_health_event()], &[]);

        assert!(
            batches.lock().expect("lock").is_empty(),
            "remote alert must wait for durable alert delivery"
        );
    }

    #[test]
    fn has_durable_reflects_entries() {
        let mut sinks = SinkSet::new();
        assert!(!sinks.has_canonical_first_write());
        assert!(sinks.is_empty());
        let (remote, _) = RecordingSink::new("remote");
        sinks.add_best_effort("splunk_hec", Box::new(remote));
        assert!(!sinks.has_canonical_first_write());
        let (local, _) = RecordingSink::new("local");
        sinks.add_canonical_first_write("jsonl", Box::new(local));
        assert!(sinks.has_canonical_first_write());
        assert!(!sinks.is_empty());
    }

    #[test]
    fn transport_policy_and_persistence_role_are_independent() {
        let (local, _) = RecordingSink::new("local-collector");
        let (remote, _) = RecordingSink::new("remote");
        let mut sinks = SinkSet::new();
        sinks.add_best_effort("local_collector", Box::new(local));
        sinks.add_with_roles(
            "http",
            Box::new(remote),
            DeliveryPolicy::Durable,
            PersistenceRole::DeliveryState,
        );

        assert_eq!(sinks.entries[0].delivery_policy, DeliveryPolicy::BestEffort);
        assert_eq!(sinks.entries[0].persistence_role, PersistenceRole::None);
        assert_eq!(sinks.entries[1].delivery_policy, DeliveryPolicy::Durable);
        assert_eq!(
            sinks.entries[1].persistence_role,
            PersistenceRole::DeliveryState
        );
        assert_eq!(sinks.entries[0].transport, "local_collector");
        assert_eq!(sinks.entries[1].transport, "http");
        assert_eq!(
            sinks.delivery_posture(),
            super::DeliveryPosture::BestEffortNoReplay
        );
    }

    #[test]
    fn delivery_error_class_retryability_does_not_depend_on_message() {
        assert!(DeliveryErrorClass::TransportNoResponse.is_retryable());
        assert!(DeliveryErrorClass::Timeout.is_retryable());
        assert!(DeliveryErrorClass::HttpStatus { status: 429 }.is_retryable());
        assert!(DeliveryErrorClass::HttpStatus { status: 503 }.is_retryable());
        assert!(!DeliveryErrorClass::AuthenticationBlocked { status: 403 }.is_retryable());
        assert!(!DeliveryErrorClass::SinkApplicationRejected.is_retryable());
        assert!(!DeliveryErrorClass::PayloadCollision.is_retryable());
        assert!(!DeliveryErrorClass::DurableStorage.is_retryable());
        assert_eq!(
            DeliveryErrorClass::HttpStatus { status: 503 }.as_str(),
            "http_status"
        );
        let error = DeliveryError::new(
            DeliveryErrorClass::TransportNoResponse,
            2,
            "connection refused https://user:TT_PRIVACY_DELIVERY_26@example.invalid/path",
        );
        assert_eq!(error.class, DeliveryErrorClass::TransportNoResponse);
        assert!(!error.to_string().contains("TT_PRIVACY_DELIVERY_26"));
    }

    #[test]
    fn persistent_replay_prunes_ingested_rotation_before_unavailable_delivery() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let first = marked_event("TT_SINK_ROTATION_FIRST_26");
        let second = marked_event("TT_SINK_ROTATION_SECOND_26");
        let sink = LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig {
                max_size_bytes: 1,
                keep: 0,
            },
        )
        .with_durable_rotation();
        let namespace = sink.rotation_namespace().expect("rotation namespace");
        let (remote, _) = ScriptedDurableSink::new(
            "remote",
            [ScriptedOutcome::Failure(
                DeliveryErrorClass::TransportNoResponse,
            )],
        );
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation_and_keep(
            "jsonl",
            Box::new(sink),
            log_path.clone(),
            namespace,
            Some(0),
        );
        sinks.add_best_effort("http", Box::new(remote));
        sinks.enable_persistent_replay_with_capacity(
            outbox_path,
            vec!["remote".to_string()],
            CapacityLimits::default(),
        );

        sinks
            .persist_for_durable_replay(std::slice::from_ref(&first))
            .expect("persist first event");
        let pre_admission_failures = sinks
            .persist_for_durable_replay_with_failures(std::slice::from_ref(&second))
            .expect("persist and prune rotated event");
        assert_eq!(pre_admission_failures.len(), 1);
        let generations = crate::sink::jsonl::discover_jsonl_generations(&log_path)
            .expect("discover post-prune generations");
        assert!(generations.iter().any(|generation| generation.is_active));
        assert!(generations.iter().all(|generation| generation.is_active));

        let failures = sinks.deliver_durable().expect("post-admission dispatch");
        assert!(failures.is_empty());
    }

    #[test]
    fn persistent_replay_persists_canonical_jsonl_and_outbox_before_delivery() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let event = make_health_event();
        let sink = LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled());
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(sink),
            log_path.clone(),
            None,
        );
        sinks.enable_persistent_replay_with_capacity(
            outbox_path,
            vec!["remote".to_string()],
            super::outbox::CapacityLimits::default(),
        );

        sinks
            .persist_for_durable_replay(std::slice::from_ref(&event))
            .expect("persistent handoff");

        let output = std::fs::read_to_string(log_path).expect("canonical JSONL");
        assert_eq!(output.lines().count(), 1);
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let outbox = Outbox::open(outbox_path).expect("open outbox");
        assert!(
            outbox
                .get_event(&event.event_id)
                .expect("outbox event")
                .is_some()
        );
        assert_eq!(
            outbox
                .get_delivery(&event.event_id, "remote")
                .expect("outbox delivery")
                .expect("pending delivery")
                .state,
            DeliveryState::Pending
        );
    }

    #[test]
    fn persistent_replay_rejects_before_append_when_pending_capacity_is_full() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let first = marked_event("TT_CAPACITY_SINK_FIRST_26");
        let second = marked_event("TT_CAPACITY_SINK_SECOND_26");
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
            log_path.clone(),
            None,
        );
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["remote".to_string()],
            capacity_limits(1, u64::MAX),
        );

        sinks
            .persist_for_durable_replay(std::slice::from_ref(&first))
            .expect("first event persists");
        let before = fs::read(&log_path).expect("canonical JSONL");
        let error = sinks
            .persist_for_durable_replay(std::slice::from_ref(&second))
            .expect_err("second event exceeds pending capacity");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured capacity error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(delivery.message.contains("limit_kind=pending_events"));
        assert!(delivery.message.len() <= 200);
        assert!(!delivery.message.contains("TT_CAPACITY_SINK"));
        assert_eq!(
            fs::read(&log_path).expect("canonical JSONL unchanged"),
            before
        );
        assert_eq!(
            fs::read_to_string(&log_path)
                .expect("canonical JSONL")
                .lines()
                .count(),
            1
        );

        let outbox = Outbox::open(outbox_path).expect("reopen outbox");
        assert!(
            outbox
                .get_event(&second.event_id)
                .expect("second event lookup")
                .is_none()
        );
        assert!(
            outbox
                .get_event(&first.event_id)
                .expect("first event lookup")
                .is_some()
        );
    }

    #[test]
    fn full_pending_queue_drains_before_new_admission() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let first = make_health_event();
        let second = make_health_event();
        let (remote, calls) = ScriptedDurableSink::new(
            "remote",
            [ScriptedOutcome::Success, ScriptedOutcome::Success],
        );
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
            log_path.clone(),
            None,
        );
        sinks.add_best_effort_with_retry("synthetic", Box::new(remote), retry_config(3, 1));
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["remote".to_string()],
            capacity_limits(1, u64::MAX),
        );

        sinks
            .persist_for_durable_replay(std::slice::from_ref(&first))
            .expect("admit first event");
        let failures = sinks
            .persist_for_durable_replay_with_failures(std::slice::from_ref(&second))
            .expect("drain first event before admitting second");
        assert!(failures.is_empty());
        assert_eq!(calls.lock().expect("calls lock").len(), 1);

        let outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        assert_eq!(
            outbox
                .get_delivery(&first.event_id, "remote")
                .expect("first delivery")
                .expect("first row")
                .state,
            DeliveryState::Acked
        );
        assert_eq!(
            outbox
                .get_delivery(&second.event_id, "remote")
                .expect("second delivery")
                .expect("second row")
                .state,
            DeliveryState::Pending
        );
        drop(outbox);

        sinks.deliver_durable().expect("drain newly admitted event");
        assert_eq!(calls.lock().expect("calls lock").len(), 2);
    }

    #[test]
    fn blocked_delivery_stays_blocked_until_release_then_drains_before_admission() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let first = make_health_event();
        let second = make_health_event();
        let (remote, calls) = ScriptedDurableSink::new(
            "remote",
            [
                ScriptedOutcome::Failure(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
                ScriptedOutcome::Success,
                ScriptedOutcome::Success,
            ],
        );
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
            log_path.clone(),
            None,
        );
        sinks.add_best_effort_with_retry("synthetic", Box::new(remote), retry_config(3, 1));
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["remote".to_string()],
            capacity_limits(1, u64::MAX),
        );

        sinks
            .persist_for_durable_replay(std::slice::from_ref(&first))
            .expect("admit first event");
        let before = fs::read(&log_path).expect("canonical JSONL before blocked admission");
        let error = sinks
            .persist_for_durable_replay(std::slice::from_ref(&second))
            .expect_err("blocked work must keep the queue full");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured capacity error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert_eq!(
            fs::read(&log_path).expect("canonical JSONL after blocked rejection"),
            before
        );
        assert_eq!(calls.lock().expect("calls lock").len(), 1);
        {
            let outbox = Outbox::open(&outbox_path).expect("reopen blocked outbox");
            assert_eq!(
                outbox
                    .get_delivery(&first.event_id, "remote")
                    .expect("blocked delivery")
                    .expect("blocked row")
                    .state,
                DeliveryState::Blocked
            );
            assert!(
                outbox
                    .get_delivery(&second.event_id, "remote")
                    .expect("rejected delivery")
                    .is_none()
            );
        }

        let mut outbox = Outbox::open(&outbox_path).expect("open blocked outbox for release");
        assert_eq!(
            outbox
                .release_blocked_for_sink("remote", super::outbox::unix_millis())
                .expect("release blocked sink"),
            1
        );
        drop(outbox);

        sinks
            .persist_for_durable_replay(std::slice::from_ref(&second))
            .expect("release drains before admitting second event");
        assert_eq!(calls.lock().expect("calls lock").len(), 2);
        let outbox = Outbox::open(&outbox_path).expect("reopen released outbox");
        assert_eq!(
            outbox
                .get_delivery(&first.event_id, "remote")
                .expect("released first delivery")
                .expect("released first row")
                .state,
            DeliveryState::Acked
        );
        assert_eq!(
            outbox
                .get_delivery(&second.event_id, "remote")
                .expect("second delivery")
                .expect("second row")
                .state,
            DeliveryState::Pending
        );
    }

    #[test]
    fn concurrent_same_pair_admission_is_capacity_bounded_and_cursor_consistent() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let first = make_health_event();
        let second = make_health_event();
        let first_id = first.event_id.clone();
        let second_id = second.event_id.clone();

        let (first_remote, _) = ScriptedDurableSink::new("remote", [ScriptedOutcome::Success]);
        let mut first_sinks = SinkSet::new();
        first_sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
            log_path.clone(),
            None,
        );
        first_sinks.add_best_effort_with_retry(
            "synthetic",
            Box::new(first_remote),
            retry_config(3, 1),
        );
        first_sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["remote".to_string()],
            capacity_limits(1, u64::MAX),
        );

        let (second_remote, _) = ScriptedDurableSink::new("remote", [ScriptedOutcome::Success]);
        let mut second_sinks = SinkSet::new();
        second_sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
            log_path.clone(),
            None,
        );
        second_sinks.add_best_effort_with_retry(
            "synthetic",
            Box::new(second_remote),
            retry_config(3, 1),
        );
        second_sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["remote".to_string()],
            capacity_limits(1, u64::MAX),
        );

        let barrier = Arc::new(Barrier::new(3));
        let first_barrier = Arc::clone(&barrier);
        let first_handle = std::thread::spawn(move || {
            first_barrier.wait();
            classify_admission(first_sinks.persist_for_durable_replay(&[first]))
        });
        let second_barrier = Arc::clone(&barrier);
        let second_handle = std::thread::spawn(move || {
            second_barrier.wait();
            classify_admission(second_sinks.persist_for_durable_replay(&[second]))
        });
        barrier.wait();
        let results = [
            first_handle.join().expect("first admission thread"),
            second_handle.join().expect("second admission thread"),
        ];

        assert_eq!(results.iter().filter(|result| result.0).count(), 1);
        let loser = results
            .iter()
            .find(|result| !result.0)
            .expect("one admission must lose");
        assert_eq!(loser.1, Some(DeliveryErrorClass::DurableStorage));
        assert!(!loser.2.is_empty());

        let bytes = fs::read(&log_path).expect("canonical JSONL after contention");
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
        let admitted_id = serde_json::from_slice::<serde_json::Value>(
            bytes.strip_suffix(b"\n").expect("newline-terminated event"),
        )
        .expect("admitted event JSON")
        .get("event_id")
        .and_then(serde_json::Value::as_str)
        .expect("admitted event ID")
        .to_string();
        assert!(admitted_id == first_id || admitted_id == second_id);

        let outbox = Outbox::open(&outbox_path).expect("reopen contended outbox");
        assert!(
            outbox
                .get_event(&admitted_id)
                .expect("admitted event lookup")
                .is_some()
        );
        let rejected_id = if admitted_id == first_id {
            second_id
        } else {
            first_id
        };
        assert!(
            outbox
                .get_event(&rejected_id)
                .expect("rejected event lookup")
                .is_none()
        );
        assert_eq!(
            outbox
                .ingest_cursor()
                .expect("contention cursor lookup")
                .expect("contention cursor")
                .byte_offset,
            bytes.len() as u64
        );
    }

    #[test]
    fn persistent_replay_rejects_committed_unread_jsonl_before_append() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let first = marked_event("TT_CAPACITY_SINK_UNREAD_FIRST_26");
        let second = marked_event("TT_CAPACITY_SINK_UNREAD_SECOND_26");
        LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled())
            .emit(std::slice::from_ref(&first))
            .expect("committed canonical JSONL");
        let outbox = Outbox::open(&outbox_path).expect("create empty outbox");
        drop(outbox);
        let before = fs::read(&log_path).expect("canonical JSONL");

        let attempt = || {
            let mut sinks = SinkSet::new();
            sinks.add_canonical_first_write_path_with_rotation(
                "jsonl",
                Box::new(LocalJsonlSink::with_rotation(
                    &log_path,
                    RotationConfig::disabled(),
                )),
                log_path.clone(),
                None,
            );
            sinks.enable_persistent_replay_with_capacity(
                outbox_path.clone(),
                vec!["remote".to_string()],
                capacity_limits(1, u64::MAX),
            );
            sinks.persist_for_durable_replay(std::slice::from_ref(&second))
        };

        for error in [
            attempt().expect_err("unread event consumes the one-event capacity"),
            attempt().expect_err("the same result survives outbox reopen"),
        ] {
            let delivery = error
                .downcast_ref::<DeliveryError>()
                .expect("structured capacity error");
            assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
            assert!(delivery.message.contains("limit_kind=pending_events"));
            assert!(delivery.message.len() <= 200);
            assert!(!delivery.message.contains("TT_CAPACITY_SINK"));
        }
        assert_eq!(
            fs::read(&log_path).expect("canonical JSONL unchanged"),
            before
        );
        let outbox = Outbox::open(outbox_path).expect("reopen empty outbox");
        assert!(
            outbox
                .get_event(&second.event_id)
                .expect("second event lookup")
                .is_none()
        );
        assert!(
            outbox
                .get_event(&first.event_id)
                .expect("first recovered event lookup")
                .is_some(),
            "the already committed event must be reconciled before the new-event gate"
        );
        let cursor = outbox
            .ingest_cursor()
            .expect("recovered cursor lookup")
            .expect("recovered cursor");
        assert_eq!(cursor.byte_offset, before.len() as u64);
    }

    #[test]
    fn persistent_replay_recovers_before_capacity_scan_when_unread_bytes_exceed_limit() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let first = marked_event("TT_CAPACITY_SINK_BOUNDED_RECOVERY_FIRST_26");
        let second = marked_event("TT_CAPACITY_SINK_BOUNDED_RECOVERY_SECOND_26");
        LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled())
            .emit(std::slice::from_ref(&first))
            .expect("committed canonical JSONL");
        let before = fs::read(&log_path).expect("canonical JSONL");
        assert!(before.len() > 1, "synthetic record must exceed scan limit");

        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
            log_path.clone(),
            None,
        );
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["remote".to_string()],
            capacity_limits(1, u64::MAX),
        );
        // The production bound remains 64 MiB. This injected test limit makes
        // the already-committed record exceed the unread scan bound without
        // allocating a 64 MiB fixture. Recovery must advance the cursor first.
        sinks.set_durable_capacity_scan_limit((before.len() as u64) - 1);

        let error = sinks
            .persist_for_durable_replay(std::slice::from_ref(&second))
            .expect_err("new event must be rejected after recovery fills capacity");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured capacity error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(delivery.message.contains("limit_kind=pending_events"));
        assert!(
            !delivery
                .message
                .contains("capacity scan exceeds the bounded inspection range")
        );
        assert_eq!(
            fs::read(&log_path).expect("canonical JSONL unchanged"),
            before
        );

        let outbox = Outbox::open(outbox_path).expect("reopen recovered outbox");
        assert!(
            outbox
                .get_event(&first.event_id)
                .expect("first recovered event lookup")
                .is_some()
        );
        assert!(
            outbox
                .get_event(&second.event_id)
                .expect("prospective event lookup")
                .is_none()
        );
        assert_eq!(
            outbox
                .ingest_cursor()
                .expect("cursor lookup")
                .expect("recovered cursor")
                .byte_offset,
            before.len() as u64
        );
    }

    #[test]
    fn persistent_delivery_alert_is_admitted_once_to_jsonl_and_outbox() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let event = make_health_event();
        let alert = operational_alert_event(OperationalAlertInput {
            alert_type: "sink_delivery_failure".to_string(),
            threshold: "attempts_made=1".to_string(),
            actual_value: "sink=synthetic-remote type=synthetic class=transport_no_response"
                .to_string(),
            scan_duration_ms: None,
            scanner_error_count: None,
        });
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
            log_path.clone(),
            None,
        );
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["synthetic-remote".to_string()],
            CapacityLimits::default(),
        );

        sinks
            .persist_for_durable_replay(std::slice::from_ref(&event))
            .expect("persist original event");
        sinks
            .persist_for_durable_replay(std::slice::from_ref(&alert))
            .expect("persist delivery alert");

        let lines = fs::read_to_string(&log_path)
            .expect("canonical JSONL")
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSONL event"))
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines
                .iter()
                .filter(|line| line["event_id"] == event.event_id)
                .count(),
            1
        );
        assert_eq!(
            lines
                .iter()
                .filter(|line| line["event_id"] == alert.event_id)
                .count(),
            1
        );

        let outbox = Outbox::open(outbox_path).expect("reopen outbox");
        assert!(
            outbox
                .get_event(&event.event_id)
                .expect("original event")
                .is_some()
        );
        assert!(
            outbox
                .get_event(&alert.event_id)
                .expect("alert event")
                .is_some()
        );
        assert!(
            outbox
                .get_delivery(&alert.event_id, "synthetic-remote")
                .expect("alert delivery lookup")
                .is_none(),
            "sink-delivery alerts must not become durable replay work"
        );
    }

    #[test]
    fn full_capacity_rejects_delivery_alert_before_append_without_recursion() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let event = make_health_event();
        let alert = operational_alert_event(OperationalAlertInput {
            alert_type: "sink_delivery_failure".to_string(),
            threshold: "attempts_made=1".to_string(),
            actual_value: "sink=failed-remote type=synthetic class=transport_no_response"
                .to_string(),
            scan_duration_ms: None,
            scanner_error_count: None,
        });
        let (failed, failed_calls) = ScriptedDurableSink::new(
            "failed-remote",
            [ScriptedOutcome::Failure(
                DeliveryErrorClass::AuthenticationBlocked { status: 403 },
            )],
        );
        let (healthy, healthy_calls, healthy_alert_calls) =
            ScriptedDurableSink::new_with_alerts("healthy-remote", [ScriptedOutcome::Success]);
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
            log_path.clone(),
            None,
        );
        sinks.add_best_effort_with_retry("synthetic", Box::new(healthy), retry_config(1, 1));
        sinks.add_best_effort_with_retry("synthetic", Box::new(failed), retry_config(1, 1));
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["failed-remote".to_string(), "healthy-remote".to_string()],
            capacity_limits(1, u64::MAX),
        );

        sinks
            .persist_for_durable_replay(std::slice::from_ref(&event))
            .expect("persist original event");
        let failures = sinks
            .dispatch_durable_with_clock(&FakeClock::new(7_000))
            .expect("record failed delivery");
        assert_eq!(failures.len(), 1);
        let before = fs::read(&log_path).expect("canonical JSONL before alert");

        let error = sinks
            .persist_for_durable_replay(std::slice::from_ref(&alert))
            .expect_err("full capacity must reject alert before append");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured capacity error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert_eq!(
            fs::read(&log_path).expect("unchanged canonical JSONL"),
            before
        );

        let failed_names = failures
            .iter()
            .map(|failure| failure.name.as_str())
            .collect::<Vec<_>>();
        sinks.deliver_alerts(std::slice::from_ref(&alert), &failed_names);
        assert_eq!(failed_calls.lock().expect("failed calls").len(), 1);
        assert_eq!(healthy_calls.lock().expect("healthy calls").len(), 1);
        assert_eq!(*healthy_alert_calls.lock().expect("healthy alert calls"), 0);

        let outbox = Outbox::open(outbox_path).expect("reopen outbox");
        assert!(
            outbox
                .get_event(&event.event_id)
                .expect("original event")
                .is_some()
        );
        assert!(
            outbox
                .get_event(&alert.event_id)
                .expect("alert event")
                .is_none()
        );
    }

    #[test]
    fn durable_delivery_failure_alert_is_one_time_and_reaches_healthy_sinks() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let event = make_health_event();
        let (failed, failed_calls) = ScriptedDurableSink::new(
            "failed-remote",
            [ScriptedOutcome::Failure(
                DeliveryErrorClass::TransportNoResponse,
            )],
        );
        let (healthy, healthy_calls, healthy_alert_calls) =
            ScriptedDurableSink::new_with_alerts("healthy-remote", [ScriptedOutcome::Success]);
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
            log_path.clone(),
            None,
        );
        sinks.add_best_effort_with_retry("synthetic", Box::new(failed), retry_config(1, 1));
        sinks.add_best_effort_with_retry("synthetic", Box::new(healthy), retry_config(1, 1));
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["failed-remote".to_string(), "healthy-remote".to_string()],
            CapacityLimits::default(),
        );

        sinks
            .persist_for_durable_replay(std::slice::from_ref(&event))
            .expect("admit source event");
        let failures = sinks
            .dispatch_durable_with_clock(&FakeClock::new(8_000))
            .expect("record one failed sink and one healthy sink");
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].name, "failed-remote");
        assert_eq!(failed_calls.lock().expect("failed calls").len(), 1);
        assert_eq!(healthy_calls.lock().expect("healthy calls").len(), 1);

        let alert = operational_alert_event(OperationalAlertInput {
            alert_type: "sink_delivery_failure".to_string(),
            threshold: format!("attempts_made={}", failures[0].attempts),
            actual_value: format!(
                "sink={} type={} class={}",
                failures[0].name,
                failures[0].kind,
                failures[0].class.as_str()
            ),
            scan_duration_ms: None,
            scanner_error_count: None,
        });
        assert_eq!(alert.check_name.as_deref(), Some("sink_delivery"));
        sinks
            .persist_for_durable_replay(std::slice::from_ref(&alert))
            .expect("admit operational alert once");
        sinks.deliver_alerts(std::slice::from_ref(&alert), &[failures[0].name.as_str()]);
        assert_eq!(
            *healthy_alert_calls.lock().expect("healthy alert calls"),
            1,
            "healthy durable sink receives the one-time operational signal"
        );
        assert_eq!(failed_calls.lock().expect("failed calls").len(), 1);

        let outbox = Outbox::open(&outbox_path).expect("reopen alert outbox");
        assert!(
            outbox
                .get_delivery(&alert.event_id, "failed-remote")
                .expect("failed alert delivery lookup")
                .is_none()
        );
        assert!(
            outbox
                .get_delivery(&alert.event_id, "healthy-remote")
                .expect("healthy alert delivery lookup")
                .is_none()
        );
        drop(outbox);

        for _ in 0..3 {
            assert!(
                sinks
                    .dispatch_durable_with_clock(&FakeClock::new(8_000))
                    .expect("later durable cycle")
                    .is_empty(),
                "delivery-failure alerts must not recurse into later cycles"
            );
        }
        assert_eq!(*healthy_alert_calls.lock().expect("healthy alert calls"), 1);
    }

    #[test]
    fn persistent_replay_rejects_uncertain_capacity_before_append() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let first = marked_event("TT_CAPACITY_SINK_UNCERTAIN_FIRST_26");
        let second = marked_event("TT_CAPACITY_SINK_UNCERTAIN_SECOND_26");
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
            log_path.clone(),
            None,
        );
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["remote".to_string()],
            capacity_limits(10, u64::MAX),
        );
        sinks
            .persist_for_durable_replay(std::slice::from_ref(&first))
            .expect("initialize durable journal metadata");

        fs::OpenOptions::new()
            .write(true)
            .open(&log_path)
            .expect("open journal for deterministic truncation")
            .set_len(0)
            .expect("truncate journal");
        let after_truncation = fs::read(&log_path).expect("truncated JSONL");
        let error = sinks
            .persist_for_durable_replay(std::slice::from_ref(&second))
            .expect_err("uncertain journal capacity must fail closed");
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("structured durable storage error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(delivery.message.len() <= 200);
        assert!(!delivery.message.contains("TT_CAPACITY_SINK"));
        assert_eq!(
            fs::read(&log_path).expect("journal unchanged"),
            after_truncation
        );

        let outbox = Outbox::open(outbox_path).expect("reopen outbox");
        assert!(
            outbox
                .get_event(&second.event_id)
                .expect("second event lookup")
                .is_none()
        );
    }

    #[test]
    fn persistent_replay_delivers_canonical_jsonl_only_once() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let event = make_health_event();
        let sink = LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled());
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(sink),
            log_path.clone(),
            None,
        );
        sinks.enable_persistent_replay_with_capacity(
            outbox_path,
            vec!["remote".to_string()],
            super::outbox::CapacityLimits::default(),
        );

        sinks
            .persist_for_durable_replay(std::slice::from_ref(&event))
            .expect("persistent handoff");
        sinks
            .deliver_best_effort(std::slice::from_ref(&event))
            .expect("best-effort delivery");

        let output = std::fs::read_to_string(log_path).expect("canonical JSONL");
        assert_eq!(output.lines().count(), 1);
    }

    #[test]
    fn persistent_replay_survives_best_effort_failure_after_state_handoff() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("events.jsonl");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let state_path = directory.path().join("state.json");
        let event = make_health_event();
        let canonical = LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled());
        let (remote, _) = FailingSink::new("best-effort-remote");
        let (durable, _) = RecordingSink::new("durable-remote");
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write_path_with_rotation(
            "jsonl",
            Box::new(canonical),
            log_path.clone(),
            None,
        );
        sinks.add_best_effort("synthetic", Box::new(remote));
        sinks.add_best_effort("synthetic", Box::new(durable));
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["durable-remote".to_string()],
            super::outbox::CapacityLimits::default(),
        );

        sinks
            .persist_for_durable_replay(std::slice::from_ref(&event))
            .expect("durable persistence");
        crate::state::ScanState::default()
            .prepare_atomic_save(&state_path)
            .expect("prepare scanner state")
            .install_replace(&state_path)
            .expect("install scanner state");
        let failures = sinks
            .deliver_best_effort(std::slice::from_ref(&event))
            .expect("best-effort failure is reported");
        assert_eq!(failures.len(), 1);

        assert_eq!(
            std::fs::read_to_string(log_path)
                .expect("JSONL")
                .lines()
                .count(),
            1
        );
        let outbox = Outbox::open(outbox_path).expect("reopen outbox");
        assert!(
            outbox
                .get_event(&event.event_id)
                .expect("outbox event")
                .is_some()
        );
        assert_eq!(
            outbox
                .get_delivery(&event.event_id, "durable-remote")
                .expect("outbox delivery")
                .expect("pending delivery")
                .state,
            DeliveryState::Pending
        );
    }

    #[test]
    fn durable_retryable_failure_waits_for_the_fake_clock_before_ack() {
        let directory = tempdir().expect("temporary directory");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let event = make_health_event();
        seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");

        let (sink, calls) = ScriptedDurableSink::new(
            "remote",
            [
                ScriptedOutcome::Failure(DeliveryErrorClass::TransportNoResponse),
                ScriptedOutcome::Success,
            ],
        );
        let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 100));
        let clock = FakeClock::new(1_000);

        let failures = sinks
            .dispatch_durable_with_clock(&clock)
            .expect("schedule retry");
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].class, DeliveryErrorClass::TransportNoResponse);
        assert_eq!(calls.lock().expect("calls lock").len(), 1);

        let outbox = Outbox::open(&outbox_path).expect("reopen outbox");
        let row = outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("pending row");
        assert_eq!(row.state, DeliveryState::Pending);
        assert_eq!(row.next_attempt_at, Some(1_100));
        assert_eq!(
            row.last_error_class,
            Some(DeliveryErrorClass::TransportNoResponse)
        );
        assert!(
            outbox
                .next_ready_delivery("remote", clock.now_millis())
                .expect("ready lookup")
                .is_none()
        );
        drop(outbox);

        sinks
            .dispatch_durable_with_clock(&clock)
            .expect("not due dispatch");
        assert_eq!(calls.lock().expect("calls lock").len(), 1);

        clock.advance(100);
        let failures = sinks
            .dispatch_durable_with_clock(&clock)
            .expect("retry succeeds");
        assert!(failures.is_empty());
        assert_eq!(calls.lock().expect("calls lock").len(), 2);
        let outbox = Outbox::open(&outbox_path).expect("reopen acked outbox");
        let row = outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("acked row");
        assert_eq!(row.state, DeliveryState::Acked);
        assert_eq!(row.next_attempt_at, None);
    }

    #[test]
    fn pending_retry_time_survives_outbox_and_sink_set_restart() {
        let directory = tempdir().expect("temporary directory");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let event = make_health_event();
        seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");
        let clock = FakeClock::new(2_000);

        let (first_sink, first_calls) = ScriptedDurableSink::new(
            "remote",
            [ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus {
                status: 503,
            })],
        );
        {
            let sinks = durable_sink_set(&outbox_path, first_sink, retry_config(3, 250));
            sinks
                .dispatch_durable_with_clock(&clock)
                .expect("schedule retry before restart");
        }
        assert_eq!(first_calls.lock().expect("calls lock").len(), 1);

        let reopened = Outbox::open(&outbox_path).expect("reopen outbox");
        let row = reopened
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("pending row");
        assert_eq!(row.state, DeliveryState::Pending);
        assert_eq!(row.next_attempt_at, Some(2_250));
        drop(reopened);

        let (second_sink, second_calls) =
            ScriptedDurableSink::new("remote", [ScriptedOutcome::Success]);
        let restarted_sinks = durable_sink_set(&outbox_path, second_sink, retry_config(3, 250));
        restarted_sinks
            .dispatch_durable_with_clock(&clock)
            .expect("restart does not send early");
        assert!(second_calls.lock().expect("calls lock").is_empty());

        clock.advance(250);
        restarted_sinks
            .dispatch_durable_with_clock(&clock)
            .expect("restart replays when due");
        assert_eq!(second_calls.lock().expect("calls lock").len(), 1);
        let reopened = Outbox::open(&outbox_path).expect("reopen acked outbox");
        assert_eq!(
            reopened
                .get_delivery(&event.event_id, "remote")
                .expect("delivery row")
                .expect("acked row")
                .state,
            DeliveryState::Acked
        );
    }

    #[test]
    fn http_429_and_5xx_are_pending_until_a_later_success() {
        let directory = tempdir().expect("temporary directory");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let event = make_health_event();
        seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");

        let (sink, calls) = ScriptedDurableSink::new(
            "remote",
            [
                ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 429 }),
                ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 503 }),
                ScriptedOutcome::Success,
            ],
        );
        let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 10));
        let clock = FakeClock::new(3_000);

        sinks
            .dispatch_durable_with_clock(&clock)
            .expect("schedule 429 retry");
        let outbox = Outbox::open(&outbox_path).expect("reopen after 429");
        let row = outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("pending row");
        assert_eq!(row.state, DeliveryState::Pending);
        assert_eq!(row.next_attempt_at, Some(3_010));
        assert_eq!(
            row.last_error_class,
            Some(DeliveryErrorClass::HttpStatus { status: 429 })
        );
        drop(outbox);

        clock.advance(10);
        sinks
            .dispatch_durable_with_clock(&clock)
            .expect("schedule 5xx retry");
        let outbox = Outbox::open(&outbox_path).expect("reopen after 5xx");
        let row = outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("pending row");
        assert_eq!(row.state, DeliveryState::Pending);
        assert_eq!(row.next_attempt_at, Some(3_030));
        assert_eq!(
            row.last_error_class,
            Some(DeliveryErrorClass::HttpStatus { status: 503 })
        );
        drop(outbox);

        clock.advance(20);
        sinks
            .dispatch_durable_with_clock(&clock)
            .expect("5xx retry succeeds");
        assert_eq!(calls.lock().expect("calls lock").len(), 3);
        let outbox = Outbox::open(&outbox_path).expect("reopen successful outbox");
        assert_eq!(
            outbox
                .get_delivery(&event.event_id, "remote")
                .expect("delivery row")
                .expect("acked row")
                .state,
            DeliveryState::Acked
        );
    }

    #[test]
    fn authentication_failures_block_until_each_row_is_explicitly_released() {
        let directory = tempdir().expect("temporary directory");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let first = make_health_event();
        let second = make_health_event();
        seed_pending(&outbox_path, &[&first, &second], &["remote"]).expect("seed pending events");
        {
            let mut outbox = Outbox::open(&outbox_path).expect("open seeded outbox");
            outbox
                .record_delivery_at(
                    &first.event_id,
                    "remote",
                    DeliveryUpdate {
                        state: DeliveryState::Pending,
                        attempts: 0,
                        next_attempt_at: None,
                        last_error_class: None,
                        updated_at: 1,
                    },
                )
                .expect("order first authentication failure");
            outbox
                .record_delivery_at(
                    &second.event_id,
                    "remote",
                    DeliveryUpdate {
                        state: DeliveryState::Pending,
                        attempts: 0,
                        next_attempt_at: None,
                        last_error_class: None,
                        updated_at: 2,
                    },
                )
                .expect("order second authentication failure");
        }

        let (sink, calls) = ScriptedDurableSink::new(
            "remote",
            [
                ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 401 }),
                ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 403 }),
                ScriptedOutcome::Success,
                ScriptedOutcome::Success,
            ],
        );
        let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 10));
        let clock = FakeClock::new(4_000);

        sinks
            .dispatch_durable_with_clock(&clock)
            .expect("block authentication failures");
        let outbox = Outbox::open(&outbox_path).expect("reopen blocked outbox");
        for (event, status) in [(&first, 401), (&second, 403)] {
            let row = outbox
                .get_delivery(&event.event_id, "remote")
                .expect("delivery row")
                .expect("blocked row");
            assert_eq!(row.state, DeliveryState::Blocked);
            assert_eq!(row.next_attempt_at, None);
            assert_eq!(
                row.last_error_class,
                Some(DeliveryErrorClass::AuthenticationBlocked { status })
            );
        }
        assert!(
            outbox
                .next_ready_delivery("remote", clock.now_millis())
                .expect("blocked ready lookup")
                .is_none()
        );
        drop(outbox);
        assert_eq!(calls.lock().expect("calls lock").len(), 2);

        let mut outbox = Outbox::open(&outbox_path).expect("open for first release");
        outbox
            .release_blocked_delivery(&first.event_id, "remote", clock.now_millis())
            .expect("release first blocked row");
        drop(outbox);
        sinks
            .dispatch_durable_with_clock(&clock)
            .expect("deliver released first row");
        assert_eq!(calls.lock().expect("calls lock").len(), 3);

        let mut outbox = Outbox::open(&outbox_path).expect("open for second release");
        outbox
            .release_blocked_delivery(&second.event_id, "remote", clock.now_millis())
            .expect("release second blocked row");
        drop(outbox);
        sinks
            .dispatch_durable_with_clock(&clock)
            .expect("deliver released second row");
        assert_eq!(calls.lock().expect("calls lock").len(), 4);

        let outbox = Outbox::open(&outbox_path).expect("reopen released outbox");
        assert_eq!(
            outbox
                .get_delivery(&first.event_id, "remote")
                .expect("first delivery")
                .expect("first row")
                .state,
            DeliveryState::Acked
        );
        assert_eq!(
            outbox
                .get_delivery(&second.event_id, "remote")
                .expect("second delivery")
                .expect("second row")
                .state,
            DeliveryState::Acked
        );
    }

    #[test]
    fn poison_delivery_is_dead_but_does_not_wedge_a_later_valid_event() {
        let directory = tempdir().expect("temporary directory");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let poison = make_health_event();
        let valid = make_health_event();
        seed_pending(&outbox_path, &[&poison, &valid], &["remote"]).expect("seed pending events");
        {
            let mut outbox = Outbox::open(&outbox_path).expect("open seeded outbox");
            outbox
                .record_delivery_at(
                    &poison.event_id,
                    "remote",
                    DeliveryUpdate {
                        state: DeliveryState::Pending,
                        attempts: 0,
                        next_attempt_at: None,
                        last_error_class: None,
                        updated_at: 1,
                    },
                )
                .expect("order poison first");
            outbox
                .record_delivery_at(
                    &valid.event_id,
                    "remote",
                    DeliveryUpdate {
                        state: DeliveryState::Pending,
                        attempts: 0,
                        next_attempt_at: None,
                        last_error_class: None,
                        updated_at: 2,
                    },
                )
                .expect("order valid second");
        }

        let (sink, calls) = ScriptedDurableSink::new(
            "remote",
            [
                ScriptedOutcome::Failure(DeliveryErrorClass::SinkApplicationRejected),
                ScriptedOutcome::Success,
            ],
        );
        let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 10));
        let clock = FakeClock::new(5_000);
        sinks
            .dispatch_durable_with_clock(&clock)
            .expect("quarantine poison and deliver valid event");

        let outbox = Outbox::open(&outbox_path).expect("reopen poison outbox");
        let poison_row = outbox
            .get_delivery(&poison.event_id, "remote")
            .expect("poison delivery")
            .expect("poison row");
        assert_eq!(poison_row.state, DeliveryState::Dead);
        assert_eq!(
            poison_row.last_error_class,
            Some(DeliveryErrorClass::SinkApplicationRejected)
        );
        assert_eq!(
            outbox
                .get_delivery(&valid.event_id, "remote")
                .expect("valid delivery")
                .expect("valid row")
                .state,
            DeliveryState::Acked
        );
        assert_eq!(calls.lock().expect("calls lock").len(), 2);
    }

    #[test]
    fn retryable_failure_at_max_attempts_becomes_dead() {
        let directory = tempdir().expect("temporary directory");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let event = make_health_event();
        seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");

        let (sink, calls) = ScriptedDurableSink::new(
            "remote",
            [
                ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 503 }),
                ScriptedOutcome::Failure(DeliveryErrorClass::HttpStatus { status: 503 }),
            ],
        );
        let sinks = durable_sink_set(&outbox_path, sink, retry_config(2, 10));
        let clock = FakeClock::new(6_000);
        sinks
            .dispatch_durable_with_clock(&clock)
            .expect("schedule final retry");
        clock.advance(10);
        sinks
            .dispatch_durable_with_clock(&clock)
            .expect("dead-letter exhausted retry");

        let outbox = Outbox::open(&outbox_path).expect("reopen exhausted outbox");
        let row = outbox
            .get_delivery(&event.event_id, "remote")
            .expect("delivery row")
            .expect("dead row");
        assert_eq!(row.state, DeliveryState::Dead);
        assert_eq!(row.next_attempt_at, None);
        assert_eq!(row.attempts, 2);
        assert_eq!(
            row.last_error_class,
            Some(DeliveryErrorClass::HttpStatus { status: 503 })
        );
        assert_eq!(calls.lock().expect("calls lock").len(), 2);
    }

    #[test]
    fn durable_sinks_keep_success_and_blocked_states_independent() {
        let directory = tempdir().expect("temporary directory");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let event = make_health_event();
        seed_pending(&outbox_path, &[&event], &["healthy", "blocked"])
            .expect("seed multi-sink event");

        let (healthy, healthy_calls) =
            ScriptedDurableSink::new("healthy", [ScriptedOutcome::Success]);
        let (blocked, blocked_calls) = ScriptedDurableSink::new(
            "blocked",
            [ScriptedOutcome::Failure(
                DeliveryErrorClass::AuthenticationBlocked { status: 403 },
            )],
        );
        let mut sinks = SinkSet::new();
        sinks.add_best_effort_with_retry("synthetic", Box::new(healthy), retry_config(3, 10));
        sinks.add_best_effort_with_retry("synthetic", Box::new(blocked), retry_config(3, 10));
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["healthy".to_string(), "blocked".to_string()],
            CapacityLimits::default(),
        );
        let clock = FakeClock::new(7_000);

        let failures = sinks
            .dispatch_durable_with_clock(&clock)
            .expect("independent sink dispatch");
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].name, "blocked");
        assert_eq!(healthy_calls.lock().expect("healthy calls").len(), 1);
        assert_eq!(blocked_calls.lock().expect("blocked calls").len(), 1);

        let outbox = Outbox::open(&outbox_path).expect("reopen multi-sink outbox");
        assert_eq!(
            outbox
                .get_delivery(&event.event_id, "healthy")
                .expect("healthy delivery")
                .expect("healthy row")
                .state,
            DeliveryState::Acked
        );
        let blocked_row = outbox
            .get_delivery(&event.event_id, "blocked")
            .expect("blocked delivery")
            .expect("blocked row");
        assert_eq!(blocked_row.state, DeliveryState::Blocked);
        assert_eq!(
            blocked_row.last_error_class,
            Some(DeliveryErrorClass::AuthenticationBlocked { status: 403 })
        );
    }

    #[test]
    fn crash_after_remote_success_before_ack_replays_without_loss() {
        let directory = tempdir().expect("temporary directory");
        let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
        let event = make_health_event();
        seed_pending(&outbox_path, &[&event], &["remote"]).expect("seed pending event");

        let (sink, calls) = ScriptedDurableSink::new(
            "remote",
            [ScriptedOutcome::Success, ScriptedOutcome::Success],
        );
        let ready = {
            let outbox = Outbox::open(&outbox_path).expect("open pending outbox");
            outbox
                .next_ready_delivery("remote", 8_000)
                .expect("ready lookup")
                .expect("ready delivery")
        };
        sink.emit_canonical_once(&ready.payload)
            .expect("simulate receiver success");
        assert_eq!(calls.lock().expect("calls lock").len(), 1);

        let outbox = Outbox::open(&outbox_path).expect("reopen after simulated crash");
        assert_eq!(
            outbox
                .get_delivery(&event.event_id, "remote")
                .expect("delivery row")
                .expect("pending row")
                .state,
            DeliveryState::Pending
        );
        drop(outbox);

        let sinks = durable_sink_set(&outbox_path, sink, retry_config(3, 10));
        sinks
            .dispatch_durable_with_clock(&FakeClock::new(8_000))
            .expect("replay after restart");
        let calls = calls.lock().expect("calls lock");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
        drop(calls);

        let outbox = Outbox::open(&outbox_path).expect("reopen acknowledged outbox");
        assert_eq!(
            outbox
                .get_delivery(&event.event_id, "remote")
                .expect("delivery row")
                .expect("acked row")
                .state,
            DeliveryState::Acked
        );
    }
}

#[cfg(test)]
mod platform_tests {
    use tempfile::tempdir;

    use super::outbox::{CapacityLimits, WINDOWS_DURABLE_STORAGE_UNSUPPORTED};
    use super::{
        DeliveryError, DeliveryErrorClass, EventSink, LocalJsonlSink, RotationConfig, SinkSet,
        durable_health_json_from_path_for_platform,
    };
    use crate::event::{HealthEventInput, health_event_with_metadata};

    fn health_event() -> crate::event::Event {
        health_event_with_metadata(HealthEventInput {
            sources: &[],
            source_inventory_change: None,
            scan_duration_ms: 1,
            rule_count: 1,
            threshold_config: crate::scoring::load_thresholds(),
            active_policy_name: None,
            emitted_count: 0,
            suppressed_count: 0,
            scanner_error_count: 0,
        })
    }

    fn assert_windows_storage_error(error: Box<dyn std::error::Error>) {
        let delivery = error
            .downcast_ref::<DeliveryError>()
            .expect("Windows durable policy must return a structured delivery error");
        assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
        assert!(
            error
                .to_string()
                .contains(WINDOWS_DURABLE_STORAGE_UNSUPPORTED)
        );
    }

    #[test]
    fn simulated_windows_durable_admission_rejects_before_jsonl_append_or_outbox_creation() {
        let temp = tempdir().expect("temporary directory");
        let log_path = temp.path().join("events.jsonl");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");
        let mut sinks = SinkSet::new();
        sinks.add_canonical_first_write(
            "jsonl",
            Box::new(LocalJsonlSink::with_rotation(
                &log_path,
                RotationConfig::disabled(),
            )),
        );
        sinks.add_best_effort("synthetic", Box::new(NoopSink));
        sinks.enable_persistent_replay_with_capacity(
            outbox_path.clone(),
            vec!["synthetic".to_string()],
            CapacityLimits::default(),
        );

        let error = sinks
            .persist_for_durable_replay_with_failures_for_platform(&[health_event()], true)
            .expect_err("Windows durable admission must be rejected");
        assert_windows_storage_error(error);
        assert!(!log_path.exists());
        assert!(!outbox_path.parent().expect("outbox parent").exists());
        assert!(!outbox_path.exists());
    }

    #[test]
    fn simulated_windows_durable_health_reports_rejection_without_opening_storage() {
        let temp = tempdir().expect("temporary directory");
        let outbox_path = temp.path().join("private").join("outbox.sqlite");

        let health = durable_health_json_from_path_for_platform(&outbox_path, &[], true);
        assert_eq!(health["mode"], "unavailable");
        assert_eq!(health["error"]["class"], "durable_storage");
        assert_eq!(
            health["error"]["message"],
            super::outbox::WINDOWS_DURABLE_STORAGE_UNSUPPORTED
        );
        assert_eq!(
            DeliveryError::new(
                DeliveryErrorClass::DurableStorage,
                0,
                super::outbox::WINDOWS_DURABLE_STORAGE_UNSUPPORTED,
            )
            .to_string(),
            format!(
                "{} (after 0 attempts)",
                super::outbox::WINDOWS_DURABLE_STORAGE_UNSUPPORTED
            )
        );
        assert!(!outbox_path.parent().expect("outbox parent").exists());
        assert!(!outbox_path.exists());
    }

    struct NoopSink;

    impl EventSink for NoopSink {
        fn name(&self) -> &str {
            "synthetic"
        }

        fn emit(&self, _events: &[crate::event::Event]) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }
}
