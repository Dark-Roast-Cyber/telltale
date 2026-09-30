//! Read-only opportunistic local session context. Event3 is authoritative;
//! current source context and indexes are neither immutable history nor fuzzy matches.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use telltale_detect::timeline::{ExportedSessionTimeline, build_content_free_canonical_timeline};
use telltale_schema::event::{
    Event3Activity, Event3Family, Event3Record, path_hash, terminal_session_id,
};
use telltale_schema::observation::ObservedAt;
use telltale_schema::source::Source;
use telltale_sources::acquisition::{
    AcquisitionError, AcquisitionOptions, BoundedReadError, DirectReadLimits,
    acquire_source_bounded,
};
use telltale_sources::clients::supported_clients;
use telltale_sources::discovery::{BoundedDiscoveryError, discover_sources_bounded};

#[derive(Debug, Clone)]
pub struct InvestigationLimits {
    pub discovery_entries: usize,
    pub source_bytes: usize,
    pub records: usize,
    pub json_depth: usize,
}
impl Default for InvestigationLimits {
    fn default() -> Self {
        Self {
            discovery_entries: 16384,
            source_bytes: 8 * 1024 * 1024,
            records: 8192,
            json_depth: 64,
        }
    }
}

/// Caller-owned discovery context. Known sources are an optional bounded,
/// in-memory snapshot from an earlier discovery, not a persisted index. They
/// distinguish lost sources from events that have never been locally resolvable.
pub struct InvestigationConfig {
    pub root: PathBuf,
    pub known_sources: Vec<Source>,
    pub limits: InvestigationLimits,
}
impl InvestigationConfig {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_owned(),
            known_sources: Vec::new(),
            limits: InvestigationLimits::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvestigationResult {
    Found(InvestigatedSession),
    /// Source context cannot be read, including a deferred provider such as
    /// OpenCode. Provider deferral does not confirm local source existence.
    SourceUnavailable(SourceUnavailableReason),
    SessionUnavailable(SessionUnavailableReason),
    NotLocallyResolvable(NotLocallyResolvableReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceUnavailableReason {
    ReadOnlyProviderUnavailable,
    Missing,
    PermissionDenied,
    Unreadable,
    NonRegularSource,
    LimitExceeded,
    MalformedSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionUnavailableReason {
    ExactSessionAbsent,
    NoTimeline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotLocallyResolvableReason {
    InvalidLimits,
    EventLimitExceeded,
    MissingCorrelation,
    UnsupportedClient,
    UnknownSource,
    AmbiguousSource,
    UnsupportedSource,
    InvalidEventTimestamp,
    DiscoveryLimitExceeded,
    DiscoveryPermissionDenied,
    DiscoveryUnavailable,
    DiscoverySymlinkRoot,
    ConflictingSessionOwnership,
    AmbiguousSession,
}

impl InvestigationResult {
    /// Stable bounded codes only: no paths, content, or diagnostic strings.
    pub fn reason_code(&self) -> Option<&'static str> {
        Some(match self {
            Self::Found(_) => return None,
            Self::SourceUnavailable(reason) => match reason {
                SourceUnavailableReason::ReadOnlyProviderUnavailable => {
                    "read_only_provider_unavailable"
                }
                SourceUnavailableReason::Missing => "source_missing",
                SourceUnavailableReason::PermissionDenied => "source_permission_denied",
                SourceUnavailableReason::Unreadable => "source_unreadable",
                SourceUnavailableReason::NonRegularSource => "non_regular_source",
                SourceUnavailableReason::LimitExceeded => "source_limit_exceeded",
                SourceUnavailableReason::MalformedSource => "malformed_source",
            },
            Self::SessionUnavailable(reason) => match reason {
                SessionUnavailableReason::ExactSessionAbsent => "exact_session_absent",
                SessionUnavailableReason::NoTimeline => "session_has_no_timeline",
            },
            Self::NotLocallyResolvable(reason) => match reason {
                NotLocallyResolvableReason::InvalidLimits => "invalid_limits",
                NotLocallyResolvableReason::EventLimitExceeded => "event_limit_exceeded",
                NotLocallyResolvableReason::MissingCorrelation => "missing_correlation",
                NotLocallyResolvableReason::UnsupportedClient => "unsupported_client",
                NotLocallyResolvableReason::UnknownSource => "unknown_source",
                NotLocallyResolvableReason::AmbiguousSource => "ambiguous_source",
                NotLocallyResolvableReason::UnsupportedSource => "unsupported_source",
                NotLocallyResolvableReason::InvalidEventTimestamp => "invalid_event_timestamp",
                NotLocallyResolvableReason::DiscoveryLimitExceeded => "discovery_limit_exceeded",
                NotLocallyResolvableReason::DiscoveryPermissionDenied => {
                    "discovery_permission_denied"
                }
                NotLocallyResolvableReason::DiscoveryUnavailable => "discovery_unavailable",
                NotLocallyResolvableReason::DiscoverySymlinkRoot => "discovery_symlink_root",
                NotLocallyResolvableReason::ConflictingSessionOwnership => {
                    "conflicting_session_ownership"
                }
                NotLocallyResolvableReason::AmbiguousSession => "ambiguous_session",
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvestigatedSession {
    /// Always content-free, including an empty evidence vector on every entry.
    pub timeline: ExportedSessionTimeline,
    pub anchors: Vec<InvestigationAnchor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvestigationAnchor {
    pub recorded_entry_index: usize,
    /// Present-day entry at that exact index, not proof of historical equality.
    pub current_entry_index: Option<usize>,
}

pub struct SessionInvestigator {
    config: InvestigationConfig,
}
impl SessionInvestigator {
    pub fn new(config: InvestigationConfig) -> Self {
        Self { config }
    }

    pub fn investigate(&self, event: &Event3Record) -> InvestigationResult {
        let direct = DirectReadLimits {
            bytes: self.config.limits.source_bytes,
            records: self.config.limits.records,
            json_depth: self.config.limits.json_depth,
        };
        if !direct.is_valid() || self.config.known_sources.len() > 1024 {
            return InvestigationResult::NotLocallyResolvable(
                NotLocallyResolvableReason::InvalidLimits,
            );
        }
        if event.common().session_id.len() > 256
            || matches!(event.family(), Event3Family::Detection(v) if v.timeline_anchors.len() > direct.records)
        {
            return InvestigationResult::NotLocallyResolvable(
                NotLocallyResolvableReason::EventLimitExceeded,
            );
        }
        let Some(hash) = source_hash(event) else {
            return InvestigationResult::NotLocallyResolvable(
                NotLocallyResolvableReason::MissingCorrelation,
            );
        };
        let Some(client) = supported_clients()
            .iter()
            .find(|def| def.id.as_str() == event.common().client)
            .map(|def| def.id)
        else {
            return InvestigationResult::NotLocallyResolvable(
                NotLocallyResolvableReason::UnsupportedClient,
            );
        };
        // Native OpenCode export initializes/checkpoints/migrates its store.
        // No read-only provider is available; do not discover, read, or spawn.
        if client == telltale_schema::clients::ClientId::OpenCode {
            return InvestigationResult::SourceUnavailable(
                SourceUnavailableReason::ReadOnlyProviderUnavailable,
            );
        }
        let mut sources = match discover_sources_bounded(
            &self.config.root,
            client,
            self.config.limits.discovery_entries,
        ) {
            Ok(sources) => sources,
            Err(error) => {
                return InvestigationResult::NotLocallyResolvable(match error {
                    BoundedDiscoveryError::InvalidLimit => {
                        NotLocallyResolvableReason::InvalidLimits
                    }
                    BoundedDiscoveryError::LimitExceeded => {
                        NotLocallyResolvableReason::DiscoveryLimitExceeded
                    }
                    BoundedDiscoveryError::SymlinkRoot => {
                        NotLocallyResolvableReason::DiscoverySymlinkRoot
                    }
                    BoundedDiscoveryError::PermissionDenied => {
                        NotLocallyResolvableReason::DiscoveryPermissionDenied
                    }
                    BoundedDiscoveryError::Traversal => {
                        NotLocallyResolvableReason::DiscoveryUnavailable
                    }
                });
            }
        };
        sources.extend(
            self.config
                .known_sources
                .iter()
                .filter(|source| source.client == client)
                .cloned(),
        );
        sources.retain(|source| source.client == client && path_hash(&source.path) == hash);
        sources
            .sort_by(|a, b| (&a.source_id, &a.path, a.kind).cmp(&(&b.source_id, &b.path, b.kind)));
        sources.dedup();
        let [source] = sources.as_slice() else {
            return InvestigationResult::NotLocallyResolvable(if sources.is_empty() {
                NotLocallyResolvableReason::UnknownSource
            } else {
                NotLocallyResolvableReason::AmbiguousSource
            });
        };
        let valid = supported_clients()
            .iter()
            .filter(|def| def.id == client)
            .flat_map(|def| def.sources)
            .any(|def| def.id == source.source_id && def.kind == source.kind);
        if !valid
            || !matches!(
                source.kind,
                telltale_schema::clients::SourceKind::Jsonl
                    | telltale_schema::clients::SourceKind::ArchivedJsonl
                    | telltale_schema::clients::SourceKind::HeadlessJsonl
            )
        {
            return InvestigationResult::NotLocallyResolvable(
                NotLocallyResolvableReason::UnsupportedSource,
            );
        }
        let Ok(observed_at) = ObservedAt::new(event.common().observed_at.clone()) else {
            return InvestigationResult::NotLocallyResolvable(
                NotLocallyResolvableReason::InvalidEventTimestamp,
            );
        };
        let options = AcquisitionOptions::new(observed_at);
        let batch = match acquire_source_bounded(source, options, direct) {
            Ok(batch) => batch,
            Err(AcquisitionError::ConflictingSessionOwnership) => {
                return InvestigationResult::NotLocallyResolvable(
                    NotLocallyResolvableReason::ConflictingSessionOwnership,
                );
            }
            Err(error) => {
                return InvestigationResult::SourceUnavailable(source_failure_reason(error));
            }
        };
        let identities = batch
            .accounting
            .sessions
            .iter()
            .map(|session| session.session_id.value())
            .filter(|session| terminal_session_id(session) == event.common().session_id)
            .collect::<BTreeSet<_>>();
        if identities.len() > 1 {
            return InvestigationResult::NotLocallyResolvable(
                NotLocallyResolvableReason::AmbiguousSession,
            );
        }
        let Some(session) = identities.first() else {
            return InvestigationResult::SessionUnavailable(
                SessionUnavailableReason::ExactSessionAbsent,
            );
        };
        let observations = batch
            .observations
            .into_iter()
            .filter(|v| v.session_id().is_some_and(|id| id.value() == *session))
            .collect::<Vec<_>>();
        let Some(timeline) = build_content_free_canonical_timeline(&observations, client.as_str())
        else {
            return InvestigationResult::SessionUnavailable(SessionUnavailableReason::NoTimeline);
        };
        let anchors = if let Event3Family::Detection(detection) = event.family() {
            detection
                .timeline_anchors
                .iter()
                .map(|anchor| InvestigationAnchor {
                    recorded_entry_index: anchor.entry_index,
                    current_entry_index: timeline
                        .entries
                        .get(anchor.entry_index)
                        .map(|entry| entry.index),
                })
                .collect()
        } else {
            Vec::new()
        };
        InvestigationResult::Found(InvestigatedSession { timeline, anchors })
    }
}

fn source_failure_reason(error: AcquisitionError) -> SourceUnavailableReason {
    match error {
        AcquisitionError::BoundedSourceRead(reason) => match reason {
            BoundedReadError::Missing => SourceUnavailableReason::Missing,
            BoundedReadError::PermissionDenied => SourceUnavailableReason::PermissionDenied,
            BoundedReadError::Unreadable => SourceUnavailableReason::Unreadable,
            BoundedReadError::NonRegularSource => SourceUnavailableReason::NonRegularSource,
            BoundedReadError::LimitExceeded => SourceUnavailableReason::LimitExceeded,
            BoundedReadError::MalformedSource => SourceUnavailableReason::MalformedSource,
        },
        AcquisitionError::SourceRead => SourceUnavailableReason::Unreadable,
        AcquisitionError::ContributionCapacity
        | AcquisitionError::AttestationCapacity
        | AcquisitionError::AccountingOverflow => SourceUnavailableReason::LimitExceeded,
        AcquisitionError::InvalidAttestation
        | AcquisitionError::InvalidContribution
        | AcquisitionError::CanonicalMapping { .. }
        | AcquisitionError::CanonicalValidation { .. } => SourceUnavailableReason::MalformedSource,
        // These are rejected before acquisition; keep failure private if reached.
        AcquisitionError::UnsupportedSourceIdentity
        | AcquisitionError::SourceKindMismatch
        | AcquisitionError::ConflictingSessionOwnership => SourceUnavailableReason::MalformedSource,
    }
}

fn source_hash(event: &Event3Record) -> Option<&str> {
    match event.family() {
        Event3Family::Detection(v) => Some(&v.source_path_hash),
        Event3Family::Activity(Event3Activity::Standard(v)) => Some(&v.source_path_hash),
        Event3Family::SessionRiskSummary(v) => v.source_path_hash.as_deref(),
        Event3Family::ProcessChain(v) => Some(&v.source_path_hash),
        _ => None,
    }
}
