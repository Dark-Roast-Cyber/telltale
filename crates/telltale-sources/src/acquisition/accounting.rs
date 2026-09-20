//! Native acquisition facts for the inactive canonical runtime (Issue #51).
//! No cursor policy, baseline state, transcript retention, or exported event schema.

use std::{collections::BTreeMap, fmt};

use serde_json::Value;
use telltale_schema::observation::{CorrelationId, LOCAL_MAX_STRING_BYTES};
use telltale_schema::record::RecordKind;

use super::{AcquisitionError, ActivityContributions};

/// Bounds metadata-only sessions too: these need not emit any observations.
pub const MAX_ATTESTED_SESSIONS: usize = 4096;

#[derive(Clone, Default, Eq, PartialEq)]
pub enum AttestedValue {
    #[default]
    Missing,
    Known(String),
    Ambiguous,
}

impl fmt::Debug for AttestedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "Missing",
            Self::Known(_) => "Known([private])",
            Self::Ambiguous => "Ambiguous",
        })
    }
}

impl AttestedValue {
    pub fn known(&self) -> Option<&str> {
        match self {
            Self::Known(value) => Some(value),
            Self::Missing | Self::Ambiguous => None,
        }
    }

    fn observe(&mut self, value: &Value) -> Result<(), AcquisitionError> {
        let value = match value {
            Value::Null => return Ok(()),
            Value::String(value) => value,
            _ => return Err(AcquisitionError::InvalidAttestation),
        };
        if value.len() > LOCAL_MAX_STRING_BYTES || value.chars().any(char::is_control) {
            return Err(AcquisitionError::InvalidAttestation);
        }
        if value.trim().is_empty() {
            return Ok(());
        }
        match self {
            Self::Missing => *self = Self::Known(value.clone()),
            Self::Known(previous) if previous != value => *self = Self::Ambiguous,
            Self::Known(_) | Self::Ambiguous => {}
        }
        Ok(())
    }

    fn merge(&mut self, other: &Self) {
        match (&*self, other) {
            (_, Self::Missing) | (Self::Ambiguous, _) => {}
            (Self::Missing, _) => *self = other.clone(),
            (_, Self::Ambiguous) => *self = Self::Ambiguous,
            (Self::Known(left), Self::Known(right)) if left != right => *self = Self::Ambiguous,
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SessionMetadata {
    pub agent: AttestedValue,
    pub model: AttestedValue,
    pub provider: AttestedValue,
}

impl SessionMetadata {
    /// Field names and semantic envelope selection belong to the calling adapter.
    pub(crate) fn from_fields(
        value: &Value,
        agent: &[&str],
        model: &[&str],
        provider: &[&str],
    ) -> Result<Self, AcquisitionError> {
        let mut metadata = Self::default();
        for (field, keys) in [
            (&mut metadata.agent, agent),
            (&mut metadata.model, model),
            (&mut metadata.provider, provider),
        ] {
            for key in keys {
                if let Some(value) = value.get(key) {
                    field.observe(value)?;
                }
            }
        }
        Ok(metadata)
    }

    pub(crate) fn merge(&mut self, other: &Self) {
        self.agent.merge(&other.agent);
        self.model.merge(&other.model);
        self.provider.merge(&other.provider);
    }
}

/// Compare only adapter-selected ownership locations, before retaining a candidate.
pub(crate) fn session_identity<'a>(
    candidates: impl IntoIterator<Item = &'a Value>,
) -> Result<Option<String>, AcquisitionError> {
    let mut selected: Option<&str> = None;
    for value in candidates {
        if value.is_null() {
            continue;
        }
        let value = value.as_str().ok_or(AcquisitionError::InvalidAttestation)?;
        if value.is_empty() {
            continue;
        }
        if value.len() > LOCAL_MAX_STRING_BYTES
            || value.chars().any(char::is_control)
            || value.trim().is_empty()
        {
            return Err(AcquisitionError::InvalidAttestation);
        }
        if selected.is_some_and(|previous| previous != value) {
            return Err(AcquisitionError::ConflictingSessionOwnership);
        }
        selected = Some(value);
    }
    Ok(selected.map(str::to_owned))
}

/// Exact native-to-legacy record-kind cardinality, not COv2 family/stage counts.
/// Session attribution is canonical; legacy filename/default grouping is not retained.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct RecordCounts {
    pub user_message: u64,
    pub assistant_message: u64,
    pub tool_call: u64,
    pub tool_result: u64,
    pub session_meta: u64,
    pub other: u64,
}

impl RecordCounts {
    fn increment(&mut self, kind: RecordKind) -> Result<(), AcquisitionError> {
        let count = match kind {
            RecordKind::UserMessage => &mut self.user_message,
            RecordKind::AssistantMessage => &mut self.assistant_message,
            RecordKind::ToolCall => &mut self.tool_call,
            RecordKind::ToolResult => &mut self.tool_result,
            RecordKind::SessionMeta => &mut self.session_meta,
            _ => &mut self.other,
        };
        *count = count
            .checked_add(1)
            .ok_or(AcquisitionError::AccountingOverflow)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct NativeCounts {
    pub native_units: u64,
    pub record_counts: RecordCounts,
    pub contributions: ActivityContributions,
}

impl NativeCounts {
    fn add_unit(&mut self, kinds: &[RecordKind]) -> Result<(), AcquisitionError> {
        self.native_units = self
            .native_units
            .checked_add(1)
            .ok_or(AcquisitionError::AccountingOverflow)?;
        for &kind in kinds {
            self.record_counts.increment(kind)?;
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SessionAccounting {
    pub session_id: CorrelationId,
    pub metadata: SessionMetadata,
    pub counts: NativeCounts,
}

impl fmt::Debug for SessionAccounting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionAccounting")
            .field("session_id", &"[private]")
            .field("metadata", &self.metadata)
            .field("counts", &self.counts)
            .finish()
    }
}

/// Facts about this acquired batch only, never a cumulative session snapshot.
/// Counts outside canonical session scope remain explicitly unscoped.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SourceAccounting {
    pub sessions: Vec<SessionAccounting>,
    pub unscoped: NativeCounts,
}

#[derive(Default)]
pub(super) struct AccountingBuilder {
    // All insertion is SourceReported; no second, origin-less public session key.
    sessions: BTreeMap<String, SessionAccounting>,
    unscoped: NativeCounts,
    contribution_keys: usize,
}

impl AccountingBuilder {
    pub(super) fn record(
        &mut self,
        session: Option<&str>,
        metadata: &Result<SessionMetadata, AcquisitionError>,
        kinds: &[RecordKind],
    ) -> Result<(), AcquisitionError> {
        let metadata = metadata.as_ref().map_err(|error| *error)?;
        let Some(session) = session else {
            return self.unscoped.add_unit(kinds);
        };
        if session.len() > LOCAL_MAX_STRING_BYTES {
            return Err(AcquisitionError::InvalidAttestation);
        }
        if !self.sessions.contains_key(session) {
            if self.sessions.len() >= MAX_ATTESTED_SESSIONS {
                return Err(AcquisitionError::AttestationCapacity);
            }
            let session_id = CorrelationId::source_reported(session)
                .map_err(|_| AcquisitionError::InvalidAttestation)?;
            self.sessions.insert(
                session.to_owned(),
                SessionAccounting {
                    session_id,
                    metadata: SessionMetadata::default(),
                    counts: NativeCounts::default(),
                },
            );
        }
        let entry = self
            .sessions
            .get_mut(session)
            .ok_or(AcquisitionError::InvalidAttestation)?;
        entry.metadata.merge(metadata);
        entry.counts.add_unit(kinds)
    }

    pub(super) fn contribute<'a>(
        &mut self,
        session: Option<&str>,
        kind: RecordKind,
        name: Option<&str>,
        arguments: Option<&str>,
        content: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), AcquisitionError> {
        if kind != RecordKind::ToolCall {
            return Ok(());
        }
        let counts = match session {
            Some(session) => {
                &mut self
                    .sessions
                    .get_mut(session)
                    .ok_or(AcquisitionError::InvalidAttestation)?
                    .counts
            }
            None => &mut self.unscoped,
        };
        counts
            .contributions
            .observe(name, arguments, content, &mut self.contribution_keys)
    }

    pub(super) fn finish(self) -> SourceAccounting {
        SourceAccounting {
            sessions: self.sessions.into_values().collect(),
            unscoped: self.unscoped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acquisition::MAX_CONTRIBUTION_KEYS;

    #[test]
    fn contribution_capacity_is_source_wide_including_unscoped() {
        let mut builder = AccountingBuilder::default();
        for index in 0..MAX_CONTRIBUTION_KEYS {
            let session = format!("s-{}", index % 2);
            builder
                .record(Some(&session), &Ok(SessionMetadata::default()), &[])
                .unwrap();
            builder
                .contribute(
                    Some(&session),
                    RecordKind::ToolCall,
                    Some(&format!("synthetic-{index}")),
                    None,
                    [],
                )
                .unwrap();
        }
        builder
            .record(None, &Ok(SessionMetadata::default()), &[])
            .unwrap();
        assert_eq!(
            builder.contribute(None, RecordKind::ToolCall, Some("synthetic"), None, []),
            Err(AcquisitionError::ContributionCapacity)
        );
        assert_eq!(builder.contribution_keys, MAX_CONTRIBUTION_KEYS);
        assert!(builder.unscoped.contributions.tool_calls.is_empty());
    }

    #[test]
    fn overflow_and_capacity_fail_without_private_diagnostics() {
        let mut counts = NativeCounts {
            native_units: u64::MAX,
            ..Default::default()
        };
        assert_eq!(
            counts.add_unit(&[]),
            Err(AcquisitionError::AccountingOverflow)
        );
        let mut counts = RecordCounts {
            tool_call: u64::MAX,
            ..Default::default()
        };
        assert_eq!(
            counts.increment(RecordKind::ToolCall),
            Err(AcquisitionError::AccountingOverflow)
        );
        let mut builder = AccountingBuilder::default();
        for index in 0..MAX_ATTESTED_SESSIONS {
            builder
                .record(
                    Some(&format!("synthetic-{index}")),
                    &Ok(SessionMetadata::default()),
                    &[],
                )
                .unwrap();
        }
        assert_eq!(
            builder.record(Some("private-marker"), &Ok(SessionMetadata::default()), &[]),
            Err(AcquisitionError::AttestationCapacity)
        );
    }
}
