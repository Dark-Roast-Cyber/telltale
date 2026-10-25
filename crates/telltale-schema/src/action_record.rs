//! Action record v1: the versioned, serializable form of one action finding.
//!
//! An embedding host forwards this record across its own process boundary
//! instead of designing a wire format from facade accessors. Telltale owns the
//! record's semantics and validation; the host owns the envelope around it
//! (delivery identity, tenancy, transport version). Event 3.0 is unchanged and
//! remains the session-scoped event contract.
//!
//! A record is versioned as a whole: adding, removing, or redefining a field
//! is a new record version and a new type, never an edit of this one.
//!
//! Hosts also get the record's delivery key and the check that it travels
//! with its session event from here, so neither is re-derived per host.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::LazyLock;

use jsonschema::{Validator, validator_for};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::event::{
    EVENT3_MAX_INPUT_BYTES, Event3Family, Event3Record, parse_event_timestamp,
    redact_sensitive_text, terminal_historical_session_id, terminal_historical_tool_label,
    validate_rule_ids,
};
use crate::observation::{
    JsonValue, ObservationFamily, ObservationStage, canonical_identity_json, valid_observation_id,
};
use crate::scoring::RiskContributionType;

const DELIVERY_KEY_PREFIX: &str = "delivery:v1:sha256:";

/// Value of the `schema` field of every v1 record.
pub const ACTION_RECORD_V1_ID: &str = "telltale.action.v1";

/// JSON Schema (Draft 2020-12) for action record v1, for non-Rust consumers.
pub const ACTION_RECORD_V1_SCHEMA: &str = include_str!("../data/action-record-v1.schema.json");

/// Maximum input accepted by [`ActionRecordV1::from_json`], the same bound as
/// one serialized Event 3.0 object.
pub const ACTION_RECORD_MAX_INPUT_BYTES: usize = EVENT3_MAX_INPUT_BYTES;

const MAX_REDACTED_TEXT_BYTES: usize = 512;
const MAX_CONTEXT_TEXT_BYTES: usize = 32 * 1024;

static VALIDATOR: LazyLock<Result<Validator, ()>> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(ACTION_RECORD_V1_SCHEMA).map_err(|_| ())?;
    validator_for(&schema).map_err(|_| ())
});

/// One terminal action finding. Every field is always serialized; absent
/// values are `null`. Text is redacted and identifiers are terminal, exactly
/// as the facade's `ActionFinding` accessors return them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRecordV1 {
    /// Always [`ACTION_RECORD_V1_ID`].
    pub schema: String,
    pub telltale_version: String,
    /// Effective semantic identity of the scan (`semantic:v1:sha256:…`). A
    /// change means the host should rebaseline, not that history changed.
    pub semantic_identity: String,
    pub client: String,
    pub source_id: String,
    /// SHA-256 of the source path, as Event 3.0 `source_path_hash`.
    pub source_path_hash: String,
    pub session_id: Option<String>,
    /// `event_id` of the session Event 3.0 object projected for this action in
    /// the same scan. Event IDs are fresh per scan, so this links records and
    /// events delivered together; it is never guessed.
    pub session_event_id: Option<String>,
    /// Host-facing action group (`obs:v2:sha256:…`); bind it to the source for
    /// deduplication, since equal coordinates do not distinguish stores.
    pub coordinate: String,
    /// Optional replay identity (`replay:v1:sha256:…`); absent without source
    /// time or when ambiguous. Never substitute an invented value.
    pub replay_identity: Option<String>,
    pub detector_kind: String,
    pub finding_kind: String,
    pub observation_family: ObservationFamily,
    /// Observed stage. A requested or proposed tool call is not proof of
    /// operating-system execution.
    pub stage: ObservationStage,
    pub tool_name: Option<String>,
    /// Source-reported time only; never filled from session or scan time.
    pub occurred_at: Option<String>,
    pub timeline_index: u64,
    pub severity: String,
    /// Sum of `contributions`. Distinct from native finding risk and from the
    /// session Event 3.0 `risk_score`.
    pub promotion_score: u64,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub contributions: Vec<ActionRecordContribution>,
    pub evidence: Vec<ActionRecordEvidence>,
    pub supporting_observation_ids: Vec<String>,
    pub canonical_findings: Vec<ActionRecordFinding>,
    /// Same-pass context; empty unless the scan options enabled it.
    pub context: Vec<ActionRecordContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRecordContribution {
    pub id: String,
    #[serde(rename = "type")]
    pub contribution_type: RiskContributionType,
    pub points: u64,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRecordEvidence {
    pub field: String,
    pub rule_id: String,
    pub redacted_value: String,
}

/// A native finding behind the action, with its own risk points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRecordFinding {
    pub finding_id: String,
    pub signal_ids: Vec<String>,
    pub observation_ids: Vec<String>,
    pub detector_id: String,
    pub finding_kind: String,
    pub category: String,
    pub severity: String,
    pub risk_points: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRecordContext {
    pub offset: i32,
    pub kind: String,
    pub stage: ObservationStage,
    pub occurred_at: Option<String>,
    pub tool_name: Option<String>,
    pub redacted_text: String,
}

/// Stable error categories of the action record consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionRecordErrorCategory {
    Malformed,
    Version,
    Structure,
    Identity,
    Semantic,
}

/// Privacy-safe consumer error: a category and a code-owned constant, never
/// input text, a path, or a serde diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionRecordError {
    category: ActionRecordErrorCategory,
    code: &'static str,
}

impl ActionRecordError {
    const fn new(category: ActionRecordErrorCategory, code: &'static str) -> Self {
        Self { category, code }
    }

    pub const fn category(self) -> ActionRecordErrorCategory {
        self.category
    }

    pub const fn code(self) -> &'static str {
        self.code
    }
}

impl fmt::Display for ActionRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "action record error: {}", self.code)
    }
}

impl std::error::Error for ActionRecordError {}

fn structure(code: &'static str) -> ActionRecordError {
    ActionRecordError::new(ActionRecordErrorCategory::Structure, code)
}

fn identity(code: &'static str) -> ActionRecordError {
    ActionRecordError::new(ActionRecordErrorCategory::Identity, code)
}

fn semantic(code: &'static str) -> ActionRecordError {
    ActionRecordError::new(ActionRecordErrorCategory::Semantic, code)
}

impl ActionRecordV1 {
    /// Parse and validate one complete record from another process. Rejects
    /// oversized input, other versions, unknown fields, and values that the
    /// producer cannot emit, including text that redaction would still change.
    /// Redaction only grows stricter, so a consumer newer than its producer
    /// may reject text that the older redactor let through.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ActionRecordError> {
        if bytes.len() > ACTION_RECORD_MAX_INPUT_BYTES {
            return Err(structure("input_too_large"));
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|_| {
            ActionRecordError::new(ActionRecordErrorCategory::Malformed, "malformed_json")
        })?;
        check_version(&value)?;
        check_schema(&value)?;
        let record: Self =
            serde_json::from_value(value).map_err(|_| structure("schema_mismatch"))?;
        record.validate_semantics()?;
        Ok(record)
    }

    /// Validate a record built in this process, with the same checks as
    /// [`Self::from_json`].
    pub fn validate(&self) -> Result<(), ActionRecordError> {
        let value = serde_json::to_value(self).map_err(|_| structure("schema_mismatch"))?;
        check_version(&value)?;
        check_schema(&value)?;
        self.validate_semantics()
    }

    /// Key for delivering this action at most once: `delivery:v1:sha256:`
    /// over the semantic identity and `replay_identity` when present,
    /// otherwise the source path hash, `coordinate` and canonical finding IDs.
    /// Equal coordinates alone distinguish neither stores nor the several
    /// process-chain actions one tool call can carry. Rescans under the same
    /// rules give the same key. A new semantic identity gives new keys, so a
    /// rules change delivers again instead of matching results from the old
    /// rules.
    pub fn delivery_key(&self) -> String {
        let mut parts = vec![
            JsonValue::string("telltale:action-delivery-v1"),
            JsonValue::string(&self.semantic_identity),
        ];
        match &self.replay_identity {
            Some(replay) => parts.extend([JsonValue::string("replay"), JsonValue::string(replay)]),
            None => {
                let findings = self
                    .canonical_findings
                    .iter()
                    .map(|finding| finding.finding_id.as_str())
                    .collect::<BTreeSet<_>>();
                parts.extend([
                    JsonValue::string("coordinate"),
                    JsonValue::string(&self.source_path_hash),
                    JsonValue::string(&self.coordinate),
                    JsonValue::Array(findings.into_iter().map(JsonValue::string).collect()),
                ]);
            }
        }
        let bytes = canonical_identity_json(&JsonValue::Array(parts))
            .expect("an array of strings always encodes");
        format!(
            "{DELIVERY_KEY_PREFIX}{}",
            hex::encode(Sha256::digest(bytes))
        )
    }

    /// Check that `event`, a detection or process-chain Event 3 object, may
    /// travel with this record: the same client and source path hash, and
    /// the same session when the record has one. A linked record
    /// (`session_event_id` set) also requires that `event` is that event, of
    /// the family the action projects (process chain for a process-chain
    /// action, otherwise detection), and carries every record rule. An
    /// unlinked record names no event, so pairing it is the host's choice.
    pub fn check_session_event(&self, event: &Event3Record) -> Result<(), ActionRecordError> {
        let (chain, source_path_hash, rule_ids) = match event.family() {
            Event3Family::Detection(detection) => {
                (false, &detection.source_path_hash, &detection.rule_ids)
            }
            Event3Family::ProcessChain(chain) => (true, &chain.source_path_hash, &chain.rule_ids),
            _ => return Err(identity("event_link_mismatch")),
        };
        let common = event.common();
        if common.client != self.client || *source_path_hash != self.source_path_hash {
            return Err(identity("event_source_mismatch"));
        }
        if self
            .session_id
            .as_ref()
            .is_some_and(|id| *id != common.session_id)
        {
            return Err(identity("event_session_mismatch"));
        }
        if let Some(id) = &self.session_event_id
            && (*id != common.event_id
                || chain != (self.detector_kind == "process_chain")
                || !self.rule_ids.iter().all(|rule| rule_ids.contains(rule)))
        {
            return Err(identity("event_link_mismatch"));
        }
        Ok(())
    }

    fn validate_semantics(&self) -> Result<(), ActionRecordError> {
        if !valid_observation_id(&self.coordinate)
            || !self
                .supporting_observation_ids
                .iter()
                .chain(
                    self.canonical_findings
                        .iter()
                        .flat_map(|finding| &finding.observation_ids),
                )
                .all(|id| valid_observation_id(id))
        {
            return Err(identity("invalid_observation_id"));
        }
        if self
            .session_id
            .as_deref()
            .is_some_and(|id| terminal_historical_session_id(id) != id)
        {
            return Err(identity("invalid_session_id"));
        }
        if !self.stage.is_compatible(self.observation_family) {
            return Err(semantic("incompatible_stage"));
        }
        if !valid_optional_time(self.occurred_at.as_deref())
            || !valid_optional_tool(self.tool_name.as_deref())
        {
            return Err(semantic("invalid_time_or_tool"));
        }
        validate_rule_ids(&self.rule_ids).map_err(|_| semantic("invalid_rule_id"))?;
        let sum = self
            .contributions
            .iter()
            .try_fold(0_u64, |total, contribution| {
                total.checked_add(contribution.points)
            });
        if sum != Some(self.promotion_score) {
            return Err(semantic("promotion_score_mismatch"));
        }
        self.validate_accounting()?;
        if self
            .evidence
            .iter()
            .any(|entry| entry.redacted_value.len() > MAX_REDACTED_TEXT_BYTES)
        {
            return Err(semantic("evidence_too_large"));
        }
        let mut context_bytes = 0_usize;
        for entry in &self.context {
            context_bytes = context_bytes.saturating_add(entry.redacted_text.len());
            if entry.redacted_text.len() > MAX_REDACTED_TEXT_BYTES
                || context_bytes > MAX_CONTEXT_TEXT_BYTES
            {
                return Err(semantic("context_too_large"));
            }
            if !valid_optional_time(entry.occurred_at.as_deref())
                || !valid_optional_tool(entry.tool_name.as_deref())
            {
                return Err(semantic("invalid_time_or_tool"));
            }
        }
        // The producer redacts all three with the evidence sanitizer this
        // function wraps; it is idempotent, so redacted text is a fixed point.
        let redacted = |text: &str| redact_sensitive_text(text) == text;
        if !self
            .context
            .iter()
            .map(|entry| entry.redacted_text.as_str())
            .chain(
                self.evidence
                    .iter()
                    .map(|entry| entry.redacted_value.as_str()),
            )
            .chain(
                self.contributions
                    .iter()
                    .map(|entry| entry.rationale.as_str()),
            )
            .all(redacted)
        {
            return Err(semantic("unredacted_text"));
        }
        Ok(())
    }

    /// The action summary must be derivable from its native findings, so a
    /// receiver need not re-implement these cross-checks.
    fn validate_accounting(&self) -> Result<(), ActionRecordError> {
        let inconsistent = || semantic("inconsistent_findings");
        let findings = &self.canonical_findings;
        let distinct =
            |values: &[String]| values.iter().collect::<BTreeSet<_>>().len() == values.len();
        let finding_ids = findings
            .iter()
            .map(|finding| finding.finding_id.as_str())
            .collect::<BTreeSet<_>>();
        let detectors = findings
            .iter()
            .map(|finding| finding.detector_id.as_str())
            .collect::<BTreeSet<_>>();
        let categories = findings
            .iter()
            .map(|finding| finding.category.as_str())
            .collect::<BTreeSet<_>>();
        let observations = findings
            .iter()
            .flat_map(|finding| &finding.observation_ids)
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let strongest = findings
            .iter()
            .map(|finding| severity_rank(&finding.severity))
            .max()
            .flatten();
        let correlated = findings
            .iter()
            .any(|finding| finding.finding_kind == "correlation");
        if finding_ids.len() != findings.len()
            || !distinct(&self.rule_ids)
            || !distinct(&self.categories)
            || self
                .rule_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != detectors
            || self
                .categories
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != categories
            || strongest.is_none()
            || severity_rank(&self.severity) != strongest
            || (self.finding_kind == "correlation") != correlated
            || !distinct(&self.supporting_observation_ids)
            || self
                .supporting_observation_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != observations
            || !self.supporting_observation_ids.contains(&self.coordinate)
            || (self.replay_identity.is_some()
                && (self.occurred_at.is_none() || self.detector_kind == "process_chain"))
        {
            return Err(inconsistent());
        }
        let mut contribution_ids = BTreeSet::new();
        for contribution in &self.contributions {
            let backed = findings.iter().any(|finding| {
                finding.detector_id == contribution.id
                    && finding.risk_points.map(u64::from) == Some(contribution.points)
                    && (finding.finding_kind == "correlation")
                        == (contribution.contribution_type == RiskContributionType::ChainModifier)
            });
            if !contribution_ids.insert(contribution.id.as_str()) || !backed {
                return Err(inconsistent());
            }
        }
        if self
            .evidence
            .iter()
            .any(|entry| !detectors.contains(entry.rule_id.as_str()))
        {
            return Err(inconsistent());
        }
        let offsets = self
            .context
            .iter()
            .map(|entry| entry.offset)
            .collect::<BTreeSet<_>>();
        if offsets.len() != self.context.len() {
            return Err(inconsistent());
        }
        Ok(())
    }
}

fn severity_rank(value: &str) -> Option<usize> {
    ["informational", "low", "medium", "high", "critical"]
        .iter()
        .position(|candidate| *candidate == value)
}

fn check_version(value: &Value) -> Result<(), ActionRecordError> {
    match value.get("schema").and_then(Value::as_str) {
        Some(ACTION_RECORD_V1_ID) => Ok(()),
        _ => Err(ActionRecordError::new(
            ActionRecordErrorCategory::Version,
            "unsupported_record_version",
        )),
    }
}

fn check_schema(value: &Value) -> Result<(), ActionRecordError> {
    let validator = VALIDATOR
        .as_ref()
        .map_err(|_| structure("schema_unavailable"))?;
    if validator.is_valid(value) {
        Ok(())
    } else {
        Err(structure("schema_mismatch"))
    }
}

fn valid_optional_time(value: Option<&str>) -> bool {
    value.is_none_or(|time| parse_event_timestamp(time).is_some())
}

fn valid_optional_tool(value: Option<&str>) -> bool {
    value.is_none_or(|label| terminal_historical_tool_label(label) == label)
}

#[cfg(test)]
#[path = "action_record_tests.rs"]
mod tests;
