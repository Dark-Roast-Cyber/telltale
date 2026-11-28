//! Action record v2: the versioned, serializable form of one action finding
//! for every Telltale client.
//!
//! v1 (`telltale.action.v1`) is frozen with a closed six-client vocabulary, so
//! a client added later (Pi, and any after it) has no v1 records. v2 carries
//! the same fields with the same meaning and validation, and differs only in:
//!
//! - `client`: any name in [`ClientId::ALL`] of the consuming build. The JSON
//!   Schema constrains its shape only, so a consumer built before a new client
//!   rejects that client's records with `unknown_client` instead of accepting
//!   a name it cannot interpret. Move producer and consumer pins together.
//! - `destinations`: optional fail-closed upload destination facts
//!   ([`DestinationFacts`]), present only on actions carrying
//!   `exfil.outbound_upload`. Facts never change scores or verdicts.
//!
//! Delivery keys and aliases are byte-identical to v1 for the same action, so
//! a host moving from v1 to v2 does not redeliver anything it already handled.
//! A record version is frozen from the first release tag that carries it.

use std::sync::LazyLock;

use jsonschema::{Validator, validator_for};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::action_record::{
    ACTION_RECORD_MAX_INPUT_BYTES, ACTION_RECORD_V1_ID, ActionRecordContext,
    ActionRecordContribution, ActionRecordError, ActionRecordErrorCategory, ActionRecordEvidence,
    ActionRecordFinding, ActionRecordV1, identity, semantic, structure,
};
use crate::clients::ClientId;
use crate::destination_facts::DestinationFacts;
use crate::event::Event3Record;
use crate::observation::{ObservationFamily, ObservationStage};

/// Value of the `schema` field of every v2 record.
pub const ACTION_RECORD_V2_ID: &str = "telltale.action.v2";

/// JSON Schema (Draft 2020-12) for action record v2, for non-Rust consumers.
pub const ACTION_RECORD_V2_SCHEMA: &str = include_str!("../data/action-record-v2.schema.json");

const DESTINATION_FACTS_RULE_ID: &str = "exfil.outbound_upload";

static VALIDATOR: LazyLock<Result<Validator, ()>> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(ACTION_RECORD_V2_SCHEMA).map_err(|_| ())?;
    validator_for(&schema).map_err(|_| ())
});

/// One terminal action finding. Every field is always serialized; absent
/// values are `null`. Fields shared with [`ActionRecordV1`] keep its meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRecordV2 {
    /// Always [`ACTION_RECORD_V2_ID`].
    pub schema: String,
    pub telltale_version: String,
    pub semantic_identity: String,
    /// A name in [`ClientId::ALL`].
    pub client: String,
    pub source_id: String,
    pub source_path_hash: String,
    pub session_id: Option<String>,
    pub session_event_id: Option<String>,
    pub coordinate: String,
    pub replay_identity: Option<String>,
    pub detector_kind: String,
    pub finding_kind: String,
    pub observation_family: ObservationFamily,
    pub stage: ObservationStage,
    pub tool_name: Option<String>,
    pub occurred_at: Option<String>,
    pub timeline_index: u64,
    pub severity: String,
    pub promotion_score: u64,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub contributions: Vec<ActionRecordContribution>,
    pub evidence: Vec<ActionRecordEvidence>,
    pub supporting_observation_ids: Vec<String>,
    pub canonical_findings: Vec<ActionRecordFinding>,
    pub context: Vec<ActionRecordContext>,
    /// Upload destination facts; only with `exfil.outbound_upload`.
    pub destinations: Option<DestinationFacts>,
}

impl ActionRecordV2 {
    /// The v2 form of a v1 record with the v2-only field. The v1 record's
    /// client is not checked here; [`Self::validate`] checks the result.
    pub fn from_v1(record: ActionRecordV1, destinations: Option<DestinationFacts>) -> Self {
        let ActionRecordV1 {
            schema: _,
            telltale_version,
            semantic_identity,
            client,
            source_id,
            source_path_hash,
            session_id,
            session_event_id,
            coordinate,
            replay_identity,
            detector_kind,
            finding_kind,
            observation_family,
            stage,
            tool_name,
            occurred_at,
            timeline_index,
            severity,
            promotion_score,
            rule_ids,
            categories,
            contributions,
            evidence,
            supporting_observation_ids,
            canonical_findings,
            context,
        } = record;
        Self {
            schema: ACTION_RECORD_V2_ID.to_owned(),
            telltale_version,
            semantic_identity,
            client,
            source_id,
            source_path_hash,
            session_id,
            session_event_id,
            coordinate,
            replay_identity,
            detector_kind,
            finding_kind,
            observation_family,
            stage,
            tool_name,
            occurred_at,
            timeline_index,
            severity,
            promotion_score,
            rule_ids,
            categories,
            contributions,
            evidence,
            supporting_observation_ids,
            canonical_findings,
            context,
            destinations,
        }
    }

    /// Parse and validate one complete record from another process, with the
    /// checks of [`ActionRecordV1::from_json`] plus the v2 fields.
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

    /// The delivery key, byte-identical to [`ActionRecordV1::delivery_key`]
    /// for the same action.
    pub fn delivery_key(&self) -> String {
        self.shared_view().delivery_key()
    }

    /// Every key this action may have been delivered under, identical to
    /// [`ActionRecordV1::delivery_aliases`] for the same action.
    pub fn delivery_aliases(&self) -> Vec<String> {
        self.shared_view().delivery_aliases()
    }

    /// As [`ActionRecordV1::check_session_event`].
    pub fn check_session_event(&self, event: &Event3Record) -> Result<(), ActionRecordError> {
        self.shared_view().check_session_event(event)
    }

    fn validate_semantics(&self) -> Result<(), ActionRecordError> {
        if ClientId::from_name(&self.client).is_none() {
            return Err(identity("unknown_client"));
        }
        self.shared_view().validate_semantics()?;
        if let Some(facts) = &self.destinations
            && (!facts.is_valid()
                || !self
                    .rule_ids
                    .iter()
                    .any(|rule| rule == DESTINATION_FACTS_RULE_ID))
        {
            return Err(semantic("invalid_destinations"));
        }
        Ok(())
    }

    /// The fields v2 shares with v1, as a v1 value, so both versions share one
    /// implementation of semantics, delivery keys and event links. Never
    /// serialized: its client may be outside the v1 vocabulary.
    fn shared_view(&self) -> ActionRecordV1 {
        ActionRecordV1 {
            schema: ACTION_RECORD_V1_ID.to_owned(),
            telltale_version: self.telltale_version.clone(),
            semantic_identity: self.semantic_identity.clone(),
            client: self.client.clone(),
            source_id: self.source_id.clone(),
            source_path_hash: self.source_path_hash.clone(),
            session_id: self.session_id.clone(),
            session_event_id: self.session_event_id.clone(),
            coordinate: self.coordinate.clone(),
            replay_identity: self.replay_identity.clone(),
            detector_kind: self.detector_kind.clone(),
            finding_kind: self.finding_kind.clone(),
            observation_family: self.observation_family,
            stage: self.stage,
            tool_name: self.tool_name.clone(),
            occurred_at: self.occurred_at.clone(),
            timeline_index: self.timeline_index,
            severity: self.severity.clone(),
            promotion_score: self.promotion_score,
            rule_ids: self.rule_ids.clone(),
            categories: self.categories.clone(),
            contributions: self.contributions.clone(),
            evidence: self.evidence.clone(),
            supporting_observation_ids: self.supporting_observation_ids.clone(),
            canonical_findings: self.canonical_findings.clone(),
            context: self.context.clone(),
        }
    }
}

fn check_version(value: &Value) -> Result<(), ActionRecordError> {
    match value.get("schema").and_then(Value::as_str) {
        Some(ACTION_RECORD_V2_ID) => Ok(()),
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

#[cfg(test)]
mod tests;
