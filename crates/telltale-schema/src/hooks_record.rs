//! Strict readback of one Telltale Hooks JSONL envelope. The runtime owns
//! record production; this module needs neither hooks nor the scan pipeline.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::LazyLock;

use jsonschema::{Validator, options};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::action_record::ActionRecordV1;
use crate::clients::ClientId;
use crate::destination_facts::DestinationFacts;
use crate::event::{PrivacySanitizer, SanitizationContext, validate_rule_ids};
use crate::observation::ObservationStage;

/// Value of the `schema` field of a hooks record.
pub const HOOKS_RECORD_V1_ID: &str = "telltale_hooks.record.v1";
/// Published JSON Schema for the hooks envelope.
pub const HOOKS_RECORD_V1_SCHEMA: &str =
    include_str!("../data/telltale-hooks-record-v1.schema.json");
/// Maximum serialized Hooks JSONL record size, including its line feed. The
/// writer never writes a longer line. Labels are at most 256 bytes each; the
/// variable parts are embedded action records (up to 1 MiB for their own
/// consumer) and their rule/category lists. This allows about sixteen such
/// actions; the actions, summaries and envelope together must fit.
pub const HOOKS_RECORD_MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

#[doc(hidden)]
pub const TELEMETRY_RECORD_TOO_LARGE: &str = "telemetry_record_too_large";

/// What every ID of a hooks host self-protection rule starts with. A grant
/// never covers a finding of such a rule.
pub const HOOKS_HOST_RULE_ID_PREFIX: &str = "tth.tamper.";

#[doc(hidden)]
pub const HOOK_LABEL_MAX_BYTES: usize = 256;
#[doc(hidden)]
pub const HOOK_LABEL_ESCAPE_PREFIX: &str = "tth-esc-";
#[doc(hidden)]
pub const HOOK_TEST_SIGNATURE_RULE_IDS: &[&str] = &["tth.test.ask", "tth.test.deny"];

#[doc(hidden)]
pub fn readable_hook_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

#[doc(hidden)]
pub fn readable_hook_label(value: &str, context: SanitizationContext) -> bool {
    readable_hook_text(value, HOOK_LABEL_MAX_BYTES)
        && value == value.trim()
        && PrivacySanitizer::sanitize(context, value) == value
}

#[doc(hidden)]
pub fn escaped_hook_label(value: &str) -> bool {
    hex_id(value, HOOK_LABEL_ESCAPE_PREFIX, 32)
}

static VALIDATOR: LazyLock<Validator> = LazyLock::new(|| {
    let schema: Value =
        serde_json::from_str(HOOKS_RECORD_V1_SCHEMA).expect("bundled hooks record schema is JSON");
    options()
        .should_validate_formats(true)
        .build(&schema)
        .expect("bundled hooks record schema compiles")
});

macro_rules! vocabulary {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }

        #[cfg(test)]
        impl $name {
            const ALL: &'static [Self] = &[$(Self::$variant),+];
        }
    };
}

vocabulary!(HooksRecordKind {
    Decision,
    Outcome,
    ResultFinding,
    Lifecycle,
    Error
});
vocabulary!(HooksEvaluationStatus {
    Complete,
    VisibilityLimited,
    NotEvaluated
});
vocabulary!(HooksCoverage {
    WholeSource,
    Partial,
    Unknown
});
vocabulary!(HooksEvaluator { Daemon, InProcess });
vocabulary!(HooksScanResult {
    Passed,
    Refused,
    SkippedPiecesOnly,
    SkippedBudget,
    SkippedLate,
    SameAsWhole,
});
vocabulary!(HooksHistoryScanResult {
    Passed,
    Refused,
    SkippedBudget,
    SkippedLate
});
vocabulary!(HooksMode { Enforce, Observe });
vocabulary!(HooksVerdict { Allow, Ask, Deny });
vocabulary!(HooksReturnedVerdict { Deny });
vocabulary!(HooksDecisionBasis {
    NoFinding,
    BelowThreshold,
    ActionScore,
    SessionScore,
    RepeatedDenials,
    EvaluationGap,
    UnevaluableInput,
});
vocabulary!(HooksGrantScope {
    Once,
    Session,
    Project,
    User
});
vocabulary!(HooksGrantRefusal {
    NotUserPrompt,
    NoOffer
});
vocabulary!(HooksOutcomeResult {
    Completed,
    Failed,
    Interrupted,
    NotExecuted,
    Unknown
});
vocabulary!(HooksEnforcement {
    Honored,
    Violated,
    Declined,
    ProceededAfterAsk,
    NotReturned,
    NoDecision,
    Unknown,
});

/// One observation recorded by Telltale Hooks. Use [`Self::from_json`] or
/// [`Self::validate`] at a trust boundary; serde alone does not validate it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksRecordV1 {
    pub schema: String,
    pub record_id: String,
    pub recorded_at: String,
    pub kind: HooksRecordKind,
    pub producer: HooksProducer,
    pub harness: HooksHarness,
    pub session: HooksSession,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<HooksAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation: Option<HooksEvaluation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<HooksDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<HooksOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<HooksLifecycle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_wait_ms: Option<u64>,
    pub telltale: Vec<HooksActionEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksProducer {
    pub name: String,
    pub version: String,
    pub telltale_rev: String,
    pub semantic_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksHarness {
    pub name: String,
    pub hook_event: String,
    pub permission_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksSession {
    pub session_id: String,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub prompt_id: Option<String>,
    pub cwd_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksAction {
    pub tool_use_id: Option<String>,
    pub tool_name: Option<String>,
    pub input_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksEvaluation {
    pub status: HooksEvaluationStatus,
    pub coverage: Option<HooksCoverage>,
    pub visibility_limits: Vec<String>,
    pub failure_code: Option<String>,
    pub window_records: u64,
    pub window_truncated: bool,
    pub build_ms: Option<u64>,
    pub scan_ms: Option<u64>,
    /// Absent on old records; explicitly null when no wait was measured.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub lock_wait_ms: Option<Option<u64>>,
    pub evaluator: HooksEvaluator,
    pub evaluator_fallback: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scans: Option<HooksScans>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksScans {
    pub variants: u64,
    pub whole: Option<HooksScanResult>,
    pub together: Option<HooksScanResult>,
    /// Absent on old records; explicitly null when no history scan ran.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub history: Option<Option<HooksHistoryScanResult>>,
    pub pieces_scanned: u64,
    pub pieces_total: u64,
    pub pieces_refused: u64,
    pub first_refusal: Option<String>,
    pub whole_ms: u64,
    pub together_ms: u64,
    pub pieces_ms: u64,
    pub history_ms: u64,
}

// Serde's ordinary Option decodes both an absent field and null as None.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksDecision {
    pub mode: HooksMode,
    pub verdict: HooksVerdict,
    pub returned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returned_verdict: Option<HooksReturnedVerdict>,
    pub basis: HooksDecisionBasis,
    pub action_score: u64,
    pub session_score_before: u64,
    pub session_score_after: u64,
    pub denied_attempts_before: u32,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant: Option<HooksGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksGrant {
    pub scope: HooksGrantScope,
    pub granted_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksOutcome {
    pub result: HooksOutcomeResult,
    pub established_by: String,
    pub decision_record_id: Option<String>,
    pub prior_verdict: Option<HooksVerdict>,
    pub prior_returned: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_returned_verdict: Option<HooksReturnedVerdict>,
    pub enforcement: HooksEnforcement,
    pub duration_ms: Option<u64>,
    pub supersedes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum HooksLifecycle {
    SessionStart {
        source: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pinned_over: Option<Vec<String>>,
    },
    SessionEnd {
        reason: Option<String>,
        cumulative_score: u64,
        scored_actions: u64,
        denied_attempts: u64,
        asked_attempts: u64,
        subagents: u64,
        unsettled_calls: u64,
    },
    SubagentStart {
        agent_id: String,
        agent_type: Option<String>,
    },
    SubagentStop {
        agent_id: String,
        agent_type: Option<String>,
    },
    PermissionPrompt {},
    UserPrompt {
        prompt_sha256: String,
        prompt_bytes: u64,
    },
    Grant {
        scope: HooksGrantScope,
        tool: String,
        rule_ids: Vec<String>,
        offer_record_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        grant_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        project_sha256: Option<String>,
    },
    GrantRefused {
        cause: HooksGrantRefusal,
    },
    GrantRevoked {
        grant_id: String,
    },
    Other {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HooksActionEntry {
    pub delivery_key: String,
    pub record: ActionRecordV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destinations: Option<DestinationFacts>,
}

/// Stable categories for hooks consumer failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HooksRecordErrorCategory {
    Malformed,
    Version,
    Structure,
    Identity,
    Semantic,
}

/// Closed diagnostic data; never contains input text or a parser error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HooksRecordError {
    category: HooksRecordErrorCategory,
    code: &'static str,
}

impl HooksRecordError {
    const fn new(category: HooksRecordErrorCategory, code: &'static str) -> Self {
        Self { category, code }
    }

    pub const fn category(self) -> HooksRecordErrorCategory {
        self.category
    }

    pub const fn code(self) -> &'static str {
        self.code
    }
}

impl fmt::Display for HooksRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "hooks record error: {}", self.code)
    }
}

impl std::error::Error for HooksRecordError {}

use HooksRecordErrorCategory::{Identity, Malformed, Semantic, Structure, Version};

macro_rules! rejection_codes {
    ($($name:ident: $category:ident => $code:literal),+ $(,)?) => {
        $(const $name: HooksRecordError = HooksRecordError::new($category, $code);)+
        impl HooksRecordError {
            /// Closed vocabulary returned by the strict record reader.
            pub const CODES: &'static [&'static str] = &[$($code),+];
            /// The same diagnostic used when a reader rejects before buffering.
            pub const INPUT_TOO_LARGE_CODE: &'static str = INPUT_TOO_LARGE.code();
        }
    };
}

rejection_codes! {
    ACTION_SOURCE_MISMATCH: Identity => "action_source_mismatch",
    DELIVERY_KEY_MISMATCH: Identity => "delivery_key_mismatch",
    FINDING_SUMMARY_MISMATCH: Semantic => "finding_summary_mismatch",
    INCONSISTENT_EVALUATION: Semantic => "inconsistent_evaluation",
    INCONSISTENT_GRANT: Semantic => "inconsistent_grant",
    INCONSISTENT_KIND: Semantic => "inconsistent_kind",
    INCONSISTENT_LIFECYCLE: Semantic => "inconsistent_lifecycle",
    INCONSISTENT_OUTCOME: Semantic => "inconsistent_outcome",
    INCONSISTENT_VERDICT: Semantic => "inconsistent_verdict",
    INPUT_TOO_LARGE: Structure => "input_too_large",
    INVALID_ACTION: Semantic => "invalid_action_record",
    INVALID_DESTINATIONS: Semantic => "invalid_destinations",
    MALFORMED_JSON: Malformed => "malformed_json",
    SCHEMA_MISMATCH: Structure => "schema_mismatch",
    SCORE_MISMATCH: Semantic => "score_mismatch",
    UNREDACTED_TEXT: Semantic => "unredacted_text",
    UNSUPPORTED_RECORD_VERSION: Version => "unsupported_record_version",
}

impl HooksRecordV1 {
    /// Read one complete JSON object, optionally including its trailing JSONL
    /// newline. Reserve one byte for the line feed if it is not supplied.
    /// Redaction is a fixed-point check under the current sanitizer.
    pub fn from_json(bytes: &[u8]) -> Result<Self, HooksRecordError> {
        let value = checked_value(bytes)?;
        check_embedded_actions(&value)?;
        drop(value);
        // Deserialize from bytes so duplicate members are rejected, even
        // though the JSON Schema validator takes an already parsed Value.
        let record: Self = serde_json::from_slice(bytes).map_err(|_| SCHEMA_MISMATCH)?;
        record.validate_semantics()?;
        Ok(record)
    }

    /// Apply the same wire and semantic checks to an in-process record.
    pub fn validate(&self) -> Result<(), HooksRecordError> {
        let bytes = serde_json::to_vec(self).map_err(|_| SCHEMA_MISMATCH)?;
        let value = checked_value(&bytes)?;
        check_embedded_actions(&value)?;
        self.validate_semantics()
    }

    fn validate_semantics(&self) -> Result<(), HooksRecordError> {
        self.validate_kind()?;
        for action in &self.telltale {
            if action.delivery_key != action.record.delivery_key() {
                return Err(DELIVERY_KEY_MISMATCH);
            }
            let record = &action.record;
            let hook_source = ClientId::from_name(&record.client)
                .is_some_and(|client| client.owns_hook_journal(&record.source_id));
            // Before native hook journals, the integrated 0.7.2 development
            // build read every hook through its Claude-format window.
            let legacy_source = self.producer.version == "0.7.2"
                && record.client == "claude"
                && record.source_id == "claude.projects";
            let stage = if self.kind == HooksRecordKind::ResultFinding {
                ObservationStage::ToolResultReturned
            } else {
                ObservationStage::ToolRequested
            };
            if !(hook_source || legacy_source)
                || self.producer.semantic_identity.as_deref() != Some(&record.semantic_identity)
                || record.stage != stage
            {
                return Err(ACTION_SOURCE_MISMATCH);
            }
            if let Some(facts) = &action.destinations
                && (!record
                    .rule_ids
                    .iter()
                    .any(|id| id == "exfil.outbound_upload")
                    || !facts.is_valid())
            {
                return Err(INVALID_DESTINATIONS);
            }
        }
        if let Some(evaluation) = &self.evaluation {
            evaluation.validate(self.kind)?;
        }
        if let Some(decision) = &self.decision {
            decision.validate(self.kind, self.evaluation.as_ref(), &self.telltale)?;
        }
        if let Some(outcome) = &self.outcome {
            outcome.validate(&self.harness, self.error_code.as_deref())?;
        }
        if let Some(lifecycle) = &self.lifecycle {
            lifecycle.validate(&self.harness, &self.session)?;
        }
        self.validate_text()
    }

    fn validate_kind(&self) -> Result<(), HooksRecordError> {
        use HooksRecordKind::*;
        let evaluated = matches!(self.kind, Decision | ResultFinding);
        let size_error =
            self.kind == Error && self.error_code.as_deref() == Some(TELEMETRY_RECORD_TOO_LARGE);
        let outcome = self.kind == Outcome;
        let requires_action = evaluated
            || self.kind == Outcome
            || matches!(self.lifecycle, Some(HooksLifecycle::PermissionPrompt {}));
        if self.evaluation.is_some() != evaluated
            || self.decision.is_some() != evaluated
            || self.outcome.is_some() != (self.kind == Outcome)
            || self.lifecycle.is_some() != (self.kind == Lifecycle)
            || (!evaluated && !self.telltale.is_empty())
            || (self.kind == ResultFinding && self.telltale.is_empty())
            || (self.kind != Error && self.action.is_some() != requires_action)
            || (self.kind != Error && self.lock_wait_ms.is_some())
            || (size_error && self.lock_wait_ms.is_some())
            || (self.kind == Error && self.error_code.is_none())
            || (!matches!(self.kind, Error | Outcome) && self.error_code.is_some())
            || self.action.as_ref().is_some_and(|action| {
                action.tool_name.is_none()
                    || (action.input_sha256.is_none()
                        && (!(outcome || size_error) || action.tool_use_id.is_none()))
                    || (outcome && action.input_sha256.is_some())
            })
        {
            return Err(INCONSISTENT_KIND);
        }
        Ok(())
    }

    fn validate_text(&self) -> Result<(), HooksRecordError> {
        use SanitizationContext::{Diagnostic, Metadata, Summary};
        let view = Option::<String>::as_deref;
        check_text(
            Metadata,
            [self.producer.version.as_str(), self.harness.name.as_str()],
        )?;
        let no_session = self.session.session_id.is_empty()
            && (self.kind == HooksRecordKind::Error
                || self
                    .lifecycle
                    .as_ref()
                    .is_some_and(HooksLifecycle::is_terminal));
        check_labels(
            Metadata,
            [
                (!no_session).then_some(self.session.session_id.as_str()),
                (!(no_session
                    && self.kind == HooksRecordKind::Error
                    && self.harness.hook_event.is_empty()))
                .then_some(self.harness.hook_event.as_str()),
                view(&self.harness.permission_mode),
                view(&self.session.agent_id),
                view(&self.session.agent_type),
                view(&self.session.prompt_id),
                self.action
                    .as_ref()
                    .and_then(|action| view(&action.tool_use_id)),
                self.action
                    .as_ref()
                    .and_then(|action| view(&action.tool_name)),
                self.outcome
                    .as_ref()
                    .map(|outcome| outcome.established_by.as_str()),
            ]
            .into_iter()
            .flatten(),
        )?;
        check_text(Diagnostic, self.error_code.as_deref())?;
        if let Some(evaluation) = &self.evaluation {
            check_text(
                Diagnostic,
                evaluation
                    .failure_code
                    .as_deref()
                    .into_iter()
                    .chain(evaluation.evaluator_fallback.as_deref())
                    .chain(
                        evaluation
                            .scans
                            .as_ref()
                            .and_then(|s| view(&s.first_refusal)),
                    ),
            )?;
            check_text(
                Metadata,
                evaluation.visibility_limits.iter().map(String::as_str),
            )?;
        }
        match &self.lifecycle {
            Some(HooksLifecycle::SessionStart {
                source,
                pinned_over,
            }) => {
                check_labels(Metadata, view(source))?;
                check_text(Metadata, pinned_over.iter().flatten().map(String::as_str))?;
            }
            Some(HooksLifecycle::SessionEnd { reason, .. }) => check_labels(Summary, view(reason))?,
            Some(
                HooksLifecycle::SubagentStart {
                    agent_id,
                    agent_type,
                }
                | HooksLifecycle::SubagentStop {
                    agent_id,
                    agent_type,
                },
            ) => {
                check_labels(
                    Metadata,
                    std::iter::once(agent_id.as_str()).chain(view(agent_type)),
                )?;
            }
            Some(HooksLifecycle::Grant { tool, .. }) => check_labels(Metadata, [tool.as_str()])?,
            _ => {}
        }
        Ok(())
    }
}

fn checked_value(bytes: &[u8]) -> Result<Value, HooksRecordError> {
    if bytes.len() > HOOKS_RECORD_MAX_INPUT_BYTES
        || (bytes.len() == HOOKS_RECORD_MAX_INPUT_BYTES && !bytes.ends_with(b"\n"))
    {
        return Err(INPUT_TOO_LARGE);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| MALFORMED_JSON)?;
    if let Some(schema) = value.get("schema").and_then(Value::as_str)
        && schema != HOOKS_RECORD_V1_ID
    {
        return Err(UNSUPPORTED_RECORD_VERSION);
    }
    if !VALIDATOR.is_valid(&value) {
        // Keep the cross-field diagnostic when the wire schema also rejects
        // a contradictory local_only claim.
        let conflicting_local_only = value["telltale"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.get("destinations"))
            .any(|facts| {
                facts["local_only"] == true
                    && (facts["complete"] == false
                        || facts["destinations"]
                            .as_array()
                            .is_some_and(|entries| !entries.is_empty()))
            });
        if conflicting_local_only {
            return Err(INVALID_DESTINATIONS);
        }
        return Err(SCHEMA_MISMATCH);
    }
    Ok(value)
}

fn check_embedded_actions(value: &Value) -> Result<(), HooksRecordError> {
    for entry in value["telltale"].as_array().ok_or(SCHEMA_MISMATCH)? {
        let bytes = serde_json::to_vec(&entry["record"]).map_err(|_| INVALID_ACTION)?;
        ActionRecordV1::from_json(&bytes).map_err(|_| INVALID_ACTION)?;
    }
    Ok(())
}

fn check_text<'a>(
    context: SanitizationContext,
    texts: impl IntoIterator<Item = &'a str>,
) -> Result<(), HooksRecordError> {
    if !texts
        .into_iter()
        .all(|text| PrivacySanitizer::sanitize(context, text) == text)
    {
        return Err(UNREDACTED_TEXT);
    }
    Ok(())
}

fn hex_id(value: &str, prefix: &str, digits: usize) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == digits
            && suffix
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn check_labels<'a>(
    context: SanitizationContext,
    labels: impl IntoIterator<Item = &'a str>,
) -> Result<(), HooksRecordError> {
    if !labels
        .into_iter()
        .all(|label| escaped_hook_label(label) || readable_hook_label(label, context))
    {
        return Err(UNREDACTED_TEXT);
    }
    Ok(())
}

impl HooksEvaluation {
    fn validate(&self, kind: HooksRecordKind) -> Result<(), HooksRecordError> {
        if self.scans.as_ref().is_some_and(|scans| {
            kind != HooksRecordKind::Decision
                || scans.pieces_refused > scans.pieces_scanned
                || scans.pieces_scanned > scans.pieces_total
                || (scans.first_refusal.is_some() && scans.pieces_refused == 0)
        }) {
            return Err(INCONSISTENT_EVALUATION);
        }
        Ok(())
    }
}

impl HooksDecision {
    fn validate(
        &self,
        kind: HooksRecordKind,
        evaluation: Option<&HooksEvaluation>,
        actions: &[HooksActionEntry],
    ) -> Result<(), HooksRecordError> {
        use HooksDecisionBasis::*;
        use HooksVerdict::*;
        let result_finding = kind == HooksRecordKind::ResultFinding;
        let should_return =
            self.mode == HooksMode::Enforce && self.verdict != Allow && self.grant.is_none();
        if self.returned != should_return
            || (self.returned_verdict.is_some() && (!self.returned || self.verdict != Ask))
            || (result_finding && (self.verdict != Allow || self.basis != BelowThreshold))
        {
            return Err(INCONSISTENT_VERDICT);
        }
        if let Some(grant) = &self.grant
            && (self.mode != HooksMode::Enforce
                || self.verdict == Allow
                || !matches!(self.basis, ActionScore | SessionScore | RepeatedDenials)
                || !evaluation
                    .is_some_and(|evaluation| evaluation.status == HooksEvaluationStatus::Complete)
                || self.rule_ids.is_empty()
                || self
                    .rule_ids
                    .iter()
                    .any(|id| id.starts_with(HOOKS_HOST_RULE_ID_PREFIX))
                || !valid_grant_reference(grant))
        {
            return Err(INCONSISTENT_GRANT);
        }
        let score = actions
            .iter()
            .map(|action| action.record.promotion_score)
            .max()
            .unwrap_or(0);
        let before = self.session_score_before;
        let after = self.session_score_after;
        // A request reports only the increase after saturation. Test
        // signatures and grants can leave the session score unchanged. The
        // record does not say whether the built-in test signatures were on.
        let test_signature = !self.rule_ids.is_empty()
            && self
                .rule_ids
                .iter()
                .all(|id| HOOK_TEST_SIGNATURE_RULE_IDS.contains(&id.as_str()));
        let expected_after = before.saturating_add(score);
        let increase = expected_after - before;
        let test_score = test_signature && self.action_score == score;
        let consistent_score = if result_finding {
            after == expected_after && self.action_score == score
        } else if self.grant.is_some() {
            after == before && (self.action_score == increase || test_score)
        } else {
            (after == expected_after && self.action_score == increase)
                || (after == before && test_score)
        };
        if !consistent_score {
            return Err(SCORE_MISMATCH);
        }
        let rules: BTreeSet<_> = actions
            .iter()
            .flat_map(|action| &action.record.rule_ids)
            .collect();
        let categories: BTreeSet<_> = actions
            .iter()
            .flat_map(|action| &action.record.categories)
            .collect();
        if !self.rule_ids.iter().eq(rules) || !self.categories.iter().eq(categories) {
            return Err(FINDING_SUMMARY_MISMATCH);
        }
        Ok(())
    }
}

fn valid_grant_reference(grant: &HooksGrant) -> bool {
    match grant.scope {
        HooksGrantScope::Once | HooksGrantScope::Session => hex_id(&grant.granted_by, "tth:", 32),
        HooksGrantScope::Project | HooksGrantScope::User => hex_id(&grant.granted_by, "g-", 12),
    }
}

impl HooksOutcome {
    fn validate(
        &self,
        harness: &HooksHarness,
        error_code: Option<&str>,
    ) -> Result<(), HooksRecordError> {
        use HooksEnforcement as E;
        use HooksOutcomeResult::{NotExecuted, Unknown};
        use HooksVerdict::{Allow, Ask, Deny};
        let prior = self.decision_record_id.is_some();
        if prior != self.prior_verdict.is_some()
            || prior != self.prior_returned.is_some()
            || self
                .decision_record_id
                .iter()
                .chain(&self.supersedes)
                .any(|id| !hex_id(id, "tth:", 32))
            || (self.prior_returned == Some(true) && self.prior_verdict == Some(Allow))
            || (self.prior_returned_verdict.is_some()
                && (self.prior_returned != Some(true) || self.prior_verdict != Some(Ask)))
            || self.established_by != harness.hook_event
            || error_code.is_some_and(|code| {
                code != "outcome_ambiguous"
                    || self.result != Unknown
                    || self.supersedes.is_none()
                    || !prior
            })
        {
            return Err(INCONSISTENT_OUTCOME);
        }
        let verdict = if self.prior_returned_verdict.is_some() {
            Some(Deny)
        } else {
            self.prior_verdict
        };
        let expected = match (self.prior_returned, verdict, self.result) {
            (None, _, _) => E::NoDecision,
            (Some(true), Some(Deny), NotExecuted) => E::Honored,
            (Some(true), Some(Ask), NotExecuted) => E::Declined,
            (Some(true), _, Unknown) => E::Unknown,
            (Some(true), Some(Deny), _) => E::Violated,
            (Some(true), Some(Ask), _) => E::ProceededAfterAsk,
            _ => E::NotReturned,
        };
        if self.enforcement != expected {
            return Err(INCONSISTENT_OUTCOME);
        }
        Ok(())
    }
}

impl HooksLifecycle {
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::GrantRevoked { .. }
                | Self::Grant {
                    scope: HooksGrantScope::Project | HooksGrantScope::User,
                    ..
                }
        )
    }

    fn validate(
        &self,
        harness: &HooksHarness,
        session: &HooksSession,
    ) -> Result<(), HooksRecordError> {
        use HooksGrantScope::{Project, User};
        let invalid = INCONSISTENT_LIFECYCLE;
        match self {
            Self::Grant {
                scope,
                rule_ids,
                grant_id,
                project_sha256,
                ..
            } => {
                let terminal = matches!(scope, Project | User);
                if terminal != grant_id.is_some()
                    || (*scope == Project) != project_sha256.is_some()
                    || validate_rule_ids(rule_ids).is_err()
                    || rule_ids.is_empty()
                    || !rule_ids.windows(2).all(|pair| pair[0] < pair[1])
                {
                    return Err(invalid);
                }
            }
            Self::SessionStart {
                pinned_over: Some(sources),
                ..
            } if !sources.windows(2).all(|pair| pair[0] < pair[1]) => {
                return Err(invalid);
            }
            _ => {}
        }
        if self.is_terminal()
            && (harness.hook_event != "terminal" || !session.session_id.is_empty())
        {
            return Err(invalid);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "hooks_record_tests.rs"]
mod tests;
