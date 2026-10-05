//! Action interpretation beside the frozen session compatibility view. No I/O.
use super::session::{ProcessingError, RetentionBudget};
use crate::process_chain::{split_statements, tokenize};
use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::LazyLock;
use telltale_rules::{
    RuleV1CompatibilityExport, RuleV1CompatibilityModifier, RuleV1ContentMatcher,
};
use telltale_schema::event::{redact_sensitive_text, terminal_identifier, terminal_session_id};
use telltale_schema::observation::*;
use telltale_schema::scoring::{RiskContribution, RiskContributionType};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const ACTION_SEMANTICS_VERSION: u32 = 2;
const NATIVE_ACTION_PROFILE_VERSION: u32 = 2;
pub const REPLAY_ALGORITHM_VERSION: u32 = 1;
/// Canonical action-only content; the frozen Event3 modifier remains unchanged.
pub const DEFAULT_ACTION_DOWNLOAD_LINK_SCORE: u64 = 50;
const ACTION_CHAIN_WINDOW_SECONDS: u64 = 900;

/// Description from the action semantic owner, not compatibility YAML inference.
pub struct ActionModifierSemantics {
    pub score: u64,
    pub ordered: bool,
    pub within_seconds: Option<u64>,
    pub link: Option<&'static str>,
}
pub(crate) fn modifier_semantics(
    modifier: &RuleV1CompatibilityModifier,
    options: &DetailedEvaluationOptions,
) -> ActionModifierSemantics {
    let linked = linked_modifier(modifier);
    let ordered = linked || !modifier.when_all_categories.is_empty();
    ActionModifierSemantics {
        score: if linked {
            linked_score(modifier, options)
        } else {
            modifier.score
        },
        ordered,
        within_seconds: ordered.then_some(ACTION_CHAIN_WINDOW_SECONDS),
        link: linked.then_some("downloaded_artifact"),
    }
}

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct DetailedEvaluationOptions {
    pub context: ContextOptions,
    /// Explicit action-only linked correlation score. None selects canonical
    /// bundled action content (50); modified effective modifier scores survive.
    pub linked_download_score: Option<u64>,
    /// Core facade opt-in to its bundled process-chain owner; never a second pass.
    pub process_chain: bool,
}
impl DetailedEvaluationOptions {
    pub fn validate(&self) -> Result<(), ProcessingError> {
        if self.context.before > 32
            || self.context.after > 32
            || self.linked_download_score.is_some_and(|score| score > 100)
        {
            Err(ProcessingError::Bounds)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ActionCoordinate(String);
impl ActionCoordinate {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Privacy-safe projection of one authoritative DetectorResult -> Signal ->
/// Finding. Its risk is never the host action's aggregate score.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct CanonicalActionFinding {
    finding_id: String,
    signal_ids: Vec<String>,
    observation_ids: Vec<String>,
    detector_id: String,
    finding_kind: String,
    category: String,
    severity: String,
    risk_points: Option<u8>,
}
impl CanonicalActionFinding {
    fn from_finding(finding: &super::Finding) -> Self {
        Self {
            finding_id: finding.finding_id().into(),
            signal_ids: finding.signal_ids().to_vec(),
            observation_ids: finding.observation_ids().to_vec(),
            detector_id: terminal_identifier("rule", finding.detectors()[0].id()),
            finding_kind: finding.finding_kind().as_str().into(),
            category: terminal_identifier("category", finding.category()),
            severity: finding.severity().as_str().into(),
            risk_points: finding.risk_points(),
        }
    }
    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }
    pub fn signal_ids(&self) -> &[String] {
        &self.signal_ids
    }
    pub fn observation_ids(&self) -> &[String] {
        &self.observation_ids
    }
    pub fn detector_id(&self) -> &str {
        &self.detector_id
    }
    pub fn finding_kind(&self) -> &str {
        &self.finding_kind
    }
    pub fn category(&self) -> &str {
        &self.category
    }
    pub fn severity(&self) -> &str {
        &self.severity
    }
    pub fn risk_points(&self) -> Option<u8> {
        self.risk_points
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ActionFindingKind {
    Atomic,
    Correlation,
}

/// Privacy-safe ledger entry. Unlike the internal contribution primitive its
/// outward ID may be an opaque terminal identifier.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct ActionContribution {
    id: String,
    points: u64,
    contribution_type: RiskContributionType,
    rationale: String,
}
impl ActionContribution {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn points(&self) -> u64 {
        self.points
    }
    pub fn contribution_type(&self) -> RiskContributionType {
        self.contribution_type
    }
    pub fn rationale(&self) -> &str {
        &self.rationale
    }
}

/// Neighbors counted in canonical session order, before eligibility filtering.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ContextOptions {
    pub before: usize,
    pub after: usize,
    pub user_text: bool,
    pub assistant_text: bool,
    pub tool_arguments: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ReplayIdentity(String);
impl ReplayIdentity {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Comparison aid, not authentication or proof of per-event configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct SemanticProvenance {
    effective_rule_fingerprint: String,
    action_semantics_version: u32,
    native_profile_version: u32,
    replay_algorithm_version: u32,
    identity: String,
}
impl SemanticProvenance {
    pub fn effective_rule_fingerprint(&self) -> &str {
        &self.effective_rule_fingerprint
    }
    pub fn action_semantics_version(&self) -> u32 {
        self.action_semantics_version
    }
    pub fn native_profile_version(&self) -> u32 {
        self.native_profile_version
    }
    pub fn replay_algorithm_version(&self) -> u32 {
        self.replay_algorithm_version
    }
    pub fn identity(&self) -> &str {
        &self.identity
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ActionEvidence {
    field: String,
    rule_id: String,
    redacted_value: String,
}
impl ActionEvidence {
    pub fn field(&self) -> &str {
        &self.field
    }
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }
    pub fn redacted_value(&self) -> &str {
        &self.redacted_value
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ActionContextEntry {
    offset: i32,
    kind: String,
    occurred_at: Option<String>,
    tool_name: Option<String>,
    redacted_text: String,
}
impl ActionContextEntry {
    pub fn offset(&self) -> i32 {
        self.offset
    }
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn occurred_at(&self) -> Option<&str> {
        self.occurred_at.as_deref()
    }
    pub fn tool_name(&self) -> Option<&str> {
        self.tool_name.as_deref()
    }
    pub fn redacted_text(&self) -> &str {
        &self.redacted_text
    }
}

/// Immutable, constructor-sanitized detailed output; never an Event3 body.
#[derive(Clone, Serialize)]
#[non_exhaustive]
pub struct ActionFinding {
    canonical_findings: Vec<CanonicalActionFinding>,
    coordinate: ActionCoordinate,
    finding_kind: ActionFindingKind,
    severity: String,
    supporting_observation_ids: Vec<String>,
    detector_kind: String,
    observation_id: String,
    kind: String,
    stage: String,
    tool_name: Option<String>,
    session_id: Option<String>,
    timeline_index: usize,
    occurred_at: Option<String>,
    replay_identity: Option<ReplayIdentity>,
    rule_ids: Vec<String>,
    categories: Vec<String>,
    promotion_score: u64,
    contributions: Vec<ActionContribution>,
    evidence: Vec<ActionEvidence>,
    context: Vec<ActionContextEntry>,
}
impl ActionFinding {
    pub fn canonical_findings(&self) -> &[CanonicalActionFinding] {
        &self.canonical_findings
    }
    /// Coordinate of this host-facing action group, not a native Finding ID.
    pub fn coordinate(&self) -> &ActionCoordinate {
        &self.coordinate
    }
    pub fn finding_kind(&self) -> ActionFindingKind {
        self.finding_kind
    }
    pub fn severity(&self) -> &str {
        &self.severity
    }
    pub fn supporting_observation_ids(&self) -> &[String] {
        &self.supporting_observation_ids
    }
    pub fn detector_kind(&self) -> &str {
        &self.detector_kind
    }
    pub(crate) fn clear_replay_identity(&mut self) {
        self.replay_identity = None;
    }
    pub fn observation_id(&self) -> &str {
        &self.observation_id
    }
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn stage(&self) -> &str {
        &self.stage
    }
    pub fn tool_name(&self) -> Option<&str> {
        self.tool_name.as_deref()
    }
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
    pub fn timeline_index(&self) -> usize {
        self.timeline_index
    }
    pub fn occurred_at(&self) -> Option<&str> {
        self.occurred_at.as_deref()
    }
    pub fn replay_identity(&self) -> Option<&ReplayIdentity> {
        self.replay_identity.as_ref()
    }
    pub fn rule_ids(&self) -> &[String] {
        &self.rule_ids
    }
    pub fn categories(&self) -> &[String] {
        &self.categories
    }
    pub fn score(&self) -> u64 {
        self.promotion_score
    }
    /// Host action contribution sum; not a canonical Finding risk assessment.
    pub fn promotion_score(&self) -> u64 {
        self.promotion_score
    }
    pub fn contributions(&self) -> &[ActionContribution] {
        &self.contributions
    }
    pub fn evidence(&self) -> &[ActionEvidence] {
        &self.evidence
    }
    pub fn context(&self) -> &[ActionContextEntry] {
        &self.context
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ActionRule {
    matcher: RuleV1ContentMatcher,
    native: bool,
}
// Profiles apply only to the bundled predicates. A same-ID custom predicate
// uses its own effective matcher over the action fields, never a hidden override.
static BUNDLED: LazyLock<RuleV1CompatibilityExport> = LazyLock::new(|| {
    telltale_rules::load_default_rule_set()
        .expect("bundled rules")
        .compatibility_export()
});
pub(crate) fn compile(
    export: &RuleV1CompatibilityExport,
) -> Result<Vec<ActionRule>, super::RuleV1CompileError> {
    export
        .rules()
        .iter()
        .map(|rule| {
            let native = BUNDLED
                .rules()
                .iter()
                .find(|r| r.id == rule.id)
                .is_some_and(|base| {
                    base.matchers.len() == rule.matchers.len()
                        && base.matchers.iter().zip(&rule.matchers).all(|(a, b)| {
                            a.target == b.target
                                && a.regex == b.regex
                                && a.exclusion_regex == b.exclusion_regex
                        })
                });
            let mut content = rule.clone();
            if native {
                // Precision is compiled content, not a bypass of the effective
                // content owner. Target-local exclusions remain unchanged.
                let selection = match rule.id.as_str() {
                    "network.download" | "exfil.outbound_upload" | "exfil.encoded_http" | "mcp.server_enumeration" => Some(r"(?s:.+)"),
                    "approval.bypass.context" => Some(r"(?i:without\s+(asking|approval|confirmation|telling)|bypass\s+approval|hide\s+this|do\s+not\s+tell|silent(?:ly)?\s+run|no\s+confirm|--dangerously-skip-permissions|--no-approval)"),
                    _ => None,
                };
                if let Some(selection) = selection { for matcher in &mut content.matchers { matcher.regex = selection.into(); } }
            }
            Ok(ActionRule {
                matcher: content
                    .compile_content_matcher()
                    .map_err(|_| super::RuleV1CompileError::InvalidMetadata)?,
                native,
            })
        })
        .collect()
}

pub(crate) fn provenance(
    export: &RuleV1CompatibilityExport,
    options: &DetailedEvaluationOptions,
) -> SemanticProvenance {
    let fingerprint = export.fingerprint();
    let mut hash = Sha256::new();
    hash.update(b"telltale:action-semantic-provenance:v1\0");
    frame(&mut hash, fingerprint.as_bytes());
    frame(&mut hash, &ACTION_SEMANTICS_VERSION.to_le_bytes());
    frame(&mut hash, &NATIVE_ACTION_PROFILE_VERSION.to_le_bytes());
    frame(&mut hash, &REPLAY_ALGORITHM_VERSION.to_le_bytes());
    frame(
        &mut hash,
        &options
            .linked_download_score
            .unwrap_or_else(|| {
                export
                    .modifiers()
                    .iter()
                    .find(|m| linked_modifier(m))
                    .map_or(0, |m| linked_score(m, options))
            })
            .to_le_bytes(),
    );
    frame(&mut hash, &[u8::from(options.process_chain)]);
    if options.process_chain {
        frame(
            &mut hash,
            telltale_rules::process_chain::bundled_process_chain_yaml().as_bytes(),
        );
    }
    SemanticProvenance {
        effective_rule_fingerprint: fingerprint,
        action_semantics_version: ACTION_SEMANTICS_VERSION,
        native_profile_version: NATIVE_ACTION_PROFILE_VERSION,
        replay_algorithm_version: REPLAY_ALGORITHM_VERSION,
        identity: format!("semantic:v1:sha256:{:x}", hash.finalize()),
    }
}
fn frame(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

#[derive(Default)]
struct ActionView {
    fields: BTreeMap<&'static str, String>,
    commands: Vec<Vec<String>>,
    stages: Vec<String>,
    reads_paths: bool,
}
impl ActionView {
    fn put(&mut self, field: &'static str, text: String) {
        if !text.is_empty() {
            self.fields
                .entry(field)
                .and_modify(|v| {
                    v.push('\n');
                    v.push_str(&text);
                })
                .or_insert(text);
        }
    }
    fn text(&self, field: &str) -> &str {
        self.fields.get(field).map_or("", String::as_str)
    }
    fn fields(&self) -> Vec<(&str, &str)> {
        self.fields.iter().map(|(k, v)| (*k, v.as_str())).collect()
    }
}
fn string(value: &JsonValue) -> Option<&str> {
    if let JsonValue::String(v) = value {
        Some(v)
    } else {
        None
    }
}

fn view(observation: &CanonicalObservationV2) -> ActionView {
    let mut out = ActionView::default();
    if observation.source().ingestion_mode() == IngestionMode::Import {
        return out;
    }
    match observation.body() {
        ObservationBody::Message(message) => {
            if observation
                .capability_context()
                .map(|c| c.resolve(CapabilityId::UserContext))
                != Some(CapabilityAvailability::Supported)
            {
                return out;
            }
            let field = match message.role() {
                Some(MessageRole::User) => "user_context",
                Some(MessageRole::Assistant) => "assistant_context",
                _ => return out,
            };
            if let Some(text) = message.content().and_then(string) {
                out.put(field, text.to_owned());
            }
            for part in message
                .content_parts()
                .iter()
                .filter(|p| p.kind() == ContentPartKind::Text)
            {
                if let Some(text) = string(part.value()) {
                    out.put(field, text.to_owned());
                }
            }
        }
        ObservationBody::Tool(tool) => {
            if observation
                .capability_context()
                .map(|c| c.resolve(CapabilityId::ToolCall))
                != Some(CapabilityAvailability::Supported)
            {
                return out;
            }
            if observation.stage() == ObservationStage::ToolResultReturned {
                if let Some(text) = tool.result().and_then(string).or(tool.searchable_result()) {
                    out.put("tool_result", text.to_owned());
                }
                return out;
            }
            if !matches!(
                observation.stage(),
                ObservationStage::ToolProposed
                    | ObservationStage::ToolRequested
                    | ObservationStage::ToolExecutionStarted
                    | ObservationStage::ToolExecutionCompleted
            ) {
                return out;
            }
            if let Some(name) = tool.name() {
                out.put("tool_name", name.to_owned());
            }
            out.reads_paths = tool.name().is_some_and(|name| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "read" | "read_file" | "readfile" | "view_file" | "glob" | "list" | "grep"
                )
            });
            let mut command = String::new();
            match tool.arguments() {
                Some(JsonValue::Object(input)) => structured_input(input, &mut out, &mut command),
                Some(JsonValue::String(text)) => {
                    // Some native envelopes carry an encoded object as a string.
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text)
                        && value.is_object()
                        && let Ok(JsonValue::Object(input)) =
                            JsonValue::try_from_source_value(&value)
                    {
                        structured_input(&input, &mut out, &mut command);
                    } else {
                        command.push_str(text);
                    }
                }
                _ => {
                    let resolution = super::SelectorRegistry::new().resolve(
                        super::SelectorId::parse("command.text").unwrap(),
                        observation,
                    );
                    if let Some(JsonValue::String(text)) = resolution.value() {
                        command.push_str(text);
                    } else if let Some(text) = tool.searchable_arguments() {
                        command.push_str(text);
                    }
                }
            }
            if tool
                .name()
                .is_some_and(|name| matches!(name, "exec" | "multi_tool_use.parallel"))
                && let Some((commands, written, paths)) = script_actions(&command)
            {
                command = commands;
                out.put("authored_content", written);
                out.put("file_path", paths);
            }
            let (command, authored) = strip_heredocs(&command);
            out.put("authored_content", authored);
            out.stages = if shell_comment(&command) {
                Vec::new()
            } else {
                split_statements(&command)
            };
            out.commands = out.stages.iter().map(|s| tokenize(s)).collect();
            out.reads_paths |= out.commands.iter().any(|tokens| {
                matches!(
                    command_word(tokens),
                    "cat"
                        | "head"
                        | "tail"
                        | "grep"
                        | "rg"
                        | "source"
                        | "."
                        | "openssl"
                        | "find"
                        | "ssh"
                )
            });
            out.put("command", command.clone());
            // Command parameters, never interpreter code or quoted prose, are paths.
            for tokens in &out.commands.clone() {
                for token in tokens.iter().skip(1) {
                    if !token.contains(char::is_whitespace) {
                        out.put("file_path", token.clone());
                    }
                }
            }
            out.put("url", command);
        }
        _ => {}
    }
    out
}

/// Read only literal arguments of the supported script-tool API. Arbitrary
/// JavaScript is not executed, flattened, or treated as shell input.
fn script_actions(script: &str) -> Option<(String, String, String)> {
    if !script.contains("tools.") {
        return None;
    }
    let mut commands = Vec::new();
    let mut written = Vec::new();
    let mut paths = Vec::new();
    for (offset, _) in script.match_indices("tools.exec_command(") {
        let rest = &script[offset + "tools.exec_command(".len()..];
        let object = rest.split_once('}')?.0;
        if let Some((_, value)) = object
            .split_once("cmd:")
            .or_else(|| object.split_once("\"cmd\":"))
            && let Some(value) = script_literal(value.trim_start())
        {
            commands.push(value);
        }
    }
    for (offset, _) in script.match_indices("tools.apply_patch(") {
        if let Some(patch) =
            script_literal(script[offset + "tools.apply_patch(".len()..].trim_start())
        {
            written.extend(
                patch
                    .lines()
                    .filter(|line| !line.starts_with("+++"))
                    .filter_map(|line| line.strip_prefix('+'))
                    .map(str::to_owned),
            );
            paths.extend(
                patch
                    .lines()
                    .filter_map(|line| {
                        ["*** Add File: ", "*** Update File: ", "*** Delete File: "]
                            .iter()
                            .find_map(|prefix| line.strip_prefix(prefix))
                    })
                    .map(str::to_owned),
            );
        }
    }
    Some((commands.join("\n"), written.join("\n"), paths.join("\n")))
}
fn script_literal(text: &str) -> Option<String> {
    let mut chars = text.chars();
    let quote = chars.next().filter(|c| matches!(c, '\'' | '"' | '`'))?;
    let mut value = String::new();
    while let Some(c) = chars.next() {
        if c == quote {
            return Some(value);
        }
        if c == '\\' {
            value.push(match chars.next()? {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                c => c,
            });
        } else {
            value.push(c);
        }
    }
    None
}

fn structured_input(
    input: &BTreeMap<String, JsonValue>,
    out: &mut ActionView,
    command: &mut String,
) {
    for (key, value) in input {
        match key.as_str() {
            "command" | "cmd" | "commandLine" | "command_line" => {
                if let Some(v) = string(value) {
                    command.push_str(v);
                    command.push('\n');
                }
                if let JsonValue::Array(items) = value {
                    for v in items.iter().filter_map(string) {
                        command.push_str(v);
                        command.push(' ');
                    }
                }
            }
            "content" | "new_string" | "new_source" => {
                if let Some(v) = string(value) {
                    out.put("authored_content", v.to_owned());
                }
            }
            "edits" => {
                if let JsonValue::Array(edits) = value {
                    for edit in edits {
                        if let JsonValue::Object(edit) = edit
                            && let Some(v) = edit.get("new_string").and_then(string)
                        {
                            out.put("authored_content", v.to_owned());
                        }
                    }
                }
            }
            "old_string" | "prompt" | "description" | "todos" | "plan" | "questions"
            | "summary" | "title" | "message" | "reason" | "tldr" | "caption" | "activeForm"
            | "subject" => {}
            "url" | "uri" | "href" | "endpoint" => {
                if let Some(v) = string(value) {
                    out.put("url", v.to_owned());
                }
            }
            "file_path" | "filePath" | "path" | "paths" | "notebook_path" | "file" | "filename"
            | "target_file" | "glob" | "pattern" => {
                if let Some(v) = string(value) {
                    out.put("file_path", v.to_owned());
                }
                if let JsonValue::Array(items) = value {
                    for v in items.iter().filter_map(string) {
                        out.put("file_path", v.to_owned());
                    }
                }
            }
            _ => {
                if let Some(v) = string(value) {
                    out.put("arguments", v.to_owned());
                }
            }
        }
    }
}

/// Heredoc bodies are authored/code text, not shell statements. The shell reader
/// deliberately declines ambiguous syntax rather than treating code as commands.
fn strip_heredocs(command: &str) -> (String, String) {
    let mut output = String::new();
    let mut authored = String::new();
    let mut delimiter: Option<(String, bool)> = None;
    for line in command.lines() {
        if let Some((end, writes)) = &delimiter {
            if line.trim() == end {
                delimiter = None;
            } else if *writes {
                authored.push_str(line);
                authored.push('\n');
            }
            continue;
        }
        output.push_str(line);
        output.push('\n');
        if let Some((head, rest)) = line.split_once("<<") {
            if rest.starts_with('<') {
                continue;
            }
            let end = rest
                .trim_start_matches('-')
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(['\'', '"']);
            if !end.is_empty() {
                delimiter = Some((
                    end.to_owned(),
                    (head.contains("cat") && head.contains('>')) || head.contains("tee "),
                ));
            }
        }
    }
    (output.trim_end().to_owned(), authored)
}

fn regex(pattern: &'static str, text: &str) -> bool {
    // Closed, versioned native interpretation predicates, compiled once.
    static PATTERNS: LazyLock<std::sync::Mutex<BTreeMap<&'static str, Regex>>> =
        LazyLock::new(|| std::sync::Mutex::new(BTreeMap::new()));
    let mut patterns = PATTERNS.lock().expect("native predicate cache");
    patterns
        .entry(pattern)
        .or_insert_with(|| Regex::new(pattern).expect("native predicate"))
        .is_match(text)
}
fn command_word(tokens: &[String]) -> &str {
    let first = tokens.first().map(String::as_str).unwrap_or("");
    let first = first
        .split_once("=$(")
        .map_or(first, |(_, command)| command);
    first.rsplit(['/', '\\']).next().unwrap_or(first)
}
fn shell_comment(command: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    let mut previous = None;
    for c in command.chars() {
        if escaped {
            escaped = false;
            previous = Some(c);
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(open) = quote {
            if c == open {
                quote = None;
            }
        } else if matches!(c, '\'' | '"') {
            quote = Some(c);
        } else if c == '#' && previous.is_none_or(char::is_whitespace) {
            return true;
        }
        previous = Some(c);
    }
    false
}
fn is_download(tokens: &[String]) -> bool {
    matches!(
        command_word(tokens).to_ascii_lowercase().as_str(),
        "curl" | "wget" | "aria2c" | "invoke-webrequest" | "iwr" | "fetch"
    ) && tokens
        .iter()
        .any(|s| s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://"))
        && !is_upload(tokens)
}
fn is_upload(tokens: &[String]) -> bool {
    match command_word(tokens).to_ascii_lowercase().as_str() {
        "curl" => {
            !tokens.iter().any(|s| s == "-G" || s == "--get")
                && tokens.iter().any(|s| {
                    matches!(
                        s.as_str(),
                        "-d" | "-F"
                            | "-T"
                            | "--data"
                            | "--data-binary"
                            | "--data-raw"
                            | "--data-urlencode"
                            | "--upload-file"
                            | "--form"
                    ) || s.starts_with("--data=")
                        || (s.starts_with("-d") && s.len() > 2)
                        || (s.starts_with("-F") && s.len() > 2)
                })
                || tokens.windows(2).any(|w| {
                    matches!(w[0].as_str(), "-X" | "--request")
                        && matches!(w[1].as_str(), "POST" | "PUT")
                })
        }
        "wget" => tokens
            .iter()
            .any(|s| s.starts_with("--post-data") || s.starts_with("--post-file")),
        "aws" | "gsutil" | "rclone" => tokens
            .iter()
            .position(|s| matches!(s.as_str(), "cp" | "copy"))
            .is_some_and(|position| {
                let operands = tokens
                    .iter()
                    .skip(position + 1)
                    .filter(|s| !s.starts_with('-'))
                    .take(2)
                    .collect::<Vec<_>>();
                operands.len() == 2 && !remote(operands[0]) && remote(operands[1])
            }),
        "az" => tokens
            .windows(3)
            .any(|w| w[0] == "storage" && w[1] == "blob" && w[2] == "upload"),
        _ => false,
    }
}
fn remote(value: &str) -> bool {
    value.starts_with("s3://")
        || value.starts_with("gs://")
        || (value.contains(':') && !value.contains(":/"))
}

fn native_fields<'a>(id: &str, view: &'a ActionView) -> Vec<(&'a str, &'a str)> {
    if matches!(
        id,
        "network.download" | "exfil.outbound_upload" | "exfil.encoded_http"
    ) {
        return view
            .stages
            .iter()
            .zip(&view.commands)
            .filter(|(stage, tokens)| match id {
                "network.download" => is_download(tokens),
                "exfil.outbound_upload" => is_upload(tokens),
                _ => {
                    matches!(
                        command_word(tokens),
                        "curl" | "wget" | "fetch" | "Invoke-WebRequest"
                    ) && (regex(r"[?=&][A-Za-z0-9+/]{20,}[+=][A-Za-z0-9+/=]*", stage)
                        || (stage.contains("$(") && stage.contains("base64"))
                        || regex(r"https?://[A-Za-z0-9-]*[0-9][A-Za-z0-9-]{15,}\.", stage))
                }
            })
            .map(|(stage, _)| ("command", stage.as_str()))
            .collect();
    }
    let fields = view.fields();
    let action = |name: &str| matches!(name, "command" | "file_path" | "url" | "arguments");
    fields.into_iter().filter(|(field, text)| match id {
        "network.download" => *field == "command" && view.commands.iter().any(|t| is_download(t)),
        "execution.shell" => *field == "command" && view.commands.iter().any(|t| matches!(command_word(t), "bash" | "sh" | "zsh" | "fish" | "pwsh" | "powershell" | "cmd.exe") || t.windows(2).any(|w| matches!(w[0].as_str(), "python" | "node" | "perl" | "ruby") && matches!(w[1].as_str(), "-c" | "-e"))),
        "secret.env.read" => *field == "file_path" && view.reads_paths && !view.text("command").contains("<<") && text.split_whitespace().any(|token| regex(r"(?i)(^|[/\\])\.(env|bash_secrets|zsh_secrets)(\.[a-z0-9_-]+)?$", token) && !regex(r"(?i)\.(example|sample|template|dist)$", token)),
        "secret.private_key.read" => (*field == "file_path" && view.reads_paths && regex(r"(?i)(^|[/\\\s])id_(rsa|ed25519|ecdsa|dsa)($|\s)|(^|[/\\\s])[^\s]*key[^\s]*\.(pem|p12)($|\s)|\*\.(pem|p12)", text))
            || (*field == "tool_result" && regex(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----(?:\s|\\n)+[A-Za-z0-9+/]{16,}", text)),
        "install.package_manager" => *field == "command" && view.commands.iter().any(|t| matches!(command_word(t), "npm" | "pnpm" | "yarn" | "bun" | "pip" | "pipx" | "uv" | "cargo" | "go" | "brew" | "apt" | "apt-get" | "dnf" | "yum") && t.iter().skip(1).any(|s| matches!(s.as_str(), "install" | "add" | "i" | "get" | "run" | "create" | "x"))),
        "exfil.outbound_upload" => *field == "command" && view.commands.iter().any(|t| is_upload(t)),
        "exfil.encoded_http" => *field == "command" && view.commands.iter().any(|t| matches!(command_word(t), "curl" | "wget" | "fetch" | "Invoke-WebRequest")) && (regex(r"[?=&][A-Za-z0-9+/]{20,}[+=][A-Za-z0-9+/=]*", text) || text.contains("base64") || regex(r"https?://[A-Za-z0-9-]*[0-9][A-Za-z0-9-]{15,}\.", text)),
        "credential.api_key.pattern" => regex(r"(^|[^A-Za-z0-9_])(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|Bearer\s+[A-Za-z0-9._~+/=-]{20,})", text),
        "mcp.server_enumeration" => *field == "command" && regex(r"(?i)\bmcp(?:-scan)?\b", text) && regex(r"(?i)\b(enumerate|probe|scan)\b|tools/list.*tools/list", text),
        "approval.bypass.context" => regex(r"(?i)\b(run|execute|call|hide|bypass|do not tell)\b.{0,100}\b(without (asking|approval|confirmation|telling)|approval|user)\b|--dangerously-skip-permissions|--no-approval", text),
        "tool.injection.shape" => regex(r#"<tool_call>|</tool_call>|"tool_calls"\s*:|recipient_name\s*:|arguments\s*:\s*\{"#, text),
        "credential.cloud_harvest" | "persistence.shell_profile" | "execution.encoded_payload" | "exfil.dns_encoding" | "supply_chain.publish" => action(field),
        _ => true,
    }).collect()
}

fn linked_modifier(modifier: &RuleV1CompatibilityModifier) -> bool {
    modifier.id == "chain.download_then_execute"
        && modifier.when_all_categories == ["download", "execution"]
        && modifier.when_all_rule_ids.is_empty()
}
fn linked_score(
    modifier: &RuleV1CompatibilityModifier,
    options: &DetailedEvaluationOptions,
) -> u64 {
    options.linked_download_score.unwrap_or_else(|| {
        if BUNDLED.modifiers().iter().any(|base| {
            base.id == modifier.id
                && base.score == modifier.score
                && base.when_all_categories == modifier.when_all_categories
                && base.when_all_rule_ids == modifier.when_all_rule_ids
        }) {
            DEFAULT_ACTION_DOWNLOAD_LINK_SCORE
        } else {
            modifier.score
        }
    })
}

struct ActionStep {
    index: usize,
    time: OffsetDateTime,
    ids: BTreeSet<String>,
    categories: BTreeSet<String>,
}
fn ordered_support(
    modifier: &RuleV1CompatibilityModifier,
    history: &VecDeque<ActionStep>,
    used: &BTreeSet<usize>,
    completing: usize,
    remaining_work: &mut usize,
) -> Result<Option<Vec<usize>>, ProcessingError> {
    let requirements = modifier
        .when_all_categories
        .iter()
        .map(|s| (true, s))
        .chain(modifier.when_all_rule_ids.iter().map(|s| (false, s)))
        .collect::<Vec<_>>();
    if requirements.is_empty() {
        return Ok(None);
    }
    if history.back().is_none_or(|end| end.index != completing) {
        return Ok(None);
    }
    crate::process_chain_session::ordered_predecessors(
        history.len() - 1,
        time::Duration::seconds(ACTION_CHAIN_WINDOW_SECONDS as i64),
        requirements.len(),
        |position| history[position].time,
        |step, position| {
            let candidate = &history[position];
            if step == 0 && used.contains(&candidate.index) {
                return false;
            }
            let (category, name) = requirements[step];
            if category {
                candidate.categories.contains(name)
            } else {
                candidate.ids.contains(name)
            }
        },
        remaining_work,
    )
    .map(|result| {
        result.map(|positions| {
            positions
                .into_iter()
                .map(|position| history[position].index)
                .collect()
        })
    })
    .map_err(|_| ProcessingError::Bounds)
}

pub(crate) fn evaluate(
    export: &RuleV1CompatibilityExport,
    compiled: &[ActionRule],
    observations: &[&CanonicalObservationV2],
    options: &DetailedEvaluationOptions,
    budget: &mut RetentionBudget,
) -> Result<(Vec<ActionFinding>, BTreeMap<String, usize>), ProcessingError> {
    options.validate()?;
    let mut views = Vec::new();
    let mut work_bytes = 0usize;
    for observation in observations {
        let extracted = view(observation);
        work_bytes = work_bytes
            .checked_add(extracted.fields.values().map(String::len).sum::<usize>())
            .ok_or(ProcessingError::Bounds)?;
        if work_bytes > super::session::MAX_COMPATIBILITY_RETAINED_BYTES {
            return Err(ProcessingError::Bounds);
        }
        views.push(extracted);
    }
    let identities = observations
        .iter()
        .zip(&views)
        .map(|(o, v)| replay(o, v))
        .collect::<Vec<_>>();
    let mut counts = BTreeMap::new();
    for identity in identities.iter().flatten() {
        *counts.entry(identity.clone()).or_insert(0usize) += 1;
    }
    let mut pending: Vec<(String, OffsetDateTime, usize, usize)> = Vec::new();
    let mut history: VecDeque<ActionStep> = VecDeque::new();
    let mut remaining_sequence_work = 1_000_000usize;
    let mut remaining_link_work = 1_000_000usize;
    let mut consumed: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    let mut findings = Vec::new();
    let semantic_identity = provenance(export, options).identity;
    for (index, (observation, view)) in observations.iter().zip(&views).enumerate() {
        let mut ids = BTreeSet::new();
        let mut categories = BTreeSet::new();
        let mut evidence = Vec::new();
        let mut contributions = Vec::new();
        let mut correlation_support = BTreeMap::new();
        for (rule, compiled) in export.rules().iter().zip(compiled) {
            let fields = if compiled.native {
                native_fields(&rule.id, view)
            } else {
                view.fields()
            };
            // Native profiles are canonical interpretation of bundled predicates;
            // custom predicates always retain the effective Rule v1 matcher.
            let matched: Vec<(&str, &str)> = {
                let mapped = fields
                    .iter()
                    .map(|(k, v)| {
                        (
                            if compiled.native
                                && matches!(*k, "authored_content" | "user_context")
                                && rule.id == "credential.api_key.pattern"
                            {
                                "tool_result"
                            } else {
                                *k
                            },
                            *v,
                        )
                    })
                    .collect::<Vec<_>>();
                compiled
                    .matcher
                    .matching_fields(&mapped)
                    .iter()
                    .filter_map(|(name, value)| {
                        fields
                            .iter()
                            .find(|(k, v)| {
                                *v == *value
                                    && (*k == *name
                                        || (*name == "tool_result"
                                            && matches!(*k, "authored_content" | "user_context")))
                            })
                            .copied()
                    })
                    .collect()
            };
            let candidate = matched.iter().find(|(_, value)| {
                !compiled.native
                    || rule.id != "credential.api_key.pattern"
                    || credential_value(value)
            });
            let Some((field, value)) = candidate else {
                continue;
            };
            ids.insert(rule.id.clone());
            categories.insert(rule.category.clone());
            evidence.push(ActionEvidence {
                field: (*field).to_owned(),
                rule_id: rule.id.clone(),
                redacted_value: redact_sensitive_text(value),
            });
            if rule.score > 0 {
                contributions.push(
                    RiskContribution::new(
                        &rule.id,
                        RiskContributionType::DeterministicRule,
                        rule.score,
                        redact_sensitive_text(&rule.explanation),
                    )
                    .map_err(|_| ProcessingError::Evaluation)?,
                );
            }
        }
        let time = observation
            .occurred_at()
            .and_then(|t| OffsetDateTime::parse(t.as_str(), &Rfc3339).ok());
        let atomic_ids = ids.clone();
        let sequence_candidate = export
            .modifiers()
            .iter()
            .filter(|m| !linked_modifier(m) && !m.when_all_categories.is_empty())
            .any(|m| {
                m.when_all_categories
                    .iter()
                    .any(|category| categories.contains(category))
                    || m.when_all_rule_ids.iter().any(|id| ids.contains(id))
            });
        if let Some(time) =
            time.filter(|_| observation.session_id().is_some() && sequence_candidate)
        {
            while history.front().is_some_and(|step| {
                time - step.time > time::Duration::seconds(ACTION_CHAIN_WINDOW_SECONDS as i64)
            }) {
                remaining_sequence_work = remaining_sequence_work
                    .checked_sub(1)
                    .ok_or(ProcessingError::Bounds)?;
                history.pop_front();
            }
            history.push_back(ActionStep {
                index,
                time,
                ids: ids.clone(),
                categories: categories.clone(),
            });
            for modifier in export
                .modifiers()
                .iter()
                .filter(|m| !linked_modifier(m) && !m.when_all_categories.is_empty())
            {
                let used = consumed.entry(modifier.id.clone()).or_default();
                if let Some(indexes) = ordered_support(
                    modifier,
                    &history,
                    used,
                    index,
                    &mut remaining_sequence_work,
                )? {
                    used.insert(indexes[0]);
                    correlation_support.insert(modifier.id.clone(), indexes);
                    ids.insert(modifier.id.clone());
                    if modifier.score > 0 {
                        contributions.push(
                            RiskContribution::new(
                                &modifier.id,
                                RiskContributionType::ChainModifier,
                                modifier.score,
                                redact_sensitive_text(&modifier.explanation),
                            )
                            .map_err(|_| ProcessingError::Evaluation)?,
                        );
                    }
                }
            }
        }
        // This specialized owner is the only artifact-link reader. Unknown syntax,
        // absent source time, and unscoped observations cannot arm a timed link.
        if let Some(time) =
            time.filter(|_| observation.session_id().is_some() && !view.commands.is_empty())
        {
            let work = pending
                .len()
                .checked_mul(view.commands.len() + 1)
                .ok_or(ProcessingError::Bounds)?;
            remaining_link_work = remaining_link_work
                .checked_sub(work)
                .ok_or(ProcessingError::Bounds)?;
            pending.retain(|(_, start, _, _)| {
                time - *start <= time::Duration::seconds(ACTION_CHAIN_WINDOW_SECONDS as i64)
            });
            if ids.contains("network.download") {
                for (artifact, command_index) in downloaded_artifacts(&view.commands) {
                    if artifact != "-" {
                        pending.push((artifact, time, index, command_index));
                    }
                }
            }
            if let Some(modifier) = export.modifiers().iter().find(|m| linked_modifier(m)) {
                let linked = pending.iter().position(
                    |(artifact, start, observation_index, command_index)| {
                        *start <= time
                            && executes(
                                &view.commands,
                                artifact,
                                if *observation_index == index {
                                    command_index + 1
                                } else {
                                    0
                                },
                            )
                    },
                );
                let pipe =
                    ids.contains("network.download") && piped_execution(view.text("command"));
                if linked.is_some() || pipe {
                    let mut support = vec![index];
                    if let Some(i) = linked {
                        support.push(pending.remove(i).2);
                    }
                    support.sort_unstable();
                    support.dedup();
                    correlation_support.insert(modifier.id.clone(), support);
                    ids.insert(modifier.id.clone());
                    categories.insert("execution".to_owned());
                    let score = linked_score(modifier, options);
                    if score > 0 {
                        contributions.push(
                            RiskContribution::new(
                                &modifier.id,
                                RiskContributionType::ChainModifier,
                                score,
                                redact_sensitive_text(&modifier.explanation),
                            )
                            .map_err(|_| ProcessingError::Evaluation)?,
                        );
                    }
                    evidence.push(ActionEvidence {
                        field: "command".into(),
                        rule_id: modifier.id.clone(),
                        redacted_value: redact_sensitive_text(view.text("command")),
                    });
                }
            }
        }
        // Rule-ID-only modifiers retain their effective same-action predicates.
        let atomic = atomic_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        for modifier in export
            .triggered_modifiers(&atomic)
            .into_iter()
            .filter(|m| !linked_modifier(m) && m.when_all_categories.is_empty())
        {
            if modifier.score > 0 {
                contributions.push(
                    RiskContribution::new(
                        &modifier.id,
                        RiskContributionType::ChainModifier,
                        modifier.score,
                        redact_sensitive_text(&modifier.explanation),
                    )
                    .map_err(|_| ProcessingError::Evaluation)?,
                );
            }
            // Added after borrowed atomic IDs have been released below.
        }
        let modifiers = export
            .triggered_modifiers(&atomic)
            .into_iter()
            .filter(|m| !linked_modifier(m) && m.when_all_categories.is_empty())
            .map(|m| m.id.clone())
            .collect::<Vec<_>>();
        ids.extend(modifiers);
        if ids.is_empty() {
            continue;
        }
        let context = context(observations, index, &options.context);
        let tool_name = match observation.body() {
            ObservationBody::Tool(tool) => {
                tool.name().map(|name| terminal_identifier("tool", name))
            }
            _ => None,
        };
        let session_id = observation
            .session_id()
            .map(|s| terminal_session_id(s.value()));
        let bytes = evidence
            .iter()
            .map(|e| e.redacted_value.len() + e.field.len() + e.rule_id.len())
            .sum::<usize>()
            + context
                .iter()
                .map(|e| {
                    e.redacted_text.len()
                        + e.kind.len()
                        + e.tool_name.as_ref().map_or(0, String::len)
                        + e.occurred_at.as_ref().map_or(0, String::len)
                })
                .sum::<usize>()
            + ids.iter().map(String::len).sum::<usize>()
            + categories.iter().map(String::len).sum::<usize>()
            + observation.observation_id().len()
            + observation.kind().as_str().len()
            + observation.stage().as_str().len()
            + tool_name.as_ref().map_or(0, String::len)
            + session_id.as_ref().map_or(0, String::len)
            + observation.occurred_at().map_or(0, |t| t.as_str().len())
            + identities[index].as_ref().map_or(0, String::len)
            + contributions
                .iter()
                .map(|c| c.id().len() + c.rationale().len())
                .sum::<usize>();
        budget.consume(1 + context.len() + evidence.len(), bytes)?;
        let mut native = Vec::new();
        for id in &ids {
            let points = contributions
                .iter()
                .find(|c| c.id() == id)
                .map_or(0, |c| c.points());
            let mut metadata =
                if let Some(rule) = export.rules().iter().find(|rule| &rule.id == id) {
                    super::rule_v1::rule_metadata(rule).map_err(|_| ProcessingError::Evaluation)?
                } else {
                    super::FindingMetadata::new(
                        super::FindingKind::Correlation,
                        "action_correlation",
                        if points == 0 {
                            super::Severity::Informational
                        } else {
                            super::Severity::High
                        },
                    )
                    .map_err(|_| ProcessingError::Evaluation)?
                }
                .with_risk_points(points)
                .map_err(|_| ProcessingError::Evaluation)?
                .with_semantic_identity(&semantic_identity)
                .map_err(|_| ProcessingError::Evaluation)?;
            if let Some(session) = observation.session_id() {
                metadata = metadata
                    .with_session_id(session.value())
                    .map_err(|_| ProcessingError::Evaluation)?;
            }
            let support = correlation_support
                .get(id)
                .cloned()
                .unwrap_or_else(|| vec![index]);
            if !atomic_ids.contains(id) {
                metadata = metadata.with_correlation_scope(super::CorrelationScope::Session);
            }
            let observation_ids = support
                .iter()
                .map(|i| {
                    ObservationId::new(observations[*i].observation_id())
                        .map_err(|_| ProcessingError::Evaluation)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let result = super::DetectorResult::evaluated_match(
                super::DetectorIdentity::new(super::DetectorKind::ObservationMatch, id)
                    .map_err(|_| ProcessingError::Evaluation)?,
                &observation_ids,
                metadata,
            )
            .map_err(|_| ProcessingError::Evaluation)?;
            native.push(
                result
                    .finding()
                    .map_err(|_| ProcessingError::Evaluation)?
                    .ok_or(ProcessingError::Evaluation)?,
            );
        }
        let supporting_observation_ids = native
            .iter()
            .flat_map(|f| f.observation_ids().iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let score = native
            .iter()
            .map(|f| u64::from(f.risk_points().unwrap_or(0)))
            .sum();
        let finding_kind = if native
            .iter()
            .any(|f| f.finding_kind() == super::FindingKind::Correlation)
        {
            ActionFindingKind::Correlation
        } else {
            ActionFindingKind::Atomic
        };
        let severity = native
            .iter()
            .map(|f| f.severity())
            .max()
            .ok_or(ProcessingError::Evaluation)?
            .as_str()
            .to_owned();
        let coordinate = ActionCoordinate(observation.observation_id().to_owned());
        let canonical_findings = native
            .iter()
            .map(CanonicalActionFinding::from_finding)
            .collect::<Vec<_>>();
        let projected_contributions = native
            .iter()
            .filter(|f| f.risk_points().is_some_and(|score| score > 0))
            .map(|f| {
                let id = f.detectors()[0].id();
                ActionContribution {
                    id: terminal_identifier("rule", id),
                    points: u64::from(f.risk_points().unwrap_or(0)),
                    contribution_type: if f.finding_kind() == super::FindingKind::Correlation {
                        RiskContributionType::ChainModifier
                    } else {
                        RiskContributionType::DeterministicRule
                    },
                    rationale: contributions
                        .iter()
                        .find(|c| c.id() == id)
                        .map_or_else(String::new, |c| redact_sensitive_text(c.rationale())),
                }
            })
            .collect();
        budget.consume(
            canonical_findings.len(),
            serde_json::to_vec(&canonical_findings)
                .map_err(|_| ProcessingError::Evaluation)?
                .len(),
        )?;
        budget.consume(
            0,
            coordinate.as_str().len()
                + supporting_observation_ids
                    .iter()
                    .map(String::len)
                    .sum::<usize>()
                + severity.len(),
        )?;
        findings.push(ActionFinding {
            canonical_findings,
            coordinate,
            finding_kind,
            severity,
            supporting_observation_ids,
            detector_kind: "rule_v1_action".into(),
            observation_id: observation.observation_id().to_owned(),
            kind: observation.kind().as_str().to_owned(),
            stage: observation.stage().as_str().to_owned(),
            tool_name,
            session_id,
            timeline_index: index,
            occurred_at: observation.occurred_at().map(|t| t.as_str().to_owned()),
            replay_identity: identities[index]
                .as_ref()
                .filter(|id| counts.get(*id) == Some(&1))
                .map(|id| ReplayIdentity(id.clone())),
            rule_ids: native
                .iter()
                .map(|f| terminal_identifier("rule", f.detectors()[0].id()))
                .collect(),
            categories: native
                .iter()
                .map(|f| terminal_identifier("category", f.category()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            promotion_score: score,
            contributions: projected_contributions,
            evidence: evidence
                .into_iter()
                .map(|mut e| {
                    e.rule_id = terminal_identifier("rule", &e.rule_id);
                    e.field = terminal_identifier("field", &e.field);
                    e
                })
                .collect(),
            context,
        });
    }
    Ok((findings, counts))
}

/// Project already-evaluated process results; never reparse or reevaluate them.
pub(crate) fn process_findings(
    results: &[super::DetectorResult],
    observations: &[&CanonicalObservationV2],
    options: &DetailedEvaluationOptions,
    budget: &mut RetentionBudget,
) -> Result<Vec<ActionFinding>, ProcessingError> {
    let mut output = Vec::new();
    for result in results {
        let Some(finding) = result.finding().map_err(|_| ProcessingError::Evaluation)? else {
            continue;
        };
        let Some((index, observation)) = observations.iter().enumerate().rev().find(|(_, o)| {
            result
                .observation_ids()
                .iter()
                .any(|id| id == o.observation_id())
        }) else {
            return Err(ProcessingError::Evaluation);
        };
        let score = u64::from(result.risk_points().unwrap_or(0));
        let rule_id = terminal_identifier("rule", result.detector().id());
        let context = context(observations, index, &options.context);
        let tool_name = match observation.body() {
            ObservationBody::Tool(tool) => {
                tool.name().map(|name| terminal_identifier("tool", name))
            }
            _ => None,
        };
        let contributions = if score == 0 {
            Vec::new()
        } else {
            vec![ActionContribution {
                id: rule_id.clone(),
                points: score,
                contribution_type: if result.finding_kind() == super::FindingKind::Correlation {
                    RiskContributionType::ChainModifier
                } else {
                    RiskContributionType::DeterministicRule
                },
                rationale: "process-chain finding".into(),
            }]
        };
        let action = ActionFinding {
            canonical_findings: vec![CanonicalActionFinding::from_finding(&finding)],
            coordinate: ActionCoordinate(observation.observation_id().to_owned()),
            finding_kind: match result.finding_kind() {
                super::FindingKind::Correlation => ActionFindingKind::Correlation,
                _ => ActionFindingKind::Atomic,
            },
            severity: result.severity().as_str().into(),
            supporting_observation_ids: result.observation_ids().to_vec(),
            detector_kind: "process_chain".into(),
            observation_id: observation.observation_id().into(),
            kind: observation.kind().as_str().into(),
            stage: observation.stage().as_str().into(),
            tool_name,
            session_id: observation
                .session_id()
                .map(|s| terminal_session_id(s.value())),
            timeline_index: index,
            occurred_at: observation.occurred_at().map(|t| t.as_str().into()),
            replay_identity: None,
            rule_ids: vec![rule_id],
            categories: vec![terminal_identifier("category", result.category())],
            promotion_score: score,
            contributions,
            evidence: Vec::new(),
            context,
        };
        let bytes = serde_json::to_vec(&action)
            .map_err(|_| ProcessingError::Evaluation)?
            .len();
        budget.consume(1 + action.context.len(), bytes)?;
        output.push(action);
    }
    Ok(output)
}

fn credential_value(text: &str) -> bool {
    // Exclusions apply to each candidate, not an entire field containing a real
    // token next to a documentation example.
    static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|Bearer\s+[A-Za-z0-9._~+/=-]{20,}").unwrap()
    });
    TOKEN.find_iter(text).any(|m| {
        let token = m.as_str();
        let lower = token.to_ascii_lowercase();
        ![
            "example",
            "1234567890abcdef",
            "your_",
            "placeholder",
            "redacted",
        ]
        .iter()
        .any(|v| lower.contains(v))
            && (m.start() == 0 || !text.as_bytes()[m.start() - 1].is_ascii_alphanumeric())
    })
}

fn downloaded_artifacts(commands: &[Vec<String>]) -> Vec<(String, usize)> {
    commands
        .iter()
        .enumerate()
        .filter(|(_, t)| is_download(t))
        .filter_map(|(index, t)| {
            let client = command_word(t).to_ascii_lowercase();
            let bindings = t
                .iter()
                .filter(|token| {
                    token.contains('>')
                        || match client.as_str() {
                            "curl" => {
                                token.starts_with("--output")
                                    || token.as_str() == "--remote-name"
                                    || (token.starts_with('-')
                                        && !token.starts_with("--")
                                        && token[1..].contains(['o', 'O']))
                            }
                            "wget" => {
                                token.starts_with("--output-document") || token.starts_with("-O")
                            }
                            "invoke-webrequest" | "iwr" => token.eq_ignore_ascii_case("-OutFile"),
                            _ => false,
                        }
                })
                .count();
            if bindings > 1 {
                return None;
            }
            let mut artifact = None;
            for (i, token) in t.iter().enumerate().skip(1) {
                let next = || t.get(i + 1).cloned();
                if token == ">" || token == "1>" {
                    artifact = next();
                    break;
                }
                if token.starts_with('>') && token.len() > 1 {
                    artifact = Some(token[1..].to_owned());
                    break;
                }
                match client.as_str() {
                    "curl" => {
                        if token == "--output" {
                            artifact = next();
                            break;
                        }
                        if let Some(path) = token.strip_prefix("--output=") {
                            artifact = Some(path.into());
                            break;
                        }
                        if token.starts_with('-')
                            && !token.starts_with("--")
                            && let Some(position) = token[1..].find('o')
                        {
                            let suffix = &token[position + 2..];
                            artifact = if suffix.is_empty() {
                                next()
                            } else {
                                Some(suffix.into())
                            };
                            break;
                        }
                        if token == "-O" || token == "--remote-name" {
                            artifact = remote_basename(t);
                            break;
                        }
                    }
                    "wget" => {
                        if token == "-O" || token == "--output-document" {
                            artifact = next();
                            break;
                        }
                        if let Some(path) = token
                            .strip_prefix("--output-document=")
                            .or_else(|| token.strip_prefix("-O").filter(|s| !s.is_empty()))
                        {
                            artifact = Some(path.into());
                            break;
                        }
                    }
                    "invoke-webrequest" | "iwr" if token.eq_ignore_ascii_case("-OutFile") => {
                        artifact = next();
                        break;
                    }
                    _ => {}
                }
            }
            if artifact.is_none() && client == "wget" {
                artifact = remote_basename(t);
            }
            artifact
                .filter(|s| !s.contains(['$', '`', '*', '%', '(', ')']) && !s.is_empty())
                .map(|s| (s.trim_start_matches("./").to_owned(), index))
        })
        .collect()
}
fn remote_basename(tokens: &[String]) -> Option<String> {
    let mut urls = tokens.iter().filter(|s| {
        s.starts_with("https://") || s.starts_with("http://") || s.starts_with("ftp://")
    });
    let url = urls.next()?;
    if urls.next().is_some() {
        return None;
    }
    let path = url
        .split(['?', '#'])
        .next()?
        .split_once("://")?
        .1
        .split_once('/')?
        .1;
    let basename = path.rsplit('/').next()?;
    (!basename.is_empty()).then(|| basename.to_owned())
}
fn executes(commands: &[Vec<String>], artifact: &str, start: usize) -> bool {
    commands.iter().skip(start).any(|t| {
        let first = t.first().map(String::as_str).unwrap_or("");
        ((first.contains('/') || first.contains('\\'))
            && first.trim_start_matches("./") == artifact)
            || (matches!(
                first,
                "bash" | "sh" | "zsh" | "python" | "python3" | "node" | "perl" | "ruby"
            ) && t
                .get(1)
                .is_some_and(|s| !s.starts_with('-') && s.trim_start_matches("./") == artifact))
            || (matches!(first.to_ascii_lowercase().as_str(), "powershell" | "pwsh")
                && t.windows(2).any(|w| {
                    w[0].eq_ignore_ascii_case("-File") && w[1].trim_start_matches("./") == artifact
                }))
    })
}
fn piped_execution(command: &str) -> bool {
    let mut quote = None;
    let mut pipes = Vec::new();
    let mut escaped = false;
    for (index, c) in command.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if let Some(open) = quote {
            if c == open {
                quote = None;
            }
            continue;
        }
        if matches!(c, '\'' | '"') {
            quote = Some(c);
        } else if c == '|'
            && !command[index..].starts_with("||")
            && (index == 0 || command.as_bytes()[index - 1] != b'|')
        {
            pipes.push(index);
        }
    }
    if quote.is_some() || pipes.len() != 1 {
        return false;
    }
    let index = pipes[0];
    let left = split_statements(&command[..index]);
    let right = split_statements(&command[index + 1..]);
    left.last().zip(right.first()).is_some_and(|(left, right)| {
        let tokens = tokenize(left);
        is_download(&tokens) && download_stdout(&tokens) && consumes_stdin_code(&tokenize(right))
    })
}
fn download_stdout(tokens: &[String]) -> bool {
    let artifacts = downloaded_artifacts(&[tokens.to_vec()]);
    if artifacts.iter().any(|(path, _)| path == "-") {
        return true;
    }
    if command_word(tokens) != "curl" {
        return false;
    }
    artifacts.is_empty()
        && !tokens.iter().any(|token| {
            token.contains('>')
                || token.starts_with("--output")
                || token == "--head"
                || token == "--remote-name"
                || (token.starts_with('-')
                    && !token.starts_with("--")
                    && token[1..].contains(['o', 'O', 'I']))
        })
}
fn consumes_stdin_code(tokens: &[String]) -> bool {
    let Some(program) = tokens.first() else {
        return false;
    };
    let args = &tokens[1..];
    match program.to_ascii_lowercase().as_str() {
        "bash" | "sh" | "zsh" => {
            args.is_empty()
                || args == ["-"]
                || args == ["-s"]
                || args.first().is_some_and(|s| s == "-s") && args.get(1).is_some_and(|s| s == "--")
        }
        "python" | "python3" | "node" | "perl" | "ruby" => args.is_empty() || args == ["-"],
        "iex" | "invoke-expression" => args.is_empty(),
        "powershell" | "pwsh" => {
            args.len() == 2 && args[0].eq_ignore_ascii_case("-Command") && args[1] == "-"
        }
        _ => false,
    }
}

fn replay(observation: &CanonicalObservationV2, view: &ActionView) -> Option<String> {
    let time = observation.occurred_at()?;
    if view.fields.is_empty() {
        return None;
    }
    let mut hash = Sha256::new();
    hash.update(b"telltale:action-replay:v1\0");
    frame(&mut hash, observation.source().adapter_type().as_bytes());
    frame(&mut hash, observation.kind().as_str().as_bytes());
    frame(&mut hash, observation.stage().as_str().as_bytes());
    frame(&mut hash, time.as_str().as_bytes());
    let call = observation
        .correlation()
        .call_id()
        .filter(|id| id.origin() == CorrelationOrigin::SourceReported)
        .map(|id| id.value())
        .unwrap_or("");
    frame(&mut hash, call.as_bytes());
    for (field, value) in &view.fields {
        frame(&mut hash, field.as_bytes());
        frame(&mut hash, value.as_bytes());
    }
    Some(format!("replay:v1:sha256:{:x}", hash.finalize()))
}

pub(crate) fn context(
    observations: &[&CanonicalObservationV2],
    anchor: usize,
    options: &ContextOptions,
) -> Vec<ActionContextEntry> {
    let start = anchor.saturating_sub(options.before);
    let end = (anchor + options.after + 1).min(observations.len());
    observations
        .iter()
        .enumerate()
        .take(end)
        .skip(start)
        .filter_map(|(index, o)| {
            if index == anchor
                || o.session_id() != observations[anchor].session_id()
                || o.session_id().is_none()
            {
                return None;
            }
            let (kind, text, tool_name) = project_context(o, options)?;
            Some(ActionContextEntry {
                offset: index as i32 - anchor as i32,
                kind: kind.to_owned(),
                occurred_at: o.occurred_at().map(|t| t.as_str().to_owned()),
                tool_name,
                redacted_text: text,
            })
        })
        .collect()
}

/// Pure privacy projector usable by local investigation without opening a path.
pub fn project_context(
    o: &CanonicalObservationV2,
    options: &ContextOptions,
) -> Option<(&'static str, String, Option<String>)> {
    if o.source().ingestion_mode() == IngestionMode::Import {
        return None;
    }
    let (kind, text, tool) = match o.body() {
        ObservationBody::Message(message) => {
            let kind = match message.role() {
                Some(MessageRole::User) if options.user_text => "user_message",
                Some(MessageRole::Assistant) if options.assistant_text => "assistant_message",
                _ => return None,
            };
            let text = message
                .content()
                .and_then(string)
                .into_iter()
                .chain(
                    message
                        .content_parts()
                        .iter()
                        .filter(|p| p.kind() == ContentPartKind::Text)
                        .filter_map(|p| string(p.value())),
                )
                .collect::<Vec<_>>()
                .join("\n");
            (kind, text, None)
        }
        ObservationBody::Tool(tool)
            if options.tool_arguments
                && matches!(
                    o.stage(),
                    ObservationStage::ToolProposed
                        | ObservationStage::ToolRequested
                        | ObservationStage::ToolExecutionStarted
                        | ObservationStage::ToolExecutionCompleted
                ) =>
        {
            let text = tool
                .arguments()
                .and_then(|v| canonical_identity_json(v).ok())
                .and_then(|v| String::from_utf8(v).ok())
                .or_else(|| tool.searchable_arguments().map(str::to_owned))?;
            (
                "tool_call",
                text,
                tool.name().map(|s| terminal_identifier("tool", s)),
            )
        }
        _ => return None,
    };
    if text.trim().is_empty() {
        return None;
    }
    Some((kind, redact_sensitive_text(&text), tool))
}
