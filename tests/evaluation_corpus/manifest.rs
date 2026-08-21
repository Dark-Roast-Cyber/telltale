use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use jsonschema::validator_for;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use telltale_rules::bundled_default_rule_set;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::scoring::RiskContributionType;
use telltale_sources::clients::supported_clients;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub cases: Vec<Case>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub description: String,
    pub input: Input,
    pub eventfulness: Eventfulness,
    pub disposition: Disposition,
    pub expected_security_review: ExpectedSecurityReview,
    pub label_rationale: String,
    pub expected_visibility: VisibilityExpectation,
    pub expected_detection: DetectionExpectation,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Input {
    SourceFixture {
        fixture: String,
        client: Client,
        source_id: String,
        source_kind: SourceKindName,
    },
    NormalizedRecords {
        client: Client,
        records: Vec<RecordInput>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordInput {
    pub session_id: String,
    pub kind: RecordKindName,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub arguments: Option<String>,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisibilityExpectation {
    pub required_record_kinds: Vec<RecordKindName>,
    pub optional_fields: Vec<VisibilityField>,
    pub unavailable_fields: Vec<VisibilityField>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionExpectation {
    #[serde(default)]
    pub rule_expectations: Vec<RuleExpectation>,
    #[serde(default)]
    pub exact_rule_set: bool,
    pub expected_score: u64,
    pub expected_contributions: Vec<ExpectedContribution>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleExpectation {
    pub rule_id: String,
    pub expectation: RuleExpectationKind,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ExpectedContribution {
    pub id: String,
    #[serde(rename = "type")]
    pub contribution_type: RiskContributionType,
    pub points: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Eventfulness {
    Uneventful,
    Routine,
    Noteworthy,
}

impl Eventfulness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uneventful => "uneventful",
            Self::Routine => "routine",
            Self::Noteworthy => "noteworthy",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Benign,
    Malicious,
    Unknown,
    NotApplicable,
}

impl Disposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Benign => "benign",
            Self::Malicious => "malicious",
            Self::Unknown => "unknown",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedSecurityReview {
    Required,
    NotRequired,
    NotScored,
}

impl ExpectedSecurityReview {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::NotRequired => "not_required",
            Self::NotScored => "not_scored",
        }
    }

    pub fn is_scored(self) -> bool {
        !matches!(self, Self::NotScored)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RuleExpectationKind {
    ExpectedMatch,
    ExpectedAbsent,
    NotScored,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Client {
    Codex,
    Claude,
    Gemini,
    Openclaw,
    Qwen,
    Roocode,
    Kilocode,
    Opencode,
    Copilot,
}

impl Client {
    pub fn client_id(self) -> ClientId {
        match self {
            Self::Codex => ClientId::Codex,
            Self::Claude => ClientId::Claude,
            Self::Gemini => ClientId::Gemini,
            Self::Openclaw => ClientId::OpenClaw,
            Self::Qwen => ClientId::Qwen,
            Self::Roocode => ClientId::RooCode,
            Self::Kilocode => ClientId::KiloCode,
            Self::Opencode => ClientId::OpenCode,
            Self::Copilot => ClientId::Copilot,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SourceKindName {
    Json,
    Jsonl,
    ArchivedJsonl,
    HeadlessJsonl,
    Sqlite,
    LegacyJson,
    UiMessagesJson,
    CopilotProcessLog,
}

impl SourceKindName {
    pub fn source_kind(self) -> SourceKind {
        match self {
            Self::Json => SourceKind::Json,
            Self::Jsonl => SourceKind::Jsonl,
            Self::ArchivedJsonl => SourceKind::ArchivedJsonl,
            Self::HeadlessJsonl => SourceKind::HeadlessJsonl,
            Self::Sqlite => SourceKind::Sqlite,
            Self::LegacyJson => SourceKind::LegacyJson,
            Self::UiMessagesJson => SourceKind::UiMessagesJson,
            Self::CopilotProcessLog => SourceKind::CopilotProcessLog,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RecordKindName {
    UserMessage,
    AssistantMessage,
    ToolCall,
    ToolResult,
    SessionMeta,
    Other,
}

impl RecordKindName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserMessage => "user_message",
            Self::AssistantMessage => "assistant_message",
            Self::ToolCall => "tool_call",
            Self::ToolResult => "tool_result",
            Self::SessionMeta => "session_meta",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityField {
    Pid,
    ParentPid,
    UserIntent,
    Timestamp,
    ToolName,
    Arguments,
    Content,
    Agent,
    Model,
    Provider,
}

impl VisibilityField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pid => "pid",
            Self::ParentPid => "parent_pid",
            Self::UserIntent => "user_intent",
            Self::Timestamp => "timestamp",
            Self::ToolName => "tool_name",
            Self::Arguments => "arguments",
            Self::Content => "content",
            Self::Agent => "agent",
            Self::Model => "model",
            Self::Provider => "provider",
        }
    }
}

pub fn load_manifest(path: &Path, repo_root: &Path) -> Result<Manifest, String> {
    let bytes = fs::read(path).map_err(|error| format!("read manifest: {error}"))?;
    let text = std::str::from_utf8(&bytes).map_err(|error| format!("manifest UTF-8: {error}"))?;
    let manifest = validate_manifest_bytes(text, repo_root)?;
    Ok(manifest)
}

pub fn manifest_sha256(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("read manifest: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn validate_manifest_bytes(text: &str, repo_root: &Path) -> Result<Manifest, String> {
    let value = serde_yaml::from_str::<serde_json::Value>(text)
        .map_err(|error| format!("manifest YAML: {error}"))?;
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../evaluation/manifest.schema.json"))
            .map_err(|error| format!("manifest schema JSON: {error}"))?;
    let validator = validator_for(&schema).map_err(|error| format!("manifest schema: {error}"))?;
    if !validator.is_valid(&value) {
        let detail = validator
            .iter_errors(&value)
            .next()
            .map(|error| error.to_string())
            .unwrap_or_else(|| "unknown schema validation error".to_string());
        return Err(format!("manifest schema validation: {detail}"));
    }
    let manifest = serde_yaml::from_str::<Manifest>(text)
        .map_err(|error| format!("manifest deserialization: {error}"))?;
    validate_manifest(&manifest, repo_root)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &Manifest, repo_root: &Path) -> Result<(), String> {
    if manifest.version != 1 {
        return Err(format!(
            "unsupported manifest version {}; expected 1",
            manifest.version
        ));
    }
    let rule_set = bundled_default_rule_set().map_err(|error| error.to_string())?;
    let enabled_rule_ids = rule_set
        .rules
        .iter()
        .filter(|rule| rule.enabled && rule_set.defaults.enabled)
        .map(|rule| rule.id.clone())
        .chain(
            rule_set
                .modifiers
                .iter()
                .filter(|modifier| modifier.enabled && rule_set.defaults.enabled)
                .map(|modifier| modifier.id.clone()),
        )
        .collect::<BTreeSet<_>>();
    let mut case_ids = BTreeSet::new();
    for case in &manifest.cases {
        if case.id.trim().is_empty() || !case_ids.insert(case.id.clone()) {
            return Err(format!("duplicate or empty case id: {}", case.id));
        }
        if case.description.trim().is_empty() {
            return Err(format!("case {} has an empty description", case.id));
        }
        if case.label_rationale.trim().is_empty() {
            return Err(format!("case {} has an empty label_rationale", case.id));
        }
        let rationale = case.label_rationale.to_ascii_lowercase();
        if [
            "current score",
            "observed score",
            "actual matched rule",
            "detector output",
            "golden report",
            "baseline already",
        ]
        .iter()
        .any(|forbidden| rationale.contains(forbidden))
        {
            return Err(format!(
                "case {} has an output-derived label_rationale",
                case.id
            ));
        }
        validate_input(&case.input, repo_root)?;
        validate_tags(case)?;
        validate_visibility(&case.expected_visibility, &case.id)?;
        validate_detection(case, &enabled_rule_ids)?;
    }
    Ok(())
}

fn validate_input(input: &Input, repo_root: &Path) -> Result<(), String> {
    let Input::SourceFixture {
        fixture,
        client,
        source_id,
        source_kind,
    } = input
    else {
        return Ok(());
    };
    let relative = Path::new(fixture);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| part == Component::ParentDir)
    {
        return Err(format!("fixture path must be repo-relative: {fixture}"));
    }
    let fixture_path = repo_root.join(relative);
    if !fixture_path.is_file() {
        return Err(format!("fixture does not exist: {fixture}"));
    }
    let canonical_root = repo_root
        .canonicalize()
        .map_err(|error| format!("canonicalize repo root: {error}"))?;
    let canonical_fixture = fixture_path
        .canonicalize()
        .map_err(|error| format!("canonicalize fixture {fixture}: {error}"))?;
    if !canonical_fixture.starts_with(&canonical_root) {
        return Err(format!("fixture resolves outside repository: {fixture}"));
    }
    if expected_source_kind(*client, source_id) != Some(source_kind.source_kind()) {
        return Err(format!(
            "invalid source identity ({}, {source_id}, {})",
            client.client_id().as_str(),
            source_kind.source_kind().as_str()
        ));
    }
    Ok(())
}

fn validate_tags(case: &Case) -> Result<(), String> {
    let tags = case
        .tags
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if tags.len() != case.tags.len() {
        return Err(format!("case {} has duplicate tags", case.id));
    }
    let has_tag = |tag| tags.contains(&tag);
    let scored = case.expected_security_review.is_scored();

    if has_tag("efficacy") != scored {
        return Err(format!(
            "case {} must use the efficacy tag exactly when security review is scored",
            case.id
        ));
    }
    if has_tag("benign_confounder")
        && (case.disposition != Disposition::Benign
            || case.expected_security_review != ExpectedSecurityReview::NotRequired
            || !case
                .expected_detection
                .rule_expectations
                .iter()
                .any(|expectation| {
                    matches!(
                        expectation.expectation,
                        RuleExpectationKind::ExpectedMatch | RuleExpectationKind::ExpectedAbsent
                    )
                }))
    {
        return Err(format!(
            "case {} has an invalid benign_confounder tag",
            case.id
        ));
    }
    if has_tag("source_conformance") && !matches!(case.input, Input::SourceFixture { .. }) {
        return Err(format!(
            "case {} has source_conformance without a source fixture",
            case.id
        ));
    }
    if has_tag("candidate_source") {
        let Input::SourceFixture { source_id, .. } = &case.input else {
            return Err(format!(
                "case {} has candidate_source without a source fixture",
                case.id
            ));
        };
        if !candidate_source_ids().contains(source_id) || scored {
            return Err(format!(
                "case {} has an invalid candidate_source tag",
                case.id
            ));
        }
    }
    Ok(())
}

fn validate_visibility(visibility: &VisibilityExpectation, case_id: &str) -> Result<(), String> {
    let optional = visibility
        .optional_fields
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let unavailable = visibility
        .unavailable_fields
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if !optional.is_disjoint(&unavailable) {
        return Err(format!(
            "case {case_id} has contradictory visibility fields"
        ));
    }
    Ok(())
}

fn validate_detection(case: &Case, enabled_rule_ids: &BTreeSet<String>) -> Result<(), String> {
    let detection = &case.expected_detection;
    let mut expectations = BTreeSet::new();
    for expectation in &detection.rule_expectations {
        if !enabled_rule_ids.contains(&expectation.rule_id) {
            return Err(format!(
                "case {} references unknown enabled rule {}",
                case.id, expectation.rule_id
            ));
        }
        if !expectations.insert(expectation.rule_id.clone()) {
            return Err(format!(
                "case {} duplicates rule expectation {}",
                case.id, expectation.rule_id
            ));
        }
        if detection.exact_rule_set && expectation.expectation == RuleExpectationKind::NotScored {
            return Err(format!(
                "case {} cannot use not_scored expectations with exact_rule_set",
                case.id
            ));
        }
    }
    let mut contributions = BTreeSet::new();
    let mut expected_points = 0_u64;
    for contribution in &detection.expected_contributions {
        if contribution.points == 0
            || !telltale_schema::scoring::is_canonical_contribution_id(&contribution.id)
            || !contributions.insert((contribution.contribution_type, contribution.id.clone()))
        {
            return Err(format!(
                "case {} has malformed expected contribution",
                case.id
            ));
        }
        expected_points = expected_points
            .checked_add(contribution.points)
            .ok_or_else(|| {
                format!(
                    "case {} expected contribution points overflow the score range",
                    case.id
                )
            })?;
    }
    if expected_points != detection.expected_score {
        return Err(format!(
            "case {} expected contribution points {expected_points} do not equal expected score {}",
            case.id, detection.expected_score
        ));
    }
    Ok(())
}

pub fn expected_source_kind(client: Client, source_id: &str) -> Option<SourceKind> {
    supported_clients()
        .iter()
        .find(|definition| definition.id == client.client_id())
        .and_then(|definition| {
            definition
                .sources
                .iter()
                .find(|source| source.id == source_id)
        })
        .map(|source| source.kind)
}

pub fn supported_source_ids() -> BTreeSet<String> {
    registered_source_ids()
        .difference(&candidate_source_ids())
        .cloned()
        .collect()
}

pub fn candidate_source_ids() -> BTreeSet<String> {
    // The public registry does not encode support maturity. Keep the two
    // documented candidate identities explicit, then derive the supported
    // denominator as every other registered identity. A newly registered
    // source therefore fails evaluation coverage until its status and fixture
    // representation are reviewed.
    BTreeSet::from([
        "codex.project_sessions".to_string(),
        "opencode.project_json".to_string(),
    ])
}

fn registered_source_ids() -> BTreeSet<String> {
    supported_clients()
        .iter()
        .flat_map(|client| client.sources.iter())
        .map(|source| source.id.to_string())
        .collect()
}

pub fn fixture_path(repo_root: &Path, fixture: &str) -> PathBuf {
    repo_root.join(fixture)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_derived_source_sets_preserve_current_coverage_contract() {
        let supported = supported_source_ids();
        let candidates = candidate_source_ids();
        assert_eq!(
            supported,
            BTreeSet::from([
                "claude.projects".to_string(),
                "codex.archived_sessions".to_string(),
                "codex.headless_sessions".to_string(),
                "codex.sessions".to_string(),
                "copilot.process_log".to_string(),
                "gemini.tmp".to_string(),
                "kilocode.tasks".to_string(),
                "openclaw.agents".to_string(),
                "opencode.legacy_json".to_string(),
                "opencode.sqlite".to_string(),
                "qwen.projects".to_string(),
                "roocode.tasks".to_string(),
            ])
        );
        assert_eq!(
            candidates,
            BTreeSet::from([
                "codex.project_sessions".to_string(),
                "opencode.project_json".to_string(),
            ])
        );
        assert_eq!(
            supported_source_ids()
                .union(&candidate_source_ids())
                .cloned()
                .collect::<BTreeSet<_>>(),
            registered_source_ids()
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_fixture_symlink_outside_repository_is_rejected() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let repo_root = temporary.path().join("repository");
        fs::create_dir_all(&repo_root).expect("repository directory");
        let outside = temporary.path().join("outside.jsonl");
        fs::write(&outside, "synthetic fixture").expect("outside fixture");
        std::os::unix::fs::symlink(&outside, repo_root.join("fixture.jsonl"))
            .expect("fixture symlink");

        let input = Input::SourceFixture {
            fixture: "fixture.jsonl".to_string(),
            client: Client::Codex,
            source_id: "codex.sessions".to_string(),
            source_kind: SourceKindName::Jsonl,
        };

        assert!(validate_input(&input, &repo_root).is_err());
    }
}
