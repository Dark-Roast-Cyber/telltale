//! Process-chain detection rules.
//!
//! This module carries a second, structured rule vocabulary alongside the
//! regex/target rules in [`crate`]. Regex rules answer "does this text look
//! risky"; process-chain rules answer "did *this* process spawn *that* one, and
//! what did the child's command line say". Keeping them separate means the
//! existing detection engine is untouched: chain rules add events, they never
//! reinterpret regex matches.
//!
//! Like the rest of this crate the module is I/O-free. Callers hand it
//! [`ProcessObservation`] values and get [`ProcessChainDetection`] values back;
//! event construction, entity risk, and correlation state live downstream.
//!
//! # Emission contract
//!
//! Every rule match produces a detection, including rules that score `0`. A
//! zero-score match is marked [`ProcessChainDetection::informational`] and
//! contributes no risk, but it is still emitted so that it can anchor a
//! timeline, satisfy a correlation sequence, or answer a hunt. Scoring and
//! emission are independent decisions.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde::Deserialize;

const DEFAULT_PROCESS_CHAIN_YAML: &str = include_str!("../data/process-chain.yaml");

/// Severity bands, ordered weakest to strongest.
pub const SEVERITIES: [&str; 5] = ["informational", "low", "medium", "high", "critical"];

/// Confidence bands, ordered weakest to strongest.
pub const CONFIDENCES: [&str; 3] = ["low", "medium", "high"];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
#[non_exhaustive]
pub enum ProcessChainError {
    Parse(String),
    InvalidRegex {
        rule_id: String,
        message: String,
    },
    InvalidRuleId(String),
    DuplicateRuleId(String),
    UnknownCategory {
        rule_id: String,
        category: String,
    },
    InvalidSeverity {
        rule_id: String,
        severity: String,
    },
    InvalidConfidence {
        rule_id: String,
        confidence: String,
    },
    InvalidMatchTarget {
        rule_id: String,
        target: String,
    },
    ScoreOutOfBand {
        rule_id: String,
        severity: String,
        score: u64,
    },
    EmptySequence(String),
}

impl std::fmt::Display for ProcessChainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(message) => write!(formatter, "process-chain pack parse error: {message}"),
            Self::InvalidRegex { rule_id, message } => {
                write!(
                    formatter,
                    "rule {rule_id} has an invalid pattern: {message}"
                )
            }
            Self::InvalidRuleId(id) => write!(formatter, "rule id {id} is not canonical"),
            Self::DuplicateRuleId(id) => write!(formatter, "duplicate rule id {id}"),
            Self::UnknownCategory { rule_id, category } => {
                write!(
                    formatter,
                    "rule {rule_id} uses undeclared category {category}"
                )
            }
            Self::InvalidSeverity { rule_id, severity } => {
                write!(
                    formatter,
                    "rule {rule_id} uses unsupported severity {severity}"
                )
            }
            Self::InvalidConfidence {
                rule_id,
                confidence,
            } => {
                write!(
                    formatter,
                    "rule {rule_id} uses unsupported confidence {confidence}"
                )
            }
            Self::InvalidMatchTarget { rule_id, target } => {
                write!(
                    formatter,
                    "rule {rule_id} uses unsupported match target {target}"
                )
            }
            Self::ScoreOutOfBand {
                rule_id,
                severity,
                score,
            } => write!(
                formatter,
                "rule {rule_id} scores {score}, which is outside the {severity} band"
            ),
            Self::EmptySequence(id) => {
                write!(formatter, "correlation {id} declares no sequence steps")
            }
        }
    }
}

impl std::error::Error for ProcessChainError {}

// ---------------------------------------------------------------------------
// Pack model (YAML shape)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ProcessChainPack {
    pub version: u32,
    pub description: String,
    pub defaults: PackDefaults,
    pub categories: BTreeMap<String, CategoryMetadata>,
    #[serde(default)]
    pub rules: Vec<ChainRuleDefinition>,
    #[serde(default)]
    pub standalone: Vec<StandaloneRuleDefinition>,
    #[serde(default)]
    pub correlations: Vec<CorrelationRuleDefinition>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PackDefaults {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_risk_entity")]
    pub risk_entity: String,
    #[serde(default = "default_suppression_window")]
    pub suppression_window_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CategoryMetadata {
    pub detection_class: String,
    pub analytic_intent: String,
    #[serde(default)]
    pub investigation_fields: Vec<String>,
    #[serde(default)]
    pub falsepositives: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainRuleDefinition {
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: String,
    pub score: u64,
    pub confidence: String,
    pub parent: String,
    pub child: String,
    #[serde(default)]
    pub mitre: Vec<String>,
    pub reason: String,
    #[serde(default)]
    pub child_command_line_any: Vec<String>,
    #[serde(default)]
    pub child_command_line_none: Vec<String>,
    #[serde(default)]
    pub child_path_any: Vec<String>,
    #[serde(default)]
    pub child_path_none: Vec<String>,
    /// Severity from the upstream reference library, retained for provenance.
    #[serde(default)]
    pub source_severity: Option<u8>,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Overrides the default `parent>child` deduplication key when a rule
    /// intentionally reports a behaviour that must not collapse into the pair.
    #[serde(default)]
    pub dedup_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StandaloneRuleDefinition {
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: String,
    pub score: u64,
    pub confidence: String,
    #[serde(default)]
    pub mitre: Vec<String>,
    pub reason: String,
    /// One of `process_name`, `process_path`, `command_line`.
    pub r#match: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CorrelationRuleDefinition {
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: String,
    pub score: u64,
    pub confidence: String,
    #[serde(default)]
    pub mitre: Vec<String>,
    pub reason: String,
    pub window_seconds: u64,
    pub entity: String,
    pub sequence: Vec<CorrelationStepDefinition>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CorrelationStepDefinition {
    #[serde(default)]
    pub any_category: Vec<String>,
    #[serde(default)]
    pub any_rule_id: Vec<String>,
    #[serde(default)]
    pub any_child: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_risk_entity() -> String {
    "host".to_string()
}

fn default_suppression_window() -> u64 {
    3600
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

/// One process as seen by a source. `name` may be a bare name or a full path;
/// normalization happens at match time and never mutates the preserved values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessRef {
    pub name: String,
    pub path: Option<String>,
    pub pid: Option<u64>,
    pub command_line: Option<String>,
}

impl ProcessRef {
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    pub fn with_command_line(mut self, command_line: impl Into<String>) -> Self {
        self.command_line = Some(command_line.into());
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Normalized comparison key: basename, lowercased, `.exe` removed.
    pub fn normalized_name(&self) -> String {
        // A full path in `name` is normalized the same way as `path`, so a
        // source that only populates one of the two still matches.
        normalize_process_name(&self.name)
    }

    /// Best available path text for path conditions, falling back to `name`
    /// when the source only reports a full path in the name field.
    pub fn path_text(&self) -> &str {
        match self.path.as_deref() {
            Some(path) if !path.is_empty() => path,
            _ => self.name.as_str(),
        }
    }

    pub fn command_line_text(&self) -> &str {
        self.command_line.as_deref().unwrap_or_default()
    }
}

/// A parent/child process relationship to evaluate.
#[derive(Debug, Clone, Default)]
pub struct ProcessObservation {
    pub parent: ProcessRef,
    pub child: ProcessRef,
    /// Populated when the source knows the grandparent; used only as context.
    pub grandparent: Option<ProcessRef>,
    pub host: Option<String>,
    pub user: Option<String>,
    pub timestamp: Option<String>,
    pub source_event_id: Option<String>,
    /// True when the parent was derived from the shape of a command line rather
    /// than reported directly by the source. Inferred parents lower confidence.
    pub parent_inferred: bool,
}

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessChainDetection {
    pub rule_id: String,
    pub rule_name: String,
    pub rule_category: String,
    pub detection_class: String,
    pub signal_type: String,
    pub analytic_intent: String,
    pub severity: String,
    pub score: u64,
    pub confidence: String,
    pub mitre_attack_techniques: Vec<String>,
    pub detection_reason: String,
    pub informational: bool,
    pub risk_entity_type: String,
    pub risk_entity_value: Option<String>,
    pub investigation_fields: Vec<String>,
    pub falsepositives: Vec<String>,
    /// Rules that matched the same behaviour and lost deduplication. Their
    /// technique IDs are merged into `mitre_attack_techniques`.
    pub secondary_rule_ids: Vec<String>,
    /// Stable key used both for deduplication within an observation and for
    /// throttling repeats across observations.
    pub dedup_key: String,
    pub suppression_window_seconds: u64,
    /// Set when a false-positive control lowered the score. The underlying
    /// detection is always retained.
    pub risk_adjustment: Option<String>,
}

impl ProcessChainDetection {
    pub fn is_informational(&self) -> bool {
        self.informational
    }
}

// ---------------------------------------------------------------------------
// Compiled rules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CompiledChainRule {
    definition: ChainRuleDefinition,
    detection_class: String,
    analytic_intent: String,
    investigation_fields: Vec<String>,
    falsepositives: Vec<String>,
    command_line_any: Vec<Regex>,
    command_line_none: Vec<Regex>,
    path_any: Vec<Regex>,
    path_none: Vec<Regex>,
    dedup_key: String,
}

#[derive(Debug, Clone)]
struct CompiledStandaloneRule {
    definition: StandaloneRuleDefinition,
    detection_class: String,
    analytic_intent: String,
    investigation_fields: Vec<String>,
    falsepositives: Vec<String>,
    patterns: Vec<Regex>,
    exclude: Vec<Regex>,
    target: StandaloneTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StandaloneTarget {
    ProcessName,
    ProcessPath,
    CommandLine,
}

#[derive(Debug, Clone)]
pub struct CompiledCorrelationRule {
    pub id: String,
    pub title: String,
    pub category: String,
    pub detection_class: String,
    pub analytic_intent: String,
    pub severity: String,
    pub score: u64,
    pub confidence: String,
    pub mitre_attack_techniques: Vec<String>,
    pub reason: String,
    pub window_seconds: u64,
    pub entity: String,
    pub steps: Vec<CorrelationStep>,
    pub falsepositives: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CorrelationStep {
    pub any_category: BTreeSet<String>,
    pub any_rule_id: BTreeSet<String>,
    pub any_child: BTreeSet<String>,
}

impl CorrelationStep {
    /// A step matches when every non-empty constraint it declares is satisfied.
    pub fn matches(&self, category: &str, rule_id: &str, child: &str) -> bool {
        if !self.any_category.is_empty() && !self.any_category.contains(category) {
            return false;
        }
        if !self.any_rule_id.is_empty() && !self.any_rule_id.contains(rule_id) {
            return false;
        }
        if !self.any_child.is_empty() && !self.any_child.contains(child) {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct CompiledProcessChainRules {
    chain_rules: Vec<CompiledChainRule>,
    standalone_rules: Vec<CompiledStandaloneRule>,
    correlations: Vec<CompiledCorrelationRule>,
    default_risk_entity: String,
    default_suppression_window_seconds: u64,
}

/// The embedded process-chain rule pack as YAML.
pub fn bundled_process_chain_yaml() -> &'static str {
    DEFAULT_PROCESS_CHAIN_YAML
}

/// Parses and compiles the embedded process-chain rule pack.
pub fn load_default_process_chain_rules() -> Result<CompiledProcessChainRules, ProcessChainError> {
    load_process_chain_rules(bundled_process_chain_yaml())
}

/// Parses and compiles a process-chain rule pack from YAML.
pub fn load_process_chain_rules(
    document: &str,
) -> Result<CompiledProcessChainRules, ProcessChainError> {
    let pack: ProcessChainPack = serde_yaml::from_str(document)
        .map_err(|error| ProcessChainError::Parse(error.to_string()))?;
    compile_pack(pack)
}

fn compile_pack(pack: ProcessChainPack) -> Result<CompiledProcessChainRules, ProcessChainError> {
    let mut seen_ids = BTreeSet::new();
    let mut chain_rules = Vec::with_capacity(pack.rules.len());
    let mut standalone_rules = Vec::with_capacity(pack.standalone.len());
    let mut correlations = Vec::with_capacity(pack.correlations.len());

    for definition in pack.rules {
        if !definition.enabled.unwrap_or(pack.defaults.enabled) {
            continue;
        }
        register_id(&mut seen_ids, &definition.id)?;
        let metadata = category_metadata(&pack.categories, &definition.id, &definition.category)?;
        validate_severity(&definition.id, &definition.severity)?;
        validate_confidence(&definition.id, &definition.confidence)?;
        validate_score_band(&definition.id, &definition.severity, definition.score)?;
        let dedup_key = definition.dedup_key.clone().unwrap_or_else(|| {
            format!(
                "chain:{}>{}",
                normalize_process_name(&definition.parent),
                normalize_process_name(&definition.child)
            )
        });
        chain_rules.push(CompiledChainRule {
            command_line_any: compile_all(&definition.id, &definition.child_command_line_any)?,
            command_line_none: compile_all(&definition.id, &definition.child_command_line_none)?,
            path_any: compile_all(&definition.id, &definition.child_path_any)?,
            path_none: compile_all(&definition.id, &definition.child_path_none)?,
            detection_class: metadata.detection_class.clone(),
            analytic_intent: metadata.analytic_intent.clone(),
            investigation_fields: metadata.investigation_fields.clone(),
            falsepositives: metadata.falsepositives.clone(),
            dedup_key,
            definition,
        });
    }

    for definition in pack.standalone {
        if !definition.enabled.unwrap_or(pack.defaults.enabled) {
            continue;
        }
        register_id(&mut seen_ids, &definition.id)?;
        let metadata = category_metadata(&pack.categories, &definition.id, &definition.category)?;
        validate_severity(&definition.id, &definition.severity)?;
        validate_confidence(&definition.id, &definition.confidence)?;
        validate_score_band(&definition.id, &definition.severity, definition.score)?;
        let target = match definition.r#match.as_str() {
            "process_name" => StandaloneTarget::ProcessName,
            "process_path" => StandaloneTarget::ProcessPath,
            "command_line" => StandaloneTarget::CommandLine,
            other => {
                return Err(ProcessChainError::InvalidMatchTarget {
                    rule_id: definition.id.clone(),
                    target: other.to_string(),
                });
            }
        };
        standalone_rules.push(CompiledStandaloneRule {
            patterns: compile_all(&definition.id, &definition.patterns)?,
            exclude: compile_all(&definition.id, &definition.exclude)?,
            detection_class: metadata.detection_class.clone(),
            analytic_intent: metadata.analytic_intent.clone(),
            investigation_fields: metadata.investigation_fields.clone(),
            falsepositives: metadata.falsepositives.clone(),
            target,
            definition,
        });
    }

    for definition in pack.correlations {
        if !definition.enabled.unwrap_or(pack.defaults.enabled) {
            continue;
        }
        register_id(&mut seen_ids, &definition.id)?;
        let metadata = category_metadata(&pack.categories, &definition.id, &definition.category)?;
        validate_severity(&definition.id, &definition.severity)?;
        validate_confidence(&definition.id, &definition.confidence)?;
        validate_score_band(&definition.id, &definition.severity, definition.score)?;
        if definition.sequence.is_empty() {
            return Err(ProcessChainError::EmptySequence(definition.id.clone()));
        }
        correlations.push(CompiledCorrelationRule {
            steps: definition
                .sequence
                .iter()
                .map(|step| CorrelationStep {
                    any_category: step.any_category.iter().cloned().collect(),
                    any_rule_id: step.any_rule_id.iter().cloned().collect(),
                    any_child: step
                        .any_child
                        .iter()
                        .map(|child| normalize_process_name(child))
                        .collect(),
                })
                .collect(),
            detection_class: metadata.detection_class.clone(),
            analytic_intent: metadata.analytic_intent.clone(),
            falsepositives: metadata.falsepositives.clone(),
            id: definition.id,
            title: definition.title,
            category: definition.category,
            severity: definition.severity,
            score: definition.score,
            confidence: definition.confidence,
            mitre_attack_techniques: definition.mitre,
            reason: definition.reason,
            window_seconds: definition.window_seconds,
            entity: definition.entity,
        });
    }

    Ok(CompiledProcessChainRules {
        chain_rules,
        standalone_rules,
        correlations,
        default_risk_entity: pack.defaults.risk_entity,
        default_suppression_window_seconds: pack.defaults.suppression_window_seconds,
    })
}

fn register_id(seen: &mut BTreeSet<String>, id: &str) -> Result<(), ProcessChainError> {
    if !telltale_schema::scoring::is_canonical_contribution_id(id) {
        return Err(ProcessChainError::InvalidRuleId(id.to_string()));
    }
    if !seen.insert(id.to_string()) {
        return Err(ProcessChainError::DuplicateRuleId(id.to_string()));
    }
    Ok(())
}

fn category_metadata<'a>(
    categories: &'a BTreeMap<String, CategoryMetadata>,
    rule_id: &str,
    category: &str,
) -> Result<&'a CategoryMetadata, ProcessChainError> {
    categories
        .get(category)
        .ok_or_else(|| ProcessChainError::UnknownCategory {
            rule_id: rule_id.to_string(),
            category: category.to_string(),
        })
}

fn validate_severity(rule_id: &str, severity: &str) -> Result<(), ProcessChainError> {
    if SEVERITIES.contains(&severity) {
        Ok(())
    } else {
        Err(ProcessChainError::InvalidSeverity {
            rule_id: rule_id.to_string(),
            severity: severity.to_string(),
        })
    }
}

fn validate_confidence(rule_id: &str, confidence: &str) -> Result<(), ProcessChainError> {
    if CONFIDENCES.contains(&confidence) {
        Ok(())
    } else {
        Err(ProcessChainError::InvalidConfidence {
            rule_id: rule_id.to_string(),
            confidence: confidence.to_string(),
        })
    }
}

/// Keeps rule authoring honest: a rule's declared severity and its numeric score
/// must agree with the bands documented in docs/process-chain-detections.md.
fn validate_score_band(rule_id: &str, severity: &str, score: u64) -> Result<(), ProcessChainError> {
    let band = match severity {
        "informational" => (0, 0),
        "low" => (20, 39),
        "medium" => (40, 49),
        "high" => (50, 79),
        "critical" => (80, 100),
        _ => (0, 100),
    };
    if score < band.0 || score > band.1 {
        return Err(ProcessChainError::ScoreOutOfBand {
            rule_id: rule_id.to_string(),
            severity: severity.to_string(),
            score,
        });
    }
    Ok(())
}

fn compile_all(rule_id: &str, patterns: &[String]) -> Result<Vec<Regex>, ProcessChainError> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(&format!("(?i:{pattern})")).map_err(|error| {
                ProcessChainError::InvalidRegex {
                    rule_id: rule_id.to_string(),
                    message: error.to_string(),
                }
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// Reduces a process name or full path to a stable comparison key.
///
/// - Windows and POSIX separators are both handled.
/// - Surrounding quotes and trailing whitespace are removed.
/// - Comparison is case-insensitive.
/// - A single trailing `.exe` is removed; other dots become `_` so that names
///   like `ScreenConnect.ClientService.exe` have one canonical spelling.
/// - Matching is always whole-key equality, never substring, so `net` never
///   matches `netsh` and `7z` never matches `7za`.
pub fn normalize_process_name(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches(['"', '\''].as_ref()).trim();
    let basename = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed).trim();
    let lowered = basename.to_ascii_lowercase();
    let stem = lowered.strip_suffix(".exe").unwrap_or(&lowered);
    stem.replace(['.', '-'], "_")
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// False-positive controls supplied by the deployment. Controls lower risk and
/// mark an event informational; they never drop the underlying detection, and
/// they never apply to a rule whose command-line conditions fired, so a broad
/// allowlist cannot hide a substantially different command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessChainContext {
    pub approved_admin_users: BTreeSet<String>,
    pub management_hosts: BTreeSet<String>,
    /// Normalized process names of RMM products this environment sanctions.
    pub approved_rmm_products: BTreeSet<String>,
}

impl ProcessChainContext {
    fn user_is_approved_admin(&self, user: Option<&str>) -> bool {
        user.is_some_and(|user| {
            self.approved_admin_users
                .contains(&user.to_ascii_lowercase())
        })
    }

    fn host_is_management(&self, host: Option<&str>) -> bool {
        host.is_some_and(|host| self.management_hosts.contains(&host.to_ascii_lowercase()))
    }
}

impl CompiledProcessChainRules {
    pub fn chain_rule_count(&self) -> usize {
        self.chain_rules.len()
    }

    pub fn standalone_rule_count(&self) -> usize {
        self.standalone_rules.len()
    }

    pub fn correlations(&self) -> &[CompiledCorrelationRule] {
        &self.correlations
    }

    pub fn rule_ids(&self) -> Vec<String> {
        self.chain_rules
            .iter()
            .map(|rule| rule.definition.id.clone())
            .chain(
                self.standalone_rules
                    .iter()
                    .map(|rule| rule.definition.id.clone()),
            )
            .chain(self.correlations.iter().map(|rule| rule.id.clone()))
            .collect()
    }

    /// Evaluates one observation with no environment-specific controls.
    pub fn evaluate(&self, observation: &ProcessObservation) -> Vec<ProcessChainDetection> {
        self.evaluate_with_context(observation, &ProcessChainContext::default())
    }

    /// Evaluates one observation and returns the deduplicated detections.
    ///
    /// All matching rules are collected first, then collapsed by dedup key:
    /// the strongest score wins, losers survive as `secondary_rule_ids`, and
    /// their technique IDs are merged into the winner. Zero-score winners are
    /// still returned, marked informational.
    pub fn evaluate_with_context(
        &self,
        observation: &ProcessObservation,
        context: &ProcessChainContext,
    ) -> Vec<ProcessChainDetection> {
        let parent = observation.parent.normalized_name();
        let child = observation.child.normalized_name();
        let child_command_line = observation.child.command_line_text();
        let child_path = observation.child.path_text();

        let mut candidates: Vec<(ProcessChainDetection, bool)> = Vec::new();

        for rule in &self.chain_rules {
            if rule.definition.parent != parent || rule.definition.child != child {
                continue;
            }
            if !conditions_hold(
                &rule.command_line_any,
                &rule.command_line_none,
                child_command_line,
            ) {
                continue;
            }
            if !conditions_hold(&rule.path_any, &rule.path_none, child_path) {
                continue;
            }
            let command_line_gated = !rule.command_line_any.is_empty();
            candidates.push((self.chain_detection(rule, observation), command_line_gated));
        }

        for rule in &self.standalone_rules {
            let Some(subject) = standalone_subject(rule.target, observation) else {
                continue;
            };
            if !rule.patterns.iter().any(|regex| regex.is_match(&subject)) {
                continue;
            }
            if rule.exclude.iter().any(|regex| regex.is_match(&subject)) {
                continue;
            }
            let command_line_gated = rule.target == StandaloneTarget::CommandLine;
            candidates.push((
                self.standalone_detection(rule, observation),
                command_line_gated,
            ));
        }

        let mut detections = deduplicate(candidates.iter().map(|(detection, _)| detection.clone()));
        let gated: BTreeSet<&str> = candidates
            .iter()
            .filter(|(_, gated)| *gated)
            .map(|(detection, _)| detection.rule_id.as_str())
            .collect();

        for detection in &mut detections {
            let gated = gated.contains(detection.rule_id.as_str());
            apply_context(detection, observation, context, gated);
            if observation.parent_inferred && !detection.secondary_rule_ids.is_empty() {
                // Nothing to do; secondary IDs are unaffected by inference.
            }
            if observation.parent_inferred {
                detection.confidence = weaken_confidence(&detection.confidence);
            }
        }

        detections.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        detections
    }

    fn chain_detection(
        &self,
        rule: &CompiledChainRule,
        observation: &ProcessObservation,
    ) -> ProcessChainDetection {
        let definition = &rule.definition;
        ProcessChainDetection {
            rule_id: definition.id.clone(),
            rule_name: definition.title.clone(),
            rule_category: definition.category.clone(),
            detection_class: rule.detection_class.clone(),
            signal_type: "chain".to_string(),
            analytic_intent: rule.analytic_intent.clone(),
            severity: definition.severity.clone(),
            score: definition.score,
            confidence: definition.confidence.clone(),
            mitre_attack_techniques: definition.mitre.clone(),
            detection_reason: definition.reason.clone(),
            informational: definition.score == 0,
            risk_entity_type: self.default_risk_entity.clone(),
            risk_entity_value: risk_entity_value(&self.default_risk_entity, observation),
            investigation_fields: rule.investigation_fields.clone(),
            falsepositives: rule.falsepositives.clone(),
            secondary_rule_ids: Vec::new(),
            dedup_key: rule.dedup_key.clone(),
            suppression_window_seconds: self.default_suppression_window_seconds,
            risk_adjustment: None,
        }
    }

    fn standalone_detection(
        &self,
        rule: &CompiledStandaloneRule,
        observation: &ProcessObservation,
    ) -> ProcessChainDetection {
        let definition = &rule.definition;
        ProcessChainDetection {
            rule_id: definition.id.clone(),
            rule_name: definition.title.clone(),
            rule_category: definition.category.clone(),
            detection_class: rule.detection_class.clone(),
            signal_type: "atomic".to_string(),
            analytic_intent: rule.analytic_intent.clone(),
            severity: definition.severity.clone(),
            score: definition.score,
            confidence: definition.confidence.clone(),
            mitre_attack_techniques: definition.mitre.clone(),
            detection_reason: definition.reason.clone(),
            informational: definition.score == 0,
            risk_entity_type: self.default_risk_entity.clone(),
            risk_entity_value: risk_entity_value(&self.default_risk_entity, observation),
            investigation_fields: rule.investigation_fields.clone(),
            falsepositives: rule.falsepositives.clone(),
            secondary_rule_ids: Vec::new(),
            // A process-name or path indicator is about a specific binary, so
            // the binary is part of the key and two binaries stay two findings.
            // A command-line indicator describes one command, which the nested
            // extractor sees once per interpreter level; keying it on the rule
            // alone lets those levels collapse into a single finding.
            dedup_key: match rule.target {
                StandaloneTarget::CommandLine => format!("standalone:{}", definition.id),
                _ => format!(
                    "standalone:{}:{}",
                    definition.id,
                    observation.child.normalized_name()
                ),
            },
            suppression_window_seconds: self.default_suppression_window_seconds,
            risk_adjustment: None,
        }
    }
}

fn standalone_subject(
    target: StandaloneTarget,
    observation: &ProcessObservation,
) -> Option<String> {
    let value = match target {
        StandaloneTarget::ProcessName => observation.child.normalized_name(),
        StandaloneTarget::ProcessPath => observation.child.path_text().to_ascii_lowercase(),
        StandaloneTarget::CommandLine => {
            let child = observation.child.command_line_text();
            if child.is_empty() {
                observation.parent.command_line_text().to_string()
            } else {
                child.to_string()
            }
        }
    };
    (!value.is_empty()).then_some(value)
}

fn conditions_hold(any: &[Regex], none: &[Regex], subject: &str) -> bool {
    if !any.is_empty() {
        // An `any` condition needs text to evaluate; a source that cannot supply
        // a command line simply does not match the gated variant, and the
        // ungated variant of the same pair still fires.
        if subject.is_empty() || !any.iter().any(|regex| regex.is_match(subject)) {
            return false;
        }
    }
    if !subject.is_empty() && none.iter().any(|regex| regex.is_match(subject)) {
        return false;
    }
    true
}

fn risk_entity_value(entity: &str, observation: &ProcessObservation) -> Option<String> {
    match entity {
        "host" => observation.host.clone(),
        "user" => observation.user.clone(),
        _ => observation
            .host
            .clone()
            .or_else(|| observation.user.clone()),
    }
}

/// Collapses matches that describe the same behaviour.
///
/// Grouping is by `dedup_key`. Within a group the highest score wins; ties break
/// on the stronger severity, then on rule ID so output is deterministic. Losing
/// rule IDs are preserved on the winner, and every technique ID seen in the
/// group is merged into the winner so no ATT&CK mapping is lost.
fn deduplicate(
    detections: impl IntoIterator<Item = ProcessChainDetection>,
) -> Vec<ProcessChainDetection> {
    let mut groups: BTreeMap<String, Vec<ProcessChainDetection>> = BTreeMap::new();
    for detection in detections {
        groups
            .entry(detection.dedup_key.clone())
            .or_default()
            .push(detection);
    }

    groups
        .into_values()
        .filter_map(|mut group| {
            group.sort_by(|left, right| {
                right
                    .score
                    .cmp(&left.score)
                    .then_with(|| {
                        severity_rank(&right.severity).cmp(&severity_rank(&left.severity))
                    })
                    .then_with(|| left.rule_id.cmp(&right.rule_id))
            });
            let mut winner = group.first().cloned()?;
            let mut techniques: BTreeSet<String> =
                winner.mitre_attack_techniques.iter().cloned().collect();
            for loser in group.iter().skip(1) {
                winner.secondary_rule_ids.push(loser.rule_id.clone());
                techniques.extend(loser.mitre_attack_techniques.iter().cloned());
            }
            winner.secondary_rule_ids.sort();
            winner.secondary_rule_ids.dedup();
            winner.mitre_attack_techniques = techniques.into_iter().collect();
            Some(winner)
        })
        .collect()
}

pub fn severity_rank(severity: &str) -> usize {
    SEVERITIES
        .iter()
        .position(|candidate| *candidate == severity)
        .unwrap_or(0)
}

fn confidence_rank(confidence: &str) -> usize {
    CONFIDENCES
        .iter()
        .position(|candidate| *candidate == confidence)
        .unwrap_or(0)
}

fn weaken_confidence(confidence: &str) -> String {
    let rank = confidence_rank(confidence);
    CONFIDENCES[rank.saturating_sub(1)].to_string()
}

/// Score for the band immediately below `severity`, used when a false-positive
/// control demotes a detection without deleting it.
fn demoted(severity: &str) -> (&'static str, u64) {
    match severity {
        "critical" => ("high", 55),
        "high" => ("medium", 40),
        "medium" => ("low", 20),
        _ => ("informational", 0),
    }
}

fn apply_context(
    detection: &mut ProcessChainDetection,
    observation: &ProcessObservation,
    context: &ProcessChainContext,
    command_line_gated: bool,
) {
    // A rule that fired because of a specific command-line condition saw the
    // actual bad argument, not just a common parent/child pair. Allowlists do
    // not get to soften that.
    if command_line_gated {
        return;
    }

    let mut reason: Option<&str> = None;

    if context.user_is_approved_admin(observation.user.as_deref())
        && matches!(
            detection.rule_category.as_str(),
            "discovery" | "execution" | "persistence" | "lateral_movement"
        )
        && detection.severity != "critical"
    {
        reason = Some("approved administrative user");
    }

    if reason.is_none()
        && context.host_is_management(observation.host.as_deref())
        && matches!(
            detection.rule_category.as_str(),
            "lateral_movement" | "execution" | "discovery"
        )
    {
        reason = Some("known management server");
    }

    if reason.is_none()
        && detection.rule_category == "command_and_control"
        && context
            .approved_rmm_products
            .contains(&observation.parent.normalized_name())
    {
        reason = Some("sanctioned remote management product");
    }

    if reason.is_none()
        && detection.rule_category == "command_and_control"
        && context
            .approved_rmm_products
            .contains(&observation.child.normalized_name())
    {
        reason = Some("sanctioned remote management product");
    }

    let Some(reason) = reason else {
        return;
    };
    let (severity, score) = demoted(&detection.severity);
    detection.severity = severity.to_string();
    detection.score = score;
    detection.informational = score == 0;
    detection.risk_adjustment = Some(reason.to_string());
}

#[cfg(test)]
mod tests {
    use super::{
        ProcessChainContext, ProcessObservation, ProcessRef, load_default_process_chain_rules,
        normalize_process_name,
    };

    fn observation(parent: &str, child: &str, command_line: &str) -> ProcessObservation {
        ProcessObservation {
            parent: ProcessRef::named(parent),
            child: ProcessRef::named(child).with_command_line(command_line),
            host: Some("host-1".to_string()),
            user: Some("alice".to_string()),
            ..ProcessObservation::default()
        }
    }

    #[test]
    fn bundled_pack_compiles() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        assert!(rules.chain_rule_count() > 300);
        assert!(rules.standalone_rule_count() >= 13);
        assert_eq!(rules.correlations().len(), 6);
    }

    #[test]
    fn normalizes_paths_case_and_extension() {
        assert_eq!(
            normalize_process_name(r"C:\Windows\System32\WHOAMI.EXE"),
            "whoami"
        );
        assert_eq!(normalize_process_name("/usr/bin/PowerShell"), "powershell");
        assert_eq!(normalize_process_name("\"cmd.exe\""), "cmd");
        assert_eq!(
            normalize_process_name(r"C:\Program Files\ScreenConnect.ClientService.exe"),
            "screenconnect_clientservice"
        );
        assert_eq!(normalize_process_name("7za.exe"), "7za");
    }

    #[test]
    fn zero_risk_chain_still_emits_an_informational_detection() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        let detections = rules.evaluate(&observation("powershell.exe", "hostname.exe", "hostname"));
        let detection = detections
            .iter()
            .find(|detection| detection.rule_id == "procchain.discovery.powershell_hostname")
            .expect("informational detection emitted");
        assert_eq!(detection.score, 0);
        assert_eq!(detection.severity, "informational");
        assert!(detection.informational);
    }

    #[test]
    fn matching_is_case_insensitive_and_path_normalized() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        let observation = ProcessObservation {
            parent: ProcessRef::named(r"C:\Windows\System32\CMD.EXE"),
            child: ProcessRef::named(r"C:\Windows\System32\WHOAMI.EXE")
                .with_command_line("whoami /all"),
            ..ProcessObservation::default()
        };
        assert!(
            rules
                .evaluate(&observation)
                .iter()
                .any(|detection| detection.rule_id == "procchain.discovery.cmd_whoami")
        );
    }

    #[test]
    fn similar_binary_names_do_not_collide() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        // `net` must not match `netsh`, and `7z` must not match `7za`.
        let netsh = rules.evaluate(&observation("cmd.exe", "netsh.exe", "netsh firewall show"));
        assert!(
            netsh
                .iter()
                .all(|detection| !detection.rule_id.contains("net_account"))
        );
        let seven_za = rules.evaluate(&observation("cmd.exe", "7za.exe", "7za a out.7z data"));
        assert!(
            seven_za
                .iter()
                .any(|detection| detection.rule_id == "procchain.collection.cmd_7za")
        );
    }

    #[test]
    fn strongest_interpretation_wins_and_keeps_the_other_technique() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        let detections = rules.evaluate(&observation(
            "cmd.exe",
            "vssadmin.exe",
            "vssadmin delete shadows /all /quiet",
        ));
        let detection = detections
            .iter()
            .find(|detection| detection.dedup_key == "chain:cmd>vssadmin")
            .expect("one deduplicated finding for the pair");
        assert_eq!(detection.rule_id, "procchain.impact.vssadmin_shadow_delete");
        assert_eq!(detection.severity, "critical");
        assert!(
            detection
                .mitre_attack_techniques
                .contains(&"T1490".to_string())
        );
    }

    #[test]
    fn administrative_shadow_copy_use_is_separated_from_deletion() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        let detections = rules.evaluate(&observation(
            "cmd.exe",
            "vssadmin.exe",
            "vssadmin create shadow /for=C:",
        ));
        let detection = detections
            .iter()
            .find(|detection| detection.dedup_key == "chain:cmd>vssadmin")
            .expect("administrative variant emitted");
        assert_eq!(
            detection.rule_id,
            "procchain.credaccess.vssadmin_shadow_access"
        );
        assert_eq!(detection.severity, "medium");
    }

    #[test]
    fn office_to_powershell_scores_far_above_shell_discovery() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        let office = rules.evaluate(&observation(
            "winword.exe",
            "powershell.exe",
            "powershell -w hidden",
        ));
        let office_score = office
            .iter()
            .find(|detection| detection.rule_id == "procchain.execution.winword_powershell")
            .map(|detection| detection.score)
            .expect("office chain matched");
        let discovery = rules.evaluate(&observation("cmd.exe", "whoami.exe", "whoami"));
        let discovery_score = discovery
            .iter()
            .find(|detection| detection.rule_id == "procchain.discovery.cmd_whoami")
            .map(|detection| detection.score)
            .expect("discovery chain matched");
        assert!(office_score > discovery_score * 2);
    }

    #[test]
    fn web_server_shell_is_critical() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        let detections = rules.evaluate(&observation("w3wp.exe", "cmd.exe", "cmd /c dir"));
        let detection = detections
            .iter()
            .find(|detection| detection.rule_id == "procchain.execution.w3wp_cmd")
            .expect("web shell chain matched");
        assert_eq!(detection.severity, "critical");
        assert!(detection.score >= 80);
    }

    #[test]
    fn approved_admin_context_reduces_risk_without_deleting_the_event() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        let mut context = ProcessChainContext::default();
        context.approved_admin_users.insert("alice".to_string());
        let detections =
            rules.evaluate_with_context(&observation("cmd.exe", "whoami.exe", "whoami"), &context);
        let detection = detections
            .iter()
            .find(|detection| detection.rule_id == "procchain.discovery.cmd_whoami")
            .expect("detection retained");
        assert_eq!(detection.score, 0);
        assert!(detection.informational);
        assert_eq!(
            detection.risk_adjustment.as_deref(),
            Some("approved administrative user")
        );
    }

    #[test]
    fn allowlist_does_not_soften_a_command_line_gated_rule() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        let mut context = ProcessChainContext::default();
        context.approved_admin_users.insert("alice".to_string());
        let detections = rules.evaluate_with_context(
            &observation(
                "cmd.exe",
                "net.exe",
                "net localgroup administrators evil /add",
            ),
            &context,
        );
        let detection = detections
            .iter()
            .find(|detection| detection.rule_id == "procchain.persistence.net_account_add")
            .expect("gated rule matched");
        assert_eq!(detection.severity, "high");
        assert!(detection.risk_adjustment.is_none());
    }

    #[test]
    fn missing_command_line_still_matches_ungated_rules() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        let observation = ProcessObservation {
            parent: ProcessRef::named("winword.exe"),
            child: ProcessRef::named("powershell.exe"),
            ..ProcessObservation::default()
        };
        assert!(
            rules
                .evaluate(&observation)
                .iter()
                .any(|detection| detection.rule_id == "procchain.execution.winword_powershell")
        );
    }

    #[test]
    fn credential_dumping_command_line_scores_critical() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        let detections = rules.evaluate(&observation(
            "cmd.exe",
            "rundll32.exe",
            r"rundll32 C:\windows\system32\comsvcs.dll MiniDump 640 out.dmp full",
        ));
        let detection = detections
            .iter()
            .find(|detection| detection.rule_id == "procchain.credaccess.credential_dump_command")
            .expect("credential dump indicator matched");
        assert_eq!(detection.severity, "critical");
        assert!(detection.score >= 80);
    }

    #[test]
    fn inferred_parent_lowers_confidence() {
        let rules = load_default_process_chain_rules().expect("pack compiles");
        let mut observation = observation("cmd.exe", "mimikatz.exe", "mimikatz");
        observation.parent_inferred = true;
        let detection = rules
            .evaluate(&observation)
            .into_iter()
            .find(|detection| detection.rule_id == "procchain.credaccess.cmd_mimikatz")
            .expect("chain matched");
        assert_eq!(detection.confidence, "medium");
    }
}
