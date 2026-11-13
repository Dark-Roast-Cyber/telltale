//! Telltale integration through the supported embedding facade only
//! (`Pipeline::scan_sources_detailed`, `SourceScan`, `ActionRecordV1`).
//!
//! Telltale has no API for evaluating a single pending action, so the hook
//! writes a bounded window of native Claude Code JSONL (history plus the
//! pending call) and scans it as a `claude.projects` source, the pattern
//! docs/embedding.md prescribes for synthetic sources. Findings for the
//! pending call are the action findings anchored at its unique source time.

use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::{
    ActionRecordV1, ClientId, DetailedEvaluationOptions, EvaluationCompletion, ObservationStage,
    Pipeline, PipelineError, Source, SourceCoverage, SourceKind,
};

use crate::hooks::config::TelltaleSettings;
use crate::hooks::journal::Line;

/// Host-owned Rule v1 documents (name, content): detections of an agent
/// disabling its own hooks. Every document is loaded into the one pipeline
/// that serves every harness; an adapter with harness-specific host rules
/// adds its own `rules/*.yaml` file here.
pub const HOST_RULE_DOCUMENTS: &[(&str, &str)] = &[(
    "telltale-hooks-self-protection.yaml",
    include_str!("rules/telltale-hooks-self-protection.yaml"),
)];

#[derive(Debug)]
pub enum EngineError {
    Content(PathBuf, std::io::Error),
    Build(PipelineError),
    Provenance(PipelineError),
    Window(std::io::Error),
    Scan(PipelineError),
    NoResult,
}

impl EngineError {
    /// Closed, content-free code for telemetry.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Content(..) => "rule_content_unreadable",
            Self::Build(_) => "pipeline_build_failed",
            Self::Provenance(_) => "semantic_provenance_failed",
            Self::Window(_) => "window_write_failed",
            Self::Scan(_) => "scan_failed",
            Self::NoResult => "scan_returned_no_result",
        }
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Content(path, error) => write!(f, "cannot read {}: {error}", path.display()),
            Self::Build(error) | Self::Provenance(error) | Self::Scan(error) => {
                write!(f, "{}: {error}", self.code())
            }
            Self::Window(error) => write!(f, "{}: {error}", self.code()),
            Self::NoResult => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for EngineError {}

pub struct Engine {
    pipeline: Pipeline,
    options: DetailedEvaluationOptions,
    semantic_identity: String,
    pub build_ms: u64,
}

/// Which observation in the window the caller is asking about.
#[derive(Debug, Clone)]
pub struct Focus {
    /// Unique, strictly increasing source time written on the focus line.
    pub occurred_at: String,
    pub stage: ObservationStage,
    /// Native record `uuid` of the focus line, to detect its quarantine.
    pub native_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalStatus {
    Complete,
    /// Telltale evaluated but reported visibility limits; findings still count.
    VisibilityLimited,
    /// The focus observation was not evaluated (source failed or focus quarantined).
    NotEvaluated,
}

impl EvalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::VisibilityLimited => "visibility_limited",
            Self::NotEvaluated => "not_evaluated",
        }
    }
}

#[derive(Debug)]
pub struct Evaluation {
    pub status: EvalStatus,
    pub coverage: Option<&'static str>,
    pub visibility_limits: Vec<String>,
    /// Content-free Telltale failure or quarantine code.
    pub failure_code: Option<String>,
    /// Action records anchored at the focus observation, in Telltale order.
    pub focus_records: Vec<ActionRecordV1>,
    /// Action records anchored elsewhere in the window (already reported earlier).
    pub other_record_count: usize,
    /// Focus lines Telltale excluded (quarantined), out of `focus_count`.
    pub unevaluated_focus: usize,
    pub focus_count: usize,
    pub scan_ms: u64,
}

impl Evaluation {
    /// Highest promotion score among actions anchored at the focus.
    pub fn action_score(&self) -> u64 {
        self.focus_records
            .iter()
            .map(|record| record.promotion_score)
            .max()
            .unwrap_or(0)
    }

    pub fn rule_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .focus_records
            .iter()
            .flat_map(|record| record.rule_ids.iter().cloned())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    pub fn categories(&self) -> Vec<String> {
        let mut categories: Vec<String> = self
            .focus_records
            .iter()
            .flat_map(|record| record.categories.iter().cloned())
            .collect();
        categories.sort();
        categories.dedup();
        categories
    }
}

impl Engine {
    /// `protected_paths` are this installation's own state, telemetry, config
    /// and socket paths; with self-protection on, writes to them are detected
    /// even when they are outside the default locations the static rules know.
    pub fn new(
        settings: &TelltaleSettings,
        protected_paths: &[PathBuf],
    ) -> Result<Self, EngineError> {
        let started = Instant::now();
        let mut builder = Pipeline::builder();
        if !settings.community_rules {
            builder = builder.without_community_rules();
        }
        for path in &settings.rule_packages {
            builder = builder.rule_package(read(path)?);
        }
        if settings.self_protection_rules {
            for (_, document) in HOST_RULE_DOCUMENTS {
                builder = builder.rules_document((*document).to_owned());
            }
            if let Some(document) = protected_path_rules(protected_paths) {
                builder = builder.rules_document(document);
            }
        }
        for path in &settings.rules {
            builder = builder.rules_document(read(path)?);
        }
        if let Some(path) = &settings.policy {
            builder = builder.policy_document(read(path)?);
        }
        let pipeline = builder.build().map_err(EngineError::Build)?;
        let mut options = DetailedEvaluationOptions::default();
        options.process_chain = settings.process_chain;
        let semantic_identity = pipeline
            .semantic_provenance(&options)
            .map_err(EngineError::Provenance)?
            .identity()
            .to_owned();
        Ok(Self {
            pipeline,
            options,
            semantic_identity,
            build_ms: started.elapsed().as_millis() as u64,
        })
    }

    pub fn semantic_identity(&self) -> &str {
        &self.semantic_identity
    }

    /// Write `lines` to `window_path` and evaluate them as one Claude Code
    /// source. The caller holds the session lock, so the stable path keeps
    /// Telltale's source-bound identities stable across a session. The window
    /// holds raw tool input, so it is removed as soon as the scan returns.
    pub fn evaluate(
        &self,
        window_path: &Path,
        lines: &[Line],
        focus: &[Focus],
    ) -> Result<Evaluation, EngineError> {
        let text: String = lines.iter().map(Line::to_jsonl).collect();
        // A fresh regular file: a symlink or FIFO planted at the window path
        // must neither redirect the raw input nor stall the hook.
        crate::hooks::state::create_fresh(window_path)
            .and_then(|mut file| {
                use std::io::Write;
                file.write_all(text.as_bytes())
            })
            .map_err(EngineError::Window)?;
        let source = Source {
            client: ClientId::Claude,
            kind: SourceKind::Jsonl,
            source_id: "claude.projects".to_owned(),
            path: window_path.to_owned(),
        };
        let started = Instant::now();
        let scanned = self
            .pipeline
            .scan_sources_detailed(&[source], &self.options);
        let scan_ms = started.elapsed().as_millis() as u64;
        // Best effort: a leftover window is overwritten by the next scan anyway.
        let _ = std::fs::remove_file(window_path);
        let scan = scanned
            .map_err(EngineError::Scan)?
            .into_iter()
            .next()
            .ok_or(EngineError::NoResult)?;

        if let Some(failure) = scan.failure() {
            return Ok(Evaluation {
                status: EvalStatus::NotEvaluated,
                coverage: None,
                visibility_limits: Vec::new(),
                failure_code: Some(failure.code().to_owned()),
                focus_records: Vec::new(),
                other_record_count: 0,
                unevaluated_focus: focus.len(),
                focus_count: focus.len(),
                scan_ms,
            });
        }
        let coverage = scan.coverage().map(|coverage| match coverage {
            SourceCoverage::WholeSource => "whole_source",
            SourceCoverage::Partial => "partial",
        });
        let visibility_limits: Vec<String> = scan
            .visibility_limits()
            .iter()
            .map(|limit| limit.as_str().to_owned())
            .collect();
        let quarantined: Vec<&str> = focus
            .iter()
            .filter_map(|f| {
                scan.quarantined()
                    .iter()
                    .find(|unit| unit.native_id == f.native_id)
                    .map(|unit| unit.code)
            })
            .collect();
        let focus_quarantine = quarantined.first().map(|code| (*code).to_owned());

        let records = scan.action_records();
        let (focus_records, others): (Vec<_>, Vec<_>) = records.into_iter().partition(|record| {
            focus.iter().any(|f| {
                record.stage == f.stage
                    && record
                        .occurred_at
                        .as_deref()
                        .is_some_and(|at| same_instant(at, &f.occurred_at))
            })
        });
        let status = if quarantined.len() == focus.len() {
            EvalStatus::NotEvaluated
        } else if !quarantined.is_empty() {
            // Part of the focus was not evaluated; what was evaluated still counts.
            EvalStatus::VisibilityLimited
        } else {
            match scan.completion {
                Some(EvaluationCompletion::Complete) => EvalStatus::Complete,
                Some(EvaluationCompletion::VisibilityLimited) => EvalStatus::VisibilityLimited,
                None => EvalStatus::NotEvaluated,
            }
        };
        Ok(Evaluation {
            status,
            coverage,
            visibility_limits,
            failure_code: focus_quarantine,
            focus_records,
            other_record_count: others.len(),
            unevaluated_focus: quarantined.len(),
            focus_count: focus.len(),
            scan_ms,
        })
    }
}

/// Telltale rejects Rule v1 patterns longer than this (`MAX_PATTERN_BYTES`).
const MAX_PATTERN_BYTES: usize = 1000;

/// A Rule v1 document matching writes to, and modifying commands naming,
/// this installation's own paths (regex-escaped literals). Paths inside
/// another listed directory are dropped; rules that would exceed Telltale's
/// pattern cap are left out rather than failing the pipeline build.
fn protected_path_rules(paths: &[PathBuf]) -> Option<String> {
    let mut roots: Vec<&Path> = Vec::new();
    for path in paths {
        if path.as_os_str().len() > 1 && !roots.iter().any(|root| path.starts_with(root)) {
            roots.retain(|root| !root.starts_with(path));
            roots.push(path);
        }
    }
    // No value may break the document. `regex::escape` leaves control characters
    // in: the YAML reader refuses most of them, which takes the whole document and
    // the pipeline down, and folds line breaks, which leaves a rule that never
    // matches. What a single-quoted scalar cannot carry goes by its code point.
    let carried = |c: char| {
        matches!(c, ' '..='~' | '\u{a0}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
            && !matches!(c, '\u{2028}' | '\u{2029}' | '\u{feff}')
    };
    let literal = |path: &str| -> String {
        regex::escape(path)
            .chars()
            .map(|c| {
                if carried(c) {
                    c.to_string()
                } else {
                    format!(r"\x{{{:x}}}", c as u32)
                }
            })
            .collect()
    };
    let literals: Vec<String> = roots
        .iter()
        .filter_map(|path| path.to_str())
        .map(literal)
        .collect();
    if literals.is_empty() {
        return None;
    }
    let pattern = format!("(?:{})", literals.join("|"));
    // Same shape as rules/telltale-hooks-self-protection.yaml: a writing
    // program at command position (not `--rm`) in either order with the
    // path, or a file-writing redirection (not `2>`, `>&2`) whose target is
    // the path.
    let writer = r"(?:^|[\s;&|(`])(?:rm|mv|cp|dd|install|truncate|shred|unlink|chmod|chown|chattr|ln|tee|sed|perl|python3?|node|ruby|eval)\b";
    let redirect = r#"(?:^|[^0-9&>])>{1,2}\s*["']?[^\s;&|<>"']*?"#;
    let command = format!("(?s)(?:{writer}.*{pattern}|{pattern}.*{writer}|{redirect}{pattern})");
    // YAML single-quoted scalars escape a quote by doubling it.
    let quoted = |text: &str| format!("'{}'", text.replace('\'', "''"));
    let mut rules = String::new();
    if pattern.len() <= MAX_PATTERN_BYTES {
        rules.push_str(&format!(
            "  - id: tth.tamper.own_state_write\n    title: Agent writes Telltale Hooks state, telemetry or configuration\n    category: approval_bypass\n    severity: high\n    score: 90\n    targets: [written_path]\n    regex: {}\n    tags: [self-protection, hooks, defense-evasion]\n    explanation: A tool call writes a file under this installation's state, telemetry, configuration or socket path.\n",
            quoted(&pattern)
        ));
    }
    if command.len() <= MAX_PATTERN_BYTES {
        rules.push_str(&format!(
            "  - id: tth.tamper.own_state_command\n    title: Agent command modifies Telltale Hooks state, telemetry or configuration\n    category: approval_bypass\n    severity: high\n    score: 90\n    targets: [command]\n    regex: {}\n    tags: [self-protection, hooks, defense-evasion]\n    explanation: A command that can write or delete files names this installation's state, telemetry, configuration or socket path.\n",
            quoted(&command)
        ));
    }
    if rules.is_empty() {
        return None;
    }
    Some(format!(
        "version: 1\ndescription: Telltale Hooks self-protection for this installation's own paths.\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n{rules}modifiers: []\n"
    ))
}

/// Compare source times as instants, not strings: a Telltale pin that
/// normalized timestamps differently must not silently drop every finding.
fn same_instant(a: &str, b: &str) -> bool {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    match (
        OffsetDateTime::parse(a, &Rfc3339),
        OffsetDateTime::parse(b, &Rfc3339),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Rule, package and policy files are operator inputs: symlinks are followed
/// (dotfile managers, Nix), the target must be a regular file, and a FIFO is
/// refused rather than stalling the pipeline build. The configuration
/// validated these at load time; a failure here is a change since then and
/// gets the runtime's strict policy.
fn read(path: &Path) -> Result<String, EngineError> {
    crate::hooks::state::read_operator_input(path)
        .map_err(|error| EngineError::Content(path.to_owned(), error))
}

#[cfg(test)]
mod tests {
    use super::same_instant;

    #[test]
    fn protected_path_rules_dedupe_and_respect_the_pattern_cap() {
        use std::path::PathBuf;
        let doc = super::protected_path_rules(&[
            PathBuf::from("/srv/tth/state"),
            PathBuf::from("/srv/tth/state/telemetry.jsonl"),
            PathBuf::from("/var/log/tth/telemetry.jsonl"),
            PathBuf::from("/etc/tth/config.toml"),
        ])
        .unwrap();
        assert!(
            doc.contains("/srv/tth/state|/var/log/tth/telemetry\\.jsonl|/etc/tth/config\\.toml"),
            "{doc}"
        );
        // The nested telemetry file is covered by its state dir; the other is kept.
        // Once in the write rule, three times in the command rule (either
        // order plus the redirection form).
        assert_eq!(doc.matches("telemetry\\.jsonl").count(), 4, "{doc}");
        assert!(doc.contains("/var/log/tth/telemetry\\.jsonl"));
        assert!(!doc.contains("/srv/tth/state/telemetry"));
        let long = PathBuf::from(format!("/{}", "x".repeat(600)));
        let doc = super::protected_path_rules(&[long]).unwrap();
        assert!(doc.contains("own_state_write") && !doc.contains("own_state_command"));
        assert!(
            super::protected_path_rules(&[PathBuf::from(format!("/{}", "y".repeat(1200)))])
                .is_none()
        );
    }

    /// A character YAML refuses or folds reaches the regex by its code point, and
    /// the pattern still matches the path. YAML carries the rest as it is, so a
    /// non-ASCII home directory keeps its room under the pattern cap.
    #[test]
    fn a_path_character_yaml_cannot_carry_is_written_by_its_code_point() {
        for (c, written) in [
            ('\x01', r"\x{1}"),
            ('\x1b', r"\x{1b}"),
            ('\x7f', r"\x{7f}"),
            ('\u{9f}', r"\x{9f}"),
            ('\u{fffe}', r"\x{fffe}"),
            ('\t', r"\x{9}"),
            ('\n', r"\x{a}"),
            ('\r', r"\x{d}"),
            ('\u{85}', r"\x{85}"),
            ('\u{2028}', r"\x{2028}"),
            ('\u{2029}', r"\x{2029}"),
            ('\u{feff}', r"\x{feff}"),
        ] {
            let path = format!("/srv/a{c}b");
            let doc = super::protected_path_rules(&[std::path::PathBuf::from(&path)]).unwrap();
            let pattern = doc
                .lines()
                .find_map(|line| line.strip_prefix("    regex: '"))
                .and_then(|line| line.strip_suffix('\''))
                .unwrap();
            assert!(
                pattern.contains(&format!("/srv/a{written}b")),
                "{c:?}: {doc}"
            );
            assert!(!pattern.contains(c), "{c:?}: {doc}");
            assert!(regex::Regex::new(pattern).unwrap().is_match(&path), "{c:?}");
        }
        let doc =
            super::protected_path_rules(&[std::path::PathBuf::from("/home/synthetic/josé/日本語")]);
        assert!(doc.unwrap().contains("/home/synthetic/josé/日本語"));
    }

    /// A rules file that is not listed would silently never load.
    #[test]
    fn every_bundled_rules_file_is_a_host_rule_document() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/hooks/rules");
        let mut files: Vec<(String, String)> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
            .map(|path| {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                (name, std::fs::read_to_string(&path).unwrap())
            })
            .collect();
        files.sort();
        let mut listed: Vec<(String, String)> = super::HOST_RULE_DOCUMENTS
            .iter()
            .map(|(name, content)| ((*name).to_owned(), (*content).to_owned()))
            .collect();
        listed.sort();
        assert_eq!(listed, files);
    }

    #[test]
    fn source_times_compare_as_instants() {
        assert!(same_instant(
            "2026-11-04T00:01:01.000Z",
            "2026-11-04T00:01:01Z"
        ));
        assert!(same_instant(
            "2026-11-04T00:01:01.000Z",
            "2026-11-04T01:01:01.000+01:00"
        ));
        assert!(!same_instant(
            "2026-11-04T00:01:01.001Z",
            "2026-11-04T00:01:01.000Z"
        ));
        assert!(same_instant("not a time", "not a time"));
    }
}
