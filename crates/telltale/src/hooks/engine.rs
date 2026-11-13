//! Telltale integration through the supported embedding facade only
//! (`Pipeline::scan_sources_detailed`, `SourceScan`, `ActionRecordV1`).
//!
//! Telltale has no API for evaluating a single pending action, so the hook
//! writes a bounded window of native Claude Code JSONL (history plus the
//! pending call) and scans it as a `claude.projects` source, the pattern
//! docs/embedding.md prescribes for synthetic sources. Findings for the
//! pending call are the action findings anchored at its unique source time.

use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{
    AcquisitionError, ActionRecordV1, ClientId, DetailedEvaluationOptions, EvaluationCompletion,
    ObservationStage, Pipeline, PipelineError, Source, SourceCoverage, SourceKind,
};

use crate::hooks::config::TelltaleSettings;
use crate::hooks::journal::Line;

/// Host-owned Rule v1 documents (name, content): detections of an agent
/// disabling its own hooks. Every document is loaded into the one pipeline
/// that serves every harness; an adapter with harness-specific host rules
/// adds its own `rules/*.yaml` file here.
pub const HOST_RULE_DOCUMENTS: &[(&str, &str)] = &[
    (
        "telltale-hooks-self-protection.yaml",
        include_str!("rules/telltale-hooks-self-protection.yaml"),
    ),
    (
        "copilot-cli-self-protection.yaml",
        include_str!("rules/copilot-cli-self-protection.yaml"),
    ),
    (
        "codex-cli-self-protection.yaml",
        include_str!("rules/codex-cli-self-protection.yaml"),
    ),
];

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
    generated: GeneratedCoverage,
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
    /// Focus lines Telltale excluded (quarantined), out of `focus_count`. All
    /// of them when the focus could only be evaluated piece by piece: nothing
    /// that needs two pieces together could match.
    pub unevaluated_focus: usize,
    pub focus_count: usize,
    pub scan_ms: u64,
    /// Telltale failed the source as a whole: there is no result for any line.
    pub source_failed: bool,
    /// The source failed on capacity used up across lines, with no one line at
    /// fault: a smaller window can pass, but no search can find a culprit.
    pub capacity_failed: bool,
    /// History lines this evaluation scanned, out of those it was given.
    pub history_kept: usize,
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
    /// Custom harness homes and this binary's own path get generated rules too.
    pub fn new(
        settings: &TelltaleSettings,
        protected_paths: &[PathBuf],
    ) -> Result<Self, EngineError> {
        let started = Instant::now();
        let mut builder = Pipeline::builder();
        if !settings.community_rules {
            builder = builder.without_community_rules();
        }
        let mut generated = GeneratedCoverage::default();
        for path in &settings.rule_packages {
            builder = builder.rule_package(read(path)?);
        }
        if settings.self_protection_rules {
            for (_, document) in HOST_RULE_DOCUMENTS {
                builder = builder.rules_document((*document).to_owned());
            }
            for document in generated_documents(protected_paths, &mut generated) {
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
            generated,
            build_ms: started.elapsed().as_millis() as u64,
        })
    }

    pub fn semantic_identity(&self) -> &str {
        &self.semantic_identity
    }

    /// Evaluate `pending` with as much of `history` as Telltale accepts.
    ///
    /// Telltale fails a source as a whole, and the failure can come from what
    /// the model wrote: a line it refuses, or capacity used up across lines
    /// (contribution keys, projection items, evaluation budget). The window
    /// can be reduced, because every line in it is evaluated again for each
    /// call: if `history` and `pending` fail together, `pending` is scanned on
    /// its own, which secures its rule verdict, and then history goes back in
    /// [`restoration_order`], splitting any block the scan refuses. That finds
    /// lines that fail on their own wherever they sit (dropping only the
    /// oldest lines would lose every stage of a chain before the poison). It
    /// needs no knowledge of why Telltale failed, so it also covers sessions
    /// poisoned by older versions and failures added upstream. The cost is
    /// bounded by [`MAX_RECOVERY_SCANS`], [`MAX_CAPACITY_REFUSALS`] and
    /// [`RECOVERY_BUDGET`]; past them the remaining lines stay out. Loss is
    /// reported as the `history_lost` visibility limit.
    ///
    /// `budget` belongs to the call, so that a call evaluated twice (once
    /// whole, once projected) spends one budget. It decides how much context a
    /// call keeps, not whether the call itself is evaluated: the scan of
    /// `pending` alone does not ask it, and nor do the scans of its lines when
    /// that is past capacity, because nothing else secures the verdict. Those
    /// stop at [`PIECE_SCAN_LIMIT`] instead.
    pub fn evaluate(
        &self,
        window_path: &Path,
        history: &[Line],
        pending: &[Line],
        focus: &[Focus],
        budget: &mut RecoveryBudget,
    ) -> Result<Evaluation, EngineError> {
        let sizes: Vec<usize> = history.iter().map(|line| line.to_jsonl().len()).collect();
        let pending_bytes = pending.iter().map(|line| line.to_jsonl().len()).sum();
        let whole_bytes = pending_bytes + sizes.iter().sum::<usize>();
        let mut failure_code = None;
        if budget.admits(whole_bytes) {
            let whole = self.scan(window_path, history.iter().chain(pending), focus)?;
            budget.observe(whole_bytes, whole.scan_ms);
            if !whole.source_failed {
                return Ok(Evaluation {
                    history_kept: history.len(),
                    ..whole
                });
            }
            failure_code = whole.failure_code;
        }
        let mut best = self.scan(window_path, pending.iter(), focus)?;
        budget.observe(pending_bytes, best.scan_ms);
        let mut kept = vec![false; history.len()];
        if best.source_failed && pending.len() > 1 {
            best = self.scan_each(window_path, pending, focus, || budget.pieces_in_time())?;
        } else if best.status != EvalStatus::NotEvaluated {
            let window = Window {
                path: window_path,
                history,
                sizes: &sizes,
                pending,
                pending_bytes,
                focus,
            };
            best = self.restore_history(&window, budget, best, &mut kept)?;
        }
        best.scan_ms = budget.elapsed_ms();
        best.failure_code = best.failure_code.or(failure_code);
        best.history_kept = kept.iter().filter(|kept| **kept).count();
        // Not evaluated: the caller projects the input or applies its policy.
        if best.status != EvalStatus::NotEvaluated && best.history_kept < history.len() {
            best.status = EvalStatus::VisibilityLimited;
            best.coverage = Some("partial");
            best.visibility_limits.push("history_lost".to_owned());
        }
        Ok(best)
    }

    /// Put history back around a scan of `pending` alone, in
    /// [`restoration_order`], splitting any block Telltale refuses. Returns the
    /// widest scan that passed; `kept` says which lines it held, and they are
    /// always scanned in their original order.
    fn restore_history(
        &self,
        window: &Window<'_>,
        budget: &mut RecoveryBudget,
        mut best: Evaluation,
        kept: &mut [bool],
    ) -> Result<Evaluation, EngineError> {
        let order = restoration_order(window.sizes);
        let mut kept_bytes = window.pending_bytes;
        let mut blocks = Vec::new();
        push_halves(&mut blocks, 0..order.len());
        let mut scans = 0;
        let mut refusals_after_a_pass = 0;
        let mut passed = false;
        while let Some(block) = blocks.pop() {
            if scans == MAX_RECOVERY_SCANS
                || refusals_after_a_pass == MAX_CAPACITY_REFUSALS
                || budget.spent()
            {
                break;
            }
            let lines_in_block = &order[block.clone()];
            let bytes = kept_bytes
                + lines_in_block
                    .iter()
                    .map(|&n| window.sizes[n])
                    .sum::<usize>();
            // A scan that may not fit in what is left does not start: a smaller
            // block may fit, and otherwise the lines stay out.
            if !budget.admits(bytes) {
                push_halves(&mut blocks, block);
                continue;
            }
            scans += 1;
            for &n in lines_in_block {
                kept[n] = true;
            }
            let lines = window
                .history
                .iter()
                .zip(kept.iter())
                .filter_map(|(line, kept)| kept.then_some(line));
            let scan = self.scan(window.path, lines.chain(window.pending), window.focus)?;
            budget.observe(bytes, scan.scan_ms);
            if scan.source_failed {
                for &n in lines_in_block {
                    kept[n] = false;
                }
                refusals_after_a_pass += usize::from(scan.capacity_failed && passed);
                push_halves(&mut blocks, block);
            } else {
                kept_bytes = bytes;
                passed = true;
                best = scan;
            }
        }
        Ok(best)
    }

    /// Evaluate each line of a pending call that is past capacity as a whole,
    /// on its own, and merge what the pieces found. Findings keep their force;
    /// every focus line counts as unevaluated, because nothing spanning two
    /// pieces could match. [`RECOVERY_BUDGET`] does not stop this loop: under load
    /// it would decide whether the piece carrying a deny is seen, at a load a call
    /// can bring itself. More than one pending line only comes from a projection,
    /// so [`crate::hooks::projection::MAX_VARIANTS`] bounds the scans, and `in_time`
    /// ([`PIECE_SCAN_LIMIT`]) bounds their time. Lines past it stay unscanned, and
    /// the record says so.
    fn scan_each(
        &self,
        window_path: &Path,
        pending: &[Line],
        focus: &[Focus],
        mut in_time: impl FnMut() -> bool,
    ) -> Result<Evaluation, EngineError> {
        let mut merged = Evaluation {
            status: EvalStatus::NotEvaluated,
            coverage: None,
            visibility_limits: Vec::new(),
            failure_code: None,
            focus_records: Vec::new(),
            other_record_count: 0,
            unevaluated_focus: focus.len(),
            focus_count: focus.len(),
            scan_ms: 0,
            source_failed: false,
            capacity_failed: false,
            history_kept: 0,
        };
        for (line, one) in pending.iter().zip(focus) {
            if !in_time() {
                merged
                    .visibility_limits
                    .push("pending_pieces_unscanned".to_owned());
                break;
            }
            let scan = self.scan(
                window_path,
                std::iter::once(line),
                std::slice::from_ref(one),
            )?;
            if scan.status == EvalStatus::NotEvaluated {
                continue;
            }
            merged.status = EvalStatus::VisibilityLimited;
            merged.coverage = Some("partial");
            merged.focus_records.extend(scan.focus_records);
            for limit in scan.visibility_limits {
                if !merged.visibility_limits.contains(&limit) {
                    merged.visibility_limits.push(limit);
                }
            }
        }
        Ok(merged)
    }

    /// What the generated self-protection rules cover (`telltale hooks check`).
    pub fn generated_coverage(&self) -> &GeneratedCoverage {
        &self.generated
    }

    /// Write `lines` to `window_path` and evaluate them as one Claude Code
    /// source. The caller holds the session lock, so the stable path keeps
    /// Telltale's source-bound identities stable across a session. The window
    /// holds raw tool input, so it is removed as soon as the scan returns.
    fn scan<'a>(
        &self,
        window_path: &Path,
        lines: impl Iterator<Item = &'a Line>,
        focus: &[Focus],
    ) -> Result<Evaluation, EngineError> {
        let text: String = lines.map(Line::to_jsonl).collect();
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
                source_failed: true,
                // No acquisition error: projection or evaluation ran out.
                capacity_failed: matches!(
                    failure.acquisition_error(),
                    None | Some(AcquisitionError::ContributionCapacity)
                ),
                history_kept: 0,
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
            source_failed: false,
            capacity_failed: false,
            history_kept: 0,
        })
    }
}

/// Scans one evaluation may spend putting history back after its source failed.
/// One poison line anywhere in a full window of 256 takes at most 16 (two per
/// halving), so two always fit. Small windows scan in milliseconds, so this is
/// what normally decides.
const MAX_RECOVERY_SCANS: usize = 32;
/// Capacity refusals, after some history has gone back, that end the search.
/// Capacity is used up across lines, so no search finds a culprit: every further
/// refusal only trims what is restored, and costs a full window's scan. Refusals
/// of a line for what it holds do not count; those keep looking for the line.
const MAX_CAPACITY_REFUSALS: usize = 2;
/// Time a call may spend evaluating before no further scan starts, except the
/// scans of the pending call itself ([`Engine::evaluate`]). Every other scan is
/// admitted on a forecast ([`RecoveryBudget::admits`]) and a scan in flight cannot
/// be stopped, so the real worst case is above this. `DEADLINE_MARGIN` in the
/// evaluator is there for that, and load can still go past it.
pub const RECOVERY_BUDGET: Duration = Duration::from_secs(2);
/// Time after the start of an evaluation ([`RecoveryBudget::start`]) at which no
/// further piece of a call past capacity is scanned. It sits below `DEADLINE_MARGIN`
/// in the evaluator by the reply and the wait for the lock, and about 250 ms for the
/// piece in flight, which load can overrun. The scans ahead of the loop are not
/// limited by it. Load decides how far a call gets: what the pieces scanned found
/// keeps its force, and the rest goes to `on_unevaluable`.
pub const PIECE_SCAN_LIMIT: Duration = Duration::from_secs(5);
/// Scans smaller than this do not set the forecast's rate: their cost is mostly
/// a scan's fixed setup, which would make a larger scan look far too expensive.
const MIN_MEASURED_BYTES: usize = 64 * 1024;
/// Lines a call restores first whatever their size. Every bundled chain but one
/// links within 3 calls, so a line out of this reach matters only to a chain that
/// links by time.
const RESTORE_NEWEST: usize = 8;
/// Older lines shorter than this go back next, smallest first: they cost little
/// capacity, so a flood of long lines cannot push them out. A longer line is
/// more likely to be the flood, and goes back by age.
const SMALL_LINE_BYTES: usize = 1024;

/// One call's allowance for scanning, shared by every evaluation it needs.
pub struct RecoveryBudget {
    started: Instant,
    /// The slowest rate measured so far, in milliseconds per byte.
    ms_per_byte: f64,
}

impl RecoveryBudget {
    /// The call starts now: call this once the session lock is held, because
    /// the wait for the lock is bounded on its own.
    pub fn start() -> Self {
        Self {
            started: Instant::now(),
            ms_per_byte: 0.0,
        }
    }

    fn spent(&self) -> bool {
        self.started.elapsed() >= RECOVERY_BUDGET
    }

    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Whether another piece of a call past capacity may still be scanned.
    fn pieces_in_time(&self) -> bool {
        self.started.elapsed() < PIECE_SCAN_LIMIT
    }

    /// Whether a scan of `bytes` should fit in what is left. Twice the forecast,
    /// because lines that match rules cost more than the lines measured so far
    /// and a scan that fails at acquisition ends before the expensive stages.
    fn admits(&self, bytes: usize) -> bool {
        let forecast = Duration::from_secs_f64(self.ms_per_byte * bytes as f64 / 1000.0);
        self.started.elapsed() + forecast * 2 < RECOVERY_BUDGET
    }

    fn observe(&mut self, bytes: usize, ms: u64) {
        if bytes >= MIN_MEASURED_BYTES {
            self.ms_per_byte = self.ms_per_byte.max(ms as f64 / bytes as f64);
        }
    }
}

/// What a recovery scan is made of.
struct Window<'a> {
    path: &'a Path,
    history: &'a [Line],
    sizes: &'a [usize],
    pending: &'a [Line],
    pending_bytes: usize,
    focus: &'a [Focus],
}

/// History positions from the last to go back to the first (the end of the list
/// is tried first): the newest [`RESTORE_NEWEST`] lines, then older lines under
/// [`SMALL_LINE_BYTES`] smallest first, then the rest newest first. The sort is
/// stable, so lines of a size stay in age order. Chosen by comparing orders; see
/// the ADR 0002 addendum.
fn restoration_order(sizes: &[usize]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..sizes.len()).collect();
    let older = sizes.len().saturating_sub(RESTORE_NEWEST);
    order[..older].sort_by_key(|&n| std::cmp::Reverse(sizes[n].min(SMALL_LINE_BYTES)));
    order
}

/// Split a block Telltale refused. The newer half goes on top of the stack,
/// so it is tried first; a single line that fails is dropped.
fn push_halves(blocks: &mut Vec<Range<usize>>, block: Range<usize>) {
    if block.len() > 1 {
        let middle = block.start + block.len() / 2;
        blocks.push(block.start..middle);
        blocks.push(middle..block.end);
    }
}

/// Telltale rejects Rule v1 patterns longer than 1,024 bytes; stay under it.
const MAX_PATTERN_BYTES: usize = 1000;

// The same text as rules/*.yaml (tested): a writing program at command
// position, not `--rm` or a word after other whitespace, in the same command as
// the path unless it is an interpreter one-liner, whose program can hold `;`, and
// a file-writing redirection, not `2>` or `>&2`. An interpreter counts only with a
// flag other than `-m`: `python3 x.py <path>` hands its path to a file whose
// content no rule can see anyway. `HARMLESS` is what cannot write, whatever it names.
const COMMAND_START: &str = r#"(?:^|[;&|({`\n]|\s-(?:exec|ok)(?:dir)?\s)\s*(?:\\?(?:\S*[\\/])?(?:sudo|doas|env|command|builtin|exec|nohup|time|nice|timeout|xargs|busybox|eval|iex|if|then|do|else|!|[^\s=]+=\S*|-\S+(?:\s+\S+)?|/[A-Za-z]|[0-9]\S*|(?:ba|z|da|k)?sh|cmd(?:\.exe)?|(?:powershell|pwsh)(?:\.exe)?)\s+["']?)*\\?(?:\S*[\\/])?"#;
const WRITERS: &str = r#"(?:(?:(?:rm|mv|cp|dd|install|truncate|shred|unlink|chmod|chown|chattr|ln|tee|eval)\s|sed\s+(?:[^;&|]*\s)?-(?:[a-z]*i|-in-place))|(?:del|erase|copy|move|ren|rename|rd|rmdir|(?:Remove|Move|Copy|Rename|New)-Item|(?:Set|Add|Clear)-Content|Out-File|ri|mi|cpi|sc|ac)\s)"#;
const INTERPRETERS: &str = r#"(?:python[0-9.]*\s+-[^mvVh\s-]|(?:perl|node|ruby|php)\s+-[^vVh\s-])"#;
const SEGMENT: &str = r#"(?:[^;&|\n]|\\\n|'[^']*'|"[^"]*")*"#;
const REDIRECT_TO: &str = r#"(?:^|[^0-9&>])>{1,2}\|?\s*["']?"#;
const REDIRECT_SKIP: &str = r#"[^\s;&|<>"']*?"#;
const HARMLESS: &str = r#"^\s*(?:(?:[-A-Za-z0-9_][-.A-Za-z0-9_]* *)+[;&]+\s*)*(?:(?:git +add|test|\[) +[ !*-:=?-\[\]-_a-{}~]*[;&]+\s*)*(?:(?:git +commit|gh +(?:pr|issue))(?: +(?:"(?:(?:\\?[^-"\\;&|<>`$()\n\r]|\\["\\])-*)*"|[!*-:=?-\[\]-_a-{}~]*))*|(?:(?:cd|(?:python3?|node) +[A-Z_a-z0-9./~][!*-:=?-\[\]-_a-{}~]*)(?: +(?:"(?:(?:\\?[^-"`$\\“-„]|\$[A-Z_a-z])-*)*"|(?:[!*-:=?-\[\]-_a-{}~]|\$[A-Z_a-z])*))*(?:[;&|]+\s*|$))*(?:(?:(?:cat|head|tail|grep|jq|cut|wc|ls|stat|file|diff|sha256sum|type|echo|printf|test|tr|Get-Content|gc|git +(?:add|commit)|gh +(?:pr|issue))(?: +(?:(?:--[a-z-]+=)?(?:'(?:[^-'‘-‛]-*)*'|"(?:(?:\\?[^-"`$\\“-„]|\\\\|\$\{[A-Z_]+\}|\$[A-Z_a-z])-*)*")|(?:[!%*-,.-:=?-\[\]-_a-{}~]|-+[!*-,.-:=?-\[\]-_a-{}~]|\$[A-Z_a-z])*-*))*|git +(?:diff|log|show|blame|status|grep|ls-files|ls-tree)(?: +(?:'(?:[^-'‘-‛]-*)*'|[!*-:=?-\[\]-_a-z~]*))*|sed +-n +(?:'[^'weW‘-‛]*p'|[0-9,]+p)[^-;&|<>`$()'"\n\r\\]*|(?:sort|uniq)(?: +-[a-np-z]+)* *|python3? +-m +json\.tool *)(?:2>/dev/null *)?(?:[|\n]\s*|(?: +#[^\n\r]*)?$))*)$"#;

// The same text as the fail-safe rules in rules/*.yaml (tested): a writer word
// anywhere, matched without a list of what can wrap it, and the words that work on what
// they are handed when the path comes first.
const WRITER_ANYWHERE: &str = r#"(?:(?:^|[^-A-Za-z0-9_.])(?:rm|rmdir|mv|cp|dd|ln|tee|tar|rsync|touch|truncate|unlink|shred|trash|gio|install|ch(?:mod|own|attr)|xargs|eval|checkout|reset|restore|clean|del|erase|copy|move|ren(?:ame)?|rd|ri|mi|cpi|sc|ac|(?:Remove|Move|Copy|Rename|New)-Item|(?:Set|Add|Clear)-Content|Out-File|rmtree|rmSync|rm_rf|rimraf|remove_dir_all|removeSync)\b|(?:^|[^-2&=])>(?:[^&]|$)|\bsed\b[^;&|\n]*-(?:[a-z]*i|-in)|\B-delete\b|(?:python\S*|perl|node|ruby|php)\s+-[^mvVh\s-])"#;
const WRITER_AFTER: &str = r#"(?:(?:^|[^-A-Za-z0-9_.])(?:rm|rmdir|rimraf|mv|cp|ln|dd|tee|truncate|unlink|shred|trash|ch(?:mod|own)|xargs|del|move|ri|mi|Remove-Item|Move-Item)\b|(?:^|[^-2&=])>(?:[^&]|$)|\B-delete\b|\bsed\b[^;&|\n]*-(?:[a-z]*i|-in)|(?:python\S*|perl|node|ruby|php)\s+-[^mvVh\s-])"#;

/// What can stand before a path whose rule must not match the tail of a longer
/// one: `build/tmp` is not the home `/tmp`.
const BEFORE_PATH: &str = r"[^A-Za-z0-9_.\-\\/~]";

/// Bytes left for path fragments in the largest generated rule.
const FRAGMENT_BUDGET: usize = MAX_PATTERN_BYTES
    - COMMAND_START.len()
    - WRITERS.len()
    - INTERPRETERS.len()
    - SEGMENT.len()
    - 2 * BEFORE_PATH.len()
    - 32;

// A fail-safe rule holds a writer word list and one chunk of paths.
const _: () = assert!(
    WRITER_ANYWHERE.len() + 2 * BEFORE_PATH.len() + 32 + FRAGMENT_BUDGET <= MAX_PATTERN_BYTES
);
const _: () =
    assert!(WRITER_AFTER.len() + 2 * BEFORE_PATH.len() + 32 + FRAGMENT_BUDGET <= MAX_PATTERN_BYTES);

/// The ways a shell spells the user's home, beside its literal path.
const HOME_SPELLINGS: &str = r#"~|"?\$\{?HOME\}?"?|%USERPROFILE%|\$env:USERPROFILE"#;

/// The end of a directory name in command text or a written path.
const NAME_END: &str = r#"(?:[\\/\s"'`;&|)]|$)"#;

/// What the generated self-protection rules cover. No path is dropped for
/// size: past the cap the literals spread over more rules, and a single path
/// too long for any rule is matched by its last bytes, which every command
/// naming the whole path contains. Only a path that is not UTF-8 has no rule:
/// tool input is JSON text, so it cannot name that path exactly either.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeneratedCoverage {
    /// Protected paths, custom harness homes and the binary.
    pub paths: usize,
    pub rules: usize,
    /// Paths matched by their last bytes only.
    pub reduced: Vec<String>,
    /// Paths with no generated rule because they are not UTF-8.
    pub unrepresentable: Vec<String>,
}

/// One generated document's literal paths and rule names.
struct Family {
    /// Rule IDs are `tth.tamper.<prefix>_{write,command,command_reverse,redirect,reference}`,
    /// with `_2`, `_3`, ... on the rules past the first chunk of paths.
    prefix: &'static str,
    subject: &'static str,
    fragments: Vec<String>,
    /// A path followed by a writer counts. Not for a directory whose name alone
    /// says nothing about what a later command does, nor for a program someone
    /// may run.
    reversible: bool,
    /// Any other mention asks, which also catches what the writer rules cannot
    /// recognize: `strace rm`, `cd home && rm x`, `find home -delete`. Not for the
    /// binary: running it is what it is for.
    reference: bool,
    /// The path must not be the tail of a longer one.
    anchored: bool,
    /// What `reference` does not ask for: with a writer word anywhere in the command,
    /// these ask, however it is wrapped. Empty where any mention already asks.
    failsafe: Vec<String>,
}

/// One path as regex text: every character outside printable ASCII by its code
/// point (YAML refuses some of them in a document and folds others, and one refused
/// character would take the whole pipeline down), either separator (a Windows path
/// is also spelled with `/`, and `//` is the same path), and a space optionally
/// escaped. One entry per character, so that a long path can keep its tail.
fn path_pieces(text: &str) -> Vec<String> {
    let mut pieces = Vec::new();
    let mut previous_separator = false;
    for c in text.chars() {
        let separator = matches!(c, '/' | '\\');
        if separator && previous_separator {
            continue;
        }
        previous_separator = separator;
        pieces.push(match c {
            '/' | '\\' => r"[\\/]+".to_owned(),
            ' ' => r"\\?\s".to_owned(),
            '!'..='~' => regex::escape(c.encode_utf8(&mut [0; 4])),
            _ => format!(r"\x{{{:x}}}", c as u32),
        });
    }
    pieces
}

/// One path as regexes followed by `suffix`: its literal text, or its last bytes
/// if that does not fit one rule, and its spelling from the user's home. Nothing for
/// a path with nothing in it to match: that would match everything.
fn path_fragments(path: &Path, suffix: &str, coverage: &mut GeneratedCoverage) -> Vec<String> {
    let Some(text) = path.to_str() else {
        let path = path.display().to_string();
        if !coverage.unrepresentable.contains(&path) {
            coverage.unrepresentable.push(path);
        }
        return Vec::new();
    };
    let is_separator = |c: char| matches!(c, '/' | '\\');
    let text = text.trim_end_matches(is_separator);
    if text.is_empty() {
        return Vec::new();
    }
    let limit = FRAGMENT_BUDGET - suffix.len();
    let pieces = path_pieces(text);
    let mut used = 0;
    let mut kept: Vec<&str> = pieces
        .iter()
        .rev()
        .map(String::as_str)
        .take_while(|piece| {
            used += piece.len();
            used <= limit
        })
        .collect();
    if kept.len() < pieces.len() && !coverage.reduced.iter().any(|known| known == text) {
        coverage.reduced.push(text.to_owned());
    }
    kept.reverse();
    let mut fragments = vec![kept.concat() + suffix];
    let home = crate::hooks::config::user_home();
    let spelled = home
        .as_deref()
        .and_then(Path::to_str)
        .and_then(|home| text.strip_prefix(home.trim_end_matches(is_separator)))
        .filter(|rest| rest.is_empty() || rest.starts_with(is_separator))
        .map(|rest| format!("(?:{HOME_SPELLINGS}){}{suffix}", path_pieces(rest).concat()))
        .filter(|fragment| fragment.len() <= FRAGMENT_BUDGET);
    fragments.extend(spelled);
    fragments
}

/// Paths inside another listed directory are dropped; the directory covers them.
fn own_state_family(paths: &[PathBuf], coverage: &mut GeneratedCoverage) -> Family {
    let mut roots: Vec<&Path> = Vec::new();
    for path in paths {
        if crate::hooks::config::names_below_root(path)
            && !roots.iter().any(|root| path.starts_with(root))
        {
            roots.retain(|root| !root.starts_with(path));
            roots.push(path);
        }
    }
    coverage.paths += roots.len();
    Family {
        prefix: "own_state",
        subject: "this installation's state, telemetry, configuration, socket or rule files",
        fragments: roots
            .iter()
            .flat_map(|path| path_fragments(path, "", coverage))
            .collect(),
        reversible: true,
        reference: true,
        // The operating system can spell these with a prefix: macOS `/private`.
        anchored: false,
        failsafe: Vec::new(),
    }
}

/// A custom home's hook files (the same names as the static rules, which can
/// only know the variable and the default directory), then the home itself.
fn harness_home_families(
    homes: &[crate::hooks::config::HarnessHome],
    coverage: &mut GeneratedCoverage,
) -> [Family; 2] {
    coverage.paths += homes.len();
    let name_end = NAME_END;
    let files = |home: &crate::hooks::config::HarnessHome| match home.variable {
        "CODEX_HOME" => format!(
            r#"[\\/]+(?:hooks\.json|(?:[^\\/\s;&|"']+\.)?config\.toml|rules{name_end}|(?:[^\s;&|"']*[\\/])?hooks\.json)"#
        ),
        _ => format!(
            r#"[\\/]+(?:(?:hooks|agents){name_end}|settings(?:\.local)?\.json|(?:[^\s;&|"']*[\\/])?hooks\.json)"#
        ),
    };
    let fragments = |suffix: &dyn Fn(&crate::hooks::config::HarnessHome) -> String,
                     coverage: &mut GeneratedCoverage| {
        homes
            .iter()
            .flat_map(|home| path_fragments(&home.path, &suffix(home), coverage))
            .collect()
    };
    let whole = |_: &crate::hooks::config::HarnessHome| {
        r#"(?:[\\/]+\.\.)*[\\/]*(?:\s|$|["'`;&|)])"#.to_owned()
    };
    // Only the whole path can be told from a longer one.
    let reduced_before = coverage.reduced.len();
    let (files, dirs) = (fragments(&files, coverage), fragments(&whole, coverage));
    let anchored = coverage.reduced.len() == reduced_before;
    // Below the home through a glob or `..`: the mention above is the home itself.
    let below =
        |_: &crate::hooks::config::HarnessHome| r#"[\\/]+[^\s;&|]*(?:[*?\[{]|\.\.)"#.to_owned();
    let below = fragments(&below, coverage);
    [
        Family {
            prefix: "harness_home",
            subject: "a hook file in this session's custom harness home",
            fragments: files,
            reversible: true,
            reference: true,
            anchored,
            failsafe: Vec::new(),
        },
        Family {
            prefix: "harness_home_dir",
            subject: "this session's custom harness home",
            fragments: dirs,
            reversible: false,
            reference: true,
            anchored,
            failsafe: below,
        },
    ]
}

/// The running binary: replacing it keeps a harness's trust in the hook.
fn installed_binary_family(binary: Option<&Path>, coverage: &mut GeneratedCoverage) -> Family {
    coverage.paths += usize::from(binary.is_some());
    let fragments: Vec<String> = binary
        .into_iter()
        .flat_map(|path| path_fragments(path, NAME_END, coverage))
        .collect();
    Family {
        prefix: "installed_binary_path",
        subject: "the telltale binary that is running",
        failsafe: fragments.clone(),
        fragments,
        reversible: false,
        reference: false,
        anchored: false,
    }
}

/// Greedy, in order, so a path keeps its rule while the list before it is unchanged.
fn chunk_fragments(fragments: &[String]) -> Vec<Vec<&str>> {
    let mut chunks: Vec<Vec<&str>> = Vec::new();
    let mut used = 0;
    for fragment in fragments {
        match chunks.last_mut() {
            Some(chunk) if used + 1 + fragment.len() <= FRAGMENT_BUDGET => {
                used += 1 + fragment.len();
                chunk.push(fragment);
            }
            _ => {
                used = fragment.len();
                chunks.push(vec![fragment]);
            }
        }
    }
    chunks
}

/// What a generated rule matches: a written path, or a command unless it is
/// one of the harmless ones.
enum Selection {
    Written(String),
    Command(String),
}

/// A Rule v1 document matching writes to, and modifying commands naming, one
/// family's paths. Windows paths compare case-insensitively.
fn family_document(family: &Family, coverage: &mut GeneratedCoverage) -> Option<String> {
    let Family {
        prefix, subject, ..
    } = family;
    let mut rules = String::new();
    let mut push = |id: String, title: String, score: u8, regex: Selection| {
        // YAML single-quoted scalars escape a quote by doubling it.
        let quote = |regex: &str| regex.replace('\'', "''");
        let matcher = match regex {
            Selection::Written(regex) => format!(
                "    targets: [written_path]\n    regex: '{}'\n",
                quote(&regex)
            ),
            Selection::Command(regex) => format!(
                "    detection:\n      selection:\n        command: '{}'\n      exclude:\n        command: '{}'\n      condition: selection\n",
                quote(&regex),
                quote(HARMLESS)
            ),
        };
        let severity = if score >= 90 { "high" } else { "medium" };
        rules.push_str(&format!(
            "  - id: tth.tamper.{id}\n    title: {title}\n    category: approval_bypass\n    severity: {severity}\n    score: {score}\n{matcher}    tags: [self-protection, hooks, defense-evasion]\n    explanation: {title}.\n"
        ));
        coverage.rules += 1;
    };
    let (anchor, writer, redirect) = if family.anchored {
        (
            format!("(?:^|IFS|{BEFORE_PATH})"),
            format!("(?:{WRITERS}(?:{SEGMENT}{BEFORE_PATH})?|{INTERPRETERS}.*{BEFORE_PATH})"),
            REDIRECT_TO.to_owned(),
        )
    } else {
        (
            String::new(),
            format!("(?:{WRITERS}{SEGMENT}|{INTERPRETERS}.*)"),
            format!("{REDIRECT_TO}{REDIRECT_SKIP}"),
        )
    };
    for (index, chunk) in chunk_fragments(&family.fragments).iter().enumerate() {
        let n = match index {
            0 => String::new(),
            _ => format!("_{}", index + 1),
        };
        let pattern = format!("(?:{})", chunk.join("|"));
        let mention = format!("{anchor}{pattern}");
        push(
            format!("{prefix}_write{n}"),
            format!("Agent writes {subject}"),
            90,
            Selection::Written(mention.clone()),
        );
        push(
            format!("{prefix}_command{n}"),
            format!("Agent command modifies {subject}"),
            90,
            Selection::Command(format!("(?s){COMMAND_START}{writer}{pattern}")),
        );
        if family.reversible {
            push(
                format!("{prefix}_command_reverse{n}"),
                format!("Agent command names {subject} and then runs a writing program"),
                90,
                Selection::Command(format!(
                    "(?s){mention}.*{COMMAND_START}(?:{WRITERS}|{INTERPRETERS})"
                )),
            );
        }
        push(
            format!("{prefix}_redirect{n}"),
            format!("Agent command redirects into {subject}"),
            90,
            Selection::Command(format!("(?s){redirect}{pattern}")),
        );
        if family.reference {
            push(
                format!("{prefix}_reference{n}"),
                format!("Agent command references {subject}"),
                60,
                Selection::Command(mention),
            );
        }
    }
    for (index, chunk) in chunk_fragments(&family.failsafe).iter().enumerate() {
        let n = match index {
            0 => String::new(),
            _ => format!("_{}", index + 1),
        };
        let mention = format!("{anchor}(?:{})", chunk.join("|"));
        // One rule per direction: a path can be long and the budget holds it once. A
        // writer on both sides of it adds up to a deny, which is no loss.
        push(
            format!("{prefix}_failsafe{n}"),
            format!("Agent command names a writing program and then {subject}"),
            60,
            Selection::Command(format!("(?s){WRITER_ANYWHERE}.*{mention}")),
        );
        push(
            format!("{prefix}_failsafe_reverse{n}"),
            format!("Agent command names {subject} and then a writing program"),
            60,
            Selection::Command(format!("(?s){mention}.*{WRITER_AFTER}")),
        );
    }
    if rules.is_empty() {
        return None;
    }
    let case_insensitive = cfg!(windows);
    Some(format!(
        "version: 1\ndescription: Telltale Hooks self-protection generated for this installation.\ndefaults:\n  case_insensitive: {case_insensitive}\n  enabled: true\nrules:\n{rules}modifiers: []\n"
    ))
}

fn generated_documents(paths: &[PathBuf], coverage: &mut GeneratedCoverage) -> Vec<String> {
    let binary = std::env::current_exe().ok();
    let [home_files, homes] =
        harness_home_families(&crate::hooks::config::harness_homes(), coverage);
    [
        own_state_family(paths, coverage),
        home_files,
        homes,
        installed_binary_family(binary.as_deref(), coverage),
    ]
    .iter()
    .filter_map(|family| family_document(family, coverage))
    .collect()
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

    fn own_state_document(paths: &[std::path::PathBuf]) -> (String, super::GeneratedCoverage) {
        let mut coverage = super::GeneratedCoverage::default();
        let family = super::own_state_family(paths, &mut coverage);
        let document = super::family_document(&family, &mut coverage).unwrap_or_default();
        (document, coverage)
    }

    #[test]
    fn generated_rules_dedupe_and_never_drop_a_path_for_size() {
        use std::path::PathBuf;
        let (doc, coverage) = own_state_document(&[
            PathBuf::from("/srv/tth/state"),
            PathBuf::from("/srv/tth/state/telemetry.jsonl"),
            PathBuf::from("/var/log/tth/telemetry.jsonl"),
            PathBuf::from("/etc/tth/config.toml"),
        ]);
        let sep = r"[\\/]+";
        assert!(
            doc.contains(&format!(
                "{sep}srv{sep}tth{sep}state|{sep}var{sep}log{sep}tth{sep}telemetry\\.jsonl|{sep}etc{sep}tth{sep}config\\.toml"
            )),
            "{doc}"
        );
        // The nested telemetry file is covered by its state dir; the other is
        // kept. One copy in each of the write, command, reverse, redirect and
        // reference rules.
        assert_eq!(doc.matches("telemetry\\.jsonl").count(), 5, "{doc}");
        assert!(!doc.contains("state[\\\\/]+telemetry"), "{doc}");
        assert_eq!((coverage.paths, coverage.rules), (3, 5));

        // Past the cap the same rule IDs continue with a number.
        let many: Vec<PathBuf> = (0..12)
            .map(|i| PathBuf::from(format!("/srv/{}/rules-{i}.yaml", "x".repeat(150))))
            .collect();
        let (doc, coverage) = own_state_document(&many);
        assert!(coverage.reduced.is_empty());
        assert!(doc.contains("tth.tamper.own_state_command_2"), "{doc}");
        for i in 0..12 {
            assert_eq!(doc.matches(&format!("rules\\-{i}\\.yaml")).count(), 5);
        }

        // One path too long for any rule keeps its last bytes and is reported.
        let long = format!("/{}/state.json", "y".repeat(1200));
        let (doc, coverage) = own_state_document(&[PathBuf::from(&long)]);
        assert_eq!(coverage.reduced, [long]);
        assert_eq!(doc.matches("state\\.json").count(), 5, "{doc}");
        for (_, pattern) in doc.lines().filter_map(|line| line.split_once(": '")) {
            let pattern = pattern.strip_suffix('\'').unwrap().replace("''", "'");
            assert!(pattern.len() <= 1024, "{pattern}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_utf8_is_reported_not_dropped_silently() {
        use std::os::unix::ffi::OsStringExt;
        let path = std::ffi::OsString::from_vec(b"/srv/\xff/state".to_vec());
        let (doc, coverage) = own_state_document(&[path.into()]);
        assert!(doc.is_empty());
        assert_eq!(coverage.paths, 1);
        assert_eq!(coverage.unrepresentable.len(), 1);
    }

    #[test]
    fn generated_rule_fragments_are_the_static_rules_text() {
        for (name, document) in super::HOST_RULE_DOCUMENTS {
            for fragment in [super::COMMAND_START, super::SEGMENT, super::HARMLESS] {
                assert!(
                    document.contains(&fragment.replace('\'', "''")),
                    "{name}: {fragment}"
                );
            }
        }
        let (_, document) = super::HOST_RULE_DOCUMENTS[0];
        for fragment in [
            super::WRITERS,
            super::INTERPRETERS,
            super::REDIRECT_TO,
            super::REDIRECT_SKIP,
            super::WRITER_ANYWHERE,
            super::WRITER_AFTER,
        ] {
            assert!(
                document.contains(&fragment.replace('\'', "''")),
                "{fragment}"
            );
        }
    }

    // How the exclusions built from the readers start. Nothing else states them.
    const PLAIN_GIT: &str = r#"^\s*git +(?:clone|init)(?: +[-A-Za-z0-9_./:=@~+]+)* *$"#;
    const QUOTED_START: &str = r#"^\s*(?:cd +[!*-:=?-\[\]-_a-{}~]+ *(?:&&|;)\s*)*"#;
    const FIND_START: &str = r#"^\s*(?:(?:[-A-Za-z0-9_][-.A-Za-z0-9_]* *)+[;&]+\s*)*(?:find (?:[^-;&|<>`$()\n\r\\]|-[^defo;&|<>`$()\n\r\\'"])*-exec(?:dir)? +(?:cat|[ef]?grep|basename|dirname|head|tail|wc|ls|stat|file|du|sha256sum|md5sum|jq) (?:[^-;&|<>`$()\n\r\\]|-[^defo;&|<>`$()\n\r\\'"]|-[efd] )*(?:\\; *)?\|?\s*)?"#;

    /// Rules with an exclusion other than `HARMLESS`. Rules of one kind share one text.
    const OTHER_EXCLUSIONS: &[(&str, &[&str])] = &[
        ("find", &["tth.tamper.hook_dir_find"]),
        (
            "launch",
            &[
                "tth.tamper.hookless_harness_launch",
                "tth.tamper.harness_home_override",
                "tth.tamper.harness_package_launch",
                "tth.tamper.hook_trust_bypass",
            ],
        ),
        ("launch failsafe", &["tth.tamper.harness_launch_failsafe"]),
        ("removal failsafe", &["tth.tamper.hook_removal_failsafe"]),
        ("uninstall", &["tth.tamper.hook_uninstall"]),
        ("read", &["tth.tamper.disable_all_hooks"]),
        (
            "text",
            &[
                "tth.tamper.reader_side_effect",
                "tth.tamper.hook_env_override",
                "tth.tamper.hook_env_override_export",
                "tth.tamper.hook_config_stage",
            ],
        ),
    ];

    /// Every exclusion that is not what its rule should carry: `HARMLESS` byte for byte, the
    /// one text of its kind, or what a kind of one rule is built from. A copy that drifted
    /// would quietly let commands through one rule and not its neighbours. The same change
    /// to every copy is not drift, and this does not see it.
    fn drifted_exclusions(documents: &[&str]) -> Vec<String> {
        let mut drifted = Vec::new();
        let mut kinds: std::collections::BTreeMap<&str, &str> = Default::default();
        for document in documents {
            let (mut rule, mut lines) = ("", document.lines());
            while let Some(line) = lines.next() {
                let line = line.trim_start();
                if let Some(id) = line.strip_prefix("- id: ") {
                    rule = id;
                }
                if line != "exclude:" {
                    continue;
                }
                let copy = lines
                    .next()
                    .and_then(|next| next.trim_start().strip_prefix("command: '"))
                    .and_then(|text| text.strip_suffix('\''));
                let Some(copy) = copy else {
                    drifted.push(format!("{rule}: an exclusion this test cannot read"));
                    continue;
                };
                let kind = OTHER_EXCLUSIONS
                    .iter()
                    .find(|(_, rules)| rules.contains(&rule))
                    .map(|(kind, _)| *kind);
                let same = match kind {
                    None => copy.replace("''", "'") == super::HARMLESS,
                    Some(kind) => *kinds.entry(kind).or_insert(copy) == copy,
                };
                if !same {
                    drifted.push(format!("{rule}: {copy}"));
                }
            }
        }
        // A kind of one rule has nothing like it to differ from, only what it is built from.
        let harmless = super::HARMLESS;
        let readers = &harmless[harmless.find("(?:(?:(?:cat|").unwrap()..harmless.len() - 2];
        let launch = exclusion_of(documents, "tth.tamper.hookless_harness_launch");
        let uninstall = exclusion_of(documents, "tth.tamper.hook_uninstall");
        for (rule, built) in [
            ("disable_all_hooks", format!(r"^\s*{readers}$")),
            ("hook_dir_find", format!("{FIND_START}{readers}$")),
            (
                "harness_launch_failsafe",
                format!("{QUOTED_START}{readers}$|{launch}|{PLAIN_GIT}"),
            ),
            (
                "hook_removal_failsafe",
                format!("{QUOTED_START}{readers}$|{uninstall}"),
            ),
        ] {
            let rule = format!("tth.tamper.{rule}");
            let copy = exclusion_of(documents, &rule).replace("''", "'");
            if copy != built.replace("''", "'") {
                drifted.push(format!("{rule}: {copy}"));
            }
        }
        drifted
    }

    /// Pieces of a shared fragment still in a document once its true copies are taken out: a
    /// copy with one byte changed leaves the rest of itself behind. A copy rewritten through
    /// and through, or a rule that never used the fragment, leaves nothing and is not seen.
    fn stray_pieces(document: &str, fragments: &[&str]) -> Vec<String> {
        let fragments: Vec<String> = fragments.iter().map(|f| f.replace('\'', "''")).collect();
        let mut rest = document.to_owned();
        for fragment in &fragments {
            rest = rest.replace(fragment, "\n");
        }
        fragments
            .iter()
            .flat_map(|fragment| fragment.as_bytes().chunks(STRAY_PIECE))
            .filter(|piece| piece.len() == STRAY_PIECE)
            .filter_map(|piece| std::str::from_utf8(piece).ok())
            .filter(|piece| rest.contains(piece))
            .map(ToOwned::to_owned)
            .collect()
    }

    const STRAY_PIECE: usize = 32;

    fn with_one_character_changed(document: &str, mut at: usize) -> String {
        while !document.is_char_boundary(at) {
            at += 1;
        }
        let old = document[at..].chars().next().unwrap();
        let new = if old == '~' { '^' } else { '~' };
        let rest = at + old.len_utf8();
        format!("{}{new}{}", &document[..at], &document[rest..])
    }

    /// What `stray_pieces` looks for. `SEGMENT` and the `REDIRECT_*` are too short to leave a
    /// piece, and the exclusions have their own test.
    fn shared_fragments() -> [&'static str; 6] {
        let windows = super::WRITERS.find("|(?:del|").unwrap();
        [
            super::WRITER_ANYWHERE,
            super::WRITER_AFTER,
            super::COMMAND_START,
            &super::WRITERS[3..windows],
            &super::WRITERS[windows + 1..super::WRITERS.len() - 1],
            super::INTERPRETERS,
        ]
    }

    #[test]
    fn every_shared_fragment_copy_is_the_canonical_text() {
        for (name, document) in super::HOST_RULE_DOCUMENTS {
            let stray = stray_pieces(document, &shared_fragments());
            assert!(stray.is_empty(), "{name}: {stray:?}");
            // One character in the last copy of each is enough.
            for fragment in shared_fragments() {
                let fragment = fragment.replace('\'', "''");
                let Some(last) = document.rfind(&fragment) else {
                    assert_ne!(fragment, super::COMMAND_START, "{name}");
                    continue;
                };
                let changed = with_one_character_changed(document, last + fragment.len() / 2);
                assert!(
                    !stray_pieces(&changed, &shared_fragments()).is_empty(),
                    "{name}: a changed copy of {fragment} was not found"
                );
            }
        }
    }

    /// Every writer word of the deny rules is a writer word of the fail-safe rules, so what a
    /// deny rule stops in one spelling at least asks in the rest. A list is any alternation
    /// that holds a word every list has; a new word in one is checked without being named here.
    #[test]
    fn the_fail_safe_writers_cover_every_deny_writer() {
        // What the rules on `main` had before there were fail-safe rules, in case one is cut.
        const BEFORE_FAIL_SAFE: &[&str] = &[
            "Add-Content",
            "Clear-Content",
            "Copy-Item",
            "Move-Item",
            "New-Item",
            "Out-File",
            "Remove-Item",
            "Rename-Item",
            "Set-Content",
            "ac",
            "copy",
            "cp",
            "cpi",
            "del",
            "erase",
            "ln",
            "mi",
            "move",
            "mv",
            "rd",
            "ren",
            "rename",
            "ri",
            "rm",
            "rmdir",
            "sc",
            "sed",
            "shred",
            "tee",
            "truncate",
            "unlink",
        ];
        let list =
            regex::Regex::new(r"\(\?:((?:[A-Za-z_][-A-Za-z_0-9]*\|)+[A-Za-z_][-A-Za-z_0-9]*)\)")
                .unwrap();
        let mut words: std::collections::BTreeSet<String> =
            BEFORE_FAIL_SAFE.iter().map(ToString::to_string).collect();
        // Not in a list: `git -C <home> clean`, with its flags between the words.
        words.insert("clean".to_owned());
        for (_, document) in super::HOST_RULE_DOCUMENTS {
            let flat = document
                .replace(
                    "(?:Remove|Move|Copy|Rename|New)-Item",
                    "Remove-Item|Move-Item|Copy-Item|Rename-Item|New-Item",
                )
                .replace(
                    "(?:Set|Add|Clear)-Content",
                    "Set-Content|Add-Content|Clear-Content",
                );
            for found in list.captures_iter(&flat) {
                let found: Vec<&str> = found[1].split('|').collect();
                if ["rm", "del", "rmtree"]
                    .iter()
                    .any(|word| found.contains(word))
                {
                    words.extend(found.iter().map(ToString::to_string));
                }
            }
        }
        assert!(words.len() > BEFORE_FAIL_SAFE.len() + 5, "{words:?}");
        let writer = regex::Regex::new(super::WRITER_ANYWHERE).unwrap();
        assert!(!writer.is_match("wipe -i x"));
        for word in &words {
            for spelling in [format!("{word} -i x"), format!("{word}.exe -i x")] {
                assert!(writer.is_match(&spelling), "{spelling}");
            }
        }
    }

    fn exclusion_of<'a>(documents: &[&'a str], rule: &str) -> &'a str {
        let at = format!("- id: {rule}\n");
        let document = documents.iter().find(|d| d.contains(&at)).unwrap();
        let rest = &document[document.find(&at).unwrap()..];
        let rest = &rest[rest.find("exclude:").unwrap()..];
        let text = &rest[rest.find("command: '").unwrap() + "command: '".len()..];
        &text[..text.find('\n').unwrap() - 1]
    }

    #[test]
    fn every_exclusion_copy_is_the_canonical_text() {
        let documents: Vec<&str> = super::HOST_RULE_DOCUMENTS
            .iter()
            .map(|(_, document)| *document)
            .collect();
        let drifted = drifted_exclusions(&documents);
        assert!(drifted.is_empty(), "{}", drifted.join("\n"));
        // The readers are one text inside several exclusions: this one is only that.
        let read = exclusion_of(&documents, "tth.tamper.disable_all_hooks").replace("''", "'");
        let readers = read
            .strip_prefix(r"^\s*")
            .and_then(|read| read.strip_suffix('$'))
            .unwrap();
        for rule in [
            "tth.tamper.hook_dir_find",
            "tth.tamper.harness_launch_failsafe",
            "tth.tamper.hook_removal_failsafe",
        ] {
            let exclusion = exclusion_of(&documents, rule).replace("''", "'");
            assert!(exclusion.contains(readers), "{rule}");
        }
        assert!(super::HARMLESS.contains(readers));
        // One byte is enough in any copy, whichever rule and however far along.
        for (index, document) in documents.iter().enumerate() {
            let starts = document.match_indices("exclude:\n").map(|(at, _)| at);
            for start in starts {
                let text = start + document[start..].find("command: '").unwrap() + 10;
                let end = text + document[text..].find('\n').unwrap() - 1;
                for at in [text + 1, (text + end) / 2, end - 2] {
                    let changed = with_one_character_changed(document, at);
                    let mut with_one_changed = documents.clone();
                    with_one_changed[index] = &changed;
                    assert!(
                        !drifted_exclusions(&with_one_changed).is_empty(),
                        "byte {at} of {}",
                        &document[start..end]
                    );
                }
            }
        }
    }

    /// A character YAML refuses or folds reaches the regex by its code point, and
    /// the pattern still matches the path. So does every other character outside
    /// printable ASCII, which costs a non-ASCII path room: `\x{e9}` is six bytes where
    /// `é` is two, and past the cap the path moves to a numbered rule or keeps its tail.
    #[test]
    fn a_path_character_yaml_cannot_carry_is_written_by_its_code_point() {
        use std::path::PathBuf;
        let patterns = |doc: &str| -> Vec<String> {
            doc.lines()
                .filter_map(|line| line.split_once(": '"))
                .map(|(_, pattern)| pattern.strip_suffix('\'').unwrap().replace("''", "'"))
                .collect()
        };
        let rule = |doc: &str, rule: &str| -> String {
            let id = format!("- id: tth.tamper.{rule}");
            let rest: Vec<&str> = doc
                .lines()
                .skip_while(|line| line.trim_start() != id)
                .collect();
            patterns(&rest.join("\n")).swap_remove(0)
        };
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
            let (doc, _) = own_state_document(&[PathBuf::from(&path)]);
            // Every rule the path went into, not one of them.
            let all = patterns(&doc);
            let carrying: Vec<&String> = all
                .iter()
                .filter(|pattern| pattern.contains(r"[\\/]+srv[\\/]+a"))
                .collect();
            assert_eq!(carrying.len(), 5, "{c:?}: {doc}");
            for pattern in carrying {
                assert!(pattern.contains(&format!("a{written}b")), "{c:?}: {doc}");
                assert!(!pattern.contains(c), "{c:?}: {doc}");
            }
            let written = regex::Regex::new(&rule(&doc, "own_state_write")).unwrap();
            assert!(written.is_match(&path), "{c:?}");
            let command = regex::Regex::new(&rule(&doc, "own_state_command")).unwrap();
            assert!(command.is_match(&format!("rm -rf {path}")), "{c:?}");
        }
        // Everything else outside printable ASCII goes the same way, and still means that path.
        let path = "/home/synthetic/josé/日本語";
        let (doc, _) = own_state_document(&[PathBuf::from(path)]);
        assert!(
            doc.contains(r"jos\x{e9}[\\/]+\x{65e5}\x{672c}\x{8a9e}"),
            "{doc}"
        );
        let written = regex::Regex::new(&rule(&doc, "own_state_write")).unwrap();
        assert!(written.is_match(path), "{doc}");
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

#[cfg(test)]
mod recovery_tests {
    use super::*;

    /// The end of the list is tried first.
    fn tried_first_to_last(sizes: &[usize]) -> Vec<usize> {
        let mut order = restoration_order(sizes);
        order.reverse();
        order
    }

    #[test]
    fn the_newest_lines_go_back_first_whatever_their_size() {
        let mut sizes = vec![100; 4];
        sizes.extend(vec![4000; RESTORE_NEWEST]);
        let order = tried_first_to_last(&sizes);
        let newest: Vec<usize> = (4..4 + RESTORE_NEWEST).rev().collect();
        assert_eq!(&order[..RESTORE_NEWEST], newest.as_slice());
    }

    #[test]
    fn older_lines_go_back_short_ones_first_then_by_age() {
        let mut sizes = vec![4000, 300, 2000, 100, 1024, 1500];
        sizes.extend(vec![50; RESTORE_NEWEST]);
        let order = tried_first_to_last(&sizes);
        assert_eq!(&order[RESTORE_NEWEST..], &[3, 1, 5, 4, 2, 0]);
    }

    #[test]
    fn a_short_history_goes_back_newest_first() {
        assert_eq!(tried_first_to_last(&[9, 1, 5]), [2, 1, 0]);
        assert!(tried_first_to_last(&[]).is_empty());
    }

    fn budget_used(used: Duration, ms_per_byte: f64) -> RecoveryBudget {
        RecoveryBudget {
            started: Instant::now() - used,
            ms_per_byte,
        }
    }

    const DENY: &str = "rm -f ~/.claude/settings.json";
    const DENY_RULE: &str = "tth.tamper.hook_settings_modify";

    fn hosts(from: usize, count: usize) -> String {
        let hosts: Vec<String> = (from..from + count)
            .map(|i| format!("http://{i:x}-9.test"))
            .collect();
        hosts.join(" ")
    }

    /// A call past capacity on its own, as the runtime projects it.
    fn pieces(command: String) -> (Vec<Line>, Vec<Focus>) {
        let input = serde_json::json!({ "command": command });
        let variants = crate::hooks::projection::project(&input).unwrap();
        assert!(variants.len() <= crate::hooks::projection::MAX_VARIANTS);
        let mut lines = Vec::new();
        let mut focus = Vec::new();
        for (n, variant) in variants.iter().enumerate() {
            let at = format!("2026-11-06T00:00:00.{n:03}Z");
            let uuid = format!("uuid-{n}");
            lines.push(Line::tool_use("s", &uuid, &at, "toolu_1", "Bash", variant));
            focus.push(Focus {
                occurred_at: at,
                stage: ObservationStage::ToolRequested,
                native_id: uuid,
            });
        }
        (lines, focus)
    }

    /// The window path and the engine, for a scan of `pieces` alone.
    fn engine() -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::new(&TelltaleSettings::default(), &[]).unwrap();
        (dir, engine)
    }

    /// `used` is what the evaluation has already spent. The budget starts after the
    /// engine is built, so that the build is not charged to it.
    fn evaluate_with(command: String, used: Duration) -> (Evaluation, usize) {
        let (lines, focus) = pieces(command);
        let (dir, engine) = engine();
        let mut budget = budget_used(used, 0.0);
        let evaluation = engine
            .evaluate(
                &dir.path().join("window.jsonl"),
                &[],
                &lines,
                &focus,
                &mut budget,
            )
            .unwrap();
        (evaluation, lines.len())
    }

    /// Scan the pieces of `command`, with the time limit reached after one scan.
    fn limit_after_one_piece(command: String) -> (Evaluation, usize) {
        let (lines, focus) = pieces(command);
        let (dir, engine) = engine();
        let mut left = 1;
        let evaluation = engine
            .scan_each(&dir.path().join("window.jsonl"), &lines, &focus, || {
                let in_time = left > 0;
                left = 0;
                in_time
            })
            .unwrap();
        (evaluation, lines.len())
    }

    fn has_deny_rule(evaluation: &Evaluation) -> bool {
        evaluation.rule_ids().iter().any(|rule| rule == DENY_RULE)
    }

    fn says_unscanned(evaluation: &Evaluation) -> bool {
        evaluation
            .visibility_limits
            .iter()
            .any(|limit| limit == "pending_pieces_unscanned")
    }

    fn verdict(evaluation: &Evaluation) -> crate::hooks::state::Verdict {
        let inputs = crate::hooks::policy::Inputs {
            action_score: evaluation.action_score(),
            session_score: 0,
            denied_attempts: 0,
        };
        crate::hooks::policy::decide(inputs, &crate::hooks::config::Thresholds::default()).verdict
    }

    /// The pieces are all that secures the verdict of a call past capacity on its
    /// own, and an agent can load the CPU itself, so the budget must not drop the
    /// piece that carries a deny. It sits early in the call, so that only the scans
    /// ahead of the pieces have to finish inside the limit, not the whole call.
    #[test]
    fn a_spent_budget_does_not_stop_the_pieces_of_a_call_past_capacity() {
        let (evaluation, lines) = evaluate_with(
            format!("echo {}; {DENY}; echo {}", hosts(0, 400), hosts(400, 14600)),
            RECOVERY_BUDGET,
        );
        assert_eq!(evaluation.unevaluated_focus, lines, "in pieces");
        assert!(
            has_deny_rule(&evaluation),
            "{:?}, {:?}",
            evaluation.status,
            evaluation.rule_ids()
        );
    }

    #[test]
    fn a_deny_in_a_piece_scanned_before_the_limit_keeps_its_force() {
        let (evaluation, lines) =
            limit_after_one_piece(format!("{DENY}; echo {}", hosts(0, 15000)));
        assert!(has_deny_rule(&evaluation), "{:?}", evaluation.rule_ids());
        assert_eq!(verdict(&evaluation), crate::hooks::state::Verdict::Deny);
        assert_eq!(evaluation.status, EvalStatus::VisibilityLimited);
        assert_eq!(evaluation.unevaluated_focus, lines);
        assert!(says_unscanned(&evaluation));
    }

    /// What is left is the state a call with no finding is in, which the runtime
    /// floors at `on_unevaluable`
    /// (`a_benign_call_past_capacity_on_its_own_is_floored_and_harms_nothing_later`).
    #[test]
    fn a_deny_in_a_piece_past_the_limit_is_left_to_on_unevaluable() {
        let (evaluation, lines) =
            limit_after_one_piece(format!("echo {}; {DENY}", hosts(0, 15000)));
        assert!(!has_deny_rule(&evaluation), "{:?}", evaluation.rule_ids());
        assert_ne!(verdict(&evaluation), crate::hooks::state::Verdict::Deny);
        assert_eq!(evaluation.status, EvalStatus::VisibilityLimited);
        assert_eq!(evaluation.unevaluated_focus, lines);
        assert!(says_unscanned(&evaluation));
    }

    /// The limit counts from the start of the evaluation, not from the first piece.
    #[test]
    fn an_evaluation_already_past_the_limit_scans_no_piece() {
        let (evaluation, lines) = evaluate_with(
            format!("{DENY}; echo {}", hosts(0, 15000)),
            PIECE_SCAN_LIMIT,
        );
        assert!(!has_deny_rule(&evaluation), "{:?}", evaluation.rule_ids());
        assert_eq!(evaluation.status, EvalStatus::NotEvaluated);
        assert_eq!(evaluation.unevaluated_focus, lines);
        assert!(says_unscanned(&evaluation));
    }

    #[test]
    fn the_piece_limit_is_later_than_the_budget() {
        assert!(budget_used(RECOVERY_BUDGET, 0.0).pieces_in_time());
        assert!(!budget_used(PIECE_SCAN_LIMIT, 0.0).pieces_in_time());
    }

    #[test]
    fn a_scan_that_may_not_fit_is_not_admitted() {
        let fresh = RecoveryBudget::start();
        assert!(fresh.admits(usize::MAX / 2), "nothing measured yet");
        // 1 MB at 0.5 ms per KB: 500 ms, doubled.
        let rate = 0.0005;
        assert!(budget_used(Duration::from_millis(900), rate).admits(1_000_000));
        assert!(!budget_used(Duration::from_millis(1100), rate).admits(1_000_000));
        assert!(budget_used(Duration::from_millis(1100), rate).admits(500_000));
        assert!(!budget_used(RECOVERY_BUDGET, 0.0).admits(1));
        assert!(budget_used(RECOVERY_BUDGET, 0.0).spent());
    }

    #[test]
    fn the_slowest_rate_counts_and_small_scans_do_not_set_it() {
        let mut budget = RecoveryBudget::start();
        budget.observe(100, 50);
        assert_eq!(budget.ms_per_byte, 0.0, "mostly a scan's fixed setup");
        budget.observe(MIN_MEASURED_BYTES, 100);
        let rate = budget.ms_per_byte;
        assert!(rate > 0.0);
        budget.observe(MIN_MEASURED_BYTES * 2, 100);
        assert_eq!(budget.ms_per_byte, rate);
    }
}
