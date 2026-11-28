//! Telltale integration through the supported embedding facade only
//! (`Pipeline::scan_sources_detailed`, `SourceScan`, `ActionRecordV1`).
//!
//! Telltale has no API for evaluating a single pending action, so the hook
//! writes a bounded window of JSONL in Claude Code's record encoding (history
//! plus the pending call, each in the shape its harness reported) and scans it as the hook-journal source of the client the
//! call belongs to (`Adapter::client`, `ClientId::hook_journal_source_id`), the pattern
//! docs/embedding.md prescribes for synthetic sources. Findings for the
//! pending call are the action findings anchored at its unique source time.

use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{
    AcquisitionError, DetailedEvaluationOptions, EvaluationCompletion, ObservationStage, Pipeline,
    PipelineError, Source, SourceCoverage, SourceKind, SourceScan,
};

use telltale_rules::{DefinitionKind, LoadedDefinition, LoadedRules};

use crate::ClientId;
use crate::hooks::config::{Grants, HOST_RULE_CATEGORY, HOST_RULE_ID_PREFIX, RuleContent};
use crate::hooks::harness::{Harness, HostRules};
use crate::hooks::journal::Line;
use crate::hooks::telemetry::TelltaleAction;

/// The shared host-owned Rule v2 template (name, content): detections of an
/// agent disabling hooks, for every harness. A template writes the pattern
/// text rules share as `{{NAME}}` (`RULE_FRAGMENTS`).
const SHARED_RULE_TEMPLATE: (&str, &str) = (
    "telltale-hooks-self-protection.yaml",
    include_str!("rules/telltale-hooks-self-protection.yaml"),
);

/// The enforcement test signatures (name, content): two rules that match one
/// harmless command each. Loaded only on request
/// ([`RuleContent::test_signatures`]), and never part of
/// [`host_rule_documents`]: they are not self-protection, so tamper prevention
/// does not lock them.
pub fn test_signature_document() -> (&'static str, &'static str) {
    (
        "telltale-hooks-test-signatures.yaml",
        include_str!("rules/telltale-hooks-test-signatures.yaml"),
    )
}

/// The grant-protection template (name, content): host rules for the tool
/// calls that could raise a user-prompt event of their own making. Loaded with
/// the self-protection rules, and only while grants are on
/// ([`crate::hooks::config::Grants::enabled`]), so with grants off the rule
/// set is the same as without them.
const GRANT_RULE_TEMPLATE: (&str, &str) = (
    "telltale-hooks-grants-protection.yaml",
    include_str!("rules/telltale-hooks-grants-protection.yaml"),
);

/// The grant-protection document (name, content), expanded as
/// [`host_rule_documents`] expands the others.
pub fn grant_protection_document() -> &'static (&'static str, String) {
    static DOCUMENT: std::sync::LazyLock<(&str, String)> = std::sync::LazyLock::new(|| {
        (
            GRANT_RULE_TEMPLATE.0,
            expand_fragments(GRANT_RULE_TEMPLATE.1),
        )
    });
    &DOCUMENT
}

/// Every host rule template (name, content): the shared one, then each
/// adapter's own (`Adapter::rules`). All are loaded into the one pipeline that
/// serves every harness.
fn host_rule_templates() -> Vec<(&'static str, &'static str)> {
    let own = Harness::ALL
        .iter()
        .filter_map(|harness| match harness.adapter().rules {
            HostRules::Document(name, template) => Some((name, template)),
            HostRules::Shared => None,
        });
    std::iter::once(SHARED_RULE_TEMPLATE).chain(own).collect()
}

/// The bundled host rule documents (name, content), with every placeholder expanded.
pub fn host_rule_documents() -> &'static [(&'static str, String)] {
    static DOCUMENTS: std::sync::LazyLock<Vec<(&str, String)>> = std::sync::LazyLock::new(|| {
        host_rule_templates()
            .into_iter()
            .map(|(name, template)| (name, expand_fragments(template)))
            .collect()
    });
    &DOCUMENTS
}

/// A host rule template with every placeholder expanded, as
/// [`host_rule_documents`] expands the bundled ones. For the Rule v2
/// conversion parity test, which expands the pre-conversion templates.
#[doc(hidden)]
pub fn expand_rule_template(template: &str) -> String {
    expand_fragments(template)
}

/// Replace each `{{NAME}}` that names a `RULE_FRAGMENTS` entry by its text, quoted for
/// the single-quoted YAML value it stands in. Other text, an unknown name included,
/// stays as written; a test holds every template to known names in quoted values.
fn expand_fragments(template: &str) -> String {
    let mut expanded = String::with_capacity(2 * template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        expanded.push_str(&rest[..start]);
        rest = &rest[start + 2..];
        let fragment = rest
            .split_once("}}")
            .and_then(|(name, _)| rule_fragments().iter().find(|(known, _)| *known == name));
        match fragment {
            Some((name, text)) => {
                // YAML single-quoted values escape a quote by doubling it.
                expanded.push_str(&text.replace('\'', "''"));
                rest = &rest[name.len() + 2..];
            }
            None => expanded.push_str("{{"),
        }
    }
    expanded.push_str(rest);
    expanded
}

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

impl std::error::Error for EngineError {
    /// What made the pipeline fail, which can name a file and a rule ID: for
    /// an operator's terminal (`telltale hooks check`), never for telemetry,
    /// which carries [`Self::code`].
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build(error) | Self::Provenance(error) | Self::Scan(error) => {
                std::error::Error::source(error)
            }
            Self::Content(..) | Self::Window(_) | Self::NoResult => None,
        }
    }
}

pub struct Engine {
    pipeline: Pipeline,
    options: DetailedEvaluationOptions,
    semantic_identity: String,
    generated: GeneratedCoverage,
    /// Override entries left out because they name no rule or chain that
    /// is loaded (`rule_resolution::resolve_rule_content`).
    skipped_overrides: Vec<String>,
    /// The names of the enforcement test signatures, when they are loaded
    /// ([`test_signature_document`]); empty otherwise.
    test_signatures: Vec<String>,
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
    /// Action records anchored at the focus observation, in Telltale order,
    /// each with its upload destination facts.
    pub focus_records: Vec<TelltaleAction>,
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
    /// Nothing about the focus was evaluated (yet).
    fn not_evaluated(focus_count: usize, scan_ms: u64) -> Self {
        Self {
            status: EvalStatus::NotEvaluated,
            coverage: None,
            visibility_limits: Vec::new(),
            failure_code: None,
            focus_records: Vec::new(),
            other_record_count: 0,
            unevaluated_focus: focus_count,
            focus_count,
            scan_ms,
            source_failed: false,
            capacity_failed: false,
            history_kept: 0,
        }
    }

    /// Highest promotion score among actions anchored at the focus.
    pub fn action_score(&self) -> u64 {
        self.focus_records
            .iter()
            .map(|action| action.record.promotion_score)
            .max()
            .unwrap_or(0)
    }

    pub fn rule_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .focus_records
            .iter()
            .flat_map(|action| action.record.rule_ids.iter().cloned())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    pub fn categories(&self) -> Vec<String> {
        let mut categories: Vec<String> = self
            .focus_records
            .iter()
            .flat_map(|action| action.record.categories.iter().cloned())
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
    /// With `grants` on, the self-protection rules include
    /// [`grant_protection_document`].
    pub fn new(
        rules: &RuleContent,
        grants: &Grants,
        protected_paths: &[PathBuf],
    ) -> Result<Self, EngineError> {
        let started = Instant::now();
        // The operator's files are read once, here, as operator input (a
        // symlink is followed, but the target must be a regular file, so a
        // FIFO is refused rather than waited on), and resolution uses that
        // text. One that is gone or swapped is an unreadable-content failure,
        // distinct from content that does not build.
        let contents = rules
            .files()
            .map(|path| Ok((path.clone(), read(path)?)))
            .collect::<Result<Vec<_>, EngineError>>()?;
        let replacements = contents
            .iter()
            .map(|(path, text)| (path.clone(), text.as_str()))
            .collect::<Vec<_>>();
        let mut generated = GeneratedCoverage::default();
        let documents = if rules.self_protection {
            self_protection_documents(protected_paths, grants.enabled, &mut generated)?
        } else {
            Vec::new()
        };
        // With tamper prevention on, the self-protection rules are loaded
        // where no other content can replace them, and the rules that are
        // built must carry each one as its document defines it. Without it
        // they are ordinary bundled rules: a managed tier can replace one by
        // name, and overrides and the policy apply to them.
        let locked = rules.tamper_prevention;
        let host_rules = host_rule_definitions(&documents);
        let (fixed, mut replaceable) = if locked {
            (documents, Vec::new())
        } else {
            (Vec::new(), documents)
        };
        // Test signatures are ordinary bundled rules whatever the lock says.
        let mut test_signatures = Vec::new();
        if rules.test_signatures {
            let (name, document) = test_signature_document();
            let parsed = LoadedRules::parse(document)
                .map_err(|error| EngineError::Build(PipelineError::Compilation(error)))?;
            test_signatures = parsed
                .definitions()
                .iter()
                .map(|definition| definition.id().to_owned())
                .collect();
            replaceable.push((format!("hooks:{name}"), parsed));
        }
        let (resolution, skipped_overrides) = crate::rule_resolution::resolve_rule_set_with_host(
            &rules.packs,
            &[],
            fixed,
            replaceable,
            rules.policy.as_deref(),
            telltale_rules::RuleLoadMode::IncludeDefault,
            &rules.overrides,
            &replacements,
        )
        .map_err(|error| {
            EngineError::Build(PipelineError::Compilation(error.to_string().into()))
        })?;
        if locked && let Some(id) = altered_host_rule(&host_rules, &resolution.content) {
            return Err(EngineError::Build(PipelineError::Compilation(
                format!("user rule content changes the self-protection rule {id}").into(),
            )));
        }
        if locked && let Some(id) = dropped_host_rule(&host_rules, &resolution.rule_set) {
            return Err(EngineError::Build(PipelineError::Compilation(
                format!("the policy removes the self-protection rule {id}").into(),
            )));
        }
        let pipeline = resolution.into_pipeline().map_err(EngineError::Build)?;
        let mut options = DetailedEvaluationOptions::default();
        options.process_chain = rules.process_chain;
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
            skipped_overrides,
            test_signatures,
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
    /// stop at [`PIECE_SCAN_LIMIT`] instead, and so does the scan of a
    /// projection's lines together: past it, a projected call is not scanned.
    /// A projection past its budget ([`PendingScan::PiecesOnly`]) goes
    /// straight to the scans of its lines, and after them, if the budget
    /// admits it, to one scan of history with the line the call is journaled
    /// as ([`Request::journaled`]). That scan only adds findings: every focus
    /// line still counts as unevaluated.
    pub fn evaluate(
        &self,
        request: Request<'_>,
        budget: &mut RecoveryBudget,
    ) -> Result<Evaluation, EngineError> {
        // The trace goes back into the budget however the evaluation ends, so
        // a call whose scan failed still records what its scans did.
        let mut trace = std::mem::take(&mut budget.trace);
        let evaluated = self.evaluate_traced(request, budget, &mut trace);
        budget.trace = trace;
        evaluated
    }

    fn evaluate_traced(
        &self,
        request: Request<'_>,
        budget: &mut RecoveryBudget,
        trace: &mut ScanTrace,
    ) -> Result<Evaluation, EngineError> {
        let Request {
            client,
            window_path,
            history,
            pending,
            focus,
            scan,
            journaled,
        } = request;
        let sizes: Vec<usize> = history.iter().map(|line| line.to_jsonl().len()).collect();
        let pending_bytes = pending.iter().map(|line| line.to_jsonl().len()).sum();
        let whole_bytes = pending_bytes + sizes.iter().sum::<usize>();
        let mut failure_code = None;
        // With no history, the scan of `pending` alone is this one again.
        let mut alone = None;
        // A projection past its budget holds more than Telltale takes in one
        // scan: it is not scanned whole nor its variants together, so the
        // time goes to its pieces, the command's first.
        let pieces_only = scan == PendingScan::PiecesOnly && pending.len() > 1;
        trace.together = None;
        trace.history = None;
        if pieces_only {
            trace.whole = Some(StepOutcome::SkippedPiecesOnly);
        } else if !budget.admits(whole_bytes) {
            trace.whole = Some(StepOutcome::SkippedBudget);
        } else {
            let whole = self.scan(client, window_path, history.iter().chain(pending), focus)?;
            budget.observe(whole_bytes, whole.scan_ms);
            trace.whole_ms += whole.scan_ms;
            if !whole.source_failed {
                trace.whole = Some(StepOutcome::Passed);
                return Ok(Evaluation {
                    history_kept: history.len(),
                    ..whole
                });
            }
            trace.whole = Some(StepOutcome::Refused);
            failure_code = whole.failure_code.clone();
            alone = history.is_empty().then_some(whole);
        }
        // A projection's variants scanned together come ahead of the piece
        // loop and are bound by the same limit: past it, none is scanned.
        let late = pieces_only || (pending.len() > 1 && !budget.pieces_in_time());
        let mut best = if late {
            trace.together = Some(if pieces_only {
                StepOutcome::SkippedPiecesOnly
            } else {
                StepOutcome::SkippedLate
            });
            Evaluation::not_evaluated(focus.len(), 0)
        } else if let Some(alone) = alone {
            trace.together = Some(StepOutcome::SameAsWhole);
            alone
        } else {
            let scan = self.scan(client, window_path, pending.iter(), focus)?;
            budget.observe(pending_bytes, scan.scan_ms);
            trace.together_ms += scan.scan_ms;
            trace.together = Some(if scan.source_failed {
                StepOutcome::Refused
            } else {
                StepOutcome::Passed
            });
            scan
        };
        let mut kept = vec![false; history.len()];
        let phase = Instant::now();
        if (late || best.source_failed) && pending.len() > 1 {
            best = self.scan_each(client, window_path, pending, focus, trace, || {
                budget.pieces_in_time()
            })?;
            trace.pieces_ms += phase.elapsed().as_millis() as u64;
            // With no history there is nothing to read with the call.
            if let Some(journaled) = journaled.filter(|_| pieces_only && !history.is_empty()) {
                let window = Window {
                    client,
                    path: window_path,
                    history,
                    sizes: &sizes,
                    pending: std::slice::from_ref(journaled.0),
                    pending_bytes: journaled.0.to_jsonl().len(),
                    focus: std::slice::from_ref(journaled.1),
                };
                if self.read_history(&window, budget, trace, &mut best)? {
                    kept.fill(true);
                }
            }
        } else if best.status != EvalStatus::NotEvaluated {
            let window = Window {
                client,
                path: window_path,
                history,
                sizes: &sizes,
                pending,
                pending_bytes,
                focus,
            };
            best = self.restore_history(&window, budget, best, &mut kept)?;
            trace.history_ms += phase.elapsed().as_millis() as u64;
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
            let scan = self.scan(
                window.client,
                window.path,
                lines.chain(window.pending),
                window.focus,
            )?;
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

    /// After the pieces of a projection past its budget: one scan of history
    /// with the line the call is journaled as (`window.pending`), if `budget`
    /// admits it and the piece time limit has not passed, and none otherwise.
    /// Nothing is split or retried. What the scan finds is added to `best`,
    /// which loses nothing: its unevaluated focus and failure code stay.
    /// Returns whether history was read.
    fn read_history(
        &self,
        window: &Window<'_>,
        budget: &mut RecoveryBudget,
        trace: &mut ScanTrace,
        best: &mut Evaluation,
    ) -> Result<bool, EngineError> {
        let bytes = window.pending_bytes + window.sizes.iter().sum::<usize>();
        let skipped = if !budget.pieces_in_time() {
            Some(StepOutcome::SkippedLate)
        } else if !budget.admits(bytes) {
            Some(StepOutcome::SkippedBudget)
        } else {
            None
        };
        if skipped.is_some() {
            trace.history = skipped;
            return Ok(false);
        }
        let scan = self.scan(
            window.client,
            window.path,
            window.history.iter().chain(window.pending),
            window.focus,
        )?;
        budget.observe(bytes, scan.scan_ms);
        trace.history_ms += scan.scan_ms;
        if scan.status == EvalStatus::NotEvaluated {
            trace.history = Some(StepOutcome::Refused);
            return Ok(false);
        }
        trace.history = Some(StepOutcome::Passed);
        // With no piece evaluated, only a finding makes the call evaluated: a
        // scan that found nothing evaluated none of the call's own input.
        if best.status == EvalStatus::NotEvaluated && scan.focus_records.is_empty() {
            return Ok(true);
        }
        best.status = EvalStatus::VisibilityLimited;
        best.coverage = Some("partial");
        best.focus_records.extend(scan.focus_records);
        for limit in scan.visibility_limits {
            if !best.visibility_limits.contains(&limit) {
                best.visibility_limits.push(limit);
            }
        }
        Ok(true)
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
        client: ClientId,
        window_path: &Path,
        pending: &[Line],
        focus: &[Focus],
        trace: &mut ScanTrace,
        mut in_time: impl FnMut() -> bool,
    ) -> Result<Evaluation, EngineError> {
        let mut merged = Evaluation::not_evaluated(focus.len(), 0);
        trace.pieces_total += pending.len();
        for (line, one) in pending.iter().zip(focus) {
            if !in_time() {
                merged
                    .visibility_limits
                    .push("pending_pieces_unscanned".to_owned());
                break;
            }
            let scan = self.scan(
                client,
                window_path,
                std::iter::once(line),
                std::slice::from_ref(one),
            )?;
            trace.pieces_scanned += 1;
            if scan.status == EvalStatus::NotEvaluated {
                trace.pieces_refused += 1;
                if trace.first_refusal.is_none() {
                    trace.first_refusal = scan.failure_code;
                }
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

    /// The `rule_id` of each override entry that was left out because it
    /// names no rule or chain this engine loads: for example a
    /// self-protection rule while those are off, or a mistyped name
    /// (`telltale hooks check`).
    pub fn skipped_overrides(&self) -> &[String] {
        &self.skipped_overrides
    }

    /// The names of the enforcement test signatures this engine loaded: the
    /// rules of [`test_signature_document`], and empty unless
    /// [`RuleContent::test_signatures`] is on. A rule a config root replaces
    /// one of them with keeps the name and so stays a test signature; any
    /// other rule is not one, whatever it is called.
    pub fn test_signatures(&self) -> &[String] {
        &self.test_signatures
    }

    /// The rules this engine evaluates as they take effect: for every rule
    /// and chain whether it is enabled and what turned it off, its scores,
    /// the tier whose definition is in effect, and the overrides applied to
    /// it with their reasons (`telltale hooks check --rules`). No matchers,
    /// paths or document text.
    pub fn effective_configuration(&self) -> Result<crate::EffectiveConfigurationV1, EngineError> {
        self.pipeline
            .effective_configuration(&self.options)
            .map_err(EngineError::Provenance)
    }

    /// Evaluate `lines` as one hook-journal source of `harness`, the focus lines
    /// among them.
    fn scan<'a>(
        &self,
        client: ClientId,
        window_path: &Path,
        lines: impl Iterator<Item = &'a Line>,
        focus: &[Focus],
    ) -> Result<Evaluation, EngineError> {
        let (scan, scan_ms) = self.scan_window(client, window_path, lines)?;
        if let Some(failure) = scan.failure() {
            return Ok(Evaluation {
                failure_code: Some(failure.code().to_owned()),
                source_failed: true,
                // No acquisition error: projection or evaluation ran out.
                capacity_failed: matches!(
                    failure.acquisition_error(),
                    None | Some(AcquisitionError::ContributionCapacity)
                ),
                ..Evaluation::not_evaluated(focus.len(), scan_ms)
            });
        }
        Ok(evaluation_of(&scan, focus, scan_ms))
    }

    /// Write `lines` to `window_path` and scan them as one hook-journal source of
    /// `harness` (its client and `ClientId::hook_journal_source_id`), returning its result
    /// and how long the scan took. The caller holds the session lock, so the stable path keeps Telltale's source-bound identities
    /// stable across a session. The window holds raw tool input, so it is removed
    /// as soon as the scan returns.
    fn scan_window<'a>(
        &self,
        client: ClientId,
        window_path: &Path,
        lines: impl Iterator<Item = &'a Line>,
    ) -> Result<(SourceScan, u64), EngineError> {
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
            client,
            kind: SourceKind::Jsonl,
            source_id: client.hook_journal_source_id().to_owned(),
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
        Ok((scan, scan_ms))
    }
}

/// What a scan that ran says about its focus lines: their findings, and how much
/// of them was evaluated.
fn evaluation_of(scan: &SourceScan, focus: &[Focus], scan_ms: u64) -> Evaluation {
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

    // One record per action finding, in the same order.
    let actions = scan
        .action_records()
        .into_iter()
        .zip(&scan.action_findings)
        .map(|(record, finding)| TelltaleAction::new(record, finding.destination_facts().cloned()));
    let (focus_records, others): (Vec<_>, Vec<_>) = actions.partition(|action| {
        focus.iter().any(|f| {
            action.record.stage == f.stage
                && action
                    .record
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
    Evaluation {
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
/// piece in flight, which load can overrun. No scan of a projection's lines
/// together starts past it either; the scan of a call whole is not limited by it. Load decides how far a call gets: what the pieces scanned found
/// keeps its force, and the rest goes to `on_unevaluable`.
pub const PIECE_SCAN_LIMIT: Duration = Duration::from_secs(5);

/// The time limits one hook works within. Production code uses the
/// [`Default`], the constants the fields name; tests build a runtime with
/// generous limits to prove what an evaluation covers, and with tiny or spent
/// ones to prove what a call gets when time runs out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// [`RECOVERY_BUDGET`].
    pub recovery: Duration,
    /// [`PIECE_SCAN_LIMIT`].
    pub piece_scan: Duration,
    /// [`crate::hooks::state::SESSION_LOCK_WAIT`].
    pub session_lock_wait: Duration,
    /// [`HOOK_DEADLINE`].
    pub hook_deadline: Duration,
}

/// Time from the start of a hook after which nothing more is waited for: every
/// later wait is cut to what remains of it ([`Limits::within`]), and a call with
/// none left before its evaluation starts is not evaluated. A verdict already
/// evaluated is always recorded and delivered. The hooks that evaluate tool
/// calls are installed with a timeout of 30 s or more; this leaves room before
/// it for one scan already in flight, which is not interrupted, and for the
/// process to exit.
pub const HOOK_DEADLINE: Duration = Duration::from_secs(25);

impl Default for Limits {
    fn default() -> Self {
        Self {
            recovery: RECOVERY_BUDGET,
            piece_scan: PIECE_SCAN_LIMIT,
            session_lock_wait: crate::hooks::state::SESSION_LOCK_WAIT,
            hook_deadline: HOOK_DEADLINE,
        }
    }
}

impl Limits {
    /// These limits, none longer than `remaining`.
    pub fn within(self, remaining: Duration) -> Self {
        Self {
            recovery: self.recovery.min(remaining),
            piece_scan: self.piece_scan.min(remaining),
            session_lock_wait: self.session_lock_wait.min(remaining),
            hook_deadline: self.hook_deadline.min(remaining),
        }
    }
}
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
    limits: Limits,
    /// The slowest rate measured so far, in milliseconds per byte.
    ms_per_byte: f64,
    /// What the call's scans did; the budget spans all of them.
    trace: ScanTrace,
}

impl RecoveryBudget {
    /// The call starts now: call this once the session lock is held, because
    /// the wait for the lock is bounded on its own.
    pub fn start(limits: Limits) -> Self {
        Self {
            started: Instant::now(),
            limits,
            ms_per_byte: 0.0,
            trace: ScanTrace::default(),
        }
    }

    /// What the call's scans did so far.
    pub fn trace(&self) -> &ScanTrace {
        &self.trace
    }

    /// A budget of which `used` is already spent.
    #[cfg(test)]
    pub(crate) fn already_spent(used: Duration) -> Self {
        Self {
            started: Instant::now() - used,
            ..Self::start(Limits::default())
        }
    }

    fn spent(&self) -> bool {
        self.started.elapsed() >= self.limits.recovery
    }

    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Whether another piece of a call past capacity may still be scanned.
    fn pieces_in_time(&self) -> bool {
        self.started.elapsed() < self.limits.piece_scan
    }

    /// Whether a scan of `bytes` should fit in what is left. Twice the forecast,
    /// because lines that match rules cost more than the lines measured so far
    /// and a scan that fails at acquisition ends before the expensive stages.
    fn admits(&self, bytes: usize) -> bool {
        let forecast = Duration::from_secs_f64(self.ms_per_byte * bytes as f64 / 1000.0);
        self.started.elapsed() + forecast * 2 < self.limits.recovery
    }

    fn observe(&mut self, bytes: usize, ms: u64) {
        if bytes >= MIN_MEASURED_BYTES {
            self.ms_per_byte = self.ms_per_byte.max(ms as f64 / bytes as f64);
        }
    }
}

/// What a recovery scan is made of.
/// What [`Engine::evaluate`] scans: the call's `pending` lines (and `focus`,
/// one per pending line) with as much of `history` as Telltale accepts,
/// written to `window_path` as one hook-journal source of `client`.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub client: ClientId,
    pub window_path: &'a Path,
    pub history: &'a [Line],
    pub pending: &'a [Line],
    pub focus: &'a [Focus],
    pub scan: PendingScan,
    /// For a projection past its budget: the line the call is journaled as,
    /// which later calls read as history, and its focus. Scanned with history
    /// after the pieces, when the budget admits it.
    pub journaled: Option<(&'a Line, &'a Focus)>,
}

/// How the pending lines of a [`Request`] may be scanned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingScan {
    /// Whole, with history, and together before one by one: a call, or a
    /// projection within its budget.
    Together,
    /// Each line on its own only: a projection past its budget holds more
    /// than Telltale takes in one scan.
    PiecesOnly,
}

/// How one scan step of a call went: a closed value for its record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    /// Scanned, and Telltale accepted the source.
    Passed,
    /// Scanned, and Telltale failed the source, or for the history scan
    /// quarantined the call's own line.
    Refused,
    /// Not scanned: a projection past its budget goes to its pieces.
    SkippedPiecesOnly,
    /// Not scanned: the recovery budget did not admit it.
    SkippedBudget,
    /// Not scanned: the piece time limit had passed.
    SkippedLate,
    /// Not scanned again: with no history the whole-window scan was this one.
    SameAsWhole,
}

/// What the scans of one call did, for its record: counts, closed values and
/// milliseconds, never content. It spans every evaluation of the call (the
/// call whole, then its projection): counts and times add up, and `whole`
/// `together` and `history` say what the last evaluation did.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ScanTrace {
    /// Variants projected in place of an input Telltale excluded.
    pub variants: usize,
    /// The scan of history and the pending lines together.
    pub whole: Option<StepOutcome>,
    /// The scan of the pending lines together, without history.
    pub together: Option<StepOutcome>,
    /// The scan of history with the line a projection past its budget is
    /// journaled as, after its pieces.
    pub history: Option<StepOutcome>,
    /// Pending lines scanned one by one, of those offered to that loop.
    pub pieces_scanned: usize,
    pub pieces_total: usize,
    /// Pieces Telltale refused, and the failure code of the first.
    pub pieces_refused: usize,
    pub first_refusal: Option<String>,
    pub whole_ms: u64,
    pub together_ms: u64,
    pub pieces_ms: u64,
    pub history_ms: u64,
}

struct Window<'a> {
    client: ClientId,
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

/// Telltale rejects patterns longer than 1,024 bytes; stay under it.
const MAX_PATTERN_BYTES: usize = 1000;

// Pattern text the bundled rules share. A template in rules/*.yaml names one as `{{NAME}}`
// (`RULE_FRAGMENTS`) and the generated rules use the constants themselves, so no rule
// carries its own copy.
//
// A writing program at command position, not `--rm` or a word after other whitespace, in
// the same command as the path unless it is an interpreter one-liner, whose program can
// hold `;`, and a file-writing redirection, not `2>` or `>&2`. An interpreter counts only
// with a flag other than `-m`: `python3 x.py <path>` hands its path to a file whose content
// no rule can see anyway. `HARMLESS` is what cannot write, whatever it names.
const COMMAND_START: &str = r#"(?:^|[;&|({`\n]|\s-(?:exec|ok)(?:dir)?\s)\s*(?:\\?(?:\S*[\\/])?(?:sudo|doas|env|command|builtin|exec|nohup|time|nice|timeout|xargs|busybox|eval|iex|if|then|do|else|!|[^\s=]+=\S*|-\S+(?:\s+\S+)?|/[A-Za-z]|[0-9]\S*|(?:ba|z|da|k)?sh|cmd(?:\.exe)?|(?:powershell|pwsh)(?:\.exe)?)\s+["']?)*\\?(?:\S*[\\/])?"#;
macro_rules! posix_writers {
    () => {
        r#"(?:(?:rm|mv|cp|dd|install|truncate|shred|unlink|chmod|chown|chattr|ln|tee|eval)\s|sed\s+(?:[^;&|]*\s)?-(?:[a-z]*i|-in-place))"#
    };
}
macro_rules! windows_writers {
    () => {
        r#"(?:del|erase|copy|move|ren|rename|rd|rmdir|(?:Remove|Move|Copy|Rename|New)-Item|(?:Set|Add|Clear)-Content|Out-File|ri|mi|cpi|sc|ac)\s"#
    };
}
const POSIX_WRITERS: &str = posix_writers!();
const WINDOWS_WRITERS: &str = windows_writers!();
const WRITERS: &str = concat!("(?:", posix_writers!(), "|", windows_writers!(), ")");
const INTERPRETERS: &str = r#"(?:python[0-9.]*\s+-[^mvVh\s-]|(?:perl|node|ruby|php)\s+-[^vVh\s-])"#;
const SEGMENT: &str = r#"(?:[^;&|\n]|\\\n|'[^']*'|"[^"]*")*"#;
const REDIRECT_TO: &str = r#"(?:^|[^0-9&>])>{1,2}\|?\s*["']?"#;
const REDIRECT_SKIP: &str = r#"[^\s;&|<>"']*?"#;
// The plain reads at the end of `HARMLESS`, which the exclusions that let less through
// also allow.
macro_rules! readers {
    () => {
        r#"(?:(?:(?:cat|head|tail|grep|jq|cut|wc|ls|stat|file|diff|sha256sum|type|echo|printf|test|tr|Get-Content|gc|git +(?:add|commit)|gh +(?:pr|issue))(?: +(?:(?:--[a-z-]+=)?(?:'(?:[^-'‘-‛]-*)*'|"(?:(?:\\?[^-"`$\\“-„]|\\\\|\$\{[A-Z_]+\}|\$[A-Z_a-z])-*)*")|(?:[!%*-,.-:=?-\[\]-_a-{}~]|-+[!*-,.-:=?-\[\]-_a-{}~]|\$[A-Z_a-z])*-*))*|git +(?:diff|log|show|blame|status|grep|ls-files|ls-tree)(?: +(?:'(?:[^-'‘-‛]-*)*'|[!*-:=?-\[\]-_a-z~]*))*|sed +-n +(?:'[^'weW‘-‛]*p'|[0-9,]+p)[^-;&|<>`$()'"\n\r\\]*|(?:sort|uniq)(?: +-[a-np-z]+)* *|python3? +-m +json\.tool *)(?:2>/dev/null *)?(?:[|\n]\s*|(?: +#[^\n\r]*)?$))*"#
    };
}
const READERS: &str = readers!();
const HARMLESS: &str = concat!(
    r#"^\s*(?:(?:[-A-Za-z0-9_][-.A-Za-z0-9_]* *)+[;&]+\s*)*(?:(?:git +add|test|\[) +[ !*-:=?-\[\]-_a-{}~]*[;&]+\s*)*(?:(?:git +commit|gh +(?:pr|issue))(?: +(?:"(?:(?:\\?[^-"\\;&|<>`$()\n\r]|\\["\\])-*)*"|[!*-:=?-\[\]-_a-{}~]*))*|(?:(?:cd|(?:python3?|node) +[A-Z_a-z0-9./~][!*-:=?-\[\]-_a-{}~]*)(?: +(?:"(?:(?:\\?[^-"`$\\“-„]|\$[A-Z_a-z])-*)*"|(?:[!*-:=?-\[\]-_a-{}~]|\$[A-Z_a-z])*))*(?:[;&|]+\s*|$))*"#,
    readers!(),
    ")$"
);
// The exclusions of rules about what a command says rather than what it writes:
// `git commit` and `gh pr` text, and a harness launch or uninstall that only prints its
// version or help, or previews.
const TEXT_ONLY: &str = r#"^\s*(?:git +add [ !*-:=?-\[\]-_a-{}~]*[;&]+\s*)?(?:git +commit|gh +(?:pr|issue))(?:(?: +(?:(?:--[a-z-]+=)?(?:'(?:[^-'‘-‛]-*)*'|"(?:(?:\\?[^-"`$\\“-„]|\\\\|\$\{[A-Z_]+\}|\$[A-Z_a-z])-*)*")|(?:[!%*-,.-:=?-\[\]-_a-{}~]|-+[!*-,.-:=?-\[\]-_a-{}~]|\$[A-Z_a-z])*-*))*|(?: +(?:"(?:(?:\\?[^-"\\;&|<>`$()\n\r]|\\["\\])-*)*"|[!*-:=?-\[\]-_a-{}~]*))*)$"#;
const VERSION_OR_HELP: &str =
    r#"^(?:(?:-y|--yes|[A-Za-z0-9_./:=@~+][-A-Za-z0-9_./:=@~+]*) +)*(?:--version|-V|--help|-h) *$"#;
const DRY_RUN_OR_HELP: &str = r#"^(?:(?:-y|--yes|(?:--scope[ =])?[A-Za-z0-9_./:=@~+][-A-Za-z0-9_./:=@~+]*) +)*(?:--dry-run|--version|-V|--help|-h)(?: +(?:--scope[ =])?[A-Za-z0-9_./:=@~+][-A-Za-z0-9_./:=@~+]*)* *$"#;

// A harness launch: the program names an agent starts one by, after an optional quote
// or directory, to the end of the word; the words that can stand before it in an
// inline launch; and the variables that locate the Telltale config root, the hooks
// state, or the home both derive from. The launcher, package and hooks
// subcommand lists are generated from the hooks registry inside
// `rule_fragments()`.
// A launcher that takes a grant line, after an optional quote or directory, with an
// option or subcommand that resumes or continues an existing session (spellings from
// each harness's own help; the two launchers with options share one list). The words
// before the option are walked up to a standalone `--`, after which nothing is an
// option. It follows `COMMAND_START`.
const SESSION_RESUME: &str = r##"(?:["'](?:[^"'\n]*[\\/])?|[^\s;&|"']*[\\/])?(?:(?:claude|copilot)(?:\.exe|\.cmd)?["']?(?:[ \t]+attach|(?:[ \t]+(?:-?(?:'[^']*'|"[^"]*"|[^\s;&|'"-])(?:'[^']*'|"[^"]*"|[^\s;&|'"])*|--(?:'[^']*'|"[^"]*"|[^\s;&|'"])+|-))*[ \t]+["']?(?:--continue|--resume|--from-pr|--teleport|--session-id|(?-i:-[cr])))|codex(?:\.exe|\.cmd)?["']?(?:[ \t]+-\S*(?:[ \t]+[^-\s;&|]\S*)?)*(?:[ \t]+e(?:xec)?(?:[ \t]+-\S*(?:[ \t]+[^-\s;&|]\S*)?)*)?[ \t]+(?:resume|fork|queue))(?:[\s=;&|)`"']|$)"##;
const LAUNCH_WRAPPERS: &str = r#"(?:env|exec|nohup|sudo|command|time|setsid|i?nice|stdbuf|timeout|-\S+|[0-9]\S*|(?:ba|z)?sh\s+-l?c)"#;
const CONFIG_LOCATION_VARS: &str =
    r#"(?:XDG_(?:CONFIG|STATE)_HOME|HOME|USERPROFILE|(?:LOCAL)?APPDATA)"#;

// The fail-safe rules: a writer word anywhere, matched without a list of what can wrap
// it, and the words that work on what they are handed when the path comes first.
const WRITER_ANYWHERE: &str = r#"(?:(?:^|[^-A-Za-z0-9_.])(?:rm|rmdir|mv|cp|dd|ln|tee|tar|rsync|touch|truncate|unlink|shred|trash|gio|install|ch(?:mod|own|attr)|xargs|eval|checkout|reset|restore|clean|del|erase|copy|move|ren(?:ame)?|rd|ri|mi|cpi|sc|ac|(?:Remove|Move|Copy|Rename|New)-Item|(?:Set|Add|Clear)-Content|Out-File|rmtree|rmSync|rm_rf|rimraf|remove_dir_all|removeSync)\b|(?:^|[^-2&=])>(?:[^&]|$)|\bsed\b[^;&|\n]*-(?:[a-z]*i|-in)|\B-delete\b|(?:python\S*|perl|node|ruby|php)\s+-[^mvVh\s-])"#;
const WRITER_AFTER: &str = r#"(?:(?:^|[^-A-Za-z0-9_.])(?:rm|rmdir|rimraf|mv|cp|ln|dd|tee|truncate|unlink|shred|trash|ch(?:mod|own)|xargs|del|move|ri|mi|Remove-Item|Move-Item)\b|(?:^|[^-2&=])>(?:[^&]|$)|\B-delete\b|\bsed\b[^;&|\n]*-(?:[a-z]*i|-in)|(?:python\S*|perl|node|ruby|php)\s+-[^mvVh\s-])"#;

/// Every shared text a rule template can name, by the name it writes as `{{NAME}}`.
/// Harness launcher and package lists are built once from the hooks registry.
fn rule_fragments() -> &'static [(&'static str, String)] {
    static FRAGMENTS: std::sync::LazyLock<Vec<(&'static str, String)>> = std::sync::LazyLock::new(
        || {
            let launcher_names = crate::hooks::harness::all_harness_launchers()
                .into_iter()
                .map(regex::escape)
                .collect::<Vec<_>>()
                .join("|");
            let harness_launcher_names = format!(r"(?:{launcher_names})");
            let harness_launcher = format!(
                r#"(?:["'](?:[^"'\n]*[\\/])?|[^\s;&|"']*[\\/])?(?:{launcher_names})(?:\.exe|\.cmd)?["']?(?:[\s;&|)`]|$)"#
            );
            let package_names = crate::hooks::harness::all_harness_packages()
                .into_iter()
                .map(regex::escape)
                .collect::<Vec<_>>()
                .join("|");
            let harness_packages = format!(r"(?:{package_names})");
            let harness_names = crate::hooks::harness::Harness::ALL
                .iter()
                .map(|harness| regex::escape(harness.name()))
                .collect::<Vec<_>>()
                .join("|");
            let harness_names = format!(r"(?:{harness_names})");
            vec![
                ("COMMAND_START", COMMAND_START.to_owned()),
                ("WRITERS", WRITERS.to_owned()),
                ("POSIX_WRITERS", POSIX_WRITERS.to_owned()),
                ("WINDOWS_WRITERS", WINDOWS_WRITERS.to_owned()),
                ("INTERPRETERS", INTERPRETERS.to_owned()),
                ("SEGMENT", SEGMENT.to_owned()),
                ("REDIRECT_TO", REDIRECT_TO.to_owned()),
                ("REDIRECT_SKIP", REDIRECT_SKIP.to_owned()),
                ("HARMLESS", HARMLESS.to_owned()),
                ("READERS", READERS.to_owned()),
                ("TEXT_ONLY", TEXT_ONLY.to_owned()),
                ("VERSION_OR_HELP", VERSION_OR_HELP.to_owned()),
                ("DRY_RUN_OR_HELP", DRY_RUN_OR_HELP.to_owned()),
                ("WRITER_ANYWHERE", WRITER_ANYWHERE.to_owned()),
                ("WRITER_AFTER", WRITER_AFTER.to_owned()),
                ("HARNESS_LAUNCHER_NAMES", harness_launcher_names),
                ("HARNESS_LAUNCHER", harness_launcher),
                ("HARNESS_PACKAGES", harness_packages),
                ("HARNESS_NAMES", harness_names),
                ("LAUNCH_WRAPPERS", LAUNCH_WRAPPERS.to_owned()),
                ("SESSION_RESUME", SESSION_RESUME.to_owned()),
                ("CONFIG_LOCATION_VARS", CONFIG_LOCATION_VARS.to_owned()),
            ]
        },
    );
    &FRAGMENTS
}

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
    /// Paths matched by their last bytes only; a spelling from the user's home
    /// as `~` and the rest of the path.
    pub reduced: Vec<String>,
    /// Paths with no generated rule because they are not UTF-8.
    pub unrepresentable: Vec<String>,
}

impl GeneratedCoverage {
    /// `path`, or a spelling of it, is matched by its last bytes only.
    fn report_reduced(&mut self, path: &str) {
        if !self.reduced.iter().any(|known| known == path) {
            self.reduced.push(path.to_owned());
        }
    }
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
/// if that does not fit one rule, and its spelling from the user's home, reduced
/// the same way. Nothing for a path with nothing in it to match: that would match
/// everything.
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
    let (literal, whole) = last_bytes(&pieces, limit);
    if !whole {
        coverage.report_reduced(text);
    }
    let mut fragments = vec![literal + suffix];
    let home = crate::hooks::config::user_home();
    let rest = home
        .as_deref()
        .and_then(Path::to_str)
        .and_then(|home| text.strip_prefix(home.trim_end_matches(is_separator)))
        .filter(|rest| rest.is_empty() || rest.starts_with(is_separator));
    if let Some(rest) = rest {
        let spelled = format!("(?:{HOME_SPELLINGS})");
        let pieces = path_pieces(rest);
        let fragment = match last_bytes(&pieces, limit.saturating_sub(spelled.len())) {
            (rest, true) => spelled + &rest,
            // Matched by the last bytes of what follows the home, which a command
            // written from the home contains. The literal path's last bytes can
            // hold characters of the home that such a command does not.
            _ => {
                coverage.report_reduced(&format!("~{rest}"));
                last_bytes(&pieces, limit).0
            }
        };
        fragments.push(fragment + suffix);
    }
    fragments
}

/// The last of `pieces` that fit in `limit` bytes, joined, and whether that is
/// all of them.
fn last_bytes(pieces: &[String], limit: usize) -> (String, bool) {
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
    let whole = kept.len() == pieces.len();
    kept.reverse();
    (kept.concat(), whole)
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
    let files = |home: &crate::hooks::config::HarnessHome| {
        home.hook_files.replace("{{NAME_END}}", NAME_END)
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

/// A Rule v2 file matching writes to, and modifying commands naming, one
/// family's paths. Windows paths compare case-insensitively.
fn family_document(family: &Family, coverage: &mut GeneratedCoverage) -> Option<String> {
    family_document_with_case(family, coverage, cfg!(windows))
}

fn family_document_with_case(
    family: &Family,
    coverage: &mut GeneratedCoverage,
    case_insensitive: bool,
) -> Option<String> {
    let rules = family_rules(family);
    if rules.is_empty() {
        return None;
    }
    coverage.rules += rules.len();
    let documents = rules
        .iter()
        .map(|rule| rule.to_yaml(case_insensitive))
        .collect::<Vec<_>>();
    Some(documents.join("---\n"))
}

fn family_rules(family: &Family) -> Vec<GeneratedRule> {
    path_rules(family)
        .into_iter()
        .chain(failsafe_rules(family))
        .collect()
}

/// One generated rule, before it is written out.
struct GeneratedRule {
    id: String,
    title: String,
    score: u8,
    selection: Selection,
}

impl GeneratedRule {
    fn new(id: String, title: String, score: u8, selection: Selection) -> Self {
        Self {
            id,
            title,
            score,
            selection,
        }
    }

    /// The rule as one Rule v2 document.
    fn to_yaml(&self, case_insensitive: bool) -> String {
        let Self {
            id, title, score, ..
        } = self;
        // YAML single-quoted scalars escape a quote by doubling it.
        let quote = |regex: &str| regex.replace('\'', "''");
        let flags = if case_insensitive { "|re|i" } else { "|re" };
        let detection = match &self.selection {
            Selection::Written(regex) => format!(
                "    selection:\n        - tool.written_path{flags}: '{}'\n    condition: selection\n",
                quote(regex)
            ),
            Selection::Command(regex) => format!(
                "    selection_command:\n        tool.command{flags}|recorded_exclusion: '{}'\n    \
                 filter_command:\n        tool.command{flags}|recorded_exclusion: '{}'\n    \
                 condition: selection_command and not filter_command\n",
                quote(regex),
                quote(HARMLESS)
            ),
        };
        let severity = if *score >= 90 { "high" } else { "medium" };
        let name = format!("{HOST_RULE_ID_PREFIX}{id}");
        let uuid = generated_rule_uuid(&name);
        format!(
            "title: {title}\nid: {uuid}\nname: {name}\ntaxonomy: telltale\nstatus: stable\n\
             logsource:\n    product: ai_agent\n    category: tool_activity\n\
             detection:\n{detection}level: {severity}\ntelltale:\n    \
             category: {HOST_RULE_CATEGORY}\n    score: {score}\n    explanation: {title}.\n    \
             tags: [self-protection, hooks, defense-evasion]\n"
        )
    }
}

/// The Rule v2 `id` of a generated rule. Rule v2 ids are UUIDv4s written once
/// and committed, but these rules are generated per installation, so the id is
/// derived from the rule name instead: a SHA-256 of the name with the UUIDv4
/// version and variant bits set. The same name always gets the same id, so a
/// generated rule keeps its catalog identity across runs and installations.
fn generated_rule_uuid(name: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::new()
        .chain_update(b"telltale-hooks:generated-rule-uuid:v1\0")
        .chain_update(name.as_bytes())
        .finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// What may stand before a family's path: anything, or for a family whose paths can
/// be told from longer ones, only what cannot continue a longer path.
fn path_anchor(family: &Family) -> String {
    if family.anchored {
        format!("(?:^|IFS|{BEFORE_PATH})")
    } else {
        String::new()
    }
}

/// A rule's number among the chunks of one family: none for the first.
fn chunk_suffix(index: usize) -> String {
    match index {
        0 => String::new(),
        _ => format!("_{}", index + 1),
    }
}

/// Per chunk of a family's paths: a write to one, a writing program or a redirection
/// aimed at one, and, where the family has them, a path named before a writing
/// program and any mention at all.
fn path_rules(family: &Family) -> Vec<GeneratedRule> {
    let Family {
        prefix, subject, ..
    } = family;
    let anchor = path_anchor(family);
    let (writer, redirect) = if family.anchored {
        (
            format!("(?:{WRITERS}(?:{SEGMENT}{BEFORE_PATH})?|{INTERPRETERS}.*{BEFORE_PATH})"),
            REDIRECT_TO.to_owned(),
        )
    } else {
        (
            format!("(?:{WRITERS}{SEGMENT}|{INTERPRETERS}.*)"),
            format!("{REDIRECT_TO}{REDIRECT_SKIP}"),
        )
    };
    let mut rules = Vec::new();
    for (index, chunk) in chunk_fragments(&family.fragments).iter().enumerate() {
        let n = chunk_suffix(index);
        let pattern = format!("(?:{})", chunk.join("|"));
        let mention = format!("{anchor}{pattern}");
        rules.push(GeneratedRule::new(
            format!("{prefix}_write{n}"),
            format!("Agent writes {subject}"),
            90,
            Selection::Written(mention.clone()),
        ));
        rules.push(GeneratedRule::new(
            format!("{prefix}_command{n}"),
            format!("Agent command modifies {subject}"),
            90,
            Selection::Command(format!("(?s){COMMAND_START}{writer}{pattern}")),
        ));
        if family.reversible {
            rules.push(GeneratedRule::new(
                format!("{prefix}_command_reverse{n}"),
                format!("Agent command names {subject} and then runs a writing program"),
                90,
                Selection::Command(format!(
                    "(?s){mention}.*{COMMAND_START}(?:{WRITERS}|{INTERPRETERS})"
                )),
            ));
        }
        rules.push(GeneratedRule::new(
            format!("{prefix}_redirect{n}"),
            format!("Agent command redirects into {subject}"),
            90,
            Selection::Command(format!("(?s){redirect}{pattern}")),
        ));
        if family.reference {
            rules.push(GeneratedRule::new(
                format!("{prefix}_reference{n}"),
                format!("Agent command references {subject}"),
                60,
                Selection::Command(mention),
            ));
        }
    }
    rules
}

/// Per chunk of a family's fail-safe paths: a writer word on either side of one.
fn failsafe_rules(family: &Family) -> Vec<GeneratedRule> {
    let Family {
        prefix, subject, ..
    } = family;
    let anchor = path_anchor(family);
    let mut rules = Vec::new();
    for (index, chunk) in chunk_fragments(&family.failsafe).iter().enumerate() {
        let n = chunk_suffix(index);
        let mention = format!("{anchor}(?:{})", chunk.join("|"));
        // One rule per direction: a path can be long and the budget holds it once. A
        // writer on both sides of it adds up to a deny, which is no loss.
        rules.push(GeneratedRule::new(
            format!("{prefix}_failsafe{n}"),
            format!("Agent command names a writing program and then {subject}"),
            60,
            Selection::Command(format!("(?s){WRITER_ANYWHERE}.*{mention}")),
        ));
        rules.push(GeneratedRule::new(
            format!("{prefix}_failsafe_reverse{n}"),
            format!("Agent command names {subject} and then a writing program"),
            60,
            Selection::Command(format!("(?s){mention}.*{WRITER_AFTER}")),
        ));
    }
    rules
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
/// The host rule documents, the grant-protection document while `grants` are
/// on, and the generated rules for `protected_paths`, parsed and labelled by
/// source.
fn self_protection_documents(
    protected_paths: &[PathBuf],
    grants: bool,
    generated: &mut GeneratedCoverage,
) -> Result<Vec<(String, LoadedRules)>, EngineError> {
    let host = host_rule_documents()
        .iter()
        .chain(grants.then(grant_protection_document))
        .map(|(name, document)| (format!("hooks:{name}"), document.as_str()));
    let own = generated_documents(protected_paths, generated);
    let own = own
        .iter()
        .enumerate()
        .map(|(index, document)| (format!("hooks:generated#{index}"), document.as_str()));
    host.chain(own)
        .map(|(source, document)| {
            LoadedRules::parse(document)
                .map(|rules| (source, rules))
                .map_err(|error| EngineError::Build(PipelineError::Compilation(error)))
        })
        .collect()
}

/// Whether the policy at `path`, compiled over the host and generated rules
/// alone, leaves any of them out. Decided by effect, so it follows whatever
/// the policy can select by. A policy that does not parse is not reported
/// here: building the rules fails on it.
pub fn policy_drops_host_rule(path: &Path, grants: bool, protected_paths: &[PathBuf]) -> bool {
    let Some(policy) = read(path)
        .ok()
        .and_then(|text| serde_yaml::from_str::<telltale_rules::RulePolicy>(&text).ok())
    else {
        return false;
    };
    let Ok(documents) =
        self_protection_documents(protected_paths, grants, &mut GeneratedCoverage::default())
    else {
        return false;
    };
    let host = host_rule_definitions(&documents);
    LoadedRules::from_definitions(host.clone())
        .and_then(|rules| rules.compile(Some(&policy)))
        .is_ok_and(|compiled| dropped_host_rule(&host, &compiled).is_some())
}

/// The ID of the first enabled host rule that `compiled` (the rules after the
/// policy) does not carry.
fn dropped_host_rule<'a>(
    host: &'a [LoadedDefinition],
    compiled: &telltale_rules::CompiledRuleSet,
) -> Option<&'a str> {
    let kept = compiled
        .summaries()
        .into_iter()
        .map(|summary| summary.id)
        .collect::<std::collections::BTreeSet<_>>();
    host.iter()
        .find(|rule| rule.enabled() && !kept.contains(rule.id()))
        .map(LoadedDefinition::id)
}

/// The host rules as their documents define them, document defaults applied.
fn host_rule_definitions(documents: &[(String, LoadedRules)]) -> Vec<LoadedDefinition> {
    documents
        .iter()
        .flat_map(|(_, rules)| rules.definitions())
        .filter(|definition| definition.kind() == DefinitionKind::Rule)
        .cloned()
        .collect()
}

/// The ID of the first host rule that `merged` (the rules after user content
/// and overrides) does not carry exactly as defined. The rules merge adds
/// definitions at a tier that can replace none and applies override files
/// after them, so user content must not have reached any of these.
fn altered_host_rule<'a>(host: &'a [LoadedDefinition], merged: &LoadedRules) -> Option<&'a str> {
    host.iter()
        .find(|rule| merged.get(rule.id()) != Some(*rule))
        .map(LoadedDefinition::id)
}

fn read(path: &Path) -> Result<String, EngineError> {
    crate::hooks::state::read_operator_input(path)
        .map_err(|error| EngineError::Content(path.to_owned(), error))
}

#[cfg(test)]
mod tests;
