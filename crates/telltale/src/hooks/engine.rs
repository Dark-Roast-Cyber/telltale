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
    AcquisitionError, ActionRecordV1, DetailedEvaluationOptions, EvaluationCompletion,
    ObservationStage, Pipeline, PipelineError, Source, SourceCoverage, SourceKind, SourceScan,
};

use telltale_rules::{DefinitionKind, LoadedDefinition, LoadedRules};

use crate::ClientId;
use crate::hooks::config::{HOST_RULE_CATEGORY, HOST_RULE_ID_PREFIX, RuleContent};
use crate::hooks::harness::{Harness, HostRules};
use crate::hooks::journal::Line;

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
            .and_then(|(name, _)| RULE_FRAGMENTS.iter().find(|(known, _)| *known == name));
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
    /// Override entries left out because they name a hooks rule that is not
    /// loaded (`RuleResolution::skipped_overrides`).
    skipped_overrides: Vec<String>,
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
    pub fn new(rules: &RuleContent, protected_paths: &[PathBuf]) -> Result<Self, EngineError> {
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
            self_protection_documents(protected_paths, &mut generated)?
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
        if rules.test_signatures {
            let (name, document) = test_signature_document();
            let parsed = LoadedRules::parse(document)
                .map_err(|error| EngineError::Build(PipelineError::Compilation(error)))?;
            replaceable.push((format!("hooks:{name}"), parsed));
        }
        let resolution = crate::rule_resolution::resolve_rule_set_with_host(
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
        let skipped_overrides = resolution.skipped_overrides.clone();
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
    /// names a hooks rule this engine does not load: a self-protection rule
    /// while those are off, or a name no such rule has
    /// (`telltale hooks check`).
    pub fn skipped_overrides(&self) -> &[String] {
        &self.skipped_overrides
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
// state, or the home both derive from.
const HARNESS_LAUNCHER: &str = r#"(?:["'](?:[^"'\n]*[\\/])?|[^\s;&|"']*[\\/])?(?:claude|codex|copilot|opencode|cursor|gemini)(?:\.exe|\.cmd)?["']?(?:[\s;&|)`]|$)"#;
const LAUNCH_WRAPPERS: &str = r#"(?:env|exec|nohup|sudo|command|time|setsid|i?nice|stdbuf|timeout|-\S+|[0-9]\S*|(?:ba|z)?sh\s+-l?c)"#;
const CONFIG_LOCATION_VARS: &str =
    r#"(?:XDG_(?:CONFIG|STATE)_HOME|HOME|USERPROFILE|(?:LOCAL)?APPDATA)"#;

// The fail-safe rules: a writer word anywhere, matched without a list of what can wrap
// it, and the words that work on what they are handed when the path comes first.
const WRITER_ANYWHERE: &str = r#"(?:(?:^|[^-A-Za-z0-9_.])(?:rm|rmdir|mv|cp|dd|ln|tee|tar|rsync|touch|truncate|unlink|shred|trash|gio|install|ch(?:mod|own|attr)|xargs|eval|checkout|reset|restore|clean|del|erase|copy|move|ren(?:ame)?|rd|ri|mi|cpi|sc|ac|(?:Remove|Move|Copy|Rename|New)-Item|(?:Set|Add|Clear)-Content|Out-File|rmtree|rmSync|rm_rf|rimraf|remove_dir_all|removeSync)\b|(?:^|[^-2&=])>(?:[^&]|$)|\bsed\b[^;&|\n]*-(?:[a-z]*i|-in)|\B-delete\b|(?:python\S*|perl|node|ruby|php)\s+-[^mvVh\s-])"#;
const WRITER_AFTER: &str = r#"(?:(?:^|[^-A-Za-z0-9_.])(?:rm|rmdir|rimraf|mv|cp|ln|dd|tee|truncate|unlink|shred|trash|ch(?:mod|own)|xargs|del|move|ri|mi|Remove-Item|Move-Item)\b|(?:^|[^-2&=])>(?:[^&]|$)|\B-delete\b|\bsed\b[^;&|\n]*-(?:[a-z]*i|-in)|(?:python\S*|perl|node|ruby|php)\s+-[^mvVh\s-])"#;

/// Every shared text a rule template can name, by the name it writes as `{{NAME}}`.
const RULE_FRAGMENTS: &[(&str, &str)] = &[
    ("COMMAND_START", COMMAND_START),
    ("WRITERS", WRITERS),
    ("POSIX_WRITERS", POSIX_WRITERS),
    ("WINDOWS_WRITERS", WINDOWS_WRITERS),
    ("INTERPRETERS", INTERPRETERS),
    ("SEGMENT", SEGMENT),
    ("REDIRECT_TO", REDIRECT_TO),
    ("REDIRECT_SKIP", REDIRECT_SKIP),
    ("HARMLESS", HARMLESS),
    ("READERS", READERS),
    ("TEXT_ONLY", TEXT_ONLY),
    ("VERSION_OR_HELP", VERSION_OR_HELP),
    ("DRY_RUN_OR_HELP", DRY_RUN_OR_HELP),
    ("WRITER_ANYWHERE", WRITER_ANYWHERE),
    ("WRITER_AFTER", WRITER_AFTER),
    ("HARNESS_LAUNCHER", HARNESS_LAUNCHER),
    ("LAUNCH_WRAPPERS", LAUNCH_WRAPPERS),
    ("CONFIG_LOCATION_VARS", CONFIG_LOCATION_VARS),
];

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
/// The host rule documents and the generated rules for `protected_paths`,
/// parsed and labelled by source.
fn self_protection_documents(
    protected_paths: &[PathBuf],
    generated: &mut GeneratedCoverage,
) -> Result<Vec<(String, LoadedRules)>, EngineError> {
    let host = host_rule_documents()
        .iter()
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
pub fn policy_drops_host_rule(path: &Path, protected_paths: &[PathBuf]) -> bool {
    let Some(policy) = read(path)
        .ok()
        .and_then(|text| serde_yaml::from_str::<telltale_rules::RulePolicy>(&text).ok())
    else {
        return false;
    };
    let Ok(documents) =
        self_protection_documents(protected_paths, &mut GeneratedCoverage::default())
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

    /// Every placeholder in a template names a fragment, sits in a single-quoted value
    /// (the quoting `expand_fragments` writes), and none is left once expanded. Every
    /// fragment is named somewhere.
    #[test]
    fn every_rule_template_placeholder_is_a_known_fragment() {
        let placeholder = regex::Regex::new(r"\{\{([A-Z][A-Z0-9_]*)\}\}").unwrap();
        let quoted = regex::Regex::new(r"^\s*(?:- )?[a-z_.|]+: '.*'$").unwrap();
        let mut named = std::collections::BTreeSet::new();
        for (name, template) in super::host_rule_templates() {
            for line in template.lines() {
                for found in placeholder.captures_iter(line) {
                    let fragment = found.get(1).unwrap().as_str();
                    assert!(
                        super::RULE_FRAGMENTS
                            .iter()
                            .any(|(known, _)| *known == fragment),
                        "{name}: {fragment}"
                    );
                    assert!(
                        quoted.is_match(line),
                        "{name}: {fragment} outside a quoted value"
                    );
                    named.insert(fragment);
                }
            }
        }
        for (name, document) in super::host_rule_documents() {
            assert!(!placeholder.is_match(document), "{name}");
        }
        let unnamed: Vec<&str> = super::RULE_FRAGMENTS
            .iter()
            .map(|(fragment, _)| *fragment)
            .filter(|fragment| !named.contains(fragment))
            .collect();
        assert!(unnamed.is_empty(), "{unnamed:?}");
    }

    /// An exclusion lets commands through its rule, so none is written out by hand: each
    /// is built from the shared texts, and a change to one reaches every rule that uses it.
    #[test]
    fn every_exclusion_is_built_from_shared_text() {
        let mut filters = 0;
        for (name, template) in super::host_rule_templates() {
            let mut lines = template.lines();
            while let Some(line) = lines.next() {
                if line.trim().starts_with("filter_") {
                    filters += 1;
                    let value = lines.next().unwrap_or_default();
                    assert!(value.contains("{{"), "{name}: {value}");
                }
            }
        }
        assert!(filters > 0);
    }

    /// Every generated family, with written-path and command rules, the 90- and
    /// 60-point shapes, reverse, reference and fail-safe rules and numbered
    /// chunks, loads and compiles without notices, case-sensitive (Unix) and
    /// case-insensitive (Windows).
    #[test]
    fn generated_rule_documents_load_and_compile_in_every_shape() {
        use std::path::PathBuf;
        use telltale_rules::load_rule_set_from_documents;
        let mut coverage = super::GeneratedCoverage::default();
        let many: Vec<PathBuf> = (0..12)
            .map(|i| PathBuf::from(format!("/srv/{}/rules-{i}.yaml", "x".repeat(150))))
            .collect();
        let homes: Vec<crate::hooks::config::HarnessHome> = crate::hooks::harness::Harness::ALL
            .iter()
            .filter_map(|harness| harness.adapter().home)
            .map(|home| crate::hooks::config::HarnessHome {
                variable: home.variable,
                hook_files: home.hook_files,
                path: PathBuf::from(format!("/srv/synthetic-home/{}", home.variable)),
            })
            .collect();
        assert!(!homes.is_empty());
        let [home_files, home_dirs] = super::harness_home_families(&homes, &mut coverage);
        let families = [
            super::own_state_family(
                &[
                    PathBuf::from("/srv/tth/state"),
                    PathBuf::from("/srv/tth/it's here/telemetry.jsonl"),
                ],
                &mut coverage,
            ),
            super::own_state_family(&many, &mut coverage),
            home_files,
            home_dirs,
            super::installed_binary_family(
                Some(std::path::Path::new("/srv/synthetic/bin/telltale")),
                &mut coverage,
            ),
        ];
        let mut shapes = std::collections::BTreeSet::new();
        for family in &families {
            for case_insensitive in [false, true] {
                let v2 = super::family_document_with_case(
                    family,
                    &mut super::GeneratedCoverage::default(),
                    case_insensitive,
                )
                .unwrap();
                let v2_rules = load_rule_set_from_documents(&[&v2], None).unwrap();
                assert!(v2_rules.notices().is_empty());
                let v2 = v2_rules.compatibility_export();
                assert!(!v2.rules().is_empty(), "{}", family.prefix);
                for rule in v2.rules() {
                    shapes.insert((
                        rule.matchers[0].target.clone(),
                        rule.score,
                        rule.matchers[0].regex.starts_with("(?i:"),
                    ));
                }
                telltale_detect::v2::compile_rule_v1(&v2).unwrap();
            }
        }
        // Both selections, both scores and both case modes were covered.
        for target in ["command", "written_path"] {
            for case_insensitive in [false, true] {
                assert!(shapes.contains(&(target.to_owned(), 90, case_insensitive)));
            }
        }
        assert!(shapes.contains(&("command".to_owned(), 60, false)));
        let names = families
            .iter()
            .flat_map(super::family_rules)
            .map(|rule| rule.id)
            .collect::<Vec<_>>();
        assert!(names.iter().any(|name| name.ends_with("_2")));
        assert!(names.iter().any(|name| name.contains("failsafe")));
        assert!(names.iter().any(|name| name.contains("reverse")));
    }

    #[test]
    fn a_generated_rule_uuid_is_a_v4_shaped_uuid_derived_from_its_name() {
        let first = super::generated_rule_uuid("tth.tamper.own_state_write");
        assert_eq!(
            first,
            super::generated_rule_uuid("tth.tamper.own_state_write")
        );
        assert_ne!(
            first,
            super::generated_rule_uuid("tth.tamper.own_state_write_2")
        );
        let bytes = first.as_bytes();
        assert_eq!(bytes.len(), 36);
        assert_eq!((bytes[14], bytes[8], bytes[13]), (b'4', b'-', b'-'));
        assert!(matches!(bytes[19], b'8' | b'9' | b'a' | b'b'));
    }

    #[test]
    fn expansion_quotes_a_fragment_and_keeps_other_braces() {
        let expanded = super::expand_fragments("a: '{{SEGMENT}}' # {{}} {{NOT_A_FRAGMENT}}");
        assert_eq!(
            expanded,
            format!(
                "a: '{}' # {{{{}}}} {{{{NOT_A_FRAGMENT}}}}",
                super::SEGMENT.replace('\'', "''")
            )
        );
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
        for (_, document) in super::host_rule_documents() {
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
            let id = format!("name: tth.tamper.{rule}");
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

    /// A rules file that is not listed would silently never load. The
    /// self-protection documents and the test signatures are the two lists.
    #[test]
    fn every_bundled_rules_file_is_a_listed_document() {
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
        let mut listed: Vec<(String, String)> = super::host_rule_templates()
            .into_iter()
            .chain([super::test_signature_document()])
            .map(|(name, content)| (name.to_owned(), content.to_owned()))
            .collect();
        listed.sort();
        assert_eq!(listed, files);
    }

    /// User content is kept out of the host rules by namespace, so no host or
    /// generated rule may be outside it.
    #[test]
    fn every_host_and_generated_rule_is_in_the_reserved_namespace() {
        let mut coverage = super::GeneratedCoverage::default();
        let generated = super::generated_documents(
            &[std::path::PathBuf::from("/srv/tth/state")],
            &mut coverage,
        );
        assert!(!generated.is_empty());
        let host = super::host_rule_documents()
            .iter()
            .map(|(_, document)| document);
        for document in host.chain(&generated) {
            let set = telltale_rules::LoadedRules::parse(document).unwrap();
            assert!(!set.is_empty());
            for rule in set.definitions() {
                assert!(
                    rule.id()
                        .starts_with(crate::hooks::config::HOST_RULE_ID_PREFIX),
                    "{}",
                    rule.id()
                );
            }
        }
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

    fn budget_used(limits: Limits, used: Duration, ms_per_byte: f64) -> RecoveryBudget {
        RecoveryBudget {
            ms_per_byte,
            limits,
            ..RecoveryBudget::already_spent(used)
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
        projected(serde_json::json!({ "command": command }))
    }

    /// The variants of `input`, as the runtime projects it.
    fn projected(input: serde_json::Value) -> (Vec<Line>, Vec<Focus>) {
        let variants = crate::hooks::projection::project(&input).unwrap().variants;
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

    /// The call's trace says which scans ran: past the budget the whole and
    /// together scans are skipped, every piece is scanned, and a piece
    /// Telltale refuses is counted with its failure code.
    #[test]
    fn the_trace_counts_scanned_and_refused_pieces_with_the_first_code() {
        let inputs = [
            serde_json::json!({"command": "curl http://a\u{1}b.test/x"}),
            serde_json::json!({"command": "ls"}),
        ];
        let mut lines = Vec::new();
        let mut focus = Vec::new();
        for (n, input) in inputs.iter().enumerate() {
            let at = format!("2026-11-06T00:00:00.{n:03}Z");
            let uuid = format!("uuid-{n}");
            lines.push(Line::tool_use("s", &uuid, &at, "toolu_1", "Bash", input));
            focus.push(Focus {
                occurred_at: at,
                stage: ObservationStage::ToolRequested,
                native_id: uuid,
            });
        }
        let (dir, engine) = engine();
        let mut budget = RecoveryBudget::start(Limits::default());
        let request = Request {
            client: ClientId::Claude,
            window_path: &dir.path().join("window.jsonl"),
            history: &[],
            pending: &lines,
            focus: &focus,
            scan: PendingScan::PiecesOnly,
            journaled: None,
        };
        engine.evaluate(request, &mut budget).unwrap();
        let trace = budget.trace();
        assert_eq!(trace.whole, Some(StepOutcome::SkippedPiecesOnly));
        assert_eq!(trace.together, Some(StepOutcome::SkippedPiecesOnly));
        assert_eq!((trace.pieces_scanned, trace.pieces_total), (2, 2));
        assert_eq!(trace.pieces_refused, 1);
        assert!(trace.first_refusal.is_some(), "{trace:?}");
    }

    /// Two pieces Telltale refuses, a history line, and the line the call is
    /// journaled as, holding `journaled`: evaluated past the projection budget.
    fn refused_pieces_then_history(journaled: &str) -> (Evaluation, ScanTrace) {
        let refused = serde_json::json!({"command": "curl http://a\u{1}b.test/x"});
        let (lines, focus): (Vec<Line>, Vec<Focus>) = (0..2)
            .map(|n| {
                let at = format!("2026-11-06T00:00:01.{n:03}Z");
                let uuid = format!("uuid-{n}");
                let line = Line::tool_use("s", &uuid, &at, "toolu_2", "Bash", &refused);
                let focus = Focus {
                    occurred_at: at,
                    stage: ObservationStage::ToolRequested,
                    native_id: uuid,
                };
                (line, focus)
            })
            .unzip();
        let history = [Line::tool_use(
            "s",
            "uuid-h",
            "2026-11-06T00:00:00.000Z",
            "toolu_1",
            "Bash",
            &serde_json::json!({"command": "ls"}),
        )];
        let own_at = "2026-11-06T00:00:00.500Z";
        let own = Line::tool_use(
            "s",
            "uuid-own",
            own_at,
            "toolu_2",
            "Bash",
            &serde_json::json!({ "command": journaled }),
        );
        let own_focus = Focus {
            occurred_at: own_at.to_owned(),
            stage: ObservationStage::ToolRequested,
            native_id: "uuid-own".to_owned(),
        };
        let (dir, engine) = engine();
        let mut budget = RecoveryBudget::start(time_for_every_piece());
        let request = Request {
            client: ClientId::Claude,
            window_path: &dir.path().join("window.jsonl"),
            history: &history,
            pending: &lines,
            focus: &focus,
            scan: PendingScan::PiecesOnly,
            journaled: Some((&own, &own_focus)),
        };
        let evaluation = engine.evaluate(request, &mut budget).unwrap();
        (evaluation, budget.trace().clone())
    }

    /// Every piece refused, and the history scan finds a deny: the finding
    /// counts, and no piece of the call counts as evaluated.
    #[test]
    fn a_finding_of_the_history_scan_counts_when_every_piece_was_refused() {
        let (evaluation, trace) = refused_pieces_then_history(DENY);
        assert_eq!(trace.pieces_refused, 2);
        assert_eq!(trace.history, Some(StepOutcome::Passed));
        assert_eq!(evaluation.status, EvalStatus::VisibilityLimited);
        assert!(evaluation.rule_ids().iter().any(|id| id == DENY_RULE));
        assert_eq!(evaluation.unevaluated_focus, 2);
    }

    /// Every piece refused, and the history scan finds nothing: the call's
    /// own input was not evaluated, so it stays not evaluated.
    #[test]
    fn a_history_scan_without_a_finding_does_not_make_refused_pieces_evaluated() {
        let (evaluation, trace) = refused_pieces_then_history("ls");
        assert_eq!(trace.pieces_refused, 2);
        assert_eq!(trace.history, Some(StepOutcome::Passed));
        assert_eq!(evaluation.status, EvalStatus::NotEvaluated);
        assert!(evaluation.rule_ids().is_empty());
    }

    /// The window path and the engine, for a scan of `pieces` alone.
    fn engine() -> (tempfile::TempDir, Engine) {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::new(&RuleContent::default(), &[]).unwrap();
        (dir, engine)
    }

    /// `used` is what the evaluation has already spent. The budget starts after the
    /// engine is built, so that the build is not charged to it.
    /// `limits` are the evaluation's.
    fn evaluate_with(command: String, limits: Limits, used: Duration) -> (Evaluation, usize) {
        evaluate_projected_with(pieces(command), limits, used)
    }

    fn evaluate_projected_with(
        lines: (Vec<Line>, Vec<Focus>),
        limits: Limits,
        used: Duration,
    ) -> (Evaluation, usize) {
        evaluate_lines(lines, limits, used, PendingScan::Together)
    }

    /// No piece time limit a loaded host reaches: a test of what the pieces
    /// find does not depend on the runner's speed.
    fn time_for_every_piece() -> Limits {
        Limits {
            piece_scan: Duration::from_secs(3600),
            ..Limits::default()
        }
    }

    fn evaluate_lines(
        (lines, focus): (Vec<Line>, Vec<Focus>),
        limits: Limits,
        used: Duration,
        scan: PendingScan,
    ) -> (Evaluation, usize) {
        let (dir, engine) = engine();
        let mut budget = budget_used(limits, used, 0.0);
        let request = Request {
            client: ClientId::Claude,
            window_path: &dir.path().join("window.jsonl"),
            history: &[],
            pending: &lines,
            focus: &focus,
            scan,
            journaled: None,
        };
        let evaluation = engine.evaluate(request, &mut budget).unwrap();
        (evaluation, lines.len())
    }

    /// Scan the pieces of `command`, with the time limit reached after one scan.
    fn limit_after_one_piece(command: String) -> (Evaluation, usize) {
        let (lines, focus) = pieces(command);
        let (dir, engine) = engine();
        let mut left = 1;
        let evaluation = engine
            .scan_each(
                ClientId::Claude,
                &dir.path().join("window.jsonl"),
                &lines,
                &focus,
                &mut ScanTrace::default(),
                || {
                    let in_time = left > 0;
                    left = 0;
                    in_time
                },
            )
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
            time_for_every_piece(),
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
            Limits::default(),
            PIECE_SCAN_LIMIT,
        );
        assert!(!has_deny_rule(&evaluation), "{:?}", evaluation.rule_ids());
        assert_eq!(evaluation.status, EvalStatus::NotEvaluated);
        assert_eq!(evaluation.unevaluated_focus, lines);
        assert!(says_unscanned(&evaluation));
    }

    /// A projection Telltale accepts whole: the denied command beside a value
    /// too long for one call, so it is spread over a few variants.
    fn accepted_whole() -> (Vec<Line>, Vec<Focus>) {
        let (lines, focus) = projected(serde_json::json!({
            "command": DENY,
            "description": "d".repeat(9000),
        }));
        assert!(lines.len() > 1);
        (lines, focus)
    }

    /// The scan of a projection's variants together comes ahead of the piece
    /// loop, and is bound by the same limit: past it, nothing of the call is
    /// scanned, and the runtime applies `on_unevaluable`.
    #[test]
    fn a_projection_already_past_the_limit_is_not_scanned_together() {
        let (evaluation, lines) =
            evaluate_projected_with(accepted_whole(), Limits::default(), PIECE_SCAN_LIMIT);
        assert!(!has_deny_rule(&evaluation), "{:?}", evaluation.rule_ids());
        assert_eq!(evaluation.status, EvalStatus::NotEvaluated);
        assert_eq!(evaluation.unevaluated_focus, lines);
        assert!(says_unscanned(&evaluation));
    }

    /// Within the piece limit, a spent recovery budget does not stop that scan:
    /// the variants are evaluated together, none left unevaluated, and the deny
    /// found keeps its force.
    #[test]
    fn a_projection_within_the_limit_is_scanned_together_and_keeps_its_deny() {
        let (evaluation, _) =
            evaluate_projected_with(accepted_whole(), time_for_every_piece(), RECOVERY_BUDGET);
        assert!(has_deny_rule(&evaluation), "{:?}", evaluation.rule_ids());
        assert_eq!(verdict(&evaluation), crate::hooks::state::Verdict::Deny);
        assert_eq!(evaluation.unevaluated_focus, 0);
        assert!(!says_unscanned(&evaluation));
    }

    /// An input past the projection budget whose variants Telltale accepts
    /// together: a command of several chunks, its deny in the last chunk.
    fn past_the_budget() -> (Vec<Line>, Vec<Focus>) {
        let input = serde_json::json!({
            "command": format!("echo {}; {DENY}", "a".repeat(9000)),
            "d": "d".repeat(400_000),
        });
        let projection = crate::hooks::projection::project(&input).unwrap();
        assert!(projection.past_budget);
        projected(input)
    }

    /// Past the budget the call is not scanned whole, nor its variants
    /// together: the piece loop starts at once, the command's chunks first,
    /// and a deny in the last of them is found.
    #[test]
    fn a_projection_past_the_budget_goes_straight_to_its_pieces() {
        let (evaluation, lines) = evaluate_lines(
            past_the_budget(),
            time_for_every_piece(),
            Duration::ZERO,
            PendingScan::PiecesOnly,
        );
        assert!(has_deny_rule(&evaluation), "{:?}", evaluation.rule_ids());
        assert_eq!(verdict(&evaluation), crate::hooks::state::Verdict::Deny);
        assert_eq!(
            evaluation.unevaluated_focus, lines,
            "scanned piece by piece"
        );
    }

    /// A command of several chunks, its deny in the last: variants Telltale
    /// accepts together.
    fn split_command() -> (Vec<Line>, Vec<Focus>) {
        pieces(format!("echo {}; {DENY}", "a".repeat(9000)))
    }

    /// Variants the caller marks past the budget are never scanned together,
    /// even where Telltale would accept them together: every focus is left to
    /// the piece loop, which finds the deny.
    #[test]
    fn variants_past_the_budget_are_never_scanned_together() {
        let (evaluation, lines) = evaluate_lines(
            split_command(),
            time_for_every_piece(),
            Duration::ZERO,
            PendingScan::PiecesOnly,
        );
        assert!(has_deny_rule(&evaluation), "{:?}", evaluation.rule_ids());
        assert_eq!(
            evaluation.unevaluated_focus, lines,
            "scanned piece by piece"
        );
    }

    /// The same variants within the budget are scanned together, as before.
    #[test]
    fn variants_within_the_budget_are_scanned_together() {
        let (evaluation, _) = evaluate_lines(
            split_command(),
            time_for_every_piece(),
            Duration::ZERO,
            PendingScan::Together,
        );
        assert!(has_deny_rule(&evaluation), "{:?}", evaluation.rule_ids());
        assert_eq!(evaluation.unevaluated_focus, 0, "scanned together");
    }

    #[test]
    fn the_piece_limit_is_later_than_the_budget() {
        assert!(budget_used(Limits::default(), RECOVERY_BUDGET, 0.0).pieces_in_time());
        assert!(!budget_used(Limits::default(), PIECE_SCAN_LIMIT, 0.0).pieces_in_time());
    }

    /// A call evaluated twice (whole, then projected) spends one budget and
    /// one trace: an evaluation that fails keeps what the earlier one traced.
    #[test]
    fn a_failed_evaluation_keeps_the_calls_trace() {
        let (dir, engine) = engine();
        let at = "2026-11-06T00:00:00.000Z";
        let line = Line::tool_use(
            "s",
            "uuid-0",
            at,
            "toolu_1",
            "Bash",
            &serde_json::json!({"command": "ls"}),
        );
        let focus = Focus {
            occurred_at: at.to_owned(),
            stage: ObservationStage::ToolRequested,
            native_id: "uuid-0".to_owned(),
        };
        let mut budget = RecoveryBudget::start(Limits::default());
        budget.trace.variants = 3;
        let request = Request {
            client: ClientId::Claude,
            window_path: &dir.path().join("missing").join("window.jsonl"),
            history: &[],
            pending: std::slice::from_ref(&line),
            focus: std::slice::from_ref(&focus),
            scan: PendingScan::Together,
            journaled: None,
        };
        assert!(engine.evaluate(request, &mut budget).is_err());
        assert_eq!(budget.trace().variants, 3);
    }

    #[test]
    fn a_scan_that_may_not_fit_is_not_admitted() {
        let fresh = RecoveryBudget::start(Limits::default());
        assert!(fresh.admits(usize::MAX / 2), "nothing measured yet");
        // 1 MB at 0.5 ms per KB: 500 ms, doubled.
        let rate = 0.0005;
        assert!(budget_used(Limits::default(), Duration::from_millis(900), rate).admits(1_000_000));
        assert!(
            !budget_used(Limits::default(), Duration::from_millis(1100), rate).admits(1_000_000)
        );
        assert!(budget_used(Limits::default(), Duration::from_millis(1100), rate).admits(500_000));
        assert!(!budget_used(Limits::default(), RECOVERY_BUDGET, 0.0).admits(1));
        assert!(budget_used(Limits::default(), RECOVERY_BUDGET, 0.0).spent());
    }

    #[test]
    fn the_slowest_rate_counts_and_small_scans_do_not_set_it() {
        let mut budget = RecoveryBudget::start(Limits::default());
        budget.observe(100, 50);
        assert_eq!(budget.ms_per_byte, 0.0, "mostly a scan's fixed setup");
        budget.observe(MIN_MEASURED_BYTES, 100);
        let rate = budget.ms_per_byte;
        assert!(rate > 0.0);
        budget.observe(MIN_MEASURED_BYTES * 2, 100);
        assert_eq!(budget.ms_per_byte, rate);
    }
}
