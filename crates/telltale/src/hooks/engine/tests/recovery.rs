use super::super::*;

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
    let engine = Engine::new(&RuleContent::default(), &Grants::default(), &[]).unwrap();
    (dir, engine)
}

/// The grant-protection rules are host rules loaded only while grants are
/// on; with grants off the rule set is the one without them.
#[test]
fn grant_protection_rules_load_only_with_grants_on() {
    const GRANT_RULES: [&str; 5] = [
        "tth.tamper.hook_entry_run",
        "tth.tamper.grant_command_run",
        "tth.tamper.harness_session_resume",
        "tth.tamper.harness_session_resume_failsafe",
        "tth.tamper.grant_channel_failsafe",
    ];
    let ids = |grants: bool| -> Vec<String> {
        super::super::self_protection_documents(&[], grants, &mut GeneratedCoverage::default())
            .unwrap()
            .iter()
            .flat_map(|(_, rules)| rules.definitions())
            .map(|definition| definition.id().to_owned())
            .collect()
    };
    let (off, on) = (ids(false), ids(true));
    assert!(
        GRANT_RULES
            .iter()
            .all(|id| !off.iter().any(|known| known == id))
    );
    assert!(
        GRANT_RULES
            .iter()
            .all(|id| on.iter().any(|known| known == id))
    );
    assert_eq!(on.len(), off.len() + GRANT_RULES.len());
    let identity = |enabled: bool| {
        let grants = Grants {
            enabled,
            ..Grants::default()
        };
        Engine::new(&RuleContent::default(), &grants, &[])
            .unwrap()
            .semantic_identity()
            .to_owned()
    };
    assert_ne!(identity(true), identity(false));
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
    let (evaluation, lines) = limit_after_one_piece(format!("{DENY}; echo {}", hosts(0, 15000)));
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
    let (evaluation, lines) = limit_after_one_piece(format!("echo {}; {DENY}", hosts(0, 15000)));
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
    assert!(!budget_used(Limits::default(), Duration::from_millis(1100), rate).admits(1_000_000));
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
