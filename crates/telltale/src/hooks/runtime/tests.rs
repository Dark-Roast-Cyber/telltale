use super::*;

#[test]
fn telemetry_sink_refuses_a_line_one_byte_over_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("telemetry.jsonl");
    let runtime = Runtime::new(Config::default());
    let ctx = Context {
        harness: "claude-code",
        hook_event: "SessionStart".into(),
        session_id: "synthetic-session".into(),
        agent_id: None,
        agent_type: None,
        prompt_id: None,
        permission_mode: None,
        cwd: None,
        can_ask: false,
        can_grant: false,
    };
    let mut record = runtime.record(&ctx, Kind::Lifecycle);
    record.lifecycle = Some(json!({"event": "session_start", "source": "synthetic"}));
    let line_bytes = serde_json::to_vec(&record).unwrap().len() + 1;
    let sink = Sink::new(path.clone()).with_line_limit(line_bytes - 1);
    assert!(is_record_too_large(&sink.write(&record).unwrap_err()));
    assert!(!path.exists());
    Sink::new(path.clone())
        .with_line_limit(line_bytes)
        .write(&record)
        .unwrap();
    let accepted = std::fs::read(path).unwrap();
    assert_eq!(accepted.len(), line_bytes);
    assert_eq!(accepted.last(), Some(&b'\n'));
}

#[test]
fn telemetry_runtime_replaces_an_oversized_record_in_the_stream() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("telemetry.jsonl");
    let mut runtime = Runtime::new(Config {
        mode: Mode::Enforce,
        state_dir: Some(dir.path().join("state")),
        telemetry_path: Some(path.clone()),
        ..Config::default()
    });
    runtime.telemetry_line_limit = 1200;
    let mut ctx = Context {
        harness: "claude-code",
        hook_event: "PreToolUse".into(),
        session_id: "synthetic-session".into(),
        agent_id: None,
        agent_type: None,
        prompt_id: None,
        permission_mode: None,
        cwd: None,
        can_ask: true,
        can_grant: false,
    };
    let call = ToolCall {
        tool_name: "Bash".into(),
        tool_use_id: Some("synthetic-call".into()),
        input: json!({"command": "cat ~/.aws/credentials"}),
    };
    let response = runtime.handle(&ctx, Event::ToolRequested(call.clone()));
    assert!(matches!(response, Response::Decision(decision) if decision.verdict() == Verdict::Ask));
    ctx.hook_event = "PostToolUse".into();
    runtime.handle(
        &ctx,
        Event::ToolFinished {
            call,
            completion: Completion::Completed,
            result_text: String::new(),
            duration_ms: None,
        },
    );
    let wire = std::fs::read_to_string(path).unwrap();
    let mut lines = wire.split_inclusive('\n');
    let error = crate::HooksRecordV1::from_json(lines.next().unwrap().as_bytes()).unwrap();
    assert_eq!(
        error.error_code.as_deref(),
        Some("telemetry_record_too_large")
    );
    assert_eq!(error.kind, crate::HooksRecordKind::Error);
    assert_eq!(error.harness.hook_event, "PreToolUse");
    assert_eq!(error.session.session_id, "synthetic-session");
    let action = error.action.unwrap();
    assert_eq!(action.tool_use_id.as_deref(), Some("synthetic-call"));
    assert_eq!(action.tool_name.as_deref(), Some("Bash"));
    assert!(action.input_sha256.is_some());
    assert!(error.evaluation.is_none());
    assert!(error.decision.is_none());
    assert!(error.outcome.is_none());
    assert!(error.lifecycle.is_none());
    assert!(error.lock_wait_ms.is_none());
    assert!(error.telltale.is_empty());

    let outcome = crate::HooksRecordV1::from_json(lines.next().unwrap().as_bytes()).unwrap();
    assert_eq!(outcome.producer, error.producer);
    let outcome = outcome.outcome.unwrap();
    assert_eq!(
        outcome.decision_record_id.as_deref(),
        Some(error.record_id.as_str())
    );
    assert_eq!(outcome.prior_returned, Some(true));
    assert_eq!(
        outcome.prior_verdict,
        Some(crate::hooks_record::HooksVerdict::Ask)
    );
    assert!(lines.next().is_none());
}

#[test]
fn telemetry_replaces_a_record_over_the_array_bound_in_the_stream() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("telemetry.jsonl");
    let mut runtime = Runtime::new(Config {
        mode: Mode::Enforce,
        state_dir: Some(dir.path().join("state")),
        telemetry_path: Some(path.clone()),
        ..Config::default()
    });
    let ctx = Context {
        harness: "claude-code",
        hook_event: "PreToolUse".into(),
        session_id: "synthetic-session".into(),
        agent_id: None,
        agent_type: None,
        prompt_id: None,
        permission_mode: None,
        cwd: None,
        can_ask: true,
        can_grant: false,
    };
    let call = ToolCall {
        tool_name: "Bash".into(),
        tool_use_id: Some("synthetic-call".into()),
        input: json!({"command": "cat ~/.aws/credentials"}),
    };
    runtime.handle(&ctx, Event::ToolRequested(call.clone()));
    let wire = std::fs::read_to_string(&path).unwrap();
    let decision = crate::HooksRecordV1::from_json(wire.as_bytes()).unwrap();
    let action = TelltaleAction::new(decision.telltale[0].record.clone(), None);

    let max = HOOKS_RECORD_MAX_ARRAY_ITEMS;
    let names = |count: usize| -> Vec<String> {
        (0..count)
            .map(|index| format!("synthetic.rule_{index:04}"))
            .collect()
    };
    let filled = |array: &str, count: usize| {
        if array == "grant" {
            let mut record = runtime.record(&ctx, Kind::Lifecycle);
            record.lifecycle = Some(json!({
                "event": "grant", "scope": "session", "tool": "Bash",
                "rule_ids": names(count), "offer_record_id": decision.record_id,
            }));
            return record;
        }
        let mut record = runtime.record(&ctx, Kind::Decision);
        record.action = Some(action_of(&call));
        record.decision = Some(DecisionInfo {
            mode: "enforce",
            verdict: "ask",
            returned: true,
            returned_verdict: None,
            basis: "action_score",
            action_score: 0,
            session_score_before: 0,
            session_score_after: 0,
            denied_attempts_before: 0,
            rule_ids: if array == "rule_ids" {
                names(count)
            } else {
                Vec::new()
            },
            categories: if array == "categories" {
                names(count)
            } else {
                Vec::new()
            },
            grant: None,
        });
        if array == "telltale" {
            record.telltale = vec![action.clone(); count];
        }
        record
    };
    for array in ["telltale", "rule_ids", "categories", "grant"] {
        let at_bound = dir.path().join(format!("{array}-at-bound.jsonl"));
        Sink::new(at_bound.clone())
            .write(&filled(array, max))
            .unwrap();
        if array == "grant" {
            let written = std::fs::read(&at_bound).unwrap();
            crate::HooksRecordV1::from_json(&written).unwrap();
        }
        let over = dir.path().join(format!("{array}-over.jsonl"));
        let error = Sink::new(over.clone())
            .write(&filled(array, max + 1))
            .unwrap_err();
        assert!(is_record_too_large(&error), "{array}");
        assert!(!over.exists(), "{array}");
    }

    // Through the runtime, the record is replaced and keeps its ID.
    let over = filled("telltale", max + 1);
    runtime.emit(&over);
    let wire = std::fs::read_to_string(&path).unwrap();
    let last = wire.split_inclusive('\n').next_back().unwrap();
    let error = crate::HooksRecordV1::from_json(last.as_bytes()).unwrap();
    assert_eq!(error.record_id, over.record_id);
    assert_eq!(error.kind, crate::HooksRecordKind::Error);
    assert_eq!(
        error.error_code.as_deref(),
        Some("telemetry_record_too_large")
    );
    assert_eq!(
        error.action.unwrap().tool_use_id.as_deref(),
        Some("synthetic-call")
    );
    assert!(error.decision.is_none());
    assert!(error.telltale.is_empty());
}

/// A pipeline that cannot build evaluates nothing, whatever caused it, so it never
/// reaches an allow by default. Operator files need not be involved: an environment
/// value used to break the generated rules with none configured.
#[test]
fn every_pipeline_build_failure_is_strict() {
    let runtime = Runtime::new(Config::default());
    assert!(runtime.is_strict_failure("pipeline_build_failed"));
    assert!(!runtime.is_strict_failure("telemetry_write_failed"));
}

/// No input is known to fail a scan and none is known not to, and an agent
/// can launch its harness with no state directory: none of these is an
/// allow by default.
#[test]
fn scan_failures_and_an_unresolved_state_directory_are_strict() {
    let runtime = Runtime::new(Config::default());
    for code in [
        STATE_DIR_UNRESOLVED,
        "scan_failed",
        "semantic_provenance_failed",
        "scan_returned_no_result",
    ] {
        assert!(runtime.is_strict_failure(code), "{code}");
    }
    for error in [
        crate::hooks::engine::EngineError::NoResult,
        crate::hooks::engine::EngineError::Window(std::io::ErrorKind::Other.into()),
    ] {
        assert!(runtime.is_strict_failure(error.code()), "{error}");
    }
}

#[test]
fn source_times_render_with_milliseconds() {
    assert_eq!(format_ms(0), "1970-01-01T00:00:00.000Z");
    assert_eq!(format_ms(1_762_214_461_007), "2025-11-04T00:01:01.007Z");
}

/// An offered decision ends with the offer. A substituted ask keeps the
/// note's instruction before it and leaves out the note's closing, which
/// says repeating the call will not run it.
#[test]
fn an_offered_decision_ends_with_the_offer_and_drops_the_closing() {
    assert!(ASK_THROUGH_MODEL_NOTE.starts_with(&format!("{ASK_THROUGH_MODEL_INSTRUCTION} ")));
    let reason =
        |can_ask, verdict| match Response::offered_decision(can_ask, verdict, "why.".into()) {
            Response::Decision(decision) => (decision.verdict(), decision.reason().to_owned()),
            other => panic!("{other:?}"),
        };
    assert_eq!(
        reason(false, Verdict::Ask),
        (
            Verdict::Deny,
            format!("why. {ASK_THROUGH_MODEL_INSTRUCTION} {GRANT_OFFER_NOTE}")
        )
    );
    for (can_ask, verdict) in [
        (true, Verdict::Ask),
        (true, Verdict::Deny),
        (false, Verdict::Deny),
    ] {
        assert_eq!(
            reason(can_ask, verdict),
            (verdict, format!("why. {GRANT_OFFER_NOTE}"))
        );
    }
}

#[test]
fn ask_is_the_only_verdict_substituted_and_only_into_deny() {
    for verdict in [Verdict::Allow, Verdict::Ask, Verdict::Deny] {
        assert_eq!(returned_verdict(true, verdict), verdict);
    }
    assert_eq!(returned_verdict(false, Verdict::Allow), Verdict::Allow);
    assert_eq!(returned_verdict(false, Verdict::Ask), Verdict::Deny);
    assert_eq!(returned_verdict(false, Verdict::Deny), Verdict::Deny);
    match Response::decision(false, Verdict::Ask, "why.".into()) {
        Response::Decision(decision) => {
            assert_eq!(decision.verdict(), Verdict::Deny);
            assert_eq!(decision.reason(), format!("why. {ASK_THROUGH_MODEL_NOTE}"));
        }
        other => panic!("{other:?}"),
    }
    match Response::decision(true, Verdict::Ask, "why.".into()) {
        Response::Decision(decision) => {
            assert_eq!(decision.verdict(), Verdict::Ask);
            assert_eq!(decision.reason(), "why.");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn synthetic_call_ids_are_stable_prefixed_and_key_order_independent() {
    let a = synthetic_call_id("s", None, "bash", &json!({"command": "ls", "d": 1}));
    let b = synthetic_call_id("s", None, "bash", &json!({"d": 1, "command": "ls"}));
    assert_eq!(a, b);
    assert!(a.starts_with(SYNTHETIC_ID_PREFIX));
    assert_eq!(a.len(), SYNTHETIC_ID_PREFIX.len() + 32);
    assert_ne!(
        a,
        synthetic_call_id(
            "s",
            Some("agent"),
            "bash",
            &json!({"command": "ls", "d": 1})
        )
    );
    assert_ne!(
        a,
        synthetic_call_id("s", None, "view", &json!({"command": "ls", "d": 1}))
    );
    assert_ne!(
        a,
        synthetic_call_id("t", None, "bash", &json!({"command": "ls", "d": 1}))
    );
}

/// What a tool call gets from a pipeline that did not build, with no operator
/// files. Nothing left in the generated rules breaks a build, so the failure is
/// set directly, as `engine()` records it.
fn after_a_build_failure(edit: fn(&mut Config), can_ask: bool) -> (Response, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config {
        mode: Mode::Enforce,
        state_dir: Some(dir.path().join("state")),
        telemetry_path: Some(dir.path().join("telemetry.jsonl")),
        ..Config::default()
    };
    edit(&mut config);
    assert!(config.rules.files().next().is_none());
    let mut runtime = Runtime::new(config);
    runtime.engine_error = Some("pipeline_build_failed");
    let ctx = Context {
        harness: "claude-code",
        hook_event: "PreToolUse".to_owned(),
        session_id: "s".to_owned(),
        agent_id: None,
        agent_type: None,
        prompt_id: None,
        permission_mode: None,
        cwd: None,
        can_ask,
        can_grant: false,
    };
    let call = ToolCall {
        tool_use_id: Some("toolu_1".to_owned()),
        tool_name: "Bash".to_owned(),
        input: json!({"command": "ls"}),
    };
    let response = runtime.handle(&ctx, Event::ToolRequested(call));
    let base = dir.path().file_name().unwrap().to_string_lossy();
    (response, base.into_owned())
}

/// A projection past its budget goes straight to its pieces. When the
/// hook's deadline has already passed, the piece time limit is cut to what
/// remains of it, so none is scanned, and the call gets `on_unevaluable`,
/// never an allow on "no finding".
#[test]
fn a_projection_past_its_budget_with_no_time_left_before_the_deadline_gets_on_unevaluable() {
    use crate::hooks::config::OnError;
    for (policy, expected) in [(OnError::Ask, Verdict::Ask), (OnError::Deny, Verdict::Deny)] {
        let dir = tempfile::tempdir().unwrap();
        let no_time_left = Limits {
            piece_scan: Duration::from_secs(3600),
            hook_deadline: Duration::ZERO,
            ..Limits::default()
        };
        let mut runtime = Runtime::new(Config {
            mode: Mode::Enforce,
            state_dir: Some(dir.path().join("state")),
            on_unevaluable: policy,
            ..Config::default()
        })
        .with_limits(no_time_left);
        runtime.start_call();
        let ctx = Context {
            harness: "claude-code",
            hook_event: "PreToolUse".to_owned(),
            session_id: "s".to_owned(),
            agent_id: None,
            agent_type: None,
            prompt_id: None,
            permission_mode: None,
            cwd: None,
            can_ask: true,
            can_grant: false,
        };
        let call = ToolCall {
            tool_use_id: Some("toolu_1".to_owned()),
            tool_name: "Bash".to_owned(),
            input: json!({"command": "ls", "d": "d".repeat(400_000)}),
        };
        let projected = crate::hooks::projection::project(&call.input).unwrap();
        assert!(projected.past_budget);
        let mut session = runtime.open(&ctx).unwrap();
        let id = RequestIdentity::next(&mut session, &call);
        let mut budget = runtime.call_budget();
        let (result, _, _, _) =
            runtime.evaluate_projected(&ctx, &mut session, &id, &call, &projected, &mut budget);
        assert_eq!(budget.trace().pieces_scanned, 0);
        let decision = runtime.decide_request(
            &ctx,
            &session,
            result,
            projected.separated,
            false,
            false,
            false,
        );
        assert_eq!(decision.outcome.verdict, expected);
        assert_eq!(decision.outcome.basis, Basis::UnevaluableInput);
    }
}

/// A deadline too far away to represent is no deadline, not a panic.
#[test]
fn a_deadline_past_what_an_instant_holds_leaves_all_the_time() {
    let mut runtime = Runtime::new(Config::default()).with_limits(Limits {
        hook_deadline: Duration::MAX,
        ..Limits::default()
    });
    runtime.start_call();
    assert_eq!(runtime.remaining(), Duration::MAX);
}

/// The deadline bounds waits and work not yet started: a call whose
/// evaluation has finished is recorded and answered with its verdict even
/// when the deadline passed while it was being evaluated.
#[test]
fn a_call_evaluated_before_the_deadline_keeps_its_verdict_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let telemetry = dir.path().join("telemetry.jsonl");
    let mut runtime = Runtime::new(Config {
        mode: Mode::Enforce,
        state_dir: Some(dir.path().join("state")),
        telemetry_path: Some(telemetry.clone()),
        ..Config::default()
    });
    runtime.start_call();
    let ctx = Context {
        harness: "claude-code",
        hook_event: "PreToolUse".to_owned(),
        session_id: "s".to_owned(),
        agent_id: None,
        agent_type: None,
        prompt_id: None,
        permission_mode: None,
        cwd: None,
        can_ask: true,
        can_grant: false,
    };
    let call = ToolCall {
        tool_use_id: Some("toolu_1".to_owned()),
        tool_name: "Bash".to_owned(),
        input: json!({"command": "rm -f ~/.claude/settings.json"}),
    };
    let mut session = runtime.open(&ctx).unwrap();
    let id = RequestIdentity::next(&mut session, &call);
    let evaluated = runtime.evaluate_request(&ctx, &mut session, &id, &call);

    runtime.deadline = Some(Instant::now() - Duration::from_secs(1));
    let response = runtime
        .record_request(&ctx, session, None, id, &call, evaluated, false)
        .unwrap();

    let Response::Decision(decision) = response else {
        panic!("{response:?}");
    };
    assert_eq!(decision.verdict(), Verdict::Deny);
    let records: Vec<Value> = std::fs::read_to_string(&telemetry)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let kinds: Vec<&str> = records
        .iter()
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["decision"]);
    assert_eq!(records[0]["decision"]["verdict"], "deny");
}

#[test]
fn a_build_failure_with_no_operator_files_is_never_an_allow_by_default() {
    let (response, base) = after_a_build_failure(|_| {}, true);
    let Response::Decision(decision) = response else {
        panic!("{response:?}");
    };
    assert_eq!(decision.verdict(), Verdict::Ask);
    let reason = decision.reason();
    assert!(reason.contains("the rules did not build"), "{reason}");
    assert!(reason.contains("`telltale hooks check`"), "{reason}");
    assert!(!reason.contains(&base), "{reason}");

    // A harness that cannot ask is given a deny, like any other ask.
    let (response, _) = after_a_build_failure(|_| {}, false);
    assert!(matches!(response, Response::Decision(d) if d.verdict() == Verdict::Deny));

    // The stricter of the two policies, so `on_error` alone can raise it...
    let (response, _) = after_a_build_failure(|c| c.on_error = OnError::Deny, true);
    assert!(matches!(response, Response::Decision(d) if d.verdict() == Verdict::Deny));

    // ...and only an operator who sets both to allow gets an allow.
    let (response, _) = after_a_build_failure(|c| c.on_unevaluable = OnError::Allow, true);
    assert_eq!(response, Response::None);
}
