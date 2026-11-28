use super::*;

#[test]
fn url_target_reads_tool_argument_urls_and_keeps_completion_complete() {
    // A tool call with no URL-keyed argument has no URL: an evaluated no-match,
    // not a visibility gap.
    let plain = [command(
        "url-absent",
        "ordinary synthetic text",
        Some("2026-09-17T00:00:00Z"),
        0,
    )];
    let evaluation = evaluate(&plain, &target_plan("url", "example")).unwrap();
    assert_eq!(evaluation.completion(), EvaluationCompletion::Complete);
    assert!(evaluation.visibility_limits().is_empty());
    assert_eq!(
        evaluation.sessions()[0].detectors()[0].outcome(),
        super::super::super::RuleV1DetectorOutcome::NoMatch
    );

    // URL-keyed top-level string arguments (also JSON-encoded) are the URL fact;
    // other argument text is not.
    let encoded = [command(
        "url-present",
        r#"{"url":"https://fetch.example.invalid/page","prompt":"see other.example.org"}"#,
        Some("2026-09-17T00:00:00Z"),
        0,
    )];
    let evaluation = evaluate(&encoded, &target_plan("url", "fetch\\.example")).unwrap();
    assert_eq!(evaluation.completion(), EvaluationCompletion::Complete);
    assert_eq!(
        evaluation.sessions()[0].detectors()[0].outcome(),
        super::super::super::RuleV1DetectorOutcome::Match
    );
    let prompt_only = evaluate(&encoded, &target_plan("url", "other\\.example")).unwrap();
    assert_eq!(
        prompt_only.sessions()[0].detectors()[0].outcome(),
        super::super::super::RuleV1DetectorOutcome::NoMatch
    );

    // Mixed-target rules evaluate the URL alternative too, still complete.
    let mixed = evaluate(&encoded, &target_plan("command, url", "fetch\\.example")).unwrap();
    assert_eq!(mixed.completion(), EvaluationCompletion::Complete);
    assert_eq!(
        mixed.sessions()[0].detectors()[0].outcome(),
        super::super::super::RuleV1DetectorOutcome::Match
    );
}

#[test]
fn url_fact_agrees_between_session_selector_and_action_view() {
    let outcome = |arguments: &str, regex: &str| {
        let observations = [command(
            "url-agree",
            arguments,
            Some("2026-09-17T00:00:00Z"),
            0,
        )];
        let instance = CorrelationId::source_reported("synthetic-source-instance").unwrap();
        let evaluation = super::super::super::session::evaluate_source_with_options(
            CanonicalSourceInput {
                client: ClientId::Claude,
                source_id: "claude.projects",
                source_instance: Some(&instance),
                observations: &observations,
            },
            &target_plan("url", regex),
            None,
            &super::super::super::DetailedEvaluationOptions::default(),
        )
        .unwrap();
        let session = &evaluation.sessions()[0];
        (
            session.detectors()[0].outcome(),
            session.action_findings().len(),
        )
    };
    let matched = (super::super::super::RuleV1DetectorOutcome::Match, 1);
    let missed = (super::super::super::RuleV1DetectorOutcome::NoMatch, 0);

    // An empty URL value is not a URL fact in either view.
    assert_eq!(outcome(r#"{"url":""}"#, "^$"), missed);
    assert_eq!(outcome(r#"{"url":"","href":""}"#, "^\\n?$"), missed);

    // A member beyond the value bounds is skipped; it does not hide the URL.
    let deep =
        r#"{"url":"https://fetch.example.invalid/page","deep":[[[[[[[["skippedmarker"]]]]]]]]}"#;
    assert_eq!(outcome(deep, "fetch\\.example"), matched);
    let long = format!(
        r#"{{"url":"https://fetch.example.invalid/page","wide":[{}]}}"#,
        vec!["1"; 200].join(",")
    );
    assert_eq!(outcome(&long, "fetch\\.example"), matched);
    // The skipped member is never a URL argument. It stays searchable as action
    // command text, which the action view (only) also reads as URL text.
    assert_eq!(
        outcome(deep, "skippedmarker"),
        (super::super::super::RuleV1DetectorOutcome::NoMatch, 1)
    );
    // Nesting beyond the JSON parser's own recursion limit is skipped per
    // member too, rather than rejecting the whole object.
    let parser_deep = format!(
        r#"{{"url":"https://fetch.example.invalid/page","deep":{}"x"{}}}"#,
        "[".repeat(200),
        "]".repeat(200)
    );
    assert_eq!(outcome(&parser_deep, "fetch\\.example"), matched);
    // Only skipped members are added to command text, never the prose members
    // that structured input deliberately ignores.
    let prose = r#"{"prompt":"prosemarker","url":"https://fetch.example.invalid/page","deep":[[[[[[[["skippedmarker"]]]]]]]]}"#;
    assert_eq!(outcome(prose, "prosemarker"), missed);
    assert_eq!(
        outcome(prose, "skippedmarker"),
        (super::super::super::RuleV1DetectorOutcome::NoMatch, 1)
    );

    // Intended difference: command text is a URL fact for actions, not for
    // session URL selectors.
    assert_eq!(
        outcome("curl https://fetch.example.invalid/page", "fetch\\.example"),
        (super::super::super::RuleV1DetectorOutcome::NoMatch, 1)
    );
}
