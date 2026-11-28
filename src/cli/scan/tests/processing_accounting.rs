use super::*;

#[test]
fn source_processing_sums_tool_table_counts_across_sources_and_names_nothing() {
    use telltale_sources::acquisition::ToolTableCounts;

    let result =
        |unclassified_tool_calls, tool_operand_drift| canonical::CanonicalProcessingResult {
            events: vec![],
            status: SourceProcessingStatus::Succeeded,
            progress: AcquisitionProgress::None,
            completion: None,
            failure: None,
            accounting: vec![SourceAccounting {
                tool_table: ToolTableCounts {
                    unclassified_tool_calls,
                    tool_operand_drift,
                },
                ..Default::default()
            }],
            baseline_replacement: BaselineReplacement::NoReplacement,
            policy_accounting: None,
            quarantined: Vec::new(),
            bounded: Vec::new(),
        };
    let summary = source_processing_accounting(&[result(2, 1), result(3, 0)])
        .unwrap()
        .json();
    assert_eq!(summary["unclassified_tool_calls"], 5);
    assert_eq!(summary["tool_operand_drift"], 1);
    let quiet = source_processing_accounting(&[result(0, 0)])
        .unwrap()
        .json();
    assert_eq!(quiet["unclassified_tool_calls"], 0);
    assert_eq!(quiet["tool_operand_drift"], 0);
}

#[test]
fn bounded_value_units_count_each_unit_once_however_its_entries_are_spread() {
    use telltale_schema::observation::BoundedTarget;

    // A later drain window appends a second entry of `call-a` after the
    // entry of another unit.
    let entries = vec![
        bounded_entry("call-a", 1, BoundedTarget::Arguments),
        bounded_entry("call-b", 2, BoundedTarget::Result),
        bounded_entry("call-a", 1, BoundedTarget::Result),
    ];
    let result = canonical::CanonicalProcessingResult {
        events: vec![],
        status: SourceProcessingStatus::Succeeded,
        progress: AcquisitionProgress::None,
        completion: None,
        failure: None,
        accounting: vec![SourceAccounting::default()],
        baseline_replacement: BaselineReplacement::NoReplacement,
        policy_accounting: None,
        quarantined: Vec::new(),
        bounded: entries.clone(),
    };
    let summary = source_processing_accounting(&[result]).unwrap().json();
    assert_eq!(summary["bounded_value_unit_count"], 2);
    let listed = summary["bounded_value_units"].as_array().unwrap();
    let listed: Vec<_> = listed
        .iter()
        .map(|entry| {
            (
                entry["native_id"].as_str().unwrap(),
                entry["target"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        [
            ("call-a", "arguments"),
            ("call-b", "result"),
            ("call-a", "result")
        ]
    );

    // The cap counts units, not entries: every entry of a listed unit is
    // kept, and a count above the distinct units listed shows the cut.
    let (count, reported) = bounded_value_units(&entries, 1);
    assert_eq!(count, 2);
    let reported: Vec<_> = reported
        .iter()
        .map(|entry| {
            (
                entry["native_id"].as_str().unwrap(),
                entry["target"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(reported, [("call-a", "arguments"), ("call-a", "result")]);
    let (count, reported) = bounded_value_units(&entries, 2);
    assert_eq!((count, reported.len()), (2, 3));
}

#[test]
fn source_processing_counts_empty_successes_across_sessions_and_unscoped_records() {
    use telltale_schema::observation::CorrelationId;

    let result = |accounting: Option<SourceAccounting>| canonical::CanonicalProcessingResult {
        events: vec![],
        status: if accounting.is_some() {
            SourceProcessingStatus::Succeeded
        } else {
            SourceProcessingStatus::Failed
        },
        progress: AcquisitionProgress::None,
        completion: None,
        failure: None,
        accounting: accounting.into_iter().collect(),
        baseline_replacement: BaselineReplacement::NoReplacement,
        policy_accounting: None,
        quarantined: Vec::new(),
        bounded: Vec::new(),
    };
    let mut nonempty = SourceAccounting::default();
    nonempty.sessions.push(SessionAccounting {
        session_id: CorrelationId::source_reported("synthetic-session").unwrap(),
        metadata: Default::default(),
        counts: Default::default(),
    });
    nonempty.sessions[0].counts.record_counts = RecordCounts {
        user_message: 1,
        tool_call: 2,
        ..Default::default()
    };
    nonempty.unscoped.record_counts = RecordCounts {
        other: 3,
        ..Default::default()
    };
    for (source, successes, empties, errors, records) in [
        (Some(SourceAccounting::default()), 1, 1, 0, 0),
        (Some(nonempty.clone()), 1, 0, 0, 6),
        (None, 0, 0, 1, 0),
    ] {
        let counts = source_processing_accounting(&[result(source)]).unwrap();
        assert_eq!(counts.selected_source_count, 1);
        assert_eq!(counts.parse_success_source_count, successes);
        assert_eq!(counts.empty_source_count, empties);
        assert_eq!(counts.parse_error_source_count, errors);
        assert_eq!(counts.parsed_record_count, records);
    }

    let counts = source_processing_accounting(&[
        result(Some(SourceAccounting::default())),
        result(Some(nonempty)),
        result(None),
    ])
    .unwrap();
    assert_eq!(counts.selected_source_count, 3);
    assert_eq!(counts.parse_success_source_count, 2);
    assert_eq!(counts.empty_source_count, 1);
    assert_eq!(counts.parse_error_source_count, 1);
    assert_eq!(counts.parsed_record_count, 6);
    assert_eq!(counts.record_kind_counts["user_message"], 1);
    assert_eq!(counts.record_kind_counts["tool_call"], 2);
    assert_eq!(counts.record_kind_counts["other"], 3);
    let flow = DetectionFlowAccounting {
        effective_detection_candidate_count: 0,
        matched_rule_id_count: 0,
        allowlist_marked_detection_count: 0,
        state_deduplicated_detection_count: 0,
        emitted_detection_count: 0,
        policy_match_accounting: PolicyMatchAccountingState::NotApplicable,
    };
    assert_eq!(
        warning_codes(&diagnostic_warnings(
            &test_discovery_accounting(),
            &counts,
            &flow,
            18
        )),
        vec![
            "source_parse_error_observed",
            "source_coverage_partial",
            "no_effective_detection_candidates"
        ]
    );
}

#[test]
fn policy_accounting_without_pre_policy_results_is_unavailable() {
    let state = compute_policy_match_accounting(true, false, &[]);
    let flow = DetectionFlowAccounting {
        effective_detection_candidate_count: 0,
        matched_rule_id_count: 0,
        allowlist_marked_detection_count: 0,
        state_deduplicated_detection_count: 0,
        emitted_detection_count: 0,
        policy_match_accounting: state,
    };
    let accounting = flow.json()["policy_match_accounting"].clone();
    assert_eq!(accounting["status"], "unavailable");
    assert!(accounting["pre_policy_detection_candidate_count"].is_null());
    assert!(accounting["fully_filtered_detection_candidate_count"].is_null());
    assert!(accounting["filtered_rule_id_count"].is_null());
}

#[test]
fn suspicious_zero_warning_predicates_keep_empty_and_dedup_cases_distinct() {
    let discovery = test_discovery_accounting();
    let flow = DetectionFlowAccounting {
        effective_detection_candidate_count: 0,
        matched_rule_id_count: 0,
        allowlist_marked_detection_count: 0,
        state_deduplicated_detection_count: 0,
        emitted_detection_count: 0,
        policy_match_accounting: PolicyMatchAccountingState::NotApplicable,
    };
    let no_sources = SourceProcessingAccounting {
        selected_source_count: 0,
        parse_success_source_count: 0,
        empty_source_count: 0,
        parse_error_source_count: 0,
        parsed_record_count: 0,
        record_kind_counts: BTreeMap::new(),
        ..Default::default()
    };
    assert_eq!(
        warning_codes(&diagnostic_warnings(&discovery, &no_sources, &flow, 18)),
        vec!["no_sources_selected"]
    );

    let empty_sources = SourceProcessingAccounting {
        selected_source_count: 2,
        parse_success_source_count: 2,
        empty_source_count: 2,
        parse_error_source_count: 0,
        parsed_record_count: 0,
        record_kind_counts: BTreeMap::new(),
        ..Default::default()
    };
    assert_eq!(
        warning_codes(&diagnostic_warnings(&discovery, &empty_sources, &flow, 18)),
        vec!["selected_sources_produced_no_records"]
    );

    let productive_sources = SourceProcessingAccounting {
        selected_source_count: 2,
        parse_success_source_count: 2,
        empty_source_count: 1,
        parse_error_source_count: 0,
        parsed_record_count: 1,
        record_kind_counts: BTreeMap::from([("user_message".to_string(), 1)]),
        ..Default::default()
    };
    assert_eq!(
        warning_codes(&diagnostic_warnings(
            &discovery,
            &productive_sources,
            &flow,
            18
        )),
        vec![
            "no_tool_records_observed",
            "no_effective_detection_candidates"
        ]
    );
    assert!(
        !warning_codes(&diagnostic_warnings(
            &discovery,
            &productive_sources,
            &flow,
            0,
        ))
        .contains(&"no_effective_detection_candidates")
    );

    let repeated_positive = DetectionFlowAccounting {
        effective_detection_candidate_count: 1,
        state_deduplicated_detection_count: 1,
        ..flow
    };
    assert!(
        !warning_codes(&diagnostic_warnings(
            &discovery,
            &SourceProcessingAccounting {
                selected_source_count: 1,
                parse_success_source_count: 1,
                empty_source_count: 0,
                parse_error_source_count: 0,
                parsed_record_count: 1,
                record_kind_counts: BTreeMap::from([("tool_call".to_string(), 1)]),
                ..Default::default()
            },
            &repeated_positive,
            18,
        ))
        .contains(&"no_effective_detection_candidates")
    );
}
