use super::*;

#[test]
fn investigation_context_scan_order_matches_occurrence_and_emitted_index() {
    let dir = tempdir();
    // The offset timestamp is earlier in real time, not lexical order. Missing
    // times sort last; equal times retain source order.
    let rows = [
        (None, "needle missing first"),
        (Some("2026-09-17T00:00:03Z"), "needle late"),
        (Some("2026-09-17T01:00:00+01:00"), "needle earliest"),
        (Some("2026-09-17T00:00:01Z"), "needle tie first"),
        (Some("2026-09-17T00:00:01Z"), "needle tie second"),
        (None, "needle missing second"),
    ];
    let payload = rows.iter().map(|(timestamp, text)| {
        let mut row = serde_json::json!({"type":"user", "sessionId":"synthetic-session", "message":{"role":"user", "content":text}});
        if let Some(timestamp) = timestamp { row["timestamp"] = (*timestamp).into(); }
        format!("{row}\n")
    }).collect::<String>();
    let source = claude(dir.path(), &payload);
    let pipeline = super::super::super::Pipeline::builder().without_bundled_defaults().rules_document(
        "title: synthetic\nid: cc602218-b8b2-46e8-8dda-440c104a500a\nname: synthetic.order\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: message\ndetection:\n    selection:\n        - message.user_text|re: 'needle'\n    condition: selection\nlevel: low\ntelltale:\n    category: synthetic\n    score: 1\n    explanation: 'synthetic'\n"
    ).build().unwrap();
    let scans = pipeline.scan_sources_with_occurrences(&[source]).unwrap();
    let scan = &scans[0];
    assert_eq!(scan.occurrences.len(), rows.len());
    let record = Event3Record::from_json(&serde_json::to_vec(&scan.events[0]).unwrap()).unwrap();
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    let InvestigationResult::Found(content_free) = backend.investigate(&record) else {
        panic!("missing timeline")
    };
    let expected_rows = [2, 3, 4, 1, 0, 5];
    for (index, row) in expected_rows.into_iter().enumerate() {
        let occurrence = &scan.occurrences[index];
        assert_eq!(occurrence.timeline_index, Some(index));
        assert_eq!(
            content_free.timeline.entries[index].timestamp.as_deref(),
            rows[row].0
        );
        assert!(content_free.timeline.entries[index].evidence.is_empty());
        for anchor in [
            ContextAnchor::Occurrence(occurrence.identity.clone()),
            ContextAnchor::TimelineIndex(index),
        ] {
            let result = backend.investigate_context(&ContextInvestigationRequest {
                event: &record,
                anchor,
                before: 0,
                after: 0,
                content: ContextContent {
                    user_text: true,
                    ..Default::default()
                },
            });
            let ContextInvestigationResult::Found(found) = result else {
                panic!("missing context")
            };
            assert_eq!(found.anchor_index, index);
            assert_eq!(found.entries[0].text.as_deref(), Some(rows[row].1));
            assert_eq!(
                found.entries[0].timestamp,
                content_free.timeline.entries[index].timestamp
            );
        }
    }
}

#[test]
fn investigation_context_default_and_arguments_are_private() {
    let dir = tempdir();
    let payload = JSONL.replace(
        "ordinary_content_canary",
        "ordinary prose password=synthetic-secret token=synthetic-token",
    );
    let source = codex(dir.path(), &payload);
    let input = event(&source, "synthetic-session");
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    let content_free = backend.investigate(&input);
    let result = context(&backend, &input, 0, 0, 1, ContextContent::default());
    let ContextInvestigationResult::Found(found) = &result else {
        panic!("{result:?}")
    };
    assert_eq!(found.anchor_index, 0);
    assert_eq!(found.entries.len(), 1);
    assert_eq!(found.entries[0].linked_entry_index, Some(1));
    assert_eq!(found.entries[0].text, None);
    assert!(!found.text_budget_exhausted);
    assert_eq!(result.reason_code(), None);
    let public = format!("{result:?} {found:?}");
    for excluded in [
        "ordinary prose",
        "synthetic-secret",
        "synthetic-token",
        "OUTPUT_CANARY",
        "EXPLICIT_CALL_CANARY",
        dir.path().to_str().unwrap(),
        &path_hash(&source.path),
    ] {
        assert!(!public.contains(excluded), "{excluded}");
    }
    let result = context(
        &backend,
        &input,
        0,
        0,
        1,
        ContextContent {
            tool_arguments: true,
            ..Default::default()
        },
    );
    let ContextInvestigationResult::Found(found) = &result else {
        panic!("{result:?}")
    };
    let text = found.entries[0].text.as_deref().unwrap();
    assert!(text.contains("ordinary prose"));
    let public = format!("{result:?} {found:?}");
    for excluded in [
        "synthetic-secret",
        "synthetic-token",
        "OUTPUT_CANARY",
        "EXPLICIT_CALL_CANARY",
    ] {
        assert!(!public.contains(excluded));
    }
    assert_eq!(backend.investigate(&input), content_free);
    assert_eq!(fs::read_to_string(&source.path).unwrap(), payload);
    let ContextInvestigationResult::Found(omitted) = context(
        &backend,
        &input,
        1,
        0,
        0,
        ContextContent {
            tool_arguments: true,
            ..Default::default()
        },
    ) else {
        panic!("result anchor missing")
    };
    assert_eq!(omitted.anchor_index, 1);
    assert!(omitted.entries.is_empty());
    let absent = context(&backend, &input, 2, 1, 1, ContextContent::default());
    assert_eq!(
        absent,
        ContextInvestigationResult::AnchorUnavailable(AnchorUnavailableReason::TimelineIndexAbsent)
    );
    assert_eq!(absent.reason_code(), Some("timeline_index_absent"));
}

#[test]
fn investigation_context_mixed_native_blocks_never_export_results() {
    let dir = tempdir();
    let payload = concat!(
        "{\"type\":\"user\",\"sessionId\":\"synthetic-session\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"safe user prose\"},{\"type\":\"tool_result\",\"tool_use_id\":\"synthetic-call\",\"content\":\"RESULT_MARKER\",\"input\":{\"command\":\"RESULT_ARGUMENT_MARKER\"}}]}}\n",
        "{\"type\":\"assistant\",\"sessionId\":\"synthetic-session\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"safe assistant prose\"},{\"type\":\"tool_use\",\"id\":\"synthetic-call\",\"name\":\"shell\",\"input\":{\"command\":\"safe argument prose\"}},{\"type\":\"tool_result\",\"tool_use_id\":\"synthetic-call\",\"content\":\"ASSISTANT_RESULT_MARKER\"}]}}\n"
    );
    let source = claude(dir.path(), payload);
    let input = event(&source, "synthetic-session");
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    for enabled in [false, true] {
        let result = context(
            &backend,
            &input,
            0,
            0,
            32,
            ContextContent {
                user_text: enabled,
                assistant_text: enabled,
                tool_arguments: enabled,
            },
        );
        let ContextInvestigationResult::Found(found) = &result else {
            panic!("{result:?}")
        };
        let public = format!("{result:?} {found:?}");
        for marker in [
            "RESULT_MARKER",
            "RESULT_ARGUMENT_MARKER",
            "ASSISTANT_RESULT_MARKER",
        ] {
            assert!(!public.contains(marker), "{marker}");
        }
        for safe in [
            "safe user prose",
            "safe assistant prose",
            "safe argument prose",
        ] {
            assert_eq!(public.contains(safe), enabled, "{safe}");
        }
        if !enabled {
            assert!(found.entries.iter().all(|entry| entry.text.is_none()));
        }
    }
    // This adapter accepts extraneous arguments on a returned-result record;
    // they must never become opt-in argument context.
    let other = tempdir();
    let payload = JSONL.replace(
        "\"output\":",
        "\"arguments\":\"RETURNED_ARGUMENT_MARKER\",\"output\":",
    );
    let source = codex(other.path(), &payload);
    let acquired = telltale_sources::acquisition::acquire_source_bounded(
        other.path(),
        &source,
        telltale_sources::acquisition::AcquisitionOptions::new(
            telltale_schema::observation::ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
        ),
        telltale_sources::acquisition::DirectReadLimits {
            bytes: 8192,
            records: 32,
            json_depth: 32,
        },
    )
    .unwrap();
    assert!(acquired.observations.iter().any(|observation| {
        observation.stage() == telltale_schema::observation::ObservationStage::ToolResultReturned
            && matches!(observation.body(), telltale_schema::observation::ObservationBody::Tool(tool) if tool.arguments().is_some())
    }));
    let input = event(&source, "synthetic-session");
    let backend = SessionInvestigator::new(InvestigationConfig::new(other.path()));
    let result = context(
        &backend,
        &input,
        0,
        0,
        32,
        ContextContent {
            user_text: true,
            assistant_text: true,
            tool_arguments: true,
        },
    );
    let ContextInvestigationResult::Found(found) = &result else {
        panic!("{result:?}")
    };
    let public = format!("{result:?} {found:?}");
    assert!(public.contains("ordinary_content_canary"));
    assert!(!public.contains("RETURNED_ARGUMENT_MARKER"));
    assert!(!public.contains("OUTPUT_CANARY"));
}

#[test]
fn investigation_context_supported_messages_have_independent_class_gates() {
    let dir = tempdir();
    let payload = concat!(
        "{\"type\":\"user\",\"sessionId\":\"synthetic-session\",\"message\":{\"role\":\"user\",\"content\":\"ordinary user prose password=synthetic-secret\"}}\n",
        "{\"type\":\"assistant\",\"sessionId\":\"synthetic-session\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"ordinary assistant prose token=synthetic-token\"}]}}\n"
    );
    let source = claude(dir.path(), payload);
    let input = event(&source, "synthetic-session");
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    for (user_text, assistant_text) in [(false, false), (true, false), (false, true), (true, true)]
    {
        let result = context(
            &backend,
            &input,
            0,
            0,
            1,
            ContextContent {
                user_text,
                assistant_text,
                tool_arguments: true,
            },
        );
        let ContextInvestigationResult::Found(found) = &result else {
            panic!("{result:?}")
        };
        assert_eq!(found.entries.len(), 2);
        assert_eq!(found.entries[0].text.is_some(), user_text);
        assert_eq!(found.entries[1].text.is_some(), assistant_text);
        if user_text {
            assert!(
                found.entries[0]
                    .text
                    .as_ref()
                    .unwrap()
                    .contains("ordinary user prose")
            );
        }
        if assistant_text {
            assert!(
                found.entries[1]
                    .text
                    .as_ref()
                    .unwrap()
                    .contains("ordinary assistant prose")
            );
        }
        let public = format!("{result:?} {found:?}");
        assert!(!public.contains("synthetic-secret"));
        assert!(!public.contains("synthetic-token"));
    }
    let ContextInvestigationResult::Found(found) =
        context(&backend, &input, 1, 0, 0, ContextContent::default())
    else {
        panic!("no window")
    };
    assert_eq!(
        found
            .entries
            .iter()
            .map(|entry| entry.index)
            .collect::<Vec<_>>(),
        [1]
    );
    assert_eq!(fs::read_to_string(&source.path).unwrap(), payload);
}

#[cfg(unix)]
#[test]
fn investigation_context_radius_is_rejected_before_any_read() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempdir();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    fs::remove_file(&source.path).unwrap();
    let path = std::ffi::CString::new(source.path.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated synthetic pathname.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut config = InvestigationConfig::new(dir.path().join("absent"));
    config.known_sources.push(source);
    let backend = SessionInvestigator::new(config);
    for (before, after) in [(33, 0), (0, 33), (usize::MAX, usize::MAX)] {
        let result = context(
            &backend,
            &input,
            0,
            before,
            after,
            ContextContent::default(),
        );
        assert_eq!(
            result,
            ContextInvestigationResult::NotLocallyResolvable(
                NotLocallyResolvableReason::InvalidLimits
            )
        );
        assert_eq!(result.reason_code(), Some("invalid_limits"));
    }
}

#[test]
fn investigation_context_occurrences_are_exact_source_facts() {
    let dir = tempdir();
    let payload = concat!(
        "{\"type\":\"user\",\"sessionId\":\"synthetic-session\",\"message\":{\"role\":\"user\",\"content\":\"needle first prose\"}}\n",
        "{\"type\":\"user\",\"sessionId\":\"synthetic-session\",\"message\":{\"role\":\"user\",\"content\":\"needle second prose\"}}\n"
    );
    let source = claude(dir.path(), payload);
    let foreign = Source {
        path: source.path.with_file_name("foreign.jsonl"),
        ..source.clone()
    };
    fs::write(
        &foreign.path,
        payload
            .replace("first prose", "FOREIGN_TEXT_CANARY")
            .replace("synthetic-session", "foreign-session"),
    )
    .unwrap();
    let rule = "title: synthetic\nid: 1523429f-99fb-4ca1-85ff-dfa1ea08477d\nname: synthetic.target\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: message\ndetection:\n    selection:\n        - message.user_text|re: 'needle'\n    condition: selection\nlevel: low\ntelltale:\n    category: synthetic\n    score: 1\n    explanation: 'synthetic'\n    analytic_intent: alert\n    detection_class: security_detection\n    signal_type: atomic\n    tags: [synthetic]\n";
    let pipeline = super::super::super::Pipeline::builder()
        .without_bundled_defaults()
        .rules_document(rule)
        .build()
        .unwrap();
    let scans = pipeline
        .scan_sources_with_occurrences(&[source.clone(), foreign])
        .unwrap();
    let scan = &scans[0];
    assert_eq!(scan.occurrences.len(), 2);
    let input = Event3Record::from_json(&serde_json::to_vec(&scan.events[0]).unwrap()).unwrap();
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    for occurrence in &scan.occurrences {
        let result = backend.investigate_context(&ContextInvestigationRequest {
            event: &input,
            anchor: ContextAnchor::Occurrence(occurrence.identity.clone()),
            before: 0,
            after: 0,
            content: ContextContent {
                user_text: true,
                ..Default::default()
            },
        });
        let ContextInvestigationResult::Found(found) = &result else {
            panic!("{result:?}")
        };
        assert_eq!(Some(found.anchor_index), occurrence.timeline_index);
        assert_eq!(found.entries.len(), 1);
        assert!(!format!("{found:?}").contains(occurrence.identity.as_str()));
    }
    assert!(!scans[1].occurrences.is_empty());
    let result = backend.investigate_context(&ContextInvestigationRequest {
        event: &input,
        anchor: ContextAnchor::Occurrence(scans[1].occurrences[0].identity.clone()),
        before: 32,
        after: 32,
        content: ContextContent {
            user_text: true,
            ..Default::default()
        },
    });
    assert_eq!(
        result,
        ContextInvestigationResult::AnchorUnavailable(AnchorUnavailableReason::OccurrenceAbsent)
    );
    assert_eq!(result.reason_code(), Some("occurrence_absent"));
    assert!(!format!("{result:?}").contains("FOREIGN_TEXT_CANARY"));
}

#[test]
fn investigation_context_duplicate_native_coordinates_are_ambiguous() {
    use telltale_sources::acquisition::{
        AcquisitionOptions, DirectReadLimits, acquire_source_bounded,
    };
    let dir = tempdir();
    let source = Source {
        client: ClientId::OpenClaw,
        kind: SourceKind::Jsonl,
        source_id: "openclaw.agents".into(),
        path: dir.path().join("duplicate.jsonl"),
    };
    let payload = concat!(
        "{\"type\":\"user\",\"id\":\"synthetic-duplicate\",\"sessionId\":\"synthetic-session\",\"content\":\"FIRST_PRIVATE_PROSE\"}\n",
        "{\"type\":\"user\",\"id\":\"synthetic-duplicate\",\"sessionId\":\"synthetic-session\",\"content\":\"SECOND_PRIVATE_PROSE\"}\n"
    );
    fs::write(&source.path, payload).unwrap();
    let input = event(&source, "synthetic-session");
    let batch = acquire_source_bounded(
        dir.path(),
        &source,
        AcquisitionOptions::new(
            telltale_schema::observation::ObservedAt::new(input.common().observed_at.clone())
                .unwrap(),
        ),
        DirectReadLimits::default(),
    )
    .unwrap();
    assert_eq!(batch.observations.len(), 2);
    let id = batch.observations[0].observation_id();
    assert_eq!(id, batch.observations[1].observation_id());
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources.push(source.clone());
    let backend = SessionInvestigator::new(config);
    let request = ContextInvestigationRequest {
        event: &input,
        anchor: ContextAnchor::Occurrence(super::super::super::OccurrenceId(id.to_owned())),
        before: 32,
        after: 32,
        content: ContextContent {
            user_text: true,
            ..Default::default()
        },
    };
    for _ in 0..2 {
        let result = backend.investigate_context(&request);
        assert_eq!(
            result,
            ContextInvestigationResult::AnchorUnavailable(
                AnchorUnavailableReason::AmbiguousOccurrence
            )
        );
        assert_eq!(result.reason_code(), Some("ambiguous_occurrence"));
        for excluded in ["FIRST_PRIVATE_PROSE", "SECOND_PRIVATE_PROSE", id] {
            assert!(!format!("{result:?}").contains(excluded));
        }
    }
    assert_eq!(fs::read_to_string(&source.path).unwrap(), payload);
}

#[test]
fn investigation_context_budget_drops_farthest_text_not_structure_or_anchor() {
    let dir = tempdir();
    let prose = "ordinary synthetic prose with spaces ".repeat(40);
    let payload = (0..65).map(|_| format!("{}\n", serde_json::json!({"type":"user","sessionId":"synthetic-session","message":{"role":"user","content":prose}}))).collect::<String>();
    let source = claude(dir.path(), &payload);
    let input = event(&source, "synthetic-session");
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    let ContextInvestigationResult::Found(found) = context(
        &backend,
        &input,
        32,
        32,
        32,
        ContextContent {
            user_text: true,
            ..Default::default()
        },
    ) else {
        panic!("no context")
    };
    assert_eq!(found.entries.len(), 65);
    assert!(found.text_budget_exhausted);
    assert!(found.entries[32].text.is_some());
    assert!(found.entries[0].text.is_none());
    assert!(found.entries[64].text.is_none());
    assert!(
        found
            .entries
            .iter()
            .filter_map(|entry| entry.text.as_ref())
            .map(String::len)
            .sum::<usize>()
            <= 16384
    );
    assert!(
        found
            .entries
            .iter()
            .filter_map(|entry| entry.text.as_ref())
            .all(|text| text.len() <= 512)
    );
    // 32 retained snippets: the farther positive-index member of the last tie is dropped first.
    assert!(found.entries[16].text.is_some());
    assert!(found.entries[48].text.is_none());
    assert_eq!(fs::read_to_string(&source.path).unwrap(), payload);
}
