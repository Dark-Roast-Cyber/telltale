use super::investigation::*;
use std::fs;
use telltale_schema::clients::{ClientId, SourceKind};
use telltale_schema::event::{ActivityEventInput, Event3Record, activity_event, path_hash};
use telltale_schema::source::Source;
use telltale_sources::discovery::discover_sources;

fn event(source: &Source, session: &str) -> Event3Record {
    Event3Record::from_json(&event_json(source, session)).unwrap()
}

fn event_json(source: &Source, session: &str) -> Vec<u8> {
    let event = activity_event(ActivityEventInput {
        client: source.client,
        session_id: session.into(),
        source_path_hash: path_hash(&source.path),
        agent: None,
        model: None,
        provider: None,
        tool_name: None,
        tags: vec![],
        evidence: vec![],
        risk_contributions: vec![],
        event_time: None,
    })
    .unwrap();
    serde_json::to_vec(&event).unwrap()
}

fn codex(dir: &std::path::Path, payload: &str) -> Source {
    fs::create_dir_all(dir.join("codex/sessions")).unwrap();
    fs::write(dir.join("codex/sessions/synthetic.jsonl"), payload).unwrap();
    discover_sources(dir)
        .unwrap()
        .into_iter()
        .find(|s| s.source_id == "codex.sessions")
        .unwrap()
}

const JSONL: &str = concat!(
    "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"synthetic-session\"}}\n",
    "{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"shell\",\"call_id\":\"EXPLICIT_CALL_CANARY\",\"arguments\":\"{\\\"command\\\":\\\"ordinary_content_canary\\\"}\"}}\n",
    "{\"type\":\"response_item\",\"payload\":{\"type\":\"function_call_output\",\"call_id\":\"EXPLICIT_CALL_CANARY\",\"output\":\"/synthetic/private/OUTPUT_CANARY\"}}\n"
);

#[test]
fn investigation_context_scan_order_matches_occurrence_and_emitted_index() {
    let dir = tempfile::tempdir().unwrap();
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
    let pipeline = super::Pipeline::builder().without_bundled_defaults().rules_document(
        "version: 1\ndescription: synthetic\ndefaults: { case_insensitive: false, enabled: true }\nrules:\n  - id: synthetic.order\n    category: synthetic\n    severity: low\n    score: 1\n    targets: [user_context]\n    regex: needle\n    tags: []\n    explanation: synthetic\nmodifiers: []\n"
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

fn context(
    backend: &SessionInvestigator,
    input: &Event3Record,
    index: usize,
    before: usize,
    after: usize,
    content: ContextContent,
) -> ContextInvestigationResult {
    backend.investigate_context(&ContextInvestigationRequest {
        event: input,
        anchor: ContextAnchor::TimelineIndex(index),
        before,
        after,
        content,
    })
}

#[test]
fn investigation_context_default_and_arguments_are_private() {
    let dir = tempfile::tempdir().unwrap();
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
    let public = format!("{result:?} {}", serde_json::to_string(found).unwrap());
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
    let public = format!("{result:?} {}", serde_json::to_string(found).unwrap());
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

fn claude(dir: &std::path::Path, payload: &str) -> Source {
    fs::create_dir_all(dir.join("claude/projects")).unwrap();
    fs::write(dir.join("claude/projects/context.jsonl"), payload).unwrap();
    discover_sources(dir)
        .unwrap()
        .into_iter()
        .find(|source| source.source_id == "claude.projects")
        .unwrap()
}

#[test]
fn investigation_context_mixed_native_blocks_never_export_results() {
    let dir = tempfile::tempdir().unwrap();
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
        let public = format!("{result:?} {}", serde_json::to_string(found).unwrap());
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
    let other = tempfile::tempdir().unwrap();
    let payload = JSONL.replace(
        "\"output\":",
        "\"arguments\":\"RETURNED_ARGUMENT_MARKER\",\"output\":",
    );
    let source = codex(other.path(), &payload);
    let acquired = telltale_sources::acquisition::acquire_source_bounded(
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
    let public = format!("{result:?} {}", serde_json::to_string(found).unwrap());
    assert!(public.contains("ordinary_content_canary"));
    assert!(!public.contains("RETURNED_ARGUMENT_MARKER"));
    assert!(!public.contains("OUTPUT_CANARY"));
}

#[test]
fn investigation_context_supported_messages_have_independent_class_gates() {
    let dir = tempfile::tempdir().unwrap();
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
        let public = format!("{result:?} {}", serde_json::to_string(found).unwrap());
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
    let rule = "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: synthetic.target\n    category: synthetic\n    detection_class: security_detection\n    signal_type: atomic\n    analytic_intent: alert\n    severity: low\n    score: 1\n    targets: [user_context]\n    regex: needle\n    tags: [synthetic]\n    explanation: synthetic\nmodifiers: []\n";
    let pipeline = super::Pipeline::builder()
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
        assert!(
            !serde_json::to_string(found)
                .unwrap()
                .contains(occurrence.identity.as_str())
        );
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
    let dir = tempfile::tempdir().unwrap();
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
        anchor: ContextAnchor::Occurrence(super::OccurrenceId(id.to_owned())),
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
    let dir = tempfile::tempdir().unwrap();
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

#[test]
fn investigation_jsonl_is_content_free_and_preserves_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    let result = backend.investigate(&input);
    let InvestigationResult::Found(found) = &result else {
        panic!("{result:?}")
    };
    assert_eq!(found.timeline.entry_count, 2);
    assert_eq!(found.timeline.entries[0].linked_entry_index, Some(1));
    assert_eq!(found.timeline.entries[1].linked_entry_index, Some(0));
    assert!(found.timeline.entries.iter().all(|e| e.evidence.is_empty()));
    assert_eq!(result.reason_code(), None);
    let public = format!(
        "{result:?} {}",
        serde_json::to_string(&found.timeline).unwrap()
    );
    for canary in [
        "ordinary_content_canary",
        "OUTPUT_CANARY",
        "EXPLICIT_CALL_CANARY",
        dir.path().to_str().unwrap(),
    ] {
        assert!(!public.contains(canary));
    }
    assert_eq!(backend.investigate(&input), result);
    assert_eq!(fs::read_to_string(&source.path).unwrap(), JSONL);
    assert!(!source.path.with_extension("jsonl-wal").exists());
}

#[test]
fn investigation_exact_identity_and_known_source_loss() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources = vec![source.clone()];
    let backend = SessionInvestigator::new(config);
    assert_eq!(
        backend.investigate(&event(&source, "different-session")),
        InvestigationResult::SessionUnavailable(SessionUnavailableReason::ExactSessionAbsent)
    );
    let mut other_client = source.clone();
    other_client.client = ClientId::Claude;
    assert_eq!(
        backend.investigate(&event(&other_client, "synthetic-session")),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::UnknownSource)
    );
    fs::rename(&source.path, source.path.with_file_name("moved.jsonl")).unwrap();
    assert_eq!(
        backend.investigate(&event(&source, "synthetic-session")),
        InvestigationResult::SourceUnavailable(SourceUnavailableReason::Missing)
    );
    let fresh = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    assert_eq!(
        fresh.investigate(&event(&source, "synthetic-session")),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::UnknownSource)
    );
}

#[test]
fn investigation_bounds_and_ambiguous_source_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.source_bytes = 16;
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::SourceUnavailable(SourceUnavailableReason::LimitExceeded)
    );
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.discovery_entries = 1;
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::NotLocallyResolvable(
            NotLocallyResolvableReason::DiscoveryLimitExceeded
        )
    );
    let mut conflicting = source.clone();
    conflicting.source_id = "codex.archived_sessions".into();
    conflicting.kind = SourceKind::ArchivedJsonl;
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources = vec![conflicting, source];
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::AmbiguousSource)
    );
}

#[cfg(unix)]
#[test]
fn investigation_non_regular_source_never_blocks() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    fs::remove_file(&source.path).unwrap();
    let path = std::ffi::CString::new(source.path.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated synthetic pathname.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources = vec![source];
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::SourceUnavailable(SourceUnavailableReason::NonRegularSource)
    );
}

#[test]
fn investigation_malformed_depth_and_exact_byte_record_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.source_bytes = JSONL.len();
    config.limits.records = 3;
    assert!(matches!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::Found(_)
    ));
    for payload in ["{\"type\":", "{\"nested\":"] {
        fs::write(&source.path, payload).unwrap();
        assert_eq!(
            SessionInvestigator::new(InvestigationConfig::new(dir.path())).investigate(&input),
            InvestigationResult::SourceUnavailable(SourceUnavailableReason::MalformedSource)
        );
        assert_eq!(fs::read_to_string(&source.path).unwrap(), payload);
    }
    fs::write(&source.path, JSONL).unwrap();
    for (bytes, records, depth) in [
        (JSONL.len() - 1, 3, 64),
        (JSONL.len(), 2, 64),
        (JSONL.len(), 3, 1),
    ] {
        let mut config = InvestigationConfig::new(dir.path());
        config.limits.source_bytes = bytes;
        config.limits.records = records;
        config.limits.json_depth = depth;
        assert_eq!(
            SessionInvestigator::new(config).investigate(&input),
            InvestigationResult::SourceUnavailable(SourceUnavailableReason::LimitExceeded)
        );
    }
    assert_eq!(fs::read_to_string(&source.path).unwrap(), JSONL);
}

#[test]
fn investigation_failure_reasons_are_private_and_stateless() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    for (payload, expected) in [
        (
            "{PRIVATE_PARSE_CANARY",
            SourceUnavailableReason::MalformedSource,
        ),
        (
            r#"{"type":"PRIVATE_DISCRIMINATOR_CANARY","session_id":"synthetic-session"}"#,
            SourceUnavailableReason::MalformedSource,
        ),
    ] {
        fs::write(&source.path, payload).unwrap();
        let result = backend.investigate(&input);
        assert_eq!(result, InvestigationResult::SourceUnavailable(expected));
        let public = format!("{result:?} {}", result.reason_code().unwrap());
        assert!(!public.contains("PRIVATE_"));
        assert!(!public.contains(dir.path().to_str().unwrap()));
        assert_eq!(fs::read_to_string(&source.path).unwrap(), payload);
    }
    fs::write(
        &source.path,
        r#"{"type":"user","session_id":"synthetic-session","sessionId":"PRIVATE_OWNER_CANARY"}"#,
    )
    .unwrap();
    assert_eq!(
        backend.investigate(&input),
        InvestigationResult::NotLocallyResolvable(
            NotLocallyResolvableReason::ConflictingSessionOwnership
        )
    );
    fs::write(&source.path, JSONL).unwrap();
    assert!(matches!(
        backend.investigate(&input),
        InvestigationResult::Found(_)
    ));
}

#[test]
fn investigation_duplicate_selection_is_order_independent() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let mut conflicting = source.clone();
    conflicting.source_id = "PRIVATE_SOURCE_ID_CANARY".into();
    for sources in [
        vec![source.clone(), source.clone()],
        vec![source.clone(), conflicting.clone()],
        vec![conflicting, source.clone()],
    ] {
        let ambiguous = sources[0] != sources[1];
        let mut config = InvestigationConfig::new(dir.path());
        config.known_sources = sources;
        let result = SessionInvestigator::new(config).investigate(&input);
        if ambiguous {
            assert_eq!(
                result,
                InvestigationResult::NotLocallyResolvable(
                    NotLocallyResolvableReason::AmbiguousSource
                )
            );
        } else {
            assert!(matches!(result, InvestigationResult::Found(_)));
        }
        assert!(!format!("{result:?}").contains("PRIVATE_SOURCE_ID_CANARY"));
    }
}

#[test]
fn investigation_invalid_limits_and_unsupported_source_are_distinct() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.source_bytes = 0;
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::InvalidLimits)
    );
    let mut config = InvestigationConfig::new(dir.path());
    config.limits.discovery_entries = 0;
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::InvalidLimits)
    );
    let unsupported = Source {
        client: ClientId::Copilot,
        kind: SourceKind::CopilotProcessLog,
        source_id: "copilot.process_log".into(),
        path: dir.path().join("PRIVATE_PATH_CANARY"),
    };
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources.push(unsupported.clone());
    assert_eq!(
        SessionInvestigator::new(config).investigate(&event(&unsupported, "synthetic-session")),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::UnsupportedSource)
    );
}

#[test]
fn investigation_event_correlation_and_metadata_only_session_are_explicit() {
    use telltale_schema::event::{HealthEventInput, health_event_with_metadata};
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    let health = health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: telltale_schema::scoring::RiskThresholds {
            low: 1,
            medium: 2,
            high: 3,
            critical: 4,
        },
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    });
    let health = Event3Record::from_json(&serde_json::to_vec(&health).unwrap()).unwrap();
    assert_eq!(
        backend.investigate(&health),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::MissingCorrelation)
    );
    let mut value: serde_json::Value =
        serde_json::from_slice(&event_json(&source, "synthetic-session")).unwrap();
    value["client"] = "PRIVATE_CLIENT_CANARY".into();
    let unknown = Event3Record::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        backend.investigate(&unknown),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::UnsupportedClient)
    );
    fs::write(
        &source.path,
        "{\"type\":\"session_meta\",\"payload\":{\"session_id\":\"synthetic-session\"}}\n",
    )
    .unwrap();
    assert_eq!(
        backend.investigate(&event(&source, "synthetic-session")),
        InvestigationResult::SessionUnavailable(SessionUnavailableReason::NoTimeline)
    );
}

#[cfg(unix)]
#[test]
fn investigation_discovery_failure_is_not_source_loss() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let input = event(&source, "synthetic-session");
    fs::rename(dir.path().join("codex/sessions"), dir.path().join("saved")).unwrap();
    symlink(dir.path().join("saved"), dir.path().join("codex/sessions")).unwrap();
    let mut config = InvestigationConfig::new(dir.path());
    config.known_sources.push(source);
    assert_eq!(
        SessionInvestigator::new(config).investigate(&input),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::DiscoverySymlinkRoot)
    );
}

#[test]
fn investigation_anchors_are_only_recorded_and_current_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let source = codex(dir.path(), JSONL);
    let mut value =
        serde_json::from_slice::<serde_json::Value>(&event_json(&source, "synthetic-session"))
            .unwrap();
    value["event_type"] = "detection".into();
    value["rule_ids"] = serde_json::json!(["synthetic.rule"]);
    value["categories"] = serde_json::json!(["synthetic"]);
    value["detection_classes"] = serde_json::json!(["security_detection"]);
    value["signal_types"] = serde_json::json!(["atomic"]);
    value["analytic_intents"] = serde_json::json!(["alert"]);
    value["atlas_tags"] = serde_json::json!([]);
    value["response"] = serde_json::json!({"recommended_action":"monitor", "response_playbook":"telltale-playbook-synthetic",
        "investigation_summary":"Synthetic investigation", "escalation":"routine_review"});
    value["timeline_anchors"] = serde_json::json!([
        {"entry_index":0,"rule_ids":["synthetic.rule"],"categories":["synthetic"],"evidence_fields":["arguments"]},
        {"entry_index":99,"rule_ids":["synthetic.rule"],"categories":["synthetic"],"evidence_fields":["arguments"]}
    ]);
    let input = Event3Record::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let InvestigationResult::Found(found) =
        SessionInvestigator::new(InvestigationConfig::new(dir.path())).investigate(&input)
    else {
        panic!("missing session");
    };
    assert_eq!(
        found.anchors,
        vec![
            InvestigationAnchor {
                recorded_entry_index: 0,
                current_entry_index: Some(0)
            },
            InvestigationAnchor {
                recorded_entry_index: 99,
                current_entry_index: None
            }
        ]
    );
}

#[test]
fn investigation_json_object_and_jsonl_with_same_session_keep_clients_separate() {
    let dir = tempfile::tempdir().unwrap();
    let codex_source = codex(dir.path(), JSONL);
    fs::create_dir_all(dir.path().join("claude/projects")).unwrap();
    let payload = r#"{"type":"user","sessionId":"synthetic-session","message":{"role":"user","content":[{"type":"text","text":"CLAUDE_CONTENT_CANARY"}]}}"#;
    fs::write(dir.path().join("claude/projects/synthetic.jsonl"), payload).unwrap();
    let claude_source = discover_sources(dir.path())
        .unwrap()
        .into_iter()
        .find(|s| s.source_id == "claude.projects")
        .unwrap();
    let backend = SessionInvestigator::new(InvestigationConfig::new(dir.path()));
    for source in [&codex_source, &claude_source] {
        let result = backend.investigate(&event(source, "synthetic-session"));
        let InvestigationResult::Found(found) = &result else {
            panic!("{result:?}")
        };
        assert_eq!(found.timeline.client, source.client.as_str());
        assert_eq!(
            found.timeline.entry_count,
            if source.client == ClientId::Codex {
                2
            } else {
                1
            }
        );
        assert!(!format!("{result:?}").contains("CLAUDE_CONTENT_CANARY"));
    }
    let mut wrong_client = codex_source.clone();
    wrong_client.client = ClientId::Claude;
    assert_eq!(
        backend.investigate(&event(&wrong_client, "synthetic-session")),
        InvestigationResult::NotLocallyResolvable(NotLocallyResolvableReason::UnknownSource)
    );
    assert_eq!(fs::read_to_string(&claude_source.path).unwrap(), payload);
}

#[test]
fn investigation_opencode_is_deferred_without_launch_or_artifact_changes() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("opencode");
    fs::create_dir(&store).unwrap();
    let paths = ["opencode.db", "opencode.db-wal", "opencode.db-shm"].map(|name| store.join(name));
    for path in &paths {
        fs::write(path, b"SYNTHETIC_NOT_SQLITE").unwrap();
    }
    let before = paths.each_ref().map(|path| {
        (
            fs::read(path).unwrap(),
            fs::metadata(path).unwrap().modified().unwrap(),
        )
    });
    let bin = dir.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let executable = bin.join(format!("opencode{}", std::env::consts::EXE_SUFFIX));
    assert!(
        std::process::Command::new("rustc")
            .args([
                "--edition=2024",
                "--crate-name",
                "investigation_no_launch_helper"
            ])
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("src/investigation_tests/helper.rs")
            )
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    #[cfg(target_os = "linux")]
    let access_probe = {
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        // SAFETY: inotify takes no pointers; ownership is transferred once.
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(raw >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        for path in [dir.path(), store.as_path()]
            .into_iter()
            .chain(paths.iter().map(|p| p.as_path()))
        {
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: valid descriptor and NUL-terminated synthetic pathname.
            assert!(
                unsafe {
                    libc::inotify_add_watch(raw, path.as_ptr(), libc::IN_OPEN | libc::IN_ACCESS)
                } >= 0
            );
        }
        fd
    };
    // Only this child receives a synthetic PATH; no process-global environment
    // mutation or installed/live OpenCode executable can enter the test.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "investigation_tests::investigation_opencode_deferred_probe",
            "--ignored",
        ])
        .env("PATH", &bin)
        .env("OPENCODE_DB", &paths[0])
        .env("TELLTALE_INVESTIGATION_PROBE_ROOT", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut buffer = [0u8; 4096];
        // SAFETY: writable buffer with its exact length and a live descriptor.
        let read = unsafe {
            libc::read(
                access_probe.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        assert_eq!(
            read, -1,
            "investigation opened/read a synthetic source or discovery directory"
        );
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    assert!(!bin.join("launched").exists());
    assert_eq!(fs::read_dir(&store).unwrap().count(), 3);
    let after = paths.each_ref().map(|path| {
        (
            fs::read(path).unwrap(),
            fs::metadata(path).unwrap().modified().unwrap(),
        )
    });
    assert_eq!(before, after);
}

#[test]
#[ignore = "executed only by the synthetic no-launch subprocess test"]
fn investigation_opencode_deferred_probe() {
    use telltale_sources::acquisition::{
        AcquisitionError, AcquisitionOptions, DirectReadLimits, acquire_source_bounded,
    };
    let root = std::path::PathBuf::from(
        std::env::var_os("TELLTALE_INVESTIGATION_PROBE_ROOT").expect("synthetic probe root"),
    );
    let source = Source {
        client: ClientId::OpenCode,
        kind: SourceKind::Sqlite,
        source_id: "opencode.sqlite".into(),
        path: root.join("opencode/opencode.db"),
    };
    for session in ["ses_synthetic", "ses_SYNTHETIC_Mixed"] {
        for known in [false, true] {
            let mut config = InvestigationConfig::new(&root);
            // A traversal would exhaust this budget; provider deferral wins.
            config.limits.discovery_entries = 1;
            if known {
                config.known_sources.push(source.clone());
            }
            let backend = SessionInvestigator::new(config);
            let input = event(&source, session);
            assert_eq!(
                backend.investigate(&input),
                InvestigationResult::SourceUnavailable(
                    SourceUnavailableReason::ReadOnlyProviderUnavailable
                )
            );
            assert_eq!(
                context(
                    &backend,
                    &input,
                    0,
                    32,
                    32,
                    ContextContent {
                        user_text: true,
                        assistant_text: true,
                        tool_arguments: true
                    }
                ),
                ContextInvestigationResult::SourceUnavailable(
                    SourceUnavailableReason::ReadOnlyProviderUnavailable
                )
            );
        }
    }
    let options = AcquisitionOptions::new(
        telltale_schema::observation::ObservedAt::new("2026-01-01T00:00:00Z").unwrap(),
    );
    assert!(matches!(
        acquire_source_bounded(&source, options, DirectReadLimits::default()),
        Err(AcquisitionError::UnsupportedSourceIdentity)
    ));
    // Deferred means no discovery/source access, even when the configured root
    // is absent. Production scanner acquisition is deliberately unchanged.
    assert_eq!(
        SessionInvestigator::new(InvestigationConfig::new(root.join("absent")))
            .investigate(&event(&source, "ses_synthetic")),
        InvestigationResult::SourceUnavailable(
            SourceUnavailableReason::ReadOnlyProviderUnavailable
        )
    );
}
