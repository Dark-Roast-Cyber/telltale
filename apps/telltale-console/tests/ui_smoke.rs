mod support;

use egui::{Context, RawInput, Rect, Vec2};
use std::io::Write;
use support::{batch, parse, record, terminal};
use telltale_console::{
    state::{
        ConsoleState, FeedStatus, FindingFilter, NO_FILTERED_FINDINGS, NO_FINDINGS, NO_HEALTH,
        WAITING,
    },
    ui::{ConsoleUi, Screen},
};
use telltale_core::{
    FeedNotice, FeedNoticeCode, LocalEventFeed, LocalEventFeedConfig, StartupMode,
};

fn frame(ctx: &Context, view: &mut ConsoleUi, state: &mut ConsoleState) -> String {
    let output = render_input(ctx, view, state, vec![]);
    assert!(!output.shapes.is_empty());
    output_text(&output)
}

fn render_input(
    ctx: &Context,
    view: &mut ConsoleUi,
    state: &mut ConsoleState,
    events: Vec<egui::Event>,
) -> egui::FullOutput {
    let mut output = ctx.run_ui(
        RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(1400.0, 1000.0),
            )),
            events,
            ..Default::default()
        },
        |ctx| {
            view.render(ctx, state, "Profile: Project · synthetic-events.jsonl");
        },
    );
    // This harness inspects layout/paint output without a GPU texture backend.
    output.textures_delta.clear();
    output
}

fn output_text(output: &egui::FullOutput) -> String {
    let mut text = String::new();
    fn append(shape: &egui::epaint::Shape, text: &mut String) {
        match shape {
            egui::epaint::Shape::Text(shape) => {
                text.push_str(&shape.galley.job.text);
                text.push('\n');
            }
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    append(shape, text);
                }
            }
            _ => {}
        }
    }
    for shape in &output.shapes {
        append(&shape.shape, &mut text);
    }
    text
}

#[test]
fn navigation_and_finding_click_open_typed_selection() {
    let mut state = ConsoleState::default();
    let r = record("detection", 1);
    let id = r.common().event_id.clone();
    state.ingest(batch(vec![r]));
    let ctx = Context::default();
    let mut view = ConsoleUi::default();
    frame(&ctx, &mut view, &mut state);
    let mut output = render_input(&ctx, &mut view, &mut state, vec![]);
    fn position(shapes: &[egui::epaint::ClippedShape], needle: &str) -> egui::Pos2 {
        fn find(shape: &egui::epaint::Shape, needle: &str) -> Option<egui::Pos2> {
            match shape {
                egui::epaint::Shape::Text(t) if t.galley.job.text.starts_with(needle) => {
                    Some(t.pos + t.galley.size() * 0.5)
                }
                egui::epaint::Shape::Vec(shapes) => shapes.iter().find_map(|s| find(s, needle)),
                _ => None,
            }
        }
        shapes
            .iter()
            .find_map(|s| find(&s.shape, needle))
            .expect("visible clickable text")
    }
    for label in [
        "Detections",
        "Informational · Risk 0",
        "Sensor Health",
        "Overview",
    ] {
        let pos = position(&output.shapes, label);
        for pressed in [true, false] {
            let _ = render_input(
                &ctx,
                &mut view,
                &mut state,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
        output = render_input(&ctx, &mut view, &mut state, vec![]);
        match label {
            "Detections" => assert_eq!(view.screen, Screen::Detections),
            "Sensor Health" => assert_eq!(view.screen, Screen::SensorHealth),
            "Overview" => assert_eq!(view.screen, Screen::Overview),
            _ => assert_eq!(state.selected().unwrap().common().event_id, id),
        }
    }
    assert!(output_text(&output).contains("Event detail"));
}

#[test]
fn full_typed_detail_renders_guidance_evidence_anchors_and_distinct_times() {
    let mut value = terminal("detection", 1);
    value["event_time"] = serde_json::json!("2026-04-01T00:00:00Z");
    value["time_source"] = serde_json::json!("override");
    value["timeline_anchors"] = serde_json::json!([{
        "entry_index": 42, "rule_ids": ["rule.synthetic.test"], "categories": ["execution"], "evidence_fields": ["command"]
    }]);
    value["risk_score"] = serde_json::json!(12);
    value["risk_contributions"] = serde_json::json!([{
        "id": "rule.synthetic.test", "type": "deterministic_rule", "points": 12, "rationale": "Synthetic contribution"
    }]);
    let record = parse(value);
    let ctx = Context::default();
    let mut text = String::new();
    for _ in 0..2 {
        let mut output = ctx.run_ui(
            RawInput {
                screen_rect: Some(Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(1000.0, 6000.0),
                )),
                ..Default::default()
            },
            |ui| {
                egui::CentralPanel::default()
                    .show(ui, |ui| telltale_console::ui::detail(ui, &record));
            },
        );
        output.textures_delta.clear();
        text = output_text(&output);
    }
    for expected in [
        "Recommended response / Investigation guidance",
        "Guidance only. No action has been executed by this console.",
        "Redacted / terminal evidence",
        "TERMINAL_SYNTHETIC_MARKER",
        "Timeline anchor metadata",
        "Entry index",
        "42",
        "Event risk contributions",
        "Synthetic contribution",
        "timestamp",
        "event_time",
        "observed_at",
        "ingested_at",
        "2026-04-01T00:00:00Z",
        "2026-05-01T00:00:00Z",
        "2026-05-01T00:00:01Z",
    ] {
        assert!(text.contains(expected), "missing {expected}");
    }
    for absent in ["Agent\n", "Model\n", "Provider\n"] {
        assert!(!text.contains(absent));
    }
}

fn all_screens(state: &mut ConsoleState) {
    let ctx = Context::default();
    let mut view = ConsoleUi::default();
    for screen in [Screen::Overview, Screen::Detections, Screen::SensorHealth] {
        view.screen = screen;
        // egui's first sizing pass may intentionally discard text shapes.
        frame(&ctx, &mut view, state);
        let text = frame(&ctx, &mut view, state);
        for heading in ["Overview", "Detections", "Sensor Health"] {
            assert!(text.contains(heading));
        }
        assert!(!text.to_lowercase().contains("no threats"));
    }
}

#[test]
fn empty_and_unavailable_health_render_without_display() {
    let mut state = ConsoleState::default();
    all_screens(&mut state);
    let ctx = Context::default();
    let mut view = ConsoleUi::default();
    frame(&ctx, &mut view, &mut state);
    let text = frame(&ctx, &mut view, &mut state);
    assert!(text.contains("Waiting for Telltale events."));
    assert!(text.contains(NO_HEALTH));
    assert!(text.contains(NO_FINDINGS));
}

#[test]
fn one_detection_and_selected_detail_render_without_display() {
    let mut state = ConsoleState::default();
    let r = record("detection", 1);
    let id = r.common().event_id.clone();
    state.ingest(batch(vec![r]));
    all_screens(&mut state);
    state.select(&id);
    let ctx = Context::default();
    let mut view = ConsoleUi::default();
    frame(&ctx, &mut view, &mut state);
    let text = frame(&ctx, &mut view, &mut state);
    assert!(text.contains("Event detail"));
    assert!(text.contains(&id));
    assert!(text.contains("observed_at"));
    assert!(text.contains("ingested_at"));
    assert!(!text.contains("Provider\n"));
}

#[test]
fn filtered_empty_detections_state_is_distinct_from_empty_window() {
    let mut state = ConsoleState::default();
    state.ingest(batch(vec![record("detection", 1)]));
    let ctx = Context::default();
    let mut view = ConsoleUi {
        screen: Screen::Detections,
        filter: FindingFilter {
            query: "does-not-match".into(),
            ..Default::default()
        },
    };

    frame(&ctx, &mut view, &mut state);
    let text = frame(&ctx, &mut view, &mut state);
    assert!(text.contains(NO_FILTERED_FINDINGS));
    assert!(!text.contains(NO_FINDINGS));
}

#[test]
fn mixed_families_render_and_remain_distinct() {
    let mut state = ConsoleState::default();
    for (id, family) in [
        "detection",
        "process_chain",
        "correlation",
        "health",
        "scanner_error",
        "operational_alert",
        "activity",
        "session_risk_summary",
    ]
    .iter()
    .enumerate()
    {
        state.ingest(batch(vec![record(family, id as u64)]));
    }
    assert_eq!(state.summary().findings, 3);
    all_screens(&mut state);
    let ids: Vec<_> = state
        .records()
        .iter()
        .map(|r| r.common().event_id.clone())
        .collect();
    for id in ids {
        state.select(&id);
        all_screens(&mut state);
    }
}

#[test]
fn long_metadata_multiple_evidence_and_anchors_render() {
    let mut value = terminal("detection", 1);
    value["session_id"] = serde_json::json!("synthetic_session_".repeat(1000));
    let long_rule = format!("rule.{}test", "synthetic.".repeat(8));
    value["rule_ids"] = serde_json::json!([long_rule]);
    value["timeline_anchors"] = serde_json::json!([{
        "entry_index": 42, "rule_ids": [long_rule], "categories": ["execution"], "evidence_fields": ["command"]
    }]);
    value["evidence"].as_array_mut().unwrap().push(serde_json::json!({"field": "result", "redacted_value": "SYNTHETIC_REDACTED_".repeat(2000)}));
    let r = parse(value);
    let id = r.common().event_id.clone();
    let mut state = ConsoleState::default();
    state.ingest(batch(vec![r]));
    all_screens(&mut state);
    state.select(&id);
    all_screens(&mut state);
}

#[test]
fn degraded_notices_render_as_feed_not_sensor_telemetry() {
    let mut state = ConsoleState::default();
    let mut b = batch(vec![record("health", 1)]);
    b.notices = vec![
        FeedNotice {
            code: FeedNoticeCode::GenerationGap,
            count: 2,
        },
        FeedNotice {
            code: FeedNoticeCode::ParserMalformed,
            count: 1,
        },
    ];
    state.ingest(b);
    all_screens(&mut state);
    let ctx = Context::default();
    let mut view = ConsoleUi {
        screen: Screen::SensorHealth,
        ..Default::default()
    };
    frame(&ctx, &mut view, &mut state);
    let text = frame(&ctx, &mut view, &mut state);
    assert!(text.contains("Degraded"));
    assert!(text.contains("LocalEventFeed notices — not sensor telemetry"));
    assert!(text.contains("generation_gap"));
}

#[test]
fn degraded_empty_window_does_not_claim_to_be_waiting() {
    let mut state = ConsoleState::default();
    let mut batch = batch(vec![]);
    batch.notices.push(FeedNotice {
        code: FeedNoticeCode::ParserMalformed,
        count: 1,
    });
    state.ingest(batch);

    let ctx = Context::default();
    let mut view = ConsoleUi::default();
    frame(&ctx, &mut view, &mut state);
    let text = frame(&ctx, &mut view, &mut state);
    assert!(text.contains("feed visibility is degraded"));
    assert!(!text.contains(WAITING));
}

#[test]
fn actual_recent_feed_missing_mixed_malformed_and_append_harness() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synthetic-events.jsonl");
    let config = LocalEventFeedConfig::new(
        &path,
        StartupMode::Recent {
            max_events: 100,
            max_bytes: 256 * 1024,
        },
    );
    let mut feed = LocalEventFeed::new(config).unwrap();
    let mut state = ConsoleState::default();
    state.ingest(feed.poll().unwrap());
    assert_eq!(state.status(), FeedStatus::Waiting);
    assert_eq!(state.notices()[&FeedNoticeCode::JournalUnavailable], 1);
    assert!(!path.exists());
    all_screens(&mut state);
    {
        let mut file = std::fs::File::create(&path).unwrap();
        for (id, family) in [
            "detection",
            "detection",
            "detection",
            "health",
            "scanner_error",
            "operational_alert",
            "process_chain",
            "correlation",
        ]
        .iter()
        .enumerate()
        {
            let mut value = terminal(family, id as u64);
            if id == 1 {
                value["severity"] = serde_json::json!("high");
            }
            if id == 2 {
                value["severity"] = serde_json::json!("critical");
            }
            if id == 1 || id == 2 {
                let risk = id as u64 * 10;
                value["risk_score"] = serde_json::json!(risk);
                value["risk_contributions"] = serde_json::json!([{
                    "id": "rule.synthetic.test", "type": "deterministic_rule", "points": risk,
                    "rationale": "Synthetic finding risk"
                }]);
            }
            writeln!(file, "{value}").unwrap();
            if id == 3 {
                writeln!(file, "SYNTHETIC_MALFORMED_NOT_FOR_DISPLAY").unwrap();
            }
        }
    }
    let mut drained = false;
    for _ in 0..100 {
        let b = feed.poll().unwrap();
        drained = b.caught_up;
        state.ingest(b);
        if drained {
            break;
        }
    }
    assert!(drained);
    assert_eq!(state.records().len(), 8);
    assert_eq!(state.summary().findings, 5);
    assert_eq!((state.summary().critical, state.summary().high), (1, 1));
    assert_eq!(state.summary().highest_event_risk, Some(20));
    assert!(state.latest_health().is_some());
    assert_eq!(state.notices()[&FeedNoticeCode::ParserMalformed], 1);
    assert_eq!(state.status(), FeedStatus::Degraded);
    all_screens(&mut state);
    let appended = terminal("detection", 99);
    {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "{appended}").unwrap();
    }
    state.ingest(feed.poll().unwrap());
    assert_eq!(state.records().len(), 9);
    let id = state.findings(&FindingFilter::default())[0]
        .common()
        .event_id
        .clone();
    assert_eq!(id, parse(appended).common().event_id);
    state.select(&id);
    let ctx = Context::default();
    let mut view = ConsoleUi::default();
    for screen in [Screen::Detections, Screen::SensorHealth, Screen::Overview] {
        view.screen = screen;
        frame(&ctx, &mut view, &mut state);
        let text = frame(&ctx, &mut view, &mut state);
        assert!(text.contains("Event detail"));
        assert!(!text.contains("SYNTHETIC_MALFORMED_NOT_FOR_DISPLAY"));
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
