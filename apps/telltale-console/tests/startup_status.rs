mod support;

use clap::Parser;
use support::{batch, record};
use telltale_console::{
    startup::{Options, Profile, poll_delay},
    state::{ConsoleState, FeedStatus},
};
use telltale_core::{FeedNotice, FeedNoticeCode, StartupMode};

#[test]
fn startup_defaults_and_overrides() {
    let options = Options::try_parse_from(["telltale-console"]).unwrap();
    assert_eq!(options.path_profile, Profile::User);
    assert_eq!(options.log_path, None);
    assert_eq!(
        options.feed_config().startup,
        StartupMode::Recent {
            max_events: 100,
            max_bytes: 256 * 1024
        }
    );
    for (profile, expected) in [
        ("user", Profile::User),
        ("system", Profile::System),
        ("project", Profile::Project),
    ] {
        let options = Options::try_parse_from([
            "telltale-console",
            "--path-profile",
            profile,
            "--log-path",
            "synthetic.jsonl",
        ])
        .unwrap();
        assert_eq!(options.path_profile, expected);
        assert_eq!(
            options.feed_config().path,
            std::path::PathBuf::from("synthetic.jsonl")
        );
    }
    assert!(Options::try_parse_from(["telltale-console", "--path-profile", "invalid"]).is_err());
    assert_eq!(poll_delay(&batch(vec![])).as_millis(), 500);
    let mut backlog = batch(vec![]);
    backlog.caught_up = false;
    backlog.bytes_read = 256;
    assert_eq!(poll_delay(&backlog).as_millis(), 1);
}

#[test]
fn help_and_version_do_not_initialize_display() {
    for flag in ["--help", "--version"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_telltale-console"))
            .arg(flag)
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("telltale-console")
        );
    }
}

#[test]
fn waiting_catching_up_live_and_sticky_degraded() {
    let mut state = ConsoleState::default();
    assert_eq!(state.status(), FeedStatus::Waiting);
    state.ingest(batch(vec![]));
    assert_eq!(state.status(), FeedStatus::Waiting);
    let mut backlog = batch(vec![]);
    backlog.caught_up = false;
    state.ingest(backlog);
    assert_eq!(state.status(), FeedStatus::CatchingUp);
    state.ingest(batch(vec![record("activity", 1)]));
    assert_eq!(state.status(), FeedStatus::Live);
    let mut degraded = batch(vec![]);
    degraded.notices.push(FeedNotice {
        code: FeedNoticeCode::TruncatedGeneration,
        count: 1,
    });
    state.ingest(degraded);
    state.ingest(batch(vec![]));
    assert_eq!(state.status(), FeedStatus::Degraded);
}

#[test]
fn all_integrity_notice_codes_degrade_without_stopping_ingestion() {
    use FeedNoticeCode::*;
    for code in [
        UnsafeFile,
        DirectoryBound,
        GenerationBound,
        GenerationGap,
        ReplacedGeneration,
        TruncatedGeneration,
        ReadRace,
        StartupBoundaryUnavailable,
        NonActivePartialFrame,
        OversizedFrame,
        ParserMalformed,
        ParserVersion,
        ParserStructure,
        ParserIdentity,
        ParserSemantic,
        ParserFamily,
        EventIdCollision,
        NoticeBound,
    ] {
        let mut state = ConsoleState::default();
        let mut b = batch(vec![]);
        b.notices.push(FeedNotice { code, count: 1 });
        state.ingest(b);
        state.ingest(batch(vec![record("health", 1)]));
        assert_eq!(state.status(), FeedStatus::Degraded, "{code}");
        assert_eq!(state.records().len(), 1);
    }
}

#[test]
fn informational_notices_do_not_claim_sensor_failure() {
    let mut state = ConsoleState::default();
    let mut b = batch(vec![record("health", 1)]);
    b.notices = vec![
        FeedNotice {
            code: FeedNoticeCode::ReplaySuppressed,
            count: 1,
        },
        FeedNotice {
            code: FeedNoticeCode::DedupEvicted,
            count: 1,
        },
    ];
    state.ingest(b);
    assert_eq!(state.status(), FeedStatus::Live);
    assert_eq!(state.notice_count(), 2);
}

#[test]
fn health_eviction_is_unavailable_not_never_observed() {
    let mut state = ConsoleState::with_capacity(1);
    state.ingest(batch(vec![record("health", 1), record("activity", 2)]));
    assert!(state.latest_health().is_none());
    assert_eq!(
        state.health_unavailable_message(),
        "No scanner health event remains in the retained local window."
    );
}

#[test]
fn idle_partial_or_unavailable_frontier_does_not_busy_poll() {
    let mut stalled = batch(vec![]);
    stalled.caught_up = false;
    for code in [
        FeedNoticeCode::ActivePartialFrame,
        FeedNoticeCode::JournalUnavailable,
        FeedNoticeCode::GenerationBound,
    ] {
        stalled.notices = vec![FeedNotice { code, count: 1 }];
        assert_eq!(poll_delay(&stalled).as_millis(), 500);
    }
    stalled.notices.clear();
    assert_eq!(poll_delay(&stalled).as_millis(), 500);
    stalled.records.push(record("detection", 1));
    assert_eq!(poll_delay(&stalled).as_millis(), 1);
}
