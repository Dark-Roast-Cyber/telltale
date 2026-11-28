use super::*;

#[test]
fn watch_heartbeat_forward_clock_jump_is_due_before_the_startup_deadline() {
    let started = Instant::now();
    let last = 100_000;
    let heartbeat = WatchHeartbeat {
        interval_seconds: 60,
        last_health_unix_ms: Some(last),
        retry_started: None,
    };
    let old_deadline = started + health_heartbeat_wait(Some(last), last, 60);
    assert!(!heartbeat.is_due(last, started));
    let next_wakeup = started + WATCH_SHUTDOWN_POLL;
    assert!(next_wakeup < old_deadline);
    assert!(!heartbeat.is_due(last + 200, next_wakeup));
    assert!(heartbeat.is_due(last + 60_000, next_wakeup));
}

#[test]
fn watch_heartbeat_backward_clock_jump_is_due_before_the_startup_deadline() {
    let started = Instant::now();
    let last = 100_000;
    let heartbeat = WatchHeartbeat {
        interval_seconds: 60,
        last_health_unix_ms: Some(last),
        retry_started: None,
    };
    let old_deadline = started + health_heartbeat_wait(Some(last), last, 60);
    assert!(!heartbeat.is_due(last, started));
    let next_wakeup = started + WATCH_SHUTDOWN_POLL;
    assert!(next_wakeup < old_deadline);
    assert!(heartbeat.is_due(last - 1, next_wakeup));
}

#[test]
fn watch_heartbeat_scan_result_restarts_the_in_memory_interval_including_dry_run() {
    let started = Instant::now();
    let mut heartbeat = WatchHeartbeat {
        interval_seconds: 60,
        last_health_unix_ms: None,
        retry_started: None,
    };
    assert!(heartbeat.is_due(100_000, started));
    // Dry-run returns this time without persisting a marker. Watch must use
    // the result, not reread the absent marker and immediately scan again.
    heartbeat.after_scan(Some(100_000), true, 100_000, started);
    assert!(!heartbeat.is_due(100_000, started));
    assert!(!heartbeat.is_due(159_999, started + Duration::from_millis(59_999)));
    assert!(heartbeat.is_due(160_000, started + Duration::from_secs(60)));
    // A later scan that emitted health for another reason also resets it.
    heartbeat.after_scan(
        Some(160_000),
        false,
        160_000,
        started + Duration::from_secs(60),
    );
    assert!(!heartbeat.is_due(219_999, started + Duration::from_secs(61)));
    assert!(heartbeat.is_due(159_999, started + Duration::from_secs(61)));
}

#[test]
fn watch_heartbeat_still_due_after_scan_waits_a_monotonic_interval_before_retry() {
    let completed = Instant::now();
    for last in [None, Some(1)] {
        let mut heartbeat = WatchHeartbeat {
            interval_seconds: 60,
            last_health_unix_ms: last,
            retry_started: None,
        };
        assert!(heartbeat.is_due(100_000, completed));
        heartbeat.after_scan(last, true, 100_000, completed);
        for wall_time in [0, 100_000, 1_000_000] {
            assert!(!heartbeat.is_due(wall_time, completed + Duration::from_secs(59)));
            assert!(heartbeat.is_due(wall_time, completed + Duration::from_secs(60)));
        }
    }
}

#[test]
fn watch_heartbeat_huge_interval_never_requires_an_instant_deadline() {
    let now = Instant::now();
    let mut heartbeat = WatchHeartbeat {
        interval_seconds: u64::MAX,
        last_health_unix_ms: Some(0),
        retry_started: None,
    };
    assert!(!heartbeat.is_due(0, now));
    assert!(!heartbeat.is_due(1_000, now + Duration::from_secs(1)));
    heartbeat.last_health_unix_ms = None;
    assert!(heartbeat.is_due(1_000, now));
    heartbeat.after_scan(None, true, 1_000, now);
    assert!(!heartbeat.is_due(u64::MAX, now + Duration::from_secs(1)));
}
