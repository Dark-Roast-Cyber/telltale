use super::*;

#[test]
fn scanner_error_threshold_alerts_on_the_first_full_scan_crossing_only() {
    let harness = ThresholdHarness::new();
    let above = 0;

    harness.scan(above, false, false);
    let first = harness.take_events();
    assert_eq!(
        threshold_alerts(&first),
        1,
        "first full scan above the threshold alerts once: {first:?}"
    );
    assert_eq!(
        health_events(&first),
        1,
        "first full scan writes one health event"
    );
    assert!(
        first
            .iter()
            .any(|event| event["event_type"] == "scanner_error"),
        "new scanner_error documents still emit"
    );
    let scanner_error_count = first
        .iter()
        .find(|event| event["event_type"] == "health")
        .expect("health")["scanner_error_count"]
        .as_u64()
        .expect("scanner_error_count");
    assert!(
        scanner_error_count > above.into(),
        "pre-dedup count is above"
    );
    assert!(harness.latched(), "first crossing sets the latch");

    harness.scan(above, false, false);
    let second = harness.take_events();
    assert_eq!(
        threshold_alerts(&first) + threshold_alerts(&second),
        1,
        "two full scans over the same above-threshold set emit one threshold alert"
    );
    assert_eq!(
        health_events(&first) + health_events(&second),
        1,
        "those scans emit one health event"
    );
    assert_eq!(
        threshold_alerts(&second),
        0,
        "the second scan does not re-alert: {second:?}"
    );
    assert_eq!(
        health_events(&second),
        0,
        "a suppressed repeat does not force a health event"
    );
    assert!(
        !second
            .iter()
            .any(|event| event["event_type"] == "scanner_error"),
        "unchanged scanner_error documents still dedup"
    );
    assert!(harness.latched(), "a later full scan above keeps the latch");

    let at_threshold = u32::try_from(scanner_error_count).expect("count fits u32");
    harness.scan(at_threshold, false, false);
    let recovered = harness.take_events();
    assert_eq!(
        threshold_alerts(&recovered),
        0,
        "a full scan at the threshold does not alert"
    );
    assert!(
        !harness.latched(),
        "a full scan at or below the threshold clears the latch"
    );

    harness.scan(above, false, false);
    let again = harness.take_events();
    assert_eq!(
        threshold_alerts(&again),
        1,
        "the next full scan above alerts again: {again:?}"
    );
    assert_eq!(
        health_events(&again),
        1,
        "a threshold alert that fires writes a health event"
    );
    assert!(harness.latched(), "the new crossing sets the latch again");

    harness.scan(above, true, false);
    let targeted = harness.take_events();
    assert_eq!(
        threshold_alerts(&targeted),
        0,
        "a targeted scan does not emit the threshold alert: {targeted:?}"
    );
    assert!(
        harness.latched(),
        "a targeted scan does not clear a latch set by a full scan"
    );

    harness.scan(above, false, false);
    let after_targeted = harness.take_events();
    assert_eq!(
        threshold_alerts(&after_targeted),
        0,
        "targeted scan must not clear the latch: {after_targeted:?}"
    );
    assert_eq!(
        health_events(&after_targeted),
        0,
        "a suppressed repeat after a targeted scan does not force health"
    );

    harness.scan(above, false, true);
    let backfill = harness.take_events();
    assert_eq!(
        threshold_alerts(&backfill),
        1,
        "backfill while above repeats the alert once: {backfill:?}"
    );
    assert!(harness.latched(), "backfill does not clear the latch");

    harness.scan(above, false, false);
    let after_backfill = harness.take_events();
    assert_eq!(
        threshold_alerts(&after_backfill),
        0,
        "backfill must not clear the latch: {after_backfill:?}"
    );
    assert_eq!(
        health_events(&after_backfill),
        0,
        "a suppressed repeat after backfill does not force health"
    );
}
