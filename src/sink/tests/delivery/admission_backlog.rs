use super::*;

#[test]
fn slow_http_backlog_does_not_delay_fresh_first_write_by_backlog_length() {
    use std::io::Write;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};
    let directory = tempdir().unwrap();
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let backlog = (0..100).map(|_| make_health_event()).collect::<Vec<_>>();
    LocalJsonlSink::with_rotation(&log_path, RotationConfig::disabled())
        .emit(&backlog)
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/ingest", listener.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = std::thread::spawn(move || {
        let mut requests = 0;
        while !server_stop.load(Ordering::Relaxed) {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            read_mock_request(&mut stream);
            std::thread::sleep(Duration::from_millis(50));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{\"code\":0}").unwrap();
            requests += 1;
        }
        requests
    });
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort(
        "splunk_hec",
        Box::new(
            super::super::super::SplunkHecHttpSink::new(
                endpoint,
                "synthetic".into(),
                super::super::super::SplunkHecConfig::default(),
            )
            .with_name("remote"),
        ),
    );
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".into()],
        capacity_limits(1000, u64::MAX),
    );
    let fresh = make_health_event();
    let started = Instant::now();
    let admitted = sinks.persist_for_durable_replay(std::slice::from_ref(&fresh));
    let latency = started.elapsed();
    stop.store(true, Ordering::Relaxed);
    let requests = server.join().unwrap();
    admitted.unwrap();
    assert!((1..=16).contains(&requests));
    assert!(
        latency < Duration::from_secs(2),
        "first-write latency: {latency:?}"
    );
    assert!(
        fs::read_to_string(&log_path)
            .unwrap()
            .contains(&fresh.event_id)
    );
    let outbox = Outbox::open(&outbox_path).unwrap();
    assert_eq!(
        outbox
            .get_delivery(&fresh.event_id, "remote")
            .unwrap()
            .unwrap()
            .state,
        DeliveryState::Pending
    );
    assert!(backlog.iter().any(|event| {
        outbox
            .get_delivery(&event.event_id, "remote")
            .unwrap()
            .unwrap()
            .state
            == DeliveryState::Pending
    }));
    eprintln!(
        "synthetic backlog=100 delay=50ms requests={requests} first_write_ms={}",
        latency.as_millis()
    );
}

#[test]
fn full_pending_queue_drains_before_new_admission() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = make_health_event();
    let second = make_health_event();
    let (remote, calls) = ScriptedDurableSink::new(
        "remote",
        [ScriptedOutcome::Success, ScriptedOutcome::Success],
    );
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort_with_retry("synthetic", Box::new(remote), retry_config(3, 1));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(1, u64::MAX),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&first))
        .expect("admit first event");
    let failures = sinks
        .persist_for_durable_replay_with_failures(std::slice::from_ref(&second))
        .expect("drain first event before admitting second");
    assert!(failures.is_empty());
    assert_eq!(calls.lock().expect("calls lock").len(), 1);

    let outbox = Outbox::open(&outbox_path).expect("reopen outbox");
    assert_eq!(
        outbox
            .get_delivery(&first.event_id, "remote")
            .expect("first delivery")
            .expect("first row")
            .state,
        DeliveryState::Acked
    );
    assert_eq!(
        outbox
            .get_delivery(&second.event_id, "remote")
            .expect("second delivery")
            .expect("second row")
            .state,
        DeliveryState::Pending
    );
    drop(outbox);

    sinks.deliver_durable().expect("drain newly admitted event");
    assert_eq!(calls.lock().expect("calls lock").len(), 2);
}

#[test]
fn blocked_delivery_stays_blocked_until_release_then_drains_before_admission() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    let first = make_health_event();
    let second = make_health_event();
    let (remote, calls) = ScriptedDurableSink::new(
        "remote",
        [
            ScriptedOutcome::Failure(DeliveryErrorClass::AuthenticationBlocked { status: 403 }),
            ScriptedOutcome::Success,
            ScriptedOutcome::Success,
        ],
    );
    let mut sinks = SinkSet::new();
    sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    sinks.add_best_effort_with_retry("synthetic", Box::new(remote), retry_config(3, 1));
    sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(1, u64::MAX),
    );

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&first))
        .expect("admit first event");
    let before = fs::read(&log_path).expect("canonical JSONL before blocked admission");
    let error = sinks
        .persist_for_durable_replay(std::slice::from_ref(&second))
        .expect_err("blocked work must keep the queue full");
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("structured capacity error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert_eq!(
        fs::read(&log_path).expect("canonical JSONL after blocked rejection"),
        before
    );
    assert_eq!(calls.lock().expect("calls lock").len(), 1);
    {
        let outbox = Outbox::open(&outbox_path).expect("reopen blocked outbox");
        assert_eq!(
            outbox
                .get_delivery(&first.event_id, "remote")
                .expect("blocked delivery")
                .expect("blocked row")
                .state,
            DeliveryState::Blocked
        );
        assert!(
            outbox
                .get_delivery(&second.event_id, "remote")
                .expect("rejected delivery")
                .is_none()
        );
    }

    let mut outbox = Outbox::open(&outbox_path).expect("open blocked outbox for release");
    assert_eq!(
        outbox
            .release_blocked_for_sink("remote", super::super::super::outbox::unix_millis())
            .expect("release blocked sink"),
        1
    );
    drop(outbox);

    sinks
        .persist_for_durable_replay(std::slice::from_ref(&second))
        .expect("release drains before admitting second event");
    assert_eq!(calls.lock().expect("calls lock").len(), 2);
    let outbox = Outbox::open(&outbox_path).expect("reopen released outbox");
    assert_eq!(
        outbox
            .get_delivery(&first.event_id, "remote")
            .expect("released first delivery")
            .expect("released first row")
            .state,
        DeliveryState::Acked
    );
    assert_eq!(
        outbox
            .get_delivery(&second.event_id, "remote")
            .expect("second delivery")
            .expect("second row")
            .state,
        DeliveryState::Pending
    );
}

#[test]
fn concurrent_same_pair_admission_is_capacity_bounded_and_cursor_consistent() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("events.jsonl");
    let outbox_path = directory.path().join("private-outbox/outbox.sqlite");
    drop(Outbox::open(&outbox_path).expect("initialize shared outbox before concurrent admission"));
    let first = make_health_event();
    let second = make_health_event();
    let first_id = first.event_id.clone();
    let second_id = second.event_id.clone();

    // Persistence-only admission cannot free capacity through predrain,
    // even when the threads acquire ownership sequentially.
    let mut first_sinks = SinkSet::new();
    first_sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    first_sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(1, u64::MAX),
    );

    let mut second_sinks = SinkSet::new();
    second_sinks.add_canonical_first_write_path_with_rotation(
        "jsonl",
        Box::new(LocalJsonlSink::with_rotation(
            &log_path,
            RotationConfig::disabled(),
        )),
        log_path.clone(),
        None,
    );
    second_sinks.enable_persistent_replay_with_capacity(
        outbox_path.clone(),
        vec!["remote".to_string()],
        capacity_limits(1, u64::MAX),
    );

    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let first_handle = std::thread::spawn(move || {
        first_barrier.wait();
        classify_admission(first_sinks.persist_for_durable_replay(&[first]))
    });
    let second_barrier = Arc::clone(&barrier);
    let second_handle = std::thread::spawn(move || {
        second_barrier.wait();
        classify_admission(second_sinks.persist_for_durable_replay(&[second]))
    });
    barrier.wait();
    let results = [
        first_handle.join().expect("first admission thread"),
        second_handle.join().expect("second admission thread"),
    ];

    assert_eq!(
        results.iter().filter(|result| result.0).count(),
        1,
        "admission results: {results:?}"
    );
    let loser = results
        .iter()
        .find(|result| !result.0)
        .expect("one admission must lose");
    assert_eq!(
        loser.1,
        Some(DeliveryErrorClass::DurableStorage),
        "admission results: {results:?}"
    );
    assert!(!loser.2.is_empty(), "admission results: {results:?}");

    let bytes = fs::read(&log_path).expect("canonical JSONL after contention");
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
    let admitted_id = serde_json::from_slice::<serde_json::Value>(
        bytes.strip_suffix(b"\n").expect("newline-terminated event"),
    )
    .expect("admitted event JSON")
    .get("event_id")
    .and_then(serde_json::Value::as_str)
    .expect("admitted event ID")
    .to_string();
    assert!(admitted_id == first_id || admitted_id == second_id);

    let outbox = Outbox::open(&outbox_path).expect("reopen contended outbox");
    assert!(
        outbox
            .get_event(&admitted_id)
            .expect("admitted event lookup")
            .is_some()
    );
    let rejected_id = if admitted_id == first_id {
        second_id
    } else {
        first_id
    };
    assert!(
        outbox
            .get_event(&rejected_id)
            .expect("rejected event lookup")
            .is_none()
    );
    assert_eq!(
        outbox
            .ingest_cursor()
            .expect("contention cursor lookup")
            .expect("contention cursor")
            .byte_offset,
        bytes.len() as u64
    );
}
