use super::*;

#[test]
fn notices_are_static_and_do_not_echo_input_canaries() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("events.jsonl");
    let canary = "SYNTHETIC_FEED_PRIVACY_CANARY";
    fs::write(&path, format!("{{{canary}\n")).expect("journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");
    let batch = feed.poll().expect("poll");
    let display = batch
        .notices
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let debug = format!("{:?}", batch.notices);
    assert!(!display.contains(canary));
    assert!(!debug.contains(canary));
}

#[test]
fn privacy_notice_display_and_debug_are_static() {
    let notice = FeedNotice {
        code: FeedNoticeCode::ParserMalformed,
        count: 2,
    };

    assert_eq!(
        notice.to_string(),
        "local event feed notice: parser_malformed (2)"
    );
    let debug = format!("{notice:?}");
    assert!(debug.contains("ParserMalformed"));
    assert!(debug.contains('2'));
}

#[test]
fn privacy_invalid_limit_errors_display_and_debug_without_input_values() {
    let directory = tempdir().expect("tempdir");
    let path = directory.path().join("SYNTHETIC_FEED_PRIVACY_CANARY.jsonl");
    let invalid_limits = FeedLimits {
        max_events_per_poll: 0,
        ..FeedLimits::default()
    };
    let invalid_limit = LocalEventFeed::new(
        LocalEventFeedConfig::new(&path, StartupMode::Beginning).with_limits(invalid_limits),
    )
    .expect_err("invalid limit");
    let invalid_recent = LocalEventFeed::new(LocalEventFeedConfig::new(
        &path,
        StartupMode::Recent {
            max_events: 0,
            max_bytes: 1,
        },
    ))
    .expect_err("invalid recent limit");

    assert_eq!(invalid_limit.code(), LocalEventFeedErrorCode::InvalidLimit);
    assert_eq!(
        invalid_recent.code(),
        LocalEventFeedErrorCode::InvalidRecentLimit
    );
    assert_eq!(
        invalid_limit.to_string(),
        "local event feed configuration error: invalid_limit"
    );
    assert_eq!(
        invalid_recent.to_string(),
        "local event feed configuration error: invalid_recent_limit"
    );
    for error in [invalid_limit, invalid_recent] {
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains("SYNTHETIC_FEED_PRIVACY_CANARY"));
        assert!(!debug.contains("SYNTHETIC_FEED_PRIVACY_CANARY"));
        assert!(!display.contains(path.to_string_lossy().as_ref()));
        assert!(!debug.contains(path.to_string_lossy().as_ref()));
    }
}

#[test]
fn privacy_parser_notice_mappings_redact_canary_body_and_path() {
    let directory = tempdir().expect("tempdir");
    let path = directory
        .path()
        .join("SYNTHETIC_FEED_PRIVACY_CANARY-events.jsonl");
    let canary = "SYNTHETIC_FEED_PRIVACY_CANARY";
    let cases = vec![
        (
            format!(r#"{{"body":"{canary}""#).into_bytes(),
            FeedNoticeCode::ParserMalformed,
        ),
        (
            replace_once(
                valid_record("telltale-60616263-6465-4066-8067-686970717273"),
                "\"schema_version\":\"3.0\"",
                "\"schema_version\":\"2.0\"",
            ),
            FeedNoticeCode::ParserVersion,
        ),
        (
            replace_once(
                replace_once(
                    valid_record("telltale-74757677-7879-4080-8081-828384858687"),
                    "\"client\":\"synthetic\",",
                    "",
                ),
                "\"source_path_hash\":\"synthetic-hash\"",
                &format!("\"source_path_hash\":\"{canary}\""),
            ),
            FeedNoticeCode::ParserStructure,
        ),
        (
            replace_once(
                replace_once(
                    valid_record("telltale-88898a8b-8c8d-408e-808f-909192939495"),
                    "telltale-88898a8b-8c8d-408e-808f-909192939495",
                    "bad-event-id",
                ),
                "\"client\":\"synthetic\"",
                &format!("\"client\":\"{canary}\""),
            ),
            FeedNoticeCode::ParserIdentity,
        ),
        (
            replace_once(
                replace_once(
                    valid_record("telltale-96979899-0001-4002-8003-040506070809"),
                    "\"time_source\":\"observed\"",
                    "\"time_source\":\"invalid\"",
                ),
                "\"client\":\"synthetic\"",
                &format!("\"client\":\"{canary}\""),
            ),
            FeedNoticeCode::ParserSemantic,
        ),
        (
            replace_once(
                replace_once(
                    valid_record("telltale-10111213-1415-4016-8017-181920212223"),
                    "\"event_type\":\"activity\"",
                    "\"event_type\":\"unknown_family\"",
                ),
                "\"client\":\"synthetic\"",
                &format!("\"client\":\"{canary}\""),
            ),
            FeedNoticeCode::ParserFamily,
        ),
    ];
    let mut contents = Vec::new();
    for (body, expected) in &cases {
        assert_eq!(parser_notice(body), *expected);
        contents.extend_from_slice(body);
        contents.push(b'\n');
    }
    fs::write(&path, &contents).expect("privacy journal");
    let mut feed = LocalEventFeed::from_path(&path, StartupMode::Beginning).expect("config");

    let batch = feed.poll().expect("poll");
    let display = batch
        .notices
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let debug = format!("{:?}", batch.notices);
    let raw = String::from_utf8(contents).expect("synthetic UTF-8");
    let path_text = path.to_string_lossy();

    assert!(batch.records.is_empty());
    assert!(!display.contains(canary));
    assert!(!debug.contains(canary));
    assert!(!display.contains(&raw));
    assert!(!debug.contains(&raw));
    assert!(!display.contains(path_text.as_ref()));
    assert!(!debug.contains(path_text.as_ref()));
}
