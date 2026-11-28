use super::*;

#[test]
fn marker_checker_reports_only_case_field_and_marker_id() {
    let marker = ControlledMarker {
        id: "assignment",
        value: "TT_PRIVACY_CHECKER_25",
    };
    let error = check_serialized_event_markers(
        br#"{"evidence":[{"redacted_value":"TT_PRIVACY_CHECKER_25"}]}"#,
        "checker-case",
        &[marker],
    )
    .expect_err("controlled marker must be found");

    assert_eq!(
        error.to_string(),
        "privacy marker check failed for case checker-case, field $.<key>[0].<key>, marker assignment"
    );
}

#[test]
fn marker_checker_catches_keys_and_duplicate_key_values() {
    let marker = ControlledMarker {
        id: "marker",
        value: "TT_PRIVACY_DUPLICATE_25",
    };

    assert!(
        check_serialized_event_markers(
            br#"{"TT_PRIVACY_DUPLICATE_25":"safe"}"#,
            "key-case",
            &[marker],
        )
        .is_err()
    );
    assert!(
        check_serialized_event_markers(
            br#"{"evidence":"TT_PRIVACY_DUPLICATE_25","evidence":"safe"}"#,
            "duplicate-case",
            &[marker],
        )
        .is_err()
    );
}

#[test]
fn marker_checker_has_safe_input_and_depth_limits_and_stops_after_a_match() {
    let marker = ControlledMarker {
        id: "limit-marker",
        value: "tt_privacy_marker_checker_25",
    };
    let oversized = vec![b' '; MAX_SERIALIZED_EVENT_BYTES + 1];
    let size_error = check_serialized_event_markers(&oversized, "size-case", &[marker])
        .expect_err("oversized serialized input must be rejected");
    assert_eq!(
        size_error.to_string(),
        "privacy marker check failed for case size-case: serialized input exceeds the safe limit"
    );

    let too_deep = format!(
        "{}null{}",
        "[".repeat(MAX_MARKER_DEPTH + 1),
        "]".repeat(MAX_MARKER_DEPTH + 1)
    );
    let depth_error = check_serialized_event_markers(too_deep.as_bytes(), "depth-case", &[marker])
        .expect_err("over-nested serialized input must be rejected");
    assert_eq!(
        depth_error.to_string(),
        "privacy marker check failed for case depth-case: serialized input exceeds the safe nesting limit"
    );

    let early_error = check_serialized_event_markers(
        br#"{"evidence":"tt_privacy_marker_checker_25",invalid"#,
        "early-case",
        &[marker],
    )
    .expect_err("marker must be reported before a later malformed suffix");
    assert!(matches!(
        early_error,
        SerializedMarkerCheckError::MarkerFound { .. }
    ));
}

#[test]
fn high_confidence_markers_match_session_one_patterns_and_near_misses_do_not() {
    for marker in [
        "ghp_12345678",
        "SK-abcdefgh",
        "akia1234567890AB",
        "XOXB-12345678",
        "eYj_12345678.segment_5678.segment_9012",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ] {
        assert!(contains_high_confidence_credential_marker(marker));
    }
    for near_miss in [
        "ghp_1234567",
        "sk-1234567",
        "AKIA1234567890A",
        "xoxb-1234567",
        "segment_1234.segment_5678.segment_9012",
        "-----BEGIN OPENSSH PUBLIC KEY-----",
    ] {
        assert!(!contains_high_confidence_credential_marker(near_miss));
    }
}
