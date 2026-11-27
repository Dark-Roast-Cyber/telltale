use super::*;
use crate::acquisition::MAX_CONTRIBUTION_KEYS;

#[test]
fn tool_usage_is_bounded_checked_and_private() {
    let mut builder = AccountingBuilder::default();
    builder
        .record(Some("s"), &Ok(SessionMetadata::default()), &[])
        .unwrap();
    builder
        .tool_usage(Some("s"), RecordKind::ToolCall, Some("private-tool"), None)
        .unwrap();
    builder
        .tool_usage(
            Some("s"),
            RecordKind::ToolCall,
            Some("private-tool"),
            Some("2026-09-20T02:00:00Z"),
        )
        .unwrap();
    builder
        .tool_usage(
            Some("s"),
            RecordKind::ToolCall,
            Some("private-tool"),
            Some("2026-09-20T01:00:00Z"),
        )
        .unwrap();
    let counts = &mut builder.sessions.get_mut("s").unwrap().counts;
    assert_eq!(counts.tool_usage["private-tool"].count, 3);
    assert_eq!(counts.tool_usage["private-tool"].first_order, 1);
    assert_eq!(
        counts.tool_usage["private-tool"]
            .first_timestamp
            .as_ref()
            .unwrap()
            .0,
        2
    );
    assert!(!format!("{counts:?}").contains("private-tool"));
    counts.tool_usage.get_mut("private-tool").unwrap().count = u64::MAX;
    assert_eq!(
        builder.tool_usage(Some("s"), RecordKind::ToolCall, Some("private-tool"), None),
        Err(AcquisitionError::AccountingOverflow)
    );
    builder.tool_usage_keys = MAX_CONTRIBUTION_KEYS;
    assert_eq!(
        builder.tool_usage(
            Some("s"),
            RecordKind::ToolCall,
            Some("new-private-tool"),
            None
        ),
        Err(AcquisitionError::ContributionCapacity)
    );
}

#[test]
fn contribution_capacity_is_source_wide_including_unscoped() {
    let mut builder = AccountingBuilder::default();
    for index in 0..MAX_CONTRIBUTION_KEYS {
        let session = format!("s-{}", index % 2);
        builder
            .record(Some(&session), &Ok(SessionMetadata::default()), &[])
            .unwrap();
        builder
            .contribute(
                Some(&session),
                RecordKind::ToolCall,
                Some(&format!("synthetic-{index}")),
                None,
                [],
            )
            .unwrap();
    }
    builder
        .record(None, &Ok(SessionMetadata::default()), &[])
        .unwrap();
    assert_eq!(
        builder.contribute(None, RecordKind::ToolCall, Some("synthetic"), None, []),
        Err(AcquisitionError::ContributionCapacity)
    );
    assert_eq!(builder.contribution_keys, MAX_CONTRIBUTION_KEYS);
    assert!(builder.unscoped.contributions.tool_calls.is_empty());
}

#[test]
fn overflow_and_capacity_fail_without_private_diagnostics() {
    let mut counts = NativeCounts {
        native_units: u64::MAX,
        ..Default::default()
    };
    assert_eq!(
        counts.add_unit(&[]),
        Err(AcquisitionError::AccountingOverflow)
    );
    let mut counts = RecordCounts {
        tool_call: u64::MAX,
        ..Default::default()
    };
    assert_eq!(
        counts.increment(RecordKind::ToolCall),
        Err(AcquisitionError::AccountingOverflow)
    );
    let mut builder = AccountingBuilder::default();
    for index in 0..MAX_ATTESTED_SESSIONS {
        builder
            .record(
                Some(&format!("synthetic-{index}")),
                &Ok(SessionMetadata::default()),
                &[],
            )
            .unwrap();
    }
    assert_eq!(
        builder.record(Some("private-marker"), &Ok(SessionMetadata::default()), &[]),
        Err(AcquisitionError::AttestationCapacity)
    );
}
