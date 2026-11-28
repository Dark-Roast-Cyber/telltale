use super::*;

#[test]
fn canonical_ingress_retention_cap_is_source_wide_and_exact() {
    let text = "x".repeat(65_528);
    let mut observations = (0..128)
        .map(|index| {
            message(
                &format!("n{index}"),
                Some("session"),
                &text,
                CapabilityAvailability::Supported,
            )
        })
        .collect::<Vec<_>>();
    assert!(evaluate(&observations, &plan(0)).is_ok());
    observations.push(message(
        "excess",
        Some("other-session"),
        "x",
        CapabilityAvailability::Supported,
    ));
    assert!(matches!(
        evaluate(&observations, &plan(0)),
        Err(ProcessingError::Bounds)
    ));
}

#[test]
fn retention_budget_accepts_exact_limits_and_rejects_incremental_overage() {
    let mut exact = RetentionBudget::new();
    exact
        .consume(MAX_PROJECTION_ITEMS, MAX_COMPATIBILITY_RETAINED_BYTES)
        .unwrap();
    assert_eq!(exact.consume(1, 0), Err(ProcessingError::Bounds));
    assert_eq!(exact.consume(0, 1), Err(ProcessingError::Bounds));

    let mut incremental = RetentionBudget::new();
    incremental
        .consume(
            MAX_PROJECTION_ITEMS - 1,
            MAX_COMPATIBILITY_RETAINED_BYTES - 1,
        )
        .unwrap();
    incremental.consume(1, 1).unwrap();
}

#[test]
fn event3_projection_budget_failure_is_atomic() {
    // Evaluation remains within its retained-context budget; projection's
    // independent item budget must reject before constructing a partial batch.
    let text = format!("needle {}", "ordinary synthetic text ".repeat(30));
    let observations = (0..2000)
        .map(|index| {
            message(
                &format!("synthetic-{index}"),
                Some("session"),
                &text,
                CapabilityAvailability::Supported,
            )
        })
        .collect::<Vec<_>>();
    let evaluation = evaluate(&observations, &plan(0)).unwrap();
    assert!(matches!(
        super::super::super::event3::project_event3(&evaluation, &context()),
        Err(ProcessingError::Bounds)
    ));
}

#[test]
fn event3_occurrence_modifier_copies_are_preflight_charged() {
    let mut document = "title: synthetic\nid: 2f33e0ea-6afb-4a33-84ae-7fa76ce268cb\nname: synthetic.atomic\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: message\ndetection:\n    selection:\n        - message.user_text|re: 'needle'\n    condition: selection\nlevel: low\ntelltale:\n    category: synthetic\n    score: 1\n    explanation: 'synthetic'\n".to_owned();
    for index in 0..30 {
        document.push_str(&format!("---\ntitle: synthetic {index}\nid: 00000000-0000-4000-8000-{index:012}\nname: chain.synthetic_{index}\ntaxonomy: telltale\ncorrelation:\n    type: telltale_chain\n    rules: [synthetic.atomic]\ntelltale:\n    score: 0\n    explanation: synthetic\n"));
    }
    let plan = compile_rule_v1(
        &telltale_rules::load_rule_set_from_documents(&[&document], None)
            .unwrap()
            .compatibility_export(),
    )
    .unwrap();
    let observations = (0..100)
        .map(|index| {
            message(
                &format!("synthetic-{index}"),
                Some("session"),
                "needle",
                CapabilityAvailability::Supported,
            )
        })
        .collect::<Vec<_>>();
    let evaluation = evaluate(&observations, &plan).unwrap();
    assert!(matches!(
        super::super::super::event3::project_event3(&evaluation, &context()),
        Err(ProcessingError::Bounds)
    ));
}

#[test]
fn source_bounds_are_floors_per_mib_read_up_to_the_ceiling() {
    for bytes in [0, 1, 1024 * 1024] {
        let bounds = SourceBounds::new(SourceScale::for_source_bytes(bytes));
        assert_eq!(bounds.work, MAX_EVALUATION_BYTE_VISITS);
        assert_eq!(bounds.observations, MAX_SOURCE_OBSERVATIONS);
        assert_eq!(bounds.canonical_retained, MAX_CANONICAL_RETAINED_BYTES);
        assert_eq!(bounds.projection_items, MAX_PROJECTION_ITEMS);
        assert_eq!(bounds.compatibility_bytes, MAX_COMPATIBILITY_RETAINED_BYTES);
    }
    let half = SourceBounds::new(SourceScale::for_source_bytes(5 * 512 * 1024));
    assert_eq!(half.work, MAX_EVALUATION_BYTE_VISITS * 5 / 2);
    assert_eq!(half.observations, MAX_SOURCE_OBSERVATIONS * 5 / 2);
    for bytes in [
        MAX_SCALED_SOURCE_BYTES,
        MAX_SCALED_SOURCE_BYTES + 1,
        usize::MAX,
    ] {
        let ceiling = SourceBounds::new(SourceScale::for_source_bytes(bytes));
        assert_eq!(ceiling.work, MAX_EVALUATION_BYTE_VISITS * 64);
        assert_eq!(ceiling.observations, MAX_SOURCE_OBSERVATIONS * 64);
        assert_eq!(
            ceiling.canonical_retained,
            MAX_CANONICAL_RETAINED_BYTES * 64
        );
        assert_eq!(ceiling.projection_items, MAX_PROJECTION_ITEMS * 64);
        assert_eq!(
            ceiling.compatibility_bytes,
            MAX_COMPATIBILITY_RETAINED_BYTES * 64
        );
    }
}

#[test]
fn scaled_retention_admits_a_larger_source_and_keeps_its_exact_limit() {
    // Just over the 8 MiB floor of canonical retention, as in
    // canonical_ingress_retention_cap_is_source_wide_and_exact.
    let text = "x".repeat(65_528);
    let observations = (0..129)
        .map(|index| {
            message(
                &format!("n{index}"),
                Some("session"),
                &text,
                CapabilityAvailability::Supported,
            )
        })
        .collect::<Vec<_>>();
    let retained = observations
        .iter()
        .map(CanonicalObservationV2::retained_byte_len)
        .sum::<usize>();
    assert!(retained > MAX_CANONICAL_RETAINED_BYTES);
    assert!(matches!(
        evaluate(&observations, &plan(0)),
        Err(ProcessingError::Bounds)
    ));
    let mut retention = RetentionBudget::with_work(
        std::sync::Arc::default(),
        SourceScale::for_source_bytes(2 * 1024 * 1024),
    );
    retention
        .consume(
            MAX_PROJECTION_ITEMS * 2,
            MAX_COMPATIBILITY_RETAINED_BYTES * 2,
        )
        .unwrap();
    assert_eq!(retention.consume(1, 0), Err(ProcessingError::Bounds));
    assert_eq!(retention.consume(0, 1), Err(ProcessingError::Bounds));
    // Two MiB read allows 16 MiB of canonical retention.
    let (scaled, work) = evaluate_scaled(&observations, 2 * 1024 * 1024);
    scaled.expect("scaled retention");
    assert!(!work.is_exhausted());
}

#[test]
fn scaled_work_stays_proportional_for_costly_input() {
    // The repeated punctuation URLs of
    // repeated_punctuation_urls_exhaust_source_work_without_private_output:
    // about 4 MiB that costs about 200 byte visits per byte.
    let text = format!(
        "https://example.invalid/{}?token=SYNTHETIC-PUNCT-SECRET&needle=1",
        ":".repeat(4_000)
    );
    let observations = (0..1_024)
        .map(|index| {
            message(
                &format!("url{index}"),
                Some("session"),
                &text,
                CapabilityAvailability::Supported,
            )
        })
        .collect::<Vec<_>>();
    let bytes = text.len() * observations.len();
    let (own, work) = evaluate_scaled(&observations, bytes);
    own.expect("work within its own bytes' budget");
    assert!(work.used_bytes() > MAX_EVALUATION_BYTE_VISITS * 3);
    // The budget follows bytes read, not the work the input asks for: the
    // same observations credited with a third of their bytes exhaust it.
    let (short, work) = evaluate_scaled(&observations, bytes / 3);
    assert_eq!(short.err(), Some(ProcessingError::Bounds));
    assert!(work.is_exhausted(), "not a compatibility retention failure");
}
