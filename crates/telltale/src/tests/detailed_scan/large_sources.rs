use super::*;

#[test]
fn single_sources_past_the_floor_scan_completely() {
    // Today's floor stops this mix at about 3.3 MiB on its evaluation work.
    let root = tempfile::tempdir().unwrap();
    let pipeline = Pipeline::builder().build().unwrap();
    for client in [ClientId::Claude, ClientId::Codex] {
        let text = large_session(client, 4 * 1024 * 1024, 100);
        let source = large_source(root.path(), client, &text);
        let scans = pipeline
            .scan_sources_detailed(&[source], &DetailedEvaluationOptions::default())
            .unwrap();
        assert_whole_large_source(&scans[0], &text, 100);
    }
}

#[test]
#[ignore = "opt-in: four 64 MiB sources; run with --release -- --ignored"]
fn sixty_four_mib_single_sources_scan_completely() {
    use telltale_schema::event::{EVENT3_MAX_INPUT_BYTES, EVIDENCE_OMITTED_FIELD};
    let root = tempfile::tempdir().unwrap();
    let pipeline = Pipeline::builder().build().unwrap();
    let mut options = DetailedEvaluationOptions::default();
    options.process_chain = true;
    // A block every 1,000 rows fits the session's detection event whole; a
    // block every 100 rows exceeds 1 MiB of evidence, which the event omits
    // and marks.
    for (hits, dense) in [(1_000, false), (100, true)] {
        for client in [ClientId::Claude, ClientId::Codex] {
            let text = large_session(
                client,
                telltale_schema::observation::MAX_SCALED_SOURCE_BYTES,
                hits,
            );
            assert!(text.len() > telltale_schema::observation::MAX_SCALED_SOURCE_BYTES - 4096);
            let source = large_source(root.path(), client, &text);
            let scans = pipeline.scan_sources_detailed(&[source], &options).unwrap();
            assert_whole_large_source(&scans[0], &text, hits);
            let detection = scans[0]
                .events
                .iter()
                .find(|event| event.event_type == "detection")
                .expect("session detection event");
            assert!(serde_json::to_vec(detection).unwrap().len() <= EVENT3_MAX_INPUT_BYTES);
            let marked = detection
                .evidence
                .iter()
                .any(|item| item.field == EVIDENCE_OMITTED_FIELD);
            assert_eq!(marked, dense, "{client:?} every {hits} rows");
        }
    }
}

#[test]
fn larger_sources_keep_the_top_bounds_and_dense_units_fail_at_acquisition() {
    let root = tempfile::tempdir().unwrap();
    let pipeline = Pipeline::builder().build().unwrap();
    // Blank 1 MiB records past the 64 MiB level, then a small session. Bounds
    // stop growing at 64 MiB, and this source fits them.
    let mut blank = vec![b' '; 1024 * 1024];
    *blank.last_mut().unwrap() = b'\n';
    for client in [ClientId::Claude, ClientId::Codex] {
        let session = large_session(client, 64 * 1024, 100);
        let mut text = blank.repeat(65);
        text.extend_from_slice(session.as_bytes());
        let source = large_source(root.path(), client, "");
        std::fs::write(&source.path, &text).unwrap();
        let scans = pipeline
            .scan_sources_detailed(&[source], &DetailedEvaluationOptions::default())
            .unwrap();
        assert!(scans[0].failure().is_none(), "{:?}", scans[0].failure());
        assert_eq!(scans[0].coverage(), Some(SourceCoverage::WholeSource));
        assert!(!scans[0].action_records().is_empty());
    }
    // 1.5 MiB of three-byte records: five times the native units its bytes
    // allow. The read fails with its existing code.
    let source = large_source(root.path(), ClientId::Claude, "");
    std::fs::write(&source.path, b"{}\n".repeat(524_288)).unwrap();
    let scans = pipeline
        .scan_sources_detailed(&[source], &DetailedEvaluationOptions::default())
        .unwrap();
    let failure = scans[0].failure().expect("source fails");
    assert_eq!(failure.stage(), SourceFailureStage::Acquisition);
    assert_eq!(
        failure.acquisition_error(),
        Some(AcquisitionError::SourceRead)
    );
    assert_eq!(scans[0].coverage(), None);
}
