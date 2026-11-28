use super::*;

#[test]
fn failed_cleanup_reports_successful_append_and_keeps_pruning() {
    let directory = tempfile::tempdir().unwrap();
    let active = directory.path().join("records.jsonl");
    let unremovable = directory.path().join("records-2026-11-25.jsonl");
    let removable = directory.path().join("records-2026-11-26.jsonl");
    // Discovery had already planned cleanup. An archive can change
    // before removal; the reader's safe discovery must still reject it.
    fs::create_dir(&unremovable).unwrap();
    fs::write(&removable, b"synthetic archive\n").unwrap();
    let mut file = Sink::new(active.clone()).open_active().unwrap();
    let line = b"{\"synthetic\":true}\n";
    let result = append_and_prune(
        &mut file,
        line,
        vec![unremovable.clone(), removable.clone()],
    );
    assert_eq!(fs::read(active).unwrap(), line);
    assert!(unremovable.is_dir());
    assert!(!removable.exists());
    result.unwrap();
}
