use super::*;

#[derive(serde::Serialize)]
struct Sample {
    value: u64,
}

fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn appends_one_line_per_record_and_creates_the_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nested").join("diagnostics.jsonl");
    append_record(&path, &Sample { value: 1 }).expect("first");
    append_record(&path, &Sample { value: 2 }).expect("second");
    assert_eq!(lines(&path), [r#"{"value":1}"#, r#"{"value":2}"#]);
}

#[test]
fn rotates_to_one_generation_before_exceeding_the_bound() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("diagnostics.jsonl");
    let rotated = rotated_path(&path);
    std::fs::write(&rotated, "old generation\n").expect("old generation");
    let full = "x".repeat(MAX_FILE_BYTES as usize - 4) + "\n";
    std::fs::write(&path, &full).expect("full file");

    append_record(&path, &Sample { value: 3 }).expect("rotating append");

    assert_eq!(lines(&path), [r#"{"value":3}"#]);
    assert_eq!(std::fs::read_to_string(&rotated).expect("rotated"), full);
}

#[test]
fn refuses_an_oversized_record_without_touching_the_file() {
    #[derive(serde::Serialize)]
    struct Large {
        text: String,
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("diagnostics.jsonl");
    let record = Large {
        text: "x".repeat(MAX_RECORD_BYTES),
    };
    assert_eq!(append_record(&path, &record), Err(WriteFailure::TooLarge));
    assert!(!path.exists());
}

#[test]
fn a_directory_in_place_of_the_file_is_an_unsafe_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("diagnostics.jsonl");
    std::fs::create_dir(&path).expect("directory");
    assert_eq!(
        append_record(&path, &Sample { value: 1 }),
        Err(WriteFailure::UnsafeTarget)
    );
}

#[test]
fn a_file_in_place_of_the_directory_cannot_be_opened() {
    let dir = tempfile::tempdir().expect("tempdir");
    let parent = dir.path().join("not-a-directory");
    std::fs::write(&parent, "").expect("file");
    assert_eq!(
        append_record(&parent.join("diagnostics.jsonl"), &Sample { value: 1 }),
        Err(WriteFailure::Open)
    );
}

#[cfg(unix)]
#[test]
fn symbolic_links_are_refused_for_the_file_and_its_generation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("elsewhere.jsonl");
    std::fs::write(&target, "").expect("target");
    let path = dir.path().join("diagnostics.jsonl");
    std::os::unix::fs::symlink(&target, &path).expect("link");
    assert_eq!(
        append_record(&path, &Sample { value: 1 }),
        Err(WriteFailure::UnsafeTarget)
    );
    assert_eq!(std::fs::read_to_string(&target).expect("target"), "");

    std::fs::remove_file(&path).expect("unlink");
    std::fs::write(&path, "x".repeat(MAX_FILE_BYTES as usize)).expect("full");
    std::os::unix::fs::symlink(&target, rotated_path(&path)).expect("generation link");
    // A link in place of the generation is replaced, never written through.
    append_record(&path, &Sample { value: 1 }).expect("rotating append");
    assert_eq!(std::fs::read_to_string(&target).expect("target"), "");
    assert!(
        std::fs::symlink_metadata(rotated_path(&path))
            .expect("generation")
            .is_file()
    );
}

#[test]
fn failure_classes_are_fixed_words() {
    for failure in [
        WriteFailure::Overlap,
        WriteFailure::UnsafeTarget,
        WriteFailure::TooLarge,
        WriteFailure::Rotate,
        WriteFailure::Open,
        WriteFailure::Write,
    ] {
        let word = failure.as_str();
        assert!(
            word.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        );
    }
}
