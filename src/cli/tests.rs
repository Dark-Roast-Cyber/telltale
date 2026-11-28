use std::io::Cursor;

use super::observe_executable;

#[test]
fn executable_observation_streams_a_sha256_digest() {
    let observation = observe_executable(Ok(std::path::PathBuf::from("/tmp/telltale")), |_| {
        Ok(Box::new(Cursor::new(b"telltale-test".to_vec())))
    });

    assert_eq!(observation.status, "complete");
    assert_eq!(observation.path_hash.as_deref().unwrap().len(), 64);
    assert_eq!(
        observation.sha256.as_deref(),
        Some("95b5d3baf14cb332b2b1c62ca30438787685666fd1be1817bd469a845f4425c7")
    );
}

#[test]
fn executable_observation_degrades_without_error_text() {
    let unavailable = observe_executable(
        Err(std::io::Error::other("private failure detail")),
        |_| unreachable!(),
    );
    assert_eq!(unavailable.status, "current_exe_unavailable");
    assert_eq!(unavailable.path_hash, None);
    assert_eq!(unavailable.sha256, None);

    let unreadable = observe_executable(Ok(std::path::PathBuf::from("/tmp/telltale")), |_| {
        Err(std::io::Error::other("private failure detail"))
    });
    assert_eq!(unreadable.status, "executable_read_failed");
    assert_eq!(unreadable.sha256, None);
}

#[cfg(test)]
mod runtime_dispatch;
