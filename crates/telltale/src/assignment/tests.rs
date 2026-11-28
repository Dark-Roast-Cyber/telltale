#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Barrier};
#[cfg(target_os = "linux")]
use std::thread;

#[cfg(target_os = "linux")]
use rusqlite::Connection;
#[cfg(target_os = "linux")]
use telltale_schema::observation::{
    FactMetadata, FactProvenance, Fidelity, IngestionMode, JsonValue, MessageObservation,
    MessageRole, ObservationBody, ObservationStage, ObservedAt, Sensitivity, SourceProvenance,
    ToolObservation,
};

use super::*;

#[cfg(target_os = "linux")]
const OBSERVED_AT: &str = "2026-09-06T12:00:00Z";

#[cfg(target_os = "linux")]
fn private_root(temp: &tempfile::TempDir) -> PathBuf {
    temp.path().join("protected-assignment")
}

#[cfg(target_os = "linux")]
fn tool_builder(name: &str) -> ObservationBuilder {
    CanonicalObservationV2::builder(
        ObservationBody::Tool(ToolObservation::new().with_name(name).unwrap()),
        ObservationStage::ToolProposed,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        SourceProvenance::new(
            IngestionMode::SessionStore,
            "synthetic",
            "coordinate-less",
            Fidelity::FullNative,
        )
        .unwrap(),
    )
    .fact_metadata("tool.name", FactMetadata::reported().unwrap())
}

#[cfg(target_os = "linux")]
fn association(locator: &[u8]) -> ReplayAssociation {
    ReplayAssociation::new(
        AssignmentAdapterDomain::registered("synthetic", "coordinate-less").unwrap(),
        "synthetic-record:v1",
        locator,
    )
    .unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn process_level_claims_converge() {
    use std::env;
    use std::process::{Command, Stdio};

    if let (Ok(root), Ok(output)) = (
        env::var("TELLTALE_ASSIGNMENT_CHILD_ROOT"),
        env::var("TELLTALE_ASSIGNMENT_CHILD_OUTPUT"),
    ) {
        let mut store = ProtectedAssignmentStore::open(PathBuf::from(root)).unwrap();
        let claimed = store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        fs::write(output, claimed.observation_id()).unwrap();
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let root = private_root(&temp);
    drop(ProtectedAssignmentStore::initialize(&root).unwrap());
    let outputs = [temp.path().join("first.id"), temp.path().join("second.id")];
    let children = outputs
        .iter()
        .map(|output| {
            Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "assignment::tests::process_level_claims_converge",
                ])
                .env("TELLTALE_ASSIGNMENT_CHILD_ROOT", &root)
                .env("TELLTALE_ASSIGNMENT_CHILD_OUTPUT", output)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let statuses = children
        .into_iter()
        .map(|mut child| child.wait().unwrap())
        .collect::<Vec<_>>();
    assert!(statuses.iter().all(|status| status.success()));
    let ids = outputs
        .iter()
        .map(|output| fs::read_to_string(output).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ids[0], ids[1]);
    let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM assignments", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platforms_fail_before_state_creation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("protected-assignment");
    assert_eq!(
        ProtectedAssignmentStore::initialize(&root)
            .unwrap_err()
            .code(),
        "unsupported_platform"
    );
    assert!(!root.exists());
    assert_eq!(
        ProtectedAssignmentStore::open(&root).unwrap_err().code(),
        "unsupported_platform"
    );
    assert!(!root.exists());
}

mod claims;
#[cfg(target_os = "linux")]
mod concurrency;
#[cfg(target_os = "linux")]
mod key_rotation;
#[cfg(target_os = "linux")]
mod storage_integrity;
#[cfg(target_os = "linux")]
mod store_safety;
