use tempfile::tempdir;

use super::{
    Outbox, WINDOWS_DURABLE_STORAGE_UNSUPPORTED, acquire_admission_lock_for_platform,
    ensure_durable_storage_supported, ensure_durable_storage_supported_for_platform,
};
use crate::sink::{DeliveryError, DeliveryErrorClass};

fn assert_windows_storage_error(error: Box<dyn std::error::Error>) {
    let delivery = error
        .downcast_ref::<DeliveryError>()
        .expect("Windows durable policy must return a structured delivery error");
    assert_eq!(delivery.class, DeliveryErrorClass::DurableStorage);
    assert_eq!(delivery.attempts, 0);
    assert!(
        error
            .to_string()
            .contains(WINDOWS_DURABLE_STORAGE_UNSUPPORTED)
    );
}

#[test]
fn durable_storage_policy_allows_non_windows_platforms() {
    ensure_durable_storage_supported_for_platform(false)
        .expect("non-Windows durable storage policy");
}

#[test]
fn current_platform_uses_cfg_selected_durable_storage_policy() {
    if cfg!(windows) {
        let error = ensure_durable_storage_supported()
            .expect_err("Windows durable storage must be rejected");
        assert_windows_storage_error(error);
    } else {
        ensure_durable_storage_supported().expect("non-Windows durable storage policy");
    }
}

#[test]
fn simulated_windows_outbox_open_and_admission_reject_before_parent_creation() {
    let temp = tempdir().expect("temporary directory");
    let outbox_path = temp.path().join("private").join("outbox.sqlite");

    let error = Outbox::open_for_platform(&outbox_path, true)
        .expect_err("Windows durable outbox open must be rejected");
    assert_windows_storage_error(error);
    assert!(!outbox_path.parent().expect("outbox parent").exists());
    assert!(!outbox_path.exists());

    let error = match acquire_admission_lock_for_platform(&outbox_path, true) {
        Ok(_) => panic!("Windows durable admission must be rejected"),
        Err(error) => error,
    };
    assert_windows_storage_error(error);
    assert!(!outbox_path.parent().expect("outbox parent").exists());
    assert!(!outbox_path.exists());
}

#[test]
fn simulated_windows_read_only_health_open_rejects_before_inspection() {
    let temp = tempdir().expect("temporary directory");
    let outbox_path = temp.path().join("private").join("outbox.sqlite");

    let error = Outbox::open_read_only_for_platform(&outbox_path, true)
        .expect_err("Windows durable health open must be rejected");
    assert_windows_storage_error(error);
    assert!(!outbox_path.parent().expect("outbox parent").exists());
    assert!(!outbox_path.exists());
}

#[cfg(windows)]
#[test]
fn native_windows_outbox_open_rejects_without_creating_artifacts() {
    let temp = tempdir().expect("temporary directory");
    let outbox_path = temp.path().join("private").join("outbox.sqlite");

    let error = Outbox::open(&outbox_path).expect_err("Windows durable storage must fail closed");
    assert_windows_storage_error(error);
    assert!(!outbox_path.parent().expect("outbox parent").exists());
    assert!(!outbox_path.exists());
}
