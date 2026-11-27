//! The new crate is independently callable without acquisition or detection.

#[cfg(not(any(unix, windows)))]
use telltale_discover::inventory::InventoryErrorKind;
use telltale_discover::inventory::{InventoryContext, InventoryLimits, Platform, discover};
#[cfg(any(unix, windows))]
use telltale_discover::record::{
    CandidateOutcome, InstallationAssessment, LocatorQualification, NotImplemented,
};

#[test]
fn inventory_works_without_tokens_or_supported_detection_sources() {
    let parent = std::env::temp_dir().canonicalize().unwrap();
    let root = tempfile::tempdir_in(parent).unwrap();
    std::fs::create_dir_all(root.path().join(".pi").join("agent").join("sessions")).unwrap();
    // The candidate is home-relative on every platform; name the one running.
    let platform = if cfg!(windows) {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Linux
    };
    let context = InventoryContext::from_home(root.path().to_owned(), platform);
    let result = discover(&context, 1234, InventoryLimits::default());
    #[cfg(any(unix, windows))]
    {
        let snapshot = result.unwrap();
        assert_eq!(snapshot.entries().len(), 61);
        let pi = snapshot
            .entries()
            .iter()
            .find(|entry| entry.id() == "pi")
            .unwrap();
        assert_eq!(
            pi.candidates()[0].outcome(),
            CandidateOutcome::IndicatorPresent
        );
        for entry in snapshot.entries() {
            assert_eq!(entry.installation(), InstallationAssessment::NotAssessed);
            assert_eq!(entry.usage(), NotImplemented::NotImplemented);
            assert_eq!(
                entry.locator_qualification(),
                LocatorQualification::UpstreamCandidateOnly
            );
            assert_eq!(entry.additional_locations(), NotImplemented::NotImplemented);
            assert_eq!(
                entry.environment_relocations(),
                NotImplemented::NotImplemented
            );
            assert_eq!(entry.scanner_patterns(), NotImplemented::NotImplemented);
        }
        let wire = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(wire["schema"], "telltale.inventory/v1");
        assert_eq!(wire["entries"][0]["usage"], "not_implemented");
    }
    #[cfg(not(any(unix, windows)))]
    assert_eq!(
        result.unwrap_err().kind,
        InventoryErrorKind::UnsupportedExecutionPlatform
    );
    assert_eq!(telltale_discover::catalog::catalog().len(), 61);
}
