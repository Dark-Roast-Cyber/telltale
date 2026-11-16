//! Synthetic Unix metadata boundaries. No live home or store is accessed.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use telltale_discover::catalog::{ArtifactKind, CatalogRoot, catalog};
use telltale_discover::inventory::{
    InventoryContext, InventoryErrorKind, InventoryLimits, Platform, RootKind, discover,
};
use telltale_discover::record::{
    CandidateId, CandidateOutcome, InventoryRecord, InventorySnapshot, NotImplemented,
    ProbeImplementation,
};

fn tempdir() -> tempfile::TempDir {
    // Resolve only the test-owned fixture parent, not a collector input. On
    // macOS the system temporary directory can have a symlinked `/var` ancestor.
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}

fn context(home: &Path) -> InventoryContext {
    InventoryContext::from_home(home.to_path_buf(), Platform::Linux)
}
fn snapshot(context: &InventoryContext) -> InventorySnapshot {
    discover(context, 123_456, InventoryLimits::default()).unwrap()
}
fn entry<'a>(snapshot: &'a InventorySnapshot, id: &str) -> &'a InventoryRecord {
    snapshot
        .entries()
        .iter()
        .find(|entry| entry.id() == id)
        .unwrap()
}
fn outcome(snapshot: &InventorySnapshot, id: &str) -> CandidateOutcome {
    entry(snapshot, id).candidates()[0].outcome()
}
fn directory(root: &Path, relative: &str) {
    fs::create_dir_all(root.join(relative)).unwrap();
}
fn file(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

#[test]
fn empty_home_is_success_with_all_entries_without_fabricated_installation_or_usage() {
    let temp = tempdir();
    let result = snapshot(&context(temp.path()));
    assert_eq!(result.entries().len(), 61);
    assert!(!result.check_limit_reached());
    for entry in result.entries() {
        assert!(entry.candidates().iter().all(|candidate| matches!(
            candidate.outcome(),
            CandidateOutcome::NotFoundInCheckedCandidate | CandidateOutcome::PlatformUnverified
        )));
    }
    let json = serde_json::to_value(&result).unwrap();
    assert_eq!(json["schema"], "telltale.inventory/v1");
    assert_eq!(json["observed_at_unix_ms"], 123_456);
    for entry in json["entries"].as_array().unwrap() {
        assert_eq!(entry["usage"], "not_implemented");
        assert_eq!(entry["installation"], "not_assessed");
        assert_eq!(entry["locator_qualification"], "upstream_candidate_only");
        for field in [
            "additional_locations",
            "environment_relocations",
            "scanner_patterns",
        ] {
            assert_eq!(entry[field], "not_implemented");
        }
        for field in [
            "tokens",
            "input_tokens",
            "output_tokens",
            "cost",
            "total",
            "installed",
            "active",
        ] {
            assert!(entry.get(field).is_none());
        }
    }
}

#[test]
fn non_detection_tools_are_visible_from_empty_native_directories() {
    let temp = tempdir();
    directory(temp.path(), ".pi/agent/sessions");
    directory(temp.path(), ".gemini/tmp");
    let result = snapshot(&context(temp.path()));
    for id in ["pi", "gemini"] {
        assert_eq!(outcome(&result, id), CandidateOutcome::IndicatorPresent);
        assert_eq!(
            entry(&result, id).candidates()[0].artifact_kind(),
            ArtifactKind::NativeData
        );
    }
}

#[test]
fn native_cache_capture_mirror_and_shared_artifacts_are_distinct() {
    let temp = tempdir();
    for path in [
        ".pi/agent/sessions",
        ".config/tokscale/cursor-cache",
        ".config/tokscale/amp-cache/threads",
        ".config/tokscale/antigravity-cache/sessions",
        ".config/tokscale/trae-cache/sessions",
        ".config/tokscale/warp-cache",
        ".config/tokscale/headless/mcode",
        ".hindsight/usage",
        ".config/manicode/projects",
        ".local/share/mimocode",
    ] {
        directory(temp.path(), path);
    }
    let result = snapshot(&context(temp.path()));
    for (id, kind) in [
        ("pi", ArtifactKind::NativeData),
        ("cursor", ArtifactKind::TokscaleCache),
        ("amp", ArtifactKind::TokscaleCache),
        ("antigravity", ArtifactKind::TokscaleCache),
        ("trae", ArtifactKind::TokscaleCache),
        ("warp", ArtifactKind::TokscaleCache),
        ("mcode", ArtifactKind::TokscaleCapture),
        ("hindsight", ArtifactKind::SyncedUsageMirror),
        ("codebuff", ArtifactKind::SharedNativeData),
        ("freebuff", ArtifactKind::SharedNativeData),
        ("micode", ArtifactKind::SharedNativeData),
        ("micode-desktop", ArtifactKind::SharedNativeData),
    ] {
        assert_eq!(outcome(&result, id), CandidateOutcome::IndicatorPresent);
        assert_eq!(entry(&result, id).candidates()[0].artifact_kind(), kind);
    }
    assert_eq!(
        outcome(&result, "antigravity-cli"),
        CandidateOutcome::NotFoundInCheckedCandidate
    );
}

#[test]
fn known_legacy_primary_locations_preserve_classification_and_coverage_limits() {
    let legacy = tempdir();
    let replacements = tempdir();
    let cases = [
        ("kimi", ".kimi/sessions", ".kimi-code/sessions"),
        ("workbuddy", ".workbuddy", ".workbuddy-ai"),
        ("senpi", ".senpi/agent/sessions", ".omo/agent/sessions"),
        (
            "cherrystudio",
            ".config/CherryStudio/.claude/projects",
            ".config/CherryStudio/Data/Agents/.claude/projects",
        ),
    ];
    for (_, old, new) in cases {
        directory(legacy.path(), old);
        directory(replacements.path(), new);
    }
    let legacy = snapshot(&context(legacy.path()));
    let replacements = snapshot(&context(replacements.path()));
    for result in [&legacy, &replacements] {
        assert_eq!(result.entries().len(), 61);
        assert_eq!(
            result
                .entries()
                .iter()
                .map(|entry| entry.candidates().len())
                .sum::<usize>(),
            63
        );
        for (id, _, _) in cases {
            let entry = entry(result, id);
            assert_eq!(entry.candidates().len(), 1);
            let candidate = &entry.candidates()[0];
            assert_eq!(candidate.candidate(), CandidateId::UpstreamPrimary);
            assert_eq!(candidate.artifact_kind(), ArtifactKind::LegacyNativeData);
            assert_eq!(entry.additional_locations(), NotImplemented::NotImplemented);
            let wire = serde_json::to_value(candidate).unwrap();
            assert_eq!(wire["artifact_kind"], "legacy_native_data");
        }
    }
    for (id, _, _) in cases {
        assert_eq!(outcome(&legacy, id), CandidateOutcome::IndicatorPresent);
        assert_eq!(
            outcome(&replacements, id),
            CandidateOutcome::NotFoundInCheckedCandidate
        );
    }
}

#[test]
fn current_opencode_and_copilot_databases_are_metadata_only_indicators() {
    let temp = tempdir();
    file(
        temp.path(),
        ".local/share/opencode/opencode.db",
        b"invalid database\0PRIVATE_CONTENT",
    );
    file(
        temp.path(),
        ".copilot/session-store.db",
        b"invalid database\0PRIVATE_CONTENT",
    );
    let result = snapshot(&context(temp.path()));
    for (id, candidate) in [
        ("opencode", CandidateId::OpenCodeDefaultDatabase),
        ("copilot", CandidateId::CopilotSessionStoreDatabase),
    ] {
        let candidates = entry(&result, id).candidates();
        assert_eq!(
            candidates[0].outcome(),
            CandidateOutcome::NotFoundInCheckedCandidate
        );
        assert_eq!(candidates[1].candidate(), candidate);
        assert_eq!(candidates[1].outcome(), CandidateOutcome::IndicatorPresent);
        assert_eq!(candidates[1].artifact_kind(), ArtifactKind::NativeData);
    }
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("PRIVATE_CONTENT")
    );
}

#[test]
fn source_files_are_not_opened_and_installed_tools_are_never_executed() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let temp = tempdir();
    directory(temp.path(), ".pi/agent/sessions");
    directory(temp.path(), ".bb");
    let fifo = temp.path().join(".bb/bb.db");
    let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: a synthetic, terminated path; no descriptor or buffer ownership.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    // A FIFO that would block a session walker is also never read or listed.
    let child = temp.path().join(".pi/agent/sessions/session.jsonl");
    let name = CString::new(child.as_os_str().as_bytes()).unwrap();
    // SAFETY: same synthetic path invariant as above.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let marker = temp.path().join("EXECUTED");
    file(
        temp.path(),
        ".local/bin/pi",
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()).as_bytes(),
    );
    fs::set_permissions(
        temp.path().join(".local/bin/pi"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let result = snapshot(&context(temp.path()));
    assert_eq!(outcome(&result, "pi"), CandidateOutcome::IndicatorPresent);
    assert_eq!(outcome(&result, "bb"), CandidateOutcome::WrongType);
    assert!(!marker.exists());
}

#[test]
fn wrong_type_is_never_clean_absence() {
    let temp = tempdir();
    file(temp.path(), ".gemini", b"not a directory");
    directory(temp.path(), ".bb/bb.db");
    let result = snapshot(&context(temp.path()));
    assert_eq!(outcome(&result, "gemini"), CandidateOutcome::WrongType);
    assert_eq!(
        outcome(&result, "antigravity-cli"),
        CandidateOutcome::WrongType
    );
    assert_eq!(outcome(&result, "bb"), CandidateOutcome::WrongType);
}

#[test]
fn root_missing_malformed_wrong_type_and_limits_are_typed() {
    let temp = tempdir();
    let assert_error = |home: PathBuf, kind| {
        let error = discover(&context(&home), 0, InventoryLimits::default()).unwrap_err();
        assert_eq!(error.kind, kind);
        assert_eq!(error.root, Some(RootKind::Home));
    };
    assert_error(
        temp.path().join("missing\nPRIVATE_ROOT"),
        InventoryErrorKind::RootMissing,
    );
    assert_error(PathBuf::from("relative"), InventoryErrorKind::MalformedRoot);
    assert_error(
        temp.path().join("../escape"),
        InventoryErrorKind::MalformedRoot,
    );
    assert_error(
        temp.path().join("nul\0name"),
        InventoryErrorKind::MalformedRoot,
    );
    assert_error(
        temp.path().join("a/".repeat(65)),
        InventoryErrorKind::MalformedRoot,
    );
    file(temp.path(), "file", b"not a directory");
    assert_error(temp.path().join("file"), InventoryErrorKind::WrongType);
    for max_checks in [0, 65_537, u32::MAX] {
        let error = discover(&context(temp.path()), 0, InventoryLimits { max_checks }).unwrap_err();
        assert_eq!(error.kind, InventoryErrorKind::InvalidLimits);
        assert_eq!(error.root, None);
    }
}

#[test]
fn all_explicit_roots_are_validated_even_without_matching_artifacts() {
    let temp = tempdir();
    for root in [RootKind::Data, RootKind::Config, RootKind::AppData] {
        let mut context = context(temp.path());
        let path = Some(temp.path().join("missing"));
        match root {
            RootKind::Data => context.data_dir = path,
            RootKind::Config => context.config_dir = path,
            RootKind::AppData => context.app_data_dir = path,
            RootKind::Home => unreachable!(),
        }
        let error = discover(&context, 0, InventoryLimits::default()).unwrap_err();
        assert_eq!(error.root, Some(root));
        assert_eq!(error.kind, InventoryErrorKind::RootMissing);
    }
}

#[test]
fn aggregate_limit_charges_every_ancestor_and_directory_open() {
    let temp = tempdir();
    let context = context(temp.path());
    // Opening `/` costs one, each normal ancestor costs fstatat + openat.
    let root_checks = 1 + 2 * temp
        .path()
        .components()
        .filter(|part| matches!(part, std::path::Component::Normal(_)))
        .count() as u32;
    let error = discover(
        &context,
        0,
        InventoryLimits {
            max_checks: root_checks - 1,
        },
    )
    .unwrap_err();
    assert_eq!(error.kind, InventoryErrorKind::CheckLimitReached);
    let result = discover(
        &context,
        0,
        InventoryLimits {
            max_checks: root_checks + 1,
        },
    )
    .unwrap();
    assert_eq!(result.checks_performed(), root_checks + 1);
    assert!(result.check_limit_reached());
    let opencode = entry(&result, "opencode");
    assert_eq!(
        opencode.candidates()[0].outcome(),
        CandidateOutcome::NotFoundInCheckedCandidate
    );
    assert_eq!(
        opencode.candidates()[1].outcome(),
        CandidateOutcome::CheckLimitReached
    );
    assert_eq!(outcome(&result, "pi"), CandidateOutcome::CheckLimitReached);
    assert_eq!(result.entries().len(), 61);
}

#[test]
fn unmatched_entries_are_never_enumerated() {
    let temp = tempdir();
    directory(temp.path(), ".pi/agent/sessions");
    let before = snapshot(&context(temp.path()));
    for index in 0..1000 {
        directory(temp.path(), &format!("unmatched-{index}/nested"));
        file(
            temp.path(),
            &format!(".pi/agent/sessions/ignored-{index}.jsonl"),
            b"PRIVATE_SESSION",
        );
    }
    let after = snapshot(&context(temp.path()));
    assert_eq!(
        serde_json::to_string(&before).unwrap(),
        serde_json::to_string(&after).unwrap()
    );
}

#[test]
fn symlink_roots_ancestors_and_candidate_leaves_are_refused() {
    let temp = tempdir();
    let outside = tempdir();
    directory(outside.path(), "agent/sessions");
    symlink(outside.path(), temp.path().join("root-link")).unwrap();
    for home in [
        temp.path().join("root-link"),
        temp.path().join("root-link/agent"),
    ] {
        let error = discover(&context(&home), 0, InventoryLimits::default()).unwrap_err();
        assert_eq!(error.kind, InventoryErrorKind::SymlinkRefused);
    }
    symlink(outside.path(), temp.path().join(".pi")).unwrap();
    directory(temp.path(), ".gemini");
    symlink(
        outside.path().join("agent/sessions"),
        temp.path().join(".gemini/tmp"),
    )
    .unwrap();
    file(outside.path(), "db", b"PRIVATE_OUTSIDE");
    directory(temp.path(), ".bb");
    symlink(outside.path().join("db"), temp.path().join(".bb/bb.db")).unwrap();
    let result = snapshot(&context(temp.path()));
    for id in ["pi", "gemini", "bb"] {
        assert_eq!(outcome(&result, id), CandidateOutcome::SymlinkRefused);
    }
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("PRIVATE_OUTSIDE")
    );
}

#[test]
fn symlink_to_inside_the_approved_root_is_also_refused() {
    let temp = tempdir();
    directory(temp.path(), "retained/agent/sessions");
    symlink(temp.path().join("retained"), temp.path().join(".pi")).unwrap();
    assert_eq!(
        outcome(&snapshot(&context(temp.path())), "pi"),
        CandidateOutcome::SymlinkRefused
    );
}

#[test]
fn permissions_are_not_clean_absence() {
    let temp = tempdir();
    directory(temp.path(), "denied");
    let denied = temp.path().join("denied");
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o0)).unwrap();
    let result = discover(&context(&denied), 0, InventoryLimits::default());
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
    // Root can bypass DAC; never present that run as permission-boundary proof.
    // SAFETY: geteuid has no arguments or memory ownership preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("permission boundary not exercised: effective uid is root");
        return;
    }
    assert_eq!(
        result.unwrap_err().kind,
        InventoryErrorKind::PermissionDenied
    );
    directory(temp.path(), ".pi/agent");
    let pi = temp.path().join(".pi");
    fs::set_permissions(&pi, fs::Permissions::from_mode(0o0)).unwrap();
    let result = snapshot(&context(temp.path()));
    fs::set_permissions(&pi, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(outcome(&result, "pi"), CandidateOutcome::PermissionDenied);
}

#[test]
fn deterministic_records_and_errors_never_include_private_paths_or_controls() {
    let temp = tempdir();
    let home = temp.path().join("PRIVATE_ACCOUNT_\n\u{1b}[31m");
    directory(&home, ".pi/agent/sessions/PRIVATE_SESSION_TITLE");
    file(
        &home,
        ".pi/agent/sessions/PRIVATE_SESSION_TITLE/secret.jsonl",
        b"PRIVATE_MESSAGE\x1b",
    );
    let first = snapshot(&context(&home));
    let second = snapshot(&context(&home));
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    let error = discover(
        &context(&home.join("PRIVATE_MISSING")),
        0,
        InventoryLimits::default(),
    )
    .unwrap_err();
    let output = format!(
        "{} {first:?} {} {error:?} {error}",
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&error).unwrap()
    );
    for canary in ["PRIVATE_", "\u{1b}", "[31m", &temp.path().to_string_lossy()] {
        assert!(!output.contains(canary), "leaked canary");
    }
}

#[test]
fn explicit_roots_and_platform_conventions_are_isolated() {
    let temp = tempdir();
    let mut context = context(temp.path());
    for relative in [
        "data/opencode",
        "config/tokscale/amp-cache/threads",
        "app/CherryStudio/.claude/projects",
    ] {
        directory(temp.path(), relative);
    }
    file(temp.path(), "data/opencode/opencode.db", b"not sqlite");
    context.data_dir = Some(temp.path().join("data"));
    context.config_dir = Some(temp.path().join("config"));
    context.app_data_dir = Some(temp.path().join("app"));
    let result = snapshot(&context);
    assert_eq!(
        entry(&result, "opencode").candidates()[1].outcome(),
        CandidateOutcome::IndicatorPresent
    );
    assert_eq!(outcome(&result, "amp"), CandidateOutcome::IndicatorPresent);
    assert_eq!(
        outcome(&result, "cherrystudio"),
        CandidateOutcome::IndicatorPresent
    );
    // Synthetic contexts exercise conventions, not native platform validation.
    let mut context = InventoryContext::from_home(temp.path().to_path_buf(), Platform::MacOs);
    directory(
        temp.path(),
        "Library/Application Support/CherryStudio/.claude/projects",
    );
    directory(
        temp.path(),
        "Library/Application Support/Devin/User/acp-events",
    );
    let result = snapshot(&context);
    assert_eq!(
        outcome(&result, "cherrystudio"),
        CandidateOutcome::IndicatorPresent
    );
    assert_eq!(
        outcome(&result, "devin-desktop"),
        CandidateOutcome::IndicatorPresent
    );
    assert_eq!(
        outcome(&result, "cline"),
        CandidateOutcome::PlatformUnverified
    );
    context.platform = Platform::Windows;
    directory(temp.path(), "AppData/Roaming/CherryStudio/.claude/projects");
    directory(temp.path(), "AppData/Roaming/tokscale/amp-cache/threads");
    directory(temp.path(), "AppData/Roaming/reasonix/stats");
    let result = snapshot(&context);
    for id in ["cherrystudio", "amp", "reasonix"] {
        assert_eq!(outcome(&result, id), CandidateOutcome::IndicatorPresent);
    }
    for id in ["cline", "devin-desktop", "fx"] {
        assert_eq!(outcome(&result, id), CandidateOutcome::PlatformUnverified);
    }
    context.platform = Platform::Unknown;
    let result = snapshot(&context);
    assert!(
        result
            .entries()
            .iter()
            .all(|entry| entry.probe_implementation() == ProbeImplementation::PlatformUnverified)
    );
}

#[test]
fn fixed_root_is_environment_isolated() {
    const CHILD_ROOT: &str = "TELLTALE_TEST_INVENTORY_CHILD_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let result = snapshot(&context(Path::new(&root)));
        assert!(
            result
                .entries()
                .iter()
                .flat_map(|entry| entry.candidates())
                .all(|candidate| candidate.outcome() != CandidateOutcome::IndicatorPresent)
        );
        return;
    }
    let fixed = tempdir();
    let outside = tempdir();
    for path in [
        ".pi/agent/sessions",
        ".gemini/tmp",
        "tmp",
        "projects",
        "sessions",
        "opencode",
        "tokscale/amp-cache/threads",
        "CherryStudio/.claude/projects",
    ] {
        directory(outside.path(), path);
    }
    file(outside.path(), "opencode/opencode.db", b"invalid sqlite");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "fixed_root_is_environment_isolated",
            "--nocapture",
        ])
        .env(CHILD_ROOT, fixed.path())
        .env("HOME", outside.path())
        .env("USERPROFILE", outside.path())
        .env("XDG_DATA_HOME", outside.path())
        .env("XDG_CONFIG_HOME", outside.path())
        .env("APPDATA", outside.path())
        .env("LOCALAPPDATA", outside.path())
        .env("REASONIX_HOME", outside.path())
        .env("REASONIX_STATE_HOME", outside.path());
    for entry in catalog() {
        if let CatalogRoot::EnvironmentFallback { variable, .. } = entry.upstream_root {
            command.env(variable, outside.path());
        }
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unavailable_metadata_remains_a_typed_error_without_os_details() {
    let temp = tempdir();
    let path = temp.path().join("PRIVATE_OVERSIZE_".repeat(100));
    let error = discover(&context(&path), 0, InventoryLimits::default()).unwrap_err();
    assert_eq!(error.kind, InventoryErrorKind::MetadataUnavailable);
    let output = format!(
        "{error} {error:?} {}",
        serde_json::to_string(&error).unwrap()
    );
    assert!(!output.contains("PRIVATE_OVERSIZE"));
    assert!(!output.contains("File name too long"));
}
