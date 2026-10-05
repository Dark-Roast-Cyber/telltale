#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::{TempDir, tempdir};

const SCRIPTS: [&str; 3] = [
    "event3-contract-check",
    "producer-provenance-check",
    "local-event-feed-check",
];

const PROVENANCE: &str = r#"{"schema":"producer_provenance_manifest","version":1,"producer_manifest_id":"sha256:0000000000000000000000000000000000000000000000000000000000000000","telltale_version":"synthetic","event3":{"schema_version":"3.0","schema_sha256":"9014a15c010bc613b4deb7e0195ec56f702e9e950fb13a12c6937a733e38d754"},"rules":{},"risk_thresholds":{},"operational_alert_thresholds":{},"suppression":{"canonicalization":"suppression-v1-effective-v1","state":"none","fingerprint":null,"count":0},"features":{"emit_activity":false,"emit_session_risk_summary":false,"baseline_deviation_scoring":false,"process_chain_detections":false,"install_inventory":false,"install_inventory_interval_seconds":0}}"#;

fn fixture() -> TempDir {
    let dir = tempdir().unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for path in [
        "Makefile",
        "scripts/event3-contract-check",
        "scripts/producer-provenance-check",
        "scripts/local-event-feed-check",
        "schemas/event.schema.json",
        "schemas/historical/event-3.0.schema.json",
        "crates/telltale-schema/README.md",
        "docs/telemetry-output.md",
    ] {
        let dest = dir.path().join(path);
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::copy(root.join(path), dest).unwrap();
    }
    fs::create_dir(dir.path().join("bin")).unwrap();
    fs::create_dir(dir.path().join("tmp")).unwrap();
    fs::write(dir.path().join("provenance.json"), PROVENANCE).unwrap();
    fs::write(
        dir.path().join("metadata.mk"),
        "ci-version-consistency-check:\n\t@:\n",
    )
    .unwrap();
    for (name, script) in [
        (
            "cargo",
            r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$RECORD"
if test "$1" = run; then
    case "${FAULT:-}" in
        write) touch unexpected ;;
        nondeterministic) printf '%*s' "$(grep -c '^run ' "$RECORD")" '' ;;
        invalid) printf '{}'; exit 0 ;;
    esac
    cat "$FIXTURE/provenance.json"
fi
"#,
        ),
        (
            "git",
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"git $*\" >> \"$RECORD\"\n",
        ),
    ] {
        let path = dir.path().join("bin").join(name);
        fs::write(&path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    dir
}

fn run(dir: &TempDir, program: &str, args: &[&str], fault: &str) -> (Output, Vec<String>) {
    let record = dir.path().join("record");
    fs::write(&record, "").unwrap();
    let output = Command::new(program)
        .args(args)
        .current_dir(dir.path())
        .env(
            "PATH",
            format!(
                "{}:{}",
                dir.path().join("bin").display(),
                std::env::var("PATH").unwrap()
            ),
        )
        .env("MAKEFLAGS", "")
        .env("RECORD", &record)
        .env("FIXTURE", dir.path())
        .env("TMPDIR", dir.path().join("tmp"))
        .env("FAULT", fault)
        .output()
        .unwrap();
    let calls = fs::read_to_string(record)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    (output, calls)
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn linux_aggregate_runs_full_tests_once_and_retains_independent_checks() {
    let dir = fixture();
    let (output, calls) = run(
        &dir,
        "make",
        &[
            "--silent",
            "-f",
            "Makefile",
            "-f",
            "metadata.mk",
            "CARGO_LOCKED=--locked",
            "ci-linux-test",
        ],
        "",
    );
    success(&output);
    assert_eq!(
        calls
            .iter()
            .filter(|s| s.starts_with("test "))
            .collect::<Vec<_>>(),
        vec![
            "test --locked --quiet",
            "test --locked -p telltale-core --lib --quiet",
            "test --locked -p telltale-sources --lib --quiet",
            "test --locked -p telltale-sources --features opencode-sqlite --lib --quiet",
        ]
    );
    assert_eq!(calls.iter().filter(|s| s.starts_with("run ")).count(), 2);
    for call in calls.iter().filter(|s| s.starts_with("run ")) {
        assert!(call.starts_with("run --locked --quiet --manifest-path "));
        assert!(call.ends_with("--bin telltale -- config provenance --no-local-config"));
    }
    assert!(calls.contains(&"git diff --check".to_owned()));
    assert_eq!(fs::read_dir(dir.path().join("tmp")).unwrap().count(), 0);
    let local =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ci-local")).unwrap();
    assert!(!local.contains("run_make release-public-docs-check"));
    for stage in [
        "release-fixture-smoke",
        "package-verify",
        "telltale-console-check",
        "embedding-contract-check",
    ] {
        assert!(local.contains(&format!("run_make {stage}")));
    }
}

#[test]
fn standalone_scripts_and_make_gates_keep_exact_focused_tests() {
    let expected: [&[&str]; 3] = [
        &[
            "test --locked -p telltale-schema consumer",
            "test --locked -p telltale-schema event_constructor_family_registry",
            "test --locked --test cli native_constructor_family_registry_covers_the_reviewed_current_corpus",
            "test --locked --test cli every_native_event_constructor_emits_schema_valid_json",
            "test --locked -p telltale-schema privacy",
            "test --locked -p telltale-cli historical_schema_hashes_match_tagged_source_blobs",
            "test --locked --quiet public_docs_",
        ],
        &[
            "test --locked -p telltale-schema provenance",
            "test --locked -p telltale-rules provenance",
            "test --locked -p telltale-detect allowlist",
            "test --locked -p telltale-core provenance",
            "test --locked --test cli provenance",
        ],
        &[
            "test --locked -p telltale-sources journal",
            "test --locked -p telltale-core local_event_feed",
            "test --locked --test cli rotation",
            "test --locked -p telltale-schema consumer",
        ],
    ];
    let dir = fixture();
    for (script, expected) in SCRIPTS.iter().zip(expected) {
        for make in [false, true] {
            let path = format!("scripts/{script}");
            let (output, calls) = if make {
                run(&dir, "make", &["--silent", script], "")
            } else {
                run(&dir, "sh", &[&path], "")
            };
            success(&output);
            assert_eq!(
                calls
                    .iter()
                    .filter(|s| s.starts_with("test "))
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
    let (output, calls) = run(
        &dir,
        "make",
        &[
            "--silent",
            "CARGO_LOCKED=--locked",
            "release-public-docs-check",
        ],
        "",
    );
    success(&output);
    assert_eq!(calls, ["test --locked --quiet public_docs_"]);
}

#[test]
fn checks_only_rejects_unknown_arguments_before_work_and_keeps_fail_closed_checks() {
    let dir = fixture();
    for script in SCRIPTS {
        let path = format!("scripts/{script}");
        for args in [
            vec![path.as_str(), "--unknown"],
            vec![path.as_str(), "--checks-only", "extra"],
        ] {
            let (output, calls) = run(&dir, "sh", &args, "");
            assert_eq!(output.status.code(), Some(2));
            assert!(calls.is_empty());
            assert!(output.stdout.is_empty());
        }
        let (output, calls) = run(&dir, "sh", &[&path, "--checks-only"], "");
        success(&output);
        assert!(!calls.iter().any(|s| s.starts_with("test ")));
    }
    for fault in ["write", "nondeterministic", "invalid"] {
        let (output, _) = run(
            &dir,
            "sh",
            &["scripts/producer-provenance-check", "--checks-only"],
            fault,
        );
        assert!(!output.status.success(), "fault accepted: {fault}");
        assert_eq!(fs::read_dir(dir.path().join("tmp")).unwrap().count(), 0);
    }
    fs::write(dir.path().join("schemas/event.schema.json"), "{}").unwrap();
    let (output, calls) = run(
        &dir,
        "sh",
        &["scripts/event3-contract-check", "--checks-only"],
        "",
    );
    assert!(!output.status.success());
    assert!(calls.is_empty());
}
