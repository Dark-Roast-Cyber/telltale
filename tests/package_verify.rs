#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

const FIXTURE_VERSION: &str = env!("CARGO_PKG_VERSION");

const FAKE_CARGO: &str = r##"#!/bin/sh
set -eu
VERSION=@@VERSION@@

case "$1" in
metadata)
    no_deps=0
    manifest=
    assignment=0
    for argument in "$@"; do
        test "$argument" = "--no-deps" && no_deps=1
        test "$argument" = "protected-assignment" && assignment=1
    done
    while test "$#" -gt 0; do
        if test "$1" = "--manifest-path"; then
            shift
            manifest=$1
        fi
        shift
    done
    if test "$no_deps" -eq 1; then
        cat "$FAKE_WORKSPACE_METADATA"
    else
        python3 - "$manifest" "$assignment" <<'PY'
import json
import os
import sys

manifest, enabled = sys.argv[1], sys.argv[2] == "1"
case = os.environ.get("FAKE_PACKAGE_VERIFY_CASE", "success")
if manifest.endswith("/detect-light-consumer/Cargo.toml"):
    packages = [{"id": "consumer", "name": "telltale-detect-light-consumer"}]
    nodes = [{"id": "consumer", "deps": [], "features": []}]
else:
    assignment = manifest.endswith("/core-assignment-consumer/Cargo.toml")
    assert assignment == enabled, "assignment consumer must explicitly enable its feature"
    packages = [
        {"id": "consumer", "name": "telltale-core-assignment-consumer" if assignment else "telltale-core-consumer"},
        {"id": "core", "name": "telltale-core"},
        {"id": "sources", "name": "telltale-sources"},
    ]
    def dependency(package):
        return {"pkg": package, "dep_kinds": [{"kind": None, "target": None}]}
    core_dependencies = [dependency("sources")]
    if assignment or case == "normal-sqlite":
        packages.append({"id": "sqlite", "name": "rusqlite"})
        core_dependencies.append(dependency("sqlite"))
    nodes = [
        {"id": "consumer", "deps": [dependency("core")], "features": ["protected-assignment"] if enabled else []},
        {"id": "core", "deps": core_dependencies,
         "features": ["protected-assignment"] if assignment and case != "assignment-missing-feature" else []},
        {"id": "sources", "deps": [],
         "features": ["opencode-sqlite"] if assignment and case == "assignment-acquisition" else []},
    ]
    if any(package["id"] == "sqlite" for package in packages):
        nodes.append({"id": "sqlite", "deps": [], "features": []})
print(json.dumps({"packages": packages, "resolve": {"root": "consumer", "nodes": nodes}}))
PY
    fi
    ;;
package)
    manifest=
    while test "$#" -gt 0; do
        if test "$1" = "--manifest-path"; then
            shift
            manifest=$1
        fi
        shift
    done
    case "$manifest" in
        */crates/telltale-schema/Cargo.toml) package=telltale-schema ;;
        */crates/telltale-rules/Cargo.toml) package=telltale-rules ;;
        */crates/telltale-sources/Cargo.toml) package=telltale-sources ;;
        */crates/telltale-detect/Cargo.toml) package=telltale-detect ;;
        */crates/telltale/Cargo.toml) package=telltale-core ;;
        */Cargo.toml) package=telltale-cli ;;
        *) exit 1 ;;
    esac
    package_root="$CARGO_TARGET_DIR/package/$package-@@VERSION@@"
    mkdir -p "$package_root"
    printf '%s\n' '[package]' "name = \"$package\"" 'version = "@@VERSION@@"' > "$package_root/Cargo.toml"
    if test "$package" = telltale-cli; then
        mkdir -p "$package_root/schemas/historical"
        for schema in \
            schemas/event.schema.json \
            schemas/historical/README.md \
            schemas/historical/event-1.0.schema.json \
            schemas/historical/event-2.0.schema.json; do
            : > "$package_root/$schema"
        done
        printf '%s\n' '{"git":{"sha1":"0123456789012345678901234567890123456789"}}' > "$package_root/.cargo_vcs_info.json"
    elif test "$package" = telltale-schema; then
        mkdir -p "$package_root/data"
        : > "$package_root/data/event-3.0.schema.json"
        : > "$package_root/data/event-4.0.schema.json"
    fi
    ;;
test|check)
    ;;
run)
    for argument in "$@"; do
        case "$argument" in
            */core-assignment-consumer/Cargo.toml)
                expected_root="${CARGO_TARGET_DIR%/target/core-assignment-consumer}/protected-assignment-store"
                test "$TELLTALE_PACKAGE_ASSIGNMENT_ROOT" = "$expected_root"
                test ! -e "$TELLTALE_PACKAGE_ASSIGNMENT_ROOT"
                mkdir "$TELLTALE_PACKAGE_ASSIGNMENT_ROOT"
                printf '%s\n' "$TELLTALE_PACKAGE_ASSIGNMENT_ROOT" > "$FAKE_ASSIGNMENT_STORE_RECORD"
                : > "$TELLTALE_PACKAGE_ASSIGNMENT_ROOT/protected-state"
                if test "${FAKE_PACKAGE_VERIFY_CASE:-success}" = assignment-failure; then
                    echo "synthetic assignment consumer failure" >&2
                    exit 1
                fi
                ;;
        esac
    done
    printf '%s\n' '@@VERSION@@'
    ;;
install)
    install_root=
    while test "$#" -gt 0; do
        if test "$1" = "--root"; then
            shift
            install_root=$1
        fi
        shift
    done
    mkdir -p "$install_root/bin"
    write_binary() {
        path=$1
        version=$2
        printf '%s\n' \
            '#!/bin/sh' \
            'if test "${1:-}" = config && test "${2:-}" = provenance; then' \
            "  printf '%s\\n' '{\"schema\":\"producer_provenance_manifest\",\"version\":1,\"producer_manifest_id\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\",\"telltale_version\":\"$version\",\"event3\":{\"schema_version\":\"3.0\"},\"suppression\":{\"canonicalization\":\"suppression-v1-effective-v1\",\"state\":\"none\",\"fingerprint\":null,\"count\":0}}'" \
            'else' \
            "  printf '%s\\n' 'telltale $version (012345678901)'" \
            'fi' > "$path"
        chmod 755 "$path"
    }
    case "${FAKE_PACKAGE_VERIFY_CASE:-success}" in
        empty)
            ;;
        success)
            write_binary "$install_root/bin/telltale" "$VERSION"
            ;;
        extra)
            write_binary "$install_root/bin/telltale" "$VERSION"
            write_binary "$install_root/bin/extra" "$VERSION"
            ;;
        symlink)
            write_binary "$install_root/bin/telltale-real" "$VERSION"
            ln -s telltale-real "$install_root/bin/telltale"
            ;;
        dangling-symlink)
            ln -s missing-telltale "$install_root/bin/telltale"
            ;;
        directory)
            mkdir "$install_root/bin/telltale"
            ;;
        non-executable)
            write_binary "$install_root/bin/telltale" "$VERSION"
            chmod 644 "$install_root/bin/telltale"
            ;;
        wrong-version)
            write_binary "$install_root/bin/telltale" "0.0.0"
            ;;
        *)
            exit 1
            ;;
    esac
    ;;
*)
    exit 1
    ;;
esac
"##;

#[test]
#[cfg(target_os = "linux")]
fn package_verifier_enforces_independent_core_feature_graphs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = run_package_verifier(root, "success");
    assert!(output.status.success(), "{}", output_text(&output));
    for expected in [
        "core normal feature graph verified",
        "core assignment feature graph verified",
    ] {
        assert!(
            output_text(&output).contains(expected),
            "{}",
            output_text(&output)
        );
    }
    for (case, expected) in [
        ("normal-sqlite", "core consumer SQLite graph mismatch"),
        ("assignment-missing-feature", "AssertionError"),
        ("assignment-acquisition", "assignment enabled acquisition"),
        (
            "assignment-failure",
            "synthetic assignment consumer failure",
        ),
    ] {
        let output = run_package_verifier(root, case);
        assert_eq!(output.status.code(), Some(1), "{}", output_text(&output));
        assert!(
            output_text(&output).contains(expected),
            "{case}: {}",
            output_text(&output)
        );
    }
}

#[test]
fn package_verifier_enforces_the_canonical_executable_set() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let success = run_package_verifier(root, "success");
    assert!(success.status.success(), "{}", output_text(&success));
    assert!(output_text(&success).contains("Package verification passed"));

    for (case, expected_error) in [
        ("empty", "exactly the canonical executable set"),
        ("extra", "unexpected executable entry"),
        ("symlink", "unexpected executable entry"),
        ("dangling-symlink", "unexpected executable entry"),
        ("directory", "unexpected executable entry"),
        ("non-executable", "unexpected executable entry"),
        ("wrong-version", "unexpected telltale version output"),
    ] {
        let output = run_package_verifier(root, case);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{case}: {}",
            output_text(&output)
        );
        assert!(
            output_text(&output).contains(expected_error),
            "{case}: expected {expected_error}, got {}",
            output_text(&output)
        );
    }
}

fn run_package_verifier(root: &Path, case: &str) -> Output {
    let fixture = tempdir().expect("fake cargo fixture directory");
    let metadata = Command::new(env!("CARGO"))
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
        .expect("workspace metadata");
    assert!(metadata.status.success(), "{}", output_text(&metadata));
    let metadata_path = fixture.path().join("metadata.json");
    fs::write(&metadata_path, metadata.stdout).expect("metadata fixture");
    let cargo = fixture.path().join("cargo");
    fs::write(&cargo, FAKE_CARGO.replace("@@VERSION@@", FIXTURE_VERSION))
        .expect("fake cargo script");
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755))
        .expect("make fake cargo executable");

    let assignment_record = fixture.path().join("assignment-root.txt");
    let output = Command::new(root.join("scripts/package-verify"))
        .current_dir(root)
        .env("CARGO", &cargo)
        .env("FAKE_WORKSPACE_METADATA", metadata_path)
        .env("FAKE_PACKAGE_VERIFY_CASE", case)
        .env("FAKE_ASSIGNMENT_STORE_RECORD", &assignment_record)
        .output()
        .expect("run package verifier");
    if assignment_record.exists() {
        let store_root = fs::read_to_string(assignment_record).expect("recorded assignment root");
        assert!(
            !Path::new(store_root.trim()).exists(),
            "protected state survived verifier cleanup"
        );
    }
    output
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
