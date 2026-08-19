#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

const FIXTURE_VERSION: &str = "0.5.0";

const FAKE_CARGO: &str = r##"#!/bin/sh
set -eu
VERSION=@@VERSION@@

case "$1" in
metadata)
    no_deps=0
    for argument in "$@"; do
        test "$argument" = "--no-deps" && no_deps=1
    done
    if test "$no_deps" -eq 1; then
        printf '%s\n' '{"packages":[{"name":"telltale-cli","version":"@@VERSION@@"}]}'
    else
        printf '%s\n' '{"packages":[{"id":"consumer","name":"telltale-detect-light-consumer"}],"resolve":{"nodes":[{"id":"consumer","deps":[]}]}}'
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
    fi
    ;;
test|check)
    ;;
run)
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
        printf '%s\n' '#!/bin/sh' "printf '%s\\n' 'telltale $version (012345678901)'" > "$path"
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
    let cargo = fixture.path().join("cargo");
    fs::write(&cargo, FAKE_CARGO.replace("@@VERSION@@", FIXTURE_VERSION))
        .expect("fake cargo script");
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755))
        .expect("make fake cargo executable");

    Command::new(root.join("scripts/package-verify"))
        .current_dir(root)
        .env("CARGO", &cargo)
        .env("FAKE_PACKAGE_VERIFY_CASE", case)
        .output()
        .expect("run package verifier")
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
