use std::fs;
use std::path::Path;

const VERSION: &str = "0.4.0";
const PACKAGES: &[(&str, &str)] = &[
    ("telltale-schema", "crates/telltale-schema/Cargo.toml"),
    ("telltale-rules", "crates/telltale-rules/Cargo.toml"),
    ("telltale-sources", "crates/telltale-sources/Cargo.toml"),
    ("telltale-detect", "crates/telltale-detect/Cargo.toml"),
    ("telltale-core", "crates/telltale/Cargo.toml"),
    ("telltale-cli", "Cargo.toml"),
];

#[test]
fn official_packages_have_lockstep_metadata() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_manifest =
        fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest");
    assert!(workspace_manifest.contains(&format!("version = \"{VERSION}\"")));
    assert!(workspace_manifest.contains("authors = [\"Dark Roast Cyber\"]"));

    for (name, relative_manifest) in PACKAGES {
        let manifest = fs::read_to_string(root.join(relative_manifest)).expect("package manifest");
        assert!(manifest.contains(&format!("name = \"{name}\"")));
        assert!(manifest.contains("version.workspace = true"));
        assert!(manifest.contains("authors.workspace = true"));
        assert!(manifest.contains("homepage.workspace = true"));
        let readme = if *name == "telltale-cli" {
            "readme = \"crates/telltale-cli/README.md\""
        } else {
            "readme = \"README.md\""
        };
        assert!(manifest.contains(readme));
        assert!(manifest.contains(&format!("documentation = \"https://docs.rs/{name}\"")));
        assert!(manifest.contains("keywords = ["));
        assert!(manifest.contains("categories = ["));
    }
}

#[test]
fn registry_consumer_docs_follow_current_package_version() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in ["docs/versioning.md", "docs/release-readiness.md"] {
        let document = fs::read_to_string(root.join(relative)).expect("versioning document");
        assert!(
            document.contains("`=0.4.0`"),
            "{relative} does not name the current registry pin"
        );
        assert!(
            !document.contains("`=0.2.0`"),
            "{relative} retains a stale registry pin"
        );
    }
}

#[test]
fn publication_order_and_binary_targets_are_explicit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let names: Vec<_> = PACKAGES.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names,
        vec![
            "telltale-schema",
            "telltale-rules",
            "telltale-sources",
            "telltale-detect",
            "telltale-core",
            "telltale-cli",
        ]
    );

    let facade =
        fs::read_to_string(root.join("crates/telltale/Cargo.toml")).expect("facade manifest");
    assert!(facade.contains("name = \"telltale-core\""));
    assert!(facade.contains("include = ["));

    let cli = fs::read_to_string(root.join("Cargo.toml")).expect("cli manifest");
    let cli = cli.replace("\r\n", "\n");
    assert!(cli.contains("name = \"telltale\"\npath = \"src/main.rs\""));
    assert!(cli.contains("name = \"adr\"\npath = \"src/bin/adr.rs\""));
}

#[test]
fn package_boundaries_and_bundled_rules_are_explicit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (_, relative_manifest) in &PACKAGES[..5] {
        let manifest = fs::read_to_string(root.join(relative_manifest)).expect("library manifest");
        assert!(manifest.contains("include = ["));
        assert!(!manifest.contains(".ai/**"));
        assert!(!manifest.contains("docs/internal/**"));
    }

    let cli = fs::read_to_string(root.join("Cargo.toml")).expect("cli manifest");
    assert!(cli.contains("include = ["));
    for required in [
        "crates/telltale-cli/README.md",
        "LICENSE",
        "build.rs",
        "benches/benchmarks.rs",
        "src/**",
        "config/rules/tool-call-regex.yaml",
        "tests/fixtures/**",
    ] {
        assert!(cli.contains(required), "root package omits {required}");
    }
    assert!(!cli.contains("tests/cli.rs"));
    assert!(!cli.contains("docs/"));
    assert!(!cli.contains(".github/"));

    let canonical = include_bytes!("../config/rules/tool-call-regex.yaml");
    let packaged = include_bytes!("../crates/telltale-rules/data/tool-call-regex.yaml");
    assert_eq!(
        canonical, packaged,
        "packaged rules data drifted from canonical source"
    );

    for package in ["telltale-sources", "telltale-detect"] {
        assert_fixture_tree_matches_source(
            &root.join("tests/fixtures"),
            &root.join(format!("crates/{package}/tests/fixtures")),
        );
    }

    let canonical_license = fs::read(root.join("LICENSE")).expect("canonical license");
    for package in [
        "telltale-schema",
        "telltale-rules",
        "telltale-sources",
        "telltale-detect",
        "telltale",
    ] {
        assert_eq!(
            canonical_license,
            fs::read(root.join(format!("crates/{package}/LICENSE"))).expect("package license"),
            "license drift in {package}"
        );
    }
}

fn assert_fixture_tree_matches_source(source: &Path, package: &Path) {
    for entry in fs::read_dir(package).expect("package fixture directory") {
        let entry = entry.expect("package fixture entry");
        let package_path = entry.path();
        let relative = package_path
            .strip_prefix(package)
            .expect("fixture relative path");
        let source_path = source.join(relative);
        if package_path.is_dir() {
            assert_fixture_tree_matches_source(&source_path, &package_path);
        } else {
            assert_eq!(
                fs::read(&source_path).expect("canonical fixture"),
                fs::read(&package_path).expect("package fixture"),
                "fixture drift at {}",
                relative.display()
            );
        }
    }
}

#[test]
fn package_verification_is_local_and_ordered() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let makefile = fs::read_to_string(root.join("Makefile")).expect("makefile");
    let script = fs::read_to_string(root.join("scripts/package-verify")).expect("package verifier");

    assert!(makefile.contains("package-verify:"));
    assert!(makefile.contains("release-preflight:") && makefile.contains("package-verify"));
    assert!(script.contains("package --locked --allow-dirty"));
    assert!(script.contains("--config \"patch.crates-io."));
    assert!(script.contains("install --locked --path"));
    assert!(script.contains("--version"));
    assert!(script.contains("PACKAGED_SHA_FULL"));
    assert!(script.contains("PACKAGED_SHA_PREFIX"));
    assert!(!script.contains("cargo publish"));

    let mut previous = 0;
    for package in [
        "telltale-schema",
        "telltale-rules",
        "telltale-sources",
        "telltale-detect",
        "telltale-core",
        "telltale-cli",
    ] {
        let position = script
            .find(&format!("run_package {package}"))
            .expect("package order entry");
        assert!(
            position >= previous,
            "package order is not dependency order"
        );
        previous = position;
    }
}

#[test]
fn provenance_build_scripts_prefer_packaged_vcs_metadata() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for relative in ["build.rs", "crates/telltale-schema/build.rs"] {
        let build_script = fs::read_to_string(root.join(relative)).expect("build script");
        assert!(build_script.contains(".cargo_vcs_info.json"));
        assert!(build_script.contains("--show-toplevel"));
        assert!(build_script.contains("rev-parse"));
        assert!(build_script.contains("PUBLIC_SHA_LENGTH: usize = 12"));
        assert!(build_script.contains("public_sha"));
    }
}
