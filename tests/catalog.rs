//! Machine-readable catalog of source identities and Rule v1 vocabulary.
//!
//! `docs/catalog/*.json` is generated from the built-in source registry and the
//! Rule v1 validator. These tests fail when the committed files drift from the
//! code, or when the source tables in the owning docs name a different set of
//! source identities than the registry. Regenerate with
//! `TELLTALE_UPDATE_CATALOG=1 cargo test --locked --test catalog`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use telltale_rules::{
    DetectionDefinition, RuleDefinition, SUPPORTED_DETECTION_CONDITIONS, SUPPORTED_RULE_TARGETS,
};
use telltale_schema::event::{
    VALID_ANALYTIC_INTENTS, VALID_DETECTION_CLASSES, VALID_DETECTION_SEVERITIES, VALID_SEVERITIES,
    VALID_SIGNAL_TYPES,
};
use telltale_sources::clients::{PathRoot, SourcePattern, supported_clients};

const UPDATE_ENV: &str = "TELLTALE_UPDATE_CATALOG";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// Compares generated JSON with the committed catalog file, or rewrites it.
fn check_catalog(relative: &str, generated: &Value) {
    let path = repo_path(relative);
    let text = serde_json::to_string_pretty(generated).expect("catalog JSON") + "\n";
    if std::env::var_os(UPDATE_ENV).is_some() {
        fs::create_dir_all(path.parent().expect("catalog directory")).expect("catalog directory");
        fs::write(&path, text).expect("write catalog");
        return;
    }
    let committed = fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == text,
        "{relative} is stale; regenerate with {UPDATE_ENV}=1 cargo test --locked --test catalog"
    );
}

fn root_name(root: PathRoot) -> &'static str {
    match root {
        PathRoot::CodexHome => "codex_home",
        PathRoot::Home => "home",
        PathRoot::DataHome => "data_home",
        PathRoot::ProjectLocal => "project_local",
        other => panic!("describe path root {other:?} in tests/catalog.rs"),
    }
}

fn pattern_json(pattern: SourcePattern) -> Value {
    match pattern {
        SourcePattern::Extension(value) => json!({"extension": value}),
        SourcePattern::ExactFile(value) => json!({"exact_file": value}),
        SourcePattern::FileNameContains(value) => json!({"file_name_contains": value}),
        other => panic!("describe source pattern {other:?} in tests/catalog.rs"),
    }
}

fn sources_catalog() -> Value {
    let sources = supported_clients()
        .iter()
        .flat_map(|client| {
            client.sources.iter().map(move |source| {
                json!({
                    "client": client.id.as_str(),
                    "client_display_name": client.display_name,
                    "source_id": source.id,
                    "kind": source.kind.as_str(),
                    "root": root_name(source.root),
                    "relative_path": source.relative_path,
                    "pattern": pattern_json(source.pattern),
                    "recursive": source.recursive,
                    "project_relative_path": source.project_relative_path,
                    "fixture_relative_path": source.fixture_relative_path,
                })
            })
        })
        .collect::<Vec<_>>();
    json!({
        "generated_by": "tests/catalog.rs",
        "source_of_truth": "crates/telltale-sources/src/sources/registry.rs",
        "hand_maintained": "path_roots and source_specific_discovery are written by hand from crates/telltale-sources/src/discovery.rs, not generated; tests/upstream_formats discover cases check the behavior where a case exists.",
        "path_roots": {
            "home": "Explicit --root, else $HOME, else %USERPROFILE%.",
            "codex_home": "Explicit --root joined with .codex, else $CODEX_HOME, else <home>/.codex.",
            "data_home": "Explicit --root joined with the platform data path; else Linux $XDG_DATA_HOME or <home>/.local/share, macOS <home>/Library/Application Support, Windows %LOCALAPPDATA% then %APPDATA% then <home>/AppData/Local.",
            "project_local": "Configured project roots, else <home>/github and <home>/projects when present; project_relative_path is searched below each project.",
        },
        "source_specific_discovery": {
            "claude.projects": "Environment-resolved discovery (--root .) also searches $CLAUDE_CONFIG_DIR/projects; an explicit --root ignores it.",
            "opencode.sqlite": "Environment-resolved host discovery (--root .) retains default databases and adds $XDG_DATA_HOME/opencode or <home>/.local/share/opencode on every platform. Direct-child opencode-<channel>.db names use a nonempty ASCII alphanumeric/dot/underscore/hyphen channel; environment-resolved default files and directory components reject symlinks. OPENCODE_DB adds one exact file, absolute or relative to that XDG directory, without parent enumeration or symlink components; empty and :memory: add no file. Non-dot roots and fixtures retain exact opencode.db matching; explicit roots also accept <root>/opencode/opencode.db, and Windows retains <home>/.local/share.",
        },
        "sources": sources,
    })
}

/// Accepted keys of a `deny_unknown_fields` Rule v1 struct, read back from the
/// deserializer's own unknown-field error so the list cannot drift.
fn accepted_fields<T: serde::de::DeserializeOwned>() -> Vec<String> {
    let error = match serde_yaml::from_str::<T>("telltale_catalog_probe: 1") {
        Ok(_) => panic!("probe field was accepted"),
        Err(error) => error.to_string(),
    };
    let expected = error
        .split_once("expected one of ")
        .unwrap_or_else(|| panic!("unexpected serde error shape: {error}"))
        .1;
    let fields = expected
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(!fields.is_empty(), "no fields parsed from: {error}");
    fields
}

fn rule_vocabulary_catalog() -> Value {
    json!({
        "generated_by": "tests/catalog.rs",
        "source_of_truth": [
            "crates/telltale-rules/src/lib.rs",
            "crates/telltale-schema/src/event/mod.rs",
        ],
        "rule_fields": accepted_fields::<RuleDefinition>(),
        "detection_fields": accepted_fields::<DetectionDefinition>(),
        "detection_conditions": SUPPORTED_DETECTION_CONDITIONS,
        "targets": SUPPORTED_RULE_TARGETS,
        "detection_classes": VALID_DETECTION_CLASSES,
        "signal_types": VALID_SIGNAL_TYPES,
        "analytic_intents": VALID_ANALYTIC_INTENTS,
        "severities": {
            "values": VALID_DETECTION_SEVERITIES,
            "checked_by": "Rule v1 compilation (including telltale rules validate)",
            "event3_global_values": VALID_SEVERITIES,
        },
        "atlas_tag_prefix": "atlas:",
    })
}

#[test]
fn source_catalog_matches_registry() {
    check_catalog("docs/catalog/sources.json", &sources_catalog());
}

#[test]
fn rule_vocabulary_catalog_matches_validator() {
    check_catalog(
        "docs/catalog/rule-vocabulary.json",
        &rule_vocabulary_catalog(),
    );
}

/// Second-column headers that mark a table of source identities.
const SOURCE_ID_HEADERS: &[&str] = &["Source Identity", "Source Kind"];

/// Every second-column cell of a doc's source-identity tables, so a misspelled
/// or unknown identity is compared rather than skipped.
fn documented_source_ids(relative: &str) -> BTreeSet<String> {
    let text = fs::read_to_string(repo_path(relative)).expect("source doc");
    let second_cell = |line: &str| {
        line.trim()
            .strip_prefix('|')
            .and_then(|row| row.split('|').nth(1))
            .map(|cell| cell.trim().trim_matches('`').to_owned())
    };
    let mut ids = BTreeSet::new();
    let mut in_table = false;
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let Some(cell) = second_cell(line) else {
            in_table = false;
            continue;
        };
        let separator = lines
            .peek()
            .and_then(|next| second_cell(next))
            .is_some_and(|next| next.starts_with("---"));
        if separator {
            in_table = SOURCE_ID_HEADERS.contains(&cell.as_str());
            lines.next();
        } else if in_table {
            ids.insert(cell);
        }
    }
    assert!(
        !ids.is_empty(),
        "{relative}: no source identity table found"
    );
    ids
}

fn registry_source_ids() -> BTreeSet<String> {
    supported_clients()
        .iter()
        .flat_map(|client| client.sources.iter().map(|source| source.id.to_owned()))
        .collect()
}

#[test]
fn source_docs_name_exactly_the_registered_source_identities() {
    let registered = registry_source_ids();
    for doc in [
        "docs/session-sources.md",
        "docs/source-validation-matrix.md",
    ] {
        assert_eq!(
            documented_source_ids(doc),
            registered,
            "{doc} source tables must list exactly the registered source identities"
        );
    }
}
