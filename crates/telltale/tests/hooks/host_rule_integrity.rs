//! User rule content cannot remove, replace or weaken the hooks
//! self-protection rules while `rules.self_protection` is on. Content that
//! names one is invalid configuration, and the pipeline that is built carries
//! the host rules as their documents define them.

use crate::common;

use std::path::{Path, PathBuf};

use common::{Harness, verdict};
use serde_json::json;
use telltale_core::hooks::config::{Config, RuleContent};
use telltale_core::hooks::engine::Engine;

fn content(edit: impl FnOnce(&mut RuleContent)) -> RuleContent {
    let mut content = RuleContent::default();
    edit(&mut content);
    content
}

const HOST_RULE: &str = "tth.tamper.hook_settings_write";

fn content_file(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

fn override_entry(change: &str) -> String {
    format!(
        "version: 1\noverrides:\n  - rule_id: {HOST_RULE}\n    {change}\n    reason: synthetic test\n"
    )
}

fn rule_document(id: &str) -> String {
    format!(
        "version: 1\ndescription: synthetic\ndefaults:\n  case_insensitive: false\n  enabled: true\nrules:\n  - id: {id}\n    title: synthetic\n    category: approval_bypass\n    severity: high\n    score: 90\n    targets: [command]\n    regex: 'synthetic-never-matches-xyz'\n    tags: [synthetic]\n    explanation: synthetic.\nmodifiers: []\n"
    )
}

fn rule_package(id: &str) -> String {
    let document = rule_document(id).trim_end().replace('\n', "\n    ");
    format!(
        "format: telltale-rule-package/v1\nid: synthetic.package\nversion: 1.0.0\npublisher: synthetic\nlicense: MIT\nrule_namespace: tth\ndocuments:\n  - {document}\n"
    )
}

/// One kind of user rule content that reaches the host rule's ID.
type Place = fn(&mut RuleContent, PathBuf);

const PLACES: &[(&str, Place)] = &[
    ("organization rules", |c, p| c.packs.organization = vec![p]),
    ("deployment rules", |c, p| c.packs.deployment = vec![p]),
    ("local rules", |c, p| c.packs.local = vec![p]),
];

fn content_forms(dir: &Path) -> Vec<(String, RuleContent)> {
    let mut forms = Vec::new();
    for (name, change) in [
        ("override disables", "enabled: false"),
        ("override lowers score", "score: 5"),
    ] {
        let file = content_file(dir, &format!("{name}.yaml"), &override_entry(change));
        forms.push((name.to_owned(), content(|c| c.overrides = vec![file])));
    }
    for (name, place) in PLACES {
        let file = content_file(dir, &format!("{name}.yaml"), &rule_document(HOST_RULE));
        forms.push(((*name).to_owned(), content(|c| place(c, file))));
    }
    let file = content_file(dir, "p.yaml", &rule_package(HOST_RULE));
    forms.push((
        "package rules".to_owned(),
        content(|c| c.packs.packages = vec![file]),
    ));
    for (name, policy) in [
        (
            "policy disables a rule",
            format!("version: 1\ndisabled_rules: [{HOST_RULE}]\n"),
        ),
        (
            "policy disables the category",
            "version: 1\ndisabled_categories: [approval_bypass]\n".to_owned(),
        ),
        (
            "policy lists other rules",
            "version: 1\nenabled_rules: [network.download]\n".to_owned(),
        ),
        (
            "policy lists other categories",
            "version: 1\nenabled_categories: [network]\n".to_owned(),
        ),
    ] {
        let file = content_file(dir, &format!("{name}.yaml"), &policy);
        forms.push((name.to_owned(), content(|c| c.policy = Some(file))));
    }
    forms
}

fn write_to_hook_settings(harness: &mut Harness) -> Option<serde_json::Value> {
    harness.pre(
        "Write",
        "toolu_settings",
        json!({"file_path": "/home/synthetic/.claude/settings.json", "content": "{}"}),
    )
}

#[test]
fn the_host_rule_denies_a_write_to_the_hook_settings() {
    let mut harness = Harness::new();
    let output = write_to_hook_settings(&mut harness);
    assert_eq!(verdict(&output), Some("deny"));
    assert!(
        harness
            .decision_for("toolu_settings")
            .to_string()
            .contains(HOST_RULE),
        "the host rule is the reason"
    );
}

#[test]
fn a_call_the_host_rule_denies_is_never_allowed_under_user_content() {
    let dir = tempfile::tempdir().unwrap();
    let allowed = content_forms(dir.path())
        .into_iter()
        .filter(|(_, content)| {
            let mut harness = Harness::with(|config| config.rules = content.clone());
            verdict(&write_to_hook_settings(&mut harness)).is_none()
        })
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
    assert!(allowed.is_empty(), "allowed under: {allowed:?}");
}

#[test]
fn user_content_that_names_a_host_rule_is_invalid_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let mut accepted = Vec::new();
    for (name, content) in content_forms(dir.path()) {
        let config = Config {
            rules: content,
            ..Config::default()
        };
        match config.validate() {
            Ok(()) => accepted.push(name),
            Err(error) => {
                let error = error.to_string();
                assert!(error.contains("tth.tamper."), "{name}: {error}");
                // The message names the file, never what is in it.
                assert!(!error.contains("synthetic"), "{name}: {error}");
            }
        }
    }
    assert!(accepted.is_empty(), "accepted: {accepted:?}");
}

#[test]
fn the_pipeline_refuses_user_content_that_changes_a_host_rule() {
    let dir = tempfile::tempdir().unwrap();
    let built = content_forms(dir.path())
        .into_iter()
        .filter(|(_, content)| Engine::new(content, &[]).is_ok())
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
    assert!(built.is_empty(), "built under: {built:?}");
}

#[test]
fn an_override_that_restates_a_host_rule_is_invalid_configuration_too() {
    let dir = tempfile::tempdir().unwrap();
    let file = content_file(dir.path(), "restate.yaml", &override_entry("enabled: true"));
    let config = Config {
        rules: content(|c| c.overrides = vec![file]),
        ..Config::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn the_package_form_is_a_package() {
    // The package used above must be one the loader accepts, or the tests
    // that use it would pass for the wrong reason.
    let package = rule_package("tth.synthetic.rule");
    telltale_rules::package::RulePackage::parse(&package).unwrap();
}

#[test]
fn a_policy_that_leaves_the_self_protection_rules_alone_still_applies() {
    let dir = tempfile::tempdir().unwrap();
    for (name, policy) in [
        ("rule", "version: 1\ndisabled_rules: [network.download]\n"),
        ("category", "version: 1\ndisabled_categories: [network]\n"),
        (
            "category list",
            "version: 1\nenabled_categories: [approval_bypass, network]\n",
        ),
    ] {
        let file = content_file(dir.path(), &format!("{name}.yaml"), policy);
        let rules = content(|c| c.policy = Some(file));
        let config = Config {
            rules: rules.clone(),
            ..Config::default()
        };
        config.validate().expect(name);
        Engine::new(&rules, &[]).expect(name);
        // The host rule still denies under it.
        let mut harness = Harness::with(|config| config.rules = rules);
        let output = write_to_hook_settings(&mut harness);
        assert_eq!(verdict(&output), Some("deny"), "{name}");
    }
}

#[test]
fn without_self_protection_user_content_is_not_restricted() {
    let dir = tempfile::tempdir().unwrap();
    let file = content_file(dir.path(), "r.yaml", &rule_document(HOST_RULE));
    let rules = content(|c| {
        c.self_protection = false;
        c.packs.deployment = vec![file];
    });
    let config = Config {
        rules: rules.clone(),
        ..Config::default()
    };
    config.validate().unwrap();
    Engine::new(&rules, &[]).unwrap();
}

#[test]
fn user_content_that_does_not_name_a_host_rule_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let quiet = content_file(
        dir.path(),
        "o.yaml",
        "version: 1\noverrides:\n  - rule_id: network.download\n    score: 5\n    reason: synthetic test\n",
    );
    let own = content_file(dir.path(), "r.yaml", &rule_document("synthetic.rule"));
    let rules = content(|c| {
        c.overrides = vec![quiet];
        c.packs.deployment = vec![own];
    });
    let config = Config {
        rules: rules.clone(),
        ..Config::default()
    };
    config.validate().unwrap();
    Engine::new(&rules, &[]).unwrap();
}
