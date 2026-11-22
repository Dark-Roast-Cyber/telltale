//! With tamper prevention on (`rules.tamper_prevention`), user rule content
//! cannot remove, replace or weaken the hooks self-protection rules: content
//! that names one is invalid configuration, and the pipeline that is built
//! carries the host rules as their documents define them.
//!
//! Without it, which is the default, they are ordinary bundled rules that an
//! operator tunes like any other: an override, a policy or a replacement rule
//! applies to them.

use crate::common;

use std::path::{Path, PathBuf};

use common::{Harness, verdict};
use serde_json::json;
use telltale_core::hooks::config::{Config, RuleContent};
use telltale_core::hooks::engine::Engine;

/// Rule content under tamper prevention.
fn content(edit: impl FnOnce(&mut RuleContent)) -> RuleContent {
    let mut content = RuleContent {
        tamper_prevention: true,
        ..RuleContent::default()
    };
    edit(&mut content);
    content
}

/// Rule content as it is by default: no tamper prevention.
fn tunable(edit: impl FnOnce(&mut RuleContent)) -> RuleContent {
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

/// A UUIDv4-shaped id derived from `name`, so synthetic rules with different
/// names never share one and a replacement keeps the id of what it replaces.
fn synthetic_uuid(name: &str) -> String {
    let hash = |seed: u64| {
        name.bytes().fold(seed, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        })
    };
    let (high, low) = (hash(0xcbf2_9ce4_8422_2325), hash(0x84222325_cbf29ce4));
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        high >> 32,
        (high >> 16) & 0xffff,
        high & 0xfff,
        low >> 52,
        low & 0xffff_ffff_ffff
    )
}

fn rule_document(id: &str) -> String {
    let uuid = synthetic_uuid(id);
    format!(
        "title: synthetic\nid: {uuid}\nname: {id}\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: tool_activity\ndetection:\n    selection:\n        - tool.command|re: 'synthetic-never-matches-xyz'\n    condition: selection\nlevel: high\ntelltale:\n    category: approval_bypass\n    score: 90\n    explanation: 'synthetic.'\n    tags: [synthetic]\n"
    )
}

fn rule_package(id: &str) -> String {
    let document = rule_document(id);
    format!(
        "format: telltale-rule-package/v2\nid: synthetic.package\ntitle: Synthetic package\nversion: 1.0.0\npublisher: synthetic\nlicense: MIT\nrule_namespace: tth\n---\n{document}"
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
    let rules = tunable(|c| {
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

/// The lock is a setting of its own, and it locks rules that must be loaded.
#[test]
fn tamper_prevention_is_off_by_default_and_needs_the_rules_it_locks() {
    assert!(!RuleContent::default().tamper_prevention);
    let config = Config {
        rules: content(|c| c.self_protection = false),
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("hooks.tamper_prevention.enabled"), "{error}");
    assert!(error.contains("hooks.self_protection_rules"), "{error}");
}

/// The same rule content loads without tamper prevention, and with it the
/// only thing that changes is whether it loads.
#[test]
fn without_tamper_prevention_the_same_overrides_and_policies_load() {
    let dir = tempfile::tempdir().unwrap();
    for (name, locked) in content_forms(dir.path()) {
        // What does not build for a reason of its own, locked or not: a
        // document with another id cannot replace a rule, a package only
        // adds, and no rule has the category `network`, so a policy that
        // lists only it selects nothing.
        let replaces = PLACES.iter().any(|(place, _)| *place == name)
            || name == "package rules"
            || name == "policy lists other categories";
        let rules = RuleContent {
            tamper_prevention: false,
            ..locked
        };
        let config = Config {
            rules: rules.clone(),
            ..Config::default()
        };
        config.validate().expect(&name);
        let built = Engine::new(&rules, &[]).map(|_| ());
        assert_eq!(
            built.is_ok(),
            !replaces,
            "{name}: {:?}",
            built.err().map(|error| error.to_string())
        );
    }
}

/// An operator's override or policy decides what a self-protection rule does,
/// as for any other rule.
#[test]
fn without_tamper_prevention_an_operator_tunes_a_self_protection_rule() {
    let dir = tempfile::tempdir().unwrap();
    let decided = |rules: RuleContent| {
        let mut harness = Harness::with(|config| config.rules = rules);
        let output = write_to_hook_settings(&mut harness);
        let decision = harness.decision_for("toolu_settings");
        (
            verdict(&output).map(str::to_owned),
            decision["decision"]["rule_ids"].to_string(),
        )
    };
    // Untuned, the rule denies.
    let (untuned, rule_ids) = decided(tunable(|_| {}));
    assert_eq!(untuned.as_deref(), Some("deny"));
    assert!(rule_ids.contains(HOST_RULE), "{rule_ids}");

    // Disabled by override: the rule no longer matches.
    let off = content_file(dir.path(), "off.yaml", &override_entry("enabled: false"));
    let (_, rule_ids) = decided(tunable(|c| c.overrides = vec![off]));
    assert!(!rule_ids.contains(HOST_RULE), "{rule_ids}");

    // Scored below every threshold: it matches and restricts nothing.
    let low = content_file(dir.path(), "low.yaml", &override_entry("score: 5"));
    let (lowered, rule_ids) = decided(tunable(|c| c.overrides = vec![low]));
    assert_eq!(lowered, None);
    assert!(rule_ids.contains(HOST_RULE), "{rule_ids}");

    // The category disabled by policy: no self-protection rule matches.
    let policy = content_file(
        dir.path(),
        "policy.yaml",
        "version: 1\ndisabled_categories: [approval_bypass]\n",
    );
    let (disabled, rule_ids) = decided(tunable(|c| c.policy = Some(policy)));
    assert_eq!(disabled, None);
    assert!(!rule_ids.contains("tth.tamper."), "{rule_ids}");
}

/// A managed tier replaces a self-protection rule by name when it keeps the
/// rule's id, as it replaces a bundled core rule.
#[test]
fn without_tamper_prevention_a_managed_tier_replaces_a_self_protection_rule() {
    let dir = tempfile::tempdir().unwrap();
    let bundled = telltale_core::hooks::engine::host_rule_documents()
        .iter()
        .find_map(|(_, document)| {
            let rules = telltale_rules::LoadedRules::parse(document).unwrap();
            rules
                .definitions()
                .iter()
                .find(|definition| definition.id() == HOST_RULE)
                .and_then(|definition| definition.uuid().map(str::to_owned))
        })
        .expect("the host rule is bundled");
    let replacement = rule_document(HOST_RULE).replace(&synthetic_uuid(HOST_RULE), &bundled);
    for (name, place) in PLACES {
        let file = content_file(dir.path(), &format!("replace {name}.yaml"), &replacement);
        let rules = tunable(|c| place(c, file));
        Engine::new(&rules, &[]).expect(name);
        // The replacement never matches, so the write is no longer this
        // rule's finding.
        let mut harness = Harness::with(|config| config.rules = rules);
        write_to_hook_settings(&mut harness);
        let rule_ids = harness.decision_for("toolu_settings")["decision"]["rule_ids"].to_string();
        assert!(!rule_ids.contains(HOST_RULE), "{name}: {rule_ids}");
    }
}
