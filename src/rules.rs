//! Rule loading for the CLI: filesystem-facing wrappers around the I/O-free
//! rule language in `telltale-rules`, which this module re-exports. Tiered
//! resolution itself lives in `telltale_core::rule_resolution`, which hooks
//! shares.

use std::path::{Path, PathBuf};

#[cfg(test)]
use telltale_core::rule_resolution::canonical_or_original;
pub(crate) use telltale_core::rule_resolution::{
    RulePackPaths, RuleResolution, RuleResolutionDiagnostics,
};
pub(crate) use telltale_rules::package::CommunityRules;
pub(crate) use telltale_rules::*;

pub fn default_rule_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("config/rules/tool-call-regex.yaml")
}

#[cfg(test)]
fn load_rule_set_from_paths_with_mode_and_override_paths(
    rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
    mode: RuleLoadMode,
    override_paths: &[PathBuf],
) -> Result<CompiledRuleSet, Box<dyn std::error::Error>> {
    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
        &RulePackPaths::default(),
        rule_paths,
        policy_path,
        mode,
        override_paths,
        &[],
    )
    .map(|resolution| resolution.rule_set)
}

/// Resolve rule content for a CLI command. The CLI's own default rule file,
/// passed explicitly, is skipped unless the mode loads custom rules only (the
/// bundled defaults already hold it).
pub(crate) fn resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
    pack_paths: &RulePackPaths,
    explicit_rule_paths: &[PathBuf],
    policy_path: Option<&Path>,
    mode: RuleLoadMode,
    override_paths: &[PathBuf],
    replacements: &[(PathBuf, &str)],
) -> Result<RuleResolution, Box<dyn std::error::Error>> {
    let explicit_rule_paths = explicit_rule_paths
        .iter()
        .filter(|path| should_load_rule_path(path, mode))
        .cloned()
        .collect::<Vec<_>>();
    telltale_core::rule_resolution::resolve_rule_set(
        pack_paths,
        &explicit_rule_paths,
        Vec::new(),
        policy_path,
        mode,
        override_paths,
        replacements,
    )
}

pub(crate) fn should_load_rule_path(path: &Path, mode: RuleLoadMode) -> bool {
    if matches!(mode, RuleLoadMode::CustomOnly) {
        return true;
    }

    let default_path = default_rule_path();
    match (path.canonicalize(), default_path.canonicalize()) {
        (Ok(path), Ok(default_path)) => path != default_path,
        _ => path != default_path,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::{
        CommunityRules, RuleLoadMode, RulePackPaths, canonical_or_original,
        resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements,
    };

    fn rule_yaml(id: &str, regex: &str, score: u64) -> String {
        format!(
            r#"version: 1
description: Test rules.
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: {id}
    category: test
    severity: low
    score: {score}
    targets: [command]
    regex: '{regex}'
    tags: [test]
    explanation: Synthetic test rule.
modifiers: []
"#
        )
    }

    fn write_rule(path: &std::path::Path, id: &str, regex: &str, score: u64) {
        fs::create_dir_all(path.parent().expect("rule parent")).expect("rule parent");
        fs::write(path, rule_yaml(id, regex, score)).expect("rule file");
    }

    fn fixture_pack_paths(name: &str) -> RulePackPaths {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rule_packs")
            .join(name);
        let discovered = crate::config::discover_local_config_files(
            std::slice::from_ref(&root),
            false,
            crate::config::LocalConfigDiscoveryKind::Rules,
        )
        .expect("fixture pack discovery");
        RulePackPaths {
            organization: discovered.organization_rule_paths,
            deployment: discovered.deployment_rule_paths,
            local: discovered.local_rule_paths,
            ..RulePackPaths::default()
        }
    }

    #[test]
    fn fixture_packs_are_additive_and_stably_ordered() {
        let resolution =
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &fixture_pack_paths("ordered"),
                &[],
                None,
                RuleLoadMode::CustomOnly,
                &[],
                &[],
            )
            .expect("resolve fixture packs");

        assert_eq!(
            resolution
                .merged_rule_set
                .rules
                .iter()
                .map(|rule| rule.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "pack.organization",
                "secret.env.read",
                "pack.deployment",
                "pack.local"
            ]
        );
    }

    #[test]
    fn cli_document_defaults_match_document_loader() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("rules.yaml");
        let other_path = temp.path().join("other.yaml");
        let other = rule_yaml("test.other", "other", 7);
        fs::write(&other_path, &other).expect("write other rules");
        for (case_insensitive, enabled, definition_enabled) in [
            (false, false, false),
            (false, false, true),
            (false, true, false),
            (false, true, true),
            (true, false, false),
            (true, false, true),
            (true, true, false),
            (true, true, true),
        ] {
            let raw = format!(
                r#"version: 1
description: document defaults
defaults: {{case_insensitive: {case_insensitive}, enabled: {enabled}}}
rules:
  - id: test.simple
    category: test
    severity: low
    score: 2
    targets: [command]
    regex: needle
    enabled: {definition_enabled}
    tags: [test]
    explanation: Synthetic test rule.
  - id: test.exclusion
    category: test
    severity: low
    score: 1
    enabled: {definition_enabled}
    detection:
      selection: {{command: needle}}
      exclude: {{command: quoted}}
      condition: selection
    tags: [test]
    explanation: Synthetic test rule.
modifiers:
  - id: test.modifier
    score: 3
    enabled: {definition_enabled}
    when_all_rule_ids: [test.simple, test.exclusion]
    explanation: Synthetic test modifier.
"#,
            );
            fs::write(&path, &raw).expect("write rules");
            let resolution =
                resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                    &RulePackPaths {
                        deployment: vec![path.clone()],
                        ..RulePackPaths::default()
                    },
                    std::slice::from_ref(&other_path),
                    None,
                    RuleLoadMode::CustomOnly,
                    &[],
                    &[],
                )
                .expect("resolve rules");
            let loaded =
                super::load_rule_set_from_documents(&[&raw, &other], None).expect("load documents");
            assert_eq!(
                resolution.merged_rule_set.rules[0].enabled,
                enabled && definition_enabled
            );
            assert_eq!(
                resolution.merged_rule_set.modifiers[0].enabled,
                enabled && definition_enabled
            );
            for text in [
                "needle",
                "NEEDLE",
                "needle QUOTED",
                "NEEDLE QUOTED",
                "other",
                "OTHER",
            ] {
                let cli_match = resolution.rule_set.evaluate(&[("command", text)]).unwrap();
                let document_match = loaded.evaluate(&[("command", text)]).unwrap();
                assert_eq!(
                    cli_match.map(|matched| (matched.rule_ids, matched.score)),
                    document_match.map(|matched| (matched.rule_ids, matched.score)),
                    "case_insensitive={case_insensitive}, enabled={enabled}, definition_enabled={definition_enabled}, text={text}"
                );
            }
            let matched = resolution
                .rule_set
                .evaluate(&[("command", "needle")])
                .unwrap();
            assert_eq!(matched.is_some(), enabled && definition_enabled);
            if let Some(matched) = matched {
                assert_eq!(matched.score, 6);
                assert_eq!(
                    matched.rule_ids,
                    ["test.simple", "test.exclusion", "test.modifier"]
                );
                let text = if case_insensitive {
                    "NEEDLE QUOTED"
                } else {
                    "needle quoted"
                };
                let excluded = resolution
                    .rule_set
                    .evaluate(&[("command", text)])
                    .unwrap()
                    .unwrap();
                assert_eq!(excluded.rule_ids, ["test.simple"]);
                assert_eq!(excluded.score, 2);
            }
            assert_eq!(
                resolution
                    .rule_set
                    .evaluate(&[("command", "NEEDLE")])
                    .unwrap()
                    .is_some(),
                case_insensitive && enabled && definition_enabled
            );
            assert_eq!(
                resolution
                    .rule_set
                    .evaluate(&[("command", "other")])
                    .unwrap()
                    .unwrap()
                    .score,
                7
            );
        }
    }

    #[test]
    fn pipeline_builder_documents_remain_additive_and_reject_duplicate_ids() {
        let first = rule_yaml("test.first", "first", 1);
        let second = rule_yaml("test.second", "second", 2);
        let pipeline = telltale_core::Pipeline::builder()
            .without_bundled_defaults()
            .rules_document(&first)
            .rules_document(&second)
            .build()
            .expect("additive documents");
        assert_eq!(pipeline.rule_count(), 2);
        for duplicate in [
            first.clone(),
            first.replace("enabled: true", "enabled: false"),
        ] {
            let error = telltale_core::Pipeline::builder()
                .without_bundled_defaults()
                .rules_document(&first)
                .rules_document(duplicate)
                .build()
                .err()
                .expect("duplicate document ID must not replace");
            let telltale_core::PipelineError::Compilation(error) = error else {
                panic!("expected duplicate compilation error");
            };
            assert_eq!(error.to_string(), "duplicate rule id: test.first");
        }
        assert!(
            telltale_core::Pipeline::builder()
                .rules_document(rule_yaml("secret.env.read", "replacement", 9))
                .build()
                .is_err()
        );
    }

    #[test]
    fn fixture_pack_replaces_bundled_rule_and_wins_evaluation() {
        let resolution =
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &fixture_pack_paths("ordered"),
                &[],
                None,
                RuleLoadMode::IncludeDefault,
                &[],
                &[],
            )
            .expect("resolve bundled fixture replacement");
        let replacement = resolution
            .merged_rule_set
            .rules
            .iter()
            .find(|rule| rule.id == "secret.env.read")
            .expect("replaced bundled rule");
        assert_eq!(replacement.score, 77);
        let provenance = resolution
            .diagnostics
            .provenance
            .iter()
            .find(|entry| entry.id == "secret.env.read")
            .expect("replacement provenance");
        assert!(provenance.winner.contains("deployment:"));
        assert_eq!(
            provenance.replaced_sources,
            vec!["builtin:telltale.default"]
        );
        let matched = resolution
            .rule_set
            .evaluate(&[("command", "fixture-secret-marker")])
            .expect("replacement should evaluate")
            .expect("replacement should match");
        assert!(matched.rule_ids.contains(&"secret.env.read".to_string()));
    }

    #[test]
    fn fixture_pack_equal_tier_conflict_reports_sources() {
        let error = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &fixture_pack_paths("conflict"),
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("equal-tier fixture conflict");
        let error = error.to_string();
        assert!(error.starts_with("duplicate rule id: pack.conflict"));
        assert!(error.contains("10-first.yaml"));
        assert!(error.contains("20-second.yaml"));
    }

    #[test]
    fn fixture_modifier_replacement_and_conflict_follow_rule_semantics() {
        let replacement =
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &fixture_pack_paths("modifier-replacement"),
                &[],
                None,
                RuleLoadMode::CustomOnly,
                &[],
                &[],
            )
            .expect("modifier replacement");
        assert_eq!(replacement.merged_rule_set.modifiers[0].score, 9);
        assert_eq!(
            replacement
                .diagnostics
                .provenance
                .iter()
                .find(|entry| entry.id == "pack.modifier")
                .expect("modifier provenance")
                .replaced_sources
                .len(),
            1
        );

        let conflict = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &fixture_pack_paths("modifier-conflict"),
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("modifier conflict");
        assert!(
            conflict
                .to_string()
                .starts_with("duplicate rule id: pack.modifier.conflict")
        );
    }

    #[test]
    fn fixture_cross_kind_collision_is_rejected() {
        let error = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &fixture_pack_paths("cross-kind"),
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("cross-kind collision");
        let error = error.to_string();
        assert!(error.starts_with("duplicate rule id: pack.cross_kind"));
        assert!(error.contains("rule"));
        assert!(error.contains("modifier"));
        assert!(error.contains("10-rule.yaml"));
        assert!(error.contains("20-modifier.yaml"));
    }

    #[test]
    fn canonical_alias_of_managed_file_is_not_loaded_twice() {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rule_packs/ordered");
        let managed = root.join("organization-rules.d/10-organization.yaml");
        let alias = root
            .join("organization-rules.d")
            .join(".")
            .join("10-organization.yaml");
        let resolution =
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &RulePackPaths {
                    organization: vec![managed],
                    ..RulePackPaths::default()
                },
                &[alias],
                None,
                RuleLoadMode::CustomOnly,
                &[],
                &[],
            )
            .expect("canonical alias dedupe");
        assert_eq!(resolution.rule_set.rule_count(), 1);
    }

    #[test]
    fn ordered_packs_add_rules_and_replace_in_place() {
        let temp = tempdir().expect("tempdir");
        let deployment_first = temp.path().join("rules.d/a-deployment.yaml");
        let deployment_second = temp.path().join("rules.d/b-deployment.yaml");
        let local = temp.path().join("ui-rules.d/local.yaml");
        write_rule(&deployment_first, "pack.first", "first", 1);
        write_rule(&deployment_second, "pack.second", "second", 2);
        write_rule(&local, "pack.first", "replacement", 9);
        write_rule(
            &temp.path().join("organization-rules.d/organization.yaml"),
            "organization.only",
            "organization",
            3,
        );

        let resolution =
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &RulePackPaths {
                    organization: vec![temp.path().join("organization-rules.d/organization.yaml")],
                    deployment: vec![deployment_first, deployment_second],
                    local: vec![local],
                    ..RulePackPaths::default()
                },
                &[],
                None,
                RuleLoadMode::CustomOnly,
                &[],
                &[],
            )
            .expect("resolve packs");

        assert_eq!(
            resolution
                .merged_rule_set
                .rules
                .iter()
                .map(|rule| rule.id.as_str())
                .collect::<Vec<_>>(),
            vec!["organization.only", "pack.first", "pack.second"]
        );
        assert_eq!(resolution.merged_rule_set.rules[1].score, 9);
        let first = resolution
            .diagnostics
            .provenance
            .iter()
            .find(|entry| entry.id == "pack.first")
            .expect("replacement provenance");
        assert!(first.winner.contains("local-ui:"));
        assert_eq!(first.replaced_sources.len(), 1);
        assert!(first.replaced_sources[0].contains("deployment:"));
    }

    #[test]
    fn unsupported_pack_versions_fail_even_when_shadowed_or_disabled() {
        let temp = tempdir().expect("tempdir");
        let deployment = temp.path().join("rules.d/deployment.yaml");
        let local = temp.path().join("ui-rules.d/local.yaml");
        write_rule(&deployment, "pack.same", "first", 1);
        write_rule(&local, "pack.same", "replacement", 2);
        let paths = RulePackPaths {
            deployment: vec![deployment.clone()],
            local: vec![local.clone()],
            ..RulePackPaths::default()
        };
        let valid = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &paths,
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect("v1 pack replacement");
        assert_eq!(valid.merged_rule_set.version, 1);
        assert_eq!(valid.merged_rule_set.rules[0].score, 2);
        assert_eq!(valid.diagnostics.provenance[0].replaced_sources.len(), 1);

        for version in [0, 2] {
            for path in [&deployment, &local] {
                let raw = rule_yaml("pack.same", "first", 1)
                    .replacen("version: 1", &format!("version: {version}"), 1)
                    .replacen("enabled: true", "enabled: false", 1);
                let error =
                    resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                        &paths,
                        &[],
                        None,
                        RuleLoadMode::CustomOnly,
                        &[],
                        &[(path.clone(), &raw)],
                    )
                    .expect_err("unsupported pack version must not be laundered")
                    .to_string();
                assert!(
                    error.contains(&format!(
                        "unsupported rule set version {version}; only version 1 is supported"
                    )),
                    "{error}"
                );
                let tier = if path == &deployment {
                    "deployment"
                } else {
                    "local-ui"
                };
                assert!(
                    error.contains(&format!("invalid rule document '{tier}:")),
                    "{error}"
                );
                let filename = path.file_name().expect("rule filename").to_string_lossy();
                assert!(
                    error.contains(&format!("{filename}#document:0'")),
                    "{error}"
                );
            }
        }
    }

    #[test]
    fn equal_tier_duplicate_reports_both_sources() {
        let temp = tempdir().expect("tempdir");
        let first = temp.path().join("one.yaml");
        let second = temp.path().join("two.yaml");
        write_rule(&first, "same.id", "one", 1);
        write_rule(&second, "same.id", "two", 2);

        let error = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &RulePackPaths {
                organization: vec![first.clone(), second.clone()],
                ..RulePackPaths::default()
            },
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("equal-tier duplicate");
        let error = error.to_string();
        assert!(error.starts_with("duplicate rule id: same.id"));
        assert!(error.contains(&canonical_or_original(&first).display().to_string()));
        assert!(error.contains(&canonical_or_original(&second).display().to_string()));
    }

    #[test]
    fn explicit_rules_are_additive_only_after_managed_packs() {
        let temp = tempdir().expect("tempdir");
        let managed = temp.path().join("rules.d/managed.yaml");
        let explicit = temp.path().join("explicit.yaml");
        write_rule(&managed, "managed.id", "managed", 1);
        write_rule(&explicit, "explicit.id", "explicit", 2);

        let resolution =
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &RulePackPaths {
                    deployment: vec![managed.clone()],
                    ..RulePackPaths::default()
                },
                std::slice::from_ref(&explicit),
                None,
                RuleLoadMode::CustomOnly,
                &[],
                &[],
            )
            .expect("explicit additive rule");
        assert_eq!(resolution.rule_set.rule_count(), 2);

        let collision = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &RulePackPaths {
                deployment: vec![temp.path().join("rules.d/managed.yaml")],
                ..RulePackPaths::default()
            },
            std::slice::from_ref(&managed),
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect("same canonical managed and explicit path is deduplicated");
        assert_eq!(collision.rule_set.rule_count(), 1);

        let explicit_collision = temp.path().join("explicit-collision.yaml");
        write_rule(&explicit_collision, "managed.id", "collision", 3);
        let collision = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &RulePackPaths {
                deployment: vec![managed.clone()],
                ..RulePackPaths::default()
            },
            std::slice::from_ref(&explicit_collision),
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("distinct explicit collision");
        let collision = collision.to_string();
        assert!(collision.contains(&canonical_or_original(&managed).display().to_string()));
        assert!(
            collision.contains(
                &canonical_or_original(&explicit_collision)
                    .display()
                    .to_string()
            )
        );

        let duplicate = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &RulePackPaths::default(),
            &[explicit.clone(), explicit],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("repeated explicit document");
        assert!(
            duplicate
                .to_string()
                .starts_with("duplicate rule id: explicit.id")
        );
    }

    #[test]
    fn invalid_higher_tier_winner_does_not_fall_back() {
        let temp = tempdir().expect("tempdir");
        let deployment = temp.path().join("rules.d/deployment.yaml");
        let local = temp.path().join("ui-rules.d/local.yaml");
        write_rule(&deployment, "same.id", "valid", 1);
        write_rule(&local, "same.id", "[", 9);

        let error = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &RulePackPaths {
                deployment: vec![deployment],
                local: vec![local],
                ..RulePackPaths::default()
            },
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("invalid replacement must fail");
        assert!(error.to_string().contains("same.id"));
    }

    #[test]
    fn rule_overrides_disable_rules_and_change_scores() {
        let temp = tempdir().expect("tempdir");
        let override_path = temp.path().join("override.yaml");
        fs::write(
            &override_path,
            r#"version: 1
overrides:
  - rule_id: network.download
    enabled: false
    reason: Too noisy for this fixture.
  - rule_id: secret.env.read
    score: 7
    reason: Lab tuning.
"#,
        )
        .expect("write override");

        let rule_set = super::load_rule_set_from_paths_with_mode_and_override_paths(
            &[],
            None,
            super::RuleLoadMode::IncludeDefault,
            &[override_path],
        )
        .expect("load overridden rules");

        assert!(
            !rule_set
                .summaries()
                .iter()
                .any(|rule| rule.id == "network.download")
        );
        assert_eq!(
            rule_set
                .summaries()
                .iter()
                .find(|rule| rule.id == "secret.env.read")
                .expect("secret rule")
                .score,
            7
        );
    }

    #[test]
    fn rule_overrides_reject_unknown_rule_ids() {
        let temp = tempdir().expect("tempdir");
        let override_path = temp.path().join("override.yaml");
        fs::write(
            &override_path,
            r#"version: 1
overrides:
  - rule_id: chain.download_then_execute
    enabled: false
    reason: Modifier override is not supported yet.
"#,
        )
        .expect("write override");

        let error = super::load_rule_set_from_paths_with_mode_and_override_paths(
            &[],
            None,
            super::RuleLoadMode::IncludeDefault,
            &[override_path],
        )
        .expect_err("modifier override should fail")
        .to_string();

        assert!(error.contains("unknown rule_id 'chain.download_then_execute'"));
    }

    #[test]
    fn rule_overrides_require_reason_and_effect() {
        let temp = tempdir().expect("tempdir");
        let override_path = temp.path().join("override.yaml");
        fs::write(
            &override_path,
            r#"version: 1
overrides:
  - rule_id: network.download
    reason: "   "
"#,
        )
        .expect("write override");

        let error = super::load_rule_set_from_paths_with_mode_and_override_paths(
            &[],
            None,
            super::RuleLoadMode::IncludeDefault,
            &[override_path],
        )
        .expect_err("invalid override should fail")
        .to_string();

        assert!(error.contains("requires a non-empty reason"));
    }

    #[test]
    fn rule_overrides_apply_later_paths_deterministically() {
        let temp = tempdir().expect("tempdir");
        let first_override = temp.path().join("a.yaml");
        let second_override = temp.path().join("b.yaml");
        fs::write(
            &first_override,
            r#"version: 1
overrides:
  - rule_id: network.download
    score: 5
    reason: First local tuning.
"#,
        )
        .expect("write first override");
        fs::write(
            &second_override,
            r#"version: 1
overrides:
  - rule_id: network.download
    score: 12
    reason: Later local tuning wins.
"#,
        )
        .expect("write second override");

        let rule_set = super::load_rule_set_from_paths_with_mode_and_override_paths(
            &[],
            None,
            super::RuleLoadMode::IncludeDefault,
            &[first_override, second_override],
        )
        .expect("load overridden rules");

        assert_eq!(
            rule_set
                .summaries()
                .iter()
                .find(|rule| rule.id == "network.download")
                .expect("download rule")
                .score,
            12
        );
    }

    fn package_yaml(id: &str, namespace: &str, document: &str) -> String {
        let mut lines = document.lines();
        let mut yaml = format!(
            "format: telltale-rule-package/v1\nid: {id}\nversion: \"1.0.0\"\npublisher: Synthetic\nlicense: Apache-2.0\nrule_namespace: {namespace}\ndocuments:\n  - {}\n",
            lines.next().expect("document line")
        );
        for line in lines {
            yaml.push_str(&format!("    {line}\n"));
        }
        yaml
    }

    #[test]
    fn package_rules_are_additive_and_operator_tiers_can_replace_them() {
        let temp = tempdir().expect("tempdir");
        let package = temp.path().join("rule-packages.d/acme.yaml");
        fs::create_dir_all(package.parent().unwrap()).expect("package dir");
        fs::write(
            &package,
            package_yaml(
                "acme.rules",
                "acme",
                &rule_yaml("acme.marker", "packaged", 5),
            ),
        )
        .expect("package");
        let organization = temp.path().join("organization-rules.d/tuned.yaml");
        write_rule(&organization, "acme.marker", "tuned", 9);
        let pack_paths = |organization: Vec<PathBuf>| RulePackPaths {
            organization,
            packages: vec![package.clone()],
            ..RulePackPaths::default()
        };

        let packaged = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &pack_paths(Vec::new()),
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect("package resolves");
        assert_eq!(packaged.merged_rule_set.rules[0].score, 5);
        assert_eq!(packaged.diagnostics.packages.len(), 1);
        assert_eq!(packaged.diagnostics.packages[0].id, "acme.rules");
        assert!(!packaged.diagnostics.packages[0].embedded);

        let tuned = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &pack_paths(vec![organization]),
            &[],
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect("organization tier replaces package rule");
        assert_eq!(tuned.merged_rule_set.rules[0].score, 9);
        let provenance = &tuned.diagnostics.provenance[0];
        assert!(provenance.winner.starts_with("organization:"));
        assert!(provenance.replaced_sources[0].starts_with("package:acme.rules@1.0.0:"));

        let explicit = temp.path().join("explicit.yaml");
        write_rule(&explicit, "acme.marker", "explicit", 3);
        let error = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &pack_paths(Vec::new()),
            std::slice::from_ref(&explicit),
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .expect_err("explicit rules cannot replace package rules");
        assert!(
            error.to_string().contains("duplicate rule id: acme.marker"),
            "{error}"
        );
    }

    #[test]
    fn embedded_community_package_loads_only_with_bundled_defaults() {
        let resolve = |mode, community| {
            resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
                &RulePackPaths {
                    community,
                    ..RulePackPaths::default()
                },
                &[],
                None,
                mode,
                &[],
                &[],
            )
        };
        let default =
            resolve(RuleLoadMode::IncludeDefault, CommunityRules::Embedded).expect("default rules");
        assert_eq!(default.diagnostics.packages.len(), 1);
        assert!(default.diagnostics.packages[0].embedded);
        assert!(
            default
                .diagnostics
                .sources
                .iter()
                .any(|source| source.starts_with("package:telltale.community@"))
        );
        let core =
            resolve(RuleLoadMode::IncludeDefault, CommunityRules::Disabled).expect("core rules");
        assert!(core.diagnostics.packages.is_empty());
        assert_eq!(
            core.rule_set.rule_count(),
            telltale_rules::load_default_rule_set()
                .unwrap()
                .rule_count()
        );
        assert!(resolve(RuleLoadMode::CustomOnly, CommunityRules::Embedded).is_err());
    }
}
