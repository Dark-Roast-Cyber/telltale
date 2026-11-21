//! Rule loading for the CLI: filesystem-facing wrappers around the I/O-free
//! rule language in `telltale-rules`, which this module re-exports. Tiered
//! resolution itself lives in `telltale_core::rule_resolution`, which hooks
//! shares.

use std::path::{Path, PathBuf};

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
        CommunityRules, RuleLoadMode, RulePackPaths,
        resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements,
    };

    fn rules(content: &super::LoadedRules) -> impl Iterator<Item = &super::LoadedDefinition> {
        content
            .definitions()
            .iter()
            .filter(|definition| definition.kind() == super::DefinitionKind::Rule)
    }

    fn modifiers(content: &super::LoadedRules) -> impl Iterator<Item = &super::LoadedDefinition> {
        content
            .definitions()
            .iter()
            .filter(|definition| definition.kind() == super::DefinitionKind::Modifier)
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

    fn rule_yaml(id: &str, regex: &str, score: u64) -> String {
        let uuid = synthetic_uuid(id);
        format!(
            r#"title: Synthetic test rule
id: {uuid}
name: {id}
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re: '{regex}'
    condition: selection
level: low
telltale:
    category: test
    score: {score}
    explanation: 'Synthetic test rule.'
    tags: [test]
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
            rules(&resolution.content)
                .map(|rule| rule.id())
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
    fn cli_rule_files_match_document_loader() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("rules.yaml");
        let other_path = temp.path().join("other.yaml");
        let other = rule_yaml("test.other", "other", 7);
        fs::write(&other_path, &other).expect("write other rules");
        // Rule v2 has no document defaults: each document spells its own case
        // flag and `enabled`.
        for (case_insensitive, enabled) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let flag = if case_insensitive { "|i" } else { "" };
            let raw = format!(
                r#"title: Synthetic test rule
id: 2ad880ae-fb1b-4b0e-808f-e31e860e9a2b
name: test.simple
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re{flag}: 'needle'
    condition: selection
level: low
telltale:
    category: test
    score: 2
    explanation: 'Synthetic test rule.'
    tags: [test]
    enabled: {enabled}
---
title: Synthetic test rule
id: dec4ef35-33d2-444b-8e58-9bde2718b4a8
name: test.exclusion
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection_command:
        tool.command|re{flag}: 'needle'
    filter_command:
        tool.command|re{flag}: 'quoted'
    condition: selection_command and not filter_command
level: low
telltale:
    category: test
    score: 1
    explanation: 'Synthetic test rule.'
    tags: [test]
    enabled: {enabled}
---
title: Synthetic test modifier
id: 7fa8798b-5480-4d1f-8de3-961ebb03c0f8
name: test.modifier
taxonomy: telltale
correlation:
    type: telltale_chain
    rules: [test.simple, test.exclusion]
telltale:
    score: 3
    explanation: 'Synthetic test modifier.'
    enabled: {enabled}
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
                rules(&resolution.content).next().unwrap().enabled(),
                enabled
            );
            assert_eq!(
                modifiers(&resolution.content).next().unwrap().enabled(),
                enabled
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
                    "case_insensitive={case_insensitive}, enabled={enabled}, text={text}"
                );
            }
            let matched = resolution
                .rule_set
                .evaluate(&[("command", "needle")])
                .unwrap();
            assert_eq!(matched.is_some(), enabled);
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
                case_insensitive && enabled
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
            first.replace(
                "    tags: [test]\n",
                "    tags: [test]\n    enabled: false\n",
            ),
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
            assert_eq!(error.to_string(), "rule_content_duplicate_id");
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
            .content
            .get("secret.env.read")
            .expect("replaced bundled rule");
        assert_eq!(replacement.score(), 77);
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
        assert_eq!(modifiers(&replacement.content).next().unwrap().score(), 9);
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
            rules(&resolution.content)
                .map(|rule| rule.id())
                .collect::<Vec<_>>(),
            vec!["organization.only", "pack.first", "pack.second"]
        );
        assert_eq!(rules(&resolution.content).nth(1).unwrap().score(), 9);
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
        .expect("pack replacement");
        assert_eq!(rules(&valid.content).next().unwrap().score(), 2);
        assert_eq!(valid.diagnostics.provenance[0].replaced_sources.len(), 1);

        // A Rule v1 document, of any version, fails even when a higher tier
        // shadows it or it is disabled.
        for version in [0, 1, 2] {
            for path in [&deployment, &local] {
                let raw = format!(
                    "version: {version}\n{}",
                    rule_yaml("pack.same", "first", 1).replacen(
                        "    tags: [test]\n",
                        "    tags: [test]\n    enabled: false\n",
                        1
                    )
                );
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
                    error.contains(telltale_rules::rule_v2::RULE_V1_UNSUPPORTED),
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
        assert!(error.contains("one.yaml#document:0"), "{error}");
        assert!(error.contains("two.yaml#document:0"), "{error}");
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
        assert!(collision.contains("managed.yaml#document:0"), "{collision}");
        assert!(
            collision.contains("explicit-collision.yaml#document:0"),
            "{collision}"
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
        format!(
            "format: telltale-rule-package/v2\nid: {id}\ntitle: Synthetic package\nversion: \"1.0.0\"\npublisher: Synthetic\nlicense: Apache-2.0\nrule_namespace: {namespace}\n---\n{document}"
        )
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
        assert_eq!(rules(&packaged.content).next().unwrap().score(), 5);
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
        assert_eq!(rules(&tuned.content).next().unwrap().score(), 9);
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

    const UUID_A: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
    const UUID_B: &str = "9b2d6c8e-1f4a-4c3b-8d2e-5a6f7b8c9d0e";

    fn v2_rule_yaml(name: &str, uuid: &str, marker: &str, score: u64) -> String {
        format!(
            "title: Synthetic v2 rule\nid: {uuid}\nname: {name}\ntaxonomy: telltale\n\
             status: test\nlogsource:\n    product: ai_agent\n    category: tool_activity\n\
             detection:\n    selection:\n        tool.command|contains: {marker}\n    condition: selection\n\
             level: low\ntelltale:\n    category: test\n    score: {score}\n    explanation: Synthetic v2 rule.\n"
        )
    }

    fn write_v2(path: &std::path::Path, name: &str, uuid: &str, marker: &str, score: u64) {
        fs::create_dir_all(path.parent().expect("rule parent")).expect("rule parent");
        fs::write(path, v2_rule_yaml(name, uuid, marker, score)).expect("rule file");
    }

    fn custom(
        paths: &RulePackPaths,
        explicit: &[PathBuf],
    ) -> Result<super::RuleResolution, String> {
        resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            paths,
            explicit,
            None,
            RuleLoadMode::CustomOnly,
            &[],
            &[],
        )
        .map_err(|error| error.to_string())
    }

    #[test]
    fn rule_v2_files_load_in_every_tier() {
        let temp = tempdir().expect("tempdir");
        let organization = temp.path().join("organization-rules.d/org.yml");
        let deployment = temp.path().join("rules.d/deployment.yaml");
        let local = temp.path().join("ui-rules.d/local.yml");
        let explicit = temp.path().join("explicit.yml");
        write_v2(&organization, "v2.organization", UUID_A, "org-marker", 1);
        write_v2(&deployment, "v2.deployment", UUID_B, "deployment-marker", 2);
        write_v2(
            &local,
            "v2.local",
            "0d0c4f7e-2a1b-4c3d-8e5f-6a7b8c9d0e1f",
            "local-marker",
            3,
        );
        write_v2(
            &explicit,
            "v2.explicit",
            "1e1d5a8f-3b2c-4d4e-9f6a-7b8c9d0e1f2a",
            "explicit-marker",
            4,
        );
        let package = temp.path().join("rule-packages.d/acme.yaml");
        fs::create_dir_all(package.parent().unwrap()).expect("package dir");
        // A package is its header, then each rule file document verbatim.
        let packaged = v2_rule_yaml(
            "acme.v2",
            "2f2e6b9a-4c3d-4e5f-a07b-8c9d0e1f2a3b",
            "package-marker",
            5,
        );
        fs::write(
            &package,
            format!(
                "format: telltale-rule-package/v2\nid: acme.rules\ntitle: Acme rules\nversion: 1.0.0\n\
                 publisher: Synthetic\nlicense: Apache-2.0\nrule_namespace: acme\n---\n{packaged}"
            ),
        )
        .expect("package");
        let resolution = custom(
            &RulePackPaths {
                organization: vec![organization],
                deployment: vec![deployment],
                local: vec![local],
                packages: vec![package],
                ..RulePackPaths::default()
            },
            &[explicit],
        )
        .expect("v2 tiers resolve");
        let ids = resolution
            .rule_set
            .summaries()
            .into_iter()
            .map(|summary| (summary.id, summary.score))
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                ("acme.v2".to_owned(), 5),
                ("v2.organization".to_owned(), 1),
                ("v2.deployment".to_owned(), 2),
                ("v2.local".to_owned(), 3),
                ("v2.explicit".to_owned(), 4),
            ]
        );
        let packaged = resolution.content.get("acme.v2").expect("packaged rule");
        assert_eq!(packaged.package_id(), Some("acme.rules"));
        assert_eq!(resolution.diagnostics.packages[0].id, "acme.rules");
        assert!(
            resolution
                .diagnostics
                .provenance
                .iter()
                .any(|entry| entry.id == "v2.local" && entry.winner.starts_with("local-ui:"))
        );
    }

    #[test]
    fn rule_v2_tier_replacement_keeps_the_uuid() {
        let temp = tempdir().expect("tempdir");
        let deployment = temp.path().join("rules.d/base.yml");
        let local = temp.path().join("ui-rules.d/tuned.yml");
        write_v2(&deployment, "v2.same", UUID_A, "base-marker", 1);
        write_v2(&local, "v2.same", UUID_A, "tuned-marker", 9);
        let paths = RulePackPaths {
            deployment: vec![deployment.clone()],
            local: vec![local.clone()],
            ..RulePackPaths::default()
        };
        let replaced = custom(&paths, &[]).expect("same-UUID replacement");
        let rule = replaced.content.get("v2.same").unwrap();
        assert_eq!((rule.score(), rule.uuid()), (9, Some(UUID_A)));
        assert_eq!(replaced.diagnostics.provenance[0].replaced_sources.len(), 1);

        write_v2(&local, "v2.same", UUID_B, "tuned-marker", 9);
        let error = custom(&paths, &[]).expect_err("a different UUID does not replace");
        assert!(error.contains("rule 'v2.same'"), "{error}");
        assert!(error.contains(UUID_A) && error.contains(UUID_B), "{error}");
    }

    #[test]
    fn rule_v2_duplicates_fail_within_a_tier_and_by_uuid_across_names() {
        let temp = tempdir().expect("tempdir");
        let first = temp.path().join("rules.d/a.yml");
        let second = temp.path().join("rules.d/b.yml");
        write_v2(&first, "v2.same", UUID_A, "first", 1);
        write_v2(&second, "v2.same", UUID_B, "second", 2);
        let paths = RulePackPaths {
            deployment: vec![first.clone(), second.clone()],
            ..RulePackPaths::default()
        };
        let error = custom(&paths, &[]).expect_err("equal-tier duplicate");
        assert!(error.starts_with("duplicate rule id: v2.same"), "{error}");

        write_v2(&second, "v2.other", UUID_A, "second", 2);
        let error = custom(&paths, &[]).expect_err("one UUID on two names");
        assert!(
            error.contains(&format!("duplicate Rule v2 id {UUID_A}")),
            "{error}"
        );

        let local = temp.path().join("ui-rules.d/other.yml");
        write_v2(&second, "v2.other", UUID_B, "second", 2);
        write_v2(&local, "v2.third", UUID_A, "local", 3);
        let error = custom(
            &RulePackPaths {
                deployment: vec![first, second],
                local: vec![local],
                ..RulePackPaths::default()
            },
            &[],
        )
        .expect_err("one UUID on two names across tiers");
        assert!(
            error.contains(&format!("duplicate Rule v2 id {UUID_A}")),
            "{error}"
        );
    }

    #[test]
    fn overrides_and_policies_reach_rule_v2_rules_by_name() {
        let temp = tempdir().expect("tempdir");
        let rules_path = temp.path().join("rules.d/v2.yml");
        write_v2(&rules_path, "v2.tuned", UUID_A, "marker", 10);
        let override_path = temp.path().join("overrides.d/tune.yaml");
        fs::create_dir_all(override_path.parent().unwrap()).unwrap();
        fs::write(
            &override_path,
            "version: 1\noverrides:\n  - rule_id: v2.tuned\n    reason: synthetic tuning\n    score: 40\n",
        )
        .unwrap();
        let policy_path = temp.path().join("policy.yaml");
        fs::write(
            &policy_path,
            "name: synthetic\ndisabled_rules: [v2.tuned]\n",
        )
        .unwrap();
        let paths = RulePackPaths {
            deployment: vec![rules_path],
            ..RulePackPaths::default()
        };
        let tuned = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &paths,
            &[],
            None,
            RuleLoadMode::IncludeDefault,
            std::slice::from_ref(&override_path),
            &[],
        )
        .expect("override applies");
        let summary = tuned
            .rule_set
            .summaries()
            .into_iter()
            .find(|summary| summary.id == "v2.tuned")
            .expect("tuned rule");
        assert_eq!(summary.score, 40);
        let filtered = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &paths,
            &[],
            Some(&policy_path),
            RuleLoadMode::IncludeDefault,
            &[override_path],
            &[],
        )
        .expect("policy applies");
        assert!(
            !filtered
                .rule_set
                .summaries()
                .iter()
                .any(|summary| summary.id == "v2.tuned")
        );
        assert!(filtered.content.get("v2.tuned").unwrap().enabled());
    }

    /// The CLI resolves a config root; an embedding host feeds the builder the
    /// same documents as text in tier order. Both must give the same semantic
    /// identity and the same action records over the synthetic fixture stores.
    #[test]
    fn config_root_and_builder_agree_on_identity_and_action_records() {
        use telltale_core::{DetailedEvaluationOptions, Pipeline};

        let bundled_download_uuid = super::bundled_default_rules()
            .unwrap()
            .get("network.download")
            .and_then(|definition| definition.uuid().map(str::to_owned))
            .expect("bundled download rule");
        let root = tempdir().expect("config root");
        for (name, raw) in [
            (
                "organization-rules.d/10-replace.yaml",
                v2_rule_yaml("network.download", &bundled_download_uuid, "curl", 11),
            ),
            (
                "organization-rules.d/20-add.yaml",
                v2_rule_yaml("org.synthetic.git", UUID_A, "git", 7),
            ),
            (
                "overrides.d/10-tune.yaml",
                "version: 1\noverrides:\n  - rule_id: persistence.shell_profile\n    reason: Synthetic.\n    enabled: false\n  - rule_id: destructive.git_discard\n    reason: Synthetic.\n    score: 5\n".to_owned(),
            ),
            (
                "overrides.d/20-more.yaml",
                "version: 1\noverrides:\n  - rule_id: org.synthetic.git\n    reason: Synthetic.\n    score: 9\n".to_owned(),
            ),
            (
                "policies.d/policy.yaml",
                "disabled_rules: [destructive.database_drop]\n".to_owned(),
            ),
        ] {
            let path = root.path().join(name);
            fs::create_dir_all(path.parent().expect("parent")).expect("parent");
            fs::write(path, raw).expect("config file");
        }
        let discovered = crate::config::discover_local_config_files(
            std::slice::from_ref(&root.path().to_path_buf()),
            false,
            crate::config::LocalConfigDiscoveryKind::Rules,
        )
        .expect("discover config root");
        let policy_path = crate::config::resolve_policy_path(None, &discovered.policy_paths)
            .expect("one policy")
            .expect("discovered policy");
        let cli = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
            &RulePackPaths {
                organization: discovered.organization_rule_paths.clone(),
                ..RulePackPaths::default()
            },
            &[],
            Some(&policy_path),
            RuleLoadMode::IncludeDefault,
            &discovered.override_paths,
            &[],
        )
        .expect("CLI resolution")
        .into_pipeline()
        .expect("CLI pipeline");

        let read = |path: &PathBuf| fs::read_to_string(path).expect("document text");
        let builder = Pipeline::builder()
            .policy_document(read(&policy_path))
            .labeled_organization_rules_document(
                "replace",
                read(&discovered.organization_rule_paths[0]),
            )
            .labeled_organization_rules_document(
                "add",
                read(&discovered.organization_rule_paths[1]),
            )
            .labeled_override_document("tune", read(&discovered.override_paths[0]))
            .labeled_override_document("more", read(&discovered.override_paths[1]))
            .build()
            .expect("builder pipeline");

        let options = DetailedEvaluationOptions::default();
        let identity = cli.semantic_provenance(&options).unwrap();
        assert_eq!(
            builder.semantic_provenance(&options).unwrap().identity(),
            identity.identity()
        );
        let untuned = Pipeline::builder().build().unwrap();
        assert_ne!(
            untuned.semantic_provenance(&options).unwrap().identity(),
            identity.identity()
        );

        let fixtures =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/session_stores");
        let records = |pipeline: &Pipeline| {
            pipeline
                .scan_root_detailed(&fixtures, &options)
                .expect("fixture scan")
                .iter()
                .flat_map(|scan| scan.action_records())
                .map(|mut record| {
                    // A random Event 3 ID, new on every scan.
                    record.session_event_id = None;
                    serde_json::to_value(record).expect("record json")
                })
                .collect::<Vec<_>>()
        };
        let cli_records = records(&cli);
        assert!(!cli_records.is_empty());
        assert_eq!(records(&builder), cli_records);
    }
}
