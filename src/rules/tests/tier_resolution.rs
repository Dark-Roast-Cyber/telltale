use super::*;

#[test]
fn fixture_packs_are_additive_and_stably_ordered() {
    let resolution = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
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
fn fixture_pack_replaces_bundled_rule_and_wins_evaluation() {
    let resolution = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
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
    let replacement = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
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
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rule_packs/ordered");
    let managed = root.join("organization-rules.d/10-organization.yaml");
    let alias = root
        .join("organization-rules.d")
        .join(".")
        .join("10-organization.yaml");
    let resolution = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
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

    let resolution = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
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
            let error = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
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

    let resolution = resolve_rule_set_from_pack_paths_with_mode_override_paths_and_replacements(
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
    let core = resolve(RuleLoadMode::IncludeDefault, CommunityRules::Disabled).expect("core rules");
    assert!(core.diagnostics.packages.is_empty());
    assert_eq!(
        core.rule_set.rule_count(),
        telltale_rules::load_default_rule_set()
            .unwrap()
            .rule_count()
    );
    assert!(resolve(RuleLoadMode::CustomOnly, CommunityRules::Embedded).is_err());
}
