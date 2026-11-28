use super::*;

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
