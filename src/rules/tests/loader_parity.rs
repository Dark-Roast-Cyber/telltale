use super::*;

#[test]
fn cli_rule_files_match_document_loader() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("rules.yaml");
    let other_path = temp.path().join("other.yaml");
    let other = rule_yaml("test.other", "other", 7);
    fs::write(&other_path, &other).expect("write other rules");
    // Rule v2 has no document defaults: each document spells its own case
    // flag and `enabled`.
    for (case_insensitive, enabled) in [(false, false), (false, true), (true, false), (true, true)]
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
        let loaded = super::super::load_rule_set_from_documents(&[&raw, &other], None)
            .expect("load documents");
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

/// The CLI resolves a config root; an embedding host feeds the builder the
/// same documents as text in tier order. Both must give the same semantic
/// identity and the same action records over the synthetic fixture stores.
#[test]
fn config_root_and_builder_agree_on_identity_and_action_records() {
    use telltale_core::{DetailedEvaluationOptions, Pipeline};

    let bundled_download_uuid = super::super::bundled_default_rules()
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
        .labeled_organization_rules_document("add", read(&discovered.organization_rule_paths[1]))
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

    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/session_stores");
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
