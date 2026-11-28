use super::*;

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

    let rule_set = super::super::load_rule_set_from_paths_with_mode_and_override_paths(
        &[],
        None,
        super::super::RuleLoadMode::IncludeDefault,
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
fn rule_overrides_apply_to_chains_and_leave_out_unknown_rule_ids() {
    let temp = tempdir().expect("tempdir");
    let override_path = temp.path().join("override.yaml");
    fs::write(
        &override_path,
        r#"version: 1
overrides:
  - rule_id: chain.download_then_execute
    enabled: false
    reason: Synthetic chain override.
  - rule_id: synthetic.missing
    enabled: false
    reason: Synthetic override for a rule that is not loaded.
  - rule_id: tth.tamper.synthetic_missing
    enabled: false
    reason: Synthetic override for a hooks rule.
"#,
    )
    .expect("write override");

    let rule_set = super::super::load_rule_set_from_paths_with_mode_and_override_paths(
        &[],
        None,
        super::super::RuleLoadMode::IncludeDefault,
        &[override_path],
    )
    .expect("an unknown rule_id is left out");

    assert!(
        !rule_set
            .compatibility_export()
            .modifiers()
            .iter()
            .any(|modifier| modifier.id == "chain.download_then_execute")
    );
    let left_out = rule_set
        .notices()
        .iter()
        .filter(|notice| notice.kind == super::super::RuleLoadNotice::OVERRIDE_LEFT_OUT)
        .map(|notice| notice.rule_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(left_out, ["synthetic.missing"]);
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

    let error = super::super::load_rule_set_from_paths_with_mode_and_override_paths(
        &[],
        None,
        super::super::RuleLoadMode::IncludeDefault,
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

    let rule_set = super::super::load_rule_set_from_paths_with_mode_and_override_paths(
        &[],
        None,
        super::super::RuleLoadMode::IncludeDefault,
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
