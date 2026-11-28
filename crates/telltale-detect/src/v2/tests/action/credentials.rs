use super::*;

#[test]
fn credential_native_profile_characterizes_token_families_and_rule_v1_differences() {
    let export = telltale_rules::load_default_rule_set()
        .unwrap()
        .compatibility_export();
    let plan = crate::v2::bundled_plan();
    let matcher = export
        .rules()
        .iter()
        .find(|rule| rule.id == "credential.api_key.pattern")
        .unwrap()
        .compile_content_matcher()
        .unwrap();
    // Characterization, not credential validity or independent efficacy labels:
    // Rule v1 now shares prefix case and left boundaries for sk-/GitHub/Slack/AWS
    // shapes. Native actions still refine JWT/Bearer case and reject examples.
    for token in [
        "sk-Zq3Wt9LmP2kR7vX4nB8c",
        "ghp_Zq3Wt9LmP2kR7vX4nB8c",
        "xoxb-Zq3Wt9LmP2kR7vX4nB8c",
        "AKIA2E0A8F3B244C9986",
        "eyJZq3Wt9LmP2.kR7vX4nB8c.Y1dF6hJ0sA",
        "Bearer Zq3Wt9LmP2kR7vX4nB8c",
    ] {
        for (prefix, rule_v1, native) in [
            ("", true, true),
            (" ", true, true),
            ("=", true, true),
            ("_", false, false),
            ("a", false, false),
        ] {
            let text = format!("{prefix}{token}");
            assert_eq!(
                !matcher
                    .matching_fields(&[("tool_result", &text)])
                    .is_empty(),
                rule_v1,
                "{text}"
            );
            assert_credential_projections(plan, credential_result(&text), rule_v1, native, &text);
        }
    }
    for (text, rule_v1, native) in [
        ("ordinary output", false, false),
        ("sk-too-short", false, false),
        ("SK-Zq3Wt9LmP2kR7vX4nB8c", false, false),
        ("GHP_Zq3Wt9LmP2kR7vX4nB8c", false, false),
        ("XOxb-Zq3Wt9LmP2kR7vX4nB8c", false, false),
        ("akia2e0a8f3b244c9986", false, false),
        ("prefixAKIA2E0A8F3B244C9986", false, false),
        ("eyjZq3Wt9LmP2.kR7vX4nB8c.Y1dF6hJ0sA", true, false),
        ("bearer Zq3Wt9LmP2kR7vX4nB8c", true, false),
        ("AKIAIOSFODNN7EXAMPLE", true, false),
        ("sk-1234567890abcdef", true, false),
        ("ghp_your_Zq3Wt9LmP2kR7vX4nB8c", true, false),
        ("ghp_placeholderZq3Wt9LmP2kR7vX4nB8c", true, false),
        ("ghp_REDACTEDZq3Wt9LmP2kR7vX4nB8c", true, false),
        ("ghp_fabricatedexampleZq3Wt9LmP2kR7vX4nB8c", true, false),
        ("AKIAIOSFODNN7EXAMPLE and AKIA2E0A8F3B244C9986", true, true),
        ("AKIA2E0A8F3B244C9986 and AKIAIOSFODNN7EXAMPLE", true, true),
    ] {
        assert_eq!(
            !matcher.matching_fields(&[("tool_result", text)]).is_empty(),
            rule_v1,
            "{text}"
        );
        assert_credential_projections(plan, credential_result(text), rule_v1, native, text);
    }
}

#[test]
fn credential_boundaries_and_example_exemptions_apply_to_the_same_candidate() {
    let plan = crate::v2::bundled_plan();
    for (text, session_match) in [
        ("_ghp_Zq3Wt9LmP2kR7vX4nB8c", false),
        ("AKIAIOSFODNN7EXAMPLE", true),
        ("_ghp_Zq3Wt9LmP2kR7vX4nB8c and AKIAIOSFODNN7EXAMPLE", true),
        ("AKIAIOSFODNN7EXAMPLE and _ghp_Zq3Wt9LmP2kR7vX4nB8c", true),
    ] {
        assert_credential_projections(plan, credential_result(text), session_match, false, text);
    }
}

#[test]
fn credential_action_surfaces_remain_distinct_from_session_selectors() {
    let plan = crate::v2::bundled_plan();
    let token = "ghp_Zq3Wt9LmP2kR7vX4nB8c";
    for (case, observation, session_match) in [
        ("result", credential_result(token), true),
        (
            "argument-text",
            body(
                "credential-command",
                ObservationBody::Tool(
                    ToolObservation::new()
                        .with_name("Bash")
                        .unwrap()
                        .with_arguments(JsonValue::string(token)),
                ),
                ObservationStage::ToolRequested,
            ),
            true,
        ),
        // Object arguments without a governed command facet are not serialized
        // into Rule v1 text. The action view interprets their command key.
        (
            "structured-command-without-facet",
            body(
                "credential-command-object",
                ObservationBody::Tool(
                    ToolObservation::new()
                        .with_name("Bash")
                        .unwrap()
                        .with_arguments(
                            JsonValue::try_from_source_value(
                                &serde_json::json!({"command": token}),
                            )
                            .unwrap(),
                        ),
                ),
                ObservationStage::ToolRequested,
            ),
            false,
        ),
        (
            "assistant",
            body(
                "credential-assistant",
                ObservationBody::Message(
                    MessageObservation::new(MessageRole::Assistant)
                        .with_content(JsonValue::string(token)),
                ),
                ObservationStage::MessageObserved,
            ),
            true,
        ),
        (
            "user",
            body(
                "credential-user",
                ObservationBody::Message(
                    MessageObservation::new(MessageRole::User)
                        .with_content(JsonValue::string(token)),
                ),
                ObservationStage::MessageObserved,
            ),
            false,
        ),
        (
            "authored-content",
            body(
                "credential-write",
                ObservationBody::Tool(
                    ToolObservation::new()
                        .with_name("Write")
                        .unwrap()
                        .with_arguments(
                            JsonValue::try_from_source_value(&serde_json::json!({
                                "file_path": "notes.txt", "content": token
                            }))
                            .unwrap(),
                        ),
                ),
                ObservationStage::ToolRequested,
            ),
            false,
        ),
    ] {
        assert_credential_projections(plan, observation, session_match, true, case);
    }
}
