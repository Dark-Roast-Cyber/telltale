use super::rule_v1::evaluate_rule_v1_session_with_budget;
use super::session::RetentionBudget;
use super::*;
use std::collections::BTreeSet;
use telltale_schema::clients::ClientId;
use telltale_schema::observation::*;

const RULES: &str = r#"
version: 1
description: synthetic modifier links
defaults:
  case_insensitive: false
  enabled: true
rules:
  - id: synthetic.alpha
    category: alpha
    severity: low
    score: 7
    targets: [command]
    regex: alpha
    tags: []
    explanation: alpha
  - id: synthetic.beta
    category: beta
    severity: low
    score: 5
    targets: [command]
    regex: beta
    tags: []
    explanation: beta
modifiers:
  - id: chain.ordered
    score: 11
    when_all_categories: [alpha, beta]
    link: {calls: 2}
    explanation: ordered
  - id: chain.unordered
    score: 13
    when_all_categories: [alpha, beta]
    link: {calls: 1, order: any}
    explanation: unordered
  - id: chain.timed
    score: 17
    when_all_categories: [alpha, beta]
    link: {calls: 2, minutes: 15}
    explanation: timed
  - id: chain.legacy
    score: 19
    when_all_categories: [alpha, beta]
    explanation: legacy
"#;

fn plan() -> RuleV1CompatibilityPlan {
    let export = telltale_rules::load_rule_set_from_documents(&[RULES], None)
        .unwrap()
        .compatibility_export();
    compile_rule_v1(&export).unwrap()
}

fn builder(
    body: ObservationBody,
    stage: ObservationStage,
    id: &str,
    time: Option<&str>,
) -> ObservationBuilder {
    let mut builder = CanonicalObservationV2::builder(
        body,
        stage,
        ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
        SourceProvenance::new(
            IngestionMode::SessionStore,
            "claude_code",
            "claude.projects",
            Fidelity::FullNative,
        )
        .unwrap()
        .with_native_id(id)
        .unwrap(),
    )
    .session_id(CorrelationId::source_reported("synthetic-session").unwrap())
    .capability_context(
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported),
    );
    if let Some(time) = time {
        builder = builder.occurred_at(SourceTimestamp::new(time).unwrap());
    }
    builder
}

/// A shell call; `call` sets a source call ID shared with its result.
fn call(id: &str, command: &str, time: Option<&str>, call: Option<&str>) -> CanonicalObservationV2 {
    let mut builder = builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("Bash")
                .unwrap()
                .with_arguments(
                    JsonValue::try_from_source_value(&serde_json::json!({"command": command}))
                        .unwrap(),
                ),
        ),
        ObservationStage::ToolRequested,
        id,
        time,
    )
    .fact_metadata(
        "tool.arguments",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    )
    .fact_metadata(
        "tool.name",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    )
    .facet(
        "command.text",
        SemanticFacet::new(JsonValue::string(command)),
    )
    .unwrap()
    .fact_metadata(
        "command.text",
        FactMetadata::new(FactProvenance::Parsed, Sensitivity::Normal).unwrap(),
    );
    if let Some(call) = call {
        builder = builder.correlation(
            CorrelationIds::new().with_call_id(CorrelationId::source_reported(call).unwrap()),
        );
    }
    builder.build().unwrap()
}

fn result(id: &str, call: Option<&str>) -> CanonicalObservationV2 {
    let mut builder = builder(
        ObservationBody::Tool(ToolObservation::new().with_result(JsonValue::string("ok"))),
        ObservationStage::ToolResultReturned,
        id,
        None,
    )
    .fact_metadata(
        "tool.result",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    );
    if let Some(call) = call {
        builder = builder.correlation(
            CorrelationIds::new().with_call_id(CorrelationId::source_reported(call).unwrap()),
        );
    }
    builder.build().unwrap()
}

fn message(id: &str) -> CanonicalObservationV2 {
    builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::Assistant)
                .with_content(JsonValue::string("Checking the next step.")),
        ),
        ObservationStage::MessageObserved,
        id,
        None,
    )
    .fact_metadata("message.role", FactMetadata::reported().unwrap())
    .fact_metadata("message.content", FactMetadata::reported().unwrap())
    .build()
    .unwrap()
}

/// Untimed shell calls, one per command.
fn calls(commands: &[&str]) -> Vec<CanonicalObservationV2> {
    commands
        .iter()
        .enumerate()
        .map(|(index, command)| call(&format!("call-{index}"), command, None, None))
        .collect()
}

fn session_chains(observations: &[CanonicalObservationV2]) -> BTreeSet<String> {
    let refs = observations.iter().collect::<Vec<_>>();
    evaluate_rule_v1_session_with_budget(&plan(), &refs, &mut RetentionBudget::new())
        .unwrap()
        .triggered_modifier_ids()
        .iter()
        .cloned()
        .collect()
}

/// Chain IDs per action finding, in observation order.
fn action_chains(observations: &[CanonicalObservationV2]) -> Vec<Vec<String>> {
    let instance = CorrelationId::source_reported("synthetic-source").unwrap();
    evaluate_source_with_options(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations,
        },
        &plan(),
        None,
        &DetailedEvaluationOptions::default(),
    )
    .unwrap()
    .sessions()[0]
        .action_findings()
        .iter()
        .map(|finding| {
            finding
                .rule_ids()
                .iter()
                .filter(|id| id.starts_with("chain."))
                .cloned()
                .collect()
        })
        .collect()
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}

#[test]
fn steps_link_within_the_declared_calls() {
    let all = [
        "chain.legacy",
        "chain.ordered",
        "chain.timed",
        "chain.unordered",
    ];
    assert_eq!(
        session_chains(&calls(&["echo alpha", "echo beta"])),
        set(&all)
    );
    assert_eq!(
        session_chains(&calls(&["echo alpha", "ls", "echo beta"])),
        set(&["chain.legacy", "chain.ordered", "chain.timed"])
    );
    assert_eq!(
        session_chains(&calls(&["echo alpha", "ls", "ls", "echo beta"])),
        set(&["chain.legacy"])
    );
    // One call links every step, in any order.
    assert_eq!(session_chains(&calls(&["echo beta alpha"])), set(&all));
}

#[test]
fn declared_order_rejects_reversed_steps() {
    assert_eq!(
        session_chains(&calls(&["echo beta", "echo alpha"])),
        set(&["chain.legacy", "chain.unordered"])
    );
}

#[test]
fn minutes_cap_applies_only_when_both_steps_have_times() {
    let apart = [
        call("alpha", "echo alpha", Some("2026-09-17T00:00:00Z"), None),
        call("beta", "echo beta", Some("2026-09-17T00:20:00Z"), None),
    ];
    assert_eq!(
        session_chains(&apart),
        set(&["chain.legacy", "chain.ordered", "chain.unordered"])
    );
    // Canonical session order puts untimed records last, so the later step is
    // the untimed one.
    let untimed = [
        call("alpha", "echo alpha", Some("2026-09-17T00:00:00Z"), None),
        call("beta", "echo beta", None, None),
    ];
    assert!(session_chains(&untimed).contains("chain.timed"));
}

#[test]
fn results_and_messages_add_no_distance() {
    let observations = [
        call("alpha", "echo alpha", None, Some("call-a")),
        message("thinking"),
        result("alpha-result", Some("call-a")),
        message("planning"),
        call("beta", "echo beta", None, Some("call-b")),
    ];
    let refs = observations.iter().collect::<Vec<_>>();
    assert_eq!(
        super::modifier_link::call_positions(&refs, &mut RetentionBudget::new()).unwrap(),
        [0, 1, 0, 1, 1]
    );
    assert!(session_chains(&observations).contains("chain.unordered"));
    // A result without a call ID joins the previous call.
    let observations = [
        call("alpha", "echo alpha", None, None),
        result("alpha-result", None),
        call("beta", "echo beta", None, None),
    ];
    let refs = observations.iter().collect::<Vec<_>>();
    assert_eq!(
        super::modifier_link::call_positions(&refs, &mut RetentionBudget::new()).unwrap(),
        [0, 0, 1]
    );
}

#[test]
fn action_findings_complete_a_link_once_per_start() {
    let findings = action_chains(&calls(&["echo alpha", "echo beta", "echo beta"]));
    assert_eq!(
        findings,
        [
            vec![],
            vec![
                "chain.ordered".to_owned(),
                "chain.timed".to_owned(),
                "chain.unordered".to_owned()
            ],
            vec![],
        ]
    );
    let repeated = action_chains(&calls(&[
        "echo alpha",
        "echo beta",
        "echo alpha",
        "echo beta",
    ]));
    assert_eq!(
        repeated
            .iter()
            .filter(|chains| chains.iter().any(|id| id == "chain.ordered"))
            .count(),
        2
    );
}

#[test]
fn modifiers_without_a_link_keep_their_semantics() {
    // Session scoring: co-occurrence anywhere in the session.
    assert!(
        session_chains(&calls(&["echo beta", "ls", "ls", "ls", "echo alpha"]))
            .contains("chain.legacy")
    );
    // Action findings: declared order within the 15-minute window, timed only.
    let timed = [
        call("alpha", "echo alpha", Some("2026-09-17T00:00:00Z"), None),
        call("beta", "echo beta", Some("2026-09-17T00:01:00Z"), None),
    ];
    assert!(
        action_chains(&timed)[1]
            .iter()
            .any(|id| id == "chain.legacy")
    );
    assert!(
        !action_chains(&calls(&["echo alpha", "echo beta"]))
            .concat()
            .iter()
            .any(|id| id == "chain.legacy")
    );
}
