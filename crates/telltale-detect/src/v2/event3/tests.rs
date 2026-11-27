use super::super::session::{
    CanonicalSourceInput, MAX_PROJECTION_ITEMS, RetentionBudget, evaluate_source,
};
use super::*;
use telltale_schema::observation::*;

#[test]
fn unsafe_short_session_terminal_expansion_is_preflight_charged() {
    use super::super::session::MAX_COMPATIBILITY_RETAINED_BYTES;
    let plan = super::super::compile_rule_v1(
            &telltale_rules::load_rule_set_from_documents(&["title: synthetic\nid: 3f36ebc7-8364-403d-8e23-78e6761a7e59\nname: synthetic.session\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: message\ndetection:\n    selection:\n        - message.user_text|re: 'needle'\n    condition: selection\nlevel: low\ntelltale:\n    category: synthetic\n    score: 1\n    explanation: 'synthetic'\n"], None).unwrap().compatibility_export()
        ).unwrap();
    let instance = CorrelationId::source_reported("synthetic-instance").unwrap();
    let evaluate = |session: &str| {
        let observation = CanonicalObservationV2::builder(
            ObservationBody::Message(
                MessageObservation::new(MessageRole::User)
                    .with_content(JsonValue::string("needle")),
            ),
            ObservationStage::MessageObserved,
            ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
            SourceProvenance::new(
                IngestionMode::SessionStore,
                "claude_code",
                "claude.projects",
                Fidelity::FullNative,
            )
            .unwrap()
            .with_native_id("synthetic-session-budget")
            .unwrap(),
        )
        .session_id(CorrelationId::source_reported(session).unwrap())
        .capability_context(
            CapabilityContext::new()
                .with_override(CapabilityId::UserContext, CapabilityAvailability::Supported),
        )
        .fact_metadata(
            "message.role",
            FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
        )
        .fact_metadata(
            "message.content",
            FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
        )
        .build()
        .unwrap();
        evaluate_source(
            CanonicalSourceInput {
                client: telltale_schema::clients::ClientId::Claude,
                source_id: "claude.projects",
                source_instance: Some(&instance),
                observations: &[observation],
            },
            &plan,
            None,
        )
        .unwrap()
    };
    let context = Event3CompatibilityContext {
        source_path_hash: &"a".repeat(64),
        sessions: &[],
    };
    let safe = evaluate("abc");
    let unsafe_session = evaluate("a b");
    let projected = project_event3(&unsafe_session, &context).unwrap();
    // Constructors retain source IDs; terminal serialization applies the
    // existing identity policy, which can expand a short unsafe ID.
    assert_eq!(projected.events[0].session_id, "a b");
    let terminal = telltale_schema::event::terminal_session_id("a b");
    assert!(terminal.len() > "a b".len());
    let record = telltale_schema::event::Event3Record::from_json(
        &serde_json::to_vec(&projected.events[0]).unwrap(),
    )
    .unwrap();
    assert_eq!(record.common().session_id, terminal);

    // Find the exact safe projection byte boundary without exposing budget
    // internals. The equally short unsafe source ID must not fit there.
    let fits = |evaluation: &CanonicalSourceEvaluation, capacity: usize| {
        let mut budget = RetentionBudget::new();
        budget
            .consume(0, MAX_COMPATIBILITY_RETAINED_BYTES - capacity)
            .unwrap();
        validate_projection_budget(evaluation, &context, &BTreeMap::new(), &mut budget)
    };
    let (mut low, mut high) = (0, MAX_COMPATIBILITY_RETAINED_BYTES);
    while low < high {
        let middle = low + (high - low) / 2;
        if fits(&safe, middle).is_ok() {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    assert!(fits(&safe, low).is_ok());
    assert_eq!(fits(&unsafe_session, low), Err(ProcessingError::Bounds));
}

#[test]
fn process_occurrence_projection_has_its_own_preflight_charge() {
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name("shell")
                .unwrap()
                .with_arguments(JsonValue::string("cmd.exe /c hostname")),
        ),
        ObservationStage::ToolRequested,
        ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
        SourceProvenance::new(
            IngestionMode::SessionStore,
            "claude_code",
            "claude.projects",
            Fidelity::FullNative,
        )
        .unwrap()
        .with_native_id("synthetic-budget")
        .unwrap(),
    )
    .session_id(CorrelationId::source_reported("synthetic").unwrap())
    .occurred_at(SourceTimestamp::new("2026-09-18T00:00:00Z").unwrap())
    .fact_metadata(
        "tool.name",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    )
    .fact_metadata(
        "tool.arguments",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    )
    .build()
    .unwrap();
    let instance = CorrelationId::source_reported("synthetic-instance").unwrap();
    let rules = telltale_rules::process_chain::load_default_process_chain_rules().unwrap();
    let plan = crate::v2::bundled_plan();
    let config = crate::process_chain::ProcessChainConfig::default();
    let evaluation = evaluate_source(
        CanonicalSourceInput {
            client: telltale_schema::clients::ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &[observation],
        },
        plan,
        Some((&rules, &config)),
    )
    .unwrap();
    let context = Event3CompatibilityContext {
        source_path_hash: &"a".repeat(64),
        sessions: &[],
    };
    let mut exact = RetentionBudget::new();
    validate_projection_budget(&evaluation, &context, &BTreeMap::new(), &mut exact).unwrap();
    assert!(
        !project_event3(&evaluation, &context)
            .unwrap()
            .occurrences
            .is_empty()
    );
    // The independently retained public occurrence (object and its three
    // vectors) must fit as well as the event/evidence material.
    let mut remaining = 0;
    while exact.consume(1, 0).is_ok() {
        remaining += 1;
    }
    let without_occurrence = MAX_PROJECTION_ITEMS - remaining - 4;
    let mut limited = RetentionBudget::new();
    limited
        .consume(MAX_PROJECTION_ITEMS - without_occurrence, 0)
        .unwrap();
    assert_eq!(
        validate_projection_budget(&evaluation, &context, &BTreeMap::new(), &mut limited),
        Err(ProcessingError::Bounds)
    );
}

#[test]
fn occurrence_index_requires_exact_nonconflicting_association() {
    let associations = vec![("z".into(), 0), ("a".into(), 1), ("z".into(), 0)];
    assert_eq!(proven_occurrence_index(&associations, "a"), Some(1));
    assert_eq!(proven_occurrence_index(&associations, "z"), Some(0));
    assert_eq!(proven_occurrence_index(&associations, "missing"), None);
    assert_eq!(
        proven_occurrence_index(&[("a".into(), 0), ("a".into(), 1)], "a"),
        None
    );
}
