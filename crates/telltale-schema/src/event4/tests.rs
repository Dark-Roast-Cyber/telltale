use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::*;

const OBS_A: &str =
    "obs:v2:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OBS_B: &str =
    "obs:v2:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OBSERVED: &str = "2026-09-16T12:00:00Z";
const MATERIALIZED: &str = "2026-09-16T12:00:01Z";

fn base(id: &str, event_type: EventType, action: EventAction, body: EventBody) -> Event4Candidate {
    Event4Candidate {
        schema_version: EVENT4_SCHEMA_VERSION.to_owned(),
        event_id: id.to_owned(),
        event_type,
        event_action: action,
        occurred_at: None,
        observed_at: OBSERVED.to_owned(),
        sequence: None,
        session_id: None,
        workflow_id: None,
        trace_id: None,
        span_id: None,
        body,
        extensions: None,
    }
}

fn session(id: &str) -> Event4Candidate {
    let mut candidate = base(
        id,
        EventType::Session,
        EventAction::SessionOpened,
        EventBody::Session(SessionBody {
            session_id: "session-1".to_owned(),
            lifecycle: SessionLifecycle::Opened,
            client_ref: None,
            runtime_ref: None,
            ruleset_ref: None,
            policy_ref: None,
            capability_ref: None,
            toolset_ref: None,
            mcp_ref: None,
        }),
    );
    candidate.session_id = Some("session-1".to_owned());
    candidate
}

fn observation(id: &str) -> Event4Candidate {
    base(
        id,
        EventType::Observation,
        EventAction::MessageObserved,
        EventBody::Observation(Box::new(ObservationBody {
            observation_id: OBS_A.to_owned(),
            kind: ObservationKind::Message,
            stage: ObservationStage::Observed,
            provenance: Some(FactProvenance::Parsed),
            fact_provenance: None,
            capabilities: None,
            capability: None,
            source: None,
            correlation: None,
            runtime_ref: None,
            capability_ref: None,
            toolset_ref: None,
            mcp_ref: None,
            tool: None,
        })),
    )
}

fn finding(id: &str) -> Event4Candidate {
    let mut candidate = base(
        id,
        EventType::Finding,
        EventAction::RuleMatched,
        EventBody::Finding(Box::new(FindingBody {
            kind: FindingKind::SecurityDetection,
            category: "example".to_owned(),
            severity: Severity::Low,
            risk_points: Some(10),
            confidence: Some(Confidence::High),
            confidence_score: Some(0.75),
            title: None,
            reason: None,
            rule_ids: Some(vec!["rule.example".to_owned()]),
            detector: Detector {
                kind: DetectorKind::Rule,
                id: "rule.example".to_owned(),
                engine: None,
                version: None,
                content_ref: None,
            },
            related_observation_ids: Some(vec![OBS_A.to_owned()]),
            runtime_ref: None,
            ruleset_ref: None,
            policy_ref: None,
            capability_ref: None,
            labels: None,
            techniques: None,
            evidence: Some(vec![Evidence {
                observation_id: Some(OBS_A.to_owned()),
                field: Some("message.content".to_owned()),
                representation: EvidenceRepresentation::Classification,
                value: Some(ExtensionScalar::String("suspicious".to_owned())),
            }]),
        })),
    );
    candidate.session_id = Some("session-1".to_owned());
    candidate
}

fn decision(id: &str) -> Event4Candidate {
    base(
        id,
        EventType::Decision,
        EventAction::PolicyEvaluated,
        EventBody::Decision(DecisionBody {
            requested: Outcome::Allow,
            effective: Outcome::Allow,
            status: DecisionStatus::Evaluated,
            reason_code: "policy.allowed".to_owned(),
            policy_ref: None,
            capability_ref: None,
            basis_event_ids: None,
            approval_id: None,
            approval_state: None,
            capability: None,
            degradation_reason: None,
        }),
    )
}

fn action(id: &str, decision_ref: &str) -> Event4Candidate {
    base(
        id,
        EventType::Action,
        EventAction::EnforcementApplied,
        EventBody::Action(ActionBody {
            action_id: format!("action-{id}"),
            decision_ref: decision_ref.to_owned(),
            requested: Outcome::Allow,
            effective: Outcome::Allow,
            status: ActionStatus::Succeeded,
            reason_code: None,
            enforcement_point: Some("test".to_owned()),
            approval_id: None,
            capability_ref: None,
            capability: None,
            degradation_reason: None,
        }),
    )
}

fn state(id: &str) -> Event4Candidate {
    base(
        id,
        EventType::State,
        EventAction::RuntimeChanged,
        EventBody::State(StateBody {
            kind: StateKind::Runtime,
            state_ref: "runtime-1".to_owned(),
            change: Some(StateChange::Changed),
        }),
    )
}

fn health(id: &str) -> Event4Candidate {
    base(
        id,
        EventType::Health,
        EventAction::HealthDegraded,
        EventBody::Health(HealthBody {
            component: "sensor".to_owned(),
            status: HealthStatus::Degraded,
            reason_code: Some("sensor.partial".to_owned()),
        }),
    )
}

fn summary(id: &str) -> Event4Candidate {
    base(
        id,
        EventType::Summary,
        EventAction::SummaryEmitted,
        EventBody::Summary(SummaryBody {
            kind: SummaryKind::AgentActivity,
            scope: SummaryScope::Session,
            count: 1,
        }),
    )
}

fn accept(candidate: Event4Candidate, context: &mut Event4InMemoryContext) -> AcceptedEvent4 {
    let materialized = candidate.materialize(MATERIALIZED);
    let accepted = validate_terminal(&materialized, context).expect("valid event");
    context.apply(accepted.effect()).expect("apply effect");
    accepted
}

fn approval_request(id: &str, approval_id: &str) -> Event4Candidate {
    let mut candidate = decision(id);
    candidate.event_action = EventAction::ApprovalRequested;
    if let EventBody::Decision(body) = &mut candidate.body {
        body.requested = Outcome::RequireApproval;
        body.effective = Outcome::RequireApproval;
        body.status = DecisionStatus::Pending;
        body.approval_id = Some(approval_id.to_owned());
        body.approval_state = Some(ApprovalState::Requested);
    }
    candidate
}

fn approval_resolution(id: &str, approval_id: &str, state: ApprovalState) -> Event4Candidate {
    let mut candidate = decision(id);
    candidate.event_action = EventAction::ApprovalResolved;
    if let EventBody::Decision(body) = &mut candidate.body {
        body.approval_id = Some(approval_id.to_owned());
        body.approval_state = Some(state);
    }
    candidate
}

fn one_extension(namespace: &str, property: &str, value: ExtensionValue) -> Extensions {
    let mut local = OpenMap::new();
    local.insert(property, value);
    let mut extensions = OpenMap::new();
    extensions.insert(namespace, local);
    extensions
}

fn scalar_boundary_extensions(extra: bool) -> Extensions {
    let mut extensions = OpenMap::new();
    for namespace_index in 0..16 {
        let mut namespace = OpenMap::new();
        for property_index in 0..16 {
            let count = if extra && namespace_index == 0 && property_index == 0 {
                3
            } else {
                2
            };
            namespace.insert(
                format!("p{property_index}"),
                ExtensionValue::Array(vec![ExtensionScalar::Bool(true); count]),
            );
        }
        extensions.insert(format!("vendor{namespace_index}.space"), namespace);
    }
    extensions
}

fn sized_extensions(target: usize) -> Extensions {
    let mut extensions = OpenMap::new();
    for namespace_index in 0..16 {
        let mut namespace = OpenMap::new();
        for property_index in 0..16 {
            namespace.insert(
                format!("p{property_index}"),
                ExtensionValue::Scalar(ExtensionScalar::String(String::new())),
            );
        }
        extensions.insert(format!("vendor{namespace_index}.space"), namespace);
    }
    let mut current = serde_json::to_vec(&extensions).unwrap().len();
    assert!(current <= target);
    for (_, namespace) in &mut extensions.0 {
        for (_, value) in &mut namespace.0 {
            let ExtensionValue::Scalar(ExtensionScalar::String(text)) = value else {
                unreachable!()
            };
            let add = (target - current).min(1024);
            text.push_str(&"x".repeat(add));
            current += add;
            if current == target {
                return extensions;
            }
        }
    }
    panic!("target exceeds extension fixture capacity");
}

fn sized_event(target: usize) -> MaterializedEvent4 {
    let mut candidate = finding("evt-size");
    if let EventBody::Finding(body) = &mut candidate.body {
        body.reason = Some(String::new());
    }
    let base = serde_json::to_vec(&candidate.clone().materialize(MATERIALIZED))
        .unwrap()
        .len();
    assert!(base <= target);
    if let EventBody::Finding(body) = &mut candidate.body {
        body.reason = Some("x".repeat(target - base));
    }
    let event = candidate.materialize(MATERIALIZED);
    assert_eq!(serde_json::to_vec(&event).unwrap().len(), target);
    event
}

fn summary_with_same_extensions(id: &str, bytes: &[u8]) -> Event4Candidate {
    let value: Value = serde_json::from_slice(bytes).unwrap();
    let mut extensions = OpenMap::new();
    for (namespace, properties) in value["extensions"].as_object().unwrap() {
        let mut local = OpenMap::new();
        for (property, value) in properties.as_object().unwrap() {
            let extension = if let Some(values) = value.as_array() {
                ExtensionValue::Array(
                    values
                        .iter()
                        .map(|value| ExtensionScalar::Number(value.as_f64().unwrap()))
                        .collect(),
                )
            } else {
                ExtensionValue::Scalar(ExtensionScalar::Bool(value.as_bool().unwrap()))
            };
            local.insert(property.clone(), extension);
        }
        extensions.insert(namespace.clone(), local);
    }
    let mut candidate = summary(id);
    candidate.extensions = Some(extensions);
    candidate
}

mod acceptance;
mod canonical_encoding;
mod event_semantics;
mod size_limits;
