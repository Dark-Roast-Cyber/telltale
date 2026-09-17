//! Experimental Tool-only Event4 privacy/materialization boundary. No production wiring.

use std::fmt;

use telltale_schema::event::{PrivacySanitizer, SanitizationContext};
use telltale_schema::event4::{
    AcceptedEvent4, EVENT4_SCHEMA_VERSION, Event4Candidate, Event4Context, Event4InMemoryContext,
    Event4ValidationError, EventAction, EventBody, EventType, Fidelity, MaterializedEvent4,
    ObservationBody, ObservationKind, ObservationStage, Source, SourceMode, validate_terminal,
};
use telltale_schema::observation::{
    CanonicalObservationV2, Fidelity as InputFidelity, IngestionMode, ObservationFamily,
    ObservationStage as InputStage, SourceProvenance,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// Bounded diagnostics only; no source text or underlying OS/clock diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event4EmitError {
    UnsupportedFamily,
    UnsupportedStage,
    RandomUnavailable,
    ClockUnavailable,
    IdentityCollision,
    Terminal(Event4ValidationError),
}

impl fmt::Display for Event4EmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFamily => formatter.write_str("event4 emit: unsupported_family"),
            Self::UnsupportedStage => formatter.write_str("event4 emit: unsupported_stage"),
            Self::RandomUnavailable => formatter.write_str("event4 emit: random_unavailable"),
            Self::ClockUnavailable => formatter.write_str("event4 emit: clock_unavailable"),
            Self::IdentityCollision => formatter.write_str("event4 emit: identity_collision"),
            Self::Terminal(error) => write!(formatter, "event4 emit: {error}"),
        }
    }
}

impl std::error::Error for Event4EmitError {}

/// Projects only the five Tool stages and accepts one new in-memory Event4 record.
///
/// This experimental boundary is not wired to the pipeline or any sink. It omits
/// payloads and local evidence. Unsupported inputs return no bytes or effects.
/// Each invocation creates a new random record ID and reads the clock once, after
/// privacy projection. Retry delivery by reusing the returned canonical bytes,
/// not by invoking this function again. Any ID collision fails without retry.
pub fn emit_tool_observation_event4(
    observation: &CanonicalObservationV2,
    context: &mut Event4InMemoryContext,
) -> Result<AcceptedEvent4, Event4EmitError> {
    let mut candidate = project(observation)?;
    let mut random = [0_u8; 16];
    candidate.event_id = event_id_from_random(getrandom::fill(&mut random).map(|()| random))?;
    let materialized_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| Event4EmitError::ClockUnavailable)?;
    terminalize(candidate.materialize(materialized_at), context)
}

fn event_id_from_random(
    random: Result<[u8; 16], getrandom::Error>,
) -> Result<String, Event4EmitError> {
    let random = random.map_err(|_| Event4EmitError::RandomUnavailable)?;
    let mut id = String::with_capacity(39);
    id.push_str("evt:v4:");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in random {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(id)
}

fn terminalize(
    event: MaterializedEvent4,
    context: &mut Event4InMemoryContext,
) -> Result<AcceptedEvent4, Event4EmitError> {
    // A fresh record cannot reuse even identical accepted bytes. Phase 1's
    // idempotent validation remains available for already materialized records.
    if context.event(event.event_id()).is_some() {
        return Err(Event4EmitError::IdentityCollision);
    }
    let accepted = validate_terminal(&event, context).map_err(Event4EmitError::Terminal)?;
    context
        .apply(accepted.effect())
        .map_err(Event4EmitError::Terminal)?;
    Ok(accepted)
}

fn project(observation: &CanonicalObservationV2) -> Result<Event4Candidate, Event4EmitError> {
    if observation.kind() != ObservationFamily::Tool {
        return Err(Event4EmitError::UnsupportedFamily);
    }
    let (event_action, stage) = map_stage(observation.stage())?;
    let source = project_source(observation.source());
    Ok(Event4Candidate {
        schema_version: EVENT4_SCHEMA_VERSION.to_owned(),
        event_id: String::new(),
        event_type: EventType::Observation,
        event_action,
        occurred_at: observation
            .occurred_at()
            .map(|time| time.as_str().to_owned()),
        observed_at: observation.observed_at().as_str().to_owned(),
        sequence: observation.sequence(),
        session_id: None,
        workflow_id: None,
        trace_id: None,
        span_id: None,
        body: EventBody::Observation(Box::new(ObservationBody {
            observation_id: observation.observation_id().to_owned(),
            kind: ObservationKind::Tool,
            stage,
            provenance: None,
            fact_provenance: None,
            capabilities: None,
            capability: None,
            source,
            correlation: None,
            runtime_ref: None,
            capability_ref: None,
            toolset_ref: None,
            mcp_ref: None,
            tool: None,
        })),
        extensions: None,
    })
}

fn map_stage(stage: InputStage) -> Result<(EventAction, ObservationStage), Event4EmitError> {
    Ok(match stage {
        InputStage::ToolProposed => (EventAction::ToolProposed, ObservationStage::Proposed),
        InputStage::ToolRequested => (EventAction::ToolRequested, ObservationStage::Requested),
        InputStage::ToolExecutionStarted => (
            EventAction::ToolExecutionStarted,
            ObservationStage::ExecutionStarted,
        ),
        InputStage::ToolExecutionCompleted => (
            EventAction::ToolExecutionCompleted,
            ObservationStage::ExecutionCompleted,
        ),
        InputStage::ToolResultReturned => (
            EventAction::ToolResultReturned,
            ObservationStage::ResultReturned,
        ),
        _ => return Err(Event4EmitError::UnsupportedStage),
    })
}

fn project_source(source: &SourceProvenance) -> Option<Source> {
    let fidelity = match source.fidelity() {
        InputFidelity::FullNative => Fidelity::Exact,
        InputFidelity::PartialStructured => Fidelity::Partial,
        InputFidelity::FlattenedLossy => Fidelity::Lossy,
        InputFidelity::DerivedOnly | InputFidelity::Unknown => return None,
    };
    Some(Source {
        mode: match source.ingestion_mode() {
            IngestionMode::SessionStore => SourceMode::SessionStore,
            IngestionMode::Harness => SourceMode::Harness,
            IngestionMode::Gateway => SourceMode::Gateway,
            IngestionMode::Browser => SourceMode::Browser,
            IngestionMode::OsContext => SourceMode::OsContext,
            IngestionMode::Import => SourceMode::Import,
            IngestionMode::Other => SourceMode::Other,
        },
        adapter_id: safe_adapter_metadata(source.adapter_id())?,
        adapter_version: source.adapter_version().and_then(safe_adapter_metadata),
        native_event_id: None,
        source_path_hash: None,
        offset: None,
        fidelity,
        capabilities: None,
        fact_provenance: None,
    })
}

fn safe_adapter_metadata(value: &str) -> Option<String> {
    // Do not turn redaction markers or truncated metadata into adapter identities.
    if value.is_empty() || value.len() > 128 {
        return None;
    }
    let safe = PrivacySanitizer::sanitize(SanitizationContext::Metadata, value);
    (safe == value
        && safe.as_bytes()[0].is_ascii_alphanumeric()
        && safe
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte)))
    .then_some(safe)
}

#[cfg(test)]
fn emit_fixed(
    observation: &CanonicalObservationV2,
    context: &mut Event4InMemoryContext,
    event_id: &str,
    materialized_at: &str,
) -> Result<AcceptedEvent4, Event4EmitError> {
    let mut candidate = project(observation)?;
    candidate.event_id = event_id.to_owned();
    terminalize(candidate.materialize(materialized_at), context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use telltale_schema::observation as obs;

    const ID: &str = "evt:v4:000102030405060708090a0b0c0d0e0f";
    const TIME: &str = "2026-01-02T03:04:06Z";

    fn source() -> obs::SourceProvenance {
        obs::SourceProvenance::new(
            obs::IngestionMode::Harness,
            "synthetic",
            "synthetic.adapter",
            obs::Fidelity::FullNative,
        )
        .unwrap()
        .with_native_id("native-synthetic")
        .unwrap()
    }

    fn tool(stage: obs::ObservationStage) -> obs::CanonicalObservationV2 {
        obs::CanonicalObservationV2::builder(
            obs::ObservationBody::Tool(
                obs::ToolObservation::new()
                    .with_name("synthetic-tool")
                    .unwrap()
                    .with_reported_status(obs::ToolStatus::Succeeded),
            ),
            stage,
            obs::ObservedAt::new("2026-01-02T03:04:05Z").unwrap(),
            source(),
        )
        .fact_metadata("tool.name", obs::FactMetadata::parsed().unwrap())
        .fact_metadata("tool.reported_status", obs::FactMetadata::parsed().unwrap())
        .build()
        .unwrap()
    }

    #[test]
    fn five_tool_stages_map_without_collapsing() {
        for (stage, action, wire_stage) in [
            (
                obs::ObservationStage::ToolProposed,
                "tool.proposed",
                "proposed",
            ),
            (
                obs::ObservationStage::ToolRequested,
                "tool.requested",
                "requested",
            ),
            (
                obs::ObservationStage::ToolExecutionStarted,
                "tool.execution_started",
                "execution_started",
            ),
            (
                obs::ObservationStage::ToolExecutionCompleted,
                "tool.execution_completed",
                "execution_completed",
            ),
            (
                obs::ObservationStage::ToolResultReturned,
                "tool.result_returned",
                "result_returned",
            ),
        ] {
            let accepted =
                emit_fixed(&tool(stage), &mut Event4InMemoryContext::new(), ID, TIME).unwrap();
            let value: serde_json::Value =
                serde_json::from_slice(accepted.canonical_bytes()).unwrap();
            assert_eq!(value["event_action"], action);
            assert_eq!(value["observation"]["stage"], wire_stage);
            assert_eq!(value["observation"]["kind"], "tool");
        }
    }

    #[test]
    fn unsupported_family_has_no_effect() {
        let observation = obs::CanonicalObservationV2::builder(
            obs::ObservationBody::Message(obs::MessageObservation::new(obs::MessageRole::User)),
            obs::ObservationStage::MessageObserved,
            obs::ObservedAt::new("2026-01-02T03:04:05Z").unwrap(),
            source(),
        )
        .fact_metadata("message.role", obs::FactMetadata::parsed().unwrap())
        .build()
        .unwrap();
        let mut context = Event4InMemoryContext::new();
        assert_eq!(
            emit_tool_observation_event4(&observation, &mut context).unwrap_err(),
            Event4EmitError::UnsupportedFamily
        );
        assert_eq!(
            format!("{context:?}"),
            "Event4InMemoryContext { event_count: 0, approval_count: 0 }"
        );
    }

    #[test]
    fn unsupported_stage_fallback() {
        assert_eq!(
            map_stage(obs::ObservationStage::InferenceStarted),
            Err(Event4EmitError::UnsupportedStage)
        );
    }

    fn candidate() -> Event4Candidate {
        let mut candidate = project(&tool(InputStage::ToolRequested)).unwrap();
        candidate.event_id = ID.to_owned();
        candidate
    }

    #[test]
    fn fixed_exact_bytes_and_sha256() {
        use sha2::{Digest, Sha256};
        let observation = tool(InputStage::ToolRequested);
        assert_eq!(
            observation.observation_id(),
            "obs:v2:sha256:cc0d38d2bdaec25c8972f5f67c133993e34dc5a26035c9cb855151afd99aaf6a"
        );
        let accepted =
            emit_fixed(&observation, &mut Event4InMemoryContext::new(), ID, TIME).unwrap();
        let expected = format!(
            r#"{{"schema_version":"4.0","event_id":"{ID}","type":"observation","event_action":"tool.requested","observed_at":"2026-01-02T03:04:05Z","materialized_at":"{TIME}","observation":{{"observation_id":"{}","kind":"tool","stage":"requested","source":{{"mode":"harness","adapter_id":"synthetic.adapter","fidelity":"exact"}}}}}}"#,
            observation.observation_id()
        );
        assert_eq!(accepted.canonical_bytes(), expected.as_bytes());
        assert_eq!(
            *accepted.content_hash(),
            <[u8; 32]>::from(Sha256::digest(expected.as_bytes()))
        );
        assert_eq!(accepted.serializer_id(), "event4-json-v1");
        assert_eq!(
            format!("{:x}", Sha256::digest(accepted.canonical_bytes())),
            "456dc2da6226477fd02ffbefae2c7b4edf71f7f444dee8d77a767ba0536ab5c0"
        );
    }

    #[test]
    fn preserve_times_and_sequence() {
        let observation = obs::CanonicalObservationV2::builder(
            obs::ObservationBody::Tool(obs::ToolObservation::new().with_name("synthetic").unwrap()),
            InputStage::ToolRequested,
            obs::ObservedAt::new("2026-01-02T03:04:05Z").unwrap(),
            source(),
        )
        .occurred_at(obs::SourceTimestamp::new("2026-01-02T03:00:00Z").unwrap())
        .sequence(u64::MAX)
        .fact_metadata("tool.name", obs::FactMetadata::parsed().unwrap())
        .build()
        .unwrap();
        let accepted =
            emit_fixed(&observation, &mut Event4InMemoryContext::new(), ID, TIME).unwrap();
        let value: serde_json::Value = serde_json::from_slice(accepted.canonical_bytes()).unwrap();
        assert_eq!(value["occurred_at"], "2026-01-02T03:00:00Z");
        assert_eq!(value["observed_at"], "2026-01-02T03:04:05Z");
        assert_eq!(value["materialized_at"], TIME);
        assert_eq!(value["sequence"], u64::MAX);
        assert_eq!(
            value["observation"]["observation_id"],
            observation.observation_id()
        );
    }

    #[test]
    fn absent_times_and_sequence_stay_absent() {
        let accepted = emit_fixed(
            &tool(InputStage::ToolRequested),
            &mut Event4InMemoryContext::new(),
            ID,
            TIME,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(accepted.canonical_bytes()).unwrap();
        assert!(value.get("occurred_at").is_none());
        assert!(value.get("sequence").is_none());
    }

    #[test]
    fn random_id_encodes_exactly_128_bits() {
        assert_eq!(
            event_id_from_random(Ok(std::array::from_fn(|i| i as u8))).unwrap(),
            ID
        );
        assert_eq!(
            event_id_from_random(Ok([255; 16])).unwrap(),
            "evt:v4:ffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn random_failure_is_bounded_and_closed() {
        assert_eq!(
            event_id_from_random(Err(getrandom::Error::UNSUPPORTED)),
            Err(Event4EmitError::RandomUnavailable)
        );
    }

    #[test]
    fn real_boundary_assigns_fresh_ids_and_clock_time() {
        let observation = tool(InputStage::ToolRequested);
        let mut context = Event4InMemoryContext::new();
        let before = OffsetDateTime::now_utc();
        let first = emit_tool_observation_event4(&observation, &mut context).unwrap();
        let second = emit_tool_observation_event4(&observation, &mut context).unwrap();
        let after = OffsetDateTime::now_utc();
        assert_ne!(first.event_id(), second.event_id());
        for accepted in [first, second] {
            assert_ne!(accepted.event_id(), observation.observation_id());
            assert_eq!(accepted.event_id().len(), 39);
            assert!(accepted.event_id().starts_with("evt:v4:"));
            assert!(
                accepted.event_id()[7..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            let value: serde_json::Value =
                serde_json::from_slice(accepted.canonical_bytes()).unwrap();
            let time = OffsetDateTime::parse(value["materialized_at"].as_str().unwrap(), &Rfc3339)
                .unwrap();
            assert!(time >= before && time <= after);
        }
    }

    #[test]
    fn returned_bytes_are_reused_and_phase1_revalidation_is_idempotent() {
        let mut context = Event4InMemoryContext::new();
        let accepted = terminalize(candidate().materialize(TIME), &mut context).unwrap();
        let retry_bytes = accepted.canonical_bytes().to_vec();
        context.apply(accepted.effect()).unwrap();
        let revalidated = validate_terminal(&candidate().materialize(TIME), &context).unwrap();
        assert_eq!(
            revalidated.disposition(),
            telltale_schema::event4::AcceptanceDisposition::Idempotent
        );
        assert_eq!(retry_bytes, revalidated.canonical_bytes());
        assert_eq!(accepted.content_hash(), revalidated.content_hash());
    }

    #[test]
    fn fresh_emission_collision_never_retries_even_identical_bytes() {
        let mut context = Event4InMemoryContext::new();
        let accepted = terminalize(candidate().materialize(TIME), &mut context).unwrap();
        let before = format!("{context:?}");
        for time in [TIME, "2026-01-02T03:04:07Z"] {
            assert_eq!(
                terminalize(candidate().materialize(time), &mut context).unwrap_err(),
                Event4EmitError::IdentityCollision
            );
        }
        assert_eq!(format!("{context:?}"), before);
        assert_eq!(
            context.event(ID).unwrap().content_hash(),
            accepted.content_hash()
        );
    }

    #[test]
    fn terminal_failure_does_not_mutate_existing_context() {
        let mut context = Event4InMemoryContext::new();
        terminalize(candidate().materialize(TIME), &mut context).unwrap();
        let before = format!("{context:?}");
        let mut invalid = candidate();
        invalid.event_id = "evt:v4:11111111111111111111111111111111".to_owned();
        let error =
            terminalize(invalid.materialize("2026-01-01T00:00:00Z"), &mut context).unwrap_err();
        assert!(
            matches!(error, Event4EmitError::Terminal(error) if error.code() == telltale_schema::event4::Event4ValidationCode::MaterializationBeforeObservation)
        );
        assert_eq!(format!("{context:?}"), before);
        assert!(
            context
                .event("evt:v4:11111111111111111111111111111111")
                .is_none()
        );
    }

    #[test]
    fn safe_adapter_identity_and_version_survive() {
        let source = source().with_adapter_version("1.2.3-test").unwrap();
        let projected = project_source(&source).unwrap();
        assert_eq!(projected.adapter_id, "synthetic.adapter");
        assert_eq!(projected.adapter_version.as_deref(), Some("1.2.3-test"));
        assert_eq!(projected.mode, SourceMode::Harness);
        assert_eq!(projected.fidelity, Fidelity::Exact);
        assert!(projected.native_event_id.is_none());
    }

    #[test]
    fn unsafe_adapter_identity_omits_source_and_unsafe_version_is_omitted() {
        for (case, input) in [
            "token=synthetic-secret",
            "/home/synthetic/private",
            "C:\\Users\\synthetic\\private",
            "../private",
            "~/private",
            "https://synthetic.invalid/path",
            "[redacted]",
            "two words",
            "ghp_0123456789abcdefghijklmnopqrstuv012345",
            "x\u{2003}y",
        ]
        .iter()
        .enumerate()
        {
            let source = obs::SourceProvenance::new(
                obs::IngestionMode::Harness,
                "synthetic",
                input,
                obs::Fidelity::FullNative,
            )
            .unwrap();
            assert!(project_source(&source).is_none(), "case {case}");
            let source = self::source().with_adapter_version(input).unwrap();
            assert!(
                project_source(&source).unwrap().adapter_version.is_none(),
                "case {case}"
            );
        }
        assert!(safe_adapter_metadata(&"a".repeat(129)).is_none());
    }

    #[test]
    fn fidelity_mapping_does_not_invent_unknown_or_derived_fidelity() {
        for (input, expected) in [
            (InputFidelity::FullNative, Some(Fidelity::Exact)),
            (InputFidelity::PartialStructured, Some(Fidelity::Partial)),
            (InputFidelity::FlattenedLossy, Some(Fidelity::Lossy)),
            (InputFidelity::DerivedOnly, None),
            (InputFidelity::Unknown, None),
        ] {
            let source = obs::SourceProvenance::new(
                obs::IngestionMode::Harness,
                "synthetic",
                "synthetic.adapter",
                input,
            )
            .unwrap();
            assert_eq!(
                project_source(&source).map(|source| source.fidelity),
                expected
            );
        }
    }

    #[test]
    fn ingestion_modes_are_preserved() {
        for (input, expected) in [
            (IngestionMode::SessionStore, SourceMode::SessionStore),
            (IngestionMode::Harness, SourceMode::Harness),
            (IngestionMode::Gateway, SourceMode::Gateway),
            (IngestionMode::Browser, SourceMode::Browser),
            (IngestionMode::OsContext, SourceMode::OsContext),
            (IngestionMode::Import, SourceMode::Import),
            (IngestionMode::Other, SourceMode::Other),
        ] {
            let source = SourceProvenance::new(
                input,
                "synthetic",
                "synthetic.adapter",
                InputFidelity::FullNative,
            )
            .unwrap();
            assert_eq!(project_source(&source).unwrap().mode, expected);
        }
    }

    #[test]
    fn payloads_native_coordinates_and_local_references_never_leave_projection() {
        let marker = "SYNTHETIC_PRIVATE_MARKER";
        let source = source()
            .with_offset(marker)
            .unwrap()
            .with_source_path_hash(marker)
            .unwrap()
            .with_normalization_ref(obs::LocalReference::new(marker, "local").unwrap())
            .with_producer_identity_key_ref(
                obs::LocalReference::new(marker, "identity_key").unwrap(),
            )
            .unwrap();
        let mut builder = obs::CanonicalObservationV2::builder(
            obs::ObservationBody::Tool(
                obs::ToolObservation::new()
                    .with_name(marker)
                    .unwrap()
                    .with_arguments(obs::JsonValue::string(format!(
                        "token={marker} /home/synthetic/private"
                    )))
                    .with_result(obs::JsonValue::string(marker))
                    .with_searchable_arguments(marker)
                    .unwrap()
                    .with_searchable_result(marker)
                    .unwrap(),
            ),
            InputStage::ToolRequested,
            obs::ObservedAt::new("2026-01-02T03:04:05Z").unwrap(),
            source,
        )
        .local(
            obs::LocalEvidence::new()
                .insert(
                    "tool.raw_result",
                    obs::LocalValue::new(
                        obs::JsonValue::string(marker),
                        Some(marker),
                        obs::FactProvenance::Parsed,
                        obs::Sensitivity::Normal,
                    )
                    .unwrap(),
                )
                .unwrap()
                .with_raw_ref(obs::LocalReference::new(marker, "local").unwrap()),
        )
        .session_id(obs::CorrelationId::source_reported(marker).unwrap())
        .workflow_id(obs::CorrelationId::source_reported(marker).unwrap())
        .correlation(
            obs::CorrelationIds::new()
                .with_call_id(obs::CorrelationId::source_reported(marker).unwrap()),
        )
        .facet(
            "tool.synthetic",
            obs::SemanticFacet::new(obs::JsonValue::string(marker)),
        )
        .unwrap();
        for path in [
            "tool.name",
            "tool.arguments",
            "tool.result",
            "tool.searchable_arguments",
            "tool.searchable_result",
            "tool.synthetic",
        ] {
            builder = builder.fact_metadata(path, obs::FactMetadata::parsed().unwrap());
        }
        let observation = builder.build().unwrap();
        let accepted =
            emit_fixed(&observation, &mut Event4InMemoryContext::new(), ID, TIME).unwrap();
        let text = std::str::from_utf8(accepted.canonical_bytes()).unwrap();
        for forbidden in [
            marker,
            "native-synthetic",
            "token=",
            "/home/",
            "local",
            "normalization",
            "key_ref",
            "arguments",
            "result",
            "correlation",
            "facet",
            "session_id",
            "workflow_id",
            "offset",
            "path_hash",
            "extensions",
        ] {
            assert!(!text.contains(forbidden), "omission invariant failed");
        }
    }

    #[test]
    fn phase1_limits_and_encoding_fail_without_effects() {
        use telltale_schema::event4::{
            Event4ValidationCode, ExtensionScalar, ExtensionValue, OpenMap,
        };
        let mut oversized = candidate();
        if let EventBody::Observation(body) = &mut oversized.body {
            let mut provenance = OpenMap::new();
            provenance.insert(
                "x".repeat(70_000),
                telltale_schema::event4::FactProvenance::Parsed,
            );
            body.fact_provenance = Some(provenance);
        }
        let mut duplicate = candidate();
        let mut entries = OpenMap::new();
        entries.insert("é", ExtensionValue::Scalar(ExtensionScalar::Bool(true)));
        entries.insert(
            "e\u{301}",
            ExtensionValue::Scalar(ExtensionScalar::Bool(false)),
        );
        let mut extensions = OpenMap::new();
        extensions.insert("synthetic", entries);
        duplicate.extensions = Some(extensions);
        for (candidate, code) in [
            (oversized, Event4ValidationCode::EventTooLarge),
            (duplicate, Event4ValidationCode::DuplicateNormalizedKey),
        ] {
            let mut context = Event4InMemoryContext::new();
            let error = terminalize(candidate.materialize(TIME), &mut context).unwrap_err();
            assert!(
                matches!(error, Event4EmitError::Terminal(error) if error.code() == code),
                "{error}"
            );
            assert!(context.event(ID).is_none());
        }
    }

    #[test]
    fn error_display_and_debug_are_code_owned_only() {
        let mut invalid = candidate();
        invalid.observed_at = "SYNTHETIC_PRIVATE_MARKER /home/synthetic/private".to_owned();
        let terminal =
            terminalize(invalid.materialize(TIME), &mut Event4InMemoryContext::new()).unwrap_err();
        for error in [
            Event4EmitError::UnsupportedFamily,
            Event4EmitError::UnsupportedStage,
            Event4EmitError::RandomUnavailable,
            Event4EmitError::ClockUnavailable,
            Event4EmitError::IdentityCollision,
            terminal,
        ] {
            let text = format!("{error} {error:?}");
            assert!(text.len() < 256);
            assert!(!text.contains("SYNTHETIC_PRIVATE_MARKER"));
            assert!(!text.contains("/home/"));
        }
    }
}
