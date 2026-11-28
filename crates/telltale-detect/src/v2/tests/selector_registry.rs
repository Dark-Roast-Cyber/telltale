use super::*;

#[test]
fn standalone_selector_reports_oversized_fingerprint_epoch_without_panicking() {
    use telltale_schema::observation::{KeyedFingerprint, LocalReference, Sensitivity};
    let epoch = "e".repeat(super::super::session::MAX_EVALUATION_BYTE_VISITS + 1);
    let fingerprint = KeyedFingerprint::from_digest(
        "message.content",
        &epoch,
        format!("hmac-sha256:v1:{}", "a".repeat(64)),
    )
    .unwrap();
    drop(epoch);
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Message(
            MessageObservation::new(MessageRole::User).with_content(JsonValue::string("synthetic")),
        ),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source("large-epoch")
            .with_producer_identity_key_ref(
                LocalReference::new("producerkey:v2:synthetic", "identity_key").unwrap(),
            )
            .unwrap(),
    )
    .fact_metadata("message.role", FactMetadata::reported().unwrap())
    .fact_metadata(
        "message.content",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Secret)
            .unwrap()
            .with_keyed_fingerprint(fingerprint)
            .unwrap(),
    )
    .build()
    .unwrap();
    assert!(observation.retained_byte_len() < 100);
    let result = std::panic::catch_unwind(|| {
        SelectorRegistry::new().resolve(SelectorId::GovernedFacet("message.text"), &observation)
    });
    assert!(result.is_ok(), "work exhaustion must not panic");
    assert!(matches!(result.unwrap(), Err(ProcessingError::Bounds)));
}

#[test]
fn long_message_ordered_text_view_excludes_structured_parts() {
    use telltale_schema::observation::{ContentPart, ContentPartKind, Sensitivity};
    let body = MessageObservation::new(MessageRole::User)
        .with_content_part(ContentPart::new(
            ContentPartKind::Text,
            JsonValue::string("first"),
        ))
        .with_content_part(ContentPart::new(
            ContentPartKind::ToolResult,
            JsonValue::string("excluded"),
        ))
        .with_content_part(ContentPart::new(
            ContentPartKind::Text,
            JsonValue::Array(vec![JsonValue::string("excluded")]),
        ))
        .with_content_part(ContentPart::new(
            ContentPartKind::Text,
            JsonValue::string("second"),
        ));
    let observation = CanonicalObservationV2::builder(
        ObservationBody::Message(body),
        ObservationStage::MessageObserved,
        ObservedAt::new(OBSERVED_AT).unwrap(),
        source("parts"),
    )
    .capability_context(capabilities(CapabilityAvailability::Supported))
    .fact_metadata("message.role", FactMetadata::reported().unwrap())
    .fact_metadata(
        "message.content_parts",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Sensitive).unwrap(),
    )
    .build()
    .unwrap();
    for selector in [
        SelectorId::parse("message.text").unwrap(),
        SelectorId::CompatUserContext,
    ] {
        let resolved = SelectorRegistry::new()
            .resolve(selector, &observation)
            .unwrap();
        assert_eq!(resolved.value(), Some(&JsonValue::string("first\nsecond")));
        assert_eq!(
            resolved.metadata().unwrap().provenance(),
            FactProvenance::Derived
        );
        assert_eq!(
            resolved.metadata().unwrap().sensitivity(),
            Sensitivity::Sensitive
        );
    }
}

#[test]
fn long_message_scalar_precedence_roles_anchors_and_empty_operations() {
    use telltale_schema::observation::{ContentPart, ContentPartKind};
    for role in [
        MessageRole::User,
        MessageRole::Assistant,
        MessageRole::System,
        MessageRole::Developer,
    ] {
        let make = |scalar| {
            let mut body = MessageObservation::new(role)
                .with_content_part(ContentPart::new(
                    ContentPartKind::Text,
                    JsonValue::string("first"),
                ))
                .with_content_part(ContentPart::new(
                    ContentPartKind::Text,
                    JsonValue::string("second"),
                ));
            if scalar {
                body = body.with_content(JsonValue::string(""));
            }
            let mut builder = CanonicalObservationV2::builder(
                ObservationBody::Message(body),
                ObservationStage::MessageObserved,
                ObservedAt::new(OBSERVED_AT).unwrap(),
                source("parts-role"),
            )
            .capability_context(capabilities(CapabilityAvailability::Supported))
            .fact_metadata("message.role", FactMetadata::reported().unwrap())
            .fact_metadata("message.content_parts", FactMetadata::reported().unwrap());
            if scalar {
                builder =
                    builder.fact_metadata("message.content", FactMetadata::reported().unwrap());
            }
            builder.build().unwrap()
        };
        let observation = make(false);
        let matcher = MatcherSpec::predicate(
            "message.text",
            MatcherOperator::Regex,
            Some(JsonValue::string("\\Afirst\\nsecond\\z")),
        )
        .compile()
        .unwrap();
        assert_eq!(
            matcher.evaluate(&observation).unwrap().state(),
            &MatchState::Match
        );
        assert_eq!(
            matcher.evaluate(&make(true)).unwrap().state(),
            &MatchState::NoMatch
        );
        for (selector, expected) in [
            (SelectorId::CompatUserContext, role == MessageRole::User),
            (
                SelectorId::CompatAssistantContext,
                role == MessageRole::Assistant,
            ),
        ] {
            assert_eq!(
                SelectorRegistry::new()
                    .resolve(selector, &observation)
                    .unwrap()
                    .is_present(),
                expected
            );
        }
        let mut budget = RetentionBudget::new();
        budget
            .charge(super::super::session::MAX_EVALUATION_BYTE_VISITS)
            .unwrap();
        assert!(matches!(
            SelectorRegistry::new().try_resolve(
                SelectorId::GovernedFacet("message.text"),
                &make(true),
                &mut budget
            ),
            Err(ProcessingError::Bounds)
        ));
    }
}

#[test]
fn all_compatibility_names_are_registered() {
    for target in [
        "arguments",
        "assistant_context",
        "command",
        "file_path",
        "tool_kind",
        "tool_name",
        "tool_result",
        "url",
        "user_context",
        "written_path",
    ] {
        let selector = SelectorId::parse(&format!("compat.v1.{target}"));
        assert!(selector.is_ok(), "compat target {target} must compile");
    }
}

#[test]
fn selector_registry_has_only_contract_backed_names() {
    assert_eq!(SelectorId::all().len(), 58);
    let counts = SelectorId::all()
        .iter()
        .map(|name| name.split('.').next().expect("selector group"))
        .fold(BTreeMap::<&str, usize>::new(), |mut counts, group| {
            *counts.entry(group).or_default() += 1;
            counts
        });
    assert_eq!(
        counts,
        BTreeMap::from([
            ("browser", 3),
            ("command", 1),
            ("compat", 10),
            ("inference", 5),
            ("mcp", 4),
            ("message", 3),
            ("network", 5),
            ("process", 4),
            ("resource", 3),
            ("runtime", 4),
            ("session", 1),
            ("tool", 15),
        ])
    );

    let backing_counts = SelectorId::all()
        .iter()
        .map(|name| {
            SelectorId::parse(name)
                .expect("registered selector")
                .backing()
        })
        .fold(
            BTreeMap::<SelectorBacking, usize>::new(),
            |mut counts, backing| {
                *counts.entry(backing).or_default() += 1;
                counts
            },
        );
    assert_eq!(
        backing_counts,
        BTreeMap::from([
            (SelectorBacking::Compatibility, 10),
            (SelectorBacking::Derived, 7),
            (SelectorBacking::Direct, 2),
            (SelectorBacking::GovernedFacet, 2),
            (SelectorBacking::Typed, 37),
        ])
    );
}

#[test]
fn every_governed_facet_the_resolver_handles_is_a_registered_governed_selector() {
    let unregistered: Vec<&str> = super::super::selector::governed::ALL
        .iter()
        .copied()
        .filter(|name| SelectorId::parse(name).ok() != Some(SelectorId::GovernedFacet(name)))
        .collect();
    assert_eq!(unregistered, Vec::<&str>::new());
}

#[test]
fn every_registered_governed_selector_is_named_for_the_resolver() {
    let unhandled: Vec<&str> = SelectorId::all()
        .iter()
        .copied()
        .filter(|name| matches!(SelectorId::parse(name), Ok(SelectorId::GovernedFacet(_))))
        .filter(|name| !super::super::selector::governed::ALL.contains(name))
        .collect();
    assert_eq!(unhandled, Vec::<&str>::new());
}

#[test]
fn selector_tool_text_and_compatibility_fallbacks_are_equivalent() {
    let registry = SelectorRegistry::new();
    for availability in [
        CapabilityAvailability::Supported,
        CapabilityAvailability::Unsupported,
        CapabilityAvailability::Unknown,
    ] {
        for (value, searchable, expected) in [
            (None, None, None),
            (Some(JsonValue::string("raw")), None, Some("raw")),
            (Some(JsonValue::Object(BTreeMap::new())), None, None),
            (
                Some(JsonValue::string("raw")),
                Some("search"),
                Some("search"),
            ),
            (
                Some(JsonValue::Object(BTreeMap::new())),
                Some("search"),
                Some("search"),
            ),
        ] {
            let mut body = ToolObservation::new().with_name("synthetic").expect("name");
            if let Some(value) = &value {
                body = body
                    .with_arguments(value.clone())
                    .with_result(value.clone());
            }
            if let Some(searchable) = searchable {
                body = body
                    .with_searchable_arguments(searchable)
                    .expect("arguments")
                    .with_searchable_result(searchable)
                    .expect("result");
            }
            let mut builder = CanonicalObservationV2::builder(
                ObservationBody::Tool(body),
                ObservationStage::ToolRequested,
                ObservedAt::new(OBSERVED_AT).expect("observed at"),
                source("selector-fallback"),
            )
            .capability_context(capabilities(availability))
            .fact_metadata("tool.name", FactMetadata::reported().expect("metadata"));
            if value.is_some() {
                for path in ["tool.arguments", "tool.result"] {
                    builder =
                        builder.fact_metadata(path, FactMetadata::reported().expect("metadata"));
                }
            }
            if searchable.is_some() {
                for path in ["tool.searchable_arguments", "tool.searchable_result"] {
                    builder = builder.fact_metadata(
                        path,
                        FactMetadata::new(
                            FactProvenance::Inferred,
                            telltale_schema::observation::Sensitivity::Normal,
                        )
                        .expect("metadata"),
                    );
                }
            }
            let observation = builder.build().expect("tool observation");
            for (native, compat) in [
                ("tool.arguments.text", SelectorId::CompatArguments),
                ("tool.result.text", SelectorId::CompatToolResult),
            ] {
                let native = SelectorId::parse(native).expect("selector");
                let native_resolution = registry.resolve(native, &observation).unwrap();
                let compat_resolution = registry.resolve(compat, &observation).unwrap();
                assert_eq!(native_resolution.selector(), native);
                assert_eq!(compat_resolution.selector(), compat);
                assert_eq!(
                    native_resolution.required_capability(),
                    Some(CapabilityId::ToolCall)
                );
                assert_eq!(
                    compat_resolution.required_capability(),
                    native_resolution.required_capability()
                );
                assert_eq!(compat_resolution.presence(), native_resolution.presence());
                assert_eq!(
                    compat_resolution.value(),
                    expected.map(JsonValue::string).as_ref()
                );
                assert_eq!(compat_resolution.value(), native_resolution.value());
                assert_eq!(compat_resolution.metadata(), native_resolution.metadata());
                assert_eq!(
                    compat_resolution.presence(),
                    if expected.is_some() {
                        SelectorPresence::Present
                    } else {
                        SelectorPresence::Absent
                    }
                );
                if expected.is_some() {
                    assert_eq!(
                        compat_resolution.metadata().expect("metadata").provenance(),
                        if searchable.is_some() {
                            FactProvenance::Inferred
                        } else {
                            FactProvenance::Reported
                        }
                    );
                }
            }
        }
    }
    let observation = message(MessageRole::Assistant, "synthetic", "non-tool");
    for name in [
        "tool.arguments.text",
        "tool.result.text",
        "compat.v1.arguments",
        "compat.v1.tool_result",
    ] {
        let selector = SelectorId::parse(name).expect("selector");
        let resolution = registry.resolve(selector, &observation).unwrap();
        assert_eq!(resolution.selector(), selector);
        assert_eq!(resolution.presence(), SelectorPresence::Absent);
        assert_eq!(resolution.value(), None);
        assert_eq!(resolution.metadata(), None);
    }
}

#[test]
fn generic_namespace_facets_do_not_extend_typed_selector_backing() {
    let observation = add_facet(
        tool("synthetic", "facet-governance"),
        "network.domain",
        "example.invalid",
        FactProvenance::Parsed,
    );
    let resolution = SelectorRegistry::new()
        .resolve(
            SelectorId::parse("network.domain").expect("typed selector"),
            &observation,
        )
        .unwrap();
    assert_eq!(resolution.presence(), SelectorPresence::Absent);
}
