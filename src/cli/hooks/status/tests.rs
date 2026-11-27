use std::collections::BTreeSet;

use serde_json::{Value, json};
use telltale_core::hooks::harness::Harness;
use telltale_schema::hooks_record::{HooksMode, HooksRecordError, HooksVerdict};

use super::*;

#[test]
fn hooks_status_schema_matches_the_producer_vocabularies() {
    use evaluator::Probe::*;
    let schema: Value = serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/telltale-hooks-status-v1.schema.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let defs = &schema["$defs"];
    let config = &defs["configuration"]["properties"];
    assert_eq!(schema["properties"]["schema"]["const"], SCHEMA_ID);
    assert_eq!(
        schema["properties"]["evaluator"]["enum"],
        json!([
            NotConfigured,
            NotRunning,
            Running,
            Unreachable,
            UnsupportedPlatform,
            ConfigInvalid
        ])
    );
    assert_eq!(
        defs["harness"]["properties"]["name"]["enum"],
        json!(
            Harness::ALL
                .iter()
                .map(|harness| harness.name())
                .collect::<Vec<_>>()
        )
    );
    assert_eq!(
        defs["location"]["enum"],
        json!([
            Location::User,
            Location::System,
            Location::Managed,
            Location::Project
        ])
    );
    assert_eq!(
        defs["harness"]["properties"]["settings"]["items"]["properties"]["state"]["enum"],
        json!([
            installation::State::Present,
            installation::State::Missing,
            installation::State::Altered,
            installation::State::Unavailable,
            installation::State::NotInspected
        ])
    );
    assert_eq!(
        defs["telemetry"]["properties"]["state"]["enum"],
        json!([
            telemetry::State::Active,
            telemetry::State::Missing,
            telemetry::State::Unavailable
        ])
    );
    assert_eq!(
        config["mode"]["enum"],
        json!([Mode::Enforce, Mode::Observe, null])
    );
    assert_eq!(
        config["mode"]["enum"],
        json!([HooksMode::Enforce, HooksMode::Observe, null])
    );
    assert_eq!(
        defs["failurePolicy"]["enum"],
        json!([OnError::Allow, OnError::Ask, OnError::Deny, null])
    );
    assert_eq!(
        defs["failurePolicy"]["enum"],
        json!([
            HooksVerdict::Allow,
            HooksVerdict::Ask,
            HooksVerdict::Deny,
            null
        ])
    );
    assert_eq!(
        config["reason_detail"]["enum"],
        json!([ReasonDetail::Full, ReasonDetail::Minimal, null])
    );
    assert_eq!(
        config["ask"]["enum"],
        json!([AskRoute::Human, AskRoute::Model, null])
    );
    use ConfigurationError::{
        PipelineBuildFailed, RuleContentUnreadable, SemanticProvenanceFailed, StateDirUnresolved,
    };
    assert_eq!(
        config["error_code"]["enum"],
        json!([
            ConfigurationError::ConfigInvalid,
            RuleContentUnreadable,
            PipelineBuildFailed,
            SemanticProvenanceFailed,
            StateDirUnresolved,
            null
        ])
    );
    let counts = &defs["telemetry"]["properties"];
    let keys = |value: &Value| {
        value["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        keys(&counts["error_counts"]),
        telemetry::error_codes().map(str::to_owned).collect()
    );
    assert_eq!(
        keys(&counts["rejected_counts"]),
        HooksRecordError::CODES
            .iter()
            .map(|code| (*code).to_owned())
            .collect()
    );
}
