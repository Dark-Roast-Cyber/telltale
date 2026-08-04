use std::fmt;
use std::sync::LazyLock;

use jsonschema::{Validator, validator_for};
use serde_json::Value;

const EVENT_1_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/historical/event-1.0.schema.json"
));
const EVENT_2_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/historical/event-2.0.schema.json"
));

static EVENT_1_VALIDATOR: LazyLock<Result<Validator, HistoricalEventValidationError>> =
    LazyLock::new(|| compile_validator(EVENT_1_SCHEMA));
static EVENT_2_VALIDATOR: LazyLock<Result<Validator, HistoricalEventValidationError>> =
    LazyLock::new(|| compile_validator(EVENT_2_SCHEMA));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalEventValidationError {
    MissingSchemaVersion,
    InvalidSchemaVersionType,
    UnknownRequestedSchemaVersion,
    UnknownActualSchemaVersion,
    SchemaVersionMismatch,
    SchemaUnavailable,
    SchemaViolation,
}

impl fmt::Display for HistoricalEventValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::MissingSchemaVersion => "missing_schema_version",
            Self::InvalidSchemaVersionType => "invalid_schema_version_type",
            Self::UnknownRequestedSchemaVersion => "unknown_requested_schema_version",
            Self::UnknownActualSchemaVersion => "unknown_actual_schema_version",
            Self::SchemaVersionMismatch => "schema_version_mismatch",
            Self::SchemaUnavailable => "historical_schema_unavailable",
            Self::SchemaViolation => "historical_schema_violation",
        };
        formatter.write_str(code)
    }
}

impl std::error::Error for HistoricalEventValidationError {}

pub fn validate_historical_event(
    value: Value,
    expected_schema_version: &str,
) -> Result<Value, HistoricalEventValidationError> {
    let validator = match expected_schema_version {
        "1.0" => EVENT_1_VALIDATOR
            .as_ref()
            .map_err(|_| HistoricalEventValidationError::SchemaUnavailable)?,
        "2.0" => EVENT_2_VALIDATOR
            .as_ref()
            .map_err(|_| HistoricalEventValidationError::SchemaUnavailable)?,
        _ => {
            return Err(HistoricalEventValidationError::UnknownRequestedSchemaVersion);
        }
    };

    let object = value
        .as_object()
        .ok_or(HistoricalEventValidationError::InvalidSchemaVersionType)?;
    let actual_schema_version = match object.get("schema_version") {
        None => return Err(HistoricalEventValidationError::MissingSchemaVersion),
        Some(Value::String(version)) => version,
        Some(_) => return Err(HistoricalEventValidationError::InvalidSchemaVersionType),
    };

    if !matches!(actual_schema_version.as_str(), "1.0" | "2.0") {
        return Err(HistoricalEventValidationError::UnknownActualSchemaVersion);
    }
    if actual_schema_version != expected_schema_version {
        return Err(HistoricalEventValidationError::SchemaVersionMismatch);
    }

    validator
        .validate(&value)
        .map_err(|_| HistoricalEventValidationError::SchemaViolation)?;

    Ok(value)
}

fn compile_validator(schema_text: &str) -> Result<Validator, HistoricalEventValidationError> {
    let schema: Value = serde_json::from_str(schema_text)
        .map_err(|_| HistoricalEventValidationError::SchemaUnavailable)?;
    validator_for(&schema).map_err(|_| HistoricalEventValidationError::SchemaUnavailable)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::{
        EVENT_1_SCHEMA, EVENT_2_SCHEMA, HistoricalEventValidationError, compile_validator,
        validate_historical_event,
    };

    const EVENT_1_DETECTION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/historical_events/event-1.0.json"
    ));
    const EVENT_1_HEALTH: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/historical_events/health-1.0.json"
    ));
    const EVENT_2_DETECTION: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/historical_events/event-2.0.json"
    ));
    const EVENT_2_HEALTH: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/historical_events/health-2.0.json"
    ));

    fn fixture(raw: &str) -> Value {
        serde_json::from_str(raw).expect("historical fixture JSON")
    }

    fn fixtures() -> [(&'static str, &'static str, Value); 4] {
        [
            ("1.0", "detection", fixture(EVENT_1_DETECTION)),
            ("1.0", "health", fixture(EVENT_1_HEALTH)),
            ("2.0", "detection", fixture(EVENT_2_DETECTION)),
            ("2.0", "health", fixture(EVENT_2_HEALTH)),
        ]
    }

    fn sha256_hex(value: &[u8]) -> String {
        format!("{:x}", Sha256::digest(value))
    }

    fn assert_no_canary(error: HistoricalEventValidationError, canary: &str) {
        assert!(!format!("{error}").contains(canary));
        assert!(!format!("{error:?}").contains(canary));
    }

    #[test]
    fn validates_all_historical_fixtures_and_preserves_exact_values() {
        for (version, _, original) in fixtures() {
            let validated = validate_historical_event(original.clone(), version)
                .expect("historical event should validate");
            assert_eq!(validated, original);
            assert_eq!(
                validated["unknown_extension"],
                json!({"nested": [true, null, 7]})
            );
        }
    }

    #[test]
    fn rejects_missing_unknown_and_mismatched_versions() {
        let mut missing = fixture(EVENT_1_DETECTION);
        missing
            .as_object_mut()
            .expect("object fixture")
            .remove("schema_version");
        assert_eq!(
            validate_historical_event(missing, "1.0"),
            Err(HistoricalEventValidationError::MissingSchemaVersion)
        );

        let actual_canary = "actual-version-secret-canary";
        let mut unknown = fixture(EVENT_1_DETECTION);
        unknown["schema_version"] = json!(actual_canary);
        let error = validate_historical_event(unknown, "1.0").expect_err("unknown actual version");
        assert_eq!(
            error,
            HistoricalEventValidationError::UnknownActualSchemaVersion
        );
        assert_no_canary(error, actual_canary);

        assert_eq!(
            validate_historical_event(fixture(EVENT_1_DETECTION), "2.0"),
            Err(HistoricalEventValidationError::SchemaVersionMismatch)
        );
        assert_eq!(
            validate_historical_event(fixture(EVENT_2_DETECTION), "1.0"),
            Err(HistoricalEventValidationError::SchemaVersionMismatch)
        );
    }

    #[test]
    fn rejects_unknown_requested_and_non_string_actual_versions() {
        let requested_canary = "requested-version-secret-canary";
        let error = validate_historical_event(fixture(EVENT_1_DETECTION), requested_canary)
            .expect_err("unknown requested version");
        assert_eq!(
            error,
            HistoricalEventValidationError::UnknownRequestedSchemaVersion
        );
        assert_no_canary(error, requested_canary);

        for actual in [Value::Null, json!(7), json!({"nested": "version"})] {
            let mut value = fixture(EVENT_1_DETECTION);
            value["schema_version"] = actual;
            assert_eq!(
                validate_historical_event(value, "1.0"),
                Err(HistoricalEventValidationError::InvalidSchemaVersionType)
            );
        }
    }

    #[test]
    fn schema_violation_errors_do_not_expose_input_values() {
        let canary = "credential-schema-violation-canary";
        let mut invalid = fixture(EVENT_2_DETECTION);
        invalid["event_type"] = json!(canary);
        invalid["unknown_extension"] = json!({"secret": canary});
        let error = validate_historical_event(invalid, "2.0").expect_err("invalid event type");
        assert_eq!(error, HistoricalEventValidationError::SchemaViolation);
        assert_no_canary(error, canary);
    }

    #[test]
    fn historical_schema_hashes_match_tagged_source_blobs() {
        assert_eq!(
            sha256_hex(EVENT_1_SCHEMA.as_bytes()),
            "396065acda07468b0d30cd0759fa55b60280b070aa24ccabe89bd6a868509f03"
        );
        assert_eq!(
            sha256_hex(EVENT_2_SCHEMA.as_bytes()),
            "4b41c09e2663ead7049ccdc90737f5536942da6b6247af74f43215f29cfa00a5"
        );
    }

    #[test]
    fn schema_compilation_failures_are_bounded() {
        assert!(matches!(
            compile_validator("{not-json"),
            Err(HistoricalEventValidationError::SchemaUnavailable)
        ));
    }
}
