//! Test-only reflection of the derived wire serializer, including skipped fields.

use std::collections::BTreeSet;

use serde::Serialize;
use serde::ser::{Impossible, SerializeStruct, Serializer};
use serde_json::Value;

use super::{EVENT3_SCHEMA, KNOWN_FIELDS};
use crate::event::{EventWire, HealthEventInput, health_event_with_metadata};

#[derive(Default)]
struct WireFields {
    all: Vec<&'static str>,
    emitted: Vec<&'static str>,
}

impl SerializeStruct for WireFields {
    type Ok = Self;
    type Error = serde_json::Error;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        _value: &T,
    ) -> Result<(), Self::Error> {
        self.all.push(key);
        self.emitted.push(key);
        Ok(())
    }

    fn skip_field(&mut self, key: &'static str) -> Result<(), Self::Error> {
        self.all.push(key);
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(self)
    }
}

// Only the top-level struct is visited; values (including nested structs) are
// deliberately not serialized by the collector.
macro_rules! reject_non_struct {
    ($($method:ident $(<$t:ident: ?Sized + Serialize>)? ($($arg:ident: $ty:ty),*) -> $ok:ty;)*) => {
        $(fn $method $(<$t: ?Sized + Serialize>)? (self, $($arg: $ty),*) -> Result<$ok, Self::Error> {
            $(let _ = $arg;)*
            panic!("EventWire must serialize as a struct")
        })*
    };
}

impl Serializer for WireFields {
    type Ok = Self;
    type Error = serde_json::Error;
    type SerializeSeq = Impossible<Self, Self::Error>;
    type SerializeTuple = Impossible<Self, Self::Error>;
    type SerializeTupleStruct = Impossible<Self, Self::Error>;
    type SerializeTupleVariant = Impossible<Self, Self::Error>;
    type SerializeMap = Impossible<Self, Self::Error>;
    type SerializeStruct = Self;
    type SerializeStructVariant = Impossible<Self, Self::Error>;

    fn serialize_struct(self, name: &'static str, _len: usize) -> Result<Self, Self::Error> {
        assert_eq!(name, "EventWire");
        Ok(self)
    }

    reject_non_struct! {
        serialize_bool(v: bool) -> Self;
        serialize_i8(v: i8) -> Self;
        serialize_i16(v: i16) -> Self;
        serialize_i32(v: i32) -> Self;
        serialize_i64(v: i64) -> Self;
        serialize_u8(v: u8) -> Self;
        serialize_u16(v: u16) -> Self;
        serialize_u32(v: u32) -> Self;
        serialize_u64(v: u64) -> Self;
        serialize_f32(v: f32) -> Self;
        serialize_f64(v: f64) -> Self;
        serialize_char(v: char) -> Self;
        serialize_str(v: &str) -> Self;
        serialize_bytes(v: &[u8]) -> Self;
        serialize_none() -> Self;
        serialize_some<T: ?Sized + Serialize>(v: &T) -> Self;
        serialize_unit() -> Self;
        serialize_unit_struct(name: &'static str) -> Self;
        serialize_unit_variant(name: &'static str, index: u32, variant: &'static str) -> Self;
        serialize_newtype_struct<T: ?Sized + Serialize>(name: &'static str, v: &T) -> Self;
        serialize_newtype_variant<T: ?Sized + Serialize>(name: &'static str, index: u32, variant: &'static str, v: &T) -> Self;
        serialize_seq(len: Option<usize>) -> Self::SerializeSeq;
        serialize_tuple(len: usize) -> Self::SerializeTuple;
        serialize_tuple_struct(name: &'static str, len: usize) -> Self::SerializeTupleStruct;
        serialize_tuple_variant(name: &'static str, index: u32, variant: &'static str, len: usize) -> Self::SerializeTupleVariant;
        serialize_map(len: Option<usize>) -> Self::SerializeMap;
        serialize_struct_variant(name: &'static str, index: u32, variant: &'static str, len: usize) -> Self::SerializeStructVariant;
    }
}

fn schema_fields<'a>(root: &'a Value, node: &'a Value, fields: &mut BTreeSet<&'a str>) {
    if let Some(reference) = node.get("$ref") {
        let pointer = reference.as_str().unwrap().strip_prefix('#').unwrap();
        schema_fields(
            root,
            root.pointer(pointer).expect("local schema reference"),
            fields,
        );
    }
    if let Some(properties) = node.get("properties") {
        fields.extend(properties.as_object().unwrap().keys().map(String::as_str));
    }
    // These edges describe the same object. Never descend into properties,
    // items, or all $defs: those also contain unrelated nested field names.
    for keyword in ["allOf", "oneOf", "anyOf"] {
        if let Some(branches) = node.get(keyword) {
            for branch in branches.as_array().unwrap() {
                schema_fields(root, branch, fields);
            }
        }
    }
}

fn assert_inventory(label: &str, actual: &[&str], expected: &BTreeSet<&str>) {
    let actual_set: BTreeSet<_> = actual.iter().copied().collect();
    assert_eq!(actual.len(), actual_set.len(), "{label}: duplicate field");
    assert_eq!(&actual_set, expected, "{label}: field inventory drift");
}

fn health_event() -> crate::event::Event {
    health_event_with_metadata(HealthEventInput {
        sources: &[],
        source_inventory_change: None,
        scan_duration_ms: 0,
        rule_count: 0,
        threshold_config: crate::scoring::RiskThresholds {
            low: 20,
            medium: 50,
            high: 70,
            critical: 90,
        },
        active_policy_name: None,
        emitted_count: 0,
        suppressed_count: 0,
        scanner_error_count: 0,
    })
}

#[test]
fn event3_field_inventory_matches_strict_schema() {
    let schema: Value = serde_json::from_str(EVENT3_SCHEMA).unwrap();
    assert_eq!(schema["unevaluatedProperties"], false);
    let mut expected = BTreeSet::new();
    schema_fields(&schema, &schema, &mut expected);
    assert_eq!(expected.len(), 49, "frozen Event3 field count");
    assert!(!expected.contains("workspace"));
    assert!(!expected.contains("redacted_value"));

    let event = health_event();
    let wire = EventWire::new(&event)
        .serialize(WireFields::default())
        .unwrap();
    assert!(
        wire.all.len() > wire.emitted.len(),
        "fixture must exercise skip_field"
    );
    assert_inventory("EventWire", &wire.all, &expected);
    assert_inventory("consumer KNOWN_FIELDS", KNOWN_FIELDS, &expected);

    for (label, fields) in [
        ("EventWire", wire.all.as_slice()),
        ("consumer", KNOWN_FIELDS),
    ] {
        let missing = &fields[1..];
        assert!(std::panic::catch_unwind(|| assert_inventory(label, missing, &expected)).is_err());
        let mut extra = fields.to_vec();
        extra.push("not_an_event3_field");
        assert!(std::panic::catch_unwind(|| assert_inventory(label, &extra, &expected)).is_err());
    }
}

#[test]
fn event3_sparse_health_terminal_bytes_are_frozen() {
    let mut event = health_event();
    let time = "2026-01-02T03:04:05.000Z".to_string();
    event.timestamp = time.clone();
    event.observed_at = time.clone();
    event.ingested_at = time;
    event.event_id = "telltale-12345678-1234-4234-8234-123456789abc".to_string();
    let bytes = serde_json::to_string(&event).unwrap();
    let expected = concat!(
        r#"{"timestamp":"2026-01-02T03:04:05.000Z","observed_at":"2026-01-02T03:04:05.000Z","ingested_at":"2026-01-02T03:04:05.000Z","time_source":"observed","time_confidence":"low","time_override_reason":"missing_source_timestamp","schema_version":"3.0","event_id":"telltale-12345678-1234-4234-8234-123456789abc","telltale_version":""#,
        env!("CARGO_PKG_VERSION"),
        r#"","event_type":"health","severity":"informational","risk_score":0,"risk_contributions":[],"client":"none","session_id":"scanner","tags":["scanner","discovery"],"evidence":[{"field":"source_inventory","redacted_value":"sources=0; client_source_kinds=0","hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],"source_counts":{},"component":"scanner","check_name":"source_discovery","status":"ok","scan_duration_ms":0,"rule_count":0,"threshold_config":{"low":20,"medium":50,"high":70,"critical":90},"emitted_count":0,"suppressed_count":0,"scanner_error_count":0}"#,
    );
    assert_eq!(bytes, expected);
    assert_eq!(serde_json::to_string(&event.emittable()).unwrap(), expected);
    let object: Value = serde_json::from_str(&bytes).unwrap();
    assert!(object.as_object().unwrap().values().all(|v| !v.is_null()));
    for omitted in [
        "event_time",
        "agent",
        "rule_ids",
        "response",
        "active_policy_name",
        "process",
    ] {
        assert!(
            object.get(omitted).is_none(),
            "{omitted} must be absent, not null"
        );
    }

    event.active_policy_name = Some("synthetic-policy".to_string());
    let populated = expected.replace(
        r#","emitted_count":"#,
        r#","active_policy_name":"[policy:f0b955da26c93d508fe17ceea491db7a5384dc7ae0b9639633866ea0d00d1169]","emitted_count":"#,
    );
    assert_ne!(populated, expected, "golden insertion point must exist");
    assert_eq!(serde_json::to_string(&event).unwrap(), populated);
}
