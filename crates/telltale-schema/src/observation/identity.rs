use std::collections::BTreeMap;
use std::fmt;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::value::{nfc, opaque_text};
use super::{
    AssignmentRecord, FactMetadata, JsonValue, LocalEvidence, LocalReference, ObservationBody,
    ObservationError, ObservationFamily, ObservationStage, SourceProvenance, ValidationCode,
};

type HmacSha256 = Hmac<Sha256>;

pub const OBSERVATION_ID_PREFIX: &str = "obs:v2:sha256:";
pub const SEMANTIC_FINGERPRINT_PREFIX: &str = "sha256:";
pub const KEYED_FINGERPRINT_PREFIX: &str = "hmac-sha256:v1:";
pub const ASSIGNMENT_COMMITMENT_PREFIX: &str = "hmac-sha256:assignment-v1:";
pub const ASSIGNMENT_COMPARISON_DOMAIN: &str =
    "telltale:canonical-observation-assignment-compare-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCoordinateKind {
    NativeId,
    SourceSequence,
    Offset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityCoordinateValue {
    NativeId(String),
    SourceSequence { namespace: String, ordinal: u64 },
    Offset { namespace: String, value: String },
}

impl IdentityCoordinateValue {
    pub(crate) fn as_json(&self) -> JsonValue {
        match self {
            Self::NativeId(value) => JsonValue::string(value),
            Self::SourceSequence { namespace, ordinal } => JsonValue::Array(vec![
                JsonValue::string("session"),
                JsonValue::string(namespace),
                JsonValue::Unsigned(*ordinal),
            ]),
            Self::Offset { namespace, value } => JsonValue::Array(vec![
                JsonValue::string("offset"),
                JsonValue::string(namespace),
                JsonValue::string(value),
            ]),
        }
    }
}

impl IdentityCoordinateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NativeId => "native_id",
            Self::SourceSequence => "source_sequence",
            Self::Offset => "offset",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityBasis {
    StableSourceCoordinate {
        domain: String,
        coordinate_kind: IdentityCoordinateKind,
        coordinate_value: IdentityCoordinateValue,
        child_ordinal: u32,
    },
    PersistedAssignment {
        domain: String,
        replay_key: String,
        assignment_ref: LocalReference,
        child_ordinal: u32,
        fingerprint_key_epoch_ref: String,
    },
}

impl IdentityBasis {
    pub fn stable(
        domain: impl AsRef<str>,
        coordinate_kind: IdentityCoordinateKind,
        coordinate_value: IdentityCoordinateValue,
        child_ordinal: u32,
    ) -> Result<Self, ObservationError> {
        let domain =
            super::value::non_empty(domain.as_ref(), ValidationCode::InvalidIdentityBasis)?;
        let value_kind = match &coordinate_value {
            IdentityCoordinateValue::NativeId(_) => IdentityCoordinateKind::NativeId,
            IdentityCoordinateValue::SourceSequence { .. } => {
                IdentityCoordinateKind::SourceSequence
            }
            IdentityCoordinateValue::Offset { .. } => IdentityCoordinateKind::Offset,
        };
        if value_kind != coordinate_kind {
            return Err(ObservationError::new(ValidationCode::InvalidIdentityBasis));
        }
        validate_coordinate(&coordinate_value)?;
        Ok(Self::StableSourceCoordinate {
            domain,
            coordinate_kind,
            coordinate_value,
            child_ordinal,
        })
    }

    pub fn persisted(
        domain: impl AsRef<str>,
        replay_key: impl AsRef<str>,
        assignment_ref: LocalReference,
        child_ordinal: u32,
        fingerprint_key_epoch_ref: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        Ok(Self::PersistedAssignment {
            domain: super::value::non_empty(domain.as_ref(), ValidationCode::InvalidIdentityBasis)?,
            replay_key: opaque_text(replay_key.as_ref(), ValidationCode::InvalidIdentityBasis)?,
            assignment_ref,
            child_ordinal,
            fingerprint_key_epoch_ref: opaque_text(
                fingerprint_key_epoch_ref.as_ref(),
                ValidationCode::InvalidIdentityBasis,
            )?,
        })
    }

    pub fn kind(&self) -> IdentityBasisKind {
        match self {
            Self::StableSourceCoordinate { .. } => IdentityBasisKind::StableSourceCoordinate,
            Self::PersistedAssignment { .. } => IdentityBasisKind::PersistedAssignment,
        }
    }

    pub fn child_ordinal(&self) -> u32 {
        match self {
            Self::StableSourceCoordinate { child_ordinal, .. }
            | Self::PersistedAssignment { child_ordinal, .. } => *child_ordinal,
        }
    }

    pub fn fingerprint_key_epoch_ref(&self) -> Option<&str> {
        match self {
            Self::StableSourceCoordinate { .. } => None,
            Self::PersistedAssignment {
                fingerprint_key_epoch_ref,
                ..
            } => Some(fingerprint_key_epoch_ref),
        }
    }

    pub fn domain(&self) -> &str {
        match self {
            Self::StableSourceCoordinate { domain, .. }
            | Self::PersistedAssignment { domain, .. } => domain,
        }
    }

    pub fn coordinate(&self) -> Option<(IdentityCoordinateKind, &IdentityCoordinateValue)> {
        match self {
            Self::StableSourceCoordinate {
                coordinate_kind,
                coordinate_value,
                ..
            } => Some((*coordinate_kind, coordinate_value)),
            Self::PersistedAssignment { .. } => None,
        }
    }

    pub fn replay_key(&self) -> Option<&str> {
        match self {
            Self::StableSourceCoordinate { .. } => None,
            Self::PersistedAssignment { replay_key, .. } => Some(replay_key),
        }
    }

    pub fn assignment_ref(&self) -> Option<&LocalReference> {
        match self {
            Self::StableSourceCoordinate { .. } => None,
            Self::PersistedAssignment { assignment_ref, .. } => Some(assignment_ref),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityBasisKind {
    StableSourceCoordinate,
    PersistedAssignment,
}

#[derive(Clone, PartialEq, Eq)]
pub enum SemanticComparison {
    Comparable {
        fingerprint: String,
        key_epoch_ref: String,
    },
    Unavailable,
}

impl fmt::Debug for SemanticComparison {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Comparable { .. } => formatter.write_str("SemanticComparison::Comparable { .. }"),
            Self::Unavailable => formatter.write_str("SemanticComparison::Unavailable"),
        }
    }
}

impl fmt::Display for SemanticComparison {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Comparable { .. } => formatter.write_str("comparable"),
            Self::Unavailable => formatter.write_str("unavailable"),
        }
    }
}

impl SemanticComparison {
    pub(crate) fn comparable(fingerprint: String, key_epoch_ref: String) -> Self {
        Self::Comparable {
            fingerprint,
            key_epoch_ref,
        }
    }

    pub fn compare(&self, other: &Self) -> SemanticReplayVerdict {
        match (self, other) {
            (
                Self::Comparable {
                    fingerprint: left_fingerprint,
                    key_epoch_ref: left_epoch,
                },
                Self::Comparable {
                    fingerprint: right_fingerprint,
                    key_epoch_ref: right_epoch,
                },
            ) if left_epoch == right_epoch && left_fingerprint == right_fingerprint => {
                SemanticReplayVerdict::Equivalent
            }
            (
                Self::Comparable {
                    key_epoch_ref: left_epoch,
                    ..
                },
                Self::Comparable {
                    key_epoch_ref: right_epoch,
                    ..
                },
            ) if left_epoch == right_epoch => SemanticReplayVerdict::Mutated,
            _ => SemanticReplayVerdict::Incomparable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticReplayVerdict {
    Equivalent,
    Mutated,
    Incomparable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyedFingerprint {
    location: String,
    key_epoch_ref: String,
    algorithm: &'static str,
    digest: String,
}

impl KeyedFingerprint {
    pub fn compute(
        location: impl AsRef<str>,
        sensitivity: super::Sensitivity,
        value: &JsonValue,
        key_epoch_ref: impl AsRef<str>,
        key: &[u8],
    ) -> Result<Self, ObservationError> {
        if key.is_empty() {
            return Err(ObservationError::new(ValidationCode::InvalidFingerprint));
        }
        let location = opaque_text(location.as_ref(), ValidationCode::InvalidFingerprint)?;
        let key_epoch_ref =
            opaque_text(key_epoch_ref.as_ref(), ValidationCode::InvalidFingerprint)?;
        let payload = JsonValue::Array(vec![
            JsonValue::string("telltale:canonical-sensitive-fact-v1"),
            JsonValue::Integer(1),
            JsonValue::string(&key_epoch_ref),
            JsonValue::string(&location),
            JsonValue::string(sensitivity.as_str()),
            value.clone(),
        ]);
        let digest = hmac_digest(
            key,
            &canonical_identity_json(&payload)?,
            ValidationCode::InvalidFingerprint,
        )?;
        Ok(Self {
            location,
            key_epoch_ref,
            algorithm: "hmac-sha256-v1",
            digest: format!("{KEYED_FINGERPRINT_PREFIX}{digest}"),
        })
    }

    pub fn from_digest(
        location: impl AsRef<str>,
        key_epoch_ref: impl AsRef<str>,
        digest: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        let digest = digest.as_ref();
        if !valid_hex_digest(digest, KEYED_FINGERPRINT_PREFIX) {
            return Err(ObservationError::new(ValidationCode::InvalidFingerprint));
        }
        Ok(Self {
            location: opaque_text(location.as_ref(), ValidationCode::InvalidFingerprint)?,
            key_epoch_ref: opaque_text(key_epoch_ref.as_ref(), ValidationCode::InvalidFingerprint)?,
            algorithm: "hmac-sha256-v1",
            digest: digest.to_owned(),
        })
    }

    pub fn location(&self) -> &str {
        &self.location
    }

    pub fn key_epoch_ref(&self) -> &str {
        &self.key_epoch_ref
    }

    pub fn algorithm(&self) -> &str {
        self.algorithm
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

pub fn canonical_identity_json(value: &JsonValue) -> Result<Vec<u8>, ObservationError> {
    let mut output = Vec::new();
    encode_json(value, &mut output)?;
    Ok(output)
}

fn validate_coordinate(value: &IdentityCoordinateValue) -> Result<(), ObservationError> {
    match value {
        IdentityCoordinateValue::NativeId(value) => {
            opaque_text(value, ValidationCode::PathDerivedId)?;
        }
        IdentityCoordinateValue::SourceSequence { namespace, .. } => {
            opaque_text(namespace, ValidationCode::PathDerivedId)?;
        }
        IdentityCoordinateValue::Offset { namespace, value } => {
            opaque_text(namespace, ValidationCode::PathDerivedId)?;
            opaque_text(value, ValidationCode::PathDerivedId)?;
        }
    }
    Ok(())
}

fn encode_json(value: &JsonValue, output: &mut Vec<u8>) -> Result<(), ObservationError> {
    match value {
        JsonValue::Null => output.extend_from_slice(b"null"),
        JsonValue::Bool(true) => output.extend_from_slice(b"true"),
        JsonValue::Bool(false) => output.extend_from_slice(b"false"),
        JsonValue::Integer(number) => output.extend_from_slice(number.to_string().as_bytes()),
        JsonValue::Unsigned(number) => output.extend_from_slice(number.to_string().as_bytes()),
        JsonValue::Number(number) if number.is_finite() => {
            let number = serde_json::Number::from_f64(*number)
                .ok_or_else(|| ObservationError::new(ValidationCode::NonFiniteNumber))?;
            output.extend_from_slice(number.to_string().as_bytes());
        }
        JsonValue::Number(_) => return Err(ObservationError::new(ValidationCode::NonFiniteNumber)),
        JsonValue::String(string) => encode_string(string, output),
        JsonValue::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                encode_json(item, output)?;
            }
            output.push(b']');
        }
        JsonValue::Object(members) => {
            let mut normalized: Vec<(String, &JsonValue)> =
                members.iter().map(|(key, item)| (nfc(key), item)).collect();
            normalized.sort_by(|left, right| left.0.cmp(&right.0));
            if normalized.windows(2).any(|items| items[0].0 == items[1].0) {
                return Err(ObservationError::new(ValidationCode::DuplicateObjectKey));
            }
            output.push(b'{');
            for (index, (key, item)) in normalized.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                encode_string(key, output);
                output.push(b':');
                encode_json(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn encode_string(value: &str, output: &mut Vec<u8>) {
    output.push(b'"');
    for character in nfc(value).chars() {
        match character {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{08}' => output.extend_from_slice(b"\\b"),
            '\u{0c}' => output.extend_from_slice(b"\\f"),
            '\n' => output.extend_from_slice(b"\\n"),
            '\r' => output.extend_from_slice(b"\\r"),
            '\t' => output.extend_from_slice(b"\\t"),
            character if character <= '\u{1f}' => {
                let escape = format!("\\u{:04x}", character as u32);
                output.extend_from_slice(escape.as_bytes());
            }
            character => {
                let mut buffer = [0; 4];
                output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    output.push(b'"');
}

pub(crate) fn semantic_fingerprint(
    family: ObservationFamily,
    stage: ObservationStage,
    body: &ObservationBody,
    facets: &BTreeMap<String, super::SemanticFacet>,
    local: Option<&LocalEvidence>,
    metadata: &BTreeMap<String, FactMetadata>,
) -> Result<String, ObservationError> {
    let body_value = semantic_body(body, metadata)?;
    let facet_value = semantic_facets(facets, metadata)?;
    let local_value = semantic_local(local)?;
    let value = JsonValue::Array(vec![
        JsonValue::string("telltale:canonical-observation-semantic-v1"),
        JsonValue::Integer(1),
        JsonValue::string(family.as_str()),
        JsonValue::string(stage.as_str()),
        body_value,
        facet_value,
        local_value,
    ]);
    let digest = Sha256::digest(canonical_identity_json(&value)?);
    Ok(format!("{SEMANTIC_FINGERPRINT_PREFIX}{:x}", digest))
}

pub(crate) fn derive_stable_id(
    source: &SourceProvenance,
    family: ObservationFamily,
    stage: ObservationStage,
    child_ordinal: u32,
) -> Result<String, ObservationError> {
    let (coordinate_kind, coordinate_value) = source
        .selected_coordinate()
        .ok_or_else(|| ObservationError::new(ValidationCode::ReplayUnverifiable))?;
    let tuple = JsonValue::Array(vec![
        JsonValue::string("telltale:canonical-observation-coordinate-id-v1"),
        JsonValue::string(source.adapter_type()),
        JsonValue::string(source.adapter_id()),
        JsonValue::string(coordinate_kind.as_str()),
        coordinate_value.as_json(),
        JsonValue::string(family.as_str()),
        JsonValue::string(stage.as_str()),
        JsonValue::Unsigned(child_ordinal as u64),
    ]);
    let digest = Sha256::digest(canonical_identity_json(&tuple)?);
    Ok(format!("{OBSERVATION_ID_PREFIX}{:x}", digest))
}

fn semantic_body(
    body: &ObservationBody,
    metadata: &BTreeMap<String, FactMetadata>,
) -> Result<JsonValue, ObservationError> {
    let mut values = BTreeMap::new();
    for (path, value) in body.semantic_fields() {
        let metadata = metadata
            .get(&path)
            .ok_or_else(|| ObservationError::new(ValidationCode::MetadataCoverage))?;
        values.insert(
            path.rsplit('.').next().unwrap_or_default().to_owned(),
            identity_value(&value, &path, metadata)?,
        );
    }
    Ok(JsonValue::Object(values))
}

fn semantic_facets(
    facets: &BTreeMap<String, super::SemanticFacet>,
    metadata: &BTreeMap<String, FactMetadata>,
) -> Result<JsonValue, ObservationError> {
    let mut values = BTreeMap::new();
    for (path, facet) in facets {
        let metadata = metadata
            .get(path)
            .ok_or_else(|| ObservationError::new(ValidationCode::MetadataCoverage))?;
        values.insert(path.clone(), identity_value(facet.value(), path, metadata)?);
    }
    Ok(JsonValue::Object(values))
}

fn semantic_local(local: Option<&LocalEvidence>) -> Result<JsonValue, ObservationError> {
    let mut values = BTreeMap::new();
    if let Some(local) = local {
        for (key, value) in local.structured_values() {
            values.insert(
                key.clone(),
                local_identity_value(value, &format!("local.{key}"))?,
            );
        }
    }
    Ok(JsonValue::Object(values))
}

fn identity_value(
    value: &JsonValue,
    location: &str,
    metadata: &FactMetadata,
) -> Result<JsonValue, ObservationError> {
    if metadata.sensitivity() == super::Sensitivity::Normal {
        if !metadata.keyed_fingerprints().is_empty() {
            return Err(ObservationError::new(
                ValidationCode::FingerprintSensitivity,
            ));
        }
        return Ok(value.clone());
    }
    let fingerprints = metadata.keyed_fingerprints();
    if location.ends_with("content_parts") {
        let JsonValue::Array(parts) = value else {
            return Err(ObservationError::new(ValidationCode::InvalidFingerprint));
        };
        let mut result = Vec::with_capacity(parts.len());
        for (index, _) in parts.iter().enumerate() {
            let part_location = format!("{location}[{index}]");
            let fingerprint = fingerprints
                .iter()
                .find(|item| item.location() == part_location)
                .ok_or_else(|| ObservationError::new(ValidationCode::ReplayUnverifiable))?;
            result.push(fingerprint_descriptor(
                &part_location,
                metadata,
                fingerprint,
            ));
        }
        return Ok(JsonValue::Array(result));
    }
    let fingerprint = fingerprints
        .iter()
        .find(|item| item.location() == location)
        .ok_or_else(|| ObservationError::new(ValidationCode::ReplayUnverifiable))?;
    Ok(fingerprint_descriptor(location, metadata, fingerprint))
}

fn fingerprint_descriptor(
    location: &str,
    metadata: &FactMetadata,
    fingerprint: &KeyedFingerprint,
) -> JsonValue {
    let mut descriptor = BTreeMap::new();
    descriptor.insert("digest".to_owned(), JsonValue::string(fingerprint.digest()));
    descriptor.insert("location".to_owned(), JsonValue::string(location));
    descriptor.insert(
        "sensitivity".to_owned(),
        JsonValue::string(metadata.sensitivity().as_str()),
    );
    JsonValue::Object(descriptor)
}

fn local_identity_value(
    value: &super::LocalValue,
    location: &str,
) -> Result<JsonValue, ObservationError> {
    if value.sensitivity() == super::Sensitivity::Normal {
        if value.keyed_fingerprint().is_some() {
            return Err(ObservationError::new(
                ValidationCode::FingerprintSensitivity,
            ));
        }
        return Ok(value.value().clone());
    }
    let fingerprint = value
        .keyed_fingerprint()
        .ok_or_else(|| ObservationError::new(ValidationCode::ReplayUnverifiable))?;
    Ok(fingerprint_descriptor(
        location,
        &FactMetadata::new(value.provenance(), value.sensitivity())?,
        fingerprint,
    ))
}

pub fn valid_observation_id(value: &str) -> bool {
    value.len() == OBSERVATION_ID_PREFIX.len() + 64
        && value.starts_with(OBSERVATION_ID_PREFIX)
        && value[OBSERVATION_ID_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_hex_digest(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 64
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn valid_assignment_commitment(value: &str) -> bool {
    valid_hex_digest(value, ASSIGNMENT_COMMITMENT_PREFIX)
}

fn hmac_digest(
    key: &[u8],
    value: &[u8],
    error_code: ValidationCode,
) -> Result<String, ObservationError> {
    if key.is_empty() {
        return Err(ObservationError::new(error_code));
    }
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ObservationError::new(error_code))?;
    mac.update(value);
    let result = mac.finalize().into_bytes();
    Ok(result.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(crate) fn assignment_commitment(
    family: ObservationFamily,
    stage: ObservationStage,
    body: &ObservationBody,
    facets: &BTreeMap<String, super::SemanticFacet>,
    metadata: &BTreeMap<String, FactMetadata>,
    local: Option<&LocalEvidence>,
    key: &[u8],
) -> Result<String, ObservationError> {
    if key.is_empty() {
        return Err(ObservationError::new(ValidationCode::ReplayUnverifiable));
    }
    let mut complete = BTreeMap::new();
    complete.insert("kind".to_owned(), JsonValue::string(family.as_str()));
    complete.insert("stage".to_owned(), JsonValue::string(stage.as_str()));
    complete.insert("body".to_owned(), complete_body(body));
    complete.insert("facets".to_owned(), complete_facets(facets));
    complete.insert("fact_metadata".to_owned(), complete_metadata(metadata));
    complete.insert("local".to_owned(), complete_local(local));
    let payload = JsonValue::Array(vec![
        JsonValue::string(ASSIGNMENT_COMPARISON_DOMAIN),
        JsonValue::Integer(1),
        JsonValue::Object(complete),
    ]);
    let digest = hmac_digest(
        key,
        &canonical_identity_json(&payload)?,
        ValidationCode::ReplayUnverifiable,
    )?;
    Ok(format!("{ASSIGNMENT_COMMITMENT_PREFIX}{digest}"))
}

fn complete_body(body: &ObservationBody) -> JsonValue {
    let mut values = BTreeMap::new();
    for (path, value) in body.semantic_fields() {
        values.insert(path, value);
    }
    JsonValue::Object(values)
}

fn complete_facets(facets: &BTreeMap<String, super::SemanticFacet>) -> JsonValue {
    JsonValue::Object(
        facets
            .iter()
            .map(|(key, value)| (key.clone(), value.value().clone()))
            .collect(),
    )
}

fn complete_metadata(metadata: &BTreeMap<String, FactMetadata>) -> JsonValue {
    JsonValue::Object(
        metadata
            .iter()
            .map(|(key, value)| {
                let mut fields = BTreeMap::new();
                fields.insert(
                    "provenance".to_owned(),
                    JsonValue::string(value.provenance().as_str()),
                );
                if let Some(fidelity) = value.fidelity_override() {
                    fields.insert("fidelity".to_owned(), JsonValue::string(fidelity.as_str()));
                }
                fields.insert(
                    "sensitivity".to_owned(),
                    JsonValue::string(value.sensitivity().as_str()),
                );
                (key.clone(), JsonValue::Object(fields))
            })
            .collect(),
    )
}

fn complete_local(local: Option<&LocalEvidence>) -> JsonValue {
    let mut values = BTreeMap::new();
    if let Some(local) = local {
        for (key, value) in local.structured_values() {
            let mut fields = BTreeMap::new();
            fields.insert("value".to_owned(), value.value().clone());
            if let Some(searchable) = value.searchable() {
                fields.insert("searchable".to_owned(), JsonValue::string(searchable));
            }
            fields.insert(
                "provenance".to_owned(),
                JsonValue::string(value.provenance().as_str()),
            );
            fields.insert(
                "sensitivity".to_owned(),
                JsonValue::string(value.sensitivity().as_str()),
            );
            if let Some(raw_ref) = value.raw_ref() {
                fields.insert("raw_ref".to_owned(), reference_value(raw_ref));
            }
            values.insert(key.clone(), JsonValue::Object(fields));
        }
        if let Some(raw_ref) = local.raw_ref() {
            values.insert("raw_ref".to_owned(), reference_value(raw_ref));
        }
    }
    JsonValue::Object(values)
}

fn reference_value(reference: &LocalReference) -> JsonValue {
    let mut value = BTreeMap::new();
    value.insert("handle".to_owned(), JsonValue::string(reference.handle()));
    value.insert(
        "retention_class".to_owned(),
        JsonValue::string(reference.retention_class()),
    );
    JsonValue::Object(value)
}

pub trait AssignmentStore {
    fn lookup(&self, assignment_ref: &str) -> Result<Option<AssignmentRecord>, ObservationError>;
    fn comparison_key(&self, key_ref: &str) -> Result<Option<Vec<u8>>, ObservationError>;
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryAssignmentStore {
    assignments: BTreeMap<String, AssignmentRecord>,
    keys: BTreeMap<String, Vec<u8>>,
}

impl InMemoryAssignmentStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_key(
        &mut self,
        key_ref: impl AsRef<str>,
        key: &[u8],
    ) -> Result<(), ObservationError> {
        if key.is_empty() {
            return Err(ObservationError::new(ValidationCode::ReplayUnverifiable));
        }
        let key_ref = opaque_text(key_ref.as_ref(), ValidationCode::InvalidReference)?;
        self.keys.insert(key_ref, key.to_vec());
        Ok(())
    }

    pub fn insert_assignment(
        &mut self,
        assignment_ref: impl AsRef<str>,
        observation_id: impl AsRef<str>,
        comparison_key_ref: impl AsRef<str>,
        commitment: impl AsRef<str>,
    ) -> Result<(), ObservationError> {
        let assignment_ref =
            opaque_text(assignment_ref.as_ref(), ValidationCode::InvalidReference)?;
        let record = AssignmentRecord::new(observation_id, comparison_key_ref, commitment)?;
        self.assignments.insert(assignment_ref, record);
        Ok(())
    }
}

impl AssignmentStore for InMemoryAssignmentStore {
    fn lookup(&self, assignment_ref: &str) -> Result<Option<AssignmentRecord>, ObservationError> {
        Ok(self.assignments.get(assignment_ref).cloned())
    }

    fn comparison_key(&self, key_ref: &str) -> Result<Option<Vec<u8>>, ObservationError> {
        Ok(self.keys.get(key_ref).cloned())
    }
}
