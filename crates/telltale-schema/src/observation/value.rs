use std::collections::BTreeMap;

use unicode_normalization::UnicodeNormalization;

use super::{ObservationError, Sensitivity, ValidationCode};

pub const LOCAL_MAX_ENTRIES: usize = 16;
pub const LOCAL_MAX_KEY_BYTES: usize = 64;
pub const LOCAL_MAX_TOTAL_BYTES: usize = 65_536;
pub const LOCAL_MAX_VALUE_BYTES: usize = 16_384;
pub const LOCAL_MAX_DEPTH: usize = 6;
pub const LOCAL_MAX_STRING_BYTES: usize = 4_096;
pub const LOCAL_MAX_ARRAY_ITEMS: usize = 64;
pub const LOCAL_MAX_OBJECT_MEMBERS: usize = 32;
pub const LOCAL_MAX_SEARCHABLE_BYTES: usize = 1_024;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Integer(i64),
    Unsigned(u64),
    Number(f64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl JsonValue {
    pub fn try_from_source_value(value: &serde_json::Value) -> Result<Self, ObservationError> {
        let converted = Self::convert_source_value(value, 1)?;
        if bounded_json_bytes(&converted, 1)? > LOCAL_MAX_VALUE_BYTES {
            return Err(ObservationError::new(ValidationCode::UnboundedValue));
        }
        Ok(converted)
    }

    fn convert_source_value(
        value: &serde_json::Value,
        depth: usize,
    ) -> Result<Self, ObservationError> {
        if depth > LOCAL_MAX_DEPTH {
            return Err(ObservationError::new(ValidationCode::UnboundedValue));
        }
        match value {
            serde_json::Value::Null => Ok(Self::Null),
            serde_json::Value::Bool(value) => Ok(Self::Bool(*value)),
            serde_json::Value::Number(value) => {
                if let Some(value) = value.as_i64() {
                    Ok(Self::Integer(value))
                } else if let Some(value) = value.as_u64() {
                    Ok(Self::Unsigned(value))
                } else {
                    let value = value
                        .as_f64()
                        .ok_or_else(|| ObservationError::new(ValidationCode::NonFiniteNumber))?;
                    Self::number(value)
                }
            }
            serde_json::Value::String(value) => {
                if value.len() > LOCAL_MAX_STRING_BYTES {
                    return Err(ObservationError::new(ValidationCode::UnboundedValue));
                }
                Ok(Self::string(value))
            }
            serde_json::Value::Array(values) => {
                if values.len() > LOCAL_MAX_ARRAY_ITEMS {
                    return Err(ObservationError::new(ValidationCode::UnboundedValue));
                }
                values
                    .iter()
                    .map(|value| Self::convert_source_value(value, depth + 1))
                    .collect::<Result<Vec<_>, _>>()
                    .map(Self::Array)
            }
            serde_json::Value::Object(values) => {
                if values.len() > LOCAL_MAX_OBJECT_MEMBERS {
                    return Err(ObservationError::new(ValidationCode::UnboundedValue));
                }
                if values.keys().any(|key| key.len() > LOCAL_MAX_KEY_BYTES) {
                    return Err(ObservationError::new(ValidationCode::UnboundedValue));
                }
                values
                    .iter()
                    .map(|(key, value)| {
                        Ok((key.clone(), Self::convert_source_value(value, depth + 1)?))
                    })
                    .collect::<Result<Vec<_>, ObservationError>>()
                    .and_then(Self::object)
            }
        }
    }

    pub fn number(value: f64) -> Result<Self, ObservationError> {
        if value.is_finite() {
            Ok(Self::Number(value))
        } else {
            Err(ObservationError::new(ValidationCode::NonFiniteNumber))
        }
    }

    pub fn string(value: impl AsRef<str>) -> Self {
        Self::String(nfc(value.as_ref()))
    }

    pub fn array(values: Vec<Self>) -> Self {
        Self::Array(values)
    }

    pub fn object(
        values: impl IntoIterator<Item = (String, Self)>,
    ) -> Result<Self, ObservationError> {
        let mut object = BTreeMap::new();
        for (key, value) in values {
            let key = nfc(&key);
            if object.insert(key, value).is_some() {
                return Err(ObservationError::new(ValidationCode::DuplicateObjectKey));
            }
        }
        Ok(Self::Object(object))
    }

    pub fn canonicalize(self) -> Result<Self, ObservationError> {
        match self {
            Self::Null | Self::Bool(_) | Self::Integer(_) | Self::Unsigned(_) => Ok(self),
            Self::Number(value) if value.is_finite() => Ok(Self::Number(value)),
            Self::Number(_) => Err(ObservationError::new(ValidationCode::NonFiniteNumber)),
            Self::String(value) => Ok(Self::String(nfc(&value))),
            Self::Array(values) => values
                .into_iter()
                .map(Self::canonicalize)
                .collect::<Result<Vec<_>, _>>()
                .map(Self::Array),
            Self::Object(values) => {
                let mut object = BTreeMap::new();
                for (key, value) in values {
                    let key = nfc(&key);
                    if object.contains_key(&key) {
                        return Err(ObservationError::new(ValidationCode::DuplicateObjectKey));
                    }
                    object.insert(key, value.canonicalize()?);
                }
                Ok(Self::Object(object))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalReference {
    handle: String,
    retention_class: String,
}

impl LocalReference {
    pub fn new(
        handle: impl AsRef<str>,
        retention_class: impl AsRef<str>,
    ) -> Result<Self, ObservationError> {
        let handle = opaque_text(handle.as_ref(), ValidationCode::InvalidReference)?;
        let retention_class =
            non_empty(retention_class.as_ref(), ValidationCode::InvalidReference)?;
        if matches!(
            retention_class.as_str(),
            "external" | "exportable" | "telemetry"
        ) {
            return Err(ObservationError::new(ValidationCode::ExportableReference));
        }
        Ok(Self {
            handle,
            retention_class,
        })
    }

    pub fn handle(&self) -> &str {
        &self.handle
    }

    pub fn retention_class(&self) -> &str {
        &self.retention_class
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SemanticFacet {
    value: JsonValue,
}

impl SemanticFacet {
    pub fn new(value: JsonValue) -> Self {
        Self { value }
    }

    pub(crate) fn canonicalize(self) -> Result<Self, ObservationError> {
        Ok(Self {
            value: self.value.canonicalize()?,
        })
    }

    pub fn value(&self) -> &JsonValue {
        &self.value
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalValue {
    value: JsonValue,
    searchable: Option<String>,
    provenance: super::FactProvenance,
    sensitivity: Sensitivity,
    raw_ref: Option<LocalReference>,
    keyed_fingerprint: Option<super::KeyedFingerprint>,
}

impl LocalValue {
    pub fn new(
        value: JsonValue,
        searchable: Option<impl AsRef<str>>,
        provenance: super::FactProvenance,
        sensitivity: Sensitivity,
    ) -> Result<Self, ObservationError> {
        if sensitivity == Sensitivity::Prohibited {
            return Err(ObservationError::new(ValidationCode::ProhibitedSensitivity));
        }
        let value = value.canonicalize()?;
        let searchable = searchable.map(|text| nfc(text.as_ref()));
        if searchable
            .as_ref()
            .is_some_and(|text| text.len() > LOCAL_MAX_SEARCHABLE_BYTES)
        {
            return Err(ObservationError::new(ValidationCode::UnboundedValue));
        }
        let local = Self {
            value,
            searchable,
            provenance,
            sensitivity,
            raw_ref: None,
            keyed_fingerprint: None,
        };
        local.validate_bounds()?;
        Ok(local)
    }

    pub fn with_raw_ref(mut self, raw_ref: LocalReference) -> Result<Self, ObservationError> {
        if self.sensitivity == Sensitivity::Normal {
            return Err(ObservationError::new(ValidationCode::ReferenceSensitivity));
        }
        self.raw_ref = Some(raw_ref);
        Ok(self)
    }

    pub fn with_keyed_fingerprint(
        mut self,
        fingerprint: super::KeyedFingerprint,
    ) -> Result<Self, ObservationError> {
        if self.sensitivity == Sensitivity::Normal {
            return Err(ObservationError::new(
                ValidationCode::FingerprintSensitivity,
            ));
        }
        self.keyed_fingerprint = Some(fingerprint);
        Ok(self)
    }

    pub fn value(&self) -> &JsonValue {
        &self.value
    }

    pub fn searchable(&self) -> Option<&str> {
        self.searchable.as_deref()
    }

    pub fn provenance(&self) -> super::FactProvenance {
        self.provenance
    }

    pub fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }

    pub fn raw_ref(&self) -> Option<&LocalReference> {
        self.raw_ref.as_ref()
    }

    pub fn keyed_fingerprint(&self) -> Option<&super::KeyedFingerprint> {
        self.keyed_fingerprint.as_ref()
    }

    pub(crate) fn validate_bounds(&self) -> Result<usize, ObservationError> {
        let bytes = bounded_json_bytes(&self.value, 1)?;
        if bytes > LOCAL_MAX_VALUE_BYTES {
            return Err(ObservationError::new(ValidationCode::UnboundedValue));
        }
        if self
            .searchable
            .as_ref()
            .is_some_and(|text| text.len() > LOCAL_MAX_SEARCHABLE_BYTES)
        {
            return Err(ObservationError::new(ValidationCode::UnboundedValue));
        }
        if self.raw_ref.is_some() && self.sensitivity == Sensitivity::Normal {
            return Err(ObservationError::new(ValidationCode::ReferenceSensitivity));
        }
        if self.sensitivity == Sensitivity::Normal && self.keyed_fingerprint.is_some() {
            return Err(ObservationError::new(
                ValidationCode::FingerprintSensitivity,
            ));
        }
        Ok(bytes + self.searchable.as_ref().map_or(0, String::len))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalEvidence {
    structured_values: BTreeMap<String, LocalValue>,
    raw_ref: Option<LocalReference>,
}

impl LocalEvidence {
    pub fn new() -> Self {
        Self {
            structured_values: BTreeMap::new(),
            raw_ref: None,
        }
    }

    pub fn insert(
        mut self,
        key: impl AsRef<str>,
        value: LocalValue,
    ) -> Result<Self, ObservationError> {
        let key = nfc(key.as_ref());
        validate_local_key(&key)?;
        if self.structured_values.len() >= LOCAL_MAX_ENTRIES
            && !self.structured_values.contains_key(&key)
        {
            return Err(ObservationError::new(ValidationCode::UnboundedValue));
        }
        self.structured_values.insert(key, value);
        self.validate_bounds()?;
        Ok(self)
    }

    pub fn with_raw_ref(mut self, raw_ref: LocalReference) -> Self {
        self.raw_ref = Some(raw_ref);
        self
    }

    pub fn structured_values(&self) -> &BTreeMap<String, LocalValue> {
        &self.structured_values
    }

    pub fn raw_ref(&self) -> Option<&LocalReference> {
        self.raw_ref.as_ref()
    }

    pub(crate) fn validate_bounds(&self) -> Result<(), ObservationError> {
        if self.structured_values.len() > LOCAL_MAX_ENTRIES {
            return Err(ObservationError::new(ValidationCode::UnboundedValue));
        }
        let mut total = 0usize;
        for (key, value) in &self.structured_values {
            if key.len() > LOCAL_MAX_KEY_BYTES {
                return Err(ObservationError::new(ValidationCode::UnboundedValue));
            }
            validate_local_key(key)?;
            total = total
                .checked_add(value.validate_bounds()?)
                .ok_or_else(|| ObservationError::new(ValidationCode::UnboundedValue))?;
        }
        if total > LOCAL_MAX_TOTAL_BYTES {
            return Err(ObservationError::new(ValidationCode::UnboundedValue));
        }
        Ok(())
    }
}

impl Default for LocalEvidence {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn nfc(value: &str) -> String {
    value.nfc().collect()
}

pub(crate) fn non_empty(value: &str, code: ValidationCode) -> Result<String, ObservationError> {
    let value = nfc(value);
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err(ObservationError::new(code));
    }
    Ok(value)
}

pub(crate) fn opaque_text(value: &str, code: ValidationCode) -> Result<String, ObservationError> {
    let value = non_empty(value, code)?;
    if value.contains('/') || value.contains('\\') || value.contains("..") {
        return Err(ObservationError::new(ValidationCode::PathDerivedId));
    }
    Ok(value)
}

pub(crate) fn validate_local_key(key: &str) -> Result<(), ObservationError> {
    let registered = matches!(
        key,
        "tool.arguments"
            | "tool.result"
            | "tool.definition"
            | "tool.raw_result"
            | "message.content"
            | "message.content_parts"
            | "message.raw_content"
            | "inference.request"
            | "inference.response"
            | "inference.raw_response"
            | "tool_definition.definition"
            | "tool_definition.schema"
            | "mcp.instruction"
            | "mcp.inventory"
            | "browser.page"
            | "browser.navigation"
    );
    if key.len() > LOCAL_MAX_KEY_BYTES || !registered {
        return Err(ObservationError::new(ValidationCode::InvalidLocalKey));
    }
    Ok(())
}

pub(crate) fn bounded_json_bytes(
    value: &JsonValue,
    depth: usize,
) -> Result<usize, ObservationError> {
    if depth > LOCAL_MAX_DEPTH {
        return Err(ObservationError::new(ValidationCode::UnboundedValue));
    }
    match value {
        JsonValue::Null => Ok(4),
        JsonValue::Bool(true) => Ok(4),
        JsonValue::Bool(false) => Ok(5),
        JsonValue::Integer(number) => Ok(number.to_string().len()),
        JsonValue::Unsigned(number) => Ok(number.to_string().len()),
        JsonValue::Number(number) if number.is_finite() => Ok(number.to_string().len()),
        JsonValue::Number(_) => Err(ObservationError::new(ValidationCode::NonFiniteNumber)),
        JsonValue::String(string) => {
            if string.len() > LOCAL_MAX_STRING_BYTES {
                return Err(ObservationError::new(ValidationCode::UnboundedValue));
            }
            Ok(escaped_string_bytes(string))
        }
        JsonValue::Array(items) => {
            if items.len() > LOCAL_MAX_ARRAY_ITEMS {
                return Err(ObservationError::new(ValidationCode::UnboundedValue));
            }
            let mut total = 2usize;
            for (index, item) in items.iter().enumerate() {
                total = total
                    .checked_add(bounded_json_bytes(item, depth + 1)? + usize::from(index != 0))
                    .ok_or_else(|| ObservationError::new(ValidationCode::UnboundedValue))?;
            }
            Ok(total)
        }
        JsonValue::Object(members) => {
            if members.len() > LOCAL_MAX_OBJECT_MEMBERS {
                return Err(ObservationError::new(ValidationCode::UnboundedValue));
            }
            let mut total = 2usize;
            for (index, (key, item)) in members.iter().enumerate() {
                if key.len() > LOCAL_MAX_KEY_BYTES {
                    return Err(ObservationError::new(ValidationCode::UnboundedValue));
                }
                let item_bytes = bounded_json_bytes(item, depth + 1)?;
                total = total
                    .checked_add(
                        escaped_string_bytes(key) + 1 + item_bytes + usize::from(index != 0),
                    )
                    .ok_or_else(|| ObservationError::new(ValidationCode::UnboundedValue))?;
            }
            Ok(total)
        }
    }
}

fn escaped_string_bytes(value: &str) -> usize {
    2 + value
        .chars()
        .map(|character| match character {
            '"' | '\\' => 2,
            '\u{08}' | '\u{0c}' | '\n' | '\r' | '\t' => 2,
            character if character <= '\u{1f}' => 6,
            character => character.len_utf8(),
        })
        .sum::<usize>()
}
