//! Bounded structured values and text for observations, and the limits they are
//! validated against.

use std::collections::BTreeMap;

use unicode_normalization::UnicodeNormalization;

use super::{BoundDimension, ObservationError, Sensitivity, ValidationCode};

pub const LOCAL_MAX_ENTRIES: usize = 16;
pub const LOCAL_MAX_KEY_BYTES: usize = 64;
pub const LOCAL_MAX_TOTAL_BYTES: usize = 65_536;
pub const LOCAL_MAX_VALUE_BYTES: usize = 16_384;
pub const LOCAL_MAX_DEPTH: usize = 6;
pub const LOCAL_MAX_STRING_BYTES: usize = 4_096;
pub const LOCAL_MAX_ARRAY_ITEMS: usize = 64;
pub const LOCAL_MAX_OBJECT_MEMBERS: usize = 32;
pub const LOCAL_MAX_SEARCHABLE_BYTES: usize = 1_024;
pub const MESSAGE_MAX_TEXT_BYTES: usize = 65_536;
/// Direct textual tool results share the message text budget. Nested result
/// strings and ordinary arguments keep their structured bounds; only argument
/// fields a source declares as authored text ([`ArgumentText`]) get this budget.
pub const TOOL_RESULT_MAX_TEXT_BYTES: usize = MESSAGE_MAX_TEXT_BYTES;
pub const TOOL_PATCH_MAX_TEXT_BYTES: usize = MESSAGE_MAX_TEXT_BYTES;
pub const SEMANTIC_MAX_TOTAL_BYTES: usize = 65_536;

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
    /// Encoded semantic value size, borrowing strings/containers without cloning.
    /// Unlike ordinary bound validation, finite floats use canonical JSON spelling.
    pub fn encoded_byte_len(&self) -> Result<usize, ObservationError> {
        match self {
            Self::Integer(number) => Ok(encoded_number_len(number)),
            Self::Unsigned(number) => Ok(encoded_number_len(number)),
            Self::Number(number) => serde_json::Number::from_f64(*number)
                .map(|number| encoded_number_len(&number))
                .ok_or_else(|| ObservationError::new(ValidationCode::NonFiniteNumber)),
            Self::String(text) => Ok(escaped_string_bytes(text)),
            Self::Array(values) => {
                values
                    .iter()
                    .enumerate()
                    .try_fold(2usize, |total, (index, value)| {
                        total
                            .checked_add(value.encoded_byte_len()? + usize::from(index != 0))
                            .ok_or_else(|| ObservationError::bound(BoundDimension::EncodedBytes))
                    })
            }
            Self::Object(values) => {
                values
                    .iter()
                    .enumerate()
                    .try_fold(2usize, |total, (index, (key, value))| {
                        total
                            .checked_add(
                                escaped_string_bytes(key)
                                    + 1
                                    + value.encoded_byte_len()?
                                    + usize::from(index != 0),
                            )
                            .ok_or_else(|| ObservationError::bound(BoundDimension::EncodedBytes))
                    })
            }
            _ => bounded_json_bytes(self, 1),
        }
    }

    /// Convert direct message content; nested values retain ordinary JSON bounds.
    pub fn try_from_source_message_content(
        value: &serde_json::Value,
    ) -> Result<Self, ObservationError> {
        if let serde_json::Value::String(text) = value {
            Self::try_from_source_message_text(text)
        } else {
            Self::try_from_source_value(value)
        }
    }

    pub fn try_from_source_value(value: &serde_json::Value) -> Result<Self, ObservationError> {
        let converted = Self::convert_source_value(value, 1)?;
        if bounded_json_bytes(&converted, 1)? > LOCAL_MAX_VALUE_BYTES {
            return Err(ObservationError::bound(BoundDimension::EncodedBytes));
        }
        Ok(converted)
    }

    /// Preserve direct output text in full; structured results retain ordinary
    /// JSON bounds. Observation construction also checks the encoded aggregate.
    pub fn try_from_source_tool_result(
        value: &serde_json::Value,
    ) -> Result<Self, ObservationError> {
        if let serde_json::Value::String(text) = value {
            Self::try_from_source_message_text(text)
        } else {
            Self::try_from_source_value(value)
        }
    }

    /// The argument fields `text` declares as authored text (patches, commands,
    /// file bodies, prompts, messages) rather than scalar controls get the
    /// direct-text budget. Validate the ordinary skeleton before admitting text.
    pub fn try_from_source_tool_arguments(
        text: &ArgumentText,
        value: &serde_json::Value,
    ) -> Result<Self, ObservationError> {
        let authored = match value {
            serde_json::Value::Object(members) => authored_text_fields(text, |field| {
                members.get(field).map(serde_json::Value::as_str)
            })?
            .map(|fields| (members, fields)),
            _ => None,
        };
        if let Some((members, fields)) = authored {
            if members.len() > LOCAL_MAX_OBJECT_MEMBERS {
                return Err(ObservationError::bound(BoundDimension::ObjectMembers));
            }
            if members.keys().any(|key| key.len() > LOCAL_MAX_KEY_BYTES) {
                return Err(ObservationError::bound(BoundDimension::KeyBytes));
            }
            // Convert each other member with ordinary depth admission before
            // copying it. Never clone an unchecked source tree into a skeleton.
            let skeleton = members
                .iter()
                .map(|(key, value)| {
                    Ok((
                        key.clone(),
                        if fields.contains(&key.as_str()) {
                            Self::Null
                        } else {
                            Self::convert_source_value(value, 2)?
                        },
                    ))
                })
                .collect::<Result<Vec<_>, ObservationError>>()?;
            let skeleton = Self::object(skeleton)?;
            if bounded_json_bytes(&skeleton, 1)? > LOCAL_MAX_VALUE_BYTES {
                return Err(ObservationError::bound(BoundDimension::EncodedBytes));
            }
            let Self::Object(mut converted) = skeleton else {
                unreachable!()
            };
            for field in fields {
                let text = members[field].as_str().expect("selected text field");
                converted.insert(field.into(), Self::try_from_source_message_text(text)?);
            }
            return Ok(Self::Object(converted));
        }
        if let serde_json::Value::String(whole) = value
            && text.whole
        {
            return Self::try_from_source_message_text(whole);
        }
        Self::try_from_source_value(value)
    }

    /// [`Self::try_from_source_value`] for a tool field that failed it on a
    /// bound: each over-bound value is replaced by `null` and recorded, never
    /// truncated (see [`BoundedValue`]). Errors that are no bound still fail.
    /// Run it only after the strict conversion failed, so an in-bound value
    /// always takes the strict path.
    pub fn try_from_source_value_bounded(
        target: BoundedTarget,
        value: &serde_json::Value,
    ) -> Result<(Self, Vec<BoundedValue>), ObservationError> {
        let mut bounder = Bounder::new(target);
        let mut converted = bounder.convert(value, 1, &mut String::new())?;
        bounder.fit(&mut converted, LOCAL_MAX_VALUE_BYTES, &[], true)?;
        Ok(bounder.finish(converted, value))
    }

    /// [`Self::try_from_source_tool_result`], bounded as
    /// [`Self::try_from_source_value_bounded`] is.
    pub fn try_from_source_tool_result_bounded(
        value: &serde_json::Value,
    ) -> Result<(Self, Vec<BoundedValue>), ObservationError> {
        let serde_json::Value::String(text) = value else {
            return Self::try_from_source_value_bounded(BoundedTarget::Result, value);
        };
        let mut bounder = Bounder::new(BoundedTarget::Result);
        let converted = bounder.text(text)?;
        Ok(bounder.finish(converted, value))
    }

    /// [`Self::try_from_source_tool_arguments`], bounded as
    /// [`Self::try_from_source_value_bounded`] is. Declared authored text keeps
    /// its own budget; over-long text is replaced, not shortened.
    pub fn try_from_source_tool_arguments_bounded(
        text: &ArgumentText,
        value: &serde_json::Value,
    ) -> Result<(Self, Vec<BoundedValue>), ObservationError> {
        let authored = match value {
            serde_json::Value::Object(members) => authored_text_fields(text, |field| {
                members.get(field).map(serde_json::Value::as_str)
            })?
            .map(|fields| (members, fields)),
            _ => None,
        };
        let mut bounder = Bounder::new(BoundedTarget::Arguments);
        if let Some((members, fields)) = authored {
            if members.len() > LOCAL_MAX_OBJECT_MEMBERS {
                let root = bounder.replace("", BoundDimension::ObjectMembers, source_bytes(value));
                return Ok(bounder.finish(root, value));
            }
            let mut converted = Vec::with_capacity(members.len());
            let mut dropped = 0usize;
            for (key, item) in members {
                if key.len() > LOCAL_MAX_KEY_BYTES || nfc(key).len() > LOCAL_MAX_KEY_BYTES {
                    dropped = dropped.saturating_add(member_source_bytes(key, item));
                    continue;
                }
                let mut pointer = String::new();
                push_segment(&mut pointer, &nfc(key));
                let item = match item.as_str().filter(|_| fields.contains(&key.as_str())) {
                    Some(source) => match Self::try_from_source_message_text(source) {
                        Ok(text) => text,
                        Err(error) if error.bound_dimension().is_some() => {
                            bounder.replace(&pointer, BoundDimension::StringBytes, source.len())
                        }
                        Err(error) => return Err(error),
                    },
                    None => bounder.convert(item, 2, &mut pointer)?,
                };
                converted.push((key.clone(), item));
            }
            bounder.dropped("", dropped);
            let mut converted = Self::object(converted)?;
            bounder.fit(&mut converted, LOCAL_MAX_VALUE_BYTES, &fields, true)?;
            bounder.fit(&mut converted, BOUNDED_AGGREGATE_BYTES, &fields, false)?;
            return Ok(bounder.finish(converted, value));
        }
        if let serde_json::Value::String(whole) = value
            && text.whole
        {
            let converted = bounder.text(whole)?;
            return Ok(bounder.finish(converted, value));
        }
        Self::try_from_source_value_bounded(BoundedTarget::Arguments, value)
    }

    pub fn try_from_source_message_text(text: &str) -> Result<Self, ObservationError> {
        bounded_message_text_bytes(text)?;
        let text = nfc(text);
        bounded_message_text_bytes(&text)?;
        Ok(Self::String(text))
    }

    fn convert_source_value(
        value: &serde_json::Value,
        depth: usize,
    ) -> Result<Self, ObservationError> {
        if depth > LOCAL_MAX_DEPTH {
            return Err(ObservationError::bound(BoundDimension::Depth));
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
                    return Err(ObservationError::bound(BoundDimension::StringBytes));
                }
                Ok(Self::string(value))
            }
            serde_json::Value::Array(values) => {
                if values.len() > LOCAL_MAX_ARRAY_ITEMS {
                    return Err(ObservationError::bound(BoundDimension::ArrayItems));
                }
                values
                    .iter()
                    .map(|value| Self::convert_source_value(value, depth + 1))
                    .collect::<Result<Vec<_>, _>>()
                    .map(Self::Array)
            }
            serde_json::Value::Object(values) => {
                if values.len() > LOCAL_MAX_OBJECT_MEMBERS {
                    return Err(ObservationError::bound(BoundDimension::ObjectMembers));
                }
                if values.keys().any(|key| key.len() > LOCAL_MAX_KEY_BYTES) {
                    return Err(ObservationError::bound(BoundDimension::KeyBytes));
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
        return Err(ObservationError::bound(BoundDimension::Depth));
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
                return Err(ObservationError::bound(BoundDimension::StringBytes));
            }
            Ok(escaped_string_bytes(string))
        }
        JsonValue::Array(items) => {
            if items.len() > LOCAL_MAX_ARRAY_ITEMS {
                return Err(ObservationError::bound(BoundDimension::ArrayItems));
            }
            let mut total = 2usize;
            for (index, item) in items.iter().enumerate() {
                total = total
                    .checked_add(bounded_json_bytes(item, depth + 1)? + usize::from(index != 0))
                    .ok_or_else(|| ObservationError::bound(BoundDimension::EncodedBytes))?;
            }
            Ok(total)
        }
        JsonValue::Object(members) => {
            if members.len() > LOCAL_MAX_OBJECT_MEMBERS {
                return Err(ObservationError::bound(BoundDimension::ObjectMembers));
            }
            let mut total = 2usize;
            for (index, (key, item)) in members.iter().enumerate() {
                if key.len() > LOCAL_MAX_KEY_BYTES {
                    return Err(ObservationError::bound(BoundDimension::KeyBytes));
                }
                let item_bytes = bounded_json_bytes(item, depth + 1)?;
                total = total
                    .checked_add(
                        escaped_string_bytes(key) + 1 + item_bytes + usize::from(index != 0),
                    )
                    .ok_or_else(|| ObservationError::bound(BoundDimension::EncodedBytes))?;
            }
            Ok(total)
        }
    }
}

pub(crate) fn bounded_message_text_bytes(text: &str) -> Result<usize, ObservationError> {
    if text.len() > MESSAGE_MAX_TEXT_BYTES {
        return Err(ObservationError::bound(BoundDimension::StringBytes));
    }
    Ok(escaped_string_bytes(text))
}

pub(crate) fn bounded_tool_arguments_bytes(
    declared: &ArgumentText,
    value: &JsonValue,
) -> Result<usize, ObservationError> {
    let authored = match value {
        JsonValue::Object(members) => authored_text_fields(declared, |field| {
            members.get(field).map(|item| match item {
                JsonValue::String(text) => Some(text.as_str()),
                _ => None,
            })
        })?
        .map(|fields| (members, fields)),
        _ => None,
    };
    if let Some((members, fields)) = authored {
        if members.len() > LOCAL_MAX_OBJECT_MEMBERS {
            return Err(ObservationError::bound(BoundDimension::ObjectMembers));
        }
        // Count a borrowed skeleton, with each text field replaced by null.
        // Builder validation must not clone an unchecked nested value first.
        let mut bytes = 2usize;
        let mut text_bytes = 0usize;
        for (index, (key, item)) in members.iter().enumerate() {
            if key.len() > LOCAL_MAX_KEY_BYTES {
                return Err(ObservationError::bound(BoundDimension::KeyBytes));
            }
            let item_bytes = match item {
                JsonValue::String(text) if fields.contains(&key.as_str()) => {
                    text_bytes = text_bytes
                        .checked_add(bounded_message_text_bytes(text)?)
                        .ok_or_else(|| ObservationError::bound(BoundDimension::EncodedBytes))?;
                    4
                }
                _ => bounded_json_bytes(item, 2)?,
            };
            bytes = bytes
                .checked_add(escaped_string_bytes(key) + 1 + item_bytes + usize::from(index != 0))
                .ok_or_else(|| ObservationError::bound(BoundDimension::EncodedBytes))?;
        }
        if bytes > LOCAL_MAX_VALUE_BYTES {
            return Err(ObservationError::bound(BoundDimension::EncodedBytes));
        }
        return (bytes - 4 * fields.len())
            .checked_add(text_bytes)
            .ok_or_else(|| ObservationError::bound(BoundDimension::EncodedBytes));
    }
    if let JsonValue::String(text) = value
        && declared.whole
    {
        return bounded_message_text_bytes(text);
    }
    let bytes = bounded_json_bytes(value, 1)?;
    if bytes > LOCAL_MAX_VALUE_BYTES {
        return Err(ObservationError::bound(BoundDimension::EncodedBytes));
    }
    Ok(bytes)
}

/// The command a tool's arguments carry as authored text: its declared
/// `command` member, or the whole arguments when they may be one authored
/// string and that string is the command.
pub(crate) fn authored_command<'a>(
    declared: &ArgumentText,
    arguments: &'a JsonValue,
) -> Option<&'a str> {
    if !declared.keys.iter().any(|key| key == "command") {
        return None;
    }
    match arguments {
        JsonValue::String(text) if declared.whole => Some(text),
        JsonValue::Object(members) => match members.get("command") {
            Some(JsonValue::String(text)) => Some(text),
            _ => None,
        },
        _ => None,
    }
}

/// What a source's own tool table declares about the text in one call's
/// arguments: the keys whose string values are authored text (commands, file
/// bodies, patches, prompts, messages) and get the direct-text budget instead
/// of the structured string bound; whether the whole argument may be one
/// authored string; and whether a declared key that holds anything but a
/// string makes the arguments invalid. Tool names and keys are harness data
/// and come from the source adapter, never from this crate. Like the declared
/// operation, the declaration is no semantic field: it changes which bound a
/// value is checked against, never the value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgumentText {
    keys: Vec<String>,
    whole: bool,
    strict: bool,
}

impl ArgumentText {
    /// No authored text: every argument keeps the structured bounds.
    pub fn new() -> Self {
        Self::default()
    }
    /// An argument key whose string value is authored text. Repeats add nothing.
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        let key = key.into();
        if !key.is_empty() && !self.keys.contains(&key) {
            self.keys.push(key);
        }
        self
    }
    /// The whole argument may be one authored string. An object argument keeps
    /// the declared keys.
    pub fn with_whole(mut self) -> Self {
        self.whole = true;
        self
    }
    /// A declared key present with a value that is not a string is invalid.
    pub fn with_strict(mut self) -> Self {
        self.strict = true;
        self
    }
    pub fn keys(&self) -> &[String] {
        &self.keys
    }
    pub fn whole(&self) -> bool {
        self.whole
    }
    pub fn strict(&self) -> bool {
        self.strict
    }
    /// The declaration without strictness, for arguments in which a bounded
    /// conversion may have replaced a declared text field by `null`.
    pub(crate) fn lenient(&self) -> Self {
        Self {
            strict: false,
            ..self.clone()
        }
    }
}

/// The declared authored-text fields present as strings in these arguments,
/// or `None` when none apply. A non-string field keeps ordinary conversion
/// unless the declaration is strict.
fn authored_text_fields<'a, 'k>(
    declared: &'k ArgumentText,
    field_text: impl Fn(&str) -> Option<Option<&'a str>>,
) -> Result<Option<Vec<&'k str>>, ObservationError> {
    let mut present = Vec::new();
    for field in &declared.keys {
        match field_text(field) {
            Some(Some(_)) => present.push(field.as_str()),
            Some(None) if declared.strict => {
                return Err(ObservationError::new(ValidationCode::InvalidBody));
            }
            _ => {}
        }
    }
    Ok((!present.is_empty()).then_some(present))
}

/// Most values one tool observation records as replaced. A conversion that
/// would need more replaces the whole field instead.
pub const TOOL_MAX_BOUNDED_VALUES: usize = 16;

/// Room a bounded conversion leaves in the observation aggregate for the tool
/// name, facets and the replacement list itself.
const BOUNDED_AGGREGATE_BYTES: usize = SEMANTIC_MAX_TOTAL_BYTES - 16_384;

/// The tool field a [`BoundedValue`] was replaced in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BoundedTarget {
    Arguments,
    Result,
}

impl BoundedTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Arguments => "arguments",
            Self::Result => "result",
        }
    }
}

/// One over-bound value a bounded tool conversion replaced by `null`. The
/// side list on [`super::ToolObservation`] is the only marker: a `null` or an
/// object of this shape in source data is ordinary data, and only the bounded
/// converters create an entry. It holds coordinates and sizes, never content:
/// the pointer (RFC 6901, over keys already admitted) names where the
/// replaced value sat, or the object an over-long key was dropped from.
#[derive(Clone, PartialEq, Eq)]
pub struct BoundedValue {
    target: BoundedTarget,
    pointer: String,
    dimension: BoundDimension,
    bytes: u64,
}

impl BoundedValue {
    fn new(target: BoundedTarget, pointer: &str, dimension: BoundDimension, bytes: usize) -> Self {
        Self {
            target,
            pointer: pointer.to_owned(),
            dimension,
            bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
        }
    }
    pub fn target(&self) -> BoundedTarget {
        self.target
    }
    pub fn pointer(&self) -> &str {
        &self.pointer
    }
    pub fn dimension(&self) -> BoundDimension {
        self.dimension
    }
    /// The source size of what was replaced: a string's bytes, otherwise the
    /// encoded length of the replaced value or the dropped members.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub(crate) fn to_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            // Spelled as source conversion spells the number.
            (
                "bytes".to_owned(),
                i64::try_from(self.bytes)
                    .map(JsonValue::Integer)
                    .unwrap_or(JsonValue::Unsigned(self.bytes)),
            ),
            (
                "dimension".to_owned(),
                JsonValue::String(self.dimension.as_str().to_owned()),
            ),
            (
                "pointer".to_owned(),
                JsonValue::String(self.pointer.clone()),
            ),
            (
                "target".to_owned(),
                JsonValue::String(self.target.as_str().to_owned()),
            ),
        ]))
    }
}

/// Keys in a pointer are source content, so diagnostics show only its depth.
impl std::fmt::Debug for BoundedValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundedValue")
            .field("target", &self.target)
            .field("segments", &self.pointer.matches('/').count())
            .field("dimension", &self.dimension)
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// Collects the replacements of one bounded conversion.
struct Bounder {
    target: BoundedTarget,
    entries: Vec<BoundedValue>,
}

impl Bounder {
    fn new(target: BoundedTarget) -> Self {
        Self {
            target,
            entries: Vec::new(),
        }
    }

    /// Replace the value at `pointer`; this covers anything recorded beneath it.
    fn replace(&mut self, pointer: &str, dimension: BoundDimension, bytes: usize) -> JsonValue {
        self.entries
            .retain(|entry| !within(&entry.pointer, pointer));
        self.entries
            .push(BoundedValue::new(self.target, pointer, dimension, bytes));
        JsonValue::Null
    }

    /// Record members with over-long keys dropped from the object at `pointer`.
    fn dropped(&mut self, pointer: &str, bytes: usize) {
        if bytes > 0 {
            self.entries.push(BoundedValue::new(
                self.target,
                pointer,
                BoundDimension::KeyBytes,
                bytes,
            ));
        }
    }

    /// A whole field that is direct text: kept whole or replaced whole.
    fn text(&mut self, text: &str) -> Result<JsonValue, ObservationError> {
        match JsonValue::try_from_source_message_text(text) {
            Ok(JsonValue::String(converted))
                if escaped_string_bytes(&converted) <= BOUNDED_AGGREGATE_BYTES =>
            {
                Ok(JsonValue::String(converted))
            }
            Ok(_) => Ok(self.replace("", BoundDimension::EncodedBytes, escaped_string_bytes(text))),
            Err(error) if error.bound_dimension().is_some() => {
                Ok(self.replace("", BoundDimension::StringBytes, text.len()))
            }
            Err(error) => Err(error),
        }
    }

    /// Ordinary conversion, except that a value over a structural bound is
    /// replaced: an over-long string, an over-full array or object, or a
    /// container at the deepest level whose children would exceed the depth.
    fn convert(
        &mut self,
        value: &serde_json::Value,
        depth: usize,
        pointer: &mut String,
    ) -> Result<JsonValue, ObservationError> {
        match value {
            // The bound holds for the normalized text, which can be longer
            // than the source.
            serde_json::Value::String(text) => {
                let normalized = nfc(text);
                if text.len() > LOCAL_MAX_STRING_BYTES || normalized.len() > LOCAL_MAX_STRING_BYTES
                {
                    return Ok(self.replace(pointer, BoundDimension::StringBytes, text.len()));
                }
                Ok(JsonValue::String(normalized))
            }
            serde_json::Value::Array(items) => {
                if items.len() > LOCAL_MAX_ARRAY_ITEMS {
                    return Ok(self.replace(
                        pointer,
                        BoundDimension::ArrayItems,
                        source_bytes(value),
                    ));
                }
                if depth >= LOCAL_MAX_DEPTH && !items.is_empty() {
                    return Ok(self.replace(pointer, BoundDimension::Depth, source_bytes(value)));
                }
                let mut converted = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    let length = pointer.len();
                    push_segment(pointer, &index.to_string());
                    converted.push(self.convert(item, depth + 1, pointer)?);
                    pointer.truncate(length);
                }
                Ok(JsonValue::Array(converted))
            }
            serde_json::Value::Object(members) => {
                if members.len() > LOCAL_MAX_OBJECT_MEMBERS {
                    return Ok(self.replace(
                        pointer,
                        BoundDimension::ObjectMembers,
                        source_bytes(value),
                    ));
                }
                if depth >= LOCAL_MAX_DEPTH && !members.is_empty() {
                    return Ok(self.replace(pointer, BoundDimension::Depth, source_bytes(value)));
                }
                let mut converted = Vec::with_capacity(members.len());
                let mut dropped = 0usize;
                for (source_key, item) in members {
                    let key = nfc(source_key);
                    if source_key.len() > LOCAL_MAX_KEY_BYTES || key.len() > LOCAL_MAX_KEY_BYTES {
                        dropped = dropped.saturating_add(member_source_bytes(source_key, item));
                        continue;
                    }
                    let length = pointer.len();
                    push_segment(pointer, &key);
                    let item = self.convert(item, depth + 1, pointer)?;
                    pointer.truncate(length);
                    converted.push((key, item));
                }
                self.dropped(pointer, dropped);
                JsonValue::object(converted)
            }
            _ => JsonValue::convert_source_value(value, depth),
        }
    }

    /// Replace the largest top-level members (ties in pointer order) until
    /// the value fits `budget`; with nothing left to replace, the whole value.
    /// The skeleton pass counts declared text as `null` and never replaces it.
    fn fit(
        &mut self,
        value: &mut JsonValue,
        budget: usize,
        authored: &[&str],
        skeleton: bool,
    ) -> Result<(), ObservationError> {
        loop {
            let size = match value {
                JsonValue::Object(members) => {
                    let mut size = 2usize;
                    for (index, (key, item)) in members.iter().enumerate() {
                        size = size.saturating_add(
                            escaped_string_bytes(key)
                                + 1
                                + item_bytes(key, item, authored, skeleton)?
                                + usize::from(index != 0),
                        );
                    }
                    size
                }
                _ => bounded_json_bytes(value, 1)?,
            };
            if size <= budget {
                return Ok(());
            }
            let mut largest: Option<(usize, String)> = None;
            let mut consider = |bytes: usize, segment: &dyn Fn() -> String| {
                if largest.as_ref().is_none_or(|(most, _)| bytes > *most) {
                    largest = Some((bytes, segment()));
                }
            };
            match value {
                JsonValue::Object(members) => {
                    for (key, item) in members.iter() {
                        let text = matches!(item, JsonValue::String(_))
                            && authored.contains(&key.as_str());
                        if !matches!(item, JsonValue::Null) && !(skeleton && text) {
                            consider(item_bytes(key, item, authored, skeleton)?, &|| key.clone());
                        }
                    }
                }
                JsonValue::Array(items) => {
                    for (index, item) in items.iter().enumerate() {
                        if !matches!(item, JsonValue::Null) {
                            consider(bounded_json_bytes(item, 2)?, &|| index.to_string());
                        }
                    }
                }
                _ => {}
            }
            let Some((bytes, segment)) = largest else {
                *value = self.replace("", BoundDimension::EncodedBytes, size);
                return Ok(());
            };
            let mut pointer = String::new();
            push_segment(&mut pointer, &segment);
            let placeholder = self.replace(&pointer, BoundDimension::EncodedBytes, bytes);
            match value {
                JsonValue::Object(members) => {
                    members.insert(segment, placeholder);
                }
                JsonValue::Array(items) => {
                    let index: usize = segment.parse().expect("array index segment");
                    items[index] = placeholder;
                }
                _ => unreachable!("only containers have members"),
            }
        }
    }

    /// The sorted, unique list; more than the cap replaces the whole field.
    fn finish(
        mut self,
        value: JsonValue,
        source: &serde_json::Value,
    ) -> (JsonValue, Vec<BoundedValue>) {
        self.entries
            .sort_by(|left, right| left.pointer.cmp(&right.pointer));
        self.entries
            .dedup_by(|left, right| left.pointer == right.pointer);
        if self.entries.len() > TOOL_MAX_BOUNDED_VALUES {
            let dimension = self.entries[0].dimension;
            return (
                JsonValue::Null,
                vec![BoundedValue::new(
                    self.target,
                    "",
                    dimension,
                    source_bytes(source),
                )],
            );
        }
        (value, self.entries)
    }
}

/// Fit a call's converted arguments and result together into the room a
/// bounded conversion leaves in the observation aggregate: replace the
/// largest top-level value of either field (a member, an item, or a field
/// that is no container) by `null` until both fit, recording each replacement
/// with the entries the fields already carry. With `whole`, each field is
/// replaced whole instead. The entries then keep the cap
/// ([`cap_tool_values`]).
pub(crate) fn fit_tool_values(
    arguments: &mut Option<JsonValue>,
    result: &mut Option<JsonValue>,
    entries: &mut Vec<BoundedValue>,
    whole: bool,
) -> Result<(), ObservationError> {
    if whole {
        for (target, field) in [
            (BoundedTarget::Arguments, &mut *arguments),
            (BoundedTarget::Result, &mut *result),
        ] {
            // A `null` field holds nothing to replace, and one replaced
            // whole already has its entry.
            let Some(value) = field
                .as_mut()
                .filter(|value| !matches!(value, JsonValue::Null))
            else {
                continue;
            };
            let bytes = value.encoded_byte_len()?;
            entries.retain(|entry| entry.target != target);
            entries.push(BoundedValue::new(
                target,
                "",
                BoundDimension::EncodedBytes,
                bytes,
            ));
            *value = JsonValue::Null;
        }
        sort_entries(entries);
        return Ok(());
    }
    let fields = [
        (BoundedTarget::Arguments, arguments),
        (BoundedTarget::Result, result),
    ];
    let mut bounders = fields.each_ref().map(|(target, _)| Bounder {
        target: *target,
        entries: entries
            .iter()
            .filter(|entry| entry.target == *target)
            .cloned()
            .collect(),
    });
    loop {
        let mut size = 0usize;
        let mut largest: Option<(usize, usize, Option<String>)> = None;
        for (index, (_, field)) in fields.iter().enumerate() {
            let Some(value) = field.as_ref() else {
                continue;
            };
            size = size.saturating_add(value.encoded_byte_len()?);
            let mut consider = |bytes: usize, segment: Option<String>| {
                if largest.as_ref().is_none_or(|(most, _, _)| bytes > *most) {
                    largest = Some((bytes, index, segment));
                }
            };
            match value {
                JsonValue::Null => {}
                JsonValue::Object(members) => {
                    for (key, item) in members {
                        if !matches!(item, JsonValue::Null) {
                            consider(item.encoded_byte_len()?, Some(key.clone()));
                        }
                    }
                }
                JsonValue::Array(items) => {
                    for (position, item) in items.iter().enumerate() {
                        if !matches!(item, JsonValue::Null) {
                            consider(item.encoded_byte_len()?, Some(position.to_string()));
                        }
                    }
                }
                other => consider(other.encoded_byte_len()?, None),
            }
        }
        if size <= BOUNDED_AGGREGATE_BYTES {
            break;
        }
        let Some((bytes, index, segment)) = largest else {
            break;
        };
        let bounder = &mut bounders[index];
        let field = fields[index].1.as_mut().expect("a candidate's field");
        let Some(segment) = segment else {
            *field = bounder.replace("", BoundDimension::EncodedBytes, bytes);
            continue;
        };
        let mut pointer = String::new();
        push_segment(&mut pointer, &segment);
        let placeholder = bounder.replace(&pointer, BoundDimension::EncodedBytes, bytes);
        match field {
            JsonValue::Object(members) => {
                members.insert(segment, placeholder);
            }
            JsonValue::Array(items) => {
                let position: usize = segment.parse().expect("array index segment");
                items[position] = placeholder;
            }
            _ => unreachable!("only containers have members"),
        }
    }
    entries.clear();
    for bounder in bounders {
        entries.extend(bounder.entries);
    }
    let [(_, arguments), (_, result)] = fields;
    cap_tool_values(arguments, result, entries);
    Ok(())
}

/// Keep one observation's entries within [`TOOL_MAX_BOUNDED_VALUES`] where
/// the two fields' entries meet: while there are more, the field with more
/// entries (ties: the arguments) is replaced whole and recorded by one entry
/// for its root. Entries within the cap are only sorted.
pub(crate) fn cap_tool_values(
    arguments: &mut Option<JsonValue>,
    result: &mut Option<JsonValue>,
    entries: &mut Vec<BoundedValue>,
) {
    sort_entries(entries);
    while entries.len() > TOOL_MAX_BOUNDED_VALUES {
        let count = |target| {
            entries
                .iter()
                .filter(|entry| entry.target == target)
                .count()
        };
        let (target, field) = if count(BoundedTarget::Result) > count(BoundedTarget::Arguments) {
            (BoundedTarget::Result, &mut *result)
        } else {
            (BoundedTarget::Arguments, &mut *arguments)
        };
        let dimension = entries
            .iter()
            .find(|entry| entry.target == target)
            .expect("the field with more entries has one")
            .dimension;
        let bytes = field
            .as_ref()
            .and_then(|value| value.encoded_byte_len().ok())
            .unwrap_or(0);
        if let Some(value) = field.as_mut() {
            *value = JsonValue::Null;
        }
        entries.retain(|entry| entry.target != target);
        entries.push(BoundedValue::new(target, "", dimension, bytes));
        sort_entries(entries);
    }
}

fn sort_entries(entries: &mut Vec<BoundedValue>) {
    entries
        .sort_by(|left, right| (left.target, &left.pointer).cmp(&(right.target, &right.pointer)));
    entries.dedup_by(|left, right| left.target == right.target && left.pointer == right.pointer);
}

fn item_bytes(
    key: &str,
    item: &JsonValue,
    authored: &[&str],
    skeleton: bool,
) -> Result<usize, ObservationError> {
    match item {
        JsonValue::String(text) if authored.contains(&key) => Ok(if skeleton {
            4
        } else {
            escaped_string_bytes(text)
        }),
        _ => bounded_json_bytes(item, 2),
    }
}

/// Whether `pointer` is `ancestor` or lies beneath it.
fn within(pointer: &str, ancestor: &str) -> bool {
    pointer
        .strip_prefix(ancestor)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

pub(crate) fn push_segment(pointer: &mut String, segment: &str) {
    pointer.push('/');
    for character in segment.chars() {
        match character {
            '~' => pointer.push_str("~0"),
            '/' => pointer.push_str("~1"),
            character => pointer.push(character),
        }
    }
}

fn pointer_segments(pointer: &str) -> Option<Vec<String>> {
    if pointer.is_empty() {
        return Some(Vec::new());
    }
    pointer
        .strip_prefix('/')?
        .split('/')
        .map(|escaped| {
            let mut segment = String::new();
            let mut characters = escaped.chars();
            while let Some(character) = characters.next() {
                match character {
                    '~' => match characters.next()? {
                        '0' => segment.push('~'),
                        '1' => segment.push('/'),
                        _ => return None,
                    },
                    character => segment.push(character),
                }
            }
            Some(segment)
        })
        .collect()
}

/// The source encoded length of a value, counted without allocating it.
fn source_bytes(value: &serde_json::Value) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    let _ = serde_json::to_writer(&mut count, value);
    count.0
}

fn member_source_bytes(key: &str, value: &serde_json::Value) -> usize {
    escaped_string_bytes(key)
        .saturating_add(1)
        .saturating_add(source_bytes(value))
}

/// Each entry names a replacement that is really there: a sorted, unique,
/// capped list whose pointers resolve to `null`, or to the object an
/// over-long key was dropped from.
pub(crate) fn validate_bounded_values(
    values: &[BoundedValue],
    arguments: Option<&JsonValue>,
    result: Option<&JsonValue>,
) -> Result<(), ObservationError> {
    let invalid = || ObservationError::new(ValidationCode::InvalidBody);
    if values.len() > TOOL_MAX_BOUNDED_VALUES
        || values
            .windows(2)
            .any(|pair| (pair[0].target, &pair[0].pointer) >= (pair[1].target, &pair[1].pointer))
    {
        return Err(invalid());
    }
    for value in values {
        let mut node = match value.target {
            BoundedTarget::Arguments => arguments,
            BoundedTarget::Result => result,
        }
        .ok_or_else(invalid)?;
        let segments = pointer_segments(&value.pointer).ok_or_else(invalid)?;
        if segments.len() >= LOCAL_MAX_DEPTH {
            return Err(invalid());
        }
        for segment in &segments {
            if segment.len() > LOCAL_MAX_KEY_BYTES {
                return Err(invalid());
            }
            node = match node {
                JsonValue::Object(members) => members.get(segment.as_str()),
                JsonValue::Array(items) => segment
                    .parse::<usize>()
                    .ok()
                    .filter(|index| index.to_string() == *segment)
                    .and_then(|index| items.get(index)),
                _ => None,
            }
            .ok_or_else(invalid)?;
        }
        match (node, value.dimension) {
            (JsonValue::Null, _) | (JsonValue::Object(_), BoundDimension::KeyBytes) => {}
            _ => return Err(invalid()),
        }
    }
    Ok(())
}

pub(crate) fn escaped_string_bytes(value: &str) -> usize {
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

fn encoded_number_len(number: &impl std::fmt::Display) -> usize {
    use std::fmt::Write;
    struct Count(usize);
    impl std::fmt::Write for Count {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            self.0 += text.len();
            Ok(())
        }
    }
    let mut count = Count(0);
    write!(&mut count, "{number}").expect("counting cannot fail");
    count.0
}
