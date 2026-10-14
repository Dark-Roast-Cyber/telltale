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
/// strings and ordinary arguments keep their structured bounds; only the exact
/// apply_patch.patchText argument has the authored-text exception below.
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

    /// Exact tool argument fields that carry authored text (patches, commands,
    /// file bodies, prompts) rather than scalar controls get the direct-text
    /// budget. Validate the ordinary skeleton before admitting text.
    pub fn try_from_source_tool_arguments(
        name: Option<&str>,
        value: &serde_json::Value,
    ) -> Result<Self, ObservationError> {
        if let serde_json::Value::Object(members) = value
            && let Some(fields) = authored_text_fields(name, |field| {
                members.get(field).map(serde_json::Value::as_str)
            })?
        {
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
        if let serde_json::Value::String(text) = value
            && is_bare_command_tool(name)
        {
            return Self::try_from_source_message_text(text);
        }
        Self::try_from_source_value(value)
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
    name: Option<&str>,
    value: &JsonValue,
) -> Result<usize, ObservationError> {
    if let JsonValue::Object(members) = value
        && let Some(fields) = authored_text_fields(name, |field| {
            members.get(field).map(|item| match item {
                JsonValue::String(text) => Some(text.as_str()),
                _ => None,
            })
        })?
    {
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
        && is_bare_command_tool(name)
    {
        return bounded_message_text_bytes(text);
    }
    let bytes = bounded_json_bytes(value, 1)?;
    if bytes > LOCAL_MAX_VALUE_BYTES {
        return Err(ObservationError::bound(BoundDimension::EncodedBytes));
    }
    Ok(bytes)
}

/// The command a tool's arguments carry as authored text: its `command`
/// member, or the whole arguments when they are the command string itself.
pub(crate) fn authored_command<'a>(
    name: Option<&str>,
    arguments: &'a JsonValue,
) -> Option<&'a str> {
    match arguments {
        JsonValue::String(text) if is_bare_command_tool(name) => Some(text),
        JsonValue::Object(members) if is_authored_text_argument(name, "command") => {
            match members.get("command") {
                Some(JsonValue::String(text)) => Some(text),
                _ => None,
            }
        }
        _ => None,
    }
}

/// OpenCode v2 stores a user `!` command as `shell` arguments that are the
/// command string itself. Legacy `bash` input must still be an object.
fn is_bare_command_tool(name: Option<&str>) -> bool {
    name == Some("shell")
}

/// Exact `(tool, field)` pairs whose string values are authored text. Tool
/// names are the OpenCode names (`apply_patch` for legacy stores; `patch`,
/// `shell`, `write`, `edit`, `execute`, `subagent` for v2; `bash` and `task`
/// as stored by earlier releases); other adapters do not use these names with
/// string fields.
const AUTHORED_TEXT_ARGUMENTS: &[(&str, &[&str])] = &[
    ("apply_patch", &["patchText"]),
    ("patch", &["patchText"]),
    ("shell", &["command"]),
    ("bash", &["command"]),
    ("write", &["content"]),
    ("edit", &["oldString", "newString"]),
    ("execute", &["code"]),
    ("subagent", &["prompt"]),
    ("task", &["prompt"]),
];

pub(crate) fn is_authored_text_argument(name: Option<&str>, field: &str) -> bool {
    AUTHORED_TEXT_ARGUMENTS
        .iter()
        .any(|(tool, fields)| Some(*tool) == name && fields.contains(&field))
}

/// The authored-text fields present as strings in these arguments, or `None`
/// when none apply. A non-string field keeps ordinary conversion, except
/// `apply_patch.patchText`, whose non-string value has always been invalid.
fn authored_text_fields<'a>(
    name: Option<&str>,
    field_text: impl Fn(&str) -> Option<Option<&'a str>>,
) -> Result<Option<Vec<&'static str>>, ObservationError> {
    let Some((tool, fields)) = AUTHORED_TEXT_ARGUMENTS
        .iter()
        .find(|(tool, _)| Some(*tool) == name)
    else {
        return Ok(None);
    };
    let mut present = Vec::new();
    for field in *fields {
        match field_text(field) {
            Some(Some(_)) => present.push(*field),
            Some(None) if *tool == "apply_patch" => {
                return Err(ObservationError::new(ValidationCode::InvalidBody));
            }
            _ => {}
        }
    }
    Ok((!present.is_empty()).then_some(present))
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
