//! Rule packages: identified, versioned, namespaced rule content added to the
//! bundled core rules.
//!
//! In format `telltale-rule-package/v2` a package is a YAML stream: the first
//! document is the header, which names the package, its title, publisher and
//! license, and the namespace that every rule and chain name must use; every
//! following `---` document is one Rule v2 rule or chain, read like a rule
//! file document, sorted by `name`. Format `telltale-rule-package/v1`, whose
//! documents were Rule v1, is no longer read: it fails with an error that
//! points to the Rule v2 documentation. Packages only add definitions: loading one never replaces a
//! bundled core rule or another package's rule, and a package namespace may
//! not reuse a core namespace.
//!
//! Telltale embeds the community package ([`COMMUNITY_PACKAGE_ID`]). A
//! supplied package with that ID replaces the embedded snapshot as a whole,
//! which lets operators run a newer community release without a Telltale
//! release. Like the rest of this crate, parsing is I/O-free: callers hand
//! package text in and decide where it came from.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use sha2::{Digest, Sha256};

use crate::content::LoadedDefinition;
use crate::{LoadedRules, bundled_default_rules, rule_v2};

/// The package format whose documents are Rule v2 rules and chains.
pub const RULE_PACKAGE_FORMAT_V2: &str = "telltale-rule-package/v2";
/// The retired package format whose documents were Rule v1 documents.
const RULE_PACKAGE_FORMAT_V1: &str = "telltale-rule-package/v1";
/// Package ID of the community rules embedded in Telltale.
pub const COMMUNITY_PACKAGE_ID: &str = "telltale.community";
/// Upper bound on one package file, in bytes.
pub const MAX_RULE_PACKAGE_BYTES: usize = 4 * 1024 * 1024;

const COMMUNITY_PACKAGE_YAML: &str = include_str!("../data/community.package.yaml");
/// Namespaces reserved in addition to the namespaces of bundled core rules.
const RESERVED_NAMESPACES: &[&str] = &["procchain", "telltale"];
const MAX_IDENTIFIER_LEN: usize = 64;
const MAX_NAMESPACE_LEN: usize = 32;
pub(crate) const MAX_LABEL_LEN: usize = 256;

/// The package header: the whole first document of the stream.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageHeader {
    /// Already checked; declared so the key is accepted.
    #[serde(rename = "format")]
    _format: String,
    id: String,
    title: String,
    version: String,
    publisher: String,
    license: String,
    rule_namespace: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    revision: Option<String>,
}

/// A validated rule package.
#[derive(Debug, Clone)]
pub struct RulePackage {
    id: String,
    title: String,
    version: String,
    publisher: String,
    license: String,
    rule_namespace: String,
    source: Option<String>,
    revision: Option<String>,
    content_sha256: String,
    documents: Vec<LoadedRules>,
}

impl RulePackage {
    /// Parse and validate one package: a format v2 YAML stream.
    ///
    /// Rejects unknown formats (format v1 with a pointer to the Rule v2
    /// documentation) or header fields, a missing `title`, a `documents` key,
    /// malformed identities, hidden control or bidirectional-formatting
    /// characters in source text or decoded YAML strings, reserved or malformed
    /// namespaces, names outside the namespace, duplicate names or UUIDs, a
    /// document that redefines an anchor it aliases, rule documents not sorted
    /// by `name`, and packages without definitions. Documents are compiled
    /// here.
    pub fn parse(raw: &str) -> Result<Self, Box<dyn Error>> {
        if raw.len() > MAX_RULE_PACKAGE_BYTES {
            return Err(format!("rule package exceeds {MAX_RULE_PACKAGE_BYTES} bytes").into());
        }
        reject_hidden_characters("rule package", raw)?;
        let invalid = |error: serde_yaml::Error| format!("invalid rule package: {error}");
        let values = serde_yaml::Deserializer::from_str(raw)
            .map(Value::deserialize)
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid)?;
        for value in &values {
            reject_decoded_hidden_characters_in("rule package decoded string", value)?;
        }
        let format = values
            .first()
            .and_then(|header| header.get("format"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        match format {
            RULE_PACKAGE_FORMAT_V2 => {}
            RULE_PACKAGE_FORMAT_V1 => {
                return Err(format!(
                    "rule package format {RULE_PACKAGE_FORMAT_V1} is no longer supported: its \
                     documents are Rule v1; rebuild the package as {RULE_PACKAGE_FORMAT_V2}: see \
                     docs/rule-format.md and docs/migrations/0.8.0.md"
                )
                .into());
            }
            _ => {
                return Err(format!(
                    "unsupported rule package format; expected {RULE_PACKAGE_FORMAT_V2}"
                )
                .into());
            }
        }
        if values[0].get("documents").is_some() {
            return Err(format!(
                "invalid rule package: format {RULE_PACKAGE_FORMAT_V2} has no `documents` key; \
                 write each rule or chain as its own `---` document after the header"
            )
            .into());
        }
        // Keep typed parsing on the source for YAML string coercion and error locations.
        let package = serde_yaml::Deserializer::from_str(raw)
            .next()
            .map(PackageHeader::deserialize)
            .transpose()
            .map_err(invalid)?
            .ok_or("invalid rule package: no header document")?;
        validate_package_id(&package.id)?;
        let context = format!("rule package '{}'", package.id);
        for (index, text) in rule_v2::document_texts(raw).into_iter().enumerate() {
            rule_v2::reject_redefined_anchors(text)
                .map_err(|error| format!("{context}: document {}: {error}", index + 1))?;
        }
        validate_label("title", &package.title).map_err(|error| format!("{context}: {error}"))?;
        validate_version(&package.version).map_err(|error| format!("{context}: {error}"))?;
        for (field, value) in [
            ("publisher", &package.publisher),
            ("license", &package.license),
        ] {
            validate_label(field, value).map_err(|error| format!("{context}: {error}"))?;
        }
        for (field, value) in [("source", &package.source), ("revision", &package.revision)] {
            if let Some(value) = value {
                validate_label(field, value).map_err(|error| format!("{context}: {error}"))?;
            }
        }
        validate_namespace(&package.rule_namespace)
            .map_err(|error| format!("{context}: {error}"))?;
        let documents = read_documents(&package.rule_namespace, values.into_iter().skip(1))
            .map_err(|error| format!("{context}: {error}"))?;
        // A UUID used twice across documents fails here.
        LoadedRules::merge(documents.iter().cloned())
            .map_err(|error| format!("{context}: {error}"))?;
        let documents = documents
            .into_iter()
            .map(|document| document.with_package_id(&package.id))
            .collect();

        Ok(Self {
            id: package.id,
            title: package.title,
            version: package.version,
            publisher: package.publisher,
            license: package.license,
            rule_namespace: package.rule_namespace,
            source: package.source,
            revision: package.revision,
            content_sha256: hex::encode(Sha256::digest(raw.as_bytes())),
            documents,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// The display name.
    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn publisher(&self) -> &str {
        &self.publisher
    }

    pub fn license(&self) -> &str {
        &self.license
    }

    /// Every rule and chain name in this package starts with `<namespace>.`.
    pub fn rule_namespace(&self) -> &str {
        &self.rule_namespace
    }

    /// Informational origin of the content, such as a repository URL.
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Informational source revision the package was built from.
    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }

    /// Lowercase hex SHA-256 of the exact package text.
    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    /// The package's documents in order, each marked with the package id.
    pub fn documents(&self) -> &[LoadedRules] {
        &self.documents
    }

    pub fn into_documents(self) -> Vec<LoadedRules> {
        self.documents
    }

    /// Diagnostics never show package paths, so a version and content hash
    /// prefix tell copies apart. The prefix stays short enough that diagnostic
    /// sanitization keeps it.
    fn copy_identity(&self) -> String {
        format!(
            "version {} (content SHA-256 {}...)",
            self.version,
            &self.content_sha256[..12]
        )
    }
}

/// The community package text embedded in this build.
pub fn bundled_community_package_yaml() -> &'static str {
    COMMUNITY_PACKAGE_YAML
}

/// The community package embedded in this build.
pub fn bundled_community_package() -> Result<RulePackage, Box<dyn Error>> {
    RulePackage::parse(COMMUNITY_PACKAGE_YAML)
        .map_err(|error| format!("embedded community package: {error}").into())
}

/// How community content takes part in an effective rule set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CommunityRules {
    /// Use the embedded community package unless a supplied package with the
    /// community ID replaces it.
    #[default]
    Embedded,
    /// Omit the embedded snapshot; a supplied community package still loads.
    SuppliedOnly,
    /// Omit community content from every origin.
    Disabled,
}

/// Where an effective package came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageOrigin {
    /// The community package embedded in this build.
    Embedded,
    /// The supplied package at this index.
    Supplied(usize),
}

/// One package that takes part in an effective rule set.
#[derive(Debug, Clone)]
pub struct ResolvedRulePackage {
    pub package: RulePackage,
    pub origin: PackageOrigin,
    /// Version of the embedded community snapshot this supplied package replaced.
    pub replaced_embedded_version: Option<String>,
}

impl ResolvedRulePackage {
    pub fn summary(&self) -> RulePackageSummary {
        RulePackageSummary {
            id: self.package.id.clone(),
            version: self.package.version.clone(),
            content_sha256: self.package.content_sha256.clone(),
            embedded: self.origin == PackageOrigin::Embedded,
            replaced_embedded_version: self.replaced_embedded_version.clone(),
        }
    }
}

/// Identity of an active package, for provenance and inventory reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RulePackageSummary {
    pub id: String,
    pub version: String,
    pub content_sha256: String,
    pub embedded: bool,
    pub replaced_embedded_version: Option<String>,
}

/// Select the packages that take part in an effective rule set.
///
/// The embedded community package comes first when selected, then supplied
/// packages in their given order. A supplied package with the community ID
/// replaces the embedded snapshot. Two supplied packages with one ID, or two
/// effective packages with one namespace, are rejected rather than resolved.
pub fn resolve_rule_packages(
    community: CommunityRules,
    supplied: Vec<RulePackage>,
) -> Result<Vec<ResolvedRulePackage>, Box<dyn Error>> {
    let mut supplied_ids = BTreeMap::new();
    for package in &supplied {
        if let Some(first) = supplied_ids.insert(package.id.as_str(), package) {
            return Err(format!(
                "duplicate rule package id '{}': {} and {}; supply each package once",
                package.id,
                first.copy_identity(),
                package.copy_identity()
            )
            .into());
        }
    }
    let supplies_community = supplied_ids.contains_key(COMMUNITY_PACKAGE_ID);

    let mut resolved = Vec::new();
    let mut replaced_embedded_version = None;
    if community == CommunityRules::Embedded {
        let embedded = bundled_community_package()?;
        if supplies_community {
            replaced_embedded_version = Some(embedded.version);
        } else {
            resolved.push(ResolvedRulePackage {
                package: embedded,
                origin: PackageOrigin::Embedded,
                replaced_embedded_version: None,
            });
        }
    }
    for (index, package) in supplied.into_iter().enumerate() {
        let is_community = package.id == COMMUNITY_PACKAGE_ID;
        if is_community && community == CommunityRules::Disabled {
            continue;
        }
        resolved.push(ResolvedRulePackage {
            replaced_embedded_version: is_community
                .then(|| replaced_embedded_version.clone())
                .flatten(),
            package,
            origin: PackageOrigin::Supplied(index),
        });
    }

    let mut namespaces = BTreeMap::new();
    for entry in &resolved {
        let package = &entry.package;
        if let Some(other) = namespaces.insert(package.rule_namespace.as_str(), package.id.as_str())
        {
            return Err(format!(
                "rule packages '{other}' and '{}' both use namespace '{}'",
                package.id, package.rule_namespace
            )
            .into());
        }
    }
    Ok(resolved)
}

/// Reject hidden characters on any line of `raw`, naming it as `label`.
pub(crate) fn reject_hidden_characters(label: &str, raw: &str) -> Result<(), Box<dyn Error>> {
    // `lines()` drops CRLF endings, so any carriage return left is a lone one.
    for (line, text) in raw.lines().enumerate() {
        if let Some(character) = text
            .chars()
            .find(|character| is_hidden_character(*character))
        {
            return Err(format!(
                "{label} line {}: forbidden character U+{:04X}",
                line + 1,
                character as u32
            )
            .into());
        }
    }
    Ok(())
}

/// Reject hidden characters in any string a YAML value decodes to, keys
/// included, naming the string as `label`.
pub(crate) fn reject_decoded_hidden_characters_in(
    label: &str,
    value: &Value,
) -> Result<(), Box<dyn Error>> {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(text) => {
                if let Some(character) = text
                    .chars()
                    .find(|character| is_hidden_character(*character))
                {
                    return Err(
                        format!("{label}: forbidden character U+{:04X}", character as u32).into(),
                    );
                }
            }
            Value::Sequence(values) => pending.extend(values),
            Value::Mapping(values) => {
                for (key, value) in values {
                    pending.extend([key, value]);
                }
            }
            Value::Tagged(value) => pending.push(&value.value),
            _ => {}
        }
    }
    Ok(())
}

/// Controls and invisible formatting characters can make reviewed text differ
/// from what a matcher, terminal, or analyst tool interprets. A lone carriage
/// return and the line and paragraph separators in the range starting at
/// U+2028 are line breaks to YAML, but many viewers do not break there, so
/// they could add keys a reviewer never sees.
pub(crate) fn is_hidden_character(character: char) -> bool {
    (character.is_control() && !matches!(character, '\t' | '\n'))
        || matches!(
            character,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

fn validate_package_id(id: &str) -> Result<(), String> {
    let valid = !id.is_empty()
        && id.len() <= MAX_IDENTIFIER_LEN
        && id.split('.').all(|segment| {
            segment.starts_with(|character: char| character.is_ascii_lowercase())
                && segment.chars().all(|character| {
                    character.is_ascii_lowercase()
                        || character.is_ascii_digit()
                        || matches!(character, '_' | '-')
                })
        });
    if valid {
        Ok(())
    } else {
        Err(format!(
            "rule package id must be at most {MAX_IDENTIFIER_LEN} characters of dot-separated \
             segments that start with a-z and contain a-z, 0-9, '_' or '-'"
        ))
    }
}

fn validate_version(version: &str) -> Result<(), String> {
    let valid = version.len() <= MAX_IDENTIFIER_LEN
        && version.starts_with(|character: char| character.is_ascii_alphanumeric())
        && version.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '+' | '-' | '_')
        });
    if valid {
        Ok(())
    } else {
        Err(format!(
            "version must be at most {MAX_IDENTIFIER_LEN} characters of A-Z, a-z, 0-9, '.', '+', \
             '-' or '_' and start with a letter or digit"
        ))
    }
}

fn validate_label(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().count() > MAX_LABEL_LEN || value.contains('\n') {
        return Err(format!(
            "{field} must be one non-empty line of at most {MAX_LABEL_LEN} characters"
        ));
    }
    Ok(())
}

fn validate_namespace(namespace: &str) -> Result<(), Box<dyn Error>> {
    let valid = namespace.len() <= MAX_NAMESPACE_LEN
        && namespace.starts_with(|character: char| character.is_ascii_lowercase())
        && namespace.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        });
    if !valid {
        return Err(format!(
            "rule_namespace must be at most {MAX_NAMESPACE_LEN} characters of a-z, 0-9 or '_' \
             and start with a-z"
        )
        .into());
    }
    if RESERVED_NAMESPACES.contains(&namespace) || core_namespaces()?.contains(namespace) {
        return Err(format!("rule_namespace '{namespace}' is reserved for core rules").into());
    }
    Ok(())
}

/// First ID segments used by bundled core rules and modifiers.
fn core_namespaces() -> Result<BTreeSet<String>, Box<dyn Error>> {
    let core = bundled_default_rules()?;
    Ok(core
        .definitions()
        .iter()
        .filter_map(|definition| definition.id().split('.').next())
        .map(str::to_owned)
        .collect())
}

/// Read the documents after the header: each one Rule v2 rule or chain whose
/// name is in the namespace, sorted by name. Errors number the documents in
/// the stream, the header being document 1.
fn read_documents(
    namespace: &str,
    documents: impl Iterator<Item = Value>,
) -> Result<Vec<LoadedRules>, Box<dyn Error>> {
    let prefix = format!("{namespace}.");
    let mut previous: Option<String> = None;
    let mut loaded = Vec::new();
    for (index, document) in documents.enumerate() {
        let definition = rule_v2::read_document(document)
            .map(LoadedDefinition::from_v2)
            .map_err(|error| format!("document {}: {error}", index + 2))?;
        let name = definition.id();
        let kind = definition.kind().as_str();
        if !name.starts_with(&prefix) {
            return Err(format!("{kind} name '{name}' is outside namespace '{namespace}'").into());
        }
        if let Some(previous) = &previous
            && previous.as_str() >= name
        {
            return Err(format!(
                "documents must be sorted by name, each name once: '{name}' follows '{previous}'"
            )
            .into());
        }
        previous = Some(name.to_owned());
        loaded.push(LoadedRules::from_definitions(vec![definition])?);
    }
    if loaded.is_empty() {
        return Err("rule package contains no rule or chain documents".into());
    }
    Ok(loaded)
}

#[cfg(test)]
mod tests;
