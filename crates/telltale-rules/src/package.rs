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
const MAX_LABEL_LEN: usize = 256;

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
fn is_hidden_character(character: char) -> bool {
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
mod tests {
    use super::*;
    use crate::CompiledDefinition;

    /// A format v2 package with one rule.
    fn package(id: &str, namespace: &str, rule_id: &str) -> String {
        format!(
            r#"format: telltale-rule-package/v2
id: {id}
title: Synthetic package
version: 1.2.3
publisher: Synthetic publisher
license: Apache-2.0
rule_namespace: {namespace}
---
title: Synthetic package rule
id: 5d0f6c4e-8a1b-4c2d-9e3f-0a1b2c3d4e5f
name: {rule_id}
taxonomy: telltale
description: Synthetic package rules.
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re|i: 'synthetic-package-marker'
    condition: selection
level: low
telltale:
    category: execution
    score: 20
    explanation: Synthetic package rule.
    tags: [synthetic]
"#
        )
    }

    fn error(raw: &str) -> String {
        RulePackage::parse(raw).unwrap_err().to_string()
    }

    #[test]
    fn valid_package_exposes_identity_and_content_hash() {
        let raw = package("acme.rules", "acme", "acme.synthetic.marker");
        let parsed = RulePackage::parse(&raw).unwrap();
        assert_eq!(parsed.id(), "acme.rules");
        assert_eq!(parsed.version(), "1.2.3");
        assert_eq!(parsed.rule_namespace(), "acme");
        assert_eq!(parsed.license(), "Apache-2.0");
        assert_eq!(parsed.documents().len(), 1);
        assert_eq!(
            parsed.content_sha256(),
            hex::encode(Sha256::digest(raw.as_bytes()))
        );
    }

    #[test]
    fn definitions_must_stay_inside_the_package_namespace() {
        let message = error(&package("acme.rules", "acme", "other.synthetic.marker"));
        assert!(message.contains("outside namespace 'acme'"), "{message}");
    }

    #[test]
    fn core_and_reserved_namespaces_are_rejected() {
        for namespace in ["execution", "chain", "procchain", "telltale"] {
            let rule_id = format!("{namespace}.synthetic.marker");
            let message = error(&package("acme.rules", namespace, &rule_id));
            assert!(
                message.contains("reserved for core rules"),
                "{namespace}: {message}"
            );
        }
    }

    #[test]
    fn hidden_formatting_characters_are_rejected_with_their_line() {
        let raw = package("acme.rules", "acme", "acme.synthetic.marker")
            .replace("synthetic-package-marker", "synthetic\u{202E}marker");
        let message = error(&raw);
        assert!(message.contains("forbidden character U+202E"), "{message}");
        assert!(message.contains("line 19"), "{message}");
    }

    #[test]
    fn hidden_line_breaks_are_rejected_before_yaml_splits_on_them() {
        for separator in ['\u{2028}', '\u{2029}', '\r'] {
            let raw = package("acme.rules", "acme", "acme.synthetic.marker").replace(
                "explanation: Synthetic package rule.",
                &format!("explanation: Synthetic package rule.{separator}    enabled: false"),
            );
            let message = error(&raw);
            let expected = format!("forbidden character U+{:04X}", separator as u32);
            assert!(message.contains(&expected), "{message}");
            assert!(message.contains("line 25"), "{message}");
        }
        let message = error(&format!(
            "{}\r",
            package("acme.rules", "acme", "acme.synthetic.marker")
        ));
        assert!(message.contains("forbidden character U+000D"), "{message}");
    }

    #[test]
    fn crlf_line_endings_load_like_lf() {
        let lf = package("acme.rules", "acme", "acme.synthetic.marker").replace(
            "description: Synthetic package rules.",
            "description: |\n    First line.\n    Second line.",
        );
        let crlf = RulePackage::parse(&lf.replace('\n', "\r\n")).expect("CRLF package");
        let lf = RulePackage::parse(&lf).unwrap();
        assert_eq!(
            format!("{:?}", crlf.documents()),
            format!("{:?}", lf.documents())
        );
        assert_eq!(crlf.documents(), lf.documents());
    }

    #[test]
    fn yaml_escaped_hidden_characters_are_rejected_in_decoded_strings() {
        let base = package("acme.rules", "acme", "acme.synthetic.marker");
        let fields = [
            (
                "publisher",
                "publisher: Synthetic publisher",
                "publisher: \"VALUE\"",
            ),
            ("license", "license: Apache-2.0", "license: \"VALUE\""),
            ("source", "\n---\n", "\nsource: \"VALUE\"\n---\n"),
            ("revision", "\n---\n", "\nrevision: \"VALUE\"\n---\n"),
            (
                "document description",
                "description: Synthetic package rules.",
                "description: \"VALUE\"",
            ),
            (
                "rule explanation",
                "explanation: Synthetic package rule.",
                "explanation: \"VALUE\"",
            ),
            ("title", "title: Synthetic package\n", "title: \"VALUE\"\n"),
            ("regex", "'synthetic-package-marker'", "\"VALUE\""),
            ("tags", "tags: [synthetic]", "tags: [\"VALUE\"]"),
            (
                "selection key",
                "tool.command|re|i: 'synthetic-package-marker'",
                "\"VALUE\": marker",
            ),
            (
                "chain explanation",
                "    tags: [synthetic]\n",
                "    tags: [synthetic]\n---\ntitle: Chain\nid: 6e1f7d5a-9b2c-4d3e-8f40-1b2c3d4e5f60\nname: acme.synthetic.chain\ntaxonomy: telltale\ncorrelation:\n    type: telltale_chain\n    categories: [execution]\ntelltale:\n    score: 5\n    explanation: \"VALUE\"\n",
            ),
            (
                "ignored document field",
                "description: Synthetic package rules.",
                "description: Synthetic package rules.\nignored: \"VALUE\"",
            ),
            (
                "tagged value",
                "description: Synthetic package rules.",
                "description: Synthetic package rules.\nignored: !synthetic \"VALUE\"",
            ),
            (
                "aliased value",
                "description: Synthetic package rules.",
                "description: &text \"VALUE\"\nignored: *text",
            ),
        ];
        for (escape, code_point) in [
            (r"\u202E", "U+202E"),
            (r"\U00002066", "U+2066"),
            (r"\u200B", "U+200B"),
            (r"\uFEFF", "U+FEFF"),
            (r"\x1b", "U+001B"),
            (r"\e", "U+001B"),
            (r"\0", "U+0000"),
            (r"\b", "U+0008"),
            (r"\r", "U+000D"),
            (r"\u0085", "U+0085"),
        ] {
            for (field, original, replacement) in fields {
                let marker = "PACKAGE_HIDDEN_SENTINEL";
                let raw = base.replace(
                    original,
                    &replacement.replace("VALUE", &format!("{marker}{escape}")),
                );
                let message = RulePackage::parse(&raw)
                    .err()
                    .unwrap_or_else(|| panic!("{field}: accepted forbidden {code_point}"))
                    .to_string();
                assert!(
                    message.contains(&format!("forbidden character {code_point}")),
                    "{field}: missing forbidden-character diagnostic for {code_point}"
                );
                assert!(
                    !message.contains(marker),
                    "{field}: diagnostic leaked content"
                );
            }
        }
    }

    #[test]
    fn decoded_multiline_content_and_literal_regex_escapes_remain_valid() {
        let raw = package("acme.rules", "acme", "acme.synthetic.marker")
            .replace(
                "publisher: Synthetic publisher",
                r#"publisher: "Caf\u00E9""#,
            )
            .replace(
                "rule_namespace: acme",
                "rule_namespace: acme\nrevision: 12345",
            )
            .replace(
                "description: Synthetic package rules.",
                "description: |\n    First line.\n    Second line.",
            )
            .replace(
                "explanation: Synthetic package rule.",
                r#"explanation: "First line.\nSecond\tline.""#,
            )
            .replace("'synthetic-package-marker'", r"'\u202E|\x1b'");
        let parsed = RulePackage::parse(&raw).expect("visible escapes and multiline rule content");
        assert_eq!(parsed.publisher(), "Café");
        assert_eq!(parsed.revision(), Some("12345"));
        let rule = &parsed.documents()[0].definitions()[0];
        assert_eq!(rule.explanation(), "First line.\nSecond\tline.");
        let CompiledDefinition::Rule(compiled) = rule.compile() else {
            panic!("a rule");
        };
        assert_eq!(compiled.matchers[0].regex, r"(?i:\u202E|\x1b)");
    }

    #[test]
    fn malformed_headers_are_rejected() {
        let raw = package("acme.rules", "acme", "acme.synthetic.marker");
        assert!(
            error(&raw.replace("telltale-rule-package/v2", "telltale-rule-package/v3"))
                .contains("unsupported rule package format")
        );
        assert!(
            error(&raw.replace("id: acme.rules", "id: Acme.Rules"))
                .contains("rule package id must be")
        );
        assert!(
            error(&raw.replace("version: 1.2.3", "version: '1 2'")).contains("version must be")
        );
        assert!(
            error(&raw.replace("license: Apache-2.0", "license: ''")).contains("license must be")
        );
        assert!(
            error(&raw.replace(
                "license: Apache-2.0\n",
                "license: Apache-2.0\nunexpected: true\n"
            ))
            .contains("unknown field `unexpected`")
        );
    }

    #[test]
    fn duplicate_and_missing_definitions_are_rejected() {
        let raw = package("acme.rules", "acme", "acme.synthetic.marker");
        let duplicate = format!(
            "{raw}---\ntitle: Duplicate\nid: 6e1f7d5a-9b2c-4d3e-8f40-1b2c3d4e5f60\nname: acme.synthetic.marker\n\
             taxonomy: telltale\ncorrelation:\n    type: telltale_chain\n    rules: [acme.synthetic.marker]\n\
             telltale:\n    score: 5\n    explanation: Duplicate.\n"
        );
        assert!(
            error(&duplicate).contains("each name once"),
            "{}",
            error(&duplicate)
        );
        let empty = &raw[..raw.find("---\n").unwrap()];
        assert!(error(empty).contains("no rule or chain documents"));
    }

    fn v2_rule(name: &str, uuid: &str) -> String {
        v2_anchored_rule(name, uuid, "marker")
    }

    /// A rule whose two matchers share `pattern` through the anchor `&pattern`.
    fn v2_anchored_rule(name: &str, uuid: &str, pattern: &str) -> String {
        format!(
            "---\ntitle: Synthetic v2 rule\nid: {uuid}\nname: {name}\ntaxonomy: telltale\n\
             logsource:\n    product: ai_agent\n    category: tool_activity\n\
             detection:\n    selection:\n        - tool.command|re|i: &pattern '{pattern}'\n\
             \x20       - tool.arguments|re|i: *pattern\n    condition: selection\n\
             level: low\ntelltale:\n    category: execution\n    score: 20\n    explanation: Synthetic.\n"
        )
    }

    fn v2_chain(name: &str, uuid: &str) -> String {
        format!(
            "---\ntitle: Synthetic v2 chain\nid: {uuid}\nname: {name}\ntaxonomy: telltale\n\
             correlation:\n    type: telltale_chain\n    categories: [execution]\n\
             telltale:\n    score: 5\n    explanation: Synthetic chain.\n"
        )
    }

    const UUIDS: [&str; 3] = [
        "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        "9b2d6c8e-1f4a-4c3b-8d2e-5a6f7b8c9d0e",
        "0d0c4f7e-2a1b-4c3d-8e5f-6a7b8c9d0e1f",
    ];

    fn v2_package(documents: &str) -> String {
        format!(
            "format: telltale-rule-package/v2\nid: acme.rules\ntitle: Acme rules\nversion: 2.0.0\n\
             publisher: Synthetic publisher\nlicense: Apache-2.0\nrule_namespace: acme\n\
             source: https://example.invalid/acme\nrevision: abc123\n{documents}"
        )
    }

    #[test]
    fn v2_package_holds_sorted_rule_and_chain_documents() {
        let raw = v2_package(&format!(
            "{}{}",
            v2_chain("acme.chain", UUIDS[0]),
            v2_rule("acme.rule", UUIDS[1])
        ));
        let parsed = RulePackage::parse(&raw).expect("v2 package");
        assert_eq!(parsed.title(), "Acme rules");
        assert_eq!(parsed.revision(), Some("abc123"));
        assert_eq!(
            parsed.content_sha256(),
            hex::encode(Sha256::digest(raw.as_bytes()))
        );
        let definitions = parsed
            .documents()
            .iter()
            .flat_map(LoadedRules::definitions)
            .map(|definition| {
                (
                    definition.id(),
                    definition.kind(),
                    definition.uuid(),
                    definition.package_id(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            definitions,
            [
                (
                    "acme.chain",
                    crate::DefinitionKind::Modifier,
                    Some(UUIDS[0]),
                    Some("acme.rules")
                ),
                (
                    "acme.rule",
                    crate::DefinitionKind::Rule,
                    Some(UUIDS[1]),
                    Some("acme.rules")
                ),
            ]
        );
        let compiled = LoadedRules::merge(parsed.into_documents())
            .and_then(|rules| rules.compile(None))
            .unwrap();
        assert_eq!(compiled.rule_count(), 1);
        assert_eq!(compiled.compatibility_export().modifiers().len(), 1);
    }

    #[test]
    fn v2_package_rejects_missing_title_order_namespace_and_reused_uuids() {
        let rule = v2_rule("acme.rule", UUIDS[0]);
        let without_title = v2_package(&rule).replace("title: Acme rules\n", "");
        assert!(error(&without_title).contains("missing field `title`"));
        let unsorted = v2_package(&format!(
            "{}{}",
            v2_rule("acme.zeta", UUIDS[0]),
            v2_rule("acme.alpha", UUIDS[1])
        ));
        assert!(
            error(&unsorted).contains("sorted by name"),
            "{}",
            error(&unsorted)
        );
        let repeated = v2_package(&format!(
            "{}{}",
            v2_rule("acme.same", UUIDS[0]),
            v2_rule("acme.same", UUIDS[1])
        ));
        assert!(error(&repeated).contains("sorted by name"));
        let outside = v2_package(&v2_rule("other.rule", UUIDS[0]));
        assert!(error(&outside).contains("outside namespace 'acme'"));
        let reused = v2_package(&format!(
            "{}{}",
            v2_rule("acme.alpha", UUIDS[2]),
            v2_rule("acme.beta", UUIDS[2])
        ));
        assert!(
            error(&reused).contains("duplicate Rule v2 id"),
            "{}",
            error(&reused)
        );
        // Documents are numbered in the stream, the header being document 1.
        let v1_document = v2_package(&format!(
            "{}---\nversion: 1\ndescription: x\ndefaults: {{case_insensitive: false, enabled: true}}\nrules: []\nmodifiers: []\n",
            v2_rule("acme.alpha", UUIDS[0])
        ));
        assert_eq!(
            error(&v1_document),
            format!(
                "rule package 'acme.rules': document 3: {}",
                rule_v2::RULE_V1_UNSUPPORTED
            )
        );
        assert!(error(&v2_package("")).contains("no rule or chain documents"));
        let reserved = v2_package(&v2_rule("chain.rule", UUIDS[0]))
            .replace("rule_namespace: acme", "rule_namespace: chain");
        assert!(error(&reserved).contains("reserved for core rules"));
    }

    #[test]
    fn format_v1_packages_fail_with_a_pointer_to_rule_v2() {
        let v1 = "format: telltale-rule-package/v1\nid: acme.rules\nversion: 1.0.0\n\
                  publisher: Synthetic publisher\nlicense: Apache-2.0\nrule_namespace: acme\n\
                  documents:\n  - version: 1\n    description: x\n    defaults: {case_insensitive: true, enabled: true}\n\
                  \x20   rules: []\n    modifiers: []\n";
        assert_eq!(
            error(v1),
            "rule package format telltale-rule-package/v1 is no longer supported: its documents \
             are Rule v1; rebuild the package as telltale-rule-package/v2: see \
             docs/rule-format.md and docs/migrations/0.8.0.md"
        );
    }

    #[test]
    fn v2_header_is_the_first_document_and_has_closed_keys() {
        let rule = v2_rule("acme.rule", UUIDS[0]);
        // The v1 layout: rules under `documents` in the header.
        let listed = v2_package(&format!(
            "documents:\n{}",
            rule.trim_start_matches("---\n")
                .lines()
                .enumerate()
                .map(|(index, line)| format!(
                    "{}{line}\n",
                    if index == 0 { "  - " } else { "    " }
                ))
                .collect::<String>()
        ));
        let message = error(&listed);
        assert!(
            message.contains("has no `documents` key")
                && message.contains("its own `---` document after the header"),
            "{message}"
        );
        let message = error(&v2_package(&format!("unexpected: true\n{rule}")));
        assert!(message.contains("unknown field `unexpected`"), "{message}");
        assert!(!message.contains("`documents`"), "{message}");
        // A rule without its `---` merges into the header and fails there.
        let merged = v2_package(&rule.replacen("---\n", "", 1));
        let message = error(&merged);
        assert!(message.starts_with("invalid rule package: "), "{message}");
        // The header must come first.
        let message = error(&format!(
            "{}---\n{}",
            rule.trim_start_matches("---\n"),
            v2_package("").trim_end()
        ));
        assert!(
            message.contains("unsupported rule package format"),
            "{message}"
        );
        // A YAML-coerced header value reads as a string.
        let numeric =
            RulePackage::parse(&v2_package(&rule).replace("revision: abc123", "revision: 12345"))
                .expect("numeric revision");
        assert_eq!(numeric.revision(), Some("12345"));
    }

    #[test]
    fn v2_documents_keep_their_own_anchors() {
        let names = ["acme.alpha", "acme.beta", "acme.gamma"];
        let raw = v2_package(
            &names
                .iter()
                .zip(UUIDS)
                .map(|(name, uuid)| v2_anchored_rule(name, uuid, &format!("{name}-marker")))
                .collect::<String>(),
        );
        let expected = names
            .map(|name| {
                let regex = format!("(?i:{name}-marker)");
                (name.to_owned(), vec![regex.clone(), regex])
            })
            .to_vec();
        for raw in [raw.clone(), raw.replace('\n', "\r\n")] {
            let package = RulePackage::parse(&raw).expect("each rule defines its anchor once");
            let patterns = LoadedRules::merge(package.into_documents())
                .and_then(|rules| rules.compile(None))
                .unwrap()
                .compatibility_export()
                .rules()
                .iter()
                .map(|rule| {
                    let regexes = rule.matchers.iter().map(|m| m.regex.clone()).collect();
                    (rule.id.clone(), regexes)
                })
                .collect::<Vec<(String, Vec<String>)>>();
            assert_eq!(patterns, expected);
        }
    }

    #[test]
    fn v2_documents_reject_a_redefined_anchor() {
        let twice = v2_anchored_rule("acme.beta", UUIDS[1], "first").replace(
            "    condition: selection\n",
            "        - tool.written_path|re: &pattern 'second'\n        - tool.path|re: *pattern\n    condition: selection\n",
        );
        let raw = v2_package(&format!("{}{twice}", v2_rule("acme.alpha", UUIDS[0])));
        let expected = "rule package 'acme.rules': document 3: YAML anchor `&pattern` is defined \
                        more than once in this document; anchor names must be unique within a document";
        assert_eq!(error(&raw), expected);
        assert_eq!(error(&raw.replace('\n', "\r\n")), expected);
        // ` && ` and repeated but unaliased `&name` text are not anchors.
        let ampersands = v2_package(&v2_rule("acme.alpha", UUIDS[0]).replace(
            "    condition: selection\n",
            "        - tool.written_path|re: 'a && b&marker'\n        - tool.path|re: 'c && d&marker'\n    condition: selection\n",
        ));
        RulePackage::parse(&ampersands).expect("ampersands in patterns");
    }

    #[test]
    fn embedded_community_package_is_valid_and_namespaced() {
        let community = bundled_community_package().unwrap();
        assert_eq!(community.id(), COMMUNITY_PACKAGE_ID);
        assert_eq!(community.rule_namespace(), "tdx");
        assert_eq!(community.license(), "Apache-2.0");
        let mut rule_sets = vec![crate::bundled_default_rules().unwrap()];
        rule_sets.extend(community.into_documents());
        LoadedRules::merge(rule_sets)
            .and_then(|rules| rules.compile(None))
            .expect("community rules compile beside core");
    }

    #[test]
    fn supplied_community_package_replaces_the_embedded_snapshot() {
        let embedded = bundled_community_package().unwrap();
        let supplied = RulePackage::parse(
            &package(COMMUNITY_PACKAGE_ID, "tdx", "tdx.synthetic.marker")
                .replace("1.2.3", "99.0.0"),
        )
        .unwrap();
        let resolved = resolve_rule_packages(CommunityRules::Embedded, vec![supplied]).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].origin, PackageOrigin::Supplied(0));
        assert_eq!(resolved[0].package.version(), "99.0.0");
        assert_eq!(
            resolved[0].summary().replaced_embedded_version.as_deref(),
            Some(embedded.version())
        );
    }

    #[test]
    fn community_selection_controls_every_origin() {
        let community = RulePackage::parse(&package(
            COMMUNITY_PACKAGE_ID,
            "tdx",
            "tdx.synthetic.marker",
        ))
        .unwrap();
        let other =
            RulePackage::parse(&package("acme.rules", "acme", "acme.synthetic.marker")).unwrap();

        let embedded =
            resolve_rule_packages(CommunityRules::Embedded, vec![other.clone()]).unwrap();
        assert_eq!(
            embedded
                .iter()
                .map(|entry| entry.origin)
                .collect::<Vec<_>>(),
            [PackageOrigin::Embedded, PackageOrigin::Supplied(0)]
        );

        let supplied_only = resolve_rule_packages(
            CommunityRules::SuppliedOnly,
            vec![community.clone(), other.clone()],
        )
        .unwrap();
        assert_eq!(supplied_only.len(), 2);
        assert_eq!(supplied_only[0].replaced_embedded_version, None);

        let disabled =
            resolve_rule_packages(CommunityRules::Disabled, vec![community, other]).unwrap();
        assert_eq!(
            disabled
                .iter()
                .map(|entry| entry.package.id())
                .collect::<Vec<_>>(),
            ["acme.rules"]
        );
    }

    #[test]
    fn conflicting_package_ids_and_namespaces_fail() {
        let first =
            RulePackage::parse(&package("acme.rules", "acme", "acme.synthetic.marker")).unwrap();
        let older = RulePackage::parse(
            &package("acme.rules", "acme", "acme.synthetic.marker").replace("1.2.3", "1.0.0"),
        )
        .unwrap();
        let message =
            resolve_rule_packages(CommunityRules::Disabled, vec![first.clone(), older.clone()])
                .unwrap_err()
                .to_string();
        assert!(
            message.contains("duplicate rule package id 'acme.rules'"),
            "{message}"
        );
        for copy in [&first, &older] {
            let identity = format!(
                "version {} (content SHA-256 {}...)",
                copy.version(),
                &copy.content_sha256()[..12]
            );
            assert!(message.contains(&identity), "{message}");
        }

        let second =
            RulePackage::parse(&package("acme.extra", "acme", "acme.synthetic.other")).unwrap();
        let message = resolve_rule_packages(CommunityRules::Disabled, vec![first, second])
            .unwrap_err()
            .to_string();
        assert!(message.contains("both use namespace 'acme'"), "{message}");

        let fork =
            RulePackage::parse(&package("acme.fork", "tdx", "tdx.synthetic.marker")).unwrap();
        let message = resolve_rule_packages(CommunityRules::Embedded, vec![fork])
            .unwrap_err()
            .to_string();
        assert!(message.contains("both use namespace 'tdx'"), "{message}");
    }
}
