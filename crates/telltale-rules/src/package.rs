//! Rule packages: identified, versioned, namespaced Rule v1 content added to
//! the bundled core rules.
//!
//! A package is one YAML document. Its header names the package, its
//! publisher and license, and the namespace that every rule and modifier ID
//! must use; its `documents` are ordinary Rule v1 documents. Packages only add
//! definitions: loading one never replaces a bundled core rule or another
//! package's rule, and a package namespace may not reuse a core namespace.
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

use crate::{RuleSet, bundled_default_rule_set, validate_canonical_rule_id};

/// The only supported package format.
pub const RULE_PACKAGE_FORMAT: &str = "telltale-rule-package/v1";
/// Package ID of the community rules embedded in Telltale.
pub const COMMUNITY_PACKAGE_ID: &str = "telltale.community";
/// Upper bound on one package document, in bytes.
pub const MAX_RULE_PACKAGE_BYTES: usize = 4 * 1024 * 1024;

const COMMUNITY_PACKAGE_YAML: &str = include_str!("../data/community.package.yaml");
/// Namespaces reserved in addition to the namespaces of bundled core rules.
const RESERVED_NAMESPACES: &[&str] = &["procchain", "telltale"];
const MAX_IDENTIFIER_LEN: usize = 64;
const MAX_NAMESPACE_LEN: usize = 32;
const MAX_LABEL_LEN: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRulePackage {
    format: String,
    id: String,
    version: String,
    publisher: String,
    license: String,
    rule_namespace: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    revision: Option<String>,
    documents: Vec<RuleSet>,
}

/// A validated rule package.
#[derive(Debug, Clone)]
pub struct RulePackage {
    id: String,
    version: String,
    publisher: String,
    license: String,
    rule_namespace: String,
    source: Option<String>,
    revision: Option<String>,
    content_sha256: String,
    documents: Vec<RuleSet>,
}

impl RulePackage {
    /// Parse and validate one package document.
    ///
    /// Rejects unknown formats or header fields, malformed identities, hidden
    /// control or bidirectional-formatting characters in source text or decoded
    /// YAML strings,
    /// reserved or malformed namespaces, definition IDs outside the namespace,
    /// duplicate IDs, and packages without definitions. Rule content is
    /// compiled later, together with the rest of the effective rule set.
    pub fn parse(raw: &str) -> Result<Self, Box<dyn Error>> {
        if raw.len() > MAX_RULE_PACKAGE_BYTES {
            return Err(format!("rule package exceeds {MAX_RULE_PACKAGE_BYTES} bytes").into());
        }
        reject_hidden_characters(raw)?;
        reject_decoded_hidden_characters(raw)?;
        // Keep typed parsing on the source for YAML string coercion and error locations.
        let package = serde_yaml::from_str::<RawRulePackage>(raw)
            .map_err(|error| format!("invalid rule package: {error}"))?;
        if package.format != RULE_PACKAGE_FORMAT {
            return Err(
                format!("unsupported rule package format; expected {RULE_PACKAGE_FORMAT}").into(),
            );
        }
        validate_package_id(&package.id)?;
        let context = format!("rule package '{}'", package.id);
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
        validate_definitions(&package.rule_namespace, &package.documents)
            .map_err(|error| format!("{context}: {error}"))?;

        Ok(Self {
            id: package.id,
            version: package.version,
            publisher: package.publisher,
            license: package.license,
            rule_namespace: package.rule_namespace,
            source: package.source,
            revision: package.revision,
            content_sha256: format!("{:x}", Sha256::digest(raw.as_bytes())),
            documents: package.documents,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
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

    /// Every rule and modifier ID in this package starts with `<namespace>.`.
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

    pub fn documents(&self) -> &[RuleSet] {
        &self.documents
    }

    pub fn into_documents(self) -> Vec<RuleSet> {
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

fn reject_hidden_characters(raw: &str) -> Result<(), Box<dyn Error>> {
    // `lines()` drops CRLF endings, so any carriage return left is a lone one.
    for (line, text) in raw.lines().enumerate() {
        if let Some(character) = text
            .chars()
            .find(|character| is_hidden_character(*character))
        {
            return Err(format!(
                "rule package line {}: forbidden character U+{:04X}",
                line + 1,
                character as u32
            )
            .into());
        }
    }
    Ok(())
}

fn reject_decoded_hidden_characters(raw: &str) -> Result<(), Box<dyn Error>> {
    let value = serde_yaml::from_str::<Value>(raw)
        .map_err(|error| format!("invalid rule package: {error}"))?;
    let mut pending = vec![&value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(text) => {
                if let Some(character) = text
                    .chars()
                    .find(|character| is_hidden_character(*character))
                {
                    return Err(format!(
                        "rule package decoded string: forbidden character U+{:04X}",
                        character as u32
                    )
                    .into());
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
    let core = bundled_default_rule_set()?;
    Ok(core
        .rules
        .iter()
        .map(|rule| rule.id.as_str())
        .chain(core.modifiers.iter().map(|modifier| modifier.id.as_str()))
        .filter_map(|id| id.split('.').next())
        .map(str::to_owned)
        .collect())
}

fn validate_definitions(namespace: &str, documents: &[RuleSet]) -> Result<(), Box<dyn Error>> {
    let prefix = format!("{namespace}.");
    let mut ids = BTreeSet::new();
    for document in documents {
        document.validate_version()?;
        let definitions = document
            .rules
            .iter()
            .map(|rule| (rule.id.as_str(), "rule"))
            .chain(
                document
                    .modifiers
                    .iter()
                    .map(|modifier| (modifier.id.as_str(), "modifier")),
            );
        for (id, kind) in definitions {
            validate_canonical_rule_id(id, kind)?;
            if !id.starts_with(&prefix) {
                return Err(format!("{kind} id '{id}' is outside namespace '{namespace}'").into());
            }
            if !ids.insert(id) {
                return Err(format!("duplicate {kind} id '{id}'").into());
            }
        }
    }
    if ids.is_empty() {
        return Err("rule package contains no rule or modifier definitions".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(id: &str, namespace: &str, rule_id: &str) -> String {
        format!(
            r#"format: telltale-rule-package/v1
id: {id}
version: 1.2.3
publisher: Synthetic publisher
license: Apache-2.0
rule_namespace: {namespace}
documents:
  - version: 1
    description: Synthetic package rules.
    defaults:
      case_insensitive: true
      enabled: true
    rules:
      - id: {rule_id}
        category: execution
        severity: low
        score: 20
        targets: [command]
        regex: 'synthetic-package-marker'
        tags: [synthetic]
        explanation: Synthetic package rule.
    modifiers: []
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
            format!("{:x}", Sha256::digest(raw.as_bytes()))
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
                &format!("explanation: Synthetic package rule.{separator}        enabled: false"),
            );
            let message = error(&raw);
            let expected = format!("forbidden character U+{:04X}", separator as u32);
            assert!(message.contains(&expected), "{message}");
            assert!(message.contains("line 21"), "{message}");
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
            "description: |\n      First line.\n      Second line.",
        );
        let crlf = RulePackage::parse(&lf.replace('\n', "\r\n")).expect("CRLF package");
        let lf = RulePackage::parse(&lf).unwrap();
        assert_eq!(
            format!("{:?}", crlf.documents()),
            format!("{:?}", lf.documents())
        );
        assert_eq!(
            crlf.documents()[0].description,
            "First line.\nSecond line.\n"
        );
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
            ("source", "documents:", "source: \"VALUE\"\ndocuments:"),
            ("revision", "documents:", "revision: \"VALUE\"\ndocuments:"),
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
            (
                "regex",
                "regex: 'synthetic-package-marker'",
                "regex: \"VALUE\"",
            ),
            ("tags", "tags: [synthetic]", "tags: [\"VALUE\"]"),
            (
                "selection value",
                "regex: 'synthetic-package-marker'",
                "detection:\n          selection: {command: \"VALUE\"}",
            ),
            (
                "selection key",
                "regex: 'synthetic-package-marker'",
                "detection:\n          selection: {\"VALUE\": marker}",
            ),
            (
                "modifier explanation",
                "modifiers: []",
                "modifiers:\n      - id: acme.synthetic.chain\n        score: 5\n        explanation: \"VALUE\"",
            ),
            (
                "ignored document field",
                "description: Synthetic package rules.",
                "description: Synthetic package rules.\n    ignored: \"VALUE\"",
            ),
            (
                "tagged value",
                "description: Synthetic package rules.",
                "description: Synthetic package rules.\n    ignored: !synthetic \"VALUE\"",
            ),
            (
                "aliased value",
                "description: Synthetic package rules.",
                "description: &text \"VALUE\"\n    ignored: *text",
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
                "description: |\n      First line.\n      Second line.",
            )
            .replace(
                "explanation: Synthetic package rule.",
                r#"explanation: "First line.\nSecond\tline.""#,
            )
            .replace("regex: 'synthetic-package-marker'", r"regex: '\u202E|\x1b'");
        let parsed = RulePackage::parse(&raw).expect("visible escapes and multiline rule content");
        assert_eq!(parsed.publisher(), "Café");
        assert_eq!(parsed.revision(), Some("12345"));
        let document = &parsed.documents()[0];
        assert_eq!(document.description, "First line.\nSecond line.\n");
        assert_eq!(document.rules[0].explanation, "First line.\nSecond\tline.");
        assert_eq!(document.rules[0].regex.as_deref(), Some(r"\u202E|\x1b"));
        crate::compile_rule_sets(parsed.into_documents(), None).expect("regex escapes compile");
    }

    #[test]
    fn malformed_headers_are_rejected() {
        let raw = package("acme.rules", "acme", "acme.synthetic.marker");
        assert!(
            error(&raw.replace("telltale-rule-package/v1", "telltale-rule-package/v2"))
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
        assert!(error(&format!("{raw}unexpected: true\n")).contains("unknown field"));
    }

    #[test]
    fn duplicate_and_missing_definitions_are_rejected() {
        let raw = package("acme.rules", "acme", "acme.synthetic.marker");
        let duplicate = raw.replace(
            "    modifiers: []\n",
            "    modifiers:\n      - id: acme.synthetic.marker\n        score: 5\n        when_all_rule_ids: [acme.synthetic.marker]\n        explanation: Duplicate.\n",
        );
        assert!(error(&duplicate).contains("duplicate modifier id"));
        let start = raw.find("documents:").unwrap();
        let empty = format!("{}documents: []\n", &raw[..start]);
        assert!(error(&empty).contains("no rule or modifier definitions"));
    }

    #[test]
    fn embedded_community_package_is_valid_and_namespaced() {
        let community = bundled_community_package().unwrap();
        assert_eq!(community.id(), COMMUNITY_PACKAGE_ID);
        assert_eq!(community.rule_namespace(), "tdx");
        assert_eq!(community.license(), "Apache-2.0");
        let mut rule_sets = vec![bundled_default_rule_set().unwrap()];
        rule_sets.extend(community.into_documents());
        crate::compile_rule_sets(rule_sets, None).expect("community rules compile beside core");
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
