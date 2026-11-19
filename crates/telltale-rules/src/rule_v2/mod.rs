//! Rule v2: the Telltale Sigma profile, level 1.
//!
//! A Rule v2 file holds one or more YAML documents separated by `---`. Each
//! document is a Sigma 2.1 rule marked `taxonomy: telltale` (it has
//! `detection`), or a chain: a Sigma correlation document whose
//! `correlation.type` is the Telltale extension `telltale_chain`. Rules compile
//! into the same compiled rule Rule v1 produces and chains into the same
//! modifier, so the compatibility export, its fingerprint, and Detection v2
//! read both formats unchanged. The compiled id is the document's `name`; the
//! UUID `id` is the catalog key and never reaches the compiled form.
//!
//! The key sets are closed. Unknown top-level, `logsource`, `telltale` and
//! `correlation` keys are errors, and so is every Sigma construct level 1 does
//! not implement, by name: nothing is silently reinterpreted. Sigma `filter`
//! documents are not supported. `detection` is read in YAML mapping order,
//! because compiled matchers follow selection order.
//!
//! This front end shares only the compiled types and validators with Rule v1;
//! it never builds the Rule v1 document structs, which will be removed.

mod detection;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::error::Error;

use serde::Deserialize;
use serde_yaml::{Mapping, Value};

use crate::content::{DefinitionMetadata, RelatedRule, RuleLogSource};
use crate::{
    CompiledRule, ModifierLink, ModifierLinkOrder, RuleLoadNotice, RuleV1CompatibilityModifier,
    RuleV1CompatibilityRule, VALID_DETECTION_SEVERITIES, default_analytic_intent,
    default_chain_signal_type, default_detection_class, default_enabled, default_signal_type,
    package, validate_canonical_rule_id, validate_metadata_value, validate_modifier_link,
    validate_rule_metadata,
};

/// The only `taxonomy` a Rule v2 document may carry.
pub const RULE_V2_TAXONOMY: &str = "telltale";
/// The only `correlation.type` a Rule v2 chain may carry.
pub const RULE_V2_CHAIN_TYPE: &str = "telltale_chain";
/// The only `logsource.product` a Rule v2 rule may carry.
pub const RULE_V2_PRODUCT: &str = "ai_agent";

// Shared with the published vocabulary catalog, not a supported embedding API.
#[doc(hidden)]
pub use detection::{
    CONDITION_FORMS, FIELD_TARGETS, MAX_CONDITION_DEPTH, REGEX_FLAGS, REJECTED_MODIFIERS,
    SCOPE_MODIFIERS, VALUE_MODIFIERS,
};

/// `logsource.category` values, each fitting the fields a rule reads.
// Shared with the published vocabulary catalog, not a supported embedding API.
#[doc(hidden)]
pub const LOGSOURCE_CATEGORIES: &[&str] = &[TOOL_ACTIVITY, MESSAGE, AGENT_ACTIVITY];
/// Sigma statuses, in Sigma's order of maturity, then the two that load
/// disabled.
// Shared with the published vocabulary catalog, not a supported embedding API.
#[doc(hidden)]
pub const STATUSES: &[&str] = &[
    "experimental",
    "test",
    "stable",
    "deprecated",
    "unsupported",
];
/// Statuses whose rules and chains load disabled.
// Shared with the published vocabulary catalog, not a supported embedding API.
#[doc(hidden)]
pub const DISABLED_STATUSES: &[&str] = &["deprecated", "unsupported"];
/// Sigma `related` types.
// Shared with the published vocabulary catalog, not a supported embedding API.
#[doc(hidden)]
pub const RELATED_TYPES: &[&str] = &["derived", "obsolete", "merged", "renamed", "similar"];
/// Most characters of a one-line value such as `title` or a tag.
// Shared with the published vocabulary catalog, not a supported embedding API.
#[doc(hidden)]
pub const MAX_TITLE_CHARS: usize = 256;
/// Highest `telltale.score`.
// Shared with the published vocabulary catalog, not a supported embedding API.
#[doc(hidden)]
pub const MAX_SCORE: u64 = 100;

const DOCS: &str = "see docs/rule-format.md";
const TOOL_ACTIVITY: &str = "tool_activity";
const MESSAGE: &str = "message";
const AGENT_ACTIVITY: &str = "agent_activity";

/// What one rule file holds.
pub(crate) enum RuleFile {
    /// One Rule v1 document (it has `version`), read by the Rule v1 reader.
    V1,
    V2(Vec<Definition>),
}

/// One validated Rule v2 rule or chain, compiled whether or not it is enabled.
#[derive(Debug, Clone)]
pub(crate) struct Definition {
    pub(crate) enabled: bool,
    pub(crate) body: Body,
    pub(crate) notices: Vec<RuleLoadNotice>,
    /// Descriptive metadata for the catalog; it does not reach the compiled
    /// form.
    pub(crate) metadata: DefinitionMetadata,
}

#[derive(Debug, Clone)]
pub(crate) enum Body {
    Rule(CompiledRule),
    Chain(RuleV1CompatibilityModifier),
}

/// Read one rule file: every document must be a Rule v2 rule or chain, or the
/// file must hold exactly one Rule v1 document.
pub(crate) fn read_file(raw: &str) -> Result<RuleFile, Box<dyn Error>> {
    let documents = serde_yaml::Deserializer::from_str(raw)
        .map(Value::deserialize)
        .collect::<Result<Vec<_>, _>>()?;
    let is_v1 =
        |document: &Value| matches!(document, Value::Mapping(map) if map.contains_key("version"));
    match documents.as_slice() {
        [] => return Err("rule file holds no YAML documents".into()),
        [document] if is_v1(document) => return Ok(RuleFile::V1),
        documents if documents.iter().any(is_v1) => {
            return Err(
                "a Rule v1 document (`version`) must be the only document in its file".into(),
            );
        }
        _ => {}
    }
    package::reject_hidden_characters("rule file", raw)?;
    documents
        .into_iter()
        .enumerate()
        .map(|(index, document)| {
            read_document(document)
                .map_err(|error| format!("rule document {}: {error}", index + 1).into())
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()
        .map(RuleFile::V2)
}

pub(crate) fn read_document(document: Value) -> Result<Definition, Box<dyn Error>> {
    let Value::Mapping(map) = &document else {
        return Err(format!("a rule document must be a YAML mapping; {DOCS}").into());
    };
    reject_yaml_tags(&document)?;
    package::reject_decoded_hidden_characters_in("rule document decoded string", &document)?;
    if map.contains_key("filter") {
        return Err(format!("Sigma filter documents are not supported; {DOCS}").into());
    }
    let telltale = map.get("taxonomy").and_then(Value::as_str) == Some(RULE_V2_TAXONOMY);
    match (
        telltale,
        map.contains_key("detection"),
        map.contains_key("correlation"),
    ) {
        (true, true, false) => read_rule(serde_yaml::from_value(document)?),
        (true, false, true) => read_chain(serde_yaml::from_value(document)?),
        (true, true, true) => Err(
            "a document may hold `detection` (a rule) or `correlation` (a chain), not both".into(),
        ),
        (true, false, false) => Err(format!(
            "a `taxonomy: telltale` document needs `detection` (a rule) or `correlation` \
             (a chain); {DOCS}"
        )
        .into()),
        (false, true, _) | (false, _, true) => Err(format!(
            "a Sigma document must set `taxonomy: {RULE_V2_TAXONOMY}` to load in Telltale; {DOCS}"
        )
        .into()),
        (false, false, false) => Err(format!(
            "not a rule document: expected a Rule v2 rule or chain (`taxonomy: \
             {RULE_V2_TAXONOMY}` with `detection` or `correlation`); {DOCS}"
        )
        .into()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDocument {
    title: String,
    id: String,
    name: String,
    #[serde(default)]
    related: Vec<Related>,
    // Checked before deserialization.
    #[serde(rename = "taxonomy")]
    _taxonomy: String,
    #[serde(default)]
    status: Option<Status>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    date: Option<String>,
    #[serde(default)]
    modified: Option<String>,
    logsource: LogSource,
    detection: Mapping,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    scope: Vec<String>,
    #[serde(default)]
    falsepositives: Vec<String>,
    level: String,
    #[serde(default)]
    tags: Vec<String>,
    telltale: RuleExtension,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainDocument {
    title: String,
    id: String,
    name: String,
    #[serde(default)]
    related: Vec<Related>,
    // Checked before deserialization.
    #[serde(rename = "taxonomy")]
    _taxonomy: String,
    #[serde(default)]
    status: Option<Status>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    date: Option<String>,
    #[serde(default)]
    modified: Option<String>,
    correlation: Correlation,
    #[serde(default)]
    falsepositives: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    telltale: ChainExtension,
}

/// Metadata both document kinds share, checked the same way.
struct CommonMetadata<'a> {
    title: &'a str,
    id: &'a str,
    name: &'a str,
    related: &'a [Related],
    description: Option<&'a str>,
    license: Option<&'a str>,
    author: Option<&'a str>,
    references: &'a [String],
    date: Option<&'a str>,
    modified: Option<&'a str>,
    falsepositives: &'a [String],
    tags: &'a [String],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Related {
    id: String,
    #[serde(rename = "type")]
    kind: RelatedType,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RelatedType {
    Derived,
    Obsolete,
    Merged,
    Renamed,
    Similar,
}

impl RelatedType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Derived => "derived",
            Self::Obsolete => "obsolete",
            Self::Merged => "merged",
            Self::Renamed => "renamed",
            Self::Similar => "similar",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Experimental,
    Test,
    Stable,
    Deprecated,
    Unsupported,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Experimental => "experimental",
            Self::Test => "test",
            Self::Stable => "stable",
            Self::Deprecated => "deprecated",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogSource {
    product: String,
    category: String,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    definition: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleExtension {
    category: String,
    score: u64,
    explanation: String,
    #[serde(default = "default_analytic_intent")]
    analytic_intent: String,
    #[serde(default = "default_detection_class")]
    detection_class: String,
    #[serde(default = "default_signal_type")]
    signal_type: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainExtension {
    score: u64,
    explanation: String,
    #[serde(default = "default_analytic_intent")]
    analytic_intent: String,
    #[serde(default = "default_detection_class")]
    detection_class: String,
    #[serde(default = "default_chain_signal_type")]
    signal_type: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Correlation {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    categories: Option<Vec<String>>,
    #[serde(default)]
    rules: Option<Vec<String>>,
    #[serde(default)]
    within_calls: Option<u32>,
    #[serde(default)]
    order: Option<ChainOrder>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ChainOrder {
    Ordered,
    Any,
}

fn read_rule(document: RuleDocument) -> Result<Definition, Box<dyn Error>> {
    let atlas_tags = check_common(&CommonMetadata {
        title: &document.title,
        id: &document.id,
        name: &document.name,
        related: &document.related,
        description: document.description.as_deref(),
        license: document.license.as_deref(),
        author: document.author.as_deref(),
        references: &document.references,
        date: document.date.as_deref(),
        modified: document.modified.as_deref(),
        falsepositives: &document.falsepositives,
        tags: &document.tags,
    })?;
    let name = &document.name;
    let in_rule = |error: Box<dyn Error>| format!("rule '{name}': {error}");
    for (field, values) in [("fields", &document.fields), ("scope", &document.scope)] {
        for value in values {
            single_line(field, value, MAX_TITLE_CHARS).map_err(in_rule)?;
        }
    }
    let extension = &document.telltale;
    validate_metadata_value(name, "level", &document.level, &VALID_DETECTION_SEVERITIES)?;
    validate_rule_metadata(
        name,
        &extension.detection_class,
        &extension.signal_type,
        &extension.analytic_intent,
        &atlas_tags,
    )?;
    single_line("telltale.category", &extension.category, MAX_TITLE_CHARS).map_err(in_rule)?;
    check_score(extension.score).map_err(in_rule)?;
    non_empty("telltale.explanation", &extension.explanation).map_err(in_rule)?;
    for tag in &extension.tags {
        single_line("telltale.tags", tag, MAX_TITLE_CHARS).map_err(in_rule)?;
    }

    let lowered = detection::lower(name, &document.detection).map_err(in_rule)?;
    check_logsource(&document.logsource, lowered.uses_tool, lowered.uses_message)
        .map_err(in_rule)?;

    let metadata = DefinitionMetadata {
        uuid: Some(document.id.clone()),
        title: Some(document.title.clone()),
        status: document.status.map(|status| status.as_str().to_owned()),
        description: document.description.clone(),
        references: document.references,
        author: document.author,
        license: document.license,
        date: document.date,
        modified: document.modified,
        related: related_rules(&document.related),
        logsource: Some(RuleLogSource {
            product: document.logsource.product,
            category: document.logsource.category,
            service: document.logsource.service,
        }),
        tags: document.tags,
        falsepositives: document.falsepositives.clone(),
    };
    let rule = CompiledRule::new(
        RuleV1CompatibilityRule {
            id: document.name.clone(),
            title: Some(document.title),
            description: document.description,
            category: extension.category.clone(),
            detection_class: extension.detection_class.clone(),
            signal_type: extension.signal_type.clone(),
            analytic_intent: extension.analytic_intent.clone(),
            atlas_tags,
            severity: document.level,
            score: extension.score,
            tags: extension.tags.clone(),
            explanation: extension.explanation.clone(),
            falsepositives: document.falsepositives,
            matchers: Vec::new(),
        },
        lowered.matchers,
    );
    Ok(Definition {
        enabled: extension.enabled && loads_enabled(document.status),
        body: Body::Rule(rule),
        notices: lowered.notices,
        metadata,
    })
}

fn read_chain(document: ChainDocument) -> Result<Definition, Box<dyn Error>> {
    let atlas_tags = check_common(&CommonMetadata {
        title: &document.title,
        id: &document.id,
        name: &document.name,
        related: &document.related,
        description: document.description.as_deref(),
        license: document.license.as_deref(),
        author: document.author.as_deref(),
        references: &document.references,
        date: document.date.as_deref(),
        modified: document.modified.as_deref(),
        falsepositives: &document.falsepositives,
        tags: &document.tags,
    })?;
    let name = &document.name;
    let in_chain = |error: Box<dyn Error>| format!("chain '{name}': {error}");
    let extension = &document.telltale;
    validate_rule_metadata(
        name,
        &extension.detection_class,
        &extension.signal_type,
        &extension.analytic_intent,
        &atlas_tags,
    )?;
    check_score(extension.score).map_err(in_chain)?;
    non_empty("telltale.explanation", &extension.explanation).map_err(in_chain)?;

    let correlation = &document.correlation;
    if correlation.kind != RULE_V2_CHAIN_TYPE {
        return Err(in_chain(
            format!(
                "correlation type `{}` is not supported; Telltale chains use `{RULE_V2_CHAIN_TYPE}`",
                correlation.kind
            )
            .into(),
        )
        .into());
    }
    let (categories, rule_ids) = match (&correlation.categories, &correlation.rules) {
        (Some(categories), None) => {
            for category in categories {
                single_line("correlation.categories", category, MAX_TITLE_CHARS)
                    .map_err(in_chain)?;
            }
            (categories.clone(), Vec::new())
        }
        (None, Some(rules)) => {
            for rule in rules {
                validate_canonical_rule_id(rule, "chain rule reference")?;
            }
            (Vec::new(), rules.clone())
        }
        _ => {
            return Err(in_chain(
                "correlation needs exactly one of `categories` and `rules`".into(),
            )
            .into());
        }
    };
    if categories.is_empty() && rule_ids.is_empty() {
        return Err(
            in_chain("correlation `categories` or `rules` must not be empty".into()).into(),
        );
    }
    let link = match (correlation.within_calls, correlation.order) {
        (Some(calls), order) => Some(ModifierLink {
            calls,
            order: match order {
                None | Some(ChainOrder::Ordered) => ModifierLinkOrder::Declared,
                Some(ChainOrder::Any) => ModifierLinkOrder::Any,
            },
            minutes: None,
        }),
        (None, None) => None,
        (None, Some(_)) => {
            return Err(in_chain("correlation `order` needs `within_calls`".into()).into());
        }
    };
    validate_modifier_link(name, true, link)?;

    let metadata = DefinitionMetadata {
        uuid: Some(document.id.clone()),
        title: Some(document.title),
        status: document.status.map(|status| status.as_str().to_owned()),
        description: document.description,
        references: document.references,
        author: document.author,
        license: document.license,
        date: document.date,
        modified: document.modified,
        related: related_rules(&document.related),
        logsource: None,
        tags: document.tags,
        falsepositives: document.falsepositives.clone(),
    };
    let modifier = RuleV1CompatibilityModifier {
        id: document.name.clone(),
        score: extension.score,
        detection_class: extension.detection_class.clone(),
        signal_type: extension.signal_type.clone(),
        analytic_intent: extension.analytic_intent.clone(),
        atlas_tags,
        when_all_categories: categories,
        when_all_rule_ids: rule_ids,
        link,
        falsepositives: document.falsepositives,
        explanation: extension.explanation.clone(),
    };
    Ok(Definition {
        enabled: extension.enabled && loads_enabled(document.status),
        body: Body::Chain(modifier),
        notices: Vec::new(),
        metadata,
    })
}

fn related_rules(related: &[Related]) -> Vec<RelatedRule> {
    related
        .iter()
        .map(|related| RelatedRule {
            id: related.id.clone(),
            kind: related.kind.as_str().to_owned(),
        })
        .collect()
}

/// Check the metadata both kinds share and return the compiled ATLAS tags.
fn check_common(metadata: &CommonMetadata<'_>) -> Result<Vec<String>, Box<dyn Error>> {
    validate_canonical_rule_id(metadata.name, "rule name")?;
    let name = metadata.name;
    let context = |error: Box<dyn Error>| format!("'{name}': {error}");
    validate_uuid("id", metadata.id, true).map_err(context)?;
    single_line("title", metadata.title, MAX_TITLE_CHARS).map_err(context)?;
    for related in metadata.related {
        validate_uuid("related id", &related.id, false).map_err(context)?;
    }
    for (field, value) in [
        ("description", metadata.description),
        ("license", metadata.license),
        ("author", metadata.author),
    ] {
        if let Some(value) = value {
            plain_text(field, value).map_err(context)?;
        }
    }
    let mut seen = BTreeSet::new();
    for reference in metadata.references {
        validate_url(reference).map_err(context)?;
        if !seen.insert(reference) {
            return Err(context(format!("reference `{reference}` is listed twice").into()).into());
        }
    }
    for (field, value) in [("date", metadata.date), ("modified", metadata.modified)] {
        if let Some(value) = value {
            validate_date(field, value).map_err(context)?;
        }
    }
    for falsepositive in metadata.falsepositives {
        non_empty("falsepositives", falsepositive).map_err(context)?;
    }
    sigma_tags(metadata.tags).map_err(|error| context(error.into()).into())
}

fn loads_enabled(status: Option<Status>) -> bool {
    !matches!(status, Some(Status::Deprecated | Status::Unsupported))
}

fn check_score(score: u64) -> Result<(), Box<dyn Error>> {
    if score > MAX_SCORE {
        return Err(format!("telltale.score must be between 0 and {MAX_SCORE}").into());
    }
    Ok(())
}

fn check_logsource(
    logsource: &LogSource,
    uses_tool: bool,
    uses_message: bool,
) -> Result<(), Box<dyn Error>> {
    if logsource.product != RULE_V2_PRODUCT {
        return Err(format!("logsource.product must be `{RULE_V2_PRODUCT}`").into());
    }
    if logsource.service.is_some() {
        return Err("logsource.service is reserved for harness-specific rules".into());
    }
    if let Some(definition) = &logsource.definition {
        plain_text("logsource.definition", definition)?;
    }
    let expected = match (uses_tool, uses_message) {
        (true, false) => TOOL_ACTIVITY,
        (false, true) => MESSAGE,
        _ => AGENT_ACTIVITY,
    };
    if logsource.category != expected {
        return Err(format!(
            "logsource.category `{}` does not fit the fields used: `tool_activity` reads only \
             tool.* fields, `message` only message.* fields, `agent_activity` both; this rule \
             needs `{expected}`",
            logsource.category
        )
        .into());
    }
    Ok(())
}

/// Sigma tags: `attack.*` and other namespaces are catalog metadata; each
/// `atlas.<id>` becomes the compiled ATLAS tag `atlas:<ID>`.
fn sigma_tags(tags: &[String]) -> Result<Vec<String>, String> {
    let mut seen = BTreeSet::new();
    let mut atlas_tags = Vec::new();
    for tag in tags {
        let valid = tag.split_once('.').is_some_and(|(namespace, name)| {
            !namespace.is_empty()
                && !name.is_empty()
                && namespace
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
                && name.chars().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.')
                })
        });
        if !valid {
            return Err(format!(
                "tag `{tag}` is not a Sigma tag (`namespace.name`, lowercase a-z, 0-9, '_', '-' and '.')"
            ));
        }
        if !seen.insert(tag) {
            return Err(format!("tag `{tag}` is listed twice"));
        }
        if let Some(id) = tag.strip_prefix("atlas.") {
            atlas_tags.push(format!("atlas:{}", id.to_ascii_uppercase()));
        }
    }
    Ok(atlas_tags)
}

fn validate_uuid(field: &str, value: &str, version_4: bool) -> Result<(), Box<dyn Error>> {
    let bytes = value.as_bytes();
    let shaped = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        });
    let version_ok =
        !version_4 || (bytes[14] == b'4' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b'));
    if shaped && version_ok {
        Ok(())
    } else if version_4 {
        Err(format!(
            "`{field}` must be a lowercase UUIDv4, such as 3f2504e0-4f89-41d3-9a0c-0305e82c3301"
        )
        .into())
    } else {
        Err(format!("`{field}` must be a lowercase UUID").into())
    }
}

fn validate_date(field: &str, value: &str) -> Result<(), Box<dyn Error>> {
    let number = |range: std::ops::Range<usize>| {
        value
            .get(range)
            .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|digits| digits.parse::<u32>().ok())
    };
    let shaped = value.len() == 10 && value.as_bytes()[4] == b'-' && value.as_bytes()[7] == b'-';
    let valid = match (shaped, number(0..4), number(5..7), number(8..10)) {
        (true, Some(year), Some(month), Some(day)) => {
            let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
            let days = match month {
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                4 | 6 | 9 | 11 => 30,
                2 if leap => 29,
                2 => 28,
                _ => 0,
            };
            (1..=days).contains(&day)
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(format!("`{field}` must be a date written YYYY-MM-DD").into())
    }
}

fn validate_url(value: &str) -> Result<(), Box<dyn Error>> {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"));
    if rest.is_some_and(|rest| !rest.is_empty() && !rest.chars().any(char::is_whitespace)) {
        Ok(())
    } else {
        Err(format!("reference `{value}` must be an http or https URL").into())
    }
}

fn non_empty(field: &str, value: &str) -> Result<(), Box<dyn Error>> {
    if value.trim().is_empty() {
        return Err(format!("`{field}` must not be empty").into());
    }
    Ok(())
}

fn single_line(field: &str, value: &str, max_chars: usize) -> Result<(), Box<dyn Error>> {
    non_empty(field, value)?;
    if value.contains('\n') || value.chars().count() > max_chars {
        return Err(format!("`{field}` must be one line of at most {max_chars} characters").into());
    }
    Ok(())
}

/// Plain text: no links and no HTML or Markdown markup.
fn plain_text(field: &str, value: &str) -> Result<(), Box<dyn Error>> {
    non_empty(field, value)?;
    let tag = value.as_bytes().windows(2).any(|pair| {
        pair[0] == b'<' && (pair[1].is_ascii_alphabetic() || matches!(pair[1], b'/' | b'!' | b'?'))
    });
    if value.contains("://") || value.contains("](") || tag {
        return Err(format!(
            "`{field}` must be plain text without links or markup; put URLs in `references`"
        )
        .into());
    }
    Ok(())
}

/// YAML tags (`!name`) would reach the reader as tagged values Sigma does not
/// define.
fn reject_yaml_tags(value: &Value) -> Result<(), Box<dyn Error>> {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Tagged(tagged) => {
                return Err(format!("YAML tag `{}` is not supported", tagged.tag).into());
            }
            Value::Sequence(values) => pending.extend(values),
            Value::Mapping(values) => {
                for (key, value) in values {
                    pending.extend([key, value]);
                }
            }
            _ => {}
        }
    }
    Ok(())
}
