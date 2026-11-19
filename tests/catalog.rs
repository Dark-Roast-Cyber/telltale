//! Machine-readable catalog of source identities and Rule v2 vocabulary, and the
//! rule examples in the public docs.
//!
//! `docs/catalog/*.json` is generated from the built-in source registry and the
//! Rule v2 reader. These tests fail when the committed files drift from the
//! code, or when the source tables in the owning docs name a different set of
//! source identities than the registry. Rule examples are checked against the
//! owning docs here, outside the crate package boundaries: every YAML rule,
//! chain, package and fragment in the rule docs loads (or fails, or reports a
//! notice, as its marker says). Regenerate with
//! `TELLTALE_UPDATE_CATALOG=1 cargo test --locked --test catalog`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};
use serde_yaml::{Mapping, Value as Yaml};
use telltale_rules::package::{MAX_RULE_PACKAGE_BYTES, RULE_PACKAGE_FORMAT_V2, RulePackage};
use telltale_rules::rule_v2::{
    CONDITION_FORMS, DISABLED_STATUSES, FIELD_TARGETS, LOGSOURCE_CATEGORIES, MAX_CONDITION_DEPTH,
    MAX_SCORE, MAX_TITLE_CHARS, REGEX_FLAGS, REJECTED_MODIFIERS, RELATED_TYPES, RULE_V2_CHAIN_TYPE,
    RULE_V2_PRODUCT, RULE_V2_TAXONOMY, SCOPE_MODIFIERS, STATUSES, VALUE_MODIFIERS,
};
use telltale_rules::{
    LoadedRules, MAX_MODIFIER_LINK_CALLS, MAX_PATTERN_BYTES, SEGMENT_SCOPE_TARGETS,
    load_rule_set_from_documents,
};
use telltale_schema::event::{
    VALID_ANALYTIC_INTENTS, VALID_DETECTION_CLASSES, VALID_DETECTION_SEVERITIES, VALID_SEVERITIES,
    VALID_SIGNAL_TYPES,
};
use telltale_schema::scoring::is_canonical_contribution_id;
use telltale_sources::clients::{PathRoot, SourcePattern, supported_clients};

const UPDATE_ENV: &str = "TELLTALE_UPDATE_CATALOG";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// Compares generated JSON with the committed catalog file, or rewrites it.
fn check_catalog(relative: &str, generated: &Value) {
    let path = repo_path(relative);
    let text = serde_json::to_string_pretty(generated).expect("catalog JSON") + "\n";
    if std::env::var_os(UPDATE_ENV).is_some() {
        fs::create_dir_all(path.parent().expect("catalog directory")).expect("catalog directory");
        fs::write(&path, text).expect("write catalog");
        return;
    }
    let committed = fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == text,
        "{relative} is stale; regenerate with {UPDATE_ENV}=1 cargo test --locked --test catalog"
    );
}

fn root_name(root: PathRoot) -> &'static str {
    match root {
        PathRoot::CodexHome => "codex_home",
        PathRoot::Home => "home",
        PathRoot::DataHome => "data_home",
        PathRoot::ProjectLocal => "project_local",
        other => panic!("describe path root {other:?} in tests/catalog.rs"),
    }
}

fn pattern_json(pattern: SourcePattern) -> Value {
    match pattern {
        SourcePattern::Extension(value) => json!({"extension": value}),
        SourcePattern::ExactFile(value) => json!({"exact_file": value}),
        SourcePattern::FileNameContains(value) => json!({"file_name_contains": value}),
        other => panic!("describe source pattern {other:?} in tests/catalog.rs"),
    }
}

fn sources_catalog() -> Value {
    let sources = supported_clients()
        .iter()
        .flat_map(|client| {
            client.sources.iter().map(move |source| {
                json!({
                    "client": client.id.as_str(),
                    "client_display_name": client.display_name,
                    "source_id": source.id,
                    "kind": source.kind.as_str(),
                    "root": root_name(source.root),
                    "relative_path": source.relative_path,
                    "pattern": pattern_json(source.pattern),
                    "recursive": source.recursive,
                    "project_relative_path": source.project_relative_path,
                    "fixture_relative_path": source.fixture_relative_path,
                })
            })
        })
        .collect::<Vec<_>>();
    json!({
        "generated_by": "tests/catalog.rs",
        "source_of_truth": "crates/telltale-sources/src/sources/registry.rs",
        "hand_maintained": "path_roots and source_specific_discovery are written by hand from crates/telltale-discover/src/discovery.rs, not generated; tests/upstream_formats discover cases check the behavior where a case exists.",
        "path_roots": {
            "home": "Explicit --root, else $HOME, else %USERPROFILE%.",
            "codex_home": "Explicit --root joined with .codex, else $CODEX_HOME, else <home>/.codex.",
            "data_home": "Explicit --root joined with the platform data path; else Linux $XDG_DATA_HOME or <home>/.local/share, macOS <home>/Library/Application Support, Windows %LOCALAPPDATA% then %APPDATA% then <home>/AppData/Local.",
            "project_local": "Configured project roots, else <home>/github and <home>/projects when present; project_relative_path is searched below each project.",
        },
        "source_specific_discovery": {
            "claude.projects": "Environment-resolved discovery (--root .) also searches $CLAUDE_CONFIG_DIR/projects; an explicit --root ignores it.",
            "copilot.process_log": "Project-local logs/copilot only. Upstream ~/.copilot/logs and $COPILOT_HOME/logs are not discovered: the current default-level process-log format is unqualified; see the Copilot upstream format known-gap cases.",
            "opencode.sqlite": "Environment-resolved host discovery (--root .) retains default databases and adds $XDG_DATA_HOME/opencode or <home>/.local/share/opencode on every platform. Direct-child opencode-<channel>.db names use a nonempty ASCII alphanumeric/dot/underscore/hyphen channel; environment-resolved default files and directory components reject symlinks. OPENCODE_DB adds one exact file, absolute or relative to that XDG directory, without parent enumeration or symlink components; empty and :memory: add no file. Non-dot roots and fixtures retain exact opencode.db matching; explicit roots also accept <root>/opencode/opencode.db, and Windows retains <home>/.local/share.",
        },
        "sources": sources,
    })
}

/// The keys a `deny_unknown_fields` reader accepts, read back from its own
/// unknown-field error so the list cannot drift.
fn accepted_keys(error: &str) -> Vec<String> {
    let expected = error
        .split_once("expected one of ")
        .unwrap_or_else(|| panic!("unexpected serde error shape: {error}"))
        .1;
    let keys = expected
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(!keys.is_empty(), "no keys parsed from: {error}");
    keys
}

const PROBE_KEY: &str = "telltale_catalog_probe";

const PROBE_RULE: &str = "title: Vocabulary probe
id: 3f2504e0-4f89-41d3-9a0c-0305e82c3301
name: probe.rule
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        tool.command: x
    condition: selection
level: low
telltale:
    category: probe
    score: 1
    explanation: Probe.
";

const PROBE_CHAIN: &str = "title: Vocabulary probe chain
id: 9b2d6c8e-1f4a-4c3b-8d2e-5a6f7b8c9d0e
name: probe.chain
taxonomy: telltale
correlation:
    type: telltale_chain
    categories: [probe]
telltale:
    score: 1
    explanation: Probe.
";

fn yaml_map(raw: &str) -> Mapping {
    match serde_yaml::from_str(raw).expect("probe YAML") {
        Yaml::Mapping(map) => map,
        other => panic!("probe is not a mapping: {other:?}"),
    }
}

/// `document` with `edit` applied to the mapping at `path` (empty: the top).
fn edited(document: &Mapping, path: &[&str], edit: impl FnOnce(&mut Mapping)) -> String {
    let mut document = document.clone();
    let mut map = &mut document;
    for key in path {
        map = map
            .get_mut(*key)
            .and_then(Yaml::as_mapping_mut)
            .unwrap_or_else(|| panic!("probe has no mapping `{key}`"));
    }
    edit(map);
    serde_yaml::to_string(&document).expect("probe YAML")
}

/// Accepted keys at `path` of a probe, and those whose removal stops it from
/// loading.
fn probed_keys(document: &str, path: &[&str], load: impl Fn(&str) -> Result<(), String>) -> Value {
    let document = yaml_map(document);
    load(&serde_yaml::to_string(&document).unwrap()).expect("the probe loads");
    let unknown = edited(&document, path, |map| {
        map.insert(PROBE_KEY.into(), 1.into());
    });
    let accepted = accepted_keys(&load(&unknown).expect_err("an unknown key is rejected"));
    let mut present = document.clone();
    for key in path {
        present = present[*key].as_mapping().unwrap().clone();
    }
    let required = accepted
        .iter()
        .filter(|key| present.contains_key(key.as_str()))
        .filter(|key| {
            load(&edited(&document, path, |map| {
                map.remove(key.as_str());
            }))
            .is_err()
        })
        .cloned()
        .collect::<Vec<_>>();
    json!({"accepted": accepted, "required": required})
}

fn load_rules(raw: &str) -> Result<(), String> {
    load_rule_set_from_documents(&[raw], None)
        .map(drop)
        .map_err(|error| error.to_string())
}

/// The header document of a probe package.
fn probe_package_header() -> String {
    format!(
        "format: {RULE_PACKAGE_FORMAT_V2}\nid: probe.package\ntitle: Probe\nversion: '1.0.0'\n\
         publisher: Probe\nlicense: Apache-2.0\nrule_namespace: probe\n"
    )
}

/// Load a package of `header` followed by the probe rule as its own document.
fn load_probe_package(header: &str) -> Result<(), String> {
    RulePackage::parse(&format!("{header}---\n{PROBE_RULE}"))
        .map(drop)
        .map_err(|error| error.to_string())
}

/// What each field reads, written by hand; the test checks it names exactly
/// the reader's fields.
const FIELD_READS: &[(&str, &str)] = &[
    (
        "tool.command",
        "The command a shell tool call requested, as parsed from the call.",
    ),
    (
        "tool.arguments",
        "The raw arguments text of a tool call; absent where a source records only structured arguments.",
    ),
    (
        "tool.written_path",
        "The path a file-writing tool call requested.",
    ),
    (
        "tool.path",
        "A file path named by a tool call; its meaning depends on the source.",
    ),
    ("tool.name", "The tool name the source reported."),
    (
        "tool.kind",
        "What a call does, derived from known built-in tool names: shell, file_read, file_write, web, delegate or other.",
    ),
    ("tool.url", "The URL-keyed string arguments of a tool call."),
    ("tool.result", "The tool result text the source reported."),
    ("message.assistant_text", "Assistant message text."),
    ("message.user_text", "User message text."),
];

fn rule_vocabulary_catalog() -> Value {
    assert_eq!(
        FIELD_READS
            .iter()
            .map(|(field, _)| *field)
            .collect::<Vec<_>>(),
        FIELD_TARGETS
            .iter()
            .map(|(field, _)| *field)
            .collect::<Vec<_>>(),
        "FIELD_READS in tests/catalog.rs must describe exactly the Rule v2 fields"
    );
    let fields = FIELD_TARGETS
        .iter()
        .zip(FIELD_READS)
        .map(|((field, target), (_, reads))| {
            json!({
                "field": field,
                "reads": reads,
                "evidence_field": target,
                "scope_modifiers": SEGMENT_SCOPE_TARGETS.contains(target),
            })
        })
        .collect::<Vec<_>>();
    let scope_fields = FIELD_TARGETS
        .iter()
        .filter(|(_, target)| SEGMENT_SCOPE_TARGETS.contains(target))
        .map(|(field, _)| *field)
        .collect::<Vec<_>>();

    let defaults = load_rule_set_from_documents(&[PROBE_RULE, PROBE_CHAIN], None)
        .expect("probes load")
        .compatibility_export();
    let (rule, chain) = (&defaults.rules()[0], &defaults.modifiers()[0]);

    let mut correlation = probed_keys(PROBE_CHAIN, &["correlation"], load_rules);
    // `categories` and `rules` are exactly one of a pair, not each required.
    let exactly_one_of = ["categories", "rules"];
    for key in exactly_one_of {
        let only = edited(&yaml_map(PROBE_CHAIN), &["correlation"], |map| {
            map.remove("categories");
            map.insert(key.into(), Yaml::Sequence(vec!["probe.rule".into()]));
        });
        load_rules(&only).unwrap_or_else(|error| panic!("{key} alone: {error}"));
    }
    correlation["required"] = json!(
        correlation["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|key| !exactly_one_of.contains(&key.as_str().unwrap()))
            .collect::<Vec<_>>()
    );
    correlation["exactly_one_of"] = json!(exactly_one_of);

    // `service` deserializes but is reserved: a rule that sets it fails.
    let with_service = edited(&yaml_map(PROBE_RULE), &["logsource"], |map| {
        map.insert("service".into(), "probe".into());
    });
    assert!(
        load_rules(&with_service).is_err(),
        "logsource.service is rejected"
    );

    let name_limit = (3..=512)
        .take_while(|length| is_canonical_contribution_id(&format!("a.{}", "b".repeat(length - 2))))
        .last()
        .expect("a name length");

    json!({
        "generated_by": "tests/catalog.rs",
        "source_of_truth": [
            "crates/telltale-rules/src/rule_v2/mod.rs",
            "crates/telltale-rules/src/rule_v2/detection.rs",
            "crates/telltale-rules/src/package.rs",
            "crates/telltale-rules/src/lib.rs",
            "crates/telltale-schema/src/event/mod.rs",
        ],
        "hand_maintained": "fields[].reads, condition_forms[].meaning and tags describe behavior in prose; docs/rule-format.md owns the full description.",
        "format": "Rule v2, the Telltale Sigma profile, level 1",
        "taxonomy": RULE_V2_TAXONOMY,
        "rule_keys": probed_keys(PROBE_RULE, &[], load_rules),
        "chain_keys": probed_keys(PROBE_CHAIN, &[], load_rules),
        "logsource": {
            "keys": probed_keys(PROBE_RULE, &["logsource"], load_rules),
            "product": RULE_V2_PRODUCT,
            "categories": LOGSOURCE_CATEGORIES,
            "reserved_keys": ["service"],
        },
        "fields": fields,
        "value_modifiers": VALUE_MODIFIERS,
        "regex_flags": REGEX_FLAGS,
        "scope_modifiers": {
            "values": SCOPE_MODIFIERS,
            "default": "field",
            "fields": scope_fields,
        },
        "rejected_modifiers": REJECTED_MODIFIERS,
        "condition_forms": CONDITION_FORMS
            .iter()
            .map(|(form, meaning)| json!({"form": form, "meaning": meaning}))
            .collect::<Vec<_>>(),
        "filter_identifiers": ["filter", "filter_*"],
        "statuses": {
            "values": STATUSES,
            "load_disabled": DISABLED_STATUSES,
        },
        "related_types": RELATED_TYPES,
        "levels": {
            "values": VALID_DETECTION_SEVERITIES,
            "event3_global_values": VALID_SEVERITIES,
        },
        "telltale_rule_keys": probed_keys(PROBE_RULE, &["telltale"], load_rules),
        "telltale_chain_keys": probed_keys(PROBE_CHAIN, &["telltale"], load_rules),
        "telltale_defaults": {
            "analytic_intent": rule.analytic_intent,
            "detection_class": rule.detection_class,
            "rule_signal_type": rule.signal_type,
            "chain_signal_type": chain.signal_type,
            "enabled": true,
        },
        "analytic_intents": VALID_ANALYTIC_INTENTS,
        "detection_classes": VALID_DETECTION_CLASSES,
        "signal_types": VALID_SIGNAL_TYPES,
        "correlation": {
            "type": RULE_V2_CHAIN_TYPE,
            "keys": correlation,
            "orders": ["ordered", "any"],
            "default_order": "ordered",
        },
        "tags": {
            "atlas": "atlas.<id> compiles to the ATLAS tag atlas:<ID>",
            "attack_technique": "attack.tNNNN or attack.tNNNN.NNN lists technique TNNNN[.NNN] in the catalog",
            "telltale_labels": "free-form labels go in telltale.tags",
        },
        "package": {
            "format": RULE_PACKAGE_FORMAT_V2,
            "layout": "A YAML stream: the header document first, then each Rule v2 rule or chain as its own `---` document, sorted by name.",
            "header_keys": probed_keys(&probe_package_header(), &[], load_probe_package),
        },
        "limits": {
            "max_pattern_bytes": MAX_PATTERN_BYTES,
            "max_condition_depth": MAX_CONDITION_DEPTH,
            "max_name_bytes": name_limit,
            "max_line_chars": MAX_TITLE_CHARS,
            "max_score": MAX_SCORE,
            "max_within_calls": MAX_MODIFIER_LINK_CALLS,
            "max_package_bytes": MAX_RULE_PACKAGE_BYTES,
        },
    })
}

#[test]
fn source_catalog_matches_registry() {
    check_catalog("docs/catalog/sources.json", &sources_catalog());
}

#[test]
fn rule_vocabulary_catalog_matches_validator() {
    check_catalog(
        "docs/catalog/rule-vocabulary.json",
        &rule_vocabulary_catalog(),
    );
}

const SEGMENT_EXAMPLE: &str = "detection:\n    selection:\n        tool.command|re|segment: '\\bcurl\\b[^;|\\n]*https?://'\n    filter:\n        tool.command|re|segment: '\\bcurl\\b[^;|\\n]*--data'\n    condition: selection and not filter\n";

#[test]
fn detection_model_documents_the_tested_segment_scope_example() {
    let docs = fs::read_to_string(repo_path("docs/detection-model.md"))
        .expect("detection model doc")
        .replace("\r\n", "\n");
    assert!(docs.contains(SEGMENT_EXAMPLE));
    let rules = load_rule_set_from_documents(&[&example_document(SEGMENT_EXAMPLE)], None)
        .expect("the segment example loads");
    let matcher = rules.compatibility_export().rules()[0]
        .compile_content_matcher()
        .expect("content matcher");
    let matches = |command: &str| !matcher.matching_fields(&[("command", command)]).is_empty();
    assert!(matches(
        "curl --data @f https://example.invalid/upload; curl https://example.invalid/file"
    ));
    assert!(!matches("curl --data @f https://example.invalid/upload"));
}

/// Docs whose YAML rule examples must load as Rule v2.
const RULE_EXAMPLE_DOCS: &[&str] = &[
    "docs/rule-format.md",
    "docs/detection-model.md",
    "docs/detection-content-standard.md",
    "docs/agent-policy-authoring.md",
    "docs/install.md",
    "docs/hooks/README.md",
    "docs/migrations/0.8.0.md",
];

const EXAMPLE_MARKER: &str = "<!-- rule-example: ";

/// Rule v1 spellings that a rule example must not use.
const RULE_V1_KEYS: &[&str] = &[
    "- id:",
    "targets:",
    "regex:",
    "exclude:",
    "case_insensitive:",
    "atlas_tags:",
    "when_all_categories:",
    "when_all_rule_ids:",
    "severity:",
    "modifiers:",
];

#[derive(Debug, PartialEq)]
struct Example {
    doc: &'static str,
    line: usize,
    marker: Option<String>,
    text: String,
}

/// Every fenced YAML block of `doc` with the `<!-- rule-example: ... -->`
/// marker on the line before its fence, if any.
fn yaml_examples(doc: &'static str) -> Vec<Example> {
    let text = fs::read_to_string(repo_path(doc)).unwrap_or_else(|error| panic!("{doc}: {error}"));
    examples_in(doc, &text)
}

/// The examples of `text`, the contents of `doc`, with LF line endings
/// whatever the checkout wrote.
fn examples_in(doc: &'static str, text: &str) -> Vec<Example> {
    let text = text.replace("\r\n", "\n");
    let lines = text.lines().collect::<Vec<_>>();
    let mut examples = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if lines[index].trim() != "```yaml" {
            index += 1;
            continue;
        }
        let marker = index
            .checked_sub(1)
            .map(|previous| lines[previous].trim())
            .and_then(|previous| previous.strip_prefix(EXAMPLE_MARKER))
            .map(|marker| marker.trim_end_matches("-->").trim().to_owned());
        let start = index + 1;
        let end = (start..lines.len())
            .find(|line| lines[*line].trim() == "```")
            .unwrap_or_else(|| panic!("{doc}:{}: unclosed YAML block", index + 1));
        examples.push(Example {
            doc,
            line: index + 1,
            marker,
            text: lines[start..end]
                .iter()
                .map(|line| format!("{line}\n"))
                .collect(),
        });
        index = end + 1;
    }
    examples
}

/// A complete rule or chain document from an example: a full document as is,
/// otherwise a fragment's keys over a synthetic rule (or chain, for a
/// `correlation` fragment). A fragment without `logsource` gets the category
/// its fields need.
fn example_document(text: &str) -> String {
    let fragment = yaml_map(text);
    if fragment.contains_key("taxonomy") {
        return text.to_owned();
    }
    let mut document = yaml_map(if fragment.contains_key("correlation") {
        PROBE_CHAIN
    } else {
        PROBE_RULE
    });
    if fragment.contains_key("detection") && !fragment.contains_key("logsource") {
        let detection = serde_yaml::to_string(&fragment["detection"]).unwrap();
        let category = match (detection.contains("tool."), detection.contains("message.")) {
            (true, false) => "tool_activity",
            (false, true) => "message",
            _ => "agent_activity",
        };
        document["logsource"]["category"] = category.into();
    }
    for (key, value) in fragment {
        document.insert(key, value);
    }
    serde_yaml::to_string(&document).unwrap()
}

fn check_example(example: &Example) -> Result<(), String> {
    let text = &example.text;
    let marker = example.marker.as_deref();
    if marker == Some("skip") {
        return Ok(());
    }
    if let Some(key) = RULE_V1_KEYS.iter().find(|key| {
        text.lines()
            .any(|line| line.trim_start().starts_with(**key))
    }) {
        if marker == Some("rule v1") {
            return Ok(());
        }
        return Err(format!("uses the Rule v1 key `{key}`; write it in Rule v2"));
    }
    if text.starts_with("format: ") {
        if !text.starts_with(&format!("format: {RULE_PACKAGE_FORMAT_V2}\n")) {
            return Err(format!(
                "a package example must use {RULE_PACKAGE_FORMAT_V2}"
            ));
        }
        let error = RulePackage::parse(text)
            .err()
            .map(|error| error.to_string());
        return expect_outcome(marker, error, Vec::new());
    }
    let rule_keys = [
        "taxonomy",
        "detection",
        "correlation",
        "logsource",
        "telltale",
        "tags",
    ];
    let Ok(Yaml::Mapping(first)) = serde_yaml::Deserializer::from_str(text)
        .next()
        .map(Yaml::deserialize)
        .transpose()
        .map(Option::unwrap_or_default)
    else {
        return match marker {
            Some(_) => Err("a marked example must be a YAML mapping".into()),
            None => Ok(()),
        };
    };
    if !rule_keys.iter().any(|key| first.contains_key(*key)) {
        return match marker {
            Some(_) => Err("a marked example is not rule content".into()),
            None => Ok(()),
        };
    }
    let document = example_document(text);
    let (error, notices) = match LoadedRules::parse(&document) {
        Err(error) => (Some(error.to_string()), Vec::new()),
        Ok(loaded) => {
            if let Some(definition) = loaded.definitions().iter().find(|d| !d.is_rule_v2()) {
                return Err(format!("`{}` is not Rule v2", definition.id()));
            }
            match load_rule_set_from_documents(&[&document], None) {
                Err(error) => (Some(error.to_string()), Vec::new()),
                Ok(rules) => (
                    None,
                    rules.notices().iter().map(|notice| notice.kind).collect(),
                ),
            }
        }
    };
    expect_outcome(marker, error, notices)
}

fn expect_outcome(
    marker: Option<&str>,
    error: Option<String>,
    notices: Vec<&str>,
) -> Result<(), String> {
    match (marker, error) {
        (None, None) if notices.is_empty() => Ok(()),
        (None, None) => Err(format!("loads with notices {notices:?}; mark it")),
        (None, Some(error)) => Err(format!("does not load: {error}")),
        (Some(marker), error) => {
            if let Some(expected) = marker.strip_prefix("error: ") {
                match error {
                    Some(error) if error.contains(expected) => Ok(()),
                    Some(error) => Err(format!("error {error:?} does not contain {expected:?}")),
                    None => Err(format!("loads, but the marker expects error {expected:?}")),
                }
            } else if let Some(expected) = marker.strip_prefix("notice: ") {
                match error {
                    Some(error) => Err(format!("does not load: {error}")),
                    None if notices.contains(&expected) => Ok(()),
                    None => Err(format!("notices {notices:?} do not include {expected}")),
                }
            } else {
                Err(format!("unknown marker {marker:?}"))
            }
        }
    }
}

#[test]
fn rule_doc_examples_load_as_rule_v2() {
    // A Windows checkout may write the docs with CRLF line endings; the
    // examples read from them must not change.
    for doc in RULE_EXAMPLE_DOCS {
        let text = fs::read_to_string(repo_path(doc)).unwrap();
        let crlf = text.replace("\r\n", "\n").replace('\n', "\r\n");
        assert_eq!(examples_in(doc, &crlf), examples_in(doc, &text), "{doc}");
    }
    let mut checked = 0;
    let failures = RULE_EXAMPLE_DOCS
        .iter()
        .flat_map(|doc| yaml_examples(doc))
        .filter_map(|example| {
            checked += 1;
            check_example(&example)
                .err()
                .map(|error| format!("{}:{}: {error}", example.doc, example.line))
        })
        .collect::<Vec<_>>();
    assert!(
        failures.is_empty(),
        "rule doc examples:\n{}",
        failures.join("\n")
    );
    assert!(checked > 20, "only {checked} YAML examples found");
}

/// Second-column headers that mark a table of source identities.
const SOURCE_ID_HEADERS: &[&str] = &["Source Identity", "Source Kind"];

/// Every second-column cell of a doc's source-identity tables, so a misspelled
/// or unknown identity is compared rather than skipped.
fn documented_source_ids(relative: &str) -> BTreeSet<String> {
    let text = fs::read_to_string(repo_path(relative)).expect("source doc");
    let second_cell = |line: &str| {
        line.trim()
            .strip_prefix('|')
            .and_then(|row| row.split('|').nth(1))
            .map(|cell| cell.trim().trim_matches('`').to_owned())
    };
    let mut ids = BTreeSet::new();
    let mut in_table = false;
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let Some(cell) = second_cell(line) else {
            in_table = false;
            continue;
        };
        let separator = lines
            .peek()
            .and_then(|next| second_cell(next))
            .is_some_and(|next| next.starts_with("---"));
        if separator {
            in_table = SOURCE_ID_HEADERS.contains(&cell.as_str());
            lines.next();
        } else if in_table {
            ids.insert(cell);
        }
    }
    assert!(
        !ids.is_empty(),
        "{relative}: no source identity table found"
    );
    ids
}

fn registry_source_ids() -> BTreeSet<String> {
    supported_clients()
        .iter()
        .flat_map(|client| client.sources.iter().map(|source| source.id.to_owned()))
        .collect()
}

#[test]
fn source_docs_name_exactly_the_registered_source_identities() {
    let registered = registry_source_ids();
    for doc in [
        "docs/session-sources.md",
        "docs/source-validation-matrix.md",
    ] {
        assert_eq!(
            documented_source_ids(doc),
            registered,
            "{doc} source tables must list exactly the registered source identities"
        );
    }
}
