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
        error(&raw.replace("id: acme.rules", "id: Acme.Rules")).contains("rule package id must be")
    );
    assert!(error(&raw.replace("version: 1.2.3", "version: '1 2'")).contains("version must be"));
    assert!(error(&raw.replace("license: Apache-2.0", "license: ''")).contains("license must be"));
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
            .map(|(index, line)| format!("{}{line}\n", if index == 0 { "  - " } else { "    " }))
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
        &package(COMMUNITY_PACKAGE_ID, "tdx", "tdx.synthetic.marker").replace("1.2.3", "99.0.0"),
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

    let embedded = resolve_rule_packages(CommunityRules::Embedded, vec![other.clone()]).unwrap();
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

    let disabled = resolve_rule_packages(CommunityRules::Disabled, vec![community, other]).unwrap();
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

    let fork = RulePackage::parse(&package("acme.fork", "tdx", "tdx.synthetic.marker")).unwrap();
    let message = resolve_rule_packages(CommunityRules::Embedded, vec![fork])
        .unwrap_err()
        .to_string();
    assert!(message.contains("both use namespace 'tdx'"), "{message}");
}
