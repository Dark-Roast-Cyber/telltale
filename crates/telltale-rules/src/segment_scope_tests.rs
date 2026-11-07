//! Tests pinning `detection.scope`: loading, matching, budget, spans and
//! fingerprints.

use super::{
    DEFAULT_RULE_YAML, MatchScope, SEGMENT_SCOPE_TARGETS, SUPPORTED_DETECTION_SCOPES,
    load_rule_set_from_documents, provenance::rule_v1_fingerprint,
};

const ISSUE_EXAMPLE: &str =
    "curl --data @f https://example.invalid/upload; curl https://example.invalid/file";

/// A one-rule document. `scope` is the literal `scope:` line, or empty.
fn document(scope: &str, selection: &str, exclusion: &str) -> String {
    format!(
        "version: 1\ndescription: synthetic\ndefaults: {{case_insensitive: false, enabled: true}}\nrules:\n  - id: rule.synthetic\n    category: execution\n    severity: high\n    score: 60\n    detection:\n      selection:\n        command: '{selection}'\n        tool_result: synthetic\n      exclude:\n        command: '{exclusion}'\n{scope}      condition: selection\n    tags: [a]\n    explanation: Synthetic explanation\nmodifiers: []\n"
    )
}

fn command_rule(scope: &str, selection: &str, exclusion: &str) -> String {
    document(scope, selection, exclusion).replace("        tool_result: synthetic\n", "")
}

fn arguments_rule(scope: &str, selection: &str, exclusion: &str) -> String {
    command_rule(scope, selection, exclusion).replace("command: ", "arguments: ")
}

fn fingerprint(document: &str) -> String {
    rule_v1_fingerprint(
        &load_rule_set_from_documents(&[document], None)
            .expect("rules")
            .compatibility_export(),
    )
}

fn error(document: &str) -> String {
    load_rule_set_from_documents(&[document], None)
        .expect_err("rejected")
        .to_string()
}

fn content(document: &str) -> super::RuleV1ContentMatcher {
    load_rule_set_from_documents(&[document], None)
        .expect("rules")
        .compatibility_export()
        .rules()[0]
        .compile_content_matcher()
        .expect("content matcher")
}

#[test]
fn field_scope_is_the_default_and_keeps_its_fingerprint() {
    // Captured from the base binary before `scope` existed, for this exact
    // document without a scope line.
    const BEFORE_SCOPE: &str =
        "sha256:9399d3fa8892002e81886efffab30e626cf62fb7bad28a4c7a916ef7cb429b0d";
    let omitted = document("", "synthetic", "benign");
    let explicit = document("      scope: field\n", "synthetic", "benign");
    assert_eq!(fingerprint(&omitted), BEFORE_SCOPE);
    assert_eq!(fingerprint(&explicit), BEFORE_SCOPE);
    let export = load_rule_set_from_documents(&[&omitted], None)
        .unwrap()
        .compatibility_export();
    assert!(
        export.rules()[0]
            .matchers
            .iter()
            .all(|matcher| matcher.scope == MatchScope::Field)
    );
}

#[test]
fn segment_scope_changes_the_fingerprint() {
    let field = command_rule("", "synthetic", "benign");
    let segment = command_rule("      scope: segment\n", "synthetic", "benign");
    assert_ne!(fingerprint(&field), fingerprint(&segment));
    // Only the scope of the bundled download rule differs from before it was
    // declared: without the line, the core fingerprint is the base one.
    const CORE_BEFORE_SCOPE: &str =
        "sha256:e67a359521c89f06399334c49c6587a9e6df4c9cbeb055392e24ae248602df25";
    let bundled = DEFAULT_RULE_YAML.replace("\r\n", "\n");
    let segment_fingerprint = fingerprint(&bundled);
    assert_ne!(segment_fingerprint, CORE_BEFORE_SCOPE);
    for newline in ["\n", "\r\n"] {
        let bundled = bundled.replace('\n', newline);
        let normalized = bundled.replace("\r\n", "\n");
        assert_eq!(normalized.matches("      scope: segment\n").count(), 1);
        let without = normalized.replace("      scope: segment\n", "");
        assert!(!without.contains("      scope: segment"));
        let explicit_field = normalized.replace("      scope: segment\n", "      scope: field\n");
        assert_eq!(
            fingerprint(&without.replace('\n', newline)),
            CORE_BEFORE_SCOPE
        );
        assert_eq!(
            fingerprint(&explicit_field.replace('\n', newline)),
            CORE_BEFORE_SCOPE
        );
        assert_eq!(fingerprint(&bundled), segment_fingerprint);
    }
}

#[test]
fn a_legacy_and_a_segment_matcher_with_the_same_pattern_both_stay_identified() {
    let base = "version: 1\ndescription: synthetic\ndefaults: {case_insensitive: false, enabled: true}\nrules:\n  - id: rule.synthetic\n    category: execution\n    severity: high\n    score: 60\n    targets: [command]\n    regex: synthetic\n    tags: [a]\n    explanation: Synthetic explanation\nmodifiers: []\n";
    let both = base.replace(
        "    regex: synthetic\n",
        "    regex: synthetic\n    detection:\n      selection: {command: synthetic}\n      scope: segment\n",
    );
    let export = load_rule_set_from_documents(&[&both], None)
        .unwrap()
        .compatibility_export();
    assert_eq!(
        export.rules()[0]
            .matchers
            .iter()
            .map(|matcher| matcher.scope)
            .collect::<Vec<_>>(),
        [MatchScope::Field, MatchScope::Segment]
    );
    assert_ne!(fingerprint(base), fingerprint(&both));
}

#[test]
fn invalid_scopes_fail_at_load_with_a_clear_error() {
    let unknown = error(&command_rule("      scope: line\n", "x", "y"));
    assert!(
        unknown.contains(
            "unknown variant `line`, expected one of `field`, `segment`, `exclusion_segment`"
        ),
        "{unknown}"
    );
    let prose = error(&document("      scope: segment\n", "x", "y"));
    assert_eq!(
        prose,
        "rule rule.synthetic uses scope 'segment' with target 'tool_result'; segment scope supports only command-text targets: arguments, command, url"
    );
    let rule_level = error(
        &command_rule("", "x", "y")
            .replace("    tags: [a]\n", "    scope: segment\n    tags: [a]\n"),
    );
    assert!(rule_level.contains("unknown field `scope`"), "{rule_level}");
    for target in super::SUPPORTED_RULE_TARGETS {
        let rule = command_rule("      scope: segment\n", "x", "y")
            .replace("        command: 'x'", &format!("        {target}: 'x'"))
            .replace("        command: 'y'", &format!("        {target}: 'y'"));
        assert_eq!(
            load_rule_set_from_documents(&[&rule], None).is_ok(),
            SEGMENT_SCOPE_TARGETS.contains(target),
            "{target}"
        );
    }
    // The published vocabulary names exactly the deserializable scopes,
    // default first.
    assert_eq!(
        MatchScope::default().as_str(),
        SUPPORTED_DETECTION_SCOPES[0]
    );
    assert_eq!(SUPPORTED_DETECTION_SCOPES.len(), 3);
    for (value, scope) in SUPPORTED_DETECTION_SCOPES.iter().zip([
        MatchScope::Field,
        MatchScope::Segment,
        MatchScope::ExclusionSegment,
    ]) {
        assert_eq!(scope.as_str(), *value);
        assert!(
            load_rule_set_from_documents(
                &[&command_rule(&format!("      scope: {value}\n"), "x", "y")],
                None
            )
            .is_ok()
        );
    }
}

#[test]
fn segment_scope_applies_selection_and_exclusion_to_the_same_segment() {
    // The exclusion is not quote-aware itself, so only the segmenter keeps a
    // quoted or escaped separator from hiding it.
    let upload = "--data";
    let field = content(&command_rule("", r"curl\b[^;|]*https://", upload));
    let segment = content(&command_rule(
        "      scope: segment\n",
        r"curl\b[^;|]*https://",
        upload,
    ));
    let cases = [
        (ISSUE_EXAMPLE, false, true),
        (
            "curl --data @f https://example.invalid/upload https://example.invalid/file",
            false,
            false,
        ),
        // Quoted separators do not split a segment.
        (
            "curl https://example.invalid/upload -H 'X: a;b' --data @f",
            false,
            false,
        ),
        (
            "curl https://example.invalid/upload -H \"X: a|b\" --data @f",
            false,
            false,
        ),
        // An escaped separator does not split either.
        (
            "curl https://example.invalid/upload -H X:a\\;b --data @f",
            false,
            false,
        ),
        (
            "curl https://example.invalid/upload && echo --data",
            false,
            true,
        ),
        ("echo none", false, false),
    ];
    for (command, field_match, segment_match) in cases {
        let fields = [("command", command)];
        assert_eq!(
            !field.matching_fields(&fields).is_empty(),
            field_match,
            "field: {command}"
        );
        assert_eq!(
            !segment.matching_fields(&fields).is_empty(),
            segment_match,
            "segment: {command}"
        );
    }
}

#[test]
fn compiled_rule_sets_evaluate_segment_scope_like_the_content_matcher() {
    let rules = load_rule_set_from_documents(
        &[&command_rule(
            "      scope: segment\n",
            r"curl\b[^;|]*https://",
            r"curl\b[^;|]*--data",
        )],
        None,
    )
    .unwrap();
    let matched = rules
        .evaluate(&[("command", ISSUE_EXAMPLE)])
        .unwrap()
        .expect("match");
    assert_eq!(matched.rule_ids, ["rule.synthetic"]);
    // Evidence is the whole field, not the segment.
    assert_eq!(matched.evidence[0].field, "command");
    assert_eq!(matched.evidence[0].redacted_value, ISSUE_EXAMPLE);
    assert!(
        rules
            .evaluate(&[("command", "curl --data @f https://example.invalid/x")])
            .unwrap()
            .is_none()
    );
}

#[test]
fn anchors_apply_per_segment_and_spans_stay_field_relative() {
    let anchored = content(&command_rule("      scope: segment\n", "^rm -rf$", "^$"));
    let text = "cd /tmp &&   rm -rf  ;  ls";
    let fields = [("command", text)];
    let spans = anchored
        .try_matching_spans(&fields, &mut |_| Ok::<_, std::convert::Infallible>(()))
        .unwrap();
    assert_eq!(spans.len(), 1);
    let (_, value, range) = &spans[0];
    assert_eq!(&value[range.clone()], "rm -rf");
    assert_eq!(range.start, text.find("rm").unwrap());
    let unanchored = content(&command_rule("", "^rm -rf$", "^$"));
    assert!(unanchored.matching_fields(&[("command", text)]).is_empty());
    // A pattern cannot span segments.
    let spanning = content(&command_rule("      scope: segment\n", "a.*b", "^$"));
    assert!(spanning.matching_fields(&[("command", "a; b")]).is_empty());
    assert!(!spanning.matching_fields(&[("command", "a b")]).is_empty());
}

const EXCLUSION_SCOPE: &str = "      scope: exclusion_segment\n";

#[test]
fn exclusion_segment_drops_only_matches_inside_an_excluded_segment() {
    let rule = content(&command_rule(EXCLUSION_SCOPE, "curl", "secret"));
    let matched = |value: &str| !rule.matching_fields(&[("command", value)]).is_empty();
    assert!(!matched("curl secret"));
    assert!(!matched("curl secret; echo ok"));
    assert!(!matched("none"));
    assert!(matched("curl secret; curl ok"));
    assert!(matched("curl ok; curl secret"));
    assert!(matched("echo secret; curl ok"));

    // The selection reads the field: `^` anchors to it, and a match that crosses
    // segments counts even though a segment holds the exclusion.
    let anchored = content(&command_rule(EXCLUSION_SCOPE, "^curl", "secret"));
    assert!(
        anchored
            .matching_fields(&[("command", "echo; curl ok")])
            .is_empty()
    );
    let crossing = content(&command_rule(EXCLUSION_SCOPE, "a; b", "a"));
    assert!(!crossing.matching_fields(&[("command", "a; b")]).is_empty());

    // A continuation before a separator is not part of the excluded statement,
    // but one that continues the command keeps its text in the segment.
    let exact = content(&command_rule(EXCLUSION_SCOPE, "curl", "^curl x$"));
    let exact_match = |value: &str| !exact.matching_fields(&[("command", value)]).is_empty();
    assert!(!exact_match("curl x \\\n&& echo ok"));
    assert!(exact_match("curl x \\\n  -d y"));
    assert!(exact_match("curl x \\\\"));
}

#[test]
fn exclusion_segment_reads_one_exact_json_shape_and_only_to_drop_a_match() {
    let exclusion = "^curl secret$";
    let rule = content(&arguments_rule(EXCLUSION_SCOPE, "curl", exclusion));
    let matched = |value: &str| !rule.matching_fields(&[("arguments", value)]).is_empty();

    // Every selection match in the command is excluded: the match is dropped.
    assert!(!matched(r#"{"cmd":"curl secret"}"#));
    assert!(!matched(r#"{"cmd":"curl secret; echo ok","workdir":"/w"}"#));
    assert!(!matched(r#"{"command":["bash","-lc","curl secret"]}"#));
    // The raw text decides everything else.
    assert!(matched(r#"{"cmd":"curl secret; curl ok"}"#));
    assert!(matched(r#"{"cmd":"curl secret","description":"curl ok"}"#));
    assert!(matched(r#"{"cmd":"curl secret","args":"x"}"#));
    assert!(matched(r#"{"note":"curl secret"}"#));
    assert!(matched(r#"{"cmd":"curl secret""#));
    // A command without a selection match leaves the raw text to decide.
    let raw_only = content(&arguments_rule(EXCLUSION_SCOPE, "curl.,.x", exclusion));
    assert!(
        !raw_only
            .matching_fields(&[("arguments", r#"{"cmd":"curl","x":1}"#)])
            .is_empty()
    );

    // The rest of the command is read as one line, as raw JSON lets a selection
    // cross its escaped line breaks. The excluded segment is not part of it.
    let crossing = content(&arguments_rule(
        EXCLUSION_SCOPE,
        "curl(?:.*ok| secret)",
        exclusion,
    ));
    let crosses = |value: &str| !crossing.matching_fields(&[("arguments", value)]).is_empty();
    assert!(crosses(r#"{"cmd":"curl secret; curl \nok"}"#));
    assert!(!crosses(r#"{"cmd":"curl secret; echo \nok"}"#));

    // The reader only drops: text the raw field does not match stays unmatched.
    let escaped = format!("{{\"cmd\":\"{}u0063url ok\"}}", char::from(92));
    assert!(!matched(&escaped));

    // Outside the excluded segments the raw spelling still decides, however
    // JSON escapes it.
    let quoted = content(&arguments_rule(
        EXCLUSION_SCOPE,
        "curl [^\"]*ok",
        "^curl ok$",
    ));
    let quotes = |value: &str| !quoted.matching_fields(&[("arguments", value)]).is_empty();
    assert!(!quotes(r#"{"cmd":"curl ok; curl \"ok"}"#));
    let hidden = format!("{{\"cmd\":\"curl ok; curl {}u0022ok\"}}", char::from(92));
    assert!(quotes(&hidden));

    // Other targets and scopes never read it.
    let shaped = r#"{"cmd":"curl secret"}"#;
    let command = content(&command_rule(EXCLUSION_SCOPE, "curl", exclusion));
    assert!(!command.matching_fields(&[("command", shaped)]).is_empty());
    let segment = content(&arguments_rule("      scope: segment\n", "curl", exclusion));
    assert!(!segment.matching_fields(&[("arguments", shaped)]).is_empty());
    let field = content(&arguments_rule("", "curl", exclusion));
    assert!(!field.matching_fields(&[("arguments", shaped)]).is_empty());
}

#[test]
fn json_spelling_blanks_each_range_in_every_literal_that_decodes_to_the_text() {
    use crate::segment::blank_json_spelling;
    let slash = char::from(92);
    // A decoded e-acute and a surrogate pair, each spelled as escapes.
    let (acute, pair) = (format!("{slash}u00e9"), format!("{slash}ud83d{slash}ude00"));
    let raw = format!(
        "{{\"cmd\":\"a{slash}\"b {acute}{pair}; c\",\"note\":\"a{slash}\"b {acute}{pair}; c\",\"x\":\"a\"}}"
    );
    let text = "a\"b \u{e9}\u{1f600}; c";
    // The first range covers the escaped quote, the second both escaped characters.
    let blanked = blank_json_spelling(&raw, text, &[0..3, 4..10]).expect("decoded");
    let literal = format!("{}; c", " ".repeat(5 + acute.len() + pair.len()));
    assert_eq!(
        blanked,
        format!("{{\"cmd\":\"{literal}\",\"note\":\"{literal}\",\"x\":\"a\"}}")
    );
    // A line break reads as a space, as in the one-line remainder.
    let lines = format!("{{\"cmd\":\"a{slash}nb\",\"x\":\"a\"}}");
    assert_eq!(
        blank_json_spelling(&lines, "a\nb", &[]).as_deref(),
        Some("{\"cmd\":\"a  b\",\"x\":\"a\"}")
    );
    // Nothing decodes to the text, or a literal does not decode: no result.
    assert_eq!(blank_json_spelling(&raw, "other", &[]), None);
    let lone = format!("{{\"cmd\":\"{slash}ud83d\"}}");
    assert_eq!(blank_json_spelling(&lone, "x", &[]), None);
}

#[test]
fn exclusion_segment_charges_each_scan_before_it_runs() {
    let visits = |matcher: &super::RuleV1ContentMatcher, name: &str, value: &str| {
        let mut visits = Vec::new();
        matcher
            .try_matching_fields(&[(name, value)], &mut |bytes| {
                visits.push(bytes);
                Ok::<_, ()>(())
            })
            .unwrap();
        visits
    };
    // Name, the selection scan, the segmentation pass, then one byte over each
    // holding segment that an exclusion scan reads.
    let command = content(&command_rule(EXCLUSION_SCOPE, "curl", "secret"));
    assert_eq!(
        visits(&command, "command", "curl secret; curl ok"),
        [7, 20, 20, 12, 8]
    );

    let arguments = content(&arguments_rule(EXCLUSION_SCOPE, "curl", "secret"));
    // The parse, the command's scans and exclusion, the remainder's pass, exclusion
    // and scan, each other string, then the raw text's blanking pass and scan.
    let (dropped, text) = (r#"{"cmd":"curl secret","workdir":"/w"}"#, "plain");
    assert_eq!(
        visits(&arguments, "arguments", dropped),
        [9, 36, 11, 11, 12, 11, 12, 0, 2, 36, 36]
    );
    // No parse is charged for text that cannot be JSON.
    assert_eq!(visits(&arguments, "arguments", text), [9, 5, 5]);
    assert_eq!(
        arguments.try_matching_fields(&[("arguments", dropped)], &mut |_| Err("exhausted")),
        Err("exhausted")
    );
}

#[test]
fn segment_scope_charges_each_scan_before_it_runs() {
    let matcher = content(&command_rule("      scope: segment\n", "needle", "quoted"));
    let mut visits = Vec::new();
    let fields = [
        ("command", "x; needle quoted ; needle"),
        ("command", "none"),
    ];
    let matched = matcher
        .try_matching_fields(&fields, &mut |bytes| {
            visits.push(bytes);
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(matched, [("command", "x; needle quoted ; needle")]);
    // Name, the segmentation pass, then each segment plus one byte: `x` misses,
    // `needle quoted` matches and is excluded, `needle` counts. The second
    // field is segmented and its only segment misses.
    assert_eq!(visits, [7, 25, 2, 14, 14, 7, 7, 7, 4, 5]);
    assert_eq!(
        matcher.try_matching_fields(&fields, &mut |_| Err("exhausted")),
        Err("exhausted")
    );
    // The segmentation pass is charged before any segment is scanned.
    let mut budget: usize = 31;
    assert_eq!(
        matcher.try_matching_fields(&fields, &mut |bytes| {
            budget = budget.checked_sub(bytes).ok_or("exhausted")?;
            Ok(())
        }),
        Err("exhausted")
    );
}

#[test]
fn case_insensitive_defaults_apply_to_segment_scope() {
    let rule = command_rule("      scope: segment\n", "needle", "quoted")
        .replace("case_insensitive: false", "case_insensitive: true");
    let matcher = content(&rule);
    assert!(
        matcher
            .matching_fields(&[("command", "NEEDLE QUOTED")])
            .is_empty()
    );
    assert!(
        !matcher
            .matching_fields(&[("command", "NEEDLE QUOTED; NEEDLE")])
            .is_empty()
    );
}

#[test]
fn documented_segment_scope_example_behaves_as_described() {
    // The `detection` block from docs/detection-model.md, verbatim. The root
    // catalog tests check doc consistency outside the crate package boundary.
    let rule = "version: 1\ndescription: synthetic\ndefaults: {case_insensitive: false, enabled: true}\nrules:\n  - id: rule.synthetic\n    category: download\n    severity: low\n    score: 20\n    detection:\n      selection:\n        command: '\\bcurl\\b[^;|\\n]*https?://'\n      exclude:\n        command: '\\bcurl\\b[^;|\\n]*--data'\n      scope: segment\n      condition: selection\n    tags: [a]\n    explanation: Synthetic explanation\nmodifiers: []\n";
    let matcher = content(rule);
    assert!(
        !matcher
            .matching_fields(&[("command", ISSUE_EXAMPLE)])
            .is_empty()
    );
    assert!(
        matcher
            .matching_fields(&[("command", "curl --data @f https://example.invalid/upload")])
            .is_empty()
    );
}
