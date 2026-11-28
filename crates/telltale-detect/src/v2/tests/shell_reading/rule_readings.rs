use super::*;

/// A comment is no part of what a rule's exclusion may read. Its text would
/// otherwise veto the command it sits beside.
#[test]
fn comment_text_triggers_no_exclusion() {
    const RULE: &str = "approval.bypass.context";
    const COMMAND: &str = "claude --dangerously-skip-permissions";
    const NOTE: &str = "for documentation without asking quoted example";
    let reader = Reader::new();
    assert!(reader.rules(COMMAND).contains(RULE));
    for command in [
        format!("{COMMAND} # {NOTE}"),
        format!("# {NOTE}\n{COMMAND}"),
        format!("{COMMAND} #{NOTE}"),
    ] {
        assert!(reader.rules(&command).contains(RULE), "{command:?}");
    }
    // The text of a call that really passes it still counts.
    assert!(!reader.rules(&format!("{COMMAND} {NOTE}")).contains(RULE));
}

/// A custom rule's segments read the code, so a comment neither vetoes it nor
/// merges what a shell keeps apart. Quote removal is no part of a segment rule,
/// which promises that quotes are respected.
#[test]
fn a_segment_rule_reads_the_code_with_its_quotes() {
    fn custom(rule: &str, regex: &str, exclude: &str) -> String {
        format!(
            "title: synthetic\nid: 0223f0bf-30ed-436c-8784-63086033677f\nname: {rule}\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: tool_activity\ndetection:\n    selection_command:\n        tool.command|re|segment: '{regex}'\n    filter_command:\n        tool.command|re|segment: '{exclude}'\n    condition: selection_command and not filter_command\nlevel: low\ntelltale:\n    category: custom\n    score: 10\n    explanation: 'synthetic'\n    tags: [custom]\n"
        )
    }
    let document = custom("custom.fetch", "^fetch\\b", "--post");
    let rules = telltale_rules::load_rule_set_from_documents(&[&document], None).unwrap();
    let plan = compile_rule_v1(&rules.compatibility_export()).unwrap();
    let reader = Reader { plan: &plan };
    let fires = |command: &str| reader.rules(command).contains("custom.fetch");
    assert!(fires("fetch a"));
    assert!(fires("true; fetch a"));
    assert!(!fires("fetch --post a"));
    // The comment's words are no segment's, and its apostrophe merges nothing.
    assert!(fires("fetch a # --post"));
    assert!(fires("# don't\nfetch --post a; fetch b"));
    assert!(fires("# don't\nfetch a"));
    // A separator in a quote stays in its word, whatever a reading takes off.
    assert!(!fires("echo \"a; fetch b\""));
    assert!(!fires("echo 'a; fetch b'"));
}

/// A recorded-exclusion rule also selects from the command with its quotes read
/// away, and judges its exclusion on the recorded text. A separator or quote that a
/// quoted string holds is bare in that reading, so a quoted message stays excluded,
/// while a live separator after a quote-split word is still selected, because the
/// recorded text is then no excluded command.
#[test]
fn a_recorded_exclusion_rule_reads_quote_free_text_and_judges_the_exclusion_on_the_recorded_text() {
    /// `scope` is a `      scope: <name>\n` line naming the scope modifier of
    /// both keys, or empty for none.
    fn custom(scope: &str) -> String {
        let scope = match scope.trim().strip_prefix("scope: ") {
            Some(name) => format!("|{name}"),
            None => String::new(),
        };
        format!(
            "title: Synthetic remove\nid: 9c4f1e2a-3b5d-4c6e-8f70-1a2b3c4d5e6f\nname: custom.remove\ntaxonomy: telltale\nlogsource:\n    product: ai_agent\n    category: tool_activity\ndetection:\n    selection_command:\n        tool.command|re{scope}: '(?:^|[;&|\\n])\\s*rm\\s+\\S*secret'\n    filter_command:\n        tool.command|re{scope}: '^git +commit +-m +(?:\"[^\"]*\"|\\x27[^\\x27]*\\x27)$'\n    condition: selection_command and not filter_command\nlevel: low\ntelltale:\n    category: custom\n    score: 10\n    explanation: synthetic\n    tags: [custom]\n"
        )
    }
    let fires_under = |scope: &str, command: &str| {
        let document = custom(scope);
        let rules = telltale_rules::load_rule_set_from_documents(&[&document], None).unwrap();
        let plan = compile_rule_v1(&rules.compatibility_export()).unwrap();
        Reader { plan: &plan }
            .rules(command)
            .contains("custom.remove")
    };
    let fires = |command: &str| fires_under("      scope: recorded_exclusion\n", command);
    // A quoted separator is quoted: the message is excluded, in either quote.
    assert!(!fires("git commit -m \"x; rm secret\""));
    assert!(!fires("git commit -m 'x; rm secret'"));
    assert!(!fires("git commit -m \"x\\ny; rm secret\""));
    assert!(!fires("git commit -m \"x\n; rm secret\""));
    // A live separator is not, however the word after it is spelled.
    assert!(fires("rm secret"));
    assert!(fires("git commit -m x; rm secret"));
    assert!(fires("git commit -m x; \"r\"m secret"));
    assert!(fires("git commit -m 'x'; r'm' secret"));
    assert!(fires("git commit -m \"x\"; \"r\"m secret"));
    assert!(fires("git commit -m \"x\" && \"r\"m secret"));
    assert!(fires("git commit -m \"x; rm secret\"; \"r\"m secret"));
    assert!(fires("git commit -m 'x\\'; \"r\"m secret"));
    assert!(fires("\"r\"m secret"));
    assert!(fires("\"r\"m \"sec\"ret"));
    // A quote-split word inside the segment holding the match is read too.
    assert!(fires("rm 'sec'ret"));
    assert!(fires("true\nrm \"sec\"\"ret\""));
    // Nothing else about the excluded segment is excused.
    assert!(fires("git commit -m \"x\" \"y; rm secret\""));
    // Field and segment scope read as before: field scope vetoes on the quote-free
    // reading's exclusion, segment scope reads the code with its quotes.
    assert!(fires_under("", "git commit -m \"x; rm secret\""));
    assert!(!fires_under(
        "      scope: segment\n",
        "git commit -m \"x; rm secret\""
    ));
    assert!(!fires_under("      scope: segment\n", "\"r\"m secret"));
}

/// What a shell leaves of a word is matched but never shown. Redaction relies on
/// quotes this reading lacks, so evidence stays the text the call recorded.
#[test]
fn the_unquoted_reading_stays_out_of_evidence() {
    const RULE: &str = "destructive.filesystem_wipe";
    const TOKEN: &str = "ghp_Zq3Wt9LmP2kR7vX4nB8cY1dF6hJ0sA5uE3iO";
    let reader = Reader::new();
    let evidence = |command: &str| {
        let findings = reader.findings(serde_json::json!({"command": command}));
        findings
            .iter()
            .flat_map(|finding| finding.evidence())
            .find(|evidence| evidence.rule_id() == RULE)
            .cloned()
            .unwrap_or_else(|| panic!("{command:?}"))
    };
    // Found only in the reading: the recorded text, and no position in it.
    let found = evidence("\"rm\" -rf /");
    assert_eq!(found.redacted_value(), "\"rm\" -rf /");
    assert_eq!(found.highlight(), None);
    // Found in the recorded text too: its position there.
    let found = evidence("echo \"a\"; rm -rf /");
    assert_eq!(found.redacted_value(), "echo \"a\"; rm -rf /");
    assert_eq!(found.highlight(), Some(10..18));
    // Redaction reads the recorded text alone.
    let found = evidence(&format!("\"rm\" -rf / \"{TOKEN}\""));
    assert!(!found.redacted_value().contains(TOKEN));
    assert_eq!(found.redacted_value().matches("rm").count(), 1);
}

/// A rule finds a command once, however many readings of the text hold it.
#[test]
fn two_readings_of_a_stage_give_one_hit() {
    let reader = Reader::new();
    let hits = |command: &str| {
        reader
            .findings(serde_json::json!({"command": command}))
            .iter()
            .filter(|finding| finding.rule_ids().iter().any(|id| id == "network.download"))
            .count()
    };
    let plain = hits("curl https://example.invalid/a -o a");
    assert_eq!(plain, 1);
    for command in [
        "curl \\\n https://example.invalid/a -o a",
        "curl https://example.invalid/a -o a; true",
        "true; curl https://example.invalid/a -o a",
        "curl https://example.invalid/a -o a # note",
    ] {
        assert_eq!(hits(command), plain, "{command:?}");
    }
}
