//! The `tool_kind` target (`tool.kind` in Rule v2): what a call does, as the declared kind of its
//! source's tool table, else the kind of a native tool name, else nothing. The
//! session selectors and the action view give the same value for the same call.

use super::actions::{self, view_tool_kind};
use super::selector::{SelectorId, SelectorRegistry};
use super::session::RetentionBudget;
use super::tool_arguments::is_shell_tool;
use super::written_path_tests::{declared_tool, file_tool};
use super::{DetailedEvaluationOptions, EvaluationStatus, compile_rule_v1};
use regex::Regex;
use serde_json::json;
use telltale_schema::observation::{CanonicalObservationV2, JsonValue, ToolKind, ToolOperation};

const ALL_KINDS: [ToolKind; 6] = [
    ToolKind::Shell,
    ToolKind::FileRead,
    ToolKind::FileWrite,
    ToolKind::Web,
    ToolKind::Delegate,
    ToolKind::Other,
];

/// The name pattern of the shell-execution rule before it selected a kind, as
/// the rule compiler read it: case-insensitive.
const OLD_SHELL_NAME_PATTERN: &str =
    r"(?i:^(shell|exec_command|shell_command|bash|sh|zsh|fish|pwsh|powershell|cmd\.exe)$)";

fn call(name: &str, declared: Option<ToolKind>) -> CanonicalObservationV2 {
    let arguments = json!({"target": "synthetic"});
    match declared {
        Some(kind) => declared_tool("kind", name, arguments, ToolOperation::new(kind)),
        None => file_tool("kind", name, arguments),
    }
}

fn selector_kind(observation: &CanonicalObservationV2) -> Option<String> {
    let resolution = SelectorRegistry::new()
        .resolve(
            SelectorId::parse("compat.v1.tool_kind").unwrap(),
            observation,
        )
        .unwrap();
    match resolution.value() {
        Some(JsonValue::String(text)) if resolution.is_present() => Some(text.clone()),
        _ => None,
    }
}

#[test]
fn both_consumers_read_the_declared_kind_else_the_name_kind_else_none() {
    let cases: &[(&str, Option<ToolKind>, Option<&str>)] = &[
        // No declaration: the name lists give the kind, in any letter case.
        ("Bash", None, Some("shell")),
        ("SHELL", None, Some("shell")),
        ("exec_command", None, Some("shell")),
        ("cmd.exe", None, Some("shell")),
        ("Write", None, Some("file_write")),
        ("read_file", None, Some("file_read")),
        // No kind is known for any other undeclared call; it is not `other`.
        ("synthetic_tool", None, None),
        ("shell_help", None, None),
        ("exec_command_status", None, None),
        ("mcp__shell", None, None),
        // A declaration gives the kind, and wins over the name.
        ("monitor", Some(ToolKind::Shell), Some("shell")),
        ("Bash", Some(ToolKind::Other), Some("other")),
        ("Write", Some(ToolKind::Delegate), Some("delegate")),
        ("lookup", Some(ToolKind::Web), Some("web")),
    ];
    for (name, declared, expected) in cases {
        let observation = call(name, *declared);
        assert_eq!(
            selector_kind(&observation).as_deref(),
            *expected,
            "selector: {name} {declared:?}"
        );
        assert_eq!(
            view_tool_kind(&observation),
            *expected,
            "action view: {name} {declared:?}"
        );
    }
    for kind in ALL_KINDS {
        let observation = call("synthetic_tool", Some(kind));
        assert_eq!(selector_kind(&observation).as_deref(), Some(kind.as_str()));
        assert_eq!(view_tool_kind(&observation), Some(kind.as_str()));
    }
}

/// The fallback holds the names the shell-execution rule selected by name, and
/// matches them as that pattern did: any letter case, and the long s as `s`.
#[test]
fn the_shell_name_fallback_matches_the_names_the_rule_selected() {
    let old = Regex::new(OLD_SHELL_NAME_PATTERN).unwrap();
    let names = [
        "shell",
        "exec_command",
        "shell_command",
        "bash",
        "sh",
        "zsh",
        "fish",
        "pwsh",
        "powershell",
        "cmd.exe",
        "Bash",
        "SHELL",
        "PowerShell",
        "Cmd.EXE",
        "Exec_Command",
        "\u{17f}h",
        "ba\u{17f}h",
        "bash ",
        " bash",
        "bash\n",
        "bashful",
        "cmd_exe",
        "cmdXexe",
        "shell_help",
        "exec_command_status",
        "mcp__shell",
        "read_file",
        "",
    ];
    for name in names {
        assert_eq!(is_shell_tool(name), old.is_match(name), "{name:?}");
    }
    // Every character the pattern's letters fold to, in every position of
    // every name, agrees with the pattern.
    let letters = "shelxcmdobapzwfin_.";
    let class = Regex::new(&format!("(?i:[{}])", regex::escape(letters))).unwrap();
    let every: String = (0..=0x10_ffff).filter_map(char::from_u32).collect();
    let folds: Vec<char> = class
        .find_iter(&every)
        .filter_map(|found| found.as_str().chars().next())
        .collect();
    assert!(folds.contains(&'\u{17f}'));
    for name in &names[..10] {
        let chars: Vec<char> = name.chars().collect();
        for at in 0..chars.len() {
            for fold in &folds {
                let mut variant = chars.clone();
                variant[at] = *fold;
                let variant: String = variant.into_iter().collect();
                assert_eq!(
                    is_shell_tool(&variant),
                    old.is_match(&variant),
                    "{variant:?}"
                );
            }
        }
    }
}

#[cfg(feature = "source-io")]
mod tests;

/// A declared record that names no tool, with the command facet adapters derive.
fn nameless(command: &str) -> CanonicalObservationV2 {
    use telltale_schema::observation::{
        CapabilityAvailability, CapabilityContext, CapabilityId, CorrelationId, FactMetadata,
        FactProvenance, Fidelity, IngestionMode, ObservationBody, ObservationStage, ObservedAt,
        SemanticFacet, Sensitivity, SourceProvenance, SourceTimestamp, ToolObservation,
    };
    let tool = ToolObservation::new()
        .with_arguments(JsonValue::try_from_source_value(&json!({"command": command})).unwrap())
        .with_operation(ToolOperation::new(ToolKind::Shell));
    CanonicalObservationV2::builder(
        ObservationBody::Tool(tool),
        ObservationStage::ToolRequested,
        ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
        SourceProvenance::new(
            IngestionMode::SessionStore,
            "claude_code",
            "claude.projects",
            Fidelity::FullNative,
        )
        .unwrap()
        .with_native_id("nameless")
        .unwrap(),
    )
    .session_id(CorrelationId::source_reported("synthetic-session").unwrap())
    .occurred_at(SourceTimestamp::new("2026-09-17T00:00:00Z").unwrap())
    .capability_context(
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported),
    )
    .facet(
        "command.text",
        SemanticFacet::new(JsonValue::string(command)),
    )
    .unwrap()
    .fact_metadata(
        "command.text",
        FactMetadata::new(FactProvenance::Parsed, Sensitivity::Normal).unwrap(),
    )
    .fact_metadata(
        "tool.arguments",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    )
    .build()
    .unwrap()
}

/// The target is the kind of the tool a record names: a declared shell record
/// that names none has no kind, in either consumer, so the rule's kind clause
/// does not select it. Its `command` clause still reads its command text.
#[test]
fn a_record_that_names_no_tool_has_no_kind_and_is_credited_by_its_command_only() {
    let plain = nameless("printf synthetic");
    assert_eq!(selector_kind(&plain), None);
    assert_eq!(view_tool_kind(&plain), None);
    assert!(!super::written_path_tests::session_rule_ids(&plain).contains(&SHELL.to_owned()));
    assert!(!super::written_path_tests::action_rule_ids(plain).contains(&SHELL.to_owned()));
    let wrapped = nameless("bash -lc 'printf synthetic'");
    assert_eq!(selector_kind(&wrapped), None);
    assert_eq!(view_tool_kind(&wrapped), None);
    assert!(super::written_path_tests::session_rule_ids(&wrapped).contains(&SHELL.to_owned()));
}

const SHELL: &str = "execution.shell";

const CUSTOM_RULES: &str = r#"
title: synthetic
id: 563b9d31-64ab-4f9f-8d9a-a084c9a0126c
name: synthetic.by_name
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.name|re|i: '^probe$'
    condition: selection
level: low
telltale:
    category: synthetic
    score: 1
    explanation: 'synthetic'
---
title: synthetic
id: 4bdba06f-0ef6-4205-8428-ae4cba9252a8
name: synthetic.by_kind
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.kind|re|i: '^(delegate|web)$'
    condition: selection
level: low
telltale:
    category: synthetic
    score: 1
    explanation: 'synthetic'
"#;

/// A custom rule may select on either target, in a session scan and in an
/// action reading alike.
#[test]
fn custom_rules_select_on_tool_name_and_on_tool_kind_in_both_consumers() {
    let export = telltale_rules::load_rule_set_from_documents(&[CUSTOM_RULES], None)
        .unwrap()
        .compatibility_export();
    let plan = compile_rule_v1(&export).unwrap();
    let compiled = actions::compile(&export).unwrap();
    let cases = [
        (call("probe", None), vec!["synthetic.by_name"]),
        (
            call("task", Some(ToolKind::Delegate)),
            vec!["synthetic.by_kind"],
        ),
        (
            call("lookup", Some(ToolKind::Web)),
            vec!["synthetic.by_kind"],
        ),
        (
            call("probe", Some(ToolKind::Web)),
            vec!["synthetic.by_kind", "synthetic.by_name"],
        ),
        (call("view", Some(ToolKind::FileRead)), vec![]),
        (call("synthetic_tool", None), vec![]),
        (call("Bash", None), vec![]),
    ];
    for (observation, expected) in cases {
        let mut session: Vec<_> = plan
            .detectors()
            .iter()
            .filter(|detector| {
                detector.evaluate(&observation).evaluation_status()
                    == EvaluationStatus::EvaluatedMatch
            })
            .map(|detector| detector.detector().id().to_owned())
            .collect();
        session.sort();
        let (findings, _) = actions::evaluate(
            &export,
            &compiled,
            &[&observation],
            &DetailedEvaluationOptions::default(),
            &mut RetentionBudget::new(),
        )
        .unwrap();
        let mut action: Vec<_> = findings
            .iter()
            .flat_map(|finding| finding.rule_ids().iter().cloned())
            .collect();
        action.sort();
        assert_eq!(session, expected, "session {observation:?}");
        assert_eq!(action, expected, "action {observation:?}");
    }
}
