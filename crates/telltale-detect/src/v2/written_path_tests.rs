use super::rule_v1::evaluate_rule_v1_session_with_budget;
use super::session::RetentionBudget;
use super::*;
use telltale_schema::clients::ClientId;
use telltale_schema::observation::*;

const PERSISTENCE: &str = "persistence.shell_profile";

/// A native file-tool call with the given name and JSON arguments.
pub(super) fn file_tool(
    id: &str,
    name: &str,
    arguments: serde_json::Value,
) -> CanonicalObservationV2 {
    call(id, name, arguments, None)
}

/// A shell call, with the command facet adapters derive from its arguments.
pub(super) fn shell(id: &str, command: &str) -> CanonicalObservationV2 {
    call(
        id,
        "Bash",
        serde_json::json!({ "command": command }),
        Some(command),
    )
}

fn call(
    id: &str,
    name: &str,
    arguments: serde_json::Value,
    command: Option<&str>,
) -> CanonicalObservationV2 {
    let mut builder = CanonicalObservationV2::builder(
        ObservationBody::Tool(
            ToolObservation::new()
                .with_name(name)
                .unwrap()
                .with_arguments(JsonValue::try_from_source_value(&arguments).unwrap()),
        ),
        ObservationStage::ToolRequested,
        ObservedAt::new("2026-09-18T00:00:00Z").unwrap(),
        SourceProvenance::new(
            IngestionMode::SessionStore,
            "claude_code",
            "claude.projects",
            Fidelity::FullNative,
        )
        .unwrap()
        .with_native_id(id)
        .unwrap(),
    )
    .session_id(CorrelationId::source_reported("synthetic-session").unwrap())
    .occurred_at(SourceTimestamp::new("2026-09-17T00:00:00Z").unwrap())
    .capability_context(
        CapabilityContext::new()
            .with_override(CapabilityId::ToolCall, CapabilityAvailability::Supported),
    )
    .fact_metadata(
        "tool.name",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    )
    .fact_metadata(
        "tool.arguments",
        FactMetadata::new(FactProvenance::Reported, Sensitivity::Normal).unwrap(),
    );
    // Adapters derive the resource path from a `file_path` argument.
    if let Some(path) = arguments
        .get("file_path")
        .and_then(serde_json::Value::as_str)
    {
        builder = builder
            .facet("resource.path", SemanticFacet::new(JsonValue::string(path)))
            .unwrap()
            .fact_metadata(
                "resource.path",
                FactMetadata::new(FactProvenance::Parsed, Sensitivity::Normal).unwrap(),
            );
    }
    if let Some(command) = command {
        builder = builder
            .facet(
                "command.text",
                SemanticFacet::new(JsonValue::string(command)),
            )
            .unwrap()
            .fact_metadata(
                "command.text",
                FactMetadata::new(FactProvenance::Parsed, Sensitivity::Normal).unwrap(),
            );
    }
    builder.build().unwrap()
}

fn written_path(observation: &CanonicalObservationV2) -> Option<String> {
    let resolution = SelectorRegistry::new()
        .resolve(SelectorId::CompatWrittenPath, observation)
        .unwrap();
    match resolution.value() {
        Some(JsonValue::String(path)) if resolution.is_present() => Some(path.clone()),
        _ => None,
    }
}

pub(super) fn session_rule_ids(observation: &CanonicalObservationV2) -> Vec<String> {
    let rules = telltale_rules::load_default_rule_set().unwrap();
    let plan = compile_rule_v1(&rules.compatibility_export()).unwrap();
    evaluate_rule_v1_session_with_budget(&plan, &[observation], &mut RetentionBudget::new())
        .unwrap()
        .effective_rule_ids()
        .to_vec()
}

pub(super) fn action_rule_ids(observation: CanonicalObservationV2) -> Vec<String> {
    let rules = telltale_rules::load_default_rule_set().unwrap();
    let plan = compile_rule_v1(&rules.compatibility_export()).unwrap();
    let instance = CorrelationId::source_reported("synthetic-source").unwrap();
    let output = evaluate_source_with_options(
        CanonicalSourceInput {
            client: ClientId::Claude,
            source_id: "claude.projects",
            source_instance: Some(&instance),
            observations: &[observation],
        },
        &plan,
        None,
        &DetailedEvaluationOptions::default(),
    )
    .unwrap();
    output.sessions()[0]
        .action_findings()
        .iter()
        .flat_map(|finding| finding.rule_ids().iter().cloned())
        .collect()
}

fn writes() -> Vec<CanonicalObservationV2> {
    vec![
        file_tool(
            "write",
            "Write",
            serde_json::json!({"file_path": "/home/synthetic/.bashrc", "content": "alias ll='ls -l'\n"}),
        ),
        file_tool(
            "edit",
            "edit",
            serde_json::json!({"filePath": "/home/synthetic/.zshrc", "oldString": "a", "newString": "b"}),
        ),
        file_tool(
            "create",
            "str_replace_based_edit_tool",
            serde_json::json!({"command": "create", "path": "/home/synthetic/.profile", "file_text": "export X=1\n"}),
        ),
        // A known write tool whose record kept only the path.
        file_tool(
            "path-only",
            "write_file",
            serde_json::json!({"path": "~/.bash_profile"}),
        ),
        // Arguments a native envelope carries as an encoded object.
        file_tool(
            "encoded",
            "fs_write",
            serde_json::Value::String(
                r#"{"path":"/home/synthetic/.config/fish/config.fish","content":"set -x X 1"}"#
                    .to_owned(),
            ),
        ),
    ]
}

fn reads() -> Vec<CanonicalObservationV2> {
    vec![
        file_tool(
            "read",
            "Read",
            serde_json::json!({"file_path": "/home/synthetic/.bashrc"}),
        ),
        file_tool(
            "view",
            "str_replace_based_edit_tool",
            serde_json::json!({"command": "view", "path": "/home/synthetic/.zshrc"}),
        ),
        file_tool(
            "grep",
            "Grep",
            serde_json::json!({"pattern": "PATH", "path": "/home/synthetic/.bashrc"}),
        ),
        file_tool(
            "read-file",
            "read_file",
            serde_json::Value::String(r#"{"absolute_path":"/home/synthetic/.profile"}"#.to_owned()),
        ),
    ]
}

#[test]
fn written_path_names_only_the_files_a_call_writes() {
    let paths = writes().iter().map(written_path).collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            Some("/home/synthetic/.bashrc".to_owned()),
            Some("/home/synthetic/.zshrc".to_owned()),
            Some("/home/synthetic/.profile".to_owned()),
            Some("~/.bash_profile".to_owned()),
            Some("/home/synthetic/.config/fish/config.fish".to_owned()),
        ]
    );
    for read in reads() {
        assert_eq!(written_path(&read), None);
    }
    assert_eq!(
        SelectorId::CompatWrittenPath.required_capability(),
        Some(CapabilityId::ToolCall)
    );
}

#[test]
fn native_startup_file_writes_are_persistence_and_reads_are_not() {
    for write in writes() {
        assert!(session_rule_ids(&write).iter().any(|id| id == PERSISTENCE));
        assert!(action_rule_ids(write).iter().any(|id| id == PERSISTENCE));
    }
    for read in reads() {
        assert!(!session_rule_ids(&read).iter().any(|id| id == PERSISTENCE));
        assert!(!action_rule_ids(read).iter().any(|id| id == PERSISTENCE));
    }
}

#[test]
fn startup_file_paths_in_shell_reads_are_not_persistence() {
    let read = shell("shell-read", "grep -n PATH ~/.bashrc");
    assert!(!session_rule_ids(&read).iter().any(|id| id == PERSISTENCE));
    assert!(!action_rule_ids(read).iter().any(|id| id == PERSISTENCE));
    let write = shell("shell-write", "echo 'alias ll=ls' >> ~/.bashrc");
    assert!(session_rule_ids(&write).iter().any(|id| id == PERSISTENCE));
    assert!(action_rule_ids(write).iter().any(|id| id == PERSISTENCE));
}
