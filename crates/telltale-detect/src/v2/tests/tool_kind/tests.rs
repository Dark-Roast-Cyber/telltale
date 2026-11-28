use super::*;
use telltale_schema::clients::ClientId;

const CLIENTS_WITH_A_SHELL_ROW: [ClientId; 6] = [
    ClientId::Claude,
    ClientId::Codex,
    ClientId::Copilot,
    ClientId::OpenCode,
    ClientId::Qwen,
    ClientId::OpenClaw,
];

/// A source's table never declares a kind other than shell for a name the
/// shell-execution rule once selected: a declaration cannot lose a match the
/// name gave.
#[test]
fn no_table_row_on_the_old_shell_name_list_declares_another_kind() {
    let rows = telltale_sources::declared_tools();
    assert!(rows.iter().any(|row| row.kind == ToolKind::Shell));
    for row in rows {
        if is_shell_tool(row.name) {
            assert_eq!(row.kind, ToolKind::Shell, "{:?} {}", row.client, row.name);
        }
    }
}

fn plan() -> super::super::super::RuleV1CompatibilityPlan {
    let rules = telltale_rules::load_default_rule_set().expect("bundled rules");
    compile_rule_v1(&rules.compatibility_export()).expect("bundled plan")
}

fn fires(
    plan: &super::super::super::RuleV1CompatibilityPlan,
    rule: &str,
    o: &CanonicalObservationV2,
) -> bool {
    plan.detectors()
        .iter()
        .filter(|detector| detector.detector().id() == rule)
        .any(|detector| {
            detector.evaluate(o).evaluation_status() == EvaluationStatus::EvaluatedMatch
        })
}

/// Credit for shell execution follows the kind a source declares: every
/// client with a shell row gets it for each of those rows, whatever the
/// call's text, and not for its tools of another kind.
#[test]
fn shell_execution_fires_by_declared_kind_for_each_client_and_not_for_its_other_tools() {
    let plan = plan();
    let rows = telltale_sources::declared_tools();
    for client in CLIENTS_WITH_A_SHELL_ROW {
        let own: Vec<_> = rows.iter().filter(|row| row.client == client).collect();
        let shell: Vec<_> = own
            .iter()
            .filter(|row| row.kind == ToolKind::Shell)
            .collect();
        let other: Vec<_> = own
            .iter()
            .filter(|row| row.kind != ToolKind::Shell)
            .collect();
        assert!(!shell.is_empty() && !other.is_empty(), "{client:?}");
        for row in shell {
            let observation = declared_tool(
                "shell",
                row.name,
                json!({"command": "printf synthetic", "cmd": "printf synthetic"}),
                ToolOperation::new(row.kind),
            );
            assert!(
                fires(&plan, "execution.shell", &observation),
                "{client:?} {}",
                row.name
            );
        }
        for row in other {
            // Neither the name nor the text is a shell's.
            assert!(!is_shell_tool(row.name), "{client:?} {}", row.name);
            let observation = declared_tool(
                "other",
                row.name,
                json!({"path": "/synthetic/a.txt", "url": "https://example.invalid/a"}),
                ToolOperation::new(row.kind),
            );
            assert!(
                !fires(&plan, "execution.shell", &observation),
                "{client:?} {}",
                row.name
            );
        }
    }
}

/// A call with no declaration is credited by the names the rule selected,
/// and by nothing else.
#[test]
fn shell_execution_fires_for_an_undeclared_shell_name_and_not_for_other_names() {
    let plan = plan();
    for name in ["shell", "exec_command", "shell_command", "Bash", "cmd.exe"] {
        let observation = file_tool("name", name, json!({"x": "printf synthetic"}));
        assert!(fires(&plan, "execution.shell", &observation), "{name}");
    }
    for name in ["read_file", "shell_help", "mcp__shell", "bashful", "probe"] {
        let observation = file_tool("name", name, json!({"x": "printf synthetic"}));
        assert!(!fires(&plan, "execution.shell", &observation), "{name}");
    }
}
