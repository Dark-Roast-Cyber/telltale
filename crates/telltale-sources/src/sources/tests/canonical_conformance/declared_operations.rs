use super::*;

#[test]
fn every_registered_source_declares_its_write_read_and_shell_operations() {
    use telltale_schema::observation::ToolKind;
    for client in crate::clients::supported_clients() {
        for definition in client.sources {
            #[cfg(not(feature = "opencode-sqlite"))]
            if definition.id == "opencode.sqlite" {
                continue;
            }
            let (observations, read_tool, _directory) =
                declared_fixture(client.id, definition.id, definition.kind);
            let operations = observations
                .iter()
                .filter(|observation| observation.stage() == ObservationStage::ToolRequested)
                .filter_map(|observation| match observation.body() {
                    ObservationBody::Tool(tool) => tool.operation(),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let id = definition.id;
            // Operands are copies of the arguments they were read from.
            for observation in &observations {
                if let ObservationBody::Tool(tool) = observation.body()
                    && let Some(operation) = tool.operation()
                {
                    let operands: usize = [
                        operation.commands(),
                        operation.written_paths(),
                        operation.read_paths(),
                        operation.urls(),
                    ]
                    .into_iter()
                    .flatten()
                    .map(String::len)
                    .sum();
                    let arguments = tool
                        .arguments()
                        .map_or(0, |arguments| arguments.encoded_byte_len().unwrap());
                    assert!(
                        operands <= arguments,
                        "{id}: operands exceed their arguments"
                    );
                }
            }
            assert!(
                operations
                    .iter()
                    .any(|operation| operation.kind() == ToolKind::FileWrite
                        && operation.written_paths() == [WRITTEN]),
                "{id}: a write declares its written path"
            );
            assert!(
                operations
                    .iter()
                    .any(|operation| operation.kind() == ToolKind::Shell
                        && operation
                            .commands()
                            .iter()
                            .any(|command| command == COMMAND)),
                "{id}: a shell call declares its command"
            );
            if read_tool {
                assert!(
                    operations
                        .iter()
                        .any(|operation| operation.kind() == ToolKind::FileRead
                            && operation.read_paths() == [READ]),
                    "{id}: a read declares its read path"
                );
            } else {
                // The source has no read tool of its own; reads are shell
                // commands, whose text carries the path.
                assert!(
                    operations.iter().any(|operation| operation
                        .commands()
                        .iter()
                        .any(|command| command.contains(READ))),
                    "{id}: a read through the shell declares its command"
                );
            }
        }
    }
}

#[test]
fn mcp_shaped_tool_calls_keep_their_names_and_are_never_declared_as_builtins() {
    let mcp_tool = "mcp__fixture_docs__search_pages";
    let (dir, path) = {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("mcp-conformance.jsonl");
        let content = assistant_tools(&[(mcp_tool, serde_json::json!({"query": "synthetic"}))]);
        fs::write(&path, content).expect("fixture");
        (directory, path)
    };
    let batch = crate::acquisition::acquire_source(
        &source(ClientId::Claude, "claude.projects", SourceKind::Jsonl, path),
        crate::acquisition::AcquisitionOptions::new(
            ObservedAt::new(OBSERVED_AT).expect("observed time"),
        ),
    )
    .expect("Claude MCP conformance fixture");
    drop(dir);
    let requested = batch
        .observations
        .iter()
        .find_map(|obs| match obs.body() {
            ObservationBody::Tool(tool) if obs.stage() == ObservationStage::ToolRequested => {
                Some(tool)
            }
            _ => None,
        })
        .expect("MCP tool request");
    assert_eq!(requested.name(), Some(mcp_tool));
    assert!(
        requested.operation().is_none(),
        "MCP tool call must never inherit a built-in ToolOperation declaration"
    );
    assert_eq!(
        batch
            .accounting
            .sessions
            .iter()
            .flat_map(|s| s.counts.tool_usage.keys())
            .filter(|name| name.as_str() == mcp_tool)
            .count(),
        1
    );
}
