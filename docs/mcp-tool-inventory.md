# MCP Tool Inventory

ADR emits MCP inventory as `activity` events when `telltale scan --emit-activity` or `telltale watch --emit-activity` is enabled.

The first implementation is static and local-only. It reads known MCP configuration files, normalizes configured server metadata, and emits one `activity` event per configured server with:

- `session_id = "mcp_inventory"`
- `tool_name = "mcp::<server_name>"`
- tags including `mcp`, `mcp_inventory`, and either `mcp_inventory_supported` or `mcp_inventory_unsupported`
- evidence field `mcp_server_inventory` with server name, transport, redacted command/package details, URL host, argument count, environment variable names, declared tool names when present, and support status

ADR does not connect to MCP servers during scan. That keeps the batch scanner side-effect free and avoids executing arbitrary configured commands. Actual tool names are only emitted when a local config or exported inventory payload explicitly declares a `tools` array. Otherwise ADR reports the configured MCP server as installed tooling and leaves runtime tool enumeration to later active-inspection work.

## Supported Static Config Sources

| Client | Static config path | Status | Notes |
| --- | --- | --- | --- |
| Codex | `.codex/config.toml` | supported | Reads `[mcp_servers.<name>]` and `[mcp.servers.<name>]` sections with `command`, `url`, `type`/`transport`, and `args` metadata. |
| Claude Code | `.claude.json`, `.mcp.json`, workspace `.mcp.json` within depth 4 | supported | Reads `mcpServers`, `mcp_servers`, and `mcp.servers` JSON objects. |
| Gemini CLI | `.gemini/settings.json` | supported | Reads common JSON MCP server objects when present. |
| OpenCode | `.config/opencode/opencode.json` | supported | Reads common JSON MCP server objects when present. |
| OpenClaw | `.openclaw/config.json` | supported | Reads common JSON MCP server objects when present. |
| Qwen CLI | `.qwen/settings.json` | supported | Reads common JSON MCP server objects when present. |
| RooCode | VS Code extension settings | not yet supported | Configuration storage varies by VS Code profile and extension version; session parsing remains supported. |
| KiloCode | VS Code extension settings | not yet supported | Configuration storage varies by VS Code profile and extension version; session parsing remains supported. |
| GitHub Copilot | Copilot MCP configuration | not yet supported | ADR currently supports Copilot process-log activity, but not static MCP config inventory. |

## Open Source Enumeration Reference

The open MCP ecosystem already has active enumeration tooling. The official MCP Inspector supports `tools/list`, `resources/list`, and `prompts/list` over stdio, SSE, and streamable HTTP transports. ADR's static inventory deliberately stops before that active connection step; a future optional command can reuse the same normalized event shape for inspector-style `tools/list` output.

## Unsupported And Lossy Fields

- Env values are never emitted; ADR only records env variable names.
- Full command lines are redacted when they look likely to carry inline secrets.
- TOML parsing is intentionally narrow for Codex MCP server sections and should be replaced with a full parser only if the dependency and lockfile impact are accepted.
- Runtime MCP tool enumeration, resources, prompts, OAuth state, and server capability negotiation are not performed by the scanner today.
