#!/usr/bin/env node
// Disposable stdio MCP server for real-harness tests. No dependencies.
//
// Exposes one tool, `touch_canary`, that creates an empty file named `name`
// in E2E_WORK (or the current directory) and records `note` next to it. The
// file is ground truth for execution: it exists only if Claude Code actually
// ran the MCP call. The model is asked to put a marker string in `note`, so
// the test can check that Telltale evaluates MCP tool arguments.
//
// Protocol: JSON-RPC 2.0, one message per line on stdin/stdout (MCP stdio).
"use strict";
const fs = require("fs");
const path = require("path");

const work = process.env.E2E_WORK || process.cwd();
const TOOL = {
  name: "touch_canary",
  description:
    "Create an empty canary file in the sandbox working directory. Use `note` for the exact text the test asks you to record.",
  inputSchema: {
    type: "object",
    properties: {
      name: { type: "string", description: "File name (no directories)" },
      note: { type: "string", description: "Text recorded next to the file" },
    },
    required: ["name"],
  },
};

function send(message) {
  process.stdout.write(JSON.stringify(message) + "\n");
}

function reply(id, result) {
  send({ jsonrpc: "2.0", id, result });
}

function fail(id, code, message) {
  send({ jsonrpc: "2.0", id, error: { code, message } });
}

function handle(request) {
  const { id, method, params } = request;
  switch (method) {
    case "initialize":
      return reply(id, {
        protocolVersion: (params && params.protocolVersion) || "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "tth-canary", version: "0.1.0" },
      });
    case "ping":
      return reply(id, {});
    case "tools/list":
      return reply(id, { tools: [TOOL] });
    case "tools/call": {
      const args = (params && params.arguments) || {};
      if (!params || params.name !== TOOL.name) {
        return fail(id, -32602, `unknown tool ${params && params.name}`);
      }
      const name = path.basename(String(args.name || "canary"));
      fs.writeFileSync(path.join(work, name), "");
      fs.writeFileSync(path.join(work, name + ".note"), String(args.note || ""));
      return reply(id, {
        content: [{ type: "text", text: `created ${name}` }],
        isError: false,
      });
    }
    default:
      if (id === undefined || id === null) return; // notification
      return fail(id, -32601, `method not found: ${method}`);
  }
}

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let newline;
  while ((newline = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (!line) continue;
    let request;
    try {
      request = JSON.parse(line);
    } catch {
      continue;
    }
    try {
      handle(request);
    } catch (error) {
      if (request.id !== undefined) fail(request.id, -32603, String(error));
    }
  }
});
process.stdin.on("end", () => process.exit(0));
