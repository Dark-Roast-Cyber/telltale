#!/usr/bin/env python3
"""GitHub Copilot CLI hook contract captures (capture tooling, not the adapter).

Runs `copilot -p` against the scripted mock model (BYOK, COPILOT_OFFLINE=true:
no GitHub credentials, no model tokens) with stub hooks in an isolated
COPILOT_HOME, and checks a canary file to see whether the harness honored each
hook decision.

Usage: capture-copilot.py [scenario ...]      (default: all)
Env:   COPILOT_BIN (default: copilot on PATH), CAPTURE_ROOT (default: mktemp)
Outputs per scenario: <root>/<scenario>/{hooks.jsonl, model-requests.jsonl, summary.json, stdout.txt, stderr.txt}
"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capture_common import HERE, STUB, Run, tool_results_seen_by_model  # noqa: E402

MCP = os.path.join(HERE, "mock-mcp.py")

BIN = os.environ.get("COPILOT_BIN", "copilot")
ROOT = os.environ.get("CAPTURE_ROOT") or tempfile.mkdtemp(prefix="capture-copilot-")
CAMEL = ["sessionStart", "sessionEnd", "userPromptSubmitted", "preToolUse", "postToolUse", "postToolUseFailure",
         "permissionRequest", "agentStop", "subagentStart", "subagentStop", "errorOccurred", "notification",
         "preCompact"]
PASCAL = ["PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "Stop", "SubagentStop"]


def hook(label, mode, timeout=30, command=None):
    cmd = command or f"{STUB} {label} {mode}"
    return {"type": "command", "bash": cmd, "timeoutSec": timeout}


def write_hooks(run, pre_mode="noop", fmt="camel", timeout=30, pre_command=None):
    hooks = {}
    if fmt in ("camel", "both"):
        for ev in CAMEL:
            pre = ev == "preToolUse"
            hooks[ev] = [hook(ev, pre_mode if pre else "noop", timeout, pre_command if pre else None)]
    if fmt in ("pascal", "both"):
        for ev in PASCAL:
            pre = ev == "PreToolUse"
            hooks[ev] = [hook("Pascal:" + ev, pre_mode if pre and fmt == "pascal" else "noop", timeout,
                              pre_command if pre and fmt == "pascal" else None)]
    d = os.path.join(run.home, ".copilot", "hooks")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "tth-capture.json"), "w") as f:
        json.dump({"version": 1, "hooks": hooks}, f, indent=1)


def canary_cmd(run, name="canary.txt"):
    return f"touch {run.canary(name)} && echo TTH_CANARY"


def copilot(run, prompt, flags, env_extra=None, model=None, offline=True):
    env = run.base_env(COPILOT_HOME=os.path.join(run.home, ".copilot"),
                       COPILOT_PROVIDER_BASE_URL=f"http://127.0.0.1:{run.port}/v1",
                       COPILOT_MODEL=model or os.environ.get("CAPTURE_MODEL", "gpt-5.4"),
                       COPILOT_PROVIDER_API_KEY="mock", COPILOT_AUTO_UPDATE="false",
                       **({"COPILOT_OFFLINE": "true"} if offline else {}), **(env_extra or {}))
    mcp = json.dumps({"mcpServers": {"tthmock": {"type": "local", "command": sys.executable,
                                                 "args": ["-I", MCP], "tools": ["*"]}}})
    argv = [BIN, "-p", prompt, "--no-auto-update", "--disable-builtin-mcps", "--log-level", "all",
            "--log-dir", os.path.join(run.dir, "logs"), "--additional-mcp-config", mcp, *flags]
    return run.run(argv, env)


def scenario(name, steps, pre_mode="noop", fmt="camel", flags=("--allow-all-tools",), expect=None,
             timeout=30, pre_command=None, env_extra=None, setup=None, note="", model=None, offline=True):
    run = Run(ROOT, name)
    marker = f"TTHSCN-{name}"
    if setup:
        setup(run)
    resolved = json.loads(json.dumps(steps).replace("@CANARY@", canary_cmd(run)).replace("@WORK@", run.work))
    run.start_mock({"conversations": [{"match": marker, "steps": resolved}]})
    write_hooks(run, pre_mode, fmt, timeout, pre_command)
    try:
        copilot(run, f"{marker}: follow the scripted steps.", list(flags), env_extra, model, offline)
    finally:
        run.stop()
    s = run.summary(expect=expect, note=note)
    seen = tool_results_seen_by_model(run)
    with open(os.path.join(run.dir, "tool-results-seen.json"), "w") as f:
        json.dump(seen, f, indent=1)
    return s


BASH = lambda cmd: {"name": "bash", "arguments": {"command": cmd, "description": "capture step"}}  # noqa: E731
CANARY = {"tool_calls": [BASH("@CANARY@")]}

SCENARIOS = {
    # Discover the tool list (model-requests.jsonl) without running tools.
    "explore": lambda: scenario("explore", [{"text": "nothing to do"}]),
    "explore-online": lambda: scenario("explore-online", [{"text": "nothing to do"}], offline=False,
                                       model="claude-sonnet-5.5"),
    # Payload shapes for common tools, camelCase and PascalCase registrations at once.
    "lifecycle": lambda: scenario("lifecycle", [
        {"tool_calls": [BASH("echo hello > out.txt")]},
        {"tool_calls": [{"name": "view", "arguments": {"path": "@WORK@/out.txt"}}]},
        {"tool_calls": [{"name": "create", "arguments": {"path": "@WORK@/new.txt", "file_text": "created\n"}}]},
        {"tool_calls": [{"name": "edit", "arguments": {"path": "@WORK@/new.txt", "old_str": "created",
                                                         "new_str": "edited"}}]},
        {"tool_calls": [BASH("ls /nonexistent-dir-for-capture")]},
        {"tool_calls": [BASH("echo parallel-a"), BASH("echo parallel-b")]},
        {"tool_calls": [{"name": "grep", "arguments": {"pattern": "hello"}}]},
        {"tool_calls": [{"name": "web_fetch", "arguments": {"url": "https://example.invalid/page"}}]},
        {"tool_calls": [{"name": "tthmock-echo", "arguments": {"text": "hi from mcp"}}]},
        {"text": "done"}], fmt="both", model="claude-sonnet-5.5", offline=False,
        flags=("--allow-all-tools", "--allow-all-paths", "--allow-all-urls")),
    # GPT-5 tool set: freeform apply_patch and rg.
    "lifecycle-patch": lambda: scenario("lifecycle-patch", [
        {"tool_calls": [{"name": "apply_patch", "custom": True, "input":
            "*** Begin Patch\n*** Add File: @WORK@/patched.txt\n+line one\n*** End Patch\n"}]},
        {"tool_calls": [{"name": "apply_patch", "custom": True, "input":
            "*** Begin Patch\n*** Update File: @WORK@/patched.txt\n@@\n-line one\n+line two\n*** End Patch\n"}]},
        {"tool_calls": [{"name": "rg", "arguments": {"pattern": "line"}}]},
        {"text": "done"}], fmt="both", flags=("--allow-all-tools", "--allow-all-paths")),
    # Deny forms (canary must be absent).
    "deny-flat": lambda: scenario("deny-flat", [CANARY], "deny-flat", expect="absent"),
    "deny-flat-yolo": lambda: scenario("deny-flat-yolo", [CANARY], "deny-flat", flags=("--yolo",), expect="absent"),
    "deny-flat-autopilot": lambda: scenario("deny-flat-autopilot", [CANARY], "deny-flat",
                                            flags=("--allow-all-tools", "--autopilot"), expect="absent"),
    "deny-pascal-hso": lambda: scenario("deny-pascal-hso", [CANARY], "deny-hso", fmt="pascal", expect="absent"),
    "deny-pascal-flat": lambda: scenario("deny-pascal-flat", [CANARY], "deny-flat", fmt="pascal", expect="absent"),
    "deny-camel-hso": lambda: scenario("deny-camel-hso", [CANARY], "deny-hso", note="Claude-style output on camelCase event"),
    "deny-exit2": lambda: scenario("deny-exit2", [CANARY], "exit2", expect="absent"),
    # Ask.
    "ask-flat": lambda: scenario("ask-flat", [CANARY], "ask-flat", note="-p with --allow-all-tools"),
    "ask-flat-autopilot": lambda: scenario("ask-flat-autopilot", [CANARY], "ask-flat",
                                           flags=("--allow-all-tools", "--autopilot")),
    "ask-flat-noallow": lambda: scenario("ask-flat-noallow", [CANARY], "ask-flat", flags=(),
                                         note="-p without --allow-all-tools"),
    # Allow: does it bypass the harness permission check? (no --allow-all-tools; tool would need approval)
    "allow-noallow": lambda: scenario("allow-noallow", [CANARY], "allow-flat", flags=(),
                                      note="hook allow without --allow-all-tools"),
    "noop-noallow": lambda: scenario("noop-noallow", [CANARY], "noop", flags=(),
                                     note="baseline: no hook opinion, no --allow-all-tools"),
    "noop-vs-denytool": lambda: scenario("noop-vs-denytool", [CANARY], "noop",
                                         flags=("--allow-all-tools", "--deny-tool=shell"),
                                         note="control: --deny-tool=shell with no hook opinion"),
    "allow-vs-denytool": lambda: scenario("allow-vs-denytool", [CANARY], "allow-flat",
                                          flags=("--allow-all-tools", "--deny-tool=shell"),
                                          note="hook allow against an explicit --deny-tool rule"),
    # Failure behavior.
    "fail-exit1": lambda: scenario("fail-exit1", [CANARY], "exit1"),
    "fail-crash": lambda: scenario("fail-crash", [CANARY], "crash"),
    "fail-invalid": lambda: scenario("fail-invalid", [CANARY], "invalid"),
    "fail-exit2-silent": lambda: scenario("fail-exit2-silent", [CANARY], "exit2-silent"),
    "fail-timeout": lambda: scenario("fail-timeout", [CANARY], "sleep:8,deny-flat", timeout=3),
    "fail-missing": lambda: scenario("fail-missing", [CANARY], pre_command="/nonexistent/tth-hook-binary"),
    # Agent-reachable hook disabling: repo settings with disableAllHooks (user-level deny hook installed).
    "disable-repo": lambda: scenario("disable-repo", [CANARY], "deny-flat", setup=repo_settings({"disableAllHooks": True}),
                                     note="untrusted folder"),
    "disable-repo-trusted": lambda: scenario("disable-repo-trusted", [CANARY], "deny-flat",
                                             flags=("--allow-all-tools", "--trust-folder"),
                                             setup=repo_settings({"disableAllHooks": True}), note="--trust-folder"),
    # Cross-tool: Claude Code hooks in the repo's .claude/settings.json (no user hooks configured).
    "claude-settings": lambda: claude_settings_scenario(),
    # Which .claude/settings.json events Copilot fires, and their shapes (every event the hooks'
    # Claude Code fragment registers, plus Stop), including inside a subagent.
    "claude-settings-all": lambda: claude_settings_all_scenario(),
    # Subagent: a task call whose child runs the canary-like command (recorded, not denied).
    "subagent": lambda: subagent_scenario("subagent", "noop", "camel"),
    "subagent-deny": lambda: subagent_scenario("subagent-deny", "deny-flat", "camel", expect="absent"),
}


def repo_settings(obj):
    def setup(run):
        d = os.path.join(run.work, ".github", "copilot")
        os.makedirs(d)
        with open(os.path.join(d, "settings.json"), "w") as f:
            json.dump(obj, f)
    return setup


def claude_settings_scenario():
    run = Run(ROOT, "claude-settings")
    marker = "TTHSCN-claude-settings"
    d = os.path.join(run.work, ".claude")
    os.makedirs(d)
    with open(os.path.join(d, "settings.json"), "w") as f:
        json.dump({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": f"{STUB} claude:PreToolUse deny-hso"}]}]}}, f)
    run.start_mock({"conversations": [{"match": marker, "steps": [CANARY_STEP(run)]}]})
    try:
        copilot(run, f"{marker}: follow the scripted steps.", ["--allow-all-tools", "--trust-folder"])
    finally:
        run.stop()
    return run.summary(note=".claude/settings.json PreToolUse deny-hso, --trust-folder, no Copilot hooks")


CLAUDE_EVENTS = ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "PostToolBatch",
                 "PermissionRequest", "SessionEnd", "SubagentStart", "SubagentStop", "Stop", "Notification"]


def claude_settings_all_scenario():
    run = Run(ROOT, "claude-settings-all")
    # Its own repository root, so Copilot reads this .claude/settings.json even when CAPTURE_ROOT is in a repo.
    subprocess.run(["git", "init", "-q", run.work], check=True)
    marker, child = "TTHSCN-csa", "TTHCHILD-csa"
    tool_events = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest")
    hooks = {}
    for ev in CLAUDE_EVENTS:
        entry = {"type": "command", "command": f"{STUB} claude:{ev} noop", "timeout": 30}
        hooks[ev] = [{"matcher": "*", "hooks": [entry]}] if ev in tool_events else [{"hooks": [entry]}]
    os.makedirs(os.path.join(run.work, ".claude"))
    with open(os.path.join(run.work, ".claude", "settings.json"), "w") as f:
        json.dump({"hooks": hooks}, f)
    run.start_mock({"conversations": [
        {"match": child, "steps": [{"tool_calls": [BASH("echo child")]}, {"text": "child done"}]},
        {"match": marker, "steps": [
            {"tool_calls": [BASH("echo parent")]},
            {"tool_calls": [{"name": "task", "arguments": {
                "description": "child capture", "agent_type": "task", "name": "child",
                "prompt": f"{child}: run the scripted step."}}]},
            {"text": "parent done"}]}]})
    try:
        copilot(run, f"{marker}: follow the scripted steps.", ["--allow-all-tools", "--trust-folder"])
    finally:
        run.stop()
    return run.summary(note=".claude/settings.json registers every Claude Code event, --trust-folder, no Copilot hooks")


def CANARY_STEP(run):
    return {"tool_calls": [BASH(canary_cmd(run))]}


def subagent_scenario(name, mode, fmt, expect=None):
    run = Run(ROOT, name)
    marker, child = f"TTHSCN-{name}", f"TTHCHILD-{name}"
    run.start_mock({"conversations": [
        {"match": child, "steps": [{"tool_calls": [BASH(canary_cmd(run))]}, {"text": "child done"}]},
        {"match": marker, "steps": [
            {"tool_calls": [{"name": "task", "arguments": {
                "description": "child capture", "agent_type": "task", "name": "child",
                "prompt": f"{child}: run the scripted step."}}]},
            {"text": "parent done"}]}]})
    write_hooks(run, mode, "both" if mode == "noop" else fmt)
    try:
        copilot(run, f"{marker}: follow the scripted steps.", ["--allow-all-tools"])
    finally:
        run.stop()
    return run.summary(expect=expect)


if __name__ == "__main__":
    names = sys.argv[1:] or list(SCENARIOS)
    print(f"# root: {ROOT}", file=sys.stderr)
    for n in names:
        SCENARIOS[n]()
