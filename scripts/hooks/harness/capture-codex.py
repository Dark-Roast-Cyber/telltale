#!/usr/bin/env python3
"""OpenAI Codex CLI hook contract captures (capture tooling, not the adapter).

Runs `codex exec` against the scripted mock model (custom model provider over
the Responses API: no OpenAI credentials, no model tokens) with stub hooks in an
isolated CODEX_HOME, and checks a canary file to see whether the harness
honored each hook decision. `REAL_MODEL=1` instead uses the default OpenAI
provider with the auth.json found in CODEX_AUTH_HOME (symlinked, never copied).

Usage: capture-codex.py [scenario ...]      (default: all mock scenarios)
Env:   CODEX_BIN (default: codex on PATH), CAPTURE_ROOT (default: mktemp)
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capture_common import HERE, STUB, Run, tool_results_seen_by_model  # noqa: E402

BIN = os.environ.get("CODEX_BIN", "codex")
ROOT = os.environ.get("CAPTURE_ROOT") or tempfile.mkdtemp(prefix="capture-codex-")
MCP = os.path.join(HERE, "mock-mcp.py")
EVENTS = ["SessionStart", "SessionEnd", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse",
          "SubagentStart", "SubagentStop", "Stop", "Interrupt", "PreCompact", "PostCompact"]
YOLO = ("--dangerously-bypass-approvals-and-sandbox",)


def write_config(run, codex_home, pre_mode, timeout, pre_command, model, real):
    hooks = {}
    for ev in EVENTS:
        pre = ev == "PreToolUse"
        cmd = (pre_command if pre and pre_command else f"{STUB} {ev} {pre_mode if pre else 'noop'}")
        hooks[ev] = [{"hooks": [{"type": "command", "command": cmd, "timeout": timeout}]}]
    with open(os.path.join(codex_home, "hooks.json"), "w") as f:
        json.dump({"hooks": hooks}, f, indent=1)
    lines = [f'model = "{model}"', "check_for_update_on_startup = false",
             f'[mcp_servers.tthmock]\ncommand = "{sys.executable}"\nargs = ["-I", "{MCP}"]']
    if not real:
        lines.insert(1, 'model_provider = "mock"')
        lines.append(f'[model_providers.mock]\nname = "mock"\nbase_url = "http://127.0.0.1:{run.port}/v1"\n'
                     'wire_api = "responses"\nrequest_max_retries = 0\nstream_max_retries = 0')
    with open(os.path.join(codex_home, "config.toml"), "w") as f:
        f.write("\n".join(lines) + "\n")


def scenario(name, steps, pre_mode="noop", flags=YOLO, expect=None, timeout=30, pre_command=None,
             model="gpt-5.5", trust=True, note="", child=None, real_prompt=None, setup=None, env_extra=None):
    real = bool(real_prompt)
    run = Run(ROOT, name)
    codex_home = os.path.join(run.home, ".codex")
    os.makedirs(codex_home)
    if real:  # point at existing credentials in place, never copy them
        os.symlink(os.path.join(os.environ["CODEX_AUTH_HOME"], "auth.json"), os.path.join(codex_home, "auth.json"))
    marker = f"TTHSCN-{name}"
    canary = f"touch {run.canary()} && echo TTH_CANARY"
    if setup:
        setup(run)
    convs = []
    if child:
        convs.append({"match": f"TTHCHILD-{name}", "steps": json.loads(json.dumps(child).replace("@CANARY@", canary))})
    convs.append({"match": marker, "steps": json.loads(
        json.dumps(steps).replace("@CANARY@", canary).replace("@WORK@", run.work).replace("@CHILD@", f"TTHCHILD-{name}"))})
    if not real:
        run.start_mock({"conversations": convs})
    write_config(run, codex_home, pre_mode, timeout, pre_command, model, real)
    env = run.base_env(CODEX_HOME=codex_home, **(env_extra or {}))
    argv = [BIN, "exec", "--skip-git-repo-check", "--json", *flags]
    if trust:
        argv.append("--dangerously-bypass-hook-trust")
    prompt = real_prompt.replace("@CANARY@", canary) if real else f"{marker}: follow the scripted steps."
    argv.append(prompt)
    try:
        run.run(argv, env, timeout=240)
    finally:
        run.stop()
        if real:
            os.unlink(os.path.join(codex_home, "auth.json"))
    s = run.summary(expect=expect, note=note)
    with open(os.path.join(run.dir, "tool-results-seen.json"), "w") as f:
        json.dump(tool_results_seen_by_model(run), f, indent=1)
    return s


def rules(decision):
    def setup(run):
        d = os.path.join(run.home, ".codex", "rules")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "default.rules"), "w") as f:
            f.write(f'prefix_rule(pattern=["touch"], decision="{decision}", justification="capture test")\n')
    return setup


def EXEC(cmd):
    return {"name": "exec_command", "arguments": {"cmd": cmd}}


def SHELL(argv):
    return {"name": "shell", "arguments": {"command": argv}}


CANARY = {"tool_calls": [EXEC("@CANARY@")]}
PATCH_ADD = "*** Begin Patch\n*** Add File: @WORK@/patched.txt\n+line one\n*** End Patch\n"
PATCH_UPD = "*** Begin Patch\n*** Update File: @WORK@/patched.txt\n@@\n-line one\n+line two\n*** End Patch\n"

SCENARIOS = {
    "explore": lambda: scenario("explore", [{"text": "nothing to do"}]),
    "explore-mock-model": lambda: scenario("explore-mock-model", [{"text": "nothing to do"}], model="mock-model"),
    "lifecycle": lambda: scenario("lifecycle", [
        {"tool_calls": [EXEC("echo hello > out.txt")]},
        {"tool_calls": [{"name": "apply_patch", "custom": True, "input": PATCH_ADD}]},
        {"tool_calls": [{"name": "apply_patch", "custom": True, "input": PATCH_UPD}]},
        {"tool_calls": [EXEC("ls /nonexistent-dir-for-capture")]},
        {"tool_calls": [EXEC("echo parallel-a"), EXEC("echo parallel-b")]},
        {"tool_calls": [{"name": "echo", "namespace": "mcp__tthmock", "arguments": {"text": "hi from mcp"}}]},
        {"text": "done"}]),
    # Real model (REAL: costs tokens; needs CODEX_AUTH_HOME). Confirms the mock-driven shapes.
    "real-deny": lambda: scenario("real-deny", [], "deny-hso", expect="absent",
                                  model=os.environ.get("REAL_CODEX_MODEL", "gpt-6.1-sol"), real_prompt=(
        "This is a disposable test directory. Run exactly this shell command once, verbatim, with your shell "
        "tool: @CANARY@ . If it is blocked, do not retry and do not run anything else; reply BLOCKED. "
        "Otherwise reply RAN.")),
    # Which failures still produce PostToolUse? (bad patch, missing binary, unknown MCP tool, parallel deny)
    "lifecycle-failures": lambda: scenario("lifecycle-failures", [
        {"tool_calls": [{"name": "apply_patch", "custom": True, "input":
                         "*** Begin Patch\n*** Update File: @WORK@/missing.txt\n@@\n-a\n+b\n*** End Patch\n"}]},
        {"tool_calls": [EXEC("/nonexistent/binary-for-capture")]},
        {"tool_calls": [{"name": "nope", "namespace": "mcp__tthmock", "arguments": {}}]},
        {"tool_calls": [EXEC("@CANARY@"), EXEC("echo sibling-ran")]},
        {"text": "done"}], pre_mode="deny-hso"),
    "explore-no-unified-exec": lambda: scenario("explore-no-unified-exec", [{"text": "nothing to do"}],
                                                flags=YOLO + ("--disable", "unified_exec")),
    "lifecycle-shell": lambda: scenario("lifecycle-shell", [
        {"tool_calls": [SHELL(["bash", "-lc", "echo argv-form > argv.txt"])]},
        {"tool_calls": [{"name": "shell_command", "arguments": {"command": "echo string-form"}}]},
        {"text": "done"}], flags=YOLO + ("--disable", "unified_exec")),
    # Deny forms.
    "deny-hso": lambda: scenario("deny-hso", [CANARY], "deny-hso", expect="absent"),
    "deny-legacy": lambda: scenario("deny-legacy", [CANARY], "block-legacy", expect="absent"),
    "deny-exit2": lambda: scenario("deny-exit2", [CANARY], "exit2", expect="absent"),
    "deny-flat": lambda: scenario("deny-flat", [CANARY], "deny-flat", note="Copilot-style flat output"),
    # Approval / sandbox modes with deny.
    "deny-hso-default": lambda: scenario("deny-hso-default", [CANARY], "deny-hso", flags=(), expect="absent",
                                         note="codex exec defaults"),
    "deny-hso-fullauto": lambda: scenario("deny-hso-fullauto", [CANARY], "deny-hso",
                                          flags=("-s", "workspace-write", "-c", 'approval_policy="on-request"'),
                                          expect="absent"),
    # Ask / allow.
    "ask-hso": lambda: scenario("ask-hso", [CANARY], "ask-hso"),
    "ask-hso-onrequest": lambda: scenario("ask-hso-onrequest", [CANARY], "ask-hso",
                                          flags=("-s", "workspace-write", "-c", 'approval_policy="on-request"')),
    "ask-hso-debug": lambda: scenario("ask-hso-debug", [CANARY], "ask-hso",
                                      env_extra={"RUST_LOG": "codex_hooks=debug,codex_core=info"}),
    "allow-hso": lambda: scenario("allow-hso", [CANARY], "allow-hso"),
    # Exec-policy rules vs hook allow (Codex accepts allow only together with updatedInput).
    "rule-forbidden-noop": lambda: scenario("rule-forbidden-noop", [CANARY], "noop", setup=rules("forbidden"),
                                            note="baseline: execpolicy forbidden"),
    "rule-forbidden-allow": lambda: scenario("rule-forbidden-allow", [CANARY], "allow-updated-hso",
                                             setup=rules("forbidden"), note="hook allow+updatedInput vs forbidden"),
    "rule-prompt-noop": lambda: scenario("rule-prompt-noop", [CANARY], "noop", setup=rules("prompt"),
                                         flags=("-c", 'approval_policy="on-request"'),
                                         note="baseline: execpolicy prompt, on-request, no approver"),
    "rule-prompt-allow": lambda: scenario("rule-prompt-allow", [CANARY], "allow-updated-hso", setup=rules("prompt"),
                                          flags=("-c", 'approval_policy="on-request"'),
                                          note="hook allow+updatedInput vs prompt rule"),
    "rule-prompt-ask": lambda: scenario("rule-prompt-ask", [CANARY], "ask-hso", setup=rules("prompt"),
                                        flags=("-c", 'approval_policy="on-request"'),
                                        note="hook ask where Codex itself would prompt"),
    # Failures.
    "fail-exit1": lambda: scenario("fail-exit1", [CANARY], "exit1"),
    "fail-crash": lambda: scenario("fail-crash", [CANARY], "crash"),
    "fail-invalid": lambda: scenario("fail-invalid", [CANARY], "invalid"),
    "fail-exit2-silent": lambda: scenario("fail-exit2-silent", [CANARY], "exit2-silent"),
    "fail-timeout": lambda: scenario("fail-timeout", [CANARY], "sleep:8,deny-hso", timeout=3),
    "fail-missing": lambda: scenario("fail-missing", [CANARY], pre_command="/nonexistent/tth-hook-binary"),
    # Trust: without --dangerously-bypass-hook-trust, do untrusted user hooks run?
    "untrusted-hooks": lambda: scenario("untrusted-hooks", [CANARY], "deny-hso", trust=False),
    # Subagent (multi_agent_v1 tools are offered to non-catalog model ids). The parent sleeps
    # instead of wait_agent because the mock cannot know the child's agent id in advance.
    "subagent": lambda: scenario("subagent", [
        {"tool_calls": [{"name": "spawn_agent", "namespace": "multi_agent_v1",
                         "arguments": {"message": "@CHILD@: run the scripted step."}}]},
        {"tool_calls": [EXEC("sleep 6")]},
        {"text": "parent done"}],
        child=[CANARY, {"text": "child done"}], pre_mode="deny-hso", expect="absent", model="mock-model"),
}


if __name__ == "__main__":
    names = sys.argv[1:] or [n for n in SCENARIOS if not n.startswith("real-")]
    print(f"# root: {ROOT}", file=sys.stderr)
    for n in names:
        if n.startswith("explore:"):  # explore:<model> lists the tools Codex offers that model id
            scenario("explore-" + n.split(":", 1)[1], [{"text": "nothing to do"}], model=n.split(":", 1)[1])
        else:
            SCENARIOS[n]()
