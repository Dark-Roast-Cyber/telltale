#!/usr/bin/env python3
"""OpenCode plugin contract captures, v1 and v2 plugin APIs (capture tooling, not the shim).

Runs `opencode run` against the scripted mock model (custom OpenAI-compatible
provider: no credentials, no model tokens) with a capture plugin installed in an
isolated XDG config home, and checks a canary file to see whether the harness
honored each plugin decision. v2 always runs `--standalone` so it never
attaches to a shared background service.

Usage: capture-opencode.py <v1|v2> [scenario ...]
Env:   OPENCODE_V1_BIN, OPENCODE_V2_BIN (default: opencode on PATH), CAPTURE_ROOT
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capture_common import HERE, Run, tool_results_seen_by_model  # noqa: E402

GEN = sys.argv[1] if len(sys.argv) > 1 else "v2"
BIN = os.environ.get(f"OPENCODE_{GEN.upper()}_BIN", "opencode")
ROOT = os.environ.get("CAPTURE_ROOT") or tempfile.mkdtemp(prefix=f"capture-opencode-{GEN}-")
PLUGIN = os.path.join(HERE, "opencode", GEN, "tth-capture.js")
MCP = os.path.join(HERE, "mock-mcp.py")


def config(run, permission, extra, model="mock-model"):
    base = f"http://127.0.0.1:{run.port}/v1"
    if GEN == "v1":
        cfg = {"$schema": "https://opencode.ai/config.json", "autoupdate": False, "share": "disabled",
               "model": f"mock/{model}",
               "provider": {"mock": {"npm": "@ai-sdk/openai-compatible", "name": "Mock",
                                     "options": {"baseURL": base, "apiKey": "mock"},
                                     "models": {model: {"name": "Mock", "tool_call": True}}}},
               "mcp": {"tthmock": {"type": "local", "command": [sys.executable, "-I", MCP], "enabled": True}}}
        if permission is not None:
            cfg["permission"] = permission
    else:
        cfg = {"model": f"mock/{model}",
               "providers": {"mock": {"name": "Mock", "package": "@ai-sdk/openai-compatible",
                                      "settings": {"baseURL": base, "apiKey": "mock"},
                                      "models": {model: {"name": "Mock"}}}},
               "mcp": {"tthmock": {"type": "local", "command": [sys.executable, "-I", MCP]}}}
        if permission is not None:
            cfg["permission"] = permission
    cfg.update(extra or {})
    return cfg


def scenario(name, steps, mode="noop", flags=("--auto",), expect=None, permission=None, extra=None,
             child=None, plugin_text=None, note="", timeout=120, model="mock-model"):
    run = Run(ROOT, name)
    marker = f"TTHSCN-{name}"
    canary = f"touch {run.canary()} && echo TTH_CANARY"
    convs = []
    if child:
        convs.append({"match": f"TTHCHILD-{name}", "steps": json.loads(json.dumps(child).replace("@CANARY@", canary))})
    convs.append({"match": marker, "steps": json.loads(json.dumps(steps).replace("@CANARY@", canary)
                                                       .replace("@WORK@", run.work)
                                                       .replace("@CHILD@", f"TTHCHILD-{name}"))})
    run.start_mock({"conversations": convs})
    cfg_dir = os.path.join(run.home, ".config", "opencode")
    os.makedirs(os.path.join(cfg_dir, "plugins"))
    with open(os.path.join(cfg_dir, "opencode.json"), "w") as f:
        json.dump(config(run, permission, extra, model), f, indent=1)
    target = os.path.join(cfg_dir, "plugins", "tth-capture.js")
    if plugin_text is not None:
        with open(target, "w") as f:
            f.write(plugin_text)
    else:
        shutil.copy(PLUGIN, target)
    env = run.base_env(STUB_MODE=mode, OPENCODE_DISABLE_AUTOUPDATE="1", OPENCODE_DISABLE_LSP_DOWNLOAD="1",
                       OPENCODE_DISABLE_DEFAULT_PLUGINS="1", OPENCODE_DISABLE_MODELS_FETCH="1")
    argv = [BIN, "run", *(["--standalone"] if GEN == "v2" else []), "--format", "json", *flags,
            f"{marker}: follow the scripted steps."]
    try:
        run.run(argv, env, timeout=timeout)
    finally:
        run.stop()
    s = run.summary(expect=expect, note=note)
    with open(os.path.join(run.dir, "tool-results-seen.json"), "w") as f:
        json.dump(tool_results_seen_by_model(run), f, indent=1)
    return s


V1 = GEN == "v1"
FILE = "filePath" if V1 else "path"


def SH(cmd):
    if V1:
        return {"name": "bash", "arguments": {"command": cmd, "description": "capture step"}}
    return {"name": "shell", "arguments": {"command": cmd}}


def T(*calls):
    return {"tool_calls": list(calls)}


DONE = {"text": "done"}
CANARY = T(SH("@CANARY@"))
SUB_AGENT = "tthworker"
AGENTS_V2 = {"agents": {SUB_AGENT: {"description": "capture worker", "mode": "subagent"}}}
AGENTS_V1 = {"agent": {SUB_AGENT: {"description": "capture worker", "mode": "subagent"}}}


def SUBAGENT():
    prompt = "@CHILD@: run the scripted steps."
    if V1:
        return {"name": "task", "arguments": {"description": "capture child", "prompt": prompt, "subagent_type": SUB_AGENT}}
    return {"name": "subagent", "arguments": {"agent": SUB_AGENT, "description": "capture child", "prompt": prompt}}


def deny_rules(effect):
    # Native permission rule for the shell tool.
    if V1:
        return {"bash": effect}
    return [{"action": "shell", "resource": "*", "effect": effect}]


def perm(effect):
    return {"permission" if V1 else "permissions": deny_rules(effect)}


LIFECYCLE = [
    T(SH("echo lifecycle-start")),
    T({"name": "write", "arguments": {FILE: "@WORK@/a.txt", "content": "one\n"}}),
    T({"name": "edit", "arguments": {FILE: "@WORK@/a.txt", "oldString": "one", "newString": "two"}}),
    T({"name": "read", "arguments": {FILE: "@WORK@/a.txt"}}),
    T(SH("echo failing; exit 3")),
    T(SH("echo par1"), SH("echo par2")),
    T({"name": "webfetch", "arguments": {"url": "http://127.0.0.1:9/nothing", "format": "text"}}),
    T({"name": "tthmock_echo", "arguments": {"text": "mcp hello"}}),
    CANARY,
    DONE,
]

SCENARIOS = {
    "explore": lambda: scenario("explore", [{"text": "nothing to do"}]),
    "explore-gpt": lambda: scenario("explore-gpt", [{"text": "nothing to do"}], model="gpt-5.4"),
    "lifecycle": lambda: scenario("lifecycle", LIFECYCLE, expect="present"),
    "deny-throw": lambda: scenario("deny-throw", [CANARY, DONE], mode="throw", expect="absent"),
    "deny-toolerror": lambda: scenario("deny-toolerror", [CANARY, DONE], mode="toolerror", expect="absent"),
    "deny-throw-parallel": lambda: scenario(
        "deny-throw-parallel", [T(SH("@CANARY@"), SH("echo sibling > @WORK@/sibling.txt")), DONE], mode="throw",
        expect="absent", note="sibling call in the same step: check work/sibling.txt"),
    "deny-throw-noauto": lambda: scenario("deny-throw-noauto", [CANARY, DONE], mode="throw", flags=(), expect="absent"),
    "hang": lambda: scenario("hang", [CANARY, DONE], mode="hang", expect="absent", timeout=45,
                             note="never-resolving execute.before; harness killed at 45 s if it does not time out"),
    "init-throw": lambda: scenario("init-throw", [CANARY, DONE], mode="init-throw",
                                   note="plugin throws during init/setup: does the run proceed?"),
    "syntax-error": lambda: scenario("syntax-error", [CANARY, DONE], plugin_text="export default {{{ not js\n",
                                     note="plugin file fails to parse"),
    "perm-deny": lambda: scenario("perm-deny", [CANARY, DONE], mode="perm-deny", expect="absent"),
    "perm-ask": lambda: scenario("perm-ask", [CANARY, DONE], mode="perm-ask", note="evaluate effect=ask in run mode"),
    "perm-ask-noauto": lambda: scenario("perm-ask-noauto", [CANARY, DONE], mode="perm-ask", flags=()),
    "perm-allow-vs-deny": lambda: scenario("perm-allow-vs-deny", [CANARY, DONE], mode="perm-allow", extra=perm("deny"),
                                           note="plugin allow vs native deny rule"),
    "noop-vs-deny": lambda: scenario("noop-vs-deny", [CANARY, DONE], extra=perm("deny"), expect="absent",
                                     note="control: native deny rule, plugin noop"),
    "native-ask-noauto": lambda: scenario("native-ask-noauto", [CANARY, DONE], extra=perm("ask"), flags=(),
                                          note="control: native ask rule, no --auto"),
    "perm-allow-vs-ask": lambda: scenario("perm-allow-vs-ask", [CANARY, DONE], mode="perm-allow", extra=perm("ask"),
                                          flags=(), note="plugin allow vs native ask rule without --auto"),
    "subagent": lambda: scenario("subagent", [T(SUBAGENT()), DONE], child=[CANARY, DONE], mode="throw",
                                 expect="absent", extra=AGENTS_V1 if V1 else AGENTS_V2),
    # GPT-family model ids get a patch tool instead of edit/write.
    "lifecycle-patch": lambda: scenario("lifecycle-patch", [
        T({"name": "apply_patch" if V1 else "patch", "arguments": {"patchText":
            "*** Begin Patch\n*** Add File: p.txt\n+alpha\n*** End Patch"}}),
        T({"name": "apply_patch" if V1 else "patch", "arguments": {"patchText":
            "*** Begin Patch\n*** Update File: p.txt\n@@\n-alpha\n+beta\n*** End Patch"}}),
        DONE], model="gpt-5.4"),
    # v2 exposes MCP tools only inside Code Mode (`execute`); does the inner call reach tool hooks?
    "mcp-codemode": lambda: scenario("mcp-codemode", [
        T(SH("sleep 3; echo wait-for-mcp")),
        T(SH("echo wait-for-mcp-catalog")),
        T({"name": "execute", "arguments": {"code": "return await tools.tthmock.echo({ text: 'TTH_' + 'CANARY via code mode' })"}}),
        DONE], mode="throw",
        note="throw mode; only the inner MCP call input contains the match string (built at runtime)"),
    "pure": lambda: scenario("pure", [CANARY, DONE], mode="throw", flags=("--auto", "--pure"),
                             note="v1 --pure: run without external plugins"),
}

if __name__ == "__main__":
    names = sys.argv[2:] or list(SCENARIOS)
    print(f"# root: {ROOT}", file=sys.stderr)
    for n in names:
        SCENARIOS[n]()
