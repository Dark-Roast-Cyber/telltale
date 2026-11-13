#!/usr/bin/env python3
"""Real GitHub Copilot CLI enforcement tests for `telltale hooks`.

Each scenario runs the real Copilot CLI binary against the scripted loopback
model (mock-model.py, BYOK with COPILOT_OFFLINE=true: no credentials, no model
tokens) with `telltale hooks` registered from its own `copilot-cli settings`
output, in a disposable HOME/COPILOT_HOME/XDG and a working directory that is
its own git repository. The model asks for `touch <canary> && <command>`; the
canary file is ground truth for execution. Results join three views: the
canary, hooks telemetry (decision and outcome), and what each hook
invocation printed (a pass-through recorder around the hook).

The scripted model makes the run deterministic and free, so it tests what the
harness does with the hook's answers, not what a real model would ask for.
Real-model runs are a separate, deliberate step (they need the user's auth).

Usage: copilot-cli-e2e.py [scenario ...]            (default: all)
Env:   COPILOT_BIN (default: copilot on PATH), TTH_BIN (default: target/release/telltale),
       E2E_ROOT (default: mktemp -d), E2E_EVALUATOR (true|false, default true),
       E2E_SOCKET_DIR (default: the temp dir; Unix socket paths must stay short)
Output: <root>/<scenario>/{summary.json, hook-io.jsonl, tth-state/telemetry.jsonl, ...} and <root>/summary.jsonl
"""
import fcntl
import json
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
SELF = os.path.abspath(__file__)
sys.path.insert(0, HERE)


def tee(log, argv):
    """Pass-through recorder: run the hook, record what it printed and its exit code."""
    raw = sys.stdin.buffer.read()
    p = subprocess.run(argv, input=raw, capture_output=True)
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = {}
    event = payload.get("hook_event_name") or payload.get("hookName") or (
        "tool:" + str(payload.get("toolName")) + (":post" if "toolResult" in payload or "error" in payload else "")
        if "toolName" in payload else "lifecycle")
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps({"event": event, "stdout": p.stdout.decode(errors="replace"),
                            "stderr": p.stderr.decode(errors="replace")[-400:], "exit": p.returncode}) + "\n")
    sys.stdout.buffer.write(p.stdout)
    sys.stderr.buffer.write(p.stderr)
    return p.returncode


if len(sys.argv) > 2 and sys.argv[1] == "tee":
    sys.exit(tee(sys.argv[2], sys.argv[3:]))

from capture_common import Run, tool_results_seen_by_model  # noqa: E402

MCP = os.path.join(HERE, "mock-mcp.py")
BIN = os.environ.get("COPILOT_BIN", "copilot")
TTH = os.environ.get("TTH_BIN", os.path.join(REPO, "target", "release", "telltale"))
ROOT = os.environ.get("E2E_ROOT") or tempfile.mkdtemp(prefix="copilot-e2e-")
EVALUATOR = os.environ.get("E2E_EVALUATOR", "true")
SOCKETS = os.environ.get("E2E_SOCKET_DIR") or tempfile.gettempdir()
MARKERS = os.path.join(REPO, "crates", "telltale", "tests", "hooks", "e2e-marker-rules.yaml")
PASCAL = {"preToolUse": "PreToolUse", "postToolUse": "PostToolUse", "postToolUseFailure": "PostToolUseFailure",
          "agentStop": "Stop", "subagentStop": "SubagentStop", "userPromptSubmitted": "UserPromptSubmit",
          "sessionStart": "SessionStart", "sessionEnd": "SessionEnd"}
DENY, ASK, RESULT = "echo TTH_E2E_DENY_MARKER", "echo TTH_E2E_ASK_MARKER", "printf 'TTH_E2E_RESULT_%s' MARKER"


def bash(cmd):
    return {"name": "bash", "arguments": {"command": cmd, "description": "e2e step"}}


def hook_command(run, entry="copilot-cli"):
    return f"{sys.executable} -I {SELF} tee {run.dir}/hook-io.jsonl {TTH} hooks {entry} hook"


def prepare(run, fmt, command, timeout, claude_settings, config, top_config=""):
    subprocess.run(["git", "init", "-q", run.work], check=True)
    sock = os.path.join(SOCKETS, f"tth-e2e-{os.getpid()}-{run.name}.sock")
    with open(os.path.join(run.dir, "tth-config.toml"), "w") as f:
        f.write(config if config is not None else
                f'{top_config}[telltale]\nrules = ["{MARKERS}"]\n\n[evaluator]\nenabled = {EVALUATOR}\n'
                f'idle_timeout_secs = 120\nsocket = "{sock}"\n')
    if claude_settings:
        fragment = json.loads(subprocess.check_output([TTH, "hooks", "claude-code", "settings", hook_command(run, "claude-code")]))
        os.makedirs(os.path.join(run.work, ".claude"))
        with open(os.path.join(run.work, ".claude", "settings.json"), "w") as f:
            json.dump(fragment, f, indent=1)
        return
    hooks = json.loads(subprocess.check_output([TTH, "hooks", "copilot-cli", "settings", hook_command(run)]))
    if command:
        hooks["hooks"]["preToolUse"][0]["command"] = command
    if timeout:
        hooks["hooks"]["preToolUse"][0]["timeoutSec"] = timeout
    if fmt == "pascal":
        hooks["hooks"] = {PASCAL[k]: v for k, v in hooks["hooks"].items() if k in PASCAL}
    d = os.path.join(copilot_home(run), "hooks")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "telltale-hooks.json"), "w") as f:
        json.dump(hooks, f, indent=1)


def copilot_home(run):
    return os.path.join(run.home, getattr(run, "home_name", ".copilot"))


def copilot_env(run):
    return run.base_env(COPILOT_HOME=copilot_home(run),
                        COPILOT_PROVIDER_BASE_URL=f"http://127.0.0.1:{run.port}/v1",
                        COPILOT_MODEL=os.environ.get("E2E_MODEL", "gpt-5.4"), COPILOT_PROVIDER_API_KEY="mock",
                        COPILOT_AUTO_UPDATE="false", COPILOT_OFFLINE="true",
                        TELLTALE_HOOKS_STATE_DIR=os.path.join(run.dir, "tth-state"),
                        TELLTALE_HOOKS_CONFIG=os.path.join(run.dir, "tth-config.toml"))


def argv_for(run, flags):
    mcp = json.dumps({"mcpServers": {"tthmock": {"type": "local", "command": sys.executable,
                                                 "args": ["-I", MCP], "tools": ["*"]}}})
    return ["--no-auto-update", "--disable-builtin-mcps", "--log-level", "all",
            "--log-dir", os.path.join(run.dir, "logs"), "--additional-mcp-config", mcp, *flags]


HOOK_PROMPT = "Hook permission request"
ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[@-Z\\-_]")


class Pty:
    """Copilot's interactive TUI under a pseudo-terminal, read as plain text."""

    def __init__(self, argv, env, cwd):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(cwd)
            os.execve(argv[0], argv, env)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 200, 0, 0))
        self.raw = b""

    def text(self):
        return ANSI.sub(b"", self.raw).decode(errors="replace")

    def pump(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    return False
                if not chunk:
                    return False
                self.raw += chunk
        return True

    def wait_for(self, pattern, seconds):
        end = time.time() + seconds
        while time.time() < end:
            if re.search(pattern, self.text()):
                return True
            if not self.pump(0.3):
                return bool(re.search(pattern, self.text()))
        return False

    def send(self, data):
        os.write(self.fd, data)

    def close(self):
        for sig in (signal.SIGINT, signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
            try:
                if os.waitpid(self.pid, os.WNOHANG) != (0, 0):
                    return
                os.kill(self.pid, sig)
            except (ChildProcessError, ProcessLookupError):
                return
            self.pump(1.5)


def interactive(run, prompt, flags, answer):
    """Run `copilot -i`, answer a folder-trust dialog, wait for the hook's ask prompt, then send `answer`."""
    p = Pty([BIN, "-i", prompt, *argv_for(run, flags)], copilot_env(run), run.work)
    notes = {}
    try:
        deadline = time.time() + 90
        while time.time() < deadline:
            p.pump(0.5)
            text = p.text()
            if re.search(r"(?i)trust the files|do you trust", text) and "trust" not in notes:
                notes["trust"] = True
                p.send(b"\r")
                continue
            if HOOK_PROMPT in text:
                break
        time.sleep(1.0)
        p.pump(1.0)
        notes["prompt_screen"] = p.text()[-3000:]
        notes["prompted"] = HOOK_PROMPT in p.text()
        if answer:
            p.send(answer)
        p.wait_for(r"(?i)all done|done\b", 30)
        p.pump(2)
        notes["final_screen"] = p.text()[-2000:]
    finally:
        p.close()
        with open(os.path.join(run.dir, "pty.txt"), "w") as f:
            f.write(p.text())
    return notes


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


def scenario(name, steps, expect, *, fmt="camel", flags=("--allow-all-tools",), command=None, timeout=None,
             claude_settings=False, config=None, top_config="", answer=None, child=None, note="",
             home_name=None, rule=None, intact=None):
    run = Run(ROOT, name)
    if home_name:
        run.home_name = home_name
    marker = f"TTHE2E-{name}"
    prepare(run, fmt, command, timeout, claude_settings, config, top_config)
    resolve = lambda obj: json.loads(json.dumps(obj).replace("@CANARY@", f"touch {run.canary()}")  # noqa: E731
                                     .replace("@COPILOT_HOME@", copilot_home(run)))
    conversations = [{"match": marker, "steps": resolve(steps)}]
    if child:
        conversations.insert(0, {"match": f"TTHCHILD-{name}", "steps": resolve(child)})
    run.start_mock({"conversations": conversations})
    prompt = f"{marker}: follow the scripted steps."
    notes = {}
    try:
        if answer is None:
            run.run([BIN, "-p", prompt, *argv_for(run, flags)], copilot_env(run))
        else:
            notes = interactive(run, prompt, flags, answer)
    finally:
        run.stop()
        pid = os.path.join(run.dir, "tth-state", "evaluator.pid")
        if os.path.exists(pid):
            try:
                os.kill(int(open(pid).read().strip()), signal.SIGTERM)
            except (ValueError, ProcessLookupError):
                pass
    present = os.path.exists(run.canary())
    records = read_jsonl(os.path.join(run.dir, "tth-state", "telemetry.jsonl"))
    io = read_jsonl(os.path.join(run.dir, "hook-io.jsonl"))
    seen = [str(text)[:300] for text in tool_results_seen_by_model(run).values()]
    summary = {
        "scenario": name, "canary": "present" if present else "absent", "expected": expect,
        "pass": present == (expect == "present"), "note": note,
        "decisions": [{"harness": d["harness"]["name"], "event": d["harness"]["hook_event"],
                       "tool": d["action"]["tool_name"], "agent_id": d["session"]["agent_id"],
                       "verdict": d["decision"]["verdict"], "returned": d["decision"]["returned"],
                       "returned_verdict": d["decision"].get("returned_verdict"),
                       "basis": d["decision"]["basis"],
                       "rules": d["decision"]["rule_ids"], "evaluator": d["evaluation"]["evaluator"],
                       "fallback": d["evaluation"].get("evaluator_fallback")}
                      for d in records if d["kind"] == "decision"],
        "outcomes": [{"tool": o["action"]["tool_name"], "result": o["outcome"]["result"],
                      "enforcement": o["outcome"]["enforcement"], "by": o["outcome"]["established_by"]}
                     for o in records if o["kind"] == "outcome"],
        "errors": [e.get("error_code") for e in records if e["kind"] == "error"],
        "hook_output": [{"event": i["event"], "stdout": i["stdout"].strip()[:200], "exit": i["exit"]}
                        for i in io if i["stdout"].strip() or i["exit"] != 0],
        "hook_invocations": len(io),
        "model_saw": [s for s in seen if "TTH" in s or "Denied" in s or "Telltale" in s][:4],
        "exit": getattr(run, "exit", None),
    }
    # Self-protection scenarios: the rule that decided, and the file it protects.
    fired = [r for d in summary["decisions"] if d["verdict"] == "deny" for r in d["rules"]]
    if rule:
        summary["rule"] = rule
        summary["pass"] = summary["pass"] and any(r.startswith(rule) for r in fired)
    if rule is False:  # benign control: no opinion on the call
        summary["pass"] = summary["pass"] and all(d["verdict"] == "allow" for d in summary["decisions"])
    if intact:
        summary["intact"] = os.path.exists(os.path.join(copilot_home(run), intact))
        summary["pass"] = summary["pass"] and summary["intact"]
    if notes:
        summary["interactive"] = {"prompted": notes.get("prompted"), "trust_dialog": notes.get("trust", False)}
    line = json.dumps(summary)
    print(line, flush=True)
    with open(os.path.join(run.dir, "summary.json"), "w") as f:
        f.write(line + "\n")
    with open(os.path.join(ROOT, "summary.jsonl"), "a") as f:
        f.write(line + "\n")
    return summary


CANARY = lambda cmd: [{"tool_calls": [bash(f"@CANARY@ && {cmd}")]}, {"text": "done"}]  # noqa: E731
TASK = lambda name: [{"tool_calls": [{"name": "task", "arguments": {  # noqa: E731
    "description": "child step", "agent_type": "task", "name": "child",
    "prompt": f"TTHCHILD-{name}: run the scripted step."}}]}, {"text": "done"}]
PADDED = lambda size: [{"tool_calls": [{"name": "bash", "arguments": {  # noqa: E731
    "command": "@CANARY@ && ls", "description": "p" * size}}]}, {"text": "done"}]
DOWN, ENTER, ESC = b"\x1b[B", b"\r", b"\x1b"
TRUST = ("--allow-all-tools", "--trust-folder")
UNEVALUABLE, OVERSIZED = 2_000_000, 33 * 1024 * 1024
ALLOW_UNEVALUABLE = 'on_unevaluable = "allow"\n'

SCENARIOS = {
    "benign": lambda: scenario("benign", CANARY("ls"), "present"),
    "deny": lambda: scenario("deny", CANARY(DENY), "absent"),
    "deny-pascal": lambda: scenario("deny-pascal", CANARY(DENY), "absent", fmt="pascal"),
    "deny-subagent": lambda: scenario("deny-subagent", TASK("deny-subagent"), "absent", child=CANARY(DENY)),
    "deny-yolo": lambda: scenario("deny-yolo", CANARY(DENY), "absent", flags=("--yolo",)),
    "deny-autopilot": lambda: scenario("deny-autopilot", CANARY(DENY), "absent",
                                       flags=("--allow-all-tools", "--autopilot")),
    "ask": lambda: scenario("ask", CANARY(ASK), "absent", note="-p --allow-all-tools"),
    "ask-yolo": lambda: scenario("ask-yolo", CANARY(ASK), "absent", flags=("--yolo",)),
    "ask-autopilot": lambda: scenario("ask-autopilot", CANARY(ASK), "absent",
                                      flags=("--allow-all-tools", "--autopilot")),
    # Interactive: the hook's ask is put to the user; deny it, then approve it.
    "ask-interactive-deny": lambda: scenario("ask-interactive-deny", CANARY(ASK), "absent", answer=ESC,
                                             note="interactive, --allow-all-tools, user declines"),
    "ask-interactive-approve": lambda: scenario("ask-interactive-approve", CANARY(ASK), "present", answer=ENTER,
                                                note="interactive, --allow-all-tools, user approves"),
    "ask-interactive-yolo": lambda: scenario("ask-interactive-yolo", CANARY(ASK), "absent", flags=("--yolo",),
                                             answer=ESC, note="interactive, --yolo, user declines"),
    # Silence never loosens Copilot's own permissions.
    "denytool": lambda: scenario("denytool", CANARY("ls"), "absent", flags=("--allow-all-tools", "--deny-tool=shell"),
                                 note="benign call, --deny-tool=shell: Copilot's deny holds"),
    # A repository .claude/settings.json Claude Code install runs under Copilot.
    "claude-settings": lambda: scenario("claude-settings", CANARY(DENY), "absent", claude_settings=True,
                                        flags=("--allow-all-tools", "--trust-folder")),
    # Its ask is Claude's hookSpecificOutput form on a PascalCase event.
    "claude-settings-ask": lambda: scenario("claude-settings-ask", CANARY(ASK), "absent", claude_settings=True,
                                            flags=TRUST, note="-p, Claude-form ask"),
    "claude-settings-ask-interactive-deny": lambda: scenario(
        "claude-settings-ask-interactive-deny", CANARY(ASK), "absent", claude_settings=True, answer=ESC,
        note="interactive, Claude-form ask, user declines"),
    "claude-settings-ask-interactive-approve": lambda: scenario(
        "claude-settings-ask-interactive-approve", CANARY(ASK), "present", claude_settings=True, answer=ENTER,
        note="interactive, Claude-form ask, user approves"),
    # Default on_unevaluable on that route, reached by real payloads. Input past
    # the projection budget is evaluated and asks; input past the payload limit
    # is answered without being parsed. The controls set on_unevaluable = allow:
    # the same call then runs, so Copilot itself does not refuse its size.
    "claude-settings-unevaluable": lambda: scenario(
        "claude-settings-unevaluable", PADDED(UNEVALUABLE), "absent", claude_settings=True, flags=TRUST,
        note="default on_unevaluable, input past the projection budget"),
    "claude-settings-unevaluable-control": lambda: scenario(
        "claude-settings-unevaluable-control", PADDED(UNEVALUABLE), "present", claude_settings=True, flags=TRUST,
        top_config=ALLOW_UNEVALUABLE, note="control: same call, on_unevaluable = allow"),
    "claude-settings-oversized": lambda: scenario(
        "claude-settings-oversized", PADDED(OVERSIZED), "absent", claude_settings=True, flags=TRUST,
        note="default on_unevaluable, payload past the 32 MiB limit"),
    "claude-settings-oversized-control": lambda: scenario(
        "claude-settings-oversized-control", PADDED(OVERSIZED), "present", claude_settings=True, flags=TRUST,
        top_config=ALLOW_UNEVALUABLE, note="control: same call, on_unevaluable = allow"),
    # Advisory context on a flagged result (postToolUse additionalContext).
    "result-context": lambda: scenario("result-context", CANARY(RESULT), "present"),
    # Failure handling.
    "fail-missing": lambda: scenario("fail-missing", CANARY("ls"), "absent", command="/nonexistent/telltale"),
    "fail-exit1": lambda: scenario("fail-exit1", CANARY("ls"), "absent", command="sh -c 'exit 1'"),
    "fail-config": lambda: scenario("fail-config", CANARY("ls"), "absent", config="this is = not [valid toml\n",
                                    note="invalid hooks config denies tool calls (payload-less flat form)"),
    "fail-config-pascal": lambda: scenario("fail-config-pascal", CANARY("ls"), "absent", fmt="pascal",
                                           config="this is = not [valid toml\n"),
    "timeout": lambda: scenario("timeout", CANARY(DENY), "present", timeout=2,
                                command=f"sh -c 'sleep 5; exec {TTH} hooks copilot-cli hook'",
                                note="residual: a hook that times out lets the call run"),
    # Self-protection. The canary precedes the tamper command, so it shows nothing ran; --yolo
    # turns off Copilot's own path check, which would refuse a path outside the work directory anyway.
    "tamper-hook-file": lambda: scenario(
        "tamper-hook-file", CANARY("rm -f @COPILOT_HOME@/hooks/telltale-hooks.json"), "absent",
        flags=("--yolo",), rule="tth.tamper.copilot_hook_", intact="hooks/telltale-hooks.json",
        note="agent removes its hook file: denied by rule content, file intact"),
    "tamper-custom-home": lambda: scenario(
        "tamper-custom-home", CANARY("rm -f @COPILOT_HOME@/hooks/telltale-hooks.json"), "absent",
        flags=("--yolo",), home_name="agents/custom-home", rule="tth.tamper.harness_home_",
        intact="hooks/telltale-hooks.json",
        note="COPILOT_HOME has no .copilot in it: only the rule generated from the hook's environment knows it"),
    "tamper-benign": lambda: scenario(
        "tamper-benign", CANARY("rm -rf @COPILOT_HOME@/logs/old"), "present", flags=("--yolo",), rule=False,
        note="control: a writer under the home that does not touch hook files runs"),
}

if __name__ == "__main__":
    if not os.access(TTH, os.X_OK):
        sys.exit(f"build first: cargo build --release ({TTH})")
    print(f"# root: {ROOT}", file=sys.stderr)
    for n in sys.argv[1:] or list(SCENARIOS):
        SCENARIOS[n]()
