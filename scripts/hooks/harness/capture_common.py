"""Shared helpers for harness contract captures (capture tooling, not the product).

Each scenario gets a disposable run directory with its own HOME, harness config
home and working directory, a scripted mock model (mock-model.py) on a loopback
port, and a stub hook that records every payload. The canary file is ground
truth: it exists only if the harness executed the canary command.
"""
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
STUB = os.path.join(HERE, "stubs", "stub-hook.py")
MOCK = os.path.join(HERE, "mock-model.py")
PASS_ENV = ("PATH", "LANG", "TERM", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
            "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS")


class Run:
    def __init__(self, root, name):
        self.name = name
        self.dir = os.path.join(root, name)
        shutil.rmtree(self.dir, ignore_errors=True)
        self.home = os.path.join(self.dir, "home")
        self.work = os.path.join(self.dir, "work")
        for d in (self.home, self.work):
            os.makedirs(d)
        self.rec_log = os.path.join(self.dir, "hooks.jsonl")
        self.model_log = os.path.join(self.dir, "model-requests.jsonl")
        open(self.rec_log, "w").close()
        self.mock = None
        self.port = None

    def canary(self, name="canary.txt"):
        return os.path.join(self.work, name)

    def start_mock(self, script):
        path = os.path.join(self.dir, "mock-script.json")
        with open(path, "w") as f:
            json.dump(script, f, indent=1)
        port_file = os.path.join(self.dir, "mock.port")
        self.mock = subprocess.Popen([sys.executable, "-I", MOCK, path, self.model_log, port_file])
        for _ in range(100):
            if os.path.exists(port_file) and open(port_file).read().strip():
                self.port = int(open(port_file).read())
                return self.port
            time.sleep(0.05)
        raise RuntimeError("mock model did not start")

    def stop(self):
        if self.mock:
            self.mock.terminate()
            self.mock.wait()

    def base_env(self, **extra):
        env = {k: os.environ[k] for k in PASS_ENV if k in os.environ}
        no_proxy = ",".join(filter(None, [os.environ.get("NO_PROXY", ""), "127.0.0.1", "localhost"]))
        env.update(HOME=self.home, TMPDIR=os.path.join(self.dir, "tmp"), NO_PROXY=no_proxy, no_proxy=no_proxy,
                   REC_LOG=self.rec_log, XDG_CONFIG_HOME=os.path.join(self.home, ".config"),
                   XDG_DATA_HOME=os.path.join(self.home, ".local", "share"),
                   XDG_STATE_HOME=os.path.join(self.home, ".local", "state"),
                   XDG_CACHE_HOME=os.path.join(self.home, ".cache"))
        os.makedirs(env["TMPDIR"], exist_ok=True)
        env.update({k: str(v) for k, v in extra.items()})
        return env

    def run(self, argv, env, timeout=180, stdin=subprocess.DEVNULL):
        t0 = time.time()
        with open(os.path.join(self.dir, "stdout.txt"), "w") as out, \
                open(os.path.join(self.dir, "stderr.txt"), "w") as err:
            try:
                p = subprocess.run(argv, cwd=self.work, env=env, stdout=out, stderr=err, timeout=timeout, stdin=stdin)
                code = p.returncode
            except subprocess.TimeoutExpired:
                code = "timeout"
        self.elapsed = round(time.time() - t0, 1)
        self.exit = code
        return code

    def records(self):
        return [json.loads(l) for l in open(self.rec_log) if l.strip()]

    def model_requests(self):
        if not os.path.exists(self.model_log):
            return []
        return [json.loads(l) for l in open(self.model_log) if l.strip()]

    def summary(self, canary_name="canary.txt", expect=None, note=""):
        present = os.path.exists(self.canary(canary_name))
        recs = self.records()
        events = [r["label"] + ("*" if r["mode"] != "noop" else "") for r in recs]
        verdict = ""
        if expect:
            verdict = "PASS" if (present == (expect == "present")) else "FAIL"
        line = {"scenario": self.name, "canary": "present" if present else "absent", "expect": expect,
                "verdict": verdict, "exit": self.exit, "secs": self.elapsed, "events": events, "note": note}
        with open(os.path.join(self.dir, "summary.json"), "w") as f:
            json.dump(line, f, indent=1)
        print(json.dumps(line))
        return line


def tool_results_seen_by_model(run):
    """Tool outputs as the model saw them in its next request (chat or responses wire)."""
    seen = {}
    for req in run.model_requests():
        body = req["body"]
        for item in body.get("messages") or []:
            if isinstance(item, dict) and item.get("role") == "tool":
                seen[item.get("tool_call_id")] = item.get("content")
        for item in body.get("input") or [] if isinstance(body.get("input"), list) else []:
            if isinstance(item, dict) and item.get("type") in ("function_call_output", "custom_tool_call_output"):
                seen[item.get("call_id")] = item.get("output")
    return seen
