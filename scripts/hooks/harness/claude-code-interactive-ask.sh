#!/usr/bin/env bash
# Interactive `ask` approval in a real Claude Code session, driven through tmux.
#
# Headless `-p` sessions decline every `ask` (no approver), so the only way to
# observe an approved ask is an interactive session. This runs `claude` in a
# detached tmux pane with the same isolation as claude-code-e2e.sh (local auth
# mode: real HOME for the stored login, `--setting-sources project` plus
# `--settings` so the user's own settings and hooks never load), asks the model
# for the ask-marker command, approves the permission prompt, and checks that
# telltale hooks settled the call as `proceeded_after_ask`.
#
# Usage: scripts/hooks/harness/claude-code-interactive-ask.sh [approve|decline]
# Env: E2E_ROOT, TTH_BIN, E2E_MODEL as in claude-code-e2e.sh. Costs model tokens.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
bin=${TTH_BIN:-$repo/target/release/telltale}
root=${E2E_ROOT:-$(mktemp -d)}
model=${E2E_MODEL:-claude-sonnet-5-5}
choice=${1:-approve}
name=interactive-ask-$choice
r=$root/$name
[ -x "$bin" ] || { echo "build first: cargo build --release" >&2; exit 2; }
command -v tmux > /dev/null || { echo "tmux required" >&2; exit 2; }

rm -rf -- "${r:?}"; mkdir -p "$r/work"
"$bin" claude-code settings "$bin claude-code hook" \
  | python3 -c 'import json,sys; f=json.load(sys.stdin); f["permissions"]={"allow":["Bash"]}; json.dump(f, sys.stdout)' \
  > "$r/settings.json"
printf 'mode = "enforce"\n\n[telltale]\nrules = ["%s"]\n\n[evaluator]\nenabled = true\nidle_timeout_secs = 300\n' \
  "$repo/crates/telltale/tests/hooks/e2e-marker-rules.yaml" > "$r/tth-config.toml"

session=tth-$$
tmux new-session -d -s "$session" -x 160 -y 50 -c "$r/work" \
  env -i PATH="$PATH" HOME="$HOME" TERM=xterm-256color \
  TELLTALE_HOOKS_STATE_DIR="$r/tth-state" TELLTALE_HOOKS_CONFIG="$r/tth-config.toml" \
  claude --model "$model" --setting-sources project --settings "$r/settings.json"
cleanup() { tmux kill-session -t "$session" 2> /dev/null || true
  local pidfile=$r/tth-state/evaluator.pid; [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2> /dev/null || true; }
trap cleanup EXIT

pane() { tmux capture-pane -p -t "$session" -S -60; }
wait_for() { # $1 regex, $2 seconds
  local i; for ((i = 0; i < $2 * 2; i++)); do
    if pane | grep -qE "$1"; then return 0; fi; sleep 0.5
  done
  echo "timed out waiting for /$1/" >&2; pane | tail -30 >&2; return 1
}

# First-run trust prompt for the new directory, if shown.
if wait_for 'trust|Yes, proceed|>' 60 && pane | grep -qiE 'trust'; then
  tmux send-keys -t "$session" Enter; sleep 1
fi
wait_for '^\s*>|\? for shortcuts|Try "' 60
sleep 1
tmux send-keys -t "$session" -l 'Run exactly this Bash command once, verbatim, and reply RAN or BLOCKED: touch canary-ask && echo TTH_E2E_ASK_MARKER'
sleep 0.5; tmux send-keys -t "$session" Enter

# telltale hooks returns `ask`; Claude Code shows its permission prompt with our reason.
wait_for 'Telltale Hooks' 120
pane > "$r/prompt-pane.txt"
sleep 1
case $choice in
  approve) tmux send-keys -t "$session" Enter ;;            # first option: Yes
  decline) tmux send-keys -t "$session" Escape ;;           # dismiss = No
  *) echo "choice must be approve or decline" >&2; exit 2 ;;
esac
# Wait for the harness to report the call's outcome (PostToolUse or a batch settlement).
for ((i = 0; i < 240; i++)); do
  grep -q '"kind":"outcome"' "$r/tth-state/telemetry.jsonl" 2> /dev/null && break; sleep 0.5
done
sleep 2
pane > "$r/final-pane.txt"
tmux send-keys -t "$session" -l '/exit'; tmux send-keys -t "$session" Enter; sleep 3

python3 - "$r" "$choice" <<'EOF'
import json, os, sys
run, choice = sys.argv[1:3]
present = os.path.exists(os.path.join(run, "work", "canary-ask"))
records = [json.loads(l) for l in open(os.path.join(run, "tth-state", "telemetry.jsonl"))]
decisions = [r for r in records if r["kind"] == "decision" and r["action"]["tool_name"] == "Bash"]
outcomes = [r for r in records if r["kind"] == "outcome" and r["action"]["tool_name"] == "Bash"]
prompts = [r for r in records if r["kind"] == "lifecycle" and r["lifecycle"].get("event") == "permission_prompt"]
summary = {
    "scenario": f"interactive-ask-{choice}",
    "canary": "present" if present else "absent",
    "expected": "present" if choice == "approve" else "absent",
    "decisions": [(d["decision"]["verdict"], d["decision"]["returned"], d["decision"]["rule_ids"]) for d in decisions],
    "permission_prompts": len(prompts),
    "outcomes": [(o["outcome"]["result"], o["outcome"]["enforcement"], o["outcome"]["established_by"]) for o in outcomes],
}
summary["pass"] = summary["canary"] == summary["expected"] and any(
    o["outcome"]["enforcement"] == ("proceeded_after_ask" if choice == "approve" else "declined") for o in outcomes)
print(json.dumps(summary))
EOF
