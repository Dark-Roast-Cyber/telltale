#!/usr/bin/env python3
"""Turn a recorder capture (scripts/hooks/harness/recorder.py or stub-hook.py output) into a contract fixture.

Keeps each hook stdin payload exactly as the harness produced it, except that the
disposable run directory prefix, and the home directory of the user who ran the
capture (local Claude Code runs keep the real HOME so the stored login resolves,
and transcript paths live under it), are rewritten to synthetic paths so no host
path or user name leaks into the repository. Usage:

    sanitize-capture.py [--envelope] [--only REGEX] <hooks.jsonl> <run-dir> > fixture.jsonl

Default output is one bare payload per line (the Claude Code fixture format).
--envelope wraps each line as {"event": <label>, "stub": <mode>, "payload": ...}
for harnesses whose payloads do not name their own event (Copilot camelCase
events, OpenCode plugin hooks). --only keeps records whose label matches REGEX.
The output is refused if it still contains the invoking user's home directory,
user name or temporary directory.
"""
import getpass
import json
import os
import re
import sys

args = sys.argv[1:]
envelope = "--envelope" in args
args = [a for a in args if a != "--envelope"]
only = None
if "--only" in args:
    i = args.index("--only")
    only = re.compile(args[i + 1])
    del args[i : i + 2]
src, run_dir = args[0], args[1].rstrip("/")
home = os.path.expanduser("~").rstrip("/")


def encoded(path):
    # Claude Code also encodes the cwd into the project directory name with '-'.
    return path.replace("/", "-").replace(".", "-")


replacements = [(run_dir, "/home/synthetic/run"), (encoded(run_dir), "-home-synthetic-run")]
if home and home != "/" and not run_dir.startswith(home + "/.claude"):
    replacements += [(home, "/home/synthetic"), (encoded(home), "-home-synthetic")]
leaks = {home, os.environ.get("TMPDIR", "").rstrip("/"), getpass.getuser()}
leaks.discard("")
out = []
for line in open(src, encoding="utf-8"):
    record = json.loads(line)
    label = record.get("label", "")
    if only and not only.search(label):
        continue
    if envelope:
        value = {"event": label, "stub": record.get("mode", "noop"), "payload": record["payload"]}
    else:
        value = record["payload"]
    text = json.dumps(value, ensure_ascii=False)
    for needle, replacement in replacements:
        text = text.replace(needle, replacement)
    for leak in leaks:
        if leak in text:
            sys.exit(f"refusing: output still contains a host value ({len(leak)} chars) in a {label!r} record")
    out.append(text)
print("\n".join(out))
