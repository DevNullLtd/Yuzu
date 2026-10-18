#!/usr/bin/env python3
"""
docs-drift-pr-guard.py -- PreToolUse hook: run the docs drift gate before `gh pr create`.

Runs both layers of scripts/ci/check-docs-drift.py (docs/docs-drift-gate.md)
on the branch about to become a PR, so drift is caught before the PR exists
rather than on its first CI run:

  - fact parity over the working tree;
  - the doc-coupling touch rule over merge-base(origin/<base>, HEAD)..HEAD,
    honouring `doc-coupling-exempt:` lines in the body passed via
    --body / -b / --body-file / -F.

On failure it denies the Bash call with the gate's own output as the reason.
The docs-lint CI jobs are the server-side backstop for sessions without hooks,
and for PRs opened any other way (the GitHub UI, the API, an MCP tool).

TRUST BOUNDARY. The gate that runs is ALWAYS the one in $CLAUDE_PROJECT_DIR,
the tree whose .claude/settings.json enabled this hook. The tree the command
runs in (the hook input's `cwd`, often a worktree) is passed to it as
`--root`, which it reads as data only. Never execute a script from the cwd's
tree: a session can sit in a checkout of an untrusted branch (a fork PR under
review), and running its check-docs-drift.py would run attacker-authored code
with the developer's credentials. If the project tree predates the gate, the
hook does nothing.

Wired via .claude/settings.json -> hooks.PreToolUse (matcher Bash).

Design (matches changelog-fragment-guard.py conventions):
  - Fail-open: ANY error (no git, no origin/<base>, unparseable command, a
    timeout) -> allow the call. A convention hook must never wedge a session.
  - UTF-8 explicit on stdin.
  - ALWAYS exit 0; the decision is carried in the JSON, not the exit code.
"""
import json
import os
import shlex
import subprocess
import sys
import tempfile

# Punctuation runs made only of these characters end a command, so the next
# word is in command position. Newline is punctuation here (not whitespace)
# so a command on a later line of a multi-line Bash call is still seen.
_SEP_CHARS = set(";&|(\n")


def _is_separator(tok):
    return bool(tok) and set(tok) <= _SEP_CHARS


def pr_create_args(command):
    """The arguments of a `gh pr create` invoked at a command position, or
    None. Matching tokens rather than text means the phrase inside a quoted
    argument (a commit message, an echo) never fires the hook."""
    lex = shlex.shlex(command, posix=True, punctuation_chars="();<>|&\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    toks = list(lex)
    for i in range(len(toks) - 2):
        if toks[i:i + 3] == ["gh", "pr", "create"] and (i == 0 or _is_separator(toks[i - 1])):
            rest = toks[i + 3:]
            end = next((j for j, t in enumerate(rest) if _is_separator(t)), len(rest))
            return rest[:end]
    return None


def pr_args(args, cwd):
    """(base, body) from `gh pr create` arguments."""
    base, body = "dev", ""
    it = iter(args)
    for t in it:
        key, eq, val = t.partition("=")
        if key in ("--base", "-B"):
            base = val if eq else next(it, base)
        elif key in ("--body", "-b"):
            body = val if eq else next(it, "")
        elif key in ("--body-file", "-F"):
            path = val if eq else next(it, "")
            if path and path != "-":
                with open(os.path.join(cwd, path), encoding="utf-8", errors="replace") as f:
                    body = f.read()
    return base, body


def git(root, *args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, timeout=30)


def main():
    try:
        raw = sys.stdin.buffer.read()
        data = json.loads(raw.decode("utf-8", errors="replace")) if raw else {}
    except Exception:
        return
    if data.get("tool_name") != "Bash":
        return
    command = str((data.get("tool_input") or {}).get("command") or "")
    if "gh" not in command:
        return
    args = pr_create_args(command)
    if args is None:
        return

    project = os.environ.get("CLAUDE_PROJECT_DIR")
    if not project:
        return
    gate = os.path.join(project, "scripts", "ci", "check-docs-drift.py")
    if not os.path.isfile(gate):
        return  # the trusted tree predates the gate
    cwd = data.get("cwd") or project
    top = git(cwd, "rev-parse", "--show-toplevel")
    if top.returncode:
        return
    root = top.stdout.strip()

    base, body = pr_args(args, cwd)
    mb = git(root, "merge-base", f"origin/{base}", "HEAD")
    if mb.returncode:
        return  # no remote-tracking base to diff against: fail open
    failures = []

    facts = subprocess.run([sys.executable, "-I", gate, "--root", root],
                           capture_output=True, text=True, timeout=60)
    if facts.returncode:
        failures.append(facts.stderr.strip())

    body_path = None
    if body:
        fd, body_path = tempfile.mkstemp(prefix="yuzu_docs_drift_", suffix=".md")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(body)
    try:
        touch = subprocess.run([sys.executable, "-I", gate, "--root", root, "--touch",
                                mb.stdout.strip(), "HEAD", *([body_path] if body_path else [])],
                               capture_output=True, text=True, timeout=60)
    finally:
        if body_path:
            os.unlink(body_path)
    if touch.returncode:
        failures.append(touch.stderr.strip())

    if not failures:
        return
    reason = ("Docs drift gate failed (docs/docs-drift-gate.md) -- fix this before opening the PR; "
              "CI runs equivalent checks.\n\n" + "\n\n".join(f for f in failures if f) +
              "\n\nUpdate the docs, or for a touch-rule miss add `doc-coupling-exempt: <rule-id> — <reason>` "
              "to the PR body. Never grow scripts/ci/docs-drift-baseline.json to get past this.")
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # fail-open
    finally:
        sys.exit(0)  # ALWAYS exit 0 -- decision is in the JSON, never the exit code
