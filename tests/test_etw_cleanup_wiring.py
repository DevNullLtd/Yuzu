#!/usr/bin/env python3
"""Pins the Windows job's wiring of scripts/ci/stop-dead-etw-sessions.ps1 (#7175).

BEST-EFFORT source-text tripwire: the script's decisions are proved on a Windows runner by its own -SelfTest
step, but nothing there notices the steps being deleted, reordered behind the suite, or the post-test step losing
its `always()`. This reads .github/workflows/ci.yml's `windows:` job and checks:

  1. the self-test step, the pre-test cleanup and `Test (non-pg suites)` appear in that order, once each;
  2. the post-test cleanup comes after `Test (non-pg suites)` and carries `if: always()` (a cancelled job still
     runs it; an `if:` with no status function would be skipped on failure);
  3. every call is `shell: pwsh` with a `timeout-minutes` cap and goes through the one script, with -SelfTest only on
     the self-test step; the self-test and pre-test steps carry no `if:` and no `continue-on-error` (a skipped or
     ignored step would leave the guard silently off);
  4. the script is ASCII only (Windows PowerShell 5.1 misreads BOM-less UTF-8) and never exits non-zero; real mode
     (everything after the -SelfTest block) opens with a catch-all `try` and ends `} catch {` ... `exit 0`, and has no
     line that STARTS with `throw` (the `throw`s inside the injected `$query` closure sit in `if` lines and are caught
     by Invoke-EtwSessionCleanup's own try), so housekeeping can never turn the test phase red;
  5. each real step runs the script with exactly `-Phase pre-test` / `-Phase post-test` (the script's ValidateSet
     would turn any other value into a red step).
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CI = ROOT / ".github" / "workflows" / "ci.yml"
PS1 = ROOT / "scripts" / "ci" / "stop-dead-etw-sessions.ps1"

SELFTEST = "Self-test the ETW leaked-session cleanup"
PRE = "Stop ETW sessions leaked by dead Yuzu test processes (pre-test)"
POST = "Stop ETW sessions leaked by dead Yuzu test processes (post-test)"
SUITE = "Test (non-pg suites)"


def windows_job_steps(text):
    m = re.search(r"^  windows:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n)", text, re.S | re.M)
    if not m:
        raise SystemExit("FAIL: no `windows:` job in ci.yml")
    body = m.group(1)
    parts = re.split(r"^      - name: ", body, flags=re.M)[1:]
    return {p.split("\n", 1)[0].strip(): p for p in parts}, [p.split("\n", 1)[0].strip() for p in parts]


def code_only(text):
    """The script with quoted strings and # comments blanked, line by line (a lexical approximation, enough to keep
    prose and string literals such as the self-test's `-Command "...; exit 3"` from being mistaken for statements)."""
    out = []
    for line in text.splitlines():
        line = re.sub(r"'[^'\n]*'", "''", line)
        line = re.sub(r'"[^"\n]*"', '""', line)
        out.append(line.split("#", 1)[0])
    return "\n".join(out)


def main():
    errors = []
    steps, order = windows_job_steps(CI.read_text(encoding="utf-8"))
    for name in (SELFTEST, PRE, POST, SUITE):
        if order.count(name) != 1:
            errors.append(f"step {name!r} appears {order.count(name)} times in the windows job, expected 1")
    if not errors:
        i_self, i_pre, i_suite, i_post = (order.index(n) for n in (SELFTEST, PRE, SUITE, POST))
        if not i_self < i_pre < i_suite:
            errors.append("order must be self-test, then pre-test cleanup, then the suite")
        if not i_post > i_suite:
            errors.append("the post-test cleanup must come after the suite")
        if not re.search(r"^        if: always\(\)\s*$", steps[POST], re.M):
            errors.append("the post-test cleanup must carry `if: always()`")
        for name in (SELFTEST, PRE, POST):
            body = steps[name]
            if "shell: pwsh" not in body:
                errors.append(f"{name!r} must be `shell: pwsh`")
            if not re.search(r"^        timeout-minutes: (?:[1-9]|1[0-5])\s*$", body, re.M):
                errors.append(f"{name!r} must carry a `timeout-minutes` cap of 1 to 15 (a wedged logman must not hold the runner)")
            if "./scripts/ci/stop-dead-etw-sessions.ps1" not in body:
                errors.append(f"{name!r} must run ./scripts/ci/stop-dead-etw-sessions.ps1")
        if "-SelfTest" not in steps[SELFTEST]:
            errors.append("the self-test step must pass -SelfTest")
        for name in (SELFTEST, PRE):
            if re.search(r"^        ['\"]?(if|continue-on-error)['\"]?\s*:", steps[name], re.M):
                errors.append(f"{name!r} must not carry `if:` or `continue-on-error` (the guard would be silently off)")
        for name, phase in ((PRE, "pre-test"), (POST, "post-test")):
            if "-SelfTest" in steps[name]:
                errors.append(f"{name!r} must not pass -SelfTest")
            # the script's ValidateSet makes any other value a parameter-binding failure, which is a red step
            if not re.search(rf"^\s*run:\s+\./scripts/ci/stop-dead-etw-sessions\.ps1 -Phase {phase}\s*$", steps[name], re.M):
                errors.append(f"{name!r} must run the script with exactly `-Phase {phase}`")

    ps1 = PS1.read_text(encoding="utf-8")
    if any(ord(c) > 127 for c in ps1):
        errors.append("stop-dead-etw-sessions.ps1 must be ASCII only")
    # no `exit` with a non-zero code anywhere in the file (functions included), at the start of a line or after `;`,
    # `{` or `(`; only a -SelfTest throw may fail a step
    code = code_only(ps1)
    bad_exit = [c.rstrip(";})") for c in re.findall(r"(?:^|[;{(])\s*exit\s+(\S+)", code, re.M)]
    if any(c != "0" for c in bad_exit) or re.search(r"(?:^|[;{(])\s*exit\s*(?:$|[;})])", code, re.M):
        errors.append("the script must only ever `exit 0` (a failed -SelfTest expectation throws instead)")
    outside = ps1.split("if ($SelfTest) {", 1)
    # the self-test block ends at the first top-level `exit 0` + `}`; everything after it is real mode
    real_mode = outside[1].split("\n    exit 0\n}", 1)[-1] if len(outside) == 2 and "\n    exit 0\n}" in outside[1] else ""
    if not real_mode:
        errors.append("could not find the end of the -SelfTest block (expected `    exit 0` then `}`)")
    else:
        if re.search(r"^\s*throw\b", code_only(real_mode), re.M):
            errors.append("real mode must never start a statement with `throw` (housekeeping must not fail the job)")
        code_lines = [l.strip() for l in real_mode.splitlines() if l.strip() and not l.strip().startswith("#")]
        # the FIRST statement of real mode opens the catch-all, and the last-but-one closes it with a catch
        if not code_lines or code_lines[0] != "try {":
            errors.append("real mode must open with a catch-all `try {` before anything that can throw")
        elif not any(l.startswith("} catch {") for l in code_lines[-4:]):
            errors.append("real mode's catch-all `} catch {` must close the block right before the final `exit 0`")
        if not real_mode.rstrip().endswith("exit 0"):
            errors.append("the script's last statement must be `exit 0`")

    if errors:
        for e in errors:
            print("FAIL:", e)
        return 1
    print("etw cleanup wiring: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
