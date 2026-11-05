#!/usr/bin/env python3
"""Pins the Windows job's wiring of scripts/ci/stop-dead-etw-sessions.ps1 (#7175).

BEST-EFFORT source-text tripwire: the script's decisions are proved on a Windows runner by its own -SelfTest
step, but nothing there notices the steps being deleted, reordered behind the suite, or the post-test step losing
its `always()`. This reads .github/workflows/ci.yml's `windows:` job and checks:

  1. the self-test step, the pre-test cleanup and `Test (non-pg suites)` appear in that order, once each;
  2. the post-test cleanup comes after `Test (non-pg suites)` and carries `if: always()` (a cancelled job still
     runs it; an `if:` with no status function would be skipped on failure);
  3. every call is `shell: pwsh` and goes through the one script, with -SelfTest only on the self-test step;
  4. the script is ASCII only (Windows PowerShell 5.1 misreads BOM-less UTF-8), and has no `exit 1`/`throw` outside
     the -SelfTest block's own expectation helper, so housekeeping can never turn the test phase red.
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
            if "./scripts/ci/stop-dead-etw-sessions.ps1" not in body:
                errors.append(f"{name!r} must run ./scripts/ci/stop-dead-etw-sessions.ps1")
        if "-SelfTest" not in steps[SELFTEST]:
            errors.append("the self-test step must pass -SelfTest")
        for name in (PRE, POST):
            if "-SelfTest" in steps[name]:
                errors.append(f"{name!r} must not pass -SelfTest")
            if "-Phase" not in steps[name]:
                errors.append(f"{name!r} should name its -Phase")

    ps1 = PS1.read_text(encoding="utf-8")
    if any(ord(c) > 127 for c in ps1):
        errors.append("stop-dead-etw-sessions.ps1 must be ASCII only")
    outside = ps1.split("if ($SelfTest) {", 1)
    real_mode = outside[1].split("\nexit 0\n}", 1)[-1] if len(outside) == 2 else ""
    if len(outside) != 2 or "exit 1" in real_mode or re.search(r"^\s*throw\b", real_mode, re.M):
        errors.append("real mode must end `exit 0` and never `exit 1`/`throw` (housekeeping must not fail the job)")
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
