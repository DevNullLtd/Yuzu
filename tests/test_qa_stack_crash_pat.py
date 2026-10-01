#!/usr/bin/env python3
"""Regression tests for the gateway crash signatures in scripts/ci/qa-stack.sh.

`qa-stack.sh crash-check` greps each service's log for crash signatures; for
the gateway it adds GW_CRASH_PAT. On v0.14.0-rc4's soak it printed "no crash
signatures" while beam.smp had aborted at boot (#2150), because the list held
OTP process-crash shapes but not the VM dying outright. These tests rebuild
the exact pattern crash-check uses (the base `pat=` plus every GW_CRASH_PAT
line, evaluated by bash) and grep fixture lines with it, so a later edit that
breaks the `+=` chain or drops a signature fails here rather than on a red
release.

qa-stack.sh cannot be sourced (its dispatcher runs on load), so the pattern
lines are extracted from the file.
"""

import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
QA_STACK = ROOT / "scripts" / "ci" / "qa-stack.sh"

CRASHES = [
    # #2150: ERTS abort at boot on an AMX CPU (rc4 soak, verbatim).
    "sys/unix/sys_signal_stack.c:103:sys_sigaltstack(): Internal error: "
    "Failed to set alternate signal stack",
    # A failed boot (#5171's crypto NIF shape).
    'Kernel pid terminated (application_controller) ("{application_start_failure,'
    'kernel,{{shutdown,{failed_to_start_child,on_load,{on_load_function_failed,crypto,',
    "Crash dump is being written to: erl_crash.dump...done",
    # The OTP shapes that were already covered must stay covered.
    "2026-10-01T11:52:33.555557+00:00 [error] <0.704.0> crasher: initial call: "
    "application_master:init/3, pid: <0.704.0>",
    "2026-10-01T11:52:33.5+00:00 [error] <0.84.0> Supervisor: {local,yuzu_gw_sup}. "
    "Context: child_terminated. Reason: killed",
    "=CRASH REPORT==== 1-Oct-2026::11:52:33.555557 ===",
    "=SUPERVISOR REPORT==== 1-Oct-2026::11:52:33.555557 ===",
    "Reason: reached_max_restart_intensity",
    # The base pattern every service shares.
    "Segmentation fault (core dumped)",
    "AddressSanitizer: heap-use-after-free; ASAN report follows",
]

HEALTHY = [
    "2026-10-01T11:53:09.995995+00:00 [info] <0.712.0> Supervisor: {local,yuzu_gw_sup}. "
    "Started: id=yuzu_gw_health,pid=<0.720.0>.",
    "2026-10-01T11:54:54.377775+00:00 [info] <0.720.0> Health endpoint listening on port "
    "8081 (/healthz, /readyz)",
    "2026-10-01T11:53:09.996093+00:00 [info] <0.571.0> Application: yuzu_gw. Started at: "
    "'yuzu_gw@127.0.0.1'.",
    "2026-10-01T12:00:00+00:00 [warning] <0.900.0> mgmt_auth reject reason=internal_error",
    '2026-10-01T12:00:00+00:00 [error] <0.901.0> upstream call failed: message="Internal error"',
]


def crash_check_pattern():
    """The gateway's full crash-check pattern, as cmd_crash_check builds it."""
    text = QA_STACK.read_text(encoding="utf-8")
    named = [l for l in text.splitlines() if l.lstrip().startswith("GW_CRASH_PAT")]
    gw = [l for l in named if re.match(r"GW_CRASH_PAT\+?='", l)]
    if gw != named:
        bad = [l for l in named if l not in gw]
        raise AssertionError(f"GW_CRASH_PAT line(s) this test cannot read: {bad}")
    if not gw or not gw[0].startswith("GW_CRASH_PAT="):
        raise AssertionError("GW_CRASH_PAT assignments not found in qa-stack.sh")
    if 'pat+="|$GW_CRASH_PAT"' not in text:
        raise AssertionError("cmd_crash_check no longer adds GW_CRASH_PAT to the gateway pattern")
    base = re.search(r"^\s*pat='([^']*)'\s*$", text, re.M)
    if not base:
        raise AssertionError("crash-check base pattern (pat='...') not found in qa-stack.sh")
    script = "\n".join(gw) + '\nprintf %s "$GW_CRASH_PAT"\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    return base.group(1) + "|" + r.stdout


@unittest.skipIf(
    os.name == "nt" or not shutil.which("bash") or not shutil.which("grep"),
    "needs bash and grep",
)
class GatewayCrashPattern(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pat = crash_check_pattern()

    def matches(self, line):
        r = subprocess.run(["grep", "-iE", "--", self.pat], input=line + "\n",
                           capture_output=True, text=True)
        self.assertIn(r.returncode, (0, 1), r.stderr)
        return r.returncode == 0

    def test_crash_lines_match(self):
        for line in CRASHES:
            with self.subTest(line=line[:60]):
                self.assertTrue(self.matches(line), f"crash-check would miss: {line}")

    def test_healthy_lines_do_not_match(self):
        for line in HEALTHY:
            with self.subTest(line=line[:60]):
                self.assertFalse(self.matches(line), f"crash-check would flag: {line}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
