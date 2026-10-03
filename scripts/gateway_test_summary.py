#!/usr/bin/env python3
"""Zero-executed guard for the Meson gateway test wrapper (#4800).

The one summary parser for every gateway test gate: imported by
scripts/test_gateway.py (the Meson gate, via require_tests_executed), and run
as a CLI (`cancel-tolerant`) by scripts/test/eunit-gate.sh (/test) and the
release workflow's EUnit step. Pinned by tests/test_gateway_test_summary.py.
Kept in its own module (not inline in the wrapper) because the wrapper runs
rebar3 at import time and so cannot be imported by a test.

"""
import re
import sys

# rebar3 exits 0 when it discovers nothing to run, so a green exit code
# alone proves nothing. A run is only a pass if its final summary line
# reports at least one EXECUTED (passed + failed) test. Summary shapes:
#   ct:    "All 52 tests passed."
#          "Failed 6 tests. Skipped 2 (0, 2) tests. Passed 44 tests."
#   eunit: "All 311 tests passed."  "2 tests passed."  "Test passed."
#          "Failed: 2.  Skipped: 0.  Passed: 309."
#          "There were no tests to run."
# The LAST summary wins. That is sound for the invocations used today: one
# `rebar3 ct --dir ...` (or one `rebar3 eunit`) prints exactly ONE genuine
# summary, so anything matching earlier is test-emitted noise. It is NOT an
# unconditional guarantee: an invocation that makes rebar3 print several
# genuine summaries (for example `ct --spec`, one per group) would have only
# its last one judged, so an early failure could be masked by a later pass.
# tests/test_gateway_test_summary.py pins that outcome; change the
# invocation shape and that pin forces a decision about aggregating.
# No recognisable summary on an otherwise-green run is ALSO a failure: we
# cannot confirm anything ran.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Each alternative must be the WHOLE line (re.M + ^...$): rebar3 and eunit
# always print their summary on a line of its own (eunit_tty.erl,
# rebar_prv_common_test), so anchoring stops a test's own log text that
# merely CONTAINS e.g. "All 5 tests passed." from standing in for a
# summary that truncated output never delivered (#4800 Gate 5 CH-1).
_SUMMARY_RE = re.compile(
    r"^[ \t]*(?:"
    # ct and eunit, all green
    r"All (?P<all>\d+) tests? passed\."
    # eunit prints exactly one / exactly two passing tests differently
    r"|(?P<one>Test passed\.)"
    r"|(?P<two>2) tests passed\."
    # ct: each clause is printed only when its count is non-zero, except
    # "Passed", which is always printed
    r"|(?:Failed (?P<cf>\d+) tests?\. )?(?:Skipped \d+ \(\d+, \d+\) tests?\. )?"
    r"Passed (?P<cp>\d+) tests?\."
    # eunit, any failure/skip/cancel
    r"|Failed: (?P<ef>\d+)\.[ \t]+Skipped: \d+\.[ \t]+Passed: (?P<ep>\d+)\."
    r"|(?P<none>There were no tests to run)\.?"
    r")[ \t\r]*$",
    re.M,
)


def last_summary(text):
    """(executed, failed, eunit_failed_line) from the LAST summary, or None.

    eunit_failed_line is True only for eunit's "Failed: F.  Skipped: S.
    Passed: P." shape, the one shape #1005's cancellation tolerance applies to.
    """
    last = None
    for m in _SUMMARY_RE.finditer(_ANSI_RE.sub("", text)):
        last = m
    if last is None:
        return None
    g = last.group
    if g("all") is not None:
        return int(g("all")), 0, False
    if g("one") is not None:
        return 1, 0, False
    if g("two") is not None:
        return 2, 0, False
    if g("none") is not None:
        return 0, 0, False
    if g("cp") is not None:
        failed = int(g("cf") or 0)
        return failed + int(g("cp")), failed, False
    failed = int(g("ef"))
    return failed + int(g("ep")), failed, True


def executed_count(text):
    """Executed (passed + failed) count from the last summary, or None."""
    s = last_summary(text)
    return None if s is None else s[0]


def require_tests_executed(text, label, returncode):
    """Turn a green exit with zero executed tests into a failure."""
    if returncode != 0:
        return returncode
    executed = executed_count(text)
    if executed is None:
        print(f"\n[test_gateway.py] {label}: rebar3 exited 0 but printed no "
              "recognisable test summary -- cannot confirm any test ran. "
              "Failing (#4800). If rebar3 changed its summary wording, "
              "update scripts/gateway_test_summary.py.", file=sys.stderr)
        return 1
    if executed == 0:
        print(f"\n[test_gateway.py] {label}: rebar3 exited 0 but executed ZERO "
              "tests -- nothing was discovered (wrong suite directory / --dir) "
              "or every test was skipped (check the CT/eunit logs). Failing so "
              "this cannot pass as a false green (#4800).", file=sys.stderr)
        return 1
    print(f"\n[test_gateway.py] {label}: {executed} tests executed.")
    return 0


def cancel_tolerant_verdict(text, returncode):
    """Verdict for the EUnit gates that tolerate cancelled sets (#1005).

    Used by scripts/test/eunit-gate.sh (/test) and the release workflow's
    EUnit step, so all three gateway test gates share ONE parser. Returns
    (exit_code, level, message); level is None, "warning" or "error".

      - no recognisable summary        -> 1 (rebar3 failed before tests ran,
                                            or the capture was truncated)
      - zero tests executed            -> 1 (every set cancelled, or nothing
                                            discovered: the #4800 class)
      - rc 0 with >= 1 executed        -> 0
      - rc != 0, eunit "Failed: 0" line
        with >= 1 passed               -> 0 with a warning (cancellations,
                                            #1005)
      - anything else                  -> 1
    """
    s = last_summary(text)
    if s is None:
        return 1, "error", (
            f"EUnit printed no recognisable test summary (rebar3 rc={returncode}) "
            "-- rebar3 failed before any test ran, or the output was cut short. "
            "If rebar3 changed its summary wording, update "
            "scripts/gateway_test_summary.py.")
    executed, failed, eunit_failed_line = s
    if executed == 0:
        return 1, "error", (
            "EUnit executed zero tests (every set cancelled, or nothing was "
            "discovered) -- nothing was tested (#4800).")
    if returncode == 0:
        return 0, None, None
    if eunit_failed_line and failed == 0:
        return 0, "warning", (
            f"EUnit exited {returncode} but 0 tests failed and {executed} ran "
            "-- cancelled sets are tolerated (#1005).")
    return 1, "error", (
        f"EUnit exited {returncode} with {failed} failed of {executed} executed.")


def _main(argv):
    """CLI: gateway_test_summary.py cancel-tolerant RC LOGFILE [--github]"""
    if len(argv) < 3 or argv[0] != "cancel-tolerant":
        print("usage: gateway_test_summary.py cancel-tolerant RC LOGFILE [--github]",
              file=sys.stderr)
        return 2
    try:
        rc = int(argv[1])
        with open(argv[2], encoding="utf-8", errors="replace") as f:
            text = f.read()
    except (ValueError, OSError) as exc:
        print(f"gateway_test_summary: {exc}", file=sys.stderr)
        return 2
    code, level, message = cancel_tolerant_verdict(text, rc)
    if message:
        if "--github" in argv[3:]:
            print(f"::{level}::{message}")
        else:
            print(f"eunit-gate: {level}: {message}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
