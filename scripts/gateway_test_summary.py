#!/usr/bin/env python3
"""Zero-executed guard for the Meson gateway test wrapper (#4800).

The one summary parser for every gateway test gate: imported by
scripts/test_gateway.py (the Meson gate, via require_tests_executed), and run
as a CLI by scripts/test/eunit-gate.sh (/test) and the release workflow's
EUnit step and by gateway/test_runner.sh. Every gate is strict: cancellation,
nonzero exit, failed assertions and zero execution cannot pass. The old
`cancel-tolerant` CLI remains a fail-closed compatibility alias. Pinned by
tests/test_gateway_test_summary.py.
Kept in its own module (not inline in the wrapper) because the wrapper runs
rebar3 at import time and so cannot be imported by a test.

"""
import re
import sys
import tempfile
from pathlib import Path

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
_CANCELLED_RE = re.compile(r"^[ \t]*One or more tests were cancelled\.[ \t\r]*$", re.M)
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
    Passed: P." shape (retained for callers inspecting summary format).
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


def strict_verdict(text, returncode):
    """Return (exit_code, level, message) without accepting partial cancellation.

    A nonzero child status is preserved. Even a zero status cannot override
    a failed summary or EUnit's cancellation marker. The final summary must
    still establish that at least one test ran (#4800).
    """
    s = last_summary(text)
    cancelled = bool(_CANCELLED_RE.search(_ANSI_RE.sub("", text)))
    if returncode != 0:
        detail = (f"summary reports {s[1]} failed of {s[0]} executed."
                  if s else "no recognisable test summary.")
        if cancelled:
            detail += " EUnit cancelled tests; execution is incomplete."
        return returncode, "error", f"Test run exited {returncode}; {detail}"
    if s is None:
        return 1, "error", (
            "Test run printed no recognisable test summary -- cannot confirm any "
            "test ran. Check the capture and summary format (#4800).")
    executed, failed, _ = s
    if executed == 0:
        return 1, "error", (
            "Test run executed ZERO tests -- nothing was discovered or every "
            "test was skipped/cancelled (#4800).")
    if failed:
        return 1, "error", f"Test summary reports {failed} failed of {executed} executed."
    if cancelled:
        return 1, "error", "EUnit cancelled tests; partial execution cannot pass."
    return 0, None, f"{executed} tests executed."


def failure_context(text):
    """Bounded native context for Meson's console tail, never verdict evidence.

    Successful tests intentionally emit ERROR REPORTs. Only callers that have
    already established failure use this heuristic; the complete log is kept.
    """
    lines = _ANSI_RE.sub("", text).splitlines()
    marker = re.compile(r"\*failed\*|\*{3}.*(?:failed|timed out|unexpected termination)|"
                        r"==>.*: FAILED|^\*\*error:|init terminating in do_boot|"
                        r"^===>.*(?:failed|Error)", re.I)
    first = next((i for i, line in enumerate(lines) if marker.search(line)), None)
    start = max(0, first - 2) if first is not None else max(0, len(lines) - 40)
    excerpt = []
    for i in range(start, min(start + 40, len(lines))):
        line = lines[i]
        excerpt.append(f"{i + 1}: {line[:500]}" + (" [line truncated]" if len(line) > 500 else ""))
    return "\n".join(excerpt)


def require_tests_executed(text, label, returncode, prog="test_gateway.py", *, log_dir=None):
    """Require successful completion and a nonempty successful summary."""
    code, level, message = strict_verdict(text, returncode)
    if code and text:
        log_path = None
        if log_dir is not None:
            try:
                Path(log_dir).mkdir(parents=True, exist_ok=True)
                slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", label)[:80]
                # Unique, closed files survive retries and concurrent Meson runs.
                with tempfile.NamedTemporaryFile(
                        mode="w", encoding="utf-8", newline="", delete=False,
                        prefix=f"yuzu_test_gateway_{slug}_", suffix=".log", dir=log_dir) as log:
                    log.write(text)
                log_path = log.name
            except OSError as exc:
                # Diagnostics must not replace the actual child failure status.
                print(f"[{prog}] could not save gateway output: {exc}", file=sys.stderr)
        print(f"\n[{prog}] {label}: native failure context (excerpt; not the complete log):\n"
              f"{failure_context(text)}", file=sys.stderr)
        if log_path is not None:
            print(f"[{prog}] Full gateway output: {log_path}", file=sys.stderr)
    print(f"\n[{prog}] {label}: {message}", file=sys.stderr if level else sys.stdout)
    return code


def cancel_tolerant_verdict(text, returncode):
    """Deprecated name retained for older callers; cancellations now fail.

    #1005 accepted a partially cancelled run when some tests passed. That
    cannot establish completion of the requested suite, so all callers now
    use the same strict verdict, including this compatibility entrypoint.
    """
    return strict_verdict(text, returncode)


_USAGE = ("usage: gateway_test_summary.py cancel-tolerant RC LOGFILE [--github]\n"
          "       gateway_test_summary.py strict LABEL RC LOGFILE")


def _main(argv):
    """CLI.

    cancel-tolerant RC LOGFILE [--github]: deprecated strict compatibility alias.
    strict LABEL RC LOGFILE: the Meson wrapper's rule for a gate that keeps
    rebar3's own exit code (a non-zero rc stays non-zero; a green rc must
    have executed >= 1 test without failure or cancellation). Used by all gates.
    """
    mode = argv[0] if argv else None
    if mode == "cancel-tolerant" and len(argv) >= 3:
        rc_arg, log_arg = argv[1], argv[2]
    elif mode == "strict" and len(argv) == 4:
        rc_arg, log_arg = argv[2], argv[3]
    else:
        print(_USAGE, file=sys.stderr)
        return 2
    try:
        rc = int(rc_arg)
        with open(log_arg, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except (ValueError, OSError) as exc:
        print(f"gateway_test_summary: {exc}", file=sys.stderr)
        return 2
    if mode == "strict":
        return require_tests_executed(text, argv[1], rc, prog="gateway_test_summary.py")
    code, level, message = cancel_tolerant_verdict(text, rc)
    if message and level:
        if "--github" in argv[3:]:
            print(f"::{level}::{message}")
        else:
            print(f"eunit-gate: {level}: {message}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
