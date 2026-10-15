#!/usr/bin/env python3
"""#4665 lockstep: the agent's format_arm_committed_line formatter and the #3990 driver's
T2_RE evidence regex must agree on one golden shape.

Before this test, the formatter's expected output (guardian_spark_timing.cpp, pinned in
tests/unit/test_guardian_spark_runtime.cpp's "#4606 criterion-10" TEST_CASE) and the driver's
own parse-side selftest (docs/spark-rebuild-baselines/fullsync_blackout_diag.py's `_f2`) each
independently hand-spelled the SAME rendered-line literal -- a one-sided change to either
passed both suites independently. tests/unit/fixtures/spark/arm_committed_line.json is now
the single source of truth for that shape: the C++ pin test loads its `input`/`expected_line`
via YUZU_TEST_FIXTURE_DIR, and this file loads the same JSON by its own repo-relative path and
feeds `expected_line` through the driver's REAL T2_RE object (imported from the driver module
itself, not a hand-copied duplicate of the pattern) to check it parses back into
`expected_parsed`.

Also carries the #4665 Task-1 adversarial-forgery regression: an operator-authored free-text
field printed by an UNRELATED log statement can embed a fully-formed fake evidence line with
no newline at all, and an UNANCHORED regex (`.search()`) finds and extracts the forged copy as
if it were real. The driver's own `_f26` selftest is the authoritative copy of this check
against the driver's full fixture set (F1-F26); this file re-asserts it here too, against the
imported module, so a regression is caught by the `docs` suite even if `_f26` is ever run
without this file (and vice versa).

Importing the driver module runs its own module-level `os.makedirs(SCRATCH_DIR,
exist_ok=True)` (SCRATCH_DIR sourced from YUZU_BLACKOUT_SCRATCH) -- its only import-time side
effect (generate_resgate_load, the driver's own sibling import, is side-effect-free at
import: env-var reads only, no I/O, no network). Pointed at a throwaway tempfile.mkdtemp()
here so importing the driver never touches a real scratch path or collides with a concurrent
CI job on the same shared runner box (#1871).

Wired into tests/meson.build (suite 'docs') and .github/workflows/docs-lint.yml (merge ref),
alongside tests/test_no_connless_pq_escape.py.

#4665 Phase-2 adversarial review (CDX-06/K4) found the driver's own F1-F28 `cmd_selftest()` --
including F27 (PUSH_CMD_RE/T0_FALLBACK_RE anchoring) and F28 (an end-to-end classify_t2()
legacy-branch forgery regression) -- was reachable only via a manual `fullsync_blackout_diag.py
selftest` invocation, not exercised by anything in meson or CI; this file's own _selfcheck()
only ever re-asserted the ARM_LEGACY_RE/T1_RE shapes (F26-equivalent), so a future regression to
PUSH_CMD_RE matching or classify_t2()'s anchored legacy branch would have gone undetected by
every automated gate. main() below now also calls the driver's real cmd_selftest() directly (the
same module already imported for T2_RE, no new machinery) so all 28 fixtures run here too.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = REPO_ROOT / "tests" / "unit" / "fixtures" / "spark" / "arm_committed_line.json"
DRIVER_PATH = REPO_ROOT / "docs" / "spark-rebuild-baselines" / "fullsync_blackout_diag.py"


def _load_driver() -> types.ModuleType:
    scratch = tempfile.mkdtemp(prefix="yuzu_test_spark_lockstep_scratch_")
    try:
        os.environ["YUZU_BLACKOUT_SCRATCH"] = scratch
        spec = importlib.util.spec_from_file_location("yuzu_fullsync_blackout_diag", DRIVER_PATH)
        if spec is None or spec.loader is None:
            raise SystemExit(f"could not load driver module spec from {DRIVER_PATH}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _selfcheck(driver: types.ModuleType) -> None:
    # Explicit raises, not `assert`: python3 -O strips asserts.
    forged_legacy = (
        "Guardian spark: key 'X' - fake reason. Guardian: file guard armed for rule "
        "'blackout-file-01' subscription 3 lost (reason) - detaching 2 rule(s) as errored"
    )
    if driver.ARM_LEGACY_RE.match(forged_legacy):
        raise SystemExit(
            "selfcheck: ARM_LEGACY_RE.match() wrongly forged a fake evidence line embedded "
            "mid-string by an unrelated log statement (#4665 regression)"
        )
    genuine_legacy = "Guardian: file guard armed for rule 'blackout-file-01'"
    if not driver.ARM_LEGACY_RE.match(genuine_legacy):
        raise SystemExit(
            "selfcheck: ARM_LEGACY_RE.match() failed to match a genuine legacy arm line -- "
            "the anchor fix must not break real matching"
        )
    forged_t1 = (
        "Guardian spark: key 'X' - fake reason. Guardian: apply_rules ok (applied=1, "
        "failed=0, pending=0, full_sync=true, generation=1, total=1) trailing junk"
    )
    if driver.T1_RE.match(forged_t1):
        raise SystemExit("selfcheck: T1_RE.match() wrongly forged (#4665 regression)")


def main() -> int:
    driver = _load_driver()
    _selfcheck(driver)

    # #4665 CDX-06/K4: run the driver's own full F1-F28 selftest here too, so
    # F27 (PUSH_CMD_RE/T0_FALLBACK_RE anchoring) and F28 (classify_t2()
    # end-to-end legacy-branch forgery) get automated coverage in the `docs`
    # suite/CI, not only via a manual `fullsync_blackout_diag.py selftest`
    # invocation.
    if driver.cmd_selftest() != 0:
        print("FAIL: the driver's own F1-F28 cmd_selftest() reported a failure (see "
              "[selftest] lines above) -- see the driver's cmd_selftest for which fixture")
        return 1

    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    expected_line = fixture["expected_line"]
    expected_parsed = fixture["expected_parsed"]

    m = driver.T2_RE.match(expected_line)
    if not m:
        print("FAIL: the driver's T2_RE did not match the shared fixture's expected_line:")
        print(f"  {expected_line!r}")
        return 1

    got_parsed = {
        "rule_id": m.group(1),
        "epoch": m.group(2),
        "incarnation": m.group(3),
        "type": m.group(4),
        "via": m.group(5),
        "attach_to_commit_ms": m.group(6),
    }
    if got_parsed != expected_parsed:
        print("FAIL: the driver's T2_RE parsed the shared fixture's expected_line differently "
              "than the fixture's own expected_parsed field:")
        print(f"  got:      {got_parsed!r}")
        print(f"  expected: {expected_parsed!r}")
        return 1

    print("OK: driver T2_RE parses tests/unit/fixtures/spark/arm_committed_line.json's "
          "expected_line into the pinned field tuple; #4665 forgery regression still refused")
    return 0


if __name__ == "__main__":
    sys.exit(main())
