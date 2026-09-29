#!/usr/bin/env python3
"""Self-test that locks the split interlock merge-gate against silent neutering.

tests/test_split_interlock_tripwire.py enforces the ADR-0032 interlock by reading
its policy out of tests/split_interlock_ledger.json — a repo file editable in the
very PR the gate polices. That makes the gate tamper-EVIDENT, not tamper-PROOF: on
its own, a PR could open the gate by editing one JSON value (drop a cell from
gate_set, widen exclude_paths past where new engine code lands, delete an
engine-path marker, or flip a markerless gate cell green) with nothing to catch it.

This self-test is the lock. It pins the ledger's LOAD-BEARING CONSTANTS against
frozen values HERE, in test code, so neutering the gate requires editing these
constants too — which fails CI loudly and is a reviewable change the routed-concern
row routes to security review. It also exercises the tripwire's own logic against
mutated ledgers — the false-certification (RULE 2) path, the excluded-rationale guard,
the malformed-ledger error path, AND that RULE 1 actually FIRES on an engine-path
marker present in the tree while the gate is red (the last one closes the blind spot a
constant-pin cannot: a logic edit that inverts or removes the engine-path block itself,
which pinning keys/regexes does not catch). Coverage is not exhaustive — it locks the
checks probed here, not every possible logic edit — but it catches the inert-gate shapes
this gate's own prose names as the central risk.

Changing the interlock legitimately (e.g. WS-A6 lands a new gate prerequisite) means
editing BOTH the ledger and the matching constant below, in the same reviewed PR —
which is the intended, loud, auditable path, not a bug.

Wired into .github/workflows/docs-lint.yml alongside the tripwire. Stdlib only.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER = os.path.join(REPO_ROOT, "tests", "split_interlock_ledger.json")
TRIPWIRE = os.path.join(REPO_ROOT, "tests", "test_split_interlock_tripwire.py")

# --- FROZEN CONSTANTS (the lock). Editing the ledger to change any of these must
# --- also edit the value here — a loud, reviewed change, never a silent JSON edit.
EXPECTED_GATE_SET = ["a", "b", "c", "d", "h"]  # ADR-0032 unconditional set (a)-(d)+(h)
EXPECTED_SEARCH_PATHS = ["."]                   # whole tree; narrowing hides engine code
EXPECTED_EXCLUDE_PATHS = {
    "docs/",
    ".claude/",
    "changelog.d/",       # prose/evidence dirs that legitimately name markers
    "governance.d/",      # (this run's ledger records engine-path marker strings)
    "tests/split_interlock_ledger.json",
    "tests/test_split_interlock_tripwire.py",
    "tests/test_split_interlock_tripwire_selftest.py",
}
# The FULL marker dicts (keys AND regexes), not just the key sets — pinning keys
# alone let a silent neuter through: keep a marker's key but narrow its regex to a
# never-matching string and RULE 1 stops blocking that symbol undetected. Freezing
# the regexes closes that.
EXPECTED_ENGINE_PATH_MARKERS = {
    "run_row_store": {"regex": "use_case_runs"},
    "invocation_grant": {"regex": "invocation_grant|InvocationGrant"},
    "result_scoped_grant": {"regex": "release_authorization"},
    "finalisation_receipt": {"regex": "finalisation_receipt|finalization_receipt|FinalisationReceipt|FinalizationReceipt"},
    "served_from_run_id": {"regex": "served_from_run_id"},
    "released_input_digest": {"regex": "released_input_digest"},
    "reaper_metrics": {"regex": "yuzu_use_case_runs|yuzu_use_case_reaper"},
}
EXPECTED_SUBSTRATE_MARKERS = {
    "engine_principal_store": {"cell": "a", "regex": "engine_principal_store"},
    "principal_quota": {"cell": "m", "regex": "class PrincipalQuota"},
    "use_case_run_id": {"cell": "c", "regex": "use_case_run_id"},
    "release_log_store": {"cell": "d", "regex": "release_log|ReleaseLog"},
    "evaluate_as_operator": {"cell": "b", "regex": "evaluate_as_operator"},
    "capability_registry": {"cell": "h", "regex": "register_securable|create_securable|ratified_mapping"},
}

# Tripwire exit codes (mirror tests/test_split_interlock_tripwire.py) — a detected
# violation is 1, a malformed-ledger/grep error is 2. Asserting the EXACT code keeps
# a crash from masquerading as a correct detection.
TRIPWIRE_PASS = 0
TRIPWIRE_VIOLATION = 1
TRIPWIRE_ERROR = 2


def _fail(msg: str, failures: list) -> None:
    failures.append(msg)
    print(f"FAIL: {msg}", file=sys.stderr)


def _run_tripwire(ledger_path: str) -> int:
    """Invoke the tripwire against an alternate ledger; return its exit code."""
    proc = subprocess.run(
        [sys.executable, TRIPWIRE, ledger_path],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    return proc.returncode


def main() -> int:
    with open(LEDGER, encoding="utf-8") as fh:
        ledger = json.load(fh)
    failures: list[str] = []

    # 1. gate_set is pinned (UP-1) — a dropped gate cell would read the gate OPEN.
    if ledger.get("gate_set") != EXPECTED_GATE_SET:
        _fail(f"gate_set {ledger.get('gate_set')} != frozen {EXPECTED_GATE_SET}", failures)

    # 2. search_paths / exclude_paths pinned (UP-3) — a widened exclude or narrowed
    #    search hides where new engine code lands from RULE 1's grep.
    if ledger.get("search_paths") != EXPECTED_SEARCH_PATHS:
        _fail(f"search_paths {ledger.get('search_paths')} != frozen {EXPECTED_SEARCH_PATHS}", failures)
    if set(ledger.get("exclude_paths", [])) != EXPECTED_EXCLUDE_PATHS:
        _fail(f"exclude_paths {set(ledger.get('exclude_paths', []))} != frozen {EXPECTED_EXCLUDE_PATHS}", failures)

    # 3. marker dicts pinned in FULL (UP-4 + qe-4) — keys AND regexes. Deleting a
    #    marker unpins its symbol; narrowing its regex silently stops RULE 1 blocking it.
    if ledger.get("engine_path_markers") != EXPECTED_ENGINE_PATH_MARKERS:
        _fail("engine_path_markers (keys+regexes) drifted from the frozen set", failures)
    if ledger.get("substrate_markers") != EXPECTED_SUBSTRATE_MARKERS:
        _fail("substrate_markers (keys/cells/regexes) drifted from the frozen set", failures)

    # 4. every gate-set cell has a substrate marker (UP-2 / hp-1) — a markerless gate
    #    cell can be flipped green with no RULE 2 absence check.
    marked_cells = {spec["cell"] for spec in ledger.get("substrate_markers", {}).values()}
    for cell_id in EXPECTED_GATE_SET:
        if cell_id not in marked_cells:
            _fail(f"gate cell ({cell_id}) has no substrate_marker — RULE 2 cannot guard it", failures)

    # 5. every cell status is the exact enum (UP-12) — a typo silently skips RULE 2.
    for cell_id, spec in ledger.get("cells", {}).items():
        if spec.get("status") not in ("green", "red"):
            _fail(f"cell ({cell_id}) status {spec.get('status')!r} not in ('green','red')", failures)

    # 6. the tripwire's own logic still fires (guards against a future edit inverting a
    #    check — the false-green shape). Exercise it against mutated temp ledgers; the
    #    tripwire greps the real repo tree regardless of the ledger's location.
    def _write(obj, name: str, td: str) -> str:
        path = os.path.join(td, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return path

    with tempfile.TemporaryDirectory() as td:
        # Clean copy → PASS (exact code, so a crash cannot masquerade as a pass).
        rc = _run_tripwire(_write(ledger, "clean.json", td))
        if rc != TRIPWIRE_PASS:
            _fail(f"tripwire did not PASS on an unmodified ledger (got {rc}, want {TRIPWIRE_PASS})", failures)

        # False-certification: a green cell whose substrate is absent must fail. Force the
        # cell green AND neuter its substrate regex in the COPY, so this stays valid after
        # WS-A6 legitimately lands (d)'s substrate — otherwise, once (d) is really green with
        # its marker present, flipping it green is a no-op and this leg would wrongly demand a
        # VIOLATION a correct tripwire won't produce (mirrors the RULE-1 probe's self-containment).
        fc = json.loads(json.dumps(ledger))
        fc["cells"]["d"]["status"] = "green"
        fc["substrate_markers"]["release_log_store"]["regex"] = "__never_matches_substrate_zzz__"
        rc = _run_tripwire(_write(fc, "false_cert.json", td))
        if rc != TRIPWIRE_VIOLATION:
            _fail(f"tripwire did not DETECT a false certification (got {rc}, want {TRIPWIRE_VIOLATION})", failures)

        # Excluded-rationale guard: blank a rationale.
        br = json.loads(json.dumps(ledger))
        br["excluded"]["plan_hash"] = ""
        rc = _run_tripwire(_write(br, "blank_rationale.json", td))
        if rc != TRIPWIRE_VIOLATION:
            _fail(f"tripwire did not DETECT a blank excluded rationale (got {rc}, want {TRIPWIRE_VIOLATION})", failures)

        # Malformed ledger → ERROR, distinct from a detected violation (qe-3): drop a
        # required key and confirm the tripwire reports 2, not a violation-shaped 1.
        bad = json.loads(json.dumps(ledger))
        del bad["gate_set"]
        rc = _run_tripwire(_write(bad, "malformed.json", td))
        if rc != TRIPWIRE_ERROR:
            _fail(f"tripwire did not report ERROR on a malformed ledger (got {rc}, want {TRIPWIRE_ERROR})", failures)

        # RULE 1 actually FIRES (closes the blind spot a key/regex pin cannot: a logic
        # edit that inverts or drops the engine-path block). Inject a probe marker whose
        # regex matches an ALREADY-TRACKED code symbol (`compute_plan_hash`, the dispatch
        # grammar — present in server/ and NOT a real engine-path marker), while the gate
        # is red, and require the tripwire to BLOCK it. If someone inverts `if not
        # gate_open:` or deletes the RULE-1 loop, this probe stops being detected → the
        # tripwire returns PASS → this assertion fails. `compute_plan_hash` stays
        # `excluded` in the real ledger, so this proves RULE 1 without a false positive there.
        r1 = json.loads(json.dumps(ledger))
        # Force every gate cell red so the probe is valid regardless of the LIVE ledger's
        # state — once WS-A6 flips the real gate green, RULE 1 no-ops and this probe would
        # otherwise misfire. Forcing red also leaves no green cell, so RULE 2 greps nothing
        # and the only possible failure is RULE 1 firing on the injected marker.
        for _c in r1["gate_set"]:
            r1["cells"][_c]["status"] = "red"
        r1["engine_path_markers"]["__rule1_fires_probe__"] = {"regex": "compute_plan_hash"}
        rc = _run_tripwire(_write(r1, "rule1_probe.json", td))
        if rc != TRIPWIRE_VIOLATION:
            _fail(
                f"RULE 1 did not FIRE on an engine-path marker present in the tree while the "
                f"gate is red (got {rc}, want {TRIPWIRE_VIOLATION}) — the engine-path block is "
                f"inverted, removed, or otherwise inert",
                failures,
            )

    if failures:
        print(f"\n{len(failures)} interlock self-test failure(s).", file=sys.stderr)
        return 1
    print("split interlock self-test: OK — ledger constants pinned; tripwire logic fires.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
