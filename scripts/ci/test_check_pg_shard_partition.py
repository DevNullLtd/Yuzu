#!/usr/bin/env python3
"""Unit test for check-pg-shard-partition.py's own detection logic.

Governance Gate 3/4 finding (#3443 Phase 1): the checker shipped with no
permanent regression test of its own — only ad-hoc, uncommitted manual
mutation testing done once during development (a gap, a duplication, a
shard silently dropping suite membership). Every comparable local
CI-tooling self-test (flake-retry.py --selftest, check-plugin-spawn-
lexical.sh --selftest, tsan-gdb-capture.py --selftest) exercises its own
parsing/decision logic against synthetic fixtures, independent of a real
build. This does the same, exercising `parse_shard_entries()` and
`check_partition()` directly against synthetic `meson introspect --tests`
JSON and synthetic Catch2 `--list-tests --reporter xml` output — no real
build, no real yuzu_server_tests binary needed, matching the pure/IO
split the script itself was refactored to have for exactly this reason.

Run: python3 scripts/ci/test_check_pg_shard_partition.py   (exit 0 = pass)
"""
import argparse
import contextlib
import importlib.util
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "check-pg-shard-partition.py")

_spec = importlib.util.spec_from_file_location("check_pg_shard_partition", MODULE_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

SUITE = _mod.SERVER_PG_SUITE
SMOKE_SUITE = _mod.SERVER_PG_SMOKE_SUITE
AGENT_SUITE = _mod.AGENT_SHARD_SUITE


def _entry(name, exe="/fake/exe", spec="[pg][x]", extra_args=None, suite=SUITE):
    """One `meson introspect --tests` entry, server-pg-suite by default.
    Pass suite=SMOKE_SUITE for a server-pg-smoke fixture (#3443 Phase 2)."""
    cmd = [exe, spec] + (extra_args or [])
    return {"name": name, "cmd": cmd, "suite": ["yuzu:server", suite]}


def _xml(cases):
    """Synthetic Catch2 `--list-tests --reporter xml` document for `cases`,
    a list of (name, file, line) tuples."""
    body = "".join(
        f'<TestCase><Name>{n}</Name><ClassName/><Tags/>'
        f'<SourceInfo><File>{f}</File><Line>{l}</Line></SourceInfo></TestCase>'
        for n, f, l in cases
    )
    return f'<?xml version="1.0"?><MatchingTests>{body}</MatchingTests>'


def check(cond, label, failures):
    if cond:
        print(f"  ok       {label}")
    else:
        print(f"  FAIL     {label}")
        failures.append(label)


def test_parse_shard_entries_happy_path(failures):
    tests = [
        _entry("server pg unit tests shard A", spec="[pg][a]"),
        _entry("server pg unit tests shard B", spec="[pg][b]"),
        {"name": "unrelated docs test", "cmd": ["x"], "suite": ["yuzu:docs"]},
        {"name": "non-pg server test", "cmd": ["x", "~[pg]"], "suite": ["yuzu:server"]},
    ]
    entries, errors = _mod.parse_shard_entries(tests)
    check(errors == [], "happy path: no shape errors", failures)
    check(len(entries) == 2, "happy path: only the 2 server-pg entries found", failures)
    check(entries[0] == ("server pg unit tests shard A", "/fake/exe", "[pg][a]"),
          "happy path: entry tuple shape correct", failures)


def test_parse_shard_entries_collects_all_shape_errors(failures):
    # Governance Gate 4 consistency-auditor F2: two simultaneously-malformed
    # entries must BOTH be reported, not just the first.
    tests = [
        {"name": "shard broken zero specs", "cmd": ["/fake/exe"],
         "suite": ["yuzu:server", SUITE]},
        {"name": "shard broken two specs",
         "cmd": ["/fake/exe", "[pg][a]", "[pg][b]"],
         "suite": ["yuzu:server", SUITE]},
    ]
    entries, errors = _mod.parse_shard_entries(tests)
    check(entries == [], "two malformed entries: zero well-shaped entries returned", failures)
    check(len(errors) == 2, "two malformed entries: BOTH errors collected, not just the first", failures)
    check(any("shard broken zero specs" in e for e in errors),
          "zero-spec entry's error present", failures)
    check(any("shard broken two specs" in e for e in errors),
          "two-spec entry's error present", failures)


def test_parse_shard_entries_options_are_fine(failures):
    tests = [_entry("shard with option", extra_args=["--allow-running-no-tests"])]
    entries, errors = _mod.parse_shard_entries(tests)
    check(errors == [], "a -- option alongside one spec is not a shape error", failures)
    check(len(entries) == 1, "entry with an option still extracted", failures)


def test_check_partition_clean(failures):
    entries = [("shard A", "/fake/exe", "[pg][a]"), ("shard B", "/fake/exe", "[pg][b]")]
    cases_by_spec = {
        "[pg]": {("t1", "f.cpp", "1"), ("t2", "f.cpp", "2")},
        "[pg][a]": {("t1", "f.cpp", "1")},
        "[pg][b]": {("t2", "f.cpp", "2")},
    }
    ok, fail_msgs, stats = _mod.check_partition(
        entries, lambda exe, spec: cases_by_spec[spec])
    check(ok, "clean partition: reports OK", failures)
    check(fail_msgs == [], "clean partition: no failure messages", failures)
    check(stats == {"shard_count": 2, "case_count": 2}, "clean partition: stats correct", failures)


def test_check_partition_gap(failures):
    # A case tagged [pg] that no shard's filter matches.
    entries = [("shard A", "/fake/exe", "[pg][a]")]
    cases_by_spec = {
        "[pg]": {("t1", "f.cpp", "1"), ("t2", "f.cpp", "2")},
        "[pg][a]": {("t1", "f.cpp", "1")},
    }
    ok, fail_msgs, _ = _mod.check_partition(entries, lambda exe, spec: cases_by_spec[spec])
    check(not ok, "gap: reports not-ok", failures)
    check(any("in NO" in m and "shard" in m and "t2" in m for m in fail_msgs),
          "gap: failure message names the orphaned case", failures)
    check(any("(f.cpp:2)" in m for m in fail_msgs),
          "gap: failure message includes file:line (quality-engineer LOW)", failures)


def test_check_partition_duplication(failures):
    entries = [("shard A", "/fake/exe", "[pg][a]"), ("shard B", "/fake/exe", "[pg][b]")]
    cases_by_spec = {
        "[pg]": {("t1", "f.cpp", "1")},
        "[pg][a]": {("t1", "f.cpp", "1")},
        "[pg][b]": {("t1", "f.cpp", "1")},  # same case, claimed by both
    }
    ok, fail_msgs, _ = _mod.check_partition(entries, lambda exe, spec: cases_by_spec[spec])
    check(not ok, "duplication: reports not-ok", failures)
    check(any("appears in BOTH" in m and "t1" in m for m in fail_msgs),
          "duplication: failure message names the duplicated case", failures)


def test_check_partition_extra(failures):
    # A shard filter matches a case NOT tagged [pg] at all (over-broad filter).
    entries = [("shard A", "/fake/exe", "[pg][a]")]
    cases_by_spec = {
        "[pg]": {("t1", "f.cpp", "1")},
        "[pg][a]": {("t1", "f.cpp", "1"), ("stray", "f.cpp", "9")},
    }
    ok, fail_msgs, _ = _mod.check_partition(entries, lambda exe, spec: cases_by_spec[spec])
    check(not ok, "extra: reports not-ok", failures)
    check(any("not in the" in m and "reference set" in m and "stray" in m for m in fail_msgs),
          "extra: failure message names the over-matched case", failures)


def test_check_partition_multiple_binaries(failures):
    entries = [("shard A", "/exe/one", "[pg][a]"), ("shard B", "/exe/two", "[pg][b]")]
    ok, fail_msgs, _ = _mod.check_partition(entries, lambda exe, spec: {("t", "f", "1")})
    check(not ok, "multiple binaries: reports not-ok", failures)
    check(any("different binaries" in m for m in fail_msgs),
          "multiple binaries: failure message names the mismatch", failures)


def test_check_partition_empty_reference(failures):
    entries = [("shard A", "/fake/exe", "[pg][a]")]
    ok, fail_msgs, _ = _mod.check_partition(entries, lambda exe, spec: set())
    check(not ok, "empty reference set: reports not-ok", failures)
    check(any("reference set itself is empty" in m for m in fail_msgs),
          "empty reference set: failure message says so", failures)


def test_check_partition_zero_case_shard(failures):
    entries = [("shard A", "/fake/exe", "[pg][a]"), ("shard B", "/fake/exe", "[pg][b]")]
    cases_by_spec = {
        "[pg]": {("t1", "f.cpp", "1")},
        "[pg][a]": {("t1", "f.cpp", "1")},
        "[pg][b]": set(),  # a shard whose filter matches nothing
    }
    ok, fail_msgs, _ = _mod.check_partition(entries, lambda exe, spec: cases_by_spec[spec])
    check(not ok, "zero-case shard: reports not-ok", failures)
    check(any("matched ZERO cases" in m and "shard B" in m for m in fail_msgs),
          "zero-case shard: failure message names the empty shard", failures)


def test_parse_nonpg_entries_happy_path(failures):
    # Windows CI test-phase restructuring (#3443, 2026-08-28): parse_nonpg_entries
    # mirrors parse_shard_entries exactly (same _parse_suite_entries shape
    # rules), just against SERVER_NONPG_SUITE instead of SERVER_PG_SUITE.
    tests = [
        _entry("server unit tests shard A", spec="~[pg][a]", suite=_mod.SERVER_NONPG_SUITE),
        _entry("server unit tests shard B", spec="~[pg][b]", suite=_mod.SERVER_NONPG_SUITE),
        _entry("server pg unit tests shard A", spec="[pg][a]"),  # pg shard ignored here
    ]
    entries, errors = _mod.parse_nonpg_entries(tests)
    check(errors == [], "nonpg happy path: no shape errors", failures)
    check(len(entries) == 2, "nonpg happy path: only the 2 server-nonpg entries found", failures)
    check(entries[0] == ("server unit tests shard A", "/fake/exe", "~[pg][a]"),
          "nonpg happy path: entry tuple shape correct", failures)


def test_check_partition_nonpg_ref_spec_and_label(failures):
    # The actually-NEW behavior: check_partition's ref_spec/label parameters,
    # exercised with the non-pg values so a failure message never
    # misleadingly says "[pg]"/"server-pg" while checking the non-pg
    # partition (Sol review finding).
    entries = [("shard A", "/fake/exe", "~[pg][a]"), ("shard B", "/fake/exe", "~[pg][b]")]
    cases_by_spec = {
        "~[pg]": {("t1", "f.cpp", "1"), ("t2", "f.cpp", "2")},
        "~[pg][a]": {("t1", "f.cpp", "1")},
        "~[pg][b]": {("t2", "f.cpp", "2")},
    }
    ok, fail_msgs, stats = _mod.check_partition(
        entries, lambda exe, spec: cases_by_spec[spec],
        ref_spec=_mod.NONPG_REF_SPEC, label="server-nonpg")
    check(ok, "nonpg clean partition: reports OK", failures)
    check(stats == {"shard_count": 2, "case_count": 2}, "nonpg clean partition: stats correct", failures)

    # Same fixture shape as test_check_partition_gap, but nonpg-labelled —
    # proves the wording carries the RIGHT label, not just that it fails.
    gap_entries = [("shard A", "/fake/exe", "~[pg][a]")]
    gap_cases = {
        "~[pg]": {("t1", "f.cpp", "1"), ("t2", "f.cpp", "2")},
        "~[pg][a]": {("t1", "f.cpp", "1")},
    }
    gap_ok, gap_fail_msgs, _ = _mod.check_partition(
        gap_entries, lambda exe, spec: gap_cases[spec],
        ref_spec=_mod.NONPG_REF_SPEC, label="server-nonpg")
    check(not gap_ok, "nonpg gap: reports not-ok", failures)
    check(any("server-nonpg" in m and "t2" in m for m in gap_fail_msgs),
          "nonpg gap: failure message carries the server-nonpg label, not server-pg/[pg]", failures)
    check(not any("[pg]" in m.replace("~[pg]", "") for m in gap_fail_msgs),
          "nonpg gap: failure message never says the bare pg reference (only ~[pg])", failures)

    # Duplication, nonpg-labelled — mirrors test_check_partition_duplication.
    dup_entries = [("shard A", "/fake/exe", "~[pg][a]"), ("shard B", "/fake/exe", "~[pg][b]")]
    dup_cases = {
        "~[pg]": {("t1", "f.cpp", "1")},
        "~[pg][a]": {("t1", "f.cpp", "1")},
        "~[pg][b]": {("t1", "f.cpp", "1")},
    }
    dup_ok, dup_fail_msgs, _ = _mod.check_partition(
        dup_entries, lambda exe, spec: dup_cases[spec],
        ref_spec=_mod.NONPG_REF_SPEC, label="server-nonpg")
    check(not dup_ok, "nonpg duplication: reports not-ok", failures)
    check(any("appears in BOTH" in m and "t1" in m for m in dup_fail_msgs),
          "nonpg duplication: failure message names the duplicated case", failures)


def test_parse_list_tests_xml(failures):
    xml = _xml([("RbacStore: thing", "test_rbac_store.cpp", "42")])
    cases = _mod.parse_list_tests_xml(xml)
    check(cases == {("RbacStore: thing", "test_rbac_store.cpp", "42")},
          "parse_list_tests_xml: extracts (name, file, line) correctly", failures)


# ============================================================================
# check_smoke() / parse_smoke_entries() — #3443 Phase 2
# ============================================================================

def _smoke_cases(n):
    """n synthetic (name, file, line) tuples, all distinct."""
    return {(f"smoke case {i}", "f.cpp", str(i)) for i in range(n)}


def _with_exact_cases(n, fn):
    """Run fn() with _mod.SMOKE_EXACT_CASES temporarily set to n, always
    restoring the real (measured-against-the-binary) value afterward — the
    real value must never leak stale across tests or survive a failure."""
    saved = _mod.SMOKE_EXACT_CASES
    _mod.SMOKE_EXACT_CASES = n
    try:
        fn()
    finally:
        _mod.SMOKE_EXACT_CASES = saved


def _smoke_entry(name=_mod.SMOKE_ENTRY_NAME, exe="/fake/exe", spec=None,
                  flagged=True):
    spec = spec if spec is not None else _mod.SMOKE_SPEC
    extra = [_mod.ALLOW_NO_TESTS_FLAG] if flagged else []
    return _entry(name, exe=exe, spec=spec, extra_args=extra, suite=SMOKE_SUITE)


def test_parse_smoke_entries_happy_path(failures):
    tests = [_smoke_entry(), _entry("some shard", spec="[pg][a]")]  # shard entry ignored
    entries, errors = _mod.parse_smoke_entries(tests)
    check(errors == [], "smoke happy path: no shape errors", failures)
    check(len(entries) == 1, "smoke happy path: only the 1 smoke entry found", failures)
    check(entries[0] == (_mod.SMOKE_ENTRY_NAME, "/fake/exe", _mod.SMOKE_SPEC,
                         [_mod.ALLOW_NO_TESTS_FLAG]),
          "smoke happy path: 4-tuple shape correct (opts included)", failures)


def test_check_smoke_happy_path(failures):
    def run():
        entries, _ = _mod.parse_smoke_entries([_smoke_entry()])
        cases = _smoke_cases(_mod.SMOKE_EXACT_CASES)
        list_fn = lambda exe, spec: cases if spec == _mod.SMOKE_SPEC else cases | {("other", "g.cpp", "1")}
        ok, fail_msgs, stats = _mod.check_smoke(entries, "/fake/exe", list_fn)
        check(ok, "smoke clean: reports OK", failures)
        check(fail_msgs == [], "smoke clean: no failure messages", failures)
        check(stats == {"smoke_case_count": _mod.SMOKE_EXACT_CASES},
              "smoke clean: stats correct", failures)
    _with_exact_cases(3, run)


def test_check_smoke_missing_entry(failures):
    ok, fail_msgs, _ = _mod.check_smoke([], "/fake/exe", lambda exe, spec: set())
    check(not ok, "smoke missing: reports not-ok", failures)
    check(any("hollow discovery" in m for m in fail_msgs),
          "smoke missing: failure message says hollow discovery", failures)


def test_check_smoke_duplicate_entry(failures):
    entries, _ = _mod.parse_smoke_entries([
        _smoke_entry(name="server pg smoke"),
        {"name": "server pg smoke 2", "cmd": ["/fake/exe", _mod.SMOKE_SPEC,
                                              _mod.ALLOW_NO_TESTS_FLAG],
         "suite": ["yuzu:server", SMOKE_SUITE]},
    ])
    ok, fail_msgs, _ = _mod.check_smoke(entries, "/fake/exe", lambda exe, spec: set())
    check(not ok, "smoke duplicate: reports not-ok", failures)
    check(any("expected exactly one" in m for m in fail_msgs),
          "smoke duplicate: failure message says expected exactly one", failures)


def test_check_smoke_wrong_spec(failures):
    entries, _ = _mod.parse_smoke_entries([_smoke_entry(spec="[pg][wrong]")])
    ok, fail_msgs, _ = _mod.check_smoke(entries, "/fake/exe", lambda exe, spec: {("t", "f", "1")})
    check(not ok, "smoke wrong spec: reports not-ok", failures)
    check(any("spec is" in m and "[pg][wrong]" in m for m in fail_msgs),
          "smoke wrong spec: failure message names the bad spec", failures)


def test_check_smoke_wrong_name(failures):
    entries, _ = _mod.parse_smoke_entries([_smoke_entry(name="server pg smoke typo")])
    ok, fail_msgs, _ = _mod.check_smoke(entries, "/fake/exe", lambda exe, spec: {("t", "f", "1")})
    check(not ok, "smoke wrong name: reports not-ok", failures)
    check(any("name is" in m and "server pg smoke typo" in m for m in fail_msgs),
          "smoke wrong name: failure message names the bad entry name", failures)


def test_check_smoke_flag_absent(failures):
    entries, _ = _mod.parse_smoke_entries([_smoke_entry(flagged=False)])
    ok, fail_msgs, _ = _mod.check_smoke(entries, "/fake/exe", lambda exe, spec: {("t", "f", "1")})
    check(not ok, "smoke flag absent: reports not-ok", failures)
    check(any(_mod.ALLOW_NO_TESTS_FLAG in m and "missing" in m for m in fail_msgs),
          "smoke flag absent: failure message names the missing flag (D2)", failures)


def test_check_smoke_zero_cases(failures):
    entries, _ = _mod.parse_smoke_entries([_smoke_entry()])
    ok, fail_msgs, _ = _mod.check_smoke(entries, "/fake/exe", lambda exe, spec: set())
    check(not ok, "smoke zero cases: reports not-ok", failures)
    check(any("matched ZERO cases" in m for m in fail_msgs),
          "smoke zero cases: failure message says so", failures)


def test_check_smoke_count_one_below(failures):
    # Sol: an off-by-one in EITHER direction must be caught, not just a
    # coarse band — this is the case D7's exact-count design exists for.
    def run():
        entries, _ = _mod.parse_smoke_entries([_smoke_entry()])
        cases = _smoke_cases(_mod.SMOKE_EXACT_CASES - 1)
        ok, fail_msgs, stats = _mod.check_smoke(entries, "/fake/exe", lambda exe, spec: cases)
        check(not ok, "smoke count -1: reports not-ok", failures)
        check(any("expected exactly" in m for m in fail_msgs),
              "smoke count -1: failure message states the exact expectation", failures)
        check(stats.get("smoke_case_count") == _mod.SMOKE_EXACT_CASES - 1,
              "smoke count -1: stats still report the actual count found", failures)
    _with_exact_cases(3, run)


def test_check_smoke_count_one_above(failures):
    def run():
        entries, _ = _mod.parse_smoke_entries([_smoke_entry()])
        cases = _smoke_cases(_mod.SMOKE_EXACT_CASES + 1)
        ok, fail_msgs, _ = _mod.check_smoke(entries, "/fake/exe", lambda exe, spec: cases)
        check(not ok, "smoke count +1: reports not-ok", failures)
        check(any("expected exactly" in m for m in fail_msgs),
              "smoke count +1: failure message states the exact expectation", failures)
    _with_exact_cases(3, run)


def test_check_smoke_not_subset_of_pg(failures):
    def run():
        entries, _ = _mod.parse_smoke_entries([_smoke_entry()])
        smoke_cases = _smoke_cases(_mod.SMOKE_EXACT_CASES)
        stray = ("not tagged pg", "f.cpp", "99")
        smoke_with_stray = (smoke_cases - {next(iter(smoke_cases))}) | {stray}

        def list_fn(exe, spec):
            if spec == _mod.SMOKE_SPEC:
                return smoke_with_stray
            return smoke_cases  # "[pg]" reference set — missing `stray`
        ok, fail_msgs, _ = _mod.check_smoke(entries, "/fake/exe", list_fn)
        check(not ok, "smoke not-subset: reports not-ok", failures)
        check(any("not tagged [pg]" in m and "not tagged pg" in m for m in fail_msgs),
              "smoke not-subset: failure message names the over-matched case", failures)
    _with_exact_cases(3, run)


def test_check_smoke_exe_mismatch(failures):
    entries, _ = _mod.parse_smoke_entries([_smoke_entry(exe="/exe/two")])
    ok, fail_msgs, _ = _mod.check_smoke(entries, "/exe/one", lambda exe, spec: {("t", "f", "1")})
    check(not ok, "smoke exe mismatch: reports not-ok", failures)
    check(any("binary" in m and "/exe/two" in m for m in fail_msgs),
          "smoke exe mismatch: failure message names the mismatched binary", failures)


# ── Agent family (#5073) ──────────────────────────────────────────────────────
def _agent_entry(name, spec, exe="/fake/agent_exe", extra_args=("--allow-running-no-tests",)):
    """One `meson introspect --tests` entry in the agent-shard suite."""
    return {"name": name, "cmd": [exe, spec] + list(extra_args),
            "suite": ["yuzu:agent", AGENT_SUITE]}


_AGENT_REF = _mod.AGENT_REF_SPEC
_C1, _C2, _C3 = ("t1", "f.cpp", "1"), ("t2", "f.cpp", "2"), ("t3", "f.cpp", "3")


def _sp(i):
    """Shard i's fixture spec: a valid tag spec ending with the reference suffix
    (the shape the real meson specs have, and what check_agent_shard_suffix pins)."""
    return f"[s{i}]{_AGENT_REF}"


def _agent_tests(n=3):
    return [_agent_entry(f"agent unit tests shard {chr(65 + i)}", _sp(i)) for i in range(n)]


def _run_main_agent(tests, cases_by_spec):
    """Run main_agent() with introspect_tests/list_cases stubbed; returns
    (rc, stdout). Restores the module's real callables afterwards."""
    real_i, real_l = _mod.introspect_tests, _mod.list_cases
    _mod.introspect_tests = lambda builddir: tests
    _mod.list_cases = lambda exe, spec: set(cases_by_spec.get(spec, set()))
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = _mod.main_agent(argparse.Namespace(builddir="x"))
    finally:
        _mod.introspect_tests, _mod.list_cases = real_i, real_l
    return rc, buf.getvalue()


def test_agent_parse_entries(failures):
    tests = _agent_tests(2) + [
        {"name": "server shard", "cmd": ["/x", "~[pg]"], "suite": ["yuzu:server-nonpg"]},
        {"name": "agent tsan-heavy checkpoints", "cmd": ["/fake/agent_exe", "[tsan-heavy]"],
         "suite": ["yuzu:agent"]},
    ]
    entries, errors = _mod.parse_agent_entries(tests)
    check(errors == [], "agent parse: no shape errors", failures)
    check([e[0] for e in entries] == ["agent unit tests shard A", "agent unit tests shard B"],
          "agent parse: only agent-shard-suite entries (not the unsharded tsan-heavy entry)", failures)
    check(entries[0][3] == ["--allow-running-no-tests"], "agent parse: options preserved", failures)
    _e, errs = _mod.parse_agent_entries([_agent_entry("bad", "[a]", extra_args=("[b]",))])
    check(len(errs) == 1, "agent parse: a second positional spec is a shape error", failures)


def test_agent_partition_clean(failures):
    cases = {_AGENT_REF: {_C1, _C2, _C3}, _sp(0): {_C1}, _sp(1): {_C2}, _sp(2): {_C3}}
    rc, out = _run_main_agent(_agent_tests(), cases)
    check(rc == 0, "agent exact partition: rc 0", failures)
    check("A=1" in out and "B=1" in out and "C=1" in out and "::notice::" in out,
          "agent exact partition: per-shard case counts printed as a ::notice::", failures)
    check("3 agent shards, 3 cases" in out, "agent exact partition: summary line", failures)
    entries = [(n, "/fake/agent_exe", sp) for n, sp in
               (("A", _sp(0)), ("B", _sp(1)), ("C", _sp(2)))]
    ok, msgs, stats = _mod.check_partition(
        entries, lambda e, sp: cases[sp], ref_spec=_AGENT_REF, label=_mod.AGENT_LABEL)
    check(ok and stats == {"shard_count": 3, "case_count": 3},
          "agent exact partition: check_partition stats", failures)


def test_agent_partition_duplicate(failures):
    cases = {_AGENT_REF: {_C1, _C2, _C3}, _sp(0): {_C1, _C2}, _sp(1): {_C2}, _sp(2): {_C3}}
    rc, out = _run_main_agent(_agent_tests(), cases)
    check(rc == 1 and "appears in BOTH" in out, "agent duplicate: fails with the BOTH message", failures)


def test_agent_partition_missing(failures):
    cases = {_AGENT_REF: {_C1, _C2, _C3}, _sp(0): {_C1}, _sp(1): {_C2}}
    rc, out = _run_main_agent(_agent_tests(2), cases)
    check(rc == 1 and "in NO agent-shard shard" in out,
          "agent missing: a case in no shard fails with the NO-shard message", failures)


def test_agent_partition_hidden_leak(failures):
    # A shard that matches a case outside the reference set (the hidden `[.]`
    # / [tsan-heavy] leak shape an unsuffixed inclusion term produces).
    leak = ("hidden exploratory", "g.cpp", "7194")
    cases = {_AGENT_REF: {_C1, _C2, _C3}, _sp(0): {_C1, leak}, _sp(1): {_C2}, _sp(2): {_C3}}
    rc, out = _run_main_agent(_agent_tests(), cases)
    check(rc == 1 and "not in the '~[.]~[tsan-heavy]~[flaky-4086]' reference set" in out
          and "hidden exploratory" in out,
          "agent leak: an extra (hidden/tsan-heavy) case fails and is named", failures)


def test_agent_partition_zero_case_shard(failures):
    cases = {_AGENT_REF: {_C1, _C2}, _sp(0): {_C1}, _sp(1): {_C2}, _sp(2): set()}
    rc, out = _run_main_agent(_agent_tests(), cases)
    check(rc == 1 and "matched ZERO cases" in out,
          "agent zero-case shard: fails with 'matched ZERO cases'", failures)


def test_agent_hollow_discovery(failures):
    cases = {_AGENT_REF: {_C1}, _sp(0): {_C1}}
    rc, out = _run_main_agent(_agent_tests(1), cases)
    check(rc == 1 and "hollow discovery" in out, "agent hollow (1 entry): fails loud", failures)
    rc, out = _run_main_agent([], cases)
    check(rc == 1 and "hollow discovery" in out, "agent hollow (0 entries): fails loud", failures)


def test_agent_missing_allow_no_tests(failures):
    tests = _agent_tests()
    tests[1] = _agent_entry("agent unit tests shard B", _sp(1), extra_args=())
    cases = {_AGENT_REF: {_C1, _C2, _C3}, _sp(0): {_C1}, _sp(1): {_C2}, _sp(2): {_C3}}
    rc, out = _run_main_agent(tests, cases)
    check(rc == 1 and "shard B" in out and "--allow-running-no-tests" in out,
          "agent flag: a shard without --allow-running-no-tests fails and is named", failures)


def _agent_clean_cases():
    return {_AGENT_REF: {_C1, _C2, _C3}, _sp(0): {_C1}, _sp(1): {_C2}, _sp(2): {_C3}}


def test_agent_shard_names(failures):
    # Red: a duplicate name, and a name contained in another (the retired bare
    # 'agent unit tests' name is the realistic shape). Green: the real shape.
    dup = _agent_tests()
    dup[1] = _agent_entry("agent unit tests shard A", _sp(1))
    rc, out = _run_main_agent(dup, _agent_clean_cases())
    check(rc == 1 and "share the name" in out and "shard A" in out,
          "agent names: two equal entry names fail and are named", failures)
    sub = _agent_tests()
    sub[0] = _agent_entry("agent unit tests", _sp(0))
    rc, out = _run_main_agent(sub, _agent_clean_cases())
    check(rc == 1 and "is a substring of" in out and "'agent unit tests'" in out,
          "agent names: a name contained in another entry's name fails and is named", failures)
    rc, _out = _run_main_agent(_agent_tests(), _agent_clean_cases())
    check(rc == 0, "agent names: A/B/C (shared prefix, no containment) pass", failures)


def test_agent_shard_suffix_pin(failures):
    # Red: the whole spec loses the suffix (meson-side drift), and ONE comma term
    # of a multi-term spec loses it (a partial edit). Green: every term ends with it.
    drift = _agent_tests()
    drift[0] = _agent_entry("agent unit tests shard A", "[s0]~[.]~[tsan-heavy]")
    rc, out = _run_main_agent(drift, _agent_clean_cases())
    check(rc == 1 and "does not end with the reference suffix" in out,
          "agent suffix pin: a spec missing ~[flaky-4086] fails", failures)
    two = _agent_tests()
    two[0] = _agent_entry("agent unit tests shard A", f"[s0]{_AGENT_REF},[s9]")
    rc, out = _run_main_agent(two, _agent_clean_cases())
    check(rc == 1 and "'[s9]'" in out,
          "agent suffix pin: one comma term without the suffix fails and is named", failures)
    green_spec = f"[s0]{_AGENT_REF},[s9]{_AGENT_REF}"
    two[0] = _agent_entry("agent unit tests shard A", green_spec)
    green_cases = _agent_clean_cases()
    green_cases[green_spec] = {_C1}
    rc, _out = _run_main_agent(two, green_cases)
    check(rc == 0, "agent suffix pin: every comma term suffixed passes", failures)


def test_agent_shard_spec_shape(failures):
    # Red: a name-pattern term is not strippable by the isolated retry. Green: the
    # real shape (covered by every other agent test).
    bad = _agent_tests()
    bad[2] = _agent_entry("agent unit tests shard C", "some case name" + _AGENT_REF)
    rc, out = _run_main_agent(bad, _agent_clean_cases())
    check(rc == 1 and "CATCH2_TAG_SPEC" in out,
          "agent spec shape: a spec flake-retry cannot strip fails", failures)


def test_catch2_tag_spec_matches_flake_retry(failures):
    # The checker's CATCH2_TAG_SPEC is a copy (flake-retry.py is hyphenated); fail
    # if the two patterns ever diverge.
    fr_spec = importlib.util.spec_from_file_location(
        "flake_retry_for_parity", os.path.join(HERE, "flake-retry.py"))
    fr = importlib.util.module_from_spec(fr_spec)
    fr_spec.loader.exec_module(fr)
    check(fr.CATCH2_TAG_SPEC.pattern == _mod.CATCH2_TAG_SPEC.pattern,
          "CATCH2_TAG_SPEC: checker copy equals flake-retry.py's pattern", failures)


def test_default_family_is_server(failures):
    real_s, real_a = _mod.main_server, _mod.main_agent
    _mod.main_server = lambda args: 7
    _mod.main_agent = lambda args: 9
    try:
        check(_mod.main(["--builddir", "x"]) == 7,
              "default --family is server (the existing meson invocation is unchanged)", failures)
        check(_mod.main(["--builddir", "x", "--family", "agent"]) == 9,
              "--family agent routes to the agent check", failures)
        check(_mod.main(["--builddir", "x", "--family", "agent", "[spark]"]) == 9,
              "--family agent tolerates a trailing --test-args tag spec", failures)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                _mod.main(["--builddir", "x", "[spark]"])
            strict = False
        except SystemExit as e:
            strict = e.code == 2
        check(strict, "server family still rejects an unrecognised trailing argument", failures)
    finally:
        _mod.main_server, _mod.main_agent = real_s, real_a


def main():
    failures = []
    test_parse_shard_entries_happy_path(failures)
    test_parse_shard_entries_collects_all_shape_errors(failures)
    test_parse_shard_entries_options_are_fine(failures)
    test_check_partition_clean(failures)
    test_check_partition_gap(failures)
    test_check_partition_duplication(failures)
    test_check_partition_extra(failures)
    test_check_partition_multiple_binaries(failures)
    test_check_partition_empty_reference(failures)
    test_check_partition_zero_case_shard(failures)
    test_parse_nonpg_entries_happy_path(failures)
    test_check_partition_nonpg_ref_spec_and_label(failures)
    test_parse_list_tests_xml(failures)
    test_parse_smoke_entries_happy_path(failures)
    test_check_smoke_happy_path(failures)
    test_check_smoke_missing_entry(failures)
    test_check_smoke_duplicate_entry(failures)
    test_check_smoke_wrong_spec(failures)
    test_check_smoke_wrong_name(failures)
    test_check_smoke_flag_absent(failures)
    test_check_smoke_zero_cases(failures)
    test_check_smoke_count_one_below(failures)
    test_check_smoke_count_one_above(failures)
    test_check_smoke_not_subset_of_pg(failures)
    test_check_smoke_exe_mismatch(failures)
    test_agent_parse_entries(failures)
    test_agent_partition_clean(failures)
    test_agent_partition_duplicate(failures)
    test_agent_partition_missing(failures)
    test_agent_partition_hidden_leak(failures)
    test_agent_partition_zero_case_shard(failures)
    test_agent_hollow_discovery(failures)
    test_agent_missing_allow_no_tests(failures)
    test_agent_shard_names(failures)
    test_agent_shard_suffix_pin(failures)
    test_agent_shard_spec_shape(failures)
    test_catch2_tag_spec_matches_flake_retry(failures)
    test_default_family_is_server(failures)

    if failures:
        print(f"\ncheck-pg-shard-partition selftest: {len(failures)} FAILED")
        return 1
    print("\ncheck-pg-shard-partition selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
