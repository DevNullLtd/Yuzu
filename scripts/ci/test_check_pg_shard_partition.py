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
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "check-pg-shard-partition.py")

_spec = importlib.util.spec_from_file_location("check_pg_shard_partition", MODULE_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

SUITE = _mod.SERVER_PG_SUITE
SMOKE_SUITE = _mod.SERVER_PG_SMOKE_SUITE


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

    if failures:
        print(f"\ncheck-pg-shard-partition selftest: {len(failures)} FAILED")
        return 1
    print("\ncheck-pg-shard-partition selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
