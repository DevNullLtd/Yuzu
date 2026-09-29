#!/usr/bin/env python3
"""check-pg-shard-partition.py — prove the PG-tagged Catch2 case population is
exactly partitioned across this build's ``server-pg``-suite meson test()
entries: every ``[pg]`` case lands in exactly one shard, none lost, none
duplicated. Also proves the ``server-pg-smoke`` entry (#3443 Phase 2) is a
genuine, bounded, correctly-flagged subset of ``[pg]`` — one entry, the
expected name, the expected exact case count, tagged ``--allow-running-
no-tests``, and every matched case also carries ``[pg]``.

Windows CI test-phase restructuring (#3443, 2026-08-28): the same check_partition()
set-math also proves the ``server-nonpg``-suite entries partition ``~[pg]`` —
the non-pg shards the Windows job's own non-pg Test step selects by suite,
same discovery-by-suite-membership property, same failure shape, reusing
the one chokepoint rather than a second hand-rolled copy.

Replaces flake-retry.py's old verbatim positional-filter pin (a hardcoded
copy of every shard's tag-filter string, hand-updated on every split/
rebalance — missed 3 times in the same number of weeks, each time reddening
CI unconditionally; see tests/meson.build's shard-history comment). That pin
only ever proved the filter strings hadn't silently changed since the last
person to update it looked. This proves the actual property that matters —
exact partitioning of the real case population — against the compiled
binary, not against a remembered snapshot.

Runs as its own meson test() entry (suite: ['server', 'server-checks'] —
the second label is what lets the Windows non-pg Test step's
assert-suite-cover.py select it), NOT inside the cheap flake-retry selftest
(suite: 'docs'): it needs the real yuzu_server_tests binary built, which
the docs suite deliberately does not depend on. No Postgres connection
needed — --list-tests only enumerates registered TEST_CASE macros, it
never executes a test body.

Discovery is via `meson introspect <builddir> --tests`, keyed on suite
membership (yuzu:server-pg), not a hardcoded shard-name list — so a shard
add/split/rebalance needs no update here at all, only a correct suite: kwarg
on the new/changed test() entry in tests/meson.build.

Escape hatch if this checker itself is wrong: revert this file's own
test() block in tests/meson.build ('server pg shard partition invariant',
tests/meson.build's `if build_server` scope — not Linux-only). This is the
one COMPLETE single-edit de-wire: it stops the check on every leg that
builds the server, including Windows and macOS. Removing the
'server pg shard partition invariant' token from ci.yml's Linux
flake-retry.py invocation line (governance Gate 8, sre, #3443) is NOT
equivalent and covers Linux only — the Windows and macOS legs invoke
flake-retry.py with no --suite/name filter at all (it passes straight
through to `meson test`), so they would keep running this test regardless
of that edit. The separate 'check-pg-shard-partition selftest' entry
(suite: 'docs', added alongside test_check_pg_shard_partition.py) is
untouched by either revert and stays running — it exercises only synthetic
fixtures and asserts nothing about real shard state, so it is harmless to
leave in place while this checker itself is being fixed or reverted.

Pure logic (`parse_shard_entries`, `check_partition`) is separated from I/O
(`introspect_tests`, `list_cases`, `main`) specifically so it can be
exercised with synthetic fixtures, no real build or binary needed — see
test_check_pg_shard_partition.py, which follows the same in-process
synthetic-fixture precedent as flake-retry.py's own --selftest (not its
separate fake-PATH-stub subprocess tests) for the same reason: a future
regression in THIS script's own detection logic (not the shards it checks)
should fail a fast, no-build docs-suite test, not require another manual
mutation-test session.
"""
import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET  # stdlib, not defusedxml: this parses our
# own yuzu_server_tests --list-tests output, not external input — same trust
# model as flake-retry.py's and test_db.py's existing JUnit parsing, which
# also use stdlib ElementTree; defusedxml isn't a dependency anywhere in
# this repo's CI tooling and adding it for one script would be inconsistent
# with that precedent for no real risk reduction here.

SERVER_PG_SUITE = "yuzu:server-pg"
SERVER_PG_SMOKE_SUITE = "yuzu:server-pg-smoke"
# Windows CI test-phase restructuring (#3443, 2026-08-28): the non-pg server
# shards (A/B/C) partition '~[pg]' the same way the pg shards partition
# '[pg]' — same discovery-by-suite-membership property, same failure shape,
# reusing check_partition below with a different suite/ref_spec/label rather
# than a second hand-rolled copy of the same set-math.
SERVER_NONPG_SUITE = "yuzu:server-nonpg"
NONPG_REF_SPEC = "~[pg]"
SMOKE_SPEC = "[pg-smoke]"
SMOKE_ENTRY_NAME = "server pg smoke"
# Measured against the real binary once the [pg-smoke] tags landed (#3443
# Phase 2) — NOT a guess and NOT a MIN/MAX range. A range let a same-count
# drop-and-add, or a single stripped tag, pass silently; an exact count
# catches any single addition or removal. Documented residual: a same-count
# SUBSTITUTION (swap one intended case for a different [pg] case) is not
# statically caught here — that is a reviewable diff on the tag itself, and
# pinning exact case identity in this checker would recreate a duplicate
# hand-maintained manifest, the exact defect class this script exists to cure.
SMOKE_EXACT_CASES = 11
ALLOW_NO_TESTS_FLAG = "--allow-running-no-tests"


def gh(kind, msg):
    """Emit a GitHub Actions annotation (::warning::/::notice::/::error::).

    Mirrors flake-retry.py's own gh() helper — every ANTICIPATED shape- or
    partition-violation exit path in main()/check_partition() routes through
    here now (governance Gate 4 consistency-auditor F2: the partition-
    violation findings, this script's entire reason to exist, previously got
    a plain stderr print with no GH inline-annotation prefix, unlike every
    shape-violation exit path in the same file). Does NOT cover an
    unanticipated subprocess/parse failure (meson introspect crashing, a
    corrupt --list-tests XML document) — those propagate as an uncaught
    Python traceback, which still fails the job loudly, just without a
    ::error:: prefix (governance Gate 8 unhappy-path UP-1, #3628).
    """
    print(f"::{kind}::{msg}", flush=True)


def introspect_tests(builddir):
    out = subprocess.run(
        ["meson", "introspect", builddir, "--tests"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def _parse_suite_entries(tests, suite):
    """Return (entries, errors) for every entry in `tests` carrying `suite`.

    entries: [(name, exe, tag_filter_spec, opts), ...] for well-shaped
    entries — exe as cmd[0], exactly one positional (non-'-'-prefixed)
    Catch2 tag-filter spec, and the list of '-'-prefixed options (e.g.
    --allow-running-no-tests) alongside it.
    errors: human-readable strings for every malformed entry found.

    Pure function — no I/O, no sys.exit — so a synthetic `tests` list (as
    `meson introspect --tests` would emit) exercises this without a real
    build. Collects EVERY malformed entry rather than stopping at the first
    (governance Gate 4 consistency-auditor F2): two simultaneously-broken
    entries used to report only the first found.

    An entry must carry the exe as cmd[0] and exactly one positional
    (non-'-'-prefixed) tag-filter spec as its only other cmd element — this
    mirrors the same hygiene guard flake-retry.py's selftest already
    enforces (options are permitted, e.g. --allow-running-no-tests on an
    all-skip shard; two or more positional specs, or zero, is a shape
    violation).

    Shared by parse_shard_entries (SERVER_PG_SUITE) and parse_smoke_entries
    (SERVER_PG_SMOKE_SUITE, #3443 Phase 2) — same shape rules, different
    suite and (for smoke) a caller that also needs `opts`.
    """
    entries = []
    errors = []
    for t in tests:
        if suite not in t.get("suite", []):
            continue
        cmd = t.get("cmd", [])
        name = t.get("name", "<unnamed>")
        if len(cmd) < 2:
            errors.append(f"{name!r} in suite {suite!r} has no "
                           f"positional Catch2 spec")
            continue
        exe, rest = cmd[0], cmd[1:]
        specs = [a for a in rest if not a.startswith("-")]
        opts = [a for a in rest if a.startswith("-")]
        if len(specs) != 1:
            errors.append(f"{name!r} must carry exactly one positional "
                           f"tag-filter spec, found {specs!r} (options "
                           f"{opts!r} are fine, e.g. --allow-running-no-tests)")
            continue
        entries.append((name, exe, specs[0], opts))
    return entries, errors


def parse_shard_entries(tests):
    """Return (entries, errors) for every server-pg-suite entry in `tests`.

    entries: [(name, exe, tag_filter_spec), ...] for well-shaped entries
    (3-tuple — pinned by test_check_pg_shard_partition.py). errors:
    human-readable strings for every malformed entry found. See
    _parse_suite_entries for the shared shape rules.
    """
    entries, errors = _parse_suite_entries(tests, SERVER_PG_SUITE)
    return [(name, exe, spec) for name, exe, spec, _opts in entries], errors


def parse_nonpg_entries(tests):
    """Return (entries, errors) for every server-nonpg-suite entry in `tests`
    (Windows CI test-phase restructuring, #3443). Same 3-tuple shape as
    parse_shard_entries — see _parse_suite_entries for the shared rules.
    """
    entries, errors = _parse_suite_entries(tests, SERVER_NONPG_SUITE)
    return [(name, exe, spec) for name, exe, spec, _opts in entries], errors


def parse_smoke_entries(tests):
    """Return (entries, errors) for every server-pg-smoke-suite entry in
    `tests` (#3443 Phase 2). entries: [(name, exe, tag_filter_spec, opts),
    ...] — keeps `opts` (unlike parse_shard_entries) because check_smoke
    must verify --allow-running-no-tests is present (D2: an all-DSN-gated
    flagless entry would fail every DSN-less unfiltered `meson test`, e.g.
    local dev without Postgres or the sanitizer legs, breaking the
    documented skip contract in test_helpers.hpp). See _parse_suite_entries
    for the shared shape rules.
    """
    return _parse_suite_entries(tests, SERVER_PG_SMOKE_SUITE)


def list_cases(exe, filt):
    """Case identities (name, file, line) matched by `exe --list-tests filt`.

    XML reporter, not the plain --list-tests text output: Catch2 wraps long
    test names across multiple lines in the plain form, which is ambiguous
    to parse back into individual case names. --list-tests needs no
    Postgres DSN and never executes a test body — pure enumeration.
    """
    out = subprocess.run(
        [exe, "--list-tests", "--reporter", "xml", filt],
        capture_output=True, text=True, check=True,
    )
    return parse_list_tests_xml(out.stdout)


def parse_list_tests_xml(xml_text):
    """Case identities (name, file, line) from a Catch2 `--list-tests --reporter
    xml` document. Pure function, separated from the subprocess call so a
    synthetic XML string exercises it without a real binary."""
    root = ET.fromstring(xml_text)
    cases = set()
    for tc in root.findall(".//TestCase"):
        name = tc.findtext("Name")
        src = tc.find("SourceInfo")
        file_ = src.findtext("File") if src is not None else None
        line = src.findtext("Line") if src is not None else None
        cases.add((name, file_, line))
    return cases


def _fmt_case(c):
    """'name (file:line)' for a (name, file, line) tuple, consistent everywhere
    a case identity is shown in a failure message (governance Gate 3
    quality-engineer LOW: the missing/extra branches previously showed only
    names, unlike the duplicate branch, which already showed file:line)."""
    return f"{c[0]!r} ({c[1]}:{c[2]})"


def check_partition(entries, list_cases_fn, ref_spec="[pg]", label="server-pg"):
    """Given well-shaped shard entries and a case-lookup callable
    (filter_spec -> set of (name, file, line)), prove: (a) every case the
    `ref_spec` filter matches lands in exactly one shard's matched set,
    (b) no shard's filter matches a case outside that reference set.

    `ref_spec`/`label` default to the original pg-shard check ('[pg]' /
    'server-pg'); the Windows restructuring's non-pg partition (#3443) calls
    this with ref_spec='~[pg]', label='server-nonpg' — same set-math, a
    different reference filter and wording so a non-pg failure never
    misleadingly reports '[pg]'/'server-pg' in its own diagnostic (Sol
    review). `label` is used only in messages — it does not gate behavior.

    Pure with respect to I/O — `list_cases_fn` is injected so this can run
    against a real compiled binary (main(), below) or against a synthetic
    fixture (test_check_pg_shard_partition.py), with identical set-math
    either way. Returns (ok: bool, failures: list[str], stats: dict).
    """
    exes = {e for _, e, _ in entries}
    if len(exes) != 1:
        return False, [f"{label} shards use {len(exes)} different binaries "
                        f"({sorted(exes)!r}) — expected exactly one"], {}
    exe = exes.pop()

    full_ref = list_cases_fn(exe, ref_spec)
    if not full_ref:
        return False, [f"{ref_spec!r} matched zero cases on this binary — "
                        f"the {label} reference set itself is empty"], {}

    seen = {}
    union = set()
    failures = []
    for name, _exe, spec in entries:
        cases = list_cases_fn(exe, spec)
        if not cases:
            failures.append(f"{label} shard {name!r} (spec {spec!r}) matched ZERO cases")
        for c in cases:
            if c in seen:
                failures.append(f"case {_fmt_case(c)} appears in BOTH "
                                 f"{seen[c]!r} and {name!r} — not a partition")
            else:
                seen[c] = name
        union |= cases

    missing = full_ref - union
    extra = union - full_ref
    if missing:
        sample = ", ".join(_fmt_case(c) for c in sorted(missing)[:5])
        failures.append(f"{len(missing)} case(s) matched by {ref_spec!r} are in "
                         f"NO {label} shard: {sample}" + (" ..." if len(missing) > 5 else ""))
    if extra:
        sample = ", ".join(_fmt_case(c) for c in sorted(extra)[:5])
        failures.append(f"{len(extra)} case(s) matched by a {label} shard filter "
                         f"but not in the {ref_spec!r} reference set: {sample}"
                         + (" ..." if len(extra) > 5 else ""))

    stats = {"shard_count": len(entries), "case_count": len(full_ref)}
    return not failures, failures, stats


def check_smoke(smoke_entries, shard_exe, list_cases_fn):
    """Given server-pg-smoke entries (from parse_smoke_entries) and the
    shard binary path (from check_partition — so both checks agree on which
    binary is authoritative), prove the smoke set (#3443 Phase 2) is a
    genuine, bounded, correctly-flagged subset of [pg]:
      - exactly one entry in the suite (hollow / duplicate guard)
      - its name is exactly SMOKE_ENTRY_NAME
      - its exe matches shard_exe (one binary across both suites)
      - its spec is exactly SMOKE_SPEC
      - it carries ALLOW_NO_TESTS_FLAG (D2 — see parse_smoke_entries)
      - list_cases_fn(exe, SMOKE_SPEC) is nonempty and == SMOKE_EXACT_CASES
        exactly, not a range (a range let a same-count drop-and-add, or a
        single stripped tag, pass silently)
      - every matched case also carries [pg]

    Pure with respect to I/O — list_cases_fn is injected, same pattern as
    check_partition. Returns (ok: bool, failures: list[str], stats: dict).
    The count here is DISCOVERED via --list-tests, never "executed" — this
    check needs no DSN and never runs a test body.
    """
    if len(smoke_entries) == 0:
        return False, [f"no entry found in suite {SERVER_PG_SMOKE_SUITE!r} "
                        f"— hollow discovery (expected the smoke entry)"], {}
    if len(smoke_entries) > 1:
        names = sorted(n for n, _, _, _ in smoke_entries)
        return False, [f"{len(smoke_entries)} entries found in suite "
                        f"{SERVER_PG_SMOKE_SUITE!r} — expected exactly one: "
                        f"{names!r} (not a partition — pick one)"], {}

    name, exe, spec, opts = smoke_entries[0]
    failures = []
    if name != SMOKE_ENTRY_NAME:
        failures.append(f"smoke entry name is {name!r}, expected "
                         f"{SMOKE_ENTRY_NAME!r}")
    if exe != shard_exe:
        failures.append(f"smoke entry uses binary {exe!r}, expected the "
                         f"same binary as the server-pg shards ({shard_exe!r})")
    if spec != SMOKE_SPEC:
        failures.append(f"smoke entry spec is {spec!r}, expected {SMOKE_SPEC!r}")
    if ALLOW_NO_TESTS_FLAG not in opts:
        failures.append(f"smoke entry is missing {ALLOW_NO_TESTS_FLAG!r} — "
                         f"an all-DSN-gated entry without it fails every "
                         f"DSN-less unfiltered `meson test` (local dev, "
                         f"sanitizer legs), breaking the documented skip "
                         f"contract (D2, #3443 Phase 2)")
    if failures:
        return False, failures, {}

    cases = list_cases_fn(exe, spec)
    n = len(cases)
    if n == 0:
        return False, [f"{SMOKE_SPEC!r} matched ZERO cases"], {}
    if n != SMOKE_EXACT_CASES:
        return False, [f"{SMOKE_SPEC!r} matched {n} case(s), expected "
                        f"exactly {SMOKE_EXACT_CASES} — a smoke-set edit "
                        f"must update SMOKE_EXACT_CASES in the same change"], \
               {"smoke_case_count": n}

    pg_ref = list_cases_fn(exe, "[pg]")
    not_pg = cases - pg_ref
    if not_pg:
        sample = ", ".join(_fmt_case(c) for c in sorted(not_pg)[:5])
        return False, [f"{len(not_pg)} case(s) tagged {SMOKE_SPEC!r} are "
                        f"not tagged [pg]: {sample}"], {"smoke_case_count": n}

    return True, [], {"smoke_case_count": n}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--builddir", required=True)
    args = ap.parse_args(argv)

    tests = introspect_tests(args.builddir)
    entries, shape_errors = parse_shard_entries(tests)
    smoke_entries, smoke_shape_errors = parse_smoke_entries(tests)
    nonpg_entries, nonpg_shape_errors = parse_nonpg_entries(tests)
    all_shape_errors = shape_errors + smoke_shape_errors + nonpg_shape_errors
    if all_shape_errors:
        for e in all_shape_errors:
            gh("error", f"check-pg-shard-partition: {e}")
        return 1

    if len(entries) < 2:
        gh("error", f"check-pg-shard-partition: found only {len(entries)} "
                     f"entries in suite {SERVER_PG_SUITE!r} — hollow "
                     f"discovery (expected the full set of pg shards)")
        return 1
    # Non-pg hollow-discovery floor is 2 (today: shards A, B, C), same
    # reasoning as the pg floor above — a suite label typo or a dropped
    # test() entry must fail loud here, not silently check zero/one shard.
    if len(nonpg_entries) < 2:
        gh("error", f"check-pg-shard-partition: found only {len(nonpg_entries)} "
                     f"entries in suite {SERVER_NONPG_SUITE!r} — hollow "
                     f"discovery (expected the full set of non-pg shards)")
        return 1

    ok, failures, stats = check_partition(entries, list_cases)
    if not ok:
        for f in failures:
            gh("error", f"check-pg-shard-partition: {f}")
        return 1

    nonpg_ok, nonpg_failures, nonpg_stats = check_partition(
        nonpg_entries, list_cases, ref_spec=NONPG_REF_SPEC, label="server-nonpg")
    if not nonpg_ok:
        for f in nonpg_failures:
            gh("error", f"check-pg-shard-partition (non-pg): {f}")
        return 1

    shard_exe = entries[0][1]  # check_partition already proved one exe across all entries
    smoke_ok, smoke_failures, smoke_stats = check_smoke(smoke_entries, shard_exe, list_cases)
    if not smoke_ok:
        for f in smoke_failures:
            gh("error", f"check-pg-shard-partition (smoke): {f}")
        return 1

    print(f"check-pg-shard-partition: OK — {stats['shard_count']} pg shards, "
          f"{stats['case_count']} cases; {nonpg_stats['shard_count']} non-pg "
          f"shards, {nonpg_stats['case_count']} cases; both exact partitions "
          f"(no loss, no duplication); smoke: {smoke_stats['smoke_case_count']} "
          f"cases matched (not executed — see ci.yml's DSN assert + the live "
          f"test run for execution proof)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
