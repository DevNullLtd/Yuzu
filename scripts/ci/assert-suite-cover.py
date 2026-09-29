#!/usr/bin/env python3
"""assert-suite-cover.py — fail-closed guard for a `meson test --suite ...`
invocation that has no by-name fallback (#3443, Windows CI test-phase
restructuring). `meson test --suite <bad>` matches zero entries and exits
0 SILENTLY on a bare run — the opposite polarity of a by-name selection,
which fails loud on a typo. Windows' non-pg Test step selects entirely by
`--suite` (no by-name list, unlike Linux's second non-pg invocation), so a
dropped/misspelled `--suite` flag would silently stop running a whole
category of tests with a green step. This script is the loud-fail net:
run it as the FIRST line of that step, before the actual test invocation.

Proves: every registered test() entry is either matched by one of the
given `--suite` flags, or carries one of the given `--exclude-suite`
labels (deliberately out of scope for this invocation, e.g. server-pg /
server-pg-smoke, which run in a separate, gated step) — no entry is
silently in neither bucket.

`meson introspect --tests` suite strings are project-namespaced
("yuzu:server-nonpg", not "server-nonpg") — comparisons here strip the
`<project>:` prefix before matching against the bare names passed on the
command line, the exact trap a naive string-equality check would miss.

Pure logic (`compute_coverage`) is separated from I/O (`introspect_tests`,
`main`) for the same reason check-pg-shard-partition.py's is — see
test_assert_suite_cover.py.
"""
import argparse
import json
import subprocess
import sys


def gh(kind, msg):
    print(f"::{kind}::{msg}", flush=True)


def introspect_tests(builddir):
    try:
        out = subprocess.run(
            ["meson", "introspect", builddir, "--tests"],
            capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError as e:
        gh("error", f"assert-suite-cover: meson introspect failed (exit {e.returncode}): "
                     f"{e.stderr.strip()}")
        raise
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError as e:
        gh("error", f"assert-suite-cover: meson introspect returned unparseable JSON: {e}")
        raise


def _bare_suites(entry_suites):
    """['yuzu:agent', 'yuzu:server-pg'] -> {'agent', 'server-pg'} — strips the
    project-name prefix meson introspection always includes."""
    out = set()
    for s in entry_suites:
        out.add(s.split(":", 1)[1] if ":" in s else s)
    return out


def compute_coverage(tests, selected_suites, excluded_suites):
    """Pure: given `tests` (as `meson introspect --tests` emits) and the bare
    (unprefixed) suite name sets this invocation selects/excludes, return
    (ok: bool, failures: list[str], stats: dict). No I/O, no sys.exit — the
    same real-build-vs-synthetic-fixture split check-pg-shard-partition.py
    uses.
    """
    failures = []
    if not tests:
        return False, ["meson introspect returned zero test entries — "
                        "empty or broken builddir"], {}

    conflict = selected_suites & excluded_suites
    if conflict:
        return False, [f"--suite and --exclude-suite name the same suite(s) "
                        f"{sorted(conflict)!r} — a suite cannot be both "
                        f"covered by this invocation and deliberately out of "
                        f"scope for it"], {}

    selected_names = set()
    excluded_names = set()
    both_names = set()
    per_suite_hits = {s: 0 for s in selected_suites}
    for t in tests:
        bare = _bare_suites(t.get("suite", []))
        is_selected = bool(bare & selected_suites)
        is_excluded = bool(bare & excluded_suites)
        if is_selected and is_excluded:
            both_names.add(t["name"])
        elif is_selected:
            selected_names.add(t["name"])
            for s in bare & selected_suites:
                per_suite_hits[s] += 1
        elif is_excluded:
            excluded_names.add(t["name"])

    if both_names:
        failures.append(f"{len(both_names)} entr(y/ies) carry BOTH a "
                         f"selected and an excluded suite — a suite-label "
                         f"conflict, not a valid state: {sorted(both_names)[:5]!r}"
                         + (" ..." if len(both_names) > 5 else ""))

    zero_hit = sorted(s for s, n in per_suite_hits.items() if n == 0)
    if zero_hit:
        failures.append(f"--suite {zero_hit!r} matched ZERO entries — a real "
                         f"typo looks exactly like this (meson's own "
                         f"`--suite <bad>` silently matches nothing)")

    expected = {t["name"] for t in tests} - excluded_names
    missing = expected - selected_names - both_names
    if missing:
        sample = sorted(missing)[:5]
        failures.append(f"{len(missing)} entr(y/ies) covered by neither "
                         f"--suite {sorted(selected_suites)!r} nor "
                         f"--exclude-suite {sorted(excluded_suites)!r}: "
                         f"{sample!r}" + (" ..." if len(missing) > 5 else ""))

    stats = {"selected": len(selected_names), "excluded": len(excluded_names),
              "total": len(tests)}
    return not failures, failures, stats


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--builddir", required=True)
    ap.add_argument("--suite", action="append", required=True,
                     help="a suite this invocation is about to run (repeatable)")
    ap.add_argument("--exclude-suite", action="append", default=[],
                     help="a suite deliberately out of scope for this "
                          "invocation, e.g. server-pg (repeatable)")
    args = ap.parse_args(argv)

    tests = introspect_tests(args.builddir)
    ok, failures, stats = compute_coverage(
        tests, set(args.suite), set(args.exclude_suite))
    if not ok:
        for f in failures:
            gh("error", f"assert-suite-cover: {f}")
        return 1

    print(f"assert-suite-cover: OK — {stats['selected']} entr(y/ies) covered "
          f"by --suite, {stats['excluded']} deliberately excluded, "
          f"{stats['total']} total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
