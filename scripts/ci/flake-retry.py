#!/usr/bin/env python3
"""flake-retry.py — CI flake-retry wrapper around `meson test` (Yuzu).

Runs `meson test`; every run — green included — then gets the #2093 duration
watchdog (a per-suite duration/budget table in the step summary + a ::warning
for any suite past 80% of its meson timeout; reporting only, pass/fail
semantics never change). On a clean pass, exits 0 with no retry machinery.
On failure it isolates the failed Catch2 case(s) and, for those listed in
`tests/known-flaky.json` (scoped to the current OS), retries them in isolation.

Outcome contract:
  - Any failed case NOT in the list (for this OS)  -> job FAILS (real regression).
  - A failed suite we cannot classify per-case
    (non-Catch2 e.g. gateway, crash/timeout, no junit) -> job FAILS (never mask).
  - A listed case that fails ALL retries           -> job FAILS (regression in a
                                                       flaky test still blocks).
  - Every failed case is a listed flake that recovers within --retries -> PASS.

Each entry must carry a tracking `issue`, accountable `owner`, `added` date,
and expiry date; cross-platform entries (`"platforms": ["all"]`) are still
retried but emit a loud ::warning, while OS-scoped entries emit a ::notice.

Design was grilled 2026-06-22 (mechanism "C": case-level retry + static in-repo
list). Visibility is the job summary + annotations; recovered cases are also
written to meson-logs/flake-retry.json for import into the runner-local
test-runs.db. The static list remains the allowlist; DB history never changes
pass/fail semantics. Scope: ci.yml only (PR fast-path + push matrix);
nightly/sanitizer stay fail-loud. Not an ADR (reversible test tooling) —
rationale lives here and in docs/ci-architecture.md.

Effective attempts for a flaky case = original in-suite run + one enumeration
re-run (to find which cases failed) + up to --retries isolated re-runs.
"""
import argparse
import os
import platform
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone

CATCH2_EXE = re.compile(r"yuzu_\w+_tests(\.exe)?$", re.IGNORECASE)
# A positional Catch2 tag-filter spec as used by sharded meson entries (#2092).
# Grammar: one or more comma-OR'd AND-groups, each group a run of ~?[tag].
# Examples: '[pg]', '~[pg]', '[a][b]', '~[a][b]', '[pg]~[routes]~[store]'
# (a single AND-group with mid-spec negations), and '[pg][routes],[pg][store]'
# (a comma-OR of AND-groups — the auth->PG [pg] rebalance split, #2394). Bare
# case-name specs still never match (no leading '['), so a case name is never
# mistaken for a strippable spec — the invariant _cmd_without_test_specs and
# the isolated retry rely on (a recognised spec is always stripped, so it can
# never OR with the retried case name).
CATCH2_TAG_SPEC = re.compile(r"^(~?\[[^\[\]]+\])+(,(~?\[[^\[\]]+\])+)*$")
VALID_PLATFORMS = {"windows", "linux", "macos", "all"}


def detect_os():
    s = platform.system()
    return {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}.get(s, s.lower())


def gh(kind, msg):
    """Emit a GitHub Actions annotation (::warning::/::notice::/::error::)."""
    print(f"::{kind}::{msg}", flush=True)


def summary(md):
    """Append a markdown block to the job summary, if running under Actions."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(md + "\n")
        except OSError:
            pass


# ── known-flaky.json ──────────────────────────────────────────────────────────
def _parse_flake_date(value, field, where, case):
    """Return a strict YYYY-MM-DD date or raise a list-validation error."""
    if not isinstance(value, str):
        raise ValueError(f"{where} ({case}): missing/invalid '{field}' date")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as ex:
        raise ValueError(f"{where} ({case}): invalid '{field}' date {value!r}; expected YYYY-MM-DD") from ex
    if parsed.isoformat() != value:
        raise ValueError(f"{where} ({case}): invalid '{field}' date {value!r}; expected YYYY-MM-DD")
    return parsed


def load_known_flaky(path, this_os, stale_days, today=None):
    """Parse + validate the list; return {case_name: entry} applicable to this_os.

    Fail-fast (raise ValueError) on a malformed list so a structural typo can't
    silently disable protection. Every entry names its tracking issue and
    owner, plus its added and expiry dates. Expired entries are hard failures.
    `today` is injectable for deterministic tests; production callers omit it.
    Entries older than stale_days still emit a soft warning before expiry.
    """
    if not os.path.exists(path):
        return {}
    import json

    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{path}: top level must be a JSON array")

    applicable = {}
    seen_cases = set()
    if today is None:
        today = datetime.now(timezone.utc).date()
    if not isinstance(today, date):
        raise TypeError("today must be a datetime.date")
    for i, e in enumerate(data):
        where = f"{path}[{i}]"
        if not isinstance(e, dict):
            raise ValueError(f"{where}: entry must be an object")
        case = e.get("case")
        plats = e.get("platforms")
        if not isinstance(case, str) or not case:
            raise ValueError(f"{where}: missing/empty 'case'")
        if not isinstance(plats, list) or not plats or any(p not in VALID_PLATFORMS for p in plats):
            raise ValueError(f"{where} ({case}): 'platforms' must be a non-empty subset of {sorted(VALID_PLATFORMS)}")
        if len(set(plats)) != len(plats) or ("all" in plats and len(plats) != 1):
            raise ValueError(f"{where} ({case}): 'platforms' must be unique and 'all' must stand alone")
        if case in seen_cases:
            raise ValueError(f"{where} ({case}): duplicate 'case' entry")
        seen_cases.add(case)
        for field in ("reason", "issue", "owner"):
            value = e.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{where} ({case}): missing/empty '{field}'")
        added = _parse_flake_date(e.get("added"), "added", where, case)
        expires = _parse_flake_date(e.get("expires"), "expires", where, case)
        if expires < added:
            raise ValueError(f"{where} ({case}): 'expires' precedes 'added'")
        if added > today:
            raise ValueError(f"{where} ({case}): 'added' date is in the future ({added.isoformat()})")
        if expires < today:
            raise ValueError(f"{where} ({case}): expired on {expires.isoformat()}")
        cross_platform = "all" in plats
        # Soft staleness nag (by added-date age).
        age = (today - added).days
        if age > stale_days:
            gh("warning", f"known-flaky entry is {age}d old (>{stale_days}) — re-evaluate or fix: {case}")
        if cross_platform or this_os in plats:
            applicable[case] = e
    return applicable


# ── junit parsing ─────────────────────────────────────────────────────────────
def _failed_testcase_names(xml_path):
    """Return the set of <testcase> names that carry a <failure>/<error> child."""
    failed = set()
    tree = ET.parse(xml_path)
    for tc in tree.iter("testcase"):
        if tc.find("failure") is not None or tc.find("error") is not None:
            failed.add(tc.get("name", ""))
    return failed


def meson_failed_suites(builddir):
    """Suite-level: which meson test()s failed (names from meson's junit)."""
    xml_path = os.path.join(builddir, "meson-logs", "testlog.junit.xml")
    if not os.path.exists(xml_path):
        return None  # no junit -> caller treats as unclassifiable
    return _failed_testcase_names(xml_path)


def _entry_durations(builddir):
    """{meson-junit testcase name: wall seconds} from testlog.junit.xml.

    Meson writes one <testcase> per test() entry with a per-entry `time`
    attribute (the <testsuite> nodes carry aggregates we ignore). Defensive
    by design — this feeds pure reporting (#2093), so a missing file, parse
    error, or absent/garbled time attr degrades to "no row", never a crash.
    Duplicate names are summed."""
    xml_path = os.path.join(builddir, "meson-logs", "testlog.junit.xml")
    if not os.path.exists(xml_path):
        return {}
    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, OSError):
        return {}
    durations = {}
    for tc in tree.iter("testcase"):
        name = tc.get("name", "")
        try:
            secs = float(tc.get("time"))
        except (TypeError, ValueError):
            continue
        durations[name] = durations.get(name, 0.0) + secs
    return durations


def budget_rows(durations, tests):
    """Pure: [(display_name, secs, budget_or_None, frac_or_None)] per junit
    entry, mapping junit names to introspected entries via match_suite. The
    budget is the entry's meson timeout; falsy (0 = meson's "no timeout")
    becomes None, as does the whole budget for an unmappable name."""
    rows = []
    for junit_name in sorted(durations):
        secs = durations[junit_name]
        entry = match_suite(junit_name, tests)
        name = entry.get("name") if entry and entry.get("name") else junit_name
        budget = (entry.get("timeout") or None) if entry else None
        rows.append((name, secs, budget, (secs / budget) if budget else None))
    return rows


def report_suite_budgets(builddir, tests, warn_frac=0.8):
    """#2093: degrade duration creep toward a suite's meson timeout into a
    visible ::warning instead of a discontinuous red wall (the server suite
    crept 448s -> 512s/600 in green runs with zero signal before the
    2026-07-12 timeouts). Runs on every invocation — green included, that is
    the entire point — and never changes pass/fail semantics."""
    rows = budget_rows(_entry_durations(builddir), tests)
    if not rows:
        return
    for name, secs, budget, frac in rows:
        if frac is not None and frac > warn_frac:
            gh("warning",
               f"{name} at {secs:.0f}/{budget}s ({frac:.0%}) of its meson timeout — "
               f"split the suite or rebalance before this flakes (#2092, #2093)")
    lines = ["### Suite durations vs meson budgets", "",
             "| test entry | wall (s) | budget (s) | used |", "|---|---:|---:|---:|"]
    for name, secs, budget, frac in rows:
        lines.append(f"| {name} | {secs:.0f} | {f'{budget:g}' if budget else '—'} | "
                     f"{f'{frac:.0%}' if frac is not None else '—'} |")
    summary("\n".join(lines))


# ── meson introspection: suite name -> binary command ─────────────────────────
def introspect_tests(builddir):
    out = subprocess.run(
        ["meson", "introspect", builddir, "--tests"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        return []
    import json

    return json.loads(out.stdout)


def match_suite(failed_name, tests):
    """Map a meson-junit failed-suite name to its introspected test (cmd/env)."""
    # meson junit names look like "agent - yuzu:agent unit tests"; the
    # introspect `name` ("agent unit tests") is a substring. Longest match wins.
    best = None
    for t in tests:
        n = t.get("name", "")
        if n and n in failed_name and (best is None or len(n) > len(best.get("name", ""))):
            best = t
    return best


# ── running Catch2 binaries ───────────────────────────────────────────────────
def _cmd_without_test_specs(cmd):
    """cmd minus positional Catch2 tag-filter specs.

    Sharded meson entries (#2092) carry a tag spec ('~[pg]' / '[pg]') in their
    args, and Catch2 ORs positional test specs — appending a case name to the
    introspected cmd would re-run the whole shard ∪ case. The isolated retry
    must REPLACE the shard filter with the case name. argv[0] and option args
    are never touched."""
    if not cmd:
        return []
    return [cmd[0]] + [a for a in cmd[1:] if not CATCH2_TAG_SPEC.match(a)]


def _cmd_for_case_retry(cmd):
    """cmd minus tag-filter specs AND --allow-running-no-tests.

    That flag (pg shard D, #2092) survives _cmd_without_test_specs — it
    doesn't match CATCH2_TAG_SPEC — so it would otherwise carry straight into
    an isolated single-case retry. Catch2 ORs a comma inside a positional
    name spec into multiple sub-filters, so a case whose own name contains a
    literal comma (real example: ADR-0051's "...missing ONLY
    software_packages, with real deployment data in the other two tables")
    legitimately zero-matches both halves. On a whole-shard run that
    zero-match is the DSN-less-platform all-skip the flag exists for; on a
    single already-known case name it is always an error, never a
    legitimate skip — left in, that zero-match still exits 0 and
    retry_case() reports a case that never ran as recovered."""
    stripped = _cmd_without_test_specs(cmd)
    if not stripped:
        return stripped
    return [stripped[0]] + [a for a in stripped[1:] if a != "--allow-running-no-tests"]


_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def _meson_test_env(builddir):
    """Env additions replicating `meson test`'s own launch contract for a
    test() binary (#4580 root cause). `meson test` always sets
    MESON_BUILD_ROOT/MESON_SOURCE_ROOT and runs with CWD at the build root
    (never introspectable — meson injects these at launch time, not part of
    a test() entry's own declared `env`/`cmd`); a large fraction of this
    suite locates its build-output plugin .so/.dylib via exactly these two
    vars (grep tests/unit/*.cpp for MESON_BUILD_ROOT — dozens of call sites,
    several with an explicit "under meson test, this is always set" comment,
    e.g. test_disk_actions_local_dispatcher.cpp). A caller re-invoking the
    test BINARY directly, bypassing `meson test` itself, must replicate this
    contract or every such test fails deterministically on its
    plugin-not-found fallback, indistinguishable from a real regression —
    this was the actual mechanism behind #4580's ~20-case cascade, not CI
    concurrency: every case in the cascade shared this exact fallback path,
    at time=0.000 (never touched real logic), across three independent
    occurrences with unrelated original failures (PRs #4532/#4566/#4583)."""
    return {
        "MESON_BUILD_ROOT": os.path.abspath(builddir),
        "MESON_SOURCE_ROOT": _REPO_ROOT,
    }


def _run(cmd, env, workdir, builddir=None, extra=None, timeout=None):
    e = dict(os.environ)
    if builddir:
        e.update(_meson_test_env(builddir))
    e.update(env or {})
    cwd = workdir or (os.path.abspath(builddir) if builddir else None)
    return subprocess.run(
        cmd + (extra or []), env=e, cwd=cwd,
        capture_output=True, text=True, timeout=timeout,
    )


def _suite_slug(test):
    """Filesystem-safe slug for a test() entry, for the preserved-junit path."""
    name = test.get("name") or os.path.basename((test.get("cmd") or ["unknown"])[0])
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "unknown"


def _clear_stale_enum_junit(builddir):
    """Best-effort: remove any flake-retry-enum-*.catch2.xml left over from a
    PRIOR invocation before this one writes its own (#4580 review finding).
    `build-linux-*`/`build-windows-*` dirs are NOT wiped between ordinary CI
    runs (`clean:false` in ci.yml, persisted for ccache/vcpkg reuse) — without
    this, a suite that failed on run N but not on run N+1 leaves run N's file
    sitting in meson-logs/, where a same-directory failure on run N+1 (for a
    DIFFERENT suite) sweeps it into that run's own "on failure" artifact
    upload alongside genuinely-fresh evidence, with nothing in the filename
    distinguishing old from new. Called once per invocation, before any suite
    runs, so at most this run's own entries can ever be present when the
    artifact upload happens. Never raises: diagnostic bookkeeping only, must
    not affect retry semantics.

    KNOWN LIMITATION (build-ci review, 2026-09-18): ci.yml's "Test (non-pg
    suites)" step invokes flake-retry.py TWICE against the same --builddir.
    If the first invocation preserves evidence for a case that then recovers
    via known-flaky retry (rc 0, bash -e does not abort), the second
    invocation's own sweep deletes that same-run, still-legitimate file too —
    this function cannot distinguish "written earlier this run" from
    "leftover from three runs ago" by filename alone. Fail-SAFE, not
    fail-misleading (evidence silently absent, never wrong-run evidence
    silently present as current), so left as a documented follow-up rather
    than blocking this fix: stamping the preserved filename with
    GITHUB_RUN_ID would close it."""
    if not builddir:
        return
    import glob

    for stale in glob.glob(os.path.join(builddir, "meson-logs", "flake-retry-enum-*.catch2.xml")):
        try:
            os.remove(stale)
        except OSError:
            pass


def _preserve_enum_junit(builddir, test, xml_path):
    """Best-effort: copy a failed suite's enumeration re-run junit XML into
    meson-logs/ instead of letting it be deleted (#4580) — it rides the
    existing meson-logs CI artifact upload, so a future occurrence is
    diagnosable (real assertion text/file:line for every enumerated case)
    without re-downloading and manually inspecting raw run artifacts. Purely
    diagnostic: never raises, never affects retry semantics. `builddir` is
    optional (omitted in the selftest / a caller with no build) — a no-op
    then, not an error."""
    if not builddir:
        return
    try:
        logs = os.path.join(builddir, "meson-logs")
        os.makedirs(logs, exist_ok=True)
        dest = os.path.join(logs, f"flake-retry-enum-{_suite_slug(test)}.catch2.xml")
        with open(xml_path, "rb") as src, open(dest, "wb") as dst:
            dst.write(src.read())
    except OSError:
        pass


def catch2_failed_cases(test, this_os, builddir=None):
    """Re-run a failed Catch2 suite with the junit reporter; return failed case
    names, or None if it isn't a classifiable Catch2 run (non-Catch2 / crash /
    hang). `timeout` mirrors the suite's own meson-configured timeout (falsy ->
    None, meson's own "no timeout" convention) so a genuine hang degrades to a
    clean unclassifiable result instead of blocking the job indefinitely — the
    observed failure mode this guards is a fast abnormal exit, not a hang, so
    this is a robustness net rather than a fix for that specific pattern.

    This is a SEPARATE re-run of the whole suite, not a replay of the exact
    failure meson's own invocation hit (#4580) — on a suite with real-
    subprocess/environment-sensitive cases, the set returned here can differ
    from, or omit entirely, whatever case(s) actually failed the original
    invocation (meson's own junit is suite-granularity only, so there is no
    structured record of the original run's specific case to compare
    against). Every name this function returns is still a genuine failure
    from an actual run just now, so blocking on it is never a false report
    — but do not read the returned set as authoritative for *why* the
    original invocation failed."""
    # Deliberately keeps any shard tag-filter in cmd: the enumeration re-run
    # must only surface failures from THIS shard (#2092). Only the isolated
    # retry_case() strips it.
    cmd = test.get("cmd") or []
    if not cmd or not CATCH2_EXE.search(os.path.basename(cmd[0])):
        return None  # gateway (python) or anything not a Catch2 binary
    fd, xml_path = tempfile.mkstemp(suffix=".catch2.xml")
    os.close(fd)
    try:
        _run(cmd, test.get("env"), test.get("workdir"), builddir,
             extra=["--reporter", "junit", "--out", xml_path],
             timeout=test.get("timeout") or None)
        if not os.path.getsize(xml_path):
            return None  # crash/timeout before any reporter output -> unclassifiable
        cases = _failed_testcase_names(xml_path)
        _preserve_enum_junit(builddir, test, xml_path)
        return cases
    except (ET.ParseError, OSError, subprocess.TimeoutExpired):
        return None
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass


def retry_case(test, case, retries, builddir=None):
    """Return the 1-based retry attempt that passed, or 0 if none passed."""
    cmd = _cmd_for_case_retry(test.get("cmd") or [])
    for attempt in range(1, retries + 1):
        try:
            result = _run(cmd, test.get("env"), test.get("workdir"), builddir, extra=[case],
                          timeout=test.get("timeout") or None)
        except subprocess.TimeoutExpired:
            continue
        if result.returncode == 0:
            return attempt
    return 0


def write_retry_report(builddir, this_os, recovered, blocked):
    """Persist retry evidence without changing the test process' result."""
    import json

    logs = os.path.join(builddir, "meson-logs")
    path = os.path.join(logs, "flake-retry.json")
    tmp = path + f".{os.getpid()}.tmp"
    payload = {
        "platform": this_os,
        "recovered": [
            {
                "case": case,
                "cross_platform": cross,
                "attempts": attempts,
            }
            for case, cross, attempts in recovered
        ],
        "blocked": list(blocked),
    }
    try:
        os.makedirs(logs, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
        return True
    except (OSError, TypeError, ValueError) as ex:
        try:
            os.remove(tmp)
        except OSError:
            pass
        gh(
            "warning",
            "flake retry report write failed "
            f"(reporting only, run unaffected): {ex}",
        )
        return False


# ── orchestration ─────────────────────────────────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(description="meson test with known-flaky case retry")
    ap.add_argument("--builddir")  # required unless --selftest (validated below)
    ap.add_argument("--known-flaky", default="tests/known-flaky.json")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--stale-days", type=int, default=90)
    ap.add_argument("--selftest", action="store_true", help="run internal logic checks and exit")
    ap.add_argument("meson_args", nargs="*", help="passthrough args after `--`")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()
    if not args.builddir:
        ap.error("--builddir is required (unless --selftest)")

    this_os = detect_os()
    # Validate the list up front (fail-fast on a malformed list).
    try:
        flaky = load_known_flaky(args.known_flaky, this_os, args.stale_days)
    except Exception as ex:  # noqa: BLE001 — surface any list error as a hard failure
        gh("error", f"known-flaky list invalid: {ex}")
        return 2

    # 0. Clear any stale enumeration-junit evidence from a prior invocation in
    #    this same (persisted) build dir, before this run gets a chance to
    #    write its own (#4580) — see _clear_stale_enum_junit's docstring.
    _clear_stale_enum_junit(args.builddir)

    # 1. Run meson test normally.
    rc = subprocess.run(["meson", "test", "-C", args.builddir] + args.meson_args).returncode

    # 2. Duration-vs-budget watchdog (#2093) — before the green early-return,
    #    because the creep it exists to surface happens in green runs. Hard
    #    exception-guarded: reporting must never turn a green run red (e.g.
    #    introspect returning rc 0 with garbled stdout, or a non-numeric
    #    timeout reaching the frac arithmetic).
    tests = []
    try:
        tests = introspect_tests(args.builddir)
        report_suite_budgets(args.builddir, tests)
    except Exception as ex:  # noqa: BLE001 — watchdog is reporting-only by contract
        # `tests` keeps whatever introspect managed to return ([] if it was
        # introspect itself that threw) — the failure path below re-uses it.
        gh("warning", f"suite-budget watchdog failed (reporting only, run unaffected): {ex}")

    if rc == 0:
        write_retry_report(args.builddir, this_os, [], [])
        return 0

    gh("notice", "meson test failed — checking whether every failure is a known flake")

    failed_suites = meson_failed_suites(args.builddir)
    if not failed_suites:
        gh("error", "test failed but no per-suite junit to classify — failing (no masking)")
        write_retry_report(
            args.builddir,
            this_os,
            [],
            ["test failed but no per-suite junit to classify"],
        )
        return rc or 1
    blocked = []      # case names that must fail the job
    recovered = []    # (case, cross_platform, retry_attempt) that recovered
    for suite_name in sorted(failed_suites):
        test = match_suite(suite_name, tests)
        if test is None:
            blocked.append(f"{suite_name} (could not map to a binary)")
            continue
        cases = catch2_failed_cases(test, this_os, args.builddir)
        if cases is None:
            blocked.append(f"{suite_name} (not a classifiable Catch2 run — crash/non-Catch2)")
            continue
        if not cases:
            # The suite failed under meson but a solo enumeration re-run
            # reproduced no failing case — an order/contention-dependent
            # failure (or a stale junit from a crashed previous run). Nothing
            # can be attributed to a listed flake, so returning 0 here would
            # mask a real red. Block, per the header contract.
            blocked.append(f"{suite_name} (suite failed but enumeration re-run "
                           f"reproduced no failing case — unclassifiable, no masking)")
            continue
        if len(cases) > 1:
            # #4580: a solo re-run of the WHOLE suite surfacing multiple
            # failing cases for what meson reported as a single suite
            # failure is not a replay of the original invocation — do not
            # read the names below as "what failed originally". The same
            # caveat technically applies at len(cases) == 1 too (a single
            # enumerated case can still be a DIFFERENT case than whatever
            # failed originally — meson's own junit is suite-granularity
            # only, so there is nothing to compare against either way), but
            # >1 is the shape that visibly LOOKS suspicious to a human
            # reader; a lone case reads as an unremarkable, expected
            # reproduction and isn't worth a notice on every ordinary flake.
            gh("notice",
               f"{suite_name}: the enumeration re-run found {len(cases)} failing "
               "cases in a separate solo run of the whole suite, not a replay of "
               "the original invocation — the original failure may not be among "
               "these names (#4580). Assertion detail preserved at "
               f"meson-logs/flake-retry-enum-{_suite_slug(test)}.catch2.xml")
        for case in sorted(cases):
            entry = flaky.get(case)
            if entry is None:
                blocked.append(case)
                continue
            passed_attempt = retry_case(test, case, args.retries, args.builddir)
            if passed_attempt:
                cross = "all" in entry.get("platforms", [])
                recovered.append((case, cross, passed_attempt))
            else:
                blocked.append(f"{case} (listed flake but failed all {args.retries} retries)")

    # Report.
    write_retry_report(args.builddir, this_os, recovered, blocked)
    for case, cross, _attempts in recovered:
        if cross:
            gh("warning", f"CROSS-PLATFORM flake recovered on retry (needs urgent fix): {case}")
        else:
            gh("notice", f"known flake recovered on retry: {case}")
    if recovered:
        lines = ["### flake-retry", "", "Recovered known flakes (passed on retry):", ""]
        lines += [
            f"- {'⚠️ **cross-platform** ' if cross else ''}`{case}` "
            f"(retry {attempts})"
            for case, cross, attempts in recovered
        ]
        summary("\n".join(lines))

    if blocked:
        for b in blocked:
            gh("error", f"unrecovered test failure (blocking): {b}")
        summary("### flake-retry\n\nBlocking failures: " + ", ".join(f"`{b}`" for b in blocked))
        return 1
    return 0


# ── self-test (pure logic; runs without a build) ──────────────────────────────
def _selftest():
    import json

    failures = []

    def check(cond, label):
        if not cond:
            failures.append(label)

    # OS-scoping + metadata/date validation via a temp list file. `today` is
    # explicit so expiry checks are deterministic rather than calendar-dependent.
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "kf.json")
        today = date(2026, 7, 1)
        valid = {
            "case": "Win Only",
            "platforms": ["windows"],
            "reason": "r",
            "issue": "#1",
            "owner": "ci",
            "added": "2026-06-01",
            "expires": "2026-07-31",
        }
        with open(p, "w") as f:
            json.dump([
                valid,
                {**valid, "case": "Everywhere", "platforms": ["all"]},
            ], f)
        win = load_known_flaky(p, "windows", 90, today=today)
        lin = load_known_flaky(p, "linux", 90, today=today)
        check("Win Only" in win and "Everywhere" in win, "windows sees both")
        check("Win Only" not in lin and "Everywhere" in lin, "linux sees only cross-platform")

        # Every accountability/date field is mandatory, including for an OS
        # that does not apply to this run: malformed entries never hide there.
        for field in ("reason", "issue", "owner", "added", "expires"):
            malformed = dict(valid)
            del malformed[field]
            malformed["platforms"] = ["windows"]
            with open(p, "w") as f:
                json.dump([malformed], f)
            try:
                load_known_flaky(p, "linux", 90, today=today)
                check(False, f"missing-{field} should raise")
            except ValueError:
                pass

        for field in ("added", "expires"):
            malformed = dict(valid)
            malformed[field] = "2026-7-1"
            with open(p, "w") as f:
                json.dump([malformed], f)
            try:
                load_known_flaky(p, "windows", 90, today=today)
                check(False, f"non-ISO-{field} should raise")
            except ValueError:
                pass

        for label, malformed_entries in (
            ("duplicate case", [valid, dict(valid)]),
            ("ambiguous all platform", [{**valid, "platforms": ["all", "windows"]}]),
            ("duplicate platform", [{**valid, "platforms": ["windows", "windows"]}]),
        ):
            with open(p, "w") as f:
                json.dump(malformed_entries, f)
            try:
                load_known_flaky(p, "windows", 90, today=today)
                check(False, f"{label} should raise")
            except ValueError:
                pass

        for label, malformed in (
            ("expiry before added", {**valid, "expires": "2026-05-31"}),
            ("expired entry", {**valid, "expires": "2026-06-30"}),
            ("future added date", {**valid, "added": "2026-07-02"}),
        ):
            with open(p, "w") as f:
                json.dump([malformed], f)
            try:
                load_known_flaky(p, "windows", 90, today=today)
                check(False, f"{label} should raise")
            except ValueError:
                pass

        # The expiry date remains valid through that calendar day.
        with open(p, "w") as f:
            json.dump([{**valid, "expires": "2026-07-01"}], f)
        check("Win Only" in load_known_flaky(p, "windows", 90, today=today),
              "entry is valid on its expiry date")

    # junit parsing.
    with tempfile.TemporaryDirectory() as d:
        x = os.path.join(d, "t.xml")
        with open(x, "w") as f:
            f.write('<testsuites><testsuite><testcase name="A"/>'
                    '<testcase name="B"><failure>x</failure></testcase></testsuite></testsuites>')
        check(_failed_testcase_names(x) == {"B"}, "junit picks only failed cases")

    # enumeration-junit preservation (#4580).
    check(_suite_slug({"name": "agent unit tests"}) == "agent-unit-tests",
          "suite slug: spaces become dashes")
    check(_suite_slug({"name": "a/b [pg]"}) == "a-b-pg",
          "suite slug: non-filename-safe chars collapse to dashes")
    check(_suite_slug({"cmd": ["/build/yuzu_agent_tests"]}) == "yuzu_agent_tests",
          "suite slug: falls back to cmd[0] basename when name is absent")
    with tempfile.TemporaryDirectory() as d:
        builddir = os.path.join(d, "build")
        os.makedirs(builddir)
        src = os.path.join(d, "src.xml")
        with open(src, "w") as f:
            f.write("<testsuites/>")
        test = {"name": "agent unit tests"}
        _preserve_enum_junit(builddir, test, src)
        dest = os.path.join(builddir, "meson-logs", "flake-retry-enum-agent-unit-tests.catch2.xml")
        check(os.path.exists(dest), "preserve: copies junit into meson-logs/ under the slug name")
        with open(dest, encoding="utf-8") as f:
            check(f.read() == "<testsuites/>", "preserve: content copied verbatim")
        check(os.path.exists(src), "preserve: source temp file is untouched (caller still deletes it)")
        # builddir=None (e.g. a caller with no build) is a documented no-op,
        # never an error — must not raise or fabricate a path.
        _preserve_enum_junit(None, test, src)
        # An unwritable destination degrades silently — diagnostic-only,
        # must never propagate and break the actual retry flow.
        unwritable_parent = os.path.join(d, "not-a-dir")
        with open(unwritable_parent, "w") as f:
            f.write("")
        try:
            _preserve_enum_junit(unwritable_parent, test, src)
        except OSError:
            check(False, "preserve: must swallow OSError from an unwritable builddir")

        # Stale-file sweep (#4580 review finding): build dirs are NOT wiped
        # between ordinary CI runs, so a prior run's leftover
        # flake-retry-enum-*.catch2.xml must not survive into this run's own
        # artifact upload looking like fresh evidence.
        logs = os.path.join(builddir, "meson-logs")
        stale_other = os.path.join(logs, "flake-retry-enum-some-other-suite.catch2.xml")
        with open(stale_other, "w") as f:
            f.write("<testsuites/>")
        _clear_stale_enum_junit(builddir)
        check(not os.path.exists(dest) and not os.path.exists(stale_other),
              "clear-stale: removes every prior flake-retry-enum-*.catch2.xml")
        # A directory with no meson-logs/ yet (first invocation ever) or no
        # matching files must be a silent no-op, not an error.
        empty_builddir = os.path.join(d, "empty-build")
        os.makedirs(empty_builddir)
        _clear_stale_enum_junit(empty_builddir)  # must not raise
        _clear_stale_enum_junit(None)  # must not raise

    # duration extraction + budget rows (#2093).
    with tempfile.TemporaryDirectory() as d:
        logs = os.path.join(d, "meson-logs")
        os.makedirs(logs)
        with open(os.path.join(logs, "testlog.junit.xml"), "w") as f:
            f.write('<testsuites><testsuite>'
                    '<testcase name="agent - yuzu:agent unit tests" time="200.5"/>'
                    '<testcase name="agent - yuzu:agent unit tests" time="0.5"/>'   # dup: summed
                    '<testcase name="docs - yuzu:changelog order"/>'                # no time: skipped
                    '<testcase name="tar - yuzu:tar unit tests" time="garbled"/>'   # bad time: skipped
                    '</testsuite></testsuites>')
        durations = _entry_durations(d)
        check(durations == {"agent - yuzu:agent unit tests": 201.0},
              "durations: sums dups, skips missing/garbled time attrs")
        check(_entry_durations(os.path.join(d, "nope")) == {}, "durations: missing junit -> {}")

    bt = [{"name": "agent unit tests", "timeout": 240}, {"name": "docs check", "timeout": 0}]
    rows = budget_rows({"agent - yuzu:agent unit tests": 201.0,
                        "docs - yuzu:docs check": 5.0,
                        "mystery - yuzu:unmapped entry": 1.0}, bt)
    by_name = {r[0]: r for r in rows}
    check(by_name["agent unit tests"][2] == 240 and abs(by_name["agent unit tests"][3] - 201.0 / 240) < 1e-9,
          "budget rows: maps junit name, computes frac")
    check(by_name["docs check"][2] is None and by_name["docs check"][3] is None,
          "budget rows: timeout 0 (meson no-timeout) -> no budget/frac")
    check(by_name["mystery - yuzu:unmapped entry"][2] is None,
          "budget rows: unmappable junit name keeps its name, no budget")
    # >80% predicate: 0.81 fires, 0.79 doesn't (frac > warn_frac).
    frac_hi = budget_rows({"a - yuzu:agent unit tests": 0.81 * 240}, bt)[0][3]
    frac_lo = budget_rows({"a - yuzu:agent unit tests": 0.79 * 240}, bt)[0][3]
    check(frac_hi > 0.8, "watchdog fires above 80%")
    check(not (frac_lo > 0.8), "watchdog silent below 80%")

    # report_suite_budgets end-to-end (#2093): the ::warning line and summary
    # table must actually emit — an inverted threshold or a formatting
    # exception would otherwise ship silently, since the watchdog is
    # reporting-only and nothing else exercises it.
    import contextlib
    import io
    with tempfile.TemporaryDirectory() as d:
        logs = os.path.join(d, "meson-logs")
        os.makedirs(logs)
        with open(os.path.join(logs, "testlog.junit.xml"), "w") as f:
            f.write('<testsuites><testsuite>'
                    '<testcase name="server - yuzu:server unit tests" time="510.0"/>'
                    '<testcase name="tar - yuzu:tar unit tests" time="12.0"/>'
                    '</testsuite></testsuites>')
        entries = [{"name": "server unit tests", "timeout": 600},
                   {"name": "tar unit tests", "timeout": 90}]
        summary_path = os.path.join(d, "summary.md")
        old_summary = os.environ.get("GITHUB_STEP_SUMMARY")
        os.environ["GITHUB_STEP_SUMMARY"] = summary_path
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                report_suite_budgets(d, entries)
        finally:
            if old_summary is None:
                del os.environ["GITHUB_STEP_SUMMARY"]
            else:
                os.environ["GITHUB_STEP_SUMMARY"] = old_summary
        stdout = out.getvalue()
        check("::warning::" in stdout and "server unit tests at 510/600s (85%)" in stdout,
              "watchdog warning emits for the over-budget suite")
        check("tar unit tests" not in stdout, "no warning for the under-budget suite")
        with open(summary_path, encoding="utf-8") as f:
            table = f.read()
        check("### Suite durations vs meson budgets" in table
              and "| test entry | wall (s) | budget (s) | used |" in table,
              "summary table heading and header row written")
        check("| server unit tests | 510 | 600 | 85% |" in table
              and "| tar unit tests | 12 | 90 | 13% |" in table,
              "summary table rows written on green")

    # catch2 exe detection.
    check(CATCH2_EXE.search("yuzu_agent_tests.exe") is not None, "catch2 exe matches (win)")
    check(CATCH2_EXE.search("yuzu_server_tests") is not None, "catch2 exe matches (nix)")
    check(CATCH2_EXE.search("python3") is None, "python is not a catch2 exe")

    # suite matching.
    tests = [{"name": "agent unit tests", "cmd": ["x"]}, {"name": "tar unit tests", "cmd": ["y"]}]
    check(match_suite("agent - yuzu:agent unit tests", tests)["cmd"] == ["x"], "suite match")

    # sharded server suite (#2092): the two shard names must map uniquely
    # (neither is a substring of the other; longest-match protects prefixes).
    shards = [{"name": "server unit tests", "cmd": ["s", "~[pg]"]},
              {"name": "server pg unit tests", "cmd": ["s", "[pg]"]}]
    check(match_suite("server - yuzu:server unit tests", shards)["cmd"] == ["s", "~[pg]"],
          "non-pg shard maps to itself")
    check(match_suite("server - yuzu:server pg unit tests", shards)["cmd"] == ["s", "[pg]"],
          "pg shard maps to itself")

    # tag-spec surgery for isolated retries (#2092): strip positional tag
    # filters, keep argv[0] and option args, never invent args.
    check(_cmd_without_test_specs(["x", "~[pg]"]) == ["x"], "strips ~[pg]")
    check(_cmd_without_test_specs(["x", "[pg]"]) == ["x"], "strips [pg]")
    check(_cmd_without_test_specs(["x", "--foo", "[a][b]"]) == ["x", "--foo"],
          "strips compound tag spec, keeps options")
    check(_cmd_without_test_specs(["x"]) == ["x"], "no-spec cmd unchanged")
    check(_cmd_without_test_specs([]) == [], "empty cmd stays empty")
    check(_cmd_without_test_specs(["~[pg]", "[pg]"]) == ["~[pg]"],
          "argv[0] untouched even when spec-shaped")
    check(_cmd_without_test_specs(["x", "~[a][b]"]) == ["x"], "strips tilde compound spec")
    check(_cmd_without_test_specs(["x", "[pg]~[routes]~[store]~[token]"]) == ["x"],
          "strips mid-spec-negation shard filter (#2394)")
    check(_cmd_without_test_specs(["x", "[pg][routes],[pg][store],[pg][token]"]) == ["x"],
          "strips comma-OR shard filter (#2394)")
    check(_cmd_without_test_specs(["x", "a normal, prose case name"])
          == ["x", "a normal, prose case name"],
          "prose case name with a comma is NOT a spec (kept)")
    check(_cmd_without_test_specs(["x", "[.]"]) == ["x"], "strips hidden-tag spec")
    check(_cmd_without_test_specs(["x", ""]) == ["x", ""], "empty arg kept (not a spec)")

    # _cmd_for_case_retry (2026-08-17, found reviewing PR #3174's pg-shard-D
    # routing): --allow-running-no-tests must NOT survive into an isolated
    # single-case retry. It doesn't match CATCH2_TAG_SPEC, so
    # _cmd_without_test_specs() alone keeps it — and a case name with a
    # literal comma (Catch2 ORs a comma inside a positional spec) then
    # legitimately zero-matches, which the flag turns into a silent exit 0.
    check(_cmd_for_case_retry(["x", "[pg][audit_store]~[routes]~[store]~[token],"
                               "[pg][software_deployment]~[routes]~[store]~[token]",
                               "--allow-running-no-tests"]) == ["x"],
          "strips both the pg-shard-D tag spec and --allow-running-no-tests")
    check(_cmd_for_case_retry(["x", "--allow-running-no-tests", "[pg]"]) == ["x"],
          "strips the flag regardless of its position relative to the tag spec")
    check(_cmd_for_case_retry(["x", "--foo"]) == ["x", "--foo"],
          "an unrelated option flag is not mistaken for --allow-running-no-tests")
    check(_cmd_for_case_retry(["--allow-running-no-tests"]) == ["--allow-running-no-tests"],
          "argv[0] untouched even when it equals the flag")

    # Repo-hygiene guard (#2092): every positional arg on the server test()
    # entries in tests/meson.build must be a Catch2 tag-filter spec — the
    # invariant the retry surgery relies on. A future case-name or comma-list
    # spec would OR with the retried case and corrupt recovery verdicts; this
    # catches it at test time instead of in a masked flake.
    meson_build = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "..", "..", "tests", "meson.build")
    with open(meson_build, encoding="utf-8") as f:
        _src = f.read()
    # Entry-shaped parse (kwarg order and line breaks don't matter): grab
    # every test(..., server_test_exe, ...) body, then any args: [...] list
    # inside it. An args-less entry has no positional specs to strip, so it
    # is correctly exempt; both shard entries must be found and args-carrying
    # or the guard fails loudly instead of silently inspecting half the
    # surface.
    _entries = re.findall(r"test\(\s*'[^']*',\s*server_test_exe\b(.*?)\)", _src, re.S)
    # Windows CI test-phase restructuring (#3443, 2026-08-28): 12 pg shards
    # (10 + shard K + shard L, ADR-0065's instruction-cluster carve,
    # 2026-08-31) + 4 non-pg shards (A/B + shard C, then a later
    # measured-by-time follow-up added shard D, carved from B's [body_cap]
    # tests) + the smoke entry (also server_test_exe) = 17. The floor stays
    # a loose ">=", same spirit as the original "twelve" (itself a floor,
    # not an exact pin) -- exactness is check-pg-shard-partition.py's job,
    # against the real binary.
    check(len(_entries) >= 17, "meson.build: all seventeen server shard entries located")
    _shard_specs = []
    for _body in _entries:
        # Quote-aware list match: a naive [(.*?)] truncates at the tag spec's
        # own inner ']' and validates nothing (found independently by two
        # governance reviewers) — the ']' inside a quoted string must be
        # consumed by the string alternative, not end the list.
        _m = re.search(r"args:\s*\[((?:\s*'[^']*'\s*,?)*)\]", _body, re.S)
        if not _m:
            continue  # an args-less entry has no positional specs to strip
        _args = re.findall(r"'([^']*)'", _m.group(1))
        check(bool(_args), "meson.build: args-carrying server entry extracted non-empty")
        # Positional tag-filter specs vs Catch2 OPTION flags. A shard whose
        # cases ALL skip on a DSN-less platform (macOS: shard D, every case
        # gated on YUZU_TEST_POSTGRES_DSN) needs `--allow-running-no-tests`, or
        # Catch2 exits 4 on an all-skipped run and reds the leg (#2092). Option
        # flags are exempt from the tag-spec hygiene guard and from the shard
        # pin below (which keys on the positional specs). The whole-shard
        # enumeration re-run (catch2_failed_cases) preserves options, including
        # this one — it still needs to survive a DSN-less all-skip. The
        # isolated SINGLE-CASE retry (_cmd_for_case_retry) does NOT preserve
        # --allow-running-no-tests specifically: a comma-containing case name
        # would otherwise zero-match (Catch2 ORs a comma in a positional name
        # spec) and the flag would turn that into a silent false "recovered"
        # instead of the honest failure a single-case retry should never
        # tolerate zero matches on (found reviewing PR #3174's pg-shard-D
        # routing, 2026-08-17 — see _cmd_for_case_retry's own docstring).
        _specs = [a for a in _args if not a.startswith("-")]
        _opts = [a for a in _args if a.startswith("-")]
        check(bool(_specs), "meson.build: server entry has at least one positional spec")
        for _arg in _specs:
            check(CATCH2_TAG_SPEC.match(_arg) is not None,
                  f"meson.build server test arg {_arg!r} is not a tag-filter spec")
        for _opt in _opts:
            check(_opt.startswith("--"),
                  f"meson.build server test option {_opt!r} is not a --long flag")
        _shard_specs.append(tuple(_specs))
    # Positive pin, SCOPED DOWN (Phase 1, #3443): this used to pin all twelve
    # shard filters verbatim -- a hardcoded string hand-updated on every
    # pg-shard split/rebalance, missed 3 times in as many weeks, each time
    # reddening CI unconditionally (full incident history was here; it's
    # tests/meson.build's own shard-history comment now, the authoritative
    # copy, not duplicated here a second time to go stale independently).
    #
    # The pg shards' partition identity is now proven STRUCTURALLY, against
    # the real compiled binary, by scripts/ci/check-pg-shard-partition.py --
    # a dedicated meson test() entry (suite: ['server', 'server-checks'],
    # needs yuzu_server_tests built, which this selftest deliberately does
    # not depend on). It
    # discovers shard entries via `meson introspect --tests` keyed on suite
    # membership ('yuzu:server-pg'), not a hardcoded name/filter list, so a
    # pg-shard add/split/rebalance needs no update here at all -- only a
    # correct suite: kwarg on the new/changed test() entry, which the same
    # check would itself catch getting dropped (hollow-discovery guard).
    #
    # What's left to pin here: the NON-pg shard filters (auth/mcp split, now
    # four since a later measured-by-time follow-up carved shard D's
    # [body_cap] tests out of B, on top of the earlier B -> B+C split, #3443
    # 2026-08-28) -- comparatively stable, unlike the pg shards, which get
    # rebalanced -- so a small verbatim pin is proportionate for them
    # specifically. Plus a COUNT-based (not exact-string) sanity check that
    # extraction still finds a real pg-shard population (now 12: 10 + shard
    # K + shard L, plus the smoke entry makes 13 total non-excluded specs --
    # see the comment on the >= 13 floor below), as a second, independent signal
    # alongside check-pg-shard-partition.py's own hollow-discovery guard, in
    # case the two checks are ever run without each other.
    _NONPG_SPECS = (
        ("~[pg][auth],~[pg][mcp]",),
        ("~[pg]~[auth]~[mcp]~[cel]~[viz]~[scope]~[dispatch]~[nvd]~[dex]~[body_cap]",),
        ("~[pg]~[auth]~[mcp][cel],~[pg]~[auth]~[mcp][viz],~[pg]~[auth]~[mcp][scope],"
         "~[pg]~[auth]~[mcp][dispatch],~[pg]~[auth]~[mcp][nvd],~[pg]~[auth]~[mcp][dex]",),
        ("[body_cap]~[auth]~[mcp]~[cel]~[viz]~[scope]~[dispatch]~[nvd]~[dex]",),
    )
    _pg_specs = [s for s in _shard_specs if s not in _NONPG_SPECS]
    check(all(spec in _shard_specs for spec in _NONPG_SPECS),
          "meson.build: all four non-pg shard tag filters extracted verbatim")
    # _pg_specs = 12 real pg shards (10 + K + L, ADR-0065's instruction-
    # cluster carve, 2026-08-31) + the smoke entry (also server_test_exe,
    # also not one of the three excluded non-pg tuples) = 13. The smoke
    # entry's own spec ('[pg-smoke]',) has always been counted here; this is
    # a pre-existing property of the extraction, not new to any split
    # (verified against the pre-split source: smoke was already included,
    # making the OLD floor's true value 11 before K, not the "10 pg-shard
    # entries" an even older message claimed).
    check(len(_pg_specs) >= 13,
          f"meson.build: at least 13 pg-shard-or-smoke entries found (got {len(_pg_specs)}) "
          "-- exact partition identity is proven separately, against the real "
          "binary, by check-pg-shard-partition.py")

    if failures:
        print("SELFTEST FAILURES:", *failures, sep="\n  ")
        return 1
    print("flake-retry selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
