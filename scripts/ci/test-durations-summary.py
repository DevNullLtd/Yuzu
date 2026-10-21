#!/usr/bin/env python3
"""test-durations-summary.py — per-invocation test-duration report (Yuzu, #4884).

Reads meson-logs/testlog.json (written by the `meson test` that just ran), and
appends two tables to $GITHUB_STEP_SUMMARY (stdout when unset):

  * one row per meson test() entry: wall seconds, meson timeout, % of timeout;
  * the N slowest Catch2 *test cases* across those entries.

The case table is fed by Catch2's own `--durations=yes` output
(`<secs> s: <name>`). Catch2 prints that line at the end of EVERY section, with
the test case's own root line last on each (re-)entry, so a raw per-name sum
would rank nested section timings next to their parent and merge identically
named sections of different cases. This script therefore keeps a line only when
its name is a listed test case of that entry (`--list-tests --verbosity quiet`
is one bare case name per line), and sums those per case across re-entries
(`runs` = re-entries). Known limit: a section named exactly like another case of the
same entry is summed into that case. An entry whose listing fails degrades to unfiltered
lines, marked `(unfiltered)` in the table.

Reporting only, never a gate (#4884): any failure in the reporting path becomes
a ::warning and exit 0. `--selftest` is the only non-zero exit, and it is
dispatched before and outside that handler.

Wired once after EACH flake-retry.py invocation in ci.yml (not at end of job):
meson overwrites testlog.json per invocation. On a red invocation `bash -e`
stops before this runs; the uploaded meson-logs artifact carries testlog.json,
so run this script against it locally.
"""
import argparse
import json
import os
import re
import subprocess
import sys

DURATION_LINE = re.compile(r"^\s*(\d+\.\d+) s: (.+?)\s*$")
# Only Catch2 test binaries are ever spawned for a case listing (the same
# shape flake-retry.py selects on); any other entry is never re-executed.
CATCH2_EXE = re.compile(r"yuzu_\w+_tests(\.exe)?$", re.IGNORECASE)
TOP = 25  # rows in the slowest-cases table


def summary(md):
    """Append markdown to the job summary; stdout when not under Actions."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        print(md)
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write(md + "\n")


# ── pure core ────────────────────────────────────────────────────────────────
def parse_durations(stdout):
    """[(secs, name)] for every Catch2 `<secs> s: <name>` line in stdout."""
    return [(float(m.group(1)), m.group(2))
            for m in map(DURATION_LINE.match, (stdout or "").splitlines()) if m]


def entry_name(json_name):
    """'server+server-pg - yuzu:server pg unit tests shard C' -> the test() name."""
    return json_name.split(" - ", 1)[-1].split(":", 1)[-1]


def summarise(records, tests, cases_by_entry, top):
    """-> (entry_rows, case_rows).

    records: parsed testlog.json lines; tests: `meson introspect --tests`;
    cases_by_entry: {entry: set(case names) | None} for the Catch2 entries that
    printed duration lines (None = listing failed -> keep every line, flagged).
    An entry absent from it contributes no case rows.
    entry_rows: [(entry, wall_s, timeout_s|None, frac|None, unfiltered)], by wall.
    case_rows:  top-N [(entry, case, secs, runs)], summed per (entry, case).
    """
    timeouts = {t.get("name"): (t.get("timeout") or None) for t in tests}
    wall, cases = {}, {}
    for rec in records:
        name = entry_name(rec.get("name", ""))
        wall[name] = wall.get(name, 0.0) + float(rec.get("duration") or 0.0)
        if name not in cases_by_entry:
            continue
        keep = cases_by_entry[name]
        for secs, case in parse_durations(rec.get("stdout")):
            if keep is None or case in keep:
                agg = cases.setdefault((name, case), [0.0, 0])
                agg[0] += secs
                agg[1] += 1
    entry_rows = []
    for name, secs in sorted(wall.items(), key=lambda kv: (-kv[1], kv[0])):
        budget = timeouts.get(name)
        entry_rows.append((name, secs, budget, (secs / budget) if budget else None,
                           name in cases_by_entry and cases_by_entry[name] is None))
    ranked = sorted(cases.items(), key=lambda kv: (-kv[1][0], kv[0]))[:max(top, 0)]
    return entry_rows, [(e, c, v[0], v[1]) for (e, c), v in ranked]


def _cell(text):
    return text.replace("|", "\\|")


def render(label, entry_rows, case_rows):
    out = [f"### Test durations — {label}", "",
           "| test entry | wall (s) | timeout (s) | used |", "|---|---:|---:|---:|"]
    for name, secs, budget, frac, unfiltered in entry_rows:
        shown = _cell(name) + (" (unfiltered)" if unfiltered else "")
        out.append(f"| {shown} | {secs:.0f} | {f'{budget:g}' if budget else '—'} | "
                   f"{f'{frac:.0%}' if frac is not None else '—'} |")
    out += ["", f"#### Top {len(case_rows)} slowest Catch2 cases", "",
            "| entry | case | s | runs |", "|---|---|---:|---:|"]
    out += [f"| {_cell(e)} | {_cell(c)} | {s:.2f} | {n} |" for e, c, s, n in case_rows]
    return "\n".join(out)


# ── thin shell (OS interaction) ──────────────────────────────────────────────
def list_cases(cmd, run=subprocess.run):
    """Bare case names a Catch2 entry runs, or None if the listing is unusable."""
    # ponytail: one --list-tests spawn per Catch2 entry (~19); switch to a second
    # xml reporter if the spawns ever matter.
    try:
        p = run(list(cmd) + ["--list-tests", "--verbosity", "quiet"],
                capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    return {ln.strip() for ln in p.stdout.splitlines() if ln.strip()} or None


def collect_cases(records, tests, lister=list_cases):
    """{entry: set|None} for every Catch2 entry that printed duration lines."""
    cmds = {t.get("name"): t.get("cmd") or [] for t in tests}
    out = {}
    for rec in records:
        name = entry_name(rec.get("name", ""))
        cmd = cmds.get(name)
        if name in out or not cmd or not CATCH2_EXE.search(os.path.basename(cmd[0])):
            continue
        if parse_durations(rec.get("stdout")):
            out[name] = lister(cmd)
    return out


def read_records(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def introspect_tests(builddir):
    p = subprocess.run(["meson", "introspect", builddir, "--tests"],
                       capture_output=True, text=True, timeout=60)
    return json.loads(p.stdout) if p.returncode == 0 else []


def report(builddir, label):
    path = os.path.join(builddir, "meson-logs", "testlog.json")
    records = read_records(path)
    tests = introspect_tests(builddir)
    rows = summarise(records, tests, collect_cases(records, tests), TOP)
    summary(render(label, *rows))


# ── selftest ─────────────────────────────────────────────────────────────────
def _checks():
    import tempfile
    import types
    res = []

    def check(label, ok):
        res.append((label, bool(ok)))

    check("parse: leading whitespace + float accepted",
          parse_durations("  0.123 s: a case\n12.500 s: b") == [(0.123, "a case"), (12.5, "b")])
    check("parse: noise rejected",
          parse_durations("All tests passed\n--- s: x\n3 s: int\n0.5 s:\n\n") == [])
    check("entry_name", entry_name("server+server-pg - yuzu:server pg unit tests shard C")
          == "server pg unit tests shard C")

    tests = [{"name": "ent", "timeout": 100, "cmd": ["/b/yuzu_server_tests"]},
             {"name": "slow", "timeout": 0, "cmd": ["/b/yuzu_agent_tests"]}]
    log = "0.1 s: leaf1\n0.2 s: leaf2\n1.0 s: root\n0.3 s: leaf1\n2.0 s: root\n"
    recs = [{"name": "server - yuzu:ent", "stdout": log, "duration": 50.0}]
    ents, cs = summarise(recs, tests, {"ent": {"root"}}, 25)
    check("summarise: sectioned case -> one root row, runs=2, secs summed, leaves dropped",
          cs == [("ent", "root", 3.0, 2)])
    check("summarise: entry % from introspect timeout", ents == [("ent", 50.0, 100, 0.5, False)])
    clash = [{"name": "server - yuzu:ent", "duration": 1.0,
              "stdout": "1.000 s: other case\n1.000 s: parent\n2.000 s: other case\n"}]
    _, cs = summarise(clash, tests, {"ent": {"parent", "other case"}}, 25)
    check("summarise: known limit - a section named like another case of its entry is summed into that case",
          cs == [("ent", "other case", 3.0, 2), ("ent", "parent", 1.0, 1)])

    ents, cs = summarise(recs, tests, {"ent": None}, 25)
    check("summarise: None case set keeps every line and flags (unfiltered)",
          len(cs) == 3 and ents[0][4] is True and "(unfiltered)" in render("x", ents, cs))
    two = [{"name": "s - yuzu:a", "stdout": "1.0 s: shared\n", "duration": 1.0},
           {"name": "s - yuzu:b", "stdout": "2.0 s: shared\n", "duration": 2.0}]
    _, cs = summarise(two, [], {"a": {"shared"}, "b": {"other"}}, 25)
    check("summarise: a name is only kept for the entry whose case set lists it",
          cs == [("a", "shared", 1.0, 1)])
    _, cs = summarise(two, [], {"a": {"shared"}, "b": {"shared"}}, 25)
    check("summarise: identical names in two entries stay separate rows", len(cs) == 2)

    many = [{"name": "s - yuzu:e", "stdout": "".join(f"{i}.0 s: c{i}\n" for i in range(1, 6)),
             "duration": 1.0}]
    _, cs = summarise(many, [], {"e": {f"c{i}" for i in range(1, 6)}}, 3)
    check("summarise: top-N sorted descending and capped", [c[1] for c in cs] == ["c5", "c4", "c3"])

    ents, _ = summarise([{"name": "s - yuzu:slow", "stdout": "", "duration": 4.0},
                         {"name": "s - yuzu:ghost", "stdout": "", "duration": 1.0}], tests, {}, 5)
    check("summarise: timeout 0 / unmappable name -> None, rendered as an em dash",
          [(e[0], e[2], e[3]) for e in ents] == [("slow", None, None), ("ghost", None, None)]
          and "| — | — |" in render("x", ents, []))

    calls = []
    recs3 = [{"name": "s - yuzu:ent", "stdout": log, "duration": 1.0},
             {"name": "s - yuzu:slow", "stdout": log, "duration": 1.0},
             {"name": "s - yuzu:eunit", "stdout": "no durations here\n", "duration": 9.0},
             {"name": "s - yuzu:py", "stdout": log, "duration": 1.0}]
    tests3 = tests + [{"name": "eunit", "timeout": 5, "cmd": ["/b/yuzu_gateway_eunit"]},
                      {"name": "py", "timeout": 5, "cmd": ["/usr/bin/python3", "t.py"]}]
    got = collect_cases(recs3, tests3, lister=lambda c: calls.append(c) or {"root"})
    check("collect: only Catch2 entries with duration lines are listed; others never spawn",
          sorted(got) == ["ent", "slow"] and len(calls) == 2)
    ents, _ = summarise(recs3, tests3, got, 5)
    check("summarise: entries without duration lines still get a row",
          "eunit" in [e[0] for e in ents])

    def runner(rc=0, out="", exc=None):
        def run(*a, **k):
            if exc:
                raise exc
            return types.SimpleNamespace(returncode=rc, stdout=out)
        return run

    check("list_cases: success parses bare names", list_cases(["x"], runner(0, "a\n b \n\n")) == {"a", "b"})
    check("list_cases: nonzero / timeout / OSError / empty -> None",
          all(list_cases(["x"], r) is None for r in (
              runner(1, "a"), runner(exc=subprocess.TimeoutExpired("x", 30)),
              runner(exc=OSError("no exe")), runner(0, "\n"))))

    check("render: headings and both table headers",
          all(s in render("L", [], []) for s in (
              "### Test durations — L", "| test entry | wall (s) | timeout (s) | used |",
              "| entry | case | s | runs |", "slowest Catch2 cases")))

    with tempfile.TemporaryDirectory(prefix="yuzu_test_durations_") as d:
        os.makedirs(os.path.join(d, "meson-logs"))
        before = os.environ.pop("GITHUB_STEP_SUMMARY", None)
        import contextlib
        import io
        with open(os.path.join(d, "meson-logs", "testlog.json"), "w") as f:
            f.write("{not json\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--builddir", d, "--label", "bad"])
        check("main: malformed JSON line -> ::warning and exit 0",
              rc == 0 and "::warning::" in buf.getvalue())
        if before is not None:
            os.environ["GITHUB_STEP_SUMMARY"] = before
    return res


def selftest():
    res = _checks()
    for label, ok in res:
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    failed = [lb for lb, ok in res if not ok]
    print("test-durations-summary selftest:", "FAILED: " + "; ".join(failed) if failed else "OK")
    return 1 if failed else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--builddir", default="build")
    ap.add_argument("--label", default="tests")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:  # before and outside the warning-only handler below
        return selftest()
    try:
        report(args.builddir, args.label)
    except Exception as ex:  # reporting only: never fail the job (#4884 AC2)
        print(f"::warning::test-durations-summary: report skipped ({type(ex).__name__}: {ex})",
              flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
