#!/usr/bin/env python3
"""tsan-gdb-capture.py — multi-binary gdb stack capture for the TSan nightly (#1038).

The nightly TSan job's diagnostic step used to gdb a single hardcoded binary
(`./tests/yuzu_server_tests`), so a crash in yuzu_agent_tests, yuzu_tar_tests or
yuzu_transport_tests captured no stack at all (#1038, R-06). This derives the
binaries to inspect from the run itself and appends every capture to one file.

Two entry paths, matching the two ways the TSan job can end badly:

  failure   — `meson test` ran to completion and something failed. The failing
              meson entries come from meson-logs/testlog.junit.xml; each maps back
              to its binary + args through `meson introspect --tests`, using the
              same longest-substring contract flake-retry.py already relies on.
              That mapping is IMPORTED from flake-retry.py rather than
              re-implemented, so the two cannot drift; tests/meson.build documents
              the naming constraint the sharded server entries must keep for it to
              hold, and the selftest below fails loudly if the import ever breaks.

  cancelled — the job hit its 60-minute timeout, i.e. a test hung. That is exactly
              the case a stack helps most (#1038, NICE-3), but meson never got to
              write testlog.junit.xml, so there is no failure list to read. What we
              do know: an entry that FINISHED has a section in testlog.txt. The
              stuck entry is therefore among the introspected Catch2 entries with no
              section. We replay those candidates (bounded — see BUDGETS) and let
              gdb's SIGINT interrupt dump the hung thread stacks.

Catch2 shuffles case order per run, so a replay only reproduces the original
interleaving if it re-uses that run's seed — parsed per-entry from that entry's own
testlog.txt section, not globally (a global grep would staple the first binary's
seed onto every other binary, R-06's "extract per-binary seed").

Best-effort by contract. This only ever runs when the job is ALREADY failing or
cancelled, so every internal error degrades to a note in the capture file and
exit 0: a diagnostic must never mask the real failure, nor invent a second one.
"""
import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FLAKE_RETRY = os.path.join(HERE, "flake-retry.py")

# Per-binary gdb wall budget, how many binaries we replay, and the grace we give
# gdb to finish dumping after SIGINT before timeout(1) escalates to KILL.
#
# The failure path runs inside the job's normal 60-min budget, so it can afford
# to be thorough. The cancelled path CANNOT: GitHub gives a cancelled job a
# 5-minute window and then forcibly terminates whatever is still running — and
# `Upload meson testlog and stack capture` is a LATER step, so every second spent
# in gdb is a second the upload might not get. A capture we cannot upload is worth
# nothing, so the cancelled budget is sized to leave the upload most of the window:
# worst case here is 2 x (45 + 10) = 110s of gdb, leaving ~3 of the 5 minutes.
BUDGETS = {
    #                per-binary   max bins        total   SIGINT->KILL grace
    "failure":   {"budget": 300, "max_bins": 4, "total": 900, "kill_after": 30},
    "cancelled": {"budget": 45,  "max_bins": 2, "total": 110, "kill_after": 10},
}

SEED_RE = re.compile(r"Randomness seeded to:\s*(\d+)")
# meson's testlog.txt banners each entry: "===== 3/5 =====" then "test: <name>".
# The <name> is byte-identical to the junit <testcase name=...>, which is what
# makes the junit -> section -> seed join safe.
BANNER_RE = re.compile(r"^={10,}\s+\d+/\d+\s+={10,}\s*$")
TEST_NAME_RE = re.compile(r"^test:\s+(.*?)\s*$")


def gh(kind, msg):
    """Emit a GitHub Actions annotation (::notice::/::warning::). sre O-1: the
    operator reading the workflow log should see diagnostic state without having
    to click into step output."""
    print(f"::{kind}::{msg}", flush=True)


def load_flake_retry():
    """Import flake-retry.py (hyphenated -> importlib, as its own test does).

    Single source of truth for the junit-name -> introspected-entry mapping. If
    this ever fails, the selftest fails in `meson test` on every platform, rather
    than the nightly silently losing its diagnostic at 06:00 UTC."""
    spec = importlib.util.spec_from_file_location("flake_retry", FLAKE_RETRY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── testlog.txt: per-entry sections, seeds, and who actually finished ─────────
def parse_sections(text):
    """{entry name: section body} from testlog.txt. Last occurrence wins (a
    re-run entry's most recent attempt is the one whose seed we want)."""
    sections, name, buf = {}, None, []
    for line in text.splitlines():
        if BANNER_RE.match(line):
            if name is not None:
                sections[name] = "\n".join(buf)
            name, buf = None, []
            continue
        m = TEST_NAME_RE.match(line)
        if m and name is None:
            name = m.group(1)
        buf.append(line)
    if name is not None:
        sections[name] = "\n".join(buf)
    return sections


def seed_of(section):
    """The Catch2 seed this entry ran with, or None if it crashed before Catch2
    printed it (replay then falls back to an unseeded shuffle)."""
    m = SEED_RE.search(section or "")
    return int(m.group(1)) if m else None


def read_testlog(builddir):
    path = os.path.join(builddir, "meson-logs", "testlog.txt")
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# ── selecting what to replay ──────────────────────────────────────────────────
def is_catch2(fr, test):
    """Only Catch2 binaries are worth a gdb replay — the python/hygiene entries
    (changelog order, proto version check, this selftest) have no native stack."""
    cmd = test.get("cmd") or []
    return bool(cmd) and bool(fr.CATCH2_EXE.search(os.path.basename(cmd[0])))


def targets_for_failure(fr, failed_names, tests, seeds):
    """Failing junit entries -> [(display name, cmd, env, seed)], deduped by the
    exact command (the two #2092 server shards share a binary but carry different
    tag filters — if both failed, both are worth replaying; if only one did, we
    must replay THAT shard's filter, not the whole suite)."""
    targets, seen = [], set()
    for name in sorted(failed_names):
        entry = fr.match_suite(name, tests)
        if not entry or not is_catch2(fr, entry):
            continue
        cmd = tuple(entry.get("cmd") or [])
        if not cmd or cmd in seen:
            continue
        seen.add(cmd)
        targets.append((name, list(cmd), entry.get("env") or {}, seeds.get(name)))
    return targets


def targets_for_cancelled(fr, tests, sections):
    """No junit (meson was killed mid-run), so infer: a Catch2 entry with no
    testlog.txt section never finished, and the hung one is among those. Ordered
    by introspect order for determinism; the caller bounds how many we take.

    "Finished" is resolved with the SAME longest-match mapping the failure path
    uses (flake-retry's match_suite), not a plain `name in section_name` test. A
    bare substring check is weaker than the contract in tests/meson.build, and it
    fails in the one direction that costs us the bug: given entries `server unit
    tests` and (hypothetically) `server unit tests pg`, a finished section for the
    LONGER name would also "contain" the shorter one, marking a hung entry as
    finished and skipping the very binary we needed a stack for."""
    finished = set()
    for sect_name in sections:
        entry = fr.match_suite(sect_name, tests)
        if entry and entry.get("name"):
            finished.add(entry["name"])

    targets = []
    for entry in tests:
        name = entry.get("name") or ""
        if not is_catch2(fr, entry) or name in finished:
            continue
        cmd = list(entry.get("cmd") or [])
        if cmd:
            targets.append((name, cmd, entry.get("env") or {}, None))
    return targets


# ── gdb ───────────────────────────────────────────────────────────────────────
def gdb_argv(cmd, seed, budget, kill_after):
    """timeout(1) + gdb batch argv for one replay.

    `--signal=INT` is what makes the cancelled/hang path produce anything: on a
    plain SIGTERM gdb dies and we capture nothing, whereas SIGINT interrupts the
    *inferior*, `run` returns, and gdb goes on to execute the backtrace commands
    below. --kill-after guarantees we still exit if gdb itself wedges.

    Program args go through `--args`, and we deliberately DO NOT touch
    `startup-with-shell`. That pairing is load-bearing and not obvious:

      gdb builds the inferior's argument string at `--args` PARSE time, escaping
      shell metacharacters (`~[pg]` is stored as `\\~\\[pg\\]` — `show args` will
      tell you so) on the assumption that its startup shell will unescape them
      again on the way to execve. Escaping and shell are one mechanism, not two.
      Turning the shell off while still using `--args` therefore breaks the
      round-trip and the inferior receives the BACKSLASHES: verified on gdb 15.1
      (Ubuntu 24.04) — argv[1] came through as `5c 7e 5c 5b 70 67 5c 5d`, i.e.
      literally `\\~\\[pg\\]`. gdb 17.1 (Ubuntu 26.04, the current Big Tam image)
      happens to unescape anyway, which is exactly what makes this the nastiest
      class of bug: a diagnostic that silently replays the WRONG Catch2 shard, and
      reports its no-repro with total confidence, on any runner with an older gdb.

    So: keep the shell, let gdb escape and the shell unescape, and the tag spec
    arrives byte-identical (`7e 5b 70 67 5d`) on both gdb 15.1 and 17.1. The
    escaping also means the shell never globs `[pg]` against the cwd. `_selftest`
    asserts this end-to-end against a real gdb wherever one exists, rather than
    trusting the Python list — asserting the list is what let this through."""
    replay = list(cmd)
    if seed is not None:
        replay += ["--rng-seed", str(seed)]
    replay += ["--order", "rand"]
    return [
        "timeout", "--signal=INT", f"--kill-after={kill_after}", str(budget),
        "gdb", "-batch",
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-ex", "set print thread-events off",
        "-ex", "set backtrace limit 80",
        "-ex", "run",
        "-ex", 'printf "\\n=== thread backtraces (full) ===\\n"',
        "-ex", "thread apply all bt full",
        "-ex", 'printf "\\n=== info registers ===\\n"',
        "-ex", "info registers",
        "-ex", "quit",
        "--args",
    ] + replay


def classify(captured):
    """What the replay actually got, for the ::notice:: and the in-file annotation.

    A TSan-aborted run (SIGABRT after a printed race report) and a bus error are
    just as much a capture as a SIGSEGV — matching only on SIGSEGV produced a
    false-negative "did not crash" note for every non-allocator race (R-13)."""
    if "SIGINT" in captured:
        return "hang", "interrupted after the time budget — stacks are of the HUNG run"
    if re.search(r"received signal|SIGSEGV|SIGABRT|SIGBUS|ThreadSanitizer:", captured):
        return "crash", "reproduced — stacks captured"
    return "no-repro", ("did not crash this run — Catch2 shuffle non-determinism; "
                        "re-dispatch the nightly for another attempt")


def capture_one(name, cmd, env, seed, budget, kill_after, builddir, out):
    argv = gdb_argv(cmd, seed, budget, kill_after)
    run_env = dict(os.environ)
    run_env.update({k: str(v) for k, v in (env or {}).items()})
    try:
        proc = subprocess.run(argv, cwd=builddir, env=run_env,
                              capture_output=True, text=True,
                              timeout=budget + kill_after + 30)
        captured = (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        captured = f"(gdb could not be run: {exc})\n"

    outcome, note = classify(captured)
    binary = os.path.basename(cmd[0])
    out.write(f"\n{'=' * 78}\n")
    out.write(f"=== {name}\n")
    out.write(f"=== binary : {binary}\n")
    out.write(f"=== argv   : {' '.join(cmd[1:]) or '(none)'}\n")
    out.write(f"=== seed   : {seed if seed is not None else '(not recovered)'}\n")
    out.write(f"=== outcome: {outcome} — {note}\n")
    out.write(f"{'=' * 78}\n")
    out.write(captured)
    out.flush()
    gh("notice", f"gdb capture: binary={binary} seed={seed if seed is not None else 'none'} "
                 f"outcome={outcome}")
    return outcome


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--builddir", default="build-linux-tsan")
    ap.add_argument("--output", default=None,
                    help="capture file (default: <builddir>/stack-capture.log)")
    ap.add_argument("--mode", choices=sorted(BUDGETS), default="failure",
                    help="failure: read junit. cancelled: infer the hung entries.")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()

    out_path = args.output or os.path.join(args.builddir, "stack-capture.log")

    # The best-effort contract is STRUCTURAL, not a promise in a comment. Meson's
    # junit can be present but truncated (the run was killed mid-write), and
    # ET.parse would then raise straight out of here — replacing the capture with
    # a Python traceback in an already-red job. Anything unexpected becomes a note
    # in the capture file plus a ::warning::, and we still exit 0.
    try:
        return _capture(args, out_path)
    except Exception as exc:  # noqa: BLE001 — a diagnostic must never add a failure
        gh("warning", f"stack capture failed internally ({exc!r}) — the job's real "
                      f"failure is unaffected")
        try:
            with open(out_path, "a", encoding="utf-8") as out:
                out.write(f"\n(stack capture failed internally: {exc!r})\n")
        except OSError:
            pass
        return 0


def _capture(args, out_path):
    limits = BUDGETS[args.mode]

    with open(out_path, "a", encoding="utf-8") as out:
        if not shutil.which("gdb"):
            gh("warning", "gdb unavailable on this runner — skipping stack capture")
            out.write("(gdb unavailable on this runner — no stack captured)\n")
            return 0

        fr = load_flake_retry()
        tests = fr.introspect_tests(args.builddir)
        if not tests:
            gh("warning", "meson introspect returned no tests — skipping stack capture")
            out.write("(meson introspect returned no tests — no stack captured)\n")
            return 0

        sections = parse_sections(read_testlog(args.builddir))
        seeds = {name: seed_of(body) for name, body in sections.items()}

        # The mode the caller asked for is a hint, not gospel: it comes from
        # `steps.test.outcome`, and what we can actually DO depends on whether
        # meson lived long enough to write testlog.junit.xml. Decide on the
        # evidence, so a job that reports 'failure' but died mid-run (killed
        # meson, OOM, runner reboot) still gets the inference path instead of
        # silently capturing nothing.
        failed = None if args.mode == "cancelled" else fr.meson_failed_suites(args.builddir)

        if failed is not None:
            targets = targets_for_failure(fr, failed, tests, seeds)
        elif args.mode == "cancelled" or sections:
            # No junit. Either the job was cancelled (timed out — so a test WAS
            # running and never returned), or meson was killed part-way through a
            # run that had already completed some entries. Either way the entries
            # with no testlog.txt section are the ones still in flight, and the
            # stuck one is among them. Note a timeout with ZERO completed entries
            # is normal — a hang in the first test — so an empty `sections` is not
            # a reason to bail here, only in the else below.
            targets = targets_for_cancelled(fr, tests, sections)
            limits = BUDGETS["cancelled"]  # we may be inside the grace window
            gh("notice", f"no testlog.junit.xml (run cut short): {len(targets)} Catch2 "
                         f"entr{'y' if len(targets) == 1 else 'ies'} never completed — "
                         f"replaying under gdb to catch the hang")
        else:
            # `failure` mode, no junit, and not one entry finished: meson never got
            # a test running, so the failure is upstream of the test binaries
            # (setup, a missing exe, Postgres). Nothing to point gdb at.
            gh("warning", "no testlog.junit.xml and no completed test entry — the "
                          "failure is upstream of the test binaries; nothing to capture")
            out.write("(no junit and no completed test entry — nothing to capture)\n")
            return 0

        if not targets:
            gh("notice", "no Catch2 binary to replay under gdb — nothing to capture")
            out.write("(no Catch2 binary to replay under gdb — nothing to capture)\n")
            return 0

        # Bounded, and loud about it: a silently-truncated capture reads as
        # "we looked at everything" when we did not.
        if len(targets) > limits["max_bins"]:
            dropped = [n for n, _, _, _ in targets[limits["max_bins"]:]]
            gh("warning", f"{len(targets)} candidate binaries, capturing the first "
                          f"{limits['max_bins']}; NOT captured: {', '.join(dropped)}")
            out.write(f"(capture capped at {limits['max_bins']} binaries; "
                      f"not captured: {', '.join(dropped)})\n")
            targets = targets[:limits["max_bins"]]

        kill_after = limits["kill_after"]
        spent = 0
        for name, cmd, env, seed in targets:
            remaining = limits["total"] - spent
            if remaining < 30:
                gh("warning", f"total gdb budget ({limits['total']}s) exhausted — "
                              f"{name} not captured")
                out.write(f"\n(total gdb budget exhausted — {name} not captured)\n")
                break
            budget = min(limits["budget"], remaining)
            capture_one(name, cmd, env, seed, budget, kill_after, args.builddir, out)
            # Charge the SIGINT->KILL grace too: a hung inferior really can burn
            # budget+kill_after of wall clock, and on the cancelled path the thing
            # this budget is protecting is the upload step's share of GitHub's
            # 5-minute window. Undercounting it is how the capture survives but the
            # artifact does not.
            spent += budget + kill_after

    return 0


# ── selftest ──────────────────────────────────────────────────────────────────
def _gdb_roundtrip(check):
    """Run a REAL gdb and assert the inferior receives the Catch2 tag spec
    byte-for-byte.

    This exists because the pure-logic argv assertions above cannot see the bug
    they were supposed to prevent: gdb rewrites the inferior's arguments between
    our argv list and execve, and an earlier version of this script delivered
    `\\~\\[pg\\]` to Catch2 while every list-level assertion still passed. The only
    honest test of "the shard filter survives" is to look at what the process
    actually got.

    FAIL-SAFE BY CONSTRUCTION: this asserts a failure ONLY when it positively
    observes the mangling. Every way gdb can fail to run cleanly — absent, wrong
    OS, can't attach (macOS Homebrew gdb without codesigning; a restrictive
    ptrace_scope), times out, emits no ARGV line — is a SKIP, never a failure. It
    must be safe to have in the `docs` suite that gates every PR on Linux, Windows
    AND macOS: a green environment that merely lacks a working gdb must not turn
    the suite red. Its teeth are live exactly where a working gdb exists — the TSan
    nightly (which installs gdb) and any local Linux/Docker run — which is exactly
    where the capture itself runs. The universal regression guard is the pure-logic
    `set startup-with-shell off not in argv` assertion above; this is the empirical
    belt-and-suspenders on top of it."""
    # macOS ships no `timeout` (it's `gtimeout` from coreutils), so stock macOS
    # skips here anyway; the checks below make an installed-but-unusable gdb safe.
    if os.name != "posix" or not shutil.which("gdb") or not shutil.which("timeout"):
        print("  (gdb round-trip: SKIPPED — no POSIX gdb/timeout here)")
        return

    import tempfile
    try:
        with tempfile.TemporaryDirectory() as td:
            echo = os.path.join(td, "argv_echo.py")
            with open(echo, "w", encoding="utf-8") as f:
                f.write("import sys\nprint('ARGV=' + '|'.join(sys.argv[1:]))\n")
            # Same code path the real capture uses — not a hand-written gdb command.
            argv = gdb_argv([sys.executable, echo, "~[pg]"], 222, 60, 10)
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        # gdb could not be run to completion here — not evidence the code is wrong.
        print(f"  (gdb round-trip: SKIPPED — gdb could not run: {exc!r})")
        return

    out = (proc.stdout or "") + (proc.stderr or "")
    line = next((l for l in out.splitlines() if l.startswith("ARGV=")), None)
    if line is None:
        # gdb ran but never launched the inferior (can't attach / codesign / ptrace
        # policy). No observation to make → skip, don't fail.
        print(f"  (gdb round-trip: SKIPPED — gdb produced no ARGV line; rc={proc.returncode})")
        return

    got = line[len("ARGV="):].split("|")
    check(got == ["~[pg]", "--rng-seed", "222", "--order", "rand"],
          f"gdb round-trip: inferior must receive the tag spec UNESCAPED, got {got!r} "
          f"(a `\\~\\[pg\\]` here means gdb's escaping lost its startup shell)")


def _selftest():
    """Pure-logic checks (no meson, no build dir) plus one real-gdb round-trip where
    a gdb exists. Mirrors flake-retry.py's --selftest so both are enforced by
    `meson test` on every platform."""
    failures = []

    def check(cond, label):
        if not cond:
            failures.append(label)

    # The import contract this whole script is built on.
    try:
        fr = load_flake_retry()
        check(callable(fr.match_suite) and callable(fr.meson_failed_suites),
              "flake-retry.py exposes match_suite/meson_failed_suites")
        check(fr.CATCH2_EXE.search("yuzu_server_tests") is not None,
              "flake-retry.py CATCH2_EXE still matches a Catch2 binary")
    except Exception as exc:  # noqa: BLE001 — a broken import must fail the test
        failures.append(f"import flake-retry.py: {exc!r}")
        print("SELFTEST FAILURES:", *failures, sep="\n  ")
        return 1

    # testlog.txt section parsing + per-entry seed. Two entries, two seeds: the
    # bug this replaces stapled the first seed found onto every binary.
    log = """Log of Meson test suite run on 2026-07-14T06:00:00

Inherited environment: FOO=bar

==================================== 1/3 =====================================
test:         tar - yuzu:tar unit tests
start time:   06:00:01
duration:     6.51s
result:       exit status 0
command:      /b/tests/yuzu_tar_tests
----------------------------------- stdout -----------------------------------
Randomness seeded to: 111
All tests passed
==============================================================================

==================================== 2/3 =====================================
test:         server - yuzu:server unit tests
start time:   06:00:08
duration:     9.00s
result:       exit status 1
command:      /b/tests/yuzu_server_tests ~[pg]
----------------------------------- stdout -----------------------------------
Randomness seeded to: 222
ThreadSanitizer: data race
==============================================================================
"""
    sections = parse_sections(log)
    check(set(sections) == {"tar - yuzu:tar unit tests", "server - yuzu:server unit tests"},
          "parse_sections finds exactly the two entries")
    check(seed_of(sections["tar - yuzu:tar unit tests"]) == 111, "per-entry seed: tar -> 111")
    check(seed_of(sections["server - yuzu:server unit tests"]) == 222,
          "per-entry seed: server -> 222 (not the first seed in the file)")
    check(seed_of("no seed here") is None, "missing seed degrades to None")

    tests = [
        {"name": "tar unit tests", "cmd": ["/b/tests/yuzu_tar_tests"], "env": {}},
        {"name": "server unit tests", "cmd": ["/b/tests/yuzu_server_tests", "~[pg]"], "env": {}},
        {"name": "server pg unit tests",
         "cmd": ["/b/tests/yuzu_server_tests", "[pg]"], "env": {"PG": "1"}},
        {"name": "agent unit tests", "cmd": ["/b/tests/yuzu_agent_tests"], "env": {}},
        {"name": "changelog order", "cmd": ["/usr/bin/python3", "t.py"], "env": {}},
    ]
    seeds = {name: seed_of(body) for name, body in sections.items()}

    # R-06: a failure in a NON-server binary must produce that binary, which is
    # the entire bug — the old step only ever gdb'd ./tests/yuzu_server_tests.
    t = targets_for_failure(fr, {"agent - yuzu:agent unit tests"}, tests, seeds)
    check([x[1] for x in t] == [["/b/tests/yuzu_agent_tests"]],
          "R-06: an agent-only failure replays the AGENT binary")

    # The two server shards share a binary but not a tag filter: both failing must
    # replay both filters — not one binary twice, and not the unfiltered suite.
    t = targets_for_failure(
        fr, {"server - yuzu:server unit tests", "server - yuzu:server pg unit tests"},
        tests, seeds)
    by_name = {name: (cmd, env, seed) for name, cmd, env, seed in t}
    check(sorted(cmd for cmd, _, _ in by_name.values()) ==
          sorted([["/b/tests/yuzu_server_tests", "~[pg]"],
                  ["/b/tests/yuzu_server_tests", "[pg]"]]),
          "both #2092 server shards replay with their own tag filter")
    check([n for n, _, _, _ in t] == sorted(by_name),
          "target order is deterministic (sorted) — the budget cap must be stable")
    check(by_name["server - yuzu:server unit tests"][2] == 222,
          "the shard that ran replays with ITS OWN seed")
    # The pg shard has no testlog.txt section here (it never completed), so its
    # seed must come back None — NOT the 222 belonging to the other shard. That
    # cross-contamination is precisely the per-binary-seed bug in R-06.
    check(by_name["server - yuzu:server pg unit tests"][2] is None,
          "an entry with no section gets no seed, not another entry's seed")
    check(by_name["server - yuzu:server pg unit tests"][1] == {"PG": "1"},
          "the pg shard carries its introspected env")

    # Non-Catch2 entries have no native stack to capture.
    t = targets_for_failure(fr, {"docs - yuzu:changelog order"}, tests, seeds)
    check(t == [], "a python/hygiene entry is never gdb'd")

    # Cancelled path: the entries with no testlog.txt section are the candidates.
    # tar + server finished (they have sections); server-pg and agent did not.
    t = targets_for_cancelled(fr, tests, sections)
    check([x[0] for x in t] == ["server pg unit tests", "agent unit tests"],
          "cancelled: only the entries that never finished are candidates")
    # A timeout in the FIRST test leaves no completed sections at all. That is the
    # stuck-test case we most want a stack for, so it must yield every Catch2
    # entry as a candidate — not be mistaken for "nothing ran, nothing to do".
    t = targets_for_cancelled(fr, tests, {})
    check([x[0] for x in t] == ["tar unit tests", "server unit tests",
                                "server pg unit tests", "agent unit tests"],
          "cancelled with nothing finished: every Catch2 entry is a hang candidate")
    check(all("python3" not in c[0] for _, c, _, _ in t),
          "the python/hygiene entries are still never candidates")

    # "Finished" must be resolved by LONGEST match, not bare substring. With a
    # hypothetical overlapping pair, a finished section for the LONGER name also
    # contains the shorter one — a substring test would mark the hung shorter entry
    # as finished and skip the one binary we needed.
    overlapping = [
        {"name": "server unit tests", "cmd": ["/b/tests/yuzu_server_tests"], "env": {}},
        {"name": "server unit tests pg",
         "cmd": ["/b/tests/yuzu_server_tests", "[pg]"], "env": {}},
    ]
    t = targets_for_cancelled(
        fr, overlapping, {"server - yuzu:server unit tests pg": "Randomness seeded to: 9"})
    check([x[0] for x in t] == ["server unit tests"],
          "cancelled: a finished LONGER-named entry does not mark the hung shorter "
          "one as finished (longest-match, not substring)")

    # gdb argv: seed replay, args straight through --args, SIGINT-on-timeout.
    argv = gdb_argv(["/b/tests/yuzu_server_tests", "~[pg]"], 222, 90, 10)
    check(argv[:4] == ["timeout", "--signal=INT", "--kill-after=10", "90"],
          "timeout sends SIGINT (so a HUNG inferior still dumps stacks), then KILLs")
    check("--args" in argv and argv[argv.index("--args") - 1] == "quit",
          "program args are passed via --args, after every gdb -ex")
    check(argv[argv.index("--args") + 1:] ==
          ["/b/tests/yuzu_server_tests", "~[pg]", "--rng-seed", "222", "--order", "rand"],
          "replay argv keeps the shard's tag filter and appends the seed")
    # REGRESSION GUARD. `set startup-with-shell off` alongside --args is precisely
    # the bug: gdb escapes the args at --args parse time expecting its startup
    # shell to unescape them, so killing the shell delivers `\~\[pg\]` to the
    # inferior on gdb 15.1. Keep them paired. See gdb_argv's docstring.
    check("set startup-with-shell off" not in argv,
          "startup shell is NOT disabled — it is what unescapes gdb's own escaping")
    argv_noseed = gdb_argv(["/b/tests/yuzu_agent_tests"], None, 300, 30)
    check("--rng-seed" not in argv_noseed, "an unrecovered seed degrades to a plain shuffle")

    # classify(): a TSan abort and a hang are captures, not "did not crash" (R-13).
    check(classify("ThreadSanitizer: data race")[0] == "crash", "TSan abort counts as a capture")
    check(classify("Program received signal SIGSEGV")[0] == "crash", "SIGSEGV counts")
    check(classify("Program received signal SIGINT")[0] == "hang", "SIGINT = the hang capture")
    check(classify("all tests passed")[0] == "no-repro", "a clean replay is honestly reported")

    # Budgets must leave the LATER upload step room inside GitHub's 5-minute
    # post-cancellation window, or the capture is taken and then thrown away.
    c = BUDGETS["cancelled"]
    worst = c["max_bins"] * (c["budget"] + c["kill_after"])
    check(worst <= 120,
          f"cancelled-path worst case ({worst}s of gdb) must leave most of GitHub's "
          f"300s cancellation window for the artifact upload")

    # The one assertion that would have caught the escaping bug.
    _gdb_roundtrip(check)

    if failures:
        print("SELFTEST FAILURES:", *failures, sep="\n  ")
        return 1
    print("tsan-gdb-capture selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
