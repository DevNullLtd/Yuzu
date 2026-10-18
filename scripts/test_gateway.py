#!/usr/bin/env python3
"""Run Erlang gateway tests via rebar3.

Used by Meson test() because Ninja quotes compound shell commands
as a single argument, which breaks cmd.exe on Windows.

Three responsibilities beyond the bare rebar3 invocation:
  1. Retry the rebar3 test command up to 4 times when hex.pm fetch
     fails. hex.pm is intermittently flaky and an HTTP 502 / TCP RST
     on a single fetch attempt would otherwise fail the test even
     though Yuzu is fine. The retry helper detects the
     "Failed to fetch and copy dep:" sentinel and backs off
     exponentially (5s, 10s, 20s) between attempts. After any
     successful attempt rebar3's user-level hex cache holds the deps
     so subsequent runs find them locally without a network
     round-trip — on the persistent self-hosted Windows runner this
     means hex.pm is only touched on the very first run.
  2. Zero-executed guard (#4800): a rebar3 exit 0 that executed no
     tests, or printed no recognisable summary, fails the run
     (scripts/gateway_test_summary.py).
  3. Live-streamed output under a hard wall-clock deadline
     (`_run_streamed`, `_RUN_DEADLINE_SECS`) BELOW meson's own
     suite-level test timeout. A prior version of this wrapper called
     `subprocess.run(..., stdout=PIPE)` and only wrote the captured
     output after the child fully exited — its own docstring claimed
     output was "teed... live", which was false (a rule-3 truth
     finding: the comment described intended behaviour, not what the
     code did). When a Windows CI hang left that child never exiting,
     every failed run showed "zero output" — which told us nothing
     about where the hang occurred and cost three blind CI rounds
     chasing the wrong mechanism (HA WS-4 4.3a, PR #4573). Streaming
     plus a deadline that dumps the process tree and force-kills it
     means a future hang is diagnosed HERE, in this log, instead of
     reported as a featureless timeout by the outer harness.

A previous iteration (b33f1df) added an explicit pre-fetch step
running `rebar3 as test compile --deps_only` ahead of the actual
test invocation, intending to populate the hex cache earlier. On
Windows this turned out to leave `_build/test/lib/yuzu_gw/` in a
state where the subsequent `rebar3 as test eunit` compile race-d
with cover instrumentation, and cover would error with
`{cover,get_abstract_code,...,enoent,gateway_pb.beam}` on the
gpb-generated proto module — sometimes during gateway eunit,
sometimes during gateway ct, depending on which test ran first.
The pre-fetch was redundant on persistent runners (cache already
warm) so it was removed in favor of the simpler retry-on-test
flow. Linux and macOS were unaffected throughout.

Usage:
    test_gateway.py <gateway_dir> eunit               # whole EUnit suite
    test_gateway.py <gateway_dir> eunit --shard K/N   # EUnit shard K of N
    test_gateway.py <gateway_dir> ct                  # Common Test suites

`--shard K/N` (eunit only) runs shard K of a deterministic N-way partition
of the top-level test modules, each module in its own test process (via
gateway/eunit_shard.config.script); the N shards together run exactly what
the whole-suite `--dir` run does. The partition, and why it is faithful to
`--dir`, is in scripts/gateway_eunit_shards.py. Meson runs the gateway eunit suite as
shards (`gateway eunit shard A`, `... shard B`; root meson.build) so each
stays well inside the per-run deadline below on the Windows MSVC leg.
"""
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from erlang_toolchain import base_env, kill_tree, rebar3_prefix, windows_stdio_isolation  # noqa: E402

# Ensure locally-installed OTP 28 and rebar3 are on PATH (Meson inherits
# system PATH which may still point at the distro's older OTP 25 packages).
_extra_paths = [
    os.path.expanduser("~/.cache/rebar3/bin"),  # rebar3 local install
    "/usr/local/bin",                            # OTP 28 from source
]
_path = os.environ.get("PATH", "")
for p in reversed(_extra_paths):
    if os.path.isdir(p) and p not in _path:
        _path = p + ":" + _path
os.environ["PATH"] = _path

from gateway_eunit_shards import (  # noqa: E402
    SHARD_CONFIG_SCRIPT, foreign_modules, parse_shard, shard_load, shard_modules)

# Zero-executed guard (#4800): a rebar3 exit 0 with ZERO executed tests, or
# with no recognisable summary, is a failure. Logic and the summary shapes
# it accepts live in scripts/gateway_test_summary.py (pinned by
# tests/test_gateway_test_summary.py). Every sys.exit in this file goes
# through it (also pinned there); a non-zero code passes through unchanged,
# which is how the usage errors below exit 2.
from gateway_test_summary import require_tests_executed as _require_tests_executed  # noqa: E402

gateway_dir = sys.argv[1]
suite = sys.argv[2]  # "eunit" or "ct"
# Optional `--shard K/N`, eunit only. Parsed by hand (one fixed shape) so a
# typo is a loud usage error before any rebar3 work, never a whole-suite run.
_extra = sys.argv[3:]
shard = None
label = suite
if _extra:
    if suite != "eunit" or len(_extra) != 2 or _extra[0] != "--shard":
        print(f"usage: test_gateway.py <gateway_dir> eunit [--shard K/N] | ct "
              f"(got extra arguments {_extra!r})", file=sys.stderr)
        sys.exit(_require_tests_executed("", label, 2))
    try:
        shard = parse_shard(_extra[1])
    except ValueError as exc:
        print(f"test_gateway.py: {exc}", file=sys.stderr)
        sys.exit(_require_tests_executed("", label, 2))
    label = f"{suite} shard {shard[0]}/{shard[1]}"

# Clean the app's beam directory to prevent stale beam files from crashing
# Erlang's cover module during instrumentation.  Only the app ebin is
# removed — dependency beams (meck, proper, gun, …) are kept so they
# don't need to be recompiled on every run.
#
# REBAR_BASE_DIR selects the rebar3 `_build/` root; meson.build sets
# it per test (`_build_eunit_1`, `_build_eunit_2`, ... per eunit shard,
# `_build_ct`) so no two gateway rebar3 processes race on the same ebin
# tree. Absolute paths win over
# relative — meson hands us an absolute `_build_<suite>`; fall back to
# `<gateway>/_build` when the env var is unset (e.g. direct script
# invocation for local debugging).
_base = os.environ.get("REBAR_BASE_DIR") or str(Path(gateway_dir) / "_build")
app_ebin = Path(_base) / "test" / "lib" / "yuzu_gw" / "ebin"
if app_ebin.exists():
    shutil.rmtree(app_ebin)

cmd = rebar3_prefix() + ["as", "test", suite]
if suite == "ct":
    # Every CT suite lives in apps/yuzu_gw/test/ct/. `rebar3 ct` with no
    # `--dir` (or with `--dir apps/yuzu_gw/test`, which ct does NOT recurse)
    # discovers ZERO suites, prints "All 0 tests passed." and exits 0 --
    # the #4800 false green that hid #4707 and #4708 from every Meson/CI
    # run. The zero-executed guard at the bottom of this file fails the run
    # if a future path move ever recreates that.
    cmd += ["--dir", "apps/yuzu_gw/test/ct"]
elif suite == "eunit" and shard is None:
    cmd += ["--dir", "apps/yuzu_gw/test"]
elif suite == "eunit":
    # One shard: no test named on the command line, so rebar3 runs the
    # `eunit_tests` list that gateway/eunit_shard.config.script adds to
    # rebar.config -- this shard's modules, each `{spawn, {module, M}}`.
    # NOT `--module m1,m2`: that runs every module in one shared test
    # process, unlike `--dir` (see the script's header). The env is applied
    # below, once `env` exists.
    _test_dir = Path(gateway_dir) / "apps" / "yuzu_gw" / "test"
    _mods = shard_modules(str(_test_dir), *shard)
    if not _mods:
        print(f"test_gateway.py: {label} is empty: {shard[1]} shards over "
              f"{_test_dir} leaves this one nothing to run -- lower N.",
              file=sys.stderr)
        sys.exit(_require_tests_executed("", label, 2))
    if not (Path(gateway_dir) / SHARD_CONFIG_SCRIPT).is_file():
        print(f"test_gateway.py: {label} needs {Path(gateway_dir) / SHARD_CONFIG_SCRIPT}",
              file=sys.stderr)
        sys.exit(_require_tests_executed("", label, 2))
    print(f"[test_gateway.py] {label}: {len(_mods)} modules, weight "
          f"{shard_load(_mods):.1f}: {' '.join(_mods)}", flush=True)

if suite == "eunit":
    # Pre-create the eunit_surefire report dir (gateway/rebar.config
    # eunit_opts `{dir, "_build/test/eunit"}`, resolved relative to the
    # rebar3 CWD = gateway_dir). Belt-and-suspenders only: OTP 26+
    # eunit_surefire:init/1 already self-creates this dir via
    # filelib:ensure_dir + file:make_dir, so the dir's existence is not
    # the failure mode it was once thought to be (#1403).
    #
    # NOTE on the `eunit_surefire:write_report ... {error,enoent}` crash
    # seen in Windows eunit logs: that is a SEPARATE, HARMLESS artifact,
    # not a build-breaker. With `--dir`, eunit's top-level group is named
    # `directory "<abs path>"`; eunit_surefire:escape_suitename/1 turns
    # the path's `/` into `:`, producing a filename like
    # `TEST-directory_C::...:test.xml`. `:` is illegal in a Windows
    # filename, so file:open fails with enoent on every Windows run. It
    # does NOT affect the exit code: eunit's result comes from the
    # eunit_tty listener, and eunit:test waits for listeners to terminate
    # with ANY exit reason (see lib/eunit/src/eunit.erl). The surefire XML
    # is not consumed by CI, so the broken report is moot. (A `--shard`
    # run has no `directory` group; its per-module groups give ordinary
    # file names. Concurrent shards share this dir, but never a module.) The actual
    # intermittent #1403 failure was an unrelated test-isolation ETS race
    # (yuzu_gw_test_registry now serialises registry start across modules)
    # — its crash cancelled tests, which DID fail the build, and happened
    # to print alongside the always-present surefire noise.
    surefire_dir = Path(gateway_dir) / "_build" / "test" / "eunit"
    surefire_dir.mkdir(parents=True, exist_ok=True)

# For CT runs, set minimal perf parameters so the heavyweight perf suite
# finishes quickly.  The perf suite defaults to 10k agents, 50k heartbeats,
# and a 300-second endurance test — far too long for CI.
# Run full perf tests explicitly with default env vars:
#   cd gateway && rebar3 ct --suite=yuzu_gw_perf_SUITE
# base_env() carries the Windows temp-dir fix (TEMP/TMP/TMPDIR -> a native
# path) so the test path's cold _build can't hit the gpb-plugin \\tmp\
# robocopy hang either. See scripts/erlang_toolchain.py.
env = base_env()
if shard is not None:
    env["REBAR_CONFIG"] = str(Path(gateway_dir).resolve() / SHARD_CONFIG_SCRIPT)
    env["YUZU_GW_EUNIT_SHARD_MODULES"] = ",".join(_mods)
else:
    # Never inherit a shard selection into a whole-suite or ct run.
    env.pop("REBAR_CONFIG", None)
    env.pop("YUZU_GW_EUNIT_SHARD_MODULES", None)
if suite == "ct":
    env["YUZU_PERF_AGENTS"] = "10"
    env["YUZU_PERF_HEARTBEATS"] = "100"
    env["YUZU_PERF_FANOUT"] = "10"
    env["YUZU_PERF_CHURN_AGENTS"] = "10"
    env["YUZU_PERF_CHURN_CYCLES"] = "1"
    env["YUZU_PERF_ENDURANCE_AGENTS"] = "10"
    env["YUZU_PERF_ENDURANCE_SECS"] = "1"
    # The scale suite (yuzu_gw_scale_SUITE, 500 agents by default) runs its
    # `gate` group here: a broken invariant (Register parallelism, replay,
    # notices lost on an outage or a planned stop, fan-out answers, ...) fails
    # the leg. Switched on once all six cases passed in gate mode on three
    # consecutive runs after the PR #5695 fixes; docs/testing/gateway-scale-tests.md.
    env["YUZU_GW_SCALE_GATE"] = "1"

# ──────────────────────────────────────────────────────────────────────
# hex.pm flake retry helper
# ──────────────────────────────────────────────────────────────────────
HEX_FAIL_PATTERN = "Failed to fetch and copy dep:"

# PER SUITE, and each value must stay BELOW that suite's own meson
# `timeout:` in the root meson.build `test('gateway eunit shard ' + ...)` /
# `test('gateway ct')` definitions (the eunit value applies to each shard,
# and to a whole-suite local run), so a hang is diagnosed HERE — with a process-tree dump and a
# targeted kill — rather than reported as featureless "TIMEOUT, zero output"
# by the outer harness. This gap between the two timeouts is itself
# load-bearing: it is what makes the marker+dump below reachable before
# meson's own kill fires. A single 540s value used to serve both suites
# while `gateway ct` had a 300s meson timeout, so for ct meson always killed
# first and the dump was unreachable (#4800). Change a meson timeout and
# its value here together.
_SUITE_DEADLINE_SECS = {
    "eunit": 540,  # meson timeout 600, per shard
    "ct": 540,     # meson timeout 600
}
_RUN_DEADLINE_SECS = _SUITE_DEADLINE_SECS[suite]


class _ProcessDeadlineExceeded(Exception):
    pass


def _dump_process_tree():
    """Best-effort process listing, for diagnosing a hung child tree."""
    try:
        if os.name == "nt":
            subprocess.run(["tasklist", "/V"], check=False)
        else:
            subprocess.run(["ps", "-ef"], check=False)
    except Exception as exc:  # noqa: BLE001 - diagnostic path, never fatal
        print(f"[test_gateway.py] process-tree dump failed: {exc}", file=sys.stderr)


def _kill_process_tree(proc):
    """Kill the whole child tree, not just the immediate rebar3 process.

    The shared erlang_toolchain.kill_tree (the same one build_gateway.py
    uses): root killed last, taskkill in its own process group and bounded,
    retried across a second Ctrl-C.
    """
    if not kill_tree(proc):
        print("[test_gateway.py] process-tree kill reported failure; some "
              "processes may survive", file=sys.stderr)


def _run_streamed(args, deadline_secs):
    """Run a subprocess with output TEED LIVE to our stdout (not buffered
    until exit, unlike a bare `subprocess.run(..., stdout=PIPE)`), under a
    hard wall-clock deadline.

    Returns (returncode, captured_output_str). On a deadline breach, dumps
    a process listing, force-kills the whole child tree, and returns
    returncode -1 with whatever output was captured up to that point —
    the hang is then located in the log instead of silent.

    POSIX: the child runs in its own process group (`start_new_session`)
    so `_kill_process_tree` can reach grandchildren (e.g. a `peer`-spawned
    BEAM) the same way an outer job-object/process-tree kill would.
    """
    popen_kwargs = dict(
        cwd=gateway_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    # Null stdin + a private console on Windows (erlang_toolchain hazard 3);
    # the stdout pipe above is the other half. Never -noinput: it breaks the
    # standard_io `peer` nodes the multinode eunit suite starts.
    popen_kwargs.update(windows_stdio_isolation())
    if os.name == "nt":
        popen_kwargs["creationflags"] = (
            popen_kwargs.get("creationflags", 0) | subprocess.CREATE_NEW_PROCESS_GROUP
        )
    else:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(args, **popen_kwargs)
    try:
        return _stream_until_exit(proc, deadline_secs)
    except BaseException:
        # Ctrl-C, or a closed console: the child sits on its own console and
        # process group, so neither reaches it. Kill the tree before
        # unwinding, or it survives holding the _build locks.
        _kill_process_tree(proc)
        raise


def _stream_until_exit(proc, deadline_secs):
    """The body of `_run_streamed`, split out so every exit path of it is
    covered by the caller's kill-on-exception guard."""
    lines = []
    line_queue: "queue.Queue[str | None]" = queue.Queue()

    def _reader():
        try:
            for line in iter(proc.stdout.readline, ""):
                line_queue.put(line)
        finally:
            line_queue.put(None)

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    start = time.monotonic()
    deadline_hit = False
    while True:
        remaining = deadline_secs - (time.monotonic() - start)
        if remaining <= 0:
            deadline_hit = True
            break
        try:
            line = line_queue.get(timeout=remaining)
        except queue.Empty:
            continue
        if line is None:
            break
        sys.stdout.write(line)
        sys.stdout.flush()
        lines.append(line)

    if deadline_hit:
        print(
            f"\n[test_gateway.py] DEADLINE EXCEEDED after {deadline_secs}s — "
            "dumping process tree and killing the child before meson's own "
            "suite-level timeout fires blind:",
            file=sys.stderr,
        )
        _dump_process_tree()
        _kill_process_tree(proc)
        # Drain whatever the reader thread already queued.
        while True:
            try:
                line = line_queue.get_nowait()
            except queue.Empty:
                break
            if line is None:
                break
            sys.stdout.write(line)
            lines.append(line)
        try:
            returncode = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            returncode = -1
    else:
        returncode = proc.wait()

    return returncode, "".join(lines)


def run_with_retry(args, label, max_attempts=4):
    """Run a rebar3 command with retry on hex.pm fetch flakes.

    Returns an object with `.returncode`/`.stdout`, matching the subset of
    `subprocess.CompletedProcess` this script's callers use. Output is
    streamed live (see `_run_streamed`) and also captured for the hex.pm
    sentinel check below.

    Backoff: 5s, 10s, 20s between attempts (exponential). Total worst
    case is ~35s of waits across 4 attempts, plus the actual rebar3
    runtime per attempt.
    """

    class _Result:
        def __init__(self, returncode, stdout):
            self.returncode = returncode
            self.stdout = stdout

    result = _Result(-1, "")
    for attempt in range(1, max_attempts + 1):
        returncode, output = _run_streamed(args, _RUN_DEADLINE_SECS)
        result = _Result(returncode, output)
        if returncode == 0:
            return result
        if HEX_FAIL_PATTERN in output and attempt < max_attempts:
            backoff = 5 * (2 ** (attempt - 1))
            print(
                f"\n[test_gateway.py] {label}: hex.pm fetch failure detected "
                f"(attempt {attempt}/{max_attempts}) — sleeping {backoff}s and retrying",
                file=sys.stderr,
            )
            time.sleep(backoff)
            continue
        # Non-hex failure or last attempt — surface it.
        return result
    return result


# Output is captured for the zero-executed guard and also teed to console.
# run_with_retry handles hex.pm fetch flakes by detecting the
# "Failed to fetch and copy dep:" sentinel and backing off between
# attempts. 4 attempts × ~35s of waits at most before giving up.
result = run_with_retry(cmd, label, max_attempts=4)
output = result.stdout or ""

# A shard must run only its own modules. If rebar3 ever stopped honouring
# REBAR_CONFIG it would fall back to its default test set (the whole app plus
# test/), and every shard would silently run everything: not a false green,
# but the timeout this split exists to avoid. Fail that loudly instead.
returncode = result.returncode
if shard is not None:
    _foreign = foreign_modules(output, _mods)
    if _foreign:
        print(f"\n[test_gateway.py] {label}: eunit ran {len(_foreign)} module(s) "
              f"outside this shard (e.g. {', '.join(_foreign[:5])}) -- the "
              f"shard selection ({SHARD_CONFIG_SCRIPT} via REBAR_CONFIG) was not "
              "applied. Failing.", file=sys.stderr)
        if returncode == 0:
            returncode = 1

# Zero-executed guard (#4800), imported at the top: judged per run, so a
# shard that executes nothing fails on its own.
# (An OTP-25-only override used to live here: when CT's I/O handler crashed
# at teardown it replaced rebar3's non-zero exit with 0 if every "N failed"
# count in the output was 0. Governance for #4800 found that it could also
# pass a run in which a whole suite was auto-skipped ("0 failed, 6 skipped"),
# so it was removed. OTP 28 is the only supported toolchain
# (scripts/erlang_toolchain.py, CI), and on any other OTP the wrapper now
# fails closed on rebar3's own exit code.)
sys.exit(_require_tests_executed(output, label, returncode))
