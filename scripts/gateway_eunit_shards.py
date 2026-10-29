#!/usr/bin/env python3
"""Deterministic shard partition for the gateway EUnit suite.

The Meson `gateway eunit shard <X>` tests (root meson.build) each run one
shard through `scripts/test_gateway.py <gateway_dir> eunit --shard K/N`.
Kept in its own module, like gateway_test_summary.py, because the wrapper
runs rebar3 at import time and so cannot be imported by a test. Pinned by
tests/test_gateway_eunit_shards.py.

WHY SHARD: the whole suite (`rebar3 eunit --dir apps/yuzu_gw/test`) took
461s on the Windows MSVC leg at 56f3e0df6 (85% of the wrapper's 540s
deadline) and then exceeded it as PR #5695 added modules (runs 39078203756
and 39103378230 both died at `DEADLINE EXCEEDED after 540s`). Rebar compile
is ~14s of that; the rest is test time, so the fix is to split the suite.

WHAT A SHARD RUNS, AND WHY IT IS THE SAME AS `--dir`
  rebar3 hands `--dir apps/yuzu_gw/test` to eunit as {dir, <out dir>}, and
  eunit_data:get_directory_module_tests/1 turns that into one {module, M}
  per top-level .beam in the directory, after DROPPING `M_tests` whenever
  `M` is also in the directory (eunit runs `M_tests` as part of `M`), each
  wrapped in its own setup group, so each module runs in its OWN test
  process. Each {module, M} runs M's own test functions plus `M_tests` if
  that module is loadable.
  A shard reproduces both halves:
    * the module set: `eunit_units` applies the same rules --
      - top-level `apps/yuzu_gw/test/*.erl` only (eunit does not recurse,
        so `test/ct/*_SUITE.erl` was never in the `--dir` run either);
      - `M_tests` is dropped when `M` is present (no such pair exists
        today; the rule is here so one added later is not run twice);
      - helper modules (`yuzu_gw_scale_*`, `yuzu_gw_test_listener`, the
        stub services, ...) ARE included, as `--dir` included them: they
        define no test functions today, so they contribute zero tests,
        but a helper that gains one still runs it in exactly one shard;
    * the process per module: the shard's modules reach eunit as
      `{spawn, {module, M}}` through gateway/eunit_shard.config.script
      (REBAR_CONFIG + YUZU_GW_EUNIT_SHARD_MODULES, set by the wrapper). The
      `rebar3 eunit --module m1,m2` form was tried first and is NOT
      equivalent: it runs every module in ONE shared process, and a shard
      was cancelled in yuzu_gw_planned_stop_tests' setup (`::shutdown`)
      by a link an earlier module left on that process.
  The shards together therefore run the same tests as `--dir` when their
  union is the same module set, which tests/test_gateway_eunit_shards.py
  pins. Only the ORDER differs: `--dir` runs the directory in the order of
  an Erlang dict (effectively arbitrary), a shard runs its modules sorted.
  Compilation is unaffected: rebar3 eunit compiles the whole `test/` dir
  under the test profile whatever the test selection is, so every helper a
  shard's modules call is built. If rebar3 ever ignored REBAR_CONFIG, it
  would run its default test set (everything) in every shard; the wrapper
  fails a shard whose output names a module outside it (`foreign_modules`).

PARTITION: greedy longest-processing-time. Each unit gets a weight
  (`WEIGHT_HINTS` seconds if listed, else DEFAULT_TEST_WEIGHT for a
  `*_tests` module and DEFAULT_HELPER_WEIGHT for anything else); units are
  taken heaviest first (ties broken by name) and each goes to the shard with
  the smallest running total (ties broken by lowest shard index). Pure
  function of the sorted file names and the committed table, so it is
  deterministic on every host; a new module needs no edit here — it gets
  the default weight and lands in exactly one shard. Within a shard the
  modules run in sorted name order.

WEIGHT_HINTS: per-module wall time in seconds on the Windows MSVC leg (the
  slowest leg), from the `[done in X s]` lines of run 39103378230 (head
  5adc6e5f8). Modules at or above ~5s are listed; everything else is close
  enough to the default that listing it buys nothing. A hint only steers
  balance — a stale or missing entry can never drop or duplicate a module.
  Re-derive from a fresh Windows log when the shards drift apart (the
  wrapper prints each shard's module list and weight total).
"""
import os
import re

# Seconds on Windows MSVC, run 39103378230 (5adc6e5f8), `[done in X s]`.
# yuzu_grpc_client_channel_tests was still running when that run hit its
# deadline, so its value is the macOS measurement (14.2s) scaled by the
# ~2.1x Windows/macOS ratio of the other heavy modules.
WEIGHT_HINTS = {
    "yuzu_gw_heartbeat_buffer_bound_tests": 64.3,
    "yuzu_gw_heartbeat_binding_tests": 52.3,
    "yuzu_gw_app_tests": 50.1,
    "yuzu_gw_registration_replay_tests": 39.0,
    "yuzu_grpc_client_channel_tests": 30.0,
    "yuzu_gw_notify_ack_tests": 25.7,
    "yuzu_gw_heartbeat_verdict_tests": 23.2,
    "yuzu_gw_health_tests": 18.2,
    "yuzu_grpc_listener_tests": 15.3,
    "yuzu_gw_session_cap_tests": 15.0,
    "yuzu_gw_notify_pending_tests": 13.3,
    "yuzu_gw_log_text_sites_tests": 11.7,
    "yuzu_gw_register_lifecycle_tests": 10.7,
    "yuzu_gw_owner_restart_tests": 9.1,
    "yuzu_gw_agent_registration_tests": 8.4,
    "yuzu_gw_mgmt_pins_tests": 7.8,
    "yuzu_gw_heartbeat_conn_rpc_tests": 6.6,
    "yuzu_grpc_client_tests": 6.5,
    "yuzu_gw_memory_shedder_tests": 6.3,
    "yuzu_gw_circuit_breaker_tests": 5.8,
    "yuzu_gw_register_bound_tests": 5.4,
    "yuzu_gw_upstream_notify_result_tests": 5.0,
}
DEFAULT_TEST_WEIGHT = 1.0    # an unlisted `*_tests` module
DEFAULT_HELPER_WEIGHT = 0.0  # anything else: no test functions today

TEST_SUFFIX = "_tests"

# The rebar3 config script (relative to the gateway dir) that turns
# YUZU_GW_EUNIT_SHARD_MODULES into the shard's `eunit_tests`.
SHARD_CONFIG_SCRIPT = "eunit_shard.config.script"

_MODULE_HEADING_RE = re.compile(r"^\s*module '([^']+)'\s*$", re.M)


def eunit_units(module_names):
    """The module set `rebar3 eunit --dir` would hand eunit, sorted.

    `module_names` are the top-level test-dir module names (no extension).
    Mirrors eunit_data:get_directory_module_tests/1: `M_tests` is dropped
    when `M` is present, because running `M` already runs `M_tests`.
    """
    names = set(module_names)
    return sorted(
        m for m in names
        if not (m.endswith(TEST_SUFFIX) and m[: -len(TEST_SUFFIX)] in names)
    )


def list_test_modules(test_dir):
    """Top-level `*.erl` module names in `test_dir` (not recursive)."""
    return sorted(
        f[:-4] for f in os.listdir(test_dir)
        if f.endswith(".erl") and os.path.isfile(os.path.join(test_dir, f))
    )


def weight(module, hints=None):
    hints = WEIGHT_HINTS if hints is None else hints
    if module in hints:
        return hints[module]
    return DEFAULT_TEST_WEIGHT if module.endswith(TEST_SUFFIX) else DEFAULT_HELPER_WEIGHT


def partition(module_names, n, hints=None):
    """Split `eunit_units(module_names)` into `n` lists (shard 1 first).

    Greedy longest-processing-time; deterministic. Every unit lands in
    exactly one shard; each shard's list is sorted.
    """
    if n < 1:
        raise ValueError(f"shard count must be >= 1, got {n}")
    units = eunit_units(module_names)
    shards = [[] for _ in range(n)]
    loads = [0.0] * n
    for m in sorted(units, key=lambda u: (-weight(u, hints), u)):
        i = min(range(n), key=lambda k: (loads[k], k))
        shards[i].append(m)
        loads[i] += weight(m, hints)
    return [sorted(s) for s in shards]


def shard_load(modules, hints=None):
    return sum(weight(m, hints) for m in modules)


def parse_shard(spec):
    """'K/N' -> (K, N), 1 <= K <= N. Raises ValueError otherwise."""
    try:
        k_s, n_s = spec.split("/")
        k, n = int(k_s), int(n_s)
    except ValueError:
        raise ValueError(f"--shard expects K/N (e.g. 1/2), got {spec!r}") from None
    if not 1 <= k <= n:
        raise ValueError(f"--shard {spec!r}: need 1 <= K <= N")
    return k, n


def shard_modules(test_dir, k, n, hints=None):
    """The sorted module list for shard K of N over `test_dir`."""
    return partition(list_test_modules(test_dir), n, hints)[k - 1]


def foreign_modules(output, modules):
    """Modules eunit reported (`module 'X'` headings) outside the shard.

    A shard's module M may legitimately report `M_tests` too (eunit runs it
    as part of M). Anything else means the shard selection was not applied.
    Sorted, de-duplicated.
    """
    allowed = set(modules) | {m + TEST_SUFFIX for m in modules}
    return sorted({m for m in _MODULE_HEADING_RE.findall(output) if m not in allowed})
