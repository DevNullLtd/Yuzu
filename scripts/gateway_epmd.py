#!/usr/bin/env python3
r"""Run-private epmd for the gateway test wrapper (#4853).

WHY. The multinode eunit modules (yuzu_gw_registry_multinode_tests and
yuzu_gw_cluster_formation_multinode_tests) start Erlang distribution and
`peer` nodes through the host's one epmd on port 4369. On a self-hosted pool
several runner agents share one box and one OS identity (#1871). When a job
completes, the runner's "Complete job" step logs `Terminate orphan process:
... (epmd)` and kills that epmd, wherever it came from: a CONCURRENT job's
origin node loses its registration and its next `peer:start_link` times out,
a false red in a test the job's own change never touched. Seen on two PRs'
Windows legs on 2026-10-21 (runs 39613908142 and 39632327827), each 28-50 s
after another job on the same box completed.

WHAT. isolate() gives each wrapper run its own epmd port through
ERL_EPMD_PORT. Every VM the run starts inherits it (rebar3, the eunit VM, the
`peer` nodes, the epmd the first distributed node starts), so nothing the run
does touches port 4369 and no other job's cleanup can reach this run's epmd.
Nothing has to START the epmd: erl starts it on first use, on that port.
stop() removes it at exit; a refusal (nodes still registered) leaves it for
the runner's own orphan cleanup, which is now the only job that can see it.

An ERL_EPMD_PORT already in the environment is an operator's own isolation (a
per-runner .env, or a developer debugging against a shared epmd) and wins
untouched.

The decision (pick_port) is pure; the OS (port_is_free, stop) is a thin shell
with injectable seams. Pinned by tests/test_gateway_epmd.py.
"""
import random
import shutil
import socket
import subprocess

# Below every supported OS's ephemeral range (Linux 32768+, Windows/macOS
# 49152+), so an outgoing connection's source port can never take it.
PORT_RANGE = (21000, 29999)
_MAX_TRIES = 20
_KILL_TIMEOUT_SECS = 10


def pick_port(is_free, rng=random):
    """First free port among _MAX_TRIES random candidates, else None."""
    for _ in range(_MAX_TRIES):
        port = rng.randint(*PORT_RANGE)
        if is_free(port):
            return port
    return None


def port_is_free(port):
    """True when nothing listens on `port`. No SO_REUSEADDR on purpose: a bind
    that would share a live listener must fail on every platform."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("", port))
        except OSError:
            return False
    return True


def isolate(env, pick=pick_port, is_free=port_is_free):
    """Point `env` at a run-private epmd port; return it as a string.

    Returns None, leaving `env` alone, when the run keeps the epmd it had: an
    explicit ERL_EPMD_PORT (operator isolation), or no free port found (the
    run falls back to the shared epmd, exactly as before this existed).
    """
    if env.get("ERL_EPMD_PORT"):
        return None
    port = pick(is_free)
    if port is None:
        return None
    env["ERL_EPMD_PORT"] = str(port)
    return str(port)


def stop(port, env, which=shutil.which, run=subprocess.run):
    """Best-effort `epmd -port <port> -kill`. Never raises: it runs at exit,
    where a failure has nobody left to report to. Returns True when the kill
    was attempted."""
    try:
        epmd = which("epmd", path=env.get("PATH"))
        if not epmd:
            return False
        run([epmd, "-port", str(port), "-kill"], env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=_KILL_TIMEOUT_SECS, check=False)
        return True
    except Exception:  # noqa: BLE001 - exit-time cleanup, never fatal
        return False
