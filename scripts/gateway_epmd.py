#!/usr/bin/env python3
r"""Run-private epmd for the gateway test wrapper (#4853).

The multinode eunit modules boot Erlang distribution and `peer` nodes through
the host's one epmd (port 4369). On a shared self-hosted box a finishing job's
orphan cleanup kills that epmd under every concurrent job, and their next
`peer:start_link` times out (the incident and its evidence: the #4853 row of
docs/erlang-gateway-build.md). isolate() gives each wrapper run its own port
through ERL_EPMD_PORT; every VM the run starts inherits it, erl starts the
epmd there on first use, and stop() removes it at exit. An ERL_EPMD_PORT
already in the environment is the operator's own isolation and wins untouched.

The decision (pick_port) is pure; the OS (port_is_free, stop) is a thin shell
with injectable seams. Pinned by tests/test_gateway_epmd.py.
"""
import atexit
import glob
import os
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


def isolate(env, is_free=port_is_free, rng=random):
    """Point `env` at a run-private epmd port; return it as a string.

    Returns None, leaving `env` alone, when the run keeps the epmd it had: an
    explicit ERL_EPMD_PORT (operator isolation), or no free port found (the
    run falls back to the shared epmd, exactly as before this existed).
    """
    if env.get("ERL_EPMD_PORT"):
        return None
    port = pick_port(is_free, rng)
    if port is None:
        return None
    env["ERL_EPMD_PORT"] = str(port)
    # The epmd erl auto-starts here inherits this: without it `epmd -kill` is
    # refused while any node is still registered (a leaked peer), and the
    # run's epmd would outlive it.
    env.setdefault("ERL_EPMD_RELAXED_COMMAND_CHECK", "1")
    return str(port)


def find_epmd(env, which=shutil.which, glob_=glob.glob):
    """The epmd on `env`'s PATH, else the one inside the OTP install that PATH's
    erl belongs to: Windows OTP keeps epmd.exe only under <root>/erts-<vsn>/bin,
    never in <root>/bin (where erlexec finds it, and PATH does not)."""
    path = env.get("PATH")
    found = which("epmd", path=path)
    if found:
        return found
    erl = which("erl", path=path)
    if not erl:
        return None
    root = os.path.dirname(os.path.dirname(os.path.realpath(erl)))
    # Exact names: a bare `epmd*` also matches epmd.pdb in a Windows install.
    hits = sorted(hit for name in ("epmd", "epmd.exe")
                  for hit in glob_(os.path.join(root, "erts-*", "bin", name)))
    return hits[-1] if hits else None


def stop(port, env, which=shutil.which, run=subprocess.run, glob_=glob.glob):
    """Best-effort `epmd -port <port> -kill`. Never raises: it runs at exit,
    where a failure has nobody left to report to. Returns True when the kill
    was attempted."""
    try:
        epmd = find_epmd(env, which, glob_)
        if not epmd:
            return False
        run([epmd, "-port", str(port), "-kill"], env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=_KILL_TIMEOUT_SECS)
        return True
    except Exception:  # noqa: BLE001 - exit-time cleanup, never fatal
        return False


def activate(env, register=atexit.register, say=print, isolate_=isolate):
    """What the wrapper does with the run's env: isolate it, say which epmd the
    run uses (the one thing a reader of a red log needs), and register the exit
    cleanup for a port this run owns. Returns the owned port or None."""
    explicit = env.get("ERL_EPMD_PORT")
    port = isolate_(env)
    if port:
        say(f"[test_gateway.py] run-private epmd: ERL_EPMD_PORT={port}", flush=True)
        register(stop, port, env)
    elif explicit:
        say(f"[test_gateway.py] epmd: using ERL_EPMD_PORT={explicit} from the environment", flush=True)
    else:
        say("[test_gateway.py] epmd: no free private port found, using the shared epmd "
            "(#4853 can recur)", flush=True)
    return port
