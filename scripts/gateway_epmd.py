#!/usr/bin/env python3
r"""Run-private epmd for the gateway test wrapper (#4853).

The multinode eunit modules boot Erlang distribution and `peer` nodes through
the host's one epmd (port 4369). On a shared self-hosted box a finishing job's
orphan cleanup kills that epmd under every concurrent job, and their next
`peer:start_link` times out (the incident and its evidence: the #4853 row of
docs/erlang-gateway-build.md). isolate() gives each wrapper run its own port
through ERL_EPMD_PORT; every VM the run starts inherits it, erl starts the
epmd there on first use, and stop() asks it to exit when the wrapper does (epmd
refuses while a node is still registered; the runner's orphan cleanup then
reaps it). An ERL_EPMD_PORT already in the environment is the operator's own
isolation and wins untouched.

The decision (pick_port) is pure; the OS (port_is_free, stop) is a thin shell
with injectable seams. Pinned by tests/test_gateway_epmd.py.
"""
import atexit
import errno
import glob
import os
import re
import shutil
import socket
import subprocess

# Below every default ephemeral range (Linux 32768+, Windows/macOS 49152+), so
# an outgoing connection's source port does not take it. The span (8999) is
# PRIME on purpose: pid % span then reaches every start port even for Windows
# pids, which are multiples of 4 (a span of 9000 reached a quarter of them).
PORT_RANGE = (21000, 29998)
# Coprime with the span. A scan steps over a run of unusable ports (a Windows
# excluded-port block) instead of crawling through it one port at a time.
_SCAN_STRIDE = 101
_MAX_TRIES = 20
_KILL_TIMEOUT_SECS = 5
# A host without IPv6 raises one of these opening or binding the v6 probe.
_NO_IPV6 = (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL)


def pick_port(is_free, pid=os.getpid):
    """First free port on a scan that starts at a port derived from this
    process's id, else None. epmd binds long after the probe (once the first
    distributed node starts), so two runs choosing the same free port would end
    up sharing one epmd. Concurrent runs have distinct pids and so start at
    distinct ports (the prime span makes that hold for any pid stride), and the
    scan stride keeps their paths apart afterwards.
    Accepted residual: two live pids a whole number of spans apart start at the
    same port, a busy start port can move one scan onto the other's path, and the
    probe cannot see an epmd that has not bound yet. Sharing is then the
    pre-change state for that pair, not a new failure."""
    span = PORT_RANGE[1] - PORT_RANGE[0] + 1
    start = pid() % span
    for i in range(_MAX_TRIES):
        port = PORT_RANGE[0] + (start + i * _SCAN_STRIDE) % span
        if is_free(port):
            return port
    return None


def port_is_free(port):
    """True when nothing listens on `port` on IPv4 or IPv6: epmd binds both, and
    a holder on either stack makes it start nowhere, without saying so. No
    SO_REUSEADDR on purpose: a bind that would share a live listener must fail
    on every platform. A probe that cannot run at all counts as not free, so a
    restricted host falls back to the shared epmd instead of aborting the run;
    a host with no IPv6 has nothing to hold the port there."""
    for family, host in ((socket.AF_INET, ""), (socket.AF_INET6, "::")):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                if family == socket.AF_INET6:
                    probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                probe.bind((host, port))
        except OSError as exc:
            if family == socket.AF_INET6 and exc.errno in _NO_IPV6:
                continue
            return False
    return True


def isolate(env, is_free=port_is_free, pid=os.getpid):
    """Point `env` at a run-private epmd port; return it as a string.

    Returns None, leaving `env` alone, when the run keeps the epmd it had: an
    explicit ERL_EPMD_PORT (operator isolation), or no free port found (the
    run falls back to the shared epmd, exactly as before this existed).

    The epmd erl later starts on that port keeps its default strict kill check
    on purpose: `epmd -kill` is refused while any node is registered, so this
    run's exit-time cleanup does not take down an epmd that another run, which
    shares the port by the residual pick_port accepts, still has nodes on. (An
    epmd with no node registered yet is not protected; that is the same
    residual.) A leaked peer only leaves this run's own epmd to the runner.
    """
    if env.get("ERL_EPMD_PORT"):
        return None
    port = pick_port(is_free, pid)
    if port is None:
        return None
    env["ERL_EPMD_PORT"] = str(port)
    return str(port)


def find_epmd(env, which=shutil.which, glob_=glob.glob):
    """The epmd on `env`'s PATH, else the one inside the OTP install that PATH's
    erl belongs to: Windows OTP keeps epmd.exe only under <root>/erts-<vsn>/bin
    (where erlexec looks for it); PATH holds only <root>/bin, which has none."""
    path = env.get("PATH")
    found = which("epmd", path=path)
    if found:
        return found
    erl = which("erl", path=path)
    if not erl:
        return None
    root = os.path.dirname(os.path.dirname(os.path.realpath(erl)))
    # Exact names: a bare `epmd*` also matches epmd.pdb in a Windows install.
    # The root is escaped: a `[` or `*` in an install path is a path, not a pattern.
    hits = [hit for name in ("epmd", "epmd.exe")
            for hit in glob_(os.path.join(glob.escape(root), "erts-*", "bin", name))]
    return max(hits, key=_erts_version) if hits else None


def _erts_version(path):
    """(16, 3, 1) for .../erts-16.3.1/bin/epmd.exe, so erts-16 outranks erts-9.
    Read from the erts directory's own name, not the whole path, so an install
    root that itself contains `erts-<digits>` cannot tie every hit."""
    m = re.fullmatch(r"erts-([0-9]+(?:\.[0-9]+)*)", os.path.basename(os.path.dirname(os.path.dirname(path))))
    return tuple(int(part) for part in m.group(1).split(".")) if m else ()


def stop(port, env, which=shutil.which, run=subprocess.run, glob_=glob.glob, say=print,
         is_free=port_is_free):
    """Best-effort `epmd -port <port> -kill`. Never raises: it runs at exit,
    where nobody can catch an exception. Returns True when nothing is left to
    stop: epmd accepted the kill, or nothing listens on the port (a `ct` run
    starts no distribution, so no epmd was ever started). Otherwise (no epmd
    found, a hung or failed call, or a refusal because a node is still
    registered) it says that the run's epmd may still be running, with the
    command that removes it: nothing else reports it, and on a host with no
    runner to reap it the epmd and its port would stay until someone does."""
    epmd = None
    try:
        if is_free(int(port)):  # the wrapper registers the port as the string it set in env
            return True
        epmd = find_epmd(env, which, glob_)
        stopped = bool(epmd) and run(
            [epmd, "-port", str(port), "-kill"], env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=_KILL_TIMEOUT_SECS).returncode == 0
    except Exception:  # noqa: BLE001 - exit-time cleanup, never fatal
        stopped = False
    if not stopped:
        command = f'"{epmd}"' if epmd else "epmd"  # Windows keeps epmd.exe off PATH
        try:
            say(f"[test_gateway.py] the run-private epmd on port {port} may still be running; "
                f"stop it with: {command} -port {port} -kill", flush=True)
        except Exception:  # noqa: BLE001 - a closed stdout at exit has nobody left to tell either
            pass
    return stopped


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
        say("[test_gateway.py] epmd: no usable private port found, using the shared epmd "
            "(another job's cleanup can kill it, #4853)", flush=True)
    return port
