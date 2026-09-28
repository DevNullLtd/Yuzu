#!/usr/bin/env python3
"""Build the Erlang gateway using rebar3.

Used by Meson custom_target because Ninja quotes compound shell commands
(e.g. 'cd /d path && rebar3 compile') as a single argument, which breaks
cmd.exe on Windows.  This script works on all platforms.

Toolchain resolution, the Windows hazards (the MSYS2 temp dir, console
stdio, invisible git prompts) and the process-tree kill are shared with
test_gateway.py through erlang_toolchain.py - handle them there, not here.

On Windows the child never touches an inherited stdio handle: its merged
stdout+stderr go to a pipe this wrapper relays to its own stdout and tees to
<build dir>/meson-logs/yuzu_gateway_build.log. An IDE-launched Ninja (CLion)
can hand its children handles the Erlang VM cannot write to; without the pipe
the VM dies on its first write ("Writer crashed ('The handle is invalid.')",
exit 127) having printed nothing anywhere.
"""
import os
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from erlang_toolchain import (  # noqa: E402
    base_env,
    kill_tree,
    rebar3_prefix,
    windows_stdio_isolation,
)

LOG_NAME = "yuzu_gateway_build.log"
EXIT_TIMEOUT = 124  # conventional timeout exit code (matches GNU `timeout`)
_POLL_SECS = 0.25
_RELAY_JOIN_SECS = 30
_REAP_SECS = 30


def _say(stream, text):
    """Best-effort diagnostic line. A broken or missing stream - the IDE case
    this wrapper exists for - must never abort the build or skip a kill.

    A stream that fails is detached from sys, so the interpreter's shutdown
    flush of its leftover buffer cannot fail too and replace our exit code
    with 120.
    """
    try:
        stream.write(text + "\n")
        stream.flush()
    except (AttributeError, OSError, ValueError):
        for name in ("stdout", "stderr"):
            if getattr(sys, name, None) is stream:
                setattr(sys, name, None)


def build_timeout(environ):
    """Bound on the rebar3 compile, in seconds.

    A hung gateway build must fail fast instead of burning the whole CI job's
    timeout (a stuck dep fetch or an orphaned erl.exe/epmd.exe holding a lock
    once silently ate 120 min). Default 15 min; override with
    YUZU_GATEWAY_BUILD_TIMEOUT (seconds; 0 or negative disables).
    """
    try:
        return int(environ.get("YUZU_GATEWAY_BUILD_TIMEOUT", "900"))
    except ValueError:
        return 900


def open_build_log(log_dir):
    """Create <log_dir>/yuzu_gateway_build.log for this run.

    Returns (path, fd), or (None, None) when there is nowhere to write.

    The safety of the path rests on WHERE it is, not on how it is opened:
    log_dir is the build tree's meson-logs/, inside the build owner's own
    trust domain (anyone who can plant files there can already edit
    build.ninja). It used to be a fixed name in a shared temp dir, opened with
    a plain "wb", which let another local user redirect a SYSTEM-context
    build's write through a planted symlink. The open is still defensive: an
    existing file or planted link is unlinked rather than written through,
    and O_EXCL refuses a regular file or live link re-created in between.
    That is best-effort, not a guarantee: O_NOFOLLOW exists only on POSIX, so
    on Windows a DANGLING link re-planted in that window is followed.

    If the previous log cannot be removed (Windows: another process holds it
    open without delete sharing), this run logs to a fresh uniquely-named
    yuzu_gateway_build.<random>.log beside it instead (mkstemp, itself
    O_EXCL), so the stale log is never mistaken for this run's. Those
    fallback files are not cleaned up; a build-dir wipe removes them.
    """
    if not log_dir or not os.path.isdir(log_dir):
        return None, None
    path = os.path.join(log_dir, LOG_NAME)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        stem, ext = os.path.splitext(LOG_NAME)
        try:
            fd, path = tempfile.mkstemp(prefix=stem + ".", suffix=ext, dir=log_dir)
        except OSError:
            return None, None
        return path, fd
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        return path, os.open(path, flags, 0o644)
    except OSError:
        return None, None


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _close_fd(fd):
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass


class Relay:
    """Drain the child's merged stdout+stderr to our stdout and the log.

    Writes go through os.write on raw fds, never sys.stdout: a daemon thread
    blocked inside a BufferedWriter holds its lock, which wedges (or fatally
    aborts) interpreter shutdown when the sink stops reading. The cost is that
    a raw write to an interactive Windows console skips Python's UTF-16
    console translation, so non-ASCII output shows in the console's OEM code
    page there (pipes - CI, IDEs - and the log get the exact bytes). A failing
    sink is dropped and the drain continues - a stalled drain fills the pipe
    and blocks the child. If reading itself fails the pipe is closed, so the
    child gets a broken pipe instead of blocking on a full one.
    """

    def __init__(self, src, out_fd, log_fd):
        self._src = src
        self._out_fd = out_fd
        self._log_fd = log_fd
        self.log_complete = log_fd is not None
        self.read_error = None
        # True while a write to OUR stdout is in progress, so a stall can be
        # blamed on whoever stopped reading it rather than on the child.
        self.writing_stdout = False
        self._thread = threading.Thread(
            target=self._run, name="build_gateway-relay", daemon=True
        )

    def start(self):
        self._thread.start()

    def join(self, timeout):
        """True once the child's output has been fully drained."""
        self._thread.join(timeout)
        return not self._thread.is_alive()

    def close_log(self):
        """Release the log fd. Only for a relay whose thread never started."""
        _close_fd(self._log_fd)
        self._log_fd = None

    def _run(self):
        try:
            while True:
                try:
                    chunk = self._src.read1(65536)
                except (OSError, ValueError) as exc:
                    self.read_error = exc
                    self.log_complete = False
                    break
                if not chunk:
                    break
                if self._log_fd is not None:
                    try:
                        _write_all(self._log_fd, chunk)
                    except OSError:
                        self.log_complete = False
                        self.close_log()
                if self._out_fd is not None:
                    self.writing_stdout = True
                    try:
                        _write_all(self._out_fd, chunk)
                    except OSError:
                        self._out_fd = None
                    finally:
                        self.writing_stdout = False
        finally:
            self.close_log()
            try:
                self._src.close()
            except (OSError, ValueError):
                pass


def _stdout_fd():
    try:
        sys.stdout.flush()
        return sys.stdout.fileno()
    except (AttributeError, OSError, ValueError):
        return None


def _reap(proc):
    try:
        proc.wait(timeout=_REAP_SECS)
    except subprocess.TimeoutExpired:
        pass


def _kill_and_reap(proc):
    """Kill the whole child tree (rebar3 -> escript -> erl -> beam; a bare
    proc.kill() orphans the grandchildren, the very _build lock-holders the
    timeout exists to clear), then reap the root even if a Ctrl-C arrived
    mid-kill. Returns kill_tree's verdict."""
    try:
        return kill_tree(proc, _REAP_SECS)
    finally:
        _reap(proc)


def _kill_note(killed):
    if killed:
        return "killed the process tree"
    return "tried to kill the process tree (the kill reported failure; some processes may survive)"


def _wait(proc, timeout_s):
    """Wait for proc in short slices; None once timeout_s has passed.

    Never a single blocking Popen.wait(): on Windows it cannot be interrupted,
    and the child's private console never sees the keypress, so Ctrl-C would
    otherwise hang until the build finished or timed out.
    """
    deadline = time.monotonic() + timeout_s if timeout_s > 0 else None
    while True:
        try:
            return proc.wait(timeout=_POLL_SECS)
        except subprocess.TimeoutExpired:
            if deadline is not None and time.monotonic() >= deadline:
                return None


def describe_exit(returncode):
    if sys.platform == "win32":
        return f"code {returncode} (0x{returncode & 0xFFFFFFFF:08X})"
    if returncode < 0:
        return f"signal {-returncode}"
    return f"code {returncode}"


def _log_hint(log_path, relay, drained):
    if not log_path or relay is None:
        return ""
    if relay.log_complete and drained:
        return f"\n  full child output: {log_path}"
    return f"\n  partial child output: {log_path}"


def run_build(cmd, cwd, env, timeout_s, log_dir, relay_output=None):
    """Run cmd under the timeout; return the wrapper's exit code.

    relay_output (default: on Windows only) routes the child's output through
    the pipe + Relay described in the module docstring.
    """
    if relay_output is None:
        relay_output = sys.platform == "win32"
    popen_kwargs = {"cwd": cwd, "env": env}
    popen_kwargs.update(windows_stdio_isolation())
    if sys.platform != "win32":
        # New session so the whole tree shares a process group we can signal.
        popen_kwargs["start_new_session"] = True
    log_path = log_fd = None
    if relay_output:
        popen_kwargs["stdout"] = subprocess.PIPE
        popen_kwargs["stderr"] = subprocess.STDOUT
        log_path, log_fd = open_build_log(log_dir)
        if log_fd is None and log_dir and os.path.isdir(log_dir):
            _say(sys.stderr, f"build_gateway: could not create a build log in "
                 f"{log_dir}; output goes to the console only.")

    _say(sys.stdout, f"build_gateway: running {cmd!r} in {cwd}")
    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
    except OSError as exc:
        _close_fd(log_fd)
        _say(sys.stderr, f"build_gateway: could not launch child: {exc}")
        return 1

    relay = None
    try:
        if proc.stdout is not None:
            relay = Relay(proc.stdout, _stdout_fd(), log_fd)
            relay.start()
            log_fd = None  # the relay thread owns it now
        returncode = _wait(proc, timeout_s)
    except KeyboardInterrupt:
        killed = _kill_and_reap(proc)
        _say(sys.stderr, f"build_gateway: interrupted - {_kill_note(killed)}.")
        raise
    except BaseException:
        _kill_and_reap(proc)
        raise
    finally:
        if log_fd is not None:
            if relay is not None:
                relay.close_log()
            else:
                _close_fd(log_fd)

    if returncode is None:
        # Kill FIRST: a broken or blocked stderr must never leave the tree
        # (and its _build locks) alive.
        killed = _kill_and_reap(proc)
        drained = relay.join(5) if relay else True
        if relay is not None and relay.writing_stdout:
            cause = ("  Our own stdout stopped being read (a paused console or a "
                     "stalled log consumer), which backed up the child's output.")
        else:
            cause = ("  Likely a hung dep fetch or an orphaned erl.exe/epmd.exe "
                     "holding a lock; see docs/erlang-gateway-build.md.")
        _say(
            sys.stderr,
            f"\nbuild_gateway: rebar3 compile exceeded {timeout_s}s "
            f"(YUZU_GATEWAY_BUILD_TIMEOUT); {_kill_note(killed)}.\n"
            f"  cmd: {cmd}\n" + cause + _log_hint(log_path, relay, drained),
        )
        return EXIT_TIMEOUT

    drained = relay.join(_RELAY_JOIN_SECS) if relay else True
    if not drained:
        if relay.writing_stdout:
            why = "our own stdout stopped being read"
        else:
            why = "a process outside the rebar3 tree still holds the pipe"
        _say(
            sys.stderr,
            f"build_gateway: output still draining {_RELAY_JOIN_SECS}s after "
            f"rebar3 exited ({why}); the tail of the output may be missing.",
        )
    if returncode:
        _say(
            sys.stderr,
            f"build_gateway: child exited with {describe_exit(returncode)}; "
            f"command: {cmd!r}" + _log_hint(log_path, relay, drained),
        )
    return returncode


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    gateway_dir = argv[0]
    cmd = rebar3_prefix() + ["compile"]
    # Ninja runs custom_target commands from the build directory, so the log
    # lands in <build dir>/meson-logs/ - beside Meson's own logs, and in the
    # tree ci.yml's Windows leg uploads on failure.
    log_dir = os.path.join(os.getcwd(), "meson-logs")
    return run_build(cmd, gateway_dir, base_env(), build_timeout(os.environ), log_dir)


if __name__ == "__main__":
    sys.exit(main())
