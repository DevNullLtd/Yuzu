#!/usr/bin/env python3
r"""Shared Erlang toolchain resolution for the Meson gateway wrappers.

Both build_gateway.py and test_gateway.py invoke rebar3 from Meson on every
platform, and both must handle these Windows-specific hazards *identically* —
when they drift, things break. (They did: build_gateway.py was de-hardcoded
in #1606, test_gateway.py was not, so gateway ct/eunit failed with
FileNotFoundError [WinError 2] on the Wee Tam runners while the build passed.)

  1. `subprocess.run(["rebar3", ...])` cannot exec a bare/extensionless
     `rebar3` or a `.CMD` shim on Windows — CreateProcess does not apply
     PATHEXT to the program name — so it raises FileNotFoundError [WinError 2]
     even though `rebar3` is on PATH. Resolve the real escript + rebar3
     escript (the proven `<escript.exe> <rebar3-escript> ...` invocation,
     which also bypasses the choco shim / OTP launcher-stub segfault), and
     fall back to a shutil.which() launcher path *with* its extension.

  2. MSYS2 exports TEMP/TMP=/tmp, which native programs resolve to the bogus
     UNC path \\tmp\. On a cold _build, rebar3's gpb-plugin install then runs
     `robocopy /move \\tmp\... <dest>` and hangs ~forever retrying a
     nonexistent SMB host. Force a real native temp dir, and set TMPDIR too
     (rebar3's system_tmpdir() reads ["TMPDIR","TEMP","TMP"] in that order).

  3. An IDE-launched Ninja (CLion) can hand its children stdio handles the
     Erlang VM cannot use: it dies writing its first line ("Writer crashed
     ('The handle is invalid.')", exit 127) before printing anything. The
     load-bearing fix is that the child's stdout/stderr go to a PIPE the
     wrapper owns, never an inherited handle — both wrappers read their
     child through a pipe. `windows_stdio_isolation()` adds the other half:
     null stdin and a private console (CREATE_NO_WINDOW), so no inherited
     console handle is ever touched.

     Do NOT add `-noinput` to ERL_FLAGS here. ERL_FLAGS reaches every VM
     rebar3 starts, including `peer` nodes started with
     `connection => standard_io` (yuzu_gw_cluster_formation_multinode_tests),
     and `-noinput` breaks those: `peer:call` times out. It also turns any
     stdin read into a crash that kills all later output, where null stdin
     alone just returns eof.

  4. That private console is invisible, so anything that prompts on it — a
     git credential prompt while rebar3 fetches a git dependency on a cold
     _build (a 401, an authenticating proxy) — would block unseen until the
     wrapper's deadline. `base_env()` sets GIT_TERMINAL_PROMPT=0 and
     GCM_INTERACTIVE=never so such a fetch fails fast and visibly instead.

Resolution precedence mirrors the runner provisioning contract — see
deploy/windows/Provision-Windows-Runner.ps1 + toolchain-manifest.json.
"""
import glob
import os
import shutil
import signal
import subprocess
import sys
import tempfile


def rebar3_prefix():
    """Return the argv prefix that runs rebar3 portably.

    Callers append their own subcommand, e.g.
        rebar3_prefix() + ["compile"]
        rebar3_prefix() + ["as", "test", "eunit", "--dir", "..."]
    On non-Windows this is just ["rebar3"]; on Windows it resolves the real
    escript + rebar3 escript (or a which()-resolved launcher with extension).
    Exits 1 with an actionable message if the toolchain can't be located.
    """
    if sys.platform != "win32":
        return ["rebar3"]

    def _env_file(*names):
        for n in names:
            v = os.environ.get(n)
            if v and os.path.isfile(v):
                return v
        return None

    escript = _env_file("YUZU_ESCRIPT", "ESCRIPT")
    if not escript:
        roots = [r"C:\Erlang"]
        roots += glob.glob(r"C:\Program Files\Erlang*")
        roots += glob.glob(r"C:\Program Files\erl*")
        candidates = []
        for root in roots:
            candidates += sorted(
                glob.glob(os.path.join(root, "erts-*", "bin", "escript.exe")),
                reverse=True,
            )
            candidates.append(os.path.join(root, "bin", "escript.exe"))
        escript = next((c for c in candidates if os.path.isfile(c)), None)
    if not escript:
        escript = shutil.which("escript")

    rebar3_escript = _env_file("YUZU_REBAR3", "REBAR3")
    if not rebar3_escript:
        rebar3_escript = next(
            (
                c
                for c in (
                    r"C:\tools\rebar3\rebar3",
                    r"C:\ProgramData\chocolatey\lib\rebar3\tools\rebar3",
                )
                if os.path.isfile(c)
            ),
            None,
        )

    if escript and rebar3_escript:
        return [escript, rebar3_escript]

    # Last resort: a PATH-resolved launcher WITH its extension (.cmd/.bat),
    # which subprocess CAN exec — a bare "rebar3" cannot.
    launcher = shutil.which("rebar3")
    if launcher:
        return [launcher]

    sys.stderr.write(
        "erlang_toolchain: could not locate the Erlang toolchain on Windows.\n"
        "  Set YUZU_ESCRIPT and YUZU_REBAR3 (see "
        "deploy/windows/toolchain-manifest.json), or put escript.exe and\n"
        "  rebar3 on PATH.\n"
        f"  escript={escript!r} rebar3={rebar3_escript!r} "
        f"which(rebar3)={shutil.which('rebar3')!r}\n"
    )
    sys.exit(1)


def base_env():
    """A copy of os.environ with a sane native temp dir on Windows.

    Prefer RUNNER_TEMP (guaranteed-native, per-runner, e.g. D:\\ci\\work-N\\
    _temp); validate it's a real drive-letter dir (never trust a "/tmp" that
    tempfile.gettempdir() may echo back); set TEMP/TMP/TMPDIR. Also turns
    off interactive git credential prompts (hazard 4 above). No-op off
    Windows (returns a plain os.environ copy).
    """
    env = os.environ.copy()
    if sys.platform == "win32":
        real_temp = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
        if not (len(real_temp) >= 2 and real_temp[1] == ":" and os.path.isdir(real_temp)):
            real_temp = os.path.join(os.environ.get("LOCALAPPDATA", r"C:\Windows"), "Temp")
            os.makedirs(real_temp, exist_ok=True)
        env["TEMP"] = real_temp
        env["TMP"] = real_temp
        env["TMPDIR"] = real_temp
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GCM_INTERACTIVE"] = "never"
    return env


def windows_stdio_isolation():
    """Popen kwargs that keep a rebar3 child off the caller's console.

    Null stdin plus a private console (CREATE_NO_WINDOW) — hazard 3 above.
    The caller must ALSO give the child a stdout/stderr pipe it owns; that
    pipe is the part that actually fixes the IDE failure. A caller needing
    other creation flags ORs them in. Empty dict off Windows.
    """
    if sys.platform != "win32":
        return {}
    return {
        "stdin": subprocess.DEVNULL,
        "creationflags": subprocess.CREATE_NO_WINDOW,
    }


def _signal_tree(proc, timeout):
    """One attempt at killing proc's whole tree. True if it reported success."""
    if sys.platform == "win32":
        # By absolute path (never a taskkill.exe planted in the cwd); in its
        # own process group, so a second console Ctrl-C cannot kill taskkill
        # halfway through the walk; bounded, so a wedged taskkill cannot
        # re-open the unbounded wait a caller's deadline exists to close.
        taskkill = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe"
        )
        try:
            result = subprocess.run(
                [taskkill, "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0
    try:
        # The group id IS the root's pid (start_new_session), so this still
        # reaches the group after the root itself has been reaped, where
        # os.getpgid(proc.pid) would fail and strand the survivors.
        os.killpg(proc.pid, signal.SIGKILL)
        return True
    except OSError:
        return False


def kill_tree(proc, timeout=30):
    """Kill a wrapper's rebar3 child and every descendant (escript, erl, beam).

    Returns True when the tree kill reported success; False means some
    descendants may have survived (the caller should say so, never claim a
    clean kill). POSIX callers must have started the child with
    start_new_session=True so the tree is one process group.

    The root is killed LAST: taskkill /T walks the tree from the root, so a
    root killed first strands every descendant. A Ctrl-C arriving mid-kill
    (an impatient second press) retries the walk, up to three attempts, and
    is re-raised afterwards. Shared by both wrappers so their kill paths
    cannot drift apart again.
    """
    interrupted = False
    ok = False
    try:
        for _ in range(3):
            try:
                ok = _signal_tree(proc, timeout)
                break
            except KeyboardInterrupt:
                interrupted = True
    finally:
        try:
            proc.kill()
        except OSError:
            pass
    if interrupted:
        raise KeyboardInterrupt
    return ok
