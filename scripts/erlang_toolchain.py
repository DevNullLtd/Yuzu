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


# ── OTP version pin ─────────────────────────────────────────────────────────
# The oldest OTP release the gateway is built and tested against, as a floor
# WITHIN its major: "28.4" accepts 28.4, 28.4.2, 28.5.0.7 and any later 28.x,
# never 28.3 or 29.x (a new major is a deliberate migration, not a drift).
# That one rule covers every pinned toolchain today - the Windows runner
# contract (28.4.2, deploy/windows/toolchain-contract.json), the macOS CI
# download (28.5.0.7, ci.yml) and setup-beam's otp-version '28' (latest 28.x,
# ci.yml and release.yml) - while refusing the Homebrew `erlang` 29 that a
# shell can put first on PATH. YUZU_OTP_VERSION overrides it for a one-off;
# there is deliberately no Meson option, because a non-default option stored
# in a branch-shared CI build dir breaks every older branch's --reconfigure
# (see require_gateway in meson.build).
DEFAULT_OTP_VERSION = "28.4"


def wanted_otp_version():
    """The pinned OTP version: YUZU_OTP_VERSION if set, else the default."""
    return os.environ.get("YUZU_OTP_VERSION") or DEFAULT_OTP_VERSION


def _exe(name):
    return name + ".exe" if sys.platform == "win32" else name


def probe_install(bin_dir):
    """(canonical_bin, version) of the OTP install that bin_dir's erl runs.

    Reads <root>/releases/<major>/OTP_VERSION, which every OTP install ships
    (kerl, asdf, mise, Homebrew, distro packages, the Windows installer), so
    usually no VM is started. The root is two levels above the real erl
    binary: Homebrew's bin/erl is a symlink into lib/erlang/bin/, kerl's is a
    script beside its releases/.

    A launcher SHIM directory (Chocolatey's C:\\ProgramData\\chocolatey\\bin,
    Scoop's shims) has no releases/ beside it, so the erl there is asked for
    code:root_dir() and the install's own <root>/bin is returned instead of the
    shim dir. That matters: rebar3 must never run through the Chocolatey
    escript shim (the launcher-stub segfault this module's rebar3_prefix
    exists to avoid), and YUZU_OTP_BIN goes first on PATH. (None, None) if
    bin_dir has no working erl.
    """
    erl = os.path.join(bin_dir, _exe("erl"))
    if not os.path.isfile(erl):
        return None, None
    roots = [os.path.dirname(os.path.dirname(os.path.realpath(erl))),
             os.path.dirname(os.path.abspath(bin_dir))]
    for root in roots:
        for path in sorted(glob.glob(os.path.join(root, "releases", "*", "OTP_VERSION"))):
            try:
                with open(path, encoding="ascii", errors="replace") as f:
                    v = f.read().strip()
            except OSError:
                continue
            if v:
                return bin_dir, v
    try:
        out = subprocess.run(
            [erl, "-noshell", "-eval",
             'R=code:root_dir(),'
             'F=filename:join([R,"releases",erlang:system_info(otp_release),"OTP_VERSION"]),'
             '{ok,B}=file:read_file(F),io:format("~s~n~s",[R,B]),halt().'],
            capture_output=True, text=True, timeout=60,
            **windows_stdio_isolation(),
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    lines = out.stdout.strip().splitlines()
    if out.returncode != 0 or len(lines) < 2 or not lines[1].strip():
        return None, None
    real_bin = os.path.join(lines[0].strip(), "bin")
    canonical = real_bin if os.path.isfile(os.path.join(real_bin, _exe("erl"))) else bin_dir
    return canonical, lines[1].strip()


def otp_version(bin_dir):
    """The full OTP version ("28.4.2") that bin_dir's erl runs, or None."""
    return probe_install(bin_dir)[1]


def _version_key(v):
    return tuple(int(p) if p.isdigit() else 0 for p in v.split("."))


def version_matches(found, wanted):
    """True when found is wanted or later, within wanted's major.

    "28.4" accepts "28.4", "28.4.2", "28.5.0.7", "28.40"; rejects "28.3.9",
    "29.1.1". "28" accepts any 28.x. Components compare numerically.
    """
    if not found or not wanted:
        return False
    f, w = _version_key(found), _version_key(wanted)
    return f[0] == w[0] and f >= w


def _kerl_installations():
    """Install dirs from `kerl list installations` plus kerl's own dirs.

    kerl need not be on PATH for its installs to be usable, so the default
    locations are scanned too (KERL_BASE_DIR, ~/.kerl).
    """
    dirs = []
    if shutil.which("kerl"):
        try:
            out = subprocess.run(["kerl", "list", "installations"],
                                 capture_output=True, text=True, timeout=30)
            for line in out.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    dirs.append(parts[1])
        except (OSError, subprocess.SubprocessError):
            pass
    for base in (os.environ.get("KERL_DEFAULT_INSTALL_DIR"),
                 os.environ.get("KERL_BASE_DIR"),
                 os.path.expanduser("~/.kerl")):
        if base:
            dirs += glob.glob(os.path.join(base, "*"))
            dirs += glob.glob(os.path.join(base, "installs", "*"))
    return dirs


def otp_candidates():
    """(source, bin_dir) for every OTP install found, in precedence order.

    YUZU_OTP_BIN (explicit) first, then the erl already on PATH, then version
    managers and well-known install locations. Duplicates (same real erl) are
    dropped, keeping the first.
    """
    found = []

    def add(source, bin_dir):
        if bin_dir and os.path.isfile(os.path.join(bin_dir, _exe("erl"))):
            found.append((source, os.path.abspath(bin_dir)))

    add("YUZU_OTP_BIN", os.environ.get("YUZU_OTP_BIN"))
    on_path = shutil.which("erl")
    if on_path:
        add("PATH", os.path.dirname(on_path))
    for d in _kerl_installations():
        add("kerl", os.path.join(d, "bin"))
    asdf = os.environ.get("ASDF_DATA_DIR") or os.path.expanduser("~/.asdf")
    for d in sorted(glob.glob(os.path.join(asdf, "installs", "erlang", "*"))):
        add("asdf", os.path.join(d, "bin"))
    mise = os.environ.get("MISE_DATA_DIR") or os.path.expanduser("~/.local/share/mise")
    for d in sorted(glob.glob(os.path.join(mise, "installs", "erlang", "*"))):
        add("mise", os.path.join(d, "bin"))
    if sys.platform == "win32":
        if os.environ.get("ERLANG_HOME"):
            add("ERLANG_HOME", os.path.join(os.environ["ERLANG_HOME"], "bin"))
        for root in ([r"C:\Erlang"] + glob.glob(r"C:\Program Files\Erlang*")
                     + glob.glob(r"C:\Program Files\erl*")):
            add("windows-install", os.path.join(root, "bin"))
    else:
        for prefix in ("/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"):
            for d in sorted(glob.glob(os.path.join(prefix, "opt", "erlang@*"))):
                add("homebrew", os.path.join(d, "bin"))
            add("homebrew", os.path.join(prefix, "opt", "erlang", "bin"))
        for d in (["/usr/local/lib/erlang/bin"] + sorted(glob.glob("/opt/erlang*/bin"))
                  + ["/usr/lib64/erlang/bin", "/usr/lib/erlang/bin"]):
            add("system", d)

    seen, unique = set(), []
    for source, bin_dir in found:
        key = os.path.realpath(os.path.join(bin_dir, _exe("erl")))
        if key not in seen:
            seen.add(key)
            unique.append((source, bin_dir))
    return unique


def find_otp(wanted=None):
    """Resolve the pinned OTP. Returns (bin_dir, version, source, report).

    bin_dir is None when nothing matches; report is a list of
    "source: bin_dir -> version" lines describing every install inspected, for
    the caller's error message. An explicit YUZU_OTP_BIN must itself match: a
    wrong explicit choice is an error, never silently replaced. Otherwise the
    erl already on PATH wins when it matches (it is the operator's active
    choice); failing that, the highest matching release among the rest.
    """
    wanted = wanted or wanted_otp_version()
    report, matches = [], []
    for source, found_dir in otp_candidates():
        bin_dir, v = probe_install(found_dir)
        via = f" (shim for {bin_dir})" if bin_dir and bin_dir != found_dir else ""
        report.append(f"{source}: {found_dir}{via} -> {v or 'no working erl'}")
        bin_dir = bin_dir or found_dir
        ok = version_matches(v, wanted)
        if source == "YUZU_OTP_BIN":
            return (bin_dir, v, source, report) if ok else (None, None, None, report)
        if ok:
            if source == "PATH":
                return bin_dir, v, source, report
            matches.append((_version_key(v), bin_dir, v, source))
    if not matches:
        return None, None, None, report
    _, bin_dir, v, source = max(matches, key=lambda m: m[0])
    return bin_dir, v, source, report


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
        # The pinned OTP (resolved by Meson, or here) before any other install,
        # so rebar3 runs on the same release the build was configured against.
        # Same preference as the install-root scan below (the real
        # erts-*/bin/escript.exe first), but inside the pinned install; its
        # bin/escript.exe only when bin/ really is an install's (releases/
        # beside it), never a launcher-shim directory.
        otp_bin = os.environ.get("YUZU_OTP_BIN") or find_otp()[0]
        if otp_bin:
            otp_root = os.path.dirname(os.path.abspath(otp_bin))
            pinned = sorted(
                glob.glob(os.path.join(otp_root, "erts-*", "bin", "escript.exe")),
                reverse=True,
            )
            if os.path.isdir(os.path.join(otp_root, "releases")):
                pinned.append(os.path.join(otp_bin, "escript.exe"))
            escript = next((c for c in pinned if os.path.isfile(c)), None)
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
    off interactive git credential prompts (hazard 4 above).

    On every platform, puts the pinned OTP's bin/ first on PATH: the one Meson
    resolved at configure time (YUZU_OTP_BIN, passed through the target's
    env), or one resolved here when the wrapper is run by hand. rebar3 is an
    escript (`#!/usr/bin/env escript`), so this is what decides which OTP it
    runs on; without it a newer OTP earlier on PATH (Homebrew `erlang`) wins.
    """
    env = os.environ.copy()
    otp_bin = env.get("YUZU_OTP_BIN") or find_otp()[0]
    if otp_bin:
        env["YUZU_OTP_BIN"] = otp_bin
        env["PATH"] = otp_bin + os.pathsep + env.get("PATH", "")
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


def main(argv=None):
    """`erlang_toolchain.py find-otp [--version V]`

    On success prints three lines (bin dir, full version, where it was found)
    and exits 0. Meson runs this at configure time; ensure-erlang.sh runs it to
    activate the same OTP in a shell. On failure exits 1 and lists every
    install it inspected on stderr, so the operator sees why (e.g. "PATH:
    /opt/homebrew/bin -> 29.1.1") rather than a silent wrong-version build.
    """
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] != "find-otp":
        sys.stderr.write("usage: erlang_toolchain.py find-otp [--version V]\n")
        return 2
    wanted = wanted_otp_version()
    if len(argv) >= 3 and argv[1] == "--version" and argv[2]:
        wanted = argv[2]
    bin_dir, version, source, report = find_otp(wanted)
    if bin_dir:
        print(bin_dir)
        print(version)
        print(source)
        return 0
    sys.stderr.write(f"erlang_toolchain: no Erlang/OTP {wanted} found.\n")
    sys.stderr.write("  inspected:\n" + "".join(f"    {r}\n" for r in report) if report
                     else "  no Erlang/OTP install found at all.\n")
    sys.stderr.write(f"  Install OTP {wanted} (e.g. `kerl build-install {wanted} "
                     f"~/.kerl/{wanted}`), or point YUZU_OTP_BIN at its bin/.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
