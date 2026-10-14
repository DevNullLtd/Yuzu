#!/usr/bin/env python3
r"""Shared Erlang toolchain resolution for the Meson gateway wrappers.

Two jobs. First, WHICH Erlang/OTP: the pinned release (DEFAULT_OTP_VERSION, a
floor within its major) is resolved by `find-otp` - at configure time by Meson,
in a shell by ensure-erlang.sh - and base_env() puts it first on PATH for every
rebar3 the wrappers run, on every platform. Second, the Windows hazards below.

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
import re
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


def _read_text(path):
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _release_otp_version(root):
    """The LIVE release's OTP_VERSION under root, or "" when undeterminable.

    One releases/*/OTP_VERSION: that is it. Several (a `make install` of a new
    major over an old one leaves the old releases/<n>/ behind): the live one is
    named by releases/start_erl.data ("<erts_vsn> <otp_rel>"), which every
    `make install` writes. Picking the alphabetically-first OTP_VERSION
    instead reported a stale 28.4.2 for a live OTP 29 - the exact
    wrong-version build this resolver exists to prevent. If start_erl.data is
    absent or names a release with no OTP_VERSION, return "" so the caller
    asks the VM itself rather than guess.
    """
    files = sorted(glob.glob(os.path.join(root, "releases", "*", "OTP_VERSION")))
    if len(files) == 1:
        return _read_text(files[0])
    if len(files) > 1:
        parts = _read_text(os.path.join(root, "releases", "start_erl.data")).split()
        # The release name is a bare OTP major ("28"); anything else (a relx
        # app release, a "../" path) is not trusted to name a directory.
        if len(parts) == 2 and re.fullmatch(r"\d+", parts[1]):
            live = os.path.join(root, "releases", parts[1], "OTP_VERSION")
            if os.path.isfile(live):
                return _read_text(live)
    return ""


def probe_install(bin_dir):
    """(canonical_bin, version) of the OTP install that bin_dir's erl runs.

    Reads the live release's <root>/releases/<rel>/OTP_VERSION (see
    _release_otp_version), which every OTP install ships (kerl, asdf, mise,
    Homebrew, distro packages, the Windows installer), so usually no VM is
    started. The root is two levels above the REAL erl: Homebrew's bin/erl and
    a distro's /usr/bin/erl are symlinks into <root>/bin/, kerl's is a script
    beside its releases/.

    canonical_bin is the install's own bin/, never a shared directory that
    merely holds a link or shim to it: a symlinked erl resolves to its real
    directory (so /usr/bin or /opt/homebrew/bin, with every other tool in
    them, is never put first on PATH), and a launcher SHIM directory
    (Chocolatey's C:\\ProgramData\\chocolatey\\bin, Scoop's shims) - no
    releases/ to read - is resolved by asking that erl for code:root_dir().
    rebar3 must never run through the Chocolatey escript shim (the
    launcher-stub segfault this module's rebar3_prefix exists to avoid), and
    YUZU_OTP_BIN goes first on PATH. (None, None) if bin_dir has no working
    erl.
    """
    erl = os.path.join(bin_dir, _exe("erl"))
    if not os.path.isfile(erl):
        return None, None
    real_erl = os.path.realpath(erl)
    real_root = os.path.dirname(os.path.dirname(real_erl))
    v = _release_otp_version(real_root)
    if v:
        # Only an erl that is ITSELF a link moves to its real directory; a
        # symlinked parent (macOS /var -> /private/var) changes nothing.
        return (os.path.dirname(real_erl) if os.path.islink(erl) else bin_dir), v
    v = _release_otp_version(os.path.dirname(os.path.abspath(bin_dir)))
    if v:
        return bin_dir, v
    try:
        out = subprocess.run(
            [erl, "-noshell", "-eval",
             'R=code:root_dir(),'
             'F=filename:join([R,"releases",erlang:system_info(otp_release),"OTP_VERSION"]),'
             '{ok,B}=file:read_file(F),io:format("~s~n~s",[R,B]),halt().'],
            capture_output=True, text=True, errors="replace", timeout=60,
            **windows_stdio_isolation(),
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    lines = out.stdout.strip().splitlines()
    if out.returncode != 0 or len(lines) < 2 or not lines[1].strip():
        return None, None
    real_bin = os.path.join(lines[0].strip(), "bin")
    canonical = real_bin if os.path.isfile(os.path.join(real_bin, _exe("erl"))) else bin_dir
    return os.path.normpath(canonical), lines[1].strip()


def otp_version(bin_dir):
    """The full OTP version ("28.4.2") that bin_dir's erl runs, or None."""
    return probe_install(bin_dir)[1]


def _version_key(v):
    """Numeric tuple of a version. Each dot component contributes its LEADING
    digits, so otp_patch_apply's "28.5**" is (28, 5), never (28, 0)."""
    key = []
    for part in v.strip().split("."):
        m = re.match(r"\d+", part)
        key.append(int(m.group()) if m else 0)
    return tuple(key)


def version_matches(found, wanted):
    """True when found is wanted or later, within wanted's major.

    "28.4" accepts "28.4", "28.4.0", "28.4.2", "28.5.0.7", "28.5**", "28.40";
    rejects "28.3.9", "29.1.1". "28" accepts any 28.x. Components compare
    numerically, padded with zeros, so "28.4" and "28.4.0" are equal.
    """
    if not found or not wanted:
        return False
    f, w = _version_key(found), _version_key(wanted)
    n = max(len(f), len(w))
    f, w = f + (0,) * (n - len(f)), w + (0,) * (n - len(w))
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
                                 capture_output=True, text=True, errors="replace",
                                 timeout=30)
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

    YUZU_OTP_BIN (explicit) first - always listed when set, even if it holds no
    erl, so a typo is reported rather than silently replaced - then the erl
    already on PATH, then version managers and well-known install locations.
    Duplicates (same real erl) are dropped, keeping the first.

    Deliberately NOT scanned: C:\\Erlang. On Windows any authenticated user can
    create a directory under C:\\, and the CI runners build as LOCAL SYSTEM, so
    a planted C:\\Erlang winning here would put attacker code first on PATH
    for a SYSTEM build. The Windows installer and the runner contract use
    C:\\Program Files (administrator-owned); point YUZU_OTP_BIN or ERLANG_HOME
    elsewhere deliberately if needed.
    """
    found = []

    def add(source, bin_dir):
        if bin_dir and os.path.isfile(os.path.join(bin_dir, _exe("erl"))):
            found.append((source, os.path.abspath(bin_dir)))

    explicit = os.environ.get("YUZU_OTP_BIN")
    if explicit:
        found.append(("YUZU_OTP_BIN", os.path.abspath(explicit)))
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
        for root in (glob.glob(r"C:\Program Files\Erlang*")
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
    "source: dir -> version" lines describing every install inspected, for the
    caller's error message. An explicit YUZU_OTP_BIN must itself hold a
    matching erl: a wrong or missing explicit choice is an error, never
    silently replaced. Otherwise the erl already on PATH wins when it matches
    (it is the operator's active choice); failing that, the highest matching
    release among the rest.
    """
    wanted = wanted or wanted_otp_version()
    report, matches = [], []
    for source, found_dir in otp_candidates():
        if "\n" in found_dir or "\r" in found_dir:
            # A line break would shift find-otp's line-oriented output, so the
            # shell / Meson would read another line as the bin dir. Refuse it.
            report.append(f"{source}: {found_dir!r} -> refused (line break in path)")
            continue
        bin_dir, v = probe_install(found_dir)
        via = f" (resolves to {bin_dir})" if bin_dir and bin_dir != found_dir else ""
        report.append(f"{source}: {found_dir}{via} -> {v or 'no working erl here (expected its bin/ directory)'}")
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
        # Administrator-owned install roots only: never C:\Erlang, which any
        # authenticated user can create (see otp_candidates).
        roots = glob.glob(r"C:\Program Files\Erlang*")
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
    otp_bin = env.get("YUZU_OTP_BIN")
    if otp_bin:
        # Meson resolved this at configure time. Re-check it: if that install
        # was removed or replaced since (kerl delete, brew upgrade), rebar3
        # would otherwise fall through to whatever erl is next on PATH - the
        # wrong-version build this module exists to prevent.
        v = otp_version(otp_bin)
        if not version_matches(v, wanted_otp_version()):
            sys.stderr.write(
                f"erlang_toolchain: the configured Erlang/OTP at {otp_bin} is now "
                f"{v or 'missing'}, not {wanted_otp_version()} or a later "
                f"{wanted_otp_version().split('.')[0]}.x. Reconfigure the build "
                "(meson setup --reconfigure <builddir>) to resolve it again.\n")
            sys.exit(1)
    else:
        otp_bin = find_otp()[0]
        if not otp_bin:
            sys.stderr.write(
                f"erlang_toolchain: warning: no Erlang/OTP {wanted_otp_version()} "
                "(or later same-major) found; using whatever erl is on PATH. "
                "Run `erlang_toolchain.py find-otp` to see what was found.\n")
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


EXIT_FOUND, EXIT_NO_MATCH, EXIT_USAGE, EXIT_INTERNAL = 0, 1, 2, 3


def main(argv=None):
    """`erlang_toolchain.py find-otp [--version V]`

    Exit codes (Meson relies on them, so keep them distinct):
      0  found: prints four lines (bin dir, full version, where it was found,
         the pin it was checked against - Meson passes that pin to the
         targets so a build re-checks against the CONFIGURED pin)
      1  no install passes the pin: lists every install inspected on stderr,
         so the operator sees why (e.g. "PATH: /opt/homebrew/bin -> 29.1.1")
      2  usage error
      3  the resolver itself failed (a bug or an unreadable environment): a
         traceback on stderr. Never reported as "no matching OTP".
    Meson runs this at configure time; ensure-erlang.sh runs it to activate
    the same OTP in a shell.
    """
    try:
        return _main(argv)
    except Exception:  # noqa: BLE001 - every resolver failure must surface as 3
        import traceback
        traceback.print_exc()
        sys.stderr.write("erlang_toolchain: internal error (exit 3); this is a "
                         "resolver bug, not a missing Erlang/OTP.\n")
        return EXIT_INTERNAL


def _main(argv):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] != "find-otp":
        sys.stderr.write("usage: erlang_toolchain.py find-otp [--version V]\n")
        return EXIT_USAGE
    wanted = wanted_otp_version()
    if len(argv) >= 3 and argv[1] == "--version" and argv[2]:
        wanted = argv[2]
    major = wanted.split(".")[0]
    if not re.fullmatch(r"\d+(\.\d+)*", wanted):
        sys.stderr.write(f"erlang_toolchain: invalid OTP version pin {wanted!r} "
                         "(YUZU_OTP_VERSION / --version must be digits and dots).\n")
        return EXIT_USAGE
    bin_dir, version, source, report = find_otp(wanted)
    if bin_dir:
        print(bin_dir)
        print(version)
        print(source)
        print(wanted)
        return EXIT_FOUND
    sys.stderr.write(f"erlang_toolchain: no Erlang/OTP {wanted} or later {major}.x found.\n")
    sys.stderr.write("  inspected:\n" + "".join(f"    {r}\n" for r in report) if report
                     else "  no Erlang/OTP install found at all.\n")
    if sys.platform == "win32":
        hint = (f"Install OTP {wanted} or a later {major}.x from https://www.erlang.org/downloads "
                "(installs under C:\\Program Files)")
    elif sys.platform == "darwin":
        hint = (f"Install OTP {wanted} or a later {major}.x (`brew install erlang@{major}`, "
                f"or kerl: `kerl build-install {wanted} ~/.kerl/{wanted}`)")
    else:
        hint = (f"Install OTP {wanted} or a later {major}.x (kerl: `kerl build-install "
                f"{wanted} ~/.kerl/{wanted}`, asdf, or your distribution's packages)")
    sys.stderr.write(f"  {hint}, or point YUZU_OTP_BIN at its bin/ directory; then "
                     "reconfigure (meson setup --reconfigure <builddir>).\n")
    return EXIT_NO_MATCH


if __name__ == "__main__":
    sys.exit(main())
