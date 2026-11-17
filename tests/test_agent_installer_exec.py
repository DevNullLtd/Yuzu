#!/usr/bin/env python3
"""WP13 governance N1/N-QEN1/N-WRAPEXIT: EXECUTED tests of install-agent-user.sh with stub tools.

Sources the installer (YUZU_INSTALLER_SOURCE_ONLY=1), redirects every root path into a temp dir,
puts stub useradd/usermod/getent/install/chown/visudo/getcap/setcap first on PATH and runs
do_install / check_install. The assertions are on EXIT STATUS and on what was left on disk, so a
mutation that keeps the strings but neuters the exit (or the sudoers removal) fails here. No root,
nothing outside the temp dir is touched.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts/install-agent-user.sh"
errs = []


def stub(bindir, name, body):
    p = bindir / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(0o755)


def scenario(label, want, *, visudo_ok=True, getcap="empty", setcap=True, wrapper_install_ok=True,
             old_sudoers=False, check=False, sudoers_content=None, binary_exists=True):
    """want: expected exit status, or 'nonzero'."""
    with tempfile.TemporaryDirectory(prefix="yuzu_test_installer_exec_") as d:
        d = pathlib.Path(d)
        bindir = d / "bin"
        bindir.mkdir()
        for tool in ("sed", "cat", "grep", "mktemp", "rm", "stat", "id", "printf", "dirname",
                     "date", "awk", "sort", "mv", "rmdir", "tr", "head", "uname", "bash", "env",
                     "mkdir", "true", "false", "chmod", "cp", "ln", "readlink", "tee", "wc"):
            for cand in ("/usr/bin/", "/bin/"):
                if os.path.exists(cand + tool):
                    os.symlink(cand + tool, bindir / tool)
                    break
        stub(bindir, "useradd", "exit 0")
        stub(bindir, "usermod", "exit 0")
        stub(bindir, "getent", "exit 0")
        stub(bindir, "chown", "exit 0")
        # install: succeed, except for the wrapper path when asked to fail; copies the source
        # file for a regular file install so the sudoers content lands where the test reads it.
        stub(bindir, "install", f'''
for a in "$@"; do last="$a"; done
case "$last" in *yuzu-systemctl) {"exit 0" if wrapper_install_ok else "exit 1"};; esac
if [ "$1" = "-d" ]; then exit 0; fi
src=""; for a in "$@"; do src="$last_prev"; last_prev="$a"; done
# last arg = dest, second to last = source
n=$#; i=0; for a in "$@"; do i=$((i+1)); [ $i -eq $((n-1)) ] && s="$a"; done
cp "$s" "$last" 2>/dev/null; exit 0''')
        stub(bindir, "visudo", "exit 0" if visudo_ok else "echo 'syntax error' >&2; exit 1")
        if getcap != "missing":
            stub(bindir, "getcap", 'echo "$1 cap_net_admin+eip"' if getcap == "caps" else "exit 0")
        if setcap:
            stub(bindir, "setcap", "exit 0")  # a no-op: the capability (if any) stays "live"
        binary = d / "yuzu-agent"
        if binary_exists:
            binary.write_text("x")
        sudoers = d / "sudoers.d-yuzu-agent"
        if old_sudoers:
            sudoers.write_text("yuzu ALL=(root) NOPASSWD: /usr/bin/systemctl enable *\n")
        elif sudoers_content is not None:
            sudoers.write_text(sudoers_content)
        wrapper_dir = d / "libexec"
        wrapper = wrapper_dir / "yuzu-systemctl"
        if sudoers_content is not None and check:
            wrapper_dir.mkdir()
            wrapper.write_text("#!/bin/sh\n")
            wrapper.chmod(0o755)
        driver = f'''
export YUZU_INSTALLER_SOURCE_ONLY=1
source "{SCRIPT}" --account-name yuzu_t --binary-path "{binary}"
PLATFORM=linux
STATE_DIR={d}/state; CACHE_DIR={d}/cache; LOG_DIR={d}/log
SUDOERS_TARGET={sudoers}
SYSTEMCTL_WRAPPER_DIR={wrapper_dir}; SYSTEMCTL_WRAPPER_PATH={wrapper}
require_root() {{ :; }}
{"check_install" if check else "do_install"}
echo "RC=$?"
'''
        env = {"PATH": str(bindir), "HOME": str(d), "LC_ALL": "C"}
        r = subprocess.run(["/bin/bash", "-c", driver], capture_output=True, text=True, env=env,
                           timeout=60)
        m = [l for l in r.stdout.splitlines() if l.startswith("RC=")]
        rc = int(m[-1][3:]) if m else None
        ok = (rc not in (0, None)) if want == "nonzero" else (rc == want)
        if not ok:
            errs.append(f"{label}: expected exit {want}, got {rc}\n{r.stdout[-500:]}{r.stderr[-300:]}")
        return d, sudoers, rc


# ── install: every failing step must make the installer exit non-zero ──────────────────────
scenario("happy path", 0)
scenario("setcap missing while the binary carries caps (N1)", 5, getcap="caps", setcap=False)
scenario("getcap missing AND setcap missing: cannot verify (N1)", 5, getcap="missing", setcap=False)
scenario("setcap present but the capability stays live", 5, getcap="caps")  # stub setcap is a no-op
scenario("visudo rejects the file (R1)", 3, visudo_ok=False)
d, sud, _ = scenario("visudo rejects and an old glob file exists (R1)", 3, visudo_ok=False,
                     old_sudoers=True)
if sud.exists():
    errs.append("a failed sudoers validation left the previous glob-carrying file in place")
scenario("wrapper install fails (N-WRAPEXIT)", 4, wrapper_install_ok=False)
d, sud, _ = scenario("wrapper install fails: no systemctl grant is written", 4,
                     wrapper_install_ok=False)
if sud.exists() and "yuzu-systemctl" in sud.read_text():
    errs.append("a failed wrapper install still wrote the wrapper grant")

# ── --check: drift must be a non-zero exit (the case used to fall through to exit 0) ────────
good = ("yuzu_t ALL=(root) NOPASSWD: {W}\n")
scenario("check: getcap missing is drift (R2)", "nonzero", check=True, getcap="missing",
         sudoers_content="x\n")
scenario("check: capabilities present is drift", "nonzero", check=True, getcap="caps",
         sudoers_content="x\n")


# ══ NON-SOURCED runs (WP13 governance R3-FALSEGREEN) ══════════════════════════════════════════
# The real script, executed as `bash install-agent-user.sh ...`, so the bottom `case "$ACTION"`
# dispatch and its `exit $?` are part of what is tested. YUZU_INSTALLER_TEST_ROOT redirects every
# root-owned path under a temp prefix and skips the root check (test knob, see the script).
import getpass

WRAPPER_BODY = "#!/bin/sh\nexit 0\n"


def run_script(label, want, args, *, platform="Linux", visudo_ok=True, getcap="empty", setcap=True,
               wrapper_install_ok=True, layout=None, caps_on_binary=False, extra_env=None, uid0=False,
               test_root_override=None, sudoers_mode=None, cwd_is_dir=False):
    """layout: None (nothing exists), 'healthy', 'old_glob', 'no_wrapper', 'no_wrapper_grant'."""
    me = getpass.getuser()
    with tempfile.TemporaryDirectory(prefix="yuzu_test_installer_run_") as d:
        d = pathlib.Path(d)
        bindir = d / "bin"
        bindir.mkdir()
        for tool in ("sed", "cat", "grep", "mktemp", "rm", "stat", "id", "printf", "dirname", "date",
                     "awk", "sort", "mv", "rmdir", "tr", "head", "bash", "env", "mkdir", "true",
                     "false", "chmod", "cp", "ln", "readlink", "tee", "wc", "basename"):
            for cand in ("/usr/bin/", "/bin/"):
                if os.path.exists(cand + tool):
                    os.symlink(cand + tool, bindir / tool)
                    break
        if platform == "Darwin":
            stub(bindir, "uname", "echo Darwin")
            # BSD stat: no -c; -f '%Su' prints the owner. A GNU-style call must fail like on macOS.
            (bindir / "stat").unlink()
            stub(bindir, "stat", f'[ "$1" = "-f" ] && {{ echo {me}; exit 0; }}; echo "stat: illegal option" >&2; exit 1')
            stub(bindir, "dscl", f'case "$*" in *PrimaryGroupID*) echo "PrimaryGroupID: 300";; *) ;; esac; exit 0')
            stub(bindir, "dscacheutil", "exit 0")
        else:
            stub(bindir, "uname", "echo Linux")
        for t in ("useradd", "usermod", "getent", "chown"):
            stub(bindir, t, "exit 0")
        stub(bindir, "install", f'''
for a in "$@"; do last="$a"; done
case "$last" in *yuzu-systemctl) {"true" if wrapper_install_ok else "exit 1"};; esac
if [ "$1" = "-d" ]; then mkdir -p "$last" 2>/dev/null; exit 0; fi
n=$#; i=0; for a in "$@"; do i=$((i+1)); [ $i -eq $((n-1)) ] && s="$a"; done
mkdir -p "$(dirname "$last")" 2>/dev/null; cp "$s" "$last" 2>/dev/null; chmod 755 "$last" 2>/dev/null; exit 0''')
        stub(bindir, "visudo", "exit 0" if visudo_ok else "echo 'syntax error' >&2; exit 1")
        if getcap != "missing":
            stub(bindir, "getcap", 'echo "$1 cap_net_admin+eip"' if getcap == "caps" else "exit 0")
        if setcap:
            stub(bindir, "setcap", "exit 0")
        root = d / "root"
        root.mkdir()
        for sub in ("var/lib/yuzu-agent", "var/cache/yuzu-agent", "var/log/yuzu-agent",
                    "Library/Application Support/Yuzu", "Library/Caches/Yuzu", "Library/Logs/Yuzu",
                    "etc/sudoers.d", "usr/libexec/yuzu"):
            if layout is not None:
                (root / sub).mkdir(parents=True)
        binary = d / "yuzu-agent"
        binary.write_text("x")
        sudoers = root / "etc/sudoers.d/yuzu-agent"
        wrapper = root / "usr/libexec/yuzu/yuzu-systemctl"
        mac = platform == "Darwin"
        grant = f"{me} ALL=(root) NOPASSWD: {wrapper}\n"
        if layout == "healthy":
            sudoers.write_text(("# c\n" + (f"{me} ALL=(root) NOPASSWD: /bin/launchctl enable system/*\n" if mac else grant)))
            if not mac:
                wrapper.write_text(WRAPPER_BODY); wrapper.chmod(0o755)
        elif layout == "old_glob":
            sudoers.write_text(f"{me} ALL=(root) NOPASSWD: /usr/bin/systemctl enable *\n" + grant)
            wrapper.write_text(WRAPPER_BODY); wrapper.chmod(0o755)
        elif layout == "no_wrapper":
            sudoers.write_text(grant)
        elif layout == "no_wrapper_grant":
            sudoers.write_text(f"{me} ALL=(root) NOPASSWD: /usr/sbin/iptables\n")
            wrapper.write_text(WRAPPER_BODY); wrapper.chmod(0o755)
        elif layout == "mac_bootstrap":
            sudoers.write_text(f"{me} ALL=(root) NOPASSWD: /bin/launchctl bootstrap system *\n")
        if uid0:  # simulate a root caller: the installer reads the uid through `id -u`
            (bindir / "id").unlink()
            stub(bindir, "id", '[ "$1" = "-u" ] && echo 0 || echo root')
        if sudoers_mode is not None and sudoers.exists():
            sudoers.chmod(sudoers_mode)
        root_value = str(root) if test_root_override is None else test_root_override.replace("@D@", str(d))
        env = {"PATH": str(bindir), "HOME": str(d), "LC_ALL": "C", "YUZU_INSTALLER_TEST_ROOT": root_value, **(extra_env or {})}
        r = subprocess.run(["/bin/bash", str(SCRIPT), "--account-name", me, "--binary-path", str(binary), *args],
                           capture_output=True, text=True, env=env, timeout=60,
                           cwd=str(d) if cwd_is_dir else None)
        ok = (r.returncode != 0) if want == "nonzero" else (r.returncode == want)
        if not ok:
            errs.append(f"[non-sourced] {label}: expected exit {want}, got {r.returncode}\n{r.stdout[-400:]}{r.stderr[-300:]}")
        return d, root, r


# --check on a healthy layout MUST exit 0 (a GNU `stat -f` made it always 1), drift MUST exit 1
run_script("check healthy linux => 0", 0, ["--check"], layout="healthy")
run_script("check healthy macos => 0", 0, ["--check"], layout="healthy", platform="Darwin")
run_script("check: old glob grant => 1", 1, ["--check"], layout="old_glob")
run_script("check: missing wrapper => 1", 1, ["--check"], layout="no_wrapper")
run_script("check: wrapper grant absent => 1", 1, ["--check"], layout="no_wrapper_grant")
run_script("check: caps present => 1", 1, ["--check"], layout="healthy", getcap="caps")
run_script("check: getcap missing => 1", 1, ["--check"], layout="healthy", getcap="missing")
run_script("check macos: bootstrap grant => 1", 1, ["--check"], layout="mac_bootstrap", platform="Darwin")
_, _, r = run_script("check --no-cap-cleanup with caps => 0 but warns the check is skipped", 0,
                     ["--check", "--no-cap-cleanup"], layout="healthy", getcap="caps")
if "SKIPPED" not in r.stderr:
    errs.append("--check --no-cap-cleanup must warn that the capability check is skipped")

# R4-CHECKGREEN: a sudoers file the caller cannot read means the grants are UNVERIFIED: exit 6, never 0
_, _, r = run_script("check: sudoers present but unreadable (mode 0000) => 6", 6, ["--check"],
                     layout="healthy", sudoers_mode=0)
if "UNVERIFIED" not in r.stderr:
    errs.append("an unreadable sudoers file must be reported as UNVERIFIED on stderr")
# a real drift still wins over unverified (1, not 6) is covered by the old-glob case above

# N5-2: real drift (exit 1) takes precedence over unverified (exit 6) when both are present
run_script("check: drift AND unreadable sudoers => 1 (drift wins over unverified)", 1,
           ["--check", "--account-name", "someone-else-entirely"], layout="healthy", sudoers_mode=0)

# R4-OWNER: state dirs owned by someone other than the account are drift (exit 1)
run_script("check: state dir owned by another account => 1", 1,
           ["--check", "--account-name", "someone-else-entirely"], layout="healthy")

# R4-TESTROOT: the escape hatch is refused for root and validated
_, _, r = run_script("root run with YUZU_INSTALLER_TEST_ROOT set is refused", 1, [], uid0=True)
if "root run" not in r.stderr:
    errs.append("the root refusal must say why")
run_script("root --check with the variable set is refused too", 1, ["--check"], layout="healthy", uid0=True)
run_script("relative TEST_ROOT refused", 1, [], test_root_override="relative/dir")
# N5-1: an EXISTING, caller-owned relative directory passes every other guard, so only the
# absolute-path check can refuse it (mutating that check turns this red).
_, _, r = run_script("existing caller-owned RELATIVE TEST_ROOT is refused by the absolute-path check", 1, [],
                     test_root_override="root", cwd_is_dir=True)
if "absolute" not in r.stderr:
    errs.append("a relative TEST_ROOT must be refused with the absolute-path message")
run_script("TEST_ROOT of / refused", 1, [], test_root_override="/")
run_script("TEST_ROOT of // refused", 1, [], test_root_override="//")
run_script("non-existent TEST_ROOT refused", 1, [], test_root_override="@D@/does-not-exist")
run_script("TEST_ROOT not owned by the caller refused", 1, [], test_root_override="/usr")
_ln = []
def _symlink_case():
    with tempfile.TemporaryDirectory(prefix="yuzu_test_installer_lnk_") as t:
        t = pathlib.Path(t)
        (t / "real").mkdir()
        os.symlink(t / "real", t / "link")
        run_script("symlinked TEST_ROOT refused", 1, [], test_root_override=str(t / "link"))
_symlink_case()
_, _, r = run_script("an honoured TEST_ROOT prints the loud banner on stderr", 0, [])
if "TEST-ONLY MODE" not in r.stderr:
    errs.append("the TEST-ONLY banner must be printed on stderr when the variable is honoured")

# install matrix through the real dispatch: 0 / 3 / 4 / 5
run_script("install healthy => 0", 0, [], layout=None)
run_script("install: visudo rejects => 3", 3, [], visudo_ok=False)
run_script("install: wrapper install fails => 4", 4, [], wrapper_install_ok=False)
run_script("install: setcap missing with caps => 5", 5, [], getcap="caps", setcap=False)
run_script("install: getcap and setcap missing => 5", 5, [], getcap="missing", setcap=False)
_, _, r = run_script("install --no-cap-cleanup with live caps => 0 but LOUD on stderr", 0,
                     ["--no-cap-cleanup"], getcap="caps")
if "STILL LIVE" not in r.stderr:
    errs.append("--no-cap-cleanup with live capabilities must warn on stderr")
_, _, r = run_script("install --no-setcap is accepted with a deprecation warning", 0, ["--no-setcap"])
if "deprecated alias" not in r.stderr:
    errs.append("--no-setcap must print the deprecation warning (it used to be emitted before warn() existed)")
# SOURCE_ONLY set on an EXECUTED script must not silently exit 0
d, root, r = run_script("executed with SOURCE_ONLY still runs (no silent no-op)", 3, [],
                        visudo_ok=False, extra_env={"YUZU_INSTALLER_SOURCE_ONLY": "1"})
if "only for sourcing" not in r.stderr:
    errs.append("SOURCE_ONLY on an executed script must warn")

for e in errs:
    print("FAIL:", e)
sys.exit(1 if errs else 0)
