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

for e in errs:
    print("FAIL:", e)
sys.exit(1 if errs else 0)
