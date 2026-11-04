#!/usr/bin/env python3
"""Behaviour tests for scripts/test/ensure-puppeteer.sh and scripts/test/ensure-gcovr.sh.

Both helpers install tooling for the /test gates, so every branch that decides "ready" or
"NOT READY" is exercised here against STUB executables in a sandbox: a temp HOME, a stub bin dir
first on PATH, a coreutils-only symlink farm behind it (so a node/python3/gcovr on the host can
never leak in), a temp YUZU_GCOVR_VENV and TMPDIR, and a private copy of the script plus the few repo
files it reads. The script runs with its working directory in a NEUTRAL empty temp dir (neither the
repo nor the sandbox repo), so a missing `cd` shows up as a stub that ran in the wrong place. The real
repo tree and the real $HOME are never touched; each case asserts the former.

Stubs append their argv to one log (calls.log), so a case can say which tools ran and which did not.
Side observations that are not "a tool ran" (what the filesystem looked like when a stub was called,
where it ran, whether the lock descriptor leaked into it) go to calls.log.<suffix>, so the exact-list
assertions on calls.log stay readable. `timeout`, `gtimeout`, `flock` and `ldd` are deliberately NOT in
the farm: by default the scripts run unwrapped and unlocked (the macOS situation), and a case that
cares installs a stub of its own.

The puppeteer cases are portable (they run natively on macOS under /test). The gcovr cases assume the
Linux path of ensure-gcovr.sh, which gates on `uname -s`, and are skipped elsewhere; only the
non-Linux no-op case, which stubs uname, runs everywhere.

YUZU_ENSURE_SCRIPT_DIR points the harness at a directory holding variants of the two scripts
(mutation checking); unset, the real scripts under scripts/test/ are used.
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import pty  # for the "a terminal on stdin" cases; absent on Windows, where nothing here runs
except ImportError:  # pragma: no cover
    pty = None

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = Path(os.environ.get("YUZU_ENSURE_SCRIPT_DIR", ROOT / "scripts" / "test"))
FARM_TOOLS = ("bash sh dirname basename sed head grep readlink sha256sum cut cat ls mkdir rm ln mv "
              "uname touch chmod tr mktemp tail wc od").split()

# A sequence stub: STUB_<VAR> is a space-separated list of outcomes ("ok"/"fail"), one per call; the
# last repeats. The call count lives in $STUB_LOG.<name>.
_SEQ = """n=$(cat "$STUB_LOG.@NAME" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$STUB_LOG.@NAME"
res=ok; i=0
for w in ${@VAR:-ok}; do i=$((i+1)); res=$w; [ "$i" -ge "$n" ] && break; done
"""
# Shell text that evaluates to "open" or "closed" for the lock descriptor (fd 9) as seen by a stub.
# `: >&9` fails on a closed descriptor.
_FD9 = '$( ( : >&9 ) 2>/dev/null && echo open || echo closed )'
# What every stub that is a child of the script reports: where it ran (.cwd) and whether the lock
# descriptor (fd 9) reached it (.fd9).
_OBSERVE = """echo "@T $PWD" >> "$STUB_LOG.cwd"
echo "@T """ + _FD9 + """" >> "$STUB_LOG.fd9"
"""

NODE = """#!/bin/sh
case "$1" in --version) echo "${STUB_NODE_VERSION:-v22.23.0}"; exit 0;; esac
""" + _OBSERVE.replace("@T", "node") + """case "$*" in
  *puppeteer.launch*)
""" + _SEQ.replace("@NAME", "launches").replace("@VAR", "STUB_LAUNCH") + """
    [ "$res" = ok ] && { echo "launched Chrome/1"; exit 0; }
    echo boom >&2; exit 1;;
  *executablePath*)
    [ -z "$STUB_EXEPATH_ERR" ] || { echo "Error: Cannot find package 'puppeteer'" >&2; exit 1; }
    echo "${PUPPETEER_EXECUTABLE_PATH:-$STUB_EXE}"; exit 0;;
esac
exit 0
"""
NPM = """#!/bin/sh
echo "npm $*" >> "$STUB_LOG"
""" + _OBSERVE.replace("@T", "npm") + """echo "npm skip_download=$PUPPETEER_SKIP_DOWNLOAD" >> "$STUB_LOG.state"
[ "${STUB_NPM_RC:-0}" = 0 ] || { echo "npm ERR! boom" >&2; exit "$STUB_NPM_RC"; }
mkdir -p node_modules/puppeteer; : > node_modules/.package-lock.json
"""
# The browser installer: records what the cache looked like when it was called (the build directory,
# and any *chrome*.zip archive beside it), then (on a call that is meant to succeed) leaves a
# runnable-looking binary at $STUB_EXE unless STUB_NPX_CREATES=0.
NPX = """#!/bin/sh
echo "npx $*" >> "$STUB_LOG"
""" + _OBSERVE.replace("@T", "npx") + _SEQ.replace("@NAME", "npx").replace("@VAR", "STUB_NPX") + """
dir=${STUB_BUILD:-$(dirname "$(dirname "$STUB_EXE")")}; parent=$(dirname "$dir"); zip=0
for z in "$parent"/*chrome*.zip; do [ -e "$z" ] && zip=1; done
echo "npx#$n dir=$([ -e "$dir" ] && echo 1 || echo 0) zip=$zip" >> "$STUB_LOG.state"
[ "$res" = ok ] || { echo "npx: download failed" >&2; exit 1; }
if [ "${STUB_NPX_CREATES:-1}" = 1 ]; then
  mkdir -p "$(dirname "$STUB_EXE")"; : > "$STUB_EXE"; chmod +x "$STUB_EXE"
fi
"""
# A browser binary: one that can print its version, and one too broken even for that.
BROWSER_RUNS = '#!/bin/sh\necho "Chrome 1.2.3"\n'
BROWSER_BROKEN = "#!/bin/sh\nexit 1\n"
LDD_MISSING_NSS = '#!/bin/sh\necho "$1" >> "$STUB_LOG.ldd"\nprintf \'\\tlibc.so.6 => /lib/libc.so.6\\n\\tlibnss3.so => not found\\n\'\n'
LDD_ALL_FOUND = "#!/bin/sh\nprintf '\\tlibc.so.6 => /lib/libc.so.6\\n'\n"
# The same two, but reporting whether the lock descriptor reached them.
LDD_ALL_FOUND_OBS = ("#!/bin/sh\necho \"ldd " + _FD9 + "\" >> \"$STUB_LOG.fd9\"\n"
                     "printf '\\tlibc.so.6 => /lib/libc.so.6\\n'\n")
BROWSER_BROKEN_OBS = '#!/bin/sh\necho "chrome ' + _FD9 + '" >> "$STUB_LOG.fd9"\nexit 1\n'
# timeout/gtimeout: logs "<name> <first four args>" (the scripts call `-k 10 <secs> <cmd>`, with
# --foreground first only when stdin is a terminal), then runs the command, or pretends to have timed
# out: with STUB_TIMEOUT_RC set every wrapped command "times out", or only those whose argv contains
# STUB_TIMEOUT_ONLY.
TIMEOUT = """#!/bin/sh
echo "@N $1 $2 $3 $4" >> "$STUB_LOG"
if [ -n "$STUB_TIMEOUT_RC" ]; then
  case "$*" in *"${STUB_TIMEOUT_ONLY:-}"*) exit "$STUB_TIMEOUT_RC";; esac
fi
[ "$1" = --foreground ] && shift
shift 3; exec "$@"
"""
FLOCK = '#!/bin/sh\necho "flock $*" >> "$STUB_LOG"\nexit "${STUB_FLOCK_RC:-0}"\n'
UNAME_DARWIN = "#!/bin/sh\necho Darwin\n"
# A gcovr on PATH that is not ours. --version prints the baked-in version; anything else is the
# capability probe, which records where it ran and with what, and exits with the baked-in status.
GCOVR = """#!/bin/sh
case "$1" in --version) echo "gcovr-version """ + _FD9 + """" >> "$STUB_LOG.fd9"; echo "gcovr @VER"; exit 0;; esac
echo "gcovr-probe """ + _FD9 + """" >> "$STUB_LOG.fd9"
echo "$PWD $*" >> "$STUB_LOG.probe"
exit @RC
"""
# python3 builds a stub venv: bin/{pip,gcovr,python}. pip honours STUB_PIP_RC; the venv's python is
# the health probe (`import gcovr, jinja2, ...`) and succeeds unless STUB_VENV_HEALTHY=0. Venv creation
# records, in $STUB_LOG.venv, whether the build marker already existed at that moment and whether a
# moved-aside copy of the previous venv (marked by a `sentinel` file) is visible, and, in
# $STUB_LOG.fd9, whether the lock descriptor reached it (as it does for pip, and not for the venv's own
# gcovr and python, which the script runs as probes).
PYTHON3 = """#!/bin/sh
echo "python3 $*" >> "$STUB_LOG"
if [ "$1" = -c ]; then
  case "$2" in
    *"print("*) echo 3.9; exit 0;;
    *version_info*) [ "${STUB_PY_OK:-1}" = 1 ]; exit $?;;
    *ensurepip*) [ "${STUB_ENSUREPIP_OK:-1}" = 1 ]; exit $?;;
  esac
  exit 0
fi
if [ "$1" = -m ] && [ "$2" = venv ]; then
  aside=0; for d in "$3".yuzu-gcovr-old.*; do [ -e "$d/sentinel" ] && aside=1; done
  echo "marker=$([ -e "$3/.yuzu-gcovr-venv" ] && echo 1 || echo 0) aside=$aside" >> "$STUB_LOG.venv"
  echo "venv-create """ + _FD9 + """" >> "$STUB_LOG.fd9"
  mkdir -p "$3/bin"; echo "home = /stub" > "$3/pyvenv.cfg"
  cat > "$3/bin/pip" <<'EOF'
#!/bin/sh
echo "pip $*" >> "$STUB_LOG"
echo "pip """ + _FD9 + """" >> "$STUB_LOG.fd9"
[ "${STUB_PIP_RC:-0}" = 0 ] || { echo "pip ERROR: boom" >&2; exit "$STUB_PIP_RC"; }
EOF
  cat > "$3/bin/gcovr" <<'EOF'
#!/bin/sh
echo "venv-gcovr """ + _FD9 + """" >> "$STUB_LOG.fd9"
echo "gcovr 8.7"
EOF
  cat > "$3/bin/python" <<'EOF'
#!/bin/sh
echo "venv-python """ + _FD9 + """" >> "$STUB_LOG.fd9"
[ "${STUB_VENV_HEALTHY:-1}" = 1 ]
EOF
  chmod +x "$3/bin/pip" "$3/bin/gcovr" "$3/bin/python"
fi
exit 0
"""


def _uname_s():
    try:
        return subprocess.run(["uname", "-s"], capture_output=True, text=True).stdout.strip()
    except OSError:
        return ""


# ensure-gcovr.sh gates on `uname -s` and its cases assume the Linux path, so they run only where
# both Python and uname say Linux.
IS_LINUX = sys.platform.startswith("linux") and _uname_s() == "Linux"


def gcovr_stub(version="8.7", probe_rc=0):
    return GCOVR.replace("@VER", version).replace("@RC", str(probe_rc))


def elf_bytes(shoff=64, shentsize=64, shnum=3, shstrndx=2, size=256, ei_class=2, ei_data=1):
    """A file that starts with a real 64-byte ELF header: magic, class (2 = ELF64), data (1 = little
    endian), version 1, then e_shoff (u64 at 0x28), e_shentsize (u16 at 0x3a), e_shnum (u16 at 0x3c) and
    e_shstrndx (u16 at 0x3e), little endian, zero padded to `size` bytes (cut to it when it is shorter
    than the header). The defaults describe a COMPLETE file at its exact minimum size: a section-header
    table of 3 entries of 64 bytes at offset 64 ends at byte 256."""
    h = bytearray(64)
    h[0:4] = b"\x7fELF"
    h[4], h[5], h[6] = ei_class, ei_data, 1
    h[0x28:0x30] = shoff.to_bytes(8, "little")
    h[0x3a:0x3c] = shentsize.to_bytes(2, "little")
    h[0x3c:0x3e] = shnum.to_bytes(2, "little")
    h[0x3e:0x40] = shstrndx.to_bytes(2, "little")
    return (bytes(h) + bytes(max(0, size - 64)))[:size]


def timeout_stub(name="timeout"):
    return TIMEOUT.replace("@N", name)


class Sandbox:
    """A temp HOME + stub bin + private repo copy for one script run."""

    def __init__(self, pin_in="8.7", pin_txt="8.7"):
        self._tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_ensure_")
        self.tmp = Path(self._tmp.name).resolve()
        self.home, self.bin, self.farm = (self.tmp / d for d in ("home", "bin", "farm"))
        self.neutral, self.tmpdir = self.tmp / "neutral", self.tmp / "tmpdir"
        self.repo, self.log, self.venv = self.tmp / "repo", self.tmp / "calls.log", self.tmp / "venv"
        for d in (self.home, self.bin, self.farm, self.neutral, self.tmpdir,
                  self.repo / "scripts" / "test", self.repo / "tests" / "puppeteer"):
            d.mkdir(parents=True)
        self.log.touch()
        for tool in FARM_TOOLS:
            real = shutil.which(tool)
            if real:
                (self.farm / tool).symlink_to(real)
        for name in ("ensure-puppeteer.sh", "ensure-gcovr.sh"):
            shutil.copy(SCRIPT_DIR / name, self.repo / "scripts" / "test" / name)
        (self.repo / "requirements-ci.in").write_text(f"meson==1.12.1\ngcovr=={pin_in}\n")
        (self.repo / "requirements-ci.txt").write_text(
            f"gcovr=={pin_txt} \\\n    --hash=sha256:{'0' * 64}\nmeson==1.12.1 \\\n"
            f"    --hash=sha256:{'1' * 64}\n")
        (self.repo / "tests" / "puppeteer" / "package-lock.json").write_text("{}\n")

    def cleanup(self):
        self._tmp.cleanup()

    def stub(self, name, body, where=None):
        path = (where or self.bin) / name
        path.write_text(body)
        path.chmod(0o755)

    def calls(self):
        return self.log.read_text().splitlines()

    def side(self, suffix):
        """Lines a stub wrote to calls.log.<suffix> (empty when it never wrote any)."""
        path = Path(f"{self.log}.{suffix}")
        return path.read_text().splitlines() if path.exists() else []

    def reset_logs(self):
        """Forget every call and side observation (including the stubs' call counters)."""
        for path in self.tmp.glob(self.log.name + "*"):
            path.unlink()
        self.log.touch()

    def req_sha(self):
        return hashlib.sha256((self.repo / "requirements-ci.txt").read_bytes()).hexdigest()

    def run(self, script, local_bin=False, stdin=subprocess.DEVNULL, timeout=60, **env):
        """Run <script> with an `env -i`-style environment; a None value unsets that variable.
        stdin is /dev/null (no terminal), so the timeout wrapper never gets --foreground unless a
        case passes a pty. A script still running after `timeout` seconds is a failure, not a hang."""
        dirs = [self.bin] + ([self.home / ".local" / "bin"] if local_bin else []) + [self.farm]
        full = {"HOME": str(self.home), "PATH": os.pathsep.join(map(str, dirs)),
                "STUB_LOG": str(self.log), "YUZU_GCOVR_VENV": str(self.venv),
                "TMPDIR": str(self.tmpdir), "LC_ALL": "C", **env}
        full = {k: v for k, v in full.items() if v is not None}
        try:
            return subprocess.run([shutil.which("bash"), str(self.repo / "scripts" / "test" / script)],
                                  env=full, cwd=self.neutral, stdin=stdin, capture_output=True, text=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise AssertionError(f"{script} still running after {timeout}s (blocked?)") from e


def _git_status():
    if not shutil.which("git"):
        return None
    return subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"],
                          capture_output=True, text=True).stdout


@unittest.skipIf(sys.platform == "win32" or not shutil.which("bash"), "needs bash and POSIX stubs")
class SandboxCase(unittest.TestCase):
    pin_in = pin_txt = "8.7"

    def setUp(self):
        before = _git_status()
        self.addCleanup(lambda: self.assertEqual(_git_status(), before, "real repo tree was written"))
        self.sb = Sandbox(self.pin_in, self.pin_txt)
        self.addCleanup(self.sb.cleanup)

    def expect(self, r, rc, fragment):
        self.assertEqual(r.returncode, rc, r.stdout + r.stderr)
        self.assertIn(fragment, r.stderr if rc else r.stdout)

    def write(self, path, text):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def fifo(self, path):
        """A named pipe at `path`: opening it for writing blocks until a reader appears, so a script
        that tries to use it as a lock file hangs (the harness timeout turns that into a failure)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(path)
        return path

    def assert_fd9(self, lines, install_tags, probe_tags):
        """`lines` are "<tag> open|closed" observations. Every tag in install_tags must have been seen
        and only ever with the lock descriptor open; every tag in probe_tags seen and only ever closed
        (a tag never seen would make the check vacuous)."""
        seen = {}
        for line in lines:
            tag, _, state = line.rpartition(" ")
            seen.setdefault(tag, set()).add(state)
        self.assertEqual(seen, {**{t: {"open"} for t in install_tags}, **{t: {"closed"} for t in probe_tags}})


class EnsurePuppeteer(SandboxCase):
    SCRIPT = "ensure-puppeteer.sh"
    NPM_CI = "npm ci --ignore-scripts --no-audit --no-fund"
    INSTALL = "npx --no-install puppeteer browsers install chrome"

    def setUp(self):
        super().setUp()
        for name, body in (("node", NODE), ("npm", NPM), ("npx", NPX)):
            self.sb.stub(name, body)
        self.pp = self.sb.repo / "tests" / "puppeteer"
        self.addCleanup(self.assert_children_ran_in_tests_puppeteer)
        # puppeteer's cache layout: <cache>/chrome/<build>/<platform dir>/<binary>
        self.cache = self.sb.tmp / "pcache"
        self.chrome = self.cache / "chrome"
        self.build = self.chrome / "linux-1.2.3"
        self.exe = self.build / "chrome-linux64" / "chrome"
        self.make_browser()

    def assert_children_ran_in_tests_puppeteer(self):
        """The script itself runs in a neutral directory, so every npm/npx/node call it made got
        to tests/puppeteer only through its own `cd`."""
        for line in self.sb.side("cwd"):
            tool, _, cwd = line.partition(" ")
            self.assertEqual(cwd, str(self.pp), f"{tool} ran in the wrong directory")

    def make_browser(self, exe=None, runs=True):
        """A browser binary at `exe`: one that prints its version (runs) or one that cannot."""
        exe = Path(exe or self.exe)
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_text(BROWSER_RUNS if runs else BROWSER_BROKEN)
        exe.chmod(0o755)
        return exe

    def make_binary(self, data, exe=None, mode=0o755):
        """A browser file with exactly these bytes (it cannot run: nothing here is a real executable)."""
        exe = Path(exe or self.exe)
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_bytes(data)
        exe.chmod(mode)
        return exe

    def run_script(self, **env):
        return self.sb.run(self.SCRIPT, **{"STUB_EXE": str(self.exe),
                                           "PUPPETEER_CACHE_DIR": str(self.cache), **env})

    def install_modules(self, lock_mtime, modules_mtime):
        (self.pp / "node_modules" / "puppeteer").mkdir(parents=True)
        mod_lock = self.pp / "node_modules" / ".package-lock.json"
        mod_lock.touch()
        os.utime(self.pp / "package-lock.json", (lock_mtime, lock_mtime))
        os.utime(mod_lock, (modules_mtime, modules_mtime))

    def npx_calls(self):
        return [c for c in self.sb.calls() if c.startswith("npx ")]

    def npx_states(self):
        return [s for s in self.sb.side("state") if s.startswith("npx#")]

    # --- 1. node -----------------------------------------------------------------------------

    def test_missing_node(self):
        (self.sb.bin / "node").unlink()
        self.expect(self.run_script(), 1, "node is not on PATH")

    def test_node_version_floor_is_22_12(self):
        for version, rc in (("v20.1.0", 1), ("v21.99.0", 1), ("v22.11.0", 1), ("v22.12.0", 0),
                            ("v22.23.0", 0), ("v23.0.0", 0), ("v24.1.0", 0)):
            with self.subTest(version):
                r = self.run_script(STUB_NODE_VERSION=version)
                self.assertEqual(r.returncode, rc, r.stdout + r.stderr)
                if rc:
                    self.assertIn("older than 22.12", r.stderr)
                else:
                    self.assertIn(f"node {version[1:]}", r.stdout)

    def test_home_unset(self):
        self.expect(self.run_script(HOME=None), 1, "HOME is not set")
        self.assertEqual(self.sb.calls(), [])

    # --- 2. dependencies ---------------------------------------------------------------------

    def test_fresh_install_runs_npm_ci_with_the_safe_flags_in_tests_puppeteer(self):
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(self.sb.calls(), [self.NPM_CI])
        # the browser download is deferred to its own step so a failure there names itself
        self.assertEqual(self.sb.side("state"), ["npm skip_download=1"])
        # the script ran in a neutral directory: npm and node got to tests/puppeteer by its own `cd`
        self.assertIn(f"npm {self.pp}", self.sb.side("cwd"))
        self.assertIn(f"node {self.pp}", self.sb.side("cwd"))
        self.assertTrue((self.pp / "node_modules" / "puppeteer").is_dir())
        self.assertEqual(list(self.sb.neutral.iterdir()), [], "nothing may land in the caller's directory")

    def test_up_to_date_modules_skip_npm(self):
        self.install_modules(1_000_000, 1_000_100)
        self.expect(self.run_script(), 0, "already match")
        self.assertEqual(self.sb.calls(), [])

    def test_lockfile_newer_than_modules_reinstalls(self):
        self.install_modules(1_000_100, 1_000_000)
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(self.sb.calls(), [self.NPM_CI])

    def test_failed_npm_ci(self):
        self.expect(self.run_script(STUB_NPM_RC="1"), 1, "npm ci failed")

    # --- timeouts ----------------------------------------------------------------------------

    def test_network_steps_run_under_timeout_or_gtimeout_with_a_kill_grace(self):
        for name in ("timeout", "gtimeout"):
            with self.subTest(name):
                self.sb.reset_logs()
                shutil.rmtree(self.pp / "node_modules", ignore_errors=True)
                self.sb.stub(name, timeout_stub(name))
                self.expect(self.run_script(), 0, "ready")
                # npm ci (install step), then the two probes: executablePath and the launch check
                self.assertEqual(self.sb.calls(), [f"{name} -k 10 600 npm", self.NPM_CI,
                                                   f"{name} -k 10 60 node", f"{name} -k 10 60 node"])
                (self.sb.bin / name).unlink()

    def test_timeouts_are_overridable_and_reach_the_wrapper(self):
        self.sb.stub("timeout", timeout_stub())
        self.exe.unlink()
        self.expect(self.run_script(YUZU_ENSURE_NPM_TIMEOUT="11", YUZU_ENSURE_BROWSER_TIMEOUT="22",
                                    YUZU_ENSURE_LAUNCH_TIMEOUT="33"), 0, "ready")
        self.assertEqual(self.sb.calls(), ["timeout -k 10 11 npm", self.NPM_CI,
                                           "timeout -k 10 60 node",            # executablePath: nothing there
                                           "timeout -k 10 22 npx", self.INSTALL,
                                           "timeout -k 10 60 node",            # executablePath after install
                                           "timeout -k 10 33 node"])           # the launch check

    def test_a_timed_out_step_says_so(self):
        self.sb.stub("timeout", timeout_stub())
        r = self.run_script(STUB_TIMEOUT_RC="124")
        self.expect(r, 1, "npm ci failed")
        self.assertIn("timed out after 600s: npm ci", r.stdout)

    # --- the lock ----------------------------------------------------------------------------

    def test_install_takes_an_exclusive_lock_with_a_bounded_wait(self):
        self.sb.stub("flock", FLOCK)
        xdg = self.sb.tmp / "xdg"
        for name, env, lock, wait in (
                ("default", {}, self.sb.home / ".cache", 2400),
                ("XDG_CACHE_HOME and an override", {"XDG_CACHE_HOME": str(xdg),
                                                    "YUZU_ENSURE_LOCK_TIMEOUT": "7"}, xdg, 7)):
            with self.subTest(name):
                self.sb.reset_logs()
                shutil.rmtree(self.pp / "node_modules", ignore_errors=True)
                self.expect(self.run_script(**env), 0, "ready")
                self.assertIn(f"flock -w {wait} 9", self.sb.calls())
                self.assertTrue((lock / "yuzu-ensure-puppeteer.lock").exists())

    def test_lock_file_is_opened_for_append_never_truncated(self):
        self.sb.stub("flock", FLOCK)
        lock = self.write(self.sb.tmp / "xdg" / "yuzu-ensure-puppeteer.lock", "held by someone\n")
        self.expect(self.run_script(XDG_CACHE_HOME=str(self.sb.tmp / "xdg")), 0, "ready")
        self.assertEqual(lock.read_text(), "held by someone\n")

    def test_a_symlinked_lock_file_is_refused_and_its_target_untouched(self):
        self.sb.stub("flock", FLOCK)
        xdg = self.sb.tmp / "xdg"
        xdg.mkdir()
        victim = self.write(self.sb.tmp / "victim.txt", "precious\n")
        dangling = self.sb.tmp / "not-yet.txt"
        for name, target in (("existing target", victim), ("dangling target", dangling)):
            with self.subTest(name):
                self.sb.reset_logs()
                (xdg / "yuzu-ensure-puppeteer.lock").unlink(missing_ok=True)
                (xdg / "yuzu-ensure-puppeteer.lock").symlink_to(target)
                self.expect(self.run_script(XDG_CACHE_HOME=str(xdg)), 1, "symlink")
                self.assertEqual(victim.read_text(), "precious\n")
                self.assertFalse(dangling.exists(), "the link must not be written through")
                self.assertEqual(self.sb.calls(), [])  # neither flock nor npm ran

    def test_lock_wait_that_times_out_is_not_ready(self):
        self.sb.stub("flock", FLOCK)
        self.expect(self.run_script(STUB_FLOCK_RC="1"), 1, "timed out waiting for another")
        self.assertNotIn(self.NPM_CI, self.sb.calls())

    def test_install_steps_keep_the_lock_descriptor_and_probes_do_not(self):
        # An orphaned npm/npx must keep the lock (the next run waits for it instead of racing it); a
        # probe (executablePath, the launch check, `--version`, ldd) must never hold it. The flow runs
        # every one of them: npm ci, a launch that fails, ldd, the binary's own --version (broken), a
        # heal, npx, and a launch that works.
        for with_timeout in (False, True):
            with self.subTest(with_timeout=with_timeout):
                self.sb.reset_logs()
                shutil.rmtree(self.pp / "node_modules", ignore_errors=True)
                self.make_browser()
                self.exe.write_text(BROWSER_BROKEN_OBS)
                self.sb.stub("flock", FLOCK)
                self.sb.stub("ldd", LDD_ALL_FOUND_OBS)
                if with_timeout:
                    self.sb.stub("timeout", timeout_stub())
                self.expect(self.run_script(STUB_LAUNCH="fail ok"), 0, "ready")
                self.assertEqual(self.npx_calls(), [self.INSTALL])  # the heal path really ran
                self.assert_fd9(self.sb.side("fd9"), install_tags=("npm", "npx"),
                                probe_tags=("node", "ldd", "chrome"))
                (self.sb.bin / "timeout").unlink(missing_ok=True)

    def test_a_lock_file_that_is_not_a_regular_file_is_refused_not_blocked_on(self):
        self.sb.stub("flock", FLOCK)
        xdg = self.sb.tmp / "xdg"
        self.fifo(xdg / "yuzu-ensure-puppeteer.lock")
        self.expect(self.run_script(XDG_CACHE_HOME=str(xdg)), 1, "not a regular file")
        self.assertEqual(self.sb.calls(), [])  # neither flock nor npm ran

    # --- 3. the browser ---------------------------------------------------------------------

    def test_missing_browser_is_installed(self):
        self.exe.unlink()
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(self.npx_calls(), [self.INSTALL])

    def test_node_that_cannot_load_puppeteer_says_so_and_does_not_download(self):
        # A broken import must not read as "browser absent": no pointless download, and node's own
        # error stays visible.
        r = self.run_script(STUB_EXEPATH_ERR="1")
        self.expect(r, 1, "node could not load puppeteer")
        self.assertIn("Cannot find package 'puppeteer'", r.stderr)
        self.assertEqual(self.npx_calls(), [])

    def test_install_that_reports_success_without_a_binary_is_not_ready(self):
        self.exe.unlink()
        self.expect(self.run_script(STUB_NPX_CREATES="0"), 1, "not where puppeteer looks")

    def test_install_failing_twice_is_not_ready(self):
        self.exe.unlink()
        self.expect(self.run_script(STUB_NPX="fail fail"), 1, "failed twice")
        self.assertEqual(len(self.npx_calls()), 2)

    def test_first_install_failure_heals_the_build_dir_and_retries_once(self):
        # an interrupted download: the build directory exists with no binary, a stale archive beside it
        self.exe.unlink()
        (self.build / "chrome-linux64").mkdir(parents=True, exist_ok=True)
        stale = self.write(self.chrome / "chrome-linux64-1.2.3.zip", "partial")
        unrelated = self.write(self.chrome / "notes.zip", "not a browser archive")
        keep = self.make_browser(self.chrome / "linux-9.9.9" / "chrome-linux64" / "chrome")
        r = self.run_script(STUB_NPX="fail ok")
        self.expect(r, 0, "ready")
        self.assertEqual(self.npx_calls(), [self.INSTALL, self.INSTALL])
        # the first call saw the damage; by the retry the build dir and the chrome archive were cleared
        self.assertEqual(self.npx_states(), ["npx#1 dir=1 zip=1", "npx#2 dir=0 zip=0"])
        self.assertFalse(stale.exists())
        self.assertTrue(unrelated.exists(), "only archives with chrome in the name are removed")
        self.assertTrue(keep.exists(), "another build in the cache must be left alone")
        self.assertIn("removing the partial browser install", r.stdout)

    def test_launch_failure_from_missing_libraries_names_them_and_does_not_reinstall(self):
        # even a binary that cannot print its version is not reinstalled when libraries are missing
        self.make_browser(runs=False)
        self.sb.stub("ldd", LDD_MISSING_NSS)
        r = self.run_script(STUB_LAUNCH="fail")
        self.expect(r, 1, "libnss3.so => not found")
        self.assertIn("a reinstall will not help", r.stderr)
        self.assertIn("boom", r.stderr)  # the launch output is shown
        self.assertEqual(self.npx_calls(), [])
        self.assertEqual(self.sb.side("ldd"), [str(self.exe)])
        self.assertTrue(self.exe.exists())

    def test_a_browser_that_runs_but_will_not_launch_is_never_deleted(self):
        # e.g. an unwritable TMPDIR: the binary prints its version, so it is healthy
        stale = self.write(self.chrome / "chrome-linux64-1.2.3.zip", "kept")
        for name, ldd in (("no ldd", None), ("ldd finds every library", LDD_ALL_FOUND)):
            with self.subTest(name):
                self.sb.reset_logs()
                if ldd:
                    self.sb.stub("ldd", ldd)
                r = self.run_script(STUB_LAUNCH="fail")
                self.expect(r, 1, "NOT reinstalled")
                self.assertIn("boom", r.stderr)
                self.assertIn("Last line: boom", r.stderr)
                self.assertEqual(self.npx_calls(), [])
                self.assertEqual(self.exe.read_text(), BROWSER_RUNS)
                self.assertTrue(stale.exists())
                self.assertEqual(self.sb.side("launches"), ["1"])

    def test_launch_failure_of_a_broken_binary_heals_and_reinstalls_once(self):
        self.make_browser(runs=False)
        self.sb.stub("ldd", LDD_ALL_FOUND)
        r = self.run_script(STUB_LAUNCH="fail ok")
        self.expect(r, 0, "ready")
        self.assertIn("reinstalling it once", r.stdout)
        self.assertIn("launched Chrome/1", r.stdout)
        self.assertEqual(self.npx_calls(), [self.INSTALL])
        self.assertEqual(self.npx_states(), ["npx#1 dir=0 zip=0"])
        self.assertEqual(self.sb.side("launches"), ["2"])

    def test_heal_finds_the_cache_the_way_puppeteer_does(self):
        home_cache = self.sb.home / ".cache" / "puppeteer"
        for name, env_cache, base in (("trailing slash", f"{self.cache}/", self.cache),
                                      ("default under HOME", None, home_cache)):
            with self.subTest(name):
                self.sb.reset_logs()
                exe = self.make_browser(base / "chrome" / "linux-1.2.3" / "chrome-linux64" / "chrome",
                                        runs=False)
                r = self.run_script(STUB_EXE=str(exe), PUPPETEER_CACHE_DIR=env_cache, STUB_LAUNCH="fail ok")
                self.expect(r, 0, "ready")
                self.assertIn("removing the partial browser install", r.stdout)
                self.assertEqual(self.npx_states(), ["npx#1 dir=0 zip=0"])

    def test_browser_that_never_launches_fails_after_exactly_one_reinstall(self):
        self.make_browser(runs=False)
        r = self.run_script(STUB_LAUNCH="fail")
        self.expect(r, 1, "will not start headless")
        self.assertIn("after a reinstall", r.stderr)
        self.assertEqual(self.npx_calls(), [self.INSTALL])
        self.assertEqual(self.sb.side("launches"), ["2"])

    def test_launch_failure_with_an_explicit_browser_never_touches_it(self):
        # The user's (broken) binary sits in a perfectly healable cache layout: only
        # PUPPETEER_EXECUTABLE_PATH may be what protects it.
        mine = self.make_browser(self.chrome / "linux-7.7.7" / "chrome-linux64" / "chrome", runs=False)
        self.write(self.chrome / "chrome-mine.zip", "x")
        r = self.run_script(STUB_LAUNCH="fail", PUPPETEER_EXECUTABLE_PATH=str(mine))
        self.expect(r, 1, "left alone")
        self.assertEqual(self.npx_calls(), [])
        self.assertEqual(mine.read_text(), BROWSER_BROKEN)
        self.assertTrue((self.chrome / "chrome-mine.zip").exists())

    def test_broken_browser_outside_puppeteers_chrome_cache_is_left_alone(self):
        # A path printed by puppeteer that is not <cache>/chrome/<build>/... is never deleted from.
        # Relative to the script's working directory (the neutral dir), which exists for the checks.
        relative = Path("rel") / "linux-1.2.3" / "chrome-linux64" / "chrome"
        cases = (
            ("another directory", str(self.sb.tmp / "elsewhere" / "linux-1.2.3" / "chrome-linux64" / "chrome"),
             self.sb.tmp / "elsewhere" / "linux-1.2.3" / "chrome-linux64" / "chrome"),
            ("outside via ..", f"{self.chrome}/../outside/chrome", self.cache / "outside" / "chrome"),
            ("a relative path", str(relative), self.sb.neutral / relative),
            ("beside, not under, chrome", str(self.cache / "chrome-other" / "linux-1.2.3" / "chrome"),
             self.cache / "chrome-other" / "linux-1.2.3" / "chrome"),
        )
        stale = self.write(self.chrome / "chrome-linux64-1.2.3.zip", "kept")
        for name, printed, real in cases:
            with self.subTest(name):
                self.sb.reset_logs()
                self.make_browser(real, runs=False)
                r = self.run_script(STUB_LAUNCH="fail", STUB_EXE=printed)
                self.expect(r, 1, "left alone")
                self.assertIn("boom", r.stderr)
                self.assertEqual(self.npx_calls(), [])
                self.assertTrue(real.exists())
                self.assertTrue(stale.exists())

    def test_explicit_browser_path_that_is_missing_never_downloads(self):
        r = self.run_script(PUPPETEER_EXECUTABLE_PATH="/nonexistent/chrome")
        self.expect(r, 1, "nothing is there")
        self.assertEqual(self.npx_calls(), [])

    def test_explicit_browser_path_that_exists_is_used_as_is(self):
        mine = self.make_browser(self.sb.tmp / "mine" / "chrome")
        r = self.run_script(PUPPETEER_EXECUTABLE_PATH=str(mine))
        self.expect(r, 0, "browser already present")
        self.assertEqual(self.npx_calls(), [])

    # --- the exact timeout argv ----------------------------------------------------------------

    def test_every_probe_and_install_step_has_its_own_timeout(self):
        # a broken browser through the whole recovery path, with distinct launch and default timeouts
        self.install_modules(1_000_000, 1_000_100)
        self.make_browser(runs=False)
        self.sb.stub("ldd", LDD_ALL_FOUND)
        self.sb.stub("timeout", timeout_stub())
        r = self.run_script(STUB_LAUNCH="fail ok", YUZU_ENSURE_LAUNCH_TIMEOUT="33")
        self.expect(r, 0, "ready")
        self.assertEqual(self.sb.calls(), [
            "timeout -k 10 60 node",                      # executablePath
            "timeout -k 10 33 node",                      # launch check: fails
            "timeout -k 10 60 node",                      # executablePath, for the diagnosis
            "timeout -k 10 20 ldd",
            f"timeout -k 10 20 {self.exe}",               # the binary's own --version
            "timeout -k 10 60 node",                      # executablePath, inside the heal
            "timeout -k 10 900 npx", self.INSTALL,        # the reinstall
            "timeout -k 10 33 node"])                     # launch check: works

    def test_the_timeout_wrapper_gets_foreground_only_with_a_terminal_on_stdin(self):
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.sb.stub("timeout", timeout_stub())
        try:
            self.expect(self.run_script(stdin=slave), 0, "ready")
        finally:
            os.close(slave)
        calls = self.sb.calls()
        self.assertIn("timeout --foreground -k 10 600", calls)
        self.assertNotIn("timeout -k 10 600 npm", calls)
        # and the wrapped command still ran
        self.assertIn(self.NPM_CI, calls)

    # --- the cache directory the heal trusts ---------------------------------------------------

    def test_a_relative_cache_dir_is_never_healed(self):
        # puppeteer resolves a relative PUPPETEER_CACHE_DIR against ITS OWN working directory, not ours,
        # so a textual match proves nothing: the browser below sits exactly where the string says, and
        # still must not be removed.
        rel = Path("rel_cache") / "chrome" / "linux-1.2.3" / "chrome-linux64" / "chrome"
        real = self.make_browser(self.sb.neutral / rel, runs=False)
        stale = self.write(self.sb.neutral / "rel_cache" / "chrome" / "chrome-linux64-1.2.3.zip", "kept")
        r = self.run_script(PUPPETEER_CACHE_DIR="rel_cache", STUB_EXE=str(rel), STUB_LAUNCH="fail")
        self.expect(r, 1, "not inside puppeteer's own cache directory")
        self.assertEqual(self.npx_calls(), [])
        self.assertEqual(real.read_text(), BROWSER_BROKEN)
        self.assertTrue(stale.exists())
        self.assertNotIn("removing the partial browser install", r.stdout)

    def test_a_home_with_a_trailing_slash_still_matches_the_default_cache_dir(self):
        exe = self.make_browser(self.sb.home / ".cache" / "puppeteer" / "chrome" / "linux-1.2.3"
                                / "chrome-linux64" / "chrome", runs=False)
        r = self.run_script(HOME=f"{self.sb.home}/", PUPPETEER_CACHE_DIR=None, STUB_EXE=str(exe),
                            STUB_LAUNCH="fail ok")
        self.expect(r, 0, "ready")
        self.assertIn("removing the partial browser install", r.stdout)
        self.assertEqual(self.npx_states(), ["npx#1 dir=0 zip=0"])

    # --- a browser that cannot print its version: incomplete, or merely unrunnable? -------------

    def elf_case(self, data, mode=0o755):
        """The browser is these bytes (a file nothing can execute), its launch fails, no library is
        missing (there is no ldd) and `--version` fails too: the script must decide from the bytes."""
        stale = self.write(self.chrome / "chrome-linux64-1.2.3.zip", "stale")
        keep = self.make_browser(self.chrome / "linux-9.9.9" / "chrome-linux64" / "chrome")
        exe = self.make_binary(data, mode=mode)
        return exe, stale, keep

    def assert_left_alone(self, r, exe, data, stale, keep):
        self.expect(r, 1, "complete but cannot run")
        self.assertIn("NOT reinstalled", r.stderr)
        self.assertEqual(self.npx_calls(), [], "a complete binary must not be reinstalled")
        self.assertEqual(exe.read_bytes(), data)
        self.assertTrue(self.build.is_dir())
        self.assertTrue(stale.exists())
        self.assertTrue(keep.exists())
        self.assertEqual(self.sb.side("launches"), ["1"])

    def assert_healed(self, r, exe, stale, keep):
        self.expect(r, 0, "ready")
        self.assertIn("reinstalling it once", r.stdout)
        self.assertEqual(self.npx_calls(), [self.INSTALL])
        # the build directory and the archive were gone by the time the installer ran
        self.assertEqual(self.npx_states(), ["npx#1 dir=0 zip=0"])
        self.assertFalse(stale.exists())
        self.assertTrue(keep.exists(), "another build in the cache must be left alone")
        self.assertEqual(self.sb.side("launches"), ["2"])

    def test_a_structurally_complete_elf_that_cannot_run_is_left_in_place(self):
        # Intact section-header table (the header's own fields describe a file that ends exactly where
        # this one does, or later): a limit or a sandbox stopped it, a download cannot help.
        for name, data in (
                ("exactly at the end of the table", elf_bytes(shoff=64, shentsize=64, shnum=3, shstrndx=2,
                                                              size=256)),
                ("padded past it", elf_bytes(size=4096)),
                ("a table further in", elf_bytes(shoff=2048, shentsize=64, shnum=10, shstrndx=9, size=4096)),
                ("a wide table entry", elf_bytes(shoff=64, shentsize=256, shnum=2, shstrndx=1, size=576))):
            with self.subTest(name):
                self.sb.reset_logs()
                exe, stale, keep = self.elf_case(data)
                r = self.run_script(STUB_LAUNCH="fail")
                self.assert_left_alone(r, exe, data, stale, keep)

    def test_a_complete_elf_is_left_in_place_whatever_ldd_says_about_libraries_it_finds(self):
        data = elf_bytes(size=4096)
        self.sb.stub("ldd", LDD_ALL_FOUND)
        exe, stale, keep = self.elf_case(data)
        self.assert_left_alone(self.run_script(STUB_LAUNCH="fail"), exe, data, stale, keep)

    def test_an_elf_cut_short_is_healed_and_reinstalled_once(self):
        for name, data in (
                ("table starts beyond the end", elf_bytes(shoff=1_000_000, size=4096)),
                ("table runs past the end", elf_bytes(shoff=64, shentsize=64, shnum=100, shstrndx=99,
                                                      size=4096)),
                ("one byte short of the table", elf_bytes(shoff=64, shentsize=64, shnum=3, shstrndx=2,
                                                          size=255)),
                ("table offset with the sign bit set", elf_bytes(shoff=(1 << 64) - 256, size=4096)),
                ("shorter than a header, with the magic", elf_bytes(size=10)),
                ("one byte shorter than a header", elf_bytes(size=63)),
                ("only the magic", b"\x7fELF")):
            with self.subTest(name):
                self.sb.reset_logs()
                exe, stale, keep = self.elf_case(data)
                r = self.run_script(STUB_LAUNCH="fail ok")
                self.assert_healed(r, exe, stale, keep)

    def test_a_zero_length_browser_is_healed(self):
        # Not executable: browser_runs refuses it before it is ever run (see the note in the report
        # about an EXECUTABLE empty file, which a shell happily "runs").
        exe, stale, keep = self.elf_case(b"", mode=0o644)
        self.assert_healed(self.run_script(STUB_LAUNCH="fail ok"), exe, stale, keep)

    def test_a_file_that_is_not_an_elf_is_healed(self):
        for name, data in (
                ("garbage", bytes(range(256)) * 4),
                ("text", b"this is not a browser\n" * 20),
                ("a shell script", BROWSER_BROKEN.encode()),
                ("a shell script behind a #! line, 64 bytes or more",
                 b"#!/bin/sh\n" + b"# padding padding padding padding padding padding padding\n" + b"exit 1\n"),
                ("a Mach-O header (macOS)", bytes.fromhex("cffaedfe0c000001") + bytes(4096))):
            with self.subTest(name):
                self.sb.reset_logs()
                exe, stale, keep = self.elf_case(data)
                self.assert_healed(self.run_script(STUB_LAUNCH="fail ok"), exe, stale, keep)

    def test_an_elf_that_is_not_64_bit_little_endian_is_not_trusted_as_complete(self):
        # The size arithmetic only holds for ELF64 little endian; for anything else there is no
        # evidence either way, and the conservative answer is the pre-existing one: reinstall once.
        for name, data in (("32-bit", elf_bytes(ei_class=1, size=4096)),
                           ("big-endian", elf_bytes(ei_data=2, size=4096)),
                           ("unknown class", elf_bytes(ei_class=0, size=4096)),
                           ("unknown data encoding", elf_bytes(ei_data=0, size=4096))):
            with self.subTest(name):
                self.sb.reset_logs()
                exe, stale, keep = self.elf_case(data)
                self.assert_healed(self.run_script(STUB_LAUNCH="fail ok"), exe, stale, keep)

    def test_a_complete_elf_that_will_not_launch_after_the_missing_library_check_is_still_not_deleted(self):
        # the library check wins first, and it also leaves the file alone
        data = elf_bytes(size=4096)
        exe, stale, keep = self.elf_case(data)
        self.sb.stub("ldd", LDD_MISSING_NSS)
        r = self.run_script(STUB_LAUNCH="fail")
        self.expect(r, 1, "libnss3.so => not found")
        self.assertEqual(self.npx_calls(), [])
        self.assertEqual(exe.read_bytes(), data)

    def test_a_truncated_elf_stays_healed_only_once(self):
        # still broken after the single reinstall: stop, do not loop
        exe, stale, keep = self.elf_case(elf_bytes(shoff=1_000_000, size=4096))
        r = self.run_script(STUB_LAUNCH="fail")
        self.expect(r, 1, "after a reinstall")
        self.assertEqual(self.npx_calls(), [self.INSTALL])

    # --- macOS layout: an .app bundle several directories deep, with spaces in its names --------

    def test_macos_layout_heals_the_whole_build_directory_and_its_archive(self):
        build = self.chrome / "mac_arm-1.2.3"
        app = build / "chrome-mac-arm64" / "Google Chrome for Testing.app" / "Contents" / "MacOS"
        exe = app / "Google Chrome for Testing"
        self.make_browser(exe, runs=False)
        leftover = self.write(build / "chrome-mac-arm64" / "leftover.txt", "half-extracted")
        stale = self.write(self.chrome / "1.2.3-chrome-mac-arm64.zip", "partial")
        unrelated = self.write(self.chrome / "notes.zip", "not a browser archive")
        other = self.make_browser(self.chrome / "mac_arm-9.9.9" / "chrome-mac-arm64" / "Google Chrome for Testing.app"
                                  / "Contents" / "MacOS" / "Google Chrome for Testing")
        r = self.run_script(STUB_EXE=str(exe), STUB_BUILD=str(build), STUB_LAUNCH="fail ok")
        self.expect(r, 0, "ready")
        self.assertIn(f"removing the partial browser install at {build}", r.stdout)
        self.assertEqual(self.npx_calls(), [self.INSTALL])
        self.assertEqual(self.npx_states(), ["npx#1 dir=0 zip=0"])  # gone by the time the installer ran
        self.assertFalse(leftover.exists())
        self.assertFalse(stale.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue(other.exists(), "the other build must survive")
        self.assertTrue(exe.exists(), "the reinstall put the browser back")
        self.assertEqual(self.sb.side("launches"), ["2"])


class GcovrCase(SandboxCase):
    SCRIPT = "ensure-gcovr.sh"

    def setUp(self):
        super().setUp()
        self.sb.stub("python3", PYTHON3)
        self.link = self.sb.home / ".local" / "bin" / "gcovr"
        self.stamp = self.sb.venv / ".requirements-ci.sha256"

    def run_script(self, local_bin=True, **env):
        return self.sb.run(self.SCRIPT, local_bin=local_bin, **env)

    def pip_calls(self):
        return [c for c in self.sb.calls() if c.startswith("pip ")]

    def venv_creations(self):
        return [c for c in self.sb.calls() if c.startswith("python3 -m venv ")]

    def build(self, **env):
        """A first, successful install; leaves calls.log empty afterwards."""
        self.expect(self.run_script(**env), 0, "ready")
        self.sb.reset_logs()

    def old_dirs(self, venv=None):
        """The moved-aside previous venvs: <venv>.yuzu-gcovr-old.<pid>, a name only the script uses."""
        venv = venv or self.sb.venv
        return sorted(p.name for p in venv.parent.glob(venv.name + ".yuzu-gcovr-old.*"))


class EnsureGcovrNonLinux(GcovrCase):
    """Runs everywhere (it stubs uname)."""

    def test_non_linux_is_a_no_op(self):
        self.sb.stub("uname", UNAME_DARWIN)
        self.expect(self.run_script(), 0, "not Linux")
        self.assertEqual(self.sb.calls(), [])
        self.assertFalse(self.sb.venv.exists())


@unittest.skipUnless(IS_LINUX, "ensure-gcovr.sh only does anything on Linux (it gates on uname -s)")
class EnsureGcovr(GcovrCase):
    # --- ready / no-op -----------------------------------------------------------------------

    def test_fresh_install_hash_verifies_and_links(self):
        self.expect(self.run_script(), 0, "ready (gcovr 8.7)")
        pip = self.pip_calls()
        self.assertEqual(len(pip), 1)
        self.assertIn("--require-hashes", pip[0])
        self.assertIn(str(self.sb.repo / "requirements-ci.txt"), pip[0])
        self.assertEqual(os.readlink(self.link), str(self.sb.venv / "bin" / "gcovr"))
        self.assertEqual(self.stamp.read_text().strip(), self.sb.req_sha())
        # the marker is written BEFORE venv creation, so a build killed mid-way is recognisably ours
        self.assertEqual(self.sb.side("venv"), ["marker=1 aside=0"])
        self.assertTrue((self.sb.venv / ".yuzu-gcovr-venv").exists())

    def test_repeat_run_is_a_no_op(self):
        self.build()
        self.expect(self.run_script(), 0, "already installed")
        self.assertEqual(self.sb.calls(), [])

    def test_a_second_run_straight_after_the_first_installs_nothing(self):
        # the Phase 7b shape: /test runs the helper in Phase 0b and again before the coverage gate
        self.expect(self.run_script(), 0, "ready")
        self.expect(self.run_script(), 0, "already installed")
        self.assertEqual(len(self.pip_calls()), 1)
        self.assertEqual(len(self.venv_creations()), 1)

    def test_unmanaged_gcovr_at_the_pin_is_accepted_after_the_capability_probe(self):
        self.sb.stub("gcovr", gcovr_stub("8.7"))
        (self.sb.bin / "python3").unlink()  # nothing here may need python
        r = self.run_script()
        self.expect(r, 0, "using gcovr 8.7")
        self.assertIn(str(self.sb.bin / "gcovr"), r.stdout)
        self.assertEqual(self.sb.calls(), [])
        self.assertFalse(self.sb.venv.exists())
        self.assertFalse(self.link.exists() or self.link.is_symlink())
        # the probe asks for what coverage-gate.sh asks for, on an empty tree in a scratch directory
        (probe,) = self.sb.side("probe")
        cwd, args = probe.split(" ", 1)
        self.assertEqual(args, "--root . --json-summary j.json --xml x.xml --html --html-details -o i.html .")
        self.assertEqual(Path(cwd).parent, self.sb.tmpdir)
        self.assertTrue(Path(cwd).name.startswith("yuzu_test_gcovr_probe."))
        self.assertEqual(list(self.sb.tmpdir.iterdir()), [], "the scratch directory is removed")

    def test_probe_runs_under_timeout(self):
        self.sb.stub("gcovr", gcovr_stub("8.7"))
        self.sb.stub("timeout", timeout_stub())
        self.expect(self.run_script(), 0, "using gcovr 8.7")
        # the version lookup (20 s), then the capability probe (60 s)
        self.assertEqual(self.sb.calls(), ["timeout -k 10 20 gcovr", "timeout -k 10 60 gcovr"])

    def test_the_managed_venv_probes_each_have_a_timeout(self):
        self.sb.stub("timeout", timeout_stub())
        self.build()
        self.expect(self.run_script(), 0, "already installed")
        self.assertEqual(self.sb.calls(), ["timeout -k 10 20 gcovr",                       # PATH's gcovr
                                           f"timeout -k 10 20 {self.sb.venv}/bin/gcovr",   # venv_version
                                           f"timeout -k 10 30 {self.sb.venv}/bin/python"])  # venv_healthy

    def test_unmanaged_gcovr_that_fails_the_probe_is_not_accepted(self):
        # reports the pin but cannot produce the reports (a dependency missing): the managed one is
        # installed, and since ~/.local/bin precedes it on PATH, ours is what resolves afterwards
        self.sb.stub("gcovr", gcovr_stub("8.7", probe_rc=1), where=self.sb.farm)
        self.expect(self.run_script(), 0, "ready (gcovr 8.7)")
        self.assertEqual(len(self.pip_calls()), 1)
        self.assertEqual(len(self.sb.side("probe")), 1)
        self.assertEqual(os.readlink(self.link), str(self.sb.venv / "bin" / "gcovr"))

    def test_unmanaged_gcovr_at_another_version_is_replaced_but_a_shadow_after_install_is_refused(self):
        self.sb.stub("gcovr", gcovr_stub("8.6"))
        r = self.run_script()
        self.expect(r, 1, "which reports '8.6'")
        self.assertIn("PATH resolves 'gcovr' to", r.stderr)
        self.assertEqual(len(self.pip_calls()), 1)  # it did install; only the PATH entry is wrong

    def test_same_version_shadow_that_cannot_produce_reports_is_refused_after_install(self):
        self.sb.stub("gcovr", gcovr_stub("8.7", probe_rc=1))  # ahead of ~/.local/bin on PATH
        r = self.run_script()
        self.expect(r, 1, "cannot produce the coverage reports")
        self.assertEqual(len(self.pip_calls()), 1)
        self.assertEqual(len(self.sb.side("probe")), 2)  # once before the install, once after

    def test_same_version_shadow_that_works_is_accepted_after_install(self):
        # The ready-check already accepts it, so nothing is installed; this pins the other half.
        self.sb.stub("gcovr", gcovr_stub("8.7", probe_rc=0))
        self.expect(self.run_script(), 0, "using gcovr 8.7")
        self.assertEqual(self.pip_calls(), [])

    def test_stale_requirements_stamp_rebuilds(self):
        self.build()
        self.stamp.write_text("deadbeef\n")
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(len(self.pip_calls()), 1)
        self.assertEqual(self.stamp.read_text().strip(), self.sb.req_sha())

    def test_unhealthy_venv_is_rebuilt(self):
        self.build()
        self.expect(self.run_script(STUB_VENV_HEALTHY="0"), 0, "ready")
        self.assertEqual(len(self.pip_calls()), 1)
        self.assertEqual(self.old_dirs(), [])

    def test_complete_managed_venv_with_a_missing_link_is_relinked_not_rebuilt(self):
        self.build()
        self.link.unlink()
        # the python3 / ensurepip prerequisites are only checked when a build is needed
        (self.sb.bin / "python3").unlink()
        self.expect(self.run_script(), 0, "(re)linking")
        self.assertEqual(self.sb.calls(), [])
        self.assertEqual(os.readlink(self.link), str(self.sb.venv / "bin" / "gcovr"))
        self.assertEqual(self.stamp.read_text().strip(), self.sb.req_sha())

    def test_complete_managed_venv_shadowed_on_path_is_not_rebuilt(self):
        self.build()
        sentinel = self.write(self.sb.venv / "sentinel", "old\n")
        self.sb.stub("gcovr", gcovr_stub("8.6"))  # something else ahead of the link on PATH
        r = self.run_script()
        self.expect(r, 1, "which reports '8.6'")
        self.assertEqual(self.sb.calls(), [], "a rebuild would change nothing, so none may happen")
        self.assertTrue(sentinel.exists())
        self.assertEqual(self.old_dirs(), [])

    # --- rebuild safety ----------------------------------------------------------------------

    def test_rebuild_moves_the_old_venv_aside_then_removes_it(self):
        self.build()
        (self.sb.venv / "sentinel").write_text("old\n")
        self.stamp.write_text("deadbeef\n")
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(self.sb.side("venv"), ["marker=1 aside=1"])  # old copy visible while building
        self.assertEqual(self.old_dirs(), [])
        self.assertFalse((self.sb.venv / "sentinel").exists())

    def test_failing_pip_leaves_a_state_the_next_run_recovers_from(self):
        self.build()
        (self.sb.venv / "sentinel").write_text("old\n")
        self.stamp.write_text("deadbeef\n")
        self.expect(self.run_script(STUB_PIP_RC="1"), 1, "pip could not install")
        # the half-built venv is ours (marker, no stamp) and the previous one is still on disk
        self.assertTrue((self.sb.venv / ".yuzu-gcovr-venv").exists())
        self.assertFalse(self.stamp.exists())
        self.assertEqual(len(self.old_dirs()), 1)
        self.assertTrue((self.sb.venv.parent / self.old_dirs()[0] / "sentinel").exists())
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(self.stamp.read_text().strip(), self.sb.req_sha())
        self.assertEqual(self.old_dirs(), [])

    def test_failing_pip_on_a_fresh_box_is_recoverable_too(self):
        self.expect(self.run_script(STUB_PIP_RC="1"), 1, "pip could not install")
        self.expect(self.run_script(), 0, "ready")

    def test_populated_non_venv_directory_is_never_deleted(self):
        self.sb.venv.mkdir()
        (self.sb.venv / "precious.txt").write_text("keep\n")
        r = self.run_script()
        self.expect(r, 1, "refusing to replace")
        self.assertIn("remove it by hand (rm -rf)", r.stderr)  # says how to recover from a leftover
        self.assertEqual([p.name for p in self.sb.venv.iterdir()], ["precious.txt"])
        self.assertEqual(self.venv_creations(), [])
        self.assertEqual(self.old_dirs(), [])

    def test_a_plain_python_venv_is_not_ours_and_is_never_deleted(self):
        # any virtualenv has a pyvenv.cfg; a project's own .venv must survive YUZU_GCOVR_VENV pointing at it
        for name, files in (("pyvenv.cfg only", ["pyvenv.cfg"]),
                            ("a real-looking venv", ["pyvenv.cfg", "bin/python", "lib/site.py"])):
            with self.subTest(name):
                venv = self.sb.tmp / ("project_" + str(len(files)))
                for f in files:
                    self.write(venv / f, "x\n")
                self.sb.reset_logs()
                r = self.run_script(YUZU_GCOVR_VENV=str(venv))
                self.expect(r, 1, "refusing to replace")
                self.assertIn("rm -rf", r.stderr)
                self.assertEqual(sorted(str(p.relative_to(venv)) for p in venv.rglob("*") if p.is_file()),
                                 sorted(files))
                self.assertEqual(self.venv_creations(), [])
                self.assertEqual(self.pip_calls(), [])
                self.assertEqual(self.old_dirs(venv), [])
                self.assertFalse(self.link.is_symlink())

    def test_directories_the_guard_accepts_are_replaced(self):
        # (files present in the existing $VENV) -> accepted as ours / empty, so rebuilt in place
        for i, (name, files) in enumerate((
                ("empty directory", []),
                ("half-built venv: marker only, no pyvenv.cfg", [".yuzu-gcovr-venv"]),
                ("finished venv of ours: requirements stamp only", [".requirements-ci.sha256"]))):
            with self.subTest(name):
                venv = self.sb.tmp / f"venv_{i}"
                venv.mkdir()
                for f in files:
                    (venv / f).write_text("x\n")
                self.sb.reset_logs()
                self.link.unlink(missing_ok=True)  # the previous case's link would read as "a gcovr at the pin"
                self.expect(self.run_script(YUZU_GCOVR_VENV=str(venv)), 0, "ready")
                self.assertEqual(len(self.pip_calls()), 1)
                self.assertEqual(self.sb.side("venv"), ["marker=1 aside=0"])
                self.assertEqual((venv / ".requirements-ci.sha256").read_text().strip(), self.sb.req_sha())
                # A replaced $VENV is moved aside and removed; nothing (not even an empty husk) may remain.
                self.assertEqual(self.old_dirs(venv), [])

    def test_old_venv_leftovers_are_removed_by_name_only(self):
        parent, name = self.sb.venv.parent, self.sb.venv.name
        removed, kept = [], []
        for suffix, files in (("123", []),                       # empty (a kill mid-delete)
                              ("99", []),                        # empty, no markers of any kind
                              ("456", ["bin/x"]),                # half-deleted
                              ("789", ["notes.txt"]),            # not even a venv: ours by NAME
                              ("", ["notes.txt"]),               # whatever follows the dot
                              ("x12", ["notes.txt"])):
            d = parent / f"{name}.yuzu-gcovr-old.{suffix}"
            d.mkdir()
            for f in files:
                self.write(d / f, "x\n")
            removed.append(d)
        # Nothing else: other people's `.old.N` directories (the name this script used to claim), names
        # that merely start like ours, and anything that is not a directory.
        for leftover in (f"{name}.old.3", f"{name}.old.123", f"{name}.old.keep", f"{name}.old.",
                         f"{name}.yuzu-gcovr-old", f"{name}.yuzu-gcovr-oldx",
                         f"other.yuzu-gcovr-old.1", f"{name}x.yuzu-gcovr-old.1"):
            kept.append(self.write(parent / leftover / "notes.txt", "not ours\n"))
        a_file = self.write(parent / f"{name}.yuzu-gcovr-old.55", "a file, not a directory\n")
        target = self.write(self.sb.tmp / "linked_target" / "notes.txt", "target\n")
        link = parent / f"{name}.yuzu-gcovr-old.999"
        link.symlink_to(target.parent)
        self.expect(self.run_script(), 0, "ready")
        for d in removed:
            self.assertFalse(d.exists(), d.name)
        for f in kept:
            self.assertEqual(f.read_text(), "not ours\n", f.parent.name)
        self.assertEqual(a_file.read_text(), "a file, not a directory\n")
        self.assertTrue(link.is_symlink(), "a symlink is never taken for a leftover")
        self.assertEqual(target.read_text(), "target\n")

    def test_a_symlinked_leftover_is_never_followed(self):
        # The victim holds a file; a symlink with the leftover's name points at it. Neither the first
        # sweep (before the build) nor the one after it may reach through the link.
        victim = self.write(self.sb.tmp / "victim" / "precious.txt", "precious\n")
        deep = self.write(self.sb.tmp / "victim" / "sub" / "also.txt", "also\n")
        link = self.sb.venv.parent / f"{self.sb.venv.name}.yuzu-gcovr-old.7"
        link.symlink_to(victim.parent)
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(victim.read_text(), "precious\n")
        self.assertEqual(deep.read_text(), "also\n")

    def test_a_users_own_old_directory_survives_a_rebuild_next_to_a_custom_venv(self):
        # <venv>.old.N used to be removed by name; it could be a directory of the user's own.
        venv = self.sb.tmp / "my_gcovr"
        mine = self.write(self.sb.tmp / "my_gcovr.old.3" / "notes.txt", "my own directory\n")
        self.build(YUZU_GCOVR_VENV=str(venv))
        (venv / "sentinel").write_text("old\n")
        (venv / ".requirements-ci.sha256").write_text("deadbeef\n")  # force a rebuild: old venv moves aside
        self.link.unlink()
        self.expect(self.run_script(YUZU_GCOVR_VENV=str(venv)), 0, "ready")
        self.assertEqual(self.sb.side("venv"), ["marker=1 aside=1"])  # the real rebuild happened
        self.assertEqual(mine.read_text(), "my own directory\n")
        self.assertEqual(self.old_dirs(venv), [])

    def test_a_leftover_from_an_interrupted_rebuild_is_removed_on_the_next_run(self):
        # (a run that finds everything ready exits first and sweeps nothing; this one has work to do)
        self.build()
        self.link.unlink()
        leftover = self.write(f"{self.sb.venv}.yuzu-gcovr-old.4242/bin/half", "half-deleted\n")
        self.expect(self.run_script(), 0, "(re)linking")
        self.assertFalse(leftover.parent.exists())
        self.assertTrue((self.sb.venv / ".yuzu-gcovr-venv").exists(), "the venv itself is untouched")

    def test_a_trailing_slash_on_the_venv_path_is_normalised(self):
        self.sb.stub("flock", FLOCK)
        self.expect(self.run_script(YUZU_GCOVR_VENV=f"{self.sb.venv}/"), 0, "ready (gcovr 8.7)")
        # the lock sits BESIDE the venv, never inside it, and the link carries no doubled slash
        self.assertTrue(Path(f"{self.sb.venv}.lock").exists())
        self.assertFalse((self.sb.venv / ".lock").exists())
        self.assertIn(f"flock -w 1200 9", self.sb.calls())
        self.assertEqual(os.readlink(self.link), f"{self.sb.venv}/bin/gcovr")
        self.assertEqual(self.sb.side("venv"), ["marker=1 aside=0"])
        self.assertEqual(self.stamp.read_text().strip(), self.sb.req_sha())
        # and a second run with the same spelling finds it ready
        self.sb.reset_logs()
        self.expect(self.run_script(YUZU_GCOVR_VENV=f"{self.sb.venv}/"), 0, "already installed")
        self.assertEqual(self.pip_calls(), [])

    def test_a_venv_path_that_is_only_slashes_is_refused(self):
        r = self.run_script(YUZU_GCOVR_VENV="/")
        self.expect(r, 1, "must not be empty or /")
        self.assertEqual(self.sb.calls(), [])

    # --- refusals and environment ------------------------------------------------------------

    def test_home_unset(self):
        self.expect(self.run_script(HOME=None), 1, "HOME is not set")
        self.assertEqual(self.sb.calls(), [])

    def test_local_bin_missing_from_path(self):
        self.expect(self.run_script(local_bin=False), 1, "is not on PATH")

    def test_regular_file_at_the_link_is_not_replaced(self):
        self.link.parent.mkdir(parents=True)
        self.link.write_text("precious\n")
        self.expect(self.run_script(), 1, "is not a symlink")
        self.assertEqual(self.link.read_text(), "precious\n")
        self.assertEqual(self.sb.calls(), [])

    def test_python_older_than_3_10(self):
        self.expect(self.run_script(STUB_PY_OK="0"), 1, "older than 3.10")
        self.assertEqual(self.pip_calls(), [])

    def test_missing_ensurepip(self):
        self.expect(self.run_script(STUB_ENSUREPIP_OK="0"), 1, "ensurepip")

    def test_missing_python3_when_an_install_is_needed(self):
        (self.sb.bin / "python3").unlink()
        self.expect(self.run_script(), 1, "python3 is not on PATH")

    # --- timeouts ----------------------------------------------------------------------------

    def test_pip_runs_under_timeout_or_gtimeout_with_a_kill_grace(self):
        for name in ("timeout", "gtimeout"):
            with self.subTest(name):
                self.sb.stub(name, timeout_stub(name))
                venv = self.sb.tmp / f"venv_{name}"
                self.link.unlink(missing_ok=True)
                self.sb.reset_logs()
                self.expect(self.run_script(YUZU_GCOVR_VENV=str(venv)), 0, "ready")
                self.assertIn(f"{name} -k 10 600 {venv}/bin/pip", self.sb.calls())
                (self.sb.bin / name).unlink()

    def test_pip_timeout_is_overridable(self):
        self.sb.stub("timeout", timeout_stub())
        self.expect(self.run_script(YUZU_ENSURE_PIP_TIMEOUT="5"), 0, "ready")
        self.assertIn(f"timeout -k 10 5 {self.sb.venv}/bin/pip", self.sb.calls())

    def test_a_timed_out_pip_says_so(self):
        self.sb.stub("timeout", timeout_stub())
        r = self.run_script(STUB_TIMEOUT_RC="124", STUB_TIMEOUT_ONLY="/bin/pip")
        self.expect(r, 1, "pip could not install")
        self.assertIn("timed out after 600s", r.stdout)

    def test_venv_creation_runs_under_a_timeout_too(self):
        self.sb.stub("timeout", timeout_stub())
        self.expect(self.run_script(), 0, "ready")
        self.assertIn(f"timeout -k 10 300 python3", self.sb.calls())
        self.sb.reset_logs()
        shutil.rmtree(self.sb.venv)
        self.link.unlink()
        r = self.run_script(STUB_TIMEOUT_RC="124", STUB_TIMEOUT_ONLY="-m venv")
        self.expect(r, 1, "could not create the virtualenv")
        self.assertIn("timed out after 300s: python3 -m", r.stdout)
        self.assertEqual(self.pip_calls(), [])

    def test_the_timeout_wrapper_gets_foreground_only_with_a_terminal_on_stdin(self):
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.sb.stub("timeout", timeout_stub())
        try:
            self.expect(self.run_script(stdin=slave), 0, "ready")
        finally:
            os.close(slave)
        calls = self.sb.calls()
        self.assertIn("timeout --foreground -k 10 300", calls)  # venv creation
        self.assertIn("timeout --foreground -k 10 600", calls)  # pip
        self.assertFalse(any(c.startswith("timeout -k") for c in calls), calls)
        self.assertEqual(len(self.pip_calls()), 1)  # the wrapped command still ran

    # --- the lock ----------------------------------------------------------------------------

    def test_build_takes_an_exclusive_lock_with_a_bounded_wait(self):
        self.sb.stub("flock", FLOCK)
        for name, env, wait in (("default", {}, 1200), ("override", {"YUZU_ENSURE_LOCK_TIMEOUT": "7"}, 7)):
            with self.subTest(name):
                self.link.unlink(missing_ok=True)
                shutil.rmtree(self.sb.venv, ignore_errors=True)
                self.sb.reset_logs()
                self.expect(self.run_script(**env), 0, "ready")
                self.assertIn(f"flock -w {wait} 9", self.sb.calls())
                self.assertTrue(Path(f"{self.sb.venv}.lock").exists())

    def test_lock_file_is_opened_for_append_never_truncated(self):
        self.sb.stub("flock", FLOCK)
        lock = self.write(f"{self.sb.venv}.lock", "held by someone\n")
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(lock.read_text(), "held by someone\n")

    def test_a_symlinked_lock_file_is_refused_and_its_target_untouched(self):
        self.sb.stub("flock", FLOCK)
        victim = self.write(self.sb.tmp / "victim.txt", "precious\n")
        dangling = self.sb.tmp / "not-yet.txt"
        lock = Path(f"{self.sb.venv}.lock")
        for name, target in (("existing target", victim), ("dangling target", dangling)):
            with self.subTest(name):
                lock.unlink(missing_ok=True)
                lock.symlink_to(target)
                self.sb.reset_logs()
                self.expect(self.run_script(), 1, "symlink")
                self.assertEqual(victim.read_text(), "precious\n")
                self.assertFalse(dangling.exists(), "the link must not be written through")
                self.assertEqual(self.pip_calls(), [])
                self.assertNotIn("flock -w 1200 9", self.sb.calls())

    def test_lock_wait_that_times_out_is_not_ready(self):
        self.sb.stub("flock", FLOCK)
        self.expect(self.run_script(STUB_FLOCK_RC="1"), 1, "timed out waiting for another")
        self.assertEqual(self.pip_calls(), [])

    def test_a_lock_file_that_is_not_a_regular_file_is_refused_not_blocked_on(self):
        self.sb.stub("flock", FLOCK)
        self.fifo(f"{self.sb.venv}.lock")
        self.expect(self.run_script(), 1, "not a regular file")
        self.assertEqual(self.pip_calls(), [])
        self.assertEqual(self.venv_creations(), [])
        self.assertFalse(any(c.startswith("flock") for c in self.sb.calls()))
        self.assertFalse(self.sb.venv.exists())

    def test_install_steps_keep_the_lock_descriptor_and_probes_do_not(self):
        # pip and `python3 -m venv` keep it (an orphaned install makes the next run wait); every probe
        # (gcovr --version, the venv's own gcovr and python, the capability probe) closes it.
        for with_timeout in (False, True):
            with self.subTest(with_timeout=with_timeout, case="a venv that must be rebuilt"):
                self.sb.stub("flock", FLOCK)
                if with_timeout:
                    self.sb.stub("timeout", timeout_stub())
                venv = self.sb.tmp / f"venv_a{with_timeout}"
                self.link.unlink(missing_ok=True)
                self.build(YUZU_GCOVR_VENV=str(venv))
                # unhealthy: venv_version and venv_healthy both run, inside the lock, before the rebuild
                self.expect(self.run_script(YUZU_GCOVR_VENV=str(venv), STUB_VENV_HEALTHY="0"), 0, "ready")
                self.assert_fd9(self.sb.side("fd9"), install_tags=("venv-create", "pip"),
                                probe_tags=("venv-gcovr", "venv-python"))
            with self.subTest(with_timeout=with_timeout, case="a gcovr that fails the capability probe"):
                shutil.rmtree(self.sb.venv, ignore_errors=True)
                self.link.unlink(missing_ok=True)
                self.sb.reset_logs()
                self.sb.stub("gcovr", gcovr_stub("8.7", probe_rc=1), where=self.sb.farm)
                self.expect(self.run_script(), 0, "ready (gcovr 8.7)")
                self.assert_fd9(self.sb.side("fd9"), install_tags=("venv-create", "pip"),
                                probe_tags=("gcovr-version", "gcovr-probe", "venv-gcovr"))
                (self.sb.farm / "gcovr").unlink()
            (self.sb.bin / "timeout").unlink(missing_ok=True)


@unittest.skipUnless(IS_LINUX, "ensure-gcovr.sh only does anything on Linux (it gates on uname -s)")
class EnsureGcovrPinMismatch(SandboxCase):
    pin_in, pin_txt = "8.7", "8.6"

    def test_txt_and_in_must_agree(self):
        self.sb.stub("python3", PYTHON3)
        self.expect(self.sb.run("ensure-gcovr.sh", local_bin=True), 1, "must agree with requirements-ci.in")
        self.assertEqual(self.sb.calls(), [])


if __name__ == "__main__":
    unittest.main()
