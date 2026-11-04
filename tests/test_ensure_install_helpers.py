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

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = Path(os.environ.get("YUZU_ENSURE_SCRIPT_DIR", ROOT / "scripts" / "test"))
FARM_TOOLS = ("bash sh dirname basename sed head grep readlink sha256sum cut cat ls mkdir rm ln mv "
              "uname touch chmod tr mktemp").split()

# A sequence stub: STUB_<VAR> is a space-separated list of outcomes ("ok"/"fail"), one per call; the
# last repeats. The call count lives in $STUB_LOG.<name>.
_SEQ = """n=$(cat "$STUB_LOG.@NAME" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$STUB_LOG.@NAME"
res=ok; i=0
for w in ${@VAR:-ok}; do i=$((i+1)); res=$w; [ "$i" -ge "$n" ] && break; done
"""
# What every stub that is a child of the script reports: where it ran (.cwd) and whether the lock
# descriptor (fd 9) leaked into it (.fd9). `: >&9` fails on a closed descriptor.
_OBSERVE = """echo "@T $PWD" >> "$STUB_LOG.cwd"
echo "@T $( ( : >&9 ) 2>/dev/null && echo open || echo closed )" >> "$STUB_LOG.fd9"
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
dir=$(dirname "$(dirname "$STUB_EXE")"); parent=$(dirname "$dir"); zip=0
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
# timeout/gtimeout: logs "<name> <first four args>" (the scripts call `-k 10 <secs> <cmd>`), then runs
# the command, or pretends to have timed out.
TIMEOUT = """#!/bin/sh
echo "@N $1 $2 $3 $4" >> "$STUB_LOG"
[ -z "$STUB_TIMEOUT_RC" ] || exit "$STUB_TIMEOUT_RC"
shift 3; exec "$@"
"""
FLOCK = '#!/bin/sh\necho "flock $*" >> "$STUB_LOG"\nexit "${STUB_FLOCK_RC:-0}"\n'
UNAME_DARWIN = "#!/bin/sh\necho Darwin\n"
# A gcovr on PATH that is not ours. --version prints the baked-in version; anything else is the
# capability probe, which records where it ran and with what, and exits with the baked-in status.
GCOVR = """#!/bin/sh
case "$1" in --version) echo "gcovr @VER"; exit 0;; esac
echo "$PWD $*" >> "$STUB_LOG.probe"
exit @RC
"""
# python3 builds a stub venv: bin/{pip,gcovr,python}. pip honours STUB_PIP_RC; the venv's python is
# the health probe (`import gcovr, jinja2, ...`) and succeeds unless STUB_VENV_HEALTHY=0. Venv creation
# records, in $STUB_LOG.venv, whether the build marker already existed at that moment and whether a
# moved-aside copy of the previous venv (marked by a `sentinel` file) is visible.
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
  aside=0; for d in "$3".old.*; do [ -e "$d/sentinel" ] && aside=1; done
  echo "marker=$([ -e "$3/.yuzu-gcovr-venv" ] && echo 1 || echo 0) aside=$aside" >> "$STUB_LOG.venv"
  mkdir -p "$3/bin"; echo "home = /stub" > "$3/pyvenv.cfg"
  cat > "$3/bin/pip" <<'EOF'
#!/bin/sh
echo "pip $*" >> "$STUB_LOG"
echo "pip $( ( : >&9 ) 2>/dev/null && echo open || echo closed )" >> "$STUB_LOG.fd9"
[ "${STUB_PIP_RC:-0}" = 0 ] || { echo "pip ERROR: boom" >&2; exit "$STUB_PIP_RC"; }
EOF
  printf '#!/bin/sh\\necho "gcovr 8.7"\\n' > "$3/bin/gcovr"
  printf '#!/bin/sh\\n[ "${STUB_VENV_HEALTHY:-1}" = 1 ]\\n' > "$3/bin/python"
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

    def run(self, script, local_bin=False, **env):
        """Run <script> with an `env -i`-style environment; a None value unsets that variable."""
        dirs = [self.bin] + ([self.home / ".local" / "bin"] if local_bin else []) + [self.farm]
        full = {"HOME": str(self.home), "PATH": os.pathsep.join(map(str, dirs)),
                "STUB_LOG": str(self.log), "YUZU_GCOVR_VENV": str(self.venv),
                "TMPDIR": str(self.tmpdir), "LC_ALL": "C", **env}
        full = {k: v for k, v in full.items() if v is not None}
        return subprocess.run([shutil.which("bash"), str(self.repo / "scripts" / "test" / script)],
                              env=full, cwd=self.neutral, capture_output=True, text=True, timeout=60)


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
                self.assertEqual(self.sb.calls(), [f"{name} -k 10 600 npm", self.NPM_CI,
                                                   f"{name} -k 10 60 node"])
                (self.sb.bin / name).unlink()

    def test_timeouts_are_overridable_and_reach_the_wrapper(self):
        self.sb.stub("timeout", timeout_stub())
        self.exe.unlink()
        self.expect(self.run_script(YUZU_ENSURE_NPM_TIMEOUT="11", YUZU_ENSURE_BROWSER_TIMEOUT="22",
                                    YUZU_ENSURE_LAUNCH_TIMEOUT="33"), 0, "ready")
        self.assertEqual(self.sb.calls(), ["timeout -k 10 11 npm", self.NPM_CI,
                                           "timeout -k 10 22 npx", self.INSTALL,
                                           "timeout -k 10 33 node"])

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

    def test_the_lock_descriptor_is_closed_for_every_child(self):
        for with_timeout in (False, True):
            with self.subTest(with_timeout=with_timeout):
                self.sb.reset_logs()
                shutil.rmtree(self.pp / "node_modules", ignore_errors=True)
                self.exe.unlink(missing_ok=True)  # so npm, node and npx all run
                self.sb.stub("flock", FLOCK)
                if with_timeout:
                    self.sb.stub("timeout", timeout_stub())
                self.expect(self.run_script(), 0, "ready")
                self.assertEqual(sorted(set(self.sb.side("fd9"))),
                                 ["node closed", "npm closed", "npx closed"])

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
        venv = venv or self.sb.venv
        return sorted(p.name for p in venv.parent.glob(venv.name + ".old.*"))


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
        self.assertEqual(self.sb.calls(), ["timeout -k 10 60 gcovr"])

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
        self.expect(self.run_script(), 1, "refusing to replace")
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
                self.expect(self.run_script(YUZU_GCOVR_VENV=str(venv)), 1, "refusing to replace")
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
                              ("456", ["bin/x"]),                # half-deleted
                              ("789", ["notes.txt"])):           # not even a venv: ours by NAME
            d = parent / f"{name}.old.{suffix}"
            d.mkdir()
            for f in files:
                self.write(d / f, "x\n")
            removed.append(d)
        for suffix in ("keep", "12x", "x12", ""):
            kept.append(self.write(parent / f"{name}.old.{suffix}" / "notes.txt", "not ours\n"))
        target = self.write(self.sb.tmp / "linked_target" / "notes.txt", "target\n")
        (parent / f"{name}.old.999").symlink_to(target.parent)
        self.expect(self.run_script(), 0, "ready")
        for d in removed:
            self.assertFalse(d.exists(), d.name)
        for f in kept:
            self.assertEqual(f.read_text(), "not ours\n", f.parent.name)
        self.assertTrue((parent / f"{name}.old.999").is_symlink(), "a symlink is never taken for a leftover")
        self.assertEqual(target.read_text(), "target\n")

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
        r = self.run_script(STUB_TIMEOUT_RC="124")
        self.expect(r, 1, "pip could not install")
        self.assertIn("timed out after 600s", r.stdout)

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

    def test_the_lock_descriptor_is_closed_for_pip(self):
        for with_timeout in (False, True):
            with self.subTest(with_timeout=with_timeout):
                self.sb.stub("flock", FLOCK)
                if with_timeout:
                    self.sb.stub("timeout", timeout_stub())
                venv = self.sb.tmp / f"venv_{with_timeout}"
                self.link.unlink(missing_ok=True)
                self.sb.reset_logs()
                self.expect(self.run_script(YUZU_GCOVR_VENV=str(venv)), 0, "ready")
                self.assertEqual(self.sb.side("fd9"), ["pip closed"])


@unittest.skipUnless(IS_LINUX, "ensure-gcovr.sh only does anything on Linux (it gates on uname -s)")
class EnsureGcovrPinMismatch(SandboxCase):
    pin_in, pin_txt = "8.7", "8.6"

    def test_txt_and_in_must_agree(self):
        self.sb.stub("python3", PYTHON3)
        self.expect(self.sb.run("ensure-gcovr.sh", local_bin=True), 1, "must agree with requirements-ci.in")
        self.assertEqual(self.sb.calls(), [])


if __name__ == "__main__":
    unittest.main()
