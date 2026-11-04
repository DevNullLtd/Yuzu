#!/usr/bin/env python3
"""Behaviour tests for scripts/test/ensure-puppeteer.sh and scripts/test/ensure-gcovr.sh.

Both helpers install tooling for the /test gates, so every branch that decides "ready" or
"NOT READY" is exercised here against STUB executables in a sandbox: a temp HOME, a stub bin dir
first on PATH, a coreutils-only symlink farm behind it (so a node/python3/gcovr on the host can
never leak in), a temp YUZU_GCOVR_VENV, and a private copy of the script plus the few repo files it
reads. The real repo tree and the real $HOME are never touched; each case asserts the former.

Stubs append their argv to one log (calls.log), so a case can say which tools ran and which did not.
Side observations that are not "a tool ran" (what the filesystem looked like when a stub was called,
how many times a stub has been called) go to calls.log.state / calls.log.<counter> so the exact-list
assertions on calls.log stay readable. `timeout`, `flock` and `ldd` are deliberately NOT in the
farm: by default the scripts run unwrapped and unlocked (the macOS situation), and a case that cares
installs a stub of its own.

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
              "uname touch chmod tr").split()

# A sequence stub: STUB_<VAR> is a space-separated list of outcomes ("ok"/"fail"), one per call; the
# last repeats. The call count lives in $STUB_LOG.<name>.
_SEQ = """n=$(cat "$STUB_LOG.@NAME" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$STUB_LOG.@NAME"
res=ok; i=0
for w in ${@VAR:-ok}; do i=$((i+1)); res=$w; [ "$i" -ge "$n" ] && break; done
"""

NODE = """#!/bin/sh
case "$1" in --version) echo "${STUB_NODE_VERSION:-v22.23.0}"; exit 0;; esac
case "$*" in
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
echo "npm skip_download=$PUPPETEER_SKIP_DOWNLOAD" >> "$STUB_LOG.state"
[ "${STUB_NPM_RC:-0}" = 0 ] || { echo "npm ERR! boom" >&2; exit "$STUB_NPM_RC"; }
mkdir -p node_modules/puppeteer; : > node_modules/.package-lock.json
"""
# The browser installer: records what the cache looked like when it was called, then (on a call that
# is meant to succeed) leaves a runnable-looking binary at $STUB_EXE unless STUB_NPX_CREATES=0.
NPX = """#!/bin/sh
echo "npx $*" >> "$STUB_LOG"
""" + _SEQ.replace("@NAME", "npx").replace("@VAR", "STUB_NPX") + """
dir=$(dirname "$(dirname "$STUB_EXE")"); parent=$(dirname "$dir"); zip=0
for z in "$parent"/*.zip; do [ -e "$z" ] && zip=1; done
echo "npx#$n dir=$([ -e "$dir" ] && echo 1 || echo 0) zip=$zip" >> "$STUB_LOG.state"
[ "$res" = ok ] || { echo "npx: download failed" >&2; exit 1; }
if [ "${STUB_NPX_CREATES:-1}" = 1 ]; then
  mkdir -p "$(dirname "$STUB_EXE")"; : > "$STUB_EXE"; chmod +x "$STUB_EXE"
fi
"""
LDD_MISSING_NSS = '#!/bin/sh\necho "$1" >> "$STUB_LOG.ldd"\nprintf \'\\tlibc.so.6 => /lib/libc.so.6\\n\\tlibnss3.so => not found\\n\'\n'
LDD_ALL_FOUND = "#!/bin/sh\nprintf '\\tlibc.so.6 => /lib/libc.so.6\\n'\n"
# Logs "timeout <secs> <cmd>" then runs the command, or pretends to have timed out.
TIMEOUT = """#!/bin/sh
echo "timeout $1 $2" >> "$STUB_LOG"
[ -z "$STUB_TIMEOUT_RC" ] || exit "$STUB_TIMEOUT_RC"
shift; exec "$@"
"""
FLOCK = '#!/bin/sh\necho "flock $*" >> "$STUB_LOG"\nexit "${STUB_FLOCK_RC:-0}"\n'
UNAME_DARWIN = "#!/bin/sh\necho Darwin\n"
GCOVR_87 = '#!/bin/sh\necho "gcovr 8.7"\n'
GCOVR_86 = '#!/bin/sh\necho "gcovr 8.6"\n'
# python3 builds a stub venv: bin/{pip,gcovr,python}. pip honours STUB_PIP_RC; the venv's python is
# the health probe (`import gcovr, jinja2, ...`) and succeeds unless STUB_VENV_HEALTHY=0. Venv
# creation records whether a moved-aside copy of the previous venv (marked by a `sentinel` file) is
# visible at that moment.
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
  for d in "$3".old.*; do [ -e "$d/sentinel" ] && echo old_aside >> "$STUB_LOG.state"; done
  mkdir -p "$3/bin"; echo "home = /stub" > "$3/pyvenv.cfg"
  cat > "$3/bin/pip" <<'EOF'
#!/bin/sh
echo "pip $*" >> "$STUB_LOG"
[ "${STUB_PIP_RC:-0}" = 0 ] || { echo "pip ERROR: boom" >&2; exit "$STUB_PIP_RC"; }
EOF
  printf '#!/bin/sh\\necho "gcovr 8.7"\\n' > "$3/bin/gcovr"
  printf '#!/bin/sh\\n[ "${STUB_VENV_HEALTHY:-1}" = 1 ]\\n' > "$3/bin/python"
  chmod +x "$3/bin/pip" "$3/bin/gcovr" "$3/bin/python"
fi
exit 0
"""


class Sandbox:
    """A temp HOME + stub bin + private repo copy for one script run."""

    def __init__(self, pin_in="8.7", pin_txt="8.7"):
        self._tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_ensure_")
        self.tmp = Path(self._tmp.name).resolve()
        self.home, self.bin, self.farm = (self.tmp / d for d in ("home", "bin", "farm"))
        self.repo, self.log, self.venv = self.tmp / "repo", self.tmp / "calls.log", self.tmp / "venv"
        for d in (self.home, self.bin, self.farm, self.repo / "scripts" / "test",
                  self.repo / "tests" / "puppeteer"):
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

    def stub(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def calls(self):
        return self.log.read_text().splitlines()

    def side(self, suffix):
        """Lines a stub wrote to calls.log.<suffix> (empty when it never wrote any)."""
        path = Path(f"{self.log}.{suffix}")
        return path.read_text().splitlines() if path.exists() else []

    def req_sha(self):
        return hashlib.sha256((self.repo / "requirements-ci.txt").read_bytes()).hexdigest()

    def run(self, script, local_bin=False, **env):
        """Run <script> with an `env -i`-style environment; a None value unsets that variable."""
        dirs = [self.bin] + ([self.home / ".local" / "bin"] if local_bin else []) + [self.farm]
        full = {"HOME": str(self.home), "PATH": os.pathsep.join(map(str, dirs)),
                "STUB_LOG": str(self.log), "YUZU_GCOVR_VENV": str(self.venv), "LC_ALL": "C", **env}
        full = {k: v for k, v in full.items() if v is not None}
        return subprocess.run([shutil.which("bash"), str(self.repo / "scripts" / "test" / script)],
                              env=full, capture_output=True, text=True, timeout=60)


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


class EnsurePuppeteer(SandboxCase):
    SCRIPT = "ensure-puppeteer.sh"
    NPM_CI = "npm ci --ignore-scripts --no-audit --no-fund"
    INSTALL = "npx --no-install puppeteer browsers install chrome"

    def setUp(self):
        super().setUp()
        for name, body in (("node", NODE), ("npm", NPM), ("npx", NPX)):
            self.sb.stub(name, body)
        self.pp = self.sb.repo / "tests" / "puppeteer"
        # puppeteer's cache layout: <cache>/chrome/<build>/<platform dir>/<binary>
        self.chrome = self.sb.tmp / "pcache" / "chrome"
        self.build = self.chrome / "linux-1.2.3"
        self.exe = self.build / "chrome-linux64" / "chrome"
        self.make_browser()

    def make_browser(self, exe=None):
        exe = exe or self.exe
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)

    def run_script(self, **env):
        return self.sb.run(self.SCRIPT, **{"STUB_EXE": str(self.exe), **env})

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

    def test_missing_node(self):
        (self.sb.bin / "node").unlink()
        self.expect(self.run_script(), 1, "node is not on PATH")

    def test_old_node(self):
        self.expect(self.run_script(STUB_NODE_VERSION="v20.1.0"), 1, "older than")

    def test_home_unset(self):
        self.expect(self.run_script(HOME=None), 1, "HOME is not set")
        self.assertEqual(self.sb.calls(), [])

    def test_fresh_install_runs_npm_ci_with_the_safe_flags(self):
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(self.sb.calls(), [self.NPM_CI])
        # the browser download is deferred to its own step so a failure there names itself
        self.assertEqual(self.sb.side("state"), ["npm skip_download=1"])

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

    def test_network_steps_run_under_timeout_when_it_exists(self):
        self.sb.stub("timeout", TIMEOUT)
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(self.sb.calls(), ["timeout 600 npm", self.NPM_CI, "timeout 60 node"])

    def test_a_timed_out_step_says_so(self):
        self.sb.stub("timeout", TIMEOUT)
        r = self.run_script(STUB_TIMEOUT_RC="124")
        self.expect(r, 1, "npm ci failed")
        self.assertIn("timed out after 600s: npm ci", r.stdout)

    def test_install_takes_an_exclusive_lock_when_flock_exists(self):
        self.sb.stub("flock", FLOCK)
        cache = self.sb.tmp / "xdg"
        self.expect(self.run_script(XDG_CACHE_HOME=str(cache)), 0, "ready")
        self.assertIn("flock -w 900 9", self.sb.calls())
        self.assertTrue((cache / "yuzu-ensure-puppeteer.lock").exists())

    def test_lock_wait_that_times_out_is_not_ready(self):
        self.sb.stub("flock", FLOCK)
        self.expect(self.run_script(STUB_FLOCK_RC="1"), 1, "timed out waiting for another")
        self.assertNotIn(self.NPM_CI, self.sb.calls())

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
        (self.chrome / "linux-1.2.3.zip").write_text("partial")
        keep = self.chrome / "linux-9.9.9" / "chrome-linux64" / "chrome"
        self.make_browser(keep)
        r = self.run_script(STUB_NPX="fail ok")
        self.expect(r, 0, "ready")
        self.assertEqual(self.npx_calls(), [self.INSTALL, self.INSTALL])
        # the first call saw the damage; by the retry the build dir and the zip were cleared
        self.assertEqual(self.npx_states(), ["npx#1 dir=1 zip=1", "npx#2 dir=0 zip=0"])
        self.assertTrue(keep.exists(), "another build in the cache must be left alone")
        self.assertIn("removing the partial browser install", r.stdout)

    def test_launch_failure_from_missing_libraries_names_them_and_does_not_reinstall(self):
        self.sb.stub("ldd", LDD_MISSING_NSS)
        r = self.run_script(STUB_LAUNCH="fail")
        self.expect(r, 1, "libnss3.so => not found")
        self.assertIn("a reinstall will not help", r.stderr)
        self.assertEqual(self.npx_calls(), [])
        self.assertEqual(self.sb.side("ldd"), [str(self.exe)])
        self.assertTrue(self.exe.exists())

    def test_launch_failure_without_missing_libraries_heals_and_reinstalls_once(self):
        self.sb.stub("ldd", LDD_ALL_FOUND)
        r = self.run_script(STUB_LAUNCH="fail ok")
        self.expect(r, 0, "ready")
        self.assertIn("reinstalling it once", r.stdout)
        self.assertIn("launched Chrome/1", r.stdout)
        self.assertEqual(self.npx_calls(), [self.INSTALL])
        self.assertEqual(self.npx_states(), ["npx#1 dir=0 zip=0"])
        self.assertEqual(self.sb.side("launches"), ["2"])

    def test_browser_that_never_launches_fails_after_exactly_one_reinstall(self):
        r = self.run_script(STUB_LAUNCH="fail")
        self.expect(r, 1, "will not start headless")
        self.assertIn("after a reinstall", r.stderr)
        self.assertEqual(self.npx_calls(), [self.INSTALL])
        self.assertEqual(self.sb.side("launches"), ["2"])

    def test_launch_failure_with_an_explicit_browser_never_touches_it(self):
        # The user's binary sits in a perfectly healable cache layout: only PUPPETEER_EXECUTABLE_PATH
        # may be what protects it.
        mine = self.chrome / "linux-7.7.7" / "chrome-linux64" / "chrome"
        self.make_browser(mine)
        (self.chrome / "mine.zip").write_text("x")
        r = self.run_script(STUB_LAUNCH="fail", PUPPETEER_EXECUTABLE_PATH=str(mine))
        self.expect(r, 1, "left alone")
        self.assertEqual(self.npx_calls(), [])
        self.assertEqual(mine.read_text(), "#!/bin/sh\n")
        self.assertTrue((self.chrome / "mine.zip").exists())

    def test_launch_failure_outside_a_chrome_cache_directory_leaves_the_browser_alone(self):
        other = self.sb.tmp / "elsewhere" / "linux-1.2.3" / "chrome-linux64" / "chrome"
        self.make_browser(other)
        r = self.run_script(STUB_LAUNCH="fail", STUB_EXE=str(other))
        self.expect(r, 1, "left alone")
        self.assertIn("boom", r.stderr)
        self.assertEqual(self.npx_calls(), [])
        self.assertTrue(other.exists())

    def test_explicit_browser_path_that_is_missing_never_downloads(self):
        r = self.run_script(PUPPETEER_EXECUTABLE_PATH="/nonexistent/chrome")
        self.expect(r, 1, "nothing is there")
        self.assertEqual(self.npx_calls(), [])

    def test_explicit_browser_path_that_exists_is_used_as_is(self):
        mine = self.sb.tmp / "mine" / "chrome"
        self.make_browser(mine)
        r = self.run_script(PUPPETEER_EXECUTABLE_PATH=str(mine))
        self.expect(r, 0, "browser already present")
        self.assertEqual(self.npx_calls(), [])


class EnsureGcovr(SandboxCase):
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

    def build(self, **env):
        """A first, successful install; leaves calls.log empty afterwards."""
        self.expect(self.run_script(**env), 0, "ready")
        self.sb.log.write_text("")

    def old_dirs(self, venv=None):
        venv = venv or self.sb.venv
        return sorted(p.name for p in venv.parent.glob(venv.name + ".old.*"))

    # --- ready / no-op -----------------------------------------------------------------------

    def test_fresh_install_hash_verifies_and_links(self):
        self.expect(self.run_script(), 0, "ready (gcovr 8.7)")
        pip = self.pip_calls()
        self.assertEqual(len(pip), 1)
        self.assertIn("--require-hashes", pip[0])
        self.assertIn(str(self.sb.repo / "requirements-ci.txt"), pip[0])
        self.assertEqual(os.readlink(self.link), str(self.sb.venv / "bin" / "gcovr"))
        self.assertEqual(self.stamp.read_text().strip(), self.sb.req_sha())
        self.assertTrue((self.sb.venv / ".yuzu-gcovr-venv").exists(), "build marker is written first")

    def test_repeat_run_is_a_no_op(self):
        self.build()
        self.expect(self.run_script(), 0, "already installed")
        self.assertEqual(self.sb.calls(), [])

    def test_unmanaged_gcovr_at_the_pin_is_accepted_and_left_alone(self):
        self.sb.stub("gcovr", GCOVR_87)
        (self.sb.bin / "python3").unlink()  # nothing here may need python
        r = self.run_script()
        self.expect(r, 0, "using gcovr 8.7")
        self.assertIn(str(self.sb.bin / "gcovr"), r.stdout)
        self.assertEqual(self.sb.calls(), [])
        self.assertFalse(self.sb.venv.exists())
        self.assertFalse(self.link.exists() or self.link.is_symlink())

    def test_unmanaged_gcovr_at_another_version_is_replaced_but_a_shadow_after_install_is_refused(self):
        self.sb.stub("gcovr", GCOVR_86)
        r = self.run_script()
        self.expect(r, 1, "which reports '8.6'")
        self.assertIn("PATH resolves 'gcovr' to", r.stderr)
        self.assertEqual(len(self.pip_calls()), 1)  # it did install; only the PATH entry is wrong

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

    # --- rebuild safety ----------------------------------------------------------------------

    def test_rebuild_moves_the_old_venv_aside_then_removes_it(self):
        self.build()
        (self.sb.venv / "sentinel").write_text("old\n")
        self.stamp.write_text("deadbeef\n")
        self.expect(self.run_script(), 0, "ready")
        self.assertIn("old_aside", self.sb.side("state"))  # visible while the new venv was built
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
        self.assertFalse([c for c in self.sb.calls() if "venv" in c])
        self.assertEqual(self.old_dirs(), [])

    def test_directories_the_guard_accepts_are_replaced(self):
        # (files present in the existing $VENV) -> accepted as ours / empty, so rebuilt in place
        for i, (name, files) in enumerate((("empty directory", []),
                            ("half-built venv: marker only, no pyvenv.cfg", [".yuzu-gcovr-venv"]),
                            ("venv from an older script: pyvenv.cfg only", ["pyvenv.cfg"]))):
            with self.subTest(name):
                venv = self.sb.tmp / f"venv_{i}"
                venv.mkdir()
                for f in files:
                    (venv / f).write_text("x\n")
                self.sb.log.write_text("")
                self.link.unlink(missing_ok=True)  # the previous case's link would read as "a gcovr at the pin"
                self.expect(self.run_script(YUZU_GCOVR_VENV=str(venv)), 0, "ready")
                self.assertEqual(len(self.pip_calls()), 1)
                self.assertEqual((venv / ".requirements-ci.sha256").read_text().strip(), self.sb.req_sha())
                # A replaced $VENV is moved aside and removed; nothing (not even an empty husk) may remain.
                self.assertEqual(self.old_dirs(venv), [])

    def test_only_recognisable_old_venv_leftovers_are_removed(self):
        mine = self.sb.venv.parent / (self.sb.venv.name + ".old.123")
        mine.mkdir()
        (mine / "pyvenv.cfg").write_text("home = /stub\n")
        marked = self.sb.venv.parent / (self.sb.venv.name + ".old.456")
        marked.mkdir()
        (marked / ".yuzu-gcovr-venv").write_text("")
        theirs = self.sb.venv.parent / (self.sb.venv.name + ".old.other")
        theirs.mkdir()
        (theirs / "notes.txt").write_text("not a venv\n")
        self.expect(self.run_script(), 0, "ready")
        self.assertFalse(mine.exists())
        self.assertFalse(marked.exists())
        self.assertEqual((theirs / "notes.txt").read_text(), "not a venv\n")

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

    def test_non_linux_is_a_no_op(self):
        self.sb.stub("uname", UNAME_DARWIN)
        self.expect(self.run_script(), 0, "not Linux")
        self.assertEqual(self.sb.calls(), [])

    def test_python_older_than_3_10(self):
        self.expect(self.run_script(STUB_PY_OK="0"), 1, "older than 3.10")
        self.assertEqual(self.pip_calls(), [])

    def test_missing_ensurepip(self):
        self.expect(self.run_script(STUB_ENSUREPIP_OK="0"), 1, "ensurepip")

    def test_missing_python3_when_an_install_is_needed(self):
        (self.sb.bin / "python3").unlink()
        self.expect(self.run_script(), 1, "python3 is not on PATH")

    def test_pip_runs_under_timeout_and_the_build_under_flock_when_they_exist(self):
        self.sb.stub("timeout", TIMEOUT)
        self.sb.stub("flock", FLOCK)
        self.expect(self.run_script(), 0, "ready")
        self.assertIn(f"timeout 600 {self.sb.venv}/bin/pip", self.sb.calls())
        self.assertIn("flock -w 600 9", self.sb.calls())
        self.assertTrue(Path(f"{self.sb.venv}.lock").exists())

    def test_lock_wait_that_times_out_is_not_ready(self):
        self.sb.stub("flock", FLOCK)
        self.expect(self.run_script(STUB_FLOCK_RC="1"), 1, "timed out waiting for another")
        self.assertEqual(self.pip_calls(), [])


class EnsureGcovrPinMismatch(SandboxCase):
    pin_in, pin_txt = "8.7", "8.6"

    def test_txt_and_in_must_agree(self):
        self.sb.stub("python3", PYTHON3)
        self.expect(self.sb.run("ensure-gcovr.sh", local_bin=True), 1, "must agree with requirements-ci.in")
        self.assertEqual(self.sb.calls(), [])


if __name__ == "__main__":
    unittest.main()
