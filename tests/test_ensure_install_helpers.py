#!/usr/bin/env python3
"""Behaviour tests for scripts/test/ensure-puppeteer.sh and scripts/test/ensure-gcovr.sh.

Both helpers install tooling for the /test gates, so every branch that decides "ready" or
"NOT READY" is exercised here against STUB executables in a sandbox: a temp HOME, a stub bin dir
first on PATH, a coreutils-only symlink farm behind it (so a node/python3/gcovr on the host can
never leak in), a temp YUZU_GCOVR_VENV, and a private copy of the script plus the few repo files it
reads. The real repo tree and the real $HOME are never touched; each case asserts the former.

Stubs append their argv to one log, so a case can say which tools ran and which did not.
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
FARM_TOOLS = ("bash sh dirname sed head grep readlink sha256sum cut cat ls mkdir rm ln uname "
              "touch chmod").split()

NODE = """#!/bin/sh
case "$1" in --version) echo "${STUB_NODE_VERSION:-v22.23.0}"; exit 0;; esac
case "$*" in
  *puppeteer.launch*) [ "${STUB_LAUNCH:-ok}" = ok ] && { echo "launched Chrome/1"; exit 0; }
                      echo boom >&2; exit 1;;
  *executablePath*) [ "${STUB_BROWSER:-yes}" = yes ]; exit $?;;
esac
exit 0
"""
NPM = """#!/bin/sh
echo "npm $*" >> "$STUB_LOG"
[ "${STUB_NPM_RC:-0}" = 0 ] || { echo "npm ERR! boom" >&2; exit "$STUB_NPM_RC"; }
mkdir -p node_modules/puppeteer; : > node_modules/.package-lock.json
"""
NPX = '#!/bin/sh\necho "npx $*" >> "$STUB_LOG"\n'
UNAME_DARWIN = "#!/bin/sh\necho Darwin\n"
GCOVR_87 = '#!/bin/sh\necho "gcovr 8.7"\n'
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
  mkdir -p "$3/bin"; echo "home = /stub" > "$3/pyvenv.cfg"
  printf '#!/bin/sh\\necho "pip $*" >> "$STUB_LOG"\\n' > "$3/bin/pip"
  printf '#!/bin/sh\\necho "gcovr 8.7"\\n' > "$3/bin/gcovr"
  chmod +x "$3/bin/pip" "$3/bin/gcovr"
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

    def req_sha(self):
        return hashlib.sha256((self.repo / "requirements-ci.txt").read_bytes()).hexdigest()

    def run(self, script, local_bin=False, **env):
        """Run <script> with an `env -i`-style environment; returns CompletedProcess."""
        dirs = [self.bin] + ([self.home / ".local" / "bin"] if local_bin else []) + [self.farm]
        full = {"HOME": str(self.home), "PATH": os.pathsep.join(map(str, dirs)),
                "STUB_LOG": str(self.log), "YUZU_GCOVR_VENV": str(self.venv), "LC_ALL": "C", **env}
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

    def setUp(self):
        super().setUp()
        for name, body in (("node", NODE), ("npm", NPM), ("npx", NPX)):
            self.sb.stub(name, body)
        self.pp = self.sb.repo / "tests" / "puppeteer"

    def run_script(self, **env):
        return self.sb.run(self.SCRIPT, **env)

    def install_modules(self, lock_mtime, modules_mtime):
        (self.pp / "node_modules" / "puppeteer").mkdir(parents=True)
        mod_lock = self.pp / "node_modules" / ".package-lock.json"
        mod_lock.touch()
        os.utime(self.pp / "package-lock.json", (lock_mtime, lock_mtime))
        os.utime(mod_lock, (modules_mtime, modules_mtime))

    def test_missing_node(self):
        (self.sb.bin / "node").unlink()
        self.expect(self.run_script(), 1, "node is not on PATH")

    def test_old_node(self):
        self.expect(self.run_script(STUB_NODE_VERSION="v20.1.0"), 1, "older than")

    def test_fresh_install_runs_npm_ci_with_the_safe_flags(self):
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(self.sb.calls(), ["npm ci --ignore-scripts --no-audit --no-fund"])

    def test_up_to_date_modules_skip_npm(self):
        self.install_modules(1_000_000, 1_000_100)
        self.expect(self.run_script(), 0, "already match")
        self.assertEqual(self.sb.calls(), [])

    def test_lockfile_newer_than_modules_reinstalls(self):
        self.install_modules(1_000_100, 1_000_000)
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(self.sb.calls(), ["npm ci --ignore-scripts --no-audit --no-fund"])

    def test_browser_that_will_not_launch_fails(self):
        self.expect(self.run_script(STUB_LAUNCH="fail"), 1, "will not start headless")

    def test_explicit_browser_path_that_is_missing_never_downloads(self):
        r = self.run_script(STUB_BROWSER="no", PUPPETEER_EXECUTABLE_PATH="/nonexistent/chrome")
        self.expect(r, 1, "nothing is there")
        self.assertNotIn("npx", " ".join(self.sb.calls()))

    def test_failed_npm_ci(self):
        self.expect(self.run_script(STUB_NPM_RC="1"), 1, "npm ci failed")


class EnsureGcovr(SandboxCase):
    SCRIPT = "ensure-gcovr.sh"

    def setUp(self):
        super().setUp()
        self.sb.stub("python3", PYTHON3)
        self.link = self.sb.home / ".local" / "bin" / "gcovr"

    def run_script(self, local_bin=True, **env):
        return self.sb.run(self.SCRIPT, local_bin=local_bin, **env)

    def pip_calls(self):
        return [c for c in self.sb.calls() if c.startswith("pip ")]

    def test_fresh_install_hash_verifies_and_links(self):
        self.expect(self.run_script(), 0, "ready (gcovr 8.7)")
        pip = self.pip_calls()
        self.assertEqual(len(pip), 1)
        self.assertIn("--require-hashes", pip[0])
        self.assertIn(str(self.sb.repo / "requirements-ci.txt"), pip[0])
        self.assertEqual(os.readlink(self.link), str(self.sb.venv / "bin" / "gcovr"))
        self.assertEqual((self.sb.venv / ".requirements-ci.sha256").read_text().strip(), self.sb.req_sha())

    def test_repeat_run_is_a_no_op(self):
        self.expect(self.run_script(), 0, "ready")
        self.sb.log.write_text("")
        self.expect(self.run_script(), 0, "already installed")
        self.assertEqual(self.sb.calls(), [])

    def test_stale_requirements_stamp_rebuilds(self):
        self.expect(self.run_script(), 0, "ready")
        (self.sb.venv / ".requirements-ci.sha256").write_text("deadbeef\n")
        self.sb.log.write_text("")
        self.expect(self.run_script(), 0, "ready")
        self.assertEqual(len(self.pip_calls()), 1)
        self.assertEqual((self.sb.venv / ".requirements-ci.sha256").read_text().strip(), self.sb.req_sha())

    def test_another_gcovr_earlier_on_path_is_refused(self):
        self.sb.stub("gcovr", GCOVR_87)
        self.expect(self.run_script(), 1, "PATH resolves 'gcovr' to")

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

    def test_populated_non_venv_directory_is_never_deleted(self):
        self.sb.venv.mkdir()
        (self.sb.venv / "precious.txt").write_text("keep\n")
        self.expect(self.run_script(), 1, "refusing to delete")
        self.assertEqual([p.name for p in self.sb.venv.iterdir()], ["precious.txt"])
        self.assertFalse([c for c in self.sb.calls() if "venv" in c])


class EnsureGcovrPinMismatch(SandboxCase):
    pin_in, pin_txt = "8.7", "8.6"

    def test_txt_and_in_must_agree(self):
        self.sb.stub("python3", PYTHON3)
        self.expect(self.sb.run("ensure-gcovr.sh", local_bin=True), 1, "must agree with requirements-ci.in")
        self.assertEqual(self.sb.calls(), [])


if __name__ == "__main__":
    unittest.main()
