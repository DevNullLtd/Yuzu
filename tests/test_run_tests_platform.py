#!/usr/bin/env python3
"""Exercise the local test runner's platform selection and failure propagation."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
BASH = shutil.which("bash")


@unittest.skipUnless(BASH, "the shell runner requires bash")
class RunnerPlatform(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="yuzu_test_runner_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("scripts", "bin", "build/tests"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/run-tests.sh", self.root / "scripts/run-tests.sh")
        self.executable("bin/uname", 'printf "%s\\n" "$YUZU_TEST_PLATFORM"\n')
        self.executable("bin/meson", '''
printf 'meson' >> "$YUZU_TEST_CALLS"
printf ' <%s>' "$@" >> "$YUZU_TEST_CALLS"
printf '\\n' >> "$YUZU_TEST_CALLS"
for arg in "$@"; do
    case "$arg" in
        yuzu_*_tests) [[ -x "$YUZU_BUILDDIR/tests/$arg" ]] || exit 2 ;;
    esac
done
exit "${YUZU_TEST_COMPILE_EXIT:-0}"
''')
        self.executable("build/tests/yuzu_agent_tests", '''
printf 'agent\\n' >> "$YUZU_TEST_CALLS"
printf '%s\\n%s\\n' "$MESON_BUILD_ROOT" "$YUZU_BUILDDIR" > "$YUZU_TEST_CALLS.agent-root"
exit "${YUZU_TEST_AGENT_EXIT:-0}"
''')
        self.executable("scripts/integration-test.sh", '''
printf 'integration <%s> <%s>\\n' "$1" "$2" >> "$YUZU_TEST_CALLS"
exit "${YUZU_TEST_INTEGRATION_EXIT:-0}"
''')

    def executable(self, relative, body):
        path = self.root / relative
        path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
        path.chmod(0o755)

    def server(self):
        self.executable("build/tests/yuzu_server_tests", '''
printf 'server\\n' >> "$YUZU_TEST_CALLS"
printf '%s\\n%s\\n' "$MESON_BUILD_ROOT" "$YUZU_BUILDDIR" > "$YUZU_TEST_CALLS.server-root"
exit "${YUZU_TEST_SERVER_EXIT:-0}"
''')

    def run_tier(self, platform, tier="unit", **overrides):
        env = os.environ.copy()
        env.update(YUZU_TEST_PLATFORM=platform, **overrides)
        # Resolve fixture paths inside MSYS2 on Windows before constructing PATH.
        # This also keeps the fixture independent of the developer's build dir.
        command = '''
fixture_root=$1
if command -v cygpath >/dev/null 2>&1; then fixture_root=$(cygpath -u "$fixture_root"); fi
export PATH="$fixture_root/bin:$PATH"
export YUZU_BUILDDIR="$fixture_root/build"
export YUZU_TEST_CALLS="$fixture_root/calls.log"
exec bash "$fixture_root/scripts/run-tests.sh" "$2"
'''
        result = subprocess.run(
            [BASH, "-c", command, "runner-fixture", str(self.root), tier],
            env=env, capture_output=True, text=True, encoding="utf-8", timeout=10,
        )
        calls = self.root / "calls.log"
        return result, calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []

    def test_darwin_runs_agent_and_skips_unavailable_server(self):
        result, calls = self.run_tier("Darwin")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(calls[0].endswith(" <yuzu_agent_tests>"), calls)
        self.assertEqual(calls[1:], ["agent"])
        self.assertNotIn("yuzu_server_tests", calls[0])
        self.assertIn("Server unit tests", result.stdout)
        self.assertIn("(skipped)", result.stdout)

    def test_windows_runs_agent_without_server(self):
        result, calls = self.run_tier("MINGW64_NT-10.0")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls[1:], ["agent"])
        self.assertNotIn("yuzu_server_tests", calls[0])

    def test_darwin_agent_failure_stays_failure(self):
        result, calls = self.run_tier("Darwin", YUZU_TEST_AGENT_EXIT="7")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls[1:], ["agent"])

    def test_missing_agent_is_not_a_platform_skip(self):
        (self.root / "build/tests/yuzu_agent_tests").unlink()
        result, calls = self.run_tier("Darwin")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("C++ test compilation failed", result.stdout)

    def test_linux_runs_both_binaries(self):
        self.server()
        result, calls = self.run_tier("Linux")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(calls[0].endswith(" <yuzu_agent_tests> <yuzu_server_tests>"), calls)
        self.assertEqual(calls[1:], ["agent", "server"])

    def test_linux_missing_server_fails(self):
        result, calls = self.run_tier("Linux")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("yuzu_server_tests", calls[0])
        self.assertEqual(len(calls), 1)

    def test_both_binaries_receive_selected_build_root_over_stale_environment(self):
        self.server()
        result, calls = self.run_tier("Linux", MESON_BUILD_ROOT="/stale-unrelated-build")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls[1:], ["agent", "server"])
        for component in ("agent", "server"):
            observed, selected = (self.root / f"calls.log.{component}-root").read_text().splitlines()
            self.assertEqual(observed, selected)
            self.assertNotEqual(observed, "/stale-unrelated-build")

    def test_linux_server_failure_stays_failure(self):
        self.server()
        result, calls = self.run_tier("Linux", YUZU_TEST_SERVER_EXIT="9")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls[1:], ["agent", "server"])

    def test_non_linux_integration_is_explicitly_skipped(self):
        result, calls = self.run_tier("Darwin", "integration", YUZU_TEST_INTEGRATION_EXIT="8")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, [])
        self.assertIn("Full-stack integration test", result.stdout)
        self.assertIn("(skipped)", result.stdout)
        self.assertIn("Passed:  0", result.stdout)

    def test_linux_integration_runs_and_preserves_failure(self):
        result, calls = self.run_tier("Linux", "integration", YUZU_TEST_INTEGRATION_EXIT="8")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ["integration <--agents> <2>"])


if __name__ == "__main__":
    unittest.main()
