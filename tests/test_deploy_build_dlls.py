#!/usr/bin/env python3
"""scripts/deploy_build_dlls.py reports a DLL copy that did not happen.

The script copies the vcpkg DLLs next to the Windows executables (and the
plugin DLLs into build/plugins); yuzu-agent.iss then installs
agents\\core\\*.dll. It used to swallow PermissionError on every copy, so a
copy that never happened left the build tree without the DLL and exited 0.
Now a failed copy whose destination is absent fails the run (exit 1, no
stamp, the DLL named on stderr), and one whose destination exists (a running
agent holds the old copy) is a stderr warning. Which DLLs are copied is
unchanged, including the release build's non-existent "other config"
directory. Stdlib only; the copy failure is injected, so it runs as root too.
"""

import contextlib
import importlib.util
import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "deploy_build_dlls.py"


def load():
    spec = importlib.util.spec_from_file_location("deploy_build_dlls", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class DeployBuildDlls(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_deploy_dlls_")
        self.tmp = Path(self._tmp.name)
        self.prefix = self.tmp / "vcpkg_installed" / "x64-windows"
        self.bin = self.prefix / "bin"
        self.bin.mkdir(parents=True)
        for n in ("fmt.dll", "spdlog.dll", "zlib1.dll"):
            (self.bin / n).write_bytes(n.encode())
        (self.prefix / "debug" / "bin").mkdir(parents=True)
        (self.prefix / "debug" / "bin" / "zlibd1.dll").write_bytes(b"debug")
        self.build = self.tmp / "build-windows"
        (self.build / "agents" / "plugins" / "os_info").mkdir(parents=True)
        (self.build / "agents" / "plugins" / "os_info" / "os_info.dll").write_bytes(b"plugin")

    def tearDown(self):
        self._tmp.cleanup()

    def run_main(self, fail_names=(), extra=()):
        mod = load()
        real_copy2 = shutil.copy2

        def copy2(src, dst, *a, **kw):
            if os.path.basename(src) in fail_names:
                raise PermissionError(13, "The process cannot access the file", dst)
            return real_copy2(src, dst, *a, **kw)

        argv = ["deploy_build_dlls.py", "--build-root", str(self.build), "--vcpkg-bin", str(self.bin), *extra]
        err = io.StringIO()
        with mock.patch.object(mod.shutil, "copy2", copy2), mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stderr(err):
            code = mod.main()
        return code, err.getvalue()

    def test_clean_copy(self):
        code, err = self.run_main()
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        core = self.build / "agents" / "core"
        self.assertEqual(sorted(p.name for p in core.iterdir()), ["fmt.dll", "spdlog.dll", "zlib1.dll"])
        self.assertTrue((self.build / "plugins" / "os_info.dll").is_file())
        self.assertTrue((self.build / ".dlls_deployed").is_file())

    def test_failed_copy_with_no_destination_fails(self):
        code, err = self.run_main(fail_names=("spdlog.dll",))
        self.assertEqual(code, 1, err)
        self.assertIn("ERROR: could not copy", err)
        self.assertIn("spdlog.dll", err)
        self.assertFalse((self.build / ".dlls_deployed").exists(), "stamp written for an incomplete copy")

    def test_failed_plugin_copy_fails(self):
        code, err = self.run_main(fail_names=("os_info.dll",))
        self.assertEqual(code, 1, err)
        self.assertIn("os_info.dll", err)

    def test_locked_existing_destination_warns(self):
        self.assertEqual(self.run_main()[0], 0)
        newer = self.bin / "fmt.dll"
        newer.write_bytes(b"newer")
        os.utime(newer, (os.path.getmtime(newer) + 60,) * 2)
        code, err = self.run_main(fail_names=("fmt.dll",))
        self.assertEqual(code, 0, err)
        self.assertIn("WARNING: could not replace", err)
        self.assertIn("fmt.dll", err)
        self.assertEqual((self.build / "agents" / "core" / "fmt.dll").read_bytes(), b"fmt.dll")

    def test_release_build_copies_no_debug_dll(self):
        # The release branch's "other config" path does not resolve to
        # <prefix>/debug/bin; this pins that no debug-only DLL reaches a release
        # agents/core (which yuzu-agent.iss installs by glob).
        code, err = self.run_main()
        self.assertEqual(code, 0, err)
        self.assertFalse((self.build / "agents" / "core" / "zlibd1.dll").exists())

    def test_missing_vcpkg_dir_is_reported(self):
        shutil.rmtree(self.bin)
        with mock.patch.dict(os.environ, {"VCPKG_ROOT": str(self.tmp / "no-vcpkg")}), \
                mock.patch.object(os.path, "expanduser", lambda p: str(self.tmp / "no-home")):
            code, err = self.run_main()
        self.assertEqual(code, 0, err)
        self.assertIn("WARNING: no vcpkg DLL directory found", err)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
