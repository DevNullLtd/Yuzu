#!/usr/bin/env python3
"""Regression tests for the builder/runtime ABI guard in Dockerfile.gateway (#2150).

The guard is a RUN step in the gateway image's runtime stage. It fails the
image build when the runtime's Alpine release or musl version differs from the
builder's, or when musl >= 1.2.6 is paired with an OTP whose ERTS sizes its
signal stack with the compile-time SIGSTKSZ (beam.smp then aborts at boot on
AMX-capable Intel CPUs, #1743). A guard that silently passes is worse than no
guard, and one shipped failing open once already: `apk version -t` prints
nothing for a version it cannot parse, which read as "not older".

These tests run the guard's real text, with Docker's line continuations
joined, under `sh`. Three things are substituted so it runs without Docker or
Alpine: the paths it reads (a temp-dir alpine-release, a fake musl loader that
prints `Version X`, the builder's env file) and `apk`, replaced by a shim that
implements `apk version -t` for plain dotted versions and, like apk, prints
nothing for anything else. The shim's comparison is not apk's in general; the
tests lock the guard's control flow, not apk's version semantics.
"""

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "deploy" / "docker" / "Dockerfile.gateway"
MOUNT = "--mount=type=bind,from=builder,source=/build-abi.env,target=/tmp/build-abi.env"

APK_SHIM = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import re, sys
    a = sys.argv[1:]
    if a[:2] != ["version", "-t"] or len(a) != 4:
        sys.exit(2)
    import os
    mode = os.environ.get("YUZU_TEST_APK_SILENT")
    if mode == "1":
        sys.exit(1)
    if mode == "musl-double":
        print("" if a[3] == "1.2.6" else "<<")
        sys.exit(0)
    v = r"[0-9]+(\\.[0-9]+)*"
    if not (re.fullmatch(v, a[2]) and re.fullmatch(v, a[3])):
        sys.exit(1)
    x = [int(p) for p in a[2].split(".")]
    y = [int(p) for p in a[3].split(".")]
    n = max(len(x), len(y))
    x += [0] * (n - len(x))
    y += [0] * (n - len(y))
    print("<" if x < y else ">" if x > y else "=")
    """
)


def guard_body():
    """The guard RUN's shell text, continuations joined as Docker does."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.startswith("RUN ") and MOUNT in line:
            body = []
            j = i + 1
            while True:
                body.append(lines[j])
                if not lines[j].rstrip("\n").endswith("\\"):
                    break
                j += 1
            return re.sub(r"\\\n", "", "".join(body)).strip()
    raise AssertionError("abi-guard RUN step not found in Dockerfile.gateway")


@unittest.skipIf(os.name == "nt" or shutil.which("sh") is None, "needs a POSIX sh")
class AbiGuard(unittest.TestCase):
    def run_guard(self, build, runtime_alpine, runtime_musl, apk_silent=False):
        """build: the raw bytes of /build-abi.env, as the builder writes it."""
        with tempfile.TemporaryDirectory(prefix="yuzu_test_abi_guard_") as d:
            d = Path(d)
            (d / "bin").mkdir()
            (d / "lib").mkdir()
            apk = d / "bin" / "apk"
            apk.write_text(APK_SHIM.replace("/usr/bin/env python3", sys.executable))
            loader = d / "lib" / "ld-musl-x86_64.so.1"
            loader.write_text(
                "#!/bin/sh\necho 'musl libc (x86_64)'\n"
                + (f"echo 'Version {runtime_musl}'\n" if runtime_musl else "")
                + "exit 1\n"
            )
            for f in (apk, loader):
                f.chmod(f.stat().st_mode | stat.S_IXUSR)
            (d / "alpine-release").write_text(runtime_alpine + "\n")
            (d / "build-abi.env").write_text(build)

            body = guard_body()
            for real, fake in (
                ("/tmp/build-abi.env", str(d / "build-abi.env")),
                ("/etc/alpine-release", str(d / "alpine-release")),
                ("/lib/ld-musl-*.so.1", str(d / "lib") + "/ld-musl-*.so.1"),
            ):
                self.assertIn(real, body, f"guard no longer reads {real}; update this test")
                body = body.replace(real, fake)
            env = dict(os.environ, PATH=f"{d / 'bin'}{os.pathsep}{os.environ['PATH']}")
            if apk_silent:
                env["YUZU_TEST_APK_SILENT"] = "1" if apk_silent is True else apk_silent
            r = subprocess.run(["sh", "-c", body], env=env, capture_output=True, text=True)
            return r.returncode, r.stdout + r.stderr

    @staticmethod
    def env(alpine, musl, otp):
        return f"BUILD_ALPINE={alpine}\nBUILD_MUSL={musl}\nBUILD_OTP={otp}\n"

    def assertPasses(self, *a):
        rc, out = self.run_guard(*a)
        self.assertEqual(rc, 0, out)

    def assertFails(self, *a, says=None, **kw):
        rc, out = self.run_guard(*a, **kw)
        self.assertNotEqual(rc, 0, out)
        if says:
            self.assertIn(says, out)

    # The shipped state: Alpine 3.23 / musl 1.2.5 on both sides, OTP 28.
    def test_matched_323_passes(self):
        self.assertPasses(self.env("3.23", "1.2.5", "28.5.0.2"), "3.23.6", "1.2.5")

    # The defect that shipped in 0.13.0 .. 0.14.0-rc4.
    def test_runtime_324_on_323_builder_fails(self):
        self.assertFails(self.env("3.23", "1.2.5", "28.5.0.2"), "3.24.1", "1.2.6", says="differs")

    # Same musl, different Alpine release: an OpenSSL ABI skew on its own.
    def test_alpine_mismatch_same_musl_fails(self):
        self.assertFails(self.env("3.22", "1.2.5", "28.5.0.2"), "3.23.6", "1.2.5", says="differs")

    def test_non_dotted_alpine_fails(self):
        self.assertFails(self.env("edge", "1.2.5", "28.5.0.2"), "3.23.6", "1.2.5",
                         says="not a plain dotted version")
        self.assertFails(self.env("3.23", "1.2.5", "28.5.0.2"), "3.23_alpha20250108", "1.2.5",
                         says="not a plain dotted version")

    def test_malformed_dotted_versions_fail(self):
        for otp in ("29..1", "29.1.", ".29"):
            with self.subTest(otp=otp):
                self.assertFails(self.env("3.23", "1.2.5", otp), "3.23.6", "1.2.5",
                                 says="not a plain dotted version")

    # apk printing nothing for a validated version must never read as "not older".
    def test_silent_apk_fails_closed(self):
        self.assertFails(self.env("3.24", "1.2.6", "28.5.0.2"), "3.24.1", "1.2.6",
                         apk_silent=True, says="could not compare versions")

    def test_musl_mismatch_same_alpine_fails(self):
        self.assertFails(self.env("3.23", "1.2.5", "28.5.0.2"), "3.23.6", "1.2.6", says="differs")

    # Upstream erlang:28-alpine moving to 3.24 while still on OTP 28.
    def test_musl_126_with_otp28_fails(self):
        self.assertFails(self.env("3.24", "1.2.6", "28.5.0.2"), "3.24.1", "1.2.6", says="AMX")

    def test_musl_126_with_otp290_fails(self):
        self.assertFails(self.env("3.24", "1.2.6", "29.0.6"), "3.24.1", "1.2.6", says="AMX")

    def test_musl_126_with_otp291_passes(self):
        self.assertPasses(self.env("3.24", "1.2.6", "29.1"), "3.24.1", "1.2.6")

    def test_musl_126_with_otp30_passes(self):
        self.assertPasses(self.env("3.25", "1.2.7", "30.0.1"), "3.25.0", "1.2.7")

    # Real OTP_VERSION shapes apk cannot parse must fail closed (sec-F1).
    def test_otp_rc_tag_fails_closed(self):
        self.assertFails(self.env("3.24", "1.2.6", "29.0-rc1"), "3.24.1", "1.2.6",
                         says="not a plain dotted version")

    def test_otp_patched_marker_fails_closed(self):
        self.assertFails(self.env("3.23", "1.2.5", "28.5.0.2**"), "3.23.6", "1.2.5",
                         says="not a plain dotted version")

    # Two releases/*/OTP_VERSION files: the builder writes a second bare line,
    # and sourcing the env file fails on it (command not found) before the
    # guard's own checks run.
    def test_otp_two_versions_fails_closed(self):
        build = "BUILD_ALPINE=3.23\nBUILD_MUSL=1.2.5\nBUILD_OTP=28.5.0.2\n29.1\n"
        rc, out = self.run_guard(build, "3.23.6", "1.2.5")
        self.assertEqual(rc, 127, out)

    # Each comparison must be exactly one symbol; a pair that happens to be two
    # characters long in total ("" + "<<") must not pass.
    def test_apk_output_checked_per_comparison(self):
        rc, out = self.run_guard(self.env("3.24", "1.2.6", "28.5.0.2"), "3.24.1", "1.2.6",
                                 apk_silent="musl-double")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("could not compare versions", out)

    def test_empty_runtime_musl_fails(self):
        self.assertFails(self.env("3.23", "1.2.5", "28.5.0.2"), "3.23.6", "",
                         says="not a plain dotted version")

    def test_empty_build_otp_fails(self):
        self.assertFails(self.env("3.23", "1.2.5", ""), "3.23.6", "1.2.5",
                         says="not a plain dotted version")

    def test_empty_build_musl_fails(self):
        self.assertFails(self.env("3.23", "", "28.5.0.2"), "3.23.6", "1.2.5",
                         says="not a plain dotted version")


class BuilderWritesWhatGuardReads(unittest.TestCase):
    def test_builder_records_all_three_keys(self):
        text = DOCKERFILE.read_text(encoding="utf-8")
        writer = text[text.index("> /build-abi.env") - 600 : text.index("> /build-abi.env")]
        for key in ("BUILD_ALPINE=", "BUILD_MUSL=", "BUILD_OTP="):
            self.assertIn(key, writer)
            self.assertIn("$" + key.rstrip("="), guard_body())


if __name__ == "__main__":
    unittest.main(verbosity=2)
