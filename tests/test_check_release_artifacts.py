#!/usr/bin/env python3
"""Regression net for scripts/check-release-artifacts.sh (#5242).

The release job runs that script before SHA256SUMS and `gh release create`.
Its expected SBOM set must include the three chisel images now that
docker-publish-chisel is in the release job's needs; while it was not, rc2,
rc4 and rc6 published without some of those SBOMs and nothing went red.

These tests read the script's own SBOM_BASES, check it names every chisel
image, run the real script against a synthetic complete artifacts directory
(it must pass), then remove each expected SBOM in turn (it must fail and name
the file). Since S8 every .deb/.rpm/.exe/.pkg also needs its own SBOM pair,
and an SBOM that belongs to no artifact of the release is refused. Stdlib
only; needs a POSIX bash, so it skips on Windows.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check-release-artifacts.sh"
VERSION = "0.14.0-rc9"

ARCHIVES = ["yuzu-linux-x64.tar.gz", "yuzu-gateway-linux-x64.tar.gz",
            "yuzu-agent-windows-x64.zip", "yuzu-agent-macos-arm64.tar.gz"]
PACKAGES = ["yuzu-server_0.14.0-rc9_amd64.deb", "yuzu-server-0.14.0-0.1.rc9.x86_64.rpm",
            "YuzuAgentSetup-0.14.0_rc9.exe",
            "YuzuAgent-0.14.0_rc9-arm64.pkg"]
CHISEL = ["yuzu-server-chisel-image", "yuzu-gateway-chisel-image", "yuzu-agent-chisel-image"]


def script_sbom_bases() -> list:
    """The SBOM_BASES array as the script declares it, so this test cannot
    drift from it."""
    text = SCRIPT.read_text(encoding="utf-8")
    block = re.search(r"^SBOM_BASES=\((.*?)^\)", text, re.S | re.M).group(1)
    return re.findall(r'^\s*"([^"]+)"', block, re.M)


def make_artifacts(d: Path) -> None:
    for name in ARCHIVES + PACKAGES:
        (d / name).write_bytes(b"x")
    for base in script_sbom_bases() + [package_stem(p) for p in PACKAGES]:
        for fmt in ("cdx.json", "spdx.json"):
            (d / f"{base}.{fmt}").write_text(json.dumps({"name": base}))


def package_stem(name: str) -> str:
    return name.rsplit(".", 1)[0]


# Not on Windows: there `bash` resolves to the WSL stub, which refuses to run as
# LOCAL SYSTEM on the CI runners (ci.yml). Linux CI and Docs Lint cover it.
@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None, "needs a POSIX bash")
class CheckReleaseArtifacts(unittest.TestCase):
    def run_script(self, d: Path) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(SCRIPT), str(d), VERSION],
                              capture_output=True, text=True)

    def test_script_expects_every_chisel_sbom(self):
        self.assertTrue(set(CHISEL) <= set(script_sbom_bases()), script_sbom_bases())

    def test_complete_set_passes(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
            d = Path(t)
            make_artifacts(d)
            r = self.run_script(d)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_each_missing_sbom_fails(self):
        for base in script_sbom_bases():
            for fmt in ("cdx.json", "spdx.json"):
                with self.subTest(sbom=f"{base}.{fmt}"), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                    d = Path(t)
                    make_artifacts(d)
                    (d / f"{base}.{fmt}").unlink()
                    r = self.run_script(d)
                    self.assertNotEqual(r.returncode, 0, f"{base}.{fmt} missing but the gate passed")
                    self.assertIn(f"missing SBOM: {base}.{fmt}", r.stderr)

    def test_each_missing_package_sbom_fails(self):
        for pkg in PACKAGES:
            for fmt in ("cdx.json", "spdx.json"):
                sbom = f"{package_stem(pkg)}.{fmt}"
                with self.subTest(sbom=sbom), tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                    d = Path(t)
                    make_artifacts(d)
                    (d / sbom).unlink()
                    r = self.run_script(d)
                    self.assertNotEqual(r.returncode, 0, f"{sbom} missing but the gate passed")
                    self.assertIn(f"missing SBOM for {pkg}: {sbom}", r.stderr)

    def test_orphan_sbom_is_refused(self):
        # An SBOM for a package this release does not carry (a leftover from an
        # earlier build) would be signed into SHA256SUMS: refuse it.
        # Both formats, and a stem of each package kind, so neither the
        # *.spdx.json glob nor one extension's lookup can quietly drop out.
        for orphan in ("yuzu-agent_0.14.0-rc8_amd64.cdx.json", "yuzu-agent_0.14.0-rc8_amd64.spdx.json",
                       "yuzu-server-0.14.0-0.1.rc8.x86_64.spdx.json", "YuzuAgentSetup-0.14.0_rc8.cdx.json",
                       "YuzuAgent-0.14.0_rc8-arm64.spdx.json"):
            with self.subTest(orphan=orphan), tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                d = Path(t)
                make_artifacts(d)
                (d / orphan).write_text("{}")
                r = self.run_script(d)
                self.assertNotEqual(r.returncode, 0, f"orphan SBOM {orphan} present but the gate passed")
                self.assertIn(f"file={orphan}::SBOM describes no artifact of this release", r.stderr)

    def test_retired_assets_are_refused(self):
        # ADR-0035 step 2: a server installer or an old-name Windows/macOS
        # archive or SBOM must fail the gate, not be hashed into SHA256SUMS.
        for stray in ("YuzuServerSetup-0.14.0_rc9.exe", "yuzu-windows-x64.zip",
                      "yuzu-macos-arm64.tar.gz", "yuzu-windows-x64.cdx.json"):
            with self.subTest(stray=stray), \
                    tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                d = Path(t)
                make_artifacts(d)
                (d / stray).write_bytes(b"x")
                r = self.run_script(d)
                self.assertNotEqual(r.returncode, 0, f"{stray} present but the gate passed")
                self.assertIn(f"release must not carry {stray}", r.stderr)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
