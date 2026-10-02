#!/usr/bin/env python3
"""Regression net for scripts/check-release-artifacts.sh (#5242).

The release job runs that script before SHA256SUMS and `gh release create`.
Its expected SBOM set must include the three chisel images now that
docker-publish-chisel is in the release job's needs; while it was not, rc2,
rc4 and rc6 published without some of those SBOMs and nothing went red.

These tests run the real script against a synthetic, complete artifacts
directory (it must pass), then remove each chisel SBOM in turn (it must
fail and name the file). Stdlib only, needs bash; skips where bash is absent.
"""

import json
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
            "yuzu-windows-x64.zip", "yuzu-macos-arm64.tar.gz"]
PACKAGES = ["yuzu-server_0.14.0-rc9_amd64.deb", "yuzu-server-0.14.0-0.1.rc9.x86_64.rpm",
            "YuzuAgentSetup-0.14.0_rc9.exe", "YuzuServerSetup-0.14.0_rc9.exe",
            "YuzuAgent-0.14.0_rc9-arm64.pkg"]
SBOM_BASES = ["yuzu-linux-x64", "yuzu-gateway-linux-x64", "yuzu-windows-x64",
              "yuzu-macos-arm64", "yuzu-server-image", "yuzu-gateway-image",
              "yuzu-postgres-image", "yuzu-server-chisel-image",
              "yuzu-gateway-chisel-image", "yuzu-agent-chisel-image"]
CHISEL = ["yuzu-server-chisel-image", "yuzu-gateway-chisel-image", "yuzu-agent-chisel-image"]


def make_artifacts(d: Path) -> None:
    for name in ARCHIVES + PACKAGES:
        (d / name).write_bytes(b"x")
    for base in SBOM_BASES:
        for fmt in ("cdx.json", "spdx.json"):
            (d / f"{base}.{fmt}").write_text(json.dumps({"name": base}))


@unittest.skipIf(shutil.which("bash") is None, "needs bash")
class CheckReleaseArtifacts(unittest.TestCase):
    def run_script(self, d: Path) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(SCRIPT), str(d), VERSION],
                              capture_output=True, text=True)

    def test_complete_set_passes(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
            d = Path(t)
            make_artifacts(d)
            r = self.run_script(d)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_each_missing_chisel_sbom_fails(self):
        for base in CHISEL:
            for fmt in ("cdx.json", "spdx.json"):
                with self.subTest(sbom=f"{base}.{fmt}"), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_rel_") as t:
                    d = Path(t)
                    make_artifacts(d)
                    (d / f"{base}.{fmt}").unlink()
                    r = self.run_script(d)
                    self.assertNotEqual(r.returncode, 0, f"{base}.{fmt} missing but the gate passed")
                    self.assertIn(f"missing SBOM: {base}.{fmt}", r.stderr)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
