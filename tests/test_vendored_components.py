#!/usr/bin/env python3
"""The vendored-components manifest cannot drift from the files it describes.

server/core/vendored-components.json lists every third-party component compiled
into yuzu-server that no package manager describes: the web assets it serves
(htmx and its SSE extension, ECharts with the ZRender and tslib code bundled in
it, three.js, Cytoscape.js, IBM Plex) and the vendored C++ QR-code library.
scripts/ci/artifact-sbom.py puts them on the SBOM of every artifact holding
yuzu-server, so a file changed or added without its entry would ship an SBOM
that names the wrong bytes, or none. These tests pin `artifact-sbom.py
check-vendored`:

  - the checkout itself agrees with the manifest;
  - on a scratch copy of the tracked files, a changed vendored file, a new
    third-party file under server/core/vendor/ or server/core/static/, a
    changed htmx literal in static_js_bundle.cpp, a deleted file, a NOTICE
    recording a hash no listed file has, and a NOTICE whose SPDX licence
    differs from the manifest each fail, while a first-party `yuzu-*.js`, an
    edit to the .cpp outside the literals and a NOTICE with a correct hash pass;
  - an unresolved version stays null (never guessed), and a resolved one is in
    its purl.

Stdlib only; never edits the checkout (mutations happen on the copy).
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ci" / "artifact-sbom.py"
MANIFEST = "server/core/vendored-components.json"
COPIED = ["server/core/static", "server/core/vendor", "server/core/src/static_js_bundle.cpp", MANIFEST]


def run_check(root: Path):
    return subprocess.run([sys.executable, "-I", str(SCRIPT), "check-vendored", "--source-root", str(root)],
                          capture_output=True, text=True)


class Checkout(unittest.TestCase):
    def test_checkout_matches_manifest(self):
        r = run_check(ROOT)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(": OK", r.stdout)

    def test_manifest_records_what_was_asked(self):
        m = json.loads((ROOT / MANIFEST).read_text(encoding="utf-8"))
        by = {c["id"]: c for c in m["components"]}
        # The components the server is known to embed; a removal must be deliberate.
        for cid in ("htmx", "htmx-ext-sse", "echarts", "zrender", "tslib", "three", "cytoscape",
                    "ibm-plex-sans", "ibm-plex-mono", "qrcodegen"):
            self.assertIn(cid, by)
        self.assertEqual(by["cytoscape"]["purl"], "pkg:npm/cytoscape@3.33.3")
        for c in m["components"]:
            if c["version_status"] == "unresolved":
                self.assertIsNone(c["version"], c["id"])
            for f in c.get("files", []):
                self.assertRegex(f["sha256"], r"^[0-9a-f]{64}$")


class ScratchCopy(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_vendored_"))
        for rel in COPIED:
            src, dst = ROOT / rel, self.tmp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def assertFails(self, needle: str):
        r = run_check(self.tmp)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn(needle, r.stderr)

    def assertPasses(self):
        r = run_check(self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def edit_manifest(self, fn):
        p = self.tmp / MANIFEST
        m = json.loads(p.read_text(encoding="utf-8"))
        fn(m)
        p.write_text(json.dumps(m), encoding="utf-8")

    def test_copy_passes(self):
        self.assertPasses()

    def test_changed_vendored_file_fails(self):
        p = self.tmp / "server/core/vendor/echarts.min.js"
        p.write_bytes(p.read_bytes() + b"\n")
        self.assertFails("server/core/vendor/echarts.min.js: is 1034103 bytes")

    def test_changed_binary_file_fails(self):
        p = self.tmp / "server/core/vendor/ibm-plex/ibm-plex-mono-latin-400-normal.woff2"
        data = bytearray(p.read_bytes())
        data[100] ^= 0xFF
        p.write_bytes(bytes(data))
        self.assertFails("ibm-plex-mono-latin-400-normal.woff2: is 17544 bytes")

    def test_new_vendor_file_fails(self):
        (self.tmp / "server/core/vendor/leaflet.min.js").write_text("/* leaflet */\n")
        self.assertFails("server/core/vendor/leaflet.min.js: not in vendored-components.json")

    def test_new_third_party_static_file_fails(self):
        (self.tmp / "server/core/static/jquery.min.js").write_text("/* jquery */\n")
        self.assertFails("server/core/static/jquery.min.js: not in vendored-components.json")

    def test_new_first_party_static_file_passes(self):
        (self.tmp / "server/core/static/yuzu-new-page.js").write_text("// ours\n")
        self.assertPasses()

    def test_changed_htmx_literal_fails(self):
        p = self.tmp / "server/core/src/static_js_bundle.cpp"
        s = p.read_text(encoding="utf-8")
        self.assertIn('historyCacheSize:10', s)
        p.write_text(s.replace('historyCacheSize:10', 'historyCacheSize:11', 1), encoding="utf-8")
        self.assertFails("server/core/src/static_js_bundle.cpp#kHtmxJsPart1+kHtmxJsPart2+kHtmxJsPart3+kHtmxJsPart4")

    def test_changed_sse_literal_fails(self):
        p = self.tmp / "server/core/src/static_js_bundle.cpp"
        s = p.read_text(encoding="utf-8")
        p.write_text(s.replace("Server Sent Events Extension", "Server-Sent Events Extension", 1), encoding="utf-8")
        self.assertFails("static_js_bundle.cpp#kSseJs")

    def test_edit_outside_the_literals_passes(self):
        p = self.tmp / "server/core/src/static_js_bundle.cpp"
        p.write_text("// a comment added above the literals\n" + p.read_text(encoding="utf-8"), encoding="utf-8")
        self.assertPasses()

    def test_deleted_file_fails(self):
        (self.tmp / "server/core/vendor/three-orbit-controls.js").unlink()
        self.assertFails("server/core/vendor/three-orbit-controls.js: no such file")

    def test_stale_notice_hash_fails(self):
        p = self.tmp / "server/core/vendor/echarts-NOTICE.txt"
        s = p.read_text(encoding="utf-8")
        p.write_text(s.replace("bf4a223524e40b77", "0000000000000000", 1), encoding="utf-8")
        self.assertFails("echarts-NOTICE.txt records SHA-256 0000000000000000")

    def test_notice_with_a_listed_hash_passes(self):
        # A NOTICE beside a vendored file (as fix/wp14 adds for Cytoscape) is
        # accepted when every hash it records is a listed file's.
        (self.tmp / "server/core/static/cytoscape-NOTICE.txt").write_text(
            "SHA-256: 5bca02e1e46211b7a34e661f033b899306edc3595ed02a01f280a860a509b9de\n"
            "SPDX-License-Identifier: MIT\n")
        self.assertPasses()

    def test_notice_licence_disagreeing_fails(self):
        p = self.tmp / "server/core/vendor/three-NOTICE.txt"
        p.write_text(p.read_text(encoding="utf-8").replace("SPDX-License-Identifier: MIT",
                                                           "SPDX-License-Identifier: Apache-2.0"), encoding="utf-8")
        self.assertFails("three: server/core/vendor/three-NOTICE.txt says SPDX-License-Identifier: Apache-2.0")

    def test_guessed_version_fails(self):
        def guess(m):
            next(c for c in m["components"] if c["id"] == "htmx-ext-sse")["version"] = "2.2.3"
        self.edit_manifest(guess)
        self.assertFails("htmx-ext-sse: unresolved, so `version` must be null (do not guess)")

    def test_resolved_purl_without_version_fails(self):
        def drop(m):
            next(c for c in m["components"] if c["id"] == "echarts")["purl"] = "pkg:npm/echarts"
        self.edit_manifest(drop)
        self.assertFails("echarts: resolved, so its purl must carry the version")

    def test_listed_file_outside_tracked_roots_fails(self):
        def move(m):
            next(c for c in m["components"] if c["id"] == "qrcodegen")["files"][0]["path"] = MANIFEST
        self.edit_manifest(move)
        self.assertFails("a vendored file must lie under")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
