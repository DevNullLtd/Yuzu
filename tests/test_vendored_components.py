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
    third-party file under server/core/vendor/ or server/core/static/ (also
    in a subdirectory, whatever its name), a changed htmx literal in
    static_js_bundle.cpp, a deleted file, a symbolic link (to a file, to a
    directory, dangling) under a tracked root, a tracked root or a NOTICE's
    parent directory that is a link, an unreadable directory, a
    NOTICE no component names, one recording a hash that is not a file of a
    component naming it, one that is not UTF-8, one whose path leaves the
    checkout, and one whose SPDX licence differs from the manifest each fail,
    while a first-party `yuzu-*.js`, an edit to the .cpp outside the literals
    and a named NOTICE with its component's hash pass;
  - an unresolved version stays null (never guessed), and a resolved one is in
    its purl.

Stdlib only; never edits the checkout (mutations happen on the copy).
"""

import json
import os
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

    CYTOSCAPE_SHA = "5bca02e1e46211b7a34e661f033b899306edc3595ed02a01f280a860a509b9de"

    def name_notice(self, cid, rel):
        def add(m):
            c = next(c for c in m["components"] if c["id"] == cid)
            c["notice"] = (c.get("notice") or []) + [rel]
        self.edit_manifest(add)

    def unname_notice(self, cid, rel):
        def drop(m):
            c = next(c for c in m["components"] if c["id"] == cid)
            c["notice"] = [n for n in c.get("notice") or [] if n != rel]
            if not c["notice"]:
                del c["notice"]
        self.edit_manifest(drop)

    def test_notice_with_its_components_hash_passes(self):
        # A NOTICE beside a vendored file (#8257's Cytoscape NOTICE, which the
        # manifest names) is accepted when the component it attributes names it
        # and every hash it records is one of that component's files.
        p = self.tmp / "server/core/static/cytoscape-NOTICE.txt"
        self.assertIn(self.CYTOSCAPE_SHA, p.read_text(encoding="utf-8"))
        self.assertTrue(any(c["id"] == "cytoscape" and "server/core/static/cytoscape-NOTICE.txt" in c.get("notice", [])
                            for c in json.loads((self.tmp / MANIFEST).read_text(encoding="utf-8"))["components"]))
        self.assertPasses()

    def test_notice_no_component_names_fails(self):
        # An attribution-named file is exempt from listing only as some
        # component's `notice`: otherwise any file could be named *-NOTICE.txt.
        self.unname_notice("cytoscape", "server/core/static/cytoscape-NOTICE.txt")
        self.assertFails("server/core/static/cytoscape-NOTICE.txt: an attribution file no component in "
                         "vendored-components.json names as its `notice`")
        (self.tmp / "server/core/vendor/qrcodegen/sub").mkdir()
        (self.tmp / "server/core/vendor/qrcodegen/sub/LICENSE.txt").write_text("MIT\n", encoding="utf-8")
        self.assertFails("server/core/vendor/qrcodegen/sub/LICENSE.txt: an attribution file no component")

    def test_notice_carrying_another_components_hash_fails(self):
        # echarts' NOTICE recording Cytoscape's (listed) hash in place of
        # echarts' own vouches for nothing about echarts.
        p = self.tmp / "server/core/vendor/echarts-NOTICE.txt"
        s = p.read_text(encoding="utf-8")
        echarts = "bf4a223524e40b77c304bec67e1222cf551f14880cf42c69dc046558e11c07b1"
        self.assertIn(echarts, s)
        p.write_text(s.replace(echarts, self.CYTOSCAPE_SHA, 1), encoding="utf-8")
        self.assertFails(f"server/core/vendor/echarts-NOTICE.txt records SHA-256 {self.CYTOSCAPE_SHA}, which is "
                         f"no file of a component naming it (echarts)")

    def test_utf16_notice_fails(self):
        # Re-encoded, its SHA-256 and SPDX lines no longer match the byte
        # patterns: it must fail, not pass unchecked.
        p = self.tmp / "server/core/vendor/echarts-NOTICE.txt"
        p.write_bytes(p.read_text(encoding="utf-8").encode("utf-16"))
        self.assertFails("server/core/vendor/echarts-NOTICE.txt is not UTF-8 text (the NOTICE of echarts")

    def test_utf16_notice_without_a_bom_fails(self):
        # BOM-less UTF-16 of ASCII text is valid UTF-8 with a NUL beside each
        # character, so its SPDX and SHA-256 lines would go unread; the NUL
        # fails it (a licence change hidden this way must not pass). The
        # ECharts NOTICE is ASCII-only, so its UTF-16 IS valid UTF-8: only the
        # NUL rule can fail it.
        p = self.tmp / "server/core/vendor/echarts-NOTICE.txt"
        raw = p.read_bytes()
        self.assertTrue(raw.isascii())
        text = raw.decode("ascii").replace("SPDX-License-Identifier: Apache-2.0", "SPDX-License-Identifier: MIT")
        self.assertNotEqual(text, raw.decode("ascii"))
        for enc in ("utf-16-le", "utf-16-be"):
            with self.subTest(encoding=enc):
                p.write_bytes(text.encode(enc))
                p.read_bytes().decode("utf-8")   # valid UTF-8, NULs and all
                self.assertFails("server/core/vendor/echarts-NOTICE.txt is not UTF-8 text (the NOTICE of echarts")

    def test_sha256_inside_a_longer_hex_run_fails(self):
        # A recorded SHA-256 glued to another hex digit is never extracted by
        # the 64-digit pattern, so a stale hash could hide there: the run fails.
        p = self.tmp / "server/core/vendor/echarts-NOTICE.txt"
        s = p.read_text(encoding="utf-8")
        echarts = "bf4a223524e40b77c304bec67e1222cf551f14880cf42c69dc046558e11c07b1"
        self.assertIn(echarts, s)
        for glued in (self.CYTOSCAPE_SHA + "0", "f" + self.CYTOSCAPE_SHA, echarts + self.CYTOSCAPE_SHA):
            with self.subTest(glued=glued[:8]):
                p.write_text(s.replace(echarts, glued, 1), encoding="utf-8")
                self.assertFails(f"server/core/vendor/echarts-NOTICE.txt holds a run of {len(glued)} hex digits")

    def test_notice_with_a_bom_passes(self):
        p = self.tmp / "server/core/vendor/echarts-NOTICE.txt"
        p.write_bytes(b"\xef\xbb\xbf" + p.read_bytes())
        self.assertPasses()

    def test_notice_path_outside_the_checkout_fails(self):
        self.name_notice("cytoscape", "../outside-NOTICE.txt")
        self.assertFails("cytoscape: notice ../outside-NOTICE.txt: path must be relative to the repository root")
        self.name_notice("three", "/etc/three-NOTICE.txt")
        self.assertFails("three: notice /etc/three-NOTICE.txt: path must be relative to the repository root")

    # ── What the walk must not skip ──────────────────────────────────────────

    def test_nested_file_named_like_first_party_fails(self):
        # first_party_patterns' `*` never crosses a `/`: a third-party file in
        # a subdirectory is never first-party, whatever the directory is named.
        (self.tmp / "server/core/static/yuzu-x").mkdir()
        (self.tmp / "server/core/static/yuzu-x/lodash.js").write_text("/* lodash */\n")
        self.assertFails("server/core/static/yuzu-x/lodash.js: not in vendored-components.json")

    def test_nested_yuzu_named_file_fails(self):
        (self.tmp / "server/core/static/sub").mkdir()
        (self.tmp / "server/core/static/sub/yuzu-foo.js").write_text("/* not ours */\n")
        self.assertFails("server/core/static/sub/yuzu-foo.js: not in vendored-components.json")

    def symlink(self, target: Path, link: Path, directory=False):
        try:
            os.symlink(target, link, target_is_directory=directory)
        except (OSError, NotImplementedError, AttributeError) as e:
            self.skipTest(f"cannot create a symbolic link here: {e}")

    def test_directory_link_under_a_tracked_root_fails(self):
        # os.walk does not descend into a linked directory: the .js in it
        # would otherwise go unchecked.
        outside = Path(tempfile.mkdtemp(prefix="yuzu_test_vendored_outside_"))
        self.addCleanup(shutil.rmtree, outside, True)
        (outside / "lodash.min.js").write_text("/* lodash */\n")
        self.symlink(outside, self.tmp / "server/core/vendor/lodash", directory=True)
        self.assertFails("server/core/vendor/lodash is a symbolic link;")

    def test_file_link_under_a_tracked_root_fails(self):
        self.symlink(self.tmp / "server/core/vendor/echarts.min.js", self.tmp / "server/core/static/charts.js")
        self.assertFails("server/core/static/charts.js is a symbolic link;")

    def test_listed_file_that_is_a_link_fails(self):
        p = self.tmp / "server/core/vendor/echarts.min.js"
        real = self.tmp / "echarts.real.js"
        p.rename(real)
        self.symlink(real, p)
        self.assertFails("server/core/vendor/echarts.min.js is a symbolic link;")

    def test_dangling_link_under_a_tracked_root_fails(self):
        self.symlink(self.tmp / "nowhere.js", self.tmp / "server/core/static/gone.js")
        self.assertFails("server/core/static/gone.js is a symbolic link;")

    # The walk's own link checks see only links BELOW a tracked root's top
    # directory (os.walk follows the top itself). The two tests below are
    # links only the per-path check (`_linked_part`) sees: without it, both
    # trees read as identical copies and pass.

    def test_tracked_root_that_is_a_link_fails(self):
        outside = Path(tempfile.mkdtemp(prefix="yuzu_test_vendored_outside_"))
        self.addCleanup(shutil.rmtree, outside, True)
        vendor = self.tmp / "server/core/vendor"
        shutil.copytree(vendor, outside / "vendor")
        shutil.rmtree(vendor)
        self.symlink(outside / "vendor", vendor, directory=True)
        self.assertFails("server/core/vendor is a symbolic link;")

    def test_notice_whose_parent_directory_is_a_link_fails(self):
        # A NOTICE outside the tracked roots (which the walk never visits)
        # read through a linked parent directory.
        outside = Path(tempfile.mkdtemp(prefix="yuzu_test_vendored_outside_"))
        self.addCleanup(shutil.rmtree, outside, True)
        shutil.copy2(self.tmp / "server/core/static/cytoscape-NOTICE.txt", outside / "cytoscape-NOTICE.txt")
        self.symlink(outside, self.tmp / "licenses", directory=True)
        self.name_notice("cytoscape", "licenses/cytoscape-NOTICE.txt")
        self.assertFails("licenses is a symbolic link;")

    def test_unreadable_directory_fails(self):
        if os.name == "nt" or os.geteuid() == 0:
            self.skipTest("a mode-000 directory is readable here")
        d = self.tmp / "server/core/vendor/locked"
        d.mkdir()
        (d / "lodash.min.js").write_text("/* lodash */\n")
        d.chmod(0)
        try:  # restored before tearDown's rmtree, which runs before cleanups
            self.assertFails("server/core/vendor/locked: cannot be read")
        finally:
            d.chmod(0o700)

    def test_notice_licence_disagreeing_fails(self):
        p = self.tmp / "server/core/vendor/three-NOTICE.txt"
        p.write_text(p.read_text(encoding="utf-8").replace("SPDX-License-Identifier: MIT",
                                                           "SPDX-License-Identifier: Apache-2.0"), encoding="utf-8")
        self.assertFails("three: server/core/vendor/three-NOTICE.txt says SPDX-License-Identifier: Apache-2.0")

    def test_id_outside_the_spdx_id_characters_fails(self):
        # The id is used as it is in the CycloneDX bom-ref and the SPDXID, and
        # SPDX allows only [A-Za-z0-9.-]: anything else would make the two
        # halves name the component differently, so the manifest refuses it.
        for bad in ("qr_codegen", "qr codegen", "qrcodegen/2", "qrcödegen"):
            with self.subTest(id=bad):
                def rename(m, bad=bad):
                    next(c for c in m["components"] if c["id"] == "qrcodegen")["id"] = bad
                shutil.copy2(ROOT / MANIFEST, self.tmp / MANIFEST)
                self.edit_manifest(rename)
                self.assertFails("`id` may hold only letters, digits, `.` and `-`")

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
