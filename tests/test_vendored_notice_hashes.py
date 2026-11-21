#!/usr/bin/env python3
"""Every SHA-256 a vendored NOTICE records is the hash of the file it names.

The vendored web assets under server/core/static and server/core/vendor each
carry a `*-NOTICE.txt` that records the upstream source and the SHA-256 of the
vendored bytes (docs/cpp-conventions.md, docs/dependency-updates.md "Vendored
JavaScript assets"). test_static_js_bundle.cpp pins each file's byte count, but
a same-size edit keeps that green while the NOTICE hash goes stale. This test
closes that half.

Two recorded forms are understood:
  1. a `Vendored file: <repo-relative path>` line plus a `SHA-256: <hex>` line
     (echarts, three, three-orbit, cytoscape); the n-th `SHA-256:` line belongs
     to the n-th `Vendored file:` line;
  2. table rows `<hex>  <bytes>  <file name>` under a `SHA-256` heading, the
     file name relative to the NOTICE's directory (ibm-plex); the byte count is
     checked as well.

Any other 64-hex-digit token in a NOTICE fails as unbound, so a hash cannot be
recorded in a shape this test silently skips. A NOTICE recording no hash at all
is not this test's concern (qrcodegen today).

Overlap: `artifact-sbom.py check-vendored` (server/core/vendored-components.json)
also checks every NOTICE hash, but per component: each hash a NOTICE records
must be the hash of a file of a component that names that NOTICE as its
`notice`. This test binds each hash to the one file the NOTICE's own
`Vendored file:` line or table row names, which that check does not.

Stdlib only; never edits the checkout (the self-tests use a scratch copy).
"""

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTICE_ROOTS = ("server/core/static", "server/core/vendor")

HEX64 = re.compile(r"\b[0-9a-f]{64}\b")
SINGLE = re.compile(r"^SHA-256:\s*([0-9a-f]{64})\s*$")
VENDORED = re.compile(r"^Vendored file:\s*(\S+?),?(?:\s|$)")
ROW = re.compile(r"^\s*([0-9a-f]{64})\s+(\d+)\s+(\S+)\s*$")


def tracked_notices(root: Path):
    """The tracked *-NOTICE.txt files under NOTICE_ROOTS (falls back to a walk off git)."""
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--", *NOTICE_ROOTS],
                             capture_output=True, check=True).stdout.decode()
        names = [n for n in out.split("\0") if n]
    except (OSError, subprocess.CalledProcessError):
        names = [str(p.relative_to(root)) for r in NOTICE_ROOTS for p in (root / r).rglob("*")]
    return sorted(root / n for n in names if n.endswith("-NOTICE.txt"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_notice(root: Path, notice: Path):
    """Return a list of error strings for one NOTICE."""
    rel = notice.relative_to(root).as_posix()
    errs = []
    singles, vendored, seen = [], [], set()
    for ln, line in enumerate(notice.read_text(encoding="utf-8").splitlines(), 1):
        if m := SINGLE.match(line):
            singles.append((ln, m.group(1)))
            seen.add((ln, m.group(1)))
        elif m := VENDORED.match(line):
            vendored.append(m.group(1))
        elif m := ROW.match(line):
            seen.add((ln, m.group(1)))
            target = notice.parent / m.group(3)
            if not target.is_file():
                errs.append(f"{rel}:{ln}: records {m.group(3)}, which does not exist")
                continue
            if target.stat().st_size != int(m.group(2)):
                errs.append(f"{rel}:{ln}: records {m.group(3)} as {m.group(2)} bytes; "
                            f"it is {target.stat().st_size}")
            if sha256(target) != m.group(1):
                errs.append(f"{rel}:{ln}: records SHA-256 {m.group(1)[:16]}... for {m.group(3)}; "
                            f"it is {sha256(target)[:16]}...")
        for h in HEX64.findall(line):
            if (ln, h) not in seen:
                errs.append(f"{rel}:{ln}: a SHA-256-shaped value in neither recorded form "
                            "('SHA-256: <hex>' with a 'Vendored file:' line, or "
                            "'<hex>  <bytes>  <name>')")
    if singles and len(singles) != len(vendored):
        errs.append(f"{rel}: {len(singles)} 'SHA-256:' line(s) but {len(vendored)} "
                    "'Vendored file:' line(s); each hash must name its file")
        return errs
    for (ln, h), path in zip(singles, vendored):
        target = root / path
        if not target.is_file():
            errs.append(f"{rel}:{ln}: names {path}, which does not exist")
        elif sha256(target) != h:
            errs.append(f"{rel}:{ln}: records SHA-256 {h[:16]}... for {path}; "
                        f"it is {sha256(target)[:16]}...")
    return errs


def check_tree(root: Path):
    notices = tracked_notices(root)
    errs = []
    for n in notices:
        errs.extend(check_notice(root, n))
    return notices, errs


class Checkout(unittest.TestCase):
    def test_every_recorded_hash_matches_its_file(self):
        notices, errs = check_tree(ROOT)
        self.assertGreaterEqual(len(notices), 5, f"expected the vendored NOTICEs, found {notices}")
        self.assertEqual(errs, [], "\n".join(errs))


class SelfTest(unittest.TestCase):
    """Mutations on a scratch copy, so a broken detector cannot pass silently."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_notice_")
        self.tmp = Path(self._tmp.name)
        for r in NOTICE_ROOTS:
            shutil.copytree(ROOT / r, self.tmp / r)

    def tearDown(self):
        self._tmp.cleanup()

    def errs(self):
        _, errs = check_tree(self.tmp)
        return errs

    def test_copy_passes(self):
        self.assertEqual(self.errs(), [])

    def test_same_size_edit_to_vendored_file_fails(self):
        p = self.tmp / "server/core/static/cytoscape.min.js"
        data = bytearray(p.read_bytes())
        data[100] = ord("x") if data[100] != ord("x") else ord("y")
        p.write_bytes(bytes(data))
        self.assertTrue(any("cytoscape.min.js" in e for e in self.errs()), self.errs())

    def test_edited_font_row_fails(self):
        p = self.tmp / "server/core/vendor/ibm-plex/ibm-plex-sans-latin-400-normal.woff2"
        data = bytearray(p.read_bytes())
        data[-1] ^= 0xFF
        p.write_bytes(bytes(data))
        self.assertTrue(any("ibm-plex-sans-latin-400-normal.woff2" in e for e in self.errs()),
                        self.errs())

    def test_stale_notice_hash_fails(self):
        p = self.tmp / "server/core/vendor/echarts-NOTICE.txt"
        text = p.read_text(encoding="utf-8")
        p.write_text(re.sub(r"(SHA-256: )[0-9a-f]{64}", r"\g<1>" + "0" * 64, text), encoding="utf-8")
        self.assertTrue(any("echarts.min.js" in e for e in self.errs()), self.errs())

    def test_hash_in_unknown_form_fails(self):
        p = self.tmp / "server/core/vendor/three-NOTICE.txt"
        p.write_text(p.read_text(encoding="utf-8") + "\nsha256 = " + "a" * 64 + "\n",
                     encoding="utf-8")
        self.assertTrue(any("neither recorded form" in e for e in self.errs()), self.errs())

    def test_hash_without_named_file_fails(self):
        p = self.tmp / "server/core/vendor/three-orbit-NOTICE.txt"
        text = p.read_text(encoding="utf-8")
        p.write_text(re.sub(r"(?m)^Vendored file:.*\n", "", text), encoding="utf-8")
        self.assertTrue(any("each hash must name its file" in e for e in self.errs()), self.errs())


if __name__ == "__main__":
    unittest.main()
