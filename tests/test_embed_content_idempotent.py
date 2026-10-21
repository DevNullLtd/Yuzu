#!/usr/bin/env python3
"""Regression net for server/core/scripts/embed_content.py's write-if-changed
behaviour (meson `docs` suite).

meson.build runs the generator as a build_always_stale custom_target whose
ninja rule has restat=1: an output whose mtime did not move prunes the
recompile of bundled_content.cpp and the relink of libyuzu_server_core /
yuzu-server / yuzu_server_tests. If the generator rewrites an unchanged file,
or its output is not deterministic, every `ninja` invocation silently pays
that cost again (~30 s measured). Nothing fails; the build just gets slow, so
only a test can hold the property.

Runs the real generator against the real content/ tree, into a per-run
yuzu_test_ temp dir. Needs PyYAML (hard build dependency; fail-closed like
test_capability_gate_consistency.py).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import yaml  # type: ignore[import-not-found]  # noqa: F401
except ImportError:
    print("ERROR: test_embed_content_idempotent.py requires PyYAML "
          "(`pip install pyyaml`).", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "server" / "core" / "scripts" / "embed_content.py"
CONTENT = ROOT / "content"
PAST_NS = 1_000_000_000 * 10**9   # 2001-09-09: far from any plausible 'now'


def run_gen(out: Path, hashseed: str | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if hashseed is not None:
        env["PYTHONHASHSEED"] = hashseed
    return subprocess.run([sys.executable, str(SCRIPT), str(CONTENT), str(out)],
                          capture_output=True, text=True, env=env, timeout=60)


class EmbedContentIdempotent(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="yuzu_test_embed_")
        self.addCleanup(self._td.cleanup)
        self.out = Path(self._td.name) / "bundled_content.cpp"

    def generate(self, **kw) -> bytes:
        r = run_gen(self.out, **kw)
        self.assertEqual(r.returncode, 0, r.stderr)
        return self.out.read_bytes()

    def test_second_run_is_byte_identical_and_does_not_touch_output(self):
        ref = self.generate()
        # Not vacuous: a real bundle, not an empty/skipped one.
        self.assertGreater(len(ref), 10_000)
        self.assertIn(b'R"BCT(', ref)
        # Backdate so a coarse-mtime filesystem cannot mask a rewrite.
        os.utime(self.out, ns=(PAST_NS, PAST_NS))
        self.assertEqual(self.out.stat().st_mtime_ns, PAST_NS)
        r = run_gen(self.out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.out.read_bytes(), ref)
        self.assertEqual(self.out.stat().st_mtime_ns, PAST_NS,
                         "unchanged output was rewritten: restat pruning is lost "
                         "and every ninja run recompiles + relinks the server")

    def test_truncated_output_is_rewritten(self):
        ref = self.generate()
        self.out.write_bytes(ref[: len(ref) // 2])      # crash-mid-write shape
        r = run_gen(self.out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.out.read_bytes(), ref)

    def test_empty_and_missing_output_are_written(self):
        ref = self.generate()
        self.out.write_bytes(b"")
        run_gen(self.out)
        self.assertEqual(self.out.read_bytes(), ref)
        self.out.unlink()
        r = run_gen(self.out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.out.read_bytes(), ref)

    def test_single_flipped_byte_is_rewritten(self):
        ref = self.generate()
        bad = bytearray(ref)
        bad[len(bad) // 2] ^= 0x01                      # same length, one bit
        self.out.write_bytes(bytes(bad))
        os.utime(self.out, ns=(PAST_NS, PAST_NS))
        r = run_gen(self.out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.out.read_bytes(), ref)
        self.assertGreater(self.out.stat().st_mtime_ns, PAST_NS)

    @unittest.skipIf(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                     "needs POSIX permissions enforced on the caller")
    def test_readonly_output_with_equal_bytes_is_tolerated(self):
        ref = self.generate()
        self.out.chmod(0o444)
        self.addCleanup(lambda: self.out.chmod(0o644))
        r = run_gen(self.out)          # must not try to open for write
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.out.read_bytes(), ref)

    def test_output_is_deterministic_across_hash_seeds(self):
        ref = self.generate(hashseed="0")
        for seed in ("1", "2", "random"):
            other = Path(self._td.name) / f"seed{seed}.cpp"
            r = run_gen(other, hashseed=seed)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(other.read_bytes(), ref,
                             f"PYTHONHASHSEED={seed} changed the bytes: "
                             "nondeterministic output defeats the byte compare")

    def test_stdout_counts_are_nonzero(self):          # guards an empty content root
        r = run_gen(self.out)
        m = re.search(r"\((\d+) definitions, (\d+) sets", r.stdout)
        self.assertIsNotNone(m, r.stdout)
        self.assertGreater(int(m.group(1)), 0)


if __name__ == "__main__":
    unittest.main()
