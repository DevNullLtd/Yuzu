#!/usr/bin/env python3
"""Tests for scripts/ci/prune-buildcache.py (WP15/S9, governance BC-1/K14).

The release publish jobs export buildx `type=local` caches that never drop
superseded blobs. The pruner must remove only blobs no index can reach, never
touch a directory that may be in use or that it cannot make sense of, and
never leave an index naming a removed blob. The layout below has the shape a
real `cache-to type=local,mode=max` export writes (checked against one on
2026-11-18): index.json -> cache manifest -> BuildKit cache config (layers
named under "blob", records under cache-key "digest"s that are not blobs) and
layer blobs. Stdlib only.
"""

import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ci" / "prune-buildcache.py"
spec = importlib.util.spec_from_file_location("prune_buildcache", SCRIPT)
pb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pb)

DAY = 86400


def put(cache, data):
    h = hashlib.sha256(data).hexdigest()
    p = cache / "blobs" / "sha256" / h
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return h


def export(cache, layer_payloads):
    """Write one cache export (as buildx does: new blobs, then index.json)."""
    layers = [put(cache, b"\x1f\x8b" + x) for x in layer_payloads]
    config = {"layers": [{"blob": "sha256:" + h, "parent": i - 1} for i, h in enumerate(layers)],
              "records": [{"digest": "sha256:" + hashlib.sha256(b"key%d" % i).hexdigest(),
                           "layers": [{"layer": i}]} for i in range(len(layers))]}
    cfg = put(cache, json.dumps(config).encode())
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.buildkit.cacheconfig.v0",
                           "digest": "sha256:" + cfg, "size": 1},
                "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                            "digest": "sha256:" + h, "size": 1,
                            "annotations": {"containerd.io/uncompressed": "sha256:" + "0" * 64}}
                           for h in layers]}
    man = put(cache, json.dumps(manifest).encode())
    index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
             "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": "sha256:" + man, "size": 1}]}
    (cache / "index.json").write_text(json.dumps(index))
    (cache / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    return {man, cfg, *layers}


def age_all(cache, seconds):
    t = time.time() - seconds
    for root, _d, files in os.walk(cache):
        for f in files:
            os.utime(os.path.join(root, f), (t, t))


class PruneBuildcache(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_buildcache_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cache = self.tmp / "server"
        self.cache.mkdir()

    def blobs(self):
        return set(os.listdir(self.cache / "blobs" / "sha256"))

    def test_superseded_blobs_go_and_the_current_export_stays(self):
        old = export(self.cache, [b"base", b"pkgs-attempt-1"])
        current = export(self.cache, [b"base", b"pkgs-attempt-2"])
        age_all(self.cache, 2 * DAY)
        out = pb.prune(str(self.cache))
        self.assertIn("removed", out)
        self.assertEqual(self.blobs(), current)
        self.assertTrue(old - current)
        self.assertTrue(current <= pb.referenced(str(self.cache)))

    def test_recently_written_directory_is_skipped(self):
        export(self.cache, [b"a"])
        export(self.cache, [b"b"])
        before = self.blobs()
        out = pb.prune(str(self.cache))
        self.assertIn("skipped", out)
        self.assertEqual(self.blobs(), before)

    def test_young_unreferenced_blob_is_kept(self):
        export(self.cache, [b"a"])
        current = export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        young = put(self.cache, b"\x1f\x8bbeing-written")
        t = time.time() - 4 * 3600  # older than quiet-hours, younger than min-age
        os.utime(self.cache / "blobs" / "sha256" / young, (t, t))
        pb.prune(str(self.cache))
        self.assertEqual(self.blobs(), current | {young})

    def test_dry_run_removes_nothing(self):
        export(self.cache, [b"a"])
        export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        before = self.blobs()
        self.assertIn("would remove", pb.prune(str(self.cache), dry_run=True))
        self.assertEqual(self.blobs(), before)

    def test_incoherent_cache_is_not_touched(self):
        current = export(self.cache, [b"a"])
        export(self.cache, [b"b"])  # current index now names b's blobs
        age_all(self.cache, 2 * DAY)
        # Remove a layer the current index needs: the tree is already broken,
        # so nothing is deleted from it.
        idx = json.loads((self.cache / "index.json").read_text())
        man = json.loads((self.cache / "blobs" / "sha256" /
                          idx["manifests"][0]["digest"][7:]).read_bytes())
        os.remove(self.cache / "blobs" / "sha256" / man["layers"][0]["digest"][7:])
        before = self.blobs()
        out = pb.prune(str(self.cache))
        self.assertIn("skipped", out)
        self.assertEqual(self.blobs(), before)
        self.assertTrue(current)

    def test_unreadable_index_is_not_touched(self):
        export(self.cache, [b"a"])
        (self.cache / "index.json").write_text("{not json")
        age_all(self.cache, 2 * DAY)
        before = self.blobs()
        self.assertIn("skipped", pb.prune(str(self.cache)))
        self.assertEqual(self.blobs(), before)

    def test_record_digests_and_diff_ids_are_not_required_blobs(self):
        current = export(self.cache, [b"a", b"b"])
        age_all(self.cache, 2 * DAY)
        self.assertTrue(current <= pb.referenced(str(self.cache)))

    def test_index_that_changes_to_name_a_removed_blob_removes_the_whole_directory(self):
        old = export(self.cache, [b"a"])
        current = export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        gone = sorted(old - current)[0]

        def concurrent_export():
            # An export in the prune window re-used a blob the sweep has just
            # removed and pointed the index at it: that cache is broken.
            idx = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                   "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                                  "digest": "sha256:" + gone, "size": 1}]}
            (self.cache / "index.json").write_text(json.dumps(idx))

        out = pb.prune(str(self.cache), after_sweep=concurrent_export)
        self.assertIn("REMOVED WHOLE DIRECTORY", out)
        self.assertFalse(self.cache.exists())

    def test_index_that_changes_harmlessly_keeps_the_directory(self):
        export(self.cache, [b"a"])
        current = export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        index = (self.cache / "index.json").read_text()

        def rewrite_same_content():
            (self.cache / "index.json").write_text(index + "\n")

        out = pb.prune(str(self.cache), after_sweep=rewrite_same_content)
        self.assertNotIn("REMOVED WHOLE DIRECTORY", out)
        self.assertEqual(self.blobs(), current)

    def test_non_cache_directory_is_skipped(self):
        (self.cache / "file").write_text("x")
        self.assertIn("not a type=local cache", pb.prune(str(self.cache)))

    def test_cli_refuses_unsafe_windows(self):
        with self.assertRaises(SystemExit):
            pb.main(["--quiet-hours", "1", str(self.cache)])


if __name__ == "__main__":
    unittest.main()
