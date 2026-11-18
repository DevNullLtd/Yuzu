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

import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "ci" / "prune-buildcache.py"
LOCK = ROOT / "scripts" / "ci" / "buildcache-lock.sh"
CACHE_PRUNE = ROOT / ".github" / "workflows" / "cache-prune.yml"
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

    def prune(self, *a, **kw):
        ok, line = pb.prune(str(self.cache), *a, **kw)
        return line

    def test_superseded_blobs_go_and_the_current_export_stays(self):
        old = export(self.cache, [b"base", b"pkgs-attempt-1"])
        current = export(self.cache, [b"base", b"pkgs-attempt-2"])
        age_all(self.cache, 2 * DAY)
        out = self.prune()
        self.assertIn("removed", out)
        self.assertEqual(self.blobs(), current)
        self.assertTrue(old - current)
        self.assertTrue(current <= pb.referenced(str(self.cache)))

    def test_recently_written_directory_is_skipped(self):
        export(self.cache, [b"a"])
        export(self.cache, [b"b"])
        before = self.blobs()
        out = self.prune()
        self.assertIn("skipped", out)
        self.assertEqual(self.blobs(), before)

    def test_young_unreferenced_blob_is_kept(self):
        export(self.cache, [b"a"])
        current = export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        young = put(self.cache, b"\x1f\x8bbeing-written")
        t = time.time() - 4 * 3600  # older than quiet-hours, younger than min-age
        os.utime(self.cache / "blobs" / "sha256" / young, (t, t))
        self.prune()
        self.assertEqual(self.blobs(), current | {young})

    # ── G8P3-cpp-safety-1: a future mtime is an error, not a silent skip ──
    def test_file_dated_in_the_future_is_an_error_not_a_silent_skip(self):
        export(self.cache, [b"a"])
        export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        before = self.blobs()
        f = self.cache / "blobs" / "sha256" / sorted(before)[0]
        t = time.time() + 2 * 3600
        os.utime(f, (t, t))
        ok, line = pb.prune(str(self.cache))
        self.assertFalse(ok, line)
        self.assertIn("dated", line)
        self.assertIn("in the future", line)
        self.assertEqual(self.blobs(), before)
        # Within the slack it is a write in progress: skipped quietly.
        t = time.time() + 600
        os.utime(f, (t, t))
        ok, line = pb.prune(str(self.cache))
        self.assertTrue(ok, line)
        self.assertIn("written in the last", line)

    # ── G8P3-cpp-safety-2: an oversize JSON blob is not read as a layer ──
    def test_oversize_json_blob_skips_the_directory(self):
        export(self.cache, [b"a"])
        current = export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        before = self.blobs()
        orig = pb.MAX_JSON_BLOB
        pb.MAX_JSON_BLOB = 100  # the manifests and config here are larger
        self.addCleanup(setattr, pb, "MAX_JSON_BLOB", orig)
        ok, line = pb.prune(str(self.cache))
        self.assertFalse(ok, line)
        self.assertIn("starts like JSON but is larger than", line)
        self.assertEqual(self.blobs(), before)
        pb.MAX_JSON_BLOB = orig
        self.assertTrue(pb.prune(str(self.cache))[0])
        self.assertEqual(self.blobs(), current)

    def test_oversize_layer_is_still_a_layer(self):
        # Over the cap but not JSON (gzip magic): read as a layer, as before.
        export(self.cache, [b"a"])
        current = export(self.cache, [b"b" * 5000])
        age_all(self.cache, 2 * DAY)
        sizes = {h: os.path.getsize(self.cache / "blobs" / "sha256" / h) for h in current}
        json_max = max(n for h, n in sizes.items()
                       if (self.cache / "blobs" / "sha256" / h).read_bytes()[:1] in (b"{", b"["))
        self.assertGreater(max(sizes.values()), json_max)
        orig = pb.MAX_JSON_BLOB
        pb.MAX_JSON_BLOB = json_max
        self.addCleanup(setattr, pb, "MAX_JSON_BLOB", orig)
        ok, line = pb.prune(str(self.cache))
        self.assertTrue(ok, line)
        self.assertEqual(self.blobs(), current)

    def test_dry_run_removes_nothing(self):
        export(self.cache, [b"a"])
        export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        before = self.blobs()
        self.assertIn("would remove", self.prune(dry_run=True))
        self.assertEqual(self.blobs(), before)

    def test_broken_cache_is_removed_whole(self):
        # G8-chaos-1: an index naming a missing layer fails the next import
        # ("NotFound content") whatever happens, and skipping it forever left
        # the runner broken until someone deleted it by hand.
        export(self.cache, [b"a"])
        export(self.cache, [b"b"])  # current index now names b's blobs
        age_all(self.cache, 2 * DAY)
        idx = json.loads((self.cache / "index.json").read_text())
        man = json.loads((self.cache / "blobs" / "sha256" /
                          idx["manifests"][0]["digest"][7:]).read_bytes())
        os.remove(self.cache / "blobs" / "sha256" / man["layers"][0]["digest"][7:])
        ok, out = pb.prune(str(self.cache))
        self.assertTrue(ok, out)
        self.assertIn("REMOVED WHOLE DIRECTORY: broken", out)
        self.assertFalse(self.cache.exists())

    def test_broken_cache_is_only_reported_on_a_dry_run(self):
        export(self.cache, [b"a"])
        (self.cache / "index.json").write_text("{not json")
        age_all(self.cache, 2 * DAY)
        before = self.blobs()
        self.assertIn("would remove whole directory", self.prune(dry_run=True))
        self.assertEqual(self.blobs(), before)

    def test_unparseable_index_is_broken(self):
        export(self.cache, [b"a"])
        (self.cache / "index.json").write_text("{not json")
        age_all(self.cache, 2 * DAY)
        self.assertIn("REMOVED WHOLE DIRECTORY", self.prune())
        self.assertFalse(self.cache.exists())

    def test_recently_written_broken_cache_is_left_alone(self):
        export(self.cache, [b"a"])
        (self.cache / "index.json").write_text("{not json")
        self.assertIn("skipped", self.prune())
        self.assertTrue(self.cache.exists())

    # ── G8-chaos-1: a cache in use (its lock held) is never touched ──
    def test_cache_whose_lock_is_held_is_skipped(self):
        export(self.cache, [b"a"])
        current = export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        before = self.blobs()
        fd = os.open(str(self.cache) + ".lock", os.O_RDWR | os.O_CREAT, 0o644)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_SH)  # as buildcache-lock.sh holds it
        ok, out = pb.prune(str(self.cache))
        self.assertTrue(ok)
        self.assertIn("in use", out)
        self.assertEqual(self.blobs(), before)
        fcntl.flock(fd, fcntl.LOCK_UN)
        self.prune()
        self.assertEqual(self.blobs(), current)

    def test_symlinked_cache_or_lock_is_refused(self):
        export(self.cache, [b"a"])
        export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        link = self.tmp / "link"
        link.symlink_to(self.cache)
        before = self.blobs()
        ok, out = pb.prune(str(link))
        self.assertFalse(ok)
        self.assertIn("symlink", out)
        (self.tmp / "elsewhere").write_text("")
        Path(str(self.cache) + ".lock").symlink_to(self.tmp / "elsewhere")
        ok, out = pb.prune(str(self.cache))
        self.assertFalse(ok)
        self.assertIn("lock file", out)
        self.assertEqual(self.blobs(), before)

    # ── G8-PRUNE-oserror-abort: an odd entry is an error, never an abort ──
    def test_non_regular_entries_are_reported_not_removed(self):
        export(self.cache, [b"a"])
        current = export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        (self.cache / "blobs" / "sha256" / ("e" * 64)).mkdir()
        os.mkfifo(self.cache / "blobs" / "sha256" / ("f" * 64))
        t = time.time() - 2 * DAY
        for n in ("e" * 64, "f" * 64):
            os.utime(self.cache / "blobs" / "sha256" / n, (t, t))
        ok, out = pb.prune(str(self.cache))
        self.assertFalse(ok)
        self.assertIn("ERROR on 2", out)
        self.assertEqual(self.blobs(), current | {"e" * 64, "f" * 64})

    def test_referenced_fifo_or_deep_json_skips_without_hanging(self):
        old = export(self.cache, [b"a"])
        export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        idx = json.loads((self.cache / "index.json").read_text())
        man = idx["manifests"][0]["digest"][7:]
        p = self.cache / "blobs" / "sha256" / man
        p.unlink()
        os.mkfifo(p)
        os.utime(p, (time.time() - 2 * DAY,) * 2)
        before = self.blobs()
        ok, out = pb.prune(str(self.cache))  # a FIFO opened for reading would block
        self.assertFalse(ok)
        self.assertIn("nothing removed", out)
        self.assertEqual(self.blobs(), before)
        p.unlink()
        p.write_bytes(b"[" * 100000 + b"]" * 100000)
        os.utime(p, (time.time() - 2 * DAY,) * 2)
        ok, out = pb.prune(str(self.cache))
        self.assertFalse(ok)
        self.assertIn("nested too deeply", out)
        self.assertTrue(old <= self.blobs())

    def test_a_failing_removal_is_reported_and_the_rest_still_go(self):
        export(self.cache, [b"a"])
        export(self.cache, [b"c"])
        current = export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        victims = sorted(self.blobs() - current)
        real = os.remove

        def flaky(path, *a, **kw):
            if os.path.basename(path) == victims[0]:
                raise PermissionError(13, "Permission denied", path)
            return real(path, *a, **kw)

        pb.os.remove = flaky
        try:
            ok, out = pb.prune(str(self.cache))
        finally:
            pb.os.remove = real
        self.assertFalse(ok)
        self.assertIn("Permission denied", out)
        self.assertEqual(self.blobs(), current | {victims[0]})

    def test_cli_processes_every_directory_and_exits_1_on_an_error(self):
        other = self.tmp / "gateway"
        other.mkdir()
        export(self.cache, [b"a"])
        export(self.cache, [b"b"])
        export(other, [b"x"])
        cur_other = export(other, [b"y"])
        age_all(self.cache, 2 * DAY)
        age_all(other, 2 * DAY)
        (self.cache / "blobs" / "sha256" / ("e" * 64)).mkdir()
        os.utime(self.cache / "blobs" / "sha256" / ("e" * 64), (time.time() - 2 * DAY,) * 2)
        r = subprocess.run(["python3", "-I", str(SCRIPT), str(self.cache), str(other)],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("ERROR", r.stdout)
        self.assertEqual(set(os.listdir(other / "blobs" / "sha256")), cur_other)

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

        out = self.prune(after_sweep=concurrent_export)
        self.assertIn("REMOVED WHOLE DIRECTORY", out)
        self.assertFalse(self.cache.exists())

    def test_index_that_changes_harmlessly_keeps_the_directory(self):
        export(self.cache, [b"a"])
        current = export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        index = (self.cache / "index.json").read_text()

        def rewrite_same_content():
            (self.cache / "index.json").write_text(index + "\n")

        out = self.prune(after_sweep=rewrite_same_content)
        self.assertNotIn("REMOVED WHOLE DIRECTORY", out)
        self.assertEqual(self.blobs(), current)

    def test_non_cache_directory_is_skipped(self):
        (self.cache / "file").write_text("x")
        self.assertIn("not a type=local cache", self.prune())

    def test_cli_refuses_unsafe_windows(self):
        # The quiet window must exceed the longest publish job (120 min).
        for hours in ("1", "2"):
            with self.assertRaises(SystemExit):
                pb.main(["--quiet-hours", hours, str(self.cache)])


@unittest.skipUnless(shutil.which("flock") and shutil.which("bash"), "needs flock(1) and bash")
class BuildcacheLock(unittest.TestCase):
    """scripts/ci/buildcache-lock.sh against the pruner: a held lock makes the
    prune skip the directory; killing the holder (as the runner's end-of-job
    cleanup does) releases it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_buildcache_lock_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cache = self.tmp / "server"
        self.cache.mkdir()

    def test_held_lock_makes_the_prune_skip_and_kill_releases_it(self):
        export(self.cache, [b"a"])
        current = export(self.cache, [b"b"])
        age_all(self.cache, 2 * DAY)
        env = dict(os.environ, RUNNER_TEMP=str(self.tmp), YUZU_BUILDCACHE_LOCK_HOLD="60",
                   YUZU_BUILDCACHE_LOCK_WAIT="5")
        r = subprocess.run(["bash", str(LOCK), "hold", str(self.cache)], env=env,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        holder = int(re.search(r"^holder=(\d+)$", r.stdout, re.M).group(1))
        self.addCleanup(lambda: os.kill(holder, signal.SIGTERM) if _alive(holder) else None)
        before = set(os.listdir(self.cache / "blobs" / "sha256"))
        ok, out = pb.prune(str(self.cache))
        self.assertIn("in use", out)
        self.assertEqual(set(os.listdir(self.cache / "blobs" / "sha256")), before)
        os.kill(holder, signal.SIGTERM)
        for _ in range(50):
            if not _alive(holder):
                break
            time.sleep(0.1)
        ok, out = pb.prune(str(self.cache))
        self.assertIn("removed", out)
        self.assertEqual(set(os.listdir(self.cache / "blobs" / "sha256")), current)

    def test_lock_wait_times_out_while_a_prune_holds_it(self):
        fd = os.open(str(self.cache) + ".lock", os.O_RDWR | os.O_CREAT, 0o644)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        env = dict(os.environ, RUNNER_TEMP=str(self.tmp), YUZU_BUILDCACHE_LOCK_WAIT="1")
        r = subprocess.run(["bash", str(LOCK), "hold", str(self.cache)], env=env,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("could not take the lock", r.stderr)


def _alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:  # a zombie child of this process counts as gone
        return os.waitpid(pid, os.WNOHANG) == (0, 0)
    except ChildProcessError:
        return True


class CachePruneWiring(unittest.TestCase):
    """Lexical tripwires on cache-prune.yml (they read the YAML as text)."""

    def test_db_sweep_runs_even_when_a_prune_step_fails(self):
        text = CACHE_PRUNE.read_text(encoding="utf-8")
        i = text.index("- name: Sweep leaked yuzu_test_* databases (#1367)\n")
        step = text[i:text.index("\n\n", i)]
        self.assertIn("if: success() || failure()", step)

    def test_prune_walks_every_runners_cache(self):
        # G8-BC-1: each Big Tam runner has its own tool cache; one weekly job
        # must reach all four.
        text = CACHE_PRUNE.read_text(encoding="utf-8")
        i = text.index("- name: Prune unreferenced buildx cache blobs (WP15/S9)")
        step = text[i:text.index("- name:", i + 10)]
        self.assertIn('"${tc%/work-*/_tool}"/work-*/_tool/yuzu-docker-buildcache', step)
        self.assertIn("python3 -I scripts/ci/prune-buildcache.py", step)
        self.assertIn('exit "$rc"', step)

    @unittest.skipUnless(shutil.which("flock") and shutil.which("bash"), "needs flock(1) and bash")
    def test_stale_chisel_sweep_skips_a_locked_directory(self):
        # G8P3-cpp-safety-3: the 30-day chisel sweep removed a directory whole
        # with `rm -rf`, ignoring the lock a publish job holds on it. Run the
        # step's own script against a scratch tool cache.
        text = CACHE_PRUNE.read_text(encoding="utf-8")
        i = text.index("- name: Prune buildx chisel local cache older than 30 days")
        step = text[i:text.index("\n      - ", i + 10)]
        body = step[step.index("run: |\n") + len("run: |\n"):]
        script = "\n".join(ln[10:] for ln in body.splitlines())
        tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_chisel_sweep_"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        bc = tmp / "yuzu-docker-buildcache"
        old = time.time() - 40 * DAY
        for name in ("server-chisel", "agent-chisel", "gateway-chisel", "server"):
            (bc / name / "blobs").mkdir(parents=True)
            os.utime(bc / name, (old, old))
        os.utime(bc / "gateway-chisel", None)  # used recently: not stale
        fd = os.open(str(bc / "agent-chisel") + ".lock", os.O_RDWR | os.O_CREAT, 0o644)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_SH)  # a publish job is using agent-chisel
        r = subprocess.run(["bash", "-c", script], env=dict(os.environ, RUNNER_TOOL_CACHE=str(tmp)),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse((bc / "server-chisel").exists(), r.stdout)
        self.assertTrue((bc / "agent-chisel" / "blobs").is_dir(), "a locked directory was removed")
        self.assertIn("agent-chisel skipped: in use", r.stdout)
        self.assertTrue((bc / "gateway-chisel").is_dir())
        self.assertTrue((bc / "server").is_dir())


if __name__ == "__main__":
    unittest.main()
