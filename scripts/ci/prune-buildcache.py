#!/usr/bin/env python3
"""Prune unreferenced blobs from buildx `type=local` cache directories.

release.yml's publish jobs export their build cache with
`cache-to: type=local,dest=$RUNNER_TOOL_CACHE/yuzu-docker-buildcache/<image>,mode=max`.
Each export writes the new blobs and replaces `index.json`, but never deletes
the blobs the previous index referenced and the new one does not. Since
YUZU_PACKAGE_REFRESH (WP15/S9) changes the package layer on every run
attempt, every release adds a fresh set of runtime-stage blobs that nothing
ever removes (measured on Big Tam: one server cache directory at 20 GB, of
which 6.3 GB was referenced).

A cache directory is a coherent artifact: an index that names a missing blob
fails the next build that imports it ("NotFound content"). So:

  - IN USE is decided by a LOCK, not by the clock. Every publish job holds a
    shared flock on DIR.lock from before its first build until the job ends
    (scripts/ci/buildcache-lock.sh). This script takes an exclusive,
    NON-blocking flock on the same file and holds it for the whole pass over
    that directory; when it cannot, the directory is skipped as in use. So a
    prune never overlaps an import or an export by a job that holds the lock.
  - As defence in depth against a writer that does not take the lock (a tag
    cut before the lock existed, a hand-run build), a directory with any file
    modified in the last --quiet-hours (default 3, above the longest publish
    job's 120-minute timeout) is skipped too. A file dated more than
    FUTURE_SLACK_S ahead of the clock (a clock that stepped back, or a forward-
    dated file) would make that window never end, so it is an ERROR (exit 1,
    reported), not a silent skip every week.
  - The referenced set is every sha256 digest found anywhere in index.json and,
    recursively, in every referenced blob that parses as JSON (OCI indexes and
    manifests, image configs, the BuildKit cache config, which names layers
    under "blob"). Over-marking only keeps more.
  - Only unreferenced regular files last modified more than --min-age-hours ago
    (default 24) are removed.
  - A directory that is BROKEN (index.json unparseable, or the index names a
    manifest, config or layer blob that is missing) fails its next import
    whatever this script does, so, under the lock and outside the quiet window,
    it is removed whole: the next build runs cold instead of failing.
  - A directory this script cannot reason about (an entry it cannot read, a
    JSON blob nested too deeply to parse, a blob that starts like JSON but is
    larger than MAX_JSON_BLOB, a non-regular entry under blobs/) is skipped and
    reported as an ERROR; nothing in it is removed. (Treating an oversize JSON
    blob as a layer would lose the references it holds, and remove blobs a
    manifest still needs.)
  - A symlinked cache directory or lock file is refused (skipped as an error).

Clock-guard disposition (docs/clock-guarded-retention.md register,
"prune-buildcache.py"): the wall clock only ages blobs that no index can name
and gates the quiet window; liveness is proven by the lock, and what is kept
is decided by content (the references), so a wrong clock cannot make it remove
a referenced blob. The content is a regenerable build cache.

Every directory is processed even when an earlier one fails.

Usage: prune-buildcache.py [--dry-run] [--min-age-hours N] [--quiet-hours N] DIR [DIR...]
Exit status: 0 every directory was pruned or deliberately skipped; 1 at least
one directory hit an error (reported, others still processed); 2 usage error.
"""

import argparse
import errno
import fcntl
import json
import os
import re
import shutil
import stat
import sys
import time

DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
HEXNAME = re.compile(r"\A[0-9a-f]{64}\Z")
MAX_JSON_BLOB = 64 * 1024 * 1024
# How far ahead of the clock a file's mtime may be before the clock or the file
# is treated as wrong (an ERROR) rather than as a write in progress.
FUTURE_SLACK_S = 3600


class Broken(Exception):
    """The cache cannot be imported as it stands (it fails the next build)."""


class Unknown(Exception):
    """This script cannot tell what the cache needs; touch nothing."""


def digests_in(doc, out, required):
    """Collect every sha256 digest string in a JSON document into `out` (the
    keep set; over-marking only keeps more). Digests that must exist as blobs
    for the cache to be usable go into `required` too: an OCI descriptor's
    (an object with mediaType and digest: the index's manifests, a manifest's
    config and layers) and a BuildKit cache config's layer `blob`. The other
    digests (cache-key record digests, uncompressed diff IDs in annotations)
    name no blob, so their absence is normal. Iterative, so a deeply nested
    document cannot exhaust the stack."""
    stack = [doc]
    while stack:
        d = stack.pop()
        if isinstance(d, dict):
            v = d.get("digest")
            if isinstance(v, str) and DIGEST.match(v) and isinstance(d.get("mediaType"), str):
                required.add(v[len("sha256:"):])
            b = d.get("blob")
            if isinstance(b, str) and DIGEST.match(b):
                required.add(b[len("sha256:"):])
            stack.extend(d.values())
        elif isinstance(d, list):
            stack.extend(d)
        elif isinstance(d, str) and DIGEST.match(d):
            out.add(d[len("sha256:"):])


def blob_path(cache, hexd):
    return os.path.join(cache, "blobs", "sha256", hexd)


def load_json_blob(path):
    """The blob as JSON, or None when it is not JSON (a layer tarball). Raises
    Unknown when it cannot be read or is JSON this script cannot parse."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            raise Unknown(f"blob {os.path.basename(path)[:12]} is not a regular file")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as f:
            head = f.read(1)
            if head not in (b"{", b"["):
                return None
            if st.st_size > MAX_JSON_BLOB:
                raise Unknown(f"blob {os.path.basename(path)[:12]} starts like JSON but is larger than "
                              f"{MAX_JSON_BLOB // 2**20} MiB; its references cannot be read")
            data = head + f.read()
    except OSError as e:
        raise Unknown(f"cannot read blob {os.path.basename(path)[:12]} ({e})")
    try:
        return json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return None
    except RecursionError:
        raise Unknown(f"blob {os.path.basename(path)[:12]} is JSON nested too deeply to read")


def referenced(cache):
    """The set of blob hex digests the cache's index.json can reach. Raises
    Broken when the index is unreadable or a blob it needs is missing, and
    Unknown when a blob cannot be read."""
    try:
        with open(os.path.join(cache, "index.json"), "rb") as f:
            index = json.load(f)
    except RecursionError:
        raise Unknown("index.json is nested too deeply to read")
    except ValueError as e:
        raise Broken(f"index.json unparseable ({e})")
    except OSError as e:
        raise Unknown(f"cannot read index.json ({e})")
    keep, required, parsed = set(), set(), set()
    todo = set()
    digests_in(index, todo, required)
    while todo:
        h = todo.pop()
        if h in keep:
            continue
        keep.add(h)
        p = blob_path(cache, h)
        if not os.path.lexists(p):
            if h in required:
                raise Broken(f"a manifest, config or layer blob is missing (sha256:{h[:12]})")
            continue
        doc = load_json_blob(p)
        if doc is not None and h not in parsed:
            parsed.add(h)
            more = set()
            digests_in(doc, more, required)
            todo |= more - keep
    for h in required:
        if not os.path.lexists(blob_path(cache, h)):
            raise Broken(f"a manifest, config or layer blob is missing (sha256:{h[:12]})")
    return keep


def newest_mtime(cache):
    newest = 0.0
    for root, _dirs, files in os.walk(cache):
        for name in files:
            try:
                newest = max(newest, os.lstat(os.path.join(root, name)).st_mtime)
            except OSError:
                pass
    return newest


def lock_exclusive(cache):
    """An exclusive non-blocking flock on CACHE.lock, or None when a publish job
    (or another prune) holds it. Raises OSError on anything else."""
    path = cache.rstrip("/") + ".lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        os.close(fd)
        if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            return None
        raise
    return fd


def prune(cache, min_age_h=24.0, quiet_h=3.0, dry_run=False, now=None, after_sweep=None):
    """Prune one cache directory. Returns (ok, one-line summary); ok is False
    when an error made it skip work it should have done."""
    cache = cache.rstrip("/")
    if os.path.islink(cache):
        return False, f"{cache}: ERROR: skipped (a symlink; refusing to prune through it)"
    if not os.path.isfile(os.path.join(cache, "index.json")):
        return True, f"{cache}: skipped (no index.json, not a type=local cache)"
    try:
        fd = lock_exclusive(cache)
    except OSError as e:
        return False, f"{cache}: ERROR: skipped (cannot open its lock file: {e})"
    if fd is None:
        return True, f"{cache}: skipped (in use: a publish job holds {cache}.lock)"
    try:
        return _prune_locked(cache, min_age_h, quiet_h, dry_run, now, after_sweep)
    finally:
        os.close(fd)


def _prune_locked(cache, min_age_h, quiet_h, dry_run, now, after_sweep):
    now = time.time() if now is None else now
    newest = newest_mtime(cache)
    if newest - now > FUTURE_SLACK_S:
        return False, (f"{cache}: ERROR: skipped, nothing removed (a file is dated "
                       f"{(newest - now) / 3600:.1f} h in the future: the clock or that file's time is wrong, "
                       f"and the quiet window would never end)")
    if now - newest < quiet_h * 3600:
        return True, f"{cache}: skipped (written in the last {quiet_h:g} h; a build may be using it)"
    try:
        with open(os.path.join(cache, "index.json"), "rb") as f:
            index_before = f.read()
        keep = referenced(cache)
    except Broken as e:
        if dry_run:
            return True, f"{cache}: would remove whole directory (broken: {e})"
        shutil.rmtree(cache, ignore_errors=True)
        if os.path.lexists(cache):
            return False, f"{cache}: ERROR: broken ({e}) and could not be removed whole"
        return True, (f"{cache}: REMOVED WHOLE DIRECTORY: broken ({e}); its next import would fail, "
                      f"the next build runs without this cache")
    except (Unknown, OSError) as e:
        return False, f"{cache}: ERROR: skipped, nothing removed ({e})"
    blobs_dir = os.path.join(cache, "blobs", "sha256")
    removed, freed, kept_young, errors = [], 0, 0, []
    try:
        names = sorted(os.listdir(blobs_dir)) if os.path.isdir(blobs_dir) else []
    except OSError as e:
        return False, f"{cache}: ERROR: cannot list blobs ({e})"
    for name in names:
        if name in keep:
            continue
        p = os.path.join(blobs_dir, name)
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            continue
        except OSError as e:
            errors.append(f"{name[:12]}: {e}")
            continue
        if not stat.S_ISREG(st.st_mode) or not HEXNAME.match(name):
            errors.append(f"{name[:24]!r}: not a blob (non-regular file or not a sha256 name); left alone")
            continue
        if now - st.st_mtime < min_age_h * 3600:
            kept_young += 1
            continue
        if not dry_run:
            try:
                os.remove(p)
            except FileNotFoundError:
                continue
            except OSError as e:
                errors.append(f"{name[:12]}: {e}")
                continue
        removed.append(name)
        freed += st.st_size
    if after_sweep:
        after_sweep()
    if removed and not dry_run:
        # Under the lock nothing should have rewritten the index; if something
        # that does not take the lock did, and it now names a removed blob, the
        # cache is broken: remove it whole rather than leave it to fail a build.
        try:
            with open(os.path.join(cache, "index.json"), "rb") as f:
                index_after = f.read()
        except OSError:
            index_after = b""
        if index_after != index_before:
            try:
                broken = bool(referenced(cache) & set(removed))
            except (Broken, Unknown):
                broken = True
            if broken:
                shutil.rmtree(cache, ignore_errors=True)
                return True, (f"{cache}: REMOVED WHOLE DIRECTORY: its index changed during the prune and "
                              f"named a removed blob; the next build runs without this cache")
    verb = "would remove" if dry_run else "removed"
    line = (f"{cache}: {verb} {len(removed)} unreferenced blob(s), {freed / 2**30:.2f} GiB; "
            f"kept {len(keep)} referenced, {kept_young} unreferenced younger than {min_age_h:g} h")
    if errors:
        return False, line + f"; ERROR on {len(errors)} entr(ies): " + "; ".join(errors[:5])
    return True, line


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--min-age-hours", type=float, default=24.0)
    ap.add_argument("--quiet-hours", type=float, default=3.0)
    ap.add_argument("dirs", nargs="+")
    a = ap.parse_args(argv)
    if a.min_age_hours < 1 or a.quiet_hours < 2.5:
        ap.error("--min-age-hours must be >= 1 and --quiet-hours >= 2.5 (a publish job runs up to 120 min)")
    ok = True
    for d in a.dirs:
        try:
            if not os.path.isdir(d):
                continue
            good, line = prune(d, a.min_age_hours, a.quiet_hours, a.dry_run)
        except Exception as e:  # noqa: BLE001 - one directory must not stop the rest
            good, line = False, f"{d}: ERROR: {type(e).__name__}: {e}"
        print(line, flush=True)
        if not good:
            ok = False
            if os.environ.get("GITHUB_ACTIONS"):
                print(f"::warning::buildx cache prune: {line}", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
