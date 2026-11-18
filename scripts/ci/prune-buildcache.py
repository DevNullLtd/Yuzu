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
can fail the next build that imports it. So this script removes only what no
index can name, and never leaves a partial tree:

  - A directory with any file modified in the last --quiet-hours (default 3,
    above the publish jobs' 90-minute timeout) is skipped: an export or import
    may be in progress.
  - The referenced set is every sha256 digest found anywhere in index.json and,
    recursively, in every referenced blob that parses as JSON (OCI indexes and
    manifests, image configs, the BuildKit cache config, which names layers
    under "blob"). Over-marking only keeps more.
  - A directory whose index.json is missing or unparseable, or that references
    a JSON-looking blob it does not have, is skipped and reported: it is not
    coherent enough to reason about.
  - Only unreferenced blobs last modified more than --min-age-hours ago
    (default 24) are removed.
  - After the sweep the index is read again. If it changed and now names a
    blob that was just removed (an export started in the window), the whole
    directory is removed: the next build runs cold instead of importing a
    broken cache.

Usage: prune-buildcache.py [--dry-run] [--min-age-hours N] [--quiet-hours N] DIR [DIR...]
Exit status: 0 done (skipped directories included); 2 usage error.
"""

import argparse
import json
import os
import re
import shutil
import sys
import time

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_JSON_BLOB = 64 * 1024 * 1024


class Incoherent(Exception):
    pass


def digests_in(doc, out, required):
    """Collect every sha256 digest string in a JSON document into `out` (the
    keep set; over-marking only keeps more). Digests that must exist as blobs
    for the cache to be usable go into `required` too: an OCI descriptor's
    (an object with mediaType and digest: the index's manifests, a manifest's
    config and layers) and a BuildKit cache config's layer `blob`. The other
    digests (cache-key record digests, uncompressed diff IDs in annotations)
    name no blob, so their absence is normal."""
    if isinstance(doc, dict):
        d = doc.get("digest")
        if isinstance(d, str) and DIGEST.match(d) and isinstance(doc.get("mediaType"), str):
            required.add(d[len("sha256:"):])
        b = doc.get("blob")
        if isinstance(b, str) and DIGEST.match(b):
            required.add(b[len("sha256:"):])
        for v in doc.values():
            digests_in(v, out, required)
    elif isinstance(doc, list):
        for v in doc:
            digests_in(v, out, required)
    elif isinstance(doc, str) and DIGEST.match(doc):
        out.add(doc[len("sha256:"):])


def blob_path(cache, hexd):
    return os.path.join(cache, "blobs", "sha256", hexd)


def load_json_blob(path):
    """The blob as JSON, or None when it is not JSON (a layer tarball)."""
    try:
        if os.path.getsize(path) > MAX_JSON_BLOB:
            return None
        with open(path, "rb") as f:
            head = f.read(1)
            if head not in (b"{", b"["):
                return None
            return json.loads(head + f.read())
    except (ValueError, UnicodeDecodeError):
        return None


def referenced(cache):
    """The set of blob hex digests the cache's index.json can reach. Raises
    Incoherent when a blob the cache needs (a manifest, config or layer) is
    missing: such a tree is not touched."""
    try:
        with open(os.path.join(cache, "index.json"), "rb") as f:
            index = json.load(f)
    except (OSError, ValueError) as e:
        raise Incoherent(f"index.json missing or unreadable ({e})")
    keep, required, parsed = set(), set(), set()
    todo = set()
    digests_in(index, todo, required)
    while todo:
        h = todo.pop()
        if h in keep:
            continue
        keep.add(h)
        p = blob_path(cache, h)
        if not os.path.exists(p):
            if h in required:
                raise Incoherent(f"a manifest, config or layer blob is missing (sha256:{h[:12]})")
            continue
        doc = load_json_blob(p)
        if doc is not None and h not in parsed:
            parsed.add(h)
            more = set()
            digests_in(doc, more, required)
            todo |= more - keep
    for h in required:
        if not os.path.exists(blob_path(cache, h)):
            raise Incoherent(f"a manifest, config or layer blob is missing (sha256:{h[:12]})")
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


def prune(cache, min_age_h=24.0, quiet_h=3.0, dry_run=False, now=None, after_sweep=None):
    """Prune one cache directory. Returns a one-line summary."""
    now = time.time() if now is None else now
    if not os.path.isfile(os.path.join(cache, "index.json")):
        return f"{cache}: skipped (no index.json, not a type=local cache)"
    if now - newest_mtime(cache) < quiet_h * 3600:
        return f"{cache}: skipped (written in the last {quiet_h:g} h; a build may be using it)"
    with open(os.path.join(cache, "index.json"), "rb") as f:
        index_before = f.read()
    try:
        keep = referenced(cache)
    except Incoherent as e:
        return f"{cache}: skipped ({e})"
    blobs_dir = os.path.join(cache, "blobs", "sha256")
    removed, freed, kept_young = [], 0, 0
    for name in sorted(os.listdir(blobs_dir)) if os.path.isdir(blobs_dir) else []:
        if name in keep:
            continue
        p = os.path.join(blobs_dir, name)
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if now - st.st_mtime < min_age_h * 3600:
            kept_young += 1
            continue
        removed.append(name)
        freed += st.st_size
        if not dry_run:
            os.remove(p)
    if after_sweep:
        after_sweep()
    if removed and not dry_run:
        try:
            with open(os.path.join(cache, "index.json"), "rb") as f:
                index_after = f.read()
        except OSError:
            index_after = b""
        if index_after != index_before:
            try:
                now_keep = referenced(cache)
                broken = bool(now_keep & set(removed))
            except Incoherent:
                broken = True
            if broken:
                shutil.rmtree(cache, ignore_errors=True)
                return (f"{cache}: REMOVED WHOLE DIRECTORY: its index changed during the prune and "
                        f"named a removed blob; the next build runs without this cache")
    verb = "would remove" if dry_run else "removed"
    return (f"{cache}: {verb} {len(removed)} unreferenced blob(s), {freed / 2**30:.2f} GiB; "
            f"kept {len(keep)} referenced, {kept_young} unreferenced younger than {min_age_h:g} h")


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--min-age-hours", type=float, default=24.0)
    ap.add_argument("--quiet-hours", type=float, default=3.0)
    ap.add_argument("dirs", nargs="+")
    a = ap.parse_args(argv)
    if a.min_age_hours < 1 or a.quiet_hours < 2:
        ap.error("--min-age-hours must be >= 1 and --quiet-hours >= 2 (a publish job runs up to 90 min)")
    for d in a.dirs:
        if os.path.isdir(d):
            print(prune(d.rstrip("/"), a.min_age_hours, a.quiet_hours, a.dry_run))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
