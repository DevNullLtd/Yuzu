#!/usr/bin/env python3
"""Fail when the gateway builder index's supported platforms disagree on Alpine (#6711).

deploy/docker/Dockerfile.gateway pins `erlang:28-alpine@sha256:<index>`, a multi-arch
index whose per-platform entries are built independently upstream, so they can sit on
different Alpine releases (amd64 on 3.23 and arm64 on 3.24 when #6711 was filed). The
runtime stage is `alpine:<X.Y>` and the #2150 abi-guard needs builder and runtime on the
same release, but only fires after a full build and only for the platform being built.

This check reads the pinned index and, for every platform named on the Dockerfile's
`# yuzu:gateway-platforms` marker line, requires its manifest to carry
`org.opencontainers.image.base.name` = `alpine:<X.Y>` equal to the runtime stage's tag.
Platforms the Dockerfile does not list are unsupported by design (the first RUN of the
deps stage refuses them) and are reported, never failed. Fails closed: a supported
platform with no entry, or an entry with no readable annotation, is a failure.

Usage:
    check-gateway-base-index.py [--dockerfile PATH] [--index-file PATH]

`--index-file` reads the index JSON from disk instead of the registry (offline runs).
The pure `check()` is what tests/test_gateway_base_index.py exercises.
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_DOCKERFILE = ROOT / "deploy" / "docker" / "Dockerfile.gateway"

BASE_NAME_KEY = "org.opencontainers.image.base.name"
INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
ALPINE_RE = re.compile(r"alpine:([0-9]+\.[0-9]+)(?:\.[0-9]+)?$")

MARKER_RE = re.compile(r"^#\s*yuzu:gateway-platforms\s+(.+?)\s*$", re.M)
BUILDER_RE = re.compile(r"^FROM\s+(?P<repo>[\w./-]+):(?P<tag>[\w.-]+)@(?P<digest>sha256:[0-9a-f]{64})\s+AS\s+deps\s*$", re.M)
RUNTIME_RE = re.compile(r"^FROM\s+alpine:(?P<tag>[0-9]+\.[0-9]+)(?:@sha256:[0-9a-f]{64})?\s*$", re.M)


def platform_key(entry):
    p = entry.get("platform") or {}
    return f"{p.get('os', '')}/{p.get('architecture', '')}"


def alpine_release(entry):
    """`3.23` from the entry's base.name annotation, or None when absent/unreadable."""
    name = (entry.get("annotations") or {}).get(BASE_NAME_KEY, "")
    m = ALPINE_RE.fullmatch(name)
    return m.group(1) if m else None


def check(index, supported, runtime_alpine):
    """Return (failures, notes). `failures` empty means the pin is consistent."""
    failures, notes = [], []
    if not supported:
        return ["no supported platforms listed"], notes
    entries = {}
    for e in index.get("manifests", []):
        key = platform_key(e)
        # Attestation manifests report unknown/unknown; they are not images.
        if key.startswith("linux/"):
            entries.setdefault(key, e)
    for plat in supported:
        e = entries.get(plat)
        if e is None:
            failures.append(f"{plat}: no entry in the pinned index")
            continue
        rel = alpine_release(e)
        if rel is None:
            failures.append(f"{plat}: no readable {BASE_NAME_KEY} annotation (cannot prove its Alpine release)")
        elif rel != runtime_alpine:
            failures.append(f"{plat}: builder entry is on Alpine {rel}, the runtime stage is alpine:{runtime_alpine}")
    for plat in sorted(set(entries) - set(supported)):
        notes.append(f"{plat}: Alpine {alpine_release(entries[plat]) or '?'} (unsupported platform, not checked)")
    return failures, notes


def parse_dockerfile(text):
    marker = MARKER_RE.search(text)
    builder = BUILDER_RE.search(text)
    runtimes = RUNTIME_RE.findall(text)
    if not marker:
        raise SystemExit("FATAL: no `# yuzu:gateway-platforms` marker line in the Dockerfile")
    if not builder:
        raise SystemExit("FATAL: no digest-pinned `FROM <repo>:<tag>@sha256:… AS deps` line in the Dockerfile")
    if len(runtimes) != 1:
        raise SystemExit(f"FATAL: expected exactly one `FROM alpine:X.Y` runtime stage, found {len(runtimes)}")
    return marker.group(1).split(), builder.groupdict(), runtimes[0]


def fetch_index(repo, digest):
    """Fetch an index by digest from Docker Hub with an anonymous pull token."""
    if "/" not in repo:
        repo = f"library/{repo}"
    tok_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
    with urllib.request.urlopen(tok_url, timeout=30) as r:
        token = json.load(r)["token"]
    req = urllib.request.Request(
        f"https://registry-1.docker.io/v2/{repo}/manifests/{digest}",
        headers={"Authorization": f"Bearer {token}", "Accept": ", ".join(INDEX_TYPES)},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dockerfile", type=Path, default=DEFAULT_DOCKERFILE)
    ap.add_argument("--index-file", type=Path, help="read the index JSON from this file instead of the registry")
    args = ap.parse_args(argv)

    supported, builder, runtime_alpine = parse_dockerfile(args.dockerfile.read_text())
    try:
        if args.index_file:
            index = json.loads(args.index_file.read_text())
        else:
            index = fetch_index(builder["repo"], builder["digest"])
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        print(f"FATAL: could not read the pinned index {builder['repo']}:{builder['tag']}@{builder['digest']}: {exc}",
              file=sys.stderr)
        return 2

    failures, notes = check(index, supported, runtime_alpine)
    print(f"gateway-base-index: {builder['repo']}:{builder['tag']}@{builder['digest'][:19]} "
          f"supported={','.join(supported)} runtime=alpine:{runtime_alpine}")
    for n in notes:
        print(f"  note: {n}")
    for f in failures:
        print(f"  FAIL: {f}", file=sys.stderr)
    if failures:
        print("FATAL: the pinned builder index and the runtime stage disagree on Alpine for a supported platform. "
              "See #6711 and the Dockerfile.gateway header.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
