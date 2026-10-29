#!/usr/bin/env python3
"""Fail when the gateway builder index's supported platforms disagree on Alpine (#6711).

deploy/docker/Dockerfile.gateway pins `erlang:28-alpine@sha256:<index>`, a multi-arch
index whose per-platform entries are built independently upstream, so they can sit on
different Alpine releases (amd64 on 3.23 and arm64 on 3.24 when #6711 was filed). The
runtime stage is `alpine:<X.Y>` and the #2150 abi-guard needs builder and runtime on the
same release, but it only fires after a full build and only for the platform being built.

This check reads the pinned index and, for every platform named on the Dockerfile's
`# yuzu:gateway-platforms` marker line, requires every manifest entry for that platform
to carry `org.opencontainers.image.base.name` = `alpine:<X.Y>` equal to the runtime
stage's tag. It reads the publisher's ANNOTATION; it does not inspect the image, so the
abi-guard (which reads the real /etc/alpine-release and musl) stays the build-time
enforcement. Platforms the Dockerfile does not list are unsupported by design (the first
RUN of the deps stage refuses them) and are reported, never failed. Fails closed: a
supported platform with no entry, or an entry with no readable annotation, is a failure.

The fetched index body is hashed against the pinned digest before it is trusted.

Exit codes: 0 consistent; 1 a supported platform disagrees (or has no usable entry);
2 the registry could not be read (outage, rate limit, digest mismatch); 3 the Dockerfile
or the index has a shape this script does not understand (a lint defect, not a verdict).

Usage:
    check-gateway-base-index.py [--dockerfile PATH] [--index-file PATH]

`--index-file` reads the index JSON from disk instead of the registry (offline runs; the
digest check is skipped because a file has no registry digest to compare against).
The pure `check()` is what tests/test_gateway_base_index.py exercises.

To disable this check if it proves unusable: delete the `gateway-base-index` job in
.github/workflows/docker-healthcheck-invariants.yml and the "Gateway base index lint"
step in docs-lint.yml. Nothing else depends on it; the abi-guard remains.
"""

import argparse
import hashlib
import json
import re
import sys
import time
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
BUILDER_RE = re.compile(
    r"^FROM\s+(?P<repo>[\w./-]+):(?P<tag>[\w.-]+)@(?P<digest>sha256:[0-9a-f]{64})\s+AS\s+deps\s*$",
    re.M | re.I,
)
RUNTIME_RE = re.compile(r"^FROM\s+alpine:(?P<tag>[0-9]+\.[0-9]+)(?:@sha256:[0-9a-f]{64})?\s*$", re.M | re.I)

RETRY_DELAYS = (2, 5, 15)  # seconds before attempts 2, 3 and 4


class InputDefect(Exception):
    """The Dockerfile or the index has a shape this script does not understand (exit 3)."""


class RegistryError(Exception):
    """The registry could not be read, or served a body that is not the pinned one (exit 2)."""


def platform_key(entry):
    p = entry.get("platform") or {}
    return f"{p.get('os', '')}/{p.get('architecture', '')}"


def alpine_release(entry):
    """`3.23` from the entry's base.name annotation, or None when absent/unreadable."""
    name = (entry.get("annotations") or {}).get(BASE_NAME_KEY, "")
    m = ALPINE_RE.fullmatch(name) if isinstance(name, str) else None
    return m.group(1) if m else None


def check(index, supported, runtime_alpine):
    """Return (failures, notes). `failures` empty means the pin is consistent.

    Raises InputDefect when `index` is not an image index or its entries are mis-shaped.
    """
    if not isinstance(index, dict) or not isinstance(index.get("manifests"), list):
        raise InputDefect("the pinned digest did not resolve to an image index (no `manifests` list); "
                          "pin the index digest, not a per-platform manifest")
    for e in index["manifests"]:
        if not isinstance(e, dict) or not isinstance(e.get("platform", {}), dict) \
                or not isinstance(e.get("annotations", {}), dict):
            raise InputDefect("an index entry is not an object with object `platform` and `annotations`")
    failures, notes = [], []
    if not supported:
        return ["no supported platforms listed"], notes
    entries = {}
    for e in index["manifests"]:
        key = platform_key(e)
        # Attestation manifests report unknown/unknown; they are not images.
        if key.startswith("linux/"):
            entries.setdefault(key, []).append(e)
    for plat in supported:
        found = entries.get(plat)
        if not found:
            failures.append(f"{plat}: no entry in the pinned index")
            continue
        for e in found:
            rel = alpine_release(e)
            if rel is None:
                failures.append(f"{plat}: no readable {BASE_NAME_KEY} annotation "
                                "(cannot tell which Alpine release it was built on)")
            elif rel != runtime_alpine:
                failures.append(f"{plat}: builder entry is annotated as Alpine {rel}, "
                                f"the runtime stage is alpine:{runtime_alpine}")
    for plat in sorted(set(entries) - set(supported)):
        rels = sorted({alpine_release(e) or "?" for e in entries[plat]})
        notes.append(f"{plat}: annotated as Alpine {'/'.join(rels)} (unsupported platform, not checked)")
    return failures, notes


def parse_dockerfile(text):
    marker = MARKER_RE.findall(text)
    builder = list(BUILDER_RE.finditer(text))
    runtimes = RUNTIME_RE.findall(text)
    if len(marker) != 1:
        raise InputDefect(f"expected exactly one `# yuzu:gateway-platforms` marker line, found {len(marker)}")
    if len(builder) != 1:
        raise InputDefect(f"expected exactly one digest-pinned `FROM <repo>:<tag>@sha256:... AS deps` line, "
                          f"found {len(builder)}")
    if len(runtimes) != 1:
        raise InputDefect(f"expected exactly one `FROM alpine:X.Y` runtime stage, found {len(runtimes)}")
    return marker[0].split(), builder[0].groupdict(), runtimes[0]


def _get(url, headers, attempts=len(RETRY_DELAYS) + 1):
    """GET with bounded retries on 429/5xx/network faults; returns the raw body."""
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "yuzu-ci-gateway-base-index", **headers})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read()
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code != 429 and exc.code < 500:
                break
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            delay = min(int(retry_after), 30) if retry_after and retry_after.isdigit() else None
        except (urllib.error.URLError, OSError) as exc:
            last, delay = exc, None
        if i < attempts - 1:
            time.sleep(delay if delay is not None else RETRY_DELAYS[i])
    raise RegistryError(f"{url}: {last}")


def fetch_index(repo, digest):
    """Fetch an index by digest from Docker Hub (anonymous token) and verify the body hash."""
    if "/" not in repo:
        repo = f"library/{repo}"
    tok_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
    try:
        token = json.loads(_get(tok_url, {}))["token"]
    except (ValueError, KeyError) as exc:
        raise RegistryError(f"token response not understood: {exc!r}")
    body = _get(f"https://registry-1.docker.io/v2/{repo}/manifests/{digest}",
                {"Authorization": f"Bearer {token}", "Accept": ", ".join(INDEX_TYPES)})
    got = "sha256:" + hashlib.sha256(body).hexdigest()
    if got != digest:
        raise RegistryError(f"the registry served a body hashing to {got}, not the pinned {digest}")
    try:
        return json.loads(body)
    except ValueError as exc:
        raise RegistryError(f"the pinned index is not JSON: {exc}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dockerfile", type=Path, default=DEFAULT_DOCKERFILE)
    ap.add_argument("--index-file", type=Path, help="read the index JSON from this file instead of the registry")
    args = ap.parse_args(argv)

    try:
        supported, builder, runtime_alpine = parse_dockerfile(args.dockerfile.read_text(encoding="utf-8"))
        if args.index_file:
            try:
                index = json.loads(args.index_file.read_text(encoding="utf-8"))
            except ValueError as exc:
                raise InputDefect(f"{args.index_file} is not JSON: {exc}")
        else:
            index = fetch_index(builder["repo"], builder["digest"])
        failures, notes = check(index, supported, runtime_alpine)
    except InputDefect as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 3
    except RegistryError as exc:
        print(f"FATAL: could not read the pinned index (registry unavailable, or the body is not the "
              f"pinned one): {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"FATAL: could not read an input file: {exc}", file=sys.stderr)
        return 3

    print(f"gateway-base-index: {builder['repo']}:{builder['tag']}@{builder['digest'][:19]} "
          f"supported={','.join(supported)} runtime=alpine:{runtime_alpine}")
    for n in notes:
        print(f"  note: {n}")
    for f in failures:
        print(f"  FAIL: {f}", file=sys.stderr)
    if failures:
        print("FATAL: the pinned builder index and the runtime stage disagree on Alpine for a supported "
              "platform, per the index's annotations (the build's abi-guard is the build-time check). "
              "See #6711 and the Dockerfile.gateway header.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
