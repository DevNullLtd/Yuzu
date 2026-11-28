#!/usr/bin/env python3
"""Fail when the gateway builder index's supported platforms disagree on Alpine (#6711).

deploy/docker/Dockerfile.gateway pins a multi-arch builder index
(`hexpm/erlang:<otp>-alpine-<X.Y.Z>@sha256:<index>` since WP15), whose per-platform
entries are built independently upstream, so they can sit on different Alpine releases
(the upstream erlang:28-alpine index had amd64 on 3.23 and arm64 on 3.24 when #6711 was
filed). The runtime stage is `alpine:<X.Y>` and the #2150 abi-guard needs builder and
runtime on the same release, but it only fires after a full build and only for the
platform being built.

This check reads the pinned index and, for every platform named on the Dockerfile's
`# yuzu:gateway-platforms` marker line, requires every manifest entry for that platform
to be shown as built on the runtime stage's Alpine release. The evidence, per entry:
the `org.opencontainers.image.base.name` = `alpine:<X.Y>` annotation when the publisher
set one (Docker's official images do); otherwise the FIRST history entry of the entry's
image config, which for an image built on Alpine's minirootfs reads
`ADD alpine-minirootfs-<X.Y.Z>-<arch>.tar.gz /` (the hexpm images record this and no
annotation); its <arch> must be the platform's. When the builder tag itself names an
Alpine release (`...-alpine-<X.Y.Z>`), that release must be the runtime stage's too.
It reads what the publisher RECORDED; it does not run the image, so the abi-guard
(which reads the real /etc/alpine-release and musl) stays the build-time enforcement.
Platforms the Dockerfile does not list are unsupported by design (the first RUN of the
deps stage refuses them) and are reported, never failed. Fails closed: a supported
platform with no entry, or an entry with neither a readable annotation nor a readable
minirootfs history entry, is a failure.

Every fetched body (the index, a per-platform manifest, an image config) is hashed
against the digest that names it before it is trusted.

Exit codes: 0 consistent; 1 a supported platform disagrees (or has no usable entry);
2 the registry could not be read (outage, rate limit, digest mismatch); 3 the Dockerfile
or the index has a shape this script does not understand, or the command line is wrong
(a lint defect, not a verdict).

Usage:
    check-gateway-base-index.py [--dockerfile PATH] [--index-file PATH [--configs-file PATH]]

`--index-file` reads the index JSON from disk instead of the registry (offline runs; the
digest check is skipped because a file has no registry digest to compare against).
`--configs-file` (with `--index-file` only) is a JSON object mapping a per-platform
manifest digest from that index to its image config, for entries with no annotation.
The pure `check()` is what tests/test_gateway_base_index.py exercises.

To disable the networked check if it proves unusable, put `if: false` on (or delete) the
`gateway-base-index` job in .github/workflows/docker-healthcheck-invariants.yml; if that job
was ever made a required check, take it out of branch protection first. KEEP this script,
tests/test_gateway_base_index.py and the "Gateway base index lint" step in docs-lint.yml:
the test also holds the executed arch-guard contract for Dockerfile.gateway. The build's
abi-guard remains the build-time enforcement either way.
"""

import argparse
import hashlib
import http.client
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
# The base layer of an image built on Alpine's minirootfs, as BuildKit records it in the
# image config's first history entry.
MINIROOTFS_RE = re.compile(r"ADD alpine-minirootfs-([0-9]+\.[0-9]+)\.[0-9]+-([a-z0-9_]+)\.tar\.gz /(?: # buildkit)?")
# OCI platform architecture (and variant) -> the arch Alpine names its minirootfs for.
MINIROOTFS_ARCH = {
    "amd64": "x86_64", "arm64": "aarch64", "arm64/v8": "aarch64", "386": "x86",
    "arm/v6": "armhf", "arm/v7": "armv7", "ppc64le": "ppc64le", "s390x": "s390x",
    "riscv64": "riscv64", "loong64": "loongarch64",
}
# A builder tag that names its Alpine release: `28.5.0.8-alpine-3.23.8`.
TAG_ALPINE_RE = re.compile(r"(?:^|-)alpine-?([0-9]+\.[0-9]+)(?:\.[0-9]+)?$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MANIFEST_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)

MARKER_RE = re.compile(r"^#\s*yuzu:gateway-platforms\s+(.+?)\s*$", re.M)
BUILDER_RE = re.compile(
    r"^FROM\s+(?P<repo>[\w./-]+):(?P<tag>[\w.-]+)@(?P<digest>sha256:[0-9a-f]{64})\s+AS\s+deps\s*$",
    re.M | re.I,
)
RUNTIME_RE = re.compile(r"^FROM\s+alpine:(?P<tag>[0-9]+\.[0-9]+)(?:@sha256:[0-9a-f]{64})?\s*$", re.M | re.I)

RETRY_DELAYS = (2, 5, 15)  # seconds before attempts 2, 3 and 4
MAX_BODY = 8 * 1024 * 1024  # an index is a few KiB; refuse anything absurd


class InputDefect(Exception):
    """The Dockerfile or the index has a shape this script does not understand (exit 3)."""


class RegistryError(Exception):
    """The registry could not be read, or served a body that is not the pinned one (exit 2).

    `transient` is True for faults a re-run may clear (outage, rate limit, network error), False
    for ones it will not (a 4xx for the pinned digest, an oversized response), and None when a
    re-run is worth trying once but a repeat means the pin or the registry content changed (a
    body that is not the pinned one, which a truncated response also produces; a token or
    manifest body that is not what was asked for).
    """

    def __init__(self, message, transient=True):
        super().__init__(message)
        self.transient = transient


def platform_key(entry):
    p = entry.get("platform") or {}
    return f"{p.get('os', '')}/{p.get('architecture', '')}"


def alpine_release(entry):
    """`3.23` from the entry's base.name annotation, or None when absent/unreadable."""
    name = (entry.get("annotations") or {}).get(BASE_NAME_KEY, "")
    m = ALPINE_RE.fullmatch(name) if isinstance(name, str) else None
    return m.group(1) if m else None


def config_alpine_release(config, platform):
    """`3.23` from the image config's FIRST history entry, or None when it is not an Alpine
    minirootfs layer for `platform`'s architecture (or the config is mis-shaped).

    Only the first entry counts: it is the base layer, and a later `ADD` of a file with the
    same name would say nothing about what the image is built on."""
    arch = platform.split("/", 1)[1] if "/" in platform else ""
    want = MINIROOTFS_ARCH.get(arch)
    if not want or not isinstance(config, dict):
        return None
    history = config.get("history")
    if not isinstance(history, list) or not history or not isinstance(history[0], dict):
        return None
    created_by = history[0].get("created_by")
    m = MINIROOTFS_RE.fullmatch(created_by) if isinstance(created_by, str) else None
    if not m or m.group(2) != want:
        return None
    return m.group(1)


def entry_platform(entry):
    """`linux/arm64/v8`-style key used for the minirootfs arch lookup."""
    p = entry.get("platform") or {}
    key = f"{p.get('os', '')}/{p.get('architecture', '')}"
    if p.get("variant") and f"{p.get('architecture', '')}/{p.get('variant')}" in MINIROOTFS_ARCH:
        key += f"/{p.get('variant')}"
    return key


def validate_index(index):
    """Raise InputDefect unless `index` is an image index whose entries are objects."""
    if not isinstance(index, dict) or not isinstance(index.get("manifests"), list):
        raise InputDefect("the pinned digest did not resolve to an image index (no `manifests` list); "
                          "pin the index digest, not a per-platform manifest")
    for e in index["manifests"]:
        if not isinstance(e, dict) or not isinstance(e.get("platform", {}), dict) \
                or not isinstance(e.get("annotations", {}), dict):
            raise InputDefect("an index entry is not an object with object `platform` and `annotations`")


def check(index, supported, runtime_alpine, configs=None):
    """Return (failures, notes). `failures` empty means the pin is consistent.

    `configs` maps a per-platform manifest digest to its image config (parsed JSON); it
    is consulted only for an entry with no readable base.name annotation.

    Raises InputDefect when `index` is not an image index or its entries are mis-shaped.
    """
    configs = configs or {}
    validate_index(index)
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
            rel, how = alpine_release(e), "annotated as"
            if rel is None:
                cfg = configs.get(e.get("digest"))
                rel, how = config_alpine_release(cfg, entry_platform(e)), "built (per its image config) on"
            if rel is None:
                failures.append(f"{plat}: no readable {BASE_NAME_KEY} annotation and no Alpine minirootfs "
                                "base layer for this architecture in its image config's first history entry "
                                "(cannot tell which Alpine release it was built on)")
            elif rel != runtime_alpine:
                failures.append(f"{plat}: builder entry is {how} Alpine {rel}, "
                                f"the runtime stage is alpine:{runtime_alpine}")
    for plat in sorted(set(entries) - set(supported)):
        rels = sorted({alpine_release(e) or "?" for e in entries[plat]})
        if rels == ["?"]:
            notes.append(f"{plat}: no {BASE_NAME_KEY} annotation (unsupported platform, not checked)")
        else:
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
    b = builder[0].groupdict()
    if b["digest"] != b["digest"].lower():
        raise InputDefect(f"the pinned digest {b['digest']} is not lower-case hex (Docker rejects it too)")
    return marker[0].split(), b, runtimes[0]


def tag_failures(builder, runtime_alpine):
    """A builder tag that names an Alpine release must name the runtime stage's."""
    m = TAG_ALPINE_RE.search(builder["tag"])
    if m and m.group(1) != runtime_alpine:
        return [f"the builder tag {builder['repo']}:{builder['tag']} names Alpine {m.group(1)}, "
                f"the runtime stage is alpine:{runtime_alpine}"]
    return []


def _retry_after(headers):
    """Seconds to wait per a Retry-After header: 1..30, or None when absent/unusable."""
    value = headers.get("Retry-After") if headers else None
    # Bounded length: int() of a very long digit string raises on Python 3.11+.
    if value and len(value) <= 9 and value.isascii() and value.isdigit():
        return max(1, min(int(value), 30))
    return None


def _get(url, headers, attempts=len(RETRY_DELAYS) + 1):
    """GET with bounded retries on 429/5xx/network faults; returns the raw body (at most MAX_BODY)."""
    last, transient = None, True
    for i in range(attempts):
        delay = None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "yuzu-ci-gateway-base-index", **headers})
            with urllib.request.urlopen(req, timeout=30) as r:
                body = r.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise RegistryError(f"{url}: response larger than {MAX_BODY} bytes", transient=False)
            return body
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code != 429 and exc.code < 500:
                transient = False
                break
            delay = _retry_after(exc.headers)
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            # IncompleteRead and BadStatusLine are HTTPException, not OSError: a truncated or garbled
            # response is as transient as a refused connection.
            last = exc
        if i < attempts - 1:
            time.sleep(delay if delay is not None else RETRY_DELAYS[i])
    raise RegistryError(f"{url}: {last}", transient=transient)


def _token(repo):
    tok_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
    try:
        token = json.loads(_get(tok_url, {}))["token"]
        if not isinstance(token, str) or not token:
            raise ValueError("token is not a non-empty string")
    except (ValueError, KeyError, TypeError, RecursionError) as exc:
        raise RegistryError(f"token response not understood: {exc!r}", transient=None)
    return token


def _fetch_verified(repo, token, kind, digest, accept):
    """GET /v2/<repo>/<kind>/<digest>, hash it against `digest`, and return the parsed JSON."""
    body = _get(f"https://registry-1.docker.io/v2/{repo}/{kind}/{digest}",
                {"Authorization": f"Bearer {token}", "Accept": ", ".join(accept)})
    got = "sha256:" + hashlib.sha256(body).hexdigest()
    if got != digest:
        raise RegistryError(f"the registry served a body hashing to {got}, not the pinned {digest}",
                            transient=None)
    try:
        return json.loads(body)
    except ValueError as exc:
        raise RegistryError(f"the pinned {kind[:-1]} {digest} is not JSON: {exc}", transient=None)


def _library(repo):
    return repo if "/" in repo else f"library/{repo}"


def fetch_index(repo, digest):
    """Fetch an index by digest from Docker Hub (anonymous token) and verify the body hash."""
    repo = _library(repo)
    return _fetch_verified(repo, _token(repo), "manifests", digest, INDEX_TYPES)


def fetch_configs(repo, index, supported):
    """{manifest digest: image config} for every supported-platform entry with no readable
    annotation, each manifest and config verified against the digest that names it."""
    validate_index(index)
    repo = _library(repo)
    token, out = None, {}
    for e in index["manifests"]:
        if platform_key(e) not in supported or alpine_release(e) is not None:
            continue
        d = e.get("digest")
        if not isinstance(d, str) or not DIGEST_RE.match(d):
            raise InputDefect(f"{platform_key(e)}: the index entry's digest {d!r} is not a sha256 digest")
        token = token or _token(repo)
        manifest = _fetch_verified(repo, token, "manifests", d, MANIFEST_TYPES)
        cfg = manifest.get("config") if isinstance(manifest, dict) else None
        cd = cfg.get("digest") if isinstance(cfg, dict) else None
        if not isinstance(cd, str) or not DIGEST_RE.match(cd):
            raise InputDefect(f"{platform_key(e)}: manifest {d} names no sha256 config digest")
        out[d] = _fetch_verified(repo, token, "blobs", cd, ("application/vnd.oci.image.config.v1+json",
                                                            "application/vnd.docker.container.image.v1+json"))
    return out


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse exits 2 by default, which this script reserves for "registry unreadable".
        self.print_usage(sys.stderr)
        print(f"FATAL: {self.prog}: {message}", file=sys.stderr)
        sys.exit(3)


def main(argv=None):
    ap = _Parser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dockerfile", type=Path, default=DEFAULT_DOCKERFILE)
    ap.add_argument("--index-file", type=Path, help="read the index JSON from this file instead of the registry")
    ap.add_argument("--configs-file", type=Path,
                    help="with --index-file: JSON object of manifest digest -> image config")
    args = ap.parse_args(argv)
    if args.configs_file and not args.index_file:
        ap.error("--configs-file needs --index-file")

    try:
        supported, builder, runtime_alpine = parse_dockerfile(args.dockerfile.read_text(encoding="utf-8"))
        configs = {}
        if args.index_file:
            try:
                index = json.loads(args.index_file.read_text(encoding="utf-8"))
                if args.configs_file:
                    configs = json.loads(args.configs_file.read_text(encoding="utf-8"))
            except ValueError as exc:
                raise InputDefect(f"an input file is not JSON: {exc}")
            if not isinstance(configs, dict):
                raise InputDefect(f"{args.configs_file} is not a JSON object of digest -> config")
        else:
            index = fetch_index(builder["repo"], builder["digest"])
            configs = fetch_configs(builder["repo"], index, supported)
        failures, notes = check(index, supported, runtime_alpine, configs)
        failures = tag_failures(builder, runtime_alpine) + failures
    except InputDefect as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 3
    except RegistryError as exc:
        if exc.transient:
            advice = "this looks transient: re-run the job"
        elif exc.transient is None:
            advice = ("re-run once (a truncated response looks like this); if it repeats, check the pinned "
                      "digest in Dockerfile.gateway")
        else:
            advice = ("re-running will not help: check the pinned digest in Dockerfile.gateway "
                      "(deleted, or not the index it claims to be)")
        print(f"FATAL: could not read the pinned index; {advice}: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, RecursionError) as exc:
        # Unreadable or non-UTF-8 input file, JSON nested past the recursion limit, and the like.
        print(f"FATAL: could not read an input file: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001 - a lint defect must not read as the exit-1 verdict
        print(f"FATAL: internal error in the lint ({type(exc).__name__}: {exc}); this is a defect in "
              "scripts/ci/check-gateway-base-index.py, not a platform mismatch", file=sys.stderr)
        return 3

    print(f"gateway-base-index: {builder['repo']}:{builder['tag']}@{builder['digest'][:19]} "
          f"supported={','.join(supported)} runtime=alpine:{runtime_alpine}")
    for n in notes:
        print(f"  note: {n}")
    for f in failures:
        print(f"  FAIL: {f}", file=sys.stderr)
    if failures:
        print("FATAL: the pinned builder and the runtime stage disagree on Alpine for a supported "
              "platform, per the builder tag, the index's annotations or its image configs (the build's "
              "abi-guard is the build-time check). "
              "See #6711 and the Dockerfile.gateway header.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
