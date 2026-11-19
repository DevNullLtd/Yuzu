#!/usr/bin/env bash
# Pin a locally built image by ID, and prove a pushed image is the one that
# was scanned (WP15/S9).
#
# release.yml builds each published image twice: once with `load: true`, which
# the healthcheck probe and scripts/ci/image-vuln-gate.sh check, and once
# pushed by digest (`push-by-digest=true`). The second build normally reuses the first's layers, but
# nothing forces it to, and the Big Tam runners share one Docker daemon, so a
# tag can be re-pointed by another job. This script closes both gaps:
#
#   pin IMAGE
#       Resolve IMAGE (a tag) to its local image ID once, right after the
#       build, and record its filesystem: the ordered layer diff IDs. Prints
#       `id=<image id>` and `layers=<diff id>,<diff id>,...` lines, ready to
#       append to $GITHUB_OUTPUT. Every later check uses the ID, never the tag.
#
#   verify-pushed REF@DIGEST LAYERS
#       Read the pushed image's layer diff IDs from the registry and fail
#       unless they equal LAYERS (from `pin`). The image config (labels,
#       created time) legitimately differs between the two builds; the
#       filesystem must not. Run right after the push and before the image is
#       attested or signed, by scripts/ci/image-publish.sh `verified`, which
#       records the result in the publish journal.
#
# Exit status: 0 ok; 1 mismatch, unreadable image or registry error (fail
# closed); 2 usage error.
set -euo pipefail

err() {
    if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error::$*"; else echo "ERROR: $*" >&2; fi
}
usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2; exit 2; }

# Reads `docker ... --format '{{json ...}}'` output on stdin and prints the
# diff IDs comma-joined. Accepts an image config ({"rootfs": ...}, as
# `imagetools inspect --format '{{json .Image}}'` prints for a single-platform
# manifest), a bare diff-ID list (`docker image inspect` .RootFS.Layers), or a
# platform map (an index) holding linux/amd64 or exactly one image. Anything
# else fails.
layers_from_json() {
    python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError as e:
    sys.exit("unreadable JSON: %s" % e)
if isinstance(d, dict) and "rootfs" not in d:
    # A platform map (an index). Every image release.yml publishes is
    # linux/amd64 only; any other shape is ambiguous and refused.
    if "linux/amd64" in d:
        d = d["linux/amd64"]
    elif len(d) == 1:
        d = next(iter(d.values()))
    else:
        sys.exit("index without a linux/amd64 image: %s" % sorted(d))
if isinstance(d, dict):
    d = (d.get("rootfs") or {}).get("diff_ids")
if not isinstance(d, list) or not d or not all(isinstance(x, str) and x.startswith("sha256:") for x in d):
    sys.exit("no usable layer diff IDs (ambiguous index or malformed config)")
print(",".join(d))
'
}

cmd="${1:-}"
case "$cmd" in
    pin)
        [ "$#" -eq 2 ] || usage
        image="$2"
        id="$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null)" \
            || { err "$image is not present in the local Docker daemon"; exit 1; }
        case "$id" in sha256:*) ;; *) err "$image: unexpected image ID '$id'"; exit 1 ;; esac
        layers="$(docker image inspect --format '{{json .RootFS.Layers}}' "$id" | layers_from_json)" \
            || { err "$image: could not read its layer diff IDs"; exit 1; }
        echo "id=$id"
        echo "layers=$layers"
        ;;
    verify-pushed)
        [ "$#" -eq 3 ] || usage
        ref="$2"; want="$3"
        case "$ref" in *@sha256:*) ;; *) err "verify-pushed needs a digest reference, got '$ref'"; exit 1 ;; esac
        [ -n "$want" ] || { err "verify-pushed: no expected layers (was the image pinned?)"; exit 1; }
        got="$(docker buildx imagetools inspect "$ref" --format '{{json .Image}}' | layers_from_json)" \
            || { err "$ref: could not read the pushed image's layers"; exit 1; }
        if [ "$got" != "$want" ]; then
            err "$ref is NOT the image that was scanned: its layers differ from the scanned build's. Do not attest or sign it; re-run the job."
            echo "scanned: $want" >&2
            echo "pushed:  $got" >&2
            exit 1
        fi
        echo "ok: $ref has the scanned image's layers ($(printf '%s' "$got" | awk -F, '{ print NF }') layers)"
        ;;
    *) usage ;;
esac
