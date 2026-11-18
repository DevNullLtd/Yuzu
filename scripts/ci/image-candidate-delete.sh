#!/usr/bin/env bash
# Deletes leftover candidate digests of a release image from GHCR, refusing
# any digest a release tag names (WP15/S9, G8P6-release-deploy-1).
#
# Why. A publish attempt that pushed but did not finish leaves its digest in
# GHCR: untagged (the buildx jobs push by digest) or under the agent bundle's
# `:candidate-<run id>-<attempt>` tag. GHCR deletes a package VERSION, and a
# version IS a digest: deleting it deletes every tag that names it. A publish
# journal cannot decide which digests are safe: one ending `tagging` (or
# `tagged` with a failed upload, so no journal at all) may have moved a
# release tag to its digest. So this script decides at delete time, from the
# registry: it lists every tag of the package (the GitHub packages API),
# resolves each one other than a `candidate-*` tag (`docker buildx imagetools
# inspect`), and refuses to delete a digest any of them names, directly or as
# a child of an index. The API's own tag-to-version view is checked too; the
# two must agree.
#
# Usage:
#   image-candidate-delete.sh [--delete] OWNER PACKAGE DIGEST...
#       OWNER is the organisation (devnullltd), PACKAGE the image name
#       (yuzu-server, yuzu-agent-bundle-chisel, ...), DIGEST sha256:<64 hex>.
#       Without --delete (the default) it only checks and reports: nothing is
#       deleted. With --delete it checks again immediately before each
#       deletion and deletes only when EVERY named digest passes.
#
# Refused (nothing deleted) when: a digest is malformed, is not exactly one
# version of the package, or is named by a non-candidate tag (or is a child of
# an index such a tag names); the package API and the registry disagree about
# a tag; any listing or resolution fails; or a release.yml run of REPO is
# queued or in progress (a run moving a tag now could name the digest after
# the check).
#
# Left behind: the signature and attestation referrers of a deleted digest
# (`sha256-<hex>.sig`/`.att` tags, or untagged referrer versions). They are
# tagged, so this script refuses them; they describe an image that no longer
# exists and are harmless.
#
# Environment: REGISTRY (default ghcr.io), REPO (default DevNullLtd/Yuzu, for
# the in-progress run check). Needs gh (with read:packages and
# delete:packages: `gh auth refresh -s read:packages,delete:packages`, admin
# on the package), docker buildx and jq. Tests: tests/test_image_publish.py
# CandidateDelete.
#
# Exit status: 0 every digest passed (and, with --delete, was deleted);
# 1 refused or a check failed; 2 usage; 3 a release tag no longer resolved
# after the deletion (investigate at once).
set -euo pipefail

REGISTRY="${REGISTRY:-ghcr.io}"
REPO="${REPO:-DevNullLtd/Yuzu}"

err() { echo "ERROR: $*" >&2; }
usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2; exit 2; }

DELETE=0
if [ "${1:-}" = "--delete" ]; then DELETE=1; shift; fi
[ "$#" -ge 3 ] || usage
OWNER="$1"; PKG="$2"; shift 2
[[ "$OWNER" =~ ^[a-z0-9][a-z0-9-]*$ ]] || { err "bad owner '$OWNER' (lower case)"; exit 2; }
[[ "$PKG" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || { err "bad package '$PKG'"; exit 2; }
for d in "$@"; do
    [[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || { err "bad digest '$d' (sha256:<64 hex>)"; exit 2; }
done
TARGETS=("$@")
IMAGE="$REGISTRY/$OWNER/$PKG"
API="/orgs/$OWNER/packages/container/$PKG/versions"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# check DIGEST...: fills VID[digest] and fails (returns 1, having printed why)
# unless every one of DIGEST may be deleted.
declare -A VID=()
check() {
    local refused=0 tag d vid n line want got raw kids
    VID=()
    # 1. No release run that could move a tag right now.
    if ! n="$(gh run list --repo "$REPO" --workflow release.yml --limit 50 --json status \
            --jq '[.[] | select(.status != "completed")] | length')"; then
        err "could not list release.yml runs of $REPO"; return 1
    fi
    [ "$n" = 0 ] || { err "$n release.yml run(s) of $REPO queued or in progress: wait until none is"; return 1; }
    # 2. Every version and its tags, from the packages API.
    if ! gh api --paginate "$API?per_page=100" \
            --jq '.[] | [(.id | tostring), .name, ((.metadata.container.tags // []) | join(","))] | @tsv' \
            >"$WORK/versions.tsv"; then
        err "could not list the versions of $PKG"; return 1
    fi
    [ -s "$WORK/versions.tsv" ] || { err "the packages API listed no version of $PKG"; return 1; }
    : >"$WORK/protected"
    : >"$WORK/apitags"
    while IFS=$'\t' read -r vid d tags; do
        if ! [[ "$vid" =~ ^[0-9]+$ && "$d" =~ ^sha256:[0-9a-f]{64}$ ]]; then
            err "unexpected version row from the API: '$vid' '$d'"; return 1
        fi
        [ -n "$tags" ] || continue
        IFS=, read -r -a arr <<<"$tags"
        for tag in "${arr[@]}"; do
            case "$tag" in candidate-*) continue ;; esac
            printf '%s\t%s\n' "$tag" "$d" >>"$WORK/apitags"
            printf '%s\n' "$d" >>"$WORK/protected"
        done
    done <"$WORK/versions.tsv"
    # 3. Every such tag, resolved in the registry; an index protects its children.
    while IFS=$'\t' read -r tag want; do
        if ! got="$(docker buildx imagetools inspect "$IMAGE:$tag" --format '{{.Manifest.Digest}}')"; then
            err "could not resolve $IMAGE:$tag"; return 1
        fi
        if [ "$got" != "$want" ]; then
            err "$IMAGE:$tag names $got in the registry but $want in the packages API; not deleting anything"
            return 1
        fi
        if ! raw="$(docker buildx imagetools inspect "$IMAGE:$tag" --raw)"; then
            err "could not read $IMAGE:$tag"; return 1
        fi
        if ! kids="$(jq -r '(.manifests // [])[] | .digest' <<<"$raw")"; then
            err "could not parse the manifest of $IMAGE:$tag"; return 1
        fi
        [ -z "$kids" ] || printf '%s\n' "$kids" >>"$WORK/protected"
    done <"$WORK/apitags"
    # 4. Each target: exactly one version, named by no protected tag.
    for d in "$@"; do
        n="$(awk -F '\t' -v d="$d" '$2 == d' "$WORK/versions.tsv" | wc -l)"
        if [ "$n" != 1 ]; then
            err "$d is $n versions of $PKG, not exactly one: refused"; refused=1; continue
        fi
        line="$(awk -F '\t' -v d="$d" '$2 == d' "$WORK/versions.tsv")"
        vid="${line%%$'\t'*}"
        [[ "$vid" =~ ^[0-9]+$ ]] || { err "$d has no usable version id: refused"; refused=1; continue; }
        if grep -qxF "$d" "$WORK/protected"; then
            err "$d is named by a release tag (or is part of an image one names): refused"
            awk -F '\t' -v d="$d" '$2 == d { print "  " $1 }' "$WORK/apitags" >&2
            refused=1; continue
        fi
        VID[$d]="$vid"
        echo "deletable: $IMAGE@$d (version $vid; tags: $(cut -f3 <<<"$line" | sed 's/^$/none/'))"
    done
    return "$refused"
}

check "${TARGETS[@]}" || { err "nothing deleted"; exit 1; }
if [ "$DELETE" = 0 ]; then
    echo "check only: nothing deleted (pass --delete to delete these, after the operator agrees)"
    exit 0
fi
for d in "${TARGETS[@]}"; do
    # Again, immediately before this deletion: a tag may have moved since.
    check "$d" >/dev/null || { err "refused on the re-check before deleting $d; stopped"; exit 1; }
    vid="${VID[$d]:-}"
    [[ "$vid" =~ ^[0-9]+$ ]] || { err "no version id for $d; stopped"; exit 1; }
    gh api -X DELETE "$API/$vid" >/dev/null
    echo "deleted: $IMAGE@$d (version $vid)"
done
# Every release tag still resolves.
rc=0
cut -f1 "$WORK/apitags" | sort -u | while read -r tag; do
    docker buildx imagetools inspect "$IMAGE:$tag" --format '{{.Manifest.Digest}}' >/dev/null 2>&1 \
        || { err "$IMAGE:$tag no longer resolves after the deletion"; exit 3; }
done || rc=$?
exit "$rc"
