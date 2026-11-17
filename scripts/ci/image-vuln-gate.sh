#!/usr/bin/env bash
# Image vulnerability gate (WP15/S9).
#
# Scans each container image with a pinned Trivy and FAILS when any image has a
# CRITICAL vulnerability that has a fix available and is not accepted in
# .trivyignore.yaml. It also prints (and optionally saves) the HIGH+CRITICAL
# table for the record; HIGH findings do not fail the gate.
#
# Where it runs:
#   - release.yml, on every published image, on the locally built image BEFORE
#     the push (docker-publish, docker-publish-postgres, docker-publish-chisel,
#     docker-publish-agent-bundle). A failure there stops that image from being
#     pushed, and the release job, which needs every docker-publish job except
#     the agent bundle, does not run.
#   - pre-release.yml security-scan, on the published tags, after the release.
#     Detective only there: a new CVE disclosed after the push turns QA red.
#
# Usage:
#   scripts/ci/image-vuln-gate.sh [--report-dir DIR] IMAGE [IMAGE...]
#
# IMAGE is anything `trivy image` accepts; a local Docker image is scanned from
# the daemon (no pull).
#
# Environment:
#   TRIVY_BIN        use this trivy binary instead of installing the pinned one
#                    (local runs, tests). It must be TRIVY_VERSION.
#   TRIVY_CACHE_DIR  Trivy's DB and layer cache. Default: a fresh per-run
#                    directory. Never point it at a fixed shared path: the
#                    self-hosted pools run four runners as ONE OS identity, so
#                    $HOME/.cache/trivy would be shared by concurrent jobs
#                    (#1871). The pinned binary is installed per run for the
#                    same reason ($RUNNER_TEMP, else a mktemp directory).
#   YUZU_TRIVYIGNORE ignore file (default: <repo>/.trivyignore.yaml).
#
# Exit status: 0 every image passed; 1 a fixable CRITICAL was found, a scan
# failed, or the setup failed (fail closed: a scan that did not complete is
# never a pass); 2 usage error.
set -euo pipefail

# Pinned Trivy. The sha256 values are from trivy_0.70.0_checksums.txt; the
# checksums file and the Linux-64bit tarball were verified with
# `cosign verify-blob` against their .sigstore.json bundles (issuer
# token.actions.githubusercontent.com, identity github.com/aquasecurity/trivy)
# on 2026-11-17. Bump all three together, and re-verify the signatures.
TRIVY_VERSION="0.70.0"
TRIVY_SHA256_LINUX_64BIT="8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9"
TRIVY_SHA256_LINUX_ARM64="2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IGNORE_FILE="${YUZU_TRIVYIGNORE:-$ROOT/.trivyignore.yaml}"

err() {
    if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error::$*"; else echo "ERROR: $*" >&2; fi
}

usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2; exit 2; }

REPORT_DIR=""
IMAGES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --report-dir) [ $# -ge 2 ] || usage; REPORT_DIR="$2"; shift ;;
        -h|--help) usage ;;
        --) shift; IMAGES+=("$@"); break ;;
        -*) err "unknown option: $1"; usage ;;
        *) IMAGES+=("$1") ;;
    esac
    shift
done
[ "${#IMAGES[@]}" -gt 0 ] || usage

# ── The ignore file: present, and every entry has a reason and an expiry ────
# Trivy itself accepts an entry with neither, so this is the only place that
# keeps an acceptance from becoming permanent and unexplained.
if [ ! -r "$IGNORE_FILE" ]; then
    err "ignore file $IGNORE_FILE is missing or unreadable (the gate does not run without it)"
    exit 1
fi
ids=$(grep -cE '^[[:space:]]*-[[:space:]]+id:' "$IGNORE_FILE" || true)
stmts=$(grep -cE '^[[:space:]]+statement:[[:space:]]*[^[:space:]]' "$IGNORE_FILE" || true)
exps=$(grep -cE '^[[:space:]]+expired_at:[[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]*$' "$IGNORE_FILE" || true)
if [ "$ids" != "$stmts" ] || [ "$ids" != "$exps" ]; then
    err "$IGNORE_FILE: $ids entries but $stmts statements and $exps expired_at dates; every entry needs both"
    exit 1
fi

# ── Trivy ────────────────────────────────────────────────────────────────────
WORK="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/yuzu-image-vuln-gate.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if [ -n "${TRIVY_BIN:-}" ]; then
    TRIVY="$TRIVY_BIN"
else
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64)          asset="Linux-64bit"; want="$TRIVY_SHA256_LINUX_64BIT" ;;
        Linux/aarch64|Linux/arm64) asset="Linux-ARM64"; want="$TRIVY_SHA256_LINUX_ARM64" ;;
        *) err "no pinned Trivy for $(uname -s)/$(uname -m); set TRIVY_BIN"; exit 1 ;;
    esac
    tgz="trivy_${TRIVY_VERSION}_${asset}.tar.gz"
    url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${tgz}"
    curl -fsSL --retry 3 --retry-delay 5 -o "$WORK/$tgz" "$url" \
        || { err "could not download $url"; exit 1; }
    echo "${want}  $WORK/$tgz" | sha256sum -c --quiet - \
        || { err "$tgz does not match its pinned sha256; refusing to run it"; exit 1; }
    tar -xzf "$WORK/$tgz" -C "$WORK" trivy
    TRIVY="$WORK/trivy"
fi
"$TRIVY" --version 2>/dev/null | grep -qx "Version: ${TRIVY_VERSION}" \
    || { err "$TRIVY is not Trivy ${TRIVY_VERSION}"; exit 1; }

export TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-$WORK/cache}"
[ -z "$REPORT_DIR" ] || mkdir -p "$REPORT_DIR"

# ── Scan ─────────────────────────────────────────────────────────────────────
failed=0
for image in "${IMAGES[@]}"; do
    echo "==> $image"
    report=(--format table)
    if [ -n "$REPORT_DIR" ]; then
        name="$(printf '%s' "$image" | sed 's#.*/##; s#[@:].*##')"
        report+=(--output "$REPORT_DIR/trivy-${name}.txt")
    fi

    # The record: HIGH and CRITICAL, fixed or not. Informational, but a scan
    # that cannot complete is a failure, not an empty report.
    if ! "$TRIVY" image --quiet --scanners vuln --severity HIGH,CRITICAL \
            --ignorefile "$IGNORE_FILE" "${report[@]}" "$image"; then
        err "$image: Trivy could not scan the image (treated as a failure)"
        failed=1
        continue
    fi
    [ -z "$REPORT_DIR" ] || cat "$REPORT_DIR/trivy-${name}.txt"

    # The gate. Exit code 3 means findings; anything else non-zero is a Trivy
    # error, which must not read as a pass either.
    rc=0
    "$TRIVY" image --quiet --scanners vuln --severity CRITICAL --ignore-unfixed \
        --ignorefile "$IGNORE_FILE" --exit-code 3 --format table "$image" || rc=$?
    case "$rc" in
        0) echo "    pass: no fixable CRITICAL vulnerability" ;;
        3) err "$image has a fixable CRITICAL vulnerability (table above). Rebuild on current packages, or accept it in .trivyignore.yaml with a statement and an expiry."
           failed=1 ;;
        *) err "$image: Trivy exited $rc during the gate scan (treated as a failure)"
           failed=1 ;;
    esac
done

exit "$failed"
