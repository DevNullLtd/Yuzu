#!/usr/bin/env bash
# Image vulnerability gate (WP15/S9).
#
# Scans each container image with a pinned Trivy and FAILS when any image has a
# CRITICAL vulnerability that has a fix available and is not accepted in
# .trivyignore.yaml. It also prints (and optionally saves) the HIGH+CRITICAL
# table for the record; HIGH findings do not fail the gate.
#
# It also fails, before or instead of a pass, when the scan could not mean
# anything:
#   - the Trivy DB is older than 72 hours (or its age cannot be read): the DB
#     is downloaded ONCE per run, its UpdatedAt printed, and every scan uses
#     that DB (`--skip-db-update`);
#   - Trivy found no OS package in the image (a FROM-scratch or chiselled image
#     has no package database it can read), unless the image is listed, with a
#     reason, in scripts/ci/image-vuln-gate-not-covered.txt; a listed image is
#     printed as NOT COVERED on every run;
#   - .trivyignore.yaml is not in the strict shape
#     scripts/ci/image-vuln-gate-checks.py accepts (every entry: a scope, a
#     statement, an expiry at most 92 days out, an approver).
#
# Where it runs:
#   - release.yml, on every published image, on the locally built image BEFORE
#     the push (docker-publish, docker-publish-postgres, docker-publish-chisel,
#     docker-publish-agent-bundle). A failure there stops that image from being
#     pushed, and the release job, which needs every docker-publish job except
#     the agent bundle, does not run. Each job keeps the reports (--report-dir)
#     as evidence: see docs/ci-architecture.md "Release image vulnerability
#     gate".
#   - pre-release.yml security-scan, on the published tags, after the release.
#     Detective only there: a new CVE disclosed after the push turns QA red.
#
# Usage:
#   scripts/ci/image-vuln-gate.sh [--report-dir DIR] [NAME=]IMAGE [[NAME=]IMAGE...]
#
# IMAGE must be in the local Docker daemon: a tag or, better, an image ID (see
# scripts/ci/image-identity.sh). Every scan passes `--image-src docker`, so
# Trivy never falls back to containerd, podman or a registry: a missing image
# fails the gate instead of a same-named image from elsewhere being scanned and
# passed. pre-release.yml `docker pull`s the published tags first.
#
# NAME is the published repository name (yuzu-server-chisel). It names the
# reports and is what the not-covered list is matched against. Without it the
# name is the tag's last path component without the tag (a bare image ID gets
# `image-<first 12 hex>` and can never match the list). Two images with the
# same name in one run are refused.
#
# With --report-dir, three files per image: trivy-NAME.json (the full Trivy
# report: image ID, layer diff IDs, OS, every package, HIGH+CRITICAL findings
# and the accepted ones), trivy-NAME.txt (the same as a table) and
# trivy-NAME.gate.txt (Trivy version, DB UpdatedAt, image ID, OS package count,
# coverage and the gate result).
#
# Environment (every other TRIVY_* variable is cleared, so the environment
# cannot change the DB source, the severities or what is ignored; Trivy also
# gets an empty config file, so a trivy.yaml in the working directory is not
# read):
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
# failed, the DB was stale, an image was not covered, or the setup failed (fail
# closed: a scan that did not complete is never a pass); 2 usage error.
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
CHECKS=(python3 -I "$ROOT/scripts/ci/image-vuln-gate-checks.py")
NOT_COVERED="$ROOT/scripts/ci/image-vuln-gate-not-covered.txt"

# Keep the two TRIVY_* variables this script reads, then clear every other one:
# Trivy maps every flag to a TRIVY_* variable (TRIVY_DB_REPOSITORY,
# TRIVY_SEVERITY, TRIVY_IGNOREFILE, TRIVY_SKIP_FILES, TRIVY_INSECURE, ...), and
# none of that may change what the gate scans or with which DB. The cache
# directory reaches Trivy as --cache-dir, not through the environment.
trivy_bin_env="${TRIVY_BIN:-}"
trivy_cache_env="${TRIVY_CACHE_DIR:-}"
while IFS= read -r v; do unset "$v"; done < <(compgen -e | grep '^TRIVY_' || true)

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

# ── The ignore file: present, and every entry well formed ──────────────────
# Trivy itself accepts an entry with no reason, no expiry and no scope, so this
# is the only place that keeps an acceptance from becoming permanent,
# unexplained, unapproved or wider than one package. It is parsed, not
# grepped: a flow-style entry or a decoy line inside a statement cannot pass.
if [ ! -r "$IGNORE_FILE" ]; then
    err "ignore file $IGNORE_FILE is missing or unreadable (the gate does not run without it)"
    exit 1
fi
if ! "${CHECKS[@]}" ignore-file "$IGNORE_FILE"; then
    err "$IGNORE_FILE is not in the shape the gate accepts (above): every entry needs \`paths\` or \`purls\`, a statement, an expired_at at most 92 days out and an approved_by login"
    exit 1
fi

# ── Trivy ────────────────────────────────────────────────────────────────────
WORK="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/yuzu-image-vuln-gate.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if [ -n "$trivy_bin_env" ]; then
    TRIVY="$trivy_bin_env"
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

CACHE="${trivy_cache_env:-$WORK/cache}"
# Trivy's own temporary files (image layers it extracts) go under WORK too, so
# a killed run leaves nothing in the shared /tmp (the trap removes WORK).
mkdir -p "$WORK/tmp"
export TMPDIR="$WORK/tmp"
: > "$WORK/trivy.yaml"
# Every Trivy call: the empty config, the cache, and the default DB sources
# named explicitly (they are Trivy 0.70.0's defaults: the Google mirror of
# Docker Hub's aquasec/trivy-db, then GitHub's).
COMMON=(--config "$WORK/trivy.yaml" --cache-dir "$CACHE")
DB_REPOS="mirror.gcr.io/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2"
[ -z "$REPORT_DIR" ] || mkdir -p "$REPORT_DIR"

# ── The DB: once per run, and fresh ──────────────────────────────────────────
# Downloaded (or updated) once, here, with its log visible (it names the
# repository it came from); every scan below then runs with --skip-db-update,
# so all images are judged against the same DB, whose age is checked first.
# The DB is not signed; its age is the check that a stale or replayed copy
# cannot pass.
echo "==> Trivy ${TRIVY_VERSION}: vulnerability DB"
if ! "$TRIVY" image "${COMMON[@]}" --db-repository "$DB_REPOS" --download-db-only; then
    err "could not download the Trivy vulnerability DB (treated as a failure)"
    exit 1
fi
if ! db_info="$("${CHECKS[@]}" db-age "$CACHE/db/metadata.json")"; then
    err "the Trivy vulnerability DB is stale or unreadable (above); re-run once the published DB is current"
    exit 1
fi
printf '%s\n' "$db_info" | sed 's/^/    /'
db_updated="$(printf '%s\n' "$db_info" | sed -n 's/^trivy_db_updated_at=//p')"
db_downloaded="$(printf '%s\n' "$db_info" | sed -n 's/^trivy_db_downloaded_at=//p')"

summary() {
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
    printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY" || true
}
summary "### Image vulnerability gate (Trivy ${TRIVY_VERSION}, DB UpdatedAt ${db_updated})"
summary ""
summary "| Image | OS packages | Coverage | Result |"
summary "|---|---|---|---|"

# ── Scan ─────────────────────────────────────────────────────────────────────
failed=0
declare -A seen_names=()
for arg in "${IMAGES[@]}"; do
    # NAME=IMAGE, or a bare IMAGE (an image reference cannot contain "=").
    case "$arg" in
        *=*) name="${arg%%=*}"; image="${arg#*=}" ;;
        *)   name=""; image="$arg" ;;
    esac
    if [ -z "$name" ]; then
        case "$image" in
            sha256:*) name="image-${image:7:12}" ;;
            *) name="$(printf '%s' "$image" | sed 's#.*/##; s#[@:].*##')" ;;
        esac
    fi
    if ! [[ "$name" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || [ -z "$image" ]; then
        err "bad image argument '$arg' (NAME must be lower-case letters, digits, '.', '_' or '-')"
        exit 2
    fi
    if [ -n "${seen_names[$name]:-}" ]; then
        err "two images named '$name' in one run; their reports would overwrite each other (pass NAME=IMAGE)"
        exit 2
    fi
    seen_names[$name]=1
    echo "==> $name: $image"
    json="$WORK/trivy-${name}.json"
    table="$WORK/trivy-${name}.txt"
    result="FAIL"
    coverage="unknown"
    os_packages="?"
    os_desc="?"

    # The record: HIGH and CRITICAL, fixed or not, and the accepted findings
    # (--show-suppressed), as JSON, which also lists every package (that is
    # what the coverage check counts). Not --quiet: Trivy's log names the OS
    # it detected and warns when it finds no OS package. Informational, but a
    # scan that cannot complete is a failure, not an empty report.
    if ! "$TRIVY" image "${COMMON[@]}" --skip-db-update --image-src docker --scanners vuln \
            --severity HIGH,CRITICAL --show-suppressed --ignorefile "$IGNORE_FILE" \
            --format json --output "$json" "$image" \
        || ! "$TRIVY" convert --quiet --format table --severity HIGH,CRITICAL --show-suppressed \
            --output "$table" "$json"; then
        err "$image: Trivy could not scan the image (treated as a failure)"
        failed=1
        summary "| $name | ? | ? | could not scan |"
        continue
    fi
    cat "$table"

    # Coverage: an image whose OS packages Trivy could not see was not scanned.
    if cov="$("${CHECKS[@]}" coverage "$json" "$name" "$NOT_COVERED")"; then
        coverage="$(printf '%s\n' "$cov" | sed -n 's/^coverage=//p')"
        os_packages="$(printf '%s\n' "$cov" | sed -n 's/^os_packages=//p')"
        os_desc="$(printf '%s\n' "$cov" | sed -n 's/^os=//p')"
        echo "    OS: $os_desc, $os_packages OS packages scanned"
        printf '%s\n' "$cov" | grep '^warning:' || true
        if [ "$coverage" = "not-covered" ]; then
            reason="$(printf '%s\n' "$cov" | sed -n 's/^reason=//p')"
            echo "    NOT COVERED by OS package scanning (listed in scripts/ci/image-vuln-gate-not-covered.txt): $reason"
            [ -z "${GITHUB_ACTIONS:-}" ] || echo "::warning::$name: OS packages NOT scanned (Trivy sees none; listed as not covered)"
        fi
        cov_ok=1
    else
        err "$image: OS packages not scanned (above)"
        failed=1
        coverage="not-covered (unlisted)"
        cov_ok=0
    fi

    # The gate. Exit code 3 means findings; anything else non-zero is a Trivy
    # error, which must not read as a pass either.
    rc=0
    "$TRIVY" image "${COMMON[@]}" --quiet --skip-db-update --image-src docker --scanners vuln \
        --severity CRITICAL --ignore-unfixed --ignorefile "$IGNORE_FILE" \
        --exit-code 3 --format table "$image" || rc=$?
    case "$rc" in
        0) if [ "$cov_ok" = 1 ]; then
               result="pass"
               echo "    pass: no fixable CRITICAL vulnerability"
           else
               result="FAIL: OS packages not scanned"
           fi ;;
        3) err "$image has a fixable CRITICAL vulnerability (table above). Rebuild on current packages, or accept it in .trivyignore.yaml with a scope, a statement, an expiry and an approver."
           result="FAIL: fixable CRITICAL"
           failed=1 ;;
        *) err "$image: Trivy exited $rc during the gate scan (treated as a failure)"
           result="FAIL: Trivy exited $rc"
           failed=1 ;;
    esac
    summary "| $name | $os_packages | $coverage | $result |"

    if [ -n "$REPORT_DIR" ]; then
        cp "$json" "$table" "$REPORT_DIR/"
        image_id="$(python3 -I -c 'import json,sys; print((json.load(open(sys.argv[1])).get("Metadata") or {}).get("ImageID") or "?")' "$json" 2>/dev/null || echo '?')"
        {
            echo "image: $name ($image)"
            echo "image id: $image_id"
            echo "trivy: $TRIVY_VERSION"
            echo "trivy db: UpdatedAt $db_updated, DownloadedAt $db_downloaded"
            echo "os: $os_desc"
            echo "os packages scanned: $os_packages"
            echo "coverage: $coverage"
            echo "ignore file: $(sha256sum "$IGNORE_FILE" | cut -d' ' -f1)"
            echo "gate: $result"
            echo "scanned at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        } > "$REPORT_DIR/trivy-${name}.gate.txt"
    fi
done

exit "$failed"
