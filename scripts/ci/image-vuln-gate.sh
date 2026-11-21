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
#   - the Trivy DB: it is downloaded ONCE per run into a fresh, empty cache
#     directory this script creates (an inherited TRIVY_CACHE_DIR is never
#     used), pinned by the manifest digest the registry reports for the tag,
#     which is recorded; the gate fails when the DB is older than 72 hours,
#     its age cannot be read, or it was not downloaded by this run. Every scan
#     uses that DB (`--skip-db-update`). The DB is NOT signed upstream (no
#     cosign signature or attestation on aquasecurity/trivy-db, checked
#     2026-11-18): TLS to the registry and the recorded digest are the only
#     evidence of what was used;
#   - Trivy found no OS package in the image (a FROM-scratch or chiselled image
#     has no package database it can read), unless the image is listed, in
#     force, in scripts/ci/image-vuln-gate-not-covered.txt; a listed image is
#     printed as NOT COVERED on every run;
#   - the image's OS release is one Trivy has no advisory data for: Trivy marks
#     it end of service life, its family has no canary here, its version is a
#     pre-release (`_alpha`, `_rc`, `~rc`, `-rc`, ...: Trivy reads it against
#     the released version's advisories) or not a released version number, or
#     a canary (a tiny root filesystem of the same OS release holding packages
#     older than every fix) matches nothing against this run's DB (Debian
#     testing/sid, Alpine edge, an Ubuntu devel series). A scan of such an
#     image reads clean whatever it ships;
#   - .trivyignore.yaml is not in the strict shape
#     scripts/ci/image-vuln-gate-checks.py accepts (every entry: a concrete
#     path inside the image or a full versioned purl, a statement, an expiry
#     at most 92 days out, an approver, and an approval reference and date,
#     which are checked for format only: nothing verifies them against the
#     pull request). Trivy never reads that file: it reads a copy the checker
#     writes holding only the entries in force.
#
# Where it runs:
#   - release.yml, on every published image, on the locally built image BEFORE
#     the push (docker-publish, docker-publish-postgres, docker-publish-chisel,
#     docker-publish-agent-bundle), with --release. A failure there stops that
#     image from being pushed, and the release job, which needs every
#     docker-publish job except the agent bundle, does not run. Each job keeps
#     the reports (--report-dir) as evidence, a refused image's included: see
#     docs/ci-architecture.md "Release image vulnerability gate".
#   - pre-release.yml security-scan, on the published tags, after the release.
#     Detective only there: a new CVE disclosed after the push turns QA red.
#
# Usage:
#   scripts/ci/image-vuln-gate.sh [--release] [--budget SECONDS] [--report-dir DIR [--attempt N]] [NAME=]IMAGE [[NAME=]IMAGE...]
#
# --release: an acceptance (an ignore entry or a not-covered listing) whose
# approval_ref is `pending` is NOT honoured. Without it a pending one is
# honoured and reported as pending.
#
# IMAGE must be in the local Docker daemon: a tag or, better, an image ID (see
# scripts/ci/image-identity.sh). Every scan passes `--image-src docker`, so
# Trivy never falls back to containerd, podman or a registry: a missing image
# fails the gate instead of a same-named image from elsewhere being scanned and
# passed. pre-release.yml `docker pull`s the published tags first.
#
# NAME is the published repository name (yuzu-server-chisel). It names the
# reports and is what the not-covered list is matched against (exactly).
# Without it the name is the tag's last path component without the tag (a bare
# image ID gets `image-<first 12 hex>` and can never match the list). Two
# images with the same name in one run are refused.
#
# With --report-dir, per image: trivy-NAME.json (the full Trivy report: image
# ID, layer diff IDs, OS, every package, HIGH+CRITICAL findings and the
# accepted ones), trivy-NAME.txt (the same as a table) and trivy-NAME.gate.txt
# (Trivy version, the DB's repository@digest and dates, image ID, OS, OS
# package count, coverage, the advisory canary, the ignore file and the gate
# result). A trivy-NAME.gate.txt is written for every image on every exit the
# script reaches after reading its arguments, including a SIGTERM/SIGINT
# (`gate: FAIL: cancelled ...`), with `gate: FAIL: <reason>` when the gate
# refused it or stopped early, so a refusal leaves evidence too. SIGKILL, and
# a usage error before the image list is read, leave none.
#
# --attempt N (release.yml passes the workflow's run attempt) names the reports
# trivy-NAME.attempt-N.{json,txt,gate.txt} and records the attempt, so a
# re-run's reports sit beside the earlier attempts' and never replace them.
#
# Environment: every TRIVY_* variable is cleared, so the environment cannot
# change the DB source, the cache, the severities or what is ignored; Trivy
# also gets an empty config file, so a trivy.yaml in the working directory is
# not read. Two inputs remain, for local runs and tests only:
#   TRIVY_BIN        use this trivy binary instead of installing the pinned one.
#                    It must be TRIVY_VERSION. Refused on GitHub Actions.
#   YUZU_TRIVYIGNORE ignore file to validate (default: <repo>/.trivyignore.yaml).
#                    It goes through the same parser; Trivy reads only the
#                    checker's canonical YAML copy of it.
# The pinned binary, the DB and Trivy's temporary files live in a per-run
# directory ($RUNNER_TEMP, else $TMPDIR), never a fixed shared path: the
# self-hosted pools run four runners as ONE OS identity (#1871).
#
# Time budget. Every long-running call runs under `timeout`, bounded by its
# own deadline AND by what is left of the gate's overall budget (--budget,
# default GATE_BUDGET = 1500 s, 25 minutes): the digest lookup RESOLVE_DEADLINE
# per DB source, the whole Trivy download (every curl retry included)
# CURL_DEADLINE, each DB download DB_DEADLINE per source, each scan
# SCAN_DEADLINE. When the budget runs out the gate stops itself, writes
# `gate: FAIL: gate stopped ...: the gate ran out of its <N>s budget` for every
# image not yet judged, and exits 1. So the gate ends, with its reports, within
# the budget plus KILL_AFTER (+ cleanup) of starting: below the 30-minute
# timeout of pre-release.yml's security-scan job (which passes --budget 1200
# to leave room for its pulls) and of every release.yml job that runs it. A
# job timeout or cancel that comes first is a signal, handled below.
#
# Signals. The Actions runner cancels a step with SIGINT, then SIGTERM about
# 7.5 s later, then SIGKILL. On the first SIGINT or SIGTERM the gate ignores
# any further one, writes `gate: FAIL: cancelled (<signal>) ...` for every
# image not yet judged AT ONCE, then stops the running child (SIGTERM, and
# SIGKILL after SIGNAL_GRACE = 3 s), removes its work directory and exits
# 130/143: all of it well inside the 7.5 s before the runner's second signal.
#
# Exit status: 0 every image passed; 1 a fixable CRITICAL was found, a scan
# failed, the DB was stale or unpinnable, an image was not covered or has no
# advisory data, the budget ran out, or the setup failed (fail closed: a scan
# that did not complete is never a pass); 2 usage error; 130/143 cancelled by
# SIGINT/SIGTERM.
set -euo pipefail

# Pinned Trivy. The sha256 values are from trivy_0.70.0_checksums.txt; the
# checksums file and the Linux-64bit tarball were verified with
# `cosign verify-blob` against their .sigstore.json bundles (issuer
# token.actions.githubusercontent.com, identity github.com/aquasecurity/trivy)
# on 2026-11-17. Bump all three together, and re-verify the signatures.
TRIVY_VERSION="0.70.0"
TRIVY_SHA256_LINUX_64BIT="8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9"
TRIVY_SHA256_LINUX_ARM64="2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d"

# The DB sources, tried in order: Trivy 0.70.0's defaults (the Google mirror of
# Docker Hub's aquasec/trivy-db, then GitHub's), named explicitly. Each tag is
# resolved to a manifest digest first and the download is pinned to it.
DB_REPOS=("mirror.gcr.io/aquasec/trivy-db" "ghcr.io/aquasecurity/trivy-db")
DB_TAG="2"
# Deadlines (seconds), per call; every call is also bounded by what is left of
# the gate's overall budget. Worst case with both DB sources failing slowly:
# 2 x 60 + 180 + 2 x 420 = 1140 s of network calls, then the scans; the budget
# (GATE_BUDGET, or --budget) cuts the total.
RESOLVE_DEADLINE=60
CURL_DEADLINE=180
CURL_ATTEMPT=60
DB_DEADLINE=420
SCAN_DEADLINE=600
GATE_BUDGET=1500
# `timeout --kill-after`: a child that ignores SIGTERM is killed this long after.
KILL_AFTER=2
# On a signal, how long the gate waits for its child before killing it. With
# KILL_AFTER, well under the runner's 7.5 s between SIGINT and SIGTERM.
SIGNAL_GRACE=3

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IGNORE_FILE="${YUZU_TRIVYIGNORE:-$ROOT/.trivyignore.yaml}"
CHECKS=(python3 -I "$ROOT/scripts/ci/image-vuln-gate-checks.py")
NOT_COVERED="$ROOT/scripts/ci/image-vuln-gate-not-covered.txt"

# Keep the one TRIVY_* variable this script reads, then clear every other one:
# Trivy maps every flag to a TRIVY_* variable (TRIVY_DB_REPOSITORY,
# TRIVY_SEVERITY, TRIVY_IGNOREFILE, TRIVY_CACHE_DIR, TRIVY_INSECURE, ...), and
# none of that may change what the gate scans or with which DB.
trivy_bin_env="${TRIVY_BIN:-}"
inherited_cache="${TRIVY_CACHE_DIR:-}"
while IFS= read -r v; do unset "$v"; done < <(compgen -e | grep '^TRIVY_' || true)
# Test hook (no network): the DB digest to pin. Only with TRIVY_BIN, which is
# itself refused on GitHub Actions below.
test_db_digest="${YUZU_GATE_TEST_DB_DIGEST:-}"
unset YUZU_GATE_TEST_DB_DIGEST

err() {
    if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error::$*"; else echo "ERROR: $*" >&2; fi
}

usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2; exit 2; }

REPORT_DIR=""
RELEASE=0
ATTEMPT=""
BUDGET_ARG=""
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --report-dir) [ $# -ge 2 ] || usage; REPORT_DIR="$2"; shift ;;
        --attempt) [ $# -ge 2 ] || usage; ATTEMPT="$2"; shift ;;
        --budget) [ $# -ge 2 ] || usage; BUDGET_ARG="$2"; shift ;;
        --release) RELEASE=1 ;;
        -h|--help) usage ;;
        --) shift; ARGS+=("$@"); break ;;
        -*) err "unknown option: $1"; usage ;;
        *) ARGS+=("$1") ;;
    esac
    shift
done
[ "${#ARGS[@]}" -gt 0 ] || usage
if [ -n "$ATTEMPT" ]; then
    [[ "$ATTEMPT" =~ ^[1-9][0-9]{0,3}$ ]] || { err "--attempt must be a run attempt number (1-9999)"; exit 2; }
    [ -n "$REPORT_DIR" ] || { err "--attempt names the reports, so it needs --report-dir"; exit 2; }
fi
if [ -n "$BUDGET_ARG" ]; then
    if ! [[ "$BUDGET_ARG" =~ ^[1-9][0-9]{0,3}$ ]] || [ "$BUDGET_ARG" -gt 3600 ]; then
        err "--budget must be a number of seconds (1-3600)"
        exit 2
    fi
    GATE_BUDGET="$BUDGET_ARG"
fi
# The budget's end, on bash's SECONDS clock (seconds since the script started).
GATE_DEADLINE=$((SECONDS + GATE_BUDGET))
# The reports' file stem for image NAME: trivy-NAME, or trivy-NAME.attempt-N.
ATTEMPT_SUFFIX="${ATTEMPT:+.attempt-$ATTEMPT}"

# ── Names first, so every exit path below can write each image's report ──────
NAMES=()
REFS=()
declare -A seen_names=()
for arg in "${ARGS[@]}"; do
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
    NAMES+=("$name")
    REFS+=("$image")
done
if [ -n "$REPORT_DIR" ]; then
    mkdir -p "$REPORT_DIR" || { err "cannot create report directory $REPORT_DIR"; exit 1; }
fi

summary() {
    [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
    printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY" || true
}
SUMMARY_HEADER=0
summary_header() {
    [ "$SUMMARY_HEADER" = 0 ] || return 0
    SUMMARY_HEADER=1
    summary "### Image vulnerability gate (Trivy ${TRIVY_VERSION}, DB ${DB_REF}, UpdatedAt ${db_updated})"
    summary ""
    summary "| Image | OS packages | Coverage | Result |"
    summary "|---|---|---|---|"
}

# Facts recorded in every .gate.txt, filled in as the run gets to them.
MODE="check"; [ "$RELEASE" = 0 ] || MODE="release (pending approvals not honoured)"
DB_REF="(not downloaded)"
db_updated="?"
db_downloaded="?"
ignore_desc="(not validated)"
ABORT_REASON=""
declare -A reported=()

# write_gate_txt NAME IMAGE RESULT [extra lines...]
write_gate_txt() {
    [ -n "$REPORT_DIR" ] || return 0
    local n="$1" img="$2" res="$3"
    shift 3
    {
        echo "image: $n ($img)"
        echo "mode: $MODE"
        [ -z "$ATTEMPT" ] || echo "run attempt: $ATTEMPT"
        echo "trivy: $TRIVY_VERSION"
        echo "trivy db: $DB_REF, UpdatedAt $db_updated, DownloadedAt $db_downloaded"
        [ $# -eq 0 ] || printf '%s\n' "$@"
        echo "ignore file: $ignore_desc"
        echo "gate: $res"
        echo "scanned at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$REPORT_DIR/trivy-${n}${ATTEMPT_SUFFIX}.gate.txt"
    reported[$n]=1
}

die() {
    ABORT_REASON="$*"
    err "$*"
    exit 1
}

WORK=""
CANCELLED=""
# report_unjudged RC: every image that has no report yet gets one recording why
# the gate stopped (a refusal must leave evidence). A cancelled run's reads
# `gate: FAIL: cancelled (SIGINT) ...` or `(SIGTERM)`.
# shellcheck disable=SC2317 # run by on_signal and finish (traps)
report_unjudged() {
    local rc="$1" i res
    for i in "${!NAMES[@]}"; do
        if [ -z "${reported[${NAMES[$i]}]:-}" ]; then
            if [ -n "$CANCELLED" ]; then
                res="FAIL: cancelled ($CANCELLED) before this image was judged"
            else
                res="FAIL: gate stopped before this image was judged: ${ABORT_REASON:-unexpected error (exit $rc)}"
            fi
            write_gate_txt "${NAMES[$i]}" "${REFS[$i]}" "$res" || true
            summary_header
            summary "| ${NAMES[$i]} | ? | ? | ${res} |"
        fi
    done
}
# The long-running child (Trivy, curl, the digest lookup), run through `child`
# so a SIGTERM/SIGINT is handled at once (bash runs a trap only after a
# FOREGROUND child exits, but interrupts `wait` for one), and under `timeout`:
#   child DEADLINE CMD...  runs CMD for at most DEADLINE seconds, or what is
#   left of the gate's budget if that is less. When the budget is gone the
#   gate stops (die), whatever CMD returned.
CHILD=""
child() {
    local limit="$1" left rc=0
    shift
    left=$((GATE_DEADLINE - SECONDS))
    [ "$left" -gt 0 ] || die "the gate ran out of its ${GATE_BUDGET}s budget"
    [ "$limit" -le "$left" ] || limit="$left"
    timeout --kill-after="$KILL_AFTER" "$limit" "$@" &
    CHILD=$!
    wait "$CHILD" || rc=$?
    CHILD=""
    [ "$SECONDS" -lt "$GATE_DEADLINE" ] || die "the gate ran out of its ${GATE_BUDGET}s budget"
    return "$rc"
}
# shellcheck disable=SC2317 # run by the TERM/INT traps
on_signal() {
    # Ignore the runner's second signal (SIGTERM ~7.5 s after its SIGINT): a
    # default-action signal here would kill bash before the report is written.
    trap '' TERM INT
    CANCELLED="$1"
    ABORT_REASON="cancelled ($1)"
    # The report first, before any wait.
    report_unjudged "$2"
    if [ -n "$CHILD" ]; then
        # `timeout` passes the SIGTERM on to its command and SIGKILLs it
        # KILL_AFTER seconds later; the gate waits SIGNAL_GRACE at most, then
        # SIGKILLs `timeout` itself.
        kill -TERM "$CHILD" 2>/dev/null || true
        local waited=0
        while kill -0 "$CHILD" 2>/dev/null && [ "$waited" -lt $((SIGNAL_GRACE * 10)) ]; do
            sleep 0.1
            waited=$((waited + 1))
        done
        kill -KILL "$CHILD" 2>/dev/null || true
        wait "$CHILD" 2>/dev/null || true
    fi
    exit "$2"
}
trap 'on_signal SIGTERM 143' TERM
trap 'on_signal SIGINT 130' INT
# shellcheck disable=SC2317 # run by the EXIT trap
finish() {
    local rc=$?
    [ "$rc" -eq 0 ] || report_unjudged "$rc"
    [ -z "$WORK" ] || rm -rf "$WORK"
    exit "$rc"
}
trap finish EXIT

if [ -n "$trivy_bin_env" ] && [ -n "${GITHUB_ACTIONS:-}" ]; then
    die "TRIVY_BIN is for local runs and tests; the gate on GitHub Actions installs its pinned Trivy itself"
fi
if [ -n "$test_db_digest" ] && [ -z "$trivy_bin_env" ]; then
    die "YUZU_GATE_TEST_DB_DIGEST is a test hook and needs TRIVY_BIN"
fi
if [ -n "$inherited_cache" ]; then
    echo "note: TRIVY_CACHE_DIR=$inherited_cache is ignored; the gate downloads its DB into a fresh directory"
fi

WORK="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/yuzu-image-vuln-gate.XXXXXX")"

# ── The ignore file: present, every entry well formed, and only that read ────
# Trivy itself accepts an entry with no reason, no expiry and no scope, so this
# is the only place that keeps an acceptance from becoming permanent,
# unexplained, unapproved or wider than one package. It is parsed, not
# grepped: a flow-style entry or a decoy line inside a statement cannot pass.
# Trivy then reads the checker's canonical copy of the entries in force (an
# expired entry, and with --release a pending one, are left out), always as
# YAML: a plain-format file or an entry the parser did not see cannot reach it.
if [ ! -r "$IGNORE_FILE" ]; then
    die "ignore file $IGNORE_FILE is missing or unreadable (the gate does not run without it)"
fi
ign_flags=(--emit "$WORK/trivyignore.yaml")
nc_flags=()
if [ "$RELEASE" = 1 ]; then ign_flags+=(--require-approved); nc_flags+=(--require-approved); fi
if ! ign_out="$("${CHECKS[@]}" ignore-file "$IGNORE_FILE" "${ign_flags[@]}")"; then
    printf '%s\n' "$ign_out"
    die "$IGNORE_FILE is not in the shape the gate accepts (above): every entry needs a concrete \`paths\` item (a path inside the image, with a '/', not a Trivy target name such as Python) or a full versioned \`purls\` item, a statement, an expired_at at most 92 days out, approved_by, and approved_on with approval_ref (or approval_ref: pending)"
fi
printf '%s\n' "$ign_out" | grep -v -E '^(in_force|pending|pending_not_honoured)=' || true
in_force="$(printf '%s\n' "$ign_out" | sed -n 's/^in_force=//p')"
pending_all="$(printf '%s\n' "$ign_out" | sed -n 's/^pending=//p')"
pending_out="$(printf '%s\n' "$ign_out" | sed -n 's/^pending_not_honoured=//p')"
ignore_desc="$(sha256sum "$IGNORE_FILE" | cut -d' ' -f1), ${in_force} entry(ies) in force, ${pending_all} pending approval (${pending_out} not honoured)"
TRIVY_IGNORE="$WORK/trivyignore.yaml"
if ! nc_out="$("${CHECKS[@]}" not-covered "$NOT_COVERED" "${nc_flags[@]}")"; then
    die "$NOT_COVERED is malformed (above)"
fi
printf '%s\n' "$nc_out"

# ── Trivy ────────────────────────────────────────────────────────────────────
if [ -n "$trivy_bin_env" ]; then
    TRIVY="$trivy_bin_env"
else
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64)          asset="Linux-64bit"; want="$TRIVY_SHA256_LINUX_64BIT" ;;
        Linux/aarch64|Linux/arm64) asset="Linux-ARM64"; want="$TRIVY_SHA256_LINUX_ARM64" ;;
        *) die "no pinned Trivy for $(uname -s)/$(uname -m); set TRIVY_BIN" ;;
    esac
    tgz="trivy_${TRIVY_VERSION}_${asset}.tar.gz"
    url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${tgz}"
    child "$CURL_DEADLINE" curl -fsSL --retry 3 --retry-delay 5 --max-time "$CURL_ATTEMPT" -o "$WORK/$tgz" "$url" \
        || die "could not download $url (within ${CURL_DEADLINE}s)"
    echo "${want}  $WORK/$tgz" | sha256sum -c --quiet - \
        || die "$tgz does not match its pinned sha256; refusing to run it"
    tar -xzf "$WORK/$tgz" -C "$WORK" trivy
    TRIVY="$WORK/trivy"
fi
"$TRIVY" --version 2>/dev/null | grep -qx "Version: ${TRIVY_VERSION}" \
    || die "$TRIVY is not Trivy ${TRIVY_VERSION}"

# The DB and layer cache: always a fresh, empty directory of this run.
CACHE="$WORK/cache"
mkdir "$CACHE"
# Trivy's own temporary files (image layers it extracts) go under WORK too, so
# a killed run leaves nothing in the shared /tmp (the trap removes WORK).
mkdir -p "$WORK/tmp"
export TMPDIR="$WORK/tmp"
: > "$WORK/trivy.yaml"
# Every Trivy call: the empty config and this run's cache.
COMMON=(--config "$WORK/trivy.yaml" --cache-dir "$CACHE")
# Each scan: Trivy's own timeout (its default is 5 minutes), just inside the
# `timeout` the gate runs it under, so Trivy normally reports it itself.
SCAN_TIMEOUT=(--timeout "$((SCAN_DEADLINE - 10))s")

# ── The DB: once per run, pinned by digest, and fresh ────────────────────────
# Each source's tag is resolved to its manifest digest and the download pinned
# to repository@digest (Trivy verifies the manifest and layers against it), so
# the digest recorded in every report is the DB that was used. Every scan below
# then runs with --skip-db-update, so all images are judged against that DB,
# whose age and download time are checked first.
echo "==> Trivy ${TRIVY_VERSION}: vulnerability DB"
start_epoch="$(date +%s)"
for repo in "${DB_REPOS[@]}"; do
    if [ -n "$test_db_digest" ]; then
        digest="$test_db_digest"
    elif child $((RESOLVE_DEADLINE + 5)) "${CHECKS[@]}" resolve-digest "$repo:$DB_TAG" \
            --deadline "$RESOLVE_DEADLINE" > "$WORK/digest"; then
        digest="$(cat "$WORK/digest")"
    else
        echo "    could not resolve $repo:$DB_TAG within ${RESOLVE_DEADLINE}s; trying the next source"
        continue
    fi
    if ! [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        echo "    $repo:$DB_TAG resolved to '$digest', not a digest; trying the next source"
        continue
    fi
    echo "    $repo:$DB_TAG is $digest"
    if child "$DB_DEADLINE" "$TRIVY" image "${COMMON[@]}" --db-repository "$repo@$digest" --download-db-only; then
        DB_REF="$repo@$digest"
        break
    fi
    rm -rf "${CACHE:?}/db"
done
[ "$DB_REF" != "(not downloaded)" ] || die "could not download the Trivy vulnerability DB from any source (treated as a failure)"
if ! db_info="$("${CHECKS[@]}" db-age "$CACHE/db/metadata.json" --downloaded-after "$start_epoch")"; then
    die "the Trivy vulnerability DB is stale, unreadable or not this run's download (above); re-run once the published DB is current"
fi
printf '%s\n' "$db_info" | sed 's/^/    /'
db_updated="$(printf '%s\n' "$db_info" | sed -n 's/^trivy_db_updated_at=//p')"
db_downloaded="$(printf '%s\n' "$db_info" | sed -n 's/^trivy_db_downloaded_at=//p')"

summary_header

# advisory_canary FAMILY OS_NAME: returns 0 when this run's DB holds advisories
# for that OS release, and sets ADVISORY to a one-line description. Each
# (family, release) is checked once per run. Not called in a subshell: it
# caches its result.
declare -A canary_result=()
canary_n=0
ADVISORY=""
advisory_canary() {
    local key="$1 $2" dir out msg
    if [ -z "${canary_result[$key]:-}" ]; then
        canary_n=$((canary_n + 1))
        dir="$WORK/canary-$canary_n"
        out="$WORK/canary-$canary_n.json"
        if "${CHECKS[@]}" canary-rootfs "$dir" "$1" "$2" \
            && child "$SCAN_DEADLINE" "$TRIVY" rootfs "${COMMON[@]}" "${SCAN_TIMEOUT[@]}" --quiet --skip-db-update --scanners vuln \
                --format json --output "$out" "$dir" \
            && msg="$("${CHECKS[@]}" canary-check "$out" "$1" "$2")"; then
            canary_result[$key]="ok|$1 $2: $(printf '%s\n' "$msg" | sed -n 's/^canary_advisories=//p') advisories matched by the canary"
        else
            canary_result[$key]="fail|$1 $2: the DB holds no advisory data for it (canary matched nothing or could not run)"
        fi
    fi
    ADVISORY="${canary_result[$key]#*|}"
    [ "${canary_result[$key]%%|*}" = ok ]
}

# ── Scan ─────────────────────────────────────────────────────────────────────
failed=0
for idx in "${!NAMES[@]}"; do
    name="${NAMES[$idx]}"
    image="${REFS[$idx]}"
    echo "==> $name: $image"
    stem="trivy-${name}${ATTEMPT_SUFFIX}"
    json="$WORK/${stem}.json"
    table="$WORK/${stem}.txt"
    result="FAIL"
    coverage="unknown"
    os_packages="?"
    os_desc="?"
    advisory="not checked"

    # The record: HIGH and CRITICAL, fixed or not, and the accepted findings
    # (--show-suppressed), as JSON, which also lists every package (that is
    # what the coverage check counts). Not --quiet: Trivy's log names the OS
    # it detected and warns when it finds no OS package. Informational, but a
    # scan that cannot complete is a failure, not an empty report. The table
    # names --scanners vuln: without it Trivy 0.70.0's `convert` writes a
    # 0-byte table for a clean report (no findings, or no Results), and an
    # empty table is refused here, before any push, so a published attempt's
    # three reports are never empty (scripts/check-release-artifacts.sh
    # requires that; G8P5-unhappy-path-1).
    if ! child "$SCAN_DEADLINE" "$TRIVY" image "${COMMON[@]}" "${SCAN_TIMEOUT[@]}" --skip-db-update --image-src docker --scanners vuln \
            --severity HIGH,CRITICAL --show-suppressed --ignorefile "$TRIVY_IGNORE" \
            --format json --output "$json" "$image" \
        || ! child "$SCAN_DEADLINE" "$TRIVY" convert --quiet --format table --scanners vuln --severity HIGH,CRITICAL \
            --show-suppressed --output "$table" "$json" \
        || [ ! -s "$table" ]; then
        err "$image: Trivy could not scan the image (treated as a failure)"
        failed=1
        summary "| $name | ? | ? | could not scan |"
        [ -z "$REPORT_DIR" ] || [ ! -s "$json" ] || cp "$json" "$REPORT_DIR/"
        write_gate_txt "$name" "$image" "FAIL: Trivy could not scan the image"
        reported[$name]=1
        continue
    fi
    cat "$table"

    # Coverage (Trivy's JSON report, explicitly): an image whose OS packages
    # Trivy could not see was not scanned, and one whose OS release has no
    # advisory data was not judged.
    cov_ok=0
    cov="$("${CHECKS[@]}" coverage "$json" "$name" "$NOT_COVERED" "${nc_flags[@]}")" && cov_rc=0 || cov_rc=$?
    verdict="$(printf '%s\n' "$cov" | sed -n 's/^verdict=//p')"
    os_packages="$(printf '%s\n' "$cov" | sed -n 's/^os_packages=//p')"
    os_desc="$(printf '%s\n' "$cov" | sed -n 's/^os=//p')"
    os_family="$(printf '%s\n' "$cov" | sed -n 's/^os_family=//p')"
    os_name="$(printf '%s\n' "$cov" | sed -n 's/^os_name=//p')"
    printf '%s\n' "$cov" | grep '^warning:' || true
    if [ "$cov_rc" = 0 ]; then
        coverage="$(printf '%s\n' "$cov" | sed -n 's/^coverage=//p')"
        echo "    OS: $os_desc, $os_packages OS packages scanned"
        if [ "$coverage" = "not-covered" ]; then
            reason="$(printf '%s\n' "$cov" | sed -n 's/^reason=//p')"
            echo "    NOT COVERED by OS package scanning (listed in scripts/ci/image-vuln-gate-not-covered.txt): $reason"
            [ -z "${GITHUB_ACTIONS:-}" ] || echo "::warning::$name: OS packages NOT scanned (Trivy sees none; listed as not covered)"
            advisory="n/a (OS packages not scanned)"
            cov_ok=1
        elif advisory_canary "$os_family" "$os_name"; then
            advisory="$ADVISORY"
            echo "    advisory data: $advisory"
            cov_ok=1
        else
            advisory="$ADVISORY"
            err "$image: $advisory"
            coverage="covered, NO ADVISORY DATA"
            verdict="no-advisory-data"
        fi
    else
        err "$image: OS packages not scanned, or no advisory data for its OS (above)"
        coverage="$verdict"
    fi
    [ "$cov_ok" = 1 ] || failed=1

    # The gate. Exit code 3 means findings; anything else non-zero is a Trivy
    # error, which must not read as a pass either.
    rc=0
    child "$SCAN_DEADLINE" "$TRIVY" image "${COMMON[@]}" "${SCAN_TIMEOUT[@]}" --quiet --skip-db-update --image-src docker --scanners vuln \
        --severity CRITICAL --ignore-unfixed --ignorefile "$TRIVY_IGNORE" \
        --exit-code 3 --format table "$image" || rc=$?
    case "$rc" in
        0) if [ "$cov_ok" = 1 ]; then
               result="pass"
               echo "    pass: no fixable CRITICAL vulnerability"
           else
               case "$verdict" in
                   eosl) result="FAIL: OS release is end of service life" ;;
                   pre-release) result="FAIL: no advisory data for a pre-release OS release" ;;
                   unsupported-os|no-advisory-data) result="FAIL: no advisory data for the OS release" ;;
                   *) result="FAIL: OS packages not scanned" ;;
               esac
           fi ;;
        3) err "$image has a fixable CRITICAL vulnerability (table above). Rebuild on current packages, or accept it in .trivyignore.yaml with a scope, a statement, an expiry and an approval."
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
        write_gate_txt "$name" "$image" "$result" \
            "image id: $image_id" \
            "os: $os_desc" \
            "os packages scanned: $os_packages" \
            "coverage: $coverage" \
            "advisory data: $advisory"
    fi
    reported[$name]=1
done

exit "$failed"
