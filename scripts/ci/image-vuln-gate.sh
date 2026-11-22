#!/usr/bin/env bash
# Image vulnerability gate (WP15/S9).
#
# Scans each container image with two pinned scanners, Trivy and grype, and
# FAILS when either reports a CRITICAL vulnerability that has a fix available
# and is not accepted in that scanner's acceptance file (.trivyignore.yaml,
# .grypeignore.yaml). It also prints (and optionally saves) each scanner's
# table for the record (Trivy: HIGH and CRITICAL; grype: every severity);
# findings below CRITICAL, and CRITICALs without a fix, do not fail the gate.
#
# Why two: they catalogue different things. Trivy does not identify the
# Erlang/OTP runtime the gateway image bundles (its ERTS), so OTP CVEs never
# reach its report; grype matches it from beam.smp's version string. A
# finding from EITHER fails the image. grype scans a `docker save` of the
# image's local ID (`docker-archive:`), never `docker:`, because grype's
# docker source asks the daemon to PULL an image it does not have, which
# would scan and pass a same-named image from a registry.
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
#     writes holding only the entries in force;
#   - .grypeignore.yaml is not in the same strict shape (scope: grype's
#     package name AND version, optionally its type; the same statement,
#     expiry and approval rules). grype never reads it either: it reads a
#     generated config holding only the `ignore:` rules in force (`-c`, which
#     also stops grype reading a .grype.yaml from its working directory);
#   - the grype DB: its listing (latest.json) is fetched ONCE per run, the
#     archive it names is downloaded into a fresh directory, its sha256 is
#     checked against the listing, and grype imports it; the gate fails when
#     the listed or imported DB is older than 72 hours, its age cannot be
#     read, or grype's status of the imported DB is not the listed one. Every
#     grype scan runs with DB updates off and grype's own age check on. The
#     listing is NOT signed upstream: TLS to its host and the recorded
#     checksum are the only evidence of which DB was used;
#   - a grype DB provider the images need (nvd for every image, and each
#     image's OS family's: alpine, debian, ubuntu) is missing, or its capture
#     time is unreadable, in the future or older than 72 hours. A reviewed
#     provider waiver in .grypeignore.yaml (`provider_waivers:`, one per
#     provider, at most 14 days out) admits that provider's capture when it
#     is ONLY older than 72 hours, and nothing else: never a missing
#     provider, a bad capture time, the DB's own age, checksum or status, a
#     finding, a component or coverage failure. An image judged with one
#     passes DEGRADED: its grype .gate.txt names the waiver (`provider
#     waiver: ...` and a `DEGRADED: ...` line) and the step summary says so.
#     No flag, input or variable enables one on GitHub Actions: only the
#     committed file does (YUZU_GRYPEIGNORE is pinned to it there);
#   - grype did not detect the OS that Trivy did, on an image whose OS
#     packages Trivy scanned: grype then matches none of them.
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
# result); and grype-NAME.json (grype's report: every match, every severity,
# and the accepted ones as ignoredMatches), grype-NAME.txt (its table) and
# grype-NAME.gate.txt (grype version, the DB's URL, checksum, schema and build
# time, the provider waivers used or `provider waiver: none used`, image ID,
# distro, match counts, the ignore file and grype's result).
# A .gate.txt of EACH scanner is written for every image on every exit the
# script reaches after reading its arguments, including a SIGTERM/SIGINT
# (`gate: FAIL: cancelled ...`), with `gate: FAIL: <reason>` when the gate
# refused it or stopped early, so a refusal leaves evidence too. SIGKILL, and
# a usage error before the image list is read, leave none.
#
# --attempt N (release.yml passes the workflow's run attempt) names the reports
# trivy-NAME.attempt-N.{json,txt,gate.txt} and grype-NAME.attempt-N.{json,txt,
# gate.txt} and records the attempt, so a re-run's reports sit beside the
# earlier attempts' and never replace them.
#
# Environment: every TRIVY_* and GRYPE_* variable is cleared, so the
# environment cannot change the DB source, the cache, the severities or what
# is ignored; Trivy also gets an empty config file, so a trivy.yaml in the
# working directory is not read, and grype runs with only the generated config
# (`-c`), in a working directory and HOME of this run. Inputs that remain, for
# local runs and tests only:
#   TRIVY_BIN        use this trivy binary instead of installing the pinned one.
#                    It must be TRIVY_VERSION. Refused on GitHub Actions.
#   GRYPE_BIN        the same for grype; it must be GRYPE_VERSION. Refused on
#                    GitHub Actions.
#   YUZU_TRIVYIGNORE ignore file to validate (default: <repo>/.trivyignore.yaml).
#                    It goes through the same parser; Trivy reads only the
#                    checker's canonical YAML copy of it. On GitHub Actions it
#                    may name only the repository's file.
#   YUZU_GRYPEIGNORE grype acceptance file to validate (default:
#                    <repo>/.grypeignore.yaml); grype reads only the config
#                    generated from it. On GitHub Actions it may name only the
#                    repository's file (so it cannot supply a provider waiver).
# The pinned binaries, both DBs, the image archive grype reads and the
# scanners' temporary files live in a per-run directory ($RUNNER_TEMP, else
# $TMPDIR), never a fixed shared path: the self-hosted pools run four runners
# as ONE OS identity (#1871).
#
# Time budget. Every long-running call runs under `timeout`, bounded by its
# own deadline AND by what is left of the gate's overall budget (--budget,
# default GATE_BUDGET = 1500 s, 25 minutes): the digest lookup RESOLVE_DEADLINE
# per DB source, the whole Trivy and grype downloads (every curl retry
# included) CURL_DEADLINE each, each Trivy DB download DB_DEADLINE per source,
# the grype DB listing RESOLVE_DEADLINE, its archive DB_DEADLINE and its import
# IMPORT_DEADLINE, each `docker image inspect` RESOLVE_DEADLINE, each `docker
# save` SAVE_DEADLINE, each scan SCAN_DEADLINE. When the budget runs out the gate stops itself, writes
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
# Exit status: 0 every image passed both scanners; 1 a fixable CRITICAL was
# found by either, a scan failed, a DB was stale or unpinnable, an image was
# not covered or has no advisory data, grype did not detect the OS, the budget
# ran out, or the setup failed (fail closed: a scan that did not complete is
# never a pass); 2 usage error; 130/143 cancelled by SIGINT/SIGTERM.
set -euo pipefail

# Pinned Trivy. The sha256 values are from trivy_0.70.0_checksums.txt; the
# checksums file and the Linux-64bit tarball were verified with
# `cosign verify-blob` against their .sigstore.json bundles (issuer
# token.actions.githubusercontent.com, identity github.com/aquasecurity/trivy)
# on 2026-11-17. Bump all three together, and re-verify the signatures.
TRIVY_VERSION="0.70.0"
TRIVY_SHA256_LINUX_64BIT="8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9"
TRIVY_SHA256_LINUX_ARM64="2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d"

# Pinned grype (published 2026-11-09; the newest release at least seven days
# old when pinned, the repository's Dependabot cooldown). The sha256 values are
# from grype_0.121.3_checksums.txt, whose signature was verified on 2026-11-20
# with `cosign verify-blob --bundle grype_0.121.3_checksums.txt.sigstore.json`
# (issuer token.actions.githubusercontent.com, identity
# https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main),
# and both tarballs matched it. Bump all three together, and re-verify.
GRYPE_VERSION="0.121.3"
GRYPE_SHA256_LINUX_AMD64="e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85"
GRYPE_SHA256_LINUX_ARM64="b7815598d48da78bfd16f5b98ef28e1bb09c03d34fc8c3e350f99b6ccb3c7cba"
# grype's DB: grype 0.121.3's default v6 listing, named explicitly. The listing
# names one archive and its sha256; the gate downloads that archive itself and
# checks it before grype imports it, so grype never fetches a DB on its own.
GRYPE_DB_URL="https://grype.anchore.io/databases/v6"
# The DB providers whose freshness the gate requires. NVD, for every run: it
# supplies the matches for binaries grype identifies by version, the gateway's
# Erlang/OTP runtime among them. Each image's OS family's provider (alpine,
# debian, ubuntu: the canary families), checked per image, so a lagging
# provider refuses only the images on that OS.
GRYPE_REQUIRED_PROVIDERS=(nvd)
# Components grype must catalogue in an image (NAME=component...): the reason
# grype runs at all. Trivy does not see the gateway's Erlang/OTP runtime, and
# grype's JSON lists only matches, so without this a runtime grype stopped
# recognising would read as clean.
# Each entry is component=version: grype must report that exact version, so a
# version it misreads (an ERTS version, a truncated one) refuses the image
# instead of being matched against the wrong advisories. The version is the OTP
# each gateway Dockerfile pins (tests/test_image_vuln_gate.py checks they
# agree, so a builder bump updates this table and re-runs the real gate). Both
# gateway images were checked to catalogue erlang 28.5.0.8 (from the bundled
# ERTS's beam.smp) with grype 0.121.3 on 2026-11-20.
declare -A GRYPE_REQUIRED_COMPONENTS=(
    [yuzu-gateway]="erlang=28.5.0.8"
    [yuzu-gateway-chisel]="erlang=28.5.0.8"
)

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
IMPORT_DEADLINE=300
SAVE_DEADLINE=600
SCAN_DEADLINE=600
GATE_BUDGET=1500
# `timeout --kill-after`: a child that ignores SIGTERM is killed this long after.
KILL_AFTER=2
# On a signal, how long the gate waits for its child before killing it. With
# KILL_AFTER, well under the runner's 7.5 s between SIGINT and SIGTERM.
SIGNAL_GRACE=3

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IGNORE_FILE="${YUZU_TRIVYIGNORE:-$ROOT/.trivyignore.yaml}"
trivy_ignore_env="${YUZU_TRIVYIGNORE:-}"
CHECKS=(python3 -I "$ROOT/scripts/ci/image-vuln-gate-checks.py")
NOT_COVERED="$ROOT/scripts/ci/image-vuln-gate-not-covered.txt"
GRYPE_IGNORE_FILE="${YUZU_GRYPEIGNORE:-$ROOT/.grypeignore.yaml}"
grype_ignore_env="${YUZU_GRYPEIGNORE:-}"

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
# The same for grype: GRYPE_BIN is kept, every other GRYPE_* variable cleared
# (grype reads its whole config from the environment too: GRYPE_EXCLUDE,
# GRYPE_IGNORE, GRYPE_ONLY_FIXED, GRYPE_DB_*, ...). Test hook (no network): a
# directory holding latest.json and the archive it names, used instead of
# GRYPE_DB_URL. Only with GRYPE_BIN, which is refused on GitHub Actions below.
grype_bin_env="${GRYPE_BIN:-}"
while IFS= read -r v; do unset "$v"; done < <(compgen -e | grep '^GRYPE_' || true)
test_grype_db_dir="${YUZU_GATE_TEST_GRYPE_DB_DIR:-}"
unset YUZU_GATE_TEST_GRYPE_DB_DIR

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
    summary "### Image vulnerability gate (Trivy ${TRIVY_VERSION}, DB ${DB_REF}, UpdatedAt ${db_updated}; grype ${GRYPE_VERSION}, DB ${GRYPE_DB_REF})"
    summary ""
    if [ "${#GRYPE_DB_WAIVERS[@]}" -gt 0 ]; then
        summary "**DEGRADED: provider waiver in force** for grype DB provider(s) $(waived_desc), older than 72 hours: every image judged while it is in force uses it (each grype .gate.txt names the waiver)."
        summary ""
    fi
    summary "| Image | OS packages | Coverage | Result |"
    summary "|---|---|---|---|"
}

# Facts recorded in every .gate.txt, filled in as the run gets to them.
MODE="check"; [ "$RELEASE" = 0 ] || MODE="release (pending approvals not honoured)"
DB_REF="(not downloaded)"
db_updated="?"
db_downloaded="?"
ignore_desc="(not validated)"
GRYPE_DB_REF="(not downloaded)"
grype_ignore_desc="(not validated)"
# Provider waivers USED (one `waiver: ...` line from the checker each): for the
# providers every image needs (nvd), and for the image being judged (its OS
# family's provider). Each makes that image's grype pass DEGRADED.
GRYPE_DB_WAIVERS=()
IMAGE_WAIVERS=()
declare -A waived_providers=()
UNJUDGED=0
IMAGE_LAPSED=0
# Set once an image found the run-wide waiver lapsed (a run crossing UTC
# midnight on its expiry day), so images reported later say so too.
RUN_LAPSED=0
ABORT_REASON=""
declare -A reported=()
declare -A grype_reported=()

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

# write_grype_gate_txt NAME IMAGE RESULT [extra lines...]: grype's verdict for
# the image, in grype-NAME[.attempt-N].gate.txt.
write_grype_gate_txt() {
    [ -n "$REPORT_DIR" ] || return 0
    local n="$1" img="$2" res="$3"
    shift 3
    {
        echo "image: $n ($img)"
        echo "mode: $MODE"
        [ -z "$ATTEMPT" ] || echo "run attempt: $ATTEMPT"
        echo "grype: $GRYPE_VERSION"
        echo "grype db: $GRYPE_DB_REF"
        waiver_lines
        [ $# -eq 0 ] || printf '%s\n' "$@"
        echo "ignore file: $grype_ignore_desc"
        echo "gate: $res"
        echo "scanned at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$REPORT_DIR/grype-${n}${ATTEMPT_SUFFIX}.gate.txt"
    grype_reported[$n]=1
}

# waiver_lines: the provider waivers used for the image being reported, one
# `provider waiver: ...` line each and a `DEGRADED: ...` line, or a line saying
# none was used. Never a line a `gate:` reader would count.
waiver_lines() {
    local w provs=""
    if [ $((${#GRYPE_DB_WAIVERS[@]} + ${#IMAGE_WAIVERS[@]})) -eq 0 ]; then
        echo "provider waiver: none used"
        return 0
    fi
    if [ "$UNJUDGED" = 1 ]; then
        # The run's waiver was in force (or lapsed), but this image was never judged.
        if [ "$RUN_LAPSED" = 1 ]; then
            echo "provider waiver: lapsed during this run ($(waived_desc run)), and the image was not judged"
        else
            echo "provider waiver: in force for this run ($(waived_desc)), but the image was not judged"
        fi
        return 0
    fi
    if [ "$IMAGE_LAPSED" = 1 ]; then
        # The run-wide (nvd) waiver lapsed before this image was judged: name
        # only that one as lapsed; an OS-provider waiver the image did use is
        # still listed. The image failed, so nothing here says DEGRADED.
        echo "provider waiver: lapsed during this run ($(waived_desc run)), so it did not admit the stale provider for this image"
        for w in "${IMAGE_WAIVERS[@]}"; do
            echo "provider waiver: ${w#waiver: }"
        done
        return 0
    fi
    for w in "${GRYPE_DB_WAIVERS[@]}" "${IMAGE_WAIVERS[@]}"; do
        echo "provider waiver: ${w#waiver: }"
        w="${w#waiver: provider }"
        provs="${provs:+$provs, }${w%% *}"
    done
    echo "DEGRADED: provider waiver in force ($provs): grype judged this image with a DB provider older than 72 hours"
}
# waived_desc [run]: the providers waived for the image being judged (with
# `run`, only the run-wide ones), or empty.
waived_desc() {
    local w provs=""
    local -a ws=("${GRYPE_DB_WAIVERS[@]}")
    [ "${1:-}" = run ] || ws+=("${IMAGE_WAIVERS[@]}")
    for w in "${ws[@]}"; do
        w="${w#waiver: provider }"
        provs="${provs:+$provs, }${w%% *}"
    done
    printf '%s' "$provs"
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
    if [ -n "$CANCELLED" ]; then
        res="FAIL: cancelled ($CANCELLED) before this image was judged"
    else
        res="FAIL: gate stopped before this image was judged: ${ABORT_REASON:-unexpected error (exit $rc)}"
    fi
    UNJUDGED=1
    IMAGE_WAIVERS=()
    IMAGE_LAPSED=0
    for i in "${!NAMES[@]}"; do
        if [ -z "${reported[${NAMES[$i]}]:-}" ]; then
            write_gate_txt "${NAMES[$i]}" "${REFS[$i]}" "$res" || true
            summary_header
            summary "| ${NAMES[$i]} | ? | ? | ${res} |"
        fi
        if [ -z "${grype_reported[${NAMES[$i]}]:-}" ]; then
            write_grype_gate_txt "${NAMES[$i]}" "${REFS[$i]}" "$res" || true
            summary_header
            summary "| ${NAMES[$i]} (grype) | - | - | ${res} |"
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

# A provider waiver (or an acceptance) is honoured only from the committed
# files: on GitHub Actions YUZU_GRYPEIGNORE and YUZU_TRIVYIGNORE may name
# nothing but the repository's own file, and the gate then reads that path,
# never the one given, so no workflow input or variable can supply one. A
# path that cannot be resolved is refused, never let through.
# pin_repo_file VAR VALUE REPO_FILE: refuse VALUE unless it is REPO_FILE.
pin_repo_file() {
    local given want
    [ -n "$2" ] || return 0
    given="$(realpath -m -- "$2" 2>/dev/null)" || given=""
    want="$(realpath -m -- "$3" 2>/dev/null)" || want=""
    if [ -z "$given" ] || [ -z "$want" ] || [ "$given" != "$want" ]; then
        die "$1 is for local runs and tests; on GitHub Actions the gate reads only $3"
    fi
}
if [ -n "${GITHUB_ACTIONS:-}" ]; then
    pin_repo_file YUZU_GRYPEIGNORE "$grype_ignore_env" "$ROOT/.grypeignore.yaml"
    pin_repo_file YUZU_TRIVYIGNORE "$trivy_ignore_env" "$ROOT/.trivyignore.yaml"
    GRYPE_IGNORE_FILE="$ROOT/.grypeignore.yaml"
    IGNORE_FILE="$ROOT/.trivyignore.yaml"
fi
if [ -n "$trivy_bin_env" ] && [ -n "${GITHUB_ACTIONS:-}" ]; then
    die "TRIVY_BIN is for local runs and tests; the gate on GitHub Actions installs its pinned Trivy itself"
fi
if [ -n "$grype_bin_env" ] && [ -n "${GITHUB_ACTIONS:-}" ]; then
    die "GRYPE_BIN is for local runs and tests; the gate on GitHub Actions installs its pinned grype itself"
fi
if [ -n "$test_db_digest" ] && [ -z "$trivy_bin_env" ]; then
    die "YUZU_GATE_TEST_DB_DIGEST is a test hook and needs TRIVY_BIN"
fi
if [ -n "$test_grype_db_dir" ] && [ -z "$grype_bin_env" ]; then
    die "YUZU_GATE_TEST_GRYPE_DB_DIR is a test hook and needs GRYPE_BIN"
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
# grype's acceptance file: the same parser and rules, scoped by package name
# and version; grype reads the generated config of the entries in force.
if [ ! -r "$GRYPE_IGNORE_FILE" ]; then
    die "grype ignore file $GRYPE_IGNORE_FILE is missing or unreadable (the gate does not run without it)"
fi
GRYPE_WAIVERS="$WORK/grype-waivers.json"
gign_flags=(--emit "$WORK/grype-config.yaml" --emit-waivers "$GRYPE_WAIVERS")
[ "$RELEASE" = 0 ] || gign_flags+=(--require-approved)
if ! gign_out="$("${CHECKS[@]}" grype-ignore-file "$GRYPE_IGNORE_FILE" "${gign_flags[@]}")"; then
    printf '%s\n' "$gign_out"
    die "$GRYPE_IGNORE_FILE is not in the shape the gate accepts (above): every entry needs a package_name and a package_version (grype's, exact; package_type optional), a statement, an expired_at at most 92 days out, approved_by, and approved_on with approval_ref (or approval_ref: pending); every provider waiver a provider (nvd, alpine, debian or ubuntu, once each), a statement, an expired_at at most 14 days out and not passed, and the same approval fields"
fi
printf '%s\n' "$gign_out" | grep -v -E '^(in_force|pending|pending_not_honoured|waivers_in_force|waivers_pending|waivers_pending_not_honoured)=' || true
g_in_force="$(printf '%s\n' "$gign_out" | sed -n 's/^in_force=//p')"
g_pending_all="$(printf '%s\n' "$gign_out" | sed -n 's/^pending=//p')"
g_pending_out="$(printf '%s\n' "$gign_out" | sed -n 's/^pending_not_honoured=//p')"
g_waivers="$(printf '%s\n' "$gign_out" | sed -n 's/^waivers_in_force=//p')"
g_waivers_out="$(printf '%s\n' "$gign_out" | sed -n 's/^waivers_pending_not_honoured=//p')"
g_waivers_pend="$(printf '%s\n' "$gign_out" | sed -n 's/^waivers_pending=//p')"
grype_ignore_desc="$(sha256sum "$GRYPE_IGNORE_FILE" | cut -d' ' -f1), ${g_in_force} entry(ies) in force, ${g_pending_all} pending approval (${g_pending_out} not honoured), ${g_waivers} provider waiver(s) in force, ${g_waivers_pend} pending approval (${g_waivers_out} not honoured)"
GRYPE_CONFIG="$WORK/grype-config.yaml"
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

# ── grype ────────────────────────────────────────────────────────────────────
if [ -n "$grype_bin_env" ]; then
    GRYPE="$grype_bin_env"
else
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64)              garch="amd64"; want="$GRYPE_SHA256_LINUX_AMD64" ;;
        Linux/aarch64|Linux/arm64) garch="arm64"; want="$GRYPE_SHA256_LINUX_ARM64" ;;
        *) die "no pinned grype for $(uname -s)/$(uname -m); set GRYPE_BIN" ;;
    esac
    gtgz="grype_${GRYPE_VERSION}_linux_${garch}.tar.gz"
    url="https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/${gtgz}"
    child "$CURL_DEADLINE" curl -fsSL --proto '=https' --retry 3 --retry-delay 5 --max-time "$CURL_ATTEMPT" \
        -o "$WORK/$gtgz" "$url" \
        || die "could not download $url (within ${CURL_DEADLINE}s)"
    echo "${want}  $WORK/$gtgz" | sha256sum -c --quiet - \
        || die "$gtgz does not match its pinned sha256; refusing to run it"
    mkdir "$WORK/grype-bin"
    tar -xzf "$WORK/$gtgz" -C "$WORK/grype-bin" grype
    GRYPE="$WORK/grype-bin/grype"
fi
# grype's own state: this run's DB directory, a HOME and working directory of
# this run (so no user or project grype config is found), and no network of
# its own (no DB update, no update check). Its age check stays on as well.
GRYPE_DB_CACHE="$WORK/grype-db"
GRYPE_HOME="$WORK/grype-home"
mkdir -p "$GRYPE_DB_CACHE" "$GRYPE_HOME"
# run_grype DEADLINE ARGS...: grype under `child`, with only the environment
# the gate gives it.
run_grype() {
    local limit="$1"
    shift
    child "$limit" env -C "$GRYPE_HOME" HOME="$GRYPE_HOME" XDG_CONFIG_HOME="$GRYPE_HOME/.config" \
        XDG_CACHE_HOME="$GRYPE_HOME/.cache" GRYPE_DB_CACHE_DIR="$GRYPE_DB_CACHE" GRYPE_DB_AUTO_UPDATE=false \
        GRYPE_DB_VALIDATE_AGE=true GRYPE_DB_MAX_ALLOWED_BUILT_AGE=72h GRYPE_DB_REQUIRE_UPDATE_CHECK=false \
        GRYPE_CHECK_FOR_APP_UPDATE=false "$GRYPE" "$@"
}
run_grype "$RESOLVE_DEADLINE" --version > "$WORK/grype-version" 2>/dev/null || true
grep -qx "grype ${GRYPE_VERSION}" "$WORK/grype-version" || die "$GRYPE is not grype ${GRYPE_VERSION}"

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

# ── The grype DB: once per run, checked against its listing, and fresh ───────
# The listing names one archive and its sha256; the gate downloads that archive
# into this run's directory, checks the sha256, and has grype import it. grype
# then reports the imported DB's build time and schema, which must be the
# listing's, so the DB recorded in every report is the DB grype scanned with.
echo "==> grype ${GRYPE_VERSION}: vulnerability DB"
glisting="$WORK/grype-listing.json"
if [ -n "$test_grype_db_dir" ]; then
    cp "$test_grype_db_dir/latest.json" "$glisting" || die "test hook: no latest.json in $test_grype_db_dir"
else
    child "$RESOLVE_DEADLINE" curl -fsSL --proto '=https' --retry 3 --retry-delay 5 --max-time 30 \
        -o "$glisting" "$GRYPE_DB_URL/latest.json" \
        || die "could not fetch the grype DB listing $GRYPE_DB_URL/latest.json (within ${RESOLVE_DEADLINE}s; treated as a failure)"
fi
if ! glist_info="$("${CHECKS[@]}" grype-db-listing "$glisting")"; then
    die "the grype DB listing is stale, unreadable or not in the shape the gate accepts (above): a stale one, re-run once the published DB is current; a status other than active, the pinned grype's DB schema is retired and grype needs a bump"
fi
gdb_path="$(printf '%s\n' "$glist_info" | sed -n 's/^path=//p')"
gdb_sum="$(printf '%s\n' "$glist_info" | sed -n 's/^checksum=//p')"
gdb_built="$(printf '%s\n' "$glist_info" | sed -n 's/^built=//p')"
gdb_schema="$(printf '%s\n' "$glist_info" | sed -n 's/^schema=//p')"
if [ -n "$test_grype_db_dir" ]; then
    cp "$test_grype_db_dir/$gdb_path" "$WORK/$gdb_path" || die "test hook: no $gdb_path in $test_grype_db_dir"
else
    child "$DB_DEADLINE" curl -fsSL --proto '=https' --retry 3 --retry-delay 5 --max-time "$((DB_DEADLINE - 20))" \
        -o "$WORK/$gdb_path" "$GRYPE_DB_URL/$gdb_path" \
        || die "could not download the grype DB $GRYPE_DB_URL/$gdb_path (within ${DB_DEADLINE}s; treated as a failure)"
fi
echo "${gdb_sum#sha256:}  $WORK/$gdb_path" | sha256sum -c --quiet - \
    || die "the grype DB archive $gdb_path does not match the listing's $gdb_sum; refusing to import it"
run_grype "$IMPORT_DEADLINE" db import "$WORK/$gdb_path" \
    || die "grype could not import the DB $gdb_path (within ${IMPORT_DEADLINE}s; treated as a failure)"
rm -f "$WORK/$gdb_path"
run_grype "$RESOLVE_DEADLINE" db status -o json > "$WORK/grype-db-status.json" 2>"$WORK/grype-db-status.err" || true
if ! gstat="$("${CHECKS[@]}" grype-db-status "$WORK/grype-db-status.json" --built "$gdb_built" --schema "$gdb_schema")"; then
    cat "$WORK/grype-db-status.err" >&2 || true
    die "grype's status of the imported DB is not the DB this run downloaded and verified, or it is stale (above)"
fi
run_grype "$RESOLVE_DEADLINE" db providers -o json > "$WORK/grype-db-providers.json" 2>"$WORK/grype-db-status.err" || true
if ! gprov="$("${CHECKS[@]}" grype-db-providers "$WORK/grype-db-providers.json" --waivers "$GRYPE_WAIVERS" \
        "${GRYPE_REQUIRED_PROVIDERS[@]}")"; then
    cat "$WORK/grype-db-status.err" >&2 || true
    die "a grype DB provider every image needs (${GRYPE_REQUIRED_PROVIDERS[*]}) is missing or older than 72 hours, or the provider waivers could not be read (above): an old one, re-run once the published DB is current, or, when its upstream source is stalled and the release cannot wait, record a reviewed provider waiver in .grypeignore.yaml (docs/ci-architecture.md \"A grype DB provider is stale\"); a missing one, the DB may have renamed it and GRYPE_REQUIRED_PROVIDERS needs updating"
fi
printf '%s\n' "$gprov" | sed 's/^/    /'
mapfile -t GRYPE_DB_WAIVERS < <(printf '%s\n' "$gprov" | grep '^waiver: ' || true)
for w in "${GRYPE_DB_WAIVERS[@]}"; do
    w="${w#waiver: provider }"
    waived_providers[${w%% *}]=1
    [ -z "${GITHUB_ACTIONS:-}" ] || echo "::warning::DEGRADED: provider waiver in force: grype DB provider ${w%% *} is older than 72 hours (every image)"
done
[ "${#GRYPE_DB_WAIVERS[@]}" -eq 0 ] || echo "    DEGRADED: provider waiver in force for $(waived_desc): every image judged while it is in force uses it"
GRYPE_DB_REF="$GRYPE_DB_URL/$gdb_path ($gdb_sum, schema $gdb_schema, built $gdb_built)"
printf '%s\n' "$gstat" | sed 's/^/    /'
echo "    $GRYPE_DB_REF"

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

# grype_scan NAME IMAGE TRIVY_OS_FAMILY: grype's scan of the image, judged
# and reported on its own (grype-NAME[.attempt-N].*). TRIVY_OS_FAMILY is the
# OS family Trivy scanned the OS packages of, or empty when Trivy did not
# (not covered, or no scan): grype must then have detected the same family,
# or it matched none of those packages. Sets failed=1 when grype refuses the
# image or cannot judge it.
ARCHIVE="$WORK/image.tar"
grype_scan() {
    local n="$1" img="$2" want_family="$3" id stem gjson gtable gcdx ginfo gres rc comps="" cinfo="" pinfo=""
    local distro="?" matches="?" ignored="?" fcrit="?" fcrit_acc="?" gid="?"
    stem="grype-${n}${ATTEMPT_SUFFIX}"
    IMAGE_WAIVERS=()
    IMAGE_LAPSED=0
    gjson="$WORK/${stem}.json"
    gtable="$WORK/${stem}.txt"
    gcdx="$WORK/${stem}.cdx.json"
    echo "==> $n: grype"
    # The image's local ID (`docker image inspect` never pulls), then a `docker
    # save` of that ID (never pulls either): what grype reads is the image in
    # this daemon, or nothing.
    # Not in a $( ) subshell: `child` must run in the gate's own shell, so a
    # budget stop or a signal is handled by the gate's traps.
    id=""
    if child "$RESOLVE_DEADLINE" docker image inspect --format '{{.Id}}' "$img" > "$WORK/image-id" 2>/dev/null; then
        id="$(cat "$WORK/image-id")"
    fi
    if ! [[ "$id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        err "$img: grype could not scan: it is not an image in the local Docker daemon (treated as a failure; the gate never pulls)"
        failed=1
        summary "| $n (grype) | - | - | not a local image |"
        write_grype_gate_txt "$n" "$img" "FAIL: not an image in the local Docker daemon"
        grype_reported[$n]=1
        return 0
    fi
    rm -f "$ARCHIVE"
    if ! child "$SAVE_DEADLINE" docker save -o "$ARCHIVE" "$id"; then
        rm -f "$ARCHIVE"
        err "$img: could not export $id for grype (treated as a failure)"
        failed=1
        summary "| $n (grype) | - | - | could not export |"
        write_grype_gate_txt "$n" "$img" "FAIL: could not export the image for grype" "image id: $id"
        grype_reported[$n]=1
        return 0
    fi
    # The record: every severity, fixed or not, and the accepted findings
    # (ignoredMatches), as JSON and as a table, in one scan. Not -q: it would
    # hide grype's error messages too, so stderr is kept and shown on failure.
    if ! run_grype "$SCAN_DEADLINE" -c "$GRYPE_CONFIG" -o "json=$gjson" -o "table=$gtable" -o "cyclonedx-json=$gcdx" \
            "docker-archive:$ARCHIVE" 2>"$WORK/grype.err" \
        || ! ginfo="$("${CHECKS[@]}" grype-report "$gjson")" \
        || [ ! -s "$gtable" ]; then
        cat "$WORK/grype.err" >&2 || true
        rm -f "$ARCHIVE"
        err "$img: grype could not scan the image (treated as a failure)"
        failed=1
        summary "| $n (grype) | - | - | could not scan |"
        [ -z "$REPORT_DIR" ] || [ ! -s "$gjson" ] || cp "$gjson" "$REPORT_DIR/"
        write_grype_gate_txt "$n" "$img" "FAIL: grype could not scan the image" "image id: $id"
        grype_reported[$n]=1
        return 0
    fi
    cat "$gtable"
    distro="$(printf '%s\n' "$ginfo" | sed -n 's/^distro_family=//p')"
    gid="$(printf '%s\n' "$ginfo" | sed -n 's/^image_id=//p')"
    matches="$(printf '%s\n' "$ginfo" | sed -n 's/^matches=//p')"
    ignored="$(printf '%s\n' "$ginfo" | sed -n 's/^ignored=//p')"
    fcrit="$(printf '%s\n' "$ginfo" | sed -n 's/^fixable_critical=//p')"
    fcrit_acc="$(printf '%s\n' "$ginfo" | sed -n 's/^fixable_critical_accepted=//p')"
    local dver
    dver="$(printf '%s\n' "$ginfo" | sed -n 's/^distro_version=//p')"
    # The components grype must have catalogued in this image (see
    # GRYPE_REQUIRED_COMPONENTS), from its CycloneDX output of the same scan.
    comps="${GRYPE_REQUIRED_COMPONENTS[$n]:-}"
    local comps_ok=1 comps_desc="none required"
    if [ -n "$comps" ]; then
        # shellcheck disable=SC2086 # a space-separated list of component names
        if cinfo="$("${CHECKS[@]}" grype-components "$gcdx" $comps 2>"$WORK/grype-components.err")"; then
            comps_desc="$(printf '%s\n' "$cinfo" | sed -n 's/^component_//p' | tr '\n' ' ' | sed 's/=/ /g; s/ $//')"
        else
            comps_ok=0
            cat "$WORK/grype-components.err" >&2 || true
            # Missing, or present at another version: the checker's words say which.
            comps_desc="NOT AS REQUIRED (required: $comps): $(tr '\n' ' ' < "$WORK/grype-components.err" | sed 's/ $//')"
        fi
    fi

    # The gate: only matches with a fix, fail at CRITICAL. grype exits 2 when
    # the threshold is crossed and 1 on an error; anything but 0 and 2 is an
    # error and must not read as a pass.
    rc=0
    run_grype "$SCAN_DEADLINE" -c "$GRYPE_CONFIG" --only-fixed --fail-on critical -o table \
        "docker-archive:$ARCHIVE" 2>"$WORK/grype.err" || rc=$?
    rm -f "$ARCHIVE"
    # A run that started on a run-wide (nvd) waiver re-checks it for each image:
    # it may have lapsed since (a run crossing UTC midnight on its expiry day).
    # A waivers file that cannot be read is told apart from a lapse.
    local recheck="ok"
    if [ "${#GRYPE_DB_WAIVERS[@]}" -gt 0 ] && ! "${CHECKS[@]}" grype-db-providers "$WORK/grype-db-providers.json" \
            --waivers "$GRYPE_WAIVERS" "${GRYPE_REQUIRED_PROVIDERS[@]}" > /dev/null 2>"$WORK/grype-recheck.err"; then
        cat "$WORK/grype-recheck.err" >&2 || true
        if grep -q '^provider waivers .* missing or unreadable' "$WORK/grype-recheck.err"; then
            recheck="unreadable"
        else
            recheck="lapsed"
            IMAGE_LAPSED=1
            RUN_LAPSED=1
        fi
    fi
    case "$rc" in
        0) if [ "$recheck" = lapsed ]; then
               err "$img: the $(waived_desc run) provider waiver lapsed during this run, so the stale provider is not admitted for this image (treated as a failure)"
               gres="FAIL: provider waiver lapsed during the run"
               failed=1
           elif [ "$recheck" = unreadable ]; then
               err "$img: the provider waivers could not be read again for this image (above; treated as a failure)"
               gres="FAIL: provider waivers unreadable"
               failed=1
           elif [ -n "$want_family" ] && ! pinfo="$("${CHECKS[@]}" grype-db-providers "$WORK/grype-db-providers.json" \
                   --waivers "$GRYPE_WAIVERS" "$want_family")"; then
               err "$img: grype's DB provider for $want_family is missing or older than 72 hours, so its $want_family advisories are not current (treated as a failure): an old one, re-run once the published DB is current, or, when its upstream source is stalled and the release cannot wait, record a reviewed provider waiver in .grypeignore.yaml, or renew one that has lapsed (docs/ci-architecture.md \"A grype DB provider is stale\"); a missing one, the DB may have renamed it"
               gres="FAIL: grype DB provider $want_family is stale"
               failed=1
           elif [ "$comps_ok" != 1 ]; then
               err "$img: grype did not catalogue $comps, the component it runs on this image for (above); a grype or base-image change stopped it recognising the runtime (treated as a failure)"
               gres="FAIL: grype did not catalogue $comps as required"
               failed=1
           elif [ "$fcrit" != 0 ]; then
               # The gate scan passed, but the record scan of the same archive
               # lists a fixable CRITICAL that no acceptance covers: the two
               # scans disagree, and a pass must not be published beside it.
               err "$img: grype's gate scan passed but its record lists $fcrit fixable CRITICAL not accepted (treated as a failure)"
               gres="FAIL: grype's record and gate scans disagree"
               failed=1
           elif [ -n "$want_family" ] && [ "$distro" != "$want_family" ]; then
               err "$img: grype did not detect the OS ($want_family): it detected distro '${distro:-none}', so it matched none of the OS packages Trivy scanned (treated as a failure)"
               gres="FAIL: grype did not detect the OS ($want_family)"
               failed=1
           else
               gres="pass"
               echo "    grype pass: no fixable CRITICAL vulnerability"
           fi ;;
        2) err "$img: grype found a fixable CRITICAL vulnerability (table above). Rebuild on current packages or a fixed base, or accept it in .grypeignore.yaml with a package scope, a statement, an expiry and an approval."
           gres="FAIL: fixable CRITICAL"
           failed=1 ;;
        *) cat "$WORK/grype.err" >&2 || true
           err "$img: grype exited $rc during the gate scan (treated as a failure)"
           gres="FAIL: grype exited $rc"
           failed=1 ;;
    esac
    # The image's own provider waiver, when the OS provider check above used one
    # (pinfo holds that check's output; a failed check prints no `waiver:` line).
    mapfile -t IMAGE_WAIVERS < <(printf '%s\n' "$pinfo" | grep '^waiver: ' || true)
    local wdesc w
    wdesc="$(waived_desc)"
    for w in "${IMAGE_WAIVERS[@]}"; do
        [ "$IMAGE_LAPSED" = 0 ] || break
        w="${w#waiver: provider }"
        waived_providers[${w%% *}]=1
        printf '    %s\n' "DEGRADED: provider waiver in force: grype DB provider ${w%% *} is older than 72 hours"
        [ -z "${GITHUB_ACTIONS:-}" ] || echo "::warning::$n: DEGRADED: provider waiver in force: grype DB provider ${w%% *} is older than 72 hours"
    done
    if [ -n "$wdesc" ] && [ "$IMAGE_LAPSED" = 0 ]; then
        summary "| $n (grype) | - | distro ${distro:-none} | $gres (DEGRADED: provider waiver in force: $wdesc) |"
    else
        summary "| $n (grype) | - | distro ${distro:-none} | $gres |"
    fi
    if [ -n "$REPORT_DIR" ]; then
        cp "$gjson" "$gtable" "$REPORT_DIR/"
        write_grype_gate_txt "$n" "$img" "$gres" \
            "image id: $id" \
            "image id (grype): $gid" \
            "distro: ${distro:-none} ${dver}" \
            "matches: $matches not accepted, of them fixable CRITICAL: $fcrit (the gate's verdict is its own scan below)" \
            "accepted (ignoredMatches): $ignored, of them fixable CRITICAL: $fcrit_acc" \
            "required components: $comps_desc"
    fi
    grype_reported[$n]=1
    IMAGE_WAIVERS=()
    IMAGE_LAPSED=0
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
        grype_scan "$name" "$image" ""
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

    # grype, on the same image. The OS-detection cross-check applies only when
    # Trivy scanned the OS packages (covered); a not-covered image has none
    # Trivy could see, so there is nothing to cross-check.
    want_family=""
    case "$coverage" in covered) want_family="$os_family" ;; esac
    grype_scan "$name" "$image" "$want_family"
done

if [ "${#waived_providers[@]}" -gt 0 ]; then
    wsum="$(printf '%s\n' "${!waived_providers[@]}" | sort | paste -sd, - | sed 's/,/, /g')"
    echo "DEGRADED: provider waiver in force for grype DB provider(s) $wsum (older than 72 hours; each grype .gate.txt names the waiver)"
    summary ""
    summary "**DEGRADED: provider waiver in force** for grype DB provider(s) $wsum (older than 72 hours; each grype .gate.txt names the waiver)."
fi
exit "$failed"
