#!/usr/bin/env bash
# Verify docker-compose files reference the expected Yuzu version.
#
# Enforces two rules for every
# `ghcr.io/<owner>/yuzu-{server,gateway,agent,postgres,postgres-ha}[-chisel]:<tag>`
# reference in tracked compose files:
#
#   1. The tag must be parameterized as `${YUZU_VERSION:-<default>}` — bare
#      `X.Y.Z` or `X.Y.Z-suffix` tags are rejected so a version bump never
#      leaves a stale compose file behind.
#   2. The `<default>` inside the parameterization must equal the version
#      passed on the command line — this is what runs in the release workflow
#      so a tagged release fails fast if the in-tree default was not updated.
#
# Floating tags (`latest`, `local`, etc.) are ignored — they are intentional
# for dev/local compose files.
#
# Usage:
#   scripts/check-compose-versions.sh <expected-version>
#   scripts/check-compose-versions.sh 0.9.0
#
# Exits non-zero on any violation; emits GitHub Actions `::error file=...`
# annotations so failures surface inline on the PR / release run.

set -euo pipefail

if [[ $# -lt 1 || -z "${1:-}" ]]; then
  echo "usage: $0 <expected-version>" >&2
  echo "  e.g. $0 0.9.0" >&2
  exit 2
fi

EXPECTED="$1"
shift

# Files to check. Explicit args after the version override the default tracked
# list — used by tests/shell/test_check_compose_versions.sh for hermetic
# fixtures; the release job passes only the version, so it uses the default.
# Local-only files (`docker-compose.local.yml`) are gitignored and omitted; a
# new tracked compose must be opted in here consciously.
if [ "$#" -gt 0 ]; then
  FILES=("$@")
else
  FILES=(
    docker-compose.uat.yml
    deploy/docker/docker-compose.yml
    deploy/docker/docker-compose.reference.yml
    deploy/docker/docker-compose.reference-gateway.yml
    deploy/docker/docker-compose.reference-gateway-cluster.yml
    deploy/docker/docker-compose.uat.yml
    deploy/docker/docker-compose.full-uat.yml
    deploy/docker/docker-compose.sanitizer-uat.yml
    deploy/docker/docker-compose.demo.yml
    deploy/docker/docker-compose.ha-postgres.yml
  )
fi

fail=0

emit_error() {
  local file="$1" line="$2" msg="$3"
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "::error file=${file},line=${line}::${msg}"
  else
    echo "error: ${file}:${line}: ${msg}" >&2
  fi
  fail=1
}

for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || continue

  # Match any `ghcr.io/<owner>/yuzu-{server,gateway,agent}:<tag>` occurrence
  # and inspect the captured tag. Using grep -n gives us line numbers for
  # actionable GHA annotations.
  while IFS=: read -r lineno rest; do
    [[ -z "$lineno" ]] && continue
    # Pull just the tag off the matched line.
    if [[ "$rest" =~ ghcr\.io/[^/]+/yuzu-(server|gateway|agent|postgres-ha|postgres)(-chisel)?:([^[:space:]\"\']+) ]]; then
      tag="${BASH_REMATCH[3]}"
    else
      continue
    fi

    # Parameterized form: `${YUZU_VERSION:-<default>}` — verify the default.
    if [[ "$tag" =~ ^\$\{YUZU_VERSION:-([^}]+)\}$ ]]; then
      default="${BASH_REMATCH[1]}"
      if [[ "$default" != "$EXPECTED" ]]; then
        emit_error "$f" "$lineno" \
          "parameterized default '$default' does not match expected version '$EXPECTED' — update the \${YUZU_VERSION:-...} default"
      fi
      continue
    fi

    # Hardcoded numeric tag (X, X.Y, X.Y.Z, X.Y.Z-rcN, ...) — reject.
    if [[ "$tag" =~ ^[0-9]+(\.[0-9]+)*(-[A-Za-z0-9._]+)?$ ]]; then
      emit_error "$f" "$lineno" \
        "hardcoded image tag '$tag' — use \${YUZU_VERSION:-$EXPECTED} so version bumps update it automatically"
      continue
    fi

    # Anything else (latest, local, sha-*, ...) is intentional and allowed.
  done < <(grep -nE 'ghcr\.io/[^/]+/yuzu-(server|gateway|agent|postgres-ha|postgres)(-chisel)?:' "$f" || true)
done

if [[ $fail -ne 0 ]]; then
  echo "" >&2
  echo "compose version check failed — see errors above." >&2
  exit 1
fi

echo "compose version check passed for ${EXPECTED}"
