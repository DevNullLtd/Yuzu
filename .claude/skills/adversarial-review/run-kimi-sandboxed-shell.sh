#!/usr/bin/env bash
# Exact-command collector allowed by Kimi's restricted permission profile.
# It accepts no model-controlled command text and emits bounded empirical context.

set -euo pipefail

[[ $# -eq 0 ]] || { echo "error: sandbox dispatcher accepts no arguments" >&2; exit 2; }
: "${YUZU_KIMI_SANDBOX_REPO:?set YUZU_KIMI_SANDBOX_REPO}"
: "${YUZU_KIMI_SANDBOX_REVIEW_DIR:?set YUZU_KIMI_SANDBOX_REVIEW_DIR}"
: "${YUZU_KIMI_SANDBOX_IMAGE:?set YUZU_KIMI_SANDBOX_IMAGE to an immutable image digest}"

case "$YUZU_KIMI_SANDBOX_IMAGE" in
  *@sha256:*) ;;
  *) echo "error: sandbox image must be pinned by digest" >&2; exit 2 ;;
esac

command -v docker >/dev/null 2>&1 || {
  echo "error: docker is required for Kimi sandboxed shell mode" >&2; exit 2; }

REPO="$(cd "$YUZU_KIMI_SANDBOX_REPO" && pwd)"
REVIEW_DIR="$(cd "$YUZU_KIMI_SANDBOX_REVIEW_DIR" && pwd)"
DOCKER_ARGS=(
  run --rm --pull never
  --network none
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges
  --pids-limit 256
  --memory "${YUZU_KIMI_SANDBOX_MEMORY:-4g}"
  --cpus "${YUZU_KIMI_SANDBOX_CPUS:-4}"
  --user "$(id -u):$(id -g)"
  --env HOME=/tmp/kimi-home
  --env "YUZU_REVIEW_OUTPUT=$REVIEW_DIR/KIMI_SANDBOX_OUTPUT.md"
  --tmpfs "/tmp:rw,nosuid,nodev,noexec,size=1g"
  --volume "$REPO:$REPO:ro"
  --volume "$REVIEW_DIR:$REVIEW_DIR:rw"
  --workdir "$REPO"
)

if [[ -n "${YUZU_KIMI_SANDBOX_GIT_DIR:-}" ]]; then
  GIT_DIR="$(cd "$YUZU_KIMI_SANDBOX_GIT_DIR" && pwd)"
  DOCKER_ARGS+=(--volume "$GIT_DIR:$GIT_DIR:ro")
fi
if [[ -n "${YUZU_KIMI_SANDBOX_PLATFORM:-}" ]]; then
  DOCKER_ARGS+=(--platform "$YUZU_KIMI_SANDBOX_PLATFORM")
fi

exec docker "${DOCKER_ARGS[@]}" "$YUZU_KIMI_SANDBOX_IMAGE" /bin/bash -lc \
  'if command -v git >/dev/null 2>&1; then
     { git status --short; git diff --stat; git log -5 --oneline --decorate; }
   else
     echo "sandbox image has no git; orchestrator dynamic evidence remains authoritative"
   fi > "$YUZU_REVIEW_OUTPUT" 2>&1'
