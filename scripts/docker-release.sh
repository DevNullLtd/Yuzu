#!/usr/bin/env bash
# docker-release.sh — Build and push Yuzu Docker images to GHCR
#
# Usage (local builds; publishing is not a use of this script):
#   ./scripts/docker-release.sh --build-only v0.8.0  # build only, no push
#   ./scripts/docker-release.sh --dry-run v0.8.0     # print commands only
# Without a flag it pushes :X.Y.Z, :X.Y, :latest to GHCR: NOT a release procedure.
#
# Requires: docker, gh (GitHub CLI, authenticated)
# Designed for: Windows (Docker Desktop) + MSYS2 bash
#
# Releases are published by release.yml; a push from this script moves release
# tags outside it, bypassing the release image gate and the publish journal
# (docs/ci-architecture.md, "Release tag policy", Limit 1). Doing so is an
# owner-decided incident, recorded in a tracking issue and announced.

set -euo pipefail

# Enable BuildKit so the Dockerfiles' cache mounts (`RUN --mount=type=cache`)
# take effect even on older docker versions where BuildKit isn't the default.
export DOCKER_BUILDKIT=1

# ── Parse flags ───────────────────────────────────────────────────────────
DRY_RUN=false
BUILD_ONLY=false
VERSION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)   DRY_RUN=true; shift ;;
        --build-only) BUILD_ONLY=true; shift ;;
        -h|--help)
            sed -n '2,7p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        v*)          VERSION="$1"; shift ;;
        *)           echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 [--dry-run|--build-only] <version-tag>"
    echo "  e.g. $0 --build-only v0.8.0   (a bare push is not a release procedure; see the header)"
    exit 1
fi

# ── Validate version format ──────────────────────────────────────────────
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "Error: version must match v<major>.<minor>.<patch>[...]  (got: $VERSION)"
    exit 1
fi

TAG="${VERSION#v}"  # strip leading v → 0.8.0

# ── Derive GHCR owner from git remote (lowercase) ───────────────────────
REMOTE_URL=$(git remote get-url origin 2>/dev/null || true)
if [[ -z "$REMOTE_URL" ]]; then
    echo "Error: no git remote 'origin' found"
    exit 1
fi
OWNER=$(echo "$REMOTE_URL" | sed -E 's|.*github\.com[:/]([^/]+)/.*|\1|' | tr '[:upper:]' '[:lower:]')
REGISTRY="ghcr.io/${OWNER}"

echo "=== Yuzu Docker Release ==="
echo "  Version:  $VERSION ($TAG)"
echo "  Registry: $REGISTRY"
echo "  Platform: linux/amd64"
echo ""

# ── Determine tags ───────────────────────────────────────────────────────
SERVER_IMAGES=("${REGISTRY}/yuzu-server:${TAG}")
GATEWAY_IMAGES=("${REGISTRY}/yuzu-gateway:${TAG}")

# Stable releases (no prerelease suffix) also get :latest and :major.minor
if [[ ! "$TAG" =~ -(alpha|beta|rc) ]]; then
    MAJOR_MINOR=$(echo "$TAG" | grep -oP '^\d+\.\d+')
    SERVER_IMAGES+=("${REGISTRY}/yuzu-server:${MAJOR_MINOR}" "${REGISTRY}/yuzu-server:latest")
    GATEWAY_IMAGES+=("${REGISTRY}/yuzu-gateway:${MAJOR_MINOR}" "${REGISTRY}/yuzu-gateway:latest")
    echo "  Stable release — tagging: ${TAG}, ${MAJOR_MINOR}, latest"
else
    echo "  Pre-release — tagging: ${TAG} only"
fi
echo ""

# ── Helper: run or print ─────────────────────────────────────────────────
run() {
    if $DRY_RUN; then
        echo "[dry-run] $*"
    else
        echo "+ $*"
        MSYS_NO_PATHCONV=1 "$@"
    fi
}

# ── Preflight checks ─────────────────────────────────────────────────────
if ! $DRY_RUN; then
    # Docker running?
    if ! docker info >/dev/null 2>&1; then
        echo "Error: Docker is not running. Start Docker Desktop and retry."
        exit 1
    fi

    # Repo root?
    REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
    if [[ -z "$REPO_ROOT" ]]; then
        echo "Error: not inside a git repository"
        exit 1
    fi
    cd "$REPO_ROOT"

    # Dockerfiles exist?
    for f in deploy/docker/Dockerfile.server deploy/docker/Dockerfile.gateway; do
        if [[ ! -f "$f" ]]; then
            echo "Error: $f not found"
            exit 1
        fi
    done

    # Authenticate to GHCR via gh CLI
    echo "Authenticating to ghcr.io via gh CLI..."
    GH_TOKEN=$(gh auth token 2>/dev/null || true)
    if [[ -z "$GH_TOKEN" ]]; then
        echo "Error: gh auth token failed. Run 'gh auth login' first."
        exit 1
    fi
    echo "$GH_TOKEN" | MSYS_NO_PATHCONV=1 docker login ghcr.io -u "$(gh api user -q .login)" --password-stdin
    echo ""
fi

# ── Build images (in parallel) ───────────────────────────────────────────
# Server and gateway are fully independent Docker builds. Run them at the
# same time so wall-clock time is max(server, gateway) instead of the sum.
# --progress=plain keeps the interleaved output readable (no TTY redraws).
echo "=== Building yuzu-server and yuzu-gateway in parallel ==="

SERVER_BUILD_ARGS=(-f deploy/docker/Dockerfile.server --platform linux/amd64 --progress=plain)
for img in "${SERVER_IMAGES[@]}"; do
    SERVER_BUILD_ARGS+=(-t "$img")
done

GATEWAY_BUILD_ARGS=(-f deploy/docker/Dockerfile.gateway --platform linux/amd64 --progress=plain)
for img in "${GATEWAY_IMAGES[@]}"; do
    GATEWAY_BUILD_ARGS+=(-t "$img")
done

run docker build "${SERVER_BUILD_ARGS[@]}" . &
SERVER_PID=$!
run docker build "${GATEWAY_BUILD_ARGS[@]}" . &
GATEWAY_PID=$!

SERVER_STATUS=0
GATEWAY_STATUS=0
wait "$SERVER_PID" || SERVER_STATUS=$?
wait "$GATEWAY_PID" || GATEWAY_STATUS=$?

if (( SERVER_STATUS != 0 || GATEWAY_STATUS != 0 )); then
    echo ""
    echo "Error: parallel build failed (server=$SERVER_STATUS gateway=$GATEWAY_STATUS)"
    exit 1
fi
echo ""

# ── Push images ──────────────────────────────────────────────────────────
if $BUILD_ONLY; then
    echo "=== Build complete (--build-only, skipping push) ==="
else
    echo "=== Pushing images ==="
    for img in "${SERVER_IMAGES[@]}" "${GATEWAY_IMAGES[@]}"; do
        run docker push "$img"
    done
    echo ""

    echo "=== Done ==="
    echo ""
    echo "Pull commands:"
    echo "  docker pull ${REGISTRY}/yuzu-server:${TAG}"
    echo "  docker pull ${REGISTRY}/yuzu-gateway:${TAG}"
fi
