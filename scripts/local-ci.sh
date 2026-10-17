#!/bin/bash
# Yuzu Local CI — run the same CI checks as GitHub Actions locally
#
# Usage:
#   bash scripts/local-ci.sh                  # gcc-15 debug (default)
#   bash scripts/local-ci.sh gcc-15 release   # gcc-15 release + LTO
#   bash scripts/local-ci.sh clang-21 debug   # clang-21 debug
#   (Dockerfile.ci / ci-entrypoint.sh accept only gcc-15 and clang-21 — the
#   compilers CI builds and tests, which are also the supported floor.)
#   bash scripts/local-ci.sh build            # build the CI image only
#   bash scripts/local-ci.sh shell            # interactive shell in CI image
#
# First run builds the Docker image (~40 min for vcpkg).
# Subsequent runs reuse the image and complete in ~3-5 min.
#
# ccache is persisted in a Docker volume across runs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Docker Desktop PATH (Windows/MSYS2)
export PATH="/c/Program Files/Docker/Docker/resources/bin:$PATH"

IMAGE_NAME="yuzu-ci"
CCACHE_VOLUME="yuzu-ci-ccache"

COMPILER="${1:-gcc-15}"
BUILD_TYPE="${2:-debug}"

# ── Build image if needed ────────────────────────────────────────────────
build_image() {
    echo "Building CI image (this takes ~40 min on first run)..."
    docker build -t "$IMAGE_NAME" \
        -f "$REPO_ROOT/deploy/docker/Dockerfile.ci" \
        "$REPO_ROOT"
}

if [[ "$COMPILER" == "build" ]]; then
    build_image
    echo "CI image built: $IMAGE_NAME"
    docker images "$IMAGE_NAME" --format "  Size: {{.Size}}"
    exit 0
fi

# Auto-build if image doesn't exist
if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    build_image
fi

# Create ccache volume if needed
docker volume inspect "$CCACHE_VOLUME" &>/dev/null 2>&1 || \
    docker volume create "$CCACHE_VOLUME" >/dev/null

# ── Run CI ───────────────────────────────────────────────────────────────
if [[ "$COMPILER" == "shell" ]]; then
    echo "Starting interactive CI shell..."
    docker run --rm -it \
        -v "$REPO_ROOT:/src:ro" \
        -v "$CCACHE_VOLUME:/ccache" \
        "$IMAGE_NAME" bash
    exit 0
fi

echo "Running: $COMPILER $BUILD_TYPE"
echo ""

docker run --rm \
    -v "$REPO_ROOT:/src:ro" \
    -v "$CCACHE_VOLUME:/ccache" \
    "$IMAGE_NAME" "$COMPILER" "$BUILD_TYPE"
