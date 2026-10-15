#!/usr/bin/env bash
# build-agent-bundle.sh — assemble the chiselled Yuzu agent-bundle delivery image
#
# Produces a single chiselled (FROM scratch) image that carries the Yuzu agent
# for THREE target triplets — linux-x64, windows-x64, macos-arm64 — all pinned
# to one version, so a design partner who can only `docker pull` can still get
# the right agent onto every endpoint OS.
#
# The Windows (MSVC) and macOS (Apple Clang) agents cannot be cross-built in a
# Linux Docker stage, so this does NOT compile anything. It downloads the
# signed/notarized per-platform archives + native installers from the matching
# GitHub *release*, verifies them against the release SHA256SUMS, lays them out
# under /opt/yuzu-agents, and bakes them into the chiselled image.
#
# Usage:
#   bash scripts/build-agent-bundle.sh [--version X.Y.Z[-rcN]] [--push] [--multiarch]
#                                      [--registry ghcr.io/owner] [--image-name NAME]
#                                      [--no-test] [--keep-staging]
#
# Examples:
#   bash scripts/build-agent-bundle.sh                       # build the default version locally
#   bash scripts/build-agent-bundle.sh --version 0.11.0 --push
#   bash scripts/build-agent-bundle.sh --multiarch --push    # linux/amd64+arm64 -> registry
#
# Default version tracks the current GA release line (must have published
# Windows/macOS agent artifacts). Override with --version for another release.

set -euo pipefail
export COPYFILE_DISABLE=1   # macOS: don't emit ._ AppleDouble sidecars (viz-UAT lesson)

# ── Resolve repo + paths ──────────────────────────────────────────────────
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "$REPO_ROOT" ] || { echo "error: not inside the Yuzu git repo" >&2; exit 1; }
cd "$REPO_ROOT"

DOCKERFILE="deploy/docker/Dockerfile.agent-bundle.chisel"
STAGING="deploy/docker/.agent-bundle-build"   # build context (gitignored)
BUNDLE_ROOT="$STAGING/yuzu-agents"            # becomes /opt/yuzu-agents

# ── Defaults / config ─────────────────────────────────────────────────────
VERSION="${YUZU_VERSION:-0.12.0}"
IMAGE_NAME="yuzu-agent-bundle-chisel"
PUSH=0; MULTIARCH=0; RUN_TEST=1; KEEP_STAGING=0

# REPO_SLUG drives THREE things: the registry namespace (below), `gh release
# download` (:116) and `gh attestation verify` (:148). A wrong value silently
# downloads another project's artifacts and verifies provenance against the
# wrong repository, so an unresolvable remote is a HARD ERROR here rather than
# a guessed default -- same fail-loud stance as the GHCR login in release.yml,
# which this file previously contradicted. Set YUZU_REPO_SLUG to run outside a
# checkout. Note the old `-n` guard could not catch a non-GitHub remote either:
# sed passes non-matching input through unchanged, so the whole URL survived as
# a "slug"; the shape check below rejects that too.
REPO_SLUG="${YUZU_REPO_SLUG:-$(git remote get-url origin 2>/dev/null | sed -E 's|.*github\.com[:/]([^/]+/[^/.]+)(\.git)?$|\1|')}"
case "$REPO_SLUG" in
  */*/*|*://*|*" "*|"")
    printf '[xx] cannot determine the GitHub repo slug (got: %s)\n' "${REPO_SLUG:-<empty>}" >&2
    printf '     run inside a checkout with a github.com origin, or set YUZU_REPO_SLUG=owner/repo\n' >&2
    exit 1 ;;
  */*) ;;
  *)
    printf '[xx] cannot determine the GitHub repo slug (got: %s)\n' "$REPO_SLUG" >&2
    printf '     run inside a checkout with a github.com origin, or set YUZU_REPO_SLUG=owner/repo\n' >&2
    exit 1 ;;
esac

derive_owner() {
  printf '%s' "$REPO_SLUG" | cut -d/ -f1 | tr '[:upper:]' '[:lower:]'
}
REGISTRY="${YUZU_REGISTRY:-ghcr.io/$(derive_owner)}"

# ── Pretty output ─────────────────────────────────────────────────────────
if [ -t 1 ]; then C_G=$'\e[32m'; C_B=$'\e[34m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_0=$'\e[0m'; else C_G=; C_B=; C_Y=; C_R=; C_0=; fi
ok()   { printf "${C_G}[ok]${C_0} %s\n" "$*"; }
info() { printf "${C_B}[..]${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}[!!]${C_0} %s\n" "$*"; }
fail() { printf "${C_R}[xx]${C_0} %s\n" "$*" >&2; }
die()  { fail "$*"; exit 1; }

# ── Arg parsing ────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --version)     VERSION="$2"; shift ;;
    --version=*)   VERSION="${1#*=}" ;;
    --registry)    REGISTRY="$2"; shift ;;
    --registry=*)  REGISTRY="${1#*=}" ;;
    --image-name)  IMAGE_NAME="$2"; shift ;;
    --image-name=*) IMAGE_NAME="${1#*=}" ;;
    --push)        PUSH=1 ;;
    --multiarch)   MULTIARCH=1; PUSH=1 ;;   # multi-platform images must be pushed
    --no-test)     RUN_TEST=0 ;;
    --keep-staging) KEEP_STAGING=1 ;;
    -h|--help)     sed -n '2,33p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
  shift
done

VERSION="${VERSION#v}"                 # normalise: store without leading v
TAG="v${VERSION}"                      # release tag carries the v
IMAGE_REF="${REGISTRY}/${IMAGE_NAME}:${VERSION}"

# ── Tooling ────────────────────────────────────────────────────────────────
if command -v sha256sum >/dev/null 2>&1; then SHACHK="sha256sum"
elif command -v shasum  >/dev/null 2>&1; then SHACHK="shasum -a 256"
else die "need sha256sum or shasum on PATH"; fi
command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
command -v unzip  >/dev/null 2>&1 || die "need unzip on PATH (the windows archive is a .zip)"
command -v gh >/dev/null 2>&1 || die "need the GitHub CLI (gh), authenticated, to download release assets — 'brew install gh && gh auth login'"

DL=""; SMOKE_TMP=""
cleanup() {
  [ -n "$DL" ] && rm -rf "$DL" 2>/dev/null || true
  [ -n "$SMOKE_TMP" ] && rm -rf "$SMOKE_TMP" 2>/dev/null || true
  [ "${KEEP_STAGING:-0}" = 1 ] || rm -rf "$STAGING" 2>/dev/null || true
}
trap cleanup EXIT

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Yuzu agent-bundle (chiselled delivery image)     ║"
echo "╚══════════════════════════════════════════════════╝"
info "version=$VERSION  tag=$TAG  repo=$REPO_SLUG"
info "image=$IMAGE_REF  push=$PUSH  multiarch=$MULTIARCH"

# ── 1. Download + verify release assets ────────────────────────────────────
# Download by glob so we match GitHub's *canonical* asset names: GitHub
# sanitises some characters on upload (e.g. the Debian '~' in 0.12.0~rc0 is
# served as '.', so for releases before 0.14.0-rc3 the name in SHA256SUMS !=
# the downloadable name; #5141 fixed that). We therefore verify by HASH
# presence in the signed manifest, never by filename.
DL="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-agent-bundle.XXXXXX")"
ARCHIVES="yuzu-linux-x64.tar.gz yuzu-windows-x64.zip yuzu-macos-arm64.tar.gz"

info "Downloading agent artifacts + SHA256SUMS for $VERSION (this is large)..."
gh release download "$TAG" --repo "$REPO_SLUG" -D "$DL" --clobber \
  -p 'yuzu-linux-x64.tar.gz' -p 'yuzu-windows-x64.zip' -p 'yuzu-macos-arm64.tar.gz' \
  -p 'yuzu-agent_*_amd64.deb' -p 'yuzu-agent-*.x86_64.rpm' \
  -p 'YuzuAgent-*-macos-arm64.pkg' -p 'YuzuAgentSetup-*.exe' \
  -p 'SHA256SUMS' \
  || die "gh release download failed for $TAG (is gh authenticated? does $TAG exist?)"

# Resolve the installer filenames as actually downloaded (post-sanitisation).
pick() { ( cd "$DL" && ls $1 2>/dev/null | head -1 ); }
DEB="$(pick 'yuzu-agent_*_amd64.deb')"
RPM="$(pick 'yuzu-agent-*.x86_64.rpm')"
PKG="$(pick 'YuzuAgent-*-macos-arm64.pkg')"
EXE="$(pick 'YuzuAgentSetup-*.exe')"
[ -n "$DEB" ] || die "no .deb installer asset on $TAG"
[ -n "$RPM" ] || die "no .rpm installer asset on $TAG"
[ -n "$PKG" ] || die "no .pkg installer asset on $TAG"
[ -n "$EXE" ] || die "no Windows installer asset on $TAG"
[ -s "$DL/SHA256SUMS" ] || die "no SHA256SUMS on $TAG"

# Verify every artifact by checking its sha256 appears in the signed manifest.
verify_hash() {
  local f="$1" h
  [ -s "$DL/$f" ] || die "download missing or empty: $f"
  h="$($SHACHK "$DL/$f" | awk '{print $1}')"
  grep -qi "^${h}  " "$DL/SHA256SUMS" \
    || die "NOT in signed SHA256SUMS (corrupt or tampered): $f"
}
info "Verifying downloads against the signed release SHA256SUMS (by hash)..."
for a in $ARCHIVES "$DEB" "$RPM" "$PKG" "$EXE"; do verify_hash "$a"; done
ok "All 7 artifacts verified against the signed release SHA256SUMS"

# Best-effort provenance attestation (does not gate the build).
if gh attestation verify "$DL/yuzu-linux-x64.tar.gz" --repo "$REPO_SLUG" >/dev/null 2>&1; then
  ok "SLSA provenance attestation verified (gh attestation)"
else
  warn "Could not verify provenance attestation (offline, or gh too old) — continuing on SHA256 only"
fi

# ── 2. Lay out the /opt/yuzu-agents tree ───────────────────────────────────
info "Laying out the bundle tree..."
[ "$KEEP_STAGING" = 1 ] || rm -rf "$STAGING"
mkdir -p "$BUNDLE_ROOT"

# extract_payload <platform> <archive> <unpacker> : strips yuzu-server, keeps
# the agent binary + core lib + plugins (+ windows runtime DLLs).
extract_payload() {
  local plat="$1" archive="$2" how="$3"
  local dst="$BUNDLE_ROOT/$plat" ex; ex="$(mktemp -d "$DL/ex.XXXXXX")"
  mkdir -p "$dst/installers" "$dst/payload/bin" "$dst/payload/plugins"
  case "$how" in
    tar) tar xzf "$DL/$archive" -C "$ex" ;;
    zip) unzip -q "$DL/$archive" -d "$ex" ;;
  esac
  # Find the single top-level dir that actually contains bin/ — robust to a
  # stray sibling (e.g. __MACOSX/ from a Finder/ditto re-zip) that would
  # otherwise break a bare `*/` glob.
  local top="" d
  for d in "$ex"/*/; do [ -d "${d}bin" ] && { top="$d"; break; }; done
  [ -n "$top" ] || die "unexpected layout in $archive (no */bin under $ex)"
  cp -R "$top"bin/.     "$dst/payload/bin/"
  cp -R "$top"plugins/. "$dst/payload/plugins/" 2>/dev/null || true
  rm -f "$dst/payload/bin/yuzu-server" "$dst/payload/bin/yuzu-server.exe"
  chmod -R a+rX "$dst/payload"
  # The unix agent binary must be executable for the partner's foreground run.
  # tar preserves the bit, but re-assert it and fail closed so a repackaged
  # archive can't ship a non-runnable agent. (The Windows .exe needs no +x.)
  if [ "$plat" != "windows-x64" ]; then
    chmod +x "$dst/payload/bin/yuzu-agent" 2>/dev/null || true
    [ -x "$dst/payload/bin/yuzu-agent" ] || die "$plat agent binary is not executable"
  fi
}

extract_payload linux-x64   yuzu-linux-x64.tar.gz   tar
extract_payload windows-x64 yuzu-windows-x64.zip    zip
extract_payload macos-arm64 yuzu-macos-arm64.tar.gz tar

cp "$DL/$DEB" "$BUNDLE_ROOT/linux-x64/installers/"
cp "$DL/$RPM" "$BUNDLE_ROOT/linux-x64/installers/"
cp "$DL/$PKG" "$BUNDLE_ROOT/macos-arm64/installers/"
cp "$DL/$EXE" "$BUNDLE_ROOT/windows-x64/installers/"
cp "$DL/SHA256SUMS" "$BUNDLE_ROOT/UPSTREAM-SHA256SUMS"
printf '%s\n' "$VERSION" > "$BUNDLE_ROOT/VERSION"

# ── 3. READMEs (per-OS install + how to point at the gateway) ───────────────
cat > "$BUNDLE_ROOT/README.txt" <<EOF
Yuzu Agent Bundle — ${VERSION}
==============================================================================
Three agent triplets, all at version ${VERSION} (matching the Yuzu server and
gateway of the same version):

  linux-x64     Linux   x86_64          (glibc)
  windows-x64   Windows x86_64          (MSVC, Authenticode-signed)
  macos-arm64   macOS   Apple Silicon   (notarized)

This is a DELIVERY image, not a runtime: it ships the agent for three operating
systems so you can copy the right one onto each endpoint. Nothing here runs the
Windows or macOS binaries — a Linux container cannot.

Extract the whole tree
----------------------------------------------------------------------------
  # self-extract into ./yuzu-agents/ :
  docker run --rm -v "\$PWD:/out" ${IMAGE_REF}

  # or copy out without running anything in the container:
  cid=\$(docker create ${IMAGE_REF}); docker cp "\$cid:/opt/yuzu-agents" .; docker rm "\$cid"

Layout
----------------------------------------------------------------------------
  <os>/installers/   native installer(s) — turnkey: installs a service + user
  <os>/payload/      raw agent binary + core lib + plugins — sideload / foreground

Read <os>/README.txt for per-OS install steps and how to point the agent at
your gateway. For a no-TLS demo stack the raw payload (which lets you pass
--no-tls) is the easiest path; the installers assume a TLS deployment.

Integrity
----------------------------------------------------------------------------
  SHA256SUMS           checksums of every file in THIS tree
  UPSTREAM-SHA256SUMS  the signed checksums from the ${TAG} GitHub release
  Verify:  cd yuzu-agents && sha256sum -c SHA256SUMS
EOF

cat > "$BUNDLE_ROOT/linux-x64/README.txt" <<EOF
Yuzu Agent — linux-x64 — ${VERSION}
==============================================================================
DEMO (no-TLS stack, foreground) — simplest:
  cd payload
  LD_LIBRARY_PATH="\$PWD/bin" ./bin/yuzu-agent \\
    --server <GATEWAY_HOST>:50051 --no-tls \\
    --enrollment-token <TOKEN> \\
    --plugin-dir "\$PWD/plugins" --data-dir ./data --log-level info

PERSISTENT (systemd service via native package):
  Debian/Ubuntu:  sudo apt-get install ./installers/${DEB}
  RHEL/Fedora:    sudo dnf install ./installers/${RPM}
  The package installs the 'yuzu-agent' service (default --server <hostname>:50051,
  TLS on). Point it at your gateway + token with a drop-in:
    sudo systemctl edit yuzu-agent
  and add (the empty ExecStart= clears the packaged one):
    [Service]
    ExecStart=
    ExecStart=/usr/local/bin/yuzu-agent --server <GATEWAY_HOST>:50051 \\
      --enrollment-token <TOKEN> --plugin-dir /usr/lib/yuzu/plugins \\
      --data-dir /var/lib/yuzu-agent
    # append --no-tls to that line if you are connecting to the no-TLS demo stack
  then:
    sudo systemctl enable --now yuzu-agent
EOF

cat > "$BUNDLE_ROOT/macos-arm64/README.txt" <<EOF
Yuzu Agent — macos-arm64 — ${VERSION}  (Apple Silicon, notarized)
==============================================================================
DEMO (no-TLS stack, foreground) — simplest:
  cd payload
  DYLD_LIBRARY_PATH="\$PWD/bin" ./bin/yuzu-agent \\
    --server <GATEWAY_HOST>:50051 --no-tls \\
    --enrollment-token <TOKEN> \\
    --plugin-dir "\$PWD/plugins" --data-dir ./data --log-level info
  # The binary is signed + notarized. If macOS quarantines copied files:
  #   xattr -dr com.apple.quarantine ./bin ./plugins

PERSISTENT (launchd daemon via signed .pkg):
  sudo installer -pkg installers/${PKG} -target /
  Edit /Library/LaunchDaemons/com.yuzu.agent.plist — add to <ProgramArguments>:
    --server <GATEWAY_HOST>:50051   --enrollment-token <TOKEN>
    (and --no-tls if connecting to the no-TLS demo stack)
  then reload:
    sudo launchctl bootout   system /Library/LaunchDaemons/com.yuzu.agent.plist 2>/dev/null || true
    sudo launchctl bootstrap system /Library/LaunchDaemons/com.yuzu.agent.plist
EOF

cat > "$BUNDLE_ROOT/windows-x64/README.txt" <<EOF
Yuzu Agent — windows-x64 — ${VERSION}  (Authenticode-signed)
==============================================================================
DEMO (no-TLS stack, foreground) — PowerShell:
  cd payload
  .\\bin\\yuzu-agent.exe --server <GATEWAY_HOST>:50051 --no-tls \`
    --enrollment-token <TOKEN> --plugin-dir .\\plugins --data-dir .\\data --log-level info
  # the runtime DLLs the agent needs sit next to the .exe in bin\\

PERSISTENT (Windows service via signed installer):
  Double-click installers\\${EXE} and enter the gateway address + enrollment
  token on the configuration page. Or install unattended:
    .\\installers\\${EXE} /VERYSILENT /SUPPRESSMSGBOXES /TOKEN=<TOKEN>
  (set the gateway address on the config page; see docs/agent-bundle.md for the
  full silent-install parameter list). The service is named 'YuzuAgent'.
EOF

# Fresh checksums over the laid-out tree. NUL-delimited so a path with spaces
# (defensive — the tree has none today) can't mis-split.
( cd "$BUNDLE_ROOT" && find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 $SHACHK > SHA256SUMS )

# Stage the self-extract entrypoint alongside yuzu-agents/ in the build context.
cp deploy/docker/agent-bundle-extract.sh "$STAGING/extract.sh"

ok "Bundle tree staged at $BUNDLE_ROOT"
du -sh "$BUNDLE_ROOT" 2>/dev/null | awk '{print "     payload size: "$1}'

# ── 4. Build the image ─────────────────────────────────────────────────────
BUILD_ARGS=(--build-arg BUNDLE_VERSION="$VERSION" --build-arg BUNDLE_SOURCE_RELEASE="$TAG")
if [ "$MULTIARCH" = 1 ]; then
  info "Building multi-arch (linux/amd64,linux/arm64) and pushing $IMAGE_REF..."
  docker buildx build \
    --platform linux/amd64,linux/arm64 \
    -f "$DOCKERFILE" "${BUILD_ARGS[@]}" \
    -t "$IMAGE_REF" --push "$STAGING"
  ok "Pushed multi-arch $IMAGE_REF"

  # Verify the pushed index carries BOTH arches — a failed/partial leg must not
  # silently ship a single-arch "multi-arch" tag — then smoke the host-arch
  # variant end-to-end (the local-build smoke below is skipped on this path).
  info "Verifying pushed multi-arch manifest..."
  plats="$(docker buildx imagetools inspect "$IMAGE_REF" \
    --format '{{range .Manifest.Manifests}}{{.Platform.OS}}/{{.Platform.Architecture}} {{end}}' 2>/dev/null || true)"
  case "$plats" in *linux/amd64*) : ;; *) die "pushed manifest missing linux/amd64 (got: $plats)";; esac
  case "$plats" in *linux/arm64*) : ;; *) die "pushed manifest missing linux/arm64 (got: $plats)";; esac
  ok "manifest carries both arches"
  if [ "$RUN_TEST" = 1 ]; then
    info "Smoke-testing the pushed image (host arch)..."
    docker pull -q "$IMAGE_REF" >/dev/null
    SMOKE_TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-bundle-test.XXXXXX")"
    # --user: on rootful docker (GHA-hosted runners) the self-extract would
    # otherwise write root-owned files into the bind mount and the cleanup
    # rm -rf below dies with EPERM — which, since the single-arch path
    # smoke-tests BEFORE pushing, blocked the v0.13.0 bundle publish.
    docker run --rm --user "$(id -u):$(id -g)" -v "$SMOKE_TMP:/out" "$IMAGE_REF" >/dev/null
    [ "$(cat "$SMOKE_TMP/yuzu-agents/VERSION")" = "$VERSION" ] || die "self-extract produced wrong VERSION"
    ( cd "$SMOKE_TMP/yuzu-agents" && $SHACHK -c SHA256SUMS >/dev/null ) || die "in-image SHA256SUMS failed"
    rm -rf "$SMOKE_TMP"; SMOKE_TMP=""
    ok "multi-arch smoke passed (both arches present + host-arch self-extract)"
  fi
else
  info "Building $IMAGE_REF (host arch)..."
  DOCKER_BUILDKIT=1 docker build \
    -f "$DOCKERFILE" "${BUILD_ARGS[@]}" \
    -t "$IMAGE_REF" "$STAGING"
  ok "Built $IMAGE_REF"

  if [ "$RUN_TEST" = 1 ]; then
    info "Smoke-testing the image..."
    docker run --rm "$IMAGE_REF" list >/dev/null || die "entrypoint 'list' failed"
    t="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-bundle-test.XXXXXX")"
    # --user: see the multi-arch smoke above — root-owned extraction breaks
    # the rm -rf cleanup on rootful docker, and here that aborts pre-push.
    docker run --rm --user "$(id -u):$(id -g)" -v "$t:/out" "$IMAGE_REF" >/dev/null
    [ "$(cat "$t/yuzu-agents/VERSION")" = "$VERSION" ] || die "self-extract produced wrong VERSION"
    for f in linux-x64/payload/bin/yuzu-agent \
             windows-x64/payload/bin/yuzu-agent.exe \
             macos-arm64/payload/bin/yuzu-agent; do
      [ -s "$t/yuzu-agents/$f" ] || die "missing $f in extracted bundle"
    done
    ( cd "$t/yuzu-agents" && $SHACHK -c SHA256SUMS >/dev/null ) || die "in-image SHA256SUMS failed"
    rm -rf "$t"
    ok "Smoke test passed (self-extract + 3 agent binaries + checksums)"
  fi

  if [ "$PUSH" = 1 ]; then
    info "Pushing $IMAGE_REF..."
    docker push "$IMAGE_REF"
    ok "Pushed $IMAGE_REF"
  fi
fi

[ "$KEEP_STAGING" = 1 ] || rm -rf "$STAGING"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Agent bundle ready                               ║"
echo "╚══════════════════════════════════════════════════╝"
echo "  Image:    $IMAGE_REF"
echo "  Pull:     docker pull $IMAGE_REF"
echo "  Extract:  docker run --rm -v \"\$PWD:/out\" $IMAGE_REF"
echo "  Triplets: linux-x64, windows-x64, macos-arm64  (installers + raw payload)"
[ "$PUSH" = 1 ] || echo "  (local only — re-run with --push, or --multiarch --push, to publish)"
echo ""
