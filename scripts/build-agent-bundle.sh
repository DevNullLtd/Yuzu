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
# per-platform archives + native installers from the matching
# GitHub *release*, verifies the release SHA256SUMS' cosign signature (keyless,
# exact workflow identity) and then each artifact against ITS OWN line in that
# manifest, lays them out under /opt/yuzu-agents, and bakes them into the
# chiselled image. This is a Sigstore check of the release manifest; it is not
# the agent's detached-CMS verifier (plugin loader / OTA updater).
#
# Neither the Windows installer/agent (Authenticode signing is skipped in the
# release workflow today, #239) nor the macOS agent/.pkg is code-signed or
# notarized; the cosign check above is the only authenticity check there is
# (see docs/agent-bundle.md).
#
# Usage:
#   bash scripts/build-agent-bundle.sh [--version X.Y.Z[-rcN]] [--push] [--multiarch]
#                                      [--registry ghcr.io/owner] [--image-name NAME]
#                                      [--no-test] [--keep-staging]
#                                      [--signer-repo owner/repo] [--verify-only]
#
# --signer-repo   repo whose release.yml signed SHA256SUMS. Default is a fixed
#                 table by version: <= 0.13.x Tr3kkR/Yuzu, later DevNullLtd/Yuzu
#                 (the identity is baked into the Fulcio cert and not rewritten
#                 by the repo move). Never derived from the checkout's origin.
# --keep-staging  keep this run's staging dir (its path is printed) instead of
#                 removing it on exit. Each run stages in its own mktemp dir.
# --verify-only   download, verify the signature and every hash, then stop
#                 (no docker, no build, no --push/--multiarch). Needs gh, cosign,
#                 sha256sum or shasum, and a git checkout.
# cosign is REQUIRED; there is no skip flag (fail closed).
#
# Examples:
#   bash scripts/build-agent-bundle.sh                       # build the default version locally
#   bash scripts/build-agent-bundle.sh --version 0.11.0 --push
#   bash scripts/build-agent-bundle.sh --multiarch --push    # linux/amd64+arm64 -> registry
#
# Default version tracks the current GA release line (must have published
# Windows/macOS agent artifacts). Override with --version for another release.

set -euo pipefail
# Byte-wise character classes: the version/hash regexes below must not accept
# locale-specific digits or letters (a superscript two is not a version digit).
export LC_ALL=C
export COPYFILE_DISABLE=1   # macOS: don't emit ._ AppleDouble sidecars (viz-UAT lesson)

# ── Resolve repo + paths ──────────────────────────────────────────────────
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "$REPO_ROOT" ] || { echo "error: not inside the Yuzu git repo" >&2; exit 1; }
cd "$REPO_ROOT"

DOCKERFILE="deploy/docker/Dockerfile.agent-bundle.chisel"
# Build context: a PER-RUN mktemp dir under deploy/docker/ (gitignored via
# .agent-bundle-build*), created at the layout step and removed only by the run
# that made it, so two hand builds in one checkout can never share or delete
# each other's tree. STAGING stays empty until then.
STAGING_PREFIX="deploy/docker/.agent-bundle-build"
STAGING=""
BUNDLE_ROOT=""                                # $STAGING/yuzu-agents -> /opt/yuzu-agents

# ── Defaults / config ─────────────────────────────────────────────────────
VERSION="${YUZU_VERSION:-0.15.0}"
IMAGE_NAME="yuzu-agent-bundle-chisel"
PUSH=0; MULTIARCH=0; RUN_TEST=1; KEEP_STAGING=0; VERIFY_ONLY=0; SIGNER_REPO=""
STAGING_OWNED=0

# REPO_SLUG drives THREE things: the registry namespace (below), `gh release
# download` and `gh attestation verify`. A wrong value silently
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
    --verify-only) VERIFY_ONLY=1 ;;
    --signer-repo) [ $# -ge 2 ] || die "--signer-repo needs owner/repo"; SIGNER_REPO="$2"; shift ;;
    --signer-repo=*) SIGNER_REPO="${1#*=}" ;;
    -h|--help)     awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
  shift
done

[ "$VERIFY_ONLY" = 0 ] || [ "$PUSH" = 0 ] \
  || die "--verify-only downloads and verifies only: it builds and pushes nothing, so --push/--multiarch cannot apply"
VERSION="${VERSION#v}"                 # normalise: store without leading v
TAG="v${VERSION}"                      # release tag carries the v
IMAGE_REF="${REGISTRY}/${IMAGE_NAME}:${VERSION}"

# ── Signer identity (hard-coded era table; NEVER derived from REPO_SLUG) ───
# The Fulcio certificate SAN of a release's SHA256SUMS signature names the repo
# that ran release.yml. That is fixed at build time: <= 0.13.x were signed as
# Tr3kkR/Yuzu, the first release after the 2026-09-28 move (0.14.0-rc2) as
# DevNullLtd/Yuzu (docs/user-manual/release-verification.md). A checkout's
# origin (REPO_SLUG) can be a fork or the other era's name, so it must not
# decide who we trust. Parsing is strict and bounded: X.Y.Z[-(alpha|beta|rc)N],
# 1-4 digits per field, anything else is refused.
parse_signer_repo() {
  local v="$1" major minor
  [[ "$v" =~ ^([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})(-(alpha|beta|rc)[0-9]{1,4})?$ ]] \
    || return 1
  major=$((10#${BASH_REMATCH[1]})); minor=$((10#${BASH_REMATCH[2]}))
  if [ "$major" -eq 0 ] && [ "$minor" -le 13 ]; then
    printf '%s' 'Tr3kkR/Yuzu'
  else
    printf '%s' 'DevNullLtd/Yuzu'
  fi
}
[[ "$VERSION" =~ ^([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})(-(alpha|beta|rc)[0-9]{1,4})?$ ]] \
  || die "malformed --version '$VERSION' (want X.Y.Z or X.Y.Z-{alpha,beta,rc}N, 1-4 digits per field)"
ERA_SIGNER_REPO="$(parse_signer_repo "$VERSION")" || ERA_SIGNER_REPO=""
if [ -z "$SIGNER_REPO" ]; then
  [ -n "$ERA_SIGNER_REPO" ] || die "cannot derive the signer repo for version '$VERSION'; pass --signer-repo owner/repo"
  SIGNER_REPO="$ERA_SIGNER_REPO"
fi
[[ "$SIGNER_REPO" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] \
  || die "malformed --signer-repo '$SIGNER_REPO' (want owner/repo)"
if [ "$SIGNER_REPO" != "$ERA_SIGNER_REPO" ]; then
  warn "--signer-repo $SIGNER_REPO differs from the era table's $ERA_SIGNER_REPO for $VERSION."
  warn "Only a release you KNOW was built by that repo's release.yml should be verified this way;"
  warn "never copy a repo name out of a cosign error message."
fi
SIGNER_IDENTITY="https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG}"
SIGNER_ISSUER="https://token.actions.githubusercontent.com"

# ── Tooling ────────────────────────────────────────────────────────────────
if command -v sha256sum >/dev/null 2>&1; then SHACHK="sha256sum"
elif command -v shasum  >/dev/null 2>&1; then SHACHK="shasum -a 256"
else die "need sha256sum or shasum on PATH"; fi
if [ "$VERIFY_ONLY" = 0 ]; then
  command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
  command -v unzip  >/dev/null 2>&1 || die "need unzip on PATH (the windows archive is a .zip)"
fi
# cosign is mandatory: SHA256SUMS is only trustworthy once its signature is
# verified, so a missing cosign is a hard stop, never a skipped check.
command -v cosign >/dev/null 2>&1 || die "need cosign on PATH to verify SHA256SUMS' signature (no skip flag, by design) — install cosign v3 from the Sigstore releases (https://docs.sigstore.dev/cosign/system_config/installation/) or your package manager, and check 'cosign version' is v3.x (tested with v3.1.3; the release workflow uses v3.0.5; an older cosign may not read the .sigstore bundle)"
command -v gh >/dev/null 2>&1 || die "need the GitHub CLI (gh), authenticated, to download release assets — 'brew install gh && gh auth login'"

DL=""; SMOKE_TMP=""
cleanup() {
  if [ -n "$DL" ]; then rm -rf "$DL" 2>/dev/null || warn "could not remove the download dir $DL"; fi
  if [ -n "$SMOKE_TMP" ]; then rm -rf "$SMOKE_TMP" 2>/dev/null || warn "could not remove $SMOKE_TMP"; fi
  # Only the staging dir THIS run created (a --verify-only run never does); the
  # case guard confines the rm to our own mktemp'd name.
  if [ "${STAGING_OWNED:-0}" = 1 ]; then
    if [ "${KEEP_STAGING:-0}" = 1 ]; then
      info "staging kept at $STAGING"
    else
      case "$STAGING" in "$STAGING_PREFIX".??????) rm -rf "$STAGING" 2>/dev/null || warn "could not remove the staging dir $STAGING" ;; esac
    fi
  fi
}
trap cleanup EXIT

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Yuzu agent-bundle (chiselled delivery image)     ║"
echo "╚══════════════════════════════════════════════════╝"
info "version=$VERSION  tag=$TAG  repo=$REPO_SLUG  signer=$SIGNER_REPO"
info "image=$IMAGE_REF  push=$PUSH  multiarch=$MULTIARCH"

# ── 1. Download + verify release assets ────────────────────────────────────
# Download by glob so we match GitHub's *canonical* asset names: GitHub
# sanitises some characters on upload (e.g. the Debian '~' in 0.12.0~rc0 is
# served as '.', so for releases before 0.14.0-rc3 the name in SHA256SUMS !=
# the downloadable name; #5141 fixed that). Trust is established in two steps:
# (1) cosign verifies SHA256SUMS against SHA256SUMS.sigstore with the exact
# release.yml identity, BEFORE the manifest is read for anything; (2) each
# artifact's hash must equal the hash on ITS OWN line of that manifest, found by
# exact name (with a unique, explicit `~`->`.` fallback for pre-0.14.0-rc3).
DL="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-agent-bundle.XXXXXX")"

# The Windows and macOS archives are agent-only and named for it since
# ADR-0035 ladder step 2 (yuzu-agent-windows-x64.zip,
# yuzu-agent-macos-arm64.tar.gz). Earlier releases name them
# yuzu-windows-x64.zip / yuzu-macos-arm64.tar.gz and also hold the server,
# which extract_payload strips, so a hand-run against an older tag still
# works: both names are requested and whichever exists is used.
info "Downloading agent artifacts + SHA256SUMS for $VERSION (this is large)..."
gh release download "$TAG" --repo "$REPO_SLUG" -D "$DL" --clobber \
  -p 'yuzu-linux-x64.tar.gz' \
  -p 'yuzu-agent-windows-x64.zip' -p 'yuzu-agent-macos-arm64.tar.gz' \
  -p 'yuzu-windows-x64.zip' -p 'yuzu-macos-arm64.tar.gz' \
  -p 'yuzu-agent_*_amd64.deb' -p 'yuzu-agent-*.x86_64.rpm' \
  -p 'YuzuAgent-*-macos-arm64.pkg' -p 'YuzuAgentSetup-*.exe' \
  -p 'SHA256SUMS' -p 'SHA256SUMS.sigstore' -p 'SHA256SUMS.bundle' \
  || die "gh release download failed for $TAG (is gh authenticated? does $TAG exist?)"

# ── Authenticate SHA256SUMS before ANY use of it ───────────────────────────
if [ ! -s "$DL/SHA256SUMS.sigstore" ]; then
  if [ -s "$DL/SHA256SUMS.bundle" ]; then
    die "$TAG carries only the legacy SHA256SUMS.bundle (no SHA256SUMS.sigstore); this script verifies the .sigstore form only and will not trust an unverified SHA256SUMS — verify that release by hand: cosign verify-blob --bundle SHA256SUMS.bundle --certificate-identity https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG} --certificate-oidc-issuer ${SIGNER_ISSUER} SHA256SUMS"
  fi
  die "no SHA256SUMS.sigstore on $TAG; refusing to trust SHA256SUMS without its signature (releases v0.8.0-rc0 to v0.10.0 carry neither a .sigstore nor a .bundle and cannot be verified this way)"
fi
[ -s "$DL/SHA256SUMS" ] || die "no SHA256SUMS on $TAG"
info "Verifying SHA256SUMS signature (cosign, identity $SIGNER_IDENTITY)..."
if ! cosign verify-blob \
      --bundle "$DL/SHA256SUMS.sigstore" \
      --certificate-identity "$SIGNER_IDENTITY" \
      --certificate-oidc-issuer "$SIGNER_ISSUER" \
      "$DL/SHA256SUMS" 2>"$DL/cosign.err" >"$DL/cosign.out"; then
  fail "cosign verify-blob FAILED for $TAG (expected signer $SIGNER_REPO):"
  sed 's/^/     cosign: /' "$DL/cosign.err" >&2
  fail "The only legitimate signers are Tr3kkR/Yuzu (<= 0.13.x) and DevNullLtd/Yuzu (after)."
  fail "A mismatch on the default path means a tampered release or the wrong download source."
  fail "NEVER set --signer-repo to the subject cosign reports above."
  fail "Rule out first: cosign older than v3.x ('cosign version'), a wrong system clock, or a"
  fail "Sigstore/TUF network failure. There is no offline mode: check your proxy/DNS and re-run;"
  fail "if it persists for about an hour, or cosign reports an expired or unverifiable trusted"
  fail "root, treat it as permanent and update cosign."
  die "SHA256SUMS signature did not verify; refusing to use it"
fi
ok "SHA256SUMS signature verified (signer $SIGNER_REPO, $TAG)"

# Resolve the installer filenames as actually downloaded (post-sanitisation).
# A release can carry installers of SEVERAL versions (v0.13.0-rc6 ships the rc4
# and rc6 .deb/.rpm side by side), so each installer is chosen by the REQUESTED
# version: the exact file names that version can have, per package format
# (spellings seen on published releases, e.g. for 0.13.0-rc6):
#   .deb  yuzu-agent_0.13.0.rc6_amd64.deb   ('~' served as '.', before 0.14.0-rc3)
#         yuzu-agent_0.14.0-rc3_amd64.deb   (0.14.0-rc3 and later; '~' also tried)
#         yuzu-agent_0.15.0_amd64.deb       (stable)
#   .rpm  yuzu-agent-0.13.0-0.1.rc6.x86_64.rpm / yuzu-agent-0.15.0-1.x86_64.rpm
#   .pkg  YuzuAgent-0.13.0_rc6-macos-arm64.pkg / YuzuAgent-0.15.0-macos-arm64.pkg
#   .exe  YuzuAgentSetup-0.13.0_rc6.exe / YuzuAgentSetup-0.15.0.exe
# Exactly one candidate must exist; none or several is a hard stop that names
# them (done in the parent shell: a die inside $(...) would only end the subshell).
VER_BASE="${VERSION%%-*}"; VER_PRE=""
[ "$VER_BASE" = "$VERSION" ] || VER_PRE="${VERSION#*-}"
# select_installer <var> <label> <glob> <candidate>...
select_installer() {
  local var="$1" label="$2" glob="$3" c present; shift 3
  local -a hits=()
  for c in "$@"; do [ -e "$DL/$c" ] && hits+=("$c"); done
  case "${#hits[@]}" in
    1) printf -v "$var" '%s' "${hits[0]}" ;;
    0) present="$( (cd "$DL" && ls $glob 2>/dev/null) | tr '\n' ' ' || true)"
       die "no $label installer asset for $VERSION on $TAG (expected one of: $*; downloaded: ${present:-<none>})" ;;
    *) die "ambiguous: ${#hits[@]} $label installer assets match $VERSION on $TAG: ${hits[*]}" ;;
  esac
}
DEB=""; RPM=""; PKG=""; EXE=""
if [ -n "$VER_PRE" ]; then
  select_installer DEB ".deb" 'yuzu-agent_*_amd64.deb' \
    "yuzu-agent_${VER_BASE}.${VER_PRE}_amd64.deb" "yuzu-agent_${VER_BASE}-${VER_PRE}_amd64.deb" \
    "yuzu-agent_${VER_BASE}~${VER_PRE}_amd64.deb"
  select_installer RPM ".rpm" 'yuzu-agent-*.x86_64.rpm' "yuzu-agent-${VER_BASE}-0.1.${VER_PRE}.x86_64.rpm"
  select_installer PKG ".pkg" 'YuzuAgent-*-macos-arm64.pkg' "YuzuAgent-${VER_BASE}_${VER_PRE}-macos-arm64.pkg"
  select_installer EXE "Windows" 'YuzuAgentSetup-*.exe' "YuzuAgentSetup-${VER_BASE}_${VER_PRE}.exe"
else
  select_installer DEB ".deb" 'yuzu-agent_*_amd64.deb' "yuzu-agent_${VERSION}_amd64.deb"
  select_installer RPM ".rpm" 'yuzu-agent-*.x86_64.rpm' "yuzu-agent-${VERSION}-1.x86_64.rpm"
  select_installer PKG ".pkg" 'YuzuAgent-*-macos-arm64.pkg' "YuzuAgent-${VERSION}-macos-arm64.pkg"
  select_installer EXE "Windows" 'YuzuAgentSetup-*.exe' "YuzuAgentSetup-${VERSION}.exe"
fi
info "Installers selected for $VERSION: $DEB $RPM $PKG $EXE"
# `|| true`: with pipefail a pattern that matches nothing (the old archive names
# on a new release, or the reverse) would otherwise kill the script silently
# at the assignment instead of reaching the fallback / the named die below.
pick() { ( cd "$DL" && ls $1 2>/dev/null | head -1 ) || true; }
WIN_ZIP="$(pick 'yuzu-agent-windows-x64.zip')"; [ -n "$WIN_ZIP" ] || WIN_ZIP="$(pick 'yuzu-windows-x64.zip')"
MAC_TGZ="$(pick 'yuzu-agent-macos-arm64.tar.gz')"; [ -n "$MAC_TGZ" ] || MAC_TGZ="$(pick 'yuzu-macos-arm64.tar.gz')"
[ -n "$WIN_ZIP" ] || die "no Windows archive on $TAG"
[ -n "$MAC_TGZ" ] || die "no macOS archive on $TAG"
ARCHIVES="yuzu-linux-x64.tar.gz $WIN_ZIP $MAC_TGZ"

# sums_hashes <name> [sanitised]: print the hash of every SHA256SUMS line whose
# name field equals <name> exactly (fixed-string compare, no regex, no globbing;
# the name comes in via ENVIRON so awk -v escape processing never touches it).
# A line is `<64 hex>` + two spaces (text) or space + `*` (binary marker) +
# name. With `sanitised`, the line's `~` is read as `.` (GitHub served `~` as
# `.` before 0.14.0-rc3, #5141), so the downloaded name can be compared.
sums_hashes() {
  WANT="$1" MODE="${2:-exact}" awk '
    BEGIN { want = ENVIRON["WANT"]; san = (ENVIRON["MODE"] == "sanitised") }
    length($0) > 66 && substr($0, 65, 1) == " " && (substr($0, 66, 1) == " " || substr($0, 66, 1) == "*") {
      name = substr($0, 67)
      if (san) gsub(/~/, ".", name)
      if (name == want) print substr($0, 1, 64)
    }' "$DL/SHA256SUMS"
}

# Verify one artifact against ITS OWN line of the (already authenticated)
# manifest: exactly one name match, a 64 lower-case-hex hash, equal to ours.
verify_hash() {
  local f="$1" h want matches n
  [ -s "$DL/$f" ] || die "download missing or empty: $f"
  h="$($SHACHK "$DL/$f" | awk '{print $1}')" || die "cannot hash $f"
  matches="$(sums_hashes "$f" exact)" || matches=""
  if [ -z "$matches" ]; then
    matches="$(sums_hashes "$f" sanitised)" || die "cannot read SHA256SUMS while looking up $f"
    [ -n "$matches" ] || die "no line for $f in SHA256SUMS (a hash on another file's line does not count)"
  fi
  n="$(printf '%s\n' "$matches" | wc -l | tr -d ' ')"
  [ "$n" = 1 ] || die "ambiguous: $n SHA256SUMS lines match the name $f"
  want="$matches"
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "malformed hash on the SHA256SUMS line for $f"
  [ "$h" = "$want" ] || die "hash MISMATCH against its own SHA256SUMS line (corrupt or tampered): $f"
}
info "Verifying each download against its own line of the authenticated SHA256SUMS..."
for a in $ARCHIVES "$DEB" "$RPM" "$PKG" "$EXE"; do verify_hash "$a"; done
ok "All 7 artifacts match their own SHA256SUMS line (manifest signature verified)"

if [ "$VERIFY_ONLY" = 1 ]; then
  ok "--verify-only: $TAG verified (signer $SIGNER_REPO); stopping before any build"
  exit 0
fi

# Best-effort provenance attestation (does not gate the build).
if gh attestation verify "$DL/yuzu-linux-x64.tar.gz" --repo "$REPO_SLUG" >/dev/null 2>&1; then
  ok "SLSA provenance attestation verified (gh attestation)"
else
  warn "Could not verify provenance attestation (offline, or gh too old) — continuing on SHA256 only"
fi

# ── 2. Lay out the /opt/yuzu-agents tree ───────────────────────────────────
info "Laying out the bundle tree..."
STAGING="$(mktemp -d "$REPO_ROOT/$STAGING_PREFIX.XXXXXX")" || die "cannot create a staging dir under $REPO_ROOT/deploy/docker"
STAGING="${STAGING#"$REPO_ROOT"/}"            # relative, so the cleanup case guard matches
STAGING_OWNED=1
BUNDLE_ROOT="$STAGING/yuzu-agents"
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
extract_payload windows-x64 "$WIN_ZIP" zip
extract_payload macos-arm64 "$MAC_TGZ" tar

{ cp "$DL/$DEB" "$BUNDLE_ROOT/linux-x64/installers/" \
  && cp "$DL/$RPM" "$BUNDLE_ROOT/linux-x64/installers/" \
  && cp "$DL/$PKG" "$BUNDLE_ROOT/macos-arm64/installers/" \
  && cp "$DL/$EXE" "$BUNDLE_ROOT/windows-x64/installers/" \
  && cp "$DL/SHA256SUMS" "$BUNDLE_ROOT/UPSTREAM-SHA256SUMS" \
  && cp "$DL/SHA256SUMS.sigstore" "$BUNDLE_ROOT/UPSTREAM-SHA256SUMS.sigstore" \
  && printf '%s\n' "$VERSION" > "$BUNDLE_ROOT/VERSION"; } \
  || die "cannot copy the verified release files into $BUNDLE_ROOT (disk full or not writable?)"

# ── 3. READMEs (per-OS install + how to point at the gateway) ───────────────
cat > "$BUNDLE_ROOT/README.txt" <<EOF
Yuzu Agent Bundle — ${VERSION}
==============================================================================
Three agent triplets, all at version ${VERSION} (matching the Yuzu server and
gateway of the same version):

  linux-x64     Linux   x86_64          (glibc)
  windows-x64   Windows x86_64          (MSVC, NOT Authenticode-signed today, #239)
  macos-arm64   macOS   Apple Silicon   (NOT signed or notarized)

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
  What each check proves (the Windows and macOS binaries are not code-signed,
  so these are the only authenticity checks there are):
  - SHA256SUMS, below: THIS tree is internally consistent. Anyone who edits
    the tree can regenerate it, so it does NOT show the tree is genuine.
  - UPSTREAM-SHA256SUMS(.sigstore): the release archives and installers the
    build downloaded matched the signed ${TAG} release manifest. It does not
    cover payload/ as laid out here.
  - The bundle IMAGE signature: the only check that covers what you extracted.
    Verify the image you pulled BEFORE trusting or running anything in it
    (published by CI; a hand-built image is not signed):
      cosign verify ${IMAGE_REF} \\
        --certificate-identity https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG} \\
        --certificate-oidc-issuer ${SIGNER_ISSUER}

  SHA256SUMS           checksums of every file in THIS tree
  UPSTREAM-SHA256SUMS  the checksums from the ${TAG} GitHub release; this
                       script verified them before use (cosign, signer
                       ${SIGNER_REPO}, release.yml @ ${TAG})
  UPSTREAM-SHA256SUMS.sigstore  the cosign bundle for that file. Re-verify:
    cosign verify-blob --bundle UPSTREAM-SHA256SUMS.sigstore \\
      --certificate-identity ${SIGNER_IDENTITY} \\
      --certificate-oidc-issuer ${SIGNER_ISSUER} UPSTREAM-SHA256SUMS
    (This needs network access to Sigstore's TUF root, or a local --trusted-root;
    it is absent from bundles built before this check existed.)
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
Yuzu Agent — macos-arm64 — ${VERSION}  (Apple Silicon, NOT signed or notarized)
==============================================================================
DEMO (no-TLS stack, foreground) — simplest:
  cd payload
  DYLD_LIBRARY_PATH="\$PWD/bin" ./bin/yuzu-agent \\
    --server <GATEWAY_HOST>:50051 --no-tls \\
    --enrollment-token <TOKEN> \\
    --plugin-dir "\$PWD/plugins" --data-dir ./data --log-level info
  # The macOS agent is NOT signed or notarized (see docs/agent-bundle.md), so
  # Gatekeeper will quarantine copied files. The sha256 files in this bundle only
  # show it is internally consistent; what authenticates payload/ is the bundle
  # IMAGE signature. Clear quarantine only after this succeeds on the image you
  # pulled (CI-published images only):
  #   cosign verify ${IMAGE_REF} \\
  #     --certificate-identity https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG} \\
  #     --certificate-oidc-issuer ${SIGNER_ISSUER}
  # then:
  #   xattr -dr com.apple.quarantine ./bin ./plugins

PERSISTENT (launchd daemon via the .pkg; the .pkg is not signed or notarized either):
  sudo installer -pkg installers/${PKG} -target /
  Edit /Library/LaunchDaemons/com.yuzu.agent.plist — add to <ProgramArguments>:
    --server <GATEWAY_HOST>:50051   --enrollment-token <TOKEN>
    (and --no-tls if connecting to the no-TLS demo stack)
  then reload:
    sudo launchctl bootout   system /Library/LaunchDaemons/com.yuzu.agent.plist 2>/dev/null || true
    sudo launchctl bootstrap system /Library/LaunchDaemons/com.yuzu.agent.plist
EOF

cat > "$BUNDLE_ROOT/windows-x64/README.txt" <<EOF
Yuzu Agent — windows-x64 — ${VERSION}  (NOT Authenticode-signed today, #239)
==============================================================================
DEMO (no-TLS stack, foreground) — PowerShell:
  cd payload
  .\\bin\\yuzu-agent.exe --server <GATEWAY_HOST>:50051 --no-tls \`
    --enrollment-token <TOKEN> --plugin-dir .\\plugins --data-dir .\\data --log-level info
  # the runtime DLLs the agent needs sit next to the .exe in bin\\

PERSISTENT (Windows service via the installer; it is not Authenticode-signed today,
so SmartScreen may warn, see #239 and docs/agent-bundle.md):
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
    SMOKE_TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-bundle-test.XXXXXX")"; t="$SMOKE_TMP"
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
    rm -rf "$t"; SMOKE_TMP=""
    ok "Smoke test passed (self-extract + 3 agent binaries + checksums)"
  fi

  if [ "$PUSH" = 1 ]; then
    info "Pushing $IMAGE_REF..."
    docker push "$IMAGE_REF"
    ok "Pushed $IMAGE_REF"
  fi
fi

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
