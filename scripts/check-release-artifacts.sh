#!/usr/bin/env bash
# Verify every expected Yuzu release artifact has a CycloneDX + SPDX
# SBOM before `gh release create` runs. Fails fast (exit 1) if any
# expected asset is missing so the release job stops before publishing
# a partial release — the same failure mode #362 / #408 were opened to
# prevent.
#
# Usage:
#   scripts/check-release-artifacts.sh <artifacts-dir> [<release-version>]
#   scripts/check-release-artifacts.sh artifacts 0.14.0-rc3
#
# With <release-version> (the tag without its leading "v") it also checks
# every package/installer name carries that version, so a file left in a
# reused build workspace by an earlier release cannot ship (#5141).
#
# Expected contents of <artifacts-dir> after the flatten step:
#
#   Archives / installers (one each):
#     yuzu-linux-x64.tar.gz
#     yuzu-gateway-linux-x64.tar.gz
#     yuzu-windows-x64.zip
#     yuzu-macos-arm64.tar.gz
#
#   Glob archives (at least one match each):
#     *.deb                     (linux server+agent+gateway)
#     *.rpm                     (linux server+agent+gateway)
#     YuzuAgentSetup-*.exe      (Windows agent installer)
#     YuzuServerSetup-*.exe     (Windows server installer)
#     YuzuAgent-*.pkg           (macOS agent installer)
#
#   Per-platform SBOMs (matching the 4 archives above):
#     yuzu-linux-x64.cdx.json        + .spdx.json
#     yuzu-gateway-linux-x64.cdx.json + .spdx.json
#     yuzu-windows-x64.cdx.json       + .spdx.json
#     yuzu-macos-arm64.cdx.json       + .spdx.json
#
#   Image SBOMs:
#     yuzu-server-image.cdx.json   + .spdx.json
#     yuzu-gateway-image.cdx.json  + .spdx.json
#     yuzu-postgres-image.cdx.json + .spdx.json   (#1318)
#
# Every file's name must also be one GitHub stores unchanged
# ([A-Za-z0-9._-], not starting with "."), or SHA256SUMS and the
# provenance subjects would name an asset that does not exist.
#
# Emits GitHub Actions `::error file=...` annotations so failures show
# up inline on the release run summary.

set -euo pipefail

if [[ $# -lt 1 || -z "${1:-}" ]]; then
  echo "usage: $0 <artifacts-dir>" >&2
  exit 2
fi

ART_DIR="$1"
RELEASE_VERSION="${2:-}"

if [[ ! -d "$ART_DIR" ]]; then
  echo "::error::artifacts directory not found: $ART_DIR" >&2
  exit 1
fi

fail=0

# ── Required single-file archives ────────────────────────────────────
REQUIRED_ARCHIVES=(
  "yuzu-linux-x64.tar.gz"
  "yuzu-gateway-linux-x64.tar.gz"
  "yuzu-windows-x64.zip"
  "yuzu-macos-arm64.tar.gz"
)

for f in "${REQUIRED_ARCHIVES[@]}"; do
  if [[ ! -f "$ART_DIR/$f" ]]; then
    echo "::error::missing required archive: $f" >&2
    fail=1
  fi
done

# ── Required glob archives (at least one match) ──────────────────────
REQUIRED_GLOBS=(
  "*.deb"
  "*.rpm"
  "YuzuAgentSetup-*.exe"
  "YuzuServerSetup-*.exe"
  "YuzuAgent-*.pkg"
)

for pat in "${REQUIRED_GLOBS[@]}"; do
  # shellcheck disable=SC2206 # intentional globbing
  matches=( "$ART_DIR"/$pat )
  if [[ ! -e "${matches[0]}" ]]; then
    echo "::error::no files match required pattern: $pat" >&2
    fail=1
  fi
done

# ── SBOMs (CycloneDX + SPDX) for every archive base ─────────────────
# Base names map 1:1 to the per-platform SBOMs emitted by the build
# jobs. Image SBOMs use a different naming convention (see below).
SBOM_BASES=(
  "yuzu-linux-x64"
  "yuzu-gateway-linux-x64"
  "yuzu-windows-x64"
  "yuzu-macos-arm64"
  "yuzu-server-image"
  "yuzu-gateway-image"
  # yuzu-postgres joined the release images in #1318; docker-publish-postgres
  # is in the release job's needs, so its SBOM artifact must be present.
  "yuzu-postgres-image"
)

for base in "${SBOM_BASES[@]}"; do
  for fmt in cdx.json spdx.json; do
    f="${base}.${fmt}"
    if [[ ! -f "$ART_DIR/$f" ]]; then
      echo "::error::missing SBOM: $f" >&2
      fail=1
    elif [[ ! -s "$ART_DIR/$f" ]]; then
      echo "::error::SBOM is empty: $f" >&2
      fail=1
    fi
  done
done

# ── Sanity check: SBOMs parse as JSON ────────────────────────────────
# `jq` is available on ubuntu-24.04 runners. If absent we skip rather
# than fail — the structural check is a bonus, not the contract.
if command -v jq >/dev/null 2>&1; then
  for f in "$ART_DIR"/*.cdx.json "$ART_DIR"/*.spdx.json; do
    [[ -f "$f" ]] || continue
    if ! jq empty "$f" >/dev/null 2>&1; then
      echo "::error file=$f::SBOM is not valid JSON" >&2
      fail=1
    fi
  done
fi

# ── Asset names: stored by GitHub unchanged, and all from THIS release ──
# Two ways a published name has gone wrong, both shipped before this gate:
#  - GitHub silently rewrites characters outside [A-Za-z0-9._-] in asset
#    names (a "~" becomes "."), so the stored asset no longer matches the
#    name in SHA256SUMS or its provenance subject (#5141, rc1/rc2 .debs).
#  - build-linux runs in a reused self-hosted workspace (clean: false), and
#    a package left there by an earlier release was uploaded, attested and
#    checksummed as this release's output (v0.13.0-rc6 shipped rc4 .debs
#    and .rpms).
# So every file must have a GitHub-safe name, and every package/installer
# must carry this release's version in the form its builder writes.
for f in "$ART_DIR"/*; do
  [[ -f "$f" ]] || continue
  name="${f##*/}"
  if [[ ! "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "::error file=$name::asset name contains a character GitHub rewrites on upload (allowed: A-Z a-z 0-9 . _ -)" >&2
    fail=1
  fi
done

if [[ -n "$RELEASE_VERSION" ]]; then
  base="${RELEASE_VERSION%%-*}"
  pre=""
  [[ "$RELEASE_VERSION" == *-* ]] && pre="${RELEASE_VERSION#*-}"
  underscored="${RELEASE_VERSION//-/_}"
  if [[ -n "$pre" ]]; then rpm_rel="0.1.${pre}"; else rpm_rel="1"; fi
  for f in "$ART_DIR"/*.deb "$ART_DIR"/*.rpm "$ART_DIR"/*.exe "$ART_DIR"/*.pkg; do
    [[ -f "$f" ]] || continue
    name="${f##*/}"
    case "$name" in
      *.deb) [[ "$name" == *_"${RELEASE_VERSION}"_*.deb ]] ;;
      *.rpm) [[ "$name" == *-"${base}"-"${rpm_rel}".*.rpm ]] ;;
      *.exe) [[ "$name" == *-"${underscored}".exe ]] ;;
      *.pkg) [[ "$name" == *-"${underscored}"-*.pkg ]] ;;
    esac || {
      echo "::error file=$name::package is not from release ${RELEASE_VERSION} (stale file from an earlier build in the workspace?)" >&2
      fail=1
    }
  done
fi

if (( fail )); then
  echo ""
  echo "::error::release artifact completeness gate FAILED — see errors above" >&2
  exit 1
fi

echo "Release artifact completeness gate: OK"
echo "  archives:         ${#REQUIRED_ARCHIVES[@]} required files present"
echo "  installers/pkgs:  ${#REQUIRED_GLOBS[@]} required globs satisfied"
echo "  SBOMs:            ${#SBOM_BASES[@]} bases × 2 formats (CycloneDX + SPDX) present"
if [[ -n "$RELEASE_VERSION" ]]; then
  echo "  asset names:      GitHub-safe; every package is from ${RELEASE_VERSION}"
else
  echo "  asset names:      GitHub-safe (no version given: package versions not checked)"
fi
