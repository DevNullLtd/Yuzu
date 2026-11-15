# Release Verification

Every Yuzu release ships a verifiable supply-chain bundle: cryptographic
signatures, SLSA build provenance, and Software Bill of Materials (SBOM)
documents in both CycloneDX and SPDX formats. This page documents the
commands an operator or procurement reviewer runs to verify each piece.

All examples assume you have downloaded the release assets from
<https://github.com/DevNullLtd/Yuzu/releases> into the current directory, and
that the tag under verification is `v0.11.0`. Substitute as needed.

> **Warning: older release pages show a wildcard command.** The GitHub release
> pages for v0.7.0-rc1 to v0.15.0 (18 of the 22 pages published in that range,
> all published before the fix in #7529) print a `cosign verify-blob` command
> whose identity is a wildcard (`--certificate-identity-regexp '.*'`); the other
> 4 carry no cosign command. A wildcard accepts a signature from
> any GitHub repository, so it proves almost nothing. Do not copy it: use the
> exact, tag-bound commands on this page.

## Which owner applies to your release

Yuzu moved from the personal account `Tr3kkR` to the `DevNullLtd` organisation
on **2026-09-28**. That changes two things a verifier must get right, and they
move together:

| | Releases up to **v0.13.0** | Releases after **2026-09-28** |
|---|---|---|
| Image namespace (`OWNER`) | `tr3kkr` | `devnullltd` |
| Signing identity (`SIGNER_REPO`) | `Tr3kkR/Yuzu` | `DevNullLtd/Yuzu` |

The signing identity is baked into the Fulcio certificate's SAN at build time
and is **not** rewritten by GitHub's redirect, so verifying a v0.13.0 artifact
against `DevNullLtd/Yuzu` fails, and vice versa. Every command below reads
these two shell variables — set them once for the release you are verifying:

```bash
# Releases up to v0.13.0 (the worked example below, v0.11.0, is one of these):
OWNER=tr3kkr;      SIGNER_REPO=Tr3kkR/Yuzu

# Releases after 2026-09-28:
# OWNER=devnullltd; SIGNER_REPO=DevNullLtd/Yuzu
```

Image *pulls* do **not** follow this split: every historical tag was mirrored
into `ghcr.io/devnullltd/` on 2026-09-29, so `OWNER=devnullltd` works for every
release. `ghcr.io/tr3kkr/` is retained read-only for anything already pinned to
it. Only the SIGNING IDENTITY is era-dependent, because it is fixed in the
certificate at build time and cannot be restamped.

## What ships with every release

| Asset type | Files | Verified with |
|------------|-------|---------------|
| Platform archives | `yuzu-linux-x64.tar.gz`, `yuzu-gateway-linux-x64.tar.gz`, `yuzu-agent-windows-x64.zip`, `yuzu-agent-macos-arm64.tar.gz` (the Windows and macOS archives hold the agent only, and were named `yuzu-windows-x64.zip` / `yuzu-macos-arm64.tar.gz` in earlier releases) | `sha256sum -c SHA256SUMS` |
| Native installers | `*.deb`, `*.rpm`, `YuzuAgentSetup-*.exe`, `YuzuAgent-*.pkg` (`YuzuServerSetup-*.exe` was discontinued: the server runs on Linux only, ADR-0035) | `sha256sum -c SHA256SUMS` |
| Checksum manifest | `SHA256SUMS` | `cosign verify-blob` against `SHA256SUMS.sigstore` |
| Cosign bundle | `SHA256SUMS.sigstore` (legacy filename `SHA256SUMS.bundle`: the only name on v0.7.x; v0.11.0-rc1 to v0.11.0 carry both) | Sigstore OIDC identity |
| CycloneDX SBOMs | `yuzu-*.cdx.json`, including the images: `yuzu-{server,gateway,postgres}-image.cdx.json` and `yuzu-{server,gateway,agent}-chisel-image.cdx.json` | `cyclonedx validate` |
| SPDX SBOMs | `yuzu-*.spdx.json`, including the same image set | `spdx-tools validate` |
| SLSA provenance | `<artifact>.intoto.jsonl` per asset (also in GitHub's attestation registry) | `gh attestation verify` |
| Docker images | `ghcr.io/${OWNER}/yuzu-{server,gateway,postgres}:<tag>` and `ghcr.io/${OWNER}/yuzu-{server,gateway,agent}-chisel:<tag>` | `cosign verify` |

## Prerequisites

```bash
# GitHub CLI for attestation verification
#   Ubuntu/Debian: sudo apt install gh
#   macOS:         brew install gh
#   Windows:       winget install --id GitHub.cli

# cosign v2.6.2 or later, for Sigstore signature verification
#   Ubuntu/Debian: curl -sSLO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 && chmod +x cosign-*
#   macOS:         brew install cosign
#   Windows:       winget install --id Sigstore.Cosign

# (Optional) CycloneDX CLI for SBOM validation
#   npm install -g @cyclonedx/cyclonedx-cli
```

No long-lived keys are required. All signatures are keyless (Sigstore /
Fulcio) and bound to the GitHub Actions OIDC identity of the release
workflow that produced them.

## 1. Checksum verification (fastest)

Every release ships a `SHA256SUMS` manifest covering every archive,
installer, and SBOM.

```bash
sha256sum -c SHA256SUMS
```

All lines should print `OK`. This catches corruption but does **not**
prove authenticity — use the cosign step below for that.

## 2. Verify the checksum manifest signature (cosign)

`SHA256SUMS.sigstore` is a Sigstore cosign bundle proving `SHA256SUMS`
was signed by the GitHub Actions workflow that produced this release.

```bash
# TAG is the exact tag of the release you downloaded
TAG=v0.11.0
cosign verify-blob \
  --bundle SHA256SUMS.sigstore \
  --certificate-identity "https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

The identity is an exact match, bound to the tag: a signature from a
different tag of the same repository (an older or a downgraded release)
does not verify. Use the `SIGNER_REPO` for your release's era (the table
above); never take it from an error message.

On success: `Verified OK`. Combined with step 1, this proves every
listed asset is exactly what the workflow produced.

## 3. Verify Docker image signatures (cosign)

```bash
# same TAG as step 2
cosign verify \
  --certificate-identity "https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/${OWNER}/yuzu-server:${TAG#v}

cosign verify \
  --certificate-identity "https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/${OWNER}/yuzu-gateway:${TAG#v}
```

Output includes the signing certificate's SAN
(`https://github.com/<SIGNER_REPO>/.github/workflows/release.yml@refs/tags/v0.11.0`),
the Rekor log entry, and the image digest. Pin by digest for production
deployments:

```bash
docker pull ghcr.io/${OWNER}/yuzu-server:0.11.0
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/${OWNER}/yuzu-server:0.11.0
# → ghcr.io/${OWNER}/yuzu-server@sha256:...
```

## 4. Verify SLSA build provenance (GitHub attestations)

Every binary archive, installer, and Docker image has a SLSA v1.0 build
provenance attestation stored in GitHub's native attestation registry.
The provenance records the exact workflow run, commit, builder, and
inputs used to produce the artifact.

```bash
# Binary archives / installers
gh attestation verify yuzu-linux-x64.tar.gz --repo "${SIGNER_REPO}"
gh attestation verify YuzuAgentSetup-0.11.0.exe --repo "${SIGNER_REPO}"
gh attestation verify yuzu-agent-macos-arm64.tar.gz --repo "${SIGNER_REPO}"

# Docker images (by digest)
gh attestation verify \
  oci://ghcr.io/${OWNER}/yuzu-server@sha256:<digest> \
  --repo "${SIGNER_REPO}"
```

Success prints the attestation's predicate type
(`https://slsa.dev/provenance/v1`), builder ID
(`https://github.com/actions/runner`), and the source repository +
commit SHA that produced the artifact.

**Offline / air-gapped verification.** Download the attestation bundle
with `gh attestation download <file> --repo "$SIGNER_REPO" -o
<file>.jsonl`, then verify offline with
`gh attestation verify --bundle <file>.jsonl <file>`.

## 5. Inspect the SBOM

Each platform archive and Docker image ships SBOMs in both CycloneDX
and SPDX formats. Use whichever your procurement or SCA tool consumes.

**Known limitations of the platform SBOMs.** They are generated from the whole
build workspace (the vcpkg ports tree and build trees included), not from the
archive alone, so they can list components the archive does not ship or load.
A finding in a component the archive does not contain does not apply to it.
Since ADR-0035 step 3 the Windows and macOS builds install only the agent's
dependencies, so the server's dependencies (`libpq`, `drogon`, `xmlsec`) are no
longer installed on those build machines and the Windows agent archive carries
none of their DLLs (the Windows release build's "Verify the agent runs from the packaged archive" step
refuses an archive that does; it has not yet run on a real release tag). What a
given release's SBOM lists beyond the archive is not asserted here: inspect the
SBOM of the release you verify.

```bash
# List all components + versions (CycloneDX, pretty-printed)
jq -r '.components[] | "\(.name)\t\(.version)"' yuzu-linux-x64.cdx.json | column -t

# Validate CycloneDX 1.6 schema
cyclonedx validate --input-file yuzu-linux-x64.cdx.json

# Count components
jq '.components | length' yuzu-linux-x64.cdx.json

# Find all dependencies declaring a specific license
jq -r '.components[] | select(.licenses[]?.license.id == "MIT") | .name' \
  yuzu-linux-x64.cdx.json
```

### SPDX

```bash
jq -r '.packages[] | "\(.name)\t\(.versionInfo)"' yuzu-linux-x64.spdx.json | column -t
```

### Docker image SBOMs

```bash
jq '.components | length' yuzu-server-image.cdx.json
jq -r '.components[] | "\(.name)@\(.version)"' yuzu-server-image.cdx.json | sort -u
```

## 6. End-to-end verification script

Drop-in script that runs steps 1–4 for a Linux x64 release download:

```bash
#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?usage: verify.sh <version, e.g. 0.11.0>}"

# Pick the pair for the release under verification -- see "Which owner applies
# to your release". These MUST move together: OWNER decides where the image
# lives, SIGNER_REPO decides what the certificate SAN must say.
OWNER="${OWNER:-tr3kkr}"                   # devnullltd for releases after 2026-09-28
SIGNER_REPO="${SIGNER_REPO:-Tr3kkR/Yuzu}"  # DevNullLtd/Yuzu for the same

IDENTITY="https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/v${VERSION#v}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

echo "→ sha256sum -c SHA256SUMS"
sha256sum -c SHA256SUMS

echo "→ cosign verify-blob (SHA256SUMS)"
cosign verify-blob \
  --bundle SHA256SUMS.sigstore \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  SHA256SUMS

echo "→ cosign verify (Docker images)"
for img in server gateway; do
  cosign verify \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "ghcr.io/${OWNER}/yuzu-${img}:${VERSION}" >/dev/null
  echo "  ghcr.io/${OWNER}/yuzu-${img}:${VERSION} OK"
done

echo "→ gh attestation verify (binary archives)"
for f in yuzu-linux-x64.tar.gz yuzu-gateway-linux-x64.tar.gz; do
  [[ -f "$f" ]] && gh attestation verify "$f" --repo "${SIGNER_REPO}"
done

echo "✓ all checks passed for v${VERSION}"
```

## Enterprise compliance mapping

| Framework / ask | Covered by |
|-----------------|------------|
| SOC 2 CC6.8 (integrity of software) | cosign image + blob signatures |
| SOC 2 CC7.1 (change management traceability) | SLSA provenance attestation |
| NIST SSDF PW.5 (archive / protect) | SHA256SUMS + signed manifest |
| NIST SSDF PS.3 (provide provenance) | SLSA v1.0 attestation |
| Executive Order 14028 (SBOM for federal sales) | CycloneDX + SPDX SBOMs per artifact |
| ISO/IEC 5962 (SPDX conformance) | SPDX 2.3 SBOMs |
| EU CRA Annex V | Provenance + SBOM + signed artefact bundle |

## Troubleshooting

**`cosign verify-blob: no matching signatures` / `certificate identity
mismatch`** — do NOT widen the identity to a wildcard; that accepts a
signature from any workflow. Check, in order: the release carries no signature
file (v0.8.0-rc0 to v0.10.0 have neither a `.sigstore` nor a `.bundle`); `TAG` is not exactly the
tag you downloaded; or `SIGNER_REPO` is wrong for the era (`Tr3kkR/Yuzu` up to
0.13.x, `DevNullLtd/Yuzu` after). The only legitimate signers are those two
repositories: if the default for the release's era fails, treat the download
as suspect (wrong source or tampered), and never set `SIGNER_REPO` to the
subject cosign prints. A network error reaching Sigstore's TUF root usually
clears on a re-run (cosign needs network access to the TUF root, or a local
`--trusted-root`; there is no offline mode in `scripts/build-agent-bundle.sh`); if
it persists for about an hour, or cosign reports an expired or unverifiable
trusted root, update cosign (v2.6.2 or later) instead of waiting.

**`SHA256SUMS.sigstore: no such file`** — the v0.7.x releases ship the
bundle only under the legacy filename `SHA256SUMS.bundle`; v0.8.0-rc0 to
v0.10.0 ship neither file (no signature to verify). v0.11.0-rc1, -rc2 and
v0.11.0 carry both names side-by-side (byte-identical bundles, either can be
passed to `cosign verify-blob --bundle`); v0.12.0 onwards ship only the
canonical `.sigstore` filename. `scripts/build-agent-bundle.sh` performs the
same exact-identity check on `SHA256SUMS.sigstore` and refuses any release
without it (see [the agent bundle guide](../agent-bundle.md)).

**`gh attestation verify: no attestations found`** — run `gh auth login`
first; the GitHub CLI must be able to query
`/repos/<SIGNER_REPO>/attestations`. Unauthenticated queries are
rate-limited and can return empty lists.

**`cyclonedx validate: unable to parse`** — the CycloneDX CLI pins to
CycloneDX 1.5 by default; Yuzu ships CycloneDX 1.6. Upgrade the CLI
(`npm i -g @cyclonedx/cyclonedx-cli@latest`) or use `jq` for structural
validation (`jq empty yuzu-linux-x64.cdx.json`).

## References

- Sigstore / cosign: <https://docs.sigstore.dev/>
- SLSA v1.0: <https://slsa.dev/spec/v1.0/provenance>
- CycloneDX: <https://cyclonedx.org/>
- SPDX: <https://spdx.dev/>
- GitHub Artifact Attestations: <https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds>
- Syft (Anchore): <https://github.com/anchore/syft>
