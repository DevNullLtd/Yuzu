# Release Verification

Yuzu releases ship a verifiable supply-chain bundle: cryptographic
signatures, SLSA build provenance, and Software Bill of Materials (SBOM)
documents in both CycloneDX and SPDX formats. Not every release, and not
every asset of a release, carries every piece: older releases lack some of
them, and provenance covers only the build outputs (section 4 says which).
This page documents the commands an operator or procurement reviewer runs to
verify each piece.

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

## What a release ships

| Asset type | Files | Verified with |
|------------|-------|---------------|
| Platform archives | `yuzu-linux-x64.tar.gz`, `yuzu-gateway-linux-x64.tar.gz`, `yuzu-agent-windows-x64.zip`, `yuzu-agent-macos-arm64.tar.gz` (the Windows and macOS archives hold the agent only, and were named `yuzu-windows-x64.zip` / `yuzu-macos-arm64.tar.gz` in earlier releases) | `sha256sum -c SHA256SUMS` |
| Native installers | `*.deb`, `*.rpm`, `YuzuAgentSetup-*.exe`, `YuzuAgent-*.pkg` (`YuzuServerSetup-*.exe` was discontinued: the server runs on Linux only, ADR-0035) | `sha256sum -c SHA256SUMS` |
| Checksum manifest | `SHA256SUMS` | `cosign verify-blob` against `SHA256SUMS.sigstore` |
| Cosign bundle | `SHA256SUMS.sigstore` (legacy filename `SHA256SUMS.bundle`: the only name on v0.7.x; v0.11.0-rc1 to v0.11.0 carry both) | Sigstore OIDC identity |
| CycloneDX SBOMs | One per binary archive, package and installer (the Compose Wizard zip, first-party HTML and JavaScript, has none), named after the file without its extension (`yuzu-linux-x64.cdx.json`, `yuzu-agent_X.Y.Z_amd64.cdx.json`, `YuzuAgentSetup-X.Y.Z.cdx.json`, ...), and one per image: `yuzu-{server,gateway,postgres}-image.cdx.json` and `yuzu-{server,gateway,agent}-chisel-image.cdx.json` | `cyclonedx validate` |
| SPDX SBOMs | `*.spdx.json`, the same set | `spdx-tools validate` |
| SLSA provenance | `<artifact>.intoto.jsonl` where present: the platform archives and native installers of v0.11.0-rc2 and later (the Docker images' provenance is in GitHub's attestation registry only; which releases the registry holds is in section 4) | `gh attestation verify` |
| Docker images | `ghcr.io/${OWNER}/yuzu-{server,gateway,postgres}:<tag>` and `ghcr.io/${OWNER}/yuzu-{server,gateway,agent}-chisel:<tag>` | `cosign verify` |

## Prerequisites

```bash
# GitHub CLI 2.102.0 or later, for attestation verification (check: gh --version)
#   Linux:   GitHub's official packages, https://github.com/cli/cli/blob/trunk/docs/install_linux.md
#            (a distribution's own gh package is often older than 2.102.0)
#   macOS:   brew install gh
#   Windows: winget install --id GitHub.cli

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

Which assets have a SLSA v1.0 build provenance attestation depends on the
release:

| Releases | Attested assets | Where the attestation is |
|---|---|---|
| v0.14.0-rc2 and later (built as `DevNullLtd/Yuzu`) | every platform archive, native installer and Docker image | GitHub's attestation registry; the archives and installers also ship it as `<asset>.intoto.jsonl` |
| v0.11.0-rc2 to v0.13.0 (built as `Tr3kkR/Yuzu`) | every platform archive and native installer (this page gives no way to verify these releases' Docker image provenance) | the `<asset>.intoto.jsonl` release asset. On 2026-11-18 GitHub's attestation API returned no attestation for the Linux archive of v0.11.0, v0.12.0 or v0.13.0, so verify these from the asset with `--bundle` (the offline procedure below) |
| v0.11.0-rc1 and earlier | none | — |

The worked example on this page, v0.11.0, is in the second row: add
`--bundle <asset>.intoto.jsonl` to the commands below (for example
`--bundle yuzu-linux-x64.tar.gz.intoto.jsonl`), having downloaded that asset
with the archive.

In no release are the SBOMs, `SHA256SUMS`, its `.sigstore` bundle or the
Compose Wizard zip attested: the SBOMs and the wizard zip are covered by
`SHA256SUMS` (section 1), and `SHA256SUMS` by its cosign signature
(section 2). An asset with no attestation fails `gh attestation verify`; it
never passes it. The provenance records the exact workflow run, commit,
builder, and inputs used to produce the artifact.

**Use gh 2.102.0 or later.** Every command below pins the attestation to
`release.yml` at this release's tag with `--signer-workflow` and
`--source-ref`; `--repo` alone accepts an attestation from any workflow in the
repository. Older gh versions do not enforce those two flags as written:
before 2.68.0 `--source-ref` does not exist; before 2.97.0 the
`--signer-workflow` value is used as an unescaped regular expression; and
before 2.102.0 it is matched only against the start of the certificate's
identity, and `--source-ref` is compared case-insensitively (GitHub CLI
advisories GHSA-mm27-mwq9-fr5g, GHSA-wjmr-j3rp-mh2g and GHSA-4mq3-hpgx-9cx8).

```bash
# Binary archives / installers
gh attestation verify yuzu-linux-x64.tar.gz --repo "${SIGNER_REPO}" \
  --signer-workflow "${SIGNER_REPO}/.github/workflows/release.yml" \
  --source-ref "refs/tags/${TAG}"
gh attestation verify YuzuAgentSetup-0.11.0.exe --repo "${SIGNER_REPO}" \
  --signer-workflow "${SIGNER_REPO}/.github/workflows/release.yml" \
  --source-ref "refs/tags/${TAG}"
gh attestation verify yuzu-agent-macos-arm64.tar.gz --repo "${SIGNER_REPO}" \
  --signer-workflow "${SIGNER_REPO}/.github/workflows/release.yml" \
  --source-ref "refs/tags/${TAG}"

# Docker images (by digest)
gh attestation verify \
  oci://ghcr.io/${OWNER}/yuzu-server@sha256:<digest> \
  --repo "${SIGNER_REPO}" \
  --signer-workflow "${SIGNER_REPO}/.github/workflows/release.yml" \
  --source-ref "refs/tags/${TAG}"
```

Success prints the attestation's predicate type
(`https://slsa.dev/provenance/v1`), builder ID
(`https://github.com/actions/runner`), and the source repository +
commit SHA that produced the artifact.

**Offline / air-gapped verification.** On a machine with network access,
fetch the attestation bundle and the Sigstore trusted root:

```bash
gh attestation download yuzu-linux-x64.tar.gz --repo "${SIGNER_REPO}"
#   writes sha256:<digest>.jsonl to the current directory (sha256-<digest>.jsonl on Windows)
gh attestation trusted-root > trusted_root.jsonl
```

The platform archives and installers of v0.11.0-rc2 and later also ship the
same bundle as `<asset>.intoto.jsonl` (the table above); for v0.11.0-rc2 to
v0.13.0 that asset is the only source, so pass it as `--bundle` instead of
downloading. Copy the bundle and `trusted_root.jsonl` to the offline machine,
then run the same pinned check against the local files:

```bash
gh attestation verify yuzu-linux-x64.tar.gz \
  --bundle "sha256:$(sha256sum yuzu-linux-x64.tar.gz | cut -d' ' -f1).jsonl" \
  --custom-trusted-root trusted_root.jsonl \
  --repo "${SIGNER_REPO}" \
  --signer-workflow "${SIGNER_REPO}/.github/workflows/release.yml" \
  --source-ref "refs/tags/${TAG}"
```

With `--bundle`, gh compares `--repo` only with the repository name recorded
in the signing certificate when the release was built.

## 5. Inspect the SBOM

Every binary archive (all but the Compose Wizard zip), `.deb`, `.rpm`, Windows
installer and macOS `.pkg`, and every Docker image the release publishes (see
"Docker image SBOMs" below), has its own SBOM in both CycloneDX and SPDX
formats. Use
whichever your procurement or SCA tool consumes. A file's SBOM has the file's
name with `.cdx.json` or `.spdx.json` in place of `.tar.gz`, `.zip`, `.deb`,
`.rpm`, `.exe` or `.pkg`, and records the file's name and SHA-256 on its root
(`metadata.component` in CycloneDX, the described package in SPDX), so you can
check that an SBOM belongs to the file you hold:

```bash
jq -r '.metadata.component | "\(.name) \(.hashes[0].content)"' yuzu-agent_X.Y.Z_amd64.cdx.json
sha256sum yuzu-agent_X.Y.Z_amd64.deb
```

**What a file's SBOM lists.** The release unpacks each file and lists what is
in it:

- **The vcpkg libraries its C++ binaries are built with.** They are linked
  statically (on Windows most ship as DLLs next to the agent instead), and a
  scanner identifies neither, so the release takes them from the vcpkg
  installation it built with, with the installed version,
  the licence, a `pkg:github` (or `pkg:generic`) purl naming the upstream
  source, and a CPE where NVD has a product for the library. The agent's files
  list the agent's libraries; a file holding `yuzu-server` also lists the
  server's (`libpq`, `xmlsec`, `drogon`, `libxlsxwriter` and what they need). The list is every
  vcpkg library the build installs for that component, so it can include one
  a binary ends up not using; it does not omit a vcpkg library the binary
  uses. A library whose vcpkg record gives no licence is listed without one
  (`NOASSERTION` in SPDX), and the SBOM names those libraries in its
  `yuzu:sbom:licence-noassertion` note (see "Reading the `yuzu:sbom:` notes"
  below).
- **The gateway's Erlang/OTP release:** its applications (Hex packages carry a
  `pkg:hex` purl) and the Erlang runtime, as one `erlang` component.
- **Anything else a scanner recognises in the unpacked file.**

The Windows installer is not unpacked by the release. When the Inno Setup
compiler builds it, the compiler also writes a manifest: the list of files it
packed into the installer, with the SHA-256 of each. The installer's SBOM
lists those files. Each one is read from the build directory and must match
the SHA-256 the compiler recorded, or the release fails. The files are listed
at their paths in the build directory (for example
`agents/plugins/status/status.dll`), not at the paths the installer puts them
(`plugins\status.dll` under the install directory). The SBOM lists every
file the installer holds, whichever components an installation selects, and
does not record which component installs each one. The SBOM says this in its
`yuzu:sbom:contents` note, and its root names the installer and its SHA-256.

Not listed yet, though the file holds it: code vendored into the source tree
and compiled into `yuzu-server` (qrcodegen, and the web assets it embeds: htmx,
ECharts, three.js, Cytoscape, IBM Plex fonts; see `NOTICE`), the Windows
installer's own InnoSetup runtime and what the compiler embeds beside the
packed files (the licence text, the icon and the installer's compiled script),
and the code the gateway's bundled Erlang
runtime links into its emulator, `beam.smp` (PCRE2, asmjit, zstd, Ryu and an
MD5 implementation taken from OpenSSL; the SBOM lists the runtime as one
`erlang` component). An SBOM whose file holds something it does not list says
so in the data: a CycloneDX `compositions` entry with `aggregate: incomplete`
for its root, and in SPDX (which has no such field) a `CONTAINS NOASSERTION`
relationship on the described package. The `yuzu:sbom:incomplete-reasons`
note names why, by the tokens below, and the `yuzu:sbom:incomplete` note says
it in prose. The marker follows what a file holds, not its name: every SBOM of
a file holding `yuzu-server` is marked (`server-vendored`), as are the
installer's and every gateway SBOM. Today the files holding `yuzu-server` are
the Linux archive and the server `.deb` and `.rpm`, so the agent's files (the
Windows and macOS archives, the agent `.deb`, `.rpm` and `.pkg`) carry no
marker: no release after 0.15.0 puts `yuzu-server.exe` or a macOS `yuzu-server`
in them, and the Windows release job refuses an agent archive holding
`yuzu-server.exe`. (v0.15.0 and earlier shipped the server in
`yuzu-windows-x64.zip` and `yuzu-macos-arm64.tar.gz`; their SBOMs predate this
change and carry no marker at all, so their silence says nothing about
completeness.) Image SBOMs are marked too (below).

Libraries the binaries load from the operating system at run time (glibc,
`libsystemd`, the MSVC runtime, and the host OpenSSL `libcrypto` the gateway's
`crypto` application loads) are not in the file and are not listed. They are
not a reason for the marker, which is about what the file holds: an SBOM
without it can still depend on operating-system libraries.

### Why an SBOM says it is incomplete

The `yuzu:sbom:incomplete-reasons` note holds one or more of these tokens,
comma-separated. The set is closed: a new reason gets a new token, and an
existing token keeps its meaning. Read the tokens, not the prose, in a script.

| Token | On | What the SBOM does not list |
|---|---|---|
| `server-vendored` | a file or image holding `yuzu-server` | qrcodegen and the web assets compiled into it |
| `installer-runtime` | the Windows installer | InnoSetup's setup loader and uninstaller, and the licence text, icon and compiled installer script the compiler embeds |
| `erts-static` | a gateway file or image | what the Erlang emulator `beam.smp` vendors: PCRE2, asmjit, zstd, Ryu, OpenSSL's MD5 |
| `image-static-cpp` | a server or agent image | the vcpkg libraries linked statically into `yuzu-server` or `yuzu-agent`, which the image scan cannot see (the matching package's SBOM lists them) |
| `pgvector-source` | the `yuzu-postgres` image | pgvector, which the image builds from source, so it has no package record for the scan to read |

**Your scanner may not show the marker.** Neither a CycloneDX `compositions`
entry nor an SPDX `CONTAINS NOASSERTION` relationship is a finding: grype (checked
with grype 0.122.0 on a marked gateway SBOM) reports matches and says nothing
about completeness. How Dependency-Track presents either has not been checked
on a live instance. No finding for a file is not evidence that it
holds no vulnerable component: read the marker yourself, as below.

**The SBOM is not an attribution source yet.** Every vcpkg library carries the
licence vcpkg records, but its copyright text (SPDX `copyrightText`) is
`NOASSERTION`, because vcpkg's records hold none; the release would carry one
over if they did. Third-party attribution for the release is in `NOTICE`, which
is not generated from these SBOMs.

SBOMs of releases before this change were a scan of the whole build workspace
and list thousands of components (the vcpkg ports catalogue among them) that
the release does not ship.

**What to expect from a dependency scanner.** Feeding these SBOMs to grype,
Dependency-Track or a similar tool, expect:

- **No CVE match for libraries without a CPE.** NVD has no product for `re2`,
  `jsoncpp`, `nlohmann-json`, `cli11`, `libuuid`, `trantor` or `utf8-range`
  under the names tried, so those are listed with a purl only and a
  CPE-matching scanner reports nothing for them, whatever their state.
- **Matches that do not apply.** `libpq` carries PostgreSQL's CPE, so server
  CVEs in PostgreSQL are reported against it although only the client library
  ships; triage each against the libpq client.
- **Duplicates.** A library can appear twice: once from the vcpkg record and
  once where the scanner recognises the same library in a file (a DLL on
  Windows, for example). `utf8-range` carries protobuf's source purl, because
  vcpkg builds it from the protobuf repository.
- **No dependency graph for the vcpkg libraries.** They are listed as
  components of the file; the SBOM does not record which library depends on
  which.

### Reading the `yuzu:sbom:` notes

The release writes its notes on an SBOM's root under one key per note, spelled
the same in both formats: `yuzu:sbom:incomplete-reasons`,
`yuzu:sbom:incomplete`, `yuzu:sbom:contents`, `yuzu:sbom:licence-noassertion`
and the others. In CycloneDX each note is a `metadata.properties` entry whose
`name` is the key. SPDX has no properties, so each note is one line of the
described package's `comment`, the key, a colon and a space, then the value:

```text
yuzu:sbom:artifact: yuzu-gateway-linux-x64.tar.gz
yuzu:sbom:incomplete-reasons: erts-static
```

A note that is absent means the SBOM does not carry it (no
`yuzu:sbom:incomplete-reasons` note: no marker). The release writes each note
once: treat a file that carries two copies of one as altered. The release
check refuses a second copy of the notes it reads (`yuzu:sbom:unpacked-files`
on a file SBOM, `yuzu:sbom:incomplete-reasons` on an image SBOM pair); it does
not read the others. To read one note from either
format (set `KEY` to the note you want, and the file names to your SBOMs):

```bash
KEY=yuzu:sbom:incomplete-reasons
# CycloneDX: the metadata property named KEY
jq -r --arg k "$KEY" '.metadata.properties[]? | select(.name == $k) | .value' yuzu-gateway-linux-x64.cdx.json
# SPDX: the line of the described package's comment that starts with "KEY: "
jq -r '(.relationships[] | select(.spdxElementId == "SPDXRef-DOCUMENT" and .relationshipType == "DESCRIBES")
        | .relatedSpdxElement) as $root | .packages[] | select(.SPDXID == $root) | .comment // empty' \
  yuzu-gateway-linux-x64.spdx.json | sed -n "s/^$KEY: //p"
```

```bash
# Every note, and the CycloneDX marker itself
jq -r '.metadata.properties[] | select(.name | startswith("yuzu:sbom:")) | "\(.name): \(.value)"' yuzu-linux-x64.cdx.json
jq '.compositions' yuzu-linux-x64.cdx.json
# Every note, and the SPDX marker itself (the CONTAINS NOASSERTION relationship)
jq -r '(.relationships[] | select(.spdxElementId == "SPDXRef-DOCUMENT" and .relationshipType == "DESCRIBES")
        | .relatedSpdxElement) as $root | .packages[] | select(.SPDXID == $root) | .comment // empty' \
  yuzu-linux-x64.spdx.json | grep '^yuzu:sbom:'
jq '.relationships[] | select(.relationshipType == "CONTAINS" and .relatedSpdxElement == "NOASSERTION")' yuzu-linux-x64.spdx.json
```

### CycloneDX

From 0.16.0, the Windows agent archive and installer also carry Microsoft's
Visual C++ runtime in the agent's `bin` directory, unmodified and signed by
Microsoft: `vcruntime140.dll`, `vcruntime140_1.dll`, `msvcp140.dll`,
`msvcp140_atomic_wait.dll` and any other `vcruntime140_*.dll` or
`msvcp140_*.dll` the build machine's Visual Studio redistributable directory
holds. Each Windows SBOM describes its own artifact: the archive's SBOM
is made from the unpacked archive, which holds these DLLs in `bin`, and the
installer's SBOM lists the files its installer packs, with the runtime DLLs at
`msvc-runtime\...` (see "What a file's SBOM lists" above). The cataloguer that
makes the archive's SBOM (syft, through the pinned `anchore/sbom-action`)
lists each native DLL it finds as an application component, named and versioned from the DLL's version resource (for a
Microsoft DLL, its file description), with a CPE and no package URL (purl), so
a runtime DLL can appear more than once. A scanner or policy that matches
components on purl does not see them. No release SBOM has yet been inspected
for these entries. The authoritative version of the runtime a release shipped
is the file version of the Microsoft-signed DLLs in its payload (the archive's
`bin` directory, or `bin` under the installed agent's directory). The
`Build Windows x64` job's step summary lists the staged DLLs and their file
versions for that workflow run and is kept only as long as the run is. The
version follows the Visual C++ toolset the release is pinned to
(`deploy/packaging/windows/msvc-toolset.pin`). Their licence terms are in
`NOTICE`. Windows Update does not service this copy; see "Windows agent:
Visual C++ runtime" in the [user manual](README.md#windows-agent-visual-c-runtime).

```bash
# List all components + versions (CycloneDX, pretty-printed)
jq -r '.components[] | "\(.name)\t\(.version)\t\(.purl // "")"' yuzu-linux-x64.cdx.json | column -t

# Validate the CycloneDX schema
cyclonedx validate --input-file yuzu-linux-x64.cdx.json

# Count components
jq '.components | length' yuzu-linux-x64.cdx.json

# Find all dependencies declaring a specific license
jq -r '.components[] | select(.licenses[]? | (.license.id // .expression) == "MIT") | .name' \
  yuzu-linux-x64.cdx.json
```

### SPDX

```bash
jq -r '.packages[] | "\(.name)\t\(.versionInfo)"' yuzu-linux-x64.spdx.json | column -t

# Check the SPDX SBOM belongs to the file you hold: name and SHA-256 of the described package
jq -r '(.relationships[] | select(.spdxElementId == "SPDXRef-DOCUMENT" and .relationshipType == "DESCRIBES")
        | .relatedSpdxElement) as $root | .packages[] | select(.SPDXID == $root)
        | "\(.name) \(.checksums[] | select(.algorithm == "SHA256") | .checksumValue)"' yuzu-linux-x64.spdx.json
sha256sum yuzu-linux-x64.tar.gz
```

### Docker image SBOMs

The release publishes six images, each with an SBOM pair among the release
assets: `yuzu-server`, `yuzu-gateway` and `yuzu-postgres`
(`yuzu-<name>-image.{cdx,spdx}.json`), and `yuzu-server-chisel`,
`yuzu-gateway-chisel` and `yuzu-agent-chisel`
(`yuzu-<name>-chisel-image.{cdx,spdx}.json`). Each is a syft scan (v1.57.2, the
same version as the file SBOMs) of the image by its digest
(`ghcr.io/<owner>/<image>@sha256:...`), the digest the release signs and
attests, so the SBOM describes that exact image, not whatever a tag points at
later. It lists the operating-system packages and what syft recognises in the
image's files, so it does not list the C++ libraries linked statically into
`yuzu-server` or `yuzu-agent` (the `yuzu-linux-x64` archive and the
`yuzu-server` and `yuzu-agent` package SBOMs list those), nor what the gateway
images' Erlang emulator vendors, nor the `yuzu-postgres` image's pgvector. The
release marks each of the six incomplete the same way as a file SBOM: the two
server images `server-vendored, image-static-cpp`, the agent image
`image-static-cpp`, the two gateway images `erts-static`, and the
`yuzu-postgres` image `pgvector-source`. Beyond those, an image SBOM lists what
syft recognises and no more. The release's SBOM scope check does not hold image
SBOMs to the file rules (entry bound, forbidden paths), but it refuses an image
SBOM pair that should carry the marker and does not, one carrying only part of
it, and one named as a release image that lacks that image's title label.

The agent-bundle image (`yuzu-agent-bundle-chisel`) is not a release image: it
is built from the published release afterwards, by a separate job. Its syft
SBOM pair is kept only as a three-day workflow artifact, is not a release
asset and is not marked, although the image holds `yuzu-agent`: the agent
package SBOMs inside the release list that binary's libraries.

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

TAG="v${VERSION#v}"
IDENTITY="https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

# The pinned attestation check below needs gh 2.102.0 or later (section 4).
# A version that is not plain X.Y.Z (a development build) is refused too.
GH_VERSION="$(gh --version | awk 'NR==1 {print $3}')"
if [[ ! "$GH_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
   || [[ "$(printf '%s\n' 2.102.0 "$GH_VERSION" | sort -V | head -1)" != 2.102.0 ]]; then
  echo "gh ${GH_VERSION:-(unknown)} is not a release at or above 2.102.0; install 2.102.0 or later first" >&2
  exit 1
fi

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
  [[ -f "$f" ]] || continue
  # Use the shipped <asset>.intoto.jsonl when it was downloaded too: for
  # v0.11.0-rc2 to v0.13.0 it is the only source (section 4).
  bundle=()
  [[ -f "$f.intoto.jsonl" ]] && bundle=(--bundle "$f.intoto.jsonl")
  gh attestation verify "$f" ${bundle[@]+"${bundle[@]}"} --repo "${SIGNER_REPO}" \
    --signer-workflow "${SIGNER_REPO}/.github/workflows/release.yml" \
    --source-ref "refs/tags/${TAG}"
done

echo "✓ all checks passed for v${VERSION}"
```

## Enterprise compliance mapping

| Framework / ask | Covered by |
|-----------------|------------|
| SOC 2 CC6.8 (integrity of software) | cosign image + blob signatures |
| SOC 2 CC7.1 (change management traceability) | SLSA provenance attestation, for the attested assets and releases only (section 4) |
| NIST SSDF PW.5 (archive / protect) | SHA256SUMS + signed manifest |
| NIST SSDF PS.3 (provide provenance) | SLSA v1.0 attestation (roughly SLSA Build level 2, not 3), for the attested assets and releases only (section 4) |
| Executive Order 14028 (SBOM for federal sales) | CycloneDX + SPDX SBOMs per artifact |
| ISO/IEC 5962 (SPDX conformance) | SPDX 2.3 SBOMs |
| EU CRA Annex V | Provenance + SBOM + signed artefact bundle (provenance as in section 4) |

The table names the evidence each item points to; it is not a statement that
a control is met. In particular, the provenance is roughly SLSA Build level 2,
not level 3: release builds run on persistent self-hosted runners that also
run CI and share its caches, the build steps run in the job that holds the
signing identity, and no tag ruleset limits who can start a release
([CI architecture](../ci-architecture.md#release-build-environment-and-provenance)).
Releases before v0.11.0-rc2 carry no provenance, and the SBOMs, `SHA256SUMS`
and the Compose Wizard zip are never attested.

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
CycloneDX 1.5 by default; Yuzu's SBOMs are CycloneDX 1.7 (syft v1.57.2; earlier
releases shipped 1.6). Upgrade the CLI
(`npm i -g @cyclonedx/cyclonedx-cli@latest`) or use `jq` for structural
validation (`jq empty yuzu-linux-x64.cdx.json`).

## References

- Sigstore / cosign: <https://docs.sigstore.dev/>
- SLSA v1.0: <https://slsa.dev/spec/v1.0/provenance>
- CycloneDX: <https://cyclonedx.org/>
- SPDX: <https://spdx.dev/>
- GitHub Artifact Attestations: <https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds>
- Syft (Anchore): <https://github.com/anchore/syft>
