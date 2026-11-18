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

**cosign version.** Every `cosign verify` of a Docker image on this page needs **cosign v3.0 or
later**. Recent releases' images are signed with cosign v3's bundle format, and cosign v2.x reports
`no signatures found` for a genuine image (some v2.x builds accept `--new-bundle-format` but
ignore it, so do not rely on that flag). cosign v3 also verifies older releases' images. `cosign
verify-blob` of a release's `SHA256SUMS` works with cosign v2.6.2 or later.

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
| CycloneDX SBOMs | `yuzu-*.cdx.json`, including the images: `yuzu-{server,gateway,postgres}-image.cdx.json` and `yuzu-{server,gateway,agent}-chisel-image.cdx.json` | `cyclonedx validate` |
| SPDX SBOMs | `yuzu-*.spdx.json`, including the same image set | `spdx-tools validate` |
| SLSA provenance | `<artifact>.intoto.jsonl` where present: the platform archives and native installers of v0.11.0-rc2 and later (the Docker images' provenance is in GitHub's attestation registry only; which releases the registry holds is in section 4) | `gh attestation verify` |
| Docker images | `ghcr.io/${OWNER}/yuzu-{server,gateway,postgres}:<tag>` and `ghcr.io/${OWNER}/yuzu-{server,gateway,agent}-chisel:<tag>` (the `-chisel` variants' operating-system packages are not vulnerability-scanned: [below](#image-vulnerability-scan-before-publishing)) | `cosign verify` |
| Image vulnerability scan reports | `trivy-yuzu-{server,gateway,postgres}.attempt-<N>.{json,txt,gate.txt}` and `trivy-yuzu-{server,gateway,agent}-chisel.attempt-<N>.{json,txt,gate.txt}`, `<N>` being the workflow run attempt, and each passing attempt's publish journal `publish-<image>.attempt-<N>.txt` (none on v0.15.0 or any earlier release: the scan postdates them) | `sha256sum -c SHA256SUMS`; see [below](#image-vulnerability-scan-before-publishing) |
| Agent-bundle image scan report | `trivy-yuzu-agent-bundle-chisel.attempt-<N>.{json,txt,gate.txt}` and `publish-yuzu-agent-bundle-chisel.attempt-<N>.txt`, attached after the release with its own checksum list `yuzu-agent-bundle-chisel-image-vuln-gate.attempt-<N>.SHA256SUMS` and `.sigstore` (none on v0.15.0 or any earlier release) | `cosign verify-blob` with the same identity as `SHA256SUMS`, then `sha256sum -c` that list ([commands below](#image-vulnerability-scan-before-publishing)) |

**Do not trust an image tag that has no GitHub Release.** The images are pushed, signed and tagged
before the GitHub Release is created, and a failed publish job stops the release. A release workflow
moves an image's tags only after the pushed digest was checked to be the scanned image and was
signed and attested, but a `:X.Y.Z` tag can still exist in GHCR for a version that has no GitHub
Release, or whose release lacks that image's SBOM in `SHA256SUMS`. Use an image only when its version has a published GitHub Release and the image
passes `cosign verify` (step 3) with the exact release identity.

**`:latest` moves before the Release exists.** For a stable release, the floating tags `:latest` and
`:X.Y` of `yuzu-server`, `yuzu-gateway`, `yuzu-postgres` and the three `-chisel` images move when
each image is tagged (after its digest is verified, signed and attested), which is during the release
workflow and BEFORE the GitHub Release is created
(the Release is created only after every one of those images is published). For the minutes in
between, and for as long as the release stays unfinished when a later image or the release step
fails, `:latest` names a version that has no GitHub Release, and can name the new version for some
images and the previous one for others. (The agent-bundle image is tagged only as `:X.Y.Z`, after the
Release.) So do not deploy `:latest` or `:X.Y` blind: resolve it to a digest, and check that digest
belongs to a version with a published GitHub Release and passes `cosign verify` for that release's
tag. Pinning a release's exact tag or digest avoids the question.

Check that the Release exists, verify every image of it, and compare `:latest` with it:

```bash
TAG=vX.Y.Z    # the release you mean to deploy
# 1. The GitHub Release exists (exit 1, "release not found", when it does not):
gh release view "$TAG" --repo DevNullLtd/Yuzu --json tagName,isDraft,publishedAt
# 2. Every image of that release is signed by that release's workflow and tag:
for img in yuzu-server yuzu-gateway yuzu-postgres yuzu-server-chisel yuzu-gateway-chisel \
           yuzu-agent-chisel yuzu-agent-bundle-chisel; do
  cosign verify \
    --certificate-identity "https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "ghcr.io/${OWNER}/${img}:${TAG#v}" > /dev/null && echo "${img}:${TAG#v} verified"
done
# 3. What :latest names now, against the release's own tag (repeat per image you pull):
docker buildx imagetools inspect "ghcr.io/${OWNER}/yuzu-server:latest" --format '{{.Manifest.Digest}}'
docker buildx imagetools inspect "ghcr.io/${OWNER}/yuzu-server:${TAG#v}" --format '{{.Manifest.Digest}}'
```

Accept the release only when step 1 prints `"isDraft":false` and a `publishedAt` date (a draft is
not a release, and `gh release view` shows drafts to anyone with access to the repository), every
`verified` line prints, and, before you deploy `:latest`, the two digests are equal. Releases before
the chisel variants and the agent bundle have no such images, so those names fail to resolve there
(the agent bundle is tagged only as `:X.Y.Z`, never `:latest`). If only `yuzu-agent-bundle-chisel`
fails to verify, read the bundle's publish journals (below): they say how far each attempt got, and
whether any attempt moved the tag.

## Image vulnerability scan before publishing

Before `release.yml` pushes an image, it scans the locally built image (by image ID) with a pinned
Trivy and refuses to push it when the scanner finds a **CRITICAL vulnerability that has a fix
available** in what it can see and the finding is not an accepted one. "What it can see" is narrower
than the image: the list below says what it does not cover. Accepted findings are listed in
`.trivyignore.yaml` in the repository at the release tag; the release scan honours an entry only when
it is scoped to concrete file paths inside the image (each a path with a `/`, with no wildcard
character and not a scanner result name such as `Python`) or to packages at exact versions, never to
a bare vulnerability id; states why the finding does not apply; expires at most 92 days out; and carries an
approver's login, an approval date and a pull-request reference that are not `pending`. The release
scan checks those three approval fields for **format only**: it does not confirm with GitHub that the
pull request exists or that the named person approved it, and nothing stops the approver it names
from being the change's own author. The control behind an acceptance is the project's review of the
change that adds it, and that review is not required: once pull request #8243 is merged, the
repository's code-owner entries for these files will request a review from a release owner (until
then nothing requests one), but the branch rules do not require a code owner's review (an owner
decision), so any one approving review merges the change. To audit an
acceptance, follow its pull-request reference and check who approved it there.

The release scan also refuses to push, rather than report a clean scan, when:

- the scanner sees no operating-system package in an image that is not on the reviewed not-covered
  list (the chiselled images are on it, below);
- the scanner cannot show its database holds advisories for the image's operating-system release,
  as the scanner identifies that release from the image's files: the scanner marks the release end
  of life; the distribution is not Debian, Ubuntu or Alpine; the version is a pre-release (`_alpha`,
  `_rc`, `~rc1`, `-rc`, Debian testing or sid, Alpine edge, and similar markers) or not a plain
  release number; or a test scan of that release holding packages older than every fix matches
  nothing. A clean scan of such an image would prove nothing about what it ships;
- the vulnerability database is older than 72 hours, or was not downloaded by that run.

After the release, the pre-release QA workflow scans the published tags again with a newer database;
a finding there is reported, it cannot unpublish anything.

What this does **not** gate:

- HIGH and lower findings, and CRITICAL findings with no fix released: they are in the report, not
  refused.
- The operating-system packages of the chiselled images (`yuzu-*-chisel`, and the agent-bundle delivery
  image): they are built from Ubuntu package slices with no package database the scanner can read, so
  their OS packages are not scanned at all. Each report's `.gate.txt` says `coverage: not-covered` for
  them. Choose the non-chisel image if you need its OS packages covered by this scan.
- PostgreSQL itself in `yuzu-postgres`: its packages come from the PostgreSQL project's repository,
  which publishes no advisories the scanner matches, and the image holds them at the pinned minor.
- The gateway's bundled Erlang/OTP runtime, and anything statically linked into the server and agent
  binaries.
- The integrity of the vulnerability database itself: its publisher does not sign it. Each report
  records the database's registry digest, so the database a scan used can be identified afterwards,
  but a database altered before the download is not detected.

Each release carries the reports for the six images it publishes (inside `SHA256SUMS`):
`trivy-<image>.attempt-<N>.json` (the full report, including the image ID, the layer digests and
every package), `trivy-<image>.attempt-<N>.txt` (the same as a table) and
`trivy-<image>.attempt-<N>.gate.txt` (the run attempt, the Trivy version, the database's digest and
date, the OS, the OS package count, the coverage, the advisory-data check, the accepted-findings
file's hash and the result). `<N>` is the release workflow's run attempt; every attempt's reports are
kept, a refused or cancelled attempt's (`gate: FAIL: <reason>`, `gate: FAIL: cancelled ...`)
included. Beside each attempt whose scan passed is its publish journal,
`publish-<image>.attempt-<N>.txt`: one line per publishing step that attempt completed, in this
order and with one digest throughout:

```
publish: none
publish: push-started <repository>[:candidate-<run>-<N>]
publish: verified <repository>@sha256:<digest>
publish: signed-attested <repository>@sha256:<digest>
publish: tagging <repository>:<tag>[,...] sha256:<digest>
publish: tagged <repository>:<tag>[,...] sha256:<digest>
```

Each line is written before the next step starts, and the image's tags are moved only after the
`signed-attested` line: the digest was first checked to have the scanned image's layers, then signed
and attested. A journal that stops early records how far that attempt got (`tagging` means some of
its tags may have moved). An attempt with no journal normally pushed nothing (its scan refused the
image, or the job stopped first), but a missing journal is absence of a record, not proof: the
upload of the record can fail.

For each of the six images the published image is the HIGHEST attempt whose journal ends
`publish: tagged`, and the release is not created unless there is one and no higher attempt ends
`publish: tagging`. To check one of them (the release's assets, downloaded beside `SHA256SUMS` and
verified as above):

```bash
OWNER=devnullltd; TAG=vX.Y.Z   # the release, as set above
img=yuzu-server   # or yuzu-gateway, yuzu-postgres, yuzu-server-chisel, ...
# Each attempt's last journal line, in attempt order (attempt 10 after 9):
for f in $(ls publish-${img}.attempt-*.txt | sort -V); do echo "$f: $(tail -n 1 "$f")"; done
docker buildx imagetools inspect "ghcr.io/${OWNER}/${img}:${TAG#v}" --format '{{.Manifest.Digest}}'
```

The highest attempt whose last line is `publish: tagged ...` must name the digest the last command
prints. A refusal that was never followed by a release (the tag was cut again instead) is kept only
in that workflow run's artifacts, for 90 days.

**Candidate tags and untagged digests are not releases.** The packages also hold images no release
names: a `:candidate-<run>-<N>` tag on `yuzu-agent-bundle-chisel` (how the bundle is pushed before
it is checked), and untagged digests in every package (an attempt whose push was not verified,
signed or tagged, or that a later attempt replaced). Do not deploy them, and do not take a
signature on one as a release: a published image is the digest a release tag (`:X.Y.Z`) names, of a
version with a published GitHub Release, that `cosign verify` accepts for that release's tag.
Candidates are left in place; nothing deletes them as routine cleanup. If you use image
automation that picks the newest tag, restrict it to release tags (`^[0-9]+\.[0-9]+\.[0-9]+$`, which
excludes candidate and pre-release tags) or pin by digest, so it never selects a candidate.

**Release images and release tags: what is enforced and what is practice.** Enforced by the
release workflow: within it, a release tag is moved only by its "Tag the release" step, after the
image is scanned, verified, signed and attested, and the workflow deletes no image. Practice, not
enforced: a wrong or superseded release is fixed by a new patch release; deleting a published
release or a GHCR package version, and moving a release tag outside the workflow, are
owner-decided incidents, recorded in a tracking issue and announced. A patch release does not move
the superseded release's own `:X.Y.Z` (a deployment pinned to that tag keeps pulling the image it
names), and a patch on an older `X.Y` line moves `:latest` to that line until the next stable
release on the newest line, so pin a version or a digest if that matters to you. Two older
maintainer scripts (`scripts/docker-release.sh`, `scripts/build-agent-bundle.sh --push`) can push
release tags outside the release workflow, bypassing its gate and journal; they are not used to
publish a release, and an image they pushed is not one the release's signed records name. If a
release image or tag ever had to stop being served, the project would announce it with the release.
Either of the following is an incident, not a registry fault to wait out; report it through
[private vulnerability reporting](https://github.com/DevNullLtd/Yuzu/security/advisories/new):

- **A release's `:X.Y.Z`, or a digest its journal names, stops resolving or changes without such an
  announcement.** Do not adopt the new digest. Keep deploying the digest you already have only if
  `cosign verify` still accepts THAT DIGEST for that release's tag (verify the digest, not the tag,
  which may now name something else); never replace it with an image no release names:

  ```bash
  cosign verify \
    --certificate-identity "https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "ghcr.io/${OWNER}/<image>@sha256:<the digest you deployed>"
  ```

- **You suspect a release digest itself is compromised.** Stop deploying that digest to new hosts,
  and handle the hosts already running it under your own incident process (isolating them if your
  process calls for it). Do not switch to an image no release names; move only to a digest a later
  release announces and that `cosign verify` accepts, by digest as above, for that release's tag.

The agent-bundle image is built after the release exists, so its reports and journals are attached
afterwards, every attempt's, with a signed checksum list per attempt (table above). Check them, and
that the bundle's tag names the digest of the highest `tagged` attempt:

```bash
TAG=vX.Y.Z
gh release download "$TAG" --repo DevNullLtd/Yuzu --dir bundle-scan \
  --pattern 'yuzu-agent-bundle-chisel-image-vuln-gate.attempt-*' \
  --pattern 'trivy-yuzu-agent-bundle-chisel.attempt-*' \
  --pattern 'publish-yuzu-agent-bundle-chisel.attempt-*'
cd bundle-scan
for sums in yuzu-agent-bundle-chisel-image-vuln-gate.attempt-*.SHA256SUMS; do
  cosign verify-blob --bundle "${sums}.sigstore" \
    --certificate-identity "https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$sums"
  sha256sum -c "$sums"
done
grep -H '^gate:' trivy-yuzu-agent-bundle-chisel.attempt-*.gate.txt
for f in $(ls publish-yuzu-agent-bundle-chisel.attempt-*.txt | sort -V); do echo "$f: $(tail -n 1 "$f")"; done
docker buildx imagetools inspect "ghcr.io/${OWNER}/yuzu-agent-bundle-chisel:${TAG#v}" --format '{{.Manifest.Digest}}'
```

Every list must print `Verified OK` and every file `OK`. The highest attempt whose journal's last
line is `publish: tagged ...` is the published bundle image: the digest on that line must equal
what the last command prints, and that attempt's `gate:` line must be `gate: pass`. If an attempt
above it ends `publish: tagging`, the tag may name either digest: do not deploy the bundle until a
later attempt ends `tagged`. When no attempt ends `publish: tagged`, the record cannot say what the
tag names: an attempt ending `tagging` may have moved it, and so may an attempt whose record was
never uploaded. Deploy the bundle only if the digest the last command prints is on some attempt's
`tagging` or `tagged` line (that digest was checked and signed before any tag moved) and passes
`cosign verify` for the release's tag; otherwise do not deploy it, and ask the project. A re-run
adds new report assets and never replaces a completed one (an upload that was interrupted, which
GitHub never served, is replaced). The reports are a point-in-time record:
a vulnerability disclosed after the release is not in them.

## Prerequisites

```bash
# GitHub CLI 2.102.0 or later, for attestation verification (check: gh --version)
#   Linux:   GitHub's official packages, https://github.com/cli/cli/blob/trunk/docs/install_linux.md
#            (a distribution's own gh package is often older than 2.102.0)
#   macOS:   brew install gh
#   Windows: winget install --id GitHub.cli

# cosign v3.0 or later, for Sigstore signature verification (see "cosign version" at
# the top of this page)
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

Rely on the signed list, not on the release's asset list: release assets
can change after publication (GitHub's immutable-releases setting is off
for this repository, and the agent bundle's files are attached after the
release). Download every asset and run `sha256sum -c SHA256SUMS` without
`--ignore-missing`, so a listed file that is missing or changed fails. An
asset that no signed list names proves nothing, and the agent bundle's
per-attempt lists are not themselves listed anywhere signed, so a removed
attempt (its list, signature and files together) cannot be detected.

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

Each platform archive and Docker image ships SBOMs in both CycloneDX
and SPDX formats. Use whichever your procurement or SCA tool consumes.

**Known limitations of the platform SBOMs.** They are generated from the whole
build workspace (the vcpkg ports tree and build trees included), not from the
archive alone, so they can list components the archive does not ship or load.
A finding in a component the archive does not contain does not apply to it.
Since ADR-0035 step 3 the Windows and macOS builds install only the agent's
dependencies, so the server's dependencies (`libpq`, `drogon`, `xmlsec`, `libxlsxwriter`) are no
longer installed on those build machines and the Windows agent archive carries
none of their DLLs (the Windows release build's "Verify the agent runs from the packaged archive" step
refuses an archive that carries the DLLs of `libpq`, `drogon` or `xmlsec`, and does not yet check those of `libxlsxwriter`; it has not yet run on a real release tag). What a
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
trusted root, update cosign (v2.6.2 or later for this check; v3.0 or later if you also verify
images) instead of waiting.

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
