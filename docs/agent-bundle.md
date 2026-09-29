# Agent bundle — three-triplet delivery image

A single **chiselled** (FROM scratch) container image that carries the Yuzu
agent for three target triplets at one pinned version:

| Triplet | OS / arch | Toolchain | Signing |
|---|---|---|---|
| `linux-x64` | Linux x86_64 (glibc) | GCC | — |
| `windows-x64` | Windows x86_64 | MSVC | Authenticode |
| `macos-arm64` | macOS Apple Silicon | Apple Clang | not signed / not notarized |

It exists so a design partner who can only **`docker pull`** can still get the
right agent onto every endpoint OS — the companion to the chiselled
server/gateway demo images (`docs/demo-environment.md`).

Image: `ghcr.io/<owner>/yuzu-agent-bundle-chisel:<version>`

> ⚠ **This is a delivery vehicle, not a runtime.** A Linux container cannot run
> a Windows `.exe` or a macOS Mach-O. The image stores the binaries and offers a
> busybox userland to copy them out — nothing in it executes the agents. To
> *run* a Linux agent in a container, use `yuzu-agent-chisel` instead.

## Why it's assembled from release artifacts (not built from source)

The Windows (MSVC) and macOS (Apple Clang) agents **cannot be cross-built in a
Linux Docker stage** — they require their native toolchains. So this image is
not compiled: `scripts/build-agent-bundle.sh` downloads the Windows-signed /
macOS-unsigned per-platform archives **and** native installers from the matching GitHub
*release*, verifies them against the release `SHA256SUMS`, lays them out under
`/opt/yuzu-agents`, and bakes that tree into the chiselled image. This is the
same provenance customers get from the Releases page — just packaged for
`docker pull`.

Each triplet ships **both** forms:

```
/opt/yuzu-agents/
  README.txt              VERSION   SHA256SUMS   UPSTREAM-SHA256SUMS
  linux-x64/
    installers/   yuzu-agent_<v>_amd64.deb   yuzu-agent-<v>.x86_64.rpm
    payload/      bin/yuzu-agent  bin/libyuzu_agent_core.so  plugins/*.so
  windows-x64/
    installers/   YuzuAgentSetup-<v>.exe
    payload/      bin/yuzu-agent.exe  bin/yuzu_agent_core.dll  bin/*.dll  plugins/*.dll
  macos-arm64/
    installers/   YuzuAgent-<v>-macos-arm64.pkg
    payload/      bin/yuzu-agent  bin/libyuzu_agent_core.dylib  plugins/*.dylib
```

- **`payload/`** — raw agent binary + core library + plugins (Windows also gets
  the vcpkg runtime DLLs). Sideload / run-in-foreground. The natural fit for the
  **no-TLS demo stack** because you pass `--no-tls` directly.
- **`installers/`** — native packages that install a background service and a
  dedicated user. The fit for a **persistent / real (TLS) deployment**. Note the
  installers default to TLS on, so add `--no-tls` if you point them at the demo.

## Build & publish (maintainers)

```bash
# Build locally for your host arch (downloads + verifies + assembles + smoke-tests):
bash scripts/build-agent-bundle.sh                      # default version

# Pin a specific release and push a single-arch image:
bash scripts/build-agent-bundle.sh --version 0.11.0 --push

# Multi-arch (so arm64 and amd64 hosts both pull natively) — pushes to the registry:
bash scripts/build-agent-bundle.sh --multiarch --push
```

The script verifies all seven artifacts against the release `SHA256SUMS` and
**refuses to build** on mismatch; when `gh` is present it also best-effort
verifies the SLSA provenance attestation. Registry owner is derived from
`origin` (override with `--registry`); image name with `--image-name`.

### Version pinning

The default version (`scripts/build-agent-bundle.sh`) tracks the current GA
release line — currently **`0.12.0`** — and must equal the version of the demo
server/gateway the agents enroll into. The bundle can only be built for a version
whose GitHub release has published the Windows/macOS archives, so when the next
release ships, bump the `VERSION` default **and** the `docker-compose.demo.yml`
pins together. In CI the `docker-publish-agent-bundle` job passes
`--version ${GITHUB_REF_NAME#v}`, so a tagged release always builds + signs a
matching bundle automatically — manual builds are only needed off-cycle.

## Use it (partner)

> **Prerequisite — image visibility.** GHCR packages are **private by default**.
> Before hand-off either make the package public (GitHub → your packages → the
> package → *Package settings* → *Change visibility*) or grant the partner read
> access; otherwise their `docker pull` returns `unauthorized` / `403`. A partner
> pulling a still-private image must first authenticate:
> `echo <PAT-with-read:packages> | docker login ghcr.io -u <github-user> --password-stdin`.

```bash
docker pull ghcr.io/<owner>/yuzu-agent-bundle-chisel:<version>

# Self-extract the whole tree into ./yuzu-agents/ :
docker run --rm -v "$PWD:/out" ghcr.io/<owner>/yuzu-agent-bundle-chisel:<version>

# …or copy it out without running anything in the container:
cid=$(docker create ghcr.io/<owner>/yuzu-agent-bundle-chisel:<version>)
docker cp "$cid:/opt/yuzu-agents" .
docker rm "$cid"

# Other entrypoint verbs:
docker run --rm <img> list     # recursive listing
docker run --rm <img>          # prints the bundle README
```

> Extracted files are owned by **root** (the image copies them as root). On a
> Linux host either `sudo chown -R "$(id -u):$(id -g)" yuzu-agents`, or extract as
> yourself: `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/out" <img>`.
> (On Docker Desktop / macOS the VM boundary makes this transparent.)

Then copy the directory for each endpoint's OS onto that machine and follow its
`README.txt`. Quick reference (point every agent at the **gateway's** agent port
`50051` and the enrollment token from the demo, e.g.
`/tmp/yuzu-demo/enrollment-token`):

**Linux** — foreground (demo):
```bash
cd yuzu-agents/linux-x64/payload
LD_LIBRARY_PATH="$PWD/bin" ./bin/yuzu-agent \
  --server <GATEWAY_HOST>:50051 --no-tls --enrollment-token <TOKEN> \
  --plugin-dir "$PWD/plugins" --data-dir ./data --log-level info
```
Persistent: `sudo apt-get install ./installers/<deb>` (or `dnf install ./installers/<rpm>`),
then `sudo systemctl edit yuzu-agent` to set `--server`/`--enrollment-token`
(+ `--no-tls` for the demo) and `sudo systemctl enable --now yuzu-agent`.

**macOS** — foreground (demo):
```bash
cd yuzu-agents/macos-arm64/payload
DYLD_LIBRARY_PATH="$PWD/bin" ./bin/yuzu-agent \
  --server <GATEWAY_HOST>:50051 --no-tls --enrollment-token <TOKEN> \
  --plugin-dir "$PWD/plugins" --data-dir ./data --log-level info
```
Persistent: `sudo installer -pkg installers/<pkg> -target /`, then add
`--server`/`--enrollment-token` to `/Library/LaunchDaemons/com.yuzu.agent.plist`
and `launchctl bootstrap system …`. If Gatekeeper quarantines copied files,
clear it first: `xattr -dr com.apple.quarantine yuzu-agents/macos-arm64`.

**Windows** — foreground (demo, PowerShell):
```powershell
cd yuzu-agents\windows-x64\payload
.\bin\yuzu-agent.exe --server <GATEWAY_HOST>:50051 --no-tls `
  --enrollment-token <TOKEN> --plugin-dir .\plugins --data-dir .\data --log-level info
```
Persistent: run `installers\YuzuAgentSetup-<v>.exe` (enter gateway + token on the
config page), or fully unattended —
`installers\YuzuAgentSetup-<v>.exe /VERYSILENT /SUPPRESSMSGBOXES /SERVER=<GATEWAY_HOST>:50051 /TOKEN=<TOKEN>`
(the installer takes the gateway address as `/SERVER=`, not only the GUI page).
Service name `YuzuAgent`.

## Verify integrity

Every file is checksummed twice over:

```bash
cd yuzu-agents
sha256sum -c SHA256SUMS          # checksums of the laid-out tree
# UPSTREAM-SHA256SUMS is the signed checksum manifest from the GitHub release.
```

The Windows binaries are Authenticode-signed; that signature is embedded and
survives the copy in/out of the image. **macOS binaries are not yet signed or
notarized** (deferred — see Phase B / `docs/macos-code-signing` when it lands),
so a copied macOS file is unsigned and Gatekeeper will quarantine it; clear it
with `xattr -dr com.apple.quarantine <dir>`.

The **image itself** (when built by the `docker-publish-agent-bundle` release
job) is cosign-keyless-signed with SLSA provenance and a CycloneDX/SPDX SBOM, so
a partner's security team can verify it before trusting the pull:

```bash
cosign verify ghcr.io/<owner>/yuzu-agent-bundle-chisel:<version> \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='^https://github.com/<owner>/Yuzu/\.github/workflows/release\.yml@.*'
gh attestation verify oci://ghcr.io/<owner>/yuzu-agent-bundle-chisel:<version> --repo <owner>/Yuzu
```

(Manual off-cycle builds via `scripts/build-agent-bundle.sh` are *not* image-signed
— only the CI job signs. Prefer the released, CI-published image for partners.)

## Files

- `deploy/docker/Dockerfile.agent-bundle.chisel` — the chiselled assembler.
- `scripts/build-agent-bundle.sh` — download → verify → lay out → build → (push).
- This doc.
