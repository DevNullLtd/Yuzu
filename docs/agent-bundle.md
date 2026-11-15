# Agent bundle — three-triplet delivery image

A single **chiselled** (FROM scratch) container image that carries the Yuzu
agent for three target triplets at one pinned version:

| Triplet | OS / arch | Toolchain | Signing |
|---|---|---|---|
| `linux-x64` | Linux x86_64 (glibc) | GCC | — |
| `windows-x64` | Windows x86_64 | MSVC | not signed today (Authenticode signing is skipped in the release workflow, [#239](https://github.com/DevNullLtd/Yuzu/issues/239)) |
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
not compiled: `scripts/build-agent-bundle.sh` downloads the (unsigned: neither
Windows nor macOS is code-signed today) per-platform archives **and** native installers from the matching GitHub
*release*, authenticates the release `SHA256SUMS` (cosign signature, exact
`release.yml` identity) and matches every download to its own line in it, lays them out under
`/opt/yuzu-agents`, and bakes that tree into the chiselled image. This is the
same provenance customers get from the Releases page — just packaged for
`docker pull`.

Each triplet ships **both** forms:

```
/opt/yuzu-agents/
  README.txt   VERSION   SHA256SUMS   UPSTREAM-SHA256SUMS   UPSTREAM-SHA256SUMS.sigstore
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

The script first runs `cosign verify-blob` on the release's `SHA256SUMS`
against `SHA256SUMS.sigstore` with the exact identity
`https://github.com/<signer>/.github/workflows/release.yml@refs/tags/<tag>`
(issuer `https://token.actions.githubusercontent.com`; never a regexp), and only
then reads it: each of the seven artifacts must equal the hash on **its own**
`SHA256SUMS` line (found by exact file name, with a unique `~` to `.` fallback
for releases before 0.14.0-rc3, where GitHub served the Debian `~` as `.`; a hash
that appears only on another file's line is a failure). Each installer is
chosen by the **requested version**: a pre-release can carry the installers of
earlier pre-releases beside its own (v0.13.0-rc6 also holds the rc4 `.deb` and
`.rpm`), so the script derives the exact file names for that version and
refuses to build if none, or more than one, exists. It **refuses to build** on
any failure, including a missing `cosign` (required, v2.6.2 or later, no skip flag), a
missing `.sigstore`, or a legacy release that carries only `SHA256SUMS.bundle`.
The signer is a fixed table by version, not read from `origin`: `Tr3kkR/Yuzu`
up to `v0.13.x`, `DevNullLtd/Yuzu` after the 2026-09-28 move (see
`docs/user-manual/release-verification.md`); override with
`--signer-repo owner/repo`, which prints a `[!!]` warning when it differs from
the table. The only legitimate signers are those two repositories: never set
`--signer-repo` to the subject cosign reports in a failure, because a mismatch
on the default means a tampered release or the wrong download source (rule out
an old cosign, a wrong clock and a Sigstore network failure first).

Requirements: `gh` (authenticated), `cosign` v2.6.2 or later with network access to
Sigstore's TUF root (there is no offline mode; `--trusted-root` is not wired
in), `sha256sum` or `shasum`, `git`, and a Yuzu checkout. A full build also
needs `docker` and `unzip`. The script is bash; run it on Linux or macOS, or
under WSL2 / Git Bash on Windows. `--verify-only` downloads and verifies, then
stops, with no docker needed (and `--push`/`--multiarch` with it is an error).
The script also best-effort verifies the SLSA provenance attestation; that step
does not gate the build. Registry owner is derived from `origin` (override with
`--registry`); image name with `--image-name`.

### Version pinning

The default version (`scripts/build-agent-bundle.sh`) tracks the current GA
release line — currently **`0.15.0`** — and must equal the version of the demo
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

Verify the image **by digest first**, then pull and extract from that same
`@sha256:` reference. `cosign verify` of a tag is answered by the registry; it
never reads an image already on your machine, so a verify of `:<version>` says
nothing about a mirrored, `docker load`ed or locally built image, nor about a tag
that moved after you pulled. `<signer>` is `Tr3kkR/Yuzu` for releases up to
`v0.13.x` and `DevNullLtd/Yuzu` after (see "Verify integrity" below).

```bash
# 1. resolve the tag to a digest at the registry (needs docker buildx; if this prints
#    an error or an empty digest, stop: step 3 refuses to run)
VERIFIED=
DIGEST=$(docker buildx imagetools inspect ghcr.io/<owner>/yuzu-agent-bundle-chisel:<version> \
  --format '{{.Manifest.Digest}}')

# 2. verify that digest against the exact, tag-bound identity; only a successful
#    verify sets VERIFIED
cosign verify "ghcr.io/<owner>/yuzu-agent-bundle-chisel@${DIGEST}" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity='https://github.com/<signer>/.github/workflows/release.yml@refs/tags/v<version>' \
  && VERIFIED=$DIGEST

# 3. every line below takes the verified digest and is refused when step 2 failed or
#    was skipped (also when this whole block is pasted at once)
docker pull "ghcr.io/<owner>/yuzu-agent-bundle-chisel@${VERIFIED:?step 2 did not verify - stop}"

# Self-extract the whole tree into ./yuzu-agents/ :
docker run --rm -v "$PWD:/out" "ghcr.io/<owner>/yuzu-agent-bundle-chisel@${VERIFIED:?step 2 did not verify - stop}"

# …or copy it out without running anything in the container:
cid=$(docker create "ghcr.io/<owner>/yuzu-agent-bundle-chisel@${VERIFIED:?step 2 did not verify - stop}") \
  && docker cp "$cid:/opt/yuzu-agents" . && docker rm "$cid"

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
Two known limits: the RPM installs but its service does not start yet (the
unit expects `/usr/local/bin`, the RPM installs to `/usr/bin`, #4916), and the
Linux binaries need glibc 2.38 or newer, so neither package nor the payload
runs on RHEL/Rocky 9, Ubuntu 22.04 or Debian 12 yet (#5143).

**macOS** — foreground (demo):
```bash
cd yuzu-agents/macos-arm64/payload
DYLD_LIBRARY_PATH="$PWD/bin" ./bin/yuzu-agent \
  --server <GATEWAY_HOST>:50051 --no-tls --enrollment-token <TOKEN> \
  --plugin-dir "$PWD/plugins" --data-dir ./data --log-level info
```
Persistent: `sudo installer -pkg installers/<pkg> -target /` installs the agent
but does not start it until a server trust anchor is configured. Add
`--server`, `--ca-cert` (or `--no-tls` for this demo) and `--enrollment-token` to
`/Library/LaunchDaemons/com.yuzu.agent.plist`, then run `launchctl bootstrap system …`.
To start it on first install instead, pre-stage the plist
([Deploying with MDM](../deploy/packaging/macos/README.md#deploying-with-mdm)). If Gatekeeper quarantines copied files,
clear it first: `xattr -dr com.apple.quarantine yuzu-agents/macos-arm64`.

**Windows** — foreground (demo, PowerShell):
```powershell
cd yuzu-agents\windows-x64\payload
.\bin\yuzu-agent.exe --server <GATEWAY_HOST>:50051 --no-tls `
  --enrollment-token <TOKEN> --plugin-dir .\plugins --data-dir .\data --log-level info
```
Persistent: run `installers\YuzuAgentSetup-<v>.exe` (enter gateway + token on the
config page), or fully unattended —
`installers\YuzuAgentSetup-<v>.exe /VERYSILENT /SUPPRESSMSGBOXES /SERVER=<GATEWAY_HOST>:50051 /TOKEN=<TOKEN> /LOG=<path>`
(the installer takes the gateway address as `/SERVER=`, not only the GUI page).
Give the token with `/TOKEN=` or `/TOKEN_FILE=<file>` (not both, nor `/TOKEN_FILE=`
together with a token typed in the wizard). Either way, the installer writes it to
`%ProgramData%\Yuzu\enrollment-token` (Administrators and
SYSTEM only) and configures the service with `--enrollment-token-file` pointing at
it — a service registered by this installer no longer carries the token on its
command line, and the agent removes the file after its first accepted registration, or when the server refuses the token.
A service registered by an earlier installer keeps its earlier command line until
the installer is run again (with the original `/SERVER=` and `/NOTLS`;
`sc.exe qc YuzuAgent` shows which form a service has). `/TOKEN_FILE=` keeps
the token out of the Setup command line entirely; `/TOKEN=` does not — Setup still
writes its own whole command line, including the `/TOKEN=` value, to the `/LOG=`
file. The token must be exactly 64 lowercase hexadecimal characters; the installer
exits with code 7 on anything else.
Keep `/LOG=`: without it Setup writes no log, and the log is the only record of
why an unattended install failed and what it did about the service. Tokens can be
reused, so write the log where only Administrators and SYSTEM can read it, and
restrict or delete it after the deployment; deployment tools (SCCM's
AppEnforce.log, Intune) record the command line too.
Service name `YuzuAgent`.
If a silent install exits with code **7** and its `/LOG=` log says "The update
trust-anchor directory is not secured", the installer refused to continue
because it could not confirm that only Administrators and SYSTEM can write
`%ProgramData%\Yuzu\agent-certs`, and that both have full control of it and of
everything in it. The lines after it give the directory and then the reason.
The installer refuses when the directory, or anything in it, is a junction,
symbolic link, subdirectory or hard link; when the directory already existed but
was not secured; or when a file in it is not owned by Administrators or SYSTEM.
It never takes such a directory or file over. Remove a junction or directory link
with `cmd /c rmdir "<path>"` and a file link with `cmd /c del "<path>"` (each
removes the link, never its target; not `Remove-Item -Recurse`, which in Windows
PowerShell 5.1 deletes a junction target's contents). For an unsecured directory,
move any bundle you placed there yourself somewhere safe, delete the directory,
run the installer again, then copy the bundle back in as an administrator. For a
file refused because of its owner: inspect it, and if it is yours, run
`icacls "<file>" /setowner *S-1-5-32-544 /L`. A fresh install also refuses if
the installing account's TEMP folder is on another drive: set TEMP and TMP to a
folder on the system drive, or install as SYSTEM. The
check runs before the agent service is stopped, so the service is left as it was.
A refusal never leaves `agent-certs` less protected than it was: a new directory
is locked in the installer's private temporary folder and moved into place only
once it passes the check, so if security software blocks the lock nothing is
created at the path; an existing directory's own permissions are never changed,
and the abort message says which happened.

Installers from 0.14.0-rc1 to rc5 also refuse with code 7 wherever PowerShell
is restricted to Constrained Language Mode -- WDAC script enforcement, or
AppLocker script rules for an install run by an administrator rather than as
SYSTEM (#5196): use a later installer. Installers from 0.14.0-rc1 to rc3 also hit this when started from
PowerShell 7 through another process (#5176): run them from a new
`powershell.exe` or `cmd.exe` window that was not itself started from
PowerShell 7, or use a later installer.

If an upgrade fails after the installer has stopped the agent service -- for
example a file in the program directory cannot be replaced, which a
`/SUPPRESSMSGBOXES` install answers with Abort -- Setup exits with code **5**.
If the `YuzuAgent` service was running, or still starting, when the upgrade
began, Setup starts it again before it exits. It does so even when `/NOSTART`
was given: `/NOSTART` applies only to an installation that completed. The log
records the outcome on its `DeinitializeSetup:` lines. "has been started again
and is RUNNING" (or "is RUNNING again; Setup did not have to start it") means the
agent is back up. "could NOT be started again" gives the state Setup saw and
sc.exe's exit code: start the service with `sc.exe start YuzuAgent` (in
PowerShell, plain `sc` is Set-Content), check
`C:\Program Files\Yuzu\logs\yuzu-agent.log` if that fails too, or run the
installer again. Setup reports only a state it observed: it waits up to 45
seconds for a slow stop to finish and up to 10 seconds to see the service
running. Either way, the files the failed installation had already replaced are
not put back, so the agent may be running a mix of old and new files until you
run the installer again. A service that was already stopped before the upgrade
stays stopped. Installers up to 0.14.0 left the service stopped after a failed
upgrade (#5250).

Uninstall: `"C:\Program Files\Yuzu\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES`
(add `/LOG=<path>` to keep a log; if the agent was installed to another
directory, use the path in its `UninstallString` registry value). A silent
uninstall removes the program but **keeps `%ProgramData%\Yuzu`**, which holds
the agent's identity and its mTLS private key; an interactive uninstall asks. To
decommission a device, revoke its certificate on the server (find its serial in
`GET /api/v1/ca/issued` with an unconfined account, because a management-group-confined
account, or one with no `Inventory:Read` grant, is refused that list, though a confined `Security:Delete` holder can revoke a serial it
already knows; then `POST /api/v1/ca/revoke`; see `docs/user-manual/device-management.md`) and
delete that directory. Revocation
alone does not disconnect an agent that reaches the server through a gateway;
see "Gateway-proxied agents: revocation scope" in `docs/auth-architecture.md`.
Uninstallers from releases up to 0.14.0-rc2 hang on a silent uninstall (#5147) —
upgrade first.

## Verify integrity

Three checks, and they cover different things:

```bash
cd yuzu-agents
sha256sum -c SHA256SUMS          # the laid-out tree is intact (NOT proof it is genuine:
                                 # anyone who edits the tree can regenerate this file)
# UPSTREAM-SHA256SUMS is the checksum manifest from the GitHub release, which the
# build verified before use; UPSTREAM-SHA256SUMS.sigstore is its cosign bundle.
# It authenticates the release archives and installers, not payload/ as laid out.
# SIGNER_REPO is Tr3kkR/Yuzu for releases up to v0.13.x, DevNullLtd/Yuzu after.
# Needs cosign v2.6.2 or later and network access to Sigstore's TUF root:
SIGNER_REPO=DevNullLtd/Yuzu
TAG=v<version>
cosign verify-blob --bundle UPSTREAM-SHA256SUMS.sigstore \
  --certificate-identity "https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com UPSTREAM-SHA256SUMS
```

`UPSTREAM-SHA256SUMS.sigstore` is absent from bundles built before this check
existed, and the first release that carries a `SHA256SUMS.sigstore` to rebuild
from is v0.11.0-rc1. The check that covers what you extracted is the
signature on the **image**: verify it by digest, as in "Use it (partner)" above,
before you pull, run or extract anything, and extract from that same `@sha256:`
reference. A registry verify does not cover a mirrored, `docker load`ed or
locally built image.

**Nothing in the bundle is code-signed today.** The release workflow's
Authenticode steps for the Windows binaries and installer are skipped (no
signing certificate is provisioned, [#239](https://github.com/DevNullLtd/Yuzu/issues/239)),
so do not expect a valid Authenticode signature (`Get-AuthenticodeSignature`
reports `NotSigned`) and SmartScreen may warn. **macOS binaries are not signed
or notarized either** (deferred, see Phase B / `docs/macos-code-signing` when it
lands), so a copied macOS file is unsigned and Gatekeeper will quarantine it. Clear
that with `xattr -dr com.apple.quarantine <dir>` only after the image signature
below verified, because the cosign signatures are the only authenticity check.

The **image itself** (when built by the `docker-publish-agent-bundle` release
job) is cosign-keyless-signed with SLSA provenance and a CycloneDX/SPDX SBOM, so
a partner's security team can verify it before trusting the pull. The command is
the digest form from "Use it (partner)"; `DIGEST` is resolved with the same
`docker buildx imagetools inspect` call:

```bash
cosign verify "ghcr.io/<owner>/yuzu-agent-bundle-chisel@${DIGEST}" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity='https://github.com/<signer>/.github/workflows/release.yml@refs/tags/v<version>'
gh attestation verify "oci://ghcr.io/<owner>/yuzu-agent-bundle-chisel@${DIGEST}" --repo <owner>/Yuzu
```

`<signer>` is the repository that ran `release.yml` for that tag (`DevNullLtd/Yuzu` since the 2026-09-28 move, `Tr3kkR/Yuzu` before it); the identity is an exact, tag-bound match, and `<owner>` is the registry owner.

(Manual off-cycle builds via `scripts/build-agent-bundle.sh` are *not* image-signed
— only the CI job signs. Prefer the released, CI-published image for partners.)

## Files

- `deploy/docker/Dockerfile.agent-bundle.chisel` — the chiselled assembler.
- `scripts/build-agent-bundle.sh` — download → verify → lay out → build → (push).
- This doc.
