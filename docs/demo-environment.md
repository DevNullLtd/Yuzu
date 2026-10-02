# Cedar & Vale demo environment

A **repeatable, release-pinned** sales demo of the full Yuzu stack: a chiselled
Ubuntu 26.04 server and gateway, plus a fleet of the smallest chiselled Ubuntu
26.04 agents acting as clients. It is built for **sales demos, not UAT** — the
goal is that it comes up identically every time and only ever changes when you
point it at a new release.

> ⚠ **Demo, not production.** The stack runs `--no-tls --no-https
> --metrics-no-auth` with a baked admin password (`admin` / `adminpassword1`).
> None of that belongs in a production deployment. See
> `docs/user-manual/server-admin.md` for hardened deployment.

## At a glance

| Tier | Image | Base |
|------|-------|------|
| Server | `ghcr.io/<owner>/yuzu-server-chisel:<version>` | chiselled Ubuntu 26.04, `FROM scratch` |
| Postgres (server substrate, #1318) | `ghcr.io/<owner>/yuzu-postgres:<version>` | `postgres:18` + pgvector (no `-chisel` variant — same image production composes use) |
| Gateway | `ghcr.io/<owner>/yuzu-gateway-chisel:<version>` | chiselled Ubuntu 26.04, `FROM scratch` |
| Agents (×N, default 10) | `ghcr.io/<owner>/yuzu-agent-chisel:<version>` | chiselled Ubuntu 26.04, `FROM scratch` |

Files:

- `deploy/docker/Dockerfile.server.chisel`
- `deploy/docker/Dockerfile.gateway.chisel`
- `deploy/docker/Dockerfile.agent.chisel`
- `deploy/docker/Dockerfile.postgres` (published by `docker-publish-postgres`, not the chisel job)
- `deploy/docker/docker-compose.demo.yml` — the demo stack
- `deploy/docker/demo-gateway-sys.config` — gateway upstream/listener config
- `scripts/start-demo.sh` — the launcher (entry point; `--build` also builds/tags `yuzu-postgres`)

## Quick start

```bash
# Bootstrap: build the chiselled images locally and run the stack. --build is
# needed only until a tagged release publishes the -chisel images (the
# docker-publish-chisel job does that on every release — see "Publishing").
bash scripts/start-demo.sh --build

# Steady state, once images are published: pull the pinned release images.
bash scripts/start-demo.sh                # uses local images if present, else pulls
bash scripts/start-demo.sh --pull         # force a refresh from GHCR

# Knobs
bash scripts/start-demo.sh --agents 25    # number of agent clients (default 10)
bash scripts/start-demo.sh --version 0.13.0
bash scripts/start-demo.sh --keep         # don't wipe state on start

# Lifecycle
bash scripts/start-demo.sh status
bash scripts/start-demo.sh logs server
bash scripts/start-demo.sh token          # reprint the enrollment token
bash scripts/start-demo.sh stop
```

> **Pulling published images?** GHCR packages are private by default — for
> `--pull` (or the steady-state auto-pull) the `-chisel` packages must be made
> public, or you must `docker login ghcr.io` with a PAT that has `read:packages`.
> `--build` needs no registry auth (it builds locally).

When it is up:

- Dashboard / REST: `http://localhost:8080` (`admin` / `adminpassword1`)
- Gateway health / metrics: `http://localhost:8081/healthz`, `http://localhost:9568/metrics`
- Join more machines: point a native `yuzu-agent` at `<host>:50051` (the
  gateway's agent port is published) with the token in
  `/tmp/yuzu-demo/enrollment-token`.

The launcher does a **clean start by default** (`down -v` then `up`) so every
run yields an identical fleet of exactly N agents. Pass `--keep` to preserve
state across restarts.

## The stability contract

Every image in `docker-compose.demo.yml` is pinned to `${YUZU_VERSION:-X.Y.Z}`.
There is intentionally **no `build:` section** in the compose file: in steady
state the stack pulls immutable, signed, released GHCR images, so it only
changes when you bump `YUZU_VERSION` to a new release. `--build` exists only to
bootstrap the images locally before they are published.

`scripts/check-compose-versions.sh` is part of the release gate and now tracks
`docker-compose.demo.yml`: at release time the `${YUZU_VERSION:-...}` default
in the demo compose must equal the version being tagged, exactly like the
production compose files. (The check was extended to recognise the `-chisel`
repo suffix.)

## Why "chiselled Ubuntu 26.04"

[Chisel](https://github.com/canonical/chisel) cuts a minimal root filesystem
from Ubuntu package *slices* — only the files actually needed — which we then
assemble `FROM scratch`. The result is a distroless-style image that is still
"Ubuntu inside": no shell, no apt, no package manager, far smaller attack
surface, and no CVEs from packages you never installed.

| Image | Chiselled | Prior (debian/alpine) |
|-------|-----------|-----------------------|
| server | **~85 MB** | ~177 MB |
| gateway | **~111 MB** | (alpine) |
| agent | **~108 MB** | (debian) |

The runtime slice set per image:

- **Common:** `base-files`, `base-passwd_data` (/etc/passwd+group), `netbase_config`
  (/etc/protocols+services), `ca-certificates_data`, `libc6_libs` (glibc — and
  critically the dlopened **NSS modules** `libnss_dns`/`libnss_files`, without
  which `getaddrinfo` can't resolve the `server`/`gateway` compose hostnames),
  `libgcc-s1_libs`, `libstdc++6_libs`, `libssl3t64_libs`, `zlib1g_libs`,
  `busybox-static_bins`.
- **server / agent:** also `libsqlite3-0_libs`. The agent additionally carries
  `libyuzu_agent_core.so` and the plugin directory (`LD_LIBRARY_PATH` makes them
  discoverable since there is no `ldconfig` at runtime).
- **gateway:** also `libncursesw6_libs` + `libtinfo6_libs` (the BEAM emulator
  links ncurses). The Erlang release bundles its own ERTS (`include_erts`), so
  no Erlang install is needed — only the shared libs ERTS links against.

### Builder vs runtime

The runtime image is 100% Ubuntu 26.04 chisel slices. The *builder* stage is
throwaway scaffolding:

- server / agent build on `debian:trixie-slim` (proven, fast with the existing
  vcpkg/ccache cache mounts; Canonical apt mirrors have historically been flaky
  from CI). Build-on-older-glibc / run-on-newer-glibc is the safe direction.
  Pass `--build-arg BUILDER_IMAGE=ubuntu:26.04` to compile on Ubuntu itself.
- gateway builds on `erlang:28` (debian/**glibc**, NOT `erlang:28-alpine`) — the
  bundled ERTS + crypto NIF must link the same libc family as the chiselled
  Ubuntu runtime.

### The healthcheck / shell tradeoff

A `FROM scratch` image has no shell, so the production compose healthchecks
(`bash -c 'exec 3<>/dev/tcp/...'`, `wget`) would not work. Each chiselled image
therefore bakes a single **static busybox** (`busybox-static_bins`); the demo
compose healthchecks call `/bin/busybox wget --spider`. The gateway goes
further and symlinks busybox's *full applet set* so the Erlang/OTP release boot
script (`bin/yuzu_gw`, which shells out to `dirname`/`sed`/`grep`/`awk`/…) has a
working POSIX userland.

This is the reason the chiselled images are published under a **`-chisel` repo
suffix** instead of replacing the production `yuzu-server`/`yuzu-gateway`
images: the production images and their compose files assume a `bash` userland
the chiselled images deliberately omit. Keeping them separate is additive and
risk-free to existing deployments.

## How the demo enrols agents

The launcher runs the same two-phase flow as the viz-UAT rig:

1. Bring up server + gateway; wait for both healthchecks.
2. Log in as admin, `POST /api/settings/enrollment-tokens` to mint a multi-use
   token.
3. Bring up the agent tier scaled to `DEMO_AGENT_COUNT` (compose
   `deploy.replicas`), passing the token. A valid enrollment token
   auto-enrols the agent — no manual approval step.
4. Poll `/metrics` until `yuzu_agents_registered_total >= N`.

Each agent replica mounts its **own tmpfs** at the data dir, so the persistent
agent UUID (`identity_store`) is unique per container and the fleet shows N
distinct agents rather than one. tmpfs also makes the agents ephemeral, which
is what makes a clean restart reproducible.

## Getting agents onto real endpoints

The in-compose agents are Linux containers. To enrol a partner's **Windows,
Linux, and macOS** machines, ship them the agent via the **agent-bundle**
delivery image — one chiselled container holding all three triplets
(`windows-x64`, `linux-x64`, `macos-arm64`) at the same version, with both
native installers and raw payloads. They `docker pull` it, extract the right
triplet per endpoint, and point each agent at `<host>:50051` with the demo
enrollment token. Build/usage: `docs/agent-bundle.md` and
`scripts/build-agent-bundle.sh`.

## Publishing (release pipeline)

The `docker-publish-chisel` job in `.github/workflows/release.yml` builds all
three `*.chisel` Dockerfiles for **linux/amd64** (the QEMU-emulated arm64 leg
was dropped; see the open decision below) and pushes them as
`ghcr.io/<owner>/yuzu-{server,gateway,agent}-chisel:<version>`, signed (cosign
keyless) with SLSA provenance. It is gated on the same core build jobs as
`docker-publish` (`build-linux`, `build-gateway`) and runs in parallel with it.
Since #5242 it **is** a dependency of the `release` job, so the chisel images'
SBOMs are always release assets inside `SHA256SUMS`; a failed chisel build now
blocks the release.

The three-triplet **agent bundle** (`yuzu-agent-bundle-chisel`) is *not* built by
this job — it repackages the release's own signed agent binaries for three OS
triplets and is published separately after the release (see `docs/agent-bundle.md`
and `scripts/build-agent-bundle.sh`).

> **Open decision — arm64 build strategy.** The job currently builds arm64 via
> **QEMU emulation** on the amd64 self-hosted runner. The C++ images compile all
> vcpkg dependencies (gRPC, abseil, protobuf, OpenSSL) from source, which is very
> slow under emulation and may need the 240-minute timeout on a cold cache. For
> a sustainable release cadence, move the arm64 leg to a **native arm64 runner**
> (self-hosted, or a GitHub-hosted `ubuntu-24.04-arm`) and merge per-arch
> manifests. This needs a runner-topology decision — see the team before relying
> on the QEMU path for every release.

Until a release publishes these images, run the demo with `--build` on the
target architecture. On an arm64 host (Apple Silicon, Ampere, Graviton) that
produces native arm64 images directly.
