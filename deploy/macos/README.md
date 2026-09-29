# BigMags — macOS CI runner provisioning spec

The macOS/Apple-Silicon self-hosted CI leg, peer to Big Tam (Linux,
`deploy/linux/`) and Wee Tam (Windows, `deploy/windows/`). Registers the
`yuzu-bigmags-macos` runner pool that `ci.yml`'s `macos` job targets, replacing
the GitHub-hosted `macos-15` image for the **test** leg. (The `release.yml`
notarize build stays on hosted `macos-15` until on-box signing is set up — see
"Phase B" at the bottom.)

**The box:** Mac Mini, Apple M4 Pro, 12 cores, 24 GiB unified memory, macOS 26
(arm64). Hostname `BigMags`. Administered over Tailscale.

## Divergences from Big Tam / Wee Tam (read first)

This box is a different class of machine from the Threadripper Tams, so the
model deliberately diverges in three places:

1. **2 runner agents, not 4.** 24 GiB and no user-exposed CPU-affinity/CCD
   pinning on Apple Silicon. Two agents let a push/nightly build not block a PR
   check while staying inside the memory envelope. Falling back to 1 is trivial
   (deregister one service, remove one inventory row). Naming keeps the
   load-bearing `-N` suffix: `yuzu-bigmags-macos-0`, `yuzu-bigmags-macos-1`.
2. **No CPU pinning / no `Start-PinnedRunner` equivalent.** There is no
   `taskset`/CCD affinity to replicate. Per-agent build parallelism is bounded
   by `YUZU_BUILD_JOBS` in the runner `.env` (see Contracts) instead — the one
   knob that must be tuned against real memory pressure (Phase 4).
3. **No PostgreSQL, no per-agent PG cluster.** macOS is an agent-only platform
   (ADR-0035 / #2394): the server `[pg]` suite skips when
   `YUZU_TEST_POSTGRES_DSN` is unset, which it is here. No sanitizers either
   (none in CI; also broken on macOS 26 "Tahoe").

The runner **service** is a **system LaunchDaemon** (`/Library/LaunchDaemons/
com.yuzu.ci-runner.rN.plist`) running `run.sh` as `yuzuci` — NOT the runner's own
`svc.sh`. On macOS `svc.sh` installs a per-*user* LaunchAgent that only runs while
that user has an active GUI session, which a headless service account never has;
a LaunchDaemon runs at boot with no login. (This is the one place the runner's
built-in service model doesn't fit a headless box.)

## Standing up a new box

Steps 1–2 are one-time box setup. Steps 3–4 are per-agent and are where the
cutover happens. Every command below was validated on BigMags on 2026-08-17
except where marked "verify".

### 1. OS baseline

```bash
# hostname should already read BigMags on all three scopes
scutil --get ComputerName; scutil --get LocalHostName; scutil --get HostName

# A sleeping runner is a hung CI job. Never system-sleep; never disk-sleep;
# no power nap; auto-restart after a power blip.
sudo pmset -a sleep 0 disksleep 0 powernap 0 autorestart 1

# Command Line Tools (Apple Clang >= 16 for -std=c++23; BigMags shipped clang 21).
# Headless install (avoids the GUI xcode-select --install popup over SSH):
sudo touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in_progress
softwareupdate -l | grep -i "command line tools"          # find the label
sudo softwareupdate -i "Command Line Tools for Xcode 26.6-26.6"   # match your OS
sudo rm -f /tmp/.com.apple.dt.CommandLineTools.installondemand.in_progress
```

CLT SDK is sufficient for CI parity: the ES SDK (`usr/lib/libEndpointSecurity.tbd`
+ `usr/include/EndpointSecurity/`) ships with the Command Line Tools SDK too
(it is not an `.framework` bundle, and "needs full Xcode" is a myth — see
`docs/darwin-compat.md`'s EndpointSecurity row); today's build probe is
mis-formed and never finds it on any SDK (`feat/macos-spark-a0.5-es-probe`
fixes this), so the real ES client currently compiles as a `required:false`
no-op regardless of SDK. The `com.apple.developer.endpoint-security.client`
entitlement + root + a signed/notarized binary are the actual on-device
gates for the real ES path, not the SDK choice.

### 2. Shared build substrate

```bash
# Homebrew — the box's egress is sometimes 429'd (shared NAT / GitHub incidents),
# so the curl installer can fail; the git method uses the git protocol and dodges it.
sudo mkdir -p /opt/homebrew && sudo chown -R "$(whoami):admin" /opt/homebrew
git clone https://github.com/Homebrew/brew /opt/homebrew
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"

# CRITICAL: the CI "Install dependencies" step runs `brew` and
# `pip3 --break-system-packages pyyaml` as the NON-admin runner user `yuzuci`
# (group staff), which cannot write an admin-owned prefix. Make /opt/homebrew
# staff-group-writable + setgid — the same treatment /opt/ci gets below — or the
# FIRST real CI job fails at "Install dependencies" (brew relink / brew-python
# site-packages write). Validating a build as an admin user does NOT exercise this.
sudo chgrp -R staff /opt/homebrew
sudo chmod -R g+rwX /opt/homebrew
sudo find /opt/homebrew -type d -exec chmod g+s {} +

# CI toolchain packages. NOTE pkg-config — the hosted macos-15 image bakes it in
# and the ci.yml brew line historically omitted it; a bare box needs it or vcpkg's
# abseil pkgconfig-fixup fails (delta #1). ci.yml's macOS brew line now lists it too.
export HOMEBREW_NO_AUTO_UPDATE=1
brew install ninja ccache pipx autoconf automake libtool pkg-config

# CI root (mirrors /srv/ci on Linux, D:\ci on Windows). setgid + group staff so
# the yuzuci runner user (a staff member) inherits access to the warm binary cache.
sudo mkdir -p /opt/ci && sudo chown "$(whoami):staff" /opt/ci && chmod 2775 /opt/ci
mkdir -p /opt/ci/{tool_cache,ccache,src} /opt/ci/tool_cache/yuzu-vcpkg-binary-cache-macos

# Commit-tracked bootstrapping fetcher (see below) — install it for cache warming.
install -m 755 "$(git -C /opt/ci/src/Yuzu rev-parse --show-toplevel)/deploy/macos/vcpkg-fetch.sh" /opt/ci/vcpkg-fetch.sh
```

The **pinned per-user toolchain (cmake 4.3.4, meson 1.11.2, PyYAML) and vcpkg are
NOT provisioned at the box level** — the `ci.yml` macOS job installs them itself
every run (`pipx install cmake==4.3.4`, `pipx install meson==…`, `pip pyyaml`,
`lukka/run-vcpkg` clones vcpkg into the workspace). The box only supplies brew +
CLT + the shared binary cache. (The `/opt/ci/vcpkg` + `/opt/ci/src/Yuzu`
checkout used for the initial manual cache-warm is optional scaffolding, not a
runner dependency.)

### 2a. Warm the binary cache (once, before first job)

Cold vcpkg builds gRPC/protobuf/libpq+postgresql from source and pull ~20 GitHub
tarballs — slow, memory-heavy, and 429-prone during any GitHub degradation. Warm
it **once, serially**, so the runners (which share the cache) never pay it and
never run two cold builds at once:

```bash
export VCPKG_ROOT=/opt/ci/vcpkg VCPKG_DEFAULT_BINARY_CACHE=/opt/ci/tool_cache/yuzu-vcpkg-binary-cache-macos
export X_VCPKG_ASSET_SOURCES="clear;x-script,/opt/ci/vcpkg-fetch.sh {url} {sha512} {dst};x-block-origin"
git clone https://github.com/microsoft/vcpkg /opt/ci/vcpkg
git -C /opt/ci/vcpkg checkout 4b77da7fed37817f124936239197833469f1b9a8
/opt/ci/vcpkg/bootstrap-vcpkg.sh -disableMetrics
# in tmux, under caffeinate, from a Yuzu checkout:
./scripts/setup.sh --tests --native-file meson/native/macos-appleclang.ini
```

Write the warm cache **directly** into
`/opt/ci/tool_cache/yuzu-vcpkg-binary-cache-macos` (the path the runner jobs read
via `${runner.tool_cache}/yuzu-vcpkg-binary-cache-macos`, with
`RUNNER_TOOL_CACHE=/opt/ci/tool_cache`). The cache is content-addressed, so if you
warmed a different dir just copy the zips over. The `X_VCPKG_ASSET_SOURCES`
fetcher is a **bootstrapping aid only** — it is NOT set in the runner environment
(the warm cache means jobs don't download; the Tams carry no fetcher). Keep it
for re-warming when a dependency changes or GitHub is degraded.

### 3. The runner identity

```bash
# Dedicated NON-admin service account (GitHub advises against admin/root runners).
# staff primary group → inherits /opt/ci + /opt/homebrew access via the setgid above.
sudo sysadminctl -addUser yuzuci -fullName "Yuzu CI Runner" -home /Users/yuzuci -shell /bin/zsh
# sysadminctl ASSIGNS the home but does not CREATE it — do so explicitly, or the
# runner's ~/Library/Caches/ccache and ~/.local (pipx) writes have nowhere to go.
sudo createhomedir -c -u yuzuci
# yuzuci needs brew on PATH. Write as root to the absolute path then hand it over;
# `sudo -u yuzuci … ~` resolves to the CALLER's home without -H, so avoid that form.
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' | sudo tee -a /Users/yuzuci/.zprofile >/dev/null
sudo chown yuzuci:staff /Users/yuzuci/.zprofile
```

### 4. Register the agents

Use `register-bigmags-runner.sh` (this dir) per agent index. It applies the
drain gate, mints a registration token, lays down `.env`/`.path`, configures the
runner with the exact labels, and installs the launchd service as `yuzuci`:

Run it **as your admin user (NOT under `sudo`)** — it mints the registration
token with *your* `gh` auth and `sudo`s internally for the root-only steps.
`sudo ./register…` would run `gh` as root, whose `HOME`/keychain has no auth.

```bash
./deploy/macos/register-bigmags-runner.sh 0
./deploy/macos/register-bigmags-runner.sh 1
```

Then self-test and record the manifest:

```bash
./deploy/macos/assert-toolchain.sh          # must pass before you trust the pool
```

**CUTOVER ORDERING (load-bearing).** The `runner-inventory-sentinel` cron ticks
every 30 min and fails on any drift between `.github/runner-inventory.json` and
GitHub's actual runner set (`strict_unknown_runners: true`). So:

1. Register both agents (step 4) so they report **online** with exactly
   `self-hosted, macOS, ARM64, yuzu-bigmags-macos`.
2. **Immediately** merge the inventory + workflow PR (they ship together on
   `feat/bigmags-macos-runner`). Registering before the rows land →
   `UNKNOWN` drift; merging before online → `MISSING`/`OFFLINE` drift. Keep the
   two close.
3. Update the `installed:` dates in the inventory rows to the real date, and
   rename `changelog.d/NNNN-…` to the real PR number, before merge.
4. Once GitHub's API is healthy, run `runner-health-check.py --mode preflight`
   (needs the `RUNNER_INVENTORY_TOKEN` Administration:read PAT) to confirm
   `bigmags_pool_healthy` emits `true` — the `macos` job fail-closed-skips until
   it does.

### 5. Deregister / stop / recover

**Stop an agent** (leaves it registered, just not listening):
```bash
sudo launchctl bootout system/com.yuzu.ci-runner.r0
```

**Deregister an agent** — ORDER MATTERS. `KeepAlive=true` respawns `run.sh` the
instant `config.sh remove` makes the listener exit 0, so **boot the daemon out
first**, then remove:
```bash
sudo launchctl bootout system/com.yuzu.ci-runner.r0 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.yuzu.ci-runner.r0.plist
( cd /opt/ci/actions-runner/r0 && sudo -u yuzuci ./config.sh remove \
    --token "$(gh api -X POST repos/DevNullLtd/Yuzu/actions/runners/remove-token --jq .token)" )
```

**Bump the runner version**: deregister, then re-run
`sudo RUNNER_VERSION=<new> ./deploy/macos/register-bigmags-runner.sh <idx>`
(or omit `RUNNER_VERSION` to auto-take the latest). Do it at an idle window — the
register script refuses while a `Runner.Worker` (job) is live.

**Recover a wedged daemon** (crash-looping — check `_diag/daemon.err.log`):
```bash
sudo launchctl bootout system/com.yuzu.ci-runner.r0 2>/dev/null || true
sudo launchctl bootstrap system /Library/LaunchDaemons/com.yuzu.ci-runner.r0.plist
```
The `ThrottleInterval=30` in the plist caps respawn rate so a misconfig can't
hot-loop and flood the logs / fill `/opt/ci` while you investigate.

## Contracts (why the env vars exist)

Set in each agent's runner-directory `.env` / `.path` (read by the launchd
service at job start):

| Var | Value | Why |
|---|---|---|
| `RUNNER_TOOL_CACHE` | `/opt/ci/tool_cache` | Shared vcpkg binary-cache root. `VCPKG_DEFAULT_BINARY_CACHE` in `ci.yml` derives from it and `cache-prune.yml`'s `prune-macos` job prunes under it. Shared across both agents so they share one warm cache. (Also the telemetry-DB root **once Phase 4 wires `ci-telemetry.py` into the `macos` job** — not yet live; see Phase 4 below.) |
| `YUZU_BUILD_JOBS` | `6` (tune) | Per-agent build parallelism, honored by `meson compile -j "${YUZU_BUILD_JOBS:-6}"` in the `macos` job. **The single most important knob on 24 GiB.** 2 agents × 6 = 12 cores; worst case is both agents cold-compiling at once. Drop to 4 if you see swap — but note the swap signal needs the Phase-4 telemetry DB, which isn't wired yet, so re-validate 6 under concurrent load. |
| `HOMEBREW_NO_AUTO_UPDATE` | `1` | Stops `brew install` from git-pulling `/opt/homebrew` on every job (write + network round-trip); steady-state installs become a fast no-op. Written into each agent's `.env` by `register-bigmags-runner.sh`. |
| PATH (`.path`) | `/opt/homebrew/bin` + system | So `brew`/`pipx`/`python3` resolve for the job's "Install dependencies" step (which then prepends its own pipx bin dir to `GITHUB_PATH`). |

ccache: the `macos` job uses `~/Library/Caches/ccache`, which persists naturally
in `yuzuci`'s home on a persistent runner — no shared override needed.

## `toolchain-manifest.json`

**Not yet scripted (Phase 4 to-do).** The intent, mirroring Wee Tam: a
provisioner emits `/opt/ci/toolchain-manifest.json` (host-generated like a
lockfile, **not committed**) recording the resolved pins/env, and a manifest
cross-check is added to `assert-toolchain.sh`. Today `assert-toolchain.sh`
validates the **live substrate directly** (tools, versions, dirs, sleep state) —
which is the check that actually gates registration — rather than a JSON file.
Planned shape:

```json
{
  "generated": "<date>", "host": "BIGMAGS", "runner_count": 2,
  "pins": { "vcpkg_baseline": "4b77da7f…", "cmake": "4.3.4", "meson": "1.11.2",
            "pyyaml": "6.0.3", "build_jobs": 6 },
  "env": { "RUNNER_TOOL_CACHE": "/opt/ci/tool_cache",
           "VCPKG_BINARY_CACHE": "/opt/ci/tool_cache/yuzu-vcpkg-binary-cache-macos" },
  "telemetry": { "root": "/opt/ci/tool_cache",
                 "dbs": ["/opt/ci/tool_cache/…/yuzu-bigmags-macos-0/test-runs.db",
                         "…/yuzu-bigmags-macos-1/test-runs.db"] },
  "tools": [ { "name": "clang", "version": "21.0.0", "required": true }, … ]
}
```
No `postgres_clusters` section — macOS provisions no PG (unlike Wee Tam).

## Deltas from the GitHub-hosted `macos-15` image

Things the ephemeral hosted image gave us for free that a bare box needs:

1. **`pkg-config`** — added to the box provisioning AND to `ci.yml`'s macOS brew
   line. Without it, vcpkg abseil's pkgconfig-fixup fails.
2. **No authenticated asset fetcher in the hosted CI** — confirmed by grep. The
   429s we saw warming the cache were a GitHub incident, not a chronic throttle.
   Runners rely on the warm local binary cache (no downloads → no 429s), exactly
   like the Tams. `vcpkg-fetch.sh` is operator tooling for warming only.

## Phase B — on-box signing / notarization (later, separate)

`release.yml`'s `build-macos` already codesigns + notarizes on hosted `macos-15`
using existing secrets (`MACOS_SIGNING_CERT`, `MACOS_NOTARIZATION_APPLE_ID`, …).
Migrating it to BigMags needs a **persistent, managed keychain** on the box
(create/unlock/delete per run, no resident cert/password) and `notarytool`
credential storage — the single biggest new operational concern, deliberately
deferred until the test leg is proven here.
