# CI cutover runbook — Shulgi (Ubuntu 24.04) → Big Tam (Ubuntu 26.04)

Status: **CUTOVER COMPLETE** (2026-06-20/21). **Every** self-hosted job has moved
off the old single-host runners: all Linux → Big Tam (`yuzu-bigtam-linux`), all
Windows → Wee Tam (`yuzu-weetam-windows`). Sequence: `ci.yml` linux (#1609,
merged) → `sanitizer-tests` + `nightly` + `codeql` Linux → **`release.yml` Linux
legs + the remaining Windows stragglers + build-speed** (PR #1615). **`yuzu-wsl2-linux`
(Shulgi) and `yuzu-local-windows` are retired**, and are removed from
`.github/runner-inventory.json` (item 6). `proto-compat` / `cache-prune-linux`
are pinned to `yuzu-bigtam-linux`; they previously used the bare
`[self-hosted, Linux, X64]` label, which the Shulgi WSL2 runner also carried.
Deregistering the runners in GitHub (Settings → Actions → Runners) is a separate
admin step; until it is done the sentinel reports them as unknown runners.

The sections below are the historical runbook + per-file record; the future-tense
"deferred" / "pre-flip" framing is preserved as the record of how the flip was
sequenced.

Branches: `ci/ubuntu-2604-cutover` (ci.yml, merged),
`ci/bigtam-followup-self-hosted-legs` (sanitizer/nightly/codeql), and
`ci/retire-shulgi-localwindows` (#1615 — release + Windows stragglers +
build-speed). Several extra fixes were
needed beyond the plan — some because Big Tam runs **4 runners on one host**
(Shulgi was one), two surfaced only by the **cold from-source rebuild** Big Tam
forces (its caches start empty):

- **meson not on the default PATH (follow-up discovery).** ci.yml installs meson
  via `pip3 install --user` (→ `~/.local/bin`) and adds it to `$GITHUB_PATH`
  **per-job**; that PATH addition does NOT persist to other workflows. The
  sanitizer-tests + codeql Linux legs were *verify-only* (asserted tools on
  PATH, installed nothing) on the assumption the toolchain was baked into the
  host — true on the long-lived Shulgi WSL2 runner, FALSE on Big Tam. Fix: give
  those legs a real flock-wrapped `Install system packages` step (apt toolchain
  + `pip3 install ... requirements-ci.txt` + `echo ~/.local/bin >> $GITHUB_PATH`),
  mirroring ci.yml. nightly already installed, so it only needed the flock wrap.
- **libpq breaks the sanitizer triplets when built from source (cold-build
  discovery).** The `x64-linux-{asan,tsan}` overlay triplets are
  `LIBRARY_LINKAGE dynamic`, so vcpkg built libpq as a `.so`. libpq is a recent
  dep (Postgres substrate, ADR-0006) and the sanitizer caches hadn't been rebuilt
  since it landed, so this only bit on Big Tam's cold build (would bite Shulgi
  too on a cold rebuild). Two failures: TSan — PostgreSQL's shared-lib
  `libpq-refs-stamp` check rejects the injected `__tsan_func_exit` ("must not
  call exit") → vcpkg install fails; ASan — a dynamic libpq.so emits no
  standalone `libpgcommon.a`, so `meson.build:320`'s `find_library('pgcommon',
  required:true)` fails. Fix: per-port `if(PORT STREQUAL "libpq") set(...static)`
  in both sanitizer triplets (matches stock x64-linux); vcpkg's libpq Makefile
  builds the `.so`/runs refs-stamp only on the `all-shared-lib` path, so the
  static path sidesteps both. Commit on the follow-up branch.
- **apt lock:** the matrix legs race `apt-get`. `DPkg::Lock::Timeout` does NOT cover
  `apt-get update`'s lists lock, so the install step is wrapped in `flock -w 600 9 …
  9>/tmp/yuzu-ci-apt.lock`. **The sanitizer/nightly/codeql legs must add the SAME
  flock when they move to Big Tam** (reuse that lock path so they coordinate).
- **eunit fixed-port collision:** `yuzu_gw_health_nf_tests` hardcoded `health_port=18081`
  → 2nd concurrent leg got `eaddrinuse` → setup crash → eunit cancelled the group
  ("0 failures, one cancelled, exit 1"). Fixed to ephemeral port 0 (commit `60412341`).
- Pre-created shared `yuzu-ci-postgres` container (no per-leg creation race) + job-env
  `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` (harmless defence; the cookie reports were red herrings).
- The per-runner `.env` (HOME/ERL_EPMD_PORT) was tried but the runner ignored it; it
  proved unnecessary once the above landed.

The self-hosted Linux CI is moving from Shulgi (`yuzu-wsl2-linux`, WSL2 Ubuntu
24.04, GCC 13 / Clang 19) to the Big Tam pool (`yuzu-bigtam-linux-{0..3}`, native
Ubuntu 26.04, **GCC 15 / Clang 21**). This runbook is the one-shot flip to run
**once Big Tam is back online and healthy**.

## Why it is deferred

GCC 15 / Clang 21 exist only on Ubuntu 26.04. Shulgi is 24.04 and **cannot**
build them. While Big Tam is offline, Shulgi is the only available Linux runner —
flipping the compiler now would fail every self-hosted Linux job at the
`apt-get install gcc-15` step. So the scaffolding below is landed, but the live
`runs-on:` / compiler / `ImageOS` changes wait for Big Tam.

## What is already staged (this PR)

- `meson/native/linux-gcc15.ini`, `meson/native/linux-clang21.ini` (additive; the
  24.04 `linux-gcc13.ini` / `linux-clang19.ini` stay for Shulgi).
- `deploy/docker/Dockerfile.ci-linux`, `Dockerfile.ci` (+ `ci-entrypoint.sh`),
  and the four sanitizer images `Dockerfile.{server,agent}-{asan,tsan}` →
  `ubuntu:26.04` + gcc-15/clang-21. (`Dockerfile.runner-linux` left on its
  `actions-runner` base — it is the *containerized* runner path, not Big Tam,
  which is a native runner.)
- `.github/workflows/pre-release.yml` `install-deb` matrix gained `ubuntu:26.04`.

## Pre-flip verification (do these first)

Status verified on Big Tam 2026-06-20 (now back online): OS = Ubuntu 26.04,
gcc-15/g++-15 installed, clang-21 + the rest apt-installable, `runner` user has a
dedicated `/etc/sudoers.d/10-runner` NOPASSWD grant, runners run as `runner` from
`/home/runner/r{0..3}`. Outstanding items below.

0. **Container runtime (HARD PREREQ).** `scripts/ci/ensure-postgres.sh` needs
   docker (or a pre-set `YUZU_TEST_POSTGRES_DSN`) for the server-test step. Big
   Tam shipped with **no** container runtime. Install it (needs root on Big Tam):
   ```
   sudo apt-get update && sudo apt-get install -y docker.io
   sudo usermod -aG docker runner
   sudo systemctl restart 'actions.runner.Tr3kkR-Yuzu.yuzu-bigtam-linux-*.service'
   sudo -u runner docker run --rm hello-world   # verify
   ```
   (`docker.io` 29.1.3 is in 26.04's archive; Docker Hub egress confirmed.)
   Without this the `linux` job fails at "Ensure Postgres".
1. **Big Tam online & healthy** — `gh api repos/Tr3kkR/Yuzu/actions/runners`
   shows `yuzu-bigtam-linux-*` as `online`; ci.yml `preflight` reports
   `bigtam_pool_healthy == true`.
2. **Toolchain present on the host** — validated on `ubuntu:26.04` and on Big Tam:
   gcc 15.2.0 default, clang-21 1.21.1.8,
   `libasan8`/`libubsan1`/`libtsan2`/`libssl3t64`/`libgcc-15-dev`/`libpq5` all
   resolve; a C++23 `<print>` program compiles & runs.
3. **`erlef/setup-beam` ImageOS — RESOLVED: keep `ubuntu24`.** setup-beam has
   **no** `ubuntu26` prebuilt OTP (supported ImageOS tops out at `ubuntu24`).
   ImageOS only selects which OTP tarball to fetch; the 24.04 build runs on 26.04
   (same `libcrypto.so.3` soname). **Do NOT flip ImageOS to ubuntu26** — it would
   fail to resolve the asset. Validate via `gateway eunit` on the Big Tam leg.
4. **Per-runner state** — `scripts/ci/ensure-postgres.sh` works on Big Tam (needs
   item 0); ccache (`~/.cache/ccache`) and the vcpkg binary cache
   (`runner.tool_cache/yuzu-vcpkg-binary-cache-linux`) directories are writable.

## The flip (edits)

Reference by content — line numbers drift. In every file below, the change is
`gcc-13`→`gcc-15`, `g++-13`→`g++-15`, `clang-19`→`clang-21`,
`clang++-19`→`clang++-21`, `linux-gcc13.ini`→`linux-gcc15.ini`,
`linux-clang19.ini`→`linux-clang21.ini`. **`ImageOS: ubuntu24` stays `ubuntu24`**
(see pre-flip item 3). Pin compile jobs to `…, yuzu-bigtam-linux` and gate them on
`bigtam_pool_healthy` (compiler-agnostic jobs like proto-compat stay on the
broader `linux_pool` gate).

Incremental order: do ci.yml first, prove it green on Big Tam, then the rest.

1. **`.github/workflows/ci.yml`** — `linux` job — **DONE (2026-06-20).**
   matrix→`[gcc-15, clang-21]`, the `exclude` ternaries, the apt line, `CC`/`CXX`,
   `--native-file`, `-Db_lto`; `runs-on`→`[self-hosted, Linux, X64, yuzu-bigtam-linux]`;
   `if`→`bigtam_pool_healthy == 'true'` (new gate added to
   `scripts/ci/runner-health-check.py` + the preflight outputs). `ImageOS` left at
   `ubuntu24` with an explanatory comment. `proto-compat` left on the generic pool
   (no compiler — needs no pin). The GHA-hosted **canary** stays on
   `ubuntu-24.04`/gcc-13 per the "keep GHA-hosted on 24.04" decision, so it no
   longer mirrors the primary toolchain (a known, accepted divergence).
2. **`.github/workflows/sanitizer-tests.yml`** — **DONE (2026-06-21).** Both legs
   repinned to `…, yuzu-bigtam-linux`; new `preflight` job gates both on
   `bigtam_pool_healthy`; gcc-15/g++-15 + `linux-gcc15.ini`;
   `YUZU_GW_ALLOW_DEFAULT_COOKIE=1`. The *verify-only* toolchain step was
   replaced with a real flock-wrapped `Install system packages` step (meson is
   not on Big Tam's default PATH — see shared-host fixes above).
3. **`.github/workflows/nightly.yml`** — **DONE (2026-06-21).** ASan + TSan +
   Coverage all repinned to `…, yuzu-bigtam-linux` (coverage was the generic
   pool, but a gcc-15 build can't land on the Shulgi/gcc-13 fallback, so it is
   pinned too; renamed "Coverage (GCC 13)"→"(GCC 15)"); new `preflight` job gates
   all three on `bigtam_pool_healthy`; every apt line flock-wrapped (incl. the
   best-effort `gdb` install in the TSan gdb step); gcc-15 + `linux-gcc15.ini`;
   `YUZU_GW_ALLOW_DEFAULT_COOKIE=1`.
4. **`.github/workflows/codeql.yml`** — **DONE (2026-06-21).** Linux matrix leg
   repinned to `…, yuzu-bigtam-linux`; new Linux-only flock-wrapped
   `Install system packages` step (same meson-PATH reason); `TOOLS=` +
   `CC`/`CXX` → gcc-15, `linux-gcc15.ini`; Windows leg unchanged. **No
   `bigtam_pool_healthy` gate** — a job-level `if` can't reference `matrix`, so
   gating just the Linux leg of this Linux+Windows matrix job would require
   splitting it (out of scope; CodeQL is not a required check).
5. **`.github/workflows/release.yml`** — **DONE (2026-06-21, #1615).** All 5
   self-hosted Linux legs (`build-linux`, `build-gateway`,
   `docker-publish{,-postgres,-chisel}`) pinned to `…, yuzu-bigtam-linux`;
   `build-linux` → gcc-15 (CC/CXX, verify-deps, `linux-gcc15.ini`);
   `build-windows` → `yuzu-weetam-windows`. The docker buildx local cache moved off
   the Shulgi-only `/mnt/d/docker-buildcache` mount to
   `${runner.tool_cache}/yuzu-docker-buildcache`. `CCACHE_MAXSIZE=30G` added so the
   build doesn't inherit the host default. (An interim pin to `yuzu-wsl2-linux` —
   the runner NAME, not a label — would have queued forever; Shulgi's label is
   `yuzu-shulgi`. release.yml only runs at tag time, so the first Big Tam release
   is its real validation; note Big Tam ships RPM 6.0 vs Shulgi's 4.x.)
6. **`.github/runner-inventory.json`** — **DONE for the inventory; runner
   deregistration on GitHub is still a separate admin step.** `yuzu-wsl2-linux` and
   `yuzu-local-windows` removed (both retired); `proto-compat` and
   `cache-prune-linux` pinned to `yuzu-bigtam-linux`, so those two jobs can no
   longer land on a still-registered Shulgi runner. The pool gates are
   label-driven, so retired runners just drop out (nothing gates on `all_healthy`).
7. **`docs/ci-architecture.md`** — **DONE (2026-06-21, #1615).** Runner-topology
   table consolidated (Big Tam = all Linux, Wee Tam = all Windows, both retired
   runners listed under "Retired"), tier summary + "Ubuntu 26.04 migration" marked
   COMPLETE, and a "Build speed" section added.
8. **Big Tam host provisioning (build speed)** — **DONE (2026-06-21).** On the
   `runner` user (shared `HOME=/home/runner` across r0–r3): ccache `max_size=50G`
   (host default 5 GiB is far too small); `mold` (`apt install mold`) wired via
   `-fuse-ld=mold` in the gcc-15/clang-21 native files; `rpm` (rpmbuild) for
   release packaging (absent on fresh 26.04 — was the first-release blocker);
   `requirements-ci.txt` (incl. meson 1.11.1) pre-installed in `~/.local` so the
   per-job `pip --user --require-hashes` is a no-op (no re-download).

## Rollback

Revert the `runs-on` pins and compiler tokens to gcc-13/clang-19/`ImageOS: ubuntu24`
and the jobs run on Shulgi again unchanged. The staged 26.04 Docker images and
native files are inert when nothing references them, so they need no rollback.
