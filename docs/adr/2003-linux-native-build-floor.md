# ADR-2003 — Linux native build floor: build in an EL9 container, declare glibc 2.34 for server, agent and gateway

**Status:** Proposed (2026-10-10) — open for review. **Do not start implementation until the "Questions for reviewers" below are answered on this PR.**
**Authors:** Fraser Jarvis (@fjarvis); design adjudication by the enterprise-architect (Fable) review, 2026-10-09
**Date:** 2026-10-10
**Relates to:** #5143 (glibc/libstdc++ floor), #5171 (gateway RPM cannot boot on RHEL-family), the v0.14.1 release notes (both listed as known issues), `docs/user-manual/README.md` "Supported Platforms", `docs/build-guide.md`, `docs/ci-architecture.md`, `docs/agent-bundle.md`, ADR-0008 (static vcpkg libpq/CRT picks)

---

## Context

Every v0.14.x Linux artifact — the `.tar.gz`, `.deb` and `.rpm` for the server, gateway and agent — is built natively on the self-hosted "Big Tam" runner: Ubuntu 26.04, `gcc-15`, mold, vcpkg triplet `x64-linux-static` (static vcpkg libraries; **dynamic glibc and libstdc++**). The result is that the binaries carry the *build host's* runtime floor, not a deliberately chosen one:

| Component | Needs at run time | Runs on | Does not run on |
|---|---|---|---|
| Server | glibc 2.38, `GLIBCXX_3.4.34` (GCC 15's libstdc++) | Ubuntu 26.04, Fedora 42 | Ubuntu 22.04 and 24.04, Debian 12 and 13, RHEL/Rocky 9 and 10 |
| Agent | glibc 2.38 and GCC 14's libstdc++ (`CXXABI_1.3.15`) | Ubuntu 24.04, 26.04, Fedora 42 | Ubuntu 22.04, Debian 12, RHEL/Rocky 9 |
| Gateway `.deb`/`.rpm` | glibc 2.38 (prebuilt Ubuntu-24 OTP) and the OTP `crypto` NIF's OpenSSL imports | Ubuntu 24.04/26.04 (`.deb`) | RHEL, Rocky, Fedora (`undefined symbol: EVP_sm4_cbc`; no RPM-based distribution is validated), older Debian/Ubuntu |

(Source: the Pre-release QA install legs, which failed the same six jobs for v0.14.0 and v0.14.1, and the "Supported Platforms" table in `docs/user-manual/README.md`.)

Two causes, both visible in the repository:

1. **#5143 — the floor is an accident of the build host.** The code itself needs only GCC 13 (`docs/build-guide.md`; `Dockerfile.server` already compiles the tree with gcc-13). `GLIBCXX_3.4.34` and glibc 2.38 are artefacts of *where* it is built. `docs/cpp-conventions.md` already names one symptom: the glibc-2.38 `__isoc23_*` scanf-family trap, which is policed by convention rather than eliminated.
2. **#5171 — the gateway's OTP is a prebuilt Ubuntu tarball.** `release.yml` installs OTP with `erlef/setup-beam` (`ImageOS: ubuntu24`). Its `crypto.so` is linked against Ubuntu's OpenSSL and imports `EVP_sm4_*`, which Red Hat's OpenSSL is built without. The `.deb` `Depends` line is hand-written (`adduser` only: `deploy/packaging/debian/build-deb.sh`, `build-gateway-deb.sh`), and the gateway RPM spec is `AutoReqProv: no` (`deploy/packaging/rpm/yuzu-gateway.spec`), so nothing declares an OpenSSL or glibc requirement either.

The mainstream enterprise Linux estate — RHEL/Rocky/Alma 9, Ubuntu 22.04 LTS (supported to April 2027), Debian 12 — is exactly what the current artifacts exclude. The only supported way onto those hosts today is a container image.

## Decision

**Declare one native Linux floor for 0.15.0 — glibc 2.34, `GLIBCXX_3.4.29`, `CXXABI_1.3.13`, `OPENSSL_3.0.0` (the RHEL/Rocky 9 baseline) — for the server, the agent and the gateway.** Build every native Linux artifact inside a Rocky 9 container with `gcc-toolset-15`, and build the gateway's OTP in that same container against EL9's own (dynamically linked) libcrypto.

1. **Floor image.** A maintained image, `deploy/docker/Dockerfile.build-el9`: `rockylinux:9` + `gcc-toolset-15` (same GCC major as the build host today) + mold (EPEL) + `rpm-build` + dpkg tooling (EPEL) + Erlang/OTP 28 built from a pinned-sha source tarball with dynamic SSL + rebar3. It is published to GHCR, pinned by digest and tracked by Dependabot.
2. **Toolchain mechanics.** `gcc-toolset` is the ODR-safe way to run a new compiler on an old runtime: it links only `libstdc++_nonshared.a` (stateless, newer code) into each object and leaves the **system `libstdc++.so.6` as the single runtime copy**. Nothing in the tree gets a private copy of libstdc++.
3. **vcpkg.** A new overlay triplet `triplets/x64-linux-el9-static.cmake`. This is load-bearing: `scripts/ci/vcpkg-triplet-sentinel.sh` keys on `vcpkg.json`, the triplet and the vcpkg commit — **not the toolchain** — so reusing the host-built `vcpkg_installed/x64-linux-static` inside the container would silently link glibc-2.38-era objects. A distinct triplet makes the sentinel key and install it separately.
4. **A symbol-floor gate.** `scripts/ci/check-elf-floor.sh` plus `deploy/packaging/linux-floor.json` (glibc 2.34, GLIBCXX 3.4.29, CXXABI 1.3.13, OPENSSL_3.0.0, and a forbid-list containing `EVP_sm4_*`) runs `objdump -T` over **every ELF in the staging directory** (binaries, all plugins, ERTS, `crypto.so`) and fails if any imported symbol version exceeds the floor. It runs in the release workflow after "Package archive" and in Pre-release QA, and is unit-tested on fixture symbol lists.
5. **Gateway (#5171).** OTP built in the floor image against EL9's libcrypto yields one `crypto.so` whose imports are a subset of every target distro's libcrypto. The RPM gets explicit `Requires: glibc >= 2.34, openssl-libs >= 3.0, ncurses-libs` (keeping `AutoReqProv: no`); the `.deb` gets `Depends: libssl3t64 | libssl3 (>= 3.0.0)`. SM4 ciphers disappear from `crypto:supports()`; nothing in Yuzu uses them.
6. **`.deb` dependencies.** Derived rather than hand-written — either `dpkg-shlibdeps` in a `debian:12` stage, or mapped from the gate's measured maxima: `libc6 (>= 2.34), libstdc++6 (>= 11), libgcc-s1`.
7. **Local validation without publishing.** `scripts/ci/floor-build.sh` is the same script CI runs: `docker run -v` of a clean clone → `meson setup/compile` → packaging → the floor gate. It publishes nothing and can be run on any Linux box with docker.

Windows and macOS are untouched: `build-windows` and `build-macos` do not change, the floor script is Linux-only, and the agent bundle repackages the same Linux tarball.

## Alternatives considered

| Alternative | Why not |
|---|---|
| **Static `libstdc++` / `libgcc` (`-static-libstdc++ -static-libgcc`) so only glibc remains** | **Rejected for the agent; unsafe.** All 62 agent plugins are `shared_library(... dependencies: [yuzu_agent_core_dep])`, so they link the C++ symbols of `libyuzu_agent_core.so` directly — not only the `plugin.h` C ABI — and the loader uses `dlopen(RTLD_LAZY\|RTLD_LOCAL)` (`plugin_loader.cpp`). A static libstdc++ in each DSO gives N copies of the exception globals, locale and typeinfo: a `std::exception` thrown in the core and caught in a plugin (or the reverse) fails the typeinfo match and terminates. spdlog, fmt and abseil would have the same ODR problem across copies. |
| **Bundle OpenSSL into the gateway (`--disable-dynamic-ssl-lib`) or ship `libcrypto.so.3` beside the release** | Makes Yuzu the patcher of an OpenSSL copy on every CVE, and changes the SBOM story. Kept only as the **fallback** if EL9's OpenSSL (EL9.8 ships 3.5.x) leaks `OPENSSL_3.x`-versioned symbols into `crypto.so` — the floor gate would catch that — in which case `security-guardian` owns the bundled-OpenSSL patch cadence. |
| **Build the gateway RPM on a Rocky/RHEL-9 runner only** | Fixes the RPM but not the `.deb`, the server or the agent; leaves two toolchains. Subsumed by the container build. |
| **Drop the SM4 dependency from OTP** | It is OTP's own link, not Yuzu code; not ours to remove. Removing it falls out of building against EL9 anyway. |
| **Declare the gateway RH-family unsupported; container only** | Abandons RHEL, the mainstream enterprise platform. |
| **Floor = Ubuntu 24.04, native build with gcc-14** | Still excludes RHEL 9, Ubuntu 22.04 and Debian 12. Kept only as the last resort if neither the container-on-Big-Tam nor the hosted-runner path works. |

## Consequences

**Positive**
- Server, agent and gateway run on RHEL/Rocky 9, Ubuntu 22.04/24.04 and Debian 12. The Pre-release QA install legs become a meaningful release gate instead of a permanently-red known failure.
- The floor is a *declared, tested contract*. The glibc-2.38 scanf trap and every similar class is removed by building against 2.34 headers instead of policed by convention.
- Package dependencies are measured, not hand-written.
- Distros keep patching OpenSSL and libstdc++; there is no bundled copy to re-ship.

**Costs and risks**
- **CI time.** The first container release adds roughly 45–60 minutes (vcpkg from scratch for the new triplet); a cache under `runner.tool_cache` plus a host ccache mount brings later runs close to today's. OTP from source adds ~10 minutes once per image build.
- **New infrastructure.** A digest-pinned floor image on GHCR with Dependabot, and a nightly canary build. Image provenance feeds the SBOM (OTP source provenance in the gateway SBOM; `docs/user-manual/release-verification.md`).
- **Runner mechanics are unverified.** Big Tam has docker (docker-publish already uses buildx there), but the runner is itself a container (`Dockerfile.runner-linux`, `--work /home/runner/_work`). `docker run -v` from inside it maps **host** paths, which buildx socket access does not prove. `build-ci` must verify bind-mount viability *before* S1 is committed to. Fallback: a GitHub-hosted `container:` job on `ubuntu-24.04` (the host's glibc is irrelevant inside the container) at ~60–90 minutes, no Big Tam ccache, and contention for the repository's 10 GB `actions/cache` quota (see the cache comments in `ci.yml`).
- **Gateway loses SM4** in `crypto:supports()`. No Yuzu use found.
- **EL9.8 OpenSSL 3.5 symbol versioning** is the one place the design could surprise us; the floor gate exists to catch it and the bundled-OpenSSL fallback is described above.
- **Confidence:** high on the mechanism, floor numbers and the plugin-ABI rejection (checked against the tree and a `rockylinux:9` container); medium on CI minutes and on the OpenSSL versioning point.

## Phased plan (each slice independently mergeable, each with a CI-visible gate)

| Slice | Content | Gate |
|---|---|---|
| **S0 — gate first** | `check-elf-floor.sh`, `linux-floor.json`, fixture unit tests; wired into `release.yml` (after "Package archive") and `pre-release.yml`, **report-only** | The script's own tests; reports the *current* violations so the gap is measured |
| **S1 — floor image** | `Dockerfile.build-el9`, `meson/native/linux-gcc15-el9.ini`, `triplets/x64-linux-el9-static.cmake`, `floor-build.sh`; nightly `linux-el9-floor` canary on Big Tam (+ `workflow_dispatch`) | Canary builds and passes the S0 gate |
| **S2 — server and agent** | `release.yml` `build-linux` runs through `floor-build.sh`; derived `.deb` `Depends`; S0 gate becomes **enforcing** | Pre-release QA legs ubuntu:22.04 / 24.04 / debian:12 / rockylinux:9 green for server and agent. **Closes #5143** |
| **S3 — gateway** | `build-gateway` in the floor image; RPM `Requires`; `.deb` `Depends: libssl3t64 \| libssl3 (>= 3.0.0)` | fedora:42 + rockylinux:9 gateway legs green. **Closes #5171** |
| **S4 — docs and governance** | "Supported Platforms" rewritten, `build-guide.md`, `ci-architecture.md`, release-verification (OTP provenance), changelog fragments | Docs lint; `docs-writer` + `release-deploy` sign-off |

## Questions for reviewers

Only the operator and the other maintainers can decide these; the recommendation in each is the design's default.

1. **Floor commitment.** Commit to the RHEL 9 floor (glibc 2.34) for all three components — which keeps Ubuntu 22.04 (EOL April 2027) and Debian 12 in support — or declare Ubuntu 24.04 / EL9 only? CI cost is the same either way; this is a support-promise decision. *Recommended: glibc 2.34 for all three.*
2. **Floor image.** Published to GHCR, digest-pinned and Dependabot-tracked, or built ad hoc inside each release run? *Recommended: GHCR.*
3. **OTP provenance.** Build OTP 28 from a pinned source tarball, or take RabbitMQ's signed `erlang-rpm`? *Recommended: pinned source.*
4. **Canary.** Approve a nightly `linux-el9-floor` build on Big Tam (~20 min/night) so floor drift never waits for a release tag? *Recommended: yes.*
5. **Runner bind-mounts.** If `build-ci` finds `docker run -v` needs path mapping on the containerised Big Tam runner, who adjusts the runner provisioning (`deploy/linux`)? *Recommended: the operator, with `build-ci` supplying the exact change.*
6. **Gateway SM4.** Is dropping SM4 from the gateway's `crypto:supports()` acceptable? *Recommended: yes.*

## Reviewers required when this moves to implementation

`build-ci` (release.yml, the sentinel, triplet, runner mechanics), `release-deploy` (packages, `Depends`/`Requires`), `cross-platform`, `cpp-safety` (nonshared-libstdc++ duplication proof, plugin ABI), `security-guardian` (the artifact-signature verify chokepoint is unchanged; OpenSSL posture), `gateway-erlang` (OTP build, `crypto.so`), `docs-writer`, `sre` (canary, CI cost), and `compliance-officer` (SBOM: OTP-from-source attestation).

## Out of scope

- Windows and macOS builds.
- aarch64 Linux artifacts (not shipped today).
- Changing the Docker images' bases (they carry their own runtime libraries and are the supported route for older distros until S2/S3 land).
- Vendoring or patching OpenSSL.
