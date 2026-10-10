# ADR-2003 — Linux native build floors: EL9 for server and gateway, glibc 2.17 with a bundled C++ runtime for the agent

**Status:** Proposed (rev 2, 2026-10-10 — revised after review on PR #5631) — open for review. **Implementation starts only after the "Questions" section is answered on the PR.**
**Authors:** Fraser Jarvis (@fjarvis); design adjudication and spike by the enterprise-architect (Fable) review, 2026-10-09 and 2026-10-10
**Date:** 2026-10-10
**Relates to:** #5143 (glibc/libstdc++ floor), #5171 (gateway RPM cannot boot on RHEL-family), the v0.14.1 release notes (both listed as known issues), `docs/user-manual/README.md` "Supported Platforms", `docs/build-guide.md`, `docs/ci-architecture.md`, `docs/agent-bundle.md`, ADR-0008 (static vcpkg libpq/CRT picks)

**Revision 2 changes:** the agent now has its **own, much lower floor** (glibc 2.17 / kernel 3.10, the RHEL 7 generation, for the agent's main customer) built by a **second floor image**; Question 1 is split into a server/gateway promise and an agent promise; the agent track is sequenced independently of server/gateway; the S0 gate report is a precondition to fixing the agent floor and is **now measured** (below); a fallback toolset and a bind-mount precondition are stated; a floor-review rule is added; the plugin counts are measured.

---

## Context

Every v0.14.x native Linux artifact — `.tar.gz`, `.deb` and `.rpm` for the server, gateway and agent — is built natively on the self-hosted "Big Tam" runner: Ubuntu 26.04, `gcc-15`, mold, vcpkg triplet `x64-linux-static` (static vcpkg libraries; **dynamic glibc and libstdc++**). The binaries therefore carry the build host's runtime floor by accident, not by choice:

| Component | Needs at run time | Runs on | Does not run on |
|---|---|---|---|
| Server | glibc 2.38, `GLIBCXX_3.4.34` | Ubuntu 26.04, Fedora 42 | Ubuntu 22.04 and 24.04, Debian 12 and 13, RHEL/Rocky 9 and 10 |
| Agent | glibc 2.38, `GLIBCXX_3.4.32`, `CXXABI_1.3.15`, `LIBSYSTEMD_240` | Ubuntu 24.04, 26.04, Fedora 42 | Ubuntu 22.04, Debian 12, every RHEL-family release before 10 |
| Gateway `.deb`/`.rpm` | glibc 2.38 (prebuilt Ubuntu-24 OTP) and the OTP `crypto` NIF's OpenSSL imports | Ubuntu 24.04/26.04 (`.deb`) | RHEL, Rocky, Fedora (`undefined symbol: EVP_sm4_cbc`); no RPM-based distribution validated |

Pre-release QA has failed the same six install legs for both v0.14.0 and v0.14.1.

**Why.** (1) *#5143:* the floor is an accident of the build host — the code needs only GCC 13 (`docs/build-guide.md`; `Dockerfile.server` already compiles the tree with gcc-13); glibc 2.38 and `GLIBCXX_3.4.34` come from *where* it is built. (2) *#5171:* the gateway's OTP is a prebuilt Ubuntu tarball (`erlef/setup-beam`, `ImageOS: ubuntu24` in `release.yml`), whose `crypto.so` imports `EVP_sm4_*`; the `.deb` `Depends` is hand-written (`adduser` only: `deploy/packaging/debian/build-deb.sh`, `build-gateway-deb.sh`) and the gateway RPM spec is `AutoReqProv: no` (`deploy/packaging/rpm/yuzu-gateway.spec`), so nothing declares an OpenSSL or glibc requirement.

### Scope decisions from review

- **Server and gateway:** the n-2 LTS releases of each distro — Ubuntu 26.04, 24.04, 22.04; Debian 13, 12; RHEL-family 10, 9. **RHEL 8 is out of scope** for both. The EL9 floor (glibc 2.34) is therefore right for them.
- **Agent:** must run on much older systems. The agent's main customer runs RHEL 7-generation Linux (**version and support status unconfirmed — see Questions**), so the working target is RHEL/CentOS/OL 7: glibc 2.17, `GLIBCXX_3.4.19`, kernel 3.10, systemd 219, OpenSSL 1.0.2k, rpm 4.11.

### Spike results (S0 baseline for the shipped agent, v0.14.1)

Measured on the release tarball (the `.deb` is byte-identical; 68 agent ELFs, 69 in the tarball including the server). Plugin counts: **69 plugin directories, each with a `shared_library` target on `origin/dev`** (`ls agents/plugins | wc -l`; `grep -c 'shared_library(' agents/plugins/*/meson.build`); **66 ship in the 0.14.1 tarball** (three newer plugins post-date the cut).

- The agent set needs `GLIBC_2.38`, `GLIBCXX_3.4.32`, `CXXABI_1.3.15`, `LIBSYSTEMD_240`, `BLKID_1.0`. 43 of 66 plugins exceed glibc 2.17 directly; all 66 do through `libyuzu_agent_core.so`.
- Distinct symbols above 2.17: `getentropy`, `__explicit_bzero_chk` (2.25); `fcntl64`, `renameat2` (2.28); `log`/`log2`/`pow` (2.29); `__libc_single_threaded`, `pthread_sigmask` (2.32); `stat`/`fstat`/`lstat64`/`fstatat64` (2.33); 22 `pthread_*`/`dl*`/`getaddrinfo_a`/`__libc_start_main` (2.34); `arc4random_buf` (2.36); `__isoc23_sscanf/strtol/strtoll/strtoul/strtoull` (2.38, core + 14 plugins).
- **Every glibc item is a header-redirect artefact of the 2.38 build host.** Only two are source-level: `explicit_bzero` (`sdk/secure_zero.hpp`) and the `::renameat2` wrapper (`confined_fs_posix.cpp`, which already has an `ENOSYS` fallback).
- `GLIBCXX_3.4.20–3.4.32`: the C++11-ABI symbols (≥ 3.4.21) mean RHEL 7's libstdc++ (3.4.19) **can never satisfy the agent** — the runtime must be carried with it.
- Run on a real `centos:7` container: the shipped agent fails with `GLIBC_2.28/2.32/2.34/2.38 not found, GLIBCXX_3.4.20 not found`. `rpm -ivh --test` on rpm 4.11 fails on `LIBSYSTEMD_221/222/237/240`, `rpmlib(PayloadIsZstd)` and `rpmlib(LargeFiles)`.
- **What RHEL 7 actually forbids:** one hard blocker — **sd-bus**. systemd 219 exports `LIBSYSTEMD_209..229` but **no `sd_bus_*`** (verified with `nm`); the core itself (`guard_systemd.cpp`, `spark_service.cpp`) and 7 plugins link it, so the agent cannot start on EL7 as built. It needs a source change (runtime `dlopen` of libsystemd, 9 translation units). Everything else is gated or already has fallbacks: `pidfd_open`/`close_range`/`execveat` are `syscall()`-gated with fallbacks (the 2.17 sysroot headers lack their `SYS_*` numbers, so they need local `#define`s or the fast paths silently compile out); no use of `statx`, `getrandom`, `memfd_create`, `copy_file_range`, `openat2`, `io_uring`, fanotify, cgroup v2 or nftables in agents/sdk/common. C++23 library use is `<format>` (117 files), `<expected>` (35), `<filesystem>` (61), `<semaphore>` (2); no `<print>`, `<stacktrace>` or chrono time zones — **GCC 13+ suffices**.
- **Plugins on EL7:** 58 build and run unchanged after a rebuild; 7 need a source change so the sd-bus leg degrades to `constrained` when libsystemd's bus API is absent (`device_identity`, `event_logs` — its journal leg survives — `firewall`, `firmware_posture`, `privacy_permissions`, `tar` power collector, `wifi`, plus the core); 1 cannot work (`platform_security`'s `/sys/kernel/security/lockdown` row, a 5.4 kernel feature → `constrained`).
- Dependencies from vcpkg are static (grpc, protobuf, abseil, OpenSSL 3, sqlite, spdlog, libxml2, CLI11, httplib), so the target distro's copies are irrelevant. The dynamic system libraries are libc/libm/libpthread/libdl, libstdc++, libgcc_s, libsystemd and libblkid.

## Decision

**Two floors, two floor images.**

| | Server and gateway | Agent |
|---|---|---|
| **Floor** | glibc 2.34, `GLIBCXX_3.4.29`, `CXXABI_1.3.13`, `OPENSSL_3.0.0` (RHEL/Rocky 9) | glibc 2.17, kernel 3.10; **libstdc++/libgcc_s bundled** (the distro's are irrelevant) |
| **Scope** | n-2 LTS per distro; RHEL 8 out | oldest OS that must run: RHEL-family 7.9 |
| **Image** | `deploy/docker/Dockerfile.build-el9`: `rockylinux:9` + `gcc-toolset-15` (fallback 14, then 13) + mold + `rpm-build` + dpkg tooling + OTP 28 from a pinned source tarball | `build-agent-floor`: `ubuntu:24.04` host + a **pinned conda-forge GCC 14 + glibc-2.17 sysroot (kernel 3.10 headers)**, or the crosstool-NG fallback below |
| **Builds** | server, gateway and their `.deb`/`.rpm` | agent tarball, agent `.deb`/`.rpm`, the agent-bundle payload |

**The key property:** an artifact built at the lowest floor runs on every newer distro. So the agent needs **one** image — no intermediate EL8 image — and the EL9 image cannot simply be "lowered" for the agent (the floor is the libc the code is linked against).

### Agent floor — required and best-effort

Required (CI leg or test for each): RHEL/CentOS/OL **7.9** (glibc 2.17); RHEL **8** (2.28), **9** (2.34), **10** (2.39); Ubuntu **20.04** (2.31), **22.04** (2.35), **24.04** (2.39), **26.04** (2.43); Debian **11** (2.31), **12** (2.36), **13** (2.41).
Best-effort (run by construction, no CI leg): Ubuntu 18.04 (2.27), Debian 10 (2.28), SLES 12 SP5 (2.22), SLES 15 (2.26+), Amazon Linux 2 (2.26, EOL June 2026) and 2023 (2.34).

### Agent mechanics

1. **Toolchain.** The EL7 software-collection ceiling is `devtoolset-11` (GCC 11.2.1) — no C++23. A CentOS 7 image (EOL; `vault.centos.org`; GCC bootstrapped from source) is rejected. The **proven** alternative is conda-forge GCC 14 plus its `sysroot_linux-64` 2.17 on the Ubuntu host: it builds `<format>`, `<expected>`, `<filesystem>` and threads and emits ELFs needing at most `GLIBC_2.14`. Pin an explicit conda spec with sha256. **Fallback** if `compliance-officer` rejects conda-forge provenance: crosstool-NG GCC 14 + glibc 2.17 + 3.10 headers (source-provenanced, about an hour, cached).
2. **Bundled C++ runtime** (the manylinux/auditwheel pattern). Ship one private `libstdc++.so.6` and `libgcc_s.so.1` and give every agent ELF `RUNPATH=$ORIGIN`-relative resolution of them, so the core and all plugins resolve **one** copy. This is *not* the static-libstdc++ approach rejected below: there is one runtime, so exceptions and `typeinfo` cross the core/plugin boundary safely. Proven: a core `.so`, a `dlopen(RTLD_LAZY|RTLD_LOCAL)` C-ABI plugin and a main, with a `YuzuCoreError`/`std::exception` caught across the DSO boundary both ways, ran on `centos:7`, `ubuntu:22.04`, `debian:12` and Ubuntu 26.04 with the bundle, and failed on `centos:7` without it. `plugin.h` stays pure C.
3. **Layout hazard (verified).** A directory listed in `/etc/ld.so.conf.d` sorts first in `ld.so.cache`, so a bundled libstdc++ in `/usr/lib/yuzu` would become **every process's libstdc++**. Ship it in `/usr/lib/yuzu/runtime/`, **not** in `ld.so.conf`, found by `RUNPATH` only. Two warts: `-pthread` is mandatory (libpthread is separate before glibc 2.34), and conda's compiler injects an absolute prefix rpath, which must be stripped (`patchelf`) and gated as "`$ORIGIN`-only `RUNPATH`".
4. **Source changes (agent track, S2-agent):** a runtime `dlopen` shim for libsystemd/libblkid (the 7 plugins degrade to `constrained` without the bus API); local `SYS_*` number defines for the syscall-gated paths; an `explicit_bzero` fallback; the stale `$ORIGIN/../../core` plugin rpath fixed.
5. **Packaging for rpm 4.11 / systemd 219.** The host `rpm` 6 defaults break rpm 4.11, so set `_rpmformat 4` and `_binary_payload w9.gzdio` (no zstd); Debian 10/11 `dpkg` lacks zstd, so `dpkg-deb -Zxz`. systemd 219 ignores unit directives it does not know — `StartLimitIntervalSec`/`Burst` in `[Unit]`, `StateDirectory`, `ReadWritePaths`, `ProtectSystem=strict` — which would silently leave the service unhardened; add a `%post`/`postinst` drop-in when `systemctl --version` < 232. SELinux is unchanged (unconfined service, as on EL9).
6. **vcpkg** runs on the Ubuntu host (cmake/git/ninja/python host-native, no EL7 bootstrap) with a new triplet `x64-linux-glibc217-static` that chainloads the sysroot toolchain file. libsystemd/blkid headers are absent from the sysroot and are `dlopen`ed anyway.

### Server and gateway mechanics (unchanged from rev 1, with reviewer fixes)

- **`gcc-toolset` is the ODR-safe way to run a new compiler on an old runtime:** it links only `libstdc++_nonshared.a` into each object and leaves the system `libstdc++.so.6` the single runtime copy. Red Hat's contract is that `libstdc++_nonshared.a` carries the *full* delta over the base runtime, and the floor gate verifies it. **Toolset order: 15, then 14, then 13 on any S0/S1 leak** (the tree needs GCC 13). `gcc-toolset-15` was confirmed on Rocky 9.7/9.8; Rocky is a 1:1 rebuild, so RHEL 9.7 should match (toolset 13 since 9.3, 14 since 9.5) — **medium confidence**, to be verified on RHEL 9 proper.
- **New triplet `triplets/x64-linux-el9-static.cmake`.** `scripts/ci/vcpkg-triplet-sentinel.sh` keys on `vcpkg.json`, the triplet and the vcpkg commit, **not the toolchain** — reusing the host-built `x64-linux-static` tree would silently link glibc-2.38-era objects.
- **Gateway (#5171):** OTP 28 built from a pinned-sha source tarball in the EL9 image, dynamic SSL, against the **oldest in-scope OpenSSL 3.0.x headers** (Ubuntu 22.04's 3.0.2), not EL9's possibly rebased 3.2/3.5, so `crypto.so` stays within `OPENSSL_3.0.0`. RPM `Requires: glibc >= 2.34, openssl-libs >= 3.0, ncurses-libs` (keeping `AutoReqProv: no`); `.deb` `Depends: libssl3t64 | libssl3 (>= 3.0.0)`. SM4 leaves `crypto:supports()` (no Yuzu use).
- **Bundled OpenSSL fallback** (only if the gate shows `crypto.so` importing above `OPENSSL_3.0.0`): taking it changes the SBOM and the patch cadence, so it is decided by **`security-guardian` together with the operator and recorded as an amendment to this ADR** before it ships.
- **`.deb` dependencies** are derived (`dpkg-shlibdeps` in a `debian:12` stage, or from the gate's measured maxima: `libc6 (>= 2.34), libstdc++6 (>= 11), libgcc-s1`), never hand-written.

### The floor gate and its baseline

`scripts/ci/check-elf-floor.sh` plus per-artifact floor files under `deploy/packaging/` (`linux-floor.json`: the server/gateway floor; an agent floor file allowing glibc 2.17 and, for the bundled runtime, its own sonames) runs `objdump -T` over every ELF in the staging directory (binaries, plugins, ERTS, `crypto.so`, the bundled runtime) and fails on any import above the floor, any forbidden symbol (`EVP_sm4_*`), or an absolute `RUNPATH`. **The baseline is recorded** in a committed `deploy/packaging/linux-floor-baseline.json` (per artifact: maxima plus the offending-symbol list, generated by the gate's `--emit-baseline`) and as a CI artifact with the full report, so the gate can be tuned before it becomes enforcing. The agent bundle repackages the gated staging directory and is covered transitively; the bundle job re-runs the gate on the extracted payload.

## Alternatives considered

| Alternative | Why not |
|---|---|
| **Static `libstdc++`/`libgcc` in each DSO** | **Unsafe for the agent.** The agent plugins `shared_library(... dependencies: [yuzu_agent_core_dep])` link the C++ symbols of `libyuzu_agent_core.so` directly (not only the `plugin.h` C ABI), and the loader uses `dlopen(RTLD_LAZY\|RTLD_LOCAL)`. A copy per DSO duplicates exception globals, locale and `typeinfo`: an exception thrown in the core and caught in a plugin fails the typeinfo match and terminates; spdlog/fmt/abseil hit the same ODR problem. A **single bundled runtime** (above) removes the problem. |
| **CentOS 7 image with GCC built from source** | EOL repositories (`vault.centos.org`), a GCC bootstrap, and `devtoolset-11` tops out at GCC 11 (no C++23). |
| **Lower the EL9 image for the agent** | Impossible: the floor is the libc the code is linked against. |
| **An intermediate EL8 agent image** | Unneeded: one glibc-2.17 build runs on every newer distro. |
| **Bundle OpenSSL into the gateway by default** | Makes Yuzu the patcher of an OpenSSL copy; kept only as the gated fallback. |
| **Declare the gateway RH-family unsupported (container only)** | Abandons RHEL, the mainstream enterprise platform. |
| **Floor = Ubuntu 24.04, native, gcc-14** | Still excludes every in-scope RHEL/Ubuntu 22.04/Debian 12 host. Last resort only. |

## Consequences

**Positive:** server and gateway run on the n-2 LTS set; the agent runs on RHEL 7.9 through 26.04; the QA install legs become a real release gate; package dependencies are measured; the glibc-2.38 `__isoc23_*` trap (`docs/cpp-conventions.md`) is removed by building against old headers, not policed; distros keep patching OpenSSL and libstdc++ for server and gateway.

**Costs and risks**
- **Two floor images**, both digest-pinned on GHCR with Dependabot, plus nightly canaries (`linux-el9-floor`, `linux-agent-floor`). First container release about +45–60 minutes (vcpkg from scratch per new triplet); caches and a host ccache mount bring later runs close to today's. OTP from source adds ~10 minutes per image build.
- **Yuzu now owns the patching of a bundled libstdc++/libgcc_s** shipped with the agent (distro updates no longer reach it), and records the conda-forge (or crosstool-NG) toolchain provenance in the SBOM.
- **On EL7 the 7 sd-bus-backed plugins degrade to `constrained`** and `platform_security`'s lockdown row is absent; this must be documented as the EL7 support statement.
- **Container testing is limited.** A `centos:7` container proves load, `--version`, plugin scan and rpm install, but cannot exercise the 3.10-kernel fallbacks (the host kernel is used) or systemd 219 units (the host is cgroup v2). A real EL7 host or VM is needed for those.
- **Runner mechanics are unverified.** Big Tam is itself a container (`Dockerfile.runner-linux`); `docker run -v` from inside it maps **host** paths. See the S1 precondition.
- **Upgrades:** the `.deb`/`.rpm` `Depends`/`Requires` changes are additive on upgrade (nothing removed). The Docker and chisel images carry their own runtimes and are unaffected. `docs/agent-bundle.md` ("needs glibc 2.38", ~line 133) must be rewritten for the new floor.
- **Confidence:** high on mechanism and numbers (measured or run); medium on toolchain-provenance acceptance and EL7 maintenance. Not verified: RHEL 9 proper's toolset list; the RHEL 7 ELS end date (30 June 2028 per Red Hat's 2024 extension — plausible, to confirm); rpm 6 `_rpmformat 4` output being accepted by rpm 4.11 (needs the EL7 leg); a full vcpkg build on the 2.17 triplet; runner bind-mounts.

## Phased plan (each slice mergeable, each with a CI-visible gate)

The agent track and the server/gateway track are independent.

| Slice | Content | Gate / precondition |
|---|---|---|
| **S0 — gate first (precondition for everything)** | `check-elf-floor.sh`, floor files, committed baseline, `--emit-baseline`; wired into `release.yml` (after "Package archive") and Pre-release QA, **report-only**; adds a `centos:7` `rpm -ivh --test` and `--version` leg | The script's tests; the baseline measures the current gap. **Fixing the agent floor depends on this report.** |
| **S1a — EL9 image** | `Dockerfile.build-el9`, `meson/native/linux-gcc15-el9.ini`, `triplets/x64-linux-el9-static.cmake`, `floor-build.sh` (the same script a developer runs locally; publishes nothing); nightly canary | **Precondition: `build-ci` verifies `docker run -v` on the containerised Big Tam runner.** Fallback: a GitHub-hosted `container:` job on `ubuntu-24.04` (~60–90 min, no Big Tam ccache, contention for the 10 GB `actions/cache` quota) |
| **S1b — agent-floor image** | `build-agent-floor`, pinned conda-forge toolchain (or crosstool-NG), `triplets/x64-linux-glibc217-static.cmake`; nightly canary | Same bind-mount precondition; depends only on S0 |
| **S2-agent** | The source changes above, bundled runtime layout, rpm/deb compat flags, the 219 drop-in; agent gate **enforcing** | QA legs `centos:7`, `rockylinux:8`/`9`, `ubuntu:22.04`, `debian:12` green. **Closes #5143 for the agent.** Needs S0 and S1b only — **not blocked on server/gateway** |
| **S2-server** | `release.yml` `build-linux` server through `floor-build.sh`; derived `.deb` `Depends`; server gate enforcing | QA legs ubuntu:22.04/24.04, debian:12/13, rockylinux:9 green. **Closes #5143 for the server** (needs S1a) |
| **S3 — gateway** | OTP in the EL9 image against the oldest 3.0.x headers; RPM `Requires`; `.deb` `Depends` | fedora:42 + rockylinux:9 gateway legs green. **Closes #5171** (needs S1a) |
| **S4 — docs and governance** | "Supported Platforms", `build-guide.md`, `ci-architecture.md`, `agent-bundle.md`, release-verification (toolchain and OTP provenance), changelog fragments | Docs lint; `docs-writer` + `release-deploy` sign-off |

## Floor review rule

Re-evaluate both floors (a) when the next Ubuntu LTS ships (the n-2 window moves), (b) at each RHEL major GA, and (c) at RHEL 7 ELS end (30 June 2028, to be confirmed) — at which point the agent floor may rise (to glibc 2.28 if the customer is on RHEL 8+, which would remove the bundling and sd-bus work). Each review is a one-line amendment to this ADR plus a baseline refresh.

## Questions

Split into the two promises the review asked for. Recommended answers are the design's defaults.

**Server and gateway promise (reviewers)**
1. Commit to n-2 LTS with the EL9 floor (glibc 2.34), RHEL 8 out of scope? *Recommended: yes, as the review set.*
2. EL9 image published to GHCR (digest-pinned, Dependabot) rather than built in each release run? *Recommended: GHCR.*
3. OTP 28 from a pinned source tarball, not RabbitMQ's signed `erlang-rpm`? *Recommended: pinned source.*
4. Approve nightly canaries for both floor images (~20 min each per night)? *Recommended: yes.*
5. If `docker run -v` needs path mapping on the containerised Big Tam runner, who adjusts its provisioning (`deploy/linux`)? *Recommended: the operator, with `build-ci` supplying the change.*
6. Is dropping SM4 from the gateway's `crypto:supports()` acceptable? *Recommended: yes.*

**Agent promise (the operator and the customer)**
7. **What exactly is the customer's OS and patch level** (RHEL 7.x? 7.4+ has a `getrandom` backport) **and do they have ELS/ELTS?** If they are on RHEL 8 or later, the agent floor is glibc 2.28 and the bundling and sd-bus work disappear.
8. Are SUSE and Amazon Linux in scope (currently best-effort)?
9. Is it acceptable that on EL7 the 7 sd-bus-backed plugins report `constrained` and the lockdown row is absent?
10. Accept the second image and Yuzu's responsibility for patching the bundled libstdc++/libgcc_s?
11. Is conda-forge toolchain provenance acceptable to `compliance-officer`, or should the crosstool-NG fallback be the primary?
12. Can a real EL7 host or VM be made available for the kernel-3.10 and systemd-219 tests?

## Reviewers required when this moves to implementation

`build-ci` (release.yml, sentinel, triplets, runner mechanics, both images), `release-deploy` (packages, rpm 4.11 / dpkg compatibility, `Depends`/`Requires`, the 219 drop-in), `cross-platform`, `cpp-safety` (bundled runtime and cross-DSO exceptions, the dlopen shim, plugin ABI), `security-guardian` (the artifact-signature verify chokepoint is unchanged; bundled OpenSSL decision; the libsystemd dlopen shim), `gateway-erlang` (OTP build, `crypto.so`), `docs-writer`, `sre` (canaries, CI cost), and `compliance-officer` (SBOM: toolchain and OTP provenance, bundled runtime).

## Out of scope

Windows and macOS builds; aarch64 Linux artifacts (not shipped today); changing the Docker images' bases (they carry their own runtimes and remain the supported route for older distros until S2 lands); RHEL 8 for server and gateway; vendoring or patching OpenSSL.
