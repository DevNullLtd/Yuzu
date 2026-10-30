# ADR-2003 — Linux native build floors: a glibc 2.28 (EL8) image for all C++, an EL9 image for the gateway's OTP

**Status:** Accepted (2026-10-19, by merge of PR #5631 at rev 5 — the reviewer answered all ten questions on that PR and stated that implementation can proceed on that basis). Slices S1–S4 start on the operator's go, not on this acceptance.
**Authors:** Fraser Jarvis (@fjarvis); design adjudication and spike by the enterprise-architect (Fable) review, 2026-10-09 and 2026-10-10
**Date:** 2026-10-10
**Relates to:** #5143 (glibc/libstdc++ floor), #5171 (gateway RPM cannot boot on RHEL-family), the v0.14.1 release notes (both listed as known issues), `docs/user-manual/README.md` "Supported Platforms", `docs/build-guide.md`, `docs/ci-architecture.md`, `docs/agent-bundle.md`, ADR-0008 (static vcpkg libpq/CRT picks)

**Revision 5 changes (reviewer's answers, 2026-10-19):** all ten questions are answered (see "Decisions on the questions"). The ones that change the plan: the **server is built in the EL8 image** while its promise and gate stay n-2 LTS at glibc 2.34 (Q1); the images are published to **GHCR**, digest-pinned with Dependabot and the nightly refresh (Q2); OTP 28 comes from a **pinned source tarball** (Q3); both nightly canaries are approved (Q4); **`build-ci` owns the Big Tam provisioning change end to end, including applying it** (Q5); SM4 is dropped from `crypto:supports()` (Q6); **Amazon Linux 2 is best-effort only**, bought back only for a named customer fleet under contract (Q7); the reviewer provides an **EL8 VM** (Q8); the SUSE line is as proposed (Q9); and toolchain provenance is accepted, with **Rocky versus UBI8 decided at S1** (Q10). No design change from rev 4.

**Revision 4 changes (EL8 trial build, 2026-10-13):** the rev 3 design was **built and measured**, not just predicted. The agent *and* the server build in a `rockylinux:8` + `gcc-toolset-15` container with **no C++ source changes**; every one of the 88 resulting ELFs needs at most **glibc 2.28** (the server too, so it would pass a 2.28 gate as well as the 2.34 promise); all run on Rocky 8 and 9, Amazon Linux 2023, Ubuntu 20.04/22.04/24.04 and Debian 11/12. Corrections to rev 3: the build needs a small **meson link wiring** change (`threads` + `-lanl`; "zero source changes" meant C++ only), the trial triplet must chainload the vcpkg Linux toolchain rather than replace it, Rocky packages are RESF-signed rebuilds (not Red Hat-signed), SLES is "by construction" rather than required, and the server's floor values are now stated in the table. See "Trial build results" below.

**Revision 3 changes (operator answers, 2026-10-10):** RHEL 7 is **dropped** — the agent's customers run supported, patched releases (at most about three months behind). That removes the whole rev-2 agent apparatus (conda-forge sysroot, bundled C++ runtime, sd-bus shim, rpm 4.11 and systemd 219 compatibility): at a glibc **2.28** floor **none of it is needed**, and the agent needs **no C++ source change** (measured by building it, below), only meson link wiring. The agent floor is now **RHEL 8**, built in the same plain `rockylinux:8` + `gcc-toolset` image as the server (proposed; Question 1), with a small separate EL9 image kept only for the gateway's OTP. Amazon Linux **2023** is required; Amazon Linux **2** (glibc 2.26, end of support 30 June 2026) is best-effort with the cost of buying it back itemised (Q7). The operator's "RHEL 8, even 9, is fine for server" is recorded under Question 1.

**Revision 2 changes (superseded where rev 3 says so):** the agent got its own lower floor and a second image; Question 1 was split into server/gateway and agent promises; the S0 gate report became a precondition and is now measured; a fallback toolset and a bind-mount precondition were stated; a floor-review rule was added.

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

### Scope decisions

- **Server and gateway:** the n-2 LTS releases of each distro — Ubuntu 26.04, 24.04, 22.04; Debian 13, 12; RHEL-family 10, 9 (the reviewer's decision; the operator confirmed RHEL 8 or 9 is acceptable as a server floor, see Question 1). Their **gate** stays at glibc 2.34.
- **Agent:** supported, patched releases only — no RHEL 7, no distro more than about three months behind its vendor patches. Floor **RHEL 8** (glibc 2.28, kernel 4.18, systemd 239).

### Spike results (S0 baseline for the shipped agent, v0.14.1)

Measured on the release tarball (the `.deb` is byte-identical; 68 agent ELFs). Plugin counts: **69 plugin directories with a `shared_library` target on `origin/dev`**; **66 ship in the 0.14.1 tarball**. All versioned-symbol and run results below are from live runs of the shipped agent (`LD_LIBRARY_PATH=bin bin/yuzu-agent --version`) in distro containers, not inference.

- **Exceeding glibc 2.28 (on Rocky 8):** GLIBC 2.29 (`log/log2/pow`), 2.32 (`__libc_single_threaded`, `pthread_sigmask`), 2.33 (`stat`/`fstat`/`lstat64`/`fstatat64`), 2.34 (22 `pthread_*`/`dl*`/`getaddrinfo_a`/`__libc_start_main`), 2.36 (`arc4random_buf`), 2.38 (`__isoc23_*`, `fmod`, `strlcpy`/`strlcat`). 46 of the 68 ELFs exceed 2.28 directly; all 68 do through `libyuzu_agent_core.so`. GLIBCXX 3.4.26 (45 `std::filesystem` symbols) to 3.4.32; CXXABI 1.3.13 and 1.3.15; `LIBSYSTEMD_240`. **No OpenSSL import** (vcpkg static, no `libcrypto` in `NEEDED`).
- **Every glibc item is a header artefact of the 2.38 build host.** EL8's 2.28 headers carry no `__isoc23` redirects and declare `renameat2`, `explicit_bzero`, `getentropy` and the `SYS_pidfd_open`/`close_range`/`execveat`/`pidfd_send_signal` numbers (kernel-headers 4.18) — **no agent source change is needed at 2.28.**
- **sd-bus is not a blocker on EL8.** Rocky 8's systemd 239 `libsystemd.so.0` exports 277 `sd_bus_*` symbols, including the `LIBSYSTEMD_240` one the agent imports (Red Hat backport; highest exported tag `LIBSYSTEMD_250`).
- **Where the shipped 0.14.1 agent runs today:** it fails on `rockylinux:8` (the list above), on `rockylinux:9` (2.36/2.38, GLIBCXX 3.4.30–32, CXXABI 1.3.15) and on `amazonlinux:2023` (2.36/2.38 only); `amazonlinux:2` fails on everything plus `LIBSYSTEMD_221/222/237/240`. `rpm -ivh --test` agrees (auto-generated `Requires`).
- **C++23 library use:** `<format>` (117 files), `<expected>` (35), `<filesystem>` (61), `<semaphore>` (2); no `<print>`, `<stacktrace>` or chrono time zones — **GCC 13+ suffices**.
- **Bundled C++ runtime: not required (tested).** A probe — a core `.so` using `<format>`, `<expected>`, `<filesystem>`, `to_chars`/`from_chars`, plus a C-ABI plugin `dlopen(RTLD_LAZY|RTLD_LOCAL)`ed that catches `YuzuCoreError`, `std::exception`, `std::filesystem::filesystem_error` and `std::format_error` **by type** across the DSO boundary — built with `gcc-toolset-13`, `14` and `15` on `rockylinux:8`. Every ELF imports at most `GLIBC_2.26`, `GLIBCXX_3.4.22`, `CXXABI_1.3.11`; the newer libstdc++ symbols (210–227) are defined locally from `libstdc++_nonshared.a`, while `__cxa_throw`, `__cxa_begin_catch` and the exception `typeinfo` stay imported from the **one** system libstdc++. It ran with 5/5 catches on rockylinux:8 and 9, amazonlinux:2023 and 2, debian:10–13, ubuntu:18.04–24.04 and opensuse/leap:15.6. `nm` of toolset-15's `libstdc++_nonshared.a` confirms every newer ABI symbol the real agent needs is present (`exception_ptr::_M_addref/_M_release`, `__cxa_call_terminate`, `ios_base_library_init`, `to_chars` including the `_Float128` forms, `condition_variable::wait`).
- **Packaging at 2.28:** rpm 4.14.3 (EL8) supports `rpmlib(PayloadIsZstd)` and `rpmlib(LargeFiles)` (`rpm -ivh --test --nodeps` rc=0 on the 0.14.1 zstd rpm) — no `_rpmformat`/`_binary_payload` flags. Debian 10 (dpkg 1.19.8) and 11 (1.20.14) reject `control.tar.zst`; Debian 12 and Ubuntu 18.04's patched dpkg accept it. systemd 239: `systemd-analyze verify` of the shipped unit reports no unknown directive — **no drop-in needed**.
- Dependencies from vcpkg are static (grpc, protobuf, abseil, OpenSSL 3, sqlite, spdlog, libxml2, CLI11, httplib). The dynamic system libraries are libc/libm/libpthread/libdl, libstdc++, libgcc_s, libsystemd and libblkid.

### Trial build results (rev 4, measured)

A throwaway build of `origin/dev` (agent core, 69 plugins, server, tests; no gateway) in `rockylinux:8` (after `dnf update`, 8.10 content) with `gcc-toolset-15` (GCC 15.2.1 — worked first time, toolsets 14 and 13 were not exercised), cmake 3.26.5, ninja 1.8.2 (PowerTools), python3.11 + `pip install meson==1.6.1`, no EPEL and no mold (the toolset's `ld.bfd`). No push, no commit.

- **Maxima over 88 ELFs** (agent, core, 69 plugins, server, canaries, tools, 12 test binaries): `yuzu-agent` GLIBC 2.28 / GLIBCXX 3.4.22 / CXXABI 1.3.9; `libyuzu_agent_core.so` 2.28 / 3.4.22 / 1.3.11 / LIBSYSTEMD_240; `yuzu-server` **2.28** / 3.4.22 / 1.3.11; plugins 2.14 (63 of 69), 2.26 (2), 2.28 (4). The only glibc imports above 2.26 anywhere are `fcntl64@2.28` (12 ELFs, from meson's `_FILE_OFFSET_BITS=64`) and `renameat2@2.28` (1). **Nothing exceeds the agent floor; nothing exceeds the 2.34 server gate.** GLIBCXX tops out at 3.4.22 because the newer delta is linked statically from `libstdc++_nonshared.a`. No ELF imports an OpenSSL versioned symbol (vcpkg-static, no `libcrypto` in `NEEDED`). `LIBSYSTEMD` 240 in 6 ELFs, 237 in `echo`, 209 in `event_logs`; `BLKID_1.0` in `bitlocker`. All RUNPATHs are `$ORIGIN`-relative (the stale `$ORIGIN/../../core` is on all 69 plugins).
- **Runs:** `yuzu-agent --version` and `yuzu-server --version` succeed, and `ldd -r` over the 74 non-test ELFs shows no missing symbol or version, on plain `rockylinux:8` (distro libstdc++ 3.4.25, no toolset), `rockylinux:9`, `amazonlinux:2023`, `ubuntu:20.04/22.04/24.04`, `debian:11/12`. The minimal Amazon Linux and Debian/Ubuntu images needed `systemd-libs`/`libsystemd0` and `libblkid` installed (the packages declare them); Rocky 8 and 9 needed nothing. `amazonlinux:2` fails exactly as predicted (`fcntl64`/`renameat2` at GLIBC_2.28; `LIBSYSTEMD_221/222/237/240`).
- **Tests in plain `rockylinux:8`:** all 8 server non-Postgres suites pass (4,470 cases, 111 skipped, 0 failed; Postgres-gated tests were not run); the plugin ABI, spark, lexical-gate, shard-partition, SIGTERM-harness and echo suites pass (653 echo cases). Four agent-test groups fail in the container (`content_dist` exec seam — `/bin/echo` is a script on EL; `local_security_policy` lockout; 3 `autoruns` cases; an intermittent `asset_tags`). The same EL8-built test binary passes everything (4,853 passed) on an Ubuntu 26.04 host, and `autoruns`/`asset_tags` also fail on `ubuntu:22.04`, so these are container-environment sensitivities, not toolchain defects — but a real EL8 VM (Question 8) is the right check.
- **Needed changes (no C++):** (1) `triplets/x64-linux-el8-static.cmake` chainloading a small `x64-linux-el8-toolchain.cmake` that **includes vcpkg's `scripts/toolchains/linux.cmake` first** — a bare chainload dropped `-fPIC` and the `VCPKG_*_FLAGS` plumbing and broke the grpc port's codegen; the toolchain file takes the vcpkg root from `$VCPKG_ROOT` and the toolset from `YUZU_GCC_TOOLSET` (default 15); (2) `meson/native/linux-gcc15-el8.ini` (toolset compilers, `cpp_std=c++23`, no mold); (3) `meson.build` +10 lines on Linux: `add_project_dependencies(dependency('threads'), cxx.find_library('anl', required: false), language: 'cpp')`. The first link had 7 failing targets: `discovery.so` needs `-pthread` because GCC 15's `<thread>` emits an undefined `pthread_create`/`pthread_join` on glibc < 2.34, and `yuzu-server` plus `http_client`, `content_dist`, `printing` and two server test binaries need `-lanl` because cpp-httplib uses `getaddrinfo_a`. `-ldl` was **not** needed (the dlopen references arrive via the cmake imported targets). The link arguments must follow the objects (a native-file `link_args` entry is dropped by `--as-needed`). The resulting `NEEDED` additions (`libanl.so.1`, `libpthread.so.0`) load on every newer distro tested. (4) The container `PATH` must include `/usr/sbin` (libpq's `./configure` needs `zic`; without it it reports a misleading "cross-compiling" error). No vcpkg port pulled a symbol above glibc 2.28 (`arc4random_buf`, `strlcpy`, `strlcat` came from the build host's libc headers, not the ports) and no overlay port is needed.
- **Timings (32 cores):** image 80 s; vcpkg cold 314 s for 26 packages (source tarballs pre-cached); meson setup about 1 min; first full ninja build 519 s for 1,429 steps. The "+45–60 min first release" estimate in rev 3 is therefore high for a 32-core box (roughly 15 min of build plus downloads); a smaller runner will be slower, so it stays a ceiling until measured on Big Tam.

## Decision

**One C++ floor image, one small OTP image.**

| | C++ (agent, server, gateway's non-OTP parts) | OTP for the gateway |
|---|---|---|
| **Floor** | **agent:** glibc **2.28**, `GLIBCXX_3.4.25`, `CXXABI_1.3.11`, `LIBSYSTEMD` 239 (+ the measured `_240` backport), `BLKID_1.0`. **Server (promise and gate):** glibc 2.34, `GLIBCXX_3.4.29`, `CXXABI_1.3.13` (the GCC 11 / EL9 equivalents), `OPENSSL_3.0.0`, `LIBSYSTEMD_240`, `BLKID_1.0`; measured maximum when built in this image is glibc 2.28 | glibc 2.34, `OPENSSL_3.0.0` (RHEL/Rocky 9) |
| **Image** | `deploy/docker/Dockerfile.build-el8`: `rockylinux:8` pinned by digest after `dnf update` to 8.10 content (the `rockylinux:8` tag is 8.9 content; prefer `quay.io/rockylinux/rockylinux:8.10`, or `registry.access.redhat.com/ubi8` if the SBOM story must be "Red Hat-signed" — Rocky's packages are RESF-signed rebuilds, so decide at S1 with the image digest and the `gcc-toolset-15-gcc` NEVRA in hand) + `gcc-toolset-15` (fallback 14, then 13 — all verified in AppStream) + cmake 3.26 + python3.11 (`pip install meson==1.6.1`) + ninja (PowerTools) + **no EPEL** (mold and patchelf are EPEL-only: the floor native file drops `-fuse-ld=mold` and uses the toolset's own `ld.bfd`; verified) + `/usr/sbin` on `PATH` (libpq's `./configure` needs `zic`) + `rpm-build` + dpkg tooling | `deploy/docker/Dockerfile.build-otp-el9`: `rockylinux:9` + gcc + the oldest in-scope OpenSSL 3.0.x headers + ncurses; no vcpkg, no toolset |
| **Builds** | agent tarball/`.deb`/`.rpm`, agent-bundle payload; the server and its packages (decided — Q1) | OTP 28 from a pinned-sha source tarball, for the gateway `.deb`/`.rpm` |
| **Gate** | agent at 2.28; server and gateway at 2.34 | 2.34 |

**The key property:** an artifact built at the lowest floor runs on every newer distro. `gcc-toolset` is the ODR-safe way to run a new compiler on an old runtime: it links only `libstdc++_nonshared.a` into each object and leaves the system `libstdc++.so.6` the single runtime copy, so cross-DSO exceptions work (tested above). Red Hat's contract is that the archive carries the *full* delta; the floor gate verifies it.

**Why the gateway still needs EL9.** EL8 ships OpenSSL 1.1.1k only. An OTP 28 `crypto.so` built there needs `libcrypto.so.1.1`, which Ubuntu 22.04 and Debian 12 do not carry and EL9 has only as `compat-openssl11` — it would fail the in-scope set. EPEL8's `openssl3` is unsupported on RHEL and reintroduces the rebase risk; a bundled OpenSSL makes Yuzu its patcher. So OTP builds against EL9 with OpenSSL 3.0.x headers.

### Agent floor — required and best-effort

Required (CI leg or test for each): RHEL/Rocky/Alma/OL **8** (glibc 2.28), **9** (2.34), **10** (2.39); Amazon Linux **2023** (2.34); Ubuntu **20.04** (2.31), **22.04** (2.35), **24.04** (2.39), **26.04** (2.43); Debian **11** (2.31), **12** (2.36), **13** (2.41); 
SUSE: **SLES 15 SP3+ by construction** (glibc 2.31); tested on the current service pack through an `opensuse/leap:15.6` `--version` leg (SP3/SP4 are out of general support and SP5 is LTSS-only, so the live targets are SP6/SP7); not listed as required unless a customer names it. Best-effort (run by construction, a non-gating `--version` leg only): **Amazon Linux 2** (2.26), Ubuntu 18.04 (2.27), Debian 10 (2.28), SLES 12 SP5 and SLES 15 SP0–2 (2.22–2.26, EOL). Not supported: RHEL/CentOS 7 and earlier, Amazon Linux 1.

### Packaging

- **RPM:** the existing auto-generated `Requires` (`libc.so.6(GLIBC_2.x)` set) is correct; no compatibility flags.
- **`.deb`:** `dpkg-deb -Zxz` unconditionally (free; removes the Debian 10/11 zstd class). `Depends` derived, not hand-written: `libc6 (>= 2.28), libstdc++6 (>= 8), libgcc-s1 | libgcc1, libsystemd0, libblkid1` for the agent.
- **Fix the stale `$ORIGIN/../../core` plugin `RUNPATH`.**

### Server and gateway mechanics

- **Toolset order: 15, then 14, then 13 on any S0/S1 leak** (the tree needs GCC 13).
- **New triplet `triplets/x64-linux-el8-static.cmake`**, chainloading `/opt/rh/gcc-toolset-15/root/usr/bin/{gcc,g++}`. `scripts/ci/vcpkg-triplet-sentinel.sh` keys on `vcpkg.json`, the triplet and the vcpkg commit, **not the toolchain** — reusing the host-built `x64-linux-static` tree would silently link glibc-2.38-era objects.
- **Gateway (#5171):** OTP built in the EL9 image, dynamic SSL, against the **oldest in-scope OpenSSL 3.0.x headers** (Ubuntu 22.04's 3.0.2), so `crypto.so` stays within `OPENSSL_3.0.0`. RPM `Requires: glibc >= 2.34, openssl-libs >= 3.0, ncurses-libs` (keeping `AutoReqProv: no`); `.deb` `Depends: libssl3t64 | libssl3 (>= 3.0.0)`. SM4 leaves `crypto:supports()` (no Yuzu use).
- **Bundled OpenSSL fallback** (only if the gate shows `crypto.so` importing above `OPENSSL_3.0.0`): decided by **`security-guardian` together with the operator and recorded as an amendment to this ADR** before it ships.
- **Server `.deb` dependencies** derived from the gate's measured maxima (`libc6 (>= 2.28), libstdc++6 (>= 8), libgcc-s1`), never hand-written.

### The floor gate and its baseline

`scripts/ci/check-elf-floor.sh` plus floor files under `deploy/packaging/` (an agent floor at 2.28 and a server/gateway floor at 2.34, each allowing the measured `LIBSYSTEMD_240` and `BLKID_1.0`) runs `objdump -T` over every ELF in the staging directory (binaries, plugins, ERTS, `crypto.so`) and fails on any import above the floor, any forbidden symbol (`EVP_sm4_*`), or an absolute `RUNPATH`. **The baseline is recorded** in a committed `deploy/packaging/linux-floor-baseline.json` (per artifact: maxima plus the offending-symbol list, generated by `--emit-baseline`) and as a CI artifact with the full report, so the gate can be tuned before it becomes enforcing. The agent bundle repackages the gated staging directory and is covered transitively; the bundle job re-runs the gate on the extracted payload.

## Alternatives considered

| Alternative | Why not |
|---|---|
| **RHEL 7 / glibc 2.17 agent floor (rev 2)** | Dropped by the operator. It needed a conda-forge sysroot, a bundled C++ runtime for Yuzu to patch, an sd-bus `dlopen` shim, rpm 4.11 flags and a systemd 219 drop-in. |
| **Static `libstdc++`/`libgcc` in each DSO (`-static-libstdc++`)** | Unsafe: agent plugins link the C++ symbols of `libyuzu_agent_core.so`, and the loader uses `dlopen(RTLD_LAZY\|RTLD_LOCAL)`; a full copy per DSO duplicates exception globals. **`libstdc++_nonshared.a` (what `gcc-toolset` links) is not this** — it carries only delta code, with typeinfo and exception globals single-copy in the system runtime; the by-type catch probe above passed. |
| **A bundled private libstdc++/libgcc_s** | Needed only below glibc 2.28; at 2.28 it makes Yuzu the patcher of a runtime for no support gain. |
| **One EL8 image for everything including OTP** | The gateway's OpenSSL needs EL9 (above). |
| **Separate EL9 image for the server (reviewer's literal EL9 server floor)** | Costs a second triplet, vcpkg tree and canary for no support gain; the server's gate is 2.34 regardless of the image that builds it. Kept as the fallback if the reviewer insists. |
| **Lower the EL9 image for the agent** | Impossible: the floor is the libc the code is linked against. |
| **Bundle OpenSSL into the gateway by default** | Makes Yuzu the patcher of an OpenSSL copy; kept only as the gated fallback. |
| **Declare the gateway RH-family unsupported (container only)** | Abandons RHEL, the mainstream enterprise platform. |
| **Floor = Ubuntu 24.04, native, gcc-14** | Still excludes every in-scope RHEL, Ubuntu 22.04 and Debian 12 host. Last resort only. |

### Buying Amazon Linux 2 back (bounded increment, not a design fork)

AL2 (glibc 2.26, systemd 219, rpm 4.11) already loads the EL8-toolset ELFs for libc/libstdc++, so the delta is: (a) a runtime `dlopen` shim for libsystemd's bus API (9 translation units: `agents/core/src/{main,guard_systemd,guardian_state_reader,spark_service}.cpp`, `firewall`, `device_identity`, `event_logs`, the `echo` power collector, `wifi`) — without it the core and 7 plugins do not load; those 7 then report `constrained`; (b) scrub `GLIBC_2.27/2.28` imports: meson's default `-D_FILE_OFFSET_BITS=64` turns `fcntl` into `fcntl64@GLIBC_2.28` (measured), so a project-wide `-U_FILE_OFFSET_BITS` (harmless on x86_64) plus `renameat2` → `syscall()`, and whatever vcpkg ports pick up; the agent gate floor drops to 2.26; (c) rpm 4.11 flags (`rpmlib(LargeFiles)`/`PayloadIsZstd` fail there); (d) a systemd 219 `%post` drop-in for the unit directives it ignores; (e) an `amazonlinux:2` required leg and the `constrained` support statement. Estimate 3–5 engineer-days plus a permanent extra leg. AWS states AL2 reached end of support on 2026-06-30.

## Consequences

**Positive:** the agent runs on RHEL 8 through 26.04 with **no C++ source change** (built and measured; only meson link wiring); no toolchain beyond Red Hat's own packaged `gcc-toolset` (signed by Red Hat on RHEL/UBI, by the Rocky project on Rocky), no bundled runtime for Yuzu to patch; one vcpkg triplet and one canary for all C++; the QA install legs become a real release gate; package dependencies are measured; the glibc-2.38 `__isoc23_*` trap (`docs/cpp-conventions.md`) is removed by building against old headers, not policed; distros keep patching OpenSSL and libstdc++.

**Costs and risks**
- **Two small images**, both digest-pinned on GHCR with Dependabot, plus nightly canaries (`linux-el8-floor`, `linux-otp-el9`). First container release roughly 15 minutes of build plus downloads on a 32-core box (measured, vcpkg 5 min + compile ~10 min; a smaller runner will be slower, so treat +45–60 minutes as a ceiling until measured on Big Tam); caches and a host ccache mount bring later runs close to today's. The Docker Hub tag moves, so Dependabot alone is not enough: a scheduled rebuild (the nightly canary) bumps the digest, and the floor baseline is re-emitted on every image bump (a toolset minor can change `libstdc++_nonshared.a`).
- **Runner mechanics are unverified.** Big Tam is itself a container (`Dockerfile.runner-linux`); `docker run -v` from inside it maps **host** paths. See the S1 precondition.
- **Container testing cannot exercise the RHEL 8 `platform_security` lockdown row** (a host-kernel feature) or a real systemd-239 unit run; an EL8 VM is needed for those (Q8: the reviewer provides one).
- **Upgrades:** `Depends`/`Requires` changes are additive on upgrade. The Docker and chisel images carry their own runtimes and are unaffected. `docs/agent-bundle.md` ("needs glibc 2.38", ~line 133) must be rewritten.
- **Confidence:** high on the floor, sd-bus, `nonshared` cross-DSO behaviour, packaging and unit-file findings (all run). Medium on a full vcpkg + meson build inside the EL8 image (bootstrap and toolchain verified, the ports were not built — a port that hard-requires a >2.28 symbol, e.g. `arc4random_buf`/`strlcpy`, would cost an overlay port and shows up in the S0 baseline) and on RHEL 8 proper's toolset list (verified on Rocky 8).

## Phased plan (each slice mergeable, each with a CI-visible gate)

| Slice | Content | Gate / precondition |
|---|---|---|
| **S0 — gate first (precondition for everything)** | `check-elf-floor.sh`, floor files (agent 2.28, server/gateway 2.34), committed baseline, `--emit-baseline`; wired into `release.yml` (after "Package archive") and Pre-release QA, **report-only**; a `rockylinux:8` `rpm -ivh --test` + `--version` leg | The script's tests; the baseline measures the current gap |
| **S1 — EL8 image** | `Dockerfile.build-el8`, `meson/native/linux-gcc15-el8.ini` (no mold), `triplets/x64-linux-el8-static.cmake` + `x64-linux-el8-toolchain.cmake` (which includes vcpkg's `linux.cmake` first), the `meson.build` `threads` + `-lanl` wiring (trial: +10 lines), `floor-build.sh` (the same script a developer runs locally; publishes nothing); nightly canary that builds the image, bumps its digest, re-emits the baseline and runs the agent unit tests in a plain `rockylinux:8` container (no toolset — the `nonshared` cross-DSO proof on real code, and where a port leak surfaces first) | **Precondition: `build-ci` verifies `docker run -v` on the containerised Big Tam runner and, if path mapping is needed, makes and applies the provisioning change itself (Q5).** Fallback: a GitHub-hosted `container:` job on `ubuntu-24.04` (~60–90 min, no Big Tam ccache, contention for the 10 GB `actions/cache` quota) |
| **S1-otp — OTP image** | `Dockerfile.build-otp-el9` (OTP only) | Depends on nothing else |
| **S2-agent** | Build the agent through the EL8 image; `dpkg-deb -Zxz`; derived `Depends`; stale RUNPATH fix; agent gate **enforcing** | QA legs rockylinux:8/9, amazonlinux:2023, ubuntu:20.04/22.04/24.04, debian:11/12/13 green; best-effort non-gating amazonlinux:2, ubuntu:18.04, debian:10. **Closes #5143 for the agent** |
| **S2-server** | `release.yml` `build-linux` server through `floor-build.sh` (EL8 image; the EL9 image if the reviewer overrules); derived `.deb` `Depends`; server gate at 2.34 enforcing | QA legs ubuntu:22.04/24.04, debian:12/13, rockylinux:9 green. **Closes #5143 for the server** |
| **S3 — gateway** | OTP from the EL9 image against the oldest 3.0.x headers; RPM `Requires`; `.deb` `Depends` | fedora:42 + rockylinux:9 gateway legs green. **Closes #5171** (needs S1-otp) |
| **S4 — docs and governance** | "Supported Platforms", `build-guide.md`, `ci-architecture.md`, `agent-bundle.md`, release-verification (OTP provenance), changelog fragments | Docs lint; `docs-writer` + `release-deploy` sign-off |

## Floor review rule

Re-evaluate both floors (a) when the next Ubuntu LTS ships (the n-2 window moves), (b) at each RHEL major GA, and (c) at RHEL 8 end of maintenance support (31 May 2029, to confirm) — at which point the agent floor rises to EL9 and the two C++/OTP images merge. Each review is a one-line amendment to this ADR plus a baseline refresh.

## Decisions on the questions

The reviewer answered all ten on PR #5631 on 2026-10-19 and stated that implementation can proceed on this basis. The questions are kept in short form so each decision stays attached to what it settles.

**Server and gateway**
1. **Yes.** The server and the agent are built in the one EL8 image. The server's promise and gate stay n-2 LTS at glibc 2.34 (measured maximum when built there: 2.28).
2. **Yes.** The EL8 and OTP images are published to GHCR, digest-pinned, with Dependabot and the nightly refresh.
3. **Yes.** OTP 28 is built from a pinned source tarball, not RabbitMQ's signed `erlang-rpm`.
4. **Yes.** Both nightly canaries (`linux-el8-floor`, `linux-otp-el9`) are approved.
5. **`build-ci` owns the Big Tam provisioning change end to end, including applying it** — not a change handed to the reviewer to apply. If `docker run -v` needs path mapping on the containerised runner (`deploy/linux`), `build-ci` makes and applies it; this is the S1 precondition.
6. **Yes.** SM4 is dropped from the gateway's `crypto:supports()`.

**Agent**
7. **Amazon Linux 2 is best-effort only.** Buy it back (3–5 engineer-days plus a permanent leg, itemised above) only if a named customer fleet under contract is on it.
8. **Yes.** The reviewer provides an EL8 VM for the `platform_security` lockdown row and a real systemd-239 unit run. It is needed by S2.
9. **Yes.** SLES 15 SP3+ by construction, tested on the current service pack via `opensuse/leap:15.6`; SLES 15 SP0–2 and SLES 12 unsupported.
10. **Provenance accepted.** Rocky 8 versus UBI8 is decided at S1, with the image digest and the `gcc-toolset` package version in hand (UBI8 if the SBOM must say "Red Hat").

## Reviewers required when this moves to implementation

`build-ci` (release.yml, sentinel, triplets, runner mechanics, both images), `release-deploy` (packages, dpkg compatibility, `Depends`/`Requires`), `cross-platform`, `cpp-safety` (cross-DSO exceptions with `libstdc++_nonshared.a`, plugin ABI), `security-guardian` (the artifact-signature verify chokepoint is unchanged; bundled OpenSSL decision), `gateway-erlang` (OTP build, `crypto.so`), `docs-writer`, `sre` (canaries, CI cost), and `compliance-officer` (SBOM: toolchain and OTP provenance).

## Out of scope

Windows and macOS builds; aarch64 Linux artifacts (not shipped today); changing the Docker images' bases (they carry their own runtimes and remain the supported route for older distros until S2 lands); RHEL 7 and Amazon Linux 1; vendoring or patching OpenSSL.
