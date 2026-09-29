---
status: proposed
date: 2026-07-21
owner: Fraser Jarvis (Darwin/macOS compatibility guardian)
deciders: >-
  pending — acceptance requires at least one recorded independent review and a linked tracking issue
  (SOC 2 Workstream F change-management evidence; cf. ADR-0006/0007 decision records). This draft
  was shaped by a grill-with-docs design session on 2026-07-21 and reviewed by Fable acting as
  Enterprise Architect (verdict ACCEPT-WITH-CHANGES; the three blockers and should-fixes are
  incorporated in this revision).
scope: platform — supported operating systems per deployable, the CI/release matrix, and the platform-specific server code + build/CI plumbing that removal deletes
amends: >-
  0031-presentation-core-engine-decomposition Gate G10 — the "MSVC static linkage included" clause of
  the Drogon build canary is VOIDED; the canary becomes Linux-only. See Decision 6.
related: >-
  0006-server-postgresql-substrate / 0007-server-single-backend-no-sqlite-fallback / 0008-postgres-substrate-architecture
  (the server substrate this ADR makes single-OS as well as single-backend);
  0031-presentation-core-engine-decomposition (**accepted 2026-07-14**, on `dev`; the Linux-only
  constraint here binds all three server-role binaries it defines);
  1005-headless-platform-use-case-engines (a headless, containerised control plane is more coherent
  as Linux-only);
  docs/windows-build.md, docs/darwin-compat.md, docs/os-capability-matrix.md, docs/ci-architecture.md,
  docs/uat-environment.md (the reference docs whose Windows/macOS-server content this ADR retires).
---

# 0035 — The Yuzu Server is a Linux-only component; Windows and macOS are Agent-only platforms

## Binding status

Nothing here binds reviews or blocks PRs until this ADR's status is **accepted**. On acceptance the
Decisions bind **prospectively**, and the implementation ladder below is the order in which they
become true. This ADR decides a direction and authorises the removal work; it does not itself remove
code — that lands in the follow-up PRs the ladder names. The Decision-6 amendment to ADR-0031 takes
effect on this ADR's acceptance, on the same change-management basis ADR-0031 used to amend
ADR-1005 and ADR-0006's Update section amends ADR-0006.

## Context

Yuzu ships three C++/Erlang deployables plus the agent:

- **Yuzu Server** — the control plane (REST v1, MCP, HTMX dashboard, instruction/policy/scope
  engines, RBAC, audit, PKI, Postgres-backed stores). PostgreSQL is its sole storage substrate and
  it fails closed at boot without it (ADR-0006/0007/0008).
- **Yuzu Gateway** — the Erlang/OTP relay between agents and the server.
- **Yuzu Agent** — the per-endpoint daemon that runs plugins on managed Windows / macOS / Linux
  machines. This is the product's reason to be cross-platform: you manage a fleet of Windows and
  macOS endpoints, so the agent must run there.

Today the build/release matrix treats the **server** as a first-class Windows *and* macOS target:

- `release.yml`'s "Build Windows x64" job compiles and signs `yuzu-server.exe`, builds a
  `YuzuServerSetup-*.exe` InnoSetup installer (`deploy/packaging/windows/yuzu-server.iss`), and
  bundles the server + the full vcpkg DLL sweep (including `libpq.dll`) into `yuzu-windows-x64.zip`.
- The "Build macOS ARM64" job bundles **and notarizes** `yuzu-server` inside
  `yuzu-macos-arm64.tar.gz`, and stages `scripts/install-server-postgres.sh` — whose local mode
  covers Homebrew `postgresql@NN`. So while no macOS server **`.pkg` installer** has ever shipped
  (the release matrix's macOS-server column is `—`), a **scripted native-macOS server install path
  does ship today**. The claim to retire is "no `.pkg`", not "no macOS server".
- CI builds the server on Windows and macOS across several workflows, with differing depth:
  - **`ci.yml`** — the only workflow that **builds and runs the server test suite** on Windows
    (Wee Tam) *and* on macOS (which runs `scripts/ci/ensure-postgres.sh` and the native
    `--suite server` leg).
  - **`nightly.yml`** — its Windows ASan job is **already agent-only** (`-Dbuild_server=false`,
    `--suite agent`); it does not build the server. (An earlier draft of this ADR wrongly listed it
    as a Windows server-test leg.)
  - **`codeql.yml`** — **builds** the Windows server for analysis but does not run the test suite.
  - **`instructions-windows-validate.yml`** — stands up a live `yuzu-server.exe` **smoke rig**, not
    the unit suite.

This carries a large, recurring cost for a server configuration **no one deploys in production**:

1. **The server's heaviest, flakiest dependency surface is non-Linux pain.** The server links
   `grpc`/`protobuf`/`abseil` **and** `libpq` (Postgres client). The Windows static-linkage of the
   grpc stack (LNK2038/LNK2005, issues #375/#376) and libpq's DLL/CRT-mismatch hazard (silent
   wrong-CRT link — the load-bearing `_vcpkg_lib_win` pick, `meson.build` Windows libpq branch, and
   the CLAUDE.md vcpkg notes) exist *only* to keep a non-Linux server building. Postgres-backed
   server tests are the slowest, most timeout-prone leg on both Windows and macOS (the 2026-07-12
   Windows server-suite timeout that forced the pre-migrated-template test pattern).
2. **Enterprises deploy the control plane on Linux.** The realistic deployment target is a container
   (the published Docker image, Kubernetes) or a Linux host binary/`.deb`/`.rpm`. A native
   Windows-Server or macOS install of a Postgres-backed control plane is not how customers run this
   class of software, and there is **no known production or POC deployment** of the server on native
   Windows or macOS. It is pre-1.0 (v0.12.0).
3. **It privileges an unused path over the product's actual promise.** Engineering effort spent
   green-lighting the Windows/macOS *server* is effort not spent on the Windows/macOS *agent*, which
   is where cross-platform support genuinely matters.

The agent is a different story: it is SQLite-only (no libpq), and Windows/macOS support is the
whole point. It stays fully cross-platform.

ADR-0031 (**accepted 2026-07-14**) is decomposing "the server" into three binaries (presentation /
core / engine). "Drop the non-Linux server" must therefore be stated as a property of the *server
role*, so it carries forward to all three binaries rather than being scoped to today's monolith. One
of ADR-0031's still-open gates — **G10**, the Drogon presentation-layer build canary — is specified
"MSVC static linkage included"; this ADR interacts with it directly (Decision 6).

## Decision

### 1. The server is a Linux-only component

The Yuzu Server — the current monolith and **every binary the ADR-0031 decomposition splits it into
(presentation, core, engine/UCE host)** — is a Linux x86_64/arm64 component. It is built, tested,
released, and supported on Linux only. Its blessed deployment surface is the published container
image (Kubernetes or any OCI runtime) and the Linux host binary / `.deb` / `.rpm`. This is the
operating-system counterpart to ADR-0007's single-backend posture: the server already refuses to run
without PostgreSQL; it now targets one OS as well.

### 2. Windows and macOS are Agent-only (and endpoint) platforms

Windows and macOS are **managed-endpoint** platforms. On them Yuzu ships the **Agent only**. The
agent remains fully first-class on Windows (MSVC), macOS (Apple Clang), and Linux (GCC/Clang),
including CI, sanitizers where applicable, and signed/notarized installers.

### 3. Full removal now — not deprecation, not dead-code retention

Because there are no deployments to strand (Context §2), the Windows/macOS server is removed outright
rather than deprecated over a sunset window or left in-tree as unbuilt "best-effort" source.
Concretely, removal covers: the server from the Windows/macOS release staging (incl.
`install-server-postgres.sh` from the macOS tarball); the `YuzuServerSetup-*.exe` InnoSetup path;
the server build/test legs on the Windows and macOS CI runners; the server-side `#ifdef _WIN32` /
`#ifdef __APPLE__`-specific branches under `server/core/` (the POSIX/Linux branch is retained); and
the build-system + CI plumbing that exists solely for the non-Linux server (the meson Windows libpq
branch, the libpq link-provenance canaries, and Postgres provisioning on the endpoint-OS CI legs —
ladder step 4). Leaving the code but disabling CI is explicitly rejected (Considered and rejected
§C): unbuilt code rots and emits a false "it still compiles" signal.

### 4. The build enforces Linux-only via a feature option — without breaking default configures

`build_server` is converted from a plain boolean (which defaults **true**, so a naive "error on
non-Linux" would break every fresh `meson setup build-macos` / `scripts/setup.sh` on Windows and
macOS — including agent-only developers) into a **Meson feature option** with the semantics:

- `auto` (default) on a **Linux target** → build the server; on a **non-Linux target** → silently
  **disabled** with an informational message. A plain checkout configures agent-only off-Linux with
  no error.
- `enabled` on a non-Linux target → **hard configure error** with a clear message ("the Yuzu server
  is Linux-only; see ADR-0035").
- `disabled` → never build the server.

The check keys on `host_machine.system() == 'linux'` (the *target*), so a **Linux-target cross build
from any build machine stays legal** — matching "the server *runs* on Linux", not "you may only
build it on Linux". The same PR updates `scripts/setup.sh`, the CLAUDE.md quickstarts, and the docs
that pass `-Dbuild_server=false` (now `-Dbuild_server=disabled`).

### 5. Windows/macOS release archives become agent-only and are renamed for honesty

With the server gone, `yuzu-windows-x64.zip` and `yuzu-macos-arm64.tar.gz` contain only the agent +
plugins. They are renamed to say so (e.g. `yuzu-agent-windows-x64.zip`,
`yuzu-agent-macos-arm64.tar.gz`) so the artifact name does not imply a server is inside. The rename
has a real blast radius — every consumer of the old names is updated in the same change (ladder step
2). The Linux `yuzu-linux-x64.tar.gz` remains "server + agent".

### 6. Amendment to ADR-0031 Gate G10 — the Drogon build canary is Linux-only

ADR-0031 Decision 5 gates the Drogon presentation binary on **G10: "a build canary — Drogon linked
into the existing Meson/vcpkg matrix, MSVC static linkage included — must pass before this leg is
committed to,"** explicitly citing the #375 grpc/abseil-on-MSVC history. Under Decision 1 the
presentation binary is a Linux-only server-role component, so its MSVC static linkage is out of
scope. **The "MSVC static linkage included" clause of G10 is VOIDED; the Drogon canary becomes
Linux-only.** The rest of G10 (Drogon must link cleanly into the existing Meson/vcpkg matrix on
Linux before the leg is committed) stands. This removes a contradiction that would otherwise exist
between two accepted ADRs — G10 would require a Windows-MSVC canary for a binary Decision 1 forbids
from building on Windows.

## Considered and rejected

- **A. Keep the Windows/macOS server (status quo).** Rejected: recurring CI cost and flake
  (grpc/libpq static-linkage, slow Postgres server tests on two endpoint-OS legs) for a
  configuration with zero known deployments and no demand. The value delivered does not justify the
  maintenance tax.
- **B. Deprecate with a one-or-two-release sunset window.** Rejected: a sunset window protects
  existing users, and there are none (pre-1.0, no native server deployments). A sunset here is
  ceremony that prolongs the cost it is meant to retire.
- **C. Untier (drop CI + artifacts) but keep the server platform code in-tree.** Rejected: unbuilt
  platform branches rot, and a green agent build emits a false "the non-Linux server still compiles"
  signal. If the OS is unsupported, the honest state is that the code is gone. (Reversal cost is
  bounded but grows over time — see Consequences.)
- **D. Narrow the ADR to Windows only; keep the macOS server for dev ergonomics.** Rejected, but the
  cost is real and must be stated honestly: **macOS today runs a native server build and a native
  server test suite** — the maintainer's own MacBook (arm64, Apple Clang 17) compiles `yuzu-server`
  (171 MB) and runs `meson test -C build-macos --suite server` and `/test` end-to-end against a
  Colima-hosted Postgres (memory `macbook-local-build-setup.md`; Colima hosts *only* the Postgres
  container, not the server). Full removal retires a **live, daily-used** macOS server dev/test loop
  and drops **Apple Clang as a second-compiler diversity signal for server code** (GCC + MSVC found
  real bugs historically; losing Apple Clang on the server narrows that). The decision still stands —
  "the server is a Linux component" is a cleaner, more defensible EA statement than "the server runs
  anywhere except Windows", and macOS server dev is served by a Linux builder container / VM /
  Docker — but the ADR names this as a cost paid, not a cost already sunk. Ladder step 5 names the
  replacement macOS dev workflow and the `/test` consequence.
- **E. Drop the gateway's Windows CI compile too.** Rejected: it is nearly free (rides the existing
  Windows agent leg + already-provisioned rebar3) and guards real Erlang portability. Removing it
  would trade a cheap early-warning for a marginal CI-time saving. (See Gateway, below.)

## Gateway

The gateway already ships Linux-only — the release matrix's gateway Windows/macOS columns are `—`;
the only artifacts are `yuzu-gateway-linux-x64.tar.gz` + `.deb`/`.rpm`, built by a Linux self-hosted
job. This ADR **affirms** the gateway as a Linux-only deployable, co-located with the server.

The gateway's meson `custom_target('gateway')` fires whenever `rebar3` is on `PATH`
(`meson.build:440`), **independent of `build_server`**. It therefore continues to compile on the
Windows agent CI leg with no extra wiring, and we **keep** this Windows compile as a cheap
portability canary for the Erlang code — it ships nothing and costs only the rebar3-on-Windows
toolchain already provisioned on Wee Tam. It is a **known-fragile, non-blocking** canary (CodeQL
notes the target "may fail on Windows", `codeql.yml:445`) — it must stay `continue-on-error` /
informational, or it reintroduces the Windows flake this ADR exists to shed. **Standing
prerequisite:** the canary exists only while `rebar3` stays on Wee Tam's `PATH` (the target is
find-program-gated); a runner reprovision that drops rebar3 silently deletes it. Its toolchain owner
is the runner-provisioning path (`deploy/windows/Provision-Windows-Runner.ps1`, `YUZU_REBAR3`).

## Consequences

**Positive**

- **Removes the server's non-Linux dependency pain from CI** — the libpq/Postgres client surface and
  the grpc-stack static-linkage hazards no longer need to hold on Windows/macOS, and the slow,
  timeout-prone **server test suite** stops running on both endpoint-OS runners (currently `ci.yml`).
- **Shrinks the endpoint-platform supply-chain surface.** Agent-only Windows/macOS artifacts no
  longer ship `yuzu-server(.exe)`, `libpq.dll`, or the vcpkg server-DLL sweep, and the macOS artifact
  no longer carries a **notarized** server binary. That materially reduces the signed/notarized
  footprint, the SBOM/CVE-response surface, and the patch surface on endpoint OSes — a genuine
  enterprise-readiness benefit.
- **Simpler, more honest release matrix** — server is Linux-only (image + `.deb`/`.rpm` + tarball);
  Windows/macOS ship a clearly-named agent artifact; gateway is Linux-only.
- **A defensible EA position** — "control plane on Linux, agents on the endpoints" matches how this
  class of platform is actually deployed and how the server is architected (containerised,
  Postgres-backed, k8s-friendly; coherent with ADR-1005's headless direction).
- **Focuses cross-platform effort where it pays** — the Windows/macOS *agent*.

**Honest limits (do not overclaim)**

- **Windows/macOS CI is reduced, not eliminated.** The **agent** still links
  `grpc`/`protobuf`/`abseil` on Windows and macOS, so the grpc-stack toolchain and its linkage config
  stay. What goes away is the server-specific surface (libpq, Postgres server tests, dashboard/REST/
  MCP server build, server InnoSetup, notarized server binary). The relief is real but partial.
- **The gateway canary is advisory only** and must remain non-blocking (see Gateway).
- **A live macOS server dev/test loop is retired.** Developers lose the native `build-macos`
  `--suite server` path and native `/test` server coverage on macOS; the `/test` "standard surface"
  becomes platform-asymmetric (server gates run on Linux only). The replacement is a Linux builder
  container / VM / the Docker image — already viable, but now the only path. Server code also loses
  Apple Clang as a compiler-diversity signal (Considered and rejected §D).

**Risks and mitigations**

- **Windows-only enterprises (no Linux/k8s competency).** A shop with no Linux footprint loses the
  option of a native Windows-Server control plane. Mitigation: the server is designed for
  containerised deployment; Docker Desktop / WSL2 / a single Linux VM are all viable on Windows
  hardware, and the agent — the part that must be native on Windows — is unaffected. Given no known
  such deployment, this is a latent risk, not an active one; it is called out so acceptance is an
  informed choice.
- **Reversal cost grows monotonically.** "Recoverable from git history" is true only for code that
  existed at removal. Every server line written *after* acceptance will be Linux-only by
  construction — there will be no `_WIN32`/`__APPLE__` branches to resurrect, only a port to write —
  so the cost of ever restoring a non-Linux server rises with time-since-acceptance. The ADR is
  reversible by a superseding ADR, not by silent drift, but reversal is a project, not a `git revert`.

**Interaction with in-flight / accepted work**

- **ADR-0031 (accepted 2026-07-14).** Decision 1 binds the Linux-only constraint to the presentation,
  core, and engine binaries as they are split out; Decision 6 amends its Gate G10 to drop the MSVC
  clause. This *simplifies* the decomposition — every server-role binary targets one OS.
- **ADR-1005 (headless platform / use-case engines).** Reinforcing, not conflicting: a headless,
  containerised, Postgres-backed control plane with separately-deployed use-case engines is *more*
  coherent as Linux-only.
- **`build_agent` stays a boolean; `build_server` becomes a feature** (Decision 4). `-Dbuild_server=false`
  becomes `-Dbuild_server=disabled` across CI and docs — the CI change is mostly flipping/renaming an
  option plus the configure guard, not new build plumbing.

## Implementation ladder (follow-up PRs — not this ADR)

1. **CI** — make the Windows and macOS legs agent-only: in `ci.yml` set the server feature to
   `disabled` and drop the `--suite server` runs on **both** Wee Tam and the macOS leg (incl. that
   leg's `scripts/ci/ensure-postgres.sh` for server tests); drop the Windows server build row in
   `codeql.yml`; retire or re-scope `instructions-windows-validate.yml` (its live `yuzu-server.exe`
   smoke rig is server-only). `nightly.yml` Windows ASan is already agent-only — no change. Sweep
   `pre-release.yml` (its Windows/macOS install jobs are already agent-installer-only, but the
   artifact-name change reaches it). Keep the (non-blocking) gateway canary. Prune now-unused Windows
   server cache scopes (`cache-prune.yml`).
2. **Release + rename blast radius** — remove the server from the Windows/macOS staging in
   `release.yml` (incl. `install-server-postgres.sh` from the macOS tarball); delete the
   `YuzuServerSetup` / `deploy/packaging/windows/yuzu-server.iss` path; rename the Windows/macOS
   archives to their agent-only names and update **every** consumer: `scripts/check-release-artifacts.sh`
   (the `FILES` array **and** the `.cdx.json`/`.spdx.json` SBOM name expectations), the SBOM artifact
   names + provenance-attestation subjects in `release.yml`, `.claude/skills/release/SKILL.md`,
   `.codex/skills/release/SKILL.md`, `docs/user-manual/release-verification.md`, and
   `scripts/build-agent-bundle.sh`. Update the release-notes platform matrix (server row → Linux-only)
   and the platform-archives table.
3. **Build guard** — implement Decision 4: convert `build_server` to a feature option, key the guard
   on `host_machine.system()`, and update `scripts/setup.sh`, the CLAUDE.md quickstarts, and any docs
   passing `-Dbuild_server=false` in the same PR.
4. **Code + build/CI plumbing** — remove server-side `_WIN32` / `__APPLE__`-specific branches under
   `server/core/` (retain POSIX/Linux; do not disturb `agents/shared/` or `sdk/`, which stay
   cross-platform); and remove the plumbing that exists only for the non-Linux server: the
   `meson.build` Windows libpq branch (incl. the `_vcpkg_lib_win` CRT-mismatch note), the libpq
   link-provenance canary steps in `ci.yml` (Windows DLL-import + macOS static variants), Postgres
   provisioning for server tests on the Wee Tam and macOS legs, the CLAUDE.md vcpkg libpq-DLL
   paragraph, and the server-dep entries in `deploy/windows/README.md` / `toolchain-manifest.json`.
5. **Docs + dev workflow** — retire the server sections of `docs/windows-build.md`; scope
   `docs/darwin-compat.md` to the agent and **document the replacement macOS server dev workflow**
   (Linux builder container / VM / Docker image) and the `/test` platform-asymmetry
   (`.claude/skills/test/SKILL.md`); make `docs/uat-environment.md`'s native rig Linux-only; update
   `docs/os-capability-matrix.md`, `docs/ci-architecture.md`, `docs/capability-map.md`, and the
   CLAUDE.md build sections; add a `changelog.d/` fragment; add release-note guidance pointing any
   former Windows/macOS-server curiosity at the Docker image / Linux binary.

## Security note (for Gate 6)

Endpoint platforms no longer receive a control-plane binary in their artifact — this removes the
"someone accidentally ran the server on a managed endpoint" footgun and the `YuzuServerSetup` patch
surface from Windows/macOS. The enrollment / PKI story (Register / ProxyRegister, the "never
internet-expose `:50051`" rule) is OS-agnostic and **unchanged** by this ADR — the agent's transport
and trust model are identical whether or not a server can be built on the same OS.
