---
status: accepted
date: 2026-07-21
accepted: 2026-11-10
owner: Fraser Jarvis (Darwin/macOS compatibility guardian)
deciders: >-
  Decided 2026-11-10 by Fraser Jarvis (owner) after consulting Tr3kkR and Doomgoose; all three agreed.
  Tracking issue of record: #2323 (SOC 2 Workstream F change-management evidence; cf. ADR-0006/0007
  decision records). Independent reviews of record: (1) Fable acting as Enterprise Architect on the
  2026-07-21 draft, verdict ACCEPT-WITH-CHANGES, whose three blockers and should-fixes were
  incorporated before the ADR merged as `proposed`; (2) a second Fable Enterprise Architect re-read
  against `origin/dev` cd163fe4d on 2026-11-10, verdict ACCEPT-WITH-CHANGES, whose required
  corrections are incorporated in the acceptance change; (3) the review of the acceptance pull
  request itself, #7465.
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
  2003-linux-native-build-floor (the server's Linux build floor: an EL8 build image);
  0069-gateway-transport-owned-grpc-cowboy-gun-overload-model (already cites this ADR for "server and
  gateway are Linux-only");
  docs/windows-build.md, docs/darwin-compat.md, docs/os-capability-matrix.md, docs/ci-architecture.md,
  docs/uat-environment.md (the reference docs whose Windows/macOS-server content this ADR retires).
---

# 0035 — The Yuzu Server is a Linux-only component; Windows and macOS are Agent-only platforms

## Binding status

Accepted 2026-11-10 (#2323). The Decisions bind **prospectively**, and the implementation ladder below is the order in which they
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
  - **`ci.yml`** — the only workflow that **builds and runs the server test suite** off Linux. On
    Windows (Wee Tam) it runs the full set: `server-nonpg`, `server-checks`, `server-pg` (14
    shards) on the debug leg, or the `server pg smoke` entry on the release leg, plus the `yuzu_pg_canary.exe` libpq provenance step.
    On macOS it builds the server and runs the non-`[pg]` server suite and the static-libpq
    canary, but **not** the `[pg]` suite: that was dropped there under this ADR's name by #2394
    while the ADR was still `proposed` (see the "Server Postgres suite skipped on macOS" step in
    `ci.yml` and `docs/ci-architecture.md`, "macOS does NOT run the server `[pg]` suite"), a
    partial, pre-acceptance step 1. No Postgres is provisioned on the macOS leg.
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
   Windows or macOS. It is pre-1.0 (v0.12.0 when this ADR was drafted; v0.15.0 at acceptance).
   **Post-draft fact (2026-11-10):** after this ADR was drafted, the Windows server installer
   received real work — PR #5326 hardened the existing `YuzuServerSetup-*.exe` for 0.14.1
   (closing #5196, #5210 and #5272; #5343 followed separately), with
   `deploy/packaging/windows/yuzu-server.iss` + `generate-config.ps1`, a runbook in
   `docs/user-manual/server-admin.md`, and release-notes copy in `release.yml` advertising
   `YuzuServerSetup-*.exe /ADMIN_USER=…`. The "no deployments" premise is unaffected, because **the
   installer has never produced a running service**: `yuzu-server.exe` has no service entry point,
   so the installed `YuzuServer` service never starts (#5325, open). (`server-admin.md` also
   documents wrapping the server with `sc.exe` or NSSM; there is no known deployment that way
   either.) The same 0.14.1 changelog and `server-admin.md` already tell users the Windows
   server is not a supported deployment, citing this ADR.
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

Because there are no deployments to strand (Context §2 — and the 0.14.x `YuzuServerSetup` installer
created none, since its service cannot start, #5325), the Windows/macOS server is removed outright
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
macOS — including agent-only developers) into a **Meson feature option** (under a new option name;
see the Update at the end of this decision) with the semantics:

- `auto` (default) on a **Linux target** → build the server; on a **non-Linux target** → silently
  **disabled** with an informational message. A plain checkout configures agent-only off-Linux with
  no error.
- `enabled` on a non-Linux target → **hard configure error** with a clear message ("the Yuzu server
  is Linux-only; see ADR-0035").
- `disabled` → never build the server.

The check keys on `host_machine.system() == 'linux'` (the *target*), so a **Linux-target cross build
from any build machine stays legal** — matching "the server *runs* on Linux", not "you may only
build it on Linux". The same PR updates `scripts/setup.sh`, the CLAUDE.md quickstarts, and the docs
that pass `-Dbuild_server=false` (to the feature option's `disabled` value, under the option name the
Update below requires).

The Meson guard alone is not enough: since 5b903db26 (#4295) `vcpkg.json` lists `"default-features": ["server",
"tests"]`, so a plain `vcpkg install` on Windows or macOS still builds the server-only dependencies
(libpq, xmlsec, drogon) even when Meson then skips the server. The same PR therefore also makes the
non-Linux paths install agent dependencies only — either `scripts/setup.sh` and the Windows/macOS CI
legs pass `--x-no-default-features --x-feature=tests` off Linux, or the manifest default drops
`server` and the Linux paths opt in. The choice is the implementing PR's, recorded there.

**Update (2026-11-10, ladder step 1):** the feature option takes a NEW name (for example `server`,
so `-Dserver=disabled`); it does not retype `build_server`. Retyping the existing boolean
`build_server` as a feature breaks existing build dirs, measured with Meson 1.11.1:
`meson setup --reconfigure` fails on any build dir that stored the boolean, whether or not
`-Dbuild_server=disabled` is passed, and `meson setup --wipe` fails on a build dir that was
configured with an explicit `-Dbuild_server=<bool>`. Renaming the persistent CI build dirs would
cover CI only: it does not reach developer trees, because `scripts/setup.sh` reuses an existing
build dir via `--reconfigure`. A new option name avoids the retype everywhere, so it is the
recommendation outright. `build_server` then stays a boolean (deprecated, then removed) or is
deleted in the same change; the implementing PR records which.

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

This change also carries a reciprocal `Update (2026-11-10)` note at ADR-0031's Gate G10, so a reader
of ADR-0031 sees the amendment (the ADR-0006 "Update" precedent). Issue #2701 ("ADR-0031 G10: prove
Drogon…") currently says to preserve the Windows MSVC and macOS Apple Clang server matrix and that
#2323 "does not relax this requirement"; on acceptance its platform-matrix clause narrows to Linux
and its dependency on #2185 (the Windows CI leg) drops for G10. A Drogon build canary already exists
(`yuzu_drogon_canary`, `server/core/meson.build`, WS-B1) and today builds on every server leg, Wee
Tam included; it is `build_server`-gated, so ladder step 1 makes it Linux-only with no further
wiring.

## Considered and rejected

- **A. Keep the Windows/macOS server (status quo).** Rejected: recurring CI cost and flake
  (grpc/libpq static-linkage, slow Postgres server tests on two endpoint-OS legs) for a
  configuration with zero known deployments and no demand. The value delivered does not justify the
  maintenance tax.
- **B. Deprecate with a one-or-two-release sunset window.** Rejected: a sunset window protects
  existing users, and there are none (pre-1.0, no native server deployments). A sunset here is
  ceremony that prolongs the cost it is meant to retire. This held after 0.14.1 shipped a Windows
  server installer, because that installer's service cannot start (#5325; Context §2). Evidence that
  any `YuzuServerSetup` install ever ran as a service would reopen this option. Instead of a sunset,
  ladder step 2 carries a release-notes removal notice.
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
(the `custom_target('gateway', …)` in the root `meson.build`), **independent of `build_server`**. It therefore continues to compile on the
Windows agent CI leg with no extra wiring, and we **keep** this Windows compile as a cheap
portability canary for the Erlang code — it ships nothing and costs only the rebar3-on-Windows
toolchain already provisioned on Wee Tam. It is a **known-fragile, non-blocking** canary (CodeQL
notes the target "may fail on Windows" in `codeql.yml`'s Windows build step) — it must stay `continue-on-error` /
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
- **`build_agent` stays a boolean; the server switch becomes a feature** (Decision 4). `-Dbuild_server=false`
  becomes the feature option's `disabled` value across CI and docs, under a NEW option name such as
  `-Dserver=disabled` (Decision 4's Update, 2026-11-10) — the CI change is mostly flipping/renaming
  an option plus the configure guard, not new build plumbing.

## Implementation ladder (follow-up PRs — not this ADR)

1. **CI** — make the Windows and macOS legs agent-only: in `ci.yml` set the server feature to
   `disabled`. On Wee Tam drop `server-nonpg`, `server-checks`, `server-pg` and the
   `server pg smoke` entry, the `yuzu_pg_canary.exe` provenance step and Postgres provisioning. On
   the macOS leg drop the server build, the non-`[pg]` `--suite server` run, the
   `yuzu_pg_canary` static-libpq check and the "skipped on macOS" placeholder step (there is no
   macOS Postgres provisioning left to remove, #2394). In `docs/ci-architecture.md`, rewrite the
   "#3508 … deliberately NOT adopted" paragraph and the "PG coverage by platform" table: their
   stated reason ("ADR-0035 is `proposed`, not accepted") lapses on acceptance. Drop the Windows
   server build row in
   `codeql.yml`; retire or re-scope `instructions-windows-validate.yml` (its live `yuzu-server.exe`
   smoke rig is server-only). `nightly.yml` Windows ASan is already agent-only — no change. Sweep
   `pre-release.yml` (its Windows/macOS install jobs are already agent-installer-only, but the
   artifact-name change reaches it). Keep the (non-blocking) gateway canary. Prune now-unused Windows
   server cache scopes (`cache-prune.yml`).

   *Status: done — #7499 (merged 2026-11-11).* As
   implemented: the Windows and macOS legs of `ci.yml` pass `-Dbuild_server=false` (the boolean;
   the feature option is step 3) and drop every item listed above for them, and the Windows leg
   moves to `build-windows-agent-{debug,release}` and deletes the old dirs, so a branch cut
   before this change never shares a stored `build_server` value with one cut after it.
   `codeql.yml`'s Windows row is kept, agent-only (`-Dbuild_server=false`) rather than dropped,
   because it is the only CodeQL coverage of the agent's Windows code.
   `instructions-windows-validate.yml` is deleted. `vcpkg install` is unchanged (the full
   manifest, server ports included) until step 3, which changes it on every Windows and macOS
   workflow at once. `cache-prune.yml` has no Windows-server-only scope to prune: its Windows
   `sweep-test-databases.sh` step goes with Wee Tam's Postgres in step 4, and until then
   `Assert-Toolchain.ps1` still health-checks those clusters in the Windows job.
   `pre-release.yml` needs no change at all: it never referenced the Windows or macOS
   archives (it checks only the Linux and gateway tarballs).

   **Release ordering (owner decision, 2026-11-10; satisfied by step 2):** step 2 MUST merge before the next release
   tag, or that release MUST explicitly accept shipping a Windows/macOS server that CI never
   built or tested before tagging, recorded as a `changelog.d` caveat fragment merged through a
   reviewed PR (whose description names the approver and the date) and promoted before tagging,
   so `release.yml` carries the caveat into that release's notes (the exact form
   and the `release.yml` check are in
   `.claude/skills/release/SKILL.md`, Phase 0 preflight). From step 1 on, CI no longer compiles
   or tests the Windows or macOS server, but `release.yml` still builds and ships it until step 2.
   If a Windows or macOS server compile break surfaces at release time before step 2, the remedy
   is to land step 2 (drop the server from those release jobs), not to patch server code for an
   unsupported platform.
2. **Release + rename blast radius** — stop building the server in `release.yml`'s Windows and
   macOS jobs (`-Dbuild_server=false` on their configure; remove their server `--help` smoke tests,
   `yuzu-server.exe` from the Windows signing set, and `build-macos/yuzu-server` from the macOS
   codesign loop and notarization zip) and remove it from their staging (incl. `install-server-postgres.sh` from the macOS
   tarball), so the `/release` preflight grep goes empty; delete the
   `YuzuServerSetup` / `deploy/packaging/windows/yuzu-server.iss` path; rename the Windows/macOS
   archives to their agent-only names and update **every** consumer: `scripts/check-release-artifacts.sh`
   (its `REQUIRED_ARCHIVES` list **and** the `.cdx.json`/`.spdx.json` SBOM name expectations, `SBOM_BASES`), the SBOM artifact
   names + provenance-attestation subjects in `release.yml`, `.claude/skills/release/SKILL.md`,
   `.codex/skills/release/SKILL.md`, `docs/user-manual/release-verification.md`, and
   `scripts/build-agent-bundle.sh`. Update the release-notes platform matrix (server row → Linux-only)
   and the platform-archives table. Replace the `YuzuServerSetup-*.exe` release-notes copy with a
   removal notice ("`YuzuServerSetup-*.exe` is discontinued; use the container image or the Linux
   packages"), remove the Windows server runbook from `docs/user-manual/server-admin.md`, and close
   #5325 and #1835 as resolved by removal.

   *Status: done — #7523.* As implemented, with these deviations and
   additions:
   - **The Windows DLL sweep is unchanged.** `release.yml` copies every DLL in
     `vcpkg_installed/x64-windows/bin`, and that tree keeps the server ports until step 3, so the
     agent archive still carries `libpq.dll` and the other server-port DLLs until step 3.
     Pruning by a hand-written list, proven on no runner, was judged riskier than one more
     release with unused DLLs (plan review, 2026-11-11). Instead a new, gating step extracts the
     archive, checks it holds every plugin DLL the build produced and no `yuzu-server.exe`, and
     runs `yuzu-agent.exe --help` with `PATH` cut to the Windows directories, so a DLL the agent
     or its core library imports at load time and the archive lacks fails the job before the
     installers are built or anything is attested or published. It does not cover DLLs only a
     plugin imports, or the MSVC runtime, which the runner supplies from System32.
   - **The platform SBOMs over-list, and step 3 does not fully fix that.** Both the Windows and
     macOS SBOMs are generated with `path: .`, the whole workspace (vcpkg's ports tree and build
     trees included), so they list PostgreSQL client libraries and other components the agent
     archive does not ship or load (verified against the v0.15.0 SBOMs). That is pre-existing; the
     release notes, `docs/user-manual/release-verification.md` and `upgrading.md` disclose it.
   - **The macOS "Notarize binaries" step** now reads the notarization status and fails unless it is
     `Accepted`. Like the rest of macOS signing it is dormant until a signing secret is set.
   - **The macOS codesign and notarization steps** pointed at `build-macos/yuzu-server` and
     `build-macos/yuzu-agent`, paths that never existed (they never ran: no signing secret is
     set). The server line is gone and the agent path is now `build-macos/agents/core/yuzu-agent`.
   - **The in-archive top-level directory** is renamed with the archive
     (`yuzu-agent-<version>-{windows-x64,macos-arm64}`).
   - **`scripts/build-agent-bundle.sh`** accepts either archive name, so a hand-run against a tag
     cut before this change still works.
   - **`build-installer.sh`** builds the agent installer only; `--target server|all` is refused.
   - **The `/release` preflight's hand check** is replaced by `tests/test_release_agent_only.py`
     (Docs Lint and `meson test`), which fails if a Windows or macOS server build, `YuzuServerSetup`
     or an old archive name comes back, and if the archive names in `release.yml`,
     `scripts/check-release-artifacts.sh` and `scripts/build-agent-bundle.sh` disagree.
   - **Also done here, ahead of step 5:** the release notes' "Windows (server + agent)" and "macOS
     (server + agent)" archive rows, and the user manual's "Supported Platforms" table (Server is
     now "No" on Windows and macOS). The retirement guidance for an existing Windows or macOS
     server ("Moving a Windows or macOS server to Linux" in `docs/user-manual/server-admin.md`)
     and an `upgrading.md` breaking-change section land here too. That guidance is a fresh Linux
     deployment with agents enrolled as new installations, not a data migration: the CA store records the CA key's
     absolute path (`ca_store.ca_root.key_ref`), and a Linux server refuses a key outside its own
     CA directory, so a Windows server's restored database could not sign agent certificates or
     publish CRLs. Carrying data over would need a server change; none is planned. Re-pointing an
     already-enrolled agent or gateway at a different server has no supported procedure either,
     so the guidance treats them as new installations (follow-ups #7524, and #7525 for a Windows agent's non-default CA).
   - **#5325 and #1835** are closed as resolved by removal when this change merges.
   - Proof without an RC (owner decision, 2026-11-11): the static pins, plus a Windows rehearsal of
     the agent-only build, packaging and installer on a build box. The first stable tag after this
     change is the first real run of the changed jobs.
3. **Build guard** — implement Decision 4: convert `build_server` to a feature option, key the guard
   on `host_machine.system()`, make the non-Linux `vcpkg install` paths skip the `server` feature,
   and update `scripts/setup.sh`, the CLAUDE.md quickstarts, and any docs passing
   `-Dbuild_server=false` in the same PR. The feature option takes a NEW option name (for example
   `server`), not a retype of `build_server`: see Decision 4's **Update (2026-11-10, ladder step
   1)** for why. Also update `tests/shell/test_build_examples_gating.sh` (suite `platform`, runs on
   the Windows and macOS legs): it configures against the vcpkg tree with the default server
   switch, so once the server ports leave the Windows/macOS install it must pass
   `-Dbuild_server=false` (or the new option's `disabled`) off Linux. The rename also reaches the
   two pins that assert the switch: `scripts/ci/test_runner_health_check.py` (`ci.yml`, step 1)
   and `tests/test_release_agent_only.py` (`release.yml`, step 2). This includes `release.yml`'s
   `build-windows` and `build-macos` jobs: verify afterwards that the Windows agent archive no
   longer carries `libpq.dll` or the other server-port DLLs.

   *Status: done — #TBD.* As implemented, with these deviations and additions:
   - **Option name: `server`** (feature, default `auto`). `auto` builds the server on a Linux
     target (judged by `host_machine.system()` lowercased, because Meson keeps a cross file's
     `system = 'Linux'` verbatim; so a Linux-target cross build from any host stays legal) and is off for any other target; `-Dserver=enabled` on a non-Linux target is a
     configure error carrying the ADR message; `disabled` never builds it.
   - **`build_server` is KEPT, deprecated** (`deprecated: true`, default `true`), still honoured
     as an extra off-switch, and `-Dserver=enabled` together with a passed or stored
     `build_server=false` is an error. Deleting it would break every build dir and branch that stored or passes it;
     its removal is owned by step 4, with the build-dir wipe (step 4's text now says so). On
     Linux, a server turned off only by the deprecated boolean says so at configure.
   - **vcpkg choice.** The manifest default is unchanged (`server` and `tests` stay default
     features, so Linux and the images keep the full set). Non-Linux paths opt out instead:
     `ci.yml` Windows/macOS, `nightly.yml` Windows ASan and `codeql.yml` Windows install with
     `--x-no-default-features --x-feature=tests`; `release.yml`'s Windows and macOS jobs with
     `--x-no-default-features` (no tests); `scripts/setup.sh` on a Windows or macOS host without
     a cross file always passes `--x-no-default-features --x-feature=tests` (a plain run after
     `--tests` must not drop Catch2 from a build dir that stored `build_tests=true`; pinned).
     The agent Dockerfiles use `-Dserver=disabled`. Each Wee Tam runner keeps its own persistent
     `vcpkg_installed/x64-windows` tree; the CI, nightly and CodeQL Windows jobs share the
     `+tests` agent-only profile on it, and `release.yml` (a clean checkout, no `tests`) installs
     its own. The reverse reconcile (a full tree down to agent-only) was exercised on Windows in
     the rehearsal below (one non-healing case: a kill while removing libpq); it has not been
     exercised on macOS.
   - **No server switch in CI.** The Windows and macOS `ci.yml` legs, nightly Windows ASan and
     CodeQL Windows pass no `-Dserver` at all (`auto` is already off there), because a stored
     non-default option in a persistent build dir breaks an older branch's reconfigure.
     `release.yml` is the exception and passes `-Dserver=disabled`, as it builds fresh.
   - **Deviation: `tests/shell/test_build_examples_gating.sh` passes no off-switch.** The text
     above said it must pass `-Dbuild_server=false` or `disabled`; with `auto` it configures
     agent-only off Linux on its own, so adding a flag would test less. Instead, off Linux it now
     asserts from the introspected targets that no `yuzu-server` target exists.
   - **Added: `release.yml` refuses server-port DLLs.** The "Verify the agent runs from the
     packaged archive" step fails if the archive holds a `libpq*`, `libecpg*`, `libpgtypes*`, `drogon*`,
     `trantor*`, `jsoncpp*` or `*xmlsec*` DLL (the nine DLLs a full x64-windows vcpkg tree has
     and an agent-only one lacks, measured: drogon, jsoncpp, libecpg, libecpg_compat,
     libpgtypes, libpq, libxmlsec1, libxmlsec1-openssl, trantor), so the "verify afterwards" instruction above is a permanent
     gate, pinned (with mutants) in `tests/test_release_agent_only.py`. This supersedes step 2's
     note that the DLL sweep was left unchanged.
   - **Not yet verified.** The release-time DLL refusal has never run on a real release (it
     ran in the Windows rehearsal below, which is not a release), nothing was run on macOS
     (no box), and the added publish wait below is untimed. If the refusal fails on
     a release tag, no image is pushed (the build jobs' attestations and workflow artifacts are
     still recorded): `docker-publish`, `docker-publish-chisel` and
     `docker-publish-postgres` all need `build-windows` and `build-macos` (UP-12, pinned in
     `tests/test_release_agent_only.py`), so a failed agent packaging step pushes no versioned
     image. The first release tag after this change (an RC by plan) has to confirm the added wait
     (the images now start after the slowest agent build, ~40 min).
   - **Release publish coupling (owner decision, 2026-11-12; wording confirmed by the owner the
     same day).** The three image-publish jobs (`docker-publish`, `docker-publish-chisel`,
     `docker-publish-postgres`) need `build-windows` and `build-macos`, and
     `docker-publish-postgres` also needs `build-linux` and `build-gateway` (it needs no build
     as an input; the jobs are success gates). Why: no `:X.Y.Z` image may exist for a release whose
     agent packaging refused (UP-12). Costs: the images start only after the slowest agent build
     (~40 min, untimed until an RC), and a failed or cancelled Windows or macOS build blocks every
     image and the GitHub Release. Recovery: fix the cause and re-tag, or "Re-run failed jobs" on
     the newest run for the tag (a server-DLL refusal is deterministic, so re-running without
     fixing the Wee Tam vcpkg tree fails the same way). There is no sanctioned images-only publish
     path today (tracked separately).
   - **Interim gap until step 5: no native server stack on macOS.** `scripts/start-UAT.sh`
     and the native-stack phases of `/test` need a server binary, which macOS no longer
     builds; run the Linux stack (containers) instead.
   - Pins: `tests/test_server_feature_option.py` (new: lexical pins with mutants, a real
     configure for Windows, macOS and Linux targets, and the `setup.sh` / gating pins),
     `tests/test_release_agent_only.py` and `scripts/ci/test_runner_health_check.py` move to the
     new switch and the install opt-out.
   - Proof: static pins plus a Windows rehearsal on a build box (not a CI run, not a release;
     the first release tag after this change, an RC by plan, is the first real run of the changed
     release jobs).
     Rehearsal (2026-11-12, Windows 11 build box, MSVC 19.44, Meson 1.11.1, pwsh 7.6, scratch
     clones and a scratch vcpkg copy and binary cache; workflow step bodies extracted from the
     YAML, never retyped):
     - `ci.yml`'s Windows install, configure (no server switch: "Server: off", no server
       target) and build pass; `meson test --suite agent` 19/19. `-Dserver=enabled` is refused
       with the ADR-0035 message. `release.yml`'s install (none of the nine server DLLs),
       `-Dserver=disabled` configure and build pass, with no `yuzu-server.exe`.
     - The archive refusal, run on a real packaged zip under both a plain `pwsh -File` and the
       Actions template: a clean archive passes and `yuzu-agent.exe --help` runs; `bin\libpq.dll`,
       a nested `xmlsec1-openssl.dll` plus `bin\LIBPQ.DLL`, and `libecpg.dll` plus
       `libpgtypes.dll` alone are each refused, naming every planted file, before `--help`.
       Without `-Recurse` the refusal never fires (the reason the pin keeps it).
     - vcpkg reconcile in place, both directions, with `scripts/setup.sh`: full to agent-only
       removes the nine DLLs; agent-only to full restores them; killing vcpkg during a
       binary-cache restore or during `Installing libpq` converges on the next run; the agent
       builds and `--suite agent` passes in both directions; a pre-step-3 checkout with no
       re-install fails its configure naming libpq, and its `setup.sh` fixes it. One gap: a
       kill while vcpkg is REMOVING libpq (full to agent-only) leaves libpq `purge ok
       half-installed` with part of its files on disk, and re-running the agent-only install
       does not finish the purge (3 of 3). `libpq.dll` was already gone each time, a
       pre-step-3 build still fails loudly (a debug build at configure, measured; a release
       build likely at compile, since `lib/libpq.lib` survives and `include/libpq-fe.h` does
       not), and the archive refusal catches any surviving
       DLL; the remedy is to delete `vcpkg_installed` (or run a full install) and re-run
       `setup.sh` (`docs/windows-build.md`).
     - Persistent build dirs alternated between this change and its parent (`ci.yml`'s
       `build-windows-agent-debug`, and the `build-windows-asan` configure with
       `-Dbuild_server=false`): every reconfigure and build passes without a wipe. A
       pre-step-3 checkout reconfiguring a step-3 dir prints Meson's "build_server is
       deprecated" notice and drops the stored `server` value (harmless; step 4 must allow
       for it).
4. **Code + build/CI plumbing** — remove server-side `_WIN32` / `__APPLE__`-specific branches under
   `server/core/` (retain POSIX/Linux; do not disturb `agents/shared/` or `sdk/`, which stay
   cross-platform); and remove the plumbing that exists only for the non-Linux server: the
   `meson.build` Windows libpq branch (incl. the `_vcpkg_lib_win` CRT-mismatch note), the libpq
   link-provenance canary steps in `ci.yml` (Windows DLL-import + macOS static variants), Postgres
   provisioning for server tests on the Wee Tam and macOS legs, the CLAUDE.md vcpkg libpq-DLL
   paragraph, and the server-dep entries in `deploy/windows/README.md` / `toolchain-contract.json`
   (its Postgres pin). Remove only the libpq branch: CLAUDE.md's "Windows grpc/protobuf/abseil is
   load-bearing — both halves" rule survives, because the agent still links that stack.
   Also in this step: **remove the deprecated `build_server` boolean** that step 3 kept declared
   (`meson.options`, its two reads in `meson.build`, and the pins in
   `tests/test_server_feature_option.py`). Deleting it makes Meson refuse to reconfigure any
   build dir that stored it ("Unknown options", even with `--wipe`), so this is a build-dir
   delete-or-rename event (`rm -rf <dir>`; `--wipe` replays the stored options and does not
   help) on every persistent dir (Wee Tam's, the macOS and Linux runners', and
   developers' `build-*`), done together with the Wee Tam deprovisioning. `main`'s nightly still passes
   `-Dbuild_server=false` until `main` carries step 3, so delete a persistent dir only once
   the branch that removes the option is the one its jobs build. (Measured in the step-3
   rehearsal: a branch that still declares the option, reconfiguring a dir that stored the
   step-3 `server` value, drops it silently and prints Meson's deprecation notice.)
5. **Docs + dev workflow** — retire the server sections of `docs/windows-build.md`; scope
   `docs/darwin-compat.md` to the agent and **document the replacement macOS server dev workflow**
   (Linux builder container / VM / Docker image) and the `/test` platform-asymmetry
   (`.claude/skills/test/SKILL.md`); make `docs/uat-environment.md`'s native rig Linux-only; update
   `docs/os-capability-matrix.md`, `docs/ci-architecture.md`, `docs/capability-map.md`, and the
   CLAUDE.md build sections; (the user manual's "Supported Platforms" table and the
   "(server + agent)" release-notes lines in `release.yml` were done in step 2); fix the Windows-server behaviour
   notes in `docs/user-manual/authentication.md` and `tls.md`; add a `changelog.d/` fragment; add release-note guidance pointing any
   former Windows/macOS-server curiosity at the Docker image / Linux binary.

## Security note (for Gate 6)

Endpoint platforms no longer receive a control-plane binary in their artifact — this removes the
"someone accidentally ran the server on a managed endpoint" footgun and the `YuzuServerSetup` patch
surface from Windows/macOS. The enrollment / PKI story (Register / ProxyRegister, the "never
internet-expose `:50051`" rule) is OS-agnostic and **unchanged** by this ADR — the agent's transport
and trust model are identical whether or not a server can be built on the same OS.
