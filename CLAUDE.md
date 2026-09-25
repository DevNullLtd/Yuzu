# Yuzu — Claude Code Guide

**This file is a contents page, not a knowledge base.** Before adding anything, read
`docs/instruction-file-standard.md` — it defines where a rule belongs and why the default is *not
here*. This file, `AGENTS.md`, and the four routed-concern tables load into every session; each is
budgeted at 40,000 characters and capped at 48,000 (`tests/test_issue_docs.py`).

## What is Yuzu?

An agentic enterprise endpoint management platform — a single control plane where agentic colleagues
query, command, scan, patch, and enforce policy compliance on Windows/Linux/macOS fleets in real
time; an open-source alternative to commercial endpoint platforms, built in C++23.

Goal: match mature-platform capability (`docs/capability-map.md`) with modern architecture —
gRPC/Protobuf transport, Prometheus-native metrics, **PostgreSQL server substrate + SQLite on the
agent** (ADR-0006), and a compiler-stable plugin ABI.

## Target architecture

Operators (agentic AI · browser · REST API · automation) → **Yuzu Server** (REST API v1, HTMX
dashboard — server-rendered and **dark-theme-only**, Instruction Engine, Policy Engine, Response /
Scope / RBAC / Audit, Scheduler, `/metrics`, Management Groups) → gRPC/Protobuf/mTLS bidirectional
streaming → **Yuzu Agent** per endpoint (Plugin Host over a **stable C ABI**, Trigger Engine, SQLite
KV, hash-verified content distribution, user interaction on Windows, per-plugin metrics).

Full component reference: `docs/architecture.md`.

## Glossary — three meanings of "agent"

Use the disambiguated form in commits, PRs, and new docs:

- **Agent daemon** — the C++ binary in `agents/core/` on each managed endpoint (the usual meaning).
- **Governance agent** — the `.claude/agents/*.md` review actors run during `/governance`.
- **Agentic worker** — an external LLM-driven client driving Yuzu via MCP, REST, or the dashboard
  (`docs/agentic-first-principle.md`).

## Context discipline

Context is the scarce resource. Keep this thread lean; spend file-reading budget in subagents.

- **Search before reading.** Grep (it *is* ripgrep) honours `.gitignore`; Read / Glob / `find` do
  **not** — keep those out of build, vendored and generated trees (`*.pb.h/.cc`, `vcpkg_installed/`).
- **Delegate broad reads.** Unknown locations or many-file sweeps → an `Explore` (or
  `general-purpose`) subagent that returns conclusions, not file dumps.
- **Summarise and hand off proactively** — record files touched, facts learned, open questions, next
  command; then continue or spawn a fresh agent.
- **For code changes:** owning module → its tests → smallest coherent patch → targeted suite
  (`meson test -C build-<os> --suite <agent|server|tar>`) before the broad one.

## Agent team & governance

Specialized agents live in `.claude/agents/` (each declares its role, triggers, reference docs).
`workflow-orchestrator` owns the gate sequence; **`/governance <range>` is the entry point** — never
hand-run the gates.

Pipeline (8 gates): Change Summary + Resource Ledger → security-guardian + docs-writer →
domain-triggered (`cpp-expert` + `cpp-safety` on any C++) → happy-path + unhappy-path +
consistency-auditor → chaos-injector → compliance-officer + sre + enterprise-readiness → findings
addressed → iterate.

**Four standing rules, all catastrophic-if-violated:**

1. **Routed-concern triggers are UNCONDITIONAL** — open the tables and match row by row against the
   changed paths; never work from recall. Diff size decides WHICH agents, never WHETHER.
2. **Severity is DERIVED, not chosen** — from a TRIGGER, an IMPACT, every applicable EXPOSURE, and an
   EPISTEMIC STATUS. BLOCKING = the derived band is CRITICAL or HIGH. **Policy floors** gate as
   contract violations and bypass the derivation entirely.
3. **`docs-writer` owns WORDING; the DOMAIN agent owns TRUTH.** A comment contradicting the code is a
   truth finding at native severity. A *missing* required doc is a third category — a truth finding,
   never capped at NICE.
4. **Gate 8 re-runs every gate whose DOMAIN THE FIX DIFF TOUCHES** — not only those whose findings
   prompted the fix.

**All four rules, the ledger schema, the run-ledger contract, and the enumerated list of files that
merely POINT at them are defined ONCE — in `.claude/skills/governance/SKILL.md`.** This file loses on
conflict. The skill is read from your **working tree**, so a branch predating a change to it, or to
the routed-concern tables, silently runs the old pipeline; Step 0 opens with a per-file currency
check against `origin/dev`. The same rule governs any claim that a file or row is *absent* — verify
with `git show origin/dev:<path>`, never a working-tree `ls`.

## Routed concerns (read the doc, not this file)

One row per concern — catastrophic-if-violated invariants, routed doc, loading agents. Split across
four files solely for the per-file ceiling: the first holds platform/product/data/observability
concerns, the second auth, access-control, and request-admission chokepoints, the third the
security-posture plugins (the Wave 8 split), the fourth Forensics / per-user-software-data concerns
(the Wave 10 split). Same authority as this file.

@.claude/routed-concerns.md
@.claude/routed-concerns-access-control.md
@.claude/routed-concerns-security-posture.md
@.claude/routed-concerns-software-estate.md

## Domain entry points

Read the named doc **first** when the work touches that surface.

| Surface | Read first |
|---|---|
| macOS / Darwin (this instance is the compatibility guardian) | `docs/darwin-compat.md` |
| `gateway/` or any `*.erl` | `docs/erlang-gateway-build.md` (`/gateway-eunit`, `/gateway-dialyzer`) |
| Standing up or debugging the stack | `docs/uat-environment.md` — three mutually-exclusive rigs, all binding 8080 + 50051, so only one runs at a time |
| Build, vcpkg, test invocation | `docs/build-guide.md` |
| Unit-test helpers and fixtures | `docs/testing/unit-test-conventions.md` |
| Guardian / Guaranteed State | `docs/yuzu-guardian-design-v1.1.md` §24 (standing invariants), §9.1 (store schema) |
| Instruction Engine content plane | `docs/Instruction-Engine.md`; DSL `docs/yaml-dsl-spec.md`; tutorial `docs/getting-started.md` |
| CI matrix and gates | `docs/ci-architecture.md` |
| Enterprise / SOC 2 scope | `docs/enterprise-readiness-soc2-first-customer.md` (7 workstreams; Gate 6 agents evaluate every change against it) |
| Roadmap and capability map | `docs/roadmap.md`, `docs/capability-map.md` (headline progress figure is overstated) |
| Issues, labels, ADRs | `docs/agents/issue-standard.md`, `docs/agents/triage-labels.md`, `docs/adr/README.md` |

**ADR numbers are author-namespaced**, and `0016`/`0031` each host two accepted ADRs — cite those by
filename, never number alone.

## Build

Meson is the sole build system. **Every time you add, remove, or rename a source file, update
`meson.build` in the affected directory** and verify the build compiles.

```bash
./scripts/setup.sh                              # debug build, default compiler
./scripts/setup.sh --buildtype release --lto    # release + LTO
./scripts/setup.sh --tests                      # enable tests
```

**Per-OS build directories** — `build-linux` / `build-windows` / `build-macos`, so one tree built
from multiple hosts (WSL2 + native Windows + macOS) never clobbers itself. `setup.sh` auto-picks and
**refuses to reconfigure** a dir recorded for another host unless `--wipe`; it never auto-wipes.

**A manual `meson setup` needs two load-bearing flags, both pointing INTO THE TREE** —
`-Dcmake_prefix_path` *and* `-Dpkg_config_path` against a populated `vcpkg_installed/<triplet>`.
Neither is optional and neither substitutes for the other; an out-of-tree build dir needs both. The
full command, the measurements behind it, and the two failure modes it avoids are in
`docs/build-guide.md`.

**Windows:** `docs/windows-build.md` is the source of truth — two hard rules, **never `vcvars64.bat`**
and **never Clang from `C:\Program Files\LLVM\bin`** (must be cl.exe/MSVC), both enforced by hooks
(`.claude/hookify.block-vcvars64.local.md`, `.claude/hookify.warn-clang-windows-compiler.local.md`).
Provisioning a native runner: `deploy/windows/README.md`.

## Test

Every test target carries a `suite:` label so `--suite` filters directly:

```bash
meson test -C build-linux --suite <server|agent|tar> --print-errorlogs   # omit --suite for everything
```

Tests need `-Dbuild_tests=true`. Catch2 tag filtering and the per-component symlinks are in
`docs/build-guide.md`. **Do not remove `include_type: 'system'`** on a new dependency — load-bearing
for build-log readability, and hook-enforced
(`.claude/hookify.warn-drop-include-type-system.local.md`).

`/test` (`.claude/skills/test/SKILL.md`) is the single-command pre-commit/pre-push gate — compiles
HEAD, upgrades from the previous release, runs the standard surface, and persists every result and
timing to `~/.local/share/yuzu/test-runs.db`. Modes `--quick` / default / `--full`; history via
`bash scripts/test/test-db-query.sh`. CI history is separate and per runner — see
`docs/ci-architecture.md`.

## Project layout

```
agents/core/      Agent daemon (gRPC client, plugin loader, trigger engine)
agents/plugins/   50 plugins
server/core/      Server daemon (sessions, auth, dashboard, REST API, policy engine)
gateway/          Erlang/OTP gateway (standalone rebar3 project)
sdk/              Public SDK — stable C ABI (plugin.h) + C++23 wrapper
common/include/   Shared header-only root between server/core and agents/ (#2549)
proto/            Protobuf definitions (source of truth for wire protocol)
tests/unit/       Catch2 unit tests
docs/             Architecture docs, conventions, roadmap, capability map
```

**`common/include/` firewall (#2549) — pure decision code only:** no I/O, no store/wire types, no
server-trust-boundary authority. Two named exceptions, not a category: `shutdown_watcher.hpp` (#3007)
— a self-pipe fd, a dedicated watcher thread, and firewalled failure-path logging, with the
signal-handler side staying a single async-signal-safe `write()`; no store/wire access, no
trust-boundary authority. And `tls_policy.hpp` (#4722) — the shared TLS cipher policy: OpenSSL-only,
memory-only SSL_CTX calls plus ONE process-environment write (`GRPC_SSL_CIPHER_SUITES`), no file/socket
I/O, no store/wire types, no trust-boundary authority (it selects cipher suites; it authenticates
nobody). **A new I/O-bearing file here must be named in this annotation** (amend it
in the same change) — this does not open the root to I/O generally.

`proto/meson.build` invokes `proto/gen_proto.py`, which runs `protoc` and flattens `#include`
subdirectory prefixes (headers ship as `"common.pb.h"`), producing `yuzu_proto` via
`yuzu_proto_dep`. `build-ci` owns this codegen flow.

## vcpkg

Manifest `vcpkg.json`, pinned `builtin-baseline` (matches `vcpkgGitCommitId` in CI) — required by the
abseil `version>=` constraint, else vcpkg resolves against HEAD.

**Windows grpc/protobuf/abseil is load-bearing — both halves.** The `triplets/x64-windows.cmake`
static-linkage override AND meson's hand-wired `protobuf_dep`/`grpcpp_dep` are the only config
avoiding both LNK2038 and LNK2005 — **don't simplify either half** without reading
`.claude/agents/build-ci.md` (full #375 timeline). Linux/macOS unaffected.

Per-package rationale — OpenSSL required on every platform including Windows, the libpq DLL/CRT pick
(ADR-0006/0008), the catch2 platform filter — is in `docs/build-guide.md`.

## CI architecture

Three tiers: Tier 1 PR fast-path (`ci.yml`, <10 min), Tier 2 push to dev/main (full matrix), Tier 3
nightly (sanitizers + coverage; failure auto-opens `nightly-broken` and **no merge to main while it
is open**). `workflow_dispatch`/cron fire only once the workflow file is on `main`. Full reference:
`docs/ci-architecture.md`; `build-ci` owns the matrix, `cross-platform` the Windows/macOS specifics.

**Standing invariant — failure-path `if:` guards need an explicit status function.** An `if:`
containing no status-check function has an implicit `success()` ANDed on, so
`if: steps.X.outcome == 'failure'` is **unsatisfiable**. Every failure-path step must lead with
`failure() && …` or `failure() || cancelled()`. This silently skipped the nightly TSan gdb capture on
every red nightly for two months (#1038); `grep -n "outcome ==" .github/workflows/` before trusting
any failure-path guard.

**Release gates:** the `release:` job runs `scripts/check-compose-versions.sh` first, so **before
tagging** bump the `${YUZU_VERSION:-X.Y.Z}` default in every tracked compose file and verify locally
— else the job fails only after the full build matrix. A new compose file must be added to the
script's `FILES` array (auto-discovery is deliberately off). Details and the healthcheck-invariant
gate: `docs/ci-architecture.md` → "Gates outside the tier ladder".

## Changelog

**Never edit `CHANGELOG.md`** — add one fragment `changelog.d/<PR#>-<slug>.<section>.md` (body = the
finished `- ` bullet), assembled at release. A hook and the `Changelog fragments` CI job enforce
this; see `changelog.d/README.md`.

## Test conventions

Full contract: **`docs/testing/unit-test-conventions.md`**. The rules most often broken:

- Use `yuzu::test::unique_temp_path` / `TempDbFile` / `TempDir` from `tests/unit/test_helpers.hpp`,
  with a **`yuzu_test_` (underscore) prefix** so names match the Defender exclusion wildcard.
  **Never** salt uniqueness with `std::hash<std::thread::id>` or `std::chrono::steady_clock`
  (#473/#482) — both hook-enforced (`.claude/hookify.warn-temp-path-*.local.md`).
- **Standing invariant:** both self-hosted CI pools run 4 runner agents as ONE shared OS identity on
  ONE box (Windows "Wee Tam", Linux "Big Tam"). A fixed registry key, port, named object or path is a
  cross-JOB shared resource and two concurrent jobs collide (#1871). **Salt every such identifier**
  per-test/per-process, exactly like `unique_temp_path()`.
- `sqlite3_changes()` after `step()` on a shared FULLMUTEX connection is a data race — use
  `RETURNING` or the db mutex (#1033; hook-enforced).

## Product UI and plugin scope

**`frontend-design` is marketing-only.** Its varied light/dark aesthetic fits a standalone pitch
surface, not the **dark-theme-only** product. Use it on the Cedar & Vale deck
(`deploy/docker/cedar-vale/app/`) and future marketing pages. **Never on product UI** —
`server/core/src/*_ui.cpp`, `server/core/static/*`, including in-product fleet viz (`viz_*_ui.cpp`,
`yuzu-viz*.js` — product despite the name). Product UI stays HTMX-first, server-rendered,
dark-theme-only.

**No htmx `hx-on`.** Dashboard CSP is `script-src 'self' 'unsafe-inline'` (no `unsafe-eval`); htmx
compiles `hx-on:*` with `new Function()`, which CSP **blocks at runtime — the handler silently does
nothing**. Use a plain inline `onclick`/`oninput` calling a JS helper, or an `htmx:afterSettle` body
listener. Core `hx-*` attributes and the `HX-Trigger` header don't eval. Verify button-driven JS in a
headless browser for a CSP `pageerror`, not just that the page renders.

## Agent skills

**`/dev-team`** is committed project-level (`.claude/skills/dev-team/`) so every collaborator gets it
via git. Its fleet config, backends and defaults are documented in its own SKILL.md Step 0 — read
that, not a copy here. Invoke `/dev-team <task>`.

## Adding to this file

Don't, by default. `docs/instruction-file-standard.md` gives the placement ladder — a hookify rule, a
header comment at the site, a `docs/` file plus a routed-concern row, a routed-concern row alone, and
only then this file. Text belongs here only if it is cross-cutting, decision-grade, and needed
*before* you know which files you will touch.
