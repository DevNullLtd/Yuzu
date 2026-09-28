# Contributing to Yuzu

## License and Contributor License Agreement

Yuzu is dual-licensed:

- The **community edition** (everything outside the `enterprise/` directory) is
  [AGPL-3.0-or-later](LICENSE).
- The **enterprise edition** (`enterprise/`) is under a separate commercial
  license — see [`enterprise/LICENSE-ENTERPRISE.md`](enterprise/LICENSE-ENTERPRISE.md).

To preserve the ability to ship the same code under both licenses, **every
contributor must sign a Contributor License Agreement** ([CLA.md](CLA.md))
before their pull request can be merged. The CLA grants the project steward
the right to redistribute your contribution under both the AGPL and the
commercial license.

- **Individual contributors** — include `Signed-off-by: Your Name <email>` in
  each commit and add yourself to [CLA.md](CLA.md) by opening a pull request
  that appends your name to the "Signatories" section, or (once the CLA bot
  is live at `.github/workflows/cla.yml`) sign via the automated workflow on
  your first PR.
- **Corporate contributors** — contact the project steward (see
  [NOTICE](NOTICE)) to execute a corporate CLA covering all employees.

If you do not wish to sign the CLA, you may not contribute code, documentation,
or other materials to this repository. File an issue instead — the maintainers
can implement the idea under their own copyright.

## Code of Conduct

This project adopts the [Contributor Covenant](CODE_OF_CONDUCT.md) (v3.0). By
participating — as a human or an agentic worker acting on someone's behalf — you
are expected to uphold it. Report unacceptable behavior privately to the project
maintainer at nathan.dornbrook@gmail.com.

## Getting Started

> **Meson and Ninja are required — they are the project's only build toolchain.**
> Everything in this repo assumes both are installed and on your `PATH`:
> `scripts/setup.sh`, `meson compile` / `meson test`, the per-OS build
> directories, and the `/test` pre-commit pipeline all drive Meson + Ninja
> directly. **CMake is not an alternative build system** here — it is pulled in
> only as a Meson dependency-resolution method, never invoked to build. Without
> Meson + Ninja you cannot build, test, or run any of the tooling, so install
> them first (Meson 1.12.0, the pin in `requirements-ci.txt`; a recent Ninja)
> before following the steps below.

1. **Prerequisites**: Meson 1.12.0 (`requirements-ci.txt`), Ninja, CMake, a C++23 compiler, and vcpkg. See [CLAUDE.md](CLAUDE.md) for full build instructions.
2. **Clone and build**:
   ```bash
   git clone https://github.com/Tr3kkR/Yuzu.git && cd Yuzu
   ./scripts/setup.sh
   meson compile -C build-linux
   ```

## Agent and instruction files

`CLAUDE.md` and `AGENTS.md` are contents pages, not knowledge bases: they load into every agent
session, so anything added to them is paid on every session whether or not the work touches that
subject. Before adding to either — or to the routed-concern tables under `.claude/` — read
**`docs/instruction-file-standard.md`**. It gives the placement ladder (a hook, a header comment at
the site, a `docs/` file plus a routed-concern row, a routed-concern row alone, and only then an
instruction file) and the budget CI enforces.

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for how components interact.

See [`docs/roadmap.md`](docs/roadmap.md) for the development plan.

See [`docs/capability-map.md`](docs/capability-map.md) for the target feature set.

## Branch Naming

- `feature/<short-description>` for new functionality
- `fix/<short-description>` for bug fixes
- `fix/<finding-id>-<short-description>` for RC sprint findings (e.g., `fix/C1-gateway-tls`)

Branch from `dev` — all work merges into `dev`; `main` is release-only. Keep branches focused
on a single change.

## Erlang Gateway

The gateway (`gateway/`) is a standalone rebar3 project using Erlang/OTP. See `docs/erlang-gateway-blueprint.md` for the architecture.

- Run EUnit tests: `cd gateway && rebar3 eunit`
- Run Common Test: `cd gateway && rebar3 ct --dir apps/yuzu_gw/test`
- Always pass `--dir apps/yuzu_gw/test` with `--suite` flags
- Review all Erlang changes with the gateway-erlang agent (`.claude/agents/gateway-erlang.md`)

## MCP Server

The MCP server is embedded in the C++ server at `POST /mcp/v1/`. Changes to MCP tools, resources, or prompts are in `server/core/src/mcp_server.hpp` / `mcp_server.cpp`. Tests are in `tests/unit/server/test_mcp_server.cpp`.

## Governance

All code changes follow mandatory governance gates defined in `CLAUDE.md`. In summary: change summary, security + docs deep-dive, domain-triggered review, correctness & resilience analysis (happy-path + unhappy-path + consistency-auditor in parallel), chaos analysis (chaos-injector), all findings addressed before merge. See the Agent Team section in CLAUDE.md for the full workflow and gate definitions.

## Filing Issues

Issue filing, labelling, and closing follow the repo standard:
[`docs/agents/issue-standard.md`](docs/agents/issue-standard.md). The short version:

- **Search for duplicates before filing** — comment new evidence on an existing issue rather
  than filing a twin.
- One actionable outcome per issue, with Context / Evidence / Acceptance criteria / Origin
  sections in the body. (Reporting via the web templates? A description and reproduction steps
  are enough — triage fills in the rest; the full format binds the `gh`/agent path.)
- Every issue carries exactly one type label; every non-`roadmap` issue also carries one triage
  state (`roadmap` = parked scope: no triage state, no priority). Priority (`P0`/`P1`/`P2`)
  is a triage decision: set it if you have the context (agents and maintainers do);
  leave it off a drive-by report and triage will add it.
- **Never file an exploitable security vulnerability as a public issue.** Use
  [GitHub private vulnerability reporting](https://github.com/Tr3kkR/Yuzu/security/advisories/new)
  (see [SECURITY.md](SECURITY.md)). Public `security`-labelled issues are for hardening and
  defense-in-depth work only.
- A PR that resolves an issue says `Closes #N` in its body; partial work says `Relates to #N`
  and never uses a closing keyword.

## Pull Request Process

1. Ensure CI passes (builds on Linux, Windows, macOS, ARM64)
2. Run `clang-tidy` locally against changed files (the repo `.clang-tidy` config is picked up automatically)
3. Write a clear PR title and description using the PR template
4. Declare linked issues in the PR body: `Closes #N` for every issue the PR fully resolves;
   `Relates to #N` for partial work
5. Keep PRs small where possible; large features should be broken into incremental PRs

## Changelog

**Do not edit `CHANGELOG.md` in a PR** — direct edits to its `[Unreleased]`
section are rejected by the `Changelog fragments` CI check (they made every
second PR conflict and void its approvals). Instead, add **one new file**
describing your change:

```
changelog.d/<PR-or-issue-number>-<short-slug>.<section>.md
```

where `<section>` is one of `added`, `changed`, `deprecated`, `removed`,
`fixed`, `security`, and the body is the finished bullet (starting `- `)
exactly as it should read in the changelog. Fragments are assembled into
`CHANGELOG.md` at release time. Full convention (including guidance for AI
coding agents): [`changelog.d/README.md`](changelog.d/README.md). Changes with
no operator-visible effect (pure refactors, CI plumbing, test-only) can skip
the fragment.

## Coding Standards

The project follows C++23 conventions enforced by `.clang-tidy`:

- **Naming**: PascalCase classes, snake_case functions/variables, `k`-prefix constants, trailing `_` for private members
- **Error handling**: Use `std::expected<T, E>` — no exceptions in core code
- **Includes**: `#pragma once`, ordered STL → third-party → project
- **Strings**: Prefer `std::string_view` for parameters, `std::format` for formatting
- **Memory**: No raw `new`/`delete`; use smart pointers and RAII

See [CLAUDE.md](CLAUDE.md) for the complete coding conventions.

## Observability Standards

When adding new features:

- **Metrics**: Use Prometheus naming (`yuzu_server_*` / `yuzu_agent_*`) with consistent labels (`agent_id`, `plugin`, `method`, `status`)
- **Response schemas**: All instruction responses must declare typed columns (bool, int32, int64, string, datetime) for downstream analytics
- **Audit events**: Use the structured format: `{timestamp, principal, action, target_type, target_id, detail}`
- **Events**: Follow the common envelope: `{event_type, timestamp, source, payload}`

## Writing Plugins

Plugins use a stable C ABI (`sdk/include/yuzu/plugin.h`) with a C++ wrapper (`sdk/include/yuzu/plugin.hpp`).

1. Copy `agents/plugins/example/` as a starting point
2. Implement your plugin class using the `YUZU_PLUGIN_EXPORT` macro
3. Add a `meson.build` that builds a shared library
4. Register your plugin directory in the parent `meson.build`

See the existing plugins for patterns.

## Running Tests

```bash
./scripts/setup.sh --tests
meson test -C build-linux --print-errorlogs
```

Tests use [Catch2](https://github.com/catchorg/Catch2) and live in `tests/unit/`.

Tests that touch PostgreSQL are tagged `[pg]` and follow the recipe in step 7
of [`docs/postgres-store-playbook.md`](docs/postgres-store-playbook.md) —
fixtures, pre-migrated templates (`PgTestTemplate` + `YUZU_REQUIRE_PG_DB_TPL`
for store-behaviour tests), and the local one-liner
`docker run -d -e POSTGRES_USER=yuzu -e POSTGRES_PASSWORD=yuzu -e POSTGRES_DB=yuzu -p 5433:5432 postgres:18`
followed by `export YUZU_TEST_POSTGRES_DSN=postgresql://yuzu:yuzu@localhost:5433/yuzu`.
Skip-vs-fail contract: with `YUZU_TEST_POSTGRES_DSN` **unset**, `[pg]` tests
skip cleanly (no local database needed for non-Postgres work); **set but
broken**, they FAIL — deliberate, since CI guarantees a database, so an
unreachable DSN is breakage to surface, never to skip past.

## Build System

Meson is the sole build system. **Every time you add, remove, or rename a source file, update `meson.build` in the affected directory.** Do not use CMake as a build system (it exists only as a Meson dependency method).
