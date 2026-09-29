# Yuzu Codex Guide

Use repo-local Codex skills first. Start with the narrowest matching skill and combine skills when a change crosses domains.

## Route By Task

- `governance`: run `/governance <range>` or full governance review. Produces a change summary, bounded review fanout, a governance ledger, and a blocking decision.
- `test`: run `/test`, `/test --quick`, `/test --full`, `/test --instructions`, or quarantine-mode validation. Preserves the test-runs DB and UAT lifetime rules.
- `tdd`: build a feature or fix test-first with Yuzu's public-interface, tracer-bullet red-green-refactor loop.
- `diagnose`: debug failures, flakes, and performance regressions through reproduce, minimize, hypothesize, instrument, fix, and regression-test.
- `grill-with-docs`: interrogate plans against Yuzu's domain language, `CONTEXT.md`, code, and ADRs; create ADRs lazily in `docs/adr/` only when warranted.
- `yuzu-build`: configure, compile, test, choose suites, or recover a broken build directory.
- `yuzu-meson`: edit any `meson.build`, change source lists, adjust dependencies, or update build graph behavior.
- `yuzu-proto`: edit `.proto` files, `proto/gen_proto.py`, `proto/meson.build`, `proto/buf.yaml`, or `gateway/priv/proto/**`.
- `yuzu-plugin-abi`: change `sdk/include/yuzu/plugin.h`, `plugin.hpp`, plugin descriptors, `plugin_loader.cpp`, or plugin action contracts.
- `yuzu-windows-msvc`: handle Windows MSYS2 + MSVC builds, `setup_msvc_env.sh`, `triplets/x64-windows.cmake`, Windows CI, or the Windows-specific protobuf/grpc wiring in root `meson.build`.

## Operational Workflows

- `/governance` may use Codex subagents because the slash command is an explicit request for delegated review. Keep review agents bounded, read-only, and role-specific. Store role prompts in `.codex/skills/governance/SKILL.md`; do not create `.codex/agents`.
- C++ governance requires a Resource Ledger in Gate 1 plus `cpp-expert` and `cpp-safety` in Gate 3 for any C++ diff. The ledger names every new or modified raw resource, owner type, acquisition, release, transfer behavior, and failure cleanup. New manual cleanup in touched C++ code is blocking unless wrapped by RAII/scope guard or explicitly justified.
- `/test` is the high-level validation orchestrator. It may run long-lived scripts and must preserve `~/.local/share/yuzu/test-runs.db` behavior. Do not stop the native UAT stack at the end of default/full test runs unless the user explicitly asks.
- `/tdd` and `/diagnose` should read `CONTEXT.md` and relevant ADRs before naming domain concepts or selecting a regression seam.
- `/grill-with-docs` is the ADR-adjacent workflow. ADRs live in `docs/adr/` and are created lazily only for hard-to-reverse, surprising, real trade-off decisions.

## Repo Invariants

- Meson is the only project build system.
- Use `./scripts/setup.sh` for canonical setup. Default build directories are `build-linux`, `build-windows`, and `build-macos`.
- Treat `proto/yuzu/**` as the canonical wire contract.
- Treat `gateway/priv/proto/**` as a gateway mirror that must stay synced with canonical proto sources.
- Treat `sdk/include/yuzu/plugin.h` as the stable C ABI boundary.
- On Windows, use MSYS2 bash plus `source ./setup_msvc_env.sh`. If the build touches the gateway custom target, also `source scripts/ensure-erlang.sh`.
- Never use `vcvars64.bat`.
- Never switch Windows protobuf/grpc back to Meson's cmake dependency path without reviewing the Windows-specific rules in root `meson.build` and `docs/windows-build.md`.

## Codex Versus Claude

- Codex setup is repo-local under `.codex` plus `CODEX.md`, `CONTEXT.md`, and `docs/agents/**`.
- Claude files are source material for parity but remain unchanged by this setup. Do not mutate `.claude/**` or `CLAUDE.md` unless the user asks for a Claude workflow change.
- Codex uses the runtime sandbox and escalation prompts for command safety. Do not clone `.claude/settings.json` into a Codex allowlist.

## Domain Docs

- This repo uses a single-context layout: `CONTEXT.md` at the root and ADRs in `docs/adr/`.
- `docs/agents/issue-standard.md` is the binding standard for every `gh issue` operation (ADR-3001): dedupe before filing, four body sections, three-axis labels, and never-close rules for `security`/`do-not-close` issues.
- `docs/agents/issue-tracker.md` records GitHub Issues at `github.com/DevNullLtd/Yuzu` (command crib).
- `docs/agents/triage-labels.md` records the full label taxonomy, including the canonical triage mapping.
- `docs/agents/domain.md` records how engineering skills consume context and ADRs.

## Validation Defaults

- Build graph or source-list change: `meson compile -C <builddir>`
- Proto change: `buf lint proto`, `buf breaking proto --against '.git#subdir=proto,ref=origin/main'` when history is available, then rebuild consumers
- ABI or descriptor change: run targeted agent/plugin tests, especially descriptor and loader coverage
- Prefer `meson test -C <builddir> --suite <suite> --print-errorlogs` over broad runs when the change is scoped

## Read On Demand

- Build entrypoint: `scripts/setup.sh`
- Windows flow: `docs/windows-build.md`, `setup_msvc_env.sh`
- Proto codegen: `proto/meson.build`, `proto/gen_proto.py`, `gateway/rebar.config`
- ABI boundary: `sdk/include/yuzu/plugin.h`, `sdk/include/yuzu/plugin.hpp`, `agents/core/src/plugin_loader.cpp`
- CI behavior: `.github/workflows/ci.yml`
