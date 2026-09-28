# Erlang Gateway — Build & Quality

The gateway (`gateway/`) is a standalone rebar3 project. It compiles independently from the C++ codebase.

> Routed out of `CLAUDE.md`. The `gateway-erlang` agent loads this doc on any `gateway/` or `*.erl` change. For routine runs, prefer the `/gateway-eunit` and `/gateway-dialyzer` skills — they bundle the toolchain activation, the `--dir` flag, and result interpretation.

## Build & verify commands
```bash
cd gateway
rebar3 compile                               # compile
rebar3 eunit --dir apps/yuzu_gw/test         # unit tests (309 tests as of HA WS-4 #4555)
rebar3 dialyzer                              # type analysis — must be warning-free
rebar3 ct --dir apps/yuzu_gw/test --suite <name>  # Common Test
bash scripts/check-proto-codegen.sh          # F-3 (#1243): committed *_pb.erl in sync with priv/proto
```

**Proto codegen drift (`check-proto-codegen.sh`).** The gateway carries its own gpb-generated `apps/yuzu_gw/src/*_pb.erl` (separate from the server's protoc output). gpb modules are self-contained: change a `.proto` field but forget to regenerate and the gateway silently drops that field in transit (the PR5 enrollment-CSR field-drop bug). The guard regenerates with rebar.config's own pinned `gpb_opts` (read via `file:consult`, so it cannot drift from the build) into a temp dir and byte-diffs against the committed modules. It runs after `rebar3 compile` (needs `_build/gpb`) and is wired into the release workflow's gateway job. gpb is version-pinned (4.21.7) + `target_erlang_version` fixed, so the output is deterministic. To fix a drift failure: regenerate the modules and commit them.

**Always run `rebar3 dialyzer` after any Erlang change.** Compilation succeeding is not enough — dialyzer catches type violations, dead code, and missing dependencies that the compiler silently accepts. The project uses `warnings_as_errors` for compile but dialyzer warnings are separate.

**`--dir apps/yuzu_gw/test` is mandatory on `rebar3 eunit`**, not optional. Without it, rebar3 3.27 intersects discovered test modules against the `src/`-derived `modules` list in `yuzu_gw.app` and rejects every orphan test module (`*_tests` without a 1:1 src counterpart, every `*_SUITE` file, helpers) with `Module X not found in project` before running a single test. Tracked as **#337**; `scripts/run-tests.sh erlang-unit` already applies the workaround, but if you invoke rebar3 directly you must pass the flag yourself.

**`rebar3 eunit --module X` does NOT give you test isolation.** It runs the full `--dir` phase first, then the module filter, **in the same BEAM VM**. The second run inherits polluted state — meck mocks, registered names, leaked processes, send_after timers — from the first, so a passing filtered run does not prove the test is order-independent, and a failing filtered run may be failing because of pollution rather than the test itself. For real isolation, `rm -rf gateway/_build/test` between runs (forces a fresh BEAM) or drop into `erl -pa _build/test/lib/yuzu_gw/ebin -pa _build/test/lib/*/ebin` and call test functions directly. This gotcha wasted meaningful debugging time on #336.

## Toolchain activation (Erlang on PATH)

`rebar3` and the meson custom_target that wraps it both need `erl` on PATH. Forgetting to activate is the usual cause of phantom `.gateway_built` failures while the C++ targets succeed. Source the cross-platform helper before any gateway work and verify:

```bash
source scripts/ensure-erlang.sh           # default: latest 28.x
source scripts/ensure-erlang.sh 28.4.2    # exact pin
command -v erl >/dev/null || { echo "Erlang missing"; exit 1; }
```

The helper probes kerl → asdf → Homebrew (macOS) → MSYS2 installer (Windows) and **always returns 0** so it can't trip the caller's `set -e`. Callers MUST verify `command -v erl` themselves. Default version tracks `release.yml`'s `erlef/setup-beam` `otp-version` — bump both together. Native `cmd.exe`/PowerShell is out of scope; documented Windows build path is MSYS2 bash.

## Standing Erlang pitfalls

**Windows IDE builds: invalid handle / no Erlang output.** An IDE-launched
Ninja (CLion) can hand its children stdio handles the Erlang VM cannot use. The
VM then dies on its first write (`Writer crashed ('The handle is invalid.')`,
exit 127; console-mode errors such as `SetConsoleModeInitIn` have also been
reported) before printing anything, so the IDE shows a failed step with no
Erlang output. On Windows both gateway wrappers therefore never give the child
an inherited stdio handle: its stdout+stderr go to a pipe the wrapper owns (the
part that actually fixes this), and its stdin is null on a private hidden
console (`CREATE_NO_WINDOW`) — those two shared through
`scripts/erlang_toolchain.py`'s `windows_stdio_isolation()`.
`build_gateway.py` relays the pipe to its own stdout and tees it to
`<build dir>/meson-logs/yuzu_gateway_build.log`, which `ci.yml`'s Windows leg
uploads with the rest of `meson-logs/` on failure. (If that file is held open
by something that blocks deleting it, the run logs to a fresh
`yuzu_gateway_build.<random>.log` beside it instead; the failure message
always names the file actually written.) On a nonzero exit or a timeout
(`YUZU_GATEWAY_BUILD_TIMEOUT`, default 900 s) it names the command, the exit
code and that log. **If a CLion gateway build fails with no Erlang output, read
that log first.**

Two consequences to know. Because the child's console is invisible, git
credential prompts are disabled (`GIT_TERMINAL_PROMPT=0`,
`GCM_INTERACTIVE=never`): a cold `_build` fetching a git dependency behind an
authenticating proxy or with missing credentials fails fast with git's error
instead of prompting — set up credentials or proxy config beforehand. And do
**not** add `-noinput` to `ERL_FLAGS` for these wrappers: `ERL_FLAGS` reaches
every VM rebar3 starts, and `-noinput` breaks the `standard_io` `peer` nodes
the multinode eunit suite uses.

| Area | Issue |
|---|---|
| `ctx` dependency | `ctx:background/0` is used for grpcbox RPC calls. `ctx` is a transitive dep of `grpcbox` but must be listed in `yuzu_gw.app.src` `applications` since we call it directly — otherwise dialyzer can't find it in the PLT. **Rule: if you call a function from a transitive dependency, add it to the applications list.** |
| `-spec` contracts | If a function spec says `-spec f(map()) -> ok`, passing an atom like `f(some_atom)` compiles fine but dialyzer flags it. Always respect `-spec` contracts, even in catch/fallback paths. |
| Circuit breaker dead code | `on_success/1` and `on_failure/1` only receive states `closed` or `half_open` (never `open`, because `check_circuit/1` rejects before the RPC runs). Don't add catchall clauses for states that are structurally unreachable — dialyzer knows the type is fully covered. |
| `gpb` plugin warning | `Plugin gpb does not export init/1` is a benign warning from rebar3 — gpb is used via `grpc` config, not as a rebar3 plugin. Ignore it. |
| Stray `.beam` / crash dumps | `erl_crash.dump` and loose `.beam` files in the gateway root are artifacts. They should be gitignored or deleted, never committed. |
| Shutdown flush | During `stop/1`, `flush_sync/0` is the correct way to drain the heartbeat buffer. Do not fall back to `queue_heartbeat/1` with sentinel atoms — it violates the `map()` spec and would corrupt the buffer. If `flush_sync` fails, the process is already dead and the buffer is lost. |
| Canonical-name mock leak (#336 family) | If a test kills a registered gen_server and registers a throwaway mock under the same canonical name, cleanup must compare the pre-test pid with `whereis(Name)` at teardown and kill the replacement when they differ — for not-owned names too. Otherwise a later module's setup adopts the impostor via `{already_started, Pid}` and its first `gen_server:call` times out ("One or more tests were cancelled", platform-dependent via eunit module order). Reference fix: `yuzu_gw_health_nf_tests.erl` cleanup (commit 4375116c); root-cause leak tracked in #1363. |
