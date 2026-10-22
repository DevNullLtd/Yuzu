# Erlang Gateway — Build & Quality

The gateway (`gateway/`) is a standalone rebar3 project. It compiles independently from the C++ codebase.

> Routed out of `CLAUDE.md`. The `gateway-erlang` agent loads this doc on any `gateway/` or `*.erl` change. For routine runs, prefer the `/gateway-eunit` and `/gateway-dialyzer` skills — they bundle the toolchain activation, the `--dir` flag, and result interpretation.

## Build & verify commands
```bash
cd gateway
rebar3 compile                               # compile
rebar3 eunit --dir apps/yuzu_gw/test         # unit tests (count changes often; a clean run's summary line reports it)
rebar3 dialyzer                              # type analysis — must be warning-free
rebar3 ct --dir apps/yuzu_gw/test/ct --suite <name>  # Common Test (ct does not recurse: --dir apps/yuzu_gw/test finds no suites)
bash scripts/check-proto-codegen.sh          # F-3 (#1243): committed *_pb.erl in sync with priv/proto
```

**TLS test legs and `YUZU_REQUIRE_TLS_TESTS`.** The one-way-TLS and mutual-TLS legs of `yuzu_gw_heartbeat_conn_rpc_tests` mint throwaway certificates with the `openssl` CLI under `$TMPDIR`. The certificate tests in `yuzu_gw_authz_tests` and `yuzu_gw_authz_rpc_tests` mint theirs under `/tmp`. `yuzu_gw_mtls_tests` keeps its own setup (also under `/tmp`) and ignores `YUZU_REQUIRE_TLS_TESTS`: without `openssl` it substitutes placeholder tests that always pass, named `mTLS handshake skipped: <reason>` and `one-way handshake skipped (openssl unavailable)`. By default an unavailable or failing `openssl` makes the legs of the other three modules (`yuzu_gw_heartbeat_conn_rpc_tests`, `yuzu_gw_authz_tests`, `yuzu_gw_authz_rpc_tests`) contribute no tests and print `SKIPPED <module>: openssl certificates unavailable: ...` on the console, so a run without `openssl` can still report all tests passed. Set `YUZU_REQUIRE_TLS_TESTS=1` in the environment to turn that skip into a failing test in those three modules (`yuzu_gw_authz_tests:certs_unavailable/2` implements the switch). Use it on any machine that is expected to have `openssl`. It is optional and unset by default; the `linux` job of `ci.yml` sets it, and no other workflow or job does.

**Proto codegen drift (`check-proto-codegen.sh`).** The gateway carries its own gpb-generated `apps/yuzu_gw/src/*_pb.erl` (separate from the server's protoc output). gpb modules are self-contained: change a `.proto` field but forget to regenerate and the gateway silently drops that field in transit (the PR5 enrollment-CSR field-drop bug). The guard regenerates with rebar.config's own pinned `gpb_opts` (read via `file:consult`, so it cannot drift from the build) into a temp dir and byte-diffs against the committed modules. It runs after `rebar3 compile` (needs `_build/gpb`) and is wired into the release workflow's gateway job. gpb is version-pinned (4.21.7) + `target_erlang_version` fixed, so the output is deterministic. To fix a drift failure: regenerate the modules and commit them.

**Always run `rebar3 dialyzer` after any Erlang change.** Compilation succeeding is not enough — dialyzer catches type violations, dead code, and missing dependencies that the compiler silently accepts. The project uses `warnings_as_errors` for compile but dialyzer warnings are separate.

**`--dir apps/yuzu_gw/test` is mandatory on `rebar3 eunit`**, not optional. Without it, rebar3 3.27 intersects discovered test modules against the `src/`-derived `modules` list in `yuzu_gw.app` and rejects every orphan test module (`*_tests` without a 1:1 src counterpart, every `*_SUITE` file, helpers) with `Module X not found in project` before running a single test. Tracked as **#337**; `scripts/run-tests.sh erlang-unit` already applies the workaround, but if you invoke rebar3 directly you must pass the flag yourself.

**`rebar3 eunit --module X` does NOT give you test isolation.** It runs the full `--dir` phase first, then the module filter, **in the same BEAM VM**. The second run inherits polluted state — meck mocks, registered names, leaked processes, send_after timers — from the first, so a passing filtered run does not prove the test is order-independent, and a failing filtered run may be failing because of pollution rather than the test itself. For real isolation, `rm -rf gateway/_build/test` between runs (forces a fresh BEAM) or drop into `erl -pa _build/test/lib/yuzu_gw/ebin -pa _build/test/lib/*/ebin` and call test functions directly. This gotcha wasted meaningful debugging time on #336.

## Toolchain activation (Erlang on PATH)

**Meson resolves the gateway's Erlang/OTP itself, at configure time.** No
activation step is needed for a Meson/Ninja build: `meson setup` runs
`scripts/erlang_toolchain.py find-otp`, which searches the `erl` already on
PATH, kerl (its installs are found whether or not the `kerl` command is on
PATH), asdf, mise, Homebrew (`erlang@28` before `erlang`), common Linux
prefixes and the Windows installer directories, and accepts an install only if
the OTP_VERSION of its LIVE release passes the pin (with several `releases/<n>/`
left by installing one major over another, the live one is the release named in
`releases/start_erl.data`). Selection: an explicit `YUZU_OTP_BIN` must itself
match, or configure skips the gateway with the WARNING (an error under
`-Drequire_gateway=true`); otherwise the `erl` already on PATH wins when it
matches (it is your active choice); otherwise the highest matching release
found. `C:\Erlang` is never searched on Windows: any user can create it, and
the CI runners build as SYSTEM. The resolved `bin/` reaches the
gateway build and both gateway tests as `YUZU_OTP_BIN`, which the wrappers put
first on PATH, so `ninja` alone builds with the right OTP even when a newer
one (Homebrew `erlang` 29) is first in the shell. The configure summary names
what it chose: `Erlang gateway: enabled, Erlang/OTP 28.4 (kerl) at ...`, and
the end-of-configure Components summary repeats it (or `SKIPPED (...)`).

**The pin is a floor within the major: OTP 28.4 or any later 28.x.** It is
`DEFAULT_OTP_VERSION` in `scripts/erlang_toolchain.py`, the single source
for Meson, the wrappers and `ensure-erlang.sh`. It accepts every pinned
toolchain today (the Windows runner contract's 28.4.2, the macOS CI download's
28.5.0.7, setup-beam's latest 28.x) and refuses 28.3 and earlier and any 29.x:
moving to a new major is a deliberate migration. There is no Meson option for
it, for the same branch-shared-build-dir reason as `require_gateway`. To see
every install the resolver found and why it chose (or refused) each:

```bash
python3 scripts/erlang_toolchain.py find-otp
```

If `rebar3` is present but no install passes the pin, configure prints
`WARNING: Erlang gateway: SKIPPED.` with that inventory and continues without
the gateway; `-Drequire_gateway=true` turns that into a configure error. A
crash inside the resolver is always a configure error, never a skip. An OTP
installed after configure is picked up on the next reconfigure; if the OTP
Meson resolved is removed or replaced after configure, the gateway build stops
with "...reconfigure the build" rather than falling back to another `erl`.

**Overriding the choice.** Both overrides are read at **configure** time and
baked into the build: configure passes the resolved `YUZU_OTP_BIN` and the pin
it checked (`YUZU_OTP_VERSION`) to the gateway targets, whose environment
replaces any value exported when running `ninja` - so set them on
`meson setup` / `meson setup --reconfigure`, not on `ninja`. Ninja's automatic
regeneration after a `meson.build` change reconfigures with the environment of
THAT `ninja` invocation, so keep an override exported in the shell you build
from, or reconfigure explicitly after changing it.

- `YUZU_OTP_BIN=<install>/bin` picks one install. It must hold a matching
  `erl`; a wrong version or a path with no `erl` is reported, never replaced.
- `YUZU_OTP_VERSION=<digits.and.dots>` changes the floor for that configure
  (same-major rule). Anything that is not digits and dots is rejected.

### Changing the Erlang/OTP pin

The floor is a repository toolchain contract, like the Windows SDK pin in
`docs/windows-build.md`. A change to it is one PR that updates every copy
together:

- `DEFAULT_OTP_VERSION` in `scripts/erlang_toolchain.py` (Meson, the wrappers
  and `ensure-erlang.sh` all read it);
- every OTP the build actually installs: the `setup-beam` `otp-version` in
  `ci.yml`, `release.yml`, `nightly.yml`, `codeql.yml`, `sanitizer-tests.yml`
  and `fork-dynamic-review.yml`; the macOS `OTP_VERSION` + its sha256 in
  `ci.yml`; `deploy/windows/toolchain-contract.json`,
  `deploy/windows/Provision-Windows-Runner.ps1` and
  `Test-ToolchainContract.ps1` (and the runners' maintenance record,
  `deploy/windows/README.md`); `scripts/runner-ops/upgrade-erlang-linux.sh`;
  the gateway image base tags and the `otp_fix_min` guard in
  `Dockerfile.gateway` and its siblings; and Dependabot's Erlang rules
  (`.github/dependabot.yml`, `docs/dependency-updates.md`);
- the scripts that name a version: `scripts/ensure-erlang.sh`'s fallback
  literal (used only if it cannot read the pin), `scripts/ci/assert-gateway-tests.py`'s
  message, and any `source scripts/ensure-erlang.sh <version>` caller
  (`scripts/release-preflight.sh` and `scripts/integration-test.sh` pass `""`,
  which selects the pin);
- the user-facing statements: `docs/user-manual/gateway.md`,
  `docs/build-guide.md`, `README.md`, `docs/darwin-compat.md`,
  `docs/rhel9-build-setup.md`, `docs/testing/integration-tests.md`.

`tests/test_erlang_toolchain_otp.py` fails if the Windows contract's or the
macOS CI download's version stops passing the pin. A move to a new MAJOR also
needs the gateway dependency set (rebar.config) proven on it first, and on the
Windows host the old and new OTP side by side until every active branch carries
the bump, because branches not rebased onto it will refuse the new major.

### Shells: `scripts/ensure-erlang.sh`

For running rebar3 or `erl` by hand, the sourceable helper asks the
same resolver (`find-otp`) and activates what it picks in the current shell -
on MSYS2 through a native Windows Python, converting the path with `cygpath`.
When no suitable Python exists, or the resolver errors or its pick fails to
activate, it falls back to its own narrower search (kerl, asdf, Homebrew, the
Windows installer). After `source scripts/ensure-erlang.sh <version>`, check
with `find-otp --version <version>`; a bare `find-otp` checks the default pin.

```bash
source scripts/ensure-erlang.sh           # the pin above: 28.4 or later 28.x
source scripts/ensure-erlang.sh 28.4.2    # 28.4.2 or later 28.x
python3 scripts/erlang_toolchain.py find-otp >/dev/null   # exit 0 = the erl it reports passes the pin
```

A working `erl` of the wrong version on PATH is not success: the helper
reports it, keeps searching, and if nothing passes the pin it says so and
leaves PATH unchanged - so `command -v erl` alone can pass with the wrong OTP.
It **always returns 0**, including under a caller's `set -euo pipefail`, so it
can't kill the caller; callers verify the version. Native `cmd.exe`/PowerShell is out of scope; the
documented Windows build path is MSYS2 bash.

Erlang/OTP 28.4 or later 28.x is the only supported toolchain for the gateway test gates:
`scripts/test_gateway.py` no longer carries the old OTP-25 CT teardown-race
override (removed in #4800 because it could pass a run with an auto-skipped
suite), so an OTP 25 run that hits that race fails closed.

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
`<build dir>/meson-logs/yuzu_gateway_build.log`, which every `ci.yml` leg
uploads with the rest of `meson-logs/` on failure. The pipe and the log are
used on **every** platform (they were once Windows-only): the gateway target
runs in Ninja's console pool, so a redirected or IDE build otherwise keeps only
the command line, and `meson-log.txt` is rewritten by every configure, so it
cannot hold build output. The log starts with the time, the command and the
OTP release and `bin/` it ran on. (If that file is held open
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
| Metric HELP strings are ASCII-only (#4707, #5177) | `yuzu_gw_telemetry.erl` is UTF-8, so an em dash or smart quote in a `{help, ...}` string becomes a charlist element > 255; `prometheus_text_format` calls `iolist_to_binary/1` on it and raises `badarg` on **every** scrape, so `:9568/metrics` returns a bare inets HTTP 500 for the whole registry. `yuzu_gw_telemetry_tests:metrics_scrape_renders_test_/0` renders the real registry to catch it in eunit; the rule across all components is in `docs/observability-conventions.md`. |
| WSL epmd shadows Windows epmd (dev hosts running both) | With WSL localhost forwarding, `wslrelay` owns `127.0.0.1:4369`/`::1:4369` and forwards to a Linux `epmd` (started by any WSL-side distributed test, e.g. the multinode eunit modules), while Windows `epmd.exe` only holds `0.0.0.0:4369`. Windows nodes then register and resolve through the Linux epmd, and Windows multinode eunit fails with `peer:start_it` timeouts / `System NOT running to use fully qualified hostnames`. Before a Windows-side run: `epmd -names` in WSL, and `epmd -kill` there if nothing is registered. CI is unaffected (the Linux and Windows pools are separate boxes). |
| Shutdown flush | During `stop/1`, `flush_sync/0` is the correct way to drain the heartbeat buffer. Do not fall back to `queue_heartbeat/1` with sentinel atoms — it violates the `map()` spec and would corrupt the buffer. If `flush_sync` fails, the process is already dead and the buffer is lost. |
| Canonical-name mock leak (#336 family) | If a test kills a registered gen_server and registers a throwaway mock under the same canonical name, cleanup must compare the pre-test pid with `whereis(Name)` at teardown and kill the replacement when they differ — for not-owned names too. Otherwise a later module's setup adopts the impostor via `{already_started, Pid}` and its first `gen_server:call` times out ("One or more tests were cancelled", platform-dependent via eunit module order). Reference fix: `yuzu_gw_health_nf_tests.erl` cleanup (commit 4375116c); root-cause leak tracked in #1363. |
