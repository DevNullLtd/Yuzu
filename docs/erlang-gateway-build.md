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

**Gateway image platforms (#6711).** `deploy/docker/Dockerfile.gateway` builds for `linux/amd64` only. Its pinned `erlang:28-alpine` index is mixed upstream (amd64 on Alpine 3.23, every other platform on 3.24), the runtime stage is Alpine 3.23, and the abi-guard refuses a builder on a newer Alpine than the runtime on every architecture until the gateway is on OTP 29.1 (musl 1.2.6 with an older OTP aborts at boot on AMX CPUs, #1743; AMX is x86-only, so for arm64 this is a lockstep policy), so the deps stage refuses any other `TARGETARCH` up front. This is a scoping choice: older `erlang:28-alpine` indexes keep both architectures on Alpine 3.23, and whether to re-pin to one is tracked in #6740. The supported list is the `# yuzu:gateway-platforms` marker in the Dockerfile; `scripts/ci/check-gateway-base-index.py` (run in `docker-healthcheck-invariants.yml`, fixture-tested by `tests/test_gateway_base_index.py`) fails when the pinned index does not annotate a listed platform as built on the runtime stage's Alpine release (it reads the publisher's annotation; the build's abi-guard remains the build-time check, and it exits 1 on a mismatch, 2 when the registry is unreadable and 3 on an input it does not understand). Lift the restriction with that re-pin (#6740) or with the move to OTP 29.1 or newer. The check covers the platforms on the marker line only: the others are reported as notes, not failures.

`apps/yuzu_gw/test/ct` includes `yuzu_gw_scale_SUITE`, which starts the gateway, a fake server and a load generator as separate nodes and runs 500 simulated agents through seven scenarios (about 1 min of the CT run with the PR #5695 fixes); see `docs/testing/gateway-scale-tests.md` for the 5,000 and 25,000 sizes and the `gate` group.

**TLS test legs and `YUZU_REQUIRE_TLS_TESTS`.** The TLS legs of seven modules mint throwaway certificates with the `openssl` CLI in a `0700` directory under `/tmp` or `$TMPDIR`: `yuzu_gw_heartbeat_conn_rpc_tests`, `yuzu_gw_authz_tests`, `yuzu_gw_authz_rpc_tests`, `yuzu_gw_mtls_tests`, `yuzu_grpc_client_tls_tests`, `yuzu_grpc_wire_tests` and `yuzu_grpc_origin_wire_tests`. By default an unavailable or failing `openssl` makes the TLS legs of those modules contribute no tests and print `SKIPPED <module>: openssl certificates unavailable: ...` on the console, so a run without `openssl` can still report all tests passed. Set `YUZU_REQUIRE_TLS_TESTS=1` in the environment to turn that skip into a failing test in all seven (`yuzu_gw_authz_tests:certs_unavailable/2` implements the switch and every module calls it). Use it on any machine that is expected to have `openssl`. It is optional and unset by default; the `linux` job of `ci.yml` sets it, and no other workflow or job does.

**Proto codegen drift (`check-proto-codegen.sh`).** The gateway carries its own gpb-generated `apps/yuzu_gw/src/*_pb.erl` (separate from the server's protoc output). gpb modules are self-contained: change a `.proto` field but forget to regenerate and the gateway silently drops that field in transit (the PR5 enrollment-CSR field-drop bug). The guard regenerates with rebar.config's own pinned `gpb_opts` (read via `file:consult`, so it cannot drift from the build) into a temp dir and byte-diffs against the committed modules. It runs after `rebar3 compile` (needs `_build/gpb`) and is wired into the release workflow's gateway job. gpb is version-pinned (4.21.7) + `target_erlang_version` fixed, so the output is deterministic. To fix a drift failure: regenerate the modules and commit them.

**Always run `rebar3 dialyzer` after any Erlang change.** Compilation succeeding is not enough — dialyzer catches type violations, dead code, and missing dependencies that the compiler silently accepts. The project uses `warnings_as_errors` for compile but dialyzer warnings are separate.

**`--dir apps/yuzu_gw/test` is mandatory on `rebar3 eunit`**, not optional. Without it, rebar3 3.27 intersects discovered test modules against the `src/`-derived `modules` list in `yuzu_gw.app` and rejects every orphan test module (`*_tests` without a 1:1 src counterpart, every `*_SUITE` file, helpers) with `Module X not found in project` before running a single test. Tracked as **#337**; `scripts/run-tests.sh erlang-unit` already applies the workaround, but if you invoke rebar3 directly you must pass the flag yourself.

**`rebar3 eunit --module X` does NOT give you test isolation.** It runs the full `--dir` phase first, then the module filter, **in the same BEAM VM**. The second run inherits polluted state — meck mocks, registered names, leaked processes, send_after timers — from the first, so a passing filtered run does not prove the test is order-independent, and a failing filtered run may be failing because of pollution rather than the test itself. For real isolation, `rm -rf gateway/_build/test` between runs (forces a fresh BEAM) or drop into `erl -pa _build/test/lib/yuzu_gw/ebin -pa _build/test/lib/*/ebin` and call test functions directly. This gotcha wasted meaningful debugging time on #336.

## The malloc_trim NIF

The gateway's only C is `apps/yuzu_gw/c_src/yuzu_gw_mem_trim_nif.c`: one function, `malloc_trim(0)`, with no input, no state and no allocation, which `yuzu_gw_mem_reclaim` calls after a memory-reclaim pass (operator description: `docs/user-manual/gateway.md`, "Giving memory back after a drop").

- **Where it is built.** `apps/yuzu_gw/rebar.config` has a `pre_hooks` entry keyed `"-linux-gnu-"`. rebar3 matches that as a regex against the Erlang target (`<otp>-<system_architecture>-<wordsize>`, e.g. `28.5.0.2-x86_64-pc-linux-gnu-64`), so the hook runs on glibc Linux and not on Alpine/musl (`-linux-musl-`), macOS (`-apple-darwin`) or Windows (`win32`). No Docker, Meson or CI change: the glibc builders (`Dockerfile.gateway.chisel`, `Dockerfile.ci-gateway`, the Meson `.gateway_built` target on Linux, `release.yml`'s gateway job) all have a C compiler, and the Alpine builder, macOS and Windows never need one. The `.so` lands in `apps/yuzu_gw/priv/` (gitignored, kept out of Docker contexts by `.dockerignore`) and ships in the release's `lib/yuzu_gw-*/priv`.
- **It fails hard on glibc Linux.** The hook runs `c_src/build_mem_trim_nif.sh`, which fails `rebar3 compile` when no compiler is found (`CC` overrides it): a soft skip would ship a `.deb`, `.rpm` or chiselled image without the trim and nobody would notice. `yuzu_gw_mem_trim_tests:loaded_exactly_on_glibc_linux_test/0` fails on a glibc Linux eunit run whose NIF did not load. The script writes to a temporary name and renames, so the parallel Meson eunit shards (one rebar3 each, one shared `priv/`) never load a half-written file.
- **A hook command runs only its first command.** rebar3 cut `"a && b"` and `"a; b"` to `a` (checked 2026-10-29 on rebar3 3.27.0), which is why the hook calls a script rather than an inline `mkdir ... && cc ...`.
- **Loading is optional.** `yuzu_gw_mem_trim`'s `-on_load` always returns `ok`, so a missing or unloadable `.so` never stops the module (or, in an embedded release, the boot); `malloc_trim/0` then raises `error:nif_not_loaded`, which the reclaim pass turns into "garbage collection only" with one notice line.
- **Why not `port_compiler` or a Makefile.** `pc` would be a new Hex plugin (supply-chain review, a pin, a PLT interaction) for one file; a Makefile adds a `make` requirement. A compiler alone is enough.
- **Memory safety.** The C gets `cpp-safety` review. It was built once with `-fsanitize=address,undefined` and loaded into a BEAM with the sanitizer runtimes preloaded (gcc 14.2, Debian, 2026-10-29: 8,000 calls from four processes while eight others churned the heap, no report). It is not fuzzed: there is no input to fuzz (arity 0). Gateway C that handles peer input would need fuzzing as well; this function handles none.

## The gRPC layer and how listeners are started

The gateway contains no grpcbox (nor chatterbox, hpack, acceptor_pool or gproc): its two listeners (agent, management) are its own thin gRPC layer over Cowboy/Ranch, and its connection to the server is its own unary gRPC client over gun, in `gateway/apps/yuzu_gw/src/`:

| Module | Role |
|---|---|
| `yuzu_grpc_listener` | One Ranch listener per `{yuzu_gw, grpc_listeners}` entry; a `gen_server` a supervisor starts. Its header documents every entry key. |
| `yuzu_grpc_stream_h` | The only Cowboy stream handler: runs the `auth_fun`, resolves the caller's address, routes the call, spawns the runner. |
| `yuzu_grpc_origin` | Which address a call is attributed to (`transport` / `proxy_protocol` / `forwarded_for`); pure. |
| `yuzu_grpc_route`, `yuzu_grpc_runner`, `yuzu_grpc_stream`, `yuzu_grpc_frame`, `yuzu_grpc` | Route table from the proto modules, handler runner (unary, server-streaming, bidi; any non-gRPC-error failure is `INTERNAL`), the stream API (`yuzu_grpc_stream:send(Stream, Message)`, stream first), message framing, and the ctx accessors (`peer/1`, `origin/1`, `peer_cert/1`, `conn_pid/1`). |
| `yuzu_grpc_client`, `yuzu_grpc_client_channel`, `yuzu_grpc_client_config` | The upstream (gateway-to-server) client, unary only: `yuzu_grpc_client:unary/5` makes one call over a connection `yuzu_grpc_client_channel:pick/2` hands it; the channel (one `gen_server` per `{yuzu_gw, upstream_client}` channel, a child of `yuzu_gw_sup` ahead of `yuzu_gw_upstream`) owns a pool of gun HTTP/2 connections per endpoint and reopens them with 100 ms to 5 s jittered backoff; `yuzu_grpc_client_config` parses the channels and applies the `upstream_tcp_nodelay` default. |

Listeners are the **last children** of `yuzu_gw_sup`, one `yuzu_grpc_listener` child spec per entry, so nothing is served before the registry, router and agent supervisor exist and a listener that cannot bind stops the tree. `yuzu_gw_app` validates every entry (and refuses a leftover `{grpcbox, [{servers, ...}]}` or `{grpcbox, [{client, ...}]}` block, and a gateway with no `default_channel` in `{yuzu_gw, upstream_client}` unless `{allow_no_upstream, true}`) before the supervisor starts. `YUZU_GW_AGENT_PORT` / `YUZU_GW_MGMT_PORT` rewrite the matching entry's port. The operator-facing description is in `docs/user-manual/gateway.md`, "gRPC listeners".

The upstream client is `yuzu_grpc_client` over gun, configured by `{yuzu_gw, [{upstream_client, ...}]}` (operator description in `docs/user-manual/gateway.md`, "The upstream client"). The vendored, patched grpcbox (`gateway/_checkouts/grpcbox`, `grpcbox.yuzu.patch`), `scripts/verify-vendored-grpcbox.sh`, the CI and release "Verify vendored grpcbox integrity" steps and the `grpcbox_plugin` rebar3 plugin are gone, and `rebar.lock` holds no grpcbox, chatterbox, hpack, acceptor_pool or gproc. The direct dependencies are cowboy (listeners), gun (upstream client), ctx (the gRPC layer's request-context type), gpb, telemetry, prometheus, prometheus_httpd and recon. The test clients are `yuzu_gw_test_client` (unary, server-streaming and bidirectional calls over the same channel module; it exists for the wire tests and is not in the release) and `yuzu_gw_test_listener:client_channel/2`.

**Test helpers** (in `apps/yuzu_gw/test/`). Tests start listeners through `yuzu_gw_test_listener:start/1` (a `grpc_listeners` entry on a probed free loopback port, returns `{Port, Pid}`) and talk to them through `yuzu_gw_test_listener:client_channel/2` or `yuzu_grpc_wire_tests:client_chan/4`; do not write another `start_listener`/`probe_free_port`. `yuzu_gw_test_relay` is a plain TCP splice that writes a fixed header first (a PROXY protocol header, as an F5 iRule or HAProxy `send-proxy-v2` would) and then copies bytes both ways, so TLS and the client certificate pass through it untouched; use it for the `proxy_protocol` origin tests (`yuzu_grpc_origin_wire_tests` makes real calls through it and through a `forwarded_for` listener and reads the origin the handler sees, and `yuzu_grpc_origin_tests` covers the pure resolution). A wire test never waits on a sleep: it waits on a message, a monitor, a telemetry event or a stub counter.

**The compose wizard's gateway config is checked from both sides without either toolchain on the other's runner.** The wizard (`tools/compose-wizard/`) embeds a gateway `sys.config` in the compose files it generates, where nothing parses it until a container boots. Two golden files hold exactly that block for the plaintext and operator-TLS modes: `tests/fixtures/compose-wizard/gateway-sys.config.plaintext` and `.operator`. `tests/test_compose_wizard.py` (run by `docs-lint.yml`, which has Node and no Erlang) regenerates the block with the wizard and requires it to equal the golden file byte for byte. `yuzu_gw_config_posture_tests:wizard_golden_configs_test_` (run in the gateway eunit leg, which has Erlang and no Node) feeds the same files through `file:consult`, `yuzu_gw_app:evaluate_listeners/1` and `evaluate_mgmt_posture/3`; a missing golden file fails and does not skip. After an intended wizard change, regenerate the goldens with `python3 tests/test_compose_wizard.py --regenerate-gateway-goldens` (needs `node` on `PATH`) and review the diff. The two goldens are byte-identical today because the wizard does not emit a TLS gateway yet (it refuses a gateway together with TLS, and the gateway block it does emit is plaintext in both cases); the operator golden will diverge from the plaintext one when the wizard does.

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

**Meson runs the EUnit suite as two shards: `gateway eunit shard A` and
`gateway eunit shard B`.** Each is `scripts/test_gateway.py gateway eunit
--shard K/2` with its own `REBAR_BASE_DIR` (`gateway/_build_eunit_1`,
`_build_eunit_2`), a 540s wrapper deadline and a 600s meson timeout. The whole
suite had outgrown one 540s run on the Windows leg (PR #5695). The partition is
deterministic and weighted by measured per-module Windows times
(`scripts/gateway_eunit_shards.py`). A new test module lands in a shard without
any edit. Between them the two shards run exactly the module set that
`rebar3 eunit --dir apps/yuzu_gw/test` runs, each module in its own test
process, as under `--dir`. The shard's module list reaches rebar3 through
`gateway/eunit_shard.config.script` (`REBAR_CONFIG`), not through `--module`,
because `--module m1,m2` runs every listed module in one shared process.
`tests/test_gateway_eunit_shards.py` pins this. `python3 scripts/test_gateway.py
gateway eunit` with no `--shard` still runs the whole suite in one go, which is
what you want locally. One thing is different: the modules run in a different
order, sorted within each shard rather than in `--dir`'s order. A module that
leaks VM state can therefore fail in a shard and pass in the whole run, or the
other way round (see the canonical-name pitfall below).

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
| `ctx` dependency | `ctx` functions (`ctx:get/3` and friends) are called directly: the context is the gRPC layer's request-context type. `ctx` is a direct dependency in `rebar.config` and listed in `yuzu_gw.app.src` `applications`; it used to arrive transitively through grpcbox, which is gone. **Rule: if you call a function from a transitive dependency, add it to the applications list.** |
| `-spec` contracts | If a function spec says `-spec f(map()) -> ok`, passing an atom like `f(some_atom)` compiles fine but dialyzer flags it. Always respect `-spec` contracts, even in catch/fallback paths. |
| Circuit breaker dead code | `on_success/1` and `on_failure/1` only receive states `closed` or `half_open` (never `open`, because `check_circuit/1` rejects before the RPC runs). Don't add catchall clauses for states that are structurally unreachable — dialyzer knows the type is fully covered. |
| `gpb` plugin warning | `Plugin gpb does not export init/1` is a benign warning from rebar3 — gpb is used via `grpc` config, not as a rebar3 plugin. Ignore it. |
| Stray `.beam` / crash dumps | `erl_crash.dump` and loose `.beam` files in the gateway root are artifacts. They should be gitignored or deleted, never committed. |
| Metric HELP strings are ASCII-only (#4707, #5177) | `yuzu_gw_telemetry.erl` is UTF-8, so an em dash or smart quote in a `{help, ...}` string becomes a charlist element > 255; `prometheus_text_format` calls `iolist_to_binary/1` on it and raises `badarg` on **every** scrape, so `:9568/metrics` returns a bare inets HTTP 500 for the whole registry. `yuzu_gw_telemetry_tests:metrics_scrape_renders_test_/0` renders the real registry to catch it in eunit; the rule across all components is in `docs/observability-conventions.md`. |
| Adding a gateway metric | Declare it as an entry of `yuzu_gw_telemetry:metric_specs/0` (the one list `declare_metrics/0` declares), give it a series at start in `seed_metrics/0` or an entry with a reason in `unseeded_metrics/0`, and give it a row in `docs/user-manual/metrics.md`. `yuzu_gw_metrics_scrape_tests` starts the gateway from `gateway/config/sys.config`, fetches `/metrics` over HTTP, and fails on a declared metric that is not rendered with HELP and TYPE, has no series and no reason, or is not in metrics.md, on a `yuzu_gw_` metric metrics.md names that is not declared, on a family rendered outside the list, and on an alert expression in `docs/prometheus/yuzu-alerts.yml` that reads an undeclared `yuzu_gw_` metric. A periodic sample goes in `yuzu_gw_gauge`: a FIXED list of named processes (`sampled_processes/0`), never a walk of every process or connection. |
| Gauges named `*_seconds` (prometheus library) | `prometheus_gauge:declare/1` reads a `_seconds` suffix as a duration unit and converts every value set from native time units, so a Unix timestamp set on such a gauge read back as about 1.76. Declare a timestamp or plain-seconds gauge with `{duration_unit, false}` (counters ending `_seconds_total` are not affected). `yuzu_gw_telemetry_tests:cert_gauges_test_/0` reads the value back. |
| WSL epmd shadows Windows epmd (dev hosts running both) | With WSL localhost forwarding, `wslrelay` owns `127.0.0.1:4369`/`::1:4369` and forwards to a Linux `epmd` (started by any WSL-side distributed test, e.g. the multinode eunit modules), while Windows `epmd.exe` only holds `0.0.0.0:4369`. Windows nodes then register and resolve through the Linux epmd, and Windows multinode eunit fails with `peer:start_it` timeouts / `System NOT running to use fully qualified hostnames`. Before a Windows-side run: `epmd -names` in WSL, and `epmd -kill` there if nothing is registered. CI is unaffected (the Linux and Windows pools are separate boxes). |
| Shared epmd killed by another job's cleanup (#4853) | On a shared self-hosted box the runner's `Complete job` step logs `Terminate orphan process: ... (epmd)` and kills the box-wide epmd when the job that started it finishes. A concurrent job's origin node then loses its registration and its next `peer:start_link` in the multinode eunit modules times out (`peer:start_it`, `exit:timeout`): a red in a test the job's own change never touched. Seen on two PRs' Windows legs on 2026-10-21, 28-50 s after another job on the box completed. `scripts/test_gateway.py` therefore gives every eunit and ct run its own `ERL_EPMD_PORT` (`scripts/gateway_epmd.py`). It logs which epmd the run uses (read the `[test_gateway.py] ... epmd` line first, then `epmd -port <N> -names`); an `ERL_EPMD_PORT` already set in the environment wins untouched, any non-empty value, so `4369` goes back to the shared epmd. `epmd -port <N> -kill` runs at normal exit; epmd refuses it while a node is still registered, and the wrapper then says the epmd may still be running and prints the command that removes it (on Windows `epmd.exe` is under the OTP install's `erts-<vsn>\bin`, not on PATH). A refused kill or a killed wrapper leaves the epmd to the runner's orphan cleanup; on a workstation with no runner it stays until `epmd -port <N> -kill`. A `rebar3 eunit`/`ct` started outside the wrapper (`release.yml`'s eunit step, `scripts/test/eunit-gate.sh`, `scripts/run-tests.sh`, `gateway/test_runner.sh`, `scripts/test/perf-gate.sh`, `scripts/ci/check-gateway-eunit-order.sh`) still uses the shared 4369. |
| Shutdown flush | During `stop/1`, `flush_sync/0` is the correct way to drain the heartbeat buffer. Do not fall back to `queue_heartbeat/1` with sentinel atoms — it violates the `map()` spec and would corrupt the buffer. If `flush_sync` fails, the process is already dead and the buffer is lost. |
| Canonical-name mock leak (#336 family) | If a test kills a registered gen_server and registers a throwaway mock under the same canonical name, cleanup must compare the pre-test pid with `whereis(Name)` at teardown and kill the replacement when they differ — for not-owned names too. Otherwise a later module's setup adopts the impostor via `{already_started, Pid}` and its first `gen_server:call` times out ("One or more tests were cancelled", platform-dependent via eunit module order). Reference fix: `yuzu_gw_health_nf_tests.erl` cleanup (commit 4375116c); root-cause leak tracked in #1363. |
