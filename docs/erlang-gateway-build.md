# Erlang Gateway — Build & Quality

The gateway (`gateway/`) is a standalone rebar3 project. It compiles independently from the C++ codebase.

> Routed out of `CLAUDE.md`. The `gateway-erlang` agent loads this doc on any `gateway/` or `*.erl` change. For routine runs, prefer the `/gateway-eunit` and `/gateway-dialyzer` skills — they bundle the toolchain activation, the `--dir` flag, and result interpretation.

## Build & verify commands
```bash
cd gateway
rebar3 compile                               # compile
rebar3 eunit --dir apps/yuzu_gw/test         # unit tests (657 tests as of the adversarial-review fixes of the heartbeat verdict replay change, as reported by the code author)
rebar3 dialyzer                              # type analysis — must be warning-free
rebar3 ct --dir apps/yuzu_gw/test/ct --suite <name>  # Common Test (ct does not recurse: --dir apps/yuzu_gw/test finds no suites)
bash scripts/check-proto-codegen.sh          # F-3 (#1243): committed *_pb.erl in sync with priv/proto
```

**TLS test legs and `YUZU_REQUIRE_TLS_TESTS`.** The TLS legs of seven modules mint throwaway certificates with the `openssl` CLI in a `0700` directory under `/tmp` or `$TMPDIR`: `yuzu_gw_heartbeat_conn_rpc_tests`, `yuzu_gw_authz_tests`, `yuzu_gw_authz_rpc_tests`, `yuzu_gw_mtls_tests`, `yuzu_grpc_client_tls_tests`, `yuzu_grpc_wire_tests` and `yuzu_grpc_origin_wire_tests`. By default an unavailable or failing `openssl` makes the TLS legs of those modules contribute no tests and print `SKIPPED <module>: openssl certificates unavailable: ...` on the console, so a run without `openssl` can still report all tests passed. Set `YUZU_REQUIRE_TLS_TESTS=1` in the environment to turn that skip into a failing test in all seven (`yuzu_gw_authz_tests:certs_unavailable/2` implements the switch and every module calls it). Use it on any machine that is expected to have `openssl`. It is optional and unset by default; the `linux` job of `ci.yml` sets it, and no other workflow or job does.

**Proto codegen drift (`check-proto-codegen.sh`).** The gateway carries its own gpb-generated `apps/yuzu_gw/src/*_pb.erl` (separate from the server's protoc output). gpb modules are self-contained: change a `.proto` field but forget to regenerate and the gateway silently drops that field in transit (the PR5 enrollment-CSR field-drop bug). The guard regenerates with rebar.config's own pinned `gpb_opts` (read via `file:consult`, so it cannot drift from the build) into a temp dir and byte-diffs against the committed modules. It runs after `rebar3 compile` (needs `_build/gpb`) and is wired into the release workflow's gateway job. gpb is version-pinned (4.21.7) + `target_erlang_version` fixed, so the output is deterministic. To fix a drift failure: regenerate the modules and commit them.

**Always run `rebar3 dialyzer` after any Erlang change.** Compilation succeeding is not enough — dialyzer catches type violations, dead code, and missing dependencies that the compiler silently accepts. The project uses `warnings_as_errors` for compile but dialyzer warnings are separate.

**`--dir apps/yuzu_gw/test` is mandatory on `rebar3 eunit`**, not optional. Without it, rebar3 3.27 intersects discovered test modules against the `src/`-derived `modules` list in `yuzu_gw.app` and rejects every orphan test module (`*_tests` without a 1:1 src counterpart, every `*_SUITE` file, helpers) with `Module X not found in project` before running a single test. Tracked as **#337**; `scripts/run-tests.sh erlang-unit` already applies the workaround, but if you invoke rebar3 directly you must pass the flag yourself.

**`rebar3 eunit --module X` does NOT give you test isolation.** It runs the full `--dir` phase first, then the module filter, **in the same BEAM VM**. The second run inherits polluted state — meck mocks, registered names, leaked processes, send_after timers — from the first, so a passing filtered run does not prove the test is order-independent, and a failing filtered run may be failing because of pollution rather than the test itself. For real isolation, `rm -rf gateway/_build/test` between runs (forces a fresh BEAM) or drop into `erl -pa _build/test/lib/yuzu_gw/ebin -pa _build/test/lib/*/ebin` and call test functions directly. This gotcha wasted meaningful debugging time on #336.

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

`rebar3` and the meson custom_target that wraps it both need `erl` on PATH. Forgetting to activate is the usual cause of phantom `.gateway_built` failures while the C++ targets succeed. Source the cross-platform helper before any gateway work and verify:

```bash
source scripts/ensure-erlang.sh           # default: latest 28.x
source scripts/ensure-erlang.sh 28.4.2    # exact pin
command -v erl >/dev/null || { echo "Erlang missing"; exit 1; }
```

OTP 28 is the only supported toolchain for the gateway test gates: `scripts/test_gateway.py` no longer carries the old OTP-25 CT teardown-race override (removed in #4800 because it could pass a run with an auto-skipped suite), so an OTP 25 run that hits that race now fails closed. The helper probes kerl → asdf → Homebrew (macOS) → MSYS2 installer (Windows) and **always returns 0** so it can't trip the caller's `set -e`. Callers MUST verify `command -v erl` themselves. Default version tracks `release.yml`'s `erlef/setup-beam` `otp-version` — bump both together. Native `cmd.exe`/PowerShell is out of scope; documented Windows build path is MSYS2 bash.

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
| `ctx` dependency | `ctx` functions (`ctx:get/3` and friends) are called directly: the context is the gRPC layer's request-context type. `ctx` is a direct dependency in `rebar.config` and listed in `yuzu_gw.app.src` `applications`; it used to arrive transitively through grpcbox, which is gone. **Rule: if you call a function from a transitive dependency, add it to the applications list.** |
| `-spec` contracts | If a function spec says `-spec f(map()) -> ok`, passing an atom like `f(some_atom)` compiles fine but dialyzer flags it. Always respect `-spec` contracts, even in catch/fallback paths. |
| Circuit breaker dead code | `on_success/1` and `on_failure/1` only receive states `closed` or `half_open` (never `open`, because `check_circuit/1` rejects before the RPC runs). Don't add catchall clauses for states that are structurally unreachable — dialyzer knows the type is fully covered. |
| `gpb` plugin warning | `Plugin gpb does not export init/1` is a benign warning from rebar3 — gpb is used via `grpc` config, not as a rebar3 plugin. Ignore it. |
| Stray `.beam` / crash dumps | `erl_crash.dump` and loose `.beam` files in the gateway root are artifacts. They should be gitignored or deleted, never committed. |
| Metric HELP strings are ASCII-only (#4707, #5177) | `yuzu_gw_telemetry.erl` is UTF-8, so an em dash or smart quote in a `{help, ...}` string becomes a charlist element > 255; `prometheus_text_format` calls `iolist_to_binary/1` on it and raises `badarg` on **every** scrape, so `:9568/metrics` returns a bare inets HTTP 500 for the whole registry. `yuzu_gw_telemetry_tests:metrics_scrape_renders_test_/0` renders the real registry to catch it in eunit; the rule across all components is in `docs/observability-conventions.md`. |
| WSL epmd shadows Windows epmd (dev hosts running both) | With WSL localhost forwarding, `wslrelay` owns `127.0.0.1:4369`/`::1:4369` and forwards to a Linux `epmd` (started by any WSL-side distributed test, e.g. the multinode eunit modules), while Windows `epmd.exe` only holds `0.0.0.0:4369`. Windows nodes then register and resolve through the Linux epmd, and Windows multinode eunit fails with `peer:start_it` timeouts / `System NOT running to use fully qualified hostnames`. Before a Windows-side run: `epmd -names` in WSL, and `epmd -kill` there if nothing is registered. CI is unaffected (the Linux and Windows pools are separate boxes). |
| Shutdown flush | During `stop/1`, `flush_sync/0` is the correct way to drain the heartbeat buffer. Do not fall back to `queue_heartbeat/1` with sentinel atoms — it violates the `map()` spec and would corrupt the buffer. If `flush_sync` fails, the process is already dead and the buffer is lost. |
| Canonical-name mock leak (#336 family) | If a test kills a registered gen_server and registers a throwaway mock under the same canonical name, cleanup must compare the pre-test pid with `whereis(Name)` at teardown and kill the replacement when they differ — for not-owned names too. Otherwise a later module's setup adopts the impostor via `{already_started, Pid}` and its first `gen_server:call` times out ("One or more tests were cancelled", platform-dependent via eunit module order). Reference fix: `yuzu_gw_health_nf_tests.erl` cleanup (commit 4375116c); root-cause leak tracked in #1363. |
