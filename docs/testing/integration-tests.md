# Yuzu Integration Testing

This document describes how to run the end-to-end integration tests for the Yuzu system (Server + Gateway + Agent).

## Prerequisites

### Required
- Built C++ server and agent: `meson compile -C build-linux`
- Erlang/OTP 28.4 or any later 28.x, with rebar3
- curl, nc (netcat)

### Optional
- grpcurl (for gRPC probing tests)
- Docker (for isolated test environments)

## Test Suites

### 1. Shell-based Full-Stack Integration Test

The primary integration test runs all three components together:

```bash
# Quick smoke test with 1 agent
./scripts/integration-test.sh

# Test with multiple agents
./scripts/integration-test.sh --agents 10

# Real TLS stack: the server on its generated default certificates, the gateway hop
# pinned over mutual TLS, agents to the gateway over one-way TLS
./scripts/integration-test.sh --tls

# What CI runs: TLS, every port taken from the OS, plus the gateway's real-upstream
# and management-listener Common Test suites (yuzu_gw_real_upstream_SUITE,
# yuzu_gw_real_mgmt_SUITE) against the stack's server and gateway
./scripts/integration-test.sh --tls --free-ports --gateway-ct
```

The script needs Postgres (`YUZU_TEST_POSTGRES_DSN`; it creates a uniquely named database and
drops it on exit), `psql`, `openssl`, `curl`, `python3` and Erlang/OTP with `rebar3` (it builds the
gateway release). `--free-ports` makes concurrent runs on one host safe.

This test:
- Starts the C++ server in gateway mode with `--gateway-upstream`. The gateway-upstream service refuses to start without gateway peer authorization or an acknowledgement. The plaintext mode passes `--no-tls --insecure-gateway-peer` (the check is disabled, so that mode does not exercise it). `--tls` passes no acknowledgement: the server runs on its generated default certificates and enforces the automatic pin of its own `default-gateway.pem`, the leaf the gateway presents, so the gateway hop is pinned mutual TLS and the script asserts the server booted enforcing with that leaf's SPKI prefix and denied no call
- Starts the Erlang gateway (the `rebar3 as prod release` build, on a generated `sys.config`) connecting to the server
- With `--tls`, runs the gateway's management listener (`:50063`, the privileged command plane) in the production posture except for the mode: strict mutual TLS, `auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1`, `mgmt_peer_pins` naming the server's default leaf, and `mgmt_peer_auth_mode` set to `identity_or_pin`. The rig opts in to that mode (#6016); the shipped configs stay on `pin`, so the shipped `pin` configuration (resolved and judged by the real boot-guard functions) is covered by the eunit module `yuzu_gw_config_posture_tests`, not exercised on the real stack. The server is started with `--gateway-command-addr` (and `--rate-limit 10000`, so the burst below is not answered with 429) and forwards commands over it
- Starts N C++ agents connecting through the gateway
- Runs ~20 test scenarios covering connectivity, registration, heartbeats, and stability
- With `--tls`, covers the management hop (server to gateway to agent and back, #5175): it logs in to the server's REST API, dispatches `os_info.os_name` to the real agent through the gateway (one round trip, then 300 commands over the server's single management connection) and requires every command to return the agent's SUCCESS and the server to count every forward as `ok`. With `--gateway-ct`, `yuzu_gw_real_mgmt_SUITE` also dials the management listener directly: the server's pinned leaf is served, and so is the server identity (#6016: the real server leaf is admitted by identity in the `identity_or_pin` mode the script configures, a renewed-key leaf and a same-key re-issue carrying the identity are served, one carrying another install's identity or an agent-style URI is refused), while a valid but unpinned leaf of the same CA (the gateway's own, or an enrolled agent's) is refused with `UNAUTHENTICATED` and counted in `yuzu_gw_mgmt_auth_rejected_total`; 300 `SendCommand` streams over one connection complete; and the early-end paths (unknown agent, a fan-out deadline that passes before the agent answers, cancelled streams) leave the connection serving. Afterwards the gateway log must hold no `function_clause`, crash report or `[error]` line and the server log no `Socket closed` or failed `Gateway SendCommand`

### 2. Erlang Gateway Unit Tests (EUnit)

```bash
cd gateway
./test_runner.sh eunit
```

Test modules:
- `yuzu_gw_registry_tests` — ETS routing table (the registry makes no pg call)
- `yuzu_gw_registry_cost_tests` — per-registration pg calls (none) and O(N) removal cost, by reduction count
- `yuzu_gw_agent_registration_tests` — registration runs after `init/1`; `start_child` never waits for the registry; refusals never trip the agent supervisor
- `yuzu_gw_agent_tests` — Agent gen_statem lifecycle
- `yuzu_gw_upstream_tests` — Heartbeat batching and proxy
- `yuzu_gw_router_tests` — Command fanout coordinator
- `yuzu_gw_proto_tests` — Protobuf helper functions
- `yuzu_gw_scale_tests` — Scale and stress tests (50K+ agents)

### 3. Erlang Gateway Common Test Suites

```bash
cd gateway
./test_runner.sh ct
```

Test suites:
- `yuzu_gw_integration_SUITE` — Component integration with mocked upstream
- `yuzu_gw_e2e_SUITE` — End-to-end flows with simulated gRPC
- `yuzu_gw_scale_SUITE` — 500 simulated agents (by default) against the real gateway listeners and a fake server: registration ramp and storm, server crash, gateway crash, planned stop, management fan-out. See [gateway-scale-tests.md](gateway-scale-tests.md)

### 4. C++ Unit Tests

```bash
meson test -C build-linux --print-errorlogs
```

## Test Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Integration Test Script                    │
│                   (scripts/integration-test.sh)               │
└──────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│   C++ Server     │ │  Erlang Gateway  │ │   C++ Agent(s)   │
│  (gateway mode)  │ │   (yuzu_gw)      │ │  (1..N instances)│
│                  │ │                  │ │                  │
│  Ports:          │ │  Ports:          │ │  Connects to:    │
│  - :50050 agent  │ │  - :50051 agent  │ │  Gateway :50051  │
│  - :50051 gw     │ │  - :50052 mgmt   │ │                  │
│  - :8090 web     │ │                  │ │                  │
└──────────────────┘ └──────────────────┘ └──────────────────┘
         ▲                   │
         │   GatewayUpstream │
         └───────────────────┘
              (gRPC)
```

## Test Categories

### Basic Connectivity (Tests 1-8)
- Server web UI accessibility
- Agent registration through gateway
- Agent process health
- Gateway process health
- Log verification for connection activity
- Heartbeat cycle continuity

### Server API Endpoints (Tests 9-11)
- Prometheus metrics endpoint (`/metrics`)
- Health check endpoint (`/health`)
- Help/catalog endpoint (`/api/help`)

### Gateway-Server Communication (Tests 12-13)
- GatewayUpstream service connectivity
- Agent-facing gRPC port availability

### Agent Session Management (Tests 14-15)
- Session persistence across heartbeats
- Multi-agent registration

### Error Handling (Test 16)
- Server graceful error handling for invalid endpoints

### Stability Tests (Tests 17-20)
- Rapid heartbeat under load
- Gateway stability
- Server stability
- Log health check (no critical errors)

### gRPC Probing (if grpcurl available)
- Server gRPC reflection
- Gateway gRPC reflection
- GatewayUpstream service

### Connection Recovery
- Agent disconnect isolation
- Component stability after disconnects

## Scale Testing

The multi-node scale suite, `yuzu_gw_scale_SUITE`, drives N simulated agents
over real HTTP/2 against the gateway, with the server replaced by a fake on a
real listener, and reports registration latency, replay time, notices lost,
memory per connection and mailbox peaks. How to run it at 5,000 and 25,000
agents, what it checks, and the numbers before the PR #5695 fixes are in
[gateway-scale-tests.md](gateway-scale-tests.md).

The EUnit module below exercises the registry and router data structures alone,
in one VM, with no listener and no upstream:

```bash
# Default: 50,000 agents
cd gateway
rebar3 as test eunit --module=yuzu_gw_scale_tests

# Custom scale
YUZU_SCALE_AGENTS=100000 rebar3 as test eunit --module=yuzu_gw_scale_tests
```

Scale tests verify:
- Bulk registration performance
- O(1) lookup at scale
- Pagination completeness
- Memory per agent bounds
- Fanout dispatch throughput
- Heartbeat batch accumulation

## Coverage Reports

```bash
# Gateway coverage
cd gateway
./test_runner.sh cover

# View coverage report
open _build/test/cover/index.html
```

## Troubleshooting

### Gateway fails to start
- Check that ports 50051/50052 are not in use
- Verify Erlang/OTP version: `erl -version`
- Check rebar3 dependencies: `rebar3 deps`

### Agents fail to register
- Check gateway logs for connection errors
- Verify enrollment token is valid
- Check server is in gateway mode (`--gateway-mode`)
- If a hand-started server exits at boot with a gateway peer authorization error, it needs `--insecure-gateway-peer` (plaintext rig), a gateway key pin, or the generated default certificates; `scripts/integration-test.sh` passes `--insecure-gateway-peer` in its plaintext mode and relies on the automatic pin of the generated default certificates with `--tls`

### Tests time out
- Increase timeouts in test configuration
- Check for resource exhaustion (file descriptors, ports)
- Run with fewer agents

### mTLS failures
- Verify certificate validity
- Check CA chain is complete
- Ensure client cert has correct CN/SAN

## CI Integration

The integration tests can be run in CI:

```yaml
# Example GitHub Actions job
integration-test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Build C++ components
      run: |
        ./scripts/setup.sh --tests
        meson compile -C build-linux
    - name: Build Erlang gateway
      run: cd gateway && rebar3 compile
    - name: Run integration tests
      run: ./scripts/integration-test.sh --agents 5
```

## Gateway Python Test Suite

The `test_gateway.py` script (`scripts/test_gateway.py`) provides a Python-based gateway test harness that cleans stale beam files and runs `rebar3 as test eunit` or `ct` against the gateway directory:

```bash
python3 scripts/test_gateway.py gateway eunit               # whole EUnit suite (Windows: python or py -3)
python3 scripts/test_gateway.py gateway eunit --shard 1/2   # one EUnit shard, as Meson runs it
python3 scripts/test_gateway.py gateway ct
```

It is the wrapper Meson's gateway `test()` targets call, and CI runs it that way (`meson test --suite gateway`); invoke it directly only for local debugging. Meson runs EUnit as two shards, `gateway eunit shard A` and `gateway eunit shard B` (`--shard 1/2` and `2/2`), each in its own `REBAR_BASE_DIR`; between them they run exactly what the whole-suite run does (`docs/erlang-gateway-build.md`). `ct` runs use a minimised performance profile.

## MCP Integration Testing

The MCP server is tested at the unit level via `tests/unit/server/test_mcp_server.cpp` (JSON-RPC parsing, tier policy, token integration, tool dispatch). For manual integration testing:

```bash
# Create an MCP token (a cookie-session REST write, so it needs the same-site Origin).
# A tiered token must carry expires_at: unix epoch seconds, in the future, at most 90 days out.
# macOS: EXPIRES_AT=$(date -v+7d +%s)
EXPIRES_AT=$(date -d '+7 days' +%s)
curl -X POST http://localhost:8080/api/v1/tokens \
  -H "Origin: http://localhost:8080" \
  -H "Cookie: $COOKIE" \
  -d "{\"name\":\"mcp-test\",\"mcp_tier\":\"readonly\",\"expires_at\":$EXPIRES_AT}"

# Call MCP endpoint: send ONLY the Authorization header, never the session cookie.
# /mcp/v1/ refuses a credential with no MCP tier (403, -32003), and a live cookie is
# resolved before the Bearer token, so a request carrying both is refused too.
curl -X POST http://localhost:8080/mcp/v1/ \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_agents","arguments":{}},"id":1}'
```

## Adding New Tests

### Shell tests
Add new test cases in `scripts/integration-test.sh` following the pattern:
```bash
log "Test: Description"
# Test logic
assert_eq "Test name" "expected" "$actual"
```

### Erlang tests
1. Add test function to existing `*_tests.erl` or create new module
2. Add to test fixture list
3. Run with `rebar3 as test eunit --dir apps/yuzu_gw/test` (#337)

### Common Test
1. Add test function to `*_SUITE.erl`
2. Add to `all/0` or appropriate group
3. Run with `rebar3 as test ct --dir apps/yuzu_gw/test/ct` (ct does not recurse; without `--dir` it runs zero suites and still exits 0, #4800)
