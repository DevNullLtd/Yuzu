# Yuzu Integration Testing

This document describes how to run the end-to-end integration tests for the Yuzu system (Server + Gateway + Agent).

## Prerequisites

### Required
- Built C++ server and agent: `meson compile -C build-linux`
- Erlang/OTP 26+ with rebar3
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

# Test with mTLS enabled
./scripts/integration-test.sh --agents 5 --tls
```

This test:
- Starts the C++ server in gateway mode
- Starts the Erlang gateway connecting to the server
- Starts N C++ agents connecting through the gateway
- Runs ~20 test scenarios covering connectivity, registration, heartbeats, and stability

### 2. Erlang Gateway Unit Tests (EUnit)

```bash
cd gateway
./test_runner.sh eunit
```

Test modules:
- `yuzu_gw_registry_tests` — ETS routing table and pg groups
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

The Erlang gateway includes scale tests that can exercise high agent counts:

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
python3 scripts/test_gateway.py gateway eunit   # or: ... gateway ct  (Windows: python or py -3)
```

It is the wrapper Meson's gateway `test()` targets call, and CI runs it that way (`meson test --suite gateway`); invoke it directly only for local debugging. `ct` runs use a minimised performance profile.

## MCP Integration Testing

The MCP server is tested at the unit level via `tests/unit/server/test_mcp_server.cpp` (JSON-RPC parsing, tier policy, token integration, tool dispatch). For manual integration testing:

```bash
# Create an MCP token
curl -X POST http://localhost:8080/api/v1/tokens \
  -H "Cookie: $COOKIE" \
  -d '{"name":"mcp-test","mcp_tier":"readonly","expires_in_days":7}'

# Call MCP endpoint
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
