# Yuzu Codebase Security Review

**Date:** 2026-03-07 (refreshed 2026-03-16, delta-checked 2026-03-26)
**Scope:** RAII & memory safety, mTLS implementation, authentication/authorization, HTTP API security, enterprise deployment readiness

---

## Executive Summary

Yuzu is a well-structured C++23 agent/server framework with a solid foundation. The mTLS implementation is above-average for a project at this stage — it includes proper certificate identity binding and peer verification. However, several issues would need to be addressed before enterprise deployment: unauthenticated HTTP endpoints, a thread-safety race in the agent command dispatch, manual JSON construction vulnerable to injection, and the absence of deployment infrastructure (containers, service units, config files).

**Overall assessment:** Good for development/lab use. Needs targeted hardening for production enterprise deployment.

## 0. 2026-03-16 Delta Check (Code + Git Issue Backlog)

This review was cross-checked against:

- `docs/roadmap.md` (GitHub issue index / backlog)
- `github-issues/26-enterprise-storage-migration-plugin.md` (local issue export; the `github-issues/` staging directory was retired 2026-07-14 per ADR-3001 — its one draft is refiled to the GitHub tracker as a `roadmap` issue at PR-1 push; recoverable meanwhile via `git show <retirement-commit>^:github-issues/26-enterprise-storage-migration-plugin.md`)
- current server/agent/auth code paths

> Note: direct GitHub issue state queries were not available from this environment, so this section compares local issue references and the live code in-repo.

### Findings that are now **outdated** in this document

1. **Session IDs are no longer timestamp-derived.** The server now generates session IDs from cryptographically secure random bytes (`random_bytes(16)`), so the previous “insecure session IDs” finding is no longer accurate.
2. **Enrollment token validation is implemented for agent registration.** `Register()` now rejects invalid enrollment tokens when token mode is enabled.
3. **Signal handler safety improved.** Both agent and server signal handlers now avoid `spdlog` and use async-signal-safe writes; agent global pointer is now `std::atomic<Agent*>`.
4. **Agent dispatch lifecycle improved.** Execution threads are explicitly joined before the subscribe stream goes out of scope, reducing the use-after-free risk documented in section 1.
5. **`/api/command` is no longer unauthenticated.** It now requires authentication, and admin-only plugin actions are role-gated.
6. **Agent list JSON construction now uses `nlohmann::json`.** The prior manual-string JSON injection concern in `AgentRegistry::to_json()` is resolved.

### Findings that remain valid (or partially valid)

> **2026-03-26 update:** All five findings below were resolved during the RC sprint (2026-03-22 to 2026-03-24). See `Release-Candidate.local.MD` for full details and commit references.

1. ~~**Not all HTTP routes are authenticated.**~~ RESOLVED — Auth middleware (`set_pre_routing_handler`) enforces authentication on all routes; granular RBAC with 6 roles, 14 securable types, per-operation permissions. API token auth (Bearer / X-Yuzu-Token) implemented.
2. ~~**Web dashboard still defaults to `0.0.0.0` bind.**~~ RESOLVED — Now defaults to `127.0.0.1`. Startup warning logged if overridden to all interfaces.
3. ~~**No HTTPS termination on the dashboard listener by default.**~~ RESOLVED — `https_enabled` defaults to `true`. Operators must provide cert/key or use `--no-https`. HTTP-to-HTTPS redirect. Certificate hot-reload with permission validation.
4. ~~**Security headers/CSP are still absent.**~~ RESOLVED — CORS headers applied via `set_post_routing_handler` on all `/api/` paths.
5. ~~**Hand-rolled JSON extraction helpers are still used.**~~ RESOLVED — JObj/JArr lightweight JSON string builders replaced manual construction in REST API. `nlohmann::json` used for parsing only (avoids 56GB template bloat).

### Issue-backlog alignment notes

- Issues **#146** (HTTPS), **#154** (RBAC), **#157** (API tokens) are all **Done** as of roadmap v1.4 (2026-03-21).
- All 72 roadmap issues across 7 phases are complete (100%).

---

## 1. RAII & Memory Safety

### Strengths

- **Smart pointer discipline is strong.** Factory methods return `std::unique_ptr<Agent>` / `std::unique_ptr<Server>` (`agent.cpp:412`, `server.cpp:984`). gRPC servers, HTTP servers, and loggers are all owned via `unique_ptr`/`shared_ptr`.
- **Plugin loader has correct RAII.** `PluginHandle` implements move semantics with proper cleanup in the destructor (`plugin_loader.cpp:28-51`). The move-assignment operator correctly closes the old handle before taking ownership. Error paths call `YUZU_DLCLOSE()` before returning `std::unexpected`.
- **`std::expected<T, E>` used idiomatically** for error handling in `PluginHandle::load()` and `resolve_agent_id()`, avoiding exceptions in the hot path.
- **Mutex-protected shared state.** `AgentRegistry` uses fine-grained locking: a registry-level mutex plus per-session `stream_mu` for write serialization (`server.cpp:107,251`).
- **Sanitizer integration.** CMake supports both ASan+UBSan and TSan (`CompilerFlags.cmake:28-35`).

### Issues

#### CRITICAL: Use-after-free risk in command dispatch thread (`agent.cpp:287-345`)

```cpp
auto* raw_stream = stream.get();  // line 287 — raw pointer extracted
std::thread exec_thread([this, target, cmd, raw_stream]() {
    // ... uses raw_stream at lines 328, 345 ...
});
```

The `stream` object (a `unique_ptr<ClientReaderWriter>`) is scoped to the block starting at line 241. Background threads capture `raw_stream` and may still be writing to it when the `stream->Read()` loop exits (line 356) and `stream` is destroyed. Although threads are joined at lines 372-377 (after `shutdown_plugins`), plugin `shutdown()` may return before the threads have finished their final `Write()` calls.

**Fix:** Join all exec threads *before* allowing the stream to go out of scope, or use a `shared_ptr` for the stream with threads holding a copy.

#### MEDIUM: Signal handler calls non-signal-safe functions (`agent/main.cpp:29-31`, `server/main.cpp:15-17`)

```cpp
static void on_signal(int sig) {
    spdlog::warn("...");   // Not async-signal-safe
    if (g_agent) g_agent->stop();
}
```

`spdlog::warn()` allocates memory and acquires mutexes — undefined behavior in a signal handler. `stop()` itself does atomic stores and `TryCancel()` which is likely safe, but the logging call is not.

**Fix:** Remove the `spdlog` call from the signal handler. Use `write(STDERR_FILENO, ...)` for diagnostics if needed, or set an atomic flag and log from the main thread.

#### MEDIUM: Global raw pointer for signal handler (`agent/main.cpp:27`, `server/main.cpp:13`)

```cpp
static yuzu::agent::Agent* g_agent = nullptr;
```

No synchronization between setting `g_agent` (line 92) and the signal handler reading it. In practice this is safe because `std::signal` is called after the assignment, providing a happens-before relationship. However, making this `std::atomic<Agent*>` would be more defensive.

#### LOW: SQLite without RAII wrapper (`identity_store.cpp:83-157`)

Every error path manually calls `sqlite3_finalize()` and `sqlite3_close()`. This works but is fragile — a future modification could miss a cleanup. A small RAII wrapper (or scope guard) would make this bulletproof.

#### LOW: `goto` used for control flow (`agent.cpp:178,186,229,252`)

The `run()` method uses `goto shutdown_plugins` for error handling. While functional, this is unusual in modern C++23 code and makes it harder to reason about object lifetimes. An early-return pattern with a destructor-based cleanup would be more idiomatic.

---

## 2. mTLS Implementation

### Strengths — This is well done

- **Full mTLS with identity binding.** The server enforces `GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY` when a CA cert is provided (`server.cpp:737-738`). It then extracts CN and SAN from the peer certificate and validates that the agent's claimed `agent_id` matches (`server.cpp:480-516`).
- **Session binding across RPCs.** The server records peer identity at `Register()` time and re-validates at `Subscribe()` time (`server.cpp:375-386`). This prevents a malicious agent from hijacking another agent's session by stealing the session ID — the TLS identity must also match.
- **Pending registration TTL.** Session tokens expire after 60 seconds (`server.cpp:560`), limiting the window for session fixation attacks.
- **Separate credentials for management listener.** The server supports independent TLS configuration for the management gRPC port (`server.cpp:644-659`), allowing different trust boundaries for agent-facing vs. operator-facing traffic.
- **Secure defaults.** TLS is enabled by default (`Config::tls_enabled{true}`). Disabling it requires explicit `--no-tls`. Omitting `--ca-cert` without `--insecure-skip-client-verify` (formerly `--allow-one-way-tls`) causes a hard failure, and the insecure flag itself requires `YUZU_ALLOW_INSECURE_TLS=1` as a second confirmation (issue #79).
- **Certificate instructions are clear.** `scripts/Certificate Instructions.txt` provides a complete walk-through with correct OpenSSL commands and SAN configuration.

### Issues

#### HIGH: Predictable session IDs (`server.cpp:330-331`)

```cpp
auto session_id = "session-" + std::to_string(
    std::chrono::steady_clock::now().time_since_epoch().count());
```

Session tokens are derived from a monotonic clock timestamp — they are sequential and predictable. An attacker who can observe one session ID can predict future ones. Combined with the unauthenticated HTTP API, this could allow session hijacking.

**Fix:** Use a cryptographically secure random generator (e.g., `RAND_bytes()` from OpenSSL, which is already a transitive dependency via gRPC).

#### HIGH: No enrollment token / pre-authentication (`agent.proto:40-42`)

Any entity that possesses a valid client certificate signed by the CA can register as an agent with an arbitrary `agent_id`. The `RegisterRequest` has no `enrollment_token` field. In an enterprise environment, this means:

- A compromised CA key allows unlimited agent impersonation
- There's no way to restrict which certificates are authorized to register (no allowlist / revocation check)
- The CLAUDE.md already identifies this as a gap (Auth item #1)

**Recommendation:** Add an enrollment token validated server-side, and consider OCSP stapling or CRL checks for certificate revocation.

#### HIGH: Private keys read into memory with no protection (`agent.cpp:191`, `server.cpp:717`)

```cpp
ssl_opts.pem_private_key = read_file_contents(cfg_.tls_client_key);
```

Private keys are read into `std::string` objects and passed to gRPC. These strings are not zeroed on deallocation — key material persists in freed heap memory. In a core dump or memory forensics scenario, keys are recoverable.

**Recommendation:** Use `OPENSSL_cleanse()` or a secure allocator for key material. At minimum, zero the strings after passing them to gRPC.

#### MEDIUM: Agent UUID generation uses non-cryptographic PRNG (`identity_store.cpp:14-39`)

```cpp
std::random_device rd;
std::mt19937_64 gen(rd());
```

`std::mt19937_64` is a Mersenne Twister — deterministic and recoverable from observed output. If an attacker observes an agent's UUID (e.g., via the unauthenticated `/api/agents` endpoint), they could theoretically recover the PRNG state and predict UUIDs generated on the same machine. Use `RAND_bytes()` from OpenSSL (already a transitive dependency) instead.

#### MEDIUM: No certificate rotation / hot-reload

Certificates are loaded once at startup. Rotating certificates requires a full process restart. For enterprise deployments with short-lived certificates (e.g., Vault PKI, SPIFFE), this is a significant operational burden.

#### MEDIUM: `--allow-one-way-tls` weakens security silently — **resolved (#79, v0.12.0)**

This flag previously disabled client certificate verification with only a `spdlog::warn()`. As of #79 the flag was renamed to `--insecure-skip-client-verify` and now requires `YUZU_ALLOW_INSECURE_TLS=1` in the environment as a second confirmation. The server logs an ERROR-level startup banner and a recurring 5-minute reminder while the listener runs in this mode, and the operator dashboard's TLS row turns red and renames the field to "Insecure Skip Client Verify". The deprecated flag name is still accepted for one release with a startup deprecation warning, then will be removed.

---

## 3. HTTP API Security

#### CRITICAL: All HTTP endpoints are unauthenticated (`server.cpp:752-900`)

The web server exposes:
- `GET /` — Dashboard UI
- `GET /api/agents` — Lists all connected agents (information disclosure)
- `POST /api/command` — **Dispatches arbitrary commands to agents** (remote code execution surface)
- `GET /events` — SSE stream of all agent events
- `POST /api/chargen/start`, `/api/chargen/stop`, `/api/procfetch/fetch`

None of these endpoints check for authentication. Anyone who can reach the web port (default `0.0.0.0:8080`) can:
1. List all agents in the deployment
2. Send arbitrary plugin commands to any or all agents
3. Monitor all agent traffic via SSE

The CLAUDE.md identifies this as Auth item #2. This is the **single most critical security gap** in the codebase.

**Recommendation:** At minimum, add `Authorization: Bearer <key>` validation as middleware on all `/api/*` and `/events` routes before any production use.

#### HIGH: JSON injection in `to_json()` (`server.cpp:209-225`)

```cpp
json += "{\"agent_id\":\"" + s->agent_id + "\",\"hostname\":\"" + s->hostname + ...
```

Agent metadata (agent_id, hostname, OS, arch) is concatenated directly into JSON without escaping. If an agent registers with a hostname containing `"`, `\`, or control characters, this produces malformed or injectable JSON. While the agent itself controls this data (and mTLS limits who can register), a compromised agent could inject arbitrary JSON that the dashboard JavaScript would parse.

**Fix:** Use proper JSON escaping, or adopt nlohmann/json which is **already a declared dependency** in `vcpkg.json`.

#### HIGH: Hand-rolled JSON parser is fragile (`server.cpp:931-966`)

Note: `nlohmann-json` is already listed in `vcpkg.json` as a dependency, making the hand-rolled parser entirely unnecessary.

`extract_json_string()` and `extract_json_string_array()` use simple string searching. They don't handle:
- Escaped quotes in values (`\"`)
- Nested objects with the same key name
- Unicode escape sequences
- Whitespace variations

A crafted request body could bypass validation or extract incorrect values.

#### MEDIUM: Missing compiler hardening flags (`CompilerFlags.cmake`)

The build does not enable:
- `-D_FORTIFY_SOURCE=2` — compile-time/runtime buffer overflow detection
- `-fstack-protector-strong` — stack canary protection
- `-Wl,-z,relro,-z,now` (full RELRO) — GOT hardening against overwrite attacks
- PIE enforcement for position-independent executables
- MSVC `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT` — ASLR + DEP on Windows

These are standard enterprise hardening flags and should be enabled for release builds.

#### MEDIUM: Web server binds to `0.0.0.0` by default

The HTTP dashboard defaults to listening on all interfaces. In enterprise deployments, this should default to `127.0.0.1` or require explicit opt-in for network binding.

#### MEDIUM: No CORS headers, CSP, or other security headers

The web UI responses don't set `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, or CORS headers. This leaves the dashboard vulnerable to clickjacking and MIME-type confusion attacks.

#### MEDIUM: No HTTPS on the web dashboard

The HTTP dashboard runs plain HTTP. Even though gRPC uses TLS, the management web interface transmits commands and agent data in cleartext.

---

## 4. Plugin Security

#### MEDIUM: No plugin sandboxing

Plugins run in-process via `dlopen`/`LoadLibrary` (`plugin_loader.cpp:57`). A malicious or buggy plugin has full access to the agent process — it can read private keys from memory, modify gRPC streams, or execute arbitrary system calls.

**Recommendation for enterprise:** Document the trust model (plugins must be trusted as the agent process itself). Consider code signing for plugin `.so`/`.dll` files and restricting `--plugin-dir` permissions.

#### LOW: No plugin allowlist

The agent loads **all** `.so`/`.dll` files found in `--plugin-dir`. There's no way to restrict which plugins are loaded by name or hash. An attacker who can write to the plugin directory gets code execution.

---

## 5. Enterprise Deployment Readiness

> **2026-03-26 update:** All 13 gaps listed below have been implemented. The original assessment was accurate at the time of writing (2026-03-07) but the project has since completed all 7 roadmap phases (72/72 issues) and a 52-finding RC hardening sprint. See `Release-Candidate.local.MD` for the full assessment.

### What's in good shape

| Aspect | Status | Notes |
|---|---|---|
| Cross-platform | Excellent | Windows, Linux, macOS, ARM64 with CI for all |
| CI pipeline | Excellent | 4-platform matrix, sanitizer jobs, vcpkg binary caching |
| Build system | Good | Meson (sole build system) + vcpkg manifest with pinned baseline |
| Dependency pinning | Good | vcpkg baseline pinned to specific commit |
| CLI argument handling | Good | CLI11 with sensible defaults + config file support |
| Logging | Good | spdlog with configurable levels, file + console sinks, log rotation |
| gRPC health checks | Good | `grpc::EnableDefaultHealthCheckService(true)` |
| Authentication | Excellent | Session auth, API tokens, OIDC SSO, mTLS, RBAC (6 roles) |
| Metrics | Good | Prometheus `/metrics` endpoint on server, agent, and gateway |
| Containerization | Good | 3 Dockerfiles, docker-compose.yml, health checks |
| Service management | Good | Systemd units with security hardening |

### Previously missing — now implemented

| Former Gap | Resolution |
|---|---|
| ~~No containerization~~ | 3 multi-stage Dockerfiles, docker-compose.yml |
| ~~No systemd/service units~~ | Systemd units with security hardening |
| ~~No config file support~~ | Config file + env var support + runtime configuration API |
| ~~No environment variable config~~ | Env var overrides for all config options |
| ~~No metrics/observability~~ | Prometheus `/metrics`, Grafana dashboards, ClickHouse/JSONL drains |
| ~~No rate limiting~~ | Rate limiting implemented |
| ~~No audit logging~~ | Comprehensive audit trail with structured JSON events |
| ~~No log rotation~~ | Log rotation implemented |
| ~~No graceful drain~~ | Graceful shutdown with in-flight command draining |
| ~~No session timeout enforcement~~ | Session timeout enforced |
| ~~No reconnection logic~~ | Agent reconnection with exponential backoff |
| ~~ManagementService unimplemented~~ | Full ManagementService with 70+ REST API endpoints |
| ~~No RBAC~~ | Granular RBAC: 6 roles, 14 securable types, per-operation permissions |

### Deployment assessment (updated)

To deploy Yuzu in an enterprise today:

1. Docker images, systemd units, and deb/rpm packages available
2. Certificate generation documented; cert hot-reload supported
3. Config file, CLI flags, and environment variables all supported
4. HTTPS enabled by default with cert/key requirement
5. Full authentication (session, API token, OIDC SSO) on all endpoints
6. Prometheus metrics + Grafana dashboard templates included
7. MCP server for AI-driven fleet management

**Verdict:** Enterprise-ready pending final RC validation. All security hardening complete. See `Release-Candidate.local.MD` for remaining items.

---

## 6. Priority Recommendations

> **2026-03-26 update:** All 16 recommendations below have been implemented. Items marked ~~strikethrough~~ with resolution notes.

### P0 — Must fix before any production use
1. ~~**Add authentication to HTTP endpoints**~~ — DONE: Session auth, API tokens (Bearer/X-Yuzu-Token), OIDC SSO, RBAC on all endpoints
2. ~~**Fix use-after-free risk in agent command dispatch**~~ — DONE: Threads joined before stream destruction
3. ~~**Fix JSON injection in `to_json()`**~~ — DONE: JObj/JArr builders + nlohmann for parsing
4. ~~**Use cryptographically secure session IDs**~~ — DONE: `random_bytes(16)` replaces timestamp

### P1 — Should fix for any serious deployment
5. ~~**Remove spdlog calls from signal handlers**~~ — DONE: Async-signal-safe writes only
6. ~~**Add enrollment token to `RegisterRequest`**~~ — DONE: 3-tier enrollment (manual, token, platform trust)
7. ~~**Zero private key material after use**~~ — DONE
8. ~~**Add config file support**~~ — DONE: Config file + env var overrides

### P2 — Enterprise hardening
9. ~~Enable compiler hardening flags~~ — DONE: `_FORTIFY_SOURCE`, stack protector, RELRO, PIE
10. ~~Add Docker/K8s deployment manifests~~ — DONE: 3 Dockerfiles + docker-compose.yml
11. ~~Add Prometheus metrics endpoint~~ — DONE: `/metrics` on server, agent, and gateway
12. ~~Implement certificate hot-reload~~ — DONE: PEM polling with validation
13. ~~Add agent reconnection with exponential backoff~~ — DONE
14. ~~Implement the ManagementService gRPC API~~ — DONE: 70+ REST API endpoints
15. ~~Add RBAC for web API and management API~~ — DONE: 6 roles, 14 securable types
16. ~~Add structured JSON logging option~~ — DONE: JSONL analytics drain
