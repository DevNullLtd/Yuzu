# Code Review — Full Governance Retrospective (2026-03-28)

> **Supersedes** the original 2026-03-20 5-agent review. This document is the authoritative finding register for the Yuzu codebase, maintained across governance review sessions.

## Review Context

| Field | Value |
|-------|-------|
| Date | 2026-03-28 |
| Process | 7-gate governance (expanded from 5 gates on 2026-03-28) |
| Scope | Tiers 1-4 complete. |
| Prior art | RC sprint (2026-03-22 to 2026-03-24) found 52 findings (7C/16H/22M/7L), all resolved |
| Agents used | security-guardian, docs-writer, architect, dsl-engineer, performance, happy-path, unhappy-path, consistency-auditor, chaos-injector, quality-engineer |
| Invocations | ~77 agent invocations across Gates 1-5 (Tiers 1-4) |

## Governance Process (7 Gates)

1. **Change Summary** — codebase inventory for Tier 1 partitions
2. **Mandatory deep-dive** — security-guardian + docs-writer on all Tier 1 batches
3. **Domain-triggered review** — architect + dsl-engineer + performance
4. **Correctness & resilience** — happy-path + unhappy-path + consistency-auditor (parallel)
5. **Chaos analysis** — chaos-injector synthesized 10 compound failure scenarios
6. **Finding resolution** — code fixes committed and tested
7. **Iteration** — re-build + full test suite pass

## Tier 1 Partitions Reviewed

| Partition | Batches | Files | Status |
|-----------|---------|-------|--------|
| A: Auth & Security | A1 (auth, RBAC, OIDC), A2 (tokens, certs) | ~11 files | Complete |
| B1: REST API | B1 (rest_api_v1.cpp/.hpp) | ~2 files | Complete |
| D: Engines | D1 (CEL, policy), D2 (scope, workflow, schedule), D3 (compliance, approval, execution) | ~22 files | Complete |
| E: MCP Server | E1 (mcp_server, jsonrpc, policy) | ~4 files | Complete |

---

## Master Finding Register

### CRITICAL (1 found, 1 fixed)

| ID | Finding | File | Fix Commit |
|----|---------|------|------------|
| G2-SEC-A1-001 | OIDC JWT signature never validated — forged ID tokens possible | oidc_provider.cpp | `f05609a` |

### HIGH — Security (5 found, 5 fixed)

| ID | Finding | File | Fix Commit |
|----|---------|------|------------|
| G2-SEC-A1-002 | `check_scoped_permission` unsynchronized SQLite access | rbac_store.cpp | `6814755` (mutex added) |
| G2-SEC-A2-002 | ApiTokenStore no mutex on shared db handle | api_token_store.cpp | `46183c0` |
| G2-SEC-D1-001 | ReDoS via `std::regex` in CEL `.matches()` | cel_eval.cpp | `11a5590` (RE2) |
| G2-SEC-D1-002 | No wall-clock execution timeout on CEL evaluation | cel_eval.cpp | `2978296` |
| G2-SEC-D2-001 | ReDoS via `std::regex` in scope `MATCHES` operator | scope_engine.cpp | `11a5590` (RE2) |

### HIGH — Architecture (3 found, 3 fixed)

| ID | Finding | File | Fix Commit |
|----|---------|------|------------|
| G3-ARCH-001 | server.cpp god object (11K LOC, 28 store members) | server.cpp | **Fixed**: decomposed to 4.4K LOC + 24 extracted files |
| G3-ARCH-002 | Two-tier DB ownership with decoupled lifetimes | Multiple | **Fixed**: InstructionDbPool RAII wrapper (G3-ARCH-T2-002) |
| G3-ARCH-003 | 11 stores lack SQLite mutexes | 9 store headers | `6814755` (9 stores), `46183c0` (2 stores) |

### HIGH — Performance (5 found, 3 fixed)

| ID | Finding | File | Fix Commit |
|----|---------|------|------------|
| G3-PERF-001 | Regex recompilation per CEL evaluation call | cel_eval.cpp | Mitigated by RE2 (faster than std::regex) |
| G3-PERF-002 | Regex recompilation per scope agent | scope_engine.cpp | Mitigated by RE2 |
| G3-PERF-004 | RBAC check: 2+ SQL queries per request, no cache | rbac_store.cpp | `2978296` (perm cache) |
| G3-PERF-005 | RBAC scoped check: N+2 query amplification | rbac_store.cpp | Partially mitigated by cache |
| G3-PERF-010 | Fleet compliance cache writes under shared_lock (UB) | policy_store.cpp | `babb600` (unique_lock) |

### HIGH — DSL (2 found, 2 fixed)

| ID | Finding | File | Fix Commit |
|----|---------|------|------------|
| G3-DSL-001 | ReDoS in CEL + scope (same as D1-001/D2-001) | cel_eval.cpp, scope_engine.cpp | `11a5590` |
| G3-DSL-002 | No wall-clock timeout on CEL (same as D1-002) | cel_eval.cpp | `2978296` |

### HIGH — Correctness & Resilience (Gate 4)

| ID | Finding | File | Fix Commit |
|----|---------|------|------------|
| G4-UHP-AUTH-001 | Deleted user retains active sessions 8hrs | auth.cpp | `babb600` |
| G4-UHP-AUTH-003 | ManagementGroupStore has zero mutex (RBAC hot path) | management_group_store.hpp | `6814755` |
| G4-UHP-AUTH-004 | `check_scoped_permission` TOCTOU across lock releases | rbac_store.cpp | Documented; needs refactor |
| G4-CON-AUTH-001 | Session role never updated on role change | auth.cpp | `babb600` |
| G4-CON-AUTH-002 | Deleted user sessions never invalidated (dup of AUTH-001) | auth.cpp | `babb600` |
| G4-UHP-POL-001 | Unresolved CEL variable silently → false non-compliance | cel_eval.cpp | `2978296` (tri-state) |
| G4-UHP-POL-003 | No fix retry limit — infinite remediation loop | policy_store.cpp | `2978296` (max 3) |
| G4-UHP-POL-006 | Fleet compliance cache data race (dup of PERF-010) | policy_store.cpp | `babb600` |
| G4-UHP-POL-008 | CEL error conflated with non-compliance | compliance_eval.cpp | `2978296` (ComplianceResult enum) |
| G4-UHP-MCP-002 | MCP read_only_mode captured by value, runtime toggle dead | mcp_server.cpp | `babb600` (const bool&) |
| G4-UHP-MCP-003 | MCP kill switch only evaluated at startup | mcp_server.cpp | `46183c0` (runtime check) |
| G4-UHP-MCP-004 | Approval workflow: no TTL, no notification, unbounded queue | approval_manager.cpp | `2978296` (7-day TTL, 1000 cap) |
| G4-UHP-MCP-005 | ApprovalManager TOCTOU on concurrent approve/reject | approval_manager.cpp | `46183c0` (mutex + atomic WHERE) |

### HIGH — Documentation (10 found, 0 fixed — deferred)

| ID | Finding | File |
|----|---------|------|
| G2-DOC-A1-001 | HTTPS flag docs stale (`--https` vs `--no-https`) | authentication.md |
| G2-DOC-A1-003 | RBAC docs missing 5 securable types | rbac.md |
| G2-DOC-A1-004 | All 6 system role permission counts wrong | rbac.md |
| G2-DOC-A2-002 | REST API doesn't accept `mcp_tier` despite docs claiming it | rest-api.md |
| G2-DOC-A2-005 | Device token endpoints entirely undocumented | rest-api.md |
| G2-DOC-B1-001 | Inventory v1 endpoints undocumented | rest-api.md |
| G2-DOC-B1-002 | Execution statistics endpoints undocumented | rest-api.md |
| G2-DOC-B1-003 | Device token endpoints undocumented (dup of A2-005) | rest-api.md |
| G2-DOC-B1-004 | Software deployment endpoints (7) undocumented | rest-api.md |
| G2-DOC-B1-005 | License management endpoints (4) undocumented | rest-api.md |

**Key stat:** 24 of 52 REST API v1 endpoints (46%) have zero documentation.

### MEDIUM — Fixed (12)

| ID | Finding | Fix Commit |
|----|---------|------------|
| G2-SEC-A1-003 | No minimum password length | `9ad692b` (12-char min) |
| G2-SEC-A1-004 | Expired sessions never reaped | `9ad692b` (opportunistic reaper) |
| G2-SEC-A2-001 | mt19937_64 instead of CSPRNG for tokens | `9ad692b` (RAND_bytes) |
| G2-SEC-B1-004 | Missing security response headers | `9ad692b` (X-Frame-Options, HSTS, etc.) |
| G2-SEC-B1-005 | No CSRF protection beyond SameSite=Lax | `6814755` (Origin validation) |
| G2-SEC-D2-005 | Schedule scope_expression not validated before storage | `9ad692b` |
| G2-SEC-D2-006 | Schedule enable/disable missing audit event | `9ad692b` |
| G2-SEC-D2-008 | Workflow retry_count/delay unbounded | `9ad692b` (clamp to 10/3600) |
| G3-ARCH-005 | 6 non-thread-safe static RNGs | `babb600` (thread_local) |
| G4-UHP-POL-007 | Offline agents retain stale compliance status | `9ad692b` (24hr staleness TTL) |
| G4-UHP-POL-009 | `invalidate_policy` sets undeclared 'pending' status | `babb600` (→'unknown') |
| G4-UHP-MCP-008 | MCP automation starves human dashboard rate limit | `6814755` (separate bucket) |

### MEDIUM — Fixed (2026-03-28 session 2)

| ID | Finding | Fix |
|----|---------|-----|
| G2-SEC-A1-005 | RBAC `set_permission` doesn't validate effect value | Reject values other than "allow"/"deny" before DB write |
| G2-SEC-A1-006 | OIDC pending challenges map unbounded | Cap at 1000 entries; cleanup expired + evict oldest on overflow |
| G2-SEC-A2-003 | API token ID from 12-char hash prefix (collision risk) | Extended to 24 hex chars (96-bit collision resistance) |
| G2-SEC-A2-004 | `mcp_tier` not validated at store layer | Call `mcp::is_valid_tier()` before DB write |
| G2-SEC-B1-001 | Dead CORS helper reflects arbitrary Origin | Removed origin reflection; API is same-origin by design |
| G2-SEC-B1-002 | No upper bound on execution statistics `limit` | Clamp to 1000 on both agent and definition stats endpoints |
| G2-SEC-B1-003 | Inventory evaluate: 10K hardcoded limit | Reduced to 5000 |
| G2-SEC-D1-003 | CEL recursion depth 64 vs documented 10 | Reduced to 16 |
| G2-SEC-D1-004 | Unbounded string concatenation in CEL | 64 KiB cap (`kMaxStringResultLen`); throws on overflow |
| G2-SEC-D2-002 | NOT recursion bypasses scope depth | Added `DepthGuard` to `parse_not_legacy()` and `parse_unary()` |
| G2-SEC-E1-004 | `yuzu://server/health` resource skips RBAC | Added `perm_fn(req, res, "Server", "Read")` check |
| G3-DSL-004 | NOT recursion bypass in CEL parser | Same fix as D2-002 — DepthGuard in both NOT paths |
| G3-DSL-006 | Unknown characters silently skipped in CEL lexer | Return `TokenType::Error` instead of silent skip |

### MEDIUM — Remaining (unfixed, Tier 1 only)

| ID | Finding | Notes |
|----|---------|-------|
| G2-SEC-D1-005 | (Dup of PERF-010 — fixed) | — |
| G2-SEC-D2-003 | No execution time bound on scope evaluation | Mitigated: tree depth capped at 10, RE2 linear-time; no practical timeout risk |
| G2-SEC-D2-011 | Scheduled execution doesn't enforce creator's permissions | Re-validate at dispatch |
| G2-SEC-E1-001 | MCP read_only captured by value (fixed in mcp_server, but server.cpp caller needs check) | Verify end-to-end |
| G3-DSL-005 | yaml-dsl-spec.md lists MATCHES/EXISTS as "planned" | Update spec |
| G4-CON-AUTH-004 | Token ID generation inconsistent across stores | Standardize |
| G4-CON-AUTH-005 | Dual role system without formal mapping | Document contract |
| G4-UHP-MCP-011 | No scope blast-radius enforcement (warning only) | Add hard limit for Phase 2 write tools |

### LOW — Summary (not itemized, ~40 findings)

Categories: defense-in-depth suggestions, minor inconsistencies, documentation formatting, test coverage gaps, informational observations. Full details in the Gate 2-5 agent outputs during the 2026-03-28 conversation.

---

## Chaos Scenarios (Gate 5)

The chaos-injector synthesized 10 compound failure scenarios from Gate 4 risks. The 4 most dangerous:

| ID | Severity | Chain | Status |
|----|----------|-------|--------|
| CHAOS-T1-001 | CRITICAL | Ghost admin after deletion (3 findings) | **Fixed** — sessions invalidated on removal/role change |
| CHAOS-T1-002 | CRITICAL | ReDoS double-tap — server DoS via 6-char regex | **Fixed** — RE2 linear-time matching |
| CHAOS-T1-005 | CRITICAL | Infinite remediation loop from CEL typo | **Fixed** — fix retry limit (3) + tri-state compliance |
| CHAOS-T1-009 | CRITICAL | Full chain: 8 findings → complete control-plane takeover | **Mostly fixed** — 6 of 8 constituent findings resolved |

All 10 scenarios documented in the 2026-03-28 Gate 5 conversation output.

---

## Commits (2026-03-28 governance session)

| Commit | Description | Files | +/- |
|--------|-------------|-------|-----|
| `d3d19bb` | Add 4 governance agents + expand 5→7 gates | 6 | +720 |
| `3603de8` | Fix governance process findings (terminology, contracts) | 5 | +38/-25 |
| `babb600` | Fix 9 findings: sessions, cache race, scope safety, MCP toggle, RNGs | 11 | +43/-14 |
| `46183c0` | Fix 4 findings: store mutexes, approval TOCTOU, MCP kill switch | 7 | +29/-8 |
| `f05609a` | OIDC JWT signature verification via JWKS (CRITICAL) | 2 | +307/-1 |
| `11a5590` | Replace std::regex with RE2 (ReDoS fix) | 4 | +33/-30 |
| `2978296` | CEL timeout, compliance tri-state, fix retry, approval TTL, RBAC cache | 10 | +251/-87 |
| `9ad692b` | Passwords, headers, validation, staleness | 6 | +81/-30 |
| `6814755` | CSRF, 9 store mutexes, MCP rate limit, scope guard | 11 | +59/-3 |

**Total: 9 commits, 35 files, +812/-201 lines**

---

## Tier 2 — Data Integrity (completed 2026-03-28)

### Scope

| Partition | Batches | Files | Status |
|-----------|---------|-------|--------|
| C: Data Stores | C1-C4 | 21 store pairs (hpp+cpp) | Complete |
| F: Server Infrastructure | F1-F4 | server.cpp (11.4K LOC), NVD (6), patch_manager (2) | Complete |
| I: Gateway Erlang | I1-I4 | 18 .erl files | Complete |

**Agents used:** security-guardian (×4), architect, performance, happy-path, unhappy-path, consistency-auditor, chaos-injector
**Invocations:** ~10 agent invocations across Gates 2-5

### Tier 2 Finding Register

#### CRITICAL (4 found, 4 fixed)

| ID | Finding | File | Fix |
|----|---------|------|-----|
| G2-SEC-C1-001 | TagStore mutex declared but never locked | tag_store.cpp | Added shared_lock/unique_lock to all methods + _impl variants |
| G2-SEC-C1-002 | DiscoveryStore mutex declared but never locked | discovery_store.cpp | Added shared_lock/unique_lock to all methods |
| G2-SEC-C2-001 | InstructionStore mutex declared but never locked | instruction_store.cpp | Added shared_lock/unique_lock to all methods + _impl variants |
| G2-SEC-C2-002 | DeploymentStore mutex declared but never locked | deployment_store.cpp | Added shared_lock/unique_lock to all methods + _impl variants |

#### HIGH — Security & Concurrency (17 found, 10 fixed)

| ID | Finding | File | Fix |
|----|---------|------|-----|
| G2-SEC-C1-003 | ResponseStore cleanup thread bypasses mutex | response_store.cpp | Wrapped cleanup DELETE in unique_lock |
| G2-SEC-C1-004 | AuditStore cleanup thread bypasses mutex | audit_store.cpp | Wrapped cleanup DELETE in unique_lock |
| G2-SEC-C1-005 | ResponseStore sqlite3_step return unchecked in store() | response_store.cpp | Documented; see G4-UHP-T2-001 |
| G2-SEC-C1-006 | AuditStore sqlite3_step return unchecked in log() | audit_store.cpp | Documented; see G4-UHP-T2-001 |
| G2-SEC-C3-001 | ManagementGroupStore most methods lack mutex | management_group_store.cpp | Pre-existing from Tier 1 (partial) |
| G2-SEC-C4-001 | QuarantineStore mutex declared but never locked | quarantine_store.cpp | Added shared_lock/unique_lock + _impl |
| G2-SEC-C4-002 | QuarantineStore quarantine_device TOCTOU | quarantine_store.cpp | Fixed: check+insert atomic under lock |
| G2-SEC-C2-003 | DeploymentStore cancel_job TOCTOU | deployment_store.cpp | Fixed: check+update atomic under lock |
| G2-SEC-C4-006 | WebhookStore detached threads use-after-free risk | webhook_store.cpp | Documented; needs thread pool refactor |
| G2-SEC-C2-004 | InstructionQuery.limit no upper bound | instruction_store.cpp | Documented |
| G2-SEC-C2-005 | list_sets() no LIMIT clause | instruction_store.cpp | Documented |
| G2-SEC-C2-006 | list_jobs() no LIMIT clause | deployment_store.cpp | Documented |
| G2-SEC-I2-001 | ETS take_pending TOCTOU race | yuzu_gw_registry.erl | Documented; fix: use ets:take/2 |
| G2-SEC-I3-004 | Empty agent_ids broadcasts to entire fleet | yuzu_gw_router.erl | Documented; needs safety guard |
| G2-SEC-I3-009 | Dev config ships plaintext gRPC on 0.0.0.0 | sys.config | Documented |
| G2-SEC-I3-010 | No app-level auth on management gRPC | all services | Documented; mTLS in prod |
| G2-SEC-I1-001 | Env variable integers no range validation | yuzu_gw_app.erl | Documented |

#### HIGH — Architecture (3 found, 3 fixed)

| ID | Finding | File | Fix |
|----|---------|------|-----|
| G3-ARCH-T2-001 | server.cpp god object (11.4K LOC, 27 stores) | server.cpp | **Fixed**: decomposed to 4.4K LOC + 24 extracted files |
| G3-ARCH-T2-002 | Shared instruction DB fragile lifetime | server.cpp | **Fixed**: InstructionDbPool RAII wrapper |
| G3-ARCH-T2-003 | Gateway proto missing stagger/delay fields | agent.proto | **Fixed**: synced gateway proto from canonical |

#### HIGH — Performance (5 found, 0 fixed — documented)

| ID | Finding | File | Notes |
|----|---------|------|-------|
| G3-PERF-T2-003 | TagStore.set_tag recompiles SQL per call | tag_store.cpp | Pre-compile at construction |
| G3-PERF-T2-004 | AgentRegistry.touch_activity exclusive lock on heartbeat | server.cpp | Switch to shared_mutex |
| G3-PERF-T2-005 | ExecutionTracker recursive_mutex, all exclusive | execution_tracker.cpp | Switch to shared_mutex |
| G3-PERF-T2-001/002 | TagStore/InstructionStore unlocked (dup of CRITICAL) | — | Fixed above |
| G2-SEC-F3-001 | NvdDatabase no thread safety | nvd_db.cpp | **Fixed**: added shared_mutex + busy_timeout |

#### HIGH — Correctness & Resilience (Gate 4)

| ID | Finding | File | Notes |
|----|---------|------|-------|
| G4-UHP-T2-001 | sqlite3_step return unchecked across all stores | All stores | Documented; needs systematic fix |
| G4-UHP-T2-002 | Cleanup threads continue on persistent DB failure | response/audit_store | Documented; needs backoff |
| G4-UHP-T2-003 | No DB integrity check on startup | All stores | Documented; add PRAGMA quick_check |
| G4-CON-T2-003 | Gateway heartbeat drops pending_commands | yuzu_gw_agent_service | Documented; architectural decision |
| G4-CON-T2-004 | Gateway ListAgents omits platform/agent_version | yuzu_gw_mgmt_service | Documented |

#### MEDIUM — Summary (53 total, see gate outputs for full details)

Key categories:
- **Unbounded queries** (12 stores): Missing LIMIT clauses, no pagination support
- **Consistency gaps** (12): Path canonicalization, mutex type, error return types, ID generation
- **Gateway**: Supervision strategy, heartbeat buffer drops, router fanout serialization, backpressure silent drops
- **Server infra**: Detached threads (×2), gRPC message size, NVD LIKE wildcard injection, EventBus lock-under-callback
- **Data integrity**: FK enforcement inconsistent, TOCTOU in ProductPackStore, missing composite indexes

#### LOW — Summary (~35 findings, not itemized)

Categories: retention policies, input validation, helper duplication, naming inconsistencies, informational observations.

### Tier 2 Chaos Scenarios (Gate 5)

| ID | Severity | Chain | Status |
|----|----------|-------|--------|
| CHAOS-T2-001 | CRITICAL | Disk-full silent data loss: all 20+ stores silently discard writes | Constituent findings fixed (mutexes); sqlite3_step checking still needed |
| CHAOS-T2-002 | CRITICAL | Corrupt DB → ghost server: server starts, serves empty data | Documented; needs PRAGMA quick_check gate |
| CHAOS-T2-003 | HIGH | NTP jump → approval wipe + schedule skip + premature cleanup | Documented |
| CHAOS-T2-004 | HIGH | Gateway router crash → 100+ commands hang | Documented |
| CHAOS-T2-005 | HIGH | Agent reconnect storm → dropped heartbeats + stale state | Documented |

### Tier 2 Fix Summary

| Files Modified | Change | Finding IDs |
|---------------|--------|-------------|
| tag_store.hpp/cpp | Added mutex locks to all 13 methods + 2 _impl variants | C1-001 |
| discovery_store.cpp | Added mutex locks to all 5 methods | C1-002 |
| instruction_store.hpp/cpp | Added mutex locks to all 10 methods + 2 _impl variants | C2-001 |
| deployment_store.hpp/cpp | Added mutex locks to all 5 methods + 2 _impl variants, atomic cancel_job | C2-002, C2-003 |
| quarantine_store.hpp/cpp | Added mutex locks to all 5 methods + 1 _impl variant, atomic quarantine | C4-001, C4-002 |
| nvd_db.hpp/cpp | Added shared_mutex + busy_timeout + locks to all 8 methods + 2 _impl variants | F3-001, CON-T2-001/002 |
| response_store.cpp | Wrapped cleanup thread DELETE in unique_lock | C1-003 |
| audit_store.cpp | Wrapped cleanup thread DELETE in unique_lock | C1-004 |
| gateway/priv/proto/.../agent.proto | Synced from canonical (added stagger_seconds, delay_seconds) | ARCH-T2-003 |

---

## Tier 3 — Functional Correctness (completed 2026-03-28)

### Scope

| Partition | Batches | Files | Status |
|-----------|---------|-------|--------|
| G: Agent Core | G1-G3 | 23 files (agent, identity, certs, cloud, plugins, triggers, KV, updater, utils) | Complete |
| H: Plugins | H1-H8 | 44 plugin dirs, ~54 files | Complete |
| J: Proto & SDK | J1 | 4 .proto + 7 SDK headers | Complete |

**Agents used:** security-guardian (×9), architect, performance, happy-path, unhappy-path, consistency-auditor, chaos-injector
**Invocations:** ~14 agent invocations across Gates 2-5

### Tier 3 Finding Register

#### CRITICAL (13 found, 4 fixed)

| ID | Finding | File | Fix |
|----|---------|------|-----|
| G2-SEC-G1-001 | Enrollment token visible in process args (`/proc/pid/cmdline`) | main.cpp:97 | Documented; support token-from-file or env-only |
| G2-SEC-G1-002 | Private key blob not zeroed after cert store export (Windows) | cert_store.cpp:213 | **Fixed**: `SecureZeroMemory` on CNG + CAPI intermediate blobs |
| G2-SEC-G2-001 | No code signing on plugins — allowlist is optional | plugin_loader.cpp:242 | Documented; make allowlist mandatory in production |
| G2-SEC-G2-002 | No version downgrade protection in OTA updater | updater.cpp:253 | **Fixed**: `compare_semver()` rejects older/equal versions |
| G2-SEC-H3-001 | Command injection in discovery_plugin `ping_host()` via `system()` | discovery_plugin.cpp:321 | Documented; add `inet_pton` validation or use `execvp` |
| G2-SEC-H3-002 | SSRF via DNS rebinding in http_client — TOCTOU on resolved IP | http_client_plugin.cpp:106 | Documented; pin resolved IP for connection lifetime |
| G2-SEC-H3-003 | Arbitrary file write via path traversal in http_client download | http_client_plugin.cpp:426 | **Fixed**: path traversal rejection + parent canonicalization |
| G2-SEC-H4-001 | Command injection in certificates_plugin Linux (`parse_openssl_output`) | certificates_plugin.cpp:327 | **Fixed**: `is_safe_path()` validation before shell interpolation |
| G2-SEC-H4-002 | Command injection in certificates_plugin macOS `delete_cert` thumbprint | certificates_plugin.cpp:698 | **Fixed**: `is_valid_thumbprint()` hex-only validation |
| G2-SEC-H4-003 | Command injection in certificates_plugin macOS PEM echo to openssl | certificates_plugin.cpp:554 | **Fixed**: temp file approach replaces `echo '...'` pipe |
| G2-SEC-H4-004 | Certificate deletion from ROOT store without authorization | certificates_plugin.cpp:772 | Documented; require confirm + RBAC elevation |
| G2-SEC-H5-001 | TOCTOU in filesystem write allows base_dir escape for new files | filesystem_plugin.cpp:1505 | Documented; canonicalize parent, reconstruct path |
| G2-SEC-H8-001 | script_exec unbounded output → agent OOM | script_exec_plugin.cpp:107 | **Fixed**: 16 MiB hard output cap (`kMaxOutputBytes`) |

#### HIGH — Security (36 found, 2 fixed)

| ID | Finding | File |
|----|---------|------|
| G2-SEC-G1-003 | Identity DB (agent.db) no file permission restrictions | identity_store.cpp:111 |
| G2-SEC-G1-004 | No validation of CLI-provided agent_id format | identity_store.cpp:106 |
| G2-SEC-G1-005 | Cert discovery doesn't verify private key file permissions | cert_discovery.cpp:37 |
| G2-SEC-G1-006 | IMDS token unsanitized in HTTP headers (CRLF injection) | cloud_identity.cpp:209 |
| G2-SEC-G2-003 | TOCTOU between SHA-256 hash check and dlopen | plugin_loader.cpp:253 |
| G2-SEC-G2-004 | Plugin dir traversal via symlinks in recursive scan | plugin_loader.cpp:236 | **Fixed**: symlink rejection before load |
| G2-SEC-G2-005 | `dispatch_` callback read without lock in `fire_trigger` | trigger_engine.cpp:144 |
| G2-SEC-G2-006 | Updater no download size limit — disk fill DoS | updater.cpp:330 | **Fixed**: 512 MiB hard cap (`kMaxDownloadBytes`) |
| G2-SEC-G2-007 | Updater hash from same server as binary — single trust point | updater.cpp:264 |
| G2-SEC-H3-004 | HTTP GET response body unbounded in memory | http_client_plugin.cpp:309 | **Fixed**: capped at kMaxDownloadSize (100 MiB) |
| G2-SEC-H3-005 | SSRF bypass via redirect following (httplib defaults on) | http_client_plugin.cpp:234 |
| G2-SEC-H3-006 | SSRF IP check missing 100.64/10, 198.18/15 ranges | http_client_plugin.cpp:62 | **Fixed**: added CGNAT + benchmarking ranges |
| G2-SEC-H3-007 | WiFi interface name injection into shell command | wifi_plugin.cpp:196 |
| G2-SEC-H3-008 | Chargen 1ms min rate enables CPU/network exhaustion | chargen_plugin.cpp:101 |
| G2-SEC-H4-005 | Command injection in bitlocker via crafted device name | bitlocker_plugin.cpp:129 |
| G2-SEC-H4-006 | Quarantine bypass via ESTABLISHED,RELATED existing connections | quarantine_plugin.cpp:288 |
| G2-SEC-H4-007 | macOS quarantine overwrites entire pf ruleset | quarantine_plugin.cpp:435 |
| G2-SEC-H4-008 | Quarantine temp file race in /tmp (macOS) | quarantine_plugin.cpp:412 |
| G2-SEC-H4-009 | IOC domain check only searches /etc/hosts (false negatives) | ioc_plugin.cpp:666 |
| G2-SEC-H4-010 | Event logs sanitizer bypass allows filtered PowerShell injection | event_logs_plugin.cpp:94 |
| G2-SEC-H4-011 | No thumbprint hex validation in certificates plugin | certificates_plugin.cpp:756 | **Fixed** (with H4-002) |
| G2-SEC-H5-002 | content_dist upload_file reads arbitrary files without mandatory base_dir | content_dist_plugin.cpp:483 |
| G2-SEC-H5-003 | No hash re-verification before executing staged content | content_dist_plugin.cpp:441 | **Fixed**: re-verify hash via `expected_hash` param before execute |
| G2-SEC-H5-004 | Staging directory in /tmp with weak permissions | content_dist_plugin.cpp:51 | **Fixed**: `owner_all` perms on Unix staging dir |
| G2-SEC-H6-001 | Unsanitized username in shell command (Linux lastlog) | users_plugin.cpp:366 |
| G2-SEC-H7-001 | `command_exists()` uses `system()` — injection hazard | installed_apps_plugin.cpp:58 |
| G2-SEC-H8-002 | script_exec child inherits full parent environment (secrets) | script_exec_plugin.cpp:205 | **Fixed**: sanitized env (PATH,HOME,USER,LANG,LC_ALL,TERM,TZ only) |
| G2-SEC-H8-003 | script_exec no working directory restriction | script_exec_plugin.cpp:160 |
| G2-SEC-H8-004 | script_exec POSIX timeout doesn't kill process group | script_exec_plugin.cpp:239 | **Fixed**: `setsid()` + `kill(-pid, SIGKILL)` kills entire group |
| G2-SEC-H8-005 | WMI null pointer crash in get_instance error paths | wmi_plugin.cpp:230 |
| G2-SEC-H8-006 | WMI `is_select_only` trivially bypassable | wmi_plugin.cpp:68 |
| G2-SEC-J1-001 | Prometheus label injection — no escaping | metrics.hpp:28 | **Fixed**: escape `\`, `"`, `\n` in label values |
| G2-SEC-J1-002 | No null-check on plugin descriptor fields after load | plugin_loader.cpp:207 |
| G2-SEC-J1-003 | Empty `agent_ids` = broadcast — dangerous proto3 default | management.proto:60 |
| G3-ABI-J1-001 | No `reserved` field declarations in any proto message | All .proto |
| G3-ABI-J1-002 | Plugin descriptor struct has no padding/struct_size for ABI evolution | plugin.h:74 |

#### HIGH — Architecture & Correctness (Gate 3-4, 7 found, 3 fixed)

| ID | Finding | File | Fix |
|----|---------|------|-----|
| G3-ARCH-T3-001 | TriggerEngine never wired into agent — registration stubs silently succeed | agent.cpp:348 | Documented |
| G3-ARCH-T3-002 | Stagger/delay sleep blocks thread pool workers — DoS on staggered dispatch | agent.cpp:908 | **Fixed**: capped stagger 5min, delay 5min, total 10min max |
| G3-ARCH-T3-005 | Double plugin shutdown on normal exit — ABI contract violation | agent.cpp:480,1030 | **Fixed**: `plugins_.clear()` after explicit shutdown prevents double-call |
| G4-UHP-T3-001 | No retry/reconnect on registration or stream failure — agent exits permanently | agent.cpp:667 | **Fixed**: reconnect loop with exponential backoff (1s to 5min) |
| G4-UHP-T3-002 | No command execution timeout — hanging plugin consumes worker forever | agent.cpp:972 | Documented; plugins handle own timeouts |
| G4-UHP-T3-007 | gRPC stream break loses all in-flight results; no reconnect | agent.cpp:840 | **Fixed**: reconnect loop re-registers and re-subscribes |
| G4-CON-T3-003 | Trigger registration stubs return success but do nothing (dup of ARCH-T3-001) | agent.cpp:348 | Documented |
| G4-CON-T3-005 | Shared `plugin_ctx_` — all KV writes go to last-initialized plugin's namespace | agent.cpp:444 | **Fixed**: per-plugin `PluginContextImpl` with correct `plugin_name` |

#### HIGH — Performance (Gate 3, 1 found, 1 fixed)

| ID | Finding | File | Fix |
|----|---------|------|-----|
| G3-PERF-T3-003 | Histogram bucket double-counting — all histogram metrics incorrect | metrics.hpp:92 | **Fixed**: observe() now increments only first matching bucket |

#### MEDIUM — Summary (52 total, by category)

Key categories:
- **Input validation** (14): Tag key allowlist unenforced, thumbprint hex, IP validation, service name @, registry username path traversal, WMI unbounded results, ping count, regex DoS bypass
- **Resource exhaustion** (10): Unbounded output in 8+ plugins, KV store no quota, DNS cache unbounded, chargen rate
- **Credential hygiene** (4): Enrollment token not zeroed, key path disclosed, child env inheritance, IMDS token unsanitized
- **TOCTOU / symlinks** (5): Filesystem write, cert deletion, atomic write temp name, file trigger mtime
- **Lock contention / threading** (6): Metrics triple-lock, tags plugin no mutex, trigger deadlock risk, COM init per-call
- **Protocol / ABI** (5): secure_zero platform coverage, ScopeCondition.op is string, RUNNING=0 default, no calling convention annotation, context lifetime undocumented
- **Information disclosure** (4): WiFi BSSID geolocation, proxy credentials, DNS cache browsing history, process cmdlines in Echo state
- **HTTP/staging** (4): Plaintext HTTP downloads, BCrypt handle leak, predictable temp file, staging dir permissions

#### LOW — Summary (~45 findings, not itemized)

Categories: documentation gaps, dead code, informational observations, latent risks from shell command patterns with hardcoded inputs, minor inconsistencies, algorithm inefficiencies.

### Tier 3 Chaos Scenarios (Gate 5)

| ID | Severity | Chain | Findings | Status |
|----|----------|-------|----------|--------|
| CHAOS-T3-001 | CRITICAL | Full agent takeover via malicious plugin injection | G2-001+003+004, G2-002 | All UNFIXED |
| CHAOS-T3-002 | CRITICAL | RCE via certificate plugin cmd injection (3 vectors) | H4-001/002/003/004, UHP-002 | **Partially fixed** — 3/5 constituents (cmd injection) fixed |
| CHAOS-T3-003 | CRITICAL | Persistent compromise: SSRF + content staging + file write | H3-002/003/005, H5-003/004 | **Partially fixed** — H3-003 (path traversal) fixed |
| CHAOS-T3-004 | HIGH | Fleet DoS: thread pool exhaustion + OOM + KV corruption | ARCH-002, H8-001, UHP-002, CON-005 | **Partially fixed** — CON-005 (KV namespace) fixed |
| CHAOS-T3-005 | CRITICAL | Silent fleet downgrade + credential theft | G2-002, G1-001, H5-001 | All UNFIXED |
| CHAOS-T3-006 | HIGH | Agent identity theft: key material + SSRF + no reconnect | G1-002, H3-002, UHP-001 | All UNFIXED |
| CHAOS-T3-007 | HIGH | Cascading fleet blackout: server interruption → all agents exit | UHP-001, ARCH-002, UHP-002 | All UNFIXED |
| CHAOS-T3-008 | HIGH | Trust anchor destruction: unauthorized cert purge + no reconnect | H4-004, H4-001/002/003, UHP-001 | **Partially fixed** — 3/5 constituents (cmd injection) fixed |
| CHAOS-T3-009 | HIGH | MCP approval bypass via parameter injection chain | H3-003, CON-005, H3-002 | **Partially fixed** — H3-003 + CON-005 fixed (2/3) |

### Fix Priority Matrix

| Priority | Findings | Chaos Scenarios Broken |
|----------|----------|----------------------|
| **P0 (fix now)** | H4-001/002/003 (cmd injection in certs) | T3-002, T3-008 | **FIXED** |
| **P0 (fix now)** | UHP-T3-001 (no reconnect) | T3-006, T3-007, T3-008 | **FIXED** |
| **P0 (fix now)** | H3-003 (path traversal in download) | T3-003, T3-009 | **FIXED** |
| **P0 (fix now)** | CON-T3-005 (shared plugin_ctx_ KV corruption) | T3-004, T3-009 | **FIXED** |
| **P1 (before release)** | G2-003 (TOCTOU hash-to-dlopen) | T3-001 | Unfixed |
| **P1 (before release)** | ARCH-T3-002 (stagger blocks workers) | T3-004, T3-007 | **FIXED** |
| **P1 (before release)** | G2-002 (no downgrade protection) | T3-001, T3-005 | **FIXED** |
| **P1 (before release)** | H3-002 (DNS rebinding SSRF) | T3-003, T3-006, T3-009 | Unfixed |
| **P1 (before release)** | PERF-T3-003 (histogram double-count) | Data correctness | **FIXED** |
| **P2 (this sprint)** | UHP-T3-002 (no command timeout) | T3-002, T3-004, T3-007 | Unfixed |
| **P2 (this sprint)** | G1-002 (key not zeroed) | T3-006 | **FIXED** |
| **P2 (this sprint)** | H5-003/004 (staging verification) | T3-003 | **FIXED** |
| **P2 (this sprint)** | H8-001 (script_exec OOM) | T3-004 | **FIXED** |

### Tier 3 Commits (2026-03-28 governance session)

| Commit | Description | Files | Changes |
|--------|-------------|-------|---------|
| (pending) | Fix 10 Tier 3 findings: KV isolation, histogram, cmd injection, path traversal, label escaping, double shutdown | 6 | +281/-32 |

**Files modified:**
- `agents/core/src/agent.cpp` — Per-plugin `PluginContextImpl` for KV namespace isolation; double-shutdown prevention via `plugins_.clear()`; per-plugin context in shutdown paths
- `agents/plugins/certificates/src/certificates_plugin.cpp` — `is_valid_thumbprint()` hex validation; `is_safe_path()` shell metachar check; temp file for macOS PEM parsing; thumbprint validation at action entry points
- `agents/plugins/http_client/src/http_client_plugin.cpp` — Path traversal rejection (`..` components); parent directory canonicalization before file write
- `sdk/include/yuzu/metrics.hpp` — Histogram `observe()` fixed to increment only first matching bucket; `escape_label_value()` for Prometheus label injection prevention
- `tests/unit/test_metrics.cpp` — Updated histogram test expectations to match corrected bucket counting

---

## Remaining Work: Tier 4

### Tier 4 — Coverage & Completeness

| Partition | Batches | Files | Focus |
|-----------|---------|-------|-------|
| K: Tests | K1-K6 | 80 test files | Coverage gaps, test isolation, assertion quality |
| L: Docs, YAML, Deploy, CI | L1-L4 | 103 files | 24 undocumented REST endpoints, YAML def sync, CI coverage |

**Estimated: ~20 agent invocations, ~1 hour**

### Execution Notes for Future Sessions

1. **Build environment:** builddir is at `/mnt/data/builddir`. Root filesystem (`/dev/sda1`) has limited space — always build on `/mnt/data`. vcpkg tools at `/root/Yuzu/vcpkg_installed/x64-linux/tools/{protobuf,grpc}/`.
2. **Test baseline:** 6/6 suites pass (gateway CT integration test may skip if no upstream). 30,171 assertions, 350 test cases.
3. **RE2 dependency:** Added to `server/core/meson.build` via cmake method. Already installed as gRPC transitive dep.
4. **Erlang gateway:** Pre-existing rebar3/OTP version issues on this box. Gateway compiles but CT suite needs live upstream.
5. **Rate limits:** Session hit Claude API rate limits after ~50 agent invocations. Plan for 2-3 sessions to complete Tiers 2-4.
6. **Documentation debt:** The 10 HIGH doc findings (24 undocumented endpoints) should be addressed in a dedicated docs session, not interleaved with code fixes.
7. **Tier 3 volume:** 142 Gate 2 + 16 Gate 3 + 14 Gate 4 = ~170 findings (after dedup). 13 CRITICAL, ~43 HIGH, ~52 MEDIUM, ~45 LOW. Fix P0 findings first — they break 7 of 9 chaos scenarios.

---

## Session 2 Fix Summary (2026-03-28)

### Findings Fixed: 27

| Priority | Fixed | Category |
|----------|-------|----------|
| P0 | 1 | Agent reconnect loop with exponential backoff |
| P1 | 4 | Downgrade protection, stagger cap, symlink rejection, download size limit |
| P2 | 6 | Key zeroing, script_exec OOM/env/process group, staging hash+perms |
| Tier 1 MEDIUM | 13 | RBAC validation, OIDC cap, token IDs, CORS, exec limits, CEL depth+concat+lexer, scope NOT depth, MCP RBAC |
| Tier 3 HIGH | 3 | SSRF ranges, HTTP GET body cap, response body limit |

### Files Modified: 14

| File | Changes |
|------|---------|
| agents/core/src/agent.cpp | Reconnect loop, stagger cap, conditional plugin shutdown |
| agents/core/src/cert_store.cpp | SecureZeroMemory on CNG + CAPI key blobs |
| agents/core/src/plugin_loader.cpp | Symlink rejection before dlopen |
| agents/core/src/updater.cpp | compare_semver(), download size cap (512 MiB) |
| agents/plugins/content_dist/src/content_dist_plugin.cpp | Staging dir perms, hash re-verify before exec |
| agents/plugins/http_client/src/http_client_plugin.cpp | CGNAT/benchmark IP ranges, response body cap |
| agents/plugins/script_exec/src/script_exec_plugin.cpp | 16 MiB output cap, setsid+kill(-pid), env sanitization |
| server/core/src/api_token_store.cpp | 24-char token ID, mcp_tier validation |
| server/core/src/cel_eval.cpp | Depth 64→16, string concat cap, Error token, DepthGuard on NOT paths |
| server/core/src/mcp_server.cpp | RBAC on server/health resource |
| server/core/src/oidc_provider.cpp/hpp | Pending challenges cap (1000), cleanup_expired_states_locked() |
| server/core/src/rbac_store.cpp | Effect "allow"/"deny" validation |
| server/core/src/rest_api_v1.cpp | Exec stats limit clamp, CORS origin reflection removed, inventory cap |

### Chaos Scenarios Impact

| Scenario | Before | After |
|----------|--------|-------|
| CHAOS-T3-004 (Fleet DoS) | Partially fixed (1/4) | Mostly fixed (3/4) — stagger cap + OOM cap + reconnect |
| CHAOS-T3-005 (Silent downgrade) | All UNFIXED | Partially fixed — downgrade blocked |
| CHAOS-T3-006 (Identity theft) | All UNFIXED | Partially fixed — key zeroing + reconnect |
| CHAOS-T3-007 (Fleet blackout) | All UNFIXED | Mostly fixed — reconnect + stagger cap |
| CHAOS-T3-008 (Trust anchor destruction) | Partially fixed (3/5) | Mostly fixed — reconnect added |

---

## Tier 4 — Coverage & Completeness (completed 2026-03-28)

### Scope

| Partition | Batches | Files | Status |
|-----------|---------|-------|--------|
| K: Tests | K1-K6 | 82 test files (28,108 lines) | Complete |
| L: Docs, YAML, Deploy, CI | L1-L4 | 233+ files | Complete |

**Agents used:** quality-engineer, docs-writer, consistency-auditor
**Invocations:** 3 agent invocations (Gate 2)

### K: Test Coverage Analysis

#### CRITICAL — Untested Core Components (4 findings)

| ID | Finding | File | Lines |
|----|---------|------|-------|
| G2-QE-K1-001 | REST API v1 handler layer has zero tests | rest_api_v1.cpp | 1,887 |
| G2-QE-K1-002 | Workflow engine state machine has zero tests | workflow_engine.cpp | 949 |
| G2-QE-K1-003 | ProductPack content model store has zero tests | product_pack_store.cpp | 680 |
| G2-QE-K1-004 | Agent core orchestration has zero tests | agent.cpp | 1,160 |

#### HIGH — Untested Stores & Components (6 findings)

| ID | Finding | File | Lines |
|----|---------|------|-------|
| G2-QE-K2-001 | InventoryStore has zero tests | inventory_store.cpp | 276 |
| G2-QE-K2-002 | DeploymentStore has zero tests | deployment_store.cpp | 282 |
| G2-QE-K2-003 | DiscoveryStore has zero tests | discovery_store.cpp | 247 |
| G2-QE-K2-004 | RuntimeConfigStore has zero tests | runtime_config_store.cpp | 225 |
| G2-QE-K2-005 | DirectorySync (AD/Entra) has zero tests | directory_sync.cpp | 1,013 |
| G2-QE-K2-006 | test_plugin_loader.cpp is a 22-line stub | test_plugin_loader.cpp | 22 |

#### HIGH — Plugin Test Coverage (1 finding)

| ID | Finding | Notes |
|----|---------|-------|
| G2-QE-K3-001 | 38 of 45 plugins have zero test coverage | Only 7 plugins tested (filesystem, echo, vuln_scan, http_client, content_dist, interaction, agent_logging, storage, registry, wmi — descriptor-level only for most) |

#### MEDIUM — Thin Tests (2 findings)

| ID | Finding | File | Lines |
|----|---------|------|-------|
| G2-QE-K4-001 | test_plugin_loader only tests empty/nonexistent dirs | test_plugin_loader.cpp | 22 |
| G2-QE-K4-002 | test_https_config only tests config defaults, not TLS | test_https_config.cpp | 92 |

**Test baseline:** 82 files, 28,108 lines, 350 test cases, 30,171 assertions. Server stores well-tested (14/19). Engines well-tested (4/5). Gateway has excellent coverage (22 test files).

### L: Documentation Audit

#### HIGH — Undocumented REST API Endpoints (1 finding, FIXED)

| ID | Finding | Fix |
|----|---------|-----|
| G2-DOC-L1-001 | 25 of 52 v1 REST endpoints undocumented (48%) | **Fixed**: all 25 endpoints documented in `docs/user-manual/rest-api.md` |

**Undocumented endpoint categories (now documented):**
1. Inventory (4 endpoints): tables, per-agent, query, evaluate
2. Execution Statistics (3 endpoints): fleet summary, per-agent, per-definition
3. Device Tokens (3 endpoints): list, create, revoke
4. Software Deployment (7 endpoints): packages CRUD, deployments CRUD, start/rollback/cancel
5. License Management (4 endpoints): list, activate, remove, alerts
6. Infrastructure (2 endpoints): topology, fleet statistics
7. File Retrieval (1 endpoint): agent file upload receiver
8. OpenAPI Spec (1 endpoint): self-describing API schema

#### MEDIUM — Undocumented Legacy/Settings Endpoints (~44 endpoints)

| ID | Finding | Notes |
|----|---------|-------|
| G2-DOC-L2-001 | ~44 legacy/settings endpoints undocumented | Product packs, notifications, chargen/procfetch, entire settings sub-API (~27 routes). Settings endpoints are HTMX-driven (not for external automation). |

#### LOW — Documentation Observations

- 0 phantom/stale docs (every documented endpoint confirmed in code)
- Operations docs are thin: disaster recovery (85 lines), capacity planning (80 lines)
- No Kubernetes deployment manifests

### L: YAML Consistency Audit

| ID | Finding | Severity |
|----|---------|----------|
| G2-CON-L3-001 | All 44 agent plugins have complete YAML definitions — 0 action mismatches | ✓ Clean |
| G2-CON-L3-002 | All parameter names/types consistent between YAML and code (6 plugins deep-dived) | ✓ Clean |
| G2-CON-L3-003 | 0 orphaned definitions (10 server-side YAMLs are legitimate) | ✓ Clean |
| G2-CON-L3-004 | Server-side `plugin:` naming inconsistency: `server` vs `server_internal` vs `_server` | LOW |

### Tier 4 Summary

| Category | Total Findings | CRITICAL | HIGH | MEDIUM | LOW |
|----------|---------------|----------|------|--------|-----|
| Test coverage | 13 | 4 | 7 | 2 | 0 |
| Documentation | 2 | 0 | 1 (fixed) | 1 | 2 |
| YAML consistency | 1 | 0 | 0 | 0 | 1 |
| **Total** | **16** | **4** | **8** | **3** | **3** |

### Tier 4 Fix

| File | Change | Finding ID |
|------|--------|------------|
| docs/user-manual/rest-api.md | Documented 25 undocumented v1 REST endpoints across 8 sections + updated ToC | G2-DOC-L1-001 |

---

## Cross-Tier Summary (All Tiers)

| Tier | Scope | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| 1: Auth, API, Engines, MCP | 39 files | 1 | 25 | 25 | ~40 | 39 fixed |
| 2: Data Stores, Server, Gateway | 57 files | 4 | 25 | 53 | ~35 | 18 fixed |
| 3: Agent, Plugins, Proto/SDK | 81 files | 13 | 44 | 52 | ~45 | 20 fixed |
| 4: Tests, Docs, YAML, CI | 315 files | 4 | 8 | 3 | 3 | 1 fixed |
| **Total** | **492 files** | **22** | **102** | **133** | **~123** | **78 fixed** |

**Total findings: ~380. Total fixed: 78. Fix rate: 20% (code fixes) + doc fixes.**

Test coverage gaps (Tier 4 CRITICALs) are by nature write-new-tests work, not bug fixes. The codebase's security and correctness posture is substantially improved by the Tier 1-3 fixes.
