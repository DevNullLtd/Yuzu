# SYNTHESIS — #3937 MCP engine-principal mutation twins fail closed

VERDICT: **PASS** (both reviewers PASS; no CRITICAL/HIGH). Panel: Codex (empirical, compiled) + Kimi-K3 (static). Adjudicated by Opus against real code.

## Findings (ranked)
1. **[CDX-001 / K6] MEDIUM — throwing audit bypasses the 503/A4 envelope (BOTH reviewers).** The 8 twins called the domain `audit_fn` directly (only handling a `false` return), so a *throwing* audit sink escaped before the 503 — while the REST twins are throw-safe via `emit_behavioral_audit`→`try_persist_audit`. Both confirm the SECURITY property survives (throw precedes payload → no success, no secret leak); the gap is the A4 contract shape on the throw path + REST/MCP asymmetry. **FIXED**: routed all 8 domain success audits through `yuzu::server::detail::try_persist_audit` (throw → false → the existing fail-closed 503 fires). + throwing-audit regression test.
2. **[CDX-003 / K7] MEDIUM — stale set-and-proceed authorities (BOTH).** `audit-log.md:184` said "MCP signals non-fatally"; the plugin-config source comment scoped "~20 pre-existing" without noting #3937; the mcp-server.md bullet overclaimed `mcp_audit("error")` "records server-side". **ALL FIXED** (audit-log.md corrected; comment updated; bullet reworded to best-effort + generic counter/warn log).
3. **[CDX-002 / K8] LOW (adjudicated) — served kTools[] descriptions omit the audit-failure recovery.** Codex MEDIUM; Kimi adjudicated LOW because the A4 error envelope ALREADY carries the per-tool remediation at failure time — so the omission costs anticipatory context, not recovery guidance. Opus concurs LOW → **FILE** (A5 polish; not a defect).
4. **[K3-mint] LOW — mint 503 omits the non-secret token_id (deterministic reconciliation).** create-half REFUTED (caller-supplied id). mint-half is a LOW ergonomic improvement; the `a4_error` shape doesn't cleanly carry it → **FILE** (recovery via "list" already works).
5. **[K4] LOW — mcp_audit("success") return discarded on the success path.** The DOMAIN mutation row (what ADR-1005 governs) IS gated; the generic invocation row is secondary. The bullet already scopes to "their audit row". No change (documented scope is correct).

## Refuted / withdrawn (verified)
- **K2 REFUTED** (Codex empirical): rotate is principal+session-scoped, does NOT require the orphaned credential's secret; re-serve within grace works (api_token_store.hpp:350-374 + tests). The mint/rotate remediation is correct.
- **K3-create REFUTED**: create_engine_principal takes a caller-supplied principal_id (the caller knows it).
- **K1 WITHDRAWN** (Kimi): the 8 are the complete engine-principal mutation set (Codex full-file rg + docs).
- **K5 WITHDRAWN** (Kimi): the PR did update mcp-server.md/mcp.md/auth-architecture.md + tests (Kimi's bundle was mcp_server.cpp-only).

## Test note
Codex's `[audit_failclose]` run SKIPPED (no local Postgres in its sandbox); Opus ran them against PG :5433 — 11 cases pass. Empirical coverage exists.

## Fixes applied this round
CDX-001 (8 domain audits → try_persist_audit) + throwing-audit test · CDX-003 (3 doc/comment fixes). Follow-ups filed: CDX-002/K8 (kTools descriptions), K3-mint (token_id in 503).
