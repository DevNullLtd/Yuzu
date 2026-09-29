# SYNTHESIS — engine-principal REST audit-fail-closed (#2466/#2406)

VERDICT: **PASS** (both reviewers PASS; no BLOCK). All findings LOW. Panel: Codex (empirical, compiled+ran kernel tests) + Kimi-K3 (static). Adjudicated by Opus against the real code.

## Consolidated findings (ranked)

1. **[C1 / K8] LOW — changelog fragment says "fresh" credential (BOTH reviewers).** The `changelog.d/2466-*.security.md` line "rotate again for a fresh, audited credential" contradicts the corrected code + rest-api.md, which re-serve the SAME successor secret. Highest-provenance finding (Codex full-tree + Kimi code-half-verified). Winner: valid. → FIX (changelog wording).

2. **[K4] LOW — mint 503 "revoke+re-mint" ambiguous.** Kimi: principal-revoke → mint 409s "not active". Codex REFUTED: a credential-level revoke exists (`DELETE /api/v1/tokens/{token_id}`, rest_api_v1.cpp:314-322), so revoking the unusable credential leaves the principal active → mint succeeds. Adjudication: Codex is right the path EXISTS, but "revoke+re-mint" is ambiguous (which revoke?). → FIX by simplifying the message to the unambiguous "rotate" recovery (which works with the single orphan credential); drop "revoke+re-mint".

3. **[K2] LOW — confirm 503 "reconcile" implies re-confirm.** Kimi: confirm consumed the pending successor, so a retry fails. Codex: "reconcile" = a read per the surface contract, taste not defect. Adjudication: both right; the message is cheap to make more actionable. → FIX (message: "verify via GET; do not re-confirm").

4. **[K1] LOW (Kimi downgraded MEDIUM→LOW) — reads-proceed posture in-code visibility.** The rationale IS documented (auth-architecture.md:2975-2987 + rest-api.md, Codex verified) — the "undocumented exception" prong is refuted. Surviving residue: the 4 read sites `(void)` the bool with no site-level comment; a future author could copy the pattern onto a route needing fail-closed. → FIX (brief read-site posture comment). NOT touching the shared rest_audit.hpp summary line (out of scope; kernel serves many routes).

5. **[K6] LOW — Sec-Audit-Failed header on the 403 engine-session denial = audit-health oracle to the denied engine class.** Kimi: a compromised engine token learns audit is down + this probe left no row. Codex REFUTED: intentional shared signal, docs apply it to denials, suppressing makes the drop silent-on-that-response. ADJUDICATION (Opus): KEEP the header, document deliberate. Marginal exploit value — during an audit outage ALL engine-principal MUTATIONS fail closed fleet-wide, so a default-deny engine principal's "unaudited window" is limited to RBAC-constrained reads; uniform Sec-Audit-Failed semantics is a monitoring virtue; defenders get the server-side warn+metric regardless. → FIX (in-code note recording the deliberate accept + backstop), no behavior change.

## Refuted / non-issues (verified against code)
- **[K3] REFUTED** — a4_error (rest_a4_envelope_http.hpp:54-57) only sets correlation-id + builds JSON; does NOT touch Sec-Audit-Failed. Header survives (Codex read source; my `[audit_failclose]` tests assert it on the 503 and pass with PG).
- **[K5] deliberate** — confirm_metric("success") before the audit check is the #2404 policy (metric = store outcome, not HTTP). security-guardian round-1 cleared it; already commented in-code.
- **[K7] non-issue** — the `[audit_failclose]` tests are `[pg]`-gated (skip locally without a DSN, as in Codex's run); CI runs server tests WITH Postgres (`scripts/ci/ensure-postgres.sh`, CLAUDE.md: env-set→run/fail), and I ran all 6 + the 124 existing engine-principal cases against PG :5433 — all pass. Route-level coverage exists and runs in CI.

## What each reviewer ran
- Codex: `meson compile` PASS; `[rest][audit][helper]` 5/12 PASS; `[audit_failclose]` 6/6 SKIPPED (no local DSN); `git diff --check` PASS; read a4_error/MCP twin/docs/tests full-tree.
- Kimi: static over the diff + rest_audit.hpp + handler bodies; could not see docs/a4_error/tests/changelog (not in bundle) — hence K1/K3/K4/K8 gated on Codex testimony.
- Opus: adjudicated all against the real code; ran the PG-backed tests.

## Fixes to apply (all LOW, wording/comment only — no logic/behavior change)
C1/K8 changelog · K4 mint message · K2 confirm message · K1 read-site comment · K6 deliberate-note. No Gate-8 re-review triggered (substance already PASSed; changes are prose).
