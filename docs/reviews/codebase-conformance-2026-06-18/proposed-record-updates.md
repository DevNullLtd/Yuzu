# Proposed Record Updates — Conformance Audit 2026-06-18

Companion to [`register.md`](./register.md). These are **proposals, not applied edits.** They
correct the *records* where the audit found them out of step with the code. Scope per the
review brief: **draft the ADR / CLAUDE.md corrections**; the broader product-doc fixes are
included as proposals for your triage (not auto-applied), and confirmed *code-side* gaps are
flagged but **not** filed as issues.

Recurring theme: the records lag *behind* the code. The codebase is the source of truth here
far more often than the docs are — so most of these "catch the record up to reality".

---

## A. CLAUDE.md edits (in-scope record)

CLAUDE.md held up unusually well — only two genuine staleness items.

1. **Plugin count `44 → 47`** · `agent-01` · `CLAUDE.md:198`
   - Before: `agents/plugins/   44 plugins`
   - After:  `agents/plugins/   47 plugins`
   - Proof: `ls -d agents/plugins/*/ | wc -l` = **47**. (Update any other "44 plugins" mention to match.)

2. **Extend the PKI routed concern past PR5d to PR6 (subordinate-CA)** · `pki-16`
   - The PKI routed-concern paragraph currently ends the ladder at **PR5d**. `pki-architecture.md`
     marks PR6 subordinate-CA "in review", but the code is in fact wired (root-CSR export,
     import-chain validation, dashboard import). Add a PR6 clause stating subordinate-CA issuance
     is WIRED, so the routed concern matches the shipped surface.

> Not a CLAUDE.md edit, but worth noting: the Postgres-flip routed concern is **accurate** — Phase-3
> UAT behaviorally confirmed fail-closed boot, `/readyz` PG conjunction, `yuzu_pg_*` metrics, and the
> `endpoint_state` born-on-PG schema. No change needed.

---

## B. ADR corrections (in-scope record)

1. **Gateway-scaling decision has no formal ADR** · `gw-22`
   - `docs/adr/` contains 0001–0010; **ADR-0002 is `reachability-graph-data-model`**. The gateway
     scaling decision (WhatsApp/RabbitMQ-tier, grpcbox removal) lives only in an informal
     `project_gateway_scalability_workstream` memory / plan that cites a non-existent
     `docs/adrs/0002-gateway-scaling.md` (note the plural `adrs`, and the number collision).
   - **Proposed:** promote the gateway-scaling decision to a real numbered ADR under `docs/adr/`
     (next free number), and fix the dangling `docs/adrs/0002-…` references. Removes a live
     number/path collision in the architectural record.

2. **ADRs 0001–0005 are accepted but unbuilt on mainline** · `vuln-02…07, vuln-14, vuln-15`
   - The reachability/attack-path engine ADRs (observed-grounded graph, host+service data model,
     event-driven telemetry, PostgreSQL-persisted scored graph, Dijkstra/Yen attack-path scoring,
     KEV pre-filter) are **accepted**, but no implementing code exists on `feat/postgres-f3-flip`
     (it's the `#1206` spike). The records read as if the design is settled with nothing flagging
     it as not-yet-shipped.
   - **Proposed:** add a one-line `Status:` banner to ADRs 0001–0005 — e.g. *"Accepted;
     implementation is spike-grade (PR #1206), not in mainline as of 2026-06."* Keeps
     accepted-but-unbuilt honest without reopening the decisions.

---

## C. Authoritative product-doc corrections (proposals — NOT applied)

These are the bulk of the drift. All are doc-behind-code unless noted. Grouped by target file;
each cites its register row(s).

### `docs/user-manual/authentication.md` — **do these first (one is dangerous)**
- **`auth-18` (contradiction):** Remove the "Group-to-Role Mapping" sentence *"If the OIDC user's
  email or display name matches a local admin account, they are also granted admin regardless of
  group membership."* The code **deliberately refuses** this (`auth.cpp:782-789`, explicit C3
  security-fix: email/display_name are "attacker-controlled"). The manual currently documents a
  privilege-escalation path that does not exist — correct it to "admin via OIDC **only** through
  explicit `admin_group_id` membership."
- **`auth-19`:** "API tokens are always granted full admin-level access" is false — a token inherits
  its creator's *current* role (`auth_routes.cpp:88-102`, defaults to `user`; scoped/MCP tokens are
  403'd from admin ops). Rewrite to describe role-inheriting tokens.

### `docs/capability-map.md` — systematically understates shipped work
- **`asp-03` (HIGH):** §31.2 Event Guards marked ":x: Not implemented" — Registry/File/SCM guards are
  shipped + wired (`guardian_engine.cpp:516-705`). Mark Partial (3 of 4; WFP/ETW remain).
- **`asp-02`:** §28.3 Response Offloading ":x:" but fully shipped (`offload_routes.cpp`, contradicts
  its own §20.7 which marks it Done).
- **`asp-05`:** §30.1–30.4 Scope Walking all ":x:" but shipped (`result_set_store.cpp`, 10+ REST routes,
  `scope_engine.cpp:420`).
- **`asp-15`/`asp-10`:** §18.10 2FA/TOTP ":x:" but substantially shipped (`totp.cpp`, `mfa_step_up.cpp`,
  enrollment UI + step-up gates). Also breaks the "Advanced 101/101 100%" headline arithmetic.
- **`vuln-14`:** §9.4 marks Vulnerability Scanning ✅ Done, but the ADR-0001/0005 engine is a spike —
  qualify as legacy-plugin-done / modern-engine-pending.
- **`asp-01`:** "Progress at a Glance: New (Ph 8-16) 2/44 (5%)" understates (≥3/44; self-contradicts §20.7).
- Recompute the headline percentages — several are internally inconsistent with the body.

### `docs/roadmap.md`
- **`asp-06`:** Phase 15 status table "0 done / 8 open / 0%" → at least 2/8 done (15.B + 15.C shipped),
  15.G partial.

### `docs/enterprise-parity-plan.md` — pre-Postgres-flip throughout
- **`asp-07`/`asp-16`:** "Server Database = SQLite (embedded, WAL mode)" and the advantage *"No SQL
  Server dependency — SQLite is embedded, zero-ops"* are **false** post-flip (server fails closed
  without Postgres — Phase-3 verified). Rewrite the architecture row + advantage to "server: PostgreSQL
  (operator-provisioned); agent: SQLite edge warehouse."
- **`asp-08`:** baseline "Yuzu v0.7.0, 165/184 capabilities" is stale (`meson.build` = 0.12.0;
  capability-map = 169/228). Refresh version + counts.

### `docs/Instruction-Engine.md`
- **`instr-20`:** Current-State table marks InstructionStore/ExecutionTracker/ApprovalManager/
  ScheduleEngine as "Stub" — they are fully implemented. Update.
- **`instr-21`:** "150/184 (82%)" headline is stale — reconcile with capability-map.

### `docs/os-capability-matrix.md`
- **`agent-12` (contradiction):** Row 29 marks DEX perf telemetry "Linux ✅ … echo_perf.cpp", but
  `echo_perf.cpp:190` is `kPlanned` on Linux (returns `valid=false`); `echo_schema_registry.cpp:296`
  confirms `kPlanned`. Change Linux to ⛔/Planned. (This is exactly the "Linux-only-network gap" class
  of matrix overclaim the doc itself warns about.)

### `docs/dex-signal-catalog.md` (+ `dex_routes.cpp` comment)
- **`dex-17`:** the doc instructs `dex_obs_platforms()` be kept in sync with the Linux collectors, but
  the map lists only 7 of 17 shipped Linux obs_types; the in-code deferral comment (`dex_routes.cpp:133-140`,
  "land WITH their collectors in #1523") is stale — the collectors already shipped. See §D (code side).

### MCP docs (`docs/mcp-server.md`, `docs/user-manual/mcp.md`, `docs/agentic-first-principle.md`)
- **`mcp-05`/`mcp-06`/`mcp-07`/`mcp-08`:** tool counts ("27 total", "23 tools", 34-row table) and "3
  resources" are stale vs the live `tools/list`. The docs already say `tools/list` is authoritative —
  either drop the hard numbers or refresh them.

### Smaller record fixes
- **`echo-14`:** `echo-dashboard.md` §9 / `scope-walking-design.md` §11 mark PR-B/PR-C/PR-D pending — shipped.
- **`echo-19`:** `asset-tagging-guide.md` ITServiceOwner lists 10 securable types; code seeds 16
  (`rbac_store.cpp:401-435`) with different names (Infrastructure vs Device, no Scope, Execution).
- **`viz-24`:** `fleet-viz-invariants.md` PR7 states an 80 KB bundle soft cap — verify against the
  current `yuzu-viz.js` size and update the cap or note the overage.
- **`instr-12`:** `executions-history-ladder.md` PR2 "Known coverage gap" still lists MCP
  `execute_instruction` as producing `execution_id=''` — it now threads it (#1088, already in CLAUDE.md).
- **`ci-15`:** `docker-compose.yml:33-37` inline comment "the server does not consume this yet — #1320
  wires…" is stale post-flip; the server now requires the DSN.
- **`policy-24`:** `policy-engine.md:247` invalidation-resets-to-pending detail needs reconciling with
  the actual status writer.
- **`agent-02`:** `agent-privilege-model.md:70` "all 217 instructions" count — verify against the
  current instruction set.
- **`pki-22`:** verify KEK lifecycle audit verbs + `yuzu_server_secret_decrypt_failures` metric +
  break-glass voided-secrets boot flag are wired (ADR-0010 consequences) — marked PARTIAL.
- **`gw-19`:** `gateway.md:188-222` GatewayUpstream RPC/field-number table vs proto — reconcile.
- **`asp-09`:** SOC2 §3.5 data inventory titled "server-side SQLite stores" — add the Postgres
  `endpoint_state` schema and reframe now that PG is mandatory.

---

## D. Code-side gaps surfaced (NOT doc drift — flagged, not filed)

The audit found a handful of cases where the **code** is the side that's wrong (the doc states the
correct intent). Per scope these are not filed as issues — listed here for your triage.

- **`mcp-03` (Tier-A invariant violation):** MCP CA tools `list_issued_certs` / `revoke_certificate`
  serialize output via `nlohmann::json` + `.dump()` (`mcp_server.cpp:2482-2589`), violating the
  documented "JObj/JArr output only — nlohmann parse-only" invariant. Either fix the two call sites or
  consciously relax the invariant.
- **`mcp-04` (Tier-A, audit completeness):** every MCP call sets `action=mcp.<tool>` but the dedicated
  `AuditEvent.mcp_tool` column is **never populated** (`auth_routes.cpp:466-487`) — SOC2-relevant gap.
- **`mcp-14`:** MCP error responses don't carry the full A4 envelope (`correlation_id`,
  `retry_after_ms`, `remediation`) that `agentic-first-principle.md` A4 requires for *every* surface.
- **`dex-17`:** `dex_obs_platforms()` under-attributes 10 shipped Linux signals → a real Linux fleet's
  `/dex` Catalogue shows them as not-collected ("monitored, quiet reads as healthy" — the exact failure
  the code comment warns against). Fix the map + delete the stale `#1523` deferral comment.
- **`gw-20`:** verify the shutdown graceful-drain order (`router ! drain` → drain in-flight → flush
  heartbeat buffer) in `yuzu_gw_app.erl:119-144` — marked PARTIAL.

---

## E. Unsettled

- **`gw-23` (LOW, UNVERIFIABLE):** `erlang-gateway-build.md:11` claims the eunit suite has **148 tests**.
  Static count ≈ 98 simple + 17 generators (generators expand to an unknown multiple). The eunit run
  couldn't be driven cleanly from a background shell this session (`ensure-erlang.sh` must be sourced in
  an interactive shell). Re-run `source scripts/ensure-erlang.sh && rebar3 eunit --dir apps/yuzu_gw/test`
  interactively to confirm/correct the count.

---

## How to apply

Sections **A** and **B** are the sanctioned record edits. Sections **C** and **D** are proposals —
review the register row for each (full evidence + adversarial verdict) before acting. Suggested order:
`auth-18` (security-doc correction) → A (CLAUDE.md) → B (ADR hygiene) → the capability-map/parity-plan
refresh (largest reader-facing inaccuracy) → the rest.
