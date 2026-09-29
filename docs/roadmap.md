# Yuzu Development Roadmap

**Version:** 3.0 | **Date:** 2026-09-07 | dev @ `d295db964`

This roadmap transforms Yuzu from a functional agent/server framework into a full-featured enterprise endpoint management platform. Work is organized into 20 phases: 0–16 (17 phases) are scheduled and tracked as GitHub issues (126 issues total), each building on the previous; 17–19 are proposed extensions (agentic-surface hardening, compliance/lifecycle, threat graph) not yet all filed as issues.

<!-- Reproducibility recipe for the next re-roll: batch-resolve every issue number cited below in one
     call — `gh api graphql -f query="query { repository(owner: \"Tr3kkR\", name: \"Yuzu\") {
     i<N>: issue(number: <N>) { number state stateReason closedAt title } ... } }"` (one alias per issue
     number, extracted via `grep -oE 'issues/[0-9]+' docs/roadmap.md | sort -u` — 129 unique numbers: the
     126 Index rows plus #251/#252 (decision log) and #1562 (15.H follow-up); #555–#557 are cited twice) —
     then diff against the tables below. **`stateReason` is load-bearing, not optional**: a `state`-only
     pull cannot distinguish a genuinely-delivered `COMPLETED` closure from a `NOT_PLANNED` backlog-reset
     closure (2026-07-14 closed 11 issues NOT_PLANNED — #252, #263–#268, #283, #286, #292, #552 — none of
     which are "delivered" by the closure alone).

     **Status vocabulary — a counting contract, not prose.** Every Index row's Status cell MUST begin
     (after stripping any leading `**`/`__` markdown emphasis) with EXACTLY one of these 5 literal
     strings, followed by a word boundary — this is a plain-English restatement of the reference
     parser's regex below, nothing more: a trailing `**`/`__` closing the emphasis, a space, an em
     dash, a paren, or end-of-line all count as the boundary; anything else (e.g. the literal fused
     into a longer word) does not match. Everything from that boundary onward is free-text annotation
     the counting rule ignores. A `Done` cell's annotation must never itself negate delivery (no "not
     shipped"/"not built"/"not implemented" after a `Done` literal) — a row whose annotation qualifies
     *how* something shipped stays `Done`; a row whose annotation says nothing shipped must carry
     `Partial` instead, never `Done`. The 5 literals:
       - `Done` — closed COMPLETED, or closed NOT_PLANNED *with* a cited delivery-evidence path/ADR (the
         thing shipped differently from how the issue described it, or shipped with a small non-blocking
         gap called out in the annotation — a genuinely unshipped major capability is `Partial`, not `Done`).
       - `Partial` — real delivery exists but a materially advertised capability of the issue does not
         work end-to-end (e.g. records+audits with no working dispatch path). **Decay path:** a `Partial`
         row promoted to `Done` by a later edit MUST re-verify the specific gap the annotation named is
         actually closed (re-run the `grep`/`ls` check the row's own annotation cites) — do not promote
         on the strength of unrelated GitHub activity (a new commit, a closed follow-up issue, a merged
         PR) without checking the row's own cited evidence path first; this is the same `stateReason`
         discipline this recipe already applies to closures, extended to Partial→Done edits.
       - `Closed — not planned` — closed NOT_PLANNED with NO delivery evidence (a real decision not to
         build it, distinct from `Done`-via-NOT_PLANNED above).
       - `Open` — still open on GitHub, including "in progress" work (a PR ladder or partial soak does not
         promote an open issue to `Done`/`Partial` — put the detail in the free-text annotation instead).
       - `Deferred` — open but explicitly re-scoped pending a decision (see Phase 9 banner) — distinct from
         plain `Open` (no decision is pending on a plain-`Open` row, just unstarted work).
     **Counting rule:** `Done` counts toward the rollup's Done column; `Partial`/`Open`/`Deferred`/
     `Closed — not planned` all count toward Open. No other literal, no synonym (`Shipped`, `Largely
     shipped`, `In progress`, `Resolved`, etc.), and no special-casing in the parser — if a row needs a
     different verdict, change the row's leading literal, not the parser. Verify each NOT_PLANNED row's
     delivery claim by `grep`/`ls` against the cited files — do not infer delivery from the closure alone.
     A reference parser implementing exactly this rule: strip each Index row's Status cell of leading
     `**`/`__`, match `^(Done|Partial|Closed — not planned|Open|Deferred)\b`, sum `Done` vs everything
     else per phase. No table of synonyms, no regex alternation beyond the 5 literals above.
     **Negation check** (must return nothing before trusting any `Done` count): `grep -nE '^\|[^|]*\|
     [^|]*\|[^|]*\|[^|]*\| *\**Done\**[^|]*(NOT|not) (shipped|built|implemented)' docs/roadmap.md` — a
     hit means a `Done` row's own annotation contradicts its literal and must be regraded `Partial`.
     Cross-check "Recommended Execution Order" / "Delivered outside the roadmap" claims with
     `gh pr list --state open --search <term>` and `grep`/`ls` against the cited files — never restate
     status from memory of a prior version of this doc. -->

## GitHub Issue Index

| Phase | Issue | # | Title | Status |
|-------|-------|---|-------|--------|
| **0** | 0.1 | [#146](https://github.com/Tr3kkR/Yuzu/issues/146) | HTTPS for Web Dashboard | Done |
| | 0.2 | [#147](https://github.com/Tr3kkR/Yuzu/issues/147) | Agent OTA Update Management | Done |
| | 0.3 | [#148](https://github.com/Tr3kkR/Yuzu/issues/148) | Secure Temp File Creation in Filesystem Plugin | Done |
| | 0.4 | [#150](https://github.com/Tr3kkR/Yuzu/issues/150) | SDK Utility Functions (JSON/Table Conversion) | Done |
| | 0.5 | [#152](https://github.com/Tr3kkR/Yuzu/issues/152) | Complete Foundation Partial Items | Done |
| **1** | 1.1 | [#166](https://github.com/Tr3kkR/Yuzu/issues/166) | Server-Side Response Persistence | Done |
| | 1.2 | [#167](https://github.com/Tr3kkR/Yuzu/issues/167) | Response Filtering, Pagination, and Sorting | Done |
| | 1.3 | [#168](https://github.com/Tr3kkR/Yuzu/issues/168) | Response Aggregation Engine | Done |
| | 1.4 | [#169](https://github.com/Tr3kkR/Yuzu/issues/169) | Audit Trail System | Done |
| | 1.5 | [#170](https://github.com/Tr3kkR/Yuzu/issues/170) | Device Tagging System | Done |
| | 1.6 | [#171](https://github.com/Tr3kkR/Yuzu/issues/171) | Scope Expression Engine and Device Filtering | Done |
| | 1.7 | [#172](https://github.com/Tr3kkR/Yuzu/issues/172) | CSV and JSON Data Export | Done |
| **2** | 2.1 | [#149](https://github.com/Tr3kkR/Yuzu/issues/149) | Instruction Definitions | Done |
| | 2.2 | [#151](https://github.com/Tr3kkR/Yuzu/issues/151) | Instruction Sets (Grouping and Organization) | Done |
| | 2.3 | [#153](https://github.com/Tr3kkR/Yuzu/issues/153) | Instruction Scheduling | Done |
| | 2.4 | [#155](https://github.com/Tr3kkR/Yuzu/issues/155) | Instruction Approval Workflows | Done |
| | 2.5 | [#158](https://github.com/Tr3kkR/Yuzu/issues/158) | Instruction Hierarchies and Follow-Up Workflows | Done |
| | 2.6 | [#160](https://github.com/Tr3kkR/Yuzu/issues/160) | Instruction Progress Tracking and Statistics | Done |
| | 2.7 | [#163](https://github.com/Tr3kkR/Yuzu/issues/163) | Instruction Rerun and Cancellation | Done |
| | 2.8 | [#205](https://github.com/Tr3kkR/Yuzu/issues/205) | Error Code Taxonomy (1xxx-4xxx) | Done |
| | 2.9 | [#206](https://github.com/Tr3kkR/Yuzu/issues/206) | Concurrency Enforcement (real-usage scope) | **Partial** — per-device enforcement shipped (ADR-1007, 2026-09-02); the four other originally advertised modes are out of scope by decision, not pending (`docs/adr/1007-concurrency-enforcement-scope.md:88-95,986`) |
| | 2.10 | [#207](https://github.com/Tr3kkR/Yuzu/issues/207) | YAML Authoring UI (Form + CodeMirror) | Done |
| | 2.11 | [#208](https://github.com/Tr3kkR/Yuzu/issues/208) | Legacy Command Shim | Done |
| | 2.12 | [#209](https://github.com/Tr3kkR/Yuzu/issues/209) | Structured Result Envelope | Done |
| **3** | 3.1 | [#154](https://github.com/Tr3kkR/Yuzu/issues/154) | Granular RBAC System | Done |
| | 3.2 | [#156](https://github.com/Tr3kkR/Yuzu/issues/156) | Management Groups | Done |
| | 3.3 | [#157](https://github.com/Tr3kkR/Yuzu/issues/157) | Token-Based API Authentication | Done |
| | 3.4 | [#159](https://github.com/Tr3kkR/Yuzu/issues/159) | OIDC / SSO Integration | Done |
| | 3.5 | [#161](https://github.com/Tr3kkR/Yuzu/issues/161) | REST / HTTP Management API (v1) | Done |
| | 3.6 | [#162](https://github.com/Tr3kkR/Yuzu/issues/162) | Device Quarantine (Network Isolation) | Done |
| | 3.7 | [#164](https://github.com/Tr3kkR/Yuzu/issues/164) | IOC Checking | Done |
| | 3.8 | [#165](https://github.com/Tr3kkR/Yuzu/issues/165) | Certificate Inventory and Management | Done |
| | 3.9 | [#210](https://github.com/Tr3kkR/Yuzu/issues/210) | Scope DSL Extensions (MATCHES, EXISTS, len, startswith) | **Done** |
| **4** | 4.1 | [#173](https://github.com/Tr3kkR/Yuzu/issues/173) | Agent-Side Key-Value Storage | Done |
| | 4.2 | [#174](https://github.com/Tr3kkR/Yuzu/issues/174) | HTTP Download and Upload (Agent-Initiated) | Done |
| | 4.3 | [#177](https://github.com/Tr3kkR/Yuzu/issues/177) | Content Staging and Execution | Done |
| | 4.4 | [#181](https://github.com/Tr3kkR/Yuzu/issues/181) | Agent Sleep and Stagger Control | Done |
| | 4.5 | [#184](https://github.com/Tr3kkR/Yuzu/issues/184) | Trigger Framework (Agent-Side) | Done |
| | 4.6 | [#189](https://github.com/Tr3kkR/Yuzu/issues/189) | Desktop User Interaction (Windows) | Done |
| | 4.7 | [#193](https://github.com/Tr3kkR/Yuzu/issues/193) | Agent Logging and Remote Log Retrieval | Done |
| | 4.8 | [#212](https://github.com/Tr3kkR/Yuzu/issues/212) | service.set_start_mode Cross-Platform Primitive | Done |
| **5** | 5.1 | [#175](https://github.com/Tr3kkR/Yuzu/issues/175) | Policy Rules and Fragments | Done — remediation ("Fix") is operator-gated, never automatic; distinct from Guardian (Phase 16), see body note |
| | 5.2 | [#176](https://github.com/Tr3kkR/Yuzu/issues/176) | Policy Assignment and Deployment | Done |
| | 5.3 | [#178](https://github.com/Tr3kkR/Yuzu/issues/178) | Compliance Dashboard and Statistics | Done |
| | 5.4 | [#179](https://github.com/Tr3kkR/Yuzu/issues/179) | Policy Cache Invalidation and Force Re-Evaluation | Done |
| | 5.5 | [#211](https://github.com/Tr3kkR/Yuzu/issues/211) | CEL Adoption for Policy Compliance Expressions | Done |
| **6** | 6.1 | [#180](https://github.com/Tr3kkR/Yuzu/issues/180) | Registry Plugin (Read/Write/Enumerate) | Done |
| | 6.2 | [#182](https://github.com/Tr3kkR/Yuzu/issues/182) | Per-User Registry Operations | Done |
| | 6.3 | [#183](https://github.com/Tr3kkR/Yuzu/issues/183) | WMI Query and Method Invocation | Done |
| | 6.4 | [#186](https://github.com/Tr3kkR/Yuzu/issues/186) | Per-User Application Inventory | Done |
| | 6.5 | [#188](https://github.com/Tr3kkR/Yuzu/issues/188) | File System Advanced Operations | Done |
| | 6.6 | [#192](https://github.com/Tr3kkR/Yuzu/issues/192) | Registry Change Trigger | Done |
| **7** | 7.1 | [#185](https://github.com/Tr3kkR/Yuzu/issues/185) | Gateway Node Implementation | Done |
| | 7.2 | [#187](https://github.com/Tr3kkR/Yuzu/issues/187) | System Health Monitoring and Statistics | Done |
| | 7.3 | [#190](https://github.com/Tr3kkR/Yuzu/issues/190) | Runtime Configuration API | Done |
| | 7.4 | [#191](https://github.com/Tr3kkR/Yuzu/issues/191) | System Notifications | Done |
| | 7.5 | [#194](https://github.com/Tr3kkR/Yuzu/issues/194) | Active Directory / Entra Integration | Done |
| | 7.6 | [#195](https://github.com/Tr3kkR/Yuzu/issues/195) | Custom Properties on Devices | Done |
| | 7.7 | [#196](https://github.com/Tr3kkR/Yuzu/issues/196) | Agent Deployment Jobs | Done |
| | 7.8 | [#197](https://github.com/Tr3kkR/Yuzu/issues/197) | Patch Deployment Workflow | **Partial** — records + audits only; dispatch (#4138) and ingestion (#3676) are unwired, see body note |
| | 7.9 | [#198](https://github.com/Tr3kkR/Yuzu/issues/198) | Product Packs (Bundled Definitions) | Done |
| | 7.10 | [#199](https://github.com/Tr3kkR/Yuzu/issues/199) | User Sessions and Group Membership Plugins | Done |
| | 7.11 | [#200](https://github.com/Tr3kkR/Yuzu/issues/200) | Advanced User Interaction (Surveys, DND) | Done |
| | 7.12 | [#201](https://github.com/Tr3kkR/Yuzu/issues/201) | Event Subscriptions (Webhooks) | Done |
| | 7.13 | [#213](https://github.com/Tr3kkR/Yuzu/issues/213) | ProductPack Ed25519 Trust Chain and Verification | Done |
| | 7.14 | [#214](https://github.com/Tr3kkR/Yuzu/issues/214) | Workflow Primitives (if, foreach, retry) | Done |
| | 7.15 | [#215](https://github.com/Tr3kkR/Yuzu/issues/215) | WiFi Network Enumeration | Done |
| | 7.16 | [#216](https://github.com/Tr3kkR/Yuzu/issues/216) | Wake-on-LAN Support | Done |
| | 7.17 | [#217](https://github.com/Tr3kkR/Yuzu/issues/217) | Inventory Table Enumeration and Item Lookup | Done |
| | 7.18 | [#218](https://github.com/Tr3kkR/Yuzu/issues/218) | Device Discovery (Unmanaged Endpoints) | Done |
| | 7.19 | [#235](https://github.com/Tr3kkR/Yuzu/issues/235) | Timeline Activity Record (TAR) | Done |
| | 7.20 | [#236](https://github.com/Tr3kkR/Yuzu/issues/236) | MCP Server (Model Context Protocol) Phase 1 | Done — **doc-integrity note:** #236 is not an issue and never was — issues and PRs share one number sequence and #236 is PR "Release v0.1.0" (2026-03-21); the v2.0 link was wrong from birth. Status confirmed by code inspection (`server/core/src/mcp_server.cpp`) instead |
| **8** | 8.1 | [#253](https://github.com/Tr3kkR/Yuzu/issues/253) | Response Visualization Engine | **Done** |
| | 8.2 | [#254](https://github.com/Tr3kkR/Yuzu/issues/254) | Response Templates | **Done** |
| :white_check_mark: | 8.3 | [#255](https://github.com/Tr3kkR/Yuzu/issues/255) | Response Offloading (Data Export Streams) | Done |
| **9** | 9.1 | [#256](https://github.com/Tr3kkR/Yuzu/issues/256) | Connector Framework (Core) | **Deferred** — see Phase 9 body note |
| | 9.2 | [#257](https://github.com/Tr3kkR/Yuzu/issues/257) | Inventory Repository Model | **Deferred** — see Phase 9 body note |
| | 9.3 | [#258](https://github.com/Tr3kkR/Yuzu/issues/258) | SCCM / ConfigMgr Connector | **Deferred** — see Phase 9 body note |
| | 9.4 | [#259](https://github.com/Tr3kkR/Yuzu/issues/259) | Intune Connector | **Deferred** — see Phase 9 body note |
| | 9.5 | [#260](https://github.com/Tr3kkR/Yuzu/issues/260) | ServiceNow Connector | **Deferred** — see Phase 9 body note |
| | 9.6 | [#261](https://github.com/Tr3kkR/Yuzu/issues/261) | WSUS Connector | **Deferred** — see Phase 9 body note |
| | 9.7 | [#262](https://github.com/Tr3kkR/Yuzu/issues/262) | CSV / File Upload Connector | **Deferred** — see Phase 9 body note |
| | 9.8 | [#263](https://github.com/Tr3kkR/Yuzu/issues/263) | Inventory Consolidation & Normalization | **Closed — not planned** (NOT_PLANNED, 2026-07-14) — consolidation/dedup absent; normalization primitives exist (`product_normalize.cpp`) but no cross-source consolidation, see body note |
| **10** | 10.1 | [#264](https://github.com/Tr3kkR/Yuzu/issues/264) | Software Catalog Store | **Partial** — store + normalizer compiled and tested; no production writer/reader at the pin — the SLE matcher that populates it is PR4 (`product_registry_store.cpp:43`) |
| | 10.2 | [#265](https://github.com/Tr3kkR/Yuzu/issues/265) | Software Usage Tracking | **Closed — not planned** (NOT_PLANNED, 2026-07-14) — ADR-0024 places usage metering/reclamation in the **SAM UCE module** (Decision D15, distinct from ADR-1005's vulnerability UCE); no agent usage-sync source exists in-server |
| | 10.3 | [#266](https://github.com/Tr3kkR/Yuzu/issues/266) | License Entitlements & Compliance | **Closed — not planned** (NOT_PLANNED, 2026-07-14) — ADR-0024 places the entitlement plane in the **SAM UCE module** (Decision D12, distinct from ADR-1005's vulnerability UCE); not built in-server |
| | 10.4 | [#267](https://github.com/Tr3kkR/Yuzu/issues/267) | Software Tags | **Closed — not planned** (NOT_PLANNED, 2026-07-14) — no server-side software-tags code found; NOT UCE-scoped (ADR-0024 Decision 15 keeps product tags core), just not yet built (tracked as a future `product_tags` migration, "PR4") |
| **11** | 11.1 | [#268](https://github.com/Tr3kkR/Yuzu/issues/268) | Consumer Application Registration | **Closed — not planned** (NOT_PLANNED, 2026-07-14) — the auth/token substance was absorbed into ADR-1005 engine principals (`EnginePrincipalStore`, delivered); the push/consumer-deploy fanout this issue described was never built, see body note |
| | 11.2 | [#269](https://github.com/Tr3kkR/Yuzu/issues/269) | Event Source Management | Open |
| | 11.3 | [#270](https://github.com/Tr3kkR/Yuzu/issues/270) | PowerShell Module | Open |
| | 11.4 | [#271](https://github.com/Tr3kkR/Yuzu/issues/271) | Python SDK | Open |
| **12** | 12.1 | [#272](https://github.com/Tr3kkR/Yuzu/issues/272) | Mapped Drive History | **Done** (closed 2026-07-04 — shipped as the TAR capture source `tar_mapdrive_collector.cpp`, not a `users` plugin action) |
| | 12.2 | [#273](https://github.com/Tr3kkR/Yuzu/issues/273) | Printer Inventory | Open |
| | 12.3 | [#274](https://github.com/Tr3kkR/Yuzu/issues/274) | Port Scanning | Open |
| | 12.4 | [#275](https://github.com/Tr3kkR/Yuzu/issues/275) | NetBIOS Lookup | Open |
| | 12.5 | [#276](https://github.com/Tr3kkR/Yuzu/issues/276) | Open Windows Enumeration | Open |
| | 12.6 | [#277](https://github.com/Tr3kkR/Yuzu/issues/277) | Directory Hash (Recursive) | Open |
| | 12.7 | [#278](https://github.com/Tr3kkR/Yuzu/issues/278) | Survey Dialog | Open |
| | 12.8 | [#279](https://github.com/Tr3kkR/Yuzu/issues/279) | Do-Not-Disturb Mode | **Done** (closed 2026-08-01) |
| | 12.9 | [#280](https://github.com/Tr3kkR/Yuzu/issues/280) | Active Response Tracking | Open |
| | 12.10 | [#281](https://github.com/Tr3kkR/Yuzu/issues/281) | Patch Inventory Event Generation | Open |
| | 12.11 | [#282](https://github.com/Tr3kkR/Yuzu/issues/282) | Application Whitelisting | Open |
| | 12.12 | [#283](https://github.com/Tr3kkR/Yuzu/issues/283) | Inventory Replication (Delta Sync) | **Done** (NOT_PLANNED, 2026-07-14, delivered differently: ADR-0016's hash-skip conditional sync, `sync_scheduler.hpp`) |
| | 12.13 | [#284](https://github.com/Tr3kkR/Yuzu/issues/284) | Binary Resource Distribution | Open |
| **13** | 13.1 | [#285](https://github.com/Tr3kkR/Yuzu/issues/285) | 2FA for Instruction Approval (TOTP) | Open (stale — TOTP/MFA step-up shipped generally, not wired to approval, see body note) |
| | 13.2 | [#286](https://github.com/Tr3kkR/Yuzu/issues/286) | Composable Instruction Chains | **Done** (NOT_PLANNED, 2026-07-14, delivered: `workflow_engine.cpp` `foreach_source` step field + step interpolation) |
| | 13.3 | [#287](https://github.com/Tr3kkR/Yuzu/issues/287) | Process / Sync Logging UI | Open |
| | 13.4 | [#288](https://github.com/Tr3kkR/Yuzu/issues/288) | Dashboard Branding | Open |
| | 13.5 | [#289](https://github.com/Tr3kkR/Yuzu/issues/289) | MCP Phase 2 (Write Tools) | Done |
| **14** | 14.1 | [#290](https://github.com/Tr3kkR/Yuzu/issues/290) | P2P Content Distribution | Open |
| | 14.2 | [#291](https://github.com/Tr3kkR/Yuzu/issues/291) | Multi-Gateway Topology | Open |
| | 14.3 | [#292](https://github.com/Tr3kkR/Yuzu/issues/292) | Database Sharding (Response Partitioning) | **Partial** (#292 closed NOT_PLANNED, 2026-07-14) — not implemented as designed (no sharding/partitioning code); the underlying scaling need is addressed differently by the Postgres substrate migration (ADR-0039), see body note |
| | 14.4 | [#293](https://github.com/Tr3kkR/Yuzu/issues/293) | vCenter Connector | Open |
| | 14.5 | [#294](https://github.com/Tr3kkR/Yuzu/issues/294) | Additional Connectors (BigFix, O365, Oracle) | Open |
| | 14.6 | [#295](https://github.com/Tr3kkR/Yuzu/issues/295) | High Availability | Open (stale — superseded by ADR-2002, see body note) |
| **15** | 15.A | [#547](https://github.com/Tr3kkR/Yuzu/issues/547) | TAR dashboard page shell + retention-paused source list | **Done** (paused_at + status extension + dashboard page + Scan + Re-enable + typed-confirmation Purge) |
| | 15.B | [#548](https://github.com/Tr3kkR/Yuzu/issues/548) | Result-set store + REST API (composable scope, the differentiator) | **Done** (closed 2026-07-04) |
| | 15.C | [#549](https://github.com/Tr3kkR/Yuzu/issues/549) | Scope-engine `from_result_set:` + dashboard chip + sidebar + breadcrumb | **Done** (closed 2026-07-04) |
| | 15.D | [#550](https://github.com/Tr3kkR/Yuzu/issues/550) | TAR SQL frame: relocate, scope-walking-aware, "save as result set" | **Done** (closed 2026-07-04) |
| | 15.E | [#551](https://github.com/Tr3kkR/Yuzu/issues/551) | YAML DSL `fromResultSet:` + `definition_store` validation + spec amendment | **Done** (closed 2026-07-04) |
| | 15.F | [#552](https://github.com/Tr3kkR/Yuzu/issues/552) | Reference walkthrough integration test (Chrome IR end-to-end) | **Done** (NOT_PLANNED, 2026-07-14, delivered differently: an in-process Catch2 test, `tests/unit/server/test_chrome_ir_chain.cpp`, not the originally-scoped scripted UAT variant, see body) |
| | 15.G | [#553](https://github.com/Tr3kkR/Yuzu/issues/553) | Operational hardening — live re-eval, GC sweep, Prometheus + audit polish | **Done** (closed 2026-07-04) — `yuzu_result_set_resolve_seconds` histogram + audit-polish pass still outstanding (minor, non-blocking), see body |
| | 15.H | [#554](https://github.com/Tr3kkR/Yuzu/issues/554) | TAR process tree viewer | **Done** 2026-06-18 (as-built: local-TAR-data-only reconstruction, no seed; `docs/tar-dashboard.md` §5). REST/MCP parity deferred. |
| **16** | 16.A | [#555](https://github.com/Tr3kkR/Yuzu/issues/555) | System Guardian — Windows-first delivery (PRs 1-15 per implementation plan) | Open — in progress: Spark engine rungs 1-7+, `GuardianEngine`, `BaselineStore`, `/guaranteed-state` UI shipped; Spark is wired (`agent.cpp:1255`) but inert by default — `prefer_spark_=false`, legacy `IGuard` remains the sole live enforcement path; 59 merged guardian PRs at the pin (more since) (issue itself still open — no sub-checklist tracks the PR ladder) |
| | 16.B | [#556](https://github.com/Tr3kkR/Yuzu/issues/556) | System Guardian — Linux delivery (inotify, netlink, D-Bus, audit, sysctl) | Open — **started early** (`guard_systemd.cpp` exists) ahead of the stated 16.A-soak gate, see body note |
| | 16.C | [#557](https://github.com/Tr3kkR/Yuzu/issues/557) | System Guardian — macOS delivery (Endpoint Security, fseventsd, launchd) | Open (gated on 16.A + 16.B soak + ES entitlement) |

## Current Status

| Phase | Done | Open | Total | Progress |
|-------|:----:|:----:|:-----:|----------|
| 0: Foundation | 5 | 0 | 5 | 100% |
| 1: Data Infrastructure | 7 | 0 | 7 | 100% |
| 2: Instruction System | 11 | 1 | 12 | 92% — 2.9 is **Partial**, not Done (per-device concurrency shipped, ADR-1007; the other four modes are out of scope by decision) |
| 3: Security & RBAC | 9 | 0 | 9 | 100% |
| 4: Agent Infrastructure | 8 | 0 | 8 | 100% |
| 5: Policy Engine | 5 | 0 | 5 | 100% |
| 6: Windows Depth | 6 | 0 | 6 | 100% |
| 7: Scale & Integration | 19 | 1 | 20 | 95% — 7.8 is **Partial**, not Done (patch deploy records + audits only; dispatch #4138 and ingestion #3676 are unwired) |
| 8: Visualization & Response Experience | 3 | 0 | 3 | 100% |
| 9: Connector Framework & Multi-Source Inventory | 0 | 8 | 8 | 0% — **Deferred** (owner decision 2026-09-07: placement — core vs. use-case-engine — is an open question to be settled before any re-plan, see Phase 9 body note); demoted out of the #2 execution-order slot it held since 2026-03 |
| 10: Software Catalog & License Compliance | 0 | 4 | 4 | 0% — 10.1 (product registry) is **Partial** (store compiled/tested, no production writer/reader at the pin); 10.2–10.4 closed NOT_PLANNED with no delivery, see Phase 10 note |
| 11: Consumer Model & Platform Extensibility | 0 | 4 | 4 | 0% |
| 12: Remaining Agent Capabilities | 3 | 10 | 13 | 23% |
| 13: Security Hardening & Operational Polish | 2 | 3 | 5 | 40% |
| 14: Scale & Enterprise Readiness | 0 | 6 | 6 | 0% — 14.3 is **Partial** (not implemented as designed; the underlying need is addressed differently by the Postgres substrate migration) |
| 15: TAR Dashboard & Scope Walking | 8 | 0 | 8 | 100% |
| 16: System Guardian — Real-Time GS | 0 | 3 | 3 | 0% — issue-closure only; substantial implementation progress not reflected here, see 16.A/16.B body notes |
| **Total** | **86** | **40** | **126** | **68%** |

**Done** requires verified delivery: closed COMPLETED, or closed NOT_PLANNED *with* a cited delivery-evidence path/ADR (e.g. 12.12/#283 shipped differently as ADR-0016's hash-skip sync). A row whose annotation itself negates delivery (contains "not shipped"/"not built"/"not implemented") MUST carry the **Partial** literal, never `Done` — the annotation may qualify a `Done` row's *manner* of delivery, never contradict *that* delivery happened. **Open** is everything else, including issues closed **NOT_PLANNED with no delivery** (a real decision not to build the thing, distinct from a still-open backlog item — see the Issue Index's "Closed — not planned" rows for the per-issue distinction and `stateReason`) and **Partial** items (real but narrower delivery than "Done" implies: 2.9 per-device-only concurrency; 7.8 patch deploy records+audits with no working dispatch/ingestion path; 10.1 store+normalizer compiled/tested with zero production writer/reader at the pin; 14.3 not implemented as designed, underlying need addressed differently). The number moved from 94/126 (75%) → 90/126 (71%) → 89/126 (71%) → 88/126 (70%) → 87/126 (69%) → **86/126 (68%)** across five corrective passes: first, the initial pull used `state` without `stateReason` and miscounted 5 NOT_PLANNED-with-no-delivery closures (9.8, 10.2, 10.3, 10.4, 11.1) as Done while missing 1 NOT_PLANNED-with-delivery closure (12.12) that should have counted — net **−4**; second, 2.9 was reverted from Done to **Partial** per ADR-1007's own text ("Issue 2.9 no longer claims 'Done'; it reflects the real, narrower scope this ADR ships," `docs/adr/1007-concurrency-enforcement-scope.md:986`) — net **−1**; third, 7.8 was reverted from Done to **Partial** — the HTTP deploy path audits "Deployed … to N agents" but dispatches nothing (#4138) and patch inventory ingestion has zero production callers (#3676) — net **−1**; fourth, 10.1 was reverted from Done to **Partial** — `ProductRegistryStore` is constructed at boot and `/readyz`-wired but has zero production call sites invoking its data methods anywhere outside itself and its unit tests (`product_normalize.cpp` likewise uncalled in production; the SLE matcher that would use both is PR4, `product_registry_store.cpp:43`) — net **−1**; fifth, 14.3 was reverted from Done to **Partial** — its own annotation said "not implemented as designed," which the anti-negation rule above now forces onto the honest literal rather than leaving as a self-contradicting `Done` cell — net **−1**. 94 − 4 − 1 − 1 − 1 − 1 = **86**.

**Scaffolded** means DDL/structs/stubs exist but business logic is not wired. See `docs/Instruction-Engine.md` for Phase 2 scaffold details.

---

## Delivered outside the roadmap (2026-04 → 2026-09)

Capability that shipped without being scheduled on this roadmap — each item is authorised and traceable through the ADR, PR, or issue it cites (or, where only files are cited, through the merged PRs that added them); verified against dev @ `d295db964` by file/ADR lookup, not memory:

- **Postgres substrate program** (ADR-0006–0065) — server storage substrate migrated store-by-store from SQLite to PostgreSQL; only `server/core/src/nvd_db.cpp` remains SQLite (scheduled for deletion under ADR-1005 Phase 7).
- **SCIM / SAML / OIDC identity linkage** (ADR-2001, `docs/adr/2001-scim-oidc-identity-linkage.md`).
- **HA workstreams landed so far** (ADR-2002, as of dev @ `d295db964` — verified by merge-commit ancestry, not `gh pr view` state) — WS-0 (agent command idempotency+replay), WS-1 (server-plane state → Postgres, milestones 1a/1b/1c), WS-7 (HA-Postgres Patroni+etcd+HAProxy compose profile), and WS-2a (durable event outbox + #3924 cross-replica SSE delivery, IS an ancestor of the pin) are done; WS-3 slice 3.1 (#4011, fenced `LeaderElector` primitive, IS an ancestor) is done but inert (no loop wired). **WS-10 (#4092) is NOT an ancestor of the pin** — merged 2026-09-07 12:58 UTC, ~1 hour after `d295db964`'s 11:01 UTC — so it stays open/not-done at this pin. See `docs/ha-delivery-matrix.md`.
- **ADR-1005 engine principals + on-behalf guard** — `server/core/src/on_behalf_guard.hpp` (rejects on-behalf-of assertions on every ingress except the four health-probe paths).
- **`/auto` pre-flight + deployment** — `server/core/src/preflight_routes.cpp`, `server/core/src/deployment_routes.cpp`.
- **DEX / network quality / device pages** — `server/core/src/dex_routes.cpp`, `server/core/src/network_routes.cpp`, `server/core/src/device_routes.cpp`.
- **Fleet visualization (3D)** — `server/core/src/viz_routes.cpp`.
- **Plugin-config plane** (ADR-3005, `docs/adr/3005-plugin-config-store.md`).
- **PKI/CA + KEK routes** — `server/core/src/ca_routes.cpp`, `server/core/src/kek_routes.hpp`.
- **Management-plane SPKI pinning** (#1422) — enforced gateway-side in `gateway/apps/yuzu_gw/src/yuzu_gw_authz.erl` (`mgmt_peer_pins`: SPKI SHA-256 of the server leaf + serverAuth EKU); `server/core/src/server.cpp` documents the contract and surfaces the rejection.
- **Agent daily-sync framework** (ADR-0016, `docs/adr/0016-agent-daily-sync-framework.md`) — `agents/core/src/sync_scheduler.cpp`.
- **New agent plugins**: `power_health`, `disk_actions`, `filesystem_posture`, `device_identity`, `netprobe`, `procfetch`, `rdp_control`, `vuln_scan` (all present under `agents/plugins/`).

---

## Phase 0: Foundation Completion

*Close the remaining Foundation-tier gaps. These are prerequisites for production use.*

### Issue 0.1: HTTPS for Web Dashboard :white_check_mark:
**Capability:** 18.9 | **Scope:** Server | **Status:** Done

`httplib::SSLServer` with OpenSSL support (`-DCPPHTTPLIB_OPENSSL_SUPPORT`). CLI flags: `--https`, `--https-port` (default 8443), `--https-cert`, `--https-key`, `--no-https-redirect`. HTTP-to-HTTPS 301 redirect server. Secure cookie flag when HTTPS enabled. Settings UI has TLS configuration section.

**Files:** `server/core/src/server.cpp` (lines 2531-2560, 4412-4462), `server/core/meson.build` (OpenSSL dep)

### Issue 0.2: Agent OTA Update Management :white_check_mark:
**Capability:** 1.4 | **Scope:** Agent + Server | **Status:** Done

`CheckForUpdate`/`DownloadUpdate` RPCs in agent.proto. Full updater implementation with hash verification and platform-specific self-update.

**Files:** `agents/core/src/updater.cpp`, `proto/yuzu/agent/v1/agent.proto` (lines 29-33, 130-157)

### Issue 0.3: Secure Temp File Creation in Filesystem Plugin :white_check_mark:
**Capability:** 10.12 | **Scope:** Plugin | **Status:** Done

`yuzu_create_temp_file()` and `yuzu_create_temp_dir()` in SDK with secure permissions (POSIX 0600/0700, Windows owner-only DACL). Filesystem plugin exposes `create_temp` and `create_temp_dir` actions.

**Files:** `sdk/include/yuzu/plugin.h` (lines 207-244), `agents/plugins/filesystem/src/filesystem_plugin.cpp`

### Issue 0.4: SDK Utility Functions (JSON/Table Conversion) :white_check_mark:
**Capability:** 24.6 | **Scope:** SDK | **Status:** Done

`yuzu_table_to_json()`, `yuzu_json_to_table()`, `yuzu_split_lines()`, `yuzu_generate_sequence()`, `yuzu_free_string()` implemented in plugin.h C ABI.

**Files:** `sdk/include/yuzu/plugin.h` (lines 153-206)

### Issue 0.5: Complete Foundation Partial Items :white_check_mark:
**Capabilities:** 1.8, 4.5, 10.3 | **Scope:** Agent + Plugins | **Status:** Done

- **1.8** `connection_info` action: server address, TLS status, session ID, gRPC channel state, reconnect count, latency, uptime.
- **4.5** `dns_cache` action: Windows `DnsGetCacheDataTable`, Linux systemd-resolved query.
- **10.3** `offset`/`limit` parameters on filesystem `read` action (1-based line offset, configurable max).

**Files:** `agents/plugins/diagnostics/src/diagnostics_plugin.cpp`, `agents/plugins/network_config/src/network_config_plugin.cpp`, `agents/plugins/filesystem/src/filesystem_plugin.cpp`

---

## Phase 1: Server-Side Data Infrastructure

*Build the server-side systems that all advanced features depend on: persistent response storage, device metadata, audit logging, and a query language.*

### Issue 1.1: Server-Side Response Persistence :white_check_mark:
**Capabilities:** 20.2, 20.4 | **Scope:** Server | **Status:** Done

Originally shipped on SQLite (WAL mode); migrated to PostgreSQL under the Wave 1.2 store migration (ADR-0039, PR #2691). `StoredResponse` struct, configurable TTL retention (default 90 days), background cleanup thread.

**Files:** `server/core/src/response_store.hpp`, `server/core/src/response_store.cpp`

### Issue 1.2: Response Filtering, Pagination, and Sorting :white_check_mark:
**Capability:** 20.2 | **Scope:** Server | **Status:** Done

`ResponseQuery` struct with agent_id, status, time range (since/until), limit/offset pagination. Exposed via `GET /api/responses/{instruction_id}` with query parameters.

**Files:** `server/core/src/response_store.hpp`, `server/core/src/response_store.cpp`, `server/core/src/server.cpp`

### Issue 1.3: Response Aggregation Engine
**Capability:** 20.3 | **Scope:** Server

Server-side aggregation of response data. Support group-by columns with `count`, `sum`, `min`, `max` operations. Aggregation definitions are attached to instruction definitions (when those exist) or specified ad-hoc. Return aggregated results alongside raw data.

**Files:** `server/core/src/response_store.cpp`, `proto/yuzu/server/v1/management.proto`

### Issue 1.4: Audit Trail System :white_check_mark:
**Capability:** 21.2 | **Scope:** Server | **Status:** Done

`AuditStore` with SQLite WAL backend. `AuditEvent` struct: timestamp, principal, principal_role, action, target_type, target_id, detail, source_ip, user_agent, session_id, result. Query with filtering and pagination. Default 365-day retention.

**Files:** `server/core/src/audit_store.hpp`, `server/core/src/audit_store.cpp`, `server/core/src/server.cpp`

### Issue 1.5: Device Tagging System :white_check_mark:
**Capabilities:** 3.10, 3.6, 3.7 | **Scope:** Server + Agent | **Status:** Done

`TagStore` on the PostgreSQL substrate (ADR-0050, schema `tag_store`). `DeviceTag` struct: agent_id, key, value, source (agent/server/api/mcp), updated_at. Validation: key max 64 chars `[a-zA-Z0-9_.:-]`, value max 448 bytes. Agent tag sync from heartbeat. `agents_with_tag()` for scope queries. Device criticality (3.6) and location (3.7) implemented as special-purpose tags.

**Files:** `server/core/src/tag_store.hpp`, `server/core/src/tag_store.cpp`, `agents/plugins/tags/src/tags_plugin.cpp`

### Issue 1.6: Scope Expression Engine and Device Filtering :white_check_mark:
**Capabilities:** 19.3, 2.2, 2.11 | **Scope:** Server | **Status:** Done

494-line recursive-descent parser. 9 operators: `==`, `!=`, `LIKE`, `<`, `>`, `<=`, `>=`, `IN`, `CONTAINS`. AND/OR/NOT combinators, wildcard LIKE matching, case-insensitive comparison, max nesting depth 10. `AttributeResolver` callback for evaluation. Target estimation via `GET /api/target/estimate`.

**Files:** `server/core/src/scope_engine.hpp`, `server/core/src/scope_engine.cpp`, `server/core/src/server.cpp`

### Issue 1.7: CSV and JSON Data Export
**Capabilities:** 20.5, 24.5 | **Scope:** Server

Export response data and inventory as CSV or JSON. Support:
- Export specific instruction responses by ID
- Export inventory data by plugin
- Generic JSON-to-CSV conversion endpoint
- Stream large exports to avoid memory pressure

**Files:** `server/core/src/server.cpp`, new `server/core/src/data_export.cpp`

---

## Phase 2: Instruction System

*Transform ad-hoc commands into a governed instruction lifecycle. YAML-defined instruction definitions with typed parameter and result schemas, executed through the existing `CommandRequest` wire protocol, tracked by `ExecutionTracker`, stored by `ResponseStore`, and audited by `AuditStore`. See `docs/Instruction-Engine.md` for the full architectural blueprint and `docs/yaml-dsl-spec.md` for the YAML specification.*

### Issue 2.1: Instruction Definitions
**Capability:** 2.6 | **Scope:** Server + Proto

YAML-first InstructionDefinitions (see `docs/yaml-dsl-spec.md` Section 3). Each definition stored with `yaml_source` column (verbatim YAML, source of truth) plus denormalized columns for efficient queries. Features:
- **Content model:** `apiVersion: yuzu.io/v1alpha1`, `kind: InstructionDefinition`, `metadata` + `spec` + `status`
- **Type:** `question` (read-only) or `action` (may modify state)
- **Execution spec:** plugin, action, concurrency mode (per-device/per-definition/per-set/global:N/unlimited), stagger
- **Parameter schema:** JSON Schema subset — type (string, boolean, int32, int64, datetime, guid), required, validation (maxLength, pattern, enum, min/max)
- **Result schema:** Typed columns (bool, int32, int64, string, datetime, guid, clob) with aggregation config (groupBy + operations)
- **Approval mode:** auto (default for questions), role-gated (default for actions), always
- **Compatibility:** minAgentVersion, requiredPlugins — server-side pre-dispatch check
- **Legacy command shim:** Auto-generate definitions from plugin descriptors on server startup (Section 15 of Instruction-Engine.md)

CRUD via REST API. Import/export as YAML and JSON.

**Files:** `server/core/src/instruction_store.hpp`, `server/core/src/instruction_store.cpp`, `server/core/src/server.cpp`

### Issue 2.2: Instruction Sets (Grouping and Organization)
**Capability:** 2.7 | **Scope:** Server

InstructionSets are the **permission boundary** (see `docs/yaml-dsl-spec.md` Section 4). Users execute definitions within sets; authors publish to sets; approvers approve set-governed actions. Sets declare:
- `contents` — list of InstructionDefinition IDs, PolicyFragment IDs, workflow templates
- `permissions` — executeRoles, authorRoles, approveRoles
- `defaults` — approvalMode, responseRetentionDays, targetEstimationRequiredAbove
- `publishing` — signed flag, visibility (org/public)

CRUD via management API. RBAC system (Phase 3) binds `Principal + Role + SecurableType(InstructionSet) + Operation`.

**Files:** `server/core/src/instruction_store.hpp`, `server/core/src/instruction_store.cpp`

### Issue 2.3: Instruction Scheduling
**Capability:** 2.9 | **Scope:** Server

`ScheduleEngine` evaluates due schedules on a background thread (60-second tick). Schedule model:
- frequency_type (daily, weekly, monthly, interval)
- interval_minutes for sub-day granularity
- time_of_day, day_of_week, day_of_month for calendar schedules
- scope_expression for device targeting (evaluated by `ScopeEngine`)
- requires_approval flag — creates approval record instead of immediate dispatch
- next/last execution tracking, execution_count

Dispatches via the same `CommandRequest` path. CRUD via management API.

**Files:** `server/core/src/schedule_engine.hpp`, `server/core/src/schedule_engine.cpp`, `server/core/src/server.cpp`

### Issue 2.4: Instruction Approval Workflows
**Capability:** 2.10 | **Scope:** Server

`ApprovalManager` implements approval gating per Instruction-Engine.md Section 6.1 `spec.approval.mode`:
- `auto` — questions auto-approved, no gate
- `role-gated` — actions require approval from a user with an approveRole on the InstructionSet
- `always` — all executions require explicit approval

Rules: submitter cannot approve own actions. Approval record includes submitted_by, reviewed_by, review_comment, scope_expression. On approval, dispatch proceeds automatically. On rejection, execution is marked rejected with comment.

**Files:** `server/core/src/approval_manager.hpp`, `server/core/src/approval_manager.cpp`, `server/core/src/server.cpp`

### Issue 2.5: Instruction Hierarchies and Follow-Up Workflows
**Capability:** 2.8 | **Scope:** Server

`Execution.parent_id` tracks parent-child relationships. Follow-up instructions dispatched using parent's response data as input. `ExecutionTracker.get_children()` enables drill-down. Previous-result filtering: server extracts columns from parent response, passes as parameters to child definition.

**Files:** `server/core/src/execution_tracker.hpp`, `server/core/src/execution_tracker.cpp`

### Issue 2.6: Instruction Progress Tracking and Statistics
**Capabilities:** 2.12, 1.9 | **Scope:** Server + Agent

`ExecutionTracker` maintains per-execution aggregate status per Instruction-Engine.md Section 9.3:
- `Execution` struct: agents_targeted, agents_responded, agents_success, agents_failure
- `AgentExecStatus` struct: per-agent dispatched_at, first_response_at, completed_at, exit_code, error_detail
- `ExecutionSummary` with progress_pct
- Aggregate status: succeeded, completed (≥minSuccessPercent), failed, timed_out, cancelled, partial

Error codes follow the 4-category taxonomy (1xxx plugin, 2xxx transport, 3xxx orchestration, 4xxx agent).

**Files:** `server/core/src/execution_tracker.hpp`, `server/core/src/execution_tracker.cpp`, `server/core/src/server.cpp`

### Issue 2.7: Instruction Rerun and Cancellation
**Capability:** 2.13 | **Scope:** Server + Agent

- **Rerun:** `ExecutionTracker.create_rerun()` — clone execution with same params/scope, set `rerun_of`, optionally target only failed agents
- **Cancel:** `ExecutionTracker.mark_cancelled()` — set status=cancelled, send cancel signal to agents via heartbeat flag or new `CancelCommand` message

**Files:** `server/core/src/execution_tracker.hpp`, `server/core/src/execution_tracker.cpp`, `server/core/src/server.cpp`, `agents/core/src/agent.cpp`

### Issue 2.8: Error Code Taxonomy (1xxx-4xxx)
**Scope:** Server + Agent

Implement the 4-category error code taxonomy from `docs/Instruction-Engine.md` Section 9: 1xxx plugin, 2xxx transport, 3xxx orchestration, 4xxx agent. Each code has defined retry semantics. Per-definition `minSuccessPercent` determines aggregate execution status.

**Files:** `server/core/src/execution_tracker.hpp`, `server/core/src/execution_tracker.cpp`, `agents/core/src/agent.cpp`, `proto/yuzu/common/v1/common.proto`

### Issue 2.9: Concurrency Enforcement (real-usage scope, ADR-1007)
**Scope:** Server | **Status:** Partial — the four other originally advertised modes are out of scope by decision, not pending; only per-device enforcement shipped (ADR-1007, 2026-09-02). ADR-1007 itself records this: "`docs/roadmap.md` Issue 2.9 no longer claims 'Done'; it reflects the real, narrower scope this ADR ships" (`docs/adr/1007-concurrency-enforcement-scope.md:986`).

Only `per-device` is enforced, server-side, via a dedicated `concurrency_claims` table in
`execution_tracker`'s Postgres schema (a partial unique index gives race-free claim/release — see
ADR-1007). This is a corrected scope, not the originally-documented 5 modes: a real-usage audit of
shipped `content/definitions/*.yaml` found `per-definition`/`global`/`global-singleton` attach
exclusively to catalog-only `plugin: server`-class definitions with no live agent-dispatch path
(building DSL enforcement for them would guard a path those 42 operations don't take), and
`per-set` has zero real usage and no defined grouping mechanism anywhere. See
`docs/yaml-dsl-spec.md` §12 and `docs/Instruction-Engine.md` §10 for the corrected behavior
description.

**Files:** `server/core/src/execution_tracker.{hpp,cpp}`, `server/core/src/dispatch_scope_ladder.hpp`, `server/core/src/workflow_routes.{hpp,cpp}`, `server/core/src/schedule_runner.{hpp,cpp}`

### Issue 2.10: YAML Authoring UI (Form + CodeMirror)
**Scope:** Server

Extend `instruction_ui.cpp` with form mode (input fields, parameter/result builders) and YAML mode (CodeMirror 6 editor, server-side validation). Import/export endpoints. Follows HTMX fragment pattern. Design: `docs/Instruction-Engine.md` Section 11.

**Files:** `server/core/src/instruction_ui.cpp`, `server/core/src/instruction_store.cpp`, `server/core/src/server.cpp`

### Issue 2.11: Legacy Command Shim
**Scope:** Server

Auto-generate InstructionDefinitions from plugin descriptors (`YuzuPluginDescriptor.actions[]`). Bridges ad-hoc commands into the governed pipeline with open-schema parameters. CLI tool: `yuzu-admin generate-definitions`. Design: `docs/Instruction-Engine.md` Section 15.

**Files:** New `server/core/src/legacy_shim.cpp`, `server/core/src/instruction_store.cpp`, `server/core/src/server.cpp`

### Issue 2.12: Structured Result Envelope
**Scope:** Server + Agent

Implement the canonical `InstructionResult` envelope from `docs/Instruction-Engine.md` Section 18. Typed columns (bool, int32, int64, string, datetime, guid, clob) with structured rows. Prerequisite for workflow chaining, policy evaluation, and typed data export.

**Files:** `server/core/src/response_store.hpp`, `server/core/src/response_store.cpp`, `server/core/src/execution_tracker.cpp`, `agents/core/src/agent.cpp`

---

## Phase 3: Security, RBAC, and Access Control

*Enterprise authentication, granular permissions, and security response capabilities.*

### Issue 3.1: Granular RBAC System
**Capability:** 18.3 | **Scope:** Server

Replace the two-role system with a full RBAC model:
- **Principals:** Users or groups with unique IDs
- **Roles:** Named permission containers (built-in + custom)
- **Securable types:** Categories of protected resources (InstructionSet, Policy, Security, Infrastructure, etc.)
- **Operations:** Per-securable-type actions (Read, Write, Execute, Delete, Approve, etc.)
- **Permissions:** Bind role + securable type + operation + allowed/denied

CRUD for all entities via management API and Settings UI. RBAC can be globally enabled/disabled. System roles cannot be deleted.

**Files:** `server/core/src/auth.cpp`, new `server/core/src/rbac.cpp`, `server/core/src/settings_ui.cpp`, `proto/yuzu/server/v1/management.proto`

### Issue 3.2: Management Groups
**Capabilities:** 19.4, 18.4, 16.3 | **Scope:** Server

Hierarchical device groups for scoping access, policies, and operations:
- Static membership (manual device assignment) or dynamic (scope expression evaluation)
- Nested hierarchy (parent/child groups)
- Role assignments scoped to management groups (Principal + Role + ManagementGroup triple)
- Policies assigned to management groups
- All list/query endpoints filter results by the caller's group visibility

CRUD via management API and dashboard UI.

**Files:** New `server/core/src/management_groups.cpp`, `server/core/src/server.cpp`, `server/core/src/rbac.cpp`, `proto/yuzu/server/v1/management.proto`

### Issue 3.3: Token-Based API Authentication
**Capability:** 18.7 | **Scope:** Server

API tokens for programmatic access alongside session cookies:
- Generate long-lived tokens with optional expiry
- Per-token scope (all operations, or restricted to specific instruction sets)
- Token passed via `Authorization: Bearer <token>` header or custom `X-Yuzu-Token` header
- Token CRUD in Settings UI (admin) and via management API
- Rate limiting per token

**Files:** `server/core/src/auth.cpp`, `server/core/src/server.cpp`, `server/core/src/settings_ui.cpp`

### Issue 3.4: OIDC / SSO Integration
**Capability:** 18.5 | **Scope:** Server

Replace the greyed-out SSO stub with a real OIDC flow:
- Configure IdP (issuer URL, client ID, client secret, redirect URI)
- Authorization code flow with PKCE
- Map OIDC claims to Yuzu principals and roles
- Session creation after successful OIDC authentication
- Support multiple IdPs (future)

**Files:** `server/core/src/auth.cpp`, `server/core/src/login_ui.cpp`, `server/core/src/server.cpp`, `server/core/src/settings_ui.cpp`

### Issue 3.5: REST / HTTP Management API (v1)
**Capability:** 24.3 | **Scope:** Server

Formalize the existing HTTP endpoints into a versioned REST API at `/api/v1/`:
- All entity CRUD follows consistent patterns: `GET /api/v1/{entity}`, `GET /api/v1/{entity}/{id}`, `POST /api/v1/{entity}`, `PUT /api/v1/{entity}/{id}`, `DELETE /api/v1/{entity}/{id}`, `POST /api/v1/{entity}/search`
- Search endpoint accepts filter expression tree, sort, start, pageSize
- JSON request/response bodies
- Authentication via session cookie or API token
- OpenAPI/Swagger spec generation

**Files:** `server/core/src/server.cpp`, new `server/core/src/rest_api.cpp`

### Issue 3.6: Device Quarantine (Network Isolation)
**Capabilities:** 9.6, 9.9 | **Scope:** Plugin + Server

New `quarantine` plugin:
- **QuarantineDevice:** Modify routing tables/hosts file to restrict networking to management channel only. Disable IPv6. Accept whitelist IPs.
- **UnquarantineDevice:** Restore original network config. Optional reboot.
- **GetQuarantineStatus:** Return current quarantine state.
- **ModifyQuarantineWhitelist:** Add IPs to whitelist of quarantined device.

Server-side: track quarantine state per device, history, and whitelist. Dashboard indicator for quarantined devices.

**Files:** New `agents/plugins/quarantine/`, `server/core/src/server.cpp`

### Issue 3.7: IOC Checking
**Capability:** 9.7 | **Scope:** Plugin

New `ioc` plugin or add to existing `security`-related plugin:
- **CheckSimpleIoc:** Match IP ranges, IP addresses, ports, domains, and file hashes against local endpoint state. Multiple parameters OR'd together.
- File spec checks done live; network checks use historical connection data (configurable lookback window, default 7 days).
- Cross-platform where data sources exist (Windows primary, Linux/macOS best-effort).

**Files:** New `agents/plugins/ioc/`

### Issue 3.8: Certificate Inventory and Management
**Capability:** 9.8 | **Scope:** Plugin

New `certificates` plugin:
- **GetCertificates:** Enumerate certificates in system stores. Return subject, issuer, thumbprint, dates, serial number, store name.
- **DeleteCertificates:** Remove certificate by thumbprint from specified store.
- Windows: CryptoAPI certificate store enumeration. Linux: `/etc/ssl/certs`. macOS: Keychain.

**Files:** New `agents/plugins/certificates/`

### Issue 3.9: Scope DSL Extensions (MATCHES, EXISTS, len, startswith)
**Scope:** Server

Add 4 operators to `scope_engine.cpp`: `MATCHES` (regex), `EXISTS` (tag presence), `len()` (string length), `startswith()` (prefix check). Parser architecture supports these without structural changes — add `TokenType` variants and `CompOp` cases. Design: `docs/Instruction-Engine.md` Section 8.2.

**Files:** `server/core/src/scope_engine.hpp`, `server/core/src/scope_engine.cpp`, `tests/unit/`

---

## Phase 4: Agent Infrastructure

*Agent-side capabilities that enable advanced features: persistent storage, content distribution, triggers, and user interaction.*

### Issue 4.1: Agent-Side Key-Value Storage :white_check_mark:
**Capabilities:** 23.1, 23.3 | **Scope:** Agent SDK + Plugin | **Status:** Done

Add persistent key-value storage to the agent, backed by the existing `agent.db` SQLite database:
- **Storage.Set:** Store a named table (overwrite or append with max row limit)
- **Storage.Get:** Retrieve by name
- **Storage.List:** List all table names
- **Storage.Delete:** Remove a table
- **Storage.Check:** Test if table exists

Expose via plugin SDK (new `yuzu_ctx_storage_*` functions in `plugin.h`) and as a built-in `storage` plugin.

**Files:** `sdk/include/yuzu/plugin.h`, `sdk/include/yuzu/plugin.hpp`, `agents/core/src/agent.cpp`, new `agents/plugins/storage/`

### Issue 4.2: HTTP Download and Upload (Agent-Initiated) :white_check_mark:
**Capabilities:** 13.3, 13.4, 10.13 | **Scope:** Plugin + Agent | **Status:** Done

New `http` plugin or extend agent core:
- **HttpGetFile:** Download file from URL with hash/size verification. Support both server content channel and external URLs. Return temp file path (cleaned up after instruction).
- **HttpPost:** Send data to external endpoint. Support custom headers, content types, authorization. Return status code and response body.
- **FileUpload:** Upload file from endpoint to server (reverse of HttpGetFile). Streaming upload for large files.

**Files:** New `agents/plugins/http_client/`, `server/core/src/server.cpp` (file receive endpoint)

### Issue 4.3: Content Staging and Execution :white_check_mark:
**Capabilities:** 13.1, 13.2 | **Scope:** Agent + Server | **Status:** Done

Server-to-agent content distribution:
- **Stage:** Server pushes content manifest, agent downloads files to local staging directory. Verify integrity via hash.
- **StageAndExecute:** Download to temp directory, execute command, clean up. Return exit code and output.

Server side: content repository for hosting files, manifest generation, and download tracking.

**Files:** New `agents/plugins/content_dist/`, `server/core/src/server.cpp` (content hosting endpoints)

### Issue 4.4: Agent Sleep and Stagger Control :white_check_mark:
**Capability:** 1.6 | **Scope:** Agent | **Status:** Done

- **Sleep:** Server instructs agent to pause for N seconds (testing/maintenance).
- **Stagger:** Agent introduces random delay (0 to N seconds) before executing an instruction, preventing thundering herd on broadcast. Configurable default stagger range.

Implement as built-in agent behavior (not a plugin), triggered by fields in `CommandRequest`.

**Files:** `agents/core/src/agent.cpp`, `proto/yuzu/agent/v1/agent.proto`

### Issue 4.5: Trigger Framework (Agent-Side) :white_check_mark:
**Capabilities:** 17.1-17.6 | **Scope:** Agent SDK + Agent Core | **Status:** Done

Add a trigger evaluation engine to the agent:
- **Plugin SDK extension:** New `yuzu_register_trigger` function in `plugin.h` for plugins to register trigger handlers.
- **Trigger types:**
  - `interval`: Timer-based (configurable seconds/minutes/hours, min 30s)
  - `file_change`: Filesystem watcher (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows)
  - `directory_change`: Recursive directory monitoring
  - `service_status_change`: React to service start/stop/crash (Windows SCM, systemd on Linux)
  - `event_log`: React to Windows Event Log entries matching XPath filter
  - `agent_startup`: Fire on agent boot
- **Debouncing:** Configurable debounce window to coalesce rapid events.
- **Trigger templates:** Server-defined trigger configurations pushed to agents.

Triggers invoke a callback (plugin action + params) when they fire. Used by the policy engine.

**Files:** `sdk/include/yuzu/plugin.h`, `sdk/include/yuzu/plugin.hpp`, `agents/core/src/agent.cpp`, new `agents/core/src/trigger_engine.cpp`

### Issue 4.6: Desktop User Interaction (Windows) :white_check_mark:
**Capabilities:** 14.1-14.3 | **Scope:** Plugin | **Status:** Done

New `interaction` plugin (Windows-only initially):
- **ShowNotification:** Toast notification (Information/Warning/Error) with configurable timeout. Returns immediately.
- **ShowAnnouncement:** Modal dialog with description, optional icon, choices, and default buttons (Later/Dismiss). Sync or async.
- **ShowQuestion:** Yes/No dialog with customizable button text. Sync or async.
- Async mode: returns immediately, response delivered via topic when user interacts.
- Target specific user session or all sessions.

**Files:** New `agents/plugins/interaction/`

### Issue 4.7: Agent Logging and Remote Log Retrieval :white_check_mark:
**Capability:** 1.7 | **Scope:** Agent + Plugin | **Status:** Done

Extend the `diagnostics` plugin:
- **GetKeyFiles:** Return paths to config, executable, log, data directory, temp directory.
- **SetLogLevel:** Dynamically change agent log level without restart.
- **GetLog:** Retrieve last N lines of agent log (or by time range). Stream large logs.

**Files:** `agents/plugins/diagnostics/src/diagnostics_plugin.cpp`, `agents/core/src/agent.cpp`

### Issue 4.8: service.set_start_mode Cross-Platform Primitive :white_check_mark:
**Scope:** Plugin | **Status:** Done

Add `set_start_mode` action to the `services` plugin. Parameters: `serviceName`, `mode` (automatic/manual/disabled/masked). Cross-platform: Windows `ChangeServiceConfigW`, Linux `systemctl enable/disable/mask`, macOS `launchctl enable/disable`. `masked` maps to `disabled` with warning on non-Linux. Returns previous/new/effective mode. Design: `docs/Instruction-Engine.md` Section 16.

**Files:** `agents/plugins/services/src/services_plugin.cpp`

---

## Phase 5: Policy Engine and Compliance

*Desired-state policies with scheduled evaluation (`PolicyEvaluator`, default 3600s interval,
`policy_evaluator.hpp:107`) and operator-gated remediation — detection is on a schedule, applying a
fix is always an explicit action, never automatic (`docs/user-manual/policy-engine.md` § Compliance
Evaluation Pipeline: "Remediation is never automatic"). Distinct from Guardian's (Phase 16)
kernel-event-driven, real-time, agent-side enforcement — do not conflate the two.*

### Issue 5.1: Policy Rules and Fragments :white_check_mark:
**Capabilities:** 16.1, 16.2 | **Scope:** Server + Agent | **Status:** Done — note: "Fix" below means *evaluable-and-remediable*, not auto-remediated; applying the fix is a separate, explicit operator-gated action (`POST /api/policies/{id}/remediate`), never triggered automatically by evaluation

Core policy engine:
- **Fragments:** Reusable compliance check/fix code blocks. Each fragment defines a check instruction (evaluate state) and optional fix instruction (remediate). Parameters are configured when rules are created.
- **Rules:** Bind a fragment to one or more triggers. Rule types: Check (evaluate only) or Fix (evaluate, with a fix instruction available for a separate, explicit operator-gated remediation call — evaluation alone never remediates). Status codes: Received, CheckErrored, CheckFailed, CheckPassed, FixErrored, FixPassed, FixFailed.
- **Agent-side evaluation:** Rules evaluate on trigger fire, agent startup, and initial receipt. De-bounce prevents rapid re-evaluation.
- **Server-side management:** CRUD for fragments and rules via management API.

**Files:** New `server/core/src/policy_engine.cpp`, `agents/core/src/agent.cpp`, `proto/yuzu/agent/v1/agent.proto` (policy push/status RPCs)

### Issue 5.2: Policy Assignment and Deployment :white_check_mark:
**Capabilities:** 16.3, 16.8 | **Scope:** Server | **Status:** Done

- Policies are assigned to management groups (from Issue 3.2)
- Changes accumulate as pending; admin explicitly deploys
- Deployment compiles the policy document, hashes it, and pushes to agents
- Agents pull policy on next connection or receive push notification
- Pending changes review UI in dashboard

**Files:** `server/core/src/policy_engine.cpp`, `server/core/src/server.cpp`, dashboard UI updates

### Issue 5.3: Compliance Dashboard and Statistics :white_check_mark:
**Capabilities:** 16.4, 16.5 | **Scope:** Server | **Status:** Done

- Device compliance status per policy and per rule
- Fleet-wide compliance posture summary (% compliant, % non-compliant, % unknown)
- Rule evaluation history (chronological log with status changes)
- Effectiveness metrics: time to compliance, remediation success rate
- Dashboard UI: compliance tab with drill-down from fleet → policy → rule → device

**Files:** `server/core/src/policy_engine.cpp`, `server/core/src/dashboard_ui.cpp`, `server/core/src/server.cpp`

### Issue 5.4: Policy Cache Invalidation and Force Re-Evaluation :white_check_mark:
**Capabilities:** 16.7 | **Scope:** Agent + Server | **Status:** Done

- **Invalidate:** Reset agent's policy to empty; agent re-downloads on next connection.
- **ForceStatusReport:** Schedule a full compliance status report on next agent restart.
- Expose both as actions dispatchable from the dashboard.

**Files:** `agents/core/src/agent.cpp`, `server/core/src/server.cpp`

### Issue 5.5: CEL Adoption for Policy Compliance Expressions :white_check_mark:
**Scope:** Server | **Status:** Done
**Depends on:** 5.1

Adopt [Common Expression Language (CEL)](https://github.com/google/cel-spec) for typed policy evaluation. CEL handles `spec.compliance.expression`, `spec.fix.when`, and `spec.rollout.condition` — typed evaluation that the scope DSL cannot do. The scope DSL stays for device targeting. abseil is already a transitive dep via gRPC, making cel-cpp a natural addition. Design: `docs/Instruction-Engine.md` Section 8.3.

**Files:** `vcpkg.json`, new `server/core/src/cel_evaluator.cpp`, `server/core/src/policy_engine.cpp`

---

## Phase 6: Windows Platform Depth

*Registry, WMI, per-user operations, and Windows-specific advanced capabilities.*

### Issue 6.1: Registry Plugin (Read/Write/Enumerate) :white_check_mark:
**Capabilities:** 12.4-12.6 | **Scope:** Plugin | **Status:** Done

New `registry` plugin (Windows-only):
- **GetValue:** Read registry value by hive/subkey/name. Return name, type, data.
- **SetValue:** Write registry value. Support REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ.
- **DeleteKey / DeleteValue:** Remove registry keys or values.
- **KeyExists / ValueExists:** Check existence.
- **EnumerateKeys / EnumerateValues:** Recursive listing.

All operations support HKLM, HKCU, HKCR, HKU hives.

**Files:** New `agents/plugins/registry/`

### Issue 6.2: Per-User Registry Operations :white_check_mark:
**Capability:** 12.7 | **Scope:** Plugin | **Status:** Done

Extend the registry plugin with per-user variants:
- Load each user's NTUSER.DAT hive
- Enumerate/get/set/delete across all user hives
- Dedicated methods: `EnumerateUserKeys`, `GetUserValues`, `SetUserValues`, `DeleteUserKey`, `DeleteUserValues`

**Files:** `agents/plugins/registry/src/registry_plugin.cpp`

### Issue 6.3: WMI Query and Method Invocation :white_check_mark:
**Capabilities:** 12.1, 12.2 | **Scope:** Plugin | **Status:** Done

New `wmi` plugin (Windows-only):
- **RunWmiQuery:** Execute WQL query against any WMI namespace. Return structured tabular results.
- **RunWmiInstanceMethod:** Call instance method on a WMI object.
- **RunWmiStaticMethod:** Call static method on a WMI class.
- COM initialization with proper cleanup. Structured output (not raw PowerShell text).

**Files:** New `agents/plugins/wmi/`

### Issue 6.4: Per-User Application Inventory :white_check_mark:
**Capability:** 7.5 | **Scope:** Plugin | **Status:** Done

Extend `installed_apps` plugin:
- Enumerate per-user installations (`list_per_user`) via each profile's `Software\Microsoft\Windows\CurrentVersion\Uninstall`, read from the live `HKEY_USERS\<SID>` hive or an offline `NTUSER.DAT` mount — the shared ladder in `agents/shared/win_profiles.hpp` (#2771), not a literal `HKCU` read.
- Distinguish system-wide from user-specific installs in output.

**Files:** `agents/plugins/installed_apps/src/installed_apps_plugin.cpp`

### Issue 6.5: File System Advanced Operations :white_check_mark:
**Capabilities:** 10.7-10.10, 10.14, 10.15 | **Scope:** Plugin | **Status:** Done

Extend the `filesystem` plugin:
- **GetFilePermissions:** ACL enumeration (Windows DACL, POSIX permissions)
- **GetDigitalSignature:** Authenticode/codesign verification (Windows WinVerifyTrust, macOS codesign)
- **GetVersionInfo:** PE version resource extraction (Windows)
- **FindAndReplace / FindAndDelete / WriteText / AppendText:** Text file manipulation operations
- **FindFileBySizeAndHash:** Locate files matching both size and hash criteria
- **FindDirectoryByName:** Find directories by name pattern

**Files:** `agents/plugins/filesystem/src/filesystem_plugin.cpp`

### Issue 6.6: Registry Change Trigger :white_check_mark:
**Capability:** 17.5 | **Scope:** Agent | **Status:** Done

Add `registry_change` trigger type to the trigger framework (Issue 4.5):
- Monitor HKLM or HKCR subkeys using Windows Registry change notification APIs
- Optional recursive monitoring of subkeys
- Used by the policy engine to react to registry modifications

**Files:** `agents/core/src/trigger_engine.cpp`

---

## Phase 7: Scale, Integration, and Advanced Features

*Multi-node architecture, external integrations, and remaining advanced/future capabilities.*

### Issue 7.1: Gateway Node Implementation
**Capability:** 22.5 | **Scope:** Erlang gateway (`gateway/`)

The Erlang gateway (`gateway/`) implements the command fanout plane. Core proxy
functionality (Register, Subscribe, Heartbeat batching, Inventory, StreamStatus)
is implemented. See `docs/erlang-gateway-blueprint.md`.

Remaining work:
- Proxy agent registrations to upstream server — **done**
- Batch heartbeats (reduce connection count on server) — **done**
- Proxy subscribe streams — **done**
- Report stream status to upstream — **done**
- Gateway handles local TLS termination — **done**
- Deploy at branch offices to reduce WAN traffic

**Files:** `gateway/` (Erlang/OTP, rebar3), `proto/yuzu/gateway/v1/gateway.proto`, `server/core/src/server.cpp` (GatewayUpstream handlers)

### Issue 7.1.1: Gateway Adjacency, Load Shedding, and Latency-Based Redistribution
**Capability:** 22.5 | **Scope:** Erlang gateway (`gateway/`)
**Depends on:** 7.1

Implement cluster-aware agent redistribution so gateway nodes can dynamically
balance agent load based on measured latency and node capacity:

- **Adjacency table** — each node tracks peer agent count, CPU/memory, inter-node RTT, drain state
- **Load shedding** — shed agents via GOAWAY when overloaded, draining, or rebalancing for a new node; rate-limited to prevent reconnection storms
- **Agent absorption** — accept reconnecting agents; optionally pull agents from overloaded peers
- **Latency-based redistribution** — measure agent↔node RTT from heartbeats, compute affinity scores, migrate agents to lower-latency peers when improvement exceeds threshold
- **Stability** — cooldown window and hysteresis to prevent oscillation
- **Telemetry** — adjacency updates, shed/absorb counts, migration decisions exposed as Prometheus metrics

**Design:** `docs/erlang-gateway-blueprint.md` § "Gateway Adjacency and Latency-Based Agent Redistribution"

**Files:** `gateway/apps/yuzu_gw/src/yuzu_gw_cluster.erl` (new), `gateway/apps/yuzu_gw/src/yuzu_gw_agent.erl`, `gateway/apps/yuzu_gw/src/yuzu_gw_telemetry.erl`

### Issue 7.2: System Health Monitoring and Statistics
**Capabilities:** 22.1, 22.6, 22.2 | **Scope:** Server

- **Health endpoint:** CPU, memory, connection counts, queue depths, per-component health
- **Statistics:** High-level (connected devices, in-flight instructions, pending approvals) and detailed (per-definition execution counts, response rates)
- **Topology:** Map of server nodes, gateways, and agent counts
- Expose via REST API and dashboard UI

**Files:** `server/core/src/server.cpp`, new `server/core/src/system_health.cpp`

### Issue 7.3: Runtime Configuration API
**Capability:** 22.4 | **Scope:** Server

Expose server configuration via REST API (no restart required for supported settings):
- `MaxInstructionTtlMinutes`, `MaxResponseTtlMinutes`, `MaxSimultaneousInFlightInstructions`
- Heartbeat interval range
- Session timeout
- NVD sync interval

Read-only for most settings initially; writable for operational tuning params.

**Files:** `server/core/src/server.cpp`, REST API endpoints

### Issue 7.4: System Notifications
**Capability:** 21.3 | **Scope:** Server

Server-generated alerts for:
- System health warnings (high CPU, low disk, connection limits approaching)
- License expiry warnings
- Agent enrollment surge
- Per-instruction and per-component notifications

Notification store with CRUD, filtering, and search. Dashboard notification bell.

**Files:** New `server/core/src/notifications.cpp`, `server/core/src/dashboard_ui.cpp`

### Issue 7.5: Active Directory / Entra Integration
**Capability:** 18.6 | **Scope:** Server

Replace the greyed-out AD/Entra section:
- LDAP/LDAPS connection to AD
- Import users and security groups as principals
- Map AD group membership to Yuzu roles
- Periodic sync for membership changes
- Entra ID (Azure AD) support via Microsoft Graph API

**Files:** `server/core/src/auth.cpp`, `server/core/src/settings_ui.cpp`, new `server/core/src/directory_sync.cpp`

### Issue 7.6: Custom Properties on Devices
**Capability:** 19.6 | **Scope:** Server

Extensible typed metadata on devices:
- **Custom property types:** Define name, data type (string, int, bool, datetime), validation
- **Custom property values:** Set/get per device
- Usable in scope expressions for targeting
- CRUD via management API and dashboard

**Files:** `server/core/src/server.cpp`, `proto/yuzu/server/v1/management.proto`

### Issue 7.7: Agent Deployment Jobs
**Capability:** 19.7 | **Scope:** Server

Server-initiated agent installation on discovered endpoints:
- Store installer binaries per OS/arch
- Create deployment jobs targeting IP/FQDN lists with credentials
- Job management: status tracking, cancellation, retry
- Supported OS enumeration

**Files:** New `server/core/src/deploy.cpp`, `server/core/src/server.cpp`

### Issue 7.8: Patch Deployment Workflow
**Capabilities:** 8.3-8.8 | **Scope:** Plugin + Server | **Status:** **Partial** — dispatch (#4138) and ingestion (#3676) are unwired; only records + audits work

New `patch` plugin and server-side patch management:
- **Plugin (agent-side):** Deploy patch (download + install), get status, test patch server connection, restart with notification
- **Server-side:** Patch metadata retrieval (KB details, severity, supersedence), per-device compliance tracking, fleet-wide compliance dashboard, deployment orchestration with reboot control

**Correction (ADR-0062, 2026-08-28):** server-side **deployment orchestration with reboot
control** (`PatchManager::execute_deployment()`) had zero production callers and was removed —
`POST /api/patches/deploy` creates deployment/target records only; see `docs/capability-map.md`
§8.3/§8.4/§8.6 and tracking issue #3669. **Patch metadata retrieval** and the **fleet-wide
compliance dashboard** are separately affected too: `PatchManager::record_patches()`, the only
method that writes patch inventory, was independently found to have zero production callers as
well (pre-existing, predates this migration) — see `docs/capability-map.md` §8.5/§8.7 and
tracking issue #3676. The remaining server-side capabilities listed above are unaffected.

**Further correction (2026-09-08, #4138):** `POST /api/patches/deploy` returns `201` and audits
"Deployed … to N agents", but dispatches no command to any agent — a stronger claim than #3669's
"creates records only" phrasing above suggested (that phrasing described the *absence* of the
removed reboot-control orchestration; #4138 confirms the *presence* of a success response/audit
trail with no dispatch behind it at all). Combined with #3676 (patch inventory can never
populate), the honest status is **records + audits only, no working dispatch or ingestion path**.

**Files:** New `agents/plugins/patch/`, `server/core/src/server.cpp`

### Issue 7.9: Product Packs (Bundled Definitions)
**Capability:** 22.8 | **Scope:** Server

Import/export bundles of instruction definitions, policy fragments, trigger templates:
- ZIP format containing definition files
- Upload via management API or dashboard
- Automatic instruction set creation
- Version tracking and conflict resolution

**Files:** `server/core/src/instruction_store.cpp`, `server/core/src/server.cpp`

### Issue 7.10: User Sessions and Group Membership Plugins
**Capabilities:** 6.2-6.5 | **Scope:** Plugin

Extend the `users` plugin:
- **GetPrimaryUser:** Heuristic-based primary user detection (most frequent login, console owner)
- **GetLocalGroupMembers:** Enumerate members of local groups (Administrators, Remote Desktop Users, etc.)
- **GetInboundConnectionHistory:** Login/logout and RDP session audit trail
- **GetActiveSessions:** RDP, console, SSH sessions with state

**Files:** `agents/plugins/users/src/users_plugin.cpp`

### Issue 7.11: Advanced User Interaction (Surveys, DND)
**Capabilities:** 14.4-14.6 | **Scope:** Plugin

Extend the `interaction` plugin (Issue 4.6):
- **ShowSurvey:** Multi-question form with customizable choices, icons, free-text option, and response aggregation. Unique survey names prevent repeat display. Response validity period.
- **SetDoNotDisturb:** Suppress notifications for N minutes.
- **GetActiveResponses:** List pending survey/question responses.

**Files:** `agents/plugins/interaction/src/interaction_plugin.cpp`

### Issue 7.12: Event Subscriptions (Webhooks)
**Capabilities:** 21.4, 21.5, 16.6 | **Scope:** Server

Push events to external systems:
- Webhook endpoints (HTTP POST with event payload)
- Event source configuration (which events trigger notifications)
- Management-group-scoped subscriptions
- Policy compliance change events
- Retry with exponential backoff

**Files:** New `server/core/src/event_subscriptions.cpp`, `server/core/src/server.cpp`

### Issue 7.13: ProductPack Ed25519 Trust Chain and Verification
**Scope:** Server
**Depends on:** 7.9

Implement Ed25519-based signing, 3-level key hierarchy (org root → signing key → manifest), and verification pipeline for ProductPacks. `tar.zst` format with `manifest.json` (per-file SHA-256), `manifest.sig`, `signing-key.der`. JSON revocation list. Server config: `require_signed`, `allow_self_signed`, `trust_store_path`. Self-signing CLI for dev. Design: `docs/Instruction-Engine.md` Section 13.

**Files:** New `server/core/src/pack_signing.cpp`, `server/core/src/instruction_store.cpp`, `server/core/src/server.cpp`

### Issue 7.14: Workflow Primitives (if, foreach, retry)
**Scope:** Server
**Depends on:** 2.5, 2.12

Server-side orchestration: `workflow.if` (branch on expression), `workflow.foreach` (iterate result rows, dispatch child per row), `workflow.retry` (retry with backoff). Compose existing InstructionDefinitions — no new execution semantics. Uses `Execution.parent_id` for linking. Design: `docs/Instruction-Engine.md` Section 7.9.

**Files:** New `server/core/src/workflow_engine.cpp`, `server/core/src/execution_tracker.cpp`, `server/core/src/instruction_store.cpp`

### Issue 7.15: WiFi Network Enumeration
**Capability:** 4.6 | **Scope:** Plugin

List visible SSIDs (signal, security, channel, BSSID) and saved WiFi profiles. Windows: WlanAPI. Linux: NetworkManager D-Bus / `nmcli`. macOS: CoreWLAN.

**Files:** `agents/plugins/network_config/src/network_config_plugin.cpp` or new `agents/plugins/wifi/`

### Issue 7.16: Wake-on-LAN Support
**Capability:** 4.7 | **Scope:** Plugin + Server

Send WoL magic packets from server or agent (peer wake for same-subnet). Check WoL adapter status. Windows: WMI. Linux: `ethtool`. macOS: `pmset`.

**Files:** `agents/plugins/network_actions/src/network_actions_plugin.cpp`, `server/core/src/server.cpp`

### Issue 7.17: Inventory Table Enumeration and Item Lookup
**Capabilities:** 15.3, 15.4 | **Scope:** Agent SDK + Server

`inventory.list_tables` — enumerate available data sources per plugin. `inventory.query` — query a table with optional filter, column subset, limit. Plugins declare tables via SDK. Server caches and exposes via REST.

**Files:** `sdk/include/yuzu/plugin.h`, `agents/core/src/agent.cpp`, `server/core/src/server.cpp`

### Issue 7.18: Device Discovery (Unmanaged Endpoints)
**Capability:** 19.5 | **Scope:** Plugin + Server

Discover unmanaged endpoints via agent-assisted subnet scanning (ARP, mDNS, ICMP), AD/DHCP import, or CSV upload. Server reconciles against registered agents: managed, unmanaged, or stale. Dashboard coverage view with deployment link (Issue 7.7).

**Files:** New `agents/plugins/discovery/`, new `server/core/src/device_discovery.cpp`, `server/core/src/server.cpp`

### Issue 7.20: MCP Server (Model Context Protocol) Phase 1 :white_check_mark:
**Capabilities:** 24.8, 24.9, 24.10 | **Scope:** Server | **Status:** Done
**Depends on:** 3.3, 3.5

Embedded MCP server at `POST /mcp/v1/` using JSON-RPC 2.0 transport. Enables AI models (e.g., Claude Desktop) to query fleet status and investigate endpoints. Phase 1 delivers 22 read-only tools, 3 resources, and 4 prompts. Three authorization tiers (readonly, operator, supervised) enforced before RBAC. MCP tokens use the existing API token system with an `mcp_tier` column and mandatory expiration (max 90 days). Kill switch: `--mcp-disable`, `--mcp-read-only`. Settings UI section with enable/disable and read-only toggles. Audit logging on every tool call (`action: "mcp.<tool_name>"`).

**Files:** `server/core/src/mcp_server.hpp`, `server/core/src/mcp_server.cpp`, `server/core/src/mcp_jsonrpc.hpp`, `server/core/src/mcp_policy.hpp`, `server/core/src/server.cpp`, `server/core/src/settings_ui.cpp`

---

## Phase 8: Visualization & Response Experience

*Make collected data actionable with charts, templates, and processing pipelines.*

### Issue 8.1: Response Visualization Engine :white_check_mark:
**Capabilities:** 20.6 (partial), new | **Scope:** Server | **Status:** Done

Server-side chart rendering for instruction responses. `spec.visualization` (singular) or `spec.visualizations` (canonical plural for multi-chart) on `InstructionDefinition`. Five chart types (`pie`, `bar`, `column`, `line`, `area`) × three processors (`single_series`, `multi_series`, `datetime_series`) with camelCase fields (`labelField`, `valueField`, `seriesField`, `xField`, `yField`, `maxCategories`, `valueLabel`); snake_case forms accepted as deprecated aliases. REST: `GET /api/v1/executions/{id}/visualization?definition_id=<id>&index=<N>` gated on `Response:Read`. Dashboard auto-renders a chart deck above the results table by reverse-resolving the dispatched `(plugin, action)` to a chart-bearing definition (`InstructionDefinition:Read` required for chart to appear). Renderer is Apache ECharts 5 (vendored at `server/core/vendor/echarts.min.js`, served at `/static/echarts.min.js`) wrapped by a thin adapter at `/static/yuzu-charts.js` that maps the visualization payload onto ECharts options and reads Yuzu design tokens (`--mds-color-chart-*`) for theming, so re-skinning Yuzu re-skins every chart with no JS rebuild. Engine row cap 10 000 with `rows_capped: true` flag; label cardinality cap 10 000.

Six demo charts ship as default examples — `content/definitions/visualization_demo_set.yaml` (`InstructionSet demo.visualization.fleet-posture`) and `content/packs/visualization-demo-pack.yaml` (`ProductPack pack.demo.visualization`) — covering vulnerability severity (the headline pie), Defender real-time protection, disk encryption protection state, firewall state per profile (multi-series column), certificate issuer breakdown (top-N + Other), and OS distribution.

**Files:** `server/core/src/visualization_engine.{hpp,cpp}`, `server/core/src/charts_js_bundle.cpp`, `server/core/src/instruction_store.{hpp,cpp}` (visualization_spec column + MigrationRunner v2), `server/core/src/rest_api_v1.cpp`, `server/core/src/dashboard_routes.{hpp,cpp}`, `docs/yaml-dsl-spec.md` § `spec.visualization`, `docs/user-manual/instructions.md` § Response Visualization, plus `tests/unit/server/test_visualization_engine.cpp` and `tests/unit/server/test_rest_visualization.cpp`.

### Issue 8.2: Response Templates :white_check_mark:
**Capability:** 20.6 | **Scope:** Server | **Status:** Done
**Depends on:** 8.1

Named response view configurations on `InstructionDefinition` — column subset, sort order, and filter presets the dashboard's filter-bar **View** dropdown surfaces. Storage is the `response_templates_spec` JSON column on `instruction_definitions` (migration v3); a `__default__` template is synthesised on read from `spec.result.columns` (preferred) or the plugin's column schema, so the dropdown is never empty even before an operator authors anything.

REST CRUD at `/api/v1/definitions/{id}/response-templates[/{template_id}]`. Filter ops accepted: `equals`, `not_equals`, `contains`, `starts_with`, `ends_with`. Reads gated on `InstructionDefinition:Read`, mutations on `InstructionDefinition:Write`. Audit events: `response_template.create`, `response_template.update`, `response_template.delete`. Dashboard auto-applies the `equals`-op clauses to the URL filter map; other ops are honoured by REST consumers but not auto-applied client-side in this revision.

**Files:** `server/core/src/response_templates_engine.{hpp,cpp}` (new), `server/core/src/instruction_store.{hpp,cpp}` (column + migration v3), `server/core/src/rest_api_v1.cpp` (5 routes), `server/core/src/dashboard_routes.{hpp,cpp}` (selector + visibility + template-driven sort/filter defaults), `docs/yaml-dsl-spec.md` § `spec.responseTemplates`, `docs/user-manual/instructions.md` § Response Templates, `docs/user-manual/rest-api.md` § Response Templates, `tests/unit/server/test_response_templates_engine.cpp`, `tests/unit/server/test_rest_response_templates.cpp`.

### Issue 8.3: Response Offloading (Data Export Streams) :white_check_mark:
**Capability:** 20.7 | **Scope:** Server | **Status:** Done
**Depends on:** 8.1

Named external HTTP endpoints that receive a copy of `agent.registered` and `execution.completed` events as they fire. Built around a sibling `OffloadTargetStore` (Postgres schema `offload_target_store`, ADR-0059 — migrated off the original SQLite `offload_targets.db`) wired into `AgentServiceImpl` next to the existing webhook fan-out, so every event that fires a webhook also fans out to every enabled offload target whose `event_types` filter matches.

Targets carry typed auth (none / bearer / basic / hmac), a server-side batching threshold (`batch_size > 1` accumulates events into a per-target buffer and flushes on threshold), and a unique `name` so a definition can name a specific subset via `spec.offload.targets` in YAML. `auth_credential` is `SecretCodec`-encrypted at rest (ADR-0010) and never returned by any REST surface (paranoia-double-check assertion in `test_rest_offload_targets.cpp`); a `has_credential` flag reports whether one is configured. Outgoing requests carry `X-Yuzu-Event`, `X-Yuzu-Event-Count`, and (for hmac) `X-Yuzu-Signature: sha256=<hex>` headers — receivers can share verification code with webhooks.

REST: `GET/POST/DELETE /api/v1/offload-targets`, `GET /api/v1/offload-targets/{id}`, `GET /api/v1/offload-targets/{id}/deliveries`. RBAC: `Infrastructure:Read`/`Write`. Audit events: `offload_target.create` (success | denied), `offload_target.delete`.

**Known follow-up:** the dispatcher does not yet extract `spec.offload.targets` from the originating definition — `fire_event(target_filter)` honours an explicit caller-supplied filter, but the agent-service fan-out passes none. Wiring the per-instruction filter through the command_id -> execution_id correlation (HA WS-1(1b): `ExecutionTracker::lookup_execution_id`, not the retired in-proc `cmd_execution_ids_` map) -> `definition_id` -> `InstructionStore` is tracked separately so the global fan-out path lands clean first.

**Files:** `server/core/src/offload_target_store.{hpp,cpp}` (Postgres migration, ADR-0059, fresh-start cutover — no backfill), `server/core/src/offload_routes.{hpp,cpp}`, `server/core/src/server.cpp` (`SecretCodec`-gated construction + AgentService wiring + route registration), `server/core/src/agent_service_impl.{hpp,cpp}` (`set_offload_target_store` + fire_event at 3 call sites), `docs/yaml-dsl-spec.md` § `spec.offload`, `docs/user-manual/rest-api.md` § Offload Targets, `docs/adr/0059-offload-target-store-postgres-migration.md`, `tests/unit/server/test_offload_target_store.cpp`, `tests/unit/server/test_rest_offload_targets.cpp`.

---

## Phase 9: Connector Framework & Multi-Source Inventory

*Federate inventory data from external management systems. Core enterprise integration capability.*

> **Owner decision (2026-09-07):** deferred — declared next priority since 2026-03 with zero commits;
> whether connectors are core estate-fact collection (ADR-1005 Decision 2) or use-case interpretation
> belonging in an engine is an **open placement question to be settled before any re-plan**. ADR-1005
> itself does not classify connectors either way, and Decision 2 places estate-fact *collection* in
> core — so "connectors belong in a UCE" is not a settled ADR-1005 consequence, it is the open question
> this deferral is waiting on. The sketches below (9.1–9.7) are retained for traceability but are not
> necessarily the design that ships once the placement question resolves — a core re-plan keeps the
> in-server `ConnectorStore`/`ConnectorEngine` shape (evolved; sketch: originally SQLite; any
> implementation is Postgres-native per ADR-0006:37-38); a use-case-engine re-plan
> would instead build on ADR-1005's engine-principal / REST+MCP-twin model. 9.8 (Inventory
> Consolidation & Normalization, #263) closed NOT_PLANNED with no delivery (see its own
> **Closed — not planned** status) and is unaffected by this deferral either way.

The 9.x sketches predate ADR-0006; any future implementation is Postgres-native — ADR-0006:37-38 is the normative rule ("No new server-side SQLite store is added without an explicit exception ADR"), never SQLite. ADR-0012 is the author contract for whoever builds it, not the substrate rule itself.

### Issue 9.1: Connector Framework (Core)
**Capability:** new | **Scope:** Server | **Status:** Deferred (see banner above)

Pluggable connector architecture for bidirectional data sync with external systems:
- `ConnectorStore` (sketch: originally SQLite; any implementation is Postgres-native per ADR-0006:37-38): connector type, name, config (encrypted credentials), schedule, status
- `ConnectorEngine`: background sync with pluggable connector implementations
- Connector interface:
  ```cpp
  class Connector {
  public:
      virtual std::string type() const = 0;
      virtual SyncResult sync(const ConnectorConfig& config, InventoryRepository& repo) = 0;
      virtual ConnectionTestResult test(const ConnectorConfig& config) = 0;
  };
  ```
- Sync lifecycle: NotStarted → Pending → InProgress → Completed/Failed/Cancelled
- REST: `GET/POST/PUT/DELETE /api/v1/connectors`, `POST .../sync`, `POST .../test`
- Dashboard: Connectors page in Settings with add/edit/delete/test/sync actions

**Files:** New `server/core/src/connector_store.cpp`, `server/core/src/connector_engine.cpp`, `server/core/src/settings_routes.cpp`

### Issue 9.2: Inventory Repository Model
**Capability:** new | **Scope:** Server | **Status:** Deferred (see banner above)
**Depends on:** 9.1

Named repositories for partitioned inventory data:
- `RepositoryStore` (sketch: originally SQLite; any implementation is Postgres-native per ADR-0006:37-38): named repositories per type (inventory, compliance, entitlement)
- Default repository created on first boot (cannot be deleted)
- Connectors bound to repositories; multiple connectors per repository
- Consolidation, deduplication, normalization pipeline
- Repository types: Inventory, Compliance, Entitlement (extensible)
- REST: `GET/POST/PUT/DELETE /api/v1/repositories`

**Files:** New `server/core/src/repository_store.cpp`, `server/core/src/rest_api_v1.cpp`

### Issue 9.3: SCCM / ConfigMgr Connector
**Capability:** new | **Scope:** Server | **Status:** Deferred (see banner above)
**Depends on:** 9.1

SQL query against ConfigMgr database:
- Hardware inventory (Win32_ComputerSystem, Win32_OperatingSystem, etc.)
- Software inventory (installed applications, MSI packages)
- User/device associations
- Patch compliance data
- Configuration: database server, instance, auth (Windows/SQL login)

**Files:** New `server/core/src/connectors/sccm_connector.cpp`

### Issue 9.4: Intune Connector
**Capability:** new | **Scope:** Server | **Status:** Deferred (see banner above)
**Depends on:** 9.1

Microsoft Graph API integration (`/deviceManagement/managedDevices`):
- Device inventory (hardware, OS, compliance state)
- Installed applications
- Configuration profiles and compliance policies
- OAuth2 client credentials flow (reuse DirectorySync Graph client)

**Files:** New `server/core/src/connectors/intune_connector.cpp`

### Issue 9.5: ServiceNow Connector
**Capability:** new | **Scope:** Server | **Status:** Deferred (see banner above)
**Depends on:** 9.1

ServiceNow REST API (Table API) integration:
- CMDB CI records (cmdb_ci_computer, cmdb_ci_server)
- Incidents and change requests (optional)
- User/group import
- OAuth2 or basic auth

**Files:** New `server/core/src/connectors/servicenow_connector.cpp`

### Issue 9.6: WSUS Connector
**Capability:** new | **Scope:** Server | **Status:** Deferred (see banner above)
**Depends on:** 9.1

SQL query against WSUS database:
- Update approval status
- Per-device patch compliance
- Update metadata (KB, severity, classification)
- Configuration: database server, instance, auth

**Files:** New `server/core/src/connectors/wsus_connector.cpp`

### Issue 9.7: CSV / File Upload Connector
**Capability:** new | **Scope:** Server | **Status:** Deferred (see banner above)
**Depends on:** 9.1

Import inventory data from structured files:
- Parse TSV/CSV with configurable column mapping
- Upload via REST API or dashboard file picker
- Validation and error reporting per row
- Scheduling support for automated file ingestion from watched directories

**Files:** New `server/core/src/connectors/file_upload_connector.cpp`

### Issue 9.8: Inventory Consolidation & Normalization
**Capability:** new | **Scope:** Server | **Status:** **Closed — not planned** (#263 closed NOT_PLANNED, 2026-07-14) — **not delivered as this issue's cleanup pipeline**: consolidation/dedup absent — `server/core/src/software_catalog_rollup.{hpp,cpp}` is a rollup view, not a cross-source consolidation pipeline, and contains no deduplication or consolidation-reporting logic. Normalization primitives *do* exist, just not in service of this issue's scope: `server/core/src/product_normalize.{hpp,cpp}` is deterministic title/vendor normalization for the ADR-0024 SLE catalog matcher (Decision 6), not the multi-source cross-connector consolidation this issue sketched (verified 2026-09-10)
**Depends on:** 9.2 (moot — 9.1–9.7 are deferred, see Phase 9 banner, and 9.8 was closed not-planned rather than shipped)

Multi-source inventory cleanup pipeline (never built):
- Deduplication by device identity (hostname + MAC + serial)
- Software normalization: vendor/title/version canonicalization
- Hardware normalization: processor model mapping, VM detection
- Consolidation reports: matched vs. unmatched, normalization coverage percentage
- Runs after each connector sync or on-demand via REST

**Files:** New `server/core/src/inventory_consolidation.cpp`, `server/core/src/repository_store.cpp` — neither exists; `software_catalog_rollup.{hpp,cpp}` is a separate, narrower rollup that does not substitute for this issue's scope.

---

## Phase 10: Software Catalog & License Compliance

*Normalized software identification for license management and compliance reporting.*

> **Superseded by ADR-0024 (2026-07-06, status: proposed).** This phase's design is superseded by
> `docs/adr/0024-software-licensing-entitlements.md` ("Software Licensing &
> Entitlements", capability §27 — renamed by the same ADR). **Note the two use-case-engine (UCE)
> modules in play across this roadmap are distinct** — ADR-1005 Phase 7 re-homes the **vulnerability
> UCE** (NVD/CVE matching); ADR-0024 re-scopes part of its own design to a separate **SAM UCE**
> (Software Asset Management) module. Neither is the other. Against that ADR: only **licence
> discovery** (a new agent `license_scan` plugin on the ADR-0016 daily-sync framework) and the
> **product registry** (the SQLite `CatalogStore` sketch becomes the born-on-Postgres
> `ProductRegistryStore`) are built in-server — a placement claim, not a delivery claim: the store
> compiles and is unit-tested but has no production writer/reader yet (10.1 is **Partial**, see below).
> The **entitlement plane** (5 sources: manual, CSV, M365
> connector, agent-observed FlexLM/KMS — Decisions D12/D14) and **usage metering & reclamation**
> (Decision D15) are re-scoped to the **SAM UCE module** and are **not built in-server** — 10.2/10.3
> below did not ship as designed and their GitHub issues closed NOT_PLANNED, not delivered.
> **Software tags are a separate case, not UCE-scoped**: ADR-0024 Decision 15 explicitly states
> "product tags on `ProductRegistryStore` stay core" (`docs/adr/0024-software-licensing-entitlements.md:530`)
> — the design keeps them **in-server**, but the implementation (a `product_tags` migration) hasn't
> landed yet (`product_registry_store.cpp` marks it "PR4 — do NOT add it here"); 10.4/#267 closed
> NOT_PLANNED because the issue's own REST-surface sketch wasn't built, not because tags were ruled
> out of the server. REST is unified under `/api/v1/sle/*` for what did ship. The issue breakdown is
> retained for traceability (10.1–10.4 ↔ #264–#267).

### Issue 10.1: Software Catalog Store
**Capability:** new | **Scope:** Server | **Status:** **Partial** (#264 closed NOT_PLANNED, 2026-07-14) — store + normalizer compiled and tested (`ProductRegistryStore`, `product_normalize.{hpp,cpp}`, per ADR-0024's product-registry-stays-core decision, see banner above), but no production writer/reader at the pin: `product_registry_store_` is constructed at boot, wired into `/readyz`, and metrics-registered, with zero call sites invoking its data methods (insert/find/match) anywhere outside the store itself and its unit tests — the SLE matcher that would populate/query it is PR4 (`product_registry_store.cpp:43`)
**Depends on:** 9.8 (moot — see 9.8's own Closed-not-planned status)

Canonical software registry:
- `CatalogStore` (SQLite): normalized software entries (vendor, title, version, edition, platform)
- Catalog import from CSV/JSON
- Manual curation UI: merge duplicates, set canonical names, mark as ignored
- Automatic matching: raw inventory entries linked to catalog entries by fuzzy title/vendor
- REST: `GET/POST/PUT /api/v1/catalog/software`, `POST /api/v1/catalog/software/match`

**Files (as shipped):** `server/core/src/product_registry_store.{hpp,cpp}` — not the sketched `catalog_store.cpp`/`entitlement_store.cpp`, which don't exist.

### Issue 10.2: Software Usage Tracking
**Capability:** new | **Scope:** Agent + Server | **Status:** **Closed — not planned** (#265 closed NOT_PLANNED, 2026-07-14) — **not delivered**: ADR-0024 places usage metering/reclamation in the **SAM UCE module** (Decision D15, "usage joined with entitlement data for a reclamation purpose" — distinct from ADR-1005 Phase 7's *vulnerability* UCE); no `software_usage` agent plugin and no agent usage-sync source exist in-server (verified 2026-09-07)
**Depends on:** 10.1

Agent-side application usage metering (never built in-server):
- New `software_usage` agent plugin
- Track application launches, cumulative run time, last-used timestamp
- Categorize: Used (30d), Rarely Used (90d), Unused (>90d), Unreported
- Report via ReportInventory RPC
- Server-side aggregation: per-title usage across fleet
- Dashboard: usage summary with reclamation candidates

**Files:** New `agents/plugins/software_usage/`, `server/core/src/catalog_store.cpp` — neither exists.

### Issue 10.3: License Entitlements & Compliance
**Capability:** new | **Scope:** Server | **Status:** **Closed — not planned** (#266 closed NOT_PLANNED, 2026-07-14) — **not delivered**: ADR-0024 places the entitlement plane (`SoftwareEntitlementStore`, Decision D12) in the **SAM UCE module** (distinct from ADR-1005 Phase 7's *vulnerability* UCE); no `entitlement_store.cpp` or entitlement REST surface exists in-server (verified 2026-09-07)
**Depends on:** 10.1

License compliance calculation (never built in-server):
- Entitlement records: product, purchased_seats, license_type (per-device/per-user/site/enterprise)
- Compliance calculation: installed_count vs. entitled_count
- Over/under-licensed reporting per product
- REST: `GET/POST/PUT/DELETE /api/v1/entitlements`
- Dashboard: license compliance summary with drill-down

**Files:** New `server/core/src/entitlement_store.cpp`, `server/core/src/rest_api_v1.cpp` — the store doesn't exist.

### Issue 10.4: Software Tags
**Capability:** new | **Scope:** Server | **Status:** **Closed — not planned** (#267 closed NOT_PLANNED, 2026-07-14) — **not delivered, but NOT UCE-scoped either**: ADR-0024 Decision 15 explicitly keeps "product tags on `ProductRegistryStore`" **core** (`docs/adr/0024-software-licensing-entitlements.md:530`); the gap is purely that the implementation hasn't landed — `product_registry_store.cpp:43` marks the `product_tags` migration "PR4 — do NOT add it here" (verified 2026-09-07)
**Depends on:** 10.1

Server-side tags on software catalog entries (design decided core-scoped, implementation not yet built):
- Tag software titles for categorization (e.g., "approved", "prohibited", "eval")
- Used for Management Group rules ("devices with software tagged X")
- REST: `GET/POST/DELETE /api/v1/catalog/software/{id}/tags`
- Dashboard: tag management in catalog view

**Files:** `server/core/src/catalog_store.cpp`, `server/core/src/management_group_store.cpp` — the catalog-tags surface doesn't exist yet; `product_registry_store.cpp` is where it lands (per its own "PR4" comment) once built; `management_group_store.cpp` exists but has no software-tag linkage today.

---

## Phase 11: Consumer Model & Platform Extensibility

*Formalize third-party integration and provide client libraries for automation.*

### Issue 11.1: Consumer Application Registration
**Capability:** 24.4 | **Scope:** Server | **Status:** **Closed — not planned** (#268 closed NOT_PLANNED, 2026-07-14) — **not delivered as scoped**: no `ConsumerStore`/`server/core/src/consumer_store.cpp` exists (verified 2026-09-07); the auth/token *substance* described below was separately absorbed into ADR-1005 engine principals (`EnginePrincipalStore`, delivered) but that is a different architecture, not this issue's design shipping

> **ADR-1005 note:** the consumer auth/token model described below (scoped API
> tokens, rate limits, consumer identity) is absorbed into ADR-1005's **engine
> principals** (see `docs/adr/1005-headless-platform-use-case-engines.md`
> Decision 5 and the execution plan's Phase 4) — delivered under that name, not
> as `ConsumerStore`. The push/consumer-deploy fanout mechanics (pushing
> instruction definitions and policies *to* consumers) are **not** addressed by
> ADR-1005 and were never built.

Formal model for external systems consuming Yuzu data (never built as designed):
- `ConsumerStore` (SQLite): name, URL, max_concurrent_instructions, offload_target, enabled
- Consumers get scoped API tokens with rate limits
- Custom data field for consumer-specific metadata
- Consumer deploy: push instruction definitions and policies to specific consumers
- REST: `GET/POST/PUT/DELETE /api/v1/consumers`
- Dashboard: Consumers page in Settings

**Files:** New `server/core/src/consumer_store.cpp`, `server/core/src/settings_routes.cpp` — the store doesn't exist.

### Issue 11.2: Event Source Management
**Capability:** 21.5 | **Scope:** Server | **Status:** Open

Configure which system events generate notifications and webhook deliveries:
- Event source categories: agent_lifecycle, execution, compliance, security, system
- Per-category enable/disable with severity threshold
- Granular event type selection within each category
- REST: `GET/PUT /api/v1/event-sources`
- Dashboard: Event Sources section in Settings

**Files:** New `server/core/src/event_source_config.cpp`, `server/core/src/webhook_store.cpp`, `server/core/src/notification_store.cpp`

### Issue 11.3: PowerShell Module
**Capability:** 24.7 (partial) | **Scope:** External | **Status:** Open

`Yuzu.Management` PowerShell module wrapping REST API v1:
- Cmdlets: `Connect-YuzuServer`, `Get-YuzuAgent`, `Send-YuzuInstruction`, `Get-YuzuCompliance`, `Get-YuzuAuditLog`, `New-YuzuSchedule`, etc.
- Authentication: API token via `Connect-YuzuServer -Server <url> -Token <token>`
- Tab completion for instruction names, agent IDs, scope attributes
- Published to PowerShell Gallery

**Files:** New `sdk/powershell/`

### Issue 11.4: Python SDK
**Capability:** 24.7 (partial) | **Scope:** External | **Status:** Open

`yuzu-sdk` Python package wrapping REST API v1:
- Async support via httpx
- Typed models (dataclasses or Pydantic)
- Convenience methods: `client.agents.list()`, `client.instructions.execute()`, etc.
- Published to PyPI

**Files:** New `sdk/python/`

---

## Phase 12: Remaining Agent Capabilities

*Close all 19 "Not Started" items from the capability map to reach 100% coverage.*

### Issue 12.1: Mapped Drive History
**Capability:** 3.8 | **Scope:** Agent Plugin | **Status:** **Done** (closed 2026-07-04) — shipped as a **TAR capture source**, not `users` plugin actions

**As shipped:** `tar_mapdrive_collector.cpp` — a TAR (Timeline Activity Record) capture source, queryable via `tar.sql`, not the two ad-hoc `users`-plugin actions sketched below.

Original sketch — new actions in `users` plugin: `mapped_drives`, `mapped_drive_history`.
- Windows: WMI `Win32_MappedLogicalDisk` + Event Log 4624/4634 for historical connections
- Returns: drive_letter, remote_path, username, timestamp, direction (inbound/outbound)

**Files (as shipped):** `agents/plugins/tar/src/tar_mapdrive_collector.cpp`

### Issue 12.2: Printer Inventory
**Capability:** 3.9 | **Scope:** Agent Plugin | **Status:** Open

New action in `hardware` plugin: `printers`.
- Windows: `EnumPrinters` API. Linux: CUPS `lpstat`. macOS: `lpstat`
- Returns: name, driver, port, status, shared, default, network/local

**Files:** `agents/plugins/hardware/src/hardware_plugin.cpp`

### Issue 12.3: Port Scanning
**Capability:** 4.11 | **Scope:** Agent Plugin | **Status:** Open

New action in `discovery` plugin: `scan_ports`.
- Parameters: target_ips (comma-separated), ports (range notation: "22,80,443,8000-8100")
- Non-blocking connect with configurable timeout (default 2s)
- Returns: ip, port, status (open/closed/filtered), service_guess

**Files:** `agents/plugins/discovery/src/discovery_plugin.cpp`

### Issue 12.4: NetBIOS Lookup
**Capability:** 4.9 | **Scope:** Agent Plugin | **Status:** Open

New action in `discovery` plugin: `netbios_lookup`.
- Parameters: ip_addresses (comma-separated)
- Send NetBIOS Name Query (UDP 137) and parse response
- Returns: ip, netbios_name, domain, mac_address

**Files:** `agents/plugins/discovery/src/discovery_plugin.cpp`

### Issue 12.5: Open Windows Enumeration
**Capability:** 5.5 | **Scope:** Agent Plugin | **Status:** Open

New action in `interaction` plugin: `list_windows` (Windows-only).
- `EnumWindows` + `GetWindowText` + `GetWindowThreadProcessId`
- Returns: hwnd, title, process_name, pid, visible, minimized

**Files:** `agents/plugins/interaction/src/interaction_plugin.cpp`

### Issue 12.6: Directory Hash (Recursive)
**Capability:** 10.11 | **Scope:** Agent Plugin | **Status:** Open

New action in `filesystem` plugin: `hash_directory`.
- Recursive SHA-256 of all file contents, sorted by relative path for deterministic output
- Returns: directory_hash, file_count, total_bytes, elapsed_ms

**Files:** `agents/plugins/filesystem/src/filesystem_plugin.cpp`

### Issue 12.7: Survey Dialog
**Capability:** 14.4 | **Scope:** Agent Plugin | **Status:** Open

Extend `interaction` plugin: `survey` action.
- Multi-question form: text input, single-choice, multi-choice, rating scale
- Windows: WinForms-style dialog. Linux: zenity --forms. macOS: osascript
- Unique survey name prevents repeat display. Response validity period.
- Returns: structured JSON response with question_id → answer mapping

**Files:** `agents/plugins/interaction/src/interaction_plugin.cpp`

### Issue 12.8: Do-Not-Disturb Mode
**Capability:** 14.5 | **Scope:** Agent Plugin | **Status:** **Done** (closed 2026-08-01) — shipped as designed (`interaction_plugin.cpp` `set_dnd` action)

Extend `interaction` plugin: `set_dnd` / `get_dnd_status` actions.
- Suppress all notifications/dialogs for configurable duration
- Persisted in agent KV storage (survives restart)
- Returns: active (bool), expires_at (timestamp)

**Files:** `agents/plugins/interaction/src/interaction_plugin.cpp`

### Issue 12.9: Active Response Tracking
**Capability:** 14.6 | **Scope:** Agent Plugin | **Status:** Open

Extend `interaction` plugin: `list_pending` action.
- Returns all outstanding surveys/questions awaiting user input
- Includes: interaction_id, type, prompt, issued_at, timeout_at

**Files:** `agents/plugins/interaction/src/interaction_plugin.cpp`

### Issue 12.10: Patch Inventory Event Generation
**Capability:** 8.9 | **Scope:** Agent Plugin | **Status:** Open

Extend `windows_updates` plugin: `generate_inventory_events` action.
- Emit structured events for each installed/missing patch
- Feed into AnalyticsEventStore for SIEM/compliance integration
- Event format: patch_kb, status (installed/missing), severity, agent_id, timestamp

**Files:** `agents/plugins/windows_updates/src/windows_updates_plugin.cpp`

### Issue 12.11: Application Whitelisting
**Capability:** 9.10 | **Scope:** Agent Plugin | **Status:** Open

New `app_control` plugin:
- Windows: AppLocker policy query/modification via WMI or PowerShell
- Linux: fapolicyd rules (if available)
- Actions: `get_policy`, `add_rule`, `remove_rule`, `get_blocked_events`

**Files:** New `agents/plugins/app_control/`

### Issue 12.12: Inventory Replication (Delta Sync)
**Capability:** 15.5 | **Scope:** Agent + Server | **Status:** **Done** (#283 closed NOT_PLANNED, 2026-07-14, delivered differently: ADR-0016's hash-skip conditional sync — the agent sends only a content hash, not the full payload, on steady state — `docs/adr/0016-agent-daily-sync-framework.md`, `agents/core/src/sync_scheduler.hpp`)

Agent-side inventory cache with delta sync (original sketch — see the ADR-0016 evidence above for the as-shipped mechanism):
- Agent-side: inventory cache in SQLite KV store, track hash of last-sent inventory per plugin
- Server-side: track per-agent sync state (last_sync_at, inventory_hash)
- Only send changed inventory since last sync, reducing bandwidth for large fleets

**Files (as shipped):** `agents/core/src/sync_scheduler.{hpp,cpp}`, `server/core/src/device_inventory_store.cpp`, `server/core/src/software_inventory_store.cpp` — not the `agent.cpp`/`inventory_store.cpp` sketch below.

### Issue 12.13: Binary Resource Distribution
**Capability:** 22.7 | **Scope:** Server | **Status:** Open

Server-side resource registry for versioned binary blobs:
- Resource model: name, version, platform, hash, size, upload_at
- Agents pull resources by name + version with SHA-256 hash verification
- Used by instructions that need supporting files (scripts, configs, tools)
- REST: `GET/POST/DELETE /api/v1/resources`, `GET /api/v1/resources/{name}/{version}/download`

**Files:** New `server/core/src/resource_store.cpp`, `server/core/src/rest_api_v1.cpp`

---

## Phase 13: Security Hardening & Operational Polish

*Close remaining security gaps and improve operational UX.*

### Issue 13.1: 2FA for Instruction Approval (TOTP)
**Capability:** new | **Scope:** Server | **Status:** Open (stale — TOTP + MFA step-up landed generally, not wired to instruction approval specifically)

TOTP (`totp.{hpp,cpp}`) and a general step-up MFA framework (`mfa_step_up.{hpp,cpp}`) shipped as part of the auth-and-authz workstream — `require_mfa_step_up` currently gates role-elevation endpoints (`auth_routes.cpp`), not the approval endpoint. This issue's specific ask — a `totp_code` requirement on instruction approval — is not wired; the primitive it would reuse already exists. Original sketch:

TOTP (RFC 6238) second factor on instruction approval:
- Per-user TOTP secret stored encrypted in auth store
- QR code enrollment via Settings UI
- Approval endpoint requires `totp_code` parameter when 2FA is enabled for the user
- Fallback: email-based one-time code (requires SMTP configuration)
- Configurable: per-user opt-in or system-wide enforcement

**Files:** `server/core/src/approval_manager.cpp`, `server/core/src/auth.cpp`, `server/core/src/settings_routes.cpp`

### Issue 13.2: Composable Instruction Chains
**Capability:** new | **Scope:** Server | **Status:** **Done** (closed 2026-07-14) — shipped in `workflow_engine.cpp` (`foreach_source` step field, step-interpolation)
**Depends on:** 7.14 (Workflow Primitives)

Server-side multi-step instruction composition extending the WorkflowEngine:
- Variables from previous steps available via `${step_name.field}` interpolation
- CEL conditions for conditional step execution
- Result row iteration via `foreach` for fan-out patterns
- Provides composable instruction chaining without requiring an agent-side scripting language

**Files:** `server/core/src/workflow_engine.cpp`, `server/core/src/execution_tracker.cpp`

### Issue 13.3: Process / Sync Logging UI
**Capability:** new | **Scope:** Server | **Status:** Open

Dashboard page at `/monitoring` with operational log views:
- Tabs: Connector Sync Log, Scheduled Executions, Infrastructure Log
- Reuse existing AuditStore with category filtering
- HTMX fragments with 30s auto-refresh
- Status indicators, filtering by action type / status / time range

**Files:** New `server/core/src/monitoring_ui.cpp`, `server/core/src/dashboard_routes.cpp`

### Issue 13.4: Dashboard Branding
**Capability:** new | **Scope:** Server | **Status:** Open

White-label customization for enterprise deployments:
- `BrandingConfig`: logo_url, product_name, primary_color, accent_color
- Stored in RuntimeConfigStore (safe keys)
- Settings UI: branding section with live preview
- CSS variables for theme customization, applied globally

**Files:** `server/core/src/css_bundle.cpp`, `server/core/src/settings_routes.cpp`, `server/core/src/runtime_config_store.cpp`

### Issue 13.5: MCP Phase 2 (Write Tools)
**Capabilities:** 24.8 (extension) | **Scope:** Server | **Status:** Done (#289)
**Depends on:** 7.20 (MCP Phase 1)

> **Shipped (R2, 2026-07):** all five write tools (`set_tag`, `delete_tag`,
> `approve_request`, `reject_request`, `quarantine_device`) are dispatched;
> `execute_instruction` was already done. Approval-gated ops use the
> ticket-then-recall flow (mint `kApprovalRequired` + `approval_id`/`status_url` →
> admin approves → recall consumes once). "SSE streaming for execution progress"
> is satisfied by the shipped `GET /api/v1/events` (sprint W5.1) — not rebuilt.
> See `docs/mcp-server.md` Phase 2 and `docs/user-manual/mcp.md`.

6 write/execute tools for the MCP server:
- `set_tag`, `delete_tag` — device tag management
- `execute_instruction` — dispatch instruction to agents (operator/supervised tiers)
- `approve_request`, `reject_request` — approval workflow actions (supervised tier)
- `quarantine_device` — network isolation (supervised tier)
- Approval workflow integration for destructive operations
- SSE streaming for execution progress

**Files:** `server/core/src/mcp_server.cpp`, `server/core/src/mcp_policy.hpp`

---

## Phase 14: Scale & Enterprise Readiness

*Features needed for very large deployments (>100K devices) and enterprise-grade resilience.*

### Issue 14.1: P2P Content Distribution
**Capability:** 13.5 | **Scope:** Agent | **Status:** Open

Agent mesh for peer content sharing within subnets:
- Leader election via mDNS/broadcast within subnet
- Content announce/request protocol over UDP
- Cache management: LRU eviction, configurable max size
- Falls back to server download when no peers have content
- Bandwidth throttling to avoid network saturation

**Files:** New `agents/core/src/p2p_mesh.cpp`, `agents/plugins/content_dist/src/content_dist_plugin.cpp`

### Issue 14.2: Multi-Gateway Topology
**Capability:** 22.5 (extension) | **Scope:** Gateway + Server | **Status:** Open
**Depends on:** 7.1, 7.1.1

Server supports multiple concurrent gateway registrations:
- Gateway affinity: agents assigned to nearest gateway via latency probing
- Gateway failover: agents reconnect to alternate gateway on primary failure
- Topology view shows all gateways with agent counts and health status

**Files:** `server/core/src/agent_registry.cpp`, `server/core/src/gateway_service_impl.cpp`, `gateway/apps/yuzu_gw/src/yuzu_gw_cluster.erl`

### Issue 14.3: Database Sharding (Response Partitioning)
**Capability:** new | **Scope:** Server | **Status:** **Partial** (#292 closed NOT_PLANNED, 2026-07-14) — not implemented as designed below (no sharding/partitioning code exists); **obsoleted by the Postgres substrate migration**, which addresses the underlying scaling need differently

The original design (monthly SQLite files with a query router spanning partitions, to reduce single-file WAL contention) is moot: `response_store.cpp` migrated off SQLite onto PostgreSQL (ADR-0039, Wave 1.2, PR #2691), which handles high-throughput partitioning/scaling at the substrate layer instead. Issue closed as superseded rather than implemented.

**Files:** `server/core/src/response_store.cpp`

### Issue 14.4: vCenter Connector
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 9.1

VMware vSphere API integration:
- Sync: VMs, ESXi hosts, datastores, clusters, resource pools
- VM-to-agent correlation via hostname or UUID
- Virtual summary reporting (physical hosts, guest count, density)

**Files:** New `server/core/src/connectors/vcenter_connector.cpp`

### Issue 14.5: Additional Connectors (BigFix, O365, Oracle)
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 9.1

Extend the connector framework with additional integrations:
- **BigFix**: REST API integration for inventory and patch compliance sync
- **Office 365**: Microsoft Graph API for license and usage data
- **Oracle LMS**: Database query for Oracle deployment facts and licensing

**Files:** New `server/core/src/connectors/bigfix_connector.cpp`, `server/core/src/connectors/o365_connector.cpp`, `server/core/src/connectors/oracle_connector.cpp`

### Issue 14.6: High Availability
**Capability:** new | **Scope:** Server | **Status:** Open (stale — **superseded by ADR-2002**, see body note)

> **Superseded by ADR-2002 (High Availability Architecture).** The active-passive-over-shared-SQLite/NFS design sketched below is explicitly disavowed by the ADR itself as "pre-Postgres and now wrong." The current HA design targets **active-active** on the Postgres substrate (both self-managed on-prem and future SaaS), decomposed into workstreams WS-0…WS-14 tracked in `docs/ha-delivery-matrix.md`. **As of dev @ `d295db964` (2026-09-07, pinned 12:01 UTC+1 / 11:01 UTC)** — verified by `git merge-base --is-ancestor <merge-sha> d295db964`, not `gh pr view` state (a PR's current state can postdate the pin): WS-0, WS-1, WS-7, and **WS-2a (both 2a-1 and 2a-2, #3924 — cross-replica SSE delivery, merged 2026-09-03, IS an ancestor)** are done; **WS-3 slice 3.1** (fenced `LeaderElector` primitive, #4011, merged 2026-09-06, IS an ancestor) is done but inert — no loop wired yet, no runtime behaviour change. **WS-10 is NOT done at the pin** — #4092 (background-job replica-safety classification) merged 2026-09-07 **12:58 UTC**, roughly an hour *after* the pin, and is confirmed NOT an ancestor of `d295db964`; at the pin, WS-10 remains **PR #4092 open**, matching `docs/ha-delivery-matrix.md`'s own state at the pin (which also still records WS-2a-2 outstanding and WS-3 as merely "planned" — that file's own re-stamp commits landed on `dev` after this pin too; the roadmap follows verified PR-ancestry facts over the matrix file's stamp date, and the matrix will catch up on its own schedule). The remaining workstreams (WS-2b, WS-3 3.2/3.3/3.4, WS-4, WS-5, WS-6, WS-8-readyz, WS-9, WS-10, WS-11…WS-14) are not started at the pin. See "Delivered outside the roadmap" above and the Dependency Graph below.

> **Since the pin (re-verified against dev @ `c7f3a5bed`, 2026-09-13):** WS-10 is **done** (#4092, merged 2026-09-07). WS-3 3.2 (#4134, the elector now gates `FencedLeaderOnly` passes — not `DisabledUntilFixed` ones, see the gate note below), 3.3 (#4169, durable command outbox — a fifth `FencedLeaderOnly` pass, `command_outbox.deliver`, sharing 3.2's `schedule_tick_thread_` loop with `schedule_runner.tick` rather than adding one; five passes across four background loops in total) and 3.4 (#4194, remediation CAS) are **done**, and WS-4 slice 4.1 (fenced `GatewayRouteStore`, #4245) is done but **inert** — nothing reads it for dispatch until 4.2. `docs/ha-delivery-matrix.md` is the live record. Live active-active HA is still not delivered.

<details><summary>Original active-passive design (superseded — kept for history)</summary>

Active-passive failover for server resilience:
- Shared SQLite over network filesystem (NFS/SMB) or replicated storage
- Heartbeat between primary and standby servers
- Automatic failover on primary health check failure
- Gateway re-registration on failover event
</details>

**Files:** New `server/core/src/ha_manager.cpp`, `server/core/src/server.cpp` (superseded — see `docs/adr/2002-high-availability-architecture.md` and `docs/ha-delivery-matrix.md` for the current file map)

---

## Phase 15: TAR Dashboard & Scope Walking

*The differentiating operator experience. Composable scope from previous query results, surfaced in the dashboard and the YAML DSL, anchored on a dedicated TAR page that puts retention awareness, ad-hoc SQL, and process-tree forensics under one roof. The reference end-to-end walkthrough is the Chrome IR scenario in `docs/scope-walking-design.md` §10.*

> **Status correction (2026-07-01).** The bulk of this phase shipped on 2026-05-31 but the item statuses below were never updated from "Open". Corrected here: **15.A–15.E and 15.H are shipped**; **15.G is largely shipped** (GC-sweep thread, quota/pin caps, re-eval, GC/alive gauges); **15.F (this item) is the only substantially-open piece** and is in progress on `feat/tar-15f-chrome-ir-e2e`.

### Issue 15.A: TAR Dashboard Page Shell + Retention-Paused Source List
**Capability:** new | **Scope:** Server (dashboard + REST) + TAR plugin (status extension) | **Status:** **Shipped** — `/tar` page shell + retention-paused source list (scan / one-click re-enable) live 2026-05-31; typed-confirmation purge completed the frame 2026-07-01 (`tar_page_ui.cpp`, `dashboard_routes.cpp`). Persistence remains a tracked follow-up.

New `/tar` page off the main dashboard nav. First frame is the retention-paused source list — directly enabled by the issue #539 retention guard. Per-source `<source>_paused_at` timestamp added to `tar.status`, server aggregates per-device responses, dashboard renders a sortable filterable table with one-click re-enable and a typed-confirmation purge. Independent re-enable per source (the #539 invariant).

**As shipped:** the destructive **Purge data** action (design §3.4) is a new agent action `tar.purge_source` (drops all warehouse tiers for a source, leaving it paused), a `POST /fragments/tar/retention-paused/purge` handler gated on `Infrastructure:Delete`, and a typed-hostname confirmation (a native `prompt()` — CSP-safe, no custom modal). The paused-guard is **agent-side** (`tar.purge_source` refuses if the source is enabled) — authoritative, and it closes the scan→purge TOCTOU; the server frame is an ephemeral live scan (no persisted paused-state, so no server-side `SOURCE_NOT_PAUSED` check). Audit verb `tar.source.purge`; metric `yuzu_tar_source_purge_total{result}`. `rows_deleted` is computed agent-side (returned in the response record), not in the fire-and-forget dispatch audit row.

**Files:** `server/core/src/dashboard_routes.cpp`, `server/core/src/dashboard_ui.cpp`, `agents/plugins/tar/src/tar_plugin.cpp`, new `tests/unit/server/test_tar_dashboard_*`. Design: `docs/tar-dashboard.md` §3.

### Issue 15.B: Result-Set Store + REST API
**Capability:** new (foundational) | **Scope:** Server | **Status:** **Shipped** 2026-05-31 (`68427bba`)

`result_set_store.cpp` with new `result_sets.db`. Schema per `docs/scope-walking-design.md` §3 — immutable lineage edges, TTL with pin override, source payload JSON for live re-eval. REST: `POST /api/v1/result-sets`, `from-inventory-query`, `from-tar-query`, `from-instruction-result`, `GET .../{id}`, `.../{id}/members`, `.../{id}/lineage`, `pin` / `unpin` / `re-eval`, `DELETE`. Audit hooks per §9.

**As shipped:** `result_set_store.{cpp,hpp}` is **SQLite** (born before the 2026-06-09 Postgres flip; queued for migration in `docs/postgres-migration-ladder.md`). The REST surface landed **in `rest_api_v1.cpp`**, not a separate `result_set_routes.cpp`. Covered by `test_result_set_store.cpp`, `test_result_set_matcher.cpp`, `test_rest_result_sets_async.cpp`.

**Files:** `server/core/src/result_set_store.{cpp,hpp}`, `server/core/src/result_set_matcher.{cpp,hpp}`, `server/core/src/rest_api_v1.cpp`. Design: `docs/scope-walking-design.md` §3, §6, §9.

### Issue 15.C: Scope Engine `from_result_set:` + Dashboard Chip + Sidebar + Breadcrumb
**Capability:** 1.6 (extension) | **Scope:** Server | **Status:** **Shipped** 2026-05-31 (`68427bba`; owner-scope + IDOR/DoS hardening `4f10a69b`). `from_result_set:` short-circuit in `scope_engine`/`agent_registry`, sidebar/breadcrumb/chip UI in `result_sets_ui`. Covered by `test_scope_walking_authz.cpp`, `test_scope_engine.cpp`.
**Depends on:** 15.B

Scope Engine grammar gains `from_result_set:<id-or-alias>` as a third short-circuit kind alongside `__all__` and `group:<name>`. Composes with attribute predicates via `AND`/`OR`/`NOT`. Dashboard sidebar lists active result sets (last_used_at then created_at DESC); chain breadcrumb above every query frame mirrors `parent_id` walks; scope chip surfaces in TAR / inventory / instruction frames.

**Files:** `server/core/src/scope_engine.{cpp,hpp}`, `server/core/src/dashboard_routes.cpp`, `server/core/src/dashboard_ui.cpp`. Design: `docs/scope-walking-design.md` §4, §8.

### Issue 15.D: TAR SQL Frame — Relocate, Scope-Walking-Aware, Save-as-Result-Set
**Capability:** new | **Scope:** Server | **Status:** **Shipped** 2026-05-31 (`e7b47ca3`, PR-D). Async producers (`from-tar-query` / `from-instruction-result`), re-eval, the response matcher (`result_set_matcher.cpp`), and the scope-walking-aware TAR SQL frame. Covered by `test_rest_result_sets_async.cpp`, `test_result_set_matcher.cpp`.
**Depends on:** 15.A, 15.B, 15.C

Relocate the existing `/fragments/tar-sql` route onto the TAR dashboard page. Wire scope-chip resolution to `from_result_set:` (15.C). Add "Save as result set" affordance on the results pane — server creates a new result set with `source_kind=tar_query`, members = union of agents that returned ≥1 row by default. Default name is `tar-<5-char-sql-hash>`.

**Files:** `server/core/src/dashboard_routes.cpp`, `server/core/src/agent_service_impl.cpp` (TAR result envelope to carry the producing agent IDs explicitly). Design: `docs/tar-dashboard.md` §4.

### Issue 15.E: YAML DSL `fromResultSet:` + `definition_store` Validation + Spec Amendment
**Capability:** new | **Scope:** Server (DSL) | **Status:** **Shipped** 2026-05-31 (`e6361a3a`, relocation `9a6b15f7`, governance fixes `89c7b46c`, PR-E). `selector:` / `fromResultSet:` parses and lowers (`scope_yaml.{cpp,hpp}`); rules 1–2 enforced at create; rule 3 at dispatch via the `instruction.scope_resolution_failed` audit row. **Policy `fromResultSet:` deferred to PR-E2** (TTL vs. continuous policy eval; needs `Policy.owner_principal` + pinned-set rule). Covered by `test_scope_yaml.cpp`, `test_yaml_scan.cpp`.
**Depends on:** 15.B, 15.C

`scope:` block in `InstructionDefinition`, `InstructionSet`, `Policy` gains `fromResultSet:` as a mutually-exclusive (or composable-with-`selector:`) form. Validation: `fromResultSet + assignment.managementGroups` rejected at YAML load; `fromResultSet` requires `assignment.mode = static`. Resolution at instruction *invocation* time, not load time. Spec section in `docs/yaml-dsl-spec.md`.

**Files:** `server/core/src/definition_store.cpp`, `server/core/src/policy_store.cpp`, `docs/yaml-dsl-spec.md`. Design: `docs/scope-walking-design.md` §7.

### Issue 15.F: Reference Walkthrough — Chrome IR End-to-End Integration Test
**Capability:** new (regression net) | **Scope:** Tests | **Status:** **Done** (#552 closed NOT_PLANNED, 2026-07-14, delivered differently — see "As built" below)
**Depends on:** 15.B, 15.C, 15.D, 15.E

Drives the §10 walkthrough (inventory-ground → TAR-query narrow → instruction-result narrow → pin) and asserts: the lineage chain is complete (`GET /{id}/lineage` reconstructs root→leaf); the audit trail is complete (one `result_set.create` per step + the pin); pinning prevents mid-incident GC (a pinned set survives `gc_sweep()` and cannot be deleted until unpinned); and the chain tears down cleanly.

**As built:** an **in-process Catch2 test** at `tests/unit/server/test_chrome_ir_chain.cpp` (server suite), driving the real `/api/v1/result-sets` handlers via `TestRouteSink` with a real `ResultSetStore` + a recording fake command-dispatch — CI-runnable, no live stack. There is **no** `tests/integration/` dir or `scripts/uat/synthetic-fleet.sh`; those design-doc paths were aspirational. A full multi-process UAT-stack variant remains a future option.

**Files:** `tests/unit/server/test_chrome_ir_chain.cpp`, `tests/meson.build`. Design: `docs/scope-walking-design.md` §10.

### Issue 15.G: Operational Hardening — Live Re-Eval, GC Sweep, Prometheus + Audit Polish
**Capability:** new | **Scope:** Server | **Status:** **Largely shipped** (2026-05-31 ladder) — remaining items tracked below.
**Depends on:** 15.B

Live re-eval (`POST /api/v1/result-sets/{id}/re-eval`); background GC sweep every 5 min; per-operator 10K result-set quota + 50 pin cap with `429 RESULT_SET_QUOTA` / `409 PIN_LIMIT`; Prometheus metrics (`yuzu_result_sets_total`, `yuzu_result_sets_alive`, `yuzu_result_set_resolve_seconds` histogram, GC counter, quota-rejection counter); audit polish on every state transition.

**Shipped:** re-eval endpoint; background GC-sweep thread wired in `server.cpp` (`ResultSetStore::gc_sweep()`); Prometheus `yuzu_result_sets_total`, `yuzu_result_sets_alive`, `yuzu_result_set_gc_total`, and `yuzu_result_set_quota_rejected`; quota (`kMaxPerOwner=10000` → `429`) and pin cap (`kMaxPinsPerOwner=50` → `409`) enforced in the store. **Still open:** the `yuzu_result_set_resolve_seconds` histogram and a final audit-polish pass. Recommend narrowing 15.G to just these remainders.

**Files:** `server/core/src/result_set_store.cpp`, `server/core/src/result_set_routes.cpp`, `server/core/src/server.cpp`. Design: `docs/scope-walking-design.md` §3.3, §9.

### Issue 15.H: TAR Process Tree Viewer
**Capability:** new (forensic) | **Scope:** Server (engine + routes + UI) | **Status:** **Shipped** 2026-06-18 ([#1551](https://github.com/Tr3kkR/Yuzu/pull/1551)) — as-built: local-TAR-data-only, deviates from the original seed-snapshot design below.

**As-built (shipped).** Reconstructs a per-host process tree entirely from that host's **local TAR warehouse** (`$Process_Live` + `$TCP_Live`, via the read-only `tar.sql` action) — **no seed**, no `/proc`/`CreateToolhelp32Snapshot`/`proc_listallpids` walk, no server-side mirror, no live probe. The tree is built server-side in C++ from the flat event stream (recursive CTEs are blocked on the agent). Collapsible two-column tree + sticky detail panel, inline remote-`IP:port` per row, same-name sibling grouping, client-side All/Running/Exited + anomalies-only + text filters, and a name-based suspicious parent→child spawn heuristic. Timescale is a preset (On boot · On agent install · Last minute · 10m · hour · day) or a custom From/To (UTC) window — **not** `?as_of`. Honest in-page limitations: no seed → aged-out-of-the-live-cap processes may not appear; **Windows is names-only** (ETW Kernel-Process — no path/cmdline; populated on Linux/macOS); "On boot"/"On agent install" are TAR-derived proxies. `Infrastructure:Read` to view; reconstruction dispatches a live `tar.sql` so it also requires `Execution:Execute` + device scope; the detail cache is keyed by a CSPRNG token bound to the originating operator. Audit verbs `tar.process_tree.read` (dispatch + success + `csprng_unavailable` failure) and `tar.process_tree.detail`.

**Deliberate deviation.** The original design (next paragraph) reconstructed from a seed snapshot taken at agent install / first start, which depended on the agent service-install-hardening track. The as-built drops that dependency by reading only retained TAR events; the honesty banner states the resulting completeness limit. REST/MCP parity (`GET /api/v1/tar/process-tree/{id}`) is a tracked follow-up ([#1562](https://github.com/Tr3kkR/Yuzu/issues/1562)).

<details><summary>Original seed-based design (superseded — kept for history)</summary>

`tar.process_tree` agent action walks `/proc` (Linux), `CreateToolhelp32Snapshot` + `Process32FirstW`/`NextW` (Windows), `proc_listallpids` + `proc_pidinfo(PROC_PIDTBSDINFO|PIDPATHINFO)` (macOS). Stores tagged `action='seed'` rows in `process_live` per PID. Server reconstructs the tree by replaying seed + subsequent `started` / `stopped` events from `process_live`. Renderer: collapsible nested `<details>` / `<summary>` for v1, no graph library. Time-slicing via `?as_of=<ts>`. Honest "tree as observed since <seed_ts>" badge; orphan reparenting shown as it would be in a live `ps`. Cmdline redaction reuses `tar_plugin.cpp` `load_redaction_patterns`. Data quality depends on the agent running from boot/install and being tamper-resistant — that hardening pillar is the parallel Guardian PR ladder.
</details>

**Files (as-built):** `server/core/src/tar_process_tree.{hpp,cpp}` (pure engine), `server/core/src/tar_tree_routes.{hpp,cpp}` (routes), `server/core/src/tar_page_ui.cpp` (frame wiring), `tests/unit/server/test_tar_process_tree.cpp` + `test_tar_tree_routes.cpp`. Design: `docs/tar-dashboard.md` §5.

---

## Phase 16: System Guardian — Real-Time Agent-Side Guaranteed State

*The headline parity feature against the leading commercial endpoint-management platforms' real-time enforcement engines. PolicyStore (Phase 5) covers server-side compliance evaluation on a scheduled poll (`PolicyEvaluator`, default 3600s interval, `policy_evaluator.hpp:107`) with operator-gated remediation — never automatic (see Phase 5 note); this phase covers the **kernel-event-driven, microsecond-latency, pre-login-active, fully-offline-capable** agent-side enforcement that makes guaranteed state operationally true rather than approximately true. Without Phase 16, "policy engine equivalent" overclaims — an hour-scale window (let alone one gated on a further explicit operator action) is unacceptable for security-sensitive settings (firewall ports, registry-backed posture, EDR running). Design: `docs/yuzu-guardian-design-v1.1.md` (architecture), `docs/yuzu-guardian-windows-implementation-plan.md` (Windows-first 17-PR delivery ladder).*

### Issue 16.A: System Guardian — Windows-first delivery
**Capability:** 31.1, 31.2, 31.3, 31.6, 31.7, 31.8, 31.9, 31.10 | **Scope:** Agent (Windows) + Server | **Status:** In progress — far beyond "PRs 1-2 shipped": 59 merged guardian PRs land the Spark detection engine (rungs 1–7+, ADR-0021), `GuardianEngine`, `BaselineStore`, and the `/guaranteed-state` operator UI (rule list, event timeline, approval workflow). **Spark is wired (`agent.cpp:1255`) but inert by default** — `prefer_spark_=false`, legacy `IGuard` remains the sole live enforcement path; Spark makes no enforcement decisions today. Issue #555 itself remains open — the PR ladder has no GitHub sub-checklist tracking it item-by-item.
**GitHub:** [#555](https://github.com/Tr3kkR/Yuzu/issues/555)

End-to-end Windows enforcement using kernel-backed user-mode APIs:
- **Event guards (~0 ms latency)** — RegNotifyChangeKeyValue (Registry Guard), NotifyServiceStatusChange (SCM Guard), FwpmFilterSubscribeChanges0 (WFP Guard), OpenTrace + ProcessTrace with session pooling (ETW Guard).
- **Condition guards (configurable interval)** — Process Guard (hybrid ETW + ToolHelp32), Software Guard (Registry Uninstall + WMI), Compliance Guard (Event Log + WMI), WMI Guard (arbitrary query).
- **Pre-login activation** — agent service `SERVICE_AUTO_START` + `FailureActions`; `GuardianEngine::start_local()` runs before Register RPC.
- **Offline capable** — policy cached in `kv_store.db` `__guardian__` namespace; enforcement continues when server is unreachable.
- **Operator surface** — `/guaranteed-state` dashboard page (rule list + event timeline + kernel-wiring health), HTMX rule editor, approval workflow via existing `ApprovalManager`, MCP read-only tools, HMAC rule signing with `CredWrite`/`CredRead` key storage, quarantine integration via WFP block-all filter at weight 65535.

PRs 1-2 (proto, server store, agent scaffolding, REST + dispatch hook) shipped. PRs 3-15 in `docs/yuzu-guardian-windows-implementation-plan.md`. 14 prerequisite issues already filed (#452-#457, #477-#479, #483, #485, #487, #488, #491).

**Files (anticipated):** `proto/yuzu/guardian/v1/guaranteed_state.proto` (shipped), `server/core/src/guaranteed_state_store.{hpp,cpp}` (shipped), `agents/core/src/guardian_engine.{hpp,cpp}` (shipped), `agents/core/src/guard_*.{hpp,cpp}` (PR 3+), `agents/core/src/state_evaluator.{hpp,cpp}`, `agents/core/src/remediation_engine.{hpp,cpp}`, `agents/core/src/guard_audit.{hpp,cpp}`, `server/core/src/dashboard_guaranteed_state.{hpp,cpp}` (PR 4).

### Issue 16.B: System Guardian — Linux delivery
**Capability:** 31.4, 31.6 (Linux) | **Scope:** Agent (Linux) | **Status:** Open
**Depends on:** 16.A soak | **GitHub:** [#556](https://github.com/Tr3kkR/Yuzu/issues/556)

Linux equivalents of Windows event guards: Inotify Guard (`inotify_add_watch`), Netlink Guard (`NETLINK_KOBJECT_UEVENT`), D-Bus Guard (`org.freedesktop.systemd1` signals), Audit Guard (`auditd` consumer for syscall-level assertions), Sysctl Guard (`/proc/sys` watch + write remediation). Linux-specific assertion types (`config-file-key-equals`, `kernel-param-equals`, `selinux-mode-enforcing`). Remediation methods: systemd D-Bus service control, atomic file rewrite, `sysctl -w`, package install/remove via dpkg/rpm.

**Why gated on Windows soak:** the architectural primitives (state evaluator, remediation engine, resilience strategies, audit journal) are platform-agnostic — only the guard implementations are platform-specific. Building Linux before Windows soak risks discovering a primitive-level bug that the Windows track would have caught first.

**As found (2026-09-07):** `agents/core/src/guard_systemd.cpp` already exists — Linux delivery began before the stated 16.A soak gate was satisfied. Recorded honestly rather than silently reconciled.

**Sequencing decision pending (PO):** 16.B began before the 16.A soak gate — accept and drop the gate, or pause 16.B. Until decided, 16.B proceeds ungated: nothing enforces the gate, so it is advisory.

**Files:** new `agents/core/src/guard_inotify.{cpp,hpp}`, `guard_netlink.{cpp,hpp}`, `guard_dbus.{cpp,hpp}`, `guard_audit_linux.{cpp,hpp}`, `guard_sysctl.{cpp,hpp}` (all Linux-only); `agents/core/src/guard_systemd.cpp` (already started); `agents/core/meson.build` Linux block adding `libdbus-1`, `libaudit` deps.

### Issue 16.C: System Guardian — macOS delivery
**Capability:** 31.5, 31.6 (macOS) | **Scope:** Agent (macOS) | **Status:** Open
**Depends on:** 16.A + 16.B soak, Endpoint Security entitlement | **GitHub:** [#557](https://github.com/Tr3kkR/Yuzu/issues/557)

macOS equivalents using Apple's Endpoint Security (ES) framework — *requires the `com.apple.developer.endpoint-security.client` entitlement*, which Apple grants per-bundle-ID after Developer Program enrolment and notarisation review (typically 4-8 weeks). Without ES the macOS surface is reduced to FSEvents Guard (`fseventsd` consumer) + Launchd Guard (plist polling + `launchctl` poll). macOS-specific assertion types (`plist-key-equals`, `launchd-service-running`, `xprotect-version-current`, `gatekeeper-enabled`). Remediation: plist serialisation + atomic write, `launchctl bootstrap`/`bootout`, `spctl --master-enable`.

**Entitlement gating** is tracked out-of-band in the customer-facing release-readiness doc; the issue ships in two phases — degraded surface first (FSEvents + Launchd, no ES), full surface when entitlement lands.

**Files:** new `agents/core/src/guard_endpoint_security.{cpp,hpp}` (macOS, ES-entitlement-gated), `guard_fsevents.{cpp,hpp}` (macOS), `guard_launchd.{cpp,hpp}` (macOS).

---

## Phase 17: Agentic Surface Hardening (Proposed)

*Implements the four agentic-first invariants from `docs/agentic-first-principle.md` (A1 dashboard parity, A2 discovery, A3 observability, A4 error envelope). Source: `docs/capability-agentic-audit-2026-05.md` §7 P1. Every operation a human can perform via the dashboard must be performable by an authenticated agentic worker through a documented, discoverable, machine-readable surface.*

### Issue 17.1: Introspection Endpoints (`/api/v1/discover/*`)
**Capability:** new | **Scope:** Server (REST + MCP) | **Status:** Done (tracker #1794)

`/api/v1/discover/routes` (sourced from `openapi_spec()`), `/discover/plugins` (sourced from registered `PluginInfo`), `/discover/scope-kinds`, `/discover/permissions` (RBAC catalog), `/discover/instructions`. Each mirrored as an MCP tool (`discover_routes`, etc.). Supplants out-of-band YAML / Markdown for agent worker capability discovery. Implements **A2**. See `docs/agentic-first-principle.md` §A2 for the shipped shape of each endpoint.

**Files:** `server/core/src/discover_routes.{cpp,hpp}` (module named `discover_routes.*`/`DiscoverRoutes`, singular — the filename originally planned here, `discovery_routes.{cpp,hpp}`, was already taken by an unrelated pre-existing module: directory sync / patch management / deployment / network-discovery routes at `/api/directory/*`, `/api/patches/*`, `/api/deployments/*`, `/api/discovery/*`), `server/core/src/openapi_spec_access.hpp` (exposes `openapi_spec()` for external linkage), `mcp_server.cpp` tool registration, `docs/agentic-first-principle.md` §A2.

### Issue 17.2: Dashboard JSON Content Negotiation
**Capability:** new | **Scope:** Server (dashboard) | **Status:** Proposed — confirmed not started (no `Accept: application/json` content-negotiation code found in `dashboard_routes.cpp` as of 2026-09-07)

Honor `Accept: application/json` on `/fragments/*` page routes; return structured rows/columns/links/actions parallel to the HTML fragment. First-cut targets the admin surfaces (user mgmt, enrollment-token administration, settings panels). Existing fragments are not retroactively required to comply — backfill is opportunistic, A1 applies to new routes from the date of adoption. Implements **A1**.

**Files:** `server/core/src/dashboard_routes.cpp`, `dashboard_ui.cpp`, fragment route handlers.

### Issue 17.3: Agent-Facing JSON SSE Channel
**Capability:** new | **Scope:** Server (REST) | **Status:** **Done** — shipped as `GET /api/v1/events` (sprint W5.1), built on `execution_event_bus.{hpp,cpp}`

`/api/v1/events?since=&filter=execution_id:X|agent_id:Y` emits structured JSON envelopes (not HTML fragments) on the same `event_bus_` and `ExecutionEventBus` that drive the existing HTMX `/events`. Patterns after `/api/v1/guaranteed-state/events` (`rest_api_v1.cpp:2498`). Decide separately whether to deprecate the HTML-fragment `/events` channel or keep both. Implements **A3**.

**Files:** new `server/core/src/agent_sse_routes.{cpp,hpp}`, reuse `server.cpp:2450-2478` infrastructure.

### Issue 17.4: Service-Account Principal Type
**Capability:** new | **Scope:** Server (auth) | **Status:** Proposed — **absorbed into the ADR-1005 auth follow-up**

> **ADR-1005 note:** this issue's substance (a machine principal type with
> least-privilege scoping and rotation) is absorbed into the engine-principal
> class and the auth-architecture follow-up design (execution plan Phase 2b /
> Phase 4 — see `docs/adr-1005-execution-plan.md`). Do not implement it
> standalone; it would build a second, parallel machine-principal model.

`auth_db` migration adds `principal_type IN ('user','service_account')`. Service accounts can be scoped to mgmt-group / plugin / operation subsets. Token rotation pair-overlap workflow exposed via REST. Required for least-privilege agentic worker identity in multi-tenant deployments. Touches A2 (discovery surface for service-account scopes).

**Files:** `server/core/src/auth_db.{cpp,hpp}`, `auth_routes.{cpp,hpp}`, `auth_manager.cpp`, new migration.

### Issue 17.5: Structured Error Envelope Rev
**Capability:** new | **Scope:** Server (REST + MCP) | **Status:** **Done** — shipped as the A4 error envelope, `server/core/src/rest_a4_envelope.hpp`

Every failure response includes `correlation_id`, `retry_after_ms` (nullable), `remediation` (URL or hint, nullable). On `kPermissionDenied` name the missing `securable_type:operation`. On `kApprovalRequired` return `approval_id` + `status_url`. Implements **A4**.

**Files:** `mcp_jsonrpc.hpp`, every REST handler emitting an error response, OpenAPI spec.

---

## Phase 18: Compliance & Lifecycle (Proposed)

*Capabilities currently absent from the roadmap; commonly required for enterprise compliance and lifecycle management. Source: `docs/capability-agentic-audit-2026-05.md` §7 P3. See also: the ADR-1005 execution plan (`docs/adr-1005-execution-plan.md`) — several items in this phase are boundary-affected by the headless-platform decision and must be re-evaluated against ADR-1005 Decision 2 before implementation.*

### Issue 18.1: Vulnerability Lifecycle
**Capability:** new | **Scope:** UCE module (was: Server) | **Status:** Proposed — `vuln_finding_store.{hpp,cpp}` exists as an interim in-server placement grandfathered by ADR-1005 §92 (surface #2, placement-only); it has no production `reconcile_agent` caller at this commit (tests only), so the lifecycle itself is unimplemented. Re-homes under ADR-1005 Phase 7 (#4099).

CVE → CVSS → owner → SLA → remediation tracking. Supplements the existing `vuln_scan` collection plugin with a findings store carrying a triage lifecycle (new / triaged / accepted-risk / remediated / reopened) **in the vulnerability-management use-case engine (UCE) module, not a server-side store** — the execution plan's M3 milestone builds exactly this findings store + lifecycle as part of the module that re-homes the server-side NVD capability (ADR-1005 grandfathered surface #2; see `docs/adr-1005-execution-plan.md`, Module scoping). Integrates with Phase 9 connectors for SCCM/Intune CVE feeds.

### Issue 18.2: Compliance Reporting Templates
**Capability:** new | **Scope:** Server | **Status:** Proposed — **boundary-affected by ADR-1005**

CIS Benchmarks, NIST 800-171, SOC 2 evidence-pack templates that compose PolicyStore rules + audit log entries into auditor-ready PDF/CSV bundles.

> **ADR-1005 note:** compliance-framework mappings are interpretation baked
> into code — re-evaluate against Decision 2's boundary test before
> implementation; likely a future UCE module.

### Issue 18.3: Certificate Lifecycle
**Capability:** new | **Scope:** Server + agent | **Status:** Proposed

Auto-renewal, expiry alerts, revocation workflow. Extends existing certificate inventory (capability §3.8) with lifecycle.

### Issue 18.4: Secrets-Vault Integration
**Capability:** new | **Scope:** Server | **Status:** Proposed

HashiCorp Vault, Azure Key Vault, AWS Secrets Manager connectors for connector credentials and enrollment tokens. Replaces SQLite-encrypted-at-rest for shops with a vault.

### Issue 18.5: SBOM Ingest
**Capability:** new | **Scope:** Server | **Status:** Proposed — **boundary-affected by ADR-1005**

CycloneDX / SPDX import. Component-level vulnerability linkage so a CVE on `openssl-1.1.1k` lights up every fleet host carrying that component.

> **ADR-1005 note:** joins fleet data with external domain data — re-evaluate
> against Decision 2's boundary test before implementation; the execution
> plan's deferred ledger earmarks it as a separate future UCE module.

### Issue 18.6: Hardware Attestation
**Capability:** new | **Scope:** Agent + server | **Status:** Proposed

TPM, Secure Boot, UEFI verification. Reports posture state into compliance reporting (18.2).

### Issue 18.7: Agent-Side Component Inventory Collection
**Capability:** new | **Scope:** Agent + server | **Status:** Proposed

Bundled/vendored-dependency and embedded-runtime detection (Electron/Chromium, Go/Rust buildinfo,
filesystem-resident lockfiles) that today's package-manager-based `installed_software` source can't
see — the generation-side companion to Issue 18.5 (SBOM Ingest). See `docs/adr/0028-*`.

### Out of scope (documented exclusions)

- **MDM (mobile)** — partner integration only; Yuzu's agent surface is workstation + server, not iOS / Android.
- **OS deployment / imaging / PXE** — partner integration only; out of scope for endpoint management.
- **EDR-class telemetry at the agent** — integrate via Phase 9 connectors to existing EDR (CrowdStrike, SentinelOne, MS Defender for Endpoint); do not re-implement at the agent.

---

## Phase 19: Threat Graph & Defender Posture (Proposed)

*Extends the `feat/viz-engine` 11-PR ladder with the Threat Graph product vision: a single canvas where SOC analysts, defenders, and system architects see the full per-host IPC graph + cross-host network graph + per-process security posture, so they can decide where to insert hardened controls (WAF, IPS, API gateways, VxLAN separation, firewalls) and which surfaces (network parsers etc.) to harden against which vulnerability classes. Anti-Mythos framing — Yuzu is the defender's mirror of LLM-driven offensive enumeration. Source: `docs/plans/threat-graph-roadmap.md`.*

### Issue 19.1: Fleet IPC Enumeration — Unix Sockets, Named Pipes, Shared Memory
**Capability:** 28.8 | **Scope:** Agent (plugins) + server (wire) | **Status:** Proposed

Four new agent plugins so the topology snapshot covers all same-host IPC channels, not just TCP loopback:

- `unix_sockets` — Linux + macOS path-bound + abstract-namespace AF_UNIX enumeration, mapped to owning processes via `lsof -U` / `/proc/net/unix` cross-reference. Windows AF_UNIX (Win10 1803+) is a follow-up.
- `named_pipes` — Windows `\\.\pipe\*` via `NtQueryDirectoryObject` + ALPC port inventory; Linux FIFO inventory (`find / -type p`) as a smaller follow-up.
- `shared_memory` — SysV `ipcs -m` + POSIX `/dev/shm` listing + `/dev/mqueue` (Linux + macOS); Windows shared sections (`NtQuerySection`) follow.
- `signed_binaries` — Authenticode (Windows `WinVerifyTrust`), codesign (macOS `SecCodeCheckValidity`), IMA/EVM (Linux `getxattr security.ima`). Required for the posture-glyph "signed/unsigned" check.

Wire model extension: new `EdgeKind` enum on `ConnectionEdge` (`TcpLoopback`, `UnixSocket`, `NamedPipe`, `SharedMemory`, `DBus`, `ALPC`, `EbpfMap`), `socket_path` for filesystem-backed channels, `world_accessible` boolean flagging endpoints any process can join (Unix socket `0666`, abstract socket, world-rw `/dev/shm`).

### Issue 19.2: Process Binary Hashing + VirusTotal Server-Side Integration
**Capability:** 28.8 | **Scope:** Agent (`processes` extension) + server (new) | **Status:** Proposed

Extend the existing `processes` plugin to emit SHA-256 of each process's binary path. Server-side **`virustotal_cache.db`** store + a rate-limited (free tier: 4 req/min) VirusTotal API client; results cached with 7-day TTL keyed by hash. Threat-mode posture envelope carries `binary.hash_sha256` + `binary.virustotal_score`. API key lives in Settings → External Integrations, server-side, never on agent.

### Issue 19.3: Per-Process Posture Envelope
**Capability:** 28.8 | **Scope:** Server | **Status:** Proposed

`ProcessNode.posture` envelope synthesises vulnerability scan (existing) + AV status (existing `antivirus`) + signed-binary verification (19.1) + firewall exposure (existing `firewall`) + disk encryption (existing `bitlocker`) + VirusTotal score (19.2) into one composite indicator. Server-side aggregation; agent plugins each contribute their slice. Composite glyph rendered as Sprite-child of each process Sphere (hidden when hardened, `!`/`⚠`/`?` otherwise).

### Issue 19.4: Threat-Mode Toggle on `/viz/fleet`
**Capability:** 28.8 | **Scope:** Server (renderer) | **Status:** Proposed

`?mode=threat` URL param + `T`-key shortcut + UI control, persisted in `localStorage.yuzuVizMode`. Shared camera / scene-graph / dispatch contracts with the existing Fleet mode. Threat mode adds: posture-glyph rendering, IPC-edge rendering (19.1), `world_accessible` red glow, recommendation ghost overlays (19.5). Mode-state in URL hash takes precedence over `localStorage` (shareable links).

### Issue 19.5: Recommendation Store + Agentic Recommender Integration
**Capability:** 28.9 | **Scope:** Server | **Status:** Proposed

New **`recommendations.db`** store. Schema: `id`, `customer_id`, `generated_at`, `generated_by`, `kind` (insert_waf / vxlan_separate / firewall_rule / harden_parser / kill_world_socket / other), `target_node_ids` (JSON), `target_edge_keys` (JSON), `rationale`, `status` (open / accepted / dismissed / applied), `operator_note`, `yaml_source`. REST CRUD at `/api/v1/recommendations/...` + matching MCP tools. An external agentic AI worker posts recommendations using a service-scoped API token; recommendations are ghost-overlaid in Threat mode. Accept / dismiss / apply via the existing approval workflow (`workflows.db`). "Apply" calls existing plugin actions via REST `/api/v1/dispatch`.

### Issue 19.6: Action Surface — Click-Through to Existing Plugins
**Capability:** 28.8 | **Scope:** Server (renderer + REST) | **Status:** Proposed

Side-panel on node / edge click in Threat mode. Buttons call existing plugin actions through REST `/api/v1/dispatch`; no new `viz.actions` API surface. Initial action menu: check binary hash against VirusTotal, re-scan vulnerabilities, view firewall rules, add firewall rule, run sockwho, run ad-hoc bash, check AV / disk encryption status, kill process, quarantine binary. Each button respects the operator's RBAC (the button greys out if `Plugin:Execute` is missing).

### Issue 19.7: Cross-Platform Parity Sweep — AV, Disk Encryption, Firewall
**Capability:** 9.x extension | **Scope:** Agent (existing plugins) | **Status:** Proposed

Audit `antivirus`, `bitlocker`, `firewall` plugins for macOS + Linux coverage. Plugin skeletons already have all three platform branches; verify each branch actually reports posture (macOS XProtect / third-party AV verified 2026-07-16 — real definition-bundle probe + endpoint-security extension enumeration, `security.antivirus.xprotect_status`; gaps remain: Linux ClamAV/SentinelOne/Crowdstrike, macOS FileVault, Linux LUKS, macOS `pfctl`, Linux `nftables`). Optionally rename `bitlocker` plugin to `disk_encryption` (decision deferred — breaking API token scope strings is the cost; recommendation in roadmap doc is to keep the name and add `disk_encryption` as an action alias).

### Issue 19.8: Container-Runtime Awareness — `Containerised` Edge Scope
**Capability:** 28.8 | **Scope:** Server (topology classification) + agent (optional new plugin) | **Status:** Proposed

Detect Docker / Kubernetes / Podman in the host environment (could extend `os_info` or new `container_runtime` plugin). Server-side fleet topology classifier adds a `Containerised` `EdgeScope` for inter-container traffic on private RFC1918 / Docker default ranges. New `MountedSocket` edge kind for bind-mounted host sockets (the `/var/run/docker.sock` container-escape pattern) — special render to flag boundary crossings.

### Issue 19.9: D-Bus + eBPF + Windows ALPC IPC (Defence-in-Depth)
**Capability:** 28.8 | **Scope:** Agent (new plugins) | **Status:** Proposed

Lower-priority IPC channels that round out the Threat Graph:
- `dbus` plugin — `busctl list` system + session bus enumeration on Linux.
- `ebpf_inventory` plugin — `bpftool map list` + `prog list` (root-only).
- `alpc_ports` plugin — Windows ALPC port enumeration via `NtAlpcQueryInformation`.

Land after the foundational IPC plugins (19.1) ship and the rendering model proves stable.

---

## Phase 20: Reflex — Agent-Local Automated Response (Proposed)

*Sparks (ADR-0021) already give the agent a converged, use-case-agnostic detection layer; Reflex is
the third and last sovereign Spark consumer alongside Guardian (real-time compliance enforcement)
and DEX (curated telemetry) — a YAML-authored, agent-local binding from a Spark to a small chain of
plugin-action Reactions, executed on the device the instant the Spark fires, with or without server
connectivity. Design contract: `docs/reflex-design.md`; ADR: `docs/adr/0021-spark-reflex-architecture.md`
(Decisions 2, 4, 5, 6, 7, 8, 9, 10 and the 2026-09-17 Reflex amendment). No GitHub tracking issue filed yet
for this phase as a whole — file one before implementation slices land, per
`docs/agents/issue-standard.md`.*

### Issue 20.1: Reflex Set Authoring, Storage, and Safety/Consent Gates
**Capability:** new | **Scope:** Server | **Status:** Proposed

YAML-authoritative Reflex Set CRUD (`ReflexSetStore`, born-on-PostgreSQL per ADR-0012), the
`dangerous_reactions_in_spec()` safety chokepoint (extends the existing `dangerous_*_in_spec`
doctrine, fed by `CommandCapabilityRegistry::classify`), and the device-classification consent gate
(the free-form `device_class` asset tag, `server` | `workstation`, unclassified = workstation =
fail-closed — see `docs/asset-tagging-guide.md` "Recipe: Reflex consent gate").

### Issue 20.2: Digest-Bound Two-Person Approval and Deploy/Push
**Capability:** new | **Scope:** Server | **Status:** Proposed

Deploy gated on a dedicated `Reflex:Execute` RBAC permission (never the Guardian-only `Push` cross-seed),
approved by a different principal than both the last editor and the deployer, bound to a canonical
digest over compiled content + assignment scope, recomputed and compared at every compile. Compiled
Reflex Sets fan out over the reserved `__reflex__` plugin name's `push_sets` action.

### Issue 20.3: Agent-Local Spark→Reaction Execution
**Capability:** new | **Scope:** Agent | **Status:** Proposed

`ReflexEngine`, a queued SparkEngine consumer (never inline) that runs each fired Reflex's Reaction
chain locally via the agent's `LocalDispatcher` — authorized once, at deploy time, by 20.1/20.2, never
re-authorized per fire (agent-local dispatch is architecturally distinct from the server's
operator-dispatch `classify_and_authorize_dispatch`/`DispatchCaller` chokepoint — see
`docs/reflex-design.md` "Safety chokepoint"). Per-set serialized concurrency, bounded detached reaction
workers counted into the agent's hard-exit grace sum, crash-safe (an in-flight chain marker is aborted,
never resumed).

### Issue 20.4: Reflex Outcomes, Observability, and Dashboard
**Capability:** new | **Scope:** Server | **Status:** Proposed

Outcomes ride the existing `__guard__`/`event` channel (`GuaranteedStateEvent.family == "reflex"`),
land in a Reflex-only `reflex_outcomes` table (ADR-0021 Decision 6 partial supersession), and are
never surfaced on the executions-history ladder (agent-local automation, not operator dispatch).
Fleet Prometheus families, heartbeat tags, audit verbs, SOC 2 evidence rows, REST + MCP CRUD, and an
HTMX `/reflex` dashboard round-tripping the YAML — never the model.

---

## Open Decisions

| # | Issue | Topic | Status |
|---|-------|-------|--------|
| D1 | [#251](https://github.com/Tr3kkR/Yuzu/issues/251) | License key generation and signing strategy | **Open** — Options: signed keys (offline), license server (online), or hybrid. Blocks production use of capability 22.3. |
| D2 | [#252](https://github.com/Tr3kkR/Yuzu/issues/252) | CEL is a custom subset, not full Common Expression Language | **Closed — not planned** (NOT_PLANNED, 2026-07-14) — decided to keep the custom CEL subset; full `cel-cpp` adoption will not be pursued |

## Future Phase (T3 Items — Not Scheduled)

These capabilities are tracked but not yet scheduled. Each will become a GitHub issue when prioritized.

| # | Capability | Notes |
|---|-----------|-------|
| 4.10 | ARP scanning | Active subnet discovery (partially covered by `discovery` plugin `scan_subnet`) |
| 12.3 | WMI namespace enumeration | WMI discovery (partially covered by `wmi` plugin configurable namespace) |
| 22.3 | License management | Seat count, expiry, feature entitlements (LicenseStore exists; key generation strategy TBD — see D1) |
| 23.2 | Remote key-value access | Cross-agent storage access |

---

## Dependency Graph

```
Phase 0–7 (substantially done; 2 items Partial, not Done — see below)
  └── Foundation → Data Infrastructure → Instruction System (2.9 Partial) → Security/RBAC
      → Agent Infrastructure → Policy Engine → Windows Depth → Scale & Integration (7.8 Partial)

Phase 8 (Visualization & Response Experience)
  ├── 8.1 Visualization Engine ── builds on ResponseStore + InstructionStore
  ├── 8.2 Response Templates ──── requires 8.1
  └── 8.3 Response Offloading ─── independent (reuses WebhookStore pattern)

Phase 9 (Connector Framework) — DEFERRED, see Phase 9 body banner
  ├── 9.1 Connector Core ──────── independent (new subsystem) — not started
  ├── 9.2 Repository Model ────── requires 9.1 — not started
  ├── 9.3–9.7 Connectors ─────── require 9.1 (all independent of each other) — not started
  └── 9.8 Consolidation ──────── requires 9.2 — CLOSED — NOT PLANNED (#263, no delivery): consolidation/
                                    dedup absent; normalization primitives exist (`product_normalize.cpp`,
                                    ADR-0024's SLE catalog matcher) but no cross-source consolidation;
                                    `software_catalog_rollup.{hpp,cpp}` is a separate, narrower rollup
                                    that does not substitute for this scope

Phase 10 (Software Catalog) — NOT DONE under ADR-0024 "Software Licensing & Entitlements" (SLE);
  0/4 Done — 10.1 is Partial (placed in-server but unwired to any producer/consumer), 10.2–10.4
  closed NOT_PLANNED with no delivery
  ├── 10.1 Catalog Store ──────── PARTIAL — `ProductRegistryStore` (born-on-Postgres) + `product_normalize`
  │                                 compile and are unit-tested; zero production writer/reader at the pin
  │                                 — the SLE matcher that would use both is PR4
  ├── 10.2 Usage Tracking ─────── CLOSED — NOT PLANNED (#265, no delivery): ADR-0024 re-scopes this to
  │                                 the SAM UCE module (Decision D15); no in-server usage-sync source
  ├── 10.3 Entitlements ───────── CLOSED — NOT PLANNED (#266, no delivery): ADR-0024 re-scopes this to
  │                                 the SAM UCE module (Decision D12); no in-server entitlement store
  └── 10.4 Software Tags ──────── CLOSED — NOT PLANNED (#267, no delivery) — NOT UCE-scoped: ADR-0024
                                    Decision 15 keeps product tags core, just not yet built (tracked as
                                    a future `product_tags` migration)

Phase 11 (Consumer Model)
  ├── 11.1 Consumer Registration ── independent
  ├── 11.2 Event Sources ──────── independent (extends WebhookStore + NotificationStore)
  ├── 11.3 PowerShell Module ──── independent (wraps REST API)
  └── 11.4 Python SDK ─────────── independent (wraps REST API)

Phase 12 (Agent Capabilities)
  ├── 12.1–12.6 ─── independent plugin extensions (no cross-deps)
  ├── 12.7–12.9 ─── extend interaction plugin (sequential within plugin)
  ├── 12.10 Patch Events ──────── extends windows_updates plugin
  ├── 12.11 App Whitelisting ──── new plugin (independent)
  ├── 12.12 Inventory Delta ───── extends agent core + InventoryStore
  └── 12.13 Resource Distribution ── independent (new server store)

Phase 13 (Security & Polish)
  ├── 13.1 2FA / TOTP ─────────── extends ApprovalManager
  ├── 13.2 Instruction Chains ─── requires 7.14 Workflows
  ├── 13.3 Monitoring UI ──────── independent (new dashboard page)
  ├── 13.4 Branding ───────────── independent (CSS + RuntimeConfigStore)
  └── 13.5 MCP Phase 2 ───────── requires 7.20 MCP Phase 1

Phase 14 (Scale & Enterprise)
  ├── 14.1 P2P Content ────────── independent (agent-side mesh) — not started
  ├── 14.2 Multi-Gateway ──────── requires 7.1 + 7.1.1 — not started
  ├── 14.3 DB Sharding ────────── PARTIAL (closed NOT_PLANNED) — not implemented as designed; the
  │                                 underlying scaling need is obsoleted by the Postgres substrate
  │                                 migration below, addressed differently
  ├── 14.4 vCenter Connector ──── requires 9.1 (deferred — see Phase 9) — not started
  ├── 14.5 Additional Connectors ── requires 9.1 (deferred — see Phase 9) — not started
  └── 14.6 High Availability ──── SUPERSEDED by ADR-2002 below — see the HA block

Cross-phase dependencies:
  Phase 10 ──→ Phase 9.8 (catalog needs normalized inventory, as originally scoped) — the dependency
    itself is now moot: Phase 10 is 0/4 Done (10.1 Partial in-server, see Phase 10 note) and 9.8 is
    Closed — not planned (no consolidation code shipped); 10.1 did not in fact need 9.8
  Phase 13.2 ──→ Phase 7.14 (chains extend workflows) — done
  Phase 14.4–14.5 ──→ Phase 9.1 (connectors need framework) — both blocked on the deferred Phase 9

Postgres substrate migration (ADR-0006, ADR-0007, ADR-0008, ADR-0010, ADR-0012, + the Wave 1-4 store ladder)
  └── DONE — server storage substrate is PostgreSQL; only `server/core/src/nvd_db.cpp` remains SQLite,
      scheduled for deletion under ADR-1005 Phase 7 (below)

Software Licensing & Entitlements (ADR-0024, status: proposed) — supersedes the Phase 10 sketch above;
  spans TWO placements, not one — see the Phase 9/10 block above for the per-issue breakdown
  ├── In-server placement (PARTIAL): `ProductRegistryStore` (#264/10.1) — the SQLite `CatalogStore`
  │     sketch's replacement; compiles and is tested but has no production writer/reader at the pin;
  │     product tags (10.4/#267) are core-scoped by Decision 15 but not yet built
  └── Re-scoped to the **SAM UCE module** (NOT built in-server, #265/10.2 + #266/10.3 closed
        NOT_PLANNED with no delivery): the 5-source entitlement plane (D12) and usage metering/
        reclamation (D15) — distinct from ADR-1005 Phase 7's *vulnerability* UCE below

Phase 15 (TAR Dashboard & Scope Walking) — DONE, all 8 issues (15.A–15.H) shipped
  └── requires ResponseStore (Phase 1.1), ScopeEngine (Phase 1.6), TAR plugin (Phase 7.19)

Phase 16 (System Guardian — Guaranteed State)
  16.A Windows-first ──── IN PROGRESS (Spark engine rungs 1-7+, GuardianEngine, BaselineStore,
                           /guaranteed-state UI shipped; Spark wired (agent.cpp:1255) but INERT by
                           default — prefer_spark_=false, legacy IGuard is the sole live enforcement
                           path; 59 merged guardian PRs at the pin (more since); issue #555 itself still open)
    └── 16.B Linux ─────── STARTED EARLY (`guard_systemd.cpp` exists) ahead of the stated 16.A-soak
                            gate — sequencing decision pending, see 16.B body note
          └── 16.C macOS ── NOT STARTED; gated on 16.A + 16.B soak + Endpoint Security entitlement

ADR-1005 (Headless Platform & Use-Case Engines, `docs/adr-1005-execution-plan.md`)
  ├── Phase 6 (module cutover to engine-principal auth) ── gated on M3(d) confinement mechanism
  └── Phase 7 (NVD/vuln UCE strangler migration) ────────── NEXT, not started
        └── deletes `nvd_db.cpp` (the last server-side SQLite store, Postgres block above)

Phase 9 (Connector Framework) ── DEMOTED, NOT a dependent of ADR-1005 Phase 7 (no such edge exists —
  owner decision withdrawn 2026-09-07: ADR-1005 does not classify connectors, and Decision 2 places
  estate-fact collection in core). Standalone, PLACEMENT REVIEW PENDING: whether connectors are core
  estate-fact collection or use-case interpretation belonging in an engine is an open question to be
  settled before any re-plan; Phase 9 issues #256–#262 stay deferred/unscheduled until it is
  (see Phase 9 body banner)

High Availability (ADR-2002, `docs/ha-delivery-matrix.md`) — supersedes Phase 14.6 above
  [as of dev @ `d295db964`, 2026-09-07, 11:01 UTC — every claim below is merge-commit-ancestry-verified
   (`git merge-base --is-ancestor <merge-sha> d295db964`), NOT `gh pr view` current state, which can
   postdate the pin; re-check before acting — PR/workstream state moves within hours]
  ├── Phase A (WS-0, WS-1, WS-2a, WS-7, WS-10) ── WS-0/WS-1/WS-7 DONE; WS-2a DONE (2a-1 + 2a-2,
  │                                                 #3924 merged 2026-09-03, IS an ancestor); WS-10 NOT
  │                                                 DONE at the pin — #4092 merged 2026-09-07 12:58 UTC,
  │                                                 ~1h AFTER the pin, confirmed NOT an ancestor; stays
  │                                                 PR #4092 open / not started here
  ├── Phase B (WS-3..WS-6, WS-8-readyz, WS-13) ── ALL required before a 2nd server replica; mostly not
  │                                                 started, EXCEPT WS-3 slice 3.1 (fenced `LeaderElector`
  │                                                 primitive, #4011 merged 2026-09-06, IS an ancestor)
  │                                                 — done but INERT, no loop wired yet
  └── Phase C (enable/validate/operate: WS-9, WS-11, WS-12, WS-14) ── not started

Route-sink refactor (#2542) — cross-cutting, ongoing
  [as of dev @ `d295db964`, verified by ancestry, not `gh pr view` state]
  └── extracts remaining route owners onto HttpRouteSink for testability, across Phases 3-14's REST
      surfaces; PR #4083 (custom-properties) merged 2026-09-07 14:29 UTC — AFTER the pin, NOT an
      ancestor of `d295db964`; PR #4057 (dashboard/nvd) IS an ancestor — it is in fact `d295db964`
      itself (#4057's merge commit sha == the pin sha)
  └── since the pin: complete — PR-4…PR-12 landed and #2542 is closed (re-verified 2026-09-13)
```

---

## Recommended Execution Order

Phases 0, 1, 3, 4, 5, 6, 8, and 15 are complete (all-Done). Phase 2 and Phase 7 are 92%/95% Done
respectively — each has exactly one Partial item (2.9 concurrency, 7.8 patch deployment; see the Index
for both). Phase 10 is 0/4 Done — 10.1 is placed in-server but Partial (no production writer/reader at
the pin); 10.2–10.4 closed NOT_PLANNED with no delivery (see Phase 10 note).
Phase 9 is demoted (deferred pending an owner placement decision, not an ADR-1005 consequence — see
Phase 9 body banner — no longer the #2 slot it held since 2026-03). The order below leads with the fronts the commit log and
open-PR list show as currently active, then works through the remaining backlog phases. PR and
workstream states below are **as of dev @ `d295db964` (2026-09-07)** and drift within hours — re-check
before acting on any "open" / "in progress" claim:

1. **ADR-1005 Phase 7 — NVD/vuln UCE strangler migration.** Next up, not started — PRs A–D are
   unblocked; PR E (the server-side deletion) is gated on the M3 parity + Decision 14 confinement
   gates and the Phase 0.3 deprecation window per `docs/adr-1005-execution-plan.md` (Phase 6 precedes
   it on the ladder), so "next" means A–D, not the whole phase. Re-homes the
   server-side NVD sync + CVE matching capability (and the grandfathered ADR-0023/ADR-4001 additions)
   into the vulnerability-management use-case engine module; deletes `server/core/src/nvd_db.cpp`,
   the **last server-side SQLite store** — closing out the Postgres substrate migration. See
   `docs/adr-1005-execution-plan.md` Phase 7. (No dependency on Phase 9 — see Phase 9's own entry.)
2. **High Availability (ADR-2002).** As of dev @ `d295db964` (11:01 UTC) — verified by merge-commit
   ancestry (`git merge-base --is-ancestor`), not `gh pr view` state: Phase A partly done — WS-0/WS-1/
   WS-7/WS-2a (both 2a-1 and 2a-2, #3924 merged 2026-09-03, IS an ancestor) are done — 2a-2's own row
   text names loss-free cross-replica reconnect (durable outbox replay `ORDER BY event_id`) as a
   still-outstanding 2nd-replica precondition (see the gate note below); **WS-10 is NOT
   done at the pin** — #4092 merged 2026-09-07 12:58 UTC, ~1h *after* the pin, confirmed NOT an
   ancestor, so WS-10 stays PR #4092 open here. Phase B has one early slice landed — WS-3 3.1 (fenced
   `LeaderElector` primitive, #4011 merged 2026-09-06, IS an ancestor) is done but **inert** (no loop
   wired, no runtime change) — the rest of Phase B (WS-3 3.2/3.3/3.4, WS-4, WS-5, WS-6, WS-8-readyz,
   WS-13) plus all of WS-10 remain the gate for a 2nd server replica. `docs/ha-delivery-matrix.md` at
   the pin agrees (WS-2a-2 outstanding / WS-3 planned / WS-10 planned there too) — the matrix's own
   re-stamp for WS-2a-2 and WS-3 (`a38fe5dac`, committed 2026-09-06 19:14 UTC+1 on a sibling lineage)
   first reached `dev` via merge `a27f179e3` on 2026-09-07 13:44 UTC+1 — after this pin, so it is not
   an ancestor of `d295db964`; the matrix visible at the pin therefore still shows the pre-re-stamp
   state. WS-10's docs update ships inside PR #4092 itself (merged 2026-09-07 12:58 UTC) — likewise
   **after** this pin, so the matrix and this roadmap should converge once `dev` moves past them; the
   roadmap here follows verified ancestry, not the matrix file's stamp date or `gh pr view`'s live
   state. **Since the pin (re-verified 2026-09-13 @ `c7f3a5bed`):** WS-10 and WS-3 3.2/3.3/3.4 are done
   (#4092, #4134, #4169, #4194) and WS-4 4.1 is done (#4245; inert — nothing reads it for dispatch until
   4.2), so the 2nd-replica gate is now at least the rest of WS-4 plus WS-5, WS-6, WS-8-readyz and
   WS-13 — see below, four more items belong in that gate too. Those four are easy to miss because
   each shows "done" at a coarser grain: the two `DisabledUntilFixed` named fixes (`nvd_sync`'s
   engine-tier migration, the concurrency-claims reconciler's PG-clock fix #4093) that
   `background_jobs.hpp`'s classification holds out of the safe-to-scale set regardless of WS-10's
   status — `leader_gate.hpp` deliberately lets both keep running today; the hold is the deployment
   safe-to-scale gate, procedural only, never this runtime gate; WS-2a's own
   unshipped precondition (loss-free cross-replica reconnect via durable outbox replay `ORDER BY
   event_id` — WS-2a shows "done" at the row-status level, but its own row text in
   `docs/ha-delivery-matrix.md`'s WS-2 row names this the outstanding 2nd-replica precondition,
   corroborated by `docs/executions-history-ladder.md`'s replica-local `Last-Event-ID` mechanism);
   #4014 (WS-11 leader identity/epoch + CRL-freshness-staleness metrics + split-brain alert + the
   `/readyz` decision), which the WS-3 3.2 exit-criteria note names a **hard prerequisite before a 2nd
   replica or any WS-9 failover scenario** and which is distinct from WS-8-readyz's per-tier health
   contract already listed above; and #4098 (verify webhook/offload emit sites are per-replica-origin
   before a 2nd replica — tracked against `store_worker_pool.worker_loop`'s `StoreWorkerPool::workers_`
   thread — or a fleet-triggered emit double-delivers). That gate is procedural: nothing in code
   refuses a 2nd replica today. See
   `docs/ha-delivery-matrix.md`; re-verify before acting — its own boxed "Gate" callout hasn't caught
   up to WS-11/WS-13 yet, so read the per-row exit-criteria notes too, not the callout alone
   (Tr3kkR/Yuzu#4618). This cluster of PRs merged within a 4-day
   window straddling the pin (#3924 2026-09-03, #4011 2026-09-06, #4092 2026-09-07 12:58 — the pin
   itself is 2026-09-07 11:01, between #4011 and #4092).
3. **Guardian hardening (Phase 16).** 16.A Windows-first soak continues (Spark engine, BaselineStore,
   `/guaranteed-state` UI — 59 merged guardian PRs at the pin, with more since, e.g. #4190, #4224, #4225,
   #4284, #4302); 16.B Linux delivery has already started
   (`guard_systemd.cpp`) ahead of the stated 16.A-soak gate — **sequencing decision pending (PO)**:
   accept and drop the gate, or pause 16.B. 16.C macOS remains blocked on the Endpoint Security
   entitlement.
4. **Route-sink refactor (#2542).** Ongoing cross-cutting hygiene (8 route owners moving onto
   `HttpRouteSink` for testability) — rides along with other phase work rather than blocking it. As of
   dev @ `d295db964`, verified by ancestry: PR #4083 (custom-properties) merged 2026-09-07 14:29 UTC,
   **after** the pin — not an ancestor, so it was still open at the pin; PR #4057 (dashboard/nvd) is an
   ancestor — it is `d295db964` itself. **Since the pin (re-verified 2026-09-13): done.** The remaining route
   owners landed (PR-4 through PR-12, including #4083) and #2542 is closed.
5. **Phase 12** — Remaining agent capabilities (closes capability map further; no blockers;
   parallelizable). 12.1 and 12.8 already shipped.
6. **Phase 11** — Consumer model & SDKs (platform extensibility, parallelizable with 12). 11.1 closed
   NOT_PLANNED with no delivery (its auth/token substance was absorbed into ADR-1005 engine principals,
   but the issue's own scope was never built); 11.2–11.4 not started.
7. **Phase 13** — Remaining security hardening & polish: 13.1 (2FA on approval — stale, general MFA
   step-up exists but isn't wired to approval), 13.3 (monitoring UI), 13.4 (branding). 13.2 and 13.5
   already shipped.
8. **Phase 14** — Remaining scale items: 14.1 (P2P content), 14.2 (multi-gateway), 14.4–14.5
   (additional connectors — nominally depend on the now-deferred Phase 9). 14.3 Partial (Closed —
   not planned; the sharding design was obsoleted by the Postgres substrate — see the Index row);
   14.6 superseded by the ADR-2002 HA program above.
9. **Phase 9 (demoted)** — Connector framework. **Deferred.** **Owner decision (2026-09-07):**
   declared next priority since 2026-03 with zero commits; whether connectors are core estate-fact
   collection (ADR-1005 Decision 2) or use-case interpretation belonging in an engine is an **open
   placement question to be settled before any re-plan** — not a settled ADR-1005 consequence.
   9.8 closed NOT_PLANNED with no delivery and is unaffected either way.

---

## Issue Summary

| Phase | Issues | Capabilities Covered |
|-------|:------:|:-------------------:|
| 0: Foundation | 5 | 7 |
| 1: Data Infrastructure | 7 | 12 |
| 2: Instruction System | 12 | 10 |
| 3: Security & RBAC | 9 | 12 |
| 4: Agent Infrastructure | 8 | 14 |
| 5: Policy Engine | 5 | 6 |
| 6: Windows Depth | 6 | 13 |
| 7: Scale & Integration | 20 | 24 |
| 8: Visualization & Response Experience | 3 | 3 |
| 9: Connector Framework | 8 | 8 |
| 10: Software Catalog | 4 | 4 |
| 11: Consumer Model | 4 | 4 |
| 12: Agent Capabilities | 13 | 13 |
| 13: Security & Polish | 5 | 5 |
| 14: Scale & Enterprise | 6 | 6 |
| 15: TAR Dashboard & Scope Walking | 8 | 8 |
| 16: System Guardian (Real-Time GS) | 3 | 10 |
| **Total** | **126** | **159** |

Plus 4 future-tier items tracked but not scheduled. The remaining capabilities are covered by existing "Done" implementations.
