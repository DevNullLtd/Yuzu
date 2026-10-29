# Yuzu Codebase Conformance Audit — Code vs. Documented Intent

> **Comparison of the codebase against the *intent* recorded in its documents** (ADRs, CLAUDE.md routed concerns, WIRED/SHIPPED status markers, user manuals, capability-map/roadmap).

| | |
|---|---|
| Branch | `feat/postgres-f3-flip` |
| HEAD | `1f375f29` |
| Date | 2026-06-18 |
| Method | 17-domain multi-agent fan-out; each claim statically verified + adversarially re-checked by an independent skeptic; behavioral claims confirmed against a live Postgres-flipped stack (Phase 3 UAT) |
| Claims audited | **388** |
| Confirmed | **340 (87%)** |
| Non-confirmed (drift) | **48** |

## 1. Result at a glance

**By intent tier**

| Tier | Meaning | Claims | Confirmed | Drift |
|---|---|--:|--:|--:|
| A | Architectural law (ADR / routed-concern) | 201 | 189 | 12 |
| B | Aspirational (capability-map/roadmap) | 20 | 6 | 14 |
| C | Current-state WIRED/SHIPPED claim | 77 | 68 | 9 |
| D | User-manual behavioral spec | 90 | 77 | 13 |

**Drift by severity:** HIGH=1, MEDIUM=15, LOW=31 (+ 1 unsettled/UNVERIFIABLE)

**Drift by direction:** `doc-ahead-of-code`=25, `code-ahead-of-doc`=16, `contradiction`=6, `none`=1

**Headline.** The codebase is **highly faithful to its binding intent** — 87% of claims confirmed, and **Tier-A architectural law (ADRs + routed concerns) holds at 189/201**. The dominant drift pattern is the *opposite* of the usual failure mode: **the docs lag behind the code** (`code-ahead-of-doc` + the bulk of `doc-ahead-of-code` are Tier-B capability-map entries that mark *shipped* features "Not implemented"). The single systemic exception worth code attention is the cluster of MCP/audit invariant gaps and one dangerous **user-manual contradiction** (auth-18) that documents a privilege-escalation path the code deliberately refuses.

## 2. Phase 3 — Live UAT evidence (Postgres-flipped stack)

Booted the **native `feat/postgres-f3-flip` server binary** (`build-macos/server/core/yuzu-server`, built 2026-06-18 08:25) against a throwaway `yuzu-postgres:local` container. Behavioral confirmation of the dominant architectural cluster:

| Check | Result | Substantiates |
|---|---|---|
| Boot **without** DSN | `[PG] Refusing to start: no PostgreSQL DSN. Set --postgres-dsn / YUZU_POSTGRES_DSN (ADR-0006/0007 …)` → `run(): refusing to serve` → shutdown | **Fail-closed** (ADR-0007); asp-07/asp-16/ci-15 (parity-plan "SQLite zero-ops" is false) |
| Boot **with** DSN | `/healthz` 302, `/readyz` `{"status":"ready"}` | server runs on Postgres; `pg_pool` in `/readyz` conjunction |
| `/metrics` | `yuzu_pg_pool_{size=16,open=1,in_use=0,waiters=0}` + `yuzu_pg_acquire_wait_seconds` histogram | #1368 `PgPool::Observer` metrics wired |
| Postgres schema | `public.schema_meta` row `endpoint_state\|1`; table `endpoint_state.endpoints` | ADR-0008 shared meta + schema-per-store; born-on-PG `OfflineEndpointStore` via `PgMigrationRunner` |
| `yuzu_fleet_perf_*` (dex-21) | wired at `agent_registry.cpp:1478-1481` | resolved static (was UNVERIFIABLE) |
| executions drawer stamps (instr-22) | `workflow_routes.cpp:190` emits `data-execution-id`; `instruction_ui.cpp:765` binds | resolved static (was UNVERIFIABLE) |

## 3. Drift findings (48)

Ordered by severity, then domain. `direction`: `doc-ahead-of-code` = claimed but not built · `code-ahead-of-doc` = built but doc stale · `contradiction` = code does what the doc forbids (or vice-versa) · `superseded-decision` = reality outgrew an ADR.

### `asp-03` · HIGH · DRIFTED · doc-ahead-of-code
**Domain:** Aspirational accuracy (capability-map/roadmap/parity/SOC2) (Tier B)
**Source:** docs/capability-map.md:1163-1171 (§31.2)
**Claim:** Event Guards — Kernel-Event-Driven Enforcement (Windows) §31.2 is :x: Not implemented (PRs 3, 5, 6, 7, 10). Registry Guard, SCM Guard, WFP Guard, ETW Guard listed as roadmap.
**Evidence:** guard_registry.cpp exists (start() at line 239 with enforcement logic, enforce-mode recreate at line 310, non-Windows no-op stub at line 545). guard_file.cpp exists (FileGuard::start() at line 84 with Windows implementation, no-op stub at line 457). guard_service.cpp exists. guardian_engine.cpp:516-705 wires FileGuard (line 536), ServiceGuard (line 602), and RegistryGuard (line 660) into the engine. WFP Guard and ETW Guard are absent (no guard_wfp* or guard_etw* files). So Registry + File + SCM guards ARE shipped, making this PARTIAL not :x:.
**Verdict note:** [drift upheld] Drift independently confirmed. capability-map.md:1163-1171 (§31.2 "Event Guards — Kernel-Event-Driven Enforcement (Windows)") is marked :x: "Not implemented (PRs 3, 5, 6, 7, 10)" and lists four primitives. Three are in fact shipped and wired into the production agent: (1) Registry Guard — RegistryGuard using RegNotifyChangeKeyValue + WaitForMultipleObjects (agents/core/src/guard_registry.cpp:456,468,522) with enforce-mode key recreate/write-back (RegCreateKeyExW, line 319), wired in guardian_engine.cpp:660-709; (2) SCM Guard — ServiceGuard using NotifyServiceStatusChangeW + OpenSCManagerW/OpenServiceW (guard_service.cpp:347-449), wired in guardian_engine.cpp:598-658, git commit e841be56 "real-time Windows service run-state enforcement (PR5)"; (3) File Guard — FileGuard using ReadDirectoryChangesW + FindFirstChangeNotificationW (guard_file.cpp:176,309), wired in guardian_engine.cpp:516-596. All four guard sources are in agents/core/meson.build:41 and compiled into the agent. Only WFP Guard and ETW Guard remain genuinely absent (no guard_wfp*/guard_etw* sources exist outside unrelated Echo/network code). The section should therefore be :large_orange_diamond: Partial (3 of 4 named primitives shipped), not :x:. (Note: the drift direction is code-ahead-of-doc — the doc under-states shipped work — not the auditor's stated "doc-ahead-of-code"; but the drift itself is real and material.) I could not find any code or doc text that satisfies the :x: Not-implemented claim, so the finding stands.
**Recommended record update:** none

### `agent-12` · MEDIUM · DRIFTED · contradiction
**Domain:** Agent core, plugins, privilege, OS matrix (Tier A)
**Source:** docs/os-capability-matrix.md line 29: "DEX — performance telemetry (CPU/mem/disk levels) | Windows ✅ | Linux ✅ | macOS ⛔ | echo_perf.cpp (Win: GetSystemTimes...; Linux: /proc)"
**Claim:** echo_perf.cpp is the source of truth for DEX perf telemetry and implements Linux (/proc) collection (Linux ✅).
**Evidence:** echo_perf.cpp:190 `#else // !_WIN32 — Linux (/proc) and macOS (host_statistics) are kPlanned`; read_perf_counters() returns empty PerfCounters with valid=false on BOTH Linux and macOS (lines 194-198). The machine-readable source-of-truth echo_schema_registry.cpp:296 marks perf source `OsSupportStatus::kPlanned` for linux (and :298 macos), only :291 windows kSupported. The cited source-of-truth file does NOT deliver Linux perf.
**Verdict note:** [drift upheld] Confirmed drift. The matrix row docs/os-capability-matrix.md:29 ("DEX — performance telemetry (CPU/mem/disk levels)") cites `echo_perf.cpp` as its source of truth, marks Linux ✅, and says "Linux: /proc". The cited file does NOT deliver this on Linux: agents/plugins/echo/src/echo_perf.cpp:190-198 — the non-Windows `read_perf_counters()` returns `PerfCounters` with valid=false and the inline comment "collect_perf records nothing on this platform yet". The file's own header agents/plugins/echo/src/echo_perf.hpp:18 states "Linux (/proc) and macOS (host_statistics) are kPlanned in the registry." The machine-readable source of truth echo_schema_registry.cpp:296 marks the `perf` source OsSupportStatus::kPlanned for linux (only :291 windows kSupported), and echo_plugin.cpp:725 emits `unsupported_platform` when the read is invalid. The Linux /proc perf code that DOES exist (agents/core/src/dex_linux_collector.cpp poll_perf at :243 + dex_linux_proc.cpp parse_proc_stat/parse_commit_pct/parse_diskstats) belongs to a DIFFERENT capability — it produces sustained-breach DEX reliability SIGNALS (cpu_sustained/memory_pressure/disk_latency observations, the matrix's line-28 "DEX — reliability signals" row), not the continuous BRD-A1 device performance-level warehouse tier ($Perf_Live/$Perf_Hourly) that echo_perf.cpp owns and line 29 describes. So no source satisfies the "Linux ✅" claim for the row as cited.
**Recommended record update:** CLAUDE.md edit

### `asp-02` · MEDIUM · DRIFTED · doc-ahead-of-code
**Domain:** Aspirational accuracy (capability-map/roadmap/parity/SOC2) (Tier B)
**Source:** docs/capability-map.md:1076-1078 (§28.3)
**Claim:** Response Offloading (§28.3) is :x: Not implemented. 'Configure external HTTP endpoints to receive response data in real time. OffloadTarget model with auth, event filtering, and batch delivery.'
**Evidence:** §20.7 (capability-map.md:848-850) marks the exact same capability DONE with OffloadTargetStore, batch_size, typed auth (none/bearer/basic/hmac), CRLF-guarded headers, REST CRUD at /api/v1/offload-targets, and wiring in agent_service_impl.cpp (agent.registered and execution.completed events). offload_routes.cpp line 1 and offload_target_store.cpp line 1 confirm existence. Roadmap 8.3 is also Done. §28.3 and §20.7 describe the same feature; §28.3 has not been updated.
**Verdict note:** [drift upheld] Drift confirmed. The documented claim in docs/capability-map.md:1076-1078 (§28.3) marks Response Offloading as ":x: Not implemented", but the feature is fully shipped in code. Verified independently: server/core/src/offload_target_store.hpp:33-90 defines OffloadAuthType {None,Bearer,Basic,Hmac} and the OffloadTarget model (name/url/auth_type/auth_credential/event_types/batch_size/enabled); offload_target_store.cpp implements typed auth header construction (lines 583-591), CRLF-guard rationale on auth_credential (lines 248-251), batching (build_batch_body line 519, per-target batch_size dispatch line 668), and credential-omitting reads. REST CRUD is registered in offload_routes.cpp at /api/v1/offload-targets (GET list :66, POST create :84, GET one :136, DELETE :158, GET deliveries :197) gated by perm_fn. Wiring into agent_service_impl.cpp fires offload events for agent.registered (line 516) and execution.completed (lines 1239, 1470). This exactly matches the §20.7 entry (capability-map.md:848-850) which correctly marks the SAME capability DONE. §28.3 is an internal contradiction with §20.7 and is the stale/incorrect entry — doc-ahead-of-code (doc understates implemented reality). Auditor evidence independently corroborated; I did not rely on it.
**Recommended record update:** none

### `asp-05` · MEDIUM · DRIFTED · doc-ahead-of-code
**Domain:** Aspirational accuracy (capability-map/roadmap/parity/SOC2) (Tier B)
**Source:** docs/capability-map.md:1137-1151 (§30.1-§30.4)
**Claim:** All four Scope Walking and Result Set capabilities (§30.1-§30.4) are :x: Not implemented.
**Evidence:** result_set_store.cpp (857 lines) implements ResultSetStore with create_pending (line 373), list_by_owner (line 381), lineage (line 466), pin/unpin (lines 634/662), GC sweep, per-owner quotas. rest_api_v1.cpp has 10+ /api/v1/result-sets routes (GET, POST, from-inventory-query, from-echo-query, from-instruction-result, re-eval, members, lineage, pin, unpin, delete — lines 3135-3570). scope_engine.cpp:420-434 implements from_result_set: short-circuit kind. result_sets_ui.cpp (render_result_sets_sidebar, render_result_set_detail, from_result_set token display). result_set_matcher.cpp exists. CHANGELOG (~line 1194-1234) confirms these shipped. §30.1, §30.2, and §30.3 should be DONE; §30.4 operational hardening is PARTIAL (metrics present, full GC/re-eval in code).
**Verdict note:** [drift upheld] Independently confirmed the drift is real. The doc (capability-map.md:1137-1151) marks all four §30 capabilities as ":x: Not implemented," but the code substantively implements all four and they are wired into the running server. §30.1: ResultSetStore (server/core/src/result_set_store.cpp, 857 lines — insert/list_by_owner:381, lineage with cycle guard:466, gc_sweep:827, pin/unpin, per-owner quotas) is instantiated in server/core/src/server.cpp:1734-1736 against result_sets.db and is part of /readyz (server.cpp:4372). §30.2: from_result_set:<id-or-alias> short-circuit scope kind in scope_engine.cpp:420-434, resolved at dispatch (server.cpp:5318), membership preload in agent_registry.cpp:1102-1155, sidebar/breadcrumb in result_sets_ui.cpp. §30.3: fromResultSet: YAML validation with the exact documented combo rules in instruction_store.cpp:392-412 (validate_definition_scope, rejects fromResultSet+managementGroups and fromResultSet+dynamic, deferred dispatch-time resolution) for InstructionDefinition/InstructionSet. §30.4: gc_sweep, POST /api/v1/result-sets/{id}/re-eval (rest_api_v1.cpp:3428), and Prometheus metrics yuzu_result_sets_total / yuzu_result_set_quota_rejected with 429 quota rejection (rest_api_v1.cpp:3069-3122). CHANGELOG.md:1191-1233 explicitly documents these as shipped across PRs C/D/E. The only incompleteness is policy-level fromResultSet, which is explicitly gated as "not yet supported for policies" (policy_store.cpp:684) — a minor sub-surface gap that does not rescue an "all four Not implemented" claim. Direction is doc-ahead-of-code (doc understates shipped reality).
**Recommended record update:** none

### `asp-07` · MEDIUM · DRIFTED · doc-ahead-of-code
**Domain:** Aspirational accuracy (capability-map/roadmap/parity/SOC2) (Tier B)
**Source:** docs/enterprise-parity-plan.md:16
**Claim:** Architecture comparison table: 'Server Database | SQL Server (multiple DBs) | SQLite (embedded, WAL mode)'. Yuzu stated advantage: 'No SQL Server dependency — SQLite is embedded, zero-ops'.
**Evidence:** server.cpp:929-944 constructs a PgPool, fails closed on empty/unreachable postgres_dsn with '[PG] Refusing to start' log token. CHANGELOG [Unreleased] states 'BREAKING — the server now runs on PostgreSQL (ADR-0006/0007)... there is no SQLite fallback for the server.' offline_endpoint_store.cpp line 5 includes pg/pg_pool.hpp and line 58 takes PgPool& constructor. The server now REQUIRES PostgreSQL; the 'zero-ops SQLite' claim is no longer accurate for any server deployment.
**Verdict note:** [drift upheld] Drift independently confirmed. docs/enterprise-parity-plan.md:16 still lists 'Server Database | ... | SQLite (embedded, WAL mode)' and line 30 (repeated at line 632) claims 'No SQL Server dependency — SQLite is embedded, zero-ops' as a standing Yuzu advantage, with NO acknowledgment of the Postgres flip anywhere in the doc. The code contradicts this: server.cpp:937-941 logs '[PG] Refusing to start' and sets startup_failed_=true when postgres_dsn is empty, and server.cpp:964-967 fails closed when the database is unreachable — there is no SQLite fallback for the server substrate. CHANGELOG.md:12 confirms 'BREAKING — the server now runs on PostgreSQL (ADR-0006/0007) ... there is no SQLite fallback for the server.' The first born-on-Postgres store is real: offline_endpoint_store.cpp:5 includes pg/pg_pool.hpp and offline_endpoint_store.cpp:58's constructor takes pg::PgPool&. The 'zero-ops embedded SQLite, no SQL Server dependency' claim is now categorically false — the server has a hard PostgreSQL dependency and refuses to boot without it.
**Recommended record update:** none

### `asp-08` · MEDIUM · DRIFTED · doc-ahead-of-code
**Domain:** Aspirational accuracy (capability-map/roadmap/parity/SOC2) (Tier B)
**Source:** docs/enterprise-parity-plan.md:5
**Claim:** Document baseline: 'Yuzu v0.7.0, 165/184 capabilities done'.
**Evidence:** Capability map (docs/capability-map.md:35) shows current count at 169/228 done overall. The enterprise-parity-plan uses an older capability count (184 total vs 228 total now) and an older version number. The document predates Phase 8+ features, scope walking, Guardian PRs, PostgreSQL substrate, DEX signals, and network quality dashboard. Version reference v0.7.0 is stale; the product has advanced materially.
**Verdict note:** [drift upheld] Drift independently confirmed on three axes. (1) Version: enterprise-parity-plan.md:5 and :11 cite "Yuzu v0.7.0", but meson.build declares version: '0.12.0' (five minor versions ahead). (2) Capability count: the plan states "165/184 capabilities done" while the authoritative capability-map.md:35 shows "169/228 done (74%)" — total grew from 184 to 228 (44 Phase 8-16 capabilities added per capability-map.md:33) and done moved 165→169. (3) Architecture staleness: enterprise-parity-plan.md:16 still lists "Server Database = SQLite (embedded, WAL mode)", but CHANGELOG.md [Unreleased] documents a BREAKING flip to PostgreSQL as the server substrate (the very change on this branch). The auditor's verdict holds; I verified each fact from source files rather than the cited evidence.
**Recommended record update:** none

### `asp-15` · MEDIUM · PARTIAL · doc-ahead-of-code
**Domain:** Aspirational accuracy (capability-map/roadmap/parity/SOC2) (Tier B)
**Source:** docs/enterprise-readiness-soc2-first-customer.md §3.2 and docs/capability-map.md §18.10
**Claim:** Workstream B requires '2FA/TOTP for high-risk approvals'. Capability map §18.10 states not implemented.
**Evidence:** totp.cpp and totp.hpp exist. auth_db.cpp:489-521 adds mfa_totp_secret BLOB, mfa_enrolled_at, mfa_last_counter columns, mfa_recovery_codes table in schema v2 migration. auth_db.cpp:1221 implements mfa_init_enrollment(), mfa_verify_enrollment(). rest_api_v1.cpp:805 defines StepUpFn; step_up_fn is wired into token creation (line 1325), deletion (line 1477), session revocation (line 1660), software packages (line 3806), guaranteed-state rules (line 4299). The SOC2 doc says this requirement is open; it is more advanced than claimed — TOTP infrastructure and step-up integration are present. What remains is completing the MFA enrollment UI and audit evidence.
**Verdict note:** [drift upheld] Drift is real and I could not refute it. capability-map.md §18.10 (line 780-782) flatly states "Two-Factor Authentication for Approvals :x: T2 — Not implemented." That status is false: TOTP/2FA is substantially shipped and wired into the build (server/core/meson.build:271-273 compiles totp.cpp, mfa_step_up.cpp, mfa_qr.cpp). Concretely: (a) full enrollment UI with server-rendered QR — settings_routes.cpp:786 render_mfa_fragment + routes /fragments/settings/mfa (4441), /api/settings/mfa/init|verify|disable|recovery-codes (4452-4536); (b) login MFA challenge + step-up endpoints — auth_routes.cpp:767 /login/mfa, 963 /login/mfa/enroll, 1134 /login/mfa/stepup; (c) a real (non-stub) step-up enforcement gate — mfa_step_up.cpp:16 require_mfa_step_up (fail-closed on store error, freshness window, OIDC amr handling) constructed in server.cpp:5005 with live config cfg_.mfa_step_up_window_secs / cfg_.mfa_enforcement and applied to high-risk REST endpoints (rest_api_v1.cpp:1325 tokens, 1660 sessions, 3806 software-packages, 3979 software-deployments/start, 4299 guaranteed-state rules, 4632 push) and settings user-management (settings_routes.cpp:3450, 3538); (d) CLI flags --mfa-enforcement and --mfa-step-up-window-secs (main.cpp:257,266) with optional/required/admin-only modes; (e) schema (auth_db.cpp:489-523) and ops (mfa_init_enrollment/verify/status/recovery/disable). Two notes on the auditor's framing: the direction is doc-BEHIND-code (code is ahead of the doc), not "doc-ahead-of-code"; and the auditor's "what remains is the enrollment UI" is wrong — the enrollment UI exists. The only genuine gaps vs §18.10's narrow wording are instruction-approval-workflow-specific gating and the email-OTP fallback, neither of which is implemented — but that does not justify a blanket "Not implemented" status. The SOC2 doc §3.2 line 71 lists this only as a target "Required Feature/Control," which is defensible, but capability-map §18.10 is a factual error.
**Recommended record update:** none

### `asp-16` · MEDIUM · DRIFTED · doc-ahead-of-code
**Domain:** Aspirational accuracy (capability-map/roadmap/parity/SOC2) (Tier B)
**Source:** docs/enterprise-parity-plan.md (architecture comparison, advantages section)
**Claim:** Yuzu advantage: 'No SQL Server dependency — SQLite is embedded, zero-ops'. The 'Yuzu Equivalent' column throughout references SQLite for response persistence, audit trail, etc.
**Evidence:** CHANGELOG [Unreleased] BREAKING entry: 'the server now runs on PostgreSQL (ADR-0006/0007)... operator action: provision a reachable PostgreSQL... and set YUZU_POSTGRES_DSN before upgrading.' server.cpp:937-938 emits '[PG] Refusing to start: no PostgreSQL DSN'. OfflineEndpointStore is already Postgres-native. The enterprise-parity-plan's competitive advantage claim of 'zero-ops embedded SQLite' is now inaccurate for the server component — operators must provision and manage a PostgreSQL instance. The agent remains SQLite.
**Verdict note:** [drift upheld] Drift independently confirmed. docs/enterprise-parity-plan.md asserts the competitive advantage "No SQL Server dependency — SQLite is embedded, zero-ops" at line 30 (and again at line 16 "Server Database ... SQLite (embedded, WAL mode)" and line 632 "SQLite (embedded, zero-ops)"), with SQLite referenced throughout the "Yuzu Equivalent" column (lines 74, 233, 249, 286, 326). The server code contradicts this: server.cpp:937-941 emits "[PG] Refusing to start: no PostgreSQL DSN ... the server requires Postgres" and sets startup_failed_ when cfg_.postgres_dsn is empty; server.cpp:964-967 also fails closed when the database is unreachable — there is explicitly no SQLite fallback (comment at server.cpp:931). OfflineEndpointStore is born-on-Postgres (server.cpp:985-992). CHANGELOG.md:12 documents this as a live "BREAKING — the server now runs on PostgreSQL (ADR-0006/0007)" requiring operators to provision and set YUZU_POSTGRES_DSN before upgrading. The "zero-ops embedded SQLite" advantage is therefore inaccurate for the server; only the agent remains SQLite. Could not refute.
**Recommended record update:** none

### `auth-18` · MEDIUM · DRIFTED · contradiction
**Domain:** Auth / RBAC / sessions / tokens (Tier D)
**Source:** docs/user-manual/authentication.md "Group-to-Role Mapping": "If the OIDC user's email or display name matches a local admin account, they are also granted admin regardless of group membership."
**Claim:** OIDC grants admin if the user's email or display name matches a local admin account, regardless of group membership
**Evidence:** auth.cpp:782-789 create_oidc_session: "Security (C3 fix): Admin role via OIDC ONLY through explicit group membership. Do NOT match on email/display_name — these are attacker-controlled values." Role is admin ONLY if a group equals admin_group_id; no email/display-name path exists
**Verdict note:** [drift upheld] Drift confirmed independently. The doc at docs/user-manual/authentication.md:288 states: "If the OIDC user's email or display name matches a local admin account, they are also granted admin regardless of group membership." I traced the OIDC code path myself: the callback handler at server/core/src/auth_routes.cpp:1357-1400 extracts email/display from claims and passes them to create_oidc_session, performing NO email/display-name admin matching. In create_oidc_session (server/core/src/auth.cpp:782-793) the role is admin ONLY if a value in `groups` equals `admin_group_id`; there is no email/display-name path. An explicit C3 security-fix comment (auth.cpp:783-784) states admin via OIDC is ONLY through explicit group membership because email/display_name are "attacker-controlled values." No other caller or code site applies such a match. The doc describes a privilege-escalation fallback that the code deliberately does not implement — a direct contradiction.
**Recommended record update:** CLAUDE.md edit

### `auth-19` · MEDIUM · DRIFTED · code-ahead-of-doc
**Domain:** Auth / RBAC / sessions / tokens (Tier D)
**Source:** docs/user-manual/authentication.md "API Tokens": "API tokens are always granted full admin-level access. RBAC scoping for API tokens is planned for a future release."
**Claim:** API tokens are always granted full admin-level access
**Evidence:** auth_routes.cpp:95-99 synthesize_token_session: "Resolve the creator's actual legacy role fresh (not unconditional admin)"; synth.role = get_user_role(principal_id).value_or(Role::user). A non-admin creator's token gets a user-role session, not admin
**Verdict note:** [drift upheld] Drift independently confirmed. authentication.md:350 claims "API tokens are always granted full admin-level access." The code contradicts this: synthesize_token_session (server/core/src/auth_routes.cpp:88-102) sets synth.role = auth_mgr_.get_user_role(api_token.principal_id).value_or(auth::Role::user) — the token inherits the creator's CURRENT legacy role (auth.cpp:737-743 returns the stored per-user role: user or admin), defaulting to Role::user, NOT unconditional admin. Furthermore require_admin (auth_routes.cpp:153-194) explicitly returns 403 for service-scoped tokens (line 163), MCP-tier tokens (line 172), and any session where role != admin (line 182). So a non-admin creator's token, and all scoped/MCP tokens, are denied admin operations. There is no code path that grants every API token admin access; the doc is stale.
**Recommended record update:** CLAUDE.md edit

### `dex-17` · MEDIUM · PARTIAL · code-ahead-of-doc
**Domain:** DEX telemetry (Tier D)
**Source:** docs/dex-signal-catalog.md:396-401 — "keep dex_obs_platforms() in sync with these collectors" + Linux table rows marked "live"
**Claim:** The server-side per-OS coverage map dex_obs_platforms() attributes all shipped Linux collector signals to Linux.
**Evidence:** Linux agent collectors emit disk.error, fs.corruption, hw.error, os.bugcheck, os.dirty_shutdown, os.time_unsynced, service.hung, process.hung (dex_linux_kmsg/journal) + hw.cpu_throttled (sysfs) + perf.disk_latency_high (proc), but dex_routes.cpp:128-145 dex_obs_platforms() kLinux[] lists only 7 (perf.cpu_sustained, perf.memory_pressure, storage.low, os.uptime_report, process.crashed, service.crashed, memory.exhausted). The code comment l.133-140 acknowledges the gap is deliberate pending the #1523 batch.
**Verdict note:** [drift upheld] Independently confirmed the drift. The documented claim (docs/dex-signal-catalog.md:399-401: dex_obs_platforms() "gains the new Linux obs_types ... keep it in sync with these collectors", plus the Linux status table at lines 452-470 marking 17 obs_types as Linux signals) is NOT satisfied by the code. server/core/src/dex_routes.cpp:128-132 kLinux[] lists only 7 obs_types (perf.cpu_sustained, perf.memory_pressure, storage.low, os.uptime_report, process.crashed, service.crashed, memory.exhausted). The other 10 Linux signals the doc attributes to Linux are NOT in the map: perf.disk_latency_high, hw.cpu_throttled, service.hung, os.time_unsynced, os.bugcheck, os.dirty_shutdown, disk.error, fs.corruption, hw.error, process.hung. Critically, the code comment at dex_routes.cpp:133-140 justifies the omission by claiming these "land WITH their collectors in the dex-linux-signals batch (#1523)" — but the collectors ARE present and shipped on this branch: dex_linux_kmsg.cpp emits disk.error/fs.corruption/hw.error/os.bugcheck/os.dirty_shutdown/process.hung (verified via grep); dex_linux_journal.cpp emits os.time_unsynced/service.hung and routes _TRANSPORT=kernel lines through classify_kernel_message (journal.cpp:137-138); dex_linux_sysfs.cpp emits hw.cpu_throttled; dex_linux_proc emits perf.disk_latency_high. All are listed in agents/core/meson.build:41 (built) and wired into dex_linux_collector.cpp (includes dex_linux_sysfs.hpp/journal.hpp/proc.hpp; poll loop calls poll_journald() at line 223). So the deliberate-deferral comment is stale, the map under-attributes 10 of 17 Linux signals, and a real Linux fleet's /dex Catalogue would show those signals as not-Linux-collected — the exact "monitored, quiet reads as healthy" failure the comment itself warns against. Direction is code-ahead-of-doc-instruction: the map was never updated when the collectors landed.
**Recommended record update:** CLAUDE.md edit

### `gw-20` · MEDIUM · PARTIAL · doc-ahead-of-code
**Domain:** Gateway (Erlang) (Tier C)
**Source:** yuzu_gw_app.erl:119-144 stop/1 + docs/user-manual implied graceful drain: 'Stop accepting new commands via the router' on shutdown.
**Claim:** On shutdown the gateway tells the router to stop accepting new commands (RouterPid ! drain), then drains in-flight commands, then flushes the heartbeat buffer.
**Evidence:** yuzu_gw_app.erl:123-129 sends RouterPid ! drain, but yuzu_gw_router.erl has NO drain clause — grep 'drain' in the router returns nothing; the message falls through handle_info(_Info,State)->{noreply,State} (172-173) and is silently ignored. The router keeps accepting send_command during drain. drain_pending/1 (147-169) and flush_sync (137) DO work.
**Verdict note:** [drift upheld] Independently confirmed the drift is real. yuzu_gw_app.erl:127 sends `RouterPid ! drain`, with the comment at :122 "Stop accepting new commands via the router." But yuzu_gw_router.erl has NO clause matching `drain`: the message handlers are handle_call({send_command,...}) (line 60), handle_call(_Request,...) (115), handle_cast(_Msg,...) (118), handle_info({fanout_timeout,...}) (121), handle_info({fanout_terminal,...}) (144), and the catch-all handle_info(_Info, State) -> {noreply, State} (172-173). The plain `drain` term arrives as an info message and is silently swallowed at line 172. The router #state{} record (34-36) holds only `fanouts` — there is no draining flag, and handle_call({send_command,...}) (60) dispatches unconditionally with no drain check, so the router keeps accepting new commands throughout the 10s drain window. A repo-wide grep finds `drain` nowhere in the router module. Steps 2 (drain_pending/1, app.erl:147-169) and 3 (flush_sync, app.erl:137) do work as documented; only step 1 ("stop accepting new commands") is unimplemented. Direction is doc/comment-ahead-of-code.
**Recommended record update:** none

### `mcp-03` · MEDIUM · DRIFTED · contradiction
**Domain:** MCP & agentic-first (A1-A4) (Tier A)
**Source:** CLAUDE.md routed-concern (MCP doc): "JObj/JArr output (never nlohmann::json output — parse only)"; docs/mcp-server.md Architecture: "nlohmann::json is used for parsing only"
**Claim:** MCP output serialization uses JObj/JArr string builders only; nlohmann::json is never used to serialize output (parse-only).
**Evidence:** list_issued_certs builds output via nlohmann::json items/payload and emits payload.dump() (mcp_server.cpp:2482-2510); revoke_certificate likewise (mcp_server.cpp:2580-2589). Both embed nlohmann-serialized JSON into the response text. Doc/CLAUDE invariant forbids nlohmann output.
**Verdict note:** [drift upheld] Drift independently confirmed. The documented invariant in docs/mcp-server.md:13 states "nlohmann::json is used for parsing only" (echoed by the CLAUDE.md MCP routed-concern "never nlohmann::json output"). However, two reachable, registered MCP tools build their RESPONSE payload with nlohmann::json and serialize it as output: list_issued_certs constructs `nlohmann::json items`/`nlohmann::json payload` and emits `payload.dump()` embedded as the response text content (server/core/src/mcp_server.cpp:2482-2508), and revoke_certificate builds `nlohmann::json payload = {{"revoked",true},...}` and emits `payload.dump()` (server/core/src/mcp_server.cpp:2580-2588). Both are confirmed registered tools (registration at lines 377/385, perm map 461/462, handlers at 2458/2525). The outer envelope uses JObj/JArr (the file uses that pattern in ~130 sites per the invariant), but the actual data payload the agentic client consumes is nlohmann-serialized output — a direct contradiction of the parse-only claim. I could not find any code path satisfying the documented claim for these two handlers. (Lines 2289/2328 are input/storage re-serialization, a separate gray area.)
**Recommended record update:** CLAUDE.md edit

### `mcp-04` · MEDIUM · PARTIAL · contradiction
**Domain:** MCP & agentic-first (A1-A4) (Tier A)
**Source:** CLAUDE.md routed-concern (MCP doc): "audit-event shape"; docs/mcp-server.md Security Model: "Every MCP tool call logged with action: mcp.<tool_name> and mcp_tool field on AuditEvent"
**Claim:** Every MCP tool call is logged with action mcp.<tool_name> AND populates the mcp_tool field on AuditEvent.
**Evidence:** mcp_audit helper (mcp_server.cpp:798-800) calls audit_fn with action "mcp."+tool_name, target_type="mcp_tool", target_id=tool_name. AuthRoutes::audit_log (auth_routes.cpp:466-487) sets target_type/target_id but NEVER sets event.mcp_tool. Grep for '.mcp_tool =' across server/core/src/*.cpp returns no matches — the dedicated AuditEvent.mcp_tool column (audit_store.hpp:29) is always empty.
**Verdict note:** [drift upheld] Independently confirmed the drift. The documented claim has two parts; only the first holds. (1) Action IS set: every MCP tool call audits with action "mcp."+tool_name (server/core/src/mcp_server.cpp:799). (2) The mcp_tool field is NEVER populated. The central audit chokepoint AuthRoutes::make_audit_event (server/core/src/auth_routes.cpp:442-459) and AuthRoutes::audit_log (server/core/src/auth_routes.cpp:466-487) set principal/role/action/result/source_ip/user_agent/session_id/target_type/target_id/detail but never event.mcp_tool. The MCP AuditFn signature (server/core/src/mcp_server.hpp:45-47) has no mcp_tool parameter; the call site routes tool_name into target_id and the literal string "mcp_tool" into target_type, NOT into the dedicated AuditEvent.mcp_tool field. The field is moreover not even a persisted column: the CREATE TABLE (server/core/src/audit_store.cpp:47-61) and 12-field INSERT (server/core/src/audit_store.cpp:91-94, binds 110-120) omit mcp_tool entirely. A repo-wide grep shows the only ".mcp_tool =" assignments are in hand-built test fixtures (tests/unit/server/test_mcp_server.cpp:319,475) that never exercise the real audit path; no production code sets it. So AuditEvent.mcp_tool (audit_store.hpp:29) is permanently empty and dead.
**Recommended record update:** CLAUDE.md edit

### `mcp-14` · MEDIUM · PARTIAL · doc-ahead-of-code
**Domain:** MCP & agentic-first (A1-A4) (Tier A)
**Source:** docs/agentic-first-principle.md A4: "Every failure response — REST, MCP, gRPC — includes code, message, correlation_id, retry_after_ms, remediation"
**Claim:** MCP error responses carry the full A4 envelope (correlation_id, retry_after_ms, remediation).
**Evidence:** Only the dex-perf MCP tools emit A4 data (correlation_id + nullable retry_after_ms + remediation) via the a4_data helper (mcp_server.cpp:1952-1980, #1463 gate). All other MCP error sites use plain error_response (mcp_jsonrpc.hpp:113-127) carrying only code+message (+optional opaque data). Code comment at mcp_server.cpp:1950-1951 explicitly tracks the rest-of-MCP backfill under #1470.
**Verdict note:** [drift upheld] Independently confirmed the drift. The A4 rule (docs/agentic-first-principle.md:60-77) states universally that every MCP failure response "includes ... correlation_id, retry_after_ms, remediation" plus two specialisations (kPermissionDenied names securable_type:operation; kApprovalRequired returns approval_id + status_url). The code does NOT satisfy this for the MCP layer at large. Only the 4 dex-perf tools carry the A4 envelope, via the a4_data lambda + make_correlation_id() (server/core/src/mcp_server.cpp:1952-2059), explicitly gated by #1463. All other ~80 MCP error sites use plain error_response(id, code, message) from mcp_jsonrpc.hpp:113-127, which emits only code+message (+ optional opaque data that is not the A4 envelope — e.g. the CA revoke site at mcp_server.cpp:2558-2561 emits {"audit_persisted":false}, not correlation_id/retry/remediation). The single kApprovalRequired site (mcp_server.cpp:834-840) returns only code+message — no approval_id or status_url specialisation; there is no kPermissionDenied site carrying the missing-permission specialisation at all. The developers themselves track the rest-of-MCP backfill in an in-code comment under #1470 (mcp_server.cpp:1946-1951). The auditor's cited evidence is all accurate.
**Recommended record update:** none

### `echo-19` · MEDIUM · DRIFTED · code-ahead-of-doc
**Domain:** Echo & scope-walking (Tier D)
**Source:** docs/asset-tagging-guide.md 'IT Service Owner Role': ITServiceOwner has 10 securable types with 5 operations each (50 permissions total), listing Device, Tag, InstructionDefinition, InstructionSet, InstructionExecution, Response, Scope, Schedule, Approval, ManagementGroup
**Claim:** ITServiceOwner is seeded with exactly the 10 listed securable types (50 permissions).
**Evidence:** server/core/src/rbac_store.cpp:401-435 seeds 16 securable types (Infrastructure, InstructionDefinition, InstructionSet, Execution, Schedule, Approval, Tag, AuditLog, Response, ManagementGroup, Policy, DeviceToken, SoftwareDeployment, License, FileRetrieval, GuaranteedState) x CRUD + an extra GuaranteedState:Push. Names differ (doc 'Device'/'Scope'/'InstructionExecution' vs code 'Infrastructure'/no Scope/'Execution').
**Verdict note:** [drift upheld] Drift independently confirmed. server/core/src/rbac_store.cpp:402-417 seeds ITServiceOwner across 16 securable types (Infrastructure, InstructionDefinition, InstructionSet, Execution, Schedule, Approval, Tag, AuditLog, Response, ManagementGroup, Policy, DeviceToken, SoftwareDeployment, License, FileRetrieval, GuaranteedState), each crossed with the 5-element crud_ops array {Read, Write, Execute, Delete, Approve} (rbac_store.cpp:167,421) = 80 permissions, plus an extra GuaranteedState:Push insert (rbac_store.cpp:435) = 81 total permissions. The doc (docs/asset-tagging-guide.md:296-300) claims exactly 10 securable types and 50 permissions, and its listed names diverge from the code: doc lists Device/Scope/InstructionExecution which do NOT exist in itso_types (code uses Infrastructure, Execution, has no Scope), and the doc entirely omits Policy, DeviceToken, SoftwareDeployment, License, FileRetrieval, GuaranteedState, AuditLog, and the GuaranteedState:Push grant. Both the count and the type names are wrong; code is ahead of doc.
**Recommended record update:** CLAUDE.md edit

### `agent-01` · LOW · DRIFTED · code-ahead-of-doc
**Domain:** Agent core, plugins, privilege, OS matrix (Tier C)
**Source:** CLAUDE.md line 198: "agents/plugins/   44 plugins"
**Claim:** The agent has 44 plugins under agents/plugins/.
**Evidence:** `ls -1d agents/plugins/*/` = 47 directories, all 47 wired via `subdir('agents/plugins/...')` in meson.build:347-393 (count = 47, no disk/meson mismatch). Even excluding the two demo/example plugins (example, chargen) the count is 45, still not 44.
**Verdict note:** [drift upheld] Independently confirmed the drift. agents/plugins/ contains 47 plugin directories, each with its own meson.build and a shared_module/shared_library target, and all 47 are wired into the build via subdir('agents/plugins/...') in meson.build lines 347-393 (verified count = 47, no disk-vs-meson mismatch). CLAUDE.md line 198 states "44 plugins". No counting interpretation satisfies 44: full count is 47, excluding the two demo/example plugins (example, chargen) gives 45. The documented number is a stale magic count, undercounting by 3.
**Recommended record update:** CLAUDE.md edit

### `agent-02` · LOW · DRIFTED · code-ahead-of-doc
**Domain:** Agent core, plugins, privilege, OS matrix (Tier D)
**Source:** docs/agent-privilege-model.md line 70: "Privilege matrix (all 217 instructions)"
**Claim:** The privilege matrix covers all 217 instructions.
**Evidence:** `grep -rh 'kind: InstructionDefinition' content/definitions/*.yaml | wc -l` = 224 (234 metadata.id lines, 230 action: entries across 68 definition files). Actual shipped instruction count is 224, not 217.
**Verdict note:** [drift upheld] Drift confirmed independently. docs/agent-privilege-model.md:70 heads the privilege matrix with "(all 217 instructions)". The actual shipped catalogue is 224 `kind: InstructionDefinition` documents across 68 files in content/definitions/*.yaml (`grep -rh 'kind: InstructionDefinition' content/definitions/*.yaml | wc -l` = 224; kinds breakdown also shows 10 InstructionSet + 5 TriggerTemplate + 1 Policy separately, so 224 is the clean instruction-definition figure). Even discounting the 3 demo definitions in t2_chaining_examples.yaml the count is 221 — still > 217. The "217" string appears exactly once in the whole repo and was written on 2026-05-06 (commit c951af55) and never updated as the catalogue grew. Documented 217 < actual 224 => code-ahead-of-doc, real drift.
**Recommended record update:** none

### `asp-01` · LOW · DRIFTED · doc-ahead-of-code
**Domain:** Aspirational accuracy (capability-map/roadmap/parity/SOC2) (Tier B)
**Source:** docs/capability-map.md:29-35
**Claim:** Progress at a Glance: New (Ph 8-16) = 2/44 done (5%), with Phase 8 having only 8.1 and 8.2 done.
**Evidence:** Roadmap line 85 shows 8.3 (Response Offloading) explicitly marked Done. offload_routes.cpp and offload_target_store.cpp exist and are wired in agent_service_impl.cpp:499-1239. Additionally, scope-walking features 15.B and 15.C are shipped in code (result_set_store.cpp 857 lines, /api/v1/result-sets routes in rest_api_v1.cpp:3135-3570, scope_engine.cpp:420-434 has from_result_set handler, result_sets_ui.cpp exists). Real count is at minimum 3/44 (8.1, 8.2, 8.3) and likely 5/44+ once 15.B and 15.C are counted. The '5%' headline materially understates delivered capability.
**Verdict note:** [drift upheld] Independently confirmed the drift. The capability-map "Progress at a Glance" headline (docs/capability-map.md:33) reads "New (Ph 8-16) = 2/44 done (5%)" and the claim asserts Phase 8 has only 8.1 and 8.2 done. This is contradicted by the SAME document's own detail entry: §20.7 Response Offloading (Phase 8.3, #255) is marked Done (:white_check_mark:) at docs/capability-map.md:848. That feature is genuinely shipped: offload_target_store.cpp (30k), offload_routes.cpp, route registration in server.cpp:8561-8563 (OffloadRoutes::register_routes, not dead code), and event fan-out wired in agent_service_impl.cpp:499-516 and :1221-1239. The roadmap independently marks 8.3 Done at docs/roadmap.md:85. So Phase 8 has at least 8.1+8.2+8.3 = 3 done, not 2. Additionally, scope-walking 15.B/15.C are shipped in code (result_set_store.cpp 36k, result_sets_ui.cpp, full REST CRUD at server/core/src/rest_api_v1.cpp:3135-3571, from_result_set: handler at scope_engine.cpp:420-440) yet the map still marks them "Not implemented" at docs/capability-map.md:1139 and :1143 — a corroborating doc-behind-code gap. I could find no code or reading that satisfies the "2/44 / only 8.1 and 8.2" claim. The 5% headline materially understates delivered capability and is self-contradictory with the document's own entries.
**Recommended record update:** none

### `asp-06` · LOW · DRIFTED · doc-ahead-of-code
**Domain:** Aspirational accuracy (capability-map/roadmap/parity/SOC2) (Tier B)
**Source:** docs/roadmap.md:157 (Phase 15 current status table)
**Claim:** Phase 15: Echo Dashboard and Scope Walking — 0 done, 8 open, 0% progress.
**Evidence:** Issues 15.B (result-set store + REST API) and 15.C (scope-engine from_result_set + dashboard) are shipped in code per result_set_store.cpp, rest_api_v1.cpp scope-walking routes, scope_engine.cpp, and result_sets_ui.cpp. Issue 15.G (operational hardening) is PARTIAL (prometheus metrics yuzu_result_sets_total etc in rest_api_v1.cpp:3122, pin/quota enforcement present). CHANGELOG lines 1194-1234 confirm the shipping. The Phase 15 table should show at minimum 2/8 done (15.B and 15.C), with 15.G as partial.
**Verdict note:** [drift upheld] I independently confirmed the drift. The roadmap Phase 15 status table (docs/roadmap.md:157) reads "0 done, 8 open, 0% progress" and the per-issue detail rows mark 15.B (line 1496), 15.C (line 1503) and 15.G (line 1535) all as "Open", but the code for these is fully shipped. (1) Issue 15.B — result-set store + REST: server/core/src/result_set_store.cpp is a real 857-line store (schema, lineage, TTL, pin, gc_sweep), and the complete REST surface exists in server/core/src/rest_api_v1.cpp: GET /api/v1/result-sets (3136), POST create (3162), from-inventory-query (3227), from-echo-query (3336), from-instruction-result (3377), GET /{id} (3488), /{id}/members (3501), /{id}/lineage (3532), /{id}/pin (3555), /{id}/unpin (3576), /{id}/re-eval (3428), DELETE /{id} (3596). (2) Issue 15.C — scope engine from_result_set: server/core/src/scope_engine.cpp:425 parses the from_result_set:<id-or-alias> short-circuit kind, and server/core/src/result_sets_ui.cpp renders the sidebar (render_result_sets_sidebar:46), lineage breadcrumb (line 90) and copyable from_result_set: scope token (line 116). (3) Issue 15.G — operational hardening is PARTIAL: gc_sweep wired in server/core/src/server.cpp:7881, per-owner quota/pin caps (kMaxPerOwner/kMaxPinsPerOwner in result_set_store.cpp), and Prometheus metrics yuzu_result_sets_total (rest_api_v1.cpp:3122), yuzu_result_sets_alive (server.cpp:7891), yuzu_result_set_quota_rejected (resolve_seconds histogram not found). Git history confirms shipping: commit 68427bba "feat(scope-walking): result-set store, REST, from_result_set: scope kind, dashboard UI" and 4f10a69b (PR 1202 review fixes). The table should show at minimum 2/8 done (15.B + 15.C) with 15.G partial. I could not refute the auditor.
**Recommended record update:** none

### `asp-09` · LOW · PARTIAL · doc-ahead-of-code
**Domain:** Aspirational accuracy (capability-map/roadmap/parity/SOC2) (Tier B)
**Source:** docs/enterprise-readiness-soc2-first-customer.md §3.5 Data Inventory table
**Claim:** Server-side data inventory lists all stores as 'server-side SQLite stores': audit.db, responses.db, guaranteed-state.db, ca.db, etc.
**Evidence:** The vast majority of named SQLite stores (audit_store.cpp, response_store.cpp, guaranteed_state_store.cpp, ca_store.cpp, policy_store.cpp, etc.) still use sqlite3 directly — confirmed by audit_store.cpp:5 includes sqlite3.h. However, OfflineEndpointStore is now born-on-Postgres (offline_endpoint_store.cpp:5 includes pg/pg_pool.hpp, line 58 takes PgPool&) and the server boot requires PostgreSQL per server.cpp:937-938. The data inventory table misses the new endpoint_state schema on Postgres and will need updating as each store migrates.
**Verdict note:** [drift upheld] Drift confirmed. The SOC2 data-inventory section at docs/enterprise-readiness-soc2-first-customer.md:144 is titled "Data Inventory — server-side SQLite stores" and the listed rows (audit.db, responses.db, guaranteed-state.db, ca.db) are individually accurate — those stores still use SQLite directly (audit_store.cpp:5, response_store.cpp:6, guaranteed_state_store.cpp:7, ca_store.cpp:5 all #include <sqlite3.h>; policy_store.hpp:3 / policy_store.cpp:62 use sqlite3_open_v2). However the section's framing and enumeration have drifted: (1) offline_endpoint_store.cpp:5-6,58 is born-on-Postgres — it takes a pg::PgPool& and writes the endpoint_state Postgres schema (offline_endpoint_store.cpp:20,92), the only one of 28 server stores not exclusively SQLite-backed, and the table omits it entirely; (2) the server now FAILS CLOSED without PostgreSQL (server.cpp:937-941 — "[PG] Refusing to start", "the server requires Postgres"), so the "SQLite stores" heading mis-frames the now-mandatory Postgres substrate; (3) a doc-wide grep for postgres/postgresql/endpoint_state/ADR-0006/substrate in the file returns zero hits, so the substrate migration is unacknowledged in this inventory.
**Recommended record update:** none

### `asp-10` · LOW · DRIFTED · doc-ahead-of-code
**Domain:** Aspirational accuracy (capability-map/roadmap/parity/SOC2) (Tier B)
**Source:** docs/capability-map.md:29-35 (Progress at a Glance) and §16 Policy and Compliance Engine
**Claim:** Advanced tier: 101/101 done (100%). Domain 16 'Policy & Compliance Engine' shows 8/8 done.
**Evidence:** §18.10 Two-Factor Authentication for Approvals is explicitly tagged T2 (Advanced tier) at capability-map.md:780 and marked :x: Not implemented. The domain summary table (line 57) shows '18. Auth & Authorization | 10 | 9 | 0 | 1' — 1 Not Started at T2. If Advanced tier is defined as T2 items, 18.10 being T2 and :x: means Advanced cannot be 100%. The 101/101 count either incorrectly excludes 18.10 from the Advanced count, or the T2 tag on 18.10 is wrong.
**Verdict note:** [drift upheld] Confirmed the drift is real — it is a self-contradiction within docs/capability-map.md. The legend at line 22 defines T2 = "Advanced". Section §18.10 "Two-Factor Authentication for Approvals" is tagged `T2` and marked `:x:` Not implemented at capability-map.md:780. The domain summary table corroborates this at line 57: "18. Auth & Authorization | 10 | 9 | 0 | 1" (1 Not Started). I independently counted the T2-tagged capability headings in the headline's scope (domains 1–24, before the separately-tracked Phase 8–16 §25+ rows): 100 total, 99 Done, exactly 1 Not Started — and that single Not-Started T2 item is §18.10 (verified via grep '^###.*`T2`' filtered to ':x:'). The "Progress at a Glance" headline at line 31 nonetheless asserts "Advanced 101/101 done (100%)". A tier containing an explicitly Not-Started member cannot be 100% done, and both the total (101 vs actual 100) and the done count (101 vs actual 99) are inconsistent with the body and the per-domain table. I also checked the code: TOTP/MFA scaffolding exists (server/core/src/totp.hpp, auth_db.cpp mfa_* operations) and a step_up_fn gates some sensitive REST routes (tokens, sessions, software-packages in rest_api_v1.cpp), but it is login/step-up MFA — not wired into the approval workflows that §18.10 specifically describes (no step_up_fn on approval routes in workflow_routes.cpp). So the doc's `:x:` on §18.10 is itself accurate; the only error is the 100% Advanced headline overstating completion. The drift is a documentation arithmetic/percentage overstatement (doc-ahead-of-code).
**Recommended record update:** none

### `ci-15` · LOW · DRIFTED · doc-ahead-of-code
**Domain:** Build / CI / release / deploy (Tier C)
**Source:** deploy/docker/docker-compose.yml:33-37 — inline comment 'The server does not consume this [YUZU_POSTGRES_DSN] yet — #1320 wires the --postgres-dsn / env plumbing — so today it is inert and the server still boots without Postgres.'
**Claim:** The dev docker-compose.yml server comment correctly describes the server's relationship to YUZU_POSTGRES_DSN.
**Evidence:** Comment at docker-compose.yml:33-37 says the server does not consume the DSN and 'still boots without Postgres', but server.cpp:938-991 now requires the DSN and fails closed (PR 3 landed, commit 09e0f4cd). The compose itself does provide a postgres service with depends_on service_healthy (:52-54, :58-85), so the stack actually works — only the comment is stale.
**Verdict note:** [drift upheld] Drift independently confirmed. The compose comment at deploy/docker/docker-compose.yml:33-37 claims the server 'does not consume this yet', that #1320 'wires' it (future tense), that the DSN 'is inert', that 'the server still boots without Postgres', and that 'the current binary would reject an unknown --postgres-dsn flag'. The code contradicts all of these: main.cpp:144-148 now defines the --postgres-dsn CLI option bound to YUZU_POSTGRES_DSN via ->envname() (so the flag is NOT rejected, and the help text itself says 'REQUIRED — the server fails closed without a reachable database'); server.cpp:937-941 sets startup_failed_ and logs '[PG] Refusing to start' when the DSN is empty; server.cpp:964-967 also fails closed if the DSN is unreachable. The DSN is therefore consumed and mandatory — not inert, and the server does NOT boot without Postgres. Git history confirms #1320 PR 3 has landed (HEAD 1f375f29 / e21c170d / 09e0f4cd), so the comment's anticipatory future-tense wording is now stale (doc-behind-code).
**Recommended record update:** CLAUDE.md edit

### `gw-08` · LOW · DRIFTED · contradiction
**Domain:** Gateway (Erlang) (Tier D)
**Source:** docs/user-manual/gateway.md:148-150: 'sends them in a single BatchHeartbeat RPC at a configurable interval (default: 10 seconds)'; config example shows {heartbeat_batch_interval_ms, 10000}.
**Claim:** The default heartbeat batching interval is 10 seconds (10000 ms).
**Evidence:** gateway/config/sys.config:20 sets {heartbeat_batch_interval_ms, 1000} (comment: '1s gives ~0.5s avg latency'); yuzu_gw_heartbeat_buffer.erl:62 code default is also 1000ms. The shipped default is 1s, not the documented 10s.
**Verdict note:** [drift upheld] Independently confirmed the drift. The doc at docs/user-manual/gateway.md:150 states the default heartbeat batching interval is 10 seconds and (per the cited example) shows {heartbeat_batch_interval_ms, 10000}. Every authoritative code/config default is 1000 ms (1 second): the code fallback in gateway/apps/yuzu_gw/src/yuzu_gw_heartbeat_buffer.erl:62 (application:get_env(yuzu_gw, heartbeat_batch_interval_ms, 1000)), the dev config gateway/config/sys.config:20 ({heartbeat_batch_interval_ms, 1000}, comment '1s gives ~0.5s avg latency'), and the prod config gateway/config/sys.config.prod:39 ({heartbeat_batch_interval_ms, 1000}). No code path yields a 10-second default. The doc is off by 10x in the contradicting direction.
**Recommended record update:** CLAUDE.md edit

### `gw-09` · LOW · DRIFTED · contradiction
**Domain:** Gateway (Erlang) (Tier D)
**Source:** docs/user-manual/gateway.md:226-261 config example: {mgmt_listen_port,50052}, {upstream_pool_size,16}.
**Claim:** Default config: mgmt_listen_port=50052, upstream_pool_size=16.
**Evidence:** gateway/config/sys.config:9 mgmt_listen_port=50063 (not 50052); :17 upstream_pool_size=32 (not 16). The same doc's TLS-posture table (line 284) correctly uses 50063, so the config-example block is internally stale.
**Verdict note:** [drift upheld] Drift independently confirmed. The doc config example at docs/user-manual/gateway.md:238 specifies {mgmt_listen_port, 50052} and :245 specifies {upstream_pool_size, 16}, but the actual default config gateway/config/sys.config:9 sets {mgmt_listen_port, 50063} and :17 sets {upstream_pool_size, 32}. The production config gateway/config/sys.config.prod:29,36 also uses 50063/32. The grpcbox listener block (sys.config:79) binds port 50063, and the same doc's TLS-posture table (gateway.md:284) correctly cites :50063 — so the config-example block is internally stale/contradictory. No in-code fallback default of 50052 or 16 exists; yuzu_gw_app.erl reads these keys straight from application env, which is sourced from these config files. Both documented values are wrong.
**Recommended record update:** CLAUDE.md edit

### `gw-19` · LOW · PARTIAL · code-ahead-of-doc
**Domain:** Gateway (Erlang) (Tier D)
**Source:** docs/user-manual/gateway.md:188-222: GatewayUpstream service RPC table lists exactly ProxyRegister, BatchHeartbeat, ProxyInventory, NotifyStreamStatus with the given message field numbers.
**Claim:** The GatewayUpstream RPC set and message field numbers match the proto.
**Evidence:** proto/yuzu/gateway/v1/gateway.proto field numbers match exactly (BatchHeartbeatRequest heartbeats=1/gateway_node=2 :47-52; StreamStatusNotification agent_id=1..gateway_node=5 :58-72). BUT a 5th RPC ForwardGuardianMessage (:43-44) exists in both the canonical proto and gateway_pb and is wired (yuzu_gw_upstream.erl:490, forward_guardian_message), absent from the doc's RPC table.
**Verdict note:** [drift upheld] Drift confirmed independently. The doc RPC table at docs/user-manual/gateway.md:188-193 lists only 4 RPCs (ProxyRegister, BatchHeartbeat, ProxyInventory, NotifyStreamStatus). The canonical proto at proto/yuzu/gateway/v1/gateway.proto:13-45 defines a 5th RPC, ForwardGuardianMessage (lines 43-44, request/response ForwardGuardianRequest/ForwardGuardianAck). This 5th RPC is fully wired in the gateway: gateway_pb.erl:6136 (service def) and :6149 (rpc names list) register it; yuzu_gw_upstream.erl:46/116-117 exports and implements forward_guardian_message/2, :490 maps its types, and :236 issues the do_rpc('ForwardGuardianMessage',...); yuzu_gw_guardian.erl:42 invokes it; dedicated tests exist (yuzu_gw_guardian_forward_tests.erl). The message field numbers cited (BatchHeartbeatRequest heartbeats=1/gateway_node=2 at proto:47-52; StreamStatusNotification agent_id=1..gateway_node=5 at proto:58-72) do match the doc exactly, so the only gap is the missing RPC-table row — code-ahead-of-doc, partial.
**Recommended record update:** CLAUDE.md edit

### `gw-22` · LOW · DRIFTED · doc-ahead-of-code
**Domain:** Gateway (Erlang) (Tier A)
**Source:** Intent-doc reference for this domain lists 'docs/adr/0002-*' as gateway intent; memory project_gateway_scalability_workstream cites docs/adrs/0002-gateway-scaling.md.
**Claim:** An ADR-0002 encodes the gateway scaling decision used to verify this domain.
**Evidence:** docs/adr/0002-reachability-graph-data-model.md is about the attack-path reachability graph, NOT the gateway. No docs/adrs/ directory exists; grep for gateway-scaling/0002-scal in docs/adr* returns nothing. The gateway-scaling ADR referenced by memory is absent on branch feat/postgres-f3-flip.
**Verdict note:** [drift upheld] Independently confirmed the drift on branch feat/postgres-f3-flip. (1) docs/adr/0002-reachability-graph-data-model.md:7-26 is about the attack-path reachability graph (host/service nodes, two edge classes), not the gateway. (2) The cited path docs/adrs/0002-gateway-scaling.md is absent: `git cat-file -e HEAD:docs/adrs/0002-gateway-scaling.md` fails with 'does not exist in HEAD', and docs/adrs/ does not exist in the working tree. (3) A real gateway-scaling ADR-0002 (commit e00dd8d8, '#376 ADR-0002 — gateway scaling toward WhatsApp/RabbitMQ tier') exists, but `git branch -a --contains e00dd8d8` shows it lives ONLY on feat/quic-transport, not on this branch. The memory project_gateway_scalability_workstream and the intent-doc reference therefore point at an ADR that is not present on this branch, while the docs/adr/0002 slot is occupied by an unrelated ADR. Could not refute.", "corrected_severity": "LOW", "refuted": false}
**Recommended record update:** ADR correction/superseding

### `instr-12` · LOW · DRIFTED · code-ahead-of-doc
**Domain:** Instruction Engine & executions ladder (Tier C)
**Source:** executions-history-ladder.md PR2 'Known coverage gap': lists MCP execute_instruction (mcp_server.cpp) among dispatch surfaces that produce execution_id='' responses
**Claim:** MCP execute_instruction produces execution_id='' responses (does not thread execution_id)
**Evidence:** Contradicted by code: mcp_server.cpp:2306-2366 now creates the execution row and threads execution_id into dispatch_fn (#1088). The ladder doc lines 26-29 still list 'MCP execute_instruction (mcp_server.cpp)' in the coverage-gap bullet list as if unwired.
**Verdict note:** [drift upheld] Independently confirmed the drift is real. The doc (docs/executions-history-ladder.md lines 24-29, "Known coverage gap") still lists "MCP execute_instruction (mcp_server.cpp)" among dispatch surfaces that produce execution_id='' responses falling back to the legacy timestamp-window join. The code contradicts this: server/core/src/mcp_server.cpp now creates the execution row via execution_tracker->create_execution() (line 2332, comment "#1088 — create the execution row BEFORE dispatch"), threads execution_id into dispatch_fn as its 6th argument (line 2366), updates set_agents_targeted (line 2423), and includes execution_id in both the success and no_agents_reached response payloads (lines 2401, 2433). CLAUDE.md's routed-concerns entry independently corroborates: "MCP execute_instruction as a tracked-execution producer (#1088)". So MCP execute_instruction is a fully wired tracked-execution producer, no longer a coverage gap, yet the ladder doc's gap list was not updated. This is a stale-doc drift, code-ahead-of-doc.
**Recommended record update:** CLAUDE.md edit

### `instr-20` · LOW · DRIFTED · code-ahead-of-doc
**Domain:** Instruction Engine & executions ladder (Tier B)
**Source:** Instruction-Engine.md sec 3 Current-State Assessment table: InstructionStore/ExecutionTracker/ApprovalManager/ScheduleEngine marked 'Stub' (DDL + signatures only, no business logic)
**Claim:** InstructionStore, ExecutionTracker, ApprovalManager, and ScheduleEngine are stubs with no business logic
**Evidence:** All four are full implementations: instruction_store.cpp (1025 LOC, CRUD+import/export+signature verify), execution_tracker.cpp (758 LOC, create/query/upsert/refresh_counts/rerun/cancel + SSE publish), approval_manager.cpp (309 LOC, submit/approve/reject/pending_count with ownership rule), schedule_engine.cpp (358 LOC, frequency validation/evaluate_due/advance). The same doc's sec 1 ('Verified from implementation') and sec 3 footer ('Instruction engine fully implemented') already contradict the 'Stub' table.
**Verdict note:** [drift upheld] Drift independently confirmed. The doc's section 3 "Current-State Assessment" table at HEAD (docs/Instruction-Engine.md:52-55) marks InstructionStore, ExecutionTracker, ApprovalManager, and ScheduleEngine all as "Stub" with notes saying only DDL + signatures defined, "no business logic" (also stated at line 40). The actual code contradicts this: server/core/src/instruction_store.cpp (1025 LOC) has full CRUD + JSON import/export + signature verification (import_definition_json_impl, create/update/delete_definition, export_definition_json); execution_tracker.cpp (758 LOC) has create_execution INSERT, query/summary, update_agent_status with ON CONFLICT DO UPDATE upsert + SSE publish (lines 320-380), get_children/rerun; approval_manager.cpp (309 LOC) implements submit/query/approve/reject/pending_count with the ownership rule "reviewer must not be the submitter" (approval_manager.cpp:274-275); schedule_engine.cpp (358 LOC) has is_valid_frequency, compute_initial_next_execution, evaluate_due() (line 272), advance_schedule() (line 302), full CRUD. The code was committed Apr-Jun 2026 (predating the audit). The doc is even self-contradictory — line 11 ("Verified from implementation") and line 62 ("Instruction engine fully implemented") refute its own "Stub" table. The "Stub" status labels are stale; this is code-ahead-of-doc drift.
**Recommended record update:** CLAUDE.md edit

### `instr-21` · LOW · DRIFTED · doc-ahead-of-code
**Domain:** Instruction Engine & executions ladder (Tier B)
**Source:** Instruction-Engine.md lines 62 & 1453: '150/184 capabilities done (82%). All 7 phases complete (72/72 issues). Instruction engine fully implemented.'
**Claim:** Overall progress is 150/184 capabilities (82%)
**Evidence:** docs/capability-map.md:30-35 reports a different ledger: Foundation 33/33, Advanced 101/101, Future 33/50, New(Ph8-16) 2/44, Overall 169/228 done (74%). The 150/184 (82%) figure in Instruction-Engine.md does not match the authoritative capability-map, and CLAUDE.md itself warns the headline figure is overstated.
**Verdict note:** [drift upheld] Drift independently confirmed. docs/Instruction-Engine.md:62 states 'Overall progress: 150/184 capabilities done (82%). All 7 phases complete (72/72 issues)' and line 1453 cites 'docs/capability-map.md | 184 capabilities, 150 done (82%)' as its authoritative source. But the cited source no longer says that: docs/capability-map.md:35 reports 'Overall 169/228 done (74%)' and the TOTAL row at docs/capability-map.md:71 confirms 228 total / 169 done / 5 partial / 54 not-started. Git history proves capability-map.md once contained 'Overall ... 150/184 done (82%)' (recovered via `git log -S "150/184" -- docs/capability-map.md`) but was later corrected (commit db8b8d6c 'sync headline counters with table totals' plus the Phase 8-16 capability additions to 228). The 184/150 figure was never re-synced in Instruction-Engine.md, so it is stale and self-contradicts its own named source. CLAUDE.md:85 independently warns the capability-map headline is overstated, reinforcing that progress figures here are not load-bearing contracts. I could not find any current artifact that satisfies the 184/82% claim.
**Recommended record update:** CLAUDE.md edit

### `mcp-05` · LOW · DRIFTED · code-ahead-of-doc
**Domain:** MCP & agentic-first (A1-A4) (Tier C)
**Source:** docs/mcp-server.md Phase 1 (Implemented): "26 read-only tools" + "1 write/execute tool" (27 total)
**Claim:** Phase 1 ships 26 read-only tools plus 1 write/execute tool (execute_instruction).
**Evidence:** kTools array registers 35 tools (kToolCount = sizeof; unique-name count = 35 via grep over mcp_server.cpp:189-393). The doc's enumerated Phase-1 list stops at the 26 DEX-read set and execute_instruction; code additionally has list_issued_certs, revoke_certificate, get_dex_perf_fleet/cohorts/cohort_diff, list_dex_perf_devices, get_network_fleet, list_network_devices, get_guardian_schemas.
**Verdict note:** [drift upheld] Drift independently confirmed. docs/mcp-server.md:23-34 "Phase 1 (Implemented)" claims exactly 27 implemented tools: line 25 enumerates 26 read-only tools by name (verified: 26 backtick-quoted names) and line 27 names 1 write/execute tool (execute_instruction); Phase 2 (line 34) lists only the 5 still-planned write tools (set_tag, delete_tag, approve_request, reject_request, quarantine_device). The code's kTools array (server/core/src/mcp_server.cpp:189-393) registers 35 tools — kToolCount = sizeof(kTools)/sizeof at line 395 = 35, and my per-name enumeration yields 35 unique names. The 8 tools present in code but absent from the doc entirely are: get_dex_perf_fleet (291), get_dex_perf_cohorts (299), get_dex_perf_cohort_diff (306), list_dex_perf_devices (320), get_network_fleet (334), list_network_devices (346), list_issued_certs (377), revoke_certificate (385). All are security-mapped and dispatchable (mcp_server.cpp:446-451), exposed via the tools/list loop (lines 596-600), and none appear anywhere in docs/mcp-server.md. The doc undercounts implemented tools by 8 (~30%).
**Recommended record update:** CLAUDE.md edit

### `mcp-06` · LOW · DRIFTED · code-ahead-of-doc
**Domain:** MCP & agentic-first (A1-A4) (Tier A)
**Source:** docs/agentic-first-principle.md A2 (Discovery): "MCP tools/list enumerates 23 MCP tools"
**Claim:** MCP tools/list enumerates 23 MCP tools.
**Evidence:** tools/list iterates kToolCount = 35 (mcp_server.cpp:596-601, kTools 35 entries). A2's "23 MCP tools" is stale.
**Verdict note:** [drift upheld] Drift confirmed independently. docs/agentic-first-principle.md:35 states "MCP tools/list enumerates 23 MCP tools". The actual handler at server/core/src/mcp_server.cpp:594-605 iterates `for (int i = 0; i < kToolCount; ++i)` over kTools with no filtering. kToolCount = sizeof(kTools)/sizeof(kTools[0]) (mcp_server.cpp:395), and the kTools array (mcp_server.cpp:189-393) contains exactly 35 entries — verified by both an automated name count and by listing every name (list_agents ... revoke_certificate, including the DEX, network-quality, and internal-CA tool families). The documented 23 is stale by 12 tools. I attempted to find code satisfying the 23-tool claim (e.g. a read-only-mode subset that hides write tools from tools/list) but none exists — tools/list is unconditional; read-only gating happens only at tools/call.
**Recommended record update:** CLAUDE.md edit

### `mcp-07` · LOW · PARTIAL · code-ahead-of-doc
**Domain:** MCP & agentic-first (A1-A4) (Tier D)
**Source:** docs/user-manual/mcp.md Available Tools table (34 rows) + caveat "the authoritative tool/resource/prompt list is the server's own tools/list ... counts in this document are illustrative"
**Claim:** The user-manual tool table mirrors the server's tools/list; the manual explicitly defers to the live tools/list as authoritative.
**Evidence:** Manual table has 34 numbered rows (mcp.md rows 1-34); code registers 35 tools. The manual is missing get_guardian_schemas (registered at mcp_server.cpp:260). The manual carries the explicit "counts are illustrative / tools/list authoritative" caveat (mcp.md:46-48), so it is honest about drift.
**Verdict note:** [drift upheld] Independently confirmed the drift. The kTools array in server/core/src/mcp_server.cpp registers 35 tools (counted from the struct entries between lines 189-393; sizeof guard at line 395). The user-manual table in docs/user-manual/mcp.md has only 34 numbered rows (lines 251-284). A set diff shows exactly one tool present in code but absent from the manual table: get_guardian_schemas, registered at mcp_server.cpp:260. No tool appears in the doc that is missing from code, so this is purely code-ahead-of-doc by one entry. The documented claim is two-part: (1) the table "mirrors" tools/list and (2) the manual "explicitly defers to the live tools/list as authoritative." Part (2) is fully satisfied — the authoritative-tools/list caveat exists verbatim at mcp.md:46-48 ("counts in this document are illustrative") and is reaffirmed at mcp.md:244. Part (1) is violated by exactly one missing row. Because the manual is explicit and honest that the static table is illustrative and tools/list is the source of truth, the impact is confined to a human reading the static table; an agentic worker following the doc's own guidance (use live tools/list) is unaffected.
**Recommended record update:** CLAUDE.md edit

### `mcp-08` · LOW · DRIFTED · code-ahead-of-doc
**Domain:** MCP & agentic-first (A1-A4) (Tier C)
**Source:** docs/mcp-server.md Phase 1: "3 resources: yuzu://server/health, yuzu://compliance/fleet, yuzu://audit/recent"
**Claim:** MCP exposes exactly 3 resources.
**Evidence:** kResources has 4 entries (mcp_server.cpp:474-481): the three named plus yuzu://guardian/schemas. resources/read handles the 4th at mcp_server.cpp:757-772.
**Verdict note:** [drift upheld] Drift confirmed independently. docs/mcp-server.md:28 states "3 resources: yuzu://server/health, yuzu://compliance/fleet, yuzu://audit/recent". But kResources in server/core/src/mcp_server.cpp:474-481 defines 4 entries: the three named PLUS yuzu://guardian/schemas (line 479-480). kResourceCount = sizeof(kResources)/sizeof(kResources[0]) (line 483) therefore equals 4, and resources/list enumerates all 4 (lines 612-615). resources/read also handles the 4th URI at mcp_server.cpp:757. Notably the doc DOES list the corresponding tool get_guardian_schemas (docs/mcp-server.md:25) but omits the guardian schemas resource at line 28, so this is an internal doc inconsistency too. Could not find any code that satisfies the "exactly 3" claim — the array unambiguously has 4. Direction is code-ahead-of-doc, as the auditor stated. Severity LOW: a one-off doc undercount of a read-only resource list; no functional, contract, or security impact, just a discoverability/accuracy gap.
**Recommended record update:** CLAUDE.md edit

### `pki-16` · LOW · PARTIAL · code-ahead-of-doc
**Domain:** PKI / CA / mTLS / secrets-at-rest (Tier C)
**Source:** CLAUDE.md PKI routed concern stops at PR5d; pki-architecture.md roadmap marks PR6 subordinate-CA "in review" — but full code is wired
**Claim:** CLAUDE.md PKI routed concern describes the ladder only through PR5d; the subordinate-CA (PR6) surface (root-csr export, import-chain validation, dashboard import panel, issuer_key_id) is fully built and wired.
**Evidence:** CLAUDE.md PKI concern: grep PR6/subordinate/root-csr/import-chain = 0 hits; yet server.cpp:3131 export_ca_csr, :3175 import_subordinate_chain, ca_routes.cpp:474/:506 routes, :142 dashboard import form, ca_store.cpp:235 issuer_key_id (migration v5) all present. pki-architecture.md DOES cover PR6 (marked "in review").
**Verdict note:** [drift upheld] Drift independently confirmed. The CLAUDE.md PKI routed concern (CLAUDE.md:238) narrates the PKI PR ladder inline (PR2, PR3, PR4, PR4b, PR5, PR5b, PR5c, PR5d) and stops at PR5d — grep against that concern for PR6/subordinate/root-csr/import-chain/issuer_key_id returns 0 hits. Yet the PR6 subordinate-CA surface is fully built and wired: server.cpp:3131 export_ca_csr() and :3174 import_subordinate_chain() are real implementations wired into route registration at server.cpp:8581/:8584; ca_routes.cpp:474 GET /api/v1/ca/root-csr and :506 POST /api/v1/ca/import-chain are registered, :142 has the dashboard hx-post import <form>, :707 the dashboard /api/settings/ca/import-chain wrapper; ca_store.cpp:235 adds issuer_key_id via migration v5 plus :101-104 CaMode::Subordinate serialization and migration v4 chain_pem; and the validation engine in x509_ca.cpp (cert_matches_key:948, cert_is_ca:970, verify_chain_to_bundle:983, issuer_key_id:779) holds real OpenSSL implementations, not stubs. The routed doc docs/pki-architecture.md DOES document PR6 fully (section at :308, surfaces at :372, roadmap row at :445 marked 'in review'). So this is code-ahead-of-CLAUDE.md, with the deeper routed doc accurate — exactly the auditor's PARTIAL characterization.
**Recommended record update:** CLAUDE.md edit

### `pki-22` · LOW · PARTIAL · doc-ahead-of-code
**Domain:** PKI / CA / mTLS / secrets-at-rest (Tier D)
**Source:** ADR-0010 Consequences + docs/user-manual/server-admin.md "Key management": KEK lifecycle audit verbs (kek.generated/rotated/retired), secret_decrypt_failures metric, --accept-voided-secrets break-glass flag
**Claim:** KEK lifecycle audit events + the yuzu_server_secret_decrypt_failures metric are wired into the running server, and a break-glass voided-secrets boot flag exists.
**Evidence:** secret_codec.hpp:254-274 defines AuditHook (unset=no-op) + decrypt_failure_counts seam, but server.cpp wires neither (grep kek.generated/secret.decrypt_failure/yuzu_server_secret_decrypt_failures = 0 hits); absent: --accept-voided-secrets across server/. server-admin.md:902/:906 honestly says rotation surface + voided-secrets flag "ship with the first secret-bearing store migration".
**Verdict note:** [drift upheld] Independently confirmed the drift. The codec MECHANISM exists and is tested — secret_codec.cpp emits kek.generated (:672), kek.rotated (:829), kek.retired (:1046), secret.decrypt_failure (:325) via emit_audit, and decrypt_failure_counts() (secret_codec.hpp:273-274) backs yuzu_server_secret_decrypt_failures_total. BUT it is NOT wired into the running server: SecretCodec is constructed only at secret_codec.cpp:264 invoked solely by tests/unit/server/test_secret_codec.cpp; grep across server/core/src/ shows no SecretCodec construction in server.cpp or any production path (only comments in aes_gcm.hpp and offline_endpoint_store.hpp, the latter stating "No secrets — plain columns, no SecretCodec"). The header itself states the wiring is pending: secret_codec.hpp:256-257 ("Wiring to the AuditStore happens where the codec is constructed (the per-store migration PRs); unset = no-op") and :270-272 (register the metric "when the wiring PR exposes it"; "the metrics endpoint reads this when the codec is wired into ServerImpl"). The --accept-voided-secrets flag exists nowhere in server/ or agents/ C++ source — only in docs/adr/0010 (:283, which itself says "named at implementation, e.g. --accept-voided-secrets") and server-admin.md:906. The user-manual is honest about deferral (server-admin.md:902 #1341, :904 "once the codec is wired into a serving store", :906 "ships with the first secret-bearing store migration"); however ADR-0010 Consequences (:210-214) presents the audit verbs/metric as active "audit-taxonomy entries from the first implementation PR" without the same not-yet-wired caveat — the doc-ahead-of-code surface the claim targets.
**Recommended record update:** none

### `policy-24` · LOW · PARTIAL · doc-ahead-of-code
**Domain:** Policy / compliance evaluation (Tier D)
**Source:** user-manual policy-engine.md:247: invalidation resets statuses to 'pending'
**Claim:** Invalidation resets all agent statuses to 'pending'.
**Evidence:** update_agent_status only accepts compliant/non_compliant/unknown/fixing/error and rejects any other status (policy_store.cpp:1016-1018); 'pending' is not a valid status. The status table (policy-engine.md:171-179) itself never lists 'pending' — it lists 'unknown' as 'Not yet evaluated, status invalidated'. The 'pending' wording in the Cache Invalidation prose is inconsistent with the rest of the doc and the enum.
**Verdict note:** [drift upheld] Drift confirmed. policy-engine.md:247 (and :249 by reference) states per-policy/fleet invalidation "Reset all agent statuses to `pending`". The actual code does NOT use 'pending': PolicyStore::invalidate_policy runs `UPDATE policy_status SET status = 'unknown' WHERE policy_id = ?` (server/core/src/policy_store.cpp:1260) and invalidate_all_policies runs `UPDATE policy_status SET status = 'unknown'` (policy_store.cpp:1288). 'pending' is not a member of the valid status enum either — update_agent_status only accepts compliant/non_compliant/unknown/fixing/error and rejects anything else (policy_store.cpp:1016-1018). The doc is internally inconsistent too: its own status table (policy-engine.md:177) lists `unknown` = 'Not yet evaluated, status invalidated', which matches the code; only the Cache Invalidation prose says 'pending'. So the documented claim is not satisfied by code.
**Recommended record update:** CLAUDE.md edit

### `echo-14` · LOW · DRIFTED · code-ahead-of-doc
**Domain:** Echo & scope-walking (Tier C)
**Source:** docs/echo-dashboard.md §9 + scope-walking-design.md §11: PR-B (result-set store + REST), PR-C (scope chip/sidebar/breadcrumb), PR-D (Echo SQL frame scope-walking-aware) all marked 'Pending'
**Claim:** PR-B, PR-C and PR-D are pending/not yet built.
**Evidence:** All shipped: result-set REST routes rest_api_v1.cpp:3135-3608 (PR-B); sidebar/detail/lineage/pin fragments server.cpp:5870-5945 + result_sets_ui.cpp (PR-C); Echo-page SQL frame is scope-walking-aware echo_page_ui.cpp:300-305 scope chip + :470 POST /api/v1/result-sets/from-echo-query + pollSet materialisation (PR-D). The doc status tables still say 'Pending'.
**Verdict note:** [drift upheld] Drift confirmed independently. docs/echo-dashboard.md §9 lines 249-251 still mark PR-B/PR-C/PR-D as "Pending", but all three are shipped and committed in the live tree. PR-B: result_set_store.{cpp,hpp} exists and REST routes GET/POST /api/v1/result-sets, /from-inventory-query, /from-echo-query are wired (rest_api_v1.cpp:3135-3330). PR-C: result_sets_ui.cpp renders sidebar/detail/lineage(breadcrumb)/pin fragments wired in server.cpp:5869-6011 (result_set_store_->lineage at :5913). PR-D: echo_page_ui.cpp:300-478 has the scope chip (echo-sql-scope), POST /api/v1/result-sets/from-echo-query, and pollSet materialization polling — and commit e7b47ca3 is literally "feat(scope-walking): ... Echo SQL frame (PR-D)". The doc is also self-inconsistent: scope-walking-design.md §11 line 336 already marks PR-E as "Shipped", which sequentially depends on PR-B/C/D, yet echo-dashboard.md §9 still says those three are Pending. Direction is code-ahead-of-doc.
**Recommended record update:** CLAUDE.md edit

### `viz-24` · LOW · DRIFTED · code-ahead-of-doc
**Domain:** Fleet visualization (Tier D)
**Source:** fleet-viz-invariants.md §Process-layer PR7 — Soft cap 1000 process dots per cube; bundle size cap <80 KB
**Claim:** The renderer bundle stays under the 80 KB soft cap stated in the PR 7 process-layer invariant
**Evidence:** yuzu-viz.js is 87898 bytes (~85.8 KB), above the PR-7 '<80 KB' cap; later PRs (8/9/12) added listener/talking sockets + tube wires. The renderer doc header itself notes it 'crossed the MSVC 16,380-byte raw-string literal limit at PR 6'. No active test pins an 80 KB ceiling.
**Verdict note:** [drift upheld] Independently confirmed the drift. docs/fleet-viz-invariants.md:179 states "Soft cap. 1000 process dots per cube; bundle size cap <80 KB." The actual renderer bundle server/core/static/yuzu-viz.js is 87898 bytes (~85.8 KB), which exceeds the 81920-byte (80 KB) threshold by ~5978 bytes (~7%). At PR 7 (commit 98576dbf) the same file was only 48530 bytes (well under cap), and later PRs 8/9/12 (commits cb80a285 localhost edges, ba7e34a8 listener/talking sockets, d597803a three-tier layout + tube wires) grew it past 80 KB. Git history (-S "bundle size cap") shows the cap line was added at PR 7 and never revised. There is no active enforcement: no test pins the ceiling, and server/core/scripts/embed_js.py only guards the unrelated MSVC 14,000-byte raw-string chunk limit (CHUNK_SIZE = 14_000), not a total-bundle cap. This is genuine code-ahead-of-doc drift.
**Recommended record update:** CLAUDE.md edit

### `vuln-02` · LOW · PARTIAL · doc-ahead-of-code
**Domain:** Vuln / reachability engine (Tier A)
**Source:** ADR-0002 (accepted): two node tiers (host + service nodes), two edge classes (network reachability + local-IPC), no identity/account nodes.
**Claim:** Code models host nodes, service nodes (host,port,proto,process), network edges, and local-IPC edges per the data model.
**Evidence:** fleet_topology_types.hpp models machines/processes/connections for the viz renderer; the design doc itself (vuln-scan-engine-design.md:43-45 considered-and-rejected) explicitly says the renderer's MachineNode/ProcessNode are a 60s-TTL rendering projection and the analytic host/service/local-IPC vocabulary is 'new vocabulary computed on a schedule' — not yet built. No service-node or local-IPC edge type exists in code (grep). The ADR data model is accepted intent, not implemented.
**Verdict note:** [drift upheld] I independently confirmed the drift; I could not find code satisfying the claim. The claim asserts the code "models host nodes, service nodes (host,port,proto,process), network edges, and local-IPC edges per the data model." The only topology code is server/core/src/fleet_topology_types.hpp, which models MachineNode, ProcessNode, ConnectionEdge (EdgeScope Local/InternalFleet/External), and ListenerSocket — a 60s-TTL viz renderer projection (fleet_topology_store.hpp:13,99-111 "60-second TTL ... render"). There is NO ServiceNode type keyed on (host, listening port, protocol, owning process), no analytic host node, and no network-reachability-edge (src host→dst service) or local-IPC-edge (service→service) type. A codebase-wide grep (server/, agents/, sdk/, proto/, and the .claude worktrees, excluding build dirs) for ServiceNode/service_node/host_node/local_ipc/ipc_edge/reachability_edge/trust_zone/attack_path/chokepoint found zero implementations (the only "crown jewel"/"chokepoint" hits are the unrelated CA private-key seam and generic code comments). The vuln_scan plugin (agents/plugins/vuln_scan/src/) contains no graph model. ADR-0002 itself (docs/adr/0002-reachability-graph-data-model.md:42-45, "Considered and rejected") explicitly says reusing the renderer's MachineNode/ProcessNode was rejected and that the derived analytic layer "is new vocabulary computed on a schedule" — i.e., not yet built; the parent design doc (vuln-scan-engine-design.md §3, "North Star — for review", graph layer = Phases 6-8) confirms the model is future work. The auditor's PARTIAL / doc-ahead-of-code verdict is accurate.
**Recommended record update:** none

### `vuln-03` · LOW · DRIFTED · doc-ahead-of-code
**Domain:** Vuln / reachability engine (Tier A)
**Source:** ADR-0003 (accepted): move connection capture from poll to event-driven (eBPF/ETW/NetworkExtension), edge-aggregated, federated agent SQLite edge warehouse; raw firehose never reaches server.
**Claim:** Flow telemetry is event-driven and edge-aggregated into a federated agent SQLite warehouse.
**Evidence:** Capture is still poll-based: design doc 4.1 table marks per-connection capture 'Have (observed); poll-based — misses short-lived flows' and 4.2 'Move to event capture' as Add. No eBPF/ETW-flow/NetworkExtension flow collector exists for the reachability graph (grep for the event-capture flow path returns DEX/Echo collectors, not a flow-summary edge warehouse). ADR is accepted; code unchanged from the poll PoC.
**Verdict note:** [drift upheld] Independently confirmed: no event-driven flow capture exists for the reachability/vuln-scan graph; capture is still poll-based, matching the PoC the ADR set out to replace. Evidence in code: agents/plugins/echo/src/echo_network_collector.cpp uses GetExtendedTcpTable (lines 713/719/747/753), /proc/net/tcp + /proc/net/tcp6 (lines 356-357), and libproc (line 54), and explicitly returns empty for Windows quality with a note that Microsoft-Windows-TCPIP ETW is kPlanned (lines 858-860). The only ETW present is PROCESS capture (agents/plugins/echo/src/echo_proc_etw.hpp — Microsoft-Windows-Kernel-Process, not network flow). No eBPF/tracepoint flow collector (the only tcp_connect hits are the SQL helper EchoDatabase::query_recent_tcp_connections, echo_db.cpp:661) and no NetworkExtension/.mm files exist. The graph is fed by fleet_snapshot.v1 built from the live /proc/net/tcp snapshot merged with the Echo warehouse (agents/plugins/echo/src/echo_fleet_snapshot.hpp:81-90) — a poll, not an event firehose, and no (src,dst,port,proto,first_seen,last_seen,count) flow-summary edge warehouse. ADR-0003 (docs/adr/0003-telemetry-capture-model.md, status: accepted) states the flow telemetry IS event-driven, edge-aggregated, and federated; the design doc's own §4.1/§4.2 honestly mark 'Event-driven flow capture' as Add. So the ADR is doc-ahead-of-code drift, as the auditor found.
**Recommended record update:** none

### `vuln-04` · LOW · DRIFTED · doc-ahead-of-code
**Domain:** Vuln / reachability engine (Tier A)
**Source:** ADR-0004 (accepted, generalised by ADR-0006): the derived scored graph + cross-store scoring join + pgvector live in server-side PostgreSQL; agent SQLite stays the federated edge warehouse.
**Claim:** The derived scored reachability graph is persisted in server-side PostgreSQL (with pgvector for identity matching).
**Evidence:** No persisted reachability/scored-graph store exists in Postgres or anywhere: grep for reachability/graph/edge/attack_path store returns NONE. The observed graph (FleetTopologyStore) is in-memory only (60s TTL, no history — fleet_topology_store.hpp:13-26). The one existing vuln store, NvdDatabase, is SQLite (nvd_db.hpp:3,64; nvd_db.cpp:213 sqlite3_open_v2, :256 CREATE TABLE cve) and pre-dates the ADR. No pgvector usage anywhere.
**Verdict note:** [drift upheld] I independently confirm the drift is real. The documented claim — a derived, scored reachability graph persisted in server-side PostgreSQL with pgvector for identity matching — is NOT implemented in code. Evidence I verified myself: (1) The server pg/ store directory (server/core/src/pg/) contains only the substrate (pg_raii.hpp, pg_pool.cpp, pg_migration_runner.cpp, secret_codec) and NO graph/scored-graph/reachability store. (2) The only Postgres-backed store in the entire server is offline_endpoint_store (offline_endpoint_store.hpp:46,69 take a PgPool&) — that is the "last-known endpoint state" half of ADR-0004, not the scored graph. (3) fleet_topology_store.cpp has NO persistence at all (grep for sqlite3_open/PgPool/INSERT INTO/CREATE TABLE returns nothing); the header confirms it is a pure in-memory aggregator with a 60s-TTL cache holding all state in std::unordered_map members (fleet_topology_store.hpp:323-369). (4) The one existing vuln store, NvdDatabase, is SQLite (raw sqlite3* at nvd_db.hpp:3,64) and is a CVE-feed cache, not a scored reachability graph. (5) No pgvector usage in any source file — it appears only in deploy/CI files where the Postgres Docker image is built WITH the extension available (docker-compose.reference.yml, release.yml), but nothing in the application code uses it. (6) No scoring/attack-path/chokepoint/adjacency logic exists for the vuln graph. The design doc itself confirms this is doc-ahead-of-code: docs/vuln-scan-engine-design.md marks "Persisted reachability graph + history" as "Add" (line 277), lists pgvector identity matching as Phase 4 and "Topology ingest & persistence" as Phase 6 (lines 452,459-460), and notes only Phase 0 (Spike #1206) is DONE (line 440). docs/plans/threat-graph-roadmap.md is labeled "Internal planning draft." The claim under review is decided-but-unbuilt target architecture.", "refuted": false
**Recommended record update:** none

### `vuln-05` · LOW · DRIFTED · doc-ahead-of-code
**Domain:** Vuln / reachability engine (Tier A)
**Source:** ADR-0005 (accepted): attack-path scoring via depth-bounded max-probability paths (Dijkstra + Yen k-shortest), per-finding attack-path score replaces raw CVSS as default ranking.
**Claim:** Findings are ranked by a depth-bounded max-probability attack-path score (Dijkstra/Yen), replacing raw CVSS.
**Evidence:** No attack-path scoring code exists: grep -E 'dijkstra|yen.*shortest|attack.path.scor|traversab' across agents/ server/ proto/ (excluding tests/worktrees) returns NONE. Findings, where produced at all (NvdDatabase::match_inventory, nvd_db.cpp:358), carry only a bare severity label (CveMatch has no score/path field, nvd_db.hpp:31-39). ADR algorithm decisions are 'accepted, substrate-independent' (ADR-0005:52-59) but explicitly unbuilt (design doc Phase 7).
**Verdict note:** [drift upheld] Independently confirmed: no attack-path scoring code exists. Grep for dijkstra|yen|k-shortest|attack_path|traversab|max_prob across agents/server/proto/sdk (excluding tests/build dirs) returns nothing relevant; the only chokepoint/crown-jewel hits are unrelated (server/core/src/key_provider.hpp:6, guardian_ingest.hpp:37, device_routes.cpp:344 — CA key + audit chokepoints, not graph scoring). The finding struct CveMatch (server/core/src/nvd_db.hpp:31-39) has no score/path field — only a bare severity label. The producer NvdDatabase::match_inventory (server/core/src/nvd_db.cpp:357) just runs a LIKE SELECT + version compare with no ranking; the vuln_scan plugin has zero scoring logic (its only std::sort at agents/plugins/vuln_scan/src/vuln_scan_plugin.cpp:199 sorts AppInfo). The capability is genuinely unbuilt. CAVEAT lowering severity: the source docs are self-honest, not overclaiming. ADR-0005 (docs/adr/0005-attack-path-and-chokepoint-scoring.md:52-59) marks only the *algorithm* decisions 'accepted' and explicitly ties the scoring join to a not-yet-relied-on substrate; the design doc lists it as 'Phase 7' (docs/vuln-scan-engine-design.md:464-468) and states 'until Phase 7, no attack-path claims' (line 486-487). So the gap is roadmap/ADR-vs-implementation on an explicitly-accepted-but-unbuilt feature whose docs already flag the unbuilt status, rather than a doc falsely asserting a shipped present-tense capability.
**Recommended record update:** none

### `vuln-06` · LOW · DRIFTED · doc-ahead-of-code
**Domain:** Vuln / reachability engine (Tier A)
**Source:** ADR-0005: chokepoints via path-set frequency over top-k paths; segmentation via cost-weighted min-cut; multi-jewel via MST/Kruskal (Phase 8).
**Claim:** Chokepoint (path-set frequency) and segmentation (cost-weighted min-cut) recommendations are computed.
**Evidence:** grep -E 'chokepoint|min.cut|mincut|steiner|kruskal' across agents/ server/ proto/ (excluding tests/worktrees) returns NONE. The only 'chokepoint'/'crown jewel' string hits are PKI CA-key comments (ca_store.hpp:9, key_provider.hpp:6, server.cpp:219,2915) — unrelated. Phase 8, unbuilt.
**Verdict note:** [drift upheld] Independently confirmed the drift. ADR-0005 (docs/adr/0005-attack-path-and-chokepoint-scoring.md:26-31) documents chokepoints via path-set frequency over top-k paths, segmentation via cost-weighted min-cut, and multi-jewel via MST/Kruskal "(later, Phase 8)". No implementation exists anywhere in agents/, server/, proto/, sdk/: zero hits for min-cut/mincut/steiner/kruskal; every 'chokepoint' string is an unrelated code-flow single-entry-point pattern; every 'crown jewel' string is a PKI CA-key comment (ca_store.hpp, key_provider.hpp, server.cpp:219/2915). None of the specified algorithms (Dijkstra/Yen k-shortest/Bellman-Ford/label-propagation/Pregel) or scoring inputs (EPSS/KEV/w=-log P) appear in code — apparent grep hits were false positives (MfaAlreadyEnrolled matching 'yen'; 'traverse' in network comments). The only adjacent code is fleet_topology_store (ADR-0002 observed graph, no scoring) and the vuln_scan plugin (per-host CVE/config matcher, no graph reasoning). The 'Phase 8' references in code are an unrelated feature-phase numbering (#254 response templates, #255 offload), not ADR-0005's Phase 8.
**Recommended record update:** none

### `vuln-07` · LOW · DRIFTED · doc-ahead-of-code
**Domain:** Vuln / reachability engine (Tier A)
**Source:** ADR-0005 two-matcher split: an agent-side KEV-only pre-filter self-flags candidates; the server-side authoritative matcher is the only source of low-FP findings; the ~200x KEV/NVD size ratio is the line.
**Claim:** An agent-side KEV-only pre-filter (zero-message local flags) exists, separate from the server authoritative matcher.
**Evidence:** No KEV pre-filter or KEV flag exists anywhere: grep -E 'kev|known.exploited|cisa.kev' across vuln_scan plugin and nvd_*.cpp/hpp returns NONE. The agent vuln_scan plugin still ships the full static matcher (cve_rules.hpp CveRule with affected_below, icontains/compare_versions — agents/plugins/vuln_scan/src/cve_rules.hpp:8-21), not a KEV-only pre-filter. ADR accepted, unbuilt.
**Verdict note:** [drift upheld] Drift is real and independently confirmed. (1) No KEV pre-filter or flag exists anywhere: my own grep of 'kev|known.exploited|cisa.kev' across agents/ and server/ C++ returns only unrelated tokens (kevent, NetworkEvent, kEval). (2) The agent plugin ships a static matcher, not a KEV pre-filter — agents/plugins/vuln_scan/src/vuln_scan_plugin.cpp:334-358 (do_cve_scan_impl) loops yuzu::vuln::kCveRules (defined cve_rules.hpp:72) using icontains product match + compare_versions(app.version, rule.affected_below); CveRule (cve_rules.hpp:8-15) has no KEV/known-exploited field and there is no (has-KEV ∧ exposes-service) self-flag. (3) The doc describes the feature as architecture: docs/adr/0005-attack-path-and-chokepoint-scoring.md:38-42 (status 'accepted', line 2) defines the 'agent-side KEV-only pre-filter' with the ~200x ratio; docs/vuln-scan-engine-design.md:315-326 tabulates the two-matcher split. (4) The design doc itself confirms it is unbuilt future work — line 449 'Phase 3 ... ship the `kev` flag ... (enables §4.4)' and line 445 marks current state as Phase 0 spike with the matcher 'acknowledged PoC-grade'. So the documented KEV pre-filter is accepted-but-not-implemented: doc-ahead-of-code drift, exactly as the auditor found.
**Recommended record update:** none

### `vuln-14` · LOW · PARTIAL · code-ahead-of-doc
**Domain:** Vuln / reachability engine (Tier B)
**Source:** capability-map.md §9.4: 'Vulnerability Scanning :white_check_mark: T1 — vuln_scan plugin + NVD database sync on server.'
**Claim:** Vulnerability scanning is a completed (checkmark) capability.
**Evidence:** The checkmark is defensible for the narrow claim it makes (plugin + server NVD sync both exist: vuln_scan_plugin.cpp, nvd_sync.cpp wired server.cpp:907). But it omits the design doc's own honesty bar (§8: 'until Phase 2 lands, capability-map describes this as an early heuristic matcher, NOT modern vulnerability scanning'). The capability-map text does not carry that caveat, so the checkmark overstates maturity given the substring/single-bound/no-backport matcher (vuln-12).
**Verdict note:** [drift upheld] Independently confirmed the drift; could not refute it. The literal §9.4 claim ("vuln_scan plugin + NVD database sync on server") is TRUE: the plugin exists (agents/plugins/vuln_scan/src/vuln_scan_plugin.cpp), NvdSyncManager is constructed and started at server.cpp:910-912, status/sync endpoints at server.cpp:5151+, and the matcher match_inventory is wired (nvd_db.cpp:358, REST /api/nvd/match at server.cpp:5221, fleet_topology_store.cpp:824). HOWEVER the drift is real on maturity: (1) The matcher is PoC-grade exactly as critiqued — nvd_db.cpp:365/379 matches product via LIKE '%name%' (substring), uses a SINGLE upper bound 'affected_below' with no versionStartIncluding lower bound (lines 385-391), and has NO backport/distro-advisory correlation (only product/affected_below/fixed_in/severity columns). (2) The design doc explicitly mandates the missing caveat: vuln-scan-engine-design.md:485-487 says "until Phase 2 lands, capability-map.md describes this as an early heuristic matcher, NOT 'modern vulnerability scanning'"; the doc header marks itself "Supersedes the static PoC matcher" and Phase 0 notes "matcher acknowledged PoC-grade". (3) grep of capability-map.md confirms NO maturity caveat anywhere near §9.4 (no heuristic/PoC/spike/Phase-2 text). So the ✅ T1 checkmark overstates maturity by omitting the project's own required honesty note; direction is doc-overstates / code-ahead-of-doc.
**Recommended record update:** CLAUDE.md edit

### `vuln-15` · LOW · DRIFTED · doc-ahead-of-code
**Domain:** Vuln / reachability engine (Tier D)
**Source:** design doc §6: scope-walking materializes graph-produced host sets (hosts on a probable attack path / chokepoint hosts) as result sets (from_result_set:<id>) for remediation.
**Claim:** Graph conclusions (attack-path host sets, chokepoint hosts) become actionable result sets via scope-walking.
**Evidence:** Scope-walking / result-sets exists as a separate primitive, but there is no graph layer producing attack-path or chokepoint host sets to feed it (vuln-05, vuln-06 NONE). The integration the doc describes cannot exist because its upstream (the scored graph) is unbuilt. Phase 7/8 dependent.
**Verdict note:** [drift upheld] Confirmed the drift independently. The scope-walking / result-set primitive fully exists (server/core/src/result_set_store.{hpp,cpp}, scope_engine.cpp:425 implements the `from_result_set:` short-circuit, result_set_matcher.cpp, result_sets_ui.cpp). But the result-set source kinds are exactly four (result_set_store.hpp:43-46: inventory_query, echo_query, instruction_result, manual_curate) — there is no attack_path or chokepoint source kind. More fundamentally, the upstream graph layer that §6 says "produces host sets (hosts on a probable attack path to a jewel; the chokepoint hosts)" does NOT exist: grep across server/ and agents/ finds zero reachability-graph code, no Dijkstra/Yen/min-cut/betweenness, and no crown_jewel/trust_zone/entry_point/traversability code (the only "graph" hit is the generic cytoscape.min.js; every "chokepoint" hit is an unrelated security/ingest chokepoint). The vuln_scan plugin is the PoC matcher only (scan/cve_scan/config_scan/summary/inventory) and is explicitly marked superseded by this design. The integration §6 describes therefore cannot exist because its upstream (the scored graph) is unbuilt — exactly what the auditor concluded. The doc itself confirms this is aspirational: it is labeled "North Star — for review" with the graph layer scoped to Phases 7 (attack-path scoring) and 8 (chokepoints), and the capability map states "until Phase 7, no attack-path claims."
**Recommended record update:** none

### `gw-23` · NONE · UNVERIFIABLE · none
**Domain:** Gateway (Erlang) (Tier C)
**Source:** docs/erlang-gateway-build.md:11: 'rebar3 eunit --dir apps/yuzu_gw/test  # unit tests (148 tests)'.
**Claim:** The standard gateway eunit suite contains 148 tests.
**Evidence:** Static count: 98 simple foo_test()/-> functions + 17 foo_test_() generators across apps/yuzu_gw/test/*.erl. Generators expand via foreach/setup fixtures into an unknown multiple, so 148 is plausible but cannot be confirmed without running. Erlang toolchain is not activatable in this sandbox (ensure-erlang.sh found no kerl/asdf/brew install; command -v erl fails).
**Verdict note:** Settle by `cd gateway && rebar3 eunit --dir apps/yuzu_gw/test` and reading the reported total.
**Recommended record update:** none

## 4. Confirmed claims (340)

Proof of what was verified intact, grouped by domain. `✓ id — claim — evidence`.

<details><summary><b>Agent core, plugins, privilege, OS matrix</b> — 21 confirmed</summary>

- `agent-03` [A] Install scripts create a dedicated unprivileged account: _yuzu on macOS, yuzu on Linux, YuzuAgent/NT SERVICE\YuzuAgent on Windows. — _install-agent-user_
- `agent-04` [A] Generated sudoers grants the specific absolute-path binaries the matrix lists with narrowed arg globs. — _install-agent-user_
- `agent-05` [A] The Windows install script does not grant SeDebugPrivilege / SeLoadDriverPrivilege / SeImpersonatePrivilege / SeTakeOwnershipPrivilege. — _install-agent-user_
- `agent-06` [A] install-agent-user.ps1 $RequiredGroups is exactly Event Log Readers / Performance Monitor Users / Performance Log Users (no Administrators). — _install-agent-user_
- `agent-07` [A] Linux setcap applies cap_net_admin,cap_net_raw,cap_dac_read_search,cap_sys_ptrace to the agent binary. — _install-agent-user_
- `agent-08` [A] The agent process never runs as root/LocalSystem and (future) production images refuse to start as root. — _No geteuid()==0 refusal in agents/core/src/agent_
- `agent-09` [A] RegistryGuard is no-op off-Windows (start() returns false). — _guard_registry_
- `agent-10` [A] FileGuard is no-op off-Windows (start() returns false). — _guard_file_
- `agent-11` [A] make_service_guard() returns SystemdServiceGuard on Linux (observe-only, enforce deferred) and ServiceGuard on Windows; macOS/other = ServiceGuard fallback. — _guard_systemd_
- `agent-13` [A] Linux DEX perf telemetry (CPU/mem levels) IS actually delivered to the server (Linux ✅ is substantively true despite the wrong citation). — _agent_
- `agent-14` [A] Windows net sampler provides throughput (GetIfTable2) + system-wide retransmit (GetTcpStatisticsEx) but no RTT (deferred ESTATS). — _net_quality_sampler_
- `agent-15` [A] The server gates the retransmit gauge to Linux only (retrans_gauge_eligible returns os==linux). — _agent_registry_
- `agent-16` [A] A macOS DEX collector exists and is wired into the agent build using DiagnosticReports/OSLog/IOKit. — _dex_macos_collector_
- `agent-17` [A] process_enum.cpp implements per-OS process enumeration (Windows, Linux /proc, macOS sysctl). — _process_enum_
- `agent-18` [A] dangerous_enforce_in_spec gates dangerous enforce-promotion at all three paths (create/rule_spec, REST update, push builder backstop). — _guardian_rule_spec_
- `agent-19` [D] The quarantine plugin shells out using `sudo -n` prefix and absolute binary paths (PATH-injection defence). — _quarantine_plugin_
- `agent-20` [A] install-agent-user.ps1 configures the YuzuProcBoot boot AutoLogger and sets deny-interactive-logon rights via secedit. — _install-agent-user_
- `agent-21` [A] The agent uses SQLite for KV/local storage and does NOT link libpq (Postgres is server-only). — _kv_store_
- `agent-22` [A] The plugin loader loads plugins via a stable C ABI (dlopen/LoadLibrary + a C descriptor export). — _plugin_loader_
- `agent-23` [A] The agent intercepts the reserved plugin name __guard__ in agent.cpp before the normal plugin dispatch. — _agent_
- `agent-24` [D] rdp_control and bitlocker plugins are Windows-only (guarded; n/a on Linux/macOS). — _rdp_control plugin core logic under `#ifdef _WIN32` (lines 33,48,57,289,331) with `#ifndef _WIN32` stub branch (line 318)_

</details>

<details><summary><b>Aspirational accuracy (capability-map/roadmap/parity/SOC2)</b> — 6 confirmed</summary>

- `asp-04` [B] Two-Factor Authentication for Approvals (§18.10) is :x: Not implemented. 'TOTP (RFC 6238) second factor for instruction approval workflows. Per-user TOTP enroll — _totp_
- `asp-11` [B] §31.7 Audit Journal and Server Store: :large_orange_diamond: PARTIAL. 'Agent-side journal (agents/core/src/guard_audit.{hpp,cpp}) lands with PR 3'. — _Server store (guaranteed_state_store_
- `asp-12` [B] Phase 8 in roadmap shows 8.1 Done, 8.2 Done, 8.3 Done. Capability map §20.7 marks Response Offloading as :white_check_mark:. — _Roadmap line 85 explicitly marks issue #255 Response Offloading as Done_
- `asp-13` [B] Session management: revocation SHIPPED ('DELETE /api/v1/sessions admin force-logout, DELETE /api/v1/sessions/me self-revoke including API tokens; audit actions  — _rest_api_v1_
- `asp-14` [B] Pre-Login Activation and Offline Capability (§31.8) is :white_check_mark: DONE. 'GuardianEngine::start_local() runs before the Register RPC, so once guard imple — _guardian_engine_
- `asp-17` [B] Guardian Engine and Wire Protocol (§31.1) is :large_orange_diamond: In progress (PRs 1-2 shipped). 'Every rule reports errored until guard implementations land  — _guardian_engine_

</details>

<details><summary><b>Auth / RBAC / sessions / tokens</b> — 23 confirmed</summary>

- `auth-01` [A] https_enabled defaults to true; --no-https disables it — _server/core/include/yuzu/server/server_
- `auth-02` [A] Web UI bind default is 127.0.0.1, not 0.0.0.0 — _main_
- `auth-03` [A] /metrics allows unauthenticated localhost access only; remote needs auth unless --metrics-no-auth — _server_
- `auth-04` [A] Server validates TLS private-key file permissions, refusing group/others-readable keys (Unix), skipped on Windows — _file_utils_
- `auth-05` [A] All responses carry the six SOC2-C1 security headers, constructed/applied solely via HeaderBundle::make()/apply() — _security_headers_
- `auth-06` [A] Password PBKDF2-SHA256 uses >=100,000 iterations — _server/core/include/yuzu/server/auth_
- `auth-07` [A] Session tokens have >=128 bits entropy; API tokens hashed with SHA-256 — _auth_
- `auth-08` [A] auth.db is chmod 0600 (parent dir 0700) on Unix at create time — _auth_db_
- `auth-09` [A] AuthDB schema goes through MigrationRunner::run, not direct sqlite3_exec(schema) — _auth_db_
- `auth-10` [A] User-create endpoint ignores the role parameter; new users always land as 'user' — _settings_routes_
- `auth-11` [A] require_admin emits auth.admin_required denied audit at the gate; AuthDB cleanup thread cadence is 60s — _auth_routes_
- `auth-12` [A] DELETE /api/settings/users/:name and role-change reject self-target (byte-exact, empty fail-closed, audit emitted) — _settings_routes_
- `auth-13` [A] Token revocation requires caller to own the token; cross-user revoke returns 404 identical to unknown-id; admin role is sole bypass; denied audited with owner d — _rest_api_v1_
- `auth-14` [A] invalidate_user_sessions performs dual-write with DB outside mu_, in-memory under mu_, wiping in-memory even when DB write fails (db_persisted=false surfaced) — _auth_
- `auth-15` [A] MCP-tier enforcement runs before the RBAC/role check on both MCP and REST transports — _auth_routes_
- `auth-16` [A] RBAC seeds exactly 6 system roles and 19 securable types — _rbac_store_
- `auth-17` [D] On RBAC store open/migrate failure the server fails closed (device visibility falls to role-scoped path, no fleet exposure) — _server_
- `auth-20` [C] MFA TOTP is wired with login challenge, enroll, and step-up endpoints; 11 high-risk step-up sites; OIDC amr short-circuit — _auth_routes_
- `auth-21` [C] OIDC PKCE flow validates issuer, audience, signature, expiration, iat, and nonce; rejects alg:none — _oidc_provider_
- `auth-22` [C] Certificate hot-reload polls PEM files, validates key permissions before applying, audits cert.reload — _cert_reloader_
- `auth-23` [D] Session token capped at 64 hex chars and API token at 256 chars; oversized tokens rejected pre-crypto — _auth_routes_
- `auth-24` [A] Session cookies set HttpOnly+SameSite (Secure when HTTPS); auth/token/RBAC SQL is parameterized; OIDC HTTP client verifies TLS by default — _auth_routes_
- `auth-25` [A] auth.db / api_token / rbac stores remain SQLite (auth is a gated Postgres-migration store, agent stays SQLite) — _auth_db_

</details>

<details><summary><b>Build / CI / release / deploy</b> — 23 confirmed</summary>

- `ci-01` [C] ci.yml implements a three-tier split: PRs build only gcc-13 debug / Windows debug / macOS debug + proto-compat; pushes build the full gcc-13/clang-19 × debug/re — _ci_
- `ci-02` [C] nightly.yml runs sanitizers (ASan+UBSan, TSan) and coverage on a 06:00 UTC cron on the self-hosted Linux runner and opens/comments a nightly-broken issue on fai — _nightly_
- `ci-03` [A] Both the x64-windows triplet static-linkage override for the grpc stack and meson.build's Windows-only find_library() construction of protobuf_dep/grpcpp_dep ar — _triplets/x64-windows_
- `ci-04` [A] vcpkg.json declares openssl unconditionally (no platform filter), and meson.build links libssl/libcrypto into grpcpp_dep on Windows. — _vcpkg_
- `ci-05` [A] vcpkg.json and vcpkg-configuration.json both pin baseline 4b77da7..., and a version>= constraint on abseil is present requiring the baseline. — _vcpkg_
- `ci-06` [A] libpq is wired into the server only (disabler() when !build_server), the agent never links libpq, and pgcommon/pgport + openssl are added explicitly with buildt — _meson_
- `ci-07` [A] No workflow uses save-always: true, and zizmor.yml has a guard step that greps for and fails on save-always. — _zizmor_
- `ci-08` [D] release.yml's release job runs check-compose-versions.sh before downloading any artifacts; the script rejects bare numeric or mismatched-default ghcr yuzu image — _release_
- `ci-09` [A] The server fails closed when YUZU_POSTGRES_DSN/--postgres-dsn is empty or the substrate is unreachable, logging '[PG] Refusing to start' and refusing to serve. — _server/core/src/server_
- `ci-10` [A] CI provides a real PostgreSQL 16 and exports YUZU_TEST_POSTGRES_DSN on every server-test leg via scripts/ci/ensure-postgres.sh. — _ci_
- `ci-11` [C] release.yml has docker-publish-postgres (multi-arch, cosign keyless + SBOM + provenance) plus docker-publish-chisel and docker-publish-agent-bundle jobs. — _release_
- `ci-12` [A] gen_proto.py flattens yuzu/.../foo.pb.h includes to foo.pb.h while leaving google/protobuf/* canonical; proto/meson.build invokes it to produce yuzu_proto. — _proto/gen_proto_
- `ci-13` [A] The CI runner topology matches the ci-architecture doc: macOS on GHA-hosted macos-15 (not macos-14), Windows + Linux self-hosted; the per-OS build dir conventio — _ci_
- `ci-14` [C] scripts/start-UAT.sh treats a missing Postgres sidecar as fatal (fail-closed) now that #1320 PR 3 (fail-closed server boot) has landed. — _PR 3 landed on this branch (commit 09e0f4cd; server_
- `ci-16` [C] docker-compose.demo.yml release-pins all images (server/gateway/agent chisel + postgres) via ${YUZU_VERSION:-0.12.0}, postgres has no -chisel variant, and the v — _docker-compose_
- `ci-17` [A] ci.yml's Windows Test step prepends the buildtype-correct vcpkg DLL bin dir to PATH so libpq.dll loads, and Windows libpq is a DLL (triplet static override is g — _ci_
- `ci-18` [A] The build toolchain prerequisites for libpq (bison/flex on Linux, autotools on macOS) are reflected in CI and the server Docker image build. — _Dockerfile_
- `ci-19` [C] ci.yml's self-hosted jobs are gated fail-closed on a preflight runner-health output with == 'true' (not != 'false'). — _ci_
- `ci-20` [A] The Windows triplet does NOT set VCPKG_BUILD_TYPE release, while the Linux static triplet DOES set it. — _triplets/x64-windows_
- `ci-21` [D] The yuzu-postgres image's first-boot init script fails closed on missing/equal app password and validates non-superuser app role ownership. — _postgres-init/10-create-yuzu-role-db_
- `ci-22` [C] ci.yml has a detect-ci-changes job and a GHA-hosted ubuntu-24.04 workflow canary that mirrors the linux build for workflow-touching PRs. — _ci_
- `ci-23` [C] proto-compat runs buf lint and buf breaking against origin/main with full history. — _ci_
- `ci-24` [A] The root meson.build declares the gateway custom_target and gateway eunit/ct tests gated on rebar3 being on PATH, and the agent/server/tests/plugins are gated b — _meson_

</details>

<details><summary><b>DEX telemetry</b> — 21 confirmed</summary>

- `dex-01` [A] The DEX observer catalogue contains exactly 103 distinct obs_types (waves 1+2+3 = 20+50+33). — _agents/core/src/dex_signal_catalog_
- `dex-02` [A] Spec count exceeds obs_type count because os.bugcheck, fs.corruption and disk.port_reset carry dual provider spellings. — _dex_signal_catalog_
- `dex-03` [A] The catalogue subscribes to 22 distinct Windows event channels. — _Robust python extraction of the 2nd quoted field of each spec yields 22 distinct channels (incl_
- `dex-04` [A] The server-side display catalogue dex_signal_groups() carries 107 distinct types = the 103 Windows event types + storage.low + perf.cpu_sustained/memory_pressur — _dex_routes_
- `dex-05` [A] DEX signals are emitted as ruleless observations with rule_id sentinel "__observation__" and event_type set to the obs_type; there is no separate category field — _dex_event_
- `dex-06` [A] Each obs_type carries a max_per_hour cap enforced per fixed wall-clock hour-bucket, saturating at cap and emitting exactly one warning per (type, hour). — _dex_rate_limiter_
- `dex-07` [C] Fleet blast-radius detector fires when >=5 distinct devices report the same (obs_type, subject) within a 15-min window, default cooldown 1h; thresholds operator — _dex_blast_radius_
- `dex-08` [C] DexAlertRouter raises a notification + dex.signal webhook per routed obs_type, suppressed to once per device per hour, with nothing routed by default and a per- — _dex_alert_router_
- `dex-09` [C] perf.cpu_sustained fires at >=90% busy for 5 consecutive 120s samples (10 min) re-arming <70% for 3; memory 90/80; disk-latency 25ms/15ms; each via dex_perf_bre — _dex_perf_breach_
- `dex-10` [C] Windows state poll emits storage.low at >=90% used OR <5 GiB free, and battery hw.error when full-charge < 80% of design, with poll-and-latch. — _dex_win_poll_
- `dex-11` [A] Every DEX observation is emitted with Guardian severity "info"; DEX applies its own framing. — _dex_event_
- `dex-12` [A] The guardian_observations DEX projection is written in the SAME transaction as the Guardian event so a redelivered event_id rolls back both (at-least-once dedup — _guaranteed_state_store_
- `dex-13` [D] The seven DEX REST endpoints (signals, scope, signals/{obs_type}, perf/fleet, perf/cohorts, perf/cohort-diff, perf/devices) all exist and are gated on Guarantee — _rest_api_v1_
- `dex-14` [D] All seven DEX reads are exposed as MCP tools (list_dex_signals, get_dex_signal_scope, get_dex_signal_detail, get_dex_perf_fleet, get_dex_perf_cohorts, get_dex_p — _mcp_server_
- `dex-15` [D] Per-signal and per-device DEX drill-downs emit the documented distinct audit verbs (dex.signal.view, dex.device.view, dex.device.perf.query, dex.device.procperf — _dex_routes_
- `dex-16` [C] DEX ships per-OS collectors selected at compile time: Windows EvtSubscribe + state poll, macOS IOKit/oslog, Linux /proc+journald, with a no-op default. — _dex_observer_
- `dex-18` [D] process.crashed dual-emits legacy detail_json keys process/exception_code/faulting_module for backward compat. — _dex_event_
- `dex-19` [D] --dex-disable (YUZU_AGENT_DEX_DISABLE) arms no observer and suppresses heartbeat perf tags / dex observer tags. — _main_
- `dex-20` [D] process.resource_limit is a macOS-only obs_type that renders under the dashboard 'Other' bucket (not in the Windows event catalogue). — _process_
- `dex-21` [D] The server aggregates agent heartbeat perf tags into yuzu_fleet_perf_* Prometheus gauges with stat labels avg/p50/p90/max and a reporting population gauge. — _Heartbeat perf-tag emission confirmed agent-side (agent_
- `dex-22` [C] dex_win_poll emits on the transition INTO a bad state, suppresses while persistent, re-arms on recovery; first poll on first tick not at arm. — _dex_win_poll_

</details>

<details><summary><b>Device pages</b> — 22 confirmed</summary>

- `dev-01` [A] Two surfaces exist: /devices (fleet list) and /device?id= (per-device entity page) with Device info / DEX / Guardian lens tabs. — _device_routes_
- `dev-02` [A] "Get live info" dispatches read-only instructions (os_info/uptime, processes/list_hashed) to the agent now and polls the response store. — _device_routes_
- `dev-03` [A] Live dispatch audits per-kind with distinct verbs device.live.uptime and device.live.processes for works-council separability. — _device_routes_
- `dev-04` [A] processes/list_hashed emits proc|pid|name|sha256|path and hashes the kernel-resolved executable, not argv[0]. — _processes_plugin_
- `dev-05` [A] sha256_file is YUZU_EXPORT, bounded at 512 MiB per image, and dedupes by path. — _plugin_loader_
- `dev-06` [A] DEX scoring is per-render: page-open scores one device, list scores only filtered rows, and devices_fn is identity-only (does not score). — _device_routes_
- `dev-07` [A] DEX and Guardian lenses gate on GuaranteedState:Read (scoped) and audit on open as dex.device.view / guardian.device.view. — _device_routes_
- `dev-08` [A] Live-info panels require Execution:Execute (in addition to a scoped GuaranteedState:Read floor) scoped to the device. — _device_routes_
- `dev-09` [D] A read-only operator (no Execute) gets an in-panel explanatory note rather than a silent failure. — _device_routes_
- `dev-10` [A] Every per-device route (page/info/dex/guardian/live) gates on scoped_perm_fn (tier + management-group, ancestor-aware); out-of-scope returns 403. — _device_routes_
- `dev-11` [D] /devices list requires Infrastructure:Read and sources from the same per-operator scoped provider as /api/agents (get_visible_agents_json). — _device_routes_
- `dev-12` [D] The device list shows only currently-connected devices and renders no offline/status filter. — _server_
- `dev-13` [D] The process list previews the first 10 rows and is searchable by name, PID, or hash (and path). — _device_ui_
- `dev-14` [D] The Get live info button is shown only when the device is online (disabled when offline). — _device_ui_
- `dev-15` [C] Live-info dispatch is intentionally untracked (execution_id=""), so it produces no ExecutionTracker row and is absent from the executions drawer. — _server_
- `dev-16` [D] The result poll allows ~40 attempts at 700ms (~28s) before declaring a timeout with a Reload-to-retry prompt. — _device_routes_
- `dev-17` [D] The result poll treats a terminal SUCCESS frame (status 1) with no output as done rather than polling to a false timeout. — _device_routes_
- `dev-18` [A] The single-device row lookup is unscoped (authz handled by the ancestor-aware scoped gate first); it must not re-apply the non-ancestor list scoping. — _device_routes_
- `dev-19` [D] The Device-info lens gates on Infrastructure:Read (scoped) and does not audit-on-open, unlike the DEX/Guardian PII lenses. — _device_routes_
- `dev-20` [D] The Device-info lens does not fabricate hardware/serial/owner/MAC fields; they are deferred to the inventory slice. — _device_ui_
- `dev-21` [D] The result poll constrains a guessed/stolen command_id (plugin prefix match, <=64 chars, agent_id match) so only the named agent's matching-kind rows render. — _device_routes_
- `dev-22` [D] List-level per-team filtering is not applied beyond the Infrastructure:Read gate; an operator with global Infrastructure:Read sees the whole connected fleet (pe — _server_

</details>

<details><summary><b>Fleet visualization</b> — 24 confirmed</summary>

- `viz-01` [A] /viz/fleet and /viz/host/<id> page shells respond with Cache-Control: no-cache, no-store, must-revalidate — _server_
- `viz-02` [A] /static/yuzu-viz.js and /static/yuzu-viz-host.js are served no-cache,no-store,must-revalidate; cytoscape/three vendored libs keep public,max-age=86400 — _server_
- `viz-03` [A] The literal /viz/fleet route is registered before the /viz/host/([^/]+) regex route so first-match-wins routing does not swallow 'fleet' — _server_
- `viz-04` [A] --viz-disable / YUZU_VIZ_DISABLE returns 503 before any RBAC permission evaluation on the topology endpoints — _viz_routes_
- `viz-05` [A] machines_max defaults 5000, ceiling 100000, and a snapshot over the cap returns 413 (never truncated) — _viz_routes_
- `viz-06` [A] Audit actions are viz.fleet_topology and viz.fleet_topology.invalidate with target_type FleetTopology and result success/denied/failure — _viz_routes_
- `viz-07` [A] Any JSON embedded in a <script type="application/json"> fragment is run through escape_json_for_script (escapes </ to <\/) before insertion — _viz_routes_
- `viz-08` [C] The fetch-duration histogram fires once per refill via a finally-equivalent path, even when the fetcher throws — _fleet_topology_store_
- `viz-09` [A] yuzu_viz_refill_* metrics are typed gauge (snapshot value at refill time), not counter — _server_
- `viz-10` [A] The importmap is declared before the type=module loader and an HTMLScriptElement.supports('importmap') detector runs first with a visible fallback error — _viz_page_ui_
- `viz-11` [A] webglcontextlost (with preventDefault) + webglcontextrestored handlers are wired and WASD keys early-return on editable targets — _yuzu-viz_
- `viz-12` [A] Renderer rejects responses whose schema != fleet_topology.v1 and surfaces 401/403/503 distinctly; server emits schema fleet_topology.v1 / schema_minor 4 — _yuzu-viz_
- `viz-13` [A] Per-agent layout uses FNV-1a 32-bit (hash32) and cubes use MeshPhysicalMaterial({transparent:true,opacity:0.18}) — _yuzu-viz_
- `viz-14` [D] CATEGORY_PALETTE has the six categories system/browser/database/web/runtime/other with the exact hex values listed — _yuzu-viz_
- `viz-15` [A] TIER_Y dict places database/app/frontend at the documented heights with TIER_GAP=22, classifyTier priority db>frontend>app, WEB_PORTS={80,443,8080,8443,8088} — _yuzu-viz_
- `viz-16` [A] AxesHelper is absent from the renderer and camera default is (45,60,45) targeting TIER_Y.app (also used for NaN-recovery) — _grep AxesHelper in yuzu-viz_
- `viz-17` [A] Hover raycast tests sockets then talking-sockets then processes then edges then cubes; listener spheres cream 0xfff2cc, talking spheres 0x7ec4f8 — _yuzu-viz_
- `viz-18` [A] Internal wires use TubeGeometry over a CubicBezierCurve3 with vertical end-tangents; external stubs use a QuadraticBezierCurve3 bow; buildWireTube returns an in — _yuzu-viz_
- `viz-19` [A] fleet_snapshot_json is field 4 on HeartbeatRequest, ingested via a single shared parse_fleet_snapshot_json across all sites — _proto/yuzu/agent/v1/agent_
- `viz-20` [A] IP-spoof guard rejects overlapping local_ips with rejection counter + topology.push.rejected audit; first push emits topology.push.first; push_snapshot does NOT — _fleet_topology_store_
- `viz-21` [A] The gateway gpb modules (gateway_pb, management_pb, agent_pb) carry HeartbeatRequest.fleet_snapshot_json field 4 so the JSON is not silently stripped on re-enco — _gateway_pb_
- `viz-22` [A] OfflineEndpointStore is a Postgres store (schema endpoint_state) merged into /viz/fleet: appends stale=true empty-process nodes only for agents absent from the  — _offline_endpoint_store_
- `viz-23` [C] yuzu_viz_offline_hosts_total counts merged offline nodes and is described; the offline store upsert runs from the shared HeartbeatIngestion path — _viz_routes_
- `viz-25` [D] In-file renderer comments describing the internal-wire geometry are accurate — _yuzu-viz_

</details>

<details><summary><b>Gateway (Erlang)</b> — 19 confirmed</summary>

- `gw-01` [A] The distribution-cookie boot guard fails CLOSED: if YUZU_GW_COOKIE is unset/known-default, yuzu_gw_app:check_distribution_cookie/0 refuses to start (unless YUZU — _yuzu_gw_app_
- `gw-02` [A] Gateway refuses to boot when the grpcbox upstream channel is TLS-but-unverified (https without verify_peer); plaintext is allowed. — _yuzu_gw_app_
- `gw-03` [C] On the gateway Register path, the upstream RegisterResponse (incl. signed per-agent certificate) is relayed to the agent verbatim with no field drop. — _yuzu_gw_agent_service_
- `gw-04` [A] All three gpb modules (gateway_pb, management_pb, agent_pb) carry csr_pem and issued_certificate so the CSR/cert is not dropped in transit. — _grep csr_pem: gateway_pb_
- `gw-05` [C] gateway/_checkouts/grpcbox is the stock v0.17.1 with a 2-line patch making fail_if_no_peer_cert and verify read from transport_opts (defaulting to true/verify_p — _grpcbox_
- `gw-06` [A] A proto-codegen drift guard exists, regenerates from priv/proto using rebar.config gpb_opts via file:consult, byte-diffs committed modules, and is wired into CI — _gateway/scripts/check-proto-codegen_
- `gw-07` [D] Heartbeats are batched into a BatchHeartbeat RPC; on failure the buffer is retained, capped at 10,000. — _yuzu_gw_heartbeat_buffer_
- `gw-10` [D] Each agent is a gen_statem (yuzu_gw_agent) with states connecting, streaming, disconnected. — _yuzu_gw_agent_
- `gw-11` [D] Command fanout is coordinated by yuzu_gw_router which dispatches to agent processes and aggregates terminal responses progressively. — _yuzu_gw_router_
- `gw-12` [A] ctx is declared in yuzu_gw.app.src applications because ctx:background/0 is called directly. — _apps/yuzu_gw/src/yuzu_gw_
- `gw-13` [A] Prometheus HTTP exporter is started with start/0 after application:set_env, not start/1. — _yuzu_gw_app_
- `gw-14` [D] All 13 documented gateway metrics are registered/emitted in yuzu_gw_telemetry.erl. — _grep in yuzu_gw_telemetry_
- `gw-15` [D] The three cluster/migration/GOAWAY metrics are NOT yet implemented. — _grep in yuzu_gw_telemetry_
- `gw-16` [D] Gateway clustering (multi-node, adjacency routing, GOAWAY shedding, node monitoring) is not yet implemented; gateway runs single-node. — _grep across apps/yuzu_gw/src/: zero matches for monitor_nodes|adjacency|goaway|absorb|hash_ring|consistent_hash|vnode_
- `gw-17` [A] sys.config.prod wires upstream mutual TLS (https + verify_peer + tlsv1.2 + default-gateway leaf) and agent-listener one-way TLS (ssl=>true, verify_none, fail_if — _config/sys_
- `gw-18` [D] The agent process emits NotifyStreamStatus on both stream connect and disconnect. — _yuzu_gw_agent_
- `gw-21` [C] On upstream reconnect the gateway replays ProxyRegister for all held agents as a spaced drip through the circuit breaker, with replay metrics. — _yuzu_gw_upstream_
- `gw-24` [A] The gateway proxies the agent-facing AgentService (Register/Subscribe/Heartbeat/ReportInventory) so agents need zero changes; agent_pb is the listener's service — _sys_
- `gw-25` [D] The gateway does not populate RegisterRequest.gateway_observed_peer (agent origin attribution deferred to QUIC #376). — _yuzu_gw_agent_service_

</details>

<details><summary><b>Guardian / Guaranteed-State</b> — 25 confirmed</summary>

- `guard-01` [A] dangerous_enforce_in_spec (guardian_rule_spec.cpp) is the single chokepoint gating dangerous enforce-promotion at create (derive_rule_spec), REST metadata updat — _guardian_rule_spec_
- `guard-02` [A] Enforce + service-stopped targeting protected SCM keys (WinDefend, WdNisSvc, Sense, wscsvc, mpssvc, EventLog, RpcSs, DcomLaunch, YuzuAgent) is rejected (400) an — _guardian_rule_spec_
- `guard-03` [A] Enforce-mode registry writes to persistence/privilege keys are denylisted with canonicalisation (lowercase, /→\, collapse repeated \) to defeat path-dodging. — _guardian_rule_spec_
- `guard-04` [A] The push fan-out and heartbeat reconcile source the enforced set from each deployed Baseline's deployed_snapshot (captured at deploy), not the live member set — — _baseline_store_
- `guard-05` [A] H2/G9 cross-check unit tests bind the server's published schema enums and the agent's per-type support arrays so a type added/removed on one side without the ot — _tests/unit/server/test_guardian_resilience_schema_
- `guard-06` [A] __guard__ is rejected at plugin load time and intercepted at dispatch time before the plugin match loop (defence-in-depth, both halves present). — _plugin_loader_
- `guard-07` [A] The Guardian push rides serialized proto bytes in CommandRequest.payload (bytes), not the parameters string map, so the Erlang gateway's UTF-8 re-encode cannot  — _server_
- `guard-08` [A] Push is in the full ops[] catalogue but deliberately excluded from crud_ops[] (the cross-seeded set) and granted only on GuaranteedState per role. — _rbac_store_
- `guard-09` [A] The agent dispatches enforcement on the typed proto spark().type()/assertion().type() blocks; yaml_source is stored only for display, never parsed for enforceme — _guardian_engine_
- `guard-10` [C] The Linux systemd service guard is observe-only; an enforce-mode rule on Linux reports drift.detected (platform=linux) but never remediates, no error. — _guard_systemd_
- `guard-11` [C] Windows ServiceGuard enforce uses argv-style advapi32 service-control APIs (StartServiceW/ControlService), not shell-out. — _guard_service_
- `guard-12` [D] Only the registry and file guards emit guard.compliant; Windows SCM and Linux systemd service guards never emit it. — _guard_registry_
- `guard-13` [C] The REST /status endpoint returns hardcoded zero compliant/drifted/errored counts; real fleet compliance is the dashboard-only census (guardian_agent_rule_statu — _rest_api_v1_
- `guard-14` [D] There is no /api/v1 Baseline route; Baseline create/deploy is GUI-only, REST can only author individual Guards. — _grep for 'api/v1_
- `guard-15` [C] REST POST /rules defaults enforcement_mode to 'enforce' and validates it is exactly 'enforce' or 'audit' (no third 'disabled' value). — _rest_api_v1_
- `guard-16` [D] PUT /rules/<id> with an enforcement_mode differing from the stored value returns 400 ('enforcement_mode is immutable...') and audits a denied update. — _rest_api_v1_
- `guard-17` [D] service-disabled is not a published/armable assertion — it is excluded from the schema and rejected at authoring; start-type drift is only detectable via an aud — _guardian_schema_registry_
- `guard-18` [C] The rule signature is stored but not verified before the agent arms a guard (signing/HMAC deferred). — _guardian_engine_
- `guard-19` [C] Durable event journaling (A3) is not yet implemented — events detected before the event sink is wired (pre-network arm) are dropped, not buffered. — _guardian_engine_
- `guard-20` [C] The registry guard opens enforce keys with KEY_SET_VALUE and falls back to a read-only watch (reporting remediation.failed) when write access is denied, never s — _guard_registry_
- `guard-21` [C] Guardian message forwarding through the Erlang gateway is best-effort, dropping under an open circuit or at capacity and counting drops by reason (circuit_open  — _yuzu_gw_upstream_
- `guard-22` [A] DEX observations are emitted through the same event pipeline using the reserved sentinel __observation__ as rule_id and obs_type as event_type (e.g. process.cra — _dex_event_
- `guard-23` [C] The Guardian server stores remain SQLite (not yet Postgres-migrated) and use the SqliteStmt/SqliteTxn RAII owners. — _baseline_store_
- `guard-24` [C] GuardianEngine performs two-phase init: start_local() arms cached guards pre-network and sync_with_server() runs post-Register; sync before start_local is ignor — _guardian_engine_
- `guard-25` [D] Seeded RBAC role grants match the manual: PlatformEngineer = Read/Write/Delete/Push on GuaranteedState; Operator = Read+Push; Viewer = Read. — _rbac_store_

</details>

<details><summary><b>Instruction Engine & executions ladder</b> — 20 confirmed</summary>

- `instr-01` [A] execution_id is stamped onto responses from an in-memory command_id->execution_id map that is registered at dispatch time before any RPC is sent — _agent_service_impl_
- `instr-02` [A] Terminal-status branches must not erase cmd_execution_ids_ so agents 2..N of a fan-out still stamp the correct execution_id — _The only cmd_execution_ids__
- `instr-03` [A] An empty-output terminal CommandResponse folds into the existing RUNNING row via finalize_terminal_status instead of creating a second sentinel row; on both ing — _finalize_terminal_status called at agent_service_impl_
- `instr-04` [A] query_by_execution includes the redundant `execution_id != ''` predicate so the partial index idx_resp_execution_ts is used — _Index created at response_store_
- `instr-05` [A] The three ExecutionTracker mutators publish exactly the documented event taxonomy in the documented ordering — _execution_tracker_
- `instr-06` [A] gc_terminal_channels pins each victim Channel with a local shared_ptr before locking, erases under the write lock, and parks copies in a `dead` vector declared  — _execution_event_bus_
- `instr-07` [A] ExecutionEventBus member is declared before ExecutionTracker so it outlives the tracker, and shutdown resets tracker before bus — _server_
- `instr-08` [A] /api/v1/events is the agentic sibling reusing ExecutionEventBus, emits the wrapped JSON envelope, and audits under api.v1.events.subscribe — _rest_api_v1_
- `instr-09` [A] The agentic /api/v1/events handler emits replay-gap and events-dropped synthetic envelopes and enforces a per-connection queue cap — _rest_api_v1_
- `instr-10` [A] notify_exec_tracker early-returns for execution_id starting with polchk- so compliance checks never create tracker rows or SSE events — _agent_service_impl_
- `instr-11` [C] MCP execute_instruction creates an execution row before dispatch and threads execution_id into cmd_dispatch, making it a tracked producer — _mcp_server_
- `instr-13` [C] Workflow-step dispatch still passes empty execution_id (coverage gap open) — _workflow_routes_
- `instr-14` [A] Shipped content is build-time embedded into bundled_content.cpp and seeded on first boot; there is no runtime --content-dir flag — _server/core/meson_
- `instr-15` [A] meson setup fails the configure step when PyYAML is not importable — _server/core/meson_
- `instr-16` [D] InstructionStore stores the original YAML in a yaml_source TEXT column plus denormalized columns for queries — _instruction_store_
- `instr-17` [C] A from-scratch CEL-compatible evaluator exists in cel_eval.cpp and compliance_eval delegates to it — _server/core/src/cel_eval_
- `instr-18` [C] Server-side concurrency enforcement backed by a concurrency_locks SQLite table with the documented mode set exists — _concurrency_manager_
- `instr-19` [D] ApprovalManager rejects an approval where the reviewer equals the submitter and prevents double-review via atomic WHERE status='pending' — _approval_manager_
- `instr-22` [A] Drawer/list markup carries the documented stable data-attribute/id stamps that the client SSE listener binds to — _Not settled by reading the C++ anchors in this audit's scope; the stamps live in dashboard fragment markup (instruction_ui_
- `instr-23` [A] The agentic /api/v1/events route audits under api.v1.events.subscribe with no per-session dedup (deferred) — _rest_api_v1_

</details>

<details><summary><b>MCP & agentic-first (A1-A4)</b> — 16 confirmed</summary>

- `mcp-01` [A] The MCP tier check (tier_allows) runs BEFORE the RBAC permission check on every tool call. — _mcp_server_
- `mcp-02` [A] --mcp-disable / YUZU_MCP_DISABLE rejects all /mcp/v1/ requests with kMcpDisabled (-32005); --mcp-read-only / YUZU_MCP_READ_ONLY blocks write/execute tools. — _main_
- `mcp-09` [C] MCP exposes 4 prompts with the listed names. — _kPrompts has exactly those 4 entries (mcp_server_
- `mcp-10` [D] execute_instruction on the supervised tier returns a not-implemented/approval-required error because the approval re-dispatch path is not built. — _requires_approval(supervised, Execution, Execute) == true (mcp_policy_
- `mcp-11` [D] operator-tier execute_instruction auto-executes; absent scope/agent_ids defaults to all agents (__all__). — _tier_allows(operator, Execution, Execute) true & requires_approval false (mcp_policy_
- `mcp-12` [C] execute_instruction creates an ExecutionTracker row before dispatch and returns both command_id and execution_id so the worker can bridge to /api/v1/events. — _mcp_server_
- `mcp-13` [A] A3 JSON SSE channel GET /api/v1/events is shipped, gated on Execution:Read, audits api.v1.events.subscribe, supports replay and Sec-Audit-Failed. — _rest_api_v1_
- `mcp-15` [A] The A2 /api/v1/discover/* discovery family is built. — _Grep for 'discover/routes|discover/plugins|/api/v1/discover|discover_routes' across server/core/src/*_
- `mcp-16` [D] MCP token creation rejects missing expiration and any TTL exceeding 90 days. — _api_token_store_
- `mcp-17` [C] MCP tier is stored as an mcp_tier column on the existing api_tokens table. — _api_token_store_
- `mcp-18` [D] The MCP server advertises protocol version 2025-03-26 on initialize. — _initialize handler returns protocolVersion "2025-03-26" (mcp_server_
- `mcp-19` [A] get_dex_signal_detail emits a dex.signal.view audit (target ObsType) and validates obs_type to [A-Za-z0-9._-]{1,64}, rejecting malformed before the audit. — _obs_type charset+length validation (mcp_server_
- `mcp-20` [C] A Settings UI fragment exposes MCP enable/disable and read-only toggles bound to cfg_->mcp_disable / mcp_read_only. — _settings_routes_
- `mcp-21` [A] tier_allows enforces readonly=Read-only, operator=Read+Tag Write/Delete+Execute (auto), supervised=all; requires_approval gates supervised destructive ops + ope — _mcp_policy_
- `mcp-22` [D] prompts/get wraps untrusted string arguments (agent_id, policy_id, principal) in untrusted-data sentinels with JSON-escaped values. — _prompts/get calls untrusted_prompt_argument() for agent_id (mcp_server_
- `mcp-23` [A] The MCP DEX/perf/network/CA tools are at parity with sibling /api/v1/* REST endpoints (same read model / aggregations). — _Each tool's description and dispatch reference the REST sibling and share providers: DEX tools use guaranteed_state_store aggregations (mcp__

</details>

<details><summary><b>Network quality</b> — 21 confirmed</summary>

- `net-01` [A] yuzu.net_retrans_pct is an INTERVAL delta (ΔΣretr/ΔΣsegs smoothed over heartbeats via agent-core RetransWindow), NOT the disproven absolute lifetime ratio. — _agents/core/src/net_quality_sampler_
- `net-02` [A] yuzu.net_degraded is RETIRED — agent no longer emits it; server still parses kNetTagDegraded defensively for rolling upgrades; gauge absent-not-zero. — _agents/core/src/agent_
- `net-03` [A] Windows retransmit rate is WITHHELD from the yuzu_fleet_net_retrans_pct gauge (server-side gate retrans_gauge_eligible(os) — Linux-only today); it still shows o — _server/core/src/agent_registry_
- `net-04` [A] yuzu_fleet_net_* gauges carry an `os` label (per-OS, never blended); never alert on a cross-OS aggregate. — _server/core/src/agent_registry_
- `net-05` [A] kNetTag* static_assert pins in test_network_perf_model.cpp ensure agent emit literals match server-side constants. — _tests/unit/server/test_network_perf_model_
- `net-06` [C] Network sampling shares the agent's --dex-disable flag — disabling DEX disables the network heartbeat facts. — _agents/core/src/agent_
- `net-07` [D] Linux: RTT via netlink INET_DIAG per-connection TCP_INFO; retransmit via per-connection sum; throughput via /proc/net/dev. — _agents/core/src/net_quality_sampler_
- `net-08` [D] Windows: throughput via GetIfTable2; retransmit via GetTcpStatisticsEx (system-wide; includes loopback; RTT deferred/absent); macOS emits nothing (all-invalid). — _agents/core/src/net_quality_sampler_
- `net-09` [D] The Windows retransmit MIB is measurement-first UNVALIDATED (netem test was Linux-only; biased low on loopback-dominated hosts) and is WITHHELD from yuzu_fleet_ — _agents/core/src/net_quality_sampler_
- `net-10` [D] Access to /network requires GuaranteedState:Read permission; /network is a sub-view of DEX (not a standalone top-level nav). — _server/core/src/network_routes_
- `net-11` [D] Degraded classification and co-occurrence 'also app' headline are a later slice. yuzu_fleet_net_degraded gauge is wired but unfed (absent when no agent reports  — _server/core/src/server_
- `net-12` [D] Gauges and dashboard cannot disagree on the same heartbeat sample — shared validators in network_perf_rules.hpp are used by both recompute_metrics and the /netw — _server/core/src/network_perf_rules_
- `net-13` [D] Per-connection netqual Echo tier is opt-in (netqual_enabled=true), off by default, stores only coarse destination class (loopback/private/public — raw address dr — _agents/plugins/echo/src/echo_plugin_
- `net-14` [D] netqual per-connection tier has no dashboard consumer yet — it is the foundation for the deferred per-destination drill; queryable via Execute-gated Echo SQL as  — _agents/plugins/echo/src/echo_schema_registry_
- `net-15` [D] RTT carries its own (smaller) denominator — devices that do not report smoothed RTT are excluded from RTT numbers, never counted as 0 ms. This is tracked as rtt — _server/core/src/network_perf_model_
- `net-16` [D] Absent metrics are ABSENT (nullopt/null), never 0 — a device that does not report a metric is excluded from that metric's denominator. — _server/core/src/network_perf_model_
- `net-17` [D] Throughput is a coarse upper bound — sums all non-loopback interface byte counters; deliberately does not filter interfaces by name (fragile heuristic); over-co — _agents/core/src/net_quality_sampler_
- `net-18` [A] The `os` label on fleet network gauges must never be a cross-OS blend; an `os` cardinality DoS from a spoofed tag is bounded by the normalize_os allowlist (wind — _server/core/src/agent_registry_
- `net-19` [C] The /network page shell is a DEX sub-view (not a standalone top-level nav), rendered by the shared guardian_page_ui.cpp kGuardianDetailPageHtml shell with DEX m — _server/core/src/network_routes_
- `net-20` [D] The netlink INET_DIAG dump is bounded against a wedged heartbeat thread via SO_RCVTIMEO (2 s); a stalled dump degrades to an absent sample, not a hung agent. — _agents/core/src/net_quality_sampler_
- `net-21` [D] The co-occurrence 'also app' band (app_unstable) is not yet wired to a real DEX crash/hang store — it hardcodes false, deferred to the per-connection collector  — _server/core/src/server_

</details>

<details><summary><b>PKI / CA / mTLS / secrets-at-rest</b> — 22 confirmed</summary>

- `pki-01` [A] CA root is ECDSA P-384 (10-yr); all server/agent leaves are ECDSA P-256; signature digest follows issuer key strength (P-384→SHA-384, P-256→SHA-256); 100% OpenS — _default_certs_
- `pki-02` [A] CA root private key lives behind KeyProvider (FileKeyProvider, 0600 PEM); ca.db holds only opaque key_ref, never the key; key loaded transiently and zeroed per  — _key_provider_
- `pki-03` [A] ca.db revoke() uses RETURNING for change detection (no sqlite3_changes on shared conn), opened FULLMUTEX + 0600, migrations via MigrationRunner namespace ca_sto — _ca_store_
- `pki-04` [C] First-boot ensure_default_certs() generates root+3 leaves; ERROR banner, audit server.default_certs_generated/in_use, gauge yuzu_server_default_certs_active, -- — _server_
- `pki-05` [C] Per-agent mTLS issuance + revocation enforcement is wired across Register re-auth, Subscribe, Heartbeat, DownloadUpdate, and a periodic stream sweep, issuer-sco — _server_
- `pki-06` [A] sign_csr verifies proof-of-possession (X509_REQ_verify); leaf subject/SAN/EKU are server-chosen from the authenticated agent_id, never from CSR fields. — _x509_ca_
- `pki-07` [A] Direct and gateway-proxied enrollment share one guarded signer wired in server.cpp with identical 16 KiB cap, rate-limit, ca_issued recording, and reissue-block — _server_
- `pki-08` [C] GET /ca/root + /ca/crl public; GET /ca/issued Security:Read; POST /ca/revoke Security:Delete; GET /ca/root-csr Security:Read; POST /ca/import-chain Security:Wri — _ca_routes_
- `pki-09` [C] POST /api/v1/ca/issue is deferred and not implemented. — _absent: grep "/ca/issue\"" across server/core/src returns only the ca_routes_
- `pki-10` [A] CA inventory + revoke are exposed as MCP tools list_issued_certs (Read, all tiers) and revoke_certificate (Delete, supervised-only) with the same RBAC perms. — _mcp_server_
- `pki-11` [A] Agent generates its own P-256 keypair + CSR, persists key at 0600, renews at 2/3 of validity; agent_csr is self-contained OpenSSL and does not link server x509_ — _agent_csr_
- `pki-12` [C] Gateway TLS is a reference config (sys.config.prod): upstream mutual TLS, fail-closed boot if https-without-verify_peer (override env), agent listener one-way T — _gateway/config/sys_
- `pki-13` [C] A vendored+patched grpcbox (_checkouts/grpcbox + grpcbox.yuzu.patch) makes fail_if_no_peer_cert/verify configurable so the agent listener runs one-way TLS witho — _gateway/_checkouts/grpcbox/ exists with src/include + grpcbox_
- `pki-14` [C] PR5b is partial: --cert-san (validated/dedup extra SANs, wildcard-rejected, IP-checked) and Dockerfile.server cert-dir ownership shipped; the encrypted-by-defau — _default_certs_
- `pki-15` [A] import_subordinate_chain validates parseable → CA:TRUE → carries-our-key (cert_matches_key) → chains-to-parent, in that order, then switches mode keeping key un — _server_
- `pki-17` [C] The SecretCodec envelope-encryption mechanism is shipped: blob v1 layout, kek_meta fingerprint table in schema secrets, fail-closed boot init, rotation/retireme — _pg/secret_codec_
- `pki-18` [A] Payload AES-GCM AAD excludes kek_version; wrap AAD adds kek_version; AAD fields are u32-BE length-prefixed (canonical, anti-swap). — _secret_codec_
- `pki-19` [A] KekProvider is a distinct interface from KeyProvider exposing generate_kek/resolve_kek/wrap_dek/unwrap_dek/kek_check_value/delete_kek — never raw KEK export; Fi — _key_provider_
- `pki-20` [A] DEKs and recovered plaintext use a move-only zeroizing SecureBuffer (OPENSSL_cleanse dtor); decrypt returns SecureBuffer; Error/external-error never embed secre — _secure_buffer_
- `pki-21` [C] The four recover-plaintext gated stores and the api_token/ca stores are still SQLite (no secret column has landed in a Postgres column yet); SecretCodec is ship — _auth_db_
- `pki-23` [A] decrypt fails closed (audited+counted, never empty-secret) and encrypt aborts the caller's write on any CSPRNG/EVP failure; oversized plaintext rejected; failur — _secret_codec_
- `pki-24` [A] FileKeyProvider stores KEKs as 0600 raw files (atomic write), caches one resident zeroizing copy; boot serializes via pg advisory lock so a second server agains — _key_provider_

</details>

<details><summary><b>Policy / compliance evaluation</b> — 24 confirmed</summary>

- `policy-01` [A] Compliance is driven by a PolicyEvaluator background thread on a 10s cadence (the check->verdict->PolicyStore::update_agent_status path); was previously dead co — _server_
- `policy-02` [A] After a 15-second grace window the evaluator reads each agent's response and scores it. — _policy_evaluator_
- `policy-03` [A] The per-policy evaluation interval is clamped to a 60-second floor. — _dispatch_due clamps: int64_t interval = std::max<int64_t>(interval_for(p, d__
- `policy-04` [A] A policy with no interval trigger defaults to 3600s (1 hour). — _policy_evaluator_
- `policy-05` [A] PolicyEvaluator mints polchk-* correlation ids that notify_exec_tracker skips — no ExecutionTracker row, no SSE; compliance is NOT in the executions drawer. — _gen_execution_id() returns 'polchk-' + hex (policy_evaluator_
- `policy-06` [A] policy_eval_thread_ is joined before the stores are torn down. — _stop() sets stop_requested_ (server_
- `policy-07` [A] The evaluator drives the EXACT same dispatch path as operator-initiated commands via a hoisted shared command_dispatch_fn. — _command_dispatch_fn defined once (server_
- `policy-08` [A] Remediation is never automatic — there is no automatic non_compliant -> fix loop; fixes are explicit operator actions only. — _collect_ready Check phase only writes verdict via update_agent_status, never dispatches a fix (policy_evaluator_
- `policy-09` [D] A policy with an empty compliance expression (checks nothing) is reported as error, never compliant. — _verdict_for(): 'if (cel_
- `policy-10` [D] Verdict mapping: plugin failure/timeout/rejection->error; non-responder after grace->unknown; success failing CEL->non_compliant; success satisfying CEL->compli — _is_terminal_failure (FAILURE/TIMEOUT/REJECTED) -> error (policy_evaluator_
- `policy-11` [D] On server restart, any agent left mid-remediation (fixing) is reset to unknown and re-evaluated. — _PolicyEvaluator ctor boot-reconciliation loops all policies/statuses and resets status=='fixing' to 'unknown' (policy_evaluator_
- `policy-12` [D] POST /api/policies/{id}/evaluate requires Policy:Execute, returns 202 with execution_id, 409 when no check instruction or no agents match. — _compliance_routes_
- `policy-13` [D] POST /api/policies/{id}/remediate requires Policy:Execute, intersects caller agent_ids with policy scope, 409 when remediation unavailable/no eligible agents. — _compliance_routes_
- `policy-14` [D] Evaluation timing is in-memory (last_eval_ map), so after restart every enabled policy is due on the first tick. — _last_eval_ is an in-memory std::unordered_map (policy_evaluator_
- `policy-15` [D] PolicyStore is backed by SQLite WAL with a mutex protecting the DB handle. — _policy_store_
- `policy-16` [A] Compliance status writes avoid the sqlite3_changes()-after-step anti-pattern on the shared PolicyStore connection. — _update_agent_status uses INSERT _
- `policy-17` [D] FleetCompliance is now computed from real per-agent verdicts (header: get_fleet_compliance always read 0% before this component). — _compute_fleet_compliance_locked computes fc_
- `policy-18` [A] The blocking dispatch_fn is never invoked while holding the evaluator mutex (kickoff_check/dispatch_instruction lock discipline). — _kickoff_check acquires mu_ only for the dedupe scan (policy_evaluator_
- `policy-19` [A] Duplicate check dispatch is prevented: a second Check for a policy already in flight is dropped (bounds in_flight_ growth, prevents stale overwrite). — _kickoff_check scans in_flight_ for an existing Phase::Check with same policy_id and returns "" (policy_evaluator_
- `policy-20` [D] Fix attempts are capped at 3; exceeding the cap forces status to error. — _PolicyStore::update_agent_status: kMaxFixAttempts=3, on 'fixing' transition with attempts>=3 forces effective_status='error' (policy_store_
- `policy-21` [C] A malformed policy/result cannot crash the process: tick() is wrapped in try/catch in the thread loop so an exception does not call std::terminate. — _Thread lambda wraps policy_evaluator_->tick() in try/catch(std::exception)/catch(_
- `policy-22` [D] An agent that does not respond (or only RUNNING) within the grace window is scored unknown. — _collect_ready: 'if (it == best_
- `policy-23` [D] Per-policy (/invalidate) and fleet-wide (/invalidate-all) cache invalidation reset agent statuses for re-evaluation. — _POST /api/policies/:id/invalidate calls policy_store_->invalidate_policy(id) (compliance_routes_
- `policy-25` [C] Per-verdict observability counter (yuzu_server_policy_verdicts_total{status}) and eval-error counters are emitted. — _collect_ready increments metrics->counter("yuzu_server_policy_verdicts_total",{{"status",status}}) (policy_evaluator_

</details>

<details><summary><b>Postgres substrate & migration</b> — 24 confirmed</summary>

- `pg-01` [A] The server's storage substrate is PostgreSQL; the agent stays SQLite. — _server/core/src/server_
- `pg-02` [A] The server fails closed (non-zero exit, no SQLite fallback) when no DSN is configured or the database is unreachable. — _server_
- `pg-03` [A] ~27 existing server SQLite stores are migrating incrementally to Postgres. — _28 *_store_
- `pg-04` [C] OfflineEndpointStore is the first born-on-Postgres store, schema endpoint_state, heartbeat-ingest upsert via INSERT...ON CONFLICT...RETURNING off the gRPC hot-p — _offline_endpoint_store_
- `pg-05` [A] OfflineEndpointStore upsert is hooked via the shared HeartbeatIngestion seam. — _heartbeat_ingestion_
- `pg-06` [C] viz_routes merges persisted offline endpoints as stale-flagged nodes so aged-out hosts do not vanish. — _viz_routes_
- `pg-07` [A] A shared public.schema_meta(store,version,upgraded_at) table tracks versions; the runner creates one Postgres schema per store. — _pg_migration_runner_
- `pg-08` [A] Migrations run under SET LOCAL search_path to the store schema; runtime statements schema-qualify explicitly. — _pg_migration_runner_
- `pg-09` [A] Concurrent migration runners are serialized by a cluster-wide pg_advisory_xact_lock. — _pg_migration_runner_
- `pg-10` [A] Store names must match [a-z_][a-z0-9_]{0,62} and exclude public/information_schema/pg_. — _pg_migration_runner_
- `pg-11` [A] The runner refuses to migrate when schema_meta says v0 but the store schema already contains tables (schema-drift guard, #1368 CH-11). — _pg_migration_runner_
- `pg-12` [A] A malformed conninfo is reported as a fixed string (no credential echo) and libpq buffers are freed with PQfreemem/PQconninfoFree. — _pg_pool_
- `pg-13` [A] PgPool::Observer hooks feed the documented yuzu_pg_* counters/histogram/gauges. — _server_
- `pg-14` [A] The /readyz conjunction includes a pg_pool entry (valid AND connect breaker closed, non-lease-consuming) and the offline_endpoint_store entry. — _server_
- `pg-15` [A] pg_pool_ is reset last in stop(), after the gRPC drain quiesces lease-holding handler threads. — _server_
- `pg-16` [A] The substrate is raw libpq + in-house RAII (pg_raii.hpp), a shared PgPool, and PgMigrationRunner — no libpqxx. — _server/core/src/pg/ contains pg_raii_
- `pg-17` [C] A Windows static-link canary (libpq running SELECT 1) exists and is built; Windows libpq is dynamic, Linux/macOS static. — _server/core/src/pg/canary_main_
- `pg-18` [C] The app-side AES-256-GCM SecretCodec (DEK-per-secret, KEK behind KekProvider) is shipped with a secrets schema, kek_meta fingerprint table, fail-closed boot ver — _pg/secret_codec_
- `pg-19` [A] The secret-bearing stores (auth, webhooks, offload_targets, runtime_config) are NOT yet migrated to Postgres / SecretCodec; they remain pending. — _No production store includes SecretCodec (grep shows only key_provider_
- `pg-20` [A] Migrated stores cut over via a per-store migrate_from_sqlite() first-boot backfill. — _grep for migrate_from_sqlite across server/core/src returns empty_
- `pg-21` [A] A single shared PgPool is constructed before any Postgres-backed store and injected into each. — _server_
- `pg-22` [A] The pool injects statement_timeout/lock_timeout GUCs and TCP keepalives, and has a connect-failure circuit breaker with exponential backoff + jitter. — _pg_pool_
- `pg-23` [A] No secret material is stored as a plain Postgres column; secret columns are hash-only or AES-256-GCM envelope-encrypted blobs. — _The only Postgres-backed store (offline_endpoint_store) holds only agent_id/hostname/os/timestamps (offline_endpoint_store_
- `pg-24` [C] CI and deploy artifacts (composes, Dockerfile.server, systemd, install) have grown a Postgres service. — _scripts/ci/ensure-postgres_

</details>

<details><summary><b>Echo & scope-walking</b> — 21 confirmed</summary>

- `echo-01` [A] Untrusted operator SQL is executed on a dedicated read-only, authorizer-sandboxed SQLite connection that allowlists only registry-known warehouse tables; truste — _agents/plugins/echo/src/echo_db_
- `echo-02` [A] The echo.sql agent action validates then runs operator SQL via execute_user_query, while internal rollup/stats queries use execute_query. — _agents/plugins/echo/src/echo_plugin_
- `echo-03` [A] execute_user_query passes explicit byte length (not -1) so an embedded NUL is a tokenizer error, and rejects any trailing statement after the first. — _agents/plugins/echo/src/echo_db_
- `echo-04` [A] If the read-only sandbox connection cannot be opened, operator SQL is refused (fail closed) for the process lifetime. — _agents/plugins/echo/src/echo_db_
- `echo-05` [A] The result-set store is a dedicated SQLite database named result_sets.db with result_sets + result_set_members tables and lineage parent_id edges. — _server/core/src/result_set_store_
- `echo-06` [A] The Scope Engine adds a from_result_set:<id-or-alias> short-circuit kind that resolves to materialised members and composes with attribute predicates via AND/OR — _server/core/src/scope_engine_
- `echo-07` [A] from_result_set: resolution is owner-checked; a reference the resolver does not own no-matches rather than leaking another operator's set. — _server/core/src/result_set_store_
- `echo-08` [A] Result sets carry default 1h TTL, 10000/operator hard cap, 50-pin cap, and a background GC sweep deleting unpinned expired rows. — _result_set_store_
- `echo-09` [C] from-echo-query / from-instruction-result create a pending result set with a source_execution_id, materialised asynchronously by a maintenance thread. — _result_set_store_
- `echo-10` [C] DSL fromResultSet:/selector: parses and lowers (platform->ostype, tags->EXISTS tag:), rules 1-2 enforced at create, rule 3 enforced at dispatch via instruction. — _server/core/src/scope_yaml_
- `echo-11` [C] Policy fromResultSet: is not yet supported; create_policy rejects both the scalar and block forms. — _server/core/src/policy_store_
- `echo-12` [D] A dedicated /echo page exists requiring auth, hosting the retention-paused source list with Scan and Re-enable. — _server/core/src/server_
- `echo-13` [D] Responses are deduplicated by received_at_ms and a non-true/false enabled value surfaces a value-error badge rather than being dropped. — _server/core/src/dashboard_routes_
- `echo-15` [C] The process-tree viewer (echo.process_tree action, /fragments/echo/process-tree and /api/v1/echo/process-tree/{id} routes) is not yet built. — _No server route handler for process-tree: grep for 'process-tree' in server/core/src/*_
- `echo-16` [D] The Purge-data action (echo.purge_source agent action, Infrastructure:Delete, typed-confirm) is not yet implemented. — _absent: grep 'purge_source'/'echo_
- `echo-17` [D] Exactly four structured categories exist with environment restricted to the three allowed values and a 448-byte value cap. — _server/core/src/tag_store_
- `echo-18` [D] Setting the service tag auto-creates a dynamic management group named 'Service: <value>' scoped by tag:service == value. — _server/core/src/rest_api_v1_
- `echo-20` [D] The scope engine supports tag:<key> equality and EXISTS tag:<name> presence, and the YAML selector.tags block lowers each tag to a presence check. — _scope_engine_
- `echo-21` [A] The full result-sets REST surface (list/get/create/from-*/lineage/members/pin/unpin/re-eval/delete) is wired. — _server/core/src/rest_api_v1_
- `echo-22` [D] The tag-categories and tag-compliance REST endpoints exist with the documented behaviour. — _settings_routes_
- `echo-23` [A] Membership is materialised at create time and resolution silently drops stale members rather than erroring. — _result_set_store_

</details>

<details><summary><b>Vuln / reachability engine</b> — 8 confirmed</summary>

- `vuln-01` [A] The reachability graph is built from observed flows only (no potential/config-derived edges, no fabric reachability). — _The only graph-bearing code is FleetTopologyStore (server/core/src/fleet_topology_store_
- `vuln-08` [A] A graph/topology securable type and audited trust-zone/crown-jewel authoring surfaces exist. — _Doc itself states 'neither exists today' (§3_
- `vuln-09` [C] FleetTopologyStore exists today as an in-memory observed host-to-host graph with IP→agent resolution and edge classification. — _server/core/src/fleet_topology_store_
- `vuln-10` [C] The NVD vuln overlay on the topology graph is wired but inert (produces no findings today). — _fleet_topology_store_
- `vuln-11` [C] Phase 0 spike is done: agent inventory action, runtime rule delivery, static matcher present; that PoC matcher is the thing later phases supersede. — _agents/plugins/vuln_scan/ present: vuln_scan_plugin_
- `vuln-12` [C] The server-side matcher is the engine (CPE/PURL identity, version ranges, backport correctness) — i.e. Phases 1-2 done. — _Server matcher is STILL the PoC: NvdDatabase::match_inventory uses 'product LIKE %name_lower%' + single compare_versions(version, affected_b_
- `vuln-13` [C] A server-side NVD mirror with background sync (real NVD API fetch) exists and is wired into the server. — _NvdDatabase (SQLite cve table, nvd_db_
- `vuln-16` [A] Container/instance attribution in the graph is platform-gated and never claims cross-kernel visibility. — _No container-attribution code in the reachability graph path exists yet (the eBPF cgroup / Windows-silo attribution is Phase 6 'Add' per des_

</details>
