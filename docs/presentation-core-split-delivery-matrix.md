# Presentation / Core / Engine Split — Delivery Matrix

The delivery spine for the **three-binary decomposition** of the Yuzu server
(`docs/adr/0031-presentation-core-engine-decomposition.md` — cite by filename, it shares the number
0031 with the engine-principal-store ADR). Those ADRs record the *model and invariants*; this matrix
tracks *what ships, in what order, who reviews it, and how we know it's done*. **If a row here disagrees
with the ADRs, the ADR wins; on delivery status, this matrix is the source of truth.** The `/split`
skill is a pointer to both and loses to both.

**Verified against the tree 2026-09-24** (`origin/dev` @ `5b7613641` + `feat/split-a4-lens-followups`, which closed GAP-1 (#4857: the `/dex/perf/app` device-model picker now reads the SAME `dex_perf_cohorts(DexPerfApi::fleet_snapshot(...))` derivation as the public `GET /api/v1/dex/perf/cohorts`, `DexRoutes::TagValuesFn` deleted) and the review follow-ups #4855/#1762/#4856/#4858; previously `origin/dev` @ `4486fc13c` + `feat/split-a4-lens-dashboard-rewire` (#4860), which closed #4576's device-lens half + the `guardian` family's own device-lens (#4483) deferral (`device_lens_routes.{hpp,cpp}`'s `/fragments/device/dex`+`/fragments/device/guardian` lenses now call `DexApi`/`GuardianApi`, enrolled in the `device` seam family) and #4626's `dex_perf` dashboard deferral (`dex_perf_ui.cpp`+`dex_app_perf_ui.{hpp,cpp}` now call `DexPerfApi` exclusively, `AppPerfProviders` retired, enrolled in the `dex_perf` seam family) — see the WS-A4 row for the four disclosed behaviour deltas (guardian zero-guard rendering, the F2b/per-device app-perf placeholder-wording collapse, the per-device perf-strip empty-snapshot rendering, and the per-device app-perf audit-before-not-wired over-audit) and the new GAP-1 residual; WS-0 merged #4161, INV-31-4 global test found already-shipped #842/#3991/#3992 — WS-A4 re-scoped; the three-way lexical caveat re-verified against `check-api-parity.py` and `HttplibRouteSink`/`test_openapi_spec_completeness.cpp` in review round 2; the `network` family landed as the FIRST per-family in-process API seam — `NetworkApi`/`network_api.{hpp,cpp}` + `scripts/ci/check-seam-closure.py` — see the WS-A4 row; #4249 then split that seam's factory header into `network_api.hpp` (abstract) + `network_api_local.hpp` (core-only), with the boundary between them CI-enforced, cutting the two-header shape the remaining families copy; #4250 then applied that template to the SECOND family, `verify` (`/auto` VERIFY app-perf compare — `VerifyApi`, all 3 consumers routed) — **MERGED to dev (PR #4292)**; **`feat/split-a4-compliance-seam` then applied the template to the THIRD family, `compliance`** (`ComplianceApi`, the read surface's 3 consumers — dashboard, REST v1, MCP — routed; the un-twinned policy/fragment mutators split OUT into `policy_admin_routes.{hpp,cpp}`, deliberately outside the seam-closure enforced set per INV-31-4, tracked as a WS-A3 gap under #4334; a pre-existing confinement/audit gap on the legacy `GET /api/compliance/{id}` route, kept byte-identical here, is tracked separately under #4333) — **MERGED to dev (PR #4337)**; **`feat/split-a4-device-seam` then applied the template to the FOURTH family, `device`** (`DeviceApi` — `list_devices()` == `GET /api/v1/devices`, `lookup_device()` == `GET /api/v1/devices/{id}`, an O(1) registry point lookup carrying forward the #3564 timing-oracle posture to REST as well as MCP; all 3 consumers — dashboard, REST v1, MCP — routed with BYTE-IDENTICAL authz per consumer (REST's `fleet_read_fn`+`in_scope`, MCP `list_agents` staying deliberately unconfined — the known World-A gap #4041, and the dashboard's service-scoped hand-403 + `device.list.view` denial audit); the DEX/Guardian device lenses split OUT to `device_lens_routes.{hpp,cpp}`, deliberately outside the seam-closure enforced set — unlike `compliance`'s WS-A3 mutator gap, the reason here is that DEX/Guardian are a DIFFERENT family's data awaiting their own future seam, not an un-twinned mutator; two honest, deliberate behaviour deltas: the legacy `GET /fragments/devices/list` fragment's search no longer matches on device tags (`DeviceApi` has no bulk all-agents tag read; the `/devices` page already redirects to `/hardware`, and the single-device detail page still shows tags), and `tags` is now ALWAYS present (as `[]` when empty) on `GET /api/v1/devices/{id}` + MCP `get_agent_details`, where it was previously omitted only in the never-hit-in-production null-TagStore case; `DeviceRow.segment` deleted (never assigned); seam-closure now enforces **4 families** — **MERGED to dev (PR #4484)**); **`feat/split-a4-dex-seam` then applied the template to the FIFTH family, `dex`** (the DEX signals / experience-score surface — `DexApi`, GuaranteedStateStore-backed `/api/v1/dex/*` reads; the pure-type foundation relocated the DEX leaf PODs + `DexFleet`/`DexSignalGroup` out of the CATASTROPHIC `guaranteed_state_store.hpp` + httplib-coupled `dex_routes.hpp` into a pure `dex_types.hpp`, making `dex_read_model.hpp` store-free; the 12 REST `/api/v1/dex/*` signal handlers AND their MCP twins route model assembly through the seam byte-identically (each requires `dex_api` and no longer calls a store-backed builder directly); `/live` + `/perf/*` + `/devices/{id}/app-perf` are deliberately EXCLUDED (the future `DexPerfApi` Seam 2); dashboard + device-lens rewire deferred, tracked **ISSUE #4576** (the `/dex` dashboard fragments need a build-vs-render split that risks HTML drift; the `/fragments/device/dex` lens's DEX half IS routable now via `DexApi::device_score`, but its file's Guardian half shares one `GuaranteedStateStore*` handle and awaits `GuardianApi`, so the file stays store-coupled — the DEX half does NOT itself await GuardianApi); seam-closure now enforces **4 consumer-enforced families + 1 header-only (`dex`)** (dex enforces only the pure seam headers + the impl-purity rule, not a consumer route/renderer TU — a weaker guarantee than the prior 4, honestly stated)); **`feat/split-a4-dex-perf-seam` then applied the template to the SIXTH family, `dex_perf`** (`DexPerfApi` — the DEX app-perf-over-time sequel to `dex`: heartbeat-now `/api/v1/dex/perf/{fleet,cohorts,cohort-diff,devices}` (registry-backed, `DexPerfFn`) + Postgres B1/B2 over-time `/perf/{apps,app,app/devices,group,tag}` + the per-device drill `GET /api/v1/dex/devices/{id}/app-perf`; `/dex/perf/compare` stays `VerifyApi`, excluded. The abstract `dex_perf_api.hpp` is store-type-free from its FIRST commit — the `dex` seam's own PR #4582 leak (a shared model header bundling pure structs with store-pointer builder decls) is applied as a design lesson up front: `dex_app_perf_model.hpp` is split into pure (`dex_app_perf_pure.hpp`) + core-only (`dex_app_perf_builders.hpp`) halves, and two floor-free/no-suppression store-header PODs (`AppPerfVersionDeviceRow`, `AppPerfAppSummary`) are relocated into a new pure `app_perf_types.hpp` (mirroring `dex_types.hpp`); `AppPerfFleetRow`/`AppPerfDailyRow` stay store-side and are denylisted (`EXTRA_STORE_TYPE_TOKENS`) since the floor/audit gates must interpose on them BEFORE anything crosses the seam. `dex_device_app_perf_json` (parked in `dex`'s `dex_read_builders.hpp` pending this seam) is absorbed into its real home. `AppPerfProviders` is DELIBERATELY NOT reused by the seam (a Fable review found its `.cohort` field dead in production, dragging VerifyApi's types into the closure if formalized) — kept unchanged, still wired in `server.cpp` additively alongside the seam, for its one remaining live consumer set (the dashboard fragments, see below). **The REST + MCP consumer rewire landed in the SAME change as the seam build** (mirroring `dex`'s own PR #4582 first-commit shape, which also landed its REST+MCP rewire together): all 9 REST `/api/v1/dex/perf/*` handlers + the `GET /api/v1/dex/devices/{id}/app-perf` drill, and their 9 MCP tool twins + `get_dex_device_app_perf`, call `dex_perf_api`/`dex_perf_api_` exclusively (zero remaining direct `app_perf_providers.<member>()`/`dex_perf_fn()` calls in `rest_api_v1.cpp` or `mcp_server.cpp`, grep-verified). **Only the dashboard (`dex_app_perf_ui.*`, `dex_perf_ui.cpp`) was deferred at the time**, disclosed, mirroring `dex`'s own #4576 dashboard deferral, and tracked as **ISSUE #4626** — it still called `AppPerfProviders`/`dex_perf_fn` directly, which was why that provider bundle could not yet be retired; seam-closure enforced `dex_perf` at the HEADER level only (same posture as `dex`, since the dashboard consumer was not yet routed). Since retired by `feat/split-a4-lens-dashboard-rewire` (#4626) — see the WS-A4 row's "closed three of the deferrals above" bullet. Verified: `g++ -E` on `dex_perf_api.hpp` names zero store types; `[dex_perf_api]` 6 cases/65 assertions green against live PG (parity + `kDexCohortFloor` suppression + ADR-0017 confinement); `[app_perf]` 97 cases/3640 assertions green (two pre-existing REST/MCP test harnesses needed a `FnDexPerfApi` test double — `tests/unit/server/test_dex_perf_api_double.hpp`, mirroring the established `FnVerifyApi` pattern — to keep exercising the now-rewired handlers); `[dex]`/`[mcp]` regression suites unaffected; `meson compile` clean. **WS-B1 Drogon canary added on `feat/split-b1-drogon-canary` — Linux build+link+run proven, `#375` triplet/meson branch untouched, Windows MSVC static leg deferred to CI** — **MERGED to dev (PR #4293)**); **`feat/split-a4-schedule-seam` then applied the template to the SEVENTH family, `schedule`** (`ScheduleApi` — the recurring-schedule READ surface: `GET /fragments/schedules`, `GET /api/v1/schedules`, MCP `list_schedules`, all three routed through the SAME `list_schedules()` call; the unversioned legacy `POST`/`DELETE`/`enable` `/api/schedules` mutators, `schedule_routes.cpp`, are a separate, deliberately untouched capability with no public REST v1/MCP twin — nothing to carve out, unlike `compliance`'s WS-A3 gap. A Fable design review (before any code was written) caught that the seam-closure lint's store-detection heuristics (`*_store.hpp` suffix, `pg/*.hpp` includes) do NOT catch `ScheduleEngine`/`WorkflowEngine` — both are Postgres-backed but named `*_engine.hpp` — so `FORBIDDEN_HEADER_PATTERNS` and `EXTRA_STORE_TYPE_TOKENS` gained an explicit pair for each, closing a blindness the `dex` seam's #4582 leak didn't even have a chance to hit (that leak was at least catchable by the `*Store` suffix). `InstructionSchedule`/`ScheduleQuery`/`ScheduleListResult` relocated out of `schedule_engine.hpp` into a pure `schedule_types.hpp` (compliance_types.hpp precedent); `schedule_row_json` split out of the entangled `workflow_model.hpp` (which previously bundled it with the unseamed `workflow` family's builders and `#include`d BOTH `schedule_engine.hpp` AND `workflow_engine.hpp` despite claiming "pure, I/O-free" — that claim was false and is now corrected) into a genuinely pure `schedule_model.{hpp,cpp}`. **A deliberate, disclosed behaviour delta** (unlike most prior seams' byte-identical posture): the dashboard fragment was upgraded from the unchecked `ScheduleEngine::query_schedules()` to the seam's honest `list_schedules()` (same checked call REST v1/MCP already used), so a store failure now renders a distinct degraded state instead of the previously-indistinguishable "No schedules configured" — proven by a new `FnScheduleApi` test double (`test_schedule_api_double.hpp`) injecting a store failure directly into the fragment, something no test harness could do before this seam existed. Seam-closure enforces `schedule` at the HEADER level only (same posture as `dex`/`dex_perf`, for the same multi-family-consumer-TU reason — `workflow_routes.cpp` also holds the unseamed `workflow` family's routes — NOT because a rewire is outstanding: both REST v1 and the dashboard fragment ARE rewired). Verified: `g++ -E` on `schedule_api.hpp` names zero store types; `[schedule_api]` 3 cases/25 assertions green against live PG; `[schedules]`/`[workflow]` (122 cases) / `[mcp]` (917 cases, 21277 assertions) regression suites green; `check-seam-closure.py` + its selftest green; `meson compile` clean); **`feat/split-a4-workflow-seam` then applied the template to the EIGHTH family, `workflow`** (`WorkflowApi` — the multi-step-workflow READ surface: `GET /api/v1/workflows`, `GET /api/v1/workflows/{id}`, `GET /api/v1/workflow-executions/{id}`, and their MCP twins `list_workflows`/`get_workflow`/`get_workflow_execution`, all three routed through `WorkflowApi::list_workflows`/`get_workflow`/`get_workflow_execution`; the legacy unversioned `GET /api/workflows[/{id}]`/`GET /api/workflow-executions/{id}` reads and every `POST`/`DELETE`/`.../execute` mutator (`workflow_routes.cpp`) are a separate, deliberately untouched capability with no public REST v1/MCP twin of their own — nothing to carve out, unlike `compliance`'s WS-A3 gap. `Workflow`/`WorkflowStep`/`WorkflowExecution`/`WorkflowStepResult`/`WorkflowQuery` relocated out of `workflow_engine.hpp` into a pure `workflow_types.hpp` (`workflow_engine.hpp` re-`#include`s it, ODR-safe, mirroring `schedule_types.hpp`'s own relocation); `workflow_model.hpp` needed no FURTHER split — it DID originally bundle another family's builder (`schedule_row_json`), but the seventh family's own PR already split that out into `schedule_model.hpp`, so by the time `workflow` landed there was nothing left to carve out and making the remainder genuinely pure was a one-line include swap from `workflow_engine.hpp` to `workflow_types.hpp`. **Unlike `schedule`, this seam introduces NO behaviour delta**: `WorkflowEngine::list_workflows`/`get_workflow`/`get_execution` already returned a checked `std::expected` to their pre-seam REST v1/MCP callers (the honest-empty-vs-failure distinction `schedule`'s own seam had to newly introduce for its dashboard fragment was already present here), so `LocalWorkflowApi` is a byte-identical thin wrap in production, with one PRECISE, disclosed exception rather than a blanket "no delta" claim (adversarial-review round finding: the original wording overclaimed here): `GET /api/v1/workflows`' AND MCP `list_workflows`' pre-seam separate `!is_open()` pre-check (both routes carried the identical guard) is dropped, so an engine that is non-null but NOT open now answers the genericized `service unavailable` + `retry_after_ms:5000` (via the seam call's own internal `!open_` guard) instead of the base's plain `workflow engine not available` with no retry hint — a real body/status delta for that ONE state, unreachable in production regardless, since ADR-0012 fails the whole server closed at boot on a migration failure before any request-serving code runs. `workflow_api_local.hpp`'s factory doc comment says the engine must be "known live" before the factory is called; `test_workflow_api.cpp`'s own degrade test deliberately violates that to prove the seam forwards the AUTHORITATIVE degrade rather than swallowing it — a fixture-only, documented exception to the factory's stated contract, not a production path. The MCP twins route through a new member `workflow_api_`/`set_workflow_api` rather than a `build_handler` parameter, mirroring `schedule`'s own `set_schedule_api` setter idiom — `build_handler`'s own `WorkflowEngine* workflow_engine` parameter is now UNUSED inside these three tool bodies, kept unremoved for constructor-signature stability across its two forwarding overloads (a disclosed, deferred follow-up, not an oversight — this sentence is that disclosure). Seam-closure enforces `workflow` at the HEADER level only (same posture as `dex`/`dex_perf`/`schedule`, for the same multi-family-consumer-TU reason — `workflow_routes.cpp` is itself the family's own multi-purpose file, holding the legacy GET/mutator routes alongside the seamed ones — NOT because a rewire is outstanding: both REST v1 and MCP are fully rewired). Verified: `g++ -E` on `workflow_api.hpp` names zero store types; `[workflow_api]` 5 cases/39 assertions green against live PG (wiring + an unopened-engine degrade probe on all three methods); `[workflow]` 130 cases/1489 assertions green (route + engine regression, plus a new `FnWorkflowApi`-injected store-failure test on `GET /api/v1/workflows` proving the `genericize_db_error` degrade without a live broken-schema Postgres connection); `[schedule_api]`+`[schedules]` 14 cases/118 assertions green (unaffected by `workflow_model.hpp`'s purification); `[mcp]` 921 cases/21304 assertions green; `check-seam-closure.py` + its selftest green; `meson compile` clean — full `yuzu_server_tests` link succeeded. **Adversarial-review round (FortitudeEtc, Kimi K3 + Codex Sol cross-examined) found a MEDIUM gap: five of the six rewired handlers (all but the original `GET /api/v1/workflows` degrade test) had no test proving they call the seam rather than the raw engine — a mutation run reverting each to `workflow_engine` directly passed unchanged.** Closed with 6 new seam-bypass tripwire tests (3 REST, 3 MCP — one per rewired route/tool, including a clean non-crashing replacement for the list route's own prior crash-only guard), each wiring a REAL `WorkflowEngine` holding genuine data AND a DISTINGUISHING `FnWorkflowApi`/`workflow_api_for_test` double at the SAME id, so the two doors answer differently and a revert flips the test from pass to fail — empirically re-verified by reverting `GET /api/v1/workflows/{id}` on a scratch copy, confirming its new test failed cleanly, then restoring and re-confirming green. The round's four wording nits (this paragraph's own prior "byte-identical"/"never bundled" overclaims, the seam-closure docstring's stale "seven families", and the changelog's legacy-GET/mutator conflation) are also fixed in place.); **`feat/split-a4-guardian-seam` then applied the template to the NINTH family, `guardian`** (`GuardianApi` — the Guardian / Guaranteed State read surface: `GET /api/v1/guaranteed-state/{rules,rules/{id},status,status/{agent_id},rules/{id}/status,agents/{id}/rules,device-compliance,events}` — eight of the family's nine public REST+MCP resources; the ninth, `GET /guaranteed-state/schemas` / MCP `get_guardian_schemas`, is DELIBERATELY excluded — a compiled-in, store-free catalog with no store call for REST/MCP to drift on, so it keeps calling `guardian::guardian_schema_catalog()` directly, exactly like the unrelated `GET /discover/scope` route. `guardian_types.hpp` (the family's pure header) carries TWO relocations, not one: `GuaranteedStateRuleRow`/`GuaranteedStateEventRow`/`GuaranteedStateEventQuery`/`GuaranteedStateReadError` out of `guaranteed_state_store.hpp` (the `dex_types.hpp`/`schedule_types.hpp` precedent), AND the six pre-existing pure result structs (`GuardianStatusRollup` through `GuardianDeviceComplianceRollup`, plus its nested `GuardianDeviceComplianceGuardRow`) out of `guardian_model.hpp` — that second relocation is NEW to this family: `guardian_model.hpp`'s own function declarations forward-declare `GuaranteedStateStore`/`BaselineStore` and so cannot itself sit in the abstract header's closure (the abstract-header probe text-scans for a bare `*Store` token, catching even a forward declaration), a constraint no prior family's shared model header happened to hit. **Design correction mid-build, caught by the OWN test suite, not by review**: the first cut gated `guardian_api`'s CONSTRUCTION on both `guaranteed_state_store_` AND `baseline_store_` being present (mirroring `workflow_api`'s/`schedule_api`'s single-required-reference shape) — this broke ~30 pre-existing REST/MCP test cases that (correctly, matching production reality where seven of the eight methods never touch `BaselineStore` at all) wire only `GuaranteedStateStore` when exercising a non-`device_compliance` tool. Reverted to `dex_perf_api`'s own established shape instead: BOTH store pointers nullable, `guardian_api` constructed UNCONDITIONALLY, each method null-guards its OWN dependency (`device_compliance` alone needs both) — same "a null store/reader degrades the corresponding method to nullopt, matching the resource's existing store-unavailable 503 today" trade-off `dex_perf_api_local.hpp` already accepted, including its one disclosed wording simplification (a genuinely-unwired dependency and a live read-degrade now render the SAME 503 message, where the pre-seam handlers used two; neither REST nor MCP surfaces the distinction today, and the unwired case is unreachable in production regardless — `guaranteed_state_store_`/`baseline_store_` fail the whole server closed at boot per ADR-0012 §1 if either can't open). `device_lens_routes.cpp`'s `/fragments/device/guardian` fragment is NOT rewired onto this seam, mirroring `dex`'s own device-lens deferral (#4576) verbatim — tracked as its own follow-up, not done here. `guardian_routes.cpp`'s dashboard fragments stay OUTSIDE the seam-closure enforced set (interleaved read+mutator TU, same posture as `dex`/`dex_perf`/`schedule`/`workflow`'s own multi-purpose consumer files — a `policy_admin_routes.hpp`-style mutator carve-out is a disclosed, separate follow-up). **Governance round (security-guardian + docs-writer + architect + cpp-expert + cpp-safety + quality-engineer, all six in parallel): zero CRITICAL/HIGH; one BLOCKING quality-engineer finding** — no seam-bypass tripwire test existed for `guardian`, unlike every one of the 6 prior families with a store-backed multi-family consumer TU (`dex`/`dex_perf`/`schedule`/`workflow`; `rest_api_v1.cpp`/`mcp_server.cpp` are INSPECTED-NOT-ENFORCED and already `#include guaranteed_state_store.hpp` for the mutators, so a silent revert of a read handler to the raw store compiles clean and stays green). Closed with 16 new seam-bypass tripwire tests (8 REST + 8 MCP, one per rewired resource/tool — full parity with the family's method count, going further than `workflow`'s own 3+3 subset since `guardian` has 8 methods not 3), each wiring a REAL store (or, for `list_rules`/`status`/`status/{agent_id}`, a real store ALSO holding genuinely different data) AND a DISTINGUISHING `FnGuardianApi` double at the same id/key, so a revert-to-raw-store flips the test from pass to fail — `tests/unit/server/test_guardian_api_double.hpp` is the new double, mirroring `FnWorkflowApi`'s shape across all 8 methods. Four SHOULD/NICE doc-staleness findings (3 independently converged on the SAME defect — security-guardian, docs-writer, and cpp-expert each separately caught a "server.cpp wires this iff BOTH stores present" comment in `mcp_server.hpp`/`rest_api_v1.hpp` left over from the reverted both-required design) fixed in place: the two stale param/setter doc comments, `check-seam-closure.py`'s own family-comment incorrectly listing `schemas` among the seamed routes, and `device_lens_routes.hpp`'s banner (architect finding — "until DEX/Guardian get their own seam" was unconditionally false for both named systems the moment this PR landed, since DEX already had one). **PR review round 1 (#4744): one BLOCKING, fixed** — 2 of those 16 tripwires (REST `rules/{id}/status`, MCP `get_guardian_rule_status`) were NOT revert-sensitive on the handler's `get_rule()` existence pre-check (the real store and the double both answered `r1`, so reverting only that leg stayed green — a false-green closure test, a governance policy floor); both now query an id only the double knows, so each of the handler's two seam calls is independently revert-sensitive. Also fixed from the same review: the null-baseline degrade test now asserts all seven store-only methods live (it exercised two), a null-store/live-baseline `device_compliance` test added, the `list_events` null-store path disclosed as an empty 200 (not the pre-seam 503; unreachable in production), and the governance ledger fragment committed. Verified: `g++ -E` on `guardian_api.hpp` names zero store types; `check-seam-closure.py` + its selftest green (nine families); `[guardian_api]` 11 cases green against live PG (wiring + the null-store / null-baseline-only (all seven store-only methods asserted live) / null-store-with-live-baseline degrade probes + a non-empty `list_events` round-trip); `[guardian]`+`[guardian_routes]`+`[guaranteed_state_store]`+`[adr0017]`+`[device_guards]`+`[baseline]`+`[twins]` 43+281 cases green; `[mcp]` 935+ cases green; `meson compile` clean.) Re-stamp
this line whenever the table is revised — a matrix from a stale checkout is worse than none, and the
current-state claims below were wrong in the first draft because they were copied from stale ADR status
columns. Grep the tree, don't trust a doc.

> **⚠️ Standing instruction — update on close.** Every PR that closes or materially changes the status
> of a workstream in this matrix MUST update that row **and** re-stamp the Verified line in the SAME PR.
> Treat status drift as a review-blocking defect, exactly like a stale doc comment.

**Companion docs:** `docs/adr/0031-presentation-core-engine-decomposition.md` (INV-31-1..6, the 5-step
migration), `docs/adr/0032-use-case-admission-protocol.md` (the interlock — binds immediately on
acceptance), `docs/adr/0033-access-control-spine.md`, `docs/adr-1005-execution-plan.md` (M3 = the NVD
matcher-parity gate, *not* the fragment↔REST programme), `docs/adr/2002-high-availability-architecture.md`
(§4/§5 — MCP session + replay ring → durable core outbox), `docs/ha-delivery-matrix.md` (the HA
deliverables this split *consumes*).

---

## ⚠️ Current-state is grepped from the tree, not the ADRs (the docs are stale)

The first draft asserted a falsified current state; a three-model adversarial panel (Fable /
`gpt-6-astra` / Kimi-K3) caught it. Verified:

- `authorize_list_read` **exists** — 142 occurrences (was 66 at the 2026-09-17 stamp; the per-family seam
  cutovers added confined reads), `server/core/src/rbac_store.hpp:340`, live callers,
  pinned by `tests/unit/server/test_list_read_confinement.cpp` (`[1715]`). `require_list_read` (ADR-0017
  PR-A) shipped. **#1714 / #1715 / #1716 CLOSED.** Engine-principal RBAC enforcement shipped.
- **The real engine-gate blocker is #2665 (OPEN)** — #1715 shipped **additive** authorization (a global
  deny does not override a management-group allow); ADR-0032 interlock **(b)** needs **deny-precedence**.
  This ADR-level contradiction must be named, not assumed satisfied.
- Absent (0 occurrences): `use_case_run_id`, the release-log store, the `evaluate_as_operator` seam — so
  the admission/grant/audit substrate (interlock c/d/h) is open while confinement (a/b-partial) shipped.
- **The INV-31-4 GLOBAL contract test EXISTS and is green** — `scripts/ci/check-api-parity.py` (whole-tree
  CI gate) + `tests/unit/server/test_openapi_spec_completeness.cpp` (in-process `TestRouteSink` half),
  shipped out-of-band under **#842 / #3991 / #3992**; `/api/vN` drift is zero (196 routes / 195 OpenAPI
  entries / 1 allowlisted CORS `OPTIONS`). **ADR-0031's "that test does not exist today" is STALE**
  (corrected 2026-09-08). **Caveat:** it's a **LEXICAL tripwire, not a proof** (scans `server/core/src/*.cpp`
  only) — a literal registration absent from OpenAPI fails the build; a non-literal *direct* verb call warns
  (exit 0); a helper- or header-defined registration (e.g. a `register_*(sink, "/path", …)` helper whose
  body makes the verb call) escapes **SILENTLY** — no warning, no failure (type-aware successor #2572). So WS-A4's contract-test half is DONE *for literal registrations*; what remains is the
  *per-family* seam enforcement (gates WS-B2) for the remaining families not yet done, and the handler→API seam
  refactor — do NOT rebuild the global test.
- **The FIRST per-family seam landed: `network` (2026-09-10), then split into the two-header template
  (2026-09-11, #4249); **`verify` followed as the SECOND family** (#4250, `/auto` VERIFY app-perf
  compare — `VerifyApi`, all 3 consumers routed).** The seam is now TWO headers, not one: `network_api.hpp` is the ABSTRACT
  `NetworkApi` interface + `NetDeviceQuery` — a presentation TU's whole view of the family, with ZERO
  store-type references, not even a forward-declaration; `network_api_local.hpp` is CORE-ONLY — it holds
  the store-backed factory `make_local_network_api(...)`, the store forward-decls the factory signature
  needs, and the lifetime contract doc — and is included only by `network_api.cpp` (the impl),
  `server.cpp` (wiring), and `test_network_api.cpp` (tests), never by a route/renderer/model TU. The
  method set equals the family's public REST resources (`fleet_now` == `GET /api/v1/network/fleet`,
  `device_list` == `GET /api/v1/network/devices`). **All three consumers route through the abstract
  header** — the dashboard fragments (`network_ui.cpp`), the REST handlers (`rest_api_v1.cpp`), and the
  MCP tools (`get_network_fleet`/`list_network_devices` in `mcp_server.cpp`) — replacing the old ad-hoc
  `net_perf_fn` provider/memo that `server.cpp` used to assemble. This two-header shape is the
  **per-family pattern the remaining families copy**: API methods == public REST resources;
  renderers/handlers consume the API's response shapes, never a raw internal read model or a `Store*`;
  the store-backed impl and its factory stay in the `<family>_api_local.hpp` half; the
  caller-context/audit-at-API contract is deferred to the WS-A2r contract design (today's handlers still
  call `emit_behavioral_audit` themselves, unchanged). **Enforcement scope is honest and partial**,
  piloted by `scripts/ci/check-seam-closure.py`'s include-closure lint: the network dashboard/routes/
  model/api translation units are ENFORCED store-free, and #4249 added a FOURTH forbidden pattern,
  `*_api_local.hpp`, so those same TUs are also enforced against reaching the core-only factory header —
  the abstract/local boundary is CI-enforced, not conventional (pinned by
  `tests/test_seam_closure_selftest.py` probes 7/8: a synthetic presentation TU reaching a
  `*_api_local.hpp` fires and names the chain; one reaching only the abstract half passes).
  `rest_api_v1.cpp` and `mcp_server.cpp` are multi-family TUs holding real store access for many other
  families, so their per-family sections are INSPECTED-NOT-ENFORCED (reviewed by hand, not gated) until a
  block- or symbol-scoped successor exists. **Two decisions recorded, not re-decided:**
  (1) `network_api_local.hpp` itself IS in the lint's enforced TU set, so its own purity (forward-decls
  only, zero store `#include`s) is lint-enforced, not review-only. (An earlier draft kept it out on the
  belief it would self-match `*_api_local.hpp` by basename; governance disproved that — a TU is excluded
  from its own include closure, so it never self-matches — and enforcing it closes the gap for free.)
  The presentation-visible CONTRACT is a PAIR that moves together at WS-B2: `<family>_api.hpp` plus the
  family's pure model header (`network_perf_model.hpp` here); an impure model header breaks the abstract
  header even when the abstract header itself is clean, so families copy the pair. **`verify` (#4250) is the first family that had to CONSTRUCT its pure half rather than inherit it:** unlike `network` (whose `network_perf_model.hpp` already held everything the seam needed), `verify`'s pure model header (`app_perf_compare.hpp`) did not — so #4250 (a) relocated the shared validator `app_perf_param_valid`/`kAppPerfParamCap` OUT of the store-coupled `dex_app_perf_model.hpp` into it (definition unmoved, re-exposed transitively so no existing consumer's include changed), and (b) defined `VerifyRoutes::AuditFn` LOCALLY rather than alias `DexRoutes::AuditFn`, because `dex_routes.hpp` transitively reaches the B1 store headers. The lesson generalises: the pair a family copies is *the abstract api header + a pure model header*, and any pure helper a presentation TU needs (validators, caps, audit-fn shapes) must be made to live in the pure header, moved there if it currently sits in a store-coupled one. (2) the new pattern is a
  NAMING CONVENTION, not a structural one — only a header literally named `*_api_local.hpp` is caught, so
  a family that names its factory header differently (e.g. `<family>_factory.hpp`) is invisible to the
  gate; the template therefore PRESCRIBES the `<family>_api.hpp` (abstract) + `<family>_api_local.hpp`
  (core-only factory) names for every family that copies this pattern.
  **The pilot also closed an A1 dashboard-parity gap it surfaced**: `available_keys` (the cohort-picker
  tag-key list) was on the dashboard fragment but absent from the public REST/MCP fleet resource — now
  added to `NetPerfFleetNow` and serialized on `GET /api/v1/network/fleet` (JSON + OpenAPI) and MCP
  `get_network_fleet` (payload + typed output schema). NB the seam design deliberately DIVERGES from DEX
  here — DEX serves `available_keys` only from its dedicated `GET /api/v1/dex/perf/cohorts` route (never
  its pollable fleet endpoint), whereas network has no cohorts route and so surfaces the distinct tag KEYS
  on the fleet resource itself, resolved unconditionally in `fleet_now` (the distinct-key namespace does
  not depend on a cohort key) and bounded by the 5s snapshot memo. A round-2 governance finding (4 agents)
  caught that the first cut gated this on `!cohort_key.empty()`, leaving the field structurally always `[]`
  on the key-less fleet surface; fixed + locked by a `fleet_now("")` test.
  Behaviour is otherwise byte-identical; the `network.device.view` audit and its deny stayed in the
  handlers, unchanged.
- **`compliance` is the THIRD family (`feat/split-a4-compliance-seam`) and needed MORE than `verify`
  did.** (a) Unlike `verify`, `compliance` had no pre-existing pure model header to construct a pure
  half *inside* — the whole type cluster (`Policy`, `PolicyFragment`, `PolicyTrigger`, `PolicyInput`,
  `PolicyGroupBinding`, `PolicyAgentStatus`, `ComplianceSummary`, `FleetCompliance`, `PolicyQuery`,
  `FragmentQuery`, `PolicyReadError`, plus a NEW `PolicyDetail` composite) was relocated OUT of the
  pg-coupled `policy_store.hpp` into a new pure `compliance_types.hpp` — `policy_store.hpp`
  re-`#include`s it so existing includers keep seeing the types transitively (ODR-safe pure
  relocation, not a duplication; `class PolicyStore` and its mutator-only helpers stay in
  `policy_store.hpp`), and `compliance_model.hpp` was made pure by flipping its one store include to
  `compliance_types.hpp`. (b) `compliance` is the FIRST family whose routes file mixed seamed reads
  with un-twinned mutators: `compliance_routes.cpp` carried both the `GET` resources this seam fronts
  AND the policy/fragment POST/DELETE/enable/disable/invalidate/evaluate/remediate handlers, which have
  no public REST v1 or MCP twin. Those mutators moved verbatim to new `policy_admin_routes.{hpp,cpp}`,
  which deliberately keeps direct `PolicyStore`/`PolicyEvaluator` access and sits OUTSIDE
  `check-seam-closure.py`'s `compliance` family — the split discriminator is **"has a public REST/MCP
  twin" (INV-31-4)**, never read-vs-write; a mutator that later grows a public twin is the one that
  would move back into the seamed file. **This is a live WS-A3 gap, not a done cutover**: the
  compliance family's read surface is seamed and enforced, but its mutators have no versioned public
  twin yet, so `compliance` is not fully WS-B2-cutover-ready until that gap closes (tracked #4334) —
  do not read `compliance` as "done" the way `network`/`verify` are for their narrower read-only
  scope. Separately, a pre-existing confinement/audit gap on the legacy `GET /api/compliance/{id}`
  route was found and is intentionally kept byte-identical rather than fixed in this seam PR (tracked
  #4333, out of scope for a behaviour-preserving refactor).
- **`device` is the FOURTH family (PR #4484, MERGED to dev)** — the narrowest method set yet
  (`list_devices`/`lookup_device`, 1:1 with `GET /api/v1/devices[/{id}]`, INV-31-4), unifying the
  THREE live consumers (dashboard `device_routes.cpp`, REST v1, MCP `list_agents`/`get_agent_details`)
  behind one store-free `DeviceApi` (`device_api.hpp` + core-only `device_api_local.hpp`, the same
  two-header template). Authorization is BYTE-IDENTICAL per consumer, not merely "equivalent" —
  REST keeps `fleet_read_fn`+`authz::in_scope`, MCP `list_agents` stays deliberately unconfined
  (the known World-A gap, #4041 — not fixed here), and the dashboard keeps its service-scoped
  hand-403 + `device.list.view` denial audit, now filtering `api_->list_devices()`'s unscoped rows
  through the SAME `visible_set_fn` `get_visible_agents_json` already applied. `lookup_device` is an
  O(1) registry point lookup (mirrors `network`/`verify`/`compliance`'s posture): the #3564
  timing-oracle fix — a miss and an out-of-scope hit must take the identical not-found path, including
  when the backing tag-store read is itself degraded — now covers the REST detail route too, not just
  MCP. **DEX + Guardian lenses split OUT** to `device_lens_routes.{hpp,cpp}` — outside `DeviceApi`'s
  own narrow 1:1 contract (they serve those FAMILIES' own data, per-device signal summary / per-guard
  compliance state, not `device`'s), but now ENROLLED in `check-seam-closure.py`'s `device` family as
  that family's own second presentation TU: `feat/split-a4-lens-dashboard-rewire` rewired both
  fragments onto `DexApi::device_score`/`GuardianApi::device_guards` (closing #4576's lens half and the
  `guardian` family's own device-lens deferral), so this file no longer touches `GuaranteedStateStore*`
  directly — see that PR's own behaviour delta (a zero-guard device now renders "No guards evaluated"
  even under a degraded rule-catalogue read). **Two honest, deliberate behaviour deltas, both because
  `DeviceApi` has no bulk/live "scopable tags" read (a different concept from the persistent `TagStore`
  operator tags `DeviceDetail` carries):** (1) the legacy `GET /fragments/devices/list`
  fragment's search no longer matches on device tags — no test exercised tag-search, so this is a real
  but minor functional narrowing; the `/devices` page already redirects to `/hardware` (unaffected) and
  the single-device *detail* page still shows operator tags unchanged. (2) `tags` is now ALWAYS present (as `[]`
  when empty) on `GET /api/v1/devices/{id}` and MCP `get_agent_details`, where the pre-rewire code
  OMITTED the key only in the null-TagStore case — a case that never occurs in production (TagStore is
  a core Postgres store; the server fails closed without it). `DeviceRow.segment` (dashboard-only) is
  deleted — confirmed never assigned anywhere in the tree even before this rewire, not merely unused by
  this file. `online`/`last_seen` are unchanged in effect (still the same hardcoded `true`/"now"
  constants, reproduced render-side instead of via a provider closure). Seam-closure now enforces
  **4 families**.
- **The `*_ui.cpp` audit-relocation premise below (and previously in the WS-A4 row) was FALSE — corrected
  here.** Verified against the tree: the behavioural-PII audit was NEVER in `*_ui.cpp` (those are pure
  render functions with zero audit calls); `emit_behavioral_audit` is already centralized in
  `rest_audit.hpp` and called only from `*_routes.cpp`/`rest_api_v1.cpp`. What "PII-audit relocation"
  actually means: at the WS-B2 presentation cutover, the presentation-side handler's `network.device.view`
  (and siblings') audit call becomes redundant with core's REST-side audit and must be REMOVED there, not
  duplicated — a double row per view would corrupt works-council countability. The relocation is
  handler→API-at-cutover, never `*_ui.cpp`→anywhere.
- **WS-B1 Drogon canary — Linux green; the Windows MSVC static-link risk, stated concretely so a CI
  result is interpretable.** Drogon 1.9.12 (trantor 1.5.26, jsoncpp 1.9.6) is at the pinned
  `builtin-baseline`, added UNCONDITIONALLY (default features only). On Windows the base
  `triplets/x64-windows.cmake` linkage is `dynamic`, and drogon/trantor/jsoncpp/brotli are NOT in the
  `#375` static-override list (`abseil|grpc|protobuf|upb|re2|c-ares|utf8-range`), so they build as
  ordinary DLLs + import libs — the SAME shape as sqlite3/libxml2 (which use `method:'cmake'` on
  Windows) and libpq (hand-wired `find_library` on Windows — same dynamic-DLL shape), none hitting
  LNK2038. So the canary uses the uniform cmake-dep pattern, not the
  hand-wired static branch. **What the canary proves, and its two Windows caveats (corrected per the WS-B1 governance round):**
  it proves Drogon **links and loads** into the matrix. It is registered as a meson test so CI *runs* it
  (not just builds it), surfacing a load-time failure. Its body forces `drogon::app()` (the inline forwarder to the out-of-line `HttpAppFramework::instance()`) and marshals **no
  STL across the DLL boundary**, so it does NOT by itself validate the C++ ABI hazard below — that, and
  Drogon+gRPC coexistence, are WS-B2 concerns. (1) **Runtime CRT / `_ITERATOR_DEBUG_LEVEL` mismatch (NOT
  a link-time LNK2038).** On Windows Drogon is a dynamic DLL; an MSVC import lib carries no
  iterator-debug/`detect_mismatch` records (those live in the DLL's objects), so the debug leg **links
  green**. The `#375`-era concern was that meson's cmake translator read `IMPORTED_LOCATION_RELEASE` even for
  `--buildtype=debug`; that premise is NOT re-verified against the pinned Meson 1.11.1, whose
  translator (`mesonbuild/cmake/tracetargets.py`) selects `cfg='DEBUG'` and prefers
  `IMPORTED_IMPLIB_DEBUG` when the target exports a DEBUG config (Drogon's does) — so a `/MDd` debug
  exe loading a `/MD` release DLL is a POSSIBLE-but-unconfirmed mismatch that
  could bite at **runtime** when STL crosses the boundary — but this is a HAZARD TO VALIDATE, not a
  proven outcome: the repo's own debug-build DLL selection may already resolve it. Meson picks
  the debug-config Drogon import lib (`debug/lib/drogon.lib`) for the DIRECT dependency on a debug build, `ci.yml` prepends
  `vcpkg_installed/x64-windows/debug/bin` to PATH before the Windows debug `server-checks` step, and
  `deploy_build_dlls.py` selects the matching-config DLL dir — so the loader may resolve the debug DLL
  by name regardless of what the import lib recorded. The open question is whether the debug/release
  Drogon DLLs share a filename (no `DEBUG_POSTFIX`). If they share a name, PATH order resolves the debug
  one; if they differ, the outcome depends on what ends up beside the exe — `deploy_build_dlls.py`'s
  secondary gap-fill can copy the other config's differently-named DLL, which could then LOAD (a silent
  mismatch) rather than fail. Either way the categorical "loads the release DLL" claim is unproven. A future STL-marshalling canary + a
  `dumpbin`/import-provenance assertion resolve this at WS-B2 before prescribing the `#375` option-D
  (build-type-conditional import lib) fix — which would not touch the grpc branch. (2) **c-ares double-linkage (LNK2005) — the canary does
  NOT and CANNOT exercise this.** It links drogon/trantor only, never gRPC, so there is a single
  (static, trantor-internal) c-ares copy. The two-copy LNK2005 hazard needs gRPC + trantor in one link,
  i.e. the presentation binary linked beside the core gRPC stack — a WS-B2 concern, and per ADR-0031 the
  two live in *separate binaries* so they may never co-link. Linux resolves the `$<LINK_ONLY:...>`-dropped
  transitive set explicitly (OpenSSL/c-ares/zlib/uuid/brotli via pkg-config); Windows dynamic DLLs resolve
  their own deps at load, so that append list is best-effort there. A Windows link/load red here is the
  gate working — report it, do not paper over it. **The Windows PR leg is the ONLY leg that exercises the
  dynamic-DLL LOAD assertion** (Linux builds+links only); it is skipped when the Wee Tam pool is
  unhealthy, so branch protection must treat a skipped Windows context as NOT-pass, and a CI presence
  tripwire should guard the canary from silently ceasing to run (#4296). **WS-B2 follow-ups surfaced by this round:** feature-gate
  Drogon to a server vcpkg feature (agent/ASan/cross legs currently build it unused; #4295), a
  STL-marshalling canary + a `dumpbin`/`ldd` import-provenance assertion, the Drogon+gRPC coexistence
  link test, and adding Drogon/trantor/jsoncpp to `NOTICE`'s third-party attribution list once a shipped
  binary links them. (Drogon's transitive tree already appears in the release SBOM today — `release.yml`'s Syft
  scan covers `path: .` incl. `vcpkg_installed`, per this PR's changelog fragment — so SBOM pickup is
  NOT a WS-B2 deferral.)

---

## Two axes + a cross-cutting lane (read first)

- **Axis A — logical seam / authority (monolith-OK).** Public versioned API as sole authority; every
  handler/renderer calls the API, never a store pointer; the INV-31-4 contract test; the ADR-0032/0033
  confinement + admission + audit substrate. *Makes the split correct.* Almost all buildable while one
  binary.
- **Axis B — physical decomposition.** Drogon + G10, strangler cutover, extract presentation, extract
  engine, state relocation, event spine, component service identity, `uce` DB decomposition, supervision,
  per-binary `/readyz`. *Makes the split real.*
- **Lane X — cross-cutting / continuous.** Fan-out measurement, version-skew compat, split-topology
  config, split observability, validation harness, credential hardening.

"The split shipped" as a claim = the presentation binary extracted (all families cut over, httplib
presentation retired) **and** the engine binary extracted behind its interlock gate. The two extractions
are ordered: engine is **fifth** (ADR-0031 §5), after presentation.

---

## ⚠️ STANDING MERGE-GATE — the ADR-0032 interlock binds immediately

**No engine-path code — anything that admits a run, mints a grant, serves a use-case result, or composes
released facts — merges into ANY binary until the unconditional interlock set (a)–(d)+(h) lands
complete**, including (h)'s full credential fields (admitting-credential id, frozen grant snapshot,
requesting-credential id). This binds *now*, independent of packaging: reference-and-defer is safe for
*who owns* a prerequisite, never for *whether it gates a merge*. WS-A2a and WS-A6 live under this gate.
WS-0 certifies no in-flight engine-path ballot ships before it closes.

## ⚠️ The safe-to-extract gate (the load-bearing constraint) — ONE table

The strangler's **first live family cutover** is the real extraction moment — the first request to cross
into a separate process reaching core over the network. The gate governs *that*, and each subsequent
family. WS-B8 (httplib retirement) is the *completion*, never the trigger. **A component is extractable
only when every clause below is green for the family being cut.**

**safe-to-extract(PRESENTATION)** — before any family's live cutover:

| Clause | Row | Invariant / source |
|---|---|---|
| Seam enforced + INV-31-4 test green for that family | WS-A4 | INV-31-4, migration step 3 |
| That family's public REST+MCP capabilities exist | WS-A3 | migration step 3 sizing |
| Sessions + MCP replay relocated & durable | WS-B3 | ADR-2002 §4/§5 |
| Event spine live on the HA WS-2a outbox | WS-B4 | G1; ADR-2002 §5 |
| Component service identity live | WS-B6 | INV-31-5, Decision 6 |
| Presentation `/readyz` composed (never green while core down) | WS-B7 | INV-31-6 |
| Drogon build canary green | WS-B1 | G10 |
| K-fanout measured / accepted | WS-X1 | Cost K, gate on step 4 |
| Version-skew compat enforced | WS-X2 | Decision 6 (two deployable units) |
| 6a break-glass surface live | WS-X4 | Decision 6a |
| Presentation holds zero DB credentials | WS-B11 | INV-31-3 |
| Per-family seam+contract check + rollback path | WS-B2 | strangler safety |

**safe-to-extract(ENGINE)** — before WS-B9:

| Clause | Row | Source |
|---|---|---|
| Presentation already extracted (engine is fifth) | WS-B8 | ADR-0031 §5 |
| Interlock (a)–(d)+(h) complete | WS-A6 / WS-A5 | ADR-0032 (the merge-gate floor) |
| #2665 resolved (deny-precedence) + `evaluate_as_operator` seam built | WS-A5 | ADR-0032 (b) |
| Exec semantics (i) | WS-A1 | ADR-0032 (i) |
| Engine readiness (k) · cross-run isolation (l) · per-principal quota (m) | WS-B9 | ADR-0032 (k)(l)(m) |
| `uce` DB decomposition — engine cannot reach `yuzu`, core no grant on `uce` | WS-B11 | INV-31-3 |
| Engine boundary (B2-contract) security: grant + input-hash verification at the engine | WS-B9 | Decision 2/7 |
| Joined cross-boundary audit evidence | WS-A4 / WS-X5 | audit continuity |

Miss any and the failure is **structural, not cosmetic**: a renderer still holding a `Store*` after
cutover means the boundary didn't remove the coupling; a `/readyz` green while core is down hides an
outage; an engine composing facts before the interlock enlarges authority core never confined.

---

## The matrix — current state, reviewers, status

Columns: **WS · Delivers · Axis · Owner · Depends · Gates cutover? · Reviewers · Status**.
`Owner=THIS` = net-new here; else status is *pulled* from the named source (re-verified by WS-0).
`Gates cutover?` = does the safe-to-extract gate depend on this row (P = presentation, E = engine).

| WS | Delivers | Axis | Owner | Depends | Gates? | Reviewers | Status |
|----|----------|:---:|-------|---------|:---:|-----------|--------|
| **WS-0** | Reconciliation & **interlock certification** — re-verify every deferred item **against the tree**; certify interlock (a)/(b#2665)/(c)/(d)/(h); certify no in-flight engine-path ballot ships before the merge-gate closes; ratify HA §1c with the **ADR-1005 owner (Dave Rae)** — **DONE: ratified decoupled 2026-09-07** (dissent recorded-with-rebuttal); bottom out #2665 as the engine-gate's real open question. **DONE 2026-09-08** — certification `docs/security-reviews/split-ws0-interlock-certification-2026-09-08.md`; merge-gate armed as a hard CI tripwire (`tests/test_split_interlock_tripwire.py` + `tests/split_interlock_ledger.json`, wired into `docs-lint.yml`) PLUS a routed-concern row; gate CLOSED (b/c/d/h red — (b) is #2665 deny-precedence + #2675 seam); no in-flight engine-path ballot; ADR-0032 cells (a)/(m)/(f)/(h) found STALE → **#4124** (a tracked doc follow-up correcting the ADR's own table — NOT a WS-0 deliverable; the ledger+cert carry the correct state) | — | THIS | — | **predecessor of all** | architect + security-guardian | **done** |
| **WS-A1** | Baseline execution-semantics repair (step 1); also interlock (i) | A | THIS | WS-0 | — | architect + cpp-safety | planned |
| **WS-A2r** | In-process public-API contracts, **read/command paths** (step 2, read half) | A | THIS | WS-A1 | — | architect | planned |
| **WS-A2a** | In-process **admission / grant / finalisation-receipt** contracts (step 2, admission half) — **under the standing merge-gate** | A | THIS | WS-A1, WS-A6(c/d/h) | — | architect + security-guardian | blocked on interlock |
| **WS-A3** | Capability parity — the ~40–60 missing public REST+MCP capabilities, **per family** (devices, settings, `/auto`, …) | A | THIS (ADR-0031 §3) | WS-0 | feeds A4 per-family | consistency-auditor + architect | planned |
| **WS-A4** | **Logical seam enforcement + INV-31-4 contract test** — handlers/renderers call the API, never a store pointer; build fails on any registered route absent from the published OpenAPI; **at the WS-B2 cutover, remove the presentation-side handler's behavioural-PII audit call once core's REST-side audit covers the same view (audit continuity — not a `*_ui.cpp` relocation; see the current-state bullet above)**. **⚠️ The GLOBAL drift test (interlock-(j)'s testability half only, LEXICAL — see the current-state caveat above) SHIPPED out-of-band under #842/#3991/#3992** — see the "INV-31-4 global contract test EXISTS" current-state bullet above for detail. Interlock (j)'s **generated-projection** half (#2678) stays RED — **currently unscheduled, tracked in ADR-0032 (j), owned by no workstream row** (only (j)'s testability half was ever in WS-A4's scope). **The FIRST per-family in-process API seam landed on `network`** (`NetworkApi`, all 3 consumers routed, `scripts/ci/check-seam-closure.py` piloted — see the current-state bullet above for the pattern + honest enforcement scope + the `available_keys` A1-parity fix it surfaced and closed). **The template is now the two-header shape** (`<family>_api.hpp` abstract + `<family>_api_local.hpp` core-only factory, boundary CI-enforced, #4249) — see the current-state bullet above. **`verify` (#4292), `compliance` (#4337), `device` (#4484) and `dex` (`feat/split-a4-dex-seam`) followed as the second through fifth families** — `compliance`'s read surface is seamed and enforced, but its policy/fragment mutators have no public REST/MCP twin yet (a WS-A3 gap, #4334) so that family is not fully WS-B2-cutover-ready; `device`'s DEX/Guardian lenses are similarly split OUT (`device_lens_routes.{hpp,cpp}`) but for a different reason — they're a FUTURE family's data, not an un-twinned mutator; `dex` is the DEX **signals** surface only (`DexApi`, 12 GSS-backed `/api/v1/dex/*` reads; **both REST and MCP twins routed through the seam** — no store-backed builder called directly in a routed handler). Deferred follow-up (accepted, tracked ISSUE #4576): the `/dex` dashboard fragments (DEX-SIGNALS, `dex_routes.cpp`) stay on the builders — still store-coupled, routing needs a build-vs-render split that risks HTML drift, unchanged by `feat/split-a4-lens-dashboard-rewire` below. `dex_perf` (the SIXTH family, `DexPerfApi`) is the app-perf-over-time sequel — store-type-free from commit one (applying the `dex` seam's own PR #4582 lesson up front, see the current-state bullet above), with a passing parity test against live PG, and **both REST and MCP twins routed through the seam** (landed in the same change as the seam build, mirroring `dex`'s own first-commit shape); its dashboard consumer rewire (`dex_perf_ui.cpp`, `dex_app_perf_ui.{hpp,cpp}`) was deferred at the time, tracked **ISSUE #4626**; `/live` remains its own unowned tiny seam. `schedule` (the SEVENTH family, `ScheduleApi`) is the recurring-schedule read surface, fully rewired (fragment + REST v1 + MCP), with a deliberate, disclosed degrade-honesty delta on its dashboard fragment. `workflow` (the EIGHTH family, `WorkflowApi`) is the multi-step-workflow read surface — REST v1 + MCP fully rewired, byte-identical behaviour throughout (see the current-state bullet above for why it needed no delta, unlike `schedule`). `guardian` (the NINTH family, `GuardianApi`) is the Guardian / Guaranteed State read surface — REST v1 + MCP fully rewired for 8 of its 9 public resources (`schemas` deliberately excluded, store-free); UNLIKE every prior family, its factory takes both backing stores as NULLABLE pointers with per-method degrade (mirrors `dex_perf_api`'s own multi-dependency shape, not the single-required-reference one `workflow`/`schedule` used) — see the current-state bullet above for why the single-required-reference shape was tried first and reverted after breaking ~30 pre-existing tests. **`feat/split-a4-lens-dashboard-rewire` then closed three of the deferrals above**: `device_lens_routes.{hpp,cpp}`'s `/fragments/device/dex` + `/fragments/device/guardian` lenses now call `DexApi::device_score`/`GuardianApi::device_guards` respectively (closing #4576's lens half and the `guardian` family's own device-lens deferral) and are enrolled in the `device` family's seam-closure enforcement; `dex_perf`'s dashboard fragments (`dex_perf_ui.cpp`, `dex_app_perf_ui.{hpp,cpp}`) now call `DexPerfApi` exclusively, retiring `AppPerfProviders` (closing #4626) and enrolling those TUs in the `dex_perf` family's seam-closure enforcement. Four disclosed deltas: (1) a device with zero reported guards now renders "No guards evaluated" even under a degraded fleet-wide rule-catalogue read (the per-agent `device_guards` call no longer depends on that read's health for a zero-row device); (2) the F2b trend/app-list panel (`/fragments/dex/perf/apps` + `/app`) AND the per-device app-perf drill (`/fragments/dex/device/app-perf`) placeholders collapsed to one wording, "App performance data unavailable (not configured or degraded) — retry shortly." — the F2a fleet-now Performance tab's "no perf snapshot provider wired" and the version-devices drill's "no app-perf device provider wired" are UNCHANGED, more specific placeholders, not folded into this collapse; (3) the per-device DEX signal-history percentile strips now render "no comparison data" over an empty `DexPerfSnapshot{}` when no `dex_perf_fn` is wired, where the section was previously omitted (production always wires one, so no visible production change); (4) the per-device app-perf drill's `dex.device.app_perf.view` audit now fires even on an unwired `dex_perf_api_` (introduced by this change — previously null-checked before the audit; over-audits, never under-audits). GAP-1 (the device-model picker's fleet-wide tag-values read outside the seam) was closed by the follow-up change #4857: the picker now reads the public cohorts resource via `DexPerfApi::fleet_snapshot`, so every `/dex` app-perf DATA read goes through `DexPerfApi` — a reasoned choice (architect D1) over a new tag-values route; the cohorts resource lists sub-floor cohort names/counts with percentiles suppressed (names and counts are NOT themselves floor-suppressed — only the per-point percentile detail is), outside ADR-0017's per-agent-row scope. Disclosed, pre-existing residual: the SAME fragment's management-GROUP selector (as opposed to the device-model one GAP-1 closed) still reads group names via `DexRoutes::GroupListFn` — a closure in `server.cpp` calling `ManagementGroupStore::list_groups()` directly, outside the `DexPerfApi` seam — a selector-only, non-app-perf-data dependency this GAP-1 fix did not touch and does not claim to. **REMAINING for WS-A4:** the same seam on the other families (gates WS-B2) · handler→API seam refactor generally · the audit-removal-at-cutover step (not yet reached — no family has cut over) · closing the `compliance` write-surface WS-A3 gap (#4334) · `dex`'s own `/dex` DEX-SIGNALS dashboard fragments (still store-coupled, #4576's dashboard half) · `guardian_routes.cpp`'s mutator carve-out (disclosed, not started) · `schedule`/`workflow` have no dashboard deferral of their own (their consumer sets are fully rewired). | A | THIS | WS-A2r, WS-A3 (that family) | **P (per family)** | architect + security-guardian + cpp-safety | **partial** — global drift test done (#842); NINE families (`network` #4232 + `verify` #4292 + `compliance` #4337 + `device` #4484 + `dex` signals REST+MCP + `dex_perf` REST+MCP + `schedule` REST+MCP+fragment + `workflow` REST+MCP + `guardian` REST+MCP) have the per-family seam built and their consumers routed, and the `device`/`dex_perf` dashboard+lens deferrals (#4576's lens half, #4626) are now closed; the remaining families + the general seam refactor + the cutover-time audit removal + `compliance`'s WS-A3 write-surface gap (#4334) + `dex`'s own `/dex` dashboard rewire + GAP-1's tag-values seam gap remain |
| **WS-A5** | Input confinement — **SHIPPED** (`authorize_list_read` / `require_list_read` live; #1714/#1715/#1716 CLOSED). Residual: **#2665** (additive vs interlock-(b) deny-precedence) + `evaluate_as_operator` seam (absent) | A | /auth | WS-0 | **E** | security-guardian | shipped; #2665 open |
| **WS-A6** | Admission/grant/audit substrate — (c) D12 audit with indexed `use_case_run_id`, (d) P7 release-log store, (h) capability-declaration registry with full credential fields. (a) shipped. **Under merge-gate** | A | /auth + exec-plan | WS-0, WS-A5 | **E** | security-guardian + architect + docs-writer | (a) shipped; c/d/h absent |
| **WS-B1** | Drogon build canary (G10) — Drogon linked into the Meson/vcpkg matrix, **structurally isolated** from the `#375` MSVC static grpc/abseil stack (Drogon is not in the static-override list and is a dynamic DLL on Windows; coexistence is by construction, with the Windows leg exercised in CI). Landed as `yuzu_drogon_canary` (`server/core/src/drogon_canary_main.cpp`, sibling of `yuzu_pg_canary`), forcing the out-of-line `HttpAppFramework::instance()` symbol via the inline `drogon::app()` forwarder; `drogon` added UNCONDITIONALLY to `vcpkg.json` (default features only — no orm/postgres/sqlite3; ADR-0031 §5), transitive trantor/jsoncpp/brotli/c-ares pulled by the port. `#375` grpc/protobuf/abseil triplet + hand-wired meson branch UNTOUCHED — drogon is not in the static-override list, so it uses the sqlite3/libxml2 dynamic-DLL cmake-dep pattern. | B | THIS | WS-0 | **P** | build-ci + cross-platform | **MERGED to dev (PR #4293; follow-up #4546 fixed Drogon's static transitive deps via `-Dpkg_config_path`)** — Linux green (build+link+run proven, in CI); the Windows MSVC static-leg caveat below is unrevisited since merge — re-verify against CI history, don't assume green, before citing it as closed |
| **WS-B2** | Drogon **strangler port + cutover plane** — presentation binary beside httplib; **ingress routing/steering** between the two; per-family port (async + repoint→core API + SSE rewrite + per-family seam+contract); **long-lived stream drain**; **per-family rollback**. First live cutover behind the gate | B | THIS | WS-B1, WS-A2r, WS-A4(family) | (the gate) | architect + cpp-safety + cross-platform | planned |
| **WS-B3** | State relocation — (a) sessions inherit HA durable-PG; (b) MCP replay ring → **durable core outbox** | B | (a) HA WS-1 / (b) HA WS-2b | WS-0; HA WS-1/WS-2 | **P** | authdb + security-guardian | **(a) DONE** (HA WS-1); (b) outstanding (HA WS-2b) |
| **WS-B4** | Cross-process event spine — **rides the HA WS-2a durable `event_outbox`** (not a second transport); record the ADR-0032 Decision 9 G1 channel choice (per-subscriber vs multiplexed-with-TCB-admission) | B | THIS + HA WS-2a | HA WS-2a, WS-A2r | **P** | architect + sre + security-guardian | HA WS-2a-1 done (table); 2a-2 NOTIFY/cursor-poll outstanding |
| **WS-B6** | **Component service identity + peer attestation (INV-31-5 / Decision 6)** — presentation→core mTLS identity; peer-IP/correlation attested as infra metadata only; core stops trusting in-process identity | B | THIS | WS-A2r | **P** | security-guardian + cross-platform | planned |
| **WS-B7** | **Per-binary readiness (INV-31-6)** — presentation `/readyz` = core reachable at a compatible API version, never green while core down; core readyz = the monolith's `/readyz` as HA WS-8 left it — the runtime `pg_reachable` probe plus BOOT-state store rows (store `is_open()` is latched, #3061; do NOT add per-store runtime probes), and presentation never reads `pg_reachable` directly (INV-31-3 — it asks core); engine readyz **(day-one — in the cutover gate)** | B | THIS | WS-A2r | **P** | sre + docs-writer | planned (helps HA WS-8) |
| **WS-B8** | **First live cutover → progressive family cutover → httplib presentation retirement** (step 4 completion) | B | THIS | gate: safe-to-extract(presentation) | completes it | architect + security-guardian | planned |
| **WS-B9** | **Extract engine binary** (step 5) — own process; facts/effects only through core; redeem release authorization before the first byte; engine boundary (B2-contract) security; (k)(l)(m) | B | THIS | gate: safe-to-extract(engine) incl. WS-B8 done | (the gate) | security-guardian + architect + cpp-safety | planned |
| **WS-B10** | Supervision / one-deployment-unit — **covers the migration period too**; one install / one health / one upgrade / one version across three processes + Postgres | B | THIS | WS-B2 (from first cutover) | — | release-deploy + sre | planned |
| **WS-B11** | **`uce` DB decomposition (INV-31-3)** — revoke core's grant on `uce`; engine credentials that structurally cannot reach `yuzu`; presentation holds zero DB credentials; `uce` provisioning / roles / retention / migrations; **negative DB-access tests** | B | THIS | WS-0 | **P + E** | architect + security-guardian + cpp-safety | planned |
| **WS-X1** | K-fanout measurement — per-view core-call fan-out on the busiest fragment; accept or mitigate | X | THIS | WS-A4 | **P** | performance + sre | planned |
| **WS-X2** | Version-skew compat contract — core-API compat (day one) + presentation↔engine B2 contract (separately versioned) | X | THIS | WS-A2r | **P** | architect | planned |
| **WS-X3** | Credential-exchange hardening (INV-31-1, phased — P2) — presentation-audience-bound session token so raw bearers don't persist in presentation memory | X | THIS | WS-B8 | — | security-guardian | planned (P2) |
| **WS-X4** | **Break-glass 6a minimal surface + offline first-admin/recovery** — runs `on_behalf_guard` + every ADR-0033 §1 filter. **Binds at first cutover** (core loses every ingress but presentation at B8) | X | THIS + /auth | WS-A5 | **P** | security-guardian | planned |
| **WS-X5** | **Split-topology config** (co-located-vs-split flags; run three processes + PG in dev/CI) + **continuous split observability** (cross-boundary correlation ids, per-boundary latency, three `/metrics` + trace context, audit continuity, reaper-liveness alert) + **validation harness** (parity, seam "no store ptr in a renderer", negative DB-access, SSE-across-boundary, version-skew, backout) | X | THIS | tracks all | — | quality-engineer + chaos-injector + sre | planned (continuous) |

### Hard invariants that must not regress when landing any WS

- **INV-31-1** — presentation is a credential pipe: never asserts identity, mints a grant, or decides a permission.
- **INV-31-2** — core confines inputs, the engine composes them (admit-then-filter via the shipped `authorize_list_read` chokepoint + the open #2665 deny-precedence reconciliation).
- **INV-31-3** — no cross-component DB access: engine never touches `yuzu`, core holds no grant on `uce`, presentation owns no DB.
- **INV-31-4** — no private core API: every registered route appears in the published OpenAPI; the build fails otherwise. *(Enforced today only by a LEXICAL gate — literal registrations fail the build, non-literal direct verb calls warn, helper-/header-defined registrations can escape undetected; #2572 is the type-aware closure.)*
- **INV-31-5** — presentation's service identity attests infrastructure, not people.
- **INV-31-6** — every store a component depends on appears in that component's readiness probe.
- On-behalf-of rejected on every ingress (the four health-probe paths excepted); isolation enforced as-if-remote from day one; no UI-only capability; the ADR-0032 interlock standing merge-gate; **a component is extractable only when its safe-to-extract gate is fully green at the first cutover.**

---

## Phased build order

- **Phase 0 — Reconcile & arm the merge-gate:** WS-0 + stand up the standing ADR-0032 interlock merge-gate.
- **Phase A — Seam & authority (monolith; parallel where the graph allows):** WS-A1 → WS-A2r, WS-A3
  (per-family), **WS-A4** (the net-new heart), WS-B1 (Drogon canary, parallel), WS-B11 (DB decomposition —
  can start early), WS-X2, WS-X5 (continuous from here). WS-A2a + WS-A6 (the interlock substrate) proceed
  **under the merge-gate**; WS-A5's #2665 residual is tracked. Nothing is extracted yet.
- **Phase B — Extract presentation:** WS-B2 (cutover plane) + WS-B3 + WS-B4 + WS-B6 + WS-B7 + WS-X1 +
  WS-X4 + WS-B11(presentation half) → **first live cutover behind the gate** → WS-B8 progressive cutover
  + httplib retirement → WS-B10 supervision, WS-X3.
- **Phase C — Extract engine:** **WS-B9** behind the engine gate (needs WS-B8 done + interlock (a)–(d)+(h)
  closed + #2665 resolved) → WS-B11(engine half) → finalize supervision/readyz.

**Highest-leverage first slices after WS-0:** **WS-A4's remaining work** — its GLOBAL INV-31-4 drift test
already shipped (#842/#3991/#3992; do NOT rebuild it — see the current-state bullet), and the FIRST
per-family seam (`network`) landed as the pilot pattern (see the current-state bullet), so what's left is
copying that pattern to the remaining families, the handler→API seam refactor generally, and the
cutover-time audit removal (deferred to each family's WS-B2 cutover, not a `*_ui.cpp` change). **WS-B1**
(Drogon canary) is MERGED (#4293) — no longer an open first slice. **WS-B11** (DB decomposition) is
a third independent early start. None waits on an external
programme now that WS-A3 is THIS-owned per-family.

## Relationship to HA (the split *consumes* HA, does not gate it)

The presentation/core split is **not** a prerequisite for active-active — HA §1c is decoupled,
**ratified by the ADR-1005 owner (Dave Rae), 2026-09-07**. The one in-process blocker HA cared about —
the agent `Subscribe` stream — is solved by gateway-fronting (HA WS-4), not the split. But the split has **one-way dependencies** on HA deliverables and inherits them
rather than rebuilding:

- **Sessions** (WS-B3a) inherit HA WS-1 (**done** — durable `SessionStore`, DB-clock authority).
- **Event spine** (WS-B4) rides HA WS-2a's durable `event_outbox` (**2a-1 done**; 2a-2 NOTIFY + cursor-poll
  outstanding) — never a second transport.
- **MCP replay durability** (WS-B3b) is HA WS-2b (outstanding) — ADR-2002 §4/§5 supersedes exec-plan
  D15d's non-durable stance.

The split's own contribution *helps* HA operability (tier-split `/readyz`, WS-B7) but never discharges
HA's replica gates. Kimi's original dissent (that the split is a hard safety prerequisite) is kept
recorded-with-rebuttal in `docs/ha-delivery-matrix.md`, not erased.

## Per-WS workflow

Landing a WS slice mirrors the standard Yuzu flow: read the routed doc first → smallest coherent patch
in the owning module → its tests → `/test` → `/governance <range>` with the reviewers named in the row.
A WS is done only when its safe-to-extract clause (if any) has a passing WS-X5 validation-harness scenario.
