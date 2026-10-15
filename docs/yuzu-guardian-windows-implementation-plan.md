# Plan — Wire up Yuzu Guardian on Windows (Phase 1 skeleton)

## Context

`docs/yuzu-guardian-design-v1.1.md` specifies a new agent-side Guardian engine for real-time policy enforcement on Windows, Linux, and macOS. Windows is the stated top priority. The design is complete and decided — this plan scopes a **Windows-first delivery** as a series of reviewable PRs that stand up the skeleton (dispatch, proto, one event guard, remediation, audit, server store, minimal dashboard) before the long tail of guard types and hardening.

The exploration found that the agent already has everything Guardian needs to graft onto: service install with `SERVICE_AUTO_START` + `FailureActions` (`main.cpp:136–200`), a clean pre-network vs post-network split in `AgentImpl::run()` (`agent.cpp:407–1117`), a plugin dispatch loop at `agent.cpp:975–993` with no reserved names yet, a thread-safe plugin-namespaced `KvStore`, an existing `RegNotifyChangeKeyValue` watcher pattern in `TriggerEngine::registry_watch_loop()` (`trigger_engine.cpp`), `wintrust`/`wbemuuid`/`ole32` already linked, and a generic `ApprovalManager` whose `definition_id` field can key off `guaranteed_state_*` without code changes. On the server side, `MigrationRunner`, `RestApiV1` (sink + `JObj`/`JArr` pattern), `DashboardRoutes`, and `kTools[]`/`kToolSecurity` arrays in `mcp_server.cpp` all have clear slot-in points.

Gaps: no ETW consumer, no WFP subscriber, no `INetFwPolicy2` usage, no `CredWrite` — all Windows-link additions (`tdh`, `fwpuclnt`, `rpcrt4`, `hnetcfg`) and net-new code. Agent-side there is no policy evaluator today, so Guardian is additive.

Goal of this plan: land PRs 1–4 below to get **one end-to-end Windows rule working** (Registry Guard → state evaluator → registry-write remediation → audit journal → server store → push to agent → dashboard list). Everything else (ETW/WFP/SCM guards, condition guards, resilience strategies, quarantine, MCP tools, HTMX rule editor) is scoped as PRs 5+.

## Delivery sequence

### PR 1 — Proto + wire skeleton + server store stub

Land the wire contract and empty server store first so later PRs have something to push/receive.

- `proto/yuzu/guardian/v1/guaranteed_state.proto` — new file with the five messages from §7.1 (`GuaranteedStateRule`, `GuaranteedStatePush`, `GuaranteedStateEvent`, `GuaranteedStateStatus`, `GuaranteedStateRuleStatus`). Extend `GuaranteedStateRuleStatus` with three fields not in the design doc — `bool guard_healthy = 8;`, `google.protobuf.Timestamp last_notification = 9;`, `uint64 notifications_total = 10;` — to carry the kernel-wiring health signal surfaced in PR 3.
- `proto/meson.build` — append the new `.proto` to the `custom_target` `input:` array and update `output:`/`gen_srcs`/`gen_hdrs` (follow the agent.proto / management.proto pattern exactly).
- `server/core/src/guaranteed_state_store.hpp/.cpp` — new store following `audit_store.*` shape. Tables from §9.1 (`guaranteed_state_rules`, `guaranteed_state_events` + indexes). Declares a static `kMigrations` vector and calls `MigrationRunner::run(db_, "guaranteed_state_store", kMigrations)` inside `create_tables()`. CRUD: `create_rule`, `list_rules`, `get_rule`, `update_rule`, `delete_rule`, `insert_event`, `query_events`.
- `server/core/src/server.cpp` — instantiate the store at startup next to the other stores.
- `server/core/meson.build` — add the new sources.

Verification: `meson compile -C build-linux` + `build-windows` both clean; `meson test -C build-* --suite server` green; new `test_guaranteed_state_store.cpp` covers the migration path and CRUD round-trip.

### PR 2 — REST v1 + `__guard__` dispatch hook + empty GuardianEngine

Stand up the control-plane surface and the agent-side scaffolding without yet starting any real guard.

- `server/core/src/rest_api_v1.cpp/.hpp` — add the endpoints from §9.2 using the existing `perm_fn`/`audit_fn`/`JObj`/`JArr` pattern. RBAC: securable type `"GuaranteedState"` with operations `"Create" | "Read" | "Update" | "Delete" | "Push"`.
- `agents/core/src/guardian_engine.hpp/.cpp` — `GuardianEngine` class per §8.2 with `start_local()` / `sync_with_server(CommsLayer&)` / `stop()` / `apply_rules(push)` / `get_status()`. In this PR these are stubs that persist rules into the shared `KvStore` under plugin namespace `"__guardian__"` (§3 of the Explore 1 report — option A, no second SQLite file) but don't spawn any guards yet.
- `agents/core/src/agent.cpp` — two edits:
  1. After `KvStore::open` succeeds (around line 447) call `guardian_.start_local()` — before the Register RPC so Guardian is enforcing before the network comes up (§4 of the design).
  2. Immediately before the plugin-match loop at line 975, intercept `cmd.plugin() == "__guard__"` and route to `GuardianEngine::handle_command(cmd, stream, &stream_write_mu_)`. Actions: `push_rules`, `get_status`. Response written under `stream_write_mu_` using the same pattern as the existing final-response write at `agent.cpp:1089–1102`.
  3. After `Register()` succeeds (around line 803) call `guardian_.sync_with_server(comms)`.
- `agents/core/meson.build` — add `src/guardian_engine.cpp` unconditionally (engine itself is portable; only the guard implementations are platform-gated — follow the existing `cert_discovery.cpp` placement).

Verification: `meson test --suite agent` green; new `test_guardian_engine.cpp` fakes a `GuaranteedStatePush` and asserts rules land in `KvStore` under `__guardian__`. Server integration: `curl -X POST /api/v1/guaranteed-state/rules` → `GET /rules` shows it → `POST /push` → agent has it in KV.

### PR 3 — Registry Guard + StateEvaluator + RemediationEngine (registry-write) + AuditJournal — the end-to-end Windows vertical slice

This is the PR where a real rule actually fires on Windows. Keep it narrowly focused on one guard type and one remediation method so the whole loop can be proven.

- `agents/core/src/guard_base.hpp` — abstract `GuardBase` per §8.2 (`start/stop/type/rule_id/category/read_current_state`).
- `agents/core/src/guard_manager.hpp/.cpp` — instantiates guards per active rule, owns their threads, routes fired events into `StateEvaluator`. Implements the ETW-session and SCM-handle pooling placeholders from §8.3 (pooling logic itself arrives with the ETW/SCM guard PRs — for now a plain per-rule map is fine).
- `agents/core/src/guard_registry.hpp/.cpp` — **Windows only.** `RegNotifyChangeKeyValue` watch loop per §5.1.1 using `WaitForMultipleObjects` against the notify event + a stop event. Re-read state on fire; hand `StateSnapshot` to evaluator. Thread created with `_beginthreadex` at 64 KB stack (§8.3). **Reuse the existing pattern in `TriggerEngine::registry_watch_loop()` (`trigger_engine.cpp`)** — don't reinvent it. 10–50 ms debounce support per §6.5 (input debounce only; remediation + audit debounce arrive in PR 4).
- `agents/core/src/state_evaluator.hpp/.cpp` — assertion registry from §6.3 with only two entries landed in this PR: `registry-value-equals` and `registry-value-absent`. Returns `compliant | drift | exempt`.
- `agents/core/src/remediation_engine.hpp/.cpp` — Windows methods from §14.1 limited to `registry-write` + `registry-delete` + `method: auto` for the two above assertion types (§6.4). `RegSetValueExW` / `RegDeleteValueW` / `RegDeleteKeyExW`. **No `reg.exe` shell-out (§14).** Re-entrancy flag from §8.4 (per-rule `remediating_` atomic + 5 ms suppression window).
- `agents/core/src/guard_audit.hpp/.cpp` — MPSC queue + dedicated writer thread per §8.3. Writes `GuaranteedStateEvent` rows to a local SQLite journal (new table inside `kv_store.db` is fine; keyed by monotonically increasing `event_seq`). Drained by `GuardianEngine::sync_with_server` into `CommandResponse { plugin: "__guard__", action: "event" }`.
- `agents/core/src/assertion_types.hpp/.cpp` — two-entry registry to start; extension is just `register()` calls.
- **Kernel-wiring self-test on start + per-guard health metric** (added to this PR so we don't ship blind):
  - `GuardBase::self_test()` default implementation, overridden per guard. For `RegistryGuard`: on `start()`, after the watch is armed, the guard writes a sentinel DWORD under its own namespace key (e.g. `HKLM\SOFTWARE\Yuzu\Guardian\Probe\<rule_id>`), waits up to 500 ms for its own notification to round-trip, then deletes the sentinel. If the round-trip fails the guard marks itself `UNHEALTHY` and emits a `guard.unhealthy` audit event; `GuardianEngine::start_local()` continues (one dead guard must not block the rest) but `GuaranteedStateRuleStatus.status` for that rule reports `errored`.
  - Add fields to `GuardBase`: `std::atomic<steady_clock::time_point> last_notification_at_`, `std::atomic<uint64_t> notifications_total_`, `std::atomic<Health> health_` (`Healthy | Unhealthy | Unknown`). Updated by the watch loop; exposed on `get_status`.
  - Extend `GuaranteedStateRuleStatus` proto (§7.1) with `bool guard_healthy = 8; google.protobuf.Timestamp last_notification = 9; uint64 notifications_total = 10;` so the server/dashboard can tell the difference between "compliant because nothing's happening" and "deaf because the subscription silently went nowhere." This is a proto edit that goes back to **PR 1**; list it there now that we know we need it.
- `agents/core/meson.build`:
  ```meson
  guardian_sources = files('src/guard_base.hpp', 'src/guard_manager.cpp',
                           'src/state_evaluator.cpp',
                           'src/remediation_engine.cpp',
                           'src/guard_audit.cpp',
                           'src/assertion_types.cpp')
  if host_machine.system() == 'windows'
    guardian_sources += files('src/guard_registry.cpp')
    # advapi32 already linked; no new libs yet this PR
  endif
  ```
- Server: `server/core/src/guaranteed_state_store.cpp` — `insert_event` wired into the `__guard__` action: "event" path in the server's command-response handler so that journal rows from the agent land in `guaranteed_state_events`.

Verification: new `tests/unit/test_guard_registry.cpp` Windows-only — opens a test HKCU key, starts a `RegistryGuard`, flips the value, asserts evaluator fires and `remediation_engine` writes it back. **Plus a dedicated self-test test**: start `RegistryGuard` against a known-good path, assert `health_ == Healthy` and `notifications_total_ >= 1` within 500 ms of `start()` returning; then start a second guard against an intentionally broken path (no `KEY_NOTIFY` access) and assert it transitions to `Unhealthy` and emits `guard.unhealthy`. Manual UAT: author a `block-registry-example` rule via REST, push it, flip the key on a Windows box (WSL doesn't cut it for this one — needs native Windows), confirm `events` table shows a remediated drift **and** the dashboard's rule row shows the guard as healthy with a recent `last_notification` timestamp.

### PR 4 — Resilience strategies + re-arm on boot + `/guaranteed-state` dashboard list page

Wrap the vertical slice with the operational surface and the two safety-critical pieces the design calls out as "always on": reconciliation and resilience.

- `agents/core/src/resilience_strategy.hpp/.cpp` — `Fixed`, `Backoff`, `Escalation` per §8.5 + §6.6 YAML examples. `RaceDetector` per §8.5 (sliding-window drifts/second).
- `agents/core/src/guard_reconciliation.hpp/.cpp` — periodic full-state check calling every active guard's `read_current_state()` (every guard must implement this per §8.2). Runs once at startup (the "catch drift from while the agent was off" sweep from §4) and on a configurable interval (default 60 s).
- `server/core/src/dashboard_guaranteed_state.hpp/.cpp` — main page at `/guaranteed-state` and fragments `summary`, `rules`, `events` from §10.3. Follow `dashboard_routes.cpp` style — no HTMX rule editor yet, just list + detail reads. No approval flow yet.
- `server/core/src/server.cpp` — register the new dashboard routes next to `DashboardRoutes` around line 4202.

Verification: `test_resilience_strategy.cpp` covers the three strategies and race detector; integration test: agent with a rule that has `resilience: { strategy: backoff, initial_delay: 50ms, multiplier: 2, max_delay: 5s }` against a flaky remediation stub confirms the delay sequence; dashboard page renders rule list + event timeline.

### PRs 5+ (scoped, not in this plan's detail)

Tracking list, in the order the design doc suggests and sized roughly one-PR-per-row:

- **PR 5** — Service-control remediation + `service-running/stopped/disabled` assertions + SCM Guard (`NotifyServiceStatusChange`).
- **PR 6** — Firewall: `firewall-port-blocked` assertion + `INetFwPolicy2` (COM; needs `hnetcfg.lib`) + Registry Guard on the `FirewallRules` subtree (design §5.1.3 says that's the practical primary).
- **PR 7** — ETW Guard + session pooling per §8.3 (`tdh.lib`). Implement as a separate ETW session manager that multiplexes to rule evaluators.
- **PR 8** — Process Guard (hybrid — ETW `Microsoft-Windows-Kernel-Process` primary + `CreateToolhelp32Snapshot` backup) + `process-running/not-running` + `WinVerifyTrust` for `verify_signature` (`wintrust.lib` already linked).
- **PR 9** — WMI Guard + Compliance Guard + Software Guard (reuse existing `IWbemServices` usage from `hardware_plugin.cpp` / `wmi_plugin.cpp`). COM init: worker threads in the condition-guard pool must `CoInitializeEx(nullptr, COINIT_MULTITHREADED)` per §8.3.
- **PR 10** — WFP Guard (`fwpuclnt.lib` + `rpcrt4.lib`) as defence-in-depth.
- **PR 11** — Approval workflow: reuse `ApprovalManager` with `definition_id = "guaranteed_state_rule_*"`; add `/api/v1/guaranteed-state/approvals*` endpoints; dashboard pending-approvals pane from §10.1. No ApprovalManager code changes required (already generic).
- **PR 12** — HMAC rule signing (HKDF per §11.2) + `CredWrite`/`CredRead` key storage on Windows (`advapi32` already linked) + agent-side signature validation before activating a rule.
- **PR 13** — MCP read-only tools: `list_guaranteed_state_rules`, `get_guaranteed_state_rule`, `get_guaranteed_state_alerts`. Append to `kTools[]` + `kToolSecurity` + `build_handler()` switch — pattern from `list_policies` at `mcp_server.cpp:991–1017`.
- **PR 14** — HTMX rule editor (create/update/delete) + YAML validation + conflict detection (§11.8).
- **PR 15** — Quarantine (§11.7): WFP block-all filter at weight 65535, instruction handlers `quarantine.add_exception | remove_exception | lift`, server-side DNS resolution, resilience reset on lift.
- **PR 16** — Linux Phase N–R (inotify / netlink / D-Bus / sysctl / audit / package guards) — Windows should be fully soaked before Linux work begins.
- **PR 17** — macOS Phase S–X — after Linux, contingent on Endpoint Security entitlement availability.

## Critical files to touch for PRs 1–4

Net-new:

```
proto/yuzu/guardian/v1/guaranteed_state.proto
server/core/src/guaranteed_state_store.{hpp,cpp}
server/core/src/dashboard_guaranteed_state.{hpp,cpp}
agents/core/src/guardian_engine.{hpp,cpp}
agents/core/src/guard_base.hpp
agents/core/src/guard_manager.{hpp,cpp}
agents/core/src/guard_registry.{hpp,cpp}        (Windows-only)
agents/core/src/guard_reconciliation.{hpp,cpp}
agents/core/src/state_evaluator.{hpp,cpp}
agents/core/src/remediation_engine.{hpp,cpp}
agents/core/src/guard_audit.{hpp,cpp}
agents/core/src/assertion_types.{hpp,cpp}
agents/core/src/resilience_strategy.{hpp,cpp}
agents/core/src/race_detector.{hpp,cpp}
tests/unit/test_guard_registry.cpp               (Windows-only)
tests/unit/test_guardian_engine.cpp
tests/unit/test_state_evaluator.cpp
tests/unit/test_resilience_strategy.cpp
tests/unit/test_guaranteed_state_store.cpp
```

Modified:

```
proto/meson.build                 — append new .proto + outputs
agents/core/src/agent.cpp         — 3 edits at ~L447, ~L803, ~L975
agents/core/meson.build           — add Guardian sources incl. host_machine == 'windows' block
server/core/src/rest_api_v1.{hpp,cpp}  — new endpoints
server/core/src/server.cpp        — store init + dashboard route registration
server/core/meson.build           — add new sources
tests/unit/meson.build            — register new tests (Windows gating for guard_registry test)
docs/yaml-dsl-spec.md             — add `kind: GuaranteedStateRule` (done with PR 1)
```

## Patterns and existing code to reuse (don't reinvent)

- **Registry watcher**: `TriggerEngine::registry_watch_loop()` in `agents/core/src/trigger_engine.cpp` already has a working `RegNotifyChangeKeyValue` loop: it polls each watch's event with `WaitForSingleObject(evt, 0)` once per 2 s tick and stops through `wait_for_stop`, it does not block in `WaitForMultipleObjects`. Lift the re-arm structure into `RegistryGuard`; the blocking wait against a stop event is new work.
- **Windows service registration**: `main.cpp:136–200` already does `SERVICE_AUTO_START` + `FailureActions`. Guardian gets pre-login activation for free — no service-config changes needed.
- **Plugin-namespaced KV**: `agents/core/include/yuzu/agent/kv_store.hpp` — Guardian uses namespace `"__guardian__"`, no second DB file.
- **Store + MigrationRunner**: `server/core/src/audit_store.{hpp,cpp}` is the cleanest template; `server/core/src/migration_runner.hpp` drives schema versions.
- **REST endpoint shape**: `server/core/src/rest_api_v1.cpp` `JObj`/`JArr` builders and `perm_fn("securable", "op")` callback — mirror exactly.
- **MCP tool registration** (PR 13): `kTools[]` + `kToolSecurity` + the `list_policies` dispatch at `mcp_server.cpp:991–1017`.
- **ApprovalManager** (PR 11): `approval_manager.{hpp,cpp}` — `definition_id` is a free-form string, Guardian plugs in via `"guaranteed_state_rule_create"` / `"guaranteed_state_rule_update"` — no manager code changes.
- **COM init** (PR 9): `hardware_plugin.cpp` / `wmi_plugin.cpp` already use `IWbemServices`; the condition-guard thread pool must call `CoInitializeEx(nullptr, COINIT_MULTITHREADED)` per §8.3 — a detail currently implicit in the existing plugins.
- **Meson `host_machine.system() == 'windows'` conditional**: `agents/plugins/hardware/meson.build:3–7` (WMI libs) and `agents/plugins/filesystem/meson.build:2–5` (version.lib) are the models.

## Risks / open questions surfaced during exploration

1. **Existing `sc.exe binPath` bug in the Inno Setup installer** (`deploy/packaging/windows/yuzu-agent.iss:130`) — stuffs the full command line into `binPath`. Unrelated to Guardian directly but Guardian's pre-login enforcement claim relies on this service config being correct. **Action**: file the issue (it's already known per user memory `project_session_handover_2026-04-18.md`) and fix in a **separate small PR before PR 3**, so the Windows UAT in PR 3 isn't fighting a service-launch bug.
2. **The stale-DB / session-auth bug** listed in `CLAUDE.md` ("Known bug: stale DB breaks session auth on restart") will also surface in Guardian UAT since `guardian.sync_with_server` happens after Register. Not new, but worth flagging in the PR 3 test plan.
3. **ETW session cap** (64 system-wide, shared with Defender/EDR) — the pooling design (§8.3) is non-optional on boxes with EDR installed. PR 7 (ETW Guard) must ship the pooling manager or it will fail on customer machines that already have EDR. Don't land ETW without pooling.
4. **`RegNotifyChangeKeyValue` re-arm gap** (§5.1.1) — the design accepts reconciliation as the backstop. PR 4's reconciliation guard is load-bearing for this; don't ship PR 3 without at least a minimum-viable reconciliation sweep, even if full `RaceDetector` is deferred.

## End-to-end verification for PRs 1–4 (Windows)

1. **Unit**: `meson test -C build-linux --suite server` + `meson test -C build-windows --suite agent` all green (the Registry Guard test is `#ifdef _WIN32` and only runs on native Windows).
2. **Integration (Windows, native)**:
   - Install agent service fresh (`yuzu-agent.exe --install-service`).
   - Reboot, confirm service runs.
   - From the dashboard / REST: `POST /api/v1/guaranteed-state/rules` with a YAML rule asserting `registry-value-equals` on `HKCU\Software\YuzuTest\Flag = 1`.
   - `POST /api/v1/guaranteed-state/push` → scope includes the agent.
   - On the Windows box, `reg add HKCU\Software\YuzuTest /v Flag /t REG_DWORD /d 0 /f`.
   - Within <100 ms Guardian should rewrite the value to 1 and emit a `drift.remediated` event.
   - Confirm the event lands at `GET /api/v1/guaranteed-state/events` and on the `/guaranteed-state` dashboard page.
3. **Offline**: stop the server, repeat step 2.3 — enforcement must still work from cached policy. Restart server, confirm queued events flush.
4. **Pre-login**: reboot the Windows box, sign in; `events` table should show Guardian's startup reconciliation event before any user-session event — proves §4's pre-login activation.
5. **Kernel-wiring proof**: immediately after service start, the dashboard rule row must show `guard_healthy = true` with a `last_notification` timestamp <1 s old (the self-test probe). Then manually deny `KEY_NOTIFY` on the watched path (e.g. via `icacls` on an HKLM subkey owned by SYSTEM) and restart the agent — the same rule must flip to `errored` with a `guard.unhealthy` event. This confirms we can tell "plugged into the kernel" from "silently deaf."
