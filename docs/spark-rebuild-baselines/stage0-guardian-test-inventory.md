# Stage 0 baseline — Guardian test inventory (Stage 2 spec surface)

Captured 2026-07-05 on `feat/spark-rebuild` @ origin/dev (2294dfe0). This is the "treat the existing suite as spec" baseline for Stage 2's gate (`guardian_engine.{hpp,cpp}` re-homed onto SparkEngine — must pass this suite **unmodified**). Counts are `TEST_CASE`/`SCENARIO` occurrences, not asserted behaviors — use as a completeness checksum, not a substitute for reading the files.

| File | Cases | Covers |
|---|---:|---|
| `tests/unit/test_guardian_engine.cpp` | 18 | `apply_rules`/full_sync/delta merge, KV cache + `policy_generation` survive reconstruct, fail-closed `get_status`, dispatch routing, drift event_id (#1307), degrade-gracefully on null KvStore, `stop()` semantics |
| `tests/unit/test_guard_file.cpp` | 14 | Windows file guard (ReadDirectoryChangesW watcher) |
| `tests/unit/test_guard_registry.cpp` | 10 | Windows registry guard (RegNotifyChangeKeyValue watcher) |
| `tests/unit/test_guard_service.cpp` | 5 | Windows service guard (SCM `NotifyServiceStatusChange`) |
| `tests/unit/test_guard_systemd.cpp` | 14 | Linux service guard (`SystemdServiceGuard`, sd-bus `ActiveState`, observe-only) |
| `tests/unit/server/test_guaranteed_state_store.cpp` | 47 | `GuaranteedStateStore` (`guaranteed-state.db`) — §9.1 schema, rule persistence |
| `tests/unit/server/test_rest_guaranteed_state.cpp` | 88 | REST surface over Guardian rules/status |
| `tests/unit/server/test_guardian_routes.cpp` | 19 | Dashboard fragment routes |
| `tests/unit/server/test_guardian_push_builder.cpp` | 10 | Push fan-out builder incl. the H1 dangerous-enforce downgrade-to-audit backstop |
| `tests/unit/server/test_guardian_resilience_schema.cpp` | 21 | Resilience strategy (Persist/Backoff/Bounded retry) schema |
| `tests/unit/server/test_guardian_form_render.cpp` | 7 | Dashboard authoring form rendering |
| `tests/unit/server/test_baseline_store.cpp` | 13 | `BaselineStore` — `deployed_member_rule_ids()`/`deployed_snapshot`, Push-not-Write invariant |
| `tests/unit/test_trigger_engine.cpp` | 45 | TriggerEngine — **retires Stage 5**; NOT part of the Stage 2 preserved-spec set, but its scenario coverage (interval/file_change/service_status/registry_change/agent_startup semantics) is the acceptance bar for the Stage-1 spark types replacing it |

**Total: 266 cases** across 12 files (excludes `test_trigger_engine.cpp`, superseded not preserved; counts re-tallied against `dev` 2026-07-11 — was 267 at capture, minor unrelated churn since). **But "the whole suite passes unmodified" is NOT a valid Stage 2 gate** — see the split below.

## The Stage 2 gate is a two-part split, NOT "the whole suite passes unmodified" (corrected 2026-07-06)

The naive gate "the entire Guardian suite passes unmodified against the SparkEngine-based engine" is internally contradictory and would be green precisely when it should be red. The suite splits into two groups that behave **oppositely** under the Stage 2 re-homing (guards stop owning threads; each rule arms sparks via SparkEngine):

**Group A — extraction / contract / persistence (pass UNMODIFIED, but do NOT gate the re-homing):**
- `test_guardian_engine.cpp` (18) — its own header states *"PR 2 has no real guard threads... out of scope (PR 3+): Real guard threads, drift detection, remediation."* It tests KV persistence, `apply_rules`, proto round-trip, `policy_generation`. Green here proves the persistence/dispatch contract survives — it says **nothing** about whether guards still arm/watch/fire.
- The pure helpers in the guard tests (`systemd_decide_emit`, `parse_active_state`, `systemd_is_compliant`, the classifiers) — these move to the spark *type* and pass unmodified, but again don't exercise the SparkEngine wiring.
- The server-side stores/routes/render tests (`test_guaranteed_state_store`, `test_rest_guaranteed_state`, `test_guardian_routes`, `test_guardian_push_builder`, `test_guardian_resilience_schema`, `test_guardian_form_render`, `test_baseline_store`) — the server half doesn't change shape in Stage 2, so these are unaffected.

**Group B — watcher delivery (EXPECTED TO CHANGE — they test the mechanism being removed):**
- `test_guard_{file,registry,service,systemd}.cpp` DO test the watcher path — but the **current thread-per-guard model**. `guard_systemd.cpp:263` is `thread_ = std::thread(...)` per guard; `test_guard_systemd.cpp` carries `static_assert(!std::is_move_constructible_v<SystemdServiceGuard>)` asserting the guard *owns* its thread/eventfd/bus. Stage 2 removes exactly that. These tests **cannot pass unmodified** — they assert the retired ownership model. Treat them as a spec to **port**, not preserve.

**Consequence — the corrected Stage 2 gate is two parts:**
1. **Extraction/contract parity:** Group A passes unmodified.
2. **Delivery parity (NEW, and the part that actually gates the re-homing):** for each guard type, a SparkEngine-level test proving an armed spark still produces the same **drift/enforce edge**, plus **A2 re-arm**, **debounce/dedup**, and **dangerous-enforce** behavior, through the new wiring. The current `test_guard_*` cases are the behavioral spec these port from.

This is the identical extraction-vs-delivery split applied to DEX Stage 4 (`stage0-dex-obs-stream-baseline.md`). Without part 2, a re-homing that silently stops arming guards passes the entire suite green — the exact failure the DEX split guards against.

## §24 standing invariants (`docs/yuzu-guardian-design-v1.1.md`) — must survive Stage 2 verbatim

1. **RBAC `Push` seed is Guardian-only** — `Push` absent from `crud_ops[]` in `rbac_store.cpp`, granted explicitly per role on `GuaranteedState` alone (H-4, issue #485).
2. **Reserved plugin name `__guard__`** intercepted before the plugin match loop — both load-time (`plugin_loader.cpp`) and dispatch-time (`agent.cpp`) checks stay.
3. **`dangerous_enforce_in_spec` is the single enforce-safety chokepoint** (`guardian_rule_spec.cpp`) — gates `derive_rule_spec`, the REST metadata update, and the push backstop (which downgrades dangerous enforce to audit). Extend, never fork.
4. **Enforced set reads via `BaselineStore::deployed_member_rule_ids()`**, sourced from each deployed Baseline's `deployed_snapshot` — never the live member set.
5. **Guardian wire payloads in `CommandRequest.parameters` are not gateway-safe** — raw proto bytes must not ride a `map<string,string>` the gateway re-encodes via `gpb:e_type_string`.

Stage 6 (wire: `yuzu.policy.v1` replaces `GuaranteedStatePush`) is where invariants 4 and 5 get **redesigned**, not just preserved — the compiled per-device policy document and the digest-bound approval (ADR-0021 Decisions on the approval workflow) supersede the `deployed_snapshot` member-ID-list mechanism and must carry the same Push-not-Write and gateway-safety guarantees forward under the new wire format. Flag this explicitly in the Stage 6 PR description so reviewers check for regression, not just difference.
