#pragma once

/// @file background_jobs.hpp
/// WS-10 (ADR-2002 §Decomposition item 10): the checked-in, exhaustive
/// classification of EVERY server background pass for replica-safety, so a
/// newly-added pass cannot silently double-run under a second replica.
///
/// THE UNIT IS THE PASS, NOT THE THREAD. One thread multiplexes many passes of
/// different classes — `result_set_maint_thread_` alone runs 11 (the per-replica
/// event-outbox poll, several advisory-locked reaps, gauge refreshes), and
/// `health_recompute_thread_` runs a mix of read-only gauges, a fleet-wide CRL
/// re-publish, and a per-replica stream teardown. Classifying a thread wholesale
/// would falsely certify an unsafe pass riding a mostly-safe thread. Each entry
/// below is one unit of work.
///
/// THREE CLASSES (ADR-2002 item 10):
///   - ReplicaSafe          — correct to run on every replica concurrently,
///                            because it is read-only/local, idempotent, an
///                            execute-once CAS, or an advisory-lock SINGLE-WRITER
///                            retention pass. MUST-run-per-replica passes (the
///                            event-outbox poll, ADR-2002 §5) are ReplicaSafe and
///                            must NEVER be leader-gated.
///   - FencedLeaderOnly     — side-effecting singleton work that double-fires
///                            across replicas (agent dispatch, redundant CRL
///                            re-publishes).
///                            Runs only on the WS-3 fenced leader; ENFORCEMENT is
///                            slice 10.3 (rides WS-3 3.2), not this file. ADDING a
///                            FencedLeaderOnly pass REQUIRES wrapping its dispatch
///                            site with `leader_gate_permits<background_job_class(
///                            "<pass>")>(leader_elector_.get())` (leader_gate.hpp) —
///                            the consteval class lookup pins the CLASS but not gate
///                            PRESENCE, so a new row without a gate site compiles and
///                            double-fires (adversarial review K5; CI sweep #4121).
///   - DisabledUntilFixed   — not yet replica-safe and not yet leader-gated; must
///                            not run per-replica until its named fix lands.
///
/// HOW CLASSIFICATION IS ENFORCED — and the honest limit of it. This array is the
/// single compile-time source of truth (git-auditable, CI-compiled), and
/// `tests/unit/server/test_background_jobs.cpp` pins its internal consistency +
/// completeness against the audited inventory (a count tripwire). Every
/// CATASTROPHIC-CLASS site carries `YUZU_ASSERT_BACKGROUND_JOB(...)` — a consteval
/// lookup that makes removing/renaming its table entry a BUILD FAILURE (the
/// `command_capability.hpp` ExecuteGate precedent): all FencedLeaderOnly and
/// DisabledUntilFixed passes (schedule/policy/quarantine dispatch, ca.publish_crl,
/// nvd_sync, the concurrency reconciler), plus the load-bearing ReplicaSafe ones —
/// the event-outbox poll, the three retention prunes, the app_perf rollup upsert,
/// and the MUST-run-per-replica / shared-PG-writing passes found by the sweep
/// (cert reloader, catalogue rollup, provisional-MFA cleanup, OTA watchdog, MCP
/// projector, MCP bridge sweep + session gc, store-worker delivery pools, the
/// HA WS-8 Postgres reachability probe). This
/// proves named⇒classified for those sites. It does NOT yet prove pass⇒named for
/// every dispatch site — a consteval sweep visiting ALL of them is a tracked
/// follow-up (#4094) — so completeness rests on THIS array plus the recorded
/// sweep methodology below and the routed-concern review
/// (cpp-safety+sre+compliance-officer on any new background pass). A new
/// side-effecting pass is a diff against THIS array, never a silent addition.
///
/// SWEEP METHODOLOGY (how this array was made exhaustive — repeat it on any audit).
/// Over `server/core/` + `common/include/yuzu/`, grep for: `std::thread` /
/// `std::jthread` / `*_thread_` members / `.detach()` (thread-start sites);
/// `while (`/`for (;;)` bodies containing `sleep_for` / `wait_for` / a
/// condition-variable wait (periodic loops); and the verbs `run_loop` / `sweep` /
/// `tick` / `reap` / `cleanup` / `refresh` / `drain` / `recompute` / `poll` /
/// `reconcile` / `sync` / `watchdog`. For each hit decide: per-request handler
/// (OUT — rides the caller's thread, e.g. the detached gateway-forward, the lazy
/// FleetTopologyStore refill, per-request SSE waits) or a standing background pass
/// (IN — gets a row here). The 2026-09-07 sweep added 8 passes an earlier revision
/// missed (cert reloader, catalogue rollup, provisional-MFA cleanup, OTA watchdog,
/// MCP projector, MCP bridge sweep, MCP session gc, store-worker delivery pools);
/// deliberately-excluded non-passes (documented so the next audit does not re-flag
/// them): the detached per-dispatch gateway-forward thread, FleetTopologyStore's
/// request-path refill, ExecutionEventBus inline gc, `shutdown_watcher.hpp`'s
/// signal self-pipe watcher, per-request SSE `wait_for` loops, and boot-time
/// one-shot poll loops (`default_certs.cpp`, `nvd_client.cpp`).

#include <array>
#include <cstddef>
#include <string_view>

namespace yuzu::server {

enum class BackgroundJobClass {
    ReplicaSafe,
    FencedLeaderOnly,
    DisabledUntilFixed,
};

struct BackgroundJobDecl {
    std::string_view pass;          ///< stable pass symbol (unique key)
    std::string_view owning_thread; ///< the thread whose tick invokes it
    BackgroundJobClass cls;
    std::string_view mechanism;     ///< why the class holds (the recorded rationale)
};

/// The exhaustive inventory (44 passes). Verified against the source sweep
/// 2026-09-07 per the SWEEP METHODOLOGY above (plus the WS-4 4.2a addition of
/// `gateway_route_store.reap_stale_routes`, 2026-09-11, and the HA WS-8 addition
/// of `pg_reachability_probe.tick`, 2026-09-24); keep the count
/// tripwire in `test_background_jobs.cpp` in step with any add/remove here.
inline constexpr std::array kBackgroundJobs = std::to_array<BackgroundJobDecl>({
    // ---- result_set_maint_thread_ (2s tick) ----
    {"session_clock_monitor.observe", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica local host-clock drift metric"},
    {"result_set_store.materialize", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "execute-once via status='pending' CAS UPDATE; device rows ON CONFLICT DO NOTHING"},
    {"result_set_store.gc_sweep", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded (ADR-0036/0040); regenerable scratch, a double-gc of already-expired rows is harmless"},
    {"response_store.reap_expired", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (ADR-0039)"},
    {"guaranteed_state_store.reap_expired", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (ADR-0038, #2663)"},
    {"session_store.reap_expired", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory-lock own-statement (ADR-2002 §4)"},
    {"execution_tracker.reap_command_execution_mappings", "result_set_maint_thread_",
     BackgroundJobClass::ReplicaSafe, "clock-guarded + pg_advisory_xact_lock"},
    {"execution_tracker.reconcile_stale_concurrency_claims", "result_set_maint_thread_",
     BackgroundJobClass::DisabledUntilFixed,
     "advisory-lock SINGLE-WRITER (pg_try_advisory_xact_lock, WS-10 10.2, this change) — prevents "
     "concurrent double-reconcile — but NOT yet safe for a 2nd replica: its clock authority is still "
     "replica-local system_clock (both the claim expires_at write via now_epoch() and the reconcile "
     "read/compare), NOT shared PG-now, so a skewed winner could release a live claim early. Named fix: "
     "concurrency_claims DB-clock-authority migration (WS-1 class, #3715 shape, tracked #4093). Same "
     "posture as nvd_sync.do_sync (a pending prerequisite migration → DisabledUntilFixed), NOT "
     "ReplicaSafe — the advisory lock is real progress but does not make two replicas' clocks one "
     "authority. Runs on the single replica today; the class gates a 2nd replica on the fix"},
    {"execution_tracker.reap_event_outbox", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + pg_try_advisory_xact_lock"},
    {"execution_tracker.poll_event_outbox_once", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "MUST run per-replica — cross-replica SSE delivery (ADR-2002 §5); NEVER leader-gate"},
    {"gateway_route_store.reap_stale_routes", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded (SessionStore shape, clock-guard part 1 carved out, part 4 adopted "
     "direction-keyed decline-once/drain-on-repeat) + pg_try_advisory_xact_lock own-statement; "
     "DB-clock-authored leases — every replica may tick it, all but the advisory-lock holder "
     "skip (PR #4299 round-2 external review); matches the other reaper classifications (WS-4 4.2a)"},
    {"result_set_store.counts", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "read-only gauge refresh"},

    // ---- app_perf_rollup_thread_ (1h tick) ----
    {"app_perf_rollup.roll_window", "app_perf_rollup_thread_", BackgroundJobClass::ReplicaSafe,
     "idempotent upsert (ON CONFLICT (app_name,version,day) DO UPDATE)"},
    {"app_perf_fleet_store.run_retention_prune", "app_perf_rollup_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (WS-10 10.2)"},

    // ---- preflight_runner_thread_ (60s tick) ----
    {"preflight_runner.redispatch_readonly_checks", "preflight_runner_thread_",
     BackgroundJobClass::ReplicaSafe,
     "read-only/idempotent check re-dispatch to a frozen cohort (routed concern: safe ONLY while read-only)"},
    {"preflight_run_store.run_retention_prune", "preflight_runner_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (WS-10 10.2)"},
    {"deployment_run_store.run_retention_prune", "preflight_runner_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (WS-10 10.2); piggybacks the preflight thread"},

    // ---- policy_eval_thread_ (10s tick) — tick() SPLITS into two passes (PR #4134) ----
    {"policy_evaluator.collect_ready", "policy_eval_thread_", BackgroundJobClass::ReplicaSafe,
     "MUST run per-replica: the ONLY completion path that matures an in-flight Check/FixWait created by "
     "the operator-synchronous evaluate_now()/remediate() plane (accepted on any replica, ungated) to a "
     "terminal verdict — gating it strands an operator remediation as `fixing` forever on a non-leader "
     "(two-dispatch-planes rule). Replica-local + in-memory; the durable per-(policy,agent) remediation "
     "claim it RELEASES at FixWait maturation (WS-3 3.4) is held only by this dispatching replica, so "
     "there is still nothing to fence"},
    {"policy_evaluator.dispatch_due", "policy_eval_thread_", BackgroundJobClass::FencedLeaderOnly,
     "side-effecting due-policy scheduling dispatch; ADR-0056 claim_due_policies is fleet-safe but the leader-only gate cuts non-leader churn (WS-3 3.2). The operator remediation plane (WS-3 3.4) is a SEPARATE, ungated path with its own durable per-(policy,agent) CAS — not this due-scheduling dispatch"},

    // ---- schedule_tick_thread_ (30s schedule eval; 5s outbox delivery sub-tick) ----
    {"schedule_runner.tick", "schedule_tick_thread_", BackgroundJobClass::FencedLeaderOnly,
     "side-effecting scheduled dispatch — enqueues a durable outbox occurrence; double-enqueue across replicas without a fenced leader (WS-3 3.2/3.3)"},
    {"command_outbox.deliver", "schedule_tick_thread_", BackgroundJobClass::FencedLeaderOnly,
     "side-effecting wire dispatch of pending command-outbox occurrences (WS-3 3.3); effectively-once holds via the stable command_id + agent dedup, but the leader gate keeps a second replica from redundantly re-driving"},

    // ---- quarantine_reconcile_thread_ (20s tick) ----
    {"quarantine_reconciler.tick", "quarantine_reconcile_thread_", BackgroundJobClass::FencedLeaderOnly,
     "side-effecting containment re-dispatch (WS-3 3.2; confirm WS-4/5 stream-locality interaction)"},

    // ---- quarantine_snapshot_refresh_thread_ (20s tick) ----
    {"quarantine_store.list_quarantined_snapshot", "quarantine_snapshot_refresh_thread_",
     BackgroundJobClass::ReplicaSafe, "per-replica read-only cache for the #881 dispatch gate"},

    // ---- health_recompute_thread_ (15s tick) ----
    {"health_store.recompute_metrics", "health_recompute_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica read-only fleet gauges (incl. stream-budget/pg-pool/KEK-state/cohort-perf gauges)"},
    {"software_inventory_store.count_stale_agents", "health_recompute_thread_",
     BackgroundJobClass::ReplicaSafe, "read-only inventory-freshness gauge"},
    {"registry.reap_stale_sessions", "health_recompute_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica in-memory Subscribe-stream reap (local presence)"},
    {"ca.publish_crl", "health_recompute_thread_", BackgroundJobClass::FencedLeaderOnly,
     "DB-WRITE: freshness re-publish; numbering is safe on any replica (WS-6 6.1 table lock), gated only to avoid N redundant CRLs per stale tick"},
    {"registry.teardown_revoked_streams", "health_recompute_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica: tears down only the Subscribe streams connected to THIS replica"},
    {"mcp_stream_bridge.sweep", "health_recompute_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica in-memory: pin-ack/session-death/age-reaper teardown over THIS replica's ≤256 bridge records; no shared state"},
    {"mcp_session_registry.gc", "health_recompute_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica in-memory: destroys expired MCP session streams held by THIS replica; no shared state"},

    // ---- engine_rotation_sweep_thread_ (60s tick) ----
    {"api_token_store.sweep_expired_rotations", "engine_rotation_sweep_thread_",
     BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (SkippedLock outcome); already single-writer compliant"},

    // ---- insecure_tls_reminder_thread_ (300s tick) ----
    {"insecure_tls_reminder", "insecure_tls_reminder_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica idempotent log + audit reminder"},

    // ---- web_thread_ / redirect_thread_ (blocking listeners, no periodic pass) ----
    {"web_server.listen", "web_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica HTTP listener; work is per-request handlers, not a periodic pass"},
    {"redirect_server.listen", "redirect_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica HTTP→HTTPS 301 listener"},

    // ---- store-internal threads ----
    {"audit_store.cleanup_once", "AuditStore::cleanup_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (the canonical retention reference impl)"},
    {"analytics_event_store.drain_batch", "AnalyticsEventStore::drain_thread_",
     BackgroundJobClass::ReplicaSafe, "SHARED-PG outbox, advisory-lock SINGLE-SWEEPER: a pg_try_advisory_xact_lock claim + UPDATE...RETURNING claims a batch (drained=true), then delivers to the registered sink(s) with NO lease held (revert-on-failure) — concurrent replicas serialize on the lock, one sweeper per tick"},
    {"nvd_sync.do_sync", "NvdSyncManager::sync_thread_", BackgroundJobClass::DisabledUntilFixed,
     "engine-tier migration pending (ADR-1005 Phase 7 / ADR-0023); only a process-local single-flight (sync_active_ CAS), not cross-replica — must move to the engine tier or be leader-gated before a 2nd replica"},

    // ---- other dedicated component threads (added by the 2026-09-07 exhaustive sweep) ----
    {"cert_reloader.run_loop", "CertReloader::thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica: polls THIS replica's on-disk cert/key mtimes and hot-swaps its own in-process SSL_CTX; each reload also writes ONE audit row (an unconditional INSERT, not deduplicated — per-replica audit observations are expected to differ)"},
    {"software_catalog_rollup.refresh_catalog_rollup", "SoftwareCatalogRollup::thread_",
     BackgroundJobClass::ReplicaSafe,
     "SHARED-PG, SINGLE-WRITER: refresh_catalog_rollup ALREADY takes a transaction-scoped pg_try_advisory_xact_lock (skip-if-held) before its one-txn DELETE+INSERT atomic replace of the catalogue rollup tables, and is keep-last-good on failure — so concurrent replicas serialize on the lock (a loser skips), never racing the unique-key replace"},
    {"auth_db.cleanup_provisional_mfa", "AuthDB::cleanup_thread_", BackgroundJobClass::ReplicaSafe,
     "SHARED-PG, idempotent: a single predicate-scoped UPDATE expiring stale provisional-MFA rows on a PG now() cutoff (shared clock) — an already-cleared row ceases to match, so concurrent replicas converge with no advisory lock. NOT row-count-bounded (no LIMIT; kWriteTimeout bounds the connection acquire, not the rows) and not a would-wipe reaper"},
    {"ota_transfer_watchdog.sweep_once", "OtaTransferWatchdog::sweeper_", BackgroundJobClass::ReplicaSafe,
     "per-replica: cancels only the OTA transfers registered on THIS replica's gRPC server (borrowed ServerContext*); the sole per-replica OTA deadline enforcer — MUST run per-replica, never leader-gate; no shared state"},
    {"mcp_stream_bridge.run_projector", "McpStreamBridge::projector_", BackgroundJobClass::ReplicaSafe,
     "per-replica in-process: projects ExecutionEventBus progress/terminal frames to the MCP SSE listeners connected to THIS replica; MUST run per-replica; no shared state (terminals are durably re-fetchable)"},
    {"store_worker_pool.worker_loop", "StoreWorkerPool::workers_", BackgroundJobClass::ReplicaSafe,
     "per-replica in-process delivery-queue drain (WebhookStore + OffloadTargetStore delivery_pool_): POSTs the events THIS replica enqueued via submit(); MUST run per-replica. CAVEAT/tracked: the pass itself is replica-local, but whether a given logical event is enqueued once-per-fleet or once-per-replica is an EMIT-SITE concern (verify webhook/offload emit sites are per-replica-origin before a 2nd replica, or a fleet-triggered emit double-delivers; tracked #4098)"},
    {"pg_reachability_probe.tick", "PgReachabilityProbe::thread_", BackgroundJobClass::ReplicaSafe,
     "HA WS-8 per-replica read-only probe (pg_is_in_recovery() / transaction_read_only on its own dedicated connection) feeding THIS replica's /readyz pg_reachable row; MUST run per-replica — each replica measures its OWN path to Postgres; never leader-gate (a follower would then report stale/unready and be evicted from the LB)"},
});

/// Index of `pass` in kBackgroundJobs, or -1 if absent. consteval so a site
/// assertion resolves at compile time.
consteval int background_job_index(std::string_view pass) {
    for (std::size_t i = 0; i < kBackgroundJobs.size(); ++i)
        if (kBackgroundJobs[i].pass == pass)
            return static_cast<int>(i);
    return -1;
}

/// The class of a background pass, resolved at COMPILE TIME (slice 3.2's runtime
/// gate, `leader_gate.hpp`, dispatches on this). Pairs with
/// `YUZU_ASSERT_BACKGROUND_JOB` at the same site: an unclassified `pass` throws
/// in constant evaluation, which is a hard BUILD FAILURE — the gate can never be
/// applied to an unclassified pass, and never silently defaults to a class. This
/// is what makes the runtime leader-gate unable to drift from this table: change
/// a pass's class here and its gate follows, because the gate reads it FROM here.
consteval BackgroundJobClass background_job_class(std::string_view pass) {
    const int i = background_job_index(pass);
    if (i < 0)
        throw "background pass is not classified in kBackgroundJobs "
              "(server/core/src/background_jobs.hpp)";
    return kBackgroundJobs[static_cast<std::size_t>(i)].cls;
}

/// Assert (at compile time) that a background pass is classified in
/// kBackgroundJobs. Place at each pass's dispatch site. An unregistered pass is
/// a build failure — the "nothing silently escapes" guarantee.
#define YUZU_ASSERT_BACKGROUND_JOB(pass_literal) \
    static_assert(::yuzu::server::background_job_index(pass_literal) >= 0, \
                  "background pass '" pass_literal \
                  "' is not classified in kBackgroundJobs (server/core/src/background_jobs.hpp) — " \
                  "WS-10 requires every background pass be classified for replica-safety")

} // namespace yuzu::server
