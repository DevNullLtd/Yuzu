#pragma once

/**
 * heartbeat_ingestion.hpp — shared ingestion pipeline for heartbeat payloads.
 *
 * #1000 / arch-S2: both AgentServiceImpl::Heartbeat (direct) and
 * GatewayUpstreamServiceImpl::BatchHeartbeat (gateway-batch) perform the
 * same fan-out of work for each accepted heartbeat:
 *   • health_store_->upsert(agent_id, status_tags)
 *   • yuzu_heartbeats_received_total{via=...}++
 *   • optional fleet_snapshot.v1 parse + FleetTopologyStore::push_snapshot
 *   • yuzu_viz_topology_pushed_total{via=...}++ / push_parse_errors_total++
 *
 * Three independent ingestion features have followed this pattern. The
 * next will drift between the two paths in production unless the work
 * lives behind one entry point. HeartbeatIngestion owns that entry point;
 * each gRPC service is reduced to one call per heartbeat.
 *
 * The class holds non-owning pointers to the shared stores wired in
 * server bring-up. The `via` label is the only per-call difference
 * between the direct and gateway paths.
 */

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {
class FleetTopologyStore;
class OfflineEndpointStore;
} // namespace yuzu::server

namespace yuzu::server::detail {
class AgentRegistry;
class AgentHealthStore;
} // namespace yuzu::server::detail

namespace yuzu::agent::v1 {
class HeartbeatRequest;
}

namespace yuzu::server {

class HeartbeatIngestion {
public:
    HeartbeatIngestion(detail::AgentRegistry& registry, detail::AgentHealthStore* health_store,
                       FleetTopologyStore* fleet_topology_store, MetricsRegistry* metrics,
                       OfflineEndpointStore* offline_store = nullptr)
        : registry_(registry), health_store_(health_store),
          fleet_topology_store_(fleet_topology_store), metrics_(metrics),
          offline_store_(offline_store) {}

    HeartbeatIngestion(const HeartbeatIngestion&) = delete;
    HeartbeatIngestion& operator=(const HeartbeatIngestion&) = delete;

    /// Borrowed durable last-known-endpoint store (#1320 PR 3). Nulled in
    /// server stop() after the gRPC drain so a late ingest cannot touch the
    /// released store. Optional — null = no persistence (legacy behavior).
    void set_offline_endpoint_store(OfflineEndpointStore* s) { offline_store_ = s; }

    /// HA WS-5 (ADR-2002 §7a): lets a disconnect handler reach the same
    /// durable presence store this class writes, for the session-guarded
    /// presence clear (presence_departure.hpp) — reusing the
    /// existing wiring rather than threading a second pointer through
    /// `AgentServiceImpl`/`GatewayUpstreamServiceImpl`. May be null.
    [[nodiscard]] OfflineEndpointStore* offline_endpoint_store() const { return offline_store_; }

    /// Ingest one heartbeat. `agent_id` is the session-resolved agent id
    /// (already validated by the caller). `via` is "direct" or "gateway"
    /// — the only label that varies between the two ingestion paths.
    ///
    /// `resolved_session_id` (HA WS-5): the session id the caller resolved
    /// `agent_id` from — for the gateway path, the directory-resolved
    /// session, which may belong to a gateway-fronted agent this replica
    /// holds no local `AgentSession` for. When non-empty it is what the
    /// durable presence row records as `session_id`, so a heartbeat ingested
    /// on a non-owning replica cannot blank it (the other presence columns
    /// blank-preserve in `OfflineEndpointStore::upsert`).
    ///
    /// `presence_batch` (#5686): per-RPC state for a batched caller. Once a
    /// presence upsert in the batch has failed, later entries skip theirs
    /// (each would wait out its own bounded acquire on the same degraded
    /// store) EXCEPT half-open probes: the entry right after the FIRST failure
    /// is attempted (an isolated failure costs only itself), and the spacing
    /// doubles on each further consecutive failure -- after the Nth
    /// consecutive failure the next 2^(N-1) - 1 entries are skipped and the
    /// entry after them attempts the upsert again (1st failure skips 0, 2nd
    /// skips 1, 3rd skips 3, ...). Under total saturation the attempts land
    /// on entries 1, 2, 4, 8, 16, 32, ... A probe that succeeds closes the
    /// trip (store_failed=false, spacing reset), so a store that recovers
    /// mid-batch is detected by the next probe and later entries are written
    /// again. Everything else in ingest() still runs for a skipped entry.
    ///
    /// Bound under TOTAL saturation (every attempt fails): at most
    /// floor(log2 N) + 1 upserts are attempted per batch of N, each bounded at
    /// the store's 250 ms acquire, instead of N (82 s at N=330 before #5686).
    /// Under PARTIAL brownout the spacing resets on each success, so tail
    /// agents are not systematically starved of presence refresh.
    ///
    /// The trip consumes `OfflineEndpointStore::upsert()`'s bool, which is
    /// false on ANY failure: lease timeout, query error, and also a
    /// not-open store or an empty agent_id. A caller therefore cannot tell
    /// pool saturation from a permanent condition by this signal alone.
    ///
    /// Null (the direct path) = attempt every upsert, as before.
    struct PresenceBatch {
        /// True while the most recent attempted upsert failed (the trip).
        bool store_failed{false};
        /// Entries whose upsert was skipped by the trip (not attempted).
        std::size_t skipped{0};
        /// Upsert attempts that failed in this batch (never reset). Unlike
        /// store_failed, which a later successful probe clears, a nonzero
        /// value tells the caller the batch hit presence trouble even when
        /// the store recovered, and when the failure was on the LAST entry.
        std::size_t failed{0};
        /// Entries skipped since the last failed attempt (probe spacing).
        std::size_t skips_since_fail{0};
        /// Entries (counting the probe itself) between attempts while
        /// tripped. 1 after the first failure of a streak (the next entry is
        /// the probe) and after any success; doubles on each further
        /// consecutive failure, capped at kMaxProbeSpacing.
        std::size_t next_probe{1};
        static constexpr std::size_t kMaxProbeSpacing = std::size_t{1} << 16;
    };
    void ingest(const ::yuzu::agent::v1::HeartbeatRequest& hb, std::string_view agent_id,
                std::string_view via, std::string_view resolved_session_id = {},
                PresenceBatch* presence_batch = nullptr);

    /// Guardian heartbeat reconcile (M5 / #1209). Invoked once per heartbeat that
    /// carries the `yuzu.guardian_generation` tag, with the agent's applied policy
    /// generation. The server wires this to compare against the current generation
    /// and re-push a lagging agent — the convergence path for an agent that was
    /// offline at push time or has just reconnected. An agent also reports
    /// generation 0 (intermittently, see the agent's back-off) while a boot
    /// re-arm failure is unresolved (#5513), so the same
    /// re-push is its catch-up. Optional; unset = no reconcile.
    using GuardianReconcileFn =
        std::function<void(std::string_view agent_id, std::uint64_t agent_generation)>;
    void set_guardian_reconcile_fn(GuardianReconcileFn fn) {
        guardian_reconcile_fn_ = std::move(fn);
    }

    /// Quarantine reconnect reconciler (#3425). Invoked UNCONDITIONALLY once
    /// per ingested heartbeat (unlike the guardian hook above, this one
    /// carries no tag to gate on — reconnect itself is the signal). The
    /// callee (`QuarantineContainmentReconciler::notify_agent_heartbeat`)
    /// owns its own fast-path cache lookup, so an unset or a hit-nothing fn
    /// costs at most one branch here. Optional; unset = no reconcile.
    ///
    /// Synchronized (governance Gate 3, cpp-safety, 2026-08-24) — unlike
    /// `guardian_reconcile_fn_`/`offline_store_` above, which are bare/raw
    /// and rely on the (pre-existing, out of scope for this fix) benign-
    /// aligned-pointer-store argument. That argument does not extend to a
    /// `std::function`: a live `ingest()` call on a heartbeat-handler thread
    /// can still be INSIDE `quarantine_reconcile_fn_(...)` — doing blocking
    /// Postgres + gRPC-dispatch I/O — when `server.cpp`'s stop() sequence
    /// nulls the fn and then `.reset()`s the `QuarantineContainmentReconciler`
    /// the fn's closure captures. `agent_server_->Shutdown(deadline)` is a
    /// BOUNDED drain, not a quiescence guarantee (same "a handler thread can
    /// legitimately outlive the deadline" precedent as the `execution_tracker_`/
    /// `nvd_sync_`/`web_thread_` teardown comments in server.cpp) — so a
    /// reassignment-during-call (a `std::function`'s destructive multi-word
    /// reassign racing its own `operator()`) and a post-null dangling capture
    /// are both real, not theoretical. `quarantine_reconcile_mu_` makes
    /// `set_quarantine_reconcile_fn(nullptr)` an actual drain barrier: it
    /// takes the EXCLUSIVE lock, so it cannot return while `ingest()` still
    /// holds the SHARED lock across an in-flight call — the caller in
    /// server.cpp's stop() is therefore guaranteed no invocation is in
    /// flight once `set_quarantine_reconcile_fn(nullptr)` returns, and only
    /// then is it safe to `.reset()` the reconciler the closure captures.
    /// Concurrent `ingest()` calls from different heartbeats are unaffected
    /// (shared/shared never blocks each other) — only the teardown set(nullptr)
    /// pays the cost of a real wait, and only once, at shutdown.
    using QuarantineReconcileFn = std::function<void(std::string_view agent_id)>;
    void set_quarantine_reconcile_fn(QuarantineReconcileFn fn) {
        std::unique_lock lock(quarantine_reconcile_mu_);
        quarantine_reconcile_fn_ = std::move(fn);
    }

private:
    detail::AgentRegistry& registry_;
    detail::AgentHealthStore* health_store_;
    FleetTopologyStore* fleet_topology_store_;
    MetricsRegistry* metrics_;
    OfflineEndpointStore* offline_store_{nullptr};
    GuardianReconcileFn guardian_reconcile_fn_;
    QuarantineReconcileFn quarantine_reconcile_fn_;
    std::shared_mutex quarantine_reconcile_mu_;
};

} // namespace yuzu::server
