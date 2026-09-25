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
    /// durable presence store this class writes, for a session-guarded
    /// delete (`OfflineEndpointStore::remove_if_session`) — reusing the
    /// existing wiring rather than threading a second pointer through
    /// `AgentServiceImpl`/`GatewayUpstreamServiceImpl`. May be null.
    [[nodiscard]] OfflineEndpointStore* offline_endpoint_store() const { return offline_store_; }

    /// Ingest one heartbeat. `agent_id` is the session-resolved agent id
    /// (already validated by the caller). `via` is "direct" or "gateway"
    /// — the only label that varies between the two ingestion paths.
    void ingest(const ::yuzu::agent::v1::HeartbeatRequest& hb, std::string_view agent_id,
                std::string_view via);

    /// Guardian heartbeat reconcile (M5 / #1209). Invoked once per heartbeat that
    /// carries the `yuzu.guardian_generation` tag, with the agent's applied policy
    /// generation. The server wires this to compare against the current generation
    /// and re-push a lagging agent — the convergence path for an agent that was
    /// offline at push time or has just reconnected. Optional; unset = no reconcile.
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
