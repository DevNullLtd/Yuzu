#include "heartbeat_ingestion.hpp"

#include "agent_registry.hpp"
#include "fleet_topology_store.hpp"
#include "offline_endpoint_store.hpp"

#include "agent.grpc.pb.h"

#include <yuzu/metrics.hpp>
#include <spdlog/spdlog.h>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <string>

namespace yuzu::server {

void HeartbeatIngestion::ingest(const ::yuzu::agent::v1::HeartbeatRequest& hb,
                                std::string_view agent_id, std::string_view via) {
    const std::string agent_id_str(agent_id);
    const std::string via_str(via);

    if (health_store_) {
        health_store_->upsert(agent_id_str, hb.status_tags());
    }
    if (metrics_) {
        metrics_->counter("yuzu_heartbeats_received_total", {{"via", via_str}}).increment();
    }

    // Durable last-known endpoint state (#1320 PR 3, Postgres substrate):
    // persist who this agent is + that we just heard from it, so a host that
    // ages out of the in-memory 60 s topology cache renders stale-flagged on
    // /viz/fleet instead of vanishing. Best-effort and OFF the gRPC hot-path
    // lock — a slow/blipping database never blocks the heartbeat (the in-memory
    // stores stay authoritative). Does not touch the executions-ladder
    // invariants (the command_id -> execution_id correlation / polchk-):
    // those live on the CommandResponse path, not here.
    if (offline_store_) {
        std::string hostname;
        std::string os;
        std::string agent_version;
        std::string arch;
        std::string session_id;
        if (auto sess = registry_.get_session(agent_id_str)) {
            hostname = sess->hostname;
            os = sess->os;
            agent_version = sess->agent_version;
            arch = sess->arch;
            // HA WS-5: threaded through so a later graceful disconnect can
            // session-guard its presence-row delete (remove_if_session) —
            // see agent_service_impl.cpp / gateway_service_impl.cpp.
            session_id = sess->session_id;
        }
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
        // agent_ts is RESERVED: the schema/struct carry it for a future
        // agent-emitted snapshot timestamp, but the heartbeat path has no such
        // value today, so it is always 0 in production (gov consistency
        // SHOULD-1). Staleness is driven entirely by the server-side
        // last_heartbeat_ms. Wire a real agent ts here when one exists, or drop
        // the column — tracked as a follow-up.
        //
        // agent_version/arch: a session-lookup miss above leaves both blank,
        // which upsert() treats as "preserve the last-known value" (round-3 v2
        // columns) rather than blanking a value this store already learned.
        offline_store_->upsert(agent_id_str, hostname, os, now_ms, /*agent_ts=*/0, agent_version,
                               arch, session_id);
    }

    // Guardian heartbeat reconcile (M5 / #1209): if the agent reported its applied
    // policy generation, hand it to the reconcile hook so the server can re-push a
    // lagging agent (offline at push time / just reconnected). Parse defensively —
    // a malformed tag from a buggy agent must not disturb the rest of ingestion.
    if (guardian_reconcile_fn_) {
        const auto& tags = hb.status_tags();
        auto it = tags.find("yuzu.guardian_generation");
        if (it != tags.end()) {
            std::uint64_t gen = 0;
            const auto& v = it->second;
            auto [ptr, ec] = std::from_chars(v.data(), v.data() + v.size(), gen);
            // Require the WHOLE tag to parse (ptr at end) — "123abc" must be
            // rejected, not silently read as 123 (cpp-expert / #1209).
            if (ec == std::errc() && ptr == v.data() + v.size())
                guardian_reconcile_fn_(agent_id_str, gen);
        }
    }

    // #3425: quarantine reconnect reconciler. Unconditional — reconnect
    // itself is the signal, no tag to gate on (unlike the guardian hook
    // above). Defensive: never let a reconcile hook take down the rest of
    // ingestion.
    //
    // Held for the ENTIRE call, not just the fn copy (governance Gate 3,
    // cpp-safety, 2026-08-24) — the shared lock IS the liveness proof
    // `set_quarantine_reconcile_fn(nullptr)`'s exclusive lock waits on; a
    // copy-then-call-outside-the-lock idiom would let set(nullptr) return
    // while a copied fn is still running, which reopens the same
    // use-after-free window this lock exists to close. Concurrent ingest()
    // calls from other heartbeats are unaffected (shared/shared never
    // blocks).
    {
        std::shared_lock lock(quarantine_reconcile_mu_);
        if (quarantine_reconcile_fn_) {
            try {
                quarantine_reconcile_fn_(agent_id_str);
            } catch (const std::exception& e) {
                spdlog::warn("[{}] Heartbeat quarantine reconcile threw for agent={}: {}", via_str,
                            agent_id_str, e.what());
            }
        }
    }

    // PR 10 / UAT 2026-05-12 — fleet_snapshot.v1 ingestion. Parse failures
    // are non-fatal: a malformed payload from a buggy agent must not knock
    // the heartbeat path offline for the rest of the fleet.
    if (fleet_topology_store_ && !hb.fleet_snapshot_json().empty()) {
        std::string os_from_session;
        if (auto sess = registry_.get_session(agent_id_str))
            os_from_session = sess->os;
        std::string parse_err;
        auto parsed = FleetTopologyStore::parse_fleet_snapshot_json(
            hb.fleet_snapshot_json(), agent_id_str, os_from_session, &parse_err);
        if (parsed.has_value()) {
            fleet_topology_store_->push_snapshot(std::move(*parsed));
            if (metrics_) {
                metrics_->counter("yuzu_viz_topology_pushed_total", {{"via", via_str}}).increment();
            }
        } else {
            spdlog::warn("[{}] Heartbeat fleet_snapshot from agent={} rejected ({})", via_str,
                         agent_id_str, parse_err);
            if (metrics_) {
                metrics_->counter("yuzu_viz_topology_push_parse_errors_total", {{"via", via_str}})
                    .increment();
            }
        }
    }
}

} // namespace yuzu::server
