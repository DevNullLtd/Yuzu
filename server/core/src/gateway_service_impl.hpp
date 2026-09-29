#pragma once

/// @file gateway_service_impl.hpp
/// gRPC GatewayUpstream service: ProxyRegister, BatchHeartbeat, ProxyInventory.

#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include "agent.grpc.pb.h"
#include "gateway.grpc.pb.h"
#include "management.grpc.pb.h"
#include "agent_registry.hpp"
#include "cert_issuance_source.hpp"
#include "event_bus.hpp"
#include "gateway_route_store.hpp"

// Forward declarations
namespace yuzu::server {
class ManagementGroupStore;
class InventoryStore;
class SoftwareInventoryStore;
class AppPerfDailyStore;
class DeviceInventoryStore;
class SoftwareLicensingStore;
class AppUsageStore;
class FleetTopologyStore;
class HeartbeatIngestion;
class AnalyticsEventStore;
class AuditStore;
class GuaranteedStateStore;
class BlastRadiusDetector;
class DexAlertRouter;
} // namespace yuzu::server

namespace yuzu::server::detail {

namespace gw = ::yuzu::gateway::v1;
namespace pb = ::yuzu::agent::v1;

// HA WS-4 4.3: `StreamStatusNotification.cluster_id` is gateway-asserted,
// untrusted input — see gateway_service_impl.cpp's ingest-clamp comment at
// its NotifyStreamStatus CONNECTED use for the full rationale. Declared here
// (not TU-local) because `main.cpp`'s `--gateway-cluster-addr` CLI parser
// (`parse_gateway_cluster_addrs`, gateway_mgmt_stub_pool.hpp) validates a
// configured cluster_id key against this SAME bound — one constant, two
// call sites, never a duplicated magic number.
inline constexpr std::size_t kMaxClusterIdLen = 64;

// HA WS-4 4.3 (sre Gate 3): caps GatewayUpstreamServiceImpl::
// unmapped_clusters_warned_'s ENTRY COUNT — each entry is already
// per-entry-bounded by kMaxClusterIdLen, but the set itself had no cap on
// how many distinct unmapped cluster_id values it could accumulate over
// process lifetime. 256 is generous headroom over any real deployment's
// cluster count (a handful to low tens) while still bounding worst-case
// memory from a session cycling through many distinct malformed/
// misconfigured values.
inline constexpr std::size_t kMaxUnmappedClustersWarned = 256;

class GatewayUpstreamServiceImpl : public gw::GatewayUpstream::Service {
public:
    GatewayUpstreamServiceImpl(AgentRegistry& registry, EventBus& bus, auth::AuthManager& auth_mgr,
                               auth::AutoApproveEngine& auto_approve,
                               yuzu::MetricsRegistry* metrics = nullptr,
                               AgentHealthStore* health_store = nullptr);

    /// HA WS-4 slice 4.1: born-on-PG agent->cluster routing directory (see
    /// gateway_route_store.hpp). Written on connect/heartbeat/disconnect below;
    /// INERT this slice — nothing reads it for dispatch yet. nullptr (default,
    /// and set back to nullptr in server.cpp's stop() before the store resets)
    /// disables the writes — every write site below is fail-OPEN and tolerates
    /// a null store the same way it tolerates a degraded write.
    void set_gateway_route_store(GatewayRouteStore* store) { gateway_route_store_ = store; }
    /// HA WS-4 4.3: the set of `cluster_id` keys `--gateway-cluster-addr`
    /// configured (plus the auto-aliased `"default"`), for a CONNECTED-time
    /// early warning when a session announces an unmapped cluster_id — see
    /// the NotifyStreamStatus CONNECTED branch. nullptr (the default, and
    /// what server.cpp wires when the flag is unset) means single-cluster
    /// mode: skip the check entirely, since every cluster_id resolves to the
    /// legacy stub regardless of its value in that mode. The pointee is
    /// immutable, boot-time-built config (`GatewayMgmtStubPool`'s key set,
    /// server.cpp) — no lifetime/mutation concerns beyond outliving this
    /// object, same contract as every other raw store pointer here.
    void set_known_gateway_clusters(const std::unordered_set<std::string>* clusters) {
        known_gateway_clusters_ = clusters;
    }
    /// Test-only, see ProxyRegister's `proxy_register_interleave_hook_for_test_`
    /// firing-point comment in gateway_service_impl.cpp.
    void set_proxy_register_interleave_hook_for_test(std::function<void()> hook) {
        proxy_register_interleave_hook_for_test_ = std::move(hook);
    }
    void set_mgmt_group_store(ManagementGroupStore* store) { mgmt_group_store_ = store; }
    void set_inventory_store(InventoryStore* store) { inventory_store_ = store; }
    void set_software_inventory_store(SoftwareInventoryStore* store) {
        software_inventory_store_ = store;
    }
    void set_app_perf_daily_store(AppPerfDailyStore* store) { app_perf_daily_store_ = store; }
    void set_device_inventory_store(DeviceInventoryStore* store) {
        device_inventory_store_ = store;
    }
    /// Typed detected-licence projection (ADR-0024) — receives the
    /// software_licensing daily-sync source via ProxyInventory.
    void set_software_licensing_store(SoftwareLicensingStore* store) {
        software_licensing_store_ = store;
    }
    /// Typed per-agent last-used app-usage projection (Wave 7 PR7.2, ADR-0016
    /// §5) — receives the app_usage daily-sync source via ProxyInventory.
    void set_app_usage_store(AppUsageStore* store) { app_usage_store_ = store; }
    // PR 10 / UAT 2026-05-12: gateway-proxied heartbeats carry the
    // same fleet_snapshot_json field as direct heartbeats. Wire the
    // topology store so BatchHeartbeat ingests pushes from agents that
    // connect via the gateway. Without this hook, gateway-routed
    // fleets would still see /viz/fleet/topology fall back to the
    // dispatch path. nullptr disables for tests.
    void set_fleet_topology_store(FleetTopologyStore* store) { fleet_topology_store_ = store; }

    /// #1000 / arch-S2: shared HeartbeatIngestion (see AgentServiceImpl).
    void set_heartbeat_ingestion(HeartbeatIngestion* hi) { heartbeat_ingestion_ = hi; }

    /// W1.4 / #827: AnalyticsEventStore for the gateway enrollment path's
    /// `agent.enrollment_*` events (mirrors AgentServiceImpl's direct
    /// path). Without this set, the proxied-enrollment surface had no
    /// audit/analytics emission at all — a gap relative to direct
    /// connections that #827 closes alongside the race fix.
    void set_analytics_store(std::weak_ptr<AnalyticsEventStore> store) {
        analytics_store_ = std::move(store);
    }

    /// W1.4 / #827: AuditStore wired for enrollment-token consume rows
    /// on the gateway-proxied path. See AgentServiceImpl::set_audit_store
    /// for the SOC 2 / wire-collapse rationale — same contract here.
    void set_audit_store(AuditStore* store) { audit_store_ = store; }

    /// Guardian Half B: store for ingesting unsolicited "__guard__" drift
    /// events forwarded from gateway-connected agents via
    /// ForwardGuardianMessage. Same store AgentServiceImpl uses on the direct
    /// Subscribe path; both call the shared ingest_guardian_response so they
    /// cannot diverge. nullptr disables ingest (tests / store-less configs).
    void set_guaranteed_state_store(GuaranteedStateStore* store) {
        guaranteed_state_store_ = store;
    }

    /// Fleet-wide DEX incident detector (blast radius, coverage-map D3) — the
    /// shared ingest feeds it ruleless observations from gateway-connected
    /// agents, same as the direct path. nullptr disables detection.
    void set_blast_radius_detector(BlastRadiusDetector* detector) {
        blast_radius_detector_ = detector;
    }

    /// Operator-routed per-signal alerting (coverage-map F1) — fed alongside
    /// the blast-radius detector at the same ingest chokepoint. nullptr
    /// disables routing.
    void set_dex_alert_router(DexAlertRouter* router) { dex_alert_router_ = router; }

    /// PR5d: per-agent CSR signer. Same signature as
    /// AgentServiceImpl::AgentCertSigner; server.cpp wires BOTH to the SAME
    /// `sign_agent_csr`, so they cannot semantically drift (a type change breaks
    /// both wirings at compile time). Lets ProxyRegister issue a per-agent client
    /// cert to a gateway-enrolled agent exactly as the direct Register path does —
    /// closing the gap where through-gateway agents never received one. nullptr
    /// (default) = no issuance (tests / CA inactive), identical to direct.
    using AgentCertSigner = std::function<std::optional<std::pair<std::string, std::string>>(
        const std::string& csr_pem, const std::string& agent_id, CertIssuanceSource src)>;
    void set_agent_cert_signer(AgentCertSigner signer) { agent_cert_signer_ = std::move(signer); }

    grpc::Status ProxyRegister(grpc::ServerContext* context, const pb::RegisterRequest* request,
                               pb::RegisterResponse* response) override;

    grpc::Status BatchHeartbeat(grpc::ServerContext* context,
                                const gw::BatchHeartbeatRequest* request,
                                gw::BatchHeartbeatResponse* response) override;

    grpc::Status ProxyInventory(grpc::ServerContext* context, const pb::InventoryReport* request,
                                pb::InventoryAck* response) override;

    grpc::Status NotifyStreamStatus(grpc::ServerContext* context,
                                    const gw::StreamStatusNotification* request,
                                    gw::StreamStatusAck* response) override;

    grpc::Status ForwardGuardianMessage(grpc::ServerContext* context,
                                        const gw::ForwardGuardianRequest* request,
                                        gw::ForwardGuardianAck* response) override;

    // Status accessors for dashboard
    std::size_t session_count() const;

private:
    AgentRegistry& registry_;
    EventBus& bus_;
    auth::AuthManager& auth_mgr_;
    auth::AutoApproveEngine& auto_approve_;
    yuzu::MetricsRegistry* metrics_{nullptr};
    AgentHealthStore* health_store_{nullptr};
    GatewayRouteStore* gateway_route_store_{nullptr};
    const std::unordered_set<std::string>* known_gateway_clusters_{nullptr};
    // HA WS-4 4.3: which unmapped cluster_ids have already logged the
    // CONNECTED-time warning — once per id, not once per connect, so a
    // flapping/reconnecting agent on a permanently-misconfigured cluster
    // doesn't spam the log. The metric counter emitted alongside it (same
    // NotifyStreamStatus branch) increments on every occurrence regardless.
    mutable std::mutex unmapped_clusters_warned_mu_;
    std::unordered_set<std::string> unmapped_clusters_warned_;
    ManagementGroupStore* mgmt_group_store_{nullptr};
    InventoryStore* inventory_store_{nullptr};
    SoftwareInventoryStore* software_inventory_store_{nullptr};
    AppPerfDailyStore* app_perf_daily_store_{nullptr};
    DeviceInventoryStore* device_inventory_store_{nullptr};
    SoftwareLicensingStore* software_licensing_store_{nullptr};
    AppUsageStore* app_usage_store_{nullptr};
    FleetTopologyStore* fleet_topology_store_{nullptr};
    HeartbeatIngestion* heartbeat_ingestion_{nullptr};
    std::weak_ptr<AnalyticsEventStore> analytics_store_;
    AuditStore* audit_store_{nullptr};
    GuaranteedStateStore* guaranteed_state_store_{nullptr};
    BlastRadiusDetector* blast_radius_detector_{nullptr};
    DexAlertRouter* dex_alert_router_{nullptr};
    AgentCertSigner agent_cert_signer_;

    // Map of gateway session_id -> agent_id for validation.
    mutable std::mutex sessions_mu_;
    std::unordered_map<std::string, std::string> gateway_sessions_;

    // HA WS-4 4.2a #8: sessions whose `register_fresh` lost the connection
    // epoch race (RegisterFreshResult::won == false) at ProxyRegister time.
    // The session still enrolls/connects normally (unchanged from before this
    // slice — see the ProxyRegister "fresh" branch), but its directory row
    // belongs to a NEWER connection, so the FOLLOW-UP NotifyStreamStatus
    // CONNECTED for this session must not call announce_connected — doing so
    // would report `matched=false` and pollute the desync counter with a
    // benign, expected race loss (see record_directory_desync's header
    // comment). Same lock (sessions_mu_) as gateway_sessions_, entries added
    // at ProxyRegister time and removed together with gateway_sessions_'s
    // entry on DISCONNECTED.
    std::unordered_set<std::string> lost_race_sessions_;

    // HA WS-4 4.4 post-build adversarial review (PR #4636 FortitudeEtc,
    // BLOCKER 1): a per-agent striped lock serializing ProxyRegister's own
    // decide (renew_leases/reclaim_tombstoned_session) -> install
    // (AgentRegistry::register_agent/GatewayRouteStore::register_fresh ->
    // map_session -> gateway_sessions_) sequence for one agent_id at a time.
    // Without it, two concurrent ProxyRegister calls for the SAME agent_id
    // (an ordinary reconnect-storm timing, no partition required) can
    // interleave: a stale replay's decide-phase confirms its presented
    // session still owns the durable row, then — before that replay calls
    // register_agent — an entirely separate FRESH registration for the same
    // agent completes in full (both its own register_agent install AND its
    // register_fresh, which unconditionally wins the row). The replay then
    // proceeds to call register_agent: AgentRegistry::register_agent's own
    // two-phase guard (agent_registry.cpp) only catches a second call that
    // STARTS during THIS call's revoke window, not one that already
    // completed entirely beforehand — so the replay's install silently
    // overwrites the fresh registration's in-memory AgentSession, leaving
    // the durable store correctly on the fresh session while the in-memory
    // registry (what `send_to` actually dispatches through) points at the
    // stale one. Striped (one mutex per agent_id, not a single global lock)
    // so unrelated agents' registrations never contend; the map itself is
    // never pruned, matching `AgentRegistry::agents_`'s own never-erase-the-
    // key lifetime (bounded by the number of DISTINCT agents ever seen, not
    // by connection churn).
    std::mutex registration_locks_mu_;
    std::unordered_map<std::string, std::shared_ptr<std::mutex>> registration_locks_;

    /// Returns the (lazily-created) per-agent registration mutex for
    /// `agent_id`. The returned shared_ptr keeps the mutex alive for the
    /// caller's lock_guard even if another thread races to look up the same
    /// agent_id concurrently (the map itself is only touched under
    /// `registration_locks_mu_`, released before the returned mutex is ever
    /// locked).
    std::shared_ptr<std::mutex> registration_lock_for(const std::string& agent_id);

    /// Test-only, see the setter above and ProxyRegister's firing-point
    /// comment. nullptr (default) in production.
    std::function<void()> proxy_register_interleave_hook_for_test_;
};

// -- ManagementServiceImpl (placeholder) --------------------------------------

class ManagementServiceImpl : public ::yuzu::server::v1::ManagementService::Service {
public:
    // Placeholder.
};

} // namespace yuzu::server::detail
