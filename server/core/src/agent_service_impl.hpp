#pragma once

/// @file agent_service_impl.hpp
/// gRPC AgentService implementation: Register, Heartbeat, Subscribe, OTA updates.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include "agent.grpc.pb.h"
#include "agent_registry.hpp"
#include "cert_issuance_source.hpp"
#include "event_bus.hpp"
#include "ota_transfer_watchdog.hpp"
#include "ota_total_admission.hpp"
#include "principal_quota.hpp"
#include "rate_limiter.hpp"

// Forward declarations to avoid pulling in full store headers
namespace yuzu::server {
class ResponseStore;
class TagStore;
class AnalyticsEventStore;
class AuditStore;
class ManagementGroupStore;
class NotificationStore;
class WebhookStore;
class OffloadTargetStore;
class InventoryStore;
class SoftwareInventoryStore;
class AppPerfDailyStore;
class DeviceInventoryStore;
class SoftwareLicensingStore;
class AppUsageStore;
class UpdateRegistry;
class ExecutionTracker;
class FleetTopologyStore;
class HeartbeatIngestion;
class GuaranteedStateStore;
class BlastRadiusDetector;
class DexAlertRouter;
struct UpdatePackage;
struct StoredResponse;
struct AnalyticsEvent;
enum class Severity;
} // namespace yuzu::server

namespace yuzu::server::detail {

namespace pb = ::yuzu::agent::v1;

class AgentServiceImpl : public pb::AgentService::Service {
public:
    AgentServiceImpl(AgentRegistry& registry, EventBus& bus, bool require_client_identity,
                     auth::AuthManager& auth_mgr, auth::AutoApproveEngine& auto_approve,
                     yuzu::MetricsRegistry& metrics, bool gateway_mode = false,
                     UpdateRegistry* update_registry = nullptr);

    void set_update_registry(UpdateRegistry* reg) { update_registry_ = reg; }

    /// Bounds on the agent OTA pull path (issue #913 + #911). Defaults are the
    /// SHIPPED defaults, not placeholders: the path is bounded even when an
    /// operator configures nothing and when a test constructs this service
    /// without calling the setter below.
    ///
    /// The CONCURRENCY cap is the primary defence and the rate bucket is
    /// deliberately loose. #913's attack is N parallel streams, which a
    /// per-peer semaphore stops exactly; a tight bucket would instead meter
    /// RETRIES, which is what produced the lockout pathologies recorded on
    /// #934 (7.5h) and #941 (75min). At capacity 20 / refill 1-per-minute a
    /// flapping mobile agent reconnecting five times spends five tokens and
    /// recovers them in five minutes, so neither lockout is reachable.
    struct OtaBoundConfig {
        int max_concurrent_per_peer{2};
        double rate_capacity{20.0};
        double rate_refill_per_min{1.0};
        /// Whole-transfer bound, enforced by cancelling the RPC from the
        /// watchdog thread — the only thing that unblocks a `ServerWriter::Write`
        /// stalled on a zero receive window (#911 UP-101).
        std::chrono::seconds transfer_deadline{900};
        /// Per-chunk bound. Catches the slow-drip peer, whose every Write
        /// completes but slowly, before the whole-transfer deadline would.
        std::chrono::seconds chunk_stall_deadline{30};
        /// #935: the admission key falls back to peer IP when no client
        /// certificate is presented, so the key space is attacker-influenced
        /// and MUST be capped.
        ///
        /// FLOOR, deliberately: a value below `kMinPeersTracked` is clamped up.
        /// Setting it near or below the live peer count does not merely shrink a
        /// cache — every insert then evicts, and `locate_locked` mints a FULL
        /// burst for the re-inserted key, so the rate dimension silently stops
        /// limiting anything (at 1 it is off entirely). A cap that disables the
        /// limiter it exists to protect is worse than no cap.
        std::size_t max_peers_tracked{50000};

        /// Server-wide ceiling on concurrent transfers across ALL peers. The
        /// per-peer cap bounds one identity; where the identity gate is inert the
        /// key falls back to source IP, so that bound scales with the caller's
        /// address space. This one does not.
        int max_concurrent_total{64};

        /// Percentage of `max_concurrent_total` reserved for CERTIFICATE-keyed
        /// peers. A flat shared ceiling is itself exhaustible: a handful of source
        /// addresses holding slow transfers to the transfer deadline can occupy
        /// every slot and deny the fleet — cheaper than the address-space scaling
        /// the flat cap was added to prevent. IP-keyed peers may therefore occupy
        /// at most `(100 - this)%` of the cap; enrolled peers may use all of it,
        /// so an unauthenticated flood cannot starve an enrolled fleet.
        int cert_reserve_pct{50};
    };

    /// Reconfigure the OTA bounds. SET BEFORE TRAFFIC — call it before
    /// `BuildAndStart`, which is what every current caller does.
    ///
    /// The QUOTA half is safe at any time: `PrincipalQuota::set_config`
    /// reconfigures in place under its own mutex and never replaces the object, so
    /// an in-flight `DownloadUpdate` holding a `QuotaSlot` keeps a valid owner. (An
    /// earlier revision rebuilt the quota through a `unique_ptr`, orphaning exactly
    /// that back-pointer — a use-after-free that only the absence of a mid-flight
    /// caller kept unreachable.)
    ///
    /// `ota_cfg_` ITSELF IS NOT. It is a plain struct with no synchronisation, and
    /// the handler reads `chunk_stall_deadline` once per chunk and
    /// `transfer_deadline` once per transfer. A concurrent write is a data race, so
    /// an earlier version of this comment ("safe to call at any time") was an
    /// invitation to write one. Making it safe means an atomic snapshot or a
    /// seqlock, which is unwarranted while no runtime caller exists — but a future
    /// caller must add it rather than trust this comment.
    void set_ota_bound_config(const OtaBoundConfig& cfg);

    /// #416: require a POSITIVE peer identity on the two agent-initiated OTA
    /// RPCs, and bind the client-supplied `agent_id` to the certificate.
    ///
    /// Gated on the LISTENER being strict (`tls_enabled && !using_default_agent_certs`),
    /// NOT on `require_client_identity_`. The two differ exactly where it matters:
    /// on default agent certs the listener deliberately relaxes to
    /// request-but-do-not-require so an unenrolled agent can bootstrap
    /// (see server.cpp's agent-listener credential block), while
    /// `require_client_identity_` is `tls_enabled && !tls_ca_cert.empty()` and is
    /// TRUE there. Gating on the latter would reject every bootstrapping agent's
    /// OTA pull. Default false = inert, which is also what a plain-TLS or
    /// no-TLS deployment gets.
    void set_require_positive_ota_identity(bool v) { require_positive_ota_identity_ = v; }
    /// #1128: operator-declared multi-egress NAT/proxy CIDRs for the NAT-aware
    /// Subscribe binding relaxation. Empty (default) keeps strict exact-match.
    void set_trusted_nat_cidrs(std::vector<std::string> cidrs) {
        trusted_nat_cidrs_ = std::move(cidrs);
    }
    /// #1128 / gov UP-2: opt-in to the mTLS-identity NAT accommodation. Default
    /// false; only safe with per-agent client certs (see Config doc).
    void set_nat_trust_mtls_identity(bool enabled) { nat_trust_mtls_identity_ = enabled; }
    void set_response_store(ResponseStore* store) { response_store_ = store; }
    void set_tag_store(TagStore* store) { tag_store_ = store; }
    void set_analytics_store(std::weak_ptr<AnalyticsEventStore> store) {
        analytics_store_ = std::move(store);
    }
    /// W1.4 / #827: AuditStore wired for enrollment-token consume rows.
    /// SOC 2 CC7.2/CC7.3 require attributable credential-rejection logs;
    /// the Register handler emits one audit row per successful consume AND
    /// one per lost-race rejection (with `already_consumed_by=<agent_id>`
    /// detail naming the race winner). nullptr disables emission — used
    /// by the existing test harness that doesn't construct an AuditStore.
    /// W1.1 audit_log → bool: the handler observes the return so a
    /// dropped audit row surfaces as a counter increment plus an
    /// analytics-event severity escalation, never a silent loss.
    void set_audit_store(AuditStore* store) { audit_store_ = store; }
    void set_health_store(AgentHealthStore* store) { health_store_ = store; }
    void set_mgmt_group_store(ManagementGroupStore* store) { mgmt_group_store_ = store; }
    void set_notification_store(NotificationStore* store) { notification_store_ = store; }
    void set_webhook_store(WebhookStore* store) { webhook_store_ = store; }
    void set_offload_target_store(OffloadTargetStore* store) { offload_target_store_ = store; }
    /// Typed software-inventory projection (ADR-0016) — receives the
    /// installed_software daily-sync source via ReportInventory.
    void set_software_inventory_store(SoftwareInventoryStore* store) {
        software_inventory_store_ = store;
    }
    /// Typed per-device app-perf daily projection (DEX app-perf-over-time B1) —
    /// receives the app_perf daily-sync source via ReportInventory.
    void set_app_perf_daily_store(AppPerfDailyStore* store) { app_perf_daily_store_ = store; }
    /// Typed device-CI projection (ADR-0016) — receives the device_ci daily-sync
    /// source via ReportInventory.
    void set_device_inventory_store(DeviceInventoryStore* store) {
        device_inventory_store_ = store;
    }
    /// Typed detected-licence projection (ADR-0024) — receives the
    /// software_licensing daily-sync source via ReportInventory.
    void set_software_licensing_store(SoftwareLicensingStore* store) {
        software_licensing_store_ = store;
    }
    /// Typed per-agent last-used app-usage projection (Wave 7 PR7.2, ADR-0016
    /// §5) — receives the app_usage daily-sync source via ReportInventory.
    void set_app_usage_store(AppUsageStore* store) { app_usage_store_ = store; }
    /// Guardian (Guaranteed State) store — receives drift/remediation events
    /// ingested from the agent `__guard__` side-channel on the Subscribe stream
    /// (contract G2/step 5). nullptr disables ingest — used by tests that don't
    /// build a Guardian store.
    void set_guaranteed_state_store(GuaranteedStateStore* store) {
        guaranteed_state_store_ = store;
    }
    /// Fleet-wide DEX incident detector (blast radius, coverage-map D3) — the
    /// shared Guardian ingest feeds it each ruleless observation. nullptr
    /// disables detection. Set-before-traffic, like the store setters above.
    void set_blast_radius_detector(BlastRadiusDetector* detector) {
        blast_radius_detector_ = detector;
    }
    /// Operator-routed per-signal alerting (coverage-map F1) — fed alongside
    /// the blast-radius detector at the same ingest chokepoint. nullptr
    /// disables routing. Set-before-traffic.
    void set_dex_alert_router(DexAlertRouter* router) { dex_alert_router_ = router; }

    /// UAT 2026-05-12: after a fresh agent registers, the next
    /// `/api/v1/viz/fleet/topology` call must not return a snapshot
    /// computed before this agent was on the dispatch list. Without
    /// this hook the cube renders as `stale, ts=0, procs=[]` for the
    /// remainder of the 60 s TTL window, which UAT flagged as a
    /// "this should not happen" state. nullptr disables the wiring —
    /// used by tests that don't build a topology store.
    ///
    /// Plain raw pointer (not atomic): registration runs on the gRPC
    /// dispatcher; setter runs once during server bring-up before the
    /// dispatcher accepts traffic.
    void set_fleet_topology_store(FleetTopologyStore* store) { fleet_topology_store_ = store; }

    /// #1000 / arch-S2: HeartbeatIngestion encapsulates the shared
    /// per-heartbeat work (health upsert, metrics, fleet_snapshot push)
    /// so both this service and GatewayUpstreamServiceImpl funnel
    /// through one entry point. Set after bring-up alongside the stores.
    void set_heartbeat_ingestion(HeartbeatIngestion* hi) { heartbeat_ingestion_ = hi; }

    /// UAT 2026-05-06 #8: when set, response-receipt paths (Subscribe +
    /// process_gateway_response) call `update_agent_status` so the
    /// executions detail drawer's per-agent KPI table populates as
    /// responses arrive, and the SSE `agent-transition` event fires
    /// (which the drawer client listens to for live updates without
    /// page reload). nullptr disables the wiring — used by tests that
    /// don't exercise the executions ladder.
    ///
    /// Stored atomically because `process_gateway_response` is invoked
    /// from detached `std::thread` workers spawned by `forward_gateway
    /// _pending` in server.cpp; those threads outlive the gRPC server's
    /// Shutdown drain (gateway-forward is a *client* of the gateway,
    /// not a server-side handler). Setting nullptr at shutdown lets
    /// in-flight forwarders observe the null and short-circuit
    /// `notify_exec_tracker` instead of dereferencing a destroyed
    /// `ExecutionTracker` (governance UAT 2026-05-06 Gate 7 re-review).
    void set_execution_tracker(ExecutionTracker* tracker) {
        execution_tracker_.store(tracker, std::memory_order_release);
    }

    /// PR3: per-agent mTLS issuance + enforcement. The signer (wired by ServerImpl
    /// after the default-cert bootstrap, when a CA issuing key is available) signs a
    /// client leaf bound to agent_id from the agent's CSR, returning
    /// {leaf_pem, ca_chain_pem}; nullopt = signing unavailable/failed. The revocation
    /// checker returns true iff a presented peer leaf PEM is revoked (checked against
    /// ca_store). set_require_client_identity recomputes the mTLS-identity-required
    /// posture AFTER bootstrap — require_client_identity_ is otherwise baked at ctor,
    /// before the default CA exists. All set once during bring-up, before the gRPC
    /// dispatcher accepts traffic.
    /// `src` records whether issuance entered via the direct Register path or the
    /// gateway proxy, threaded into the ca.cert.issued audit (#1290).
    using AgentCertSigner = std::function<std::optional<std::pair<std::string, std::string>>(
        const std::string& csr_pem, const std::string& agent_id, CertIssuanceSource src)>;
    void set_agent_cert_signer(AgentCertSigner signer) { agent_cert_signer_ = std::move(signer); }
    void set_revocation_checker(std::function<bool(const std::string& peer_cert_pem)> checker) {
        revocation_checker_ = std::move(checker);
    }
    /// Recognizer returning true iff a presented client leaf was issued by our
    /// internal CA (signature-verified). When set, the Register re-auth gate
    /// enforces identity/revocation ONLY for Yuzu-issued certs — a foreign cert in
    /// a multi-CA trust bundle falls through to bootstrap rather than being trusted
    /// as an agent identity (Hermes CRITICAL-1). Null = single-trust-root
    /// deployment: every authenticated cert is treated as an agent (legacy).
    void set_peer_cert_recognizer(std::function<bool(const std::string& peer_cert_pem)> r) {
        peer_cert_recognizer_ = std::move(r);
    }
    void set_require_client_identity(bool v) { require_client_identity_ = v; }

    grpc::Status Register(grpc::ServerContext* context, const pb::RegisterRequest* request,
                          pb::RegisterResponse* response) override;

    grpc::Status Heartbeat(grpc::ServerContext* context, const pb::HeartbeatRequest* request,
                           pb::HeartbeatResponse* response) override;

    grpc::Status
    Subscribe(grpc::ServerContext* context,
              grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) override;

    // Record send time for latency measurement.
    void record_send_time(const std::string& command_id);

    /// #2557: drops the send-time record for a fan-out that reached nobody
    /// (`sent == 0`) or a dispatch that never completed (an exception unwound
    /// before any agent response arrived). Without this, `record_send_time`'s
    /// entry survives until SOME LATER agent response happens to carry the
    /// same `command_id` (which, for a dispatch that reached nobody, never
    /// happens) — a slow, unbounded leak of `cmd_send_times_` entries on every
    /// refused/zero-reach `/api/command` dispatch. Safe to call from a
    /// destructor/RAII guard: it does not throw except on a mutex-lock
    /// failure (`std::system_error`, `std::lock_guard`'s constructor), which
    /// every caller's own `catch` already absorbs. Deliberately NOT marked
    /// `noexcept` (governance round 1, CPPX-2) — a `noexcept` violation
    /// calls `std::terminate()` before any caller's `catch` runs, which
    /// would be strictly worse than letting that vanishingly rare failure
    /// propagate to a guard that already handles it.
    /// @return true if an entry was actually removed.
    bool discard_send_time(const std::string& command_id);

    /// Register the executions-tracker row id that this command_id belongs
    /// to (PR 2). Called by the dispatch path after `create_execution`
    /// returns the new id. The mapping is consumed by the response-receipt
    /// handlers and stamped onto every StoredResponse so the executions
    /// detail drawer can correlate exactly via `query_by_execution`. Empty
    /// `execution_id` removes any existing mapping for this command_id.
    void record_execution_id(const std::string& command_id, const std::string& execution_id);

    // Process a CommandResponse forwarded from the gateway.
    void process_gateway_response(const std::string& agent_id, const pb::CommandResponse& resp);

    // -- Server-rendered SSE row helpers ----------------------------------------
    // Parsing utilities (columns_for_plugin, split_fields, etc.) are in
    // result_parsing.hpp.  Only rendering helpers that depend on AgentServiceImpl
    // state remain here.

    static std::string thead_for_plugin(const std::string& plugin);
    static std::string render_row(const std::string& agent_name, const std::string& plugin,
                                  const std::string& line,
                                  const std::vector<std::string>& col_names);

    /// #826: extract the bare IP from a gRPC peer string. gRPC encodes
    /// peer as `ipv4:1.2.3.4:5678` (and `ipv6:[::1]:5678`, `unix:/tmp/s`,
    /// etc.). Subscribe's peer-mismatch check operates on IPs because the
    /// port differs across the Register and Subscribe RPCs from the same
    /// agent — the meaningful security check is "same network endpoint",
    /// not "same TCP four-tuple". Returns an empty string for unparseable
    /// inputs; the caller MUST treat empty as a mismatch (never as a wild
    /// match) to avoid recreating the #826 skip.
    ///
    /// Public for unit testability — exercised in test_agent_service_impl.cpp.
    static std::string extract_peer_ip(std::string_view peer);

    /// #1128 — NAT-aware per-session peer-binding decision (pure). `exact_ok` is
    /// the strict result (Subscribe IP == Register IP, or a trusted-gateway IP
    /// under gateway-mode). When that fails, a mismatch is DOWNGRADED to advisory
    /// iff a stronger accommodation applies: a matching mTLS client identity
    /// (`client_identity_matches`), or both IPs sharing one operator-declared
    /// trusted NAT CIDR. Anything else is reject. An empty `register_ip` or
    /// `subscribe_ip` is always reject (#826: empty is a mismatch, never a
    /// wildcard) regardless of accommodation. Pure + static for unit testability.
    enum class PeerBindingOutcome { exact_ok, advisory_mtls, advisory_nat_cidr, reject };
    static PeerBindingOutcome evaluate_peer_binding(bool exact_ok, std::string_view register_ip,
                                                    std::string_view subscribe_ip,
                                                    bool client_identity_matches,
                                                    const std::vector<std::string>& trusted_nat_cidrs);

    /// The metadata key carrying the session id on the direct Subscribe path
    /// (see Subscribe's own use below). Public — HA WS-4 4.1's
    /// GatewayUpstreamServiceImpl::ProxyRegister reuses this SAME key + reader
    /// to recognise a gateway circuit-recovery replay, so the two paths cannot
    /// silently drift onto different metadata keys.
    static constexpr std::string_view kSessionMetadataKey = "x-yuzu-session-id";

    /// Read a single gRPC client-metadata value by key, or empty if absent.
    /// Public for the same reason as `kSessionMetadataKey` above.
    static std::string client_metadata_value(const grpc::ServerContext& context,
                                             std::string_view key);

    void publish_output_rows(const std::string& agent_id, const std::string& plugin,
                             const std::string& raw_output);

    // -- OTA Update RPCs -------------------------------------------------------

    grpc::Status CheckForUpdate(grpc::ServerContext* context,
                                const pb::CheckForUpdateRequest* request,
                                pb::CheckForUpdateResponse* response) override;

    grpc::Status DownloadUpdate(grpc::ServerContext* context,
                                const pb::DownloadUpdateRequest* request,
                                grpc::ServerWriter<pb::DownloadUpdateChunk>* writer) override;

    // Direct daily-sync push (ADR-0016). Validates the session, resolves the
    // agent_id, and persists via the shared inventory ingest seam (identical to
    // the gateway ProxyInventory path).
    grpc::Status ReportInventory(grpc::ServerContext* context, const pb::InventoryReport* request,
                                 pb::InventoryAck* response) override;

private:
    AgentRegistry& registry_;
    EventBus& bus_;
    auth::AuthManager& auth_mgr_;
    auth::AutoApproveEngine& auto_approve_;
    yuzu::MetricsRegistry& metrics_;

    static constexpr auto kPendingRegistrationTtl = std::chrono::seconds(60);

    // -- PendingRegistration (must be complete before use in unordered_map) -----
    struct PendingRegistration {
        std::string agent_id;
        std::string register_peer;
        std::vector<std::string> peer_identities;
        std::chrono::steady_clock::time_point created_at;
    };

    // Pending Register calls waiting for the corresponding Subscribe.
    std::mutex pending_mu_;
    std::unordered_map<std::string, PendingRegistration> pending_by_session_id_;

    // Command timing instrumentation
    std::mutex cmd_times_mu_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> cmd_send_times_;
    std::unordered_set<std::string> cmd_first_seen_;

    /// #2557: the ONE place `cmd_send_times_` is erased. Every mutation site
    /// (a completed round-trip, `discard_send_time`) goes through this so the
    /// `yuzu_cmd_send_times_pending` gauge can never drift from the map's true
    /// size — a bare `.erase(it)` at a new call site would be exactly that
    /// drift. Caller holds `cmd_times_mu_`.
    void erase_send_time_locked(
        std::unordered_map<std::string, std::chrono::steady_clock::time_point>::iterator it);
    /// Publishes the current `cmd_send_times_.size()` to the pending-count
    /// gauge. Caller holds `cmd_times_mu_`.
    void publish_send_times_gauge_locked();
    // The former in-process `cmd_execution_ids_` map (command_id ->
    // execution_id) moved to Postgres (HA WS-1(1b), ADR-2002 section 5) —
    // see ExecutionTracker::record_command_execution /
    // ::lookup_execution_id. It was replica-local: a response landing on a
    // DIFFERENT gateway-fronted replica than the one that dispatched found
    // no mapping and silently dropped the correlation. The PG-backed
    // version is shared across replicas and carries its own clock-guarded
    // retention sweep (execution_tracker.cpp's reap_command_execution_
    // mappings), closing the unbounded-growth risk the map's doc comment
    // used to flag here (sec-M1 / perf-S1).
    std::atomic<size_t> output_row_count_{0};
    std::vector<std::string> tar_dynamic_columns_; // TAR SQL dynamic schema cache
    bool require_client_identity_{false};
    bool gateway_mode_{false};
    // #1128: operator-declared multi-egress NAT/proxy ranges (see Config). Empty
    // = strict exact-match peer binding (default). Set once at wiring time via
    // set_trusted_nat_cidrs; read-only on the Subscribe path thereafter.
    std::vector<std::string> trusted_nat_cidrs_;
    // #1128 / gov UP-2: gate for the mTLS-identity NAT accommodation. Default
    // false — identity-match relaxes the IP binding ONLY when the operator
    // affirms per-agent certs. See Config::nat_trust_mtls_identity.
    bool nat_trust_mtls_identity_{false};
    UpdateRegistry* update_registry_{nullptr};

    // ── OTA pull bounds (#913 / #911 / #416) ────────────────────────────────
    OtaBoundConfig ota_cfg_{};
    // A DIRECT member, deliberately not a unique_ptr. PrincipalQuota holds a
    // mutex so it is neither movable nor assignable, but it never needs to be
    // replaced: `set_config` reconfigures it in place. Holding it by value makes
    // the lifetime hazard structurally impossible rather than merely documented —
    // there is no pointer to reseat, so no live QuotaSlot can be orphaned.
    PrincipalQuota ota_quota_;
    OtaTransferWatchdog ota_watchdog_;
    bool require_positive_ota_identity_{false};

    /// Bounds the identity-deny AUDIT write. The write is synchronous and
    /// Postgres-backed and sits ahead of every admission bound, so an enrolled peer
    /// looping a mismatched CheckForUpdate would otherwise pin a server thread per
    /// call on the audit path. A few per second per key is far above any legitimate
    /// rate (an agent checks every 6h by default) and far below a flood. The metric
    /// counts every rejection regardless, so suppression shows as a gap between the
    /// counter and the row count, never as a missing signal.
    ///
    /// KEYED ON THE PEER AND THE REASON, NEVER ON THE CLAIM. The key is built by
    /// `ota_identity_audit_key` (ota_audit_key.hpp), which carries the full
    /// history of what went wrong here twice; the short version is that keying on
    /// the caller's `claimed_agent_id` did not bound anything, and keying on the
    /// peer alone let a foreign-CA holder squat a victim's bucket.
    ///
    /// WHAT THIS DOES AND DOES NOT BOUND. A new bucket now costs a certificate
    /// the listener accepts plus a TLS handshake, so it is no longer free to mint
    /// — but it is not impossible either, and this is deliberately not described
    /// as a value the caller cannot influence. The map itself is still unbounded:
    /// `RateLimiter::purge_stale()` has no production caller, so entries live for
    /// the process lifetime. That is tolerable only because the handshake cost
    /// dominates: nobody exhausts memory here more cheaply than they exhaust the
    /// TLS path. `kMaxAuditKeyIdentity` clamps the per-entry cost. Wiring an
    /// eviction sweep is tracked separately.
    ///
    /// Every path reaching this limiter has already presented a certificate: the
    /// certless case is `no_client_identity`, which short-circuits above. So the
    /// key's mode is "cert" in practice, and the peer_ip arm exists for the
    /// composer's completeness rather than as a reachable branch here.
    RateLimiter ota_identity_audit_limiter_{2};

    /// One in this many admission rejections is logged (the first always is).
    /// See should_log_ota_rejection for why the log is sampled but the metric is not.
    static constexpr std::uint64_t kOtaRejectionLogSample = 100;
    std::atomic<std::uint64_t> ota_rejection_log_seq_{0};

    /// Rate-samples the admission-rejection log line. Not const: it advances a
    /// counter.
    bool should_log_ota_rejection();

    /// Server-wide transfer gate (OtaBoundConfig::max_concurrent_total plus the
    /// certificate reserve). Lives in its own header because the counter is the
    /// one part of this gate a live-wire test cannot observe — see
    /// ota_total_admission.hpp.
    OtaTotalAdmission ota_total_admission_;

    /// The admission key for one OTA call, plus which keying produced it.
    ///
    /// Certificate identity when the peer presented one, else the peer IP. The
    /// fallback is load-bearing, not a convenience: the agent listener does not
    /// always require a client certificate, and keying every certless peer on a
    /// single empty string would collapse the whole unenrolled fleet onto ONE
    /// bucket, where one agent's pulls lock out every other (issue #935). Peer
    /// IP is the same keying the HTTP-side RateLimiter already uses.
    struct AdmissionKey {
        std::string key;   ///< the value the per-peer quota is bucketed on
        const char* mode;  ///< "cert" | "peer_ip" | "unknown" — the metric label
    };
    AdmissionKey ota_admission_key(const grpc::ServerContext& ctx) const;

    /// #416 — see set_require_positive_ota_identity. Returns OK when the gate is
    /// off. `claimed_agent_id` is the request-body value, which is unverified
    /// until this binds it to the certificate.
    grpc::Status require_positive_ota_identity(grpc::ServerContext* context, std::string_view rpc,
                                               const std::string& claimed_agent_id);
    ResponseStore* response_store_{nullptr};
    TagStore* tag_store_{nullptr};
    std::weak_ptr<AnalyticsEventStore> analytics_store_;
    AuditStore* audit_store_{nullptr};
    AgentHealthStore* health_store_{nullptr};
    ManagementGroupStore* mgmt_group_store_{nullptr};
    NotificationStore* notification_store_{nullptr};
    WebhookStore* webhook_store_{nullptr};
    OffloadTargetStore* offload_target_store_{nullptr};
    SoftwareInventoryStore* software_inventory_store_{nullptr};
    AppPerfDailyStore* app_perf_daily_store_{nullptr};
    DeviceInventoryStore* device_inventory_store_{nullptr};
    SoftwareLicensingStore* software_licensing_store_{nullptr};
    AppUsageStore* app_usage_store_{nullptr};
    GuaranteedStateStore* guaranteed_state_store_{nullptr};
    BlastRadiusDetector* blast_radius_detector_{nullptr};
    DexAlertRouter* dex_alert_router_{nullptr};
    FleetTopologyStore* fleet_topology_store_{nullptr};
    HeartbeatIngestion* heartbeat_ingestion_{nullptr};
    /// Atomic — see `set_execution_tracker` doc for why detached
    /// gateway-forward threads require the lock-free release/acquire
    /// pair instead of a plain raw pointer.
    std::atomic<ExecutionTracker*> execution_tracker_{nullptr};

    // PR3 per-agent mTLS (set post-bootstrap; empty = disabled / legacy path).
    AgentCertSigner agent_cert_signer_;
    std::function<bool(const std::string&)> revocation_checker_;
    std::function<bool(const std::string&)> peer_cert_recognizer_;

    static std::vector<std::string> extract_peer_identities(const grpc::ServerContext& context);
    /// PR3: the presented client leaf PEM from the gRPC auth context (the
    /// x509_pem_cert property), or empty if no client cert was presented.
    static std::string extract_peer_cert_pem(const grpc::ServerContext& context);
    static bool peer_identity_matches_agent_id(const grpc::ServerContext& context,
                                               const std::string& agent_id);
    static bool has_identity_overlap(const std::vector<std::string>& lhs,
                                     const std::vector<std::string>& rhs);

    void prune_expired_pending_locked();
    static std::string extract_plugin(const std::string& command_id);

    /// PR3: if a Yuzu-issued client leaf is presented and revoked, return a
    /// non-OK status to send back; otherwise grpc::Status::OK. Lets the
    /// agent-initiated RPCs (Heartbeat, DownloadUpdate) lock out a revoked agent
    /// from liveness + OTA, not just the command channel — `Subscribe` keeps its
    /// own richer audited gate. No-op when no checker is wired or no/foreign cert
    /// is presented (the checker is issuer-scoped). `rpc` labels the metric/log.
    grpc::Status reject_revoked_peer(grpc::ServerContext* context, std::string_view rpc);

    /// UAT 2026-05-06 #8: notify the executions tracker of a per-agent
    /// state change for the given command_id. Resolves command_id →
    /// execution_id via `ExecutionTracker::lookup_execution_id` (HA
    /// WS-1(1b): PG-backed, shared across replicas — no longer an
    /// in-process map) and calls `ExecutionTracker::update_agent_status`
    /// with a synthesised
    /// `AgentExecStatus` (status, exit_code, error_detail, timestamps).
    /// Each call publishes an `agent-transition` SSE event the drawer's
    /// client listens to for live-updates without a page reload.
    ///
    /// No-op on the executions-drawer/SSE side if the tracker isn't wired
    /// or `lookup_execution_id` finds no mapping — ordinary out-of-band
    /// dispatch, a workflow-step dispatch (CONSIST-2/sec-M2, which never
    /// records one), a genuine degrade on the correlation table's own
    /// write/read side, or the correlation table's own bounded (24h)
    /// retention aging a mapping out from under a still-legitimately-
    /// running command (ADR-1007, originally UP-1, unhappy-path Gate 4
    /// finding, PR #3784 fix round — reconciled onto HA WS-1(1b) above,
    /// which closed this fallback's ORIGINAL restart-survival case by
    /// persisting the correlation itself). Those remaining cases are NOT a
    /// full no-op, though: per-device concurrency-claim release/renewal is
    /// routed around the unresolved correlation via
    /// `ExecutionTracker::release_concurrency_claim_by_command`/
    /// `renew_concurrency_claim_by_command`, keyed on `command_id` alone
    /// (rides the wire response independent of the correlation table). See
    /// those methods' doc comments.
    void notify_exec_tracker(const std::string& command_id, const std::string& agent_id,
                             const pb::CommandResponse& resp);

    /// HA WS-1(1b), ADR-2002 section 5: the single chokepoint every
    /// command_id -> execution_id read goes through (response-stamping in
    /// process_gateway_response's four branches, plus notify_exec_tracker) —
    /// resolves via `ExecutionTracker::lookup_execution_id`, or nullopt if
    /// the tracker isn't wired / the read degrades / there is no mapping. A
    /// second hand-rolled load-and-lookup at a new call site is the drift
    /// this helper exists to prevent (mirrors this codebase's other single-
    /// chokepoint conventions, e.g. `dispatch_confined_arms`).
    std::optional<std::string> resolve_execution_id(const std::string& command_id) const;
};

} // namespace yuzu::server::detail
