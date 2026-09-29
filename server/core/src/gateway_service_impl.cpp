#include "gateway_service_impl.hpp"

#include <chrono>

#include <nlohmann/json.hpp>

#include "agent_service_impl.hpp"
#include "analytics_event_store.hpp"
#include "audit_store.hpp"
#include "enrollment_token_rejection.hpp"
#include "fleet_topology_store.hpp"
#include "gateway_mgmt_stub_pool.hpp" // kUnknownGatewayClusterLabel
#include "grpc_audit_signal.hpp"
#include "grpc_on_behalf_enforce.hpp"
#include "guaranteed_state_store.hpp"
#include "app_perf_daily_store.hpp"
#include "app_perf_ingestion.hpp"
#include "device_ci_ingestion.hpp"
#include "typed_inventory_sources.hpp"
#include "guardian_ingest.hpp"
#include "heartbeat_ingestion.hpp"
#include "offline_endpoint_store.hpp" // HA WS-5: remove_if_session on disconnect
#include "inventory_ingestion.hpp"
#include "inventory_store.hpp"
#include "management_group_store.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "on_behalf_guard.hpp" // onbehalf::sanitize_for_log
#include "software_inventory_store.hpp"
#include "software_licensing_ingestion.hpp"
#include "software_licensing_store.hpp"
#include "app_usage_ingestion.hpp"
#include "app_usage_store.hpp"
#include "peer_ip.hpp"

namespace yuzu::server::detail {

namespace {

// HA WS-4 slice 4.1: lease TTL for GatewayRouteStore rows. The gateway's own
// heartbeat-forwarding cadence batches on a ~1s flush interval
// (gateway/config/sys.config's heartbeat_batch_interval_ms), but the
// underlying signal this lease must survive is the AGENT's own heartbeat
// interval — default 30s (agents/core/include/yuzu/agent/agent.hpp,
// Config::heartbeat_interval) — since BatchHeartbeat's renew_leases call
// below only fires once per agent heartbeat. 3x that (90s) tolerates a
// couple of missed heartbeats without the route reading stale; INERT this
// slice (nothing reads is_stale yet) but the margin is chosen now so a
// future reader doesn't inherit an accidentally-tight TTL.
constexpr int kGatewayRouteLeaseTtlSecs = 90;

// PR #4299 review (MINOR): pin this against GatewayRouteStore's own
// duplicate of the same value (gateway_route_store.hpp::kKnownLeaseTtlSecs;
// see that header's doc comment and gateway_route_store.cpp's
// reap_stale_routes() constants comment for why the value is duplicated
// rather than shared via a cross-store include). The reap grace window
// (kStaleLeaseGraceSecs = 2x kKnownLeaseTtlSecs) is only a safe margin over
// THIS constant if the two never drift — following the kNetTag*
// static_assert precedent (test_network_perf_model.cpp) of pinning two
// deliberately-duplicated constants at the one point they are BOTH visible,
// so a future bump to one alone is a build failure, not a silent margin
// erosion.
static_assert(kGatewayRouteLeaseTtlSecs == yuzu::server::kKnownLeaseTtlSecs,
             "gateway_service_impl.cpp's kGatewayRouteLeaseTtlSecs and "
             "gateway_route_store.hpp's kKnownLeaseTtlSecs are a deliberately "
             "duplicated pair (see both files' comments) — they must be bumped "
             "together or the reap grace window (>= 1x this TTL) silently erodes");

// HA WS-4 #4324: `StreamStatusNotification.stream_home_id` is gateway-
// asserted, untrusted input like every other field on this message. The
// gateway mints it as `string:lowercase(binary:encode_hex(crypto:
// strong_rand_bytes(16)))` — 32 hex chars (yuzu_gw_agent.erl) — so 64 bytes
// gives headroom for a future longer id without leaving the value unbounded.
// An oversized incoming value is treated as MALFORMED and clamped to empty
// (legacy/no-fence for that call) rather than rejecting the whole RPC or
// comparing/storing the oversized value — see the CONNECTED/DISCONNECTED
// branches below.
constexpr std::size_t kMaxStreamHomeIdLen = 64;

// HA WS-4 4.3: kMaxClusterIdLen is declared in gateway_service_impl.hpp, not
// here — see that declaration's comment for why (main.cpp's CLI parser needs
// it too).

// HA WS-4 slice 4.1 / 4.2b Task B: shared log+metric helper for a degraded
// GatewayRouteStore write (gateway_route_store.hpp). This function ONLY logs
// and counts — it never decides proceed-vs-refuse. What each CALLER does next
// is PER-SITE, not uniform (Task B's per-site fail-closed contract): as of
// 4.2b Task C the directory IS read for dispatch (fallback-only, on a local
// registry miss), so the reader's trust predicate — not the write posture —
// is the integrity backstop for most sites. Only a write whose LOSS is
// otherwise unrecoverable, OR a READ whose wrong answer is more dangerous
// than a refusal, is worth refusing the RPC over:
//   - register_fresh (the ProxyRegister fresh-registration branch) — it
//     CREATES the row, and a missed create persists until reconnect with no
//     other write on the path able to fill in a first row, so its caller
//     returns UNAVAILABLE right after this call (mirrors the existing #3401
//     register_agent-failure precedent).
//   - HA WS-4 4.4 round-2 review fix (UP-4/COMP-6): the replay-ADOPT
//     decision's OWN renew_leases and reclaim_tombstoned_session calls (in
//     ProxyRegister's presented-session branch, BEFORE register_agent runs)
//     are ALSO fail-CLOSED — a degraded read here can't tell "still valid,
//     adopt" from "superseded, refuse" any better than we can, and a wrong
//     ADOPT installs a placement that may belong to a genuine zombie
//     session, unconditionally overwriting a healthy replica's correct one.
//     This is a stronger failure mode than register_fresh's own (a missed
//     CREATE is merely absent; a wrong ADOPT actively clobbers), so it gets
//     the same fail-closed treatment.
//   - Every OTHER site stays fail-OPEN on a DEGRADED READ (store_unavailable/
//     db_error — this function's two `reason`s) and proceeds — see each call
//     site's own comment for why that site specifically tolerates it:
//     announce_connected (the CONNECTED notify is a droppable gen_server:cast
//     on the gateway side; a Postgres blip must not refuse every gateway
//     CONNECTED fleet-wide), BatchHeartbeat's OWN renew_leases call (a renew
//     failure only yields premature lease-staleness, which the reader's
//     `routable` predicate already treats as not-routable — a fundamentally
//     different risk than the decision-phase renew above, which decides
//     ADOPT vs REFUSE rather than merely extending an already-adopted
//     lease), and deregister (bounded by the 90s lease TTL regardless).
//   - #4669 CARVE-OUT (narrower than the above, NOT a degraded-read case): a
//     NEW, SEPARATE READ-ONLY pre-check (`has_cluster_affinity_conflict`)
//     runs BEFORE registry_.set_gateway_route in NotifyStreamStatus's
//     CONNECTED handling — see that call site's own comment for why it is a
//     distinct call rather than a reorder of announce_connected's own write.
//     When that pre-check SUCCEEDS with a definitive conflict, that IS
//     fail-closed — the whole CONNECTED is refused, nothing is published to
//     the in-memory registry either. This is not a "can't tell" degraded
//     answer (a DEGRADED pre-check read stays fail-OPEN, still routed
//     through THIS function with op="announce_connected" — see that call
//     site); it is an affirmative "no" from the durable store, and an
//     affirmative "no" is always honored, never downgraded to fail-open.
//     announce_connected's OWN later write (unchanged position/posture) also
//     independently re-checks the same affinity atomically — see
//     `AnnounceResult::cluster_affinity_violation` and its call site's
//     comment for the narrow race the pre-check alone cannot close.
void record_route_store_failure(yuzu::MetricsRegistry* metrics, std::string_view op,
                                GatewayRouteStoreError err) {
    const char* reason =
        err == GatewayRouteStoreError::store_unavailable ? "store_unavailable" : "db_error";
    spdlog::warn("[gateway] GatewayRouteStore {} degraded ({}) — see call site for fail-open vs "
                 "fail-closed handling",
                 op, reason);
    if (metrics) {
        metrics
            ->counter("yuzu_server_gateway_route_write_failed_total",
                      {{"op", std::string(op)}, {"reason", reason}})
            .increment();
    }
}

// WS-4 4.2a #8 — guard-no-op / directory-desync visibility. A guard (the
// session-scoped WHERE clauses in announce_connected/deregister/renew_leases,
// and NotifyStreamStatus's own gateway_sessions_ lookup) rejecting a write is
// NOT a store failure — the call succeeded, the store correctly refused to
// touch a row it doesn't own. That refusal is exactly the "systemic desync"
// signal an operator needs visibility into (in-memory gateway_sessions_ vs.
// the durable directory row disagreeing about which session currently owns
// an agent's route), separate from record_route_store_failure's degraded-I/O
// signal above. `count` lets a batched caller (renew_leases' shortfall)
// report magnitude in one increment instead of one call per missing row.
//
// Deliberately EXCLUDED from this counter: a `register_fresh` epoch-race
// loss (RegisterFreshResult::won == false). That is an expected, benign
// outcome of concurrent connects for the SAME agent — see the ProxyRegister
// `lost_race_sessions_` bookkeeping below, which skips the FOLLOW-UP
// announce_connected call entirely for a losing session so it never reaches
// this counter as a false "session_mismatch" desync.
void record_directory_desync(yuzu::MetricsRegistry* metrics, std::string_view op,
                             std::string_view outcome, double count = 1.0) {
    spdlog::warn("[gateway] GatewayRouteStore {} guard rejected the write (outcome={}, count={}) "
                 "— directory may be out of sync with the in-memory session map",
                 op, outcome, count);
    if (metrics) {
        metrics
            ->counter("yuzu_server_gateway_route_desync_total",
                      {{"op", std::string(op)}, {"outcome", std::string(outcome)}})
            .increment(count);
    }
}

} // namespace

// -- Constructor --------------------------------------------------------------

GatewayUpstreamServiceImpl::GatewayUpstreamServiceImpl(AgentRegistry& registry, EventBus& bus,
                                                       auth::AuthManager& auth_mgr,
                                                       auth::AutoApproveEngine& auto_approve,
                                                       yuzu::MetricsRegistry* metrics,
                                                       AgentHealthStore* health_store)
    : registry_(registry), bus_(bus), auth_mgr_(auth_mgr), auto_approve_(auto_approve),
      metrics_(metrics), health_store_(health_store) {
    if (metrics_) {
        metrics_->describe(
            "yuzu_server_gateway_route_write_failed_total",
            "HA WS-4: GatewayRouteStore directory writes/reads (register_fresh/"
            "announce_connected/deregister/renew_leases/reclaim_tombstoned_session) "
            "that degraded instead of succeeding, by op and reason. PER-SITE posture "
            "(4.2b, extended 4.4 round-2 review UP-4/COMP-6): register_fresh, and the "
            "replay-ADOPT decision's own renew_leases/reclaim_tombstoned_session calls, "
            "are fail-CLOSED (the ProxyRegister RPC returns UNAVAILABLE); every other "
            "writer (announce_connected, BatchHeartbeat's own renew_leases, deregister) "
            "stays fail-OPEN (the RPC proceeds, integrity living at the fallback-only "
            "dispatch reader's trust predicate) - so for the fail-open writers this "
            "counter is the only signal a systemic write failure would otherwise leave "
            "invisible. #4669: op=\"cluster_affinity_check\" is a SEPARATE READ (the "
            "pre-check ahead of set_gateway_route) - also fail-OPEN on a degraded read, "
            "deliberately counted under its OWN op label rather than folded into "
            "\"announce_connected\", which stays the write's own count.",
            "counter");
        // Post-merge review #4344 follow-up (MEDIUM finding 2, docs/observability-conventions.md):
        // pre-seed every (op,reason) combo this counter can ACTUALLY emit (record_route_store_failure
        // is called for all four ops above with only these two GatewayRouteStoreError reasons —
        // gateway_route_store.hpp). Lazy-created-on-first-increment means a single isolated
        // incident never crosses `rate()>0`/`increase()>0` — the first sample IS the incident, and
        // there is no second sample within the window to diff against — so the very alert meant to
        // catch a lone failure stays silent on it. Mirrors the desync counter's own pre-seed block
        // immediately below.
        for (const char* op :
            {"register_fresh", "announce_connected", "deregister", "renew_leases",
             "reclaim_tombstoned_session",
             // #4669: the read-only pre-check ahead of set_gateway_route —
             // see that call site's comment for why it is a distinct op from
             // "announce_connected".
             "cluster_affinity_check"}) {
            for (const char* reason : {"store_unavailable", "db_error"}) {
                metrics_->counter("yuzu_server_gateway_route_write_failed_total",
                                  {{"op", op}, {"reason", reason}});
            }
        }
        metrics_->describe(
            "yuzu_server_gateway_route_desync_total",
            "HA WS-4 4.2a: GatewayRouteStore session-guard writes (announce_connected/"
            "deregister/renew_leases) that succeeded but matched/renewed zero rows for the "
            "presented session, plus NotifyStreamStatus's own unknown-session reject, by op "
            "and outcome. A guard rejection is EXPECTED at a low background rate (stale/"
            "superseded-session notifications the guards exist to no-op on) - a sustained rise "
            "is the signal that the in-memory session map and the durable directory have gone "
            "out of sync. A register_fresh epoch-race LOSS is deliberately excluded (see the "
            "lost_race_sessions_ bookkeeping) so a benign concurrent-connect race never inflates "
            "this counter. Two benign contributors not to page on: a post-restart/failover "
            "baseline rise (a replica that lost its in-memory session map until agents "
            "re-announce), and a redelivered/duplicate DISCONNECTED notification. #4669: "
            "outcome=\"cluster_affinity_violation\" (op=\"announce_connected\") is the ONE "
            "exception to \"benign, don't page\" above - a session-matched CONNECTED claiming a "
            "DIFFERENT cluster_id than the agent's durably-bound home affinity, refused "
            "fail-closed. ANY non-zero rate is worth investigating (a misconfigured/renamed "
            "gateway cluster_id, or a genuine rogue-gateway claim attempt), not a background rate "
            "to tolerate like the others.",
            "counter");
        // PR #4299 review (SHOULD 1, observability-conventions.md:12): seed
        // only the (op,outcome) pairs this file ACTUALLY emits (see the
        // record_directory_desync call sites below) — never the full
        // op x outcome cross-product, most of which no code path can
        // produce. Without this, a healthy server that never once hits a
        // guard rejection reads identically to one where the desync signal
        // itself is broken.
        metrics_->counter("yuzu_server_gateway_route_desync_total",
                          {{"op", "renew_leases"}, {"outcome", "shortfall"}});
        // Task B (4.2b, #4246 #10): BatchHeartbeat's renew now excludes a
        // session this replica's gateway_sessions_ doesn't recognize (no
        // agent_id to correlate against) rather than silently dropping it —
        // see that call site's comment.
        metrics_->counter("yuzu_server_gateway_route_desync_total",
                          {{"op", "renew_leases"}, {"outcome", "unknown_session"}});
        metrics_->counter("yuzu_server_gateway_route_desync_total",
                          {{"op", "announce_connected"}, {"outcome", "session_mismatch"}});
        metrics_->counter("yuzu_server_gateway_route_desync_total",
                          {{"op", "deregister"}, {"outcome", "session_mismatch"}});
        // HA WS-4 #4324: the per-home stream-generation fence's two new
        // outcomes — a genuine stale-home mismatch (the case this fence
        // exists to catch) and a malformed (oversized) incoming
        // stream_home_id on either notification kind.
        metrics_->counter("yuzu_server_gateway_route_desync_total",
                          {{"op", "deregister"}, {"outcome", "stale_home"}});
        metrics_->counter("yuzu_server_gateway_route_desync_total",
                          {{"op", "announce_connected"}, {"outcome", "malformed_home_id"}});
        metrics_->counter("yuzu_server_gateway_route_desync_total",
                          {{"op", "deregister"}, {"outcome", "malformed_home_id"}});
        // HA WS-4 4.3: cluster_id ingest clamp, same shape as stream_home_id
        // above.
        metrics_->counter("yuzu_server_gateway_route_desync_total",
                          {{"op", "announce_connected"}, {"outcome", "malformed_cluster_id"}});
        // #4669: a session-matched CONNECTED claiming a DIFFERENT cluster_id
        // than the agent's durably-bound home affinity — refused outright
        // (fail-closed), distinct from an ordinary session_mismatch desync.
        // See gateway_route_store.hpp's "AGENT<->CLUSTER AFFINITY" note.
        metrics_->counter("yuzu_server_gateway_route_desync_total",
                          {{"op", "announce_connected"}, {"outcome", "cluster_affinity_violation"}});
        metrics_->counter("yuzu_server_gateway_route_desync_total",
                          {{"op", "notify_stream_status"}, {"outcome", "unknown_session"}});
        // HA WS-4 4.4 post-build adversarial review (PR #4636 FortitudeEtc,
        // BLOCKER 2): a CONNECTED whose session_id is a live entry in
        // gateway_sessions_ (passes the check above) but is no longer the
        // CURRENTLY-installed session for this agent in the in-memory
        // registry — a delayed/superseded reannounce arriving after a
        // genuine newer registration has already installed. Rejected by
        // AgentRegistry::set_gateway_route's own session check rather than
        // clobbering the newer session's placement.
        metrics_->counter("yuzu_server_gateway_route_desync_total",
                          {{"op", "notify_stream_status"}, {"outcome", "stale_connected_session"}});
        // HA WS-4 4.4 (`#4246` #6): a replay's presented session belonged to
        // a DIFFERENT, LIVE session by the time reclaim_tombstoned_session
        // ran — a genuine stale/zombie replay, refused outright (see
        // ProxyRegister's adopt/refuse decision above).
        metrics_->counter("yuzu_server_gateway_route_desync_total",
                          {{"op", "proxy_register"}, {"outcome", "session_superseded"}});
    }
}

std::shared_ptr<std::mutex>
GatewayUpstreamServiceImpl::registration_lock_for(const std::string& agent_id) {
    std::lock_guard lock(registration_locks_mu_);
    auto& slot = registration_locks_[agent_id];
    if (!slot) slot = std::make_shared<std::mutex>();
    return slot;
}

// -- ProxyRegister ------------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::ProxyRegister(grpc::ServerContext* context,
                                                       const pb::RegisterRequest* request,
                                                       pb::RegisterResponse* response) {
    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp. Must run
    // before any side effect below (audit, auth-mgr lookup, registry write).
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    const auto& info = request->info();

    // #1064: on this path the transport peer is the GATEWAY's IP, not the
    // agent's — so an audit row keyed on `context->peer()` mis-attributes the
    // source (SOC 2 IR-2; SIEM "race-loss IP must equal winner IP" false
    // negatives). Prefer the gateway-observed agent origin IP carried in the
    // RegisterRequest (a bare IP the gateway fills; empty under transports that
    // can't observe the agent peer — see the proto field comment), validated
    // through the same strict parser as direct peers. Fall back to the gateway
    // IP when absent, recording origin_observed=false so an auditor knows the
    // source_ip is the relay, not the agent. Both IPs go in `detail`.
    const std::string gateway_ip = context ? extract_peer_ip(context->peer()) : std::string{};
    const std::string observed_origin =
        ::yuzu::server::detail::normalize_bare_ip(request->gateway_observed_peer());
    const std::string agent_source_ip = observed_origin.empty() ? gateway_ip : observed_origin;
    // Capture by value (gov Hermes SEC-07): defensive against a future refactor
    // that stores/returns the lambda — the captured strings then can't dangle.
    const auto append_origin_detail = [gateway_ip, observed_origin](std::string& detail) {
        detail.append(" gateway_ip=").append(gateway_ip);
        if (observed_origin.empty())
            detail.append(" origin_observed=false");
    };

    // -- W1.4 R2 / UP-H1 agent_id length bound (mirror of direct Register) ----
    // Same rationale as the direct-connect path in AgentServiceImpl::Register
    // — cap before any audit emission, auth-mgr lookup, or SHA-256. Source
    // label on the metric is `gateway_proxy` so SRE can see attacks coming
    // through the gateway vs direct-connect agents.
    if (info.agent_id().empty() || info.agent_id().size() > auth::kMaxAgentIdLength) {
        spdlog::warn(
            "[gateway] ProxyRegister rejected: agent_id length {} (max {}, empty disallowed)",
            info.agent_id().size(), auth::kMaxAgentIdLength);
        if (metrics_) {
            metrics_
                ->counter("yuzu_register_invalid_agent_id_total",
                          {{"reason", "length"}, {"source", "gateway_proxy"}})
                .increment();
        }
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "agent_id length exceeds 256 chars or empty");
    }

    // -- Tiered enrollment (same logic as AgentServiceImpl::Register) ----------
    //
    // W1.3 R2 / UP-7 / sec-G MEDIUM-1: trusted-peer noting moved to the
    // success path below (after `gw_enrolled:`). The prior implementation
    // recorded the peer BEFORE the enrollment branches with the rationale
    // that denied enrollments still contribute to gateway-trust discovery.
    // That inverts the trust model: any peer that can reach :50055 with
    // ANY ProxyRegister payload (forged enrollment token, garbage agent_id,
    // anything that fails token validation or admin denial) would become
    // trusted for the rest of the process lifetime.
    //
    // The trusted-set is now populated ONLY when the proxy enrollment
    // succeeds. The set still assumes the gateway-upstream listener (:50055)
    // is itself authenticated via TLS/mTLS at the operator's network
    // boundary — without that, an attacker who reaches the port AND knows
    // a valid enrollment token could still add themselves; the post-PR-3
    // native-QUIC redesign tightens this with mandatory peer-cert pinning.

    // Fast path: agent already enrolled from a prior connection
    {
        auto prior = auth_mgr_.get_pending_status(info.agent_id());
        if (prior && *prior == auth::PendingStatus::approved) {
            spdlog::info("[gateway] Agent {} re-registering (already enrolled)", info.agent_id());
            goto gw_enrolled;
        }
        // #1067: reject an admin-DENIED agent BEFORE consuming any enrollment
        // token — same token-depletion DoS as the direct-connect path (W1.4
        // UP-M3). The gateway proxies the agent's RegisterRequest unmodified, so
        // this path is equally reachable; mirror the direct fix here.
        if (prior && *prior == auth::PendingStatus::denied) {
            // gov #1134: bounded denied-attempt signal (mirror of the direct
            // Register path). A counter, not an audit row (DoS-safe under a
            // denied flood). event=security routes it to the SIEM. metrics_ is
            // null-guarded (optional on this service).
            if (metrics_) {
                metrics_
                    ->counter("yuzu_register_denied_total",
                              {{"source", "gateway_proxy"}, {"event", "security"}})
                    .increment();
            }
            spdlog::warn("[gateway] Register rejected: agent {} is admin-denied (no token consumed)",
                         info.agent_id());
            response->set_accepted(false);
            response->set_reject_reason("enrollment denied by administrator");
            response->set_enrollment_status("denied");
            return grpc::Status::OK;
        }
    }

    {
        const auto& enrollment_token = request->enrollment_token();

        if (!enrollment_token.empty()) {
            // -- W1.1 UP-H2 length bound (mirrored from the direct path) ------
            if (enrollment_token.size() > auth::kMaxEnrollmentTokenLength) {
                spdlog::warn(
                    "[gateway] Agent {} presented oversize enrollment token ({} chars > {})",
                    info.agent_id(), enrollment_token.size(), auth::kMaxEnrollmentTokenLength);
                if (metrics_) {
                    metrics_
                        ->counter("yuzu_enrollment_token_rejected_total",
                                  {{"variant", "invalid_input_length"}})
                        .increment();
                }
                if (auto analytics_store = analytics_store_.lock()) {
                    AnalyticsEvent ae;
                    ae.event_type = "agent.enrollment_denied";
                    ae.agent_id = info.agent_id();
                    ae.hostname = info.hostname();
                    ae.os = info.platform().os();
                    ae.arch = info.platform().arch();
                    ae.severity = Severity::kWarn;
                    ae.attributes = {{"reason", "invalid_input_length"},
                                     {"token_length", enrollment_token.size()},
                                     {"source", "gateway_proxy"}};
                    analytics_store->emit(std::move(ae));
                }
                response->set_accepted(false);
                response->set_reject_reason(
                    std::string(yuzu::server::kEnrollmentTokenRejectionPublicMessage));
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            }

            // -- W1.4 / #827 atomic consume (mirror of AgentServiceImpl) ------
            auto claim_result =
                auth_mgr_.consume_enrollment_token(enrollment_token, info.agent_id());
            if (!claim_result.has_value()) {
                auto err = claim_result.error();
                auto variant = yuzu::server::enrollment_rejection_variant_name(err);
                auto metric_name = yuzu::server::enrollment_rejection_metric_name(err);
                spdlog::warn("[gateway] Agent {} enrollment-token consume rejected: variant={}",
                             info.agent_id(), variant);
                if (metrics_) {
                    if (err == auth::EnrollmentTokenError::already_consumed) {
                        metrics_->counter(std::string(metric_name), {}).increment();
                    } else {
                        metrics_
                            ->counter(std::string(metric_name), {{"variant", std::string(variant)}})
                            .increment();
                    }
                }

                std::string already_consumed_by;
                if (err == auth::EnrollmentTokenError::already_consumed) {
                    auto hash = auth::AuthManager::sha256_hex(enrollment_token);
                    already_consumed_by = auth_mgr_.last_consumer_for_token_hash(hash);
                }

                bool audit_ok = true;
                if (audit_store_ && audit_store_->is_open()) {
                    AuditEvent ev;
                    ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();
                    ev.principal = "agent:" + info.agent_id();
                    ev.principal_role = "agent";
                    ev.action = std::string(yuzu::server::enrollment_event_action());
                    ev.target_type = "enrollment_token";
                    auto hash_for_audit = auth::AuthManager::sha256_hex(enrollment_token);
                    ev.target_id = hash_for_audit.substr(0, 8);
                    std::string detail = std::string("variant=")
                                             .append(variant)
                                             .append(" presenter=")
                                             .append(info.agent_id())
                                             .append(" source=gateway_proxy");
                    if (!already_consumed_by.empty()) {
                        detail.append(" already_consumed_by=").append(already_consumed_by);
                    }
                    append_origin_detail(detail); // #1064: gateway_ip + origin_observed
                    ev.detail = std::move(detail);
                    ev.source_ip = agent_source_ip; // #1064: agent origin, not gateway IP
                    ev.result = "failure";
                    audit_ok = audit_store_->log(ev);
                }

                // #1063: surface a dropped audit row on the wire (mirror REST
                // Sec-Audit-Failed) so the operator sees the evidence-chain gap.
                if (!audit_ok)
                    signal_grpc_audit_failed(context);

                if (auto analytics_store = analytics_store_.lock()) {
                    AnalyticsEvent ae;
                    ae.event_type = "agent.enrollment_denied";
                    ae.agent_id = info.agent_id();
                    ae.hostname = info.hostname();
                    ae.os = info.platform().os();
                    ae.arch = info.platform().arch();
                    if (err == auth::EnrollmentTokenError::already_consumed || !audit_ok) {
                        ae.severity = Severity::kError;
                    } else {
                        ae.severity = Severity::kWarn;
                    }
                    nlohmann::json attrs = {{"reason", std::string(variant)},
                                            {"audit_emitted", audit_ok},
                                            {"source", "gateway_proxy"}};
                    if (!already_consumed_by.empty()) {
                        attrs["already_consumed_by"] = already_consumed_by;
                    }
                    ae.attributes = std::move(attrs);
                    analytics_store->emit(std::move(ae));
                }

                response->set_accepted(false);
                response->set_reject_reason(
                    std::string(yuzu::server::kEnrollmentTokenRejectionPublicMessage));
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            }
            const auto& claim = claim_result.value();
            spdlog::info("[gateway] Agent {} auto-enrolled via enrollment token id={} ({}/{})",
                         info.agent_id(), claim.token_id, claim.use_count_after,
                         claim.max_uses == 0 ? -1 : claim.max_uses);

            bool enroll_audit_ok = true;
            if (audit_store_ && audit_store_->is_open()) {
                AuditEvent ev;
                ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                ev.principal = "agent:" + info.agent_id();
                ev.principal_role = "agent";
                ev.action = std::string(yuzu::server::enrollment_event_action());
                ev.target_type = "enrollment_token";
                ev.target_id = claim.token_id;
                std::string detail =
                    std::string("variant=success source=gateway_proxy use_count=")
                        .append(std::to_string(claim.use_count_after))
                        .append("/")
                        .append(claim.max_uses == 0 ? std::string{"unlimited"}
                                                    : std::to_string(claim.max_uses));
                append_origin_detail(detail); // #1064: gateway_ip + origin_observed
                ev.detail = std::move(detail);
                ev.source_ip = agent_source_ip; // #1064: agent origin, not gateway IP
                ev.result = "success";
                enroll_audit_ok = audit_store_->log(ev);
            }
            // #1065 / #1063: a dropped SUCCESS audit row is the same
            // evidence-chain degradation as a dropped failure row — was
            // fire-and-forget. Surface on the wire and escalate analytics,
            // mirroring the denial path's audit_ok handling. SOC 2 CC7.2.
            if (!enroll_audit_ok) {
                signal_grpc_audit_failed(context);
                if (auto analytics_store = analytics_store_.lock()) {
                    AnalyticsEvent ae;
                    ae.event_type = "agent.enrollment_audit_dropped";
                    ae.agent_id = info.agent_id();
                    ae.hostname = info.hostname();
                    ae.os = info.platform().os();
                    ae.arch = info.platform().arch();
                    ae.severity = Severity::kError;
                    ae.attributes = {{"result", "success"},
                                     {"audit_emitted", false},
                                     {"source", "gateway_proxy"}};
                    analytics_store->emit(std::move(ae));
                }
            }

            if (!auth_mgr_.ensure_enrolled(info.agent_id(), info.hostname(), info.platform().os(),
                                           info.platform().arch(), info.agent_version())) {
                response->set_accepted(false);
                response->set_reject_reason("enrollment denied by administrator");
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            }
        } else {
            // Auto-approve policies (no peer IP available from gateway yet)
            auth::ApprovalContext approval_ctx;
            approval_ctx.hostname = info.hostname();
            approval_ctx.attestation_provider = request->attestation_provider();

            auto matched_rule = auto_approve_.evaluate(approval_ctx);
            if (!matched_rule.empty()) {
                spdlog::info("[gateway] Agent {} auto-approved by policy: {}", info.agent_id(),
                             matched_rule);
                if (!auth_mgr_.ensure_enrolled(info.agent_id(), info.hostname(),
                                               info.platform().os(), info.platform().arch(),
                                               info.agent_version())) {
                    response->set_accepted(false);
                    response->set_reject_reason("enrollment denied by administrator");
                    response->set_enrollment_status("denied");
                    return grpc::Status::OK;
                }
            } else {
                // Tier 1: pending queue
                auto pending_status = auth_mgr_.get_pending_status(info.agent_id());

                if (!pending_status) {
                    auth_mgr_.add_pending_agent(info.agent_id(), info.hostname(),
                                                info.platform().os(), info.platform().arch(),
                                                info.agent_version());

                    response->set_accepted(false);
                    response->set_reject_reason("awaiting admin approval");
                    response->set_enrollment_status("pending");
                    bus_.publish("pending-agent", info.agent_id());
                    spdlog::info("[gateway] Agent {} placed in pending queue", info.agent_id());
                    return grpc::Status::OK;
                }

                switch (*pending_status) {
                case auth::PendingStatus::pending:
                    response->set_accepted(false);
                    response->set_reject_reason("still awaiting admin approval");
                    response->set_enrollment_status("pending");
                    return grpc::Status::OK;
                case auth::PendingStatus::denied:
                    response->set_accepted(false);
                    response->set_reject_reason("enrollment denied by administrator");
                    response->set_enrollment_status("denied");
                    return grpc::Status::OK;
                case auth::PendingStatus::approved:
                    spdlog::info("[gateway] Agent {} enrolled (admin-approved)", info.agent_id());
                    break;
                }
            }
        }
    } // end enrollment checks

gw_enrolled:
    // -- Enrolled -- register the agent ----------------------------------------
    //
    // W1.3 R2 / UP-7: trust-after-auth. Only record the gateway's peer IP
    // in the trusted set AFTER enrollment succeeds. Re-registration (fast
    // path at the top of the function) also lands here, so a gateway that
    // re-proxies an already-enrolled agent keeps refreshing the trust
    // entry — exactly the lifetime the TTL eviction (UP-2 / UP-3) expects.
    if (context) {
        registry_.note_trusted_gateway_peer(extract_peer_ip(context->peer()));
    }

    // HA WS-4 4.4 (`#4246` #6 / ADR-2002 §7 finding 6b's design review):
    // decide the registration branch — fresh vs. replay-ADOPTING an existing
    // session — BEFORE calling register_agent below. The pre-4.4 code called
    // register_agent unconditionally first, then decided; register_agent
    // ALWAYS installs a brand-new AgentSession over any prior one (see that
    // struct's IMMUTABILITY CONTRACT comment, agent_registry.hpp), which
    // means the "re-announce" branch's own gateway_node/wire_capabilities/
    // stream_home_id were being wiped by the very same call that "won" the
    // re-announce — a live, reachable bug on a single replica (no core
    // restart needed), not just a multi-replica one. Deciding first lets a
    // genuine stale/zombie replay be refused OUTRIGHT, before anything is
    // installed, instead of installing then rolling back.
    //
    // gateway_route_store.hpp's FORWARD NOTE states the binding rule this
    // block implements (docs-writer Gate 2 finding doc-S1: keep this quote
    // in sync with that comment rather than restating an earlier draft of
    // it — the reclaim_tombstoned_session clause below is NOT an
    // undocumented deviation from the rule, it's the rule's second ADOPT
    // path): "mechanism (c) must ADOPT the presented session into
    // gateway_sessions_/registry only if the directory renew_leases call
    // matched >= 1 row (a store-side CAS proving the row still belongs to
    // that session) OR the guarded CAS reclaim_tombstoned_session re-arms a
    // row this session's row was TOMBSTONED under — NEVER write back a
    // server-minted session to a gateway whose agent still holds the
    // original." register_fresh must NEVER run for an adopted session: it
    // mints a fresh epoch and unconditionally wins the guarded upsert,
    // which would clobber a route a NEWER
    // connection already holds.
    // HA WS-4 4.4 post-build adversarial review (PR #4636 FortitudeEtc,
    // BLOCKER 1): held for the ENTIRE remainder of this function — every
    // return path from here on releases it via RAII. See
    // registration_locks_'s header comment for the exact interleaving this
    // closes (a concurrent fresh registration for this SAME agent_id
    // completing its own decide+install between THIS call's decide and its
    // own register_agent/register_fresh/map_session install).
    auto reg_lock_ptr = registration_lock_for(info.agent_id());
    std::lock_guard<std::mutex> reg_lock(*reg_lock_ptr);

    std::string presented_session;
    if (context) {
        presented_session = AgentServiceImpl::client_metadata_value(
            *context, AgentServiceImpl::kSessionMetadataKey);
    }

    std::string session_id; // non-empty here means "adopting an existing session"
    bool store_confirmed_adopt = false; // did renew_leases/reclaim actually touch a row?
    if (!presented_session.empty()) {
        bool adopt;
        if (gateway_route_store_) {
            // HA WS-4 4.4 review fix (F1): the DIRECTORY governs this
            // decision whenever it is configured — an in-memory
            // `gateway_sessions_` hit is NEVER trusted on its own to
            // override it. `gateway_sessions_` is erased ONLY by a
            // DISCONNECTED (NotifyStreamStatus), so a replica whose
            // gateway uplink partitions for longer than the reap grace
            // window (270s) with core itself still UP keeps a session
            // "known in memory" long after `reap_stale_routes` has
            // tombstoned (and later hard-deleted) its row — adopting on
            // memory alone in that window would install a fresh
            // AgentSession (wiping placement) and then have
            // `announce_connected`'s fallback INSERT no-op against the
            // still-tombstoned row (`ON CONFLICT DO NOTHING`), leaving the
            // route permanently unrepaired. Worse, the same short-circuit
            // let a genuine ZOMBIE through: an agent that reconnected to a
            // DIFFERENT gateway node under a new session S2 (a fresh,
            // correct directory row) while this node's stale local ETS
            // entry for the OLD session S1 was still intact would ADOPT S1
            // on memory alone and overwrite S2's live placement. Always
            // consulting the store first closes both: the store already
            // knows the right answer in every case memory could get wrong.
            std::vector<std::string> renew_agents{info.agent_id()};
            std::vector<std::string> renew_ids{presented_session};
            auto renew_res = gateway_route_store_->renew_leases(renew_agents, renew_ids,
                                                                 kGatewayRouteLeaseTtlSecs);
            if (!renew_res) {
                // HA WS-4 4.4 review fix (round-2, UP-4/COMP-6): FAIL-CLOSED,
                // deliberately breaking with this file's usual per-site
                // fail-open convention (record_route_store_failure's header
                // comment). Every OTHER fail-open site in this file degrades
                // to "the lease looks slightly staler than it is" — bounded,
                // low-consequence. THIS decision is different in kind: a
                // wrong ADOPT here doesn't just accept a redundant write, it
                // INSTALLS a placement that may belong to a genuine zombie
                // session, unconditionally overwriting whatever a healthy
                // replica correctly holds — the exact failure register_fresh
                // is already fail-closed to prevent for a fresh registration.
                // A degraded store can't distinguish "still valid, adopt" from
                // "superseded, refuse" any better than we can, so refuse
                // rather than gamble on the more dangerous of the two wrong
                // answers. UNAVAILABLE (not FAILED_PRECONDITION): this is "we
                // can't tell right now", not "we checked and it's stale" — the
                // gateway's do_rpc/do_rpc_replay treats it as an ordinary
                // transport-shaped failure (record_result_no_replay counts it
                // against the breaker), not the FAILED_PRECONDITION-specific
                // disconnect-and-force-reconnect path.
                record_route_store_failure(metrics_, "renew_leases", renew_res.error());
                spdlog::warn("[gateway] ProxyRegister: degraded renew_leases during replay-adopt "
                            "decision for agent {} — refusing (fail-closed) rather than adopting "
                            "an unverified session", info.agent_id());
                return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                                    "routing directory unavailable");
            } else if (*renew_res >= 1) {
                // The durable directory still owns this session for this
                // agent (this replica's in-memory map may or may not have
                // known it — either way the store just confirmed it).
                adopt = true;
                store_confirmed_adopt = true;
            } else {
                // Zero rows: no LIVE row under this session. Try to reclaim a
                // TOMBSTONED (or entirely absent) row — a guarded CAS that
                // can NEVER win against a row a DIFFERENT, LIVE session
                // holds (gateway_route_store.hpp's reclaim_tombstoned_session
                // doc comment).
                auto reclaim_res = gateway_route_store_->reclaim_tombstoned_session(
                    info.agent_id(), presented_session, kGatewayRouteLeaseTtlSecs);
                if (!reclaim_res) {
                    // Same fail-CLOSED rationale as the renew_leases degraded
                    // branch above — see that comment.
                    record_route_store_failure(metrics_, "reclaim_tombstoned_session",
                                               reclaim_res.error());
                    spdlog::warn("[gateway] ProxyRegister: degraded reclaim_tombstoned_session "
                                "during replay-adopt decision for agent {} — refusing "
                                "(fail-closed) rather than adopting an unverified session",
                                info.agent_id());
                    return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                                        "routing directory unavailable");
                } else if (*reclaim_res) {
                    adopt = true;
                    store_confirmed_adopt = true;
                } else {
                    // The row belongs to a DIFFERENT, LIVE session — a
                    // genuine stale/zombie replay (including the zombie
                    // case above: THIS node's memory says S1, the store
                    // says S2 owns the row). adopt stays false regardless
                    // of what gateway_sessions_ believes.
                    adopt = false;
                }
            }
        } else {
            // No directory configured to check against — trust the
            // presented session IFF this replica's own memory still knows
            // it, matching pre-4.1 behavior (nothing to fence with, so
            // memory is the only signal there is).
            std::lock_guard lock(sessions_mu_);
            auto it = gateway_sessions_.find(presented_session);
            adopt = it != gateway_sessions_.end() && it->second == info.agent_id();
        }

        if (!adopt) {
            record_directory_desync(metrics_, "proxy_register", "session_superseded");
            spdlog::warn("[gateway] ProxyRegister: presented session {} for agent {} is "
                        "superseded by a different live session — refusing the replay so the "
                        "gateway forces the agent to reconnect fresh",
                        presented_session, info.agent_id());
            return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                                "session superseded; reconnect");
        }
        session_id = presented_session;
    }

    // Test-only interleave seam (HA WS-4 4.4 post-build review, PR #4636
    // FortitudeEtc BLOCKER 1 regression test): fires once, synchronously,
    // in the EXACT window the finding cited — after the decide-phase above,
    // before register_agent installs anything. A test callback that itself
    // dispatches a competing ProxyRegister for the SAME agent_id from here
    // deterministically proves registration_lock_for's serialization (that
    // competing call blocks on the same per-agent mutex this call already
    // holds, rather than racing to install ahead of it). No-op (nullptr) in
    // production. Mirrors AgentRegistry::register_agent's own
    // register_agent_interleave_hook_for_test_ seam (Gate 5 CH-1a).
    if (proxy_register_interleave_hook_for_test_) {
        auto hook = std::move(proxy_register_interleave_hook_for_test_);
        proxy_register_interleave_hook_for_test_ = nullptr;
        hook();
    }

    // #3401 Gap 2: register_agent fails closed if the W1.5/#823 device-token revoke sweep
    // itself errors. Note the peer trust note above already ran — a store fault does not
    // un-trust the gateway peer (that entry has its own TTL eviction, UP-2/UP-3); only the
    // agent's own registration is refused. UNAVAILABLE, not accepted=false (the agent's
    // PERMANENT-rejection signal, agent.cpp:1649-1657), so the agent retries on its normal
    // reconnect backoff.
    auto reg_result = registry_.register_agent(info);
    if (!reg_result) {
        spdlog::error("ProxyRegister: register_agent failed for '{}': {}", info.agent_id(),
                      reg_result.error());
        return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                            "registration temporarily unavailable");
    }
    // HA WS-4 4.2b follow-up (post-merge review #4344, MEDIUM finding 1): the just-installed
    // session, held by pointer identity so a later rollback below (if register_fresh fails) can
    // tell "still ours" apart from "already superseded by a concurrent registration" without
    // relying on session_id (still empty at this point — mapped later by map_session).
    auto installed = *reg_result;
    // Auto-add to root management group
    if (mgmt_group_store_ && mgmt_group_store_->is_open())
        mgmt_group_store_->add_member(ManagementGroupStore::kRootGroupId, info.agent_id());

    bool lost_epoch_race = false;
    if (!session_id.empty()) {
        // -- Adopted an existing session (replay path) -------------------------
        //
        // register_agent above just installed a brand-new AgentSession, so
        // this session's gateway_node/wire_capabilities/stream_home_id are
        // EMPTY again regardless of what they held a moment ago — that trio
        // is deliberately NOT carried forward here (it would risk publishing
        // a stale placement past a concurrent teardown). Convergence is the
        // gateway's job: `yuzu_gw_upstream`'s replay handler re-sends this
        // agent's own CONNECTED notification once it sees this adoption
        // succeed (HA WS-4 4.4, `yuzu_gw_agent.erl`'s `upstream_reannounced`
        // handling), which republishes the trio through the existing,
        // session-guarded `NotifyStreamStatus` → `set_gateway_route` path —
        // the same mechanism every fresh connection already relies on.
        // No further store write here (HA WS-4 4.4 review fix, F1): the
        // decision block above already renewed or reclaimed the row via
        // `renew_leases`/`reclaim_tombstoned_session` whenever
        // `gateway_route_store_` is configured (`store_confirmed_adopt`) —
        // a second renew here would be a redundant round trip, and doing
        // it AGAIN with only `session_id` (no `store_confirmed_adopt`
        // signal) is exactly the in-memory-trusts-itself shape that let a
        // tombstoned/zombie row go unnoticed. When no store is configured
        // there is nothing to renew.
        spdlog::debug("[gateway] ProxyRegister: adopted presented session {} for agent {} "
                     "(store-confirmed={})",
                     session_id, info.agent_id(), store_confirmed_adopt);
    } else {
        // -- Fresh registration (unchanged behavior) --------------------------
        session_id =
            "gw-session-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(16));
        if (gateway_route_store_) {
            if (auto res = gateway_route_store_->register_fresh(info.agent_id(), session_id);
                !res) {
                record_route_store_failure(metrics_, "register_fresh", res.error());
                // Task B (4.2b): register_fresh is the ONE fail-CLOSED
                // record_route_store_failure call site — every other site
                // stays fail-open (see that function's header comment for the
                // per-site contract). register_fresh CREATES the row; a
                // missed create here persists until reconnect/4.4 (no other
                // write on this path fills in a first row for this agent), so
                // an agent whose route cannot be durably recorded must be
                // refused rather than allowed to connect unrouteable.
                // Same STATUS shape as the #3401 register_agent refusal earlier
                // in this handler: UNAVAILABLE, not accepted=false, so the agent
                // retries on its normal reconnect backoff. UNLIKE that
                // refusal, though, THIS one runs AFTER register_agent has
                // already installed the session (connected gauge, agent-online
                // publish, root-group membership) — so refusing here without
                // rollback would leave a contextless "ghost" session behind
                // forever: reap_stale_sessions only TryCancels sessions that
                // carry a server_context, and a gateway-proxied session never
                // has one. Ghost-session rollback (post-merge review #4344,
                // MEDIUM finding 1): tear the just-installed session back down
                // by POINTER identity — remove_agent_if_same is a no-op if a
                // concurrent registration has already superseded `installed`,
                // so this never clobbers a newer session that won the race in
                // between. Root-group membership above is deliberately LEFT —
                // it's an idempotent (ON CONFLICT DO NOTHING), durable
                // fleet-membership fact, not a liveness signal, and removing
                // it would hide a re-registering agent's data from
                // root-confined operators.
                registry_.remove_agent_if_same(info.agent_id(), installed);
                return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                                    "routing directory unavailable");
            } else if (!res->won) {
                // A newer connection's register_fresh already won the epoch race
                // (out-of-order delivery, gateway_route_store.hpp). Inert this
                // slice — nothing dispatches through this store yet — so just
                // note it; this session still enrolls and connects normally.
                // 4.2a #8: recorded in lost_race_sessions_ below so the
                // FOLLOW-UP NotifyStreamStatus CONNECTED for this session
                // skips announce_connected instead of reporting a false
                // "session_mismatch" desync (see record_directory_desync's
                // header comment).
                lost_epoch_race = true;
                spdlog::debug("[gateway] ProxyRegister: register_fresh for agent {} session {} "
                              "lost the epoch race to a newer connection",
                              info.agent_id(), session_id);
            }
        }
    }

    response->set_session_id(session_id);
    response->set_accepted(true);
    response->set_enrollment_status("enrolled");

    // PR5d: mirror the direct Register path — if the agent sent a CSR and the
    // signer is wired (CA active), sign a per-agent client leaf bound to agent_id
    // and return it. Before this, a gateway-enrolled agent registered fine but
    // never received a per-agent cert (only the direct AgentServiceImpl::Register
    // signed), so it retried then degraded to one-way TLS. The agent↔gateway hop
    // is one-way TLS in M1 (PR5c) — the leaf is presented to a non-verifying
    // listener for now — but issuing it completes per-agent-mTLS-day-one (D4),
    // records the cert in ca_issued for inventory/revocation, and future-proofs
    // gateway mTLS. The Erlang gateway relays the RegisterResponse verbatim
    // (yuzu_gw_agent_service:register/2), so issued_certificate flows to the agent
    // (gateway_pb/agent_pb carry the fields since PR5). Signing failure is
    // non-fatal — the agent stays on the bootstrap posture and retries.
    //
    // Gate parity with the direct path (intentional): we only reach gw_enrolled
    // after enrollment succeeded (denied/pending agents returned early above; the
    // re-register fast-path reaches here only for an already-APPROVED agent). Like
    // the direct path, issuance is NOT gated on cert revocation — revoke is
    // serial-scoped (it invalidates a presented leaf); DENYING the agent is what
    // stops re-enrollment/re-issuance (checked above). The shared signer
    // (sign_agent_csr) carries the per-agent rate-limit + CSR-size cap, so both
    // paths share one issuance chokepoint and cannot drift.
    if (!request->csr_pem().empty() && agent_cert_signer_) {
        // #1273 B-2: the signer (sign_agent_csr) runs INSIDE this synchronous gRPC
        // handler and is now reachable over the one-way-TLS gateway edge. An
        // exception out of it (OpenSSL error, bad_alloc, …) would propagate out of
        // the sync handler and terminate the server. Contain it and degrade to
        // no-cert (identical to a nullopt return — the agent stays on bootstrap).
        std::optional<std::pair<std::string, std::string>> issued;
        try {
            issued = agent_cert_signer_(request->csr_pem(), info.agent_id(),
                                        CertIssuanceSource::GatewayProxy);
        } catch (const std::exception& e) {
            spdlog::error("[gateway] ProxyRegister: signer threw for agent {}: {}",
                          info.agent_id(), e.what());
        } catch (...) {
            // Non-std throw (foreign exception across a plugin/.so boundary, etc.)
            // must not escape the sync handler either (gov #1273 Hermes).
            spdlog::error("[gateway] ProxyRegister: signer threw a non-std exception for agent {}",
                          info.agent_id());
        }
        if (issued) {
            response->set_issued_certificate(issued->first);
            response->set_issued_ca_chain(issued->second);
            spdlog::info("[gateway] Issued per-agent client cert for {}", info.agent_id());
        } else {
            spdlog::warn("[gateway] ProxyRegister: client-cert signing failed for agent {}",
                         info.agent_id());
        }
    }

    // Store session_id on the AgentSession so session-aware cleanup works.
    // Without this, remove_agent_if_session would always no-op for gateway agents.
    registry_.map_session(session_id, info.agent_id());

    {
        std::lock_guard lock(sessions_mu_);
        gateway_sessions_[session_id] = info.agent_id();
        // 4.2a #8: remember a register_fresh epoch-race loss against ITS
        // session_id so the follow-up NotifyStreamStatus CONNECTED can skip
        // announce_connected instead of reporting a benign race-loss as a
        // desync (see record_directory_desync's header comment). A session
        // that reaches this line via the re-announce or unknown-session
        // branches never had lost_epoch_race set, so this is a plain insert,
        // never a stale leftover from a prior session reusing this id (a
        // freshly-minted random 128-bit session_id does not collide with an
        // old entry still needing eviction).
        if (lost_epoch_race)
            lost_race_sessions_.insert(session_id);
    }

    spdlog::info("[gateway] ProxyRegister succeeded: agent={}, session={}", info.agent_id(),
                 session_id);
    return grpc::Status::OK;
}

// -- BatchHeartbeat -----------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::BatchHeartbeat(grpc::ServerContext* context,
                                                        const gw::BatchHeartbeatRequest* request,
                                                        gw::BatchHeartbeatResponse* response) {
    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    int acked = 0;
    for (const auto& hb : request->heartbeats()) {
        // Validate that the session is known
        std::string agent_id;
        {
            std::lock_guard lock(sessions_mu_);
            auto it = gateway_sessions_.find(hb.session_id());
            if (it != gateway_sessions_.end()) {
                agent_id = it->second;
            }
        }
        if (agent_id.empty()) {
            spdlog::debug("[gateway] BatchHeartbeat: unknown session {}", hb.session_id());
            continue;
        }
        // #1000 / arch-S2: shared HeartbeatIngestion keeps the per-heartbeat
        // work (health upsert, metrics, fleet_snapshot push) identical to
        // the direct-heartbeat path so the two cannot drift.
        //
        // Gate 7 UP-10 — per-entry try/catch. A gateway BatchHeartbeat can
        // carry thousands of agents' heartbeats in one RPC; if ingest()
        // throws on a single entry (std::bad_alloc on a near-cap map walk,
        // a malformed payload that slips past the parser's own guard, an
        // exception out of health_store_/metrics_), an unhandled throw
        // would abort the whole RPC handler and silently drop every
        // remaining heartbeat in the batch — a single bad agent could
        // blank a gateway's entire fleet. Isolate each entry.
        if (heartbeat_ingestion_) {
            try {
                heartbeat_ingestion_->ingest(hb, agent_id, "gateway");
            } catch (const std::exception& ex) {
                spdlog::warn("[gateway] BatchHeartbeat: ingest threw for agent {} — "
                             "skipping entry, batch continues: {}",
                             agent_id, ex.what());
                continue;
            } catch (...) {
                spdlog::warn("[gateway] BatchHeartbeat: ingest threw unknown exception for "
                             "agent {} — skipping entry, batch continues",
                             agent_id);
                continue;
            }
        }
        ++acked;
    }

    // HA WS-4 4.1: batch-renew the route lease for every session in this
    // heartbeat batch, in ONE call (gateway_route_store.hpp's renew_leases is
    // itself a single batched statement) — matches BatchHeartbeat's own
    // batching rather than one write per agent per interval.
    //
    // #4246 #10 (closes the prior defense-in-depth gap): renew_leases now
    // correlates BOTH agent_id AND session_id, so every session collected
    // here needs its own resolved agent_id from gateway_sessions_ — the SAME
    // lookup the ingest loop above performs. The agent_id source is
    // DELIBERATELY the per-replica in-memory map, not the wire (the wire's
    // HeartbeatRequest carries no agent_id at all — only session_id): the
    // renew's trust anchor is the DURABLE (agent_id, session_id) binding
    // already stored in the directory, not a caller-supplied value, so a
    // compromised/buggy gateway asserting the wrong pairing simply matches
    // zero rows (counted below) rather than renewing a foreign agent's
    // lease. A session this replica does NOT locally know (unresolved
    // agent_id) has nothing to correlate against and is excluded from the
    // renewal batch entirely; it was never ingested above either (see the
    // "unknown session" branch). This is the SAME per-replica-in-memory
    // limitation ADR-2002 §7 already records for the ProxyRegister
    // re-announce known-session check (#4246 #3, deferred to WS-5 shared
    // presence) — not a new gap introduced by #10's correlation. On the
    // monolith (single replica, today's only shipped topology) it is
    // unreachable: every session this replica minted is in its own map, so
    // nothing is ever excluded. Re-deriving via `session_to_agent` (rather
    // than reusing the ingest loop's per-iteration `agent_id`) keeps renewal
    // independent of whether ingest happened to throw on that entry this
    // cycle, matching the prior "not gated on ingest success" property.
    if (gateway_route_store_) {
        std::unordered_map<std::string, std::string> session_to_agent; // session_id -> agent_id
        // Sessions this replica's gateway_sessions_ doesn't recognize —
        // excluded from the renew batch above (nothing to correlate), but
        // still surfaced via the desync counter below so a systemic
        // "gateway sending heartbeats for sessions the server doesn't know"
        // condition (or, once multi-replica routing exists, an LB handing a
        // batch to a replica that never registered the session) stays
        // visible rather than silently dropped — the exact signal #4246 #8
        // exists for.
        std::unordered_set<std::string> unknown_sessions;
        {
            std::lock_guard lock(sessions_mu_);
            for (const auto& hb : request->heartbeats()) {
                if (hb.session_id().empty())
                    continue;
                auto it = gateway_sessions_.find(hb.session_id());
                if (it != gateway_sessions_.end())
                    session_to_agent.emplace(hb.session_id(), it->second);
                else
                    unknown_sessions.insert(hb.session_id());
            }
            // PR #4299 review (SHOULD 2): a session that lost its
            // register_fresh epoch race (lost_race_sessions_) is EXPECTED to
            // never match a row again — it is excluded from desync on its own
            // CONNECTED (see record_directory_desync's header comment) but
            // was previously still counted here on every SUBSEQUENT
            // heartbeat. Drop known race-losers BEFORE comparing against
            // rows_updated.
            //
            // PR #4299 round-2 external review (LOW, disputed between the two
            // reviewers — VERIFIED against the code): a lost-race session's
            // agent_routes row is claimed to be "renewed by heartbeats but
            // excluded from this eligible set", undercounting the shortfall
            // by one. Not reachable: a lost-race session's CONNECTED handler
            // (this file, NotifyStreamStatus) checks `lost_race_sessions_`
            // and skips the `announce_connected` call ENTIRELY for that
            // session_id — including its fallback `ON CONFLICT DO NOTHING`
            // insert — so no agent_routes row is ever created under a
            // lost-race session_id. renew_leases() (gateway_route_store.cpp)
            // now correlates agent_id AND session_id, so it can never touch a
            // row that doesn't exist under that pair either. There is
            // therefore nothing for a subsequent heartbeat to "renew" for a
            // lost-race session in the first place; excluding it from
            // `eligible` here removes a permanent false shortfall, not a real
            // row from the count.
            for (auto it = session_to_agent.begin(); it != session_to_agent.end();) {
                if (lost_race_sessions_.contains(it->first))
                    it = session_to_agent.erase(it);
                else
                    ++it;
            }
        }
        // Distinct (deduped) count — a retried batch repeating the same
        // unknown session id must not inflate this beyond the actual number
        // of un-correlatable sessions, matching the dedup already applied to
        // the eligible/shortfall accounting below.
        if (!unknown_sessions.empty()) {
            record_directory_desync(metrics_, "renew_leases", "unknown_session",
                                    static_cast<double>(unknown_sessions.size()));
        }
        if (!session_to_agent.empty()) {
            // A `std::unordered_map` keyed on session_id already collapses a
            // RETRIED batch's duplicate session id (the Erlang buffer retains
            // a failed batch and PREPENDS the next one with no dedup —
            // gateway/apps/yuzu_gw/src/yuzu_gw_heartbeat_buffer.erl) to one
            // entry, so the two parallel arrays below are already the
            // distinct, race-loser-filtered eligible set — no separate
            // sort/unique pass needed (PR #4299 review SHOULD 2).
            std::vector<std::string> renew_agents;
            std::vector<std::string> renew_sessions;
            renew_agents.reserve(session_to_agent.size());
            renew_sessions.reserve(session_to_agent.size());
            for (const auto& [session_id, agent_id] : session_to_agent) {
                renew_sessions.push_back(session_id);
                renew_agents.push_back(agent_id);
            }
            if (auto res = gateway_route_store_->renew_leases(renew_agents, renew_sessions,
                                                              kGatewayRouteLeaseTtlSecs);
                !res) {
                // Task B (4.2b): fail-OPEN, deliberately — same rationale as
                // the ProxyRegister renew sites above: this call only extends
                // an EXISTING row's lease, never creates one, so a degraded
                // batch at worst leaves rows stale, which a future reader
                // already treats as not-routable. Refusing the whole batch
                // (thousands of agents) over one renew failure would be a
                // much larger blast radius than the staleness it avoids.
                record_route_store_failure(metrics_, "renew_leases", res.error());
            } else {
                const int eligible = static_cast<int>(renew_sessions.size());
                const int shortfall = eligible - *res; // clamp >= 0 via the guard below
                if (shortfall > 0) {
                    record_directory_desync(metrics_, "renew_leases", "shortfall",
                                            static_cast<double>(shortfall));
                }
            }
        }
    }

    response->set_acknowledged_count(acked);
    spdlog::debug("[gateway] BatchHeartbeat from node '{}': {}/{} acked", request->gateway_node(),
                  acked, request->heartbeats_size());
    return grpc::Status::OK;
}

// -- ProxyInventory -----------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::ProxyInventory(grpc::ServerContext* context,
                                                        const pb::InventoryReport* request,
                                                        pb::InventoryAck* response) {
    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    std::string agent_id;
    {
        std::lock_guard lock(sessions_mu_);
        auto it = gateway_sessions_.find(request->session_id());
        if (it != gateway_sessions_.end()) {
            agent_id = it->second;
        }
    }
    if (agent_id.empty()) {
        spdlog::warn("[gateway] ProxyInventory: unknown session {}", request->session_id());
        response->set_received(false);
        return grpc::Status::OK;
    }

    // The generic loop runs before the typed seams, so enforce the shared
    // whole-report cap here before any store write or pool acquisition.
    if (!validate_inventory_report_source_count(agent_id, *request, metrics_)) {
        response->set_received(true);
        return grpc::Status::OK;
    }

    // Generic per-source blob persistence (sync-framework baseline; backs the
    // kInventoryQuery scope source + the inventory eval engine). The TYPED sources
    // (installed_software / app_perf / device_ci / software_licensing) are persisted
    // via their own normalized stores + shared seams below — skip them here, or they
    // double-store into the generic InventoryStore. That generic store is read on
    // Infrastructure:Read (query_inventory/get_agent_inventory), so a typed source
    // leaking into it bypasses its own securable AND breaks direct/gateway parity
    // (the direct ReportInventory path has no generic loop). is_typed_inventory_source
    // is the single skip-list — a new typed source registers there (ADR-0016 §5).
    if (inventory_store_ && inventory_store_->is_open()) {
        int64_t collected_epoch = 0;
        if (request->has_collected_at()) {
            collected_epoch = request->collected_at().millis_epoch() / 1000;
        }
        for (const auto& [plugin_name, data_bytes] : request->plugin_data()) {
            if (is_typed_inventory_source(plugin_name))
                continue; // typed projections, handled by their seams below
            std::string json_str(data_bytes.begin(), data_bytes.end());
            // #2437-class guard: this is the ONLY call site of InventoryStore::upsert
            // in the tree, and this blob is raw wire bytes off an agent (relayed via
            // the gateway) with no prior validation - not even a confirmed parse,
            // let alone a depth check. dump() on data_json is unboundedly recursive
            // (mcp_jsonrpc.hpp), so a poisoned blob stored here would SIGSEGV the
            // whole process on the next read (data_inventory_routes.cpp,
            // inventory_eval.cpp). Reject the raw text BEFORE parse/store - this one
            // chokepoint retroactively protects every reader for FUTURE rows, but
            // does not heal rows already written before this guard shipped (the
            // three read-side guards cover those). Skip only this one source; still
            // ack the overall report. Log identifiers only, never the payload.
            if (mcp::json_exceeds_depth(json_str, mcp::kMcpMaxJsonDepth)) {
                spdlog::warn("[gateway] ProxyInventory: rejecting '{}' blob from agent={} - "
                            "nests too deeply (#2437-class)",
                            onbehalf::sanitize_for_log(plugin_name, 128), agent_id);
                if (metrics_)
                    // Fixed sentinel, not plugin_name: this map's KEYS are raw,
                    // agent-supplied strings for the generic (non-typed) source
                    // family, so using plugin_name as a label here would let a
                    // single agent mint unbounded metric series just by
                    // submitting over-depth blobs under different made-up
                    // names. Matches validate_inventory_report_source_count's
                    // own "__report__" sentinel a few lines above for the
                    // same reason. outcome is its OWN "rejected_depth" value,
                    // not the existing "rejected" - that value is documented
                    // (docs/user-manual/inventory.md) and alerted on
                    // (YuzuInventoryReportRejected) as meaning specifically a
                    // whole report rejected at the source-map cap; reusing it
                    // here would make a single over-depth blob page an
                    // operator with the wrong runbook (gov consistency, same
                    // reasoning as validate_inventory_report_source_count's
                    // own rejected-vs-dropped distinction in
                    // inventory_ingestion.cpp).
                    metrics_
                        ->counter("yuzu_inventory_ingest_total",
                                 {{"source", "__generic__"}, {"outcome", "rejected_depth"}})
                        .increment();
                continue;
            }
            inventory_store_->upsert(agent_id, plugin_name, json_str, collected_epoch);
        }
    }
    // Typed installed_software via the shared seam (ADR-0016 §5) — byte-identical
    // to the direct ReportInventory path; fills response->need_full for any
    // source needing a cold-cache resync.
    if (software_inventory_store_ && software_inventory_store_->is_open()) {
        // Isolate ingest failures, identical to the direct ReportInventory path
        // — otherwise an exception escapes as gRPC UNKNOWN (UP-9 / parity).
        try {
            ingest_inventory_report(*software_inventory_store_, agent_id, *request, *response,
                                    metrics_);
        } catch (const std::exception& ex) {
            spdlog::warn("[gateway] ProxyInventory: inventory ingest threw for agent={} — acked: {}",
                         agent_id, ex.what());
        } catch (...) {
            spdlog::warn("[gateway] ProxyInventory: inventory ingest threw (unknown) for agent={} "
                         "— acked",
                         agent_id);
        }
    }
    // Typed app_perf via its shared seam (DEX app-perf-over-time B1) — byte-identical
    // to the direct ReportInventory path, independently guarded + isolated.
    if (app_perf_daily_store_ && app_perf_daily_store_->is_open()) {
        try {
            ingest_app_perf_report(*app_perf_daily_store_, agent_id, *request, *response, metrics_);
        } catch (const std::exception& ex) {
            spdlog::warn("[gateway] ProxyInventory: app_perf ingest threw for agent={} — acked: {}",
                         agent_id, ex.what());
        } catch (...) {
            spdlog::warn("[gateway] ProxyInventory: app_perf ingest threw (unknown) for agent={} "
                         "— acked",
                         agent_id);
        }
    }
    // Typed device_ci via its shared seam (ADR-0016) — byte-identical to the direct
    // ReportInventory path, independently guarded + isolated.
    if (device_inventory_store_ && device_inventory_store_->is_open()) {
        try {
            ingest_device_ci_report(*device_inventory_store_, agent_id, *request, *response,
                                    metrics_);
        } catch (const std::exception& ex) {
            spdlog::warn("[gateway] ProxyInventory: device_ci ingest threw for agent={} — acked: {}",
                         agent_id, ex.what());
        } catch (...) {
            spdlog::warn("[gateway] ProxyInventory: device_ci ingest threw (unknown) for agent={} "
                         "— acked",
                         agent_id);
        }
    }
    // Typed software_licensing via its shared seam (ADR-0024 Decision 5) —
    // byte-identical to the direct ReportInventory path, independently guarded
    // + isolated.
    if (software_licensing_store_ && software_licensing_store_->is_open()) {
        try {
            ingest_software_licensing_report(*software_licensing_store_, agent_id, *request,
                                             *response, metrics_);
        } catch (const std::exception& ex) {
            spdlog::warn("[gateway] ProxyInventory: software_licensing ingest threw for agent={} "
                         "— acked: {}",
                         agent_id, ex.what());
        } catch (...) {
            spdlog::warn("[gateway] ProxyInventory: software_licensing ingest threw (unknown) for "
                         "agent={} — acked",
                         agent_id);
        }
    }
    // Typed app_usage via its shared seam (Wave 7 PR7.2) — byte-identical to
    // the direct ReportInventory path, independently guarded + isolated.
    if (app_usage_store_ && app_usage_store_->is_open()) {
        try {
            ingest_app_usage_report(*app_usage_store_, agent_id, *request, *response, metrics_);
        } catch (const std::exception& ex) {
            // P11: unlike the sibling blocks above, a swallowed throw here with no
            // nack lets the agent's SyncScheduler advance last_hash and go
            // hash-only for a day with nothing persisted — the nack forces a full
            // resend next cycle. Follow-up issue filed at delivery to retrofit the
            // four sibling blocks (installed_software/app_perf/device_ci/
            // software_licensing) with the same nack; do not do it here.
            response->add_need_full("app_usage");
            spdlog::warn("[gateway] ProxyInventory: app_usage ingest threw for agent={} — "
                         "nacked: {}",
                         agent_id, ex.what());
        } catch (...) {
            response->add_need_full("app_usage");
            spdlog::warn("[gateway] ProxyInventory: app_usage ingest threw (unknown) for "
                         "agent={} — nacked",
                         agent_id);
        }
    }
    response->set_received(true);
    return grpc::Status::OK;
}

// -- NotifyStreamStatus -------------------------------------------------------

grpc::Status
GatewayUpstreamServiceImpl::NotifyStreamStatus(grpc::ServerContext* context,
                                               const gw::StreamStatusNotification* request,
                                               gw::StreamStatusAck* response) {
    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    const auto& agent_id = request->agent_id();
    const auto& session_id = request->session_id();

    // Verify session
    {
        std::lock_guard lock(sessions_mu_);
        auto it = gateway_sessions_.find(session_id);
        if (it == gateway_sessions_.end() || it->second != agent_id) {
            spdlog::warn("[gateway] NotifyStreamStatus: unknown session {} for agent {}",
                         session_id, agent_id);
            // 4.2a #8: this in-memory gateway_sessions_ guard, not the
            // directory store, but the same "systemic desync visibility"
            // signal the architect flagged as the dominant post-restart
            // symptom (a replica that lost its gateway_sessions_ map, or a
            // notification for a session that was never wired through
            // ProxyRegister on this replica).
            record_directory_desync(metrics_, "notify_stream_status", "unknown_session");
            response->set_acknowledged(false);
            return grpc::Status::OK;
        }
    }

    switch (request->event()) {
    case gw::StreamStatusNotification::CONNECTED: {
        // PLAN item 5 (CC-03, peer finding PLAN-007): `wire_capabilities` was
        // read off the wire and dropped on the floor here — p3's advertised
        // capability set never reached the registry, so the dispatch
        // chokepoint's routed-path gateway-capability check (agent_registry.cpp)
        // had nothing to consult and every gateway session looked
        // capability-less. Record the FULL set exactly as advertised; a
        // reconnect (a fresh CONNECTED, which this branch always is —
        // `wire_capabilities` is sent with EVERY CONNECTED notification, not
        // only the first) REPLACES it, never merges.
        //
        // M1 (review finding, post-merge round): node + capabilities publish
        // through ONE call, `set_gateway_route` — they used to be two calls,
        // which both raced `send_to`/`send_to_all`'s reads on `gateway_node`
        // (a C++ data race: written under a different lock than it was read
        // under) and exposed an observable intermediate state (node set,
        // capabilities not yet replaced) that could false-deny a dispatch.
        std::vector<std::string> wire_capabilities(request->wire_capabilities().begin(),
                                                    request->wire_capabilities().end());
        // HA WS-4 #4324: stream_home_id is gateway-asserted, untrusted input
        // (see kMaxStreamHomeIdLen's comment) — bound it once, here, before
        // publishing it into the registry or the directory below. An
        // oversized value is malformed: clamp to empty (legacy/no-fence for
        // this call) rather than rejecting the whole RPC or using it
        // unbounded downstream.
        std::string stream_home_id = request->stream_home_id();
        if (stream_home_id.size() > kMaxStreamHomeIdLen) {
            record_directory_desync(metrics_, "announce_connected", "malformed_home_id");
            stream_home_id.clear();
        }
        // HA WS-4 4.3: cluster_id is gateway-asserted, untrusted input, same
        // as stream_home_id above — see kMaxClusterIdLen's comment. Clamp
        // once, here, before it reaches set_gateway_route/announce_connected
        // (Fable pre-implementation review, 4.3 plan) — it is later used as
        // a Prometheus metric label's resolution key in
        // forward_gateway_pending (server.cpp), so an unbounded value is
        // both a routing-correctness and a metrics-cardinality risk.
        std::string cluster_id = request->cluster_id();
        if (cluster_id.size() > kMaxClusterIdLen) {
            record_directory_desync(metrics_, "announce_connected", "malformed_cluster_id");
            // pr-rev finding (FortitudeEtc/Codex+Kimi, SHOULD 2): clamping
            // to EMPTY made a malformed value indistinguishable from
            // "legitimately never set" — empty resolves to the "default"
            // cluster in GatewayMgmtStubPool::resolve() (the correct
            // behavior for the real "gateway never announced one" case),
            // so an oversized/malformed cluster_id was silently routed to
            // whatever cluster "default" happens to be, contradicting
            // "never a silent fallback to the wrong cluster". Clamp to the
            // reserved kUnknownGatewayClusterLabel sentinel instead — in
            // multi-cluster mode this can never match a real configured
            // key (parse_gateway_cluster_addrs rejects it as a config
            // value, see main.cpp/gateway_mgmt_stub_pool.hpp), so it
            // resolves to the genuine unknown_cluster/unmapped_cluster_seen
            // path instead of a silent default.
            cluster_id = std::string(yuzu::server::kUnknownGatewayClusterLabel);
        }
        // #4669: a READ-ONLY, non-mutating pre-check, BEFORE publishing
        // anything — refuses EARLY (before set_gateway_route's in-memory
        // write, the PRIMARY dispatch path: `AgentSession::cluster_id`, read
        // by `send_to`/`send_to_all`) if the durable store shows THIS SAME
        // session already durably bound to a DIFFERENT cluster
        // (gateway_route_store.hpp's "AGENT<->CLUSTER AFFINITY" note). Kept
        // as a SEPARATE check rather than reordering `announce_connected`'s
        // own WRITE ahead of `set_gateway_route`, specifically so an
        // ORDINARY stale/superseded CONNECTED (a DIFFERENT session than the
        // one the row currently holds — set_gateway_route's own
        // `stale_connected_session` check below, unrelated to affinity)
        // keeps its EXISTING short-circuit shape unchanged: this pre-check
        // can only ever fire true for a SESSION-MATCHED, CLUSTER-MISMATCHED
        // row, the one case `set_gateway_route`'s own session-only check
        // cannot see. A DEGRADED read stays fail-OPEN (proceed), matching
        // every other `announce_connected`-adjacent site's per-site
        // contract (Task B) — only a DEFINITIVE conflict is fail-closed.
        // `announce_connected` (below, in its ORIGINAL position/logic)
        // remains the enforcement OF RECORD — its own guarded UPDATE
        // independently re-checks the SAME affinity atomically at write
        // time, so a mismatched cluster_id can never persist DURABLY; it can
        // only let this pre-check miss a violation the write then still
        // refuses. Gate 2 security-guardian correction (2026-09-21): this
        // is NOT bounded to a microsecond race margin — a rogue's claimed
        // placement CAN reach the in-memory dispatch registry
        // (set_gateway_route, read by send_to/send_to_all) before the
        // durable store gets a chance to refuse it. pr-rev fix (FortitudeEtc/
        // Codex+Kimi, BLOCKER, 2026-09-22): the window this describes used
        // to be open-ended — a definitive refusal on the WRITE only emitted a
        // metric+audit, never rolling back the already-published in-memory
        // entry, so it persisted with NO reconciliation until process
        // restart. The write-time branch below now calls
        // `registry_.unpublish_gateway_route` on a definitive violation,
        // closing the window down to the time between this pre-check's
        // fail-open and that write actually completing — for the ORDINARY
        // case (pre-check degrades, write succeeds and correctly refuses),
        // this is now a narrow race again, not open-ended. ONE compound case
        // remains genuinely open-ended: this pre-check AND
        // announce_connected's own write BOTH degrading simultaneously (same
        // Postgres pool) — then the write never reaches the
        // `cluster_affinity_violation` branch at all (it reports
        // `db_error`/`store_unavailable` instead), so there is nothing to
        // revert, and the rogue's placement persists for as long as BOTH
        // stay degraded. `YuzuGatewayClusterAffinityCheckDegradedDuringWrite`
        // (docs/prometheus/yuzu-alerts.yml) exists specifically to make THAT
        // compound window observable. See #4697 for the still-missing
        // regression test covering both cases.
        if (gateway_route_store_) {
            bool skip = false;
            {
                std::lock_guard lock(sessions_mu_);
                skip = lost_race_sessions_.contains(session_id);
            }
            if (!skip) {
                if (auto conflict = gateway_route_store_->has_cluster_affinity_conflict(
                        agent_id, session_id, cluster_id);
                    !conflict) {
                    // A DISTINCT op label from "announce_connected" (never
                    // conflated with it): this is a separate READ, and a
                    // pre-existing test pins the ONE write-failure increment
                    // announce_connected's OWN degraded call below produces
                    // per CONNECTED — doubling that under the same label
                    // would also make an SRE dashboard misread "one degraded
                    // write" as "two", conflating a read failure with a
                    // write failure.
                    record_route_store_failure(metrics_, "cluster_affinity_check", conflict.error());
                    // fail-OPEN (per-site contract, unchanged): fall through.
                } else if (*conflict) {
                    spdlog::warn(
                        "[gateway] NotifyStreamStatus: CONNECTED for agent {} (session {}) "
                        "claims cluster_id '{}', which differs from this agent's already-bound "
                        "cluster affinity — REFUSING as a likely cross-cluster identity claim "
                        "(#4669), not publishing this placement anywhere",
                        agent_id, session_id, cluster_id);
                    record_directory_desync(metrics_, "announce_connected",
                                            "cluster_affinity_violation");
                    if (audit_store_ && audit_store_->is_open()) {
                        AuditEvent ev;
                        ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                           std::chrono::system_clock::now().time_since_epoch())
                                           .count();
                        ev.principal = "gateway_cluster:" + cluster_id;
                        ev.principal_role = "gateway";
                        ev.action = "gateway.cluster_affinity_violation";
                        ev.target_type = "agent";
                        ev.target_id = agent_id;
                        ev.detail = std::string("session=")
                                        .append(session_id)
                                        .append(" claimed_cluster_id=")
                                        .append(cluster_id)
                                        .append(" detected_at=pre_check");
                        ev.result = "failure";
                        if (!audit_store_->log(ev))
                            signal_grpc_audit_failed(context);
                    }
                    response->set_acknowledged(false);
                    return grpc::Status::OK;
                }
            }
        }
        // HA WS-4 4.4 post-build adversarial review (PR #4636 FortitudeEtc,
        // BLOCKER 2): the session check just above (gateway_sessions_) only
        // proves `session_id` is SOME live entry for this agent — multiple
        // sessions can coexist there until each is individually torn down by
        // its own DISCONNECTED — not that it is the CURRENT one. Without this
        // check, set_gateway_route would publish a delayed/superseded
        // session's placement over a genuinely newer registration's, ahead of
        // the durable store even getting a chance to reject the corresponding
        // announce_connected write below. A `false` return means a different,
        // now-current session is installed for this agent — reject this
        // CONNECTED outright rather than publishing a stale route or
        // continuing to the (now-meaningless) announce_connected write.
        if (!registry_.set_gateway_route(agent_id, session_id, request->gateway_node(),
                                         std::move(wire_capabilities), stream_home_id,
                                         cluster_id)) {
            spdlog::warn("[gateway] NotifyStreamStatus: CONNECTED for session {} (agent {}) is "
                        "no longer the currently-installed session — rejecting the publish "
                        "rather than clobbering a newer registration's placement",
                        session_id, agent_id);
            record_directory_desync(metrics_, "notify_stream_status", "stale_connected_session");
            response->set_acknowledged(false);
            return grpc::Status::OK;
        }
        // HA WS-4 4.1: mirror the same CONNECTED fact into the durable,
        // cross-replica routing directory (gateway_route_store.hpp). As of
        // 4.2b Task C the directory IS read for dispatch (fallback-only, on a
        // local-registry miss). announce_connected nonetheless stays fail-OPEN
        // deliberately (Task B per-site contract) — this NotifyStreamStatus
        // CONNECTED is itself a droppable gen_server:cast on the gateway side
        // (the erlang caller does not block on it), and registry_.set_gateway_route
        // just above has ALREADY published the in-memory route — failing this
        // RPC now would split the two (memory says connected, directory does
        // not) and risk a routing black hole for no correctness gain. The
        // reader's `routable` trust predicate, not this write, is the integrity
        // backstop. #4669: the ONE exception is `cluster_affinity_violation`
        // below — by this point the #4669 pre-check ABOVE has already refused
        // the common case, so reaching a violation HERE is only the narrow
        // race window that comment describes; still counted distinctly, but
        // `set_gateway_route` has already run by then (that race's accepted
        // cost — see the pre-check's own comment).
        if (gateway_route_store_) {
            // 4.2a #8: a session recorded in lost_race_sessions_ lost its
            // register_fresh epoch race — the durable row already belongs to
            // a NEWER connection, so calling announce_connected here would
            // only report matched=false and pollute the desync counter with
            // an expected, benign race loss (see record_directory_desync's
            // header comment). Skip the directory write entirely; registry_
            // .set_gateway_route above is unaffected (legacy in-memory
            // routing is not gated on the epoch race).
            bool skip_announce = false;
            {
                std::lock_guard lock(sessions_mu_);
                skip_announce = lost_race_sessions_.contains(session_id);
            }
            if (skip_announce) {
                spdlog::debug("[gateway] NotifyStreamStatus CONNECTED: session {} lost its "
                             "register_fresh epoch race — skipping directory announce_connected",
                             session_id);
            } else if (auto res = gateway_route_store_->announce_connected(
                           agent_id, session_id, cluster_id, request->gateway_node(),
                           kGatewayRouteLeaseTtlSecs, stream_home_id);
                       !res) {
                record_route_store_failure(metrics_, "announce_connected", res.error());
            } else if (res->cluster_affinity_violation) {
                // Gate 4 consistency-auditor SHOULD (2026-09-21): this is the
                // SECOND of the two `cluster_affinity_violation` detection
                // sites (the pre-check above catches the common case; this
                // one is reached only in the narrow race window that
                // pre-check's own comment describes — a definitive conflict
                // the pre-check missed, e.g. on a degraded read). The pre-
                // check site emits BOTH the metric and an AuditEvent; before
                // this fix, this site emitted only the metric, so an operator
                // correlating the desync counter against the audit log could
                // see an increment here with no matching audit row. Emit the
                // same audit event here too — best-effort, matching the
                // pre-check site's pattern, since `set_gateway_route` has
                // already run by this point (the pre-check's own "accepted
                // cost" for this race) and this audit row is the only
                // durable record of which agent/session/cluster hit it.
                record_directory_desync(metrics_, "announce_connected", "cluster_affinity_violation");
                // pr-rev finding (FortitudeEtc/Codex+Kimi, BLOCKER, 2026-09-22,
                // empirically confirmed): this is a DEFINITIVE violation --
                // the durable store correctly refused to record the claimed
                // placement -- but `registry_.set_gateway_route` ABOVE (this
                // same call sequence, before this write ran) already
                // published it to the in-memory dispatch registry that
                // send_to/send_to_all actually read. Without this call, the
                // rogue's cluster_id/gateway_node/wire_capabilities/
                // stream_home_id would persist as the LIVE in-memory dispatch
                // target indefinitely, with no reconciliation ever bringing
                // it back in line with the durable (correctly-refused) state
                // -- a degraded pre-check read followed by a successful,
                // definitively-refused write left the rogue's placement live.
                // Revert exactly what that publish just installed for THIS
                // session; a `false` return means the session was already
                // superseded by something newer in the interim, in which
                // case there is nothing of THIS call's to revert (the newer
                // publish is not touched).
                if (!registry_.unpublish_gateway_route(agent_id, session_id)) {
                    spdlog::debug(
                        "[gateway] NotifyStreamStatus: cluster_affinity_violation revert "
                        "no-op for agent {} session {} — session already superseded",
                        agent_id, session_id);
                }
                if (audit_store_ && audit_store_->is_open()) {
                    AuditEvent ev;
                    ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();
                    ev.principal = "gateway_cluster:" + cluster_id;
                    ev.principal_role = "gateway";
                    ev.action = "gateway.cluster_affinity_violation";
                    ev.target_type = "agent";
                    ev.target_id = agent_id;
                    ev.detail = std::string("session=")
                                    .append(session_id)
                                    .append(" claimed_cluster_id=")
                                    .append(cluster_id)
                                    .append(" detected_at=announce_connected_write");
                    ev.result = "failure";
                    if (!audit_store_->log(ev))
                        signal_grpc_audit_failed(context);
                }
            } else if (!res->matched) {
                record_directory_desync(metrics_, "announce_connected", "session_mismatch");
            }
        }
        // HA WS-4 4.3 (Fable pre-implementation review, finding 3): in
        // multi-cluster mode (known_gateway_clusters_ set), warn once per
        // unmapped cluster_id so an operator learns a session accepted with
        // an unroutable cluster BEFORE the first dispatch to it silently
        // drops, rather than only from the drop itself. nullptr
        // (single-cluster mode, the default) skips this entirely — every
        // cluster_id resolves to the legacy stub regardless of its value.
        if (known_gateway_clusters_ && !cluster_id.empty() &&
            !known_gateway_clusters_->contains(cluster_id)) {
            bool first_warning = false;
            bool cap_reached_transition = false;
            {
                std::lock_guard lock(unmapped_clusters_warned_mu_);
                // sre Gate 3: unmapped_clusters_warned_ is per-entry bounded
                // (kMaxClusterIdLen) but was previously unbounded in COUNT — a
                // session cycling through many distinct malformed/misconfigured
                // cluster_id values grew it indefinitely. Capped the entry
                // count (below kMaxUnmappedClustersWarned).
                //
                // unhappy-path Gate 4 finding (UP-6): the FIRST version of this
                // cap fix bounded memory correctly but let LOGGING degrade to
                // unbounded — past the cap, every occurrence of any distinct
                // id not already in the set re-warned (never inserted, so
                // "first" every time). A gateway peer already past the
                // mgmt-plane's mTLS+peer-pin auth (#1422) but varying its
                // announced cluster_id across reconnects — compromised,
                // misconfigured, or simply buggy — could still drive an
                // unbounded per-connect WARN rate (a log/disk-pressure DoS,
                // distinct from the memory growth the cap already fixed).
                // Fixed: past the cap, do NOT log per-occurrence at all — only
                // the metric below (unconditional, every occurrence) keeps
                // counting. `cap_reached_transition` fires the ONE explicit
                // "we've stopped logging individually" notice, exactly once,
                // at the moment the cap is first reached.
                if (unmapped_clusters_warned_.size() >= kMaxUnmappedClustersWarned) {
                    first_warning = false;
                } else {
                    auto [_, inserted] = unmapped_clusters_warned_.insert(cluster_id);
                    first_warning = inserted;
                    cap_reached_transition =
                        inserted && unmapped_clusters_warned_.size() == kMaxUnmappedClustersWarned;
                }
            }
            if (first_warning) {
                spdlog::warn("[gateway] Agent {} connected announcing cluster_id '{}', which is "
                             "not in --gateway-cluster-addr's configured map — commands for this "
                             "agent (and any other agent on this cluster) will be dropped as "
                             "unknown_cluster until it is added",
                             agent_id, cluster_id);
            }
            if (cap_reached_transition) {
                spdlog::warn("[gateway] unmapped cluster_id tracking reached its cap ({} "
                             "distinct ids) — further distinct unmapped cluster_id values will "
                             "still be counted (yuzu_server_gateway_forward_total{{status="
                             "\"unmapped_cluster_seen\"}}) but no longer individually logged",
                             kMaxUnmappedClustersWarned);
            }
            if (metrics_) {
                metrics_->counter("yuzu_server_gateway_forward_total",
                                  {{"cluster_id", std::string(yuzu::server::kUnknownGatewayClusterLabel)},
                                   {"status", "unmapped_cluster_seen"}})
                    .increment();
            }
        }
        spdlog::info("[gateway] Agent {} stream CONNECTED at gateway node '{}' ({} wire "
                     "capabilit{})",
                     agent_id, request->gateway_node(), request->wire_capabilities_size(),
                     request->wire_capabilities_size() == 1 ? "y" : "ies");
        break;
    }

    case gw::StreamStatusNotification::DISCONNECTED: {
        // HA WS-4 #4324: stream_home_id is gateway-asserted, untrusted input
        // — bound it once, here, before the fence comparison and everything
        // downstream in this branch reuses the (possibly-clamped) value.
        std::string stream_home_id = request->stream_home_id();
        if (stream_home_id.size() > kMaxStreamHomeIdLen) {
            record_directory_desync(metrics_, "deregister", "malformed_home_id");
            stream_home_id.clear();
        }

        // HA WS-4 #4324 — the per-home stream-generation fence. Resolved
        // ONCE, HERE, before ANY of the three DISCONNECTED effects below
        // (registry clear_stream_if_session/remove_agent_if_session, the
        // durable directory deregister, and the gateway_sessions_/
        // lost_race_sessions_ erase) run. This is a design-review-mandated
        // structural fix, not a style choice: fencing only a SUBSET of the
        // three (e.g. the registry+store writes but not the session-map
        // erase) is WORSE than the pre-#4324 unfenced behavior — a stale
        // DISCONNECTED(home1) for a session re-homed to home2 would then
        // correctly no-op the registry/store teardown, but STILL erase
        // gateway_sessions_[session_id], so the very NEXT genuine
        // notification for that live re-homed session (its real
        // DISCONNECTED, or a CONNECTED) fails this handler's own "Verify
        // session" gate above as `unknown_session` — the live session can
        // never again be torn down by its own real events, a stale-
        // placement trap bounded only by the 90s lease TTL, plus an
        // unknown_session desync storm. So: proceed with all three, or skip
        // all three — never split them.
        //
        // `stored_home` is `nullopt` when the registry has no session
        // matching (agent_id, session_id) AT ALL (already gone via an
        // earlier disconnect, or this session_id belongs to a different
        // agent/was superseded) — that case has nothing for THIS fence to
        // protect and is already handled correctly and independently by the
        // legacy session_id guards below (clear_stream_if_session/
        // remove_agent_if_session/deregister's own session-scoped
        // predicate). Only a MATCHING session_id with a DIFFERING home id is
        // this fence's concern.
        if (auto stored_home = registry_.gateway_stream_home_id(agent_id, session_id);
            stored_home.has_value()) {
            // Mirrors gateway_route_store.cpp's deregister predicate
            // byte-for-byte (`stream_home_id IS NULL OR stream_home_id = $3`)
            // — never diverge the two: an EMPTY stored home ADMITS ANY
            // incoming value, stamped or not.
            //
            // PREDICATE FIX (PR #4492 review, HIGH): the prior form also
            // required `stream_home_id.empty()` on the incoming side for the
            // empty-stored branch to admit. A stored-empty home never
            // represents a live placement worth protecting — under the
            // single-producer invariant it means ONLY "this session's own
            // CONNECTED (which calls set_gateway_route) hasn't run yet" or
            // "legacy, never stamped." The gateway dispatches CONNECTED and
            // DISCONNECTED as two independently `spawn_monitor`'d RPC
            // workers with NO ordering guarantee between them, so an
            // ordinary (no re-home) DISCONNECTED can reach this handler
            // BEFORE its own paired CONNECTED — the old both-empty
            // requirement misclassified that stamped-but-legitimate
            // DISCONNECTED as `stale_home`, skipped all three teardown
            // effects, and let the delayed CONNECTED publish a route for an
            // already-dead stream (a regression vs. the pre-#4324 unfenced
            // behavior, where the same reordering self-corrected).
            const bool home_matches = stored_home->empty() || (*stored_home == stream_home_id);
            if (!home_matches) {
                record_directory_desync(metrics_, "deregister", "stale_home");
                response->set_acknowledged(true);
                return grpc::Status::OK;
            }
        }

        // `clear_stream_if_session` also clears the advertised-capability set
        // (agent_registry.cpp) — a session whose stream is gone has nothing
        // live to route a dispatch-tagged command through, so no separate
        // clear call is needed here.
        registry_.clear_stream_if_session(agent_id, session_id);
        const bool removed_current_session =
            registry_.remove_agent_if_session(agent_id, session_id);
        // HA WS-5 (ADR-2002 §7a): same session-guarded mirror as the direct
        // path (agent_service_impl.cpp) — keeps a gateway-fronted agent's
        // graceful disconnect from leaving a stale presence row matched by
        // scope evaluation until the TTL expires. Gated on
        // removed_current_session — see agent_service_impl.cpp's sibling
        // call for the full false-negative rationale (external review
        // finding, 2026-09-22): an unconditional delete here could remove a
        // LIVE agent's presence row on an ordinary same-replica reconnect.
        if (removed_current_session && heartbeat_ingestion_)
            if (auto* offline = heartbeat_ingestion_->offline_endpoint_store())
                offline->remove_if_session(agent_id, session_id);
        // HA WS-4 4.1: mirror the DISCONNECTED fact into the durable routing
        // directory too — session-guarded (gateway_route_store.hpp), so a
        // DIFFERENT, superseded session's DISCONNECTED can't tear down a newer
        // re-home. A SAME-session late DISCONNECTED is now ALSO fenced — see
        // the #4324 fence resolved at the top of this branch, above, which
        // covers this write (via the passed-through `stream_home_id`), the
        // legacy in-memory teardown just above, AND the session-map erase
        // below — CLOSED under today's shipped-gateway single-producer
        // invariant, was #4246 #4 / #4324 (see gateway_route_store.hpp's
        // "SCOPE OF CLOSED" note: the fence is check-then-act, not atomic
        // with these effects, which is safe only because no producer of a
        // genuinely concurrent same-session CONNECTED exists today — 4.3/4.4
        // must close that gap before live re-home ships). Task B (4.2b): fail-OPEN,
        // deliberately — a degraded tombstone write here leaves a stale row
        // behind, but that row is bounded by the 90s lease TTL regardless
        // (kGatewayRouteLeaseTtlSecs): once the lease expires, a future
        // routable-aware reader (`lookup_routes`' `routable` computation)
        // already treats it as not-routable without needing the tombstone,
        // and `reap_stale_routes` eventually cleans it up. Failing the
        // registry cleanup above over this would be a needless correctness
        // regression for no equivalent safety gain.
        if (gateway_route_store_) {
            if (auto res = gateway_route_store_->deregister(agent_id, session_id, stream_home_id);
                !res) {
                record_route_store_failure(metrics_, "deregister", res.error());
            } else if (!res->removed) {
                record_directory_desync(metrics_, "deregister", "session_mismatch");
            }
        }
        {
            std::lock_guard lock(sessions_mu_);
            gateway_sessions_.erase(session_id);
            lost_race_sessions_.erase(session_id);
        }
        spdlog::info("[gateway] Agent {} stream DISCONNECTED at gateway node '{}'", agent_id,
                     request->gateway_node());
        break;
    }

    default:
        spdlog::warn("[gateway] NotifyStreamStatus: unknown event {} for agent {}",
                     static_cast<int>(request->event()), agent_id);
        response->set_acknowledged(false);
        return grpc::Status::OK;
    }

    response->set_acknowledged(true);
    return grpc::Status::OK;
}

// -- ForwardGuardianMessage ---------------------------------------------------

grpc::Status
GatewayUpstreamServiceImpl::ForwardGuardianMessage(grpc::ServerContext* context,
                                                   const gw::ForwardGuardianRequest* request,
                                                   gw::ForwardGuardianAck* response) {
    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    const auto& agent_id = request->agent_id();

    // agent_id is gateway-asserted (the gateway stamps the agent's bound
    // Subscribe-stream identity, not a value from the frame). Do a cheap
    // diagnostic lookup, but LOG-AND-ACCEPT on a miss rather than reject: the
    // registry's gateway view is populated by best-effort NotifyStreamStatus
    // (dropped while the upstream circuit is open), so a strict "must be
    // registered" gate would silently lose real drift events during exactly
    // the reconnect storms Guardian most needs to report. Accept matches the
    // best-effort durability posture (durable buffering is Guardian A3). Debug
    // level so the happy path (agent always registered via ProxyRegister) does
    // not spam logs at fleet scale.
    if (!registry_.get_session(agent_id)) {
        spdlog::debug("[gateway] ForwardGuardianMessage: agent {} not in registry "
                      "(accepting anyway — best-effort)",
                      agent_id);
    }

    const auto& resp = request->response();
    if (resp.plugin() != "__guard__" || !resp.command_id().empty()) {
        // Defence-in-depth: the gateway only forwards UNSOLICITED "__guard__" events
        // (no command_id) here; a mislabelled frame, or a SOLICITED reply that should
        // have gone through normal command correlation (command_id set — H2 / #1209),
        // must not be ingested as a Guardian event. Drop it (still ack — we consumed
        // the RPC). A solicited reply reaching this path is a gateway routing bug.
        spdlog::warn("[gateway] ForwardGuardianMessage: not an unsolicited guardian event "
                     "(plugin='{}', command_id='{}') from agent {} — dropping",
                     resp.plugin(), resp.command_id(), agent_id);
        response->set_acknowledged(true);
        return grpc::Status::OK;
    }

    if (guaranteed_state_store_) {
        // Shared one-true-path ingest (same fn the direct Subscribe loop uses).
        ingest_guardian_response(*guaranteed_state_store_, agent_id, resp,
                                 blast_radius_detector_, dex_alert_router_, metrics_);
    } else {
        spdlog::warn("[gateway] ForwardGuardianMessage: no guaranteed-state store wired — "
                     "dropping event from agent {}",
                     agent_id);
    }

    response->set_acknowledged(true);
    return grpc::Status::OK;
}

// -- session_count ------------------------------------------------------------

std::size_t GatewayUpstreamServiceImpl::session_count() const {
    std::lock_guard lock(sessions_mu_);
    return gateway_sessions_.size();
}

} // namespace yuzu::server::detail
