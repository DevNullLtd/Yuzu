#include "agent_service_impl.hpp"

#include "ota_signature_sidecar.hpp"

#include "ota_audit_key.hpp"

#include "on_behalf_guard.hpp"
#include "ota_transfer_rules.hpp"

#include <algorithm>
#include <string_view>

#include <grpc/grpc_security_constants.h>

#include <chrono>
#include <ctime>

#include "analytics_event_store.hpp"
#include "audit_store.hpp"
#include "cidr_match.hpp"
#include "enrollment_token_rejection.hpp"
#include "execution_tracker.hpp"
#include "fleet_topology_store.hpp"
#include "grpc_audit_signal.hpp"
#include "grpc_on_behalf_enforce.hpp"
#include "guaranteed_state.pb.h"
#include "guaranteed_state_store.hpp"
#include "app_perf_daily_store.hpp"
#include "app_perf_ingestion.hpp"
#include "device_ci_ingestion.hpp"
#include "guardian_ingest.hpp"
#include "heartbeat_ingestion.hpp"
#include "offline_endpoint_store.hpp" // HA WS-5: remove_if_session on disconnect
#include "inventory_ingestion.hpp"
#include "inventory_store.hpp"
#include "software_inventory_store.hpp"
#include "software_licensing_ingestion.hpp"
#include "software_licensing_store.hpp"
#include "app_usage_ingestion.hpp"
#include "app_usage_store.hpp"
#include "management_group_store.hpp"
#include "notification_store.hpp"
#include "offload_target_store.hpp"
#include "peer_ip.hpp"
#include "response_store.hpp"
#include "result_parsing.hpp"
#include "tag_store.hpp"
#include "update_registry.hpp"
#include "web_utils.hpp"
#include "webhook_store.hpp"

// compare_versions is declared in nvd_db.hpp
#include "nvd_db.hpp"

namespace yuzu::server::detail {

// Bring html_escape into scope for the HTML rendering methods.
using yuzu::server::html_escape;


// -- Constructor --------------------------------------------------------------

AgentServiceImpl::AgentServiceImpl(AgentRegistry& registry, EventBus& bus,
                                   bool require_client_identity, auth::AuthManager& auth_mgr,
                                   auth::AutoApproveEngine& auto_approve,
                                   yuzu::MetricsRegistry& metrics, bool gateway_mode,
                                   UpdateRegistry* update_registry)
    : registry_(registry), bus_(bus), auth_mgr_(auth_mgr), auto_approve_(auto_approve),
      metrics_(metrics), require_client_identity_(require_client_identity),
      gateway_mode_(gateway_mode), update_registry_(update_registry) {
    // Build the OTA quota from the DEFAULT bounds so the DownloadUpdate path is
    // bounded even when no operator config is applied and in every test that
    // constructs this service directly. set_ota_bound_config() replaces it.
    set_ota_bound_config(ota_cfg_);
}

// -- Register -----------------------------------------------------------------

grpc::Status AgentServiceImpl::Register(grpc::ServerContext* context,
                                        const pb::RegisterRequest* request,
                                        pb::RegisterResponse* response) {
    metrics_.counter("yuzu_grpc_requests_total", {{"method", "Register"}, {"status", "received"}})
        .increment();

    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp. Must run
    // before any side effect below (audit, auth-mgr lookup, registry write).
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    const auto& info = request->info();

    // -- W1.4 R2 / UP-H1 agent_id length bound -------------------------------
    // Cap agent_id BEFORE any audit emission, mTLS check, or auth-mgr
    // lookup so a presenter with a 1 MiB agent_id can't inflate audit
    // rows, exhaust SQLite row budgets, or force SHA-256 work on a giant
    // string. The protobuf has no length constraint on agent_id and W1.4
    // PR1 audits the value verbatim — this is the gate. Empty agent_id
    // is also rejected: every downstream code path assumes a non-empty
    // string (registry keys, audit principal, pending_agents lookup).
    // INVALID_ARGUMENT chosen (not UNAUTHENTICATED) because the request
    // is structurally malformed, not credential-rejected. Counter has
    // a distinct metric name from token rejections so SRE alerts on
    // input-shape attacks don't bucket into credential-failure noise.
    if (info.agent_id().empty() || info.agent_id().size() > auth::kMaxAgentIdLength) {
        spdlog::warn("Register rejected: agent_id length {} (max {}, empty disallowed)",
                     info.agent_id().size(), auth::kMaxAgentIdLength);
        metrics_.counter("yuzu_register_invalid_agent_id_total", {{"reason", "length"}})
            .increment();
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "agent_id length exceeds 256 chars or empty");
    }

    // PR3: Register is bootstrap-exempt. A first-enrollment agent presents NO
    // client cert (it obtains one via this very call), so a no-cert Register is
    // permitted even when mTLS identity is required. But a PRESENTED cert (re-auth
    // after enrollment) MUST match the claimed agent_id and must not be revoked.
    if (require_client_identity_ && context) {
        const auto idents = extract_peer_identities(*context);
        if (!idents.empty()) {
            // Hermes CRITICAL-1: only treat a presented cert as a Yuzu agent
            // identity if it was issued by OUR CA. In a multi-CA trust bundle a
            // foreign cert (e.g. corporate-CA) carrying a spoofed CN=<agent_id>
            // would otherwise pass the CN match below and be trusted as
            // re-authentication. When a recognizer is wired (our CA is active) and
            // says the cert is not ours, fall through to bootstrap rather than
            // trusting it. When no recognizer is wired (operator-supplied single
            // trust root) every authenticated cert is an agent — legacy behaviour.
            const std::string peer_pem = extract_peer_cert_pem(*context);
            const bool treat_as_identity =
                !peer_cert_recognizer_ || peer_cert_recognizer_(peer_pem);
            if (treat_as_identity) {
                if (!peer_identity_matches_agent_id(*context, info.agent_id())) {
                    spdlog::warn("mTLS identity mismatch: claimed agent_id={}", info.agent_id());
                    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                                        "agent_id must match client certificate identity (CN/SAN)");
                }
                if (revocation_checker_ && !peer_pem.empty() && revocation_checker_(peer_pem)) {
                    spdlog::warn("Register rejected: revoked client cert for agent {}",
                                 info.agent_id());
                    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                                        "client certificate is revoked");
                }
            }
        }
    }

    // -- Tiered enrollment -------------------------------------------------------

    bool is_reauth = false; // Track whether this is a reconnection vs first enrollment

    // Fast path: agent already enrolled from a prior connection — skip enrollment
    {
        auto prior = auth_mgr_.get_pending_status(info.agent_id());
        if (prior && *prior == auth::PendingStatus::approved) {
            spdlog::info("Agent {} re-registering (already enrolled)", info.agent_id());
            is_reauth = true;
            goto enrolled;
        }
        // #1067: reject an admin-DENIED agent BEFORE consuming any enrollment
        // token. Previously the consume happened first and the admin-deny check
        // (ensure_enrolled) only fired afterward — so a denied attacker burned a
        // use of the token on every attempt, depleting a max_uses=1 token until
        // the legitimate agent could no longer enroll (token-depletion DoS,
        // W1.4 UP-M3). Checking the recorded denial here pre-empts the consume.
        //
        // Residual (gov #1134 UP-1/UP-2): `prior` is a snapshot read before the
        // consume, so an admin denial that races into the snapshot→consume
        // window still burns one use (the agent is then correctly blocked by the
        // ensure_enrolled defence-in-depth below). This kills the practical DoS
        // — a persistently-denied attacker no longer depletes tokens — but the
        // narrow race is closed only by option (b) refund-on-deny, tracked as a
        // follow-up.
        if (prior && *prior == auth::PendingStatus::denied) {
            // gov #1134 (Tr3kkR): this early short-circuit returns before the
            // legacy denied-handling code, which used to emit an
            // `agent.enrollment_denied` analytics signal — leaving only
            // spdlog. Replace it with the bounded, DoS-safe primitive: a
            // counter (NOT a per-attempt audit row, which a denied-flood
            // attacker could turn into a WAL write-amplification lever).
            // event=security routes it to the SIEM via Prometheus, the same
            // path as the stolen-session mismatch counters.
            metrics_
                .counter("yuzu_register_denied_total",
                         {{"source", "direct"}, {"event", "security"}})
                .increment();
            spdlog::warn("Register rejected: agent {} is admin-denied (no token consumed)",
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
            // -- W1.1 UP-H2 length bound (mirrored on the gateway path) --------
            // Reject oversize input before any SHA-256 / map walk work. The
            // bound matches kMaxEnrollmentTokenLength (256 chars — well
            // above the legitimate 64-hex-char token format). Length-based
            // rejections get their own variant in the typed error so SIEM
            // filters can distinguish "input garbage" from "valid token
            // shape, wrong/expired/race-lost".
            if (enrollment_token.size() > auth::kMaxEnrollmentTokenLength) {
                spdlog::warn("Agent {} presented oversize enrollment token ({} chars > {})",
                             info.agent_id(), enrollment_token.size(),
                             auth::kMaxEnrollmentTokenLength);
                metrics_
                    .counter("yuzu_enrollment_token_rejected_total",
                             {{"variant", "invalid_input_length"}})
                    .increment();
                if (auto analytics_store = analytics_store_.lock()) {
                    AnalyticsEvent ae;
                    ae.event_type = "agent.enrollment_denied";
                    ae.agent_id = info.agent_id();
                    ae.hostname = info.hostname();
                    ae.os = info.platform().os();
                    ae.arch = info.platform().arch();
                    ae.severity = Severity::kWarn;
                    ae.attributes = {{"reason", "invalid_input_length"},
                                     {"token_length", enrollment_token.size()}};
                    analytics_store->emit(std::move(ae));
                }
                response->set_accepted(false);
                response->set_reject_reason(
                    std::string(yuzu::server::kEnrollmentTokenRejectionPublicMessage));
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            }

            // -- W1.4 / #827 atomic consume ------------------------------------
            // The prior validate_enrollment_token returned a bare bool with a
            // race window between "valid?" and "++use_count". Replaced with
            // consume_enrollment_token which performs the check-and-increment
            // under one unique_lock and reports the typed outcome so we can
            // audit the lost-race case with attribution.
            auto claim_result =
                auth_mgr_.consume_enrollment_token(enrollment_token, info.agent_id());
            if (!claim_result.has_value()) {
                auto err = claim_result.error();
                auto variant = yuzu::server::enrollment_rejection_variant_name(err);
                auto metric_name = yuzu::server::enrollment_rejection_metric_name(err);
                spdlog::warn("Agent {} enrollment-token consume rejected: variant={}",
                             info.agent_id(), variant);
                // High-signal counter for race-lost; low-signal bucket for
                // everything else. enrollment_rejection_metric_name does
                // the variant→metric mapping in one place.
                if (err == auth::EnrollmentTokenError::already_consumed) {
                    metrics_.counter(std::string(metric_name), {}).increment();
                } else {
                    metrics_.counter(std::string(metric_name), {{"variant", std::string(variant)}})
                        .increment();
                }

                // For race-loss the audit detail names the winner so an
                // operator can reconstruct "agent X tried to enroll with a
                // token already consumed by agent Y". We look the winner
                // up via the token-hash (constant-time scan); empty result
                // means the token row was concurrently revoked/expired
                // between consume and the lookup — rare but possible.
                std::string already_consumed_by;
                if (err == auth::EnrollmentTokenError::already_consumed) {
                    auto hash = auth::AuthManager::sha256_hex(enrollment_token);
                    already_consumed_by = auth_mgr_.last_consumer_for_token_hash(hash);
                }

                // Audit row — W1.1 audit_log → bool pattern. The handler
                // observes the return so a dropped audit row surfaces via
                // the analytics-event Severity::kError escalation rather
                // than silently disappearing. SOC 2 CC7.2 evidence chain.
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
                    // No raw token in audit detail (it would let an
                    // attacker who later compromises audit storage replay
                    // the token). The hash prefix (8 hex chars = 32 bits
                    // identifying entropy) is enough to correlate with
                    // the create-token audit row.
                    auto hash_for_audit = auth::AuthManager::sha256_hex(enrollment_token);
                    ev.target_id = hash_for_audit.substr(0, 8);
                    std::string detail = std::string("variant=")
                                             .append(variant)
                                             .append(" presenter=")
                                             .append(info.agent_id());
                    if (!already_consumed_by.empty()) {
                        detail.append(" already_consumed_by=").append(already_consumed_by);
                    }
                    ev.detail = std::move(detail);
                    if (context)
                        ev.source_ip = extract_peer_ip(context->peer());
                    ev.result = "failure";
                    audit_ok = audit_store_->log(ev);
                }

                // #1063: surface a dropped audit row on the wire (mirror REST
                // Sec-Audit-Failed) so the operator sees the evidence-chain gap,
                // not just the analytics-severity escalation below.
                if (!audit_ok)
                    signal_grpc_audit_failed(context);

                if (auto analytics_store = analytics_store_.lock()) {
                    AnalyticsEvent ae;
                    ae.event_type = "agent.enrollment_denied";
                    ae.agent_id = info.agent_id();
                    ae.hostname = info.hostname();
                    ae.os = info.platform().os();
                    ae.arch = info.platform().arch();
                    // Race-loss is a credential-leak signal — escalate
                    // severity above the generic invalid-token noise so
                    // SIEM rules can fire on it independently. Dropped
                    // audit row is an evidence-chain degradation — also
                    // escalate to Error per W1.1 UP-H1.
                    if (err == auth::EnrollmentTokenError::already_consumed || !audit_ok) {
                        ae.severity = Severity::kError;
                    } else {
                        ae.severity = Severity::kWarn;
                    }
                    nlohmann::json attrs = {{"reason", std::string(variant)},
                                            {"audit_emitted", audit_ok}};
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

            // Success path. The token has been atomically claimed (use_count
            // already incremented under the lock).
            const auto& claim = claim_result.value();
            spdlog::info("Agent {} auto-enrolled via enrollment token id={} ({}/{})",
                         info.agent_id(), claim.token_id, claim.use_count_after,
                         claim.max_uses == 0 ? -1 : claim.max_uses);

            // Success audit row — same action/target as the failure path so
            // SIEM filters can pivot on result=success vs failure.
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
                ev.detail = std::string("variant=success use_count=")
                                .append(std::to_string(claim.use_count_after))
                                .append("/")
                                .append(claim.max_uses == 0 ? std::string{"unlimited"}
                                                            : std::to_string(claim.max_uses));
                if (context)
                    ev.source_ip = extract_peer_ip(context->peer());
                ev.result = "success";
                enroll_audit_ok = audit_store_->log(ev);
            }
            // #1065 / #1063: a dropped SUCCESS audit row is the same
            // evidence-chain degradation as a dropped failure row — was
            // fire-and-forget. Surface it on the wire and escalate analytics,
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
                    ae.attributes = {
                        {"result", "success"}, {"audit_emitted", false}, {"source", "direct"}};
                    analytics_store->emit(std::move(ae));
                }
            }

            // Persist enrollment so reconnections don't need a valid token.
            // Returns false if the agent was explicitly denied by an admin.
            if (!auth_mgr_.ensure_enrolled(info.agent_id(), info.hostname(), info.platform().os(),
                                           info.platform().arch(), info.agent_version())) {
                response->set_accepted(false);
                response->set_reject_reason("enrollment denied by administrator");
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            }
        } else {
            // Tier 1.5: Auto-approve policies -- check before pending queue
            auth::ApprovalContext approval_ctx;
            approval_ctx.hostname = info.hostname();
            approval_ctx.attestation_provider = request->attestation_provider();

            // gov #1117 (happy-path SHOULD): route through the canonical
            // extract_peer_ip so the auto-approve peer_ip is the same strict,
            // validated form as the #826 binding check. The old inline
            // scheme/port strip mishandled IPv6 (`[::1]` brackets) and could
            // yield a different string than the binding comparison used.
            if (context)
                approval_ctx.peer_ip = extract_peer_ip(context->peer());

            auto matched_rule = auto_approve_.evaluate(approval_ctx);
            if (!matched_rule.empty()) {
                spdlog::info("Agent {} auto-approved by policy: {}", info.agent_id(), matched_rule);
                // Persist enrollment so reconnections skip enrollment entirely.
                // Returns false if admin-denied — admin denials outrank auto-approve.
                if (!auth_mgr_.ensure_enrolled(info.agent_id(), info.hostname(),
                                               info.platform().os(), info.platform().arch(),
                                               info.agent_version())) {
                    response->set_accepted(false);
                    response->set_reject_reason("enrollment denied by administrator");
                    response->set_enrollment_status("denied");
                    return grpc::Status::OK;
                }
                // Fall through to normal registration
            } else {
                // Tier 1: No token, no policy match -- check the pending queue
                auto pending_status = auth_mgr_.get_pending_status(info.agent_id());

                if (!pending_status) {
                    // First time seeing this agent -- add to pending queue
                    auth_mgr_.add_pending_agent(info.agent_id(), info.hostname(),
                                                info.platform().os(), info.platform().arch(),
                                                info.agent_version());

                    response->set_accepted(false);
                    response->set_reject_reason("awaiting admin approval");
                    response->set_enrollment_status("pending");
                    bus_.publish("pending-agent", info.agent_id());
                    spdlog::info("Agent {} placed in pending approval queue", info.agent_id());
                    if (auto analytics_store = analytics_store_.lock()) {
                        AnalyticsEvent ae;
                        ae.event_type = "agent.enrollment_pending";
                        ae.agent_id = info.agent_id();
                        ae.hostname = info.hostname();
                        ae.os = info.platform().os();
                        ae.arch = info.platform().arch();
                        analytics_store->emit(std::move(ae));
                    }
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
                    if (auto analytics_store = analytics_store_.lock()) {
                        AnalyticsEvent ae;
                        ae.event_type = "agent.enrollment_denied";
                        ae.agent_id = info.agent_id();
                        ae.hostname = info.hostname();
                        ae.os = info.platform().os();
                        ae.arch = info.platform().arch();
                        ae.severity = Severity::kWarn;
                        ae.attributes = {{"reason", "admin_denied"}};
                        analytics_store->emit(std::move(ae));
                    }
                    return grpc::Status::OK;

                case auth::PendingStatus::approved:
                    spdlog::info("Agent {} enrolled (admin-approved)", info.agent_id());
                    // Fall through to normal registration
                    break;
                }
            } // auto-approve else
        }
    } // end enrollment checks

enrolled:
    // -- Agent is enrolled -- proceed with registration --------------------------

    // #3401 Gap 2: register_agent fails closed if the W1.5/#823 device-token revoke sweep
    // itself errors — refuse the registration rather than install a session the sweep could
    // not clear stale tokens for. UNAVAILABLE (not accepted=false / reject_reason, which the
    // agent treats as a PERMANENT rejection, agent.cpp:1649-1657) so the agent retries with its
    // normal reconnect backoff. The PG failure detail stays server-side (spdlog only).
    if (auto reg_result = registry_.register_agent(info); !reg_result) {
        spdlog::error("Register: register_agent failed for '{}': {}", info.agent_id(),
                      reg_result.error());
        return grpc::Status(grpc::StatusCode::UNAVAILABLE,
                            "registration temporarily unavailable");
    }
    // Auto-add to root management group
    if (mgmt_group_store_ && mgmt_group_store_->is_open())
        mgmt_group_store_->add_member(ManagementGroupStore::kRootGroupId, info.agent_id());

    // UAT 2026-05-12: invalidate any cached topology snapshot so the
    // next /api/v1/viz/fleet/topology refill dispatches to the new
    // agent and the renderer doesn't show this cube as stale (`ts=0,
    // procs=[]`) for up to the 60 s TTL window.
    if (fleet_topology_store_)
        fleet_topology_store_->invalidate();

    if (auto analytics_store = analytics_store_.lock()) {
        AnalyticsEvent ae;
        ae.event_type = "agent.registered";
        ae.agent_id = info.agent_id();
        ae.hostname = info.hostname();
        ae.os = info.platform().os();
        ae.arch = info.platform().arch();
        ae.agent_version = info.agent_version();
        ae.attributes = {
            {"enrollment_method", request->enrollment_token().empty() ? "approval" : "token"},
            {"enrollment_type", is_reauth ? "reauth" : "initial"}};
        nlohmann::json plugins_list = nlohmann::json::array();
        for (const auto& p : info.plugins()) {
            plugins_list.push_back(p.name());
        }
        ae.payload = {{"plugins", plugins_list}};
        analytics_store->emit(std::move(ae));
    }

    // Create notification for FIRST enrollment only (#3261 governance
    // hardening, Gate 4 happy-path + unhappy-path UP-3). Unconditional on
    // is_reauth would fire "Agent Enrolled" on every gRPC reconnect - a
    // server restart with N connected agents floods the (unreaper'd,
    // docs/enterprise-readiness-soc2-first-customer.md:316) notification
    // feed with N rows for zero new enrollments. This is deliberately
    // narrower than the webhook/offload suppression below: `agent.registered`
    // firing on reauth IS the documented contract
    // (docs/user-manual/rest-api.md's webhook/offload sections say "enrolls
    // or re-enrolls"), so only the dashboard-toast side is gated here.
    if (!is_reauth && notification_store_ && notification_store_->is_open()) {
        notification_store_->create("success", "Agent Enrolled",
                                    "Agent " + info.agent_id() + " (" + info.hostname() +
                                        ") enrolled successfully");
    }

    // Fire webhook + offload for agent enrollment (documented to fire on
    // both first enrollment AND re-enrollment - see the comment above).
    //
    // Both sinks receive the same serialised body; we build the JSON +
    // dump it ONCE (perf-S1) outside either guard so that one sink being
    // disabled does not silently disable the other (HP-1 / UP-6
    // regression caught at Gate 4).
    if ((webhook_store_ && webhook_store_->is_open()) ||
        (offload_target_store_ && offload_target_store_->is_open())) {
        nlohmann::json payload = {
            {"event", "agent.registered"},    {"agent_id", info.agent_id()},
            {"hostname", info.hostname()},    {"os", info.platform().os()},
            {"arch", info.platform().arch()}, {"agent_version", info.agent_version()}};
        const auto body = payload.dump();
        if (webhook_store_ && webhook_store_->is_open()) {
            webhook_store_->fire_event("agent.registered", body);
        }
        if (offload_target_store_ && offload_target_store_->is_open()) {
            offload_target_store_->fire_event("agent.registered", body);
        }
    }

    // Sync agent-reported tags to persistent TagStore. A failed sync cannot
    // fail the Register RPC (enrollment must not hinge on a tag write), but
    // it is surfaced rather than swallowed — the sync rolled back
    // atomically, so the agent keeps its PRIOR complete tag set and
    // re-syncs on its next Register. Observability is this warn line ONLY:
    // write-path failures have no counter (yuzu_server_tag_store_read_
    // degrade_total is reads-only — governance sec-L1/sre-2; a wave-level
    // write-degrade-metric decision is tracked as follow-up, deliberately
    // not a one-store one-off here).
    if (tag_store_ && !info.scopable_tags().empty()) {
        std::unordered_map<std::string, std::string> tags;
        for (const auto& [k, v] : info.scopable_tags()) {
            tags[k] = v;
        }
        if (auto sync = tag_store_->sync_agent_tags(info.agent_id(), tags); !sync) {
            spdlog::warn("Register({}): tag sync failed ({}) — prior tag set retained, agent "
                         "re-syncs on next Register",
                         info.agent_id(), sync.error());
        }
    }

    auto session_id =
        "session-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(16));
    response->set_session_id(session_id);
    response->set_accepted(true);
    response->set_enrollment_status("enrolled");

    // PR3: if the agent sent a CSR and a signer is wired (the CA is active), sign
    // a per-agent client leaf bound to agent_id and return it; the agent persists
    // it and reconnects with mutual TLS. Signing failure is non-fatal — the agent
    // stays on the bootstrap (request-but-don't-require) posture and can retry.
    if (!request->csr_pem().empty() && agent_cert_signer_) {
        // #1273 B-2: contain any exception out of the signer — it runs in this sync
        // handler; a throw would terminate the server. Degrade to no-cert (the
        // agent stays on the bootstrap posture), same as a nullopt return. Mirrors
        // the gateway ProxyRegister path so both issuance sites are crash-safe.
        std::optional<std::pair<std::string, std::string>> issued;
        try {
            issued = agent_cert_signer_(request->csr_pem(), info.agent_id(),
                                        CertIssuanceSource::Direct);
        } catch (const std::exception& e) {
            spdlog::error("Register: signer threw for agent {}: {}", info.agent_id(), e.what());
        } catch (...) {
            spdlog::error("Register: signer threw a non-std exception for agent {}",
                          info.agent_id());
        }
        if (issued) {
            response->set_issued_certificate(issued->first);
            response->set_issued_ca_chain(issued->second);
            spdlog::info("Issued per-agent client cert for {}", info.agent_id());
        } else {
            spdlog::warn("Register: client-cert signing failed for agent {}", info.agent_id());
        }
    }

    PendingRegistration pending;
    pending.agent_id = info.agent_id();
    pending.register_peer = context ? context->peer() : std::string{};
    pending.peer_identities =
        context ? extract_peer_identities(*context) : std::vector<std::string>{};
    pending.created_at = std::chrono::steady_clock::now();
    {
        std::lock_guard lock(pending_mu_);
        prune_expired_pending_locked();
        pending_by_session_id_[session_id] = std::move(pending);
    }

    return grpc::Status::OK;
}

// -- Heartbeat ----------------------------------------------------------------

grpc::Status AgentServiceImpl::Heartbeat(grpc::ServerContext* context,
                                         const pb::HeartbeatRequest* request,
                                         pb::HeartbeatResponse* response) {
    metrics_.counter("yuzu_grpc_requests_total", {{"method", "Heartbeat"}, {"status", "received"}})
        .increment();

    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    // PR3: lock a revoked agent out of liveness too — otherwise a revoked cert,
    // rejected at Subscribe, could keep heart-beating and mask the revocation by
    // staying "online" in the fleet view.
    if (auto s = reject_revoked_peer(context, "heartbeat"); !s.ok())
        return s;

    // Validate session
    const auto& session_id = request->session_id();
    std::string agent_id;
    {
        std::lock_guard lock(pending_mu_);
        auto it = pending_by_session_id_.find(std::string(session_id));
        if (it != pending_by_session_id_.end()) {
            agent_id = it->second.agent_id;
        }
    }
    if (agent_id.empty()) {
        // Try the registry directly
        auto session = registry_.find_by_session(session_id);
        if (session) {
            agent_id = session->agent_id;
        }
    }

    if (agent_id.empty()) {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "unknown session");
    }

    // #1000 / arch-S2: per-heartbeat work (health upsert, metrics,
    // fleet_snapshot push) lives in HeartbeatIngestion so the direct and
    // gateway-batch paths cannot drift. `touch_activity` is direct-only
    // — gateway-routed agents have their activity timestamp refreshed
    // through ProxyRegister + the gateway's own bookkeeping.
    registry_.touch_activity(agent_id);
    if (heartbeat_ingestion_) {
        // Gate 7 UP-10 — isolate ingest failures. An exception here would
        // otherwise fail the whole Heartbeat RPC; the agent would retry,
        // but a deterministically-bad payload would wedge the agent in a
        // heartbeat-retry loop. Swallow + log so the heartbeat still acks
        // (the snapshot push is best-effort; health/metrics already ran).
        try {
            heartbeat_ingestion_->ingest(*request, agent_id, "direct");
        } catch (const std::exception& ex) {
            spdlog::warn("Heartbeat: ingest threw for agent {} — heartbeat still acked: {}",
                         agent_id, ex.what());
        } catch (...) {
            spdlog::warn("Heartbeat: ingest threw unknown exception for agent {} — "
                         "heartbeat still acked",
                         agent_id);
        }
    }

    response->set_acknowledged(true);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
    response->mutable_server_time()->set_millis_epoch(now_ms);

    spdlog::debug("Heartbeat from agent={} (session={})", agent_id, session_id);
    return grpc::Status::OK;
}

// -- ReportInventory ----------------------------------------------------------

grpc::Status AgentServiceImpl::ReportInventory(grpc::ServerContext* context,
                                               const pb::InventoryReport* request,
                                               pb::InventoryAck* response) {
    metrics_
        .counter("yuzu_grpc_requests_total",
                 {{"method", "ReportInventory"}, {"status", "received"}})
        .increment();

    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    if (auto s = reject_revoked_peer(context, "report_inventory"); !s.ok())
        return s;

    // Validate session → resolve agent_id (mirrors Heartbeat).
    const auto& session_id = request->session_id();
    std::string agent_id;
    {
        std::lock_guard lock(pending_mu_);
        auto it = pending_by_session_id_.find(std::string(session_id));
        if (it != pending_by_session_id_.end())
            agent_id = it->second.agent_id;
    }
    if (agent_id.empty()) {
        auto session = registry_.find_by_session(session_id);
        if (session)
            agent_id = session->agent_id;
    }
    if (agent_id.empty()) {
        response->set_received(false);
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "unknown session");
    }

    response->set_received(true);

    // Reject abusive source-map cardinality before any typed store sees the
    // report. The empty ack deliberately avoids a resend-amplification loop.
    if (!validate_inventory_report_source_count(agent_id, *request, &metrics_))
        return grpc::Status::OK;

    // Each typed source ingests through its own shared seam (ADR-0016 §5) — the SAME
    // seam the gateway ProxyInventory path uses — independently guarded + isolated, so
    // one store being down or one payload being bad can't fail the RPC into a retry
    // loop. ack=received is already set, so a skipped ingest just defers to the next
    // sync + the weekly full-floor.
    //
    // INTENTIONAL ASYMMETRY (gov architect A-1 / consistency S1): neither direct path
    // upserts *generic* (non-typed) plugin_data keys into the generic InventoryStore.
    // The live sources (installed_software, app_perf, device_ci, software_licensing)
    // are TYPED and routed through their typed seams on both paths, so the two paths
    // stay symmetric;
    // a future GENERIC source must fold its upsert into ingest_inventory_report (pass the
    // InventoryStore&), not add a parallel loop here.
    if (software_inventory_store_ && software_inventory_store_->is_open()) {
        try {
            ingest_inventory_report(*software_inventory_store_, agent_id, *request, *response,
                                    &metrics_);
        } catch (const std::exception& ex) {
            spdlog::warn("ReportInventory: inventory ingest threw for agent {} — acked: {}",
                         agent_id, ex.what());
        } catch (...) {
            spdlog::warn("ReportInventory: inventory ingest threw unknown exception for agent {} "
                         "— acked",
                         agent_id);
        }
    }
    if (app_perf_daily_store_ && app_perf_daily_store_->is_open()) {
        try {
            ingest_app_perf_report(*app_perf_daily_store_, agent_id, *request, *response, &metrics_);
        } catch (const std::exception& ex) {
            spdlog::warn("ReportInventory: app_perf ingest threw for agent {} — acked: {}", agent_id,
                         ex.what());
        } catch (...) {
            spdlog::warn("ReportInventory: app_perf ingest threw unknown exception for agent {} — "
                         "acked",
                         agent_id);
        }
    }
    if (device_inventory_store_ && device_inventory_store_->is_open()) {
        try {
            ingest_device_ci_report(*device_inventory_store_, agent_id, *request, *response,
                                    &metrics_);
        } catch (const std::exception& ex) {
            spdlog::warn("ReportInventory: device_ci ingest threw for agent {} — acked: {}",
                         agent_id, ex.what());
        } catch (...) {
            spdlog::warn("ReportInventory: device_ci ingest threw unknown exception for agent {} — "
                         "acked",
                         agent_id);
        }
    }
    if (software_licensing_store_ && software_licensing_store_->is_open()) {
        try {
            ingest_software_licensing_report(*software_licensing_store_, agent_id, *request,
                                             *response, &metrics_);
        } catch (const std::exception& ex) {
            spdlog::warn("ReportInventory: software_licensing ingest threw for agent {} — "
                         "acked: {}",
                         agent_id, ex.what());
        } catch (...) {
            spdlog::warn("ReportInventory: software_licensing ingest threw unknown exception for "
                         "agent {} — acked",
                         agent_id);
        }
    }
    if (app_usage_store_ && app_usage_store_->is_open()) {
        try {
            ingest_app_usage_report(*app_usage_store_, agent_id, *request, *response, &metrics_);
        } catch (const std::exception& ex) {
            // P11: unlike the sibling blocks above, a swallowed throw here with no
            // nack lets the agent's SyncScheduler advance last_hash and go
            // hash-only for a day with nothing persisted — the nack forces a full
            // resend next cycle. Follow-up issue filed at delivery to retrofit the
            // four sibling blocks (installed_software/app_perf/device_ci/
            // software_licensing) with the same nack; do not do it here.
            response->add_need_full("app_usage");
            spdlog::warn("ReportInventory: app_usage ingest threw for agent {} — nacked: {}",
                         agent_id, ex.what());
        } catch (...) {
            response->add_need_full("app_usage");
            spdlog::warn("ReportInventory: app_usage ingest threw unknown exception for agent {} "
                         "— nacked",
                         agent_id);
        }
    }
    spdlog::debug("ReportInventory from agent={} (session={})", agent_id, session_id);
    return grpc::Status::OK;
}

// -- Subscribe ----------------------------------------------------------------

grpc::Status AgentServiceImpl::Subscribe(
    grpc::ServerContext* context,
    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) {
    if (!context) {
        return grpc::Status(grpc::StatusCode::INTERNAL, "missing server context");
    }

    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp. This is the
    // "command-result handler" the execution plan's PR 1.1 rationale names:
    // the agent posts CommandResponse results over this bidi stream, so a
    // reserved header at stream-open must stop it before any registry work.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    const auto session_id = client_metadata_value(*context, kSessionMetadataKey);
    if (session_id.empty()) {
        spdlog::warn("Subscribe rejected: missing {} metadata", kSessionMetadataKey);
        return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, "missing session metadata");
    }

    // PR3: revoked-cert gate. The presented client leaf IS the agent's mTLS
    // identity (issued bound to agent_id at enrollment). If its serial is on the
    // CRL the whole data plane is closed to it — reject before any registry work.
    // Independent of pending_mu_: reads only the gRPC auth context + ca_store, so it
    // runs BEFORE the plane lock is taken (no cross-store query under the lock,
    // gov #1117). No-op when no cert is presented or no checker is wired.
    if (revocation_checker_) {
        const std::string peer_pem = extract_peer_cert_pem(*context);
        if (!peer_pem.empty() && revocation_checker_(peer_pem)) {
            metrics_
                .counter("yuzu_grpc_revoked_cert_total",
                         {{"event", "security"}, {"rpc", "subscribe"}})
                .increment();
            const auto ids = extract_peer_identities(*context);
            const std::string cert_id = ids.empty() ? std::string{} : ids.front();
            spdlog::warn("Subscribe rejected: revoked client cert (session={}, cert_id={})",
                         session_id, cert_id);
            if (audit_store_ && audit_store_->is_open()) {
                AuditEvent ev;
                ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                ev.principal = "agent:" + cert_id;
                ev.principal_role = "agent";
                ev.action = "session.cert_revoked";
                ev.target_type = "Session";
                ev.target_id = session_id;
                ev.detail = "reason=revoked_client_cert cert_id=" + cert_id;
                ev.source_ip = extract_peer_ip(context->peer());
                ev.session_id = session_id;
                ev.result = "denied";
                if (!audit_store_->log(ev))
                    signal_grpc_audit_failed(context);
            }
            return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                                "client certificate is revoked");
        }
    }

    std::string agent_id;
    // #1128: when a peer-IP mismatch is DOWNGRADED to advisory (NAT-aware
    // relaxation below), the forensic audit row must be emitted OUT of the
    // pending_mu_ critical section (same DoS rule as the reject path — a
    // lock-held WAL write serializes the plane under flood, gov #1117). Capture
    // the row's inputs while locked; emit after the lock block closes.
    bool nat_advisory_emit = false;
    std::string advisory_reason;
    std::string advisory_agent_id;
    std::string advisory_register_ip;
    std::string advisory_subscribe_ip;
    {
        std::unique_lock lock(pending_mu_);
        prune_expired_pending_locked();
        auto it = pending_by_session_id_.find(session_id);
        if (it == pending_by_session_id_.end()) {
            spdlog::warn("Subscribe rejected: unknown or expired session id");
            return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                                "invalid or expired session");
        }

        // #826 — peer-mismatch enforcement. The old code skipped this
        // check ENTIRELY when `gateway_mode_` was set, on the theory
        // that gateway-proxied agents present the gateway's IP rather
        // than their own. That justified relaxing the per-IP check but
        // NOT skipping all peer validation: an attacker on the gateway
        // network segment could intercept a Register response, read
        // the session_id (plaintext in non-mTLS deployments), then
        // open Subscribe from an arbitrary IP with the stolen session
        // and the server would accept it.
        //
        // The correct rule is:
        //   (a) Always allow Subscribe peer IP == Register peer IP
        //       (same agent, possibly different ephemeral port).
        //   (b) IF gateway-mode, also allow Subscribe peer IP to be a
        //       previously-recorded trusted gateway IP. Trusted gateway
        //       IPs are noted at GatewayUpstreamServiceImpl::ProxyRegister
        //       time — the gateway's own peer becomes known-good for
        //       the lifetime of the process.
        //   (c) Reject anything else.
        //
        // Per-port matching is too tight (gRPC opens separate
        // connections for Register vs Subscribe in some clients) and
        // unconditional skip is too loose (#826). Per-IP with a
        // trusted-gateway whitelist is the middle ground.
        const auto subscribe_peer_ip = extract_peer_ip(context->peer());
        const auto register_peer_ip = extract_peer_ip(it->second.register_peer);
        bool peer_ok = !subscribe_peer_ip.empty() && subscribe_peer_ip == register_peer_ip;
        if (!peer_ok && gateway_mode_) {
            peer_ok = registry_.is_trusted_gateway_peer(subscribe_peer_ip);
        }

        // #1128 — NAT-aware relaxation. The exact-IP binding above false-rejects
        // a LEGITIMATE direct-connect agent whose Register and Subscribe egress
        // different public IPs (multi-egress NAT, proxy pool, CG-NAT, SD-WAN).
        // Strict exact-match stays the DEFAULT — with no relaxation configured
        // this block is inert and behaviour is unchanged. Two opt-in
        // accommodations DOWNGRADE a mismatch to advisory (audit + metric, no
        // reject):
        //   (a) mTLS-advisory: a verified client identity that matches the one
        //       bound at Register is a STRONGER identity than source IP — the
        //       #827 agent_id↔session and #1118 mTLS-identity bindings are the
        //       authoritative layers, so the IP becomes defence-in-depth only.
        //   (b) trusted-NAT-CIDR: both IPs fall inside one operator-declared
        //       multi-egress range (analogous to --gateway-mode, but scoped to
        //       direct-connect NAT rather than a trusted gateway).
        // A mismatch OUTSIDE these accommodations is still a hard reject — the
        // stolen-session replay guard (#826) is intact. The decision itself is a
        // pure, unit-tested helper (evaluate_peer_binding); this site computes
        // its inputs, then records the advisory signal. mTLS-advisory does NOT
        // bypass the independent mTLS identity gate below (#1118) — it only
        // relaxes the IP comparison.
        if (!peer_ok) {
            bool identity_matches = false;
            // gov UP-2: the mTLS-identity accommodation is OPT-IN
            // (nat_trust_mtls_identity_). Default off — a shared/fleet-wide
            // client cert would otherwise make every identity "match" and turn
            // this into a session-replay bypass. Only compute the overlap when
            // the operator has affirmed per-agent certs.
            if (nat_trust_mtls_identity_ && require_client_identity_) {
                const auto sub_ids = extract_peer_identities(*context);
                identity_matches = has_identity_overlap(it->second.peer_identities, sub_ids);
            }
            switch (evaluate_peer_binding(/*exact_ok=*/false, register_peer_ip, subscribe_peer_ip,
                                          identity_matches, trusted_nat_cidrs_)) {
            case PeerBindingOutcome::advisory_mtls:
                advisory_reason = "mtls_identity_match";
                break;
            case PeerBindingOutcome::advisory_nat_cidr:
                advisory_reason = "trusted_nat_cidr";
                break;
            case PeerBindingOutcome::exact_ok:  // unreachable (exact_ok=false above)
            case PeerBindingOutcome::reject:
                break; // advisory_reason stays empty → falls through to reject
            }

            if (!advisory_reason.empty()) {
                // Tolerated multi-egress. The metric increments under the lock
                // (matches the reject path — an in-memory counter is not the WAL
                // write the lock rule targets); the audit row is deferred to
                // out-of-lock emission after the critical section.
                //
                // gateway_mode label mirrors the _peer_mismatch_total reject
                // counter for SIEM correlation parity — a `reason` label alone
                // would not let an analyst slice advisory vs reject volume by
                // the same operator-mode dimension across both counters.
                metrics_
                    .counter("yuzu_grpc_subscribe_peer_advisory_total",
                             {{"event", "security"},
                              {"reason", advisory_reason},
                              {"gateway_mode", gateway_mode_ ? "true" : "false"}})
                    .increment();
                spdlog::info("Subscribe peer mismatch tolerated ({}) for session {} "
                             "(register_ip={}, subscribe_ip={})",
                             advisory_reason, session_id, register_peer_ip, subscribe_peer_ip);
                nat_advisory_emit = true;
                advisory_agent_id = it->second.agent_id;
                advisory_register_ip = register_peer_ip;
                advisory_subscribe_ip = subscribe_peer_ip;
                peer_ok = true;
            }
        }

        if (!peer_ok) {
            // event=security is the SIEM-routing tag: we don't write to SIEM
            // directly — we emit via Prometheus and let Splunk et al. (which
            // have a Prometheus receiver) filter on event="security". Stolen-
            // session signal (#1059).
            metrics_
                .counter("yuzu_grpc_subscribe_peer_mismatch_total",
                         {{"event", "security"},
                          {"gateway_mode", gateway_mode_ ? "true" : "false"}})
                .increment();
            spdlog::warn("Subscribe rejected: peer mismatch for session {} (register_ip={}, "
                         "subscribe_ip={}, gateway_mode={})",
                         session_id, register_peer_ip, subscribe_peer_ip,
                         gateway_mode_ ? "true" : "false");
            // #1059: a peer-mismatch rejection is a stolen-session signal —
            // emit an audit row (spdlog is not the audit log). Copy the
            // registry entry's agent_id, then RELEASE pending_mu_ BEFORE the
            // audit write: AuditStore::log holds its own mutex and runs a WAL
            // INSERT (busy_timeout=5s), and pending_mu_ is the global
            // Register/Subscribe/Heartbeat lock — holding it across the write
            // under a peer-mismatch flood would serialize the whole plane
            // (gov #1117 perf / UP-1). `it` is invalidated by the unlock, so
            // agent_id MUST be copied first (gov UP-2). SOC 2 CC7.2.
            const std::string mismatch_agent_id = it->second.agent_id;
            const std::string raw_peer{context->peer()};
            lock.unlock();
            if (audit_store_ && audit_store_->is_open()) {
                AuditEvent ev;
                ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                ev.principal = "agent:" + mismatch_agent_id;
                ev.principal_role = "agent";
                // Action domain + target shape follow the session.* convention
                // (gov #1117 architect/consistency): the target IS the session,
                // and target_type is PascalCase to match auth.login's `Session`
                // so SIEM filters on target_type=="Session" catch this row.
                ev.action = "session.peer_mismatch";
                ev.target_type = "Session";
                ev.target_id = session_id;
                std::string detail = std::string("agent_id=")
                                         .append(mismatch_agent_id)
                                         .append(" register_ip=")
                                         .append(register_peer_ip)
                                         .append(" subscribe_ip=")
                                         .append(subscribe_peer_ip)
                                         .append(" gateway_mode=")
                                         .append(gateway_mode_ ? "true" : "false");
                // UP-4: strict extract_peer_ip returns empty for a malformed
                // peer — preserve the raw gRPC peer string so the forensic row
                // isn't blind to the attacker's address.
                if (subscribe_peer_ip.empty())
                    detail.append(" raw_peer=").append(raw_peer);
                ev.detail = std::move(detail);
                ev.source_ip = subscribe_peer_ip;
                ev.session_id = session_id;
                ev.result = "denied";
                if (!audit_store_->log(ev))
                    signal_grpc_audit_failed(context);
            }
            return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "peer mismatch");
        }

        // PR3 gov (enterprise-readiness BLOCKING): GRADUAL identity enforcement.
        // Enforce the #1118 overlap only when this session actually bound a client
        // identity at Register (peer_identities non-empty). A session that
        // registered WITHOUT a client cert — a not-yet-provisioned or a legacy
        // pre-PR3 agent — has no cryptographic identity to match, and is left on
        // the pre-PR3 posture (session + #826 peer-IP binding) rather than being
        // hard-rejected. This makes per-agent mTLS a non-breaking, gradual rollout:
        // a provisioned agent (bound non-empty) MUST present its leaf (strict — a
        // no-cert Subscribe yields has_identity_overlap(non-empty, {})==false →
        // reject, so the stolen-session guard holds), while an unprovisioned agent
        // keeps working. A future --require-agent-identity flag can harden this to
        // require a bound identity for ALL agents once a fleet is fully enrolled.
        if (require_client_identity_ && !it->second.peer_identities.empty()) {
            const auto subscribe_ids = extract_peer_identities(*context);
            if (!has_identity_overlap(it->second.peer_identities, subscribe_ids)) {
                // event=security is the SIEM-routing tag (see
                // observability-conventions.md); Splunk et al. filter on it.
                metrics_
                    .counter("yuzu_grpc_subscribe_identity_mismatch_total",
                             {{"event", "security"}})
                    .increment();
                spdlog::warn("Subscribe rejected: mTLS identity mismatch for session {}",
                             session_id);
                // #1118: mTLS identity mismatch is a stolen-session signal — the
                // session_id was presented with a client cert that doesn't match
                // the one bound at Register. Audit it, mirroring #1059's
                // peer-mismatch row. Copy agent_id, release pending_mu_ BEFORE the
                // audit write (gov #1117 / UP-1 — no lock-held WAL write), emit
                // out of the lock. SOC 2 CC7.2.
                const std::string mismatch_agent_id = it->second.agent_id;
                // Capture cert identities before unlock for the forensic detail
                // (gov #1134 sre SHOULD): record what was presented at Subscribe
                // vs what was bound at Register, so an auditor can identify the
                // cert used in the attempt. `it` is invalidated by the unlock.
                const auto join_ids = [](const std::vector<std::string>& v) {
                    std::string s;
                    for (const auto& id : v) {
                        if (!s.empty())
                            s += ",";
                        s += id;
                    }
                    return s;
                };
                const std::string presented = join_ids(subscribe_ids);
                const std::string bound = join_ids(it->second.peer_identities);
                lock.unlock();
                if (audit_store_ && audit_store_->is_open()) {
                    AuditEvent ev;
                    ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();
                    ev.principal = "agent:" + mismatch_agent_id;
                    ev.principal_role = "agent";
                    ev.action = "session.identity_mismatch";
                    ev.target_type = "Session";
                    ev.target_id = session_id;
                    ev.detail = "agent_id=" + mismatch_agent_id +
                                " reason=mtls_identity_mismatch presented=[" + presented +
                                "] bound=[" + bound + "]";
                    ev.source_ip = extract_peer_ip(context->peer());
                    ev.session_id = session_id;
                    ev.result = "denied";
                    if (!audit_store_->log(ev))
                        signal_grpc_audit_failed(context);
                }
                return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "peer identity mismatch");
            }
        }

        agent_id = it->second.agent_id;
        pending_by_session_id_.erase(it);
    }

    // #1128: a tolerated (advisory) peer-IP mismatch is still a security-
    // relevant event — pair the advisory metric (real-time signal) with an
    // audit row (forensic evidence: which IPs, which accommodation). Emitted
    // OUT of pending_mu_ (the lock is released above) so the WAL write can't
    // serialize the plane under a multi-egress reconnect storm. result="ok"
    // (the stream WAS established) + outcome=advisory distinguishes it from the
    // result="denied" reject row that shares the session.peer_mismatch action.
    // SOC 2 CC7.2.
    if (nat_advisory_emit && audit_store_ && audit_store_->is_open()) {
        AuditEvent ev;
        ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
        ev.principal = "agent:" + advisory_agent_id;
        ev.principal_role = "agent";
        ev.action = "session.peer_mismatch";
        ev.target_type = "Session";
        ev.target_id = session_id;
        // gateway_mode field mirrors the reject-row detail (line 760) for SIEM
        // parity. Structurally always false here: gateway-mode connections take
        // the is_trusted_gateway_peer branch above and set peer_ok=true before
        // the advisory block is entered, so an advisory row is by construction
        // a direct-connect event. Keeping the field explicit lets a SIEM rule
        // join advisory and reject rows on the same operator-mode dimension.
        ev.detail = "agent_id=" + advisory_agent_id + " outcome=advisory reason=" + advisory_reason +
                    " register_ip=" + advisory_register_ip +
                    " subscribe_ip=" + advisory_subscribe_ip +
                    " gateway_mode=" + (gateway_mode_ ? "true" : "false");
        ev.source_ip = advisory_subscribe_ip;
        ev.session_id = session_id;
        ev.result = "ok";
        if (!audit_store_->log(ev))
            signal_grpc_audit_failed(context);
    }

    spdlog::info("Agent subscribe stream opened for {}", agent_id);
    // PR3 H-1: stash the presented client leaf so the background revocation sweep
    // can tear this long-lived stream down if the cert is later revoked (the gate
    // above only runs once, at establishment). Only captured when a revocation
    // checker is wired (CA active) so a non-PKI deployment stores nothing.
    registry_.set_stream(agent_id, stream, context,
                         revocation_checker_ ? extract_peer_cert_pem(*context) : std::string{});
    registry_.map_session(session_id, agent_id);

    auto subscribe_start = std::chrono::steady_clock::now();
    if (auto analytics_store = analytics_store_.lock()) {
        AnalyticsEvent ae;
        ae.event_type = "agent.connected";
        ae.agent_id = agent_id;
        ae.session_id = session_id;
        ae.attributes = {{"via", "direct"}};
        analytics_store->emit(std::move(ae));
    }

    // Read loop -- process responses from the agent
    pb::CommandResponse resp;
    while (stream->Read(&resp)) {
        registry_.touch_activity(agent_id);

        // Guardian side-channel (contract G2 / step 5): UNSOLICITED agent→server
        // messages over the reserved "__guard__" plugin (drift events). Routed at
        // the TOP of the loop body — BEFORE the RUNNING/terminal status split — so
        // they never enter the response store / executions drawer. Status-agnostic:
        // Guardian events arrive as SUCCESS, so mirroring the in-RUNNING __timing__
        // intercept would miss them. agent_id is server-stamped from the cert-bound
        // session, never self-reported.
        //
        // The empty-command_id guard is load-bearing (H2 / #1209): only a
        // command_id-LESS __guard__ message is an unsolicited drift event to
        // ingest. A __guard__ message that DOES carry a command_id is a SOLICITED
        // reply (push_rules / get_status) and must NOT be ingested as an event.
        if (resp.plugin() == "__guard__" && resp.command_id().empty()) {
            // Guardian side-channel — route through the shared ingest so the
            // direct and gateway-proxied (GatewayUpstreamServiceImpl::
            // ForwardGuardianMessage) paths cannot diverge. agent_id is
            // cert-bound from this Subscribe session. Always skip the
            // response-store / executions path.
            if (guaranteed_state_store_)
                ingest_guardian_response(*guaranteed_state_store_, agent_id, resp,
                                         blast_radius_detector_, dex_alert_router_, &metrics_);
            continue;
        }
        // Solicited __guard__ replies (push_rules / reconcile carry a command_id)
        // are fire-and-forget on this DIRECT Subscribe loop — no server caller
        // blocks on a __guard__ command_id, so drop them rather than persist a
        // row-per-agent-per-push in the response store / executions drawer (hp-F1 /
        // #1209). (For gateway-connected agents the reply is correlated and its
        // pending entry cleared on the gateway by yuzu_gw_guardian's passthrough,
        // not here.)
        if (resp.plugin() == "__guard__")
            continue;

        if (resp.status() == pb::CommandResponse::RUNNING) {
            // Intercept __timing__ metadata
            if (resp.output().starts_with("__timing__|")) {
                auto payload = resp.output().substr(11);
                auto eq = payload.find('=');
                auto ms = (eq != std::string::npos) ? payload.substr(eq + 1) : payload;
                bus_.publish("timing", "<strong id=\"stat-agent\" hx-swap-oob=\"true\">" +
                                           html_escape(ms) + " ms</strong>");
                continue;
            }
            // CHAOS-TTL-1 (PR #3784 fix round, ADR-1007): the agent's
            // concurrency-claim keepalive thread (agents/core/src/agent.cpp)
            // sends a bare RUNNING with this exact output sentinel, on a
            // fixed interval, independent of any real plugin progress. It
            // exists SOLELY to feed ExecutionTracker::renew_concurrency_claim
            // via notify_exec_tracker below — it is not a response row (no
            // output for the executions drawer/SSE to show) and must not be
            // stored, published as output, or counted as an analytics event,
            // same reasoning as the __timing__ intercept above.
            if (resp.output() == "__keepalive__") {
                notify_exec_tracker(resp.command_id(), agent_id, resp);
                continue;
            }

            // Track first response for server-side latency
            {
                std::lock_guard lock(cmd_times_mu_);
                if (!cmd_first_seen_.contains(resp.command_id())) {
                    cmd_first_seen_.insert(resp.command_id());
                    auto it = cmd_send_times_.find(resp.command_id());
                    if (it != cmd_send_times_.end()) {
                        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                           std::chrono::steady_clock::now() - it->second)
                                           .count();
                        bus_.publish("timing", "<strong id=\"stat-network\" hx-swap-oob=\"true\">" +
                                                   std::to_string(elapsed) + " ms</strong>");
                    }
                }
            }

            // Determine the plugin from command_id prefix (format: plugin-timestamp)
            std::string plugin = extract_plugin(resp.command_id());

            // Publish each row as its own SSE event
            publish_output_rows(agent_id, plugin, resp.output());

            // Store streaming response
            if (response_store_) {
                StoredResponse sr;
                sr.instruction_id = resp.command_id();
                sr.agent_id = agent_id;
                sr.status = static_cast<int>(resp.status());
                sr.plugin_result_status = static_cast<int>(resp.plugin_result_status());
                sr.output = resp.output();
                sr.plugin = plugin;
                // PR 2 / HA WS-1(1b): stamp execution_id from the PG-backed
                // command_execution table so the executions detail drawer
                // can correlate exactly, on any replica.
                if (auto eid = resolve_execution_id(resp.command_id()))
                    sr.execution_id = *eid;
                response_store_->store(sr);
            }

            // UAT 2026-05-06 #8: notify the executions tracker so the
            // drawer's per-agent KPI table populates and the SSE
            // `agent-transition` event fires for live updates.
            notify_exec_tracker(resp.command_id(), agent_id, resp);

            if (auto analytics_store = analytics_store_.lock()) {
                AnalyticsEvent ae;
                ae.event_type = "command.response";
                ae.agent_id = agent_id;
                ae.plugin = plugin;
                ae.correlation_id = resp.command_id();
                ae.payload = {{"output_bytes", resp.output().size()}};
                analytics_store->emit(std::move(ae));
            }

        } else {
            spdlog::info("Command {} completed: status={}, exit_code={}", resp.command_id(),
                         static_cast<int>(resp.status()), resp.exit_code());

            // Store completion response
            if (response_store_) {
                auto plugin_name = extract_plugin(resp.command_id());
                std::string err_detail;
                if (resp.has_error()) {
                    err_detail = resp.error().message();
                }
                // PR 2 / HA WS-1(1b): resolve execution_id from the
                // PG-backed command_execution table. Do NOT delete on
                // terminal status — a single command_id can produce N
                // terminal responses (one per agent in fan-out); deleting on
                // the first agent's terminal would leave agents 2..N with no
                // execution_id to stamp (HF-1). The row ages out via
                // ExecutionTracker::reap_command_execution_mappings instead.
                std::string current_exec;
                if (auto eid = resolve_execution_id(resp.command_id()))
                    current_exec = *eid;
                // Terminal frame with no output: update the existing
                // RUNNING rows in place — the data is already there.
                // Persisting an empty-output row whose status enum reads
                // to operators as a failure exit code was the cause of
                // the spurious "exit=1 then exit=0" pair (UAT 2026-05-06).
                //
                // Governance UAT 2026-05-06 UP-3 / chaos CH-1: the result
                // is tri-state. Only NoRow falls through to insert; an
                // Error (SQLITE_BUSY etc.) must NOT insert because that
                // re-creates the duplicate-row bug the fix removed.
                using FR = ::yuzu::server::ResponseStore::FinalizeResult;
                FR finalize_result = FR::NoRow;
                if (resp.output().empty()) {
                    finalize_result = response_store_->finalize_terminal_status(
                        resp.command_id(), agent_id, static_cast<int>(resp.status()), err_detail,
                        current_exec, static_cast<int>(resp.plugin_result_status()));
                }
                if (finalize_result == FR::NoRow) {
                    // No prior RUNNING row (terminal-only command) or the
                    // terminal frame carries output — insert as before.
                    StoredResponse sr;
                    sr.instruction_id = resp.command_id();
                    sr.agent_id = agent_id;
                    sr.status = static_cast<int>(resp.status());
                    sr.plugin_result_status = static_cast<int>(resp.plugin_result_status());
                    sr.output = resp.output();
                    sr.plugin = plugin_name;
                    sr.error_detail = err_detail;
                    sr.execution_id = current_exec;
                    response_store_->store(sr);
                }
                // FR::Updated → row already updated in place, no insert.
                // FR::Error → already logged inside the store; do NOT
                //             insert — would re-create the sentinel.
            }

            // UAT 2026-05-06 #8: notify the executions tracker on terminal
            // status so the drawer's per-agent KPI flips to its terminal
            // state and the SSE `agent-transition` event fires.
            notify_exec_tracker(resp.command_id(), agent_id, resp);

            std::string status_str =
                (resp.status() == pb::CommandResponse::SUCCESS) ? "done" : "error";
            metrics_.counter("yuzu_commands_completed_total", {{"status", status_str}}).increment();
            {
                std::string badge_cls = (status_str == "done") ? "badge-done" : "badge-error";
                std::string badge_text = (status_str == "done") ? "DONE" : "ERROR";
                bus_.publish("command-status", "<span id=\"status-badge\" class=\"" + badge_cls +
                                                   "\" hx-swap-oob=\"outerHTML\">" + badge_text +
                                                   "</span>");
            }

            if (auto analytics_store = analytics_store_.lock()) {
                AnalyticsEvent ae;
                ae.event_type = "command.completed";
                ae.agent_id = agent_id;
                ae.plugin = extract_plugin(resp.command_id());
                ae.correlation_id = resp.command_id();
                ae.severity = (resp.status() == pb::CommandResponse::SUCCESS) ? Severity::kInfo
                                                                              : Severity::kError;
                ae.payload = {{"status", status_str}, {"exit_code", resp.exit_code()}};
                if (resp.has_error()) {
                    ae.payload["error_message"] = resp.error().message();
                }
                analytics_store->emit(std::move(ae));
            }

            // Create notification on execution failure
            if (resp.status() != pb::CommandResponse::SUCCESS && notification_store_ &&
                notification_store_->is_open()) {
                std::string err_msg = resp.has_error() ? resp.error().message() : "unknown";
                notification_store_->create("error", "Execution Failed",
                                            "Command " + resp.command_id() + " on agent " +
                                                agent_id + " failed: " + err_msg);
            }

            // Fire webhook + offload on execution completion. Each sink is
            // guarded independently — one sink null/closed must not silence
            // the other (HP-1 / UP-6). Single serialise per response (perf-S1).
            if ((webhook_store_ && webhook_store_->is_open()) ||
                (offload_target_store_ && offload_target_store_->is_open())) {
                nlohmann::json wh_payload = {{"event", "execution.completed"},
                                             {"command_id", resp.command_id()},
                                             {"agent_id", agent_id},
                                             {"status", status_str},
                                             {"exit_code", resp.exit_code()}};
                if (resp.has_error()) {
                    wh_payload["error"] = resp.error().message();
                }
                const auto body = wh_payload.dump();
                if (webhook_store_ && webhook_store_->is_open()) {
                    webhook_store_->fire_event("execution.completed", body);
                }
                if (offload_target_store_ && offload_target_store_->is_open()) {
                    offload_target_store_->fire_event("execution.completed", body);
                }
            }

            // Publish total round-trip and clean up timing maps
            {
                std::lock_guard lock(cmd_times_mu_);
                auto it = cmd_send_times_.find(resp.command_id());
                if (it != cmd_send_times_.end()) {
                    auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::steady_clock::now() - it->second)
                                        .count();
                    metrics_.histogram("yuzu_command_duration_seconds")
                        .observe(static_cast<double>(total_ms) / 1000.0);
                    bus_.publish("timing", "<strong id=\"stat-total\" hx-swap-oob=\"true\">" +
                                               std::to_string(total_ms) + " ms</strong>");
                    erase_send_time_locked(it);
                }
                cmd_first_seen_.erase(resp.command_id());
            }
        }
    }

    // Agent disconnected — use session-aware cleanup so a stale Subscribe
    // handler doesn't clobber a newer connection from the same agent_id.
    registry_.clear_stream_if_session(agent_id, session_id);
    const bool removed_current_session = registry_.remove_agent_if_session(agent_id, session_id);
    // HA WS-5 (ADR-2002 §7a): mirror the departure into the durable presence
    // row too, session-guarded — so a graceful disconnect on a single
    // replica leaves scope-evaluation's outcome unchanged from pre-WS-5
    // behavior (the row would otherwise linger, matched, until the presence
    // TTL expires; see evaluate_scope's presence merge in agent_registry.cpp).
    //
    // Gated on removed_current_session (external review finding, 2026-09-22):
    // the durable row's session_id is heartbeat-driven, not registration-
    // driven (heartbeat_ingestion.cpp), so on an ordinary same-replica
    // reconnect (this session S1 superseded locally by a new S2 that hasn't
    // heartbeated yet) the row can still read S1's session_id — an
    // unconditional delete here would remove a LIVE agent's presence row.
    // A false (session mismatch — S1 already superseded) means this
    // disconnect notice is stale and must NOT touch the durable row at all.
    if (removed_current_session && heartbeat_ingestion_)
        if (auto* offline = heartbeat_ingestion_->offline_endpoint_store())
            offline->remove_if_session(agent_id, session_id);
    // PR 10 hardening — evict pushed-snapshot slot too (sec-M4 / UP-5).
    // Without this, deregistered agents render as ghost cubes
    // indefinitely from the cached last-known-good snapshot.
    if (fleet_topology_store_)
        fleet_topology_store_->evict_pushed(agent_id);
    spdlog::info("Agent subscribe stream closed for {} (session={})", agent_id, session_id);

    if (auto analytics_store = analytics_store_.lock()) {
        auto session_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now() - subscribe_start)
                                    .count();
        AnalyticsEvent ae;
        ae.event_type = "agent.disconnected";
        ae.agent_id = agent_id;
        ae.session_id = session_id;
        ae.payload = {{"session_duration_ms", session_duration}};
        analytics_store->emit(std::move(ae));
    }

    return grpc::Status::OK;
}

// -- record_send_time ---------------------------------------------------------

void AgentServiceImpl::record_send_time(const std::string& command_id) {
    std::lock_guard lock(cmd_times_mu_);
    cmd_send_times_[command_id] = std::chrono::steady_clock::now();
    output_row_count_.store(0, std::memory_order_relaxed);
    publish_send_times_gauge_locked();
}

// -- discard_send_time (#2557) -------------------------------------------------

void AgentServiceImpl::erase_send_time_locked(
    std::unordered_map<std::string, std::chrono::steady_clock::time_point>::iterator it) {
    cmd_send_times_.erase(it);
    publish_send_times_gauge_locked();
}

void AgentServiceImpl::publish_send_times_gauge_locked() {
    metrics_.gauge("yuzu_cmd_send_times_pending")
        .set(static_cast<double>(cmd_send_times_.size()));
}

bool AgentServiceImpl::discard_send_time(const std::string& command_id) {
    std::lock_guard lock(cmd_times_mu_);
    auto it = cmd_send_times_.find(command_id);
    if (it == cmd_send_times_.end())
        return false;
    erase_send_time_locked(it);
    return true;
}

// -- resolve_execution_id (HA WS-1(1b), ADR-2002 section 5) ------------------

std::optional<std::string>
AgentServiceImpl::resolve_execution_id(const std::string& command_id) const {
    // Atomic snapshot — see notify_exec_tracker's identical load for the
    // detached gateway-forward-thread rationale (governance UAT 2026-05-06
    // Gate 7 re-review HIGH).
    auto* tracker = execution_tracker_.load(std::memory_order_acquire);
    if (!tracker)
        return std::nullopt;
    // Distinguish a STORE DEGRADE from an ordinary miss (adversarial
    // review Should-fix, PR #3780): this is the hot path, hit on every
    // CommandResponse, and a nullopt here was previously indistinguishable
    // from the common "out-of-band dispatch" case. A sustained degrade now
    // counts, mirroring the write path's yuzu_exec_correlation_write_degrade_total.
    std::string degrade_reason;
    auto result = tracker->lookup_execution_id(command_id, &degrade_reason);
    if (!degrade_reason.empty())
        metrics_.counter("yuzu_exec_correlation_read_degrade_total", {{"reason", degrade_reason}})
            .increment();
    return result;
}

// -- record_execution_id (PR 2; HA WS-1(1b) — PG-backed, ADR-2002 section 5) --

void AgentServiceImpl::record_execution_id(const std::string& command_id,
                                           const std::string& execution_id) {
    // Atomic snapshot — see notify_exec_tracker's identical load for the
    // detached gateway-forward-thread rationale (governance UAT 2026-05-06
    // Gate 7 re-review HIGH). A null tracker (not wired, or mid-shutdown)
    // means the correlation is simply not recorded — same no-op posture the
    // former in-process map had before this dispatch's first write.
    auto* tracker = execution_tracker_.load(std::memory_order_acquire);
    if (!tracker)
        return;
    // Best-effort: a false return degrades observability for this one
    // command (see record_command_execution's doc comment) and is
    // deliberately not propagated to the dispatch caller — it is counted
    // here so a sustained write-side degrade is visible in Prometheus
    // (governance Gate 4/6 finding: previously log-only, asymmetric with
    // the reap path's yuzu_exec_correlation_store_degrade_total).
    if (!tracker->record_command_execution(command_id, execution_id))
        metrics_.counter("yuzu_exec_correlation_write_degrade_total").increment();
}

// -- process_gateway_response -------------------------------------------------

void AgentServiceImpl::process_gateway_response(const std::string& agent_id,
                                                const pb::CommandResponse& resp) {
    if (resp.status() == pb::CommandResponse::RUNNING) {
        // Intercept __timing__ metadata
        if (resp.output().starts_with("__timing__|")) {
            auto payload = resp.output().substr(11);
            auto eq = payload.find('=');
            auto ms = (eq != std::string::npos) ? payload.substr(eq + 1) : payload;
            bus_.publish("timing", "<strong id=\"stat-agent\" hx-swap-oob=\"true\">" +
                                       html_escape(ms) + " ms</strong>");
            return;
        }
        // CHAOS-TTL-1 — see the direct-Subscribe twin of this intercept above
        // (this function's own doc comment names it "the gateway-streamed
        // RUNNING" path); same sentinel, same reasoning.
        if (resp.output() == "__keepalive__") {
            notify_exec_tracker(resp.command_id(), agent_id, resp);
            return;
        }

        // Track first response for server-side latency
        {
            std::lock_guard lock(cmd_times_mu_);
            if (!cmd_first_seen_.contains(resp.command_id())) {
                cmd_first_seen_.insert(resp.command_id());
                auto it = cmd_send_times_.find(resp.command_id());
                if (it != cmd_send_times_.end()) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       std::chrono::steady_clock::now() - it->second)
                                       .count();
                    bus_.publish("timing", "<strong id=\"stat-network\" hx-swap-oob=\"true\">" +
                                               std::to_string(elapsed) + " ms</strong>");
                }
            }
        }

        std::string plugin = extract_plugin(resp.command_id());
        publish_output_rows(agent_id, plugin, resp.output());

        if (response_store_) {
            StoredResponse sr;
            sr.instruction_id = resp.command_id();
            sr.agent_id = agent_id;
            sr.status = static_cast<int>(resp.status());
            sr.plugin_result_status = static_cast<int>(resp.plugin_result_status());
            sr.output = resp.output();
            sr.plugin = plugin;
            // PR 2 / HA WS-1(1b): streaming response — keep the mapping
            // until completion (PG-backed, shared across replicas).
            if (auto eid = resolve_execution_id(resp.command_id()))
                sr.execution_id = *eid;
            response_store_->store(sr);
        }

        // UAT 2026-05-06 #8: gateway-streamed RUNNING — notify tracker.
        notify_exec_tracker(resp.command_id(), agent_id, resp);

        if (auto analytics_store = analytics_store_.lock()) {
            AnalyticsEvent ae;
            ae.event_type = "command.response";
            ae.agent_id = agent_id;
            ae.plugin = plugin;
            ae.correlation_id = resp.command_id();
            ae.payload = {{"output_bytes", resp.output().size()}};
            analytics_store->emit(std::move(ae));
        }
    } else {
        spdlog::info("[gateway] Command {} completed: status={}, exit_code={}", resp.command_id(),
                     static_cast<int>(resp.status()), resp.exit_code());

        if (response_store_) {
            auto gw_plugin = extract_plugin(resp.command_id());
            std::string err_detail;
            if (resp.has_error()) {
                err_detail = resp.error().message();
            }
            // PR 2 / HA WS-1(1b): resolve execution_id from the
            // PG-backed command_execution table. Do NOT delete on
            // terminal status (HF-1) — multi-agent fan-out produces N
            // terminal responses; the row ages out via
            // ExecutionTracker::reap_command_execution_mappings instead.
            std::string current_exec;
            if (auto eid = resolve_execution_id(resp.command_id()))
                current_exec = *eid;
            // Terminal frame with no output: update existing RUNNING row(s)
            // instead of inserting a separate empty-output sentinel that
            // operators misread as a failure (UAT 2026-05-06). Tri-state
            // result handling per UP-3 / chaos CH-1.
            using FR = ::yuzu::server::ResponseStore::FinalizeResult;
            FR finalize_result = FR::NoRow;
            if (resp.output().empty()) {
                finalize_result = response_store_->finalize_terminal_status(
                    resp.command_id(), agent_id, static_cast<int>(resp.status()), err_detail,
                    current_exec, static_cast<int>(resp.plugin_result_status()));
            }
            if (finalize_result == FR::NoRow) {
                StoredResponse sr;
                sr.instruction_id = resp.command_id();
                sr.agent_id = agent_id;
                sr.status = static_cast<int>(resp.status());
                sr.plugin_result_status = static_cast<int>(resp.plugin_result_status());
                sr.output = resp.output();
                sr.plugin = gw_plugin;
                sr.error_detail = err_detail;
                sr.execution_id = current_exec;
                response_store_->store(sr);
            }
            // FR::Updated → in-place; FR::Error → already logged, do NOT insert.
        }

        // UAT 2026-05-06 #8: gateway-streamed terminal — notify tracker.
        notify_exec_tracker(resp.command_id(), agent_id, resp);

        std::string status_str = (resp.status() == pb::CommandResponse::SUCCESS) ? "done" : "error";
        metrics_.counter("yuzu_commands_completed_total", {{"status", status_str}}).increment();
        {
            std::string badge_cls = (status_str == "done") ? "badge-done" : "badge-error";
            std::string badge_text = (status_str == "done") ? "DONE" : "ERROR";
            bus_.publish("command-status", "<span id=\"status-badge\" class=\"" + badge_cls +
                                               "\" hx-swap-oob=\"outerHTML\">" + badge_text +
                                               "</span>");
        }

        if (auto analytics_store = analytics_store_.lock()) {
            AnalyticsEvent ae;
            ae.event_type = "command.completed";
            ae.agent_id = agent_id;
            ae.plugin = extract_plugin(resp.command_id());
            ae.correlation_id = resp.command_id();
            ae.severity = (resp.status() == pb::CommandResponse::SUCCESS) ? Severity::kInfo
                                                                          : Severity::kError;
            ae.payload = {{"status", status_str}, {"exit_code", resp.exit_code()}};
            if (resp.has_error()) {
                ae.payload["error_message"] = resp.error().message();
            }
            analytics_store->emit(std::move(ae));
        }

        if (resp.status() != pb::CommandResponse::SUCCESS && notification_store_ &&
            notification_store_->is_open()) {
            std::string err_msg = resp.has_error() ? resp.error().message() : "unknown";
            notification_store_->create("error", "Execution Failed",
                                        "Command " + resp.command_id() + " on agent " + agent_id +
                                            " failed: " + err_msg);
        }

        if ((webhook_store_ && webhook_store_->is_open()) ||
            (offload_target_store_ && offload_target_store_->is_open())) {
            nlohmann::json wh_payload = {{"event", "execution.completed"},
                                         {"command_id", resp.command_id()},
                                         {"agent_id", agent_id},
                                         {"status", status_str},
                                         {"exit_code", resp.exit_code()}};
            if (resp.has_error()) {
                wh_payload["error"] = resp.error().message();
            }
            const auto body = wh_payload.dump();
            if (webhook_store_ && webhook_store_->is_open()) {
                webhook_store_->fire_event("execution.completed", body);
            }
            if (offload_target_store_ && offload_target_store_->is_open()) {
                offload_target_store_->fire_event("execution.completed", body);
            }
        }

        // Publish total round-trip and clean up timing maps
        {
            std::lock_guard lock(cmd_times_mu_);
            auto it = cmd_send_times_.find(resp.command_id());
            if (it != cmd_send_times_.end()) {
                auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now() - it->second)
                                    .count();
                metrics_.histogram("yuzu_command_duration_seconds")
                    .observe(static_cast<double>(total_ms) / 1000.0);
                bus_.publish("timing", "<strong id=\"stat-total\" hx-swap-oob=\"true\">" +
                                           std::to_string(total_ms) + " ms</strong>");
                erase_send_time_locked(it);
            }
            cmd_first_seen_.erase(resp.command_id());
        }
    }
}

// -- SSE row helpers ----------------------------------------------------------
// Parsing utilities are in result_parsing.hpp.  Thin delegators kept here for
// API compatibility (thead_for_plugin is called from server.cpp).

std::string AgentServiceImpl::thead_for_plugin(const std::string& plugin) {
    auto& cols = yuzu::server::columns_for_plugin(plugin);
    std::string html = "<tr>";
    for (size_t i = 0; i < cols.size(); ++i) {
        html += (i == 0) ? "<th class=\"col-agent\">" : "<th>";
        html += html_escape(cols[i]);
        html += "</th>";
    }
    html += "</tr>";
    return html;
}

std::string AgentServiceImpl::render_row(const std::string& agent_name, const std::string& plugin,
                                         const std::string& line,
                                         const std::vector<std::string>& col_names) {
    auto fields = yuzu::server::split_fields(plugin, line);

    // Build cells: agent_name + fields
    std::vector<std::string> cells;
    cells.reserve(fields.size() + 1);
    cells.push_back(agent_name);
    for (auto& f : fields)
        cells.push_back(f);

    // Data row
    std::string html = "<tr class=\"result-row\" onclick=\"toggleDetail(this)\">";
    for (size_t i = 0; i < cells.size(); ++i) {
        auto esc = html_escape(cells[i]);
        html += (i == 0) ? "<td class=\"col-agent\" title=\"" : "<td title=\"";
        html += esc;
        html += "\">";
        html += esc;
        html += "</td>";
    }
    html += "</tr>";

    // Detail drawer
    html += "<tr class=\"result-detail\"><td colspan=\"";
    html += std::to_string(cells.size());
    html += "\"><div class=\"detail-content\">";
    for (size_t i = 0; i < cells.size(); ++i) {
        auto label = (i < col_names.size()) ? col_names[i] : ("Column " + std::to_string(i + 1));
        html += "<div class=\"detail-label\">" + html_escape(label) + "</div>";
        html += "<div class=\"detail-value\">" + html_escape(cells[i]) + "</div>";
    }
    html += "</div></td></tr>";
    return html;
}

void AgentServiceImpl::notify_exec_tracker(const std::string& command_id,
                                           const std::string& agent_id,
                                           const pb::CommandResponse& resp) {
    // Atomic snapshot — detached gateway-forward worker threads spawned
    // by ServerImpl::forward_gateway_pending outlive gRPC's Shutdown
    // drain (those threads are *clients* of the gateway, not server-side
    // handlers, so Shutdown does not cancel them). Load with acquire so
    // a concurrent set_execution_tracker(nullptr) at shutdown is safely
    // observed and we short-circuit rather than dereference a destroyed
    // ExecutionTracker (governance UAT 2026-05-06 Gate 7 re-review HIGH).
    // Residual race: the tracker can begin destruction between this load
    // and the update_agent_status call below; the window is bounded by
    // ServerImpl's "drain gRPC, null setter, then reset" ordering. A
    // full fix (in-flight counter or shared_ptr lifetime) is tracked
    // as a follow-up.
    auto* tracker = execution_tracker_.load(std::memory_order_acquire);
    if (!tracker)
        return;
    // HA WS-1(1b): resolved from the PG-backed command_execution table
    // (shared across replicas), not an in-process map — a response landing
    // on a different server instance than the one that dispatched it now
    // still resolves.
    auto execution_id_opt = resolve_execution_id(command_id);
    if (!execution_id_opt || execution_id_opt->empty()) {
        // ADR-1007 by-command concurrency-claim fallback (originally UP-1,
        // unhappy-path Gate 4 finding, PR #3784 fix round — reconciled onto
        // HA WS-1(1b) above; the fallback's ORIGINAL trigger, a server
        // restart losing an in-process `cmd_execution_ids_` map, is now the
        // PG-backed `command_execution` table's own job and no longer needs
        // this fallback's help). What still reaches here, genuinely: (1)
        // every workflow-step dispatch (`workflow_routes.cpp`), which
        // always passes an empty `execution_id` (CONSIST-2/sec-M2), so
        // `record_execution_id` never records a mapping for it and
        // `resolve_execution_id` correctly returns nullopt — this is the
        // ONLY release path a workflow-step per-device claim ever reaches;
        // (2) a genuine degrade on `command_execution`'s own write or
        // read side (pool exhaustion, a query failure), which this fallback
        // also transparently covers since it doesn't depend on that table
        // having succeeded; and (3) `command_execution`'s own bounded
        // retention (`reap_command_execution_mappings`, a fixed 24h window)
        // aging a mapping out from under a command that is STILL
        // legitimately running past that window (ADR-1007 supports
        // unbounded "run until finished" dispatch) — the mapping's reap has
        // nothing to do with whether the command finished. The
        // concurrency-claim safety property does not have to share any of
        // these fates: `command_id` rides on every response
        // independent of this table, and `(command_id, agent_id)` is a
        // DB-enforced-unique match key (see
        // release_concurrency_claim_by_command's doc comment) — so route
        // release/renewal through it directly. A no-op if no open claim
        // matches (ordinary out-of-band dispatch that never took one).
        // Releases immediately on a genuine terminal response rather than
        // waiting for the reconciler.
        //
        // `__guard__-` skip (Fable adversarial-review finding, PR #3784 fix
        // round): every `__guard__.*` dispatch (push_rules / reconcile,
        // server.cpp) is minted under this reserved double-underscore
        // prefix and NEVER goes through the per-device concurrency gate —
        // confirmed no `__guard__`-plugin definition can carry
        // `concurrency_mode: per-device` (guard pushes are system-caller,
        // definition-less dispatch). Skipping it here avoids a wasted
        // write-pool lease + UPDATE on every guard push/reconcile response
        // (routine, high-frequency) for a claim that can structurally never
        // exist. Deliberately NOT extended to `tar-` (Fable's other
        // candidate): `tar` is also a REAL agent plugin name
        // (agents/plugins/tar) that a per-device-gated definition could in
        // principle target — a string-prefix skip there would risk
        // silently skipping a legitimate release if that ever happens, and
        // nothing in the code (only today's content library) guarantees it
        // won't. See ADR-1007 for the fuller note.
        if (command_id.starts_with("__guard__-"))
            return;
        switch (resp.status()) {
        case pb::CommandResponse::RUNNING:
            tracker->renew_concurrency_claim_by_command(command_id, agent_id);
            break;
        case pb::CommandResponse::SUCCESS:
        case pb::CommandResponse::FAILURE:
        case pb::CommandResponse::TIMEOUT:
        case pb::CommandResponse::REJECTED:
            tracker->release_concurrency_claim_by_command(command_id, agent_id);
            break;
        default:
            break;
        }
        return; // out-of-band dispatch, nothing to publish
    }
    const std::string& execution_id = *execution_id_opt;

    // Compliance-check correlation ids ("polchk-…", minted by PolicyEvaluator)
    // are NOT operator executions: the evaluator tags responses with this id only
    // so it can read them back via ResponseStore::query_by_execution. There is no
    // ExecutionTracker row for them, so notifying the tracker here would publish
    // an `agent-transition` SSE event (execution_tracker.cpp publishes
    // unconditionally) and create orphan agent_exec_status rows for a phantom
    // execution that the executions drawer / /api/v1/events would surface. Skip.
    if (execution_id.starts_with("polchk-"))
        return;

    // Live-query bundle correlation ids ("bundle-…", minted by
    // BundleOrchestrator) are the same case as polchk-: NOT operator
    // executions. A bundle stamps its N ordinary command responses with this
    // id only so collate can read them via ResponseStore::query_by_execution;
    // there is deliberately no ExecutionTracker row (a bundle is N commands to
    // ONE agent, which the agent-counted tracker would mark complete after the
    // first step — see ADR-0011). Notifying here would publish an
    // `agent-transition` SSE event and create an orphan agent_exec_status row
    // for a phantom execution. Skip; collate is the bundle's completion authority.
    if (execution_id.starts_with("bundle-"))
        return;

    // Pre-flight run correlation ids ("preflight-<run>-<check>", minted by
    // PreflightRoutes / PreflightRunner) are the same case: the run re-dispatches
    // each check under a stable per-check execution_id only so the grid can read
    // responses back via query_by_execution. There is no ExecutionTracker row —
    // the PreflightRunStore is the run's completion authority, NOT the executions
    // drawer. Notifying here would publish phantom agent-transition events. Skip.
    if (execution_id.starts_with("preflight-"))
        return;

    // Deployment correlation ids ("deployment-<id>-stage" / "-exec", minted by the
    // deployment engine) are the same case: the deployment re-reads stage/execute
    // responses via query_by_execution; the DeploymentRunStore is the completion
    // authority, not the executions drawer. Notifying here would publish phantom
    // agent-transition events. Skip.
    if (execution_id.starts_with("deployment-"))
        return;

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

    AgentExecStatus s;
    s.agent_id = agent_id;
    s.dispatched_at = 0; // upsert keeps prior value if non-zero
    s.exit_code = resp.exit_code();
    // CC-07: mirror the wire enum straight through — both are small,
    // stable, append-only integer enums (agent.proto's PluginResultStatus /
    // sdk/include/yuzu/plugin.h's YuzuResultStatus), so no separate mapping
    // table is needed to avoid drift; 0 in both is PLUGIN_RESULT_UNDECLARED.
    s.plugin_result_status = static_cast<int>(resp.plugin_result_status());
    if (resp.has_error()) {
        s.error_detail = resp.error().message();
    }
    switch (resp.status()) {
    case pb::CommandResponse::RUNNING:
        s.status = "running";
        s.first_response_at = now;
        s.completed_at = 0;
        break;
    case pb::CommandResponse::SUCCESS:
        s.status = "success";
        s.first_response_at = now;
        s.completed_at = now;
        break;
    case pb::CommandResponse::FAILURE:
        s.status = "failure";
        s.first_response_at = now;
        s.completed_at = now;
        break;
    case pb::CommandResponse::TIMEOUT:
        s.status = "timeout";
        s.first_response_at = now;
        s.completed_at = now;
        break;
    case pb::CommandResponse::REJECTED:
        s.status = "rejected";
        s.first_response_at = 0;
        s.completed_at = now;
        break;
    default:
        return;
    }
    tracker->update_agent_status(execution_id, s);
}

void AgentServiceImpl::publish_output_rows(const std::string& agent_id, const std::string& plugin,
                                           const std::string& raw_output) {
    if (raw_output.empty())
        return;
    auto agent_name = registry_.display_name(agent_id);
    auto& col_names = yuzu::server::columns_for_plugin(plugin);
    auto lines = yuzu::server::split_output_lines(raw_output);
    for (const auto& line : lines) {
        // TAR warehouse protocol lines: __schema__ and __total__
        if (plugin == "tar" && yuzu::server::is_tar_protocol_line(line)) {
            if (line.starts_with("__schema__|")) {
                auto cols = yuzu::server::parse_tar_schema_line(line);
                // M16: Validate schema line has non-empty columns
                if (cols.empty())
                    continue;
                // H14: Thread-safe per-instance cache with mutex
                {
                    std::lock_guard lock(cmd_times_mu_);
                    tar_dynamic_columns_ = cols;
                }
                // C1: HTML-escape column names to prevent XSS via AS aliases
                std::string thead = "<thead id=\"results-thead\" hx-swap-oob=\"true\"><tr>"
                                    "<th class=\"col-agent\">Agent</th>";
                for (const auto& c : cols) {
                    thead += "<th>";
                    // Escape HTML special characters
                    for (char ch : c) {
                        switch (ch) {
                        case '<':
                            thead += "&lt;";
                            break;
                        case '>':
                            thead += "&gt;";
                            break;
                        case '&':
                            thead += "&amp;";
                            break;
                        case '"':
                            thead += "&quot;";
                            break;
                        case '\'':
                            thead += "&#39;";
                            break;
                        default:
                            thead += ch;
                            break;
                        }
                    }
                    thead += "</th>";
                }
                thead += "</tr></thead>";
                bus_.publish("output", thead);
            }
            continue;
        }

        // Use dynamic columns for TAR SQL results if available (H14: lock)
        std::vector<std::string> tar_cols_copy;
        {
            std::lock_guard lock(cmd_times_mu_);
            tar_cols_copy = tar_dynamic_columns_;
        }
        auto& effective_cols =
            (!tar_cols_copy.empty() && plugin == "tar") ? tar_cols_copy : col_names;

        auto count = output_row_count_.fetch_add(1, std::memory_order_relaxed) + 1;
        auto row_html = render_row(agent_name, plugin, line, effective_cols);

        // All elements must be OOB-targeted — the SSE sink uses
        // hx-swap="none".  Mixing <tr> and <span> in a single
        // fragment breaks under the browser's table content model
        // (foster parenting ejects non-table elements, losing the
        // swap target).
        std::string html;
        // OOB: append rows to results tbody
        html += "<tbody id=\"results-tbody\" hx-swap-oob=\"beforeend\">";
        html += row_html;
        html += "</tbody>";
        // OOB: live row count
        html += "<span id=\"row-count\" hx-swap-oob=\"true\">";
        html += std::to_string(count);
        html += "</span>";
        // OOB: remove empty-state placeholder on first row only
        if (count == 1)
            html += "<tr id=\"empty-row\" hx-swap-oob=\"delete\"></tr>";
        bus_.publish("output", html);
    }
}

// -- OTA Update RPCs ----------------------------------------------------------

grpc::Status AgentServiceImpl::CheckForUpdate(grpc::ServerContext* context,
                                              const pb::CheckForUpdateRequest* request,
                                              pb::CheckForUpdateResponse* response) {
    metrics_
        .counter("yuzu_grpc_requests_total", {{"method", "CheckForUpdate"}, {"status", "received"}})
        .increment();

    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    // B-1 (#1239): a revoked agent must not learn the latest version / sha256 /
    // mandatory flag / rollout eligibility for its agent_id. This is the OTA
    // sibling of DownloadUpdate's gate above — both agent-initiated update RPCs
    // now reject a revoked peer. (No-op when no cert is presented or no checker
    // is wired, matching Heartbeat/DownloadUpdate.)
    if (auto s = reject_revoked_peer(context, "check_for_update"); !s.ok())
        return s;

    // #416: positive identity + agent_id/certificate binding. Inert unless the
    // agent listener requires a client certificate. agent_id matters here even
    // though this RPC streams nothing: it selects rollout eligibility below.
    if (auto s = require_positive_ota_identity(context, "check_for_update", request->agent_id());
        !s.ok())
        return s;

    if (!update_registry_) {
        response->set_update_available(false);
        return grpc::Status::OK;
    }

    auto latest =
        update_registry_->latest_for(request->platform().os(), request->platform().arch());

    if (!latest) {
        response->set_update_available(false);
        return grpc::Status::OK;
    }

    // Compare: if agent already has latest or newer, no update
    if (compare_versions(latest->version, request->current_version()) <= 0) {
        response->set_update_available(false);
        return grpc::Status::OK;
    }

    bool eligible = UpdateRegistry::is_eligible(request->agent_id(), latest->rollout_pct);

    response->set_update_available(true);
    response->set_latest_version(latest->version);
    response->set_sha256(latest->sha256);
    response->set_mandatory(latest->mandatory);
    response->set_eligible(eligible);
    response->set_file_size(latest->file_size);

    // The detached signature, when the operator uploaded one (#416/#3807).
    //
    // Read fresh from the sidecar rather than cached: it is a few KB against an
    // RPC an agent makes every six hours, and a cache would be one more place
    // for the signature to go stale relative to the binary it covers. A missing
    // sidecar is the ordinary unsigned case, not an error — the AGENT decides
    // whether that is acceptable, since this server is not the authority on its
    // own packages' authenticity.
    {
        const auto sig_path = update_registry_->signature_path(*latest);
        std::string sig;
        switch (read_signature_sidecar(sig_path, sig)) {
        case SidecarOutcome::kServed:
            response->set_update_signature(std::move(sig));
            break;
        case SidecarOutcome::kAbsent:
            break; // the ordinary unsigned case
        case SidecarOutcome::kOverCap:
            // NOT "missing" — an absent sidecar is the separate, deliberately
            // silent kAbsent branch above. Naming it here sends an operator
            // investigating an oversized or irregular file looking for one that
            // is not there.
            spdlog::error("CheckForUpdate: signature sidecar for {} is unusable (over the {} "
                          "byte cap, or not a regular file); serving as unsigned",
                          latest->filename, kMaxSignatureBytes);
            break;
        case SidecarOutcome::kUnreadable:
            // Present but unreadable is worth a log: the operator believes this
            // package is signed and every agent will be told it is not.
            spdlog::warn("CheckForUpdate: signature sidecar for {} exists but is unreadable; "
                         "serving the package as unsigned",
                         latest->filename);
            break;
        }
    }

    spdlog::info("CheckForUpdate: agent {} v{} -> v{} (eligible={}, mandatory={})",
                 request->agent_id(), request->current_version(), latest->version, eligible,
                 latest->mandatory);
    return grpc::Status::OK;
}

grpc::Status AgentServiceImpl::DownloadUpdate(grpc::ServerContext* context,
                                              const pb::DownloadUpdateRequest* request,
                                              grpc::ServerWriter<pb::DownloadUpdateChunk>* writer) {
    metrics_
        .counter("yuzu_grpc_requests_total", {{"method", "DownloadUpdate"}, {"status", "received"}})
        .increment();

    // ADR-1005 enforceable seam — see grpc_on_behalf_enforce.hpp.
    if (auto s = onbehalf::enforce(context); !s.ok()) return s;

    // PR3: a revoked agent must not be able to pull the agent binary over the OTA
    // path.
    if (auto s = reject_revoked_peer(context, "download_update"); !s.ok())
        return s;

    // #416: positive identity + agent_id/certificate binding. Inert unless the
    // agent listener requires a client certificate.
    if (auto s = require_positive_ota_identity(context, "download_update", request->agent_id());
        !s.ok())
        return s;

    // ── Per-peer admission (#913) ───────────────────────────────────────────
    const auto admission_key = ota_admission_key(*context);
    const std::string& ota_key = admission_key.key;
    metrics_.counter("yuzu_ota_admission_key_mode_total", {{"mode", admission_key.mode}})
        .increment();

    // SERVER-WIDE cap first — it is the only bound that does not scale with the
    // caller's address space. The per-peer gate below bounds one identity, but
    // where the identity gate is inert the key falls back to source IP, so a
    // caller with a /24 buys 256 independent per-peer budgets. This one is flat.
    // Taken before the per-peer bucket so a refused transfer spends no token.
    const bool cert_keyed = std::string_view(admission_key.mode) == "cert";
    auto total = ota_total_admission_.try_acquire(ota_cfg_.max_concurrent_total,
                                                  ota_cfg_.cert_reserve_pct, cert_keyed);
    if (!total.admitted) {
        metrics_.counter("yuzu_ota_download_admission_total", {{"decision", "rejected_total"}})
            .increment();
        if (should_log_ota_rejection())
            spdlog::warn("DownloadUpdate: rejected by server-wide transfer cap "
                         "(in_flight={} cap={} cert_keyed={} key={}) [sampled]",
                         total.observed_in_flight, total.effective_cap, cert_keyed,
                         onbehalf::sanitize_for_log(ota_key));
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                            "server OTA transfer capacity exceeded");
    }

    auto slot = ota_quota_.try_acquire(ota_key, QuotaSide::kEngine);

    // Published on EVERY call, admitted or not. Updating it only on the admit
    // path left it stale exactly when the map is under pressure — which is the
    // one condition YuzuOtaPeerMapNearCapacity exists to observe, since a peer
    // storm large enough to fill the map is also the case most likely to be
    // rejected rather than admitted.
    metrics_.gauge("yuzu_ota_download_peers_tracked")
        .set(static_cast<double>(ota_quota_.principal_count()));

    if (!slot.admitted()) {
        const bool by_concurrency = slot.decision().limit == QuotaLimit::kConcurrency;
        metrics_
            .counter("yuzu_ota_download_admission_total",
                     {{"decision", by_concurrency ? "rejected_concurrency" : "rejected_rate"}})
            .increment();
        // Name the peer. Admission rejections are deliberately metric-only (no
        // audit row — see docs/user-manual/audit-log.md), and the metric labels are
        // bounded, so without this line a YuzuOtaConcurrencyRejections page has NO
        // path from alert to peer.
        //
        // SAMPLED, because the obvious justification for logging every one is
        // wrong: the cap bounds concurrent ADMISSIONS, not rejections — a refused
        // request returns immediately, so rejections are bounded only by inbound
        // request rate, and the file sink is a non-rotating basic_logger_mt. One
        // peer looping refused pulls would grow the log without limit. The metric
        // is the complete count; this line exists for ATTRIBUTION, and the first
        // occurrence plus a periodic sample gives an operator the identity they
        // need without making the log the failure.
        if (should_log_ota_rejection())
            spdlog::warn("DownloadUpdate: rejected by per-peer {} bound "
                         "(key={} mode={} retry_after_ms={}) [sampled]",
                         by_concurrency ? "concurrency" : "rate",
                         onbehalf::sanitize_for_log(ota_key), admission_key.mode,
                         slot.decision().retry_after_ms);
        // One wire status for both dimensions, and a REJECT rather than a queue:
        // queueing at capacity would hold the very thread the cap exists to free.
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                            "per-peer OTA download limit exceeded");
    }
    metrics_.counter("yuzu_ota_download_admission_total", {{"decision", "admitted"}}).increment();

    // The concurrency slot is held by `slot` for the rest of this function and
    // released by its destructor on EVERY exit path, including the early returns
    // below — that is the whole reason it is an RAII reservation.
    //
    // The rate token is charged at admission and given back on SERVER-attributable
    // failure only. Metering our own failures would let an honest but unlucky
    // agent spend itself into a lockout, which is exactly the pathology recorded
    // on #934 (7.5h) and #941 (75min). Idempotent: several exit paths refund, and
    // a double refund would mint quota.
    bool refunded = false;
    auto refund_token = [&](const char* reason) {
        if (refunded)
            return;
        refunded = true;
        ota_quota_.refund(ota_key);
        // Its OWN family, deliberately not a `decision="refunded"` label on the
        // admission counter: a refunded request already incremented
        // `decision="admitted"`, so folding refunds in there stops `decision`
        // being a partition and makes sum(admission_total) double-count. The
        // `reason` label is also what makes the refund invariant checkable —
        // #939 wants deadline charges compared against deadline refunds, which
        // a single undifferentiated "refunded" bucket cannot express.
        metrics_.counter("yuzu_ota_download_refund_total", {{"reason", reason}}).increment();
    };

    if (!update_registry_) {
        refund_token("registry_unavailable"); // nothing streamed, and not the peer's doing
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, "OTA not configured");
    }

    auto pkg = update_registry_->latest_for(request->platform().os(), request->platform().arch());
    if (!pkg || pkg->version != request->version()) {
        // Refunded even though the peer chose the version: nothing was streamed,
        // so no capacity was consumed, and the bucket meters WORK DONE rather
        // than requests attempted. A staged rollout routinely has agents asking
        // for versions this server does not hold; charging for that would drain
        // their buckets against zero cost. Parallel probing is already bounded by
        // the concurrency cap, which is the dimension that matters here.
        refund_token("version_not_found");
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "version not found");
    }

    // KNOWN LIMITATION, and its consequence is worse than the read itself.
    //
    // This read is blocking and cannot be interrupted: TryCancel does not unblock
    // read(2), and O_NONBLOCK is a no-op for a regular file. That is UP-112, which
    // ships mitigated rather than closed. What is NOT obvious, and is recorded here
    // because it bit a review: a wedged read holds this peer's QuotaSlot for the
    // process lifetime, because the slot is released by scope exit and the scope
    // never exits. So that peer is refused RESOURCE_EXHAUSTED on every subsequent
    // pull until restart, and at --ota-max-concurrent-per-peer=1 a single hang is
    // permanent for that peer.
    //
    // What bounds the damage: the server-wide cap above (one wedged handler is one
    // of --ota-max-concurrent-total, not an unbounded drain), and the per-peer cap
    // (the blast radius is that peer, not the fleet). What does NOT bound it: the
    // transfer watchdog, which fires, marks the registration cancelled, and cannot
    // do anything about a thread parked in the kernel.
    //
    // Operators: keep OTA artifacts on local storage. The runbook says so.
    auto file_path = update_registry_->binary_path(*pkg);
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        spdlog::error("DownloadUpdate: binary file missing: {}", file_path.string());
        refund_token("package_missing"); // server-side artifact problem
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "binary file missing");
    }

    // ── Transfer deadline (#911 UP-101) ─────────────────────────────────────
    // Scoped to exactly this function body: the watchdog can only ever TryCancel a
    // context whose handler frame is still live, because this registration erases
    // itself before the frame returns. See ota_transfer_watchdog.hpp's LIFETIME
    // note — the agent hit the equivalent use-after-free in cancel_ctx().
    auto transfer_guard = ota_watchdog_.register_transfer(
        [context] { context->TryCancel(); },
        std::chrono::steady_clock::now() + ota_cfg_.transfer_deadline);

    constexpr std::size_t kChunkSize = 64 * 1024; // 64KB
    std::vector<char> buffer(kChunkSize);
    int64_t offset = 0;

    while (file.read(buffer.data(), static_cast<std::streamsize>(kChunkSize)) ||
           file.gcount() > 0) {
        pb::DownloadUpdateChunk chunk;
        chunk.set_data(buffer.data(), static_cast<std::size_t>(file.gcount()));
        chunk.set_offset(offset);
        chunk.set_total_size(pkg->file_size);

        // Time the Write. A peer whose receive window is open but tiny completes
        // every Write slowly; the whole-transfer deadline would eventually catch
        // that, but this bails at the first clearly-stalled chunk instead of
        // holding the thread for the entire budget.
        const auto write_started = std::chrono::steady_clock::now();
        const bool wrote = writer->Write(chunk);
        const auto write_elapsed = std::chrono::steady_clock::now() - write_started;

        // The decision itself lives in ota_transfer_rules.hpp so every branch is
        // reachable by a test without a package on disk (which would drag in
        // UpdateRegistry and a PgPool). This is the thin caller: classify, then
        // act. A Write unblocked by our own TryCancel and one that failed because
        // the peer hung up are INDISTINGUISHABLE at the return value, which is
        // why the watchdog's verdict is an input.
        const auto outcome = ota::classify_write(wrote, transfer_guard.cancelled(), write_elapsed,
                                                 ota_cfg_.chunk_stall_deadline);

        if (ota::is_terminal(outcome)) {
            if (const char* phase = ota::deadline_phase(outcome)) {
                metrics_.counter("yuzu_ota_download_deadline_exceeded_total", {{"phase", phase}})
                    .increment();
            }
            if (const char* reason = ota::refund_reason(outcome))
                refund_token(reason);

            switch (outcome) {
            case ota::TransferOutcome::kTransferDeadline:
                spdlog::warn("DownloadUpdate: transfer deadline exceeded at offset {}", offset);
                return grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED,
                                    "OTA transfer deadline exceeded");
            case ota::TransferOutcome::kChunkStalled:
                spdlog::warn(
                    "DownloadUpdate: chunk write stalled {}s at offset {}, aborting",
                    std::chrono::duration_cast<std::chrono::seconds>(write_elapsed).count(),
                    offset);
                return grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED,
                                    "OTA chunk write deadline exceeded");
            case ota::TransferOutcome::kPeerDisconnected:
                spdlog::warn("DownloadUpdate: client disconnected at offset {}", offset);
                return grpc::Status::CANCELLED;
            case ota::TransferOutcome::kContinue:
                break; // unreachable: is_terminal() excluded it
            }
        }

        offset += file.gcount();
    }

    spdlog::info("DownloadUpdate: sent {} bytes of v{} to agent {}", offset, pkg->version,
                 request->agent_id());
    return grpc::Status::OK;
}

// -- Private helpers ----------------------------------------------------------

void AgentServiceImpl::set_ota_bound_config(const OtaBoundConfig& cfg) {
    ota_cfg_ = cfg;
    // Drive the eviction counter at the moment the ceiling bites. Sampling
    // evicted_count() instead would lose every eviction between samples, and a
    // sampled cumulative value cannot honestly be exported as a counter.
    // Capturing `this` is safe: the quota is a member, so it cannot outlive us.
    ota_quota_.set_on_evict(
        [this] { metrics_.counter("yuzu_ota_download_peers_evicted_total").increment(); });
    ota_quota_.set_config(PrincipalQuotaConfig{
        .max_concurrency = cfg.max_concurrent_per_peer,
        // PrincipalQuota refills per SECOND; the OTA knob is per MINUTE because
        // that is the scale an operator reasons about for a fleet-update pull.
        .rate_per_second = cfg.rate_refill_per_min / 60.0,
        .burst = cfg.rate_capacity,
        .idle_evict_seconds = 3600,
        // Clamp UP: see OtaBoundConfig::max_peers_tracked. A too-small ceiling
        // silently disables the rate dimension rather than merely shrinking a cache.
        .max_tracked = std::max(cfg.max_peers_tracked, kMinPeersTracked),
    });
}

bool AgentServiceImpl::should_log_ota_rejection() {
    // Log the first rejection, then one in every kOtaRejectionLogSample. Cheap
    // (one relaxed atomic increment), lock-free, and it keeps the log bounded to
    // O(rejections / sample) without hiding the condition — the metric carries the
    // exact count, and YuzuOtaConcurrencyRejections alerts off the metric, not off
    // the log. The first-occurrence case matters because an operator paged at 03:00
    // needs an identity immediately, not after the sample interval.
    const auto n = ota_rejection_log_seq_.fetch_add(1, std::memory_order_relaxed);
    return n == 0 || (n % kOtaRejectionLogSample) == 0;
}

AgentServiceImpl::AdmissionKey
AgentServiceImpl::ota_admission_key(const grpc::ServerContext& ctx) const {
    const auto idents = extract_peer_identities(ctx);
    if (!idents.empty())
        return AdmissionKey{idents.front(), "cert"};

    // No client certificate. Fall back to peer IP rather than an empty shared
    // key — see the header comment on this function (#935).
    std::string ip = extract_peer_ip(ctx.peer());
    if (!ip.empty())
        return AdmissionKey{std::move(ip), "peer_ip"};

    // Neither a certificate nor a parseable peer. This is REACHABLE, not merely
    // defensive: extract_peer_ip returns empty for any scheme that is not ipv4/ipv6
    // (see peer_ip.hpp), so a unix-socket listen address collapses every caller
    // onto this one bucket — 2 concurrent transfers for the whole fleet. Yuzu
    // configures a TCP listener, so it does not arise in a supported deployment,
    // and the mode label makes it visible if it ever does.
    return AdmissionKey{std::string("unknown"), "unknown"};
}

grpc::Status AgentServiceImpl::require_positive_ota_identity(grpc::ServerContext* context,
                                                             std::string_view rpc,
                                                             const std::string& claimed_agent_id) {
    if (!require_positive_ota_identity_ || !context)
        return grpc::Status::OK;

    // `code` is a parameter because the rejections are not all the same KIND.
    // A missing/mismatched identity is UNAUTHENTICATED; an absent required field
    // is INVALID_ARGUMENT, matching what Register already returns for the same
    // empty-agent_id condition. Collapsing both onto one code would tell an agent
    // its certificate was rejected when in fact its request was malformed.
    auto deny = [&](grpc::StatusCode code, const char* reason, const char* message) {
        // event=security: unlike an admission rejection (expected steady state,
        // operational), a failed identity bind on an already-enrolled agent's OTA
        // pull is an authentication signal. Mirrors yuzu_grpc_revoked_cert_total.
        metrics_
            .counter("yuzu_grpc_ota_identity_rejected_total",
                     {{"event", "security"}, {"rpc", std::string(rpc)}, {"reason", reason}})
            .increment();
        // SANITIZED, not merely truncated. This value is attacker-chosen and it
        // lands in the file the OTA runbook names as the only attribution path for
        // these rejections, so a raw write lets a caller embed newlines and forge
        // log lines that are indistinguishable from real ones. sanitize_for_log
        // replaces control characters and bounds the length.
        spdlog::warn("{} rejected: {} (agent_id={})", rpc, reason,
                     onbehalf::sanitize_for_log(claimed_agent_id));

        // WHICH REJECTIONS GET AN AUDIT ROW, and why this is not all of them.
        //
        // The audit write is SYNCHRONOUS and PostgreSQL-backed, and this gate runs
        // BEFORE the per-peer admission bound — so an unbounded stream of denials
        // here would pin gRPC threads on the audit path, which is the exact vector
        // this change exists to close. Two distinct floods reach it: an attacker
        // looping a certless or mismatched pull (sec-2), and a fleet-wide identity
        // drift after a mass re-image, which needs no attacker at all and scales
        // with fleet size (UP-4).
        //
        // `no_client_identity` — no cert at all — has no principal to attribute,
        // is the cheapest case to forge in volume, and is left metric-only. That
        // is the same split reject_revoked_peer already makes for `heartbeat` ("a
        // flood must not hammer the WAL") and the no-resolvable-principal
        // carve-out in docs/observability-conventions.md.
        //
        // RATE-BOUNDED, and the earlier justification for not bounding it was
        // wrong. It claimed the audited reasons were "bounded by the size of the
        // issued-certificate population"; they are bounded by the number of
        // REQUESTS. One enrolled agent holding a valid certificate can loop
        // CheckForUpdate — which has no admission bound at all — with a mismatched
        // agent_id and drive one synchronous Postgres write per call, ahead of
        // every other bound. That is the vector this change exists to close, so
        // the write is gated on a small per-PEER bucket. The METRIC still counts
        // every rejection, so suppression is visible as a gap between the counter
        // and the row count, never as a missing signal.
        //
        // The bucket key is the PEER, never the claimed agent_id: see the member's
        // own comment. Keying on the claim let a caller varying it per request mint
        // a fresh, always-admitting bucket every time.
        //
        // ORDER MATTERS on both counts. The store check comes FIRST so a token is
        // never spent on a denial that could not have been written anyway, and the
        // key comes from the shared composer so the peer/reason namespacing cannot
        // drift — see ota_audit_key.hpp for what went wrong twice here.
        //
        // The limiter is consulted on REASON alone, before any check on whether a
        // store is wired. Consulting it store-first would be marginally cheaper —
        // no token is spent on a denial that could not have been written — but it
        // would also make the bound unobservable without Postgres, and this bound
        // has now shipped broken twice. A suppression counter that only moves on
        // deployments with an audit store is not a counter anyone tests. The cost
        // of the trade is one map entry per (rpc, reason, peer) on a server with
        // no audit store, which the same handshake price already bounds.
        bool audit_worthy = false;
        if (std::string_view(reason) != "no_client_identity") {
            const auto peer = ota_admission_key(*context);
            audit_worthy = ota_identity_audit_limiter_.allow(
                ota_identity_audit_key(rpc, reason, peer.mode, peer.key));
            if (!audit_worthy) {
                // The operator-facing half of the trade documented in audit-log.md
                // and metrics.md: rows are sampled under a flood, and THIS is how
                // an operator sees that it is happening rather than inferring it
                // from a gap between two other numbers.
                metrics_
                    .counter("yuzu_ota_identity_audit_suppressed_total",
                             {{"rpc", std::string(rpc)}, {"reason", reason}})
                    .increment();
            }
        }
        if (audit_worthy && audit_store_ && audit_store_->is_open()) {
            const auto ids = extract_peer_identities(*context);
            const std::string cert_id = ids.empty() ? std::string{} : ids.front();
            AuditEvent ev;
            ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
            // Clamp: Register's kMaxAgentIdLength gate is Register-only, so an
            // unclamped body value would let a peer inflate every audit row it
            // provokes (the W1.4/UP-H1 defect, on a new surface).
            ev.principal =
                "agent:" + (cert_id.empty() ? claimed_agent_id.substr(0, auth::kMaxAgentIdLength)
                                            : cert_id);
            ev.principal_role = "agent";
            // session.* keeps this inside the CC7.2 auth-sample export, which
            // filters on that prefix (see AuditQuery::action_prefixes).
            //
            // Deliberately NOT session.identity_mismatch: that verb is already
            // taken by the Subscribe mTLS binding check and carries a different
            // detail shape (presented=[...] bound=[...]). Reusing it would put
            // two different detail formats under one action, which breaks any
            // consumer parsing that field.
            ev.action = "session.ota_identity_rejected";
            ev.target_type = "AgentCertificate";
            ev.target_id = cert_id;
            ev.detail = std::string("reason=").append(reason).append(" rpc=").append(rpc);
            ev.source_ip = extract_peer_ip(context->peer());
            ev.result = "denied";
            if (!audit_store_->log(ev))
                signal_grpc_audit_failed(context);
        }
        return grpc::Status(code, message);
    };

    const auto idents = extract_peer_identities(*context);
    if (idents.empty()) {
        // The listener requires a client certificate, so a peer without an
        // identity here is anomalous rather than a bootstrap case. Register keeps
        // its bootstrap exemption; an OTA pull has none, because an agent pulling
        // an update is by definition already enrolled.
        return deny(grpc::StatusCode::UNAUTHENTICATED, "no_client_identity",
                    "client certificate required");
    }

    // Hermes CRITICAL-1, same reasoning as Register: in a multi-CA trust bundle a
    // foreign certificate carrying a spoofed CN=<agent_id> must not be accepted
    // as a Yuzu agent identity. When no recognizer is wired (operator-supplied
    // single trust root) every authenticated cert is an agent — legacy behaviour.
    const std::string peer_pem = extract_peer_cert_pem(*context);
    if (peer_cert_recognizer_ && !peer_cert_recognizer_(peer_pem))
        return deny(grpc::StatusCode::UNAUTHENTICATED, "foreign_ca",
                    "client certificate was not issued by this server's CA");

    // An ABSENT claim is refused rather than waved through. Skipping the bind on
    // an empty agent_id would make the whole check evadable by omission: the
    // protobuf default is the empty string, and CheckForUpdate feeds that value
    // straight to UpdateRegistry::is_eligible(), so a caller that simply omits
    // the field would pick its own rollout bucket while presenting a valid
    // certificate. Register already refuses an empty agent_id for the same
    // reason (see the kMaxAgentIdLength gate at the top of this file); this is
    // the OTA sibling of that rule.
    if (claimed_agent_id.empty())
        return deny(grpc::StatusCode::INVALID_ARGUMENT, "agent_id_missing", "agent_id is required");

    // Bind the request-body agent_id to the certificate. Until this, agent_id was
    // client-supplied and unverified, yet it drives rollout eligibility
    // (UpdateRegistry::is_eligible) and is logged as the acting identity.
    if (!peer_identity_matches_agent_id(*context, claimed_agent_id))
        return deny(grpc::StatusCode::UNAUTHENTICATED, "agent_id_mismatch",
                    "agent_id must match client certificate identity (CN/SAN)");

    return grpc::Status::OK;
}

std::vector<std::string>
AgentServiceImpl::extract_peer_identities(const grpc::ServerContext& context) {
    std::vector<std::string> out;
    auto auth_ctx = context.auth_context();
    if (!auth_ctx || !auth_ctx->IsPeerAuthenticated()) {
        return out;
    }

    auto append_unique = [&out](std::string_view s) {
        if (s.empty())
            return;
        for (const auto& existing : out) {
            if (existing == s)
                return;
        }
        out.emplace_back(s);
    };

    for (const auto& id : auth_ctx->GetPeerIdentity()) {
        append_unique(std::string_view{id.data(), id.size()});
    }
    for (const auto& cn : auth_ctx->FindPropertyValues(GRPC_X509_CN_PROPERTY_NAME)) {
        append_unique(std::string_view{cn.data(), cn.size()});
    }
    for (const auto& san : auth_ctx->FindPropertyValues(GRPC_X509_SAN_PROPERTY_NAME)) {
        append_unique(std::string_view{san.data(), san.size()});
    }

    return out;
}

std::string AgentServiceImpl::extract_peer_cert_pem(const grpc::ServerContext& context) {
    auto auth_ctx = context.auth_context();
    if (!auth_ctx || !auth_ctx->IsPeerAuthenticated())
        return {};
    const auto vals = auth_ctx->FindPropertyValues(GRPC_X509_PEM_CERT_PROPERTY_NAME);
    if (vals.empty())
        return {};
    return std::string(vals.front().data(), vals.front().size());
}

grpc::Status AgentServiceImpl::reject_revoked_peer(grpc::ServerContext* context,
                                                   std::string_view rpc) {
    if (!context || !revocation_checker_)
        return grpc::Status::OK;
    const std::string peer_pem = extract_peer_cert_pem(*context);
    if (peer_pem.empty() || !revocation_checker_(peer_pem))
        return grpc::Status::OK; // no cert, foreign cert, or not revoked → allow
    // event=security is the SIEM-routing tag; rpc distinguishes the surface. A
    // revoked agent that keeps calling is a decommissioned/compromised-credential
    // signal. Metric-only (no per-call audit) — Heartbeat is high-frequency and a
    // flood must not hammer the WAL; the command-channel reject (Subscribe) keeps
    // the audited row. SOC 2 CC7.2 signal via the counter.
    metrics_
        .counter("yuzu_grpc_revoked_cert_total",
                 {{"event", "security"}, {"rpc", std::string(rpc)}})
        .increment();
    spdlog::warn("{} rejected: revoked client certificate", rpc);
    // gov (compliance CC7.1): emit a forensic audit row for the lower-frequency,
    // supply-chain-relevant surfaces (download_update) — a revoked agent attempting
    // an OTA pull is worth a durable record. Heartbeat stays metric-only (high
    // frequency; a flood must not hammer the WAL). Subscribe keeps its own richer
    // audited gate, so it does not route through here.
    if (rpc != "heartbeat" && audit_store_ && audit_store_->is_open()) {
        const auto ids = extract_peer_identities(*context);
        const std::string cert_id = ids.empty() ? std::string{} : ids.front();
        AuditEvent ev;
        ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
        ev.principal = "agent:" + cert_id;
        ev.principal_role = "agent";
        ev.action = "session.cert_revoked";
        ev.target_type = "AgentCertificate";
        ev.target_id = cert_id;
        ev.detail = std::string("reason=revoked_client_cert rpc=").append(rpc);
        ev.source_ip = extract_peer_ip(context->peer());
        ev.result = "denied";
        if (!audit_store_->log(ev))
            signal_grpc_audit_failed(context);
    }
    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "client certificate is revoked");
}

bool AgentServiceImpl::peer_identity_matches_agent_id(const grpc::ServerContext& context,
                                                      const std::string& agent_id) {
    if (agent_id.empty())
        return false;
    const auto identities = extract_peer_identities(context);
    for (const auto& id : identities) {
        if (id == agent_id)
            return true;
    }
    return false;
}

std::string AgentServiceImpl::client_metadata_value(const grpc::ServerContext& context,
                                                    std::string_view key) {
    const auto& md = context.client_metadata();
    auto it = md.find(std::string(key));
    if (it == md.end())
        return {};
    return std::string(it->second.data(), it->second.length());
}

std::string AgentServiceImpl::extract_peer_ip(std::string_view peer) {
    // W1.3 R2 / consistency MEDIUM-1: thin shim to the shared parser in
    // peer_ip.hpp. Kept as a static member for ABI continuity — the unit
    // tests address it as `AgentServiceImpl::extract_peer_ip(...)` and
    // production call sites in this TU use the unqualified `extract_peer_ip`
    // pulled in by the header include. Keeping the static delegate avoids a
    // mass-rename in the test surface without forking the parser.
    return ::yuzu::server::detail::extract_peer_ip(peer);
}

AgentServiceImpl::PeerBindingOutcome AgentServiceImpl::evaluate_peer_binding(
    bool exact_ok, std::string_view register_ip, std::string_view subscribe_ip,
    bool client_identity_matches, const std::vector<std::string>& trusted_nat_cidrs) {
    if (exact_ok)
        return PeerBindingOutcome::exact_ok;
    // #826: an empty extracted IP is a mismatch, never a wildcard — no
    // accommodation can rescue it (a malformed/unix peer must still reject).
    if (register_ip.empty() || subscribe_ip.empty())
        return PeerBindingOutcome::reject;
    // mTLS identity is the stronger layer (#827 + #1118); prefer it over CIDR.
    if (client_identity_matches)
        return PeerBindingOutcome::advisory_mtls;
    if (::yuzu::server::detail::ips_share_trusted_cidr(trusted_nat_cidrs, register_ip, subscribe_ip))
        return PeerBindingOutcome::advisory_nat_cidr;
    return PeerBindingOutcome::reject;
}

bool AgentServiceImpl::has_identity_overlap(const std::vector<std::string>& lhs,
                                            const std::vector<std::string>& rhs) {
    for (const auto& left : lhs) {
        for (const auto& right : rhs) {
            if (left == right)
                return true;
        }
    }
    return false;
}

void AgentServiceImpl::prune_expired_pending_locked() {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = pending_by_session_id_.begin(); it != pending_by_session_id_.end();) {
        if (now - it->second.created_at > kPendingRegistrationTtl) {
            it = pending_by_session_id_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string AgentServiceImpl::extract_plugin(const std::string& command_id) {
    auto dash = command_id.find('-');
    if (dash != std::string::npos) {
        return command_id.substr(0, dash);
    }
    return command_id;
}

} // namespace yuzu::server::detail
