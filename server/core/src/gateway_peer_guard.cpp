#include "gateway_peer_guard.hpp"

#include <string>
#include <string_view>
#include <utility>

#include <spdlog/spdlog.h>

#include "gateway_peer_cert.hpp"
#include "grpc_peer_evidence.hpp"
#include "peer_ip.hpp"

namespace yuzu::server::detail {

namespace {

constexpr std::string_view kPrincipalPrefix = "gateway-peer:";
constexpr std::string_view kDeniedTargetType = "GatewayRpc";
constexpr std::string_view kGatewayRole = "gateway"; // principal_role of an authenticated peer
constexpr std::size_t kPrincipalSpkiChars = 8;
constexpr std::size_t kDetailSpkiChars = 16;

yuzu::Labels denied_labels(GatewayUpstreamRpc rpc, gateway_peer::DenyReason reason) {
    return {{"rpc", std::string{to_label(rpc)}},
            {"reason", std::string{gateway_peer::to_label(reason)}},
            {"event", "security"}};
}

} // namespace

GatewayPeerGuardedService::GatewayPeerGuardedService(
    gw::GatewayUpstream::Service& inner, gateway_peer::GatewayPeerPolicy policy, AuditSink audit,
    yuzu::MetricsRegistry* metrics, std::shared_ptr<DenialAuditBudget> budget,
    std::shared_ptr<DenialAuditBudget> log_budget)
    : GatewayPeerGuardedService(inner, /*acknowledged_insecure=*/false, std::move(policy),
                                std::move(audit), metrics, std::move(budget),
                                std::move(log_budget)) {}

GatewayPeerGuardedService::GatewayPeerGuardedService(gw::GatewayUpstream::Service& inner,
                                                     AcknowledgedInsecure,
                                                     yuzu::MetricsRegistry* metrics)
    : GatewayPeerGuardedService(inner, /*acknowledged_insecure=*/true,
                                gateway_peer::GatewayPeerPolicy{nullptr}, AuditSink{}, metrics,
                                nullptr, nullptr) {}

GatewayPeerGuardedService::GatewayPeerGuardedService(
    gw::GatewayUpstream::Service& inner, bool acknowledged_insecure,
    gateway_peer::GatewayPeerPolicy policy, AuditSink audit, yuzu::MetricsRegistry* metrics,
    std::shared_ptr<DenialAuditBudget> budget, std::shared_ptr<DenialAuditBudget> log_budget)
    : inner_(inner), acknowledged_insecure_(acknowledged_insecure), policy_(std::move(policy)),
      audit_(std::move(audit)), metrics_(metrics),
      budget_(budget ? std::move(budget) : std::make_shared<DenialAuditBudget>()),
      log_budget_(log_budget ? std::move(log_budget) : std::make_shared<DenialAuditBudget>()) {
    if (!metrics_)
        return;
    // Everything below is telemetry setup: a failure here is logged and must not stop the guard
    // (and with it the server) from being constructed, since an unguarded service is never the
    // alternative.
    try {
        metrics_->describe(std::string{kGatewayPeerDeniedMetric},
                           "Gateway-upstream calls refused because the caller was not an "
                           "authorized gateway peer, by rpc and closed reason",
                           "counter");
        metrics_->describe(std::string{kGatewayPeerDenialSuppressedMetric},
                           "Gateway-upstream denial audit rows not written because the per-key "
                           "audit budget was spent (the denial counter still counts every refusal)",
                           "counter");
        // Pre-seed the full closed rpc x reason grid so every series exists at 0 and
        // an alert on increase() is evaluable before the first denial.
        for (std::size_t i = 0; i < kGatewayUpstreamRpcNames.size(); ++i) {
            for (const auto reason : gateway_peer::kAllDenyReasons) {
                (void)metrics_->counter(std::string{kGatewayPeerDeniedMetric},
                                        denied_labels(static_cast<GatewayUpstreamRpc>(i), reason));
            }
        }
        (void)metrics_->counter(std::string{kGatewayPeerDenialSuppressedMetric}, {});
    } catch (...) {
        spdlog::warn("gateway peer guard: could not register the denial metrics");
    }
}

void GatewayPeerGuardedService::record_denial(grpc::ServerContext* context, GatewayUpstreamRpc rpc,
                                              gateway_peer::DenyReason reason,
                                              const std::string& spki_sha256_hex) noexcept {
    // Each step is contained on its own: a failure in one must not skip the next,
    // and none may escape. The refusal itself is decided by the caller.
    try {
        if (metrics_) {
            metrics_->counter(std::string{kGatewayPeerDeniedMetric}, denied_labels(rpc, reason))
                .increment();
        }
    } catch (...) {
    }

    try {
        const std::string_view rpc_name = to_label(rpc);
        const std::string_view reason_name = gateway_peer::to_label(reason);

        // An audit row needs an authenticated certificate holder: a computable key AND a reason
        // that can only be reached by one. Every other denial (no context, an unauthenticated
        // peer, no certificate, an unparseable one) is the counter plus a rate-limited warning.
        if (spki_sha256_hex.empty() || !denial_may_carry_audit_row(reason)) {
            // The key-less log budget is keyed by the closed reason, so it is bounded by
            // construction and one reason's flood cannot silence another's line.
            if (log_budget_->try_admit(reason_name, reason_name).admitted)
                spdlog::warn("gateway peer denied: rpc={} reason={}", rpc_name, reason_name);
            return;
        }

        const std::string spki8 = spki_sha256_hex.substr(0, kPrincipalSpkiChars);
        // Budget key: the closed reason and the peer's own key prefix. The label set and the key
        // are ours (hex and closed labels), so the key is bounded by construction.
        const std::string key = std::string{reason_name} + '|' + spki8;
        // Past the budget's key bound, new keys of one reason share that reason's overflow bucket,
        // so a flood of one reason cannot use up another reason's overflow rows.
        const std::string overflow_key = std::string{reason_name} + "|*";
        const auto admit = budget_->try_admit(key, overflow_key);
        if (admit.closed_window_suppressed > 0)
            spdlog::warn("gateway peer: {} denial audit rows suppressed in the last window (the "
                         "denial counter is complete)",
                         admit.closed_window_suppressed);
        if (!admit.admitted) {
            try {
                if (metrics_)
                    metrics_->counter(std::string{kGatewayPeerDenialSuppressedMetric}, {})
                        .increment();
            } catch (...) {
            }
            return;
        }

        spdlog::warn("gateway peer denied: rpc={} reason={} spki={}", rpc_name, reason_name,
                     spki_sha256_hex.substr(0, kDetailSpkiChars));
        if (!audit_)
            return;
        AuditEvent ev;
        // Fields are assigned in AuditEvent declaration order.
        ev.principal = std::string{kPrincipalPrefix} + spki8;
        ev.principal_role = std::string{kGatewayRole};
        ev.action = std::string{kGatewayPeerDeniedAuditAction};
        ev.target_type = std::string{kDeniedTargetType};
        ev.target_id = std::string{rpc_name};
        ev.detail = "reason=" + std::string{reason_name} + " rpc=" + std::string{rpc_name} +
                    " spki=" + spki_sha256_hex.substr(0, kDetailSpkiChars);
        if (context)
            ev.source_ip = extract_peer_ip(context->peer());
        ev.result = "denied";
        if (!audit_(ev))
            spdlog::warn("gateway peer guard: audit write failed for a denied call (rpc={})",
                         rpc_name);
    } catch (...) {
    }
}

grpc::Status GatewayPeerGuardedService::authorize(grpc::ServerContext* context,
                                                  GatewayUpstreamRpc rpc) {
    if (acknowledged_insecure_)
        return grpc::Status::OK; // boot-selected acknowledgement; see the header
    gateway_peer::Decision d; // default-constructed: deny
    grpc_peer::PeerCertEvidence peer;
    try {
        gateway_peer::PeerEvidence ev;
        ev.context_present = (context != nullptr);
        if (context) {
            peer = grpc_peer::read_peer_cert_evidence(*context);
            ev.peer_authenticated = peer.authenticated;
            ev.cert_pem = peer.pem;
        }
        d = policy_.decide(ev);
    } catch (...) {
        d = gateway_peer::Decision::deny(gateway_peer::DenyReason::InternalError);
    }
    if (d.allowed)
        return grpc::Status::OK;

    // Attribution: the key of a TLS-authenticated peer whose certificate parsed. The decision
    // carries it when it got that far; an `internal_error` that precedes or interrupts the parse
    // is attributed here, on the denial path only. Whether a row is written at all is decided in
    // record_denial by the reason, so a key computed here never widens what is audited.
    std::string spki = d.spki_sha256_hex;
    if (spki.empty() && peer.authenticated && !peer.pem.empty()) {
        try {
            spki = gateway_peer::spki_sha256_hex(std::string_view{peer.pem})
                       .value_or(std::string{});
        } catch (...) {
            spki.clear();
        }
    }
    record_denial(context, rpc, d.reason, spki);
    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, std::string{kGatewayPeerDeniedMessage});
}

grpc::Status GatewayPeerGuardedService::ProxyRegister(grpc::ServerContext* context,
                                                      const pb::RegisterRequest* request,
                                                      pb::RegisterResponse* response) {
    if (auto st = authorize(context, GatewayUpstreamRpc::ProxyRegister); !st.ok())
        return st;
    return inner_.ProxyRegister(context, request, response);
}

grpc::Status GatewayPeerGuardedService::BatchHeartbeat(grpc::ServerContext* context,
                                                       const gw::BatchHeartbeatRequest* request,
                                                       gw::BatchHeartbeatResponse* response) {
    if (auto st = authorize(context, GatewayUpstreamRpc::BatchHeartbeat); !st.ok())
        return st;
    return inner_.BatchHeartbeat(context, request, response);
}

grpc::Status GatewayPeerGuardedService::ProxyInventory(grpc::ServerContext* context,
                                                       const pb::InventoryReport* request,
                                                       pb::InventoryAck* response) {
    if (auto st = authorize(context, GatewayUpstreamRpc::ProxyInventory); !st.ok())
        return st;
    return inner_.ProxyInventory(context, request, response);
}

grpc::Status GatewayPeerGuardedService::NotifyStreamStatus(grpc::ServerContext* context,
                                                           const gw::StreamStatusNotification* request,
                                                           gw::StreamStatusAck* response) {
    if (auto st = authorize(context, GatewayUpstreamRpc::NotifyStreamStatus); !st.ok())
        return st;
    return inner_.NotifyStreamStatus(context, request, response);
}

grpc::Status GatewayPeerGuardedService::ForwardGuardianMessage(
    grpc::ServerContext* context, const gw::ForwardGuardianRequest* request,
    gw::ForwardGuardianAck* response) {
    if (auto st = authorize(context, GatewayUpstreamRpc::ForwardGuardianMessage); !st.ok())
        return st;
    return inner_.ForwardGuardianMessage(context, request, response);
}

} // namespace yuzu::server::detail
