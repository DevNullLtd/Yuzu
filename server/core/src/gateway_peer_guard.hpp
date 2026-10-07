#pragma once

/// @file gateway_peer_guard.hpp
/// `GatewayPeerGuardedService`: the gateway-upstream service wrapped so that no
/// RPC reaches the real handlers unless the caller is an authorized gateway peer.
///
/// WHO DECIDES. `gateway_peer::GatewayPeerPolicy` decides (gateway_peer_policy.hpp).
/// This class only gathers the transport evidence, asks the policy BEFORE
/// delegating, and refuses on a deny. It never delegates on a deny.
///
/// DEFAULT-DENY BY CONSTRUCTION. The guard derives from the generated service
/// base and overrides EXACTLY the five unary RPCs, each as an explicit override
/// that calls `authorize()` before delegating. The generated base answers any
/// other method, present or future, with UNIMPLEMENTED, so a method added to the
/// proto can never reach the real handlers by being forgotten here. The test
/// `gateway_peer_guard` walks the generated service descriptor and fails loudly if
/// the method set changes, if a method is streaming, or if an anonymous call to a
/// method does not return UNAUTHENTICATED.
///
/// WHAT TO REGISTER. A builder must register THIS object and only this object as the
/// gateway-upstream service. The guard wraps the SERVICE, so it covers every listener
/// the shared builder serves it on, including a listener that only requests (does not
/// require) a client certificate. `ServerImpl::setup_gateway_peer_guard` (server.cpp) builds
/// it and `tests/test_gateway_peer_registration_lexical.py` pins that it is the only
/// registration.
///
/// ACKNOWLEDGED MODE. The `AcknowledgedInsecure` constructor builds a guard that
/// admits every call. It is selected by a constructor, once, at boot; there is no
/// per-call switch. It exists so a rig that does not authorize gateway peers still
/// registers through this one class. It disables the guard on every port the service
/// is served on.
///
/// REFUSAL. Every deny, whatever its reason, is `UNAUTHENTICATED` with ONE fixed
/// message (`kGatewayPeerDeniedMessage`). The reason is exposed only through the
/// counter label, the audit row and the log, never to the caller, so the response
/// carries no oracle.
///
/// OBSERVABILITY of a denial, each step contained so that a telemetry failure can
/// never turn a deny into an allow and never escapes the handler (the decision is
/// computed first; reporting is best-effort):
///   * the unsampled counter
///     `yuzu_server_gateway_peer_denied_total{rpc,reason,event="security"}`, with
///     every closed `rpc` x `reason` series (5 x 8) pre-seeded to 0 at construction.
///     It is the complete count and the SIEM signal. `rpc` is the snake_case of the
///     proto method name (`kGatewayUpstreamRpcNames`);
///   * an audit row `session.gateway_peer_denied` (the `session.` prefix keeps it inside
///     the CC7.2 authentication-log export), result `denied`, written through the injected
///     sink ONLY when the peer's SPKI key is computable, that is, only for a TLS-authenticated
///     certificate holder, and only for the reasons `no_server_auth_eku`, `not_pinned`,
///     `outside_validity` and `internal_error`. Principal `gateway-peer:<first 8 hex of the
///     peer's own SPKI SHA-256>`, `principal_role` `unverified_peer` (the peer is
///     TLS-authenticated but was refused, so it is not labelled a gateway), detail
///     `reason=<reason> rpc=<rpc> spki=<first 16 hex>`: hex and closed labels only, never PEM,
///     subject names or serials. `principal_class` stays empty (this is not an HTTP session or
///     token principal). NO row is written for `null_context`, `not_authenticated`, `no_cert`
///     or `bad_cert`. The first three are callers the transport never authenticated (or that
///     presented nothing), which cost nothing to produce; `bad_cert` is reached only after the
///     transport DID authenticate the peer (`peer_authenticated`), but its certificate does not
///     parse, so no SPKI key exists to attribute or budget a row to. Those denials are the
///     counter plus a rate-limited warning log only (that warning carries `peer=<ip>`, the only
///     attribution such a caller has). Rows go through the keyed
///     `DenialAuditBudget` (key `<reason>|<8 hex of the peer key>`, overflow bucket
///     `<reason>|*`); the budget bounds the rows and never gates the refusal;
///   * rows the budget refused are counted in
///     `yuzu_server_gateway_peer_denial_audit_suppressed_total`, and ONE aggregate log
///     line per window reports how many were refused;
///   * a keyed denial logs one warning while the audit budget admits it; a denial with no key
///     logs one warning while a second, log-only budget (keyed by reason) admits it.
///
/// NO `x-yuzu-audit-failed` TRAILER. This is a deliberate decision, not an omission: the deny is
/// already decided when the row is written, and the denial counter is complete whether or not the
/// row lands, so a failed or suppressed audit write is set-and-proceed (logged, never attached to
/// the response).
///
/// LIFETIME. `inner` and `metrics` must outlive this object. In the server the
/// guard is declared after the inner service and torn down before it.
///
/// TESTS may construct the inner service directly with a null ServerContext; the
/// guard is never on that path. The guard itself denies a null context.

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include <yuzu/metrics.hpp>

#include "audit_store.hpp"
#include "bounded_audit_budget.hpp"
#include "gateway.grpc.pb.h"
#include "gateway_peer_policy.hpp"

namespace yuzu::server::detail {

// Same aliases gateway_service_impl.hpp declares in this namespace (redeclaring an
// alias to the same target is legal).
namespace gw = ::yuzu::gateway::v1;
namespace pb = ::yuzu::agent::v1;

/// The one message every denial carries.
inline constexpr std::string_view kGatewayPeerDeniedMessage = "gateway peer not authorized";

inline constexpr std::string_view kGatewayPeerDeniedMetric =
    "yuzu_server_gateway_peer_denied_total";
inline constexpr std::string_view kGatewayPeerDeniedAuditAction = "session.gateway_peer_denied";
inline constexpr std::string_view kGatewayPeerDenialSuppressedMetric =
    "yuzu_server_gateway_peer_denial_audit_suppressed_total";

/// The closed `rpc` label set: one enumerator per guard method, labelled with the snake_case of
/// the proto method name (like every other label in this family).
enum class GatewayUpstreamRpc : std::uint8_t {
    ProxyRegister,
    BatchHeartbeat,
    ProxyInventory,
    NotifyStreamStatus,
    ForwardGuardianMessage,
    kCount, ///< sentinel: the number of methods above, never a method
};

inline constexpr std::array<std::string_view, 5> kGatewayUpstreamRpcNames{
    "proxy_register", "batch_heartbeat", "proxy_inventory", "notify_stream_status",
    "forward_guardian_message"};
// The enum indexes the table unchecked, so a size mismatch would read out of bounds. An enumerator
// added before `kCount` without a label (or a label without an enumerator) fails the build here;
// the descriptor tripwire in test_gateway_peer_guard.cpp additionally compares the table with the
// proto.
static_assert(kGatewayUpstreamRpcNames.size() == static_cast<std::size_t>(GatewayUpstreamRpc::kCount),
              "kGatewayUpstreamRpcNames must have exactly one label per GatewayUpstreamRpc");

[[nodiscard]] constexpr std::string_view to_label(GatewayUpstreamRpc r) {
    return kGatewayUpstreamRpcNames[static_cast<std::size_t>(r)];
}

/// Whether a denial for `reason` may carry an audit row (it additionally needs a computable
/// SPKI key, so it is a necessary condition only). Derived from ONE predicate,
/// `gateway_peer::reason_proves_authenticated_cert_holder` (the reasons reachable only after the
/// transport authenticated the peer and its certificate parsed: `no_server_auth_eku`,
/// `not_pinned`, `outside_validity`), plus `internal_error`, which can occur at any stage and
/// therefore relies on the key requirement. Never true for `null_context`, `not_authenticated`,
/// `no_cert` or `bad_cert`: those are the counter plus a rate-limited warning line only (the
/// first three are not an authenticated certificate holder; `bad_cert` is an authenticated peer
/// whose certificate does not parse, so it has no key to attribute a row to).
[[nodiscard]] constexpr bool denial_may_carry_audit_row(gateway_peer::DenyReason r) {
    return gateway_peer::reason_proves_authenticated_cert_holder(r) ||
           r == gateway_peer::DenyReason::InternalError;
}

class GatewayPeerGuardedService final : public ::yuzu::gateway::v1::GatewayUpstream::Service {
public:
    /// Writes one audit row; returns false on failure. Failure is logged and
    /// otherwise ignored: an audit outage must not become a gateway outage, and
    /// it must never change a deny into an allow.
    using AuditSink = std::function<bool(const AuditEvent&)>;

    /// `inner` handles every admitted call. `metrics` may be null (no counter).
    /// `audit` may be empty (no rows). `budget` bounds the audit rows and may be null, which
    /// selects a default-sized budget owned by this object; `log_budget` bounds the warning
    /// lines of denials that have no key (same default when null).
    GatewayPeerGuardedService(gw::GatewayUpstream::Service& inner,
                              gateway_peer::GatewayPeerPolicy policy, AuditSink audit,
                              yuzu::MetricsRegistry* metrics,
                              std::shared_ptr<DenialAuditBudget> budget = nullptr,
                              std::shared_ptr<DenialAuditBudget> log_budget = nullptr);

    /// Names the one deliberate way to run WITHOUT peer authorization: the operator's explicit
    /// acknowledgement, resolved at boot. Nothing else constructs it.
    struct AcknowledgedInsecure {};

    /// Same registration shape as the enforcing guard (so the production builder has ONE
    /// registration path), but every call is admitted: there is no policy, no evidence read and
    /// no denial. The mode is fixed by this constructor and cannot change per call.
    GatewayPeerGuardedService(gw::GatewayUpstream::Service& inner, AcknowledgedInsecure,
                              yuzu::MetricsRegistry* metrics);

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

private:
    /// OK to proceed, or the fixed UNAUTHENTICATED refusal (after recording it).
    [[nodiscard]] grpc::Status authorize(grpc::ServerContext* context, GatewayUpstreamRpc rpc);
    /// `spki_sha256_hex`: the peer's own key hash (64 lowercase hex) or empty when no key is known.
    void record_denial(grpc::ServerContext* context, GatewayUpstreamRpc rpc,
                       gateway_peer::DenyReason reason,
                       const std::string& spki_sha256_hex) noexcept;

    GatewayPeerGuardedService(gw::GatewayUpstream::Service& inner, bool acknowledged_insecure,
                              gateway_peer::GatewayPeerPolicy policy, AuditSink audit,
                              yuzu::MetricsRegistry* metrics,
                              std::shared_ptr<DenialAuditBudget> budget,
                              std::shared_ptr<DenialAuditBudget> log_budget);

    gw::GatewayUpstream::Service& inner_;
    const bool acknowledged_insecure_; ///< fixed at construction; see AcknowledgedInsecure
    gateway_peer::GatewayPeerPolicy policy_;
    AuditSink audit_;
    yuzu::MetricsRegistry* metrics_;
    std::shared_ptr<DenialAuditBudget> budget_;     ///< audit rows (keyed denials only)
    std::shared_ptr<DenialAuditBudget> log_budget_; ///< warning lines of key-less denials
};

} // namespace yuzu::server::detail
