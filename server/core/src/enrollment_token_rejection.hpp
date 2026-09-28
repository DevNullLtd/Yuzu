#pragma once

/// @file enrollment_token_rejection.hpp
/// Wire-boundary collapse + audit/metric expansion contract for
/// `AuthManager::consume_and_enroll` token rejections (W1.4 / #827; WS-6 6.2 folded the consume into the atomic consume-and-enroll).
///
/// **Mirror of `device_token_rejection.hpp` (W1.3).** Same hard rule:
/// every gRPC handler that maps an `EnrollmentTokenError` to a wire
/// response MUST collapse to one opaque message ("invalid, expired, or
/// exhausted enrollment token"). Operator-facing variance lives ONLY in
/// audit rows (variant via `enrollment_rejection_variant_name`, assembled at
/// the call site — there is no `_for_storage` detail helper here because
/// enrollment rejections carry no bound-device context to guard, unlike the
/// device-token sibling's `rejection_audit_detail_for_storage`) and
/// Prometheus counters (`enrollment_rejection_metric_name`).
///
/// **Why collapse the enrollment-token surface.** Same threat model as
/// device tokens: a presenter who can discriminate `not_found` from
/// `already_consumed` learns whether the token existed and whether
/// someone beat them to it — useful intel for token-leak triage by an
/// attacker. SOC 2 CC6.1 + the auth-architecture standing invariant
/// "every credential rejection looks identical on the wire."
///
/// **Why expand into audit + metrics.** SOC 2 CC7.2/CC7.3 require
/// attributable credential-rejection logs. The audit row carries the
/// typed variant + presenter agent_id + winning agent_id (race-loss
/// case); the Prometheus counters let SRE alert on a spike of
/// `already_consumed` (an in-progress token-leak attack) without
/// scanning audit logs.

#include <yuzu/server/auth.hpp>

#include <grpcpp/support/status.h>

#include <string_view>

namespace yuzu::server {

/// gRPC status for a failed enrollment/pending store call (WS-6 6.2), shared by
/// the direct Register and gateway ProxyRegister handlers. A store outage maps
/// to UNAVAILABLE — NOT `accepted=false`/`reject_reason`, which the agent treats
/// as a PERMANENT rejection (agent.cpp:1649-1657, #3401) — so the agent retries
/// on its normal reconnect backoff. The PG failure detail stays server-side.
/// Bad caller input (oversize / NUL / empty field) is INVALID_ARGUMENT.
[[nodiscard]] inline grpc::Status enrollment_store_status(StoreError e) {
    if (e == StoreError::InvalidInput)
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "invalid enrollment request");
    return grpc::Status(grpc::StatusCode::UNAVAILABLE, "enrollment temporarily unavailable");
}

/// Public wire message — single string regardless of variant. The Register
/// RPC's `reject_reason` field gets this value verbatim. Do not vary by
/// variant under any circumstances (the wire-collapse contract above).
inline constexpr std::string_view kEnrollmentTokenRejectionPublicMessage =
    "invalid, expired, or exhausted enrollment token";

/// Operator-facing variant name. Used in audit `detail` field and as a
/// Prometheus label value. Free of `:`, `=`, spaces — usable as a label
/// without escaping.
inline std::string_view enrollment_rejection_variant_name(auth::EnrollmentTokenError e) noexcept {
    switch (e) {
    case auth::EnrollmentTokenError::invalid_input:
        return "invalid_input";
    case auth::EnrollmentTokenError::not_found:
        return "not_found";
    case auth::EnrollmentTokenError::revoked:
        return "revoked";
    case auth::EnrollmentTokenError::expired:
        return "expired";
    case auth::EnrollmentTokenError::already_consumed:
        return "already_consumed";
    case auth::EnrollmentTokenError::internal_error:
        return "internal_error";
    }
    return "unknown";
}

/// Prometheus counter name for the rejection-variant time series. The
/// canonical W1.4 high-signal variant — `already_consumed` — gets a
/// dedicated counter so SRE can wire
///
///   rate(yuzu_enrollment_token_race_lost_total[5m]) > 0
///
/// directly without a labels selector. When that counter fires, TWO agents
/// tried to enroll with the same token within the lock window — exactly
/// the attack #827 closes. Other variants bucket under the low-signal
/// `yuzu_enrollment_token_rejected_total{variant=...}` so they remain
/// visible without flooding the page-on-call surface.
inline std::string_view enrollment_rejection_metric_name(auth::EnrollmentTokenError e) noexcept {
    switch (e) {
    case auth::EnrollmentTokenError::already_consumed:
        return "yuzu_enrollment_token_race_lost_total";
    default:
        return "yuzu_enrollment_token_rejected_total";
    }
}

/// Audit-event `action` value. Single value across variants — the detailed
/// variant lives in the `detail` field. Matches the W1.3 pattern so SIEM
/// queries can filter on one action name and pivot on `detail` for the
/// variant breakdown.
inline constexpr std::string_view kEnrollmentTokenConsumedAuditAction = "enrollment.token_consumed";

inline std::string_view enrollment_event_action() noexcept {
    return kEnrollmentTokenConsumedAuditAction;
}

} // namespace yuzu::server
