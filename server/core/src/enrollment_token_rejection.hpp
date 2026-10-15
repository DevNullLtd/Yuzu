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

#include <string>
#include <string_view>

namespace yuzu::server {

/// Exact wire shape of an enrollment token: 64 lowercase hex characters (a
/// 32-byte CSPRNG value through `AuthManager::bytes_to_hex`). THE single
/// predicate for both Register and ProxyRegister (WS-6 6.2): a token that fails
/// it cannot exist, so the handlers reject it WITHOUT touching the store — an
/// unauthenticated caller must not be able to turn arbitrary junk into a Postgres
/// write transaction each (pre-auth amplification). No negative cache: the check
/// is O(64) and stateless. A shape-invalid token is answered EXACTLY like a
/// well-formed token that matched nothing (`not_found` audit/metric class,
/// the uniform public message) so the shape check is not an oracle.
[[nodiscard]] inline bool enrollment_token_shape_valid(std::string_view token) noexcept {
    if (token.size() != 64)
        return false;
    for (const char c : token) {
        const bool digit = c >= '0' && c <= '9';
        const bool lower_hex = c >= 'a' && c <= 'f';
        if (!digit && !lower_hex)
            return false;
    }
    return true;
}

/// Sanitize an AGENT-SUPPLIED descriptive string (hostname / os / arch /
/// agent_version, and the "auto-approve:<rule>" attribution) before it reaches
/// the enrollment store: drop embedded NUL bytes and other ASCII control
/// characters (0x00-0x1F, 0x7F — `\n`/`\r` in particular could otherwise forge
/// additional lines in a plain-string audit/log detail once these fields reach
/// one) and truncate to `auth::kMaxEnrollmentTextLength` on a UTF-8
/// code-point boundary. The store REJECTS out-of-bounds text
/// (`StoreError::InvalidInput`); doing that at Register would turn a long or
/// odd hostname into a permanent INVALID_ARGUMENT that strands an otherwise-
/// legitimate agent forever. These fields are descriptive only (identity is
/// `agent_id`, which keeps its own hard reject on the same control-character
/// class — see `agent_id_ok` in auth_db.cpp — because `agent_id` also feeds a
/// comma-joined bulk-audit-detail list, which no field here does today), so
/// lossy sanitising is the safe direction. Shared by Register + ProxyRegister.
[[nodiscard]] inline std::string sanitize_enrollment_text(std::string_view s) {
    std::string out;
    out.reserve(s.size() < auth::kMaxEnrollmentTextLength ? s.size()
                                                          : auth::kMaxEnrollmentTextLength);
    for (const char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (u > 0x1FU && u != 0x7FU)
            out.push_back(c);
    }
    if (out.size() > auth::kMaxEnrollmentTextLength) {
        std::size_t cut = auth::kMaxEnrollmentTextLength;
        // Back off any UTF-8 continuation bytes (10xxxxxx) so we never split a
        // multi-byte character.
        while (cut > 0 && (static_cast<unsigned char>(out[cut]) & 0xC0U) == 0x80U)
            --cut;
        out.resize(cut);
    }
    return out;
}

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
