#pragma once

/// @file mcp_admission.hpp
///
/// Credential-class admission for /mcp/v1/ (#4309): the endpoint refuses EVERY
/// credential whose `auth::Session::mcp_tier` is empty, on all three verbs
/// (GET, POST, DELETE), before any JSON-RPC parse.
///
/// Why the rule is total (no engine exemption): the MCP tier is the first of the
/// two controls an MCP caller faces (`tier_allows`, ahead of RBAC). A cookie
/// session (local / oidc / saml) and an `api_token` minted without `mcp_tier` both
/// carry an empty tier, and an empty tier makes `tier_allows` permissive, so
/// admitting one hands a human principal the whole tool surface without the tier
/// ceiling or the approval gate. Engine tokens are store-locked to the `readonly`
/// tier at mint (`validate_engine_mint`), so a tierless engine credential is an
/// unreachable corrupt row and refusing it is fail-closed, not a regression.
///
/// Placement: `admit()` runs inside the MCP auth lambda that server.cpp hands to
/// `McpServer::register_routes`, which fans out to all three verbs, so `McpServer`
/// and its unit fixture stay untouched. The per-tool `mcp_tier.empty()` guards in
/// mcp_server.cpp and the empty-tier branches in mcp_policy.hpp remain as defence
/// in depth.
///
/// ONE entry point: `admit()` performs the refusal (audit row + counter + A4
/// response) and returns whether the request is admitted. Do not split the three
/// effects across call sites; the wiring tripwire in test_mcp_route_registration.cpp
/// pins the live `admit(` call in server.cpp.
///
/// Wire contract (frozen; docs, scripts and tests quote these strings verbatim):
///   HTTP 403, JSON-RPC code kPermissionDenied (-32003), id null, A4 error.data with
///   `correlation_id`, `retry_after_ms: null` and `remediation`, and NO `permission`
///   field (service-scope clause 5: the field would claim a self-remediation grant
///   that does not exist, since the fix is a different credential, not a role).
///   Audit: `mcp.session.reject` / `failure` / `McpSession` / empty target_id /
///   `reason=tier_required auth_source=<bounded> cid=<cid>`, set-and-proceed (a failed
///   audit write never changes the refusal).
///   Counter: `yuzu_mcp_admission_refused_total{reason="tier_required"}`.

#include "mcp_jsonrpc.hpp"      // error_response_null_a4, kPermissionDenied
#include "rest_a4_envelope.hpp" // detail::make_correlation_id
#include "rest_audit.hpp"       // detail::try_persist_audit

#include <httplib.h>
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <functional>
#include <string>
#include <string_view>

namespace yuzu::server::mcp {

/// Same signature as `McpServer::AuditFn` (spelled out so this header does not depend
/// on mcp_server.hpp). A std::function, not a template parameter: the audit kernel
/// tests the hook for emptiness, which a bare lambda cannot answer.
using AdmissionAuditFn =
    std::function<bool(const httplib::Request&, const std::string& action, const std::string& result,
                       const std::string& target_type, const std::string& target_id,
                       const std::string& detail)>;

inline constexpr std::string_view kTierRequiredReason = "tier_required";
inline constexpr std::string_view kTierRequiredMessage =
    "/mcp/v1/ requires an MCP-tier bearer token";
inline constexpr std::string_view kTierRequiredRemediation =
    "mint an API token with mcp_tier readonly, operator or supervised (POST /api/v1/tokens "
    "with expires_at, or Settings > API tokens) and send it as Authorization: Bearer; do not "
    "send a session cookie with it";
inline constexpr std::string_view kAdmissionRefusedMetric = "yuzu_mcp_admission_refused_total";
inline constexpr std::string_view kSessionRejectAction = "mcp.session.reject";

/// True when the session must be refused at /mcp/v1/ admission: it carries no MCP
/// tier. Total over every principal kind (cookie sessions, tierless API tokens and,
/// fail-closed, a tierless engine row).
[[nodiscard]] inline bool requires_tiered_credential(const auth::Session& s) noexcept {
    return s.mcp_tier.empty();
}

/// `Session::auth_source` is a closed server-side set, but it reaches an audit
/// detail, so bound it anyway: anything outside the known values reads "other".
[[nodiscard]] inline std::string_view bounded_auth_source(std::string_view source) noexcept {
    for (const std::string_view known :
         {"local", "oidc", "saml", "api_token", "mcp_token", "engine_token"}) {
        if (source == known)
            return known;
    }
    return "other";
}

/// Write the 403 / -32003 refusal. Split from `admit()` so the envelope is
/// assertable on its own; production code reaches it only through `admit()`.
inline void write_tier_required(httplib::Response& res, const std::string& cid) {
    res.status = 403;
    res.set_content(error_response_null_a4(kPermissionDenied, kTierRequiredMessage, cid,
                                           kTierRequiredRemediation),
                    "application/json");
}

/// Admission decision for an authenticated /mcp/v1/ request. Returns true when the
/// request may proceed; on false the refusal (audit row, counter, response) has
/// already been performed and the caller must return without touching `res` again.
/// An admitted request writes nothing: no audit row, no counter, no response.
///
/// `audit_fn` is the server's `audit_log` hook (bool(req, action, result, target_type,
/// target_id, detail)); a null function or a failed write is NOT a reason to admit.
/// `metrics` may be null (a test or an embedder without a registry).
[[nodiscard]] inline bool admit(const auth::Session& session, const httplib::Request& req,
                                httplib::Response& res, const AdmissionAuditFn& audit_fn,
                                yuzu::MetricsRegistry* metrics) {
    if (!requires_tiered_credential(session))
        return true;

    const auto cid = yuzu::server::detail::make_correlation_id();
    std::string detail = "reason=";
    detail += kTierRequiredReason;
    detail += " auth_source=";
    detail += bounded_auth_source(session.auth_source);
    detail += " cid=";
    detail += cid;
    (void)yuzu::server::detail::try_persist_audit(audit_fn, req, std::string{kSessionRejectAction},
                                                  "failure", "McpSession", std::string{}, detail);
    if (metrics != nullptr) {
        metrics
            ->counter(std::string{kAdmissionRefusedMetric},
                      {{"reason", std::string{kTierRequiredReason}}})
            .increment();
    }
    write_tier_required(res, cid);
    return false;
}

} // namespace yuzu::server::mcp
