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
/// Placement: `admit()` runs inside the auth hook that server.cpp builds with
/// `make_admission_auth_fn()` and hands to `McpServer::register_routes`, which fans
/// out to all three verbs, so `McpServer`
/// and its unit fixture stay untouched. The per-tool `mcp_tier.empty()` guards in
/// mcp_server.cpp and the empty-tier branches in mcp_policy.hpp remain as defence
/// in depth.
///
/// `admit()` performs the refusal (audit row + counter + A4 response) and returns
/// whether the request is admitted; do not split the three effects across call sites.
/// `make_admission_auth_fn()` is the ONE place production composes it with the session
/// resolver; server.cpp passes its result to `register_routes`. test_mcp_admission.cpp
/// drives the real routes through that factory on all three verbs, and a source check in
/// test_mcp_route_registration.cpp pins that server.cpp builds its auth hook with it.
///
/// A non-empty tier is NOT validated here: an unknown tier ("bogus") is admitted and
/// the downstream `tier_allows` gate decides what it may do.
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
///
/// Audit-row budget (the refusal and the counter are NEVER sampled; only the row is):
/// a tierless client looping on /mcp/v1/ would otherwise write one synchronous audit row
/// per refusal on an httplib worker. Rows go through the shared `DenialAuditBudget`
/// (bounded_audit_budget.hpp; the gateway peer guard is the precedent): keyed
/// `tier_required|<bounded auth_source>|<principal>`, so one principal's flood spends only
/// its own rows and cannot starve another principal's evidence row, and the FIRST refusal
/// of every key always writes its row. The counter stays complete, so suppressed rows are
/// still visible as a number, and the window-opening call logs one aggregate count line.

#include "bounded_audit_budget.hpp" // DenialAuditBudget, the default limits
#include "mcp_jsonrpc.hpp"      // error_response_null_a4, kPermissionDenied
#include "rest_a4_envelope.hpp" // detail::make_correlation_id
#include "rest_audit.hpp"       // detail::try_persist_audit

#include <httplib.h>
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <spdlog/spdlog.h>

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

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
    "mint an API token with mcp_tier readonly, operator or supervised and an expires_at at "
    "most 90 days out (POST /api/v1/tokens, or Settings > API tokens), then send it as "
    "Authorization: Bearer; do not send a session cookie with it";
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
/// The sibling list is `step_up_source_label` (step_up_gate.cpp); test_mcp_admission.cpp
/// locks the two together, so extend them as a pair.
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

/// Longest principal (session username) bytes kept in the audit-budget key. With the
/// `tier_required|<source>|` prefix (at most 27 bytes) the whole key stays inside the budget's
/// own 96-byte bound, so the principal is never cut by the budget's truncation.
inline constexpr std::size_t kAdmissionBudgetPrincipalBytes = 64;

/// The audit-budget key for a refusal: `tier_required|<bounded auth_source>|<principal>`.
/// Built only from a closed reason, a closed source label and the principal's own username,
/// and used only as a map key: it is never logged, audited or put on the wire.
[[nodiscard]] inline std::string admission_budget_key(const auth::Session& session) {
    std::string key{kTierRequiredReason};
    key += '|';
    key += bounded_auth_source(session.auth_source);
    key += '|';
    key += std::string_view{session.username}.substr(0, kAdmissionBudgetPrincipalBytes);
    return key;
}

/// Admission decision for an authenticated /mcp/v1/ request. Returns true when the
/// request may proceed; on false the refusal (audit row, counter, response) has
/// already been performed and the caller must return without touching `res` again.
/// An admitted request writes nothing: no audit row, no counter, no response, and it never
/// touches `budget`.
///
/// A refusal is unconditional and ALWAYS counted (the counter is unsampled). The audit row
/// is the only effect the budget bounds: it is written only when `budget.try_admit(key)`
/// admits, where the key separates principals, so one looping client cannot spend another's
/// evidence row and cannot turn its own refusals into unbounded synchronous audit-store
/// writes on an httplib worker. The call that opens a new budget window logs one aggregate
/// line with how many rows the closed window suppressed (a count only, no caller content).
///
/// `audit_fn` is the server's `audit_log` hook (bool(req, action, result, target_type,
/// target_id, detail)); a null function or a failed write is NOT a reason to admit.
/// `metrics` may be null (a test or an embedder without a registry).
[[nodiscard]] inline bool admit(const auth::Session& session, const httplib::Request& req,
                                httplib::Response& res, const AdmissionAuditFn& audit_fn,
                                yuzu::MetricsRegistry* metrics, DenialAuditBudget& budget) {
    if (!requires_tiered_credential(session))
        return true;

    const auto cid = yuzu::server::detail::make_correlation_id();
    const auto row = budget.try_admit(admission_budget_key(session),
                                      std::string{kTierRequiredReason} + "|*");
    if (row.closed_window_suppressed > 0) {
        spdlog::warn("mcp admission: {} tier_required audit rows suppressed in the last window "
                     "(yuzu_mcp_admission_refused_total is complete)",
                     row.closed_window_suppressed);
    }
    if (row.admitted) {
        std::string detail = "reason=";
        detail += kTierRequiredReason;
        detail += " auth_source=";
        detail += bounded_auth_source(session.auth_source);
        detail += " cid=";
        detail += cid;
        (void)yuzu::server::detail::try_persist_audit(
            audit_fn, req, std::string{kSessionRejectAction}, "failure", "McpSession",
            std::string{}, detail);
    }
    if (metrics != nullptr) {
        metrics
            ->counter(std::string{kAdmissionRefusedMetric},
                      {{"reason", std::string{kTierRequiredReason}}})
            .increment();
    }
    write_tier_required(res, cid);
    return false;
}

/// Same shape as `McpServer::AuthFn` (spelled out so this header does not depend on
/// mcp_server.hpp).
using AdmissionAuthFn =
    std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;

/// The PRODUCTION auth hook for /mcp/v1/: wraps the server's session resolver with
/// admission. The returned callable resolves the session via `require_auth` (which has
/// already written its own 401 on failure), then runs `admit()` against the SAME request,
/// response and resolved session; a refusal yields nullopt (the 403 is already written),
/// an admitted request yields the session. server.cpp passes the result as
/// `register_routes`' auth hook, so all three verbs share this one gate; a harness that
/// passes a bare resolver lacks the rule. `audit` and `metrics` are captured once at
/// registration and must outlive the registered routes.
///
/// The factory owns the audit-row budget (one per registration, shared by the three verbs,
/// held by the returned callable; the budget is thread-safe). It uses the primitive's default
/// limits, the same as the gateway peer guard: at most `kDefaultAuditMaxRows` (10) rows per
/// key per `kDefaultAuditWindowMs` (10 s) window, at most `kDefaultAuditMaxKeys` (64) live
/// keys, overflow keys sharing `tier_required|*`. `now_ms` is the budget's clock, injectable
/// so tests need no sleeps; null selects steady_clock.
[[nodiscard]] inline AdmissionAuthFn
make_admission_auth_fn(AdmissionAuthFn require_auth, AdmissionAuditFn audit,
                       yuzu::MetricsRegistry* metrics, DenialAuditBudget::NowMsFn now_ms = {}) {
    auto budget = std::make_shared<DenialAuditBudget>(
        kDefaultAuditMaxRows, kDefaultAuditWindowMs, std::move(now_ms), kDefaultAuditMaxKeys);
    return [require_auth = std::move(require_auth), audit = std::move(audit), metrics,
            budget = std::move(budget)](const httplib::Request& req,
                                        httplib::Response& res) -> std::optional<auth::Session> {
        auto session = require_auth(req, res);
        if (!session)
            return std::nullopt;
        if (!admit(*session, req, res, audit, metrics, *budget))
            return std::nullopt;
        return session;
    };
}

} // namespace yuzu::server::mcp
