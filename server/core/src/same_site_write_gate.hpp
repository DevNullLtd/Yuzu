#pragma once

/// @file same_site_write_gate.hpp
///
/// The ONE named gate function for "cookie-session writes require a same-site Origin or
/// Referer": the production pre-routing handler calls it once, and the integration tests call
/// the same function. It owns the decision call (same_site_write_policy.hpp), the bounded
/// counter, the throttled warning, the `csrf.denied` audit row, the A4 403 body and the
/// `Sec-Audit-Failed` header, inside one whole-body `try/catch(...)`.
///
/// Contract:
///   - Returns true when the request was refused and `res` is populated; false otherwise.
///     Never throws. This matters because the pre-routing handler is reachable from httplib's
///     WebSocket-upgrade path outside any try/catch of its own.
///   - Runs after authentication and before authorization, step-up and the route handler. It
///     uses the session the caller already resolved and never resolves a second one. It does
///     not read, set or consume any step-up state.
///   - The audit actor is stamped from that held session, including the principal class
///     (`session.principal_kind`), not re-derived from the request's credential-presentation
///     headers. A request-time row for the same actor therefore carries the same class.
///   - The 403 body is the A4 envelope with a `remediation` and no `permission` field: the
///     refusal does not name a grant that would not, by itself, admit the caller.
///
/// Exception-path contract (every refusal is counted exactly once):
///   Normal path, in order, inside one `try`: decide; audit row; `Sec-Audit-Failed` when the
///   row was not persisted; increment the counter for the decision's reason exactly once;
///   throttled warning; status 403 and the A4 body.
///   `catch (...)`: `res.status = 403` first (a plain assignment, so the refusal stands even if
///   everything below throws); then, each in its own nested `try`: increment the `gate_error`
///   series only if the counter was not already incremented (never both series for one
///   request); set `Sec-Audit-Failed` when the audit row was not attempted or not persisted
///   (the evidence is missing either way); render the A4 body, else a short constant body,
///   else leave the status-only response. Nothing escapes. "Allocation-free" is not achievable
///   with httplib's `set_content`; the contract is that the status is assigned before any
///   allocation, and every later allocation sits in its own `try`.
///
/// Test-only fault hook: an optional last parameter lets a test throw at three points of the
/// normal path (`SameSiteFaultPoint`). Production passes nothing.

#include "body_cap_policy.hpp"
#include "on_behalf_guard.hpp"
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"
#include "same_site_write_policy.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>

namespace yuzu::server::detail {

/// The actor stamped on the `csrf.denied` row, captured from the session the pre-routing
/// handler already resolved. A struct rather than three strings: the audit helper's
/// `static_assert` checks arity and return type only, so transposed same-typed string
/// parameters would otherwise compile.
struct SameSiteAuditPrincipal {
    std::string id;   ///< session.username, the stable authorization principal
    std::string role; ///< role_to_string(effective_role(session)), as request-time rows stamp
    std::string cls;  ///< session.principal_kind
};

using SameSitePrincipalAuditFn = std::function<bool(
    const httplib::Request&, const std::string& action, const std::string& result,
    const SameSiteAuditPrincipal& principal, const std::string& target_type,
    const std::string& target_id, const std::string& detail)>;

/// Points of the normal path at which a test can inject a throw.
enum class SameSiteFaultPoint {
    kBeforeAudit, ///< after the decision, before the audit row is attempted
    kAfterCount,  ///< after the counter increment, before the response is built
    kInRender,    ///< immediately before each attempt to render the A4 body
};
using SameSiteFaultHook = std::function<void(SameSiteFaultPoint)>;

inline constexpr std::string_view kSameSiteDeniedCounter = "yuzu_server_csrf_denied_total";
inline constexpr std::string_view kSameSiteDenyMessage = "cross-site request refused";
inline constexpr std::string_view kSameSiteDenyRemediation =
    "send an Origin or Referer header naming this site, authenticate with an API token, or, "
    "behind a reverse proxy that rewrites Host, declare the public origin with "
    "--csrf-trusted-origin (docs/user-manual/server-admin.md)";
/// Last-resort body when the A4 envelope cannot be rendered. Constant, no per-request bytes.
inline constexpr std::string_view kSameSiteDenyFallbackBody =
    R"({"error":{"code":403,"message":"cross-site request refused"}})";

/// True on the first call and on every `onbehalf::kLogEvery`-th after it, so a refusal flood
/// can never become a disk-fill amplifier through per-request warnings (the counter still
/// records every refusal). One process-wide throttle, shared by both log sites below.
[[nodiscard]] inline bool same_site_log_this_one() noexcept {
    static std::atomic<std::uint64_t> hits{0};
    return hits.fetch_add(1, std::memory_order_relaxed) % onbehalf::kLogEvery == 0;
}

/// Refuse a cookie-session write that carries no same-site Origin or Referer. Returns true
/// when the request was refused (`res` fully populated: 403, A4 body, X-Correlation-Id, and
/// `Sec-Audit-Failed` when the audit row was lost). Never throws.
[[nodiscard]] inline bool
apply_same_site_write_gate(const httplib::Request& req, httplib::Response& res,
                           const auth::Session& session,
                           std::span<const std::string> trusted_origins,
                           yuzu::MetricsRegistry& metrics, const SameSitePrincipalAuditFn& audit,
                           const SameSiteFaultHook* fault_hook = nullptr) noexcept {
    bool audit_attempted = false;
    bool audit_persisted = false;
    bool counted = false;

    const auto fault = [fault_hook](SameSiteFaultPoint p) {
        if (fault_hook != nullptr && *fault_hook)
            (*fault_hook)(p);
    };
    // The bounded label: the raw path is attacker-controlled and is never a label.
    const auto count = [&](std::string_view reason) {
        metrics
            .counter(std::string(kSameSiteDeniedCounter),
                     {{"path_class", std::string(resolve_body_cap(req.method, req.path).path_class)},
                      {"reason", std::string(reason)}})
            .increment();
    };
    const auto mark_audit_failed = [&res] {
        if (!res.has_header("Sec-Audit-Failed"))
            res.set_header("Sec-Audit-Failed", "true");
    };
    const auto render_a4 = [&] {
        fault(SameSiteFaultPoint::kInRender);
        res.set_content(a4_denial(res, 403, kSameSiteDenyMessage,
                                  A4ErrorOpts{.remediation = kSameSiteDenyRemediation}),
                        "application/json");
    };

    try {
        const auto decision = evaluate_same_site_write(
            req.method, session.auth_source, req.get_header_value("Host"),
            req.get_header_value("Origin"), req.get_header_value("Referer"), trusted_origins);
        if (!decision.refuse)
            return false;

        fault(SameSiteFaultPoint::kBeforeAudit);

        // The detail is FIXED text: no header bytes reach the audit log.
        audit_attempted = true;
        audit_persisted = try_persist_audit_for_principal(
            audit, req, "csrf.denied", "denied",
            SameSiteAuditPrincipal{session.username,
                                   auth::role_to_string(auth::effective_role(session)),
                                   session.principal_kind},
            "Endpoint", onbehalf::sanitize_for_log(req.method, 16) + " " +
                            onbehalf::sanitize_for_log(req.path),
            "cross-site or header-less browser write refused");
        if (!audit_persisted)
            mark_audit_failed();

        count(decision.reason);
        counted = true;
        fault(SameSiteFaultPoint::kAfterCount);

        // Never log header VALUES: Origin and Referer can carry anything.
        if (same_site_log_this_one()) {
            spdlog::warn("same-site gate refused {} {} from {} for a cookie session ({}); a "
                         "script must send a same-site Origin or Referer or use an API token, a "
                         "Host-rewriting proxy needs --csrf-trusted-origin (1 log per {} "
                         "refusals; the counter records all)",
                         onbehalf::sanitize_for_log(req.method, 16),
                         onbehalf::sanitize_for_log(req.path),
                         onbehalf::sanitize_for_log(req.remote_addr, 64), decision.reason,
                         onbehalf::kLogEvery);
        }

        res.status = 403;
        render_a4();
        return true;
    } catch (...) {
        // Fail closed. The status assignment comes first and cannot throw; every allocation
        // after it sits in its own try so nothing below can lose the refusal.
        res.status = 403;
        try {
            if (!counted)
                count(kSameSiteReasonGateError);
        } catch (...) {
        }
        try {
            if (!audit_attempted || !audit_persisted)
                mark_audit_failed();
        } catch (...) {
        }
        try {
            if (same_site_log_this_one())
                spdlog::warn("same-site gate hit an internal error; the request was refused");
        } catch (...) {
        }
        try {
            render_a4();
        } catch (...) {
            try {
                res.set_content(std::string(kSameSiteDenyFallbackBody), "application/json");
            } catch (...) {
            }
        }
        return true;
    }
}

} // namespace yuzu::server::detail
