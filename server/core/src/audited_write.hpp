#pragma once

/// @file audited_write.hpp
/// The two guards every page-called mutation runs before it touches a store:
///
///   1. `WriteGate::refuse_cross_site` — a cookie-authorised write must name this
///      site in Origin/Referer (token callers are exempt; `browser_write_is_cross_site`).
///   2. `audit_attempted` — ADR-0033 section 9, "no audit row, no mutation": an
///      `attempted` row is written FIRST and a failed write refuses the change with a
///      503 A4 envelope and `Sec-Audit-Failed`. The caller writes the outcome row
///      afterwards; losing it leaves the `attempted` row standing, which reads as
///      "started, outcome unknown".
///
/// Same idiom as `NotificationRoutes::audited_mutation`; header-only so the webhook,
/// offload and directory routes share one definition. A caller whose OUTCOME row fails after the
/// change was made keeps its 2xx but marks the response `Sec-Audit-Failed` (the row is written
/// with `(void)detail::emit_behavioral_audit(...)`, whose header side effect is the signal).

#include <yuzu/server/auth.hpp>

#include "rest_a4_envelope_http.hpp" // detail::a4_error
#include "rest_audit.hpp"           // detail::emit_behavioral_audit
#include "web_utils.hpp"            // browser_write_is_cross_site

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// Same-site inputs for a route class. Unwired (the default) resolves no session, which
/// `browser_write_is_cross_site` treats as a cookie session, so the gate stays closed.
struct WriteGate {
    std::function<std::optional<auth::Session>(const httplib::Request&)> resolve_session;
    std::vector<std::string> trusted_origins;

    /// Defence in depth behind the central pre-routing gate (same_site_write_gate.hpp), which
    /// answers a cookie-session write first. Call it before any state is read or changed.
    /// Returns true when the write was refused (403 written and a `csrf.denied` row attempted).
    template <class AuditFn>
    [[nodiscard]] bool refuse_cross_site(const AuditFn& audit_fn, const httplib::Request& req,
                                         httplib::Response& res,
                                         const std::string& endpoint) const {
        std::string source;
        if (resolve_session)
            if (auto sess = resolve_session(req))
                source = sess->auth_source;
        if (!browser_write_is_cross_site(source, req.get_header_value("Host"),
                                         req.get_header_value("Origin"),
                                         req.get_header_value("Referer"), trusted_origins))
            return false;
        (void)detail::try_persist_audit(audit_fn, req, "csrf.denied", "denied", "Endpoint",
                                        endpoint, "cross-site or header-less browser write refused");
        res.status = 403;
        res.set_content(detail::a4_error(res, "cross-site request refused"), "application/json");
        return true;
    }
};

namespace detail {

/// Writes the `attempted` row. On failure answers 503 (A4 envelope, `Sec-Audit-Failed`) and
/// returns false: the caller must return without mutating.
template <class AuditFn>
[[nodiscard]] inline bool audit_attempted(const AuditFn& audit_fn, const httplib::Request& req,
                                          httplib::Response& res, const std::string& action,
                                          const std::string& target_type,
                                          const std::string& target_id,
                                          const std::string& detail_text) {
    if (emit_behavioral_audit(audit_fn, req, res, action, "attempted", target_type, target_id,
                              detail_text))
        return true;
    res.status = 503;
    res.set_content(a4_error(res, "audit log unavailable; the change was not made",
                             A4ErrorOpts{.retry_after_ms = 5000,
                                         .remediation = "retry once the audit log is available"}),
                    "application/json");
    return false;
}

} // namespace detail

} // namespace yuzu::server
