#pragma once

/// @file same_site_write_gate.hpp
///
/// The ONE named gate function for "cookie-session writes require a same-site Origin or
/// Referer": the production pre-routing handler calls it once, and the integration tests call
/// the same function. It owns the decision call (same_site_write_policy.hpp), the bounded
/// counter, the throttled warning, the `csrf.denied` audit row, the A4 403 body and the
/// `Sec-Audit-Failed` header, inside one whole-body `try/catch(...)`. Its first statement is
/// the method check: a read method returns false before the `try` and before any header is
/// copied, so a read pays nothing.
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
///     headers. A request that carries a cookie plus an Authorization header can therefore be
///     stamped with a different class here than a request-time row built by
///     `make_audit_event` (which stamps the class from the request's headers); this row names
///     the credential that was actually adjudicated.
///   - The audit detail is fixed text plus one closed-set reason token (the decision's reason);
///     no header bytes reach the audit log. The `gate_error` path writes no row.
///   - The 403 body is the A4 envelope with a `remediation` and no `permission` field: the
///     refusal does not name a grant that would not, by itself, admit the caller.
///
/// Exception-path contract (every refusal is counted exactly once):
///   Normal path, in order, inside one `try`: decide; audit row; `Sec-Audit-Failed` when the
///   row was not persisted; increment the counter for the decision's reason exactly once;
///   time-throttled warning (at most one per 60 s per reason); status 403 and the A4 body.
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

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
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
    "Send an Origin or Referer header naming this site, or authenticate with an API token. "
    "Behind a reverse proxy that rewrites Host, declare the public origin with "
    "--csrf-trusted-origin (or YUZU_CSRF_TRUSTED_ORIGIN) and restart; see "
    "docs/user-manual/server-admin.md.";
/// Last-resort body when the A4 envelope cannot be rendered. Constant, no per-request bytes.
inline constexpr std::string_view kSameSiteDenyFallbackBody =
    R"({"error":{"code":403,"message":"cross-site request refused"}})";

/// Minimum spacing between two warnings of the same reason.
inline constexpr std::int64_t kSameSiteLogIntervalNs = 60LL * 1'000'000'000LL;

/// Time-based log throttle: at most ONE warning per interval PER SLOT, so this gate's own
/// warnings are rate limited (the counter still records every refusal). Logging by downstream
/// audit-failure paths is separate and not throttled here. One slot per refusal reason plus
/// one for `gate_error`, so a flood of one reason cannot silence the first warning of another.
/// The first call on a slot since process start always passes. Lock-free, allocation-free and noexcept: it runs on the refusal path
/// and inside the gate's `catch (...)`. The clock is a parameter so the unit test is
/// deterministic; the production wrapper below reads `steady_clock`.
class SameSiteLogThrottle {
  public:
    static constexpr std::size_t kSlots = 4; ///< matches kSameSiteDenyReasons

    SameSiteLogThrottle() noexcept {
        for (auto& a : last_)
            a.store(kNever, std::memory_order_relaxed);
    }

    /// True when a warning on `slot` is allowed at `now_ns`; records it as logged. An
    /// out-of-range slot is folded into the last (`gate_error`) slot. Precondition: `now_ns` is
    /// non-negative monotonic nanoseconds (production passes steady_clock readings); INT64_MIN
    /// is the "never logged" sentinel and is refused (false) rather than recorded.
    [[nodiscard]] bool allow(std::size_t slot, std::int64_t now_ns) noexcept {
        if (now_ns == kNever)
            return false;
        auto& a = last_[slot < kSlots ? slot : kSlots - 1];
        auto last = a.load(std::memory_order_relaxed);
        if (last != kNever && now_ns - last < kSameSiteLogIntervalNs)
            return false;
        // One concurrent caller wins the slot; a loser has just been out-logged.
        return a.compare_exchange_strong(last, now_ns, std::memory_order_relaxed);
    }

  private:
    static constexpr std::int64_t kNever = std::numeric_limits<std::int64_t>::min();
    static_assert(std::atomic<std::int64_t>::is_always_lock_free);
    std::array<std::atomic<std::int64_t>, kSlots> last_;
};
static_assert(SameSiteLogThrottle::kSlots == kSameSiteDenyReasons.size(),
              "one throttle slot per refusal reason");

/// Index into the throttle for a decision reason; an unknown reason maps to `gate_error`.
[[nodiscard]] constexpr std::size_t same_site_log_slot(std::string_view reason) noexcept {
    for (std::size_t i = 0; i < kSameSiteDenyReasons.size(); ++i)
        if (kSameSiteDenyReasons[i] == reason)
            return i;
    return kSameSiteDenyReasons.size() - 1;
}

/// Production throttle: one process-wide instance, `steady_clock` time.
[[nodiscard]] inline bool same_site_log_this_one(std::string_view reason) noexcept {
    static SameSiteLogThrottle throttle;
    const auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                         std::chrono::steady_clock::now().time_since_epoch())
                         .count();
    return throttle.allow(same_site_log_slot(reason), now);
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
    // First statement, before the try and before any header copy: a read method is never gated.
    if (!is_same_site_write_method(req.method))
        return false;

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

        // The detail is FIXED text plus the closed-set reason token: no header bytes reach the
        // audit log.
        audit_attempted = true;
        audit_persisted = try_persist_audit_for_principal(
            audit, req, "csrf.denied", "denied",
            SameSiteAuditPrincipal{session.username,
                                   auth::role_to_string(auth::effective_role(session)),
                                   session.principal_kind},
            "Endpoint", onbehalf::sanitize_for_log(req.method, 16) + " " +
                            onbehalf::sanitize_for_log(req.path),
            std::string("cross-site or header-less browser write refused; reason=") +
                std::string(decision.reason));
        if (!audit_persisted)
            mark_audit_failed();

        count(decision.reason);
        counted = true;
        fault(SameSiteFaultPoint::kAfterCount);

        // Never log header VALUES: Origin and Referer can carry anything.
        if (same_site_log_this_one(decision.reason)) {
            spdlog::warn("same-site gate refused {} {} from {} for a cookie session ({}); a "
                         "script must send a same-site Origin or Referer or use an API token, a "
                         "Host-rewriting proxy needs --csrf-trusted-origin (at most one log "
                         "per 60 s per reason; the counter records all)",
                         onbehalf::sanitize_for_log(req.method, 16),
                         onbehalf::sanitize_for_log(req.path),
                         onbehalf::sanitize_for_log(req.remote_addr, 64), decision.reason);
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
            if (same_site_log_this_one(kSameSiteReasonGateError))
                spdlog::warn("same-site gate hit an internal error; the request was refused "
                             "(at most one log per 60 s per reason; the counter records all)");
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
