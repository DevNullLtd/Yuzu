#pragma once

/// @file same_site_write_policy.hpp
///
/// The single DECISION for "cookie-session writes require a same-site Origin or Referer".
/// Pure: no I/O, no httplib, no logging, no metrics. It plays the same role for the
/// same-site rule that `body_cap_policy.hpp` plays for the pre-auth body cap; the
/// httplib-bearing half (counter, audit row, 403 body) lives in `same_site_write_gate.hpp`.
///
/// Invariants (this banner is the canonical home; the routed-concern row points here):
///   - ONE chokepoint. `evaluate_same_site_write` is the only decision, and
///     `detail::apply_same_site_write_gate` (same_site_write_gate.hpp) is its only production
///     caller, invoked from the server's pre-routing handler after the session is resolved and
///     before any route handler runs. Coverage is by placement: every request that reaches
///     session resolution is covered, registered route or not.
///   - The decision keys on the RESOLVED session's `auth_source`, never on whether a Cookie or
///     Authorization header happens to be present. A request that resolves to a token source is
///     not riding a cookie and is not gated; one that resolves to a cookie source is gated even
///     if it also carries a token.
///   - Exemptions are the pre-session set in `is_login_exempt_path` (web_utils.hpp) plus the
///     probe paths, none of which reach the gate. No mutating registration is a probe path;
///     the route-inventory test enforces that. There is no second list. Never add another
///     early `Unhandled` return beyond the pinned exempt returns.
///   - Methods: everything except exactly GET, HEAD and OPTIONS is a write (fail closed on
///     anything else). httplib already refuses an unknown verb before pre-routing runs, so the
///     fail-closed branch here is belt and braces.
///   - The predicate is Origin and Referer only. It CALLS `browser_write_is_cross_site`
///     (web_utils.hpp) and never re-implements any branch of it. The refusal REASON is derived
///     from which headers are non-empty (both empty / Origin non-empty / Origin empty) and
///     cannot change the decision.
///   - The trusted-origin set handed to the gate is the post-`normalise_trusted_origins` set
///     (main.cpp), which drops a bare `null`; a raw, un-normalised set must never reach it.
///   - Any per-route copy of this check is defence in depth and serves unit tests that bypass
///     pre-routing; none is the authority.
///   - Two source-text tripwires pin the wiring: tests/test_same_site_wiring_lexical.py (the
///     single call site and its position) and tests/unit/server/test_same_site_exempt_inventory.cpp
///     (the bypass set). Their limits are stated in their own headers.

#include "web_utils.hpp"

#include <array>
#include <span>
#include <string>
#include <string_view>

namespace yuzu::server {

/// Closed set of refusal reasons (the metric's `reason` label; pre-seeded at boot).
inline constexpr std::string_view kSameSiteReasonNoHeaders = "no_origin_no_referer";
inline constexpr std::string_view kSameSiteReasonOriginMismatch = "origin_mismatch";
inline constexpr std::string_view kSameSiteReasonRefererMismatch = "referer_mismatch";
/// Emitted only by the gate function's exception path, never by `evaluate_same_site_write`.
inline constexpr std::string_view kSameSiteReasonGateError = "gate_error";

inline constexpr std::array<std::string_view, 4> kSameSiteDenyReasons{
    kSameSiteReasonNoHeaders,
    kSameSiteReasonOriginMismatch,
    kSameSiteReasonRefererMismatch,
    kSameSiteReasonGateError,
};

struct SameSiteDecision {
    bool refuse{false};
    std::string_view reason{}; ///< one of kSameSiteDenyReasons when `refuse`, else empty
};

/// True unless `method` is exactly "GET", "HEAD" or "OPTIONS". Case-sensitive: the request
/// line is validated against a fixed upper-case verb set before this runs, so a lower-case
/// verb is not a read.
[[nodiscard]] constexpr bool is_same_site_write_method(std::string_view method) noexcept {
    return !(method == "GET" || method == "HEAD" || method == "OPTIONS");
}

/// THE decision. `auth_source` is the resolved session's source; `host`, `origin` and `referer`
/// are the raw header values (empty when absent); `trusted_origins` is
/// `Config::csrf_trusted_origins` after `normalise_trusted_origins`.
[[nodiscard]] inline SameSiteDecision
evaluate_same_site_write(std::string_view method, std::string_view auth_source,
                         std::string_view host, std::string_view origin, std::string_view referer,
                         std::span<const std::string> trusted_origins) {
    if (!is_same_site_write_method(method))
        return {};
    if (!browser_write_is_cross_site(auth_source, host, origin, referer, trusted_origins))
        return {};
    if (origin.empty() && referer.empty())
        return {true, kSameSiteReasonNoHeaders};
    if (!origin.empty())
        return {true, kSameSiteReasonOriginMismatch};
    return {true, kSameSiteReasonRefererMismatch};
}

/// Test-pinned mirror of web_utils.hpp's literal source list, with no production caller: the
/// sources `browser_write_is_cross_site` exempts and the cookie sources it gates (auth.hpp
/// enumerates the six `auth_source` values). Pinned by the truth table: if a seventh value
/// is added, these lists and that test must be revisited deliberately. An unlisted value is
/// gated (fail closed).
inline constexpr std::array<std::string_view, 3> kTokenAuthSources{"api_token", "mcp_token",
                                                                    "engine_token"};
inline constexpr std::array<std::string_view, 3> kCookieAuthSources{"local", "oidc", "saml"};

} // namespace yuzu::server
