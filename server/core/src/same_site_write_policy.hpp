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
///     fail-closed branch here is belt and braces. A GET or HEAD on a path in
///     `kFetchMetadataGuardedPaths` is held to the same rule: same-origin or none fetch metadata
///     admits it, any other fetch metadata refuses it, and a request without fetch metadata
///     falls back to the Origin and Referer rule. Prefetch and prerender by the user's own
///     browser carry same-origin metadata and are not prevented.
///   - For a write the predicate is Origin and Referer only. It CALLS `browser_write_is_cross_site`
///     (web_utils.hpp) and never re-implements any branch of it. The refusal REASON is derived
///     from which headers are non-empty (both empty / Origin non-empty / Origin empty) and
///     cannot change the decision.
///   - The same-host comparison is scheme-aware when the listener terminates TLS itself
///     (`listener_is_tls`, the web listener's `Config::https_enabled`): the source must be
///     `https://`. Behind a TLS-terminating proxy the scheme is invisible to the server, so the
///     operator declares the public origin WITH its `https://` scheme in `--csrf-trusted-origin`,
///     which refuses a plain-http origin for that host. Without that declaration a plain-http
///     origin for the same host and port is still treated as same-site (documented residual).
///     The parameter is passed explicitly at the one production call site and has no default
///     on the decision or the gate.
///   - The trusted-origin set handed to the gate is the post-`normalise_trusted_origins` set
///     (main.cpp), which drops a bare `null`; a raw, un-normalised set must never reach it.
///   - Any per-route copy of this check is defence in depth and serves unit tests that bypass
///     pre-routing; none is the authority.
///   - The wiring is pinned by a live-stack assertion in scripts/e2e-security-test.sh (the closure
///     evidence for production) and by two best-effort source-text tripwires:
///     tests/test_same_site_wiring_lexical.py (the single call site and its position) and
///     tests/unit/server/test_same_site_exempt_inventory.cpp (the bypass set). The tripwires are
///     not proof; their limits are stated in their own headers.

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

/// Reviewed set of read paths (exact match, no prefix, no query) that dispatch work or persist
/// or refresh server state and are held to the same rule as a write. Executable data: a new
/// cookie-reachable GET that dispatches work or changes state needs an entry here
/// (tests/unit/server/test_same_site_exempt_inventory.cpp is the best-effort tripwire). A path
/// reachable with a token as well as a cookie stays open to the token caller (see the
/// decision below); only a cookie session is held to the rule.
inline constexpr std::array<std::string_view, 10> kFetchMetadataGuardedPaths{
    "/fragments/device/live/run",
    "/fragments/echo/process-tree/run",
    "/fragments/echo/process-tree/device-net",
    "/fragments/echo/capture-sources/load",
    "/fragments/dex/device/perf",
    "/fragments/dex/device/procperf",
    "/fragments/auto/deploy/result",
    "/fragments/auto/result",
    "/fragments/viz/fleet/topology",
    "/api/v1/viz/fleet/topology",
};

/// The two leading prefixes `is_guarded_read` uses as its cheap prefilter. Every table entry
/// must start with one of them, or the prefilter would silently skip that entry.
inline constexpr std::string_view kGuardedPrefixFragments = "/fragments/";
inline constexpr std::string_view kGuardedPrefixViz = "/api/v1/viz/";

[[nodiscard]] constexpr bool has_guarded_prefix(std::string_view path) noexcept {
    return path.starts_with(kGuardedPrefixFragments) || path.starts_with(kGuardedPrefixViz);
}

static_assert(kFetchMetadataGuardedPaths.size() == 10,
              "adding or removing a guarded path is a reviewed change: update the pinned count "
              "and the literal content pin in test_same_site_write_policy.cpp together");

namespace detail {
[[nodiscard]] constexpr bool guarded_table_is_well_formed() noexcept {
    for (std::size_t i = 0; i < kFetchMetadataGuardedPaths.size(); ++i) {
        const auto p = kFetchMetadataGuardedPaths[i];
        // Every entry must pass the prefilter below, have something after the prefix, and be an
        // exact path (no trailing slash, no query).
        if (!has_guarded_prefix(p) || p.back() == '/' || p.find('?') != std::string_view::npos)
            return false;
        for (std::size_t j = i + 1; j < kFetchMetadataGuardedPaths.size(); ++j)
            if (kFetchMetadataGuardedPaths[j] == p)
                return false;
    }
    return true;
}
} // namespace detail
static_assert(detail::guarded_table_is_well_formed(),
              "every guarded path must start with a prefilter prefix (is_guarded_read skips any "
              "other), be unique, and be exact: no trailing '/' and no '?'");

/// True for GET or HEAD (httplib routes HEAD to the GET handlers) on a path in the table.
/// Case-sensitive. The prefix compare keeps the common read to one cheap check; it is coupled
/// to the table by the static_assert above.
[[nodiscard]] constexpr bool is_guarded_read(std::string_view method,
                                             std::string_view path) noexcept {
    if (method != "GET" && method != "HEAD")
        return false;
    if (!has_guarded_prefix(path))
        return false;
    for (const auto p : kFetchMetadataGuardedPaths)
        if (p == path)
            return true;
    return false;
}

namespace detail {
[[nodiscard]] constexpr bool ascii_ieq(std::string_view a, std::string_view lower) noexcept {
    if (a.size() != lower.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const char c = (a[i] >= 'A' && a[i] <= 'Z') ? static_cast<char>(a[i] - 'A' + 'a') : a[i];
        if (c != lower[i])
            return false;
    }
    return true;
}
} // namespace detail

/// THE decision. `auth_source` is the resolved session's source; `host`, `origin` and `referer`
/// are the raw header values (empty when absent); `trusted_origins` is
/// `Config::csrf_trusted_origins` after `normalise_trusted_origins`. `listener_is_tls` is the
/// web listener's TLS state (`Config::https_enabled`): it selects the scheme-aware same-host
/// comparison documented on `origin_is_same_site`. `path` and `sec_fetch_site` (the raw
/// `Sec-Fetch-Site` value, empty when absent; the gate passes a fixed non-matching sentinel when
/// the header is repeated) apply to a guarded read only: a non-empty value other than
/// same-origin or none is refused, and an empty one falls back to the Origin and Referer rule. Neither `listener_is_tls`, `path` nor `sec_fetch_site` has a default here, so
/// a new caller must decide them.
[[nodiscard]] inline SameSiteDecision
evaluate_same_site_write(std::string_view method, std::string_view auth_source,
                         std::string_view host, std::string_view origin, std::string_view referer,
                         std::span<const std::string> trusted_origins, bool listener_is_tls,
                         std::string_view path, std::string_view sec_fetch_site) {
    if (is_same_site_write_method(method)) {
        if (!browser_write_is_cross_site(auth_source, host, origin, referer, trusted_origins,
                                           listener_is_tls))
            return {};
    } else {
        if (!is_guarded_read(method, path))
            return {};
        if (auth_source == "api_token" || auth_source == "mcp_token" ||
            auth_source == "engine_token")
            return {};
        if (!sec_fetch_site.empty()) {
            if (detail::ascii_ieq(sec_fetch_site, "same-origin") ||
                detail::ascii_ieq(sec_fetch_site, "none"))
                return {};
            return {true, kSameSiteReasonOriginMismatch};
        }
        if (!browser_write_is_cross_site(auth_source, host, origin, referer, trusted_origins,
                                           listener_is_tls))
            return {};
    }
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
