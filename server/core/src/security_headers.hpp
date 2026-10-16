// security_headers.hpp — HTTP security response header construction (SOC2-C1).
//
// Pure helpers that build the response-header values applied to every HTTP
// response by the post-routing handlers: server.cpp's main listener and
// health_routes.cpp's plain-HTTP listener (install_plaintext_post_routing).
// Extracted from server.cpp so the logic is unit-testable in isolation and so
// the post-routing handlers stay focused on dispatch rather than string
// construction.

#pragma once

#include <expected>
#include <string>
#include <string_view>

namespace httplib {
struct Response;
}

namespace yuzu::server::security {

// ── Validation ──────────────────────────────────────────────────────────────
//
// Validate the operator-supplied --csp-extra-sources string. The flag is
// space-separated CSP source-list entries that get appended to script-src,
// style-src, connect-src, and img-src.
//
// Rejects:
//   * Any byte < 0x20 or == 0x7F (control bytes — would cause cpp-httplib's
//     `is_field_value` check to silently drop the entire CSP header).
//   * Tokens containing ';' or ',' (would inject additional CSP directives
//     or list separators that change the header semantics).
//   * Quoted tokens that aren't on the safe allow-list. Permitted quoted
//     forms: 'self', 'none', 'sha256-...', 'sha384-...', 'sha512-...',
//     'nonce-...'. Notably 'unsafe-eval' and 'strict-dynamic' are NOT
//     accepted via this flag — operators who genuinely need them must
//     extend the server build (and accept the security trade-off).
//   * Unquoted tokens that contain a stray single quote (malformed source).
//
// On success returns a normalized (single-spaced, leading/trailing trim)
// copy of the input. On failure returns a human-readable error message
// suitable for surfacing to operators at startup.
[[nodiscard]] std::expected<std::string, std::string>
validate_csp_extra_sources(std::string_view raw);

// ── Header builders ─────────────────────────────────────────────────────────
//
// Build the Content-Security-Policy header value.
//
// `extra_sources` must already have been validated by
// validate_csp_extra_sources(). Passing un-validated input may produce a CSP
// that cpp-httplib will silently refuse to emit (any control byte) or that
// weakens browser enforcement (semicolons, quotes).
//
// `https_enabled` controls whether the `upgrade-insecure-requests` directive
// is appended. We only emit it when HTTPS is on, so HTTP-only deployments
// don't break legacy mixed-content fetches that the operator may rely on.
[[nodiscard]] std::string build_csp(std::string_view extra_sources,
                                    bool https_enabled);

// Build the Permissions-Policy header value (deny-all baseline for
// hardware/sensor APIs the dashboard never uses). Operators who need to
// loosen this should fork — there is no CLI flag because the dashboard's
// permission needs are static.
[[nodiscard]] std::string build_permissions_policy();

// Build the Referrer-Policy header value. We use strict-origin-when-cross-
// origin so the dashboard sends only the origin (not the full URL with query
// strings) when navigating to external links — defends against URL-based
// secret leakage to third parties.
[[nodiscard]] std::string build_referrer_policy();

// ── Pre-built header bundle ─────────────────────────────────────────────────
//
// Pre-computed header strings captured at server startup. Built once via
// HeaderBundle::make() and applied to every response by apply(res). Keeping
// the production server and the regression tests on a single code path
// guarantees that the headers tested in unit tests are exactly the headers
// the running server emits.
struct HeaderBundle {
    std::string csp;
    std::string permissions_policy;
    std::string referrer_policy;
    bool https_enabled{false};

    [[nodiscard]] static HeaderBundle make(std::string_view validated_extras,
                                           bool https_enabled);

    void apply(httplib::Response& res) const;
};

} // namespace yuzu::server::security
