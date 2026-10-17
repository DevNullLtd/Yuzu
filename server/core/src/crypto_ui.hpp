#pragma once

/// @file crypto_ui.hpp
/// Pure HTML renderers for the `/crypto` crypto-library-presence page (slice 1). Data in,
/// markup out: no store, no request, no clock, so the unit suites feed fixtures. The routes in
/// `crypto_routes.cpp` own gating, scope, audit and the seam reads; this header owns only the
/// markup.
///
/// Presence and versions only: nothing rendered here labels a library or version good, bad,
/// current or out of date (ADR-1005 D2). Every dynamic string goes through `html_escape` or
/// `url_encode`; no JS string is ever built from data. Colour comes from the design tokens
/// only, and the htmx `hx-on` attributes are never used (the dashboard CSP blocks them).

#include "crypto_types.hpp"

#include <string>
#include <string_view>

namespace yuzu::server::crypto_html {

/// The permanent package-level evidence caveat, rendered on every page state.
inline constexpr std::string_view kEvidenceCaveat =
    "Package-level evidence only. Statically linked, vendored and OS-bundled copies (for "
    "example LibreSSL on macOS, or DLLs shipped inside Windows applications) are not visible "
    "here. Certificates, SSH host keys and protocol settings will arrive in later releases.";

/// The whole /crypto body (component CSS, title, KPI strip, families table, caveat).
[[nodiscard]] std::string render_libraries(const CryptoSummary& s);

/// The device drill under one family row (optionally one version bucket). A continuation page
/// (`continuation` true) returns only table rows so the Load-more button can swap them in.
[[nodiscard]] std::string render_devices(const CryptoDevicesQuery& q, const CryptoDevicesPage& p,
                                         bool continuation);

/// Store degrade: a retry banner (re-requests the whole page), never an empty table.
[[nodiscard]] std::string render_unavailable(std::string_view what);

/// A refusal or bad-parameter note rendered as a 200 fragment (htmx does not swap 4xx).
[[nodiscard]] std::string render_caveat(std::string_view message);

} // namespace yuzu::server::crypto_html
