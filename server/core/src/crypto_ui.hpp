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
    "Package-level evidence only, and coverage differs by operating system: Linux reports "
    "distribution packages, macOS reports Homebrew packages only, and Windows reports only "
    "installers registered with the OS (the registry). Statically linked, vendored and "
    "OS-bundled copies (for example LibreSSL on macOS, or DLLs shipped inside Windows "
    "applications) are not visible here. Certificates, SSH host keys and protocol settings are "
    "planned and not yet available.";

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

/// The fragment URL that re-requests exactly this device page (family, version, ecosystem and
/// cursor), for a continuation row's Retry.
[[nodiscard]] std::string devices_page_url(const CryptoDevicesQuery& q);

/// The continuation-page twins. A Load-more response replaces the Load-more `<tr>` (hx-swap
/// outerHTML on `closest tr`), so a degrade or a note must itself be ONE table row spanning the
/// columns - a bare block would break the table and lose the walk. `retry_url` re-requests the
/// same continuation page (the row's own hx-get), not the whole summary.
[[nodiscard]] std::string render_unavailable_row(std::string_view what, std::string_view retry_url);
[[nodiscard]] std::string render_caveat_row(std::string_view message);

} // namespace yuzu::server::crypto_html
