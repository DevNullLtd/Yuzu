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

/// The audit-loss notice (review #6056 UP-8): a fragment whose access-audit row did not persist
/// still renders (set-and-proceed), but says so on the page as well as in the
/// `Sec-Audit-Failed` header, so a lost row is visible to the operator, not only to a client
/// that reads headers. `yuzu_server_audit_emit_failed_total` is bumped by an AuditStore write
/// failure (store not open, pool acquire timeout, INSERT error), which the shipped
/// YuzuAuditPersistFailures alert watches; a sink that THROWS (`bad_alloc`-class) is caught in
/// `detail::try_persist_audit` (rest_audit.hpp) and only logged, never counted, so the notice
/// still shows but the counter does not move.
inline constexpr std::string_view kAuditNotPersistedNotice =
    "This view could not be recorded in the audit log. Audit store write failures are counted in "
    "yuzu_server_audit_emit_failed_total, which the shipped YuzuAuditPersistFailures alert "
    "watches.";

/// kAuditNotPersistedNotice as a block, and as ONE table row for a continuation page.
[[nodiscard]] std::string render_audit_notice();
[[nodiscard]] std::string render_audit_notice_row();

/// The whole /crypto body (component CSS, title, KPI strip, families table, caveat).
[[nodiscard]] std::string render_libraries(const CryptoSummary& s);

/// The device drill under one family row (optionally one version bucket). A continuation page
/// (`continuation` true) returns only table rows so the Load-more button can swap them in.
[[nodiscard]] std::string render_devices(const CryptoDevicesQuery& q, const CryptoDevicesPage& p,
                                         bool continuation);

/// Store degrade or capacity shed on the SUMMARY: a retry banner (re-requests the whole page),
/// never an empty table. The text follows the cause: a shed says the server is busy, a store fault says the
/// inventory store could not be read, and a degraded access gate (kAccessCheck) says the
/// permission store could not be read.
[[nodiscard]] std::string render_unavailable(std::string_view what,
                                             CryptoReadCause cause = CryptoReadCause::kStoreDegraded);

/// The SUMMARY fragment's whole answer when it is not render_libraries: the component CSS (once;
/// render_libraries carries its own), the audit-loss notice when `audit_lost`, then the
/// render_unavailable banner. Without the CSS `.cry-degrade` is unstyled on a failed first load.
[[nodiscard]] std::string render_summary_unavailable(
    std::string_view what, CryptoReadCause cause = CryptoReadCause::kStoreDegraded,
    bool audit_lost = false);

/// The first-page drill twin of render_unavailable: its Retry re-requests the SAME drill
/// fragment (family, version, ecosystem) into the family's own drill box, never the summary.
[[nodiscard]] std::string render_unavailable_drill(std::string_view what, const CryptoDevicesQuery& q,
                                                   CryptoReadCause cause = CryptoReadCause::kStoreDegraded);

/// The id of a family row's drill box (`cry-exp-<url-encoded family id>`), the hx-target of the
/// row, its version chips and a first-page drill Retry.
[[nodiscard]] std::string drill_box_id(std::string_view family);

/// A refusal or bad-parameter note rendered as a 200 fragment (htmx does not swap 4xx).
[[nodiscard]] std::string render_caveat(std::string_view message);

/// The fragment URL that re-requests exactly this device page (family, version, ecosystem and
/// cursor), for a continuation row's Retry.
[[nodiscard]] std::string devices_page_url(const CryptoDevicesQuery& q);

/// The continuation-page twins. A Load-more response replaces the Load-more `<tr>` (hx-swap
/// outerHTML on `closest tr`), so a degrade or a note must itself be ONE table row spanning the
/// columns - a bare block would break the table and lose the walk. `retry_url` re-requests the
/// same continuation page (the row's own hx-get), not the whole summary.
[[nodiscard]] std::string render_unavailable_row(std::string_view what, std::string_view retry_url,
                                                 CryptoReadCause cause = CryptoReadCause::kStoreDegraded);
[[nodiscard]] std::string render_caveat_row(std::string_view message);

} // namespace yuzu::server::crypto_html
