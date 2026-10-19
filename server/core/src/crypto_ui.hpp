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

#include "crypto_api.hpp" // CryptoReadError (pure seam types; no store)
#include "crypto_types.hpp"
#include "crypto_widget_catalogue.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <optional>


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
/// inventory store could not be read, and a degraded access gate (kAccessCheck) says the access
/// check could not be completed because one of its stores (permissions, management groups or
/// tags) could not be read.
[[nodiscard]] std::string render_unavailable(std::string_view what,
                                             CryptoReadCause cause = CryptoReadCause::kStoreDegraded);

/// The SUMMARY fragment's unavailable answer (a store, capacity or access-gate failure): the
/// component CSS (once; render_libraries carries its own), the audit-loss notice when
/// `audit_lost`, then the render_unavailable banner. Without the CSS `.cry-degrade` is unstyled on
/// a failed first load. Its note answers (refusal, bad parameter) go through render_summary_caveat;
/// together the two and render_libraries are every summary answer.
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

/// render_caveat as the SUMMARY fragment's whole answer: the component CSS once, then the note,
/// so `.cry-caveat` is styled when it replaces the page body.
[[nodiscard]] std::string render_summary_caveat(std::string_view message);

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


// ── The widget dashboard (ADR-0070 D13) ──────────────────────────────────────
//
// The /crypto page body is the caller's widget grid. The dashboard fragment reads the layout,
// asks the ONE availability probe (crypto_widgets::AccessMemo) about each card, reads the data
// at most ONCE per source (one library summary, one Yuzu-issued stats read - audited once per
// render) and draws EVERY card inline from those reads. `/fragments/crypto/widget/{id}` stays
// for a single card (its Retry, and a card just added), audited per request. A click on a
// number, a bar or a chart point loads its drill into the ONE drill panel below the grid.
// Numbers render in neutral tokens: no grading colour, icon or risk order (D13 condition 5).
// Every interaction is a plain onclick calling the `cryDash` helper (dashboard_head_html) -
// never htmx hx-on, which the dashboard CSP blocks.

/// The element every dashboard swap targets (the page shell's mount).
inline constexpr std::string_view kDashboardMountId = "guardian-detail";

/// The page-only `<head>` additions of /crypto: the ECharts engine, the Yuzu chart adapter and
/// the `cryDash` helper (versioned layout PUT, drill panel, chart click binding and disposal).
/// Inserted before `</head>` by the page route, so the scripts load on this page only.
[[nodiscard]] std::string dashboard_head_html();

/// What one dashboard render read, once per source. nullopt = not read (no drawn card needed
/// it, or no card of that source was available to the caller). `*_audit_lost` = that read's
/// access-audit row did not persist (the notice is drawn once, above the grid).
struct DashboardData {
    std::optional<std::expected<CryptoSummary, CryptoReadError>> library;
    std::optional<std::expected<CaCertStats, CryptoReadError>> ca;
    bool library_audit_lost{false};
    bool ca_audit_lost{false};
    /// The layout store did not open at boot (ADR-0071 degrade posture): the layout drawn is the
    /// default, read-only (no Add / Reset / move / remove), under a notice saying saved layouts
    /// are unavailable on this server until a restart.
    bool layouts_unavailable{false};
};

/// The whole dashboard body: CSS, title, the Add-widget / Reset toolbar (the layout `version`
/// rides on the grid for the next save), the scope line above the Yuzu-issued cards, the grid of
/// cards in the layout's order - each drawn inline from `data` per `access` (refused: "not
/// available to this account (<Securable:Op> required)"; confined: the ADR-0070 R2 note;
/// degraded access check: a Retry banner) - the drill panel and the package-level caveat. A
/// layout with preserved unknown ids says how many are kept but not drawn.
[[nodiscard]] std::string render_dashboard(const CryptoDashboardLayout& layout,
                                           crypto_widgets::AccessMemo& access,
                                           const DashboardData& data);

/// The dashboard fragment's unavailable answer (layout store degraded or busy, or no seam): the
/// CSS and a banner whose Retry re-requests the dashboard. Never the default layout served as
/// if stored. The text follows the cause (busy vs database degraded).
[[nodiscard]] std::string
render_dashboard_unavailable(CryptoReadCause cause = CryptoReadCause::kStoreDegraded);
/// The stored layout cannot be read as a layout (kCorrupt): not retryable; a Reset button that
/// replaces it with the default (PUT with expected_version = `version`).
[[nodiscard]] std::string render_dashboard_corrupt(std::int64_t version);

/// The fragment URL of one widget's data (`/fragments/crypto/widget/<id>`).
[[nodiscard]] std::string widget_url(std::string_view id);
/// One library widget's data body, from the family summary. The families-table widget drills
/// into the panel AS the table (each row expands its device drill under itself).
[[nodiscard]] std::string render_library_widget(const crypto_widgets::Widget& w,
                                                const CryptoSummary& s);
/// One Yuzu-issued widget's data body, from the stats read: every count with its criterion,
/// `as_of` and the window set version (D13 conditions 1-2); a revoked widget shows the three
/// buckets side by side (each its own drill), the revoked-per-week chart three series, and the
/// partial week is marked.
[[nodiscard]] std::string render_ca_widget(const crypto_widgets::Widget& w, const CaCertStats& s);
/// A card whose data the caller may not read: kRefused "not available to this account
/// (<Securable:Op> required)"; kConfined the R2 note (crypto_widgets::kConfinedWithheldMessage).
/// A note, never an error.
[[nodiscard]] std::string render_widget_not_available(const crypto_widgets::Widget& w,
                                                      crypto_widgets::Access why);
/// A widget whose read failed (store, capacity, or a degraded access check): a banner whose
/// Retry re-requests THIS widget into its own slot. `ca` picks the Yuzu-issued wording; the
/// text distinguishes busy (kCapacity) from a degraded database.
[[nodiscard]] std::string render_widget_unavailable(const crypto_widgets::Widget& w,
                                                    CryptoReadCause cause, bool ca);
/// The Yuzu-issued certificate drill (rows carry the recorded revocation reason). A
/// continuation page (offset > 0) returns only table rows so the Load-more button can swap them
/// in; its URL carries the page's as_of so the walk is one snapshot.
[[nodiscard]] std::string render_ca_certificates(const CaCertPage& p, bool continuation);
/// The fragment URL of one Yuzu-issued list page (`/fragments/crypto/ca/certificates?...`),
/// bucket and a pinned as_of included.
[[nodiscard]] std::string ca_certificates_url(const CaCertQuery& q);
/// The Yuzu-issued drill's failure answers: the first page a block whose Retry re-requests the
/// drill into its slot; a continuation page ONE table row (it replaces the Load-more row).
/// `retry_url` empty = nothing to retry (the request did not parse).
[[nodiscard]] std::string render_ca_unavailable(std::string_view retry_url, CryptoReadCause cause,
                                                bool row);
[[nodiscard]] std::string render_ca_caveat(std::string_view message, bool row);
/// The audit-loss notice as ONE table row for a Yuzu-issued continuation page.
[[nodiscard]] std::string render_ca_audit_notice_row();
/// The drill's refusal for a caller without Security:Read (the count stays visible under
/// Inventory:Read): "The certificate list needs Security:Read ...".
inline constexpr std::string_view kCaDrillNeedsSecurityRead =
    "The certificate list needs Security:Read. The counts above stay visible with Inventory:Read; "
    "ask an administrator for Security:Read to see the certificates behind them.";

/// JSON for an inline `<script>`: dumped ASCII-only (U+2028/U+2029 and every non-ASCII code
/// point become \u escapes) with `<`, `>` and `&` escaped as < / > / &, so no
/// data can close the script element or open an HTML comment inside it.
[[nodiscard]] std::string script_json(const nlohmann::json& j);

} // namespace yuzu::server::crypto_html
