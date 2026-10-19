#pragma once

/// @file crypto_widget_catalogue.hpp
/// The ONE pure catalogue of `/crypto` dashboard widgets, the closed window set behind the
/// Yuzu-issued certificate counts, and the JSON shapers / parameter parsers of the widget,
/// layout and Yuzu-CA surfaces - shared by REST, MCP and the dashboard fragments so the three
/// cannot drift. No httplib, no MCP, no libpq, no store types.
///
/// ADR-0070 D13 (maintainer ruling) admits fixed dashboard windows into core on five
/// conditions; this file is where they are kept:
///   1. every count names its criterion (`criterion_text`, the catalogue's `criterion`) -
///      never a bare "at risk" or "weak";
///   2. every response carries `as_of` (epoch seconds and ISO 8601) and the window days, so a
///      caller can recompute it from the per-certificate list;
///   3. counts are computed at read time, nothing verdict-shaped is stored;
///   4. the windows are a closed, versioned set (`kWindowSetVersion`): adding, removing or
///      retuning one is a reviewed change to D13 and bumps the version;
///   5. no grading colour, icon or risk order is attached here or by any renderer.
///
/// The Yuzu-issued widgets read Yuzu's OWN internal-CA inventory only (ADR-0070 D6: fleet
/// certificates are never read from CaStore), so every title says "Yuzu-issued".

#include "crypto_library_model.hpp" // Params
#include "crypto_types.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::crypto_widgets {

// ── The closed window set (ADR-0070 D13 condition 4) ─────────────────────────

/// Bump on ANY change to the arrays below (a D13 placement change, reviewed as such).
inline constexpr std::string_view kWindowSetVersion = "crypto_widget_windows_v1";
inline constexpr std::array<int, 6> kExpiringWindowDays{3, 7, 14, 21, 30, 60};
inline constexpr std::array<int, 4> kExpiredWindowDays{7, 30, 60, 90};
inline constexpr std::array<int, 4> kRevokedWindowDays{7, 30, 60, 90};
inline constexpr int kIssuedWindowDays = 7;
/// The per-week series: this many ISO weeks (Monday 00:00 UTC start), the last one containing
/// `as_of`, zero-filled.
inline constexpr int kWeeklyBuckets = 26;

inline constexpr std::int64_t kSecondsPerDay = 86400;
inline constexpr std::int64_t kSecondsPerWeek = 7 * kSecondsPerDay;

// ── The expiry boundary (RFC 5280; owner ruling 2026-10-19) ──────────────────
// A certificate is valid THROUGH its notAfter, inclusive (RFC 5280 §4.1.2.5). So at `as_of` a
// certificate with not_after == as_of is still unexpired — active and expiring, never expired —
// and one whose not_after is exactly N days before as_of IS in the N-day expired window. These
// three are the ONE definition: CaStore's SQL predicates (ca_store.cpp `issued_predicate`)
// mirror them — the store may not include this header — and test_ca_store.cpp locks the two
// together on the edge rows.

/// Unexpired at `as_of`: not_after >= as_of.
[[nodiscard]] constexpr bool unexpired_at(std::int64_t not_after, std::int64_t as_of) {
    return not_after >= as_of;
}
/// Expiring within `days`: as_of <= not_after <= as_of + days.
[[nodiscard]] constexpr bool expiring_within(std::int64_t not_after, std::int64_t as_of, int days) {
    return as_of <= not_after && not_after <= as_of + days * kSecondsPerDay;
}
/// Expired within the last `days`: as_of - days <= not_after < as_of.
[[nodiscard]] constexpr bool expired_within(std::int64_t not_after, std::int64_t as_of, int days) {
    return as_of - days * kSecondsPerDay <= not_after && not_after < as_of;
}

// ── Bounds ───────────────────────────────────────────────────────────────────

/// A stored layout holds at most this many widget ids (each a catalogue id, no repeats).
inline constexpr std::size_t kMaxLayoutWidgets = 64;
/// Longest catalogue id; anything longer is refused before a lookup.
inline constexpr std::size_t kWidgetIdMaxBytes = 64;
/// The layout PUT body bound, enforced by the handler AND mirrored by body_cap_policy.hpp's
/// "/api/v1/crypto" row (a comment-coordinated pair: change both or neither).
inline constexpr std::size_t kLayoutBodyMaxBytes = 16u * 1024;
/// Yuzu-issued certificate list page bounds. REST clamps `limit`; MCP refuses outside it.
inline constexpr int kCertPageDefault = 100;
inline constexpr int kCertPageMax = 500;
/// Largest accepted `offset` (both transports refuse a larger one).
inline constexpr int kCertOffsetMax = 1000000;

// ── The catalogue ────────────────────────────────────────────────────────────

enum class WidgetKind { kNumber, kBar, kLine, kTable };
enum class WidgetGroup { kLibraries, kYuzuCa };

/// Where a click on the widget leads (every widget drills down into its data):
///   kLibraryFamilies      the family table (family summary);
///   kLibraryFamilyDevices one family's device drill (bar click = that family);
///   kCaCertificates       the Yuzu-issued list for the widget's (ca_kind, days);
///   kCaWeek               the Yuzu-issued list of the clicked week (ca_kind = kIssuedWeek or
///                         kRevokedWeek).
enum class WidgetDrill { kLibraryFamilies, kLibraryFamilyDevices, kCaCertificates, kCaWeek };

struct Widget {
    std::string_view id;
    std::string_view title;
    WidgetKind kind;
    WidgetGroup group;
    std::string_view securable; ///< the permission the widget's data read requires
    std::string_view operation;
    std::string_view criterion; ///< what the number counts, in words (D13 condition 1)
    WidgetDrill drill;
    CaCertKind ca_kind{CaCertKind::kActive}; ///< Yuzu-issued widgets only
    int days{0};                             ///< windowed Yuzu-issued widgets only
};

[[nodiscard]] std::span<const Widget> catalogue();
[[nodiscard]] const Widget* find_widget(std::string_view id);
/// The layout an operator with no stored layout sees, in display order.
[[nodiscard]] std::span<const std::string_view> default_layout();
[[nodiscard]] std::vector<std::string> default_layout_ids();

/// nullopt = a storable layout: at most kMaxLayoutWidgets ids, each a catalogue id, no repeats
/// (an empty layout is valid). Otherwise the 400 / kInvalidParams message; it names the
/// offending POSITION, never echoes the caller's bytes.
[[nodiscard]] std::optional<std::string> layout_error(std::span<const std::string> ids);

/// A stored layout as served: ids the catalogue no longer knows (a widget retired by a later
/// build) are dropped, so an old row never breaks the dashboard; the stored row is untouched.
[[nodiscard]] std::vector<std::string> known_ids(std::span<const std::string> ids);

[[nodiscard]] std::string_view kind_name(WidgetKind k);
[[nodiscard]] std::string_view group_name(WidgetGroup g);
[[nodiscard]] std::string_view drill_name(WidgetDrill d);

// ── Yuzu-issued kinds and windows ────────────────────────────────────────────

[[nodiscard]] std::string_view ca_kind_name(CaCertKind k);
[[nodiscard]] std::optional<CaCertKind> parse_ca_kind(std::string_view s);
/// True when `kind` takes a `days` window (expiring, expired, revoked, issued).
[[nodiscard]] bool kind_takes_days(CaCertKind k);
/// True when `kind` takes a `week` (issued_week, revoked_week).
[[nodiscard]] bool kind_takes_week(CaCertKind k);
/// The closed window set for a windowed kind (empty for the others).
[[nodiscard]] std::span<const int> windows_for(CaCertKind k);
/// The criterion of one Yuzu-issued count in words, e.g. "Expiring within 30 days". `days` is
/// ignored for kinds without a window; `week_label` only for the per-week kinds.
[[nodiscard]] std::string criterion_text(CaCertKind k, int days, std::string_view week_label = {});

// ── ISO weeks and timestamps (UTC) ───────────────────────────────────────────

/// Monday 00:00 UTC of the ISO week containing `epoch` (epoch seconds; negative values too).
[[nodiscard]] std::int64_t week_start_of(std::int64_t epoch);
/// The kWeeklyBuckets week starts ending with the week containing `as_of`, oldest first.
[[nodiscard]] std::vector<std::int64_t> week_starts(std::int64_t as_of);
/// ISO 8601 week label of the week starting at `week_start` (a Monday): "2026-W40". The ISO
/// year is the year of the week's Thursday, so 2024-12-30 is "2025-W01".
[[nodiscard]] std::string iso_week_label(std::int64_t week_start);
/// "YYYY-Www" -> that week's Monday 00:00 UTC. Refuses any other shape and a week the year
/// does not have (W53 of a 52-week year).
[[nodiscard]] std::optional<std::int64_t> parse_iso_week(std::string_view label);
/// "2026-10-19T08:00:00Z".
[[nodiscard]] std::string iso8601_utc(std::int64_t epoch);

// ── Parameters ───────────────────────────────────────────────────────────────

/// Yuzu-issued list parameters. Keys: kind (required: active, expiring, expired, revoked,
/// issued, issued_week, revoked_week), days (required for the windowed kinds and one of the
/// closed set, refused on the others), week ("YYYY-Www", required for the per-week kinds,
/// refused on the others), limit (default 100, clamped to [1, kCertPageMax]), offset (default
/// 0, at most kCertOffsetMax). A repeated key with differing values, a non-decimal number, an
/// unknown kind or a window outside the set is refused; unknown keys are ignored. The error is
/// the 400 message.
[[nodiscard]] std::expected<CaCertQuery, std::string>
parse_cert_params(const crypto_library::Params& p);

/// MCP's STRICT twin: a non-object root, a wrong JSON type, an unknown kind, a window outside
/// the set, a days/week on a kind that does not take it, or a limit/offset outside the bounds
/// is refused rather than clamped. nullopt = acceptable.
[[nodiscard]] std::optional<std::string> strict_cert_args_error(const nlohmann::json& args);

/// MCP `set_crypto_dashboard_layout`: `{"widgets":[ids]}` with no other key, ids strings.
/// Only the shape; the ids are judged by layout_error. nullopt = acceptable.
[[nodiscard]] std::optional<std::string> strict_layout_args_error(const nlohmann::json& args);

/// REST `PUT /api/v1/crypto/dashboard/layout` body: the same shape as the MCP arguments. The
/// ids are returned unjudged (layout_error decides).
[[nodiscard]] std::expected<std::vector<std::string>, std::string>
parse_layout_body(std::string_view body);

// ── Audit details ────────────────────────────────────────────────────────────

/// `[cid=<cid> ]ws=<window set> as_of=<epoch>` (crypto.ca.stats.view, success).
[[nodiscard]] std::string audit_detail_stats(std::string_view cid, std::int64_t as_of);
/// `[cid=<cid> ]ws=<window set> as_of=<epoch> kind=<k>[ days=<n>][ week=<w>] rows=<n>
/// offset=<n> total=<n>` (crypto.ca.certificates.view, success).
[[nodiscard]] std::string audit_detail_certs(std::string_view cid, const CaCertPage& page);
/// The failure-row twin of both: `[cid=<cid> ]ws=<window set> as_of=<epoch> <what>` where
/// `what` is "store degraded", "capacity in use" or "ca unavailable".
[[nodiscard]] std::string audit_detail_ca_degraded(std::string_view cid, std::int64_t as_of,
                                                   CryptoReadCause cause);
/// `[cid=<cid> ]widgets=<n>` (crypto.dashboard.layout.update).
[[nodiscard]] std::string audit_detail_layout(std::string_view cid, std::size_t widgets);
/// Audit target of a Yuzu-issued list: `kind=<k>[ days=<n>][ week=<w>]`.
[[nodiscard]] std::string audit_target(const CaCertQuery& q);

// ── JSON ─────────────────────────────────────────────────────────────────────

/// The catalogue as served by `GET /api/v1/crypto/widgets` / `list_crypto_widgets`.
/// `available(securable, operation)` answers whether the CALLER holds that permission; it is
/// asked once per distinct pair.
using PermissionProbe = std::function<bool(std::string_view securable, std::string_view operation)>;
[[nodiscard]] nlohmann::json widgets_json(const PermissionProbe& available);

[[nodiscard]] nlohmann::json layout_json(const CryptoDashboardLayout& layout);
[[nodiscard]] nlohmann::json ca_stats_json(const CaCertStats& s);
[[nodiscard]] nlohmann::json ca_page_json(const CaCertPage& p);

} // namespace yuzu::server::crypto_widgets
