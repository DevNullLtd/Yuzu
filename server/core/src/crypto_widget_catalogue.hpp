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
///
/// Dependants beyond the /crypto surface (L7): `ca_routes.cpp` uses the parameter parser,
/// cursor, audit and JSON shapers here for the FILTERED `GET /api/v1/ca/issued` branch, so a
/// change to them changes that route's contract too (rest-api.md, the OpenAPI literal).

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
#include <tuple>
#include <utility>
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
inline constexpr int kWeeklyBuckets = 52;

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
/// The layout PUT body bound, enforced by the handler AND by body_cap_policy.hpp's
/// "/api/v1/crypto" row before the body is buffered. The pair is locked by a static_assert in
/// crypto_routes.cpp (resolve_body_cap(...) == kLayoutBodyMaxBytes): change one and the build
/// fails until the other matches.
inline constexpr std::size_t kLayoutBodyMaxBytes = 16u * 1024;
/// Yuzu-issued certificate list page bounds. Every transport REFUSES a limit outside
/// [1, kCertPageMax] (named in the 400 / -32602 message). The filtered list pages by keyset
/// cursor only (H2): an `offset` with a filter is refused, naming it.
inline constexpr int kCertPageDefault = 100;
inline constexpr int kCertPageMax = 500;
/// Longest cursor token accepted; anything longer is refused before it is decoded.
inline constexpr std::size_t kCertCursorMaxBytes = 512;
/// A pinned `as_of` (a drill's count or a cursor's snapshot) is accepted from db_now -
/// kAsOfMaxAgeSeconds up to db_now + kAsOfFutureSkewSeconds, where db_now is the DATABASE clock
/// read in the list's own transaction (M2, ADR-0070 R4 - never the serving replica's clock;
/// CaStore enforces it through CaAsOfBounds). The skew allowance covers a page minted on one
/// database snapshot and continued a moment later.
inline constexpr std::int64_t kAsOfMaxAgeSeconds = 7 * kSecondsPerDay;
inline constexpr std::int64_t kAsOfFutureSkewSeconds = 300;

/// Shown with every Yuzu-issued count and list, and in the empty dashboard (ADR-0070 D6). The
/// counts have no purpose filter, so the note names every purpose `ca_issued` holds.
inline constexpr std::string_view kScopeNote =
    "Counts certificates Yuzu's own CA issued only (agent, server, gateway, HTTPS and "
    "code-signing); certificates on your devices are not covered.";
/// ADR-0070 R4: issued_at and revoked_at are written from the issuing replica's clock, so a
/// window edge is accurate only to the replicas' clock synchronisation.
inline constexpr std::string_view kWindowEdgeNote =
    "as_of is the database clock; issued and revoked times are recorded from the issuing "
    "server's clock, so a window edge is accurate only to the servers' clock synchronisation.";
/// The refusal a CONFINED caller gets for the Yuzu-issued counts and certificate list
/// (ADR-0070 R2): never a narrowed count. Names no permission - none would admit them.
inline constexpr std::string_view kConfinedWithheldMessage =
    "Yuzu-issued certificate figures are not available to this account: its view of the fleet "
    "is confined, and these are fleet-wide figures.";

// ── The catalogue ────────────────────────────────────────────────────────────

enum class WidgetKind { kNumber, kBar, kLine, kTable };
enum class WidgetGroup { kLibraries, kYuzuCa };

/// How a widget's data is gated - ONE classification every surface (REST /widgets, MCP
/// list_crypto_widgets, the dashboard) draws availability from:
///   kFleetRead     admit-then-filter (`fleet_read_fn`, ADR-0017): a confined caller gets a
///                  real, narrowed answer (the library widgets);
///   kFleetWideOnly the same gate, but a CONFINED caller is withheld - a "not available to
///                  this account" note, never a narrowed figure (the Yuzu-issued counts,
///                  ADR-0070 R2);
///   kGlobal        a global permission (`has_permission`): the Yuzu-issued certificate drill
///                  (Security:Read, the gate of GET /api/v1/ca/issued).
enum class WidgetGate { kFleetRead, kFleetWideOnly, kGlobal };

/// Where a click on the widget leads (every widget drills down into its data):
///   kLibraryFamilies      the family table (family summary);
///   kLibraryFamilyDevices one family's device drill (bar click = that family);
///   kCaCertificates       the Yuzu-issued list for the widget's (ca_kind, days[, bucket]);
///   kCaWeek               the Yuzu-issued list of the clicked week (ca_kind = kIssuedWeek or
///                         kRevokedWeek[, bucket]).
enum class WidgetDrill { kLibraryFamilies, kLibraryFamilyDevices, kCaCertificates, kCaWeek };

struct Widget {
    std::string_view id;
    std::string_view title;
    WidgetKind kind;
    WidgetGroup group;
    WidgetGate gate;
    std::string_view securable; ///< the permission the widget's data read requires
    std::string_view operation;
    std::string_view criterion; ///< what the number counts, in words (D13 condition 1)
    WidgetDrill drill;
    CaCertKind ca_kind{CaCertKind::kActive}; ///< Yuzu-issued widgets only
    int days{0};                             ///< windowed Yuzu-issued widgets only
};

/// The Yuzu-issued drill's gate (the certificate rows): Security:Read, global.
inline constexpr std::string_view kCaDrillSecurable = "Security";
inline constexpr std::string_view kCaDrillOperation = "Read";

[[nodiscard]] std::span<const Widget> catalogue();
[[nodiscard]] const Widget* find_widget(std::string_view id);
/// The layout an operator with no stored layout sees, in display order.
[[nodiscard]] std::span<const std::string_view> default_layout();
[[nodiscard]] std::vector<std::string> default_layout_ids();

/// nullopt = a storable layout: at most kMaxLayoutWidgets ids, each a catalogue id, no repeats
/// (an empty layout is valid). Otherwise the 400 / kInvalidParams message; it names the
/// offending POSITION, never echoes the caller's bytes.
[[nodiscard]] std::optional<std::string> layout_error(std::span<const std::string> ids);

/// A stored layout as drawn: the ids this build knows, in stored order (the stored row is
/// untouched). Ids it does not know - a widget a newer build added, or one retired - are not
/// drawn; `unknown_ids` lists them in stored order so a save can keep them.
[[nodiscard]] std::vector<std::string> known_ids(std::span<const std::string> ids);
[[nodiscard]] std::vector<std::string> unknown_ids(std::span<const std::string> ids);

/// What a save stores: the caller's ids, then the previously stored ids this build does not
/// know (kept so a rollback or a mixed-version fleet never loses another build's widgets), the
/// whole capped at `max_ids` (the caller's ids always fit: layout_error bounds them). `kept` =
/// how many unknown ids survived the cap.
struct MergedLayout {
    std::vector<std::string> ids;
    std::size_t kept{0};
};
[[nodiscard]] MergedLayout merge_preserved(std::span<const std::string> caller_ids,
                                           std::span<const std::string> stored_ids,
                                           std::size_t max_ids);
/// True when `widgets` IS the catalogue default and nothing unknown is preserved.
[[nodiscard]] bool is_default_layout(std::span<const std::string> widgets,
                                     std::size_t preserved_unknown);

[[nodiscard]] std::string_view kind_name(WidgetKind k);
[[nodiscard]] std::string_view group_name(WidgetGroup g);
[[nodiscard]] std::string_view gate_name(WidgetGate g);
[[nodiscard]] std::string_view drill_name(WidgetDrill d);

// ── Availability (drawing only, never a grant) ───────────────────────────────

/// A caller's standing for one gate: kAvailable; kRefused (the check answered 403: no grant,
/// or a read failure partway through the check, which the answer cannot tell apart);
/// kConfined (a kFleetWideOnly widget and the caller's view is confined); kDegraded (the
/// check answered 503: it could not be completed because a store behind it could not be read).
enum class Access { kAvailable, kRefused, kConfined, kDegraded };
[[nodiscard]] std::string_view access_name(Access a);

/// The ONE availability callback (server.cpp wires the same function into the REST routes, the
/// dashboard and the MCP server): kFleetRead/kFleetWideOnly ask the NON-auditing fleet-read
/// probe, kGlobal the non-auditing has_permission.
using AccessProbe = std::function<Access(WidgetGate gate, std::string_view securable,
                                         std::string_view operation)>;

/// The pure composition the fleet-read side of an AccessProbe applies: `admitted` and
/// `confined` (a present VisibleSet) from the probe, `degraded` when it answered 503.
[[nodiscard]] Access fleet_access(WidgetGate gate, bool admitted, bool confined, bool degraded);

/// An AccessProbe asked at most once per distinct (gate, securable, operation) - one per
/// render, however many widgets share it. Null probe = every answer kRefused.
class AccessMemo {
public:
    explicit AccessMemo(AccessProbe probe) : probe_(std::move(probe)) {}
    [[nodiscard]] Access operator()(WidgetGate gate, std::string_view securable,
                                    std::string_view operation);
    /// The widget's own data gate.
    [[nodiscard]] Access widget(const Widget& w) { return (*this)(w.gate, w.securable, w.operation); }
    /// Its drill's gate: the Yuzu-issued certificate rows need Security:Read (global); a
    /// library drill is the same read as the widget.
    [[nodiscard]] Access drill(const Widget& w);

private:
    AccessProbe probe_;
    std::vector<std::tuple<WidgetGate, std::string, std::string, Access>> seen_;
};

// ── Yuzu-issued kinds, buckets and windows ───────────────────────────────────

[[nodiscard]] std::string_view ca_kind_name(CaCertKind k);
[[nodiscard]] std::optional<CaCertKind> parse_ca_kind(std::string_view s);
[[nodiscard]] std::string_view bucket_name(RevokedBucket b);
[[nodiscard]] std::optional<RevokedBucket> parse_bucket(std::string_view s);
inline constexpr std::array<RevokedBucket, 3> kRevokedBuckets{
    RevokedBucket::kSuperseded, RevokedBucket::kUnpublished, RevokedBucket::kOther};
/// True when `kind` takes a `days` window (expiring, expired, revoked, issued).
[[nodiscard]] bool kind_takes_days(CaCertKind k);
/// True when `kind` takes a `week` (issued_week, revoked_week).
[[nodiscard]] bool kind_takes_week(CaCertKind k);
/// True when `kind` takes a revoked `bucket` (revoked, revoked_week).
[[nodiscard]] bool kind_takes_bucket(CaCertKind k);
/// The closed window set for a windowed kind (empty for the others).
[[nodiscard]] std::span<const int> windows_for(CaCertKind k);
/// The rule id of one Yuzu-issued count (D13 condition 1): "yuzu_ca_<kind>[_<bucket>]". The
/// threshold travels beside it (`threshold` / the week).
[[nodiscard]] std::string rule_id(CaCertKind k, std::optional<RevokedBucket> bucket = std::nullopt);
/// The criterion of one Yuzu-issued count in words - exactly the predicate, RFC 5280 boundary
/// included. `days` is ignored for kinds without a window; `week_label` only for the per-week
/// kinds; `bucket` only for the revoked kinds.
[[nodiscard]] std::string criterion_text(CaCertKind k, int days, std::string_view week_label = {},
                                         std::optional<RevokedBucket> bucket = std::nullopt);

// ── ISO weeks and timestamps (UTC) ───────────────────────────────────────────

/// Monday 00:00 UTC of the ISO week containing `epoch` (epoch seconds; negative values too).
[[nodiscard]] std::int64_t week_start_of(std::int64_t epoch);
/// The kWeeklyBuckets week starts ending with the week containing `as_of`, oldest first. No
/// production caller (L12): the store computes the series in SQL; this is the tests' reference
/// definition the store's week_starts are checked against.
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

/// Yuzu-issued list parameters (the filtered GET /api/v1/ca/issued and the dashboard drill).
/// Keys: kind (required: active, expiring, expired, revoked, issued, issued_week,
/// revoked_week), days (required for the windowed kinds and one of the closed set, refused on
/// the others), week ("YYYY-Www", required for the per-week kinds, refused on the others),
/// bucket (superseded, unpublished or other; revoked kinds only), as_of (epoch seconds; its
/// window is checked on the DATABASE clock by the read, M2), limit (default 100,
/// 1..kCertPageMax), cursor (the previous page's next_cursor, at most kCertCursorMaxBytes;
/// decoded and bound to the filter by the read). `offset` is refused (keyset paging only, H2).
/// Every refusal names its parameter; a repeated key with differing values is refused; unknown
/// keys are ignored. The error is the 400 message.
[[nodiscard]] std::expected<CaCertQuery, std::string>
parse_cert_params(const crypto_library::Params& p);

/// True when any filter key (kind, days, week, bucket, as_of, cursor) is present: GET
/// /api/v1/ca/issued then answers the filtered list; without one it answers exactly as before.
[[nodiscard]] bool has_cert_filter_params(const crypto_library::Params& p);
[[nodiscard]] bool has_cert_filter_args(const nlohmann::json& args);

/// MCP's STRICT twin over JSON arguments (`list_issued_certs` with filters): a non-object root,
/// a wrong JSON type, an unknown kind or bucket, a window outside the set, a days/week/bucket on
/// a kind that does not take it, a negative as_of, a limit outside the bounds, an over-long or
/// empty cursor, or any offset is refused; keys other than those are left to the caller.
/// nullopt = acceptable.
[[nodiscard]] std::optional<std::string> strict_cert_args_error(const nlohmann::json& args);

// ── Keyset cursor of the Yuzu-issued list (H2) ──────────────────────────────

/// A decoded cursor: the last served row's sort key (not_after, revoked_at or issued_at - per
/// kind, CaStore's order) and serial_hex, and the walk's as_of.
struct CertCursor {
    std::int64_t sort_key{0};
    std::string serial_hex;
    std::int64_t as_of{0};
};
/// The filter the cursor is bound to: kind, days, week_start, bucket and the window-set
/// version (never the limit or the caller).
[[nodiscard]] std::string cert_cursor_fingerprint(const CaCertQuery& q);
/// `c1:<fp16>:<b64url(length-prefixed {sort_key, serial_hex, as_of})>` - opaque to callers.
[[nodiscard]] std::string encode_cert_cursor(const CertCursor& at, std::string_view fp);
/// Strict: the one canonical spelling only (re-encoded and compared), a hex serial of 1..128
/// digits, non-negative integers. The error is the 400 message and names `cursor`: "invalid
/// cursor" (malformed or tampered) or a filter mismatch ("restart without a cursor").
[[nodiscard]] std::expected<CertCursor, std::string> decode_cert_cursor(std::string_view token,
                                                                         std::string_view fp);

/// A layout save: the ids, and the version the caller last read (nullopt or 0 = only when
/// nothing is stored: a first save; ADR-0071, owner decision 2026-10-19).
struct LayoutRequest {
    std::vector<std::string> widgets;
    std::optional<std::int64_t> expected_version;
};

/// MCP `set_crypto_dashboard_layout`: `{"widgets":[ids], "expected_version"?: n}` with no other
/// key, ids strings, n a non-negative integer. Only the shape; the ids are judged by
/// layout_error. nullopt = acceptable.
[[nodiscard]] std::optional<std::string> strict_layout_args_error(const nlohmann::json& args);
[[nodiscard]] LayoutRequest layout_request_from_args(const nlohmann::json& args);

/// REST `PUT /api/v1/crypto/dashboard/layout` body: the same shape as the MCP arguments. The
/// ids are returned unjudged (layout_error decides).
[[nodiscard]] std::expected<LayoutRequest, std::string> parse_layout_body(std::string_view body);

// ── Audit details ────────────────────────────────────────────────────────────

/// `[cid=<cid> ]ws=<window set> as_of=<epoch>[ widgets=<n>]` (crypto.ca.stats.view, success).
/// `widgets` = the cards one dashboard render drew from this ONE read (the per-render row).
[[nodiscard]] std::string audit_detail_stats(std::string_view cid, std::int64_t as_of,
                                             std::optional<std::size_t> widgets = std::nullopt);
/// `[cid=<cid> ]ws=<window set> as_of=<epoch>[ pinned] kind=<k>[ days=<n>][ week=<w>]
/// [ bucket=<b>] rows=<n> page=<first|continuation> total=<n>` (crypto.ca.certificates.view,
/// success).
[[nodiscard]] std::string audit_detail_certs(std::string_view cid, const CaCertPage& page);
/// `[cid=<cid> ]inventory rows=<n> limit=<n> offset=<n> has_more=<true|false>`
/// (crypto.ca.certificates.view, success, for the UNFILTERED offset-paged list: it has no
/// window set, count or cursor to name, so it records what was served and which page).
[[nodiscard]] std::string audit_detail_inventory(std::string_view cid, std::size_t rows, int limit,
                                                 int offset, bool has_more);
/// The failure-row twin of both: `[cid=<cid> ]ws=<window set> as_of=<epoch|db_now> <what>`
/// where `what` is "store degraded", "capacity in use" or "access check unavailable".
[[nodiscard]] std::string audit_detail_ca_degraded(std::string_view cid,
                                                   std::optional<std::int64_t> as_of,
                                                   CryptoReadCause cause);
/// `[cid=<cid> ]ws=<window set> withheld=confined` (a denied row: R2).
[[nodiscard]] std::string audit_detail_ca_withheld(std::string_view cid);
/// `[cid=<cid> ]widgets=<n>[ expected_version=<v>]` (crypto.dashboard.layout.update).
[[nodiscard]] std::string audit_detail_layout(std::string_view cid, std::size_t widgets,
                                              std::optional<std::int64_t> expected_version = std::nullopt);
/// Audit target of a Yuzu-issued list: `kind=<k>[ days=<n>][ week=<w>][ bucket=<b>]`.
[[nodiscard]] std::string audit_target(const CaCertQuery& q);

// ── JSON ─────────────────────────────────────────────────────────────────────

/// The catalogue as served by `GET /api/v1/crypto/widgets` / `list_crypto_widgets`, each
/// widget's `available` / `availability` (and, for the Yuzu-issued widgets, `drill_available`)
/// decided through `access` - drawing only, never a grant.
[[nodiscard]] nlohmann::json widgets_json(AccessMemo& access);

[[nodiscard]] nlohmann::json layout_json(const CryptoDashboardLayout& layout);
/// The Yuzu-issued counts: every count an object carrying rule_id, threshold (or week),
/// criterion, rule_set_version and as_of beside it (D13 condition 1); revoked counts in three
/// buckets; the week containing as_of flagged partial.
[[nodiscard]] nlohmann::json ca_stats_json(const CaCertStats& s);
/// The filtered list's rows, in GET /api/v1/ca/issued's per-row shape.
[[nodiscard]] nlohmann::json ca_items_json(const CaCertPage& p);
/// The filtered list's `filter` object: kind, days, week, week_start, bucket, rule_id,
/// criterion, rule_set_version, as_of (the snapshot every page of the walk reads), as_of_iso,
/// total, scope_note. The next page's cursor travels beside it (`next_cursor`).
[[nodiscard]] nlohmann::json ca_filter_json(const CaCertPage& p);

} // namespace yuzu::server::crypto_widgets
