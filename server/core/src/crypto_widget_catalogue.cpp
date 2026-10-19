#include "crypto_widget_catalogue.hpp"

#include "list_keyset.hpp"         // b64url: the one cursor codec
#include "model_param_helpers.hpp" // find_param / parse_nonneg / valid_text (shared with the models)

#include <algorithm>
#include <chrono>
#include <format>
#include <limits>
#include <set>
#include <unordered_set>
#include <utility>

namespace yuzu::server::crypto_widgets {

namespace {

using model_detail::find_param;
using model_detail::fnv1a_hex16;
using model_detail::is_lower_hex16;
using model_detail::length_prefixed;
using model_detail::parse_nonneg;
using model_detail::read_length_prefixed;
using model_detail::valid_text;

constexpr std::string_view kInventory = "Inventory";
constexpr std::string_view kRead = "Read";

using K = WidgetKind;
using G = WidgetGroup;
using D = WidgetDrill;
using C = CaCertKind;
using W = WidgetGate;

constexpr Widget lib(std::string_view id, std::string_view title, WidgetKind kind,
                     std::string_view criterion, WidgetDrill drill) {
    return {id, title, kind, G::kLibraries, W::kFleetRead, kInventory, kRead, criterion, drill};
}

// The Yuzu-issued COUNTS are Inventory:Read and withheld from a confined caller (ADR-0070 R2):
// population counts with no device dimension. The rows behind them stay Security:Read.
constexpr Widget ca(std::string_view id, std::string_view title, WidgetKind kind,
                    std::string_view criterion, WidgetDrill drill, CaCertKind ca_kind, int days = 0) {
    return {id,    title, kind, G::kYuzuCa, W::kFleetWideOnly, kInventory, kRead, criterion, drill,
            ca_kind, days};
}

// Every Yuzu-issued title says "Yuzu-issued" (ADR-0070 D6: this is Yuzu's own PKI, never the
// fleet's certificates), and every criterion names its window and the RFC 5280 boundary (D13
// condition 1). The windowed criteria equal criterion_text(kind, days) word for word (the
// catalogue tests lock that).
constexpr std::array<Widget, 23> kWidgets{{
    lib("lib.devices_reporting", "Devices reporting inventory", K::kNumber,
        "Devices in your scope with an installed-software inventory report", D::kLibraryFamilies),
    lib("lib.devices_with_library", "Devices with a crypto library", K::kNumber,
        "Distinct devices with at least one package matching a library family in the curated table",
        D::kLibraryFamilies),
    lib("lib.families_matched", "Library families found", K::kNumber,
        "Library families with at least one matching device", D::kLibraryFamilies),
    lib("lib.families_table", "Crypto libraries", K::kTable,
        "Each family's distinct device count and its version buckets", D::kLibraryFamilyDevices),
    lib("lib.devices_by_family", "Devices by library family", K::kBar,
        "Distinct devices carrying any package of each family", D::kLibraryFamilyDevices),

    ca("ca.active", "Yuzu-issued certificates: active", K::kNumber,
       "Status active, issued on or before as_of, notAfter on or after as_of (valid through "
       "notAfter, inclusive)",
       D::kCaCertificates, C::kActive),
    ca("ca.expiring_3d", "Yuzu-issued: expiring within 3 days", K::kNumber,
       "Status active, notAfter from as_of through as_of + 3 days (valid through notAfter, "
       "inclusive)",
       D::kCaCertificates, C::kExpiring, 3),
    ca("ca.expiring_7d", "Yuzu-issued: expiring within 7 days", K::kNumber,
       "Status active, notAfter from as_of through as_of + 7 days (valid through notAfter, "
       "inclusive)",
       D::kCaCertificates, C::kExpiring, 7),
    ca("ca.expiring_14d", "Yuzu-issued: expiring within 14 days", K::kNumber,
       "Status active, notAfter from as_of through as_of + 14 days (valid through notAfter, "
       "inclusive)",
       D::kCaCertificates, C::kExpiring, 14),
    ca("ca.expiring_21d", "Yuzu-issued: expiring within 21 days", K::kNumber,
       "Status active, notAfter from as_of through as_of + 21 days (valid through notAfter, "
       "inclusive)",
       D::kCaCertificates, C::kExpiring, 21),
    ca("ca.expiring_30d", "Yuzu-issued: expiring within 30 days", K::kNumber,
       "Status active, notAfter from as_of through as_of + 30 days (valid through notAfter, "
       "inclusive)",
       D::kCaCertificates, C::kExpiring, 30),
    ca("ca.expiring_60d", "Yuzu-issued: expiring within 60 days", K::kNumber,
       "Status active, notAfter from as_of through as_of + 60 days (valid through notAfter, "
       "inclusive)",
       D::kCaCertificates, C::kExpiring, 60),
    ca("ca.expired_7d", "Yuzu-issued: expired in the last 7 days", K::kNumber,
       "Status active, notAfter from as_of - 7 days up to, not including, as_of", D::kCaCertificates,
       C::kExpired, 7),
    ca("ca.expired_30d", "Yuzu-issued: expired in the last 30 days", K::kNumber,
       "Status active, notAfter from as_of - 30 days up to, not including, as_of", D::kCaCertificates,
       C::kExpired, 30),
    ca("ca.expired_60d", "Yuzu-issued: expired in the last 60 days", K::kNumber,
       "Status active, notAfter from as_of - 60 days up to, not including, as_of", D::kCaCertificates,
       C::kExpired, 60),
    ca("ca.expired_90d", "Yuzu-issued: expired in the last 90 days", K::kNumber,
       "Status active, notAfter from as_of - 90 days up to, not including, as_of", D::kCaCertificates,
       C::kExpired, 90),
    ca("ca.revoked_7d", "Yuzu-issued: revoked in the last 7 days", K::kNumber,
       "Revoked after as_of - 7 days and on or before as_of, counted separately by recorded "
       "reason: superseded, unpublished, other",
       D::kCaCertificates, C::kRevoked, 7),
    ca("ca.revoked_30d", "Yuzu-issued: revoked in the last 30 days", K::kNumber,
       "Revoked after as_of - 30 days and on or before as_of, counted separately by recorded "
       "reason: superseded, unpublished, other",
       D::kCaCertificates, C::kRevoked, 30),
    ca("ca.revoked_60d", "Yuzu-issued: revoked in the last 60 days", K::kNumber,
       "Revoked after as_of - 60 days and on or before as_of, counted separately by recorded "
       "reason: superseded, unpublished, other",
       D::kCaCertificates, C::kRevoked, 60),
    ca("ca.revoked_90d", "Yuzu-issued: revoked in the last 90 days", K::kNumber,
       "Revoked after as_of - 90 days and on or before as_of, counted separately by recorded "
       "reason: superseded, unpublished, other",
       D::kCaCertificates, C::kRevoked, 90),
    ca("ca.issued_7d", "Yuzu-issued: issued in the last 7 days", K::kNumber,
       "Issued after as_of - 7 days and on or before as_of, excluding unpublished (recorded, "
       "never delivered)",
       D::kCaCertificates, C::kIssued, 7),
    ca("ca.issued_per_week", "Yuzu-issued: issued per week", K::kLine,
       "Issued in each of the last 52 ISO weeks (UTC, Monday start), excluding unpublished "
       "(recorded, never delivered); the current week is partial",
       D::kCaWeek, C::kIssuedWeek),
    ca("ca.revoked_per_week", "Yuzu-issued: revoked per week", K::kLine,
       "Revoked in each of the last 52 ISO weeks (UTC, Monday start), counted separately by "
       "recorded reason: superseded, unpublished, other; the current week is partial",
       D::kCaWeek, C::kRevokedWeek),
}};

constexpr std::size_t kWidgetCount = kWidgets.size();

constexpr bool in_set(std::span<const int> set, int days) {
    for (const int d : set)
        if (d == days)
            return true;
    return false;
}

constexpr std::span<const int> windows_of(CaCertKind k) {
    switch (k) {
    case C::kExpiring:
        return kExpiringWindowDays;
    case C::kExpired:
        return kExpiredWindowDays;
    case C::kRevoked:
        return kRevokedWindowDays;
    case C::kIssued:
        return std::span<const int>(&kIssuedWindowDays, 1);
    case C::kActive:
    case C::kIssuedWeek:
    case C::kRevokedWeek:
        break;
    }
    return {};
}

// D13 condition 4, checked at compile time: every windowed widget's days are in the closed set,
// and every id is unique and short enough to store.
constexpr bool catalogue_is_closed() {
    for (std::size_t i = 0; i < kWidgets.size(); ++i) {
        const auto& w = kWidgets[i];
        if (w.id.empty() || w.id.size() > kWidgetIdMaxBytes || w.criterion.empty())
            return false;
        for (std::size_t j = 0; j < i; ++j)
            if (kWidgets[j].id == w.id)
                return false;
        // R2: every Yuzu-issued count is withheld from a confined caller; every library widget
        // is admit-then-filter. Nothing in the catalogue is gated globally.
        if (w.gate != (w.group == G::kYuzuCa ? W::kFleetWideOnly : W::kFleetRead))
            return false;
        if (w.group == G::kYuzuCa) {
            const auto set = windows_of(w.ca_kind);
            if (!set.empty() ? !in_set(set, w.days) : w.days != 0)
                return false;
        }
    }
    return true;
}
static_assert(catalogue_is_closed(),
              "every widget id must be unique, every widget must carry its group's gate class, and "
              "every windowed Yuzu-issued widget must use a window from the closed set (ADR-0070 "
              "D13 condition 4)");

constexpr std::array<std::string_view, 9> kDefaultLayout{
    "lib.devices_reporting", "lib.devices_with_library", "lib.families_matched",
    "lib.devices_by_family", "lib.families_table",       "ca.active",
    "ca.expiring_30d",       "ca.revoked_30d",           "ca.issued_per_week",
};

constexpr bool default_layout_is_known() {
    for (const auto id : kDefaultLayout) {
        bool found = false;
        for (std::size_t i = 0; i < kWidgetCount; ++i)
            found = found || kWidgets[i].id == id;
        if (!found)
            return false;
    }
    return kDefaultLayout.size() <= kMaxLayoutWidgets;
}
static_assert(default_layout_is_known(), "the default layout must name catalogue widgets only");

// Floor division and modulo (C++ `/` and `%` truncate toward zero).
constexpr std::int64_t floor_div(std::int64_t a, std::int64_t b) {
    return a / b - ((a % b != 0) && ((a < 0) != (b < 0)) ? 1 : 0);
}
constexpr std::int64_t floor_mod(std::int64_t a, std::int64_t b) { return a - floor_div(a, b) * b; }

std::chrono::year_month_day civil(std::int64_t day) {
    return std::chrono::year_month_day{std::chrono::sys_days{std::chrono::days{day}}};
}

std::int64_t day_number(const std::chrono::year_month_day& ymd) {
    return std::chrono::sys_days{ymd}.time_since_epoch().count();
}

std::optional<std::string> int_arg_error(const nlohmann::json& args, const char* key,
                                         std::int64_t lo, std::int64_t hi) {
    if (!args.contains(key))
        return std::nullopt;
    const auto& v = args[key];
    const std::string range =
        std::string(key) + " must be between " + std::to_string(lo) + " and " + std::to_string(hi);
    if (!v.is_number_integer())
        return std::string(key) + " must be a JSON integer";
    // nlohmann stores every non-negative integer as unsigned: refuse above the bound rather than
    // let get<int64_t>() wrap.
    if (v.is_number_unsigned() && v.get<std::uint64_t>() > static_cast<std::uint64_t>(hi))
        return range;
    const auto n = v.get<std::int64_t>();
    if (n < lo || n > hi)
        return range;
    return std::nullopt;
}

std::string window_list(std::span<const int> set) {
    std::string out;
    for (const int d : set)
        out += (out.empty() ? "" : ", ") + std::to_string(d);
    return out;
}

std::string cid_prefix(std::string_view cid) {
    return cid.empty() ? std::string() : std::format("cid={} ", cid);
}

} // namespace

// ── Catalogue ────────────────────────────────────────────────────────────────

std::span<const Widget> catalogue() { return std::span<const Widget>(kWidgets.data(), kWidgetCount); }

const Widget* find_widget(std::string_view id) {
    for (const auto& w : catalogue())
        if (w.id == id)
            return &w;
    return nullptr;
}

std::span<const std::string_view> default_layout() { return kDefaultLayout; }

std::vector<std::string> default_layout_ids() {
    return std::vector<std::string>(kDefaultLayout.begin(), kDefaultLayout.end());
}

std::optional<std::string> layout_error(std::span<const std::string> ids) {
    if (ids.size() > kMaxLayoutWidgets)
        return "a layout holds at most " + std::to_string(kMaxLayoutWidgets) + " widgets";
    std::unordered_set<std::string_view> seen;
    for (std::size_t i = 0; i < ids.size(); ++i) {
        // Position only, never the caller's bytes: an unknown id may be anything.
        if (ids[i].size() > kWidgetIdMaxBytes || !find_widget(ids[i]))
            return "widgets[" + std::to_string(i) + "] is not a catalogue widget id";
        if (!seen.insert(ids[i]).second)
            return "widgets[" + std::to_string(i) + "] repeats a widget already in the layout";
    }
    return std::nullopt;
}

std::vector<std::string> known_ids(std::span<const std::string> ids) {
    std::vector<std::string> out;
    std::unordered_set<std::string_view> seen;
    for (const auto& id : ids)
        if (out.size() < kMaxLayoutWidgets && find_widget(id) && seen.insert(id).second)
            out.push_back(id);
    return out;
}

std::vector<std::string> unknown_ids(std::span<const std::string> ids) {
    std::vector<std::string> out;
    std::unordered_set<std::string_view> seen;
    for (const auto& id : ids)
        if (!find_widget(id) && seen.insert(id).second)
            out.push_back(id);
    return out;
}

MergedLayout merge_preserved(std::span<const std::string> caller_ids,
                             std::span<const std::string> stored_ids, std::size_t max_ids) {
    MergedLayout out;
    out.ids.assign(caller_ids.begin(), caller_ids.end());
    std::unordered_set<std::string_view> seen(caller_ids.begin(), caller_ids.end());
    for (const auto& id : unknown_ids(stored_ids)) {
        if (out.ids.size() >= max_ids)
            break;
        if (seen.insert(id).second) {
            out.ids.push_back(id);
            ++out.kept;
        }
    }
    return out;
}

bool is_default_layout(std::span<const std::string> widgets, std::size_t preserved_unknown) {
    return preserved_unknown == 0 && std::ranges::equal(widgets, kDefaultLayout);
}

std::string_view kind_name(WidgetKind k) {
    switch (k) {
    case K::kNumber:
        return "number";
    case K::kBar:
        return "bar";
    case K::kLine:
        return "line";
    case K::kTable:
        return "table";
    }
    return "number"; // unreachable: every enumerator returns above
}

std::string_view group_name(WidgetGroup g) {
    switch (g) {
    case G::kLibraries:
        return "Crypto libraries";
    case G::kYuzuCa:
        return "Yuzu-issued certificates";
    }
    return "Crypto libraries"; // unreachable
}

std::string_view gate_name(WidgetGate g) {
    switch (g) {
    case W::kFleetRead:
        return "fleet_read";
    case W::kFleetWideOnly:
        return "fleet_wide_only";
    case W::kGlobal:
        return "global";
    }
    return "global"; // unreachable
}

std::string_view drill_name(WidgetDrill d) {
    switch (d) {
    case D::kLibraryFamilies:
        return "library_families";
    case D::kLibraryFamilyDevices:
        return "library_family_devices";
    case D::kCaCertificates:
        return "ca_certificates";
    case D::kCaWeek:
        return "ca_week";
    }
    return "library_families"; // unreachable
}

// ── Availability ─────────────────────────────────────────────────────────────

std::string_view access_name(Access a) {
    switch (a) {
    case Access::kAvailable:
        return "available";
    case Access::kRefused:
        return "not_available";
    case Access::kConfined:
        return "confined";
    case Access::kDegraded:
        return "access_check_unavailable";
    }
    return "not_available"; // unreachable
}

Access fleet_access(WidgetGate gate, bool admitted, bool confined, bool degraded) {
    if (!admitted)
        return degraded ? Access::kDegraded : Access::kRefused;
    if (gate == W::kFleetWideOnly && confined)
        return Access::kConfined;
    return Access::kAvailable;
}

Access AccessMemo::operator()(WidgetGate gate, std::string_view securable,
                              std::string_view operation) {
    for (const auto& [g, s, o, a] : seen_)
        if (g == gate && s == securable && o == operation)
            return a;
    const Access a = probe_ ? probe_(gate, securable, operation) : Access::kRefused;
    seen_.emplace_back(gate, std::string(securable), std::string(operation), a);
    return a;
}

Access AccessMemo::drill(const Widget& w) {
    if (w.group == G::kYuzuCa)
        return (*this)(W::kGlobal, kCaDrillSecurable, kCaDrillOperation);
    return widget(w);
}

// ── Yuzu-issued kinds, buckets and windows ───────────────────────────────────

std::string_view ca_kind_name(CaCertKind k) {
    switch (k) {
    case C::kActive:
        return "active";
    case C::kExpiring:
        return "expiring";
    case C::kExpired:
        return "expired";
    case C::kRevoked:
        return "revoked";
    case C::kIssued:
        return "issued";
    case C::kIssuedWeek:
        return "issued_week";
    case C::kRevokedWeek:
        return "revoked_week";
    }
    return "active"; // unreachable
}

std::optional<CaCertKind> parse_ca_kind(std::string_view s) {
    for (const auto k : {C::kActive, C::kExpiring, C::kExpired, C::kRevoked, C::kIssued,
                         C::kIssuedWeek, C::kRevokedWeek})
        if (ca_kind_name(k) == s)
            return k;
    return std::nullopt;
}

std::string_view bucket_name(RevokedBucket b) {
    switch (b) {
    case RevokedBucket::kSuperseded:
        return "superseded";
    case RevokedBucket::kUnpublished:
        return "unpublished";
    case RevokedBucket::kOther:
        return "other";
    }
    return "other"; // unreachable
}

std::optional<RevokedBucket> parse_bucket(std::string_view s) {
    for (const auto b : kRevokedBuckets)
        if (bucket_name(b) == s)
            return b;
    return std::nullopt;
}

bool kind_takes_days(CaCertKind k) { return !windows_of(k).empty(); }

bool kind_takes_week(CaCertKind k) { return k == C::kIssuedWeek || k == C::kRevokedWeek; }

bool kind_takes_bucket(CaCertKind k) { return k == C::kRevoked || k == C::kRevokedWeek; }

std::span<const int> windows_for(CaCertKind k) { return windows_of(k); }

std::string rule_id(CaCertKind k, std::optional<RevokedBucket> bucket) {
    std::string out = "yuzu_ca_" + std::string(ca_kind_name(k));
    if (bucket && kind_takes_bucket(k))
        out += "_" + std::string(bucket_name(*bucket));
    return out;
}

namespace {

// The revoked-bucket clause of a criterion: the reason exactly as the store compares it.
std::string bucket_clause(std::optional<RevokedBucket> b) {
    if (!b)
        return ", any recorded reason";
    switch (*b) {
    case RevokedBucket::kSuperseded:
        return ", reason recorded as superseded (replaced by a same-key successor)";
    case RevokedBucket::kUnpublished:
        return ", reason recorded as unpublished (recorded, never delivered)";
    case RevokedBucket::kOther:
        return ", any other recorded reason";
    }
    return {}; // unreachable
}

} // namespace

std::string criterion_text(CaCertKind k, int days, std::string_view week_label,
                           std::optional<RevokedBucket> bucket) {
    switch (k) {
    case C::kActive:
        return "Status active, issued on or before as_of, notAfter on or after as_of (valid "
               "through notAfter, inclusive)";
    case C::kExpiring:
        return std::format("Status active, notAfter from as_of through as_of + {} days (valid "
                           "through notAfter, inclusive)",
                           days);
    case C::kExpired:
        return std::format("Status active, notAfter from as_of - {} days up to, not including, "
                           "as_of",
                           days);
    case C::kRevoked:
        return std::format("Revoked after as_of - {} days and on or before as_of", days) +
               bucket_clause(bucket);
    case C::kIssued:
        return std::format("Issued after as_of - {} days and on or before as_of, excluding "
                           "unpublished (recorded, never delivered)",
                           days);
    case C::kIssuedWeek:
        return std::format("Issued in ISO week {} (Monday 00:00 UTC start) up to as_of, excluding "
                           "unpublished (recorded, never delivered)",
                           week_label);
    case C::kRevokedWeek:
        return std::format("Revoked in ISO week {} (Monday 00:00 UTC start) up to as_of",
                           week_label) +
               bucket_clause(bucket);
    }
    return {}; // unreachable
}

// ── ISO weeks and timestamps ─────────────────────────────────────────────────

std::int64_t week_start_of(std::int64_t epoch) {
    const std::int64_t day = floor_div(epoch, kSecondsPerDay);
    // 1970-01-01 was a Thursday: (day + 3) mod 7 is 0 on a Monday.
    return (day - floor_mod(day + 3, 7)) * kSecondsPerDay;
}

std::vector<std::int64_t> week_starts(std::int64_t as_of) {
    const std::int64_t last = week_start_of(as_of);
    std::vector<std::int64_t> out;
    out.reserve(kWeeklyBuckets);
    for (int i = kWeeklyBuckets - 1; i >= 0; --i)
        out.push_back(last - static_cast<std::int64_t>(i) * kSecondsPerWeek);
    return out;
}

std::string iso_week_label(std::int64_t week_start) {
    // The ISO year is the year of the week's Thursday; the week number counts Thursdays.
    const std::int64_t thursday = floor_div(week_start_of(week_start), kSecondsPerDay) + 3;
    const auto ymd = civil(thursday);
    const auto jan1 = day_number(ymd.year() / std::chrono::January / 1);
    const auto week = (thursday - jan1) / 7 + 1;
    return std::format("{:04}-W{:02}", static_cast<int>(ymd.year()), week);
}

std::optional<std::int64_t> parse_iso_week(std::string_view label) {
    if (label.size() != 8 || label[4] != '-' || label[5] != 'W')
        return std::nullopt;
    const auto year = parse_nonneg(label.substr(0, 4));
    const auto week = parse_nonneg(label.substr(6, 2));
    if (!year || !week || *year < 1 || *week < 1 || *week > 53)
        return std::nullopt;
    // Week 1 is the week containing 4 January.
    const auto jan4 = day_number(std::chrono::year{static_cast<int>(*year)} / std::chrono::January / 4);
    const std::int64_t start = week_start_of(jan4 * kSecondsPerDay) + (*week - 1) * kSecondsPerWeek;
    // Round trip: refuses W53 of a 52-week year (it would label as next year's W01).
    if (iso_week_label(start) != label)
        return std::nullopt;
    return start;
}

std::string iso8601_utc(std::int64_t epoch) {
    const std::int64_t day = floor_div(epoch, kSecondsPerDay);
    const std::int64_t secs = floor_mod(epoch, kSecondsPerDay);
    const auto ymd = civil(day);
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", static_cast<int>(ymd.year()),
                       static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day()),
                       secs / 3600, (secs % 3600) / 60, secs % 60);
}

// ── Parameters ───────────────────────────────────────────────────────────────

namespace {

constexpr std::string_view kUnknownKind =
    "unknown kind (expected active, expiring, expired, revoked, issued, issued_week or "
    "revoked_week)";
constexpr std::string_view kBadBucket = "bucket must be superseded, unpublished or other";
constexpr std::string_view kBadWeek = "invalid week (expected an ISO week such as 2026-W40)";

std::string limit_range() {
    return "limit must be an integer from 1 to " + std::to_string(kCertPageMax);
}
// H2: the filtered list pages by keyset cursor only.
constexpr std::string_view kOffsetRefused =
    "offset does not apply to a filtered list; page with cursor (the previous page's next_cursor)";
std::string cursor_length_error() {
    return "cursor must be a non-empty string of at most " + std::to_string(kCertCursorMaxBytes) +
           " bytes";
}

constexpr std::array<std::string_view, 6> kFilterKeys{"kind",   "days",  "week",
                                                      "bucket", "as_of", "cursor"};

} // namespace

std::expected<CaCertQuery, std::string> parse_cert_params(const crypto_library::Params& p) {
    std::optional<std::string> err;
    const auto* kind = find_param(p, "kind", err);
    const auto* days = find_param(p, "days", err);
    const auto* week = find_param(p, "week", err);
    const auto* bucket = find_param(p, "bucket", err);
    const auto* as_of = find_param(p, "as_of", err);
    const auto* limit = find_param(p, "limit", err);
    const auto* offset = find_param(p, "offset", err);
    const auto* cursor = find_param(p, "cursor", err);
    if (err)
        return std::unexpected(*err);
    if (offset)
        return std::unexpected(std::string(kOffsetRefused));
    if (!kind || kind->empty())
        return std::unexpected("kind is required");
    const auto k = parse_ca_kind(*kind);
    if (!k)
        return std::unexpected(std::string(kUnknownKind));
    const std::string kn(ca_kind_name(*k));
    CaCertQuery q;
    q.kind = *k;
    if (kind_takes_days(*k)) {
        if (!days || days->empty())
            return std::unexpected("days is required for kind " + kn);
        const auto n = parse_nonneg(*days);
        if (!n || *n > 3650 || !in_set(windows_of(*k), static_cast<int>(*n)))
            return std::unexpected("days must be one of " + window_list(windows_of(*k)) +
                                   " for kind " + kn);
        q.days = static_cast<int>(*n);
    } else if (days) {
        return std::unexpected("days does not apply to kind " + kn);
    }
    if (kind_takes_week(*k)) {
        if (!week || week->empty())
            return std::unexpected("week is required for kind " + kn);
        const auto ws = valid_text(*week) ? parse_iso_week(*week) : std::nullopt;
        if (!ws)
            return std::unexpected(std::string(kBadWeek));
        q.week_start = *ws;
    } else if (week) {
        return std::unexpected("week does not apply to kind " + kn);
    }
    if (bucket) {
        if (!kind_takes_bucket(*k))
            return std::unexpected("bucket does not apply to kind " + kn);
        const auto b = parse_bucket(*bucket);
        if (!b)
            return std::unexpected(std::string(kBadBucket));
        q.bucket = *b;
    }
    if (as_of) {
        const auto n = parse_nonneg(*as_of);
        if (!n)
            return std::unexpected("as_of must be an integer (epoch seconds)");
        q.as_of = *n; // its window is checked on the database clock by the read (M2)
    }
    q.limit = kCertPageDefault;
    if (limit) {
        const auto n = parse_nonneg(*limit);
        if (!n || *n < 1 || *n > kCertPageMax)
            return std::unexpected(limit_range());
        q.limit = static_cast<int>(*n);
    }
    if (cursor) {
        if (cursor->empty() || cursor->size() > kCertCursorMaxBytes || !valid_text(*cursor))
            return std::unexpected(cursor_length_error());
        q.cursor = *cursor; // decoded and bound to this filter by the read
    }
    return q;
}

bool has_cert_filter_params(const crypto_library::Params& p) {
    for (const auto key : kFilterKeys)
        if (p.contains(std::string(key)))
            return true;
    return false;
}

bool has_cert_filter_args(const nlohmann::json& args) {
    if (!args.is_object())
        return false;
    for (const auto key : kFilterKeys)
        if (args.contains(key))
            return true;
    return false;
}

std::optional<std::string> strict_cert_args_error(const nlohmann::json& args) {
    if (!args.is_object())
        return std::string(crypto_library::kArgumentsNotObject);
    if (!args.contains("kind"))
        return "kind is required";
    if (!args["kind"].is_string())
        return "kind must be a string";
    const auto k = parse_ca_kind(args["kind"].get<std::string>());
    if (!k)
        return std::string(kUnknownKind);
    const std::string kn(ca_kind_name(*k));
    if (args.contains("days")) {
        if (!kind_takes_days(*k))
            return "days does not apply to kind " + kn;
        if (const auto e = int_arg_error(args, "days", 1, 3650))
            return e;
        if (!in_set(windows_of(*k), static_cast<int>(args["days"].get<std::int64_t>())))
            return "days must be one of " + window_list(windows_of(*k)) + " for kind " + kn;
    } else if (kind_takes_days(*k)) {
        return "days is required for kind " + kn;
    }
    if (args.contains("week")) {
        if (!kind_takes_week(*k))
            return "week does not apply to kind " + kn;
        if (!args["week"].is_string())
            return "week must be a string";
        const auto w = args["week"].get<std::string>();
        if (!valid_text(w) || !parse_iso_week(w))
            return std::string(kBadWeek);
    } else if (kind_takes_week(*k)) {
        return "week is required for kind " + kn;
    }
    if (args.contains("bucket")) {
        if (!kind_takes_bucket(*k))
            return "bucket does not apply to kind " + kn;
        if (!args["bucket"].is_string() || !parse_bucket(args["bucket"].get<std::string>()))
            return std::string(kBadBucket);
    }
    if (args.contains("as_of")) {
        if (const auto e = int_arg_error(args, "as_of", 0, std::numeric_limits<std::int64_t>::max()))
            return e;
    }
    if (const auto e = int_arg_error(args, "limit", 1, kCertPageMax))
        return e;
    if (args.contains("offset"))
        return std::string(kOffsetRefused);
    if (args.contains("cursor")) {
        const auto& c = args["cursor"];
        if (!c.is_string() || c.get<std::string>().empty() ||
            c.get<std::string>().size() > kCertCursorMaxBytes)
            return cursor_length_error();
    }
    return std::nullopt;
}

std::optional<std::string> strict_layout_args_error(const nlohmann::json& args) {
    if (!args.is_object())
        return std::string(crypto_library::kArgumentsNotObject);
    for (const auto& [key, _] : args.items())
        if (key != "widgets" && key != "expected_version")
            return "unknown argument (only widgets and expected_version are accepted)";
    if (!args.contains("widgets"))
        return "widgets is required";
    const auto& w = args["widgets"];
    if (!w.is_array())
        return "widgets must be an array of widget ids";
    if (w.size() > kMaxLayoutWidgets)
        return "a layout holds at most " + std::to_string(kMaxLayoutWidgets) + " widgets";
    for (std::size_t i = 0; i < w.size(); ++i)
        if (!w[i].is_string())
            return "widgets[" + std::to_string(i) + "] must be a string";
    if (args.contains("expected_version"))
        if (const auto e = int_arg_error(args, "expected_version", 0,
                                         std::numeric_limits<std::int64_t>::max()))
            return e;
    return std::nullopt;
}

LayoutRequest layout_request_from_args(const nlohmann::json& args) {
    LayoutRequest out;
    out.widgets.reserve(args["widgets"].size());
    for (const auto& v : args["widgets"])
        out.widgets.push_back(v.get<std::string>());
    if (args.contains("expected_version"))
        out.expected_version = args["expected_version"].get<std::int64_t>();
    return out;
}

std::expected<LayoutRequest, std::string> parse_layout_body(std::string_view body) {
    const auto j = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded())
        return std::unexpected("request body must be JSON");
    if (!j.is_object())
        return std::unexpected("request body must be a JSON object");
    if (const auto e = strict_layout_args_error(j))
        return std::unexpected(*e);
    return layout_request_from_args(j);
}

// ── Keyset cursor (H2) ───────────────────────────────────────────────────────

namespace {
constexpr std::string_view kCursorPrefix = "c1:";
constexpr std::string_view kInvalidCursor = "invalid cursor";
constexpr std::string_view kCursorFilterMismatch =
    "cursor was issued for a different kind, days, week or bucket; start the list again without "
    "a cursor";
bool is_serial_hex(std::string_view s) {
    return !s.empty() && s.size() <= 128 && std::ranges::all_of(s, [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
}
} // namespace

std::string cert_cursor_fingerprint(const CaCertQuery& q) {
    const std::string kind(ca_kind_name(q.kind));
    const std::string days = std::to_string(kind_takes_days(q.kind) ? q.days : 0);
    const std::string week = std::to_string(kind_takes_week(q.kind) ? q.week_start : 0);
    const std::string bucket = q.bucket ? std::string(bucket_name(*q.bucket)) : std::string();
    const std::string ws(kWindowSetVersion);
    return fnv1a_hex16(length_prefixed({&ws, &kind, &days, &week, &bucket}));
}

std::string encode_cert_cursor(const CertCursor& at, std::string_view fp) {
    const std::string key = std::to_string(at.sort_key);
    const std::string as_of = std::to_string(at.as_of);
    std::string out(kCursorPrefix);
    out += fp;
    out += ':';
    out += keyset::b64url_encode(length_prefixed({&key, &at.serial_hex, &as_of}));
    return out;
}

std::expected<CertCursor, std::string> decode_cert_cursor(std::string_view token,
                                                          std::string_view fp) {
    const auto bad = [] { return std::unexpected(std::string(kInvalidCursor)); };
    // c1:<fp16>:<payload> - the base64url alphabet has no ':'.
    constexpr std::size_t kHead = kCursorPrefix.size() + 16;
    if (token.size() > kCertCursorMaxBytes || !token.starts_with(kCursorPrefix) ||
        token.size() < kHead + 2 || token[kHead] != ':')
        return bad();
    const auto got_fp = token.substr(kCursorPrefix.size(), 16);
    const auto payload = keyset::b64url_decode(token.substr(kHead + 1));
    if (!is_lower_hex16(got_fp) || !payload)
        return bad();
    const auto f = read_length_prefixed(*payload, 3);
    if (!f)
        return bad();
    const auto key = parse_nonneg((*f)[0]);
    const auto as_of = parse_nonneg((*f)[2]);
    if (!key || !as_of || !is_serial_hex((*f)[1]))
        return bad();
    CertCursor out{*key, std::string((*f)[1]), *as_of};
    // One spelling per position: a re-encoded token must be byte-identical (tamper evidence for
    // non-canonical base64url tails and number spellings such as a leading zero).
    if (encode_cert_cursor(out, got_fp) != token)
        return bad();
    if (got_fp != fp)
        return std::unexpected(std::string(kCursorFilterMismatch));
    return out;
}

// ── Audit ────────────────────────────────────────────────────────────────────

std::string audit_detail_stats(std::string_view cid, std::int64_t as_of,
                               std::optional<std::size_t> widgets) {
    std::string out = std::format("{}ws={} as_of={}", cid_prefix(cid), kWindowSetVersion, as_of);
    if (widgets)
        out += std::format(" widgets={}", *widgets);
    return out;
}

std::string audit_target(const CaCertQuery& q) {
    std::string out = "kind=" + std::string(ca_kind_name(q.kind));
    if (kind_takes_days(q.kind))
        out += " days=" + std::to_string(q.days);
    if (kind_takes_week(q.kind))
        out += " week=" + iso_week_label(q.week_start);
    if (q.bucket)
        out += " bucket=" + std::string(bucket_name(*q.bucket));
    return out;
}

std::string audit_detail_certs(std::string_view cid, const CaCertPage& page) {
    return std::format("{}ws={} as_of={}{} {} rows={} page={} total={}", cid_prefix(cid),
                       kWindowSetVersion, page.as_of, page.query.as_of ? " pinned" : "",
                       audit_target(page.query), page.rows.size(),
                       page.query.cursor.empty() ? "first" : "continuation", page.total);
}

std::string audit_detail_ca_degraded(std::string_view cid, std::optional<std::int64_t> as_of,
                                     CryptoReadCause cause) {
    std::string_view what;
    switch (cause) {
    case CryptoReadCause::kCapacity:
        what = "capacity in use";
        break;
    case CryptoReadCause::kAccessCheck:
        what = "access check unavailable";
        break;
    case CryptoReadCause::kNone:
    case CryptoReadCause::kStoreDegraded:
        what = "store degraded";
        break;
    }
    return std::format("{}ws={} as_of={} {}", cid_prefix(cid), kWindowSetVersion,
                       as_of ? std::to_string(*as_of) : std::string("db_now"), what);
}

std::string audit_detail_ca_withheld(std::string_view cid) {
    return std::format("{}ws={} withheld=confined", cid_prefix(cid), kWindowSetVersion);
}

std::string audit_detail_layout(std::string_view cid, std::size_t widgets,
                                std::optional<std::int64_t> expected_version) {
    std::string out = std::format("{}widgets={}", cid_prefix(cid), widgets);
    if (expected_version)
        out += std::format(" expected_version={}", *expected_version);
    return out;
}

// ── JSON ─────────────────────────────────────────────────────────────────────

nlohmann::json widgets_json(AccessMemo& access) {
    using nlohmann::json;
    auto rows = json::array();
    for (const auto& w : catalogue()) {
        const Access a = access.widget(w);
        json row{{"id", w.id},
                 {"title", w.title},
                 {"kind", kind_name(w.kind)},
                 {"group", group_name(w.group)},
                 {"gate", gate_name(w.gate)},
                 {"securable", w.securable},
                 {"operation", w.operation},
                 {"criterion", w.criterion},
                 {"drill", drill_name(w.drill)},
                 {"available", a == Access::kAvailable},
                 {"availability", access_name(a)}};
        if (w.group == G::kYuzuCa) {
            row["ca_kind"] = ca_kind_name(w.ca_kind);
            row["days"] = kind_takes_days(w.ca_kind) ? json(w.days) : json(nullptr);
            row["drill_securable"] = kCaDrillSecurable;
            row["drill_operation"] = kCaDrillOperation;
            row["drill_available"] = access.drill(w) == Access::kAvailable;
        }
        rows.push_back(std::move(row));
    }
    return json{{"window_set", kWindowSetVersion},
                {"widgets", std::move(rows)},
                {"default_layout", default_layout_ids()},
                {"max_layout_widgets", kMaxLayoutWidgets},
                {"scope_note", kScopeNote}};
}

nlohmann::json layout_json(const CryptoDashboardLayout& layout) {
    return nlohmann::json{{"widgets", layout.widgets},
                          {"is_default", layout.is_default},
                          {"version", layout.version},
                          {"preserved_unknown", layout.preserved_unknown},
                          {"max_layout_widgets", kMaxLayoutWidgets}};
}

namespace {

// One D13 count with everything condition 1 requires beside it.
nlohmann::json count_obj(CaCertKind k, int days, std::string_view week_label,
                         std::optional<RevokedBucket> bucket, std::int64_t count,
                         std::int64_t as_of) {
    nlohmann::json o{{"rule_id", rule_id(k, bucket)},
                     {"criterion", criterion_text(k, days, week_label, bucket)},
                     {"rule_set_version", kWindowSetVersion},
                     {"as_of", as_of},
                     {"count", count}};
    if (kind_takes_days(k))
        o["threshold"] = days;
    if (kind_takes_week(k))
        o["week"] = std::string(week_label);
    if (bucket)
        o["bucket"] = bucket_name(*bucket);
    return o;
}

} // namespace

nlohmann::json ca_stats_json(const CaCertStats& s) {
    using nlohmann::json;
    auto windows = [&](CaCertKind k, const std::vector<CaWindowCount>& v) {
        auto out = json::array();
        for (const auto& c : v)
            out.push_back(count_obj(k, c.days, {}, std::nullopt, c.count, s.as_of));
        return out;
    };
    auto revoked = json::array();
    for (const auto& r : s.revoked)
        for (const auto b : kRevokedBuckets)
            revoked.push_back(count_obj(C::kRevoked, r.days, {}, b,
                                        b == RevokedBucket::kSuperseded    ? r.superseded
                                        : b == RevokedBucket::kUnpublished ? r.unpublished
                                                                           : r.other,
                                        s.as_of));
    auto weeks = json::array();
    for (const auto& w : s.weeks) {
        auto rev = json::array();
        for (const auto b : kRevokedBuckets)
            rev.push_back(count_obj(C::kRevokedWeek, 0, w.label, b,
                                    b == RevokedBucket::kSuperseded    ? w.revoked_superseded
                                    : b == RevokedBucket::kUnpublished ? w.revoked_unpublished
                                                                       : w.revoked_other,
                                    s.as_of));
        weeks.push_back(json{{"week", w.label},
                             {"week_start", w.week_start},
                             {"partial", w.partial},
                             {"issued", count_obj(C::kIssuedWeek, 0, w.label, std::nullopt,
                                                  w.issued, s.as_of)},
                             {"revoked", std::move(rev)}});
    }
    return json{{"scope", "yuzu_issued"},
                {"scope_note", kScopeNote},
                {"window_edge_note", kWindowEdgeNote},
                {"rule_set_version", kWindowSetVersion},
                {"as_of", s.as_of},
                {"as_of_iso", iso8601_utc(s.as_of)},
                {"active", count_obj(C::kActive, 0, {}, std::nullopt, s.active, s.as_of)},
                {"expiring_within_days", windows(C::kExpiring, s.expiring)},
                {"expired_within_days", windows(C::kExpired, s.expired)},
                {"revoked_within_days", std::move(revoked)},
                {"issued_within_days",
                 count_obj(C::kIssued, s.issued.days, {}, std::nullopt, s.issued.count, s.as_of)},
                {"week_basis", "last 52 ISO weeks (UTC, Monday start); the current week is partial"},
                {"weeks", std::move(weeks)}};
}

nlohmann::json ca_items_json(const CaCertPage& p) {
    using nlohmann::json;
    auto rows = json::array();
    for (const auto& r : p.rows)
        rows.push_back(json{{"serial_hex", r.serial_hex},
                            {"subject", r.subject},
                            {"san", r.san},
                            {"purpose", r.purpose},
                            {"status", r.status},
                            {"not_after", r.not_after},
                            {"issued_at", r.issued_at},
                            {"revoked_at", r.revoked_at},
                            {"revocation_reason", r.revocation_reason},
                            {"issued_by", r.issued_by},
                            {"issuer_key_id", r.issuer_key_id}});
    return rows;
}

nlohmann::json ca_filter_json(const CaCertPage& p) {
    using nlohmann::json;
    const auto& q = p.query;
    const std::string week = kind_takes_week(q.kind) ? iso_week_label(q.week_start) : std::string();
    return json{{"kind", ca_kind_name(q.kind)},
                {"days", kind_takes_days(q.kind) ? json(q.days) : json(nullptr)},
                {"week", week.empty() ? json(nullptr) : json(week)},
                {"week_start", week.empty() ? json(nullptr) : json(q.week_start)},
                {"bucket", q.bucket ? json(bucket_name(*q.bucket)) : json(nullptr)},
                {"rule_id", rule_id(q.kind, q.bucket)},
                {"criterion", criterion_text(q.kind, q.days, week, q.bucket)},
                {"rule_set_version", kWindowSetVersion},
                {"as_of", p.as_of},
                {"as_of_iso", iso8601_utc(p.as_of)},
                {"total", p.total},
                {"scope_note", kScopeNote}};
}

} // namespace yuzu::server::crypto_widgets
