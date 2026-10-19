#include "crypto_widget_catalogue.hpp"

#include "model_param_helpers.hpp" // find_param / parse_nonneg / valid_text (shared with the models)

#include <algorithm>
#include <chrono>
#include <format>
#include <set>
#include <unordered_set>
#include <utility>

namespace yuzu::server::crypto_widgets {

namespace {

using model_detail::find_param;
using model_detail::parse_nonneg;
using model_detail::valid_text;

constexpr std::string_view kInventory = "Inventory";
constexpr std::string_view kSecurity = "Security";
constexpr std::string_view kRead = "Read";

using K = WidgetKind;
using G = WidgetGroup;
using D = WidgetDrill;
using C = CaCertKind;

// Every Yuzu-issued title says "Yuzu-issued" (ADR-0070 D6: this is Yuzu's own PKI, never the
// fleet's certificates), and every criterion names its window (D13 condition 1).
constexpr std::array<Widget, 23> kWidgets{{
    {"lib.devices_reporting", "Devices reporting inventory", K::kNumber, G::kLibraries, kInventory,
     kRead, "Devices in your scope with an installed-software inventory report",
     D::kLibraryFamilies},
    {"lib.devices_with_library", "Devices with a crypto library", K::kNumber, G::kLibraries,
     kInventory, kRead,
     "Distinct devices with at least one package matching a library family in the curated table",
     D::kLibraryFamilies},
    {"lib.families_matched", "Library families found", K::kNumber, G::kLibraries, kInventory, kRead,
     "Library families with at least one matching device", D::kLibraryFamilies},
    {"lib.families_table", "Crypto libraries", K::kTable, G::kLibraries, kInventory, kRead,
     "Each family's distinct device count and its version buckets", D::kLibraryFamilyDevices},
    {"lib.devices_by_family", "Devices by library family", K::kBar, G::kLibraries, kInventory, kRead,
     "Distinct devices carrying any package of each family", D::kLibraryFamilyDevices},

    {"ca.active", "Yuzu-issued certificates: active", K::kNumber, G::kYuzuCa, kSecurity, kRead,
     "Status active and not expired at as_of", D::kCaCertificates, C::kActive},
    {"ca.expiring_3d", "Yuzu-issued: expiring within 3 days", K::kNumber, G::kYuzuCa, kSecurity,
     kRead, "Active, expiring after as_of and within 3 days", D::kCaCertificates, C::kExpiring, 3},
    {"ca.expiring_7d", "Yuzu-issued: expiring within 7 days", K::kNumber, G::kYuzuCa, kSecurity,
     kRead, "Active, expiring after as_of and within 7 days", D::kCaCertificates, C::kExpiring, 7},
    {"ca.expiring_14d", "Yuzu-issued: expiring within 14 days", K::kNumber, G::kYuzuCa, kSecurity,
     kRead, "Active, expiring after as_of and within 14 days", D::kCaCertificates, C::kExpiring, 14},
    {"ca.expiring_21d", "Yuzu-issued: expiring within 21 days", K::kNumber, G::kYuzuCa, kSecurity,
     kRead, "Active, expiring after as_of and within 21 days", D::kCaCertificates, C::kExpiring, 21},
    {"ca.expiring_30d", "Yuzu-issued: expiring within 30 days", K::kNumber, G::kYuzuCa, kSecurity,
     kRead, "Active, expiring after as_of and within 30 days", D::kCaCertificates, C::kExpiring, 30},
    {"ca.expiring_60d", "Yuzu-issued: expiring within 60 days", K::kNumber, G::kYuzuCa, kSecurity,
     kRead, "Active, expiring after as_of and within 60 days", D::kCaCertificates, C::kExpiring, 60},
    {"ca.expired_7d", "Yuzu-issued: expired in the last 7 days", K::kNumber, G::kYuzuCa, kSecurity,
     kRead, "Expiry date within the 7 days up to as_of, any status", D::kCaCertificates,
     C::kExpired, 7},
    {"ca.expired_30d", "Yuzu-issued: expired in the last 30 days", K::kNumber, G::kYuzuCa,
     kSecurity, kRead, "Expiry date within the 30 days up to as_of, any status",
     D::kCaCertificates, C::kExpired, 30},
    {"ca.expired_60d", "Yuzu-issued: expired in the last 60 days", K::kNumber, G::kYuzuCa,
     kSecurity, kRead, "Expiry date within the 60 days up to as_of, any status",
     D::kCaCertificates, C::kExpired, 60},
    {"ca.expired_90d", "Yuzu-issued: expired in the last 90 days", K::kNumber, G::kYuzuCa,
     kSecurity, kRead, "Expiry date within the 90 days up to as_of, any status",
     D::kCaCertificates, C::kExpired, 90},
    {"ca.revoked_7d", "Yuzu-issued: revoked in the last 7 days", K::kNumber, G::kYuzuCa, kSecurity,
     kRead, "Revoked by Yuzu's CA within the 7 days up to as_of", D::kCaCertificates, C::kRevoked,
     7},
    {"ca.revoked_30d", "Yuzu-issued: revoked in the last 30 days", K::kNumber, G::kYuzuCa,
     kSecurity, kRead, "Revoked by Yuzu's CA within the 30 days up to as_of", D::kCaCertificates,
     C::kRevoked, 30},
    {"ca.revoked_60d", "Yuzu-issued: revoked in the last 60 days", K::kNumber, G::kYuzuCa,
     kSecurity, kRead, "Revoked by Yuzu's CA within the 60 days up to as_of", D::kCaCertificates,
     C::kRevoked, 60},
    {"ca.revoked_90d", "Yuzu-issued: revoked in the last 90 days", K::kNumber, G::kYuzuCa,
     kSecurity, kRead, "Revoked by Yuzu's CA within the 90 days up to as_of", D::kCaCertificates,
     C::kRevoked, 90},
    {"ca.issued_7d", "Yuzu-issued: issued in the last 7 days", K::kNumber, G::kYuzuCa, kSecurity,
     kRead, "Issued by Yuzu's CA within the 7 days up to as_of", D::kCaCertificates, C::kIssued, 7},
    {"ca.issued_per_week", "Yuzu-issued: issued per week", K::kLine, G::kYuzuCa, kSecurity, kRead,
     "Certificates issued in each of the last 26 ISO weeks (Monday start, UTC)", D::kCaWeek,
     C::kIssuedWeek},
    {"ca.revoked_per_week", "Yuzu-issued: revoked per week", K::kLine, G::kYuzuCa, kSecurity, kRead,
     "Certificates revoked in each of the last 26 ISO weeks (Monday start, UTC)", D::kCaWeek,
     C::kRevokedWeek},
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
        if (w.group == G::kYuzuCa) {
            const auto set = windows_of(w.ca_kind);
            if (!set.empty() ? !in_set(set, w.days) : w.days != 0)
                return false;
        }
    }
    return true;
}
static_assert(catalogue_is_closed(),
              "every widget id must be unique, and every windowed Yuzu-issued widget must use a "
              "window from the closed set (ADR-0070 D13 condition 4)");

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

// ── Yuzu-issued kinds and windows ────────────────────────────────────────────

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

bool kind_takes_days(CaCertKind k) { return !windows_of(k).empty(); }

bool kind_takes_week(CaCertKind k) { return k == C::kIssuedWeek || k == C::kRevokedWeek; }

std::span<const int> windows_for(CaCertKind k) { return windows_of(k); }

std::string criterion_text(CaCertKind k, int days, std::string_view week_label) {
    switch (k) {
    case C::kActive:
        return "Active and not expired";
    case C::kExpiring:
        return std::format("Expiring within {} days", days);
    case C::kExpired:
        return std::format("Expired in the last {} days", days);
    case C::kRevoked:
        return std::format("Revoked in the last {} days", days);
    case C::kIssued:
        return std::format("Issued in the last {} days", days);
    case C::kIssuedWeek:
        return std::format("Issued in ISO week {}", week_label);
    case C::kRevokedWeek:
        return std::format("Revoked in ISO week {}", week_label);
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

std::expected<CaCertQuery, std::string> parse_cert_params(const crypto_library::Params& p) {
    std::optional<std::string> err;
    const auto* kind = find_param(p, "kind", err);
    const auto* days = find_param(p, "days", err);
    const auto* week = find_param(p, "week", err);
    const auto* limit = find_param(p, "limit", err);
    const auto* offset = find_param(p, "offset", err);
    if (err)
        return std::unexpected(*err);
    if (!kind || kind->empty())
        return std::unexpected("kind is required");
    const auto k = parse_ca_kind(*kind);
    if (!k)
        return std::unexpected(
            "unknown kind (expected active, expiring, expired, revoked, issued, issued_week or "
            "revoked_week)");
    CaCertQuery q;
    q.kind = *k;
    if (kind_takes_days(*k)) {
        if (!days || days->empty())
            return std::unexpected("days is required for kind " + std::string(ca_kind_name(*k)));
        const auto n = parse_nonneg(*days);
        if (!n || *n > 3650 || !in_set(windows_of(*k), static_cast<int>(*n)))
            return std::unexpected("days must be one of " + window_list(windows_of(*k)) +
                                   " for kind " + std::string(ca_kind_name(*k)));
        q.days = static_cast<int>(*n);
    } else if (days) {
        return std::unexpected("days does not apply to kind " + std::string(ca_kind_name(*k)));
    }
    if (kind_takes_week(*k)) {
        if (!week || week->empty())
            return std::unexpected("week is required for kind " + std::string(ca_kind_name(*k)));
        const auto ws = valid_text(*week) ? parse_iso_week(*week) : std::nullopt;
        if (!ws)
            return std::unexpected("invalid week (expected an ISO week such as 2026-W40)");
        q.week_start = *ws;
    } else if (week) {
        return std::unexpected("week does not apply to kind " + std::string(ca_kind_name(*k)));
    }
    q.limit = kCertPageDefault;
    if (limit && !limit->empty()) {
        const auto n = parse_nonneg(*limit);
        if (!n)
            return std::unexpected("invalid limit (expected a non-negative integer)");
        q.limit = static_cast<int>(std::clamp<std::int64_t>(*n, 1, kCertPageMax));
    }
    if (offset && !offset->empty()) {
        const auto n = parse_nonneg(*offset);
        if (!n || *n > kCertOffsetMax)
            return std::unexpected("invalid offset (expected an integer from 0 to " +
                                   std::to_string(kCertOffsetMax) + ")");
        q.offset = static_cast<int>(*n);
    }
    return q;
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
        return "unknown kind";
    if (args.contains("days")) {
        if (!kind_takes_days(*k))
            return "days does not apply to kind " + std::string(ca_kind_name(*k));
        if (const auto e = int_arg_error(args, "days", 1, 3650))
            return e;
        if (!in_set(windows_of(*k), static_cast<int>(args["days"].get<std::int64_t>())))
            return "days must be one of " + window_list(windows_of(*k)) + " for kind " +
                   std::string(ca_kind_name(*k));
    } else if (kind_takes_days(*k)) {
        return "days is required for kind " + std::string(ca_kind_name(*k));
    }
    if (args.contains("week")) {
        if (!kind_takes_week(*k))
            return "week does not apply to kind " + std::string(ca_kind_name(*k));
        if (!args["week"].is_string())
            return "week must be a string";
        const auto w = args["week"].get<std::string>();
        if (!valid_text(w) || !parse_iso_week(w))
            return "invalid week (expected an ISO week such as 2026-W40)";
    } else if (kind_takes_week(*k)) {
        return "week is required for kind " + std::string(ca_kind_name(*k));
    }
    if (const auto e = int_arg_error(args, "limit", 1, kCertPageMax))
        return e;
    return int_arg_error(args, "offset", 0, kCertOffsetMax);
}

std::optional<std::string> strict_layout_args_error(const nlohmann::json& args) {
    if (!args.is_object())
        return std::string(crypto_library::kArgumentsNotObject);
    for (const auto& [key, _] : args.items())
        if (key != "widgets")
            return "unknown argument (only widgets is accepted)";
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
    return std::nullopt;
}

std::expected<std::vector<std::string>, std::string> parse_layout_body(std::string_view body) {
    const auto j = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded())
        return std::unexpected("request body must be JSON");
    if (!j.is_object())
        return std::unexpected("request body must be a JSON object");
    if (const auto e = strict_layout_args_error(j))
        return std::unexpected(*e);
    std::vector<std::string> ids;
    ids.reserve(j["widgets"].size());
    for (const auto& v : j["widgets"])
        ids.push_back(v.get<std::string>());
    return ids;
}

// ── Audit ────────────────────────────────────────────────────────────────────

std::string audit_detail_stats(std::string_view cid, std::int64_t as_of) {
    return std::format("{}ws={} as_of={}", cid_prefix(cid), kWindowSetVersion, as_of);
}

std::string audit_target(const CaCertQuery& q) {
    std::string out = "kind=" + std::string(ca_kind_name(q.kind));
    if (kind_takes_days(q.kind))
        out += " days=" + std::to_string(q.days);
    if (kind_takes_week(q.kind))
        out += " week=" + iso_week_label(q.week_start);
    return out;
}

std::string audit_detail_certs(std::string_view cid, const CaCertPage& page) {
    return std::format("{}ws={} as_of={} {} rows={} offset={} total={}", cid_prefix(cid),
                       kWindowSetVersion, page.as_of, audit_target(page.query), page.rows.size(),
                       page.query.offset, page.total);
}

std::string audit_detail_ca_degraded(std::string_view cid, std::int64_t as_of,
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
    return std::format("{}ws={} as_of={} {}", cid_prefix(cid), kWindowSetVersion, as_of, what);
}

std::string audit_detail_layout(std::string_view cid, std::size_t widgets) {
    return std::format("{}widgets={}", cid_prefix(cid), widgets);
}

// ── JSON ─────────────────────────────────────────────────────────────────────

nlohmann::json widgets_json(const PermissionProbe& available) {
    using nlohmann::json;
    // One probe per distinct (securable, operation) pair, however many widgets share it.
    std::set<std::pair<std::string_view, std::string_view>> asked;
    std::set<std::pair<std::string_view, std::string_view>> held;
    auto holds = [&](std::string_view s, std::string_view o) {
        const auto key = std::make_pair(s, o);
        if (asked.insert(key).second && available && available(s, o))
            held.insert(key);
        return held.contains(key);
    };
    auto rows = json::array();
    for (const auto& w : catalogue()) {
        json row{{"id", w.id},
                 {"title", w.title},
                 {"kind", kind_name(w.kind)},
                 {"group", group_name(w.group)},
                 {"securable", w.securable},
                 {"operation", w.operation},
                 {"criterion", w.criterion},
                 {"drill", drill_name(w.drill)},
                 {"available", holds(w.securable, w.operation)}};
        if (w.group == G::kYuzuCa) {
            row["ca_kind"] = ca_kind_name(w.ca_kind);
            row["days"] = kind_takes_days(w.ca_kind) ? json(w.days) : json(nullptr);
        }
        rows.push_back(std::move(row));
    }
    return json{{"window_set", kWindowSetVersion},
                {"widgets", std::move(rows)},
                {"default_layout", default_layout_ids()},
                {"max_layout_widgets", kMaxLayoutWidgets}};
}

nlohmann::json layout_json(const CryptoDashboardLayout& layout) {
    return nlohmann::json{{"widgets", layout.widgets},
                          {"is_default", layout.is_default},
                          {"max_layout_widgets", kMaxLayoutWidgets}};
}

nlohmann::json ca_stats_json(const CaCertStats& s) {
    using nlohmann::json;
    auto windows = [](CaCertKind k, const std::vector<CaWindowCount>& v) {
        auto out = json::array();
        for (const auto& c : v)
            out.push_back(json{{"days", c.days}, {"count", c.count}, {"criterion", criterion_text(k, c.days)}});
        return out;
    };
    auto weeks = json::array();
    for (const auto& w : s.weeks)
        weeks.push_back(json{{"week", w.label},
                             {"week_start", w.week_start},
                             {"issued", w.issued},
                             {"revoked", w.revoked}});
    return json{{"scope", "yuzu_issued"},
                {"window_set", kWindowSetVersion},
                {"as_of", s.as_of},
                {"as_of_iso", iso8601_utc(s.as_of)},
                {"active", {{"count", s.active}, {"criterion", criterion_text(C::kActive, 0)}}},
                {"expiring", windows(C::kExpiring, s.expiring)},
                {"expired", windows(C::kExpired, s.expired)},
                {"revoked", windows(C::kRevoked, s.revoked)},
                {"issued",
                 {{"days", s.issued.days},
                  {"count", s.issued.count},
                  {"criterion", criterion_text(C::kIssued, s.issued.days)}}},
                {"week_basis", "ISO 8601 weeks, Monday 00:00 UTC start"},
                {"weeks", std::move(weeks)}};
}

nlohmann::json ca_page_json(const CaCertPage& p) {
    using nlohmann::json;
    auto rows = json::array();
    for (const auto& r : p.rows)
        rows.push_back(json{{"serial_hex", r.serial_hex},
                            {"subject", r.subject},
                            {"purpose", r.purpose},
                            {"issued_at", r.issued_at},
                            {"not_after", r.not_after},
                            {"status", r.status},
                            {"revoked_at", r.revoked_at == 0 ? json(nullptr) : json(r.revoked_at)}});
    const auto& q = p.query;
    const std::string week = kind_takes_week(q.kind) ? iso_week_label(q.week_start) : std::string();
    return json{{"scope", "yuzu_issued"},
                {"window_set", kWindowSetVersion},
                {"as_of", p.as_of},
                {"as_of_iso", iso8601_utc(p.as_of)},
                {"kind", ca_kind_name(q.kind)},
                {"days", kind_takes_days(q.kind) ? json(q.days) : json(nullptr)},
                {"week", week.empty() ? json(nullptr) : json(week)},
                {"week_start", week.empty() ? json(nullptr) : json(q.week_start)},
                {"criterion", criterion_text(q.kind, q.days, week)},
                {"limit", q.limit},
                {"offset", q.offset},
                {"total", p.total},
                {"truncated", p.truncated},
                {"next_offset", p.truncated ? json(q.offset + static_cast<std::int64_t>(p.rows.size()))
                                            : json(nullptr)},
                {"certificates", std::move(rows)}};
}

} // namespace yuzu::server::crypto_widgets
