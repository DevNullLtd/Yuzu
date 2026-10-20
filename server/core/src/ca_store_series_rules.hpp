#pragma once

/// @file ca_store_series_rules.hpp
/// How `CaStore::issuance_stats` reads back its two grouped per-week series. The statement
/// returns each series as one `string_agg` of "week:count" (issued) or "week:bucket:count"
/// (revoked) items, grouped so each (week[, bucket]) appears at most once; a week with no row is
/// a zero. Pure, so the fail-closed paths are unit-tested (test_ca_store.cpp): anything the
/// statement could not have produced is refused, never read as a zero.

#include <charconv>
#include <cstdint>
#include <string_view>
#include <system_error>
#include <vector>

namespace yuzu::server::ca_series {

/// Parses `text` into `add(week, bucket, n)` calls. `fields` is 2 (issued, bucket always 0) or 3
/// (revoked, bucket 0 superseded / 1 unpublished / 2 other). An empty `text` (a NULL aggregate:
/// no rows) is an empty series. False - and the caller reports a query error - on an empty item
/// (including a trailing comma), a missing or extra field, a non-decimal or signed number, a week
/// outside [0, weeks), a bucket outside [0, 2], a negative count, or a repeated (week, bucket).
template <class Add>
[[nodiscard]] bool parse_week_series(std::string_view text, int fields, int weeks, Add&& add) {
    if (fields != 2 && fields != 3)
        return false;
    if (text.empty())
        return true;
    std::vector<bool> seen(static_cast<std::size_t>(weeks > 0 ? weeks : 0) * 3, false);
    for (;;) {
        const auto comma = text.find(',');
        std::string_view item = text.substr(0, comma);
        if (item.empty())
            return false;
        std::int64_t v[3] = {0, 0, 0};
        for (int f = 0; f < fields; ++f) {
            const auto colon = f + 1 < fields ? item.find(':') : item.size();
            if (colon == std::string_view::npos)
                return false;
            const auto part = item.substr(0, colon);
            const auto [ptr, ec] = std::from_chars(part.data(), part.data() + part.size(), v[f]);
            if (part.empty() || ec != std::errc{} || ptr != part.data() + part.size())
                return false;
            item = colon < item.size() ? item.substr(colon + 1) : std::string_view{};
        }
        const std::int64_t week = v[0];
        const std::int64_t bucket = fields == 3 ? v[1] : 0;
        const std::int64_t n = v[fields - 1];
        if (week < 0 || week >= weeks || bucket < 0 || bucket > 2 || n < 0)
            return false;
        const auto slot = static_cast<std::size_t>(week) * 3 + static_cast<std::size_t>(bucket);
        if (seen[slot])
            return false;
        seen[slot] = true;
        add(static_cast<int>(week), static_cast<int>(bucket), n);
        if (comma == std::string_view::npos)
            return true;
        text = text.substr(comma + 1);
    }
}

} // namespace yuzu::server::ca_series
