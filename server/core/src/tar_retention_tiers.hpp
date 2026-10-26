#pragma once

/// TAR retention tier defaults as published by the data-retention API.
///
/// Pure: no I/O. The table (docs/capability-registries/tar_retention_tiers.tsv)
/// is a checked-in mirror of the agent's schema registry, embedded at build
/// time because the server does not link the agent's registry; a tar-suite
/// drift test keeps it in lock-step with `capture_sources()`.
///
/// Honesty rules the API promises:
///  - These are the registry DEFAULTS every agent applies, not per-device
///    readings. TAR tiers prune on the agent; the server has no live value.
///  - A paused or errored source is never pruned (tar_aggregator.cpp
///    `source_enabled` gate), so its rows do not age.
///  - Rows may outlive their limit by up to kTarRetentionTickSeconds, and
///    longer when the retention clock guard declines a prune.

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <expected>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <yuzu/tar_retention_tick.hpp>

namespace yuzu::server::tar_retention {

/// The agent's `tar.rollup` trigger interval, shared via
/// yuzu/tar_retention_tick.hpp so the caveat figure cannot drift from the trigger.
inline constexpr std::int64_t kTarRetentionTickSeconds = yuzu::kTarRollupTickSeconds;

struct TarRetentionTier {
    std::string source;
    std::string tier; // live | hourly | daily | monthly | boot
    bool row_count{false}; // true: `limit` is rows; false: seconds
    std::int64_t limit{0};
};

/// Strict parser for the 4-column TSV (`source tier limit_kind limit`).
/// Errors name the 1-based offending line.
[[nodiscard]] inline std::expected<std::vector<TarRetentionTier>, std::string>
parse_tar_retention_tiers(std::string_view tsv) {
    constexpr std::string_view kHeader = "source\ttier\tlimit_kind\tlimit";
    std::vector<TarRetentionTier> out;
    std::set<std::pair<std::string, std::string>> seen;
    bool header_seen = false;
    std::size_t line_no = 0;

    while (!tsv.empty()) {
        const auto nl = tsv.find('\n');
        auto line = tsv.substr(0, nl);
        tsv = nl == std::string_view::npos ? std::string_view{} : tsv.substr(nl + 1);
        ++line_no;
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (line.empty())
            continue;
        const auto err = [&](std::string_view what) {
            return std::unexpected("line " + std::to_string(line_no) + ": " + std::string(what));
        };
        if (!header_seen) {
            if (line != kHeader)
                return err("bad header");
            header_seen = true;
            continue;
        }
        std::vector<std::string_view> cells;
        for (std::size_t s = 0;;) {
            const auto t = line.find('\t', s);
            if (t == std::string_view::npos) {
                cells.push_back(line.substr(s));
                break;
            }
            cells.push_back(line.substr(s, t - s));
            s = t + 1;
        }
        if (cells.size() != 4 || cells[0].empty() || cells[1].empty())
            return err("expected 4 non-empty tab-separated cells");
        if (cells[2] != "rows" && cells[2] != "seconds")
            return err("limit_kind must be rows or seconds");
        if (cells[1] != "live" && cells[1] != "hourly" && cells[1] != "daily" &&
            cells[1] != "monthly" && cells[1] != "boot")
            return err("unknown tier");
        std::int64_t limit = 0;
        const auto [p, ec] = std::from_chars(cells[3].data(), cells[3].data() + cells[3].size(), limit);
        if (ec != std::errc{} || p != cells[3].data() + cells[3].size() || limit <= 0)
            return err("limit must be a positive integer");
        if (!seen.emplace(std::string(cells[0]), std::string(cells[1])).second)
            return err("duplicate source/tier");
        out.push_back({std::string(cells[0]), std::string(cells[1]), cells[2] == "rows", limit});
    }
    if (!header_seen)
        return std::unexpected("line 1: bad header");
    return out;
}

/// Roll-up bucket width. Monthly is a calendar month (`start of month` in the
/// registry's roll-up SQL), so the worst case 31 days is used. live/boot: 0.
[[nodiscard]] inline std::int64_t bucket_seconds(std::string_view tier) noexcept {
    if (tier == "hourly")
        return 3600;
    if (tier == "daily")
        return 86400;
    if (tier == "monthly")
        return 31 * 86400;
    return 0;
}

/// Age a record is guaranteed to still be held at. Roll-up rows age from their
/// bucket START, so a time-based tier guarantees limit - bucket. Row-count
/// tiers have no fixed time depth (it needs a per-device rows/day reading).
[[nodiscard]] inline std::optional<std::int64_t>
guaranteed_depth_seconds(const TarRetentionTier& t) noexcept {
    if (t.row_count)
        return std::nullopt;
    return std::max<std::int64_t>(0, t.limit - bucket_seconds(t.tier));
}

} // namespace yuzu::server::tar_retention
