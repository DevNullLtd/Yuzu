#pragma once

// Daily-sync skip telemetry (#5332): the agent writes heartbeat tag
// `yuzu.sync.<source>.skip_streak` (plain digits) only while a source is skipping
// its collection cycle. The server counts agents per source; the value is
// agent-controlled, so it is never a label and never summed - only counted.

#include <cstddef>
#include <iterator>
#include <string>
#include <string_view>

namespace yuzu::server::detail {

/// Table of daily-sync sources reported on the fleet gauge. Add a source here and
/// nothing else changes.
inline constexpr const char* kSyncSkipSources[] = {"installed_software"};

/// Heartbeat tag key for one source's skip streak.
inline std::string sync_skip_streak_tag(std::string_view source) {
    std::string r{"yuzu.sync."};
    r += source;
    r += ".skip_streak";
    return r;
}

/// True iff `v` is 1..6 ASCII digits with a value > 0.
[[nodiscard]] inline bool parse_sync_skip_streak(std::string_view v) noexcept {
    if (v.empty() || v.size() > 6)
        return false;
    bool nonzero = false;
    for (char c : v) {
        if (c < '0' || c > '9')
            return false;
        if (c != '0')
            nonzero = true;
    }
    return nonzero;
}

} // namespace yuzu::server::detail
