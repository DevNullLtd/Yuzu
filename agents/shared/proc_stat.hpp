// proc_stat.hpp -- the process start time from /proc/<pid>/stat, to detect a recycled pid between two
// lookups of one process listing row (name, path and hash are three separate reads of a pid that can
// be reused in between: the row would then pair one process's name with another's image hash).
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace yuzu::shared {

/// Field 22 (`starttime`, clock ticks since boot) of a /proc/<pid>/stat line. The command name (field
/// 2) is parenthesised and may itself hold spaces and parentheses, so parsing starts after the LAST
/// ')'. nullopt on any off-shape text.
[[nodiscard]] inline std::optional<std::uint64_t> parse_stat_start_ticks(std::string_view stat) {
    const auto close = stat.rfind(')');
    if (close == std::string_view::npos)
        return std::nullopt;
    stat.remove_prefix(close + 1);
    // After ')' the fields are 3 (state), 4, ... : starttime is field 22, i.e. the 20th token.
    for (int field = 3; field <= 22; ++field) {
        while (!stat.empty() && stat.front() == ' ')
            stat.remove_prefix(1);
        if (stat.empty())
            return std::nullopt;
        const auto sp = stat.find(' ');
        const auto tok = stat.substr(0, sp);
        if (field == 22) {
            std::uint64_t v = 0;
            if (tok.empty())
                return std::nullopt;
            for (const char c : tok) {
                if (c < '0' || c > '9')
                    return std::nullopt;
                v = v * 10 + static_cast<std::uint64_t>(c - '0');
            }
            return v;
        }
        stat = sp == std::string_view::npos ? std::string_view{} : stat.substr(sp);
    }
    return std::nullopt;
}

/// A row is trustworthy only when the process start time seen at enumeration equals the one seen
/// after its image was hashed (both known). A mismatch or an unknown reading means the pid may have
/// been recycled: the caller reports the row's hash as unavailable rather than another process's.
[[nodiscard]] inline bool same_process(std::optional<std::uint64_t> at_enumeration,
                                       std::optional<std::uint64_t> after_hash) {
    return at_enumeration && after_hash && *at_enumeration == *after_hash;
}

} // namespace yuzu::shared
