// proc_stat.hpp -- the process start time from /proc/<pid>/stat, to detect a recycled pid between two
// lookups of one process listing row (name, path and hash are three separate reads of a pid that can
// be reused in between: the row would then pair one process's name with another's image hash).
#pragma once

#include <cstdint>
#include <limits>
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
            if (tok.empty() || tok.size() > 20) // 2^64 - 1 has 20 digits
                return std::nullopt;
            for (const char c : tok) {
                if (c < '0' || c > '9')
                    return std::nullopt;
                const auto digit = static_cast<std::uint64_t>(c - '0');
                // More than 2^64 - 1 would wrap and could equal a different process's start time.
                if (v > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10)
                    return std::nullopt;
                v = v * 10 + digit;
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

/// What the second start-time reading says about the row's pid.
enum class PidState {
    Same,     ///< both readings known and equal: the same process
    Reused,   ///< both readings known and different: the pid belongs to another process
    Unverified, ///< the first reading is unknown, so a recycled pid cannot be told from the same process
    Exited    ///< the pid's stat is unreadable: the process exited after it was listed
};

[[nodiscard]] inline PidState classify_pid(std::optional<std::uint64_t> at_enumeration,
                                           std::optional<std::uint64_t> after_hash) {
    if (!after_hash)
        return PidState::Exited;
    if (!at_enumeration)
        return PidState::Unverified;
    return *at_enumeration == *after_hash ? PidState::Same : PidState::Reused;
}

/// True for a real SHA-256 digest (64 lowercase hex), as opposed to an empty value or a
/// `hash_unavailable:<cause>` marker.
[[nodiscard]] inline bool is_sha256_digest(std::string_view hash) {
    if (hash.size() != 64)
        return false;
    for (const char c : hash)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

/// How `settle_row` changes a row once `classify_pid` is known.
struct RowSettle {
    bool drop_path{false};             ///< the path may belong to another process (or none): clear it
    std::string_view hash_cause{};     ///< non-empty: replace the hash with `hash_unavailable:<hash_cause>`
};

/// A mismatch always drops the path, but only a real digest is converted to a cause token: an
/// existing `hash_unavailable:timeout` / `skipped` marker (or an empty hash) keeps its own, more
/// specific reading. `Reused`, `Unverified` and `Exited` are distinct tokens (`pid_reused`, `pid_unverified`, `pid_exited`).
[[nodiscard]] inline RowSettle settle_row_for(PidState state, std::string_view hash) {
    if (state == PidState::Same)
        return {};
    RowSettle r;
    r.drop_path = true;
    if (is_sha256_digest(hash))
        r.hash_cause = state == PidState::Reused       ? "pid_reused"
                       : state == PidState::Unverified ? "pid_unverified"
                                                       : "pid_exited";
    return r;
}

} // namespace yuzu::shared
