#pragma once

// filesystem_search_dir.hpp -- the pure core of the filesystem plugin's search_dir action (#6478).
//
// search_dir finds directories and/or files by NAME. It rides the plugin's ONE bounded walker
// (find_by_hash::walk_bounded) with a name-matching visitor, so it has the same bounds and the same
// guards as find_by_hash: a 20 s wall clock, an entry cap, the shutdown signal, a network-mount
// refusal that precedes every call touching a path, a depth limit that never opens a directory at
// the limit, and a symlink or junction below the root that is counted and never followed or
// matched. Whatever the walk skipped or stopped short of is reported by the shared `truncated|...`
// trailer. Everything OS-bound is injected through WalkEnv, so the unit suites run it over a TempDir
// with a fake clock, cancel predicate, probe and mount list.
//
// Rows (all `|`-separated; every path goes through acl::row_field, which also makes it wire-safe):
//   result|<path>|<directory|file>
//   network_mount_guard|unavailable        (the mount table could not be read in full)
//   truncated|<reason>|visited=N|...       (the find_by_hash trailer, when anything was skipped)
//   total_matches|N
// Name MATCHING uses the raw bytes of the name; only the emitted row is scrubbed.

#include "filesystem_find_by_hash.hpp"

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::filesystem::search_dir {

namespace fbh = yuzu::filesystem::find_by_hash;

/// A name-only visit is far cheaper than a hash, so the entry cap is eight times find_by_hash's.
inline constexpr std::size_t kMaxEntriesVisited = 400'000;
/// Longest pattern the action accepts, glob or regex.
inline constexpr std::size_t kMaxPatternBytes = 256;

enum class MatchType { directories, files, both };

[[nodiscard]] inline std::optional<MatchType> parse_match_type(std::string_view v) {
    if (v == "directories")
        return MatchType::directories;
    if (v == "files")
        return MatchType::files;
    if (v == "both")
        return MatchType::both;
    return std::nullopt;
}

/// `result|<path>|<directory|file>`.
[[nodiscard]] inline std::string format_result_row(std::string_view path_utf8, bool is_dir) {
    return "result|" + acl::row_field(path_utf8) + (is_dir ? "|directory" : "|file");
}

/// The rows that close a walk, in order: the guard-off row when the mount table was unreadable, the
/// trailer when anything was skipped or stopped short, then `total_matches|N`.
[[nodiscard]] inline std::vector<std::string> format_closing_rows(const fbh::WalkOutcome& o) {
    std::vector<std::string> rows;
    if (o.mount_table_incomplete)
        rows.emplace_back(fbh::kMountGuardUnavailableRow);
    if (o.trailer_needed())
        rows.push_back(fbh::format_trailer(o));
    rows.push_back("total_matches|" + std::to_string(o.matches));
    return rows;
}

[[nodiscard]] inline fbh::WalkLimits limits_for(int max_results) {
    fbh::WalkLimits l;
    l.max_files_visited = kMaxEntriesVisited;
    l.max_results = max_results;
    return l;
}

/// Walk `root` to `max_depth` (root's children are depth 1), emitting one `result|...` row per entry
/// of a kind `type` admits whose NAME `name_matches`. A symlink, junction, FIFO, device or socket
/// is never offered to the predicate (the walker counts it).
template <class Emit>
fbh::WalkOutcome walk_search_dir(const std::string& root,
                                 const std::function<bool(std::string_view)>& name_matches,
                                 MatchType type, int max_depth, const fbh::WalkLimits& limits,
                                 const fbh::WalkEnv& env, Emit emit) {
    return fbh::walk_bounded(
        root, max_depth, limits, env,
        [&](const fbh::fs::directory_entry& entry, fbh::EntryKind kind, fbh::HashBudget&,
            fbh::WalkCounters&) {
            const bool is_dir = kind == fbh::EntryKind::directory;
            if (type == MatchType::directories && !is_dir)
                return fbh::Visit::none;
            if (type == MatchType::files && is_dir)
                return fbh::Visit::none;
            // path_utf8, never path::string(): that throws on MSVC for a name the ANSI code page
            // cannot hold.
            if (!name_matches(fbh::path_utf8(entry.path().filename())))
                return fbh::Visit::none;
            emit(format_result_row(fbh::path_utf8(entry.path()), is_dir));
            return fbh::Visit::match;
        });
}

} // namespace yuzu::filesystem::search_dir
