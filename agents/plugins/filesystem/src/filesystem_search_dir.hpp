#pragma once

// filesystem_search_dir.hpp -- the pure core of the filesystem plugin's search_dir action (#6478).
//
// search_dir finds directories and/or files by NAME. It rides the plugin's ONE bounded walker
// (find_by_hash::walk_bounded) with a name-matching visitor, so it has the same bounds and the same
// guards as find_by_hash: a 20 s wall clock, an entry cap, the shutdown signal, a network-mount
// refusal judged on a path's spelling before any call touches it (a root reached through a symlink
// is the disclosed residual, #4875), a depth limit that never opens a directory at
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

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include "filesystem_acl_parsers.hpp" // acl::row_field
#include "filesystem_find_by_hash.hpp"

namespace yuzu::filesystem::search_dir {

namespace fbh = yuzu::filesystem::find_by_hash;

/// A name-only visit is far cheaper than a hash, so the entry cap is eight times find_by_hash's.
inline constexpr std::size_t kMaxEntriesVisited = 400'000;
/// Longest pattern the action accepts, glob or regex.
inline constexpr std::size_t kMaxPatternBytes = 256;
/// The label of the closing count row; the rows come from fbh::format_outcome_rows(o, kCountLabel).
inline constexpr std::string_view kCountLabel = "total_matches";

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

/// True when a regex holds a `(?` group other than the non-capturing `(?:`. In the ECMAScript
/// grammar that is a lookahead, `(?=` or `(?!`, and search_dir refuses one: no standard library
/// bounds it (each lookahead is a fresh sub-match with its own complexity budget, so ONE lookahead
/// over one 255-byte name ran for 5 s on libc++ and nested or repeated ones multiply), and a single
/// regex_match cannot be interrupted by the walk's deadline. Judged on the spelling alone, with no
/// grammar of its own: an escaped `\(` is skipped, and a `(?` inside a bracket class is refused too
/// (the three libraries need not parse a class alike, and refusing is the safe side).
[[nodiscard]] inline bool has_lookahead(std::string_view pattern) {
    for (std::size_t i = 0; i + 1 < pattern.size(); ++i) {
        if (pattern[i] == '\\') {
            ++i; // an escaped character never opens a group
            continue;
        }
        if (pattern[i] == '(' && pattern[i + 1] == '?' &&
            (i + 2 >= pattern.size() || pattern[i + 2] != ':'))
            return true;
    }
    return false;
}

/// `result|<path>|<directory|file>`.
[[nodiscard]] inline std::string format_result_row(std::string_view path_utf8, bool is_dir) {
    return "result|" + acl::row_field(path_utf8) + (is_dir ? "|directory" : "|file");
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
