/**
 * processes_rows.hpp -- the PURE row-field neutraliser and the `query` row
 * formatter for the processes plugin (portable, unit-tested on every OS).
 *
 * The wire format is pipe-delimited, one record per line. A process name (or
 * any field) containing '|', CR or LF would shift/split fields on the
 * server-side positional parser, so those bytes are neutralised to a space
 * before emitting. A macOS process name is the full executable path and a
 * Linux comm is attacker-chosen, so every action passes the name through
 * sanitize_field -- `query` included (it was the one action that did not).
 */
#pragma once

#include <string>
#include <string_view>

namespace yuzu::processes {

// A TRAILING backslash is folded to '/'. The server decoder
// (result_parsing.hpp find_unescaped_pipe) treats `\|` as an escaped pipe, so a
// field ending in '\' (a comm of `x\`, a path ending in `\`) would glue onto the
// '|' delimiter and merge with the next column, shifting the hash and path
// columns. Other backslashes are kept: Windows paths contain them and other
// consumers (live_kinds.hpp, device_routes.cpp) split these rows on a raw '|'.
// No `\|` escape grammar is introduced here (#5208).
[[nodiscard]] inline std::string sanitize_field(std::string s) {
    for (char& c : s)
        if (c == '|' || c == '\n' || c == '\r')
            c = ' ';
    if (!s.empty() && s.back() == '\\')
        s.back() = '/';
    return s;
}

/// `proc|<pid>|<name>` -- the `list` and `query` per-process row.
[[nodiscard]] inline std::string format_query_row(long long pid, std::string_view name) {
    return "proc|" + std::to_string(pid) + "|" + sanitize_field(std::string{name});
}

/// `proc|<pid>|<name>|<sha256>|<path>` -- `list_hashed`.
[[nodiscard]] inline std::string format_hashed_row(long long pid, std::string_view name,
                                                   std::string_view sha256,
                                                   std::string_view path) {
    std::string out = "proc|" + std::to_string(pid) + "|" + sanitize_field(std::string{name}) + "|";
    out.append(sha256);
    out += '|';
    out += sanitize_field(std::string{path});
    return out;
}

/// `proc|<pid>|<ppid>|<name>|<sha256>|<path>` -- `list_tree`.
[[nodiscard]] inline std::string format_tree_row(long long pid, long long ppid,
                                                 std::string_view name, std::string_view sha256,
                                                 std::string_view path) {
    std::string out = "proc|" + std::to_string(pid) + "|" + std::to_string(ppid) + "|" +
                      sanitize_field(std::string{name}) + "|";
    out.append(sha256);
    out += '|';
    out += sanitize_field(std::string{path});
    return out;
}

} // namespace yuzu::processes
