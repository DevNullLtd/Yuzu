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

[[nodiscard]] inline std::string sanitize_field(std::string s) {
    for (char& c : s)
        if (c == '|' || c == '\n' || c == '\r')
            c = ' ';
    return s;
}

/// `proc|<pid>|<name>` -- the `query` action's per-match row.
[[nodiscard]] inline std::string format_query_row(long long pid, std::string_view name) {
    return "proc|" + std::to_string(pid) + "|" + sanitize_field(std::string{name});
}

} // namespace yuzu::processes
