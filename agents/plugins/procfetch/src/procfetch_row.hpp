/**
 * procfetch_row.hpp -- the PURE row formatter for procfetch (portable, unit-tested
 * on every OS).
 *
 * Row: `<pid>|<name>|<path>|<sha1>`, one per line. `name` and `path` are
 * endpoint-controlled (a Linux /proc/<pid>/exe link text and a macOS
 * proc_pidpath are attacker-chosen file names that may contain '|', CR or LF),
 * so both go through yuzu::util::safe_output_field (CR/LF fold to a space, '|'
 * is escaped, a backslash folds to '/'; the lossy contract of #5208). The pid
 * and the hex digest are produced by this plugin and need no escaping.
 */
#pragma once

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace yuzu::procfetch {

[[nodiscard]] inline std::string format_row(long long pid, std::string_view name,
                                            std::string_view exe_path, std::string_view sha1) {
    std::string out = std::to_string(pid);
    out += '|';
    out += yuzu::util::safe_output_field(name);
    out += '|';
    out += yuzu::util::safe_output_field(exe_path);
    out += '|';
    out.append(sha1);
    return out;
}

} // namespace yuzu::procfetch
