// netstat_parsers.hpp -- pure, host-agnostic helpers for netstat_plugin.cpp.
//
// Header-only (no I/O, no platform #ifdef) so tests/meson.build can include
// it directly into yuzu_agent_tests without pulling in netstat_plugin.cpp's
// Linux/macOS/Windows enumeration code -- same shape as firewall_parsers.hpp
// / interaction_parsers.hpp.

#pragma once

#include <string>
#include <string_view>

namespace yuzu::netstat {

// Escape '|' in a field that may contain arbitrary text (process name/path)
// so it can't be mistaken for a column separator downstream. Ported from the
// retired sockwho_plugin.cpp. Also strips CR/LF (adversarial-review gate-2
// finding, #3403): split_output_lines() on the server splits raw agent
// output on '\n' and trims a trailing '\r', with no unescape for either --
// only '\|' round-trips through unescape_pipes(). A POSIX filename may
// legally contain a newline, so an unescaped process name/path could split
// one attribution row into extra server-visible lines. There's no
// reversible escape for a control character here, so it's replaced with
// '_' (same choice as agents/shared/user_profile_model.hpp's sanitize_field).
inline std::string escape_pipes(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (char c : sv) {
        if (c == '|')
            out += "\\|";
        else if (c == '\r' || c == '\n')
            out += '_';
        else
            out += c;
    }
    return out;
}

} // namespace yuzu::netstat
