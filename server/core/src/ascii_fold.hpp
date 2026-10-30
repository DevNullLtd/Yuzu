#pragma once

/// #4990: the ONE ASCII case fold for plugin names on the Forensics tier.
///
/// Plugin names are compared case-insensitively in C++ (the catalogue lookup, the Forensics plugin
/// set, the live-output and audit summaries) and in SQL (`lower(plugin COLLATE "C")`, which folds
/// ASCII only). Every C++ comparison folds through these two functions so they agree with the SQL
/// regardless of the process locale or the database's LC_CTYPE: bytes outside A-Z are never changed.

#include <string>
#include <string_view>

namespace yuzu::server {

[[nodiscard]] constexpr char ascii_lower_char(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

[[nodiscard]] inline std::string ascii_lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out)
        c = ascii_lower_char(c);
    return out;
}

} // namespace yuzu::server
