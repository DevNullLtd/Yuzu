#pragma once

// ini_parse.hpp -- minimal INI model shared by plugins that read `[section]` /
// `key = value` configuration (sssd.conf, smb.conf). Zero-dependency leaf: std only,
// no I/O, never throws on malformed input.

#include <cstddef>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::shared {

struct IniDoc {
    std::vector<std::string> section_order; ///< first-seen order
    std::map<std::string, std::map<std::string, std::string>> sections;
};

/// Optional key/value canonicaliser applied to the trimmed key and value right before
/// insertion (nullptr = identity). A canon that empties the key drops the line. It lets a
/// caller collapse synonyms to one key so the map's last-wins is the source format's own
/// last-occurrence-wins.
using KvCanon = void (*)(std::string& key, std::string& value);

/// Trims blanks, tabs and CR/LF from both ends.
inline std::string ini_trim(std::string_view s) {
    constexpr std::string_view ws = " \t\r\n";
    const auto b = s.find_first_not_of(ws);
    if (b == std::string_view::npos)
        return {};
    const auto e = s.find_last_not_of(ws);
    return std::string(s.substr(b, e - b + 1));
}

/// `[section]` headers, `key = value` (trimmed), `#` / `;` comment lines and blank
/// lines skipped, CRLF tolerated, never throws. LAST value wins for a repeated
/// (section, key) and a re-opened section merges, so a caller concatenating a main file
/// with snippets in override order gets the merged view (SSSD conf.d, Samba include order).
inline IniDoc parse_ini(std::string_view text, KvCanon canon = nullptr) {
    IniDoc doc;
    std::string current;
    bool in_section = false;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        auto nl = text.find('\n', pos);
        if (nl == std::string_view::npos)
            nl = text.size();
        const std::string line = ini_trim(text.substr(pos, nl - pos));
        pos = nl + 1;
        if (line.empty() || line[0] == '#' || line[0] == ';')
            continue;
        if (line.front() == '[') {
            const auto close = line.find(']');
            if (close == std::string::npos) {
                in_section = false; // malformed header: ignore its keys
                continue;
            }
            current = ini_trim(std::string_view(line).substr(1, close - 1));
            in_section = true;
            if (!doc.sections.contains(current))
                doc.section_order.push_back(current);
            doc.sections[current]; // create
            continue;
        }
        const auto eq = line.find('=');
        if (!in_section || eq == std::string::npos)
            continue;
        std::string key = ini_trim(std::string_view(line).substr(0, eq));
        if (key.empty())
            continue;
        std::string value = ini_trim(std::string_view(line).substr(eq + 1));
        if (canon != nullptr) {
            canon(key, value);
            if (key.empty())
                continue;
        }
        doc.sections[current][key] = std::move(value);
    }
    return doc;
}

} // namespace yuzu::shared
