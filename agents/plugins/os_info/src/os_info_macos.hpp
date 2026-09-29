#pragma once

/**
 * os_info_macos.hpp — pure parse helper for macOS's SystemVersion.plist.
 *
 * Header-only and OS-free so the parsing is unit-tested on every host (the
 * firewall_parsers.hpp / netprobe_stats.hpp pattern) — os_info_plugin.cpp's
 * macOS leg is the only impure caller.
 *
 * /System/Library/CoreServices/SystemVersion.plist is the one source that
 * carries the human-facing product name ("macOS") — there is no sysctl for
 * it (kern.osproductversion/kern.osversion cover version/build, verified
 * byte-identical to `sw_vers -productVersion`/`-buildVersion`, but there is
 * no kern.osproductname). A hand-rolled key/value extractor avoids pulling
 * in CoreFoundation (CFPropertyListCreateWithData et al.) for one string
 * read; the plist is Apple-authored XML (flat <dict> of <key>/<string>
 * pairs at the top level), not third-party/adversarial input, so a small
 * substring-based scan is proportionate — it deliberately does not attempt
 * to be a general plist/XML parser (no nesting, no other value types).
 */

#include <optional>
#include <string>
#include <string_view>

namespace yuzu::os_info {

/// Extract the string value for `key` from a flat plist's <dict> of
/// <key>NAME</key><string>VALUE</string> pairs. Returns nullopt if the key
/// is absent, the following element isn't a <string>, or the XML is
/// truncated/malformed at the point the key is found.
[[nodiscard]] inline std::optional<std::string> parse_system_version_plist(std::string_view xml,
                                                                            std::string_view key) {
    const std::string needle = std::string("<key>") + std::string(key) + "</key>";
    auto key_pos = xml.find(needle);
    if (key_pos == std::string_view::npos)
        return std::nullopt;

    auto after_key = key_pos + needle.size();

    constexpr std::string_view kStringOpen = "<string>";
    constexpr std::string_view kStringClose = "</string>";

    auto open_pos = xml.find(kStringOpen, after_key);
    if (open_pos == std::string_view::npos)
        return std::nullopt;

    // Reject anything but whitespace between </key> and <string> — a nearer
    // '<' (another tag, a sibling <key>) means this <key> has no <string>
    // value directly following it, not that we should skip ahead to some
    // later, unrelated <string>.
    for (auto i = after_key; i < open_pos; ++i) {
        if (xml[i] == '<')
            return std::nullopt;
    }

    auto value_start = open_pos + kStringOpen.size();
    auto close_pos = xml.find(kStringClose, value_start);
    if (close_pos == std::string_view::npos)
        return std::nullopt;

    return std::string(xml.substr(value_start, close_pos - value_start));
}

} // namespace yuzu::os_info
