#pragma once

// msi_packages_macos.hpp -- pure parsing helpers for the macOS
// `pkgutil --pkgs` / `pkgutil --pkg-info <id>` receipt formats, used by
// msi_packages_plugin.cpp (list/product_codes actions). No popen here -- the
// plugin captures the subprocess output and hands it to these pure
// functions, so tests/unit/agent/test_msi_macos.cpp can exercise the exact
// parse logic against fixture vectors without a real pkgutil on the test
// host (same header-for-testability pattern as installed_apps_inventory.hpp).
//
// macOS package identifiers are reverse-domain strings (e.g.
// "com.apple.pkg.Core"), never GUIDs -- callers must carry them through
// honestly rather than coercing them into the Windows {GUID} shape.

#include <format>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field (plg-H1 pipe/newline escaping)

namespace yuzu::msi_packages::macos {

// One parsed `pkgutil --pkg-info <id>` receipt.
struct PkgInfo {
    std::string identifier;       // package-id (falls back to the id the
                                   // caller asked pkgutil about, if the
                                   // "package-id:" line is missing/malformed)
    std::string version;          // version
    std::string install_location; // volume + location, joined
};

// Split `pkgutil --pkgs` output (one identifier per line) into a vector,
// dropping blank lines. Tolerates both LF and CRLF line endings.
inline std::vector<std::string> parse_pkg_ids(std::string_view output) {
    std::vector<std::string> ids;
    std::size_t pos = 0;
    while (pos <= output.size()) {
        std::size_t eol = output.find('\n', pos);
        if (eol == std::string_view::npos)
            eol = output.size();
        std::string_view line = output.substr(pos, eol - pos);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (!line.empty())
            ids.emplace_back(line);
        if (eol == output.size())
            break;
        pos = eol + 1;
    }
    return ids;
}

// Parse one `pkgutil --pkg-info <id>` receipt: lines of "key: value" (pkgutil
// uses ": " as the separator). Unknown keys are ignored. "volume" + "location"
// are joined to form install_location, avoiding a doubled leading slash when
// volume is "/" (the common system-volume case) and location already starts
// with "/". Malformed/empty input still yields a usable PkgInfo carrying
// requested_id -- never a crash, never a fabricated version/location.
inline PkgInfo parse_pkg_info(std::string_view output, std::string_view requested_id) {
    PkgInfo info;
    info.identifier = std::string(requested_id);
    std::string volume;
    std::string location;

    std::size_t pos = 0;
    while (pos <= output.size()) {
        std::size_t eol = output.find('\n', pos);
        if (eol == std::string_view::npos)
            eol = output.size();
        std::string_view line = output.substr(pos, eol - pos);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        const std::size_t sep = line.find(": ");
        if (sep != std::string_view::npos) {
            const std::string_view key = line.substr(0, sep);
            const std::string_view value = line.substr(sep + 2);
            if (key == "package-id") {
                info.identifier = std::string(value);
            } else if (key == "version") {
                info.version = std::string(value);
            } else if (key == "volume") {
                volume = std::string(value);
            } else if (key == "location") {
                location = std::string(value);
            }
        }

        if (eol == output.size())
            break;
        pos = eol + 1;
    }

    if (!volume.empty() || !location.empty()) {
        if (volume == "/" && !location.empty() && location.front() == '/') {
            info.install_location = location; // avoid "//..."
        } else {
            info.install_location = volume + location;
        }
    }
    return info;
}

// pkgutil identifiers are reverse-domain ("com.vendor.pkg.Name"); a receipt
// carries no separate display-name field, so derive a short, human-readable
// label from the LAST dot-segment (e.g. "Name" from the example above) -- a
// deterministic transform of the real identifier, never a fabricated value.
// Falls back to the full identifier when there is no usable dot to split on.
inline std::string derive_display_name(std::string_view identifier) {
    const std::size_t dot = identifier.rfind('.');
    if (dot == std::string_view::npos || dot + 1 == identifier.size())
        return std::string(identifier);
    return std::string(identifier.substr(dot + 1));
}

// Format one `msi|identifier|name|version|install_location` inventory row with
// every DYNAMIC field pipe/newline-escaped (plg-H1): a pkgutil receipt id,
// version or install path containing '|' or a newline would otherwise shift
// columns or inject a row in the positional downstream parser. Pure, so the
// plugin's `list` action delegates here and the escaping is unit-tested without a
// live pkgutil / CommandContext. Empty fields render the "-" sentinel.
inline std::string format_msi_row(const PkgInfo& info) {
    const std::string name = derive_display_name(info.identifier);
    return std::format("msi|{}|{}|{}|{}", yuzu::util::safe_output_field(info.identifier),
                       name.empty() ? std::string("-") : yuzu::util::safe_output_field(name),
                       info.version.empty() ? std::string("-")
                                            : yuzu::util::safe_output_field(info.version),
                       info.install_location.empty()
                           ? std::string("-")
                           : yuzu::util::safe_output_field(info.install_location));
}

// Format one `product_code|identifier|name` row, both dynamic fields escaped.
inline std::string format_product_code_row(std::string_view identifier) {
    const std::string name = derive_display_name(identifier);
    return std::format("product_code|{}|{}", yuzu::util::safe_output_field(identifier),
                       name.empty() ? std::string("-") : yuzu::util::safe_output_field(name));
}

} // namespace yuzu::msi_packages::macos
