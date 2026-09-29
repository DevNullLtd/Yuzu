/**
 * services_macos_launchd.hpp — pure parser for `launchctl print-disabled <domain>`
 * output (macOS), joined against a service label to an honest startup_type.
 *
 * C-1.12 (P15, verified): the macOS services leg used to emit svc|label|pid|status
 * with no startup type at all. The naive fix would be one `launchctl print
 * system/<label>` PER service to check its enabled/disabled state — an N+1
 * anti-pattern that turns "hundreds of installed services" into hundreds of
 * subprocess spawns. Instead this header parses the output of ONE bulk call,
 * `launchctl print-disabled system` (or `gui/<uid>` for the user domain),
 * which lists every service macOS has an explicit enable/disable override for:
 *
 *   disabled services = {
 *       "com.apple.foo" => disabled
 *       "com.apple.bar" => enabled
 *   }
 *
 * Live-verified on this host (macOS 26.5.2, both the `system` and `gui/<uid>`
 * domains): the value is the literal word `enabled` or `disabled`, tab-indented
 * -- NOT the `true`/`false` booleans some older third-party docs describe.
 * `disabled` means the service won't be loaded at next boot/login, `enabled`
 * means it has an explicit override to load. A label with NO entry in this
 * map has no recorded override — its startup type is honestly "unknown",
 * never defaulted to "automatic" or "disabled" (P15: no fabricated state).
 *
 * Deliberately NOT Windows' 5-state taxonomy (automatic / automatic_delayed /
 * manual / disabled / unknown) — launchd has no boot-delay or "manual start"
 * concept to report honestly, so macOS startup_type is one of exactly three
 * values: automatic, disabled, unknown.
 *
 * Pure header, no popen/subprocess calls — the caller (services_plugin.cpp)
 * owns running `launchctl print-disabled` and hands this header the captured
 * text, so the parsing here is unit-testable directly against captured
 * fixtures with no live launchctl dependency.
 *
 * NOTE (roadmap 7.2): this label -> bool map plus small braces/quotes parser
 * is the same shape other macOS plugins will eventually want for `launchctl
 * print` output generally (the future parse_launchctl_print helper). It is
 * deliberately NOT lifted to agents/shared/ here — out of scope for this
 * package — flagged so 7.2 can converge the two instead of them drifting
 * apart.
 */

#pragma once

#include <cctype>
#include <string>
#include <string_view>
#include <unordered_map>

namespace yuzu::services_macos {

/// launchctl label -> disabled (true = disabled, false = explicitly enabled).
using DisabledMap = std::unordered_map<std::string, bool>;

/// Validate a launchctl label before trusting it as a map key or joining it
/// into pipe-delimited plugin output. Mirrors is_safe_service_name in
/// services_plugin.cpp (alphanumeric, '-', '_', '.', '@' only); kept as its
/// own copy here so this header has zero dependency on the .cpp's anonymous
/// namespace and stays independently includable/testable.
inline bool is_safe_launchd_label(std::string_view label) {
    if (label.empty() || label.size() > 256)
        return false;
    for (char c : label) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.' &&
            c != '@') {
            return false;
        }
    }
    return true;
}

/// Parse the text output of `launchctl print-disabled system` (or
/// `gui/<uid>`) into a label -> disabled map.
///
/// Tolerant of the exact braces/whitespace layout launchd emits; only lines
/// matching `"label" => enabled|disabled` are recognised (live-verified
/// token spelling, see the header comment above), everything else (the
/// `disabled services = {` header, the closing `}`, blank lines) is
/// silently skipped. A label that fails is_safe_launchd_label is dropped
/// rather than trusted into the map — it simply won't be found by
/// startup_type_for(), so the affected service degrades to "unknown"
/// instead of a value derived from an unsanitized label.
///
/// Unparseable/empty input yields an empty map. This function never throws
/// and never reports an error — degrade to "unknown" per service, exactly
/// as the boundary requires (no error|+exit-1 on unparseable output).
inline DisabledMap parse_print_disabled(std::string_view output) {
    DisabledMap result;
    size_t pos = 0;
    while (pos <= output.size()) {
        size_t line_end = output.find('\n', pos);
        std::string_view line = (line_end == std::string_view::npos)
                                     ? output.substr(pos)
                                     : output.substr(pos, line_end - pos);

        size_t q1 = line.find('"');
        size_t q2 = (q1 == std::string_view::npos) ? std::string_view::npos
                                                     : line.find('"', q1 + 1);
        size_t arrow = (q2 == std::string_view::npos) ? std::string_view::npos
                                                        : line.find("=>", q2);
        if (q1 != std::string_view::npos && q2 != std::string_view::npos &&
            arrow != std::string_view::npos) {
            std::string_view label = line.substr(q1 + 1, q2 - q1 - 1);
            std::string_view rest = line.substr(arrow + 2);
            // Trim leading AND trailing whitespace (space/tab/CR) so the
            // comparison below is exact-token, not merely a prefix match --
            // "enabled-junk" or a trailing "\r" must not be accepted as
            // "enabled".
            size_t v = rest.find_first_not_of(" \t\r");
            if (v != std::string_view::npos) {
                rest = rest.substr(v);
                size_t e = rest.find_last_not_of(" \t\r");
                rest = rest.substr(0, e + 1);
                // Live-verified token spelling (macOS 26.5.2, system + gui/<uid>
                // domains): the literal words "enabled"/"disabled", not booleans.
                bool matched = false;
                bool disabled = false;
                if (rest == "disabled") {
                    matched = true;
                    disabled = true;
                } else if (rest == "enabled") {
                    matched = true;
                    disabled = false;
                }
                if (matched && is_safe_launchd_label(label)) {
                    result[std::string(label)] = disabled;
                }
            }
        }

        if (line_end == std::string_view::npos)
            break;
        pos = line_end + 1;
    }
    return result;
}

/// Join a single label against a parsed disabled map to an honest
/// startup_type string: disabled (true) -> "disabled", explicitly enabled
/// (false) -> "automatic", absent from the map -> "unknown". An unsafe
/// label (per is_safe_launchd_label) is never looked up and always yields
/// "unknown", regardless of what the map contains.
inline std::string startup_type_for(const DisabledMap& disabled_map, std::string_view label) {
    if (!is_safe_launchd_label(label))
        return "unknown";
    auto it = disabled_map.find(std::string(label));
    if (it == disabled_map.end())
        return "unknown";
    return it->second ? "disabled" : "automatic";
}

} // namespace yuzu::services_macos
