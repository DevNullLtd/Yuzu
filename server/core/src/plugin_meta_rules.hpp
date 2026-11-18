#pragma once

/// @file plugin_meta_rules.hpp
/// WP06 F31: ingest bounds for the plugin metadata an AGENT reports in Register/ProxyRegister
/// (`PluginInfo.name/version/description/capabilities`). That text is endpoint-supplied and was
/// stored verbatim, merged fleet-wide by `AgentRegistry::help_json` and served to LLM clients
/// (`discover_plugins`), i.e. a prompt-injection channel from any enrolled endpoint.
///
/// Rules (pure, no I/O): a field outside its bound is DROPPED (a name, version, description or
/// action is never cut short into something misleading; an entry beyond the per-agent cap is
/// dropped whole) and counted by the caller. Applies ONLY to the `PluginMeta` copy used for the
/// served catalogue; `AgentSession::plugin_names` (Echo gating, heartbeat logic) is untouched.
/// The agent-reported `description` is bounded here but is deliberately NOT served by
/// `help_json`/`help_html`; plugins and actions the server's capability catalogue does not recognise are
/// omitted at serving time (`AgentRegistry::set_catalogue_filter`) (owner decision: endpoint free text is not catalogue documentation).

#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu::server::plugin_meta_rules {

inline constexpr std::size_t kMaxNameLen = 64;
inline constexpr std::size_t kMaxVersionLen = 32;
inline constexpr std::size_t kMaxDescriptionLen = 200;
inline constexpr std::size_t kMaxActions = 64;
inline constexpr std::size_t kMaxPluginsPerAgent = 64; ///< PluginInfo entries kept per agent
inline constexpr std::size_t kMaxActionLen = 64;

[[nodiscard]] inline bool is_ident_char(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
}

/// Plugin and action names: 1..N of [a-z0-9_.-].
[[nodiscard]] inline bool ident_ok(std::string_view s, std::size_t max_len) noexcept {
    if (s.empty() || s.size() > max_len)
        return false;
    for (char c : s)
        if (!is_ident_char(c))
            return false;
    return true;
}

[[nodiscard]] inline bool plugin_name_ok(std::string_view s) noexcept {
    return ident_ok(s, kMaxNameLen);
}
[[nodiscard]] inline bool action_name_ok(std::string_view s) noexcept {
    return ident_ok(s, kMaxActionLen);
}

/// Version: 1..32 of [0-9A-Za-z.+_-].
[[nodiscard]] inline bool version_ok(std::string_view s) noexcept {
    if (s.empty() || s.size() > kMaxVersionLen)
        return false;
    for (char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') || c == '.' || c == '+' || c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

/// Description: <= 200 printable ASCII (0x20..0x7e). Anything else (newline, control, non-ASCII,
/// over-long) fails: the caller drops the field to "".
[[nodiscard]] inline bool description_ok(std::string_view s) noexcept {
    if (s.size() > kMaxDescriptionLen)
        return false;
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u > 0x7e)
            return false;
    }
    return true;
}

} // namespace yuzu::server::plugin_meta_rules
