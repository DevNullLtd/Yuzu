#pragma once

/**
 * ioc_parsers.hpp — pure helpers for the ioc plugin.
 *
 * The /etc/hosts read stays in the plugin shell; the match decision lives here
 * so it is pinned on every host by tests/unit/test_ioc_parsers.cpp.
 */

#include <user_profile_model.hpp>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace yuzu::ioc {

namespace detail {
inline std::string_view strip_one_trailing_dot(std::string_view s) {
    if (!s.empty() && s.back() == '.')
        s.remove_suffix(1);
    return s;
}
} // namespace detail

/// True when `domain` equals a hostname or alias (any column after the address)
/// of an /etc/hosts line. ASCII case-insensitive, one trailing dot ignored on
/// both sides; '#' starts a comment. An empty domain never matches.
[[nodiscard]] inline bool hosts_contains_domain(std::span<const std::string> lines,
                                                std::string_view domain) {
    domain = detail::strip_one_trailing_dot(domain);
    if (domain.empty())
        return false;
    for (std::string_view line : lines) {
        line = line.substr(0, line.find('#'));
        bool first = true; // first token is the address
        std::size_t i = 0;
        while (i < line.size()) {
            i = line.find_first_not_of(" \t\r", i);
            if (i == std::string_view::npos)
                break;
            const auto end = line.find_first_of(" \t\r", i);
            const auto tok = line.substr(i, end == std::string_view::npos ? end : end - i);
            if (!first && yuzu::profiles::iequals_ascii(detail::strip_one_trailing_dot(tok), domain))
                return true;
            first = false;
            if (end == std::string_view::npos)
                break;
            i = end;
        }
    }
    return false;
}

} // namespace yuzu::ioc
