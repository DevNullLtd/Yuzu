#pragma once

/// @file outbound_url_policy.hpp
/// Pure checks for operator-supplied outbound destination URLs (webhooks and
/// offload targets). Header-only and dependency-free so the stores, routes and
/// unit tests share one definition.
///
/// A destination URL is a bearer secret in practice (Slack-style hooks) and is
/// echoed into audit rows and the analytics stream, so two shapes are refused
/// at create time: embedded userinfo (`https://user:pass@host`) and control
/// bytes (CR/LF/NUL would split an audit row). Existing rows are not rewritten.

#include <string>
#include <string_view>

namespace yuzu::server {

/// True if `s` contains any byte below 0x20 or DEL.
[[nodiscard]] inline bool url_has_control_bytes(std::string_view s) noexcept {
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7f)
            return true;
    }
    return false;
}

namespace detail {
/// Authority component of `url` (between "://" and the first '/', '?' or '#').
/// Empty when there is no "://".
[[nodiscard]] inline std::string_view url_authority(std::string_view url) noexcept {
    const auto scheme_end = url.find("://");
    if (scheme_end == std::string_view::npos)
        return {};
    auto rest = url.substr(scheme_end + 3);
    const auto end = rest.find_first_of("/?#");
    return end == std::string_view::npos ? rest : rest.substr(0, end);
}
} // namespace detail

/// True if the authority carries `user[:pass]@`.
[[nodiscard]] inline bool url_has_userinfo(std::string_view url) noexcept {
    return detail::url_authority(url).find('@') != std::string_view::npos;
}

/// `scheme://host[:port]` with any userinfo, path, query and fragment removed.
/// Returns an empty string when `url` has no "://" (never echo an unparseable
/// value).
[[nodiscard]] inline std::string url_scheme_host(std::string_view url) {
    const auto scheme_end = url.find("://");
    if (scheme_end == std::string_view::npos)
        return {};
    auto authority = detail::url_authority(url);
    if (const auto at = authority.rfind('@'); at != std::string_view::npos)
        authority = authority.substr(at + 1);
    std::string out(url.substr(0, scheme_end + 3));
    out.append(authority);
    return out;
}

} // namespace yuzu::server
