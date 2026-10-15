#pragma once

/// @file outbound_url_policy.hpp
/// Pure checks for operator-supplied outbound destination URLs (webhooks and
/// offload targets). Header-only (OpenSSL's SHA-256 is the only dependency,
/// for the audit fingerprint) so the stores, routes and unit tests share one
/// definition.
///
/// A destination URL is a bearer secret in practice (Slack-style hooks), so it
/// must never reach a Postgres audit column, a log line or the analytics stream in full (the
/// secrets-at-rest principle of ADR-0010, applied to audit text): audit rows and events carry
/// `url_audit_detail()`
/// (scheme, host and a fingerprint) instead. Two shapes are also refused at
/// create time: embedded userinfo (`https://user:pass@host`) and control bytes
/// (CR/LF/NUL would split an audit row). Existing rows are not rewritten.

#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include <openssl/sha.h>

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
/// Where the authority of `after_scheme` (the text after "://") ends: the first '/', '?' or '#',
/// or npos. The one definition validation (`url_authority`) and delivery
/// (`url_delivery_parts`) share.
[[nodiscard]] inline std::size_t authority_end(std::string_view after_scheme) noexcept {
    return after_scheme.find_first_of("/?#");
}

/// Authority component of `url` (between "://" and `authority_end`). Empty when there is no
/// "://".
[[nodiscard]] inline std::string_view url_authority(std::string_view url) noexcept {
    const auto scheme_end = url.find("://");
    if (scheme_end == std::string_view::npos)
        return {};
    auto rest = url.substr(scheme_end + 3);
    const auto end = authority_end(rest);
    return end == std::string_view::npos ? rest : rest.substr(0, end);
}

/// ASCII-only classes: the <cctype> forms follow the process locale.
[[nodiscard]] constexpr bool is_ascii_alpha(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
[[nodiscard]] constexpr bool is_ascii_digit(char c) noexcept {
    return c >= '0' && c <= '9';
}

/// A URI scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ), at most 16 bytes. Anything else before
/// "://" is part of a path or query, not a scheme.
[[nodiscard]] constexpr bool is_url_scheme(std::string_view s) noexcept {
    if (s.empty() || s.size() > 16 || !is_ascii_alpha(s.front()))
        return false;
    for (char c : s)
        if (!is_ascii_alpha(c) && !is_ascii_digit(c) && c != '+' && c != '-' && c != '.')
            return false;
    return true;
}

/// The echo-safe form of an authority (`host[:port]`, userinfo already removed), or nullopt when
/// it is not one. Host bytes outside the RFC 3986 unreserved set (`A-Za-z0-9._~-`), including
/// space, '=', ',', '%' and every byte >= 0x80, are percent-encoded, so an underscore name, a raw
/// IDN or a zone id still reads as itself while a crafted host cannot forge a neighbouring audit
/// or log field. A bracketed IPv6 literal keeps `A-Za-z0-9:.%_~-` (address and zone id) and encodes the rest. A port is 1-5
/// digits (an empty one after a trailing ':' is dropped); text after the last colon that is not a
/// port (a pasted `token:secret`), an unbracketed host with a colon, an empty host and anything
/// over 261 bytes (253-byte name + ":65535") yield nullopt.
[[nodiscard]] inline std::optional<std::string> display_host_port(std::string_view a) {
    if (a.empty() || a.size() > 261)
        return std::nullopt;
    static constexpr char kHex[] = "0123456789ABCDEF";
    auto push_encoded = [](std::string& out, char c) {
        const auto u = static_cast<unsigned char>(c);
        out.push_back('%');
        out.push_back(kHex[u >> 4]);
        out.push_back(kHex[u & 0x0f]);
    };
    std::string out;
    std::size_t host_end = 0;
    if (a.front() == '[') {
        const auto close = a.find(']');
        if (close == std::string_view::npos || close == 1)
            return std::nullopt;
        out.push_back('[');
        for (char c : a.substr(1, close - 1)) {
            // Hex digits, ':' and '.' for the address; '%' and the unreserved set cover a zone id
            // (`%25eth0`). Anything else is encoded.
            if (is_ascii_alpha(c) || is_ascii_digit(c) || c == ':' || c == '.' || c == '%' ||
                c == '-' || c == '_' || c == '~')
                out.push_back(c);
            else
                push_encoded(out, c);
        }
        out.push_back(']');
        host_end = close + 1;
    } else {
        const auto colon = a.rfind(':');
        host_end = colon == std::string_view::npos ? a.size() : colon;
        if (host_end == 0)
            return std::nullopt;
        for (char c : a.substr(0, host_end)) {
            if (c == ':')
                return std::nullopt; // unbracketed IPv6 or "a:b:80"
            if (is_ascii_alpha(c) || is_ascii_digit(c) || c == '.' || c == '-' || c == '_' ||
                c == '~')
                out.push_back(c);
            else
                push_encoded(out, c);
        }
    }
    if (host_end == a.size())
        return out;
    if (a[host_end] != ':')
        return std::nullopt;
    const auto port = a.substr(host_end + 1);
    if (port.empty())
        return out;
    if (port.size() > 5)
        return std::nullopt;
    for (char c : port)
        if (!is_ascii_digit(c))
            return std::nullopt;
    out.push_back(':');
    out.append(port);
    return out;
}
} // namespace detail

/// True if the authority carries `user[:pass]@`.
[[nodiscard]] inline bool url_has_userinfo(std::string_view url) noexcept {
    return detail::url_authority(url).find('@') != std::string_view::npos;
}

/// `scheme://host[:port]` with any userinfo, path, query and fragment removed.
/// The host is percent-encoded where needed (`detail::display_host_port`), so a crafted authority
/// cannot forge an audit or log field. Returns an empty string when `url` does not start with
/// `<scheme>://` or its authority is not a `host[:port]` (never echo an unparseable value, never
/// mistake a later "://" in a path or query for the scheme).
[[nodiscard]] inline std::string url_scheme_host(std::string_view url) {
    const auto scheme_end = url.find("://");
    if (scheme_end == std::string_view::npos || !detail::is_url_scheme(url.substr(0, scheme_end)))
        return {};
    auto authority = detail::url_authority(url);
    if (const auto at = authority.rfind('@'); at != std::string_view::npos)
        authority = authority.substr(at + 1);
    const auto shown = detail::display_host_port(authority);
    if (!shown)
        return {};
    std::string out(url.substr(0, scheme_end + 3));
    out.append(*shown);
    return out;
}

/// The pieces delivery connects with. The authority ends at the first '/', '?' or '#' (as
/// `url_authority` reads it), so `https://hooks.example?token=x` connects to `hooks.example` and
/// requests `/?token=x`; splitting at '/' alone made the query part of the host. The fragment is
/// never sent. A value with no "http(s)://" prefix keeps the historical http default.
struct UrlDeliveryParts {
    std::string scheme;    ///< "http" or "https"
    std::string host_port; ///< authority as written (userinfo is refused at create time)
    std::string path;      ///< request target: path and query, always starting with '/'
};

[[nodiscard]] inline UrlDeliveryParts url_delivery_parts(std::string_view url) {
    UrlDeliveryParts out{"http", {}, "/"};
    if (url.starts_with("https://")) {
        out.scheme = "https";
        url.remove_prefix(8);
    } else if (url.starts_with("http://")) {
        url.remove_prefix(7);
    }
    const auto end = detail::authority_end(url);
    out.host_port = std::string(url.substr(0, end));
    if (end == std::string_view::npos)
        return out;
    auto rest = url.substr(end);
    if (const auto frag = rest.find('#'); frag != std::string_view::npos)
        rest = rest.substr(0, frag);
    if (!rest.empty())
        out.path = rest.front() == '/' ? std::string(rest) : "/" + std::string(rest);
    return out;
}

/// The destination for a log line: scheme://host[:port], or a placeholder when none can be shown.
/// Never the path or query.
[[nodiscard]] inline std::string url_log_host(std::string_view url) {
    auto host = url_scheme_host(url);
    return host.empty() ? std::string("(host withheld)") : host;
}

/// The first line of a Postgres error message. The `DETAIL:` line of a constraint violation
/// quotes the failing row, which for these tables includes the destination URL.
[[nodiscard]] inline std::string first_line(const char* message) {
    const std::string_view m = message ? message : "";
    return std::string(m.substr(0, m.find('\n')));
}

/// First 12 lowercase hex characters (48 bits) of SHA-256 over the whole URL:
/// enough to tell whether two audit rows, or a row and a candidate URL, name the
/// same destination, too little to recover the secret.
[[nodiscard]] inline std::string url_fingerprint(std::string_view url) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> md{};
    SHA256(reinterpret_cast<const unsigned char*>(url.data()), url.size(), md.data());
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    for (std::size_t i = 0; i < 6; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

/// The audit-row form of a destination URL: `url=<scheme://host[:port]>
/// url_fp=<fingerprint>`. Keeps "where did the data go" answerable by host and
/// by exact-URL comparison without storing the path or query, where a
/// Slack-style token lives. An unparseable value reports the fingerprint only.
[[nodiscard]] inline std::string url_audit_detail(std::string_view url) {
    std::string out;
    // Safe on an unvalidated value (the audit-first row precedes validation): a value with
    // control bytes is never echoed, and url_scheme_host returns only a bare scheme://host[:port].
    if (const auto host = url_has_control_bytes(url) ? std::string{} : url_scheme_host(url);
        !host.empty())
        out = "url=" + host + " ";
    out += "url_fp=" + url_fingerprint(url);
    return out;
}

} // namespace yuzu::server
