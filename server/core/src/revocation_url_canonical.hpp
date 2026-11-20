#pragma once

/// @file revocation_url_canonical.hpp
/// The ONE canonicaliser for a registered CRL URL (owner ruling on #6590, 2026-11-18;
/// `docs/crypto-slice2-certificate-design.md`, "Decisions"). The canonical form is what the
/// revocation-source store keeps, what `UNIQUE (source_id, url)` and a `PUT`'s replace compare,
/// and what every response returns, so a cosmetic edit of a URL (`HTTP://CA.Example:80` for
/// `http://ca.example/`) keeps that URL's id and fetch state instead of reading as a new URL.
///
/// The form:
///   - the scheme and the host are lowercased (both are case-insensitive, RFC 3986 6.2.2.1);
///   - the port loses its leading zeros, and the scheme's default port (80 for http, 443 for
///     https) is dropped (RFC 3986 6.2.3);
///   - an IPv6 literal is written in RFC 5952 form (section 4: lowercase, no leading zeros, the
///     longest run of two or more zero fields as `::`, the first run on a tie; an IPv4-mapped
///     address in the mixed notation `::ffff:a.b.c.d` of section 5), inside brackets;
///   - an empty path is written `/` (`http://h` and `http://h?q` become `http://h/` and
///     `http://h/?q`);
///   - the path and the query are kept byte for byte: their case is kept and percent-encoding is
///     left exactly as sent (neither decoded nor re-encoded).
///
/// PURE: no I/O. Two callers, one function: the revocation-source service applies it to every
/// URL a register or `PUT` body carries (after its syntax check), and the store's open-time pass
/// (migration v2) rewrites any stored URL into this form. The store also refuses to write a URL
/// that is not already in it.
///
/// CHANGING THIS FUNCTION IS A SCHEMA CHANGE. The store re-applies it to every stored URL on every
/// open, rewrites any row whose form changed and REFUSES TO OPEN (the server does not start) when
/// a stored URL no longer canonicalises or two URLs of one source become one. A change to the form
/// therefore migrates stored rows with no migration number: review it as a migration, state its
/// effect on existing rows in the upgrade notes, and test it against stored v2 data.

#include "oidc_egress_policy.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::revocation_source {

/// RFC 5952 text form of a 16-byte IPv6 address (no brackets).
[[nodiscard]] inline std::string format_ipv6_rfc5952(const ::yuzu::server::oidc::egress::Ipv6& b) {
    static constexpr char kHex[] = "0123456789abcdef";
    // Section 5: an IPv4-mapped address (::ffff:0:0/96) is written with the IPv4 part dotted.
    bool mapped = b[10] == 0xff && b[11] == 0xff;
    for (std::size_t i = 0; i < 10 && mapped; ++i)
        mapped = b[i] == 0;
    if (mapped)
        return "::ffff:" + std::to_string(b[12]) + "." + std::to_string(b[13]) + "." +
               std::to_string(b[14]) + "." + std::to_string(b[15]);

    std::array<std::uint16_t, 8> w{};
    for (std::size_t i = 0; i < 8; ++i)
        w[i] = static_cast<std::uint16_t>((b[2 * i] << 8) | b[2 * i + 1]);
    // Section 4.2: the longest run of two or more zero fields, the first one on a tie.
    int best_at = -1;
    int best_len = 0;
    for (int i = 0; i < 8;) {
        if (w[static_cast<std::size_t>(i)] != 0) {
            ++i;
            continue;
        }
        int j = i;
        while (j < 8 && w[static_cast<std::size_t>(j)] == 0)
            ++j;
        if (j - i > best_len) {
            best_len = j - i;
            best_at = i;
        }
        i = j;
    }
    if (best_len < 2)
        best_at = -1;
    const auto field = [](std::uint16_t v) {
        std::string s;
        bool started = false;
        for (int shift = 12; shift >= 0; shift -= 4) {
            const auto nib = static_cast<std::size_t>((v >> shift) & 0xf);
            if (nib == 0 && !started && shift != 0)
                continue;
            started = true;
            s.push_back(kHex[nib]);
        }
        return s;
    };
    std::string out;
    for (int i = 0; i < 8; ++i) {
        if (i == best_at) {
            out += "::";
            i += best_len - 1;
            continue;
        }
        if (!out.empty() && out.back() != ':')
            out.push_back(':');
        out += field(w[static_cast<std::size_t>(i)]);
    }
    return out;
}

/// A canonical URL and the host it names (lowercase; an IPv6 literal in RFC 5952 form, without
/// its brackets) - the store keeps both, so the host column always agrees with the URL.
struct CanonicalCrlUrl {
    std::string url;
    std::string host;
};

/// The canonical form of `url`, or nullopt when it is not an absolute http/https URL with a host
/// and an optional 1..5-digit port in 1..65535 (no userinfo, a well-formed bracketed IPv6
/// literal without a zone). Only the parts the canonical form touches are checked here: the
/// service's syntax check (character set, length, host labels, fragment) runs first.
[[nodiscard]] inline std::optional<CanonicalCrlUrl> canonical_crl_url(std::string_view url) {
    const auto lower = [](std::string s) {
        for (auto& c : s)
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
        return s;
    };
    // A fragment is never part of a CRL URL (the service refuses it first); refusing it here too
    // keeps a `#` from being read as part of the host.
    if (url.find('#') != std::string_view::npos)
        return std::nullopt;
    const auto sep = url.find("://");
    if (sep == std::string_view::npos)
        return std::nullopt;
    const std::string scheme = lower(std::string(url.substr(0, sep)));
    if (scheme != "http" && scheme != "https")
        return std::nullopt;
    const std::string_view rest = url.substr(sep + 3);
    const auto auth_end = rest.find_first_of("/?");
    const std::string_view authority = rest.substr(0, auth_end);
    const std::string_view tail =
        auth_end == std::string_view::npos ? std::string_view{} : rest.substr(auth_end);
    if (authority.empty() || authority.find('@') != std::string_view::npos)
        return std::nullopt;

    CanonicalCrlUrl out;
    bool bracketed = false;
    std::string_view port;
    bool has_port = false;
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string_view::npos)
            return std::nullopt;
        const std::string_view lit = authority.substr(1, close - 1);
        if (lit.empty() || lit.find('%') != std::string_view::npos)
            return std::nullopt;
        const auto v6 = ::yuzu::server::oidc::egress::parse_ipv6(lit);
        if (!v6)
            return std::nullopt;
        out.host = format_ipv6_rfc5952(*v6);
        bracketed = true;
        const std::string_view after = authority.substr(close + 1);
        if (!after.empty()) {
            if (after.front() != ':')
                return std::nullopt;
            port = after.substr(1);
            has_port = true;
        }
    } else {
        const auto colon = authority.rfind(':');
        const std::string_view host = authority.substr(0, colon);
        if (host.empty() || host.find(':') != std::string_view::npos)
            return std::nullopt;
        out.host = lower(std::string(host));
        if (colon != std::string_view::npos) {
            port = authority.substr(colon + 1);
            has_port = true;
        }
    }
    std::string port_text;
    if (has_port) {
        if (port.empty() || port.size() > 5)
            return std::nullopt;
        long value = 0;
        for (const char c : port) {
            if (c < '0' || c > '9')
                return std::nullopt;
            value = value * 10 + (c - '0');
        }
        if (value < 1 || value > 65535)
            return std::nullopt;
        const bool is_default =
            (scheme == "http" && value == 80) || (scheme == "https" && value == 443);
        if (!is_default)
            port_text = std::to_string(value);
    }
    out.url = scheme + "://" + (bracketed ? "[" + out.host + "]" : out.host);
    if (!port_text.empty())
        out.url += ":" + port_text;
    if (tail.empty() || tail.front() == '?')
        out.url += '/';
    out.url.append(tail);
    return out;
}

} // namespace yuzu::server::revocation_source
