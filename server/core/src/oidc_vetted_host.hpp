#pragma once

#include <cstddef>
#include <string_view>

namespace yuzu::server::oidc {

/// True when `cracked` (the host `WinHttpCrackUrl` extracted from a token endpoint) is the host
/// the egress policy vetted (`split_http_url`'s, brackets stripped): equal byte for byte apart
/// from ASCII case and the brackets around an IPv6 literal. WinHTTP cannot pin an address, so
/// refusing to connect to any host other than the vetted one is the one check that leg has; a
/// disagreement between the two URL parsers must fail closed, as the POSIX paths do.
///
/// Any non-ASCII character on either side is a mismatch (a vetted host is ASCII: the policy
/// refuses the rest), and an empty host never matches. Pure and platform-neutral, so it is unit
/// tested on every platform although only the Windows token POST calls it.
inline bool cracked_host_is_vetted(std::wstring_view cracked, std::string_view vetted) {
    const auto unbracket = [](auto sv) {
        if (sv.size() >= 2 && sv.front() == '[' && sv.back() == ']') {
            sv.remove_prefix(1);
            sv.remove_suffix(1);
        }
        return sv;
    };
    cracked = unbracket(cracked);
    vetted = unbracket(vetted);
    if (cracked.empty() || cracked.size() != vetted.size())
        return false;
    const auto lower = [](int c) { return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c; };
    for (std::size_t i = 0; i < cracked.size(); ++i) {
        const auto w = static_cast<unsigned long>(cracked[i]);
        const auto v = static_cast<unsigned char>(vetted[i]);
        if (w > 0x7f || v > 0x7f)
            return false;
        if (lower(static_cast<int>(w)) != lower(static_cast<int>(v)))
            return false;
    }
    return true;
}

/// The port a request to `origin` ("scheme://authority", as `split_http_url` builds it) connects
/// to: an explicit ":port" after the host, else the scheme default (80 for http, 443 for https).
/// Returns 0 when an explicit port is not 1 to 5 decimal digits in 1..65535 - a value no real
/// port equals, so any comparison against it fails closed. A colon INSIDE the brackets of an IPv6
/// literal is not a port separator.
inline unsigned vetted_port_from_origin(std::string_view origin, bool cleartext) {
    unsigned port = cleartext ? 80u : 443u;
    const auto scheme_end = origin.find("://");
    const auto authority =
        scheme_end == std::string_view::npos ? origin : origin.substr(scheme_end + 3);
    const auto colon = authority.rfind(':');
    const auto bracket = authority.rfind(']');
    if (colon != std::string_view::npos &&
        (bracket == std::string_view::npos || colon > bracket)) {
        unsigned long value = 0;
        std::size_t digits = 0;
        for (const char c : authority.substr(colon + 1)) {
            if (c < '0' || c > '9' || ++digits > 5)
                return 0;
            value = value * 10 + static_cast<unsigned long>(c - '0');
        }
        if (digits == 0 || value == 0 || value > 65535)
            return 0;
        port = static_cast<unsigned>(value);
    }
    return port;
}

/// The whole Windows token-POST decision: the host AND port `WinHttpCrackUrl` produced must be
/// the host and port the egress policy vetted. A zero vetted port (an unparseable explicit port)
/// never matches.
inline bool cracked_endpoint_is_vetted(std::wstring_view cracked_host, unsigned cracked_port,
                                       std::string_view vetted_host, unsigned vetted_port) {
    return vetted_port != 0 && cracked_port == vetted_port &&
           cracked_host_is_vetted(cracked_host, vetted_host);
}

} // namespace yuzu::server::oidc
