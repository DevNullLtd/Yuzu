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

} // namespace yuzu::server::oidc
