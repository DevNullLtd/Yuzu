/**
 * host_arg.hpp — shared host/target argument validation (ADR-3002 Decision 6).
 *
 * One validator for every action that passes an operator-supplied host to a
 * network tool or probe (network_actions ping, wol check). Replaces the two
 * per-plugin `is_safe_host` copies, both of which permitted a leading `-` —
 * the option-injection shape Decision 6 names (`ping -n 4 -f` when `-f` was
 * meant to be a host). Charset stays deliberately tight: hostnames, IPv4 and
 * IPv6 literals only.
 */
#pragma once

#include <cctype>
#include <string_view>

namespace yuzu::shared {

inline constexpr std::size_t kMaxHostArgLen = 253; // RFC 1035 name ceiling

inline bool is_safe_host_arg(std::string_view host) {
    if (host.empty() || host.size() > kMaxHostArgLen)
        return false;
    // Never an option: the first byte must not be `-`. A leading `:` stays
    // legal — `::1` is how this fleet spells IPv6 loopback.
    if (host.front() == '-')
        return false;
    for (const char c : host) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != ':')
            return false;
    }
    return true;
}

} // namespace yuzu::shared
