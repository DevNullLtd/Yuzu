#pragma once

/**
 * server_address_parsers.hpp -- pure text-handling helpers for
 * server_address_resolver.cpp. No I/O, no platform dependency: unlike the
 * getaddrinfo() call itself, these are unit-testable directly.
 */

#include <string>
#include <string_view>

namespace yuzu::agent {

/// Extracts the host portion from a "host:port" target string (the agent's
/// own --server config, e.g. "10.0.0.5:50051" or
/// "server.example.com:50051"). Handles bracketed IPv6
/// ("[::1]:50051" -> "::1"); a bracket-less IPv6 literal with no port is
/// returned whole, since a port suffix on one is ambiguous (gRPC itself
/// requires brackets for that combination) and splitting on the last ':'
/// would truncate it. A target with no ':' at all (a bare host, no port)
/// is returned unchanged.
inline std::string extract_server_host(std::string_view target) {
    if (target.empty())
        return {};
    if (target.front() == '[') {
        const auto close = target.find(']');
        if (close != std::string_view::npos)
            return std::string{target.substr(1, close - 1)};
        return {}; // malformed bracket -- no safe host to extract
    }
    const auto last_colon = target.rfind(':');
    if (last_colon == std::string_view::npos)
        return std::string{target}; // no port suffix
    if (target.substr(0, last_colon).find(':') != std::string_view::npos)
        return std::string{target}; // bracket-less IPv6 -- don't truncate it
    return std::string{target.substr(0, last_colon)};
}

/// Charset-only IP-literal check: an already-literal host needs no DNS
/// round-trip at all. Deliberately not shape-validating (matches
/// quarantine_parsers.hpp's is_safe_ip) -- callers only use a positive
/// result to SKIP resolution, never to admit an unvalidated value past a
/// containment boundary on its own.
inline bool looks_like_ip_literal(std::string_view s) {
    if (s.empty() || s.size() > 45)
        return false;
    for (char c : s) {
        const bool ok = (c >= '0' && c <= '9') || c == '.' || c == ':' ||
                        (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok)
            return false;
    }
    return true;
}

} // namespace yuzu::agent
