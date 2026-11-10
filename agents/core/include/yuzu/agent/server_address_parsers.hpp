#pragma once

/**
 * server_address_parsers.hpp -- pure text-handling helpers for
 * server_address_resolver.cpp. No I/O, no platform dependency: unlike the
 * getaddrinfo() call itself, these are unit-testable directly.
 */

#include <algorithm>
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

/// The `host:port` / `[v6]:port` literal of a gRPC peer string -- what
/// `grpc::ClientContext::peer()` returns after a call: `ipv4:198.51.100.7:50051`,
/// `ipv6:[2001:db8::1]:50051`, or the percent-encoded bracket form some gRPC
/// versions produce (`ipv6:%5B2001:db8::1%5D:50051`). Empty for anything else (a
/// `dns:` / `unix:` / `uds:` peer, a list, a zone-scoped address, a bad port): the
/// caller then publishes no peer at all rather than a guess.
///
/// This is the ONE conversion between what the transport reports and the literal the
/// agent publishes to plugins as "agent.server_peer" (agent.cpp; the firewall plugin's
/// containment allows exactly that address, #3429 round 4: a plugin never resolves a
/// name, it admits only a literal agents/core published from the stream the server
/// actually answered on). Shape-checked only (octets, a hex/colon charset, a port in
/// 1..65535); the plugin validates the address bytes again before it admits it.
inline std::string grpc_peer_literal(std::string_view peer) {
    const auto strip = [&](std::string_view prefix) {
        return peer.starts_with(prefix) ? peer.substr(prefix.size()) : std::string_view{};
    };
    const auto port_ok = [](std::string_view p) {
        if (p.empty() || p.size() > 5)
            return false;
        unsigned v = 0;
        for (char c : p) {
            if (c < '0' || c > '9')
                return false;
            v = v * 10 + static_cast<unsigned>(c - '0');
        }
        return v >= 1 && v <= 65535;
    };

    if (const auto rest = strip("ipv4:"); !rest.empty()) {
        const auto colon = rest.rfind(':');
        if (colon == std::string_view::npos || !port_ok(rest.substr(colon + 1)))
            return {};
        const auto host = rest.substr(0, colon);
        int octets = 0;
        std::size_t pos = 0;
        while (pos <= host.size()) {
            const auto dot = host.find('.', pos);
            const auto part = host.substr(pos, dot == std::string_view::npos ? dot : dot - pos);
            if (part.empty() || part.size() > 3)
                return {};
            unsigned v = 0;
            for (char c : part) {
                if (c < '0' || c > '9')
                    return {};
                v = v * 10 + static_cast<unsigned>(c - '0');
            }
            if (v > 255)
                return {};
            ++octets;
            if (dot == std::string_view::npos)
                break;
            pos = dot + 1;
        }
        return octets == 4 ? std::string{rest} : std::string{};
    }

    if (const auto rest = strip("ipv6:"); !rest.empty()) {
        std::string_view body = rest;
        std::string_view after;
        const auto bracketed = [&](std::string_view open, std::string_view close) {
            if (!body.starts_with(open))
                return false;
            const auto end = body.find(close, open.size());
            if (end == std::string_view::npos)
                return false;
            after = body.substr(end + close.size());
            body = body.substr(open.size(), end - open.size());
            return true;
        };
        // A percent sign anywhere else (a zone id, any other escape) is not a literal.
        if (!bracketed("[", "]") && !bracketed("%5B", "%5D") && !bracketed("%5b", "%5d"))
            return {};
        if (!after.starts_with(':') || !port_ok(after.substr(1)))
            return {};
        if (body.size() < 2 || body.size() > 45 || std::count(body.begin(), body.end(), ':') < 2)
            return {};
        for (char c : body) {
            const bool ok = (c >= '0' && c <= '9') || c == ':' || c == '.' ||
                            (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!ok)
                return {};
        }
        return "[" + std::string{body} + "]:" + std::string{after.substr(1)};
    }
    return {};
}

} // namespace yuzu::agent
