#pragma once

/// @file coord_dsn.hpp
/// WS-3 (ADR-2002 §10): build the LeaderElector's dedicated coordination DSN from
/// the server's Postgres DSN. Header-only and PURE so it is unit-testable
/// (`test_coord_dsn.cpp`) — the whole election loop's liveness rests on this
/// connection reaching the primary quickly and staying detectable when it dies,
/// and a malformed augmentation would silently pause every FencedLeaderOnly loop
/// (fail-closed but degraded). Extracted from server.cpp's anonymous namespace so
/// the branch behaviour can be pinned (adversarial review K3/CDX-P2-03).
///
/// The elector needs its OWN never-recycled connection (§10), so it reuses the
/// SAME DSN the pool already proved reachable, augmented so a DEAD or half-open
/// coordination backend is detected quickly rather than stalling the loop — which
/// also bounds shutdown latency, since stop() joins a loop that may be mid-query
/// on this connection (#4013 + governance UP-5/UP-10):
///   - connect_timeout bounds a hung CONNECT;
///   - keepalives + a short keepalives_idle/interval/count bound a half-open
///     socket where the client would otherwise block in recv() until the OS TCP
///     timeout (connect_timeout does NOT cover an established-then-wedged socket);
///   - tcp_user_timeout (PG12+) bounds transmitted-but-unacknowledged data.
/// A parameter is appended ONLY if absent, so an operator-set value always wins.

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

inline std::string build_coord_dsn(const std::string& base) {
    if (base.empty())
        return base; // the elector fails closed on an empty DSN itself
    // Append a param only if the operator did not set it (their value wins). The
    // six keys below are distinct substrings, so a plain "key="-present test does
    // not cross-match (e.g. "keepalives=" never matches "keepalives_idle="). A DSN
    // whose VALUE literally contains "<key>=" would false-suppress the append — an
    // accepted, contrived LOW (governance UP-11), not worth a boundary-parser.
    auto has = [&](std::string_view key) {
        return base.find(std::string(key) + "=") != std::string::npos;
    };
    std::vector<std::pair<std::string, std::string>> add;
    if (!has("connect_timeout"))
        add.emplace_back("connect_timeout", "5");
    if (!has("keepalives"))
        add.emplace_back("keepalives", "1");
    if (!has("keepalives_idle"))
        add.emplace_back("keepalives_idle", "15");
    if (!has("keepalives_interval"))
        add.emplace_back("keepalives_interval", "5");
    if (!has("keepalives_count"))
        add.emplace_back("keepalives_count", "3");
    if (!has("tcp_user_timeout"))
        add.emplace_back("tcp_user_timeout", "15000");
    if (add.empty())
        return base;
    // URI detection tolerant of leading whitespace (adversarial review K3): a DSN
    // that begins with blanks is still a URI and must NOT be appended to with the
    // space-separated keyword syntax (which would corrupt it).
    const std::size_t s = base.find_first_not_of(" \t\r\n");
    const std::string_view v =
        s == std::string::npos ? std::string_view{} : std::string_view{base}.substr(s);
    const bool uri = v.rfind("postgres://", 0) == 0 || v.rfind("postgresql://", 0) == 0;
    std::string out = base;
    if (uri) {
        char sep = base.find('?') == std::string::npos ? '?' : '&';
        for (const auto& [k, val] : add) {
            out += sep;
            out += k;
            out += '=';
            out += val;
            sep = '&';
        }
    } else {
        for (const auto& [k, val] : add) {
            out += ' ';
            out += k;
            out += '=';
            out += val;
        }
    }
    return out;
}

} // namespace yuzu::server
