/**
 * network_config_routes_macos.cpp — macOS leg of `routes`: one NET_RT_DUMP
 * sysctl over the routing socket (rung 1, libc only, no framework link), address
 * family 0 so IPv4 and IPv6 come back together, decoded by the pure
 * parse_route_table_dump() in network_config_routes_parsers.hpp.
 *
 * The sysctl is the same call mac_default_gateway() already makes for
 * ip_addresses, widened from AF_INET to all families. The size-then-fill pair is
 * racy by nature (the table can grow between the two calls), so the fill is given
 * headroom and retried on ENOMEM; the buffer is also bounded, because a table that
 * large is not a workstation's and must not be buffered whole.
 *
 * Interface names come from if_indextoname(rtm_index). An index that no longer
 * resolves is rendered `-`, never guessed.
 */
#include "network_config_routes_ifname.hpp" // FIRST: see its include-order note
#include "network_config_routes_legs.hpp"

#if defined(__APPLE__)

#include <net/route.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <string>
#include <vector>

namespace yuzu::network_config {

namespace {

// A routing table past this is not buffered; the leg reports UNAVAILABLE rather
// than parse a prefix of an unbounded allocation.
constexpr std::size_t kMaxDumpBytes = 64u * 1024u * 1024u;
constexpr int kFillAttempts = 5;

enum class Fetch { Ok, Failed, TooLarge };

Fetch fetch_route_dump(std::vector<unsigned char>& out) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, 0 /* all families */, NET_RT_DUMP, 0};
    for (int attempt = 0; attempt < kFillAttempts; ++attempt) {
        std::size_t need = 0;
        if (::sysctl(mib, 6, nullptr, &need, nullptr, 0) != 0)
            return Fetch::Failed;
        if (need > kMaxDumpBytes)
            return Fetch::TooLarge;
        // Headroom: entries added between the size probe and the fill would
        // otherwise fail the fill with ENOMEM on every retry of a busy table — but never past the
        // bound: the allocation and anything the fill returns stay <= kMaxDumpBytes, and a table
        // that outgrows it makes the next probe report TooLarge.
        out.assign(std::min(need + need / 8 + 4096, kMaxDumpBytes), 0);
        std::size_t got = out.size();
        if (::sysctl(mib, 6, out.data(), &got, nullptr, 0) == 0) {
            out.resize(got);
            return Fetch::Ok;
        }
        if (errno != ENOMEM)
            return Fetch::Failed;
    }
    return Fetch::Failed;
}

} // namespace

int collect_routes_macos(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<unsigned char> blob;
    const Fetch fetched = fetch_route_dump(blob);
    if (fetched != Fetch::Ok) {
        acc.add_failure(fetched == Fetch::TooLarge ? "network_config:pf_route_dump_too_large"
                                                   : "network_config:pf_route_dump_failed");
        emit_routes(ctx, {}, acc, /*unavailable=*/true);
        return 0;
    }

    const auto parsed = parse_route_table_dump(blob);
    std::vector<RouteRow> rows;
    rows.reserve(parsed.records.size());
    for (const auto& rec : parsed.records)
        rows.push_back(mac_route_to_row(rec, interface_name_for_index(rec.ifindex)));

    if (parsed.capped)
        acc.add_failure(kTokRowCap);
    if (parsed.truncated)
        acc.add_failure("network_config:pf_route_dump_truncated");
    emit_routes(ctx, rows, acc, /*unavailable=*/false);
    return 0;
}

} // namespace yuzu::network_config

#endif // __APPLE__
