/**
 * network_config_routes_linux.cpp — Linux leg of `routes`: one RTM_GETROUTE
 * AF_UNSPEC dump over rtnetlink (rung 1), decoded by the pure
 * parse_rtnetlink_routes_chunk() in network_config_routes_parsers.hpp.
 *
 * The socket/drain mechanics are network_config_netlink.hpp's templated dump();
 * the kernel-origin check, bounded foreign-datagram discard and MSG_TRUNC
 * handling all live there. This TU adds only the request, the row cap, the
 * ifindex -> name resolution and the typed status.
 *
 * Interface names come from if_indextoname() (the kernel's own table, the same
 * source `ip` uses). An index that no longer resolves (the interface vanished
 * between the dump and the lookup) is rendered `-`, never guessed.
 */
#include "network_config_routes_ifname.hpp" // FIRST: see its include-order note
#include "network_config_routes_legs.hpp"

#if defined(__linux__)

#include <cstdint>
#include <string>
#include <vector>

#include "network_config_netlink.hpp"

namespace yuzu::network_config {

namespace {

constexpr std::uint32_t kRoutesSeq = 4; // the plugin's other dumps use 1..3

} // namespace

int collect_routes_linux(yuzu::CommandContext& ctx) {
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req{};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = kRoutesSeq;
    req.rtm.rtm_family = AF_UNSPEC; // IPv4 and IPv6 in one dump

    auto dump = netlink::dump(req, kRoutesSeq, parse_rtnetlink_routes_chunk, kRoutesRowCap);

    yuzu::shared::ConstraintAccumulator acc;
    std::vector<RouteRow> rows;
    rows.reserve(dump.records.size());
    bool multipath_collapsed = false;
    bool nexthop_object = false;
    for (const auto& rec : dump.records) {
        multipath_collapsed = multipath_collapsed || rec.multipath_collapsed;
        nexthop_object = nexthop_object || nexthop_unresolved(rec);
        rows.push_back(linux_route_to_row(rec, interface_name_for_index(rec.ifindex)));
    }

    if (dump.capped)
        acc.add_failure(kTokRowCap);
    else if (!dump.ok)
        acc.add_failure("network_config:rtnetlink_routes_dump_incomplete");
    if (multipath_collapsed)
        acc.add_failure("network_config:routes_multipath_first_nexthop_only");
    if (nexthop_object)
        acc.add_failure("network_config:routes_nexthop_object_unresolved");

    // A dump that never produced a single record AND did not complete means the
    // table was not read at all — UNAVAILABLE, not an empty (or "constrained") table.
    const bool unavailable = !dump.ok && !dump.capped && rows.empty();
    emit_routes(ctx, rows, acc, unavailable);
    return 0;
}

} // namespace yuzu::network_config

#endif // __linux__
