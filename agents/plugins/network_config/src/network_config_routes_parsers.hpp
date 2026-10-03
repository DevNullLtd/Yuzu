/**
 * network_config_routes_parsers.hpp — pure decoders and the shared row format
 * for the network_config plugin's `routes` action (full routing table).
 *
 * Why a second parser set rather than loosening the existing one:
 * parse_rtnetlink_route_chunk() / parse_default_route_dump() in
 * network_config_parsers.hpp deliberately keep ONLY the IPv4 default route in
 * the main table, because adapters/ip_addresses depend on exactly that
 * selectivity (the first record wins; a non-main default would be preferred
 * over the real one). `routes` wants the opposite — every route a reader could
 * act on — so it gets its own decoders and the old ones stay byte-identical.
 *
 * Same discipline as network_config_parsers.hpp: no I/O, no spdlog, every
 * length read from the kernel's blob is checked against the buffer before the
 * bytes are dereferenced, a malformed record sets `truncated` instead of
 * looping or reading out of bounds, and the caller learns about it rather than
 * receiving a silently short table.
 *
 * ALIGNMENT CONTRACT (rtnetlink decoder): as network_config_parsers.hpp states —
 * the buffer passed to parse_rtnetlink_routes_chunk() must be aligned to at
 * least NLMSG_ALIGNTO (network_config_netlink.hpp declares its read buffer
 * `alignas(NLMSG_ALIGNTO)`); the variable-length payloads are memcpy'd into
 * local objects before any field is read.
 *
 * Row shape (identical on every OS; `-` where an OS has no such concept):
 *   route|family|destination|prefix_len|gateway|interface|metric|table|type|origin
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <yuzu/string_utils.hpp> // yuzu::util::{sanitize_utf8,safe_output_field}

#include "network_config_parsers.hpp" // RtNetlinkParseChunk, includes the per-OS system headers

namespace yuzu::network_config {

/// Upper bound on emitted route rows (matches the arp action's kArpEntryCap). A
/// default-free-zone host can hold ~1M routes; the plugin must not buffer or
/// emit an unbounded table, and reports `routes_row_cap_reached` instead.
inline constexpr std::size_t kRoutesRowCap = 20000;

/// One route, already reduced to the cross-OS row vocabulary.
struct RouteRow {
    bool ipv6 = false;
    std::string destination; // formatted address; never empty on a real row
    unsigned prefix_len = 0;
    std::string gateway;     // empty = on-link (rendered `-`)
    std::string interface;   // empty = unknown (rendered `-`)
    std::string metric = "-";
    std::string table = "-";
    std::string type = "unicast";
    std::string origin = "-";
};

/// Render a RouteRow as the wire row. Every text field passes through
/// sanitize_utf8 + safe_output_field: interface names and gateway text come
/// from the kernel/OS, and a Linux interface name may legally contain `|`.
inline std::string format_route_row(const RouteRow& r) {
    auto field = [](const std::string& v) {
        return v.empty() ? std::string{"-"}
                         : yuzu::util::safe_output_field(yuzu::util::sanitize_utf8(v));
    };
    return std::format("route|{}|{}|{}|{}|{}|{}|{}|{}|{}", r.ipv6 ? "ipv6" : "ipv4",
                       field(r.destination), r.prefix_len, field(r.gateway), field(r.interface),
                       field(r.metric), field(r.table), field(r.type), field(r.origin));
}

#if defined(__linux__)

// ── Linux: RTM_GETROUTE (AF_UNSPEC) dump ─────────────────────────────────

/// One decoded RTM_NEWROUTE. Interface is the kernel ifindex; the impure leg
/// resolves it to a name (if_indextoname), so this decoder stays pure.
struct RtRouteFull {
    bool is_ipv6 = false;
    std::string destination;
    unsigned prefix_len = 0;
    std::string gateway; // empty = on-link
    bool has_nh_id = false;
    std::uint32_t nh_id = 0; // an `ip nexthop` object reference; gateway not resolved
    int ifindex = -1;
    std::uint32_t metric = 0; // RTA_PRIORITY; absent means 0
    std::uint32_t table = 0;
    unsigned char type = 0;     // rtm_type
    unsigned char protocol = 0; // rtm_protocol
    bool multipath_collapsed = false; // RTA_MULTIPATH held >1 nexthop; only the first is reported
};

using RtRoutesParse = RtNetlinkParseChunk<RtRouteFull>;

namespace routes_detail {

inline bool rta_u32(const struct rtattr* a, std::uint32_t& out) {
    if (static_cast<std::size_t>(RTA_PAYLOAD(a)) < sizeof(out))
        return false;
    std::memcpy(&out, RTA_DATA(a), sizeof(out));
    return true;
}

inline bool addr_text(const void* data, std::size_t payload, int family, std::string& out) {
    const std::size_t need = family == AF_INET6 ? 16 : 4;
    if (payload < need)
        return false;
    unsigned char bytes[16]{};
    std::memcpy(bytes, data, need);
    char text[INET6_ADDRSTRLEN]{};
    if (!::inet_ntop(family, bytes, text, sizeof(text)))
        return false;
    out = text;
    return true;
}

/// RTA_VIA is `struct rtvia { u16 family; u8 addr[]; }` — an IPv4 route whose
/// next hop is an IPv6 address (RFC 5549). The family inside the attribute, not
/// the route's own family, decides the address length.
inline bool via_text(const struct rtattr* a, std::string& out) {
    const std::size_t payload = static_cast<std::size_t>(RTA_PAYLOAD(a));
    if (payload < sizeof(std::uint16_t))
        return false;
    std::uint16_t fam = 0;
    std::memcpy(&fam, RTA_DATA(a), sizeof(fam));
    if (fam != AF_INET && fam != AF_INET6)
        return false;
    return addr_text(static_cast<const unsigned char*>(RTA_DATA(a)) + sizeof(fam),
                     payload - sizeof(fam), fam, out);
}

inline std::string table_name(std::uint32_t t) {
    if (t == RT_TABLE_MAIN)
        return "main";
    if (t == RT_TABLE_DEFAULT)
        return "default";
    return std::to_string(t);
}

inline std::string type_name(unsigned char t) {
    switch (t) {
    case RTN_UNICAST:
        return "unicast";
    case RTN_BLACKHOLE:
        return "blackhole";
    case RTN_UNREACHABLE:
        return "unreachable";
    case RTN_PROHIBIT:
        return "prohibit";
    case RTN_THROW:
        return "throw";
    case RTN_NAT:
        return "nat";
    case RTN_XRESOLVE:
        return "xresolve";
    default:
        return "type" + std::to_string(t);
    }
}

// Numeric literals, not RTPROT_* macros: the newer protocol ids (babel, bgp, ...)
// are missing from older kernel headers and the build must not depend on them.
inline std::string protocol_name(unsigned char p) {
    switch (p) {
    case 0:
        return "unspec";
    case 1:
        return "redirect";
    case 2:
        return "kernel";
    case 3:
        return "boot";
    case 4:
        return "static";
    case 8:
        return "gated";
    case 9:
        return "ra";
    case 10:
        return "mrt";
    case 11:
        return "zebra";
    case 12:
        return "bird";
    case 13:
        return "dnrouted";
    case 14:
        return "xorp";
    case 15:
        return "ntk";
    case 16:
        return "dhcp";
    case 17:
        return "mrouted";
    case 18:
        return "keepalived";
    case 42:
        return "babel";
    case 99:
        return "openr";
    case 186:
        return "bgp";
    case 187:
        return "isis";
    case 188:
        return "ospf";
    case 189:
        return "rip";
    case 192:
        return "eigrp";
    default:
        return "proto" + std::to_string(p);
    }
}

} // namespace routes_detail

/**
 * Decode one RTM_GETROUTE (AF_UNSPEC) dump reply chunk into every route a
 * reader could act on. Kept: IPv4 and IPv6 routes of type unicast / blackhole /
 * unreachable / prohibit / throw (and the rarer nat/xresolve) in the main table
 * AND in any custom table (VPN clients and policy routing live there). Skipped
 * as host-local noise: the local table (255), RTN_LOCAL / BROADCAST / ANYCAST /
 * MULTICAST routes, and RTM_F_CLONED cache entries.
 *
 * RTA_TABLE overrides rtm_table when present (rtm_table is only 8 bits).
 * RTA_MULTIPATH reports the FIRST nexthop only and flags `multipath_collapsed`;
 * RTA_NH_ID (an `ip nexthop` object) is flagged via has_nh_id — the gateway is
 * not resolved. The caller turns both into a typed constraint rather than
 * claiming a complete table.
 */
inline RtRoutesParse parse_rtnetlink_routes_chunk(std::span<const unsigned char> blob,
                                                  std::uint32_t expected_seq) {
    RtRoutesParse out;
    auto len = static_cast<int>(blob.size());
    const auto* h = reinterpret_cast<const struct nlmsghdr*>(blob.data());
    for (; NLMSG_OK(h, len); h = reinterpret_cast<const struct nlmsghdr*>(NLMSG_NEXT(h, len))) {
        // Sequence check FIRST — see parse_rtnetlink_link_chunk().
        if (h->nlmsg_seq != expected_seq)
            continue;
        if (h->nlmsg_type == NLMSG_DONE) {
            out.done = true;
            break;
        }
        if (h->nlmsg_type == NLMSG_ERROR) {
            out.error = true;
            break;
        }
        if (h->nlmsg_type != RTM_NEWROUTE)
            continue;
        if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg))) {
            out.truncated = true;
            break;
        }

        struct rtmsg rtm {};
        std::memcpy(&rtm, NLMSG_DATA(h), sizeof(rtm));
        if (rtm.rtm_family != AF_INET && rtm.rtm_family != AF_INET6)
            continue; // AF_MPLS, AF_BRIDGE, ... — not an IP route
        if ((rtm.rtm_flags & RTM_F_CLONED) != 0)
            continue; // cache entry, not configuration
        switch (rtm.rtm_type) {
        case RTN_LOCAL:
        case RTN_BROADCAST:
        case RTN_ANYCAST:
        case RTN_MULTICAST:
            continue; // host-local noise
        default:
            break;
        }

        RtRouteFull rec;
        rec.is_ipv6 = rtm.rtm_family == AF_INET6;
        rec.prefix_len = rtm.rtm_dst_len;
        rec.type = rtm.rtm_type;
        rec.protocol = rtm.rtm_protocol;
        rec.table = rtm.rtm_table;
        if (rec.prefix_len > (rec.is_ipv6 ? 128u : 32u)) {
            out.truncated = true; // malformed prefix length — never emit a bogus row
            continue;
        }
        rec.destination = rec.is_ipv6 ? "::" : "0.0.0.0"; // default route carries no RTA_DST

        int rta_len = static_cast<int>(h->nlmsg_len) - static_cast<int>(NLMSG_LENGTH(sizeof(rtm)));
        const auto* rta = reinterpret_cast<const struct rtattr*>(
            static_cast<const unsigned char*>(NLMSG_DATA(h)) + NLMSG_ALIGN(sizeof(rtm)));
        bool malformed = false;
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            const int family = rtm.rtm_family;
            std::uint32_t v = 0;
            switch (rta->rta_type & NLA_TYPE_MASK) {
            case RTA_DST:
                if (!routes_detail::addr_text(RTA_DATA(rta), RTA_PAYLOAD(rta), family,
                                              rec.destination))
                    malformed = true;
                break;
            case RTA_GATEWAY:
                if (!routes_detail::addr_text(RTA_DATA(rta), RTA_PAYLOAD(rta), family, rec.gateway))
                    malformed = true;
                break;
            case RTA_VIA:
                if (!routes_detail::via_text(rta, rec.gateway))
                    malformed = true;
                break;
            case RTA_OIF:
                if (routes_detail::rta_u32(rta, v))
                    rec.ifindex = static_cast<int>(v);
                else
                    malformed = true;
                break;
            case RTA_PRIORITY:
                if (routes_detail::rta_u32(rta, v))
                    rec.metric = v;
                else
                    malformed = true;
                break;
            case RTA_TABLE:
                if (routes_detail::rta_u32(rta, v))
                    rec.table = v; // overrides the 8-bit rtm_table
                else
                    malformed = true;
                break;
            case RTA_NH_ID:
                if (routes_detail::rta_u32(rta, v)) {
                    rec.has_nh_id = true;
                    rec.nh_id = v;
                } else {
                    malformed = true;
                }
                break;
            case RTA_MULTIPATH: {
                int nh_len = static_cast<int>(RTA_PAYLOAD(rta));
                const auto* nh = static_cast<const struct rtnexthop*>(RTA_DATA(rta));
                int count = 0;
                while (RTNH_OK(nh, nh_len)) {
                    if (count++ == 0) {
                        rec.ifindex = nh->rtnh_ifindex;
                        int sub_len = static_cast<int>(nh->rtnh_len) -
                                      static_cast<int>(sizeof(struct rtnexthop));
                        const auto* sub = reinterpret_cast<const struct rtattr*>(
                            reinterpret_cast<const unsigned char*>(nh) +
                            NLMSG_ALIGN(sizeof(struct rtnexthop)));
                        for (; sub_len > 0 && RTA_OK(sub, sub_len); sub = RTA_NEXT(sub, sub_len)) {
                            const int sub_type = sub->rta_type & NLA_TYPE_MASK;
                            if (sub_type == RTA_GATEWAY)
                                routes_detail::addr_text(RTA_DATA(sub), RTA_PAYLOAD(sub), family,
                                                         rec.gateway);
                            else if (sub_type == RTA_VIA)
                                routes_detail::via_text(sub, rec.gateway);
                        }
                    }
                    // RTNH_NEXT is single-argument and does NOT decrement the
                    // remaining length, unlike RTA_NEXT: the caller must, or a
                    // crafted rtnh_len on a later nexthop passes RTNH_OK against
                    // the ORIGINAL length and points past the real payload.
                    const int consumed = RTNH_ALIGN(nh->rtnh_len);
                    nh = RTNH_NEXT(nh);
                    nh_len -= consumed;
                }
                if (nh_len > 0)
                    malformed = true; // a trailing, unparseable nexthop
                rec.multipath_collapsed = count > 1;
                break;
            }
            default:
                break;
            }
        }
        if (rta_len > 0)
            malformed = true; // attribute walk stopped on a bad rta_len
        if (malformed)
            out.truncated = true;

        if (rec.table == RT_TABLE_LOCAL)
            continue; // checked AFTER the attribute walk so RTA_TABLE can override rtm_table
        out.records.push_back(std::move(rec));
    }
    if (!out.done && !out.error && len > 0)
        out.truncated = true;
    return out;
}

/// Reduce a decoded Linux route to the cross-OS row. `interface` is the name the
/// caller resolved from `ifindex` (empty when it could not).
inline RouteRow linux_route_to_row(const RtRouteFull& r, std::string interface) {
    RouteRow row;
    row.ipv6 = r.is_ipv6;
    row.destination = r.destination;
    row.prefix_len = r.prefix_len;
    row.gateway = r.gateway.empty() && r.has_nh_id ? "nhid:" + std::to_string(r.nh_id) : r.gateway;
    row.interface = std::move(interface);
    row.metric = std::to_string(r.metric);
    row.table = routes_detail::table_name(r.table);
    row.type = routes_detail::type_name(r.type);
    row.origin = routes_detail::protocol_name(r.protocol);
    return row;
}

#endif // __linux__

} // namespace yuzu::network_config
