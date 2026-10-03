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

#include <charconv>
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

namespace routes_detail {

struct NameEntry {
    int id;
    const char* name;
};

/// The table's name for `id`, else `<fallback_prefix><id>` — a route field is never empty.
template <std::size_t N>
inline std::string lookup_name(const NameEntry (&table)[N], int id, const char* fallback_prefix) {
    for (const auto& e : table)
        if (e.id == id)
            return e.name;
    return fallback_prefix + std::to_string(id);
}

} // namespace routes_detail

/// One route, already reduced to the cross-OS row vocabulary.
struct RouteRow {
    bool ipv6 = false;
    std::string destination; // formatted address; never empty on a real row
    unsigned prefix_len = 0;
    std::string gateway;     // empty = on-link
    std::string interface;   // empty = unknown
    // Every text field below is rendered `-` when empty (format_route_row): the one "absent" convention.
    std::string metric;
    std::string table;
    std::string type = "unicast";
    std::string origin;
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

// ── Windows: GetIpForwardTable2 rows ─────────────────────────────────────
//
// The IP Helper call and its SOCKADDR_INET unpacking live in the (impure, Windows
// only) leg TU. Everything decidable WITHOUT Windows headers lives here, on a
// plain struct whose addresses the shell has already rendered to text, so the
// mapping and the skip rule are unit-tested on every host.

/// One MIB_IPFORWARD_ROW2, reduced.
struct WinRoute {
    bool ipv6 = false;
    std::string destination;
    unsigned prefix_len = 0;
    std::string next_hop;     // empty = on-link (an unspecified next hop)
    std::string interface;    // ConvertInterfaceLuidToAlias, or `if<index>`
    unsigned long metric = 0; // the ROUTE metric; the interface metric is NOT added
    int protocol = 0;         // NL_ROUTE_PROTOCOL
};

inline constexpr int kWinProtocolLocal = 2; // MIB_IPPROTO_LOCAL

/// NL_ROUTE_PROTOCOL as Get-NetRoute names it (lower-cased). Numeric literals,
/// not the SDK enumerators: this header must compile on hosts without them.
inline std::string win_protocol_name(int p) {
    static constexpr routes_detail::NameEntry kNames[] = {
        {1, "other"},   {2, "local"},   {3, "netmgmt"},  {4, "icmp"},  {5, "egp"},
        {6, "ggp"},     {7, "hello"},   {8, "rip"},      {9, "isis"},  {10, "esis"},
        {11, "cisco"},  {12, "bbn"},    {13, "ospf"},    {14, "bgp"},  {15, "idpr"},
        {16, "eigrp"},  {17, "dvmrp"},  {18, "rpl"},     {19, "dhcp"}, {10002, "autostatic"},
        {10006, "static"}, {10007, "static_non_dod"},
    };
    return routes_detail::lookup_name(kNames, p, "proto");
}

/// True for the rows Windows generates for the HOST rather than for reachability,
/// the same noise the Linux leg drops with the local table and the macOS leg with
/// RTF_LOCAL / RTF_MULTICAST / RTF_BROADCAST. Only Protocol=Local rows qualify — a route
/// someone configured (NetMgmt: a VPN peer route, a static route) is kept whatever its prefix:
///   - a full-length prefix (/32, /128): the host's own addresses and its broadcast addresses
///     (Windows tags both `Local`);
///   - a multicast prefix (224.0.0.0/4, ff00::/8), one per interface.
/// Protocol=Local with a SHORTER, non-multicast prefix is kept: that is the connected-subnet
/// route (192.0.2.0/24, fe80::/64, 127.0.0.0/8) and is exactly what a reader wants.
inline bool win_route_is_host_local(const WinRoute& r) {
    if (r.protocol != kWinProtocolLocal)
        return false;
    if (r.prefix_len == (r.ipv6 ? 128u : 32u))
        return true;
    if (r.ipv6)
        return r.destination.starts_with("ff") && r.prefix_len == 8;
    // IPv4 multicast is 224.0.0.0/4: first octet 224-239.
    unsigned first = 0;
    std::from_chars(r.destination.data(), r.destination.data() + r.destination.size(), first);
    return first >= 224 && first <= 239 && r.prefix_len >= 4;
}

/// Reduce a Windows route to the cross-OS row. Windows has no table id and no
/// route type, so `table` is `-` and `type` is `unicast`.
inline RouteRow win_route_to_row(const WinRoute& r) {
    RouteRow row;
    row.ipv6 = r.ipv6;
    row.destination = r.destination;
    row.prefix_len = r.prefix_len;
    row.gateway = r.next_hop;
    row.interface = r.interface;
    row.metric = std::to_string(r.metric);
    row.origin = win_protocol_name(r.protocol);
    return row;
}

#if defined(__linux__) || defined(__APPLE__)

namespace routes_detail {

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

} // namespace routes_detail

#endif // __linux__ || __APPLE__

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

/// An `ip nexthop` object route: it names a nexthop group by id and carries no gateway of its own.
inline bool nexthop_unresolved(const RtRouteFull& r) { return r.has_nh_id && r.gateway.empty(); }

namespace routes_detail {

inline bool rta_u32(const struct rtattr* a, std::uint32_t& out) {
    if (static_cast<std::size_t>(RTA_PAYLOAD(a)) < sizeof(out))
        return false;
    std::memcpy(&out, RTA_DATA(a), sizeof(out));
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
    static constexpr NameEntry kNames[] = {
        {RTN_UNICAST, "unicast"},     {RTN_BLACKHOLE, "blackhole"}, {RTN_UNREACHABLE, "unreachable"},
        {RTN_PROHIBIT, "prohibit"},   {RTN_THROW, "throw"},         {RTN_NAT, "nat"},
        {RTN_XRESOLVE, "xresolve"},
    };
    return lookup_name(kNames, t, "type");
}

// Numeric literals, not RTPROT_* macros: the newer protocol ids (babel, bgp, ...)
// are missing from older kernel headers and the build must not depend on them.
inline std::string protocol_name(unsigned char p) {
    static constexpr NameEntry kNames[] = {
        {0, "unspec"},   {1, "redirect"}, {2, "kernel"},  {3, "boot"},     {4, "static"},
        {8, "gated"},    {9, "ra"},       {10, "mrt"},    {11, "zebra"},   {12, "bird"},
        {13, "dnrouted"}, {14, "xorp"},   {15, "ntk"},    {16, "dhcp"},    {17, "mrouted"},
        {18, "keepalived"}, {42, "babel"}, {99, "openr"}, {186, "bgp"},    {187, "isis"},
        {188, "ospf"},   {189, "rip"},    {192, "eigrp"},
    };
    return lookup_name(kNames, p, "proto");
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
                            // A nested gateway that does not decode is a malformed record,
                            // not an on-link nexthop: the top-level attributes treat it the same.
                            if (sub_type == RTA_GATEWAY) {
                                if (!routes_detail::addr_text(RTA_DATA(sub), RTA_PAYLOAD(sub),
                                                              family, rec.gateway))
                                    malformed = true;
                            } else if (sub_type == RTA_VIA) {
                                if (!routes_detail::via_text(sub, rec.gateway))
                                    malformed = true;
                            }
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
    row.gateway = nexthop_unresolved(r) ? "nhid:" + std::to_string(r.nh_id) : r.gateway;
    row.interface = std::move(interface);
    row.metric = std::to_string(r.metric);
    row.table = routes_detail::table_name(r.table);
    row.type = routes_detail::type_name(r.type);
    row.origin = routes_detail::protocol_name(r.protocol);
    return row;
}

#endif // __linux__

#if defined(__APPLE__)

// ── macOS: PF_ROUTE NET_RT_DUMP (all families) ───────────────────────────

/// One decoded routing-socket route. Interface is the kernel's rtm_index; the
/// impure leg resolves it to a name (if_indextoname), so this decoder stays pure.
struct MacRoute {
    bool is_ipv6 = false;
    std::string destination;
    unsigned prefix_len = 0;
    std::string gateway; // empty = on-link (an AF_LINK gateway) or no gateway
    int ifindex = 0;
    int flags = 0; // rtm_flags
};

struct MacRoutesParse {
    std::vector<MacRoute> records;
    bool truncated = false; // a malformed record/chain was met; the table may be short
    bool capped = false;    // stopped at kRoutesRowCap; the table is longer than reported
};

namespace routes_detail {

// Routes that describe the HOST rather than the network's reachability, plus
// per-neighbour and transient entries. Skipped for the same reason the Linux leg
// skips the local table: an operator wants the configured routes, and the arp
// action already owns neighbour entries (RTF_LLINFO).
//   RTF_LLINFO    ARP / NDP neighbour entries
//   RTF_WASCLONED host routes the kernel cloned from a CLONING route on demand
//   RTF_MULTICAST / RTF_BROADCAST  group routes
//   RTF_LOCAL     the host's own addresses
inline constexpr int kMacSkipFlags =
    RTF_LLINFO | RTF_WASCLONED | RTF_MULTICAST | RTF_BROADCAST | RTF_LOCAL;

inline std::string mac_v4_text(const unsigned char* sa) {
    std::string out;
    addr_text(sa + offsetof(struct sockaddr_in, sin_addr), 4, AF_INET, out);
    return out;
}

/// KAME stores the interface scope of a link-local (or link/node-scoped multicast)
/// address in bytes 2-3 of the address itself (`fe80:7::` is `fe80::%en0`). That
/// is an encoding artefact, not part of the address — and it is the only place the
/// scope lives in a dump — so it is cleared; the row's `interface` carries it.
inline std::string mac_v6_text(const unsigned char* sa) {
    unsigned char a[16]{};
    std::memcpy(a, sa + offsetof(struct sockaddr_in6, sin6_addr), sizeof(a));
    const bool link_local = a[0] == 0xfe && (a[1] & 0xc0) == 0x80;
    const bool scoped_mc = a[0] == 0xff && ((a[1] & 0x0f) == 1 || (a[1] & 0x0f) == 2);
    if (link_local || scoped_mc)
        a[2] = a[3] = 0;
    std::string out;
    addr_text(a, sizeof(a), AF_INET6, out);
    return out;
}

/// Prefix length from a routing-socket netmask sockaddr. The kernel TRIMS these:
/// `sa_len` covers only the bytes up to the last non-zero one, and everything
/// past it is implicitly zero (a /0 mask has `sa_len` 0 or 4). The sockaddr
/// family byte is not reliable here, so the DESTINATION's family decides the
/// address width. Returns false for a non-contiguous mask.
inline bool mac_mask_prefix(const unsigned char* sa, bool v6, unsigned& out) {
    const std::size_t sa_len = sa[0];
    const std::size_t addr_off =
        v6 ? offsetof(struct sockaddr_in6, sin6_addr) : offsetof(struct sockaddr_in, sin_addr);
    const std::size_t width = v6 ? 16 : 4;
    const std::size_t avail = sa_len > addr_off ? std::min(width, sa_len - addr_off) : 0;
    unsigned char bytes[16]{};
    std::memcpy(bytes, sa + addr_off, avail);
    unsigned ones = 0;
    std::size_t i = 0;
    for (; i < width && bytes[i] == 0xff; ++i)
        ones += 8;
    if (i < width) {
        unsigned char b = bytes[i];
        while (b & 0x80) {
            ++ones;
            b = static_cast<unsigned char>(b << 1);
        }
        if (b != 0)
            return false; // a 1 bit after a 0 bit
        for (++i; i < width; ++i)
            if (bytes[i] != 0)
                return false;
    }
    out = ones;
    return true;
}

} // namespace routes_detail

/**
 * Decode a NET_RT_DUMP blob (address family 0 = IPv4 and IPv6 together) into the
 * routes a reader could act on. Walk and bounds-check discipline is the SAME as
 * parse_default_route_dump(): every rtm_msglen is checked against the remaining
 * buffer, an unrecognised rtm_version stops the walk, every sockaddr's sa_len is
 * bounds-checked before its bytes are read, the ROUNDUP unit is the fixed 4-byte
 * routing-socket alignment, and every multi-byte header is memcpy'd. Any
 * malformation sets `truncated` instead of looping or reading out of bounds.
 *
 * Skipped (see routes_detail::kMacSkipFlags): neighbour, cloned, group and
 * host-own-address entries. A destination that is neither AF_INET nor AF_INET6 is
 * skipped silently. A route with no netmask is a host route (full-length prefix).
 * Stops at kRoutesRowCap kept routes and sets `capped`.
 */
inline MacRoutesParse parse_route_table_dump(std::span<const unsigned char> blob) {
    MacRoutesParse out;
    std::size_t off = 0;

    while (off + sizeof(rt_msghdr) <= blob.size()) {
        rt_msghdr hdr{};
        std::memcpy(&hdr, blob.data() + off, sizeof(hdr));

        if (hdr.rtm_msglen < sizeof(rt_msghdr) || off + hdr.rtm_msglen > blob.size() ||
            hdr.rtm_version != RTM_VERSION) {
            out.truncated = true;
            break;
        }

        const unsigned char* rec_end = blob.data() + off + hdr.rtm_msglen;
        const unsigned char* p = blob.data() + off + sizeof(rt_msghdr);

        const unsigned char* sa_dst = nullptr;
        const unsigned char* sa_gw = nullptr;
        const unsigned char* sa_mask = nullptr;
        bool chain_ok = true;

        for (int i = 0; i < RTAX_MAX && p < rec_end; ++i) {
            if (!(hdr.rtm_addrs & (1 << i)))
                continue;
            const std::size_t remaining = static_cast<std::size_t>(rec_end - p);
            if (remaining < 2)
                break; // the chain ends here — not an overrun
            constexpr std::size_t kAlign = sizeof(std::uint32_t);
            const std::size_t entry_len = p[0] ? p[0] : kAlign;
            if (remaining < entry_len) {
                out.truncated = true;
                chain_ok = false;
                break;
            }
            if (i == RTAX_DST)
                sa_dst = p;
            else if (i == RTAX_GATEWAY)
                sa_gw = p;
            else if (i == RTAX_NETMASK)
                sa_mask = p;
            const std::size_t adv = (entry_len + kAlign - 1) & ~(kAlign - 1);
            if (adv > remaining) {
                out.truncated = true;
                chain_ok = false;
                break;
            }
            p += adv;
        }
        off += hdr.rtm_msglen;

        // An advertised sockaddr the record ran out of bytes for is a malformed record. Without
        // this a missing netmask would read as "no netmask" and emit a /32 host route.
        const int wanted = hdr.rtm_addrs & (RTA_DST | RTA_GATEWAY | RTA_NETMASK);
        if (chain_ok && (((wanted & RTA_DST) && sa_dst == nullptr) ||
                         ((wanted & RTA_GATEWAY) && sa_gw == nullptr) ||
                         ((wanted & RTA_NETMASK) && sa_mask == nullptr))) {
            out.truncated = true;
            continue;
        }
        if (!chain_ok || sa_dst == nullptr)
            continue;
        if ((hdr.rtm_flags & routes_detail::kMacSkipFlags) != 0)
            continue;

        MacRoute rec;
        rec.ifindex = hdr.rtm_index;
        rec.flags = hdr.rtm_flags;
        // A zero-length destination is the all-zero encoding of an IPv4 default
        // (same reading as parse_default_route_dump()).
        const unsigned sa_len = sa_dst[0];
        const unsigned family = sa_len == 0 ? AF_INET : sa_dst[1];
        if (family == AF_INET) {
            rec.is_ipv6 = false;
            if (sa_len == 0) {
                rec.destination = "0.0.0.0";
            } else if (sa_len >= sizeof(struct sockaddr_in)) {
                rec.destination = routes_detail::mac_v4_text(sa_dst);
            } else {
                out.truncated = true;
                continue;
            }
        } else if (family == AF_INET6) {
            if (sa_len < sizeof(struct sockaddr_in6)) {
                out.truncated = true;
                continue;
            }
            rec.is_ipv6 = true;
            rec.destination = routes_detail::mac_v6_text(sa_dst);
        } else {
            continue; // AF_LINK / AF_SYSTEM / anything else: not an IP route
        }
        if (rec.destination.empty()) {
            out.truncated = true;
            continue;
        }

        const unsigned full = rec.is_ipv6 ? 128u : 32u;
        rec.prefix_len = full; // no netmask = a host route
        if (sa_mask != nullptr && !routes_detail::mac_mask_prefix(sa_mask, rec.is_ipv6, rec.prefix_len)) {
            out.truncated = true; // non-contiguous mask: never emit a guessed prefix
            continue;
        }

        if (sa_gw != nullptr && sa_gw[0] != 0) {
            if (sa_gw[1] == AF_INET && sa_gw[0] >= sizeof(struct sockaddr_in))
                rec.gateway = routes_detail::mac_v4_text(sa_gw);
            else if (sa_gw[1] == AF_INET6 && sa_gw[0] >= sizeof(struct sockaddr_in6))
                rec.gateway = routes_detail::mac_v6_text(sa_gw);
            // AF_LINK (`link#N`): on-link, no gateway address. Anything else: none.
        }

        if (out.records.size() >= kRoutesRowCap) {
            out.capped = true;
            break;
        }
        out.records.push_back(std::move(rec));
    }

    if (!out.capped && off < blob.size())
        out.truncated = true;
    return out;
}

/// Reduce a decoded macOS route to the cross-OS row. macOS has no route metric
/// and no table id, and its only provenance is the RTF_STATIC / RTF_DYNAMIC bits:
/// `origin` says `static` or `dynamic` when the kernel set one, else `other`.
inline RouteRow mac_route_to_row(const MacRoute& r, std::string interface) {
    RouteRow row;
    row.ipv6 = r.is_ipv6;
    row.destination = r.destination;
    row.prefix_len = r.prefix_len;
    row.gateway = r.gateway;
    row.interface = std::move(interface);
    row.type = (r.flags & RTF_BLACKHOLE) ? "blackhole" : (r.flags & RTF_REJECT) ? "reject" : "unicast";
    row.origin = (r.flags & RTF_STATIC)                        ? "static"
                 : (r.flags & (RTF_DYNAMIC | RTF_MODIFIED)) ? "dynamic"
                                                                 : "other";
    return row;
}

#endif // __APPLE__

} // namespace yuzu::network_config
