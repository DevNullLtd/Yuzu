/**
 * network_config_parsers.hpp — pure output/binary decoders for the
 * network_config plugin's native legs (PKG-NC, ADR-3002 acquisition-ladder
 * migration). No I/O, no spdlog — every parser here is unit-testable
 * directly against fixture text/bytes (see
 * tests/unit/test_network_config_parsers.cpp), mirroring the split already
 * established by agents/plugins/services/src/services_parsers.hpp and
 * agents/plugins/discovery/src/discovery_parsers.hpp: network_config_plugin.cpp
 * owns every subprocess/socket/sysctl call and hands this header the raw
 * text or bytes it captured.
 *
 * Three families:
 *   - /proc/net/arp text parsing (Linux arp leg). A standalone copy, not a
 *     re-include of discovery_parsers.hpp — the two decoders read the same
 *     kernel format but produce DIFFERENT field sets (this plugin's arp
 *     action needs the interface name and a static/dynamic type that
 *     discovery's does not), so neither is a superset of the other. If the
 *     two ever need to converge, the shared core belongs in agents/shared/
 *     as a zero-dependency header-only leaf — where this plugin already gets
 *     route_sysctl_arp.hpp from — with the two field-set wrappers on top.
 *   - resolvectl-cache / systemd-resolve-statistics captured-stdout line
 *     parsers (Linux dns_cache legs), moved here from the old inline
 *     istringstream loops in network_config_plugin.cpp.
 *   - PURE span-based binary decoders for the rtnetlink (Linux) and
 *     PF_ROUTE (macOS) reads. Bounds-checking discipline modeled EXACTLY on
 *     agents/shared/route_sysctl_arp.hpp: every length read from the blob
 *     is checked against the buffer before the corresponding bytes are
 *     dereferenced, a malformed/short record stops the walk rather than
 *     looping or reading out of bounds, and the caller learns about
 *     truncation instead of silently receiving a partial result.
 *
 *     ALIGNMENT CONTRACT (rtnetlink decoders only): the nlmsghdr/rtattr walk
 *     reads its header fields through the kernel's own NLMSG_ and RTA_
 *     macros, which cast into the caller's buffer rather than copying.
 *     Callers of the parse_rtnetlink chunk decoders must therefore pass a
 *     buffer aligned to at least NLMSG_ALIGNTO (production callers declare
 *     theirs
 *     `alignas(NLMSG_ALIGNTO)`, and so do the fixture tests). The variable-
 *     length PAYLOADS those headers describe — ifinfomsg, ifaddrmsg, rtmsg
 *     and every attribute value — are memcpy'd into locally-aligned objects
 *     before any field is read. parse_default_route_dump() takes no such
 *     precondition: it memcpys throughout.
 *
 *     The fixture tests satisfy the same precondition by a DIFFERENT
 *     mechanism: they build messages in a std::vector<unsigned char>, whose
 *     allocator returns storage aligned to at least alignof(max_align_t),
 *     which exceeds NLMSG_ALIGNTO. They do not declare alignas themselves —
 *     an earlier version of this comment said they did, which was false.
 */
#pragma once

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <span>

#include <arpa/inet.h>
#include <linux/if.h> // IFF_UP — deliberately linux/if.h, not net/if.h, to avoid the
                       // classic duplicate-struct conflict when mixed with
                       // linux/rtnetlink.h's own transitive includes.
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#endif

#if defined(__APPLE__)
#include <span>

#include <arpa/inet.h>
#include <net/route.h>
#include <netinet/in.h>
#endif

namespace yuzu::network_config {

// ── /proc/net/arp (Linux arp leg) ────────────────────────────────────────

/// One resolved row of /proc/net/arp — `arp|iface|ip|mac|type` is the
/// plugin's own emitted shape (see do_arp()).
struct ProcNetArpEntry {
    std::string iface;
    std::string ip;
    std::string mac;
    std::string type; // "static" (ATF_PERM) or "dynamic"
};

/**
 * Parse the text of /proc/net/arp into resolved entries. Pure — no
 * ifstream, no I/O. Kernel format (net/ipv4/arp.c:arp_seq_show):
 *   IP address       HW type     Flags       HW address            Mask     Device
 *   192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
 *
 * Same selectivity as discovery_parsers.hpp's parse_proc_net_arp (Ethernet
 * hwtype only, ATF_COM-complete only, non-zero MAC only) plus the Device
 * column and an ATF_PERM-derived static/dynamic type this plugin's arp
 * action needs. Tolerates CRLF, ragged/collapsed whitespace, short/blank
 * lines (skipped, never thrown), and a missing header line.
 */
inline std::vector<ProcNetArpEntry> parse_proc_net_arp(std::string_view text) {
    std::vector<ProcNetArpEntry> out;

    std::istringstream stream{std::string{text}};
    std::string line;
    bool first_line = true;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        if (first_line) {
            first_line = false;
            std::istringstream probe{line};
            std::string first_tok;
            if (probe >> first_tok && first_tok == "IP")
                continue; // the kernel header always starts with "IP address"
        }

        std::istringstream lss{line};
        std::string ip, hwtype, flags_str, mac, mask, device;
        if (!(lss >> ip >> hwtype >> flags_str >> mac >> mask >> device))
            continue; // short/ragged/blank/truncated line — skip, don't crash

        if (hwtype != "0x1")
            continue; // Ethernet only (ARPHRD_ETHER == 0x1)

        char* end = nullptr;
        errno = 0;
        const unsigned long flags = std::strtoul(flags_str.c_str(), &end, 16);
        constexpr unsigned long kAtfCom = 0x2;
        constexpr unsigned long kAtfPerm = 0x4;
        if (errno == ERANGE || end == flags_str.c_str() || *end != '\0' || !(flags & kAtfCom))
            continue; // incomplete/unresolved/overflowing — no complete bit set

        if (mac.empty() || mac == "00:00:00:00:00:00")
            continue;

        ProcNetArpEntry entry;
        entry.iface = std::move(device);
        entry.ip = std::move(ip);
        entry.mac = std::move(mac);
        entry.type = (flags & kAtfPerm) ? "static" : "dynamic";
        out.push_back(std::move(entry));
    }

    return out;
}

// ── dns_cache captured-stdout parsers (Linux) ────────────────────────────

/**
 * Split `resolvectl cache` captured stdout into non-blank, CRLF-trimmed
 * lines, ready for `cache_entry|<line>` emission. Pure text splitting --
 * the old inline istringstream loop moved here unchanged in behaviour.
 */
inline std::vector<std::string> parse_resolvectl_cache_lines(std::string_view output) {
    std::vector<std::string> lines;
    std::istringstream ss{std::string{output}};
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            lines.push_back(std::move(line));
    }
    return lines;
}

/**
 * Filter `systemd-resolve --statistics` captured stdout down to the three
 * known cache-related lines ("Current Cache Size:", "Cache Hits:",
 * "Cache Misses:"), each trimmed of leading whitespace — same selectivity
 * as the old inline loop, moved here unchanged.
 */
inline std::vector<std::string> parse_systemd_resolve_stats_lines(std::string_view output) {
    std::vector<std::string> lines;
    std::istringstream ss{std::string{output}};
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        auto start = line.find_first_not_of(" \t");
        std::string trimmed = (start == std::string::npos) ? std::string{} : line.substr(start);
        if (trimmed.starts_with("Current Cache Size:") || trimmed.starts_with("Cache Hits:") ||
            trimmed.starts_with("Cache Misses:")) {
            lines.push_back(std::move(trimmed));
        }
    }
    return lines;
}

/// Format a 6-byte Ethernet address as lowercase colon-separated hex.
/// Returns an empty string for any other length — callers treat that as
/// "unresolved/non-Ethernet", never a fabricated MAC. Shared by the Linux
/// rtnetlink IFLA_ADDRESS decode below and network_config_plugin.cpp's
/// macOS getifaddrs/sockaddr_dl adapters leg.
inline std::string format_mac(const unsigned char* addr, std::size_t len) {
    if (len != 6)
        return {};
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(17);
    for (std::size_t i = 0; i < 6; ++i) {
        if (i)
            out += ':';
        out += kHex[addr[i] >> 4];
        out += kHex[addr[i] & 0x0F];
    }
    return out;
}

/**
 * Dedupe a vector of equality-comparable values, preserving first-seen
 * order. O(n) via an unordered_set sidecar tracking what has already been
 * emitted — both callers can see up to kArpEntryCap (20000) records before
 * their own cap trims the output, and an O(n^2) `std::find` scan at that
 * boundary is a worst-case ~200M comparisons for one dedupe call.
 *
 * Two production callers (PKG-NC fix round, live before/after parity diff):
 *   - macOS arp: the PF_ROUTE NET_RT_FLAGS/RTF_LLINFO sysctl dump can report
 *     the same {ip, mac} neighbour twice on a real host — deduped on the
 *     formatted `arp|...` output line.
 *   - macOS dns_servers: unioning State:/Network/Global/DNS with every
 *     State:/Network/Service/<id>/DNS key can repeat the same resolver
 *     address across services — deduped on the address string, global-
 *     first (global is queried and appended before any per-service list).
 */
template <typename T>
inline std::vector<T> dedupe_preserve_order(const std::vector<T>& items) {
    std::vector<T> out;
    out.reserve(items.size());
    std::unordered_set<T> seen;
    seen.reserve(items.size());
    for (const auto& item : items) {
        if (seen.insert(item).second)
            out.push_back(item);
    }
    return out;
}

/**
 * Ordered union of resolver lists, first-seen order preserved.
 *
 * The macOS `dns_servers` leg must report the primary resolver AND every
 * supplemental per-service resolver: State:/Network/Global/DNS holds only the
 * primary, so reading it alone silently drops VPN split-DNS and secondary-
 * interface resolvers. Callers pass the global list FIRST, then each
 * per-service list; a resolver legitimately appearing under several services
 * collapses to its first occurrence.
 *
 * This is the DECISION half of that leg, split out from the ACQUISITION half
 * (the SCDynamicStore key enumeration) so it can be fixture-tested — the
 * "pure core, thin shell" discipline. The key enumeration itself remains
 * untested; it has no fixture surface.
 */
inline std::vector<std::string>
union_dns_servers(const std::vector<std::vector<std::string>>& groups) {
    std::vector<std::string> all;
    for (const auto& g : groups)
        all.insert(all.end(), g.begin(), g.end());
    return dedupe_preserve_order(all);
}

/**
 * Join a proxy exception list into the `bypass|<list>` row's payload. Pure.
 *
 * Empty and whitespace-only entries are dropped; the result is empty when
 * nothing survives, and the caller then emits no row at all. Split out from
 * the CoreFoundation array walk so the formatting has a fixture surface —
 * this row appears on essentially every Mac, and previously had none.
 */
inline std::string join_bypass_list(const std::vector<std::string>& entries) {
    std::string joined;
    for (const auto& e : entries) {
        if (e.empty())
            continue;
        if (!joined.empty())
            joined += ',';
        joined += e;
    }
    return joined;
}

/// One network service's proxy configuration, decoded from whichever
/// dictionary it came from. `service` is empty for the top-level (primary /
/// current-effective) dictionary and carries the interface/service key for a
/// scoped one; it is descriptive only and does not affect selection.
struct ProxyServiceConfig {
    std::string service;
    bool http_enabled = false;
    std::string http_host;
    int http_port = 0;
    bool pac_enabled = false;
    std::string pac_url;
};

/// The row `do_proxy` should emit: `found == false` means `proxy_type|none`.
struct ProxySelection {
    bool found = false;
    std::string type;    // "http" | "pac"
    std::string address; // "host:port" | the PAC URL
};

/**
 * Choose the proxy row from an ordered candidate list. Pure.
 *
 * Two properties this pins, both of which were regressions:
 *
 *  1. HTTP BEFORE PAC, within a single service. The pre-migration leg tested
 *     `networksetup -getwebproxy` in its IF branch and only reached
 *     `-getautoproxyurl` in the ELSE, so a host with both configured reported
 *     `http`. Checking PAC first silently flips such a host to `pac`.
 *
 *  2. A NON-PRIMARY SERVICE IS STILL REPORTED. SCDynamicStoreCopyProxies
 *     returns the primary/current service's settings at the top level and
 *     puts every other service under __SCOPED__. The pre-migration leg asked
 *     for the Wi-Fi service BY NAME, so reading only the top level is not a
 *     superset of it: an Ethernet-primary Mac with the proxy configured on
 *     Wi-Fi went from `proxy_type|http` to `proxy_type|none`. Callers pass the
 *     top-level config first, then each scoped service, so the primary still
 *     wins when it has one and a scoped service is consulted only otherwise.
 *
 * Selection is first-match over the ordered list; the caller owns the order.
 */
inline ProxySelection select_proxy(const std::vector<ProxyServiceConfig>& candidates) {
    for (const auto& c : candidates) {
        if (c.http_enabled && !c.http_host.empty()) {
            return {true, "http", c.http_host + ":" + std::to_string(c.http_port)};
        }
        if (c.pac_enabled && !c.pac_url.empty()) {
            return {true, "pac", c.pac_url};
        }
    }
    return {};
}

/**
 * CIDR prefix length (count of leading 1-bits) of a HOST-byte-order IPv4
 * netmask — 0.0.0.0 -> 0, 255.255.255.0 -> 24, 255.255.255.255 -> 32. Pure.
 *
 * Replaces the old macOS `ip_addresses` leg's raw hex netmask ("0xffffff00")
 * with the same prefix-length shape the Linux leg already emits (PKG-NC fix
 * round: a deliberate cross-platform consistency fix, not an oversight --
 * dashboard-side parsers have broken on exactly this shape mismatch before
 * (#3346), so it is called out explicitly here and at the emit site).
 *
 * A malformed/non-contiguous mask (not a real netmask) still returns a
 * numeric count of leading 1-bits rather than crashing — real netmasks are
 * always contiguous from the MSB, so this is exact for every value a kernel
 * actually hands back; a non-contiguous input is a kernel/driver bug this
 * function does not attempt to detect.
 */
inline unsigned int ipv4_prefix_length(std::uint32_t host_order_mask) {
    unsigned int prefix = 0;
    while (host_order_mask & 0x80000000u) {
        ++prefix;
        host_order_mask <<= 1;
    }
    return prefix;
}

/**
 * Count of LEADING 1-bits in a 16-byte IPv6 netmask, in on-wire (network)
 * byte order — a byte array has no host/network distinction, so no
 * conversion is needed before calling this (unlike ipv4_prefix_length's
 * host-order `uint32_t`).
 *
 * "Leading" is literal: the walk stops at the first byte that is not 0xFF,
 * after counting that byte's own leading run. An earlier version summed each
 * byte's run independently, which returned 16 for a non-contiguous mask like
 * ff:00:ff:… where the IPv4 function would correctly return 8. Real netmasks
 * are contiguous so no shipped host could tell the difference, but the two
 * functions now agree by construction rather than by luck.
 */
inline unsigned int ipv6_prefix_length(const unsigned char (&mask)[16]) {
    unsigned int prefix = 0;
    for (unsigned char byte : mask) {
        const bool full = (byte == 0xFF);
        while (byte & 0x80) {
            ++prefix;
            byte <<= 1;
        }
        if (!full)
            break; // stop at the first non-0xFF byte — see the note above
    }
    return prefix;
}

#if defined(__linux__)

// ── rtnetlink message-set -> records (Linux adapters/ip_addresses legs) ──

struct RtLinkRecord {
    int index = -1;
    std::string name;
    std::string mac; // empty when unresolved/non-Ethernet
    bool up = false; // IFF_UP — ADMINISTRATIVE state (link is configured up)
    // IFLA_OPERSTATE — RFC 2863 OPERATIONAL state, or -1 when the kernel did
    // not attach the attribute. These are NOT the same thing: a cable-unplugged
    // NIC is administratively up (IFF_UP) but operationally down
    // (IF_OPER_LOWERLAYERDOWN), and `ip link` prints the operational one.
    int oper_state = -1;
};

/// Map a link record to the `adapter|...|<status>` field exactly as the
/// pre-migration `ip -o link show` parse did.
///
/// The old leg read iproute2's `state <TOKEN>` field — which iproute2 renders
/// from IFLA_OPERSTATE, not from IFF_UP — and normalised "UP" to "up" and
/// EVERY other token ("DOWN", "UNKNOWN", "LOWERLAYERDOWN", "DORMANT", ...) to
/// "down". Reporting IFF_UP here instead would silently flip a carrier-down
/// NIC and every tun/tap/WireGuard device (which sit at IF_OPER_UNKNOWN) from
/// "down" to "up", so operational state is what this returns.
///
/// When the kernel omits IFLA_OPERSTATE there is no operational signal at all,
/// and the old leg's `status` variable kept its initialiser, "unknown" — so
/// that is what is returned, rather than the administrative flag or a
/// fabricated "down". In practice the kernel attaches IFLA_OPERSTATE to every
/// RTM_NEWLINK (rtnl_fill_ifinfo), so this branch is defensive; it is written
/// to match the oracle's initialiser exactly rather than to model any
/// particular iproute2 rendering, which this code does not depend on.
inline const char* link_status_string(const RtLinkRecord& rec) {
    if (rec.oper_state < 0)
        return "unknown";
    return rec.oper_state == IF_OPER_UP ? "up" : "down";
}

struct RtAddrRecord {
    int index = -1;
    std::string label; // IFA_LABEL when present, else empty
    std::string address;
    unsigned char prefix_len = 0;
    bool is_ipv6 = false;
};

struct RtRouteRecord {
    std::string gateway; // the default route's gateway, formatted
};


/// One recvmsg()-sized chunk's decode result. `records` accumulates across
/// chunks in the caller's (impure) drain loop; `done`/`error`/`truncated`
/// are per-chunk signals the caller folds into the overall dump outcome.
template <typename RecordT>
struct RtNetlinkParseChunk {
    std::vector<RecordT> records;
    bool done = false;      // NLMSG_DONE observed — the dump is complete
    bool error = false;     // NLMSG_ERROR observed — the kernel refused/failed the dump
    bool truncated = false; // a malformed/short record stopped the walk early
};

using RtLinkParse = RtNetlinkParseChunk<RtLinkRecord>;
using RtAddrParse = RtNetlinkParseChunk<RtAddrRecord>;
using RtRouteParse = RtNetlinkParseChunk<RtRouteRecord>;

/**
 * Decode one RTM_GETLINK dump reply chunk (the bytes of a single recvmsg()
 * call, which for a raw netlink socket always holds a whole number of
 * complete messages). `expected_seq` discards a stale reply left over from
 * a previous dump on the same socket (mirrors net_quality_sampler.cpp's
 * nlmsg_seq echo-check). Every multi-byte struct is memcpy'd into a local,
 * aligned object before any field is read — never a cast dereference of
 * the raw buffer.
 */
inline RtLinkParse parse_rtnetlink_link_chunk(std::span<const unsigned char> blob,
                                              std::uint32_t expected_seq) {
    RtLinkParse out;
    auto len = static_cast<int>(blob.size());
    const auto* h = reinterpret_cast<const struct nlmsghdr*>(blob.data());
    for (; NLMSG_OK(h, len); h = reinterpret_cast<const struct nlmsghdr*>(NLMSG_NEXT(h, len))) {
        // Sequence check FIRST: a stale DONE/ERROR left over from an earlier
        // dump on this socket must be discarded like any other stale reply,
        // not allowed to terminate (or fail) the current walk.
        if (h->nlmsg_seq != expected_seq)
            continue; // stale reply from an earlier dump on this socket
        if (h->nlmsg_type == NLMSG_DONE) {
            out.done = true;
            break;
        }
        if (h->nlmsg_type == NLMSG_ERROR) {
            out.error = true;
            break;
        }
        if (h->nlmsg_type != RTM_NEWLINK)
            continue;
        if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
            // Payload shorter than the fixed ifinfomsg this record must carry
            // — a malformed dump, not a record we can safely skip. Matching
            // agents/shared/route_sysctl_arp.hpp's discipline: flag truncation
            // and stop the walk rather than silently continuing past it and
            // reporting done=true/truncated=false over a smaller result.
            out.truncated = true;
            break;
        }

        struct ifinfomsg ifi {};
        std::memcpy(&ifi, NLMSG_DATA(h), sizeof(ifi));

        RtLinkRecord rec;
        rec.index = ifi.ifi_index;
        rec.up = (ifi.ifi_flags & IFF_UP) != 0;

        int rta_len =
            static_cast<int>(h->nlmsg_len) - static_cast<int>(NLMSG_LENGTH(sizeof(ifi)));
        const auto* rta = reinterpret_cast<const struct rtattr*>(
            static_cast<const unsigned char*>(NLMSG_DATA(h)) + NLMSG_ALIGN(sizeof(ifi)));
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            if (rta->rta_type == IFLA_IFNAME) {
                const auto payload = static_cast<std::size_t>(RTA_PAYLOAD(rta));
                if (payload == 0)
                    continue;
                const auto* data = static_cast<const char*>(RTA_DATA(rta));
                // NUL-bounded by the attribute's own declared payload --
                // never trust the kernel to have NUL-terminated within it.
                std::size_t name_len = 0;
                while (name_len < payload && data[name_len] != '\0')
                    ++name_len;
                rec.name.assign(data, name_len);
            } else if (rta->rta_type == IFLA_ADDRESS) {
                const auto payload = static_cast<std::size_t>(RTA_PAYLOAD(rta));
                // EXACTLY 6, never ">= 6 then truncate": a non-Ethernet link
                // (InfiniBand's 20-byte address, ip6tnl, ...) must come back
                // unresolved, matching both the old leg — which only read a
                // MAC from iproute2's `link/ether ` prefix — and format_mac's
                // own contract ("never a fabricated MAC"). Truncating here
                // would defeat that guard by pre-shortening its input.
                if (payload == 6) {
                    unsigned char mac[6];
                    std::memcpy(mac, RTA_DATA(rta), 6);
                    rec.mac = format_mac(mac, 6);
                }
            } else if (rta->rta_type == IFLA_OPERSTATE) {
                if (static_cast<std::size_t>(RTA_PAYLOAD(rta)) >= 1) {
                    unsigned char st = 0;
                    std::memcpy(&st, RTA_DATA(rta), 1);
                    rec.oper_state = static_cast<int>(st);
                }
            }
        }
        if (!rec.name.empty())
            out.records.push_back(std::move(rec));
    }
    if (!out.done && !out.error && len > 0)
        out.truncated = true; // trailing bytes that never formed a whole message
    return out;
}

/**
 * Decode one RTM_GETADDR dump reply chunk. Prefers IFA_LOCAL (the actually
 * -configured address) over IFA_ADDRESS (the peer address on a
 * point-to-point link) when both are present, matching `ip addr show`'s
 * own "inet" line. Same bounds-checking/memcpy discipline as the link
 * decoder above.
 */
inline RtAddrParse parse_rtnetlink_addr_chunk(std::span<const unsigned char> blob,
                                              std::uint32_t expected_seq) {
    RtAddrParse out;
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
        if (h->nlmsg_type != RTM_NEWADDR)
            continue;
        if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifaddrmsg))) {
            // See parse_rtnetlink_link_chunk()'s identical short-payload guard.
            out.truncated = true;
            break;
        }

        struct ifaddrmsg ifa {};
        std::memcpy(&ifa, NLMSG_DATA(h), sizeof(ifa));
        if (ifa.ifa_family != AF_INET && ifa.ifa_family != AF_INET6)
            continue;

        RtAddrRecord rec;
        rec.index = static_cast<int>(ifa.ifa_index);
        rec.prefix_len = ifa.ifa_prefixlen;
        rec.is_ipv6 = (ifa.ifa_family == AF_INET6);

        int rta_len =
            static_cast<int>(h->nlmsg_len) - static_cast<int>(NLMSG_LENGTH(sizeof(ifa)));
        const auto* rta = reinterpret_cast<const struct rtattr*>(
            static_cast<const unsigned char*>(NLMSG_DATA(h)) + NLMSG_ALIGN(sizeof(ifa)));
        std::string preferred_addr; // IFA_ADDRESS
        std::string local_addr;     // IFA_LOCAL
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            if (rta->rta_type == IFA_LABEL) {
                const auto payload = static_cast<std::size_t>(RTA_PAYLOAD(rta));
                if (payload == 0)
                    continue;
                const auto* data = static_cast<const char*>(RTA_DATA(rta));
                std::size_t name_len = 0;
                while (name_len < payload && data[name_len] != '\0')
                    ++name_len;
                rec.label.assign(data, name_len);
            } else if (rta->rta_type == IFA_ADDRESS || rta->rta_type == IFA_LOCAL) {
                const std::size_t want = ifa.ifa_family == AF_INET6 ? 16u : 4u;
                if (static_cast<std::size_t>(RTA_PAYLOAD(rta)) < want)
                    continue;
                unsigned char addr_bytes[16]{};
                std::memcpy(addr_bytes, RTA_DATA(rta), want);
                char text[INET6_ADDRSTRLEN]{};
                if (::inet_ntop(ifa.ifa_family, addr_bytes, text, sizeof(text))) {
                    if (rta->rta_type == IFA_LOCAL)
                        local_addr = text;
                    else
                        preferred_addr = text;
                }
            }
        }
        rec.address = !local_addr.empty() ? local_addr : preferred_addr;
        if (!rec.address.empty())
            out.records.push_back(std::move(rec));
    }
    if (!out.done && !out.error && len > 0)
        out.truncated = true;
    return out;
}

/**
 * Decode one RTM_GETROUTE dump reply chunk, keeping only IPv4 default
 * routes (rtm_dst_len == 0, an RTA_GATEWAY attribute present) — the same
 * single value the old `ip route show default | via` parse extracted.
 * Multiple default routes (multi-homed hosts) may each yield a record; the
 * caller takes the first.
 */
inline RtRouteParse parse_rtnetlink_route_chunk(std::span<const unsigned char> blob,
                                                std::uint32_t expected_seq) {
    RtRouteParse out;
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
            // See parse_rtnetlink_link_chunk()'s identical short-payload guard.
            out.truncated = true;
            break;
        }

        struct rtmsg rtm {};
        std::memcpy(&rtm, NLMSG_DATA(h), sizeof(rtm));
        if (rtm.rtm_family != AF_INET || rtm.rtm_dst_len != 0)
            continue; // not an IPv4 default route

        int rta_len =
            static_cast<int>(h->nlmsg_len) - static_cast<int>(NLMSG_LENGTH(sizeof(rtm)));
        const auto* rta = reinterpret_cast<const struct rtattr*>(
            static_cast<const unsigned char*>(NLMSG_DATA(h)) + NLMSG_ALIGN(sizeof(rtm)));
        std::string gw;
        // rtm_table is only 8 bits, so a table id above 255 is carried in an
        // RTA_TABLE attribute and rtm_table holds RT_TABLE_UNSPEC/COMPAT
        // instead. RTA_TABLE therefore OVERRIDES rtm_table when present.
        std::uint32_t table = rtm.rtm_table;
        bool saw_nexthop_form = false;
        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
            if (rta->rta_type == RTA_GATEWAY && RTA_PAYLOAD(rta) >= 4) {
                unsigned char addr_bytes[4]{};
                std::memcpy(addr_bytes, RTA_DATA(rta), 4);
                char text[INET_ADDRSTRLEN]{};
                if (::inet_ntop(AF_INET, addr_bytes, text, sizeof(text)))
                    gw = text;
            } else if (rta->rta_type == RTA_MULTIPATH) {
                // An ECMP / multi-uplink default route carries NO top-level
                // RTA_GATEWAY: each nexthop sits in an rtnexthop array with
                // its own. The pre-migration leg searched the whole
                // `ip route show default` blob for "via ", which matched the
                // first `nexthop via …` line, so those hosts DID report a
                // gateway. Decoding only RTA_GATEWAY would silently regress
                // every ECMP host to "-". Take the first nexthop's gateway,
                // matching the oracle's first-match behaviour.
                saw_nexthop_form = true;
                int nh_len = static_cast<int>(RTA_PAYLOAD(rta));
                const auto* nh = static_cast<const struct rtnexthop*>(RTA_DATA(rta));
                while (gw.empty() && RTNH_OK(nh, nh_len)) {
                    int sub_len = static_cast<int>(nh->rtnh_len) -
                                  static_cast<int>(sizeof(struct rtnexthop));
                    if (sub_len > 0) {
                        const auto* sub = reinterpret_cast<const struct rtattr*>(
                            reinterpret_cast<const unsigned char*>(nh) +
                            NLMSG_ALIGN(sizeof(struct rtnexthop)));
                        for (; RTA_OK(sub, sub_len); sub = RTA_NEXT(sub, sub_len)) {
                            if (sub->rta_type == RTA_GATEWAY && RTA_PAYLOAD(sub) >= 4) {
                                unsigned char nb[4]{};
                                std::memcpy(nb, RTA_DATA(sub), 4);
                                char ntext[INET_ADDRSTRLEN]{};
                                if (::inet_ntop(AF_INET, nb, ntext, sizeof(ntext)))
                                    gw = ntext;
                                break;
                            }
                        }
                    }
                    // RTNH_NEXT, unlike RTA_NEXT, is single-argument and does
                    // NOT decrement a length variable as a side effect -- the
                    // caller must. Without this, RTNH_OK's bound check on
                    // every nexthop after the first compares against the
                    // ORIGINAL total length rather than what is actually
                    // left, so a crafted rtnh_len on a later nexthop can pass
                    // the check while pointing past the real payload -- an
                    // out-of-bounds read, not merely an unfuzzed code path.
                    const int consumed = RTNH_ALIGN(nh->rtnh_len);
                    nh = RTNH_NEXT(nh);
                    nh_len -= consumed;
                }
            } else if (rta->rta_type == RTA_NH_ID) {
                // An `ip nexthop`-object route references a nexthop group by
                // id; resolving it needs a separate RTM_GETNEXTHOP dump this
                // leg does not perform. Flag it so the caller degrades
                // honestly instead of claiming there is no gateway.
                saw_nexthop_form = true;
            } else if (rta->rta_type == RTA_TABLE &&
                       static_cast<std::size_t>(RTA_PAYLOAD(rta)) >= sizeof(std::uint32_t)) {
                std::uint32_t t = 0;
                std::memcpy(&t, RTA_DATA(rta), sizeof(t));
                table = t;
            }
        }
        // MAIN TABLE ONLY. An NLM_F_DUMP RTM_GETROUTE returns default routes
        // from EVERY routing table, and the kernel emits non-main tables
        // FIRST — so without this filter the caller's records.front() does
        // not merely risk the wrong gateway, it actively prefers it. The
        // pre-migration leg ran unqualified `ip route show default`, which
        // shows the main table alone. Any host running WireGuard/wg-quick,
        // Tailscale, strongSwan or systemd-networkd RoutingPolicyRule has a
        // second table, and every emitted ip| row would otherwise carry that
        // tunnel's gateway. Verified against a live kernel: with
        // `ip route add default via 172.17.0.99 table 100` alongside main's
        // 172.17.0.1, the unfiltered dump returned the table-100 route first.
        if (table != RT_TABLE_MAIN)
            continue;
        // A main-table default route in a nexthop form this parser cannot
        // resolve (an `ip nexthop` object, or a multipath array carrying no
        // IPv4 RTA_GATEWAY) is pushed with an EMPTY gateway. The caller takes
        // the first non-empty one and, finding none, reports a degraded read
        // instead of the positive claim "this host has no default gateway".
        if (!gw.empty() || saw_nexthop_form) {
            RtRouteRecord rec;
            rec.gateway = std::move(gw);
            out.records.push_back(std::move(rec));
        }
    }
    if (!out.done && !out.error && len > 0)
        out.truncated = true;
    return out;
}

#endif // __linux__

#if defined(__APPLE__)

// ── PF_ROUTE sysctl blob -> default-gateway record (macOS ip_addresses) ──

struct DefaultRouteParse {
    std::string gateway; // empty when no default route was found
    bool found = false;
    bool truncated = false;
};

/**
 * Parse a NET_RT_DUMP/AF_INET routing-table blob into the default route's
 * gateway address, if any. Pure — no I/O. Walk/bounds-check discipline is
 * the SAME as agents/shared/route_sysctl_arp.hpp's parse_rt_flags_llinfo:
 * every rtm_msglen is checked against the remaining buffer before use, an
 * unrecognised rtm_version stops the walk (Apple has changed routing-socket
 * layout across releases with no ABI promise), every sockaddr's sa_len is
 * bounds-checked before its bytes are read, the ROUNDUP unit is the fixed
 * 4-byte routing-socket alignment (NOT sizeof(long)), and every multi-byte
 * field is memcpy'd into a local aligned object — never a cast dereference
 * of the raw blob. Any malformation stops the walk and sets `truncated`
 * rather than looping or reading out of bounds.
 *
 * A route is the default route when its family is AF_INET, its RTAX_DST
 * entry (if present at all) decodes to 0.0.0.0, and it carries an
 * RTF_GATEWAY-flagged AF_INET RTAX_GATEWAY entry. Only the first such
 * route found is kept (multiple default routes on a multi-homed host are
 * possible; the old `route -n get default` shell-out also only ever
 * reported one).
 */
inline DefaultRouteParse parse_default_route_dump(std::span<const unsigned char> blob) {
    DefaultRouteParse out;
    std::size_t off = 0;

    while (off + sizeof(rt_msghdr) <= blob.size()) {
        rt_msghdr hdr{};
        std::memcpy(&hdr, blob.data() + off, sizeof(hdr));

        if (hdr.rtm_msglen == 0) {
            out.truncated = true;
            break;
        }
        if (hdr.rtm_msglen < sizeof(rt_msghdr)) {
            out.truncated = true;
            break;
        }
        if (off + hdr.rtm_msglen > blob.size()) {
            out.truncated = true;
            break;
        }
        if (hdr.rtm_version != RTM_VERSION) {
            out.truncated = true;
            break;
        }

        const unsigned char* rec_end = blob.data() + off + hdr.rtm_msglen;
        const unsigned char* p = blob.data() + off + sizeof(rt_msghdr);

        std::string dst;
        std::string gw;
        bool dst_present = false;

        for (int i = 0; i < RTAX_MAX && p < rec_end; ++i) {
            if (!(hdr.rtm_addrs & (1 << i)))
                continue;

            const std::size_t remaining = static_cast<std::size_t>(rec_end - p);
            if (remaining < 2)
                break; // this record's address chain ends here — not an overrun

            const unsigned char sa_len = p[0];
            const unsigned char sa_family = p[1];
            constexpr std::size_t kRoutingSockaddrAlign = sizeof(std::uint32_t);
            const std::size_t entry_len = sa_len ? sa_len : kRoutingSockaddrAlign;
            if (remaining < entry_len) {
                // This sockaddr claims more than the record has left — an
                // overrun, not a normal chain end. Mark the whole parse
                // truncated (matching route_sysctl_arp.hpp's ArpParse
                // contract) but keep walking subsequent records: whatever
                // dst/gw this record already decoded before the overrun is
                // still individually valid, and the outer loop's own
                // off/rtm_msglen bookkeeping is unaffected by an inner
                // sockaddr-chain malformation.
                out.truncated = true;
                break;
            }

            if (i == RTAX_DST) {
                dst_present = true;
                if (sa_len == 0) {
                    dst = "0.0.0.0"; // a zero-length sockaddr IS the all-zero encoding
                } else if (sa_family == AF_INET && sa_len >= sizeof(struct sockaddr_in)) {
                    struct sockaddr_in sin {};
                    std::memcpy(&sin, p, sizeof(sin));
                    char buf4[INET_ADDRSTRLEN]{};
                    if (::inet_ntop(AF_INET, &sin.sin_addr, buf4, sizeof(buf4)))
                        dst = buf4;
                }
            } else if (i == RTAX_GATEWAY && sa_family == AF_INET &&
                       sa_len >= sizeof(struct sockaddr_in)) {
                struct sockaddr_in sin {};
                std::memcpy(&sin, p, sizeof(sin));
                char buf4[INET_ADDRSTRLEN]{};
                if (::inet_ntop(AF_INET, &sin.sin_addr, buf4, sizeof(buf4)))
                    gw = buf4;
            }

            std::size_t adv = entry_len;
            adv = (adv + kRoutingSockaddrAlign - 1) & ~(kRoutingSockaddrAlign - 1);
            if (adv > remaining) {
                out.truncated = true; // same overrun, discovered after rounding
                break;
            }
            p += adv;
        }

        if (!out.found && (hdr.rtm_flags & RTF_GATEWAY) && !gw.empty() &&
            (!dst_present || dst == "0.0.0.0")) {
            out.gateway = gw;
            out.found = true;
        }

        off += hdr.rtm_msglen;
    }

    if (off < blob.size())
        out.truncated = true;

    return out;
}

#endif // __APPLE__

} // namespace yuzu::network_config
