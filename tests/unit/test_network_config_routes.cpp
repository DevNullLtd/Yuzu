/**
 * test_network_config_routes.cpp — network_config_routes_parsers.hpp (Wave 11
 * PR11.2-a, the `routes` action on network_config).
 *
 * The row formatter tests run on every host. The rtnetlink decoder tests are
 * Linux-only (`#if defined(__linux__)`) and the PF_ROUTE decoder tests are
 * macOS-only (`#if defined(__APPLE__)`) — the same platform-gated-TU shape as
 * test_network_config_parsers.cpp.
 *
 * Every positive expectation comes from a REAL CAPTURE under
 * tests/unit/fixtures/wave11/network_config_routes/<os>/, with the OS's own
 * rendering of the same table (iproute2 / netstat) quoted as ground truth in the
 * sibling `.provenance.txt`. The expected rows below are hand-derived from that
 * ground truth, never from this decoder's output. The synthetic messages build
 * ONLY the malformed / adversarial shapes a real kernel never emits (short
 * attributes, an out-of-range prefix length, a crafted rtnh_len, a truncated
 * datagram) — the cases where a hand-built packed struct is the point.
 */
#include "network_config_routes_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#ifndef YUZU_TEST_FIXTURE_DIR
#define YUZU_TEST_FIXTURE_DIR "tests/unit/fixtures"
#endif

using namespace yuzu::network_config;

namespace fs = std::filesystem;

namespace {

fs::path fixture_dir(const char* os) {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "wave11" / "network_config_routes" / os;
}

// One hex line per recv() datagram / blob, chunk boundaries preserved. std::vector storage
// is aligned well past NLMSG_ALIGNTO, which the rtnetlink decoder requires.
std::vector<std::vector<unsigned char>> read_hex_lines(const fs::path& p) {
    REQUIRE(fs::exists(p));
    std::ifstream f(p);
    std::vector<std::vector<unsigned char>> out;
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
            line.pop_back();
        if (line.empty())
            continue;
        REQUIRE(line.size() % 2 == 0);
        std::vector<unsigned char> bytes;
        for (std::size_t i = 0; i < line.size(); i += 2)
            bytes.push_back(static_cast<unsigned char>(std::stoi(line.substr(i, 2), nullptr, 16)));
        out.push_back(std::move(bytes));
    }
    return out;
}

} // namespace

// ── Row formatter (portable) ──────────────────────────────────────────────

TEST_CASE("format_route_row renders the ten-field row", "[network_config][routes]") {
    RouteRow r;
    r.ipv6 = false;
    r.destination = "192.0.2.0";
    r.prefix_len = 24;
    r.gateway = "10.77.0.1";
    r.interface = "dummy0";
    r.metric = "50";
    r.table = "main";
    r.type = "unicast";
    r.origin = "static";
    CHECK(format_route_row(r) == "route|ipv4|192.0.2.0|24|10.77.0.1|dummy0|50|main|unicast|static");

    r.ipv6 = true;
    r.destination = "2001:db8:1::";
    r.prefix_len = 48;
    CHECK(format_route_row(r).starts_with("route|ipv6|2001:db8:1::|48|"));
}

TEST_CASE("format_route_row renders an on-link, nameless route with dashes",
          "[network_config][routes]") {
    RouteRow r;
    r.destination = "203.0.113.0";
    r.prefix_len = 26;
    r.type = "blackhole";
    r.origin = "boot";
    // gateway and interface empty -> `-`; metric and table keep their `-` defaults.
    CHECK(format_route_row(r) == "route|ipv4|203.0.113.0|26|-|-|-|-|blackhole|boot");
}

TEST_CASE("format_route_row cannot be split by an interface name containing the delimiter",
          "[network_config][routes]") {
    // A Linux interface name may legally contain '|', and a kernel-supplied name
    // must never add a field or a line to the row.
    RouteRow r;
    r.destination = "10.0.0.0";
    r.prefix_len = 8;
    r.interface = "ev|il\nname\\x";
    const std::string row = format_route_row(r);
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row == "route|ipv4|10.0.0.0|8|-|ev\\|il name/x|-|-|unicast|-");
}


// ── Windows mapping (portable: pure logic over a plain struct) ────────────
//
// The GetIpForwardTable2 call itself is the Windows-only shell and is verified live
// on the-rig; everything decidable without Windows headers is tested here, on every
// host, against a real capture of that table.

namespace {

// Mirrors the leg's own unpacking of a row: an unspecified next hop (0.0.0.0 / ::) is
// on-link and becomes empty.
std::vector<WinRoute> read_windows_fixture(const fs::path& p) {
    REQUIRE(fs::exists(p));
    std::ifstream f(p);
    std::vector<WinRoute> out;
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty() || line.front() == '#')
            continue;
        std::vector<std::string> c;
        std::size_t start = 0;
        for (std::size_t i = 0; i <= line.size(); ++i) {
            if (i == line.size() || line[i] == '\t') {
                c.push_back(line.substr(start, i - start));
                start = i + 1;
            }
        }
        REQUIRE(c.size() == 9);
        WinRoute r;
        r.ipv6 = c[0] == "ipv6";
        r.destination = c[1];
        r.prefix_len = static_cast<unsigned>(std::stoul(c[2]));
        r.next_hop = (c[3] == "0.0.0.0" || c[3] == "::") ? std::string{} : c[3];
        r.interface = c[4];
        r.metric = std::stoul(c[6]);
        r.protocol = std::stoi(c[7]);
        out.push_back(std::move(r));
    }
    return out;
}

} // namespace

TEST_CASE("windows routes from a real GetIpForwardTable2 capture keep reachability and drop the host's own",
          "[network_config][routes][windows_map]") {
    const auto table = read_windows_fixture(fixture_dir("windows") / "forward_table.tsv");
    REQUIRE(table.size() == 41);

    std::vector<std::string> rows;
    for (const auto& r : table)
        if (!win_route_is_host_local(r))
            rows.push_back(format_route_row(win_route_to_row(r)));

    // Hand-checked against the Get-NetRoute ground truth in the provenance file.
    const std::vector<std::string> expected{
        "route|ipv4|0.0.0.0|0|192.0.2.1|Ethernet|0|-|unicast|netmgmt",
        "route|ipv4|100.64.0.12|32|-|Tailscale|0|-|unicast|netmgmt",
        "route|ipv4|100.100.100.100|32|-|Tailscale|0|-|unicast|netmgmt",
        "route|ipv4|100.64.0.77|32|-|Tailscale|0|-|unicast|netmgmt",
        "route|ipv4|100.64.0.43|32|-|Tailscale|0|-|unicast|netmgmt",
        "route|ipv4|127.0.0.0|8|-|Loopback Pseudo-Interface 1|256|-|unicast|local",
        "route|ipv4|192.0.2.0|24|-|Ethernet|256|-|unicast|local",
        "route|ipv6|fd7a:115c:a1e0::|48|fd7a:115c:a1e0::53|Tailscale|0|-|unicast|netmgmt",
        "route|ipv6|fd7a:115c:a1e0::53|128|-|Tailscale|0|-|unicast|netmgmt",
        "route|ipv6|fe80::|64|-|VPN Adapter|256|-|unicast|local",
        "route|ipv6|fe80::|64|-|Local Area Connection|256|-|unicast|local",
        "route|ipv6|fe80::|64|-|Ethernet 2|256|-|unicast|local",
        "route|ipv6|fe80::|64|-|Ethernet|256|-|unicast|local",
        "route|ipv6|fe80::|64|-|Bluetooth Network Connection|256|-|unicast|local",
        "route|ipv6|fe80::|64|-|WiFi|256|-|unicast|local",
        "route|ipv6|fe80::|64|-|Local Area Connection* 1|256|-|unicast|local",
        "route|ipv6|fe80::|64|-|Local Area Connection* 2|256|-|unicast|local",
    };
    REQUIRE(rows.size() == expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i)
        CHECK(rows[i] == expected[i]);
}

TEST_CASE("windows host-local rule: Local full-length and multicast are dropped, the rest kept",
          "[network_config][routes][windows_map]") {
    auto route = [](bool v6, const char* dst, unsigned plen, int proto) {
        WinRoute r;
        r.ipv6 = v6;
        r.destination = dst;
        r.prefix_len = plen;
        r.protocol = proto;
        return r;
    };
    // Dropped: own address / broadcast (Local + /32 or /128), multicast prefixes.
    CHECK(win_route_is_host_local(route(false, "192.0.2.131", 32, 2)));
    CHECK(win_route_is_host_local(route(false, "192.0.2.255", 32, 2)));
    CHECK(win_route_is_host_local(route(false, "255.255.255.255", 32, 2)));
    CHECK(win_route_is_host_local(route(false, "224.0.0.0", 4, 2)));
    CHECK(win_route_is_host_local(route(false, "239.255.255.250", 32, 3))); // multicast wins over protocol
    CHECK(win_route_is_host_local(route(true, "::1", 128, 2)));
    CHECK(win_route_is_host_local(route(true, "fe80::200:5eff:fe00:5301", 128, 2)));
    CHECK(win_route_is_host_local(route(true, "ff00::", 8, 2)));
    // Kept: the connected-subnet routes, and any non-Local full-length route.
    CHECK_FALSE(win_route_is_host_local(route(false, "192.0.2.0", 24, 2)));
    CHECK_FALSE(win_route_is_host_local(route(false, "127.0.0.0", 8, 2)));
    CHECK_FALSE(win_route_is_host_local(route(true, "fe80::", 64, 2)));
    CHECK_FALSE(win_route_is_host_local(route(false, "100.64.0.12", 32, 3))); // NetMgmt peer route
    CHECK_FALSE(win_route_is_host_local(route(true, "fd7a:115c:a1e0::53", 128, 3)));
    CHECK_FALSE(win_route_is_host_local(route(false, "0.0.0.0", 0, 3)));      // default route
    CHECK_FALSE(win_route_is_host_local(route(false, "223.255.255.255", 32, 3))); // just below multicast
    CHECK_FALSE(win_route_is_host_local(route(true, "fd00::", 8, 3)));        // 'f' but not ff
}

TEST_CASE("windows protocol names cover NL_ROUTE_PROTOCOL and fall back to a numbered token",
          "[network_config][routes][windows_map]") {
    CHECK(win_protocol_name(2) == "local");
    CHECK(win_protocol_name(3) == "netmgmt");
    CHECK(win_protocol_name(13) == "ospf");
    CHECK(win_protocol_name(14) == "bgp");
    CHECK(win_protocol_name(19) == "dhcp");
    CHECK(win_protocol_name(10006) == "static");
    CHECK(win_protocol_name(777) == "proto777");
}

TEST_CASE("windows row keeps the route metric and renders an on-link next hop as a dash",
          "[network_config][routes][windows_map]") {
    WinRoute r;
    r.destination = "198.51.100.0";
    r.prefix_len = 24;
    r.interface = "Ethernet";
    r.metric = 281;
    r.protocol = 3;
    CHECK(format_route_row(win_route_to_row(r)) ==
          "route|ipv4|198.51.100.0|24|-|Ethernet|281|-|unicast|netmgmt");
    r.next_hop = "198.51.100.1";
    CHECK(format_route_row(win_route_to_row(r)).starts_with("route|ipv4|198.51.100.0|24|198.51.100.1|"));
}

#if defined(__linux__)

#include <cstring>

namespace {

const std::map<int, std::string>& capture_interfaces() {
    // From the capture host: lo = 1, eth0 = 11 (Docker bridge veth), dummy0 = 12.
    static const std::map<int, std::string> m{{1, "lo"}, {11, "eth0"}, {12, "dummy0"}};
    return m;
}

std::string iface(int idx) {
    const auto it = capture_interfaces().find(idx);
    return it == capture_interfaces().end() ? std::string{} : it->second;
}

struct Decoded {
    std::vector<RtRouteFull> records;
    bool done = false;
    bool error = false;
    bool truncated = false;
};

Decoded decode_all(const std::vector<std::vector<unsigned char>>& datagrams, std::uint32_t seq) {
    Decoded d;
    for (const auto& dg : datagrams) {
        auto chunk = parse_rtnetlink_routes_chunk(dg, seq);
        d.records.insert(d.records.end(), chunk.records.begin(), chunk.records.end());
        d.done = d.done || chunk.done;
        d.error = d.error || chunk.error;
        d.truncated = d.truncated || chunk.truncated;
    }
    return d;
}

// ── synthetic builders: ONLY for shapes a real kernel never emits ─────────

struct Attr {
    unsigned short type;
    std::vector<unsigned char> data;
};

std::vector<unsigned char> u32(std::uint32_t v) {
    std::vector<unsigned char> b(sizeof(v));
    std::memcpy(b.data(), &v, sizeof(v));
    return b;
}

void append_bytes(std::vector<unsigned char>& buf, const void* data, std::size_t n) {
    const auto* p = static_cast<const unsigned char*>(data);
    buf.insert(buf.end(), p, p + n);
}

void append_attr(std::vector<unsigned char>& buf, const Attr& a) {
    struct rtattr rta {};
    rta.rta_len = static_cast<unsigned short>(RTA_LENGTH(a.data.size()));
    rta.rta_type = a.type;
    append_bytes(buf, &rta, sizeof(rta));
    append_bytes(buf, a.data.data(), a.data.size());
    while (buf.size() % RTA_ALIGNTO != 0)
        buf.push_back(0);
}

std::vector<unsigned char> route_msg(std::uint32_t seq, unsigned char family,
                                     unsigned char dst_len, unsigned char table,
                                     unsigned char type, unsigned char proto, unsigned flags,
                                     const std::vector<Attr>& attrs) {
    std::vector<unsigned char> buf;
    struct nlmsghdr nlh {};
    nlh.nlmsg_type = RTM_NEWROUTE;
    nlh.nlmsg_flags = NLM_F_MULTI;
    nlh.nlmsg_seq = seq;
    append_bytes(buf, &nlh, sizeof(nlh));
    struct rtmsg rtm {};
    rtm.rtm_family = family;
    rtm.rtm_dst_len = dst_len;
    rtm.rtm_table = table;
    rtm.rtm_type = type;
    rtm.rtm_protocol = proto;
    rtm.rtm_flags = flags;
    append_bytes(buf, &rtm, sizeof(rtm));
    for (const auto& a : attrs)
        append_attr(buf, a);
    reinterpret_cast<struct nlmsghdr*>(buf.data())->nlmsg_len =
        static_cast<std::uint32_t>(buf.size());
    return buf;
}

std::vector<unsigned char> v4(unsigned char a, unsigned char b, unsigned char c, unsigned char d) {
    return {a, b, c, d};
}

std::vector<unsigned char> control_msg(std::uint32_t seq, unsigned short type) {
    std::vector<unsigned char> buf;
    struct nlmsghdr nlh {};
    nlh.nlmsg_type = type;
    nlh.nlmsg_seq = seq;
    nlh.nlmsg_len = sizeof(nlh);
    append_bytes(buf, &nlh, sizeof(nlh));
    return buf;
}

} // namespace

// ── The real capture ──────────────────────────────────────────────────────

TEST_CASE("routes decode of a real RTM_GETROUTE AF_UNSPEC dump matches iproute2's table",
          "[network_config][routes][rtnetlink]") {
    const auto datagrams = read_hex_lines(fixture_dir("linux") / "rtm_getroute_dump.hex");
    REQUIRE(datagrams.size() == 2);

    const auto d = decode_all(datagrams, 3);
    CHECK(d.done);
    CHECK_FALSE(d.error);
    CHECK_FALSE(d.truncated); // a clean, complete real dump must not look malformed

    std::vector<std::string> rows;
    for (const auto& rec : d.records)
        rows.push_back(format_route_row(linux_route_to_row(rec, iface(rec.ifindex))));

    // Hand-derived from the `ip -d route show table all` ground truth in the
    // provenance file, in kernel dump order. The 11 table-255 (local) routes the
    // kernel also sent are absent by design.
    const std::vector<std::string> expected{
        "route|ipv4|0.0.0.0|0|10.77.0.1|dummy0|0|100|unicast|boot",
        "route|ipv4|203.0.113.192|26|-|-|0|100|throw|boot",
        "route|ipv4|0.0.0.0|0|172.17.0.1|eth0|0|main|unicast|boot",
        "route|ipv4|10.77.0.0|24|-|dummy0|0|main|unicast|kernel",
        "route|ipv4|10.88.0.0|16|fd00:77::9|dummy0|0|main|unicast|boot",
        "route|ipv4|172.16.0.0|16|10.77.0.1|dummy0|0|main|unicast|boot",
        "route|ipv4|172.17.0.0|16|-|eth0|0|main|unicast|kernel",
        "route|ipv4|192.0.2.0|24|10.77.0.1|dummy0|50|main|unicast|static",
        "route|ipv4|198.51.100.0|24|-|dummy0|0|main|unicast|boot",
        "route|ipv4|203.0.113.0|26|-|-|0|main|blackhole|boot",
        "route|ipv4|203.0.113.64|26|-|-|0|main|unreachable|boot",
        "route|ipv4|203.0.113.128|26|-|-|0|main|prohibit|boot",
        "route|ipv6|2001:db8:1::|48|fd00:77::1|dummy0|100|main|unicast|boot",
        "route|ipv6|fd00:77::|64|-|dummy0|256|main|unicast|kernel",
        "route|ipv6|fe80::|64|-|dummy0|256|main|unicast|kernel",
        "route|ipv6|::|0|fd00:77::1|dummy0|1024|main|unicast|boot",
    };
    REQUIRE(rows.size() == expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i)
        CHECK(rows[i] == expected[i]);
}

TEST_CASE("routes decode flags the multipath route that was collapsed to its first nexthop",
          "[network_config][routes][rtnetlink]") {
    const auto d = decode_all(read_hex_lines(fixture_dir("linux") / "rtm_getroute_dump.hex"), 3);
    int collapsed = 0;
    for (const auto& rec : d.records) {
        if (rec.multipath_collapsed) {
            ++collapsed;
            // ground truth: 172.16.0.0/16 with two nexthops (10.77.0.1, 10.77.0.3) on dummy0
            CHECK(rec.destination == "172.16.0.0");
            CHECK(rec.gateway == "10.77.0.1");
        }
    }
    CHECK(collapsed == 1); // only that one route; ordinary routes are never flagged
}

TEST_CASE("routes decode ignores replies carrying another sequence number",
          "[network_config][routes][rtnetlink]") {
    const auto d = decode_all(read_hex_lines(fixture_dir("linux") / "rtm_getroute_dump.hex"), 99);
    CHECK(d.records.empty());
    CHECK_FALSE(d.done);
}

TEST_CASE("routes decode reports a datagram cut mid-message as truncated, never as complete",
          "[network_config][routes][rtnetlink]") {
    auto datagrams = read_hex_lines(fixture_dir("linux") / "rtm_getroute_dump.hex");
    datagrams.pop_back(); // no NLMSG_DONE after the cut datagram
    auto& dg = datagrams.front();
    // Cut 10 bytes into the message that follows the first boundary at or past byte 1000:
    // fewer than the 16 bytes of an nlmsghdr, so the final message is unparseable.
    std::size_t off = 0;
    std::size_t boundary = 0;
    while (off + sizeof(struct nlmsghdr) <= dg.size()) {
        std::uint32_t len = 0;
        std::memcpy(&len, dg.data() + off, sizeof(len));
        off += NLMSG_ALIGN(len);
        if (off >= 1000) {
            boundary = off;
            break;
        }
    }
    REQUIRE(boundary > 0);
    REQUIRE(boundary + 10 < dg.size());
    dg.resize(boundary + 10);

    const auto d = decode_all(datagrams, 3);
    CHECK(d.truncated);
    CHECK_FALSE(d.done);
    CHECK(d.records.size() < 16); // fewer than the 16 of the complete dump: nothing after the cut
    CHECK_FALSE(d.records.empty());
    for (const auto& rec : d.records)
        CHECK_FALSE(rec.destination.empty());
}

// ── Adversarial / malformed shapes ────────────────────────────────────────

TEST_CASE("routes decode lets RTA_TABLE override the 8-bit rtm_table",
          "[network_config][routes][rtnetlink]") {
    constexpr std::uint32_t kSeq = 7;
    // rtm_table = RT_TABLE_COMPAT (252) with the real id in RTA_TABLE.
    auto a = route_msg(kSeq, AF_INET, 8, RT_TABLE_COMPAT, RTN_UNICAST, 3, 0,
                       {{RTA_DST, v4(10, 0, 0, 0)}, {RTA_TABLE, u32(100)}});
    // rtm_table says main but RTA_TABLE says local: the override must win and skip it.
    auto b = route_msg(kSeq, AF_INET, 8, RT_TABLE_MAIN, RTN_UNICAST, 3, 0,
                       {{RTA_DST, v4(11, 0, 0, 0)}, {RTA_TABLE, u32(RT_TABLE_LOCAL)}});
    std::vector<unsigned char> chunk = a;
    chunk.insert(chunk.end(), b.begin(), b.end());
    const auto done = control_msg(kSeq, NLMSG_DONE);
    chunk.insert(chunk.end(), done.begin(), done.end());

    const auto out = parse_rtnetlink_routes_chunk(chunk, kSeq);
    REQUIRE(out.records.size() == 1);
    CHECK(out.records[0].destination == "10.0.0.0");
    CHECK(out.records[0].table == 100);
    CHECK(out.done);
    CHECK_FALSE(out.truncated);
}

TEST_CASE("routes decode skips cloned entries, host-local types and non-IP families",
          "[network_config][routes][rtnetlink]") {
    constexpr std::uint32_t kSeq = 7;
    std::vector<unsigned char> chunk;
    auto add = [&](std::vector<unsigned char> m) { chunk.insert(chunk.end(), m.begin(), m.end()); };
    const std::vector<Attr> dst{{RTA_DST, v4(10, 1, 0, 0)}};
    add(route_msg(kSeq, AF_INET, 16, RT_TABLE_MAIN, RTN_UNICAST, 2, RTM_F_CLONED, dst));
    add(route_msg(kSeq, AF_INET, 16, RT_TABLE_MAIN, RTN_LOCAL, 2, 0, dst));
    add(route_msg(kSeq, AF_INET, 16, RT_TABLE_MAIN, RTN_BROADCAST, 2, 0, dst));
    add(route_msg(kSeq, AF_INET, 16, RT_TABLE_MAIN, RTN_ANYCAST, 2, 0, dst));
    add(route_msg(kSeq, AF_INET, 16, RT_TABLE_MAIN, RTN_MULTICAST, 2, 0, dst));
    add(route_msg(kSeq, AF_PACKET, 16, RT_TABLE_MAIN, RTN_UNICAST, 2, 0, dst));
    add(route_msg(kSeq, AF_INET, 16, RT_TABLE_MAIN, RTN_UNICAST, 2, 0, dst)); // the one keeper
    const auto out = parse_rtnetlink_routes_chunk(chunk, kSeq);
    REQUIRE(out.records.size() == 1);
    CHECK(out.records[0].destination == "10.1.0.0");
    CHECK_FALSE(out.truncated);
}

TEST_CASE("routes decode rejects an out-of-range prefix length as malformed",
          "[network_config][routes][rtnetlink]") {
    constexpr std::uint32_t kSeq = 7;
    auto bad4 = route_msg(kSeq, AF_INET, 33, RT_TABLE_MAIN, RTN_UNICAST, 3, 0,
                          {{RTA_DST, v4(10, 0, 0, 0)}});
    auto out = parse_rtnetlink_routes_chunk(bad4, kSeq);
    CHECK(out.records.empty());
    CHECK(out.truncated);

    auto bad6 = route_msg(kSeq, AF_INET6, 129, RT_TABLE_MAIN, RTN_UNICAST, 3, 0, {});
    out = parse_rtnetlink_routes_chunk(bad6, kSeq);
    CHECK(out.records.empty());
    CHECK(out.truncated);
}

TEST_CASE("routes decode treats a too-short address attribute as malformed, not as absent",
          "[network_config][routes][rtnetlink]") {
    constexpr std::uint32_t kSeq = 7;
    auto m = route_msg(kSeq, AF_INET, 24, RT_TABLE_MAIN, RTN_UNICAST, 3, 0,
                       {{RTA_DST, v4(10, 0, 0, 0)}, {RTA_GATEWAY, {10, 0}}}); // 2 bytes, not 4
    const auto out = parse_rtnetlink_routes_chunk(m, kSeq);
    CHECK(out.truncated);
    // The route is still reported (its destination was readable) but the caller is
    // told the read was imperfect, and no half-parsed gateway is invented.
    REQUIRE(out.records.size() == 1);
    CHECK(out.records[0].gateway.empty());
}

TEST_CASE("routes decode surfaces an `ip nexthop` object reference without resolving it",
          "[network_config][routes][rtnetlink]") {
    constexpr std::uint32_t kSeq = 7;
    auto m = route_msg(kSeq, AF_INET, 24, RT_TABLE_MAIN, RTN_UNICAST, 3, 0,
                       {{RTA_DST, v4(10, 5, 0, 0)}, {RTA_NH_ID, u32(7)}});
    const auto out = parse_rtnetlink_routes_chunk(m, kSeq);
    REQUIRE(out.records.size() == 1);
    CHECK(out.records[0].has_nh_id);
    CHECK(format_route_row(linux_route_to_row(out.records[0], "eth0")) ==
          "route|ipv4|10.5.0.0|24|nhid:7|eth0|0|main|unicast|boot");
}

TEST_CASE("routes decode survives a later nexthop whose rtnh_len points past the payload",
          "[network_config][routes][rtnetlink]") {
    // RTNH_NEXT is single-argument and does NOT shrink the remaining length, unlike
    // RTA_NEXT: the decoder must subtract it itself. Without that, RTNH_OK on the
    // second nexthop compares against the ORIGINAL length, passes, and the walk reads
    // past the payload (a heap-buffer-overflow under ASan, since the message ends
    // exactly at the attribute). With it the second nexthop is rejected: one nexthop
    // is counted, so the route is NOT flagged collapsed, and the leftover bytes mark
    // the read malformed.
    constexpr std::uint32_t kSeq = 7;
    std::vector<unsigned char> nh;
    struct rtnexthop first {};
    first.rtnh_len = sizeof(struct rtnexthop);
    first.rtnh_ifindex = 12;
    append_bytes(nh, &first, sizeof(first));
    struct rtnexthop second {};
    second.rtnh_len = sizeof(struct rtnexthop) + 4; // claims 4 attribute bytes that are not there
    second.rtnh_ifindex = 13;
    append_bytes(nh, &second, sizeof(second));
    auto m = route_msg(kSeq, AF_INET, 16, RT_TABLE_MAIN, RTN_UNICAST, 3, 0,
                       {{RTA_DST, v4(172, 20, 0, 0)}, {RTA_MULTIPATH, nh}});
    const auto out = parse_rtnetlink_routes_chunk(m, kSeq);
    CHECK(out.truncated);
    REQUIRE(out.records.size() == 1);
    CHECK(out.records[0].ifindex == 12);
    CHECK_FALSE(out.records[0].multipath_collapsed);
}

TEST_CASE("routes decode reports NLMSG_ERROR", "[network_config][routes][rtnetlink]") {
    constexpr std::uint32_t kSeq = 7;
    const auto out = parse_rtnetlink_routes_chunk(control_msg(kSeq, NLMSG_ERROR), kSeq);
    CHECK(out.error);
    CHECK(out.records.empty());
}

TEST_CASE("routes decode renders an IPv6 default route as ::/0",
          "[network_config][routes][rtnetlink]") {
    constexpr std::uint32_t kSeq = 7;
    std::vector<unsigned char> gw(16, 0);
    gw[0] = 0xfd;
    gw[15] = 0x01;
    auto m = route_msg(kSeq, AF_INET6, 0, RT_TABLE_MAIN, RTN_UNICAST, 9, 0,
                       {{RTA_GATEWAY, gw}, {RTA_OIF, u32(12)}, {RTA_PRIORITY, u32(1024)}});
    const auto out = parse_rtnetlink_routes_chunk(m, kSeq);
    REQUIRE(out.records.size() == 1);
    CHECK(format_route_row(linux_route_to_row(out.records[0], "dummy0")) ==
          "route|ipv6|::|0|fd00::1|dummy0|1024|main|unicast|ra");
}

TEST_CASE("route type and protocol names fall back to a numbered token, never an empty field",
          "[network_config][routes][rtnetlink]") {
    RtRouteFull r;
    r.destination = "10.0.0.0";
    r.type = 99;
    r.protocol = 250;
    const auto row = linux_route_to_row(r, "eth0");
    CHECK(row.type == "type99");
    CHECK(row.origin == "proto250");
    r.type = RTN_XRESOLVE;
    r.protocol = 186;
    const auto row2 = linux_route_to_row(r, "eth0");
    CHECK(row2.type == "xresolve");
    CHECK(row2.origin == "bgp");
}

#endif // __linux__

#if defined(__APPLE__)

#include <cstring>

namespace {

const std::map<int, std::string>& mac_capture_interfaces() {
    // From the capture host's socket.if_nameindex(): lo0 = 1, en0 = 7, utun0..6 = 19..25.
    static const std::map<int, std::string> m{{1, "lo0"},   {7, "en0"},   {19, "utun0"},
                                              {20, "utun1"}, {21, "utun2"}, {22, "utun3"},
                                              {23, "utun4"}, {24, "utun5"}, {25, "utun6"}};
    return m;
}

std::string mac_iface(int idx) {
    const auto it = mac_capture_interfaces().find(idx);
    return it == mac_capture_interfaces().end() ? std::string{} : it->second;
}

std::vector<unsigned char> read_hex_blob(const fs::path& p) {
    auto lines = read_hex_lines(p);
    REQUIRE(!lines.empty());
    return std::move(lines.front());
}

// ── synthetic builders: ONLY for shapes a real kernel never emits ────────

std::vector<unsigned char> sin_bytes(unsigned char a, unsigned char b, unsigned char c,
                                     unsigned char d) {
    struct sockaddr_in sin {};
    sin.sin_len = sizeof(sin);
    sin.sin_family = AF_INET;
    const unsigned char addr[4] = {a, b, c, d};
    std::memcpy(&sin.sin_addr, addr, 4);
    std::vector<unsigned char> out(sizeof(sin));
    std::memcpy(out.data(), &sin, sizeof(sin));
    return out;
}

// A netmask sockaddr the way the kernel trims it: sa_len covers only up to the last
// non-zero byte of the address, everything after is implicitly zero.
std::vector<unsigned char> trimmed_mask_v4(std::initializer_list<unsigned char> mask_bytes) {
    std::vector<unsigned char> out(4 + mask_bytes.size(), 0); // len, family, port(2), then mask
    out[0] = static_cast<unsigned char>(out.size());
    out[1] = AF_INET;
    std::size_t i = 4;
    for (auto b : mask_bytes)
        out[i++] = b;
    return out;
}

std::vector<unsigned char> route_msg(int flags, unsigned short index,
                                     const std::vector<unsigned char>& dst,
                                     const std::vector<unsigned char>* gw,
                                     const std::vector<unsigned char>* mask) {
    std::vector<unsigned char> buf(sizeof(rt_msghdr), 0);
    int addrs = RTA_DST;
    auto add = [&](const std::vector<unsigned char>& sa) {
        buf.insert(buf.end(), sa.begin(), sa.end());
        while (buf.size() % 4 != 0)
            buf.push_back(0);
    };
    add(dst);
    if (gw) {
        addrs |= RTA_GATEWAY;
        add(*gw);
    }
    if (mask) {
        addrs |= RTA_NETMASK;
        add(*mask);
    }
    rt_msghdr hdr{};
    hdr.rtm_msglen = static_cast<unsigned short>(buf.size());
    hdr.rtm_version = RTM_VERSION;
    hdr.rtm_type = RTM_GET;
    hdr.rtm_index = index;
    hdr.rtm_flags = flags;
    hdr.rtm_addrs = addrs;
    std::memcpy(buf.data(), &hdr, sizeof(hdr));
    return buf;
}

} // namespace

// ── The real capture ──────────────────────────────────────────────────────

TEST_CASE("routes decode of a real NET_RT_DUMP matches netstat's table",
          "[network_config][routes][pf_route]") {
    const auto blob = read_hex_blob(fixture_dir("macos") / "net_rt_dump.hex");
    const auto out = parse_route_table_dump(blob);
    CHECK_FALSE(out.truncated); // a clean real dump must not look malformed
    CHECK_FALSE(out.capped);

    std::vector<std::string> rows;
    for (const auto& rec : out.records)
        rows.push_back(format_route_row(mac_route_to_row(rec, mac_iface(rec.ifindex))));

    // Hand-checked against the `netstat -rnW` ground truth in the provenance file.
    // The fixture also holds 9 real neighbour / cloned / group / own-address entries
    // that must NOT appear here (LLINFO, WASCLONED, MULTICAST, LOCAL).
    const std::vector<std::string> expected{
        "route|ipv4|0.0.0.0|0|192.0.2.1|en0|-|-|unicast|static",
        "route|ipv4|0.0.0.0|0|-|utun6|-|-|unicast|static",
        "route|ipv4|100.64.0.0|10|-|utun6|-|-|unicast|static",
        "route|ipv4|100.100.100.100|32|-|utun6|-|-|unicast|static",
        "route|ipv4|127.0.0.0|8|127.0.0.1|lo0|-|-|unicast|static",
        "route|ipv4|169.254.0.0|16|-|en0|-|-|unicast|static",
        "route|ipv4|192.0.2.0|24|-|en0|-|-|unicast|static",
        "route|ipv4|192.0.2.1|32|-|en0|-|-|unicast|static",
        "route|ipv4|192.0.2.66|32|-|en0|-|-|unicast|static",
        "route|ipv4|255.255.255.255|32|-|en0|-|-|unicast|static",
        "route|ipv4|255.255.255.255|32|-|utun6|-|-|unicast|static",
        "route|ipv6|::|0|fe80::|utun0|-|-|unicast|other",
        "route|ipv6|::|0|fe80::|utun1|-|-|unicast|other",
        "route|ipv6|::|0|fe80::|utun2|-|-|unicast|other",
        "route|ipv6|::|0|fe80::|utun3|-|-|unicast|other",
        "route|ipv6|::|0|fe80::|utun4|-|-|unicast|other",
        "route|ipv6|::|0|fe80::|utun5|-|-|unicast|other",
        "route|ipv6|::|0|fd7a:115c:a1e0::|utun6|-|-|unicast|other",
        "route|ipv6|fd7a:115c:a1e0::|48|fe80::200:5eff:fe00:5307|utun6|-|-|unicast|other",
        "route|ipv6|fd7a:115c:a1e0::53|128|-|utun6|-|-|unicast|static",
        "route|ipv6|fe80::|64|fe80::1|lo0|-|-|unicast|other",
        "route|ipv6|fe80::|64|-|en0|-|-|unicast|other",
        "route|ipv6|fe80::|64|fe80::200:5eff:fe00:5301|utun0|-|-|unicast|other",
        "route|ipv6|fe80::|64|fe80::200:5eff:fe00:5302|utun1|-|-|unicast|other",
        "route|ipv6|fe80::|64|fe80::200:5eff:fe00:5303|utun2|-|-|unicast|other",
        "route|ipv6|fe80::|64|fe80::200:5eff:fe00:5304|utun3|-|-|unicast|other",
        "route|ipv6|fe80::|64|fe80::200:5eff:fe00:5305|utun4|-|-|unicast|other",
        "route|ipv6|fe80::|64|fe80::200:5eff:fe00:5306|utun5|-|-|unicast|other",
        "route|ipv6|fe80::|64|fe80::200:5eff:fe00:5307|utun6|-|-|unicast|other",
    };
    REQUIRE(rows.size() == expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i)
        CHECK(rows[i] == expected[i]);
}

TEST_CASE("routes decode of a truncated real dump is flagged, never complete",
          "[network_config][routes][pf_route]") {
    auto blob = read_hex_blob(fixture_dir("macos") / "net_rt_dump.hex");
    REQUIRE(blob.size() > 1000);
    blob.resize(blob.size() - 50); // lands inside the last message
    const auto out = parse_route_table_dump(blob);
    CHECK(out.truncated);
    CHECK_FALSE(out.records.empty());
}

// ── Adversarial / malformed shapes ────────────────────────────────────────

TEST_CASE("macOS netmask prefix handles trimmed sockaddrs and rejects holes",
          "[network_config][routes][pf_route]") {
    unsigned p = 99;
    // sa_len 0 / a bare 4-byte header: the all-zero mask, /0.
    const unsigned char zero_len[4] = {0, 0, 0, 0};
    REQUIRE(routes_detail::mac_mask_prefix(zero_len, false, p));
    CHECK(p == 0);
    // /10 trimmed to two mask bytes (ff c0): sa_len = 4 + 2.
    const auto m10 = trimmed_mask_v4({0xff, 0xc0});
    REQUIRE(routes_detail::mac_mask_prefix(m10.data(), false, p));
    CHECK(p == 10);
    // /24 trimmed to three bytes.
    const auto m24 = trimmed_mask_v4({0xff, 0xff, 0xff});
    REQUIRE(routes_detail::mac_mask_prefix(m24.data(), false, p));
    CHECK(p == 24);
    // /32 untrimmed.
    const auto m32 = trimmed_mask_v4({0xff, 0xff, 0xff, 0xff});
    REQUIRE(routes_detail::mac_mask_prefix(m32.data(), false, p));
    CHECK(p == 32);
    // ff 00 ff: a 1 after a 0 — never guess a prefix for it.
    const auto hole = trimmed_mask_v4({0xff, 0x00, 0xff});
    CHECK_FALSE(routes_detail::mac_mask_prefix(hole.data(), false, p));
    // ff 0f: partial byte whose low bits are set, not a prefix.
    const auto low = trimmed_mask_v4({0xff, 0x0f});
    CHECK_FALSE(routes_detail::mac_mask_prefix(low.data(), false, p));
}

TEST_CASE("routes decode treats a route with no netmask as a host route",
          "[network_config][routes][pf_route]") {
    const auto dst = sin_bytes(203, 0, 113, 9);
    const auto msg = route_msg(RTF_UP | RTF_HOST | RTF_STATIC, 7, dst, nullptr, nullptr);
    const auto out = parse_route_table_dump(msg);
    REQUIRE(out.records.size() == 1);
    CHECK(out.records[0].prefix_len == 32);
    CHECK(out.records[0].destination == "203.0.113.9");
    CHECK_FALSE(out.truncated);
}

TEST_CASE("routes decode skips every host-local / neighbour / cloned / group flag",
          "[network_config][routes][pf_route]") {
    const auto dst = sin_bytes(10, 0, 0, 1);
    const auto mask = trimmed_mask_v4({0xff, 0xff, 0xff, 0xff});
    for (const int skip : {RTF_LLINFO, RTF_WASCLONED, RTF_MULTICAST, RTF_BROADCAST, RTF_LOCAL}) {
        const auto msg = route_msg(RTF_UP | RTF_HOST | skip, 7, dst, nullptr, &mask);
        CHECK(parse_route_table_dump(msg).records.empty());
    }
    const auto keep = route_msg(RTF_UP | RTF_STATIC, 7, dst, nullptr, &mask);
    CHECK(parse_route_table_dump(keep).records.size() == 1);
}

TEST_CASE("routes decode reports blackhole and reject routes by type",
          "[network_config][routes][pf_route]") {
    const auto dst = sin_bytes(203, 0, 113, 0);
    const auto mask = trimmed_mask_v4({0xff, 0xff, 0xff});
    auto bh = parse_route_table_dump(route_msg(RTF_UP | RTF_BLACKHOLE | RTF_STATIC, 1, dst, nullptr, &mask));
    REQUIRE(bh.records.size() == 1);
    CHECK(mac_route_to_row(bh.records[0], "lo0").type == "blackhole");
    auto rj = parse_route_table_dump(route_msg(RTF_UP | RTF_REJECT | RTF_STATIC, 1, dst, nullptr, &mask));
    REQUIRE(rj.records.size() == 1);
    CHECK(mac_route_to_row(rj.records[0], "lo0").type == "reject");
}

TEST_CASE("routes decode flags a non-contiguous netmask as malformed and emits no row",
          "[network_config][routes][pf_route]") {
    const auto dst = sin_bytes(10, 0, 0, 0);
    const auto bad = trimmed_mask_v4({0xff, 0x00, 0xff});
    const auto out = parse_route_table_dump(route_msg(RTF_UP | RTF_STATIC, 7, dst, nullptr, &bad));
    CHECK(out.records.empty());
    CHECK(out.truncated);
}

TEST_CASE("routes decode stops on an unrecognised rtm_version", "[network_config][routes][pf_route]") {
    const auto dst = sin_bytes(10, 0, 0, 0);
    const auto mask = trimmed_mask_v4({0xff, 0xff, 0xff});
    auto msg = route_msg(RTF_UP | RTF_STATIC, 7, dst, nullptr, &mask);
    reinterpret_cast<rt_msghdr*>(msg.data())->rtm_version = static_cast<unsigned char>(RTM_VERSION + 1);
    const auto out = parse_route_table_dump(msg);
    CHECK(out.records.empty());
    CHECK(out.truncated);
}

TEST_CASE("routes decode survives a sockaddr whose sa_len overruns its record",
          "[network_config][routes][pf_route]") {
    const auto dst = sin_bytes(10, 0, 0, 0);
    auto msg = route_msg(RTF_UP | RTF_STATIC, 7, dst, nullptr, nullptr);
    msg[sizeof(rt_msghdr)] = 200; // sa_len claims 200 bytes in a record that holds 16
    const auto out = parse_route_table_dump(msg);
    CHECK(out.records.empty());
    CHECK(out.truncated);
}

TEST_CASE("routes decode survives a zero-length message", "[network_config][routes][pf_route]") {
    std::vector<unsigned char> blob(sizeof(rt_msghdr), 0); // rtm_msglen == 0
    const auto out = parse_route_table_dump(blob);
    CHECK(out.records.empty());
    CHECK(out.truncated);
}

TEST_CASE("routes decode stops at the row cap and says so", "[network_config][routes][pf_route]") {
    const auto dst = sin_bytes(10, 0, 0, 0);
    const auto mask = trimmed_mask_v4({0xff, 0xff, 0xff, 0xff});
    const auto one = route_msg(RTF_UP | RTF_STATIC, 7, dst, nullptr, &mask);
    std::vector<unsigned char> blob;
    blob.reserve(one.size() * (kRoutesRowCap + 5));
    for (std::size_t i = 0; i < kRoutesRowCap + 5; ++i)
        blob.insert(blob.end(), one.begin(), one.end());
    const auto out = parse_route_table_dump(blob);
    CHECK(out.capped);
    CHECK(out.records.size() == kRoutesRowCap);
    CHECK_FALSE(out.truncated); // capped is its own outcome, not a malformed read
}

#endif // __APPLE__
