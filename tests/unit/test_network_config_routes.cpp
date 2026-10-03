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

// One recv() datagram per hex line, chunk boundaries preserved. std::vector storage
// is aligned well past NLMSG_ALIGNTO, which the decoder requires.
std::vector<std::vector<unsigned char>> read_hex_datagrams(const fs::path& p) {
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
    const auto datagrams = read_hex_datagrams(fixture_dir("linux") / "rtm_getroute_dump.hex");
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
    const auto d = decode_all(read_hex_datagrams(fixture_dir("linux") / "rtm_getroute_dump.hex"), 3);
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
    const auto d = decode_all(read_hex_datagrams(fixture_dir("linux") / "rtm_getroute_dump.hex"), 99);
    CHECK(d.records.empty());
    CHECK_FALSE(d.done);
}

TEST_CASE("routes decode reports a datagram cut mid-message as truncated, never as complete",
          "[network_config][routes][rtnetlink]") {
    auto datagrams = read_hex_datagrams(fixture_dir("linux") / "rtm_getroute_dump.hex");
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
