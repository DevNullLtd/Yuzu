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
#include "network_config_routes_legs.hpp"
#include "network_config_routes_parsers.hpp"
#if defined(__linux__)
#include "network_config_netlink.hpp"
#endif

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <chrono>
#include <cstring>
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
    r.ifname = "dummy0";
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
    r.ifname = "ev|il\nname\\x";
    const std::string row = format_route_row(r);
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row == "route|ipv4|10.0.0.0|8|-|ev\\|il name/x|-|-|unicast|-");
}


// ── emit_routes: the status contract every leg shares ─────────────────────────────────────

namespace {

struct RecordingCtx {
    std::vector<std::string> rows;
    int status_calls = 0;
    YuzuResultStatus status = YUZU_RESULT_STATUS_UNDECLARED;
    YuzuResultCompleteness completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
    std::string provenance;
    void write_output(std::string_view row) { rows.emplace_back(row); }
    void set_result_status(YuzuResultStatus s, YuzuResultCompleteness c, std::string_view p = {}) {
        ++status_calls;
        status = s;
        completeness = c;
        provenance = std::string{p};
    }
};

RouteRow sample_row() {
    RouteRow r;
    r.destination = "192.0.2.0";
    r.prefix_len = 24;
    r.origin = "static";
    return r;
}

} // namespace

TEST_CASE("emit_routes: a clean read is OK/FULL and an empty table is a clean answer",
          "[network_config][routes][routes_status]") {
    RecordingCtx ctx;
    yuzu::shared::ConstraintAccumulator acc;
    emit_routes(ctx, {sample_row(), sample_row()}, acc, false);
    CHECK(ctx.rows.size() == 2);
    CHECK(ctx.rows[0].starts_with("route|ipv4|192.0.2.0|24|"));
    CHECK(ctx.status == YUZU_RESULT_STATUS_OK);
    CHECK(ctx.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(ctx.provenance.empty());
    CHECK(ctx.status_calls == 1); // exactly one status per run

    RecordingCtx empty;
    emit_routes(empty, {}, acc, false); // a host with no routes: zero rows, still OK/FULL
    CHECK(empty.rows.empty());
    CHECK(empty.status == YUZU_RESULT_STATUS_OK);
    CHECK(empty.completeness == YUZU_RESULT_COMPLETENESS_FULL);
}

TEST_CASE("emit_routes: a reduced read is CONSTRAINED/PARTIAL with every token, rows still sent",
          "[network_config][routes][routes_status]") {
    RecordingCtx ctx;
    yuzu::shared::ConstraintAccumulator acc;
    acc.add_failure(kTokRowCap);
    acc.add_failure("network_config:routes_multipath_first_nexthop_only");
    acc.add_failure(kTokRowCap); // a repeated token is recorded once
    emit_routes(ctx, {sample_row()}, acc, false);
    CHECK(ctx.rows.size() == 1);
    CHECK(ctx.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(ctx.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(ctx.provenance ==
          "network_config:routes_row_cap_reached,network_config:routes_multipath_first_nexthop_only");
}

TEST_CASE("emit_routes: an unreadable table is UNAVAILABLE/PARTIAL, never an OK empty table",
          "[network_config][routes][routes_status]") {
    RecordingCtx ctx;
    yuzu::shared::ConstraintAccumulator acc;
    acc.add_failure("network_config:routes_table_unavailable");
    emit_routes(ctx, {}, acc, true);
    CHECK(ctx.rows.empty());
    CHECK(ctx.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(ctx.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(ctx.provenance == "network_config:routes_table_unavailable");
}

// ── Windows mapping (portable: pure logic over a plain struct) ────────────
//
// The GetIpForwardTable2 call itself is the Windows-only shell and is verified live
// on the-rig; everything decidable without Windows headers is tested here, on every
// host, against a real capture of that table.

namespace {

// Mirrors the leg's own unpacking of a row, through the same win_next_hop() the leg uses.
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
        r.next_hop = win_next_hop(c[3], c[3] == "0.0.0.0" || c[3] == "::");
        r.ifname = c[4];
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

    const auto result = win_routes_to_rows(table);
    CHECK_FALSE(result.capped);
    std::vector<std::string> rows;
    for (const auto& r : result.rows)
        rows.push_back(format_route_row(r));

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

TEST_CASE("windows routes: the cap counts kept routes, not the host's own entries",
          "[network_config][routes][windows_map]") {
    const auto table = read_windows_fixture(fixture_dir("windows") / "forward_table.tsv");
    // The fixture holds 41 routes of which 17 are kept. Capping at 17 keeps them all and is NOT
    // capped even though 24 host-local rows were skipped on the way; capping at 3 is capped and
    // returns exactly the first 3 kept rows.
    const auto exact = win_routes_to_rows(table, 17);
    CHECK_FALSE(exact.capped);
    CHECK(exact.rows.size() == 17);
    const auto three = win_routes_to_rows(table, 3);
    CHECK(three.capped);
    REQUIRE(three.rows.size() == 3);
    CHECK(format_route_row(three.rows[0]) == format_route_row(exact.rows[0]));
    CHECK(format_route_row(three.rows[2]) == format_route_row(exact.rows[2]));
}

TEST_CASE("windows next hop: unspecified means on-link", "[network_config][routes][windows_map]") {
    CHECK(win_next_hop("0.0.0.0", true).empty());
    CHECK(win_next_hop("::", true).empty());
    CHECK(win_next_hop("192.0.2.1", false) == "192.0.2.1");
    CHECK(win_next_hop("", false).empty()); // an AF_UNSPEC hop formats to empty and stays on-link
}

TEST_CASE("windows host-local rule: Local full-length and Local multicast are dropped, the rest kept",
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
    CHECK(win_route_is_host_local(route(false, "239.255.255.250", 32, 2)));
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
    // A route someone CONFIGURED is kept whatever its prefix — even a multicast one.
    CHECK_FALSE(win_route_is_host_local(route(false, "224.0.0.0", 4, 3)));
    CHECK_FALSE(win_route_is_host_local(route(false, "239.255.255.250", 32, 3)));
    CHECK_FALSE(win_route_is_host_local(route(true, "ff02::", 16, 3)));
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
    r.ifname = "Ethernet";
    r.metric = 281;
    r.protocol = 3;
    CHECK(format_route_row(win_route_to_row(r)) ==
          "route|ipv4|198.51.100.0|24|-|Ethernet|281|-|unicast|netmgmt");
    r.next_hop = "198.51.100.1";
    CHECK(format_route_row(win_route_to_row(r)).starts_with("route|ipv4|198.51.100.0|24|198.51.100.1|"));
}

#if defined(__linux__)

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

TEST_CASE("routes decode drops a record whose address attribute is too short and flags the read",
          "[network_config][routes][rtnetlink]") {
    constexpr std::uint32_t kSeq = 7;
    auto m = route_msg(kSeq, AF_INET, 24, RT_TABLE_MAIN, RTN_UNICAST, 3, 0,
                       {{RTA_DST, v4(10, 0, 0, 0)}, {RTA_GATEWAY, {10, 0}}}); // 2 bytes, not 4
    const auto out = parse_rtnetlink_routes_chunk(m, kSeq);
    CHECK(out.truncated);
    // No row at all: an unreadable gateway would render `-`, which means "on-link". The read is
    // reported incomplete instead of the route being reported wrong.
    CHECK(out.records.empty());
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
    // the read malformed — which now drops the record (never a row from a failed decode).
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
    CHECK(out.records.empty());
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


// ── netlink::dump drain, driven by scripted datagrams and a scripted clock ─────────────────
//
// KernelIo is the only thing these tests replace; the drain logic under test — the
// kernel-origin check, the foreign-datagram count and deadline bounds, MSG_TRUNC, the cap trim,
// short reads — is the production code, fed the REAL captured datagrams.

namespace {

struct FakeStep {
    std::vector<unsigned char> bytes;
    std::uint32_t from_pid = 0; // 0 = the kernel
    int flags = 0;              // recvmsg flags, e.g. MSG_TRUNC
    int elapsed_s = 0;          // the scripted clock advances this much BEFORE the recv returns
    bool fail = false;          // recv returns -1 (error / timeout)
};

struct FakeIo {
    std::vector<FakeStep> steps;
    bool open_ok = true;
    bool send_ok = true;
    std::size_t* consumed = nullptr; // how many recv() calls the drain made
    std::size_t next = 0;
    std::chrono::steady_clock::time_point t{std::chrono::hours{1}};

    bool open() { return open_ok; }
    bool send(const void*, std::size_t) { return send_ok; }
    ssize_t recv(unsigned char* buf, std::size_t cap, std::uint32_t& from_pid, int& flags) {
        if (consumed)
            *consumed = next;
        if (next >= steps.size())
            return -1; // script exhausted = a timeout
        const FakeStep& st = steps[next++];
        if (consumed)
            *consumed = next;
        t += std::chrono::seconds{st.elapsed_s};
        if (st.fail)
            return -1;
        REQUIRE(st.bytes.size() <= cap);
        std::memcpy(buf, st.bytes.data(), st.bytes.size());
        from_pid = st.from_pid;
        flags = st.flags;
        return static_cast<ssize_t>(st.bytes.size());
    }
    std::chrono::steady_clock::time_point now() const { return t; }
};

struct DumpRequest {
    struct nlmsghdr nlh{};
    struct rtmsg rtm{};
};

constexpr std::uint32_t kDumpSeq = 3; // the seq the real capture was taken with

auto run_dump(FakeIo io, std::size_t cap = static_cast<std::size_t>(-1)) {
    DumpRequest req;
    return netlink::dump(req, kDumpSeq, parse_rtnetlink_routes_chunk, cap, std::move(io));
}

std::vector<FakeStep> capture_steps() {
    std::vector<FakeStep> steps;
    for (auto& d : read_hex_lines(fixture_dir("linux") / "rtm_getroute_dump.hex"))
        steps.push_back(FakeStep{std::move(d)});
    return steps;
}

} // namespace

TEST_CASE("netlink dump of the real capture completes with every route and no cap",
          "[network_config][routes][netlink_dump]") {
    const auto r = run_dump(FakeIo{capture_steps()});
    CHECK(r.ok);
    CHECK_FALSE(r.capped);
    CHECK(r.records.size() == 16);
}

TEST_CASE("netlink dump discards a datagram that did not come from the kernel",
          "[network_config][routes][netlink_dump]") {
    // A local process sends a forged copy of the route datagram. If the origin check were
    // missing its 16 routes would be parsed and merged, doubling the table.
    auto steps = capture_steps();
    FakeStep forged = steps.front();
    forged.from_pid = 4242;
    steps.insert(steps.begin(), forged);
    const auto r = run_dump(FakeIo{steps});
    CHECK(r.ok);
    CHECK(r.records.size() == 16);
}

TEST_CASE("netlink dump gives up on a foreign-datagram flood instead of waiting forever",
          "[network_config][routes][netlink_dump]") {
    std::vector<FakeStep> steps;
    for (int i = 0; i < netlink::kMaxForeignDatagrams + 5; ++i) {
        FakeStep f = capture_steps().front();
        f.from_pid = 99;
        steps.push_back(std::move(f));
    }
    std::size_t consumed = 0;
    FakeIo io{steps};
    io.consumed = &consumed;
    const auto r = run_dump(std::move(io));
    CHECK_FALSE(r.ok);
    CHECK(r.records.empty());
    CHECK(consumed == static_cast<std::size_t>(netlink::kMaxForeignDatagrams) + 1); // the bound, not the script
}

TEST_CASE("netlink dump bounds the discard loop by wall-clock too, not just by count",
          "[network_config][routes][netlink_dump]") {
    // Each foreign datagram arrives 3 s after the last: the count (64) is nowhere near spent,
    // but the 4 s deadline is, by the second one. A paced local sender must not pin the thread.
    std::vector<FakeStep> steps;
    for (int i = 0; i < 10; ++i) {
        FakeStep f = capture_steps().front();
        f.from_pid = 99;
        f.elapsed_s = 3;
        steps.push_back(std::move(f));
    }
    std::size_t consumed = 0;
    FakeIo io{steps};
    io.consumed = &consumed;
    const auto r = run_dump(std::move(io));
    CHECK_FALSE(r.ok);
    CHECK(r.records.empty());
    CHECK(consumed == 2);
}

TEST_CASE("netlink dump treats a truncated datagram as incomplete and does not parse it",
          "[network_config][routes][netlink_dump]") {
    auto steps = capture_steps();
    steps.front().flags = MSG_TRUNC; // the kernel dropped the tail: a parse could not see it
    const auto r = run_dump(FakeIo{steps});
    CHECK_FALSE(r.ok);
    CHECK(r.records.empty());
}

TEST_CASE("netlink dump keeps what it decoded when the read then fails",
          "[network_config][routes][netlink_dump]") {
    auto steps = capture_steps();
    steps.pop_back();               // no NLMSG_DONE
    steps.push_back(FakeStep{{}, 0, 0, 0, /*fail=*/true});
    const auto r = run_dump(FakeIo{steps});
    CHECK_FALSE(r.ok); // never complete without NLMSG_DONE
    CHECK(r.records.size() == 16);
}

TEST_CASE("netlink dump reports NLMSG_ERROR as incomplete", "[network_config][routes][netlink_dump]") {
    std::vector<unsigned char> err(sizeof(struct nlmsghdr), 0);
    auto* h = reinterpret_cast<struct nlmsghdr*>(err.data());
    h->nlmsg_len = sizeof(struct nlmsghdr);
    h->nlmsg_type = NLMSG_ERROR;
    h->nlmsg_seq = kDumpSeq;
    const auto r = run_dump(FakeIo{{FakeStep{err}}});
    CHECK_FALSE(r.ok);
    CHECK(r.records.empty());
}

namespace {

// NLMSG_DONE as modern kernels send it: a 4-byte payload holding the dump's errno (0 = clean).
std::vector<unsigned char> done_msg(std::uint32_t seq, int dump_errno, unsigned short flags = 0) {
    std::vector<unsigned char> buf;
    struct nlmsghdr nlh {};
    nlh.nlmsg_len = static_cast<std::uint32_t>(NLMSG_LENGTH(sizeof(int)));
    nlh.nlmsg_type = NLMSG_DONE;
    nlh.nlmsg_flags = static_cast<unsigned short>(NLM_F_MULTI | flags);
    nlh.nlmsg_seq = seq;
    append_bytes(buf, &nlh, sizeof(nlh));
    append_bytes(buf, &dump_errno, sizeof(dump_errno));
    return buf;
}

// Mark the FIRST message of a datagram as sent from an interrupted dump.
void set_dump_intr_on_first(std::vector<unsigned char>& dg) {
    auto* h = reinterpret_cast<struct nlmsghdr*>(dg.data());
    h->nlmsg_flags = static_cast<unsigned short>(h->nlmsg_flags | NLM_F_DUMP_INTR);
}

} // namespace

TEST_CASE("netlink dump: rows then NLMSG_DONE carrying an errno is incomplete, never OK",
          "[network_config][routes][netlink_dump]") {
    // The kernel aborts a dump part-way (e.g. -ENOMEM) and closes it with DONE(-errno). That is a
    // SHORT table: it must not read as a clean, complete one (ok), though the rows are kept.
    auto steps = capture_steps();
    steps.pop_back(); // the clean DONE
    steps.push_back(FakeStep{done_msg(kDumpSeq, -12)});
    const auto r = run_dump(FakeIo{steps});
    CHECK_FALSE(r.ok);
    CHECK(r.records.size() == 16);
}

TEST_CASE("netlink dump: NLMSG_DONE(-errno) before any row is incomplete with no rows",
          "[network_config][routes][netlink_dump]") {
    const auto r = run_dump(FakeIo{{FakeStep{done_msg(kDumpSeq, -12)}}});
    CHECK_FALSE(r.ok);
    CHECK(r.records.empty());
}

TEST_CASE("netlink dump: a clean NLMSG_DONE(0), and a payload-less DONE, still complete",
          "[network_config][routes][netlink_dump]") {
    CHECK(run_dump(FakeIo{{FakeStep{done_msg(kDumpSeq, 0)}}}).ok);
    CHECK(run_dump(FakeIo{{FakeStep{control_msg(kDumpSeq, NLMSG_DONE)}}}).ok);
}

TEST_CASE("netlink dump: NLM_F_DUMP_INTR on a record means the table changed mid-read",
          "[network_config][routes][netlink_dump]") {
    // Route churn between the datagrams of one dump makes the kernel flag the next message; the
    // rows may be duplicated or missing, so the read is incomplete (rows kept) — never OK/FULL.
    auto steps = capture_steps();
    set_dump_intr_on_first(steps.front().bytes);
    const auto r = run_dump(FakeIo{steps});
    CHECK_FALSE(r.ok);
    CHECK(r.records.size() == 16);
}

TEST_CASE("netlink dump: NLM_F_DUMP_INTR on NLMSG_DONE is incomplete too",
          "[network_config][routes][netlink_dump]") {
    auto steps = capture_steps();
    steps.pop_back();
    steps.push_back(FakeStep{done_msg(kDumpSeq, 0, NLM_F_DUMP_INTR)});
    const auto r = run_dump(FakeIo{steps});
    CHECK_FALSE(r.ok);
    CHECK(r.records.size() == 16);
}

TEST_CASE("netlink dump: a malformed record followed by a clean DONE is not complete",
          "[network_config][routes][netlink_dump]") {
    // `ok = !truncated`: a dropped record must never be laundered into OK/FULL by the DONE after it.
    auto bad = route_msg(kDumpSeq, AF_INET, 24, RT_TABLE_MAIN, RTN_UNICAST, 3, 0,
                         {{RTA_DST, {10, 0}}}); // an IPv4 destination of 2 bytes
    const auto r = run_dump(FakeIo{{FakeStep{bad}, FakeStep{done_msg(kDumpSeq, 0)}}});
    CHECK_FALSE(r.ok);
    CHECK(r.records.empty());
}

TEST_CASE("routes decode: a truncated multipath attribute is flagged, not read past its payload",
          "[network_config][routes][rtnetlink]") {
    constexpr std::uint32_t kSeq = 7;
    // A 1-byte RTA_MULTIPATH payload is shorter than an rtnexthop header (and than the 2-byte
    // rtnh_len field itself). The walk must stop on the length, not on a value read past the end.
    auto m = route_msg(kSeq, AF_INET, 16, RT_TABLE_MAIN, RTN_UNICAST, 3, 0,
                       {{RTA_DST, v4(172, 22, 0, 0)}, {RTA_MULTIPATH, {0x01}}});
    const auto out = parse_rtnetlink_routes_chunk(m, kSeq);
    CHECK(out.truncated);
    CHECK(out.records.empty());
}

TEST_CASE("route table names: the documented 253 table is `default`",
          "[network_config][routes][rtnetlink]") {
    CHECK(routes_detail::table_name(253) == "default");
    CHECK(routes_detail::table_name(254) == "main");
}

TEST_CASE("netlink dump fails closed when it cannot open or send",
          "[network_config][routes][netlink_dump]") {
    FakeIo no_open{capture_steps()};
    no_open.open_ok = false;
    CHECK_FALSE(run_dump(std::move(no_open)).ok);
    FakeIo no_send{capture_steps()};
    no_send.send_ok = false;
    const auto r = run_dump(std::move(no_send));
    CHECK_FALSE(r.ok);
    CHECK(r.records.empty());
}

TEST_CASE("netlink dump trims to the record cap and says so",
          "[network_config][routes][netlink_dump]") {
    // The first datagram alone holds 16 records; a cap of 5 trims it, flags the cut, and is
    // never reported as a clean completion.
    const auto r = run_dump(FakeIo{capture_steps()}, 5);
    CHECK(r.capped);
    CHECK_FALSE(r.ok);
    CHECK(r.records.size() == 5);
}

TEST_CASE("routes decode drops a malformed nested multipath gateway instead of reporting on-link",
          "[network_config][routes][rtnetlink]") {
    // The FIRST nexthop carries an RTA_GATEWAY too short to be an IPv4 address (2 bytes) — and,
    // separately, an RTA_VIA whose family is neither AF_INET nor AF_INET6. Both used to be
    // swallowed: the route came out `-` (on-link) with the read still marked clean.
    constexpr std::uint32_t kSeq = 7;
    auto with_nested = [&](unsigned short nested_type, const std::vector<unsigned char>& nested) {
        std::vector<unsigned char> nh;
        struct rtnexthop hdr {};
        append_bytes(nh, &hdr, sizeof(hdr));
        append_attr(nh, Attr{nested_type, nested});
        auto* h = reinterpret_cast<struct rtnexthop*>(nh.data());
        h->rtnh_len = static_cast<unsigned short>(nh.size());
        h->rtnh_ifindex = 12;
        return route_msg(kSeq, AF_INET, 16, RT_TABLE_MAIN, RTN_UNICAST, 3, 0,
                         {{RTA_DST, v4(172, 21, 0, 0)}, {RTA_MULTIPATH, nh}});
    };
    const auto short_gw = parse_rtnetlink_routes_chunk(with_nested(RTA_GATEWAY, {10, 0}), kSeq);
    CHECK(short_gw.truncated);
    CHECK(short_gw.records.empty());

    const std::vector<unsigned char> bad_via{0x63, 0x00, 1, 2, 3, 4}; // family 99
    const auto bad = parse_rtnetlink_routes_chunk(with_nested(RTA_VIA, bad_via), kSeq);
    CHECK(bad.truncated);
    CHECK(bad.records.empty());

    // and a well-formed nested gateway is still clean
    const auto ok = parse_rtnetlink_routes_chunk(with_nested(RTA_GATEWAY, v4(10, 77, 0, 1)), kSeq);
    CHECK_FALSE(ok.truncated);
    REQUIRE(ok.records.size() == 1);
    CHECK(ok.records[0].gateway == "10.77.0.1");
}

#endif // __linux__

#if defined(__APPLE__)

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

TEST_CASE("routes decode never reports an undecodable gateway as on-link",
          "[network_config][routes][pf_route]") {
    // AF_LINK (`link#N`) IS on-link. A short AF_INET gateway or one of an unknown family is not
    // decodable, and rendering it `-` would read as on-link: the record is dropped and the read
    // flagged, like every other malformed shape on this leg.
    const auto dst = sin_bytes(198, 51, 100, 0);
    const auto mask = trimmed_mask_v4({0xff, 0xff, 0xff});
    const std::vector<unsigned char> link{8, AF_LINK, 7, 0, 0, 0, 0, 0};
    const auto on_link = parse_route_table_dump(route_msg(RTF_UP | RTF_STATIC, 7, dst, &link, &mask));
    REQUIRE(on_link.records.size() == 1);
    CHECK(on_link.records[0].gateway.empty());
    CHECK_FALSE(on_link.truncated);

    const std::vector<unsigned char> short_in{8, AF_INET, 0, 0, 10, 0, 0, 1}; // sa_len 8 < 16
    const auto s1 = parse_route_table_dump(route_msg(RTF_UP | RTF_GATEWAY, 7, dst, &short_in, &mask));
    CHECK(s1.records.empty());
    CHECK(s1.truncated);

    const std::vector<unsigned char> unknown{16, 7 /* AF_ISO */, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0};
    const auto s2 = parse_route_table_dump(route_msg(RTF_UP | RTF_GATEWAY, 7, dst, &unknown, &mask));
    CHECK(s2.records.empty());
    CHECK(s2.truncated);

    const auto gw = sin_bytes(198, 51, 100, 1);
    const auto ok = parse_route_table_dump(route_msg(RTF_UP | RTF_GATEWAY, 7, dst, &gw, &mask));
    REQUIRE(ok.records.size() == 1);
    CHECK(ok.records[0].gateway == "198.51.100.1");
    CHECK_FALSE(ok.truncated);
}

TEST_CASE("routes decode flags a record that advertises a sockaddr it does not contain",
          "[network_config][routes][pf_route]") {
    // rtm_addrs says DST|GATEWAY|NETMASK but only the destination is present. Reading that as
    // "no netmask" would emit a /32 host route with no gateway; it is a malformed record.
    const auto dst = sin_bytes(10, 9, 0, 0);
    auto msg = route_msg(RTF_UP | RTF_STATIC, 7, dst, nullptr, nullptr);
    reinterpret_cast<rt_msghdr*>(msg.data())->rtm_addrs |= RTA_GATEWAY | RTA_NETMASK;
    const auto out = parse_route_table_dump(msg);
    CHECK(out.records.empty());
    CHECK(out.truncated);

    // the same destination with nothing advertised beyond it is a legitimate host route
    const auto host = route_msg(RTF_UP | RTF_HOST | RTF_STATIC, 7, dst, nullptr, nullptr);
    const auto ok = parse_route_table_dump(host);
    REQUIRE(ok.records.size() == 1);
    CHECK_FALSE(ok.truncated);
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
