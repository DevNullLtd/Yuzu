/**
 * test_network_config_parsers.cpp — network_config_parsers.hpp (PKG-NC,
 * Wave-4 PR4.1).
 *
 * Portable text-parser tests (parse_proc_net_arp, the resolvectl/
 * systemd-resolve line filters) run on every host, matching
 * test_discovery_parsers.cpp / test_services_parsers.hpp's own precedent.
 * The rtnetlink binary-decode tests are Linux-only (`#if defined(__linux__)`)
 * and the PF_ROUTE default-route decode tests are macOS-only
 * (`#if defined(__APPLE__)`) — same platform-gated-TU shape as
 * test_route_sysctl_arp.cpp: the whole guarded section compiles to nothing
 * on a host that doesn't match.
 *
 * The rtnetlink/PF_ROUTE fixtures are built from real packed kernel structs
 * populated in this file (never hand-typed hex), so the byte layout always
 * matches whatever this compiler/platform actually produces — the same
 * discipline the header's own decoders assume of a real kernel reply.
 */
#include "network_config_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

using namespace yuzu::network_config;

// ── /proc/net/arp ─────────────────────────────────────────────────────────

TEST_CASE("parse_proc_net_arp parses a normal captured table", "[network_config]") {
    constexpr std::string_view kNormal = R"(IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.2      0x1         0x6         11:22:33:44:55:66     *        eth0
)";
    const auto entries = parse_proc_net_arp(kNormal);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].iface == "eth0");
    CHECK(entries[0].ip == "192.168.1.1");
    CHECK(entries[0].mac == "aa:bb:cc:dd:ee:ff");
    CHECK(entries[0].type == "dynamic"); // 0x2 == ATF_COM only
    CHECK(entries[1].type == "static");  // 0x6 == ATF_COM|ATF_PERM
}

TEST_CASE("parse_proc_net_arp drops incomplete/unresolved/non-Ethernet rows",
         "[network_config]") {
    constexpr std::string_view kMixed =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.10     0x1         0x0         00:00:00:00:00:00     *        eth0\n" // no ATF_COM
        "192.168.1.11     0x6         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n" // non-Ethernet hwtype
        "192.168.1.12     0x1         0x2         00:00:00:00:00:00     *        eth0\n" // all-zero MAC
        "192.168.1.13     0x1         0x2         aa:bb:cc:dd:ee:00     *        eth0\n"; // genuinely valid
    const auto entries = parse_proc_net_arp(kMixed);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "192.168.1.13");
}

TEST_CASE("parse_proc_net_arp tolerates malformed/short lines without crashing",
         "[network_config]") {
    constexpr std::string_view kMalformed =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.20\n"
        "192.168.1.21     0x1\n"
        "not even close to a real row\n"
        "192.168.1.22     0x1         0x2         aa:bb:cc:dd:ee:22     *        eth0\n";
    const auto entries = parse_proc_net_arp(kMalformed);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "192.168.1.22");
}

TEST_CASE("parse_proc_net_arp returns empty on blank/header-only input", "[network_config]") {
    CHECK(parse_proc_net_arp("").empty());
    CHECK(parse_proc_net_arp("\n\n").empty());
    CHECK(parse_proc_net_arp(
              "IP address       HW type     Flags       HW address            Mask     Device\n")
             .empty());
}

TEST_CASE("parse_proc_net_arp tolerates CRLF line endings", "[network_config]") {
    constexpr std::string_view kCrlf =
        "IP address       HW type     Flags       HW address            Mask     Device\r\n"
        "10.0.0.5         0x1         0x2         aa:11:bb:22:cc:33     *        eth1\r\n";
    const auto entries = parse_proc_net_arp(kCrlf);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].iface == "eth1");
    CHECK(entries[0].ip == "10.0.0.5");
    CHECK(entries[0].mac == "aa:11:bb:22:cc:33");
}

// ── dns_cache captured-stdout line filters ───────────────────────────────

TEST_CASE("parse_resolvectl_cache_lines splits and trims, drops blank lines",
         "[network_config]") {
    const auto lines =
        parse_resolvectl_cache_lines("example.com IN A 1.2.3.4\r\n\nexample.net IN A 5.6.7.8\r\n");
    REQUIRE(lines.size() == 2);
    CHECK(lines[0] == "example.com IN A 1.2.3.4");
    CHECK(lines[1] == "example.net IN A 5.6.7.8");
}

TEST_CASE("parse_resolvectl_cache_lines returns empty on empty output", "[network_config]") {
    CHECK(parse_resolvectl_cache_lines("").empty());
}

TEST_CASE("parse_systemd_resolve_stats_lines keeps only the three known cache lines, trimmed",
         "[network_config]") {
    constexpr std::string_view kStats = R"(DNSSEC supported by current servers: no
  Current Cache Size: 12
        Cache Hits: 345
      Cache Misses: 6
Some Other Line: ignored
)";
    const auto lines = parse_systemd_resolve_stats_lines(kStats);
    REQUIRE(lines.size() == 3);
    CHECK(lines[0] == "Current Cache Size: 12");
    CHECK(lines[1] == "Cache Hits: 345");
    CHECK(lines[2] == "Cache Misses: 6");
}

TEST_CASE("parse_systemd_resolve_stats_lines returns empty when none of the three lines appear",
         "[network_config]") {
    CHECK(parse_systemd_resolve_stats_lines("nothing relevant here\n").empty());
}

// ── dedupe_preserve_order (PKG-NC fix round: macOS arp double-counting +
//    dns_servers cross-service resolver overlap) ─────────────────────────

TEST_CASE("dedupe_preserve_order drops repeats and keeps first-seen order",
         "[network_config]") {
    const std::vector<std::string> in = {"a", "b", "a", "c", "b", "b", "d"};
    const auto out = dedupe_preserve_order(in);
    REQUIRE(out.size() == 4);
    CHECK(out[0] == "a");
    CHECK(out[1] == "b");
    CHECK(out[2] == "c");
    CHECK(out[3] == "d");
}

TEST_CASE("dedupe_preserve_order is a no-op on an already-unique list", "[network_config]") {
    const std::vector<std::string> in = {"x", "y", "z"};
    CHECK(dedupe_preserve_order(in) == in);
}

TEST_CASE("dedupe_preserve_order handles an empty list", "[network_config]") {
    CHECK(dedupe_preserve_order(std::vector<std::string>{}).empty());
}

TEST_CASE("dedupe_preserve_order simulates the macOS arp double-record regression",
         "[network_config]") {
    // Same shape as network_config_plugin.cpp's do_arp: formatted
    // "arp|-|ip|mac|-" lines, some repeated because the PF_ROUTE dump can
    // report the same neighbour twice.
    const std::vector<std::string> lines = {
        "arp|-|192.168.0.131|fc:34:97:65:1e:0a|-",
        "arp|-|192.168.0.66|00:11:22:33:44:55|-",
        "arp|-|192.168.0.131|fc:34:97:65:1e:0a|-", // duplicate
        "arp|-|224.0.0.251|01:00:5e:00:00:fb|-",
        "arp|-|224.0.0.251|01:00:5e:00:00:fb|-", // duplicate
    };
    const auto out = dedupe_preserve_order(lines);
    REQUIRE(out.size() == 3);
    CHECK(out[0] == "arp|-|192.168.0.131|fc:34:97:65:1e:0a|-");
    CHECK(out[1] == "arp|-|192.168.0.66|00:11:22:33:44:55|-");
    CHECK(out[2] == "arp|-|224.0.0.251|01:00:5e:00:00:fb|-");
}

// ── ipv4_prefix_length / ipv6_prefix_length (PKG-NC fix round: replaces
//    the old macOS hex-netmask format with the Linux leg's prefix-length
//    shape -- #3346-class consistency) ────────────────────────────────────

TEST_CASE("ipv4_prefix_length converts common netmasks to their CIDR prefix length",
         "[network_config]") {
    CHECK(ipv4_prefix_length(0x00000000u) == 0);  // 0.0.0.0
    CHECK(ipv4_prefix_length(0xff000000u) == 8);  // 255.0.0.0
    CHECK(ipv4_prefix_length(0xffffff00u) == 24); // 255.255.255.0 -- the old hex-emitting case
    CHECK(ipv4_prefix_length(0xffffffffu) == 32); // 255.255.255.255
    CHECK(ipv4_prefix_length(0xfffffff8u) == 29); // 255.255.255.248
}

TEST_CASE("ipv6_prefix_length converts common netmasks to their CIDR prefix length",
         "[network_config]") {
    {
        const unsigned char all_zero[16] = {0};
        CHECK(ipv6_prefix_length(all_zero) == 0);
    }
    {
        // /64 -- first 8 bytes all-1s, rest all-0.
        const unsigned char slash64[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                           0,    0,    0,    0,    0,    0,    0,    0};
        CHECK(ipv6_prefix_length(slash64) == 64);
    }
    {
        // /128 -- fully specified host route.
        const unsigned char slash128[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        CHECK(ipv6_prefix_length(slash128) == 128);
    }
    {
        // /12 -- partial final byte (0xf0 == 4 leading 1-bits).
        const unsigned char slash12[16] = {0xff, 0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        CHECK(ipv6_prefix_length(slash12) == 12);
    }
}

// ── format_mac: the non-6-byte guard IS the anti-fabrication fix ───────────
//
// The Linux decoder now refuses a non-6-byte IFLA_ADDRESS, but the guard lives
// in format_mac itself and on macOS every caller passes exactly 6, so nothing
// exercised it at any level on this host. These pin the contract directly.

TEST_CASE("format_mac formats exactly six bytes and refuses any other length",
          "[network_config][mac]") {
    const unsigned char six[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    CHECK(yuzu::network_config::format_mac(six, 6) == "aa:bb:cc:dd:ee:ff");

    // Lowercase hex, zero-padded — a leading-zero byte must not collapse.
    const unsigned char padded[6] = {0x00, 0x01, 0x02, 0x0a, 0x0b, 0x0c};
    CHECK(yuzu::network_config::format_mac(padded, 6) == "00:01:02:0a:0b:0c");

    // Never a fabricated MAC: not truncated from longer, not padded from
    // shorter, not produced from nothing.
    const unsigned char twenty[20] = {0x80, 0x00, 0x02, 0x08, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0xf4, 0x52, 0x14, 0x03, 0x00, 0x7b, 0xcb, 0xa1};
    CHECK(yuzu::network_config::format_mac(twenty, 20).empty());
    CHECK(yuzu::network_config::format_mac(twenty, 8).empty());
    CHECK(yuzu::network_config::format_mac(six, 5).empty());
    CHECK(yuzu::network_config::format_mac(six, 0).empty());
}

// ── join_bypass_list: the macOS `bypass|` row, present on nearly every Mac ──

TEST_CASE("join_bypass_list comma-joins entries and drops empties", "[network_config][proxy]") {
    using yuzu::network_config::join_bypass_list;
    // The default macOS exception list, verbatim from a live host.
    CHECK(join_bypass_list({"*.local", "169.254/16"}) == "*.local,169.254/16");
    CHECK(join_bypass_list({"a"}) == "a");
    // An empty element must not produce a doubled or trailing comma.
    CHECK(join_bypass_list({"a", "", "b"}) == "a,b");
    CHECK(join_bypass_list({"", "a"}) == "a");
    CHECK(join_bypass_list({"a", ""}) == "a");
    // Nothing survivable -> empty, and the caller then emits no row at all.
    CHECK(join_bypass_list({}).empty());
    CHECK(join_bypass_list({"", ""}).empty());
}

// ── REGRESSION PIN: macOS proxy service selection (portable, pure) ─────────
//
// SCDynamicStoreCopyProxies returns the PRIMARY service's settings at the top
// level and every other configured service under __SCOPED__. The pre-migration
// leg asked for the Wi-Fi service BY NAME, so a top-level-only read is not a
// superset of it: an Ethernet-primary Mac with the proxy on Wi-Fi flipped from
// `proxy_type|http` to `proxy_type|none`, STATUS OK, on an action tagged
// `compliance`.
//
// select_proxy is the DECISION half, split from the CF ACQUISITION half so it
// can be fixture-tested at all (pure core, thin shell).
//
// DECLARED UNTESTED REMAINDER for the whole macOS proxy/DNS surface, so the
// pure-function coverage below is not read as more than it proves:
//   - the __SCOPED__ per-service key enumeration (a live CF dictionary walk);
//   - the SCDynamicStoreCopyKeyList service-key enumeration behind the DNS
//     union;
//   - the CF decode of each proxy dictionary into ProxyServiceConfig.
// Each is a live CoreFoundation read with no fixture surface. The DECISIONS
// they feed (select_proxy, union_dns_servers, join_bypass_list) are pinned.

TEST_CASE("select_proxy reports a non-primary service's proxy when the primary has none",
          "[network_config][proxy]") {
    yuzu::network_config::ProxyServiceConfig primary; // Ethernet, nothing configured
    yuzu::network_config::ProxyServiceConfig wifi;
    wifi.service = "en1";
    wifi.http_enabled = true;
    wifi.http_host = "proxy.corp.example";
    wifi.http_port = 8080;

    const auto choice = yuzu::network_config::select_proxy({primary, wifi});
    // Pre-fix this returned found == false -> "proxy_type|none".
    REQUIRE(choice.found);
    CHECK(choice.type == "http");
    CHECK(choice.address == "proxy.corp.example:8080");
}

TEST_CASE("select_proxy prefers the primary service over a scoped one", "[network_config][proxy]") {
    yuzu::network_config::ProxyServiceConfig primary;
    primary.http_enabled = true;
    primary.http_host = "primary.example";
    primary.http_port = 3128;
    yuzu::network_config::ProxyServiceConfig scoped;
    scoped.service = "en1";
    scoped.http_enabled = true;
    scoped.http_host = "other.example";
    scoped.http_port = 8080;

    const auto choice = yuzu::network_config::select_proxy({primary, scoped});
    REQUIRE(choice.found);
    CHECK(choice.address == "primary.example:3128");
}

TEST_CASE("select_proxy checks HTTP before PAC within one service", "[network_config][proxy]") {
    // The old leg tested -getwebproxy in its IF and reached -getautoproxyurl
    // only in the ELSE, so a host with both configured reported `http`.
    yuzu::network_config::ProxyServiceConfig both;
    both.http_enabled = true;
    both.http_host = "web.example";
    both.http_port = 8080;
    both.pac_enabled = true;
    both.pac_url = "http://pac.example/proxy.pac";

    const auto choice = yuzu::network_config::select_proxy({both});
    REQUIRE(choice.found);
    CHECK(choice.type == "http"); // pre-fix ordering returned "pac"
}

TEST_CASE("select_proxy falls to PAC when HTTP is enabled but hostless, and to none when empty",
          "[network_config][proxy]") {
    yuzu::network_config::ProxyServiceConfig pac_only;
    pac_only.http_enabled = true; // enabled but no host -> not usable
    pac_only.pac_enabled = true;
    pac_only.pac_url = "http://pac.example/proxy.pac";
    const auto pac = yuzu::network_config::select_proxy({pac_only});
    REQUIRE(pac.found);
    CHECK(pac.type == "pac");

    CHECK_FALSE(yuzu::network_config::select_proxy({}).found);
    CHECK_FALSE(
        yuzu::network_config::select_proxy({yuzu::network_config::ProxyServiceConfig{}}).found);
}

// ── REGRESSION PIN: macOS dns_servers supplemental-resolver union ──────────
//
// State:/Network/Global/DNS holds ONLY the primary resolver. The pre-migration
// `scutil --dns` walked every service's own resolver list, so reading the
// global key alone silently dropped VPN split-DNS and secondary-interface
// resolvers -- measured live as 2 of 4 real resolvers missing.
//
// union_dns_servers is the DECISION half. UNTESTED REMAINDER: the
// SCDynamicStoreCopyKeyList enumeration that produces these groups.

TEST_CASE("union_dns_servers keeps supplemental resolvers, global first, deduped",
          "[network_config][dns]") {
    const std::vector<std::vector<std::string>> groups{
        {"100.100.100.100", "fd7a:115c:a1e0::53"}, // global (primary only)
        {"194.168.4.100", "194.168.8.100"},        // a service's own resolvers
        {"194.168.4.100", "100.100.100.100"},      // another service, overlapping
    };
    const auto out = yuzu::network_config::union_dns_servers(groups);
    // Pre-fix (global key only) this was just the first two entries.
    REQUIRE(out.size() == 4);
    CHECK(out[0] == "100.100.100.100"); // global first
    CHECK(out[1] == "fd7a:115c:a1e0::53");
    CHECK(out[2] == "194.168.4.100");
    CHECK(out[3] == "194.168.8.100");
}

TEST_CASE("union_dns_servers handles empty and single-group inputs", "[network_config][dns]") {
    CHECK(yuzu::network_config::union_dns_servers({}).empty());
    CHECK(yuzu::network_config::union_dns_servers({{}, {}}).empty());
    const auto one = yuzu::network_config::union_dns_servers({{"1.1.1.1", "1.1.1.1"}});
    REQUIRE(one.size() == 1);
    CHECK(one[0] == "1.1.1.1");
}

// ── rtnetlink message-set decode (Linux) ─────────────────────────────────

#if defined(__linux__)

#include <cstring>
#include <vector>

namespace {

void append_bytes(std::vector<unsigned char>& buf, const void* data, std::size_t n) {
    const auto* p = static_cast<const unsigned char*>(data);
    buf.insert(buf.end(), p, p + n);
}

// Appends a single rtattr (4-byte header + payload), padded to RTA_ALIGNTO
// (4 bytes) — the standard on-wire attribute framing.
void append_rtattr(std::vector<unsigned char>& buf, unsigned short type, const void* data,
                   std::size_t len) {
    struct rtattr rta {};
    rta.rta_len = static_cast<unsigned short>(RTA_LENGTH(len));
    rta.rta_type = type;
    append_bytes(buf, &rta, sizeof(rta));
    append_bytes(buf, data, len);
    while (buf.size() % RTA_ALIGNTO != 0)
        buf.push_back(0);
}

// Builds one RTM_NEWLINK message: nlmsghdr + ifinfomsg + IFLA_IFNAME +
// (optionally) IFLA_ADDRESS. nlmsg_len is patched in at the end to the
// message's true total size (already 4-aligned, since append_rtattr keeps
// the buffer 4-aligned throughout).
// `oper_state` < 0 omits IFLA_OPERSTATE entirely (the "kernel did not tell us"
// case); `mac_len` lets a test attach a non-6-byte IFLA_ADDRESS, which is what
// a non-Ethernet link (InfiniBand, ip6tnl) really sends.
std::vector<unsigned char> build_link_message(std::uint32_t seq, int index, const char* name,
                                              const unsigned char* mac, bool up,
                                              int oper_state = IF_OPER_UP,
                                              std::size_t mac_len = 6) {
    std::vector<unsigned char> buf;
    struct nlmsghdr nlh {};
    nlh.nlmsg_type = RTM_NEWLINK;
    nlh.nlmsg_flags = NLM_F_MULTI;
    nlh.nlmsg_seq = seq;
    append_bytes(buf, &nlh, sizeof(nlh));

    struct ifinfomsg ifi {};
    ifi.ifi_family = AF_UNSPEC;
    ifi.ifi_type = 1; // ARPHRD_ETHER
    ifi.ifi_index = index;
    ifi.ifi_flags = up ? static_cast<unsigned int>(IFF_UP) : 0u;
    append_bytes(buf, &ifi, sizeof(ifi));

    append_rtattr(buf, IFLA_IFNAME, name, std::strlen(name) + 1);
    if (mac)
        append_rtattr(buf, IFLA_ADDRESS, mac, mac_len);
    if (oper_state >= 0) {
        const auto st = static_cast<unsigned char>(oper_state);
        append_rtattr(buf, IFLA_OPERSTATE, &st, 1);
    }

    auto* hdr = reinterpret_cast<struct nlmsghdr*>(buf.data());
    hdr->nlmsg_len = static_cast<std::uint32_t>(buf.size());
    return buf;
}

std::vector<unsigned char> build_addr_message(std::uint32_t seq, unsigned char family,
                                               unsigned int index, unsigned char prefix_len,
                                               const void* addr_bytes, std::size_t addr_len,
                                               const char* label) {
    std::vector<unsigned char> buf;
    struct nlmsghdr nlh {};
    nlh.nlmsg_type = RTM_NEWADDR;
    nlh.nlmsg_flags = NLM_F_MULTI;
    nlh.nlmsg_seq = seq;
    append_bytes(buf, &nlh, sizeof(nlh));

    struct ifaddrmsg ifa {};
    ifa.ifa_family = family;
    ifa.ifa_prefixlen = prefix_len;
    ifa.ifa_index = index;
    append_bytes(buf, &ifa, sizeof(ifa));

    append_rtattr(buf, IFA_LOCAL, addr_bytes, addr_len);
    if (label)
        append_rtattr(buf, IFA_LABEL, label, std::strlen(label) + 1);

    auto* hdr = reinterpret_cast<struct nlmsghdr*>(buf.data());
    hdr->nlmsg_len = static_cast<std::uint32_t>(buf.size());
    return buf;
}

// `table` is the 8-bit rtm_table field; `rta_table` (when >= 0) additionally
// attaches an RTA_TABLE attribute, which overrides rtm_table for ids > 255.
std::vector<unsigned char> build_route_message(std::uint32_t seq, unsigned char dst_len,
                                                unsigned int flags, const unsigned char* gateway4,
                                                unsigned char table = RT_TABLE_MAIN,
                                                long rta_table = -1) {
    std::vector<unsigned char> buf;
    struct nlmsghdr nlh {};
    nlh.nlmsg_type = RTM_NEWROUTE;
    nlh.nlmsg_flags = NLM_F_MULTI;
    nlh.nlmsg_seq = seq;
    append_bytes(buf, &nlh, sizeof(nlh));

    struct rtmsg rtm {};
    rtm.rtm_family = AF_INET;
    rtm.rtm_dst_len = dst_len;
    rtm.rtm_flags = flags;
    rtm.rtm_table = table;
    append_bytes(buf, &rtm, sizeof(rtm));

    if (gateway4)
        append_rtattr(buf, RTA_GATEWAY, gateway4, 4);
    if (rta_table >= 0) {
        const auto t = static_cast<std::uint32_t>(rta_table);
        append_rtattr(buf, RTA_TABLE, &t, sizeof(t));
    }

    auto* hdr = reinterpret_cast<struct nlmsghdr*>(buf.data());
    hdr->nlmsg_len = static_cast<std::uint32_t>(buf.size());
    return buf;
}

std::vector<unsigned char> build_done_message(std::uint32_t seq) {
    std::vector<unsigned char> buf;
    struct nlmsghdr nlh {};
    nlh.nlmsg_type = NLMSG_DONE;
    nlh.nlmsg_seq = seq;
    nlh.nlmsg_len = sizeof(nlh);
    append_bytes(buf, &nlh, sizeof(nlh));
    return buf;
}

} // namespace

TEST_CASE("parse_rtnetlink_link_chunk decodes two interfaces then NLMSG_DONE",
         "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 42;
    const unsigned char mac1[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    std::vector<unsigned char> blob;
    auto eth0 = build_link_message(kSeq, 2, "eth0", mac1, /*up=*/true);
    auto lo = build_link_message(kSeq, 1, "lo", nullptr, /*up=*/true);
    auto done = build_done_message(kSeq);
    blob.insert(blob.end(), eth0.begin(), eth0.end());
    blob.insert(blob.end(), lo.begin(), lo.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_link_chunk(std::span{blob}, kSeq);
    CHECK(parsed.done);
    CHECK_FALSE(parsed.error);
    CHECK_FALSE(parsed.truncated);
    REQUIRE(parsed.records.size() == 2);
    CHECK(parsed.records[0].name == "eth0");
    CHECK(parsed.records[0].index == 2);
    CHECK(parsed.records[0].mac == "aa:bb:cc:dd:ee:ff");
    CHECK(parsed.records[0].up);
    CHECK(parsed.records[1].name == "lo");
    CHECK(parsed.records[1].mac.empty()); // no IFLA_ADDRESS attached
}

// ── adapters `status` must be OPERATIONAL state, not the IFF_UP admin flag ──
//
// Gate regression: the first migration draft reported `ifi_flags & IFF_UP`.
// The pre-migration leg parsed iproute2's `state <TOKEN>`, which iproute2
// renders from IFLA_OPERSTATE. The two disagree on exactly the hosts that
// matter -- a cable-unplugged NIC and every tun/tap/WireGuard device are
// administratively UP but operationally not -- so the flag would have flipped
// them from "down" to "up" fleet-wide, with every row count unchanged.

TEST_CASE("parse_rtnetlink_link_chunk records IFLA_OPERSTATE separately from IFF_UP",
          "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 7;
    const unsigned char mac1[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    // Administratively UP, operationally LOWERLAYERDOWN: the carrier-down NIC.
    auto msg = build_link_message(kSeq, 2, "eth0", mac1, /*up=*/true,
                                  /*oper_state=*/IF_OPER_LOWERLAYERDOWN);
    auto done = build_done_message(kSeq);
    std::vector<unsigned char> blob;
    blob.insert(blob.end(), msg.begin(), msg.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_link_chunk(std::span{blob}, kSeq);
    REQUIRE(parsed.records.size() == 1);
    CHECK(parsed.records[0].up); // IFF_UP is set ...
    CHECK(parsed.records[0].oper_state == IF_OPER_LOWERLAYERDOWN); // ... but carrier is down
    // The emitted field must follow the OPERATIONAL state.
    CHECK(std::string{link_status_string(parsed.records[0])} == "down");
}

TEST_CASE("link_status_string reports up only for IF_OPER_UP", "[network_config][rtnetlink]") {
    yuzu::network_config::RtLinkRecord rec;
    rec.up = true; // admin-up throughout: only oper_state may move the answer

    rec.oper_state = IF_OPER_UP;
    CHECK(std::string{link_status_string(rec)} == "up");

    // Every other operational state mapped to "down" in the old leg, including
    // IF_OPER_UNKNOWN, which is what tun/tap/WireGuard devices report.
    for (int st : {IF_OPER_UNKNOWN, IF_OPER_NOTPRESENT, IF_OPER_DOWN, IF_OPER_LOWERLAYERDOWN,
                   IF_OPER_TESTING, IF_OPER_DORMANT}) {
        rec.oper_state = st;
        CHECK(std::string{link_status_string(rec)} == "down");
    }

    // Attribute ABSENT (oper_state == -1) is a different case from an
    // ATTACHED IF_OPER_UNKNOWN value (0), tested above. The kernel always
    // attaches IFLA_OPERSTATE in practice, so this is defensive: the old
    // leg's `status` variable kept its own initialiser, "unknown", when no
    // `state` token appeared at all -- link_status_string matches that
    // initialiser exactly, not the administrative flag and not a fabricated
    // "down" (see the CLA-9 finding: an earlier version of this function and
    // this test both asserted "down" here on an unverified claim about how
    // iproute2 renders a missing attribute).
    rec.oper_state = -1;
    CHECK(std::string{link_status_string(rec)} == "unknown");
}

TEST_CASE("parse_rtnetlink_link_chunk never fabricates a MAC from a non-6-byte IFLA_ADDRESS",
          "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 9;
    // A 20-byte InfiniBand hardware address. Truncating it to 6 bytes would
    // emit a plausible-looking MAC that is not this interface's address; the
    // old leg reported "-" because it only read iproute2's `link/ether`.
    const unsigned char ib[20] = {0x80, 0x00, 0x02, 0x08, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0xf4, 0x52, 0x14, 0x03, 0x00, 0x7b, 0xcb, 0xa1};
    auto msg = build_link_message(kSeq, 3, "ib0", ib, /*up=*/true, /*oper_state=*/IF_OPER_UP,
                                  /*mac_len=*/sizeof(ib));
    auto done = build_done_message(kSeq);
    std::vector<unsigned char> blob;
    blob.insert(blob.end(), msg.begin(), msg.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_link_chunk(std::span{blob}, kSeq);
    REQUIRE(parsed.records.size() == 1);
    CHECK(parsed.records[0].name == "ib0");
    CHECK(parsed.records[0].mac.empty()); // unresolved, never a truncated guess
}

TEST_CASE("parse_rtnetlink_link_chunk discards a reply whose nlmsg_seq doesn't match",
         "[network_config][rtnetlink]") {
    const unsigned char mac1[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    auto stale = build_link_message(/*seq=*/1, 2, "eth0", mac1, true);
    auto done = build_done_message(/*seq=*/2);
    std::vector<unsigned char> blob(stale.begin(), stale.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_link_chunk(std::span{blob}, /*expected_seq=*/2);
    CHECK(parsed.done);
    CHECK(parsed.records.empty()); // the seq=1 reply was discarded, not decoded
}

TEST_CASE("parse_rtnetlink_link_chunk reports truncation, never a crash, on malformed input",
         "[network_config][rtnetlink]") {
    SECTION("empty blob") {
        std::vector<unsigned char> blob;
        const auto parsed = parse_rtnetlink_link_chunk(std::span{blob}, 1);
        CHECK(parsed.records.empty());
        CHECK_FALSE(parsed.truncated); // nothing at all is a clean (if pointless) read
        CHECK_FALSE(parsed.done);
    }

    SECTION("shorter than one nlmsghdr") {
        std::vector<unsigned char> blob(4, 0);
        const auto parsed = parse_rtnetlink_link_chunk(std::span{blob}, 1);
        CHECK(parsed.records.empty());
        CHECK(parsed.truncated);
    }

    SECTION("nlmsg_len claims more than the buffer has left") {
        const unsigned char mac1[6] = {1, 2, 3, 4, 5, 6};
        auto msg = build_link_message(1, 2, "eth0", mac1, true);
        std::vector<unsigned char> blob(msg.begin(), msg.begin() + 20); // cut mid-message
        const auto parsed = parse_rtnetlink_link_chunk(std::span{blob}, 1);
        CHECK(parsed.records.empty());
        CHECK(parsed.truncated);
    }
}

TEST_CASE("parse_rtnetlink_link_chunk flags truncation on a short-fixed-payload RTM_NEWLINK "
         "instead of silently skipping it and believing a later NLMSG_DONE",
         "[network_config][rtnetlink]") {
    // A well-formed nlmsghdr (passes NLMSG_OK) whose nlmsg_len is shorter than
    // the fixed ifinfomsg every real RTM_NEWLINK must carry -- a malformed
    // dump, not a record that is safe to skip and move past. Before the fix
    // this `continue`d to the NLMSG_DONE that follows and returned
    // done=true/truncated=false over a silently smaller result.
    struct nlmsghdr nlh {};
    nlh.nlmsg_type = RTM_NEWLINK;
    nlh.nlmsg_flags = NLM_F_MULTI;
    nlh.nlmsg_seq = 1;
    nlh.nlmsg_len = static_cast<std::uint32_t>(sizeof(nlh) + 4); // < NLMSG_LENGTH(sizeof(ifinfomsg))
    std::vector<unsigned char> blob;
    append_bytes(blob, &nlh, sizeof(nlh));
    blob.resize(nlh.nlmsg_len, 0); // pad out to the (short) claimed length

    auto done = build_done_message(1);
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_link_chunk(std::span{blob}, 1);
    CHECK(parsed.records.empty());
    CHECK(parsed.truncated);
    CHECK_FALSE(parsed.done); // must not walk past the short record to the DONE
}

TEST_CASE("parse_rtnetlink_addr_chunk prefers IFA_LOCAL and captures IFA_LABEL",
         "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 7;
    const unsigned char addr4[4] = {192, 168, 1, 50};
    auto msg = build_addr_message(kSeq, AF_INET, 2, 24, addr4, sizeof(addr4), "eth0");
    auto done = build_done_message(kSeq);
    std::vector<unsigned char> blob(msg.begin(), msg.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_addr_chunk(std::span{blob}, kSeq);
    CHECK(parsed.done);
    REQUIRE(parsed.records.size() == 1);
    CHECK(parsed.records[0].address == "192.168.1.50");
    CHECK(parsed.records[0].label == "eth0");
    CHECK(parsed.records[0].prefix_len == 24);
    CHECK_FALSE(parsed.records[0].is_ipv6);
}

TEST_CASE("parse_rtnetlink_addr_chunk decodes an IPv6 address without a label",
         "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 8;
    const unsigned char addr6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    auto msg = build_addr_message(kSeq, AF_INET6, 3, 64, addr6, sizeof(addr6), nullptr);
    std::vector<unsigned char> blob(msg.begin(), msg.end());
    auto done = build_done_message(kSeq);
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_addr_chunk(std::span{blob}, kSeq);
    REQUIRE(parsed.records.size() == 1);
    CHECK(parsed.records[0].address == "2001:db8::1");
    CHECK(parsed.records[0].label.empty());
    CHECK(parsed.records[0].is_ipv6);
}

TEST_CASE("parse_rtnetlink_addr_chunk flags truncation on a short-fixed-payload RTM_NEWADDR "
         "instead of silently skipping it and believing a later NLMSG_DONE",
         "[network_config][rtnetlink]") {
    // See parse_rtnetlink_link_chunk's identical fixture above -- same bug,
    // same fix, the other message type.
    struct nlmsghdr nlh {};
    nlh.nlmsg_type = RTM_NEWADDR;
    nlh.nlmsg_flags = NLM_F_MULTI;
    nlh.nlmsg_seq = 1;
    nlh.nlmsg_len = static_cast<std::uint32_t>(sizeof(nlh) + 4); // < NLMSG_LENGTH(sizeof(ifaddrmsg))
    std::vector<unsigned char> blob;
    append_bytes(blob, &nlh, sizeof(nlh));
    blob.resize(nlh.nlmsg_len, 0);

    auto done = build_done_message(1);
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_addr_chunk(std::span{blob}, 1);
    CHECK(parsed.records.empty());
    CHECK(parsed.truncated);
    CHECK_FALSE(parsed.done);
}

// Builds a default route with NO top-level RTA_GATEWAY, carrying an
// RTA_MULTIPATH attribute instead: an array of rtnexthop structs, each
// optionally followed by its own nested RTA_GATEWAY. A nullptr entry models a
// nexthop that itself carries no gateway (skipped when searching for the
// first resolvable one).
std::vector<unsigned char>
build_multipath_route_message(std::uint32_t seq, const std::vector<const unsigned char*>& gateways,
                              unsigned char table = RT_TABLE_MAIN) {
    std::vector<unsigned char> buf;
    struct nlmsghdr nlh {};
    nlh.nlmsg_type = RTM_NEWROUTE;
    nlh.nlmsg_flags = NLM_F_MULTI;
    nlh.nlmsg_seq = seq;
    append_bytes(buf, &nlh, sizeof(nlh));

    struct rtmsg rtm {};
    rtm.rtm_family = AF_INET;
    rtm.rtm_dst_len = 0;
    rtm.rtm_table = table;
    append_bytes(buf, &rtm, sizeof(rtm));

    std::vector<unsigned char> mp;
    for (const auto* gw : gateways) {
        std::vector<unsigned char> nh_attrs;
        if (gw)
            append_rtattr(nh_attrs, RTA_GATEWAY, gw, 4);
        struct rtnexthop rtnh {};
        rtnh.rtnh_len = static_cast<unsigned short>(sizeof(rtnh) + nh_attrs.size());
        append_bytes(mp, &rtnh, sizeof(rtnh));
        mp.insert(mp.end(), nh_attrs.begin(), nh_attrs.end());
        while (mp.size() % 4)
            mp.push_back(0);
    }
    append_rtattr(buf, RTA_MULTIPATH, mp.data(), mp.size());

    auto* hdr = reinterpret_cast<struct nlmsghdr*>(buf.data());
    hdr->nlmsg_len = static_cast<std::uint32_t>(buf.size());
    return buf;
}

// Builds an `ip nexthop`-object default route: RTA_NH_ID referencing a
// nexthop group by id, with no embedded gateway of any form.
std::vector<unsigned char> build_nh_id_route_message(std::uint32_t seq, std::uint32_t nh_id,
                                                      unsigned char table = RT_TABLE_MAIN) {
    std::vector<unsigned char> buf;
    struct nlmsghdr nlh {};
    nlh.nlmsg_type = RTM_NEWROUTE;
    nlh.nlmsg_flags = NLM_F_MULTI;
    nlh.nlmsg_seq = seq;
    append_bytes(buf, &nlh, sizeof(nlh));

    struct rtmsg rtm {};
    rtm.rtm_family = AF_INET;
    rtm.rtm_dst_len = 0;
    rtm.rtm_table = table;
    append_bytes(buf, &rtm, sizeof(rtm));

    append_rtattr(buf, RTA_NH_ID, &nh_id, sizeof(nh_id));

    auto* hdr = reinterpret_cast<struct nlmsghdr*>(buf.data());
    hdr->nlmsg_len = static_cast<std::uint32_t>(buf.size());
    return buf;
}


// Builds a RAW (possibly malformed) RTA_MULTIPATH payload from a list of
// (rtnh_len, ifindex) pairs -- no padding, no validation, exactly the bytes
// given. Lets a test construct a payload the real encoder could never
// produce, to prove the decoder degrades honestly against one anyway.
// Writes ONLY the raw rtnexthop headers back to back -- no fake payload
// padded out to match a lying rtnh_len. This is the real attack shape: a
// header whose declared length overclaims relative to what is ACTUALLY
// allocated after it. Padding to the claimed length (an earlier version of
// this builder did) would back the lie with real bytes and defeat the very
// out-of-bounds condition the fixture exists to create.
std::vector<unsigned char> build_raw_multipath_route(std::uint32_t seq,
                                                      const std::vector<unsigned short>& nh_lens) {
    std::vector<unsigned char> buf;
    struct nlmsghdr nlh {};
    nlh.nlmsg_type = RTM_NEWROUTE;
    nlh.nlmsg_flags = NLM_F_MULTI;
    nlh.nlmsg_seq = seq;
    append_bytes(buf, &nlh, sizeof(nlh));

    struct rtmsg rtm {};
    rtm.rtm_family = AF_INET;
    rtm.rtm_dst_len = 0;
    rtm.rtm_table = RT_TABLE_MAIN;
    append_bytes(buf, &rtm, sizeof(rtm));

    std::vector<unsigned char> mp;
    for (auto len : nh_lens) {
        struct rtnexthop rtnh {};
        rtnh.rtnh_len = len; // may lie -- no payload is written to back it
        append_bytes(mp, &rtnh, sizeof(rtnh));
    }
    append_rtattr(buf, RTA_MULTIPATH, mp.data(), mp.size());

    auto* hdr = reinterpret_cast<struct nlmsghdr*>(buf.data());
    hdr->nlmsg_len = static_cast<std::uint32_t>(buf.size());
    return buf;
}


TEST_CASE("parse_rtnetlink_route_chunk keeps only the IPv4 default route with a gateway",
         "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 9;
    const unsigned char gw[4] = {192, 168, 1, 1};
    // The parser's actual discriminator is dst_len==0 (a default route) plus
    // an RTA_GATEWAY attribute being present -- rtm_flags isn't consulted
    // (unlike the macOS PF_ROUTE decoder below, which does check RTF_GATEWAY
    // in the rtm_flags field; rtnetlink's rtm_flags carries a different,
    // unrelated flag namespace). `flags` here is just passed through
    // unexamined.
    auto default_route = build_route_message(kSeq, /*dst_len=*/0, /*flags=*/0, gw);
    auto specific_route = build_route_message(kSeq, /*dst_len=*/24, /*flags=*/0, nullptr);
    auto done = build_done_message(kSeq);

    std::vector<unsigned char> blob(specific_route.begin(), specific_route.end());
    blob.insert(blob.end(), default_route.begin(), default_route.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_route_chunk(std::span{blob}, kSeq);
    CHECK(parsed.done);
    REQUIRE(parsed.records.size() == 1); // the /24 route (no dst_len==0) never qualifies
    CHECK(parsed.records[0].gateway == "192.168.1.1");
}

// ── REGRESSION PIN: main-table-only default-route selection ────────────────
//
// An NLM_F_DUMP RTM_GETROUTE returns default routes from EVERY routing table,
// and the kernel emits non-main tables FIRST -- verified live: with
// `ip route add default via 172.17.0.99 table 100` alongside main's
// 172.17.0.1, the unfiltered dump returned the table-100 route at index 0.
// The caller takes records.front(), so an unfiltered decoder does not merely
// risk the wrong gateway, it actively prefers it, and stamps that VPN/policy
// gateway onto every emitted ip| row. The pre-migration leg ran unqualified
// `ip route show default`, which shows the main table alone.
//
// The non-main route is deliberately placed FIRST in this fixture: in
// main-first order the test would pass with or without the filter and would
// therefore prove nothing.

TEST_CASE("parse_rtnetlink_route_chunk ignores a policy-table default that precedes main's",
          "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 11;
    const unsigned char vpn_gw[4] = {172, 17, 0, 99};  // table 100 (policy)
    const unsigned char main_gw[4] = {172, 17, 0, 1};  // table main

    // Non-main FIRST, exactly as the kernel dumps it.
    auto policy_route =
        build_route_message(kSeq, /*dst_len=*/0, /*flags=*/0, vpn_gw, /*table=*/100);
    auto main_route =
        build_route_message(kSeq, /*dst_len=*/0, /*flags=*/0, main_gw, /*table=*/RT_TABLE_MAIN);
    auto done = build_done_message(kSeq);

    std::vector<unsigned char> blob(policy_route.begin(), policy_route.end());
    blob.insert(blob.end(), main_route.begin(), main_route.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_route_chunk(std::span{blob}, kSeq);
    CHECK(parsed.done);
    REQUIRE(parsed.records.size() == 1);
    // Pre-fix this was "172.17.0.99" -- the tunnel endpoint.
    CHECK(parsed.records[0].gateway == "172.17.0.1");
}

TEST_CASE("parse_rtnetlink_route_chunk honours an RTA_TABLE override above 255",
          "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 12;
    const unsigned char big_table_gw[4] = {10, 8, 0, 1};
    const unsigned char main_gw[4] = {192, 168, 0, 1};

    // rtm_table cannot hold 51820 (WireGuard's default), so the kernel sets
    // rtm_table to RT_TABLE_UNSPEC and carries the real id in RTA_TABLE.
    // Reading rtm_table alone would see UNSPEC != MAIN and drop it correctly
    // here -- but the mirror case matters: a route whose rtm_table says
    // RT_TABLE_MAIN while RTA_TABLE overrides it to a policy table must be
    // dropped on the ATTRIBUTE, which is why the override is read at all.
    auto wg_route = build_route_message(kSeq, /*dst_len=*/0, /*flags=*/0, big_table_gw,
                                        /*table=*/RT_TABLE_MAIN, /*rta_table=*/51820);
    auto main_route =
        build_route_message(kSeq, /*dst_len=*/0, /*flags=*/0, main_gw, /*table=*/RT_TABLE_MAIN);
    auto done = build_done_message(kSeq);

    std::vector<unsigned char> blob(wg_route.begin(), wg_route.end());
    blob.insert(blob.end(), main_route.begin(), main_route.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_route_chunk(std::span{blob}, kSeq);
    REQUIRE(parsed.records.size() == 1);
    CHECK(parsed.records[0].gateway == "192.168.0.1");
}

// ── REGRESSION PIN: veth/VLAN adapter name carries no iproute2 @peer suffix ─
//
// The pre-migration leg took the adapter name from `ip -o link show`'s second
// column, which iproute2 renders as "<name>@<parent>" whenever IFLA_LINK is
// set -- so a container's veth read as "eth0@if74" and a VLAN as
// "eth0.100@eth0". This branch emits IFLA_IFNAME, which never carries the
// suffix, and that is the DELIBERATE, DISCLOSED choice: "eth0@if74" is
// iproute2 display syntax, not a name the kernel or any other data source
// recognises, and the old sysfs speed lookup at /sys/class/net/eth0@if74/speed
// could never resolve. This pins the decision so a future "restore parity"
// change cannot silently reintroduce the suffix.
TEST_CASE("parse_rtnetlink_link_chunk emits the kernel name, never iproute2's @peer form",
          "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 13;
    const unsigned char mac[6] = {0xce, 0xb6, 0x11, 0x22, 0x33, 0x44};
    // IFLA_LINK present is exactly the condition under which iproute2 renders
    // the suffix; the decoder must still report the bare name.
    auto msg = build_link_message(kSeq, 74, "eth0", mac, /*up=*/true, IF_OPER_UP, /*mac_len=*/6);
    {
        // Append IFLA_LINK (parent ifindex) to the message and re-patch len.
        const std::uint32_t parent = 2;
        append_rtattr(msg, IFLA_LINK, &parent, sizeof(parent));
        auto* hdr = reinterpret_cast<struct nlmsghdr*>(msg.data());
        hdr->nlmsg_len = static_cast<std::uint32_t>(msg.size());
    }
    auto done = build_done_message(kSeq);
    std::vector<unsigned char> blob(msg.begin(), msg.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_link_chunk(std::span{blob}, kSeq);
    REQUIRE(parsed.records.size() == 1);
    CHECK(parsed.records[0].name == "eth0"); // NOT "eth0@if2"
    CHECK(parsed.records[0].name.find('@') == std::string::npos);
}

// ── REGRESSION PIN: multipath / nexthop-object default routes ──────────────
//
// A route decoder reading only the top-level RTA_GATEWAY silently regresses
// every ECMP or `ip nexthop`-object host to "-": neither form carries a
// top-level RTA_GATEWAY. The pre-migration leg searched the whole
// `ip route show default` TEXT for "via ", which matches the first
// `nexthop via ...` line of a multipath route's iproute2 rendering, so those
// hosts DID report a gateway before. Cross-platform review (gate 3) found
// this as the seventh silent regression on this branch.

TEST_CASE("parse_rtnetlink_route_chunk resolves the first nexthop's gateway in a "
          "multipath default route",
          "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 20;
    const unsigned char gw1[4] = {10, 0, 0, 1};
    const unsigned char gw2[4] = {10, 0, 0, 2};
    auto msg = build_multipath_route_message(kSeq, {gw1, gw2});
    auto done = build_done_message(kSeq);
    std::vector<unsigned char> blob(msg.begin(), msg.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_route_chunk(std::span{blob}, kSeq);
    CHECK(parsed.done);
    REQUIRE(parsed.records.size() == 1);
    // Pre-fix (RTA_GATEWAY only) this record never made it into the output at
    // all -- the route was silently dropped, and do_ip_addresses fell back to
    // "-" with a complete status.
    CHECK(parsed.records[0].gateway == "10.0.0.1");
}

TEST_CASE("parse_rtnetlink_route_chunk skips a gateway-less nexthop and resolves the next",
          "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 21;
    const unsigned char gw2[4] = {10, 0, 0, 2};
    // First nexthop carries no RTA_GATEWAY of its own (nullptr); the decoder
    // must not stop there.
    auto msg = build_multipath_route_message(kSeq, {nullptr, gw2});
    auto done = build_done_message(kSeq);
    std::vector<unsigned char> blob(msg.begin(), msg.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_route_chunk(std::span{blob}, kSeq);
    REQUIRE(parsed.records.size() == 1);
    CHECK(parsed.records[0].gateway == "10.0.0.2");
}

TEST_CASE("parse_rtnetlink_route_chunk pushes a gateway-less marker for an "
          "`ip nexthop`-object route",
          "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 22;
    auto msg = build_nh_id_route_message(kSeq, /*nh_id=*/1);
    auto done = build_done_message(kSeq);
    std::vector<unsigned char> blob(msg.begin(), msg.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_route_chunk(std::span{blob}, kSeq);
    // A record IS pushed (so the caller learns a main-table default route
    // exists) but its gateway is empty (so the caller does not silently
    // report "-" with a complete status -- it must degrade instead).
    REQUIRE(parsed.records.size() == 1);
    CHECK(parsed.records[0].gateway.empty());
}

// ── REGRESSION PIN: malformed RTA_MULTIPATH must degrade, never overread ───
//
// RTNH_NEXT, unlike RTA_NEXT, does not decrement a length variable as a side
// effect -- the caller must. An earlier draft of the multipath decode above
// did not, so RTNH_OK's bound check on every nexthop after the first
// compared against the ORIGINAL total length rather than what was actually
// left: a crafted rtnh_len on a later nexthop could pass the check while
// pointing past the real payload. Fixed by tracking the remaining length
// explicitly. These three cases exercise exactly the malformed shapes that
// would have exploited the bug, plus the two RTNH_OK already rejects
// unconditionally.

TEST_CASE("parse_rtnetlink_route_chunk stops cleanly when a later nexthop's "
          "rtnh_len would overrun the real remaining payload",
          "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 23;
    // Reproduces the exact bug shape: a well-formed first nexthop (rtnh_len=8,
    // no sub-attributes, genuinely 8 bytes on the wire) followed by a second
    // whose rtnh_len (12) claims 4 bytes of sub-attribute payload that were
    // NEVER WRITTEN -- build_raw_multipath_route writes raw headers only, no
    // padding to match a lying length, so those 4 bytes plus the outer
    // rtattr's own 4-byte header the decoder tries to read genuinely do not
    // exist in this allocation.
    //
    // No NLMSG_DONE is appended and the span covers exactly this message's
    // bytes: the old bug's overread would land past this vector's actual
    // heap allocation, not merely into adjacent-but-still-allocated data, so
    // ASan's heap-buffer-overflow detector is a real witness here, not a
    // no-op. (An earlier version of this fixture padded the buffer out to
    // match the claimed length and appended a trailing DONE message, which
    // silently defeated itself -- the "attack" bytes were always genuinely
    // allocated, so ASan had nothing to catch. Recorded so the mistake is
    // not repeated.)
    const auto grown = build_raw_multipath_route(kSeq, {8, 12});
    // build_raw_multipath_route assembles its result via push_back/insert, so
    // the vector's CAPACITY is very likely larger than its SIZE -- growth
    // slack that is allocated but unpoisoned, so a 1-2 byte overread past the
    // logical end would silently land there and ASan would report nothing,
    // proving nothing either way. Copy into a vector sized to exactly fit: a
    // single-shot allocation of a known size has no such slack, so a real
    // heap-buffer-overflow is guaranteed to fall in ASan's redzone.
    const std::vector<unsigned char> msg(grown.begin(), grown.end());
    REQUIRE(msg.capacity() < msg.size() + 16); // sanity: this really is tight

    // Must not crash, hang, or (under ASan) report an out-of-bounds read.
    // Fixed: RTNH_OK on the second entry now correctly sees only the 8 bytes
    // actually left after consuming the first (12 > 8), rejects it, and the
    // walk stops with no gateway resolved from either nexthop. `done` stays
    // false since no NLMSG_DONE was supplied -- irrelevant to this fixture.
    const auto parsed = parse_rtnetlink_route_chunk(std::span{msg}, kSeq);
    REQUIRE(parsed.records.size() == 1);
    CHECK(parsed.records[0].gateway.empty());
}

TEST_CASE("parse_rtnetlink_route_chunk rejects an rtnh_len shorter than sizeof(rtnexthop)",
          "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 24;
    // RTNH_OK's own built-in check (rtnh_len >= sizeof(rtnexthop)) rejects
    // this regardless of the length-tracking fix; pinned so a future change
    // to that check is also caught.
    auto msg = build_raw_multipath_route(kSeq, {4}); // sizeof(rtnexthop) is 8
    auto done = build_done_message(kSeq);
    std::vector<unsigned char> blob(msg.begin(), msg.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_route_chunk(std::span{blob}, kSeq);
    REQUIRE(parsed.records.size() == 1);
    CHECK(parsed.records[0].gateway.empty());
}

TEST_CASE("parse_rtnetlink_route_chunk rejects an rtnh_len of zero", "[network_config][rtnetlink]") {
    constexpr std::uint32_t kSeq = 25;
    // rtnh_len == 0 is also caught by RTNH_OK's >= sizeof(rtnexthop) check;
    // the real hazard it additionally guards against is an infinite loop --
    // a zero advance would never make RTNH_NEXT progress.
    auto msg = build_raw_multipath_route(kSeq, {0});
    auto done = build_done_message(kSeq);
    std::vector<unsigned char> blob(msg.begin(), msg.end());
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_route_chunk(std::span{blob}, kSeq);
    REQUIRE(parsed.records.size() == 1);
    CHECK(parsed.records[0].gateway.empty());
}

TEST_CASE("parse_rtnetlink_route_chunk flags truncation on a short-fixed-payload RTM_NEWROUTE "
         "instead of silently skipping it and believing a later NLMSG_DONE",
         "[network_config][rtnetlink]") {
    // See parse_rtnetlink_link_chunk's identical fixture further up -- same
    // bug, same fix, the third message type.
    struct nlmsghdr nlh {};
    nlh.nlmsg_type = RTM_NEWROUTE;
    nlh.nlmsg_flags = NLM_F_MULTI;
    nlh.nlmsg_seq = 1;
    nlh.nlmsg_len = static_cast<std::uint32_t>(sizeof(nlh) + 4); // < NLMSG_LENGTH(sizeof(rtmsg))
    std::vector<unsigned char> blob;
    append_bytes(blob, &nlh, sizeof(nlh));
    blob.resize(nlh.nlmsg_len, 0);

    auto done = build_done_message(1);
    blob.insert(blob.end(), done.begin(), done.end());

    const auto parsed = parse_rtnetlink_route_chunk(std::span{blob}, 1);
    CHECK(parsed.records.empty());
    CHECK(parsed.truncated);
    CHECK_FALSE(parsed.done);
}

#endif // __linux__

// ── PF_ROUTE default-route decode (macOS) ────────────────────────────────

#if defined(__APPLE__)

#include <cstring>
#include <vector>

namespace {

std::vector<unsigned char> build_default_route_blob(const unsigned char* gateway4,
                                                     bool set_gateway_flag = true) {
    std::vector<unsigned char> buf;
    rt_msghdr hdr{};
    hdr.rtm_version = RTM_VERSION;
    hdr.rtm_type = RTM_GET;
    hdr.rtm_addrs = (1 << RTAX_DST) | (1 << RTAX_GATEWAY);
    hdr.rtm_flags = set_gateway_flag ? RTF_GATEWAY : 0;

    struct sockaddr_in dst {};
    dst.sin_len = sizeof(dst);
    dst.sin_family = AF_INET; // 0.0.0.0 -- the default route's destination

    struct sockaddr_in gw {};
    gw.sin_len = sizeof(gw);
    gw.sin_family = AF_INET;
    std::memcpy(&gw.sin_addr, gateway4, 4);

    hdr.rtm_msglen =
        static_cast<u_short>(sizeof(hdr) + sizeof(dst) + sizeof(gw));

    const auto* hdr_bytes = reinterpret_cast<const unsigned char*>(&hdr);
    buf.insert(buf.end(), hdr_bytes, hdr_bytes + sizeof(hdr));
    const auto* dst_bytes = reinterpret_cast<const unsigned char*>(&dst);
    buf.insert(buf.end(), dst_bytes, dst_bytes + sizeof(dst));
    const auto* gw_bytes = reinterpret_cast<const unsigned char*>(&gw);
    buf.insert(buf.end(), gw_bytes, gw_bytes + sizeof(gw));
    return buf;
}

} // namespace

TEST_CASE("parse_default_route_dump finds the IPv4 default route's gateway",
         "[network_config][pf_route]") {
    const unsigned char gw[4] = {10, 0, 0, 1};
    auto blob = build_default_route_blob(gw);

    const auto parsed = parse_default_route_dump(std::span{blob});
    CHECK(parsed.found);
    CHECK(parsed.gateway == "10.0.0.1");
    CHECK_FALSE(parsed.truncated);
}

TEST_CASE("parse_default_route_dump ignores a non-default/non-gateway record",
         "[network_config][pf_route]") {
    const unsigned char gw[4] = {10, 0, 0, 1};
    auto blob = build_default_route_blob(gw, /*set_gateway_flag=*/false); // no RTF_GATEWAY

    const auto parsed = parse_default_route_dump(std::span{blob});
    CHECK_FALSE(parsed.found);
    CHECK(parsed.gateway.empty());
}

TEST_CASE("parse_default_route_dump reports truncation honestly on malformed input, never a crash",
         "[network_config][pf_route]") {
    SECTION("empty blob") {
        std::vector<unsigned char> blob;
        const auto parsed = parse_default_route_dump(std::span{blob});
        CHECK_FALSE(parsed.found);
        CHECK_FALSE(parsed.truncated); // nothing at all is a clean (if pointless) read
    }

    SECTION("rtm_msglen == 0") {
        const unsigned char gw[4] = {10, 0, 0, 1};
        auto blob = build_default_route_blob(gw);
        rt_msghdr hdr{};
        std::memcpy(&hdr, blob.data(), sizeof(hdr));
        hdr.rtm_msglen = 0;
        std::memcpy(blob.data(), &hdr, sizeof(hdr));
        const auto parsed = parse_default_route_dump(std::span{blob});
        CHECK_FALSE(parsed.found);
        CHECK(parsed.truncated);
    }

    SECTION("rtm_msglen extends past the buffer end") {
        const unsigned char gw[4] = {10, 0, 0, 1};
        auto full = build_default_route_blob(gw);
        std::vector<unsigned char> blob(full.begin(), full.begin() + sizeof(rt_msghdr) + 2);
        const auto parsed = parse_default_route_dump(std::span{blob});
        CHECK_FALSE(parsed.found);
        CHECK(parsed.truncated);
    }

    SECTION("unrecognised rtm_version stops the walk") {
        const unsigned char gw[4] = {10, 0, 0, 1};
        auto blob = build_default_route_blob(gw);
        rt_msghdr hdr{};
        std::memcpy(&hdr, blob.data(), sizeof(hdr));
        hdr.rtm_version = static_cast<unsigned char>(RTM_VERSION + 1);
        std::memcpy(blob.data(), &hdr, sizeof(hdr));
        const auto parsed = parse_default_route_dump(std::span{blob});
        CHECK_FALSE(parsed.found);
        CHECK(parsed.truncated);
    }
}

#endif // __APPLE__
