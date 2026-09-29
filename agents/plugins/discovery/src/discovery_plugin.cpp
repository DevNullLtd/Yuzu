/**
 * discovery_plugin.cpp — Network device discovery plugin for Yuzu
 *
 * Actions:
 *   "scan_subnet" — ARP scan + ping sweep of a subnet to find hosts.
 *
 * Output is pipe-delimited via write_output():
 *   host|ip_address|mac_address|hostname|managed
 *
 * Platform support (zero spawn sites, all native/rung 1):
 *   Windows — GetIpNetTable2 ARP read + IcmpSendEcho ping sweep.
 *   Linux   — /proc/net/arp read + unprivileged SOCK_DGRAM ICMP ping sweep
 *             (net.ipv4.ping_group_range-gated; see the honest-degrade
 *             branch in do_scan_subnet for the CONSTRAINED/UNAVAILABLE
 *             fallback when the kernel refuses the socket).
 *   macOS   — sysctl NET_RT_FLAGS/RTF_LLINFO ARP read + SOCK_DGRAM ICMP
 *             ping sweep.
 *
 * Input validation: the subnet parameter is validated as a CIDR block —
 * digits, dots and a single slash only (is_valid_cidr), then re-parsed into
 * octets and a prefix length. There is no longer a shell to inject into (the
 * action spawns nothing at all); the validation is retained because every
 * downstream step — host enumeration, inet_pton, the ICMP destination — is
 * entitled to assume a well-formed dotted quad.
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field (governance Gate 2)

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h> // GetIpNetTable2 / MIB_IPNET_ROW2 (tar_arp_collector.cpp precedent)
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include "icmp_probe.hpp" // yuzu::shared::IcmpSession — shared unprivileged ping sweep

#include "bounded_wait.hpp"        // yuzu::shared::bounded_call — uncancellable-call timeout
#include "discovery_scan_plan.hpp" // pure sweep bounds + honest-degrade decisions

// Portable (no platform guard of its own): parse_proc_net_arp for the Linux
// leg, format_mac48 + is_resolved_arp_row for the Windows leg.
#include "discovery_parsers.hpp"

#ifdef _WIN32
// Pin discovery_parsers.hpp's portable ArpRowStateMirror values against the
// real NL_NEIGHBOR_STATE enum (governance-deferred #3249) — is_resolved_arp_row
// is fixture-tested off-Windows against literal ints because this header has
// no <netioapi.h> dependency; these static_asserts are what makes that safe:
// if a future Windows SDK ever renumbered the enum, this build breaks loudly
// here rather than get_arp_table() silently misclassifying every row.
static_assert(static_cast<int>(NlnsUnreachable) == yuzu::discovery::kNlnsUnreachable);
static_assert(static_cast<int>(NlnsIncomplete) == yuzu::discovery::kNlnsIncomplete);
static_assert(static_cast<int>(NlnsProbe) == yuzu::discovery::kNlnsProbe);
static_assert(static_cast<int>(NlnsDelay) == yuzu::discovery::kNlnsDelay);
static_assert(static_cast<int>(NlnsStale) == yuzu::discovery::kNlnsStale);
static_assert(static_cast<int>(NlnsReachable) == yuzu::discovery::kNlnsReachable);
static_assert(static_cast<int>(NlnsPermanent) == yuzu::discovery::kNlnsPermanent);
static_assert(static_cast<int>(NlnsMaximum) == yuzu::discovery::kNlnsMaximum);
#endif

#ifdef __APPLE__
#include "route_sysctl_arp.hpp" // yuzu::shared::{fetch,parse}_rt_flags_llinfo — sysctl ARP read
#endif

namespace {

// ── Input sanitization ────────────────────────────────────────────────────────

/**
 * Validate that a string looks like a CIDR subnet (e.g., "192.168.1.0/24").
 * Only allows digits, dots, and slash.
 */
bool is_valid_cidr(std::string_view s) {
    if (s.empty() || s.size() > 18) return false;
    int dots = 0, slashes = 0;
    for (char c : s) {
        if (c >= '0' && c <= '9') continue;
        if (c == '.') { ++dots; continue; }
        if (c == '/') { ++slashes; continue; }
        return false; // invalid character
    }
    return dots == 3 && slashes == 1;
}

/**
 * Parse subnet into base IP and prefix length.
 * Returns false if invalid.
 */
bool parse_cidr(std::string_view cidr, uint32_t& base_ip, int& prefix_len) {
    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string_view::npos) return false;

    auto ip_str = cidr.substr(0, slash_pos);
    auto prefix_str = cidr.substr(slash_pos + 1);

    // Parse prefix length
    prefix_len = 0;
    [[maybe_unused]] auto [ptr, ec] = std::from_chars(prefix_str.data(),
                                      prefix_str.data() + prefix_str.size(),
                                      prefix_len);
    if (ec != std::errc{} || prefix_len < 8 || prefix_len > 30)
        return false;

    // Parse IP octets
    uint8_t octets[4]{};
    int octet_idx = 0;
    size_t start = 0;
    std::string ip{ip_str};
    for (size_t i = 0; i <= ip.size() && octet_idx < 4; ++i) {
        if (i == ip.size() || ip[i] == '.') {
            int val = 0;
            [[maybe_unused]] auto [p, e] = std::from_chars(ip.data() + start, ip.data() + i, val);
            if (e != std::errc{} || val < 0 || val > 255) return false;
            octets[octet_idx++] = static_cast<uint8_t>(val);
            start = i + 1;
        }
    }
    if (octet_idx != 4) return false;

    base_ip = (static_cast<uint32_t>(octets[0]) << 24) |
              (static_cast<uint32_t>(octets[1]) << 16) |
              (static_cast<uint32_t>(octets[2]) << 8) |
              static_cast<uint32_t>(octets[3]);

    return true;
}

/**
 * Convert a 32-bit IP to dotted-quad string.
 */
std::string ip_to_string(uint32_t ip) {
    return std::format("{}.{}.{}.{}",
                       (ip >> 24) & 0xFF,
                       (ip >> 16) & 0xFF,
                       (ip >> 8) & 0xFF,
                       ip & 0xFF);
}

/**
 * Generate all host IPs in a CIDR range (excludes network and broadcast).
 */
std::vector<std::string> enumerate_hosts(uint32_t base_ip, int prefix_len) {
    std::vector<std::string> result;
    uint32_t mask = 0xFFFFFFFF << (32 - prefix_len);
    uint32_t network = base_ip & mask;
    uint32_t broadcast = network | ~mask;

    // Limit to /24 (254 hosts) to prevent DoS from scanning overly large subnets
    if (prefix_len < 24) return result;

    for (uint32_t ip = network + 1; ip < broadcast; ++ip) {
        result.push_back(ip_to_string(ip));
    }
    return result;
}

struct ArpEntry {
    std::string ip;
    std::string mac;
};

/**
 * An ARP-table read that reports its own health.
 *
 * `ok=false`  — the acquisition FAILED (GetIpNetTable2 error, /proc/net/arp
 *               unopenable, sysctl error). NOT the same as an empty table.
 * `complete=false` — the table was read but is known to be partial.
 *
 * Every leg previously returned a bare empty vector for all three of "no
 * neighbours", "the API failed" and "the parse stopped early", so a scan whose
 * ARP half never ran reported a clean result with no machine-readable reason
 * (/adversarial-review Codex CDX-3, Kimi F6).
 */
struct ArpRead {
    std::vector<ArpEntry> entries;
    bool ok{true};
    bool complete{true};
};

// ── ARP table parsing ─────────────────────────────────────────────────────

#ifdef _WIN32

/**
 * Read the Windows ARP table via GetIpNetTable2(AF_INET) — the neighbour
 * cache, native (no popen). FreeMibTable is called on every exit path.
 */
ArpRead get_arp_table() {
    ArpRead out;

    PMIB_IPNET_TABLE2 table = nullptr;
    DWORD rc = GetIpNetTable2(AF_INET, &table);
    // RAII: FreeMibTable runs on every exit path below, early returns
    // included, without needing to remember to call it manually.
    std::unique_ptr<MIB_IPNET_TABLE2, decltype(&FreeMibTable)> table_owner{
        table, &FreeMibTable};
    if (rc != NO_ERROR || table == nullptr) {
        out.ok = false; // the API failed — NOT an empty neighbour cache
        return out;
    }

    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPNET_ROW2& row = table->Table[i];

        // is_resolved_arp_row (discovery_parsers.hpp) — extracted so this
        // accept/reject decision is fixture-tested off-Windows (#3249); see
        // the static_asserts above pinning its portable state mirror against
        // the real NL_NEIGHBOR_STATE enum.
        if (!yuzu::discovery::is_resolved_arp_row(
                static_cast<int>(row.State), static_cast<int>(row.PhysicalAddressLength)))
            continue;

        char ip[INET_ADDRSTRLEN]{};
        if (!inet_ntop(AF_INET, const_cast<IN_ADDR*>(&row.Address.Ipv4.sin_addr), ip, sizeof(ip)))
            continue;

        // format_mac48, not snprintf: printf-family calls are on
        // docs/cpp-conventions.md's "Forbidden in new code" list, and the
        // shared helper is portable so this formatting is unit-tested on
        // every leg rather than only on Windows.
        out.entries.push_back({ip, yuzu::discovery::format_mac48(row.PhysicalAddress)});
    }

    return out;
}

#elif defined(__APPLE__)

/**
 * Read the macOS ARP table via the routing socket sysctl
 * (route_sysctl_arp.hpp) — the same data `arp -a` reads, native (no popen).
 */
ArpRead get_arp_table() {
    ArpRead out;
    auto fetched = yuzu::shared::fetch_rt_flags_llinfo();
    if (!fetched.ok) {
        out.ok = false; // the sysctl failed — NOT an empty neighbour table
        return out;
    }
    auto parsed = yuzu::shared::parse_rt_flags_llinfo(fetched.blob);
    out.complete = !parsed.truncated;
    for (auto& rec : parsed.records)
        out.entries.push_back({std::move(rec.ip), std::move(rec.mac)});
    return out;
}

#elif defined(__linux__)

/**
 * Read the Linux ARP table from /proc/net/arp (discovery_parsers.hpp) —
 * native, no `arp -n` subprocess.
 */
ArpRead get_arp_table() {
    ArpRead out;
    std::ifstream in("/proc/net/arp");
    if (!in) {
        out.ok = false; // procfs absent or denied — NOT an empty table
        return out;
    }

    std::ostringstream contents;
    contents << in.rdbuf();
    if (in.bad()) {
        out.ok = false; // read error mid-stream
        return out;
    }

    for (auto& e : yuzu::discovery::parse_proc_net_arp(contents.str()))
        out.entries.push_back({std::move(e.ip), std::move(e.mac)});
    return out;
}

#else

ArpRead get_arp_table() {
    // No native ARP mechanism on this platform. Honest: the read did not
    // happen, so it must not present as an empty neighbour table.
    ArpRead out;
    out.ok = false;
    return out;
}

#endif

// ── Hostname resolution ───────────────────────────────────────────────────

namespace detail {

std::string resolve_hostname_blocking(const std::string& ip) {
#ifdef _WIN32
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    char host[NI_MAXHOST]{};
    if (getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa),
                    host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
        return host;
    }
#else
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    char host[1025]{};
    if (getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa),
                    host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
        return host;
    }
#endif
    return {};
}

} // namespace detail

// getnameinfo(..., NI_NAMEREQD) has no caller-supplied timeout, and a
// black-holing (not refusing) reverse-DNS path can block it for the OS
// resolver's own retry/nameserver/TCP-fallback envelope — potentially
// minutes. Plugin execute() runs synchronously on the agent's bounded
// ThreadPool with no per-task cancellation (governance Gate 4 unhappy-path
// finding), so an unbounded call here can permanently pin a worker and,
// under repeated/concurrent scans, exhaust the pool and stall every other
// command dispatched to this agent. bounded_call() bounds the WAIT (the call
// itself can't be cancelled) — see bounded_wait.hpp.
constexpr std::chrono::milliseconds kHostnameLookupTimeout{5000};

// nullopt distinguishes "the lookup timed out or was throttled by
// bounded_call's ceiling" from a present-but-empty string ("no PTR record" —
// a genuine, non-degraded answer from getnameinfo). Gate 6 SRE finding: the
// two were previously collapsed into the same empty string, so a lookup that
// silently degraded looked identical to a host with no reverse-DNS entry —
// the one place this plugin's otherwise-thorough honest-degrade reporting
// didn't reach, because the degrade is per-item rather than per-scan. The
// caller aggregates degrades across the whole hostname-resolution pass.
std::optional<std::string> resolve_hostname(const std::string& ip) {
    return yuzu::shared::bounded_call(
        kHostnameLookupTimeout, [ip] { return detail::resolve_hostname_blocking(ip); });
}

// ── Ping sweep ────────────────────────────────────────────────────────────

/**
 * Sample one host over the shared ICMP session. Builds the destination
 * address from the (already-validated, dotted-quad) IP string and delegates
 * to yuzu::shared::IcmpSession::sample — no subprocess, no per-host socket.
 */
#ifdef _WIN32
yuzu::shared::ProbeOutcome icmp_sample(yuzu::shared::IcmpSession& session, const std::string& ip,
                                       int timeout_ms) {
    struct in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
        return {std::nullopt, yuzu::shared::ProbeFailure::TransmitFailed};
    return session.sample(addr.S_un.S_addr, timeout_ms);
}
#else
yuzu::shared::ProbeOutcome icmp_sample(yuzu::shared::IcmpSession& session, const std::string& ip,
                                       int timeout_ms) {
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &sin.sin_addr) != 1)
        return {std::nullopt, yuzu::shared::ProbeFailure::TransmitFailed};
    return session.sample(sin, timeout_ms);
}
#endif

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// scan_subnet combines an ARP-table read with an ICMP ping sweep, all
// native now (zero spawn sites, rung 1 on every platform): Windows reads
// GetIpNetTable2 and pings via IcmpSendEcho; macOS reads the routing socket
// (sysctl NET_RT_FLAGS/RTF_LLINFO) and pings via an unprivileged SOCK_DGRAM
// ICMP socket; Linux reads /proc/net/arp and pings the same way, but the
// ICMP socket depends on net.ipv4.ping_group_range admitting the agent's
// gid — see do_scan_subnet's honest-degrade branch for the CONSTRAINED /
// UNAVAILABLE fallback this leg documents.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "scan_subnet",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "/proc/net/arp + unprivileged SOCK_DGRAM ICMP",
         "the ICMP sweep needs net.ipv4.ping_group_range to admit the agent's gid; "
         "ARP-only results with a CONSTRAINED/PARTIAL status otherwise, or "
         "UNAVAILABLE/PARTIAL when the ICMP socket cannot be created at all. netlink "
         "RTM_GETNEIGH is a recorded future promotion over /proc/net/arp"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "sysctl NET_RT_FLAGS/RTF_LLINFO + SOCK_DGRAM ICMP", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "GetIpNetTable2 + IcmpSendEcho", nullptr},
    },
};

} // namespace

class DiscoveryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "discovery"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Network device discovery — ARP scan and ping sweep";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"scan_subnet", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override {
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params params) override {
        if (action == "scan_subnet")
            return do_scan_subnet(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_scan_subnet(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto subnet = params.get("subnet");
        auto timeout_str = params.get("timeout_ms", "1000");

        if (subnet.empty()) {
            ctx.write_output("status|error|missing required parameter: subnet");
            return 1;
        }

        if (!is_valid_cidr(subnet)) {
            ctx.write_output("status|error|invalid CIDR subnet format (e.g., 192.168.1.0/24)");
            return 1;
        }

        // A non-numeric timeout_ms used to be discarded in silence, so an
        // automation template typo simply scanned with the default. Say so.
        // No clamp here: probe_budget_ms() owns the bound (a second clamp to
        // [100,10000] was dead — nothing can observe a value above the
        // per-host ceiling).
        int timeout_ms = 1000;
        if (!timeout_str.empty()) {
            const auto [p_end, ec] = std::from_chars(
                timeout_str.data(), timeout_str.data() + timeout_str.size(), timeout_ms);
            if (ec != std::errc{} || p_end != timeout_str.data() + timeout_str.size()) {
                timeout_ms = 1000;
                ctx.write_output(std::format(
                    "status|warning|ignoring invalid timeout_ms '{}', using default 1000ms",
                    timeout_str));
            }
        }

        uint32_t base_ip = 0;
        int prefix_len = 0;
        if (!parse_cidr(subnet, base_ip, prefix_len)) {
            ctx.write_output("status|error|failed to parse CIDR subnet");
            return 1;
        }

        auto hosts = enumerate_hosts(base_ip, prefix_len);
        if (hosts.empty()) {
            // Two different refusals: a /16 is not "too large" as a prefix, and
            // a /31 has no host bits at all. One message for both told an
            // operator the subnet was invalid when the scan simply declines it.
            if (prefix_len < 24)
                ctx.write_output(std::format(
                    "status|error|subnet has too many hosts to scan (/{} requested, /24 is the "
                    "widest supported)",
                    prefix_len));
            else
                ctx.write_output(std::format(
                    "status|error|/{} contains no usable host addresses", prefix_len));
            return 1;
        }

        ctx.report_progress(5);

        // Overall scan timeout: abort after 300 seconds and return partial results
        constexpr int kScanTimeoutSeconds = 300;
        auto scan_start = std::chrono::steady_clock::now();
        bool timed_out = false;

        // Every degrade condition below is a CANDIDATE, accumulated by
        // severity rather than applied to the ABI4 result seam immediately:
        // more than one can independently fire in a single scan (e.g. the
        // ARP read fails AND the scan later hits its deadline), and
        // yuzu_ctx_set_result_status is an unconditional overwrite — calling
        // it once per condition would let only the LAST one survive
        // (governance Gate 4 consistency-auditor finding). set_result_status
        // is called exactly once, at the end, with the worst report seen.
        yuzu::discovery::MaybeDegrade worst_degrade;

        // Step 1: Get current ARP table (fast, pre-populated entries)
        auto arp_read = get_arp_table();
        std::set<std::string> arp_ips;
        std::map<std::string, std::string> ip_to_mac;
        for (const auto& entry : arp_read.entries) {
            arp_ips.insert(entry.ip);
            ip_to_mac[entry.ip] = entry.mac;
        }

        // An ARP half that did not run is a PARTIAL scan, not a quiet network.
        if (const auto arp_degrade =
                yuzu::discovery::degrade_for_arp(arp_read.ok, arp_read.complete);
            arp_degrade.has_report) {
            ctx.write_output(std::format("status|warning|{}", arp_degrade.report.message));
            worst_degrade = yuzu::discovery::worst_of(worst_degrade, arp_degrade);
        }

        ctx.report_progress(10);

        // Step 2: Ping sweep to discover hosts not in ARP table
        // The ping will populate the ARP table for responding hosts
        int total = static_cast<int>(hosts.size());
        int done = 0;
        std::set<std::string> alive_ips;

        // ONE ICMP session per scan (never per host — a /24 must not open
        // 254 sockets). Each probe gets a short per-host budget, capped
        // independently of the caller's timeout_ms so the sweep stays finite;
        // both bounds are decided by discovery_scan_plan.hpp (tested there).
        yuzu::shared::IcmpSession session;
        yuzu::discovery::SweepTally sweep_tally;
        const int probe_timeout_ms = yuzu::discovery::probe_budget_ms(timeout_ms);
        const auto availability =
            yuzu::discovery::classify_icmp_session(session.ok(), session.permitted);

        if (const auto degrade = yuzu::discovery::degrade_for(availability); degrade.has_report) {
            // HONEST DEGRADE — resolved before any probe is attempted. Never
            // probe through an invalid session; fall back to the ARP-derived
            // host set, warn once, and stamp the ABI4 result so a machine
            // consumer cannot read a dead network as a successful empty scan.
            // Denied (Linux net.ipv4.ping_group_range refusing the
            // unprivileged SOCK_DGRAM ICMP socket) and Unavailable
            // (EMFILE/ENFILE/ENOMEM, or IcmpCreateFile failing on Windows)
            // carry distinct statuses and reason tags.
            ctx.write_output(std::format("status|warning|{}", degrade.report.message));
            worst_degrade = yuzu::discovery::worst_of(worst_degrade, degrade);
            // Confine the degrade fallback to the requested subnet — never
            // surface unrelated cached ARP neighbors (other subnets,
            // multicast/broadcast entries) as scan results.
            for (const auto& ip : yuzu::discovery::arp_hosts_in_subnet(hosts, arp_ips))
                alive_ips.insert(ip);
        } else {
            for (const auto& ip : hosts) {
                // Check overall scan timeout
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - scan_start).count();
                if (elapsed >= kScanTimeoutSeconds) {
                    timed_out = true;
                    ctx.write_output(std::format("status|warning|scan timed out after {}s, "
                                                 "returning partial results ({}/{})",
                                                 elapsed, done, total));
                    break;
                }

                // If already in ARP table, it's alive
                if (arp_ips.count(ip)) {
                    alive_ips.insert(ip);
                } else {
                    // Probe it. A non-reply is only "down" when the packet
                    // actually left the machine — sweep_tally carries the
                    // difference so a blocked sweep degrades instead of
                    // reporting a dead network (see degrade_for_sweep).
                    const auto outcome = icmp_sample(session, ip, probe_timeout_ms);
                    ++sweep_tally.probed;
                    if (outcome.replied()) {
                        ++sweep_tally.replied;
                        alive_ips.insert(ip);
                    } else if (outcome.transmit_blocked()) {
                        ++sweep_tally.transmit_blocked;
                    }
                }

                ++done;
                int progress = 10 + (done * 80 / total);
                if (done % 10 == 0 || done == total) {
                    ctx.report_progress(progress);
                }

                // Progress reporting every 50 hosts
                if (done % 50 == 0) {
                    ctx.write_output(std::format("progress|scanned {} of {} hosts, "
                                                 "{} alive so far",
                                                 done, total, alive_ips.size()));
                }
            }
        }

        // A sweep that constructed a session but could not transmit through it
        // is NOT an empty network.
        if (const auto blocked = yuzu::discovery::degrade_for_sweep(sweep_tally);
            blocked.has_report) {
            ctx.write_output(std::format("status|warning|{}", blocked.report.message));
            worst_degrade = yuzu::discovery::worst_of(worst_degrade, blocked);
        }

        // A sweep cut short by its own deadline is PARTIAL, not a clean scan.
        // The warning line above (in the sweep loop) says so to a human; this
        // accumulates it for the ABI4 result seam, which is what a machine
        // consumer reads — without it a scan that stopped at host 40 of 254 is
        // indistinguishable from a complete one.
        if (timed_out) {
            worst_degrade = yuzu::discovery::worst_of(
                worst_degrade, {true, yuzu::discovery::timeout_degrade()});
        }

        // Step 3: Re-read ARP table after ping sweep to get MACs. A failure
        // here is not separately reported: the pre-sweep read already
        // classified the ARP half, and this pass only enriches MACs.
        auto fresh_arp = get_arp_table();
        for (const auto& entry : fresh_arp.entries) {
            ip_to_mac[entry.ip] = entry.mac;
        }

        ctx.report_progress(95);

        // Step 4: Output results
        int found = 0;
        int hostname_degraded = 0;
        bool hostname_scan_timed_out = false;
        for (const auto& ip : alive_ips) {
            std::string mac = ip_to_mac.count(ip) ? ip_to_mac[ip] : "unknown";
            // The same kScanTimeoutSeconds budget that bounds the probe loop
            // above must also bound this loop: reverse-DNS has no per-call
            // timeout of its own, and up to |alive_ips| lookups against a
            // slow/unreachable resolver could otherwise run far past the
            // action's documented 300s bound (governance Gate 2 finding).
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - scan_start).count();
            if (elapsed >= kScanTimeoutSeconds) {
                hostname_scan_timed_out = true;
                break;
            }
            // resolve_hostname returns nullopt when the lookup timed out or
            // was throttled by bounded_call's ceiling, distinct from a
            // present-but-empty answer (a genuine "no PTR record"). Without
            // this distinction the two looked identical — the one place this
            // scan's otherwise-thorough honest-degrade reporting didn't
            // reach, because the degrade is per-item rather than per-scan
            // (governance Gate 6 SRE finding).
            auto resolved = resolve_hostname(ip);
            std::string hostname;
            if (resolved) {
                // hostname is a reverse-DNS PTR result -- attacker-
                // influenceable (the responding host/DNS infra controls it),
                // unlike `ip`/`mac` which come from inet_ntop/fixed-hex
                // formatters. safe_output_field it so a crafted PTR record
                // containing '|' or CR/LF can't inject an extra column or
                // forge an extra output row (same class as the sibling
                // users/certificates plugins' output-escaping fixes this
                // session; governance Gate 2 finding).
                hostname = yuzu::util::safe_output_field(*resolved);
                if (hostname.empty()) hostname = "unknown";
            } else {
                ++hostname_degraded;
                hostname = "unknown";
            }
            // managed status is always "unknown" from the agent side —
            // the server will correlate with known agent IPs
            ctx.write_output(std::format("host|{}|{}|{}|unknown", ip, mac, hostname));
            ++found;
        }
        if (hostname_degraded > 0) {
            ctx.write_output(std::format(
                "status|warning|{} of {} hostname lookups timed out or were throttled; "
                "reported as unknown",
                hostname_degraded, found));
            worst_degrade = yuzu::discovery::worst_of(
                worst_degrade, {true, yuzu::discovery::hostname_lookup_degraded()});
        }
        if (hostname_scan_timed_out) {
            worst_degrade = yuzu::discovery::worst_of(
                worst_degrade, {true, yuzu::discovery::timeout_degrade()});
            // The probe loop already wrote its own "scan timed out" warning
            // when `timed_out` is true, and the sweep already having consumed
            // the whole budget means this loop trips on its very first
            // iteration — a second, near-identical message here would be
            // redundant and its "0 of N resolved" framing misleading (the
            // hostname loop never got a real chance to run).
            if (!timed_out) {
                ctx.write_output(std::format(
                    "status|warning|hostname resolution timed out after {}s, {} of {} alive "
                    "hosts resolved",
                    kScanTimeoutSeconds, found, static_cast<int>(alive_ips.size())));
            }
        }

        // Every candidate degrade condition observed across the whole scan
        // (ARP, ICMP session, sweep-blocked, probe-loop timeout, hostname-loop
        // timeout) has been accumulated above by severity. Apply the worst one
        // to the ABI4 result seam exactly once, here — never at the individual
        // sites — so an earlier, more specific reason can't be silently
        // overwritten by a later, less specific one. Two same-severity pairs
        // are the deliberate exception, applied inside worst_of() by
        // degrade_tie_prefers_candidate(): a later scan:timeout DOES displace
        // an earlier arp:table_truncated or dns:hostname_lookup_degraded,
        // because a scan-level timeout is the more actionable reason of the
        // two, not the less (#3253). Every condition still writes its own
        // status|warning line above regardless of which one wins here.
        if (worst_degrade.has_report) {
            ctx.set_result_status(worst_degrade.report.status, worst_degrade.report.completeness,
                                  worst_degrade.report.reason);
        }

        ctx.write_output(std::format("scan_complete|{}|{}", found, total));
        ctx.report_progress(100);
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(DiscoveryPlugin)
