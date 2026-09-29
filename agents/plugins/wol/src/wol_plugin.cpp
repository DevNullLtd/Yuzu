/**
 * wol_plugin.cpp — Wake-on-LAN plugin for Yuzu
 *
 * Actions:
 *   "wake"  — Sends a Wake-on-LAN magic packet to a specified MAC address.
 *             The magic packet is a UDP broadcast containing 6 bytes of 0xFF
 *             followed by the target MAC address repeated 16 times.
 *   "check" — Checks whether a host has become reachable, typically polled
 *             after a `wake` to see whether the target booted. Native ICMP
 *             echo (yuzu::shared::IcmpSession, agents/shared/icmp_probe.hpp)
 *             with a TCP-connect fallback on port 443 for hosts/kernels
 *             that drop or deny unprivileged ICMP — no shell-out, no
 *             subprocess (ADR-3002 rung 1). See wol_check_plan.hpp for the
 *             pure mechanism-selection / honest-degrade decision logic.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   key|field1|field2|...
 *
 * Platform implementations:
 *   Windows: Winsock2 UDP broadcast (ws2_32) + IcmpSendEcho (iphlpapi)
 *   Linux:   POSIX UDP sockets + unprivileged ICMP ping socket
 *   macOS:   POSIX UDP sockets + unprivileged ICMP ping socket
 */

#include <yuzu/plugin.hpp>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <format>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <host_arg.hpp>
#include <icmp_probe.hpp>

#include "wol_check_plan.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

// ── MAC address parsing ────────────────────────────────────────────────────

/// Returns true if c is a valid hexadecimal digit.
bool is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/// Convert a hex digit to its numeric value (0-15). Caller must ensure is_hex(c).
unsigned int hex_val(char c) {
    if (c >= '0' && c <= '9')
        return static_cast<unsigned int>(c - '0');
    if (c >= 'a' && c <= 'f')
        return static_cast<unsigned int>(c - 'a' + 10);
    return static_cast<unsigned int>(c - 'A' + 10);
}

// Parse a MAC address string (AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF)
// into 6 bytes. Returns false on invalid format.
// Validates every position explicitly: HH<sep>HH<sep>HH<sep>HH<sep>HH<sep>HH
// where H is [0-9a-fA-F] and <sep> is ':' or '-' (must be consistent).
bool parse_mac(std::string_view mac_str, uint8_t out[6]) {
    // Must be exactly 17 characters: 6 pairs of 2 hex digits separated by 5 separators
    if (mac_str.size() != 17)
        return false;

    // Determine separator from position 2 — must be ':' or '-'
    char sep = mac_str[2];
    if (sep != ':' && sep != '-')
        return false;

    // Validate each of the 17 positions explicitly
    // Positions 0,1   = hex pair (byte 0)
    // Position  2     = separator
    // Positions 3,4   = hex pair (byte 1)
    // Position  5     = separator
    // Positions 6,7   = hex pair (byte 2)
    // Position  8     = separator
    // Positions 9,10  = hex pair (byte 3)
    // Position  11    = separator
    // Positions 12,13 = hex pair (byte 4)
    // Position  14    = separator
    // Positions 15,16 = hex pair (byte 5)
    for (int i = 0; i < 6; ++i) {
        int base = i * 3;
        char hi = mac_str[base];
        char lo = mac_str[base + 1];

        // Both characters must be valid hex digits
        if (!is_hex(hi) || !is_hex(lo))
            return false;

        // Check separator at the expected position (except after last byte)
        if (i < 5) {
            if (mac_str[base + 2] != sep)
                return false;
        }

        out[i] = static_cast<uint8_t>((hex_val(hi) << 4) | hex_val(lo));
    }
    return true;
}

// ── build magic packet ─────────────────────────────────────────────────────

// Build a 102-byte WoL magic packet: 6 bytes of 0xFF followed by the
// target MAC address repeated 16 times.
std::vector<uint8_t> build_magic_packet(const uint8_t mac[6]) {
    std::vector<uint8_t> packet(102);

    // 6 bytes of 0xFF
    std::memset(packet.data(), 0xFF, 6);

    // 16 repetitions of the MAC address
    for (int i = 0; i < 16; ++i) {
        std::memcpy(packet.data() + 6 + (i * 6), mac, 6);
    }

    return packet;
}

// ── L11: RAII wrapper for Winsock lifecycle ─────────────────────────────────

#ifdef _WIN32
struct WinsockGuard {
    bool ok{false};
    WinsockGuard() {
        WSADATA wsa_data;
        ok = (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0);
    }
    ~WinsockGuard() {
        if (ok) WSACleanup();
    }
    WinsockGuard(const WinsockGuard&) = delete;
    WinsockGuard& operator=(const WinsockGuard&) = delete;
};

struct SocketGuard {
    SOCKET sock{INVALID_SOCKET};
    explicit SocketGuard(SOCKET s) : sock(s) {}
    ~SocketGuard() {
        if (sock != INVALID_SOCKET) closesocket(sock);
    }
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;
    explicit operator bool() const { return sock != INVALID_SOCKET; }
    SOCKET get() const { return sock; }
};
#endif

// ── wake action (native UDP broadcast on every platform — no migration
//    needed here; ADR-3002 rung 1 already) ───────────────────────────────────

int do_wake(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto mac_param = params.get("mac");
    if (mac_param.empty()) {
        ctx.write_output("wake|error|Missing required parameter: mac");
        return 1;
    }

    // Parse MAC address
    uint8_t mac[6]{};
    if (!parse_mac(mac_param, mac)) {
        ctx.write_output(std::format("wake|error|Invalid MAC address format: {}", mac_param));
        return 1;
    }

    // Optional port (default 9 — standard WoL port)
    auto port_param = params.get("port", "9");
    int port = 9;
    try {
        port = std::stoi(std::string(port_param));
        if (port < 1 || port > 65535)
            port = 9;
    } catch (...) {
        port = 9;
    }

    // Build magic packet
    auto packet = build_magic_packet(mac);

#ifdef _WIN32
    // L11: RAII wrappers ensure cleanup on all exit paths
    WinsockGuard wsa;
    if (!wsa.ok) {
        ctx.write_output("wake|error|WSAStartup failed");
        return 1;
    }

    SocketGuard sg(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    if (!sg) {
        ctx.write_output("wake|error|Failed to create UDP socket");
        return 1;
    }
    auto sock = sg.get();
#else
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ctx.write_output("wake|error|Failed to create UDP socket");
        return 1;
    }
#endif

    // Enable broadcast
    int broadcast_enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
               reinterpret_cast<const char*>(&broadcast_enable), sizeof(broadcast_enable));

    // Set up broadcast destination
    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(static_cast<uint16_t>(port));
    dest.sin_addr.s_addr = INADDR_BROADCAST; // 255.255.255.255

    // Send the magic packet
    auto sent = sendto(sock, reinterpret_cast<const char*>(packet.data()),
                       static_cast<int>(packet.size()), 0,
                       reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));

#ifndef _WIN32
    close(sock);
#endif
    // On Windows, SocketGuard and WinsockGuard destructors handle cleanup

    if (sent < 0) {
        ctx.write_output(std::format("wake|error|Failed to send magic packet to {}", mac_param));
        return 1;
    }

    ctx.write_output(std::format(
        "wake|success|Magic packet sent to {}|port {}|{} bytes", mac_param, port, sent));
    return 0;
}

// ── check action ─────────────────────────────────────────────────────────
//
// ADR-3002 rung 1: native ICMP echo (yuzu::shared::IcmpSession) as the
// primary mechanism, with a TCP-connect fallback on
// yuzu::wol::kFallbackTcpPort for hosts/kernels that drop or deny
// unprivileged ICMP (e.g. Linux net.ipv4.ping_group_range). No shell-out,
// no subprocess. wol_check_plan.hpp's classify_check() is the pure
// decision function that turns the raw probe facts into a verdict —
// including the honest CONSTRAINED/UNAVAILABLE degrade when NEITHER
// mechanism could even be attempted (never reported as "unreachable").

int do_check(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto host = params.get("host");
    if (host.empty()) {
        ctx.write_output("check|error|Missing required parameter: host");
        return 1;
    }

    // Shared validator (ADR-3002 Decision 6) — same charset the old inline
    // loop used (alphanumeric/dot/hyphen/colon), now factored so every
    // plugin that hands an operator-supplied host to a network probe gets
    // the same option-injection guard (no leading '-').
    if (!yuzu::shared::is_safe_host_arg(host)) {
        ctx.write_output(std::format("check|error|Invalid host: {}", host));
        return 1;
    }

    auto count_param = params.get("count", "3");
    int count = 3;
    try {
        count = std::stoi(std::string(count_param));
        if (count < 1 || count > 10)
            count = 3;
    } catch (...) {
        count = 3;
    }

    auto timeout_param = params.get("timeout_ms", "1000");
    int timeout_ms = 1000;
    try {
        timeout_ms = std::stoi(std::string(timeout_param));
        if (timeout_ms < 100 || timeout_ms > 5000)
            timeout_ms = 1000;
    } catch (...) {
        timeout_ms = 1000;
    }

    const std::string host_str{host};
    constexpr auto kInterSampleGap = std::chrono::milliseconds(200);
    yuzu::wol::ProbeOutcome outcome{};

    // ── ICMP echo (primary mechanism, IPv4 only — matches netprobe's own
    //    icmp action scope; IPv6 is a tracked follow-up on that header) ────
    auto icmp_dst = yuzu::shared::resolve_first(host_str, AF_INET);
    outcome.icmp_resolved = icmp_dst.has_value();

    yuzu::shared::IcmpSession session;
    outcome.icmp_session_ok = session.ok();

    if (icmp_dst && session.ok()) {
        for (int i = 0; i < count && !outcome.icmp_replied; ++i) {
            if (i > 0)
                std::this_thread::sleep_for(kInterSampleGap);
#ifdef _WIN32
            const ULONG ipv4 = reinterpret_cast<sockaddr_in*>(&icmp_dst->addr)->sin_addr.s_addr;
            if (session.sample(ipv4, timeout_ms).replied())
                outcome.icmp_replied = true;
#else
            const auto& sin = *reinterpret_cast<sockaddr_in*>(&icmp_dst->addr);
            if (session.sample(sin, timeout_ms).replied())
                outcome.icmp_replied = true;
#endif
        }
    }

    // ── TCP-connect fallback ─────────────────────────────────────────────
    // Only spent once ICMP has failed to prove reachability -- an early
    // ICMP reply skips this entirely. AF_UNSPEC (unlike the ICMP probe
    // above) so an IPv6-only host still gets a real reachability check.
    if (!outcome.icmp_replied) {
        auto tcp_dst = yuzu::shared::resolve_first(host_str, AF_UNSPEC);
        outcome.tcp_resolved = tcp_dst.has_value();
        if (tcp_dst) {
            yuzu::shared::set_port(*tcp_dst, yuzu::wol::kFallbackTcpPort);
            for (int i = 0; i < count && !outcome.tcp_connected && !outcome.tcp_refused; ++i) {
                if (i > 0)
                    std::this_thread::sleep_for(kInterSampleGap);
                auto sample = yuzu::shared::tcp_sample(*tcp_dst, timeout_ms);
                if (sample.rtt_ms)
                    outcome.tcp_connected = true;
                else if (sample.refused)
                    outcome.tcp_refused = true;
            }
        }
    }

    const auto verdict = yuzu::wol::classify_check(outcome);

    if (verdict.mechanism == yuzu::wol::CheckMechanism::unavailable) {
        // Honest degrade: neither ICMP nor the TCP fallback could even be
        // attempted (ICMP unusable/denied AND no resolvable TCP
        // destination). Reported through the ABI4 CC-07 result-status seam
        // as CONSTRAINED/PARTIAL -- never as "unreachable", which would
        // read to an operator as "the WoL wake failed" when the truth is
        // "we couldn't check at all".
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "wol_plugin:check_unavailable");
        ctx.write_output(std::format("check|{}|unavailable|{}", host, count));
        ctx.write_output(
            std::format("mechanism|{}", yuzu::wol::check_mechanism_label(verdict.mechanism)));
        return 1;
    }

    ctx.write_output(std::format("check|{}|{}|{}", host,
                                 verdict.reachable ? "reachable" : "unreachable", count));
    ctx.write_output(
        std::format("mechanism|{}", yuzu::wol::check_mechanism_label(verdict.mechanism)));
    return 0;
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// wake builds and sends the magic packet over a raw UDP broadcast socket —
// native in-process on every platform (rung 1), unchanged by this
// migration. check is now native too (rung 1): unprivileged ICMP echo with
// a TCP-connect fallback on port 443 — zero subprocess spawns on any
// platform. Linux's ICMP leg is CONSTRAINED (not SUPPORTED) because
// net.ipv4.ping_group_range can deny the unprivileged ping socket; the TCP
// fallback covers that case, and check_unavailable (see do_check above)
// covers the case where neither mechanism is usable.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "wake",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "raw UDP broadcast socket", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "raw UDP broadcast socket", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "raw UDP broadcast socket", nullptr},
    },
    {
        /* .action      = */ "check",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "SOCK_DGRAM ICMP ping socket + TCP-connect fallback",
         "requires net.ipv4.ping_group_range to admit the process group for ICMP; falls back to "
         "a TCP connect on port 443, and reports CONSTRAINED if neither mechanism is usable"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "SOCK_DGRAM ICMP ping socket + TCP-connect fallback",
         nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IcmpSendEcho + TCP-connect fallback", nullptr},
    },
};

} // namespace

class WolPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "wol"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Sends Wake-on-LAN magic packets and checks host reachability";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"wake", "check", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params params) override {
        if (action == "wake")
            return do_wake(ctx, params);
        if (action == "check")
            return do_check(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(WolPlugin)
