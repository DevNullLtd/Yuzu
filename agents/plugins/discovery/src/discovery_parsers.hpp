/**
 * discovery_parsers.hpp — pure ARP-data parsing/formatting for discovery
 * (Wave-2 PR2.1, WP-C). Portable and header-only: this file and its test
 * TU (test_discovery_parsers.cpp) carry no platform guard and run on every
 * leg. Three consumers in discovery_plugin.cpp: parse_proc_net_arp() on the
 * Linux leg, and format_mac48() + is_resolved_arp_row() on the Windows leg.
 *
 * Kernel format (`net/ipv4/arp.c:arp_seq_show`):
 *   IP address       HW type     Flags       HW address            Mask     Device
 *   192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
 *
 * `Flags` is a hex bitmask; ATF_COM (0x2) marks a resolved ("complete")
 * entry — an in-flight probe lacks that bit and reports an unresolved
 * (usually all-zero) HW address. Both are dropped here, matching the
 * selectivity the old `arp -n` subprocess parser had (it dropped
 * "(incomplete)" rows and required HWtype "ether").
 */
#pragma once

#include <cerrno>
#include <cstdlib>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::discovery {

struct ArpEntry {
    std::string ip;
    std::string mac;
};

/**
 * Format 6 raw bytes as lowercase colon-separated hex ("aa:bb:cc:dd:ee:ff") —
 * the canonical MAC shape every leg of this plugin emits, so a Windows
 * neighbour row and a Linux /proc row are indistinguishable downstream.
 *
 * `addr` must point to at least 6 readable bytes; callers check the platform's
 * own length field first (Windows: MIB_IPNET_ROW2::PhysicalAddressLength).
 *
 * Exists as a pure function because the Windows leg previously formatted MACs
 * with snprintf, which docs/cpp-conventions.md lists under "Forbidden in new
 * code" (printf-family calls). Being portable, it is also compiled and tested
 * on every leg, so the one piece of the Windows ARP path that can be verified
 * off-Windows is verified.
 */
inline std::string format_mac48(const unsigned char* addr) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(17);
    for (int i = 0; i < 6; ++i) {
        if (i)
            out += ':';
        out += kHex[addr[i] >> 4];
        out += kHex[addr[i] & 0x0F];
    }
    return out;
}

/**
 * Parse the text of /proc/net/arp into resolved {ip, mac} entries. Pure —
 * no ifstream, no I/O. Tolerates CRLF line endings, ragged/collapsed
 * whitespace, short lines (skipped rather than throwing), and a missing
 * header line (the header is detected by its literal leading "IP" token,
 * so a header-less capture's first data row is never mistaken for one).
 */
inline std::vector<ArpEntry> parse_proc_net_arp(std::string_view text) {
    std::vector<ArpEntry> out;

    std::istringstream stream{std::string{text}};
    std::string line;
    bool first_line = true;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back(); // tolerate CRLF captures

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
            continue; // Ethernet only — preserve the old `arp -n` parser's
                      // hwtype "ether" selectivity (ARPHRD_ETHER == 0x1)

        char* end = nullptr;
        errno = 0;
        const unsigned long flags = std::strtoul(flags_str.c_str(), &end, 16);
        constexpr unsigned long kAtfCom = 0x2;
        if (errno == ERANGE || end == flags_str.c_str() || *end != '\0' || !(flags & kAtfCom))
            continue; // incomplete/unresolved/overflowing entry — no complete bit set

        if (mac.empty() || mac == "00:00:00:00:00:00")
            continue;

        out.push_back(ArpEntry{std::move(ip), std::move(mac)});
    }

    return out;
}

// ── Windows ARP-row filtering (portable predicate) ────────────────────────

/**
 * Mirrors Win32's NL_NEIGHBOR_STATE (netioapi.h / nldef.h) as plain named
 * ints so the accept/reject predicate below needs no Windows header — it
 * compiles and is fixture-tested on every leg, this Mac included, where
 * <netioapi.h> does not exist. Values are the enum's own published numeric
 * ABI — never re-derive them elsewhere; discovery_plugin.cpp's real _WIN32
 * call site carries a static_assert pinning these against the actual enum,
 * so a future SDK changing them would fail that build loudly rather than
 * silently misclassify rows here.
 */
enum ArpRowStateMirror : int {
    kNlnsUnreachable = 0,
    kNlnsIncomplete = 1,
    kNlnsProbe = 2,
    kNlnsDelay = 3,
    kNlnsStale = 4,
    kNlnsReachable = 5,
    kNlnsPermanent = 6,
    kNlnsMaximum = 7,
};

/**
 * The Windows ARP-row accept/reject decision get_arp_table()
 * (discovery_plugin.cpp) applies to every MIB_IPNET_ROW2. Extracted as a
 * pure predicate (governance-deferred #3249) so logic that used to be
 * inline in the impure GetIpNetTable2-calling loop — and therefore
 * untestable off Windows — can be fixture-tested with literal state/length
 * values on every leg, the same treatment parse_proc_net_arp above and the
 * macOS routing-socket parser (route_sysctl_arp.hpp) already give their own
 * platform's unresolved-entry filtering.
 *
 * Accepts only a resolved/reachable-ish neighbour — Reachable, Stale, Delay,
 * Probe, or Permanent — carrying at least a full 6-byte physical address.
 * Note "at least": the length test is `>= 6`, not `== 6`, so a longer
 * non-Ethernet hardware address (FireWire EUI-64, 20-byte IPoIB) is also
 * accepted and format_mac48 then renders only its first 6 bytes. The macOS
 * leg requires exactly 6 and the Linux leg filters to ARPHRD_ETHER, so the
 * three legs genuinely disagree — tracked separately rather than silently
 * converged in what is meant to be a behaviour-preserving extraction.
 * Rejects an Unreachable/Incomplete (in-flight probe, no answer yet) row or
 * a short/absent physical address. All of the above is byte-faithful to the
 * inline `switch (row.State)` this replaces, which was itself the successor
 * to an older MIB_IPNET_TYPE_DYNAMIC | MIB_IPNET_TYPE_STATIC filter.
 *
 * `state` and `phys_len` are plain ints rather than NL_NEIGHBOR_STATE/ULONG
 * so this header stays platform-neutral like its Linux/macOS siblings; the
 * real Windows call site passes `static_cast<int>(row.State)` and
 * `static_cast<int>(row.PhysicalAddressLength)`.
 */
inline bool is_resolved_arp_row(int state, int phys_len) {
    switch (state) {
    case kNlnsReachable:
    case kNlnsStale:
    case kNlnsDelay:
    case kNlnsProbe:
    case kNlnsPermanent:
        break;
    default:
        return false;
    }
    return phys_len >= 6;
}

} // namespace yuzu::discovery
