/**
 * tar_arp_parsers.hpp — pure parsers for the TAR `arp` capture source's
 * non-Windows legs (tar_arp_collector.cpp). Header-only, no I/O: the
 * collector .cpp owns reading /proc/net/arp and calling
 * agents/shared/route_sysctl_arp.hpp's sysctl fetch, and hands this header
 * the captured text/records so every parser here is unit-testable directly
 * against fixture data (see tests/unit/test_tar_arp.cpp), no live host state
 * required.
 *
 * Two independent pieces:
 *   parse_proc_net_arp()        — Linux: decodes /proc/net/arp text.
 *   arp_entry_from_route_record() (__APPLE__ only) — macOS: maps a decoded
 *       agents/shared/route_sysctl_arp.hpp record onto the TAR ArpEntry
 *       shape. That header's own binary rt_msghdr parser is ITS tested
 *       concern (tests/unit/test_route_sysctl_arp.cpp); this is only the
 *       thin {ip, mac} -> ArpEntry mapping layer TAR adds on top.
 */
#pragma once

#include "tar_capture_status.hpp" // yuzu::tar::would_exceed_cap
#include "tar_collectors.hpp" // ArpEntry, kArpEntryCap

#ifdef __APPLE__
#include <route_sysctl_arp.hpp> // agents/shared — yuzu::shared::ArpRecord
#endif

#include <cerrno>
#include <cstddef>
#include <cstdlib> // std::strtoul (Flags column, base-0 so "0x2" auto-detects)
#include <sstream>
#include <string>
#include <utility> // std::move
#include <vector>

namespace yuzu::tar {

/// Result of parsing /proc/net/arp text: the decoded entries plus whether
/// the caller's cap was reached before the whole table was consumed —
/// mirrors route_sysctl_arp.hpp's ArpParse{records, truncated} shape and the
/// Windows leg's own truncated/kArpEntryCap handling.
struct ProcNetArpParse {
    std::vector<ArpEntry> entries;
    bool truncated{false};
    // BR4-005 (round 4): true when at least one non-blank, non-header row
    // failed to tokenize into all 6 columns or carried an unparseable Flags
    // value. A malformed row is a MISSING binding relative to a genuinely
    // complete table -- diffing the surviving subset against the last
    // COMPLETE snapshot would record that omission as a false `removed`
    // event (and a false compensating `appeared` once the row parses
    // cleanly next tick). The parser still decodes every row around the
    // malformed one (kept in `entries`, for diagnostics -- e.g. logging the
    // raw incomplete-capture reason) rather than aborting outright; it is
    // the CALLER (enumerate_arp(), tar_arp_collector.cpp) that turns this
    // flag into an IncompleteCaptureError throw, mirroring how `truncated`
    // is only acted on there too.
    bool malformed{false};
};

namespace detail {

// /proc/net/arp Flags-column bits (linux/include/uapi/linux/if_arp.h).
inline constexpr unsigned long kAtfCom = 0x2;  // entry has a resolved HW address
inline constexpr unsigned long kAtfPerm = 0x4; // static/permanent entry

/// Map a /proc/net/arp Flags value onto the shared entry_type token set
/// (dynamic/static/incomplete/other), mirroring the Windows leg's
/// NL_NEIGHBOR_STATE -> entry_type mapping (entry_type_for_state in
/// tar_arp_collector.cpp). ATF_PERM is checked before ATF_COM because a
/// kernel-added permanent entry with a resolved MAC carries BOTH bits
/// (0x6) and must read as "static", not "dynamic".
inline std::string arp_entry_type_for_flags(unsigned long flags) {
    if (flags & kAtfPerm)
        return "static";
    if (flags & kAtfCom)
        return "dynamic";
    if (flags == 0x0)
        return "incomplete"; // no bits set — kernel hasn't resolved a MAC yet
    return "other";
}

} // namespace detail

/// Pure parser for /proc/net/arp text: "IP address  HW type  Flags  HW
/// address  Mask  Device", one header line then one row per neighbour.
/// Column order and the header row are per linux/net/ipv4/arp.c's
/// arp_seq_show(); fields are whitespace-separated, not fixed-width, so
/// each row is whitespace-tokenized rather than column-sliced.
///
/// The header line is always skipped (first non-blank line, unconditionally
/// — /proc/net/arp always emits one). A row that doesn't tokenize into all
/// 6 columns, or whose Flags column isn't parseable as a number, is DROPPED
/// from `entries` (the surrounding valid rows still decode — same
/// defensive tolerance as the Windows leg's ip_address.empty() skip) but
/// sets `out.malformed = true` (BR4-005, round 4) rather than passing
/// silently: a malformed row is a missing binding relative to a genuinely
/// complete table, and the CALLER (enumerate_arp(), tar_arp_collector.cpp)
/// throws IncompleteCaptureError on that flag rather than diffing the
/// surviving subset as though it were complete. Incomplete rows (Flags
/// 0x0, HW address 00:00:00:00:00:00) are KEPT and NOT malformed — parity
/// with the Windows leg reporting NlnsIncomplete/Unreachable rows rather
/// than dropping them. Stops at `cap`
/// entries and sets `truncated`, exactly like the Windows leg's own
/// kArpEntryCap enforcement.
inline ProcNetArpParse parse_proc_net_arp(const std::string& text,
                                           std::size_t cap = kArpEntryCap) {
    ProcNetArpParse out;

    std::istringstream stream(text);
    std::string line;
    bool skipped_header = false;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        if (!skipped_header) {
            skipped_header = true;
            continue; // "IP address  HW type  Flags  HW address  Mask  Device"
        }

        std::istringstream cols(line);
        std::string ip, hw_type, flags_str, mac, mask, device;
        if (!(cols >> ip >> hw_type >> flags_str >> mac >> mask >> device)) {
            out.malformed = true; // BR4-005: short row — a missing binding, not tolerated silently
            continue;
        }

        if (flags_str.front() == '-') {
            // negative token — strtoul would silently wrap it unsigned, skip instead
            out.malformed = true; // BR4-005
            continue;
        }

        char* endp = nullptr;
        errno = 0;
        const unsigned long flags = std::strtoul(flags_str.c_str(), &endp, 0);
        if (endp == flags_str.c_str() || *endp != '\0' || errno == ERANGE) {
            // not a fully-consumed, in-range number — malformed, skip
            out.malformed = true; // BR4-005
            continue;
        }

        // Checked BEFORE constructing/pushing the candidate row (round 3,
        // B3-004/B3-005): would_exceed_cap is the same shared decision the
        // Windows ARP/mapdrive loops now call, so an exact-cap table is
        // never misclassified as truncated here either.
        if (would_exceed_cap(out.entries.size(), cap)) {
            out.truncated = true;
            break;
        }

        ArpEntry e;
        e.iface = device;
        e.ip_address = ip;
        e.mac_address = mac;
        e.entry_type = detail::arp_entry_type_for_flags(flags);
        out.entries.push_back(std::move(e));
    }

    return out;
}

/// Pure classification of an `arp` collection outcome from a fetch/parse
/// result. Fetch failure, a kernel-truncated read, and an entry count over
/// the cap are three independent facts the (impure) collector must each
/// turn into a rate-limited warn decision -- extracted here so each state
/// is directly unit-testable (tests/unit/test_tar_arp.cpp) without invoking
/// a real sysctl/procfs read. Currently consumed by the macOS leg of
/// enumerate_arp() (tar_arp_collector.cpp); fetch_failed is always false
/// coming from the Linux leg, which has no separate fetch stage.
struct ArpCollectionStatus {
    bool fetch_failed{false};
    bool parse_truncated{false};
    bool capped{false};
};

inline ArpCollectionStatus classify_arp_collection(bool fetch_ok, bool parse_truncated,
                                                     std::size_t record_count,
                                                     std::size_t cap = kArpEntryCap) {
    if (!fetch_ok)
        return ArpCollectionStatus{.fetch_failed = true};
    return ArpCollectionStatus{
        .parse_truncated = parse_truncated,
        .capped = record_count > cap,
    };
}

/// Pure decision behind every once-when-it-begins/reset-when-it-clears
/// rate-limited warn in this collector (the macOS parse-truncated + cap
/// warns above, and the same pattern in the Linux/Windows legs): warn only
/// on the transition into `condition` being true, not on every call while
/// it stays true, and stop warning again immediately once it clears --
/// callers derive `previously_latched` via
/// `atomic<bool>::exchange(condition)`, keeping the latch update atomic.
inline bool should_warn_ratelimited(bool condition, bool previously_latched) {
    return condition && !previously_latched;
}

#ifdef __APPLE__

/// Map one decoded route_sysctl_arp.hpp record onto the TAR ArpEntry shape.
/// entry_type is fixed "unknown" — this sysctl source distinguishes neither
/// static/permanent nor dynamic/stale/probe entries (unlike GetIpNetTable2's
/// NL_NEIGHBOR_STATE or /proc/net/arp's Flags column), so classifying it as
/// either would be a fabricated distinction; "unknown" is the honest token
/// (matches the constrained-shape note in tar_schema_registry.cpp's macOS
/// arp row). iface is always empty: yuzu::shared::ArpRecord carries no
/// interface field for the caller to use.
inline ArpEntry arp_entry_from_route_record(const yuzu::shared::ArpRecord& rec) {
    ArpEntry e;
    e.ip_address = rec.ip;
    e.mac_address = rec.mac;
    e.entry_type = "unknown";
    return e;
}

#endif // __APPLE__

} // namespace yuzu::tar
