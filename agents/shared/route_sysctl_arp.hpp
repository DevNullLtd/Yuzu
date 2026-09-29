/**
 * route_sysctl_arp.hpp — macOS ARP table via the routing socket sysctl
 * (Wave-2 PR2.1, WP-C). Darwin-only (#ifdef __APPLE__-gated); consumer:
 * discovery's `scan_subnet` get_arp_table(). Replaces the old `arp -a`
 * subprocess call with the native mechanism `arp -a` itself reads from —
 * the kernel routing table filtered to link-layer ("llinfo") entries.
 *
 * Two clearly separated halves:
 *   fetch_rt_flags_llinfo()  — impure: size-then-fill
 *       sysctl({CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO}).
 *   parse_rt_flags_llinfo()  — pure: walks the returned rt_msghdr chain and
 *       decodes each record's trailing sockaddr_inarp (RTA_DST) and
 *       sockaddr_dl (RTA_GATEWAY) into an ArpRecord. Never trusts the blob:
 *       every length it reads is bounds-checked against the buffer before
 *       the corresponding bytes are dereferenced, and any malformed record
 *       (zero or undersized rtm_msglen, an unrecognised rtm_version, a record
 *       that would run past the buffer end, a sockaddr whose sa_len overruns
 *       its record) stops the walk rather than looping or reading out of
 *       bounds — and SETS ArpParse::truncated so the caller learns the table
 *       is incomplete instead of receiving a silent subset.
 *
 * BOTH halves report failure rather than encoding it as emptiness: an
 * ArpFetch with ok=false is a failed sysctl, not an empty neighbour table,
 * and a truncated parse is a partial table, not a complete small one. An
 * earlier cut collapsed all of these into an empty vector, which let a failed
 * or truncated ARP read reach the operator as a successful empty result
 * (/adversarial-review Codex CDX-3/CDX-5, Kimi F6/F8).
 *
 * A record without a resolved 6-byte link-layer address (sdl_alen != 6 —
 * e.g. an in-flight ARP probe) is skipped, same selectivity as the old
 * `arp -a` parser dropping "(incomplete)" rows.
 */
#pragma once

#ifdef __APPLE__

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>

// NO third-party includes here by design: docs/cpp-conventions.md — "What
// belongs in agents/shared/: zero-dependency header-only leaves ONLY —
// nothing with a build target or a core/plugin dependency edge." An earlier
// cut logged its sysctl failures via <spdlog/spdlog.h>, which forced
// spdlog_dep into every consumer's meson.build. fetch_rt_flags_llinfo()
// returns an empty buffer instead and the caller owns the reporting.

namespace yuzu::shared {

struct ArpRecord {
    std::string ip;
    std::string mac;
};

/**
 * A parse that reports whether it saw the whole table.
 *
 * `truncated` is set when the OUTER record walk stopped early — a malformed
 * or oversized rtm_msglen, or an unrecognised routing-message version — i.e.
 * whole records after that point are MISSING.
 *
 * It is deliberately NOT set when a single record's internal sockaddr chain
 * simply runs OUT before RTAX_MAX (fewer than 2 bytes left for the next
 * sockaddr's length/family prefix): that is the normal shape of a routing
 * message (padding can leave a couple of trailing bytes), so flagging it
 * marked every healthy real-world capture as partial.
 *
 * It IS set when a sockaddr inside that chain OVERRUNS — its declared
 * length claims more bytes than the record has left, or its word-rounded
 * advance would push past the record end. That is not the chain ending
 * normally; it is a malformed record silently dropping one neighbour while
 * the outer walk carries on to the next record as if nothing were wrong.
 * Reporting a smaller-but-complete-looking table in that case is exactly
 * the "quietly returns a subset" failure this flag exists to prevent.
 *
 * Either way, a record that ends without a resolved ip/mac yields no entry
 * and is skipped like any unresolved entry. The records already decoded are
 * still returned, because an ARP table is a SET and the entries that parsed
 * are individually true.
 *
 * NOTE the deliberate difference from net_quality_sampler.cpp's NET_RT_IFLIST2
 * walk, which discards the whole sample on any malformation. That one produces
 * an AGGREGATE (summed byte counters): a partial sum is a WRONG NUMBER, so it
 * must be thrown away. This produces a SET of independently-valid neighbours,
 * where discarding everything on one bad trailing record loses good data and
 * makes the scan worse. The honesty requirement is met by REPORTING the
 * truncation to the caller (which degrades the scan to PARTIAL) rather than by
 * silently returning a subset, which is what the previous version did.
 */
struct ArpParse {
    std::vector<ArpRecord> records;
    bool truncated{false};
};

/**
 * Raw sysctl buffer plus whether the fetch actually succeeded. Previously an
 * empty vector meant BOTH "no neighbours" and "the sysctl failed", so a failed
 * ARP read was reported to the operator as an empty neighbour table.
 */
struct ArpFetch {
    std::vector<unsigned char> blob;
    bool ok{false};
};

// ── impure half: raw sysctl fetch ────────────────────────────────────────

/**
 * Fetch the raw NET_RT_FLAGS/RTF_LLINFO routing-socket buffer — the same
 * data `arp -a` reads. Size-then-fill sysctl(2); no popen/exec.
 *
 * Returns ok=false when either sysctl call fails, and ok=true with an empty
 * blob when the table is genuinely empty. The caller needs that distinction to
 * decide between "no neighbours" and "the ARP half of this scan did not run";
 * this leaf carries no logging dependency (see the include block above), so
 * reporting is the caller's job.
 */
inline ArpFetch fetch_rt_flags_llinfo() {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO};
    std::size_t needed = 0;
    if (::sysctl(mib, 6, nullptr, &needed, nullptr, 0) != 0)
        return {}; // ok=false — the read FAILED, distinct from an empty table
    if (needed == 0)
        return {{}, true}; // ok=true — genuinely no neighbours

    std::vector<unsigned char> buf(needed);
    if (::sysctl(mib, 6, buf.data(), &needed, nullptr, 0) != 0)
        return {};
    buf.resize(needed);
    return {std::move(buf), true};
}

namespace detail {

inline std::string mac_to_string(const unsigned char* addr) {
    static const char* kHex = "0123456789abcdef";
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

} // namespace detail

// ── pure half: walk the rt_msghdr chain ──────────────────────────────────

/**
 * Parse a NET_RT_FLAGS/RTF_LLINFO blob into {ip, mac} records. Pure —
 * no I/O. Never trusts rtm_msglen or any sockaddr's sa_len: every step is
 * bounds-checked against `blob`'s actual size before it is dereferenced,
 * and the walk stops (returning what it has) rather than looping or
 * reading past the end on a malformed record.
 */
inline ArpParse parse_rt_flags_llinfo(std::span<const unsigned char> blob) {
    ArpParse out;
    std::size_t off = 0;

    while (off + sizeof(rt_msghdr) <= blob.size()) {
        rt_msghdr hdr{};
        std::memcpy(&hdr, blob.data() + off, sizeof(hdr));

        if (hdr.rtm_msglen == 0) {
            out.truncated = true;
            break; // malformed — would spin forever advancing by zero
        }
        if (hdr.rtm_msglen < sizeof(rt_msghdr)) {
            out.truncated = true;
            break; // malformed — shorter than its own fixed header
        }
        if (off + hdr.rtm_msglen > blob.size()) {
            out.truncated = true;
            break; // record claims more bytes than the buffer has left
        }
        // Reject a routing-message ABI version we don't know how to lay out.
        // Apple has changed routing-socket structure layout across releases
        // with no ABI promise, and decoding a future layout with today's
        // offsets yields plausible-but-wrong IPs and MACs rather than an
        // obvious failure. Same guard as net_quality_sampler.cpp's
        // NET_RT_IFLIST2 walk (docs/darwin-compat.md).
        if (hdr.rtm_version != RTM_VERSION) {
            out.truncated = true;
            break;
        }

        const unsigned char* rec_end = blob.data() + off + hdr.rtm_msglen;
        const unsigned char* p = blob.data() + off + sizeof(rt_msghdr);

        std::string ip;
        std::string mac;

        for (int i = 0; i < RTAX_MAX && p < rec_end; ++i) {
            if (!(hdr.rtm_addrs & (1 << i)))
                continue;

            const std::size_t remaining = static_cast<std::size_t>(rec_end - p);
            if (remaining < 2)
                break; // this record's address chain ends here

            // Read the two-byte sockaddr prefix straight from the blob —
            // no alignment requirement for byte access, unlike casting `p`
            // to a typed sockaddr pointer and dereferencing through it.
            const unsigned char sa_len = p[0];
            const unsigned char sa_family = p[1];
            // kRoutingSockaddrAlign: the BSD/XNU routing-socket ROUNDUP unit
            // is a fixed 4 bytes (see XNU bsd/net/route.c and route.tproj,
            // both use sizeof(uint32_t)) regardless of the platform's word
            // size -- NOT sizeof(long) (8 on LP64 Darwin). Governance Gate 3
            // finding: with only DST/GATEWAY extracted (both fixed-size,
            // always the first two entries in rtm_addrs), the wrong unit
            // never corrupted an extracted field in practice, but it would
            // silently misalign any future field added after GATEWAY.
            constexpr std::size_t kRoutingSockaddrAlign = sizeof(std::uint32_t);
            const std::size_t entry_len = sa_len ? sa_len : kRoutingSockaddrAlign;
            if (remaining < entry_len) {
                // This sockaddr claims more than the record has left — an
                // overrun, not a normal chain end. Mark the whole parse
                // truncated so the caller degrades the scan rather than
                // silently reporting a smaller, complete-looking table.
                out.truncated = true;
                break;
            }

            if (i == RTAX_DST && sa_family == AF_INET &&
                sa_len >= sizeof(struct sockaddr_inarp)) {
                // memcpy into an aligned local before touching any typed
                // field — never dereference a struct through an unaligned
                // raw pointer into the blob.
                struct sockaddr_inarp sin{};
                std::memcpy(&sin, p, sizeof(sin));
                char buf4[INET_ADDRSTRLEN]{};
                if (::inet_ntop(AF_INET, &sin.sin_addr, buf4, sizeof(buf4)))
                    ip = buf4;
            } else if (i == RTAX_GATEWAY && sa_family == AF_LINK &&
                       sa_len >= offsetof(struct sockaddr_dl, sdl_data)) {
                struct sockaddr_dl sdl{};
                std::memcpy(&sdl, p, std::min<std::size_t>(sa_len, sizeof(sdl)));
                const std::size_t needed =
                    offsetof(struct sockaddr_dl, sdl_data) +
                    static_cast<std::size_t>(sdl.sdl_nlen) + static_cast<std::size_t>(sdl.sdl_alen);
                if (sdl.sdl_alen == 6 && sa_len >= needed) {
                    // The MAC bytes themselves are read directly from the
                    // raw blob (unsigned char* — no alignment requirement),
                    // not from the (possibly truncated) local copy.
                    mac = detail::mac_to_string(
                        p + offsetof(struct sockaddr_dl, sdl_data) + sdl.sdl_nlen);
                }
            }

            // Advance to the next sockaddr in the chain, word-rounded per
            // the BSD routing-socket ROUNDUP convention. The rounded
            // advance must itself still fit in the record — a sockaddr
            // whose unrounded length fits but whose rounded length doesn't
            // must not push `p` past `rec_end`.
            std::size_t adv = entry_len;
            adv = (adv + kRoutingSockaddrAlign - 1) & ~(kRoutingSockaddrAlign - 1);
            if (adv > remaining) {
                // Same overrun as above, just discovered after rounding: the
                // unrounded length fit but the rounded advance would push
                // past the record end. Also an overrun, not a normal chain
                // end — mark truncated for the same reason.
                out.truncated = true;
                break;
            }
            p += adv;
        }

        if (!ip.empty() && !mac.empty())
            out.records.push_back(ArpRecord{std::move(ip), std::move(mac)});

        off += hdr.rtm_msglen;
    }

    // Bytes left over that cannot form another header: the buffer ends
    // mid-record. The while condition above simply stops in that case, so
    // without this the trailing partial record is dropped silently — which is
    // the same "quietly returns a subset" failure the truncated flag exists to
    // prevent.
    if (off < blob.size())
        out.truncated = true;

    return out;
}

} // namespace yuzu::shared

#endif // __APPLE__
