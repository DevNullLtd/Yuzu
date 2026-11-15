// echo_dns_collector.cpp — host DNS resolver-cache enumeration for the Echo `dns`
// capture source (ADR-0015). Impure platform shell only: the snapshot is diffed
// in echo_diff.cpp (compute_dns_events) and persisted in echo_db.cpp
// (insert_dns_events). Core capture-source pattern — types/decls in
// echo_collectors.hpp. See docs/echo-implementer.md "Adding a capture source".
//
// IMPORTANT: this reads the system DNS resolver CACHE STATE — it is host-wide and
// carries NO process attribution (no pid). Per-process DNS attribution would
// require the Microsoft-Windows-DNS-Client ETW provider and is a deferred
// follow-up; do NOT join $DNS_Live to a process by pid.
//
// Windows mechanism (per the ADR):
//   1. DnsGetCacheDataTable() enumerates the cache as a linked list of
//      {name, type}. It is an UNDOCUMENTED dnsapi.dll export, so it is resolved
//      at runtime via GetProcAddress (no import-lib dependency on it). If it
//      cannot be resolved the collector degrades to an empty result.
//   2. For each cached name+type, DnsQuery_W with DNS_QUERY_NO_WIRE_QUERY (0x10)
//      plus the undocumented cache-read flag 0x8000 reads the record DATA + TTL
//      from the cache ONLY — NO_WIRE_QUERY guarantees we never issue a real DNS
//      query (no network amplification, no privacy leak from the collector
//      itself); 0x8000 is required to surface cached records on many Win10/11
//      builds (see the call site for the muhdnscache rationale).
// Linux (systemd-resolved / /etc/hosts) and macOS (dscacheutil) are kPlanned and
// return an empty vector.

#include "echo_collectors.hpp"

#include <spdlog/spdlog.h>

#include <atomic> // rate-limited truncation warn
#include <cstring> // std::memcpy (AAAA formatting)
#include <string>
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
#include <windns.h> // DnsQuery_W / DNS_RECORD / DnsRecordListFree / DnsFree
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#endif

namespace yuzu::echo {

#ifdef _WIN32

namespace {

// Undocumented dnsapi.dll cache-table entry (stable across Windows versions;
// used by every public DNS-cache dumper). Resolved via GetProcAddress.
struct DnsCacheEntryW {
    DnsCacheEntryW* pNext;
    PWSTR pszName;
    unsigned short wType;
    unsigned short wDataLength;
    unsigned long dwFlags;
};
using DnsGetCacheDataTable_t = int(WINAPI*)(DnsCacheEntryW**);

// Delegates to the shared helper (#1681); identical -1 convert that drops the
// trailing NUL (null -> {}).
std::string wstr_to_utf8(PCWSTR w) { return yuzu::win::from_wide(w); }

std::string record_type_str(unsigned short t) {
    switch (t) {
    case DNS_TYPE_A:     return "A";
    case DNS_TYPE_NS:    return "NS";
    case DNS_TYPE_CNAME: return "CNAME";
    case DNS_TYPE_SOA:   return "SOA";
    case DNS_TYPE_PTR:   return "PTR";
    case DNS_TYPE_MX:    return "MX";
    case DNS_TYPE_TEXT:  return "TXT";
    case DNS_TYPE_AAAA:  return "AAAA";
    case DNS_TYPE_SRV:   return "SRV";
    default:             return std::string("TYPE") + std::to_string(t);
    }
}

// Format one DNS record's data field per its type. Empty string for types we
// don't decode (the row is still recorded with its name/type). DNS_RECORDW
// (explicit wide) because the project is not built /DUNICODE — the generic
// DNS_RECORD would resolve to the ANSI variant and mismatch DnsQuery_W's output.
std::string record_data_str(const DNS_RECORDW& r) {
    char buf[INET6_ADDRSTRLEN]{};
    switch (r.wType) {
    case DNS_TYPE_A: {
        IN_ADDR a{};
        a.S_un.S_addr = r.Data.A.IpAddress; // network byte order
        if (inet_ntop(AF_INET, &a, buf, sizeof(buf)))
            return buf;
        return {};
    }
    case DNS_TYPE_AAAA: {
        IN6_ADDR a6{};
        std::memcpy(&a6, &r.Data.AAAA.Ip6Address, sizeof(a6));
        if (inet_ntop(AF_INET6, &a6, buf, sizeof(buf)))
            return buf;
        return {};
    }
    case DNS_TYPE_CNAME:
    case DNS_TYPE_NS:
    case DNS_TYPE_PTR:
        return wstr_to_utf8(r.Data.PTR.pNameHost);
    case DNS_TYPE_MX:
        return wstr_to_utf8(r.Data.MX.pNameExchange);
    case DNS_TYPE_SRV:
        return wstr_to_utf8(r.Data.SRV.pNameTarget);
    case DNS_TYPE_TEXT: {
        std::string out;
        for (DWORD i = 0; i < r.Data.TXT.dwStringCount; ++i) {
            if (i)
                out += ' ';
            out += wstr_to_utf8(r.Data.TXT.pStringArray[i]);
        }
        return out;
    }
    default:
        return {};
    }
}

} // namespace

std::vector<DnsEntry> enumerate_dns() {
    std::vector<DnsEntry> out;

    HMODULE dnsapi = GetModuleHandleW(L"dnsapi.dll");
    bool owned = false;
    if (!dnsapi) {
        dnsapi = LoadLibraryW(L"dnsapi.dll");
        owned = true;
    }
    if (!dnsapi) {
        spdlog::warn("Echo dns: dnsapi.dll not available");
        return out;
    }

    auto get_table = reinterpret_cast<DnsGetCacheDataTable_t>(
        reinterpret_cast<void*>(GetProcAddress(dnsapi, "DnsGetCacheDataTable")));
    if (!get_table) {
        spdlog::warn("Echo dns: DnsGetCacheDataTable not exported by dnsapi.dll");
        if (owned)
            FreeLibrary(dnsapi);
        return out;
    }

    DnsCacheEntryW* table = nullptr;
    if (get_table(&table) == 0 || table == nullptr) {
        if (owned)
            FreeLibrary(dnsapi);
        return out; // empty cache (or call failed) — not an error
    }

    // Defense-in-depth (UP-9): bound the walk by a node ceiling so a corrupted or
    // cyclic pNext from the undocumented dnsapi list can't loop unboundedly. The
    // ceiling is far above any real resolver cache; exceeding it aborts the walk
    // (remaining nodes leak rather than risk an infinite loop on a bad list).
    constexpr std::size_t kDnsNodeWalkCap = 65536;
    bool capped = false;
    bool overrun = false;
    std::size_t nodes = 0;
    for (DnsCacheEntryW* p = table; p != nullptr;) {
        if (++nodes > kDnsNodeWalkCap) {
            overrun = true;
            break;
        }
        DnsCacheEntryW* next = p->pNext;

        if (!capped && p->pszName) {
            // Cache-only read of the record data + TTL.
            //   DNS_QUERY_NO_WIRE_QUERY (0x10) guarantees no network query is issued.
            //   0x8000 is an undocumented DNS_QUERY_* flag which — per reverse-engineering
            //   of `ipconfig /displaydns` (the "muhdnscache" research) — is required to
            //   actually read the resolver cache on many Win10/11 builds; with 0x10 alone
            //   DnsQuery_W can fail/return empty for every cached entry, defeating the
            //   whole source. OR it in defensively (ADR-0015 review HIGH-B). 0x10 is the
            //   documented-but-insufficient subset, so this only ever adds cache visibility.
            // windns.h declares DnsQuery_W with the GENERIC PDNS_RECORD* (= ANSI
            // PDNS_RECORDA* without /DUNICODE) even though the _W function returns
            // wide records. Take the out-param as the generic type to satisfy the
            // prototype, then view it as wide — the data really is DNS_RECORDW.
            constexpr DWORD kDnsQueryCacheOnly = DNS_QUERY_NO_WIRE_QUERY | 0x8000;
            PDNS_RECORD rec_generic = nullptr;
            DNS_STATUS st = DnsQuery_W(p->pszName, p->wType, kDnsQueryCacheOnly,
                                       nullptr, &rec_generic, nullptr);
            if (st == ERROR_SUCCESS && rec_generic) {
                auto* rec = reinterpret_cast<PDNS_RECORDW>(rec_generic);
                for (PDNS_RECORDW r = rec; r != nullptr; r = r->pNext) {
                    DnsEntry e;
                    e.name = wstr_to_utf8(r->pName);
                    e.record_type = record_type_str(r->wType);
                    e.data = record_data_str(*r);
                    e.ttl_remaining_s = static_cast<int64_t>(r->dwTtl);
                    e.source = "cache";
                    out.push_back(std::move(e));
                    if (out.size() >= kDnsEntryCap) {
                        capped = true;
                        break;
                    }
                }
                // DnsFree (void*) rather than DnsRecordListFree (typed PDNS_RECORD,
                // = ANSI variant without /DUNICODE) — avoids the wide/ANSI mismatch.
                DnsFree(rec_generic, DnsFreeRecordList);
            }
        }

        // Free this cache node (undocumented allocation; community-standard free:
        // the name buffer then the node, both flat allocations).
        if (p->pszName)
            DnsFree(p->pszName, DnsFreeFlat);
        DnsFree(p, DnsFreeFlat);
        p = next;
    }

    if (overrun)
        spdlog::error("Echo dns: cache walk exceeded {} nodes — aborting (possible corrupted "
                      "dnsapi list)",
                      kDnsNodeWalkCap);
    // Rate-limit the truncation warn (UP-7): log once when truncation begins, then
    // suppress until the cache drops back under the cap — avoids a 60s log-spam on a
    // persistently large-cache host.
    static std::atomic<bool> s_dns_cap_warned{false};
    if (capped) {
        if (!s_dns_cap_warned.exchange(true))
            spdlog::warn("Echo dns: entry cap {} reached — truncating (repeats suppressed until it "
                         "clears)",
                         kDnsEntryCap);
    } else {
        s_dns_cap_warned.store(false);
    }

    if (owned)
        FreeLibrary(dnsapi);
    return out;
}

#else // non-Windows: kPlanned (Linux systemd-resolved / hosts, macOS dscacheutil)

std::vector<DnsEntry> enumerate_dns() { return {}; }

#endif

} // namespace yuzu::echo
