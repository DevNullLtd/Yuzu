/**
 * win_dns_cache_table.hpp -- RAII owner for the list returned by the UNDOCUMENTED
 * dnsapi.dll export `DnsGetCacheDataTable` (Windows only; header is empty elsewhere).
 *
 * The caller owns the list: one flat allocation per node plus one for each node's name buffer,
 * released with `DnsFree(p, DnsFreeFlat)` -- the contract agents/plugins/echo/src/
 * echo_dns_collector.cpp already relies on. Without an owner every dispatch of a caller leaks the
 * whole resolver-cache table (F64 network_config.dns_cache, F66 ioc.check).
 *
 * DnsFree is resolved with GetProcAddress from the module the caller already loaded, so no plugin
 * gains a link-time dependency on dnsapi.lib. If it cannot be resolved the list is left alone (a
 * bounded leak is safer than freeing with the wrong allocator). The walk itself (node ceiling, and
 * a stop at the first node or name seen twice so a cyclic or shared-node list is never freed
 * twice) is the portable, unit-tested `release_dns_cache_list` in dns_cache_list.hpp.
 *
 * COMPILED ONLY ON WINDOWS. This revision (portable walk, static_asserts, and the ioc /
 * network_config callers using LoadLibraryExW) was compiled with MSVC 14.44 on a Windows 11 build
 * 26200 host and run in standalone harnesses: ioc `check` and network_config `dns_cache` 2000
 * calls each (no crash, no growth beyond noise), and the owner against a stand-in list allocated
 * from the process heap. NOT verified: freeing a REAL DnsGetCacheDataTable list. That API returned
 * FALSE with an empty list on every call on that host, and the assumption that DnsFree(...,
 * DnsFreeFlat) matches its allocator rests on echo_dns_collector.cpp's existing contract.
 */
#pragma once

#ifdef _WIN32

#include <cstddef>
#include <type_traits>

#include <dns_cache_list.hpp> // portable walk + kDnsCacheNodeWalkCap

#include <windows.h> // must precede windns.h

#include <windns.h>

namespace yuzu::shared {

/// Node layout of the undocumented cache table (matches echo_dns_collector.cpp).
struct DnsCacheNode {
    DnsCacheNode* pNext;
    PWSTR pszName;
    WORD wType;
    WORD wDataLength;
    DWORD dwFlags;
};

class DnsCacheTableOwner {
public:
    using DnsFreeFn = VOID(WINAPI*)(PVOID, DNS_FREE_TYPE);

    /// `dnsapi` is the module DnsGetCacheDataTable came from (still loaded for the owner's life).
    explicit DnsCacheTableOwner(HMODULE dnsapi) noexcept
        : free_fn_(dnsapi ? reinterpret_cast<DnsFreeFn>(
                                reinterpret_cast<void*>(GetProcAddress(dnsapi, "DnsFree")))
                          : nullptr) {}

    DnsCacheTableOwner(const DnsCacheTableOwner&) = delete;
    DnsCacheTableOwner& operator=(const DnsCacheTableOwner&) = delete;

    ~DnsCacheTableOwner() { release(); }

    /// Where DnsGetCacheDataTable writes the list head. Release any prior list first.
    DnsCacheNode** out() noexcept {
        release();
        return &head_;
    }
    DnsCacheNode* head() const noexcept { return head_; }

    void release() noexcept {
        DnsCacheNode* head = head_;
        head_ = nullptr;
        if (!free_fn_)
            return;
        release_dns_cache_list(head, [this](void* p) { free_fn_(p, DnsFreeFlat); });
    }

private:
    DnsCacheNode* head_ = nullptr;
    DnsFreeFn free_fn_ = nullptr;
};

static_assert(!std::is_copy_constructible_v<DnsCacheTableOwner> &&
                  !std::is_move_constructible_v<DnsCacheTableOwner> &&
                  !std::is_copy_assignable_v<DnsCacheTableOwner> &&
                  !std::is_move_assignable_v<DnsCacheTableOwner>,
              "DnsCacheTableOwner owns a foreign list: it must be neither copied nor moved");

} // namespace yuzu::shared

#endif // _WIN32
