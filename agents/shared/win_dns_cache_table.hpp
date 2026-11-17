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
 * bounded leak is safer than freeing with the wrong allocator). The walk is bounded by a node
 * ceiling, like the echo collector's, so a corrupted or cyclic pNext cannot loop forever; past the
 * ceiling the remaining nodes leak rather than risk an unbounded loop.
 *
 * COMPILED ONLY ON WINDOWS: not built on the Linux dev host (see the WP12 hand-back).
 */
#pragma once

#ifdef _WIN32

#include <cstddef>

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

/// Ceiling on nodes walked/freed, far above any real resolver cache (same figure as echo).
inline constexpr std::size_t kDnsCacheNodeWalkCap = 65536;

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
        DnsCacheNode* p = head_;
        head_ = nullptr;
        if (!free_fn_)
            return;
        std::size_t nodes = 0;
        while (p && ++nodes <= kDnsCacheNodeWalkCap) {
            DnsCacheNode* next = p->pNext;
            if (p->pszName)
                free_fn_(p->pszName, DnsFreeFlat);
            free_fn_(p, DnsFreeFlat);
            p = next;
        }
    }

private:
    DnsCacheNode* head_ = nullptr;
    DnsFreeFn free_fn_ = nullptr;
};

} // namespace yuzu::shared

#endif // _WIN32
