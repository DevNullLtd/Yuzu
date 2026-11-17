/**
 * dns_cache_list.hpp -- the portable core of releasing the list returned by the undocumented
 * dnsapi export `DnsGetCacheDataTable` (F64/F66). No OS call: the free function is a parameter, so
 * the walk is unit-tested with a fake list on every host. The Windows owner is
 * win_dns_cache_table.hpp.
 *
 * The list is foreign memory from an undocumented API, so the walk does not trust its shape:
 *  - it is bounded by a node ceiling (a corrupted or cyclic pNext cannot loop forever);
 *  - every node AND name pointer is tracked as it is freed, and the walk stops at the first one
 *    seen twice (a cycle, or two nodes sharing a node or a name, inside the ceiling would
 *    otherwise be a double free). Whatever is left past that point leaks rather than risking a
 *    second free.
 */
#pragma once

#include <cstddef>
#include <unordered_set>

namespace yuzu::shared {

/// Ceiling on nodes walked/freed, far above any real resolver cache (same figure as echo).
inline constexpr std::size_t kDnsCacheNodeWalkCap = 65536;

/// `Node` has `Node* pNext` and a pointer member `pszName`. `free_one(void*)` frees one flat
/// block. Returns the number of nodes freed.
template <typename Node, typename FreeFn>
std::size_t release_dns_cache_list(Node* head, FreeFn&& free_one) {
    std::unordered_set<const void*> seen;
    std::size_t freed = 0;
    for (Node* p = head; p != nullptr && freed < kDnsCacheNodeWalkCap;) {
        if (!seen.insert(p).second)
            break; // revisited node: cycle or shared node
        Node* next = p->pNext;
        if (p->pszName != nullptr && !seen.insert(static_cast<const void*>(p->pszName)).second)
            break; // revisited name buffer: stop before freeing anything twice
        if (p->pszName != nullptr)
            free_one(static_cast<void*>(p->pszName));
        free_one(static_cast<void*>(p));
        ++freed;
        p = next;
    }
    return freed;
}

} // namespace yuzu::shared
