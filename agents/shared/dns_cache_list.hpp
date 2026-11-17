/**
 * dns_cache_list.hpp -- the portable core of releasing the list returned by the undocumented
 * dnsapi export `DnsGetCacheDataTable` (F64/F66). No OS call: the free function is a parameter, so
 * the walk is unit-tested with a fake list on every host. The Windows owner is
 * win_dns_cache_table.hpp.
 *
 * The list is foreign memory from an undocumented API, so the walk does not trust its shape:
 *  - it is bounded by a node ceiling (a corrupted or cyclic pNext cannot loop forever);
 *  - it stops at the first NODE seen twice (a cycle or a shared node would otherwise be a double
 *    free); whatever is left past that point leaks rather than risking a second free;
 *  - a NAME buffer seen twice (two healthy nodes aliasing one buffer) is freed once and skipped
 *    thereafter: that is not evidence the list is corrupt, so the walk continues;
 *  - it never throws (the Windows owner's release() is noexcept): the bookkeeping allocates, and if
 *    that throws the walk stops and the remainder leaks. All bookkeeping for a node is done BEFORE
 *    its blocks are freed, so a throw can never fall between a free and its record.
 */
#pragma once

#include <cstddef>
#include <unordered_set>

namespace yuzu::shared {

/// Ceiling on nodes walked/freed, far above any real resolver cache (same figure as echo).
inline constexpr std::size_t kDnsCacheNodeWalkCap = 65536;

/// `Node` has `Node* pNext` and a pointer member `pszName`. `free_one(void*)` frees one flat
/// block (and must not throw). `Set` is the visited-pointer set (a parameter so a test can inject
/// a throwing allocator). Returns the number of nodes freed.
template <typename Set = std::unordered_set<const void*>, typename Node, typename FreeFn>
std::size_t release_dns_cache_list(Node* head, FreeFn&& free_one) noexcept {
    Set seen_nodes;
    Set seen_names;
    std::size_t freed = 0;
    for (Node* p = head; p != nullptr && freed < kDnsCacheNodeWalkCap;) {
        Node* next = p->pNext;
        void* name = static_cast<void*>(p->pszName);
        bool free_name = false;
        try {
            if (!seen_nodes.insert(static_cast<const void*>(p)).second)
                break; // revisited node: cycle or shared node
            free_name = name != nullptr && seen_names.insert(name).second;
        } catch (...) {
            break; // bookkeeping could not allocate: leak the rest
        }
        if (free_name)
            free_one(name);
        free_one(static_cast<void*>(p));
        ++freed;
        p = next;
    }
    return freed;
}

} // namespace yuzu::shared
