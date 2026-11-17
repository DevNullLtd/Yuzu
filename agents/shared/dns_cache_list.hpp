/**
 * dns_cache_list.hpp -- the portable core of releasing the list returned by the undocumented
 * dnsapi export `DnsGetCacheDataTable` (F64/F66). No OS call: the free function is a parameter, so
 * the walk is unit-tested with a fake list on every host. The Windows owner is
 * win_dns_cache_table.hpp.
 *
 * The list is foreign memory from an undocumented API, so the walk does not trust its shape. It
 * keeps ONE set of every pointer it has seen, nodes and names alike, because a name may alias a
 * node (its own, a later one or an earlier one) and each block must be freed at most once:
 *  - a node already in the set ends the walk, checked BEFORE the node is read (it may already have
 *    been freed, as a node or as another node's name);
 *  - a name equal to its own node ends the walk (the node is recorded, not freed: leaked);
 *  - a name seen before AS A NAME (two healthy nodes sharing a buffer) is skipped, not freed
 *    again, and the walk continues; a name seen before as anything else ends the walk;
 *  - the node ceiling bounds a corrupted or cyclic pNext;
 *  - it never throws (the Windows owner's release() is noexcept): constructing the sets and all
 *    bookkeeping for a node happen inside try/catch, BEFORE pNext is read or anything is freed. A
 *    bad_alloc (even from a set's constructor, as on MSVC) stops the walk and the rest leaks.
 * Stopping always leaks the remainder rather than risking a second free. This guards LIST ALIASING
 * only; it says nothing about whether DnsFree(DnsFreeFlat) matches the list's allocator (see
 * WP12-risk-acceptance.md).
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
    std::size_t freed = 0;
    // The sets are constructed INSIDE the try: some standard libraries (MSVC's) allocate in a
    // container's constructor, and an allocation failure there must leak the list, not reach a
    // noexcept boundary and terminate the agent.
    try {
        Set seen;  // every node and name pointer seen so far (freed, or recorded just before a free)
        Set names; // the subset of `seen` that was seen AS a name
        for (Node* p = head; p != nullptr && freed < kDnsCacheNodeWalkCap;) {
            if (!seen.insert(static_cast<const void*>(p)).second)
                break; // before ANY read of *p: it may already be freed
            void* name = static_cast<void*>(p->pszName);
            if (name == static_cast<void*>(p))
                break; // name aliases its own node
            bool free_name = false;
            if (name != nullptr) {
                if (seen.insert(static_cast<const void*>(name)).second) {
                    names.insert(static_cast<const void*>(name));
                    free_name = true;
                } else if (names.find(static_cast<const void*>(name)) == names.end()) {
                    break; // aliases a node already seen
                }
            }
            Node* next = p->pNext; // only after the bookkeeping, and before the frees
            if (free_name)
                free_one(name);
            free_one(static_cast<void*>(p));
            ++freed;
            p = next;
        }
    } catch (...) {
        // bookkeeping could not allocate: whatever is left leaks (record-before-free: nothing
        // was freed without having been recorded first)
    }
    return freed;
}

} // namespace yuzu::shared
