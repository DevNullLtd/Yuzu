#pragma once

/// @file typed_inventory_sources.hpp
/// The set of TYPED daily-sync sources (ADR-0016). Each is persisted by its own
/// normalized store via a dedicated ingest seam — NOT the generic `InventoryStore`
/// blob store.
///
/// LOAD-BEARING: the gateway `ProxyInventory` generic-blob loop MUST skip these.
/// The direct `ReportInventory` path has **no** generic loop (the documented
/// "INTENTIONAL ASYMMETRY"), so a typed source that also lands in the generic store
/// (a) breaks direct/gateway parity (ADR-0016 §5), and (b) **leaks it past its own
/// securable** — the generic store is read by `query_inventory`/`get_agent_inventory`
/// on `Infrastructure:Read`, not the per-source gate (e.g. `Inventory:Read`), so the
/// device_ci serial/UUID/MAC would be readable without `Inventory:Read`.
///
/// ADDING A TYPED SOURCE = add its wire key to `kTypedInventorySources` (one place),
/// or it silently double-stores into the generic store on the gateway path.
///
/// The ONE list. Three consumers iterate it, so none may keep its own copy:
/// - the gateway skip, through `is_typed_inventory_source`;
/// - the background purge (`InventoryStore::drain_typed_sources`, started from run() in
///   server.cpp), which deletes each source's stray generic rows;
/// - the read filter in `InventoryStore::list_tables`/`get`/`query`/`count`, which excludes
///   every source here in SQL, so a stray row (an older server, or a server rolled
///   back below the change that added the source) is never readable through the
///   generic store's `Infrastructure:Read`/`Inventory:Read` surface.

#include <algorithm>
#include <array>
#include <string_view>

namespace yuzu::server {

inline constexpr std::array<std::string_view, 6> kTypedInventorySources = {
    "installed_software",
    "app_perf",
    "device_ci",
    // software_licensing (ADR-0024 Decision 5): registered in the SAME change
    // as its seam (software_licensing_ingestion) — omission would double-store
    // detected-licence rows (incl. `user_ref`) into the generic store on the
    // gateway path, readable under Infrastructure:Read, i.e. a leak past the
    // SoftwareLicensing securable.
    "software_licensing",
    // app_usage (Wave 7b, Part 20): registered before any agent could send it, so
    // a gateway-proxied blob never lands in the generic InventoryStore, readable
    // under Infrastructure:Read, i.e. a leak past the Forensics securable.
    "app_usage",
    // certificate_inventory (ADR-0070 D12, slice-2 PR 2a-1): reserved BEFORE the
    // source or its store exists. Until the seam lands its only effects are the
    // gateway skip and the read filter, which close the stray-row window for every
    // server at or after this change.
    "certificate_inventory",
};

// Each name is a plain lowercase identifier: never empty, and only [a-z0-9_]. The
// names are wire keys and SQL array elements, so a name outside that shape is a
// review decision, not an edit.
consteval bool typed_source_names_well_formed() {
    for (const auto name : kTypedInventorySources) {
        if (name.empty())
            return false;
        for (const char c : name)
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
                return false;
    }
    return true;
}
static_assert(typed_source_names_well_formed());

[[nodiscard]] constexpr bool is_typed_inventory_source(std::string_view source) {
    return std::ranges::find(kTypedInventorySources, source) != kTypedInventorySources.end();
}

} // namespace yuzu::server
