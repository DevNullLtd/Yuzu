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
/// ADDING A TYPED SOURCE = add its wire key here (one place), or it silently
/// double-stores into the generic store on the gateway path.

#include <string_view>

namespace yuzu::server {

[[nodiscard]] inline bool is_typed_inventory_source(std::string_view source) {
    // software_licensing (ADR-0024 Decision 5): registered in the SAME change
    // as its seam (software_licensing_ingestion) — omission would double-store
    // detected-licence rows (incl. `user_ref`) into the generic store on the
    // gateway path, readable under Infrastructure:Read, i.e. a leak past the
    // SoftwareLicensing securable.
    // app_usage (Wave 7b, Part 20): this identical hunk lives in BOTH PR7b.2 and PR7b.3 so
    // no release can carry the agent-side app_usage daily-sync source without this skip —
    // otherwise a gateway-proxied blob lands in the generic InventoryStore, readable under
    // Infrastructure:Read (query_inventory/get_agent_inventory), i.e. a leak past the
    // Forensics securable. Registered here, never inline in the gateway loop.
    return source == "installed_software" || source == "app_perf" || source == "device_ci" ||
           source == "software_licensing" || source == "app_usage";
}

} // namespace yuzu::server
