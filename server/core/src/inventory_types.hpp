#pragma once

/// @file inventory_types.hpp
/// Plain value types for the device-CI roster (`InventoryDeviceRow`,
/// `InventoryDevicesResult`), split out of `inventory_routes.hpp` so the
/// hardware read model (`hardware_list_model.hpp`) and the MCP registry lane
/// (`mcp_tool_deps.hpp`) can name a row without including the Software
/// dashboard header, which pulls `software_inventory_store.hpp` (ADR-0031 seam
/// closure, #6558). `inventory_routes.hpp` re-includes this header, so existing
/// includers are unaffected. No behaviour lives here.

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

/// One row of the device-CI inventory list — host/OS/online/last-seen sourced from
/// the persisted endpoint_state store (+ the live registry's online set), PLUS the
/// device-CI enrichment (PR2, `DeviceInventoryStore`-backed, attached by
/// `attach_device_ci` in `inventory_ci_join.cpp`). A `ci_*` field is an empty string
/// OR the literal `"unknown"` sentinel when the agent hasn't synced yet / doesn't
/// know it (e.g. a serial-less VM) — render via hardware_ui.cpp's `ci_disp()`
/// helper, never raw.
struct InventoryDeviceRow {
    std::string agent_id;
    std::string hostname;
    std::string os;        ///< "windows" | "linux" | "darwin" | "?"
    bool online = false;   ///< has a live Subscribe stream right now (registry)
    std::string last_seen; ///< human-ish ("now", "12m ago", "3d ago"); "" if unknown
    bool stale = false;    ///< last heartbeat older than the staleness window

    std::string ci_serial;
    std::string ci_model;
    std::string ci_cpu_cores;   ///< decimal string
    std::string ci_cpu_threads; ///< decimal string
    std::string ci_ram_bytes;   ///< decimal string (bytes)

    // Hardware CI list/record fields (feat/hardware-ci-view). Same sentinel
    // semantics as the fields above: empty or the literal "unknown" when the
    // agent hasn't synced yet — render via ci_disp(), never raw.
    std::int64_t last_seen_ms = -1; ///< server receipt epoch ms; -1 = unknown (sort key).
                                    ///< An online row carries "now" at render time.
    std::string ci_manufacturer;
    std::string ci_cpu_model;
    std::string ci_os_name;
    std::string ci_os_version;
    std::string ci_os_build;
    std::string ci_arch;
    std::string ci_domain;
    std::string ci_primary_mac;

    // Round-3 merge fields (the retired /devices list + /device entity page folded
    // into Hardware — nothing left duplicated between the two surfaces):
    /// Online: the live session's self-reported agent_version (registry, identity
    /// field, lock-free). Offline: the last value a session of this agent reported,
    /// persisted in endpoint_state (empty until that migration lands). "" = unknown.
    std::string agent_version;
    /// Same online/offline provenance as agent_version. Prefer this over ci_arch
    /// when both are present — it is the agent's own self-report, not a device-CI
    /// sync cycle that may be up to 24h stale.
    std::string arch;
    /// Claimed IPs from the live TAR fleet-snapshot cache (FleetTopologyStore,
    /// 60s TTL) — ONLINE-ONLY, evicted on deregistration. Empty is honest for an
    /// offline row, not a degrade: there is no durable IP source today (round-3
    /// item 10; a device-CI blob field is the tracked follow-up).
    std::vector<std::string> ips;
    /// Tags (TagStore, bulk-preloaded once per roster build — never a
    /// per-row store read). Empty is a genuine "no tags", not a degrade; see
    /// InventoryDevicesResult::tags_degraded for the degrade case.
    std::vector<std::pair<std::string, std::string>> tags;
    /// DEX experience score 0-100, scored ONLY for rows the caller is about to
    /// render (device_routes.cpp's "score only rendered rows" rule — a GROUP-BY
    /// per device is too costly to run over the whole roster). -1 = not scored /
    /// no GuaranteedStateStore wired.
    int dex_score = -1;
};

/// Result of the device-CI roster read. `rows` is the roster and is ALWAYS populated
/// on the happy path — a CI-store failure never blanks the whole list, only the CI
/// columns on the affected rows (the endpoint_state roster and the device-CI
/// enrichment are two independent reads; see `attach_device_ci`). `ci_degraded` is
/// true when the CI-enrichment read itself failed (or was never wired), so any CI
/// columns on `rows` are blank rather than genuinely absent — the Hardware list's
/// "CI columns unavailable" banner and the REST `ci_degraded` field read this bit so a
/// partial read is never shown as genuinely-empty columns (#1785 review HIGH-1). The
/// `inventory.devices` audit row is `success` unless `roster_degraded` is set, which
/// audits `failure`; `ci_degraded` alone does not change it.
struct InventoryDevicesResult {
    std::vector<InventoryDeviceRow> rows;
    bool ci_degraded = false;
    /// True when the bulk tag preload failed (TagStore degrade / unwired) — every
    /// row's `tags` is then genuinely empty-because-degraded, not empty-because-
    /// no-tags; the Tags column renders an honest note instead of a blank column.
    bool tags_degraded = false;
    /// True when the durable roster read itself failed (#5531): `rows` is then
    /// empty-because-unread, never empty-because-no-devices.
    bool roster_degraded = false;
};

} // namespace yuzu::server
