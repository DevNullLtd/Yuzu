#pragma once

/// @file inventory_routes.hpp
/// Dedicated /inventory dashboard — the SOFTWARE inventory lens (installed-software
/// list: title -> installs -> versions -> installs-per-version, daily-synced,
/// ADR-0016) plus a device-CI inventory tab (host / OS / online / last-seen,
/// sourced from the persisted, offline-survivable endpoint_state store so offline
/// devices still appear) and a fleet "find software" tab (which devices run X).
///
/// The device tab's CI columns (serial / model / CPU / RAM) and the per-device CI
/// panel are real (PR2) — sourced from `DeviceInventoryStore` (the `device_ci`
/// daily-sync source, ADR-0016 source #3). Disk and owner/location are deliberately
/// NOT shown yet: disk is deferred pending a macOS `do_disks` collection fix;
/// owner/location are not agent-collected (future operator-set CMDB enrichment).
/// Clicking a device shows its CI record + installed software (get_agent_software).
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only (CSP
/// blocks hx-on — onclick/oninput helpers instead). Reuses the shared full-page
/// shell (guardian_page_ui.cpp kGuardianDetailPageHtml) + its `.gp-*` component CSS.
///
/// AUTH: the /inventory page shell is auth-only chrome. The data fragments gate on
/// the GLOBAL `Inventory:Read` (the same securable + scope predicate the REST
/// /api/v1/inventory/software route + the MCP query_installed_software tool use):
///   * SOFTWARE catalogue / version drill / FIND are FLEET-WIDE aggregates — gated on
///     global Inventory:Read; the catalogue/version counts are NOT management-group
///     scoped (ADR-0017 confinement inert under the global gate — caveated in the UI),
///     and FIND applies the same per-row management-group drop filter the REST sibling
///     does (+ audits the omission);
///   * the PER-DEVICE software drill gates on `scoped_perm_fn(Inventory,Read,id)` — the
///     tier + management-group chokepoint — so an operator only reads a device inside
///     their scope, and audits the access (set-and-proceed; machine-scope data, lower
///     sensitivity than the behavioural-PII device lenses).

#include <yuzu/server/auth.hpp>

#include "device_inventory_store.hpp"    // DeviceCiRecord / CiReadError (device-CI panel, PR2)
#include "software_inventory_store.hpp" // SoftwareCatalogRow / SoftwareVersionCount / SoftwareEntry / SoftwareFleetRow / *Query

#include <httplib.h>

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

/// One row of the device-CI inventory list — host/OS/online/last-seen sourced from
/// the persisted endpoint_state store (+ the live registry's online set), PLUS the
/// device-CI enrichment (PR2, `DeviceInventoryStore`-backed, attached by
/// `attach_device_ci` in `inventory_ci_join.cpp`). A `ci_*` field is an empty string
/// OR the literal `"unknown"` sentinel when the agent hasn't synced yet / doesn't
/// know it (e.g. a serial-less VM) — render via the shared `ci_disp()` helper
/// (inventory_ui.cpp), never raw.
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
    /// Key-sorted tags (TagStore, bulk-preloaded once per roster build — never a
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
/// columns on `rows` are blank rather than genuinely absent — the audit layer needs
/// this bit to avoid recording "success" over a partial read (#1785 review HIGH-1).
struct InventoryDevicesResult {
    std::vector<InventoryDeviceRow> rows;
    bool ci_degraded = false;
    /// True when the bulk tag preload failed (TagStore degrade / unwired) — every
    /// row's `tags` is then genuinely empty-because-degraded, not empty-because-
    /// no-tags; the Tags column renders an honest note instead of a blank column.
    bool tags_degraded = false;
};

// ── PURE renderers (implemented in inventory_ui.cpp) ─────────────────────────────
// Each returns a self-contained fragment: the inventory sub-nav + the active tab's
// content. A `std::nullopt` data argument is a STORE DEGRADE → an honest
// "data unavailable" banner, NEVER an empty table (authoritative reads, ADR-0016 §7:
// an empty table reads as "installed nowhere" — the fail-open the store forbids).

/// SOFTWARE tab: the fleet catalogue table (title · publisher · installs · versions) +
/// an empty drill container, fed by the precomputed rollup. `meta` carries the rollup
/// freshness stamp + headline counts (KPIs + "as of" line); `meta->refreshed_at == 0`
/// renders the "catalogue building" state (distinct from a refreshed-but-empty fleet).
/// `name_filter` is echoed into the search box; `capped` flags the row-cap; `stale_count`
/// feeds the stale KPI (nullopt → "—"); `now_secs` lets the pure renderer format the
/// "as of" relative time without calling the clock itself.
/// `results_only=true` (round-3 item 8, mirrors hardware_ui.cpp's `results_only`
/// pattern) renders ONLY the `#sw-results` region (search results table + drill
/// container) — used by the search box's own hx-get so a re-render never destroys
/// the input mid-keystroke. `false` renders the full page (sub-nav + KPIs + the
/// same region).
std::string render_inventory_software_fragment(
    const std::optional<std::vector<SoftwareCatalogRow>>& catalogue,
    const std::optional<CatalogRollupMeta>& meta, const std::string& name_filter,
    std::optional<std::int64_t> stale_count, bool capped, std::int64_t now_secs,
    bool results_only = false);

/// SOFTWARE drill: installs-per-version for one title (the catalogue row click target).
std::string render_inventory_versions_fragment(
    const std::string& name, const std::optional<std::vector<SoftwareVersionCount>>& versions);

/// DEVICES tab (thin CI): the device list + an empty drill container. `q`/`os_token`/
/// `status_token` are echoed into the controls so the fragment is self-describing.
std::string render_inventory_devices_fragment(const std::vector<InventoryDeviceRow>& rows,
                                              const std::string& q, const std::string& os_token,
                                              const std::string& status_token);

/// PER-DEVICE drill: the CI record panel + installed software (get_agent_software).
/// `online` drives the "live vs last daily sync" note for an offline device. `ci`
/// mirrors `DeviceInventoryStore::get_device_ci`'s three-state authoritative read: a
/// value holding a record renders the CI panel; a value holding `std::nullopt` renders
/// an honest "no CI record yet"; `std::unexpected(kDegraded)` renders a degrade
/// banner. `now_secs` lets the pure renderer format first/last-synced relative time
/// without calling the clock itself (mirrors the software rollup's `now_secs`).
std::string render_inventory_device_software_fragment(
    const std::string& agent_id, const std::string& hostname,
    const std::optional<std::vector<SoftwareEntry>>& software, bool online,
    const std::expected<std::optional<DeviceCiRecord>, CiReadError>& ci, std::int64_t now_secs);

/// FIND tab shell: the search box (hx-get -> the results endpoint) + an empty results
/// container. No data read here (the shell is just chrome under Inventory:Read).
std::string render_inventory_find_fragment(const std::string& initial_name);

/// FIND results: which devices run software `name` (already scope-filtered). `hit_cap`
/// flags a truncated page; `devices_omitted` is the management-group drop count.
std::string render_inventory_find_results_fragment(
    const std::string& name, const std::optional<std::vector<SoftwareFleetRow>>& rows, bool hit_cap,
    std::size_t devices_omitted);

/// SOFTWARE "devices ›" expansion (round-3 item 8): the same "which devices run
/// this title" data as the (now-unlinked) Find tab, but rendered as an inline
/// expansion under a catalogue row instead of a standalone page — Signature and
/// Ecosystem columns (both already on `SoftwareEntry`, previously unrendered
/// anywhere) plus a client-side `gpSearch` filter box, since a popular title can
/// have hundreds of installs. `hostnames` resolves `agent_id -> hostname` (best-
/// effort; a miss renders the bare agent_id, never blocks the row). `nullopt` rows
/// = store degrade; `devices_omitted` mirrors the Find results' management-group
/// drop count.
std::string render_inventory_software_devices_fragment(
    const std::string& name, const std::optional<std::vector<SoftwareFleetRow>>& rows, bool hit_cap,
    std::size_t devices_omitted, const std::unordered_map<std::string, std::string>& hostnames);

/// /inventory routes — the page shell + the read-only HTMX fragments. Providers are
/// injected closures (store-decoupled) so the handlers are unit-testable via
/// TestRouteSink without a live Postgres.
class InventoryRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;
    /// Per-device tier + management-group scope gate (wraps require_scoped_permission).
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;

    /// FLEET-WIDE software catalogue / version drill / fleet name query. Each returns
    /// nullopt on a store degrade (the renderer shows the banner). Empty closures =
    /// no provider wired → the route renders the "unavailable" state.
    using CatalogFn =
        std::function<std::optional<std::vector<SoftwareCatalogRow>>(const SoftwareCatalogQuery&)>;
    /// Catalogue rollup freshness stamp + headline counts (the "as of" line + KPIs).
    using CatalogMetaFn = std::function<std::optional<CatalogRollupMeta>()>;
    using VersionsFn = std::function<std::optional<std::vector<SoftwareVersionCount>>(
        const std::string& name, int limit)>;
    using FleetSoftwareFn =
        std::function<std::optional<std::vector<SoftwareFleetRow>>(const SoftwareFleetQuery&)>;

    /// One device's installed software (per-device drill, post-authz).
    using AgentSoftwareFn =
        std::function<std::optional<std::vector<SoftwareEntry>>(const std::string& agent_id)>;

    /// The device-CI roster, scoped to `username` (offline-inclusive; assembled in
    /// server.cpp from endpoint_state + the registry online set + the visible-agent
    /// set + the device-CI enrichment join, `attach_device_ci`).
    using DevicesFn = std::function<InventoryDevicesResult(const std::string& username)>;

    /// One device's CI record (per-device drill's CI panel, post-authz — the
    /// `scoped_perm_fn(Inventory,Read,id)` gate already ran). Mirrors
    /// `DeviceInventoryStore::get_device_ci`'s three-state contract exactly: a value
    /// holding a record = found; a value holding `std::nullopt` = absent (no CI
    /// synced yet); `std::unexpected(kDegraded)` = store/pool/query failure —
    /// including an unwired closure, which the route treats the same as a live
    /// failure (mirrors `AgentSoftwareFn` unwired -> nullopt -> degrade banner).
    using AgentCiFn = std::function<std::expected<std::optional<DeviceCiRecord>, CiReadError>(
        const std::string& agent_id)>;

    /// Per-(operator, agent) management-group predicate for the FIND per-row scope drop
    /// (the same Inventory:Read scope predicate the REST route uses). Empty = no filter.
    using ScopeFn =
        std::function<bool(const std::string& username, const std::string& agent_id)>;

    /// Current count of agents whose installed_software inventory is stale (freshness
    /// KPI). Empty / nullopt → the KPI renders "—".
    using StaleFn = std::function<std::optional<std::int64_t>()>;

    /// who/when/what audit sink (bool = persisted). Reused from the shared audit_fn.
    using AuditFn = std::function<bool(const httplib::Request& req, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// Best-effort agent_id -> hostname resolution for the SOFTWARE "devices ›"
    /// expansion (round-3 item 8) — a hostname is friendlier than a raw agent_id
    /// in a devices-per-package table. Whole-map read (not per-agent) so a
    /// hundred-row expansion costs one call, not N; a miss for a given agent_id
    /// renders the bare id, never blocks the row. Empty closure = no resolution
    /// (every row shows its agent_id).
    using HostnamesFn = std::function<std::unordered_map<std::string, std::string>()>;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                         ScopedPermFn scoped_perm_fn, CatalogFn catalog_fn,
                         CatalogMetaFn catalog_meta_fn, VersionsFn versions_fn,
                         FleetSoftwareFn fleet_fn, AgentSoftwareFn agent_sw_fn, DevicesFn devices_fn,
                         ScopeFn scope_fn = {}, StaleFn stale_fn = {}, AuditFn audit_fn = {},
                         AgentCiFn agent_ci_fn = {}, HostnamesFn hostnames_fn = {});

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                         ScopedPermFn scoped_perm_fn, CatalogFn catalog_fn,
                         CatalogMetaFn catalog_meta_fn, VersionsFn versions_fn,
                         FleetSoftwareFn fleet_fn, AgentSoftwareFn agent_sw_fn, DevicesFn devices_fn,
                         ScopeFn scope_fn = {}, StaleFn stale_fn = {}, AuditFn audit_fn = {},
                         AgentCiFn agent_ci_fn = {}, HostnamesFn hostnames_fn = {});

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    ScopedPermFn scoped_perm_fn_;
    CatalogFn catalog_fn_;
    CatalogMetaFn catalog_meta_fn_;
    VersionsFn versions_fn_;
    FleetSoftwareFn fleet_fn_;
    AgentSoftwareFn agent_sw_fn_;
    DevicesFn devices_fn_;
    AgentCiFn agent_ci_fn_;
    ScopeFn scope_fn_;
    StaleFn stale_fn_;
    AuditFn audit_fn_;
    HostnamesFn hostnames_fn_;
};

} // namespace yuzu::server
