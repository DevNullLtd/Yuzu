#pragma once

/// @file inventory_routes.hpp
/// /software dashboard — the SOFTWARE inventory lens (installed-software list:
/// title -> installs -> versions -> installs-per-version, daily-synced, ADR-0016)
/// plus the "devices >" expansion (which devices run title X). Devices and their CI
/// record live on /hardware; /inventory only redirects there.
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only (CSP
/// blocks hx-on — onclick/oninput helpers instead). Reuses the shared full-page
/// shell (guardian_page_ui.cpp kGuardianDetailPageHtml) + its `.gp-*` component CSS.
///
/// AUTH: the /software page shell is auth-only chrome. The Software data fragments
/// (catalogue, versions, devices) gate SOLELY on `FleetReadFn` (ADR-0017 admit-then-filter):
///   * the catalogue / version counts are a fleet-wide aggregate that cannot be narrowed to a
///     management group, so a confined caller is refused them (audited `denied`); the host
///     view and the devices tables are admitted and narrowed by the gate's own scope;
///   * service-scoped API tokens are denied outright;
///   * every call that serves data (or is refused on scope) is audited, continuation pages
///     included.

#include <yuzu/server/auth.hpp>

#include "authz_gates.hpp"             // authz::FleetReadGate (the Software fragments' SOLE gate)
#include "inventory_types.hpp"       // InventoryDeviceRow / InventoryDevicesResult (store-free)
#include "software_catalogue_model.hpp" // KpiFigures (the page does no arithmetic of its own)
#include "software_list_model.hpp"      // TotalsReads (the Find software panel reads the REST lookup's model)
#include "software_inventory_store.hpp" // SoftwareCatalogRow / SoftwareVersionCount / SoftwareEntry / SoftwareFleetRow / *Query

#include <httplib.h>

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

// ── PURE renderers (implemented in inventory_ui.cpp) ─────────────────────────────
// Each returns an HTML fragment: the whole Software page (component CSS, title block and
// content) or the part an htmx request swaps into it (results, rows, an expansion). A
// `std::nullopt` data argument is a STORE DEGRADE → an honest
// "data unavailable" banner, NEVER an empty table (authoritative reads, ADR-0016 §7:
// an empty table reads as "installed nowhere" — the fail-open the store forbids).

// -- Software page (M.9): the rebuilt, catalogue-model-backed page ----------------
// Pure types + renderers (inventory_ui.cpp). Nothing here reads a clock, a store or a
// request: the route resolves everything into these values. A `std::nullopt` row/total
// is a STORE DEGRADE and renders the retry banner, never an empty table.

/// The filter set one Software request carries (already parsed by the model).
struct SoftwarePageFilters {
    std::string q, kind, ecosystem, source;
    std::string agent_id;     ///< host view: "" = the fleet
    std::string host_display; ///< hostname for `agent_id` (falls back to the id)
    int versions_min{0};
    std::string cursor;       ///< opaque next_cursor, echoed only by the Load-more sentinel
};

/// Full = the whole page; Results = `#sw-results` + the out-of-band chips/pills/sprawl tile;
/// Rows = the next page's `<tr>` rows + sentinel.
enum class SoftwarePageMode { Full, Results, Rows };

struct SoftwarePageData {
    std::optional<std::vector<SoftwareCatalogRow>> rows;
    std::optional<software_catalogue::KpiFigures> kpis;
    std::optional<SoftwareCatalogTotals> totals;
    std::optional<std::string> next_cursor;
    /// (hostname, agent_id) pairs for the host type-ahead, sorted, capped by the route.
    std::vector<std::pair<std::string, std::string>> hosts;
    std::size_t hosts_total{0}; ///< named hosts BEFORE the route's cap (> hosts.size() = truncated)
    std::int64_t now_secs{0};
    std::int64_t shown_before{0}; ///< titles already on the page (the `shown` hint)
    std::optional<std::string> caveat; ///< parse/cursor refusal: shown instead of a table
    bool confined{false};     ///< management-group-confined caller: no fleet figures
};

struct SoftwareDevicesTable {
    std::string name;
    std::optional<std::string> version; ///< nullopt = all versions
    std::optional<std::vector<SoftwareFleetRow>> rows;
    std::unordered_map<std::string, std::string> hostnames;
    /// agent_id -> server-receipt epoch of the last installed-software sync; nullopt = the
    /// bulk read degraded (every cell renders a dash with a "last sync time unavailable"
    /// tooltip, distinct from the plain dash of a never-synced device), a missing key = never synced.
    std::optional<std::unordered_map<std::string, std::int64_t>> last_synced;
    std::optional<std::string> next_cursor;
    std::optional<std::int64_t> total; ///< the catalogue row's exact distinct device_count
    std::int64_t shown_before{0};      ///< devices already shown, INCLUDING this page
    bool scoped{false};                ///< confined caller: no `of M`, management-group note
    std::int64_t now_secs{0};
};

// -- Find software panel (SAM-18): one searchable answer to "how many, on which devices, how
// fresh" through the SAME model the REST lookups (`GET /api/v1/inventory/software[/components]`)
// call, so the card equals the REST `totals` and the rows are the REST rows.

/// Rows per Find software page (the REST call line the panel shows carries the same `limit`).
inline constexpr std::int64_t kSoftwareFindPageSize = 50;

/// The panel's kind chips, in display order: "app" (Applications) or a component kind. This is
/// the one closed set: the route refuses any other `kind` before a read and the panel renders one
/// chip per entry. Native is not offered until its collector ships.
struct SoftwareFindKind {
    std::string_view token;
    std::string_view label;
};
inline constexpr std::array<SoftwareFindKind, 4> kSoftwareFindKinds{{{"app", "Applications"},
                                                                     {"java", "Java"},
                                                                     {"python", "Python"},
                                                                     {"node", "Node"}}};

/// The panel's inputs as the route parsed them. `kind` is "app" (Applications) or a component
/// kind: "java" | "python" | "node" (kSoftwareFindKinds).
struct SoftwareFindFilters {
    std::string name, kind{"app"}, version, version_min, version_max;
    std::string status;  ///< "" | "unconfirmed" (the "show only these" link)
    std::string cursor;  ///< non-empty = a Load-more page: the rows only
};

/// True when the filters select a component kind (the components model), not applications.
[[nodiscard]] inline bool find_is_components(const SoftwareFindFilters& f) {
    return f.kind != "app";
}

/// One table row, resolved by the route (hostname, last poll) so the renderer reads nothing.
struct SoftwareFindRow {
    std::string agent_id;
    std::string hostname;  ///< "" = the roster does not know the device
    std::string os;        ///< the roster's OS string; "" = unknown
    std::string ecosystem; ///< installs only: the OS-family fallback when the roster has no OS
    std::string name;
    std::string version;
    std::string version_source; ///< components: where the version was read from
    std::string path;           ///< installs: install location; components: the component path
    std::string anchor_app;     ///< components: the application folder it sits inside
    std::string install_type;   ///< installs only
    std::string status;         ///< current | unconfirmed | disabled
    std::int64_t last_confirmed_at{0};     ///< installs only (the component table has no such column); 0 = never
    std::optional<std::int64_t> last_synced; ///< server-receipt epoch of the last sync; nullopt = never
};

/// The REST `totals` block as the panel shows it. `devices_unconfirmed` is served for components
/// only (the model does not return it for installs).
struct SoftwareFindTotals {
    std::int64_t rows{0};
    std::int64_t devices{0};
    std::int64_t devices_unconfirmed{0};
    std::optional<std::int64_t> as_of; ///< rollup refresh epoch; nullopt = computed live
};

struct SoftwareFindData {
    SoftwareFindFilters f;
    /// nullopt = STORE DEGRADE: the retry banner, never an empty table.
    std::optional<std::vector<SoftwareFindRow>> rows;
    std::optional<SoftwareFindTotals> totals;
    std::string totals_omitted; ///< when !totals: "scope" | "filters" | "building"
    std::string next_cursor;    ///< non-empty = more rows follow
    std::int64_t shown_before{0}; ///< rows on the page(s) loaded so far, this one included
    bool confined{false};         ///< management-group-confined caller: no fleet count
    std::int64_t now_secs{0};
    std::optional<std::string> caveat; ///< parse/cursor refusal: shown instead of a table (200)
};

/// The fragment `/fragments/inventory/software/find` swaps into `#fs-results`; a Load-more
/// request (`f.cursor` non-empty) returns the next `<tr>` rows instead.
[[nodiscard]] std::string render_software_find(const SoftwareFindData& d);

[[nodiscard]] std::string render_software_page(const SoftwarePageFilters& f,
                                               const SoftwarePageData& d, SoftwarePageMode mode);
/// `confined` blanks the "newest in fleet" mark (mirrors the REST `newest_omitted`).
/// `truncated` = the read hit its row limit: one muted line says the list is the top slice.
[[nodiscard]] std::string
render_software_versions_expansion(const SoftwarePageFilters& f, const std::string& name,
                                   const std::optional<std::vector<SoftwareVersionCount>>& v,
                                   bool confined, bool truncated = false);
[[nodiscard]] std::string render_software_devices_table(const SoftwarePageFilters& f,
                                                        const SoftwareDevicesTable& t,
                                                        bool rows_only);
/// `/fragments/inventory/software?...`. `with_inputs=false` leaves out `q` and `agent_id`: the
/// controls carry those through `hx-include` and the model's parser refuses a repeated key.
/// The Load-more sentinel passes true (its cursor is bound to the whole filter set).
[[nodiscard]] std::string software_page_url(const SoftwarePageFilters& f, SoftwarePageMode mode,
                                            bool with_inputs);
/// The REST call the current filters correspond to (the copy-able line under the pills).
[[nodiscard]] std::string software_rest_call(const SoftwarePageFilters& f);
/// URL-hash form of the filters: q, kind, eco, src, host, vmin (`later` is client-only).
[[nodiscard]] std::string software_page_hash(const SoftwarePageFilters& f);
/// `<script>` appended to the /software shell: hash <-> filters, expansion toggles, host
/// type-ahead. CSP-safe (no hx-on, no eval).
[[nodiscard]] std::string software_page_script();

/// /software routes — the `/inventory` 302, the page shell + the read-only HTMX fragments. Providers are
/// injected closures (store-decoupled) so the handlers are unit-testable via
/// TestRouteSink without a live Postgres.
class InventoryRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;

    /// The Software fragments' SOLE authorization gate (ADR-0017 admit-then-filter; same
    /// contract as HardwareRoutes::FleetReadFn): `admitted == false` means the response is
    /// already written (401/403/503); the returned scope is applied by the route and is the
    /// only filter. Empty closure = the fragments 503.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;

    /// Software catalogue / totals / version drill / fleet name query. Each returns nullopt
    /// on a store degrade (the renderer shows the banner). Empty closures = no provider
    /// wired -> the route renders the "unavailable" state.
    using CatalogFn =
        std::function<std::optional<std::vector<SoftwareCatalogRow>>(const SoftwareCatalogQuery&)>;
    /// Catalogue rollup freshness stamp + headline counts (the "as of" line + KPIs).
    using CatalogMetaFn = std::function<std::optional<CatalogRollupMeta>()>;
    using TotalsFn =
        std::function<std::optional<SoftwareCatalogTotals>(const SoftwareCatalogQuery&)>;
    using VersionsFn = std::function<std::optional<std::vector<SoftwareVersionCount>>(
        const SoftwareVersionsQuery&)>;
    using FleetSoftwareFn =
        std::function<std::optional<std::vector<SoftwareFleetRow>>(const SoftwareFleetQuery&)>;

    /// Current count of agents whose installed_software inventory is stale (freshness
    /// KPI). Empty / nullopt → the KPI renders "—".
    using StaleFn = std::function<std::optional<std::int64_t>()>;

    /// Devices currently connected (the strip's coverage tile). nullopt -> "—".
    using ConnectedFn = std::function<std::optional<std::int64_t>()>;

    /// Last installed-software sync (server receipt epoch) for a page of agents; nullopt =
    /// degrade, a missing key = never synced. See SoftwareInventoryStore::source_last_seen_bulk.
    using LastSyncedFn = std::function<std::optional<std::unordered_map<std::string, std::int64_t>>(
        const std::vector<std::string>&)>;

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

    /// Find software panel reads (the REST lookups' own store calls, injected so the route is
    /// unit-testable). Each returns nullopt on a store degrade.
    using ComponentsFn = std::function<std::optional<std::vector<SoftwareComponentRow>>(
        const SoftwareComponentQuery&)>;
    /// Live distinct versions of one installed title / component over the caller's scope
    /// (`software_list::scope_ids`), the input of a version range.
    using InstallVersionsFn = std::function<std::optional<std::vector<std::string>>(
        const std::string& name, const std::optional<std::vector<std::string>>& agent_ids)>;
    using ComponentVersionsFn = std::function<std::optional<std::vector<std::string>>(
        const std::string& kind, const std::string& name,
        const std::optional<std::vector<std::string>>& agent_ids)>;
    /// agent_id -> OS string from the device roster (one read per page); empty = OS unknown.
    using HostOsFn = std::function<std::unordered_map<std::string, std::string>()>;

    /// Everything the routes need, by name. The Software fragments use `fleet_read_fn` as
    /// their ONLY gate.
    struct Deps {
        AuthFn auth_fn;
        FleetReadFn fleet_read_fn;
        CatalogFn catalog_fn;
        CatalogMetaFn catalog_meta_fn;
        TotalsFn totals_fn;
        VersionsFn versions_fn;
        FleetSoftwareFn fleet_fn;
        StaleFn stale_fn;
        ConnectedFn connected_fn;
        HostnamesFn hostnames_fn;
        LastSyncedFn last_synced_fn;
        AuditFn audit_fn;
        // Find software panel (SAM-18).
        ComponentsFn components_fn;
        InstallVersionsFn install_versions_fn;
        ComponentVersionsFn component_versions_fn;
        software_list::TotalsReads totals_reads;
        HostOsFn host_os_fn;
    };

    void register_routes(httplib::Server& svr, Deps deps);

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, Deps deps);

private:
    Deps deps_;
};

} // namespace yuzu::server
