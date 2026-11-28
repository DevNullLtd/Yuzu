#pragma once

/// @file device_api.hpp
/// The FOURTH per-family in-process API seam for the presentation/core/engine
/// split (ADR-0031, WS-A4, family=`device`), copying the merged
/// `network_api.hpp`/`verify_api.hpp`/`compliance_api.hpp` templates
/// verbatim in shape. Abstract, ZERO store-shaped dependencies — only std
/// headers, so this header can be included by a future presentation-side
/// client without dragging the server's `AgentRegistry`/`TagStore` layer
/// along.
///
/// The PUBLIC method set == the public REST resources it stands in front of, 1:1
/// (INV-31-4 "no private core API"):
///   - `list_devices`   <-> `GET /api/v1/devices`      (MCP `list_agents`)
///   - `lookup_device`  <-> `GET /api/v1/devices/{id}`  (MCP `get_agent_details`)
///
/// -- IN-PROCESS READ SHAPES (#2240): NO REST/MCP TWIN, NOT CONFINED --
/// `list_devices_basic()` and `connected_count()` are projections of `list_devices()` for
/// in-process callers that do not serialise the per-device backend field (the dashboard device
/// fragment, the crypto hostname map, the two page-render connected counts). They are NOT public
/// resources and add no route or tool. Like `list_devices()` they are UNFILTERED and fleet-wide
/// (see the next banner): `connected_count()` is the replica-local registry size, the same
/// population `list_devices()` builds rows from. They are the first defaulted virtuals on a seam
/// in this tree, by design: a test double or a future remote (WS-B2) client that implements only
/// `list_devices()` inherits correct, if slower, defaults. A remote client MUST NOT add a route
/// for them (a new public resource needs REST and MCP twins, ADR-1005); it inherits the defaults
/// or uses a query option on `GET /api/v1/devices`. Note a remote count would then be filtered to
/// the caller's scope, unlike the local fleet-wide one (on REST, `count + devices_omitted` recovers
/// the fleet figure; a query option is itself a change to the public resource and needs REST and
/// MCP parity and an OpenAPI entry).
///
/// The store-backed factory (`make_local_device_api`) lives in the core-only
/// `device_api_local.hpp` — this header names no store type at all, not even
/// by forward declaration, so a presentation TU including it cannot reach one.
///
/// ── UNSCOPED DATA PROVIDER — READ BEFORE ADDING A CONSUMER (mirrors
/// compliance_api.hpp's identical banner) ──
/// `list_devices()` (and `list_devices_basic()`/`connected_count()`) return the registry's
/// UNFILTERED, fleet-wide rows or count: every connected agent, regardless of the caller's own
/// management-group confinement. This is a fan-out read of per-agent data (routed-concerns'
/// `authorize_list_read`/`require_fleet_read` MUST, ADR-0017 World A) —
/// EVERY consumer MUST apply the fleet-read/confinement gate appropriate to
/// its surface before serving this result to a caller (MCP `list_agents` does
/// so via `fleet_read_fn_`). A new fan-out read gates. The seam itself
/// is a store-free DATA PROVIDER only; auth, confinement and audit live in the
/// consumer (route/MCP handler), not here.
///
/// ── #3564 POINT-LOOKUP NOTE — READ BEFORE CHANGING `lookup_device` ──
/// `lookup_device` MUST resolve via an O(1) registry point lookup
/// (`AgentRegistry::get_session`), NEVER a linear scan over the fleet. A scan
/// whose length distinguishes "exists but not in your scope" from
/// "nonexistent" is a caller-visible timing oracle (#3564) — the O(1) point
/// lookup keeps a genuine miss cost-symmetric with a hit at this layer, and
/// this method itself performs no scoping. The confinement decision belongs to
/// the consumer, which MUST apply its own confinement gate on the requested id
/// and deny an out-of-scope id BEFORE calling this method — flat `in_scope` for
/// the REST and MCP handlers, the ancestor-aware `scoped_perm_fn`
/// (`require_scoped_permission`) for the dashboard fragment handlers. Whichever
/// gate applies, an out-of-scope caller triggers ZERO backing read here and
/// cannot learn an id exists by timing or via the degraded (`kDegraded`) branch
/// (governance #3564, security-guardian + architect). Reaching `lookup_device`
/// implies the caller has already cleared its consumer's confinement gate.

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// One device row — the shape `GET /api/v1/devices` serves (mirrors
/// `device_agent_row_json`'s exact 6-field set, `device_routes.cpp`: five registry-derived
/// fields plus `guardian_backend`, which is derived from the heartbeat health store, not the
/// registry).
/// Deliberately does NOT carry `online`/`last_seen`/`segment`/`dex_score` —
/// those are either hardcoded constants, never assigned, or DEX-family data
/// server.cpp's `DeviceRow` type carries for the dashboard fragment; this
/// seam's row is the narrower public REST/MCP shape only.
///
/// `guardian_backend` MUST stay the LAST member: several test doubles build this struct with
/// designated initialisers, which must keep compiling when a later field is appended.
struct DeviceListRow {
    std::string agent_id;
    std::string hostname;
    std::string os;       ///< "windows" | "linux" | "darwin" | "" (unknown)
    std::string arch;     ///< "x86_64" | "arm64" | "" (unknown)
    std::string agent_version;
    /// "legacy" | "spark" | "spark_failed" | "unwired", taken from the server's closed token
    /// table (guardian_backend_fleet_tags.hpp), never the raw heartbeat bytes. nullopt = NOT
    /// REPORTED: an agent older than the tag, no Guardian, a Guardian heartbeat tag group that
    /// faulted this beat, a rejected or forged value, no heartbeat within the health store's
    /// staleness window (kAgentHealthStaleness), or no heartbeat yet. It NEVER defaults to
    /// "legacy". Serialised as JSON null, key always present.
    std::optional<std::string> guardian_backend;
};

/// One tag triple — this seam's OWN shape (deliberately not `tag_store.hpp`'s
/// `DeviceTag`, which also carries `agent_id`/`updated_at`; those fields are
/// redundant inside a `DeviceDetail` already keyed by agent and are store-
/// shaped, which this header may not name).
struct DeviceTagRow {
    std::string key;
    std::string value;
    std::string source; ///< "agent" | "server" | "api" | "mcp"
};

/// Single-device detail — the shape `GET /api/v1/devices/{id}` serves:
/// `DeviceListRow`'s fields (including `guardian_backend`) plus the device's tags.
struct DeviceDetail {
    DeviceListRow row;
    std::vector<DeviceTagRow> tags;
};

/// The seam's one failure mode: a wired-but-degraded backing read (today,
/// only the tag-store lookup backing `lookup_device`'s `tags` field can fail
/// this way — the registry reads underneath both methods do not have a
/// "degraded" state of their own, only miss/hit). Mirrors
/// `compliance_types.hpp`'s `PolicyReadError` shape.
enum class DeviceReadError { kDegraded };

/// The in-process public device API. Its public methods (`list_devices`, `lookup_device`) are
/// the REST/MCP resources listed in the file banner above, so presentation/MCP consume only what
/// the public, versioned core API serves (ADR-0031 B3, INV-31-4) -- a local in-process client
/// today, a core HTTP client after the WS-B2 cutover. `list_devices_basic` and `connected_count`
/// are in-process projections of `list_devices` with no twin (see "IN-PROCESS READ SHAPES").
class DeviceApi {
public:
    virtual ~DeviceApi() = default;

    /// The fleet-wide device list — the shape `GET /api/v1/devices` serves.
    /// See the file banner's UNSCOPED DATA PROVIDER note: unfiltered,
    /// fleet-wide, no tags. Never fails (a registry read has no degraded
    /// state) — an empty fleet is a valid, honest empty vector.
    ///
    /// COST: each row's `guardian_backend` costs one health-store lookup. They are taken under
    /// that store's mutex (the heartbeat upsert path) in slices of kGuardianBackendSlice ids with
    /// a short pause between slices, so the list is not one snapshot and, for this accessor, an
    /// upsert waits for one slice rather than the whole fleet (agent_registry.hpp has the
    /// measurements and the stalls the sweep still causes). Only a caller that SERIALISES the
    /// field should pay that: today GET /api/v1/devices and MCP list_agents. Every other caller
    /// uses `list_devices_basic()` (rows, no lookup) or `connected_count()` (a number).
    [[nodiscard]] virtual std::vector<DeviceListRow> list_devices() const = 0;

    /// The same rows and order as `list_devices()` with `guardian_backend` always nullopt and NO
    /// health-store read. For callers that discard the field: the dashboard device fragment
    /// (which must never carry it) and the crypto hostname map. Non-pure so a test double that
    /// only overrides `list_devices()` keeps compiling; the default clears the field from it.
    [[nodiscard]] virtual std::vector<DeviceListRow> list_devices_basic() const {
        auto rows = list_devices();
        for (auto& row : rows)
            row.guardian_backend.reset();
        return rows;
    }

    /// How many devices `list_devices()` would return right now, without building the rows. For
    /// the two page-render connected counts. Non-pure for the same reason; the default counts
    /// `list_devices_basic()`.
    [[nodiscard]] virtual std::size_t connected_count() const {
        return list_devices_basic().size();
    }

    /// Single-device lookup by id — the shape `GET /api/v1/devices/{id}`
    /// serves. `nullopt` (inside the engaged `expected`) on a genuine miss —
    /// see the file banner's #3564 POINT-LOOKUP NOTE: this is never
    /// distinguished from an existing-but-out-of-scope id at this layer.
    /// `std::unexpected(DeviceReadError::kDegraded)` when the id resolves but
    /// the backing tag-store read fails (mirrors the REST route's existing
    /// 503-on-tag-store-degrade posture, `rest_api_v1.cpp`'s
    /// `/api/v1/devices/{id}` handler).
    [[nodiscard]] virtual std::expected<std::optional<DeviceDetail>, DeviceReadError>
    lookup_device(const std::string& agent_id) const = 0;
};

} // namespace yuzu::server
