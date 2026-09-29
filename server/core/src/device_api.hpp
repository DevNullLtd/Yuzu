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
/// The method set == the public REST resources it stands in front of, 1:1
/// (INV-31-4 "no private core API"):
///   - `list_devices`   <-> `GET /api/v1/devices`      (MCP `list_agents`)
///   - `lookup_device`  <-> `GET /api/v1/devices/{id}`  (MCP `get_agent_details`)
///
/// The store-backed factory (`make_local_device_api`) lives in the core-only
/// `device_api_local.hpp` — this header names no store type at all, not even
/// by forward declaration, so a presentation TU including it cannot reach one.
///
/// ── UNSCOPED DATA PROVIDER — READ BEFORE ADDING A CONSUMER (mirrors
/// compliance_api.hpp's identical banner) ──
/// `list_devices()` returns the registry's UNFILTERED, fleet-wide rows —
/// every connected agent, regardless of the caller's own management-group
/// confinement. This is a fan-out read of per-agent data (routed-concerns'
/// `authorize_list_read`/`require_fleet_read` MUST, ADR-0017 World A) —
/// EVERY consumer MUST apply the fleet-read/confinement gate appropriate to
/// its surface before serving this result to a caller — with ONE deliberate,
/// pre-existing exception: MCP `list_agents` serves these rows UNCONFINED by
/// design (the tracked World-A gap #4041, unchanged by the seam and byte-
/// identical to its pre-seam registry-callback behaviour). Do NOT replicate
/// that exemption in a new consumer; a new fan-out read gates. The seam itself
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

#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// One device row — the shape `GET /api/v1/devices` serves (mirrors
/// `device_agent_row_json`'s exact 5-field set, `device_routes.cpp`).
/// Deliberately does NOT carry `online`/`last_seen`/`segment`/`dex_score` —
/// those are either hardcoded constants, never assigned, or DEX-family data
/// server.cpp's `DeviceRow` type carries for the dashboard fragment; this
/// seam's row is the narrower public REST/MCP shape only.
struct DeviceListRow {
    std::string agent_id;
    std::string hostname;
    std::string os;       ///< "windows" | "linux" | "darwin" | "" (unknown)
    std::string arch;     ///< "x86_64" | "arm64" | "" (unknown)
    std::string agent_version;
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
/// `DeviceListRow`'s fields plus the device's tags.
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

/// The in-process public device API. Method set == the public REST/MCP
/// resources listed in the file banner above, so presentation/MCP consume
/// only what the public, versioned core API serves (ADR-0031 B3, INV-31-4) —
/// a local in-process client today, a core HTTP client after the WS-B2
/// cutover.
class DeviceApi {
public:
    virtual ~DeviceApi() = default;

    /// The fleet-wide device list — the shape `GET /api/v1/devices` serves.
    /// See the file banner's UNSCOPED DATA PROVIDER note: unfiltered,
    /// fleet-wide, no tags. Never fails (a registry read has no degraded
    /// state) — an empty fleet is a valid, honest empty vector.
    [[nodiscard]] virtual std::vector<DeviceListRow> list_devices() const = 0;

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
