#pragma once

/// @file discovered_devices_model.hpp
/// The one read model behind the discovered-devices twin (Network discovery):
/// `GET /api/v1/network/discovered-devices`, MCP `list_discovered_devices`
/// and the `GET /fragments/network/discovered` dashboard fragment all call the
/// SAME builders here, so the three transports cannot drift (ADR-1005,
/// api-twin-recipe.md Rule 1).
///
/// Everything here is pure and store-free: routes and tests inject a
/// `DiscoveredDevicesReadFn`; `discovered_devices_reader.hpp` adapts the real
/// store to it (core wiring only, outside the family's seam-closure set).
///
/// The row shape deliberately omits `managed` and `agent_id`: nothing sets
/// them today (`DiscoveryStore::mark_managed` has no caller), so printing them
/// would assert "unmanaged" for hosts that may well be enrolled agents.

#include "discovery_types.hpp"

#include <nlohmann/json.hpp>

#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

/// Hard cap on rows returned by one read; also the default when the caller
/// gives no `limit`. Larger inventories read `truncated: true`.
inline constexpr int kDiscoveredDevicesMaxLimit = 500;

/// Longest accepted `subnet` filter (a CIDR string is at most 43 bytes).
inline constexpr std::size_t kDiscoveredSubnetMaxLen = 64;

struct DiscoveredDevicesPage {
    std::vector<DiscoveredDevice> devices; ///< at most `limit` rows, newest last-seen first
    DiscoverySummary summary;              ///< counts over the filter, not just the page
    bool truncated{false};                 ///< more rows matched than `devices` holds
};

/// Reads one page. The error string is a short operator-safe label, never
/// driver text (the store already scrubs it).
using DiscoveredDevicesReadFn = std::function<std::expected<DiscoveredDevicesPage, std::string>(
    const std::string& subnet, int limit)>;

/// PURE: parse a `limit` query value. Empty -> the default (max); a
/// non-positive or non-numeric value -> nullopt (caller answers 400);
/// anything above the cap is clamped.
std::optional<int> parse_discovered_limit(std::string_view raw);

/// PURE: clamp an already-numeric limit (MCP). Non-positive -> nullopt.
std::optional<int> clamp_discovered_limit(long long v);

/// PURE: one row, the shared REST/MCP element shape.
nlohmann::json discovered_device_row_json(const DiscoveredDevice& d);

/// PURE: `{data:[row...], summary:{total,subnets}, truncated}`. REST adds its
/// own `meta`; MCP returns it as is.
nlohmann::json discovered_devices_json(const DiscoveredDevicesPage& page);

/// PURE: the dashboard fragment body. Every dynamic string is escaped: all
/// four text columns are agent- or caller-supplied free text.
std::string render_discovered_devices_fragment(const DiscoveredDevicesPage& page);

/// PURE: the fragment's fixed-text store-fault body (never an empty table).
std::string render_discovered_devices_unavailable();

} // namespace yuzu::server
