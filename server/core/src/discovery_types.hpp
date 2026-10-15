#pragma once

/// @file discovery_types.hpp
/// Plain value types for network-discovered hosts, split out of
/// `discovery_store.hpp` so the presentation-side read model
/// (`discovered_devices_model.hpp`) and the REST/MCP/fragment routes can name a
/// row without including a store header (ADR-0031 seam closure).

#include <cstdint>
#include <string>

namespace yuzu::server {

struct DiscoveredDevice {
    std::int64_t id{0};
    std::string ip_address;
    std::string mac_address;
    std::string hostname;
    bool managed{false};       ///< true if IP matches a known enrolled agent
    std::string agent_id;      ///< agent_id if managed
    std::string discovered_by; ///< agent_id of the agent that discovered this device
    std::int64_t discovered_at{0}; ///< epoch seconds, first-seen (preserved across upserts)
    std::int64_t last_seen{0};     ///< epoch seconds, most-recent-seen
    std::string subnet;            ///< the subnet that was scanned
};

/// Counts over the same rows a (possibly subnet-filtered) device list reads.
struct DiscoverySummary {
    std::int64_t total{0};   ///< rows matching the filter
    std::int64_t subnets{0}; ///< distinct non-empty `subnet` values among them
};

} // namespace yuzu::server
