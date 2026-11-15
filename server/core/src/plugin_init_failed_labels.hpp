#pragma once

/// Bounds the `plugin` label of `yuzu_fleet_plugin_init_failed` to the server's own plugin
/// catalogue. The heartbeat tag `yuzu.plugins_failed` is agent-supplied, so an agent must never
/// choose which names become labels: a name the catalogue does not know is summed under
/// `kUnknownPluginLabel`, which is not a catalogue name and so cannot collide with a real one.

#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "command_capability.hpp"
#include "response_tier_filter.hpp" // ascii_lower: the one plugin-name fold

namespace yuzu::server {

/// The label that carries every well-formed plugin token the catalogue does not know.
inline constexpr const char* kUnknownPluginLabel = "unknown";

/// Published every sweep, zero included, so a flat 0 is a measurement: the number of AGENTS whose
/// latest `yuzu.plugins_failed` carried at least one token not given its own plugin label, by
/// reason. An agent is counted once per reason however many tokens it sent.
inline constexpr const char* kPluginInitFailedRejectedGauge = "yuzu_fleet_plugin_init_failed_rejected";
inline constexpr const char* kPluginInitFailedRejectedHelp =
    "Agents whose latest yuzu.plugins_failed heartbeat tag carried at least one token that did not "
    "become a plugin label, by reason: unknown_plugin (well formed, but not a plugin in the "
    "server's catalogue; summed under plugin=unknown), malformed (longer than 64 characters or "
    "containing a character outside letters, digits and underscore; an empty token between commas "
    "carries no name and is ignored, but still uses one of the 32 slots), over_cap (more than 32 "
    "comma-separated slots, the rest not read). Matching is exact and case sensitive (Echo is "
    "unknown, echo is a plugin). The unit is agents, one per reason however many tokens an agent "
    "sent; plugin=unknown on yuzu_fleet_plugin_init_failed instead sums the distinct tokens of each "
    "agent. Published every sweep, 0 included; >0 means an agent is sending names the server does "
    "not know, or forged ones";
inline constexpr const char* kRejectUnknownPlugin = "unknown_plugin";
inline constexpr const char* kRejectMalformed = "malformed";
inline constexpr const char* kRejectOverCap = "over_cap";

/// Every distinct plugin named by a row of the composed catalogue, lowercased and sorted. The same
/// `for_each_row` walk `derive_forensics_plugin_set` is built on, without its securable filter, so
/// a new catalogue fragment is reflected here with no second list to keep. Names starting with
/// "__" (`__guard__`, `__sync__`) are protocol names, not plugins, and are skipped so an agent
/// cannot claim them as a label.
[[nodiscard]] inline std::vector<std::string>
catalogue_plugin_names(const CommandCapabilityRegistry& registry) {
    std::set<std::string> names;
    registry.for_each_row([&](const CommandCapability& cap) {
        if (!cap.plugin.starts_with("__"))
            names.insert(ascii_lower(cap.plugin));
    });
    return {names.begin(), names.end()};
}

} // namespace yuzu::server
