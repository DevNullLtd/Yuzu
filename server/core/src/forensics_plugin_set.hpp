#pragma once

/// #4990: derive the Forensics plugin set from the composed capability catalogue.
///
/// ONE pure helper, so the set is never a hand-kept list: every plugin with a row on the
/// `Forensics` securable (`kForensicsSecurable`, the same literal the dispatch gate keys on) is in
/// it. `server.cpp` calls this once at boot over the registry it dispatches with and REFUSES to
/// start when it returns `std::nullopt` (an empty derivation would otherwise exclude nothing and
/// silently disable the response read tier).

#include <optional>
#include <set>
#include <string>

#include "command_capability.hpp"
#include "dispatch_destructive_gate.hpp" // kForensicsSecurable
#include "response_tier_filter.hpp"

namespace yuzu::server {

/// Why the catalogue cannot be turned into a sound Forensics plugin set, or `std::nullopt` when it
/// can. The store records only the PLUGIN of a response row (the text before the first `-` of the
/// command id), never the action, so the tier is decided per plugin. Two shapes would make that
/// silently wrong, and both are refused instead of tolerated:
///   * a plugin with rows on the Forensics securable AND on another one: every row of that plugin
///     is withheld, including the ones the catalogue classifies as ordinary (the exclusion is
///     coarser than the catalogue says);
///   * a Forensics plugin whose name contains `-`: the stored plugin would be the part before it,
///     so the real plugin's rows would never match the set.
[[nodiscard]] inline std::optional<std::string>
forensics_catalogue_defect(const CommandCapabilityRegistry& registry) {
    std::set<std::string> on_forensics;
    std::set<std::string> elsewhere;
    registry.for_each_row([&](const CommandCapability& cap) {
        (cap.securable == kForensicsSecurable ? on_forensics : elsewhere).insert(ascii_lower(cap.plugin));
    });
    for (const auto& plugin : on_forensics) {
        if (plugin.find('-') != std::string::npos)
            return "Forensics plugin '" + plugin + "' contains '-', which the stored plugin split cannot represent";
        if (elsewhere.contains(plugin))
            return "plugin '" + plugin + "' has rows on the Forensics securable and on another securable: "
                   "the response tier is per plugin, so the other rows would be withheld too";
    }
    return std::nullopt;
}

/// `std::nullopt` iff no plugin in `registry` has a row on the Forensics securable, or the
/// catalogue is unsound for a per-plugin tier (`forensics_catalogue_defect`).
[[nodiscard]] inline std::optional<ForensicsPluginSet>
derive_forensics_plugin_set(const CommandCapabilityRegistry& registry) {
    if (forensics_catalogue_defect(registry))
        return std::nullopt;
    return ForensicsPluginSet::from_names(registry.plugins_on_securable(kForensicsSecurable));
}

} // namespace yuzu::server
