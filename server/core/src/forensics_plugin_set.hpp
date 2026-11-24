#pragma once

/// #4990: derive the Forensics plugin set from the composed capability catalogue.
///
/// ONE pure helper, so the set is never a hand-kept list: every plugin with a row on the
/// `Forensics` securable (`kForensicsSecurable`, the same literal the dispatch gate keys on), and
/// every plugin with a row that asks for the Forensics read tier for what it stores
/// (`StoredRowTier::ForensicsRead`, whose dispatch stays on the row's own securable), is in it.
/// `server.cpp` calls this once at boot over the registry it dispatches with and REFUSES to
/// start when it returns `std::nullopt` (an empty derivation would otherwise exclude nothing and
/// silently disable the response read tier).

#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "command_capability.hpp"
#include "dispatch_destructive_gate.hpp" // kForensicsSecurable
#include "response_provenance.hpp"       // kUnverifiedProvenanceLabel
#include "response_tier_filter.hpp"

namespace yuzu::server {

/// Why the catalogue cannot be turned into a sound Forensics plugin set, or `std::nullopt` when it
/// can. The store records only the PLUGIN of a response row (the plugin the server recorded at
/// dispatch, response_provenance.hpp), never the action, so the tier is decided per plugin. Two shapes would make that
/// silently wrong, and both are refused instead of tolerated:
///   * a plugin with rows on the Forensics securable AND on another one: every row of that plugin
///     is withheld, including the ones the catalogue classifies as ordinary (the exclusion is
///     coarser than the catalogue says);
///   * a plugin with a `ForensicsRead` row on another securable AND an ordinary row on a
///     non-Forensics securable: the tier is per plugin, so the ordinary row's stored output would
///     be withheld too;
///   * a Forensics-tier plugin whose name contains `-`: dispatch mints `<plugin>-<hex>` ids and
///     readers such as the hardware poll's last-dash split still recover the plugin from the id,
///     so a dash in a Forensics-tier plugin name is ambiguous there (the recorded plugin itself
///     does not depend on the split). This covers a plugin that is Forensics-tier only through
///     `ForensicsRead`.
[[nodiscard]] inline std::optional<std::string>
forensics_catalogue_defect(const CommandCapabilityRegistry& registry) {
    std::set<std::string> on_forensics;
    std::set<std::string> elsewhere;
    std::set<std::string> flagged;
    std::set<std::string> ordinary_elsewhere;
    registry.for_each_row([&](const CommandCapability& cap) {
        const auto name = ascii_lower(cap.plugin);
        (cap.securable == kForensicsSecurable ? on_forensics : elsewhere).insert(name);
        if (cap.securable != kForensicsSecurable)
            (cap.stored_rows == StoredRowTier::ForensicsRead ? flagged : ordinary_elsewhere).insert(name);
    });
    for (const auto& plugin : on_forensics) {
        if (plugin.find('-') != std::string::npos)
            return "Forensics plugin '" + plugin + "' contains '-', which the hardware result poll's command-id split (<plugin>-<hex>) cannot represent";
        if (elsewhere.contains(plugin))
            return "plugin '" + plugin + "' has rows on the Forensics securable and on another securable: "
                   "the response tier is per plugin, so the other rows would be withheld too";
    }
    for (const auto& plugin : flagged) {
        if (plugin.find('-') != std::string::npos)
            return "plugin '" + plugin + "' stores its rows in the Forensics read tier and contains '-', which the hardware result poll's command-id split (<plugin>-<hex>) cannot represent";
        if (ordinary_elsewhere.contains(plugin))
            return "plugin '" + plugin + "' has a row that stores in the Forensics read tier and an ordinary row: "
                   "the response tier is per plugin, so the ordinary row would be withheld too";
    }
    return std::nullopt;
}

/// `std::nullopt` iff no plugin in `registry` is Forensics-tier (a row on the Forensics securable,
/// or a `StoredRowTier::ForensicsRead` row), or the catalogue is unsound for a per-plugin tier
/// (`forensics_catalogue_defect`).
///
/// The set also carries `kUnverifiedProvenanceLabel` (#4990, UP-7): the stored plugin of a response
/// whose command id has no server dispatch record (response_provenance.hpp). Adding it HERE, to the
/// one set every consumer already reads, is what makes unresolved provenance Forensics-tier in
/// every SQL filter and every sink (live output, analytics, notification, webhook, offload,
/// tracker) with no per-consumer code. The soundness check above is unaffected: it reads the
/// catalogue, and the sentinel is not a catalogue plugin (it contains `~`, which no plugin name
/// can, and it is added after the check, once, at boot like the rest of the set).
[[nodiscard]] inline std::optional<ForensicsPluginSet>
derive_forensics_plugin_set(const CommandCapabilityRegistry& registry) {
    if (forensics_catalogue_defect(registry))
        return std::nullopt;
    auto names = registry.plugins_on_securable(kForensicsSecurable);
    registry.for_each_row([&](const CommandCapability& cap) {
        if (cap.stored_rows == StoredRowTier::ForensicsRead)
            names.push_back(ascii_lower(cap.plugin));
    });
    if (names.empty())
        return std::nullopt; // the sentinel alone must never make an empty catalogue look sound
    names.emplace_back(kUnverifiedProvenanceLabel);
    return ForensicsPluginSet::from_names(std::move(names));
}

} // namespace yuzu::server
