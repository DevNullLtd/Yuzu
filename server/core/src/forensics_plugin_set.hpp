#pragma once

/// #4990: derive the Forensics plugin set from the composed capability catalogue.
///
/// ONE pure helper, so the set is never a hand-kept list: every plugin with a row on the
/// `Forensics` securable (`kForensicsSecurable`, the same literal the dispatch gate keys on) is in
/// it. `server.cpp` calls this once at boot over the registry it dispatches with and REFUSES to
/// start when it returns `std::nullopt` (an empty derivation would otherwise exclude nothing and
/// silently disable the response read tier).

#include <optional>

#include "command_capability.hpp"
#include "dispatch_destructive_gate.hpp" // kForensicsSecurable
#include "response_tier_filter.hpp"

namespace yuzu::server {

/// `std::nullopt` iff no plugin in `registry` has a row on the Forensics securable.
[[nodiscard]] inline std::optional<ForensicsPluginSet>
derive_forensics_plugin_set(const CommandCapabilityRegistry& registry) {
    return ForensicsPluginSet::from_names(registry.plugins_on_securable(kForensicsSecurable));
}

} // namespace yuzu::server
