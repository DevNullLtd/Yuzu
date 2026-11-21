#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_file_search.hpp
/// One fragment of the command capability catalogue: `file_search`'s single action
/// (`agents/plugins/file_search/src/file_search_plugin.cpp`). Classified by reading the
/// implementation.
///
/// `search` is ReadOnly/None -- the plugin never writes, signals or changes a file. It walks the
/// local disks of one device from a caller-named root, compares leaf names against one pattern,
/// and reports for each match the name, type, size, times and the extents of the file. A matched
/// file is opened and never read, and no hash of anything is taken. One call is one slice of the
/// search; the caller loops on the cursor.
///
/// ONE row covers the action at the top tier: data above this contract (file contents, hashes)
/// is a NEW action with its own row here, never a new mode of this one.
///
/// DISPATCH securable: `FileRetrieval`, the securable the filesystem plugin's file operations
/// already use (`rbac_store.cpp`'s seeded `types[]` entry; the string below MUST equal that seed
/// literal byte-for-byte, validated by `test_capability_catalogue`'s seeded-securable-types
/// check). It is deliberately NOT `Forensics`: a `Forensics` row is single-target
/// (`dispatch_destructive_gate.hpp`'s `requires_explicit_targets` keys on the row's securable),
/// and a search must stay launchable at a fleet or a group. `AdminOrApproval` plus
/// `authz::RiskTier::High`: a listing of file names under every user's directories is
/// reconnaissance material. Ships default-off behind the plugin-config kill switch.
///
/// STORED-ROW read tier: `StoredRowTier::ForensicsRead`. What the search stored is withheld from
/// every reader that does not hold a global `Forensics:Read`, exactly like the stored rows of a
/// plugin on the `Forensics` securable: the same set, the same SQL exclusion, the same live-output
/// and failure-text rules, and the same `response.forensics.read` audit row. The default roles
/// that read them are Administrator and ForensicsAnalyst; with RBAC off, Administrator only. The
/// consequence is deliberate: a non-administrator who launches a search under an approval cannot
/// read its stored results unless they also hold `Forensics:Read`. There is no second read tier
/// and no second permission check for this plugin.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueFileSearch{{
    {
        .plugin = "file_search",
        .action = "search",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
        .stored_rows = StoredRowTier::ForensicsRead,
    },
}};

// Every row must author .execute_gate -- an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), a compile failure here rather than a
// silent runtime gap. See ExecuteGate's doc comment in command_capability.hpp.
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueFileSearch),
              "every row in kPluginActionCatalogueFileSearch must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above -- one of the several sources a
/// `CommandCapabilityRegistry` is composed from. Inline function over file-scope `constexpr`
/// storage: this header only DECLARES rows, it never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_file_search() noexcept {
    return detail::kPluginActionCatalogueFileSearch;
}

} // namespace yuzu::server::capdecls
