#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_content_dist.hpp
/// One fragment of the command capability catalogue: `content_dist`'s five
/// actions (`agents/plugins/content_dist/src/content_dist_plugin.cpp`).
/// Classified by READING the implementation, not the name, per this
/// package's spec — every row below cites what it actually does. Every
/// `securable`/`operation` pair reuses an EXISTING `RbacStore`
/// `types[]`/`ops[]` entry (`rbac_store.cpp:291-327`+ops); none is minted
/// here. Ambiguous cases are classified conservatively (Mutating over
/// ReadOnly, Irreversible over Reversible) per the spec — the row comment
/// says so where it applies.
///
///   - `stage` — downloads an operator-supplied URL to the local staging
///     directory and hash-verifies it (content_dist_plugin.cpp:do_stage).
///     Classified conservatively as Destructive/Irreversible per the
///     spec's literal definition ("Destructive = irreversible or destroys
///     data"): `dest` is a fixed `staging_dir()/filename` path, and a
///     second `stage` for the same `filename` silently overwrites whatever
///     was staged there before via a truncating write — the prior file's
///     bytes are gone with no compensating action able to recover them
///     (unlike `cleanup`, which only removes a file that still exists;
///     nothing here restores one that was overwritten). Grouped under the
///     existing `SoftwareDeployment` securable (staging a payload for
///     later execution is squarely a deployment operation) as its `Write`
///     leg; risk_tier bumped to High (above the `Write` floor of Medium)
///     to match `cleanup`'s tier for the same securable, since both rows
///     now carry the same Destructive/Irreversible classification.
///   - `execute_staged` — runs a previously staged, hash-re-verified binary
///     via `safe_execute` (argv-only, no shell). Classified conservatively
///     as Destructive/Irreversible: arbitrary local code execution can have
///     unbounded, non-undoable side effects the plugin cannot itself
///     characterize. Existing `Execution` securable, `Execute` operation,
///     risk_tier bumped to High (above the `Execute` floor of Medium) to
///     reflect that this is unconstrained arbitrary-binary execution, not a
///     narrow built-in command.
///   - `list_staged` — enumerates the staging directory and reports
///     name/size/hash per file; collects and reports only. ReadOnly/None,
///     under `SoftwareDeployment`'s `Read` leg (pairs with `stage`/`cleanup`
///     under the same securable's lifecycle).
///   - `cleanup` — deletes staged files older than N hours (and their KV
///     hash record). Classified conservatively as Destructive/Irreversible
///     per the spec's literal definition ("Destructive = irreversible or
///     destroys data") — a removed staged file is gone, not just
///     deactivated. `SoftwareDeployment`'s `Delete` leg, risk_tier at the
///     `Delete` floor of High.
///   - `upload_file` — streams a local file to the server via the PR1.6
///     grant/session protocol (content_dist_plugin.cpp:do_upload,
///     upload_grant_parsers.hpp). Classified conservatively as
///     Destructive/Irreversible per the spec's literal definition: it
///     durably persists a new server-side artifact, and per
///     `command_capability.hpp`'s own definition of `Mutability`
///     ("undone by a subsequent dispatch of the same or a COMPENSATING
///     action") there is no such action reachable through this plugin or
///     the frozen protocol — ADR-3004 records that a committed blob has
///     `retention_class` recorded but explicitly "no sweep exists yet", so
///     nothing actually deletes it. Uses the EXISTING `FileRetrieval` securable
///     (`FileRetrieval:Write` is the exact precedent the legacy
///     `/api/v1/file-retrieval` handler used — rest_api_v1.cpp:7574 — for
///     "an agent sends the server a file") rather than `UploadGrant`, which
///     governs only the grant's own mint/revoke lifecycle
///     (authz_model.hpp's `kSeedCatalogue` comment is explicit that actual
///     file transfer stays under `FileRetrieval`). risk_tier bumped to High
///     (above the `Write` floor of Medium): this action reads and
///     transmits an arbitrary local file the dispatcher names, which can
///     exfiltrate sensitive on-device data — a risk `Write`'s ordinary
///     floor does not capture.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 5> kContentDistCapabilities{{
    {
        .plugin = "content_dist",
        .action = "stage",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "SoftwareDeployment",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "content_dist",
        .action = "execute_staged",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Execution",
        .operation = authz::Operation::Execute,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "content_dist",
        .action = "list_staged",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "SoftwareDeployment",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "content_dist",
        .action = "cleanup",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "SoftwareDeployment",
        .operation = authz::Operation::Delete,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "content_dist",
        .action = "upload_file",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
}};

// #1398: every row in kContentDistCapabilities must author .execute_gate — an
// omission would value-initialize to ExecuteGate::Unspecified (the zero
// enumerator), which is a genuine compile failure here rather than a
// silent runtime gap. See ExecuteGate's doc comment in
// command_capability.hpp.
static_assert(::yuzu::server::detail::all_gates_specified(kContentDistCapabilities),
              "every row in kContentDistCapabilities must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability> plugin_action_catalogue_content_dist() noexcept {
    return detail::kContentDistCapabilities;
}

} // namespace yuzu::server::capdecls
