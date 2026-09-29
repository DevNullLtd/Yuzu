#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_a.hpp
/// PR1.10 group A + PR1.9 data A (#2204): the command-capability-catalogue
/// fragment for five plugins — filesystem (16 actions), tar (13 of its 14
/// actions — see the NOTE below), registry (9), license_scan (2), vuln_scan
/// (5) — 45 rows total. Every `dispatch_class`/`mutability` pair and every
/// `securable`/`operation` choice was made by reading the implementation,
/// never the action name; ambiguous calls are resolved conservatively
/// (Mutating over ReadOnly, Irreversible over Reversible) and say so inline.
/// `securable` reuses only names present in `rbac_store.cpp`'s
/// `seed_defaults()` `types[]`; `operation` reuses only `authz::Operation`'s
/// seven values; every `risk_tier` is at or above `authz::min_risk_tier_for`
/// its row's operation. `system_reserved` is false on every row — none of
/// these forty-five dispatches is one the server issues to itself.
///
/// NOTE — `tar.fleet_snapshot` is DELIBERATELY ABSENT from this fragment.
/// `capability_decls/core_dispatch_capabilities.hpp` (a different package's
/// file, already landed) declares `tar.fleet_snapshot` itself
/// (`system_reserved = true`, the periodic fleet-wide snapshot pull
/// `server.cpp:2427` issues to itself). `CommandCapabilityRegistry::classify`
/// keys purely on the case-insensitive `(plugin, action)` pair — it has no
/// notion of "caller context" — so a second `tar.fleet_snapshot` row here
/// would make every future classification of that pair `Ambiguous`
/// (`command_capability.hpp`'s own contract: "two fragments declaring the
/// same plugin.action is Ambiguous, never first-wins"), exactly the
/// collision the boundaries this package was given warn against. Declaring
/// it again here to satisfy "one row per action" would silently break that
/// invariant, so it is left to the fragment that already owns it. Flagged to
/// the Architect rather than resolved unilaterally either way.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 45> kPluginActionCatalogueA{{
    // ── filesystem (agents/plugins/filesystem/src/filesystem_plugin.cpp) ──
    // All 16 actions classified under the `FileRetrieval` securable — the
    // plugin's own doc comment names it a file-operations surface requiring
    // admin role. Reads are ReadOnly/None/Read/Low. create_temp(_dir) create
    // a new, trivially-undoable resource — Mutating/Reversible/Write/Medium.
    // replace/write_content can overwrite existing content the caller may
    // have no other copy of — conservatively Mutating/Irreversible (not
    // Reversible) even though the *usual* case is a deliberate, caller-
    // supplied replacement. append only adds bytes, never destroys existing
    // content — Mutating/Reversible. delete_lines is named-explicit
    // deletion of existing file content with no undo — Destructive/
    // Irreversible/Delete/High, the same treatment as tar.purge_source.
    {
        .plugin = "filesystem",
        .action = "exists",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "filesystem",
        .action = "list_dir",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "filesystem",
        .action = "file_hash",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "filesystem",
        .action = "create_temp",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "filesystem",
        .action = "create_temp_dir",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "filesystem",
        .action = "read",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "filesystem",
        .action = "get_acl",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "filesystem",
        .action = "get_signature",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "filesystem",
        .action = "find_by_hash",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "filesystem",
        .action = "search_dir",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "filesystem",
        .action = "get_version_info",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "filesystem",
        .action = "search",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        // Conservative: overwrites matched content in place; the caller's
        // replacement text is not guaranteed to be recoverable to the prior
        // state without an external copy — Irreversible, not Reversible.
        .plugin = "filesystem",
        .action = "replace",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Irreversible,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        // Conservative: overwrite=true replaces the file's entire prior
        // content with no automatic backup — Irreversible, not Reversible.
        .plugin = "filesystem",
        .action = "write_content",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Irreversible,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        // Only adds bytes to the end of the file; no existing content is
        // ever destroyed, so — unlike replace/write_content — Reversible.
        .plugin = "filesystem",
        .action = "append",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        // Named-explicit deletion of existing file content with no undo —
        // Destructive/Irreversible/Delete, the same treatment given to
        // tar.purge_source below.
        .plugin = "filesystem",
        .action = "delete_lines",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Delete,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },

    // ── tar (agents/plugins/tar/src/tar_plugin.cpp) — 13 of 14 actions; ──
    // ── fleet_snapshot is excluded, see the file-level NOTE above. ───────
    // Collector/report actions (status/query/snapshot/export/collect_*/
    // rollup/sql/compatibility) only observe the host and record/report —
    // ReadOnly/None/Read under `Infrastructure`, per DispatchClass's own
    // "collects and reports only" definition. query/export/sql can surface
    // opt-in PII sources (mapdrive usernames, dns-visited-domains, arp) via
    // a type filter or raw SQL — Medium, not the Read floor of Low.
    // configure changes plugin behaviour (retention/intervals/redaction) —
    // Mutating/Reversible/Write. rollup performs routine retention
    // deletion of expired event rows as an unconditional part of its
    // behaviour (`run_retention`, after `run_aggregation`) — genuinely
    // destroys data, so Destructive/Irreversible/Delete, matching
    // purge_source. purge_source's classification is PRESERVED verbatim
    // from server.cpp:9038-9042's `kDestructiveActionSecurable` map.
    {
        .plugin = "tar",
        .action = "status",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        // Medium, not the Read floor: a type filter can return opt-in PII
        // sources (arp/dns/mapdrive) alongside the default event union.
        .plugin = "tar",
        .action = "query",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "tar",
        .action = "snapshot",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        // Medium, not the Read floor: same PII-surfacing type filter as
        // query, wrapped as a JSON export.
        .plugin = "tar",
        .action = "export",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "tar",
        .action = "configure",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "tar",
        .action = "collect_fast",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "tar",
        .action = "collect_slow",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "tar",
        .action = "collect_perf",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "tar",
        .action = "collect_software",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        // Conservative: unconditionally runs run_retention() after
        // run_aggregation(), permanently deleting event rows past the
        // configured retention window — genuinely destroys data, so
        // Destructive/Irreversible/Delete like purge_source, not a plain
        // Mutating/Write for the aggregation half alone.
        .plugin = "tar",
        .action = "rollup",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Delete,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        // Medium, not the Read floor: validate_and_translate_sql is
        // SELECT-only (rejects INSERT/UPDATE/DELETE/DROP/etc.) but an
        // operator-authored SELECT can reach the same opt-in PII tables
        // query/export gate behind a type filter.
        .plugin = "tar",
        .action = "sql",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "tar",
        .action = "compatibility",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        // PRESERVED verbatim from server.cpp:9038-9042's
        // kDestructiveActionSecurable map (the /api/command generic-dispatch
        // per-action elevation for this one action).
        .plugin = "tar",
        .action = "purge_source",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Delete,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── registry (agents/plugins/registry/src/registry_plugin.cpp) ───────
    // Windows-only; every action classified under `Infrastructure` (no
    // dedicated registry securable exists). Reads are ReadOnly/None/Read/
    // Low. set_value can overwrite an existing value with no automatic
    // backup — conservatively Irreversible. delete_value/delete_key are
    // named-explicit deletion — Destructive/Irreversible/Delete;
    // delete_key additionally destroys an entire subtree (every value AND
    // subkey beneath it) in one call, a strictly larger blast radius than
    // delete_value, so it is declared ABOVE the Delete floor at Critical.
    // get_user_value reads a per-user hive (PII, privilege-elevated via
    // SeBackup/SeRestore) — Medium, not the Read floor.
    {
        .plugin = "registry",
        .action = "get_value",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "registry",
        .action = "set_value",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "registry",
        .action = "delete_value",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Delete,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        // Above the Delete floor: destroys an entire subtree (every value
        // and subkey beneath it) in one call — larger blast radius than
        // delete_value.
        .plugin = "registry",
        .action = "delete_key",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Delete,
        .risk_tier = authz::RiskTier::Critical,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "registry",
        .action = "key_exists",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "registry",
        .action = "enumerate_keys",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "registry",
        .action = "enumerate_values",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        // Medium, not the Read floor: reads a per-user hive (PII), gated on
        // SeBackup/SeRestore privilege internally.
        .plugin = "registry",
        .action = "get_user_value",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "registry",
        .action = "list_profiles",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── license_scan (agents/plugins/license_scan/src/license_scan_plugin.cpp) ──
    // Both actions only detect and report licence state; `SoftwareLicensing`
    // is the securable seeded specifically for this purpose (rbac_store.cpp:
    // "gates the /api/v1/sle/* detected-licence reads" — explicitly Read).
    {
        .plugin = "license_scan",
        .action = "list",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "SoftwareLicensing",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "license_scan",
        .action = "surfaces",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "SoftwareLicensing",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── vuln_scan (agents/plugins/vuln_scan/src/vuln_scan_plugin.cpp) ────
    // scan/cve_scan/config_scan/summary only detect and report vulnerability/
    // configuration findings — `Security` securable, Read. inventory returns
    // the same raw software listing tar.query's software source and the
    // `/inventory` REST route serve — `Inventory` securable, matching
    // rbac_store.cpp's own note that "the /inventory software catalog
    // remains under Inventory:Read".
    {
        .plugin = "vuln_scan",
        .action = "scan",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "vuln_scan",
        .action = "cve_scan",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "vuln_scan",
        .action = "config_scan",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "vuln_scan",
        .action = "summary",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "vuln_scan",
        .action = "inventory",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCatalogueA must author .execute_gate — an
// omission would value-initialize to ExecuteGate::Unspecified (the zero
// enumerator), which is a genuine compile failure here rather than a
// silent runtime gap. See ExecuteGate's doc comment in
// command_capability.hpp.
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueA),
              "every row in kPluginActionCatalogueA must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage, deliberately not a
/// `CommandCapabilityRegistry` instance itself: this header only DECLARES
/// rows, it never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability> plugin_action_catalogue_a() noexcept {
    return detail::kPluginActionCatalogueA;
}

} // namespace yuzu::server::capdecls
