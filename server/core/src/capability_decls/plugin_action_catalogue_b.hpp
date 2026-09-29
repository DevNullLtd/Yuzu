#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_b.hpp
/// PR1.9 data B: the command-capability classification for the 14
/// inventory/system plugins group B declares ABI4 descriptors for
/// (agents/plugins/hardware, users, status, os_info, storage,
/// installed_apps, processes, procfetch, disk_space, device_identity,
/// agent_logging, diagnostics, example, chargen) — 55 rows, one per action
/// in each plugin's `actions()` table. Every other `capability_decls/*.hpp`
/// fragment belongs to a different package and is composed alongside this
/// one only at the `CommandCapabilityRegistry` construction site — never
/// merged into this array (a duplicate `plugin.action` row across fragments
/// trips the registry's `Ambiguous` path).
///
/// This group is overwhelmingly read-only inventory collection: every row
/// below is `DispatchClass::ReadOnly` / `Mutability::None` EXCEPT `storage`'s
/// `set`/`delete`/`clear` (the plugin's own local KV store is genuinely
/// mutated) and `chargen`'s `chargen_start`/`chargen_stop` (an on-agent
/// background generation loop is started/stopped) — see the per-row comments
/// on those for the reasoning. `device_identity`, `agent_logging` and
/// `diagnostics` were expected by the originating spec to contain
/// state-changing actions; a full read of all three (device_name/domain/ou;
/// get_log/get_key_files; log_level/certificates/connection_info) found
/// every one of them to be a pure report — no host, agent-config, or
/// filesystem write anywhere in those three plugins — so all eight of their
/// rows are classified `ReadOnly`/`None` here, honestly, against the code as
/// found rather than the spec's expectation.
///
/// `securable` is drawn only from `rbac_store.cpp`'s seeded `types[]`:
/// `Inventory` for plain fact-collection (the majority), `UserManagement`
/// for the `users` plugin's account/session data (a dedicated seeded type
/// exists and fits exactly), `Infrastructure` for `storage`'s agent-local KV
/// read/write/delete (mirrors that securable's existing use for
/// agent/device-management reads AND writes elsewhere in `server/core`),
/// `Security` for the two actions that specifically enumerate TLS
/// certificate/key file paths (`diagnostics.certificates`,
/// `agent_logging.get_key_files` — mirrors `Security:Read`'s existing use
/// for CA/KEK inventory in `ca_routes.cpp`/`kek_routes.cpp`), `PluginSecret`
/// for the three actions whose output includes the live agent session
/// credential (`status.switch`, `diagnostics.connection_info`,
/// `agent_logging.get_log` — see the per-row comments for the exact
/// implementing lines), and `Execution` for `chargen`'s start/stop (mirrors
/// that securable's existing `Execution:Execute` use for command dispatch).
/// `system_reserved` is false on every row — none of these is a
/// server-initiated dispatch.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 55> kPluginActionCatalogueB{{
    // ── hardware (agents/plugins/hardware/src/hardware_plugin.cpp) ────────
    // 8 actions, all pure fact-collection (manufacturer/model/BIOS/CPU/
    // memory/disks/drivers/serial+UUID) — no host-state write anywhere.
    {
        .plugin = "hardware",
        .action = "manufacturer",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "hardware",
        .action = "model",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "hardware",
        .action = "bios",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "hardware",
        .action = "processors",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "hardware",
        .action = "memory",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "hardware",
        .action = "disks",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "hardware",
        .action = "drivers",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "hardware",
        .action = "system",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── users (agents/plugins/users/src/users_plugin.cpp) ─────────────────
    // 7 actions, all account/session reporting — no account, group, or
    // session is ever created/modified/removed by this plugin.
    {
        .plugin = "users",
        .action = "logged_on",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "UserManagement",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "users",
        .action = "sessions",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "UserManagement",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "users",
        .action = "local_users",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "UserManagement",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "users",
        .action = "local_admins",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "UserManagement",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "users",
        .action = "group_members",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "UserManagement",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "users",
        .action = "primary_user",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "UserManagement",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "users",
        .action = "session_history",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "UserManagement",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── status (agents/plugins/status/src/status_plugin.cpp) ──────────────
    // 8 actions, all agent self-report (version/platform/health/plugin and
    // module lists/connection/switch/config) — read-only throughout.
    {
        .plugin = "status",
        .action = "version",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "status",
        .action = "info",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "status",
        .action = "health",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "status",
        .action = "plugins",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "status",
        .action = "modules",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "status",
        .action = "connection",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    // `switch` emits the live agent session credential alongside connection
    // state (status_plugin.cpp:381, `session_id|{}` via `cfg("agent.session_id")`)
    // — Heartbeat/ReportInventory resolve identity from that same session_id
    // (agent_service_impl.cpp:609-627, :681-696), so this is classified under
    // `PluginSecret` rather than plain `Inventory`, not disclosed at Low risk.
    {
        .plugin = "status",
        .action = "switch",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "PluginSecret",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "status",
        .action = "config",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── os_info (agents/plugins/os_info/src/os_info_plugin.cpp) ───────────
    // 5 actions, all pure OS-fact reads (name/version/build/arch/uptime).
    {
        .plugin = "os_info",
        .action = "os_name",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "os_info",
        .action = "os_version",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "os_info",
        .action = "os_build",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "os_info",
        .action = "os_arch",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "os_info",
        .action = "uptime",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── storage (agents/plugins/storage/src/storage_plugin.cpp) ───────────
    // 5 actions over the agent's own local KV store. The only genuinely
    // mutating rows in this whole catalogue fragment: `set` writes a key
    // (Reversible — a later `set`/`delete` supersedes it); `delete` removes
    // one key whose prior value the caller cannot recover through this
    // plugin, so classified Irreversible conservatively; `clear` wipes
    // every key for the plugin in one call — Destructive/Irreversible, the
    // bulk form of `delete`. `get`/`list` stay ReadOnly. Implementing
    // effects: `do_set` calls `storage_set` at storage_plugin.cpp:140,
    // `do_delete` calls `storage_delete` at :172, `do_clear` calls
    // `storage_list`/`storage_delete` at :191-194.
    {
        .plugin = "storage",
        .action = "set",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "storage",
        .action = "get",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "storage",
        .action = "delete",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Delete,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "storage",
        .action = "list",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "storage",
        .action = "clear",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Delete,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },

    // ── installed_apps (agents/plugins/installed_apps/src/installed_apps_plugin.cpp) ──
    // 4 actions, all software-inventory reads (list/query/per-user/blob-v2
    // sync). SoftwareLicensing's own seed comment (rbac_store.cpp) confirms
    // the /inventory software catalog stays under Inventory:Read.
    {
        .plugin = "installed_apps",
        .action = "list",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "installed_apps",
        .action = "query",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "installed_apps",
        .action = "list_per_user",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "installed_apps",
        .action = "list_inventory",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── processes (agents/plugins/processes/src/processes_plugin.cpp) ─────
    // 4 actions, all process-enumeration reads (list/hashed/tree/query) —
    // never sends a signal or otherwise touches a process.
    {
        .plugin = "processes",
        .action = "list",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "processes",
        .action = "list_hashed",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "processes",
        .action = "list_tree",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "processes",
        .action = "query",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── procfetch (agents/plugins/procfetch/src/procfetch_plugin.cpp) ─────
    // 1 action: process enumeration + executable SHA-1 — read-only.
    {
        .plugin = "procfetch",
        .action = "procfetch_fetch",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── disk_space (agents/plugins/disk_space/src/disk_space_plugin.cpp) ──
    // 1 action: free/total/percent-used for one volume — read-only.
    {
        .plugin = "disk_space",
        .action = "free",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── device_identity (agents/plugins/device_identity/src/device_identity_plugin.cpp) ──
    // 3 actions (device_name/domain/ou). Read in full: NONE of the three
    // writes anything — every branch on every OS only ever calls
    // ctx.write_output(). Classified ReadOnly/None against the code as
    // found, though the originating spec expected this plugin to contain a
    // state-changing action.
    {
        .plugin = "device_identity",
        .action = "device_name",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "device_identity",
        .action = "domain",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "device_identity",
        .action = "ou",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── agent_logging (agents/plugins/agent_logging/src/agent_logging_plugin.cpp) ──
    // 2 actions. Read in full: both are pure reads (log tail, key-file
    // metadata) — no write anywhere, though the originating spec expected a
    // state-changing action here too. `get_key_files` enumerates the TLS
    // cert/key file PATHS (never contents) alongside the executable/log/
    // config paths, so it is classified under `Security` rather than plain
    // `Inventory`, mirroring `Security:Read`'s existing use for CA/KEK
    // inventory (ca_routes.cpp/kek_routes.cpp).
    //
    // `get_log` tails the agent's own log file (do_get_log,
    // agent_logging_plugin.cpp:271-311, tail_file() call at :304), which is
    // the same file agent.cpp:1754 writes the "Registered with server
    // (session={}, ...)" line to — so its output can carry the live agent
    // session credential. Classified under `PluginSecret` rather than plain
    // `Inventory` for the same reason as `status.switch` above, not
    // disclosed at Low risk.
    {
        .plugin = "agent_logging",
        .action = "get_log",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "PluginSecret",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "agent_logging",
        .action = "get_key_files",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── diagnostics (agents/plugins/diagnostics/src/diagnostics_plugin.cpp) ──
    // 3 actions. Read in full: all three are pure config/filesystem-exists
    // reads — no write anywhere, though the originating spec expected a
    // state-changing action here too. `certificates` reports TLS cert/key
    // file paths + existence (never contents), classified under `Security`
    // for the same reason as agent_logging's `get_key_files` above.
    {
        .plugin = "diagnostics",
        .action = "log_level",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "diagnostics",
        .action = "certificates",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    // `connection_info` emits the live agent session credential alongside
    // connection state (diagnostics_plugin.cpp:171, `session_id|{}` via
    // `pctx.get_config("agent.session_id")`) — classified under `PluginSecret`
    // for the same reason as `status.switch` above, not disclosed at Low risk.
    {
        .plugin = "diagnostics",
        .action = "connection_info",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "PluginSecret",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── example (agents/plugins/example/src/example_plugin.cpp) ───────────
    // 2 actions: "ping"/"echo" — trivial in-process responders, no host
    // interaction at all.
    {
        .plugin = "example",
        .action = "ping",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "example",
        .action = "echo",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },

    // ── chargen (agents/plugins/chargen/src/chargen_plugin.cpp) ───────────
    // 2 actions: "chargen_start"/"chargen_stop" start/stop an on-agent RFC
    // 864 generation loop. Classified conservatively as Mutating/Reversible
    // rather than ReadOnly: this genuinely starts/stops a running
    // background operation on the agent (analogous to `Execution:Execute`
    // command dispatch), even though it never touches host filesystem/
    // registry/config state — a later `chargen_stop`/`chargen_start` fully
    // reverses either action, so Reversible rather than Irreversible.
    // Implementing effects: `start_chargen` calls `stop_all()` then starts
    // the generation loop at chargen_plugin.cpp:119 and :134; `stop_all`
    // (chargen_plugin.cpp:156-162) signals the loop to end.
    {
        .plugin = "chargen",
        .action = "chargen_start",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Execution",
        .operation = authz::Operation::Execute,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "chargen",
        .action = "chargen_stop",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Execution",
        .operation = authz::Operation::Execute,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCatalogueB must author .execute_gate — an
// omission would value-initialize to ExecuteGate::Unspecified (the zero
// enumerator), which is a genuine compile failure here rather than a
// silent runtime gap. See ExecuteGate's doc comment in
// command_capability.hpp.
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueB),
              "every row in kPluginActionCatalogueB must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage, deliberately not a
/// `CommandCapabilityRegistry` instance itself: this header only DECLARES
/// rows, it never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability> plugin_action_catalogue_b() noexcept {
    return detail::kPluginActionCatalogueB;
}

} // namespace yuzu::server::capdecls
