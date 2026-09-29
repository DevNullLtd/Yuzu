#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_c.hpp
/// PR1.9 data C: the command-capability catalogue fragment for the 13
/// network/security agent plugins (PR1.10 group C) — network_config,
/// netprobe, netstat, network_diag, network_actions, discovery,
/// wifi, wol, http_client, certificates, firewall, quarantine, rdp_control.
/// (sockwho retired into netstat's `attribution` action, #3403 -- was its
/// own plugin group member here, now a second netstat row below.)
/// One row per action, grouped by plugin below (each group cites the
/// `.cpp` its `actions()` table came from). Every other plugin's rows live
/// in a separate fragment header owned by a different package — see
/// `command_capability.hpp`'s file comment — and none of them are
/// aggregated here.
///
/// `securable`/`operation` are drawn only from `rbac_store.cpp`'s seeded
/// `types[]`/`ops[]` (`Infrastructure` for ordinary device/network reads
/// and writes, mirroring `device_routes.cpp`/`discovery_routes.cpp`'s own
/// `Infrastructure:Read`/`Write` gates; `Security` for the
/// certificate/firewall/quarantine/RDP surface, mirroring `ca_routes.cpp`'s
/// `Security:Read`/`Write`/`Delete` gates and — for quarantine specifically
/// — `docs/authz-model.md`'s documented `Security:Execute` gate on the
/// live `quarantine_device` REST/MCP route). `risk_tier` is set at or above
/// `authz::min_risk_tier_for(operation)` on every row; `system_reserved` is
/// false throughout (every row here is a caller-attributable dispatch, not
/// a server-initiated one).
///
/// This is the highest-risk group in the run: quarantine, firewall-adjacent
/// certificate deletion, and rdp_control change host or network-reachable
/// state, several with no available undo. Each such row's comment states
/// the reversibility call and its evidence; ambiguous cases are classified
/// conservatively (Mutating over ReadOnly, Irreversible over Reversible)
/// per the owning package's spec.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 34> kPluginActionCatalogueC{{
    // ── network_config (agents/plugins/network_config/src/network_config_plugin.cpp) ──
    // All six actions only report existing adapter/DNS/proxy configuration —
    // no local or remote state is ever changed.
    {
        .plugin = "network_config",
        .action = "adapters",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "network_config",
        .action = "ip_addresses",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "network_config",
        .action = "dns_servers",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "network_config",
        .action = "proxy",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "network_config",
        .action = "dns_cache",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "network_config",
        .action = "arp",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },

    // ── netprobe (agents/plugins/netprobe/src/netprobe_plugin.cpp) ──
    // Active RTT/loss/DNS-timing probes to operator-chosen targets — read
    // measurements only, nothing is changed anywhere.
    {
        .plugin = "netprobe",
        .action = "icmp",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "netprobe",
        .action = "tcp",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "netprobe",
        .action = "dns",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },

    // ── netstat (agents/plugins/netstat/src/netstat_plugin.cpp) ──
    // `attribution` folds the retired sockwho plugin's socket-to-process
    // mapping into netstat (#3403) -- same read-only/Infrastructure shape
    // sockwho's own row carried.
    {
        .plugin = "netstat",
        .action = "netstat_list",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "netstat",
        .action = "attribution",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },

    // ── network_diag (agents/plugins/network_diag/src/network_diag_plugin.cpp) ──
    {
        .plugin = "network_diag",
        .action = "listening",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "network_diag",
        .action = "connections",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },

    // ── network_actions (agents/plugins/network_actions/src/network_actions_plugin.cpp) ──
    {
        .plugin = "network_actions",
        .action = "flush_dns",
        // Clears the local resolver cache; the cache simply repopulates on
        // the next lookup, so this is Mutating/Reversible, not Destructive.
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "network_actions",
        .action = "ping",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },

    // ── discovery (agents/plugins/discovery/src/discovery_plugin.cpp) ──
    // ARP-table read + ping sweep of a subnet — generates outbound traffic
    // but changes no state on this device or any target.
    {
        .plugin = "discovery",
        .action = "scan_subnet",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },

    // ── wifi (agents/plugins/wifi/src/wifi_plugin.cpp) ──
    {
        .plugin = "wifi",
        .action = "list_networks",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "wifi",
        .action = "connected",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },

    // ── wol (agents/plugins/wol/src/wol_plugin.cpp) ──
    {
        .plugin = "wol",
        .action = "wake",
        // Sends a Wake-on-LAN magic packet: this device's own state is
        // untouched, but the action's whole purpose is to power on a
        // remote target. This plugin has no counterpart "sleep" action, so
        // there is no undo to cite — classified Irreversible per the
        // conservative default.
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Irreversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "wol",
        .action = "check",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },

    // ── http_client (agents/plugins/http_client/src/http_client_plugin.cpp) ──
    {
        .plugin = "http_client",
        .action = "download",
        // Writes the fetched body to an operator-chosen local path,
        // truncating (download_url's std::ofstream open) whatever file was
        // already there with no prior-content backup — an irreversible
        // overwrite of arbitrary existing content, not a routine infra
        // write, so this is Destructive/Irreversible under FileRetrieval
        // (the RBAC securable for file upload/download operations) at High
        // risk rather than Infrastructure/Medium.
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::High,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "http_client",
        .action = "get",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "http_client",
        .action = "head",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },

    // ── certificates (agents/plugins/certificates/src/certificates_plugin.cpp) ──
    {
        .plugin = "certificates",
        .action = "list",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "certificates",
        .action = "details",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "certificates",
        .action = "delete",
        // Removes a certificate from a system/user store or keychain; this
        // plugin has no "restore" action and does not retain the deleted
        // cert's bytes anywhere, so a deletion cannot be undone through it.
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Security",
        .operation = authz::Operation::Delete,
        .risk_tier = authz::RiskTier::High,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },

    // ── firewall (agents/plugins/firewall/src/firewall_plugin.cpp) ──
    // Status/rule-listing only — this plugin exposes NO rule-mutation
    // action today (`actions()` is exactly {"state", "rules"}), despite the
    // "firewall" name; classified by what the code does, not the name.
    {
        .plugin = "firewall",
        .action = "state",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "firewall",
        .action = "rules",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },

    // ── quarantine (agents/plugins/quarantine/src/quarantine_plugin.cpp) ──
    {
        .plugin = "quarantine",
        .action = "quarantine",
        // Blocks essentially all network traffic except the whitelist —
        // the single most disruptive action in this catalogue fragment.
        // `unquarantine` restores reachability and is exercised end-to-end
        // by scripts/test/instructions_quarantine_survivor.py, which
        // asserts the box is NOT left locked out — but on macOS,
        // macos_load_ruleset (quarantine_plugin.cpp) replaces the whole
        // active pf ruleset via `pfctl -f`, and macos_unquarantine
        // explicitly restores only the OS-default /etc/pf.conf (or
        // disables pf) "without trying to remember and replay the prior
        // state ourselves" — any runtime pf rules the endpoint had before
        // quarantine are permanently lost. A connectivity-restoration test
        // does not prove that state is restored, so this row is classified
        // Irreversible across all platforms rather than claiming a genuine
        // tested undo that only Linux (Yuzu-owned iptables chain) and
        // Windows actually have.
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Security",
        .operation = authz::Operation::Execute,
        .risk_tier = authz::RiskTier::Critical,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "quarantine",
        .action = "unquarantine",
        // Restores reachability by re-invoking the platform release path;
        // on Linux/Windows this is a clean removal of the Yuzu-owned
        // isolation rules, but see `quarantine`'s row above for why the
        // macOS release path is not a state-preserving undo of whatever
        // was quarantined.
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Security",
        .operation = authz::Operation::Execute,
        .risk_tier = authz::RiskTier::High,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "quarantine",
        .action = "status",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "quarantine",
        .action = "whitelist",
        // Adds/removes IPs from an active quarantine's allow-list; add and
        // remove are each other's inverse, so this is Reversible.
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Security",
        .operation = authz::Operation::Execute,
        .risk_tier = authz::RiskTier::High,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },

    // ── rdp_control (agents/plugins/rdp_control/src/rdp_control_plugin.cpp) ──
    {
        .plugin = "rdp_control",
        .action = "set_state",
        // Flips the RDP registry/firewall/service gates via a shared
        // mutex-serialized code path, with do_status providing an
        // independent readback — but rdp_control_plugin.cpp's own comment
        // says enable "ensure[s] TermService is RUNNING" while on disable
        // "the service is deliberately left alone", so disable does not
        // restore the pre-enable service state even though it does close
        // the registry/firewall reachability gates. Classified
        // Irreversible rather than claiming a complete undo.
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Irreversible,
        .securable = "Security",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::High,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "rdp_control",
        .action = "status",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCatalogueC must author .execute_gate — an
// omission would value-initialize to ExecuteGate::Unspecified (the zero
// enumerator), which is a genuine compile failure here rather than a
// silent runtime gap. See ExecuteGate's doc comment in
// command_capability.hpp.
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueC),
              "every row in kPluginActionCatalogueC must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage, deliberately not a
/// `CommandCapabilityRegistry` instance itself: this header only DECLARES
/// rows, it never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability> plugin_action_catalogue_c() noexcept {
    return detail::kPluginActionCatalogueC;
}

} // namespace yuzu::server::capdecls
