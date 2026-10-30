#pragma once

// Typed dependencies a registry tool handler may reach (mcp_tool_registry.hpp,
// ToolCallContext::deps).
//
// Every member is a PROVIDER CLOSURE, not a store pointer: the hardware members are the
// very same instances HardwareRoutes::Deps receives (server.cpp wires one closure into
// both), and the /crypto members forward to the same CryptoApi instance CryptoRoutes
// serves. A
// handler that held a raw store would re-implement the join the REST route
// already composes (build_hw_roster, hw_ci_detail_fn) and drift from it, which
// is the failure docs/api-twin-recipe.md section 1 exists to prevent.
//
// ToolDeps holds provider closures and no store instance. The closures are not
// all reads: audit_fn writes audit rows, `crypto_set_dashboard_layout_fn` writes the
// CALLER'S OWN /crypto dashboard layout, and the others compose read-only views. A
// write-capable closure is admitted only when ALL of these hold (the criterion every
// later family's mutating closure is held to): it is a pure forward of the very same
// *Api method the REST twin calls, so the two cannot drift; the gate stays central (the
// record's securable / operation / ServiceScopeClass drive the generic tier and C8
// checks, and the closure never re-decides it); and its handler writes its "attempted"
// audit row BEFORE calling it and refuses to run without an audit sink ("no audit row,
// no mutation"). Nothing else here dispatches, pushes a tag or mutates a store.
//
// What a handler must not reach: any store, AgentRegistry, AuthDB, RbacStore, an
// McpServer member, or any write-capable callable beyond audit_fn and a closure
// admitted under that criterion. The
// file-level half of that rule is a lexical test (test_mcp_dispatch_coverage.cpp):
// an mcp_tools_*.cpp includes none of *_store.hpp, agent_registry.hpp,
// mcp_server.hpp, auth_db* or pg/. That test checks DIRECT includes only; a
// header reached transitively through an allowed include is not caught by it, so
// that denylist is a tripwire for the first reach for a store, not a proof. The
// transitive include closure of every mcp_tools_*.cpp and of this header is held
// store-free by scripts/ci/check-seam-closure.py's MCP registry lane (#6558),
// against that script's store-header patterns.
//
// Ownership: McpServer holds one ToolDeps by value (set once via
// McpServer::set_tool_deps before build_handler) and the tools/call lookup site
// passes its address as ToolCallContext::deps. The lifetime is the McpServer's,
// which outlives every request. A closure is empty when ServerImpl did not wire
// it; a handler must null-check `ctx.deps` and each closure it uses and answer
// an internal error rather than an empty result.
//
// The type aliases are pinned to their HardwareRoutes / McpServer twins by
// static_assert in mcp_server.cpp, so a signature change on either side is a
// build failure, not a silent copy that drifted.

#include "authz_gates.hpp"        // authz::FleetReadGate
#include "crypto_api.hpp"         // CryptoApi's query / result types (the abstract seam, no store)
#include "crypto_widget_catalogue.hpp" // crypto_widgets::Access / WidgetGate
#include "hardware_list_model.hpp" // HardwareCiDetail
#include "inventory_types.hpp"    // InventoryDevicesResult
#include "quarantine_visible.hpp" // QuarantineListFn

#include <httplib.h>

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::mcp {

struct ToolDeps {
    // The ADR-0017 admit-then-filter chokepoint (authz::AuthRoutes::require_fleet_read
    // behind a conversion lambda). For a confined-read twin this is the SOLE gate:
    // never stack tier_allows or ctx.perm_fn on the same (securable, operation).
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    // Domain-verb audit rows (ctx.audit writes only the generic mcp.<tool> row).
    // Returns false when the row did not persist.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using RosterFn = std::function<InventoryDevicesResult()>;
    using CiDetailFn = std::function<HardwareCiDetail(const std::string& agent_id)>;
    using DexScoreFn = std::function<int(const std::string& agent_id)>;

    FleetReadFn fleet_read_fn;
    AuditFn audit_fn;
    RosterFn roster_fn;      // build_hw_roster: UNFILTERED, the gate's scope is the sole filter
    CiDetailFn ci_detail_fn; // hw_ci_detail_fn: the full per-device CI record composition
    DexScoreFn dex_score_fn; // page rows only, never the whole roster (one query per call)
    QuarantineListFn quarantine_list_fn;

    // ── /crypto (mcp_tools_crypto.cpp) ──────────────────────────────────────────────────
    // One closure per CryptoApi method the seven /crypto tools call, each a thin forward to
    // the SAME CryptoApi instance CryptoRoutes serves (server.cpp builds them from
    // `crypto_api_`), so an MCP twin cannot read a different answer than the REST route or the
    // page. The CryptoApi object itself is deliberately NOT a member: ToolDeps holds provider
    // closures, never a seam object. All five are EMPTY when the deployment has no CryptoApi
    // (no inventory store), and a handler then answers an internal error, never an empty
    // result. The Yuzu-issued reads take no scope: the handler gates them (Inventory:Read,
    // withheld from a confined caller), see handle_get_crypto_ca_stats.
    using CryptoSummaryFn = std::function<std::expected<CryptoSummary, CryptoReadError>(
        const CryptoSummaryQuery&, const authz::VisibleSet&)>;
    using CryptoDevicesFn = std::function<std::expected<CryptoDevicesPage, CryptoReadError>(
        const CryptoDevicesQuery&, const authz::VisibleSet&)>;
    using CryptoCaStatsFn = std::function<std::expected<CaCertStats, CryptoReadError>(
        std::optional<std::int64_t> as_of)>;
    using CryptoLayoutFn = std::function<std::expected<CryptoDashboardLayout, CryptoReadError>(
        const std::string& username)>;
    using CryptoSetLayoutFn = std::function<std::expected<CryptoDashboardLayout, CryptoReadError>(
        const std::string& username, const std::vector<std::string>& widgets,
        std::optional<std::int64_t> expected_version)>;
    // The ONE /crypto availability callback (server.cpp's crypto_access): what the caller may
    // DRAW, never a grant. Pinned to McpServer::CryptoAccessFn by static_assert in
    // mcp_server.cpp. Empty means unwired.
    using CryptoAccessFn = std::function<crypto_widgets::Access(
        const httplib::Request&, crypto_widgets::WidgetGate, const std::string& securable_type,
        const std::string& operation)>;
    // The calling principal's username, re-resolved from the request (the registry path
    // carries no session; the two dashboard-layout tools key the caller's OWN layout on it).
    // nullopt means the session could not be resolved: the handler fails closed.
    using UsernameFn = std::function<std::optional<std::string>(const httplib::Request&)>;

    CryptoSummaryFn crypto_library_summary_fn;
    CryptoDevicesFn crypto_library_devices_fn;
    CryptoCaStatsFn crypto_ca_stats_fn;
    CryptoLayoutFn crypto_dashboard_layout_fn;
    CryptoSetLayoutFn crypto_set_dashboard_layout_fn;
    CryptoAccessFn crypto_access_fn;
    UsernameFn username_fn;
};

} // namespace yuzu::server::mcp
