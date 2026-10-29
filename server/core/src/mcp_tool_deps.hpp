#pragma once

// Typed dependencies a registry tool handler may reach (mcp_tool_registry.hpp,
// ToolCallContext::deps).
//
// Every member is a PROVIDER CLOSURE, the very same instance HardwareRoutes::Deps
// receives (server.cpp wires one closure into both), not a store pointer. A
// handler that held a raw store would re-implement the join the REST route
// already composes (build_hw_roster, hw_ci_detail_fn) and drift from it, which
// is the failure docs/api-twin-recipe.md section 1 exists to prevent.
//
// ToolDeps holds provider closures and no store instance. The closures are not
// all reads: audit_fn writes audit rows (and can only write audit rows), and the
// others compose read-only views. Nothing here dispatches, pushes a tag or
// mutates a store.
//
// What a handler must not reach: any store, AgentRegistry, AuthDB, RbacStore, an
// McpServer member, or any write-capable callable beyond audit_fn. The
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
#include "hardware_list_model.hpp" // HardwareCiDetail
#include "inventory_types.hpp"    // InventoryDevicesResult
#include "quarantine_visible.hpp" // QuarantineListFn

#include <httplib.h>

#include <functional>
#include <string>

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
};

} // namespace yuzu::server::mcp
