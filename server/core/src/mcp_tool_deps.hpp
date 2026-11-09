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
// all reads: audit_fn and audit_as_session_fn write audit rows,
// `crypto_set_dashboard_layout_fn` writes the CALLER'S OWN /crypto dashboard layout,
// `dex_score_policy_apply_fn` writes the fleet-wide DEX score policy, and the others
// compose read-only views. A
// write-capable closure is admitted only when it is a pure forward of the very same
// code the REST twin calls (so the two cannot drift), the gate stays central (the
// record's securable / operation / ServiceScopeClass drive the generic tier and C8
// checks, and the closure never re-decides it), and the pre-mutation "attempted" audit
// row is guaranteed. Two shapes meet that:
//   (i)  a pure forward of the REST twin's `*Api` method, where the HANDLER writes its
//        "attempted" audit row BEFORE calling the closure and refuses to run without an
//        audit sink ("no audit row, no mutation");
//   (ii) a pure forward of the REST twin's shared audit-first apply function (today
//        `apply_dex_score_policy`), which itself writes "attempted" before touching the
//        store and fails closed when that row is refused. The audit sink is injected per
//        request by the handler, which refuses to call the closure without one. The dex
//        closure is this shape, not literally (i): the guarantee is kept, the handler is
//        just not the one writing the row.
// Either way there is one write path and one audit-row shape shared with REST. Nothing
// else here dispatches, pushes a tag or mutates a store.
//
// What a handler must not reach: any store, AgentRegistry, AuthDB, RbacStore, an
// McpServer member, or any write-capable callable beyond audit_fn, audit_as_session_fn and
// a closure admitted under that criterion. The
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
// The type aliases are pinned to their HardwareRoutes / McpServer / AuthRoutes
// twins by static_assert in mcp_server.cpp, so a signature change on either side
// is a build failure, not a silent copy that drifted. The one alias with no twin
// to pin is SessionFn: it is wired from the member function
// `AuthRoutes::resolve_session`, which has no alias of its own.

#include "authz_gates.hpp"        // authz::FleetReadGate
#include "crypto_api.hpp"         // CryptoApi's query / result types (the abstract seam, no store)
#include "crypto_widget_catalogue.hpp" // crypto_widgets::Access / WidgetGate
#include "dex_score_policy_writer.hpp"  // DexScorePolicyProvider::ReadFn, the write request / result / audit hook
#include "hardware_list_model.hpp" // HardwareCiDetail
#include "inventory_types.hpp"    // InventoryDevicesResult
#include "quarantine_visible.hpp" // QuarantineListFn

#include <httplib.h>
#include <yuzu/server/auth.hpp> // auth::Session (the session a session-bound audit writer stamps)

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
    using CiDetailFn = std::function<HardwareCiDetail(const std::string& agent_id, bool with_sections)>;
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

    // ── DEX score policy (mcp_tools_dex.cpp) ────────────────────────────────────────────
    // The OBSERVED store text (what GET /api/v1/dex/score-policy serves) and the ONE write
    // path (apply_dex_score_policy) with the REST route's store closures, provider and clock
    // already bound; only the per-request audit sink is passed in. Both are EMPTY when the
    // deployment has no runtime-config store, and a handler then answers an internal error.
    using DexScorePolicyReadFn = DexScorePolicyProvider::ReadFn;
    using DexScorePolicyAuditFn = decltype(DexScorePolicyWriteDeps::audit);
    using DexScorePolicyApplyFn = std::function<DexScorePolicyWriteResult(
        const DexScorePolicyWriteRequest&, DexScorePolicyAuditFn)>;
    DexScorePolicyReadFn dex_score_policy_read_fn;
    DexScorePolicyApplyFn dex_score_policy_apply_fn;
    // The caller's session, resolved ONCE per write, and the session-bound audit writer the
    // domain rows go through (`AuthRoutes::audit_as_session_fn()`, the same std::function type
    // as `RestApiV1::AuditAsSessionFn`): REST binds every row to the session its route resolved
    // (#6065 PR-Q), so a credential that lapses mid-request cannot leave a row naming no one
    // while the write proceeds. `audit_fn` above re-resolves the caller per row.
    // A handler passes ONLY the session session_fn returned to audit_as_session_fn; the writer
    // stamps whatever session it is given.
    // AuditAsSessionFn is pinned to `AuthRoutes::AuditAsSessionFn` by static_assert in
    // mcp_server.cpp; SessionFn is wired from `AuthRoutes::resolve_session` (a member function,
    // so there is no alias to pin it to).
    using SessionFn = std::function<std::optional<auth::Session>(const httplib::Request&)>;
    using AuditAsSessionFn = std::function<bool(
        const httplib::Request&, const auth::Session&, const std::string& principal_role,
        const std::string& action, const std::string& result, const std::string& target_type,
        const std::string& target_id, const std::string& detail)>;
    SessionFn session_fn;
    AuditAsSessionFn audit_as_session_fn;
};

} // namespace yuzu::server::mcp
