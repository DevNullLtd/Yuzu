#pragma once

/// @file app_usage_read_model.hpp
/// Shared PURE serializer for the app-usage read surface — the Rule 1 home
/// `docs/api-twin-recipe.md` §1 describes: "REST, MCP, and the HTML dashboard
/// fragment must call the same function to build the response body's data."
/// No `httplib.h`, no `mcp_jsonrpc.hpp` — callable from both
/// `app_usage_routes.cpp` and `mcp_server.cpp` with zero transport
/// dependency, so the two JSON shapes cannot drift apart by construction
/// (the anti-pattern this file replaces: `app_usage_row_to_json()` in
/// `app_usage_routes.cpp` and an inline `JArr`/`JObj` builder in
/// `mcp_server.cpp` independently naming and serializing the same five
/// fields — same shape as the `perf_stat_json`/`stat_json` drift the recipe
/// names, mirrors `dex_read_model.hpp`'s fix for the sibling DEX twins).
///
/// Deliberately does NOT unify how each surface FETCHES the data —
/// `AppUsageRoutes` injects closures (its own established test seam, the
/// `SleRoutes`/`DexRoutes` precedent) while the MCP handler holds an
/// `AppUsageStore*` directly; both already resolve to the SAME
/// `AgentLastUsedRow` type (`app_usage_store.hpp`) before reaching this file,
/// so unifying the JSON layer alone closes the drift the review flagged
/// without forcing either surface off its own tested fetch seam.

#include "app_usage_store.hpp" // AgentLastUsedRow

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::server {

/// One agent's app-usage projection, already fetched by the caller via
/// whichever seam it uses (REST's injected closures, MCP's store pointer).
struct AppUsageModel {
    std::string agent_id;
    std::vector<AgentLastUsedRow> apps;
    /// Sourced from the store's `usage_state` PARENT row (never
    /// `apps.front().collected_at`) — a legitimate empty-snapshot replace has
    /// no row to carry it, and that empty case must still report the real
    /// collection time, not 0 (#C2). Both callers already fetch it that way;
    /// this struct just carries the already-correct value through.
    std::int64_t collected_at{0};
};

/// Shared JSON serializer (Rule 1). Returns a JSON OBJECT body
/// (`{"agent_id":...,"apps":[...],"collected_at":...}`) — callers wrap it in
/// their own envelope (REST's `ok_json`, MCP's `tool_result`).
/// `audit_persisted` mirrors `dex_read_model.hpp`'s established parameter
/// shape (omitted entirely when `true`), kept for interface consistency with
/// that file's other shared serializers — this endpoint's own fail-closed
/// audit posture means neither caller ever reaches this function on a
/// dropped audit write, so both always call with the default today.
std::string app_usage_json(const AppUsageModel& model, bool audit_persisted = true);

} // namespace yuzu::server
