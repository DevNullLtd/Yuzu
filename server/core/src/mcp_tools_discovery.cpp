// Registry-resident discovery tools (see mcp_tool_registry.hpp). Each record is the
// union of the legacy kTools / kToolSecurityRows / kToolAnnotation rows plus the
// dispatch entry point. The record's (securable, operation) drives the generic
// tier / approval / C7 / C8 gates; the handler below repeats its own
// tier_allows / perm_fn pair and must be kept in sync with the record.

#include "mcp_tool_registry.hpp"

#include "discover_routes.hpp"     // build_routes_catalog (shared with REST /discover/routes)
#include "mcp_jsonrpc.hpp"         // kTierDenied, success_response
#include "mcp_policy.hpp"          // tier_allows
#include "openapi_spec_access.hpp" // openapi_spec_json()

#include <span>

namespace yuzu::server::mcp {
namespace {

// discover_routes. The generic gates (knownness, C7, service-scope, tier, approval)
// have already run by the time this is called; the #2405 input-schema check runs
// only for approval-gated tools, so a non-gated handler must validate its own
// arguments (ctx.args may be any JSON value). discover_routes takes none and ignores
// ctx.args. This body is the former dispatch branch, with the per-request helpers
// read off the context.
void handle_discover_routes(const ToolCallContext& ctx) {
    if (!tier_allows(ctx.tier, "Infrastructure", "Read")) {
        ctx.res.set_content(ctx.a4_error(kTierDenied, "MCP tier does not allow this operation",
                                         kTierRemediation, -1, {}, true),
                            "application/json");
        return;
    }
    if (!ctx.perm_fn(ctx.req, ctx.res, "Infrastructure", "Read"))
        return;
    // Compiled-in — no store dependency, same "answers even when
    // everything else is down" property as the REST sibling.
    auto doc = yuzu::server::build_routes_catalog(yuzu::server::openapi_spec_json());
    auto result = ctx.tool_result(doc.json, kObjectOutputSchema);
    ctx.audit("success", {});
    ctx.res.set_content(success_response(ctx.id, result), "application/json");
}

// Positional initialisation only (no designated initialisers): the lexical CI gates
// (check-api-parity.py, check-mcp-retry-hints.py) read this slice.
constexpr ToolRecord kToolRecords[] = {
    {"discover_routes",
     "REST route catalog — subset of the same OpenAPI document GET /api/v1/openapi.json "
     "serves. Hand-maintained source, so it can under-report an undocumented route "
     "(the response carries a caveat field). Read-only catalog.",
     R"({"type":"object","properties":{}})",
     // #2986: build_routes_catalog's per-route projection is fixed
     // (method/path/summary/tags/description) regardless of which OpenAPI
     // operations exist — the route COUNT varies, the shape does not.
     R"j({"type":"object","properties":{"version":{"type":"integer"},"source":{"type":"string"},"description":{"type":"string"},"caveat":{"type":"string"},"count":{"type":"integer"},"routes":{"type":"array","items":{"type":"object","properties":{"method":{"type":"string"},"path":{"type":"string"},"summary":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}},"description":{"type":"string"}},"required":["method","path","summary","tags","description"]}}},"required":["version","source","description","caveat","count","routes"]})j",
     "Infrastructure", "Read", ServiceScopeClass::denied, ToolEffect::ReadOnly, true,
     "Discover REST routes", &handle_discover_routes},
};

static_assert(records_well_formed(kToolRecords),
              "mcp_tools_discovery.cpp: a record is malformed (null field or handler, bad name, "
              "effect/operation mismatch) or two records share a name; see record_defect()");

} // namespace

std::span<const ToolRecord> discovery_tool_records() {
    return kToolRecords;
}

} // namespace yuzu::server::mcp
