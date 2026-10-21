// Registry-resident device-containment tools (see mcp_tool_registry.hpp). Each record is
// the union of the legacy kTools / kToolSecurityRows / kToolAnnotation rows plus the
// dispatch entry point.
//
// list_quarantined_devices is a CONFINED READ: ToolDeps::fleet_read_fn (the ADR-0017
// admit-then-filter chokepoint) is its SOLE gate. The handler therefore calls neither
// tier_allows nor ctx.perm_fn; stacking either on the same (securable, operation) is the
// documented BLOCKING defect (authz_gates.hpp). The generic tier / C7 / C8 gates still run
// from the record before the handler is reached.

#include "mcp_tool_registry.hpp"

#include "mcp_jsonrpc.hpp"         // kInvalidParams, kInternalError, success_response
#include "mcp_retry.hpp"           // kMcpStoreFaultRetryMs
#include "mcp_tool_deps.hpp"       // ToolDeps (provider closures)
#include "quarantine_read_model.hpp" // quarantine_list_data_json / quarantine_dump (shared with REST)
#include "quarantine_visible.hpp"  // quarantine_visible_records (shared admit-then-filter read)

#include <nlohmann/json.hpp>

#include <spdlog/spdlog.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace yuzu::server::mcp {
namespace {

// MCP-only bound on the list: REST GET /api/v1/quarantine is unbounded. 200 is the same
// cap the Quarantined devices panel applies (DeviceContainmentRoutes::kPanelCap).
constexpr std::size_t kDefaultLimit = 200;
constexpr std::size_t kMaxLimit = 500;

constexpr const char* kInputSchema =
    R"j({"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":500,"default":200,"description":"Maximum records returned, 1..500 (default 200). This bound exists on the MCP tool only; the REST list is unbounded. When more records are visible, `more` is true."}}})j";

constexpr const char* kOutputSchema =
    R"j({"type":"object","properties":{"quarantined":{"type":"array","items":{"type":"object","properties":{"agent_id":{"type":"string"},"status":{"type":"string"},"quarantined_by":{"type":"string"},"quarantined_at":{"type":"integer"},"whitelist":{"type":"string"},"reason":{"type":"string"},"last_applied_at":{"type":"integer"},"last_confirmed_at":{"type":"integer"}},"required":["agent_id","status","quarantined_by","quarantined_at","whitelist","reason","last_applied_at","last_confirmed_at"]}},"count":{"type":"integer"},"more":{"type":"boolean"},"audit_persisted":{"type":"boolean","description":"Present (false) only when the audit row for this read failed to persist"}},"required":["quarantined","count","more"]})j";

// Strict-typed limit: absent selects the default; anything but an in-range JSON integer is
// refused (never stringified or clamped). enum/minimum/maximum in the advertised schema are
// not enforced for a non-approval-gated tool, so this is the only bound check. Returns
// false on a bad value.
bool parse_limit(const nlohmann::json& args, std::size_t& limit) {
    limit = kDefaultLimit;
    const auto it = args.find("limit");
    if (it == args.end())
        return true;
    // A float, string, bool or null is not an integer. A value parsed from request text is
    // unsigned when non-negative; a signed one (possible when built in code) must be positive.
    if (!it->is_number_integer())
        return false;
    if (!it->is_number_unsigned() && it->get<std::int64_t>() < 1)
        return false;
    const auto v = it->get<std::uint64_t>();
    if (v < 1 || v > kMaxLimit)
        return false;
    limit = static_cast<std::size_t>(v);
    return true;
}

// list_quarantined_devices. Twin of GET /api/v1/quarantine: the same Security:Read gate
// through fleet_read_fn, the same scoped read (quarantine_visible_records) and the same row
// builder (quarantine_read_model.hpp). The generic gates have run; ctx.args is a JSON
// object (central check) but its keys are unvalidated. Every call, success or refusal,
// leaves exactly one generic mcp.list_quarantined_devices row (a gate refusal excepted: the
// gate has already answered and the handler writes nothing).
void handle_list_quarantined_devices(const ToolCallContext& ctx) {
    const ToolDeps* deps = ctx.deps;
    if (deps == nullptr || !deps->fleet_read_fn || !deps->quarantine_list_fn) {
        spdlog::error("list_quarantined_devices: ToolDeps or a provider closure unwired - "
                      "misconfigured call site; failing closed");
        const bool audit_ok = ctx.audit("failure", "dependency unwired; failing closed");
        ctx.res.set_content(
            ctx.a4_error(kInternalError, "service unavailable", {}, -1, {}, audit_ok), // retry-hint-exempt: unwired dependency is a deployment misconfiguration
            "application/json");
        return;
    }

    const auto gate = deps->fleet_read_fn(ctx.req, ctx.res, "Security", "Read");
    if (!gate.admitted)
        return; // the gate already wrote its own A4 error body and status

    std::size_t limit = 0;
    if (!parse_limit(ctx.args, limit)) {
        const bool audit_ok = ctx.audit("denied", "invalid arguments: limit");
        ctx.res.set_content(
            ctx.a4_error(kInvalidParams, "limit must be an integer between 1 and 500",
                         "omit `limit` for the default of 200, or pass a JSON integer in 1..500", -1, {}, audit_ok), // retry-hint-exempt: caller-input rejection
            "application/json");
        return;
    }

    // The scope is pushed into the store query, so the cap applies to the caller's own
    // records. A null store read is StoreDegraded, never an empty list: a device could
    // still be contained while the caller sees "nothing quarantined".
    const auto visible = quarantine_visible_records(gate.scope, deps->quarantine_list_fn,
                                                    QuarantineVisibleOptions{.max_visible = limit});
    if (visible.status == QuarantineReadStatus::StoreDegraded) {
        const bool audit_ok = ctx.audit("failure", "quarantine list unavailable; store degraded");
        ctx.res.set_content(ctx.a4_error(kInternalError, "Quarantine list unavailable - read failed",
                                         "retry the request", /*retry_after_ms=*/kMcpStoreFaultRetryMs,
                                         {}, audit_ok),
                            "application/json");
        return;
    }

    // REST GET writes no success audit; this generic row is the only one. A dropped row is
    // surfaced as audit_persisted:false (set-and-proceed), the data is still returned.
    const bool audit_ok = ctx.audit("success", "limit=" + std::to_string(limit) + " returned=" +
                                                   std::to_string(visible.records.size()) +
                                                   (visible.more ? " more=true" : " more=false"));

    nlohmann::ordered_json body = nlohmann::ordered_json::object();
    body["quarantined"] = quarantine_list_data_json(visible.records);
    body["count"] = visible.records.size();
    body["more"] = visible.more;
    if (!audit_ok)
        body["audit_persisted"] = false;
    const auto result = ctx.tool_result(quarantine_dump(body), kOutputSchema);
    ctx.res.set_content(success_response(ctx.id, result), "application/json");
}

// Positional initialisation only (no designated initialisers): the lexical CI gates
// (check-api-parity.py, check-mcp-retry-hints.py) read this slice.
constexpr ToolRecord kToolRecords[] = {
    {"list_quarantined_devices",
     "List the devices under active quarantine that the caller may see, newest first. Use it "
     "to find what is isolated, who isolated it and why, and to check a device before calling "
     "quarantine_device (which isolates one). Each record carries agent_id, status, "
     "quarantined_by, quarantined_at, whitelist, reason and the endpoint-containment stamps "
     "last_applied_at / last_confirmed_at (0 = never). A record means the server holds a "
     "quarantine for the device. The stamps are written only by the containment "
     "reconciler, so 0 means it has not recorded it, not that the device is unisolated; to "
     "verify a device, run a `status` read through execute_instruction (plugin quarantine). "
     "Results are narrowed to "
     "the caller's management-group and service-scope visibility, so an empty list means no "
     "visible device is quarantined, not that none is quarantined fleet-wide. `limit` is "
     "1..500 (default 200); when `more` is true further visible records exist and this tool "
     "does not page: raise limit up to 500, and past that use REST GET /api/v1/quarantine for "
     "the complete list. "
     "A degraded store read is a retryable error, never an empty list. Read-only. If the audit "
     "row for the read cannot be written the list is still returned with audit_persisted "
     "false.",
     kInputSchema, kOutputSchema, "Security", "Read", ServiceScopeClass::confined,
     ToolEffect::ReadOnly, true, "List quarantined devices", &handle_list_quarantined_devices},
};

static_assert(records_well_formed(kToolRecords),
              "mcp_tools_containment.cpp: a record is malformed (null field or handler, bad name, "
              "effect/operation mismatch) or two records share a name; see record_defect()");

} // namespace

std::span<const ToolRecord> containment_tool_records() {
    return kToolRecords;
}

} // namespace yuzu::server::mcp
