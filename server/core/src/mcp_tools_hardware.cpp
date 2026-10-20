// Registry-resident hardware CI tools (see mcp_tool_registry.hpp): the MCP twins of
// GET /api/v1/hardware (list_hardware_ci) and GET /api/v1/hardware/{id}
// (get_hardware_ci).
//
// Both are CONFINED READS gated by fleet_read_fn alone (ADR-0017 admit-then-filter,
// Inventory:Read): the gate already covers the MCP tier ladder and RBAC, so neither
// handler calls tier_allows or ctx.perm_fn (stacking either is the BLOCKING defect
// authz_gates.hpp documents). They reach the data only through ToolDeps, the SAME
// roster / CI-detail / DEX-score closures HardwareRoutes::Deps receives, and shape it
// with the SAME builders REST uses (hardware_list_model.hpp), so the two surfaces
// cannot disagree on a byte of `data`.
//
// Audit posture: the CI record carries serial, system UUID and MAC (ADR-0016
// behavioural-PII tier), and the REST twins fail CLOSED when the access row does not
// persist. These tools do the same: a domain-verb row (inventory.devices /
// inventory.device.ci, via deps->audit_fn) AND the generic mcp.<tool> row (ctx.audit)
// are both written AFTER the read, and if either is dropped the data is WITHHELD.
// This is deliberately stricter than the set-and-proceed MCP default
// (audit_persisted:false); do not copy it blindly to a non-PII read.
//
// ctx.args is UNVALIDATED here beyond "is an object" (the central check): the schema's
// enum / minimum / maximum are advisory for a non-approval-gated tool, so each handler
// parses its own arguments strictly and refuses, never clamps.

#include "mcp_tool_registry.hpp"

#include "authz_model.hpp"         // authz::in_scope
#include "hardware_list_model.hpp" // the shared list / record core and JSON builders
#include "mcp_jsonrpc.hpp"         // kInternalError, kInvalidParams, success_response
#include "mcp_retry.hpp"           // kMcpStoreFaultRetryMs
#include "mcp_tool_deps.hpp"       // ToolDeps
#include "rest_audit.hpp"          // detail::try_persist_audit (the shared audit kernel)

#include <yuzu/server/auth.hpp> // auth::kMaxAgentIdLength

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <utility>

namespace yuzu::server::mcp {
namespace {

// The record schemas below spell the agent_id bound as a literal; this keeps it tied to the
// bound id_is_audit_safe actually enforces.
static_assert(auth::kMaxAgentIdLength == 256,
              "get_hardware_ci's agent_id maxLength literal must match auth::kMaxAgentIdLength");

constexpr const char* kListOutputSchema =
    R"j({"type":"object","properties":{"devices":{"type":"array","items":{"type":"object","properties":{"agent_id":{"type":"string"},"hostname":{"type":"string"},"os":{"type":"string"},"os_label":{"type":"string"},"online":{"type":"boolean"},"stale":{"type":"boolean"},"last_seen":{"type":"string"},"last_seen_ms":{"type":"integer"},"ci_present":{"type":"boolean"},"serial":{"type":["string","null"]},"model":{"type":["string","null"]},"manufacturer":{"type":["string","null"]},"cpu_model":{"type":["string","null"]},"cpu_cores":{"type":["integer","null"]},"cpu_threads":{"type":["integer","null"]},"ram_bytes":{"type":["integer","null"]},"os_name":{"type":["string","null"]},"os_version":{"type":["string","null"]},"os_build":{"type":["string","null"]},"arch":{"type":["string","null"]},"domain":{"type":["string","null"]},"primary_mac":{"type":["string","null"]},"agent_version":{"type":["string","null"]},"ips":{"type":["array","null"],"items":{"type":"string"}},"tags":{"type":"array","items":{"type":"object","properties":{"key":{"type":"string"},"value":{"type":"string"}},"required":["key","value"]}},"dex_score":{"type":["integer","null"]}},"required":["agent_id","hostname","os","os_label","online","stale","last_seen","last_seen_ms","ci_present","serial","model","manufacturer","cpu_model","cpu_cores","cpu_threads","ram_bytes","os_name","os_version","os_build","arch","domain","primary_mac","agent_version","ips","tags","dex_score"]}},"count":{"type":"integer"},"total_matching":{"type":"integer"},"devices_omitted":{"type":"integer"},"ci_degraded":{"type":"boolean"},"tags_degraded":{"type":"boolean"},"kpis":{"type":"object","properties":{"total":{"type":"integer"},"online":{"type":"integer"},"offline":{"type":"integer"},"stale":{"type":"integer"},"with_ci":{"type":["integer","null"]}},"required":["total","online","offline","stale","with_ci"]},"query":{"type":"object","properties":{"q":{"type":"string"},"os":{"type":"string"},"status":{"type":"string"},"sort":{"type":"string"},"dir":{"type":"string"},"limit":{"type":"integer"},"offset":{"type":"integer"},"tag":{"type":"string"}},"required":["q","os","status","sort","dir","limit","offset","tag"]}},"required":["devices","count","total_matching","devices_omitted","ci_degraded","tags_degraded","kpis","query"]})j";

constexpr const char* kGetOutputSchema =
    R"j({"type":"object","properties":{"agent_id":{"type":["string","null"]},"hostname":{"type":["string","null"]},"os":{"type":["string","null"]},"online":{"type":"boolean"},"last_seen":{"type":["string","null"]},"identity_state":{"type":"string","enum":["found","absent","degraded"]},"ci":{"type":["object","null"],"properties":{"manufacturer":{"type":["string","null"]},"model":{"type":["string","null"]},"serial":{"type":["string","null"]},"system_uuid":{"type":["string","null"]},"domain":{"type":["string","null"]},"ou":{"type":["string","null"]},"bios_vendor":{"type":["string","null"]},"bios_version":{"type":["string","null"]},"bios_date":{"type":["string","null"]},"cpu_model":{"type":["string","null"]},"cpu_cores":{"type":["integer","null"]},"cpu_threads":{"type":["integer","null"]},"ram_bytes":{"type":["integer","null"]},"disks_summary":{"type":["string","null"]},"primary_mac":{"type":["string","null"]},"macs_summary":{"type":["string","null"]},"nic_count":{"type":["integer","null"]},"os_name":{"type":["string","null"]},"os_version":{"type":["string","null"]},"os_build":{"type":["string","null"]},"arch":{"type":["string","null"]},"first_seen":{"type":"integer"},"last_seen":{"type":"integer"}},"required":["manufacturer","model","serial","system_uuid","domain","ou","bios_vendor","bios_version","bios_date","cpu_model","cpu_cores","cpu_threads","ram_bytes","disks_summary","primary_mac","macs_summary","nic_count","os_name","os_version","os_build","arch","first_seen","last_seen"]},"ci_state":{"type":"string","enum":["found","absent","degraded"]},"software":{"type":["array","null"],"items":{"type":"object","properties":{"name":{"type":"string"},"version":{"type":"string"},"publisher":{"type":"string"},"install_date":{"type":"string"}},"required":["name","version","publisher","install_date"]}},"software_truncated":{"type":"boolean"},"tags":{"type":["array","null"],"items":{"type":"object","properties":{"key":{"type":"string"},"value":{"type":"string"},"source":{"type":"string"},"updated_at":{"type":"integer"}},"required":["key","value","source","updated_at"]}},"agent_version":{"type":["string","null"]},"sync_supported":{"type":"boolean"},"software_last_seen":{"type":["integer","null"]}},"required":["agent_id","hostname","os","online","last_seen","identity_state","ci","ci_state","software","software_truncated","tags","agent_version","sync_supported","software_last_seen"]})j";

// ── shared answers ─────────────────────────────────────────────────────────

void answer(const ToolCallContext& ctx, std::string body) {
    ctx.res.set_content(std::move(body), "application/json");
}

// A provider the deployment did not wire. REST answers an unhinted 503 for the same
// case; it is a misconfiguration, not a transient fault, so no retry hint. The generic
// row is still written (every registry tool call leaves an mcp.<tool> row) and, when the
// domain sink exists, a failure row under the REST verb too.
void answer_unwired(const ToolCallContext& ctx, const char* verb, const char* target_type,
                    const std::string& target_id, const char* what) {
    if (ctx.deps != nullptr)
        (void)yuzu::server::detail::try_persist_audit(ctx.deps->audit_fn, ctx.req, verb, "failure",
                                                      target_type, target_id, what);
    (void)ctx.audit("failure", what);
    // retry-hint-exempt: an unwired provider is a deployment misconfiguration, not a transient fault
    answer(ctx, ctx.a4_error(kInternalError, "hardware service unavailable", {}, -1, {}, true));
}

// A failed roster / identity read: never an empty success (ADR-0016 section 7). Transient,
// so the caller is told to back off, matching REST's 503 + retry_after_ms 5000.
void answer_roster_unreadable(const ToolCallContext& ctx, const char* verb, const char* target_type,
                              const std::string& target_id, const std::string& domain_detail) {
    const bool domain_ok = yuzu::server::detail::try_persist_audit(
        ctx.deps->audit_fn, ctx.req, verb, "failure", target_type, target_id, domain_detail);
    const bool generic_ok = ctx.audit("failure", domain_detail);
    answer(ctx, ctx.a4_error(kInternalError, "hardware roster unavailable", "retry the request",
                             /*retry_after_ms=*/kMcpStoreFaultRetryMs, {},
                             domain_ok && generic_ok));
}

// Either access row was dropped: the personal data is NOT served. The message already says
// the audit subsystem is the cause, so the envelope does not also carry audit_persisted.
void answer_audit_withheld(const ToolCallContext& ctx) {
    answer(ctx, ctx.a4_error(kInternalError, "audit subsystem unavailable, request not served",
                             "retry the request", /*retry_after_ms=*/kMcpStoreFaultRetryMs, {},
                             true));
}

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// ── list_hardware_ci ───────────────────────────────────────────────────────

void handle_list_hardware_ci(const ToolCallContext& ctx) {
    const ToolDeps* deps = ctx.deps;
    if (deps == nullptr || !deps->fleet_read_fn || !deps->roster_fn) {
        answer_unwired(ctx, "inventory.devices", "Inventory", "fleet", "hardware provider unwired");
        return;
    }
    // The SOLE gate (confined read, ADR-0017). A refusal has already written its own A4
    // body and status; the handler writes nothing and audits nothing more.
    const auto gate = deps->fleet_read_fn(ctx.req, ctx.res, "Inventory", "Read");
    if (!gate.admitted)
        return;

    // Input is judged before the roster is read. The shared strict parser refuses what REST
    // would coerce or clamp (#4644); normalise_hardware_query then validates the tag key.
    std::string why;
    const auto raw = hardware_query_from_args(ctx.args, &why);
    if (!raw) {
        (void)ctx.audit("denied", "invalid arguments: " + why);
        // retry-hint-exempt: caller-input rejection
        answer(ctx, ctx.a4_error(kInvalidParams, why, "fix the argument and re-call", -1, {}, true));
        return;
    }
    const auto normalised = normalise_hardware_query(*raw);
    if (!normalised) {
        (void)ctx.audit("denied", "invalid arguments: tag key");
        // retry-hint-exempt: caller-input rejection
        answer(ctx, ctx.a4_error(kInvalidParams, "tag is not a valid tag key or key=value filter",
                                 "fix the argument and re-call", -1, {}, true));
        return;
    }

    const InventoryDevicesResult all = deps->roster_fn();
    if (all.roster_degraded) {
        answer_roster_unreadable(ctx, "inventory.devices", "Inventory", "fleet",
                                 "hardware roster read failed");
        return;
    }
    auto [scoped, omitted] = scoped_roster(all, gate.scope);
    HardwareListPage page = build_hardware_list_page(std::move(scoped), *normalised);
    if (deps->dex_score_fn)
        for (auto& row : page.rows)
            row.dex_score = deps->dex_score_fn(row.agent_id);

    // Both rows are attempted (no short-circuit) so a drop of one never hides the other.
    const std::string detail = "hardware list (MCP): devices=" + std::to_string(page.total_matching) +
                               " omitted=" + std::to_string(omitted);
    const bool domain_ok = yuzu::server::detail::try_persist_audit(
        deps->audit_fn, ctx.req, "inventory.devices", "success", "Inventory", "fleet", detail);
    const bool generic_ok = ctx.audit("success", detail);
    if (!domain_ok || !generic_ok) {
        answer_audit_withheld(ctx);
        return;
    }

    const nlohmann::json body = hardware_list_json(page, all.ci_degraded, omitted, all.tags_degraded);
    answer(ctx, success_response(ctx.id, ctx.tool_result(body.dump(), kListOutputSchema)));
}

// ── get_hardware_ci ────────────────────────────────────────────────────────

void handle_get_hardware_ci(const ToolCallContext& ctx) {
    const ToolDeps* deps = ctx.deps;
    if (deps == nullptr || !deps->fleet_read_fn || !deps->ci_detail_fn) {
        answer_unwired(ctx, "inventory.device.ci", "Agent", "", "hardware provider unwired");
        return;
    }
    const auto gate = deps->fleet_read_fn(ctx.req, ctx.res, "Inventory", "Read");
    if (!gate.admitted)
        return;

    // agent_id must be a non-empty string within the audit-trail floor: it reaches
    // target_id on every row below. A wrongly typed value is refused, never stringified.
    const auto it = ctx.args.find("agent_id");
    if (it == ctx.args.end() || !it->is_string() || it->get_ref<const std::string&>().empty() ||
        !id_is_audit_safe(it->get_ref<const std::string&>())) {
        (void)ctx.audit("denied", "invalid arguments: agent_id");
        // retry-hint-exempt: caller-input rejection
        answer(ctx, ctx.a4_error(kInvalidParams,
                                 "agent_id is required: a non-empty string of at most 256 bytes "
                                 "with no control characters",
                                 "fix the argument and re-call", -1, {}, true));
        return;
    }
    const std::string agent_id = it->get<std::string>();

    // Out-of-scope collapses to the SAME answer as a nonexistent id (the existence-oracle
    // closure REST's 404 gives). Checked BEFORE the detail is fetched, so a hidden device's
    // record is never even composed. Only the audit row tells the two apart.
    if (!authz::in_scope(gate.scope, agent_id)) {
        (void)ctx.audit("denied", "device out of the caller's scope");
        // retry-hint-exempt: not found (and out of scope) is terminal
        answer(ctx, ctx.a4_error(kInvalidParams, "not found", {}, -1, {}, true));
        return;
    }

    const HardwareCiDetail detail = deps->ci_detail_fn(agent_id);
    const HardwareCiRead read = classify_hardware_ci_read(detail);
    if (read == HardwareCiRead::RosterUnreadable) {
        // A failed roster read is never "not found" (#5531).
        answer_roster_unreadable(ctx, "inventory.device.ci", "Agent", agent_id,
                                 "hardware CI record (MCP) state=roster unreadable");
        return;
    }
    if (read == HardwareCiRead::NotFound) {
        (void)ctx.audit("failure", "not found");
        // retry-hint-exempt: not found (and out of scope) is terminal
        answer(ctx, ctx.a4_error(kInvalidParams, "not found", {}, -1, {}, true));
        return;
    }

    std::string state = !detail.ci.has_value()      ? "store degraded"
                        : !detail.ci->has_value() ? "absent"
                                                    : "found";
    if (detail.identity_degraded)
        state += " identity=roster unreadable";
    const std::string row_detail = "hardware CI record (MCP) state=" + state;
    const char* result = detail.identity_degraded ? "failure" : "success";
    const bool domain_ok = yuzu::server::detail::try_persist_audit(
        deps->audit_fn, ctx.req, "inventory.device.ci", result, "Agent", agent_id, row_detail);
    const bool generic_ok = ctx.audit(result, row_detail);
    if (!domain_ok || !generic_ok) {
        answer_audit_withheld(ctx);
        return;
    }

    const nlohmann::json body = hardware_ci_json(detail, now_secs());
    answer(ctx, success_response(ctx.id, ctx.tool_result(body.dump(), kGetOutputSchema)));
}

// Positional initialisation only (no designated initialisers): the lexical CI gates
// (check-api-parity.py, check-mcp-retry-hints.py) read this slice.
constexpr ToolRecord kToolRecords[] = {
    {"list_hardware_ci",
     "List hardware Configuration Items (CI): one row per device with its identity and "
     "the last synced hardware facts (manufacturer, model, serial, CPU, RAM, OS, MAC, tags, "
     "7-day DEX score), plus fleet KPIs. Read-only, paged (limit 1..200, default 50) and "
     "filterable by q, os, status and tag. Confined: results are narrowed to the devices "
     "the caller may read, and devices_omitted counts the ones hidden. ci_degraded or "
     "tags_degraded true means that enrichment could not be read, so a null field proves "
     "nothing; a failed roster read is a retryable error, never an empty list. Serial, "
     "system UUID and MAC are personal data: every call is audited as inventory.devices "
     "and, unlike most MCP reads, fails CLOSED (no data) when that audit row cannot be "
     "persisted. Mirrors GET /api/v1/hardware.",
     R"j({"type":"object","properties":{"q":{"type":"string","maxLength":256,"description":"Search text: whitespace-separated tokens, all must match (hostname, id, model, serial and similar)."},"os":{"type":"string","enum":["all","windows","linux","macos"],"default":"all"},"status":{"type":"string","enum":["all","online","offline"],"default":"all"},"sort":{"type":"string","enum":["name","os","status","last_seen","manufacturer","model","serial","cpu","ram","os_version","version","ip"],"default":"name"},"dir":{"type":"string","enum":["asc","desc"],"default":"asc"},"tag":{"type":"string","maxLength":256,"description":"Tag filter: key (any value) or key=value (exact)."},"offset":{"type":"integer","minimum":0,"default":0},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}}})j",
     kListOutputSchema, "Inventory", "Read", ServiceScopeClass::confined, ToolEffect::ReadOnly, true,
     "List hardware CI records", &handle_list_hardware_ci},
    {"get_hardware_ci",
     "Get one device's full hardware CI record: identity, the synced CI blob (manufacturer, "
     "model, serial, system UUID, BIOS, CPU, RAM, disks, MACs, OS), installed software (capped, "
     "software_truncated says so), tags and the live agent version. Read-only. identity_state "
     "and ci_state are each found, absent or degraded, so a store failure never reads as "
     "'this device has no CI record'. A device that does not exist and one outside the "
     "caller's scope both answer the same 'not found'. A failed roster read is a retryable "
     "error. Serial, system UUID and MAC are personal data: every call is audited as "
     "inventory.device.ci and fails CLOSED (no data) when that audit row cannot be persisted. "
     "Mirrors GET /api/v1/hardware/{id}.",
     R"j({"type":"object","properties":{"agent_id":{"type":"string","minLength":1,"maxLength":256,"description":"The device's agent id."}},"required":["agent_id"]})j",
     kGetOutputSchema, "Inventory", "Read", ServiceScopeClass::confined, ToolEffect::ReadOnly, true,
     "Get hardware CI record", &handle_get_hardware_ci},
};

static_assert(records_well_formed(kToolRecords),
              "mcp_tools_hardware.cpp: a record is malformed (null field or handler, bad name, "
              "effect/operation mismatch) or two records share a name; see record_defect()");

} // namespace

std::span<const ToolRecord> hardware_tool_records() {
    return kToolRecords;
}

} // namespace yuzu::server::mcp
