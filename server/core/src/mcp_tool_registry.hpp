#pragma once

// MCP tool registry seam: the record shape and the handler context for tools
// that live in their own translation unit (mcp_tools_<domain>.cpp) instead of
// the legacy kTools[] + if/else chain in mcp_server.cpp.
//
// A ToolRecord is the UNION of the four rows a legacy tool spreads over
// mcp_server.cpp (ToolDef, ToolSecurity, ToolAnnotation, and the dispatch
// branch), so a registry tool is declared in exactly one place. Write-set
// membership is not a field: it is DERIVED (`operation != "Read"`), which is
// exactly the parity rule the boot validator enforces for the legacy tables.
//
// How a record reaches the server: each domain file exports an explicit
// accessor returning a std::span<const ToolRecord> over its constexpr array,
// and mcp_server.cpp's registered_tool_records() lists the spans in a fixed
// order. There is deliberately NO self-registration: yuzu_server_core_lib is a
// static library, and an unreferenced self-registering object is silently
// dropped by the linker.
//
// What the dispatch chain still does BEFORE a handler runs, unchanged:
// knownness, the C7 read-only guard, service-scope default-deny, tier,
// approval and the #2405 input-schema check. A handler therefore only runs
// for a tool that has cleared the generic gates, and then performs its OWN
// perm_fn check (RBAC runs after the tier gate, never before it).
//
// The context carries the nine things every legacy branch reads and nothing
// else: no store pointers. A handler that needs one is a sign the tool belongs
// on the legacy path (or the context shape is wrong), not a reason to widen
// this struct.

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <string>
#include <string_view>

namespace yuzu::server::mcp {

// Service-scoped-token classification for the C8 chokepoint (#2298 PR 3
// §3c). `denied` is the DEFAULT (see ToolSecurity's member initializer in
// mcp_server.cpp) — a tool gets `confined`/`global_safe` only by explicit
// registration, so an unclassified or newly-added row fails closed for a
// service-scoped caller automatically, the same fail-closed-by-omission
// posture #2383's kKnownMissingSecurity classification already gives every
// tool for tier/approval. A genuine `enum class` (not a string like
// securable_type/operation) because — unlike those, which are validated
// against an EXTERNAL catalogue (rbac_store.cpp's seeded types/ops, kRbacOps/
// kRbacSecurables in mcp_server.cpp) — this is a purely internal three-way
// classification with no external system to match strings against, so a
// typo is better caught at compile time than by a runtime closed-catalogue
// check. Mirrors `ToolSecurityClass`'s TU-private-enum-plus-testonly-mirror
// shape (`ToolClassForTest`, mcp_server_testonly.hpp) rather than the
// string-catalogue shape.
//   - `denied`: the C8 chokepoint refuses a service-scoped caller outright,
//     before tier/approval ever runs.
//   - `confined`: may REACH the handler — NOT a claim the tool is
//     functionally usable by a service-scoped caller. Under the seeded-empty
//     `kServiceScopeGlobalSafe` table most `confined` tools still hit their
//     OWN downstream perm_fn/scoped_perm_fn and get denied there too (e.g.
//     execute_instruction, mcp_server.cpp's own perm_fn call); confinement
//     via a real per-agent/service check (`confine_agent_target`-shaped) is
//     what makes a `confined` tool genuinely usable.
//   - `global_safe`: proceeds unconfined. Boot-validated: every `global_safe`
//     row's (securable_type, operation) pair must appear in
//     `authz::kServiceScopeGlobalSafe` (service_scope_policy.hpp, seeded
//     EMPTY) — a `global_safe` row with no matching policy-table entry is a
//     registration defect, refused at boot the same way an unregistered
//     tool is.
enum class ServiceScopeClass {
    denied,
    confined,
    global_safe,
};

// Standard MCP annotation classification (ADR-1005 track 2g PR 2, invariant A5
// item 1); the full rationale lives with the legacy kToolAnnotation table in
// mcp_server.cpp, which a registry record's `effect`/`idempotent`/`title`
// feed identically. `effect` is the tool's substantive domain side-effect, NOT
// its approval tier.
enum class ToolEffect { ReadOnly, Additive, Destructive };

// Shared remediation hint for tier/permission denials (governance Gate 4
// consistency, #1470). `remediation` is ALWAYS a server-controlled literal —
// raw-embedded into the error envelope like the correlation id; never pass
// caller-supplied text here without escaping.
inline constexpr std::string_view kTierRemediation =
    "this MCP token's tier does not permit the operation; use a higher-tier "
    "MCP token (operator or supervised), or the REST API / dashboard";

// The generic structured-output schema for a tool whose result is a JSON
// object of unspecified shape.
inline constexpr const char* kObjectOutputSchema = R"({"type":"object","additionalProperties":true})";

struct ToolCallContext;

// A registry tool's entry point. A plain function pointer, so a ToolRecord
// stays a literal type usable in a constexpr array.
using ToolHandler = void (*)(const ToolCallContext&);

/// Everything one tools/call handler may use. Built by the dispatch chain at the
/// lookup site, AFTER the generic gates have run; every reference outlives the
/// handler call.
struct ToolCallContext {
    // Same signature as McpServer::PermFn (mcp_server.hpp); spelled out here so
    // this header does not include the whole server header.
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type,
                                      const std::string& operation)>;
    // The per-request audit helper. Returns the AuditFn bool so a SOC 2 surface can
    // report a dropped evidence row (audit_persisted:false). Default arguments do
    // not survive the std::function binding: pass BOTH arguments, `detail` empty
    // when there is none.
    using AuditFn = std::function<bool(const std::string& result_status, const std::string& detail)>;
    // The per-request A4 error envelope builder (error.data carries a fresh
    // correlation id and ALWAYS emits "remediation": null when none is given).
    // Use this, never mcp_jsonrpc.hpp's error_response_a4, which omits the key.
    // Default arguments do not survive the binding: pass all six, `{}` for
    // remediation / cid_override, -1 for retry_after_ms (a non-negative value on
    // a TRANSIENT failure so an agentic worker backs off), true for audit_ok.
    using A4ErrorFn = std::function<std::string(int code, std::string_view message,
                                                std::string_view remediation, long retry_after_ms,
                                                std::string_view cid_override, bool audit_ok)>;
    // mcp_server.cpp's tool_result(): wraps a payload as an MCP tool result.
    // Pass the output schema explicitly (nullptr for none).
    using ToolResultFn = std::string (*)(std::string_view payload, const char* output_schema_json);

    const httplib::Request& req;
    httplib::Response& res;
    const nlohmann::json& id;   // JSON-RPC request id
    const nlohmann::json& args; // tools/call `arguments`
    const std::string& tier;    // session's MCP tier; the handler re-checks tier_allows
    const PermFn& perm_fn;
    const AuditFn& audit;
    const A4ErrorFn& a4_error;
    ToolResultFn tool_result;
};

/// One registry-resident tool. A literal type, so a domain file can hold its
/// records in a `constexpr ToolRecord kToolRecords[]`. Fields appear in this
/// order and are written positionally (no designated initialisers: the
/// lexical CI gates read the slice).
struct ToolRecord {
    const char* name;
    const char* description;
    const char* input_schema_json;  // pre-serialized JSON Schema
    const char* output_schema_json; // pre-serialized, or nullptr for none
    const char* securable;          // RBAC securable type, e.g. "Infrastructure"
    const char* operation;          // RBAC operation; anything but "Read" is a write tool
    ServiceScopeClass service_scope;
    ToolEffect effect;
    bool idempotent;
    const char* title;
    ToolHandler handler;
};

} // namespace yuzu::server::mcp
