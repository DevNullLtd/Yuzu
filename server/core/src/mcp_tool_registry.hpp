#pragma once

// MCP tool registry seam: the record shape and the handler context for tools
// that live in their own translation unit (mcp_tools_<domain>.cpp) instead of
// the legacy kTools[] + if/else chain in mcp_server.cpp.
//
// A ToolRecord is the UNION of the four rows a legacy tool spreads over
// mcp_server.cpp (ToolDef, ToolSecurity, ToolAnnotation, and the dispatch
// branch), so the tool's metadata and its entry point live in one record.
// Write-set membership is not a field: it is DERIVED (`operation != "Read"`),
// which is exactly the parity rule the boot validator enforces for the legacy
// tables. One thing is NOT in the record: whether a tool is approval-gated is
// decided by requires_approval() in mcp_policy.hpp from (tier, securable,
// operation), so a destructive twin still needs its row there.
//
// How a record reaches the server: each domain file exports an explicit
// accessor returning a std::span<const ToolRecord> over its constexpr array,
// and mcp_server.cpp's registered_tool_records() lists the spans in a fixed
// order. There is deliberately NO self-registration: yuzu_server_core_lib is a
// static library, and an unreferenced self-registering object is silently
// dropped by the linker.
//
// What is and is not guaranteed about a record:
//   * record_defect()/records_well_formed() below are the ONE well-formedness
//     rule. A domain file static_asserts it over its own array (compile time),
//     and mcp_server.cpp's build_catalogue() re-applies it at boot and THROWS on
//     a defect, because the catalogue is first built in the ServerImpl
//     constructor, before (and independently of) the boot validator.
//   * The boot validator (validate_tool_security_registration) then holds the
//     merged catalogue to the cross-table rules: duplicate names across legacy
//     and registry, RBAC securable/operation catalogue membership, the
//     global_safe policy-table backing, write-set parity and the #2405 input
//     schema compile.
//   * NOT guaranteed: that a domain accessor is listed in
//     registered_tool_records() (test_mcp_dispatch_coverage catches an unwired
//     file, and the compiled ledger test does so only where a ledger row names the
//     tool; the lexical CI gates read mcp_tools_*.cpp regardless of wiring and do
//     NOT catch it), that a handler repeats the record's
//     tier_allows/perm_fn pair correctly (the record drives the generic gates;
//     the handler states its own pair and must keep it in sync), or that the
//     handler validates its own arguments: the #2405 input-schema check runs
//     only for approval-gated tools, so a non-gated handler receives
//     UNVALIDATED ctx.args (any JSON value) and must check it itself.
//
// What the dispatch chain still does BEFORE a handler runs, unchanged:
// knownness, the C7 read-only guard, service-scope default-deny, tier,
// approval and, for approval-gated tools only, the #2405 input-schema check. A
// handler therefore only runs for a tool that has cleared the generic gates,
// and then performs its OWN perm_fn check (RBAC runs after the tier gate, never
// before it).
//
// The context carries the nine things every legacy branch reads and nothing
// else: no store pointers. A handler that needs one is a sign the tool belongs
// on the legacy path (or the context shape is wrong), not a reason to widen
// this struct. The context BORROWS request-frame objects (see ToolCallContext):
// a handler completes synchronously and never stores or captures it. The
// empty-response backstop in the dispatch chain likewise assumes a handler answers
// with res.set_content; a handler that streams or uses a content provider needs
// that guard reworked first (a PR2 context decision).

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cstddef>
#include <functional>
#include <span>
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
// check. The enum is header-visible (a registry ToolRecord carries it); its
// testonly mirror `ServiceScopeClassForTest` (mcp_server_testonly.hpp) keeps
// the exhaustive-switch lockstep that `ToolClassForTest` uses for
// `ToolSecurityClass`, rather than the string-catalogue shape.
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
inline constexpr const char* kObjectOutputSchema =
    R"({"type":"object","additionalProperties":true})";

struct ToolCallContext;

// A registry tool's entry point. A plain function pointer, so a ToolRecord
// stays a literal type usable in a constexpr array.
using ToolHandler = void (*)(const ToolCallContext&);

/// Everything one tools/call handler may use. Built by the dispatch chain at the
/// lookup site, AFTER the generic gates have run.
///
/// LIFETIME: the context BORROWS request-frame objects (the request, the response,
/// the JSON-RPC id and arguments, the tier string and the three per-request
/// callables all live in the enclosing tools/call lambda's frame). They outlive the
/// handler CALL and nothing longer, so a handler must complete synchronously and
/// must never capture, copy or store `ctx` or any member of it (no deferred work,
/// no SSE or timer callback, no thread). A tool that needs to outlive the request
/// does not belong on this path.
struct ToolCallContext {
    // Same signature as McpServer::PermFn (mcp_server.hpp); spelled out here so
    // this header does not include the whole server header.
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    // The per-request audit helper. Returns true when the audit row persisted and
    // false when it was dropped, so a SOC 2 surface can report a dropped evidence
    // row (audit_persisted:false). Default arguments do not survive the
    // std::function binding: pass BOTH arguments, `detail` empty when there is none.
    using AuditFn =
        std::function<bool(const std::string& result_status, const std::string& detail)>;
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
    const char* output_schema_json; // pre-serialized; required (A5: every new tool ships a typed
                                    // output schema)
    const char* securable;          // RBAC securable type, e.g. "Infrastructure"
    const char* operation;          // RBAC operation; anything but "Read" is a write tool
    ServiceScopeClass service_scope;
    ToolEffect effect;
    bool idempotent;
    const char* title;
    ToolHandler handler;
};

// Why `r` is not a well-formed registry record, or nullptr when it is. The ONE
// rule behind both the per-file static_assert in a domain file and the runtime
// check in mcp_server.cpp's build_catalogue(), so the two cannot drift. Checks run
// null-first so a later check never dereferences a null field.
//
// NAME GRAMMAR `^[a-z][a-z0-9_]*$`, non-empty: also enforced by both lexical CI
// gates (scripts/ci/check-api-parity.py, scripts/ci/check-mcp-retry-hints.py).
constexpr bool record_name_valid(const char* name) {
    if (name == nullptr || name[0] < 'a' || name[0] > 'z')
        return false;
    for (const char* c = name + 1; *c != '\0'; ++c)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '_'))
            return false;
    return true;
}

constexpr bool record_is_read(const char* operation) {
    return std::string_view{operation} == "Read";
}

constexpr const char* record_defect(const ToolRecord& r) {
    if (r.name == nullptr)
        return "null name";
    if (r.handler == nullptr)
        return "null handler";
    if (r.description == nullptr)
        return "null description";
    if (r.input_schema_json == nullptr)
        return "null input_schema_json";
    if (r.output_schema_json == nullptr)
        return "null output_schema_json";
    if (r.securable == nullptr)
        return "null securable";
    if (r.operation == nullptr)
        return "null operation";
    if (r.title == nullptr)
        return "null title";
    if (!record_name_valid(r.name))
        return "name does not match ^[a-z][a-z0-9_]*$";
    // The annotation's effect and the RBAC operation are two spellings of "does
    // this tool mutate"; the write set is derived from the operation, so a
    // disagreement would serve readOnlyHint=true for a write tool or vice versa.
    if (r.effect != ToolEffect::ReadOnly && record_is_read(r.operation))
        return "effect is not ReadOnly but operation is \"Read\"";
    if (r.effect == ToolEffect::ReadOnly && !record_is_read(r.operation))
        return "effect is ReadOnly but operation is not \"Read\"";
    return nullptr;
}

// True when every record is well formed and no two share a name. For a domain
// file's `static_assert(records_well_formed(kToolRecords), ...)`.
constexpr bool records_well_formed(std::span<const ToolRecord> records) {
    for (std::size_t i = 0; i < records.size(); ++i) {
        if (record_defect(records[i]) != nullptr)
            return false;
        for (std::size_t j = i + 1; j < records.size(); ++j)
            if (std::string_view{records[i].name} == std::string_view{records[j].name})
                return false;
    }
    return true;
}

// One accessor per domain file, each over that file's constexpr kToolRecords[].
// mcp_server.cpp's registered_tool_records() lists them in a fixed order; a new
// accessor must be added there too (an unlisted file serves nothing).
std::span<const ToolRecord> discovery_tool_records();

} // namespace yuzu::server::mcp
