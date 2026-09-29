#pragma once

// Test-only accessors for the internal MCP dispatch/classification tables.
//
// These expose copies of translation-unit-private tables defined in
// mcp_server.cpp (kToolSecurity / kToolAnnotation / kWriteTools / kTools) so
// the annotation cross-check test — a separate TU — can assert the served
// hints without duplicating the maps. Also exposes wrappers that run the REAL
// C8 dispatch classifier / registration validator (#2383) over synthetic
// tables, plus the validator's RBAC catalogue mirrors, so drift in any of
// them cannot silently regress while tests stay green. Relocated out of
// mcp_server.hpp (issue #2385) so the production header carries no test-only
// surface. Definitions live in mcp_server.cpp; only unit tests include this
// header.

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::mcp {

// Mirrors the internal `ServiceScopeClass` enum in mcp_server.cpp (#2298 PR 3
// §3c) — same lockstep-via-exhaustive-switch shape as `ToolClassForTest`
// below; the internal enum stays TU-private with the table it classifies.
enum class ServiceScopeClassForTest {
    kDenied,
    kConfined,
    kGlobalSafe,
};

// The (tool, securable, operation, service_scope) dispatch rows from the
// internal kToolSecurity map, so the annotation cross-check test can assert
// readOnlyHint/destructiveHint against the dispatch class without
// duplicating the map.
struct ToolSecurityRow {
    std::string_view name;
    std::string_view securable;
    std::string_view operation;
    ServiceScopeClassForTest service_scope;
};
std::vector<ToolSecurityRow> tool_security_rows_for_test();

// The names explicitly classified in the internal kToolAnnotation table, so the
// cross-check test can prove every tool is classified rather than relying on the
// generator's safe fallback.
std::vector<std::string_view> tool_annotation_names_for_test();

// The --mcp-read-only guard's write-tool set, so the cross-check test can bind it
// to the non-Read dispatch class (a mutating tool missing from kWriteTools would
// silently execute under read-only mode).
std::vector<std::string_view> write_tool_names_for_test();

// The served kTools[] names (#2383 — no accessor existed before; the earlier
// tests derived the served surface from a live tools/list call).
std::vector<std::string> tool_names_for_test();

// Three-way C8 dispatch classification (#2383) — mirrors the internal
// ToolSecurityClass enum in mcp_server.cpp (kept in lockstep by the wrapper's
// exhaustive switch; the enum itself stays TU-private with the tables it
// classifies).
enum class ToolClassForTest {
    kUnknown,               // → "Unknown tool" (kMethodNotFound)
    kKnownRegistered,       // → C7 / tier / approval as normal
    kKnownMissingSecurity,  // → deny fail-closed
};

// Runs the REAL dispatch classifier over synthetic tables, so the three-way
// split cannot silently regress while validator tests stay green. Owning
// strings, not views: synthetic inputs are built inline in the test and would
// dangle behind a view-based signature. Nothing is retained past the call.
ToolClassForTest classify_tool_for_test(const std::string& tool_name,
                                        const std::vector<std::string>& known_tools,
                                        const std::vector<std::string>& registered_tools);

// Owning-string (name, securable, operation, service_scope) row for
// synthetic validator input. `service_scope` defaults to `kDenied` so
// existing/#2383-only test call sites that build this struct without
// naming it keep working unchanged — matching production's `ToolSecurity`
// default member initializer.
struct ToolSecurityRowOwned {
    std::string name;
    std::string securable;
    std::string operation;
    ServiceScopeClassForTest service_scope = ServiceScopeClassForTest::kDenied;
};

// Owning-string (name, input_schema_json) row for the validator's 4th raw
// sequence (#2405) — synthetic input-schema sources.
struct ToolSchemaRowOwned {
    std::string name;
    std::string schema_json;
};

// Runs the REAL ctor registration validator over synthetic tables — throws
// std::runtime_error naming every offender, exactly as McpServer() does.
// `input_schemas` feeds the #2405 subset-compiler offence classes; pass {}
// to exercise only the #2383 table-parity checks.
void validate_tool_registration_for_test(const std::vector<std::string>& tool_names,
                                         const std::vector<ToolSecurityRowOwned>& security_rows,
                                         const std::vector<std::string>& write_tools,
                                         const std::vector<ToolSchemaRowOwned>& input_schemas);

// The served (name, input_schema_json) pairs from kTools[] (#2405), so the
// whole-table sweep test can compile every served schema and assert the
// required-⊆-properties lint without duplicating the table.
std::vector<ToolSchemaRowOwned> input_schemas_for_test();

// The validator's closed-catalogue mirrors of rbac_store.cpp's seeded `ops[]`
// and `types[]` (#2383 UP-6/C-3) — the [rbac_store] binding test compares
// these against a live store so the mirrors cannot drift silently.
std::vector<std::string> rbac_ops_for_test();
std::vector<std::string> rbac_securables_for_test();

} // namespace yuzu::server::mcp
