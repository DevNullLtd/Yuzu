#pragma once

// Test-only accessors for the internal MCP dispatch/classification tables.
//
// These expose copies of the merged tool catalogue built in mcp_server.cpp
// (legacy kTools / kToolSecurityRows / kWriteToolsRaw / kToolAnnotation plus the
// registry records, see mcp_tool_registry.hpp) so the annotation cross-check
// test (a separate TU) can assert the served hints without duplicating the
// maps. Every accessor below returns the MERGED view, not just the legacy
// tables. Also exposes wrappers that run the REAL
// C8 dispatch classifier / registration validator (#2383) over synthetic
// tables, plus the validator's RBAC catalogue mirrors, so drift in any of
// them cannot silently regress while tests stay green. Relocated out of
// mcp_server.hpp (issue #2385) so the production header carries no test-only
// surface. Definitions live in mcp_server.cpp; only unit tests include this
// header.

#include "mcp_tool_registry.hpp"

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::mcp {

// Mirrors the `ServiceScopeClass` enum in mcp_tool_registry.hpp (#2298 PR 3
// §3c): same lockstep-via-exhaustive-switch shape as `ToolClassForTest` below.
// This header now includes the registry header, so the production enum is visible
// here; the mirror is kept so a test names the classification without depending
// on the production type, and the wrapper's exhaustive switch keeps the two in
// lockstep.
enum class ServiceScopeClassForTest {
    kDenied,
    kConfined,
    kGlobalSafe,
};

// The (tool, securable, operation, service_scope) dispatch rows from the
// merged security map, so the annotation cross-check test can assert
// readOnlyHint/destructiveHint against the dispatch class without
// duplicating the map.
struct ToolSecurityRow {
    std::string_view name;
    std::string_view securable;
    std::string_view operation;
    ServiceScopeClassForTest service_scope;
};
std::vector<ToolSecurityRow> tool_security_rows_for_test();

// The names explicitly classified in the merged annotation table, so the
// cross-check test can prove every tool is classified rather than relying on the
// generator's safe fallback.
std::vector<std::string_view> tool_annotation_names_for_test();

// The --mcp-read-only guard's write-tool set (legacy kWriteToolsRaw plus the
// registry records whose operation is not "Read"), so the cross-check test can
// bind it to the non-Read dispatch class (a mutating tool missing from it would
// silently execute under read-only mode).
std::vector<std::string_view> write_tool_names_for_test();

// The served tool names, in tools/list order: legacy kTools[] first, then the
// registry records (#2383: no accessor existed before; the earlier tests
// derived the served surface from a live tools/list call).
std::vector<std::string> tool_names_for_test();

// The names of the registry-resident tools only (mcp_tools_<domain>.cpp records),
// so the dispatch-coverage test can tell them apart from the legacy chain's tools.
std::vector<std::string> registry_tool_names_for_test();

// Builds the merged catalogue (legacy tables plus `records` in place of the real
// registry) and discards it. Throws std::logic_error, naming the record and the
// defect, when a record is malformed (see record_defect() in mcp_tool_registry.hpp);
// returns normally otherwise. Lets a test prove each boot rejection without a
// second, malformed domain file.
void build_catalogue_for_test(std::span<const ToolRecord> records);

// Runs the REAL registry-handler invocation (handler call plus the
// empty-response backstop) over a caller-built context, so a test can drive it
// with a stub handler that responds and one that forgets to.
void dispatch_registry_handler_for_test(ToolHandler handler, const ToolCallContext& ctx);

// The fixed kResources[] URIs that resources/list returns. Lets the API-parity
// ledger test check a `resource:<uri>` claim against the compiled catalogue
// without standing up the full JSON-RPC fixture. Resource templates
// (kResourceTemplates[]) are deliberately not included: the ledger contract
// names fixed resources only.
std::vector<std::string> resource_uris_for_test();

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

// Runs the REAL ctor registration validator over synthetic tables - throws
// std::runtime_error naming the offenders, exactly as McpServer() does (the
// message lists at most the first kMaxOffencesShown sorted offences, currently
// 25, plus "... and N more"; every offence is also logged individually).
// `input_schemas` feeds the #2405 subset-compiler offence classes; pass {}
// to exercise only the #2383 table-parity checks. `annotation_names` is the
// annotation table's key set for the #2422 equality check: nullptr (the
// default) maps to the validator's explicit kSkipAnnotationCheck, so the
// #2383-only synthetic tests keep working; a non-null pointer is held to exact
// equality with `tool_names`, so an EMPTY vector means "nothing is annotated"
// and every served tool is an offence.
void validate_tool_registration_for_test(
    const std::vector<std::string>& tool_names,
    const std::vector<ToolSecurityRowOwned>& security_rows,
    const std::vector<std::string>& write_tools,
    const std::vector<ToolSchemaRowOwned>& input_schemas,
    const std::vector<std::string>* annotation_names = nullptr);

// The served (name, input_schema_json) pairs, merged like tool_names_for_test (#2405), so the
// whole-table sweep test can compile every served schema and assert the
// required-⊆-properties lint without duplicating the table.
std::vector<ToolSchemaRowOwned> input_schemas_for_test();

// One tool's pre-expansion texts. Output schema is "" when the tool has none.
struct ToolTextRowOwned {
    std::string name;
    std::string description;
    std::string input_schema_json;
    std::string output_schema_json;
};

// The pre-expansion (name, description, input schema, output schema) texts of every served tool,
// kTools[] then the registry records, so the provenance test can prove each ecosystem enum is a
// generator token (the served copies are value-identical to a hand-typed table copy and cannot
// show it).
std::vector<ToolTextRowOwned> tool_templates_for_test();

// The validator's closed-catalogue mirrors of rbac_store.cpp's seeded `ops[]`
// and `types[]` (#2383 UP-6/C-3) — the [rbac_store] binding test compares
// these against a live store so the mirrors cannot drift silently.
std::vector<std::string> rbac_ops_for_test();
std::vector<std::string> rbac_securables_for_test();

} // namespace yuzu::server::mcp
