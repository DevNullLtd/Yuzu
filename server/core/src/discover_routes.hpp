#pragma once

/// @file discover_routes.hpp
///
/// A2 discovery REST surface: `GET /api/v1/discover/*` (roadmap Issue 17.1,
/// docs/agentic-first-principle.md §A2). "Every MCP tool, REST route, plugin
/// action, scope kind, RBAC permission, and instruction definition is
/// enumerable through a documented, authenticated discovery endpoint. An
/// agentic worker should be able to learn what is possible from the live
/// server alone, without a side-channel doc fetch."
///
/// Seven endpoints, modeled on the existing discovery precedent
/// `GET /api/v1/guaranteed-state/schemas` (rest_api_v1.cpp) — same
/// ETag + `Cache-Control: public, max-age=300` + 304-revalidation contract:
///   - `/discover/permissions`         — RBAC securable_type x operation catalog + role grid
///   - `/discover/instructions`        — published InstructionDefinition subset
///   - `/discover/routes`              — subset of the OpenAPI document (honesty-flagged)
///   - `/discover/scope-kinds`         — Scope DSL kinds + operators (fully static)
///   - `/discover/plugins`             — plugin/action catalog observed across the fleet
///   - `/discover/plugin-docs`         — per-plugin documentation manifest catalog (fully static)
///   - `/discover/plugin-docs/{name}`  — one plugin's manifest, narrower (#4108, fully static)
///
/// NAMING NOTE: the obvious filename `discovery_routes.{hpp,cpp}` /
/// `DiscoveryRoutes` is already taken by an unrelated, pre-existing module
/// (`/api/directory/*`, `/api/patches/*`, `/api/deployments/*`,
/// `/api/discovery/*` — directory sync, patch management, deployment,
/// network-discovery). This module is named `discover_routes.hpp` /
/// `DiscoverRoutes` (singular, matching the `/api/v1/discover/*` URL prefix)
/// to avoid clobbering it.
///
/// The six builder functions (`build_*_catalog`) are pure — no I/O beyond
/// reading the store/registry pointer passed in — and are declared here
/// specifically so `mcp_server.cpp` can call the SAME functions for the
/// mirrored `discover_*` MCP tools (A2: "Each is mirrored as an MCP tool...
/// so the LLM-native flow does not require an out-of-band fetch"). REST and
/// MCP therefore cannot drift from each other by construction.

#include "instruction_store.hpp"
#include "rbac_store.hpp"
#include "scope_engine.hpp"

#include <yuzu/server/auth.hpp> // auth::Session for AuthFn (least-privilege enrichment gate)

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <array>
#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class HttpRouteSink; // http_route_sink.hpp — avoid pulling httplib-sink machinery
                     // into every TU that only wants the builder functions below.

namespace detail {
class AgentRegistry; // agent_registry.hpp — forward-declared, pointer-only here.
} // namespace detail

/// A built discovery response plus its content-derived ETag. Mirrors
/// guardian::SchemaCatalog (guardian_schema_registry.hpp) — same shape, same
/// FNV-1a content-hash idiom (build_discovery_doc in discover_routes.cpp) —
/// but not reused directly since that type lives in the `guardian` namespace
/// for a different catalog.
struct DiscoveryDoc {
    std::string json; ///< serialised JSON body
    std::string etag; ///< strong ETag, e.g. "\"<hex>\"" — changes iff `json` changes
};

// ── Shared builders (REST + MCP both call these) ──────────────────────────

/// `/discover/permissions`. Pass-through over RbacStore::list_securable_types /
/// list_operations, plus the full role -> permissions grid
/// (list_roles + get_role_permissions). `rbac_store` must be non-null;
/// callers null-check and answer 503 / a tool error before calling this.
/// #2376: `include_roles` gates the `roles[].permissions[]` grid (the
/// authorization topology) behind `UserManagement:Read`, while the
/// securable/operation taxonomy stays readable at the route's own
/// `Infrastructure:Read`. Callers PROBE for the second permission with a
/// throwaway response — they must not 403 the whole route.
DiscoveryDoc build_permissions_catalog(RbacStore& rbac_store, bool include_roles);

/// `/discover/instructions`. Subsets InstructionStore::query_definitions
/// (enabled_only=true — only invokable definitions are published) to
/// {id, name, plugin, action, description, parameter_schema, platforms,
/// approval_mode}. `parameter_schema` is parsed into a nested JSON Schema
/// object when the stored value is valid JSON AND is itself an object, else
/// emitted as `null` (an array/string/number/bool value is nulled out too).
/// `instruction_store` must be non-null.
DiscoveryDoc build_instructions_catalog(InstructionStore& instruction_store);

/// `/discover/routes`. Subsets the OpenAPI document
/// (`yuzu::server::openapi_spec_json()`, openapi_spec_access.hpp) to
/// {method, path, summary, tags, description} per operation. Carries
/// `"source":"openapi"` plus a caveat string: the OpenAPI document is
/// hand-maintained, not generated from the live route table, and can
/// under-report. `openapi_json` is the raw OpenAPI document body (caller
/// supplies it so this function has no direct dependency on rest_api_v1.*).
DiscoveryDoc build_routes_catalog(const std::string& openapi_json);

/// `/discover/scope-kinds`. Fully static — ground kinds (`__all__`,
/// `group:<name>`), attribute kinds (`yuzu::server::detail::scope_kind_catalog()`,
/// agent_registry.hpp), CompOp operators (`yuzu::scope::operator_token`,
/// scope_engine.hpp), and the EXISTS/LEN/STARTSWITH extended forms. Answers
/// even when every store is down, like guardian_schema_catalog(). Built once
/// (static local) and cached.
const DiscoveryDoc& scope_kinds_catalog();

/// `/discover/plugin-docs`. Fully static, like `scope_kinds_catalog()`: the
/// per-plugin documentation manifests `tools/plugin-doc-gen` generates from
/// each `agents/plugins/<name>/README.md` (docs/plugin-readme-standard.md
/// rule 10), embedded at build time as `kBundledPluginDocs`
/// (bundled_content.cpp) and served verbatim — compiled-in content only,
/// never fleet-derived: no live agent, telemetry or operator-supplied text
/// ever reaches this route at runtime (that's the property this route
/// controls). It is still human-authored README prose per plugin, reviewed
/// like any other source change, not literally hardcoded by the server
/// team — the compiled-in guarantee bounds WHERE the content can come from,
/// it is not a claim that the content is adversary-proof. One builder,
/// three surfaces: this REST route, the MCP resource
/// `yuzu://plugin-docs` (byte-identical), and the per-plugin `docs` summary
/// `build_plugins_catalog` joins into `/discover/plugins` / `discover_plugins`.
/// A manifest that fails to parse is skipped with a warning and counted in
/// `skipped_invalid` so the gap is visible rather than silent. Built once and
/// cached; answers even when every store is down.
const DiscoveryDoc& plugin_docs_catalog();

/// The per-plugin summary `build_plugins_catalog` joins by plugin name, or
/// `nullptr` when no manifest documents that plugin. Exposed for the join and
/// its tests; the full manifest is `plugin_docs_catalog()`.
const nlohmann::json* plugin_docs_summary(std::string_view plugin_name);

/// One plugin's manifest, pre-serialised with its own content ETag — the
/// exact element `plugin_docs_catalog()` carries at `plugins[]` for this
/// name, byte-identical after parse. Backs both `GET
/// /api/v1/discover/plugin-docs/{name}` and the MCP resource template
/// `yuzu://plugin-docs/{name}` (#4108) so the two transports cannot drift
/// from each other (A2's shared-builder principle). This accessor itself is
/// an exact-name lookup with no normalisation of its own — the two
/// TRANSPORTS differ upstream of it: httplib decodes the REST path segment
/// (`decode_path_component`) before routing, so `%5F` reaches here as `_`;
/// the MCP `resources/read` branch passes the `uri` tail through unchanged.
/// Immaterial in practice (generated plugin names are `[a-z0-9_]`), but a
/// caller comparing behaviour across both transports should know the two
/// answer differently for a percent-encoded name. `nullptr` when no
/// manifest documents that plugin.
const DiscoveryDoc* plugin_docs_manifest(std::string_view plugin_name);

/// One row per `yuzu::scope::CompOp` value, hand-maintained (C++ has no enum
/// reflection). Shared by `build_routes_catalog`'s scope-kinds sibling
/// (`scope_kinds_catalog`, which builds the "operators" array from this) AND
/// the CROSS-CHECK unit test (`test_discovery_routes.cpp`), which asserts
/// this array covers exactly the 11 currently-declared CompOp values. The
/// REAL drift guard is `yuzu::scope::operator_token`'s exhaustive switch
/// (no `default` — see scope_engine.hpp); this array only needs to stay the
/// same SIZE as that switch's case count, which the cross-check test enforces
/// via a hard-coded expected count that a reviewer bumps when CompOp grows.
struct CompOpEntry {
    yuzu::scope::CompOp op;
    const char* name;
    const char* description;
};
const std::array<CompOpEntry, 11>& comp_op_catalog();

/// `/discover/plugins`. Wraps `AgentRegistry::help_json()` (deduplicated
/// plugin/action metadata across currently-connected agents) with a
/// discovery envelope. When `instruction_store` is non-null, each action that
/// has a published InstructionDefinition (matched on plugin+action) is enriched
/// with its `parameter_schema` inline — so an agentic worker learns how to CALL
/// an action, not just that it exists, from one request. Actions with no
/// definition carry name+description only. `agent_registry` must be non-null.
DiscoveryDoc build_plugins_catalog(const yuzu::server::detail::AgentRegistry& agent_registry,
                                   InstructionStore* instruction_store = nullptr);

/// A2 discovery REST surface. See file header.
class DiscoverRoutes {
public:
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    /// Resolves the caller's session (no deny-write on the real response). Used
    /// ONLY to gate `/discover/plugins` parameter_schema enrichment on the
    /// caller's InstructionDefinition:Read grant (security-guardian MEDIUM) — a
    /// soft, audit-free check, so it takes a throwaway Response internally.
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;

    /// Production overload — wraps `svr` in an HttplibRouteSink and delegates.
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, RbacStore* rbac_store,
                         InstructionStore* instruction_store,
                         yuzu::server::detail::AgentRegistry* agent_registry);

    /// Testable overload — register against an in-process sink (no socket).
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, RbacStore* rbac_store,
                         InstructionStore* instruction_store,
                         yuzu::server::detail::AgentRegistry* agent_registry);
};

} // namespace yuzu::server
