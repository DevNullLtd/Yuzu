#include "discover_routes.hpp"

#include "agent_registry.hpp"
#include "bundled_content.hpp"
#include "http_route_sink.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "openapi_spec_access.hpp"
#include "rest_a4_envelope_http.hpp"

#include <cstdint>
#include <cstdio>
#include <unordered_map>

namespace yuzu::server {

namespace {

using json = nlohmann::json;

// Parsed once, shared by plugin_docs_catalog() and the /discover/plugins join.
// A manifest that fails to parse is skipped and COUNTED — the catalog reports
// `skipped_invalid` so an embed defect is visible to the reader, never a
// silent gap — although embed_content.py already refuses to emit one, so the
// count is expected to stay 0.
DiscoveryDoc build_discovery_doc(json body); // forward decl: PluginDocsIndex below needs it
                                               // per-manifest, ahead of its definition at file scope.

struct PluginDocsIndex {
    std::vector<json> manifests; // embed order (name-sorted by the embedder)
    std::unordered_map<std::string, json> summary_by_name;
    // Per-plugin manifest, pre-serialised with its own content ETag — same
    // builder/idiom as the whole-catalog doc, so REST/MCP twins for
    // /discover/plugin-docs/{name} serve byte-identical bytes to the matching
    // plugins[] element (#4108).
    std::unordered_map<std::string, DiscoveryDoc> manifest_by_name;
    int skipped_invalid{0};
};

const PluginDocsIndex& plugin_docs_index() {
    static const PluginDocsIndex idx = [] {
        PluginDocsIndex out;
        for (const auto& text : kBundledPluginDocs) {
            auto m = json::parse(text, nullptr, /*allow_exceptions=*/false);
            // The generator always writes name, description, platforms and
            // readme; a manifest missing any of them is not one it produced, so
            // it is skipped and counted rather than repaired here (the path
            // rule has one home: plugin_doc_gen.py). Every key this index reads
            // is checked here — nlohmann's value() throws on a present key of
            // the wrong type, and a throw from this initialiser would 500
            // every surface built on this index (the whole-catalog and
            // per-plugin REST routes, the matching MCP resource and resource
            // template, and the discover_plugins join) on every request.
            const auto is_str = [&m](const char* key) {
                return m.contains(key) && m[key].is_string();
            };
            const auto is_obj = [&m](const char* key) {
                return m.contains(key) && m[key].is_object();
            };
            if (m.is_discarded() || !m.is_object() || !is_str("name") || !is_str("readme") ||
                !is_str("description") || !is_obj("platforms") || !is_obj("kind")) {
                ++out.skipped_invalid;
                spdlog::warn("discover/plugin-docs: skipping embedded manifest #{} ({}…): not a JSON "
                             "object with string name/description/readme and object platforms/kind",
                             out.manifests.size() + out.skipped_invalid, text.substr(0, 64));
                continue;
            }
            const std::string name = m["name"].get<std::string>();
            // The summary is what discover_plugins joins per plugin: enough for
            // an agentic caller to decide whether to read the full resource —
            // what it is, whether it mutates, where it runs, where the README is.
            // "resource" names the narrow per-plugin read path (#4108), not the
            // whole catalog, matching the summary's own stated purpose.
            json summary = {
                {"summary", m["description"]},
                {"kind", m["kind"]},
                {"platforms", m["platforms"]},
                {"readme", m["readme"]},
                {"resource", "yuzu://plugin-docs/" + name},
            };
            out.summary_by_name.emplace(name, std::move(summary));
            out.manifest_by_name.emplace(name, build_discovery_doc(m));
            out.manifests.push_back(std::move(m));
        }
        return out;
    }();
    return idx;
}

// FNV-1a 64-bit content hash -> a strong ETag, same idiom as
// guardian_schema_registry.cpp's content_etag (not shared directly — that
// helper is TU-local to a different file and the two catalogs have no other
// coupling reason to share a translation unit).
std::string content_etag(const std::string& body) {
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : body) {
        h ^= c;
        h *= 1099511628211ull;
    }
    char buf[19];
    int n = std::snprintf(buf, sizeof(buf), "\"%016llx\"", static_cast<unsigned long long>(h));
    return std::string(buf, static_cast<std::size_t>(n));
}

DiscoveryDoc build_discovery_doc(json body) {
    DiscoveryDoc doc;
    doc.json = body.dump();
    doc.etag = content_etag(doc.json);
    return doc;
}

// Serve `doc` through the standard ETag / Cache-Control / 304 contract
// (mirrors GET /api/v1/guaranteed-state/schemas, rest_api_v1.cpp).
/// Whether a discovery document is the SAME for every caller, or varies with the
/// caller's own authorization.
///
/// This distinction is a security control, not a performance tunable (#2376,
/// adversarial-review CDX-P2-002). A route whose body depends on the caller's
/// permissions serves two different representations under ONE URL. Marked
/// `public`, a shared/intermediary cache may store the privileged
/// representation and hand it to an unprivileged caller — which walks the
/// protected half straight across the authorization boundary that the
/// per-request permission probe just enforced. `private` forbids shared caches
/// from storing it at all; `Vary` additionally keeps a caller-local cache from
/// reusing one credential's response for another.
///
/// Getting this wrong is invisible in every unit test — the handler returns the
/// correct body to each caller, and the leak happens in an intermediary nobody
/// mocks. Choose deliberately when adding a discovery route: if ANY part of the
/// body is gated on the caller's grants, it is `PerCaller`.
enum class DocAudience {
    Everyone,  ///< identical for all callers — safe to share
    PerCaller, ///< varies with the caller's grants — never shareable
};

void serve_doc(const httplib::Request& req, httplib::Response& res, const DiscoveryDoc& doc,
               DocAudience audience) {
    res.set_header("ETag", doc.etag);
    if (audience == DocAudience::PerCaller) {
        res.set_header("Cache-Control", "private, max-age=300");
        // All THREE credential channels this server accepts must be named, or a
        // caller-local cache keyed on the named ones alone can serve caller A's
        // representation to caller B. `X-Yuzu-Token` was missing (Hermes pass 2):
        // two API-token callers send neither Cookie nor Authorization, so their
        // cache keys were identical. See auth_routes.cpp's credential resolution.
        res.set_header("Vary", "Authorization, Cookie, X-Yuzu-Token");
    } else {
        res.set_header("Cache-Control", "public, max-age=300");
    }
    if (req.get_header_value("If-None-Match") == doc.etag) {
        res.status = 304;
        return;
    }
    res.set_content(doc.json, "application/json");
}

} // namespace

// ── /discover/permissions ──────────────────────────────────────────────────

DiscoveryDoc build_permissions_catalog(RbacStore& rbac_store, bool include_roles) {
    // #2376: the catalogue is TWO things with different sensitivities, and the
    // split is the whole point of this parameter.
    //
    //   * the TAXONOMY (`securable_types`, `operations`) — a static list of what
    //     the RBAC model can express. Not authorization topology: it says nothing
    //     about who holds what, and an agentic worker needs it to author a grant
    //     at all (A2 discovery). Stays readable at the route's `Infrastructure:Read`.
    //
    //   * the ROLE GRID (`roles[].permissions[]`) — every role's actual granted
    //     securable/operation/effect. That IS the authorization topology the
    //     #2376 floor exists to protect, and it is strictly MORE than
    //     `GET /api/v1/rbac/roles` discloses, which the floor already gates on
    //     `UserManagement:Read`. Serving it here on the route's broader
    //     `Infrastructure:Read` made this an alternate transport around the
    //     floor: on an RBAC-off install (the default) the legacy fallback allows
    //     every `Read` to any authenticated session, so a plain `user` refused at
    //     /rbac/roles could read the entire grid here instead.
    //
    // Found by the adversarial-review panel (Codex) AFTER a 14-agent governance
    // run passed the change — that run verified coverage of the floored
    // SECURABLES and never asked which OTHER securable reaches the same DATA.
    // Do not re-merge these two halves under one gate.
    json body = {
        {"version", 1},
        {"description",
         "RBAC permission catalog: every securable_type x operation pair the RBAC "
         "store recognizes. The full role -> allowed-operations grid is included "
         "only for callers holding UserManagement:Read (#2376 authorization-topology "
         "floor). Agentic-first (A1/A2) discovery — docs/agentic-first-principle.md."},
        {"securable_types", rbac_store.list_securable_types()},
        {"operations", rbac_store.list_operations()},
    };

    if (include_roles) {
        json roles_arr = json::array();
        for (const auto& role : rbac_store.list_roles()) {
            json perms_arr = json::array();
            for (const auto& p : rbac_store.get_role_permissions(role.name)) {
                perms_arr.push_back({{"securable_type", p.securable_type},
                                     {"operation", p.operation},
                                     {"effect", p.effect}});
            }
            roles_arr.push_back({{"name", role.name},
                                 {"description", role.description},
                                 {"is_system", role.is_system},
                                 {"permissions", std::move(perms_arr)}});
        }
        body["roles"] = std::move(roles_arr);
    } else {
        // Say so EXPLICITLY rather than omitting silently. An agentic worker that
        // cannot tell "no roles exist" from "you may not see them" will report the
        // fleet has no RBAC roles — the same absent-vs-empty trap the upgrade note
        // warns evidence collectors about.
        body["roles_omitted"] = true;
        body["roles_omitted_reason"] =
            "requires UserManagement:Read (#2376 authorization-topology floor); "
            "the securable_types and operations taxonomy above is unaffected";
    }
    return build_discovery_doc(std::move(body));
}

// ── /discover/instructions ─────────────────────────────────────────────────

DiscoveryDoc build_instructions_catalog(InstructionStore& instruction_store) {
    InstructionQuery q;
    q.enabled_only = true; // "published" == invokable; a disabled definition with
                           // no visible flag would be the misleading option here.
    q.limit = 5000;        // generous ceiling for a catalog read, not a paged list.

    // ADR-0058: query_definitions now returns std::expected — a genuine DB error is
    // surfaced as a thrown exception, which the sole caller (discover_routes.cpp's
    // /api/v1/discover/instructions handler) already catches and turns into a 503
    // (discover_503), matching this file's established degrade idiom (see
    // build_plugins_catalog's identical pattern below).
    auto defs_result = instruction_store.query_definitions(q);
    if (!defs_result)
        throw std::runtime_error(defs_result.error());
    const auto& defs = *defs_result;

    json arr = json::array();
    for (const auto& d : defs) {
        // #2437-class guard: parameter_schema is stored VERBATIM at write
        // time (instruction_store.cpp import path) with no depth check
        // until this branch's own write-side guard shipped - a row written
        // before that, or via any other write path, still reaches this
        // read. nlohmann::json::parse handles very deep input fine, so
        // parsed.is_object() below would be true and the poisoned tree
        // would be moved into this array unnoticed; build_discovery_doc's
        // body.dump() further down is the unboundedly recursive call that
        // would then SIGSEGV the whole catalog response for every OTHER
        // definition too. Exclude the poisoned definition instead of
        // crashing the build; log its id, never its payload.
        if (mcp::json_exceeds_depth(d.parameter_schema, mcp::kMcpMaxJsonDepth)) {
            spdlog::warn("discover/instructions: excluding instruction definition {} - "
                         "parameter_schema nests too deeply (#2437-class)",
                         d.id);
            continue;
        }
        json param_schema; // null unless the stored value parses as a JSON object
        auto parsed = json::parse(d.parameter_schema, nullptr, /*allow_exceptions=*/false);
        // Attach only an OBJECT schema — a stored value that parses to
        // null/number/array/string is not a usable JSON Schema (UP-9), and
        // the #2986 typed outputSchema for this field advertises only
        // object/null (mcp_server.cpp). Mirrors discover_plugins below.
        if (!parsed.is_discarded() && parsed.is_object())
            param_schema = std::move(parsed);

        arr.push_back({
            {"id", d.id},
            {"name", d.name},
            {"plugin", d.plugin},
            {"action", d.action},
            {"description", d.description},
            {"parameter_schema", std::move(param_schema)},
            {"platforms", d.platforms},
            {"approval_mode", d.approval_mode},
        });
    }

    json body = {
        {"version", 1},
        {"description",
         "Published (enabled) InstructionDefinition catalog — the commands an "
         "agentic worker may dispatch via execute_instruction / "
         "POST /api/v1/instructions/execute. parameter_schema is a nested JSON "
         "Schema object when the stored value parses, else null."},
        {"count", arr.size()},
        {"truncated", defs.size() >= static_cast<std::size_t>(q.limit)},
        {"instructions", std::move(arr)},
    };
    return build_discovery_doc(std::move(body));
}

// ── /discover/routes ───────────────────────────────────────────────────────

DiscoveryDoc build_routes_catalog(const std::string& openapi_json) {
    static constexpr const char* kMethods[] = {"get", "post", "put", "delete", "patch", "options"};

    json routes_arr = json::array();
    auto spec = json::parse(openapi_json, nullptr, /*allow_exceptions=*/false);
    if (!spec.is_discarded() && spec.contains("paths") && spec["paths"].is_object()) {
        for (const auto& [path, ops] : spec["paths"].items()) {
            if (!ops.is_object())
                continue;
            for (const char* method : kMethods) {
                if (!ops.contains(method) || !ops[method].is_object())
                    continue;
                const auto& op = ops[method];
                json tags = op.value("tags", json::array());
                routes_arr.push_back({
                    {"method", std::string(method) == "get" ? "GET"
                              : std::string(method) == "post" ? "POST"
                              : std::string(method) == "put" ? "PUT"
                              : std::string(method) == "delete" ? "DELETE"
                              : std::string(method) == "patch" ? "PATCH"
                                                                : "OPTIONS"},
                    {"path", "/api/v1" + path},
                    {"summary", op.value("summary", "")},
                    {"tags", std::move(tags)},
                    {"description", op.value("description", "")},
                });
            }
        }
    }

    json body = {
        {"version", 1},
        {"source", "openapi"},
        {"description",
         "REST route catalog, subset of the SAME document GET /api/v1/openapi.json "
         "serves — the two can never disagree."},
        {"caveat",
         "This catalog is derived from the hand-maintained OpenAPI document, NOT "
         "generated from the live route table. A route that exists but was never "
         "documented in the OpenAPI spec will be under-reported here too. Per-route "
         "RBAC requirement is embedded in each entry's free-text 'description' "
         "(no structured field yet)."},
        {"count", routes_arr.size()},
        {"routes", std::move(routes_arr)},
    };
    return build_discovery_doc(std::move(body));
}

// ── /discover/scope-kinds ──────────────────────────────────────────────────

// Bind the catalog size to the enum's single-source count so adding a CompOp
// without a catalog entry is a portable BUILD failure (governance arch-SHOULD-4).
const std::array<CompOpEntry, yuzu::scope::kCompOpCount>& comp_op_catalog() {
    using yuzu::scope::CompOp;
    static const std::array<CompOpEntry, yuzu::scope::kCompOpCount> catalog = {{
        {CompOp::Eq, "Eq", "Case-insensitive equality."},
        {CompOp::Neq, "Neq", "Case-insensitive inequality."},
        {CompOp::Like, "Like", "SQL-style wildcard match (% and _)."},
        {CompOp::Lt, "Lt", "Numeric (falls back to string) less-than."},
        {CompOp::Gt, "Gt", "Numeric (falls back to string) greater-than."},
        {CompOp::Le, "Le", "Numeric (falls back to string) less-than-or-equal."},
        {CompOp::Ge, "Ge", "Numeric (falls back to string) greater-than-or-equal."},
        {CompOp::In, "In", "Value is one of a comma-separated list: `x IN (\"a\",\"b\")`."},
        {CompOp::Contains, "Contains", "Case-insensitive substring match."},
        {CompOp::Matches, "Matches",
         "RE2 regular-expression partial match (case-insensitive, ReDoS-safe, "
         "value capped at 256 chars)."},
        {CompOp::Exists, "Exists", "Unary — true iff the resolved attribute is non-empty."},
    }};
    return catalog;
}

const DiscoveryDoc& scope_kinds_catalog() {
    static const DiscoveryDoc doc = [] {
        json ground_kinds = json::array({
            {{"kind", "__all__"},
             {"syntax", "__all__"},
             {"example", "__all__"},
             {"description",
              "Every enrolled agent. Short-circuits per-device evaluation — never "
              "reaches the Scope Engine parser/resolver."}},
            {{"kind", "group:<name>"},
             {"syntax", "group:<name>"},
             {"example", "group:finance-laptops"},
             {"description",
              "Every device in the named management group. Short-circuits "
              "per-device evaluation, same as __all__."}},
        });

        json attribute_kinds = json::array();
        for (const auto& k : yuzu::server::detail::scope_kind_catalog()) {
            attribute_kinds.push_back({{"kind", k.kind},
                                       {"syntax", k.syntax},
                                       {"example", k.example},
                                       {"description", k.description}});
        }

        json operators = json::array();
        for (const auto& e : comp_op_catalog()) {
            operators.push_back({{"token", std::string(yuzu::scope::operator_token(e.op))},
                                 {"name", e.name},
                                 {"description", e.description}});
        }

        json extended_forms = json::array({
            {{"form", "EXISTS <attr>"},
             {"example", "EXISTS tag:department"},
             {"description",
              "Unary prefix form of the Exists operator (equivalent to `<attr> "
              "EXISTS`, listed for parser-grammar completeness)."}},
            {{"form", "LEN(<attr>) <op> <value>"},
             {"example", "LEN(hostname) > 5"},
             {"description",
              "Resolves <attr>, compares its string length using any of the base "
              "comparison operators (not a distinct CompOp — sugar over Eq/Neq/"
              "numeric compare)."}},
            {{"form", "STARTSWITH(<attr>, <value>)"},
             {"example", "STARTSWITH(hostname, \"WIN-\")"},
             {"description", "Case-insensitive prefix check on <attr>."}},
        });

        json body = {
            {"version", 1},
            {"description",
             "Scope DSL kinds and operators recognized by the Scope Engine "
             "(server/core/src/scope_engine.hpp) and the AgentRegistry::evaluate_scope "
             "resolver (server/core/src/agent_registry.cpp). See "
             "docs/scope-walking-design.md and docs/asset-tagging-guide.md."},
            {"ground_kinds", std::move(ground_kinds)},
            {"attribute_kinds", std::move(attribute_kinds)},
            {"operators", std::move(operators)},
            {"extended_forms", std::move(extended_forms)},
            {"combinators", json::array({"AND", "OR", "NOT"})},
        };
        return build_discovery_doc(std::move(body));
    }();
    return doc;
}

// ── /discover/plugins ───────────────────────────────────────────────────────

const DiscoveryDoc& plugin_docs_catalog() {
    static const DiscoveryDoc doc = [] {
        const auto& idx = plugin_docs_index();
        json body = {
            {"catalog", "plugin-docs"},
            {"version", 1},
            {"source", "build-embedded"},
            {"description",
             "Per-plugin documentation as data: one manifest per agent plugin that has "
             "adopted the README standard (docs/plugin-readme-standard.md), generated by "
             "tools/plugin-doc-gen from agents/plugins/<name>/README.md and embedded at build "
             "time. Each manifest carries how the plugin works, per-OS support/rung/mechanism "
             "per action, privileges, inputs, output columns with vocabularies, sample rows, "
             "caveats and source paths. Compiled-in content only — never fleet-derived. A "
             "plugin absent here has not adopted the standard yet; GET /discover/plugins "
             "reports docs:null for it. Same bytes as the MCP resource yuzu://plugin-docs."},
            {"plugin_count", idx.manifests.size()},
            {"skipped_invalid", idx.skipped_invalid},
            {"plugins", idx.manifests},
        };
        return build_discovery_doc(std::move(body));
    }();
    return doc;
}

const json* plugin_docs_summary(std::string_view plugin_name) {
    const auto& idx = plugin_docs_index();
    auto it = idx.summary_by_name.find(std::string{plugin_name});
    return it == idx.summary_by_name.end() ? nullptr : &it->second;
}

const DiscoveryDoc* plugin_docs_manifest(std::string_view plugin_name) {
    const auto& idx = plugin_docs_index();
    auto it = idx.manifest_by_name.find(std::string{plugin_name});
    return it == idx.manifest_by_name.end() ? nullptr : &it->second;
}

DiscoveryDoc build_plugins_catalog(const yuzu::server::detail::AgentRegistry& agent_registry,
                                   InstructionStore* instruction_store) {
    auto help = json::parse(agent_registry.help_json(), nullptr, /*allow_exceptions=*/false);
    bool help_ok = !help.is_discarded() && help.is_object();
    json plugins = help_ok ? help.value("plugins", json::array()) : json::array();
    json commands = help_ok ? help.value("commands", json::array()) : json::array();

    // Join published InstructionDefinitions by "pluginaction" so each action
    // that has one is enriched with its parameter_schema inline (the model learns
    // HOW to call an action, not just that it exists — the #1 anti-bumble fix).
    int enriched = 0;
    if (instruction_store) {
        std::unordered_map<std::string, json> schema_by_action;
        // Enrichment is BEST-EFFORT: a store read that throws (ADR-0058: a genuine
        // std::expected DB error is turned into a throw immediately below) degrades to
        // name+description only rather than failing the whole catalog, so the MCP tool
        // path — which has no route-level try/catch — cannot 500 on it (UP-6).
        try {
            InstructionQuery q;
            q.enabled_only = true;
            q.limit = 5000;
            // ADR-0058: query_definitions now returns std::expected; a genuine DB error
            // throws (caught immediately below), matching the pre-migration comment's
            // already-stated intent for this exact best-effort enrichment path.
            auto defs_result = instruction_store->query_definitions(q);
            if (!defs_result)
                throw std::runtime_error(defs_result.error());
            for (const auto& d : *defs_result) {
                if (d.plugin.empty() || d.action.empty())
                    continue;
                // #2437-class guard: same hazard as build_instructions_catalog
                // above - a too-deep stored parameter_schema would otherwise be
                // moved into schema_by_action below, spliced into an action's
                // entry further down, and crash on this catalog's own
                // build_discovery_doc dump(). Skip enrichment for just this
                // action rather than the whole catalog build; log the
                // definition id, never its payload.
                if (mcp::json_exceeds_depth(d.parameter_schema, mcp::kMcpMaxJsonDepth)) {
                    spdlog::warn("discover/plugins: excluding parameter_schema enrichment for "
                                "instruction definition {} - nests too deeply (#2437-class)",
                                d.id);
                    continue;
                }
                auto parsed = json::parse(d.parameter_schema, nullptr, /*allow_exceptions=*/false);
                // Attach only an OBJECT schema — a stored value that parses to
                // null/number/array/string is not a usable JSON Schema (UP-9).
                if (!parsed.is_discarded() && parsed.is_object())
                    schema_by_action.emplace(d.plugin + "\x01" + d.action, std::move(parsed));
            }
        } catch (const std::exception& ex) {
            spdlog::warn("discover/plugins: enrichment skipped — instruction read failed: {}",
                         ex.what());
            schema_by_action.clear();
        }
        if (plugins.is_array()) {
            for (auto& p : plugins) {
                if (!p.is_object() || !p.contains("actions") || !p["actions"].is_array())
                    continue;
                const std::string pname = p.value("name", "");
                for (auto& a : p["actions"]) {
                    if (!a.is_object())
                        continue;
                    auto it = schema_by_action.find(pname + "\x01" + a.value("name", ""));
                    if (it != schema_by_action.end()) {
                        a["parameter_schema"] = it->second;
                        ++enriched;
                    }
                }
            }
        }
    }

    // Documentation join (docs/plugin-readme-standard.md rule 10): every
    // observed plugin carries a build-embedded `docs` summary when a manifest
    // exists for it, else an explicit null — so a reader can tell "documented,
    // read yuzu://plugin-docs" from "not yet documented" without a second
    // request. Catalog version 3 (2 -> 3: the `docs` key).
    if (plugins.is_array()) {
        for (auto& p : plugins) {
            if (!p.is_object())
                continue;
            const auto* summary = plugin_docs_summary(p.value("name", ""));
            p["docs"] = summary ? *summary : json(nullptr);
        }
    }

    json body = {
        {"version", 3},
        {"description",
         "Plugin/action catalog observed across currently-connected agents "
         "(deduplicated by plugin name; the richest reported action list wins). "
         "NOT a build-time manifest — a plugin no currently-connected agent "
         "reports is absent from this list. To dispatch an action, call "
         "execute_instruction / POST /api/v1/instructions/execute with its "
         "plugin+action; supply the params from parameter_schema where present. "
         "Each plugin's docs field is a documentation summary {summary, kind, platforms, "
         "readme, resource} when the plugin has adopted the README standard, else "
         "null; resource names that plugin's own GET /discover/plugin-docs/<name> / "
         "yuzu://plugin-docs/<name> for the full manifest, or read the whole catalog "
         "at GET /discover/plugin-docs / yuzu://plugin-docs."},
        {"limitation",
         "An action carries an inline parameter_schema ONLY when it has a "
         "published InstructionDefinition (matched on plugin+action). Actions "
         "without one report name+description only — no per-action JSON Schema "
         "(agents report bare action names). GET /discover/instructions is the "
         "full schema-bearing catalog."},
        {"actions_enriched_with_schema", enriched},
        {"plugins", std::move(plugins)},
        {"commands", std::move(commands)},
    };
    return build_discovery_doc(std::move(body));
}

// ── Route registration ──────────────────────────────────────────────────────

namespace {

// A4-shaped 503 for the discovery surface. This surface exists to *teach* the
// A4 envelope to agentic workers, so its own degraded path must speak A4 (govern-
// ance: docs-writer BLOCKING + arch/unhappy/consistency SHOULD). a4_error mints
// the X-Correlation-Id header and derives the body `code` from res.status.
void discover_503(httplib::Response& res, std::string_view message) {
    res.status = 503;
    res.set_content(detail::a4_error(res, message,
                                     detail::A4ErrorOpts{.retry_after_ms = 5000,
                                                         .remediation = "retry after server "
                                                                        "warmup; the discovery "
                                                                        "store initialises "
                                                                        "during startup"}),
                    "application/json");
}

void register_on_sink(HttpRouteSink& sink, DiscoverRoutes::AuthFn auth_fn,
                      DiscoverRoutes::PermFn perm_fn, RbacStore* rbac_store,
                      InstructionStore* instruction_store,
                      yuzu::server::detail::AgentRegistry* agent_registry) {
    sink.Get("/api/v1/discover/permissions",
             [perm_fn, rbac_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!rbac_store || !rbac_store->is_open()) {
                     discover_503(res, "discovery store unavailable");
                     return;
                 }
                 // A corrupt/locked store row can throw mid-scan — a raw 500 would
                 // break the A4 contract this surface teaches (governance UP-11).
                 try {
                     // Probe for the grid permission with a throwaway response
                     // (the established idiom — see the quarantine per-record
                     // admit probe in rest_api_v1.cpp). A denial here must NOT
                     // 403 the route: the taxonomy is still served.
                     httplib::Response probe;
                     const bool include_roles =
                         perm_fn(req, probe, "UserManagement", "Read");
                     serve_doc(req, res,
                               build_permissions_catalog(*rbac_store, include_roles),
                               // PerCaller: the role grid is present only for a
                               // UserManagement:Read holder (see the probe above).
                               DocAudience::PerCaller);
                 } catch (const std::exception&) {
                     discover_503(res, "discovery store read failed");
                 }
             });

    sink.Get("/api/v1/discover/instructions",
             [perm_fn, instruction_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "InstructionDefinition", "Read"))
                     return;
                 if (!instruction_store || !instruction_store->is_open()) {
                     discover_503(res, "discovery store unavailable");
                     return;
                 }
                 try {
                     serve_doc(req, res, build_instructions_catalog(*instruction_store),
                               DocAudience::Everyone);
                 } catch (const std::exception&) {
                     discover_503(res, "discovery store read failed");
                 }
             });

    sink.Get("/api/v1/discover/routes",
             [perm_fn](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 // openapi_spec_json() is compiled-in — no store dependency, always
                 // answerable (matches the scope-kinds "answers even when everything
                 // else is down" property).
                 serve_doc(req, res, build_routes_catalog(openapi_spec_json()), DocAudience::Everyone);
             });

    sink.Get("/api/v1/discover/scope-kinds",
             [perm_fn](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 serve_doc(req, res, scope_kinds_catalog(), DocAudience::Everyone);
             });

    // Plugin README standard (docs/plugin-readme-standard.md rule 10): the
    // build-embedded per-plugin manifests. Static like scope-kinds — no store,
    // answers during warmup — and caller-independent, so publicly cacheable.
    sink.Get("/api/v1/discover/plugin-docs",
             [perm_fn](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 serve_doc(req, res, plugin_docs_catalog(), DocAudience::Everyone);
             });

    // Per-plugin narrow read (#4108): same manifest_by_name builder as the MCP
    // resource template yuzu://plugin-docs/{name}. Gate BEFORE the lookup so a
    // denied caller learns nothing about which plugin names exist.
    sink.Get(R"(/api/v1/discover/plugin-docs/([^/]+))",
             [perm_fn](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 const auto* doc = plugin_docs_manifest(req.matches[1].str());
                 if (!doc) {
                     res.status = 404;
                     res.set_content(detail::a4_error(res, "no documentation manifest for that plugin",
                                                       {.remediation = "GET /api/v1/discover/plugin-docs "
                                                                       "lists the documented plugins"}),
                                     "application/json");
                     return;
                 }
                 serve_doc(req, res, *doc, DocAudience::Everyone);
             });

    sink.Get("/api/v1/discover/plugins",
             [auth_fn, perm_fn, rbac_store, agent_registry,
              instruction_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!agent_registry) {
                     discover_503(res, "discovery store unavailable");
                     return;
                 }
                 // Least-privilege (gov Gate 2 security-guardian MEDIUM / UP-7):
                 // parameter_schema is InstructionDefinition:Read content (what
                 // /discover/instructions gates on). Enrich only when the caller
                 // also holds that grant — a soft, audit-free rbac check (throwaway
                 // Response absorbs any auth deny-write). Otherwise the nullptr
                 // path serves the name+description catalog. Mirrors the MCP tool.
                 InstructionStore* enrich = nullptr;
                 if (auth_fn && rbac_store && rbac_store->is_open()) {
                     httplib::Response probe;
                     if (auto sess = auth_fn(req, probe);
                         sess && rbac_store->check_permission(sess->username,
                                                              "InstructionDefinition", "Read"))
                         enrich = instruction_store;
                 }
                 try {
                     // PerCaller: `enrich` gates parameter_schema on the caller's
                     // InstructionDefinition:Read. That has varied per caller since the
                     // enrichment gate landed, so this route was publicly cacheable while
                     // permission-varying BEFORE #2376 — a pre-existing instance of the
                     // same class, fixed here because the fix is the shared helper.
                     serve_doc(req, res, build_plugins_catalog(*agent_registry, enrich),
                               DocAudience::PerCaller);
                 } catch (const std::exception&) {
                     discover_503(res, "discovery store read failed");
                 }
             });
}

} // namespace

void DiscoverRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                     RbacStore* rbac_store, InstructionStore* instruction_store,
                                     yuzu::server::detail::AgentRegistry* agent_registry) {
    HttplibRouteSink sink(svr);
    register_on_sink(sink, std::move(auth_fn), std::move(perm_fn), rbac_store, instruction_store,
                     agent_registry);
}

void DiscoverRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                     RbacStore* rbac_store, InstructionStore* instruction_store,
                                     yuzu::server::detail::AgentRegistry* agent_registry) {
    register_on_sink(sink, std::move(auth_fn), std::move(perm_fn), rbac_store, instruction_store,
                     agent_registry);
}

} // namespace yuzu::server
