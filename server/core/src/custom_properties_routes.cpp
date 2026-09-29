#include "custom_properties_routes.hpp"

#include "custom_properties_store.hpp"
#include "http_route_sink.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <string>

namespace yuzu::server::custom_properties {

namespace {

// CustomPropertiesStore error classifier — moved verbatim from server.cpp's
// anonymous namespace (#2542 PR-4): its only two call sites are the PUT
// property / POST schema handlers below, and it has no ServerImpl
// dependency. Keyed off the SHARED constant (custom_properties_store.hpp)
// rather than a local copy of the literal, so a future rename of the prefix
// can't silently regress a classified 503 back to 400 (gov Gate 8 finding,
// fjarvis re-review of PR #3065; the anonymous-namespace correction is a
// second Gate 8 finding on THIS fix — cpp-expert/architect/consistency-
// auditor independently, same round).
bool is_custom_properties_db_error(const std::string& err) {
    return err.starts_with(kCustomPropertiesDbErrorPrefix);
}

} // namespace

void register_custom_properties_routes(HttpRouteSink& sink, Deps deps) {
    // -- Custom Properties API (7.6) ----------------------------------------

    // GET /api/agents/:id/properties
    sink.Get(R"(/api/agents/([^/]+)/properties)", [deps](const httplib::Request& req,
                                                          httplib::Response& res) {
        auto agent_id = req.matches[1].str();
        // #3700: per-TARGET authorization -- NOT a global Infrastructure:Read
        // gate. The old require_permission("Infrastructure","Read") admitted
        // a global-permission holder with no target check, disclosing
        // custom-properties data for agents outside a management-group-
        // confined caller's scope (World A gap, ADR-0017). Same pattern as
        // the Tag routes' require_scoped_permission (see /api/tags/set).
        if (!deps.scoped_perm_fn(req, res, "Infrastructure", "Read", agent_id))
            return;
        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto props = deps.store->get_properties(agent_id);
        if (!props) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"custom properties store degraded"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& p : *props) {
            arr.push_back({{"key", p.key},
                           {"value", p.value},
                           {"type", p.type},
                           {"updated_at", p.updated_at}});
        }
        res.set_content(nlohmann::json({{"agent_id", agent_id}, {"properties", arr}}).dump(),
                        "application/json");
    });

    // PUT /api/agents/:id/properties/:key
    sink.Put(R"(/api/agents/([^/]+)/properties/([a-zA-Z0-9_.:-]+))",
             [deps](const httplib::Request& req, httplib::Response& res) {
        auto agent_id = req.matches[1].str();
        // #3700: per-TARGET authorization -- NOT a global Infrastructure:Write
        // gate. The old require_permission("Infrastructure","Write") admitted
        // any global-permission holder with no target check, letting a
        // caller mutate custom-properties data for any agent regardless of
        // their otherwise-confined visibility elsewhere (World A gap,
        // ADR-0017). Same pattern as the Tag routes' require_scoped_permission
        // (see /api/tags/set).
        if (!deps.scoped_perm_fn(req, res, "Infrastructure", "Write", agent_id))
            return;
        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto key = req.matches[2].str();

        std::string value;
        std::string type = "string";
        try {
            // #2437-class guard: raw-text depth check before parse - "value"
            // is dumped a few lines below (j["value"].dump() when it is not
            // a string), so the check has to run on the raw text before any
            // allocation.
            if (mcp::json_exceeds_depth(req.body, mcp::kMcpMaxJsonDepth)) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"request body nests too deeply"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            auto j = nlohmann::json::parse(req.body);
            if (j.contains("value"))
                value =
                    j["value"].is_string() ? j["value"].get<std::string>() : j["value"].dump();
            else {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"missing 'value' in request body"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            if (j.contains("type") && j["type"].is_string())
                type = j["type"].get<std::string>();
        } catch (...) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto result = deps.store->set_property(agent_id, key, value, type);
        if (!result) {
            deps.audit_fn(req, "custom_property.set", "failure", "Agent", agent_id,
                          key + ": " + result.error());
            if (is_custom_properties_db_error(result.error())) {
                spdlog::error("PUT /api/agents/{}/properties/{}: {}", agent_id, key,
                              result.error());
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            res.status = 400;
            res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                            "application/json");
            return;
        }

        deps.audit_fn(req, "custom_property.set", "success", "Agent", agent_id,
                      key + "=" + value);

        res.set_content(
            nlohmann::json(
                {{"agent_id", agent_id}, {"key", key}, {"value", value}, {"type", type}})
                .dump(),
            "application/json");
    });

    // DELETE /api/agents/:id/properties/:key
    sink.Delete(R"(/api/agents/([^/]+)/properties/([a-zA-Z0-9_.:-]+))",
                [deps](const httplib::Request& req, httplib::Response& res) {
        auto agent_id = req.matches[1].str();
        // #3700: per-TARGET authorization -- NOT a global Infrastructure:Write
        // gate. The old require_permission("Infrastructure","Write") admitted
        // any global-permission holder with no target check, letting a
        // caller delete custom-properties data for any agent regardless of
        // their otherwise-confined visibility elsewhere (World A gap,
        // ADR-0017). Same pattern as the Tag routes' require_scoped_permission
        // (see /api/tags/delete).
        if (!deps.scoped_perm_fn(req, res, "Infrastructure", "Write", agent_id))
            return;
        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto key = req.matches[2].str();

        bool deleted = deps.store->delete_property(agent_id, key);
        if (!deleted) {
            deps.audit_fn(req, "custom_property.delete", "not_found", "Agent", agent_id,
                          "key=" + key);
            res.status = 404;
            res.set_content(
                R"({"error":{"code":404,"message":"property not found"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        deps.audit_fn(req, "custom_property.delete", "success", "Agent", agent_id,
                      "key=" + key);

        res.set_content(nlohmann::json({{"deleted", true}, {"key", key}}).dump(),
                        "application/json");
    });

    // GET /api/property-schemas
    sink.Get("/api/property-schemas", [deps](const httplib::Request& req,
                                             httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
            return;
        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto schemas = deps.store->list_schemas();
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& s : schemas) {
            arr.push_back({{"key", s.key},
                           {"display_name", s.display_name},
                           {"type", s.type},
                           {"description", s.description},
                           {"validation_regex", s.validation_regex}});
        }
        res.set_content(nlohmann::json({{"schemas", arr}}).dump(), "application/json");
    });

    // POST /api/property-schemas
    sink.Post("/api/property-schemas", [deps](const httplib::Request& req,
                                              httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Write"))
            return;
        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        CustomPropertySchema schema;
        try {
            auto j = nlohmann::json::parse(req.body);
            schema.key = j.value("key", "");
            schema.display_name = j.value("display_name", "");
            schema.type = j.value("type", "string");
            schema.description = j.value("description", "");
            schema.validation_regex = j.value("validation_regex", "");
        } catch (...) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        if (schema.key.empty()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"'key' is required"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto result = deps.store->upsert_schema(schema);
        if (!result) {
            if (is_custom_properties_db_error(result.error())) {
                spdlog::error("POST /api/property-schemas: {}", result.error());
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            res.status = 400;
            res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                            "application/json");
            return;
        }

        // Original inline code called `audit_log(req, "property_schema.create",
        // "success", "PropertySchema", schema.key)` -- 5 args, relying on
        // that member's `detail = {}` default. `Deps::AuditFn` has no
        // defaults (it is a std::function, not the member it wraps), so the
        // empty detail is passed explicitly here -- same audit row, no
        // behaviour change.
        deps.audit_fn(req, "property_schema.create", "success", "PropertySchema", schema.key, "");

        res.status = 201;
        res.set_content(nlohmann::json({{"key", schema.key},
                                        {"display_name", schema.display_name},
                                        {"type", schema.type},
                                        {"description", schema.description},
                                        {"validation_regex", schema.validation_regex}})
                            .dump(),
                        "application/json");
    });
}

} // namespace yuzu::server::custom_properties
