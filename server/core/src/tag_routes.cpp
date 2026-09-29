#include "tag_routes.hpp"

#include "http_route_sink.hpp"
#include "json_extract.hpp"
#include "tag_store.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>

namespace yuzu::server::tag {

void register_tag_routes(HttpRouteSink& sink, Deps deps) {
    // -- Tags API ---------------------------------------------------------
    sink.Get("/api/tags", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Tag", "Read"))
            return;

        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"tag store not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto agent_id = req.get_param_value("agent_id");
        if (agent_id.empty()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"agent_id parameter required"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto tags = deps.store->get_all_tags(agent_id);
        if (!tags) {
            // Degrade → 503, never an empty list (#3097 classification).
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"tag store unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& t : *tags) {
            arr.push_back({{"key", t.key},
                           {"value", t.value},
                           {"source", t.source},
                           {"updated_at", t.updated_at}});
        }
        res.set_content(nlohmann::json({{"agent_id", agent_id}, {"tags", arr}}).dump(),
                        "application/json");
    });

    sink.Post("/api/tags/set", [deps](const httplib::Request& req, httplib::Response& res) {
        // CDX-R4-02: authenticate BEFORE any store/body work (401 first).
        if (!deps.auth_fn(req, res))
            return;
        if (!deps.store) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"tag store not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto agent_id = extract_json_string(req.body, "agent_id");
        auto key = extract_json_string(req.body, "key");
        auto value = extract_json_string(req.body, "value");

        if (agent_id.empty() || key.empty()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"agent_id and key required"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        if (!TagStore::validate_key(key)) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid tag key"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        // #3289 hardening-round follow-up: normalize category keys to
        // lowercase BEFORE anything downstream compares against them —
        // mirrors the REST v1 twin (rest_api_v1.cpp), which already did
        // this. Without it, a caller writing `key="Service"` (capital)
        // stored the tag under the wrong case and silently skipped the
        // `ensure_service_management_group` side effect below (a
        // case-sensitive literal comparison), even though it isn't a
        // security issue — the #3289 guard's own key check is already
        // case-insensitive regardless of this normalization. Uses
        // `kCategoryKeys` (the same constant the tag-push block 40 lines
        // below already reads) rather than a second hardcoded literal
        // list.
        {
            std::string lower_key = key;
            std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            for (auto cat_key : kCategoryKeys) {
                if (cat_key == lower_key) {
                    key = lower_key;
                    break;
                }
            }
        }

        // #3289: a service-scoped token authorizing this write via
        // require_scoped_permission below reads the PRE-WRITE `service`
        // tag to decide admission — so without this guard it could
        // authorize the very write that changes that tag out from under
        // its own confinement. Value-blind, checked before the scoped
        // gate. See deny_service_scoped_service_tag_mutation's doc
        // comment (auth_routes.hpp).
        if (deps.deny_service_scoped_tag_mutation_fn(req, res, "tag.set", agent_id, key))
            return;

        // K-04/CDX-R4-08: per-TARGET authorization -- NOT a global Tag:Write
        // gate. The old require_permission("Tag","Write") admitted a
        // service-scoped token on its ITServiceOwner grant with no target
        // check, so a service-A token could rewrite the `service` tag on a
        // service-B agent and escape its own #1788 dispatch confinement (and
        // it 403'd management-group-scoped operators). require_scoped_permission
        // enforces Tag:Write scoped to agent_id, the same gate the REST v1
        // twin (rest_api_v1.cpp) and MCP set_tag (mcp_server.cpp) use.
        if (!deps.scoped_perm_fn(req, res, "Tag", "Write", agent_id))
            return;

        // Surface the write result (#3097 classification): db_error →
        // 503, caller/validation error → 400 — a swallowed failed write
        // used to report "Tag updated" over nothing written.
        if (auto set_res = deps.store->set_tag(agent_id, key, value, "api"); !set_res) {
            const bool db_error = set_res.error().starts_with(kTagDbErrorPrefix);
            (void)deps.audit_fn(req, "tag.set", "failure", "tag", agent_id + ":" + key,
                                set_res.error());
            res.status = db_error ? 503 : 400;
            res.set_content(nlohmann::json{{"error",
                                            {{"code", res.status},
                                             {"message", db_error ? "tag store unavailable"
                                                                  : set_res.error()}}},
                                           {"meta", {{"api_version", "v1"}}}}
                                .dump(),
                            "application/json");
            return;
        }
        if (key == "service")
            deps.ensure_service_management_group_fn(value);
        // Push updated tags to agent if a structured category changed
        // Case-insensitive: API may receive "Role" but kCategoryKeys are lowercase
        {
            std::string lower_key = key;
            std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            for (auto cat_key : kCategoryKeys) {
                if (cat_key == lower_key) {
                    deps.push_asset_tags_to_agent_fn(agent_id);
                    break;
                }
            }
        }
        (void)deps.audit_fn(req, "tag.set", "success", "tag", agent_id + ":" + key, value);
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Tag updated","level":"success"}})");
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    sink.Post("/api/tags/delete", [deps](const httplib::Request& req, httplib::Response& res) {
        // CDX-R4-02: authenticate BEFORE any store/body work (401 first).
        if (!deps.auth_fn(req, res))
            return;
        if (!deps.store) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"tag store not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto agent_id = extract_json_string(req.body, "agent_id");
        auto key = extract_json_string(req.body, "key");

        if (agent_id.empty() || key.empty()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"agent_id and key required"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        // Gate 4/#3289 hardening round: normalize category keys to
        // lowercase, matching the /api/tags/set twin above — without
        // this, deleting a key by the same case a caller just set it
        // with (e.g. "Service") silently no-ops (TagStore::delete_tag
        // finds no row stored under that exact case) instead of removing
        // the tag, since /api/tags/set now stores the normalized form.
        {
            std::string lower_key = key;
            std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            for (auto cat_key : kCategoryKeys) {
                if (cat_key == lower_key) {
                    key = lower_key;
                    break;
                }
            }
        }

        // #3289: same TOCTOU guard as /api/tags/set — a service-scoped
        // token must not delete its own confinement key. See
        // deny_service_scoped_service_tag_mutation's doc comment.
        if (deps.deny_service_scoped_tag_mutation_fn(req, res, "tag.delete", agent_id, key))
            return;

        // K-04/CDX-R4-08: per-TARGET authorization (see /api/tags/set) --
        // a service-scoped token must not delete a tag on an out-of-scope
        // agent, and a group-scoped operator must be admitted on in-scope
        // targets. Same gate as the REST v1 twin and MCP delete_tag.
        if (!deps.scoped_perm_fn(req, res, "Tag", "Delete", agent_id))
            return;

        auto deleted = deps.store->delete_tag(agent_id, key);
        if (!deleted) {
            // Degrade → 503, never "not deleted" (#3097 classification;
            // the pre-migration bool conflated failure with not-found).
            (void)deps.audit_fn(req, "tag.delete", "failure", "tag", agent_id + ":" + key, "");
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"tag store unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        (void)deps.audit_fn(req, "tag.delete", *deleted ? "success" : "not_found", "tag",
                            agent_id + ":" + key, "");
        if (*deleted) {
            res.set_header("HX-Trigger",
                           R"({"showToast":{"message":"Tag deleted","level":"success"}})");
        }
        res.set_content(nlohmann::json({{"deleted", *deleted}}).dump(), "application/json");
    });

    sink.Post("/api/tags/query", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Tag", "Read"))
            return;
        if (!deps.store) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"tag store not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto key = extract_json_string(req.body, "key");
        auto value = extract_json_string(req.body, "value");

        if (key.empty()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"key required"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto agents = deps.store->agents_with_tag(key, value);
        if (!agents) {
            // Degrade → 503, never an empty agent list — this result
            // feeds operator targeting decisions (#3097 classification).
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"tag store unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& a : *agents)
            arr.push_back(a);
        res.set_content(nlohmann::json({{"agents", arr}, {"count", arr.size()}}).dump(),
                        "application/json");
    });
}

} // namespace yuzu::server::tag
