#include "config_routes.hpp"

#include "http_route_sink.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "runtime_config_store.hpp"
#include "runtime_config_view.hpp" // build_overrides_json

#include <yuzu/server/server.hpp> // struct Config (forward-declared in the header)

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <charconv>
#include <chrono>
#include <string>
#include <system_error>

namespace yuzu::server::config {

void register_config_routes(HttpRouteSink& sink, Deps deps) {
    // -- Runtime Configuration API (7.3) ------------------------------------
    sink.Get("/api/config", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
            return;

        nlohmann::json config_obj;
        // Current effective values (from cfg_ + overrides)
        config_obj["heartbeat_timeout"] = deps.cfg->session_timeout.count();
        config_obj["response_retention_days"] = deps.cfg->response_retention_days;
        config_obj["audit_retention_days"] = deps.cfg->audit_retention_days;
        config_obj["guardian_event_retention_days"] = deps.cfg->guardian_event_retention_days;
        config_obj["auto_approve_enabled"] = !deps.auto_approve->list_rules().empty();
        config_obj["log_level"] =
            spdlog::level::to_string_view(spdlog::default_logger()->level()).data();

        // Overrides from store. The omission rule lives in
        // build_overrides_json (runtime_config_view.hpp) so it was independently
        // unit-testable even while this route was still inline (the route itself is
        // also TestRouteSink-registered since #2542 PR-12), and it is one of the
        // sites the secret leaked from twice.
        // A degraded store must NOT read as "nothing is configured". This route no
        // longer returns a secret's value, so the PRESENCE of the key and its
        // `is_set` are the only way to answer "is the OIDC secret set here?" -- and
        // security-hardening.md tells operators to answer exactly that before
        // deciding whether to rotate a disclosed credential. Returning 200 with an
        // empty `overrides` would answer "never set, nothing to rotate". The PUT twin
        // below already 503s on this condition; this matches it.
        if (!deps.runtime_config_store || !deps.runtime_config_store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"runtime config store unavailable"},)"
                R"("meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        auto overrides_result = deps.runtime_config_store->get_all();
        if (!overrides_result.has_value()) {
            spdlog::error("GET /api/config: read failed: {}", overrides_result.error());
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"runtime config store unavailable"},)"
                R"("meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        nlohmann::json overrides = build_overrides_json(*overrides_result);

        nlohmann::json allowed = nlohmann::json::array();
        for (const auto& k : RuntimeConfigStore::allowed_keys())
            allowed.push_back(k);

        res.set_content(
            nlohmann::json(
                {{"config", config_obj}, {"overrides", overrides}, {"allowed_keys", allowed}})
                .dump(),
            "application/json");
    });

    sink.Put(R"(/api/config/([a-z_]+))", [deps](const httplib::Request& req,
                                                httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Write"))
            return;
        if (!deps.runtime_config_store || !deps.runtime_config_store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"runtime config store unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto key = req.matches[1].str();
        std::string value;
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
                value = j["value"].is_string() ? j["value"].get<std::string>() : j["value"].dump();
            else {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"missing 'value' in request body"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
        } catch (...) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        // Validate integer-typed keys BEFORE persisting so a
        // non-numeric or negative value does not silently land
        // in RuntimeConfigStore while leaving cfg_ at the old
        // value (the prior `try { stoi } catch (...) {}` path
        // was a ghost-write: store persists, cfg ignores,
        // operator sees 200 with no effect). UP-R5 from the
        // Guardian PR 2 governance re-run.
        const bool is_int_key =
            key == "heartbeat_timeout" || key == "response_retention_days" ||
            key == "audit_retention_days" || key == "guardian_event_retention_days";
        int parsed_int = 0;
        if (is_int_key) {
            auto first = value.data();
            auto last = value.data() + value.size();
            auto [ptr, ec] = std::from_chars(first, last, parsed_int);
            if (ec != std::errc{} || ptr != last || parsed_int < 0) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"value must be a non-negative integer"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
        }

        // Get username from session
        auto session = deps.auth_fn(req, res);
        if (!session)
            return;

        auto result = deps.runtime_config_store->set(key, value, session->username);
        if (!result) {
            // A genuine DB/crypto failure (kRuntimeConfigDbErrorPrefix) is a
            // 503 with a generic message -- never echo the internal detail
            // to the caller; caller-input validation (unknown key, bad
            // value shape, the redaction-placeholder guard) is a 400 with
            // the store's own message, which is written for an operator.
            if (result.error().starts_with(kRuntimeConfigDbErrorPrefix)) {
                spdlog::error("PUT /api/config/{}: write failed: {}", key, result.error());
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"runtime config store unavailable"},)"
                    R"("meta":{"api_version":"v1"}})",
                    "application/json");
            } else {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                "application/json");
            }
            return;
        }

        // Apply the change to in-memory config. Integer keys
        // parsed above; direct assignment here means no
        // second `try { stoi }` that could swallow errors.
        if (key == "heartbeat_timeout") {
            deps.cfg->session_timeout = std::chrono::seconds(parsed_int);
        } else if (key == "response_retention_days") {
            deps.cfg->response_retention_days = parsed_int;
        } else if (key == "audit_retention_days") {
            deps.cfg->audit_retention_days = parsed_int;
        } else if (key == "guardian_event_retention_days") {
            deps.cfg->guardian_event_retention_days = parsed_int;
        }
        // log_level is applied inside RuntimeConfigStore::set()

        // NOT the raw value. An audit detail is durable, retained by policy, and
        // readable by every role seeded AuditLog:Read (Operator among them) -- so
        // writing a credential here is a worse sink than the log and the API this
        // branch already fixed, and it is not rotatable away afterwards.
        (void)deps.audit_fn(req, "config.update", "success", "RuntimeConfig", key,
                            "value=" + (RuntimeConfigStore::is_secret_key(key)
                                            ? std::string(RuntimeConfigStore::redacted_placeholder())
                                            : value));

        res.set_content(
            nlohmann::json(RuntimeConfigStore::is_secret_key(key)
                               ? nlohmann::json{{"key", key}, {"applied", true}}
                               : nlohmann::json{{"key", key}, {"value", value}, {"applied", true}})
                .dump(),
            "application/json");
    });
}

} // namespace yuzu::server::config
