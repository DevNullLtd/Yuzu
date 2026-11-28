/// @file software_lifecycle_routes.cpp
/// See software_lifecycle_routes.hpp.

#include "software_lifecycle_routes.hpp"

#include "rest_a4_envelope_http.hpp"
#include "body_cap_policy.hpp"
#include "rest_audit.hpp"
#include "software_lifecycle_api.hpp"
#include "software_lifecycle_import.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <string_view>
#include <vector>

namespace yuzu::server {

namespace li = lifecycle_import;
namespace api = software_lifecycle_api;
using json = nlohmann::json;

namespace {

// The pre-routing body cap and the parser's own bound are one number (body_cap_policy.hpp row).
static_assert(resolve_body_cap("POST", "/api/v1/inventory/software/lifecycle/rules")
                      .max_body_bytes == li::kImportMaxBytes,
              "the software_lifecycle_rules body cap must equal lifecycle_import::kImportMaxBytes");

std::string ok_body(json data) {
    return json{{"data", std::move(data)}, {"meta", {{"api_version", "v1"}}}}.dump(
        -1, ' ', false, json::error_handler_t::replace);
}

void fail(httplib::Response& res, int status, std::string_view message,
          detail::A4ErrorOpts opts = {}) {
    res.status = status;
    res.set_content(detail::a4_error(res, message, opts), "application/json");
}

// Maps an API reply onto the response.
void respond(httplib::Response& res, const api::Reply& r) {
    switch (r.kind) {
    case api::Reply::Kind::Ok:
        res.set_content(ok_body(r.body), "application/json");
        return;
    case api::Reply::Kind::BadRequest:
        fail(res, 400, r.message);
        return;
    case api::Reply::Kind::Unavailable:
        fail(res, 503, r.message, {.retry_after_ms = r.retry_after_ms, .remediation = r.remediation});
        return;
    }
}

// A refusal row is plain; the rows of a mutation's own sequence flag a lost row on the response
// (Sec-Audit-Failed). Neither can undo what already happened.
api::AuditSink audit_for(const SoftwareLifecycleRoutes::Deps& deps, const httplib::Request& req,
                         httplib::Response& res) {
    return [&deps, &req, &res](const char* verb, const char* result, const std::string& target,
                               const std::string& detail_text, bool signal_failure) {
        return signal_failure
                   ? detail::emit_behavioral_audit(deps.audit_fn, req, res, verb, result,
                                                   api::kTargetType, target, detail_text)
                   : detail::try_persist_audit(deps.audit_fn, req, verb, result, api::kTargetType,
                                               target, detail_text);
    };
}

} // namespace

void SoftwareLifecycleRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    // The gates must be wired: an unwired gate fails closed, it never admits.
    const auto gates_wired = [deps](httplib::Response& res) {
        detail::ensure_correlation_id(res);
        if (!deps.perm_fn || !deps.audit_fn) {
            spdlog::error("SoftwareLifecycleRoutes: permission/audit gate unwired; failing closed");
            fail(res, 503, "service unavailable");
            return false;
        }
        return true;
    };

    // -- POST: import (replaces the whole imported set) -------------------------------------
    sink.Post("/api/v1/inventory/software/lifecycle/rules",
              [deps, gates_wired](const httplib::Request& req, httplib::Response& res) {
        if (!gates_wired(res))
            return;
        // The gate runs ahead of the body, the format and the name are looked at.
        if (!deps.perm_fn(req, res, "Inventory", "Write"))
            return;
        // The content type is not read. httplib folds an application/x-www-form-urlencoded body
        // into the request parameters, and the exactly-once counts below refuse a repeated
        // `name` or `format`: a missing or repeated one reaches the function as nullopt.
        const std::string name_raw =
            req.get_param_value_count("name") == 1 ? req.get_param_value("name") : std::string{};
        const std::string format_raw = req.get_param_value_count("format") == 1
                                           ? req.get_param_value("format")
                                           : std::string{};
        std::optional<std::string_view> name;
        if (req.get_param_value_count("name") == 1)
            name = name_raw;
        std::optional<std::string_view> format;
        if (req.get_param_value_count("format") == 1)
            format = format_raw;
        respond(res, api::import_rules(deps.store, name, format, req.body, audit_for(deps, req, res)));
    });

    // -- GET: list one source's rules -------------------------------------------------------
    sink.Get("/api/v1/inventory/software/lifecycle/rules",
             [deps, gates_wired](const httplib::Request& req, httplib::Response& res) {
        if (!gates_wired(res))
            return;
        if (!deps.perm_fn(req, res, "Inventory", "Read"))
            return;
        // A repeated `source` is passed as an empty token, which the function refuses.
        const std::string token = req.get_param_value_count("source") > 1 ? std::string{}
                                  : req.has_param("source") ? req.get_param_value("source")
                                                            : std::string{"imported"};
        respond(res, api::list_rules(deps.store, token, audit_for(deps, req, res)));
    });

    // -- DELETE: empty the imported set -----------------------------------------------------
    sink.Delete("/api/v1/inventory/software/lifecycle/rules",
                [deps, gates_wired](const httplib::Request& req, httplib::Response& res) {
        if (!gates_wired(res))
            return;
        if (!deps.perm_fn(req, res, "Inventory", "Write"))
            return;
        respond(res, api::delete_rules(deps.store, audit_for(deps, req, res)));
    });
}

} // namespace yuzu::server
