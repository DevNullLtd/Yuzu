/// @file software_collection_settings_routes.cpp
/// See software_collection_settings_routes.hpp. Each route is gate -> software_collection_settings_api
/// call -> HTTP mapping; the logic lives in software_collection_settings_api.cpp, shared with the
/// MCP twins.

#include "software_collection_settings_routes.hpp"

#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"
#include "software_collection_settings_api.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <string_view>

namespace yuzu::server {

namespace api = software_collection_settings_api;
using json = nlohmann::json;

namespace {

std::string ok_body(json data) {
    return json{{"data", std::move(data)}, {"meta", {{"api_version", "v1"}}}}.dump(
        -1, ' ', false, json::error_handler_t::replace);
}

void fail(httplib::Response& res, int status, std::string_view message,
          detail::A4ErrorOpts opts = {}) {
    res.status = status;
    res.set_content(detail::a4_error(res, message, opts), "application/json");
}

// Maps an API reply onto the response. Handled = the authority probe already wrote it.
void respond(httplib::Response& res, const api::Reply& r) {
    using Kind = api::Reply::Kind;
    switch (r.kind) {
    case Kind::Ok:
        res.set_content(ok_body(r.body), "application/json");
        return;
    case Kind::BadRequest:
        fail(res, 400, r.message);
        return;
    case Kind::Forbidden:
        fail(res, 403, r.message);
        return;
    case Kind::NotFound:
        fail(res, 404, r.message, {.remediation = r.remediation});
        return;
    case Kind::Unavailable:
        fail(res, 503, r.message, {.retry_after_ms = r.retry_after_ms, .remediation = r.remediation});
        return;
    case Kind::Conflict: {
        res.status = 409;
        auto body = json::parse(detail::a4_error(res, r.message, {.remediation = r.remediation}));
        body["error"]["current"] = r.body;
        res.set_content(body.dump(-1, ' ', false, json::error_handler_t::replace),
                        "application/json");
        return;
    }
    case Kind::Handled:
        return;
    }
}

// The ManagementGroup permission gate is the only authority (the global grant while RBAC
// enforcement is on, the legacy role rule while it is off): settings are managed by fleet
// administrators, and this build has no group-scoped delegation. `op` is "Read" or "Write". The
// unavailable-aware probe runs into a THROWAWAY response: a refusal is answered by the route with
// its own audited 403, and a 503 from it (the RBAC read could not be completed) or a 401 (no
// session) is copied to `res` and ends the request, so an outage is never read as a refusal or an
// admit, and a lapsed session is never recorded as withdrawn authority.
api::AuthorityFn authority_for(const SoftwareCollectionSettingsRoutes::Deps& deps,
                               const httplib::Request& req, httplib::Response& res) {
    return [&deps, &req, &res](const char* op) {
        httplib::Response probe; // throwaway
        if (deps.probe_perm_fn(req, probe, api::kGroupTargetType, op))
            return api::Authority::Admit;
        if (probe.status != 503 && probe.status != 401)
            return api::Authority::Deny;
        res.status = probe.status;
        res.body = probe.body;
        // Each probe header replaces the same-named one on `res` (`set_header` appends): the
        // probe minted its own correlation id and its body names it, so the response carries
        // exactly one.
        for (const auto& [k, v] : probe.headers)
            res.headers.erase(k);
        for (const auto& [k, v] : probe.headers)
            res.set_header(k, v);
        return probe.status == 401 ? api::Authority::Lapsed : api::Authority::Degraded;
    };
}

// A refusal row is plain; the rows of a mutation's own sequence flag a lost row on the response
// (Sec-Audit-Failed).
api::AuditSink audit_for(const SoftwareCollectionSettingsRoutes::Deps& deps,
                         const httplib::Request& req, httplib::Response& res) {
    return [&deps, &req, &res](const char* verb, const char* result, const std::string& target,
                               const std::string& detail_text, bool signal_failure) {
        return signal_failure
                   ? detail::emit_behavioral_audit(deps.audit_fn, req, res, verb, result,
                                                   api::kGroupTargetType, target, detail_text)
                   : detail::try_persist_audit(deps.audit_fn, req, verb, result,
                                               api::kGroupTargetType, target, detail_text);
    };
}

} // namespace

void SoftwareCollectionSettingsRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    const auto wired = [deps](httplib::Response& res, bool needs_mgmt) {
        detail::ensure_correlation_id(res);
        if (!deps.auth_fn || !deps.perm_fn || !deps.probe_perm_fn || !deps.scoped_perm_fn) {
            spdlog::error("SoftwareCollectionSettingsRoutes: gate unwired; failing closed");
            fail(res, 503, "service unavailable");
            return false;
        }
        if (!deps.store || (needs_mgmt && !deps.mgmt_store)) {
            fail(res, 503, "collection settings not available");
            return false;
        }
        return true;
    };
    const auto stores = [deps] {
        return api::Stores{deps.store, deps.mgmt_store, deps.plugin_config_store};
    };

    // -- GET list ---------------------------------------------------------------------------
    sink.Get("/api/v1/inventory/software/collection-settings",
             [deps, wired, stores](const httplib::Request& req, httplib::Response& res) {
                 if (!wired(res, true))
                     return;
                 if (!deps.perm_fn(req, res, api::kGroupTargetType, "Read"))
                     return;
                 respond(res, api::list(stores()));
             });

    // -- GET one group ----------------------------------------------------------------------
    sink.Get(R"(/api/v1/inventory/software/collection-settings/([a-f0-9]+))",
             [deps, wired, stores](const httplib::Request& req, httplib::Response& res) {
                 if (!wired(res, true))
                     return;
                 if (!deps.auth_fn(req, res))
                     return;
                 respond(res, api::get(stores(), req.matches[1].str(),
                                       authority_for(deps, req, res), audit_for(deps, req, res)));
             });

    // -- PUT one group ----------------------------------------------------------------------
    sink.Put(R"(/api/v1/inventory/software/collection-settings/([a-f0-9]+))",
             [deps, wired, stores](const httplib::Request& req, httplib::Response& res) {
                 if (!wired(res, true))
                     return;
                 const auto session = deps.auth_fn(req, res);
                 if (!session)
                     return;
                 respond(res, api::put(stores(), req.matches[1].str(), req.body, session->username,
                                       authority_for(deps, req, res), audit_for(deps, req, res)));
             });

    // -- GET effective settings of one device ----------------------------------------------
    sink.Get(
        R"(/api/v1/inventory/software/hosts/([A-Za-z0-9_.:-]{1,128})/collection-settings)",
        [deps, wired, stores](const httplib::Request& req, httplib::Response& res) {
            if (!wired(res, true))
                return;
            if (!deps.plugin_config_store) {
                fail(res, 503, "collection settings not available");
                return;
            }
            const std::string agent_id = req.matches[1].str();
            if (!deps.scoped_perm_fn(req, res, "Inventory", "Read", agent_id))
                return;
            respond(res, api::effective(stores(), agent_id));
        });
}

} // namespace yuzu::server
