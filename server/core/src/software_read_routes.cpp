/// @file software_read_routes.cpp
/// See software_read_routes.hpp. Each route is gate -> software_read_api call -> HTTP mapping; the
/// read logic itself lives in software_read_api.cpp, shared with the MCP twins.

#include "software_read_routes.hpp"

#include "model_param_helpers.hpp"
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <string_view>
#include <utility>

namespace yuzu::server {

namespace api = software_read_api;
namespace swc = software_catalogue;
using json = nlohmann::json;

namespace {

constexpr const char* kVerbHosts = "inventory.software.hosts";
constexpr const char* kVerbHost = "inventory.software.host";
constexpr const char* kVerbChanges = "inventory.software.changes";
constexpr const char* kVerbSummary = "inventory.software.summary";
constexpr const char* kVerbPluginHealth = "inventory.software.plugin_health";
constexpr const char* kTargetType = "Inventory";

// What every handler captures: the gate, the audit sink and the API context.
struct Ctx {
    SoftwareReadRoutes::FleetReadFn fleet_read_fn;
    SoftwareReadRoutes::AuditFn audit_fn;
    api::Ctx api;
};

void fail(httplib::Response& res, int status, std::string_view message,
          detail::A4ErrorOpts opts = {}) {
    res.status = status;
    res.set_content(detail::a4_error(res, message, opts), "application/json");
}

// The sole gate. nullopt = the response is written. The gate runs first, so a denied caller never
// reaches a read and an unwired store is not visible to an unauthenticated one.
std::optional<authz::FleetReadGate> admit(const Ctx& c, const httplib::Request& req,
                                          httplib::Response& res, const std::string& cid,
                                          const char* verb) {
    if (!c.fleet_read_fn) {
        spdlog::error("{}: fleet_read_fn unwired - misconfigured call site; failing closed; cid={}",
                      verb, cid);
        fail(res, 503, "service unavailable");
        return std::nullopt;
    }
    // The SOLE authorization gate: renders 401/403/503 itself and returns !admitted.
    auto gate = c.fleet_read_fn(req, res, "Inventory", "Read");
    if (!gate.admitted)
        return std::nullopt;
    return gate;
}

// Audit through the throw-safe kernel: false = the row did not persist (the data is still served).
api::AuditSink sink_for(const Ctx& c, const httplib::Request& req, const char* verb) {
    return [&c, &req, verb](const std::string& result, const std::string& target,
                            const std::string& detail_text) {
        return detail::try_persist_audit(c.audit_fn, req, verb, result, kTargetType, target,
                                         detail_text);
    };
}

void respond(httplib::Response& res, const api::Reply& reply) {
    using Kind = api::Reply::Kind;
    switch (reply.kind) {
    case Kind::Ok:
        res.set_content(swc::dump_safe(json{{"data", reply.body}, {"meta", {{"api_version", "v1"}}}}),
                        "application/json");
        return;
    case Kind::BadRequest:
        fail(res, 400, reply.message);
        return;
    case Kind::NotFound:
        fail(res, 404, reply.message);
        return;
    case Kind::Unavailable:
        fail(res, 503, reply.message,
             {.retry_after_ms = reply.retry_after_ms, .remediation = reply.remediation});
        return;
    }
}

// One route: correlation id, the sole gate, then the shared function.
template <class Call>
auto handler(const std::shared_ptr<const Ctx>& ctx, const char* verb, Call call) {
    return [ctx, verb, call](const httplib::Request& req, httplib::Response& res) {
        const auto cid = detail::make_correlation_id();
        res.set_header("X-Correlation-Id", cid); // echo on every path (A3)
        const auto gate = admit(*ctx, req, res, cid, verb);
        if (!gate)
            return;
        respond(res, call(ctx->api, req, gate->scope, cid, sink_for(*ctx, req, verb)));
    };
}

} // namespace

void SoftwareReadRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    const auto ctx = std::make_shared<const Ctx>(Ctx{
        .fleet_read_fn = std::move(deps.fleet_read_fn),
        .audit_fn = std::move(deps.audit_fn),
        .api = api::make_ctx(std::move(deps.reads), std::move(deps.roster_fn),
                             std::move(deps.snapshot_fn), std::move(deps.now_fn), deps.store)});

    // GET /api/v1/inventory/software/hosts
    sink.Get("/api/v1/inventory/software/hosts",
             handler(ctx, kVerbHosts,
                     [](const api::Ctx& c, const httplib::Request& req, const authz::VisibleSet& scope,
                        const std::string& cid, const api::AuditSink& audit) {
                         return api::hosts(c, model_detail::to_params(req.params), scope, cid, audit);
                     }));

    // GET /api/v1/inventory/software/hosts/{agent_id}
    sink.Get(R"(/api/v1/inventory/software/hosts/([^/]+))",
             handler(ctx, kVerbHost,
                     [](const api::Ctx& c, const httplib::Request& req, const authz::VisibleSet& scope,
                        const std::string& cid, const api::AuditSink& audit) {
                         return api::host(c, req.matches[1].str(),
                                          model_detail::to_params(req.params), scope, cid, audit);
                     }));

    // GET /api/v1/inventory/software/changes
    sink.Get("/api/v1/inventory/software/changes",
             handler(ctx, kVerbChanges,
                     [](const api::Ctx& c, const httplib::Request& req, const authz::VisibleSet& scope,
                        const std::string& cid, const api::AuditSink& audit) {
                         return api::changes(c, model_detail::to_params(req.params), scope, cid,
                                             audit);
                     }));

    // GET /api/v1/inventory/software/summary
    sink.Get("/api/v1/inventory/software/summary",
             handler(ctx, kVerbSummary,
                     [](const api::Ctx& c, const httplib::Request&, const authz::VisibleSet& scope,
                        const std::string& cid, const api::AuditSink& audit) {
                         return api::summary(c, scope, cid, audit);
                     }));

    // GET /api/v1/inventory/software/plugin-health
    sink.Get("/api/v1/inventory/software/plugin-health",
             handler(ctx, kVerbPluginHealth,
                     [](const api::Ctx& c, const httplib::Request&, const authz::VisibleSet& scope,
                        const std::string& cid, const api::AuditSink& audit) {
                         return api::plugin_health(c, scope, cid, audit);
                     }));
}

} // namespace yuzu::server
