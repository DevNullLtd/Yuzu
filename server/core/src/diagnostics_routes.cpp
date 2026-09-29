#include "diagnostics_routes.hpp"

#include "agent_registry.hpp"
#include "http_route_sink.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server::diagnostics {

void register_diagnostics_routes(HttpRouteSink& sink, Deps deps) {
    // -- Legacy API endpoints (still functional, delegate to generic path) --

    sink.Post("/api/chargen/start",
              [deps](const httplib::Request& req, httplib::Response& res) {
                  if (!deps.perm_fn(req, res, "Execution", "Execute"))
                      return;
                  deps.forward_legacy_command_fn(req, "chargen", "chargen_start", res);
              });

    sink.Post("/api/chargen/stop",
              [deps](const httplib::Request& req, httplib::Response& res) {
                  if (!deps.perm_fn(req, res, "Execution", "Execute"))
                      return;
                  deps.forward_legacy_command_fn(req, "chargen", "chargen_stop", res);
              });

    sink.Post("/api/procfetch/fetch",
              [deps](const httplib::Request& req, httplib::Response& res) {
                  if (!deps.perm_fn(req, res, "Execution", "Execute"))
                      return;
                  deps.forward_legacy_command_fn(req, "procfetch", "procfetch_fetch", res);
              });

    sink.Get(
        "/api/chargen/status", [deps](const httplib::Request& req, httplib::Response& res) {
            if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
                return;
            res.set_content(nlohmann::json({{"agent_connected", deps.registry->has_any()}}).dump(),
                            "application/json");
        });

    sink.Get(
        "/api/procfetch/status", [deps](const httplib::Request& req, httplib::Response& res) {
            if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
                return;
            res.set_content(nlohmann::json({{"agent_connected", deps.registry->has_any()}}).dump(),
                            "application/json");
        });
}

} // namespace yuzu::server::diagnostics
