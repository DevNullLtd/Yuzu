#include "nvd_routes.hpp"

#include "http_route_sink.hpp"
#include "nvd_db.hpp"
#include "nvd_sync.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::nvd {

void register_nvd_routes(HttpRouteSink& sink, Deps deps) {
    // -- NVD CVE feed endpoints -------------------------------------------

    sink.Get("/api/nvd/status",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!deps.nvd_db || !deps.nvd_db->is_open()) {
                     res.set_content(R"({"enabled":false})", "application/json");
                     return;
                 }
                 nlohmann::json j;
                 // "enabled" reflects whether the sync manager exists, not
                 // merely whether the DB file is open: under --no-nvd-sync the
                 // catalog DB is still open (for matching) but sync is off, so
                 // reporting enabled=true then 503-ing POST /api/nvd/sync was
                 // contradictory (#1889 review r2).
                 j["enabled"] = (deps.nvd_sync != nullptr);
                 j["total_cves"] = deps.nvd_db->total_cve_count();
                 if (deps.nvd_sync) {
                     auto st = deps.nvd_sync->status();
                     j["syncing"] = st.syncing;
                     j["last_sync_time"] = st.last_sync_time;
                     j["last_error"] = st.last_error;
                     j["backfill_complete"] = st.backfill_complete;
                     j["backfill_oldest_published"] = st.backfill_oldest_published;
                 }
                 res.set_content(j.dump(), "application/json");
             });

    sink.Post("/api/nvd/sync", [deps](const httplib::Request& req,
                                      httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Execute"))
            return;
        if (!deps.nvd_sync) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"NVD sync not enabled"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        // Ask the background loop to sync at its next wake and return at once.
        // (A detached thread here could outlive the manager and use-after-free
        // db_/fetcher_ during the hours-long backfill — governance BLOCKING.)
        deps.nvd_sync->request_sync();
        res.set_content(R"({"status":"sync_started"})", "application/json");
    });

    sink.Post("/api/nvd/match", [deps](const httplib::Request& req,
                                       httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
            return;
        if (!deps.nvd_db || !deps.nvd_db->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"NVD database not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        // Parse inventory: JSON body with an "inventory" array of {name, version}.
        std::vector<SoftwareItem> inventory;
        try {
            auto body = nlohmann::json::parse(req.body);
            if (body.contains("inventory") && body["inventory"].is_array()) {
                for (const auto& item : body["inventory"]) {
                    SoftwareItem si;
                    si.name = item.value("name", "");
                    si.version = item.value("version", "");
                    if (!si.name.empty())
                        inventory.push_back(std::move(si));
                }
            }
        } catch (...) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto matches = deps.nvd_db->match_inventory(inventory);
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& m : matches) {
            arr.push_back({{"cve_id", m.cve_id},
                           {"severity", m.severity},
                           {"description", m.description},
                           {"product", m.product},
                           {"installed_version", m.installed_version},
                           {"fixed_in", m.fixed_in},
                           {"source", m.source}});
        }
        res.set_content(nlohmann::json({{"findings", arr}, {"count", arr.size()}}).dump(),
                        "application/json");
    });
}

} // namespace yuzu::server::nvd
