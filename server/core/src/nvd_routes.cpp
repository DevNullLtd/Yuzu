#include "nvd_routes.hpp"

#include "http_route_sink.hpp"
#include "nvd_db.hpp"
#include "nvd_sync.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error
#include "rest_audit.hpp" // detail::try_persist_audit, emit_behavioral_audit
#include "web_utils.hpp"  // html_escape

#include <nlohmann/json.hpp>

#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::nvd {

nlohmann::json status_json(const NvdDatabase* db, const NvdSyncManager* sync) {
    if (!db || !db->is_open())
        return nlohmann::json{{"enabled", false}};
    nlohmann::json j;
    // "enabled" reflects whether the sync manager exists, not merely whether the DB file is
    // open: under --no-nvd-sync the catalog DB is still open (for matching) but sync is off,
    // so reporting enabled=true then 503-ing POST /api/nvd/sync was contradictory (#1889 r2).
    j["enabled"] = (sync != nullptr);
    j["total_cves"] = db->total_cve_count();
    if (sync) {
        auto st = sync->status();
        j["syncing"] = st.syncing;
        j["last_sync_time"] = st.last_sync_time;
        j["last_error"] = st.last_error;
        j["backfill_complete"] = st.backfill_complete;
        j["backfill_oldest_published"] = st.backfill_oldest_published;
    }
    return j;
}

std::string render_nvd_status(const nlohmann::json& st) {
    constexpr std::size_t kErrorCap = 300;
    if (!st.value("enabled", false))
        return "<div class=\"gp-placeholder\" data-nvd=\"off\">NVD sync is off on this server.</div>";
    std::string h = "<dl class=\"kvl\" data-nvd=\"on\">";
    h += "<dt>CVE entries</dt><dd>" + std::to_string(st.value("total_cves", 0)) + "</dd>";
    const std::string last = st.value("last_sync_time", std::string{});
    h += "<dt>Last sync</dt><dd>" + html_escape(last.empty() ? std::string("Never") : last) +
         "</dd>";
    if (st.value("syncing", false))
        h += "<dt>Status</dt><dd>Sync in progress</dd>";
    h += std::string("<dt>Catalog build</dt><dd>") +
         (st.value("backfill_complete", false) ? "Complete" : "In progress") + "</dd>";
    std::string err = st.value("last_error", std::string{});
    if (!err.empty()) {
        if (err.size() > kErrorCap)
            err = err.substr(0, kErrorCap) + "...";
        h += "<dt>Last error</dt><dd data-nvd-error=\"1\">" + html_escape(err) + "</dd>";
    }
    h += "</dl>";
    return h;
}

void register_nvd_routes(HttpRouteSink& sink, Deps deps) {
    // -- NVD CVE feed endpoints -------------------------------------------

    sink.Get("/api/nvd/status",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 res.set_content(status_json(deps.nvd_db, deps.nvd_sync).dump(),
                                 "application/json");
             });

    // Status card for the Deployments page. Same gate and same JSON as /api/nvd/status.
    sink.Get("/fragments/auto/nvd", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
            return;
        res.set_header("Cache-Control", "no-store");
        res.set_content(render_nvd_status(status_json(deps.nvd_db, deps.nvd_sync)),
                        "text/html; charset=utf-8");
    });

    sink.Post("/api/nvd/sync", [deps](const httplib::Request& req,
                                      httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Execute"))
            return;
        if (!deps.nvd_sync) {
            // Audit the refused request too (outcome "disabled"); the 503 stands either way.
            (void)detail::try_persist_audit(deps.audit_fn, req, "nvd.sync.request", "disabled",
                                            "NvdSync", "nvd", "");
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"NVD sync not enabled"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        // A privileged outbound action: the request is recorded BEFORE it is made, and an
        // unrecorded request is refused (ADR-1005, mutations fail closed on audit failure).
        // Nothing has been started yet, so there is nothing to reconcile.
        // emit_behavioral_audit also sets `Sec-Audit-Failed: true`, which is how a client tells
        // "not recorded, so not started" from any other 503.
        if (!detail::emit_behavioral_audit(deps.audit_fn, req, res, "nvd.sync.request", "success",
                                           "NvdSync", "nvd", "")) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "audit unavailable; sync not requested",
                                             {.retry_after_ms = 5000,
                                              .remediation = "retry the request"}),
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
