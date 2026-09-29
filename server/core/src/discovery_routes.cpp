#include "discovery_routes.hpp"

#include "enrollment_directory_model.hpp" // #4031: shared row builders, REST/MCP parity (Rule 1)
#include "http_route_sink.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

// DeploymentStore error classifier — mirrors rest_api_v1.cpp's
// access_review_error_status (AccessReviewStore's `"not_found: "` idiom),
// inverted: here the MAJORITY of a route's `unexpected` values are
// caller-input validation or not-found/wrong-state business errors (400/404
// territory), so DeploymentStore prefixes the MINORITY — genuine DB/lease
// failures — with `kDeploymentDbErrorPrefix` rather than the other way
// around. Any error NOT carrying that prefix is a 400 here (adversarial-
// review MEDIUM hardening round, 2026-08-12 — the write routes previously
// collapsed every failure, including genuine outages, to 400). Keys off the
// SHARED constant (deployment_store.hpp), never a local copy of the literal
// — a future rename of the prefix in the store must not silently regress
// every classified 503 back to 400 (gov F3).
bool is_deployment_db_error(const std::string& err) {
    return err.starts_with(kDeploymentDbErrorPrefix);
}

} // namespace

void DiscoveryRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                      AuditFn audit_fn, DirectorySync* directory_sync,
                                      PatchManager* patch_manager,
                                      DeploymentStore* deployment_store,
                                      DiscoveryStore* discovery_store) {
    // Production adapter: wrap the httplib server in the route-sink seam and
    // delegate to the testable overload (mirrors DexRoutes/GuardianRoutes).
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    directory_sync, patch_manager, deployment_store, discovery_store);
}

void DiscoveryRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                      AuditFn audit_fn, DirectorySync* directory_sync,
                                      PatchManager* patch_manager,
                                      DeploymentStore* deployment_store,
                                      DiscoveryStore* discovery_store) {
    // ── Directory Sync API (Phase 7: AD/Entra integration) ──────────────

    // POST /api/directory/sync — trigger directory sync
    sink.Post("/api/directory/sync",
             [auth_fn, perm_fn, audit_fn, directory_sync](const httplib::Request& req,
                                                           httplib::Response& res) {
                 if (!perm_fn(req, res, "Directory", "Write"))
                     return;
                 if (!directory_sync || !directory_sync->is_open()) {
                     res.status = 503;
                     res.set_content(
                         R"({"error":{"code":503,"message":"directory sync not available"},"meta":{"api_version":"v1"}})",
                         "application/json");
                     return;
                 }

                 nlohmann::json body;
                 try {
                     body = nlohmann::json::parse(req.body);
                 } catch (const std::exception& e) {
                     res.status = 400;
                     res.set_content(nlohmann::json({{"error", e.what()}}).dump(),
                                     "application/json");
                     return;
                 }

                 auto provider = body.value("provider", "entra");

                 if (provider == "entra") {
                     EntraConfig ec;
                     ec.tenant_id = body.value("tenant_id", "");
                     ec.client_id = body.value("client_id", "");
                     ec.client_secret = body.value("client_secret", "");

                     if (ec.tenant_id.empty() || ec.client_id.empty() ||
                         ec.client_secret.empty()) {
                         res.status = 400;
                         res.set_content(
                             R"({"error":"tenant_id, client_id, and client_secret are required"})",
                             "application/json");
                         return;
                     }

                     auto result = directory_sync->sync_entra(ec);
                     if (!result) {
                         // ADR-1007: the re-entrancy guard's specific refusal
                         // is a distinguishable, typed condition — a
                         // concurrent sync in progress is not a server
                         // failure, and collapsing it into 500 both mis-tells
                         // the caller (retry-after-backoff is the correct
                         // response, not "something broke") and makes it
                         // indistinguishable from a real Graph/store error in
                         // any 5xx-based alerting.
                         if (result.error() == yuzu::server::kEntraSyncAlreadyInProgress) {
                             res.status = 409;
                             res.set_content(
                                 nlohmann::json({{"error", result.error()}}).dump(),
                                 "application/json");
                             auto session = auth_fn(req, res);
                             if (session)
                                 audit_fn(req, "directory.sync", "denied", "Directory", "entra",
                                          std::string(yuzu::server::kEntraSyncAlreadyInProgress));
                             return;
                         }
                         res.status = 500;
                         res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                         "application/json");
                         return;
                     }

                     auto session = auth_fn(req, res);
                     if (session)
                         audit_fn(req, "directory.sync", "success", "Directory", "entra",
                                  "Entra ID sync completed");

                     auto status = directory_sync->get_status();
                     res.set_content(nlohmann::json({{"status", "completed"},
                                                     {"provider", "entra"},
                                                     {"user_count", status.user_count},
                                                     {"group_count", status.group_count}})
                                        .dump(),
                                    "application/json");
                 } else if (provider == "ldap") {
                     LdapConfig lc;
                     lc.server = body.value("server", "");
                     lc.port = body.value("port", 389);
                     lc.base_dn = body.value("base_dn", "");
                     lc.bind_dn = body.value("bind_dn", "");
                     lc.bind_password = body.value("bind_password", "");
                     lc.use_ssl = body.value("use_ssl", false);

                     auto result = directory_sync->sync_ldap(lc);
                     if (!result) {
                         res.status = 501;
                         res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                         "application/json");
                         return;
                     }
                     res.set_content(R"({"status":"completed","provider":"ldap"})",
                                     "application/json");
                 } else {
                     res.status = 400;
                     res.set_content(
                         R"({"error":"unsupported provider; use 'entra' or 'ldap'"})",
                         "application/json");
                 }
             });

    // GET /api/directory/users — list synced users
    //
    // #4031: row shape now comes from the shared directory_user_row_json
    // builder (also called by the REST v1 twin GET /api/v1/directory/users
    // and the MCP tool list_directory_users) — Rule 1, no more independent
    // drift on this PII-bearing shape. Also closes a real pre-existing gap
    // the #4031 issue flagged: this route exposed email/UPN/group PII with
    // NO audit call at all. Uses the file's existing void-AuditFn
    // fire-and-forget convention (matches this file's directory.sync /
    // directory.group_mapping.update / discovery.scan calls) rather than
    // the newer bool/fail-closed rest_audit.hpp contract the REST v1 twin
    // uses — upgrading DiscoveryRoutes wholesale onto that contract is a
    // separate, broader modernization, not scoped to this PR.
    sink.Get("/api/directory/users",
            [perm_fn, audit_fn, directory_sync](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!perm_fn(req, res, "Directory", "Read"))
                    return;
                if (!directory_sync || !directory_sync->is_open()) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"directory sync not available"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }

                auto group_filter = req.get_param_value("group_id");
                auto users = directory_sync->get_synced_users(group_filter);

                audit_fn(req, "directory.users.view", "success", "Directory", group_filter,
                         "legacy directory users read");

                nlohmann::json arr = nlohmann::json::array();
                for (const auto& u : users)
                    arr.push_back(directory_user_row_json(u));

                res.set_content(nlohmann::json({{"users", arr},
                                                {"count", arr.size()}})
                                   .dump(),
                                "application/json");
            });

    // GET /api/directory/status — sync status
    //
    // #4031: shape now comes from directory_status_json (shared with the
    // REST v1 twin + MCP get_directory_status) — Rule 1. No PII (counts +
    // group metadata only), so no audit call, matching this route's
    // pre-existing unaudited posture and the REST v1 twin's same decision.
    // `mapped_role` is redacted for non-admin callers — see
    // directory_status_json's own doc comment.
    sink.Get("/api/directory/status",
            [auth_fn, perm_fn, directory_sync](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Directory", "Read"))
                    return;
                if (!directory_sync || !directory_sync->is_open()) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"directory sync not available"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }

                auto session = auth_fn(req, res);
                const bool reveal_mapped_role =
                    session && auth::effective_role(*session) == auth::Role::admin;
                auto status = directory_sync->get_status();
                auto groups = directory_sync->get_synced_groups();

                res.set_content(directory_status_json(status, groups, reveal_mapped_role).dump(),
                                "application/json");
            });

    // PUT /api/directory/group-mappings — configure group-to-role mappings
    sink.Put("/api/directory/group-mappings",
            [auth_fn, perm_fn, audit_fn, directory_sync](const httplib::Request& req,
                                                          httplib::Response& res) {
                if (!perm_fn(req, res, "Directory", "Write"))
                    return;
                if (!directory_sync || !directory_sync->is_open()) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"directory sync not available"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }

                nlohmann::json body;
                try {
                    body = nlohmann::json::parse(req.body);
                } catch (const std::exception& e) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", e.what()}}).dump(),
                                    "application/json");
                    return;
                }

                if (!body.contains("mappings") || !body["mappings"].is_array()) {
                    res.status = 400;
                    res.set_content(R"({"error":"'mappings' array required"})",
                                    "application/json");
                    return;
                }

                int count = 0;
                for (const auto& m : body["mappings"]) {
                    auto group_id = m.value("group_id", "");
                    auto role_name = m.value("role_name", "");
                    if (group_id.empty())
                        continue;

                    if (role_name.empty())
                        directory_sync->remove_group_role_mapping(group_id);
                    else
                        directory_sync->configure_group_role_mapping(group_id, role_name);
                    ++count;
                }

                auto session = auth_fn(req, res);
                if (session)
                    audit_fn(req, "directory.group_mapping.update", "success",
                             "Directory", "group-mappings",
                             std::to_string(count) + " mappings updated");

                auto mappings = directory_sync->get_group_role_mappings();
                nlohmann::json mappings_arr = nlohmann::json::array();
                for (const auto& [gid, role] : mappings) {
                    mappings_arr.push_back({{"group_id", gid}, {"role_name", role}});
                }

                res.set_content(nlohmann::json({{"mappings", mappings_arr},
                                                {"count", mappings_arr.size()}})
                                   .dump(),
                                "application/json");
            });

    // ── Patch Management API (Phase 7: Patch Deployment Workflow) ────────

    // GET /api/patches — list patches across fleet
    sink.Get("/api/patches",
            [perm_fn, patch_manager](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Patch", "Read"))
                    return;
                if (!patch_manager || !patch_manager->is_open()) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"patch manager not available"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }

                PatchQuery q;
                q.agent_id = req.get_param_value("agent_id");
                q.severity = req.get_param_value("severity");
                q.status = req.get_param_value("status");
                try {
                    auto limit_str = req.get_param_value("limit");
                    if (!limit_str.empty())
                        q.limit = std::stoi(limit_str);
                } catch (...) {
                }

                auto status_filter = q.status.empty() ? "missing" : q.status;
                std::vector<PatchInfo> patches;
                if (status_filter == "installed")
                    patches = patch_manager->get_installed_patches(q);
                else
                    patches = patch_manager->get_missing_patches(q);

                nlohmann::json arr = nlohmann::json::array();
                for (const auto& p : patches) {
                    arr.push_back({{"kb_id", p.kb_id},
                                   {"title", p.title},
                                   {"severity", p.severity},
                                   {"status", p.status},
                                   {"agent_id", p.agent_id},
                                   {"released_at", p.released_at},
                                   {"scanned_at", p.scanned_at}});
                }

                // Also include fleet summary
                auto summary = patch_manager->get_fleet_patch_summary(20);
                nlohmann::json summary_arr = nlohmann::json::array();
                for (const auto& [kb, cnt] : summary) {
                    summary_arr.push_back({{"kb_id", kb}, {"affected_agents", cnt}});
                }

                res.set_content(nlohmann::json({{"patches", arr},
                                                {"count", arr.size()},
                                                {"fleet_summary", summary_arr}})
                                   .dump(),
                                "application/json");
            });

    // POST /api/patches/deploy — deploy a patch to agents
    sink.Post("/api/patches/deploy",
             [auth_fn, perm_fn, audit_fn, patch_manager](const httplib::Request& req,
                                                          httplib::Response& res) {
                 if (!perm_fn(req, res, "Patch", "Write"))
                     return;
                 if (!patch_manager || !patch_manager->is_open()) {
                     res.status = 503;
                     res.set_content(
                         R"({"error":{"code":503,"message":"patch manager not available"},"meta":{"api_version":"v1"}})",
                         "application/json");
                     return;
                 }

                 nlohmann::json body;
                 try {
                     body = nlohmann::json::parse(req.body);
                 } catch (const std::exception& e) {
                     res.status = 400;
                     res.set_content(nlohmann::json({{"error", e.what()}}).dump(),
                                     "application/json");
                     return;
                 }

                 auto kb_id = body.value("kb_id", "");
                 if (kb_id.empty()) {
                     res.status = 400;
                     res.set_content(R"({"error":"kb_id is required"})", "application/json");
                     return;
                 }

                 std::vector<std::string> agent_ids;
                 if (body.contains("agent_ids") && body["agent_ids"].is_array()) {
                     for (const auto& a : body["agent_ids"])
                         if (a.is_string())
                             agent_ids.push_back(a.get<std::string>());
                 }

                 if (agent_ids.empty()) {
                     res.status = 400;
                     res.set_content(R"({"error":"at least one agent_id is required"})",
                                     "application/json");
                     return;
                 }

                 bool reboot = body.value("reboot_if_needed", false);
                 int reboot_delay = body.value("reboot_delay_seconds", 300);
                 int64_t reboot_at = body.value("reboot_at", static_cast<int64_t>(0));

                 // Validate reboot_delay range
                 reboot_delay = std::clamp(reboot_delay, 60, 86400);

                 // Validate reboot_at: must be 0 (disabled) or in the future
                 if (reboot_at != 0) {
                     auto now_ts = std::chrono::duration_cast<std::chrono::seconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();
                     if (reboot_at < now_ts) {
                         res.status = 400;
                         res.set_content(
                             R"({"error":{"code":400,"message":"reboot_at must be in the future or 0"},"meta":{"api_version":"v1"}})",
                             "application/json");
                         return;
                     }
                 }

                 std::string created_by = "unknown";
                 auto session = auth_fn(req, res);
                 if (session)
                     created_by = session->username;

                 auto depl_result = patch_manager->deploy_patch(
                     kb_id, agent_ids, reboot, created_by, reboot_delay, reboot_at);
                 if (!depl_result) {
                     res.status = 400;
                     res.set_content(nlohmann::json({{"error", depl_result.error()}}).dump(),
                                     "application/json");
                     audit_fn(req, "patch.deploy", "denied", "Patch", "", depl_result.error());
                     return;
                 }

                 audit_fn(req, "patch.deploy", "success", "Patch", *depl_result,
                          "Deployed " + kb_id + " to " +
                              std::to_string(agent_ids.size()) + " agents");

                 res.status = 201;
                 res.set_content(nlohmann::json({{"deployment_id", *depl_result},
                                                 {"kb_id", kb_id},
                                                 {"target_count", agent_ids.size()},
                                                 {"status", "pending"}})
                                    .dump(),
                                "application/json");
             });

    // GET /api/patches/deployments/:id — deployment status
    sink.Get(R"(/api/patches/deployments/([a-f0-9]+))",
            [perm_fn, patch_manager](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Patch", "Read"))
                    return;
                if (!patch_manager) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"patch manager not available"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }

                auto id = req.matches[1].str();
                auto depl = patch_manager->get_deployment(id);
                if (!depl) {
                    res.status = 404;
                    res.set_content(R"({"error":"deployment not found"})",
                                    "application/json");
                    return;
                }

                nlohmann::json targets_arr = nlohmann::json::array();
                for (const auto& t : depl->targets) {
                    targets_arr.push_back({{"agent_id", t.agent_id},
                                           {"status", t.status},
                                           {"error", t.error},
                                           {"started_at", t.started_at},
                                           {"completed_at", t.completed_at}});
                }

                res.set_content(
                    nlohmann::json({{"id", depl->id},
                                    {"kb_id", depl->kb_id},
                                    {"title", depl->title},
                                    {"status", depl->status},
                                    {"created_by", depl->created_by},
                                    {"reboot_if_needed", depl->reboot_if_needed},
                                    {"reboot_delay_seconds", depl->reboot_delay_seconds},
                                    {"reboot_at", depl->reboot_at},
                                    {"created_at", depl->created_at},
                                    {"completed_at", depl->completed_at},
                                    {"total_targets", depl->total_targets},
                                    {"completed_targets", depl->completed_targets},
                                    {"failed_targets", depl->failed_targets},
                                    {"targets", targets_arr}})
                        .dump(),
                    "application/json");
            });

    // GET /api/patches/deployments — list all deployments
    sink.Get("/api/patches/deployments",
            [perm_fn, patch_manager](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Patch", "Read"))
                    return;
                if (!patch_manager) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"patch manager not available"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }

                int limit = 50;
                try {
                    auto limit_str = req.get_param_value("limit");
                    if (!limit_str.empty())
                        limit = std::stoi(limit_str);
                } catch (...) {
                }

                auto deployments = patch_manager->list_deployments(limit);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& d : deployments) {
                    arr.push_back({{"id", d.id},
                                   {"kb_id", d.kb_id},
                                   {"title", d.title},
                                   {"status", d.status},
                                   {"created_by", d.created_by},
                                   {"created_at", d.created_at},
                                   {"completed_at", d.completed_at},
                                   {"total_targets", d.total_targets},
                                   {"completed_targets", d.completed_targets},
                                   {"failed_targets", d.failed_targets}});
                }

                res.set_content(nlohmann::json({{"deployments", arr},
                                                {"count", arr.size()}})
                                   .dump(),
                                "application/json");
            });

    // POST /api/patches/deployments/:id/cancel — cancel a deployment
    sink.Post(R"(/api/patches/deployments/([a-f0-9]+)/cancel)",
             [perm_fn, audit_fn, patch_manager](const httplib::Request& req,
                                                 httplib::Response& res) {
                 if (!perm_fn(req, res, "Patch", "Write"))
                     return;
                 if (!patch_manager) {
                     res.status = 503;
                     res.set_content(
                         R"({"error":{"code":503,"message":"patch manager not available"},"meta":{"api_version":"v1"}})",
                         "application/json");
                     return;
                 }

                 auto id = req.matches[1].str();
                 auto cancel_result = patch_manager->cancel_deployment(id);
                 if (!cancel_result) {
                     res.status = 400;
                     res.set_content(
                         nlohmann::json({{"error", cancel_result.error()}}).dump(),
                         "application/json");
                     return;
                 }

                 audit_fn(req, "patch.deployment.cancel", "success", "Patch", id,
                          "Deployment cancelled");

                 res.set_content(R"({"status":"cancelled"})", "application/json");
             });

    // ── Deployment Jobs API (Issue 7.7) ─────────────────────────────────

    // GET /api/deployment-jobs — list all deployment jobs
    sink.Get("/api/deployment-jobs",
            [perm_fn, deployment_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Infrastructure", "Read"))
                    return;
                if (!deployment_store) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }
                auto jobs = deployment_store->list_jobs();
                if (!jobs) {
                    spdlog::error("GET /api/deployment-jobs: {}", jobs.error());
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& j : *jobs) {
                    arr.push_back({{"id", j.id},
                                   {"target_host", j.target_host},
                                   {"os", j.os},
                                   {"method", j.method},
                                   {"status", j.status},
                                   {"created_at", j.created_at},
                                   {"started_at", j.started_at},
                                   {"completed_at", j.completed_at},
                                   {"error", j.error}});
                }
                res.set_content(nlohmann::json({{"jobs", arr}}).dump(),
                                "application/json");
            });

    // POST /api/deployment-jobs — create a new deployment job
    sink.Post("/api/deployment-jobs",
             [auth_fn, perm_fn, audit_fn, deployment_store](const httplib::Request& req,
                                                             httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Write"))
                     return;
                 if (!deployment_store) {
                     res.status = 503;
                     res.set_content(
                         R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                         "application/json");
                     return;
                 }
                 auto body = nlohmann::json::parse(req.body, nullptr, false);
                 if (body.is_discarded()) {
                     res.status = 400;
                     res.set_content(R"({"error":"invalid JSON"})", "application/json");
                     return;
                 }
                 auto target = body.value("target_host", "");
                 auto os = body.value("os", "linux");
                 auto method = body.value("method", "manual");
                 auto result = deployment_store->create_job(target, os, method);
                 if (!result) {
                     if (is_deployment_db_error(result.error())) {
                         spdlog::error("POST /api/deployment-jobs: {}", result.error());
                         res.status = 503;
                         res.set_content(
                             R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                             "application/json");
                         return;
                     }
                     res.status = 400;
                     res.set_content(
                         nlohmann::json({{"error", result.error()}}).dump(),
                         "application/json");
                     return;
                 }

                 // Generate install command for manual deployments
                 std::string install_cmd;
                 if (method == "manual") {
                     if (os == "windows") {
                         install_cmd = "powershell -Command \"Invoke-WebRequest "
                                       "-Uri 'https://yuzu-server/install.ps1' "
                                       "-OutFile install.ps1; .\\install.ps1\"";
                     } else {
                         install_cmd =
                             "curl -sSL https://yuzu-server/install.sh | sudo bash";
                     }
                 }

                 auto session = auth_fn(req, res);
                 if (session) {
                     audit_fn(req, "deployment.create", "success", "DeploymentJob",
                              *result, target);
                 }

                 res.status = 201;
                 nlohmann::json resp = {{"id", *result}, {"status", "pending"}};
                 if (!install_cmd.empty())
                     resp["install_command"] = install_cmd;
                 res.set_content(resp.dump(), "application/json");
             });

    // GET /api/deployment-jobs/:id — get job status
    sink.Get(R"(/api/deployment-jobs/([a-f0-9]+))",
            [perm_fn, deployment_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Infrastructure", "Read"))
                    return;
                if (!deployment_store) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }
                auto id = req.matches[1].str();
                auto job = deployment_store->get_job(id);
                if (!job) {
                    spdlog::error("GET /api/deployment-jobs/{}: {}", id, job.error());
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }
                if (!*job) {
                    res.status = 404;
                    res.set_content(R"({"error":"job not found"})", "application/json");
                    return;
                }
                res.set_content(
                    nlohmann::json({{"id", (*job)->id},
                                    {"target_host", (*job)->target_host},
                                    {"os", (*job)->os},
                                    {"method", (*job)->method},
                                    {"status", (*job)->status},
                                    {"created_at", (*job)->created_at},
                                    {"started_at", (*job)->started_at},
                                    {"completed_at", (*job)->completed_at},
                                    {"error", (*job)->error}})
                        .dump(),
                    "application/json");
            });

    // DELETE /api/deployment-jobs/:id — cancel a pending/running job
    sink.Delete(R"(/api/deployment-jobs/([a-f0-9]+))",
               [perm_fn, audit_fn, deployment_store](const httplib::Request& req,
                                                      httplib::Response& res) {
                   if (!perm_fn(req, res, "Infrastructure", "Write"))
                       return;
                   if (!deployment_store) {
                       res.status = 503;
                       res.set_content(
                           R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                           "application/json");
                       return;
                   }
                   auto id = req.matches[1].str();
                   auto result = deployment_store->cancel_job(id);
                   if (!result) {
                       if (is_deployment_db_error(result.error())) {
                           spdlog::error("DELETE /api/deployment-jobs/{}: {}", id, result.error());
                           res.status = 503;
                           res.set_content(
                               R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                               "application/json");
                           return;
                       }
                       res.status = 400;
                       res.set_content(
                           nlohmann::json({{"error", result.error()}}).dump(),
                           "application/json");
                       return;
                   }
                   audit_fn(req, "deployment.cancel", "success", "DeploymentJob", id, "");
                   res.set_content(R"({"status":"cancelled"})", "application/json");
               });

    // ── Discovery API (Issue 7.18) ──────────────────────────────────────

    // POST /api/discovery/scan — store discovery scan results from agents
    sink.Post("/api/discovery/scan",
             [perm_fn, audit_fn, discovery_store](const httplib::Request& req,
                                                   httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Write"))
                     return;
                 if (!discovery_store || !discovery_store->is_open()) {
                     res.status = 503;
                     res.set_content(
                         R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                         "application/json");
                     return;
                 }
                 auto body = nlohmann::json::parse(req.body, nullptr, false);
                 if (body.is_discarded()) {
                     res.status = 400;
                     res.set_content(R"({"error":"invalid JSON"})", "application/json");
                     return;
                 }

                 auto subnet = body.value("subnet", "");
                 auto discovered_by = body.value("discovered_by", "");
                 int upserted = 0;
                 int failed = 0;

                 if (body.contains("devices") && body["devices"].is_array()) {
                     for (const auto& dev : body["devices"]) {
                         DiscoveredDevice d;
                         d.ip_address = dev.value("ip_address", "");
                         d.mac_address = dev.value("mac_address", "");
                         d.hostname = dev.value("hostname", "");
                         d.discovered_by = discovered_by;
                         d.subnet = subnet;
                         if (!d.ip_address.empty()) {
                             auto r = discovery_store->upsert_device(d);
                             if (r)
                                 ++upserted;
                             else
                                 ++failed;
                         }
                     }
                 }

                 // gov fjarvis BLOCKING (PR #3064 re-review): a dropped
                 // upsert_device failure used to be invisible — the loop had
                 // no else branch, the audit row unconditionally said
                 // "success", and the response unconditionally said
                 // "status":"ok". Under the pre-migration SQLite store this
                 // was a rare local-disk error; under the shared Postgres
                 // pool it also fires on an ordinary acquire-timeout under
                 // load, so the trigger rate rose materially with this PR.
                 // Discovery inventory feeds rogue/unmanaged-device
                 // detection, so a scan that silently stored nothing must
                 // never be indistinguishable from one that stored
                 // everything. Mirrors the GET route's authoritative-store
                 // posture (ADR-0012 §1) and the established "partial" audit
                 // outcome this codebase already uses for the identical
                 // some-succeeded-some-failed shape (api_token.rotate,
                 // session.revoke_all, user.delete, sle.agent.decommission,
                 // scim identity-link resolution) — not
                 // BundleOrchestrator::dispatch's ok/no_agents/partial set,
                 // which is a Prometheus metric label, not an audit outcome.
                 const bool any_failed = failed > 0;
                 const bool total_failure = any_failed && upserted == 0;
                 const char* audit_outcome =
                     !any_failed ? "success" : (upserted > 0 ? "partial" : "failure");
                 audit_fn(req, "discovery.scan", audit_outcome, "Discovery", subnet,
                          std::to_string(upserted) + "/" + std::to_string(upserted + failed) +
                              " devices stored");

                 if (total_failure) {
                     res.status = 503;
                     res.set_content(
                         R"({"error":{"code":503,"message":"discovery scan storage degraded"},"meta":{"api_version":"v1"}})",
                         "application/json");
                     return;
                 }

                 res.status = 200;
                 res.set_content(
                     nlohmann::json({{"status", any_failed ? "partial" : "ok"},
                                     {"devices_stored", upserted},
                                     {"devices_failed", failed}})
                         .dump(),
                     "application/json");
             });

    // GET /api/discovery/results — list discovered devices
    sink.Get("/api/discovery/results",
            [perm_fn, discovery_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Infrastructure", "Read"))
                    return;
                if (!discovery_store || !discovery_store->is_open()) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }
                auto subnet = req.get_param_value("subnet");
                auto devices = discovery_store->list_devices(subnet);
                if (!devices) {
                    // Authoritative store (ADR-0012 §1): a query/pool failure
                    // must surface, never render as an empty fleet.
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"discovery read degraded"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& d : *devices) {
                    arr.push_back({{"id", d.id},
                                   {"ip_address", d.ip_address},
                                   {"mac_address", d.mac_address},
                                   {"hostname", d.hostname},
                                   {"managed", d.managed},
                                   {"agent_id", d.agent_id},
                                   {"discovered_by", d.discovered_by},
                                   {"discovered_at", d.discovered_at},
                                   {"last_seen", d.last_seen},
                                   {"subnet", d.subnet}});
                }
                res.set_content(
                    nlohmann::json({{"devices", arr},
                                    {"total", static_cast<int64_t>(devices->size())}})
                        .dump(),
                    "application/json");
            });
}

} // namespace yuzu::server
