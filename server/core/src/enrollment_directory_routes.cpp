#include "enrollment_directory_routes.hpp"

#include "enrollment_directory_model.hpp"
#include "http_route_sink.hpp"
#include "rest_a4_envelope.hpp"
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"

#include <yuzu/server/server.hpp> // Config

#include <nlohmann/json.hpp>

namespace yuzu::server {

namespace {

std::string ok_json(const nlohmann::json& data) {
    nlohmann::json body;
    body["data"] = data;
    body["meta"] = {{"api_version", "v1"}};
    return body.dump();
}

std::string list_json(const nlohmann::json& data_array, int64_t total, int64_t start = 0,
                      int64_t page_size = 50) {
    nlohmann::json body;
    body["data"] = data_array;
    body["pagination"] = {{"total", total}, {"start", start}, {"page_size", page_size}};
    body["meta"] = {{"api_version", "v1"}};
    return body.dump();
}

void respond_service_unavailable(httplib::Response& res, const char* what) {
    res.status = 503;
    res.set_content(detail::a4_error(res, std::string(what) + " unavailable"),
                    "application/json");
}

} // namespace

void EnrollmentDirectoryRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn,
                                                PermFn perm_fn, AuditFn audit_fn,
                                                DirectorySync* directory_sync,
                                                auth::AutoApproveEngine* auto_approve,
                                                auth::AuthManager* auth_mgr, Config* cfg,
                                                std::shared_mutex& oidc_mu,
                                                FleetReadFn fleet_read_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    directory_sync, auto_approve, auth_mgr, cfg, oidc_mu,
                    std::move(fleet_read_fn));
}

void EnrollmentDirectoryRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn,
                                                PermFn perm_fn, AuditFn audit_fn,
                                                DirectorySync* directory_sync,
                                                auth::AutoApproveEngine* auto_approve,
                                                auth::AuthManager* auth_mgr, Config* cfg,
                                                std::shared_mutex& oidc_mu,
                                                FleetReadFn fleet_read_fn) {
    // ── GET /api/v1/directory/users — Directory:Read ────────────────────
    // Genuinely PII (email/UPN/group membership) — REST fails CLOSED on an
    // audit-persist failure (docs/api-twin-recipe.md §4), matching the
    // dex.device.view/guardian.device.view precedent for behavioural-data
    // reads. This closes the real, pre-existing audit gap the #4031 issue
    // flags: the legacy GET /api/directory/users has never audited this
    // read despite exposing PII.
    sink.Get("/api/v1/directory/users", [perm_fn, audit_fn, directory_sync](
                                            const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "Directory", "Read"))
            return;
        if (!directory_sync || !directory_sync->is_open()) {
            respond_service_unavailable(res, "directory sync");
            return;
        }
        if (!detail::emit_behavioral_audit(audit_fn, req, res, "directory.users.view", "success",
                                           "Directory", req.get_param_value("group_id"),
                                           "REST v1 directory users read")) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "audit subsystem unavailable; refusing to serve directory "
                                      "user PII without durable evidence"),
                "application/json");
            return;
        }
        auto users = directory_sync->get_synced_users(req.get_param_value("group_id"));
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& u : users)
            arr.push_back(directory_user_row_json(u));
        res.set_content(list_json(arr, static_cast<int64_t>(arr.size())), "application/json");
    });

    // ── GET /api/v1/directory/status — Directory:Read ───────────────────
    // Provider/status/counts + group-role-mapping metadata — no per-person
    // PII, so no audit call (matches list_software_deployments' "metadata,
    // not behavioural PII" precedent in docs/api-twin-recipe.md §8).
    // `mapped_role` (the AD-group -> Yuzu-role authorization map, same data
    // class as the floored OidcConfig:admin_group) is redacted for non-admin
    // callers — see directory_status_json's own doc comment.
    sink.Get("/api/v1/directory/status",
            [auth_fn, perm_fn, directory_sync](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Directory", "Read"))
                    return;
                if (!directory_sync || !directory_sync->is_open()) {
                    respond_service_unavailable(res, "directory sync");
                    return;
                }
                auto session = auth_fn(req, res);
                const bool reveal_mapped_role =
                    session && auth::effective_role(*session) == auth::Role::admin;
                auto status = directory_sync->get_status();
                auto groups = directory_sync->get_synced_groups();
                res.set_content(
                    ok_json(directory_status_json(status, groups, reveal_mapped_role)),
                    "application/json");
            });

    // ── GET /api/v1/enrollment/auto-approve-rules — Enrollment:Read ─────
    // #520 decision: REST-only, no MCP twin — see file header. Audited
    // (non-blocking): the rule set is auto-enrollment BYPASS criteria, which
    // carries the same "an attacker learning this is reconnaissance" value
    // #4028 assigns to TLS/plugin-signing config reads — but it is
    // fleet-config, not per-person data, so the posture is plain
    // try_persist_audit (log, never fail-closed), matching
    // docs/api-twin-recipe.md §4's read-vs-behavioural-PII distinction.
    sink.Get("/api/v1/enrollment/auto-approve-rules",
            [perm_fn, audit_fn, auto_approve](const httplib::Request& req,
                                              httplib::Response& res) {
                if (!perm_fn(req, res, "Enrollment", "Read"))
                    return;
                if (!auto_approve) {
                    respond_service_unavailable(res, "auto-approve engine");
                    return;
                }
                (void)detail::try_persist_audit(audit_fn, req, "enrollment.auto_approve.view",
                                                "success", "Enrollment", "",
                                                "REST v1 auto-approve rules read");
                auto rules = auto_approve->list_rules();
                nlohmann::json arr = nlohmann::json::array();
                for (std::size_t i = 0; i < rules.size(); ++i)
                    arr.push_back(auto_approve_rule_row_json(rules[i], i));
                nlohmann::json data;
                data["rules"] = arr;
                data["require_all"] = auto_approve->require_all();
                res.set_content(ok_json(data), "application/json");
            });

    // ── GET /api/v1/enrollment/pending-agents — Enrollment:Read, ADR-0017 ──
    // #520 decision: REST-only, no MCP twin — see file header. Audited
    // (non-blocking): device-identity fingerprint data, "a lighter version
    // of the device_ci GDPR-personal-data-adjacent class" per the #4031
    // issue text — enough to warrant a log entry, not per-person PII in the
    // directory.users.view sense, so not fail-closed.
    //
    // CONFINEMENT (#4031 hardening round, adversarial review of the branch
    // before push):
    // this is the ONE route among the five in this file whose rows carry
    // genuine per-agent identity (`auth::PendingAgent::agent_id` +
    // hostname/os/arch/agent_version) — see this file's header comment.
    // `.claude/routed-concerns.md` row 1 (ADR-0017 "World A"): "Every new
    // list/fan-out read of per-agent data MUST use the admit-then-filter
    // authorize_list_read chokepoint — never a bare global
    // require_permission". Gates on `fleet_read_fn` (the transport-layer
    // seam for `AuthRoutes::require_fleet_read`) as its SOLE gate — never
    // stacked with `perm_fn` (pairing them makes the AdmitScoped branch
    // permanently unreachable, since `check_permission` never consults
    // `ManagementGroupStore`; see `authz_gates.hpp`'s falsifier).
    //
    // UNDER-ADMISSION, not disclosure: the defect the bare `perm_fn` gate
    // had was NOT a fleet-wide leak to a scoped caller — `check_permission`
    // resolves only global/direct-role grants (`RbacStore::collect_roles`),
    // so a caller holding ONLY a management-group-scoped `Enrollment:Read`
    // grant was 403'd outright, never shown anyone's data. The bug was that
    // the scoped-grant feature the product's own docs (docs/user-manual/
    // rbac.md) instruct operators to use was silently inert for this route.
    // Under the intended enrollment workflow a pending (not-yet-approved)
    // agent holds no management-group membership yet — group assignment
    // follows approval, not the reverse — so the correct confined answer
    // for a scoped-only grant is typically an ADMITTED, EMPTY 200, not a
    // 403 that masks a working RBAC grant as a permission error. That is
    // NOT enforced by the data model: `management_group_members.agent_id`
    // carries no enrollment/agent-registry foreign key, and
    // `POST /api/v1/management-groups/{id}/members` accepts any non-empty
    // caller-supplied id with no existence check (management_group_store.cpp,
    // rest_api_v1.cpp), so an admin who pre-assigns a not-yet-approved
    // agent's id to a group produces a non-empty, correctly-confined result
    // via the same `authz::in_scope` filter below — never a widening either
    // way.
    sink.Get("/api/v1/enrollment/pending-agents",
            [fleet_read_fn, audit_fn, auth_mgr](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!fleet_read_fn) {
                    respond_service_unavailable(res, "fleet-read authorization gate");
                    return;
                }
                // require_fleet_read renders 401/403/503 itself and returns
                // !admitted on denial — see the comment above this route and
                // authz_gates.hpp's own doc comment for why this must stay
                // the sole gate.
                auto gate = fleet_read_fn(req, res, "Enrollment", "Read");
                if (!gate.admitted)
                    return;
                if (!auth_mgr) {
                    respond_service_unavailable(res, "auth manager");
                    return;
                }
                (void)detail::try_persist_audit(audit_fn, req, "enrollment.pending_agents.view",
                                                "success", "Enrollment", "",
                                                "REST v1 pending-agents read");
                auto agents = auth_mgr->list_pending_agents();
                // Filter out already-approved agents — they don't need admin
                // attention, matching SettingsRoutes::render_pending_fragment()'s
                // identical filter (settings_routes.cpp) so this route genuinely
                // twins that fragment's population, not just its row shape.
                // Gate 4 finding (#4031 hardening round): the unfiltered version
                // silently returned every agent that had EVER enrolled, since
                // nothing ages an approved entry out of pending_agents_ -- on any
                // real fleet that made this route's actual output diverge from
                // its name, OpenAPI summary, docs, and the API-parity ledger's
                // "twinned" status, all of which describe it as the pending/
                // denied queue. TODO: the fragment and this route independently
                // duplicate this filter predicate rather than sharing one -- a
                // follow-up could route both through a single filtered accessor
                // on AuthManager instead.
                //
                // Scope filter — `gate.scope` is the resolved meet(management-
                // group, service-scope) VisibleSet (nullopt = unfiltered TOP;
                // engaged, including empty, = filter to exactly these agents).
                // Under the intended workflow a pending agent holds no
                // management-group membership yet (enrollment/approval
                // happens before group assignment), so a scoped caller's
                // admitted result is typically the empty set — but this is a
                // workflow expectation, not a data-model guarantee (see the
                // route-header comment above): a pre-assigned membership row
                // yields a non-empty, correctly-confined result here, never
                // a widening.
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& a : agents) {
                    if (a.status == auth::PendingStatus::approved)
                        continue;
                    if (!authz::in_scope(gate.scope, a.agent_id))
                        continue;
                    arr.push_back(pending_agent_row_json(a));
                }
                res.set_content(list_json(arr, static_cast<int64_t>(arr.size())),
                                "application/json");
            });

    // ── GET /api/v1/settings/oidc — OidcConfig:Read ──────────────────────
    // #520 decision: REST-only, no MCP twin — see file header.
    // NAMING TRAP: gates on OidcConfig, never Directory — see
    // enrollment_directory_model.hpp's file header. Audited (non-blocking):
    // IdP/admin-group recon value, same reasoning as auto-approve above; the
    // client secret is never disclosed by oidc_config_json in the first
    // place (masked to a bool), so this route carries no secret-leak risk
    // an audit-failure posture would need to compensate for.
    //
    // Gate 5 chaos-injector finding (#4031 hardening round): the original
    // handler read cfg->oidc_* (plain std::string fields) with ZERO
    // synchronization while POST /api/settings/oidc
    // (settings_routes.cpp:4092) takes std::unique_lock(*oidc_mu_) before
    // reassigning the SAME fields -- a genuine data race under concurrent
    // read/write, not a "no lock exists" gap (the mutex already exists and
    // is threaded into SettingsRoutes/AuthRoutes for exactly this purpose;
    // this route just wasn't given it). std::shared_lock here matches the
    // writer's std::unique_lock on the same mutex.
    sink.Get("/api/v1/settings/oidc",
            [perm_fn, audit_fn, cfg, &oidc_mu](const httplib::Request& req,
                                               httplib::Response& res) {
                if (!perm_fn(req, res, "OidcConfig", "Read"))
                    return;
                if (!cfg) {
                    respond_service_unavailable(res, "server config");
                    return;
                }
                (void)detail::try_persist_audit(audit_fn, req, "settings.oidc.view", "success",
                                                "OidcConfig", "", "REST v1 OIDC config read");
                nlohmann::json data;
                {
                    std::shared_lock lock(oidc_mu);
                    data = oidc_config_json(*cfg);
                }
                res.set_content(ok_json(data), "application/json");
            });
}

} // namespace yuzu::server
