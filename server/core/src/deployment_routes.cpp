/// @file deployment_routes.cpp
/// `/auto` deploy fragment handlers. See deployment_routes.hpp for the auth/scope
/// contract. The cohort is the SOURCE pre-flight run's go-cohort (bucket go/warn),
/// read owner-scoped + re-intersected with the operator's current visible set; the
/// engine re-authorizes every advance and dispatches the MUTATING execute step at
/// most once per device.

#include "deployment_routes.hpp"

#include "deployment_engine.hpp"
#include "deployment_parse.hpp"
#include "deployment_run_store.hpp"
#include "http_route_sink.hpp"
#include "preflight_parse.hpp"      // bucket_from_token, PreflightTarget
#include "preflight_run_store.hpp"  // PreflightRunStore (source go-cohort)
#include "rest_a4_envelope_http.hpp" // detail::a4_denial (deny_service_scoped_) — mints/reuses
                                     // X-Correlation-Id so header and body always agree
#include "rest_audit.hpp"           // detail::try_persist_audit

#include <yuzu/server/auth.hpp> // AuthManager (id bytes)

#include <algorithm>
#include <chrono>
#include <cctype>
#include <string>
#include <unordered_set>
#include <vector>

namespace yuzu::server {

namespace {

// Page-poll cap: the open page stops polling after this many ticks; the deployment
// continues server-side (reopen to refresh). Bounds an open tab, not the run.
constexpr int kPollCap = 600;

std::string param(const httplib::Request& req, const char* key) {
    return req.has_param(key) ? req.get_param_value(key) : std::string{};
}

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string url_encode(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            out += static_cast<char>(c);
        else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

std::string gen_id() {
    return auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));
}

deployment::DeploymentConfig config_from_req(const httplib::Request& req) {
    deployment::DeploymentConfig c;
    c.url = param(req, "url");
    c.filename = param(req, "filename");
    // Normalize the SHA-256 to lowercase at intake: content_dist computes a
    // lowercase digest and compares EXACT, so an uppercase paste (the default of
    // PowerShell Get-FileHash / certutil) would otherwise fail stage on every
    // device despite being correct (#governance HIGH). We store + dispatch the
    // normalized form; is_valid_sha256 stays case-insensitive for the accept check.
    c.sha256 = param(req, "sha256");
    for (char& ch : c.sha256)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    c.args = param(req, "args");
    return c;
}

deployment::DeploymentConfig config_from_row(const DeploymentRow& r) {
    deployment::DeploymentConfig c;
    c.url = r.artifact_url;
    c.filename = r.artifact_filename;
    c.sha256 = r.artifact_sha256;
    c.args = r.exec_args;
    return c;
}

} // namespace

// REST (`GET /api/v1/deployments/preview`) + MCP (`get_deployment_preview`)
// shared builder — declared in deployment_routes.hpp so mcp_server.cpp can
// call the SAME function (api-twin-recipe.md Rule 1). Mirrors
// render_deploy_config's four scalar inputs exactly.
nlohmann::json deploy_preview_json(const std::string& run_id, const std::string& run_name,
                                   int go_count, int warn_count) {
    return nlohmann::json{
        {"run_id", run_id},
        {"name", run_name},
        {"go", go_count},
        {"warn", warn_count},
    };
}

yuzu::server::DispatchCaller
DeploymentRoutes::caller_from_session(const auth::Session& session) const {
    return yuzu::server::DispatchCaller{
        .principal = session.username,
        .principal_role = auth::role_to_string(session.role),
        .exec_visible = exec_visible_fn_ ? exec_visible_fn_(session)
                                         : yuzu::server::authz::deny_all(),
        // #1398: JIT-elevation-aware, matching every other session-derived
        // caller (server.cpp's derive_dispatch_caller).
        .principal_is_admin = auth::effective_role(session) == auth::Role::admin};
}

std::string DeploymentRoutes::advance_and_render(const std::string& deployment_id,
                                                 const yuzu::server::DispatchCaller& caller,
                                                 int attempt) {
    const std::string& viewer = caller.principal;
    if (!deploy_store_)
        return render_deploy_note("Deployment store is unavailable on this server.");
    // OWNER-SCOPED read at the seam: a not-yours deployment reads as not-found.
    auto dep = deploy_store_->get_deployment(deployment_id, viewer);
    if (!dep)
        return render_deploy_note("Deployment not found (it may have aged out of retention).");

    // Re-authorization boundary: the engine may dispatch the MUTATING execute step,
    // so it only ever acts on devices the operator CURRENTLY sees. Build the live
    // visible set from devices_fn(viewer); the engine intersects it with the frozen
    // cohort, skips the rest, and dispatches execute once per device. This is
    // TARGETING confinement — a separate question from `caller`, which is the
    // DISPATCH identity the chokepoint authorizes against (see `DispatchFn`'s
    // doc comment, deployment_engine.hpp).
    std::unordered_set<std::string> authorized;
    if (devices_fn_)
        for (const auto& d : devices_fn_(viewer))
            authorized.insert(d.agent_id);

    const auto cfg = config_from_row(*dep);
    deployment::advance(engine_, deployment_id, cfg, authorized, caller);

    // Re-read fresh state for the render.
    dep = deploy_store_->get_deployment(deployment_id, viewer);
    if (!dep)
        return render_deploy_note("Deployment not found.");
    auto devices = deploy_store_->get_devices(deployment_id);

    std::string repoll;
    if (dep->status == "running" && attempt < kPollCap)
        repoll = "/fragments/auto/deploy/result?dep=" + url_encode(deployment_id) + "&n=" +
                 std::to_string(attempt + 1);
    return render_deploy_results(*dep, devices, repoll);
}

bool DeploymentRoutes::deny_service_scoped_(const httplib::Request& req, httplib::Response& res,
                                            const std::string& action,
                                            const std::string& audit_detail,
                                            const std::string& target_type,
                                            const std::string& permission) const {
    auto session = auth_fn_(req, res);
    if (!session)
        return true; // auth_fn_ already wrote the response (401/etc).
    if (session->token_scope_service.empty())
        return false;
    // Write the 403 FIRST, audit after (mirrors PreflightRoutes/DexRoutes/
    // GuardianRoutes' deny_service_scoped_): a throwing audit_fn_ must not
    // suppress the 403.
    res.status = 403;
    // `permission` defaults empty (see header) — a caller passing a
    // non-empty override is now itself a bug, since no grant admits a
    // service-scoped caller here. `a4_denial` also fixes a second bug found
    // in the same pass: the hand-built cid never reached the
    // X-Correlation-Id header.
    res.set_content(
        detail::a4_denial(
            res, 403, "service-scoped tokens may not access this fleet-wide deployment surface",
            detail::A4ErrorOpts{.permission = permission}),
        "application/json");
    (void)detail::try_persist_audit(audit_fn_, req, action, "denied", target_type, "",
                                    audit_detail);
    return true;
}

void DeploymentRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                       DevicesFn devices_fn, DispatchFn dispatch_fn, PollFn poll_fn,
                                       AuditFn audit_fn, PreflightRunStore* preflight_store,
                                       DeploymentRunStore* deploy_store,
                                       ExecVisibleFn exec_visible_fn) {
    HttplibRouteSink sink(svr);
    exec_visible_fn_ = std::move(exec_visible_fn);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(devices_fn),
                    std::move(dispatch_fn), std::move(poll_fn), std::move(audit_fn),
                    preflight_store, deploy_store);
}

void DeploymentRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                       DevicesFn devices_fn, DispatchFn dispatch_fn, PollFn poll_fn,
                                       AuditFn audit_fn, PreflightRunStore* preflight_store,
                                       DeploymentRunStore* deploy_store) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    devices_fn_ = std::move(devices_fn);
    audit_fn_ = std::move(audit_fn);
    preflight_store_ = preflight_store;
    deploy_store_ = deploy_store;
    engine_.store = deploy_store;
    engine_.poll_fn = std::move(poll_fn);
    engine_.dispatch_fn = std::move(dispatch_fn);

    // ── Deploy config fragment for a pre-flight run ──────────────────────────
    sink.Get("/fragments/auto/deploy", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        // Owner-scoped by username below (get_run), and a service-scoped
        // token shares its creating principal's username — it would
        // otherwise read back the go/warn counts for a fleet-wide run
        // outside its own service (SEC-2/SEC-3 class). Own verb, not
        // deployment.create: no deployment is created by this GET.
        if (deny_service_scoped_(req, res, "deployment.config.view",
                                 "deploy config form denied to a service-scoped token", "Scope"))
            return;
        if (!perm_fn_ || !perm_fn_(req, res, "SoftwareDeployment", "Read"))
            return;
        if (!preflight_store_) {
            res.set_content(render_deploy_note("Pre-flight store is unavailable on this server."),
                            "text/html; charset=utf-8");
            return;
        }
        const std::string run_id = param(req, "run");
        // Owner-scoped: a not-yours run reads as not-found (no existence oracle).
        auto run = preflight_store_->get_run(run_id, session->username);
        if (!run) {
            res.set_content(render_deploy_note("Pre-flight run not found."),
                            "text/html; charset=utf-8");
            return;
        }
        res.set_content(render_deploy_config(run->run_id, run->name, run->go, run->warn),
                        "text/html; charset=utf-8");
    });

    // ── Create the deployment from the run's go-cohort + first advance ───────
    sink.Post("/fragments/auto/deploy/run", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        // Important finding from external review (PR #3156): this is the
        // deployment CREATION route itself (the first fleet-wide dispatch),
        // not just the config-view/result-poll/delete siblings already
        // fixed elsewhere in this file - a service-scoped token could
        // otherwise stage + dispatch an installer to devices outside its
        // own service.
        if (deny_service_scoped_(req, res, "deployment.create",
                                 "deployment create denied to a service-scoped token",
                                 "SoftwareDeployment"))
            return;
        // Mutating fleet action: Execute tier; + Infrastructure:Read for the device
        // resolution + the result render it returns (so the repoll isn't 403-walled).
        if (!perm_fn_ || !perm_fn_(req, res, "Infrastructure", "Read"))
            return;
        if (!perm_fn_(req, res, "SoftwareDeployment", "Execute"))
            return;
        if (!deploy_store_ || !deploy_store_->is_open() || !preflight_store_) {
            res.set_content(render_deploy_note("Deployment store is unavailable on this server."),
                            "text/html; charset=utf-8");
            return;
        }
        const auto cfg = config_from_req(req);
        std::string why;
        if (!deployment::config_valid(cfg, &why)) {
            res.set_content(render_deploy_note("Artifact invalid: " + why),
                            "text/html; charset=utf-8");
            return;
        }
        const std::string run_id = param(req, "run");
        auto run = preflight_store_->get_run(run_id, session->username);
        if (!run) {
            res.set_content(render_deploy_note("Pre-flight run not found."),
                            "text/html; charset=utf-8");
            return;
        }
        // NOTE: deploy does NOT require the pre-flight run to be 'complete' — the
        // operator can act on the devices cleared so far, mid-run (the button appears
        // with the first result). This is SAFE because the cohort below is filtered
        // to bucket go/warn, and a device only reaches go/warn once ALL its checks
        // have answered (a still-evaluating device is 'incomplete', never go/warn) —
        // so the cohort is always fully-evaluated, cleared devices, never a partial
        // per-device verdict. get_devices reads the run's persisted grid: the
        // background runner persists it every tick (≤~60s stale with no page open),
        // and the result route additionally persists it on each self-poll (tightening
        // staleness to ~1 poll while a page is open) — so a mid-run deploy sees the
        // currently-cleared cohort.
        // RESUME guard (#governance security HIGH-1): if this owner already has a
        // RUNNING deployment for this source run, render IT instead of creating a
        // second — a second deployment mints a new id, runs an independent CAS, and
        // would RE-EXECUTE the installer on devices the first already installed
        // (execute-once is per-deployment). This also makes "reopen to resume"
        // real. The partial unique index is the race-safe backstop below.
        if (auto existing = deploy_store_->find_running_for_run(run_id, session->username)) {
            if (audit_fn_)
                audit_fn_(req, "deployment.create", "resumed", "SoftwareDeployment", *existing,
                          "run=" + run_id);
            res.set_content(advance_and_render(*existing, caller_from_session(*session),
                                                /*attempt=*/0),
                            "text/html; charset=utf-8");
            return;
        }

        // Cohort = the run's go+warn devices ∩ what the operator can CURRENTLY see,
        // MINUS any device a PRIOR (completed) deployment of this run already
        // installed. The exclusion is cross-deployment execute-once (#governance
        // HIGH): after a mid-run deploy completes and more devices clear, a re-deploy
        // covers only the new / failed devices and never re-runs the installer on an
        // already-succeeded one. (The resume guard above handles the still-RUNNING
        // case; this handles the after-it-completed re-deploy.)
        std::unordered_set<std::string> visible;
        if (devices_fn_)
            for (const auto& d : devices_fn_(session->username))
                visible.insert(d.agent_id);
        std::unordered_set<std::string> already_deployed;
        for (const auto& a : deploy_store_->succeeded_agents_for_run(run_id, session->username))
            already_deployed.insert(a);
        std::vector<preflight::PreflightTarget> cohort;
        for (const auto& pd : preflight_store_->get_devices(run_id)) {
            const auto b = preflight::bucket_from_token(pd.bucket);
            if ((b == preflight::Bucket::kPass || b == preflight::Bucket::kWarnOnly) &&
                visible.count(pd.agent_id) && already_deployed.find(pd.agent_id) == already_deployed.end())
                cohort.push_back({pd.agent_id, pd.hostname, pd.os});
        }
        if (cohort.empty()) {
            if (audit_fn_)
                audit_fn_(req, "deployment.create", "no_devices", "SoftwareDeployment", run_id, "");
            res.set_content(
                render_deploy_note("No deployable devices: the go / warn-only devices you can "
                                   "currently see in that pre-flight run were already deployed "
                                   "successfully, or none are visible to you."),
                "text/html; charset=utf-8");
            return;
        }

        DeploymentRow dep;
        dep.deployment_id = gen_id();
        dep.source_run_id = run_id;
        dep.created_by = session->username;
        dep.name = run->name;
        dep.artifact_url = cfg.url;
        dep.artifact_filename = cfg.filename;
        dep.artifact_sha256 = cfg.sha256;
        dep.exec_args = cfg.args;
        dep.status = "running";
        dep.created_at_ms = now_ms();

        if (!deploy_store_->create_deployment(dep, cohort)) {
            // A concurrent create won the partial unique index race — resume the
            // winner rather than error (#governance security HIGH-1 backstop).
            if (auto existing = deploy_store_->find_running_for_run(run_id, session->username)) {
                res.set_content(advance_and_render(*existing, caller_from_session(*session),
                                                    /*attempt=*/0),
                                "text/html; charset=utf-8");
                return;
            }
            res.set_content(render_deploy_note("Could not persist the deployment."),
                            "text/html; charset=utf-8");
            return;
        }
        if (audit_fn_)
            // Audit the artifact's SHA-256 (the content identity of what ran on the
            // fleet) + URL, not just the cosmetic filename (#governance M-1 / SOC2).
            audit_fn_(req, "deployment.create", "success", "SoftwareDeployment", dep.deployment_id,
                      "run=" + run_id + " file=" + cfg.filename + " sha256=" + cfg.sha256 +
                          " url=" + cfg.url + " devices=" + std::to_string(cohort.size()));

        // First advance (stage dispatch) + render — advance_and_render re-resolves
        // the live authorized set and ticks the engine once.
        res.set_content(
            advance_and_render(dep.deployment_id, caller_from_session(*session), /*attempt=*/0),
            "text/html; charset=utf-8");
    });

    // ── Result poll: advance one tick, render (owner-scoped) ─────────────────
    sink.Get("/fragments/auto/deploy/result", [this](const httplib::Request& req,
                                                    httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        // Owner-scoped by username (advance_and_render -> get_deployment), and
        // a service-scoped token shares its creating principal's username -
        // it would otherwise re-authorize + advance the mutating engine tick
        // for a deployment outside its own service (SEC-2/SEC-3 class). This
        // narrows exposure (stops further devices being admitted on later
        // ticks); the fleet-wide creation gap on POST
        // /fragments/auto/deploy/run is closed separately, by its own
        // deny_service_scoped_ call site below.
        if (deny_service_scoped_(req, res, "deployment.advance",
                                 "deployment result poll denied to a service-scoped token"))
            return;
        // The poll BOTH renders (Read) AND advances the mutating engine (Execute) —
        // require both so an Execute-less principal can't drive a deployment, and a
        // Read-less one isn't 403-walled mid-run.
        if (!perm_fn_ || !perm_fn_(req, res, "SoftwareDeployment", "Read"))
            return;
        if (!perm_fn_(req, res, "SoftwareDeployment", "Execute"))
            return;
        const std::string dep_id = param(req, "dep");
        int attempt = 1;
        if (req.has_param("n")) {
            try {
                attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 100000);
            } catch (...) {
            }
        }
        if (audit_fn_)
            audit_fn_(req, "deployment.advance", "success", "SoftwareDeployment", dep_id, "");
        res.set_content(advance_and_render(dep_id, caller_from_session(*session), attempt),
                        "text/html; charset=utf-8");
    });

    // ── Delete a deployment (owner-scoped, confirm-guarded on the client) ────
    sink.Post("/fragments/auto/deploy/delete", [this](const httplib::Request& req,
                                                     httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        // Owner-scoped by username (delete_deployment below), and a
        // service-scoped token shares its creating principal's username —
        // it could otherwise delete evidence for a fleet-wide deployment
        // outside its own service (SEC-2/SEC-3 class).
        if (deny_service_scoped_(req, res, "deployment.delete",
                                 "deployment delete denied to a service-scoped token",
                                 "SoftwareDeployment"))
            return;
        if (!perm_fn_ || !perm_fn_(req, res, "SoftwareDeployment", "Execute"))
            return;
        const std::string dep_id = param(req, "dep");
        const bool deleted =
            deploy_store_ && deploy_store_->delete_deployment(dep_id, session->username);
        if (audit_fn_)
            audit_fn_(req, "deployment.delete", deleted ? "success" : "noop", "SoftwareDeployment",
                      dep_id, "");
        res.set_content(render_deploy_note(deleted ? "Deployment deleted."
                                                   : "Nothing to delete."),
                        "text/html; charset=utf-8");
    });

    // ── REST twin: GET /api/v1/deployments/preview (#4036, api-parity Batch A) ─
    // Owner-scoped deploy-config go/warn preview for one pre-flight run —
    // confirmed inert (reads preflight_store_ only, no DeploymentRunStore
    // call, no dispatch). Own audit verb `deployment.config.view`, already
    // distinct from `deployment.create` (matches the fragment's own comment:
    // "no deployment is created by this GET").
    sink.Get("/api/v1/deployments/preview", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        // SEC-2/SEC-3 confinement gap, same rationale + same call as the
        // fragment's own deny_service_scoped_ above: owner-scoped by
        // session->username, so a service-scoped token sharing its creating
        // principal's username could otherwise read back the go/warn counts
        // for a fleet-wide run outside its own service. NOTE: `perm_fn_`
        // below (require_permission) ALSO structurally denies a
        // service-scoped caller here per ADR-1006's default-deny flip
        // (service_scope_policy.hpp's kServiceScopeGlobalSafe allow-list is
        // seeded empty, and "SoftwareDeployment:Read" is not in it) — this
        // call is now belt-and-braces, kept for an early, `deployment.config.
        // view`-audited denial rather than the generic auth.permission_
        // required action ADR-1006's flip alone would record.
        if (deny_service_scoped_(req, res, "deployment.config.view",
                                 "REST deploy-preview denied to a service-scoped token", "Scope"))
            return;
        if (!perm_fn_ || !perm_fn_(req, res, "SoftwareDeployment", "Read"))
            return;
        if (!preflight_store_) {
            res.status = 503;
            // No retry_after_ms: preflight_store_ is wired exactly once, in
            // register_routes() at server construction (server.cpp), with no
            // runtime setter. A null value here is a permanent "this server
            // was deployed without the store configured" condition — no
            // amount of client retrying resolves it. Contrast the genuine,
            // retryable store-fault branch below (get_run_checked).
            res.set_content(
                detail::a4_error(res, "pre-flight run store is unavailable on this server"),
                "application/json");
            return;
        }
        const std::string run_id = param(req, "run");
        if (run_id.empty()) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "missing required query parameter: run"),
                            "application/json");
            return;
        }
        // #4036 hardening round: `get_run_checked`, not `get_run` — the plain
        // accessor collapses a store-level fault (pool exhausted, query error)
        // into the SAME nullopt as a genuine miss/not-yours, so a transient
        // Postgres hiccup would read as a permanent 404 rather than a
        // retryable 503, matching rest-api.md's published "Pre-flight run
        // store unavailable → 503" contract for this route (previously only
        // true for the unwired-pointer case above). Owner-scoped: a
        // not-yours run STILL reads as not-found (no existence oracle) —
        // that ambiguity is deliberate and preserved; only the store-fault
        // case is now distinguished from it.
        auto run_or = preflight_store_->get_run_checked(run_id, session->username);
        if (!run_or) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "pre-flight run store is unavailable on this server",
                                 {.retry_after_ms = 2000}),
                "application/json");
            return;
        }
        const auto& run = *run_or;
        if (!run) {
            res.status = 404;
            res.set_content(detail::a4_error(res, "pre-flight run not found"), "application/json");
            return;
        }
        // Deliberately UNAUDITED on success (stated decision, #4036) — same
        // reasoning as the /api/v1/preflight/runs twin above: run
        // scope/go/warn metadata, not per-agent behavioural PII, matching
        // the fragment's own unaudited-read posture and the
        // api-twin-recipe.md §8 worked-example precedent. The DENIAL path
        // above still audits under `deployment.config.view`.
        nlohmann::json out = {
            {"data", deploy_preview_json(run->run_id, run->name, run->go, run->warn)},
            {"meta", {{"api_version", "v1"}}},
        };
        res.set_content(out.dump(), "application/json");
    });
}

} // namespace yuzu::server
