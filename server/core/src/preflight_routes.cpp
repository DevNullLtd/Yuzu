/// @file preflight_routes.cpp
/// `/auto` page shell + config/rail fragment + run creation + result poll. See
/// preflight_routes.hpp for the auth/scope contract.
///
/// Slice 2: a run is PERSISTED (PreflightRunStore). POST /run freezes the cohort
/// (devices_fn(user) ∩ group ∩ os), creates the run, does the FIRST dispatch
/// (per-check execution_id `preflight-<run>-<key>`), and renders live. The
/// background PreflightRunner re-dispatches to reconnecting stragglers + persists
/// the grid until the window closes. The result route renders a RUNNING run live
/// (collect + compute) and a COMPLETE run from the stored grid; it ALSO persists the
/// live grid on every self-poll (via the shared `persist_and_maybe_complete`) so the
/// stored go-cohort stays current mid-run (the deploy stage reads it) and completion
/// is event-driven on whichever path settles first. Reads are OWNER-SCOPED
/// (created_by) so one operator can't open another's run.

#include "preflight_routes.hpp"

#include "preflight_eval.hpp"       // collect/applicable/dispatch_params/check_*/config_*/checks_from_json
#include "preflight_parse.hpp"      // kPreflightChecks, compute_device_results, bucket_from_token
#include "preflight_run_store.hpp"  // PreflightRunStore + rows
#include "http_route_sink.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_denial (deny_service_scoped_)
#include "rest_audit.hpp"           // detail::try_persist_audit
#include "web_utils.hpp"            // html_escape

#include <yuzu/server/auth.hpp> // auth::AuthManager (run-id bytes)

#include <algorithm>
#include <cctype>
#include <chrono>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

// Defined in guardian_page_ui.cpp — the shared dark-theme full-page shell.
// Declared at GLOBAL scope (not inside yuzu::server) to match the definition.
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

// Page-poll cap: ~5 min at the 700ms cadence. After this the page stops polling
// but the run continues SERVER-SIDE (the runner owns the window) — reopen from
// the rail to refresh. Bounds an open tab; doesn't bound the run.
constexpr int kPollCap = 430;
// Window bounds (minutes): 1 minute … 2 days.
constexpr int kMinWindowMin = 1;
constexpr int kMaxWindowMin = 2880;

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

std::string page_shell(const std::string& title, const std::string& fragment_url) {
    std::string html(kGuardianDetailPageHtml);
    auto sub = [&](const std::string& tok, const std::string& val) {
        for (auto p = html.find(tok); p != std::string::npos; p = html.find(tok, p + val.size()))
            html.replace(p, tok.size(), val);
    };
    sub("{{TITLE}}", title);
    sub("{{FRAGMENT}}", fragment_url);
    sub("<a href=\"/guardian\" class=\"nav-link active\">Guardian</a>",
        "<a href=\"/guardian\" class=\"nav-link\">Guardian</a>");
    return html;
}

std::string param(const httplib::Request& req, const char* key) {
    return req.has_param(key) ? req.get_param_value(key) : std::string{};
}

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

preflight::PreflightConfig config_from_req(const httplib::Request& req) {
    preflight::PreflightConfig c;
    c.app_name = param(req, "app_name");
    c.app_min_version = param(req, "app_min");
    c.app_max_version = param(req, "app_max");
    c.os_min_version = param(req, "os_min");
    c.req_arch = param(req, "arch");
    c.min_free_gib = preflight::parse_i64(param(req, "min_gib"));
    c.volume = param(req, "volume");
    c.reboot_block = param(req, "reboot") != "warn"; // default block
    return c;
}

// One-check threshold phrase; prefixed so it reads standalone in the
// config-summary line ("AcmeVPN ≥ 4.2.0 ≤ 4.9.99 · OS ≥ 10.0.19045 · …").
std::string threshold_text(std::string_view key, const preflight::PreflightConfig& cfg) {
    if (key == "app") {
        std::string s = cfg.app_name;
        if (cfg.app_min_version.empty() && cfg.app_max_version.empty())
            return s + " installed";
        if (!cfg.app_min_version.empty())
            s += " \xE2\x89\xA5 " + cfg.app_min_version;
        if (!cfg.app_max_version.empty())
            s += " \xE2\x89\xA4 " + cfg.app_max_version;
        return s;
    }
    if (key == "osver")
        return cfg.os_min_version.empty() ? "OS any" : ("OS \xE2\x89\xA5 " + cfg.os_min_version);
    if (key == "osarch")
        return std::string("arch ") + (cfg.req_arch.empty() ? "any" : cfg.req_arch);
    if (key == "disk")
        return "disk \xE2\x89\xA5 " + std::to_string(cfg.min_free_gib) + " GiB" +
               (cfg.volume.empty() ? "" : (" on " + cfg.volume));
    if (key == "reboot")
        return cfg.reboot_block ? "reboot must be clear" : "reboot warn-only";
    return {};
}

std::string config_summary(const preflight::PreflightConfig& cfg) {
    std::string s;
    for (const auto& c : preflight::kPreflightChecks) {
        if (!preflight::check_applicable(c.key, cfg))
            continue;
        if (!s.empty())
            s += " \xC2\xB7 ";
        s += threshold_text(c.key, cfg);
    }
    return s;
}

// Operator-visible devices in `group_id` (empty → all visible), narrowed by OS
// family (empty/"any" → no OS narrowing). IDOR-safe: always devices_fn(user) ∩
// group, never a raw fleet read.
std::vector<DeviceRow> resolve_targets(const PreflightRoutes::DevicesFn& devices_fn,
                                       const PreflightRoutes::GroupMembersFn& members_fn,
                                       const std::string& username, const std::string& group_id,
                                       const std::string& os_filter) {
    auto visible = devices_fn ? devices_fn(username) : std::vector<DeviceRow>{};
    std::vector<DeviceRow> scoped;
    if (group_id.empty()) {
        scoped = std::move(visible);
    } else {
        std::unordered_set<std::string> members;
        if (members_fn)
            for (const auto& m : members_fn(group_id))
                members.insert(m);
        for (const auto& d : visible)
            if (members.count(d.agent_id))
                scoped.push_back(d);
    }
    if (os_filter.empty() || os_filter == "any")
        return scoped;
    std::vector<DeviceRow> out;
    for (const auto& d : scoped)
        if (d.os == os_filter)
            out.push_back(d);
    return out;
}

std::string scope_label(const PreflightRoutes::GroupsFn& groups_fn, const std::string& group_id,
                        const std::string& os_filter) {
    std::string base;
    if (group_id.empty()) {
        base = "all visible devices";
    } else {
        base = group_id;
        if (groups_fn)
            for (const auto& [id, name] : groups_fn())
                if (id == group_id)
                    base = name;
    }
    if (!os_filter.empty() && os_filter != "any")
        base += " \xC2\xB7 " + os_filter;
    return base;
}

std::string gen_run_id() {
    return auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));
}

// The viewer's own recent runs as (run_id, rail-label). Owner-scoped (is_admin
// false). Shared by the config fragment + the delete route's rail re-render.
std::vector<std::pair<std::string, std::string>> recent_runs(PreflightRunStore* store,
                                                             const std::string& viewer) {
    std::vector<std::pair<std::string, std::string>> out;
    if (!store)
        return out;
    for (const auto& r : store->list_runs(viewer, /*is_admin=*/false, 12)) {
        std::string label = r.name.empty() ? std::string("Pre-flight") : r.name;
        label += " \xC2\xB7 " + std::to_string(r.go) + "go/" + std::to_string(r.nogo) + "no-go";
        if (r.status == "running")
            label += " \xC2\xB7 running";
        out.emplace_back(r.run_id, label);
    }
    return out;
}

} // namespace

// REST (`GET /api/v1/preflight/runs`) + MCP (`list_preflight_runs`) shared
// builder — declared in preflight_routes.hpp so mcp_server.cpp can call the
// SAME function (api-twin-recipe.md Rule 1). Deliberately richer than
// `recent_runs()`'s flattened rail label above: an API caller gets the raw
// go/warn/nogo/incomplete counts and lifecycle timestamps, not a pre-formatted
// display string.
nlohmann::json preflight_run_row_json(const PreflightRunRow& r) {
    return nlohmann::json{
        {"run_id", r.run_id},
        {"name", r.name},
        {"scope_label", r.scope_label},
        {"status", r.status},
        {"created_at_ms", r.created_at_ms},
        {"deadline_at_ms", r.deadline_at_ms},
        {"completed_at_ms", r.completed_at_ms},
        {"total", r.total},
        {"go", r.go},
        {"warn", r.warn},
        {"nogo", r.nogo},
        {"incomplete", r.incomplete},
    };
}

bool PreflightRoutes::deny_service_scoped_(const httplib::Request& req, httplib::Response& res,
                                           const std::string& action,
                                           const std::string& audit_detail,
                                           const std::string& permission) const {
    auto session = auth_fn_(req, res);
    if (!session)
        return true; // auth_fn_ already wrote the response (401/etc).
    if (session->token_scope_service.empty())
        return false;
    // Write the 403 FIRST, audit after (mirrors DexRoutes/GuardianRoutes'
    // deny_service_scoped_): a throwing audit_fn_ must not suppress the 403.
    // `permission` defaults empty (see header) — a caller passing a non-empty
    // override is now itself a bug, since no grant admits a service-scoped
    // caller here. `a4_denial` also fixes a second bug found in the same
    // pass (#3167): the hand-built cid never reached the X-Correlation-Id
    // header.
    res.status = 403;
    res.set_content(
        detail::a4_denial(
            res, 403, "service-scoped tokens may not access this fleet-wide pre-flight surface",
            detail::A4ErrorOpts{.permission = permission}),
        "application/json");
    (void)detail::try_persist_audit(audit_fn_, req, action, "denied", "Scope", "", audit_detail);
    return true;
}

void PreflightRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                      DevicesFn devices_fn, GroupsFn groups_fn,
                                      GroupMembersFn group_members_fn, DispatchFn dispatch_fn,
                                      CollectFn collect_fn, AuditFn audit_fn,
                                      PreflightRunStore* run_store) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(devices_fn),
                    std::move(groups_fn), std::move(group_members_fn), std::move(dispatch_fn),
                    std::move(collect_fn), std::move(audit_fn), run_store);
}

void PreflightRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                      DevicesFn devices_fn, GroupsFn groups_fn,
                                      GroupMembersFn group_members_fn, DispatchFn dispatch_fn,
                                      CollectFn collect_fn, AuditFn audit_fn,
                                      PreflightRunStore* run_store) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    devices_fn_ = std::move(devices_fn);
    groups_fn_ = std::move(groups_fn);
    group_members_fn_ = std::move(group_members_fn);
    dispatch_fn_ = std::move(dispatch_fn);
    collect_fn_ = std::move(collect_fn);
    audit_fn_ = std::move(audit_fn);
    run_store_ = run_store;

    // ── Page shell — auth-only chrome ────────────────────────────────────────
    sink.Get("/auto", [this](const httplib::Request& req, httplib::Response& res) {
        if (!auth_fn_ || !auth_fn_(req, res)) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        res.set_content(page_shell("Yuzu \xE2\x80\x94 Pre-flight", "/fragments/auto"),
                        "text/html; charset=utf-8");
    });

    // ── Config + saved-runs rail ─────────────────────────────────────────────
    sink.Get("/fragments/auto", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        // The saved-runs rail is username-scoped (recent_runs below), and a
        // service-scoped token shares its creating principal's username
        // (ApiToken::principal_id) — it would otherwise enumerate fleet-wide
        // run ids/scope labels outside its own service (SEC-2/SEC-3 class).
        if (deny_service_scoped_(req, res, "preflight.run",
                                 "pre-flight saved-runs rail denied to a service-scoped token"))
            return;
        if (!perm_fn_ || !perm_fn_(req, res, "Infrastructure", "Read"))
            return;
        std::vector<std::pair<std::string, std::string>> groups;
        if (groups_fn_)
            groups = groups_fn_();
        res.set_content(render_auto_config(groups, recent_runs(run_store_, session->username)),
                        "text/html; charset=utf-8");
    });

    // ── Delete a run (owner-scoped, confirm-guarded on the client) ───────────
    sink.Post("/fragments/auto/delete", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        // Owner-scoped by username (delete_run below), and a service-scoped
        // token shares its creating principal's username — it could otherwise
        // delete evidence for a fleet-wide run outside its own service
        // (SEC-2/SEC-3 class).
        if (deny_service_scoped_(req, res, "preflight.run.delete",
                                 "pre-flight run delete denied to a service-scoped token"))
            return;
        // A destructive mutation → the Execute tier (you needed Execute to create
        // the run), not a read tier (#governance least-privilege).
        if (!perm_fn_ || !perm_fn_(req, res, "Execution", "Execute"))
            return;
        if (!run_store_) {
            res.set_content(render_auto_rail({}), "text/html; charset=utf-8");
            return;
        }
        const std::string run_id = param(req, "run");
        // Read the run's scope (owner-scoped, so no cross-operator leak) for the
        // audit detail BEFORE the row is gone — keeps the delete event
        // self-contained for review (#governance compliance).
        std::string scope;
        if (auto r = run_store_->get_run(run_id, session->username))
            scope = r->scope_label;
        // Owner-scoped at the store seam (created_by must match) — a non-owner /
        // unknown run is a silent no-op (the rail is the viewer's own anyway).
        const bool deleted = run_store_->delete_run(run_id, session->username);
        if (audit_fn_)
            audit_fn_(req, "preflight.run.delete", deleted ? "success" : "noop", "Scope", run_id,
                      "run=" + run_id + (scope.empty() ? "" : (" scope=" + scope)));
        res.set_content(render_auto_rail(recent_runs(run_store_, session->username)),
                        "text/html; charset=utf-8");
    });

    // ── Run — freeze cohort, create run, first dispatch, render live ─────────
    sink.Post("/fragments/auto/run", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        // Fleet-wide dispatch (SEC-2/SEC-3 confinement-gap class, found during
        // Gate 2 review): resolve_targets() below calls devices_fn_ — the same
        // username-keyed provider fixed elsewhere in this branch, which does not
        // confine a service-scoped API token whose principal resolves to an
        // unscoped grant — then DISPATCHES the resolved checks via
        // command_dispatch_fn (unconfined). Denied here, ahead of/independent
        // from perm_fn_, unlike the read-only fixes elsewhere in this branch
        // because this route MUTATES (creates a run + dispatches commands, even
        // though every dispatched check is itself read-only per the /auto
        // Pre-flight routed-concern's own safety invariant).
        if (!session->token_scope_service.empty()) {
            // Write the 403 FIRST, audit after (normalized to match this
            // file's shared deny_service_scoped_ helper — #3167). `.permission`
            // omitted: kServiceScopeGlobalSafe is compile-time-empty, so no
            // grant admits a service-scoped caller here; naming one would be a
            // false self-remediation claim.
            res.status = 403;
            res.set_content(
                detail::a4_denial(
                    res, 403, "service-scoped tokens may not start a fleet-wide pre-flight run"),
                "application/json");
            (void)detail::try_persist_audit(
                audit_fn_, req, "preflight.run", "denied", "Scope", "",
                "fleet-wide pre-flight dispatch denied to a service-scoped token");
            return;
        }
        // Run dispatches AND renders the (Infrastructure:Read) result grid +
        // self-polls — require both tiers so an Execute-only principal isn't left
        // 403-ing on every repoll (#governance consistency).
        if (!perm_fn_ || !perm_fn_(req, res, "Infrastructure", "Read"))
            return;
        if (!perm_fn_(req, res, "Execution", "Execute"))
            return;
        if (!run_store_ || !run_store_->is_open()) {
            res.set_content(render_auto_note("Pre-flight run store is unavailable on this server."),
                            "text/html; charset=utf-8");
            return;
        }
        if (!dispatch_fn_) {
            res.set_content(render_auto_note("Live dispatch is unavailable on this server."),
                            "text/html; charset=utf-8");
            return;
        }
        const auto cfg = config_from_req(req);
        const std::string group_id = param(req, "group");
        const std::string os_filter = param(req, "os_filter");
        int window_min = static_cast<int>(preflight::parse_i64(param(req, "window")));
        if (window_min <= 0)
            window_min = 30;
        window_min = std::clamp(window_min, kMinWindowMin, kMaxWindowMin);

        auto targets =
            resolve_targets(devices_fn_, group_members_fn_, session->username, group_id, os_filter);
        if (targets.empty()) {
            // Audit the no-op attempt too (matches the dex no_agents pattern), so
            // an empty-scope run isn't an unrecorded gap (#governance consistency).
            if (audit_fn_)
                audit_fn_(req, "preflight.run", "no_devices", "Scope",
                          group_id.empty() ? std::string("all-visible") : group_id, "");
            res.set_content(render_auto_note("No visible devices in that scope."),
                            "text/html; charset=utf-8");
            return;
        }

        PreflightRunRow run;
        run.run_id = gen_run_id();
        run.execution_id = "preflight-" + run.run_id;
        run.created_by = session->username;
        run.name = param(req, "name");
        run.scope_label = scope_label(groups_fn_, group_id, os_filter);
        run.group_id = group_id;
        run.os_filter = os_filter;
        run.config_json = preflight::config_to_json(cfg);
        run.window_seconds = window_min * 60;
        run.created_at_ms = now_ms();
        run.deadline_at_ms = run.created_at_ms + static_cast<std::int64_t>(run.window_seconds) * 1000;
        run.status = "running";

        std::vector<preflight::PreflightTarget> ptargets;
        ptargets.reserve(targets.size());
        std::vector<std::string> agent_ids;
        agent_ids.reserve(targets.size());
        for (const auto& d : targets) {
            ptargets.push_back({d.agent_id, d.hostname, d.os});
            agent_ids.push_back(d.agent_id);
        }

        if (!run_store_->create_run(run, ptargets)) {
            res.set_content(render_auto_note("Could not persist the pre-flight run."),
                            "text/html; charset=utf-8");
            return;
        }

        // First dispatch — per-check execution_id so re-dispatches union.
        int dispatched = 0;
        for (const auto& c : preflight::kPreflightChecks) {
            if (!preflight::check_applicable(c.key, cfg))
                continue;
            dispatch_fn_(c.plugin, c.action, agent_ids, "", preflight::dispatch_params(c.key, cfg),
                         preflight::check_execution_id(run.run_id, c.key));
            ++dispatched;
        }
        if (audit_fn_)
            audit_fn_(req, "preflight.run", "success", "Scope",
                      group_id.empty() ? std::string("all-visible") : group_id,
                      "run=" + run.run_id + " checks=" + std::to_string(dispatched) +
                          " devices=" + std::to_string(agent_ids.size()));

        res.set_content(render_run(run, /*attempt=*/0), "text/html; charset=utf-8");
    });

    // ── Result poll / revisit ── ?run=<id> (owner-scoped) ────────────────────
    sink.Get("/fragments/auto/result", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        // OWNER-SCOPED by username below, and a service-scoped token shares its
        // creating principal's username — it would otherwise read back the
        // full fleet-wide device grid for a run outside its own service
        // (SEC-2/SEC-3 class; found via Gate 4 unhappy-path review).
        if (deny_service_scoped_(req, res, "preflight.run",
                                 "pre-flight result poll denied to a service-scoped token"))
            return;
        if (!perm_fn_ || !perm_fn_(req, res, "Infrastructure", "Read"))
            return;
        if (!run_store_) {
            res.set_content(render_auto_note("Pre-flight run store is unavailable on this server."),
                            "text/html; charset=utf-8");
            return;
        }
        const std::string run_id = param(req, "run");
        // OWNER-SCOPED read at the seam: a frozen-cohort run is the creator's, so we
        // pass the viewer's username — a not-yours run reads as nullopt, identical
        // to not-found, so the response can't distinguish "exists but not yours"
        // from "doesn't exist" (closes the existence oracle, Pattern D). Admin-
        // sees-all is a tracked follow-up.
        auto run = run_store_->get_run(run_id, session->username);
        if (!run) {
            res.set_content(render_auto_note("Run not found (it may have aged out of retention)."),
                            "text/html; charset=utf-8");
            return;
        }
        int attempt = 1;
        if (req.has_param("n")) {
            try {
                attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 100000);
            } catch (...) {
            }
        }
        res.set_content(render_run(*run, attempt), "text/html; charset=utf-8");
    });

    // ── REST twin: GET /api/v1/preflight/runs (#4036, api-parity Batch A) ────
    // Owner-scoped list of the caller's own saved runs — the REST/MCP twin of
    // /fragments/auto's saved-runs-rail HALF only. The config-options half
    // (`groups_fn_`, the management-group catalogue for the scope dropdown)
    // is DELIBERATELY NOT duplicated here: `groups_fn_` is wired from
    // server.cpp to `mgmt_group_store_->list_groups()` — byte-identical to
    // what `GET /api/v1/management-groups` (ManagementGroup:Read) and the
    // `list_management_groups` MCP tool already serve. Folding it into this
    // response would (a) violate the shared-builder Rule 1 by giving the same
    // catalogue two independently-maintained JSON shapes, and (b) gate
    // identical data under a DIFFERENT permission (Infrastructure:Read here
    // vs ManagementGroup:Read there) — a principal holding one but not the
    // other would read the group catalogue through whichever side door is
    // open, an authorization inconsistency worse than the duplication itself.
    // A caller assembling the full /auto config form makes two calls, exactly
    // as a REST client already must for any other page composed of more than
    // one resource.
    sink.Get("/api/v1/preflight/runs", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        // SEC-2/SEC-3 confinement gap, same rationale as the fragment's own
        // deny_service_scoped_ call sites above: this read is OWNER-scoped by
        // session->username, not fleet-wide, but a service-scoped token
        // shares its creating principal's username, so username-only
        // owner-scoping does not confine it to its OWN service — without
        // this, a token scoped to e.g. "printers" could list back a
        // fleet-wide run its creating human made for an unrelated service.
        // NOTE: `perm_fn_` below (require_permission) ALSO structurally
        // denies a service-scoped caller here per ADR-1006's default-deny
        // flip (server/core/src/service_scope_policy.hpp's
        // kServiceScopeGlobalSafe allow-list is seeded empty, and
        // "Infrastructure:Read" is not in it) — this call is now
        // belt-and-braces, kept for an EARLY, domain-verb-specific audited
        // denial (preflight.run.view, distinct from the run-creation verb
        // preflight.run per this issue's own correction) rather than the
        // generic auth.permission_required action ADR-1006's flip alone
        // would record.
        if (deny_service_scoped_(req, res, "preflight.run.view",
                                 "REST pre-flight runs list denied to a service-scoped token"))
            return;
        if (!perm_fn_ || !perm_fn_(req, res, "Infrastructure", "Read"))
            return;
        if (!run_store_) {
            res.status = 503;
            // No retry_after_ms: run_store_ is wired exactly once, in
            // register_routes() at server construction (server.cpp), with no
            // runtime setter. A null value here is a permanent "this server
            // was deployed without the store configured" condition — no
            // amount of client retrying resolves it. Contrast the genuine,
            // retryable store-fault branch below (list_runs_checked).
            res.set_content(
                detail::a4_error(res, "pre-flight run store is unavailable on this server"),
                "application/json");
            return;
        }
        // `limit`: default matches the fragment rail's own cap (12); callers
        // may ask for more, bounded well below any pagination concern for a
        // per-operator run list.
        int64_t limit = 12;
        if (req.has_param("limit")) {
            try {
                limit = std::clamp<int64_t>(std::stoll(req.get_param_value("limit")), 1, 100);
            } catch (...) {
                res.status = 400;
                res.set_content(detail::a4_error(res, "invalid limit"), "application/json");
                return;
            }
        }
        // #4036 hardening round: `list_runs_checked`, not `list_runs` — the
        // plain accessor collapses a store-level fault (pool exhausted, query
        // error) into a silently-empty vector, indistinguishable from
        // "genuinely zero saved runs". That's an accepted fail-soft posture for
        // the pre-existing HTML rail (an "honest note" a human can just
        // refresh) but is a wrong-result-presented-as-correct outcome for a
        // machine-readable `200 {"data":[]}` response — a caller cannot tell
        // "you have no runs" from "we couldn't ask". 503 here matches the
        // published contract (rest-api.md's "Pre-flight run store
        // unavailable → 503" already covers this route, not just the
        // unwired-pointer case above).
        auto rows_or = run_store_->list_runs_checked(session->username, /*is_admin=*/false,
                                                     static_cast<int>(limit));
        if (!rows_or) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "pre-flight run store is unavailable on this server",
                                 {.retry_after_ms = 2000}),
                "application/json");
            return;
        }
        const auto& rows = *rows_or;
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& r : rows)
            arr.push_back(preflight_run_row_json(r));
        // Deliberately UNAUDITED on success (stated decision, #4036): matches
        // this domain's own fragment posture today (neither /fragments/auto
        // nor its rail audits a successful read) and the api-twin-recipe.md
        // §8 worked-example precedent for a non-behavioural-PII metadata
        // list (`list_software_deployments`) — these rows are run
        // scope/lifecycle metadata, not per-agent behavioural PII, so
        // emit_behavioral_audit's stricter REST-fail-closed posture does not
        // apply, and a plain unaudited read is proportionate. The DENIAL
        // path above still gets a domain-verb-specific audit row.
        nlohmann::json out = {
            {"data", arr},
            {"pagination", {{"total", static_cast<int64_t>(rows.size())},
                            {"start", 0},
                            {"page_size", limit}}},
            {"meta", {{"api_version", "v1"}}},
        };
        res.set_content(out.dump(), "application/json");
    });
}

// Shared render: a RUNNING run computes live (collect + compute); a COMPLETE run
// reads the stored grid. Repoll while running + pending + under the page-poll cap.
std::string PreflightRoutes::render_run(const PreflightRunRow& run, int attempt) {
    bool running = (run.status == "running");
    const auto cfg = preflight::config_from_json(run.config_json);

    std::vector<preflight::PreflightDeviceResult> grid;
    bool any_pending = false;
    bool degraded = false;

    // Stored grid (durable revisit, survives ResponseStore pruning) — also the
    // #2691 finding-10 fallback for a RUNNING run whose live read degraded.
    auto read_stored_grid = [&] {
        grid.clear();
        if (!run_store_) return;
        for (const auto& r : run_store_->get_devices(run.run_id)) {
            preflight::PreflightDeviceResult dr;
            dr.agent_id = r.agent_id;
            dr.hostname = r.hostname;
            dr.os = r.os;
            dr.bucket = preflight::bucket_from_token(r.bucket);
            dr.checks = preflight::checks_from_json(r.checks_json);
            grid.push_back(std::move(dr));
        }
    };

    if (running) {
        const auto applicable = preflight::applicable_checks(cfg);
        const auto targets = run_store_ ? run_store_->get_targets(run.run_id)
                                        : std::vector<preflight::PreflightTarget>{};
        auto checks = collect_fn_ ? collect_fn_(run.run_id, applicable)
                                  : std::vector<preflight::PreflightCheckResponses>{};
        degraded = preflight::any_check_degraded(checks);
        if (degraded) {
            // #2691 finding 10: this poll's read degraded (Postgres pool/query
            // failure). Computing a grid from it would read every device as
            // Incomplete and persisting that would silently overwrite an
            // already-good stored verdict — render the last known-good stored
            // grid instead and skip persist_and_maybe_complete entirely this
            // poll. The run stays running; the next self-poll retries.
            read_stored_grid();
            any_pending = true; // keep the repoll wrapper live below
        } else {
            grid = preflight::compute_device_results(targets, checks, cfg, &any_pending);
            // Persist the live grid on EVERY self-poll (not just at completion) so
            // the stored go-cohort is always current — the Deploy stage can then
            // act on the devices cleared SO FAR, mid-run, without waiting for the
            // run to finish. The same helper completes the run the moment its
            // cohort settles (or the window closes), so completion is also
            // event-driven (no up-to-60s runner lag) — on whichever path notices
            // first, this poll or the runner tick. No PreflightRunStore lease is
            // held here (get_targets/collect already released); the helper takes
            // its own.
            const std::int64_t t = now_ms();
            const bool past_deadline = t >= run.deadline_at_ms;
            if (run_store_ && preflight::persist_and_maybe_complete(*run_store_, run.run_id, grid, t,
                                                                    past_deadline, any_pending))
                running = false; // settled/closed this pass → render Complete, stop polling
        }
    } else {
        read_stored_grid();
    }

    std::string repoll;
    if (running && any_pending && attempt < kPollCap)
        repoll = "/fragments/auto/result?run=" + url_encode(run.run_id) + "&n=" +
                 std::to_string(attempt + 1);

    std::string degrade_note;
    if (degraded)
        degrade_note = "Live results temporarily unavailable (response store degraded) — "
                       "showing the last known state. Retrying automatically.";

    return render_auto_results(grid, config_summary(cfg), run.scope_label, repoll,
                               /*run_complete=*/!running, run.run_id, degrade_note);
}

} // namespace yuzu::server
