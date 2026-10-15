/// @file hardware_routes.cpp
/// /hardware route registration — the page shells + the read-only HTMX fragments +
/// the REST v1 twins (`GET /api/v1/hardware`, `GET /api/v1/hardware/{id}`), all
/// self-registered on the shared `HttpRouteSink` (the preflight_routes.cpp pattern)
/// so this module owns its own REST surface without growing rest_api_v1.cpp's
/// register_routes argument list. Renderers live in hardware_ui.cpp; query/sort/
/// filter/paginate/JSON logic in hardware_list_model.{hpp,cpp}.

#include "hardware_routes.hpp"

#include "app_shell.hpp"
#include "authz_model.hpp"          // authz::in_scope
#include "http_route_sink.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error, ensure_correlation_id
#include "rest_audit.hpp"            // detail::emit_behavioral_audit, try_persist_audit

#include <yuzu/protective_actions.hpp> // protective::is_quarantine_control_plugin
#include <yuzu/server/auth.hpp> // auth::kMaxAgentIdLength

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>

// Shared full-page shell (defined at GLOBAL scope in guardian_page_ui.cpp).
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

void send_html(httplib::Response& res, std::string body) {
    res.set_content(std::move(body), "text/html; charset=utf-8");
}

std::string page_shell(const std::string& title, const std::string& fragment_url) {
    std::string html(kGuardianDetailPageHtml);
    auto sub = [&](const std::string& tok, const std::string& val) {
        for (auto p = html.find(tok); p != std::string::npos; p = html.find(tok, p + val.size()))
            html.replace(p, tok.size(), val);
    };
    sub("{{TITLE}}", title);
    sub("{{FRAGMENT}}", fragment_url);
    // The shared dialog module, the estate controller (quarantine, stored-data removal) and the
    // tags/properties controls load after the template's own scripts, in that order. The shell is
    // shared with pages that load none of them, so only this route family adds them.
    // Same-origin static files: the dashboard CSP needs no change.
    if (const auto end = html.rfind("</body>"); end != std::string::npos)
        html.insert(end, "<script src=\"/static/yuzu-dialog.js\" defer></script>"
                         "<script src=\"/static/yuzu-estate.js\" defer></script>"
                         "<script src=\"/static/yuzu-device-data.js\" defer></script>\n");
    // test_nav_shells.cpp pins that the shared shell carries the marker apply_shell fills.
    return shell::apply_shell(std::move(html), {.active_key = "hardware"});
}

std::string url_encode_id(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
            c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0f]);
        }
    }
    return out;
}

// Same accepted-character set + length cap as command_routes.cpp's bad_ident
// (that copy is anonymous-namespace/internal linkage, so this file defines its
// own rather than exporting a shared one) — a plugin/action string outside this
// set is refused by POST /api/command before it would ever dispatch, so an
// action row built from one is never offered a Run control (hardware_ui side)
// and a result poll naming one is rejected here too.
bool bad_hw_ident(std::string_view v) {
    constexpr std::size_t kIdentMax = 128;
    if (v.empty() || v.size() > kIdentMax)
        return true;
    return std::any_of(v.begin(), v.end(), [](unsigned char c) {
        return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                 c == '_' || c == '.' || c == '-');
    });
}

std::string hw_lens_or_overview(const std::string& raw, bool containment_ui) {
    static constexpr std::string_view kLenses[] = {"overview", "software", "tags",  "dex",
                                                   "guardian", "live",     "actions"};
    for (const auto l : kLenses)
        if (raw == l)
            return raw;
    if (containment_ui && raw == "containment")
        return raw;
    return "overview";
}

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch())
        .count();
}

HardwareListQuery query_from_request(const httplib::Request& req) {
    HardwareListQuery q;
    if (req.has_param("q")) q.q = req.get_param_value("q");
    if (req.has_param("os")) q.os = req.get_param_value("os");
    if (req.has_param("status")) q.status = req.get_param_value("status");
    if (req.has_param("sort")) q.sort = req.get_param_value("sort");
    if (req.has_param("dir")) q.desc = req.get_param_value("dir") == "desc";
    if (req.has_param("tag")) q.tag = req.get_param_value("tag");
    auto parse_u = [&](const char* name, std::size_t dflt) -> std::size_t {
        if (!req.has_param(name)) return dflt;
        try {
            long long v = std::stoll(req.get_param_value(name));
            return v < 0 ? 0 : static_cast<std::size_t>(v);
        } catch (...) { return dflt; }
    };
    q.offset = parse_u("offset", 0);
    q.limit = parse_u("limit", 50);
    return q;
}

// Assemble the operator-visible roster: the UNFILTERED roster from RosterFn, scope-
// filtered by the FleetReadGate's own scope (the SOLE filter — never double up with
// a second scope predicate). Returns the filtered roster + the drop count.
std::pair<std::vector<InventoryDeviceRow>, std::size_t>
scoped_roster(const InventoryDevicesResult& all, const authz::VisibleSet& scope) {
    std::vector<InventoryDeviceRow> out;
    std::size_t dropped = 0;
    out.reserve(all.rows.size());
    for (const auto& row : all.rows) {
        if (!authz::in_scope(scope, row.agent_id)) { ++dropped; continue; }
        out.push_back(row);
    }
    return {std::move(out), dropped};
}

// Audit-trail floor for an id taken raw from a URL: a device id reaches `target_id`
// on every audit row these routes write and on the permission-denial audit, so ids over
// kMaxAgentIdLength bytes or carrying a byte below 0x20 (CR/LF) are refused before any
// audit write. Mirrors viz_routes.cpp's agent_id floor.
bool id_is_audit_safe(const std::string& id) {
    return id.size() <= auth::kMaxAgentIdLength &&
           std::none_of(id.begin(), id.end(), [](unsigned char c) { return c < 0x20; });
}

} // namespace

HwCiAffordances HardwareRoutes::affordances_for(const httplib::Request& req, const std::string& id,
                                                const HardwareCiDetail& detail) const {
    HwCiAffordances aff;
    using S = HwSyncAffordance::State;
    const bool online = detail.identity && detail.identity->online;
    const bool can_exec = deps_.scoped_probe_fn && deps_.scoped_probe_fn(req, "Execution", "Execute", id);
    if (detail.agent_version)
        aff.sync.agent_version = *detail.agent_version;
    if (!online || !detail.agent_version)
        aff.sync.state = S::Offline;
    else if (!can_exec)
        aff.sync.state = S::NoExecute;
    else if (!agent_supports_sync_now(*detail.agent_version))
        aff.sync.state = S::Unsupported;
    else
        aff.sync.state = S::Ready;
    aff.can_write_tags = deps_.scoped_probe_fn && deps_.scoped_probe_fn(req, "Tag", "Write", id);
    aff.can_read_guaranteed_state =
        deps_.scoped_probe_fn && deps_.scoped_probe_fn(req, "GuaranteedState", "Read", id);
    aff.containment_ui = deps_.containment_ui;
    return aff;
}

void HardwareRoutes::register_routes(httplib::Server& svr, Deps deps) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(deps));
}

void HardwareRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    deps_ = std::move(deps);

    // -- Page shells (auth-only chrome; fragments carry the real gates) --
    sink.Get("/hardware", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
        if (!session) { res.set_redirect("/login"); return; }
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        send_html(res, page_shell("Yuzu \xE2\x80\x94 Hardware", "/fragments/hardware/list"));
    });

    sink.Get("/hardware/ci", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
        if (!session) { res.set_redirect("/login"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        // `lens` is forwarded so a link can open a specific lens (the row's Quarantine
        // link). It is only a hint here: the fragment applies the allowlist, and the value
        // is URL-encoded so it can never break out of the fragment URL.
        std::string fragment = "/fragments/hardware/ci?id=" + url_encode_id(id);
        if (req.has_param("lens"))
            fragment += "&lens=" + url_encode_id(req.get_param_value("lens"));
        send_html(res, page_shell("Yuzu \xE2\x80\x94 Hardware", fragment));
    });

    // -- Fragment: CI list --
    sink.Get("/fragments/hardware/list", [this](const httplib::Request& req, httplib::Response& res) {
        auto gate = deps_.fleet_read_fn ? deps_.fleet_read_fn(req, res, "Inventory", "Read")
                                       : authz::FleetReadGate{};
        if (!deps_.fleet_read_fn) {
            res.status = 503;
            send_html(res, "<div class=\"gp-placeholder\">Hardware list unavailable on this server.</div>");
            return;
        }
        if (!gate.admitted) return; // response already written by fleet_read_fn

        if (!deps_.roster_fn) {
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.devices", "failure",
                                            "Inventory", "fleet", "hardware roster provider unwired");
            send_html(res, "<div class=\"gp-placeholder\"><b>Hardware roster unavailable.</b> No "
                          "provider is wired on this server.</div>");
            return;
        }
        const InventoryDevicesResult all = deps_.roster_fn();
        auto [scoped, omitted] = scoped_roster(all, gate.scope);

        auto raw = query_from_request(req);
        auto normalised = normalise_hardware_query(raw);
        if (!normalised) {
            res.status = 400;
            send_html(res, "<div class=\"gp-placeholder\"><b>Bad request.</b> Unrecognised sort, "
                          "OS, or status filter, or invalid tag key.</div>");
            return;
        }
        const bool results_only = req.has_param("results_only") && req.get_param_value("results_only") == "1";
        if (all.roster_degraded) {
            // 200, not 5xx: htmx does not swap a failed response, so the banner
            // would never render. Mirrors the unwired arm above.
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, "inventory.devices", "failure",
                                                "Inventory", "fleet", "hardware roster read failed");
            HardwareListPage degraded;
            degraded.query = *normalised;
            degraded.containment_ui = deps_.containment_ui;
            send_html(res, render_hardware_list_fragment(degraded, false, /*roster_unavailable=*/true, results_only));
            return;
        }
        HardwareListPage page = build_hardware_list_page(std::move(scoped), *normalised);
        page.containment_ui = deps_.containment_ui;
        // DEX is scored ONLY on the page's rendered rows (device_routes.cpp's own
        // "score only rendered rows" rule) — a GROUP-BY per device is too costly to
        // run over the whole roster on every filter/sort/page click.
        if (deps_.dex_score_fn)
            for (auto& row : page.rows)
                row.dex_score = deps_.dex_score_fn(row.agent_id);

        // Quarantined pill. Phase 1 reads which of THIS PAGE's devices have an active record
        // (the read is restricted to the page's ids, so its cost is bounded by the page size
        // and nothing is shown yet). Only if there is a candidate does phase 2 make ONE
        // Security:Read list-gate decision (ADR-0017) and keep the candidates inside its
        // scope — so a caller without Security:Read, or a page with no quarantines, costs no
        // gate call and no denied audit row. The gate answers into a throwaway Response (the
        // list itself is the response): a 403 means "this caller may not see pills" and draws
        // none; an unavailable or unwired gate, or a degraded store, sets the banner flag and
        // no pill (absence is then not evidence).
        if (deps_.containment_ui && deps_.quarantine_list_fn && !page.rows.empty()) {
            std::vector<std::string> page_ids;
            page_ids.reserve(page.rows.size());
            for (const auto& row : page.rows)
                page_ids.push_back(row.agent_id);
            const auto candidates = deps_.quarantine_list_fn(&page_ids, 0);
            if (!candidates) {
                page.quarantine_degraded = true;
            } else if (!candidates->empty()) {
                httplib::Response gate_res;
                const authz::FleetReadGate qgate =
                    deps_.fleet_read_fn ? deps_.fleet_read_fn(req, gate_res, "Security", "Read")
                                        : authz::FleetReadGate{};
                if (qgate.admitted) {
                    for (const auto& r : *candidates)
                        if (authz::in_scope(qgate.scope, r.agent_id))
                            page.quarantined_ids.insert(r.agent_id);
                } else if (!deps_.fleet_read_fn || gate_res.status != 403) {
                    page.quarantine_degraded = true; // gate unwired/401/503: not a scope refusal
                }
            }
        }

        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "inventory.devices", "success", "Inventory", "fleet",
            "hardware list: devices=" + std::to_string(page.total_matching) +
                " omitted=" + std::to_string(omitted));
        (void)persisted; // HTML fragment: set-and-proceed — the header is the signal

        send_html(res, render_hardware_list_fragment(page, all.ci_degraded, false, results_only, all.tags_degraded));
    });

    // -- Fragment: CI record (overview / installed software / tags lenses) --
    sink.Get("/fragments/hardware/ci", [this](const httplib::Request& req, httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (id.empty()) {
            res.status = 400;
            send_html(res, "<div class=\"gp-placeholder\">Missing device id.</div>");
            return;
        }
        if (!id_is_audit_safe(id)) {
            res.status = 400;
            send_html(res, "<div class=\"gp-placeholder\">Invalid device id.</div>");
            return;
        }
        if (!deps_.scoped_perm_fn(req, res, "Inventory", "Read", id)) return;

        // Allowlisted: the value reaches the audit detail and echoed markup, so an unknown
        // or oversized `lens` falls back to the overview rather than being carried through.
        const std::string lens = hw_lens_or_overview(
            req.has_param("lens") ? req.get_param_value("lens") : std::string{}, deps_.containment_ui);
        const bool lens_only = req.has_param("lens_only") && req.get_param_value("lens_only") == "1";
        if (!deps_.ci_detail_fn) {
            res.status = 503;
            send_html(res, "<div class=\"gp-placeholder\">Hardware CI record unavailable on this "
                          "server.</div>");
            return;
        }
        // Sync-now poll parameters (round 2): await_since = the SERVER clock at request
        // time; n = attempt (1..30); command_id must be a __sync__- id so a guessed
        // id can't read another dispatch's result through this route.
        std::optional<std::int64_t> await_since;
        int attempt = 1;
        std::string command_id;
        if (req.has_param("await_since")) {
            try { await_since = std::stoll(req.get_param_value("await_since")); } catch (...) {}
            if (req.has_param("n")) {
                try { attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 30); } catch (...) {}
            }
            if (req.has_param("command_id")) {
                command_id = req.get_param_value("command_id");
                if (command_id.size() > 64 || !command_id.starts_with("__sync__-")) {
                    res.status = 400;
                    send_html(res, "bad request");
                    return;
                }
            }
        }

        const HardwareCiDetail detail = deps_.ci_detail_fn(id);
        HwCiAffordances aff = affordances_for(req, id, detail);
        if (lens == "tags")
            aff.can_delete_tags = deps_.scoped_probe_fn && deps_.scoped_probe_fn(req, "Tag", "Delete", id);

        std::string verb = "inventory.device.ci";
        std::string state = !detail.ci.has_value() ? "store degraded"
                            : !detail.ci->has_value() ? "absent" : "found";
        const bool no_record = !detail.identity && (!detail.ci.has_value() || !detail.ci->has_value());
        if (detail.identity_degraded && no_record)
            state = "roster unreadable";
        else if (detail.identity_degraded)
            state += " identity=roster unreadable";
        if (lens == "software") verb = "inventory.device.software";
        (void)detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, verb, detail.identity_degraded ? "failure" : "success", "Agent", id,
            "hardware CI lens=" + lens + " state=" + state +
                (await_since ? " await=" + std::to_string(attempt) : ""));

        if (await_since) {
            bool newer = true;
            if (lens == "overview" || lens.empty())
                newer = detail.ci.has_value() && detail.ci->has_value() &&
                        (**detail.ci).last_seen > *await_since;
            else if (lens == "software")
                newer = detail.software_last_seen && *detail.software_last_seen > *await_since;
            if (!newer) {
                // Early exit on an explicit refusal from the agent (e.g. a release 0.13.0
                // agent answering "plugin not found", or --inventory-disable).
                if (!command_id.empty() && deps_.responses_fn) {
                    for (const auto& r : deps_.responses_fn(command_id, id)) {
                        if (r.agent_id != id) continue;
                        if (r.status >= 2) {
                            send_html(res, render_hardware_sync_terminal(
                                               id, lens, r.output.empty() ? r.error_detail : r.output, false));
                            return;
                        }
                    }
                }
                if (attempt >= 30) {
                    send_html(res, render_hardware_sync_terminal(id, lens, "", true));
                    return;
                }
                send_html(res, render_hardware_sync_pending(id, lens, *await_since, attempt + 1, command_id));
                return;
            }
        }

        if (lens_only) {
            // Round-2 item 2: the tab bar renders once in the full record and is
            // absent from a lens-only body, so the "on" class never moved when an
            // operator clicked a different tab. Prepend it as an out-of-band swap —
            // it lives in the DOM as #hw-lens-bar and htmx patches it in place
            // alongside the innerHTML swap of #hw-ci-lens. The sync-now poll fires
            // this same lens_only path every 1-2s while waiting; it never needs the
            // bar re-swapped (the active tab hasn't changed), so it's skipped there.
            std::string body = render_hardware_lens_body(id, detail, lens, now_secs(), aff);
            if (!await_since)
                body = render_hardware_lens_bar(id, lens, /*oob=*/true, aff.containment_ui) + body;
            send_html(res, body);
        } else {
            send_html(res, render_hardware_ci_fragment(id, detail, lens, now_secs(), aff));
        }
    });

    // -- REST v1: POST /api/v1/hardware/{id}/sync — operator-requested sync-on-demand --
    // Gate = Execution:Execute scoped to the device (the same probe the Actions lens
    // uses: "make the agent run a collection now" is a device action, not an
    // inventory edit). Dispatch = SyncDispatchFn (system-reserved push, the Guardian
    // path). 202 means REQUESTED — the poll on /fragments/hardware/ci is the truth.
    sink.Post(R"(/api/v1/hardware/([^/]+)/sync)", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
        detail::ensure_correlation_id(res);
        const std::string id = req.matches[1].str();
        if (!id_is_audit_safe(id)) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "invalid device id"), "application/json");
            return;
        }
        if (!deps_.scoped_perm_fn(req, res, "Execution", "Execute", id)) return;

        std::string source = "all";
        if (!req.body.empty()) {
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded() || !body.is_object()) {
                // Counted and audited like every other refusal in this family
                // (command_routes.cpp's equivalent malformed-body check) — this path
                // used to return 400 with no audit row at all (governance Gate 8).
                (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.sync.request", "denied",
                                                "Agent", id, "malformed JSON body");
                res.status = 400;
                res.set_content(detail::a4_error(res, "body must be a JSON object"), "application/json");
                return;
            }
            // A present-but-non-string "source" (e.g. {"source":123}) used to reach
            // body.value<string>(), which THROWS nlohmann::json::type_error on a type
            // mismatch — an uncaught throw here skips the audit call entirely and
            // degrades to a bare 500 with no A4 envelope (governance Gate 4
            // unhappy-path finding). Type-check first and audit it the same as any
            // other malformed body, never let the JSON library throw past this route.
            const auto it = body.find("source");
            if (it != body.end() && !it->is_string()) {
                (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.sync.request", "denied",
                                                "Agent", id, "source field is not a string");
                res.status = 400;
                res.set_content(detail::a4_error(res, "source must be a string"), "application/json");
                return;
            }
            source = (it != body.end()) ? it->get<std::string>() : "all";
        }
        static constexpr std::string_view kSources[] = {"installed_software", "app_perf", "device_ci",
                                                        "software_licensing", "all"};
        if (std::find(std::begin(kSources), std::end(kSources), source) == std::end(kSources)) {
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.sync.request", "denied",
                                            "Agent", id, "bad source=" + source);
            res.status = 400;
            res.set_content(detail::a4_error(res, "source must be one of installed_software, app_perf, "
                                                  "device_ci, software_licensing, all"),
                            "application/json");
            return;
        }
        if (!deps_.sync_dispatch_fn || !deps_.agent_version_fn) {
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.sync.request", "failure",
                                            "Agent", id, "sync dispatch unwired");
            res.status = 503;
            res.set_content(detail::a4_error(res, "sync-on-demand is unavailable on this server",
                                             {.retry_after_ms = 5000}),
                            "application/json");
            return;
        }
        const auto version = deps_.agent_version_fn(id);
        if (!version) {
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.sync.request", "no_agents",
                                            "Agent", id, "agent_offline");
            res.status = 503;
            res.set_content(detail::a4_error(res, "agent is not connected — sync needs a live session",
                                             {.retry_after_ms = 30000}),
                            "application/json");
            return;
        }
        if (!agent_supports_sync_now(*version)) {
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.sync.request", "denied",
                                            "Agent", id,
                                            "agent_version=" + *version + " predates sync-on-demand");
            res.status = 409;
            res.set_content(detail::a4_error(res, "agent " + *version +
                                                      " predates sync-on-demand (needs 0.13.1 or "
                                                      "later); restart or upgrade the agent"),
                            "application/json");
            return;
        }
        // Audit BEFORE dispatch and fail closed on a persist failure — a sync
        // request has a real side effect on the agent, so it follows the same
        // audit-then-act, 503-on-degrade contract as every other behavioural-data
        // route in this file (see GET /api/v1/hardware above), not the "dispatch
        // first" ordering this route used to have (governance Gate 2, HIGH).
        const bool persisted = detail::emit_behavioral_audit(deps_.audit_fn, req, res,
                                                              "inventory.sync.request", "requested",
                                                              "Agent", id, "source=" + source);
        if (!persisted) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "audit subsystem unavailable — request not served",
                                             {.retry_after_ms = 5000}),
                            "application/json");
            return;
        }
        const auto r = deps_.sync_dispatch_fn(id, source);
        if (!r.sent) {
            // No second audit row here — matching the /api/v1/dex/devices/{id}/live
            // precedent this route otherwise follows: the pre-dispatch "requested"
            // row above is the durable evidence that the operator asked; whether an
            // agent was actually reached is reported by the response itself, never
            // a duplicate post-dispatch audit for the same request (governance
            // Gate 4 consistency finding — this route used to double-audit).
            res.status = 503;
            res.set_content(detail::a4_error(res, "agent is not reachable right now",
                                             {.retry_after_ms = 30000}),
                            "application/json");
            return;
        }
        nlohmann::json out = {
            {"data", {{"command_id", r.command_id},
                      {"source", source},
                      {"agents_reached", 1},
                      {"requested_at", now_secs()}}},
            {"meta", {{"api_version", "v1"}}},
        };
        res.status = 202;
        res.set_content(out.dump(), "application/json");
    });

    // -- REST v1: POST /api/v1/hardware/sync — "Sync now" for a scope (the Software page) --
    // One click, many devices. `scope` is __all__ / group:<id> / an agent id; `scope_expression`
    // is a scope DSL expression (software_sync_decision.hpp owns the request grammar and every
    // bound below).
    // GATE: the type-level Execution:Execute check (sync_perm_fn = require_permission), which reads
    // GLOBAL grants only, so an operator whose Execute is limited to management groups gets 403
    // for every scope kind. The visible-set intersection (a hidden device is dropped, never
    // reported) and the fleet-wide refusal for a filtered caller are DEFENCE IN DEPTH behind that
    // gate: with a global grant neither changes the outcome today, and they are wired for when the
    // gate becomes scope-aware.
    // REACH: this server process only. Sessions and sends are per process, so an agent attached to
    // another replica has no session here, is counted in skipped_offline with the disconnected ones
    // (this route cannot tell them apart) and is not sent to.
    // Audit BEFORE dispatch, fail closed. 202 means REQUESTED: `agents_reached` is sessions that
    // accepted the frame, not devices that have synced.
    static_assert(software_sync::kMaxIdLen == auth::kMaxAgentIdLength);
    sink.Post("/api/v1/hardware/sync", [this](const httplib::Request& req, httplib::Response& res) {
        namespace ss = software_sync;
        constexpr const char* kAction = "inventory.sync.request";
        detail::ensure_correlation_id(res);
        const auto now = [this] { return deps_.sync_now_fn ? deps_.sync_now_fn() : now_secs(); };
        if (!deps_.sync_perm_fn || !deps_.auth_fn || !deps_.sync_resolve_fn ||
            !deps_.sync_dispatch_many_fn || !deps_.sync_caller_unfiltered_fn ||
            !deps_.agent_version_fn) {
            // The derivation of "which devices may this caller sync" is this route's only
            // per-device authorization, so a missing dependency is a server misconfiguration
            // (500), not a transient outage, and it is audited. Nothing here may use the
            // dependencies that are missing; the audit sink is optional (audit-off is legal).
            (void)detail::try_persist_audit(deps_.audit_fn, req, kAction, "failure", "Scope", "",
                                            "sync fan-out unwired");
            res.status = 500;
            res.set_content(detail::a4_error(res, "sync fan-out is not configured on this server"),
                            "application/json");
            return;
        }
        if (!deps_.sync_perm_fn(req, res, "Execution", "Execute")) return;
        const auto session = deps_.auth_fn(req, res);
        if (!session) return;

        const auto parsed = ss::parse_request(nlohmann::json::parse(req.body, nullptr, false));
        if (!parsed) {
            (void)detail::try_persist_audit(deps_.audit_fn, req, kAction, "denied", "Scope", "",
                                            "bad request: " + parsed.error());
            res.status = 400;
            res.set_content(detail::a4_error(res, parsed.error()), "application/json");
            return;
        }
        const ss::Selector& sel = *parsed;
        const char* const target_type = sel.arm == DispatchArm::Ids ? "Agent" : "Scope";
        const std::string target_id = ss::target_label(sel);
        const auto refuse = [&](int status, const std::string& message, const std::string& why,
                                const detail::A4ErrorOpts& opts = {}) {
            (void)detail::try_persist_audit(deps_.audit_fn, req, kAction, "denied", target_type,
                                            target_id, why + " scope=" + ss::audit_token(sel.expr));
            res.status = status;
            res.set_content(detail::a4_error(res, message, opts), "application/json");
        };
        const auto refuse_fleet_wide = [&] {
            refuse(403, "syncing the whole fleet needs a fleet-wide Execution:Execute grant",
                   "fleet_wide_required");
        };

        // A confined caller naming the whole fleet is refused HERE: before it can take the
        // in-flight slot below and before the resolver reads the fleet. ss::decide applies the
        // same rule again to the resolver's own answer (defence in depth).
        if (sel.arm == DispatchArm::Broadcast &&
            ss::fleet_wide_denied(sel.arm, deps_.sync_caller_unfiltered_fn(*session))) {
            refuse_fleet_wide();
            return;
        }

        // Ordering: preflight 403 -> cooldown 429 -> slot 409 -> resolve -> decide -> audit ->
        // dispatch. One multi-device run at a time and one per operator per minute, both per
        // server process. The cooldown is read BEFORE the slot so a 429 never occupies it, and
        // the slot is held to the end of the handler, so the stamp after dispatch cannot
        // interleave with another run. Note the dispatch loop is sequential: a connected agent
        // that has stopped reading holds the slot (a concurrent run gets 409) until it reads or
        // disconnects; no clear time is promised.
        struct RunGuard {
            RunGuard() = default;
            RunGuard(const RunGuard&) = delete; // a copy would release the slot twice
            RunGuard& operator=(const RunGuard&) = delete;
            std::atomic<bool>* flag{nullptr};
            void release() {
                if (flag) flag->store(false);
                flag = nullptr;
            }
            ~RunGuard() { release(); }
        } run_guard;
        static_assert(!std::is_copy_constructible_v<RunGuard> && !std::is_move_constructible_v<RunGuard> &&
                          !std::is_copy_assignable_v<RunGuard> && !std::is_move_assignable_v<RunGuard>,
                      "a copied, moved or assigned guard would release the slot twice");
        const bool guarded = ss::needs_run_guard(sel.arm);
        const auto cooldown_wait = [&] {
            std::optional<std::int64_t> last;
            {
                std::lock_guard<std::mutex> lk(sync_run_mu_);
                last = ss::last_run_of(sync_last_run_, session->username);
            }
            return ss::cooldown_remaining(last, now()); // the clock is read outside the lock
        };
        const auto refuse_cooldown = [&](std::int64_t wait) {
            res.set_header("Retry-After", std::to_string(wait));
            refuse(429, "a sync run was requested a moment ago; wait " + std::to_string(wait) + "s",
                   "rate_limited cooldown=" + std::to_string(wait) + "s", {.retry_after_ms = wait * 1000});
        };
        if (guarded) {
            if (const auto wait = cooldown_wait(); wait > 0) {
                refuse_cooldown(wait);
                return;
            }
            bool idle = false;
            if (!sync_run_active_.compare_exchange_strong(idle, true)) {
                refuse(409, "another sync run is already in progress; try again in a moment",
                       "run_in_flight", {.retry_after_ms = 5000});
                return;
            }
            run_guard.flag = &sync_run_active_;
            // This operator's previous run may have stamped between the check above and taking
            // the slot. Release the slot before the refusal's audit write.
            if (const auto wait = cooldown_wait(); wait > 0) {
                run_guard.release();
                refuse_cooldown(wait);
                return;
            }
        }

        const auto resolved = deps_.sync_resolve_fn(*session, sel);
        if (resolved.status == ss::Resolved::Status::InvalidScope) {
            refuse(400, "invalid scope: " + resolved.detail, "invalid_scope");
            return;
        }
        if (resolved.status != ss::Resolved::Status::Ok) {
            // A degraded store or a failed owner check: never "no matches". Nothing was sent.
            (void)detail::try_persist_audit(deps_.audit_fn, req, kAction, "failure", target_type,
                                            target_id,
                                            "scope_unresolved reason=" + ss::audit_token(resolved.detail));
            res.status = 503;
            res.set_content(detail::a4_error(res, "the scope could not be evaluated; no device was contacted",
                                             {.retry_after_ms = 5000}),
                            "application/json");
            return;
        }

        // ponytail: one registry session lookup per candidate, so O(fleet) for __all__ before
        // the 500 cap applies; ADR-3007's paced run replaces both when the fleet outgrows it.
        std::vector<ss::Candidate> candidates;
        candidates.reserve(resolved.ids.size());
        for (const auto& id : resolved.ids)
            candidates.push_back({id, deps_.agent_version_fn(id)}); // a session on THIS process, or nullopt
        const auto plan = ss::partition(
            candidates, [](std::string_view v) { return agent_supports_sync_now(v); });

        switch (ss::decide(sel.arm, resolved.caller_unfiltered, plan.counts)) {
        case ss::Verdict::FleetWideRequired:
            refuse_fleet_wide();
            return;
        case ss::Verdict::TooMany:
            refuse(413,
                   "this would reach " + std::to_string(plan.counts.reached) + " devices; the limit is " +
                       std::to_string(ss::kMaxTargets) + " per request — narrow the scope",
                   "over_cap reached=" + std::to_string(plan.counts.reached) +
                       " cap=" + std::to_string(ss::kMaxTargets));
            return;
        case ss::Verdict::Proceed: break;
        }

        // Audit BEFORE dispatch and fail closed — same contract as the per-device route.
        if (!detail::emit_behavioral_audit(deps_.audit_fn, req, res, kAction, ss::audit_result(plan.counts),
                                           target_type, target_id, ss::audit_detail(sel, plan.counts))) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "audit subsystem unavailable — request not served",
                                             {.retry_after_ms = 5000}),
                            "application/json");
            return;
        }

        ss::DispatchResult sent;
        if (!plan.targets.empty())
            sent = deps_.sync_dispatch_many_fn(plan.targets);
        if (!plan.targets.empty() && sent.sent == 0) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "no selected device is reachable right now",
                                             {.retry_after_ms = 30000}),
                            "application/json");
            return;
        }
        if (guarded && sent.sent > 0) {
            const auto stamp_at = now(); // the clock is read outside the lock
            std::lock_guard<std::mutex> lk(sync_run_mu_);
            ss::stamp(sync_last_run_, session->username, stamp_at);
        }
        nlohmann::json out = {
            {"data", ss::summary_json(ss::finalize(plan.counts, sent.sent), sent.command_id, now())},
            {"meta", {{"api_version", "v1"}}},
        };
        res.status = 202;
        res.set_content(out.dump(), "application/json");
    });

    // -- REST v1: GET /api/v1/hardware --
    sink.Get("/api/v1/hardware", [this](const httplib::Request& req, httplib::Response& res) {
        detail::ensure_correlation_id(res);
        if (!deps_.fleet_read_fn) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "hardware service unavailable"), "application/json");
            return;
        }
        auto gate = deps_.fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted) return;

        if (!deps_.roster_fn) {
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.devices", "failure",
                                            "Inventory", "fleet", "hardware roster provider unwired");
            res.status = 503;
            res.set_content(detail::a4_error(res, "hardware roster unavailable"), "application/json");
            return;
        }
        const InventoryDevicesResult all = deps_.roster_fn();
        auto [scoped, omitted] = scoped_roster(all, gate.scope);

        auto raw = query_from_request(req);
        auto normalised = normalise_hardware_query(raw);
        if (!normalised) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "unrecognised sort, os, or status token or invalid tag key"),
                            "application/json");
            return;
        }
        if (all.roster_degraded) {
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, "inventory.devices", "failure",
                                                "Inventory", "fleet", "hardware roster read failed");
            res.status = 503;
            res.set_content(detail::a4_error(res, "hardware roster unavailable",
                                             {.retry_after_ms = 5000}),
                            "application/json");
            return;
        }
        HardwareListPage page = build_hardware_list_page(std::move(scoped), *normalised);
        if (deps_.dex_score_fn)
            for (auto& row : page.rows)
                row.dex_score = deps_.dex_score_fn(row.agent_id);

        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "inventory.devices", "success", "Inventory", "fleet",
            "hardware list (REST): devices=" + std::to_string(page.total_matching) +
                " omitted=" + std::to_string(omitted));
        if (!persisted) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "audit subsystem unavailable — request not served",
                                             {.retry_after_ms = 5000}),
                            "application/json");
            return;
        }

        nlohmann::json body = hardware_list_json(page, all.ci_degraded, omitted, all.tags_degraded);
        nlohmann::json out = {
            {"data", body},
            {"pagination", {{"total", page.total_matching}, {"start", page.query.offset},
                            {"page_size", page.query.limit}}},
            {"meta", {{"api_version", "v1"}}},
        };
        res.set_content(out.dump(), "application/json");
    });

    // -- REST v1: GET /api/v1/hardware/{id} --
    sink.Get(R"(/api/v1/hardware/([^/]+))", [this](const httplib::Request& req, httplib::Response& res) {
        detail::ensure_correlation_id(res);
        if (!deps_.fleet_read_fn) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "hardware service unavailable"), "application/json");
            return;
        }
        auto gate = deps_.fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted) return;

        const std::string agent_id = req.matches[1].str();
        if (!id_is_audit_safe(agent_id)) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "invalid device id"), "application/json");
            return;
        }
        if (!authz::in_scope(gate.scope, agent_id)) {
            // Out-of-scope collapses to the same "not found" as a genuinely
            // nonexistent id — the SAME 404 existence-oracle closure
            // `/api/v1/devices/{id}` uses (rest_api_v1.cpp). Audit posture
            // deliberately DIFFERS from that sibling, though: this route DOES
            // audit on success below (the CI blob carries ADR-0016
            // GDPR-classified serial/UUID/MAC), where /api/v1/devices/{id} does
            // not (device identity/tags alone are machine metadata) — the parity
            // claim here is scoped to the 404 shape only.
            res.status = 404;
            res.set_content(detail::a4_error(res, "not found"), "application/json");
            return;
        }
        if (!deps_.ci_detail_fn) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "hardware CI record unavailable"), "application/json");
            return;
        }
        const HardwareCiDetail detail = deps_.ci_detail_fn(agent_id);
        const bool truly_absent = !detail.identity &&
                                  (!detail.ci.has_value() ? false : !detail.ci->has_value()) &&
                                  (!detail.software || detail.software->empty()) &&
                                  (!detail.tags || detail.tags->empty());
        if (truly_absent && detail.identity_degraded) {
            // A failed roster read is never a 404 (#5531).
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, "inventory.device.ci", "failure",
                                                "Agent", agent_id,
                                                "hardware CI record (REST) state=roster unreadable");
            res.status = 503;
            res.set_content(detail::a4_error(res, "hardware roster unavailable",
                                             {.retry_after_ms = 5000}),
                            "application/json");
            return;
        }
        if (truly_absent) {
            res.status = 404;
            res.set_content(detail::a4_error(res, "not found"), "application/json");
            return;
        }

        std::string state = !detail.ci.has_value() ? "store degraded"
                            : !detail.ci->has_value() ? "absent" : "found";
        if (detail.identity_degraded)
            state += " identity=roster unreadable";
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "inventory.device.ci", detail.identity_degraded ? "failure" : "success",
            "Agent", agent_id,
            "hardware CI record (REST) state=" + state);
        if (!persisted) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "audit subsystem unavailable — request not served",
                                             {.retry_after_ms = 5000}),
                            "application/json");
            return;
        }

        nlohmann::json out = {
            {"data", hardware_ci_json(detail, now_secs())},
            {"meta", {{"api_version", "v1"}}},
        };
        res.set_content(out.dump(), "application/json");
    });

    // -- Fragment: Actions lens (the generic action runner catalogue) --
    // Dispatch itself is NOT a route here — the `hwRunAction` JS helper
    // (guardian_page_ui.cpp) posts straight to the EXISTING `POST /api/command`
    // route, so classify/authorize/destructive-gate/audit/executions-tracking all
    // apply with zero duplication, and that route IS the REST twin of "run an
    // action" by construction.
    sink.Get("/fragments/hardware/ci/actions", [this](const httplib::Request& req,
                                                      httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (id.empty()) { res.status = 400; send_html(res, "bad request"); return; }
        if (!id_is_audit_safe(id)) {
            res.status = 400;
            send_html(res, "<div class=\"gp-placeholder\">Invalid device id.</div>");
            return;
        }
        if (!deps_.scoped_perm_fn(req, res, "Inventory", "Read", id)) return;

        if (!deps_.scoped_probe_fn || !deps_.scoped_probe_fn(req, "Execution", "Execute", id)) {
            send_html(res, render_hardware_actions_lens(id, id, {}, HwActionsState::NoExecute));
            return;
        }
        if (!deps_.actions_fn) {
            send_html(res, render_hardware_actions_lens(id, id, {}, HwActionsState::Unavailable));
            return;
        }
        auto plugins = deps_.actions_fn(id);
        if (!plugins) {
            send_html(res, render_hardware_actions_lens(id, id, {}, HwActionsState::Offline));
            return;
        }

        std::string hostname = id;
        std::string agent_os;
        if (deps_.ci_detail_fn) {
            auto ident = deps_.ci_detail_fn(id).identity;
            if (ident) {
                if (!ident->hostname.empty()) hostname = ident->hostname;
                agent_os = ident->os;
            }
        }

        std::vector<HwActionRow> rows;
        for (const auto& plugin : *plugins) {
            std::unordered_map<std::string, std::string> schemas =
                deps_.schema_fn ? deps_.schema_fn(plugin.name)
                                : std::unordered_map<std::string, std::string>{};
            const std::optional<std::string> manifest =
                deps_.manifest_fn ? deps_.manifest_fn(plugin.name) : std::nullopt;
            for (const auto& action : plugin.actions) {
                // Hidden with the rest of the containment UI: a Run button on the quarantine
                // plugin's own actions is a quarantine control. REST, MCP and the Instructions
                // page are unchanged.
                if (!deps_.containment_ui &&
                    yuzu::protective::is_quarantine_control_plugin(plugin.name, action))
                    continue;
                HwActionRow row;
                row.plugin = plugin.name;
                row.action = action;
                row.bad_ident = bad_hw_ident(plugin.name) || bad_hw_ident(action);
                if (deps_.action_descriptions) {
                    auto it = deps_.action_descriptions->find(plugin.name + "." + action);
                    if (it != deps_.action_descriptions->end())
                        row.description = it->second;
                }
                if (!row.bad_ident && deps_.classify_fn) {
                    auto cap = deps_.classify_fn(plugin.name, action);
                    if (cap) row.cap = *cap;
                    else row.ambiguous = cap.error() == ClassificationError::Ambiguous;
                }
                if (row.cap) {
                    auto s_it = schemas.find(action);
                    if (s_it != schemas.end())
                        row.form = parse_action_form_spec(s_it->second);
                    // Parameter hints (round 2): the plugin-docs manifest's inputs[] +
                    // captured example. Also supplies typed fields when this deployment's
                    // store has no enabled definition for the action.
                    if (manifest)
                        apply_manifest_hints(row.form, *manifest, action, agent_os);
                }
                rows.push_back(std::move(row));
            }
        }
        (void)detail::try_persist_audit(deps_.audit_fn, req, "hardware.actions.view", "success",
                                        "Agent", id,
                                        "actions catalogue: " + std::to_string(rows.size()) + " rows");
        send_html(res, render_hardware_actions_lens(id, hostname, rows, HwActionsState::Ready));
    });

    // -- Fragment: dispatch-result poll for the Actions lens --
    sink.Get("/fragments/hardware/ci/result", [this](const httplib::Request& req,
                                                     httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        const std::string command_id = req.has_param("command_id") ? req.get_param_value("command_id") : "";
        const std::string plugin = req.has_param("plugin") ? req.get_param_value("plugin") : "";
        if (id.empty()) { res.status = 400; send_html(res, "bad request"); return; }
        if (!id_is_audit_safe(id)) {
            res.status = 400;
            send_html(res, "<div class=\"gp-placeholder\">Invalid device id.</div>");
            return;
        }
        if (!deps_.scoped_perm_fn(req, res, "Inventory", "Read", id)) return;

        if (bad_hw_ident(plugin) || command_id.size() > 64 ||
            !command_id.starts_with(plugin + "-")) {
            res.status = 400;
            send_html(res, "bad request");
            return;
        }
        int attempt = 1;
        if (req.has_param("n")) {
            try { attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 50); } catch (...) {}
        }
        if (!deps_.scoped_probe_fn || !deps_.scoped_probe_fn(req, "Execution", "Execute", id)) {
            send_html(res, "<div class=\"gp-placeholder\">Running actions needs the "
                          "<b>Execute</b> permission for this device.</div>");
            return;
        }
        if (!deps_.responses_fn) {
            send_html(res, "<div class=\"gp-mute\">Result polling unavailable on this server.</div>");
            return;
        }
        const auto rows = deps_.responses_fn(command_id, id);
        const DexAgentResponse* with_output = nullptr;
        const DexAgentResponse* terminal = nullptr;
        for (const auto& r : rows) {
            if (r.agent_id != id) continue; // another agent's rows are never rendered here
            if (!r.output.empty()) with_output = &r;
            if (r.status >= 1) terminal = &r; // 1=SUCCESS, 2+=FAILURE/TIMEOUT/REJECTED
        }

        HwActionResultView view;
        view.attempt = attempt;
        if (with_output && with_output->status == 1) {
            view.phase = HwActionResultView::Phase::Rendered;
            view.output = with_output->output;
        } else if (terminal && terminal->status == 1) {
            view.phase = HwActionResultView::Phase::RenderedEmpty;
        } else if (terminal) {
            view.phase = HwActionResultView::Phase::Failed;
            view.error_detail = terminal->error_detail;
        } else if (attempt >= 40) {
            view.phase = HwActionResultView::Phase::TimedOut;
        } else {
            send_html(res, render_hardware_result_pending(id, command_id, plugin, attempt + 1));
            return;
        }

        (void)detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "hardware.action.result", "success", "Agent", id,
            plugin + " command_id=" + command_id + " phase=" +
                std::to_string(static_cast<int>(view.phase)));
        // action name isn't carried on the wire (only plugin + command_id are, to
        // keep the poll URL short) — the panel only needs it for the RenderedEmpty
        // caption, so an empty string there is a cosmetic-only gap.
        send_html(res, render_hardware_action_result(plugin, "", view));
    });
}

} // namespace yuzu::server
