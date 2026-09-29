/// @file hardware_routes.cpp
/// /hardware route registration — the page shells + the read-only HTMX fragments +
/// the REST v1 twins (`GET /api/v1/hardware`, `GET /api/v1/hardware/{id}`), all
/// self-registered on the shared `HttpRouteSink` (the preflight_routes.cpp pattern)
/// so this module owns its own REST surface without growing rest_api_v1.cpp's
/// register_routes argument list. Renderers live in hardware_ui.cpp; query/sort/
/// filter/paginate/JSON logic in hardware_list_model.{hpp,cpp}.

#include "hardware_routes.hpp"

#include "authz_model.hpp"          // authz::in_scope
#include "http_route_sink.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error, ensure_correlation_id
#include "rest_audit.hpp"            // detail::emit_behavioral_audit, try_persist_audit

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

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
    sub("<a href=\"/guardian\" class=\"nav-link active\">Guardian</a>",
        "<a href=\"/guardian\" class=\"nav-link\">Guardian</a>");
    // The nav-sweep (10 shells) hasn't landed yet at this point in the branch history
    // in a fresh checkout of this file alone — once it has, this activates the real
    // Hardware nav link. Until then this is a silent no-op (the `sub` idiom's own
    // known failure mode), which is exactly why test_nav_shells.cpp pins it.
    sub("<a href=\"/hardware\" class=\"nav-link\">Hardware</a>",
        "<a href=\"/hardware\" class=\"nav-link active\">Hardware</a>");
    return html;
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
        send_html(res, page_shell("Yuzu \xE2\x80\x94 Hardware",
                                  "/fragments/hardware/ci?id=" + url_encode_id(id)));
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
                          "direction, OS, or status filter.</div>");
            return;
        }
        HardwareListPage page = build_hardware_list_page(std::move(scoped), *normalised);
        // DEX is scored ONLY on the page's rendered rows (device_routes.cpp's own
        // "score only rendered rows" rule) — a GROUP-BY per device is too costly to
        // run over the whole roster on every filter/sort/page click.
        if (deps_.dex_score_fn)
            for (auto& row : page.rows)
                row.dex_score = deps_.dex_score_fn(row.agent_id);

        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "inventory.devices", "success", "Inventory", "fleet",
            "hardware list: devices=" + std::to_string(page.total_matching) +
                " omitted=" + std::to_string(omitted));
        (void)persisted; // HTML fragment: set-and-proceed — the header is the signal

        const bool results_only = req.has_param("results_only") && req.get_param_value("results_only") == "1";
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
        if (!deps_.scoped_perm_fn(req, res, "Inventory", "Read", id)) return;

        const std::string lens = req.has_param("lens") ? req.get_param_value("lens") : "overview";
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
        const HwCiAffordances aff = affordances_for(req, id, detail);

        std::string verb = "inventory.device.ci";
        std::string state = !detail.ci.has_value() ? "store degraded"
                            : !detail.ci->has_value() ? "absent" : "found";
        if (lens == "software") verb = "inventory.device.software";
        (void)detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, verb, "success", "Agent", id,
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
                body = render_hardware_lens_bar(id, lens, /*oob=*/true) + body;
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
            res.set_content(detail::a4_error(res, "unrecognised sort, dir, os, or status token"),
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
        if (truly_absent) {
            res.status = 404;
            res.set_content(detail::a4_error(res, "not found"), "application/json");
            return;
        }

        std::string state = !detail.ci.has_value() ? "store degraded"
                            : !detail.ci->has_value() ? "absent" : "found";
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "inventory.device.ci", "success", "Agent", agent_id,
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
