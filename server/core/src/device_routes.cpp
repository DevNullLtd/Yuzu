/// @file device_routes.cpp
/// Route registration for the shared device surfaces — `/devices` (list) +
/// `/device?id=` (the entity page) page shells, and the read-only HTMX fragments.
/// Renderers live in device_ui.cpp. SLICE 1 is auth-only (matches the current
/// agent-list posture); later slices add the perm/privacy gates for the behavioural
/// DEX lens + the live pull (see device_routes.hpp header).

#include "device_routes.hpp"

#include "authz_model.hpp"            // authz::VisibleSet / authz::in_scope
#include "live_model.hpp"             // the ONE live-read kind table + parsers (pure; #2146)
#include "http_route_sink.hpp"
#include "rest_a4_envelope_http.hpp"  // detail::a4_denial
#include "rest_audit.hpp"             // detail::emit_behavioral_audit (Sec-Audit-Failed, #1647)
#include "web_utils.hpp"              // html_escape

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool matches(const DeviceRow& d, const std::string& q) {
    if (q.empty()) return true;
    // ADR-0031 WS-A4 wave 2: `segment` is gone (never assigned). This predicate
    // is LIST-ONLY — its sole caller is the /fragments/devices/list handler over
    // `to_device_row` output, whose `tags` is always empty (DeviceApi has no bulk
    // scopable-tags read), so list search is honestly narrower now (identity
    // fields only). The single-device page/info path populates `tags` in get_one
    // and never flows through here. See device_routes.hpp's DeviceRow doc comment.
    std::string hay = to_lower(d.hostname + " " + d.agent_id + " " + d.os + " " + d.arch);
    for (const auto& t : d.tags) hay += " " + to_lower(t);
    return hay.find(q) != std::string::npos;
}

using yuzu::server::live::LiveKind;

// An htmx out-of-band swap that fills a card count-badge / KPI tile already in the DOM.
// `cls` matches the placeholder element's class so styling survives the swap.
std::string oob(const std::string& id, const std::string& cls, const std::string& text) {
    return "<span class=\"" + cls + "\" id=\"" + id + "\" hx-swap-oob=\"true\">" + text + "</span>";
}

// Render the card body for `kind`: the typed rows come from the pure live_model.hpp
// parsers (the same unit the REST route uses), then the matching device_ui.cpp renderer
// runs and the OOB count-badge + KPI updates are appended. `output2` carries the
// optional joined dataset (process_tree's connections). `agent_os` is the device
// record's OS (authoritative for same-arity service-row shapes, K-4); empty when the
// lookup was unavailable. All agent fields are HTML-escaped at render.
std::string render_live_result(const std::string& kind, const LiveKind& lk,
                               const std::string& output, const std::string& output2,
                               const std::string& agent_os = "") {
    namespace live = yuzu::server::live;

    if (kind == "uptime") { // KPI-only (the shell's hidden loader fills the Uptime KPI)
        const auto u = live::parse_uptime(output);
        const std::string v = u.display.value_or("");
        return oob("ls-kpi-uptime", "n", v.empty() ? "&mdash;" : html_escape(v));
    }

    if (kind == "processes") { // legacy flat hashed list (retained for REST/scripted callers)
        std::vector<LiveProcess> procs;
        for (const auto& p : live::parse_processes(output))
            procs.push_back(LiveProcess{static_cast<int>(p.pid), p.name, p.sha256, p.path});
        return render_device_live_processes(procs);
    }

    if (kind == "process_tree") { // proc|pid|ppid|name|sha256|path (+ conn| join)
        const auto nodes = live::parse_process_tree(output);
        const auto conns = live::parse_process_conns(output2);
        std::string body = render_device_live_tree(nodes, conns);
        body += oob("ls-cnt-process_tree", "ls-cnt", std::to_string(nodes.size()));
        body += oob("ls-kpi-procs", "n", std::to_string(nodes.size()));
        return body;
    }

    if (kind == "services") { // Windows: svc|name|display|status|startup; Linux: svc|name|status|desc; macOS: svc|label|pid|status|startup
        const auto svc = live::parse_services(output, agent_os);
        std::string body = render_device_live_services(svc.rows);
        body += oob("ls-cnt-services", "ls-cnt",
                    std::to_string(svc.rows.size()) + " &middot; " + std::to_string(svc.running) +
                        " run");
        body += oob("ls-kpi-svc", "n", std::to_string(svc.running));
        return body;
    }

    if (kind == "users") { // user|user|host|logon_type|tty
        const auto rows = live::parse_users(output);
        std::string body = render_device_live_users(rows);
        body += oob("ls-cnt-users", "ls-cnt", std::to_string(rows.size()));
        body += oob("ls-kpi-users", "n", std::to_string(rows.size()));
        return body;
    }

    if (kind == "netconfig") { // ip|adapter|addr|prefix|gateway
        const auto rows = live::parse_netconfig(output);
        std::string body = render_device_live_netconfig(rows);
        body += oob("ls-cnt-netconfig", "ls-cnt", std::to_string(rows.size()));
        return body;
    }

    if (kind == "arp") { // arp|iface|ip|mac|type
        const auto rows = live::parse_arp(output);
        std::string body = render_device_live_arp(rows);
        body += oob("ls-cnt-arp", "ls-cnt", std::to_string(rows.size()));
        return body;
    }

    if (kind == "dns_cache") { // cache_entry|name|type|...
        const auto rows = live::parse_dns_cache(output);
        std::string body = render_device_live_dns(rows);
        body += oob("ls-cnt-dns_cache", "ls-cnt", std::to_string(rows.size()));
        return body;
    }

    if (kind == "listening") { // listen|tcp|ip|port|pid
        const auto rows = live::parse_listening(output);
        std::string body = render_device_live_listening(rows);
        body += oob("ls-cnt-listening", "ls-cnt", std::to_string(rows.size()));
        body += oob("ls-kpi-listen", "n", std::to_string(rows.size()));
        return body;
    }

    if (kind == "connections") { // conn|tcp|lip|lport|rip|rport|pid
        const auto rows = live::parse_connections(output);
        std::string body = render_device_live_connections(rows);
        body += oob("ls-cnt-connections", "ls-cnt", std::to_string(rows.size()));
        body += oob("ls-kpi-conn", "n", std::to_string(rows.size()));
        return body;
    }

    if (kind == "capture_sources") { // echo status: config|<src>_enabled|v, config|<src>_rows|N
        const auto src = live::parse_capture_sources(output);
        std::string body = render_device_live_capture_sources(src.rows);
        body += oob("ls-cnt-capture_sources", "ls-cnt",
                    std::to_string(src.on) + " of " + std::to_string(src.rows.size()) + " on");
        return body;
    }

    if (kind == "disk") { // disk|<path>|<total_bytes>|<free_bytes>|<percent_used>
        const auto disks = live::parse_disk(output);
        std::string body = render_device_live_disk(disks.rows);
        body += oob("ls-cnt-disk", "ls-cnt", std::to_string(disks.rows.size()));
        // worst_used < 0 = no measured volume; else the KPI shows the free share of the
        // fullest measured volume.
        body += oob("ls-kpi-disk", "n",
                    disks.worst_used < 0 ? "&mdash;"
                                         : std::to_string(100 - disks.worst_used) + "%");
        return body;
    }

    // The ten physical-kit panels: each is a flat `<row_prefix>|field1|field2|...` table
    // with no bespoke parsing, so lk.columns (populated only for these kinds, see the
    // live_model.cpp kind table) drives one generic parser and one shared renderer instead
    // of one render_device_live_KIND function per kind.
    if (!lk.columns.empty()) {
        const auto g = live::parse_generic_rows(lk, output);
        std::string body = render_device_live_generic(lk.columns, g.rows, g.raw_rows);
        body += oob("ls-cnt-" + kind, "ls-cnt", std::to_string(g.rows.size() + g.raw_rows.size()));
        return body;
    }

    return "<div class=\"gp-note\">Unsupported live result.</div>";
}

} // namespace

// ── Shared REST+MCP JSON builders (#4033/#2146 Batch A) — see the doc
// comments in device_routes.hpp. Pure: no httplib.h, no I/O.
nlohmann::json device_agent_row_json(const DeviceListRow& row) {
    return {
        {"agent_id", row.agent_id},
        {"hostname", row.hostname},
        {"os", row.os},
        {"arch", row.arch},
        {"agent_version", row.agent_version},
        // #2240: the key is ALWAYS present. JSON null = not reported (never "legacy"); the
        // value, when present, is already one of the server's closed token strings.
        {"guardian_backend", row.guardian_backend ? nlohmann::json(*row.guardian_backend)
                                                  : nlohmann::json(nullptr)},
    };
}

nlohmann::json device_agent_detail_json(const DeviceDetail& detail) {
    auto obj = device_agent_row_json(detail.row);
    auto tag_arr = nlohmann::json::array();
    for (const auto& t : detail.tags)
        tag_arr.push_back({{"key", t.key}, {"value", t.value}, {"source", t.source}});
    obj["tags"] = std::move(tag_arr);
    return obj;
}

void DeviceRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                   ScopedPermFn scoped_perm_fn, std::shared_ptr<const DeviceApi> api,
                                   VisibleSetFn visible_set_fn, DexScoreFn dex_score_fn,
                                   DispatchFn dispatch_fn, ResponsesFn responses_fn,
                                   AuditFn audit_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(scoped_perm_fn),
                    std::move(api), std::move(visible_set_fn), std::move(dex_score_fn),
                    std::move(dispatch_fn), std::move(responses_fn), std::move(audit_fn));
}

void DeviceRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                   ScopedPermFn scoped_perm_fn, std::shared_ptr<const DeviceApi> api,
                                   VisibleSetFn visible_set_fn, DexScoreFn dex_score_fn,
                                   DispatchFn dispatch_fn, ResponsesFn responses_fn,
                                   AuditFn audit_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    api_ = std::move(api);
    visible_set_fn_ = std::move(visible_set_fn);
    dex_score_fn_ = std::move(dex_score_fn);
    dispatch_fn_ = std::move(dispatch_fn);
    responses_fn_ = std::move(responses_fn);
    audit_fn_ = std::move(audit_fn);

    // -- /devices page shell (auth-only static chrome) --
    // Round-3 merge: /devices and /device?id= are retired in favour of the Hardware
    // CI list and record, which now cover everything these pages showed (DEX score,
    // agent version, and the DEX/Guardian/Live lenses reuse these very fragments —
    // see hardware_ui.cpp's render_hardware_lens_body). 302s, not route removal, so
    // bookmarks and the API-parity ledger's history stay intact; every
    // /fragments/device/* route below stays registered and gated exactly as before.
    sink.Get("/devices", [this](const httplib::Request& req, httplib::Response& res) {
        if (!auth_fn_(req, res)) {
            res.set_redirect("/login");
            return;
        }
        res.set_redirect("/hardware");
    });

    sink.Get("/device", [this](const httplib::Request& req, httplib::Response& res) {
        if (!auth_fn_(req, res)) {
            res.set_redirect("/login");
            return;
        }
        std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        std::string loc = "/hardware/ci";
        if (!id.empty()) {
            std::string enc;
            static const char* kHex = "0123456789ABCDEF";
            for (unsigned char c : id) {
                if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                    enc += static_cast<char>(c);
                else { enc += '%'; enc += kHex[c >> 4]; enc += kHex[c & 0x0F]; }
            }
            loc += "?id=" + enc;
        }
        res.set_redirect(loc.c_str());
    });

    // Convert one DeviceApi LIST row into the dashboard's richer render struct —
    // see device_routes.hpp's DeviceRow doc comment for exactly what is/isn't
    // reproduced (online/last_seen are byte-identical constants; segment is
    // gone; `tags` is left empty here — the list path has no per-row tags; the
    // single-device page/info path populates it separately in get_one).
    auto to_device_row = [](const DeviceListRow& r) {
        DeviceRow d;
        d.agent_id = r.agent_id;
        d.hostname = r.hostname;
        d.os = r.os;
        d.arch = r.arch;
        d.agent_version = r.agent_version;
        d.online = true;
        d.last_seen = "now";
        return d;
    };

    // -- /fragments/devices/list — global Infrastructure:Read + per-operator scope.
    // Exact /api/agents parity: the gate admits Infrastructure:Read operators and
    // the caller's OWN confinement filter (visible_set_fn_, applied via
    // authz::in_scope over api_->list_devices_basic()'s unscoped rows, ADR-0031 WS-A4
    // wave 2) admits only the caller's visible devices, so an operator never
    // enumerates devices outside their scope. --
    sink.Get("/fragments/devices/list", [this, to_device_row](const httplib::Request& req,
                                                              httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        // Fleet-wide identity/inventory disclosure (SEC-2/SEC-3 confinement-gap
        // class, found during a docs sweep): api_->list_devices_basic() below is
        // fleet-wide/UNSCOPED (see device_api.hpp's own banner) and does not by
        // itself confine a service-scoped API token whose principal resolves to
        // an unscoped grant — the full device roster (hostname, agent_id, OS,
        // online state) would still be fleet-wide.
        if (!session->token_scope_service.empty()) {
            // Write the 403 FIRST, audit after (normalized — #3167).
            // `.permission` omitted: kServiceScopeGlobalSafe is
            // compile-time-empty, so no grant admits a service-scoped caller
            // here; naming one would be a false self-remediation claim.
            res.status = 403;
            res.set_content(
                detail::a4_denial(
                    res, 403, "service-scoped tokens may not read the fleet-wide device list"),
                "application/json");
            (void)detail::try_persist_audit(
                audit_fn_, req, "device.list.view", "denied", "Infrastructure", "",
                "fleet-wide device list denied to a service-scoped token");
            return;
        }
        if (!perm_fn_(req, res, "Infrastructure", "Read")) return;
        // Confinement: an unwired visible_set_fn_ fails CLOSED (present-empty,
        // deny-all) rather than nullopt (unfiltered) — the same fail-safe the
        // old DevicesFn's "empty closure -> honest 'unavailable'" contract gave.
        std::optional<std::set<std::string>> vis =
            visible_set_fn_ ? visible_set_fn_(session->username)
                            : std::optional<std::set<std::string>>{std::set<std::string>{}};
        authz::VisibleSet scope =
            vis ? authz::VisibleSet{std::unordered_set<std::string>(vis->begin(), vis->end())}
                : std::nullopt;
        std::vector<DeviceRow> all;
        if (api_) {
            // The basic list: this fragment never renders the per-device backend, so it must
            // not pay the health-store read for it (and cannot carry it by construction).
            for (const auto& r : api_->list_devices_basic()) {
                if (!authz::in_scope(scope, r.agent_id)) continue;
                all.push_back(to_device_row(r));
            }
        }
        const std::string q = to_lower(req.has_param("q") ? req.get_param_value("q") : "");
        std::string os = req.has_param("os") ? req.get_param_value("os") : "all";
        std::string status = req.has_param("status") ? req.get_param_value("status") : "all";
        if (os.empty()) os = "all";
        if (status.empty()) status = "all";

        std::size_t total = all.size();
        std::size_t online = static_cast<std::size_t>(
            std::count_if(all.begin(), all.end(), [](const DeviceRow& d) { return d.online; }));

        std::vector<DeviceRow> rows;
        for (auto& d : all) {
            if (os != "all" && to_lower(d.os) != to_lower(os) &&
                !(os == "macos" && (d.os == "darwin")))
                continue;
            if (status == "online" && !d.online) continue;
            if (status == "offline" && d.online) continue;
            if (!matches(d, q)) continue;
            rows.push_back(d);
        }
        std::sort(rows.begin(), rows.end(), [](const DeviceRow& a, const DeviceRow& b) {
            return (a.hostname.empty() ? a.agent_id : a.hostname) <
                   (b.hostname.empty() ? b.agent_id : b.hostname);
        });
        // Score ONLY the rows we render (post-filter) — never the whole fleet,
        // so a filtered/searched list never pays for the devices it excludes.
        // (Fleet-scale pagination of this set is a tracked follow-up; the win
        // here is killing the score-all-then-filter waste.)
        if (dex_score_fn_) {
            for (auto& d : rows)
                d.dex_score = dex_score_fn_(d.agent_id);
        }
        res.set_content(render_devices_list_fragment(rows, req.has_param("q") ? req.get_param_value("q") : "",
                                                     os, status, online, total),
                        "text/html; charset=utf-8");
    });

    // Resolve one device's identity row via the O(1) point lookup. Authz is the
    // scoped_perm_fn_ gate each per-device route runs FIRST; this is the
    // post-authz row fetch. It must NOT re-apply list scoping (the list filter
    // above is a flat visible-set membership test with no ancestor walk,
    // whereas require_scoped_permission IS ancestor-aware — re-scoping here
    // would 404 a parent-group-authorized device). Tri-state result:
    // kDegraded (backing tag-store read failed — the device DOES resolve),
    // engaged-empty (genuine miss), or a row.
    auto get_one = [this, to_device_row](const std::string& id)
        -> std::expected<std::optional<DeviceRow>, DeviceReadError> {
        if (!api_) return std::optional<DeviceRow>{std::nullopt};
        auto result = api_->lookup_device(id);
        if (!result) return std::unexpected(result.error());
        if (!*result) return std::optional<DeviceRow>{std::nullopt};
        DeviceRow d = to_device_row((*result)->row);
        // ADR-0031 WS-A4 (governance happy-path): restore the page/info "Tags"
        // field from the DeviceApi detail — TagStore-sourced (the seam's chosen
        // single tag source, a superset of the registry scopable_tags), rendered
        // "key=value" exactly as the pre-rewire provider did. The LIST path stays
        // tagless (DeviceApi has no bulk all-agents tag read); only this
        // single-device path has the detail's tags in hand at zero extra cost.
        for (const auto& t : (*result)->tags)
            d.tags.push_back(t.value.empty() ? t.key : (t.key + "=" + t.value));
        return std::optional<DeviceRow>{std::move(d)};
    };

    // -- /fragments/device/page (the full page body: identity + lens tabs + lens) --
    sink.Get("/fragments/device/page", [this, get_one](const httplib::Request& req,
                                                       httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // Per-device scope: Infrastructure:Read for THIS device (tier + management
        // group, ancestor-aware). 403 = outside scope; an in-scope-but-absent device
        // falls through to the honest not-found body below.
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", id)) return;
        auto result = get_one(id);
        if (!result) {
            res.set_content(render_device_degraded(id), "text/html; charset=utf-8");
            return;
        }
        auto d = *result;
        // Score ONLY this device (a page open must not pay an N-device cost —
        // the score badge needs just this one).
        if (d && dex_score_fn_)
            d->dex_score = dex_score_fn_(d->agent_id);
        res.set_content(d ? render_device_page(*d) : render_device_not_found(id),
                        "text/html; charset=utf-8");
    });

    // -- /fragments/device/info (the Device-info lens, for tab switching) --
    sink.Get("/fragments/device/info", [this, get_one](const httplib::Request& req,
                                                       httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", id)) return; // per-device scope
        auto result = get_one(id);
        if (!result) {
            res.set_content(render_device_degraded(id), "text/html; charset=utf-8");
            return;
        }
        auto d = *result;
        res.set_content(d ? render_device_info_fragment(*d) : render_device_not_found(id),
                        "text/html; charset=utf-8");
    });

    // (DEX + Guardian device lenses — `/fragments/device/dex`,
    // `/fragments/device/guardian` — moved to device_lens_routes.{hpp,cpp};
    // ADR-0031 WS-A4 wave 2, see that file's own banner for why they live
    // outside this family's seam-closure enforced set. server.cpp registers
    // `DeviceLensRoutes` alongside `DeviceRoutes`.)

    // -- "Get live info": dispatch REAL plugin instructions at the device NOW and
    // poll the response store for the result. NOT the 30s heartbeat, NOT the
    // warehouse — each panel runs an instruction that queries the live OS. The
    // shell embeds one auto-loading panel per kind; each panel hx-gets .../run
    // (which dispatches + returns a polling div) and the div polls .../result.
    //
    // Posture mirrors the DEX device-perf dispatch (dex_routes.cpp): auth, then
    // an Execute PROBE against a throwaway response (htmx swallows a raw 403, so
    // a read-only operator gets an honest in-panel note instead), then dispatch
    // through the shared chokepoint, audited per-kind.
    auto note = [](httplib::Response& res, const std::string& text) {
        res.set_content("<div class=\"gp-note\">" + text + "</div>", "text/html; charset=utf-8");
    };
    auto can_execute = [this](const httplib::Request& req, const std::string& id) {
        httplib::Response probe; // throwaway: htmx swallows a raw 403, so probe -> note
        return scoped_perm_fn_ && scoped_perm_fn_(req, probe, "Execution", "Execute", id);
    };
    auto url_enc = [](const std::string& s) {
        static const char* kHex = "0123456789ABCDEF";
        std::string out;
        for (unsigned char c : s) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                out += static_cast<char>(c);
            else { out += '%'; out += kHex[c >> 4]; out += kHex[c & 0x0F]; }
        }
        return out;
    };
    // `kind` is already validated against the allowlist before this is called.
    // `command_id2` carries the optional secondary dispatch (process_tree's
    // connections); empty when the kind has no join.
    auto live_pending = [url_enc](const std::string& command_id, const std::string& command_id2,
                                  const std::string& agent_id, const std::string& kind, int attempt) {
        std::string u = "/fragments/device/live/result?command_id=" + url_enc(command_id) +
                        "&amp;agent_id=" + url_enc(agent_id) + "&amp;kind=" + url_enc(kind) +
                        "&amp;n=" + std::to_string(attempt);
        if (!command_id2.empty())
            u += "&amp;command_id2=" + url_enc(command_id2);
        return "<div hx-get=\"" + u +
               "\" hx-trigger=\"load delay:700ms\" hx-swap=\"outerHTML\" class=\"gp-note\">"
               "Waiting for the device to respond&hellip;</div>";
    };

    // Shell: a header + one auto-loading panel per live instruction. Probe Execute once
    // here (LOW, review #1585): a read-only operator (Read but not Execute) would
    // otherwise get the full nine-card interactive shell — each card then degrading to a
    // permission note on /run — which reveals the behavioral categories the product can
    // enumerate. Render a single placeholder instead when Execute is absent.
    sink.Get("/fragments/device/live", [this, note, can_execute](const httplib::Request& req,
                                                                 httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // Per-device live surface: scoped Read floor (the run panels re-gate Read +
        // Execute per dispatch). 403 = outside the caller's management scope.
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        if (!can_execute(req, id)) {
            note(res, "Live device info needs the <b>Execute</b> permission &mdash; it runs "
                      "read-only instructions on the device.");
            return;
        }
        res.set_content(render_device_live_shell(id), "text/html; charset=utf-8");
    });

    // Run: validate kind (allowlist) -> Execute probe -> dispatch -> audit -> poll.
    sink.Get("/fragments/device/live/run", [this, note, can_execute, live_pending](
                                               const httplib::Request& req,
                                               httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        const std::string kind = req.has_param("kind") ? req.get_param_value("kind") : "";
        // Per-device scoped Read floor (tier + management group for THIS device);
        // the Execute probe below is the soft, htmx-friendly note for a read-only
        // operator. Gate before any dispatch so an out-of-scope agent_id is refused.
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        const auto lk = yuzu::server::live::resolve_dashboard_kind(kind);
        if (!lk || id.empty()) { res.status = 400; res.set_content("bad request", "text/plain"); return; }
        if (!can_execute(req, id)) {
            note(res, "Live device info needs the <b>Execute</b> permission &mdash; it runs a "
                      "read-only instruction on the device.");
            return;
        }
        if (!dispatch_fn_ || !responses_fn_) {
            note(res, "Live device query unavailable on this server.");
            return;
        }
        const auto dispatch_outcome =
            dispatch_fn_(lk->plugin, lk->action, {id}, "", {});
        const auto& command_id = dispatch_outcome.command_id;
        const auto sent = dispatch_outcome.sent;
        // Optional SECONDARY dispatch joined at render (process_tree -> connections).
        // Dispatched to the SAME device; the result route polls it best-effort.
        std::string command_id2;
        if (!lk->plugin2.empty() && sent > 0) {
            const auto outcome2 = dispatch_fn_(lk->plugin2, lk->action2, {id}, "", {});
            if (outcome2.sent > 0)
                command_id2 = outcome2.command_id;
        }
        // Audit the DISPATCH (post-dispatch "dispatched"/"no_agents"). HIGH-1 (review
        // #1585): AuditFn is bool-returning — surface Sec-Audit-Failed so an audit-store
        // outage is visible to a SIEM instead of silently swallowed (the dashboard
        // fragment still renders; the REST sibling fails closed). Routed through the
        // shared #1647 chokepoint so a THROWING audit_fn is caught here too (catch-arm
        // parity) rather than escaping the handler. NOTE (#1549): the REST sibling audits
        // "requested" PRE-dispatch; aligning this dashboard path to pre-dispatch is a
        // tracked follow-up — until then a result= query for device.live.* must match
        // BOTH "dispatched" and "requested".
        (void)detail::emit_behavioral_audit(
            audit_fn_, req, res, lk->audit_action, sent > 0 ? "dispatched" : "no_agents", "Agent",
            id,
            lk->plugin + "/" + lk->action +
                (lk->plugin2.empty() ? "" : " + " + lk->plugin2 + "/" + lk->action2) +
                " -> " + std::to_string(sent) + " agent(s) command_id=" + command_id);
        if (sent == 0) {
            note(res, "Device offline &mdash; live info needs a connected agent.");
            return;
        }
        res.set_content(live_pending(command_id, command_id2, id, kind, 1),
                        "text/html; charset=utf-8");
    });

    // Result: re-validate kind + Execute + command_id prefix + agent match, then
    // poll the response store and render (data rides RUNNING rows, the
    // response-store contract DexRoutes relies on).
    sink.Get("/fragments/device/live/result", [this, note, can_execute, live_pending](
                                                  const httplib::Request& req,
                                                  httplib::Response& res) {
        const std::string kind = req.has_param("kind") ? req.get_param_value("kind") : "";
        const std::string command_id =
            req.has_param("command_id") ? req.get_param_value("command_id") : "";
        const std::string id = req.has_param("agent_id") ? req.get_param_value("agent_id") : "";
        const std::string command_id2 =
            req.has_param("command_id2") ? req.get_param_value("command_id2") : "";
        // Per-device scoped Read floor — a poll must honour the same management
        // scope as the dispatch (an out-of-scope agent_id is refused even with a
        // guessed command_id).
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        const auto lk = yuzu::server::live::resolve_dashboard_kind(kind);
        if (!lk) { res.status = 400; res.set_content("bad request", "text/plain"); return; }
        // Only THIS kind's plugin commands are pollable here, only for the named
        // agent — narrows what a guessed/stolen command_id can read via this route.
        // The optional secondary id must match the kind's secondary plugin prefix.
        if (id.empty() || command_id.size() > 64 || !command_id.starts_with(lk->plugin + "-")) {
            res.status = 400; res.set_content("bad request", "text/plain"); return;
        }
        if (!command_id2.empty() &&
            (lk->plugin2.empty() || command_id2.size() > 64 ||
             !command_id2.starts_with(lk->plugin2 + "-"))) {
            res.status = 400; res.set_content("bad request", "text/plain"); return;
        }
        if (!can_execute(req, id)) {
            note(res, "Live device info needs the <b>Execute</b> permission.");
            return;
        }
        if (!responses_fn_) {
            note(res, "Live device query unavailable on this server.");
            return;
        }
        // Poll budget: hashing every running binary (processes/list_tree) can
        // take longer than a warehouse query, so allow more attempts before
        // declaring a timeout (~28s at 700ms cadence).
        constexpr int kMaxAttempts = 40;
        int attempt = 1;
        if (req.has_param("n")) {
            try { attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 50); } catch (...) {}
        }
        // Hoist the responses into a named local: pointers below must outlive the loop,
        // so iterating the temporary directly would dangle (use-after-free). #1634: the
        // read is scoped to `id` AT THE STORE SEAM (responses_fn_ passes
        // ResponseQuery{.agent_id}); the post-filter below is defense-in-depth.
        const auto rows = responses_fn_(command_id, id);
        const DexAgentResponse* with_output = nullptr;
        const DexAgentResponse* terminal = nullptr; // SUCCESS or any failure terminal
        for (const auto& r : rows) {
            if (r.agent_id != id) continue; // another agent's rows are never rendered here
            if (!r.output.empty()) with_output = &r;
            if (r.status >= 1) terminal = &r; // 1=SUCCESS, 2+=FAILURE/TIMEOUT/REJECTED
        }
        // Best-effort secondary output (process_tree's connections); whatever is
        // available when the primary renders is joined — the tree renders with or
        // without it (own local outlives the loop below, like `rows`).
        std::string output2;
        std::vector<DexAgentResponse> rows2;
        if (!command_id2.empty()) {
            rows2 = responses_fn_(command_id2, id);
            for (const auto& r : rows2)
                if (r.agent_id == id && !r.output.empty() && !r.output.starts_with("error|"))
                    output2 = r.output;
        }
        // Authoritative agent OS for row-shape disambiguation (K-4), resolved
        // lazily so the pending re-poll path pays nothing; empty when the device
        // record is unavailable, in which case render_live_result falls back to
        // content-sniffing.
        auto agent_os = [this, &id]() -> std::string {
            if (!api_) return {};
            auto result = api_->lookup_device(id);
            if (!result || !*result) return {}; // miss or degraded — best-effort only,
                                                 // render_live_result falls back to content-sniffing
            return (*result)->row.os;
        };
        // Behavioural-PII access-audit chokepoint (#1647/#1703). The RESULT poll
        // is where the real process-tree / DNS / connections / users output
        // actually reaches the operator — the /run dispatch audit above records
        // the request, but only THIS route renders the PII, so the access must be
        // audited here too or the read is unaccountable (a works-council /
        // usage-class concern). Dashboard set-and-proceed posture matching /run:
        // a transient audit-store outage still renders the lens but raises
        // Sec-Audit-Failed for the SIEM (REST fail-closed is a separate seam).
        // Only fires on a branch that actually serves rendered output, never on
        // the error/failure/timeout notes.
        auto audit_live_result = [&](const char* result) {
            (void)detail::emit_behavioral_audit(
                audit_fn_, req, res, lk->audit_action, result, "Agent", id,
                lk->plugin + "/" + lk->action + " kind=" + kind +
                    " command_id=" + command_id);
        };
        if (with_output) {
            if (with_output->output.starts_with("error|")) {
                // 300, matching the sibling site in echo_tree_routes.cpp. Both
                // render the SAME `echo status` reply, and the storage-offline
                // line is 231 chars (287 when the read path is gone too), so a
                // 200-byte cap truncated it mid-sentence and dropped "Restart
                // the agent to recover." -- the operator got the problem
                // without the remedy (#2361 Gate 4, consistency-auditor).
                note(res, "The device reported an error: " +
                              html_escape(agent_error_display(with_output->output)));
                return;
            }
            audit_live_result("rendered");
            res.set_content(render_live_result(kind, *lk, with_output->output, output2, agent_os()),
                            "text/html; charset=utf-8");
            return;
        }
        if (terminal) {
            // The command COMPLETED. Failure → honest note; success-with-no-output
            // → render the empty result now (don't poll to a false timeout — UP-1).
            if (terminal->status >= 2) {
                note(res, "Query failed on the device: " +
                              html_escape(terminal->error_detail.substr(0, 200)));
                return;
            }
            audit_live_result("rendered_empty");
            res.set_content(render_live_result(kind, *lk, "", output2, agent_os()), "text/html; charset=utf-8");
            return;
        }
        if (attempt >= kMaxAttempts) {
            note(res, "No response from the device (timed out) &mdash; it may have gone offline. "
                      "Reload to retry.");
            return;
        }
        res.set_content(live_pending(command_id, command_id2, id, kind, attempt + 1),
                        "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
