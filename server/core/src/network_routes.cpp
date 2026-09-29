/// @file network_routes.cpp
/// /network route registration — the page shell + the read-only HTMX fragments.
/// Renderers live in network_ui.cpp; the model in network_perf_model.cpp. The
/// data-bearing fragments gate on GuaranteedState:Read; an unwired provider
/// degrades to an honest "unavailable" placeholder (the slice-2 state).

#include "network_routes.hpp"

#include "http_route_sink.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_denial
#include "rest_audit.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>

// Shared full-page shell (defined at GLOBAL scope in guardian_page_ui.cpp);
// declared at global scope to match the definition (the symbol is not namespaced).
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

std::string unavailable_placeholder() {
    return "<div class=\"gp-placeholder\"><b>Network telemetry unavailable</b>"
           "This server has no network snapshot provider wired yet.</div>";
}

} // namespace

void NetworkRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                    AuditFn audit_fn, NetworkApiPtr api) {
    // Production adapter: wrap the httplib server in the route-sink seam and
    // delegate to the testable overload (mirrors DexRoutes / GuardianRoutes).
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    std::move(api));
}

void NetworkRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                    AuditFn audit_fn, NetworkApiPtr api) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    api_ = std::move(api);

    // -- Page shell (auth-only static chrome; the fragment it loads gates on Read) --
    sink.Get("/network", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        std::string html(kGuardianDetailPageHtml);
        auto sub = [&](const std::string& tok, const std::string& val) {
            for (auto p = html.find(tok); p != std::string::npos; p = html.find(tok, p + val.size()))
                html.replace(p, tok.size(), val);
        };
        sub("{{TITLE}}", "Yuzu \xE2\x80\x94 Network");
        sub("{{FRAGMENT}}", "/fragments/network/overview");
        // Network sits UNDER DEX (no standalone top-nav link), so /network marks
        // the DEX nav item active; the overview fragment renders the DEX sub-nav
        // with the Network tab active. The shared shell defaults Guardian active,
        // so swap that off and DEX on. Plain string swaps on static chrome.
        sub("<a href=\"/guardian\" class=\"nav-link active\">Guardian</a>",
            "<a href=\"/guardian\" class=\"nav-link\">Guardian</a>");
        sub("<a href=\"/dex\" class=\"nav-link\">DEX</a>",
            "<a href=\"/dex\" class=\"nav-link active\">DEX</a>");
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(std::move(html), "text/html; charset=utf-8");
    });

    // -- Overview fragment (gates on GuaranteedState:Read) --
    sink.Get("/fragments/network/overview", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        if (!api_) {
            res.set_content(unavailable_placeholder(), "text/html; charset=utf-8");
            return;
        }
        std::string key = req.has_param("key") ? req.get_param_value("key") : "";
        if (key.size() > 64) // light guard; the provider validates against TagStore
            key.clear();
        res.set_content(render_network_overview_fragment(api_->fleet_now(key)),
                        "text/html; charset=utf-8");
    });

    // -- Devices drill (worst-by-metric / co-occurrence band / not-reporting / cohort) --
    sink.Get("/fragments/network/devices", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
        // Fleet-wide identity-linked disclosure (SEC-3 sibling class, Gate 8
        // review): the rendered fragment names every reporting agent's
        // agent_id, platform, and network/correlation facts fleet-wide, no
        // per-agent parameter to scope a per-target check against.
        // require_permission's service-token branch checks only the
        // ITServiceOwner ROLE, never the token's own service-tag scope, so
        // perm_fn_ alone would let a token scoped to one service read every
        // agent's network data. Denied here, ahead of/independent from
        // perm_fn_. JSON 403 body (not HTML): matches perm_fn_'s own
        // established denial shape on this same fragment (require_permission
        // already returns application/json on its 403 here).
        if (auto session = auth_fn_(req, res)) {
            if (!session->token_scope_service.empty()) {
                // Write the 403 FIRST, audit after (normalized — #3167).
                // `.permission` omitted: kServiceScopeGlobalSafe is
                // compile-time-empty, so no grant admits a service-scoped
                // caller here; naming one would be a false self-remediation
                // claim.
                res.status = 403;
                res.set_content(
                    detail::a4_denial(
                        res, 403,
                        "service-scoped tokens may not read this fleet-wide network view"),
                    "application/json");
                (void)detail::try_persist_audit(
                    audit_fn_, req, "network.device.view", "denied", "GuaranteedState", "",
                    "fleet-wide network device list denied to a service-scoped token "
                    "(dashboard fragment)");
                return;
            }
        } else {
            return; // auth_fn_ already wrote the response (401/etc).
        }
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        if (!api_) {
            res.set_content(unavailable_placeholder(), "text/html; charset=utf-8");
            return;
        }
        const NetPerfMetric metric = net_perf_metric_from_token(
            req.has_param("metric") ? req.get_param_value("metric") : "rtt");
        const bool not_reporting =
            req.has_param("filter") && req.get_param_value("filter") == "not_reporting";
        const NetCoocFilter cooc =
            req.has_param("cooc") ? net_cooc_from_token(req.get_param_value("cooc"))
                                  : NetCoocFilter::kNone;
        std::optional<std::string> cohort_filter;
        if (req.has_param("cohort_value"))
            cohort_filter = req.get_param_value("cohort_value");
        std::string key = req.has_param("key") ? req.get_param_value("key") : "";
        if (key.size() > 64)
            key.clear();
        int limit = 50;
        if (req.has_param("limit")) {
            try {
                limit = std::clamp(std::stoi(req.get_param_value("limit")), 1, 500);
            } catch (...) {}
        }
        // Behavioral-PII access audit — same verb/target as the REST sibling
        // GET /api/v1/network/devices. Set-and-proceed (HTML dashboard
        // fragment, not REST's fail-closed): a transient audit hiccup must
        // not blank this operator's view.
        (void)detail::try_persist_audit(audit_fn_, req, "network.device.view", "success",
                                        "GuaranteedState", "",
                                        "fleet-wide network device list via dashboard fragment");
        NetDeviceQuery q;
        q.metric = metric;
        q.not_reporting = not_reporting;
        q.cooc = cooc;
        q.cohort_key = key;
        q.cohort_filter = cohort_filter;
        q.limit = limit;
        const auto rows = api_->device_list(q);
        // Same memoized snapshot as device_list (5s TTL, keyed by `key`) —
        // cheap to ask again just for the cohort picker's key list.
        const auto available_keys = api_->fleet_now(key).available_keys;
        res.set_content(render_network_devices_fragment(rows, available_keys, key, metric,
                                                        not_reporting, cooc, cohort_filter, limit),
                        "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
