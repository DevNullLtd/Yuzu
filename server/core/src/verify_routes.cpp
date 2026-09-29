#include "verify_routes.hpp"

#include "app_perf_compare.hpp"  // app_perf_param_valid (PURE — no store dep)
#include "http_route_sink.hpp"   // HttpRouteSink, HttplibRouteSink
#include "rest_a4_envelope.hpp"   // detail::make_correlation_id
#include "rest_audit.hpp"         // detail::emit_behavioral_audit (#1647 chokepoint)
#include "verify_ui.hpp"
#include "web_utils.hpp"          // audit_token (H1 — neutralise k=v field forgery)

#include <yuzu/version_string.hpp> // canon_version

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

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

std::string qparam(const httplib::Request& req, const char* name) {
    return req.has_param(name) ? req.get_param_value(name) : std::string();
}

int parse_window(const httplib::Request& req) {
    int window = 7;
    if (req.has_param("window")) {
        const std::string w = req.get_param_value("window");
        char* end = nullptr;
        const long v = std::strtol(w.c_str(), &end, 10);
        if (end != w.c_str() && *end == '\0')
            window = static_cast<int>(v);
    }
    return std::clamp(window, 1, kMaxWindowDays);
}

} // namespace

void VerifyRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                   GroupsFn groups_fn, AuditFn audit_fn, VerifyApiPtr api) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(groups_fn),
                    std::move(audit_fn), std::move(api));
}

void VerifyRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                   GroupsFn groups_fn, AuditFn audit_fn, VerifyApiPtr api) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    groups_fn_ = std::move(groups_fn);
    audit_fn_ = std::move(audit_fn);
    api_ = std::move(api);

    // ── Config form — chrome; gates Infrastructure:Read like the /auto page ──
    sink.Get("/fragments/auto/verify", [this](const httplib::Request& req, httplib::Response& res) {
        if (!auth_fn_(req, res))
            return;
        if (!perm_fn_(req, res, "Infrastructure", "Read"))
            return;
        std::vector<std::pair<std::string, std::string>> groups;
        if (groups_fn_)
            groups = groups_fn_();
        res.set_content(render_verify_config(groups), "text/html");
    });

    // ── Aggregate result — reads DEX app-perf → GuaranteedState:Read ──
    sink.Get("/fragments/auto/verify/run", [this](const httplib::Request& req,
                                                 httplib::Response& res) {
        if (!auth_fn_(req, res))
            return;
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const std::string group = qparam(req, "group");
        const std::string app = qparam(req, "app");
        const std::string baseline = qparam(req, "baseline");
        const std::string candidate = qparam(req, "candidate");
        // Bad input → an honest note at 200 (the dashboard htmx config drops 4xx
        // bodies, so a 400 would render NOTHING).
        if (group.empty() || app.empty() || baseline.empty() || candidate.empty()) {
            res.set_content(
                render_verify_note("Pick a cohort, an app, and both versions, then Compare."),
                "text/html");
            return;
        }
        if (!app_perf_param_valid(group) || !app_perf_param_valid(app) ||
            !app_perf_param_valid(baseline) || !app_perf_param_valid(candidate)) {
            res.set_content(render_verify_note("A field is too long or has invalid characters."),
                            "text/html");
            return;
        }
        if (yuzu::util::canon_version(baseline) == yuzu::util::canon_version(candidate)) {
            res.set_content(
                render_verify_note("Baseline and candidate must be two different versions."),
                "text/html");
            return;
        }
        const int window = parse_window(req);
        if (!api_) {
            res.set_content(render_verify_note("The app-perf store is still warming up; retry."),
                            "text/html");
            return;
        }
        VerifyCompareQuery q{group, app, baseline, candidate, window};
        auto result = api_->compare(q);
        if (!result) { // AUTHORITATIVE degrade
            res.set_content(
                render_verify_note("The app-perf store could not be read just now; retry shortly."),
                "text/html");
            return;
        }
        const PairedComparison& c = result->comparison;
        // OPERATIONAL audit, set-and-proceed (records who compared whose canary —
        // the accountability that stands in for the absent floor). The dashboard
        // proceeds even on a lost audit row (Sec-Audit-Failed header set); the
        // per-machine PII is behind the separate drill click below. `paired=` makes a
        // singleton (paired=1) aggregate distinguishable in the log (gov UP-7).
        const auto cid = detail::make_correlation_id();
        detail::emit_behavioral_audit(
            audit_fn_, req, res, "dex.app_perf.compare", "success", "GuaranteedState", group,
            "app=" + audit_token(app) + " base=" + audit_token(baseline) + " cand=" +
                audit_token(candidate) + " cohort=" + std::to_string(result->member_count) +
                " paired=" + std::to_string(c.paired) + " view=aggregate cid=" + cid);

        const std::string drill_url =
            "/fragments/auto/verify/drill?group=" + url_encode(group) + "&app=" + url_encode(app) +
            "&baseline=" + url_encode(baseline) + "&candidate=" + url_encode(candidate) +
            "&window=" + std::to_string(window);
        res.set_content(render_verify_result(c, result->member_count, result->truncated, app,
                                             baseline, candidate, window, drill_url),
                        "text/html");
    });

    // ── Per-machine drill — the audited PII surface (opened by a click) ──
    //
    // THREAT MODEL (gov orchestrator note): this is the only VERIFY surface that
    // exposes per-machine identity (agent_id + per-machine deltas), so unlike the
    // identity-free aggregate it sits in tension with the #1522 rule that per-device
    // DEX identity must be management-group-confined. It is SAFE under the current
    // gate because it gates the GLOBAL `perm_fn(GuaranteedState, Read)`, NOT the
    // scoped gate: `check_permission` reads only global role grants, so a
    // management-group-scoped-ONLY operator returns false and never reaches here (the
    // same cohort posture as `/dex/perf/group`). The only callers who pass already
    // hold unscoped fleet-wide Read and can already pull ANY single device's app-perf
    // via the audited `GET /dex/devices/{id}/app-perf` — the cohort drill is a strict
    // subset, no NEW exposure. **If this surface is ever moved onto `scoped_perm_fn`,
    // the cohort here MUST be re-intersected with the caller's visible devices first.**
    sink.Get("/fragments/auto/verify/drill", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
        if (!auth_fn_(req, res))
            return;
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const std::string group = qparam(req, "group");
        const std::string app = qparam(req, "app");
        const std::string baseline = qparam(req, "baseline");
        const std::string candidate = qparam(req, "candidate");
        if (group.empty() || app.empty() || baseline.empty() || candidate.empty() ||
            !app_perf_param_valid(group) || !app_perf_param_valid(app) ||
            !app_perf_param_valid(baseline) || !app_perf_param_valid(candidate)) {
            res.set_content(render_verify_note("Missing or invalid parameters for the drill."),
                            "text/html");
            return;
        }
        // Same baseline!=candidate reject as /run + REST + MCP — a direct /drill hit
        // with equal versions would self-pair every machine (all-zero deltas).
        if (yuzu::util::canon_version(baseline) == yuzu::util::canon_version(candidate)) {
            res.set_content(
                render_verify_note("Baseline and candidate must be two different versions."),
                "text/html");
            return;
        }
        const int window = parse_window(req);
        if (!api_) {
            res.set_content(render_verify_note("The app-perf store is still warming up; retry."),
                            "text/html");
            return;
        }
        VerifyCompareQuery q{group, app, baseline, candidate, window};
        auto result = api_->compare(q);
        if (!result) {
            res.set_content(
                render_verify_note("The app-perf store could not be read just now; retry shortly."),
                "text/html");
            return;
        }
        // The per-machine view IS the behavioural-PII access → its OWN verb
        // (`dex.app_perf.compare.drill`, distinct from the identity-free aggregate's
        // `dex.app_perf.compare`) so works-council per-machine-PII access stays
        // independently countable. Set-and-proceed on the HTML surface; the header
        // flags a lost row.
        const auto cid = detail::make_correlation_id();
        detail::emit_behavioral_audit(audit_fn_, req, res, "dex.app_perf.compare.drill", "success",
                                      "GuaranteedState", group,
                                      "app=" + audit_token(app) + " base=" + audit_token(baseline) +
                                          " cand=" + audit_token(candidate) + " cid=" + cid);
        // The drill is normally reached behind the /run banner, but a direct-URL hit
        // must carry the same truncation warning — a capped read drops machines here
        // too (gov round-2 consistency).
        res.set_content(render_verify_drill(result->comparison, result->truncated), "text/html");
    });
}

} // namespace yuzu::server
