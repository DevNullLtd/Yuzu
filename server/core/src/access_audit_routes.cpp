// Audit and reviews page, audit half: route registration (see access_audit_routes.hpp).

#include "access_audit_routes.hpp"

#include "access_audit_render.hpp"
#include "access_audit_ui.hpp"
#include "http_route_sink.hpp"
#include "response_query_params.hpp"
#include "rest_audit.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <exception>
#include <optional>
#include <vector>
#include <stdexcept>

namespace yuzu::server {

// server/core/src/yuzu_audit_js_bundle.cpp (embed_js.py, see server/core/meson.build)
extern const std::string kYuzuAuditJs;

namespace access_audit {

namespace {

constexpr const char* kHtml = "text/html; charset=utf-8";

void respond_fragment(httplib::Response& res, const std::string& body) {
    res.set_header("Cache-Control", "no-store");
    res.set_content(body, kHtml);
}

// One audit read. A store that throws is the same "did not answer" as one that returns nullopt,
// so the panel shows its red box rather than a bare 500 that htmx would drop.
std::optional<std::vector<AuditEvent>> read_audit(const Deps& deps, const AuditQuery& q,
                                                  std::size_t* pool) {
    try {
        return deps.query_fn(q, pool);
    } catch (const std::exception& e) {
        spdlog::warn("access audit page: audit read threw: {}", e.what());
        return std::nullopt;
    }
}

bool has_nul(const std::string& s) {
    return s.find('\0') != std::string::npos;
}

// The twin refuses a NUL because it would truncate the bound value at the C-string boundary
// and silently widen the filter; the page refuses the same inputs with a note (htmx drops 4xx
// bodies, so the refusal is a 200).
const BadFilter* parse_log_request(const httplib::Request& req, LogView& v) {
    static const BadFilter kRange{kBadRange}, kText{kBadText}, kOffset{kBadOffset};
    if (req.has_param("range")) {
        const auto r = parse_range(req.get_param_value("range"));
        if (!r)
            return &kRange;
        v.range = *r;
    }
    v.principal = req.get_param_value("principal");
    v.action = req.get_param_value("action");
    if (has_nul(v.principal) || has_nul(v.action))
        return &kText;
    if (const auto off = req.get_param_value("offset"); !off.empty()) {
        const auto n = parse_query_int<int>(off);
        if (!n || *n < 0 || *n > kAuditMaxOffset)
            return &kOffset;
        v.offset = *n;
    }
    return nullptr;
}

} // namespace

void register_access_audit_routes(HttpRouteSink& sink, Deps deps) {
    if (!deps.auth_fn || !deps.perm_fn || !deps.quiet_perm_fn || !deps.audit_fn || !deps.query_fn ||
        !deps.retention_days_fn || !deps.now_fn)
        throw std::invalid_argument(
            "access_audit::register_access_audit_routes: every Deps member is required");

    sink.Get("/access/audit", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.auth_fn(req, res)) {
            res.set_redirect("/login");
            return;
        }
        // No page-level probe: each panel is gated by its own fragment, and a refusal becomes
        // the panel's "not available" note client-side.
        res.set_header("Cache-Control", "no-store");
        res.set_content(kAccessAuditHtml, kHtml);
    });

    sink.Get("/fragments/access/audit/log",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 // Gate first: a denied caller costs no parse and no read.
                 if (!deps.quiet_perm_fn(req, res, "AuditLog", "Read"))
                     return;
                 LogView v;
                 if (const auto* bad = parse_log_request(req, v)) {
                     respond_fragment(res, render_audit_log(*bad));
                     return;
                 }
                 AuditQuery q;
                 q.principal = v.principal;
                 q.action = v.action;
                 // since is inclusive; keep it positive so a tiny clock never reaches 0.
                 q.since = std::max<std::int64_t>(1, deps.now_fn() - range_seconds(v.range));
                 q.limit = kPageSize + 1; // limit is NEVER read from the client
                 q.offset = v.offset;
                 auto rows = read_audit(deps, q, nullptr);
                 if (!rows) {
                     spdlog::warn("/fragments/access/audit/log: audit store did not answer");
                     respond_fragment(res, render_audit_log(access::Unavailable{}));
                     return;
                 }
                 v.has_more = rows->size() > static_cast<std::size_t>(kPageSize);
                 if (v.has_more)
                     rows->resize(kPageSize);
                 v.rows = std::move(*rows);
                 respond_fragment(res, render_audit_log(v));
             });

    sink.Get("/fragments/access/audit/sample",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "AuditLog", "Read"))
                     return;
                 int limit = kSampleDefault;
                 if (const auto raw = req.get_param_value("limit"); !raw.empty()) {
                     const auto n = parse_query_int<int>(raw);
                     if (!n || *n < kSampleMin || *n > kSampleMax) {
                         respond_fragment(res, render_auth_sample(BadFilter{kBadSample}));
                         return;
                     }
                     limit = *n;
                 }
                 // The same auth-surface scope as GET /api/v1/audit/auth-sample.
                 AuditQuery q;
                 q.action_prefixes = {"auth.", "mfa.", "session.", "engine_principal."};
                 q.random_sample = true;
                 q.limit = limit;
                 std::size_t pool = 0;
                 auto rows = read_audit(deps, q, &pool);
                 if (!rows) {
                     spdlog::warn("/fragments/access/audit/sample: audit store did not answer");
                     respond_fragment(res, render_auth_sample(access::Unavailable{}));
                     return;
                 }
                 SampleView v;
                 v.limit = limit;
                 v.candidates = pool;
                 v.recency_capped = pool >= kAuditSampleScanCap;
                 // Evidence access is itself on the audit chain, after the read (as the twin
                 // does). A dropped row sets Sec-Audit-Failed and the panel says so. The
                 // "from=0 to=0" detail is byte-for-byte what GET /api/v1/audit/auth-sample
                 // writes for an open window (rest_api_v1.cpp builds it from since/until
                 // value_or(0)), so evidence queries match across both surfaces.
                 v.audit_failed = !detail::emit_behavioral_audit(
                     deps.audit_fn, req, res, "audit.auth_sample.exported", "success", "AuditLog",
                     "auth-sample",
                     "from=0 to=0 limit=" + std::to_string(limit) +
                         " returned=" + std::to_string(rows->size()));
                 v.rows = std::move(*rows);
                 respond_fragment(res, render_auth_sample(v));
             });

    sink.Get("/fragments/access/audit/retention",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "ServerConfig", "Read"))
                     return;
                 respond_fragment(res, render_retention(deps.retention_days_fn()));
             });

    sink.Get("/static/yuzu-audit.js", [](const httplib::Request&, httplib::Response& res) {
        // The script binds to fragment markup, so a long max-age would skew after an upgrade.
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(kYuzuAuditJs, "application/javascript; charset=utf-8");
    });
}

} // namespace access_audit
} // namespace yuzu::server
