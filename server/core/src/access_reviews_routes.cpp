// Audit and reviews page, Access reviews half: route registration (see access_reviews_routes.hpp).

#include "access_reviews_routes.hpp"

#include "access_reviews_render.hpp"
#include "http_route_sink.hpp"
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"

#include <spdlog/spdlog.h>

#include <stdexcept>

namespace yuzu::server::access_reviews {

namespace {

constexpr const char* kHtml = "text/html; charset=utf-8";

void respond_fragment(httplib::Response& res, const std::string& body) {
    // Grant populations and campaign evidence: never cached, never shared.
    res.set_header("Cache-Control", "no-store, private");
    res.set_content(body, kHtml);
}

// The REST twins refuse an engine-class session (an engine principal is not a human reviewer
// and must never read or sign this evidence); the fragments refuse it the same way, with the
// same body and the same denied row. Returns true when the response is already written.
bool deny_engine_session(const ReviewsDeps& d, const auth::Session& s, const httplib::Request& req,
                         httplib::Response& res, const char* action) {
    if (!s.is_engine())
        return false;
    (void)detail::emit_behavioral_audit(d.audit_fn, req, res, action, "denied", "AccessReview", "",
                                        "engine_session_denied");
    res.status = 403;
    res.set_content(detail::a4_error(res, "engine principals cannot access this endpoint"),
                    "application/json");
    return true;
}

// AccessReview:Read (loud, or the quiet probe for the self-loading list), then the session, then
// the engine refusal. Nothing is read before this returns true; on false the response is already
// written.
bool gate(const ReviewsDeps& d, const ReviewsDeps::PermFn& perm, const httplib::Request& req,
          httplib::Response& res, const char* action) {
    if (!perm(req, res, "AccessReview", "Read"))
        return false;
    const auto session = d.auth_fn(req, res);
    if (!session)
        return false;
    return !deny_engine_session(d, *session, req, res, action);
}

} // namespace

void register_access_reviews_routes(HttpRouteSink& sink, ReviewsDeps deps) {
    if (!deps.auth_fn || !deps.perm_fn || !deps.quiet_perm_fn || !deps.probe_perm_fn || !deps.audit_fn ||
        !deps.list_campaigns_fn || !deps.get_campaign_fn || !deps.grants_fn)
        throw std::invalid_argument(
            "access_reviews::register_access_reviews_routes: every ReviewsDeps member is required");

    sink.Get("/fragments/access/reviews/campaigns",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(deps, deps.quiet_perm_fn, req, res, "access_review.list"))
                     return;
                 const bool can_attest = deps.probe_perm_fn(req, "AccessReview", "Attest");
                 auto rows = deps.list_campaigns_fn();
                 if (!rows) {
                     spdlog::warn("/fragments/access/reviews/campaigns: {}", rows.error());
                     respond_fragment(res, render_campaigns(access::Unavailable{}, can_attest));
                     return;
                 }
                 (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, "access_review.list",
                                                     "success", "AccessReview", "",
                                                     "count=" + std::to_string(rows->size()));
                 respond_fragment(res, render_campaigns(*rows, can_attest));
             });

    sink.Get("/fragments/access/reviews/campaign",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(deps, deps.perm_fn, req, res, "access_review.get"))
                     return;
                 const std::string id = req.get_param_value("id");
                 if (id.empty()) {
                     respond_fragment(res, render_campaign_unselected());
                     return;
                 }
                 // A malformed id never reaches the store and writes no audit row (nothing was read).
                 if (!valid_campaign_id(id)) {
                     respond_fragment(res, render_campaign(access::NotFound{}, false));
                     return;
                 }
                 const bool can_attest = deps.probe_perm_fn(req, "AccessReview", "Attest");
                 auto view = deps.get_campaign_fn(id);
                 if (!view) {
                     // The store's machine-checkable prefix separates "no such campaign" (it
                     // answered) from a read failure; only the latter is "unavailable".
                     if (view.error().starts_with("not_found:")) {
                         respond_fragment(res, render_campaign(access::NotFound{}, false));
                         return;
                     }
                     spdlog::warn("/fragments/access/reviews/campaign: {}", view.error());
                     respond_fragment(res, render_campaign(access::Unavailable{}, false, id));
                     return;
                 }
                 (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, "access_review.get",
                                                     "success", "AccessReview", id, "");
                 respond_fragment(res, render_campaign(std::move(*view), can_attest));
             });

    sink.Get("/fragments/access/reviews/grants",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(deps, deps.perm_fn, req, res, "access_review.exported"))
                     return;
                 auto grants = deps.grants_fn();
                 if (!grants) {
                     spdlog::warn("/fragments/access/reviews/grants: {}", grants.error());
                     respond_fragment(res, render_grants(access::Unavailable{}));
                     return;
                 }
                 (void)detail::emit_behavioral_audit(
                     deps.audit_fn, req, res, "access_review.exported", "success", "AccessReview", "",
                     "format=view rows=" + std::to_string(grants->rows.size()) +
                         " rbac_enforcement=" + grants->rbac_enforcement);
                 respond_fragment(res, render_grants(*grants));
             });
}

} // namespace yuzu::server::access_reviews
