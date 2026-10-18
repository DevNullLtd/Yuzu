#pragma once

/// @file access_reviews_routes.hpp
/// Audit and reviews page (Phase 2 UI): the Access reviews half. Three read-only fragments that
/// the page loads; every change (open, close, attest, flag) is made by the page script calling
/// the existing REST v1 routes, never a dashboard-only route.
///
/// Routes (all GET):
///   /fragments/access/reviews/campaigns      campaign list; loud AccessReview:Read
///   /fragments/access/reviews/campaign       one campaign + summary card (?id=); loud AccessReview:Read
///   /fragments/access/reviews/grants         live grant population; loud AccessReview:Read
///
/// Twins (ADR-1005), same gate, same store read, same audit verb and shape as the twin:
///   campaigns -> GET /api/v1/access-reviews            + list_access_reviews   (access_review.list)
///   campaign  -> GET /api/v1/access-reviews/{id}       + get_access_review     (access_review.get)
///   grants    -> GET /api/v1/access-reviews/export     + export_access_review  (access_review.exported,
///                detail `format=view`)
/// An engine-class session is refused exactly as the twins refuse it (403, A4 body, a denied row
/// with detail `engine_session_denied`).
///
/// Controls (Open review, Close campaign, Attest, Flag) are drawn only when the caller also
/// holds AccessReview:Attest. That is a render-time hint probed through `probe_perm_fn`, never a
/// gate: the REST routes re-check on every write.

#include <yuzu/server/auth.hpp>

#include "access_review_store.hpp"
#include "access_reviews_render.hpp"

#include <httplib.h>

#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

namespace access_reviews {

struct ReviewsDeps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    /// The LOUD gate (`require_permission`): on false it has already written the 403 and its audit row.
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string&, const std::string&)>;
    /// Render-time capability hint. Bound to the quiet probe on a scratch `httplib::Response` (so a
    /// refusal never reaches the real response and, for a cookie session, writes no denied row).
    using ProbeFn = std::function<bool(const httplib::Request&, const std::string& securable,
                                       const std::string& op)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    /// The quiet probe (`probe_permission`): same decision as `perm_fn`, no denied row for a cookie
    /// session. Used only by the campaign list, which loads itself on every page view.
    PermFn quiet_perm_fn;
    ProbeFn probe_perm_fn;
    AuditFn audit_fn;
    /// `AccessReviewStore::list_campaigns()`; unexpected = the store did not answer (log-only text).
    std::function<std::expected<std::vector<AccessReviewCampaignRow>, std::string>()> list_campaigns_fn;
    /// `AccessReviewStore::get_campaign(id)`; the store's "not_found:" prefix passes through verbatim.
    std::function<std::expected<CampaignView, std::string>(const std::string&)> get_campaign_fn;
    /// `build_access_review(...)` + `access_review_rbac_enforcement(...)`; unexpected = a read failed.
    std::function<std::expected<GrantsView, std::string>()> grants_fn;
};

/// Throws `std::invalid_argument` when any `ReviewsDeps` member is unbound.
void register_access_reviews_routes(HttpRouteSink& sink, ReviewsDeps deps);

} // namespace access_reviews
} // namespace yuzu::server
