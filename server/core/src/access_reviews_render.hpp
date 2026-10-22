#pragma once

/// @file access_reviews_render.hpp
/// Pure HTML renderers for the Access reviews panels of `/access/audit` (Phase 2 UI): the
/// campaign list, one campaign's frozen grants (with its summary card), and the live grant
/// population. No I/O, no logging, no store handles.
///
/// Evidence rules (the routed Periodic Access Reviews concern):
///   * Flag is evidence only. The Flag control records `flagged_revoke` and the dialog says it
///     does NOT revoke; nothing here calls an RBAC or engine-principal mutation route.
///   * A campaign is read as stored: undecided grants are listed first so the render cap can
///     never hide one behind decided rows, and a grant whose principal no longer exists
///     (`source=orphan`) is kept and flagged, never dropped.
///   * `Unavailable` (the store did not answer) and `NotFound` (it answered: no such campaign)
///     are distinct states; neither is ever drawn as an empty list.
///
/// Every stored string reaches the output through `html_escape`; every campaign id placed in a
/// URL goes through `access::url_q` (a query value, never a path segment). Controls are emitted
/// only when the caller holds `AccessReview:Attest`, and only for an OPEN campaign.

#include "access_render.hpp"
#include "access_review_model.hpp"
#include "access_review_store.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace yuzu::server::access_reviews {

/// Rows drawn from one campaign / the live population before the cap banner.
inline constexpr std::size_t kGrantRenderCap = 1000;

/// Sentences the page template carries as `data-denied` / `data-unavailable`; a test pins byte
/// equality with the template.
inline constexpr std::string_view kReviewsDenied =
    "Access reviews need the AccessReview:Read permission, held by the Administrator and Reviewer "
    "roles. While RBAC is off that is the Administrator account role.";
inline constexpr std::string_view kCampaignsUnavailable =
    "The access review store did not answer, so the campaign list is unknown. This is not no reviews.";
inline constexpr std::string_view kCampaignUnavailable =
    "The access review store did not answer, so this campaign could not be read.";
inline constexpr std::string_view kGrantsUnavailable =
    "The grant population could not be read, so the list is unknown. This is not no grants.";
inline constexpr std::string_view kSelectCampaign = "Select a campaign from the list to review its grants.";

/// The campaign id shape the routes and the page script accept: the store mints 16 hex digits;
/// this is deliberately wider but excludes every URL-significant byte, so an id that passes can
/// be placed in a query value or a path segment unchanged.
[[nodiscard]] bool valid_campaign_id(std::string_view id);

struct CampaignDerived {
    int total = 0;
    int decided = 0;   ///< attested + flagged_revoke
    int flagged = 0;
    int reviewers = 0; ///< distinct non-empty reviewer names
};
[[nodiscard]] CampaignDerived derive_campaign_counts(const CampaignView& v);

/// The campaigns panel body (the whole panel interior, `.hd` included).
std::string render_campaigns(
    const std::variant<std::vector<AccessReviewCampaignRow>, access::Unavailable>& state,
    bool can_attest);

/// One campaign: the grants panel interior plus the summary card as an out-of-band swap of
/// `#ar-campaign-side`, so one response fills both columns.
/// `id` (already validated by the route) only builds the Retry button of the unavailable state.
std::string render_campaign(const std::variant<CampaignView, access::NotFound, access::Unavailable>& state,
                            bool can_attest, std::string_view id = {});

/// Nothing selected: both targets show their placeholder.
std::string render_campaign_unselected();

struct GrantsView {
    std::vector<AccessReviewRow> rows;
    std::string rbac_enforcement; ///< "enabled" | "disabled" | "degraded" at read time
};

/// The current-grants panel interior (live population, not a campaign).
std::string render_grants(const std::variant<GrantsView, access::Unavailable>& state);

} // namespace yuzu::server::access_reviews
