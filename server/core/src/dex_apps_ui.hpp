#pragma once

/// @file dex_apps_ui.hpp
/// The DEX Apps tab (`/fragments/dex/apps`): application stability per application and
/// per version, rendered from the SAME `DexAppsModel` that serves GET /api/v1/dex/apps
/// and the list_dex_apps MCP tool, so the page and the REST payload cannot disagree.
///
/// The Usage view (`/fragments/dex/apps/usage`) is the second view of the same tab: fleet
/// application usage and the exposure rate, rendered from the SAME `DexAppsUsageModel` that serves
/// GET /api/v1/dex/apps/usage, so the page and the REST payload cannot disagree.
///
/// PURE and free: no store, no httplib, no I/O. Enrolled in the seam-closure `dex`
/// family (scripts/ci/check-seam-closure.py), so a store include here is lint-caught.

#include "dex_app_perf_ui.hpp" // DexGroupOption
#include "dex_read_model.hpp"
#include "dex_usage_model.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

/// What the Stability page offers for the Usage view. `Hidden` emits nothing new, so the
/// three-argument call is byte-identical to the page before the Usage view existed and the
/// `apps__*` goldens pin the stability markup alone; the route always passes one of the other
/// three. `Offered` adds the View chips; `Refused` adds them and one line saying the Forensics
/// read permission is missing; `GateUnavailable` adds them and one line saying the permission
/// check could not be completed.
enum class DexAppsUsageEntry { Hidden, Offered, Refused, GateUnavailable };

/// Render the Apps fragment for `model`.
///
/// `platform` is a canonical scope token (all|windows|macos|linux) or "" for an
/// unrecognised request: no platform chip is lit and the page is an error panel. The
/// chips come from `window_days` and `platform`, never from the model: a degraded model
/// is default-constructed and its `platform_scope` is not the request's.
///
/// A degraded model renders the page chrome, the chips and an error panel and NOTHING
/// derived from the model (no population, coverage, policy or interval line, no table):
/// a degraded read carries a default policy and no population, so printing them would
/// state a policy and a population that were never read. It is never an empty list.
///
/// The panel's text depends on the model's `degraded_reason`: concurrency_budget and
/// pool_acquire_timeout say the server is busy; statement_timeout says the read took too long and
/// points at a shorter window (at 24h, at the database); score_policy_unavailable and
/// score_policy_invalid point at Scoring; store_not_open and query_error point at the database;
/// invalid_scope names the platform filter; an empty reason gets the generic text and any other
/// token the generic text with the token shown. Every panel but invalid_scope's prints the token as
/// a code element (an empty reason has none to print); invalid_scope's names the platform filter
/// instead.
///
/// `usage` is the Usage-view entry (see `DexAppsUsageEntry`); it defaults to `Hidden`.
std::string render_dex_apps_fragment(const DexAppsModel& model, int window_days,
                                     const std::string& platform,
                                     DexAppsUsageEntry usage = DexAppsUsageEntry::Hidden);

/// What the Usage view's chrome and controls are drawn from: the request, never the model, so a
/// refusal (which has no model) draws the same controls.
struct DexAppsUsageControls {
    int window_days{7};
    std::string platform; ///< canonical scope token (all|windows|macos|linux) or "" when unrecognised
    DexUsageSlice slice;  ///< the slice in force; a rejected group id or tag key is never placed here
    std::vector<DexGroupOption> groups; ///< the management groups offered in the group select
};

/// Render the Usage view for `model`. Every figure comes from the model; every state is words
/// (never blank, never a 0 for a withheld figure); every device count is printed beside the
/// reporting population it is read against. Pure: no store, no httplib, no clock.
std::string render_dex_apps_usage_fragment(const DexAppsUsageControls& controls,
                                           const DexAppsUsageModel& model);

/// Render the Usage view for a refused read. `reason` and `detail` are the tokens of
/// `DexUsageRefusal` (or the route's own: invalid_scope, invalid_slice with detail no_group,
/// invalid_tag_key, group_outside_slice or tag_key_outside_slice, audit_unavailable, and
/// usage_unavailable with detail not_wired). It prints the page chrome and the controls and
/// NOTHING derived from a model (no population, reporting or floor line, no table), and one panel
/// per cause that names the lever that helps. Pure.
std::string render_dex_apps_usage_refusal(const DexAppsUsageControls& controls,
                                          std::string_view reason, std::string_view detail);

} // namespace yuzu::server
