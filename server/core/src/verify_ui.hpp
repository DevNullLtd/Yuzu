#pragma once

/// @file verify_ui.hpp
/// PURE render functions for the `/auto` VERIFY stage — the cohort-paired
/// before/after app-performance evidence. Dark-theme, htmx CORE attrs only
/// (the dashboard CSP blocks hx-on); every operator-supplied string is
/// HTML-escaped at render. The numbers all come from the ONE pure engine
/// (`app_perf_compare.hpp` `build_comparison`), so this surface and the REST/MCP
/// twins cannot disagree. EVIDENTIAL ONLY — no verdict, no pass/fail; a sub-floor
/// paired cohort renders an "indicative" note (never rendered at the one-device
/// floor; the flag stays on the wire), never suppression. See verify_routes.hpp.

#include "app_perf_compare.hpp" // PairedComparison

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

/// PURE: the VERIFY config form (group dropdown + app/baseline/candidate inputs +
/// window) and an empty results container. `groups` = (id, name) for the cohort
/// dropdown. Inlines the `.vf-*` CSS once (this fragment loads with the page).
[[nodiscard]] std::string render_verify_config(const std::vector<std::pair<std::string, std::string>>& groups);

/// PURE: the aggregate result — factual summary line, the per-metric shift cards
/// (baseline mean → candidate mean + median per-machine delta), the up/flat/down
/// distribution, and a "Show per-machine pairs" button (hx-get `drill_url`, the
/// audited per-device surface). A small (sub-floor) cohort gets an "indicative"
/// note (never rendered at the one-device floor; the flag stays on the wire); an empty/insufficient cohort gets an honest note instead of fabricated 0s.
[[nodiscard]] std::string render_verify_result(const PairedComparison& c, std::int64_t cohort_size,
                                               bool truncated, const std::string& app,
                                               const std::string& baseline,
                                               const std::string& candidate, int window,
                                               const std::string& drill_url);

/// PURE: the per-machine pairs table (the audited drill) — device, CPU before/after/Δ,
/// WS before/after/Δ, samples; largest CPU mover first. Per-device behavioural data,
/// so the route audits its open.
[[nodiscard]] std::string render_verify_drill(const PairedComparison& c, bool truncated);

/// PURE: an honest note body (degrade, no provider, no group selected, etc.).
[[nodiscard]] std::string render_verify_note(const std::string& message);

} // namespace yuzu::server
