#pragma once

/// @file dex_apps_ui.hpp
/// The DEX Apps tab (`/fragments/dex/apps`): application stability per application and
/// per version, rendered from the SAME `DexAppsModel` that serves GET /api/v1/dex/apps
/// and the list_dex_apps MCP tool, so the page and the REST payload cannot disagree.
///
/// PURE and free: no store, no httplib, no I/O. Enrolled in the seam-closure `dex`
/// family (scripts/ci/check-seam-closure.py), so a store include here is lint-caught.

#include "dex_read_model.hpp"

#include <string>

namespace yuzu::server {

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
std::string render_dex_apps_fragment(const DexAppsModel& model, int window_days,
                                     const std::string& platform);

} // namespace yuzu::server
