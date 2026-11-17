#pragma once

/// @file dex_usage_json.hpp
/// The one JSON serializer for the fleet application usage model
/// (`DexAppsUsageModel`): GET /api/v1/dex/apps/usage uses it, and an MCP twin
/// reuses it so the two surfaces cannot diverge.
///
/// Rules the output keeps (each pinned by a test):
///  - A withheld figure is JSON null, never 0.
///  - Every cell carries its `kind`; a label is data (a tag value or a group
///    id), so a consumer keys on `kind` and escapes the label.
///  - Invalid UTF-8 in a label is replaced, never thrown on.
///  - No agent id appears: the model holds none.

#include "dex_usage_model.hpp"

#include <string>

namespace yuzu::server {

/// The `data` body only (the caller wraps it in its envelope).
[[nodiscard]] std::string dex_apps_usage_json(const DexAppsUsageModel& m);

} // namespace yuzu::server
