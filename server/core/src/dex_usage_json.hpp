#pragma once

/// @file dex_usage_json.hpp
/// The one JSON serializer for the fleet application usage model
/// (`DexAppsUsageModel`), shared by GET /api/v1/dex/apps/usage and the MCP tool
/// get_dex_apps_usage so the two surfaces cannot diverge, plus the pure pieces the
/// tool needs around it: the refusal classifier, the strict argument parser and the
/// audit detail shape. The classifier is the refusal table both surfaces answer by.
///
/// Rules the output keeps (each pinned by a test):
///  - A withheld figure is JSON null, never 0 (an ambiguous name withholds its device count
///    too; an application nobody ran has a true count of 0).
///  - Every cell carries its `kind`; a label is data (a tag value or a group
///    id), so a consumer keys on `kind` and escapes the label.
///  - Invalid UTF-8 in a label is replaced, never thrown on.
///  - No agent id appears: the model holds none.

#include "dex_api.hpp" // DexUsageRefusal
#include "dex_usage_model.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace yuzu::server {

/// The `data` body only (the caller wraps it in its envelope).
[[nodiscard]] std::string dex_apps_usage_json(const DexAppsUsageModel& m);

// ── Refusal classification ───────────────────────────────────────────────────

/// How a surface answers a refused usage read.
enum class DexUsageRefusalKind {
    CallerError, ///< the caller's input names nothing (invalid slice, unknown group): not retryable
    Terminal,    ///< unavailable, and a retry does not help: no retry hint
    Retryable,   ///< transient: retry after `retry_after_ms`
};

struct DexUsageRefusalClass {
    DexUsageRefusalKind kind{DexUsageRefusalKind::Retryable};
    /// Tokens only, never caller text.
    std::string message;
    /// A static literal; empty means none.
    std::string_view remediation;
    /// -1 unless `kind` is Retryable.
    std::int64_t retry_after_ms{-1};
};

/// The one table that maps a `DexUsageRefusal` to an answer. The MCP tool and the REST usage
/// route (GET /api/v1/dex/apps/usage in rest_api_v1.cpp) both call it, so the two surfaces
/// answer a refused read alike. `not_wired`, `invalid_read` and `apps_degraded` with detail
/// `score_policy_invalid` are Retryable, as they have always been on REST.
[[nodiscard]] DexUsageRefusalClass dex_usage_refusal_class(const DexUsageRefusal& f);

// ── MCP arguments ────────────────────────────────────────────────────────────

/// The validated arguments of the MCP usage tool, in the form `DexApi::apps_usage` takes.
struct DexUsageMcpRequest {
    std::string window;         ///< 24h|7d|30d|all
    std::string platform_scope; ///< all|windows|macos|linux
    std::string slice_name;     ///< fleet|platform|group|tag
    DexUsageSlice slice;
    std::int64_t floor{kDexCohortFloor};
};

/// Parse `tools/call` arguments. Strict: it refuses and never clamps or coerces. An unknown
/// key, a value of the wrong JSON type, an off-enum value, a parameter outside its slice, a
/// group or tag key the REST route would refuse and a floor outside 1..10000 are each a
/// message that names the argument and never echoes a value. Defaults are the REST route's.
[[nodiscard]] std::expected<DexUsageMcpRequest, std::string>
dex_usage_mcp_request(const nlohmann::json& args);

/// The request shape recorded in the audit detail: window, platform, slice, the group id or tag
/// key (neutralised with audit_token) and floor. Never an agent id.
[[nodiscard]] std::string dex_usage_audit_shape(const DexUsageMcpRequest& rq);

} // namespace yuzu::server
