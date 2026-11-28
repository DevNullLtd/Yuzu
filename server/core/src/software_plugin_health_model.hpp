#pragma once

/// @file software_plugin_health_model.hpp
/// Pure model behind the SAM-33 plugin-health read (`facet_health` store rows -> JSON) and the
/// fleet gauges that feed the facet alerts. No httplib, no libpq: the route injects the store
/// read and the hostname lookup.
///
/// Rules this file owns:
///  * `collecting` = full + delta + constrained + timeout + oversize. `not_collected` and
///    `disabled` collected nothing, so they are outside it (a facet unsupported on an OS reports
///    not_collected permanently and must not read as a failure).
///  * A share whose denominator is 0 is JSON null ("not shown"), never 0.
///  * Gauges carry facet and status/quantile labels only. An agent id or hostname is never a
///    label value (unbounded cardinality).

#include "software_inventory_store.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry; // sdk/include/yuzu/metrics.hpp
}

namespace yuzu::server::software_plugin_health {

/// Text before the first '.', or the whole facet when it has none (component_inventory).
[[nodiscard]] std::string plugin_of(std::string_view facet);

/// `{facets:[...], as_of, omitted}`. `hostnames` maps agent_id -> hostname for the `slowest`
/// rows (an unmapped agent gets a null hostname). `omitted_reason` empty -> `omitted` is null.
[[nodiscard]] nlohmann::json
plugin_health_json(const std::vector<FacetHealth>& facets,
                   const std::unordered_map<std::string, std::string>& hostnames,
                   std::int64_t as_of, std::string_view omitted_reason);

/// Sets `yuzu_software_facet_devices{facet,status}` for all seven statuses (0 when none) and
/// `yuzu_software_facet_duration_ms{facet,quantile=0.5|0.95}` per facet. The caller describes
/// the families.
void publish_facet_health_gauges(yuzu::MetricsRegistry& metrics,
                                 const std::vector<FacetHealth>& facets);

} // namespace yuzu::server::software_plugin_health
