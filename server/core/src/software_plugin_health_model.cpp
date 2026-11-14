#include "software_plugin_health_model.hpp"

#include <yuzu/metrics.hpp>

namespace yuzu::server::software_plugin_health {

namespace {

std::int64_t count_of(const FacetHealth& f, const std::string& status) {
    const auto it = f.devices_by_status.find(status);
    return it == f.devices_by_status.end() ? 0 : it->second;
}

nlohmann::json share(std::int64_t num, std::int64_t den) {
    if (den <= 0)
        return nullptr;
    return static_cast<double>(num) / static_cast<double>(den);
}

} // namespace

std::string plugin_of(std::string_view facet) {
    return std::string(facet.substr(0, facet.find('.')));
}

nlohmann::json plugin_health_json(const std::vector<FacetHealth>& facets,
                                  const std::unordered_map<std::string, std::string>& hostnames,
                                  std::int64_t as_of, std::string_view omitted_reason) {
    auto arr = nlohmann::json::array();
    for (const auto& f : facets) {
        nlohmann::json devices = nlohmann::json::object();
        std::int64_t total = 0;
        for (const auto st : kV3AllStatuses) {
            const std::string s(v3_status_name(st));
            devices[s] = count_of(f, s);
            total += count_of(f, s);
        }
        const std::int64_t collecting = count_of(f, "full") + count_of(f, "delta") +
                                        count_of(f, "constrained") + count_of(f, "timeout") +
                                        count_of(f, "oversize");
        const std::int64_t failing =
            count_of(f, "constrained") + count_of(f, "timeout") + count_of(f, "oversize");

        auto slowest = nlohmann::json::array();
        for (const auto& s : f.slowest) {
            // A blank roster hostname reads as unknown: null, not "".
            const auto h = hostnames.find(s.agent_id);
            slowest.push_back({{"agent_id", s.agent_id},
                               {"hostname", h == hostnames.end() || h->second.empty()
                                                ? nlohmann::json(nullptr)
                                                : nlohmann::json(h->second)},
                               {"duration_ms", s.duration_ms}});
        }
        arr.push_back({
            {"facet", f.facet},
            {"plugin", plugin_of(f.facet)},
            {"devices", std::move(devices)},
            {"collecting", collecting},
            {"timeout_share", share(count_of(f, "timeout"), collecting)},
            {"failing_share", share(failing, collecting)},
            {"disabled_share", share(count_of(f, "disabled"), total)},
            {"not_collected_share", share(count_of(f, "not_collected"), total)},
            {"duration_ms",
             {{"p50", f.duration_ms_p50}, {"p95", f.duration_ms_p95}, {"max", f.duration_ms_max}}},
            {"bytes_read",
             {{"p50", f.bytes_read_p50}, {"p95", f.bytes_read_p95}, {"max", f.bytes_read_max}}},
            {"slowest", std::move(slowest)},
        });
    }
    return {{"facets", std::move(arr)},
            {"as_of", as_of},
            {"omitted", omitted_reason.empty() ? nlohmann::json(nullptr)
                                               : nlohmann::json(std::string(omitted_reason))}};
}

void publish_facet_health_gauges(yuzu::MetricsRegistry& metrics,
                                 const std::vector<FacetHealth>& facets) {
    for (const auto& f : facets) {
        for (const auto st : kV3AllStatuses) {
            const std::string s(v3_status_name(st));
            metrics.gauge("yuzu_software_facet_devices", {{"facet", f.facet}, {"status", s}})
                .set(static_cast<double>(count_of(f, s)));
        }
        metrics.gauge("yuzu_software_facet_duration_ms", {{"facet", f.facet}, {"quantile", "0.5"}})
            .set(static_cast<double>(f.duration_ms_p50));
        metrics.gauge("yuzu_software_facet_duration_ms", {{"facet", f.facet}, {"quantile", "0.95"}})
            .set(static_cast<double>(f.duration_ms_p95));
    }
}

} // namespace yuzu::server::software_plugin_health
