#include "dex_usage_json.hpp"

#include "dex_json_detail.hpp"
#include "dex_window.hpp"

#include <nlohmann/json.hpp>

#include <utility>

namespace yuzu::server {

namespace {

using json = nlohmann::json;

const char* slice_kind_token(DexUsageSliceKind k) {
    switch (k) {
    case DexUsageSliceKind::Fleet:
        return "fleet";
    case DexUsageSliceKind::Platform:
        return "platform";
    case DexUsageSliceKind::Group:
        return "group";
    case DexUsageSliceKind::Tag:
        return "tag";
    }
    return "fleet";
}

const char* cell_kind_token(DexUsageCellKind k) {
    switch (k) {
    case DexUsageCellKind::Named:
        return "named";
    case DexUsageCellKind::Untagged:
        return "untagged";
    case DexUsageCellKind::Other:
        return "other";
    }
    return "named";
}

const char* state_token(DexUsageState s) {
    switch (s) {
    case DexUsageState::Matched:
        return "matched";
    case DexUsageState::NoUsage:
        return "no_usage";
    case DexUsageState::AmbiguousName:
        return "ambiguous_name";
    }
    return "no_usage";
}

} // namespace

std::string dex_apps_usage_json(const DexAppsUsageModel& m) {
    json apps = json::array();
    for (const auto& a : m.apps) {
        json cells = json::array();
        for (const auto& c : a.cells)
            cells.push_back({{"kind", cell_kind_token(c.kind)},
                             {"label", c.label},
                             {"devices", c.devices},
                             {"run_seconds_30d", c.totals.run_seconds_30d},
                             {"launches_30d", c.totals.launches_30d},
                             {"small_cohort", c.small_cohort}});
        json o;
        o["subject"] = a.subject;
        o["state"] = state_token(a.state);
        o["devices"] = a.devices;
        // null = withheld (below the floor, no usage or an ambiguous name), never 0.
        o["run_seconds_30d"] = a.totals ? json(a.totals->run_seconds_30d) : json(nullptr);
        o["launches_30d"] = a.totals ? json(a.totals->launches_30d) : json(nullptr);
        o["cells"] = std::move(cells);
        if (a.rate)
            o["exposure_rate"] = {{"per_hour", dex_json_detail::interval_json(a.rate->per_hour, false)},
                                  {"hours", a.rate->hours},
                                  {"crashes", a.rate->crashes},
                                  {"hangs", a.rate->hangs},
                                  {"basis", a.rate->basis}};
        else
            o["exposure_rate"] = nullptr;
        o["rate_withheld"] = a.rate_withheld.empty() ? json(nullptr) : json(a.rate_withheld);
        apps.push_back(std::move(o));
    }
    const bool keyed = m.slice.kind == DexUsageSliceKind::Group || m.slice.kind == DexUsageSliceKind::Tag;
    json out;
    out["window"] = m.window;
    out["platform_scope"] = m.platform_scope;
    out["slice"] = {{"kind", slice_kind_token(m.slice.kind)}, {"key", keyed ? json(m.slice.key) : json(nullptr)}};
    out["as_of"] = dex_iso_at(m.as_of_epoch);
    out["basis"] = kDexUsageBasis;
    out["freshness_window_hours"] = kDexUsageFreshSecs / 3600;
    out["floor"] = m.floor;
    out["floor_scope"] = "per_table";
    out["population"] = m.population;
    out["reporting_devices"] = m.reporting_devices;
    out["stale_devices"] = m.stale_devices;
    out["apps"] = std::move(apps);
    // A label is agent or caller data: invalid UTF-8 is replaced, never thrown.
    return out.dump(-1, ' ', false, json::error_handler_t::replace);
}

} // namespace yuzu::server
