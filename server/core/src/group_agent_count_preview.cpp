#include "group_agent_count_preview.hpp"

#include "result_parsing.hpp" // columns_for_plugin

#include <cctype>

namespace yuzu::server {

std::string mangle_column_key(std::string_view column_name) {
    std::string out;
    out.reserve(column_name.size());
    for (char c : column_name) {
        if (c == ' ' || c == '-')
            out += '_';
        else
            out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

std::vector<FacetFilter> resolve_group_preview_filters(
    const std::string& plugin, const std::vector<std::pair<std::string, std::string>>& fields) {
    std::vector<FacetFilter> filters;
    const auto& cols = columns_for_plugin(plugin);
    // cols[0] is always "Agent" — never itself a filterable facet (mirrors
    // DashboardRoutes::parse_filters, dashboard_routes.cpp).
    for (const auto& [key, value] : fields) {
        if (value.empty())
            continue;
        for (std::size_t i = 1; i < cols.size(); ++i) {
            if (mangle_column_key(cols[i]) == key) {
                filters.push_back(FacetFilter{static_cast<int>(i - 1), value});
                break;
            }
        }
    }
    return filters;
}

std::optional<std::int64_t>
group_agent_count_preview(ResponseStore* store, const std::string& command_id,
                          const std::vector<FacetFilter>& filters,
                          const std::optional<std::vector<std::string>>& agent_scope) {
    if (filters.empty())
        return std::int64_t{0}; // genuine: no filter -> no scoped count (matches the fragment)
    if (!store)
        return std::nullopt; // unconfigured — same posture as a degraded store
    return store->facet_agent_count(command_id, filters, agent_scope);
}

} // namespace yuzu::server
