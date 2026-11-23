#include "live_result_json.hpp"

#include "live_model.hpp"

#include <nlohmann/json.hpp>

#include <utility>

namespace yuzu::server::live {

namespace {
using json = nlohmann::ordered_json; // insertion order: the REST key order is part of the wire shape
} // namespace

std::optional<LiveResultJson> live_result_json(std::string_view kind, const std::string& output,
                                               std::size_t max_rows) {
    // Only the two rest_v1 kinds exist on this seam. Resolving through the kind table as well
    // means a kind that is later flagged rest_v1 without teaching this function fails closed
    // here (nullopt) rather than rendering as processes.
    if (kind != "uptime" && kind != "processes")
        return std::nullopt;
    if (!resolve_rest_kind(std::string(kind)))
        return std::nullopt;

    LiveResultJson r;
    json o = json::object();
    if (kind == "uptime") {
        const auto u = parse_uptime(output);
        o["kind"] = "uptime";
        if (u.display)
            o["uptime_display"] = *u.display;
        if (u.seconds)
            o["uptime_seconds"] = *u.seconds;
    } else {
        auto rows = parse_processes(output);
        if (max_rows > 0 && rows.size() > max_rows) {
            rows.resize(max_rows);
            r.truncated = true;
        }
        json procs = json::array();
        for (const auto& p : rows) {
            procs.push_back(json{{"pid", p.pid}, {"name", p.name}, {"sha256", p.sha256}, {"path", p.path}});
        }
        r.count = rows.size();
        o["kind"] = "processes";
        o["processes"] = std::move(procs);
    }
    r.body = o.dump(-1, ' ', false, json::error_handler_t::replace);
    return r;
}

} // namespace yuzu::server::live
