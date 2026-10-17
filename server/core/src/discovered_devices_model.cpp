#include "discovered_devices_model.hpp"

#include "web_utils.hpp"

#include <algorithm>
#include <charconv>

namespace yuzu::server {

std::optional<int> clamp_discovered_limit(long long v) {
    if (v <= 0)
        return std::nullopt;
    return static_cast<int>(std::min<long long>(v, kDiscoveredDevicesMaxLimit));
}

std::optional<int> parse_discovered_limit(std::string_view raw) {
    if (raw.empty())
        return kDiscoveredDevicesMaxLimit;
    long long v = 0;
    const auto [end, ec] = std::from_chars(raw.data(), raw.data() + raw.size(), v);
    if (ec != std::errc{} || end != raw.data() + raw.size())
        return std::nullopt;
    return clamp_discovered_limit(v);
}

nlohmann::json discovered_device_row_json(const DiscoveredDevice& d) {
    return {{"id", d.id},
            {"ip_address", d.ip_address},
            {"mac_address", d.mac_address},
            {"hostname", d.hostname},
            {"subnet", d.subnet},
            {"discovered_by", d.discovered_by},
            {"discovered_at", d.discovered_at},
            {"last_seen", d.last_seen}};
}

nlohmann::json discovered_devices_json(const DiscoveredDevicesPage& page) {
    nlohmann::json rows = nlohmann::json::array();
    for (const auto& d : page.devices)
        rows.push_back(discovered_device_row_json(d));
    return {{"data", std::move(rows)},
            {"summary", {{"total", page.summary.total}, {"subnets", page.summary.subnets}}},
            {"truncated", page.truncated}};
}

namespace {

std::string cell(const std::string& v) {
    return v.empty() ? std::string("&mdash;") : html_escape(v);
}

std::string when(std::int64_t epoch) {
    return epoch > 0 ? html_escape(format_iso_utc(epoch)) : std::string("&mdash;");
}

} // namespace

std::string render_discovered_devices_fragment(const DiscoveredDevicesPage& page) {
    if (page.devices.empty() && page.summary.total == 0)
        return "<div class=\"empty\">No hosts discovered yet. Results appear after a scan is "
               "stored.</div>";
    std::string h = "<p class=\"hint\">" + std::to_string(page.summary.total) + " hosts across " +
                    std::to_string(page.summary.subnets) + " subnets";
    if (page.truncated)
        h += " &middot; showing the " + std::to_string(page.devices.size()) +
             " most recently seen";
    h += "</p><table class=\"dense\"><thead><tr><th>Address</th><th>Name</th><th>MAC</th>"
         "<th>Subnet</th><th>Found by</th><th>Last seen</th></tr></thead><tbody>";
    for (const auto& d : page.devices) {
        h += "<tr><td>" + cell(d.ip_address) + "</td><td>" + cell(d.hostname) + "</td><td>" +
             cell(d.mac_address) + "</td><td>" + cell(d.subnet) + "</td><td>" +
             cell(d.discovered_by) + "</td><td>" + when(d.last_seen) + "</td></tr>";
    }
    h += "</tbody></table>";
    return h;
}

std::string render_discovered_devices_unavailable() {
    return "<div class=\"failbox\" role=\"alert\">Discovered hosts could not be read just now. "
           "Try again in a moment.</div>";
}

} // namespace yuzu::server
