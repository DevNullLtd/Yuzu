#include "discovered_devices_reader.hpp"

#include "discovery_store.hpp"

namespace yuzu::server {

DiscoveredDevicesReadFn make_discovered_devices_reader(DiscoveryStore* store) {
    return [store](const std::string& subnet,
                   int limit) -> std::expected<DiscoveredDevicesPage, std::string> {
        if (store == nullptr || !store->is_open())
            return std::unexpected("discovery store unavailable");
        // One extra row distinguishes "exactly limit" from "more than limit".
        auto rows = store->list_devices_checked(subnet, limit + 1);
        if (!rows)
            return std::unexpected(rows.error());
        auto summary = store->summarize(subnet);
        if (!summary)
            return std::unexpected(summary.error());
        DiscoveredDevicesPage page;
        page.truncated = rows->size() > static_cast<std::size_t>(limit);
        if (page.truncated)
            rows->resize(static_cast<std::size_t>(limit));
        page.devices = std::move(*rows);
        page.summary = *summary;
        return page;
    };
}

} // namespace yuzu::server
