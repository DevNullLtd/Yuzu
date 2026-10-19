#include "route_inventory.hpp"

namespace yuzu::server {

RouteInventory& RouteInventory::instance() {
    static RouteInventory inventory;
    return inventory;
}

void RouteInventory::record(const void* server, std::string_view method,
                            std::string_view pattern) {
    std::lock_guard<std::mutex> lk(mu_);
    by_server_[server].emplace(std::string(method), std::string(pattern));
}

std::vector<RouteInventory::Route> RouteInventory::routes_for(const void* server) const {
    std::lock_guard<std::mutex> lk(mu_);
    const auto it = by_server_.find(server);
    if (it == by_server_.end())
        return {};
    return {it->second.begin(), it->second.end()};
}

void RouteInventory::forget(const void* server) {
    std::lock_guard<std::mutex> lk(mu_);
    by_server_.erase(server);
}

} // namespace yuzu::server
