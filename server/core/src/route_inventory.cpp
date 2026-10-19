#include "route_inventory.hpp"

#include "step_up_policy.hpp"

#include <spdlog/spdlog.h>

namespace yuzu::server {

RouteInventory& RouteInventory::instance() {
    static RouteInventory inventory;
    return inventory;
}

bool RouteInventory::record(const void* server, std::string_view method,
                            std::string_view pattern) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (sealed_.count(server) == 0 || !is_step_up_table_method(method) ||
            step_up_policy_for(method, pattern) != nullptr) {
            by_server_[server].emplace(std::string(method), std::string(pattern));
            return true;
        }
    }
    spdlog::critical("route registration refused: {} {} has no MFA step-up policy row and the "
                     "route table is sealed",
                     method, pattern);
    return false;
}

void RouteInventory::seal(const void* server) {
    std::lock_guard<std::mutex> lk(mu_);
    sealed_.insert(server);
}

bool RouteInventory::is_sealed(const void* server) const {
    std::lock_guard<std::mutex> lk(mu_);
    return sealed_.count(server) != 0;
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
    sealed_.erase(server);
}

} // namespace yuzu::server
