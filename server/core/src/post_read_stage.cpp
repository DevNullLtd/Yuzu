#include "post_read_stage.hpp"

#include "route_inventory.hpp"

#include <stdexcept>
#include <utility>

namespace yuzu::server {

PostReadStageRegistry& PostReadStageRegistry::instance() {
    static PostReadStageRegistry registry;
    return registry;
}

void PostReadStageRegistry::install(const void* server, Stage stage) {
    if (!stage)
        throw std::logic_error("PostReadStageRegistry::install: empty stage");
    // Read the inventory before taking our own lock so the two mutexes are never nested.
    if (!RouteInventory::instance().routes_for(server).empty())
        throw std::logic_error("PostReadStageRegistry::install: a route is already registered "
                               "on this server, so it would be left without the stage");
    std::lock_guard<std::mutex> lk(mu_);
    if (by_server_.count(server) != 0)
        throw std::logic_error("PostReadStageRegistry::install: a stage is already installed "
                               "for this server");
    by_server_.emplace(server, std::make_shared<const Stage>(std::move(stage)));
}

std::shared_ptr<const PostReadStageRegistry::Stage>
PostReadStageRegistry::stage_for(const void* server) const {
    std::lock_guard<std::mutex> lk(mu_);
    const auto it = by_server_.find(server);
    return it == by_server_.end() ? nullptr : it->second;
}

void PostReadStageRegistry::forget(const void* server) {
    std::lock_guard<std::mutex> lk(mu_);
    by_server_.erase(server);
}


void ScopedPostReadStage::reset() noexcept {
    if (server_ == nullptr)
        return;
    RouteInventory::instance().forget(server_);
    PostReadStageRegistry::instance().forget(server_);
    server_ = nullptr;
}

} // namespace yuzu::server
