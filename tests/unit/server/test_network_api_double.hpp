#pragma once

/// @file test_network_api_double.hpp
/// FnNetworkApi — a test-only `NetworkApi` adapter wrapping a plain
/// `NetPerfSnapshot(cohort_key)` provider function, the shape every
/// pre-ADR-0031-WS-A4 network-perf test already builds (the retired
/// `NetPerfFn` ad-hoc provider's signature). Lets the NetworkRoutes /
/// RestApiV1 / McpServer test harnesses keep constructing a fake snapshot
/// directly instead of standing up a real AgentHealthStore/AgentRegistry
/// (`LocalNetworkApi`'s only production implementation, network_api.cpp) for
/// every network-route test.
///
/// NOT for production use — the production factory is
/// `make_local_network_api` (network_api_local.hpp).

#include "network_api.hpp"
#include "network_perf_model.hpp"

#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::test {

class FnNetworkApi final : public yuzu::server::NetworkApi {
public:
    using Fn = std::function<yuzu::server::NetPerfSnapshot(const std::string&)>;

    explicit FnNetworkApi(Fn fn) : fn_(std::move(fn)) {}

    [[nodiscard]] yuzu::server::NetPerfFleetNow
    fleet_now(const std::string& cohort_key) const override {
        return yuzu::server::net_perf_fleet_now(fn_(cohort_key));
    }

    [[nodiscard]] std::vector<yuzu::server::NetPerfDeviceRow>
    device_list(const yuzu::server::NetDeviceQuery& q) const override {
        return yuzu::server::net_perf_device_list(fn_(q.cohort_key), q.metric, q.not_reporting,
                                                  q.cooc, q.cohort_filter, q.limit);
    }

private:
    Fn fn_;
};

} // namespace yuzu::server::test
