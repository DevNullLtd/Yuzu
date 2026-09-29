#pragma once

/// @file test_device_api_double.hpp
/// JsonDeviceApi — a test-only `DeviceApi` adapter wrapping the pre-ADR-0031-
/// WS-A4 `AgentsJsonFn`-shaped provider (`() -> nlohmann::json` raw registry
/// snapshot), the shape every existing device-list test fixture already
/// builds (mirrors `AgentRegistry::to_json_obj()`'s 5-field entries). Lets a
/// harness that already wires an `AgentsJsonFn` mock (e.g. `McpTestServer`)
/// keep serving `list_agents`/`get_agent_details` byte-identically without a
/// second, parallel mock data source.
///
/// NOT for production use — the production factory is `make_local_device_api`
/// (device_api_local.hpp). `lookup_device` here is an O(n) scan over the
/// json snapshot (test-only; production's contract is O(1) — see
/// device_api.hpp's #3564 POINT-LOOKUP NOTE, which applies to the real
/// implementation, not this double).

#include "device_api.hpp"

#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::test {

class JsonDeviceApi final : public yuzu::server::DeviceApi {
public:
    using Fn = std::function<nlohmann::json()>;

    explicit JsonDeviceApi(Fn fn) : fn_(std::move(fn)) {}

    [[nodiscard]] std::vector<yuzu::server::DeviceListRow> list_devices() const override {
        std::vector<yuzu::server::DeviceListRow> out;
        if (!fn_) return out;
        for (const auto& a : fn_()) out.push_back(row_from(a));
        return out;
    }

    /// #3564 short-circuit witness: counts backing reads so a test can assert an
    /// out-of-scope caller triggered ZERO lookup (the consumer denied BEFORE
    /// reaching the API). Mirrors FakeDeviceApi.lookup_calls on the REST side.
    mutable int lookup_calls = 0;

    [[nodiscard]] std::expected<std::optional<yuzu::server::DeviceDetail>,
                                yuzu::server::DeviceReadError>
    lookup_device(const std::string& agent_id) const override {
        ++lookup_calls;
        if (fn_) {
            for (const auto& a : fn_()) {
                if (a.value("agent_id", "") != agent_id) continue;
                return std::optional<yuzu::server::DeviceDetail>{
                    yuzu::server::DeviceDetail{.row = row_from(a), .tags = {}}};
            }
        }
        return std::optional<yuzu::server::DeviceDetail>{std::nullopt};
    }

private:
    static yuzu::server::DeviceListRow row_from(const nlohmann::json& a) {
        return yuzu::server::DeviceListRow{
            .agent_id = a.value("agent_id", ""),
            .hostname = a.value("hostname", ""),
            .os = a.value("os", ""),
            .arch = a.value("arch", ""),
            .agent_version = a.value("agent_version", ""),
        };
    }

    Fn fn_;
};

} // namespace yuzu::server::test
