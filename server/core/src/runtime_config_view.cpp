#include "runtime_config_view.hpp"

#include "config_secret_keys.hpp"

namespace yuzu::server {

nlohmann::json build_overrides_json(const std::vector<RuntimeConfigEntry>& entries) {
    nlohmann::json overrides = nlohmann::json::object();
    for (const auto& e : entries) {
        if (is_secret_config_key(e.key)) {
            overrides[e.key] = {{"is_set", !e.value.empty()},
                                {"updated_by", e.updated_by},
                                {"updated_at", e.updated_at}};
        } else {
            overrides[e.key] = {{"value", e.value},
                                {"updated_by", e.updated_by},
                                {"updated_at", e.updated_at}};
        }
    }
    return overrides;
}

} // namespace yuzu::server
