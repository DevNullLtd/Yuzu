#pragma once

// Shared by test_runtime_config_store.cpp, test_runtime_config_secret_redaction.cpp,
// and test_settings_routes_oidc.cpp -- promoted here once a third file needed the
// identical helper (TrackerScope precedent, tests/unit/server/test_agent_service_impl.cpp).

#include "runtime_config_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace yuzu::server {

// read_secret() returns the zeroizing SecureBuffer type (ADR-0010 §1) -- this is the
// ONE place in the suite that materializes it back into a plain std::string, purely to
// compare against a synthetic literal each test hardcoded itself. Not the production
// pattern: the real caller (apply_runtime_config_overrides) copies straight from the
// buffer into its destination and never names std::string in between. See
// runtime_config_store.hpp's read_secret() doc comment.
inline std::string decrypt_for_test(const RuntimeConfigStore& store, const std::string& key) {
    auto sec = store.read_secret(key);
    REQUIRE(sec.has_value());
    if (!sec->has_value())
        return {};
    const auto& buf = **sec;
    return std::string(reinterpret_cast<const char*>(buf.data()), buf.size());
}

} // namespace yuzu::server
