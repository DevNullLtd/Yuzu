#pragma once

// #4990: shared fixture for route tests that read stored responses through the Forensics tier.
//
// A route harness wires `forensics_plugin_set()` (the REAL catalogue-derived set, so the tests move
// with the catalogue) and `ForensicsCaller::fn()` into the surface under test, then flips the
// caller between the three states the production resolver can return:
//   * admin()   = a global Forensics:Read          (VisibleSet nullopt)
//   * viewer()  = no Forensics:Read at all         (present-empty, also the unwired answer)
//   * scoped(a) = Forensics:Read on those agents   (present subset)
// The resolver itself is exercised against the real RbacStore in test_authz_topology_floor.cpp;
// these tests pin what each SURFACE renders for each answer, against a real store.

#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include <httplib.h>

#include "authz_model.hpp"
#include "capability_fragments.hpp"
#include "command_capability.hpp"
#include "forensics_plugin_set.hpp"
#include "forensics_visibility.hpp"

namespace yuzu::server::test {

/// The Forensics plugin set derived from the composed catalogue (aborts the test run if empty).
inline const ForensicsPluginSet& forensics_plugin_set() {
    static const CommandCapabilityRegistry registry{YUZU_ALL_CAPABILITY_FRAGMENTS};
    static const std::optional<ForensicsPluginSet> set = derive_forensics_plugin_set(registry);
    if (!set)
        throw std::runtime_error("forensics_plugin_set: the catalogue derived an empty set");
    return *set;
}

/// A plugin that is Forensics-tier (pinned by the catalogue tests) and one that is not.
inline constexpr const char* kForensicsPlugin = "browser_inventory";
inline constexpr const char* kOrdinaryPlugin = "shellexec";

/// The caller's Forensics visibility, mutable between requests. `fn()` borrows `*this`.
struct ForensicsCaller {
    authz::VisibleSet visible{std::nullopt};

    void admin() { visible = std::nullopt; }
    void viewer() { visible = authz::deny_all(); }
    void scoped(const std::vector<std::string>& agents) {
        visible = authz::VisibleSet{std::unordered_set<std::string>(agents.begin(), agents.end())};
    }

    [[nodiscard]] ForensicsVisibilityFn fn() {
        return [this](const httplib::Request&) { return visible; };
    }
};

} // namespace yuzu::server::test
