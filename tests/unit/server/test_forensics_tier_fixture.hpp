#pragma once

// #4990: shared fixture for route tests that read stored responses through the Forensics tier.
//
// A route harness wires `forensics_plugin_set()` (the REAL catalogue-derived set, so the tests move
// with the catalogue) and `ForensicsCaller::fn()` into the surface under test, then flips the
// caller between the three states the production resolver can return:
//   * admin()   = a global Forensics:Read          (VisibleSet nullopt)
//   * viewer()  = no Forensics:Read at all         (present-empty, also the unwired answer)
//   * unsupported_subset(a) = a present non-empty subset. NO production resolver returns one (there
//     is no scoped Forensics read tier, #4990 W1); a surface must treat it exactly like viewer()
//     (fail closed), so the cases using it pin "a subset can never admit a Forensics row".
//   * unknown() = the resolver could not answer    (the tri-state's Unknown, `ForensicsUnknown`)
// The resolver itself is exercised against the real RbacStore in test_authz_topology_floor.cpp;
// these tests pin what each SURFACE renders for each answer, against a real store.

#include <expected>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <httplib.h>

#include "authz_model.hpp"
#include "capability_fragments.hpp"
#include "command_capability.hpp"
#include "forensics_plugin_set.hpp"
#include "forensics_visibility.hpp"

namespace yuzu::server::test {

/// The Forensics plugin set derived from the composed catalogue (throws if empty, which Catch2 reports as a failed test).
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
    std::optional<ForensicsUnknown> unknown_why; ///< engaged = the resolver answers Unknown
    int calls{0};                                ///< how many times a surface asked the resolver

    void admin() { set(std::nullopt); }
    void viewer() { set(authz::deny_all()); }
    void unsupported_subset(const std::vector<std::string>& agents) {
        set(authz::VisibleSet{std::unordered_set<std::string>(agents.begin(), agents.end())});
    }
    void unknown(ForensicsUnknown why = ForensicsUnknown::RbacUnavailable) {
        visible = authz::deny_all(); // what an ignorant consumer would see: still nothing
        unknown_why = why;
    }

    [[nodiscard]] ForensicsVisibilityFn fn() {
        return [this](const httplib::Request&) -> ForensicsVisibility {
            ++calls;
            if (unknown_why)
                return std::unexpected(*unknown_why);
            return visible;
        };
    }

private:
    void set(authz::VisibleSet v) {
        visible = std::move(v);
        unknown_why.reset();
    }
};

/// A caller who never changes: a global Forensics:Read. For a harness whose cases are not about the
/// tier but read stored responses through a surface that now needs the tier wired.
inline ForensicsCaller& permissive_forensics_caller() {
    static ForensicsCaller caller;
    return caller;
}

/// Wire the real catalogue-derived plugin set and `caller` into any surface that has the
/// `set_forensics_plugin_set` / `set_forensics_visibility_fn` setter pair (RestApiV1, McpServer,
/// DashboardRoutes).
template <class Surface>
void wire_forensics(Surface& surface, ForensicsCaller& caller) {
    surface.set_forensics_plugin_set(&forensics_plugin_set());
    surface.set_forensics_visibility_fn(caller.fn());
}

template <class Surface>
void wire_forensics_permissive(Surface& surface) {
    wire_forensics(surface, permissive_forensics_caller());
}

} // namespace yuzu::server::test
