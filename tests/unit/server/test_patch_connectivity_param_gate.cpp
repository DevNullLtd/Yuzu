// windows_updates.patch_connectivity: the securable follows the `targets` parameter (sg10, owner
// ruling 2026-11-18). A caller-supplied `targets` list is an `Infrastructure:Read` probe of chosen
// hosts; the built-in default patch servers stay `SoftwareDeployment:Read`. Enforced at the send
// path's chokepoint call (`classify_and_authorize_dispatch` with the parameters); a dry run that
// passes none does not evaluate the escalation.

#include "agent_registry.hpp"
#include "capability_decls/plugin_action_catalogue_d.hpp"
#include "command_capability.hpp"
#include "dispatch_caller.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string>
#include <unordered_map>

using yuzu::server::authz::Operation;
using yuzu::server::CommandCapabilityRegistry;
using yuzu::server::detail::classify_and_authorize_dispatch;
using yuzu::server::detail::DispatchDenialReason;
using yuzu::server::DispatchCaller;

namespace {
using Params = std::unordered_map<std::string, std::string>;

// A caller holding exactly the listed (securable, Read) grants.
struct Grants {
    std::set<std::string> held;
    [[nodiscard]] bool operator()(std::string_view, std::string_view securable, Operation op) const {
        return op == Operation::Read && held.count(std::string(securable)) != 0;
    }
};
CommandCapabilityRegistry registry() {
    return CommandCapabilityRegistry{yuzu::server::capdecls::plugin_action_catalogue_d()};
}
const DispatchCaller kCaller{.principal = "alice", .principal_role = "operator"};
} // namespace

TEST_CASE("patch_connectivity: default targets are judged as SoftwareDeployment:Read",
          "[server][dispatch][security][capability][sg10]") {
    auto reg = registry();
    const Params none;
    const Params empty_targets{{"targets", ""}}; // an empty value is the default-target branch
    for (const Params* p : {&none, &empty_targets}) {
        Grants sd{{"SoftwareDeployment"}};
        auto ok = classify_and_authorize_dispatch(reg, kCaller, "windows_updates", "patch_connectivity", sd, p);
        REQUIRE(ok.has_value());
        CHECK(ok->securable == "SoftwareDeployment");
        Grants infra_only{{"Infrastructure"}};
        auto no = classify_and_authorize_dispatch(reg, kCaller, "windows_updates", "patch_connectivity",
                                                  infra_only, p);
        REQUIRE_FALSE(no.has_value());
        CHECK(no.error().reason == DispatchDenialReason::Forbidden);
        CHECK(no.error().securable == "SoftwareDeployment");
    }
}

TEST_CASE("patch_connectivity: a supplied targets list is judged as Infrastructure:Read",
          "[server][dispatch][security][capability][sg10]") {
    auto reg = registry();
    const Params with_targets{{"targets", "https://wsus.example.test/"}};
    Grants sd_only{{"SoftwareDeployment"}};
    auto no = classify_and_authorize_dispatch(reg, kCaller, "windows_updates", "patch_connectivity", sd_only,
                                              &with_targets);
    REQUIRE_FALSE(no.has_value());
    CHECK(no.error().reason == DispatchDenialReason::Forbidden);
    CHECK(no.error().securable == "Infrastructure");

    Grants infra{{"Infrastructure"}};
    auto ok = classify_and_authorize_dispatch(reg, kCaller, "windows_updates", "patch_connectivity", infra,
                                              &with_targets);
    REQUIRE(ok.has_value());
    CHECK(ok->securable == "Infrastructure");
}

TEST_CASE("patch_connectivity: the other windows_updates actions never escalate",
          "[server][dispatch][security][capability][sg10]") {
    auto reg = registry();
    const Params with_targets{{"targets", "x"}};
    Grants sd{{"SoftwareDeployment"}};
    for (const char* action : {"installed", "missing", "pending_reboot"}) {
        auto ok = classify_and_authorize_dispatch(reg, kCaller, "windows_updates", action, sd, &with_targets);
        REQUIRE(ok.has_value());
        CHECK(ok->securable == "SoftwareDeployment");
    }
}

TEST_CASE("patch_connectivity: a dry run with no parameters does not evaluate the escalation",
          "[server][dispatch][security][capability][sg10]") {
    // Documented limit: the pre-dispatch dry run knows no parameters, so it judges the row's own
    // securable; the send path (which always passes them) is where `targets` is enforced.
    auto reg = registry();
    Grants sd{{"SoftwareDeployment"}};
    auto ok = classify_and_authorize_dispatch(reg, kCaller, "windows_updates", "patch_connectivity", sd);
    REQUIRE(ok.has_value());
    CHECK(ok->securable == "SoftwareDeployment");
}
