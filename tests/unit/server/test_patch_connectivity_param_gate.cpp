// windows_updates.patch_connectivity: the securable follows the `targets` parameter (sg10, owner
// ruling 2026-11-18). A caller-supplied `targets` list is an `Infrastructure:Read` probe of chosen
// hosts; the built-in default patch servers stay `SoftwareDeployment:Read`. Enforced at the send
// path's chokepoint call (`classify_and_authorize_dispatch` with the parameters); a dry run that
// passes none does not evaluate the escalation.

#include "agent_registry.hpp"
#include "capability_decls/plugin_action_catalogue_d.hpp"
#include "command_capability.hpp"
#include "dispatch_caller.hpp"
#include "schedule_arming_check.hpp"
#include "schedule_arming_params.hpp"

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

// ── The ONE rule, shared by the send chokepoint and the schedule/outbox arming check ──────────

TEST_CASE("effective_securable: the shared rule, edge values",
          "[server][dispatch][security][capability][sg10]") {
    auto reg = registry();
    const auto cap = *reg.classify("windows_updates", "patch_connectivity");
    using yuzu::server::effective_securable;
    CHECK(effective_securable(cap, nullptr) == "SoftwareDeployment"); // unknown parameters
    const Params none;
    CHECK(effective_securable(cap, &none) == "SoftwareDeployment");
    const Params empty{{"targets", ""}};
    CHECK(effective_securable(cap, &empty) == "SoftwareDeployment");
    const Params blank{{"targets", "   "}}; // whitespace is SUPPLIED: the stricter reading
    CHECK(effective_securable(cap, &blank) == "Infrastructure");
    const Params other{{"target", "x"}}; // a different key never escalates
    CHECK(effective_securable(cap, &other) == "SoftwareDeployment");
    const Params real{{"targets", "h"}};
    CHECK(effective_securable(cap, &real) == "Infrastructure");
    // A row without an escalation never changes.
    const auto plain = *reg.classify("windows_updates", "installed");
    CHECK(effective_securable(plain, &real) == plain.securable);
}

TEST_CASE("classify_and_authorize_dispatch: a system caller is refused a parameter-escalated "
          "securable and admitted otherwise",
          "[server][dispatch][security][capability][sg10]") {
    auto reg = registry();
    const DispatchCaller sys{.system = true};
    Grants none{};
    const Params with_targets{{"targets", "https://wsus.example.test/"}};
    auto no = classify_and_authorize_dispatch(reg, sys, "windows_updates", "patch_connectivity", none,
                                              &with_targets);
    REQUIRE_FALSE(no.has_value());
    CHECK(no.error().reason == DispatchDenialReason::Forbidden);
    CHECK(no.error().securable == "Infrastructure");
    const Params empty{{"targets", ""}};
    CHECK(classify_and_authorize_dispatch(reg, sys, "windows_updates", "patch_connectivity", none,
                                          &empty)
              .has_value());
    CHECK(classify_and_authorize_dispatch(reg, sys, "windows_updates", "patch_connectivity", none)
              .has_value());
    CHECK(classify_and_authorize_dispatch(reg, sys, "windows_updates", "installed", none,
                                          &with_targets)
              .has_value());
}

TEST_CASE("decode_arming_parameters: decodes as the outbox send does, fails closed on bad text",
          "[server][dispatch][security][schedule][outbox][sg10]") {
    using yuzu::server::decode_arming_parameters;
    REQUIRE(decode_arming_parameters("").has_value());
    CHECK(decode_arming_parameters("")->empty());
    const auto ok = decode_arming_parameters(R"({"targets":"a","n":3,"l":[1],"z":null})");
    REQUIRE(ok.has_value());
    CHECK(ok->at("targets") == "a");
    CHECK(ok->at("n") == "3");
    CHECK(ok->at("l") == "[1]");
    CHECK(ok->at("z") == "null"); // a non-string value is SUPPLIED (non-empty), never absent
    CHECK_FALSE(decode_arming_parameters("[1,2]").has_value());
    CHECK_FALSE(decode_arming_parameters("{not json").has_value());
    CHECK_FALSE(decode_arming_parameters(std::string(200, '[') + std::string(200, ']')).has_value());
    // A non-string `targets` escalates exactly like a string one.
    auto reg = registry();
    const auto cap = *reg.classify("windows_updates", "patch_connectivity");
    const auto p = decode_arming_parameters(R"({"targets":["h"]})");
    REQUIRE(p.has_value());
    CHECK(yuzu::server::effective_securable(cap, &*p) == "Infrastructure");
}

namespace {
constexpr yuzu::server::CommandCapability kHalfPair[] = {
    {.plugin = "p", .action = "a", .dispatch_class = yuzu::server::DispatchClass::ReadOnly,
     .mutability = yuzu::server::Mutability::None, .securable = "S",
     .operation = Operation::Read, .risk_tier = yuzu::server::authz::RiskTier::Low,
     .execute_gate = yuzu::server::ExecuteGate::None, .param_escalation_key = "k"},
};
constexpr yuzu::server::CommandCapability kFullPair[] = {
    {.plugin = "p", .action = "a", .dispatch_class = yuzu::server::DispatchClass::ReadOnly,
     .mutability = yuzu::server::Mutability::None, .securable = "S",
     .operation = Operation::Read, .risk_tier = yuzu::server::authz::RiskTier::Low,
     .execute_gate = yuzu::server::ExecuteGate::None, .param_escalation_key = "k",
     .param_escalation_securable = "T"},
};
} // namespace

TEST_CASE("the capability sweep rejects a half-set escalation pair",
          "[server][dispatch][capability][sg10]") {
    static_assert(!yuzu::server::detail::all_gates_specified(kHalfPair));
    static_assert(yuzu::server::detail::all_gates_specified(kFullPair));
    SUCCEED();
}
