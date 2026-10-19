/**
 * test_step_up_policy.cpp — self-checks of the step-up policy table
 * (server/core/src/step_up_policy.hpp). Pure constexpr data: no Postgres, no sockets.
 *
 * The consteval self-check in the header already makes a duplicate key, a missing reason or a
 * missing label a build failure; these cases pin the table's CONTENT (the already-gated set and
 * the three own-gate rows) and the exact-key lookup semantics a prefix matcher would break.
 */

#include "../../../server/core/src/step_up_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

std::size_t count_class(StepUpClass c) {
    std::size_t n = 0;
    for (const auto& e : kStepUpPolicy)
        n += (e.cls == c) ? 1 : 0;
    return n;
}

} // namespace

TEST_CASE("step-up policy: table has no duplicate (method, pattern) key", "[stepup][policy]") {
    std::set<std::pair<std::string, std::string>> seen;
    for (const auto& e : kStepUpPolicy) {
        INFO(std::string(e.method) << " " << std::string(e.pattern));
        CHECK(seen.emplace(std::string(e.method), std::string(e.pattern)).second);
    }
    CHECK(seen.size() == kStepUpPolicyCount);
}

TEST_CASE("step-up policy: every row has a verb the table classifies and a pattern",
          "[stepup][policy]") {
    for (const auto& e : kStepUpPolicy) {
        INFO(std::string(e.method) << " " << std::string(e.pattern));
        CHECK(is_step_up_table_method(e.method));
        CHECK_FALSE(e.pattern.empty());
        CHECK(e.method != "GET");
        CHECK(e.method != "OPTIONS");
    }
}

TEST_CASE("step-up policy: kExempt and kOwnGate rows carry a reason, kRequired rows a label",
          "[stepup][policy]") {
    for (const auto& e : kStepUpPolicy) {
        INFO(std::string(e.method) << " " << std::string(e.pattern));
        if (e.cls == StepUpClass::kExempt || e.cls == StepUpClass::kOwnGate)
            CHECK_FALSE(e.reason.empty());
        if (e.cls == StepUpClass::kRequired)
            CHECK_FALSE(e.action_label.empty());
    }
}

TEST_CASE("step-up policy: the already-gated set is exactly the 31 routes with an in-handler call",
          "[stepup][policy]") {
    CHECK(count_class(StepUpClass::kRequired) == 31);
    CHECK(count_class(StepUpClass::kOwnGate) == 3);
    CHECK(count_class(StepUpClass::kStrong) == 0);
    for (const auto& e : kStepUpPolicy) {
        if (e.cls == StepUpClass::kRequired)
            CHECK(e.rollout == Rollout::kOriginal);
    }
}

TEST_CASE("step-up policy: kOwnGate is the three elevation routes", "[stepup][policy]") {
    const auto* a = step_up_policy_for("POST", R"(/api/v1/users/([^/]+)/elevation-eligibility)");
    const auto* b = step_up_policy_for("POST", R"(/api/v1/users/elevation-eligibility)");
    const auto* c = step_up_policy_for("POST", R"(/api/v1/elevate)");
    REQUIRE(a != nullptr);
    REQUIRE(b != nullptr);
    REQUIRE(c != nullptr);
    CHECK(a->cls == StepUpClass::kOwnGate);
    CHECK(b->cls == StepUpClass::kOwnGate);
    CHECK(c->cls == StepUpClass::kOwnGate);
    for (const auto& e : kStepUpPolicy) {
        if (e.cls == StepUpClass::kOwnGate)
            CHECK(e.pattern.find("elevat") != std::string_view::npos);
    }
}

TEST_CASE("step-up policy: lookup is by exact key, never by prefix or verb-blind",
          "[stepup][policy]") {
    SECTION("exact hit keeps today's audit label") {
        const auto* e = step_up_policy_for("POST", "/api/v1/tokens");
        REQUIRE(e != nullptr);
        CHECK(e->cls == StepUpClass::kRequired);
        CHECK(e->action_label == "POST /api/v1/tokens");
    }
    SECTION("a raw-string pattern is the registered text, escapes included") {
        const auto* e =
            step_up_policy_for("PUT", R"(/api/v1/guaranteed-state/rules/([A-Za-z0-9._\-]+))");
        REQUIRE(e != nullptr);
        CHECK(e->action_label == "PUT /api/v1/guaranteed-state/rules/{id}");
    }
    SECTION("a prefix of a registered pattern does not match") {
        CHECK(step_up_policy_for("POST", "/api/v1/token") == nullptr);
        CHECK(step_up_policy_for("POST", "/api/v1/tokens/") == nullptr);
        CHECK(step_up_policy_for("POST", "/api/v1/tokensevil") == nullptr);
    }
    SECTION("the concrete request path is not a key") {
        CHECK(step_up_policy_for("POST", "/api/v1/tokens/abc/rotate") == nullptr);
    }
    SECTION("a different verb on a registered pattern does not match") {
        CHECK(step_up_policy_for("GET", "/api/v1/tokens") == nullptr);
        CHECK(step_up_policy_for("PUT", "/api/v1/tokens") == nullptr);
        CHECK(step_up_policy_for("DELETE", "/api/v1/tokens") == nullptr);
    }
    SECTION("an empty key matches nothing") {
        CHECK(step_up_policy_for("", "") == nullptr);
        CHECK(step_up_policy_for("POST", "") == nullptr);
    }
}

TEST_CASE("step-up policy: kPendingRuling count is within its pinned ceiling", "[stepup][policy]") {
    CHECK(count_class(StepUpClass::kPendingRuling) <= kPendingRulingMax);
}

TEST_CASE("step-up policy: kPendingRulingMax equals the pending row count and may only be lowered",
          "[stepup][policy]") {
    // The ceiling is kept EXACT, so resolving a pending row forces the constant down in the same
    // change; a ceiling above the count would leave headroom for a new route to park as pending.
    CHECK(count_class(StepUpClass::kPendingRuling) == kPendingRulingMax);
    for (const auto& e : kStepUpPolicy) {
        if (e.cls != StepUpClass::kPendingRuling)
            continue;
        INFO(std::string(e.method) << " " << std::string(e.pattern));
        CHECK(e.reason == step_up_detail::kPendingReason);
        CHECK(e.action_label.empty());
    }
}

TEST_CASE("step-up policy: every kExempt reason is one of the named exempt classes",
          "[stepup][policy]") {
    using namespace step_up_detail;
    const std::set<std::string_view> classes = {
        kPreSession,         kStepUpProofEndpoint,  kSelfSignOut,       kSelfPrivilegeReduction,
        kExecutionDispatch,  kApprovalGatedElsewhere, kOperationalData, kReadShaped,
        kSyncTrigger,        kAgentUploadProtocol,  kScimBearer,        kMcpTransport,
        kContentAuthoring,   kPolicyLifecycle,      kEvidenceCapture,   kStopsEffect,
        kAlertingConfig,     kMfaEnrolment,         kSchedulingGatedWork, kSelfNotificationState};
    std::set<std::string_view> used;
    for (const auto& e : kStepUpPolicy) {
        if (e.cls != StepUpClass::kExempt)
            continue;
        INFO(std::string(e.method) << " " << std::string(e.pattern));
        CHECK(classes.contains(e.reason));
        used.insert(e.reason);
    }
    // An exempt class nobody uses is a stale entry in the reviewed vocabulary.
    CHECK(used.size() == classes.size());
}

TEST_CASE("step-up policy: unclassified-route sweep names exactly the missing mutating routes",
          "[stepup][policy]") {
    using Routes = std::vector<std::pair<std::string_view, std::string_view>>;
    SECTION("classified routes and non-mutating verbs are not reported") {
        const Routes routes = {{"POST", "/api/v1/tokens"},
                               {"POST", R"(/api/v1/elevate)"},
                               {"GET", "/api/v1/anything"},
                               {"OPTIONS", "/api/v1/anything"}};
        CHECK(step_up_unclassified_routes(routes).empty());
    }
    SECTION("an unclassified mutating route is reported with its verb") {
        const Routes routes = {{"POST", "/api/v1/tokens"}, {"PUT", "/api/v1/not-in-the-table"}};
        const auto missing = step_up_unclassified_routes(routes);
        REQUIRE(missing.size() == 1);
        CHECK(missing[0].first == "PUT");
        CHECK(missing[0].second == "/api/v1/not-in-the-table");
    }
    SECTION("a registered pattern under the wrong verb is unclassified") {
        const Routes routes = {{"PUT", "/api/v1/tokens"}};
        CHECK(step_up_unclassified_routes(routes).size() == 1);
    }
}
