/**
 * test_step_up_policy.cpp - self-checks of the step-up policy table
 * (server/core/src/step_up_policy.hpp). Pure constexpr data: no Postgres, no sockets.
 *
 * The consteval self-check in the header already makes a duplicate key, a missing reason or a
 * missing label a build failure; these cases pin the table's CONTENT (the already-gated set and
 * the three own-gate rows) and the exact-key lookup semantics a prefix matcher would break.
 */

#include "../../../server/core/src/step_up_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <iterator>
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

TEST_CASE("step-up policy: the gated set is exactly the 37 routes with an in-handler call",
          "[stepup][policy]") {
    CHECK(count_class(StepUpClass::kRequired) == 37);
    CHECK(count_class(StepUpClass::kOwnGate) == 3);
    CHECK(count_class(StepUpClass::kStrong) == 0);
}

TEST_CASE("step-up policy: the table's total and per-class row counts are pinned",
          "[stepup][policy]") {
    // Executable pins for the table counts (235 mutating REST routes: 37 required, 3 own-gate,
    // 122 exempt, 73 pending). A row added or reclassified without these numbers moving
    // together fails here.
    CHECK(kStepUpPolicyCount == 235);
    CHECK(count_class(StepUpClass::kExempt) == 122);
    CHECK(count_class(StepUpClass::kPendingRuling) == 73);
    CHECK(count_class(StepUpClass::kRequired) + count_class(StepUpClass::kOwnGate) +
              count_class(StepUpClass::kStrong) + count_class(StepUpClass::kExempt) +
              count_class(StepUpClass::kPendingRuling) ==
          kStepUpPolicyCount);
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
    SECTION("the approval decisions and the policy-generation raise carry their in-handler labels") {
        const auto* approve = step_up_policy_for("POST", R"(/api/approvals/([^/]+)/approve)");
        const auto* reject = step_up_policy_for("POST", R"(/api/approvals/([^/]+)/reject)");
        const auto* raise =
            step_up_policy_for("POST", "/api/v1/guaranteed-state/policy-generation/raise");
        REQUIRE(approve != nullptr);
        REQUIRE(reject != nullptr);
        REQUIRE(raise != nullptr);
        CHECK(approve->cls == StepUpClass::kRequired);
        CHECK(reject->cls == StepUpClass::kRequired);
        CHECK(raise->cls == StepUpClass::kRequired);
        CHECK(approve->action_label == "POST /api/approvals/{id}/approve");
        CHECK(reject->action_label == "POST /api/approvals/{id}/reject");
        CHECK(raise->action_label == "POST /api/v1/guaranteed-state/policy-generation/raise");
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

namespace {

struct PendingKey {
    std::string_view method;
    std::string_view pattern;
};

// The exact (method, pattern) set of the kPendingRuling rows, sorted by (pattern, method).
// kPendingRulingMax alone only bounds how MANY rows are pending, so swapping one pending key for
// another would pass; this list pins WHICH ones. Resolving a row (moving it to kRequired or to
// kExempt with a named reason) means deleting its entry here AND lowering kPendingRulingMax in
// the same change. A NEW mutating route is never added here: classify it kExempt with a named
// reason, or kRequired with an action label.
constexpr PendingKey kGrandfatheredPending[] = {
    {"PUT", R"(/api/config/([a-z_]+))"},
    {"POST", R"(/api/dashboard/group-from-results)"},
    {"PUT", R"(/api/directory/group-mappings)"},
    {"POST", R"(/api/settings/auto-approve)"},
    {"DELETE", R"(/api/settings/auto-approve/(\d+))"},
    {"POST", R"(/api/settings/auto-approve/(\d+)/toggle)"},
    {"POST", R"(/api/settings/auto-approve/mode)"},
    {"POST", R"(/api/settings/ca/import-chain)"},
    {"POST", R"(/api/settings/ca/revoke)"},
    {"POST", R"(/api/settings/cert-paste)"},
    {"POST", R"(/api/settings/cert-upload)"},
    {"POST", R"(/api/settings/enrollment-tokens)"},
    {"DELETE", R"(/api/settings/enrollment-tokens/(.+))"},
    {"POST", R"(/api/settings/enrollment-tokens/batch)"},
    {"POST", R"(/api/settings/management-groups)"},
    {"DELETE", R"(/api/settings/management-groups/([a-f0-9]+))"},
    {"POST", R"(/api/settings/mcp)"},
    {"POST", R"(/api/settings/oidc)"},
    {"DELETE", R"(/api/settings/pending-agents/(.+))"},
    {"POST", R"(/api/settings/pending-agents/(.+)/approve)"},
    {"POST", R"(/api/settings/pending-agents/(.+)/deny)"},
    {"POST", R"(/api/settings/pending-agents/bulk-approve)"},
    {"POST", R"(/api/settings/pending-agents/bulk-deny)"},
    {"POST", R"(/api/settings/plugin-signing/clear)"},
    {"POST", R"(/api/settings/plugin-signing/require)"},
    {"POST", R"(/api/settings/plugin-signing/upload)"},
    {"POST", R"(/api/settings/tls)"},
    {"DELETE", R"(/api/settings/updates/([^/]+)/([^/]+)/([^/]+))"},
    {"POST", R"(/api/settings/updates/([^/]+)/([^/]+)/([^/]+)/rollout)"},
    {"POST", R"(/api/settings/updates/upload)"},
    {"POST", R"(/api/settings/users)"},
    {"POST", R"(/api/v1/ca/import-chain)"},
    {"POST", R"(/api/v1/ca/issue-code-signing)"},
    {"POST", R"(/api/v1/ca/revoke)"},
    {"POST", R"(/api/v1/device-tokens)"},
    {"DELETE", R"(/api/v1/device-tokens/([a-f0-9]+))"},
    {"POST", R"(/api/v1/license)"},
    {"DELETE", R"(/api/v1/license/([a-f0-9]+))"},
    {"POST", R"(/api/v1/management-groups)"},
    {"DELETE", R"(/api/v1/management-groups/([a-f0-9]+))"},
    {"PUT", R"(/api/v1/management-groups/([a-f0-9]+))"},
    {"POST", R"(/api/v1/management-groups/([a-f0-9]+)/members)"},
    {"DELETE", R"(/api/v1/management-groups/([a-f0-9]+)/members/(.+))"},
    {"DELETE", R"(/api/v1/management-groups/([a-f0-9]+)/roles)"},
    {"POST", R"(/api/v1/management-groups/([a-f0-9]+)/roles)"},
    {"POST", R"(/api/v1/offload-targets)"},
    {"DELETE", R"(/api/v1/offload-targets/(\d+))"},
    {"DELETE", R"(/api/v1/plugin-config/([^/]+)/([^/]+))"},
    {"PUT", R"(/api/v1/plugin-config/([^/]+)/([^/]+))"},
    {"DELETE", R"(/api/v1/plugin-config/([^/]+)/([^/]+)/secret)"},
    {"PUT", R"(/api/v1/plugin-config/([^/]+)/([^/]+)/secret)"},
    {"PUT", R"(/api/v1/plugin-config/([^/]+)/kill-switch)"},
    {"POST", R"(/api/v1/quarantine)"},
    {"DELETE", R"(/api/v1/quarantine/(.+))"},
    {"POST", R"(/api/v1/secrets/kek/rewrap)"},
    {"POST", R"(/api/v1/secrets/kek/rotate)"},
    {"DELETE", R"(/api/v1/sle/agents/([^/]+))"},
    {"POST", R"(/api/v1/software-deployments)"},
    {"POST", R"(/api/v1/software-deployments/([a-f0-9]+)/rollback)"},
    {"POST", R"(/api/v1/tar/retention-paused/purge)"},
    {"POST", R"(/api/v1/upload-grants)"},
    {"DELETE", R"(/api/v1/upload-grants/([a-f0-9]+))"},
    {"POST", R"(/api/webhooks)"},
    {"DELETE", R"(/api/webhooks/(\d+))"},
    {"POST", R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+))"},
    {"POST", R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/delete)"},
    {"POST", R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/deploy)"},
    {"POST", R"(/fragments/guardian/baselines)"},
    {"POST", R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/enabled)"},
    {"POST", R"(/fragments/guardian/guards)"},
    {"POST", R"(/fragments/tar/capture-sources/push)"},
    {"POST", R"(/fragments/tar/retention-paused/purge)"},
    {"POST", R"(/fragments/tar/retention-paused/reenable)"},
};

} // namespace

TEST_CASE("step-up policy: every kPendingRuling row is in the grandfathered pending list",
          "[stepup][policy]") {
    std::set<std::pair<std::string, std::string>> pinned;
    for (const auto& k : kGrandfatheredPending)
        pinned.emplace(std::string(k.method), std::string(k.pattern));
    for (const auto& e : kStepUpPolicy) {
        if (e.cls != StepUpClass::kPendingRuling)
            continue;
        INFO("pending row not in the grandfathered list: " << std::string(e.method) << " "
                                                           << std::string(e.pattern));
        CHECK(pinned.count({std::string(e.method), std::string(e.pattern)}) == 1);
    }
}

TEST_CASE("step-up policy: the grandfathered pending list is sorted, unique and moves with the "
          "count",
          "[stepup][policy]") {
    std::set<std::pair<std::string, std::string>> seen;
    const PendingKey* prev = nullptr;
    for (const auto& k : kGrandfatheredPending) {
        INFO(std::string(k.method) << " " << std::string(k.pattern));
        CHECK(seen.emplace(std::string(k.method), std::string(k.pattern)).second);
        if (prev != nullptr)
            CHECK(std::pair(prev->pattern, prev->method) < std::pair(k.pattern, k.method));
        prev = &k;
        // Every listed key is still a pending row: a resolved row must leave this list.
        const auto* row = step_up_policy_for(k.method, k.pattern);
        REQUIRE(row != nullptr);
        CHECK(row->cls == StepUpClass::kPendingRuling);
    }
    CHECK(std::size(kGrandfatheredPending) == count_class(StepUpClass::kPendingRuling));
    CHECK(std::size(kGrandfatheredPending) == kPendingRulingMax);
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
