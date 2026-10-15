/**
 * test_launchd_state.cpp -- tests for yuzu/agent/launchd_state.hpp's
 * launchd_state_for(). Moved out of test_launchctl_list.cpp (A0 governance
 * fix round) with its header: agents/shared/ is a zero-dependency leaf, so
 * launchd_state_for (needs yuzu::agent::ServiceRunState) lives in
 * agents/core instead.
 */
#include <yuzu/agent/launchd_state.hpp>

#include <catch2/catch_test_macros.hpp>

using yuzu::shared::LaunchctlRow;

TEST_CASE("launchd_state_for: listed with a pid resolves Running",
          "[launchd_state]") {
    std::vector<LaunchctlRow> rows = {
        {"com.apple.progressd", 1190, 0},
    };
    CHECK(yuzu::agent::launchd_state_for(rows, "com.apple.progressd")
          == yuzu::agent::ServiceRunState::Running);
}

TEST_CASE("launchd_state_for: listed without a pid resolves Stopped",
          "[launchd_state]") {
    std::vector<LaunchctlRow> rows = {
        {"com.apple.SafariHistoryServiceAgent", std::nullopt, 0},
    };
    CHECK(yuzu::agent::launchd_state_for(rows, "com.apple.SafariHistoryServiceAgent")
          == yuzu::agent::ServiceRunState::Stopped);
}

TEST_CASE("launchd_state_for: a label absent from the snapshot resolves Stopped, "
          "never Paused",
          "[launchd_state]") {
    std::vector<LaunchctlRow> rows = {
        {"com.apple.progressd", 1190, 0},
    };
    CHECK(yuzu::agent::launchd_state_for(rows, "com.apple.not.installed")
          == yuzu::agent::ServiceRunState::Stopped);
}
