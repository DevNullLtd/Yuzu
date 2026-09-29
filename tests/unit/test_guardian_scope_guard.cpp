// Unit tests for GuardianRollback (ADR-0021 rung 7.7b, PR-1 item 3 / Sol B3): the
// terminate-safe rollback guard whose destructor must NEVER propagate a cleanup throw
// (a plain noexcept ~ScopeExit would std::terminate the agent mid-unwind).

#include "guardian_scope_guard.hpp"

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>

using namespace yuzu::agent;

TEST_CASE("GuardianRollback runs fn on scope exit unless committed", "[guardian][scopeguard]") {
    int ran = 0;
    {
        GuardianRollback g;
        g.fn = [&] { ++ran; };
    }
    CHECK(ran == 1);

    ran = 0;
    {
        GuardianRollback g;
        g.fn = [&] { ++ran; };
        g.committed = true; // committed -> fn does NOT run
    }
    CHECK(ran == 0);
}

TEST_CASE("GuardianRollback swallows a throwing cleanup and counts it (no terminate)",
          "[guardian][scopeguard]") {
    const auto before = guardian_rollback_cleanup_failures();
    // A cleanup that throws during the guard's destruction must be swallowed - a plain
    // noexcept destructor would call std::terminate. The counter records it.
    CHECK_NOTHROW([] {
        GuardianRollback g;
        g.fn = [] { throw std::runtime_error("cleanup boom"); };
    }());
    CHECK(guardian_rollback_cleanup_failures() == before + 1);
}
