// YUZU_REQUIRE_PG_MIGRATION_DB's own contract (#2354, #3443 Windows CI
// test-phase split) had no direct test coverage before this file — every
// other verification of it was empirical (a real Windows CI run observing
// the SKIP message) rather than a pinned, in-repo regression guard. No
// Postgres connection needed: this tests the predicate logic only, not
// migration behavior.

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

TEST_CASE("is_migration_ddl_opt_in: exact \"1\" only; fail-closed otherwise",
          "[helpers][pg_migration_skip]") {
    // The one value that opts IN to running the expensive migration DDL.
    CHECK(yuzu::test::is_migration_ddl_opt_in("1"));

    // Everything else stays opted OUT (skipped), matching the fail-closed
    // design: a stale, malformed, or merely-truthy value must never
    // silently un-skip on a shared, persistent runner.
    CHECK_FALSE(yuzu::test::is_migration_ddl_opt_in(nullptr));
    CHECK_FALSE(yuzu::test::is_migration_ddl_opt_in(""));
    CHECK_FALSE(yuzu::test::is_migration_ddl_opt_in("0"));
    CHECK_FALSE(yuzu::test::is_migration_ddl_opt_in("true"));
    CHECK_FALSE(yuzu::test::is_migration_ddl_opt_in("yes"));
    CHECK_FALSE(yuzu::test::is_migration_ddl_opt_in("11"));
    CHECK_FALSE(yuzu::test::is_migration_ddl_opt_in(" 1"));
    CHECK_FALSE(yuzu::test::is_migration_ddl_opt_in("1 "));
    CHECK_FALSE(yuzu::test::is_migration_ddl_opt_in("1\n"));
}

TEST_CASE("pg_fresh_db_migration_skipped_here: never skips off Windows",
          "[helpers][pg_migration_skip]") {
    // The whole point of #2354/#3443: Linux (and macOS) never skip these
    // tests regardless of environment — the skip is Windows-only by
    // #ifdef, not by any runtime check this test could accidentally
    // exercise on the wrong platform. Compiled out entirely on Windows,
    // where the function's own #ifdef branch (tested via
    // is_migration_ddl_opt_in above, since std::getenv itself isn't
    // meaningfully mockable here) is the live path instead.
#ifndef _WIN32
    CHECK_FALSE(yuzu::test::pg_fresh_db_migration_skipped_here());
#endif
}
