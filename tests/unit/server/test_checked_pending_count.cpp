// test_checked_pending_count.cpp -- the throw-folding wrapper around the MCP approval mint's
// per-submitter pending count (checked_pending_count.hpp).
//
// An unreadable count must refuse, never read as zero (zero would admit every principal exactly
// when the approval store is struggling), and a count that THROWS is the same unreadable count.
// The wrapper is exercised with plain callables, so no Postgres store has to be made to throw.

#include "checked_pending_count.hpp"

#include <catch2/catch_test_macros.hpp>

#include <expected>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>

using yuzu::server::checked_pending_count;
using yuzu::server::StoreReadError;

namespace {
struct NotAStdException {};

// Pins "deliberately NOT noexcept": a noexcept wrapper would std::terminate on any throw its
// catch-all did not absorb, and an accidental `noexcept` is invisible to a runtime test.
[[maybe_unused]] auto throwing_fn = []() -> std::expected<int, StoreReadError> {
    throw std::runtime_error("x");
};
static_assert(!noexcept(checked_pending_count(throwing_fn)),
              "checked_pending_count must not be noexcept");
} // namespace

TEST_CASE("checked_pending_count: a returned value passes through", "[checked_pending_count]") {
    const auto r = checked_pending_count([]() -> std::expected<int, StoreReadError> { return 7; });
    REQUIRE(r.has_value());
    CHECK(*r == 7);
    const auto zero =
        checked_pending_count([]() -> std::expected<int, StoreReadError> { return 0; });
    REQUIRE(zero.has_value());
    CHECK(*zero == 0);
}

TEST_CASE("checked_pending_count: an unexpected passes through unchanged",
          "[checked_pending_count]") {
    const auto r = checked_pending_count([]() -> std::expected<int, StoreReadError> {
        return std::unexpected(StoreReadError{"relation does not exist", "42P01"});
    });
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().message == "relation does not exist");
    CHECK(r.error().sqlstate == "42P01");
}

TEST_CASE("checked_pending_count: a thrown exception becomes an empty unexpected",
          "[checked_pending_count]") {
    SECTION("std::runtime_error") {
        const auto r = checked_pending_count([]() -> std::expected<int, StoreReadError> {
            throw std::runtime_error("driver fault");
        });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().message.empty());
        CHECK(r.error().sqlstate.empty());
    }
    SECTION("a non-std type (catch-all)") {
        const auto r = checked_pending_count(
            []() -> std::expected<int, StoreReadError> { throw NotAStdException{}; });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().message.empty());
        CHECK(r.error().sqlstate.empty());
    }
    SECTION("std::bad_alloc") {
        const auto r = checked_pending_count(
            []() -> std::expected<int, StoreReadError> { throw std::bad_alloc(); });
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().message.empty());
        CHECK(r.error().sqlstate.empty());
    }
    SECTION("an int") {
        const auto r =
            checked_pending_count([]() -> std::expected<int, StoreReadError> { throw 5; });
        REQUIRE_FALSE(r.has_value());
    }
}

TEST_CASE("checked_pending_count: a throwing count never reads as zero",
          "[checked_pending_count]") {
    // The fail-closed property the mint depends on: the result of a throw must be the error arm,
    // so `*pending_now >= cap` is never evaluated against a defaulted 0.
    const auto r = checked_pending_count(
        []() -> std::expected<int, StoreReadError> { throw std::runtime_error("x"); });
    CHECK_FALSE(r.has_value());
}
