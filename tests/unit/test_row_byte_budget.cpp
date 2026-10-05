/**
 * test_row_byte_budget.cpp -- unit tests for agents/shared/row_byte_budget.hpp, the shared
 * row/byte budget. Pure arithmetic: runs unguarded on every OS.
 */
#include <catch2/catch_test_macros.hpp>

#include <row_byte_budget.hpp>

#include <cstddef>
#include <limits>

using yuzu::shared::RowByteBudget;

TEST_CASE("RowByteBudget: defaults are unbounded", "[row_byte_budget]") {
    RowByteBudget b;
    CHECK(b.fits(std::size_t{1} << 40));
    for (int i = 0; i < (1 << 20); ++i)
        REQUIRE(b.charge(1));
    CHECK_FALSE(b.full());
    CHECK_FALSE(b.refused);
}

TEST_CASE("RowByteBudget: row cap, exact fill admitted then refused", "[row_byte_budget]") {
    RowByteBudget b{2, RowByteBudget::npos};
    CHECK(b.charge(1));
    CHECK_FALSE(b.full());
    CHECK(b.charge(1));
    CHECK(b.full());
    CHECK_FALSE(b.charge(1));
    CHECK(b.rows == 2);
    CHECK(b.refused);
}

TEST_CASE("RowByteBudget: byte cap, exact fill admitted, never wraps", "[row_byte_budget]") {
    RowByteBudget b{RowByteBudget::npos, 10};
    CHECK(b.charge(6));
    CHECK(b.charge(4));
    CHECK(b.bytes == 10);
    CHECK(b.full());
    CHECK_FALSE(b.refused);
    CHECK_FALSE(b.charge(1));
    CHECK(b.refused);
    CHECK_FALSE(b.fits(std::numeric_limits<std::size_t>::max()));
    CHECK_FALSE(b.charge(std::numeric_limits<std::size_t>::max()));
    CHECK(b.bytes == 10);
}

TEST_CASE("RowByteBudget: refused is a record, not a gate", "[row_byte_budget]") {
    RowByteBudget b{RowByteBudget::npos, 10};
    CHECK(b.charge(8));
    CHECK_FALSE(b.charge(5));
    CHECK(b.refused);
    CHECK(b.bytes == 8);
    CHECK(b.charge(2));
    CHECK(b.bytes == 10);
    CHECK(b.refused);
}

TEST_CASE("RowByteBudget: add is unconditional and saturating", "[row_byte_budget]") {
    RowByteBudget b{RowByteBudget::npos, 10};
    b.add(25);
    CHECK(b.full());
    CHECK_FALSE(b.fits(1));
    CHECK_FALSE(b.refused);
    b.add(std::numeric_limits<std::size_t>::max());
    CHECK(b.bytes == std::numeric_limits<std::size_t>::max());
}

TEST_CASE("RowByteBudget: reset clears counters, keeps limits", "[row_byte_budget]") {
    RowByteBudget b{3, 7};
    b.charge(7);
    b.charge(1);
    REQUIRE(b.refused);
    b.reset();
    CHECK(b.rows == 0);
    CHECK(b.bytes == 0);
    CHECK_FALSE(b.refused);
    CHECK(b.max_rows == 3);
    CHECK(b.max_bytes == 7);
}
