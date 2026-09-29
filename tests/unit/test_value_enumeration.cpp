/**
 * test_value_enumeration.cpp -- value_enumeration.hpp's
 * value_enumeration_is_complete, the pure decision behind
 * win_profiles.hpp's enumerate_value_names() completeness signal.
 *
 * Adversarial-review finding (gate 2, PR3.3-b): the original completeness
 * fix (commit ce96e8842) had NO test exercising the cap-truncation or
 * mid-enumeration-failure branches -- test_antivirus_local_dispatcher.cpp
 * only asserts an invariant ("exclusion_count|0" never co-occurs with a
 * failure line) that held before the fix too, and neither branch is
 * fixture-reachable through a live registry key without injecting more
 * than kMaxEnumeratedValueNames (4096) real values or a live transient
 * RegEnumValueW failure. Extracting the decision here -- mirroring
 * profile_list_actually_truncated's split from win_profiles.hpp into
 * user_profile_model.hpp -- closes that: portable, no live registry, no
 * _WIN32 guard needed.
 */

#include "value_enumeration.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::win;

TEST_CASE("value_enumeration_is_complete: ordinary case, nothing cut short",
          "[value_enumeration]") {
    // 5 values reported; the real caller computes cap = min(reported_count,
    // kMaxEnumeratedValueNames), so with reported_count well under the
    // 4096 ceiling, cap == reported_count == 5. All 5 collected.
    CHECK(value_enumeration_is_complete(5, 5, 5));
}

TEST_CASE("value_enumeration_is_complete: cap reached exactly, nothing missed",
          "[value_enumeration]") {
    // reported_count == cap == collected -- the walk reached the cap and
    // the cap happens to equal the true count, so nothing was cut off.
    CHECK(value_enumeration_is_complete(4096, 4096, 4096));
}

TEST_CASE("value_enumeration_is_complete: safety cap truncates a real value set",
          "[value_enumeration]") {
    // 5000 values reported, capped to kMaxEnumeratedValueNames (4096), and
    // the walk collects exactly the cap -- INCOMPLETE, because the cap
    // itself is below the reported count. This is the exact branch the
    // original test never drove.
    CHECK_FALSE(value_enumeration_is_complete(5000, 4096, 4096));
}

TEST_CASE("value_enumeration_is_complete: mid-enumeration failure stops the walk early",
          "[value_enumeration]") {
    // 10 values reported, cap of 10 (no truncation from the cap itself),
    // but RegEnumValueW failed at index 6 -- the walk never reached the
    // cap. This is the other branch the original test never drove.
    CHECK_FALSE(value_enumeration_is_complete(10, 10, 6));
}

TEST_CASE("value_enumeration_is_complete: zero values, trivially complete",
          "[value_enumeration]") {
    CHECK(value_enumeration_is_complete(0, 0, 0));
}

TEST_CASE("value_enumeration_is_complete: cap below count AND a mid-enum failure -- "
          "still just incomplete, not double-counted",
          "[value_enumeration]") {
    CHECK_FALSE(value_enumeration_is_complete(5000, 4096, 2000));
}
