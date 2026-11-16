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

#include "list_walk.hpp"
#include "value_enumeration.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>
#include <vector>

using namespace yuzu::win;
using namespace yuzu::shared;

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

// ── list_walk.hpp: walk_enumeration and stable_walk (pure; no registry) ─────────────────

namespace {
using Script = std::vector<std::pair<ListStep, std::string>>;

ListWalk scripted_walk(const Script& script) {
    return walk_enumeration([&](unsigned i, std::string& name, std::string& err) {
        REQUIRE(i < script.size()); // the walk never asks past a terminal answer
        const auto& [step, text] = script[i];
        (step == ListStep::Item ? name : err) = text;
        return step;
    });
}

// One scripted answer per walk: a listing, or a failed walk when `fail_at` names that walk.
struct StableFixture {
    std::vector<std::vector<std::string>> walks;
    std::size_t fail_at = static_cast<std::size_t>(-1); // index of a walk that reports an error
    std::size_t walk_calls = 0;

    ListWalk run(unsigned max_walks = 4) {
        return stable_walk(
            [&] {
                REQUIRE(walk_calls < walks.size()); // the loop never walks past max_walks
                const auto i = walk_calls++;
                if (i == fail_at)
                    return ListWalk{{}, "index 0 (rc=5)"};
                return ListWalk{walks[i], {}};
            },
            max_walks);
    }
};
} // namespace

TEST_CASE("index walk: a walk that reaches the end is complete", "[list_walk]") {
    const auto w = scripted_walk({{ListStep::Item, "a"}, {ListStep::Item, "b"}, {ListStep::End, ""}});
    CHECK(w.error.empty());
    CHECK(w.names == std::vector<std::string>{"a", "b"});
}

TEST_CASE("index walk: an error part-way empties the list and names the index", "[list_walk]") {
    const auto w = scripted_walk({{ListStep::Item, "a"},
                                  {ListStep::Item, "b"},
                                  {ListStep::Error, "rc=5"},
                                  {ListStep::Item, "never reached"}});
    CHECK(w.error == "index 2 (rc=5)");
    CHECK(w.names.empty()); // the two names found so far are not handed out
}

TEST_CASE("index walk: an error at index zero is a failed walk and not an empty list",
          "[list_walk]") {
    const auto w = scripted_walk({{ListStep::Error, "rc=6"}});
    CHECK(w.error == "index 0 (rc=6)");
    CHECK(w.names.empty());
    // An empty list that DID end is the other answer, and carries no error.
    CHECK(scripted_walk({{ListStep::End, ""}}).error.empty());
}

TEST_CASE("stable walk: two agreeing walks accept, whatever order they list in", "[list_walk]") {
    StableFixture f{{{"b", "a"}, {"a", "b"}}};
    const auto w = f.run();
    CHECK(w.error.empty());
    CHECK(w.names == std::vector<std::string>{"a", "b"}); // sorted
    CHECK(f.walk_calls == 2);
}

TEST_CASE("stable walk: a differing walk walks again and the agreeing pair is accepted",
          "[list_walk]") {
    StableFixture f{{{"a"}, {"a", "b"}, {"a", "b"}}};
    const auto w = f.run();
    CHECK(w.error.empty());
    CHECK(w.names == std::vector<std::string>{"a", "b"}); // the pair, not the first walk
    CHECK(f.walk_calls == 3);
}

TEST_CASE("stable walk: {A,B},{A},{A,B} is never certified as {A}", "[list_walk]") {
    // The regression the surrounding-stamp rule failed: a middle walk that skipped B (A removed
    // and reloaded while the walk ran) sat between two walks that listed the same names, and was
    // accepted. Only two CONSECUTIVE walks that agree certify a list.
    StableFixture three{{{"A", "B"}, {"A"}, {"A", "B"}}};
    const auto w3 = three.run(3);
    CHECK(w3.error == kWalkUnstable);
    CHECK(w3.names.empty()); // never {A}
    CHECK(three.walk_calls == 3);

    // A fourth walk that agrees with the third settles it, on the full list.
    StableFixture four{{{"A", "B"}, {"A"}, {"A", "B"}, {"A", "B"}}};
    const auto w4 = four.run(4);
    CHECK(w4.error.empty());
    CHECK(w4.names == std::vector<std::string>{"A", "B"});
    CHECK(four.walk_calls == 4);
}

TEST_CASE("stable walk: a list that never settles reports unstable after max_walks",
          "[list_walk]") {
    StableFixture f{{{"a"}, {"b"}, {"c"}, {"d"}}};
    const auto w = f.run(4);
    CHECK(w.error == kWalkUnstable);
    CHECK(w.names.empty());
    CHECK(f.walk_calls == 4);
}

TEST_CASE("stable walk: a failed walk, first or later, is returned as it is with no names",
          "[list_walk]") {
    StableFixture first{{{"a"}, {"a"}}, 0};
    const auto w1 = first.run();
    CHECK(w1.error == "index 0 (rc=5)"); // the cause is kept, not replaced
    CHECK(w1.names.empty());
    CHECK(first.walk_calls == 1);

    StableFixture later{{{"a"}, {"b"}, {"b"}}, 1};
    const auto w2 = later.run();
    CHECK(w2.error == "index 0 (rc=5)");
    CHECK(w2.names.empty());
    CHECK(later.walk_calls == 2); // it stops at the failure; the agreeing pair never forms
}

TEST_CASE("stable walk: fewer than two walks can never certify a list", "[list_walk]") {
    StableFixture one{{{"a"}, {"a"}}};
    const auto w1 = one.run(1);
    CHECK(w1.error == kWalkUnstable);
    CHECK(w1.names.empty());
    CHECK(one.walk_calls == 1);

    StableFixture none{{}};
    CHECK(none.run(0).error == kWalkUnstable);
    CHECK(none.walk_calls == 0);
}

TEST_CASE("stable walk: an empty list read twice is a complete empty list", "[list_walk]") {
    StableFixture f{{{}, {}}};
    const auto w = f.run();
    CHECK(w.error.empty());
    CHECK(w.names.empty());
    CHECK(f.walk_calls == 2);
}
