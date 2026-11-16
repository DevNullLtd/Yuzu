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

#include <optional>
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

// One scripted listing per walk attempt, and one scripted stamp per stamp call.
struct StableFixture {
    std::vector<std::optional<int>> stamps;
    std::vector<std::vector<std::string>> walks;
    std::size_t stamp_calls = 0;
    std::size_t walk_calls = 0;

    ListWalk run(unsigned max_attempts = 3) {
        return stable_walk(
            [&]() -> std::optional<int> {
                REQUIRE(stamp_calls < stamps.size());
                return stamps[stamp_calls++];
            },
            [&] {
                REQUIRE(walk_calls < walks.size());
                return ListWalk{walks[walk_calls++], {}};
            },
            max_attempts);
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

TEST_CASE("stable walk: an unchanged stamp accepts the first walk", "[list_walk]") {
    StableFixture f{{1, 1}, {{"a", "b"}}};
    const auto w = f.run();
    CHECK(w.error.empty());
    CHECK(w.names == std::vector<std::string>{"a", "b"});
    CHECK(f.walk_calls == 1);
}

TEST_CASE("stable walk: a changed stamp walks again and accepts the stable pass", "[list_walk]") {
    StableFixture f{{1, 2, 2, 2}, {{"a"}, {"a", "b"}}};
    const auto w = f.run();
    CHECK(w.error.empty());
    CHECK(w.names == std::vector<std::string>{"a", "b"}); // the second pass, not the first
    CHECK(f.walk_calls == 2);
}

TEST_CASE("stable walk: a stamp that never settles reports unstable after three attempts",
          "[list_walk]") {
    StableFixture f{{1, 2, 3, 4, 5, 6}, {{"a"}, {"b"}, {"c"}}};
    const auto w = f.run(3);
    CHECK(w.error == kStampUnstable);
    CHECK(w.names.empty());
    CHECK(f.walk_calls == 3);
}

TEST_CASE("stable walk: a stamp that cannot be taken before the walk is an incomplete listing",
          "[list_walk]") {
    StableFixture f{{std::nullopt}, {{"a"}}};
    const auto w = f.run();
    CHECK(w.error == kStampFailed);
    CHECK(w.names.empty());
    CHECK(f.walk_calls == 0); // no walk is trusted without a stamp to compare it with
}

TEST_CASE("stable walk: two failed stamps do not match and the listing is incomplete",
          "[list_walk]") {
    // The stamp before the walk is fine and the one after it fails: absent == absent must never
    // read as "unchanged".
    StableFixture f{{1, std::nullopt}, {{"a"}}};
    const auto w = f.run();
    CHECK(w.error == kStampFailed);
    CHECK(w.names.empty());

    // A walk that itself failed is returned as it is, whatever the stamps say.
    const auto failed = stable_walk([] { return std::optional<int>{1}; },
                                    [] { return ListWalk{{}, "index 0 (rc=5)"}; }, 3);
    CHECK(failed.error == "index 0 (rc=5)");
}
