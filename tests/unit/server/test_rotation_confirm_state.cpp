/**
 * test_rotation_confirm_state.cpp — locks the pure confirm-state classifier
 * (rotation_confirm_state.hpp) that decides, from the active-credential set a
 * confirm reads under the advisory lock, whether the state is a terminal
 * conflict, a permanent client error, or the one deliberately-retryable
 * empty/ambiguous case (#2404). No DB — the classifier is a pure function over
 * an already-read vector; the store test (test_api_token_store.cpp) exercises
 * the wired behaviour end-to-end.
 */

#include "rotation_confirm_state.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using yuzu::server::ApiToken;
using yuzu::server::detail::classify_confirm_state;
using yuzu::server::detail::classify_confirm_state_in_group;
using yuzu::server::detail::GroupRotationConfirmState;
using yuzu::server::detail::RotationConfirmState;
using yuzu::server::detail::pair_matches_pin;

namespace {

// A plain standalone (never-/no-longer-rotating) engine credential.
ApiToken clear_token(const std::string& id, int64_t confirmed_at = 0) {
    ApiToken t;
    t.token_id = id;
    t.principal_kind = "engine";
    t.confirmed_at = confirmed_at;
    // rotation_group / supersedes_token_id / overlap_expires_at stay empty/0.
    return t;
}

// A human credential belonging to a specific rotation_group (predecessor if
// supersedes is empty, successor otherwise).
ApiToken grouped_token(const std::string& id, const std::string& group,
                       const std::string& supersedes = {}) {
    ApiToken t;
    t.token_id = id;
    t.principal_kind = "human";
    t.rotation_group = group;
    t.supersedes_token_id = supersedes;
    return t;
}

// A human credential with no rotation linkage — one of a principal's OTHER,
// unrelated active tokens.
ApiToken unrelated_token(const std::string& id) {
    ApiToken t;
    t.token_id = id;
    t.principal_kind = "human";
    return t;
}

} // namespace

TEST_CASE("classify_confirm_state: count-based states", "[rotation_confirm]") {
    const std::string pin = "aaaa";

    // 0 active -> ambiguous with a swallowed read failure -> retryable.
    CHECK(classify_confirm_state({}, pin) == RotationConfirmState::kNoneActive);

    // >2 active -> a credential minted outside the rotation path.
    std::vector<ApiToken> three{clear_token("a"), clear_token("b"), clear_token("c")};
    CHECK(classify_confirm_state(three, pin) == RotationConfirmState::kOverfull);

    // exactly 2 -> the caller's normal pair-processing path (pin/linkage checked
    // downstream by confirm_rotation itself, not here).
    std::vector<ApiToken> two{clear_token("a"), clear_token("b")};
    CHECK(classify_confirm_state(two, pin) == RotationConfirmState::kPair);
}

TEST_CASE("classify_confirm_state: sole-credential discrimination", "[rotation_confirm]") {
    const std::string pin = "successor-1";

    SECTION("linkage NOT clear (rotation_group set) -> unresolved, do not rotate") {
        ApiToken t = clear_token(pin);
        t.rotation_group = "grp-1";
        CHECK(classify_confirm_state({t}, pin) == RotationConfirmState::kUnresolvedSole);
    }
    SECTION("linkage NOT clear (supersedes set) -> unresolved") {
        ApiToken t = clear_token(pin);
        t.supersedes_token_id = "predecessor-0";
        CHECK(classify_confirm_state({t}, pin) == RotationConfirmState::kUnresolvedSole);
    }
    SECTION("clear + pin matches + confirmed_at != 0 -> already confirmed") {
        ApiToken t = clear_token(pin, /*confirmed_at=*/12345);
        CHECK(classify_confirm_state({t}, pin) == RotationConfirmState::kSoleConfirmed);
    }
    SECTION("clear + pin matches + confirmed_at == 0 -> resolved without confirm") {
        ApiToken t = clear_token(pin, /*confirmed_at=*/0);
        CHECK(classify_confirm_state({t}, pin) == RotationConfirmState::kSoleResolved);
    }
    SECTION("clear + pin does NOT match -> the rotation moved on") {
        ApiToken t = clear_token("some-other-token", /*confirmed_at=*/999);
        CHECK(classify_confirm_state({t}, pin) == RotationConfirmState::kSoleOtherToken);
    }
}

// ── classify_confirm_state_in_group: the group-aware sibling (P2 #11) ──────

TEST_CASE("classify_confirm_state_in_group: ambiguous-empty vs positive-empty", "[rotation_confirm][group]") {
    const std::string group = "grp-1";

    // Whole-principal read empty -> ambiguous with a swallowed read failure,
    // exactly like classify_confirm_state's kNoneActive.
    CHECK(classify_confirm_state_in_group({}, group) == GroupRotationConfirmState::kAmbiguousEmpty);

    // Whole-principal read NON-empty, but nothing tagged with THIS group ->
    // a POSITIVE fact (the query worked; this rotation already resolved),
    // never ambiguous.
    std::vector<ApiToken> others{unrelated_token("a"), unrelated_token("b")};
    CHECK(classify_confirm_state_in_group(others, group) == GroupRotationConfirmState::kGroupEmpty);
}

TEST_CASE("classify_confirm_state_in_group: a human's other unrelated tokens never leak "
          "into the group filter",
          "[rotation_confirm][group]") {
    const std::string group = "grp-2";
    std::vector<ApiToken> active{unrelated_token("laptop"), unrelated_token("cli"),
                                 grouped_token("pred", group),
                                 grouped_token("succ", group, /*supersedes=*/"pred")};
    CHECK(classify_confirm_state_in_group(active, group) == GroupRotationConfirmState::kPairInGroup);
}

TEST_CASE("classify_confirm_state_in_group: exactly one row still tagged with the group is "
          "unresolved (never a synonym for resolved)",
          "[rotation_confirm][group]") {
    const std::string group = "grp-3";
    std::vector<ApiToken> active{grouped_token("succ", group, /*supersedes=*/"pred")};
    CHECK(classify_confirm_state_in_group(active, group) ==
          GroupRotationConfirmState::kUnresolvedSoleInGroup);
}

TEST_CASE("classify_confirm_state_in_group: more than two rows sharing a group is defensive "
          "overfull",
          "[rotation_confirm][group]") {
    const std::string group = "grp-4";
    std::vector<ApiToken> active{grouped_token("a", group), grouped_token("b", group),
                                 grouped_token("c", group)};
    CHECK(classify_confirm_state_in_group(active, group) ==
          GroupRotationConfirmState::kOverfullGroup);
}

// ── From dev (#2443/#2953): pair_matches_pin linkage+pin precondition ──────
// Appended alongside the P2 #11 group-aware cases above; the two suites are
// independent — engine-arm pin/linkage vs human-arm rotation_group counting.

namespace {

// A linked (predecessor, successor) pair - same rotation_group, successor's
// supersedes_token_id pointing at the predecessor.
std::pair<ApiToken, ApiToken> linked_pair(const std::string& predecessor_id,
                                          const std::string& successor_id,
                                          const std::string& group = "grp-1") {
    ApiToken predecessor = clear_token(predecessor_id);
    predecessor.rotation_group = group;
    ApiToken successor = clear_token(successor_id);
    successor.rotation_group = group;
    successor.supersedes_token_id = predecessor_id;
    return {predecessor, successor};
}

} // namespace

// #2443: `classify_confirm_state` alone only counts rows - `pair_matches_pin`
// is the additional check that closes the burn where a NEWER rotation (a
// different successor token_id than the ticket was minted for) also reads as
// `kPair`.
TEST_CASE("pair_matches_pin", "[rotation_confirm][2443]") {
    SECTION("not exactly 2 active -> false regardless of content") {
        CHECK_FALSE(pair_matches_pin({}, "x"));
        CHECK_FALSE(pair_matches_pin({clear_token("a")}, "a"));
        auto [p, s] = linked_pair("p", "s");
        CHECK_FALSE(pair_matches_pin({p, s, clear_token("c")}, "s"));
    }
    SECTION("linked pair, pin matches the successor -> true") {
        auto [p, s] = linked_pair("p", "s");
        CHECK(pair_matches_pin({p, s}, "s"));
        CHECK(pair_matches_pin({s, p}, "s")); // order-independent
    }
    SECTION("linked pair, pin does NOT match the successor (a NEWER rotation) -> false") {
        // The exact #2443 burn shape: the ticket was pinned to an OLDER
        // successor ("old-s") that has since resolved; a NEW rotation
        // produced a different successor ("new-s"). Both are still
        // structurally a valid pair - just not the pair this ticket names.
        auto [p, s] = linked_pair("p", "new-s");
        CHECK_FALSE(pair_matches_pin({p, s}, "old-s"));
    }
    SECTION("two active rows but NOT linked to each other -> false even if the pin matches "
            "one of them") {
        // Two independently-minted standalone credentials (no rotation in
        // progress between them) must never read as a confirmable pair.
        ApiToken a = clear_token("a");
        ApiToken b = clear_token("b");
        CHECK_FALSE(pair_matches_pin({a, b}, "b"));
    }
    SECTION("mismatched rotation_group -> false") {
        auto [p, s] = linked_pair("p", "s", "grp-1");
        s.rotation_group = "grp-2"; // linkage broken
        CHECK_FALSE(pair_matches_pin({p, s}, "s"));
    }
    SECTION("supersedes_token_id points at the wrong predecessor -> false") {
        auto [p, s] = linked_pair("p", "s");
        s.supersedes_token_id = "not-p";
        CHECK_FALSE(pair_matches_pin({p, s}, "s"));
    }
    SECTION("both rows look like successors (malformed) -> no predecessor found -> false") {
        ApiToken a = clear_token("a");
        a.supersedes_token_id = "x";
        ApiToken b = clear_token("b");
        b.supersedes_token_id = "y";
        CHECK_FALSE(pair_matches_pin({a, b}, "a"));
    }
}