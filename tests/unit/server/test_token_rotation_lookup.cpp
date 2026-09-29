/**
 * test_token_rotation_lookup.cpp — DB-free unit coverage for
 * `yuzu::server::detail::derive_rotation_successor` (token_rotation_lookup.hpp,
 * P2 #11). Round-4 review: the helper originally owned its own
 * `ApiTokenStore::list_active_for_principal` read, which meant its
 * `found == false` contract — the exact thing an MCP twin must honour —
 * had zero direct tests (only reachable end-to-end against live Postgres).
 * The helper now takes a plain `const std::vector<ApiToken>&`, so every case
 * here is a pure in-memory construction — no store, no PG, no [pg] tag.
 *
 * Covers: found/not-found, the SCOPING property that produced the round-3
 * blocking bug (two concurrent rotations, each must resolve to its OWN
 * successor), `predecessor_overlap_expires_at` sourced from the predecessor
 * row regardless of scan order, and the empty-vector edge.
 */

#include "token_rotation_lookup.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::server::ApiToken;
using yuzu::server::detail::derive_rotation_successor;

namespace {

ApiToken make_token(std::string token_id, std::string supersedes, int64_t overlap_expires_at = 0,
                    int64_t expires_at = 0) {
    ApiToken t;
    t.token_id = std::move(token_id);
    t.supersedes_token_id = std::move(supersedes);
    t.overlap_expires_at = overlap_expires_at;
    t.expires_at = expires_at;
    t.principal_id = "alice";
    t.principal_kind = "human";
    return t;
}

} // namespace

TEST_CASE("derive_rotation_successor: found — resolves the successor scoped to the "
          "predecessor, and overlap_expires_at from the PREDECESSOR row",
          "[token_rotation_lookup]") {
    std::vector<ApiToken> active{
        make_token("pred-1", /*supersedes=*/"", /*overlap_expires_at=*/1700000000,
                  /*expires_at=*/0),
        make_token("succ-1", /*supersedes=*/"pred-1", /*overlap_expires_at=*/0,
                  /*expires_at=*/1800000000),
    };

    auto info = derive_rotation_successor(active, "pred-1");
    CHECK(info.found);
    CHECK(info.successor_token_id == "succ-1");
    CHECK(info.successor_expires_at == 1800000000);
    // Sourced from pred-1's OWN overlap_expires_at, never succ-1's (which the
    // store never stamps — structurally 0 on every successor row).
    CHECK(info.predecessor_overlap_expires_at == 1700000000);
}

TEST_CASE("derive_rotation_successor: not found — no rotation in flight for this "
          "predecessor (the ROTATE-side caller must treat this as an ambiguous "
          "failure; the CONFIRM-side caller must treat it as the correct "
          "post-confirm state — see the header doc)",
          "[token_rotation_lookup]") {
    std::vector<ApiToken> active{
        make_token("pred-1", /*supersedes=*/"", /*overlap_expires_at=*/0),
        // An unrelated active token for the same principal, never rotated.
        make_token("other-1", /*supersedes=*/""),
    };

    auto info = derive_rotation_successor(active, "pred-1");
    CHECK_FALSE(info.found);
    CHECK(info.successor_token_id.empty());
    CHECK(info.successor_expires_at == 0);
    // pred-1's own row is present and un-rotating -- its overlap_expires_at
    // is legitimately 0, distinct from "not found".
    CHECK(info.predecessor_overlap_expires_at == 0);
}

TEST_CASE("derive_rotation_successor: post-confirm state — predecessor revoked "
          "(absent from the active set) and successor's rotation linkage cleared "
          "is a legitimate not-found, not an anomaly",
          "[token_rotation_lookup]") {
    // confirm_token_rotation revokes the predecessor (which then drops out of
    // list_active_for_principal's "not revoked" filter) and clears the
    // successor's own supersedes_token_id/rotation_group/overlap_expires_at
    // in the same transaction (api_token_store.cpp) -- so a post-confirm
    // active set for this principal contains ONLY the resolved successor,
    // now looking exactly like a fresh, never-rotated token.
    std::vector<ApiToken> active{
        make_token("succ-1", /*supersedes=*/"", /*overlap_expires_at=*/0,
                  /*expires_at=*/1800000000),
    };

    auto info = derive_rotation_successor(active, "pred-1");
    CHECK_FALSE(info.found);
    CHECK(info.predecessor_overlap_expires_at == 0);
}

TEST_CASE("derive_rotation_successor: SCOPING — two concurrent rotations for the "
          "same principal each resolve to their OWN successor (round-3 BLOCKING "
          "regression, unit-level)",
          "[token_rotation_lookup]") {
    std::vector<ApiToken> active{
        make_token("pred-A", "", /*overlap_expires_at=*/1111111111, /*expires_at=*/0),
        make_token("succ-A", "pred-A", 0, /*expires_at=*/2222222222),
        make_token("pred-B", "", /*overlap_expires_at=*/3333333333, /*expires_at=*/0),
        make_token("succ-B", "pred-B", 0, /*expires_at=*/4444444444),
    };

    auto info_a = derive_rotation_successor(active, "pred-A");
    CHECK(info_a.found);
    CHECK(info_a.successor_token_id == "succ-A");
    CHECK(info_a.successor_expires_at == 2222222222);
    CHECK(info_a.predecessor_overlap_expires_at == 1111111111);

    auto info_b = derive_rotation_successor(active, "pred-B");
    CHECK(info_b.found);
    CHECK(info_b.successor_token_id == "succ-B");
    CHECK(info_b.successor_expires_at == 4444444444);
    CHECK(info_b.predecessor_overlap_expires_at == 3333333333);

    // Cross-check: A's derivation must never leak B's id, and vice versa —
    // the exact pairing the round-3 bug broke.
    CHECK(info_a.successor_token_id != info_b.successor_token_id);
}

TEST_CASE("derive_rotation_successor: predecessor_overlap_expires_at is resolved "
          "regardless of scan order (successor row listed BEFORE the predecessor "
          "row) — the derivation must not lean on ORDER BY created_at ASC holding "
          "at second resolution",
          "[token_rotation_lookup]") {
    std::vector<ApiToken> active{
        // Successor listed FIRST, predecessor SECOND — the reverse of what
        // list_active_for_principal's ORDER BY created_at ASC produces in
        // the ordinary case, exercised here to prove the derivation doesn't
        // depend on that ordering.
        make_token("succ-1", "pred-1", 0, /*expires_at=*/9000000000),
        make_token("pred-1", "", /*overlap_expires_at=*/5000000000),
    };

    auto info = derive_rotation_successor(active, "pred-1");
    CHECK(info.found);
    CHECK(info.successor_token_id == "succ-1");
    CHECK(info.predecessor_overlap_expires_at == 5000000000);
}

TEST_CASE("derive_rotation_successor: empty active set — found is false, "
          "overlap_expires_at defaults to 0",
          "[token_rotation_lookup]") {
    std::vector<ApiToken> active;
    auto info = derive_rotation_successor(active, "pred-1");
    CHECK_FALSE(info.found);
    CHECK(info.successor_token_id.empty());
    CHECK(info.successor_expires_at == 0);
    CHECK(info.predecessor_overlap_expires_at == 0);
}
