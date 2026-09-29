#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "api_token_store.hpp"

/// @file token_rotation_lookup.hpp
/// Single source of truth for locating a human token-keyed rotation's
/// successor row after `ApiTokenStore::rotate_token`/`confirm_token_rotation`
/// (P2 #11, SOC 2 CC6.3) — shared by every transport surface that needs to
/// correlate a rotate response with the successor it just minted/re-served
/// (REST today; the MCP twin is landing separately and must call THIS, never
/// re-derive its own copy).
///
/// WHY THIS IS A SEPARATE HEADER, NOT INLINE IN THE ROUTE: a round-3 review
/// found the original REST-only inline loop had been copied verbatim from
/// the engine-principal rotate route (`rest_api_v1.cpp`'s
/// `/engine-principals/{id}/credentials/rotate`), where "the row whose
/// `supersedes_token_id` is non-empty" is a sound match because that route's
/// own store arm (`rotate_engine_credential`) enforces a <=2-ACTIVE-
/// CREDENTIALS-PER-PRINCIPAL ceiling — at most one linked row can ever exist
/// for that principal. `ApiTokenStore::rotate_token`'s own doc comment
/// (api_token_store.hpp, "Human arm") declares that invariant explicitly
/// FALSE for a human principal: "one user routinely holds N concurrent
/// unrelated named tokens" — the ceiling here is <=2 PER ROTATION GROUP,
/// never per principal. So a human principal can have SEVERAL independent
/// in-flight rotations at once, and the copied loop matched the FIRST linked
/// row it found — not necessarily the one belonging to the predecessor
/// actually rotated. Reproduced end-to-end against live Postgres: rotating
/// token A then token B (both owned by the same user) inside A's overlap
/// window returned B's raw secret paired with A's successor `token_id`;
/// confirming that id revoked A while B — the token whose secret the caller
/// actually held — stayed live and unconfirmed. EXTEND this header, never
/// fork it — a second inline copy (on the REST side, the MCP side, or a
/// future third transport) is exactly the drift that produced the bug.
///
/// WHY THIS TAKES A `const std::vector<ApiToken>&`, NOT A STORE + PRINCIPAL
/// ID (round-4 review): the derivation itself is pure — given the active set
/// for a principal, find the row scoped to a predecessor. Owning the store
/// read inside the helper made that pure logic untestable without a live
/// Postgres connection, which is exactly why it shipped with zero direct
/// tests. The caller does its own `list_active_for_principal` read (the one
/// production call site today already had a store handle) and hands the
/// result in; the `found == false` inference below — the exact contract an
/// MCP twin must honour — is now checkable with a plain in-memory vector.

namespace yuzu::server::detail {

/// Result of `derive_rotation_successor` below.
struct RotationSuccessorInfo {
    /// false iff `active` contained no row whose `supersedes_token_id`
    /// matches `predecessor_token_id`. See the function doc for the
    /// call-site-dependent meaning of this — it is NOT one contract shared
    /// by every caller (round-4 correction: an earlier version of this doc
    /// overclaimed a single "MUST fail closed" rule that is wrong after a
    /// successful confirm).
    bool found = false;
    std::string successor_token_id;
    int64_t successor_expires_at = 0;
    /// The PREDECESSOR row's own `overlap_expires_at` — never the
    /// successor's. `ApiTokenStore::rotate_token`'s successor `INSERT` never
    /// sets this column (only the predecessor's row is stamped with it), so
    /// a caller reading it off the successor row observes a structural `0`.
    /// Echoed here, from the predecessor, purely for the response's
    /// convenience — there is no separate successor-side value to report.
    int64_t predecessor_overlap_expires_at = 0;
};

/// Scans `active` (the caller's own `list_active_for_principal(principal_id)`
/// read) ONCE and returns both halves a rotate response needs: the successor
/// row scoped EXACTLY to `predecessor_token_id` (matched via
/// `supersedes_token_id == predecessor_token_id`, never merely "any linked
/// row of this principal"), and that same predecessor's own
/// `overlap_expires_at`. Takes the FIRST row matching each condition — under
/// the store's own <=2-PER-ROTATION-GROUP ceiling at most one active row can
/// ever link to a given predecessor and the predecessor id itself is unique,
/// so a second matching row is unreachable today, but the loop says so
/// explicitly (an `!info.found` / `!predecessor_found` guard on each branch,
/// plus an early `break` once both are resolved) rather than leaving
/// "first/last wins" as an incidental property of iteration order. This
/// matters because `list_active_for_principal`'s `ORDER BY created_at ASC`
/// is a `bigint` SECONDS column — a same-second predecessor/successor tie is
/// possible in principle, so the derivation does not lean on the predecessor
/// row necessarily preceding the successor row in `active`.
///
/// **The meaning of `found == false` depends on WHICH store call the caller
/// just observed succeed — this is call-site-dependent, not one contract:**
///
///   - After `rotate_token` succeeds: `found == false` is structurally
///     impossible except as a swallowed read failure.
///     `list_active_for_principal` is a best-effort maintenance-style read
///     that swallows a lease/query failure into an empty vector rather than
///     propagating a typed error (`api_token_store.hpp`), and a rotate that
///     just minted a successor row for THIS predecessor cannot legitimately
///     produce an empty scan for it. Callers MUST treat `found == false`
///     here as an ambiguous, retryable failure and fail CLOSED — never place
///     the raw secret already in hand into a response with no `token_id` to
///     ever confirm it against.
///   - After `confirm_token_rotation` succeeds: `found == false` is the
///     GUARANTEED CORRECT state, not a failure. Confirm revokes the
///     predecessor and clears the successor's `rotation_group`/
///     `supersedes_token_id`/`overlap_expires_at` in the same transaction
///     (`api_token_store.cpp`), so a post-confirm scan for the same
///     `predecessor_token_id` will never again find a linked row — the
///     rotation is resolved. A caller deriving a post-confirm response MUST
///     NOT apply the rotate-side "fail closed on not-found" rule here; there
///     is nothing ambiguous about it finding nothing.
///   - With NO preceding successful mutation this call observed itself — a
///     read-only "show my in-flight rotation" caller (e.g. a future
///     `list_tokens`-style MCP tool reading the same rows; no such twin
///     exists yet, but the ADR-1005 MCP parity gap already records one as
///     the obvious next tool) — neither of the two rules above applies.
///     `found == false` is genuinely AMBIGUOUS here: it could mean "no
///     rotation is in flight for this token" or a swallowed read failure,
///     and this header cannot tell the two apart for you — it is a pure
///     function over whatever `active` vector you supplied, with no
///     knowledge of whether a mutation preceded this call. The OBLIGATION IS
///     THE CALLER'S: decide whether to surface `found == false` as "no
///     rotation in flight" or as a read failure based on whatever OTHER
///     signal is available to it (e.g. `list_active_for_principal` itself
///     logs at warn on a swallowed failure; a typed read path would not have
///     this ambiguity at all). Do not default to treating this case as
///     benign just because it resembles the confirm-side answer above — the
///     confirm-side answer is licensed by a mutation this helper's caller
///     just observed succeed, which a read-only caller has none of.
[[nodiscard]] inline RotationSuccessorInfo
derive_rotation_successor(const std::vector<ApiToken>& active,
                          const std::string& predecessor_token_id) {
    RotationSuccessorInfo info;
    bool predecessor_found = false;
    for (const auto& t : active) {
        if (!info.found && t.supersedes_token_id == predecessor_token_id) {
            info.found = true;
            info.successor_token_id = t.token_id;
            info.successor_expires_at = t.expires_at;
        } else if (!predecessor_found && t.token_id == predecessor_token_id) {
            info.predecessor_overlap_expires_at = t.overlap_expires_at;
            predecessor_found = true;
        }
        if (info.found && predecessor_found)
            break; // both pieces resolved -- stop explicitly rather than
                   // scan to the end incidentally
    }
    return info;
}

} // namespace yuzu::server::detail
