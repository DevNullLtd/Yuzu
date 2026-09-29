/**
 * test_engine_store_error_class.cpp — locks the shared REST/MCP store-error
 * classifier (engine_store_error_class.hpp). This is the single source of truth
 * both transports dispatch through; a missed string here mis-classifies a
 * permanent client condition as a retryable transient error (or vice versa),
 * the exact defect PR #2284 review caught twice. No DB needed — pure function.
 */

#include "engine_store_error_class.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <vector>

using yuzu::server::detail::classify_engine_store_error;
using yuzu::server::detail::confirm_result_label;
using yuzu::server::detail::EngineStoreErrorClass;

TEST_CASE("classify_engine_store_error: transient / conflict / client classes",
          "[engine_store_error]") {
    using E = EngineStoreErrorClass;

    // Transient (retryable — REST 503 / MCP kInternalError).
    CHECK(classify_engine_store_error("database not open") == E::Transient);
    CHECK(classify_engine_store_error("engine principal store unavailable — try again") ==
          E::Transient);
    CHECK(classify_engine_store_error("CSPRNG failure") == E::Transient);
    CHECK(classify_engine_store_error("rotation lock could not be acquired") == E::Transient);

    // Unrecognized store error -> Transient (fail-safe default, never a
    // misleading client error).
    CHECK(classify_engine_store_error("rotation failed") == E::Transient);
    // #3015: the PoP hash-read-failure string (nullopt token_hash) has no keyed
    // needle and MUST fall through to the fail-safe Transient default (503),
    // distinct from SecretMismatch — locked so a future needle can't silently
    // reclassify it.
    CHECK(classify_engine_store_error("failed to verify rotation secret") == E::Transient);
    CHECK(classify_engine_store_error("failed to mint successor credential: connection reset") ==
          E::Transient);
    CHECK(classify_engine_store_error("no active credential to rotate — mint one first") ==
          E::Transient);

    // Conflict (don't blindly retry). "rotation confirmation unavailable"
    // contains the broad "unavailable" substring — the ordering must classify
    // it as Conflict, NOT Transient (load-bearing).
    CHECK(classify_engine_store_error("rotation confirmation unavailable — retry via rotate") ==
          E::Conflict);
    CHECK(classify_engine_store_error("grace window elapsed") == E::Conflict);
    CHECK(classify_engine_store_error("rotation in progress by a different operator") ==
          E::Conflict);
    // #2384 confirm token_id pin: a stale/wrong successor id means the
    // rotation state has moved on — 409, don't blindly retry with the same id.
    CHECK(classify_engine_store_error("token_id does not match the pending rotation successor; "
                                      "pass the token_id returned by rotate") == E::Conflict);

    // Client-validation (permanent bad input/state — REST 400 / MCP kInvalidParams).
    CHECK(classify_engine_store_error("classification must be internal or external") ==
          E::ClientValidation);
    CHECK(classify_engine_store_error("more than two active credentials") == E::ClientValidation);
    CHECK(classify_engine_store_error("engine principal not found or revoked") ==
          E::ClientValidation);
    CHECK(classify_engine_store_error("overlap window below 24h floor") == E::ClientValidation);

    // Regression guards for the two strings the round-2 review found missing:
    // both are permanent client conditions that were defaulting to Transient.
    CHECK(classify_engine_store_error("engine principal not found or not active") ==
          E::ClientValidation);
    CHECK(classify_engine_store_error("principal has a non-engine active credential") ==
          E::ClientValidation);

    // #2384: the confirm token_id input guard is a permanent client error.
    CHECK(classify_engine_store_error("token_id required") == E::ClientValidation);
}

TEST_CASE("classify_engine_store_error: #2404 confirm-replay terminal strings",
          "[engine_store_error]") {
    using E = EngineStoreErrorClass;

    // The confirm-replay conflicts (emitted only after a POSITIVE row read, so
    // terminal — a client must not blindly retry them). All four MUST classify
    // as Conflict, and none may collide with the transient/client arms.
    CHECK(classify_engine_store_error(
              "rotation already confirmed - the supplied token_id is the sole active "
              "credential; nothing to confirm") == E::Conflict);
    CHECK(classify_engine_store_error(
              "no rotation in flight - the supplied token_id is already the sole active "
              "credential; nothing to confirm") == E::Conflict);
    CHECK(classify_engine_store_error(
              "no rotation in flight for the supplied token_id - the rotation was resolved "
              "(confirmed, revoked, or cut over); rotate again if a new rotation is needed") ==
          E::Conflict);
    CHECK(classify_engine_store_error(
              "one active credential with unresolved rotation metadata - inspect the "
              "credential state and do not rotate; revoke only if it is confirmed stale") ==
          E::Conflict);

    // The >2-active confirm string is a permanent client condition (mirrors
    // rotate's), not a conflict.
    CHECK(classify_engine_store_error(
              "more than two active credentials for this principal - resolve manually "
              "before confirming") == E::ClientValidation);

    // REGRESSION (load-bearing): the deliberately-ambiguous 0-active/malformed-pair
    // string MUST stay Transient — the #2404 conflict needles must not have
    // widened to swallow it (that would turn a retryable read hiccup into a
    // terminal 409, the opposite failure).
    CHECK(classify_engine_store_error("no in-flight rotation to confirm") == E::Transient);
}

TEST_CASE("classify_engine_store_error: human token-keyed arm (P2 #11) new strings",
          "[engine_store_error]") {
    using E = EngineStoreErrorClass;

    // rotate_token/confirm_token_rotation reach these only after a POSITIVE,
    // definitive row lookup (TokenLookup::ok, api_token_store.cpp) — unlike
    // the engine arm's ambiguous 0-active case, so they classify terminally
    // (permanent client error), never the retryable default.
    CHECK(classify_engine_store_error("no such token to rotate") == E::ClientValidation);
    CHECK(classify_engine_store_error("no such token to confirm") == E::ClientValidation);
    CHECK(classify_engine_store_error("token is not a human-owned credential") ==
          E::ClientValidation);
    CHECK(classify_engine_store_error("credential is not currently active — nothing to "
                                      "rotate") == E::ClientValidation);
    CHECK(classify_engine_store_error("principal has a non-human active credential") ==
          E::ClientValidation);

    // The deliberately-ambiguous query-failure wording the mint arm reuses
    // verbatim from the engine arm must stay Transient even when reached via
    // the human path (same 0-active/read-failure ambiguity).
    CHECK(classify_engine_store_error("no active credential to rotate — mint one first") ==
          E::Transient);

    // Round 4 review found this state had silently inherited the engine arm's
    // Conflict classification via a byte-identical reuse of its
    // kSoleOtherToken wording ("the rotation was resolved..."). The fix gave
    // it its own wording — correct — but round 4 ALSO reclassified it to
    // Transient, reasoning from the "call rotate again" prose. Round 5
    // adjudication refuted that: #2404 precedent (the engine confirm was once
    // 503-retryable this same way and made an idempotent-hint-honouring agent
    // retry a permanently-failing call forever), arm parity with
    // `kSoleOtherToken` itself (identical "rotate again" guidance, Conflict),
    // and rotation_confirm_state.hpp's own "every terminal state -> Conflict
    // or ClientValidation" contract (`GroupRotationConfirmState::kGroupEmpty`
    // is a POSITIVE fact, not ambiguous) all say Conflict. This state keeps
    // ITS OWN wording (still not byte-identical to kSoleOtherToken — own
    // classifier entry, in the step-3 Conflict group) but now the correct
    // class.
    const std::string no_pending_msg =
        "no rotation currently pending for the supplied token_id — nothing "
        "to confirm; call rotate again if a new rotation is needed";
    CHECK(classify_engine_store_error(no_pending_msg) == E::Conflict);
    CHECK(no_pending_msg.find("the rotation was resolved") == std::string::npos);
}

TEST_CASE("classify_engine_store_error: round-trip over every error string "
          "rotate_token/confirm_token_rotation can emit (round 4 coverage)",
          "[engine_store_error]") {
    // HONEST SCOPE (round 6 correction — a round-5 report described this as
    // "extracted programmatically"; it is not, and that claim should not be
    // repeated). This is a HAND-WRITTEN, HAND-MAINTAINED literal table,
    // transcribed to match `ApiTokenStore::rotate_token`/`confirm_token_rotation`
    // (api_token_store.cpp) AT THE TIME OF WRITING — nothing here scans the
    // source. What it DOES catch: a classifier change (a keyed substring
    // added/removed/reordered in engine_store_error_class.hpp) that silently
    // perturbs the class of any string ALREADY LISTED here — e.g. exactly the
    // round-4 defect, where "no rotation currently pending" acquired an
    // existing "the rotation was resolved" key by accident, would have shown
    // up as a flipped CHECK the moment that string was added to this table.
    // What it does NOT catch: a BRAND NEW error string added to
    // rotate_token/confirm_token_rotation without a corresponding entry here —
    // there is no mechanism tying this table's membership to the source, so
    // an unlisted emission site is silently absent from this test, not
    // merely unclassified by it. Mitigating factor, not a fix: an
    // unrecognized string falls through to classify_engine_store_error's
    // step-7 Transient default, so the blast radius of a missed entry is
    // over-retry, never a false terminal 400/409.
    //
    // The count below is pinned to a security-review-confirmed independent
    // extraction (round 6) — 38 cases. It does NOT verify this table still
    // matches the source (see above); it only makes an ACCIDENTAL edit to
    // THIS table (an entry dropped or duplicated by a future change here)
    // loud instead of silent. Bump deliberately alongside a real audit of
    // the two functions' emission sites, never to silence a failing count.
    using E = EngineStoreErrorClass;
    struct Case {
        std::string message;
        E expected;
    };
    const std::vector<Case> cases = {
        // ── rotate_token ────────────────────────────────────────────────
        {"database not open", E::Transient},
        {"token_id required", E::ClientValidation},
        {"requesting_user required", E::ClientValidation},
        {"overlap window below 24h floor", E::ClientValidation},
        {"overlap window exceeds the maximum (10 years)", E::ClientValidation},
        {"database unavailable — try again", E::Transient},
        {"no such token to rotate", E::ClientValidation},
        {"token is not a human-owned credential", E::ClientValidation},
        {"credential is not currently active — nothing to rotate", E::ClientValidation},
        {"failed to acquire rotation lock", E::Transient},
        {"no active credential to rotate — mint one first", E::Transient},
        {"overlap window would exceed the predecessor credential's expiry", E::ClientValidation},
        {"overlap window would exceed the successor credential's expiry", E::ClientValidation},
        {"failed to mint successor credential", E::Transient},
        {"failed to stamp predecessor overlap window", E::Transient},
        {"principal has a non-human active credential", E::ClientValidation},
        {"more than two active credentials for this principal — resolve manually before "
         "rotating",
         E::ClientValidation},
        {"two active credentials not in a recognized rotation pair — resolve via revoke, "
         "not rotate",
         E::ClientValidation},
        {"rotation grace window elapsed; confirm or revoke", E::Conflict},
        {"rotation in progress by a different operator", E::Conflict},
        {"rotation failed", E::Transient}, // generic with_txn_for-failed fallback
        // validate_human_mint's own strings, surfaced verbatim as
        // rotate_token's candidate_error on the mint arm:
        {"token name cannot be empty", E::ClientValidation},
        {"service-scoped tokens must have an expiration time", E::ClientValidation},
        {"invalid MCP tier — must be 'readonly', 'operator', or 'supervised'",
         E::ClientValidation},
        {"MCP tokens must have an expiration time (max 90 days)", E::ClientValidation},
        {"MCP token TTL cannot exceed 90 days", E::ClientValidation},
        // generate_raw_token's CSPRNG failure, also surfaced as candidate_error:
        {"CSPRNG unavailable (entropy exhausted)", E::Transient},

        // ── confirm_token_rotation ──────────────────────────────────────
        {"no such token to confirm", E::ClientValidation},
        {"no in-flight rotation to confirm", E::Transient},
        // #2943 (PR #2974 review): a malformed pair found AFTER a positive
        // two-row read is TERMINAL, so it gets its own string and classifies
        // Conflict. Sharing "no in-flight rotation to confirm" above made it
        // retryable, and an agentic client retries a malformed pair forever.
        {"rotation pair is malformed - confirm cannot proceed; revoke one side explicitly",
         E::Conflict},
        // Round 5: Conflict, not Transient — see the dedicated TEST_CASE
        // above and engine_store_error_class.hpp's step-3 rationale.
        {"no rotation currently pending for the supplied token_id — nothing to confirm; "
         "call rotate again if a new rotation is needed",
         E::Conflict},
        {"more than two active credentials for this principal - resolve manually before "
         "confirming",
         E::ClientValidation},
        {"one active credential with unresolved rotation metadata - inspect the credential "
         "state and do not rotate; revoke only if it is confirmed stale",
         E::Conflict},
        {"token_id does not match the pending rotation successor; pass the token_id "
         "returned by rotate",
         E::Conflict},
        {"rotation confirmation unavailable — retry via rotate or fall back to revoke",
         E::Conflict},
        {"failed to confirm rotation", E::Transient},
        {"failed to revoke predecessor on confirm", E::Transient},
        {"failed to clear successor rotation state on confirm", E::Transient},
        {"confirm failed", E::Transient}, // generic with_txn_for-failed fallback
        // #3015 proof-of-possession: the caller-input guard is a permanent
        // client error; the PoP mismatch itself is its OWN distinct class —
        // never folded into ClientValidation or Conflict — reachable only
        // after every earlier admission gate already passed.
        {"secret required", E::ClientValidation},
        {"rotation secret mismatch — the presented secret does not verify against the "
         "pending successor",
         E::SecretMismatch},
    };

    // See the TEST_CASE-level comment: this pins accidental drift in THIS
    // table, not drift between this table and the source.
    REQUIRE(cases.size() == 41); // 39 -> 41: #3015 secret-required + secret-mismatch strings

    for (const auto& c : cases) {
        CAPTURE(c.message);
        CHECK(classify_engine_store_error(c.message) == c.expected);
    }
}

TEST_CASE("confirm_result_label maps every class to a pre-seeded metric label",
          "[engine_store_error]") {
    using E = EngineStoreErrorClass;
    // The three failure labels must exactly match the closed set pre-seeded in
    // server.cpp (surface x {success,conflict,client_error,transient}); `success`
    // is stamped by the caller, not this function.
    CHECK(std::string_view(confirm_result_label(E::ClientValidation)) == "client_error");
    CHECK(std::string_view(confirm_result_label(E::Conflict)) == "conflict");
    CHECK(std::string_view(confirm_result_label(E::Transient)) == "transient");
    // #3015: added alongside the pre-seeded set's fifth label — see
    // server.cpp's kApiTokenConfirmTotalMetric/yuzu_engine_principal_confirm_total
    // pre-seed loops.
    CHECK(std::string_view(confirm_result_label(E::SecretMismatch)) == "secret_mismatch");
}
