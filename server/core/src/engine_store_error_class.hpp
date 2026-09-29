#pragma once

/// @file engine_store_error_class.hpp
/// Single source of truth for classifying an EnginePrincipalStore /
/// ApiTokenStore `std::expected<..., std::string>` error string into an HTTP /
/// JSON-RPC status class. The REST surface (`engine_store_error_status` in
/// rest_api_v1.cpp) and the MCP surface (`mcp_error_for_store_msg` in
/// mcp_server.cpp) BOTH route through this so the two transports can never
/// disagree on whether a given store error is a client error, a conflict, or a
/// retryable transient failure (PR #2284 review Major 5 — "keep the two
/// classifiers in sync"; the hand-duplicated versions had already diverged).
///
/// LOAD-BEARING ORDERING: several conflict strings contain a broad transient
/// substring (e.g. "rotation confirmation unavailable" contains "unavailable"),
/// so the specific conflict matches MUST be tested before the broad transient
/// ones. None of the client-validation substrings contain a transient
/// substring, so they are safely tested last, before the retryable default.
///
/// POSITIVE-READ EXEMPTION (#2404, detailed at step 3): the confirm-replay
/// conflict strings are emitted only after a non-empty active-credential read,
/// so — unlike the deliberately-transient "no in-flight rotation to confirm"
/// (0-active, ambiguous with a swallowed read failure) — they are terminal.
/// The human token-keyed arm's "no rotation currently pending" (P2 #11) is
/// the SAME exemption applied to `GroupRotationConfirmState::kGroupEmpty`
/// (`rotation_confirm_state.hpp`): a POSITIVE, non-empty principal-wide read
/// that simply has nothing left tagged with the pinned rotation_group —
/// terminal Conflict, not Transient, by the identical #2404 reasoning
/// (round-5 adjudication corrected an earlier Transient misclassification of
/// this exact state; see the step-3 entry below).

#include <string>
#include <string_view>

namespace yuzu::server::detail {

enum class EngineStoreErrorClass {
    ClientValidation, //!< Bad input / bad state — REST 400, MCP kInvalidParams.
    Conflict,         //!< Rotation-state conflict, don't blindly retry — REST 409, MCP kInvalidParams.
    Transient,        //!< Store/infra failure, retryable — REST 503, MCP kInternalError.
    // #3015 proof-of-possession: the caller cleared every other admission
    // gate (ownership, pair-state, the token_id pin, tier/scope, the
    // initiator binding) but presented a secret that does not hash-match the
    // pending successor's stored hash. MUST stay a distinct outcome — never
    // folded into ClientValidation/Conflict — because it is reachable ONLY
    // after every other gate passed (confirm_rotation/confirm_token_rotation
    // check it strictly last); collapsing it into an existing class would
    // erase the one signal that makes the ordering an oracle-freedom
    // guarantee rather than just documentation. REST 403, MCP
    // kPermissionDenied.
    SecretMismatch,
};

[[nodiscard]] inline EngineStoreErrorClass classify_engine_store_error(const std::string& msg) {
    const auto has = [&](std::string_view s) { return msg.find(s) != std::string_view::npos; };

    // 1. CSPRNG failure — transient (a fresh secret couldn't be generated).
    if (has("CSPRNG"))
        return EngineStoreErrorClass::Transient;

    // 1b. "no in-flight rotation to confirm" — the deliberately-ambiguous
    //     0-active / malformed-pair read (`RotationConfirmState::kNoneActive`,
    //     `GroupRotationConfirmState::kAmbiguousEmpty`): a swallowed read
    //     failure and a genuinely empty active-credential set are
    //     indistinguishable here (UP-6, rotation_confirm_state.hpp), so this
    //     MUST stay retryable. Step 7's default happens to be Transient too,
    //     but this is an EXPLICIT entry rather than reliance on fall-through
    //     — the round-4/5 review found that an unkeyed string is exactly what
    //     lets a later addition silently change its classification by
    //     accident (the "no rotation currently pending" collision below was
    //     that same failure mode in the opposite direction).
    if (has("no in-flight rotation to confirm"))
        return EngineStoreErrorClass::Transient;

    // 1c. #3015 proof-of-possession mismatch — reachable ONLY after every
    //     earlier admission gate in confirm_rotation/confirm_token_rotation
    //     already passed (ownership, pair-state, the token_id pin, tier/
    //     scope, the initiator binding — see those functions' own doc
    //     comments for why PoP is checked strictly last). MUST classify to
    //     its own distinct SecretMismatch outcome, never Conflict or
    //     ClientValidation — folding it into either erases the signal that
    //     makes the ordering an oracle-freedom guarantee. Placed before
    //     step 2 (no substring overlap with anything below, order-
    //     independent, but grouped with the other confirm-outcome entries).
    if (has("rotation secret mismatch"))
        return EngineStoreErrorClass::SecretMismatch;

    // 2. Conflict strings that ALSO contain a broad transient substring —
    //    must win before the broad "unavailable" check below.
    // #2961: a plain restart no longer produces this for a v3-stamped pair — the
    // durable `rotation_initiator` column now resolves the binding. The two causes
    // `resolve_rotation_initiator` can return `nullopt` for are (a) NEITHER source
    // resolves an initiator (a pre-v3 pair, or a row that was never stamped) — this
    // one is genuinely reachable in normal operation — and (b) RAM and the durable
    // column DISAGREE, which fails closed. (b) is NOT reachable through any live
    // code path (both sources are written from the same requesting_user in the same
    // mint call); it can only arise from an out-of-band write to
    // `api_tokens.rotation_initiator` or a future bug, i.e. it is a tamper/
    // corruption signal, counted separately
    // (`ApiTokenStore::rotation_initiator_disagreements()`) — not a "second live
    // cause" in the sense (a) is. Both are still terminal from THIS confirm call's
    // point of view, hence Conflict either way.
    if (has("rotation confirmation unavailable"))
        return EngineStoreErrorClass::Conflict;

    // 2b. #2943: malformed pair found AFTER a positive `kPairInGroup` read —
    //     terminal, not retryable. Deliberately its OWN string rather than
    //     reusing "no in-flight rotation to confirm" above: that key is keyed
    //     Transient for the AMBIGUOUS read, and sharing it made a
    //     positive-read terminal state retryable, which an agentic client
    //     retries forever. Placed here, above the broad "unavailable" check
    //     at step 7, for the same ordering reason as the entry above it.
    //     Checked against every other key in this file for substring
    //     collision when added (the hazard this file's own header documents).
    if (has("rotation pair is malformed"))
        return EngineStoreErrorClass::Conflict;

    // 3. Other rotation-state conflicts (no broad substring, order-independent).
    //    "does not match the pending rotation": the confirm token_id pin
    //    (#2384) — a stale/wrong successor id, i.e. the rotation state has
    //    moved on. 409, don't blindly retry with the same id.
    //    The #2404 confirm-replay strings are terminal conflicts too: they are
    //    emitted ONLY after a POSITIVE row read (a non-empty active set — see
    //    rotation_confirm_state.hpp), so unlike the transient "no in-flight
    //    rotation to confirm" (0-active, ambiguous with a swallowed read
    //    failure) they carry no read-failure ambiguity and must not be retried:
    //      "sole active credential"       -> already confirmed / already resolved (pin match);
    //      "the rotation was resolved"    -> a different credential survives (pin mismatch, 1 active);
    //      "unresolved rotation metadata" -> a best-effort pair-resolve left stale linkage (#2404 F1).
    //    "no rotation currently pending for the supplied token_id" (P2 #11
    //    human token-keyed arm, `GroupRotationConfirmState::kGroupEmpty` /
    //    the `pinned.rotation_group.empty()` short-circuit,
    //    api_token_store.cpp) is the SAME #2404 exemption again: emitted only
    //    after a POSITIVE, non-empty principal-wide read that simply has
    //    nothing tagged with the pinned rotation_group — terminal, not
    //    ambiguous, exactly like `kSoleOtherToken`'s "the rotation was
    //    resolved" above, which carries the identical "rotate again if
    //    needed" guidance and is Conflict for the identical reason: telling a
    //    client to take a DIFFERENT follow-up action (call rotate, don't
    //    retry confirm) is the definition of 409, not a retry hint — an
    //    agentic caller acts on the machine class, not the prose. (Round 4
    //    shipped this as an explicit Transient entry instead — refuted by
    //    #2404 precedent, by `kSoleOtherToken` itself, and by this file's own
    //    "every terminal state -> Conflict or ClientValidation" contract;
    //    round 5 corrects it. ClientValidation was also considered and
    //    rejected: the request is well-formed and names a real, owned token,
    //    so the failure is purely resource-state, and arm parity with
    //    `kSoleOtherToken` is decisive.) None of these six substrings
    //    contains a broad transient substring ("not open"/"unavailable"/
    //    "rotation lock"), so their placement here (before step 5) is safe.
    if (has("grace window elapsed") || has("different operator") ||
        has("does not match the pending rotation") || has("sole active credential") ||
        has("the rotation was resolved") || has("unresolved rotation metadata") ||
        has("no rotation currently pending for the supplied token_id"))
        return EngineStoreErrorClass::Conflict;

    // 4. Advisory-lock contention — transient/retryable.
    if (has("rotation lock"))
        return EngineStoreErrorClass::Transient;

    // 5. Broad transient: "database not open", "... unavailable — try again",
    //    "engine referent check unavailable". No client-validation string below
    //    contains these substrings, so this broad match is safe here.
    if (has("not open") || has("unavailable"))
        return EngineStoreErrorClass::Transient;

    // 6. Genuine client-validation strings — pure input/state checks the store
    //    performs (or, for the two "recognized shape" rotate messages, only
    //    reachable AFTER a read already returned real rows, so they can't be a
    //    masked read failure). These stay client-class; everything else falls
    //    through to the retryable default.
    static constexpr std::string_view kClientValidationSubstrings[] = {
        // EnginePrincipalStore::create
        "classification must be",
        "principal_id must be in the reserved",
        "principal_id slug may only contain",
        "owner_username cannot be empty",
        "justification cannot be empty",
        // ApiTokenStore::create_token (general + engine §6/§7/§8 validation)
        "token name cannot be empty",
        "service-scoped tokens must have an expiration time",
        "invalid MCP tier",
        "MCP tokens must have an expiration time",
        "invalid principal_kind",
        "engine:-namespaced principal_id requires principal_kind=engine",
        "engine principal tokens cannot be service-scoped",
        "engine principal tokens must use mcp_tier=readonly",
        "engine principal tokens cannot be perpetual",
        "exceed 90 days",
        "engine principal not found or revoked",
        // MCP transfer_owner folds not-found/not-active into the store error
        // string (the REST twin pre-checks and 404s before reaching here), so
        // this permanent client condition must classify as ClientValidation,
        // not the retryable Transient default (PR #2284 round-2 review).
        "not found or not active",
        // Terminal data-shape condition (create_token engine path): a principal
        // whose existing credential is non-engine is a permanent client error,
        // not a transient store failure. Low reachability (the G2 namespace
        // guard normally prevents it) but classified explicitly per step 6.
        "non-engine active credential",
        "principal_id required",
        "token_id required",
        "secret required",
        "requesting_user required",
        "overlap window below 24h floor",
        "overlap window exceeds the maximum",
        "overlap window would exceed the predecessor credential's expiry",
        "overlap window would exceed the successor credential's expiry",
        "not in a recognized rotation pair",
        "more than two active credentials",
        // ApiTokenStore::rotate_token / confirm_token_rotation (human
        // token-keyed arm, P2 #11) — new, permanent client-validation
        // conditions the group-scoped state machine can name precisely
        // (unlike the principal-wide engine arm's ambiguous 0-active case,
        // these are reached only after a POSITIVE, definitive row lookup —
        // see api_token_store.cpp's TokenLookup / rotation_confirm_state.hpp's
        // classify_confirm_state_in_group for why each is safe to classify
        // terminally rather than falling to the retryable default).
        "no such token to rotate",
        "no such token to confirm",
        "token is not a human-owned credential",
        "credential is not currently active — nothing to rotate",
        "principal has a non-human active credential",
    };
    for (const std::string_view needle : kClientValidationSubstrings)
        if (has(needle))
            return EngineStoreErrorClass::ClientValidation;

    // 7. Default: an UNRECOGNIZED store-layer error (a bare "rotation
    //    failed"/"confirm failed" fallback, a DB-error-suffixed message, a
    //    swallowed read failure surfaced as "no active credential to rotate")
    //    is far more likely a transient infrastructure failure than a client
    //    error — fail SAFE (retryable), never a misleading 400/kInvalidParams.
    return EngineStoreErrorClass::Transient;
}

/// Metric `result`-label for a store error class, shared by the REST and MCP
/// confirm handlers so `yuzu_engine_principal_confirm_total{result=...}` reads
/// identically on both surfaces (#2404). `success` is stamped by the caller on
/// the ok path; this maps only the failure classes. The five labels
/// (success|conflict|client_error|transient|secret_mismatch) are the closed set
/// pre-seeded in server.cpp — keep the two in sync.
[[nodiscard]] inline const char* confirm_result_label(EngineStoreErrorClass cls) {
    switch (cls) {
    case EngineStoreErrorClass::ClientValidation:
        return "client_error";
    case EngineStoreErrorClass::Conflict:
        return "conflict";
    case EngineStoreErrorClass::Transient:
        return "transient";
    case EngineStoreErrorClass::SecretMismatch:
        return "secret_mismatch";
    }
    return "transient"; // unreachable — all enum cases return above
}

} // namespace yuzu::server::detail
