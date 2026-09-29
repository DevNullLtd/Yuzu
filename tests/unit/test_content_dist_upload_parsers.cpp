/**
 * test_content_dist_upload_parsers.cpp — pure-parser coverage for
 * `content_dist`'s `upload_file` action (content_dist_upload_parsers.hpp),
 * the AGENT half of the PR1.6 one-time upload grant + authenticated chunked
 * receive protocol. Fixture strings only — no sockets, no filesystem, no
 * process spawns, no sleeps; `backoff_delay_ms` is checked as a pure
 * function of its input, never actually slept on.
 *
 * `plan_resync_rehash` below is the pure decision `do_upload`'s commit-hash
 * repair (content_dist_plugin.cpp) is built on — a lost chunk-ack response
 * followed by a forward resync used to leave the acknowledged bytes out of
 * the commit digest, since the hasher is fed only on the ACK path and a
 * lost ACK meant that feed never happened. The orchestration itself (the
 * actual network loop, actual file reads, actual `IncrementalSha256`) is
 * NOT unit-tested here, deliberately: it lives in the "no sockets, no
 * filesystem, no process spawns" shell this file's own header comment
 * names, and TLS is mandatory for every request that shell makes with no
 * test-CA injection point — exercising it for real belongs on the
 * integration surface (CLAUDE.md's "inject the boundary" / "prefer the
 * integration surface" test-efficiency rules), not the unit suite. What is
 * pinned here is the invariant the fix depends on: which byte range must be
 * re-hashed, and that a resync which does NOT move past what has already
 * been hashed triggers no repair at all.
 */

#include "content_dist_upload_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::content_dist::upload;

// ── Credential grammar (#3136 minor) ─────────────────────────────────────

TEST_CASE("is_valid_credential_parts accepts well-formed 32/64 lowercase hex",
         "[agent][content_dist][upload]") {
    const std::string id(32, 'a');
    const std::string secret(64, 'f');
    CHECK(is_valid_credential_parts(id, secret));
}

TEST_CASE("is_valid_credential_parts rejects wrong length, case, or non-hex",
         "[agent][content_dist][upload]") {
    const std::string good_id(32, 'a');
    const std::string good_secret(64, 'f');
    CHECK_FALSE(is_valid_credential_parts(std::string(31, 'a'), good_secret)); // short id
    CHECK_FALSE(is_valid_credential_parts(std::string(33, 'a'), good_secret)); // long id
    CHECK_FALSE(is_valid_credential_parts(good_id, std::string(63, 'f')));    // short secret
    CHECK_FALSE(is_valid_credential_parts(std::string(32, 'A'), good_secret)); // uppercase
    CHECK_FALSE(is_valid_credential_parts(std::string(32, 'g'), good_secret)); // non-hex
    CHECK_FALSE(is_valid_credential_parts("", good_secret));
    CHECK_FALSE(is_valid_credential_parts(good_id, ""));
}

// ── Chunk planning ───────────────────────────────────────────────────────

TEST_CASE("plan_next_chunk: a successful multi-chunk plan walks the whole file",
         "[agent][content_dist][upload]") {
    // 25 bytes, 10-byte chunks -> 10, 10, 5.
    auto c1 = plan_next_chunk(0, 25, 10);
    REQUIRE(c1.has_value());
    CHECK(c1->start == 0);
    CHECK(c1->end == 9);
    CHECK(c1->total == 25);

    auto c2 = plan_next_chunk(10, 25, 10);
    REQUIRE(c2.has_value());
    CHECK(c2->start == 10);
    CHECK(c2->end == 19);

    auto c3 = plan_next_chunk(20, 25, 10);
    REQUIRE(c3.has_value());
    CHECK(c3->start == 20);
    CHECK(c3->end == 24); // last chunk is short, not padded

    // Nothing left once offset reaches file_size.
    CHECK_FALSE(plan_next_chunk(25, 25, 10).has_value());
}

TEST_CASE("plan_next_chunk: a chunk never exceeds chunk_max_bytes and never buffers past it",
         "[agent][content_dist][upload]") {
    auto c = plan_next_chunk(0, 1'000'000, 8 * 1024 * 1024);
    REQUIRE(c.has_value());
    CHECK(c->end - c->start + 1 == 1'000'000); // whole (small) file fits in one chunk
}

TEST_CASE("plan_next_chunk: rejects structurally invalid input", "[agent][content_dist][upload]") {
    CHECK_FALSE(plan_next_chunk(-1, 100, 10).has_value());  // negative offset
    CHECK_FALSE(plan_next_chunk(0, 0, 10).has_value());     // empty file
    CHECK_FALSE(plan_next_chunk(0, 100, 0).has_value());    // zero chunk cap
    CHECK_FALSE(plan_next_chunk(150, 100, 10).has_value()); // offset past EOF
}

TEST_CASE("chunk_count matches how many plan_next_chunk calls a fresh upload needs",
         "[agent][content_dist][upload]") {
    CHECK(chunk_count(25, 10) == 3);
    CHECK(chunk_count(20, 10) == 2);
    CHECK(chunk_count(1, 10) == 1);
    CHECK(chunk_count(0, 10) == 0);
}

// ── Resume-offset reconciliation ────────────────────────────────────────

TEST_CASE("reconcile_resume_offset accepts any offset within [0, file_size]",
         "[agent][content_dist][upload]") {
    CHECK(reconcile_resume_offset(0, 100) == 0);
    CHECK(reconcile_resume_offset(50, 100) == 50);
    CHECK(reconcile_resume_offset(100, 100) == 100); // exactly EOF is valid (upload complete)
}

TEST_CASE("reconcile_resume_offset rejects an offset outside the file",
         "[agent][content_dist][upload]") {
    CHECK_FALSE(reconcile_resume_offset(-1, 100).has_value());
    CHECK_FALSE(reconcile_resume_offset(101, 100).has_value());
}

TEST_CASE("plan_resync_rehash: the lost-ack scenario — a forward resync past what has "
         "been hashed requires repairing exactly the gap",
         "[agent][content_dist][upload]") {
    // The exact defect: chunk 1 covers [0, 40) and the server accepts it,
    // but this process never sees the 200 response (dropped connection),
    // so `hasher` is never fed those bytes — hashed_to stays 0. The retry
    // of chunk 1 then gets offset_mismatch with the server's real recorded
    // offset, 40 (it already has those bytes). Repairing the digest means
    // hashing exactly [0, 40) before adopting offset 40.
    auto range = plan_resync_rehash(/*hashed_to=*/0, /*resynced_offset=*/40);
    REQUIRE(range.has_value());
    CHECK(range->start == 0);
    CHECK(range->end == 40);
}

TEST_CASE("plan_resync_rehash: a resync that does not move past what is already hashed "
         "requires no repair",
         "[agent][content_dist][upload]") {
    // The ordinary case: hasher already covers everything up to the
    // current offset, so a resync landing at or behind that point is a
    // no-op for the digest (it might still affect the send-side offset,
    // but that is `reconcile_resume_offset`'s concern, not this one's).
    CHECK_FALSE(plan_resync_rehash(/*hashed_to=*/40, /*resynced_offset=*/40).has_value());
    CHECK_FALSE(plan_resync_rehash(/*hashed_to=*/40, /*resynced_offset=*/20).has_value());
    CHECK_FALSE(plan_resync_rehash(/*hashed_to=*/40, /*resynced_offset=*/0).has_value());
}

TEST_CASE("plan_resync_rehash: a mid-stream loss (chunk 3 of 5 acknowledged silently) "
         "still yields exactly the missing middle range",
         "[agent][content_dist][upload]") {
    // hashed_to sits at the end of chunk 2 (bytes [0,20) already fed to the
    // hasher on their own successful acks); the lost ack belongs to chunk 3,
    // [20,30); the resync target is 30. Only that ten-byte gap is missing —
    // proving the range is anchored to hashed_to, not to 0, so a resume
    // from a partial hasher state never re-hashes bytes it already has.
    auto range = plan_resync_rehash(/*hashed_to=*/20, /*resynced_offset=*/30);
    REQUIRE(range.has_value());
    CHECK(range->start == 20);
    CHECK(range->end == 30);
}

TEST_CASE("validate_chunk_ack accepts only the offset the request itself committed to",
         "[agent][content_dist][upload]") {
    // A chunk covering [10, 19] must ack exactly 20 — the agent already
    // knows this, it isn't new information from the server.
    CHECK(validate_chunk_ack(20, 20, 100) == 20);
}

TEST_CASE("validate_chunk_ack rejects a missing, disagreeing, or out-of-range acknowledgement",
         "[agent][content_dist][upload]") {
    CHECK_FALSE(validate_chunk_ack(std::nullopt, 20, 100).has_value());  // missing
    CHECK_FALSE(validate_chunk_ack(19, 20, 100).has_value());            // behind
    CHECK_FALSE(validate_chunk_ack(21, 20, 100).has_value());            // ahead
    CHECK_FALSE(validate_chunk_ack(-1, 20, 100).has_value());            // negative
    CHECK_FALSE(validate_chunk_ack(150, 20, 100).has_value());           // past EOF
}

// ── The ten frozen reason strings ───────────────────────────────────────

TEST_CASE("parse_reason recognizes every one of the ten frozen strings, and only those",
         "[agent][content_dist][upload]") {
    CHECK(parse_reason("grant_unknown") == Reason::kGrantUnknown);
    CHECK(parse_reason("grant_already_redeemed") == Reason::kGrantAlreadyRedeemed);
    CHECK(parse_reason("expired") == Reason::kExpired);
    CHECK(parse_reason("offset_mismatch") == Reason::kOffsetMismatch);
    CHECK(parse_reason("chunk_too_large") == Reason::kChunkTooLarge);
    CHECK(parse_reason("size_exceeded") == Reason::kSizeExceeded);
    CHECK(parse_reason("hash_mismatch") == Reason::kHashMismatch);
    CHECK(parse_reason("session_unknown") == Reason::kSessionUnknown);
    CHECK(parse_reason("session_terminal") == Reason::kSessionTerminal);
    CHECK(parse_reason("tls_required") == Reason::kTlsRequired);

    CHECK_FALSE(parse_reason("").has_value());
    CHECK_FALSE(parse_reason("not_a_real_reason").has_value());
    CHECK_FALSE(parse_reason("Grant_Unknown").has_value()); // case-sensitive, matches the wire exactly
}

TEST_CASE("reason_string(parse_reason(s)) round-trips for every one of the ten reasons",
         "[agent][content_dist][upload]") {
    const char* kReasons[] = {
        "grant_unknown", "grant_already_redeemed", "expired",         "offset_mismatch",
        "chunk_too_large", "size_exceeded",         "hash_mismatch",  "session_unknown",
        "session_terminal", "tls_required",
    };
    for (auto* s : kReasons) {
        auto r = parse_reason(s);
        REQUIRE(r.has_value());
        CHECK(reason_string(*r) == s);
    }
}

TEST_CASE("classify_reason maps every one of the ten frozen reasons to a decision",
         "[agent][content_dist][upload]") {
    // Resync: the response carries new authoritative state to adopt.
    CHECK(classify_reason(Reason::kOffsetMismatch) == UploadDecision::kResync);

    // Abort: every other frozen reason is a terminal, non-retryable outcome.
    // `chunk_too_large` included — the agent's cap is deterministic from
    // `chunk_max_bytes` learned at session-open, so a retry resends the
    // IDENTICAL range and cannot converge on its own (no new cap comes back
    // in-band); retrying would only burn the attempt budget.
    CHECK(classify_reason(Reason::kChunkTooLarge) == UploadDecision::kAbort);
    CHECK(classify_reason(Reason::kGrantUnknown) == UploadDecision::kAbort);
    CHECK(classify_reason(Reason::kGrantAlreadyRedeemed) == UploadDecision::kAbort);
    CHECK(classify_reason(Reason::kExpired) == UploadDecision::kAbort);
    CHECK(classify_reason(Reason::kSizeExceeded) == UploadDecision::kAbort);
    CHECK(classify_reason(Reason::kHashMismatch) == UploadDecision::kAbort);
    CHECK(classify_reason(Reason::kSessionUnknown) == UploadDecision::kAbort);
    CHECK(classify_reason(Reason::kSessionTerminal) == UploadDecision::kAbort);
    CHECK(classify_reason(Reason::kTlsRequired) == UploadDecision::kAbort);
}

// ── decide_next_action: the scenarios the spec calls out by name ───────

TEST_CASE("decide_next_action: 409 offset_mismatch re-syncs immediately, no backoff",
         "[agent][content_dist][upload]") {
    auto d = decide_next_action(409, Reason::kOffsetMismatch, 1);
    CHECK(d.action == UploadDecision::kResync);
    CHECK(d.backoff_ms == 0);
}

TEST_CASE("decide_next_action: 413 chunk_too_large aborts regardless of attempt number",
         "[agent][content_dist][upload]") {
    // No new cap comes back in-band, so a retry would resend the identical
    // range and can never converge — abort immediately rather than burn
    // the attempt budget on a guaranteed repeat failure.
    CHECK(decide_next_action(413, Reason::kChunkTooLarge, 1).action == UploadDecision::kAbort);
    CHECK(decide_next_action(413, Reason::kChunkTooLarge, kMaxAttempts + 10).action ==
         UploadDecision::kAbort);
}

TEST_CASE("decide_next_action: 410 expired aborts, no retry regardless of attempt number",
         "[agent][content_dist][upload]") {
    CHECK(decide_next_action(410, Reason::kExpired, 1).action == UploadDecision::kAbort);
    CHECK(decide_next_action(410, Reason::kExpired, kMaxAttempts + 10).action ==
         UploadDecision::kAbort);
}

TEST_CASE("decide_next_action: 422 hash_mismatch aborts", "[agent][content_dist][upload]") {
    CHECK(decide_next_action(422, Reason::kHashMismatch, 1).action == UploadDecision::kAbort);
}

TEST_CASE("decide_next_action: 409 grant_already_redeemed aborts", "[agent][content_dist][upload]") {
    CHECK(decide_next_action(409, Reason::kGrantAlreadyRedeemed, 1).action ==
         UploadDecision::kAbort);
}

TEST_CASE("decide_next_action: a retryable 5xx with no reason backs off and grows with attempt",
         "[agent][content_dist][upload]") {
    auto d1 = decide_next_action(503, std::nullopt, 1);
    CHECK(d1.action == UploadDecision::kRetry);
    CHECK(d1.backoff_ms > 0);

    auto d2 = decide_next_action(503, std::nullopt, 2);
    CHECK(d2.action == UploadDecision::kRetry);
    CHECK(d2.backoff_ms > d1.backoff_ms); // exponential, not flat

    // A connection-level failure (no HTTP response at all) is the same
    // transient case, reported by the shell as status 0.
    CHECK(decide_next_action(0, std::nullopt, 1).action == UploadDecision::kRetry);
}

TEST_CASE("decide_next_action: exhausted attempts abort even on an otherwise-retryable status",
         "[agent][content_dist][upload]") {
    auto d = decide_next_action(503, std::nullopt, kMaxAttempts);
    CHECK(d.action == UploadDecision::kAbort);
    CHECK(d.backoff_ms == 0);
}

TEST_CASE("decide_next_action: an unreasoned non-5xx status is a structural bug, not transient",
         "[agent][content_dist][upload]") {
    // A 400 with no `reason` field (e.g. a locally malformed Content-Range)
    // is never retried — it will fail identically every time.
    CHECK(decide_next_action(400, std::nullopt, 1).action == UploadDecision::kAbort);
}

TEST_CASE("backoff_delay_ms is deterministic, monotonic, and capped",
         "[agent][content_dist][upload]") {
    CHECK(backoff_delay_ms(1) == kBackoffBaseMs);
    CHECK(backoff_delay_ms(2) == kBackoffBaseMs * 2);
    CHECK(backoff_delay_ms(3) == kBackoffBaseMs * 4);
    CHECK(backoff_delay_ms(1) == backoff_delay_ms(1)); // pure — same input, same output
    for (int cap_attempt = 1; cap_attempt <= 20; ++cap_attempt)
        CHECK(backoff_delay_ms(cap_attempt) <= kBackoffCapMs);
}

TEST_CASE("attempts_exhausted is a simple threshold on kMaxAttempts",
         "[agent][content_dist][upload]") {
    CHECK_FALSE(attempts_exhausted(1));
    CHECK_FALSE(attempts_exhausted(kMaxAttempts - 1));
    CHECK(attempts_exhausted(kMaxAttempts));
    CHECK(attempts_exhausted(kMaxAttempts + 1));
}

TEST_CASE("is_transient_no_reason: only an unreasoned 5xx or a connection failure qualifies",
         "[agent][content_dist][upload]") {
    CHECK(is_transient_no_reason(503, std::nullopt));
    CHECK(is_transient_no_reason(0, std::nullopt));      // connection-level failure
    CHECK_FALSE(is_transient_no_reason(400, std::nullopt));
    CHECK_FALSE(is_transient_no_reason(200, std::nullopt));
    // A recognized reason is never "no reason", regardless of status.
    CHECK_FALSE(is_transient_no_reason(503, Reason::kSessionTerminal));
}

TEST_CASE("commit_matches accepts only a response that agrees with what this run computed",
         "[agent][content_dist][upload]") {
    CommitResponse resp{"committed", 25,
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"};
    CHECK(commit_matches(resp, 25, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_FALSE(commit_matches(resp, 26, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_FALSE(commit_matches(resp, 25, "0000000000000000000000000000000000000000000000000000000000000000"));
}

// ── Response parsing ─────────────────────────────────────────────────────

TEST_CASE("parse_session_open_response parses a well-formed session-open body",
         "[agent][content_dist][upload]") {
    auto body = R"({"upload_id":"abc123","session_secret":"deadbeef","chunk_max_bytes":8388608,)"
               R"("offset":0,"expires_at":1700000900})";
    auto session = parse_session_open_response(body);
    REQUIRE(session.has_value());
    CHECK(session->upload_id == "abc123");
    CHECK(session->session_secret == "deadbeef");
    CHECK(session->chunk_max_bytes == 8388608);
    CHECK(session->offset == 0);
    CHECK(session->expires_at == 1700000900);
}

TEST_CASE("parse_session_open_response rejects a malformed or incomplete body",
         "[agent][content_dist][upload]") {
    CHECK_FALSE(parse_session_open_response("{}").has_value());
    CHECK_FALSE(parse_session_open_response(R"({"upload_id":"abc"})").has_value());
    // chunk_max_bytes <= 0 is structurally impossible, never trusted.
    CHECK_FALSE(parse_session_open_response(
                    R"({"upload_id":"a","session_secret":"b","chunk_max_bytes":0,)"
                    R"("offset":0,"expires_at":1})")
                    .has_value());
    // #3136 should-fix: a fresh session-open ALWAYS returns offset 0 per the
    // frozen protocol text (server/core/src/upload_grant_parsers.hpp) — a
    // non-zero offset here is a server-contract violation this parser must
    // not trust, not a resume-poll value (that's StatusResponse's job).
    CHECK_FALSE(parse_session_open_response(
                    R"({"upload_id":"a","session_secret":"b","chunk_max_bytes":8388608,)"
                    R"("offset":1,"expires_at":1700000900})")
                    .has_value());
}

TEST_CASE("parse_chunk_ack_offset parses a successful chunk PUT body",
         "[agent][content_dist][upload]") {
    auto offset = parse_chunk_ack_offset(R"({"offset":1048576})");
    REQUIRE(offset.has_value());
    CHECK(*offset == 1048576);
}

TEST_CASE("parse_commit_response parses a well-formed commit body",
         "[agent][content_dist][upload]") {
    auto body = R"({"state":"committed","actual_size":25,)"
               R"("sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})";
    auto commit = parse_commit_response(body);
    REQUIRE(commit.has_value());
    CHECK(commit->state == "committed");
    CHECK(commit->actual_size == 25);
    CHECK(commit->sha256 ==
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("parse_commit_response rejects a non-committed or malformed state",
         "[agent][content_dist][upload]") {
    CHECK_FALSE(
        parse_commit_response(R"({"state":"open","actual_size":25,"sha256":"aa"})").has_value());
    CHECK_FALSE(parse_commit_response("{}").has_value());
}

TEST_CASE("parse_status_response parses the status GET body, terminal states included",
         "[agent][content_dist][upload]") {
    auto open = parse_status_response(R"({"state":"open","offset":1048576,"expires_at":1700000900})");
    REQUIRE(open.has_value());
    CHECK(open->state == "open");
    CHECK(open->offset == 1048576);

    // register_status answers 200 with the CURRENT state even once the
    // session has gone terminal — this is what resolves an ambiguous
    // commit outcome.
    auto committed = parse_status_response(R"({"state":"committed","offset":25,"expires_at":1700000900})");
    REQUIRE(committed.has_value());
    CHECK(committed->state == "committed");
}

TEST_CASE("parse_status_response rejects a malformed body", "[agent][content_dist][upload]") {
    CHECK_FALSE(parse_status_response("{}").has_value());
    CHECK_FALSE(parse_status_response(R"({"state":"","offset":0,"expires_at":1})").has_value());
}

TEST_CASE("parse_error_envelope extracts reason and message from the frozen envelope",
         "[agent][content_dist][upload]") {
    auto body = R"({"error":{"code":401,"message":"grant unknown or invalid credential",)"
               R"("reason":"grant_unknown"},"meta":{"api_version":"v1"}})";
    auto info = parse_error_envelope(body);
    REQUIRE(info.reason.has_value());
    CHECK(*info.reason == Reason::kGrantUnknown);
    CHECK(info.message == "grant unknown or invalid credential");
    CHECK_FALSE(info.offset.has_value());
}

TEST_CASE("parse_error_envelope extracts the authoritative offset merged into the error object",
         "[agent][content_dist][upload]") {
    // file_retrieval_routes.cpp merges the extra `offset` field INTO the
    // `error` object, never top-level — see send_reason()'s `extra` param.
    auto body = R"({"error":{"code":409,"message":"offset mismatch","reason":"offset_mismatch",)"
               R"("offset":4194304},"meta":{"api_version":"v1"}})";
    auto info = parse_error_envelope(body);
    REQUIRE(info.reason.has_value());
    CHECK(*info.reason == Reason::kOffsetMismatch);
    REQUIRE(info.offset.has_value());
    CHECK(*info.offset == 4194304);
}

TEST_CASE("parse_error_envelope on a generic (non-ten-reason) envelope leaves reason unset",
         "[agent][content_dist][upload]") {
    // The operator-route / generic-failure envelope shape carries no
    // `reason` field at all (see file_retrieval_routes.cpp's
    // generic_error_json) — decide_next_action then classifies by HTTP
    // status alone.
    auto body = R"({"error":{"code":503,"message":"upload grant store unavailable"},)"
               R"("meta":{"api_version":"v1"}})";
    auto info = parse_error_envelope(body);
    CHECK_FALSE(info.reason.has_value());
    CHECK(info.message == "upload grant store unavailable");
}

// ── Integer field extraction: overflow safety ───────────────────────────

TEST_CASE("a numeric field too large for int64_t is rejected, not silently overflowed",
         "[agent][content_dist][upload]") {
    // 19-digit value well past INT64_MAX (~9.22e18) — computing this with
    // an unchecked `v * 10 + digit` loop is signed-overflow undefined
    // behavior; the parser must refuse it before that point is reached.
    auto huge = parse_chunk_ack_offset(R"({"offset":99999999999999999999})");
    CHECK_FALSE(huge.has_value());

    // A value exactly at the boundary still parses correctly.
    auto at_max = parse_chunk_ack_offset(R"({"offset":9223372036854775807})");
    REQUIRE(at_max.has_value());
    CHECK(*at_max == 9223372036854775807LL);
}
