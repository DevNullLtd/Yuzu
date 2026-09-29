/**
 * test_upload_grant_parsers.cpp — pure-parser coverage for the PR1.6a
 * one-time upload grant + authenticated chunked receive protocol
 * (upload_grant_parsers.hpp). Everything here runs against fixture values
 * and an EXPLICIT injected clock — no store, no httplib, no libpq, no
 * filesystem, no CSPRNG. Pins the ten-value closed reason set, the
 * credential grammar, Content-Range parsing, offset/cap discipline, the
 * commit-verification collapse, destination-key derivation staying
 * server-facts-only, and the exact-boundary expiry rule.
 */

#include <catch2/catch_test_macros.hpp>

#include "upload_grant_parsers.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server::upload_grant;

// ── Credential grammar ──────────────────────────────────────────────────

TEST_CASE("parse_credential accepts a well-formed <id>.<secret>", "[server][upload]") {
    const std::string id(32, 'a');
    const std::string secret(64, 'b');
    auto cred = parse_credential(id + "." + secret);
    REQUIRE(cred.has_value());
    CHECK(cred->id == id);
    CHECK(cred->secret == secret);
}

TEST_CASE("parse_credential rejects grammar violations", "[server][upload]") {
    const std::string id(32, 'a');
    const std::string secret(64, 'b');

    CHECK_FALSE(parse_credential("").has_value());
    CHECK_FALSE(parse_credential(id).has_value());                       // no dot
    CHECK_FALSE(parse_credential(id + secret).has_value());              // no dot, concatenated
    CHECK_FALSE(parse_credential(id + "." + secret + ".extra").has_value()); // second dot
    CHECK_FALSE(parse_credential(id.substr(1) + "." + secret).has_value());  // short id
    CHECK_FALSE(parse_credential(id + "X." + secret).has_value());           // long id
    CHECK_FALSE(parse_credential(id + "." + secret.substr(1)).has_value());  // short secret
    // Uppercase is rejected outright, never normalized — AuthManager::bytes_to_hex
    // always emits lowercase, so an uppercase credential can never be genuine.
    std::string upper_id = id;
    upper_id[0] = 'A';
    CHECK_FALSE(parse_credential(upper_id + "." + secret).has_value());
    // Non-hex character.
    std::string bad_id = id;
    bad_id[0] = 'g';
    CHECK_FALSE(parse_credential(bad_id + "." + secret).has_value());
    // Empty id or secret half.
    CHECK_FALSE(parse_credential("." + secret).has_value());
    CHECK_FALSE(parse_credential(id + ".").has_value());
}

TEST_CASE("encode_credential round-trips through parse_credential", "[server][upload]") {
    const std::string id(32, '3');
    const std::string secret(64, '7');
    auto encoded = encode_credential(id, secret);
    auto decoded = parse_credential(encoded);
    REQUIRE(decoded.has_value());
    CHECK(decoded->id == id);
    CHECK(decoded->secret == secret);
}

TEST_CASE("constant_time_equals matches strcmp semantics on value, differs only in timing profile",
          "[server][upload]") {
    CHECK(constant_time_equals("abc", "abc"));
    CHECK_FALSE(constant_time_equals("abc", "abd"));
    CHECK_FALSE(constant_time_equals("abc", "ab"));   // length mismatch
    CHECK_FALSE(constant_time_equals("ab", "abc"));
    CHECK(constant_time_equals("", ""));
}

// ── Content-Range parsing ───────────────────────────────────────────────

TEST_CASE("parse_content_range accepts a well-formed header", "[server][upload]") {
    auto cr = parse_content_range("bytes 0-99/1000");
    REQUIRE(cr.has_value());
    CHECK(cr->start == 0);
    CHECK(cr->end == 99);
    CHECK(cr->total == 1000);
    CHECK(content_range_length(*cr) == 100);
}

TEST_CASE("parse_content_range accepts a single-byte final chunk", "[server][upload]") {
    auto cr = parse_content_range("bytes 999-999/1000");
    REQUIRE(cr.has_value());
    CHECK(content_range_length(*cr) == 1);
}

// A whole small file sent as one chunk. `end` is an inclusive byte INDEX, so
// the final byte of an N-byte entity is index N-1 — this is the common case for
// any upload under chunk_max_bytes, not an edge case.
TEST_CASE("parse_content_range accepts a whole entity in one chunk", "[server][upload]") {
    auto cr = parse_content_range("bytes 0-999/1000");
    REQUIRE(cr.has_value());
    CHECK(cr->start == 0);
    CHECK(cr->end == 999);
    CHECK(content_range_length(*cr) == 1000);
}

TEST_CASE("parse_content_range rejects malformed headers", "[server][upload]") {
    CHECK_FALSE(parse_content_range("").has_value());
    CHECK_FALSE(parse_content_range("bytes 0-99").has_value());          // no total
    CHECK_FALSE(parse_content_range("0-99/1000").has_value());           // no "bytes " prefix
    CHECK_FALSE(parse_content_range("bytes -99/1000").has_value());      // no start
    CHECK_FALSE(parse_content_range("bytes 0-/1000").has_value());       // no end
    CHECK_FALSE(parse_content_range("bytes 0-99/").has_value());         // no total
    CHECK_FALSE(parse_content_range("bytes 10-5/1000").has_value());     // end < start
    CHECK_FALSE(parse_content_range("bytes 0-1000/1000").has_value());   // end == total (last valid index is total-1)
    CHECK_FALSE(parse_content_range("bytes 0-99/0").has_value());        // total <= 0
    CHECK_FALSE(parse_content_range("bytes a-99/1000").has_value());     // non-numeric
    CHECK_FALSE(parse_content_range("bytes 0-99/-5").has_value());       // negative total
}

// ── Offset discipline ────────────────────────────────────────────────────

TEST_CASE("check_offset admits an exact match and echoes the authoritative offset on a miss",
          "[server][upload]") {
    auto ok = check_offset(/*recorded=*/100, /*start=*/100);
    CHECK(ok.ok);
    CHECK(ok.authoritative_offset == 100);

    auto mismatch = check_offset(/*recorded=*/100, /*start=*/50);
    CHECK_FALSE(mismatch.ok);
    CHECK(mismatch.authoritative_offset == 100);

    auto ahead = check_offset(/*recorded=*/100, /*start=*/150);
    CHECK_FALSE(ahead.ok);
    CHECK(ahead.authoritative_offset == 100);
}

// ── Caps ─────────────────────────────────────────────────────────────────

TEST_CASE("chunk_exceeds_max is a strict boundary", "[server][upload]") {
    CHECK_FALSE(chunk_exceeds_max(1000, 1000));
    CHECK(chunk_exceeds_max(1001, 1000));
    CHECK_FALSE(chunk_exceeds_max(0, 1000));
}

TEST_CASE("cumulative_exceeds_declared gates on offset + chunk vs declared size",
          "[server][upload]") {
    CHECK_FALSE(cumulative_exceeds_declared(/*offset=*/900, /*chunk=*/100, /*declared=*/1000));
    CHECK(cumulative_exceeds_declared(/*offset=*/900, /*chunk=*/101, /*declared=*/1000));
    CHECK_FALSE(cumulative_exceeds_declared(/*offset=*/0, /*chunk=*/1000, /*declared=*/1000));
    CHECK(cumulative_exceeds_declared(/*offset=*/1000, /*chunk=*/1, /*declared=*/1000));
}

TEST_CASE("total_exceeds_declared is a cap, not an equality requirement",
          "[server][upload]") {
    CHECK_FALSE(total_exceeds_declared(/*total=*/1000, /*declared=*/1000)); // exact match
    CHECK_FALSE(total_exceeds_declared(/*total=*/500, /*declared=*/1000));  // honest smaller total
    CHECK(total_exceeds_declared(/*total=*/1001, /*declared=*/1000));       // oversells past the cap
}

// ── Commit verification (collapsed to a single outcome) ─────────────────

TEST_CASE("verify_commit succeeds only when size and both hashes agree", "[server][upload]") {
    CHECK(verify_commit(/*actual=*/100, /*declared=*/100, "deadbeef", "deadbeef", "") ==
          CommitCheck::kOk);
    CHECK(verify_commit(100, 100, "DEADBEEF", "deadbeef", "") == CommitCheck::kOk); // case-insensitive
    CHECK(verify_commit(100, 100, "deadbeef", "deadbeef", "deadbeef") == CommitCheck::kOk);
}

TEST_CASE("verify_commit collapses EVERY failure mode to the same kMismatch outcome",
          "[server][upload]") {
    // Size OVER the cap alone.
    CHECK(verify_commit(/*actual=*/101, /*declared_max=*/100, "deadbeef", "deadbeef", "") ==
          CommitCheck::kMismatch);
    // Client-supplied hash mismatch alone.
    CHECK(verify_commit(100, 100, "deadbeef", "cafef00d", "") == CommitCheck::kMismatch);
    // Grant's expected hash mismatch alone (client hash matches computed).
    CHECK(verify_commit(100, 100, "deadbeef", "deadbeef", "cafef00d") == CommitCheck::kMismatch);
    // All three wrong at once — still just kMismatch, nothing more specific.
    CHECK(verify_commit(1000, 100, "aaaa", "bbbb", "cccc") == CommitCheck::kMismatch);
}

TEST_CASE("is_valid_expected_sha256 matches the MCP twin's ^[0-9a-f]{64}$ grammar",
          "[server][upload]") {
    const std::string valid(64, 'a');
    CHECK(is_valid_expected_sha256(valid));
    CHECK(is_valid_expected_sha256(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    // Absent is legal — the field is optional and the grant then carries no
    // expected hash (verify_commit skips that leg entirely).
    CHECK(is_valid_expected_sha256(""));

    // Everything the REST mint used to accept and persist verbatim. Each of
    // these is non-empty, so verify_commit's grant-expected leg would RUN
    // and could never match — turning the grant into one no commit can ever
    // satisfy, after it has already been redeemed.
    CHECK_FALSE(is_valid_expected_sha256("not a hash"));
    CHECK_FALSE(is_valid_expected_sha256(std::string(63, 'a'))); // too short
    CHECK_FALSE(is_valid_expected_sha256(std::string(65, 'a'))); // too long
    CHECK_FALSE(is_valid_expected_sha256(std::string(64, 'A'))); // uppercase
    CHECK_FALSE(is_valid_expected_sha256(std::string(64, 'g'))); // non-hex
    CHECK_FALSE(is_valid_expected_sha256("sha256:" + valid));
}

TEST_CASE("verify_commit treats declared_max_size as a CAP, not an equality requirement",
          "[server][upload]") {
    // The caller passes the grant's `declared_max_size`, which the frozen
    // protocol and `total_exceeds_declared` both describe as a maximum. An
    // equality test 422'd every honest upload smaller than the cap — and
    // because a commit mismatch cancels the session and deletes the blob
    // while the grant is already redeemed, that gave the agent no retry.
    CHECK(verify_commit(/*actual=*/1, /*declared_max=*/100, "deadbeef", "deadbeef", "") ==
          CommitCheck::kOk);
    CHECK(verify_commit(/*actual=*/99, /*declared_max=*/100, "deadbeef", "deadbeef", "deadbeef") ==
          CommitCheck::kOk);
    // A zero-byte upload under a non-zero cap is still a size-legal commit;
    // the hash legs remain the thing that decides whether it is the RIGHT
    // content.
    CHECK(verify_commit(/*actual=*/0, /*declared_max=*/100, "deadbeef", "deadbeef", "") ==
          CommitCheck::kOk);
    // Exactly at the cap stays legal — `>` not `>=`.
    CHECK(verify_commit(/*actual=*/100, /*declared_max=*/100, "deadbeef", "deadbeef", "") ==
          CommitCheck::kOk);
    // One byte over is not.
    CHECK(verify_commit(/*actual=*/101, /*declared_max=*/100, "deadbeef", "deadbeef", "") ==
          CommitCheck::kMismatch);
}

TEST_CASE("verify_commit treats an empty grant-expected hash as 'no constraint', not a match target",
          "[server][upload]") {
    // A grant minted with no expected_sha256 never fails on that leg.
    CHECK(verify_commit(100, 100, "deadbeef", "deadbeef", "") == CommitCheck::kOk);
}

// ── Destination-key derivation (server-facts only) ───────────────────────

TEST_CASE("is_valid_retention_class is a closed allowlist", "[server][upload]") {
    CHECK(is_valid_retention_class("standard"));
    CHECK(is_valid_retention_class("extended"));
    CHECK(is_valid_retention_class("transient"));
    CHECK_FALSE(is_valid_retention_class(""));
    CHECK_FALSE(is_valid_retention_class("Standard")); // case-sensitive closed set
    CHECK_FALSE(is_valid_retention_class("../../etc"));
}

TEST_CASE("derive_destination_key composes retention_class and grant_id only", "[server][upload]") {
    const std::string grant_id(32, 'a');
    auto key = derive_destination_key("standard", grant_id);
    CHECK(key == "standard/" + grant_id);
}

// ── Expiry (injected clock) ───────────────────────────────────────────────

TEST_CASE("is_expired: now == expires_at is still valid; now > expires_at is expired",
          "[server][upload]") {
    CHECK_FALSE(is_expired(/*expires_at=*/1000, /*now=*/999));
    CHECK_FALSE(is_expired(/*expires_at=*/1000, /*now=*/1000)); // exact boundary — NOT expired
    CHECK(is_expired(/*expires_at=*/1000, /*now=*/1001));       // one second after — expired
}

TEST_CASE("resolve_grant_ttl_secs defaults, clamps, and rejects a non-positive request",
          "[server][upload]") {
    CHECK(resolve_grant_ttl_secs(std::nullopt, 900, 900) == 900);
    CHECK(resolve_grant_ttl_secs(std::optional<std::int64_t>{300}, 900, 900) == 300);
    CHECK(resolve_grant_ttl_secs(std::optional<std::int64_t>{9999}, 900, 900) == 900); // clamped
    CHECK(resolve_grant_ttl_secs(std::optional<std::int64_t>{0}, 900, 900) == 900);    // -> default
    CHECK(resolve_grant_ttl_secs(std::optional<std::int64_t>{-5}, 900, 900) == 900);   // -> default
}

// ── Reason set + envelope ─────────────────────────────────────────────────

TEST_CASE("every one of the ten closed reasons has a distinct string and a pinned HTTP status",
          "[server][upload]") {
    const std::vector<std::pair<Reason, std::pair<std::string_view, int>>> expected = {
        {Reason::kGrantUnknown, {"grant_unknown", 401}},
        {Reason::kGrantAlreadyRedeemed, {"grant_already_redeemed", 409}},
        {Reason::kExpired, {"expired", 410}},
        {Reason::kOffsetMismatch, {"offset_mismatch", 409}},
        {Reason::kChunkTooLarge, {"chunk_too_large", 413}},
        {Reason::kSizeExceeded, {"size_exceeded", 413}},
        {Reason::kHashMismatch, {"hash_mismatch", 422}},
        {Reason::kSessionUnknown, {"session_unknown", 401}},
        {Reason::kSessionTerminal, {"session_terminal", 409}},
        {Reason::kTlsRequired, {"tls_required", 400}},
    };
    REQUIRE(expected.size() == 10);

    std::vector<std::string_view> seen_strings;
    for (const auto& [reason, want] : expected) {
        CHECK(reason_string(reason) == want.first);
        CHECK(reason_http_status(reason) == want.second);
        seen_strings.push_back(reason_string(reason));
    }
    // No two reasons collapse to the same wire string.
    for (std::size_t i = 0; i < seen_strings.size(); ++i)
        for (std::size_t j = i + 1; j < seen_strings.size(); ++j)
            CHECK(seen_strings[i] != seen_strings[j]);
}

TEST_CASE("error_envelope emits the frozen shape with the reason and any extra fields",
          "[server][upload]") {
    auto body = error_envelope(Reason::kOffsetMismatch, "offset mismatch",
                               nlohmann::json{{"offset", 42}});
    auto parsed = nlohmann::json::parse(body, nullptr, false);
    REQUIRE_FALSE(parsed.is_discarded());
    CHECK(parsed["error"]["code"] == 409);
    CHECK(parsed["error"]["message"] == "offset mismatch");
    CHECK(parsed["error"]["reason"] == "offset_mismatch");
    CHECK(parsed["error"]["offset"] == 42);
    CHECK(parsed["meta"]["api_version"] == "v1");
}

TEST_CASE("error_envelope with no extra fields still carries the base three", "[server][upload]") {
    auto body = error_envelope(Reason::kTlsRequired, "TLS is required");
    auto parsed = nlohmann::json::parse(body, nullptr, false);
    REQUIRE_FALSE(parsed.is_discarded());
    CHECK(parsed["error"]["code"] == 400);
    CHECK(parsed["error"]["reason"] == "tls_required");
    CHECK(parsed["meta"]["api_version"] == "v1");
}
