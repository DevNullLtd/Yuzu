/**
 * test_audit_token_hostile_bytes.cpp -- experiment CH-12 / UP-17 (#2146): what actually happens
 * when a caller-supplied field carrying hostile BYTES reaches an audit row. Kept as the
 * regression test for the observed behaviour (see the findings below).
 *
 * The claim under test (gate-4 unhappy-path register UP-17): `audit_token` / `log_token` pass
 * bytes >= 0x80, a 128-byte clip can split a multi-byte UTF-8 sequence, Postgres rejects invalid
 * UTF-8, so a `requested` audit row would fail to insert (the route answers 503
 * audit_unavailable) and denial / outcome rows (which ignore the insert result) would be lost
 * silently.
 *
 * The inputs below go through the REAL `AuditStore::log` on Postgres, the single writer every
 * route's audit closure ends in (`ServerImpl::audit_log` -> `AuthRoutes::audit_log` ->
 * `AuditStore::log`), and through the REAL shared execute core (`instruction_execute::run`) with
 * an audit hook backed by that store. Each case also prints a `CH12|` fact line so the observed
 * bytes are on record; the assertions then pin the behaviour so it cannot drift silently.
 *
 * FINDINGS (measured on PostgreSQL 18 before the token fix, then pinned here):
 *  - Invalid UTF-8 and NUL never fail an insert: `AuditStore::log_in_txn` scrubs every text
 *    column (sanitize_pg_text), so the `requested` row lands and no 503 audit_unavailable is
 *    reachable from hostile bytes. The execute core dispatched and every hook call became a row.
 *  - What WAS real: `log_token` passed U+2028 / U+2029 / U+0085 and the other C1 controls (valid
 *    UTF-8) into the stored detail and into log lines, where a splitlines()-style reader breaks
 *    a line on each; and `software_sync::audit_token`'s 128-byte clip cut a 3-byte character in
 *    half. Both are fixed at the shared helpers; these assertions are the regression net.
 *
 * PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set but broken.
 */

#include "audit_store.hpp"
#include "instruction_execute.hpp"
#include "software_sync_decision.hpp"
#include "utf8_sanitize.hpp"
#include "web_utils.hpp"

#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"
#include "test_instruction_execute_rig.hpp"

#include <yuzu/log_token.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::instruction_execute;
using namespace yuzu::test::instr_exec;
using yuzu::server::pg::PgPool;

namespace {

yuzu::test::PgTestTemplate hostile_tpl{"auditstore_ch12", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("ch12 template: audit store failed to migrate");
}};

constexpr std::string_view kU2028 = "\xE2\x80\xA8";
constexpr std::string_view kU2029 = "\xE2\x80\xA9";
constexpr std::string_view kU0085 = "\xC2\x85";
constexpr std::string_view kReplacement = "\xEF\xBF\xBD";

struct Hostile {
    const char* label;
    std::string bytes;
};

/// (a) a 3-byte character (EURO SIGN, E2 82 AC) whose lead byte is byte 127, so the 128-byte
/// clip of software_sync::audit_token lands inside it.
std::string straddle_128() { return std::string(127, 'a') + "\xE2\x82\xAC" + "tail"; }

/// (b) U+2028, U+2029, U+0085 and the rest of the C1 range, all as VALID UTF-8.
std::string line_separators() {
    std::string s = "x";
    s += kU2028;
    s += "y";
    s += kU2029;
    s += "z";
    s += kU0085;
    s += "w";
    for (unsigned c = 0x80; c <= 0x9F; ++c) {
        s += static_cast<char>(0xC2);
        s += static_cast<char>(c);
    }
    s += "end";
    return s;
}

/// (c) raw invalid UTF-8: stray continuation, overlong, surrogate, > U+10FFFF, truncated lead.
std::string invalid_utf8() {
    return std::string("a\xFF\xFE") + "b\xC0\xAF" + "c\xED\xA0\x80" + "d\xF5\x80\x80\x80" + "e\xE2\x82";
}

std::string hex(std::string_view s) {
    static constexpr char d[] = "0123456789abcdef";
    std::string out;
    for (const unsigned char c : s) {
        out += d[c >> 4];
        out += d[c & 0xF];
    }
    return out;
}

bool valid_utf8(std::string_view s) { return sanitize_utf8_strict(s) == s; }
bool has(std::string_view hay, std::string_view needle) {
    return hay.find(needle) != std::string_view::npos;
}
bool has_c1_or_separator(std::string_view s) {
    if (has(s, kU2028) || has(s, kU2029) || has(s, kU0085))
        return true;
    for (std::size_t i = 0; i + 1 < s.size(); ++i)
        if (static_cast<unsigned char>(s[i]) == 0xC2 &&
            static_cast<unsigned char>(s[i + 1]) >= 0x80 && static_cast<unsigned char>(s[i + 1]) <= 0x9F)
            return true;
    return false;
}

void fact(const std::string& line) { std::cout << "CH12|" << line << std::endl; }

AuditEvent event_with(const std::string& detail, const std::string& target_id = {},
                      const std::string& principal = "alice") {
    AuditEvent e;
    e.principal = principal;
    e.principal_role = "admin";
    e.action = "ch12.probe";
    e.target_type = "probe";
    e.target_id = target_id;
    e.detail = detail;
    e.result = "requested";
    return e;
}

} // namespace

// -------------------------------------------------------------------------------------------
// The helpers on their own (no database).
// -------------------------------------------------------------------------------------------

TEST_CASE("CH-12: the shared tokens emit valid UTF-8 and fold every line separator (helper level)",
          "[ch12][audit_token]") {
    // The 128-byte clip (software_sync::audit_token) on a straddling 3-byte character.
    const auto clipped = software_sync::audit_token(straddle_128());
    fact("clip128 straddle: valid_utf8=" + std::to_string(valid_utf8(clipped)) +
         " size=" + std::to_string(clipped.size()) + " tail_hex=" + hex(clipped.substr(clipped.size() - 8)));
    CHECK(valid_utf8(clipped));
    // Cut on a code point boundary: the whole character is dropped, never half of it kept.
    CHECK(clipped == std::string(127, 'a') + "...");

    // The same clip landing at every interior offset of a 2-byte (U+00E9), 3-byte (U+20AC) and
    // 4-byte (U+1F600) character: the whole character is dropped, never half of it kept.
    for (const std::string& ch : {std::string("\xC3\xA9"), std::string("\xE2\x82\xAC"),
                                 std::string("\xF0\x9F\x98\x80")}) {
        for (std::size_t inside = 1; inside < ch.size(); ++inside) {
            INFO("char bytes=" << ch.size() << " cut after " << inside << " byte(s)");
            const std::string in = std::string(128 - inside, 'a') + ch + "tail";
            const auto t = software_sync::audit_token(in);
            CHECK(valid_utf8(t));
            CHECK(t == std::string(128 - inside, 'a') + "...");
        }
        // The character ends exactly on the cap: kept whole.
        const auto kept = software_sync::audit_token(std::string(128 - ch.size(), 'a') + ch + "tail");
        CHECK(kept == std::string(128 - ch.size(), 'a') + ch + "...");
    }

    // A character that ENDS exactly on the cap survives whole.
    const std::string fits = std::string(125, 'a') + "\xE2\x82\xAC" + "tail";
    CHECK(software_sync::audit_token(fits) == std::string(125, 'a') + "\xE2\x82\xAC" + "...");

    for (const auto& h : {Hostile{"separators", line_separators()},
                          Hostile{"invalid", invalid_utf8()}}) {
        INFO(h.label);
        const auto a = audit_token(h.bytes);
        const auto l = ::yuzu::log_token(h.bytes);
        fact(std::string(h.label) + " audit_token=" + hex(a) + " valid_utf8=" + std::to_string(valid_utf8(a)));
        CHECK(a == l); // audit_token forwards to the one shared mapping
        CHECK(valid_utf8(a));
        CHECK_FALSE(has_c1_or_separator(a));
    }

    // Ordinary non-ASCII text still passes through (the neutraliser is not an ASCII filter).
    CHECK(audit_token("caf\xC3\xA9") == "caf\xC3\xA9");
    CHECK(audit_token("\xE2\x82\xAC") == "\xE2\x82\xAC");
}

// -------------------------------------------------------------------------------------------
// Real Postgres: the writer every route ends in.
// -------------------------------------------------------------------------------------------

TEST_CASE("CH-12: hostile bytes through the real AuditStore insert never lose the row",
          "[ch12][pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, hostile_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());

    const std::vector<Hostile> cases = {
        {"straddle_clip128_token", "definition=" + software_sync::audit_token(straddle_128())},
        {"straddle_raw_cut_at_128", straddle_128().substr(0, 128)}, // the pre-fix clip: half a character
        {"separators_token", "definition=" + audit_token(line_separators())},
        {"invalid_token", "definition=" + audit_token(invalid_utf8())},
        {"invalid_raw", "definition=" + invalid_utf8()},
        {"nul_raw", std::string("definition=a\0b", 14)},
    };

    std::size_t expected_rows = 0;
    for (const auto& c : cases) {
        INFO(c.label);
        // detail, target_id AND principal all carry the hostile bytes: every text column.
        const bool inserted = store.log(event_with(c.bytes, c.bytes, c.bytes));
        fact(std::string(c.label) + " input_hex=" + hex(c.bytes) + " input_valid_utf8=" +
             std::to_string(valid_utf8(c.bytes)) + " inserted=" + std::to_string(inserted));
        CHECK(inserted);
        if (inserted)
            ++expected_rows;
    }

    auto rows = store.query();
    REQUIRE(rows.has_value());
    CHECK(rows->size() == expected_rows);
    // The valid_utf8(stored) checks below are guaranteed by AuditStore's own column scrubbing
    // (invalid UTF-8 and NUL become U+FFFD before the insert), so they hold for the RAW cases too
    // and say nothing about the token fix. What they pin is "no hostile byte loses or corrupts a
    // row". The token fix itself (valid, folded output, whole-character clip) is pinned by the
    // non-PG helper-level cases above.
    for (const auto& r : *rows) {
        fact("stored detail_hex=" + hex(r.detail) + " valid_utf8=" + std::to_string(valid_utf8(r.detail)) +
             " c1_or_separator=" + std::to_string(has_c1_or_separator(r.detail)));
        CHECK(valid_utf8(r.detail));
        CHECK(valid_utf8(r.target_id));
        CHECK(valid_utf8(r.principal));
        CHECK(r.detail.find('\0') == std::string::npos);
    }
}

TEST_CASE("CH-12: an invalid byte is stored as U+FFFD, a valid character is stored byte-identically",
          "[ch12][pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, hostile_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());

    REQUIRE(store.log(event_with("ok=caf\xC3\xA9 bad=\xFF end")));
    auto rows = store.query();
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].detail == "ok=caf\xC3\xA9 bad=" + std::string(kReplacement) + " end");
}

// -------------------------------------------------------------------------------------------
// Real execute core + a hook backed by the real store: the 503 / lost-row claim, end to end.
// -------------------------------------------------------------------------------------------

TEST_CASE("CH-12: a hostile definition id neither 503s the execute core nor loses an audit row",
          "[ch12][pg][instruction_execute]") {
    YUZU_REQUIRE_PG_DB_TPL(db, hostile_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());

    const std::vector<Hostile> ids = {
        {"straddle", straddle_128().substr(0, 128)},
        {"separators", line_separators()},
        {"invalid", invalid_utf8()},
    };

    // The "invalid" row below must take the step-0 refusal arm, or its exact-row assertion is moot.
    CHECK(definition_id_is_malformed(invalid_utf8()));

    std::size_t hook_calls = 0, hook_failures = 0, min_rows = 0;
    for (const auto& h : ids) {
        const std::size_t calls_before = hook_calls;
        INFO(h.label);
        Rig r;
        r.defs[h.bytes] = make_def(h.bytes);
        AuditHook hook = [&](std::string_view result, const std::string& detail) -> bool {
            ++hook_calls;
            AuditEvent e;
            e.principal = "alice";
            e.principal_role = "admin";
            e.action = "instruction.execute";
            e.target_type = "instruction";
            e.target_id = h.bytes;
            e.detail = detail;
            e.result = std::string(result);
            const bool ok = store.log(e);
            if (!ok)
                ++hook_failures;
            return ok;
        };
        auto out = run(r.request(h.bytes, json::object(), make_caller("alice", true)), r.ports(), hook);
        const auto* ref = as_refusal(out);
        fact(std::string(h.label) + " outcome=" + (ref ? ("refusal:" + ref->reason) : "not-a-refusal"));
        const bool audit_503 = (ref != nullptr) && (ref->kind == RefusalKind::kAuditUnavailable);
        CHECK_FALSE(audit_503);
        if (definition_id_is_malformed(h.bytes)) {
            // Invalid UTF-8 is refused at step 0 (unhappy p4-3): a 400 `invalid_definition_id`,
            // never a retryable 503 from a Postgres 22021, never a dispatch; the ONE `denied` row
            // is durable even though its target_id is raw (sanitize_pg_text repairs it).
            REQUIRE(ref);
            CHECK(ref->reason == "invalid_definition_id");
            CHECK(r.calls.empty());
            CHECK(hook_calls - calls_before == 1); // exactly the ONE `denied` row, no more
            min_rows += 1;
        } else {
            CHECK(r.calls.size() == 1); // the dispatch went ahead: the `requested` row was durable
            min_rows += 2;              // `requested` and the outcome row
        }
    }
    CHECK(hook_calls >= min_rows);
    CHECK(hook_failures == 0);

    auto rows = store.query();
    REQUIRE(rows.has_value());
    CHECK(rows->size() == hook_calls); // every hook call became a stored row: none silently lost
    for (const auto& row : *rows) {
        fact("stored result=" + row.result + " detail_hex=" + hex(row.detail));
        CHECK(valid_utf8(row.detail));
        CHECK_FALSE(has_c1_or_separator(row.detail));
    }
}
