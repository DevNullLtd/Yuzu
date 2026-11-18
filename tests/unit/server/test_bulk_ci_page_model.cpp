/// @file test_bulk_ci_page_model.cpp
/// The pure model behind GET /api/v1/hardware-ci and the MCP list_hardware_ci_records tool:
/// parameter parsing (REST clamps, MCP refuses), the cursor codec (tamper, filter binding), the
/// keyset walk under every scope shape (TOP, engaged-empty, pushed-down, over the ceiling) with
/// the EXACT returned set asserted against an in-memory fake store, and the JSON row shape.
/// No Postgres: the store is reached through the Reader closure.

#include "hardware_ci_page_model.hpp"

#include "hardware_list_model.hpp"
#include "list_keyset.hpp"
#include "model_param_helpers.hpp"
#include "software_catalogue_model.hpp" // kScopePushdownMaxIds, the sibling surface's ceiling
#include "test_fake_ci_keyset_store.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
namespace hcp = yuzu::server::hardware_ci_page;
using nlohmann::json;

namespace {

using yuzu::server::test::FakeCiKeysetStore;
using FakeStore = FakeCiKeysetStore;
using yuzu::server::test::make_ci_record;

DeviceCiRecord make_record(std::string id) {
    return make_ci_record(std::move(id));
}

std::vector<std::string> ids_of(const hcp::Page& p) {
    std::vector<std::string> out;
    for (const auto& r : p.rows)
        out.push_back(r.agent_id);
    return out;
}

// Walks every page by following next_cursor; returns the concatenated ids.
std::vector<std::string> walk(FakeStore& store, hcp::Request rq, const authz::VisibleSet& scope,
                              int* pages = nullptr) {
    std::vector<std::string> all;
    int n = 0;
    for (;;) {
        const auto page = hcp::read_page(store.reader(), rq, scope, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(page.has_value());
        ++n;
        REQUIRE(n < 1000); // a runaway walk is a defect, not a long test
        for (const auto& id : ids_of(*page))
            all.push_back(id);
        if (page->next_cursor.empty())
            break;
        rq.cursor = page->next_cursor;
    }
    if (pages)
        *pages = n;
    return all;
}

hcp::Params params(std::initializer_list<std::pair<const std::string, std::string>> kv) {
    return hcp::Params(kv.begin(), kv.end());
}

} // namespace

// ── parameters ───────────────────────────────────────────────────────────────

TEST_CASE("hardware ci page: REST parameters default, clamp and refuse", "[hardware_ci_page][params]") {
    SECTION("defaults") {
        const auto r = hcp::parse_params({});
        REQUIRE(r.has_value());
        CHECK(r->limit == 100);
        CHECK(r->agent_id.empty());
        CHECK(r->cursor.empty());
    }
    SECTION("limit is clamped into [1, 1000]") {
        CHECK(hcp::parse_params(params({{"limit", "0"}}))->limit == 1);
        CHECK(hcp::parse_params(params({{"limit", "-7"}}))->limit == 1);
        CHECK(hcp::parse_params(params({{"limit", "1000"}}))->limit == 1000);
        CHECK(hcp::parse_params(params({{"limit", "1001"}}))->limit == 1000);
        CHECK(hcp::parse_params(params({{"limit", "99999999999"}}))->limit == 1000);
    }
    // Kills: returning a 400 for an integer that overflows int64 (the documented rule is that an
    // out-of-range integer clamps), and clamping the wrong way for the sign.
    SECTION("an integer too large for 64 bits clamps by its sign") {
        struct Row {
            const char* text;
            int expect;
        };
        for (const Row& row : {Row{"9223372036854775807", 1000}, Row{"9223372036854775808", 1000},
                               Row{"-9223372036854775808", 1}, Row{"-9223372036854775809", 1},
                               Row{"-99999999999999999999", 1}, Row{"99999999999999999999999", 1000},
                               Row{"0", 1}, Row{"-0", 1}, Row{"007", 7}}) {
            INFO(row.text);
            const auto r = hcp::parse_params(params({{"limit", row.text}}));
            REQUIRE(r.has_value());
            CHECK(r->limit == row.expect);
        }
    }
    SECTION("a limit that is not one decimal integer is refused") {
        for (const char* bad : {"abc", "1.5", "10x", "+5", " 5", "5 ", "-", "--5", "1e3", "0x10",
                                "-abc", "99999999999999999999x"})
            CHECK_FALSE(hcp::parse_params(params({{"limit", bad}})).has_value());
    }
    SECTION("a repeated key keeps its first value; an unknown key is ignored") {
        const auto r = hcp::parse_params(
            params({{"limit", "7"}, {"limit", "9"}, {"agent_id", "a"}, {"agent_id", "b"}, {"zzz", "1"}}));
        REQUIRE(r.has_value());
        CHECK(r->limit == 7);
        CHECK(r->agent_id == "a");
    }
    SECTION("agent_id and cursor hygiene") {
        CHECK_FALSE(hcp::parse_params(params({{"agent_id", "a\nb"}})).has_value());
        CHECK_FALSE(hcp::parse_params(params({{"agent_id", std::string(257, 'x')}})).has_value());
        CHECK(hcp::parse_params(params({{"agent_id", std::string(256, 'x')}})).has_value());
        CHECK_FALSE(hcp::parse_params(params({{"agent_id", "bad\xFF"}})).has_value());
        CHECK_FALSE(hcp::parse_params(params({{"agent_id", std::string("a\0b", 3)}})).has_value());
        CHECK_FALSE(hcp::parse_params(params({{"cursor", std::string(2049, 'c')}})).has_value());
        // An empty cursor is the first page and an empty limit is the default.
        const auto r = hcp::parse_params(params({{"cursor", ""}, {"limit", ""}}));
        REQUIRE(r.has_value());
        CHECK(r->agent_id.empty());
        CHECK(r->cursor.empty());
        CHECK(r->limit == 100);
    }
    // Kills: reading a present-but-empty agent_id as "every device" (the page of OTHER devices'
    // records a client that interpolated a missing id would then attach to the wrong device), and
    // REST and MCP refusing it in different words.
    SECTION("a present-but-empty agent_id is refused, with the MCP wording") {
        for (const hcp::Params& p : {params({{"agent_id", ""}}), params({{"agent_id", ""}, {"agent_id", "x"}}),
                                     params({{"agent_id", ""}, {"limit", "5"}})}) {
            const auto r = hcp::parse_params(p);
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == "agent_id must be a non-empty string when given");
        }
        const auto mcp = hcp::request_from_args(json{{"agent_id", ""}});
        REQUIRE_FALSE(mcp.has_value());
        CHECK(mcp.error().message == "agent_id must be a non-empty string when given");
        // a named id is still fine, and an absent key is the whole fleet
        CHECK(hcp::parse_params(params({{"agent_id", "x"}}))->agent_id == "x");
        CHECK(hcp::parse_params(params({{"limit", "5"}}))->agent_id.empty());
    }
    // Kills: judging the agent_id and the cursor in an order that gives a NUL or non-UTF-8 cursor
    // a different message from every other refused cursor (it used to read "invalid parameter
    // encoding"), so a caller and the audit trail saw two cursor refusals.
    SECTION("a cursor that is not valid text reads as every other refused cursor") {
        const std::string expected = "invalid cursor; restart from the first page";
        for (const std::string& bad : {std::string("a\0b", 3), std::string("bad\xFF"), std::string("\xC0\x80"),
                                       std::string(2049, 'c')}) {
            INFO(bad.size());
            const auto r = hcp::parse_params(params({{"cursor", bad}}));
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == expected);
            // even beside an agent_id that is itself bad: the cursor is judged first
            const auto both = hcp::parse_params(params({{"cursor", bad}, {"agent_id", "a\nb"}}));
            REQUIRE_FALSE(both.has_value());
            CHECK(both.error() == expected);
        }
        CHECK(hcp::parse_params(params({{"agent_id", "a\nb"}})).error() == "invalid agent_id");
        CHECK(hcp::parse_params(params({{"agent_id", "bad\xFF"}})).error() == "invalid parameter encoding");
    }
}

TEST_CASE("hardware ci page: MCP arguments are refused, not clamped", "[hardware_ci_page][params]") {
    // The MCP default page is 20 (each page lands in an agent's context); REST's stays 100.
    CHECK(hcp::request_from_args(json::object())->limit == 20);
    CHECK(hcp::request_from_args(json(nullptr))->limit == 20);
    CHECK(hcp::kMcpDefaultLimit == 20);
    CHECK(hcp::Request{}.limit == 100);
    CHECK(hcp::parse_params({})->limit == 100);
    // Kills: reading arguments that are not an object as "no arguments", which is a default
    // request for the whole fleet.
    for (const json& not_object : {json::array(), json("x"), json(5), json(true), json(1.5)}) {
        INFO(not_object.dump());
        const auto r = hcp::request_from_args(not_object);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().message == "arguments must be a JSON object");
    }
    CHECK(hcp::request_from_args(json{{"limit", 1}})->limit == 1);
    CHECK(hcp::request_from_args(json{{"limit", 1000}})->limit == 1000);
    CHECK_FALSE(hcp::request_from_args(json{{"limit", 0}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", 1001}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", -1}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", 1.5}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", "5"}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", UINT64_MAX}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", static_cast<std::uint64_t>(INT64_MAX)}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", static_cast<std::uint64_t>(INT64_MAX) + 1}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"limit", INT64_MIN}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"agent_id", 5}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"agent_id", ""}}).has_value());
    // The fault kind: a cursor refused before decoding (over-long, or not valid text) is
    // kCursorRefused, with the one cursor message; every other refusal is kOther, including a
    // wrongly typed cursor and the other two text checks.
    {
        const auto too_long = hcp::request_from_args(json{{"cursor", std::string(hcp::kCursorMaxBytes + 1, 'x')}});
        REQUIRE_FALSE(too_long.has_value());
        CHECK(too_long.error().fault == hcp::ArgFault::kCursorRefused);
        CHECK(too_long.error().message == "invalid cursor; restart from the first page");
        // A NUL or non-UTF-8 cursor is the same refusal (message, fault), even beside a bad agent_id.
        for (const std::string& bad : {std::string("a\0b", 3), std::string("bad\xFF")}) {
            for (const json& args : {json{{"cursor", bad}}, json{{"cursor", bad}, {"agent_id", "a\nb"}}}) {
                const auto r = hcp::request_from_args(args);
                REQUIRE_FALSE(r.has_value());
                CHECK(r.error().fault == hcp::ArgFault::kCursorRefused);
                CHECK(r.error().message == "invalid cursor; restart from the first page");
            }
        }
        CHECK(hcp::request_from_args(json{{"cursor", std::string(hcp::kCursorMaxBytes, 'x')}}).has_value());
        for (const json& other : {json{{"cursor", 7}}, json{{"agent_id", ""}}, json{{"agent_id", "a\nb"}},
                                  json{{"limit", 0}}}) {
            INFO(other.dump());
            const auto r = hcp::request_from_args(other);
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error().fault == hcp::ArgFault::kOther);
        }
    }
    CHECK_FALSE(hcp::request_from_args(json{{"agent_id", "a\tb"}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"cursor", 5}}).has_value());
    CHECK_FALSE(hcp::request_from_args(json{{"cursor", std::string(2049, 'c')}}).has_value());
    CHECK(hcp::request_from_args(json{{"unknown", true}}).has_value());
}

// ── cursors ──────────────────────────────────────────────────────────────────

namespace {

const char kSepChar = '\x1f';

// A token built from a raw payload, as a hostile client would.
std::string forge_token(const std::string& fp, const std::string& payload) {
    return "h1:" + fp + ":" + yuzu::server::keyset::b64url_encode(payload);
}

} // namespace

TEST_CASE("hardware ci page: cursor round-trips and refuses tampering", "[hardware_ci_page][cursor]") {
    const hcp::Request rq;
    const std::string fp = hcp::filter_fingerprint(rq);
    const hcp::Position at{"agent-42"};
    const std::string tok = hcp::encode_cursor(at, fp);

    const auto back = hcp::decode_cursor(tok, fp);
    REQUIRE(back.has_value());
    CHECK(back->after == "agent-42");

    SECTION("the filter fingerprint is the agent_id filter alone, byte for byte") {
        // Pinned: a later change that adds a filter must not invalidate cursors already issued, so
        // the fingerprint of today's only filter must not move.
        CHECK(fp == yuzu::server::model_detail::fnv1a_hex16("agent_id="));
        hcp::Request named;
        named.agent_id = "dev-9";
        CHECK(hcp::filter_fingerprint(named) == yuzu::server::model_detail::fnv1a_hex16("agent_id=dev-9"));
    }
    SECTION("malformed tokens") {
        for (const std::string& bad :
             {std::string("garbage"), std::string(""), std::string("h1:"), std::string("h1::"),
              std::string("h2:") + tok.substr(3), std::string("d2:") + tok.substr(3),
              std::string("H1:") + tok.substr(3), tok + "A", tok + "=", tok.substr(0, tok.size() - 1),
              tok + ":x", std::string("h1:ZZZZZZZZZZZZZZZZ:") + tok.substr(20),
              tok.substr(0, 20) + "!" + tok.substr(21)}) {
            INFO(bad);
            const auto r = hcp::decode_cursor(bad, fp);
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == hcp::CursorError::kMalformed);
        }
    }
    // Each payload below is one hostile spelling of a position. Every one must come back as an
    // error and none may crash or read past the payload.
    SECTION("a payload that lies about a field length, or carries a bad id") {
        const std::string sep(1, kSepChar);
        const auto refused = [&](const std::string& payload) {
            const auto r = hcp::decode_cursor(forge_token(fp, payload), fp);
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == hcp::CursorError::kMalformed);
        };
        // the well-formed spelling of the same shape IS accepted (so the cases below fail for the
        // defect they name, not for the harness)
        REQUIRE(hcp::decode_cursor(forge_token(fp, "5:agent" + sep), fp).has_value());

        refused("");                           // empty payload
        refused("0:" + sep);                   // zero-length after: never minted
        refused("5:agent");                    // missing trailing separator
        refused("6:agent" + sep);              // length exactly equal to what remains
        refused("7:agent" + sep);              // length past what remains
        refused("4:agent" + sep);              // length one short: the separator is not where it says
        refused("5:agent" + sep + "X");        // a byte after the separator
        refused("99:agent" + sep);
        refused("9223372036854775807:a" + sep); // INT64_MAX
        refused("9223372036854775808:a" + sep); // INT64_MAX + 1
        refused("18446744073709551616:a" + sep); // 2^64
        refused("99999999999999999999999:a" + sep);
        refused("-1:a" + sep);
        refused("+1:a" + sep);
        refused("05:agent" + sep);             // leading zero: a second spelling of the position
        refused("x:agent" + sep);
        refused(":" + sep);
        refused("3:a" + std::string(1, '\0') + "b" + sep); // NUL inside after
    }
    // `after` reaches only the bound SQL parameter of the keyset query, never a log, audit or
    // response string, so it is held to what a bound text parameter needs (strict UTF-8, no NUL,
    // at most 256 bytes) and NOT to the audit-trail floor the `agent_id` request filter meets.
    // `encode_cursor` mints a token from any stored id, so an id with a control byte must decode.
    SECTION("a stored id with a byte below 0x20 or DEL decodes: the decoder accepts what the encoder mints") {
        const std::string sep(1, kSepChar);
        for (const std::string& id : {std::string("a\x01" "b"), std::string("a\nb"), std::string("a\tb"),
                                      std::string("a\x1f" "b"), std::string("a\x7f" "b"),
                                      std::string("\x01")}) {
            INFO(id.size());
            const std::string minted = hcp::encode_cursor(hcp::Position{id}, fp);
            const auto back_id = hcp::decode_cursor(minted, fp);
            REQUIRE(back_id.has_value());
            CHECK(back_id->after == id);
        }
        // and a hostile spelling of one is accepted exactly like the encoder's own
        CHECK(hcp::decode_cursor(forge_token(fp, "3:a\x01" "b" + sep), fp).has_value());
    }
    SECTION("invalid UTF-8 in the id") {
        const std::string sep(1, kSepChar);
        for (const std::string& bad : {std::string("3:a\xFF" "b"), std::string("2:\xC3("),
                                      std::string("3:\xE2\x82" "x"), std::string("2:\xC0\x80")}) {
            INFO(bad);
            CHECK(hcp::decode_cursor(forge_token(fp, bad + sep), fp).error() == hcp::CursorError::kMalformed);
        }
    }
    // Kills: re-adding the retired `skip` field (or any second field) to the payload.
    SECTION("a second field, the retired skip form, is refused") {
        const std::string sep(1, kSepChar);
        CHECK(hcp::decode_cursor(forge_token(fp, "5:agent" + sep + "1:0" + sep), fp).error() ==
              hcp::CursorError::kMalformed);
        CHECK(hcp::decode_cursor(forge_token(fp, "5:agent" + sep + "1:7" + sep), fp).error() ==
              hcp::CursorError::kMalformed);
        CHECK(hcp::decode_cursor(forge_token(fp, "5:agent" + sep + "1:0" + sep + "1:0" + sep), fp).error() ==
              hcp::CursorError::kMalformed);
    }
    SECTION("the id length bound: 256 bytes accepted, 257 refused") {
        const std::string sep(1, kSepChar);
        const std::string ok(256, 'x');
        const auto good = hcp::decode_cursor(forge_token(fp, "256:" + ok + sep), fp);
        REQUIRE(good.has_value());
        CHECK(good->after == ok);
        CHECK(forge_token(fp, "256:" + ok + sep).size() <= hcp::kCursorMaxBytes);
        CHECK(hcp::decode_cursor(forge_token(fp, "257:" + ok + "x" + sep), fp).error() ==
              hcp::CursorError::kMalformed);
    }
    // The decoder's own length check is defence in depth: no WELL-FORMED token can reach the cap
    // (an id is at most 256 bytes, so the longest valid token is a few hundred bytes), and a token
    // longer than the cap is malformed on its shape alone. What is observable is that every such
    // token is refused, and that both parsers enforce the cap at exactly 2048.
    SECTION("no valid token reaches the cursor cap, and an over-cap token is refused everywhere") {
        const std::string longest = hcp::encode_cursor(hcp::Position{std::string(256, 'x')}, fp);
        CHECK(longest.size() < hcp::kCursorMaxBytes);
        CHECK(hcp::decode_cursor(longest, fp).has_value());
        const std::string head = "h1:" + fp + ":";
        for (const std::size_t total : {hcp::kCursorMaxBytes, hcp::kCursorMaxBytes + 1}) {
            INFO(total);
            const std::string padded = head + std::string(total - head.size(), 'A');
            REQUIRE(padded.size() == total);
            const auto r = hcp::decode_cursor(padded, fp);
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == hcp::CursorError::kMalformed);
        }
        const std::string at_cap = std::string(hcp::kCursorMaxBytes, 'A');
        const std::string over_cap = std::string(hcp::kCursorMaxBytes + 1, 'A');
        // 2048 passes the parse, 2049 does not
        CHECK(hcp::parse_params(params({{"cursor", at_cap}})).has_value());
        CHECK_FALSE(hcp::parse_params(params({{"cursor", over_cap}})).has_value());
        json args{{"cursor", at_cap}};
        CHECK(hcp::request_from_args(args).has_value());
        args["cursor"] = over_cap;
        CHECK_FALSE(hcp::request_from_args(args).has_value());
    }
    // Kills: dropping the re-encode comparison, which would accept a second spelling of a position.
    SECTION("a non-canonical base64url tail is a second spelling and is refused") {
        const std::string sep(1, kSepChar);
        const std::string base = forge_token(fp, "5:agent" + sep); // 8 bytes: 2 spare bits in the last char
        REQUIRE(hcp::decode_cursor(base, fp).has_value());
        const std::string alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        int variants = 0;
        for (const char c : alphabet) {
            if (c == base.back())
                continue;
            std::string t = base;
            t.back() = c;
            const auto r = hcp::decode_cursor(t, fp);
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error() == hcp::CursorError::kMalformed);
            ++variants;
        }
        CHECK(variants == 63);
    }
    SECTION("malformed is reported before a filter mismatch") {
        hcp::Request other;
        other.agent_id = "agent-42";
        const std::string other_fp = hcp::filter_fingerprint(other);
        CHECK(hcp::decode_cursor(tok + "A", other_fp).error() == hcp::CursorError::kMalformed);
    }
    SECTION("a cursor is bound to the agent_id filter") {
        hcp::Request other;
        other.agent_id = "agent-42";
        const auto r = hcp::decode_cursor(tok, hcp::filter_fingerprint(other));
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == hcp::CursorError::kFilterMismatch);
        // a different limit is not a different filter
        hcp::Request lim;
        lim.limit = 5;
        CHECK(hcp::filter_fingerprint(lim) == fp);
    }
}

// ── the keyset walk ──────────────────────────────────────────────────────────

TEST_CASE("hardware ci page: an unfiltered walk visits every device exactly once, in order",
          "[hardware_ci_page][walk]") {
    FakeStore store;
    for (int i = 0; i < 7; ++i)
        store.add("dev-" + std::to_string(i));

    SECTION("pages of 3 over 7 devices") {
        hcp::Request rq;
        rq.limit = 3;
        int pages = 0;
        const auto all = walk(store, rq, std::nullopt, &pages);
        CHECK(pages == 3);
        CHECK(all == std::vector<std::string>{"dev-0", "dev-1", "dev-2", "dev-3", "dev-4", "dev-5", "dev-6"});
    }
    SECTION("an exact multiple ends on a page with no cursor, not on an empty extra page") {
        FakeStore six;
        for (int i = 0; i < 6; ++i)
            six.add("d" + std::to_string(i));
        hcp::Request rq;
        rq.limit = 3;
        int pages = 0;
        const auto all = walk(six, rq, std::nullopt, &pages);
        CHECK(pages == 2);
        CHECK(all.size() == 6);
    }
    SECTION("one page larger than the data carries no cursor") {
        hcp::Request rq;
        rq.limit = 1000;
        const auto page = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(page.has_value());
        CHECK(page->rows.size() == 7);
        CHECK(page->next_cursor.empty());
    }
    SECTION("an empty store is an empty page") {
        FakeStore none;
        const auto page = hcp::read_page(none.reader(), {}, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(page.has_value());
        CHECK(page->rows.empty());
        CHECK(page->next_cursor.empty());
    }
    // A stored id carrying a control byte can land on a page boundary. The cursor minted from it
    // must decode, or the walk would hit a deterministic 400 there and never finish.
    SECTION("a stored id with a control byte at a page boundary does not wedge the walk") {
        FakeStore odd;
        const std::string boundary = "q\x01r";
        for (const std::string& id : {std::string("p"), boundary, std::string("s")})
            odd.add(id);
        hcp::Request rq;
        rq.limit = 2; // page 1 = {p, q\x01r}: the cursor is minted FROM the control-byte id
        int pages = 0;
        const auto all = walk(odd, rq, std::nullopt, &pages);
        CHECK(pages == 2);
        CHECK(all == std::vector<std::string>{"p", boundary, "s"});
        const auto first = hcp::read_page(odd.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(first.has_value());
        const auto pos = hcp::decode_cursor(first->next_cursor, hcp::filter_fingerprint(rq));
        REQUIRE(pos.has_value());
        CHECK(pos->after == boundary);
    }
    SECTION("the cursor resumes after a row inserted behind it, without a duplicate") {
        hcp::Request rq;
        rq.limit = 3;
        auto first = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(first.has_value());
        store.add("dev-05"); // sorts between dev-0 and dev-1: behind the cursor
        rq.cursor = first->next_cursor;
        const auto second = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(second.has_value());
        const auto served = ids_of(*first);
        for (const auto& id : ids_of(*second))
            CHECK(std::ranges::find(served, id) == served.end());
    }
}

TEST_CASE("hardware ci page: the agent_id filter reads one device", "[hardware_ci_page][walk]") {
    FakeStore store;
    for (const char* id : {"a", "b", "c"})
        store.add(id);
    hcp::Request rq;
    rq.agent_id = "b";
    const auto page = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
    REQUIRE(page.has_value());
    CHECK(ids_of(*page) == std::vector<std::string>{"b"});
    CHECK(page->next_cursor.empty());

    rq.agent_id = "nope";
    const auto none = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
    REQUIRE(none.has_value());
    CHECK(none->rows.empty());
    CHECK_FALSE(none->target_denied);
}

TEST_CASE("hardware ci page: scope confines the exact set returned", "[hardware_ci_page][scope]") {
    FakeStore store;
    for (const char* id : {"a", "b", "c", "d", "e", "f"})
        store.add(id);

    SECTION("a pushed-down scope returns exactly the in-scope devices that exist") {
        const authz::VisibleSet scope = std::unordered_set<std::string>{"a", "c", "e", "ghost"};
        hcp::Request rq;
        rq.limit = 2;
        const auto all = walk(store, rq, scope);
        CHECK(all == std::vector<std::string>{"a", "c", "e"});
        // the scope reached SQL as agent_ids on every read
        for (const auto& q : store.queries) {
            REQUIRE(q.agent_ids.has_value());
            CHECK(std::set<std::string>(q.agent_ids->begin(), q.agent_ids->end()) ==
                  std::set<std::string>{"a", "c", "e", "ghost"});
        }
    }
    SECTION("an engaged-empty scope returns nothing") {
        const auto page = hcp::read_page(store.reader(), {}, authz::deny_all(), nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(page.has_value());
        CHECK(page->rows.empty());
        CHECK(page->next_cursor.empty());
        REQUIRE(store.queries.size() == 1);
        CHECK(store.queries[0].agent_ids.has_value());
        CHECK(store.queries[0].agent_ids->empty());
    }
    SECTION("a named device outside the scope is answered without a store read") {
        const authz::VisibleSet scope = std::unordered_set<std::string>{"a"};
        hcp::Request rq;
        rq.agent_id = "b";
        const auto page = hcp::read_page(store.reader(), rq, scope, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(page.has_value());
        CHECK(page->rows.empty());
        CHECK(page->target_denied);
        CHECK(store.reads == 0);
    }
    SECTION("a named device inside the scope is served") {
        const authz::VisibleSet scope = std::unordered_set<std::string>{"b"};
        hcp::Request rq;
        rq.agent_id = "b";
        const auto page = hcp::read_page(store.reader(), rq, scope, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(page.has_value());
        CHECK(ids_of(*page) == std::vector<std::string>{"b"});
        CHECK_FALSE(page->target_denied);
    }
}

namespace {

// A scope of exactly `n` ids: the real ids first, then padding that matches no stored device.
authz::VisibleSet scope_of_size(const std::set<std::string>& real, std::size_t n) {
    std::unordered_set<std::string> ids(real.begin(), real.end());
    for (int i = 0; ids.size() < n; ++i)
        ids.insert("pad-" + std::to_string(i));
    return ids;
}

FakeStore forty_devices(std::set<std::string>& in_scope_real) {
    FakeStore store;
    for (int i = 0; i < 40; ++i) {
        char buf[16];
        std::snprintf(buf, sizeof buf, "dev-%03d", i);
        store.add(buf);
        if (i % 3 == 0)
            in_scope_real.insert(buf);
    }
    return store;
}

} // namespace

static_assert(hcp::kMaxPushdownScopeIds == 10000);

// This model keeps its own copy of the push-down ceiling so it does not include the software
// catalogue model; the two surfaces document the same figure, so a drift is a defect.
static_assert(hcp::kMaxPushdownScopeIds == yuzu::server::software_catalogue::kScopePushdownMaxIds,
              "the bulk CI ceiling must equal the software catalogue's push-down ceiling");

// Kills: raising or dropping the ceiling, using `>=` for `>`, and pushing a set at the ceiling
// into SQL as anything but the full id list. Pages are exact at the ceiling.
TEST_CASE("hardware ci page: a scope of exactly the ceiling is pushed into SQL, pages exact",
          "[hardware_ci_page][scope][ceiling]") {
    std::set<std::string> real;
    FakeStore store = forty_devices(real);
    const authz::VisibleSet scope = scope_of_size(real, hcp::kMaxPushdownScopeIds);
    REQUIRE(scope->size() == 10000);

    hcp::Request rq;
    rq.limit = 4;
    int pages = 0;
    const auto all = walk(store, rq, scope, &pages);
    CHECK(all == std::vector<std::string>(real.begin(), real.end()));
    CHECK(pages == 4); // 14 devices in scope, 4 per page: 4+4+4+2
    REQUIRE_FALSE(store.queries.empty());
    for (const auto& q : store.queries) {
        REQUIRE(q.agent_ids.has_value());
        CHECK(q.agent_ids->size() == 10000);
        CHECK(q.limit == 5); // limit + 1: the look-ahead row
    }
}

// Kills: reading (or post-filtering) a scope above the ceiling, and returning anything but the
// distinct terminal error. ZERO store reads is the point: nothing is scanned, so nothing can be
// counted.
TEST_CASE("hardware ci page: a scope over the ceiling with no agent_id is refused with zero reads",
          "[hardware_ci_page][scope][ceiling]") {
    std::set<std::string> real;
    FakeStore store = forty_devices(real);
    const authz::VisibleSet scope = scope_of_size(real, hcp::kMaxPushdownScopeIds + 1);
    REQUIRE(scope->size() == 10001);

    const auto page = hcp::read_page(store.reader(), {}, scope, nullptr, nullptr, hcp::kRestRowBudgetBytes);
    REQUIRE_FALSE(page.has_value());
    CHECK(page.error() == hcp::ReadError::kScopeTooWide);
    CHECK(store.reads == 0);

    // a continuation is refused the same way (the cursor is decoded first, then the scope)
    hcp::Request first;
    first.limit = 3;
    FakeStore small;
    small.add("a");
    small.add("b");
    small.add("c");
    small.add("d");
    const auto head = hcp::read_page(small.reader(), first, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
    REQUIRE(head.has_value());
    REQUIRE_FALSE(head->next_cursor.empty());
    hcp::Request next = first;
    next.cursor = head->next_cursor;
    small.reads = 0;
    const auto again = hcp::read_page(small.reader(), next, scope, nullptr, nullptr, hcp::kRestRowBudgetBytes);
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error() == hcp::ReadError::kScopeTooWide);
    CHECK(small.reads == 0);

    // the text carries no count and names the remedy
    const std::string msg(hcp::read_error_message(hcp::ReadError::kScopeTooWide));
    CHECK(msg.find("agent_id") != std::string::npos);
    CHECK(msg.find("10001") == std::string::npos);
    CHECK(hcp::audit_detail_scope_too_wide("REST") == "hardware CI records (REST) state=scope too wide");
}

// Kills: sending the id array with a named device (a 10001-element ANY for one row), and serving a
// named device without the in_scope check.
TEST_CASE("hardware ci page: a scope over the ceiling with an agent_id reads that one device by key",
          "[hardware_ci_page][scope][ceiling]") {
    std::set<std::string> real;
    FakeStore store = forty_devices(real);
    const authz::VisibleSet scope = scope_of_size(real, hcp::kMaxPushdownScopeIds + 1);

    SECTION("an in-scope device is served") {
        hcp::Request rq;
        rq.agent_id = "dev-003"; // 3 % 3 == 0: in scope
        const auto page = hcp::read_page(store.reader(), rq, scope, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(page.has_value());
        CHECK(ids_of(*page) == std::vector<std::string>{"dev-003"});
        CHECK_FALSE(page->target_denied);
        CHECK(page->next_cursor.empty());
        REQUIRE(store.queries.size() == 1);
        CHECK(store.queries[0].agent_id == std::optional<std::string>("dev-003"));
        CHECK_FALSE(store.queries[0].agent_ids.has_value());
    }
    SECTION("an out-of-scope device that exists is the empty page of a device with no record") {
        hcp::Request hidden;
        hidden.agent_id = "dev-001"; // exists, not in scope
        const auto denied = hcp::read_page(store.reader(), hidden, scope, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        hcp::Request ghost;
        ghost.agent_id = "pad-5"; // in scope, no record
        const auto none = hcp::read_page(store.reader(), ghost, scope, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(denied.has_value());
        REQUIRE(none.has_value());
        CHECK(denied->rows.empty());
        CHECK(none->rows.empty());
        CHECK(denied->next_cursor.empty());
        CHECK(none->next_cursor.empty());
        CHECK(denied->target_denied);
        CHECK_FALSE(none->target_denied);
        CHECK(hcp::page_json(*denied) == hcp::page_json(*none));
        // the hidden device was never read
        for (const auto& q : store.queries)
            CHECK(q.agent_id != std::optional<std::string>("dev-001"));
    }
}

TEST_CASE("hardware ci page: a degraded store read is an error, never an empty page",
          "[hardware_ci_page][degrade]") {
    FakeStore store;
    store.add("a");
    store.degraded = true;
    const auto page = hcp::read_page(store.reader(), {}, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
    REQUIRE_FALSE(page.has_value());
    CHECK(page.error() == hcp::ReadError::kDegraded); // not a cursor or scope error

    const authz::VisibleSet scope = std::unordered_set<std::string>{"a"};
    CHECK_FALSE(hcp::read_page(store.reader(), {}, scope, nullptr, nullptr, hcp::kRestRowBudgetBytes).has_value());
}

TEST_CASE("hardware ci page: a refused cursor surfaces its reason", "[hardware_ci_page][cursor]") {
    FakeStore store;
    store.add("a");
    hcp::Request rq;
    rq.cursor = "nonsense";
    const auto bad = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error() == hcp::ReadError::kCursorMalformed);
    CHECK(store.reads == 0);

    // a well-formed cursor issued for another filter is the other refusal
    hcp::Request named;
    named.agent_id = "a";
    hcp::Request unnamed;
    unnamed.cursor = hcp::encode_cursor({"a"}, hcp::filter_fingerprint(named));
    const auto mismatch = hcp::read_page(store.reader(), unnamed, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
    REQUIRE_FALSE(mismatch.has_value());
    CHECK(mismatch.error() == hcp::ReadError::kCursorFilterMismatch);
    CHECK(store.reads == 0);
}

// ── byte order, rows moving during a walk, the limit bound ─────────────────────

// The ids a locale-aware collation would arrange differently from their bytes (case, punctuation,
// digits against letters, a space, non-ASCII). The walk serves each exactly once, in byte order.
TEST_CASE("hardware ci page: ids a locale would reorder are served once each, in byte order",
          "[hardware_ci_page][walk][order]") {
    const std::vector<std::string> ids = {
        "Agent-1", "agent_1", "agent-1", "agent1", "PC-1", "pc-0042", "Zeta", "zeta", "AB", "ab",
        "a b",     "a-b",     "a_b",     "-x",     "_x",   "10",      "2",    "\xC3\xA9t\xC3\xA9", "Z\xC3\xA9"};
    std::vector<std::string> expected = ids;
    std::sort(expected.begin(), expected.end()); // std::string orders by unsigned byte value
    for (const int limit : {1, 2, 5, 1000}) {
        FakeStore store;
        for (const auto& id : ids)
            store.add(id);
        hcp::Request rq;
        rq.limit = limit;
        INFO(limit);
        CHECK(walk(store, rq, std::nullopt) == expected);
    }
    // Spot-check the pairs a locale-aware order would swap, so the expectation is not circular.
    const auto pos = [&](const std::string& id) {
        return std::ranges::find(expected, id) - expected.begin();
    };
    CHECK(pos("Zeta") < pos("agent-1")); // upper case before lower case
    CHECK(pos("AB") < pos("a b"));       // 'B' (0x42) before ' b'... 'A' < 'a'
    CHECK(pos("-x") < pos("10"));        // '-' (0x2D) before digits
    CHECK(pos("10") < pos("2"));         // digits are compared as text
    CHECK(pos("_x") > pos("Zeta"));      // '_' (0x5F) is after upper case, before lower case
    CHECK(pos("_x") < pos("a b"));
    CHECK(pos("agent-1") < pos("agent1")); // '-' before '1'
    CHECK(pos("agent1") < pos("agent_1")); // '1' (0x31) before '_' (0x5F)
}

// Kills: a second page that repeats, skips or reorders when a row appears ahead of, or the cursor's
// own row is deleted from, the table between the two reads. The page is compared EXACTLY.
TEST_CASE("hardware ci page: the second page is exact when a row is inserted ahead of the cursor or the "
          "cursor's row is deleted",
          "[hardware_ci_page][walk]") {
    FakeStore store;
    for (const char* id : {"d1", "d2", "d3", "d4", "d5", "d6"})
        store.add(id);
    hcp::Request rq;
    rq.limit = 2;
    const auto first = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
    REQUIRE(first.has_value());
    REQUIRE(ids_of(*first) == std::vector<std::string>{"d1", "d2"});
    REQUIRE_FALSE(first->next_cursor.empty());
    rq.cursor = first->next_cursor;

    SECTION("a row inserted ahead of the cursor is served on the page where it sorts") {
        store.add("d25"); // between d2 (the cursor) and d3
        const auto second = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(second.has_value());
        CHECK(ids_of(*second) == std::vector<std::string>{"d25", "d3"});
        CHECK_FALSE(second->next_cursor.empty());
    }
    SECTION("a row inserted behind the cursor is missed by this walk, never served twice") {
        store.add("d15"); // between d1 and d2: already passed
        const auto second = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(second.has_value());
        CHECK(ids_of(*second) == std::vector<std::string>{"d3", "d4"});
    }
    SECTION("the cursor's own row deleted: the next page continues after its key") {
        store.erase("d2");
        const auto second = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(second.has_value());
        CHECK(ids_of(*second) == std::vector<std::string>{"d3", "d4"});
        CHECK_FALSE(second->next_cursor.empty());
    }
    SECTION("every later row deleted: an empty final page with no cursor") {
        for (const char* id : {"d3", "d4", "d5", "d6"})
            store.erase(id);
        const auto second = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(second.has_value());
        CHECK(second->rows.empty());
        CHECK(second->next_cursor.empty());
    }
}

// Kills: handing the store a zero, negative or overflowing limit (the store reads <= 0 as its whole
// row ceiling, and `limit + 1` overflows at INT_MAX) when a Request is built by hand.
TEST_CASE("hardware ci page: a hand-built Request's limit is clamped before it reaches the store",
          "[hardware_ci_page][walk]") {
    FakeStore store;
    for (int i = 0; i < 1010; ++i) {
        char buf[16];
        std::snprintf(buf, sizeof buf, "d%05d", i);
        store.add(buf);
    }
    for (const int bad : {0, -5, INT_MIN}) {
        hcp::Request rq;
        rq.limit = bad;
        const auto page = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(page.has_value());
        INFO(bad);
        CHECK(page->rows.size() == 1); // clamped up to 1
        CHECK(store.queries.back().limit == 2);
    }
    for (const int big : {1001, INT_MAX}) {
        hcp::Request rq;
        rq.limit = big;
        const auto page = hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kRestRowBudgetBytes);
        REQUIRE(page.has_value());
        INFO(big);
        CHECK(page->rows.size() == 1000); // clamped down to kPageMax
        CHECK(store.queries.back().limit == 1001);
    }
}

// ── one answer per read failure, shared by both transports ─────────────────────

// Kills: a new ReadError enumerator that one transport treats as a cursor refusal and the other
// does not (the cascades were hand-copied before), and drift between the two transports' wording.
// Every enumerator before the `kCount` sentinel is walked, so adding one without a row in this
// table fails to compile (the static_assert) and, if the table were padded, fails the loop: an
// enumerator that fell to describe_read_error's out-of-range branch answers "invalid request" and
// is refused here, never skipped.
TEST_CASE("hardware ci page: every ReadError has one answer on both transports", "[hardware_ci_page][errors]") {
    struct Expect {
        hcp::ReadError e;
        bool unavailable;
        const char* message;
        bool domain_row;
        const char* outcome;
        const char* rest_detail;
        const char* mcp_detail;
        const char* rest_remediation;
        const char* mcp_remediation;
        int retry_after_ms; // -1 = none
        bool retry_after_header = false; // REST also sends Retry-After
    };
    static constexpr std::array<Expect, 6> table = {{
        {hcp::ReadError::kDegraded, true, "hardware CI records unavailable", true, "failure",
         "hardware CI records (REST) state=store unreadable",
         "hardware CI records (MCP) state=store unreadable", "", "", 5000},
        {hcp::ReadError::kCursorMalformed, false, "invalid cursor; restart from the first page", false,
         "denied", "", "invalid arguments: cursor", "", "omit cursor to restart from the first page", -1},
        {hcp::ReadError::kCursorFilterMismatch, false, "invalid cursor; restart from the first page",
         false, "denied", "", "invalid arguments: cursor", "", "omit cursor to restart from the first page", -1},
        {hcp::ReadError::kScopeTooWide, false,
         "the caller's scope covers more than 10000 devices and no agent_id was given; a credential "
         "with global read has no such limit",
         true, "denied", "hardware CI records (REST) state=scope too wide",
         "hardware CI records (MCP) state=scope too wide",
         "use a credential with global read, pass agent_id, or ask an administrator to narrow the "
         "caller's scope",
         "use a credential with global read, pass agent_id, or ask an administrator to narrow the "
         "caller's scope",
         -1},
        {hcp::ReadError::kOrderingUnverified, true,
         "the device CI data cannot be vouched for right now; retry after the hint and restart "
         "the walk from the first page (operators: see PostgreSQL collation version in "
         "server-admin.md)",
         true, "failure", "hardware CI records (REST) state=collation ordering unverified",
         "hardware CI records (MCP) state=collation ordering unverified",
         "wait retry_after_ms and call once more, then restart the walk from the first page (do not "
         "resume the old cursor); if it persists, ask an administrator to check the database "
         "collation state (see PostgreSQL collation version in server-admin.md)",
         "wait retry_after_ms and call once more, then restart the walk from the first page (do not "
         "resume the old cursor); if it persists, ask an administrator to check the database "
         "collation state (see PostgreSQL collation version in server-admin.md)",
         60000, true},
        // Busy: nothing was read, so NO domain audit row on either transport (a busy flood must
        // not become an audit INSERT flood); the 2000 ms hint is pinned here for both surfaces
        // (the CI hint script only scans newly added tools).
        {hcp::ReadError::kBusy, true,
         "hardware CI bulk read capacity in use; retry after the hint", false, "failure",
         "hardware CI records (REST) state=read capacity in use",
         "hardware CI records (MCP) state=read capacity in use",
         "wait retry_after_ms and call once more; read one page at a time, never several in parallel",
         "wait retry_after_ms and call once more; read one page at a time, never several in parallel",
         2000, true},
    }};
    static_assert(table.size() == static_cast<std::size_t>(hcp::ReadError::kCount),
                  "a new ReadError needs a row in this table (and a case in describe_read_error)");
    for (int v = 0; v < static_cast<int>(hcp::ReadError::kCount); ++v) {
        const auto e = static_cast<hcp::ReadError>(v);
        // an enumerator that is in neither switch answers the out-of-range text: refuse it
        REQUIRE(hcp::read_error_message(e) != "invalid request");
        const auto it = std::ranges::find_if(table, [&](const Expect& x) { return x.e == e; });
        INFO("enumerator " << v);
        REQUIRE(it != table.end()); // a new enumerator needs a row here
        const auto rest = hcp::describe_read_error(e, hcp::Surface::kRest);
        const auto mcp = hcp::describe_read_error(e, hcp::Surface::kMcp);
        for (const auto* f : {&rest, &mcp}) {
            CHECK(f->unavailable == it->unavailable);
            CHECK(f->message == it->message);
            CHECK(f->message == hcp::read_error_message(e));
            CHECK(f->domain_audit_row == it->domain_row);
            CHECK(f->audit_outcome == it->outcome);
            // a refusal is never retried; an unavailable read carries its own hint (5 s for a
            // failed store read, 60 s for an unverified ordering)
            CHECK(f->retry_after_ms == it->retry_after_ms);
            CHECK(f->retry_after_header == it->retry_after_header);
        }
        CHECK(rest.audit_detail == it->rest_detail);
        CHECK(mcp.audit_detail == it->mcp_detail);
        CHECK(rest.remediation == it->rest_remediation);
        CHECK(mcp.remediation == it->mcp_remediation);
    }
    // the sentinel and an out-of-range value is a refusal with no domain audit row, an empty audit
    // detail and no retry (the MCP handler's generic `denied` row is not this function's)
    for (const auto v : {hcp::ReadError::kCount, static_cast<hcp::ReadError>(99)}) {
        const auto bogus = hcp::describe_read_error(v, hcp::Surface::kRest);
        CHECK_FALSE(bogus.unavailable);
        CHECK_FALSE(bogus.domain_audit_row);
        CHECK(bogus.message == "invalid request");
        CHECK(bogus.audit_detail.empty());
    }
}

// ── JSON ─────────────────────────────────────────────────────────────────────

TEST_CASE("hardware ci page: row JSON carries the per-id ci block byte for byte, plus hash and version",
          "[hardware_ci_page][json]") {
    DeviceCiRecord rec = make_record("agent-1");
    rec.chassis_type = "Laptop";
    rec.board_serial = "BSN-1";
    rec.disks_summary = "unknown"; // a sentinel renders null, as on the per-id route

    HardwareCiDetail detail;
    detail.ci = std::optional<DeviceCiRecord>{rec};
    detail.ci_sections = std::vector<DeviceCiSection>{};
    const json per_id_ci = hardware_ci_json(detail, 0)["ci"];

    const json row = hcp::row_json(rec);
    json expected_ci = per_id_ci;
    expected_ci.erase("sections"); // the bulk page never carries sections
    CHECK(row["ci"] == expected_ci);
    CHECK_FALSE(row["ci"].contains("sections"));
    CHECK(row["agent_id"] == "agent-1");
    CHECK(row["hostname"] == "host-agent-1");
    CHECK(row["content_hash"] == "hash-agent-1");
    CHECK(row["blob_version"] == 2);
    CHECK(row["ci"]["disks_summary"].is_null());
    CHECK(row["ci"]["chassis_type"] == "Laptop");
}

TEST_CASE("hardware ci page: a v1-only record renders nulls for the v2 scalars, never defaults",
          "[hardware_ci_page][json]") {
    DeviceCiRecord rec = make_record("old-agent");
    rec.blob_version = 1;
    rec.content_hash.clear();
    rec.hostname.clear();
    const json row = hcp::row_json(rec);
    for (const char* k : {"chassis_type", "chassis_serial", "chassis_asset_tag", "chassis_source",
                          "board_vendor", "board_product", "board_serial", "board_source",
                          "machine_id_hash", "machine_id_algorithm", "machine_id_source"}) {
        INFO(k);
        REQUIRE(row["ci"].contains(k));
        CHECK(row["ci"][k].is_null());
    }
    CHECK(row["blob_version"] == 1);
    CHECK(row["content_hash"].is_null());
    CHECK(row["hostname"].is_null());
}

TEST_CASE("hardware ci page: page JSON shape and audit text", "[hardware_ci_page][json]") {
    hcp::Page page;
    page.rows.push_back(make_record("a"));
    page.next_cursor = "tok";
    const json j = hcp::page_json(page);
    CHECK(j.size() == 2);
    CHECK(j["devices"].size() == 1);
    CHECK(j["next_cursor"] == "tok");
    CHECK_FALSE(j.contains("devices_omitted"));

    hcp::Page last;
    CHECK(hcp::page_json(last)["next_cursor"] == "");

    hcp::Request rq;
    CHECK(hcp::audit_target_type(rq) == "Inventory");
    CHECK(hcp::audit_target_id(rq) == "fleet");
    // exact strings, not substrings: the grammar is a contract with the audit-log docs
    CHECK(hcp::audit_detail(page, rq, "REST", false) == "hardware CI records (REST): rows=1 scope=fleet");
    CHECK(hcp::audit_detail(page, rq, "MCP", true) ==
          "hardware CI records (MCP): rows=1 scope=authority_scoped");
    rq.cursor = "c";
    CHECK(hcp::audit_detail(page, rq, "REST", false) ==
          "hardware CI records (REST): rows=1 page=continuation scope=fleet");
    CHECK(hcp::audit_detail(page, rq, "MCP", true) ==
          "hardware CI records (MCP): rows=1 page=continuation scope=authority_scoped");
    rq.agent_id = "dev-9";
    CHECK(hcp::audit_target_type(rq) == "Agent");
    CHECK(hcp::audit_target_id(rq) == "dev-9");
    // the detail never names the device: the target does
    CHECK(hcp::audit_detail(page, rq, "REST", false).find("dev-9") == std::string::npos);
    CHECK(hcp::audit_detail_target_denied("MCP") == "hardware CI records (MCP) state=agent_id outside the caller's scope");
}

TEST_CASE("hardware ci page: a confined caller's body carries scope_basis and nothing about hidden devices",
          "[hardware_ci_page][json][security]") {
    hcp::Page page;
    page.rows.push_back(make_record("a"));

    json confined = hcp::page_json(page);
    hcp::apply_scope_disclosure(confined, /*confined=*/true);
    CHECK(confined.size() == 3);
    CHECK(confined["scope_basis"] == "authority_scoped");
    CHECK(confined["devices"].size() == 1);
    CHECK(confined["next_cursor"] == "");

    json global = hcp::page_json(page);
    hcp::apply_scope_disclosure(global, /*confined=*/false);
    CHECK(global == hcp::page_json(page)); // untouched
    CHECK_FALSE(global.contains("scope_basis"));
    CHECK(global.size() == 2);
}

// Kills: reading `rec.hostname` verbatim (an empty or "unknown" CI hostname must be null so a
// CMDB never imports a literal "unknown" as a device name).
TEST_CASE("hardware ci page: hostname is null when empty or the literal unknown, and passes a real name",
          "[hardware_ci_page][json]") {
    DeviceCiRecord rec = make_record("h-1");
    rec.hostname = "unknown";
    CHECK(hcp::row_json(rec)["hostname"].is_null());
    rec.hostname.clear();
    CHECK(hcp::row_json(rec)["hostname"].is_null());
    rec.hostname = "build-07";
    CHECK(hcp::row_json(rec)["hostname"] == "build-07");
    rec.hostname = "Unknown"; // only the exact stored sentinel is a sentinel
    CHECK(hcp::row_json(rec)["hostname"] == "Unknown");
}

// ── the byte bound (#7950) ───────────────────────────────────────────────────

namespace {

using yuzu::server::test::make_worst_case_ci_record;

constexpr std::size_t kBudgets[] = {hcp::kRestRowBudgetBytes, hcp::kMcpRowBudgetBytes};

std::string dump_replace_str(const json& j) {
    return j.dump(-1, ' ', false, json::error_handler_t::replace);
}

// Zero-padded ids so byte order is numeric order.
std::string idx_id(int i) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "dev-%05d", i);
    return buf;
}

FakeStore worst_case_store(int n) {
    FakeStore store;
    for (int i = 0; i < n; ++i)
        store.add(make_worst_case_ci_record(idx_id(i)));
    return store;
}

} // namespace

// Kills: a measure that drifts from the serialiser (a different dump, a missing replace handler, a
// reordered row), which would let a page exceed its budget while the sum says it fits. The array
// the surfaces serve is "[" + rows joined by "," + "]", so the sum plus the separators is exact.
TEST_CASE("hardware ci page: the summed row_wire_bytes equals the served devices array's bytes",
          "[hardware_ci_page][bytes]") {
    hcp::Page page;
    page.rows.push_back(make_worst_case_ci_record("w-1"));
    page.rows.push_back(make_record("plain"));
    DeviceCiRecord odd = make_record("odd");
    odd.model = std::string("bad\xff\xfe""utf8 \"quoted\" \\ back\n", 22); // not valid UTF-8: replaced
    page.rows.push_back(odd);
    page.rows.push_back(make_worst_case_ci_record("w-2"));

    std::size_t sum = 0;
    for (const auto& r : page.rows)
        sum += hcp::row_wire_bytes(r);
    const std::string array = dump_replace_str(hcp::page_json(page)["devices"]);
    CHECK(sum + (page.rows.size() - 1) + 2 == array.size());

    // And it is the per-row dump, not an approximation.
    for (const auto& r : page.rows)
        CHECK(hcp::row_wire_bytes(r) == dump_replace_str(hcp::row_json(r)).size());
}

TEST_CASE("hardware ci page: a worst-case row is wide enough to make the budgets bite",
          "[hardware_ci_page][bytes]") {
    const std::size_t w = hcp::row_wire_bytes(make_worst_case_ci_record("x"));
    // About 160 KB and never past the documented ceiling of one row (180 KB).
    CHECK(w > 100 * 1024);
    CHECK(w <= 180 * 1024);
    CHECK(hcp::kMcpRowBudgetBytes > w); // the first row alone always fits both budgets
    CHECK(hcp::kRestRowBudgetBytes > hcp::kMcpRowBudgetBytes);
}

TEST_CASE("hardware ci page: a full walk of worst-case rows serves each once, within the budget",
          "[hardware_ci_page][bytes]") {
    constexpr int kRows = 90; // more than either budget holds in one page
    for (const std::size_t budget : kBudgets) {
        INFO("budget " << budget);
        FakeStore store = worst_case_store(kRows);
        const std::size_t w = hcp::row_wire_bytes(store.rows.front());
        hcp::Request rq;
        rq.limit = 1000; // the count never cuts: only the byte bound can
        std::vector<std::string> served;
        int pages = 0;
        for (;;) {
            const auto page =
                hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, budget);
            REQUIRE(page.has_value());
            REQUIRE(++pages < 200);
            REQUIRE_FALSE(page->rows.empty()); // never an empty page with rows left
            std::size_t sum = 0;
            for (const auto& r : page->rows)
                sum += hcp::row_wire_bytes(r);
            CHECK(sum <= budget);
            // The page is MAXIMAL: one more row would have exceeded the budget.
            if (!page->next_cursor.empty())
                CHECK(sum + w > budget);
            // byte_capped says exactly "the budget, not the count, ended this page".
            CHECK(page->byte_capped == !page->next_cursor.empty());
            if (!page->next_cursor.empty()) {
                // Minted from the last KEPT row, even though fewer than limit + 1 rows were read.
                const auto at = hcp::decode_cursor(page->next_cursor, hcp::filter_fingerprint(rq));
                REQUIRE(at.has_value());
                CHECK(at->after == page->rows.back().agent_id);
            }
            // The store is still asked for limit + 1 rows: the byte bound does not narrow the read.
            CHECK(store.queries.back().limit == 1001);
            for (const auto& id : ids_of(*page))
                served.push_back(id);
            if (page->next_cursor.empty())
                break;
            rq.cursor = page->next_cursor;
        }
        CHECK(pages > 1);
        REQUIRE(served.size() == static_cast<std::size_t>(kRows));
        for (int i = 0; i < kRows; ++i)
            CHECK(served[static_cast<std::size_t>(i)] == idx_id(i)); // each once, in order, no skip
    }
}

// Kills: setting byte_capped whenever a cursor exists (the count cut is not a byte cut), and a
// byte cut that is applied before the count cut so a small page is reported as capped.
TEST_CASE("hardware ci page: the count cut alone does not set byte_capped", "[hardware_ci_page][bytes]") {
    FakeStore store = worst_case_store(10);
    hcp::Request rq;
    rq.limit = 3; // 3 worst-case rows fit both budgets
    const auto page =
        hcp::read_page(store.reader(), rq, std::nullopt, nullptr, nullptr, hcp::kMcpRowBudgetBytes);
    REQUIRE(page.has_value());
    CHECK(page->rows.size() == 3);
    CHECK_FALSE(page->next_cursor.empty());
    CHECK_FALSE(page->byte_capped);
    CHECK_FALSE(hcp::page_json(*page).contains("page_bytes_capped"));
    CHECK(hcp::audit_detail(*page, rq, "MCP", false).find("byte_capped") == std::string::npos);
}

// The last page, and a page the budget does not touch, are never marked.
TEST_CASE("hardware ci page: a page that fits is not byte_capped, even when it is the last",
          "[hardware_ci_page][bytes]") {
    FakeStore store = worst_case_store(2);
    for (const std::size_t budget : kBudgets) {
        const auto page = hcp::read_page(store.reader(), {}, std::nullopt, nullptr, nullptr, budget);
        REQUIRE(page.has_value());
        CHECK(page->rows.size() == 2);
        CHECK(page->next_cursor.empty());
        CHECK_FALSE(page->byte_capped);
    }
}

TEST_CASE("hardware ci page: the first row is always served and a row is never truncated",
          "[hardware_ci_page][bytes]") {
    FakeStore store = worst_case_store(3);
    const std::size_t w = hcp::row_wire_bytes(store.rows.front());
    for (const std::size_t budget : {std::size_t{0}, std::size_t{1}, w - 1}) {
        INFO("budget " << budget);
        const auto page = hcp::read_page(store.reader(), {}, std::nullopt, nullptr, nullptr, budget);
        REQUIRE(page.has_value());
        REQUIRE(page->rows.size() == 1); // over budget alone: served alone
        CHECK(page->rows.front().agent_id == idx_id(0));
        CHECK(hcp::row_wire_bytes(page->rows.front()) == w); // untruncated
        CHECK(page->byte_capped);
        const auto at = hcp::decode_cursor(page->next_cursor, hcp::filter_fingerprint({}));
        REQUIRE(at.has_value());
        CHECK(at->after == idx_id(0));
    }
    // One row in the store: over budget alone, but nothing was left over, so it is not capped.
    FakeStore one = worst_case_store(1);
    const auto page = hcp::read_page(one.reader(), {}, std::nullopt, nullptr, nullptr, 0);
    REQUIRE(page.has_value());
    CHECK(page->rows.size() == 1);
    CHECK(page->next_cursor.empty());
    CHECK_FALSE(page->byte_capped);
}

// The boundary is inclusive: a sum equal to the budget fits, one byte less does not.
TEST_CASE("hardware ci page: the budget boundary is inclusive", "[hardware_ci_page][bytes]") {
    FakeStore store;
    for (int i = 0; i < 6; ++i)
        store.add(make_record(idx_id(i))); // equal-width rows
    const std::size_t w = hcp::row_wire_bytes(store.rows.front());
    for (const auto& r : store.rows)
        REQUIRE(hcp::row_wire_bytes(r) == w);
    const auto at = hcp::read_page(store.reader(), {}, std::nullopt, nullptr, nullptr, 3 * w);
    REQUIRE(at.has_value());
    CHECK(at->rows.size() == 3);
    CHECK(at->byte_capped);
    const auto under = hcp::read_page(store.reader(), {}, std::nullopt, nullptr, nullptr, 3 * w - 1);
    REQUIRE(under.has_value());
    CHECK(under->rows.size() == 2);
    CHECK(under->byte_capped);
    const auto all = hcp::read_page(store.reader(), {}, std::nullopt, nullptr, nullptr, 6 * w);
    REQUIRE(all.has_value());
    CHECK(all->rows.size() == 6);
    CHECK_FALSE(all->byte_capped);
    CHECK(all->next_cursor.empty());
}

// A confined caller's pages carry the same bound and the cursor binds the same way.
TEST_CASE("hardware ci page: the byte bound applies under a pushed-down scope",
          "[hardware_ci_page][bytes][security]") {
    FakeStore store = worst_case_store(40);
    std::unordered_set<std::string> ids;
    for (int i = 0; i < 40; i += 2)
        ids.insert(idx_id(i));
    const authz::VisibleSet scope{ids};
    hcp::Request rq;
    rq.limit = 1000;
    std::vector<std::string> served;
    for (int guard = 0; guard < 100; ++guard) {
        const auto page =
            hcp::read_page(store.reader(), rq, scope, nullptr, nullptr, hcp::kMcpRowBudgetBytes);
        REQUIRE(page.has_value());
        for (const auto& id : ids_of(*page)) {
            CHECK(ids.contains(id)); // never an out-of-scope row
            served.push_back(id);
        }
        if (page->next_cursor.empty())
            break;
        rq.cursor = page->next_cursor;
    }
    REQUIRE(served.size() == ids.size());
}

TEST_CASE("hardware ci page: byte_capped reaches the body and the audit text only when set",
          "[hardware_ci_page][bytes][json]") {
    hcp::Page page;
    page.rows.push_back(make_record("a"));
    page.next_cursor = "tok";
    hcp::Request rq;
    // Not capped: byte-identical to the pre-existing shapes.
    CHECK(hcp::page_json(page).size() == 2);
    CHECK(hcp::audit_detail(page, rq, "REST", false) == "hardware CI records (REST): rows=1 scope=fleet");
    page.byte_capped = true;
    const json j = hcp::page_json(page);
    CHECK(j.size() == 3);
    CHECK(j["page_bytes_capped"] == true);
    CHECK(hcp::audit_detail(page, rq, "REST", false) ==
          "hardware CI records (REST): rows=1 scope=fleet byte_capped=1");
    rq.cursor = "c";
    CHECK(hcp::audit_detail(page, rq, "MCP", true) ==
          "hardware CI records (MCP): rows=1 page=continuation scope=authority_scoped byte_capped=1");
}
