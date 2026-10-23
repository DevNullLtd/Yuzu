/**
 * test_dex_score_policy_writer.cpp -- apply_dex_score_policy over fake read / compare-and-set /
 * audit closures and a real DexScorePolicyProvider with a fake clock: the If-Match and dry_run
 * parsers, every refusal and its denied row, the audit-first order, the success path, and the
 * outcome-unknown handling (a store error after the statement was sent, an exception escaping
 * write() after the commit). No store, no sleeps, no I/O.
 */
#include "dex_score_policy_writer.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;
using Op = DexScorePolicyWriteRequest::Op;
using St = DexScorePolicyWriteStatus;

namespace {

std::string doc_with_excellent(double e) {
    DexScorePolicy p;
    p.tiers.edges.excellent = e;
    return dex_score_policy_canonical(p);
}

const std::string kPrefixedError = std::string(kDbErrorPrefix) + "database write failed";

struct Row {
    std::string verb, result;
    json detail;
};

// One store row, one audit log, one fake clock; the provider is real.
struct World {
    std::optional<std::string> stored;
    bool read_fails{false};
    int reads{0};
    int cas_calls{0};
    int car_calls{0};
    std::optional<std::string> cas_expected;
    std::string cas_actor;
    std::string cas_text;   // the canonical text the last compare-and-set was handed
    std::string car_expected;
    // The audit rows that existed when the store was last touched (set and remove alike).
    std::vector<Row> rows_at_store;
    // When set, the store reports this error after applying (or not) the write.
    std::optional<std::string> store_error;
    bool apply_before_error{true};
    bool store_throws{false};
    // Runs right after a write is applied, before the answer returns (another writer, a clock).
    std::function<void()> after_apply;
    bool clock_throws{false};
    std::int64_t now{1'000'000};

    std::vector<Row> rows;
    std::vector<std::string> refuse_results; // audit results the audit store refuses
    int refused{0};                          // how many rows it did refuse
    int audit_throws{0};

    std::shared_ptr<DexScorePolicyProvider> provider;

    World() {
        provider = std::make_shared<DexScorePolicyProvider>(
            [this]() -> std::expected<std::optional<std::string>, std::string> {
                return stored;
            },
            [this]() -> std::int64_t {
                if (clock_throws)
                    throw std::runtime_error("clock failed");
                return now;
            },
            std::chrono::milliseconds{1});
    }

    DexScorePolicyWriteDeps deps() {
        DexScorePolicyWriteDeps d;
        d.read_stored = [this]() -> std::expected<std::optional<std::string>, std::string> {
            ++reads;
            if (read_fails)
                return std::unexpected(std::string("store down"));
            return stored;
        };
        d.compare_and_set = [this](const std::optional<std::string>& expected,
                                   const std::string& canonical,
                                   const std::string& actor) -> std::expected<bool, std::string> {
            ++cas_calls;
            cas_expected = expected;
            cas_actor = actor;
            cas_text = canonical;
            rows_at_store = rows;
            if (store_throws)
                throw std::runtime_error("boom");
            if (store_error && !apply_before_error)
                return std::unexpected(*store_error);
            if (stored != expected)
                return false;
            stored = canonical;
            if (after_apply)
                after_apply();
            if (store_error)
                return std::unexpected(*store_error);
            return true;
        };
        d.compare_and_remove = [this](const std::string& expected)
            -> std::expected<bool, std::string> {
            ++car_calls;
            car_expected = expected;
            rows_at_store = rows;
            if (store_error && !apply_before_error)
                return std::unexpected(*store_error);
            if (stored != expected)
                return false;
            stored.reset();
            if (after_apply)
                after_apply();
            if (store_error)
                return std::unexpected(*store_error);
            return true;
        };
        d.provider = provider;
        d.audit = [this](std::string_view verb, std::string_view result,
                         const std::string& detail_json) {
            if (audit_throws > 0) {
                --audit_throws;
                throw std::runtime_error("audit threw");
            }
            rows.push_back({std::string(verb), std::string(result), json::parse(detail_json)});
            for (const auto& r : refuse_results)
                if (r == result) {
                    rows.pop_back();
                    ++refused;
                    return false;
                }
            return true;
        };
        return d;
    }

    DexScorePolicyWriteResult run(Op op, std::optional<std::string> if_match,
                                  std::string body = {},
                                  std::optional<std::string> dry_run = std::nullopt) {
        DexScorePolicyWriteRequest rq;
        rq.op = op;
        rq.if_match = std::move(if_match);
        rq.body = std::move(body);
        rq.dry_run = std::move(dry_run);
        rq.actor = "alice";
        return apply_dex_score_policy(rq, deps());
    }
    DexScorePolicyWriteResult put(std::optional<std::string> if_match, std::string body,
                                  std::optional<std::string> dry_run = std::nullopt) {
        return run(Op::Put, std::move(if_match), std::move(body), std::move(dry_run));
    }
    DexScorePolicyWriteResult del(std::optional<std::string> if_match,
                                  std::optional<std::string> dry_run = std::nullopt) {
        return run(Op::Reset, std::move(if_match), {}, std::move(dry_run));
    }
};

} // namespace

// ── parsers ─────────────────────────────────────────────────────────────────

TEST_CASE("parse_if_match: accepts one strong revision, refuses everything else",
          "[dex][score_policy_writer]") {
    const std::string hex = "0123456789abcdef";
    CHECK(parse_if_match("\"" + hex + "\"").value() == hex);
    CHECK(parse_if_match(hex).value() == hex);
    CHECK(parse_if_match("  \"" + hex + "\" ").value() == hex);
    CHECK(parse_if_match("default").value() == "default");
    CHECK(parse_if_match("\"default\"").value() == "default");
    for (const char* bad : {"*", "W/\"0123456789abcdef\"", "\"a\",\"b\"", "hello", "\"\"", "",
                            "   ", "0123456789ABCDEF", "0123456789abcde", "\"default",
                            "Default"}) {
        INFO("value=" << bad);
        const auto r = parse_if_match(bad);
        REQUIRE_FALSE(r);
        CHECK(r.error().rfind("If-Match", 0) == 0);
    }
    CHECK_FALSE(parse_if_match(std::string(65, 'a')));
}

TEST_CASE("parse_dry_run: absent is false, true and false only", "[dex][score_policy_writer]") {
    CHECK(parse_dry_run(std::nullopt).value() == false);
    CHECK(parse_dry_run(std::string("true")).value() == true);
    CHECK(parse_dry_run(std::string("false")).value() == false);
    for (const char* bad : {"yes", "1", "TRUE", ""}) {
        INFO("value=" << bad);
        const auto r = parse_dry_run(std::string(bad));
        REQUIRE_FALSE(r);
        CHECK(r.error().rfind("dry_run", 0) == 0);
    }
}

TEST_CASE("dex_score_policy_http_status: the status mapping", "[dex][score_policy_writer]") {
    CHECK(dex_score_policy_http_status(St::Ok) == 200);
    CHECK(dex_score_policy_http_status(St::IfMatchMissing) == 428);
    CHECK(dex_score_policy_http_status(St::IfMatchMalformed) == 400);
    CHECK(dex_score_policy_http_status(St::Invalid) == 400);
    CHECK(dex_score_policy_http_status(St::Stale) == 409);
    CHECK(dex_score_policy_http_status(St::WriterBusy) == 503);
    CHECK(dex_score_policy_http_status(St::StoreUnavailable) == 503);
    CHECK(dex_score_policy_http_status(St::OutcomeUnknown) == 503);
    CHECK(dex_score_policy_http_status(St::AuditUnavailable) == 503);
}

// ── refusals ────────────────────────────────────────────────────────────────

TEST_CASE("writer: a bad dry_run is refused with a denied row and no store call",
          "[dex][score_policy_writer]") {
    World w;
    SECTION("PUT with dry_run=yes") {
        const auto r = w.put("default", doc_with_excellent(95.0), std::string("ye s=1\n"));
        CHECK(r.status == St::Invalid);
        REQUIRE(w.rows.size() == 1);
        CHECK(w.rows[0].verb == "dex.score_policy.update");
        CHECK(w.rows[0].result == "denied");
        CHECK(w.rows[0].detail["field"] == "dry_run");
        // the raw value is neutralised (space, '=' and the newline folded), never recorded raw
        CHECK(w.rows[0].detail["dry_run"] == "ye_s_1_");
    }
    SECTION("DELETE with dry_run=true") {
        const auto r = w.del("default", std::string("true"));
        CHECK(r.status == St::Invalid);
        CHECK(r.message == "DELETE does not support dry_run");
        REQUIRE(w.rows.size() == 1);
        CHECK(w.rows[0].verb == "dex.score_policy.reset");
        CHECK(w.rows[0].result == "denied");
    }
    CHECK(w.reads == 0);
    CHECK(w.cas_calls == 0);
    CHECK(w.car_calls == 0);
}

TEST_CASE("writer: no If-Match is 428 with a denied row and no store call",
          "[dex][score_policy_writer]") {
    World w;
    SECTION("PUT") {
        const auto r = w.put(std::nullopt, doc_with_excellent(95.0));
        CHECK(r.status == St::IfMatchMissing);
        CHECK(r.message.find("If-Match") != std::string::npos);
        REQUIRE(w.rows.size() == 1);
        CHECK(w.rows[0].verb == "dex.score_policy.update");
        CHECK(w.rows[0].result == "denied");
        CHECK(w.rows[0].detail["reason"] == "if_match_missing");
        CHECK(w.cas_calls == 0);
    }
    // DELETE shares the refusal but stamps its own verb on the row.
    SECTION("DELETE") {
        const auto r = w.del(std::nullopt);
        CHECK(r.status == St::IfMatchMissing);
        CHECK(r.message.find("If-Match") != std::string::npos);
        REQUIRE(w.rows.size() == 1);
        CHECK(w.rows[0].verb == "dex.score_policy.reset");
        CHECK(w.rows[0].result == "denied");
        CHECK(w.rows[0].detail["reason"] == "if_match_missing");
        CHECK(w.car_calls == 0);
    }
}

TEST_CASE("writer: a malformed If-Match is 400 and is recorded neutralised",
          "[dex][score_policy_writer]") {
    World w;
    const auto r = w.put(std::string("*\x01 x=y"), doc_with_excellent(95.0));
    CHECK(r.status == St::IfMatchMalformed);
    REQUIRE(w.rows.size() == 1);
    CHECK(w.rows[0].detail["reason"] == "if_match_malformed");
    const std::string recorded = w.rows[0].detail["if_match"].get<std::string>();
    CHECK(recorded == "*__x_y");
    CHECK(w.cas_calls == 0);
}

TEST_CASE("writer: a stale If-Match is 409 naming the stored revision; nothing is written",
          "[dex][score_policy_writer]") {
    World w;
    w.stored = doc_with_excellent(90.0);
    const std::string observed = dex_score_policy_revision(*w.stored);
    const auto r = w.put("default", doc_with_excellent(95.0));
    CHECK(r.status == St::Stale);
    CHECK(r.message.find(observed) != std::string::npos);
    CHECK(r.previous_revision == observed);
    REQUIRE(w.rows.size() == 1);
    CHECK(w.rows[0].result == "denied");
    CHECK(w.rows[0].detail["reason"] == "stale");
    CHECK(w.rows[0].detail["prior_revision"] == observed);
    CHECK(w.cas_calls == 0);
}

TEST_CASE("writer: the Apps projection is refused with a remediation naming tiers.edges",
          "[dex][score_policy_writer]") {
    World w;
    const auto r = w.put("default", R"({"tiers":{"excellent":{"edge":90,"name":"Excellent"}}})");
    CHECK(r.status == St::Invalid);
    CHECK(r.message == "unparseable at tiers.excellent: unknown key");
    CHECK(r.remediation.find("tiers.edges") != std::string::npos);
    REQUIRE(w.rows.size() == 1);
    CHECK(w.rows[0].detail["field"] == "tiers.excellent");
    CHECK(w.cas_calls == 0);
}

TEST_CASE("writer: version 2 is refused with the reader's own wording",
          "[dex][score_policy_writer]") {
    World w;
    const auto r = w.put("default", R"({"version":2})");
    CHECK(r.status == St::Invalid);
    CHECK(r.message == "unsupported_version at version: 2 above the supported 1");
}

TEST_CASE("writer: an oversized body is refused at document before it is parsed",
          "[dex][score_policy_writer]") {
    World w;
    const auto r = w.put("default", std::string(kDexScorePolicyMaxBytes + 1, ' ') + "{}");
    CHECK(r.status == St::Invalid);
    CHECK(r.message.rfind("oversized at document", 0) == 0);
    CHECK(w.cas_calls == 0);
}

TEST_CASE("writer: a too-deep body is refused at document", "[dex][score_policy_writer]") {
    World w;
    const auto r = w.put("default", std::string(200, '[') + std::string(200, ']'));
    CHECK(r.status == St::Invalid);
    CHECK(r.message == "request body nests too deeply");
}

TEST_CASE("writer: a validator refusal names its token and group", "[dex][score_policy_writer]") {
    World w;
    const auto r = w.put("default", R"({"tiers":{"edges":{"excellent":50,"good":60,"fair":40}}})");
    CHECK(r.status == St::Invalid);
    CHECK(r.message == "edges_not_descending at tiers.edges");
}

TEST_CASE("writer: a read failure is 503 with no audit row and no store write",
          "[dex][score_policy_writer]") {
    World w;
    w.read_fails = true;
    const auto r = w.put("default", doc_with_excellent(95.0));
    CHECK(r.status == St::StoreUnavailable);
    CHECK(r.retry_after_ms == 2000);
    CHECK(w.rows.empty());
    CHECK(w.cas_calls == 0);
}

// ── dry run ─────────────────────────────────────────────────────────────────

TEST_CASE("writer: dry_run validates, checks the precondition and stores nothing",
          "[dex][score_policy_writer]") {
    World w;
    const std::string body = doc_with_excellent(95.0);
    SECTION("no If-Match is 428") {
        CHECK(w.put(std::nullopt, body, std::string("true")).status == St::IfMatchMissing);
    }
    SECTION("a stale If-Match is 409") {
        w.stored = doc_with_excellent(90.0);
        CHECK(w.put("default", body, std::string("true")).status == St::Stale);
    }
    SECTION("a valid dry run") {
        const auto r = w.put("default", body, std::string("true"));
        REQUIRE(r.status == St::Ok);
        CHECK(r.dry_run);
        CHECK(r.previous_revision == "default");
        CHECK(r.in_force.revision == dex_score_policy_revision(body));
        CHECK(r.in_force.source == "custom");
        REQUIRE(w.rows.size() == 1);
        CHECK(w.rows[0].verb == "dex.score_policy.validate");
        CHECK(w.rows[0].result == "success");
        CHECK(w.rows[0].detail["dry_run"] == true);
        CHECK(w.cas_calls == 0);
        CHECK_FALSE(w.stored);
        REQUIRE(w.provider->current());
        CHECK(w.provider->current()->source == "default");
    }
    SECTION("dry_run=false is a real write") {
        const auto r = w.put("default", body, std::string("false"));
        CHECK(r.status == St::Ok);
        CHECK_FALSE(r.dry_run);
        CHECK(w.cas_calls == 1);
    }
}

TEST_CASE("writer: a dry run whose validate row is refused is 503 and stores nothing",
          "[dex][score_policy_writer]") {
    World w;
    w.refuse_results = {"success"};
    const auto r = w.put("default", doc_with_excellent(95.0), std::string("true"));
    CHECK(r.status == St::AuditUnavailable);
    CHECK(r.retry_after_ms == 5000);
    CHECK(w.cas_calls == 0);
    REQUIRE(w.provider->current());
    CHECK(w.provider->current()->source == "default");
}

// ── PUT ─────────────────────────────────────────────────────────────────────

TEST_CASE("writer: PUT against a never-written policy creates it and installs it",
          "[dex][score_policy_writer]") {
    World w;
    const std::string body = doc_with_excellent(95.0);
    const std::string rev = dex_score_policy_revision(body);
    const auto r = w.put("\"default\"", body);
    REQUIRE(r.status == St::Ok);
    CHECK(w.cas_calls == 1);
    CHECK_FALSE(w.cas_expected.has_value()); // nullopt: the row must be absent
    CHECK(w.cas_actor == "alice");
    CHECK(w.stored == body);
    CHECK(r.previous_revision == "default");
    CHECK(r.in_force.revision == rev);
    REQUIRE(w.rows.size() == 2);
    CHECK(w.rows[0].result == "attempted");
    CHECK(w.rows[1].result == "success");
    CHECK(w.rows[1].verb == "dex.score_policy.update");
    CHECK(w.rows[1].detail["if_match"] == "default");
    CHECK(w.rows[1].detail["prior_revision"] == "default");
    CHECK(w.rows[1].detail["revision"] == rev);
    CHECK(w.rows[1].detail["document"] == json::parse(body));
    const auto cur = w.provider->current();
    REQUIRE(cur);
    CHECK(cur->source == "custom");
    CHECK(cur->revision == rev);
}

TEST_CASE("writer: PUT stores the canonical form of the document, not the body as sent",
          "[dex][score_policy_writer]") {
    World w;
    // Whitespace, a reordered key, an integer edge and a partial document (the rest of the
    // policy takes its defaults): none of it is the canonical text.
    const std::string sent =
        "{ \"version\" : 1,\n  \"tiers\" : { \"edges\" : { \"excellent\" : 95 } } }";
    const std::string canonical = doc_with_excellent(95.0);
    const std::string rev = dex_score_policy_revision(canonical);
    REQUIRE(sent != canonical);
    REQUIRE(dex_score_policy_revision(sent) != rev);

    const auto r = w.put("default", sent);
    REQUIRE(r.status == St::Ok);
    CHECK(w.cas_text == canonical);
    CHECK(w.stored == canonical);
    CHECK(r.in_force.revision == rev);
    REQUIRE(w.rows.size() == 2);
    CHECK(w.rows[0].detail["revision"] == rev);
    CHECK(w.rows[1].detail["revision"] == rev);
    // A following GET serves the revision of the stored text; the installed policy agrees.
    CHECK(dex_policy_in_force_from_stored(w.stored).revision == rev);
    REQUIRE(w.provider->current());
    CHECK(w.provider->current()->revision == rev);
}

TEST_CASE("writer: the attempted row carries the whole proposal before the store is touched",
          "[dex][score_policy_writer]") {
    World w;
    w.stored = doc_with_excellent(90.0);
    const std::string prior = dex_score_policy_revision(*w.stored);
    const std::string body = doc_with_excellent(95.0);

    // The only row that existed when the store was hit must be the attempted one, complete.
    auto attempted_row_is_complete = [&](std::string_view verb, const json& revision,
                                         const json& document) {
        REQUIRE(w.rows_at_store.size() == 1);
        Row a = w.rows_at_store[0];
        CHECK(a.verb == verb);
        CHECK(a.result == "attempted");
        CHECK(a.detail["if_match"] == prior);
        CHECK(a.detail["prior_revision"] == prior);
        CHECK(a.detail["revision"] == revision);
        CHECK(a.detail["document"] == document);
    };
    SECTION("PUT") {
        REQUIRE(w.put(prior, body).status == St::Ok);
        attempted_row_is_complete("dex.score_policy.update", dex_score_policy_revision(body),
                                  json::parse(body));
    }
    SECTION("DELETE") {
        REQUIRE(w.del(prior).status == St::Ok);
        attempted_row_is_complete("dex.score_policy.reset", "default", nullptr);
    }
    SECTION("a refused outcome row leaves the attempted row complete and the write standing") {
        w.refuse_results = {"success"};
        const auto r = w.put(prior, body);
        CHECK(r.status == St::Ok);
        CHECK(w.stored == body);
        CHECK(w.refused == 1);
        REQUIRE(w.rows.size() == 1);
        CHECK(w.rows[0].result == "attempted");
        attempted_row_is_complete("dex.score_policy.update", dex_score_policy_revision(body),
                                  json::parse(body));
    }
}

TEST_CASE("writer: PUT over a present-but-empty row compares against the empty text",
          "[dex][score_policy_writer]") {
    World w;
    w.stored = std::string();
    const auto r = w.put("default", doc_with_excellent(95.0));
    REQUIRE(r.status == St::Ok);
    REQUIRE(w.cas_expected.has_value());
    CHECK(*w.cas_expected == "");
}

TEST_CASE("writer: PUT replaces a stored policy when If-Match is its revision",
          "[dex][score_policy_writer]") {
    World w;
    w.stored = doc_with_excellent(90.0);
    const std::string prior = dex_score_policy_revision(*w.stored);
    const std::string body = doc_with_excellent(95.0);
    const auto r = w.put(prior, body);
    REQUIRE(r.status == St::Ok);
    CHECK(*w.cas_expected == doc_with_excellent(90.0));
    CHECK(r.previous_revision == prior);
    CHECK(w.stored == body);
}

TEST_CASE("writer: the attempted row is refused: 503, no store call",
          "[dex][score_policy_writer]") {
    World w;
    w.refuse_results = {"attempted"};
    const auto r = w.put("default", doc_with_excellent(95.0));
    CHECK(r.status == St::AuditUnavailable);
    CHECK(r.retry_after_ms == 5000);
    CHECK(w.cas_calls == 0);
    CHECK_FALSE(w.stored);
}

TEST_CASE("writer: a throwing audit hook is a refused row", "[dex][score_policy_writer]") {
    World w;
    w.audit_throws = 1;
    CHECK(w.put("default", doc_with_excellent(95.0)).status == St::AuditUnavailable);
    CHECK(w.cas_calls == 0);
}

TEST_CASE("writer: a compare-and-set that reports stale is 409 with a failure row",
          "[dex][score_policy_writer]") {
    World w;
    const std::string body = doc_with_excellent(95.0);
    auto d = w.deps();
    d.compare_and_set = [&](const std::optional<std::string>&, const std::string&,
                            const std::string&) -> std::expected<bool, std::string> {
        return false; // another writer got in between the read and the write
    };
    DexScorePolicyWriteRequest rq;
    rq.if_match = "default";
    rq.body = body;
    const auto r = apply_dex_score_policy(rq, d);
    CHECK(r.status == St::Stale);
    REQUIRE(w.rows.size() == 2);
    CHECK(w.rows[1].result == "failure");
    CHECK(w.rows[1].detail["reason"] == "stale");
}

TEST_CASE("writer: a second writer in this process gets WriterBusy", "[dex][score_policy_writer]") {
    World w;
    const std::string body = doc_with_excellent(95.0);
    // The first write parks inside its commit, holding the provider's writer lock.
    std::promise<void> entered_p;
    std::promise<void> release_p;
    auto entered = entered_p.get_future();
    const auto gate = release_p.get_future().share();
    auto d1 = w.deps();
    d1.compare_and_set = [&](const std::optional<std::string>&, const std::string&,
                             const std::string&) -> std::expected<bool, std::string> {
        entered_p.set_value();
        gate.wait();
        return true;
    };
    DexScorePolicyWriteRequest rq1;
    rq1.if_match = "default";
    rq1.body = body;
    std::optional<DexScorePolicyWriteResult> first;
    std::thread t([&] { first = apply_dex_score_policy(rq1, d1); });
    entered.wait();
    const auto second = w.put("default", doc_with_excellent(96.0));
    release_p.set_value();
    t.join();
    CHECK(second.status == St::WriterBusy);
    CHECK(second.retry_after_ms == 2000);
    REQUIRE(first);
    CHECK(first->status == St::Ok);
    // rows: first attempted, second attempted, second failure (writer_busy), first success
    REQUIRE(w.rows.size() == 4);
    CHECK(w.rows[2].result == "failure");
    CHECK(w.rows[2].detail["reason"] == "writer_busy");
}

// ── DELETE ──────────────────────────────────────────────────────────────────

TEST_CASE("writer: DELETE of a never-written policy is Ok: attempted then no_change",
          "[dex][score_policy_writer]") {
    World w;
    const auto r = w.del("default");
    REQUIRE(r.status == St::Ok);
    CHECK(r.in_force.revision == "default");
    CHECK(r.previous_revision == "default");
    CHECK(r.in_force.source == "default");
    REQUIRE(w.rows.size() == 2);
    CHECK(w.rows[0].verb == "dex.score_policy.reset");
    CHECK(w.rows[0].result == "attempted");
    CHECK(w.rows[1].result == "no_change");
    CHECK(w.car_calls == 0);
}

TEST_CASE("writer: a refused no_change row keeps the DELETE answer", "[dex][score_policy_writer]") {
    World w;
    w.refuse_results = {"no_change"};
    const auto r = w.del("default");
    CHECK(r.status == St::Ok);
    CHECK(w.refused == 1);
    REQUIRE(w.rows.size() == 1);
    CHECK(w.rows[0].result == "attempted");
    CHECK(w.car_calls == 0);
}

TEST_CASE("writer: DELETE removes the exact stored text", "[dex][score_policy_writer]") {
    World w;
    w.stored = doc_with_excellent(90.0);
    const std::string prior = dex_score_policy_revision(*w.stored);
    REQUIRE(w.provider->write(w.stored, [] { return std::expected<bool, std::string>(true); }));
    const auto r = w.del(prior);
    REQUIRE(r.status == St::Ok);
    CHECK(w.car_expected == doc_with_excellent(90.0));
    CHECK_FALSE(w.stored);
    CHECK(r.previous_revision == prior);
    CHECK(r.in_force.revision == "default");
    REQUIRE(w.rows.size() == 2);
    CHECK(w.rows[1].result == "success");
    CHECK(w.rows[1].detail["revision"] == "default");
    CHECK(w.rows[1].detail["document"].is_null());
    REQUIRE(w.provider->current());
    CHECK(w.provider->current()->source == "default");
}

TEST_CASE("writer: DELETE with a stale If-Match is 409", "[dex][score_policy_writer]") {
    World w;
    w.stored = doc_with_excellent(90.0);
    const auto r = w.del("default");
    CHECK(r.status == St::Stale);
    REQUIRE(w.rows.size() == 1);
    CHECK(w.rows[0].result == "denied");
    CHECK(w.car_calls == 0);
}

// ── outcome unknown ─────────────────────────────────────────────────────────

TEST_CASE("writer: a store error with the intended text observed afterwards is a 200",
          "[dex][score_policy_writer]") {
    World w;
    w.store_error = kPrefixedError; // applied, then the connection was lost
    const std::string body = doc_with_excellent(95.0);
    const auto r = w.put("default", body);
    REQUIRE(r.status == St::Ok);
    CHECK(r.in_force.revision == dex_score_policy_revision(body));
    CHECK(r.previous_revision == "default");
    REQUIRE(w.rows.size() == 2);
    CHECK(w.rows[1].result == "success");
    CHECK(w.rows[1].detail["outcome"] == "observed_after_store_error");
}

TEST_CASE("writer: applied then overwritten before the re-read: outcome unknown, naming what "
          "is stored",
          "[dex][score_policy_writer]") {
    World w;
    w.store_error = kPrefixedError;
    const std::string other = doc_with_excellent(80.0);
    w.after_apply = [&] { w.stored = other; }; // a second writer replaces our text
    const auto r = w.put("default", doc_with_excellent(95.0));
    REQUIRE(r.status == St::OutcomeUnknown);
    const std::string observed = dex_score_policy_revision(other);
    CHECK(r.retry_after_ms == 2000);
    CHECK(r.message.find(observed) != std::string::npos);
    CHECK(r.message.find("not changed") == std::string::npos);
    CHECK(r.remediation.find("GET") != std::string::npos);
    REQUIRE(w.rows.size() == 2);
    CHECK(w.rows[1].result == "failure");
    CHECK(w.rows[1].detail["reason"] == "outcome_unknown");
    CHECK(w.rows[1].detail["observed_revision"] == observed);
}

TEST_CASE("writer: not applied and the old text observed: the same unknown-outcome shape",
          "[dex][score_policy_writer]") {
    World w;
    w.stored = doc_with_excellent(90.0);
    w.store_error = kPrefixedError;
    w.apply_before_error = false;
    const std::string prior = dex_score_policy_revision(*w.stored);
    const auto r = w.put(prior, doc_with_excellent(95.0));
    REQUIRE(r.status == St::OutcomeUnknown);
    CHECK(r.message.find("not changed") == std::string::npos);
    CHECK(w.rows.back().detail["observed_revision"] == prior);
    CHECK(w.rows.back().detail["prior_revision"] == prior);
}

TEST_CASE("writer: when the re-read fails the outcome is unknown and says so",
          "[dex][score_policy_writer]") {
    World w;
    w.store_error = kPrefixedError;
    w.apply_before_error = false;
    w.after_apply = nullptr;
    auto d = w.deps();
    const auto read = d.read_stored;
    int calls = 0;
    d.read_stored = [&]() -> std::expected<std::optional<std::string>, std::string> {
        if (++calls >= 2)
            return std::unexpected(std::string("store down\nagain"));
        return read();
    };
    DexScorePolicyWriteRequest rq;
    rq.if_match = "default";
    rq.body = doc_with_excellent(95.0);
    const auto r = apply_dex_score_policy(rq, d);
    REQUIRE(r.status == St::OutcomeUnknown);
    CHECK(r.message.find("could not be re-read") != std::string::npos);
    CHECK(r.remediation.find("GET") != std::string::npos);
    REQUIRE(w.rows.size() == 2);
    CHECK(w.rows[1].detail["reason"] == "outcome_unknown");
    CHECK(w.rows[1].detail["reread_error"] == "store_down_again");
    CHECK_FALSE(w.rows[1].detail.contains("observed_revision"));
}

TEST_CASE("writer: a throwing commit follows the re-read path", "[dex][score_policy_writer]") {
    World w;
    w.store_throws = true; // nothing applied
    const auto r = w.put("default", doc_with_excellent(95.0));
    REQUIRE(r.status == St::OutcomeUnknown);
    CHECK(w.rows.back().detail["observed_revision"] == "default");
}

TEST_CASE("writer: an exception escaping write() after the commit is resolved by the re-read",
          "[dex][score_policy_writer]") {
    World w;
    const std::string body = doc_with_excellent(95.0);
    // The provider reads its clock under its state lock right after the commit: make it throw
    // exactly there, with the text already stored.
    w.after_apply = [&] { w.clock_throws = true; };
    const auto r = w.put("default", body);
    REQUIRE(r.status == St::Ok);
    CHECK(r.in_force.revision == dex_score_policy_revision(body));
    REQUIRE(w.rows.size() == 2);
    CHECK(w.rows[1].detail["outcome"] == "observed_after_store_error");
    CHECK(w.rows[1].detail["reason"].get<std::string>().rfind("write_threw:", 0) == 0);
    // the writer lock was released on the way out: a follow-up write goes through
    w.clock_throws = false;
    const auto again = w.put(dex_score_policy_revision(body), doc_with_excellent(96.0));
    CHECK(again.status == St::Ok);
}

TEST_CASE("writer: DELETE's ambiguous outcome is resolved by what the re-read finds",
          "[dex][score_policy_writer]") {
    World w;
    w.stored = doc_with_excellent(90.0);
    w.store_error = kPrefixedError;
    const std::string prior = dex_score_policy_revision(*w.stored);

    SECTION("removed, then the connection was lost: absent is the intended state") {
        const auto r = w.del(prior);
        REQUIRE(r.status == St::Ok);
        CHECK(r.in_force.revision == "default");
        CHECK(r.previous_revision == prior);
        REQUIRE(w.rows.size() == 2);
        CHECK(w.rows[1].result == "success");
        CHECK(w.rows[1].detail["outcome"] == "observed_after_store_error");
        CHECK(w.rows[1].detail["revision"] == "default");
    }
    SECTION("not removed: the row is still stored") {
        w.apply_before_error = false;
        const auto r = w.del(prior);
        REQUIRE(r.status == St::OutcomeUnknown);
        CHECK(r.retry_after_ms == 2000);
        CHECK(r.message.find(prior) != std::string::npos);
        REQUIRE(w.rows.size() == 2);
        CHECK(w.rows[1].result == "failure");
        CHECK(w.rows[1].detail["reason"] == "outcome_unknown");
        CHECK(w.rows[1].detail["observed_revision"] == prior);
    }
    SECTION("removed, then an empty text was stored: a present row is not an absent one") {
        w.after_apply = [&] { w.stored = std::string(); };
        const auto r = w.del(prior);
        REQUIRE(r.status == St::OutcomeUnknown);
        REQUIRE(w.rows.size() == 2);
        // an empty text reads as the default revision, yet the row exists
        CHECK(w.rows[1].detail["observed_revision"] == "default");
        CHECK(w.rows[1].detail["reason"] == "outcome_unknown");
    }
    SECTION("the re-read fails") {
        w.apply_before_error = false;
        auto d = w.deps();
        const auto read = d.read_stored;
        int calls = 0;
        d.read_stored = [&]() -> std::expected<std::optional<std::string>, std::string> {
            if (++calls >= 2)
                return std::unexpected(std::string("store down"));
            return read();
        };
        DexScorePolicyWriteRequest rq;
        rq.op = Op::Reset;
        rq.if_match = prior;
        const auto r = apply_dex_score_policy(rq, d);
        REQUIRE(r.status == St::OutcomeUnknown);
        CHECK(r.message.find("could not be re-read") != std::string::npos);
        REQUIRE(w.rows.size() == 2);
        CHECK(w.rows[1].detail["reread_error"] == "store_down");
        CHECK_FALSE(w.rows[1].detail.contains("observed_revision"));
    }
}

TEST_CASE("writer: an unprefixed store refusal is a 400 with the store's text and a failure row",
          "[dex][score_policy_writer]") {
    World w;
    w.store_error = std::string("key 'x' is not a configurable runtime setting");
    w.apply_before_error = false;
    const auto r = w.put("default", doc_with_excellent(95.0));
    CHECK(r.status == St::Invalid);
    CHECK(r.message == "key 'x' is not a configurable runtime setting");
    REQUIRE(w.rows.size() == 2);
    CHECK(w.rows[1].result == "failure");
    CHECK(w.rows[1].detail["reason"] == "commit_refused");
}

TEST_CASE("writer: the answer never claims the policy was left unchanged",
          "[dex][score_policy_writer]") {
    // every OutcomeUnknown message, for each re-read result
    for (const bool applied : {true, false}) {
        World w;
        w.store_error = kPrefixedError;
        w.apply_before_error = applied;
        w.after_apply = [&] { w.stored = doc_with_excellent(70.0); };
        const auto r = w.put("default", doc_with_excellent(95.0));
        REQUIRE(r.status == St::OutcomeUnknown);
        CHECK(r.message.find("unchanged") == std::string::npos);
        CHECK(r.message.find("not changed") == std::string::npos);
        CHECK(r.message.find("was not applied") == std::string::npos);
    }
}
