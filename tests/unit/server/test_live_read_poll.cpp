/// @file test_live_read_poll.cpp
/// live_read_poll.{hpp,cpp}: the shared poll rule behind the REST live route and the MCP tool.
/// The pure reducer and the loop (with an injected read and sleep, so nothing sleeps) are
/// tested without a store; one PG-backed case pins the store wiring (agent scoped in SQL,
/// tier filter applied).

#include "live_read_poll.hpp"

#include "forensics_plugin_set.hpp"
#include "pg/pg_pool.hpp"
#include "response_store.hpp"
#include "test_forensics_tier_fixture.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace live = yuzu::server::live;

namespace {

StoredResponse row(std::int64_t id, std::int64_t ts, int status, std::string output,
                   std::string agent = "agent-1", std::string error = "") {
    StoredResponse r;
    r.id = id;
    r.timestamp = ts;
    r.status = status;
    r.output = std::move(output);
    r.agent_id = std::move(agent);
    r.error_detail = std::move(error);
    return r;
}

} // namespace

// ── reduce_rows (pure) ───────────────────────────────────────────────────────────

TEST_CASE("reduce_rows: no rows decides nothing (timeout)", "[live][poll]") {
    const auto v = live::reduce_rows({}, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kTimeout);
    CHECK(v.output.empty());
}

TEST_CASE("reduce_rows: output without a terminal row is an answer", "[live][poll]") {
    const std::vector<StoredResponse> rows{row(1, 100, 0, "proc|1|a\n")};
    const auto v = live::reduce_rows(rows, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kOk);
    CHECK(v.output == "proc|1|a\n");
}

TEST_CASE("reduce_rows: a RUNNING row with output plus a terminal failure row is a failure", "[live][poll]") {
    const std::vector<StoredResponse> rows{
        row(1, 100, 0, "partial output\n"),
        row(2, 101, 2, "", "agent-1", "plugin crashed"),
    };
    const auto v = live::reduce_rows(rows, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kDeviceFailed);
    CHECK(v.detail == "plugin crashed");
    CHECK(v.output.empty());
}

TEST_CASE("reduce_rows: failure detail is bounded to 200 bytes", "[live][poll]") {
    const std::vector<StoredResponse> rows{row(1, 100, 3, "", "agent-1", std::string(5000, 'x'))};
    const auto v = live::reduce_rows(rows, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kDeviceFailed);
    CHECK(v.detail.size() == live::kLiveDetailMaxBytes);
    CHECK(live::kLiveDetailMaxBytes == 200);
}

TEST_CASE("reduce_rows: rows join in (timestamp, id) order whatever order they arrive in", "[live][poll]") {
    SECTION("distinct timestamps") {
        const std::vector<StoredResponse> rows{
            row(9, 300, 0, "C"), row(1, 100, 0, "A"), row(5, 200, 0, "B")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "ABC");
    }
    SECTION("equal timestamps concatenate in id order") {
        const std::vector<StoredResponse> rows{
            row(30, 100, 0, "3"), row(10, 100, 0, "1"), row(20, 100, 0, "2")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "123");
    }
    SECTION("empty outputs contribute nothing") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "X"), row(2, 101, 0, ""), row(3, 102, 1, "Y")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "XY");
    }
}

TEST_CASE("reduce_rows: another agent's rows are ignored", "[live][poll]") {
    SECTION("a foreign row alone decides nothing") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "secret\n", "agent-2")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kTimeout);
    }
    SECTION("a foreign failure does not fail this agent's answer") {
        const std::vector<StoredResponse> rows{
            row(1, 100, 2, "", "agent-2", "boom"), row(2, 101, 0, "mine\n", "agent-1")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "mine\n");
    }
    SECTION("a foreign row's output is never joined") {
        const std::vector<StoredResponse> rows{
            row(1, 100, 0, "mine|", "agent-1"), row(2, 100, 0, "theirs|", "agent-2"), row(3, 101, 0, "more", "agent-1")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "mine|more");
    }
}

TEST_CASE("reduce_rows: an `error|` prefix on the joined output is a device error", "[live][poll]") {
    SECTION("first row") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "error|plugin not loaded")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kDeviceError);
        CHECK(v.detail == "plugin not loaded");
    }
    SECTION("the detail is bounded") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "error|" + std::string(5000, 'e'))};
        CHECK(live::reduce_rows(rows, "agent-1").detail.size() == live::kLiveDetailMaxBytes);
    }
    SECTION("prefix split over rows still counts: it is the JOINED output that is tested") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "err"), row(2, 101, 0, "or|late")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kDeviceError);
    }
    SECTION("`error|` inside a later row is data, not an error") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "proc|1|a\n"), row(2, 101, 0, "error|x")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "proc|1|a\nerror|x");
    }
    SECTION("`error|` from a foreign agent's row is ignored") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "error|nope", "agent-2"), row(2, 101, 0, "ok\n")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kOk);
    }
    SECTION("a failure row wins over an error| answer") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "error|x"), row(2, 101, 2, "", "agent-1", "died")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kDeviceFailed);
    }
}

TEST_CASE("reduce_rows: a success terminal with no output is an empty success, not a timeout", "[live][poll]") {
    const std::vector<StoredResponse> rows{row(1, 100, 1, "")};
    const auto v = live::reduce_rows(rows, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kOk);
    CHECK(v.output.empty());
}

TEST_CASE("reduce_rows: a RUNNING row with no output is still undecided", "[live][poll]") {
    const std::vector<StoredResponse> rows{row(1, 100, 0, "")};
    CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kTimeout);
}

// ── the loop (injected read and sleep) ───────────────────────────────────────────

namespace {
live::LivePollLimits fast_limits(int polls = 5) {
    live::LivePollLimits l;
    l.max_polls = polls;
    l.interval = std::chrono::milliseconds(500);
    return l;
}
} // namespace

TEST_CASE("poll_live_output: answers on the first read without sleeping", "[live][poll]") {
    int reads = 0, sleeps = 0;
    const auto out = live::poll_live_output(
        [&]() -> std::optional<std::vector<StoredResponse>> {
            ++reads;
            return std::vector<StoredResponse>{row(1, 1, 1, "hello\n")};
        },
        "agent-1", fast_limits(), [&](std::chrono::milliseconds) { ++sleeps; });
    CHECK(out.outcome == live::LiveOutcome::kOk);
    CHECK(out.output == "hello\n");
    CHECK(reads == 1);
    CHECK(sleeps == 0);
}

TEST_CASE("poll_live_output: sleeps the interval between reads and answers when the row lands", "[live][poll]") {
    int reads = 0;
    std::vector<std::chrono::milliseconds> slept;
    const auto out = live::poll_live_output(
        [&]() -> std::optional<std::vector<StoredResponse>> {
            ++reads;
            if (reads < 3)
                return std::vector<StoredResponse>{};
            return std::vector<StoredResponse>{row(1, 1, 0, "proc|1|a\n")};
        },
        "agent-1", fast_limits(), [&](std::chrono::milliseconds d) { slept.push_back(d); });
    CHECK(out.outcome == live::LiveOutcome::kOk);
    CHECK(reads == 3);
    REQUIRE(slept.size() == 2);
    CHECK(slept[0] == std::chrono::milliseconds(500));
}

TEST_CASE("poll_live_output: no rows for the whole budget is a timeout", "[live][poll]") {
    int reads = 0;
    const auto out = live::poll_live_output(
        [&]() -> std::optional<std::vector<StoredResponse>> {
            ++reads;
            return std::vector<StoredResponse>{};
        },
        "agent-1", fast_limits(7), [](std::chrono::milliseconds) {});
    CHECK(out.outcome == live::LiveOutcome::kTimeout);
    CHECK(reads == 7);
}

TEST_CASE("poll_live_output: every read degraded is store_degraded, not a timeout", "[live][poll]") {
    int reads = 0;
    const auto out = live::poll_live_output(
        [&]() -> std::optional<std::vector<StoredResponse>> {
            ++reads;
            return std::nullopt;
        },
        "agent-1", fast_limits(4), [](std::chrono::milliseconds) {});
    CHECK(out.outcome == live::LiveOutcome::kStoreDegraded);
    CHECK(reads == 4);
}

TEST_CASE("poll_live_output: a degrade followed by an empty read is a timeout; a later answer wins", "[live][poll]") {
    SECTION("degrade then empty reads: the store did answer, so timeout") {
        int reads = 0;
        const auto out = live::poll_live_output(
            [&]() -> std::optional<std::vector<StoredResponse>> {
                if (++reads == 1)
                    return std::nullopt;
                return std::vector<StoredResponse>{};
            },
            "agent-1", fast_limits(3), [](std::chrono::milliseconds) {});
        CHECK(out.outcome == live::LiveOutcome::kTimeout);
    }
    SECTION("degrade then an answer: the answer is returned") {
        int reads = 0;
        const auto out = live::poll_live_output(
            [&]() -> std::optional<std::vector<StoredResponse>> {
                if (++reads == 1)
                    return std::nullopt;
                return std::vector<StoredResponse>{row(1, 1, 1, "x\n")};
            },
            "agent-1", fast_limits(3), [](std::chrono::milliseconds) {});
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output == "x\n");
    }
}

TEST_CASE("poll_live_output: failure, device error and empty success pass through", "[live][poll]") {
    const auto sleep = [](std::chrono::milliseconds) {};
    const auto failed = live::poll_live_output(
        []() -> std::optional<std::vector<StoredResponse>> {
            return std::vector<StoredResponse>{row(1, 1, 0, "partial"), row(2, 2, 2, "", "agent-1", "bad")};
        },
        "agent-1", fast_limits(), sleep);
    CHECK(failed.outcome == live::LiveOutcome::kDeviceFailed);
    CHECK(failed.detail == "bad");

    const auto err = live::poll_live_output(
        []() -> std::optional<std::vector<StoredResponse>> {
            return std::vector<StoredResponse>{row(1, 1, 0, "error|nope")};
        },
        "agent-1", fast_limits(), sleep);
    CHECK(err.outcome == live::LiveOutcome::kDeviceError);
    CHECK(err.detail == "nope");

    const auto empty = live::poll_live_output(
        []() -> std::optional<std::vector<StoredResponse>> {
            return std::vector<StoredResponse>{row(1, 1, 1, "")};
        },
        "agent-1", fast_limits(), sleep);
    CHECK(empty.outcome == live::LiveOutcome::kOk);
    CHECK(empty.output.empty());
}

TEST_CASE("poll_live_output: an unwired read seam degrades rather than crashing", "[live][poll]") {
    const auto out = live::poll_live_output(live::LiveRowsFn{}, "agent-1", fast_limits(2),
                                            [](std::chrono::milliseconds) {});
    CHECK(out.outcome == live::LiveOutcome::kStoreDegraded);
}

TEST_CASE("poll_live_output: zero polls is a timeout, never a degrade", "[live][poll]") {
    const auto out = live::poll_live_output(
        []() -> std::optional<std::vector<StoredResponse>> { return std::nullopt; }, "agent-1",
        fast_limits(0), [](std::chrono::milliseconds) {});
    CHECK(out.outcome == live::LiveOutcome::kTimeout);
}

TEST_CASE("poll_live_output: the output byte cap refuses (REST) or cuts at a newline (MCP)", "[live][poll]") {
    const std::string big = "aaaa\nbbbb\ncccc\n"; // 15 bytes
    const auto read = [&]() -> std::optional<std::vector<StoredResponse>> {
        return std::vector<StoredResponse>{row(1, 1, 1, big)};
    };
    const auto sleep = [](std::chrono::milliseconds) {};

    auto limits = fast_limits();
    limits.max_output_bytes = 12;

    SECTION("refuse") {
        limits.over_cap = live::OverCapPolicy::kRefuse;
        const auto out = live::poll_live_output(read, "agent-1", limits, sleep);
        CHECK(out.outcome == live::LiveOutcome::kOutputTooLarge);
        CHECK(out.output.empty());
        CHECK_FALSE(out.truncated);
    }
    SECTION("cut at the last newline inside the cap") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto out = live::poll_live_output(read, "agent-1", limits, sleep);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output == "aaaa\nbbbb");
        CHECK(out.truncated);
    }
    SECTION("a cap that lands exactly on a newline keeps the rows before it") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        limits.max_output_bytes = 10; // "aaaa\nbbbb\n" is 10 bytes; the newline at index 9 is inside
        const auto out = live::poll_live_output(read, "agent-1", limits, sleep);
        CHECK(out.output == "aaaa\nbbbb");
        CHECK(out.truncated);
    }
    SECTION("no newline inside the cap: nothing whole fits") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        limits.max_output_bytes = 3;
        const auto out = live::poll_live_output(read, "agent-1", limits, sleep);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output.empty());
        CHECK(out.truncated);
    }
    SECTION("at or under the cap nothing is cut") {
        limits.max_output_bytes = big.size();
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto out = live::poll_live_output(read, "agent-1", limits, sleep);
        CHECK(out.output == big);
        CHECK_FALSE(out.truncated);
    }
}

TEST_CASE("poll_live_output: the default limits are the ruled 40 x 500 ms and 4 MiB refusal", "[live][poll]") {
    const live::LivePollLimits l;
    CHECK(l.max_polls == 40);
    CHECK(l.interval == std::chrono::milliseconds(500));
    CHECK(l.max_output_bytes == 4u * 1024u * 1024u);
    CHECK(l.over_cap == live::OverCapPolicy::kRefuse);
}

// ── store wiring (PG) ────────────────────────────────────────────────────────────

namespace {
// Shares the "responsestore" key with the other ResponseStore tests (identical resulting schema).
yuzu::test::PgTestTemplate live_poll_tpl{
    "responsestore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        ResponseStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("responsestore template: store failed to migrate");
    }};

void seed(ResponseStore& store, const std::string& cmd, const std::string& agent, int status,
          const std::string& output, const std::string& plugin = "os_info", const std::string& err = "") {
    StoredResponse r;
    r.instruction_id = cmd;
    r.agent_id = agent;
    r.status = status;
    r.output = output;
    r.error_detail = err;
    r.plugin = plugin;
    store.store(r);
}
} // namespace

TEST_CASE("poll_live_output [pg]: reads scoped to the target agent and joins a multi-row answer", "[live][poll][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());

    seed(store, "cmd-1", "agent-1", 0, "proc|1|a\n");
    seed(store, "cmd-1", "agent-2", 1, "proc|99|foreign\n");
    seed(store, "cmd-1", "agent-1", 1, "proc|2|b\n");
    seed(store, "cmd-other", "agent-1", 1, "proc|3|other-command\n");

    auto limits = fast_limits(1);
    const auto out = live::poll_live_output(store, "cmd-1", "agent-1",
                                            &yuzu::server::test::forensics_plugin_set(), limits,
                                            [](std::chrono::milliseconds) {});
    CHECK(out.outcome == live::LiveOutcome::kOk);
    CHECK(out.output.find("foreign") == std::string::npos);
    CHECK(out.output.find("other-command") == std::string::npos);
    CHECK(out.output.find("proc|1|a") != std::string::npos);
    CHECK(out.output.find("proc|2|b") != std::string::npos);
}

TEST_CASE("poll_live_output [pg]: a Forensics-plugin row and a null plugin set both yield nothing", "[live][poll][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());

    seed(store, "cmd-f", "agent-1", 1, "secret\n", yuzu::server::test::kForensicsPlugin);
    seed(store, "cmd-n", "agent-1", 1, "visible\n");

    auto limits = fast_limits(1);
    const auto sleep = [](std::chrono::milliseconds) {};
    CHECK(live::poll_live_output(store, "cmd-f", "agent-1", &yuzu::server::test::forensics_plugin_set(),
                                 limits, sleep)
              .outcome == live::LiveOutcome::kTimeout);
    // An unwired plugin set refuses every row rather than reading unfiltered.
    CHECK(live::poll_live_output(store, "cmd-n", "agent-1", nullptr, limits, sleep).outcome ==
          live::LiveOutcome::kTimeout);
}
