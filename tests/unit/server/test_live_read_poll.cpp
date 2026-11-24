/// @file test_live_read_poll.cpp
/// live_read_poll.{hpp,cpp}: the shared poll rule behind the REST live route and the MCP tool.
/// The pure reducer and the loop (with an injected read and sleep, so nothing sleeps) are
/// tested without a store; one PG-backed case pins the store wiring (agent scoped in SQL,
/// tier filter applied).

#include "live_read_poll.hpp"

#include "forensics_plugin_set.hpp"
#include "live_model.hpp"
#include "live_result_json.hpp"
#include "pg/pg_pool.hpp"
#include "response_store.hpp"
#include "utf8_clamp.hpp"
#include "test_forensics_tier_fixture.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
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
    CHECK_FALSE(v.partial);
}

TEST_CASE("reduce_rows: output without a terminal row is NOT an answer", "[live][poll]") {
    // A RUNNING chunk can land before the terminal frame: the poll must keep reading, never
    // answer the partial list as complete.
    const std::vector<StoredResponse> rows{row(1, 100, 0, "proc|1|a\n")};
    const auto v = live::reduce_rows(rows, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kTimeout);
    CHECK(v.partial);
    CHECK(v.output == "proc|1|a\n"); // handed back only for the loop's early over-cap exit
}

TEST_CASE("reduce_rows: the answer is decided once ANY row is terminal, in either ingest shape", "[live][poll]") {
    SECTION("direct Subscribe path: a separate empty terminal row follows the RUNNING chunks") {
        const std::vector<StoredResponse> rows{
            row(1, 100, 0, "proc|1|a\n"), row(2, 100, 0, "proc|2|b\n"), row(3, 101, 1, "")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "proc|1|a\nproc|2|b\n");
    }
    SECTION("gateway/proxy path: the terminal frame updated the RUNNING rows in place, no extra row") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "proc|1|a\n"), row(2, 100, 1, "proc|2|b\n")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "proc|1|a\nproc|2|b\n");
    }
    SECTION("gateway/proxy path: only the LAST row updated in place is still a terminal row") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "proc|1|a\n"), row(2, 100, 1, "proc|2|b\n")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kOk);
    }
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

TEST_CASE("reduce_rows: a failure row wins at once, with or without partial output and a success row", "[live][poll]") {
    SECTION("failure alone") {
        const std::vector<StoredResponse> rows{row(1, 100, 2, "", "agent-1", "boom")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kDeviceFailed);
    }
    SECTION("failure beside a success row") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "ok\n"), row(2, 101, 2, "", "agent-1", "boom")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kDeviceFailed);
    }
}

TEST_CASE("reduce_rows: failure detail is bounded to 200 bytes", "[live][poll]") {
    const std::vector<StoredResponse> rows{row(1, 100, 3, "", "agent-1", std::string(5000, 'x'))};
    const auto v = live::reduce_rows(rows, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kDeviceFailed);
    CHECK(v.detail.size() == live::kLiveDetailMaxBytes);
    CHECK(live::kLiveDetailMaxBytes == 200);
}

TEST_CASE("reduce_rows: detail cuts land on a UTF-8 boundary", "[live][poll]") {
    // 199 ASCII bytes, then a 3-byte character straddling the 200-byte cut: the whole character
    // is dropped, never half of it.
    const std::string text = std::string(199, 'a') + "\xE2\x82\xAC" + "tail"; // euro sign
    SECTION("failure text") {
        const std::vector<StoredResponse> rows{row(1, 100, 2, "", "agent-1", text)};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.detail == std::string(199, 'a'));
    }
    SECTION("error| text, cut at an offset that also shifts by the 6-byte prefix") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "error|" + text)};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kDeviceError);
        CHECK(v.detail == std::string(199, 'a'));
    }
    SECTION("a multi-byte character that fits whole is kept") {
        const std::string fits = std::string(197, 'a') + "\xE2\x82\xAC" + "tail"; // 197 + 3 = 200
        const std::vector<StoredResponse> rows{row(1, 100, 2, "", "agent-1", fits)};
        CHECK(live::reduce_rows(rows, "agent-1").detail == std::string(197, 'a') + "\xE2\x82\xAC");
    }
}

TEST_CASE("reduce_rows: rows join in id order whatever order they arrive in or their timestamps say", "[live][poll]") {
    SECTION("ids decide, the timestamp does not: a clock step back must not reorder chunks") {
        const std::vector<StoredResponse> rows{
            row(9, 100, 0, "C"), row(1, 300, 0, "A"), row(5, 200, 0, "B"), row(10, 50, 1, "")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "A\nB\nC");
    }
    SECTION("equal timestamps concatenate in id order") {
        const std::vector<StoredResponse> rows{
            row(30, 100, 0, "3"), row(10, 100, 0, "1"), row(20, 100, 0, "2"), row(40, 100, 1, "")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "1\n2\n3");
    }
    SECTION("empty outputs contribute nothing") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "X"), row(2, 101, 0, ""), row(3, 102, 1, "Y")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "X\nY");
    }
}

TEST_CASE("reduce_rows: chunks are joined at a line boundary, never fused", "[live][poll]") {
    SECTION("two chunks with no trailing newline are separated by one newline") {
        const std::vector<StoredResponse> rows{
            row(1, 100, 0, "proc|1|a|h1|/p1"), row(2, 101, 1, "proc|2|b|h2|/p2")};
        const auto v = live::reduce_rows(rows, "agent-1");
        REQUIRE(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "proc|1|a|h1|/p1\nproc|2|b|h2|/p2");
    }
    SECTION("a chunk that already ends in a newline gets no second one") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "proc|1|a\n"), row(2, 101, 1, "proc|2|b\n")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "proc|1|a\nproc|2|b\n");
    }
    SECTION("a CRLF-ended chunk gets no second separator") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "proc|1|a\r\n"), row(2, 101, 1, "proc|2|b\r\n")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "proc|1|a\r\nproc|2|b\r\n");
    }
    SECTION("an empty chunk between two chunks adds no separator and no blank line") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "A"), row(2, 101, 0, ""), row(3, 102, 1, "B")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "A\nB");
    }
    SECTION("the first chunk is never prefixed and a single chunk is unchanged") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "only")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "only");
    }
    SECTION("the parsed rows are correct: no row is fused with its neighbour") {
        const std::vector<StoredResponse> rows{
            row(1, 100, 0, "proc|1|alpha|aa|/bin/alpha"), row(2, 101, 1, "proc|2|beta|bb|/bin/beta")};
        const auto v = live::reduce_rows(rows, "agent-1");
        const auto parsed = live::parse_processes(v.output);
        REQUIRE(parsed.size() == 2);
        CHECK(parsed[0].path == "/bin/alpha");
        CHECK(parsed[1].pid == 2);
        CHECK(parsed[1].name == "beta");
        CHECK(parsed[1].path == "/bin/beta");
    }
}

TEST_CASE("reduce_rows: another agent's rows are ignored", "[live][poll]") {
    SECTION("a foreign row alone decides nothing") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "secret\n", "agent-2")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kTimeout);
        CHECK_FALSE(v.partial);
    }
    SECTION("a foreign failure does not fail this agent's answer") {
        const std::vector<StoredResponse> rows{
            row(1, 100, 2, "", "agent-2", "boom"), row(2, 101, 1, "mine\n", "agent-1")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "mine\n");
    }
    SECTION("a foreign terminal row does not make this agent's partial output an answer") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "mine\n", "agent-1"), row(2, 101, 1, "", "agent-2")};
        CHECK(live::reduce_rows(rows, "agent-1").outcome == live::LiveOutcome::kTimeout);
    }
    SECTION("a foreign row's output is never joined") {
        const std::vector<StoredResponse> rows{
            row(1, 100, 0, "mine|", "agent-1"), row(2, 100, 0, "theirs|", "agent-2"), row(3, 101, 1, "more", "agent-1")};
        CHECK(live::reduce_rows(rows, "agent-1").output == "mine|\nmore");
    }
}

TEST_CASE("reduce_rows: an `error|` prefix on the joined output is a device error", "[live][poll]") {
    SECTION("first row") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "error|plugin not loaded")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kDeviceError);
        CHECK(v.detail == "plugin not loaded");
    }
    SECTION("the detail is bounded") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "error|" + std::string(5000, 'e'))};
        CHECK(live::reduce_rows(rows, "agent-1").detail.size() == live::kLiveDetailMaxBytes);
    }
    SECTION("without a terminal row an `error|` line is still undecided") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "error|plugin not loaded")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kTimeout);
        CHECK(v.partial);
    }
    SECTION("a prefix split over two rows is two lines, not an error") {
        // Chunks are joined at a line boundary, so "err" + "or|late" is two lines.
        const std::vector<StoredResponse> rows{row(1, 100, 0, "err"), row(2, 101, 1, "or|late")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "err\nor|late");
    }
    SECTION("`error|` inside a later row is data, not an error") {
        const std::vector<StoredResponse> rows{row(1, 100, 0, "proc|1|a\n"), row(2, 101, 1, "error|x")};
        const auto v = live::reduce_rows(rows, "agent-1");
        CHECK(v.outcome == live::LiveOutcome::kOk);
        CHECK(v.output == "proc|1|a\nerror|x");
    }
    SECTION("`error|` from a foreign agent's row is ignored") {
        const std::vector<StoredResponse> rows{row(1, 100, 1, "error|nope", "agent-2"), row(2, 101, 1, "ok\n")};
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

TEST_CASE("reduce_rows: a RUNNING row with no output is still undecided and not partial", "[live][poll]") {
    const std::vector<StoredResponse> rows{row(1, 100, 0, "")};
    const auto v = live::reduce_rows(rows, "agent-1");
    CHECK(v.outcome == live::LiveOutcome::kTimeout);
    CHECK_FALSE(v.partial);
}

TEST_CASE("utf8_clamp_prefix: never ends inside a multi-byte character", "[live][poll][utf8]") {
    using yuzu::server::utf8_clamp_prefix;
    const std::string euro = "\xE2\x82\xAC"; // 3 bytes
    const std::string four = "\xF0\x9F\x98\x80"; // 4 bytes
    SECTION("a string that fits is returned whole") {
        CHECK(utf8_clamp_prefix("abc", 3) == "abc");
        CHECK(utf8_clamp_prefix("abc", 10) == "abc");
        CHECK(utf8_clamp_prefix("", 0) == "");
    }
    SECTION("ASCII is cut exactly at the bound") {
        CHECK(utf8_clamp_prefix("abcdef", 4) == "abcd");
        CHECK(utf8_clamp_prefix("abcdef", 0) == "");
    }
    SECTION("a cut inside a 3-byte character drops the whole character") {
        const std::string s = "ab" + euro + "cd";
        CHECK(utf8_clamp_prefix(s, 3) == "ab"); // would end after the lead byte
        CHECK(utf8_clamp_prefix(s, 4) == "ab"); // would end after the second byte
        CHECK(utf8_clamp_prefix(s, 5) == "ab" + euro);
    }
    SECTION("a cut inside a 4-byte character drops the whole character") {
        const std::string s = "a" + four + "b";
        CHECK(utf8_clamp_prefix(s, 2) == "a");
        CHECK(utf8_clamp_prefix(s, 3) == "a");
        CHECK(utf8_clamp_prefix(s, 4) == "a");
        CHECK(utf8_clamp_prefix(s, 5) == "a" + four);
    }
    SECTION("a bound smaller than the first character gives an empty prefix") {
        CHECK(utf8_clamp_prefix(four, 2).empty());
    }
    SECTION("stray continuation bytes with no lead byte back up to nothing, never past the start") {
        CHECK(utf8_clamp_prefix("\x80\x80\x80\x80", 2).empty());
    }
}

// ── the loop (injected read and sleep) ───────────────────────────────────────────

namespace {
live::LivePollLimits fast_limits(int polls = 5) {
    live::LivePollLimits l;
    l.max_polls = polls;
    l.interval = std::chrono::milliseconds(500);
    return l;
}
using Rows = std::optional<live::LiveRowsRead>;
const auto no_sleep = [](std::chrono::milliseconds) {};
} // namespace

TEST_CASE("poll_live_output: answers on the first read without sleeping", "[live][poll]") {
    int reads = 0, sleeps = 0;
    const auto out = live::poll_live_output(
        [&]() -> Rows {
            ++reads;
            return live::LiveRowsRead{{row(1, 1, 1, "hello\n")}};
        },
        "agent-1", fast_limits(), [&](std::chrono::milliseconds) { ++sleeps; });
    CHECK(out.outcome == live::LiveOutcome::kOk);
    CHECK(out.output == "hello\n");
    CHECK(reads == 1);
    CHECK(sleeps == 0);
}

TEST_CASE("poll_live_output: a partial answer is not returned; the poll waits for the terminal row", "[live][poll]") {
    int reads = 0;
    std::vector<std::chrono::milliseconds> slept;
    const auto out = live::poll_live_output(
        [&]() -> Rows {
            ++reads;
            if (reads == 1)
                return std::vector<StoredResponse>{};
            if (reads == 2) // the first chunk lands, the terminal frame has not
                return std::vector<StoredResponse>{row(1, 1, 0, "proc|1|a\n")};
            return std::vector<StoredResponse>{row(1, 1, 0, "proc|1|a\n"), row(2, 1, 0, "proc|2|b\n"),
                                               row(3, 2, 1, "")};
        },
        "agent-1", fast_limits(), [&](std::chrono::milliseconds d) { slept.push_back(d); });
    CHECK(out.outcome == live::LiveOutcome::kOk);
    CHECK(out.output == "proc|1|a\nproc|2|b\n"); // the whole answer, never the first chunk alone
    CHECK(reads == 3);
    REQUIRE(slept.size() == 2);
    CHECK(slept[0] == std::chrono::milliseconds(500));
}

TEST_CASE("poll_live_output: no rows for the whole budget is a timeout", "[live][poll]") {
    int reads = 0;
    const auto out = live::poll_live_output(
        [&]() -> Rows {
            ++reads;
            return std::vector<StoredResponse>{};
        },
        "agent-1", fast_limits(7), no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kTimeout);
    CHECK(out.detail.empty());
    CHECK(reads == 7);
}

TEST_CASE("poll_live_output: output with no terminal row for the whole budget is incomplete, not a timeout", "[live][poll]") {
    int reads = 0;
    const auto out = live::poll_live_output(
        [&]() -> Rows {
            ++reads;
            return std::vector<StoredResponse>{row(1, 1, 0, "proc|1|a\n")};
        },
        "agent-1", fast_limits(6), no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kIncomplete);
    CHECK(out.detail == "the device began to answer but did not finish");
    CHECK(out.output.empty()); // the partial output is discarded
    CHECK_FALSE(out.truncated);
    CHECK(reads == 6);
}

TEST_CASE("poll_live_output: partial output that later vanishes still reads as incomplete", "[live][poll]") {
    int reads = 0;
    const auto out = live::poll_live_output(
        [&]() -> Rows {
            if (++reads == 1)
                return std::vector<StoredResponse>{row(1, 1, 0, "x\n")};
            return std::vector<StoredResponse>{};
        },
        "agent-1", fast_limits(3), no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kIncomplete);
}

TEST_CASE("poll_live_output: every read degraded is store_degraded, not a timeout", "[live][poll]") {
    int reads = 0;
    const auto out = live::poll_live_output(
        [&]() -> Rows {
            ++reads;
            return std::nullopt;
        },
        "agent-1", fast_limits(4), no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kStoreDegraded);
    CHECK(reads == 4);
}

TEST_CASE("poll_live_output: a degrade followed by an empty read is a timeout; a later answer wins", "[live][poll]") {
    SECTION("degrade then empty reads: the store did answer, so timeout") {
        int reads = 0;
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                if (++reads == 1)
                    return std::nullopt;
                return std::vector<StoredResponse>{};
            },
            "agent-1", fast_limits(3), no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kTimeout);
    }
    SECTION("degrade then an answer: the answer is returned") {
        int reads = 0;
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                if (++reads == 1)
                    return std::nullopt;
                return std::vector<StoredResponse>{row(1, 1, 1, "x\n")};
            },
            "agent-1", fast_limits(3), no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output == "x\n");
    }
}

TEST_CASE("poll_live_output: failure, device error and empty success pass through", "[live][poll]") {
    const auto failed = live::poll_live_output(
        []() -> Rows {
            return std::vector<StoredResponse>{row(1, 1, 0, "partial"), row(2, 2, 2, "", "agent-1", "bad")};
        },
        "agent-1", fast_limits(), no_sleep);
    CHECK(failed.outcome == live::LiveOutcome::kDeviceFailed);
    CHECK(failed.detail == "bad");

    const auto err = live::poll_live_output(
        []() -> Rows { return std::vector<StoredResponse>{row(1, 1, 1, "error|nope")}; }, "agent-1",
        fast_limits(), no_sleep);
    CHECK(err.outcome == live::LiveOutcome::kDeviceError);
    CHECK(err.detail == "nope");

    const auto empty = live::poll_live_output(
        []() -> Rows { return std::vector<StoredResponse>{row(1, 1, 1, "")}; }, "agent-1", fast_limits(),
        no_sleep);
    CHECK(empty.outcome == live::LiveOutcome::kOk);
    CHECK(empty.output.empty());
}

TEST_CASE("poll_live_output: an unwired read seam degrades rather than crashing", "[live][poll]") {
    const auto out = live::poll_live_output(live::LiveRowsFn{}, "agent-1", fast_limits(2), no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kStoreDegraded);
}

TEST_CASE("poll_live_output: zero polls is a timeout, never a degrade", "[live][poll]") {
    const auto out = live::poll_live_output([]() -> Rows { return std::nullopt; }, "agent-1", fast_limits(0),
                                            no_sleep);
    CHECK(out.outcome == live::LiveOutcome::kTimeout);
}

TEST_CASE("poll_live_output: the output byte cap refuses (REST) or cuts at a newline (MCP)", "[live][poll]") {
    const std::string big = "aaaa\nbbbb\ncccc\n"; // 15 bytes
    const auto read = [&]() -> Rows { return std::vector<StoredResponse>{row(1, 1, 1, big)}; };

    auto limits = fast_limits();
    limits.max_output_bytes = 12;

    SECTION("refuse") {
        limits.over_cap = live::OverCapPolicy::kRefuse;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOutputTooLarge);
        CHECK(out.output.empty());
        CHECK_FALSE(out.truncated);
    }
    SECTION("cut at the last newline inside the cap") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output == "aaaa\nbbbb");
        CHECK(out.truncated);
    }
    SECTION("a cap that lands exactly on a newline keeps the rows before it") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        limits.max_output_bytes = 10; // "aaaa\nbbbb\n" is 10 bytes; the newline at index 9 is inside
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.output == "aaaa\nbbbb");
        CHECK(out.truncated);
    }
    SECTION("no newline inside the cap: nothing whole fits") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        limits.max_output_bytes = 3;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output.empty());
        CHECK(out.truncated);
    }
    SECTION("at or under the cap nothing is cut") {
        limits.max_output_bytes = big.size();
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.output == big);
        CHECK_FALSE(out.truncated);
    }
}

TEST_CASE("poll_live_output: a CRLF answer cut at a newline leaves no stray carriage return", "[live][poll]") {
    const std::string crlf = "proc|1|a|h|/p1\r\nproc|2|b|h|/p2\r\nproc|3|c|h|/p3\r\n";
    auto limits = fast_limits();
    limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
    limits.max_output_bytes = 31; // inside the second line, 15 bytes after the first newline
    const auto out = live::poll_live_output(
        [&]() -> Rows { return std::vector<StoredResponse>{row(1, 1, 1, crlf)}; }, "agent-1", limits, no_sleep);
    REQUIRE(out.outcome == live::LiveOutcome::kOk);
    CHECK(out.truncated);
    CHECK(out.output == "proc|1|a|h|/p1");
    CHECK(out.output.find('\r') == std::string::npos);
    // And the rendered JSON carries neither a raw nor an escaped carriage return.
    const auto rendered = live::live_result_json("processes", out.output);
    REQUIRE(rendered);
    CHECK(rendered->body.find('\r') == std::string::npos);
    CHECK(rendered->body.find("\\r") == std::string::npos);
}

TEST_CASE("poll_live_output: output past the cap decides at once, without waiting for a terminal row", "[live][poll]") {
    auto limits = fast_limits(40);
    limits.max_output_bytes = 12;
    int reads = 0;
    const auto read = [&]() -> Rows {
        ++reads;
        return std::vector<StoredResponse>{row(1, 1, 0, "aaaa\nbbbb\ncccc\n")}; // 15 bytes, still RUNNING
    };
    SECTION("refuse") {
        limits.over_cap = live::OverCapPolicy::kRefuse;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOutputTooLarge);
        CHECK(reads == 1);
    }
    SECTION("truncate") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output == "aaaa\nbbbb");
        CHECK(out.truncated);
        CHECK(reads == 1);
    }
    SECTION("a failure row still wins over the cap") {
        const auto out = live::poll_live_output(
            []() -> Rows {
                return std::vector<StoredResponse>{row(1, 1, 0, "aaaa\nbbbb\ncccc\n"), row(2, 2, 2, "", "agent-1", "x")};
            },
            "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kDeviceFailed);
    }
    SECTION("output within the cap and no terminal row keeps polling") {
        limits.max_output_bytes = 100;
        const auto out = live::poll_live_output(read, "agent-1", fast_limits(3), no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kIncomplete);
    }
}

TEST_CASE("poll_live_output: a read the store cut (its head is missing) is over the cap", "[live][poll]") {
    auto limits = fast_limits();
    const auto read = [&]() -> Rows {
        return live::LiveRowsRead{{row(7, 1, 1, "proc|9|tail\n")}, /*capped=*/true};
    };
    SECTION("refuse") {
        limits.over_cap = live::OverCapPolicy::kRefuse;
        CHECK(live::poll_live_output(read, "agent-1", limits, no_sleep).outcome ==
              live::LiveOutcome::kOutputTooLarge);
    }
    SECTION("truncate: what survived is returned and flagged") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto out = live::poll_live_output(read, "agent-1", limits, no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output == "proc|9|tail\n");
        CHECK(out.truncated);
    }
}

TEST_CASE("poll_live_output: the wall deadline ends a poll that is slow rather than long", "[live][poll]") {
    // Each read costs 10 s of steady-clock time; the 25 s deadline ends the poll after the third
    // read, long before max_polls.
    auto t = std::chrono::steady_clock::time_point{} + std::chrono::hours(1);
    const auto now = [&]() { return t; };
    int reads = 0;
    auto limits = fast_limits(40);
    SECTION("nothing seen: timeout") {
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                ++reads;
                t += std::chrono::seconds(10);
                return std::vector<StoredResponse>{};
            },
            "agent-1", limits, no_sleep, {}, now);
        CHECK(out.outcome == live::LiveOutcome::kTimeout);
        CHECK(reads == 3);
    }
    SECTION("output but no terminal row: incomplete") {
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                ++reads;
                t += std::chrono::seconds(10);
                return std::vector<StoredResponse>{row(1, 1, 0, "x\n")};
            },
            "agent-1", limits, no_sleep, {}, now);
        CHECK(out.outcome == live::LiveOutcome::kIncomplete);
        CHECK(reads == 3);
    }
    SECTION("every read degraded: store_degraded") {
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                ++reads;
                t += std::chrono::seconds(10);
                return std::nullopt;
            },
            "agent-1", limits, no_sleep, {}, now);
        CHECK(out.outcome == live::LiveOutcome::kStoreDegraded);
        CHECK(reads == 3);
    }
    SECTION("the first read always happens, even with a zero budget") {
        limits.deadline = std::chrono::milliseconds(0);
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                ++reads;
                return std::vector<StoredResponse>{row(1, 1, 1, "ok\n")};
            },
            "agent-1", limits, no_sleep, {}, now);
        CHECK(out.outcome == live::LiveOutcome::kOk);
        CHECK(reads == 1);
    }
}

TEST_CASE("poll_live_output: the stop predicate abandons the poll with shutting_down", "[live][poll]") {
    SECTION("already stopping: no read at all") {
        int reads = 0;
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                ++reads;
                return std::vector<StoredResponse>{};
            },
            "agent-1", fast_limits(), no_sleep, []() { return true; });
        CHECK(out.outcome == live::LiveOutcome::kShuttingDown);
        CHECK(out.output.empty());
        CHECK(reads == 0);
    }
    SECTION("stop raised between reads") {
        int reads = 0;
        bool stop = false;
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                if (++reads == 2)
                    stop = true; // raised while the second read is in flight
                return std::vector<StoredResponse>{};
            },
            "agent-1", fast_limits(40), no_sleep, [&]() { return stop; });
        CHECK(out.outcome == live::LiveOutcome::kShuttingDown);
        CHECK(reads == 2);
    }
    SECTION("stop raised during the sleep is seen straight after it") {
        int reads = 0;
        bool stop = false;
        const auto out = live::poll_live_output(
            [&]() -> Rows {
                ++reads;
                return std::vector<StoredResponse>{};
            },
            "agent-1", fast_limits(40), [&](std::chrono::milliseconds) { stop = true; },
            [&]() { return stop; });
        CHECK(out.outcome == live::LiveOutcome::kShuttingDown);
        CHECK(reads == 1);
    }
    SECTION("a decided answer is not turned into shutting_down when the stop never fires") {
        const auto out = live::poll_live_output(
            []() -> Rows { return std::vector<StoredResponse>{row(1, 1, 1, "x\n")}; }, "agent-1",
            fast_limits(), no_sleep, []() { return false; });
        CHECK(out.outcome == live::LiveOutcome::kOk);
    }
}

TEST_CASE("poll_live_output: the default limits are the ruled 40 x 500 ms, 25 s and 4 MiB refusal", "[live][poll]") {
    const live::LivePollLimits l;
    CHECK(l.max_polls == 40);
    CHECK(l.interval == std::chrono::milliseconds(500));
    CHECK(l.deadline == std::chrono::milliseconds(25000));
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
          const std::string& output, const std::string& plugin = "os_info", const std::string& err = "",
          std::int64_t timestamp = 0) {
    StoredResponse r;
    r.timestamp = timestamp; // 0 = the store stamps its own clock
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

TEST_CASE("poll_live_output [pg]: the agent scope is applied in SQL, before the row limit", "[live][poll][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());

    // One target row, then MORE foreign rows than the poll's row limit, all NEWER than it. A
    // read that applied the limit before the agent filter would fill its page with foreign rows
    // (newest first) and never see the target row; only the SQL `agent_id` scope keeps it. The
    // per-row filter inside reduce_rows cannot rescue a row the page never contained.
    seed(store, "cmd-scope", "agent-1", 1, "proc|1|mine|h|/mine\n", "os_info", "", 1000);
    for (int i = 0; i < live::kLivePollRowLimit + 8; ++i)
        seed(store, "cmd-scope", "foreign-" + std::to_string(i), 1, "proc|99|theirs\n", "os_info", "", 2000 + i);

    auto limits = fast_limits(1);
    const auto out = live::poll_live_output(store, "cmd-scope", "agent-1",
                                            &yuzu::server::test::forensics_plugin_set(), limits, no_sleep);
    REQUIRE(out.outcome == live::LiveOutcome::kOk);
    CHECK(out.output == "proc|1|mine|h|/mine\n");
    CHECK(out.output.find("theirs") == std::string::npos);
}

TEST_CASE("poll_live_output [pg]: chunks join in ingest order and a partial answer waits for its terminal row", "[live][poll][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());
    const auto* plugins = &yuzu::server::test::forensics_plugin_set();

    // The second chunk is stamped with an EARLIER timestamp (a clock step back): ids, not
    // timestamps, give the order.
    seed(store, "cmd-order", "agent-1", 0, "proc|1|a|h|/p1", "os_info", "", 500);
    seed(store, "cmd-order", "agent-1", 0, "proc|2|b|h|/p2", "os_info", "", 400);

    SECTION("no terminal row yet: incomplete after the budget, nothing returned") {
        const auto out = live::poll_live_output(store, "cmd-order", "agent-1", plugins, fast_limits(2), no_sleep);
        CHECK(out.outcome == live::LiveOutcome::kIncomplete);
        CHECK(out.output.empty());
    }
    SECTION("terminal row present: the whole answer, in ingest order, line separated") {
        seed(store, "cmd-order", "agent-1", 1, "", "os_info", "", 600);
        const auto out = live::poll_live_output(store, "cmd-order", "agent-1", plugins, fast_limits(1), no_sleep);
        REQUIRE(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.output == "proc|1|a|h|/p1\nproc|2|b|h|/p2");
    }
}

TEST_CASE("poll_live_output [pg]: a stored answer over the byte cap is cut by the bounded read", "[live][poll][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::test::PostgresTestDb db{live_poll_tpl};
    REQUIRE(db.available());
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResponseStore store{pool};
    REQUIRE(store.is_open());

    for (int i = 0; i < 5; ++i)
        seed(store, "cmd-big", "agent-1", i == 4 ? 1 : 0, std::string(100, 'a' + i) + "\n");

    auto limits = fast_limits(1);
    limits.max_output_bytes = 250; // the newest rows are kept until the cap, the older ones are cut
    const auto* plugins = &yuzu::server::test::forensics_plugin_set();

    SECTION("refuse") {
        limits.over_cap = live::OverCapPolicy::kRefuse;
        CHECK(live::poll_live_output(store, "cmd-big", "agent-1", plugins, limits, no_sleep).outcome ==
              live::LiveOutcome::kOutputTooLarge);
    }
    SECTION("truncate: the surviving (newest) rows are returned, in id order, and flagged truncated") {
        limits.over_cap = live::OverCapPolicy::kTruncateAtNewline;
        const auto out = live::poll_live_output(store, "cmd-big", "agent-1", plugins, limits, no_sleep);
        REQUIRE(out.outcome == live::LiveOutcome::kOk);
        CHECK(out.truncated);
        // The two oldest rows ('a', 'b') were cut by the store; the three newest ('c', 'd', 'e')
        // joined to 305 bytes, over the cap, so the last whole line inside 250 bytes ends the answer.
        CHECK(out.output == std::string(100, 'c') + "\n" + std::string(100, 'd'));
    }
}
